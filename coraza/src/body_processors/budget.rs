// Copyright Coraza Kubernetes Operator contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The absolute memory budget a connector can give one body-processing call.
//!
//! The parsers already bound their output relative to the size of the body (a factor of it), which keeps a
//! hostile body from amplifying without limit but still lets a large one retain a large multiple of its size.
//! A connector with a fixed memory ceiling cannot admit that: it needs to say how many bytes the parsed form may
//! use and have the parsers stop *before* allocating past it. [`MemoryBudget`] is that, and the cost functions
//! here turn what a parser is about to store into the bytes [`crate::transaction::Transaction::body_memory_bytes`]
//! would later count for it, so that the budget and the authoritative accounting agree.

use std::borrow::Cow;

use crate::collection::{
    Growth, INSERT_OVERHEAD_BYTES, KEY_COPIES_PER_INSERT, KEY_RETAINED_BYTES_PER_BYTE, Map, VALUE_ENTRY_BYTES,
    allocation_bytes, grown_list_capacity, key_bytes,
};

/// What a body processor may still retain, or no limit at all.
///
/// The default is unlimited, which is the engine's behaviour without a connector budget: charging is then one
/// branch and nothing else.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct MemoryBudget {
    /// Bytes left, or `None` for no limit.
    remaining: Option<usize>,
    /// What it started as, for messages that name it.
    limit: Option<usize>,
}

impl MemoryBudget {
    /// A budget of `limit` bytes, or no limit.
    pub(crate) const fn new(limit: Option<usize>) -> Self {
        Self {
            remaining: limit,
            limit,
        }
    }

    /// The size the budget started as, or `usize::MAX` for no limit.
    pub(crate) fn limit(&self) -> usize {
        self.limit.unwrap_or(usize::MAX)
    }

    /// Whether there is a limit.
    pub(crate) const fn is_limited(&self) -> bool {
        self.remaining.is_some()
    }

    /// Bytes left, `None` when unlimited.
    pub(crate) const fn remaining(&self) -> Option<usize> {
        self.remaining
    }

    /// Gives `bytes` back, which a limited budget gets and an unlimited one has no use for.
    pub(crate) fn refund(&mut self, bytes: usize) {
        if let Some(remaining) = &mut self.remaining {
            *remaining = remaining.saturating_add(bytes);
        }
    }

    /// Reserves `bytes` if they fit, and reports whether they did. A refused charge changes nothing, so a
    /// smaller one can still follow.
    pub(crate) fn charge(&mut self, bytes: usize) -> bool {
        match &mut self.remaining {
            None => true,
            Some(remaining) => match remaining.checked_sub(bytes) {
                Some(left) => {
                    *remaining = left;
                    true
                },
                None => false,
            },
        }
    }
}

/// `text` cut to its first `max` bytes at a character boundary, with a marker when something was cut: what an error
/// message quotes under a budget, as the message is kept long after the buffers it quotes are given back.
pub(crate) fn excerpt(text: &str, max: usize) -> Cow<'_, str> {
    if text.len() <= max {
        return Cow::Borrowed(text);
    }
    let mut cut = text.get(..text.floor_char_boundary(max)).unwrap_or_default().to_owned();
    cut.push_str("...");
    Cow::Owned(cut)
}

/// The bytes of a name that a case-insensitive map may keep for one value: the lookup key and the original beside
/// the value, each up to four times as large when the name is not valid UTF-8 (its lossy text view is held too).
///
/// This reads the name, so callers use it only when a budget is set.
pub(crate) fn map_key_bytes(key: &[u8]) -> usize {
    let per_byte = if std::str::from_utf8(key).is_ok() {
        1
    } else {
        KEY_RETAINED_BYTES_PER_BYTE
    };
    key.len().saturating_mul(per_byte).saturating_mul(KEY_COPIES_PER_INSERT)
}

/// The bytes one value costs in one map, whether its key is new or repeated: the map's own overhead, which
/// `Map`'s tests check against the measured growth, plus `key_bytes` (see [`map_key_bytes`]) and the value.
pub(crate) fn insert_cost(key_bytes: usize, value_len: usize) -> usize {
    INSERT_OVERHEAD_BYTES
        .saturating_add(key_bytes)
        .saturating_add(value_len)
}

/// What one more value of `value_len` bytes under `key` takes from each of `maps`, together. A map that holds the
/// key adds the value, its spelling of the key when that is not the map's, and the growth of a full list; one that
/// does not adds the value, the key, the list it starts and the growth of a full table of keys.
pub(crate) fn insert_growth(maps: &[&Map], key: &[u8], value_len: usize) -> Growth {
    let value = Growth {
        grown: allocation_bytes(value_len),
        freed: 0,
    };
    maps.iter().fold(Growth::default(), |sum, map| {
        let lookup = map.lookup_key(key);
        let shape = map.value_list_shape(&lookup);
        let growth = if let Some(shape) = shape {
            list_growth(shape, 0, VALUE_ENTRY_BYTES, grown_list_capacity)
        } else {
            let table = map.new_key_table_growth();
            Growth {
                grown: table.grown.saturating_add(allocation_bytes(VALUE_ENTRY_BYTES)),
                ..table
            }
        };
        let stored = key_bytes(key, &lookup, shape.is_none());
        sum.plus(value).plus(growth).plus(stored)
    })
}

/// The largest lowercase copy any of `maps` makes of `key`, which only one of them holds at a time.
pub(crate) fn lookup_scratch_bytes(maps: &[&Map], key: &[u8]) -> usize {
    maps.iter().map(|map| map.lookup_scratch_bytes(key)).max().unwrap_or(0)
}

/// The growth of a list of `element`-byte slots that holds `len` values in `capacity` slots when it takes one more,
/// after `added` more have been added to it, none while it has room: the grown allocation, and the one it replaces.
/// `grow` is the capacity a full list grows to.
pub(crate) fn list_growth(
    (len, capacity): (usize, usize),
    added: usize,
    element: usize,
    grow: fn(usize, usize) -> usize,
) -> Growth {
    let (mut len, mut capacity, mut left) = (len, capacity.max(len), added);
    // Each step fills the slots there are and grows once, so the steps are as few as the growths.
    loop {
        let room = capacity.saturating_sub(len);
        if left < room {
            return Growth::default();
        }
        left = left.saturating_sub(room);
        len = capacity;
        let grown = grow(len, capacity);
        if left == 0 {
            return Growth {
                grown: allocation_bytes(grown.saturating_mul(element)),
                freed: allocation_bytes(capacity.saturating_mul(element)),
            };
        }
        capacity = grown;
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryBudget;

    #[test]
    fn an_unlimited_budget_accepts_everything_and_a_refused_charge_changes_nothing() {
        let mut unlimited = MemoryBudget::default();
        assert!(!unlimited.is_limited());
        assert!(unlimited.charge(usize::MAX));
        assert_eq!(unlimited.remaining(), None);

        let mut budget = MemoryBudget::new(Some(10));
        assert!(budget.charge(4));
        assert!(!budget.charge(7), "seven bytes do not fit in the six left");
        assert_eq!(budget.remaining(), Some(6), "a refused charge reserves nothing");
        assert!(budget.charge(6), "exactly what is left fits");
        assert!(!budget.charge(1));
    }

    #[test]
    fn a_key_is_charged_twice_over_and_four_times_that_when_it_is_not_utf8() {
        use super::{insert_cost, map_key_bytes};
        assert_eq!(map_key_bytes(b"abc"), 6);
        // Each invalid byte is held as itself and as a three-byte U+FFFD in the text view.
        assert_eq!(map_key_bytes(b"\xff\xff\xff"), 24);
        assert_eq!(map_key_bytes(b""), 0);
        // Arithmetic that would overflow saturates instead of wrapping into a small charge.
        assert_eq!(insert_cost(usize::MAX, usize::MAX), usize::MAX);
    }

    #[test]
    fn an_excerpt_is_cut_at_a_character_boundary_and_marked() {
        use super::excerpt;
        assert!(matches!(excerpt("abc", 3), std::borrow::Cow::Borrowed("abc")));
        assert_eq!(excerpt("abcd", 3), "abc...");
        // The third byte is inside the two-byte "é", so the cut falls before it.
        assert_eq!(excerpt("ab\u{e9}d", 3), "ab...");
    }

    #[test]
    fn an_insertion_is_charged_what_the_map_allocates_for_it() {
        use super::insert_growth;
        use crate::{collection::Map, types::RuleVariable};

        // Repeated keys that share the map's spelling or keep their own, lowercase forms that are longer, and keys
        // that are not UTF-8, until their lists grow by a quarter.
        let keys: [&[u8]; 8] = [
            b"a",
            b"A",
            "\u{e9}".as_bytes(),
            "\u{c9}".as_bytes(),
            "\u{23a}".as_bytes(),
            b"",
            b"k\xff",
            b"K\xff",
        ];
        for mut map in [
            Map::new(RuleVariable::Args),
            Map::new_case_sensitive(RuleVariable::Args),
        ] {
            for round in 0..1_500 {
                for key in keys {
                    let growth = insert_growth(&[&map], key, round % 3);
                    let before = map.allocated_bytes();
                    map.add_bytes(key, b"xy".get(..round % 3).unwrap_or_default());
                    let added = map.allocated_bytes() - before;
                    assert_eq!(added, growth.grown - growth.freed, "{key:?} after {round}");
                }
            }
        }
    }
}
