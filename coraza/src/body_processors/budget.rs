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

use crate::collection::{Growth, Map, VALUE_ENTRY_BYTES, allocation_bytes, grown_list_capacity, key_bytes};

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
    #[cfg(test)]
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

/// What one more value of `value_len` bytes under `key` takes from each of `maps`, together (see [`values_growth`]).
pub(crate) fn insert_growth(maps: &[&Map], key: &[u8], value_len: usize) -> Growth {
    maps.iter().fold(Growth::default(), |sum, map| {
        sum.plus(values_growth(map, key, [value_len]))
    })
}

/// What `map` allocates for values of the lengths `lens` added under `key` in turn.
pub(crate) fn values_growth(map: &Map, key: &[u8], lens: impl IntoIterator<Item = usize>) -> Growth {
    let lookup = map.lookup_key(key);
    let shape = map.value_list_shape(&lookup);
    let spelling = key_bytes(key, &lookup, false);
    lens.into_iter()
        .enumerate()
        .fold(Growth::default(), |sum, (added, len)| {
            let growth = match value_list_growth(shape, added) {
                (_, true) => new_key_growth(map, key, &lookup, 0),
                (list, false) => list.plus(spelling),
            };
            sum.plus(growth).plus(Growth {
                grown: allocation_bytes(len),
                freed: 0,
            })
        })
}

/// What `Map::set_index` at index 0 allocates in `map` for each of `keys` in turn, rewriting a filed key in place.
pub(crate) fn first_values_growth<'k>(map: &Map, keys: impl IntoIterator<Item = &'k [u8]>, value_len: usize) -> Growth {
    let (mut new_keys, mut last_new) = (0, None);
    keys.into_iter().fold(Growth::default(), |sum, key| {
        let lookup = map.lookup_key(key);
        // Filed like the last new key, told without a second lowercase copy, as one copy is charged.
        let repeat = last_new.is_some_and(|new| map.files_under(new, &lookup));
        let growth = if repeat || map.value_list_shape(&lookup).is_some() {
            key_bytes(key, &lookup, false)
        } else {
            new_keys += 1;
            last_new = Some(key);
            new_key_growth(map, key, &lookup, new_keys - 1)
        };
        sum.plus(growth).plus(Growth {
            grown: allocation_bytes(value_len),
            freed: 0,
        })
    })
}

/// What a key `map` does not hold takes for its first value besides the value: the key, the list of one it starts, and
/// the growth of a full table after `earlier` other keys new to it.
fn new_key_growth(map: &Map, key: &[u8], lookup: &[u8], earlier: usize) -> Growth {
    map.new_key_table_growth(earlier)
        .plus(LIST_OF_ONE)
        .plus(key_bytes(key, lookup, true))
}

/// The list of one value that a key's first value starts.
const LIST_OF_ONE: Growth = Growth {
    grown: allocation_bytes(VALUE_ENTRY_BYTES),
    freed: 0,
};

/// What one more value takes from the list of its key's values that a map holds in `shape` (`None` when it holds no
/// list for the key) after `added` more were added to it, and whether it is the key's first value: that one starts a
/// list of one, which the next ones are added to.
pub(crate) fn value_list_growth(shape: Option<(usize, usize)>, added: usize) -> (Growth, bool) {
    let grow = |shape, added| list_growth(shape, added, VALUE_ENTRY_BYTES, grown_list_capacity);
    match shape {
        Some(shape) => (grow(shape, added), false),
        None if added == 0 => (LIST_OF_ONE, true),
        None => (grow((1, 1), added - 1), false),
    }
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
    fn an_excerpt_is_cut_at_a_character_boundary_and_marked() {
        use super::excerpt;
        assert!(matches!(excerpt("abc", 3), std::borrow::Cow::Borrowed("abc")));
        assert_eq!(excerpt("abcd", 3), "abc...");
        // The third byte is inside the two-byte "é", so the cut falls before it.
        assert_eq!(excerpt("ab\u{e9}d", 3), "ab...");
    }

    #[test]
    fn values_are_charged_what_the_map_allocates_for_them() {
        use super::values_growth;
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
        let three: [&[u8]; 3] = [b"", b"x", b"xy"];
        for mut map in [
            Map::new(RuleVariable::Args),
            Map::new_case_sensitive(RuleVariable::Args),
        ] {
            for round in 0..1_500 {
                for key in keys {
                    // One to three values at a time.
                    let values = three.get(..=round % 3).unwrap_or_default();
                    let growth = values_growth(&map, key, values.iter().map(|value| value.len()));
                    let before = map.allocated_bytes();
                    for value in values {
                        map.add_bytes(key, value);
                    }
                    let added = map.allocated_bytes() - before;
                    assert_eq!(added, growth.grown - growth.freed, "{key:?} after {round}");
                }
            }
        }
    }

    #[test]
    fn first_values_set_in_turn_are_charged_what_the_map_allocates_for_them() {
        use super::first_values_growth;
        use crate::{collection::Map, types::RuleVariable};

        // Each round a new name, then one new every other round, so either can be the one the table grows for.
        let mut map = Map::new(RuleVariable::FilesSizes);
        for round in 0..1_000_usize {
            let names = [format!("new{round}"), format!("Held{}", round / 2)];
            let growth = first_values_growth(&map, names.iter().map(String::as_bytes), 20);
            let before = map.allocated_bytes();
            for name in &names {
                map.set_index(name, 0, round.to_string());
            }
            let (added, charged) = (map.allocated_bytes() - before, growth.grown - growth.freed);
            // A held name is charged a new value and spelling, which its rewrite in place does not need.
            assert!(
                added <= charged && charged <= added + 64,
                "{names:?}: {added} allocated, {charged} charged"
            );
        }

        // A `filename` and a `filename*` that fold alike are one key, which the second rewrites in place, whichever
        // needs a lowercase copy, and two keys otherwise (`ß` has no simple lowercase form).
        for names in [
            [b"A.TXT".as_slice(), b"a.txt"],
            [b"a.txt", b"A.TXT"],
            [b"Q1.txt", b"q1.TXT"],
            ["\u{c9}.TXT".as_bytes(), "\u{e9}.txt".as_bytes()],
            [b"k\xff.txt", b"K\xff.TXT"],
            [b"SS.txt", "\u{df}.txt".as_bytes()],
        ] {
            let mut map = Map::new(RuleVariable::FilesSizes);
            let growth = first_values_growth(&map, names, 20);
            for name in names {
                map.set_index(name, 0, "1");
            }
            let (added, charged) = (map.allocated_bytes(), growth.grown - growth.freed);
            assert!(
                added <= charged && charged <= added + 64,
                "{names:?}: {added} allocated, {charged} charged"
            );
        }
    }
}
