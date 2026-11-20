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

use crate::collection::{
    ALLOCATION_OVERHEAD_BYTES, INSERT_OVERHEAD_BYTES, KEY_COPIES_PER_INSERT, KEY_RETAINED_BYTES_PER_BYTE,
    allocation_bytes, grown_list_capacity,
};

/// The words every error a body processor reports for the memory budget has in it.
pub(crate) const BUDGET_ERROR_PHRASE: &str = "body memory budget";

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

/// The bytes of a name that a map keeps: the lookup key and, in a case-insensitive map, the original beside each
/// value, each up to four times as large when the name is not valid UTF-8 (its lossy text view is held too).
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

/// [`insert_cost`] of a value under `key`.
pub(crate) fn map_insert_cost(key: &[u8], value_len: usize) -> usize {
    insert_cost(map_key_bytes(key), value_len)
}

/// The bytes a value costs in a map that already holds its key, beside the growth of the key's list
/// (`list_growth`, see [`crate::collection::Map::value_list_growth_bytes`], none while the list has a free slot):
/// the allocation of the value and its own spelling of the key, which only a differing one or an invalid one
/// allocates.
pub(crate) fn repeated_insert_cost(key: &[u8], value_len: usize, list_growth: usize) -> usize {
    list_growth
        .saturating_add(2 * ALLOCATION_OVERHEAD_BYTES)
        .saturating_add(map_key_bytes(key) / KEY_COPIES_PER_INSERT)
        .saturating_add(value_len)
}

/// The bytes one argument costs once it is in `ARGS_POST` and `ARGS`, knowing, for each of the two maps, the growth its
/// list for the key needs, or `None` when it does not hold the key yet. A form with a field repeated for every value is
/// the case it is for.
pub(crate) fn argument_cost_in(key: &[u8], value_len: usize, in_post: Option<usize>, in_args: Option<usize>) -> usize {
    let cost = |growth: Option<usize>| match growth {
        Some(growth) => repeated_insert_cost(key, value_len, growth),
        None => map_insert_cost(key, value_len),
    };
    cost(in_post).saturating_add(cost(in_args))
}

/// How a list of values grows when it is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListGrowthPolicy {
    /// A `Vec`'s: double, and never fewer than four slots for an entry this small.
    Vec,
    /// A [`crate::collection::Map`]'s value list: a `Vec`'s, and by a quarter from 1,024.
    Map,
}

impl ListGrowthPolicy {
    /// The capacity a full list of `len` values in `capacity` slots grows to.
    fn grown(self, len: usize, capacity: usize) -> usize {
        match self {
            Self::Map => grown_list_capacity(len, capacity),
            Self::Vec => capacity.saturating_mul(2).max(len.saturating_add(1)).max(4),
        }
    }
}

/// What taking one more value costs a list that is full: the allocation of the grown list, which is held beside the
/// old one while the values move, and the old one, which is freed once they have.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ListGrowth {
    /// Bytes of the grown list's allocation, none while the list has room.
    pub(crate) grown: usize,
    /// Bytes of the old allocation that is freed by the growth and that the budget had been charged for.
    pub(crate) freed: usize,
}

/// The growth of a list that holds `len` values in `capacity` slots when it takes one more, after `added` more have
/// been added to it, none while it has room. `element` is the size of a slot.
///
/// This works from the capacity a list really has, and not from the one a budget would have given it. The
/// allocation the list starts as is one the budget has charged when `charged` says so, which is for a list the
/// walk makes and not for one that was there before; every one the growths after it make is charged by their own.
pub(crate) fn list_growth(
    (len, capacity): (usize, usize),
    added: usize,
    element: usize,
    policy: ListGrowthPolicy,
    charged: bool,
) -> ListGrowth {
    let (mut len, mut capacity, mut left) = (len, capacity.max(len), added);
    let mut charged = charged;
    // Each step fills the slots there are and grows once, so the steps are as few as the growths.
    loop {
        let room = capacity.saturating_sub(len);
        if left < room {
            return ListGrowth::default();
        }
        left = left.saturating_sub(room);
        len = capacity;
        let grown = policy.grown(len, capacity);
        if left == 0 {
            return ListGrowth {
                grown: allocation_bytes(grown.saturating_mul(element)),
                freed: if charged {
                    allocation_bytes(capacity.saturating_mul(element))
                } else {
                    0
                },
            };
        }
        capacity = grown;
        charged = true;
    }
}

/// The bytes the key of a value that is added to a map that holds it already takes, which is its own spelling
/// when that differs from the key the map files it under (a name with a capital, or one that is not UTF-8) and
/// nothing when it is the same, as the value then points to the map's key.
pub(crate) fn spelling_bytes(key: &[u8]) -> usize {
    if key.iter().all(|byte| byte.is_ascii() && !byte.is_ascii_uppercase()) {
        return 0;
    }
    (map_key_bytes(key) / KEY_COPIES_PER_INSERT).saturating_add(2 * ALLOCATION_OVERHEAD_BYTES)
}

/// The bytes the decoded name and value of a pair occupy while it is inserted, at most the raw pair's bytes, plus
/// the allocation overhead of each.
pub(crate) fn decode_scratch_cost(raw_key_len: usize, raw_value_len: usize) -> usize {
    raw_key_len
        .saturating_add(raw_value_len)
        .saturating_add(2 * ALLOCATION_OVERHEAD_BYTES)
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
        use super::{map_key_bytes, repeated_insert_cost};
        assert_eq!(map_key_bytes(b"abc"), 6);
        // Each invalid byte is held as itself and as a three-byte U+FFFD in the text view.
        assert_eq!(map_key_bytes(b"\xff\xff\xff"), 24);
        assert_eq!(map_key_bytes(b""), 0);
        // A repeated key costs less than a new one, as the entry and not the table is added.
        assert!(repeated_insert_cost(b"k", 1, 0) < super::map_insert_cost(b"k", 1));
        // Arithmetic that would overflow saturates instead of wrapping into a small charge.
        assert_eq!(super::insert_cost(usize::MAX, usize::MAX), usize::MAX);
        assert_eq!(super::argument_cost_in(b"k", usize::MAX, None, None), usize::MAX);
    }
}
