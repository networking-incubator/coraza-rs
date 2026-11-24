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

use std::{
    borrow::Cow,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed},
};

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

/// What the rules of a body phase may still hold, under the budget a connector set for it.
///
/// It is armed for the rules of one call of `process_request_body` or `process_response_body`, with what the budget
/// has left once that body is parsed, and disarmed after them. While it is armed, rule evaluation charges what it
/// allocates and keeps (a match with its text, the `TX` entries `setvar` and `capture` write, the values `MATCHED_VARS`
/// copies) before it allocates it, and stops, fail closed, at the first charge that does not fit. Disarmed, which is
/// the engine's behaviour without a connector budget, a charge is one branch that says yes.
///
/// A charge needs only `&self`, because rules select the values they inspect by borrowing the transaction, and the
/// bytes of a match are charged while that borrow is held.
#[derive(Debug, Default)]
pub(crate) struct RuleBudget {
    /// Whether a budget is in force.
    armed: bool,
    /// Bytes left while armed.
    remaining: AtomicUsize,
    /// Whether a charge did not fit, until the transaction is reset. It outlives the phase it ended, and arming the
    /// budget again for a later body phase keeps it: rule evaluation is over for the transaction, the logging phase
    /// included, since the request is already refused and a rule that ran would allocate with the budget spent.
    stopped: AtomicBool,
    /// What the rule being evaluated has charged for the matches it holds, which stay charged if it is recorded and
    /// are given back if it is not.
    pending: AtomicUsize,
    /// What the rule being evaluated has charged for copies and lists that are gone when it ends.
    scratch: AtomicUsize,
    /// What is charged for the entries of `MATCHED_VARS`, given back when the next rule clears them, and the table
    /// that held them before the budget was armed, which a clear keeps.
    matched_vars: AtomicUsize,
    /// The capture keys `TX:0` to `TX:9` that a rule removed since they were last made again, one bit for each. The
    /// removal gave back what they held, so the next capture or the reset before the next rule charges them if it has
    /// to make them again. It outlives the budget being armed, so later recreation is still accounted for.
    removed_captures: u16,
}

impl RuleBudget {
    /// Puts `remaining` bytes in force for the rules that follow. `matched_vars_table` is what the table of
    /// `MATCHED_VARS` already holds: it is not charged, and clearing the entries does not give it back.
    pub(crate) fn arm(&mut self, remaining: usize, matched_vars_table: usize) {
        self.armed = true;
        *self.remaining.get_mut() = remaining;
        *self.pending.get_mut() = 0;
        *self.scratch.get_mut() = 0;
        *self.matched_vars.get_mut() = matched_vars_table;
    }

    /// Notes that a rule removed `TX:key`, which matters if a later capture or rule reset must remake that key.
    pub(crate) fn note_removed(&mut self, key: &str) {
        if let [digit @ b'0'..=b'9'] = key.as_bytes() {
            self.removed_captures |= 1_u16.wrapping_shl(u32::from(digit.saturating_sub(b'0')));
        }
    }

    /// The capture keys removed since the last call, one bit for each, lowest for `TX:0`: the next capture or rule
    /// reset makes them again.
    pub(crate) fn take_removed_captures(&mut self) -> u16 {
        std::mem::take(&mut self.removed_captures)
    }

    /// Ends the budget of the rules of a phase; a stop stays reported.
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    /// Back to the state of a transaction that never had a budget.
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    /// Bytes left, which the rules of a test read.
    #[cfg(test)]
    pub(crate) fn remaining(&self) -> usize {
        self.remaining.load(Relaxed)
    }

    /// Whether a budget is in force.
    pub(crate) const fn is_armed(&self) -> bool {
        self.armed
    }

    /// Whether a charge was refused.
    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped.load(Relaxed)
    }

    /// Reserves `bytes` if they fit, and reports whether they did. A refused charge reserves nothing and stops the
    /// evaluation, and nothing fits after it: what the evaluation was about to do next is not done.
    pub(crate) fn charge(&self, bytes: usize) -> bool {
        if !self.armed {
            return true;
        }
        if self.stopped.load(Relaxed) {
            return false;
        }
        let Some(left) = self.remaining.load(Relaxed).checked_sub(bytes) else {
            self.stopped.store(true, Relaxed);
            return false;
        };
        self.remaining.store(left, Relaxed);
        true
    }

    /// Gives `bytes` back.
    pub(crate) fn refund(&self, bytes: usize) {
        if self.armed && bytes > 0 {
            add(&self.remaining, bytes);
        }
    }

    /// [`RuleBudget::charge`] for a match the rule being evaluated holds until it is recorded or dropped.
    pub(crate) fn charge_pending(&self, bytes: usize) -> bool {
        let fits = self.charge(bytes);
        if fits && self.armed {
            add(&self.pending, bytes);
        }
        fits
    }

    /// [`RuleBudget::charge`] for a copy or a list that is gone when the rule being evaluated ends.
    pub(crate) fn charge_scratch(&self, bytes: usize) -> bool {
        let fits = self.charge(bytes);
        if fits && self.armed {
            add(&self.scratch, bytes);
        }
        fits
    }

    /// [`RuleBudget::charge`] for what `MATCHED_VARS` copies: the peak of the change is charged, and what it frees
    /// given back at once.
    pub(crate) fn charge_matched_vars(&self, growth: Growth) -> bool {
        self.charge_growth(growth, &self.matched_vars)
    }

    /// [`RuleBudget::charge`] for a list that grows while the rule being evaluated builds it, and is gone when the
    /// rule ends: the peak of the growth, which holds the list beside the one it replaces, is charged before the
    /// list grows, and the old one given back at once, so that the list never holds more than the budget allowed.
    pub(crate) fn charge_scratch_growth(&self, growth: Growth) -> bool {
        self.charge_growth(growth, &self.scratch)
    }

    /// Charges the peak of `growth`, gives back what it frees, and files the net under `held`.
    fn charge_growth(&self, growth: Growth, held: &AtomicUsize) -> bool {
        let fits = self.charge(growth.grown);
        if fits && self.armed {
            self.refund(growth.freed);
            add(held, growth.grown.saturating_sub(growth.freed));
        }
        fits
    }

    /// Gives back what was charged for matches the rule being evaluated dropped.
    pub(crate) fn release_pending(&self, bytes: usize) {
        if self.armed {
            self.refund(take(&self.pending, bytes));
        }
    }

    /// Gives back what was charged for a copy the rule being evaluated has dropped before it is done.
    pub(crate) fn release_scratch(&self, bytes: usize) {
        if self.armed {
            self.refund(take(&self.scratch, bytes));
        }
    }

    /// The matches of the rule are recorded: what was charged for them stays charged.
    pub(crate) fn keep_pending(&self) {
        self.pending.store(0, Relaxed);
    }

    /// The rule is done: what it held that is gone is given back.
    pub(crate) fn end_rule(&self) {
        if self.armed {
            self.refund(take(&self.pending, usize::MAX));
            self.refund(take(&self.scratch, usize::MAX));
        }
    }

    /// `MATCHED_VARS` was cleared, and keeps `kept` bytes (the table that held its entries): the rest is given back.
    pub(crate) fn matched_vars_cleared(&self, kept: usize) {
        if self.armed {
            let charged = self.matched_vars.load(Relaxed);
            self.refund(charged.saturating_sub(kept));
            self.matched_vars.store(charged.min(kept), Relaxed);
        }
    }
}

/// Adds `bytes` to `counter`. Every charge comes from the one thread that evaluates the rules of a transaction, which
/// holds it mutably, so a load and a store do: the counters are atomic only so that a transaction stays `Sync`, and
/// the read-modify-write of an atomic would be paid on every charge.
fn add(counter: &AtomicUsize, bytes: usize) {
    counter.store(counter.load(Relaxed).saturating_add(bytes), Relaxed);
}

/// Takes up to `bytes` from `counter`, and returns what it took.
fn take(counter: &AtomicUsize, bytes: usize) -> usize {
    let held = counter.load(Relaxed);
    let taken = held.min(bytes);
    counter.store(held - taken, Relaxed);
    taken
}

/// What pushing one element of `element` bytes onto a `Vec` of `len` elements and `capacity` slots allocates, and what
/// it frees: nothing while there is room, and otherwise the list that replaces this one, which is held beside it for
/// the moment of the copy.
pub(crate) fn push_growth(len: usize, capacity: usize, element: usize) -> Growth {
    reserve_growth(len, capacity, 1, element)
}

/// [`push_growth`] for `additional` elements reserved at once, as `Vec::reserve` grows a list: to what it needs or
/// twice what it holds, whichever is more, and four slots at least.
pub(crate) fn reserve_growth(len: usize, capacity: usize, additional: usize, element: usize) -> Growth {
    let needed = len.saturating_add(additional);
    if needed <= capacity {
        return Growth::default();
    }
    let grown = capacity.saturating_mul(2).max(needed).max(4);
    Growth {
        grown: allocation_bytes(grown.saturating_mul(element)),
        freed: allocation_bytes(capacity.saturating_mul(element)),
    }
}

/// What `Map::set` of one value of `len` bytes under `key` allocates: the list of one that replaces the key's values,
/// or starts them, the spelling of the key when it is not the one the map files it under, the value, and for a key the
/// map does not hold the key itself and the growth of its table, whose old table is what `freed` is. What the values it
/// replaces held is what `Map::set` returns, to be given back with it once they are gone.
pub(crate) fn set_growth(map: &Map, key: &[u8], len: usize) -> Growth {
    let lookup = map.lookup_key(key);
    let key_part = if map.value_list_shape(&lookup).is_some() {
        LIST_OF_ONE.plus(key_bytes(key, &lookup, false))
    } else {
        new_key_growth(map, key, &lookup, 0)
    };
    key_part.plus(Growth {
        grown: allocation_bytes(len),
        freed: 0,
    })
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
    values_growth_filed(map, key, &map.lookup_key(key), lens)
}

/// [`values_growth`] for a key that `map` files under `lookup`, which the caller has already worked out.
pub(crate) fn values_growth_filed(
    map: &Map,
    key: &[u8],
    lookup: &[u8],
    lens: impl IntoIterator<Item = usize>,
) -> Growth {
    let shape = map.value_list_shape(lookup);
    let spelling = key_bytes(key, lookup, false);
    lens.into_iter()
        .enumerate()
        .fold(Growth::default(), |sum, (added, len)| {
            let growth = match value_list_growth(shape, added) {
                (_, true) => new_key_growth(map, key, lookup, 0),
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
    fn a_rule_budget_charges_only_while_armed_and_gives_back_what_a_rule_did_not_keep() {
        use super::RuleBudget;

        let mut budget = RuleBudget::default();
        assert!(
            budget.charge(usize::MAX) && !budget.is_stopped(),
            "disarmed, everything fits"
        );

        budget.arm(100, 0);
        assert!(budget.charge_pending(30) && budget.charge_scratch(20) && budget.charge(10));
        assert_eq!(budget.remaining.load(super::Relaxed), 40);
        // The rule is recorded: its matches stay charged, its copies are given back.
        budget.keep_pending();
        budget.end_rule();
        assert_eq!(budget.remaining.load(super::Relaxed), 60);
        // The next rule is dropped: both are given back.
        assert!(budget.charge_pending(25) && budget.charge_scratch(5));
        budget.end_rule();
        assert_eq!(budget.remaining.load(super::Relaxed), 60);
        // A match dropped inside a rule gives its bytes back at once, once.
        assert!(budget.charge_pending(40));
        budget.release_pending(40);
        budget.release_pending(40);
        assert_eq!(budget.remaining.load(super::Relaxed), 60);
        // A copy dropped before the rule is done gives back what it was charged, and no more than the rule holds.
        assert!(budget.charge_scratch(30) && budget.charge_scratch(10));
        budget.release_scratch(30);
        assert_eq!(budget.remaining.load(super::Relaxed), 50);
        budget.release_scratch(30);
        assert_eq!(
            budget.remaining.load(super::Relaxed),
            60,
            "the ten left are all it can give back"
        );
        budget.end_rule();
        assert_eq!(budget.remaining.load(super::Relaxed), 60);

        assert!(!budget.is_stopped());
        assert!(!budget.charge(61), "sixty-one bytes do not fit in sixty");
        assert!(budget.is_stopped(), "the refusal is remembered");
        assert_eq!(budget.remaining.load(super::Relaxed), 60, "and reserved nothing");
        assert!(!budget.charge(1), "nothing fits after a stop, however small");

        budget.disarm();
        assert!(
            budget.charge(usize::MAX) && budget.is_stopped(),
            "a stop outlives the phase"
        );
        budget.reset();
        assert!(!budget.is_stopped() && !budget.is_armed());
    }

    #[test]
    fn what_a_map_holds_for_a_key_is_given_back_when_a_rule_replaces_it() {
        use super::set_growth;
        use crate::{collection::Map, types::RuleVariable};

        // New keys and rewritten ones, longer values and shorter, a key in capitals, one that is not UTF-8.
        let keys: [&[u8]; 4] = [b"a", b"Beta", b"k\xff", b"0"];
        let sizes = [0_usize, 1, 7, 300, 3, 70_000, 2];
        let mut map = Map::new(RuleVariable::TX);
        for round in 0..400 {
            for key in keys {
                let len = sizes.get(round % sizes.len()).copied().unwrap_or_default();
                let growth = set_growth(&map, key, len);
                let before = map.allocated_bytes();
                let replaced = map.set(key, [vec![b'x'; len]]);
                let after = map.allocated_bytes();
                // What is charged for the write, net of what it replaces, is what the map then holds more, a
                // little over where the replaced list's spare slots go.
                let net = growth.grown.cast_signed() - (growth.freed + replaced).cast_signed();
                let held = after.cast_signed() - before.cast_signed();
                assert!(
                    held <= net && net <= held + 64,
                    "{key:?} at round {round}: {held} more held, {net} charged"
                );
            }
        }
    }

    #[test]
    fn a_list_that_grows_is_charged_the_one_that_replaces_it_and_gives_back_the_old() {
        use super::{push_growth, reserve_growth};

        for (len, capacity) in [(0_usize, 0_usize), (3, 4), (4, 4), (9, 16), (16, 16), (1_000, 1_000)] {
            let mut list: Vec<u64> = Vec::with_capacity(capacity);
            list.resize(len, 0);
            let growth = push_growth(len, list.capacity(), size_of::<u64>());
            let held = super::allocation_bytes(list.capacity() * size_of::<u64>());
            list.push(0);
            let after = super::allocation_bytes(list.capacity() * size_of::<u64>());
            assert_eq!(
                growth.grown.saturating_sub(growth.freed),
                after - held,
                "{len} in {capacity}"
            );
            assert!(growth.freed == 0 || growth.freed == held, "{len} in {capacity}");
        }
        // Reserving several at once grows to what is needed, or twice what is held.
        let mut list: Vec<u64> = Vec::new();
        list.extend_from_slice(&[1, 2, 3]);
        let growth = reserve_growth(list.len(), list.capacity(), 100, size_of::<u64>());
        list.reserve(100);
        assert_eq!(
            growth.grown,
            super::allocation_bytes(list.capacity() * size_of::<u64>())
        );
        assert_eq!(
            reserve_growth(list.len(), list.capacity(), 1, size_of::<u64>()).grown,
            0,
            "there is room"
        );
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
