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
//
// This port is based on the original Coraza, created by Juan Pablo Tosso and
// the OWASP Coraza contributors.
//
// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Map collection implementation.
//!
//! Provides key-value storage with optional case-insensitive keys.
//! Multiple values per key are supported, and iteration follows insertion order.
//!
//! Keys are byte strings, so decoded names stay distinct even when they are not valid
//! UTF-8. This is a deliberate deviation from Go, whose `strings.ToLower` folds every invalid
//! byte through `unicode.ToLower(RuneError)` and merges `X\xff` and `X\xfe` into one entry.
//! Text interfaces use the lossy view described on [`Map::iter`]; they never decide which
//! entries exist.

use std::{borrow::Cow, hash::Hash, mem::size_of};

use indexmap::IndexMap;
use regex::Regex;

use crate::{transformations::text_of, types::RuleVariable};

/// A key-value collection that supports multiple values per key.
///
/// # Case Sensitivity
///
/// By default, keys are case-insensitive (useful for HTTP headers).
/// Use `new_case_sensitive()` for case-sensitive keys (useful for query parameters).
///
/// # Original Key Preservation
///
/// Even when using case-insensitive mode, the original key bytes are preserved
/// and returned in `MatchData` results.
pub struct Map {
    /// Whether keys are case-sensitive
    case_sensitive: bool,
    /// Internal storage from `lookup_key` to `Vec<KeyValue>`, in insertion order.
    /// Keys are lowercase for case-insensitive maps.
    data: IndexMap<Key, Vec<KeyValue>, ahash::RandomState>,
    /// The variable this collection represents
    variable: RuleVariable,
    /// Total values across all keys, kept in step with `data` by every mutator so that
    /// [`Map::value_count`] is O(1). Argument-limit checks call it once per added argument.
    ///
    /// A `u32` fills the padding after the two small fields, so `Map` and the transaction that embeds
    /// dozens of them do not grow: a full word per map measurably slowed short requests. It saturates, which
    /// four billion values of memory would never reach.
    values: u32,
}

// The counter must stay in the padding, see `Map::values`. (On 32-bit targets a word is as small as the counter, so
// there is no padding to use and no measurement behind the layout.)
#[cfg(target_pointer_width = "64")]
const _: () = assert!(
    size_of::<Map>() <= size_of::<IndexMap<Key, Vec<KeyValue>, ahash::RandomState>>() + size_of::<usize>(),
    "the value counter must fit the padding after the map's small fields"
);

/// The most a heap allocator keeps beyond the bytes asked for, for charging an allocation whose size is not
/// known yet.
///
/// A small allocation costs far more than its payload: glibc rounds a request up to a 16-byte unit after an
/// eight-byte header and never gives less than 32 bytes, and dlmalloc, which backs the WASI build, is only
/// slightly smaller. Without this a million one-byte values would be reported as one megabyte while holding
/// thirty-two.
pub(crate) const ALLOCATION_OVERHEAD_BYTES: usize = 32;

/// Bytes the allocation behind `capacity` occupies, none for an empty one: the chunk a request of that size is
/// rounded up to, the worst of the allocators the engine runs on.
pub(crate) const fn allocation_bytes(capacity: usize) -> usize {
    if capacity == 0 {
        return 0;
    }
    let rounded = capacity.saturating_add(8).div_ceil(16).saturating_mul(16);
    if rounded < 32 { 32 } else { rounded }
}

/// A key that is not valid UTF-8: its bytes, which stay authoritative, and the text view computed once for the
/// text interfaces.
#[derive(Debug, Clone)]
struct ByteKey {
    /// The key bytes, exactly as stored.
    bytes: Box<[u8]>,
    /// The text view, invalid UTF-8 replaced with U+FFFD.
    lossy: String,
}

impl ByteKey {
    /// Stores `bytes`, which are not valid UTF-8.
    fn new(bytes: &[u8]) -> Self {
        // The lossy text grows by pushing, which can leave up to twice the capacity it needs. Trim it so a key
        // costs the raw bytes plus at most three bytes per invalid byte, which is what
        // `KEY_RETAINED_BYTES_PER_BYTE` charges.
        let mut lossy = String::from_utf8_lossy(bytes).into_owned();
        lossy.shrink_to_fit();
        Self {
            bytes: bytes.into(),
            lossy,
        }
    }

    /// Bytes held by this key's allocations.
    fn allocated_bytes(&self) -> usize {
        allocation_bytes(size_of::<Self>())
            .saturating_add(allocation_bytes(self.bytes.len()))
            .saturating_add(allocation_bytes(self.lossy.capacity()))
    }
}

/// A stored key.
///
/// Keys that arrived as text stay `Text`, so the common path keeps a single allocation and a
/// borrowed text view. Raw byte keys keep their bytes authoritative; their lossy text is
/// computed once for the text interfaces.
#[derive(Debug, Clone)]
enum Key {
    /// A valid UTF-8 key, with its original casing.
    Text(String),
    /// A byte key that is not valid UTF-8. Boxed so every key stays three words: this is rare.
    Bytes(Box<ByteKey>),
}

impl Key {
    /// Stores `bytes`, keeping their exact spelling.
    fn from_slice(bytes: &[u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok(text) => Self::Text(text.to_owned()),
            Err(_) => Self::Bytes(Box::new(ByteKey::new(bytes))),
        }
    }

    /// The key bytes.
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Text(text) => text.as_bytes(),
            Self::Bytes(key) => &key.bytes,
        }
    }

    /// The text view, invalid UTF-8 replaced with U+FFFD.
    fn text(&self) -> &str {
        match self {
            Self::Text(text) => text,
            Self::Bytes(key) => &key.lossy,
        }
    }

    /// Bytes held by this key's string or byte backing allocations.
    fn allocated_bytes(&self) -> usize {
        match self {
            Self::Text(text) => allocation_bytes(text.capacity()),
            Self::Bytes(key) => key.allocated_bytes(),
        }
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Key {}

impl Hash for Key {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl std::borrow::Borrow<[u8]> for Key {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// The original spelling of the key a value was added under, kept beside the value.
///
/// A value almost always carries the same bytes as the key its map files it under (always, in a case-sensitive
/// map), and a repeated key such as `/*` or an array's path is added once per value, so storing the spelling
/// again for each one made keys cost as much as the data. `Text("")` therefore means "the map key": an empty
/// key spells itself, so the empty string cannot also be a differing spelling. Only a case-insensitive map's
/// differently cased key, or one with invalid bytes, is stored, and it is the only case that allocates.
///
/// The two variants share the niche of the text's pointer, so this is two words.
#[derive(Debug, Clone)]
enum Spelling {
    /// A valid UTF-8 spelling that differs from the map key, or `""` for the map key itself.
    Text(Box<str>),
    /// A spelling that is not valid UTF-8, and differs from the map key.
    Bytes(Box<ByteKey>),
}

impl Spelling {
    /// The spelling of `key` under a map key of `map_key` bytes.
    fn new(key: &[u8], map_key: &[u8]) -> Self {
        if key == map_key {
            return Self::default();
        }
        match std::str::from_utf8(key) {
            Ok(text) => Self::Text(text.into()),
            Err(_) => Self::Bytes(Box::new(ByteKey::new(key))),
        }
    }

    /// The key bytes, `map_key` when this value shares it.
    fn as_bytes<'a>(&'a self, map_key: &'a Key) -> &'a [u8] {
        match self {
            Self::Text(text) if text.is_empty() => map_key.as_bytes(),
            Self::Text(text) => text.as_bytes(),
            Self::Bytes(key) => &key.bytes,
        }
    }

    /// The text view, invalid UTF-8 replaced with U+FFFD.
    fn text<'a>(&'a self, map_key: &'a Key) -> &'a str {
        match self {
            Self::Text(text) if text.is_empty() => map_key.text(),
            Self::Text(text) => text,
            Self::Bytes(key) => &key.lossy,
        }
    }

    /// Whether this is `key`, given the map key it is filed under.
    fn is(&self, key: &[u8], map_key: &Key) -> bool {
        self.as_bytes(map_key) == key
    }

    /// Bytes held by this spelling's allocations.
    fn allocated_bytes(&self) -> usize {
        match self {
            Self::Text(text) => allocation_bytes(text.len()),
            Self::Bytes(key) => key.allocated_bytes(),
        }
    }
}

impl Default for Spelling {
    /// The map key itself.
    fn default() -> Self {
        Self::Text(Box::default())
    }
}

// Both must stay small: a `KeyValue` is allocated per value, and a million-value body holds a million of them.
const _: () = assert!(size_of::<Key>() == 3 * size_of::<usize>(), "a key is three words");
const _: () = assert!(
    size_of::<Spelling>() == 2 * size_of::<usize>(),
    "a spelling is a pointer and a length, the other variant fits in the niche"
);

/// Internal storage for a key-value pair.
///
/// Preserves the original key bytes and casing even when the map is case-insensitive. Values
/// are read and written as bytes; only this type knows how they are stored. The key is the map's own unless
/// it differs, see [`Spelling`], so resolving it takes the key the pair is filed under.
#[derive(Debug, Clone)]
struct KeyValue {
    /// Original key (with original casing), unless it is the map key.
    spelling: Spelling,
    /// Value
    value: Vec<u8>,
}

impl KeyValue {
    /// Creates a stored key/value pair filed under `map_key`.
    fn new(key: &[u8], map_key: &[u8], value: &[u8]) -> Self {
        Self::owned(key, map_key, Self::stored(value))
    }

    /// Creates a stored key/value pair that takes `value` without copying it.
    fn owned(key: &[u8], map_key: &[u8], value: Vec<u8>) -> Self {
        Self {
            spelling: Spelling::new(key, map_key),
            value,
        }
    }

    /// How `value` is stored.
    fn stored(value: &[u8]) -> Vec<u8> {
        value.to_vec()
    }

    /// Returns the stored bytes.
    fn value(&self) -> &[u8] {
        &self.value
    }

    /// The key bytes, given the key this pair is filed under.
    fn key_bytes<'a>(&'a self, map_key: &'a Key) -> &'a [u8] {
        self.spelling.as_bytes(map_key)
    }

    /// The key text, given the key this pair is filed under.
    fn key_text<'a>(&'a self, map_key: &'a Key) -> &'a str {
        self.spelling.text(map_key)
    }

    /// The value as text, invalid UTF-8 replaced with U+FFFD.
    fn text(&self) -> Cow<'_, str> {
        text_of(self.value())
    }

    /// Replaces the key and value, reusing their buffers.
    fn replace(&mut self, key: &[u8], map_key: &Key, value: &[u8]) {
        if !self.spelling.is(key, map_key) {
            self.spelling = Spelling::new(key, map_key.as_bytes());
        }
        self.value.clear();
        self.value.extend_from_slice(value);
    }

    /// Bytes held by this pair's allocations.
    fn allocated_bytes(&self) -> usize {
        self.spelling
            .allocated_bytes()
            .saturating_add(allocation_bytes(self.value.capacity()))
    }
}

/// Bytes of one value's entry in its key's list.
pub(crate) const VALUE_ENTRY_BYTES: usize = size_of::<KeyValue>();

/// The capacity a value list of `len` values and `capacity` slots grows to when one more is added to it, as
/// [`push_grown`] grows it.
pub(crate) fn grown_list_capacity(len: usize, capacity: usize) -> usize {
    if len >= EXACT_GROWTH_FROM {
        len.saturating_add(len / 4)
    } else {
        // `Vec`'s amortized growth: double, and never fewer than four slots for an entry this small.
        capacity.saturating_mul(2).max(len.saturating_add(1)).max(4)
    }
}

/// The length from which a value vector grows by a quarter instead of doubling, see [`push_grown`].
const EXACT_GROWTH_FROM: usize = 1024;

/// Appends `kv`, growing a long vector by a quarter rather than doubling it.
///
/// A key that repeats, such as `REQUEST_XML`'s `/*`, can hold millions of values, and a vector that doubles keeps
/// up to twice what it uses, which at a 40-byte entry is the larger part of what a flood of tiny values costs. The
/// shorter vectors headers and arguments make double as `Vec` does.
fn push_grown(values: &mut Vec<KeyValue>, kv: KeyValue) {
    if values.len() == values.capacity() && values.len() >= EXACT_GROWTH_FROM {
        values.reserve_exact(values.len() / 4);
    }
    values.push(kv);
}

/// A value count as the counter's type.
fn count_of(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

/// Lower-cases the valid UTF-8 parts of `key` and copies bytes that are not UTF-8 unchanged,
/// so distinct invalid byte sequences stay distinct.
fn lower_bytes(key: &[u8]) -> Vec<u8> {
    let mut lowered = Vec::with_capacity(key.len());
    let mut rest = key;
    loop {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                push_lowercase(&mut lowered, text);
                return lowered;
            },
            Err(error) => {
                let valid = error.valid_up_to();
                if let Some(prefix) = rest.get(..valid).and_then(|bytes| std::str::from_utf8(bytes).ok()) {
                    push_lowercase(&mut lowered, prefix);
                }
                let invalid_len = error.error_len().unwrap_or_else(|| rest.len().saturating_sub(valid));
                let end = valid.saturating_add(invalid_len).min(rest.len());
                if let Some(bytes) = rest.get(valid..end) {
                    lowered.extend_from_slice(bytes);
                }
                rest = rest.get(end..).unwrap_or_default();
            },
        }
    }
}

/// Appends `text` to `out`, lower-cased the way Go folds collection keys.
fn push_lowercase(out: &mut Vec<u8>, text: &str) {
    // Go's `strings.ToLower` is the simple mapping, not Rust's full one, so both the
    // stored keys and the lookups go through the shared helper. This path runs per key, so
    // it writes in place instead of allocating a `String`.
    crate::utils::lowercase::push_lowercase_like_go(out, text);
}

impl Map {
    /// Create a new map with case-insensitive keys.
    ///
    /// This is the default for collections like `REQUEST_HEADERS`.
    pub(crate) fn new(variable: RuleVariable) -> Self {
        Self {
            case_sensitive: false,
            data: IndexMap::with_hasher(ahash::RandomState::new()),
            variable,
            values: 0,
        }
    }

    /// Create a new map with case-sensitive keys.
    ///
    /// This is used for collections like `ARGS`, `ARGS_GET`, and `ARGS_POST`.
    pub(crate) fn new_case_sensitive(variable: RuleVariable) -> Self {
        Self {
            case_sensitive: true,
            data: IndexMap::with_hasher(ahash::RandomState::new()),
            variable,
            values: 0,
        }
    }

    /// The key `key` is stored under: as it is in a case-sensitive map, lowercase otherwise.
    /// Borrowed when that is `key` itself, which spares lookups an allocation.
    fn lookup_key<'k>(&self, key: &'k [u8]) -> Cow<'k, [u8]> {
        if self.case_sensitive || !key.iter().any(|b| b.is_ascii_uppercase() || !b.is_ascii()) {
            Cow::Borrowed(key)
        } else {
            Cow::Owned(lower_bytes(key))
        }
    }

    /// Every key, with its original casing, and value, in insertion order.
    ///
    /// Keyless selections walk the map in this order, so the last keyless match (and the
    /// `MATCHED_VAR` that follows it) reflects collection order: deterministic across runs,
    /// but still influenceable by reordering the parameters that built the collection.
    ///
    /// This is a lossy text view: keys that are not valid UTF-8 have their invalid bytes
    /// replaced with U+FFFD. Distinct byte keys still yield one entry each, so no entry is
    /// merged or dropped; `Map::iter_bytes` gives the key bytes.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> + '_ {
        self.data
            .iter()
            .flat_map(|(map_key, values)| values.iter().map(move |kv| (kv.key_text(map_key), kv.value())))
    }

    /// Every key, exactly as stored, and value, in insertion order.
    #[cfg(test)]
    pub(crate) fn iter_bytes(&self) -> impl Iterator<Item = (&[u8], &[u8])> + '_ {
        self.data
            .iter()
            .flat_map(|(map_key, values)| values.iter().map(move |kv| (kv.key_bytes(map_key), kv.value())))
    }

    /// Every key and value with its stable map-entry/value position.
    pub(crate) fn iter_bytes_indexed(&self) -> impl Iterator<Item = (usize, usize, &[u8], &[u8])> + '_ {
        self.data
            .iter()
            .enumerate()
            .flat_map(|(entry_index, (map_key, values))| {
                values
                    .iter()
                    .enumerate()
                    .map(move |(value_index, kv)| (entry_index, value_index, kv.key_bytes(map_key), kv.value()))
            })
    }

    /// The keys and values stored under `key` (whatever its case, in a case-insensitive map).
    ///
    /// The returned keys are the lossy text view described on [`Map::iter`].
    pub fn iter_key(&self, key: impl AsRef<[u8]>) -> impl Iterator<Item = (&str, &[u8])> + '_ {
        let lookup = self.lookup_key(key.as_ref());
        self.data
            .get_key_value(lookup.as_ref())
            .into_iter()
            .flat_map(|(map_key, values)| values.iter().map(move |kv| (kv.key_text(map_key), kv.value())))
    }

    /// Values under a folded key with their stable map-entry/value position.
    pub(crate) fn iter_key_bytes_indexed(&self, key: &[u8]) -> impl Iterator<Item = (usize, usize, &[u8], &[u8])> + '_ {
        let lookup = self.lookup_key(key);
        self.data
            .get_full(lookup.as_ref())
            .into_iter()
            .flat_map(|(entry_index, map_key, values)| {
                values
                    .iter()
                    .enumerate()
                    .map(move |(value_index, kv)| (entry_index, value_index, kv.key_bytes(map_key), kv.value()))
            })
    }

    /// The keys and values stored under the exact `key` bytes, without folding.
    ///
    /// A case-insensitive map is keyed by the folded bytes and a case-sensitive map by the
    /// raw bytes, so one exact lookup covers both. Nothing is allocated on this path.
    #[cfg(test)]
    pub(crate) fn iter_key_exact(&self, key: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> + '_ {
        self.data
            .get_key_value(key)
            .into_iter()
            .flat_map(|(map_key, values)| values.iter().map(move |kv| (kv.key_bytes(map_key), kv.value())))
    }

    /// Values under an exact key with their stable map-entry/value position.
    pub(crate) fn iter_key_exact_indexed(&self, key: &[u8]) -> impl Iterator<Item = (usize, usize, &[u8], &[u8])> + '_ {
        self.data
            .get_full(key)
            .into_iter()
            .flat_map(|(entry_index, map_key, values)| {
                values
                    .iter()
                    .enumerate()
                    .map(move |(value_index, kv)| (entry_index, value_index, kv.key_bytes(map_key), kv.value()))
            })
    }

    /// Return one selected value by its stable map-entry/value position.
    pub(crate) fn value_at(&self, entry_index: usize, value_index: usize, names: bool) -> Option<(&[u8], &[u8])> {
        let (map_key, values) = self.data.get_index(entry_index)?;
        let value = values.get(value_index)?;
        let key = value.key_bytes(map_key);
        Some((key, if names { key } else { value.value() }))
    }

    /// The keys and values whose (lookup) key matches `regex`.
    ///
    /// The regex runs on the lossy text view described on [`Map::iter`]; matches are still
    /// reported once per stored byte key.
    pub fn iter_regex<'a>(&'a self, regex: &'a Regex) -> impl Iterator<Item = (&'a str, &'a [u8])> {
        self.data
            .iter()
            .filter(|(lookup_key, _)| regex.is_match(lookup_key.text()))
            .flat_map(|(map_key, values)| values.iter().map(move |kv| (kv.key_text(map_key), kv.value())))
    }

    /// Keys and values matching `regex`, with stable map-entry/value positions.
    pub(crate) fn iter_regex_bytes_indexed<'a>(
        &'a self,
        regex: &'a Regex,
    ) -> impl Iterator<Item = (usize, usize, &'a [u8], &'a [u8])> {
        self.data
            .iter()
            .enumerate()
            .filter(move |(_, (lookup_key, _))| regex.is_match(lookup_key.text()))
            .flat_map(|(entry_index, (map_key, values))| {
                values
                    .iter()
                    .enumerate()
                    .map(move |(value_index, kv)| (entry_index, value_index, kv.key_bytes(map_key), kv.value()))
            })
    }

    /// Name of the variable this map holds (e.g. `ARGS`).
    pub fn name(&self) -> &str {
        self.variable.name()
    }

    /// The variable this map holds.
    pub fn variable(&self) -> RuleVariable {
        self.variable
    }

    /// The values of `key`; none if the key is absent.
    pub fn values(&self, key: impl AsRef<[u8]>) -> impl Iterator<Item = &[u8]> + '_ {
        let lookup = self.lookup_key(key.as_ref());
        self.data
            .get(lookup.as_ref())
            .into_iter()
            .flatten()
            .map(KeyValue::value)
    }

    /// All values for `key` as text, invalid UTF-8 replaced with U+FFFD; empty if the key
    /// is absent. [`Map::values`] gives them as they are.
    pub fn get(&self, key: impl AsRef<[u8]>) -> Vec<String> {
        let lookup = self.lookup_key(key.as_ref());
        self.data
            .get(lookup.as_ref())
            .map(|values| values.iter().map(|kv| kv.text().into_owned()).collect())
            .unwrap_or_default()
    }

    /// The first value of `key`; `None` if the key is absent.
    pub fn first(&self, key: impl AsRef<[u8]>) -> Option<&[u8]> {
        self.values(key).next()
    }

    /// Appends `value` to the values of `key`.
    pub(crate) fn add(&mut self, key: &str, value: impl AsRef<[u8]>) {
        self.add_bytes(key.as_bytes(), value);
    }

    /// Appends `value` to the values of the exact key bytes.
    pub(crate) fn add_bytes(&mut self, key: &[u8], value: impl AsRef<[u8]>) {
        let value = value.as_ref();
        let lookup = self.lookup_key(key);
        let kv = KeyValue::new(key, lookup.as_ref(), value);
        self.push_value(&lookup, kv);
    }

    /// Appends `value`, which the map takes without copying, to the values of the exact key bytes.
    ///
    /// The buffer is trimmed to its length first, so that a value read into a growing buffer does not keep the
    /// growth.
    pub(crate) fn add_owned(&mut self, key: &[u8], mut value: Vec<u8>) {
        value.shrink_to_fit();
        let lookup = self.lookup_key(key);
        let kv = KeyValue::owned(key, lookup.as_ref(), value);
        self.push_value(&lookup, kv);
    }

    /// Files `kv` under the map key `lookup`, creating the key if it is new.
    fn push_value(&mut self, lookup: &[u8], kv: KeyValue) {
        match self.data.get_mut(lookup) {
            Some(values) => push_grown(values, kv),
            None => {
                self.data.insert(Key::from_slice(lookup), vec![kv]);
            },
        }
        self.values = self.values.saturating_add(1);
    }

    /// Keeps the first `keep` values of `key` and drops the rest, removing the key if none stay.
    pub(crate) fn truncate_values(&mut self, key: &[u8], keep: usize) {
        let lookup = self.lookup_key(key);
        if keep == 0 {
            if let Some(removed) = self.data.shift_remove(lookup.as_ref()) {
                self.values = self.values.saturating_sub(count_of(removed.len()));
            }
        } else if let Some(values) = self.data.get_mut(lookup.as_ref()) {
            let dropped = values.len().saturating_sub(keep);
            values.truncate(keep);
            values.shrink_to_fit();
            self.values = self.values.saturating_sub(count_of(dropped));
        }
    }

    /// Moves `key` to just before `other` in insertion order if it comes after it; nothing changes if either is
    /// absent. It restores the order values were meant to be inserted in when they were added as they were read.
    pub(crate) fn order_before(&mut self, key: &[u8], other: &[u8]) {
        let (key, other) = (self.lookup_key(key), self.lookup_key(other));
        if let (Some(from), Some(to)) = (
            self.data.get_index_of(key.as_ref()),
            self.data.get_index_of(other.as_ref()),
        ) && from > to
        {
            self.data.move_index(from, to);
        }
    }

    /// Replaces the values of `key`, which keeps its position in insertion order if it is
    /// already present.
    pub(crate) fn set<V: AsRef<[u8]>>(&mut self, key: impl AsRef<[u8]>, values: impl IntoIterator<Item = V>) {
        let key = key.as_ref();
        let lookup = self.lookup_key(key);
        let key_values: Vec<KeyValue> = values
            .into_iter()
            .map(|value| KeyValue::new(key, lookup.as_ref(), value.as_ref()))
            .collect();
        let added = key_values.len();
        if let Some(replaced) = self.data.insert(Key::from_slice(lookup.as_ref()), key_values) {
            self.values = self.values.saturating_sub(count_of(replaced.len()));
        }
        self.values = self.values.saturating_add(count_of(added));
    }

    /// Replaces the value at `index` of `key`, or appends it if `index` is past the end.
    // The nested `match` is the form the hot rewrite-in-place path was benchmarked in: the same logic as
    // `if let` branches with an early return measured about 10% slower on short requests.
    #[expect(
        clippy::single_match_else,
        reason = "the nested match keeps the hot rewrite-in-place path as benchmarked"
    )]
    pub(crate) fn set_index(&mut self, key: impl AsRef<[u8]>, index: usize, value: impl AsRef<[u8]>) {
        let key = key.as_ref();
        let lookup = self.lookup_key(key);
        let value = value.as_ref();

        match self.data.get_full_mut(lookup.as_ref()) {
            Some((_, map_key, values)) => match values.get_mut(index) {
                // Rewritten in its buffers: RULE's values are set this way for every rule evaluated
                Some(entry) => entry.replace(key, map_key, value),
                None => {
                    push_grown(values, KeyValue::new(key, lookup.as_ref(), value));
                    self.values = self.values.saturating_add(1);
                },
            },
            None => {
                self.data.insert(
                    Key::from_slice(lookup.as_ref()),
                    vec![KeyValue::new(key, lookup.as_ref(), value)],
                );
                self.values = self.values.saturating_add(1);
            },
        }
    }

    /// Removes `key` and all its values, keeping the other keys in insertion order.
    ///
    /// `shift_remove` memmoves the entries after `key`, so each removal is O(N) (one runs per
    /// match under `apply_setvar`); `swap_remove` is O(1) but reorders, and ordering is the
    /// guarantee this type provides.
    pub(crate) fn remove(&mut self, key: &str) {
        let lookup = self.lookup_key(key.as_bytes());
        if let Some(removed) = self.data.shift_remove(lookup.as_ref()) {
            self.values = self.values.saturating_sub(count_of(removed.len()));
        }
    }

    /// Removes every key.
    pub(crate) fn reset(&mut self) {
        self.data.clear();
        self.values = 0;
    }

    /// Remove all entries while retaining only a bounded amount of table capacity.
    pub(crate) fn reset_for_reuse(&mut self) {
        self.data.clear();
        self.values = 0;
        self.trim_for_reuse();
    }

    /// Remove request data and release capacity charged to an active body budget.
    pub(crate) fn reset_and_release(&mut self) {
        self.data.clear();
        self.values = 0;
        self.data.shrink_to_fit();
    }

    /// Drop the backing table if it grew beyond the pool's retention budget.
    pub(crate) fn trim_for_reuse(&mut self) {
        // shortcut: drop tables above 16 KiB; raise after profiling shows large maps recur.
        const MAX_RETAINED_TABLE_BYTES: usize = 16 * 1024;
        if self.allocated_bytes() > MAX_RETAINED_TABLE_BYTES {
            self.data = IndexMap::with_hasher(ahash::RandomState::new());
            self.values = 0;
        }
    }

    /// The bytes the allocation of `key`'s value list asks for when the next value does not fit it: the grown
    /// list, which the old one is still beside while it is copied. None when the list has a free slot, or when
    /// the key is new and its list is made by the insertion itself.
    ///
    /// This follows [`push_grown`], so a list that was full before any budget saw it is charged as one that
    /// the budget filled.
    pub(crate) fn value_list_growth_bytes(&self, key: &[u8]) -> Option<usize> {
        let values = self.data.get(self.lookup_key(key).as_ref())?;
        let (len, capacity) = (values.len(), values.capacity());
        if len < capacity {
            return Some(0);
        }
        let grown = grown_list_capacity(len, capacity);
        Some(allocation_bytes(grown.saturating_mul(VALUE_ENTRY_BYTES)))
    }

    /// The length and capacity of `key`'s value list, or `None` when the map does not hold the key.
    pub(crate) fn value_list_shape(&self, key: &[u8]) -> Option<(usize, usize)> {
        let values = self.data.get(self.lookup_key(key).as_ref())?;
        Some((values.len(), values.capacity()))
    }

    /// Number of distinct keys.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Every key, lowercase in a case-insensitive map, with its values as text (as
    /// [`Map::get`] gives them), sorted by key.
    ///
    /// This is a lossy text projection: distinct byte keys that share a lossy text view
    /// share one entry here. `Map::iter_bytes` keeps them apart.
    pub fn entries(&self) -> std::collections::BTreeMap<String, Vec<String>> {
        self.data
            .iter()
            .map(|(key, values)| {
                let values = values.iter().map(|kv| kv.text().into_owned()).collect();
                (key.text().to_owned(), values)
            })
            .collect()
    }

    /// Number of values, counting each value of a repeated key.
    ///
    /// O(1): the total is maintained by every mutator, as Go's `TotalValues` is.
    pub fn value_count(&self) -> usize {
        usize::try_from(self.values).unwrap_or(usize::MAX)
    }

    /// The value count recomputed from the stored entries, as the test oracle for the maintained total.
    ///
    /// Every key it visits is counted by [`keys_scanned`], so tests can tell a scan from a read of the total.
    #[cfg(test)]
    pub(crate) fn summed_value_count(&self) -> usize {
        self.data
            .values()
            .inspect(|_| KEYS_SCANNED.with(|scanned| scanned.set(scanned.get() + 1)))
            .map(Vec::len)
            .sum()
    }

    /// Whether the map has no keys.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Estimated bytes held by this map's backing allocations.
    ///
    /// The estimate is deliberately conservative. `IndexMap` keeps its entries in a vector
    /// plus a hash index, and neither allocation shrinks when entries are removed, so both
    /// are sized from the map's capacity with an allocator alignment allowance.
    pub(crate) fn allocated_bytes(&self) -> usize {
        let mut total = index_table_bytes::<(Key, Vec<KeyValue>)>(self.data.capacity());
        for (key, values) in &self.data {
            total = total.saturating_add(key.allocated_bytes());
            total = total.saturating_add(allocation_bytes(
                values.capacity().saturating_mul(size_of::<KeyValue>()),
            ));
            for value in values {
                total = total.saturating_add(value.allocated_bytes());
            }
        }
        total
    }
}

/// Bytes retained for each stored key copy per input key byte, at most.
///
/// A byte key that is not valid UTF-8 is held twice, as its raw bytes and as the lossy text view in which
/// every invalid byte becomes the three-byte U+FFFD, so one input byte can cost four. Valid UTF-8 keys cost one.
pub(crate) const KEY_RETAINED_BYTES_PER_BYTE: usize = 4;

/// Key copies one inserted value can retain: the lookup key of a new entry and the original key stored beside
/// the value.
pub(crate) const KEY_COPIES_PER_INSERT: usize = 2;

/// Worst-case bytes one inserted value costs beyond its key and value bytes.
///
/// The entry vector and hash index are sized from capacities that may be twice the entry count, and the index
/// rounds up to a power of two (see [`index_table_bytes`]); a new key also starts a one-element value vector,
/// and a repeated key may double its value vector. Both cases are bounded by this figure, which the
/// `insert_overhead_bounds_the_measured_growth` test checks against [`Map::allocated_bytes`].
pub(crate) const INSERT_OVERHEAD_BYTES: usize = 2
    * (size_of::<(Key, Vec<KeyValue>)>() + 3 * size_of::<usize>() + 5 * (size_of::<usize>() + 1))
    + 2 * size_of::<KeyValue>()
    + ALLOCATIONS_PER_INSERT * ALLOCATION_OVERHEAD_BYTES;

/// Allocations one inserted value can make that [`ALLOCATION_OVERHEAD_BYTES`] is charged on: the new key, its
/// value vector, the spelling beside the value, and the value itself, which the entry vector's growth also
/// allocates once more.
const ALLOCATIONS_PER_INSERT: usize = 5;

/// One-time worst-case bytes a map allocates when its first entry is inserted, beyond the steady
/// [`INSERT_OVERHEAD_BYTES`] share: the vector and hash index start at four entries, and a new key's value
/// vector starts at four values.
pub(crate) const FIRST_INSERT_OVERHEAD_BYTES: usize = 4
    * (size_of::<(Key, Vec<KeyValue>)>() + 3 * size_of::<usize>() + 2 * (size_of::<usize>() + 1))
    + 4 * size_of::<KeyValue>()
    + 2 * ALLOCATION_OVERHEAD_BYTES;

/// Estimated bytes of an `IndexMap`'s backing allocations for `capacity` entries.
///
/// `IndexMap` stores entries in a vector of `(hash, key, value)` and looks them up through
/// a hash index of bucket indices, so a `HashMap` bucket model does not describe it. The
/// entry vector is sized from the capacity and the index is rounded up to a power of two,
/// which over-counts rather than under-counts. Neither allocation shrinks on removal, so a
/// cleared map keeps its cost.
pub(crate) fn index_table_bytes<T>(capacity: usize) -> usize {
    if capacity == 0 {
        return 0;
    }
    index_entries_bytes::<T>(capacity).saturating_add(index_buckets_bytes(capacity))
}

/// The capacity an `IndexMap` has grown to once it holds `len` entries: the hash index's, which the entry vector
/// follows. Its buckets are the power of two that keeps the load at or under seven eighths, four at least, and
/// a table below eight buckets holds one entry fewer than it has.
pub(crate) fn index_capacity_for(len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let buckets = if len < 4 {
        4
    } else if len < 8 {
        8
    } else {
        len.saturating_mul(8)
            .div_ceil(7)
            .checked_next_power_of_two()
            .unwrap_or(usize::MAX)
    };
    if buckets < 8 { buckets - 1 } else { buckets / 8 * 7 }
}

/// Estimated bytes of the allocations of a map of values for `len` distinct keys, once it has grown to hold them.
pub(crate) fn map_table_bytes(len: usize) -> usize {
    index_table_bytes::<(Key, Vec<KeyValue>)>(index_capacity_for(len))
}

/// Estimated bytes of the entry vector for `capacity` entries.
fn index_entries_bytes<T>(capacity: usize) -> usize {
    // Three extra words cover the hash IndexMap stores beside each entry and the padding a
    // `Bucket` may need before its key.
    capacity.saturating_mul(size_of::<T>().saturating_add(3 * size_of::<usize>()))
}

/// Estimated bytes of the hash index for `capacity` entries.
///
/// Mirrors the standard library's capacity-to-bucket mapping (at least four buckets,
/// otherwise `(capacity + 1) * 8 / 7` rounded up to a power of two) so the estimate
/// over-counts rather than under-counts. One index word and one control byte are charged per
/// bucket, plus two words for the index allocation's header.
fn index_buckets_bytes(capacity: usize) -> usize {
    if capacity == 0 {
        return 0;
    }
    let buckets = capacity
        .saturating_add(1)
        .saturating_mul(8)
        .div_ceil(7)
        .checked_next_power_of_two()
        .unwrap_or(usize::MAX)
        .max(4);
    buckets
        .saturating_mul(size_of::<usize>().saturating_add(1))
        .saturating_add(size_of::<usize>().saturating_mul(2))
}

#[cfg(test)]
thread_local! {
    /// Keys visited by [`Map::summed_value_count`] on this thread.
    static KEYS_SCANNED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Keys the key-scanning count has visited on this thread so far, which tests read to bound work without a clock.
#[cfg(test)]
pub(crate) fn keys_scanned() -> usize {
    KEYS_SCANNED.with(std::cell::Cell::get)
}

impl std::fmt::Display for Map {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}:", self.name())?;
        for (map_key, values) in &self.data {
            if let Some(first) = values.first() {
                write!(f, "    {}: ", first.key_text(map_key))?;
                for (i, kv) in values.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", kv.text())?;
                }
                writeln!(f)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "map tests use fixed fixtures")]
mod tests {
    use super::{index_buckets_bytes, index_entries_bytes, index_table_bytes};

    #[test]
    fn table_estimate_covers_capacity_and_never_undercounts() {
        for capacity in [0_usize, 1, 2, 3, 4, 7, 8, 9, 15, 16, 100, 1024] {
            let entries = index_entries_bytes::<(u64, u64)>(capacity);
            let buckets = index_buckets_bytes(capacity);
            let bytes = index_table_bytes::<(u64, u64)>(capacity);
            assert_eq!(
                bytes,
                entries.saturating_add(buckets),
                "the total must charge both the entry vector and the index"
            );
            // Each entry holds its value plus at least the hash word stored beside it.
            assert!(
                entries >= capacity.saturating_mul(size_of::<(u64, u64)>() + size_of::<usize>()),
                "capacity {capacity} entry vector underestimated: {entries}"
            );
            // The index holds one index word and one control byte per capacity entry.
            assert!(
                buckets >= capacity.saturating_mul(size_of::<usize>() + 1),
                "capacity {capacity} index underestimated: {buckets}"
            );
        }
        assert_eq!(index_table_bytes::<(u64, u64)>(0), 0, "an empty map has no table");
        assert!(
            index_table_bytes::<(u64, u64)>(9) >= index_table_bytes::<(u64, u64)>(8),
            "the estimate must not shrink as capacity grows"
        );
    }

    use super::*;

    #[test]
    fn test_map_case_insensitive() {
        let mut map = Map::new(RuleVariable::RequestHeaders);

        map.set_index("user", 1, "value");
        map.set("user-agent", vec!["value2".to_owned()]);

        assert_eq!(map.get("user"), vec!["value"]);
        assert_eq!(map.get("USER"), vec!["value"]); // Case-insensitive
        assert!(map.iter().next().is_some());
        assert!(map.iter_key("a").next().is_none());

        let regex = Regex::new("user.*");
        assert!(regex.is_ok());
        if let Ok(regex) = regex {
            assert_eq!(map.iter_regex(&regex).count(), 2);
        }

        map.add("user-agent", "value3");
        assert_eq!(map.get("user-agent").len(), 2);

        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_map_case_sensitive() {
        let mut map = Map::new_case_sensitive(RuleVariable::ArgsPost);

        map.set_index("key", 1, "value");
        map.set("key2", vec!["value2".to_owned()]);

        assert_eq!(map.get("key"), vec!["value"]);
        assert!(map.get("KEY").is_empty()); // Case-sensitive
        assert!(map.iter().next().is_some());
        assert!(map.iter_key("a").next().is_none());

        let regex = Regex::new("k.*");
        assert!(regex.is_ok());
        if let Ok(regex) = regex {
            assert_eq!(map.iter_regex(&regex).count(), 2);
        }

        map.add("key2", "value3");
        assert_eq!(map.get("key2").len(), 2);

        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_map_reset() {
        let mut map = Map::new(RuleVariable::RequestHeaders);
        map.add("key1", "value1");
        map.add("key2", "value2");
        assert_eq!(map.len(), 2);

        map.reset();
        assert_eq!(map.len(), 0);
        assert!(map.iter().next().is_none());
    }

    #[test]
    fn test_map_remove() {
        let mut map = Map::new(RuleVariable::RequestHeaders);
        map.add("key1", "value1");
        map.add("key2", "value2");
        assert_eq!(map.len(), 2);

        map.remove("key1");
        assert_eq!(map.len(), 1);
        assert!(map.get("key1").is_empty());
        assert_eq!(map.get("key2"), vec!["value2"]);
    }

    #[test]
    fn test_map_set_index_beyond_size() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.set_index("key", 0, "value0");
        map.set_index("key", 5, "value5"); // Index beyond size, should append

        let values = map.get("key");
        assert_eq!(values.len(), 2);
        assert_eq!(values, ["value0", "value5"]);
    }

    #[test]
    fn test_map_lookup_lowercases_non_ascii_keys() {
        // Keys whose only uppercase letters aren't ASCII
        let mut map = Map::new(RuleVariable::RequestHeaders);
        map.add("\u{00dc}ber", "value");

        assert_eq!(map.first("\u{00fc}ber"), Some(&b"value"[..]));
        assert_eq!(map.first("\u{00dc}ber"), Some(&b"value"[..]));
        assert_eq!(
            map.iter_key("\u{00fc}ber").next().map(|(key, _)| key),
            Some("\u{00dc}ber")
        );
        map.remove("\u{00dc}ber");
        assert!(map.is_empty());
    }

    #[test]
    fn case_insensitive_maps_fold_keys_like_go() {
        // Go lower-cases a `X-` name ending in U+0130 with its simple mapping, giving the
        // ASCII `x-i`. Rust's full mapping would store `x-i` + U+0307 and never match it.
        let mut map = Map::new(RuleVariable::RequestHeaders);
        map.add("X-\u{130}", "value");

        assert_eq!(map.first("x-i"), Some(&b"value"[..]));
        assert_eq!(map.first("X-I"), Some(&b"value"[..]));
        assert_eq!(map.entries().into_keys().collect::<Vec<_>>(), ["x-i"]);
        // The two-code-point full mapping stays a distinct key, as it does in Go.
        assert!(map.first("x-i\u{307}").is_none());
    }

    #[test]
    fn exact_lookup_does_not_fold() {
        let mut folded = Map::new(RuleVariable::RequestHeaders);
        folded.add("X-Foo", "value");
        assert_eq!(folded.iter_key_exact(b"x-foo").count(), 1);
        assert_eq!(folded.iter_key_exact(b"X-Foo").count(), 0);

        let mut raw = Map::new_case_sensitive(RuleVariable::Args);
        raw.add("Id", "value");
        assert_eq!(raw.iter_key_exact(b"Id").count(), 1);
        assert_eq!(raw.iter_key_exact(b"id").count(), 0);
    }

    #[test]
    fn test_map_first() {
        let mut map = Map::new(RuleVariable::RequestHeaders);
        assert_eq!(map.first("key"), None);

        map.add("Key", "value1");
        map.add("KEY", "value2");
        assert_eq!(map.first("key"), Some(&b"value1"[..]));
    }

    #[test]
    fn test_map_set_index_rewrites_in_place() {
        let mut map = Map::new(RuleVariable::Rule);
        map.add("msg", "first");
        map.add("msg", "second");

        map.set_index("MSG", 0, "a longer message than before");
        assert_eq!(map.get("msg"), vec!["a longer message than before", "second"]);
        assert_eq!(map.iter_key("msg").next().map(|(key, _)| key), Some("MSG"));
    }

    #[test]
    fn test_map_multiple_values_same_key() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add("id", "123");
        map.add("id", "456");
        map.add("id", "789");

        let values = map.get("id");
        assert_eq!(values.len(), 3);
        assert_eq!(values, vec!["123", "456", "789"]);
    }

    #[test]
    fn iter_follows_insertion_order() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add("f0", "a");
        map.add("f1", "b");
        map.add("f0", "c");

        let text: Vec<_> = map
            .iter()
            .map(|(key, value)| (key.to_owned(), value.to_vec()))
            .collect();
        assert_eq!(
            text,
            [
                ("f0".to_owned(), b"a".to_vec()),
                ("f0".to_owned(), b"c".to_vec()),
                ("f1".to_owned(), b"b".to_vec()),
            ]
        );
        let bytes: Vec<_> = map
            .iter_bytes()
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        assert_eq!(
            bytes,
            [
                (b"f0".to_vec(), b"a".to_vec()),
                (b"f0".to_vec(), b"c".to_vec()),
                (b"f1".to_vec(), b"b".to_vec()),
            ]
        );

        // Removing and re-adding a key moves it to the end.
        map.remove("f0");
        map.add("f0", "d");
        let keys: Vec<_> = map.iter_bytes().map(|(key, _)| key.to_vec()).collect();
        assert_eq!(keys, [b"f1".to_vec(), b"f0".to_vec()]);
    }

    #[test]
    fn remove_keeps_the_remaining_keys_in_order() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        for key in ["a", "b", "c", "d"] {
            map.add(key, key);
        }

        map.remove("b");
        let keys: Vec<_> = map.iter_bytes().map(|(key, _)| key.to_vec()).collect();
        assert_eq!(keys, [b"a".to_vec(), b"c".to_vec(), b"d".to_vec()]);
    }

    #[test]
    fn set_keeps_an_existing_keys_position() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add("a", "1");
        map.add("b", "2");
        map.add("c", "3");

        map.set("b", ["replaced"]);
        let entries: Vec<_> = map
            .iter_bytes()
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        assert_eq!(
            entries,
            [
                (b"a".to_vec(), b"1".to_vec()),
                (b"b".to_vec(), b"replaced".to_vec()),
                (b"c".to_vec(), b"3".to_vec()),
            ]
        );
    }

    #[test]
    fn map_keeps_invalid_utf8_bytes_and_text_views_replace_them() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add("id", b"\xff");

        assert_eq!(map.first("id"), Some(&b"\xff"[..]));
        assert_eq!(map.values("id").next(), Some(&b"\xff"[..]));
        assert_eq!(map.get("id"), vec!["\u{fffd}"]);
    }

    #[test]
    fn decoded_argument_names_keep_byte_identity() {
        // The decoded names of `/?%ff=a&%fe=b`, as Go's query parser produces them.
        let mut map = Map::new_case_sensitive(RuleVariable::ArgsGet);
        map.add_bytes(b"\xff", b"a");
        map.add_bytes(b"\xfe", b"b");

        assert_eq!(map.len(), 2);
        assert_eq!(map.value_count(), 2);
        assert_eq!(map.values(b"\xff").collect::<Vec<_>>(), [b"a".as_slice()]);
        assert_eq!(map.values(b"\xfe").collect::<Vec<_>>(), [b"b".as_slice()]);
        // Lookups are byte-exact: the lossy name matches neither key.
        assert!(map.values("\u{fffd}").next().is_none());
        // The text view keeps one entry per byte key, even when they print alike.
        assert_eq!(map.iter().count(), 2);
        assert!(map.iter().all(|(key, _)| key == "\u{fffd}"));
        assert_eq!(map.iter_bytes().count(), 2);
    }

    #[test]
    fn nul_names_and_lossy_equal_names_stay_distinct() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add_bytes(b"a\0b", b"nul-b");
        map.add_bytes(b"a\0c", b"nul-c");
        map.add_bytes(b"a\xff", b"ff");
        map.add_bytes(b"a\xfe", b"fe");

        assert_eq!(map.len(), 4);
        assert_eq!(map.first(b"a\0b"), Some(&b"nul-b"[..]));
        assert_eq!(map.first(b"a\0c"), Some(&b"nul-c"[..]));
        assert_eq!(map.first(b"a\xff"), Some(&b"ff"[..]));
        assert_eq!(map.first(b"a\xfe"), Some(&b"fe"[..]));
        assert!(map.first(b"a\0d").is_none());
        // The two invalid keys share the lossy text `a\u{fffd}`.
        assert_eq!(map.iter().count(), 4);
    }

    #[test]
    fn case_insensitive_maps_preserve_invalid_bytes() {
        // Deliberate deviation from Go: `strings.ToLower` folds both invalid bytes through
        // `unicode.ToLower(RuneError)`, so Go merges these into one `x\u{fffd}` entry. Byte
        // identity keeps them apart here.
        let mut map = Map::new(RuleVariable::RequestHeaders);
        map.add_bytes(b"X\xff", b"ff");
        map.add_bytes(b"X\xfe", b"fe");

        assert_eq!(map.len(), 2);
        assert_eq!(map.first(b"x\xff"), Some(&b"ff"[..]));
        assert_eq!(map.first(b"x\xfe"), Some(&b"fe"[..]));
        // Only the lossy text projection merges them.
        assert_eq!(map.entries().len(), 1);
    }

    #[test]
    fn insert_overhead_bounds_the_measured_growth() {
        use super::{
            FIRST_INSERT_OVERHEAD_BYTES, INSERT_OVERHEAD_BYTES, KEY_COPIES_PER_INSERT, KEY_RETAINED_BYTES_PER_BYTE,
        };

        // Every insertion, new key or repeated, valid or invalid UTF-8, must keep the measured allocation
        // at or under what the charge predicts for the entries inserted so far.
        for (label, distinct, invalid) in [
            ("distinct ascii keys", true, false),
            ("distinct invalid UTF-8 keys", true, true),
            ("one repeated key", false, false),
            ("one repeated invalid UTF-8 key", false, true),
        ] {
            let mut map = Map::new(RuleVariable::Files);
            let mut charged = FIRST_INSERT_OVERHEAD_BYTES;
            for index in 0..3000_usize {
                let mut key = if distinct {
                    format!("key-{index}").into_bytes()
                } else {
                    b"same-key".to_vec()
                };
                if invalid {
                    key.extend_from_slice(&[0xFF, 0xFE, 0x80]);
                }
                let value = vec![b'v'; index % 40];
                map.add_bytes(&key, &value);
                charged += INSERT_OVERHEAD_BYTES
                    + key.len() * KEY_COPIES_PER_INSERT * KEY_RETAINED_BYTES_PER_BYTE
                    + value.len();
                assert!(
                    map.allocated_bytes() <= charged,
                    "{label}: after {} inserts the map holds {} bytes but only {charged} were charged",
                    index + 1,
                    map.allocated_bytes()
                );
            }
        }
    }

    #[test]
    fn a_value_keeps_its_own_spelling_of_the_key_it_shares_with_the_map() {
        let mut map = Map::new(RuleVariable::RequestHeaders);
        map.add("User-Agent", "a");
        map.add("user-agent", "b");
        map.add("USER-AGENT", "c");
        map.add("User-Agent", "d");

        // Each value reports the spelling it arrived with, in insertion order, whatever the map filed it under.
        let spellings: Vec<&str> = map.iter().map(|(key, _)| key).collect();
        assert_eq!(spellings, ["User-Agent", "user-agent", "USER-AGENT", "User-Agent"]);
        let bytes: Vec<&[u8]> = map.iter_bytes().map(|(key, _)| key).collect();
        assert_eq!(bytes, [&b"User-Agent"[..], b"user-agent", b"USER-AGENT", b"User-Agent"]);
        let values: Vec<&[u8]> = map.iter_key("uSeR-aGeNt").map(|(_, value)| value).collect();
        assert_eq!(values, [&b"a"[..], b"b", b"c", b"d"]);
        // The entries are keyed by the lower-case form, as before.
        assert_eq!(map.entries().keys().collect::<Vec<_>>(), ["user-agent"]);
        assert_eq!(map.value_at(0, 2, true), Some((&b"USER-AGENT"[..], &b"USER-AGENT"[..])));
        assert_eq!(map.value_at(0, 1, false), Some((&b"user-agent"[..], &b"b"[..])));
        let indexed: Vec<&[u8]> = map.iter_bytes_indexed().map(|(_, _, key, _)| key).collect();
        assert_eq!(indexed, bytes);
        let regex = Regex::new("^user-agent$").unwrap();
        let matched: Vec<&str> = map.iter_regex(&regex).map(|(key, _)| key).collect();
        assert_eq!(
            matched, spellings,
            "a regex selects on the map key and reports each spelling"
        );
    }

    #[test]
    fn a_repeated_key_costs_less_than_its_own_length_per_value() {
        // The value's key is the map's own, so a long key repeated for every value is stored once.
        let key = "k".repeat(200);
        let mut map = Map::new_case_sensitive(RuleVariable::ArgsPost);
        for _ in 0..1000 {
            map.add(&key, "v");
        }
        assert_eq!(map.value_count(), 1000);
        assert!(
            map.allocated_bytes() < 1000 * key.len(),
            "{} bytes for 1000 values of a {} byte key",
            map.allocated_bytes(),
            key.len()
        );
        // And what is stored is still reported per value.
        assert!(map.iter().all(|(k, v)| k == key && v == b"v"));
        assert_eq!(map.iter_bytes().count(), 1000);
    }

    #[test]
    fn a_differing_invalid_spelling_keeps_its_bytes_and_a_shared_one_keeps_the_map_keys() {
        let mut map = Map::new(RuleVariable::RequestHeaders);
        map.add_bytes(b"X\xff", "upper");
        map.add_bytes(b"x\xff", "lower");
        map.add_bytes(b"X\xff", "upper again");

        let bytes: Vec<&[u8]> = map.iter_bytes().map(|(key, _)| key).collect();
        assert_eq!(bytes, [&b"X\xff"[..], b"x\xff", b"X\xff"]);
        let text: Vec<&str> = map.iter().map(|(key, _)| key).collect();
        assert_eq!(text, ["X\u{fffd}", "x\u{fffd}", "X\u{fffd}"]);
        assert_eq!(map.len(), 1, "one folded key");
        assert_eq!(map.values(b"X\xFF").count(), 3, "lookups fold the valid bytes only");

        let mut exact = Map::new_case_sensitive(RuleVariable::Args);
        exact.add_bytes(b"a\xff", "1");
        exact.add_bytes(b"a\xff", "2");
        exact.add_bytes(b"a\xfe", "3");
        let bytes: Vec<&[u8]> = exact.iter_bytes().map(|(key, _)| key).collect();
        assert_eq!(bytes, [&b"a\xff"[..], b"a\xff", b"a\xfe"]);
        assert_eq!(exact.iter().count(), 3);
        assert_eq!(exact.iter_key_exact(b"a\xff").count(), 2);
        assert_eq!(exact.value_at(0, 1, true), Some((&b"a\xff"[..], &b"a\xff"[..])));
    }

    #[test]
    fn rewriting_a_value_in_place_replaces_its_spelling_when_it_differs() {
        let mut map = Map::new(RuleVariable::Rule);
        map.set_index("Foo", 0, "1");
        assert_eq!(map.iter().next(), Some(("Foo", &b"1"[..])));
        map.set_index("foo", 0, "2");
        assert_eq!(map.iter().next(), Some(("foo", &b"2"[..])));
        map.set_index("FOO", 0, "3");
        assert_eq!(map.iter().next(), Some(("FOO", &b"3"[..])));
        map.set_index("foo", 0, "4");
        assert_eq!(map.iter().collect::<Vec<_>>(), [("foo", &b"4"[..])]);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn an_owned_value_is_taken_and_trimmed_to_its_length() {
        let mut map = Map::new_case_sensitive(RuleVariable::RequestXML);
        let mut value = Vec::with_capacity(4096);
        value.extend_from_slice(b"abc");
        map.add_owned(b"/*", value);
        map.add_owned(b"/*", b"def".to_vec());

        assert_eq!(map.values("/*").collect::<Vec<_>>(), [b"abc".as_slice(), b"def"]);
        assert_eq!(map.value_count(), 2);
        assert!(
            map.allocated_bytes() < 1024,
            "the spare capacity was not kept: {}",
            map.allocated_bytes()
        );
    }

    #[test]
    fn truncating_values_keeps_the_prefix_and_the_count() {
        let mut map = Map::new_case_sensitive(RuleVariable::RequestXML);
        for value in ["a", "b", "c", "d"] {
            map.add("k", value);
        }
        map.add("other", "x");
        map.truncate_values(b"k", 2);
        assert_eq!(map.values("k").collect::<Vec<_>>(), [b"a".as_slice(), b"b"]);
        assert_count(&map, 3);
        map.truncate_values(b"k", 5);
        assert_count(&map, 3);
        map.truncate_values(b"missing", 0);
        assert_count(&map, 3);
        map.truncate_values(b"k", 0);
        assert!(map.values("k").next().is_none());
        assert_eq!(map.len(), 1, "a key left with no values is removed");
        assert_count(&map, 1);
    }

    #[test]
    fn a_key_is_moved_before_another_only_when_it_comes_after_it() {
        let mut map = Map::new_case_sensitive(RuleVariable::RequestXML);
        map.add("first", "1");
        map.add("/*", "text");
        map.add("//@*", "attribute");
        map.add("last", "9");
        map.order_before(b"//@*", b"/*");
        let keys: Vec<&str> = map.iter().map(|(key, _)| key).collect();
        assert_eq!(keys, ["first", "//@*", "/*", "last"]);

        // Already in order, or absent: nothing moves.
        map.order_before(b"//@*", b"/*");
        map.order_before(b"missing", b"/*");
        map.order_before(b"first", b"missing");
        let keys: Vec<&str> = map.iter().map(|(key, _)| key).collect();
        assert_eq!(keys, ["first", "//@*", "/*", "last"]);
        assert_count(&map, 4);
    }

    #[test]
    fn long_value_lists_grow_by_a_quarter_and_short_ones_double() {
        let mut map = Map::new_case_sensitive(RuleVariable::ArgsPost);
        for _ in 0..5000_usize {
            map.add("k", "v");
            let values = map.data.get(&b"k"[..]).unwrap();
            let (len, capacity) = (values.len(), values.capacity());
            if len < 1024 {
                assert!(capacity <= 2 * len.max(4), "{len} values in room for {capacity}");
            } else {
                assert!(
                    capacity * 4 <= len * 5 + 4,
                    "{len} values in room for {capacity}, more than a quarter spare"
                );
            }
        }
        assert_count(&map, 5000);
    }

    #[test]
    fn allocations_are_charged_the_chunk_a_malloc_rounds_them_up_to() {
        use super::allocation_bytes;
        for (capacity, chunk) in [(0, 0), (1, 32), (24, 32), (25, 48), (40, 48), (41, 64), (1000, 1008)] {
            assert_eq!(allocation_bytes(capacity), chunk, "a request of {capacity}");
        }
        // A one-byte value is held in thirty-two: counting its capacity alone undercounts it.
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add("k", "v");
        assert!(map.allocated_bytes() >= 32 + 32 + size_of::<KeyValue>());
    }

    /// The maintained total must equal the values actually stored after every mutation.
    #[track_caller]
    fn assert_count(map: &Map, expected: usize) {
        assert_eq!(map.value_count(), expected, "value_count");
        assert_eq!(map.value_count(), map.summed_value_count(), "oracle");
    }

    #[test]
    fn value_count_stays_consistent_across_every_mutation() {
        let mut map = Map::new(RuleVariable::RequestHeaders);
        assert_count(&map, 0);

        map.add("A", "1");
        map.add("a", "2");
        map.add_bytes(b"b\xff", "3");
        assert_count(&map, 3);

        // `set_index` appends past the end and rewrites in place within it.
        map.set_index("A", 2, "4");
        assert_count(&map, 4);
        map.set_index("a", 0, "rewritten");
        assert_count(&map, 4);
        map.set_index("new", 7, "5");
        assert_count(&map, 5);

        // `set` replaces a key's values, shrinking or growing the total, and inserts a new key.
        map.set("a", ["x"]);
        assert_count(&map, 3);
        map.set("a", ["x", "y", "z"]);
        assert_count(&map, 5);
        map.set("fresh", ["p", "q"]);
        assert_count(&map, 7);
        map.set("fresh", Vec::<&str>::new());
        assert_count(&map, 5);

        // `remove` drops every value of the key, and an absent key changes nothing.
        map.remove("A");
        assert_count(&map, 2);
        map.remove("missing");
        assert_count(&map, 2);

        map.reset();
        assert_count(&map, 0);

        map.add("k", "v");
        map.add("k", "w");
        map.reset_for_reuse();
        assert_count(&map, 0);

        map.add("k", "v");
        map.reset_and_release();
        assert_count(&map, 0);

        // A table dropped by the retention budget starts again from zero.
        for index in 0..4096 {
            map.add(&format!("key{index}"), "value");
        }
        assert_count(&map, 4096);
        map.trim_for_reuse();
        assert_count(&map, map.summed_value_count());
        map.reset_for_reuse();
        assert_count(&map, 0);
        map.add("again", "1");
        assert_count(&map, 1);
    }

    /// The doc example of `collection::map::Map`, before it became internal.
    #[test]
    fn doc_map_type() {
        use crate::{collection::Map, types::RuleVariable};

        let mut map = Map::new(RuleVariable::RequestHeaders);
        map.add("Content-Type", "application/json");
        map.add("content-type", "text/html"); // Same key, different case

        // Case-insensitive lookup returns both values
        let values = map.get("CONTENT-TYPE");
        assert_eq!(values.len(), 2);
    }
}
