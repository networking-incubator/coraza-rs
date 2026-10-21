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
//! Multiple values per key are supported.

use std::{borrow::Cow, collections::HashMap};

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
/// Even when using case-insensitive mode, the original key casing is preserved
/// and returned in `MatchData` results.
pub struct Map {
    /// Whether keys are case-sensitive
    case_sensitive: bool,
    /// Internal storage from `lookup_key` to `Vec<KeyValue>`.
    /// Keys are lowercase for case-insensitive maps.
    data: HashMap<String, Vec<KeyValue>>,
    /// The variable this collection represents
    variable: RuleVariable,
}

/// Internal storage for a key-value pair.
///
/// Preserves the original key casing even when the map is case-insensitive. Values are read
/// and written as bytes; only this type knows how they are stored.
#[derive(Debug, Clone)]
struct KeyValue {
    /// Original key (with original casing)
    key: String,
    /// Value
    value: Vec<u8>,
}

impl KeyValue {
    /// Creates a stored key/value pair.
    fn new(key: &str, value: &[u8]) -> Self {
        Self {
            key: key.to_owned(),
            value: Self::stored(value),
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

    /// The value as text, invalid UTF-8 replaced with U+FFFD.
    fn text(&self) -> Cow<'_, str> {
        text_of(self.value())
    }

    /// Replaces the key and value, reusing their buffers.
    fn replace(&mut self, key: &str, value: &[u8]) {
        self.key.clear();
        self.key.push_str(key);
        self.value.clear();
        self.value.extend_from_slice(value);
    }
}

impl Map {
    /// Create a new map with case-insensitive keys.
    ///
    /// This is the default for collections like `REQUEST_HEADERS`.
    pub(crate) fn new(variable: RuleVariable) -> Self {
        Self {
            case_sensitive: false,
            data: HashMap::new(),
            variable,
        }
    }

    /// Create a new map with case-sensitive keys.
    ///
    /// This is used for collections like `ARGS`, `ARGS_GET`, and `ARGS_POST`.
    pub(crate) fn new_case_sensitive(variable: RuleVariable) -> Self {
        Self {
            case_sensitive: true,
            data: HashMap::new(),
            variable,
        }
    }

    /// The key `key` is stored under: as it is in a case-sensitive map, lowercase otherwise.
    /// Borrowed when that is `key` itself, which spares lookups an allocation.
    fn lookup_key<'k>(&self, key: &'k str) -> Cow<'k, str> {
        if self.case_sensitive || !key.bytes().any(|b| b.is_ascii_uppercase() || !b.is_ascii()) {
            Cow::Borrowed(key)
        } else {
            Cow::Owned(key.to_lowercase())
        }
    }

    /// Every key, with its original casing, and value, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> + '_ {
        self.data.values().flatten().map(|kv| (kv.key.as_str(), kv.value()))
    }

    /// The keys and values stored under `key` (whatever its case, in a case-insensitive map).
    pub fn iter_key(&self, key: &str) -> impl Iterator<Item = (&str, &[u8])> + '_ {
        let lookup = self.lookup_key(key);
        self.data
            .get(lookup.as_ref())
            .into_iter()
            .flatten()
            .map(|kv| (kv.key.as_str(), kv.value()))
    }

    /// The keys and values whose (lookup) key matches `regex`.
    pub fn iter_regex<'a>(&'a self, regex: &'a Regex) -> impl Iterator<Item = (&'a str, &'a [u8])> {
        self.data
            .iter()
            .filter(|(lookup_key, _)| regex.is_match(lookup_key))
            .flat_map(|(_, values)| values)
            .map(|kv| (kv.key.as_str(), kv.value()))
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
    pub fn values(&self, key: &str) -> impl Iterator<Item = &[u8]> + '_ {
        self.iter_key(key).map(|(_, value)| value)
    }

    /// All values for `key` as text, invalid UTF-8 replaced with U+FFFD; empty if the key
    /// is absent. [`Map::values`] gives them as they are.
    pub fn get(&self, key: &str) -> Vec<String> {
        let lookup = self.lookup_key(key);
        self.data
            .get(lookup.as_ref())
            .map(|values| values.iter().map(|kv| kv.text().into_owned()).collect())
            .unwrap_or_default()
    }

    /// The first value of `key`; `None` if the key is absent.
    pub fn first(&self, key: &str) -> Option<&[u8]> {
        self.values(key).next()
    }

    /// Appends `value` to the values of `key`.
    pub(crate) fn add(&mut self, key: &str, value: impl AsRef<[u8]>) {
        let lookup = self.lookup_key(key);
        let kv = KeyValue::new(key, value.as_ref());
        match self.data.get_mut(lookup.as_ref()) {
            Some(values) => values.push(kv),
            None => {
                self.data.insert(lookup.into_owned(), vec![kv]);
            },
        }
    }

    /// Replaces the values of `key`.
    pub(crate) fn set<V: AsRef<[u8]>>(&mut self, key: &str, values: impl IntoIterator<Item = V>) {
        let lookup = self.lookup_key(key);
        let key_values: Vec<KeyValue> = values
            .into_iter()
            .map(|value| KeyValue::new(key, value.as_ref()))
            .collect();
        self.data.insert(lookup.into_owned(), key_values);
    }

    /// Replaces the value at `index` of `key`, or appends it if `index` is past the end.
    pub(crate) fn set_index(&mut self, key: &str, index: usize, value: impl AsRef<[u8]>) {
        let lookup = self.lookup_key(key);
        let value = value.as_ref();

        match self.data.get_mut(lookup.as_ref()) {
            Some(values) => match values.get_mut(index) {
                // Rewritten in its buffers: RULE's values are set this way for every rule evaluated
                Some(entry) => entry.replace(key, value),
                None => values.push(KeyValue::new(key, value)),
            },
            None => {
                self.data.insert(lookup.into_owned(), vec![KeyValue::new(key, value)]);
            },
        }
    }

    /// Removes `key` and all its values.
    pub(crate) fn remove(&mut self, key: &str) {
        let lookup = self.lookup_key(key);
        self.data.remove(lookup.as_ref());
    }

    /// Removes every key.
    pub(crate) fn reset(&mut self) {
        self.data.clear();
    }

    /// Number of distinct keys.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Every key, lowercase in a case-insensitive map, with its values as text (as
    /// [`Map::get`] gives them), sorted by key.
    pub fn entries(&self) -> std::collections::BTreeMap<String, Vec<String>> {
        self.data
            .iter()
            .map(|(key, values)| {
                let values = values.iter().map(|kv| kv.text().into_owned()).collect();
                (key.clone(), values)
            })
            .collect()
    }

    /// Number of values, counting each value of a repeated key.
    pub fn value_count(&self) -> usize {
        self.data.values().map(Vec::len).sum()
    }

    /// Whether the map has no keys.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl std::fmt::Display for Map {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}:", self.name())?;
        for values in self.data.values() {
            if let Some(first) = values.first() {
                write!(f, "    {}: ", first.key)?;
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
mod tests {
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
    fn map_keeps_invalid_utf8_bytes_and_text_views_replace_them() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add("id", b"\xff");

        assert_eq!(map.first("id"), Some(&b"\xff"[..]));
        assert_eq!(map.values("id").next(), Some(&b"\xff"[..]));
        assert_eq!(map.get("id"), vec!["\u{fffd}"]);
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
