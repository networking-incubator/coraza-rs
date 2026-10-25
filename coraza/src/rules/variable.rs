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

//! Selects values from single-value and map collections for rule evaluation.

use regex::Regex;

// Re-exported for `rules` and `transaction::ctl`, which import it from here.
pub(crate) use crate::utils::lowercase_like_go;
use crate::{
    collection::{Map, MatchData, Single},
    types::RuleVariable,
};

/// A borrowed collection selected for a rule variable.
#[derive(Clone, Copy)]
pub(crate) enum CollectionView<'a> {
    /// A key-value collection such as `ARGS` or `REQUEST_HEADERS`.
    Map(&'a Map),
    /// A single-value collection such as `REQUEST_URI`.
    Single(&'a Single),
    /// A collection whose keys are exposed as values, such as `ARGS_NAMES`.
    Names(RuleVariable, &'a Map),
}

impl CollectionView<'_> {
    /// The variable identifier exposed by this view.
    fn variable(self) -> RuleVariable {
        match self {
            Self::Map(map) => map.variable(),
            Self::Single(single) => single.variable(),
            Self::Names(variable, _) => variable,
        }
    }
}

/// Key selector for a rule variable.
#[derive(Debug, Clone)]
pub(crate) enum VariableKey {
    /// Match one key, respecting the collection's case sensitivity.
    String(String),
    /// Match keys selected by a regular expression.
    Regex(Regex),
}

/// A key excluded from a variable's matches.
#[derive(Debug, Clone)]
pub(crate) struct VariableException {
    /// A literal key to exclude, or `None` when using a regex.
    key: Option<String>,
    /// A regex matching keys to exclude, or `None` when using a literal.
    regex: Option<Regex>,
}

impl VariableException {
    /// Create a literal-key exception.
    pub(crate) fn new_string(key: &str) -> Self {
        Self {
            key: Some(lowercase_like_go(key)),
            regex: None,
        }
    }

    /// Create a regex-key exception.
    pub(crate) fn new_regex(regex: Regex) -> Self {
        Self {
            key: None,
            regex: Some(regex),
        }
    }

    /// Check whether the lowered key `key_lower` is excluded.
    fn matches(&self, key_lower: &str) -> bool {
        if let Some(regex) = &self.regex {
            // Go runs exception regexes against `strings.ToLower(c.Key())`
            // (`internal/corazawaf/transaction.go:684-698`).
            return regex.is_match(key_lower);
        }
        self.key
            .as_ref()
            .is_some_and(|excluded| excluded.is_empty() || excluded == key_lower)
    }

    /// Check a key without regard to case, as runtime rule-target exclusions do.
    pub(crate) fn matches_key(&self, key: &str) -> bool {
        self.matches(&lowercase_like_go(key))
    }
}

impl PartialEq for VariableException {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.regex.as_ref().map(Regex::as_str) == other.regex.as_ref().map(Regex::as_str)
    }
}

/// Selects collection values by key, regex, exclusions, or count.
#[derive(Debug, Clone)]
pub(crate) struct VariableSpec {
    /// The variable identifier selected by this specification.
    variable: RuleVariable,
    /// Optional literal or regex key selector.
    key: Option<VariableKey>,
    /// Whether to return a count instead of the matching values.
    count: bool,
    /// Keys excluded from the selected values.
    exceptions: Vec<VariableException>,
}

impl VariableSpec {
    /// Select every value from `variable`.
    pub(crate) fn new(variable: RuleVariable) -> Self {
        Self {
            variable,
            key: None,
            count: false,
            exceptions: Vec::new(),
        }
    }

    /// Select the value stored under one key.
    pub(crate) fn new_string(variable: RuleVariable, key: String) -> Self {
        Self {
            variable,
            key: Some(VariableKey::String(key)),
            count: false,
            exceptions: Vec::new(),
        }
    }

    /// Select values whose keys match `regex`.
    pub(crate) fn new_regex(variable: RuleVariable, regex: Regex) -> Self {
        Self {
            variable,
            key: Some(VariableKey::Regex(regex)),
            count: false,
            exceptions: Vec::new(),
        }
    }

    /// Enable count mode, returning the number of selected values.
    pub(crate) fn set_count(&mut self, count: bool) {
        self.count = count;
    }

    /// Exclude a key without regard to case.
    pub(crate) fn add_exception_string(&mut self, key: &str) {
        self.exceptions.push(VariableException::new_string(key));
    }

    /// Exclude keys matched by `regex`, using its configured case sensitivity.
    pub(crate) fn add_exception_regex(&mut self, regex: Regex) {
        self.exceptions.push(VariableException::new_regex(regex));
    }

    /// Return the matches from the collection associated with this variable.
    pub(crate) fn get_matches(&self, collection: Option<CollectionView<'_>>) -> Vec<MatchData> {
        let Some(collection) = collection.filter(|view| {
            view.variable() == self.variable
                || (self.variable == RuleVariable::XML && view.variable() == RuleVariable::RequestXML)
        }) else {
            return Vec::new();
        };

        let mut matches = Vec::new();
        let mut count: usize = 0;
        let count_mode = self.count;
        let has_exceptions = !self.exceptions.is_empty();
        {
            let mut record = |variable: RuleVariable, key: &[u8], value: &[u8]| {
                if count_mode {
                    count = count.saturating_add(1);
                } else {
                    matches.push(MatchData::new(variable, String::from_utf8_lossy(key), value));
                }
            };
            let keep = |key: &[u8]| {
                let key_text = String::from_utf8_lossy(key);
                let key_lower = has_exceptions.then(|| lowercase_like_go(&key_text));
                let key_lower = key_lower.as_deref().unwrap_or(&key_text);
                !self.exceptions.iter().any(|exception| exception.matches(key_lower))
            };

            match (collection, &self.key) {
                (CollectionView::Map(map), _) => self.select(map, |key, value| {
                    if keep(key) {
                        record(self.variable, key, value);
                    }
                }),
                (CollectionView::Names(variable, map), _) => self.select(map, |key, _| {
                    if keep(key) {
                        // Go exposes the raw name bytes as the value, so keep them exact.
                        record(variable, key, key);
                    }
                }),
                (CollectionView::Single(single), None) => {
                    if keep(b"") {
                        record(single.variable(), b"", single.get_bytes());
                    }
                },
                (CollectionView::Single(_), Some(_)) => {},
            }
        }

        if self.count {
            let key = match &self.key {
                Some(VariableKey::String(key)) => key.clone(),
                _ => String::new(),
            };
            vec![MatchData::new(self.variable, key, count.to_string())]
        } else {
            matches
        }
    }

    /// The variable identifier selected by this specification.
    pub(crate) fn variable(&self) -> RuleVariable {
        self.variable
    }

    /// Visit the map entries selected by this specification, with keys as stored.
    fn select<'a>(&'a self, map: &'a Map, mut found: impl FnMut(&'a [u8], &'a [u8])) {
        match &self.key {
            Some(VariableKey::Regex(regex)) => map.iter_regex_bytes(regex).for_each(|(key, value)| found(key, value)),
            Some(VariableKey::String(key)) if !key.is_empty() => {
                map.iter_key_bytes(key.as_bytes())
                    .for_each(|(stored_key, value)| found(stored_key, value));
            },
            _ => map.iter_bytes().for_each(|(key, value)| found(key, value)),
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test regex patterns are fixed and valid")]
mod tests {
    use regex::Regex;

    use super::{CollectionView, VariableException, VariableSpec};
    use crate::{
        collection::{Map, Single},
        types::RuleVariable,
    };

    fn args() -> Map {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add("id", b"123");
        map.add("user", b"alice");
        map.add("user", b"bob");
        map
    }

    #[test]
    fn selects_a_string_key_and_preserves_value_bytes() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add("id", b"\xff");

        let matches =
            VariableSpec::new_string(RuleVariable::Args, "id".to_owned()).get_matches(Some(CollectionView::Map(&map)));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches.first().map(|matched| matched.key.as_str()), Some("id"));
        assert_eq!(
            matches.first().map(|matched| matched.value.as_slice()),
            Some(&b"\xff"[..])
        );
    }

    #[test]
    fn selects_regex_keys() {
        let map = args();
        let regex = Regex::new("us.*").expect("test regex is valid");
        let matches = VariableSpec::new_regex(RuleVariable::Args, regex).get_matches(Some(CollectionView::Map(&map)));

        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|matched| matched.key == "user"));
    }

    #[test]
    fn empty_string_key_selects_all_values() {
        let map = args();
        let matches =
            VariableSpec::new_string(RuleVariable::Args, String::new()).get_matches(Some(CollectionView::Map(&map)));

        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn excludes_keys_case_insensitively() {
        let mut map = Map::new(RuleVariable::RequestHeaders);
        map.add("Host", b"example.test");
        map.add("Cookie", b"a=b");
        let mut spec = VariableSpec::new(RuleVariable::RequestHeaders);
        spec.add_exception_string("HOST");

        let matches = spec.get_matches(Some(CollectionView::Map(&map)));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches.first().map(|matched| matched.key.as_str()), Some("Cookie"));
    }

    #[test]
    fn literal_exceptions_lower_keys_like_go() {
        // Go lowers `İ` to `i` on both sides, so a literal `İ` exception still matches it,
        // while the two-code-point `i` + U+0307 form stays distinct.
        let exception = VariableException::new_string("\u{130}");

        assert!(exception.matches_key("\u{130}"));
        assert!(exception.matches_key("I"));
        assert!(!exception.matches_key("i\u{307}"));
    }

    #[test]
    fn regex_exceptions_match_the_lowered_key() {
        let lower = VariableException::new_regex(Regex::new("^user$").expect("test regex is valid"));

        assert!(lower.matches_key("USER"));
        assert!(lower.matches_key("user"));
        assert!(!lower.matches_key("user2"));
        // U+0130 folds to `i`, as `strings.ToLower` does, so the pattern sees `i`.
        let single = VariableException::new_regex(Regex::new("^i$").expect("test regex is valid"));
        assert!(single.matches_key("\u{130}"));
        // Go matches the pattern against the lowered key, so an upper-case pattern never
        // excludes the key it was written for.
        let upper = VariableException::new_regex(Regex::new("^USER$").expect("test regex is valid"));
        assert!(!upper.matches_key("USER"));
    }

    #[test]
    fn regex_exceptions_and_count_mode_apply_after_selection() {
        let map = args();
        let exception = Regex::new("^user$").expect("test regex is valid");
        let mut spec = VariableSpec::new(RuleVariable::Args);
        spec.add_exception_regex(exception);
        spec.set_count(true);

        let matches = spec.get_matches(Some(CollectionView::Map(&map)));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches.first().map(|matched| matched.value.as_slice()), Some(&b"1"[..]));
    }

    #[test]
    fn names_view_returns_keys_as_values() {
        let map = args();
        let matches = VariableSpec::new(RuleVariable::ArgsNames)
            .get_matches(Some(CollectionView::Names(RuleVariable::ArgsNames, &map)));

        assert_eq!(matches.len(), 3);
        assert!(matches.iter().any(|matched| matched.value == b"id"));
        assert_eq!(matches.iter().filter(|matched| matched.value == b"user").count(), 2);
    }

    #[test]
    fn selects_single_values_and_counts_them() {
        let mut single = Single::new(RuleVariable::RequestURI);
        single.set(b"/\xff");

        let matched = VariableSpec::new(RuleVariable::RequestURI).get_matches(Some(CollectionView::Single(&single)));
        let mut count = VariableSpec::new(RuleVariable::RequestURI);
        count.set_count(true);
        let counted = count.get_matches(Some(CollectionView::Single(&single)));

        assert_eq!(matched.len(), 1);
        assert_eq!(matched.first().map(|item| item.value.as_slice()), Some(&b"/\xff"[..]));
        assert_eq!(counted.first().map(|item| item.value.as_slice()), Some(&b"1"[..]));
    }

    #[test]
    fn mismatched_or_missing_collections_have_no_matches() {
        let map = args();
        let spec = VariableSpec::new(RuleVariable::Args);

        assert!(spec.get_matches(None).is_empty());
        assert!(
            spec.get_matches(Some(CollectionView::Single(&Single::new(RuleVariable::RequestURI))))
                .is_empty()
        );
        assert!(
            spec.get_matches(Some(CollectionView::Map(&Map::new(RuleVariable::TX))))
                .is_empty()
        );
        assert_eq!(spec.get_matches(Some(CollectionView::Map(&map))).len(), 3);
    }

    #[test]
    fn args_matches_every_byte_key() {
        // The decoded names of `/?%ff=a&%fe=b`.
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add_bytes(b"\xff", b"a");
        map.add_bytes(b"\xfe", b"b");

        let matches = VariableSpec::new(RuleVariable::Args).get_matches(Some(CollectionView::Map(&map)));

        assert_eq!(matches.len(), 2);
        assert!(matches.iter().any(|matched| matched.value == b"a"));
        assert!(matches.iter().any(|matched| matched.value == b"b"));
    }

    #[test]
    fn names_view_returns_raw_key_bytes() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add_bytes(b"\xff", b"a");
        map.add_bytes(b"\xfe", b"b");
        map.add_bytes(b"a\0b", b"c");

        let matches = VariableSpec::new(RuleVariable::ArgsNames)
            .get_matches(Some(CollectionView::Names(RuleVariable::ArgsNames, &map)));

        assert_eq!(matches.len(), 3);
        assert!(matches.iter().any(|matched| matched.value == b"\xff"));
        assert!(matches.iter().any(|matched| matched.value == b"\xfe"));
        assert!(matches.iter().any(|matched| matched.value == b"a\0b"));
    }

    #[test]
    fn regex_selectors_match_the_lossy_key_text_without_merging() {
        let mut args = Map::new_case_sensitive(RuleVariable::Args);
        args.add_bytes(b"id\xff", b"a");
        args.add_bytes(b"id\xfe", b"b");
        let regex = Regex::new("^id").expect("test regex is valid");

        let matches = VariableSpec::new_regex(RuleVariable::Args, regex).get_matches(Some(CollectionView::Map(&args)));

        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|matched| matched.key == "id\u{fffd}"));
        assert!(matches.iter().any(|matched| matched.value == b"a"));
        assert!(matches.iter().any(|matched| matched.value == b"b"));

        let mut headers = Map::new(RuleVariable::RequestHeaders);
        headers.add_bytes(b"X-Key\xff", b"a");
        headers.add_bytes(b"X-Key\xfe", b"b");
        let regex = Regex::new("^x-key").expect("test regex is valid");

        let matches = VariableSpec::new_regex(RuleVariable::RequestHeaders, regex)
            .get_matches(Some(CollectionView::Map(&headers)));

        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|matched| matched.key == "X-Key\u{fffd}"));
    }
}
