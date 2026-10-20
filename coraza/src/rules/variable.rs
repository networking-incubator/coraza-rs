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

use crate::{
    collection::{Map, MatchData, Single},
    types::RuleVariable,
};

/// A borrowed collection selected for a rule variable.
#[derive(Clone, Copy)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by transaction variable resolution in a later port slice")
)]
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
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "constructed by SecLang variable parsing in a later port slice")
)]
pub(crate) enum VariableKey {
    /// Match one key, respecting the collection's case sensitivity.
    String(String),
    /// Match keys selected by a regular expression.
    Regex(Regex),
}

/// A key excluded from a variable's matches.
#[derive(Debug, Clone)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "constructed by SecLang variable parsing in a later port slice")
)]
pub(crate) struct VariableException {
    /// A literal key to exclude, or `None` when using a regex.
    key: Option<String>,
    /// A regex matching keys to exclude, or `None` when using a literal.
    regex: Option<Regex>,
}

impl VariableException {
    /// Create a literal-key exception.
    fn new_string(key: String) -> Self {
        Self {
            key: Some(key),
            regex: None,
        }
    }

    /// Create a regex-key exception.
    fn new_regex(regex: Regex) -> Self {
        Self {
            key: None,
            regex: Some(regex),
        }
    }

    /// Check whether `key` is excluded.
    fn matches(&self, key: &str) -> bool {
        let key_lower = key.to_lowercase();
        if let Some(regex) = &self.regex {
            return regex.is_match(&key_lower);
        }
        self.key
            .as_ref()
            .is_some_and(|excluded| excluded.is_empty() || excluded.to_lowercase() == key_lower)
    }
}

impl PartialEq for VariableException {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.regex.as_ref().map(Regex::as_str) == other.regex.as_ref().map(Regex::as_str)
    }
}

/// Selects collection values by key, regex, exclusions, or count.
#[derive(Debug, Clone)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the rule engine in a later port slice")
)]
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "constructed by SecLang variable parsing in a later port slice")
    )]
    pub(crate) fn new(variable: RuleVariable) -> Self {
        Self {
            variable,
            key: None,
            count: false,
            exceptions: Vec::new(),
        }
    }

    /// Select the value stored under one key.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "constructed by SecLang variable parsing in a later port slice")
    )]
    pub(crate) fn new_string(variable: RuleVariable, key: String) -> Self {
        Self {
            variable,
            key: Some(VariableKey::String(key)),
            count: false,
            exceptions: Vec::new(),
        }
    }

    /// Select values whose keys match `regex`.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "constructed by SecLang variable parsing in a later port slice")
    )]
    pub(crate) fn new_regex(variable: RuleVariable, regex: Regex) -> Self {
        Self {
            variable,
            key: Some(VariableKey::Regex(regex)),
            count: false,
            exceptions: Vec::new(),
        }
    }

    /// Enable count mode, returning the number of selected values.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "configured by SecLang variable parsing in a later port slice")
    )]
    pub(crate) fn set_count(&mut self, count: bool) {
        self.count = count;
    }

    /// Exclude a key without regard to case.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "configured by SecLang variable parsing in a later port slice")
    )]
    pub(crate) fn add_exception_string(&mut self, key: String) {
        self.exceptions.push(VariableException::new_string(key));
    }

    /// Exclude keys matched by `regex` without regard to case.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "configured by SecLang variable parsing in a later port slice")
    )]
    pub(crate) fn add_exception_regex(&mut self, regex: Regex) {
        self.exceptions.push(VariableException::new_regex(regex));
    }

    /// Return the matches from the collection associated with this variable.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by transaction variable resolution in a later port slice")
    )]
    pub(crate) fn get_matches(&self, collection: Option<CollectionView<'_>>) -> Vec<MatchData> {
        let Some(collection) = collection.filter(|view| view.variable() == self.variable) else {
            return Vec::new();
        };

        let mut matches = Vec::new();
        let mut count = 0;
        let mut keep = |matched| {
            count += 1;
            if !self.count {
                matches.push(matched);
            }
        };
        let kept = |key: &str| !self.exceptions.iter().any(|exception| exception.matches(key));

        match (collection, &self.key) {
            (CollectionView::Map(map), _) => self.select(map, |key, value| {
                if kept(key) {
                    keep(MatchData::new(map.variable(), key, value));
                }
            }),
            (CollectionView::Names(variable, map), _) => self.select(map, |key, _| {
                if kept(key) {
                    keep(MatchData::new(variable, key, key.as_bytes()));
                }
            }),
            (CollectionView::Single(single), None) => {
                for matched in single.find_all() {
                    if kept(&matched.key) {
                        keep(matched);
                    }
                }
            },
            (CollectionView::Single(_), Some(_)) => {},
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

    /// Visit the map entries selected by this specification.
    fn select<'a>(&'a self, map: &'a Map, mut found: impl FnMut(&'a str, &'a [u8])) {
        match &self.key {
            Some(VariableKey::Regex(regex)) => map.iter_regex(regex).for_each(|(key, value)| found(key, value)),
            Some(VariableKey::String(key)) if !key.is_empty() => {
                map.iter_key(key)
                    .for_each(|(stored_key, value)| found(stored_key, value));
            },
            _ => map.iter().for_each(|(key, value)| found(key, value)),
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test regex patterns are fixed and valid")]
mod tests {
    use regex::Regex;

    use super::{CollectionView, VariableSpec};
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
        spec.add_exception_string("HOST".to_owned());

        let matches = spec.get_matches(Some(CollectionView::Map(&map)));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches.first().map(|matched| matched.key.as_str()), Some("Cookie"));
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
}
