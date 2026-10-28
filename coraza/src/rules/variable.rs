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

    /// Check whether an already-lowered key is excluded.
    ///
    /// Callers lower the key exactly once, with [`lowercase_like_go`]: Go runs exception
    /// regexes against `strings.ToLower(c.Key())` (`internal/corazawaf/transaction.go:684-698`).
    pub(crate) fn matches_lowered(&self, key_lower: &str) -> bool {
        if let Some(regex) = &self.regex {
            return regex.is_match(key_lower);
        }
        self.key
            .as_ref()
            .is_some_and(|excluded| excluded.is_empty() || excluded == key_lower)
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
    /// The selector text reported for count-mode matches, as Go's compile-time `KeyStr`.
    count_key: String,
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
            count_key: String::new(),
            count: false,
            exceptions: Vec::new(),
        }
    }

    /// Select the value stored under one key.
    pub(crate) fn new_string(variable: RuleVariable, key: String) -> Self {
        Self {
            variable,
            count_key: key.clone(),
            key: Some(VariableKey::String(key)),
            count: false,
            exceptions: Vec::new(),
        }
    }

    /// Select values whose keys match `regex`.
    ///
    /// `count_key` is the selector Go reports for a count-mode match: its `KeyStr` keeps the
    /// surrounding slashes and is lower-cased for every variable outside
    /// `caseSensitiveVariable` (`internal/corazawaf/rule.go:562-570`).
    pub(crate) fn new_regex(variable: RuleVariable, regex: Regex, count_key: String) -> Self {
        Self {
            variable,
            key: Some(VariableKey::Regex(regex)),
            count_key,
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
        self.get_matches_filter(collection, |_, _| false)
    }

    /// Return matches after excluding transaction-local targets before count aggregation.
    pub(crate) fn get_matches_filter(
        &self,
        collection: Option<CollectionView<'_>>,
        mut excluded: impl FnMut(RuleVariable, &str) -> bool,
    ) -> Vec<MatchData> {
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
            let mut keep = |variable: RuleVariable, key: &[u8]| {
                let key_text = String::from_utf8_lossy(key);
                let key_lower = has_exceptions.then(|| lowercase_like_go(&key_text));
                let key_lower = key_lower.as_deref().unwrap_or(&key_text);
                !self
                    .exceptions
                    .iter()
                    .any(|exception| exception.matches_lowered(key_lower))
                    && !excluded(variable, &key_text)
            };

            match (collection, &self.key) {
                (CollectionView::Map(map), _) => self.select(map, false, |key, value| {
                    if keep(self.variable, key) {
                        record(self.variable, key, value);
                    }
                }),
                (CollectionView::Names(variable, map), _) => self.select(map, true, |key, _| {
                    if keep(variable, key) {
                        // Go exposes the raw name bytes as the value, so keep them exact.
                        record(variable, key, key);
                    }
                }),
                (CollectionView::Single(single), None) => {
                    if keep(single.variable(), b"") {
                        record(single.variable(), b"", single.get_bytes());
                    }
                },
                (CollectionView::Single(_), Some(_)) => {},
            }
        }

        if self.count {
            vec![MatchData::new(self.variable, self.count_key.clone(), count.to_string())]
        } else {
            matches
        }
    }

    /// The variable identifier selected by this specification.
    pub(crate) fn variable(&self) -> RuleVariable {
        self.variable
    }

    /// Copy this selector for one of the phase-specific argument collections.
    fn with_variable(&self, variable: RuleVariable) -> Self {
        Self {
            variable,
            key: self.key.clone(),
            count_key: self.count_key.clone(),
            count: self.count,
            exceptions: self.exceptions.clone(),
        }
    }

    /// Split the combined argument collections while retaining their selector state.
    pub(crate) fn split_args(self) -> Result<[Self; 2], Self> {
        let variables = match self.variable {
            RuleVariable::Args => [RuleVariable::ArgsGet, RuleVariable::ArgsPost],
            RuleVariable::ArgsNames => [RuleVariable::ArgsGetNames, RuleVariable::ArgsPostNames],
            _ => return Err(self),
        };
        Ok([self.with_variable(variables[0]), self.with_variable(variables[1])])
    }

    /// Visit the map entries selected by this specification, with keys as stored.
    ///
    /// `exact` is set for the names views: Go looks a literal names selector up as
    /// `data[key]`, without folding it (`internal/collections/named.go:129-131`), while
    /// a value view folds the selector through the map's own key.
    fn select<'a>(&'a self, map: &'a Map, exact: bool, mut found: impl FnMut(&'a [u8], &'a [u8])) {
        match &self.key {
            Some(VariableKey::Regex(regex)) => map.iter_regex_bytes(regex).for_each(|(key, value)| found(key, value)),
            Some(VariableKey::String(key)) if !key.is_empty() && exact => {
                select_exact(map, key, found);
            },
            Some(VariableKey::String(key)) if !key.is_empty() => {
                map.iter_key_bytes(key.as_bytes())
                    .for_each(|(stored_key, value)| found(stored_key, value));
            },
            _ => map.iter_bytes().for_each(|(key, value)| found(key, value)),
        }
    }
}

/// Visit the entries a names view stores under the exact selector `key`.
fn select_exact<'a>(map: &'a Map, key: &str, mut found: impl FnMut(&'a [u8], &'a [u8])) {
    // The parser has already folded a selector that Go folds, and the map is keyed by the
    // folded bytes (case-insensitive) or the raw bytes (case-sensitive), so a single
    // exact-byte lookup covers both cases and allocates nothing on this path.
    for (stored, value) in map.iter_key_exact(key.as_bytes()) {
        found(stored, value);
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
        let matches = VariableSpec::new_regex(RuleVariable::Args, regex, "/us.*/".to_owned())
            .get_matches(Some(CollectionView::Map(&map)));

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
        // Go lowers `İ` to `i`, so a literal `İ` exception is stored as `i` and still matches
        // that lowered key, while the two-code-point `i` + U+0307 form stays distinct.
        let exception = VariableException::new_string("\u{130}");

        assert_eq!(exception.key.as_deref(), Some("i"));
        assert!(exception.matches_lowered("i"));
        assert!(!exception.matches_lowered("i\u{307}"));
    }

    #[test]
    fn regex_exceptions_match_the_lowered_key() {
        let lower = VariableException::new_regex(Regex::new("^user$").expect("test regex is valid"));

        assert!(lower.matches_lowered("user"));
        assert!(!lower.matches_lowered("user2"));
        // Callers fold U+0130 to `i`, as `strings.ToLower` does, so the pattern sees `i`.
        let single = VariableException::new_regex(Regex::new("^i$").expect("test regex is valid"));
        assert!(single.matches_lowered("i"));
        // Go matches the pattern against the lowered key, so an upper-case pattern never
        // excludes the key it was written for.
        let upper = VariableException::new_regex(Regex::new("^USER$").expect("test regex is valid"));
        assert!(!upper.matches_lowered("user"));
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
    fn names_view_literal_selector_is_an_exact_lookup() {
        // A folded map is keyed by the folded bytes, so the exact selector finds it while
        // the original spelling does not. Nothing is allocated by the lookup.
        let mut folded = Map::new(RuleVariable::RequestHeaders);
        folded.add("X-Foo", "value");
        let matches = VariableSpec::new_string(RuleVariable::RequestHeadersNames, "x-foo".to_owned())
            .get_matches(Some(CollectionView::Names(RuleVariable::RequestHeadersNames, &folded)));
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches.first().map(|matched| matched.value.as_slice()),
            Some(&b"X-Foo"[..])
        );
        assert!(
            VariableSpec::new_string(RuleVariable::RequestHeadersNames, "X-Foo".to_owned())
                .get_matches(Some(CollectionView::Names(RuleVariable::RequestHeadersNames, &folded)))
                .is_empty()
        );

        // A case-sensitive map keeps the raw bytes, so the written spelling is the key.
        let mut raw = Map::new_case_sensitive(RuleVariable::Args);
        raw.add("Id", "value");
        assert_eq!(
            VariableSpec::new_string(RuleVariable::ArgsNames, "Id".to_owned())
                .get_matches(Some(CollectionView::Names(RuleVariable::ArgsNames, &raw)))
                .len(),
            1
        );
        assert!(
            VariableSpec::new_string(RuleVariable::ArgsNames, "id".to_owned())
                .get_matches(Some(CollectionView::Names(RuleVariable::ArgsNames, &raw)))
                .is_empty()
        );
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
    fn names_view_literal_selectors_are_exact_lookups() {
        // `?Id=secret`: a folded map stores the lookup key `id`, so Go's names view
        // (`data[key]`, `internal/collections/named.go:129-131`) finds the written `Id`
        // only after it is folded, which it never does.
        let mut folded = Map::new(RuleVariable::ArgsGet);
        folded.add("Id", b"secret");
        let names = |key: &str| {
            VariableSpec::new_string(RuleVariable::ArgsGetNames, key.to_owned())
                .get_matches(Some(CollectionView::Names(RuleVariable::ArgsGetNames, &folded)))
        };
        assert!(names("Id").is_empty());
        assert_eq!(names("id").len(), 1);

        // Under `case_sensitive_args_keys` the stored key keeps its spelling, so the
        // written selector matches and the folded one does not.
        let mut exact = Map::new_case_sensitive(RuleVariable::ArgsGet);
        exact.add("Id", b"secret");
        let names = |key: &str| {
            VariableSpec::new_string(RuleVariable::ArgsGetNames, key.to_owned())
                .get_matches(Some(CollectionView::Names(RuleVariable::ArgsGetNames, &exact)))
        };
        assert_eq!(names("Id").len(), 1);
        assert!(names("id").is_empty());
    }

    #[test]
    fn names_view_literal_selectors_still_find_lowered_header_names() {
        // Non-argument selectors are lowered by the parser, so the exact lookup finds
        // the folded header key; the written spelling is not a lookup key.
        let mut headers = Map::new(RuleVariable::RequestHeaders);
        headers.add("X-Foo", b"bar");

        let lowered = VariableSpec::new_string(RuleVariable::RequestHeadersNames, "x-foo".to_owned())
            .get_matches(Some(CollectionView::Names(RuleVariable::RequestHeadersNames, &headers)));
        let written = VariableSpec::new_string(RuleVariable::RequestHeadersNames, "X-Foo".to_owned())
            .get_matches(Some(CollectionView::Names(RuleVariable::RequestHeadersNames, &headers)));

        assert_eq!(lowered.len(), 1);
        assert_eq!(
            lowered.first().map(|matched| matched.value.as_slice()),
            Some(&b"X-Foo"[..])
        );
        assert!(written.is_empty());
    }

    #[test]
    fn count_mode_reports_the_constructor_selector_text() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add("re1", b"one");
        let regex = Regex::new("re").expect("test regex is valid");
        let mut spec = VariableSpec::new_regex(RuleVariable::Args, regex, "/re/".to_owned());
        spec.set_count(true);

        let matches = spec.get_matches(Some(CollectionView::Map(&map)));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches.first().map(|matched| matched.key.as_str()), Some("/re/"));
        assert_eq!(matches.first().map(|matched| matched.value.as_slice()), Some(&b"1"[..]));
    }

    #[test]
    fn args_split_preserves_selectors_counts_and_exceptions() {
        let mut literal = VariableSpec::new_string(RuleVariable::Args, "user".to_owned());
        literal.add_exception_string("blocked");
        let [get, post] = literal.split_args().expect("ARGS splits");
        assert_eq!(get.variable(), RuleVariable::ArgsGet);
        assert_eq!(post.variable(), RuleVariable::ArgsPost);
        assert_eq!(
            get.key.as_ref().map(|key| match key {
                super::VariableKey::String(key) => key.as_str(),
                super::VariableKey::Regex(_) => "regex",
            }),
            Some("user")
        );
        assert_eq!(get.exceptions, post.exceptions);

        let mut regex = VariableSpec::new_regex(
            RuleVariable::ArgsNames,
            Regex::new("^user").expect("test regex is valid"),
            "/^user/".to_owned(),
        );
        regex.set_count(true);
        regex.add_exception_regex(Regex::new("blocked").expect("test regex is valid"));
        let [get_names, post_names] = regex.split_args().expect("ARGS_NAMES splits");
        assert_eq!(get_names.variable(), RuleVariable::ArgsGetNames);
        assert_eq!(post_names.variable(), RuleVariable::ArgsPostNames);
        assert!(get_names.count);
        assert_eq!(get_names.count_key, "/^user/");
        assert_eq!(get_names.exceptions, post_names.exceptions);
        assert!(matches!(get_names.key, Some(super::VariableKey::Regex(_))));
    }

    #[test]
    fn regex_selectors_match_the_lossy_key_text_without_merging() {
        let mut args = Map::new_case_sensitive(RuleVariable::Args);
        args.add_bytes(b"id\xff", b"a");
        args.add_bytes(b"id\xfe", b"b");
        let regex = Regex::new("^id").expect("test regex is valid");

        let matches = VariableSpec::new_regex(RuleVariable::Args, regex, "/^id/".to_owned())
            .get_matches(Some(CollectionView::Map(&args)));

        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|matched| matched.key == "id\u{fffd}"));
        assert!(matches.iter().any(|matched| matched.value == b"a"));
        assert!(matches.iter().any(|matched| matched.value == b"b"));

        let mut headers = Map::new(RuleVariable::RequestHeaders);
        headers.add_bytes(b"X-Key\xff", b"a");
        headers.add_bytes(b"X-Key\xfe", b"b");
        let regex = Regex::new("^x-key").expect("test regex is valid");

        let matches = VariableSpec::new_regex(RuleVariable::RequestHeaders, regex, "/^x-key/".to_owned())
            .get_matches(Some(CollectionView::Map(&headers)));

        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|matched| matched.key == "X-Key\u{fffd}"));
    }
}
