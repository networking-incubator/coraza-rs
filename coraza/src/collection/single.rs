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

//! Single-value collection implementation.

use super::MatchData;
use crate::{transformations::text_of, types::RuleVariable};

/// A collection that holds a single byte value.
///
/// Used for variables like `REQUEST_URI`, `REQUEST_METHOD`, and others.
pub struct Single {
    /// The stored value.
    data: Vec<u8>,
    /// The variable this collection represents.
    variable: RuleVariable,
}

impl Single {
    /// Create a new single-value collection.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by transaction storage in a later port slice")
    )]
    pub(crate) fn new(variable: RuleVariable) -> Self {
        Self {
            data: Vec::new(),
            variable,
        }
    }

    /// Set the value.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by transaction storage in a later port slice")
    )]
    pub(crate) fn set(&mut self, value: impl AsRef<[u8]>) {
        self.data = value.as_ref().to_vec();
    }

    /// The stored bytes; empty if unset.
    pub fn get_bytes(&self) -> &[u8] {
        &self.data
    }

    /// The value as text, replacing invalid UTF-8 sequences; empty if unset.
    pub fn get(&self) -> std::borrow::Cow<'_, str> {
        text_of(&self.data)
    }

    /// The value as match data, with no key.
    pub fn find_all(&self) -> Vec<MatchData> {
        vec![MatchData::without_key(self.variable, self.data.as_slice())]
    }

    /// Name of the variable this value holds (e.g. `REQUEST_URI`).
    pub fn name(&self) -> &str {
        self.variable.name()
    }

    /// The variable this single value represents.
    pub fn variable(&self) -> RuleVariable {
        self.variable
    }
}

impl std::fmt::Display for Single {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.name(), text_of(&self.data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_new() {
        let single = Single::new(RuleVariable::RequestURI);
        assert_eq!(single.get(), "");
        assert_eq!(single.name(), "REQUEST_URI");
    }

    #[test]
    fn test_single_set() {
        let mut single = Single::new(RuleVariable::RequestMethod);
        single.set("GET");
        assert_eq!(single.get(), "GET");
    }

    #[test]
    fn test_single_find_all() {
        let mut single = Single::new(RuleVariable::RequestURI);
        single.set("/api/users");

        let matches = single.find_all();
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches.first().map(|matched| matched.variable),
            Some(RuleVariable::RequestURI)
        );
        assert_eq!(matches.first().map(|matched| matched.key.as_str()), Some(""));
        assert_eq!(
            matches.first().map(|matched| matched.value.as_slice()),
            Some(&b"/api/users"[..])
        );
    }

    #[test]
    fn test_single_preserves_invalid_utf8_bytes() {
        let mut single = Single::new(RuleVariable::RequestURI);
        single.set(b"/\xff");

        assert_eq!(single.get_bytes(), b"/\xff");
        assert_eq!(single.get(), "/\u{fffd}");
        let matches = single.find_all();
        assert_eq!(
            matches.first().map(|matched| matched.value.as_slice()),
            Some(&b"/\xff"[..])
        );
        assert_eq!(single.to_string(), "REQUEST_URI: /\u{fffd}");
    }

    #[test]
    fn test_single_display() {
        let mut single = Single::new(RuleVariable::RequestURI);
        single.set("/test");
        assert_eq!(single.to_string(), "REQUEST_URI: /test");
    }

    /// The doc example of `collection::single::Single`, before it became internal.
    #[test]
    fn doc_single_type() {
        use crate::{collection::Single, types::RuleVariable};

        let mut single = Single::new(RuleVariable::RequestURI);
        single.set("/api/users");
        assert_eq!(single.get(), "/api/users");
    }
}
