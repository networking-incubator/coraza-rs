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
    pub(crate) fn new(variable: RuleVariable) -> Self {
        Self {
            data: Vec::new(),
            variable,
        }
    }

    /// Set the value.
    pub(crate) fn set(&mut self, value: impl AsRef<[u8]>) {
        self.data.clear();
        self.data.extend_from_slice(value.as_ref());
    }

    /// Set a value assembled from a prefix, separator, and suffix.
    pub(crate) fn set_joined(&mut self, prefix: &[u8], separator: &[u8], suffix: &[u8]) {
        self.data.clear();
        // One growth, to what the whole needs: a charge for this buffer is for one, and three appends grow it up to
        // three.
        self.data.reserve(
            prefix
                .len()
                .saturating_add(separator.len())
                .saturating_add(suffix.len()),
        );
        self.data.extend_from_slice(prefix);
        self.data.extend_from_slice(separator);
        self.data.extend_from_slice(suffix);
    }

    /// Clear request data and drop unusually large retained buffers before pooling.
    pub(crate) fn reset_for_reuse(&mut self) {
        // shortcut: drop buffers above 4 KiB; raise after profiling shows large values recur.
        const MAX_RETAINED_CAPACITY: usize = 4 * 1024;
        self.data.clear();
        if self.data.capacity() > MAX_RETAINED_CAPACITY {
            self.data = Vec::new();
        }
    }

    /// Remove request data and release capacity charged to an active body budget.
    pub(crate) fn reset_and_release(&mut self) {
        self.data.clear();
        self.data.shrink_to_fit();
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

    /// Bytes held by the stored value's backing allocation.
    pub(crate) fn allocated_bytes(&self) -> usize {
        self.data.capacity()
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
    fn replacing_a_value_reuses_its_buffer() {
        let mut single = Single::new(RuleVariable::RequestURI);
        single.set("a longer request target");
        let capacity = single.allocated_bytes();

        single.set("short");

        assert_eq!(single.get_bytes(), b"short");
        assert_eq!(single.allocated_bytes(), capacity);
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
