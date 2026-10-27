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

//! Collection types for storing and retrieving variable data.
//!
//! Collections are used to store transaction data such as request headers,
//! query parameters, cookies, etc. They support:
//! - Case-sensitive and case-insensitive key lookups
//! - Multiple values per key
//! - Regex-based key matching
//! - Finding all values in the collection
//!
//! # Collection types
//!
//! - [`Single`] - a variable with one value
//! - [`Map`] - a variable with values selected by key

use crate::types::RuleVariable;

mod map;
mod single;

pub use map::Map;
pub use single::Single;

/// Metadata about a matched variable during rule evaluation.
///
/// Contains information about which variable matched (e.g., ARGS, HEADERS),
/// the specific key (e.g., "id" in ARGS:id), and the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchData {
    /// The variable that matched (e.g., `ARGS`, `REQUEST_HEADERS`).
    pub variable: RuleVariable,
    /// The specific key (e.g., "id" for ARGS:id), empty if no key
    pub key: String,
    /// The value of the variable, as bytes
    pub value: Vec<u8>,
    /// The rule's `msg`, as expanded for this match; empty when not expanded or unset
    pub message: String,
    /// The rule's `logdata`, as expanded for this match; empty when not expanded or unset
    pub data: String,
    /// Chain depth for this match (parent is 0; maximum is `u16::MAX`).
    /// Added before 1.0 for multiphase suppression.
    pub chain_level: u16,
}

impl MatchData {
    /// Create a new `MatchData` instance.
    pub(crate) fn new(variable: RuleVariable, key: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            variable,
            key: key.into(),
            value: value.into(),
            message: String::new(),
            data: String::new(),
            chain_level: 0,
        }
    }

    /// Create a `MatchData` instance without a key.
    pub(crate) fn without_key(variable: RuleVariable, value: impl Into<Vec<u8>>) -> Self {
        Self::new(variable, String::new(), value)
    }

    /// The value as text, invalid UTF-8 replaced with U+FFFD.
    pub fn value_text(&self) -> std::borrow::Cow<'_, str> {
        crate::transformations::text_of(&self.value)
    }

    /// Create an empty `MatchData` instance for operator-less rules.
    ///
    /// Used for rules without operators (`SecAction`, `SecMarker`) that always match.
    pub(crate) fn new_empty() -> Self {
        Self::new(RuleVariable::Unknown, String::new(), String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::MatchData;
    use crate::types::RuleVariable;

    #[test]
    fn value_text_borrows_valid_utf8() {
        let matched = MatchData::new(RuleVariable::Args, "id", b"value".to_vec());

        assert!(matches!(matched.value_text(), std::borrow::Cow::Borrowed("value")));
    }

    #[test]
    fn value_text_replaces_invalid_utf8_without_mutating_value() {
        let matched = MatchData::new(RuleVariable::Args, "id", b"\xff".to_vec());

        assert_eq!(matched.value_text(), "\u{fffd}");
        assert_eq!(matched.value, b"\xff");
    }
}
