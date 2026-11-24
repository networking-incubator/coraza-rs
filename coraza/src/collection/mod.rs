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

use std::borrow::Cow;

use crate::types::RuleVariable;

mod map;
mod single;

pub use map::Map;
#[cfg(test)]
pub(crate) use map::keys_scanned;
pub(crate) use map::{
    ALLOCATION_OVERHEAD_BYTES, FIRST_INSERT_OVERHEAD_BYTES, Growth, INSERT_OVERHEAD_BYTES, IndexedValue,
    KEY_COPIES_PER_INSERT, KEY_RETAINED_BYTES_PER_BYTE, VALUE_ENTRY_BYTES, allocation_bytes, fold_scratch_bytes,
    grown_list_capacity, index_capacity_for, index_growth, index_table_bytes, key_bytes, map_capacity_bytes,
    vec_grown_capacity,
};
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
    /// Chain depth for this match (parent is 0), matching Go's `int` depth.
    /// Added before 1.0 for multiphase suppression.
    pub chain_level: usize,
}

/// What a match takes in the list that holds it, which a list that doubles holds twice over at most.
pub(crate) const MATCH_SLOT_BYTES: usize = 2 * size_of::<MatchData>();

/// A stable position for fetching one selected value after its collection borrow ends.
#[derive(Debug, Clone, Copy)]
pub(crate) enum MatchLocation {
    /// A value in a map, optionally exposing the key as the selected value.
    Map {
        /// The transaction collection that owns the map.
        source: RuleVariable,
        /// Entry position in insertion order.
        entry_index: usize,
        /// Value position for repeated keys.
        value_index: usize,
        /// Whether this selector returns the key bytes rather than the stored value.
        names: bool,
    },
    /// A single-value collection.
    Single {
        /// The transaction collection that owns the value.
        variable: RuleVariable,
    },
}

/// A selected match that borrows collection values until an operator reports a result.
pub(crate) struct MatchRef<'a> {
    /// The selected variable.
    pub(crate) variable: RuleVariable,
    /// The lossy key reported to actions and logs, which the collection stores as text and so is never copied.
    pub(crate) key: &'a str,
    /// The original selected bytes.
    pub(crate) value: Cow<'a, [u8]>,
    /// The source position, if this match can be fetched again after releasing its borrow.
    pub(crate) location: Option<MatchLocation>,
}

impl MatchRef<'_> {
    /// The variable this match refers to.
    pub(crate) fn variable(&self) -> RuleVariable {
        self.variable
    }

    /// The lossy text key reported to rule actions and logs.
    pub(crate) fn key(&self) -> &str {
        self.key
    }

    /// The selected value bytes.
    pub(crate) fn value(&self) -> &[u8] {
        &self.value
    }

    /// The source position, if this match came from a transaction collection.
    pub(crate) fn location(&self) -> Option<MatchLocation> {
        self.location
    }

    /// Copy this match when an operator result requires mutation of its collection.
    pub(crate) fn to_owned(&self) -> MatchData {
        MatchData::new(self.variable, self.key, self.value.as_ref())
    }

    /// Materialize the selected match after it matters to rule evaluation.
    pub(crate) fn into_owned(self) -> MatchData {
        MatchData::new(self.variable, self.key, self.value.into_owned())
    }

    #[cfg(test)]
    pub(crate) fn value_is_borrowed(&self) -> bool {
        matches!(self.value, Cow::Borrowed(_))
    }
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
    pub fn value_text(&self) -> Cow<'_, str> {
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
