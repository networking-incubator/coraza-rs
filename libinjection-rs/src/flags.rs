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

//! `SQLi` dialect / quote flags for the shared tokenizer and legacy engine.
//!
//! Bit values will match libinjection-go in Phase 2a. Distinct from
//! [`crate::snapshot::ConstructFlags`] (modern construct bits).

/// Parser mode flags (quote context + SQL dialect), packed as a bitset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SqliFlags(pub u32);

impl SqliFlags {
    /// No quote simulation; dialect unset / default.
    pub const NONE: Self = Self(0);

    // Phase 2a / tokenizer lessons will add Go-compatible bits, for example:
    // pub const QUOTE_NONE: Self = Self(...);
    // pub const QUOTE_SINGLE: Self = Self(...);
    // pub const SQL_ANSI: Self = Self(...);
    // pub const SQL_MYSQL: Self = Self(...);
}
