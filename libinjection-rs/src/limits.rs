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

//! Input budget for construct analysis.
//!
//! These limits apply only to `analyze_*`. Canonical `detect_*` compatibility
//! APIs scan the complete input. Analysis storage grows with the selected input
//! prefix, so configure the budget at WAF initialization rather than from
//! untrusted request metadata.

/// Default byte budget for bounded `analyze_*` calls without explicit options.
pub const DEFAULT_MAX_INPUT_LEN: usize = 8192;

/// Alias for [`DEFAULT_MAX_INPUT_LEN`].
pub const MAX_INPUT_LEN: usize = DEFAULT_MAX_INPUT_LEN;

/// Return the prefix of `input` to scan and whether the input was truncated.
#[must_use]
pub fn scan_prefix(input: &[u8], max_len: usize) -> (&[u8], bool) {
    match input.get(..max_len) {
        Some(prefix) if prefix.len() < input.len() => (prefix, true),
        _ => (input, false),
    }
}
