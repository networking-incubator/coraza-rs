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

//! Hot-path size budgets.
//!
//! Scan depth is Coraza policy (defaults + `AnalyzeOptions`).
//! Stack buffer sizes are hard library requirements.
//! See `docs/MODERNIZATION_PLAN.md` section Scan budget.

/// Default stage-1 scan budget for `analyze_*` / `detect_*` without options.
///
/// This is a bounded modern-analysis budget, not a libinjection-go limit. When
/// the `legacy` feature is enabled, `detect_*` performs a full-input legacy
/// compatibility fallback if this budget truncates the input.
pub const DEFAULT_MAX_INPUT_LEN: usize = 8192;

/// Hard clamp for stage-1 scan budget (`u16::MAX`). Never unbounded, even if misconfigured.
pub const ABSOLUTE_MAX_INPUT_LEN: usize = 65_535;

/// Alias for [`DEFAULT_MAX_INPUT_LEN`] (same value).
pub const MAX_INPUT_LEN: usize = DEFAULT_MAX_INPUT_LEN;

/// Stack buffer size for bounded normalization (hard, not caller-overridable).
pub const NORM_BUF_LEN: usize = 512;

/// Fixed token slot count: offsets into input, no copies (hard).
pub const MAX_TOKEN_SLOTS: usize = 8;

/// Max evidence spans stored in an `AnalysisSnapshot` (hard).
pub const MAX_EVIDENCE: usize = 4;

/// Documented per-call stack budget target in bytes (soft engineering ceiling).
pub const MAX_STACK_BUDGET: usize = 4096;

/// Clamp a requested scan budget to [`ABSOLUTE_MAX_INPUT_LEN`].
///
/// Values at or below the absolute max are unchanged. Larger values are capped.
///
/// # Examples
///
/// ```
/// use libinjection::limits::{
///     ABSOLUTE_MAX_INPUT_LEN, DEFAULT_MAX_INPUT_LEN, clamp_max_input_len,
/// };
///
/// assert_eq!(
///     clamp_max_input_len(DEFAULT_MAX_INPUT_LEN),
///     DEFAULT_MAX_INPUT_LEN
/// );
/// assert_eq!(
///     clamp_max_input_len(ABSOLUTE_MAX_INPUT_LEN),
///     ABSOLUTE_MAX_INPUT_LEN
/// );
/// assert_eq!(clamp_max_input_len(usize::MAX), ABSOLUTE_MAX_INPUT_LEN);
/// ```
#[must_use]
pub const fn clamp_max_input_len(requested: usize) -> usize {
    if requested > ABSOLUTE_MAX_INPUT_LEN {
        ABSOLUTE_MAX_INPUT_LEN
    } else {
        requested
    }
}

/// Return the prefix of `input` to scan and whether the input was truncated.
#[must_use]
pub fn scan_prefix(input: &[u8], max_len: usize) -> (&[u8], bool) {
    match input.get(..max_len) {
        Some(prefix) if prefix.len() < input.len() => (prefix, true),
        _ => (input, false),
    }
}
