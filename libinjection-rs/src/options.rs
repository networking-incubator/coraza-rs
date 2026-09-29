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

//! Caller-facing analysis options (Coraza policy knobs).

use crate::limits::{DEFAULT_MAX_INPUT_LEN, clamp_max_input_len};

/// Policy for inputs that exceed the configured scan budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TruncationPolicy {
    /// Treat an incomplete analysis as requiring blocking at the policy seam.
    FailClosed,
    /// Return [`crate::snapshot::VerdictHint::Inconclusive`] and let the caller continue inspection.
    AllowInconclusive,
}

/// Options for stage-1 `analyze_*` / `detect_*`.
///
/// Set at WAF init / operator config. Never from untrusted request metadata.
///
/// # Examples
///
/// ```
/// use libinjection::{
///     limits::{ABSOLUTE_MAX_INPUT_LEN, DEFAULT_MAX_INPUT_LEN},
///     options::AnalyzeOptions,
/// };
///
/// let default_opts = AnalyzeOptions::default();
/// assert_eq!(default_opts.max_input_len, DEFAULT_MAX_INPUT_LEN);
/// assert_eq!(
///     default_opts.effective_max_input_len(),
///     DEFAULT_MAX_INPUT_LEN
/// );
///
/// let raised = AnalyzeOptions::with_max_input_len(16_384);
/// assert_eq!(raised.effective_max_input_len(), 16_384);
///
/// let too_large = AnalyzeOptions::with_max_input_len(usize::MAX);
/// assert_eq!(too_large.effective_max_input_len(), ABSOLUTE_MAX_INPUT_LEN);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnalyzeOptions {
    /// Requested scan budget in bytes.
    /// Clamped to `ABSOLUTE_MAX_INPUT_LEN` when applied inside analyze.
    pub max_input_len: usize,
    /// How to treat input that exceeds `max_input_len`.
    pub truncation_policy: TruncationPolicy,
}

impl AnalyzeOptions {
    /// Build options with an explicit scan budget (clamped on use).
    #[must_use]
    pub const fn with_max_input_len(max_input_len: usize) -> Self {
        Self {
            max_input_len,
            truncation_policy: TruncationPolicy::FailClosed,
        }
    }

    /// Allow a caller to continue with an incomplete snapshot.
    #[must_use]
    pub const fn allow_truncation(self) -> Self {
        Self {
            truncation_policy: TruncationPolicy::AllowInconclusive,
            ..self
        }
    }

    /// Scan budget after applying the absolute clamp.
    #[must_use]
    pub const fn effective_max_input_len(self) -> usize {
        clamp_max_input_len(self.max_input_len)
    }
}

impl Default for AnalyzeOptions {
    /// Defaults to [`DEFAULT_MAX_INPUT_LEN`].
    fn default() -> Self {
        Self {
            max_input_len: DEFAULT_MAX_INPUT_LEN,
            truncation_policy: TruncationPolicy::FailClosed,
        }
    }
}
