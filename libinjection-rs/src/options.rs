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

//! Caller-facing scan budget for construct analysis.

use crate::limits::DEFAULT_MAX_INPUT_LEN;

/// Options for the bounded `analyze_*` APIs.
///
/// Set at WAF initialization or operator configuration, never from request
/// metadata. Inputs above the limit are analyzed as a prefix and the resulting
/// snapshot sets [`crate::snapshot::AnalysisFlags::TRUNCATED`]. Normalization,
/// token metadata, and evidence storage grow only with that selected prefix.
///
/// # Examples
///
/// ```
/// use libinjection::{limits::DEFAULT_MAX_INPUT_LEN, options::AnalyzeOptions};
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
/// let uncapped = AnalyzeOptions::with_max_input_len(usize::MAX);
/// assert_eq!(uncapped.effective_max_input_len(), usize::MAX);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnalyzeOptions {
    /// Requested input-prefix scan budget in bytes.
    /// The scan budget is trusted configuration and is not internally clamped.
    pub max_input_len: usize,
}

impl AnalyzeOptions {
    /// Build options with an explicit scan budget.
    #[must_use]
    pub const fn with_max_input_len(max_input_len: usize) -> Self {
        Self { max_input_len }
    }

    /// Configured scan budget.
    #[must_use]
    pub const fn effective_max_input_len(self) -> usize {
        self.max_input_len
    }
}

impl Default for AnalyzeOptions {
    /// Defaults to [`DEFAULT_MAX_INPUT_LEN`].
    fn default() -> Self {
        Self {
            max_input_len: DEFAULT_MAX_INPUT_LEN,
        }
    }
}
