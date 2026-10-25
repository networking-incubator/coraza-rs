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

//! Key folding shared by the collections, the rule targets, and `ctl`.

/// Lower-case `value` the way Go's `strings.ToLower` does.
///
/// Rust's `str::to_lowercase` applies the full mapping, so U+0130 becomes `i` + U+0307;
/// Go's simple mapping gives `i`. U+0130 is the only character whose
/// full mapping expands, and the first character of any full expansion equals the simple
/// mapping, so taking the first character matches Go for every input. Do not replace this
/// with `str::to_lowercase`: it widens key comparisons that Go keeps separate.
pub(crate) fn lowercase_like_go(value: &str) -> String {
    value
        .chars()
        .map(|character| character.to_lowercase().next().unwrap_or(character))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::lowercase_like_go;

    #[test]
    fn folds_u_0130_like_go() {
        // Go's simple mapping gives `i`; the full mapping would add U+0307.
        assert_eq!(lowercase_like_go("\u{130}"), "i");
        assert_eq!(lowercase_like_go("X-\u{130}"), "x-i");
        assert_eq!(lowercase_like_go("already"), "already");
    }
}
