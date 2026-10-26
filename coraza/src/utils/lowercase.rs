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
/// with `str::to_lowercase`: the full mapping splits U+0130 into two code points, which
/// stops `İ` from comparing equal to `i` and starts it comparing equal to the two-code-point
/// sequence Go keeps distinct.
pub(crate) fn lowercase_like_go(value: &str) -> String {
    value
        .chars()
        .map(|character| character.to_lowercase().next().unwrap_or(character))
        .collect()
}

/// Append `text` to `out`, lower-cased the way Go's `strings.ToLower` does.
///
/// Encodes each lowered character straight into `out`, so collection hot paths avoid the
/// allocation [`lowercase_like_go`] makes.
pub(crate) fn push_lowercase_like_go(out: &mut Vec<u8>, text: &str) {
    for character in text.chars() {
        let lowered = character.to_lowercase().next().unwrap_or(character);
        let mut buffer = [0_u8; 4];
        out.extend_from_slice(lowered.encode_utf8(&mut buffer).as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::{lowercase_like_go, push_lowercase_like_go};

    #[test]
    fn folds_u_0130_like_go() {
        // Go's simple mapping gives `i`; the full mapping would add U+0307.
        assert_eq!(lowercase_like_go("\u{130}"), "i");
        assert_eq!(lowercase_like_go("X-\u{130}"), "x-i");
        assert_eq!(lowercase_like_go("already"), "already");
    }

    #[test]
    fn push_matches_the_string_helper() {
        for text in [
            "",
            "already",
            "Mixed-ASCII",
            "\u{130}",
            "X-\u{130}",
            "\u{00c4}\u{00df}",
            "\u{03a3}",
        ] {
            let mut pushed = Vec::new();
            push_lowercase_like_go(&mut pushed, text);
            assert_eq!(
                std::str::from_utf8(&pushed),
                Ok(lowercase_like_go(text).as_str()),
                "{text:?}"
            );
        }
    }
}
