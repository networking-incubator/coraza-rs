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
    value.chars().map(lowercase_char).collect()
}

/// Lower-case one character the way Go's `unicode.ToLower` does.
///
/// Rust's full mapping expands U+0130 into `i` + U+0307; the first code point of the
/// expansion is the simple mapping Go applies. U+0130 is the only character whose
/// lowercase full mapping expands, so taking the first works for every input.
pub(crate) fn lowercase_char(character: char) -> char {
    character.to_lowercase().next().unwrap_or(character)
}

/// Upper-case one character the way Go's `unicode.ToUpper` does.
///
/// Rust's uppercase mapping is the full one, which expands `ß` into `SS` and `ﬃ` into
/// `FFI`; Go keeps those characters unchanged because its simple mapping has no single
/// code point for them. The Greek iota-subscript characters are the exception: their
/// simple mapping is a different single code point (the prosgegrammeni capital), not the
/// first code point of the full expansion.
pub(crate) fn uppercase_char(character: char) -> char {
    let mut expansion = character.to_uppercase();
    let Some(first) = expansion.next() else {
        return character;
    };
    if expansion.next().is_none() {
        return first;
    }
    match character {
        '\u{1F80}'..='\u{1F87}' | '\u{1F90}'..='\u{1F97}' | '\u{1FA0}'..='\u{1FA7}' => {
            char::from_u32(character as u32 + 8).unwrap_or(character)
        },
        '\u{1FB3}' | '\u{1FC3}' | '\u{1FF3}' => char::from_u32(character as u32 + 9).unwrap_or(character),
        _ => character,
    }
}

/// Append `text` to `out`, lower-cased the way Go's `strings.ToLower` does.
///
/// Encodes each lowered character straight into `out`, so collection hot paths avoid the
/// allocation [`lowercase_like_go`] makes.
pub(crate) fn push_lowercase_like_go(out: &mut Vec<u8>, text: &str) {
    for character in text.chars() {
        let lowered = lowercase_char(character);
        let mut buffer = [0_u8; 4];
        out.extend_from_slice(lowered.encode_utf8(&mut buffer).as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::{lowercase_char, lowercase_like_go, push_lowercase_like_go, uppercase_char};

    #[test]
    fn folds_u_0130_like_go() {
        // Go's simple mapping gives `i`; the full mapping would add U+0307.
        assert_eq!(lowercase_like_go("\u{130}"), "i");
        assert_eq!(lowercase_like_go("X-\u{130}"), "x-i");
        assert_eq!(lowercase_like_go("already"), "already");
    }

    #[test]
    fn simple_case_mapping_matches_go() {
        // Go's strings.ToLower/ToUpper use the simple mapping.
        assert_eq!(lowercase_char('\u{00df}'), '\u{00df}');
        assert_eq!(lowercase_char('\u{0130}'), 'i');
        assert_eq!(lowercase_char('\u{03a3}'), '\u{03c3}');
        assert_eq!(lowercase_char('\u{03c2}'), '\u{03c2}');
        assert_eq!(uppercase_char('\u{00df}'), '\u{00df}');
        assert_eq!(uppercase_char('\u{0130}'), '\u{0130}');
        assert_eq!(uppercase_char('\u{03c2}'), '\u{03a3}');
        assert_eq!(uppercase_char('\u{fb03}'), '\u{fb03}');
        assert_eq!(uppercase_char('\u{01c5}'), '\u{01c4}');
        // The iota-subscript forms map to their prosgegrammeni capitals.
        assert_eq!(uppercase_char('\u{1f80}'), '\u{1f88}');
        assert_eq!(uppercase_char('\u{1fb3}'), '\u{1fbc}');
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
