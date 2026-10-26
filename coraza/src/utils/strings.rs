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

//! Byte-oriented string helpers for Coraza rule processing.

use std::fmt::Write as _;

/// Returns true if `byte` is an ASCII hexadecimal digit.
#[inline]
pub const fn valid_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

/// Converts exactly two ASCII hexadecimal bytes to their value.
pub fn x2c(input: &[u8]) -> Option<u8> {
    if input.len() != 2 {
        return None;
    }

    let high = hex_value(*input.first()?)?;
    let low = hex_value(*input.get(1)?)?;
    Some(high * 16 + low)
}

/// Removes matching single or double quotes from the ends of `input`.
pub fn maybe_remove_quotes(input: &[u8]) -> &[u8] {
    if input.len() < 2 {
        return input;
    }

    let Some(quote @ (b'\'' | b'"')) = input.first().copied() else {
        return input;
    };
    if input.last() != Some(&quote) {
        return input;
    }

    input.get(1..input.len().saturating_sub(1)).unwrap_or(input)
}

/// Unescapes `\\"` to `"` and preserves all other input bytes.
pub fn unescape_quoted_string(input: &[u8]) -> Vec<u8> {
    if !input.windows(2).any(|window| window == b"\\\"") {
        return input.to_vec();
    }

    let mut output = Vec::with_capacity(input.len());
    let mut offset = 0;
    while let Some(&byte) = input.get(offset) {
        if input.get(offset..).is_some_and(|suffix| suffix.starts_with(b"\\\"")) {
            output.push(b'"');
            offset += 2;
        } else {
            output.push(byte);
            offset += 1;
        }
    }
    output
}

/// Converts one ASCII hexadecimal byte to its value.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Quote a string using Go's `strconv.Quote` conventions.
pub(crate) fn go_quote(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for character in text.chars() {
        push_go_quoted(&mut quoted, character);
    }
    quoted.push('"');
    quoted
}

/// Quote `bytes` as Go's `%q` quotes a string: valid UTF-8 text is escaped like
/// [`go_quote`], and a byte that is not valid UTF-8 becomes `\xNN`.
pub(crate) fn go_quote_bytes(bytes: &[u8]) -> String {
    let mut quoted = String::with_capacity(bytes.len() + 2);
    quoted.push('"');
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                for character in text.chars() {
                    push_go_quoted(&mut quoted, character);
                }
                break;
            },
            Err(error) => {
                let valid = error.valid_up_to();
                if let Ok(text) = std::str::from_utf8(rest.get(..valid).unwrap_or_default()) {
                    for character in text.chars() {
                        push_go_quoted(&mut quoted, character);
                    }
                }
                let invalid = error.error_len().unwrap_or_else(|| rest.len().saturating_sub(valid));
                let end = valid.saturating_add(invalid);
                for byte in rest.get(valid..end).unwrap_or_default() {
                    write!(quoted, "\\x{byte:02x}").unwrap_or(());
                }
                rest = rest.get(end..).unwrap_or_default();
            },
        }
    }
    quoted.push('"');
    quoted
}

/// Append `character` to `quoted` as Go's `strconv.Quote` escapes it.
fn push_go_quoted(quoted: &mut String, character: char) {
    match character {
        '"' => quoted.push_str("\\\""),
        '\\' => quoted.push_str("\\\\"),
        '\u{07}' => quoted.push_str("\\a"),
        '\u{08}' => quoted.push_str("\\b"),
        '\u{0c}' => quoted.push_str("\\f"),
        '\n' => quoted.push_str("\\n"),
        '\r' => quoted.push_str("\\r"),
        '\t' => quoted.push_str("\\t"),
        '\u{0b}' => quoted.push_str("\\v"),
        character if (character as u32) < 0x20 || character as u32 == 0x7F => {
            write!(quoted, "\\x{:02x}", character as u32).unwrap_or(());
        },
        character if character.is_control() => {
            write!(quoted, "\\u{:04x}", character as u32).unwrap_or(());
        },
        character => quoted.push(character),
    }
}

#[cfg(test)]
mod tests {
    use super::{maybe_remove_quotes, unescape_quoted_string, valid_hex, x2c};

    #[test]
    fn valid_hex_accepts_ascii_hex_digits_only() {
        for byte in b"0123456789abcdefABCDEF" {
            assert!(valid_hex(*byte));
        }
        for byte in [b'g', b'G', b' ', 0x80, 0xFF] {
            assert!(!valid_hex(byte));
        }
    }

    #[test]
    fn x2c_decodes_ascii_hex_pairs() {
        assert_eq!(x2c(b"00"), Some(0));
        assert_eq!(x2c(b"0a"), Some(10));
        assert_eq!(x2c(b"41"), Some(b'A'));
        assert_eq!(x2c(b"fF"), Some(255));
    }

    #[test]
    fn x2c_rejects_wrong_length_and_non_hex_bytes() {
        for input in [&b""[..], b"1", b"123", b"G1", b"\xff0"] {
            assert_eq!(x2c(input), None);
        }
    }

    #[test]
    fn maybe_remove_quotes_preserves_bytes_and_only_matching_quotes() {
        assert_eq!(maybe_remove_quotes(b"\"hello\""), b"hello");
        assert_eq!(maybe_remove_quotes(b"'hello'"), b"hello");
        assert_eq!(maybe_remove_quotes(b"\"hello'"), b"\"hello'");
        assert_eq!(maybe_remove_quotes(b"\"hello"), b"\"hello");
        assert_eq!(maybe_remove_quotes(b"\"\xff\""), b"\xff");
        assert_eq!(maybe_remove_quotes(b""), b"");
    }

    #[test]
    fn unescape_quoted_string_preserves_other_bytes() {
        assert_eq!(unescape_quoted_string(b"hello \\\"world\\\""), b"hello \"world\"");
        assert_eq!(unescape_quoted_string(b"\\n"), b"\\n");
        assert_eq!(unescape_quoted_string(b"\xff\\\"\x80"), vec![0xFF, b'"', 0x80]);
        assert_eq!(unescape_quoted_string(b"no escapes"), b"no escapes");
    }
}
