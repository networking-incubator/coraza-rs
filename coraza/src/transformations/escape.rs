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

//! Byte-oriented escape sequence decoding transformations.

use super::{TransformationResult, unicode_bestfit::best_fit_ascii};
use crate::utils::strings::x2c;

/// Decodes C-style simple, octal, and hexadecimal escape sequences.
pub fn escape_seq_decode(input: &[u8]) -> TransformationResult {
    let Some(start) = input.iter().position(|byte| *byte == b'\\') else {
        return (input.to_vec(), false, None);
    };

    let mut output = Vec::with_capacity(input.len());
    output.extend_from_slice(input.get(..start).unwrap_or_default());
    let mut offset = start;
    let mut changed = false;

    while let Some(&byte) = input.get(offset) {
        let suffix = input.get(offset..).unwrap_or_default();
        if byte == b'\\' {
            if let Some(&escaped) = suffix.get(1) {
                if let Some(decoded) = c_escape(escaped) {
                    output.push(decoded);
                    offset += 2;
                    changed = true;
                } else if matches!(escaped, b'x' | b'X') {
                    if let Some(decoded) = suffix.get(2..4).and_then(x2c) {
                        output.push(decoded);
                        offset += 4;
                    } else {
                        offset += 2;
                    }
                    changed = true;
                } else if is_octal_digit(escaped) {
                    let digits = suffix.get(1..).unwrap_or_default();
                    let count = octal_digit_count(digits, 3);
                    output.push(octal_value(digits.get(..count).unwrap_or_default()));
                    offset += 1 + count;
                    changed = true;
                } else {
                    output.push(escaped);
                    offset += 2;
                }
            } else {
                output.push(byte);
                offset += 1;
            }
        } else {
            output.push(byte);
            offset += 1;
        }
    }

    (output, changed, None)
}

/// Decodes `JavaScript` hexadecimal, Unicode, octal, and simple escapes.
pub fn js_decode(input: &[u8]) -> TransformationResult {
    let Some(start) = input.iter().position(|byte| *byte == b'\\') else {
        return (input.to_vec(), false, None);
    };

    let mut output = Vec::with_capacity(input.len());
    output.extend_from_slice(input.get(..start).unwrap_or_default());
    let mut offset = start;
    let mut changed = false;

    while let Some(&byte) = input.get(offset) {
        let suffix = input.get(offset..).unwrap_or_default();
        if byte == b'\\' {
            if let Some(&escaped) = suffix.get(1) {
                let digits = suffix.get(2..6).unwrap_or_default();
                let unicode_digits =
                    suffix.get(1) == Some(&b'u') && digits.len() == 4 && digits.iter().all(u8::is_ascii_hexdigit);
                if unicode_digits {
                    let upper = digits.get(..2).and_then(x2c);
                    let lower = digits.get(2..4).and_then(x2c);
                    if let (Some(upper), Some(mut decoded)) = (upper, lower) {
                        if upper == 0xFF && decoded > 0 && decoded < 0x5F {
                            decoded += 0x20;
                        }
                        output.push(decoded);
                        offset += 6;
                        changed = true;
                        continue;
                    }
                }

                if escaped == b'x'
                    && let Some(decoded) = suffix.get(2..4).and_then(x2c)
                {
                    output.push(decoded);
                    offset += 4;
                    changed = true;
                    continue;
                }

                if is_octal_digit(escaped) {
                    let octal_digits = suffix.get(1..).unwrap_or_default();
                    let count = octal_digit_count(octal_digits, 3);
                    let count = if count == 3 && escaped > b'3' { 2 } else { count };
                    output.push(octal_value(octal_digits.get(..count).unwrap_or_default()));
                    offset += 1 + count;
                    changed = true;
                    continue;
                }

                output.push(js_escape(escaped));
                offset += 2;
                changed = true;
            } else {
                output.push(byte);
                offset += 1;
            }
        } else {
            output.push(byte);
            offset += 1;
        }
    }

    (output, changed, None)
}

/// Decodes CSS hexadecimal escapes and removes backslashes before other bytes.
pub fn css_decode(input: &[u8]) -> TransformationResult {
    let Some(start) = input.iter().position(|byte| *byte == b'\\') else {
        return (input.to_vec(), false, None);
    };

    let mut output = Vec::with_capacity(input.len());
    output.extend_from_slice(input.get(..start).unwrap_or_default());
    let mut offset = start;

    while let Some(&byte) = input.get(offset) {
        let suffix = input.get(offset..).unwrap_or_default();
        if byte == b'\\' {
            let Some(&escaped) = suffix.get(1) else {
                offset += 1;
                continue;
            };
            let digits = suffix.get(1..).unwrap_or_default();
            let count = hex_digit_count(digits, 6);
            if count > 0 {
                let parsed_code = digits
                    .get(..count)
                    .unwrap_or_default()
                    .iter()
                    .try_fold(0_u32, |value, digit| {
                        hex_value(*digit).map(|digit| (value << 4) | u32::from(digit))
                    });
                let Some(code) = parsed_code else {
                    output.push(escaped);
                    offset += 2;
                    continue;
                };
                let code = match code {
                    0 => u32::from(char::REPLACEMENT_CHARACTER),
                    0xFF01..=0xFF5E => code - 0xFEE0,
                    _ => code,
                };
                let decoded = char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER);
                let mut encoded = [0; 4];
                output.extend_from_slice(decoded.encode_utf8(&mut encoded).as_bytes());
                offset += 1 + count;
                if input.get(offset).is_some_and(|next| is_css_whitespace(*next)) {
                    offset += 1;
                }
            } else if escaped == b'\n' {
                offset += 2;
            } else {
                output.push(escaped);
                offset += 2;
            }
        } else {
            output.push(byte);
            offset += 1;
        }
    }

    (output, true, None)
}

/// Decodes standard URL escapes, plus signs, and IIS `%uHHHH` escapes.
pub fn url_decode_uni(input: &[u8]) -> TransformationResult {
    let Some(start) = input.iter().position(|byte| matches!(*byte, b'%' | b'+')) else {
        return (input.to_vec(), false, None);
    };

    let mut output = Vec::with_capacity(input.len());
    output.extend_from_slice(input.get(..start).unwrap_or_default());
    let mut offset = start;
    let mut changed = false;

    while let Some(&byte) = input.get(offset) {
        let suffix = input.get(offset..).unwrap_or_default();
        if byte == b'%' {
            if matches!(suffix.get(1), Some(b'u' | b'U')) {
                let digits = suffix.get(2..6).unwrap_or_default();
                if digits.len() == 4 && digits.iter().all(u8::is_ascii_hexdigit) {
                    let upper = digits.get(..2).and_then(x2c);
                    let lower = digits.get(2..4).and_then(x2c);
                    if let (Some(upper), Some(lower)) = (upper, lower) {
                        let code = u16::from_be_bytes([upper, lower]);
                        let fallback = if upper == 0xFF && lower > 0 && lower < 0x5F {
                            lower + 0x20
                        } else {
                            lower
                        };
                        output.push(best_fit_ascii(code).unwrap_or(fallback));
                        offset += 6;
                        changed = true;
                        continue;
                    }
                }
                output.extend_from_slice(suffix.get(..2).unwrap_or_default());
                offset += 2;
            } else if let Some(decoded) = suffix.get(1..3).and_then(x2c) {
                output.push(decoded);
                offset += 3;
                changed = true;
            } else {
                output.push(byte);
                offset += 1;
            }
        } else if byte == b'+' {
            output.push(b' ');
            offset += 1;
            changed = true;
        } else {
            output.push(byte);
            offset += 1;
        }
    }

    (output, changed, None)
}

/// Encodes non-ASCII UTF-8 characters as IIS-style `%uHHHH` escapes.
pub fn utf8_to_unicode(input: &[u8]) -> TransformationResult {
    if input.is_ascii() {
        return (input.to_vec(), false, None);
    }

    let mut output = Vec::with_capacity(input.len());
    for chunk in input.utf8_chunks() {
        for character in chunk.valid().chars() {
            append_character(&mut output, character);
        }
        for _ in 0..chunk.invalid().len() {
            append_character(&mut output, char::REPLACEMENT_CHARACTER);
        }
    }
    (output, true, None)
}

/// Returns the decoded byte for a recognized C-style simple escape.
fn c_escape(byte: u8) -> Option<u8> {
    match byte {
        b'a' => Some(b'\x07'),
        b'b' => Some(b'\x08'),
        b'f' => Some(b'\x0c'),
        b'n' => Some(b'\n'),
        b'r' => Some(b'\r'),
        b't' => Some(b'\t'),
        b'v' => Some(b'\x0b'),
        b'\\' => Some(b'\\'),
        b'?' => Some(b'?'),
        b'\'' => Some(b'\''),
        b'"' => Some(b'"'),
        _ => None,
    }
}

/// Returns the decoded byte for a `JavaScript` simple escape.
fn js_escape(byte: u8) -> u8 {
    match byte {
        b'a' => b'\x07',
        b'b' => b'\x08',
        b'f' => b'\x0c',
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        b'v' => b'\x0b',
        other => other,
    }
}

/// Returns whether a byte is an ASCII octal digit.
fn is_octal_digit(byte: u8) -> bool {
    matches!(byte, b'0'..=b'7')
}

/// Counts leading octal digits up to `limit`.
fn octal_digit_count(digits: &[u8], limit: usize) -> usize {
    let mut count = 0;
    while count < limit && digits.get(count).is_some_and(|byte| is_octal_digit(*byte)) {
        count += 1;
    }
    count
}

/// Parses at most three octal digits and keeps the low byte, as Coraza does.
fn octal_value(digits: &[u8]) -> u8 {
    let value = digits
        .iter()
        .fold(0, |value, digit| value * 8 + u16::from(digit.saturating_sub(b'0')));
    u8::try_from(value & 0xFF).unwrap_or_default()
}

/// Counts leading ASCII hexadecimal digits up to `limit`.
fn hex_digit_count(digits: &[u8], limit: usize) -> usize {
    let mut count = 0;
    while count < limit && digits.get(count).is_some_and(u8::is_ascii_hexdigit) {
        count += 1;
    }
    count
}

/// Returns the value of an ASCII hexadecimal digit.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Returns whether a byte is CSS whitespace.
fn is_css_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\x0c' | b'\n' | b'\t' | b'\r' | b'\x0b')
}

/// Appends an ASCII character directly or an IIS escape for a non-ASCII character.
fn append_character(output: &mut Vec<u8>, character: char) {
    if character.is_ascii() {
        output.push(character as u8);
    } else {
        append_unicode_escape(output, u32::from(character));
    }
}

/// Appends a lower-case `%u` escape with at least four hexadecimal digits.
fn append_unicode_escape(output: &mut Vec<u8>, mut code: u32) {
    let mut digits = [b'0'; 6];
    let mut start = digits.len();
    while let Some(position) = start.checked_sub(1) {
        start = position;
        if let Some(slot) = digits.get_mut(position) {
            *slot = hex_digit(u8::try_from(code & 0x0F).unwrap_or_default());
        }
        code >>= 4;
        if code == 0 {
            break;
        }
    }
    if digits.len().saturating_sub(start) < 4 {
        start = digits.len().saturating_sub(4);
    }
    output.extend_from_slice(b"%u");
    output.extend_from_slice(digits.get(start..).unwrap_or_default());
}

/// Returns the lower-case ASCII byte for a hexadecimal nibble.
fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        10..=15 => b'a' + (value - 10),
        _ => b'0',
    }
}

#[cfg(test)]
mod tests {
    use super::{css_decode, escape_seq_decode, js_decode, url_decode_uni, utf8_to_unicode};

    fn assert_result(
        transformation: fn(&[u8]) -> super::TransformationResult,
        input: &[u8],
        expected: &[u8],
        expected_changed: bool,
    ) {
        let (output, changed, error) = transformation(input);
        assert_eq!(output, expected);
        assert_eq!(changed, expected_changed);
        assert!(error.is_none());
    }

    #[test]
    fn escape_seq_decode_matches_c_escape_behavior() {
        assert_result(
            escape_seq_decode,
            b"\\a\\b\\f\\n\\r\\t\\v\\?\\'\\\"\\0\\12\\123\\x00\\xff",
            &[
                0x07, 0x08, 0x0C, 0x0A, 0x0D, 0x09, 0x0B, b'?', b'\'', b'"', 0, 10, 83, 0, 255,
            ],
            true,
        );
        assert_result(escape_seq_decode, b"\\8", b"8", false);
        assert_result(escape_seq_decode, b"\\xag", b"ag", true);
        assert_result(escape_seq_decode, b"\\", b"\\", false);
        assert_result(escape_seq_decode, b"\\xff\xfe", b"\xff\xfe", true);
    }

    #[test]
    fn js_decode_matches_javascript_escape_behavior() {
        assert_result(js_decode, b"\\u0048\\x65\\154\\154\\u006f", b"Hello", true);
        assert_result(js_decode, b"\\uff41\\uff21", b"aA", true);
        assert_result(js_decode, b"\\777", b"?7", true);
        assert_result(js_decode, b"\\u123x\\x4z", b"u123xx4z", true);
        assert_result(js_decode, b"\\x80\\200", b"\x80\x80", true);
        assert_result(js_decode, b"\\", b"\\", false);
    }

    #[test]
    fn css_decode_handles_hex_points_and_line_continuations() {
        assert_result(css_decode, b"\\48 ello\\ff41", b"Helloa", true);
        assert_result(
            css_decode,
            b"\\123\\1234\\12345\\123456\\0",
            "\u{123}\u{1234}\u{12345}\u{fffd}\u{fffd}".as_bytes(),
            true,
        );
        assert_result(css_decode, b"A\\\nB\\g\\", b"ABg", true);
        assert_result(css_decode, b"\\d800", "\u{fffd}".as_bytes(), true);
        assert_result(css_decode, b"\\ff\xfe", b"\xc3\xbf\xfe", true);
    }

    #[test]
    fn url_decode_uni_handles_best_fit_and_invalid_sequences() {
        assert_result(url_decode_uni, b"Hello+%20%u0057orld", b"Hello  World", true);
        assert_result(
            url_decode_uni,
            b"%u201dQuoted%u2019s%u2018 word%u2014dash",
            b"\"Quoted's' word-dash",
            true,
        );
        assert_result(url_decode_uni, b"%uff41%u4e2d%uff80%ff", b"a-\x80\xff", true);
        assert_result(url_decode_uni, b"%GG%2%u12%uGGGG", b"%GG%2%u12%uGGGG", false);
        assert_result(url_decode_uni, b"%u12%20", b"%u12 ", true);
    }

    #[test]
    fn utf8_to_unicode_preserves_ascii_and_replaces_invalid_bytes() {
        assert_result(utf8_to_unicode, b"Hello", b"Hello", false);
        assert_result(utf8_to_unicode, b"caf\xc3\xa9", b"caf%u00e9", true);
        assert_result(utf8_to_unicode, b"\xe4\xb8\xad", b"%u4e2d", true);
        assert_result(utf8_to_unicode, b"\xf0\x9f\x98\x80", b"%u1f600", true);
        assert_result(utf8_to_unicode, b"a\xff\xfe", b"a%ufffd%ufffd", true);
    }
}
