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

//! Byte-oriented encoding transformations.

use crate::{
    transformations::{TransformationError, TransformationResult},
    utils::strings::x2c,
};

/// Returns the input length in bytes as decimal digits.
pub fn length(input: &[u8]) -> TransformationResult {
    (input.len().to_string().into_bytes(), true, None)
}

/// Returns the input unchanged.
pub fn none(input: &[u8]) -> TransformationResult {
    (input.to_vec(), false, None)
}

/// Removes all NUL bytes from the input.
pub fn remove_nulls(input: &[u8]) -> TransformationResult {
    if !input.contains(&0) {
        return (input.to_vec(), false, None);
    }

    let transformed = input.iter().copied().filter(|byte| *byte != 0).collect();
    (transformed, true, None)
}

/// Replaces all NUL bytes with spaces.
pub fn replace_nulls(input: &[u8]) -> TransformationResult {
    let mut changed = false;
    let transformed = input
        .iter()
        .map(|byte| {
            if *byte == 0 {
                changed = true;
                b' '
            } else {
                *byte
            }
        })
        .collect();
    (transformed, changed, None)
}

/// Encodes each input byte as two lowercase hexadecimal digits.
pub fn hex_encode(input: &[u8]) -> TransformationResult {
    let mut transformed = Vec::new();
    for byte in input.iter().copied() {
        transformed.push(hex_digit(byte >> 4));
        transformed.push(hex_digit(byte & 0x0F));
    }
    (transformed, true, None)
}

/// Decodes hexadecimal input into bytes.
///
/// Odd-length or invalid input returns an empty result and an error.
pub fn hex_decode(input: &[u8]) -> TransformationResult {
    if !input.len().is_multiple_of(2) {
        return (
            Vec::new(),
            false,
            Some(TransformationError::new("odd length hex string")),
        );
    }

    let mut transformed = Vec::with_capacity(input.len() / 2);
    for pair in input.chunks_exact(2) {
        let Some(decoded) = x2c(pair) else {
            return (Vec::new(), false, Some(TransformationError::new("invalid hex string")));
        };
        transformed.push(decoded);
    }
    (transformed, true, None)
}

/// URL encodes bytes, using plus for spaces and lowercase percent escapes.
///
/// ASCII alphanumerics and asterisk are left unchanged. All other bytes are
/// percent encoded.
pub fn url_encode(input: &[u8]) -> TransformationResult {
    let mut transformed = Vec::new();
    let mut changed = false;
    for byte in input.iter().copied() {
        match byte {
            b' ' => {
                transformed.push(b'+');
                changed = true;
            },
            b'*' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => transformed.push(byte),
            _ => {
                transformed.push(b'%');
                transformed.push(hex_digit(byte >> 4));
                transformed.push(hex_digit(byte & 0x0F));
                changed = true;
            },
        }
    }
    (transformed, changed, None)
}

/// Encodes input bytes using standard Base64 with padding.
pub fn base64_encode(input: &[u8]) -> TransformationResult {
    let mut transformed = Vec::new();
    for chunk in input.chunks(3) {
        let first = chunk.first().copied().unwrap_or_default();
        let second = chunk.get(1).copied().unwrap_or_default();
        let third = chunk.get(2).copied().unwrap_or_default();
        let value = (u32::from(first) << 16) | (u32::from(second) << 8) | u32::from(third);

        transformed.push(base64_digit(((value >> 18) & 0x3F) as u8));
        transformed.push(base64_digit(((value >> 12) & 0x3F) as u8));
        if chunk.len() > 1 {
            transformed.push(base64_digit(((value >> 6) & 0x3F) as u8));
        } else {
            transformed.push(b'=');
        }
        if chunk.len() > 2 {
            transformed.push(base64_digit((value & 0x3F) as u8));
        } else {
            transformed.push(b'=');
        }
    }
    (transformed, true, None)
}

/// Converts a nibble to a lowercase hexadecimal digit.
fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + value - 10,
    }
}

/// Converts a six-bit value to a standard Base64 digit.
fn base64_digit(value: u8) -> u8 {
    match value {
        0..=25 => b'A' + value,
        26..=51 => b'a' + value - 26,
        52..=61 => b'0' + value - 52,
        62 => b'+',
        _ => b'/',
    }
}

#[cfg(test)]
mod tests {
    use super::{base64_encode, hex_decode, hex_encode, length, none, remove_nulls, replace_nulls, url_encode};

    #[test]
    fn length_and_identity_use_input_bytes() {
        assert_eq!(length(b"\x00\xff"), (b"2".to_vec(), true, None));
        assert_eq!(none(b"\x00\xff"), (b"\x00\xff".to_vec(), false, None));
        assert_eq!(length(b""), (b"0".to_vec(), true, None));
    }

    #[test]
    fn nul_transforms_preserve_other_bytes() {
        assert_eq!(remove_nulls(b"a\x00\xff\x00b"), (b"a\xffb".to_vec(), true, None));
        assert_eq!(replace_nulls(b"a\x00\xff"), (b"a \xff".to_vec(), true, None));
        assert_eq!(replace_nulls(b"plain"), (b"plain".to_vec(), false, None));
    }

    #[test]
    fn hex_transforms_round_trip_binary_and_reject_invalid_input() {
        assert_eq!(hex_encode(b"\x00\xff"), (b"00ff".to_vec(), true, None));
        assert_eq!(hex_decode(b"00Ff"), (b"\x00\xff".to_vec(), true, None));

        let (odd, odd_changed, odd_error) = hex_decode(b"0");
        assert!(odd.is_empty());
        assert!(!odd_changed);
        assert_eq!(
            odd_error.map(|error| error.message().to_owned()),
            Some("odd length hex string".to_owned())
        );

        let (invalid, invalid_changed, invalid_error) = hex_decode(b"0g");
        assert!(invalid.is_empty());
        assert!(!invalid_changed);
        assert!(invalid_error.is_some());
    }

    #[test]
    fn url_encoding_operates_on_bytes() {
        assert_eq!(url_encode(b"a b/\xff"), (b"a+b%2f%ff".to_vec(), true, None));
        assert_eq!(url_encode(b"plain*AZ09"), (b"plain*AZ09".to_vec(), false, None));
        assert_eq!(url_encode(b""), (Vec::new(), false, None));
    }

    #[test]
    fn base64_encoding_handles_padding_and_binary_input() {
        assert_eq!(base64_encode(b"A"), (b"QQ==".to_vec(), true, None));
        assert_eq!(base64_encode(b"AB"), (b"QUI=".to_vec(), true, None));
        assert_eq!(base64_encode(b"ABC"), (b"QUJD".to_vec(), true, None));
        assert_eq!(base64_encode(b"\x00\xff"), (b"AP8=".to_vec(), true, None));
        assert_eq!(base64_encode(b""), (Vec::new(), true, None));
    }
}
