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

use md5::{Digest as _, Md5};
use sha1::Sha1;

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
    for pair in input.as_chunks::<2>().0 {
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

/// Computes the MD5 digest as raw bytes. Follow it with `hex_encode` for hex output.
pub fn md5_hash(input: &[u8]) -> TransformationResult {
    (Md5::digest(input).to_vec(), true, None)
}

/// Computes the SHA1 digest as raw bytes. Follow it with `hex_encode` for hex output.
pub fn sha1_hash(input: &[u8]) -> TransformationResult {
    (Sha1::digest(input).to_vec(), true, None)
}

/// Decodes Base64 up to the first invalid byte. CR and LF are ignored.
pub fn base64_decode(input: &[u8]) -> TransformationResult {
    (do_base64_decode(input, false), true, None)
}

/// Decodes Base64 up to the first invalid byte, ignoring ASCII whitespace and dots.
pub fn base64_decode_ext(input: &[u8]) -> TransformationResult {
    (do_base64_decode(input, true), true, None)
}

/// Base64 values for ASCII bytes. 127 marks an invalid byte.
const BASE64_DEC_MAP: [u8; 128] = [
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 62, 127, 127,
    127, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 127, 127, 127, 64, 127, 127, 127, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 127, 127, 127, 127, 127, 127, 26, 27, 28, 29, 30,
    31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 127, 127, 127, 127, 127,
];

/// Decodes Base64 with the partial decoding behavior used by Coraza.
fn do_base64_decode(input: &[u8], extended: bool) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut count = 0;
    let mut bits = 0_u32;

    for &byte in input {
        if extended && (byte.is_ascii_whitespace() || byte == b'.') {
            continue;
        }
        if matches!(byte, b'\r' | b'\n') {
            continue;
        }
        if byte == b'=' || byte == b' ' || byte > 127 {
            break;
        }

        let value = BASE64_DEC_MAP.get(usize::from(byte)).copied().unwrap_or(127);
        if value == 127 {
            break;
        }

        bits = (bits << 6) | u32::from(value & 0x3F);
        count += 1;
        if count == 4 {
            let decoded = bits.to_be_bytes();
            output.extend_from_slice(decoded.get(1..).unwrap_or_default());
            count = 0;
            bits = 0;
        }
    }

    match count {
        2 => {
            let decoded = (bits << 12).to_be_bytes();
            output.push(decoded.get(1).copied().unwrap_or_default());
        },
        3 => {
            let decoded = (bits << 6).to_be_bytes();
            output.extend_from_slice(decoded.get(1..3).unwrap_or_default());
        },
        _ => {},
    }

    output
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
    use super::{
        base64_decode, base64_decode_ext, base64_encode, hex_decode, hex_encode, length, md5_hash, none, remove_nulls,
        replace_nulls, sha1_hash, url_encode,
    };

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

    #[test]
    fn hashes_return_raw_binary_digests() {
        assert_eq!(hex_encode(&md5_hash(b"hello").0).0, b"5d41402abc4b2a76b9719d911017c592");
        assert_eq!(
            hex_encode(&sha1_hash(b"hello").0).0,
            b"aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        );
        assert_eq!(hex_encode(&md5_hash(b"").0).0, b"d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            hex_encode(&sha1_hash(b"").0).0,
            b"da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert!(md5_hash(b"hello").1);
        assert!(sha1_hash(b"hello").1);
    }

    #[test]
    fn base64_decoding_preserves_partial_and_binary_results() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"VGVzdENhc2U=", b"TestCase"),
            (b"VGVzdABDYXNl", b"Test\x00Case"),
            (b"VGVzdENhc2U", b"TestCase"),
            (b"PA==", b"<"),
            (b"PFRFU1Q+", b"<TEST>"),
            (b"PHNjcmlwd", b"<scrip"),
            (b"PFR FU1Q+", b"<T"),
            (b"P.HNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", b""),
            (b"PHNjcmlwd.D5hbGVydCgxKTwvc2NyaXB0Pg==", b"<scrip"),
            (b"PHNjcmlwdD.5hbGVydCgxKTwvc2NyaXB0Pg==", b"<script"),
            (b"PFRFU1Q-", b"<TEST"),
            (b"FPucA9l+", b"\x14\xfb\x9c\x03\xd9\x7e"),
            (b"FPucA9k=", b"\x14\xfb\x9c\x03\xd9"),
            (b"FPucAw==", b"\x14\xfb\x9c\x03"),
            (b"", b""),
            (b"Zg==", b"f"),
            (b"Zm8=", b"fo"),
            (b"Zm9v", b"foo"),
            (b"Zm9vYg==", b"foob"),
            (b"Zm9vYmE=", b"fooba"),
            (b"Zm9vYmFy", b"foobar"),
            (b"c3VyZS4=", b"sure."),
            (b"c3VyZQ==", b"sure"),
            (b"c3Vy", b"sur"),
            (b"c3U=", b"su"),
            (b"bGVhc3VyZS4=", b"leasure."),
            (b"ZWFzdXJlLg==", b"easure."),
            (b"YXN1cmUu", b"asure."),
            (b"SGVs\nbG8=", b"Hello"),
        ];
        for (input, expected) in cases {
            let (result, changed, error) = base64_decode(input);
            assert_eq!(result, *expected, "input: {input:?}");
            assert!(changed, "input: {input:?}");
            assert_eq!(error, None, "input: {input:?}");
        }
        assert_eq!(base64_decode(b"\xffSGVsbG8=").0, b"");
    }

    #[test]
    fn extended_base64_decoding_ignores_dots_and_ascii_whitespace() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"VGVzdENhc2U=", b"TestCase"),
            (b"VGVzdABDYXNl", b"Test\x00Case"),
            (b"P.HNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", b"<script>alert(1)</script>"),
            (b"PFR FU1Q+", b"<TEST>"),
            (b"PHNjcmlwd.D5hbGVydCgxKTwvc2NyaXB0Pg==", b"<script>alert(1)</script>"),
            (b"PHNjcmlwdD.5hbGVydCgxKTwvc2NyaXB0Pg==", b"<script>alert(1)</script>"),
            (b"SGVs\n bG8=", b"Hello"),
        ];
        for (input, expected) in cases {
            let (result, changed, error) = base64_decode_ext(input);
            assert_eq!(result, *expected, "input: {input:?}");
            assert!(changed, "input: {input:?}");
            assert_eq!(error, None, "input: {input:?}");
        }
    }
}
