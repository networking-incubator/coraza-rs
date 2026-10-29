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

//! Validation and utility operators for encoding, byte ranges, and national IDs.

use crate::{
    operators::{Operator, Outputs},
    transaction::Transaction,
    transformations::{RegexText, text_of},
};

/// Unconditional match operator.
///
/// Forces the rule to always return true, unconditionally matching and firing all associated actions.
/// Useful for rules that should always execute their actions regardless of input, such as setting
/// variables, logging, or performing initialization tasks.
///
/// # Arguments
///
/// None. This operator takes no arguments.
///
/// # Returns
///
/// `true` (always, unconditionally)
#[derive(Debug, Clone, Copy)]
pub struct UnconditionalMatch;

impl Operator for UnconditionalMatch {
    fn evaluate(&self, _tx: &Transaction, _input: &[u8], _out: &mut Outputs) -> bool {
        true
    }
}

/// Creates a new `unconditionalMatch` operator.
pub fn unconditional_match() -> UnconditionalMatch {
    UnconditionalMatch
}

/// No match operator.
///
/// Forces the rule to always return false, effectively disabling rule matching unconditionally.
/// Useful for temporarily disabling rules without removing them, or for rules that only execute
/// actions without needing to match.
///
/// # Arguments
///
/// None. This operator takes no arguments.
///
/// # Returns
///
/// `false` (always, unconditionally)
#[derive(Debug, Clone, Copy)]
pub struct NoMatch;

impl Operator for NoMatch {
    fn evaluate(&self, _tx: &Transaction, _input: &[u8], _out: &mut Outputs) -> bool {
        false
    }
}

/// Creates a new `noMatch` operator.
pub fn no_match() -> NoMatch {
    NoMatch
}

/// Byte range validation operator.
///
/// Validates that the byte values used in input fall into the specified range(s).
/// Returns true (violation) if any byte is found outside the allowed ranges. Useful for
/// detecting binary data, control characters, or restricting character sets.
///
/// # Arguments
///
/// Comma-separated byte values or ranges (e.g., "10, 13, 32-126" for printable ASCII).
/// Ranges are specified as "start-end" and individual bytes as single numbers (0-255).
///
/// # Returns
///
/// `true` if any byte is outside the allowed range (violation detected), `false` if all bytes are valid.
#[derive(Debug, Clone)]
pub struct ValidateByteRange {
    /// Bitmap of valid bytes (256 possible byte values).
    valid_bytes: Box<[bool; 256]>,
    /// The argument was empty, which Go's factory turns into `unconditionalMatch`.
    unconditional: bool,
}

impl ValidateByteRange {
    /// Creates a new `ValidateByteRange` operator from a comma-separated list of bytes/ranges.
    ///
    /// # Arguments
    ///
    /// * `ranges` - Comma-separated list like "10,13,32-126"; an empty list matches every input, as Go's
    ///   `newValidateByteRange` returns `unconditionalMatch` for it.
    ///
    /// # Returns
    ///
    /// `Ok(ValidateByteRange)` if valid, `Err` if invalid byte values or ranges.
    ///
    /// # Errors
    ///
    /// Returns an error if a byte value or range endpoint is outside 0 to 255.
    pub fn new(ranges: &str) -> Result<Self, String> {
        if ranges.is_empty() {
            return Ok(ValidateByteRange {
                valid_bytes: Box::new([false; 256]),
                unconditional: true,
            });
        }

        let mut valid_bytes = [false; 256];

        for range_spec in ranges.split(',') {
            let range_spec = range_spec.trim();
            if range_spec.is_empty() {
                continue;
            }

            if let Some((start_str, end_str)) = range_spec.split_once('-') {
                // Range: "32-126"
                let start = start_str
                    .trim()
                    .parse::<u8>()
                    .map_err(|error| format!("invalid byte value {start_str:?}: {error}"))?;
                let end = end_str
                    .trim()
                    .parse::<u8>()
                    .map_err(|error| format!("invalid byte value {end_str:?}: {error}"))?;
                if start > end {
                    return Err(format!("invalid byte range {range_spec:?}: start exceeds end"));
                }

                for byte_val in start..=end {
                    if let Some(allowed) = valid_bytes.get_mut(usize::from(byte_val)) {
                        *allowed = true;
                    }
                }
            } else {
                // Single byte: "10"
                let byte_val = range_spec
                    .parse::<u8>()
                    .map_err(|error| format!("invalid byte value {range_spec:?}: {error}"))?;
                if let Some(allowed) = valid_bytes.get_mut(usize::from(byte_val)) {
                    *allowed = true;
                }
            }
        }

        Ok(ValidateByteRange {
            valid_bytes: Box::new(valid_bytes),
            unconditional: false,
        })
    }
}

impl Operator for ValidateByteRange {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        if self.unconditional {
            return true;
        }
        if input.is_empty() {
            return false; // Empty input is valid
        }

        // Check each byte and return true if any byte is invalid.
        for &byte in input {
            if self.valid_bytes.get(usize::from(byte)).is_none_or(|allowed| !allowed) {
                return true; // Violation detected
            }
        }

        false // All bytes are valid
    }
}

/// Creates a new `validateByteRange` operator.
///
/// # Errors
///
/// Returns an error if a byte value or range endpoint is outside 0 to 255.
pub fn validate_byte_range(ranges: &str) -> Result<ValidateByteRange, String> {
    ValidateByteRange::new(ranges)
}

/// URL encoding validation operator.
///
/// Validates URL-encoded characters in the input string. Checks that percent-encoding
/// follows proper format (%XX where X is a hexadecimal digit). Returns true if invalid
/// encoding is detected (non-hex characters or incomplete sequences).
///
/// # Arguments
///
/// None. Operates on the target variable specified in the rule.
///
/// # Returns
///
/// `true` if invalid URL encoding is found (violation), `false` if encoding is valid.
#[derive(Debug, Clone, Copy)]
pub struct ValidateUrlEncoding;

impl Operator for ValidateUrlEncoding {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        if input.is_empty() {
            return false; // Empty input is valid
        }

        let mut i = 0;

        while let Some(&byte) = input.get(i) {
            if byte == b'%' {
                let end = i.saturating_add(3);
                let Some([_, high, low]) = input.get(i..end) else {
                    return true;
                };
                if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
                    return true; // Non-hexadecimal characters (violation)
                }

                i = end; // Skip the %XX sequence
            } else {
                i += 1;
            }
        }

        false // All percent encodings are valid
    }
}

/// Creates a new `validateUrlEncoding` operator.
pub fn validate_url_encoding() -> ValidateUrlEncoding {
    ValidateUrlEncoding
}

/// UTF-8 encoding validation operator.
///
/// Checks whether the input is a valid UTF-8 encoded string. Detects encoding issues,
/// malformed sequences, and overlong encodings. Useful for preventing UTF-8 validation
/// attacks and ensuring proper character encoding.
///
/// # Arguments
///
/// None. Operates on the target variable specified in the rule.
///
/// # Returns
///
/// `true` if invalid UTF-8 encoding is found (violation), `false` if encoding is valid.
#[derive(Debug, Clone, Copy)]
pub struct ValidateUtf8Encoding;

impl Operator for ValidateUtf8Encoding {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        // As in Go Coraza, a match is a value that isn't UTF-8
        std::str::from_utf8(input).is_err()
    }
}

/// Creates a new `validateUtf8Encoding` operator.
pub fn validate_utf8_encoding() -> ValidateUtf8Encoding {
    ValidateUtf8Encoding
}

/// `@validateNid KIND REGEX`: finds national ids with REGEX and checks each, as Go
/// Coraza does: `cl` for Chilean RUTs (their check digit), `us` for US social security
/// numbers (their area, group and serial, and not all the same or consecutive digits).
///
/// Matches if one of the first 10 found is valid; each valid one is captured, at the
/// index it was found at.
#[derive(Debug, Clone)]
pub struct ValidateNid {
    /// National ID format being checked.
    kind: NidKind,
    /// Pattern used to find candidate IDs in the input.
    regex: regex::Regex,
}

/// National ID formats supported by `@validateNid`.
#[derive(Debug, Clone, Copy)]
enum NidKind {
    /// Chile
    Cl,
    /// United States
    Us,
}

impl Operator for ValidateNid {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        let text = RegexText::new(input);
        let mut valid = false;
        for (index, found) in self.regex.find_iter(text.as_str()).take(10).enumerate() {
            let range = text.original_range(found.start(), found.end());
            let original = input.get(range).unwrap_or_default();
            let nid = text_of(original);
            let checks = match self.kind {
                NidKind::Cl => is_rut(&nid),
                NidKind::Us => is_ssn(&nid),
            };
            if checks {
                valid = true;
                out.capture(index, original);
            }
        }
        valid
    }
}

/// Creates a `@validateNid` operator from `KIND REGEX`.
///
/// # Errors
///
/// If KIND is neither `cl` nor `us`, or REGEX isn't a valid regular expression.
pub fn validate_nid(argument: &str) -> Result<ValidateNid, String> {
    let invalid = || format!("invalid @validateNid argument: {argument:?}");
    let (kind, pattern) = argument.split_once(' ').ok_or_else(invalid)?;
    let kind = match kind {
        "cl" => NidKind::Cl,
        "us" => NidKind::Us,
        _ => return Err(invalid()),
    };
    let regex =
        regex::Regex::new(pattern).map_err(|error| format!("invalid @validateNid argument {argument:?}: {error}"))?;
    Ok(ValidateNid { kind, regex })
}

/// Whether `nid` is a Chilean RUT whose last character is its check digit.
fn is_rut(nid: &str) -> bool {
    if nid.len() < 8 {
        return false;
    }
    let nid: String = nid
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == 'k')
        .collect();
    let Some(check) = nid.chars().last() else {
        return false;
    };
    let Some(mut rut) = nid.strip_suffix(check).and_then(|digits| digits.parse::<u64>().ok()) else {
        return false;
    };
    let mut sum = 0_u32;
    let mut factor = 2_u32;
    while rut != 0 {
        sum += u32::try_from(rut % 10).unwrap_or_default() * factor;
        factor = if factor == 7 { 2 } else { factor + 1 };
        rut /= 10;
    }
    let expected = match sum % 11 {
        0 => '0',
        1 => 'k',
        remainder => char::from_digit(11 - remainder, 10).unwrap_or('?'),
    };
    expected == check
}

/// Whether `nid` is a plausible US social security number.
fn is_ssn(nid: &str) -> bool {
    let digits: Vec<u32> = nid.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 9 {
        return false;
    }
    let number = |range: std::ops::Range<usize>| {
        digits
            .get(range)
            .unwrap_or_default()
            .iter()
            .fold(0_u32, |number, digit| number * 10 + *digit)
    };
    let (area, group, serial) = (number(0..3), number(3..5), number(5..9));
    if area == 0 || group == 0 || serial == 0 || area >= 740 || area == 666 {
        return false;
    }
    let all_equal = digits.windows(2).all(|pair| pair.first() == pair.get(1));
    let consecutive = digits.windows(2).all(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(first, second)| *second == first.saturating_add(1))
    });
    !all_equal && !consecutive
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "operator tests use fixed valid parameters")]
mod tests {
    use super::{
        Operator as _, Outputs, no_match, unconditional_match, validate_byte_range, validate_nid,
        validate_url_encoding, validate_utf8_encoding,
    };
    use crate::transaction::Transaction;

    #[test]
    fn unconditional_and_no_match_operators() {
        let tx = Transaction::new("operator-test");
        assert!(unconditional_match().evaluate(&tx, b"", &mut Outputs::default()));
        assert!(!no_match().evaluate(&tx, b"value", &mut Outputs::default()));
    }

    #[test]
    fn validates_byte_ranges_and_url_encoding() {
        let tx = Transaction::new("operator-test");
        let bytes = validate_byte_range("32-126").unwrap();
        assert!(!bytes.evaluate(&tx, b"printable", &mut Outputs::default()));
        assert!(bytes.evaluate(&tx, b"bad\x00byte", &mut Outputs::default()));
        assert_eq!(
            validate_byte_range("126-32").err().as_deref(),
            Some("invalid byte range \"126-32\": start exceeds end")
        );

        let url = validate_url_encoding();
        assert!(!url.evaluate(&tx, b"/path%20name", &mut Outputs::default()));
        assert!(url.evaluate(&tx, b"/path%2G", &mut Outputs::default()));

        // Go's factory substitutes unconditionalMatch for an empty argument.
        let empty = validate_byte_range("").unwrap();
        assert!(empty.evaluate(&tx, b"TestCase", &mut Outputs::default()));
        assert!(empty.evaluate(&tx, b"", &mut Outputs::default()));
    }

    #[test]
    fn validates_utf8_and_national_ids() {
        let tx = Transaction::new("operator-test");
        let utf8 = validate_utf8_encoding();
        assert!(!utf8.evaluate(&tx, b"valid", &mut Outputs::default()));
        assert!(utf8.evaluate(&tx, b"\xff", &mut Outputs::default()));

        let rut = validate_nid("cl [0-9.]{1,12}-?[0-9kK]").unwrap();
        for valid in [
            b"11.111.111-1".as_slice(),
            b"16100407-3",
            b"8.492.655-8",
            b"84926558",
            b"111111111",
            b"5348281-3",
            b"10727393-k",
            b"10727393-K",
        ] {
            assert!(rut.evaluate(&tx, valid, &mut Outputs::default()));
        }
        for invalid in [
            b"11.111.111-k".as_slice(),
            b"16100407-2",
            b"8.492.655-7",
            b"84926557",
            b"111111112",
            b"5348281-4",
        ] {
            assert!(!rut.evaluate(&tx, invalid, &mut Outputs::default()));
        }

        let ssn = validate_nid("us [0-9]{3}-?[0-9]{2}-?[0-9]{4}").unwrap();
        assert!(ssn.evaluate(&tx, b"078-05-1120", &mut Outputs::default()));
        assert!(!ssn.evaluate(&tx, b"000-12-3456", &mut Outputs::default()));
        assert!(!ssn.evaluate(&tx, b"123-45-6789", &mut Outputs::default()));
        assert!(validate_nid("xx [0-9]+").is_err());
    }
}
