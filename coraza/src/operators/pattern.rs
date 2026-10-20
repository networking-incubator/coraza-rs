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

//! Regular expression matching with transaction macro expansion.

use super::{Macro, Operator, Outputs};
use crate::{transaction::Transaction, transformations::text_of, utils::strings::x2c};

/// Regular expression operator with Coraza's multiline and dotall defaults.
#[derive(Debug, Clone)]
pub struct Rx {
    /// Pattern text with parsed transaction-variable references.
    macro_param: Macro,
    /// Compiled pattern when the parameter has no transaction variables.
    cached_regex: Option<CompiledRx>,
}

/// A compiled pattern that matches either Unicode text or raw bytes.
#[derive(Debug, Clone)]
enum CompiledRx {
    /// A Unicode regular expression using lossy input text when needed.
    Text(regex::Regex),
    /// A byte regular expression for patterns that spell invalid UTF-8 bytes.
    Bytes(regex::bytes::Regex),
}

impl CompiledRx {
    /// Compile a pattern, enabling multiline and dotall behavior.
    fn new(pattern: &str) -> Result<Self, regex::Error> {
        if spells_non_utf8_bytes(pattern) {
            let pattern = unbrace_byte_escapes(pattern);
            regex::bytes::RegexBuilder::new(&format!("(?sm){pattern}"))
                .unicode(false)
                .build()
                .map(Self::Bytes)
        } else {
            regex::Regex::new(&format!("(?sm){pattern}")).map(Self::Text)
        }
    }

    /// Check whether the pattern matches the supplied bytes.
    fn is_match(&self, input: &[u8]) -> bool {
        match self {
            Self::Text(regex) => regex.is_match(&text_of(input)),
            Self::Bytes(regex) => regex.is_match(input),
        }
    }

    /// Return the match and all capture groups as bytes.
    fn captures(&self, input: &[u8]) -> Option<Vec<Option<Vec<u8>>>> {
        match self {
            Self::Text(regex) => regex.captures(&text_of(input)).map(|captures| {
                captures
                    .iter()
                    .map(|group| group.map(|group| group.as_str().as_bytes().to_vec()))
                    .collect()
            }),
            Self::Bytes(regex) => regex.captures(input).map(|captures| {
                captures
                    .iter()
                    .map(|group| group.map(|group| group.as_bytes().to_vec()))
                    .collect()
            }),
        }
    }
}

/// Whether escaped bytes in `pattern` form invalid UTF-8.
fn spells_non_utf8_bytes(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut spelled = Vec::with_capacity(bytes.len());
    let mut offset = 0;
    while let Some(rest) = bytes.get(offset..) {
        if rest.is_empty() {
            break;
        }
        if let Some((byte, length)) = byte_escape(rest) {
            spelled.push(byte);
            offset += length;
        } else {
            let Some(byte) = rest.first().copied() else {
                break;
            };
            spelled.push(byte);
            offset += 1;
            if byte == b'\\'
                && let Some(escaped) = rest.get(1).copied()
            {
                spelled.push(escaped);
                offset += 1;
            }
        }
    }
    std::str::from_utf8(&spelled).is_err()
}

/// Convert braced byte escapes to the syntax accepted by the byte regex engine.
fn unbrace_byte_escapes(pattern: &str) -> String {
    let mut result = String::with_capacity(pattern.len());
    let mut rest = pattern;
    while !rest.is_empty() {
        if let Some((byte, length)) = byte_escape(rest.as_bytes()) {
            result.push_str("\\x");
            result.push(hex_digit(byte >> 4));
            result.push(hex_digit(byte & 0x0F));
            let Some(tail) = rest.get(length..) else {
                result.push_str(rest);
                break;
            };
            rest = tail;
            continue;
        }

        let Some(character) = rest.chars().next() else {
            break;
        };
        let escaped_length = if character == '\\' {
            rest.get(1..)
                .and_then(|tail| tail.chars().next())
                .map_or(0, char::len_utf8)
        } else {
            0
        };
        let length = character.len_utf8() + escaped_length;
        let Some(segment) = rest.get(..length) else {
            result.push_str(rest);
            break;
        };
        result.push_str(segment);
        let Some(tail) = rest.get(length..) else {
            break;
        };
        rest = tail;
    }
    result
}

/// Convert one hexadecimal nibble to a lowercase ASCII digit.
fn hex_digit(nibble: u8) -> char {
    if nibble < 10 {
        char::from(b'0' + nibble)
    } else {
        char::from(b'a' + nibble - 10)
    }
}

/// Decode an ASCII `\\xHH` or `\\x{HH}` escape at the start of `pattern`.
fn byte_escape(pattern: &[u8]) -> Option<(u8, usize)> {
    let decode = |digits: &[u8]| digits.iter().all(u8::is_ascii_hexdigit).then(|| x2c(digits))?;
    match pattern {
        [b'\\', b'x', b'{', high, low, b'}', ..] => Some((decode(&[*high, *low])?, 6)),
        [b'\\', b'x', b'{', digit, b'}', ..] => Some((decode(&[b'0', *digit])?, 5)),
        [b'\\', b'x', high, low, ..] => Some((decode(&[*high, *low])?, 4)),
        _ => None,
    }
}

impl Operator for Rx {
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        let expanded;
        let regex = if let Some(regex) = &self.cached_regex {
            regex
        } else {
            let pattern = self.macro_param.expand(tx);
            let Ok(compiled) = CompiledRx::new(&pattern) else {
                return false;
            };
            expanded = compiled;
            &expanded
        };

        if !out.wants_captures() {
            return regex.is_match(input);
        }
        let Some(groups) = regex.captures(input) else {
            return false;
        };
        for (index, group) in groups.iter().take(10).enumerate() {
            out.capture(index, group.as_deref().unwrap_or(&[]));
        }
        true
    }
}

/// Create a regular expression operator.
///
/// Patterns without transaction variables are compiled immediately. Patterns
/// containing variables are compiled when evaluated.
///
/// # Errors
///
/// Returns an error for malformed macros or an invalid static regular expression.
pub fn rx(pattern: &str) -> Result<Rx, Box<dyn std::error::Error>> {
    let macro_param = Macro::new(pattern)?;
    let cached_regex = if pattern.contains("%{") {
        None
    } else {
        Some(CompiledRx::new(pattern)?)
    };
    Ok(Rx {
        macro_param,
        cached_regex,
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "operator tests use fixed valid patterns")]
mod tests {
    use super::{Operator as _, Outputs, rx};
    use crate::transaction::Transaction;

    #[test]
    fn regex_uses_multiline_and_dotall_defaults() {
        let tx = Transaction::new("operator-test");
        let mut out = Outputs::default();
        assert!(rx("^b$").unwrap().evaluate(&tx, b"a\nb\nc", &mut out));
        assert!(rx("hello.*world").unwrap().evaluate(&tx, b"hello\nworld", &mut out));
    }

    #[test]
    fn regex_matches_non_utf8_byte_escapes() {
        let tx = Transaction::new("operator-test");
        let mut out = Outputs::default();
        assert!(rx(r"\xff").unwrap().evaluate(&tx, b"\xff", &mut out));
        assert!(rx(r"\xff.*end").unwrap().evaluate(&tx, b"\xff\nend", &mut out));
        assert!(!rx(r"\xff").unwrap().evaluate(&tx, "\u{00ff}".as_bytes(), &mut out));
        assert!(rx(r"\\xff").unwrap().evaluate(&tx, br"\xff", &mut out));
    }

    #[test]
    fn regex_expands_macros_and_captures_at_most_ten_groups() {
        let mut tx = Transaction::new("operator-test");
        tx.set_tx_variable("pattern", b"(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)");
        let operator = rx("%{TX.pattern}").unwrap();
        let mut out = Outputs::new(true);
        assert!(operator.evaluate(&tx, b"abcdefghij", &mut out));
        let captures: Vec<_> = out.take_captures().collect();
        assert_eq!(captures.len(), 10);
        assert_eq!(captures.first(), Some(&(0, b"abcdefghij".to_vec())));
        assert_eq!(captures.last(), Some(&(9, b"i".to_vec())));
    }

    #[test]
    fn invalid_patterns_are_errors_or_non_matches() {
        assert!(rx("(").is_err());
        assert!(rx("%{TX.pattern}").is_ok());
        let mut tx = Transaction::new("operator-test");
        tx.set_tx_variable("pattern", b"(");
        assert!(
            !rx("%{TX.pattern}")
                .unwrap()
                .evaluate(&tx, b"input", &mut Outputs::default())
        );
    }
}
