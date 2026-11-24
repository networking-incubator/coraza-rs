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

//! Runtime expansion of `%{VARIABLE.key}` operator parameters.

use std::{borrow::Cow, fmt};

use crate::{collection::allocation_bytes, transaction::Transaction, types::RuleVariable};

/// A parsed parameter that can read values from a transaction at evaluation time.
#[derive(Debug, Clone)]
pub struct Macro {
    /// Original parameter text, used by callers for diagnostics.
    original: String,
    /// Literal and variable-reference segments in evaluation order.
    tokens: Vec<MacroToken>,
}

/// One literal segment or parsed transaction-variable reference.
#[derive(Debug, Clone, PartialEq)]
struct MacroToken {
    /// Literal text or the original variable expression body.
    text: String,
    /// Variable to read, or `None` for literal text.
    variable: Option<RuleVariable>,
    /// Optional collection key for the variable lookup.
    key: Option<String>,
}

/// An invalid macro parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroError {
    /// Human-readable parse error.
    message: String,
}

impl MacroError {
    /// Create a macro parse error.
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for MacroError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "macro error: {}", self.message)
    }
}

impl std::error::Error for MacroError {}

impl Macro {
    /// Create an empty macro parameter.
    pub fn empty() -> Self {
        Self {
            original: String::new(),
            tokens: Vec::new(),
        }
    }

    /// Parse literal text and `%{VARIABLE.key}` references.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed references or unknown variables.
    pub fn new(input: &str) -> Result<Self, MacroError> {
        let tokens = if input.is_empty() {
            Vec::new()
        } else {
            Self::compile(input)?
        };
        Ok(Self {
            original: input.to_owned(),
            tokens,
        })
    }

    /// Expand references from `tx`. An unset variable expands to an empty string.
    pub fn expand(&self, tx: &Transaction) -> String {
        self.expand_cow(tx).into_owned()
    }

    /// Expand references, borrowing the original text when the parameter is constant.
    pub(crate) fn expand_cow(&self, tx: &Transaction) -> Cow<'_, str> {
        if !self.tokens.iter().any(|token| token.variable.is_some()) {
            return Cow::Borrowed(&self.original);
        }
        let mut result = String::with_capacity(self.original.len());
        for token in &self.tokens {
            // A value is borrowed from the transaction as it is appended, not copied before.
            let text = match token.variable {
                Some(variable) => tx.get_variable_cow(variable, token.key.as_deref()).unwrap_or_default(),
                None => Cow::Borrowed(token.text.as_str()),
            };
            result.push_str(&text);
        }
        Cow::Owned(result)
    }

    /// [`Macro::expand_cow`] cut to `max` bytes at a character boundary: a variable that holds a megabyte makes a text
    /// of `max` bytes, not one of a megabyte that is cut afterwards. A value that is not UTF-8 is converted only as
    /// far as the cut (three source bytes past it at most); its temporary text can be up to three times that prefix,
    /// then is cut and freed.
    pub(crate) fn expand_capped(&self, tx: &Transaction, max: usize) -> Cow<'_, str> {
        if !self.tokens.iter().any(|token| token.variable.is_some()) {
            return Cow::Borrowed(
                self.original
                    .get(..self.original.floor_char_boundary(max))
                    .unwrap_or_default(),
            );
        }
        let mut result = String::with_capacity(self.original.len().min(max));
        for token in &self.tokens {
            let room = max.saturating_sub(result.len());
            let expanded = match token.variable {
                Some(variable) => tx
                    .get_variable_cow_capped(variable, token.key.as_deref(), room)
                    .unwrap_or_default(),
                None => Cow::Borrowed(token.text.as_str()),
            };
            if expanded.len() > room {
                result.push_str(expanded.get(..expanded.floor_char_boundary(room)).unwrap_or_default());
                break;
            }
            result.push_str(&expanded);
        }
        Cow::Owned(result)
    }

    /// Expand an operator parameter, borrowing an exact single-variable value where possible.
    pub(crate) fn expand_for_operator<'a>(&'a self, tx: &'a Transaction) -> Cow<'a, str> {
        if let [
            MacroToken {
                variable: Some(variable),
                key,
                ..
            },
        ] = self.tokens.as_slice()
        {
            return tx
                .get_variable_cow(*variable, key.as_deref())
                .unwrap_or(Cow::Borrowed(""));
        }
        self.expand_cow(tx)
    }

    /// Return the unexpanded parameter.
    pub fn as_str(&self) -> &str {
        &self.original
    }

    /// Bytes a copy of this parameter allocates: its text, its list of tokens, and each token's text and key.
    pub(crate) fn allocated_bytes(&self) -> usize {
        self.tokens.iter().fold(
            allocation_bytes(self.original.capacity()).saturating_add(allocation_bytes(
                self.tokens.capacity().saturating_mul(size_of::<MacroToken>()),
            )),
            |total, token| {
                total
                    .saturating_add(allocation_bytes(token.text.capacity()))
                    .saturating_add(token.key.as_ref().map_or(0, |key| allocation_bytes(key.capacity())))
            },
        )
    }

    /// Split the parameter into literal and variable-reference tokens.
    fn compile(input: &str) -> Result<Vec<MacroToken>, MacroError> {
        let mut tokens = Vec::new();
        let mut cursor = 0;

        while let Some(relative_start) = input.get(cursor..).and_then(|remaining| remaining.find("%{")) {
            let start = cursor + relative_start;
            if start > cursor {
                let Some(text) = input.get(cursor..start) else {
                    return Err(MacroError::new("malformed variable parameter"));
                };
                tokens.push(MacroToken {
                    text: text.to_owned(),
                    variable: None,
                    key: None,
                });
            }

            let body_start = start + 2;
            let Some(relative_end) = input.get(body_start..).and_then(|rest| rest.find('}')) else {
                return Err(MacroError::new("malformed variable: no closing braces"));
            };
            let end = body_start + relative_end;
            let Some(name) = input.get(body_start..end) else {
                return Err(MacroError::new("malformed variable parameter"));
            };

            if name.is_empty() {
                return Err(MacroError::new("empty variable name"));
            }
            if let Some(invalid_offset) = name.bytes().position(|byte| !Self::is_valid_macro_char(byte)) {
                let prefix = name.get(..invalid_offset).unwrap_or_default();
                return Err(MacroError::new(format!(
                    "malformed variable starting with \"%{{{prefix}\""
                )));
            }
            if name.ends_with('.') {
                return Err(MacroError::new("empty variable key"));
            }

            let (variable_name, key) = match name.split_once('.') {
                Some((variable_name, key)) => (variable_name, Some(key.to_ascii_lowercase())),
                None => (name, None),
            };
            let variable = variable_name
                .parse::<RuleVariable>()
                .map_err(|_parse_error| MacroError::new(format!("unknown variable {variable_name:?}")))?;

            tokens.push(MacroToken {
                text: name.to_owned(),
                variable: Some(variable),
                key,
            });
            cursor = end + 1;
        }

        if cursor < input.len() {
            let Some(text) = input.get(cursor..) else {
                return Err(MacroError::new("malformed variable parameter"));
            };
            tokens.push(MacroToken {
                text: text.to_owned(),
                variable: None,
                key: None,
            });
        }

        Ok(tokens)
    }

    /// Whether `byte` is permitted in a macro variable name or key.
    fn is_valid_macro_char(byte: u8) -> bool {
        matches!(byte, b'[' | b']' | b'.' | b'_' | b'-' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "macro tests use fixed valid references")]
mod tests {
    use std::borrow::Cow;

    use super::Macro;
    use crate::transaction::Transaction;

    #[test]
    fn empty_and_literal_parameters_are_preserved() {
        let mut tx = Transaction::new("macro-test");
        tx.set_tx_variable("id", b"42");
        let empty = Macro::new("").unwrap();
        let literal = Macro::new("caf\u{00e9} %").unwrap();
        assert!(matches!(empty.expand_cow(&tx), Cow::Borrowed("")));
        assert!(matches!(literal.expand_cow(&tx), Cow::Borrowed(_)));
        assert_eq!(empty.expand(&tx), "");
        assert_eq!(literal.expand(&tx), "caf\u{00e9} %");
        assert_eq!(
            Macro::new("caf\u{00e9} %{TX.id}").unwrap().expand(&tx),
            "caf\u{00e9} 42"
        );
    }

    #[test]
    fn expands_single_and_multiple_variables() {
        let mut tx = Transaction::new("macro-test");
        tx.set_tx_variable("score", b"42");
        tx.set_request_method(b"POST");

        assert_eq!(Macro::new("%{TX.SCORE}").unwrap().expand(&tx), "42");
        assert_eq!(
            Macro::new("before%{TX.score}after").unwrap().expand_for_operator(&tx),
            "before42after"
        );
        assert_eq!(
            Macro::new("method=%{REQUEST_METHOD} score=%{TX.score}")
                .unwrap()
                .expand(&tx),
            "method=POST score=42"
        );
    }

    #[test]
    fn operator_expansion_borrows_a_single_valid_variable_value() {
        let mut tx = Transaction::new("macro-test");
        tx.set_tx_variable("needle", "a long request-backed value");
        let parameter = Macro::new("%{TX.needle}").unwrap();

        assert!(matches!(
            parameter.expand_for_operator(&tx),
            Cow::Borrowed("a long request-backed value")
        ));
    }

    #[test]
    fn operator_expansion_keeps_lossy_text_for_invalid_utf8() {
        let mut tx = Transaction::new("macro-test");
        tx.set_tx_variable("needle", [0xFF]);
        let parameter = Macro::new("%{TX.needle}").unwrap();

        assert!(matches!(
            parameter.expand_for_operator(&tx),
            Cow::Owned(text) if text == "\u{fffd}"
        ));
    }

    /// The cut of a value that is not UTF-8 is the cut of its whole text, in whichever token of the parameter it falls.
    #[test]
    fn a_capped_expansion_is_the_whole_expansion_cut_at_a_character_boundary() {
        let values: [&[u8]; 6] = [
            b"",
            b"plain",
            b"caf\xC3\xA9",
            b"a\xFFb",
            &[0xFF; 9],
            b"\xE2\x82\xAC\xE2\x82",
        ];
        for value in values {
            let mut tx = Transaction::new("macro-test");
            tx.set_tx_variable("v", value);
            for text in [
                "literal",
                "%{TX.v}",
                "x %{TX.v}",
                "%{TX.v} y %{TX.v}",
                "[%{TX.v}%{TX.v}]%{TX.missing}",
            ] {
                let parameter = Macro::new(text).unwrap();
                let whole = parameter.expand(&tx);
                for max in 0..=whole.len() + 2 {
                    let kept = whole.get(..whole.floor_char_boundary(max)).unwrap_or_default();
                    assert_eq!(
                        parameter.expand_capped(&tx, max),
                        kept,
                        "{text:?} of {value:02x?} cut at {max}"
                    );
                }
            }
        }
    }

    #[test]
    fn unset_variables_expand_to_empty_text() {
        let tx = Transaction::new("macro-test");
        assert_eq!(Macro::new("%{TX.missing}").unwrap().expand(&tx), "");
        assert_eq!(
            Macro::new("before%{TX.missing}after").unwrap().expand(&tx),
            "beforeafter"
        );
    }

    #[test]
    fn rejects_malformed_or_unknown_references() {
        assert!(Macro::new("%{}").is_err());
        assert!(Macro::new("%{TX.}").is_err());
        assert!(Macro::new("%{TX.value").is_err());
        assert!(Macro::new("%{not_a_variable.key}").is_err());
        assert!(Macro::new("%{TX.\u{00e9}}").is_err());
    }
}
