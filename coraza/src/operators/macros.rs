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

use std::fmt;

use crate::{transaction::Transaction, types::RuleVariable};

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

    /// Expand references from `tx`. An unset variable keeps its original name text.
    pub fn expand(&self, tx: &Transaction) -> String {
        let mut result = String::with_capacity(self.original.len());
        for token in &self.tokens {
            match token.variable {
                Some(variable) => result.push_str(
                    &tx.get_variable(variable, token.key.as_deref())
                        .unwrap_or_else(|| token.text.clone()),
                ),
                None => result.push_str(&token.text),
            }
        }
        result
    }

    /// Return the unexpanded parameter.
    pub fn as_str(&self) -> &str {
        &self.original
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
    use super::Macro;
    use crate::transaction::Transaction;

    #[test]
    fn empty_and_literal_parameters_are_preserved() {
        let mut tx = Transaction::new("macro-test");
        tx.set_tx_variable("id", b"42");
        assert_eq!(Macro::new("").unwrap().expand(&tx), "");
        assert_eq!(Macro::new("caf\u{00e9} %").unwrap().expand(&tx), "caf\u{00e9} %");
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
            Macro::new("method=%{REQUEST_METHOD} score=%{TX.score}")
                .unwrap()
                .expand(&tx),
            "method=POST score=42"
        );
    }

    #[test]
    fn unset_variables_keep_the_original_name_text() {
        let tx = Transaction::new("macro-test");
        assert_eq!(Macro::new("%{TX.missing}").unwrap().expand(&tx), "TX.missing");
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
