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

//! Numeric and byte-string comparison operators.

use super::{Macro, MacroError, Operator, Outputs};
use crate::transaction::Transaction;

/// Parse a decimal integer, clamping overflow and using zero for invalid input.
fn parse_int(input: &[u8]) -> i64 {
    let Ok(text) = std::str::from_utf8(input) else {
        return 0;
    };
    let digits = input
        .strip_prefix(b"-")
        .or_else(|| input.strip_prefix(b"+"))
        .unwrap_or(input);
    if digits.is_empty() || digits.iter().any(|byte| !byte.is_ascii_digit()) {
        return 0;
    }

    match text.parse::<i64>() {
        Ok(value) => value,
        Err(error) => match error.kind() {
            std::num::IntErrorKind::PosOverflow => i64::MAX,
            std::num::IntErrorKind::NegOverflow => i64::MIN,
            _ => 0,
        },
    }
}

/// Parse an input integer, using zero when parsing fails.
fn as_int(input: &[u8]) -> i64 {
    parse_int(input)
}

/// Expand and parse an integer parameter, using zero when parsing fails.
fn parameter_int(parameter: &Macro, tx: &Transaction) -> i64 {
    parse_int(parameter.expand(tx).as_bytes())
}

/// Numeric equality. Invalid integers are treated as zero.
#[derive(Debug, Clone)]
pub struct Eq {
    /// The operator's macro-expanded integer parameter.
    macro_param: Macro,
}

impl Operator for Eq {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        as_int(input) == parameter_int(&self.macro_param, tx)
    }
}

/// Create a numeric equality operator.
///
/// # Errors
///
/// Returns an error for malformed variable references.
pub fn eq(parameter: &str) -> Result<Eq, MacroError> {
    Ok(Eq {
        macro_param: Macro::new(parameter)?,
    })
}

/// Numeric greater-than comparison. Invalid integers are treated as zero.
#[derive(Debug, Clone)]
pub struct Gt {
    /// The operator's macro-expanded integer parameter.
    macro_param: Macro,
}

impl Operator for Gt {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        as_int(input) > parameter_int(&self.macro_param, tx)
    }
}

/// Create a numeric greater-than operator.
///
/// # Errors
///
/// Returns an error for malformed variable references.
pub fn gt(parameter: &str) -> Result<Gt, MacroError> {
    Ok(Gt {
        macro_param: Macro::new(parameter)?,
    })
}

/// Numeric greater-than-or-equal comparison. Invalid integers are treated as zero.
#[derive(Debug, Clone)]
pub struct Ge {
    /// The operator's macro-expanded integer parameter.
    macro_param: Macro,
}

impl Operator for Ge {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        as_int(input) >= parameter_int(&self.macro_param, tx)
    }
}

/// Create a numeric greater-than-or-equal operator.
///
/// # Errors
///
/// Returns an error for malformed variable references.
pub fn ge(parameter: &str) -> Result<Ge, MacroError> {
    Ok(Ge {
        macro_param: Macro::new(parameter)?,
    })
}

/// Numeric less-than comparison. Invalid integers are treated as zero.
#[derive(Debug, Clone)]
pub struct Lt {
    /// The operator's macro-expanded integer parameter.
    macro_param: Macro,
}

impl Operator for Lt {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        as_int(input) < parameter_int(&self.macro_param, tx)
    }
}

/// Create a numeric less-than operator.
///
/// # Errors
///
/// Returns an error for malformed variable references.
pub fn lt(parameter: &str) -> Result<Lt, MacroError> {
    Ok(Lt {
        macro_param: Macro::new(parameter)?,
    })
}

/// Numeric less-than-or-equal comparison. Invalid integers are treated as zero.
#[derive(Debug, Clone)]
pub struct Le {
    /// The operator's macro-expanded integer parameter.
    macro_param: Macro,
}

impl Operator for Le {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        as_int(input) <= parameter_int(&self.macro_param, tx)
    }
}

/// Create a numeric less-than-or-equal operator.
///
/// # Errors
///
/// Returns an error for malformed variable references.
pub fn le(parameter: &str) -> Result<Le, MacroError> {
    Ok(Le {
        macro_param: Macro::new(parameter)?,
    })
}

/// Case-sensitive byte equality.
#[derive(Debug, Clone)]
pub struct StrEq {
    /// The operator's macro-expanded byte parameter.
    macro_param: Macro,
}

impl Operator for StrEq {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        input == self.macro_param.expand(tx).as_bytes()
    }
}

/// Create a case-sensitive byte equality operator.
///
/// # Errors
///
/// Returns an error for malformed variable references.
pub fn streq(parameter: &str) -> Result<StrEq, MacroError> {
    Ok(StrEq {
        macro_param: Macro::new(parameter)?,
    })
}

/// Byte substring matching. An empty parameter matches every input.
#[derive(Debug, Clone)]
pub struct Contains {
    /// The operator's macro-expanded byte parameter.
    macro_param: Macro,
}

impl Operator for Contains {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        contains_bytes(input, self.macro_param.expand(tx).as_bytes())
    }
}

/// Create a byte substring operator.
///
/// # Errors
///
/// Returns an error for malformed variable references.
pub fn contains(parameter: &str) -> Result<Contains, MacroError> {
    Ok(Contains {
        macro_param: Macro::new(parameter)?,
    })
}

/// Byte prefix matching.
#[derive(Debug, Clone)]
pub struct BeginsWith {
    /// The operator's macro-expanded byte parameter.
    macro_param: Macro,
}

impl Operator for BeginsWith {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        input.starts_with(self.macro_param.expand(tx).as_bytes())
    }
}

/// Create a byte prefix operator.
///
/// # Errors
///
/// Returns an error for malformed variable references.
pub fn begins_with(parameter: &str) -> Result<BeginsWith, MacroError> {
    Ok(BeginsWith {
        macro_param: Macro::new(parameter)?,
    })
}

/// Byte suffix matching.
#[derive(Debug, Clone)]
pub struct EndsWith {
    /// The operator's macro-expanded byte parameter.
    macro_param: Macro,
}

impl Operator for EndsWith {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        input.ends_with(self.macro_param.expand(tx).as_bytes())
    }
}

/// Create a byte suffix operator.
///
/// # Errors
///
/// Returns an error for malformed variable references.
pub fn ends_with(parameter: &str) -> Result<EndsWith, MacroError> {
    Ok(EndsWith {
        macro_param: Macro::new(parameter)?,
    })
}

/// Whether `needle` occurs in `haystack`, including an empty `needle`.
pub(super) fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|window| window == needle)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "operator tests use fixed valid parameters")]
mod tests {
    use super::{begins_with, contains, ends_with, eq, ge, gt, le, lt, streq};
    use crate::{operators::Operator, transaction::Transaction};

    fn matches(operator: &impl Operator, input: &[u8], tx: &Transaction) -> bool {
        operator.evaluate(tx, input, &mut super::Outputs::default())
    }

    #[test]
    fn integer_operators_match_coraza_numeric_behavior() {
        let tx = Transaction::new("operator-test");
        assert!(matches(&eq("1").unwrap(), b"01", &tx));
        assert!(matches(&eq("invalid").unwrap(), b"also-invalid", &tx));
        assert!(matches(&gt("10").unwrap(), b"11", &tx));
        assert!(matches(&ge("10").unwrap(), b"10", &tx));
        assert!(matches(&lt("10").unwrap(), b"9", &tx));
        assert!(matches(&le("10").unwrap(), b"10", &tx));
        assert!(!matches(&le("10").unwrap(), b"11", &tx));
    }

    #[test]
    fn integer_inputs_clamp_overflow_and_reject_invalid_values() {
        assert_eq!(super::as_int(b"9223372036854775807"), i64::MAX);
        assert_eq!(super::as_int(b"-9223372036854775808"), i64::MIN);
        assert_eq!(super::as_int(b"9223372036854775808"), i64::MAX);
        assert_eq!(super::as_int(b"-9223372036854775809"), i64::MIN);
        assert_eq!(super::as_int(b"999999999999999999999x"), 0);
        assert_eq!(super::as_int(b"\xff"), 0);
    }

    #[test]
    fn macro_expanded_integer_parameters_clamp_overflow() {
        let mut tx = Transaction::new("operator-test");
        tx.set_tx_variable("positive", b"9223372036854775808");
        tx.set_tx_variable("negative", b"-9223372036854775809");

        assert!(matches(&eq("%{TX.positive}").unwrap(), b"9223372036854775807", &tx));
        assert!(matches(&eq("%{TX.negative}").unwrap(), b"-9223372036854775808", &tx));
    }

    #[test]
    fn operators_expand_transaction_variables() {
        let mut tx = Transaction::new("operator-test");
        tx.set_tx_variable("threshold", b"10");
        tx.set_tx_variable("method", b"POST");

        assert!(matches(&gt("%{TX.threshold}").unwrap(), b"11", &tx));
        assert!(matches(&streq("%{TX.method}").unwrap(), b"POST", &tx));
    }

    #[test]
    fn string_operators_preserve_byte_semantics() {
        let tx = Transaction::new("operator-test");
        assert!(matches(&streq("a").unwrap(), b"a", &tx));
        assert!(!matches(&streq("A").unwrap(), b"a", &tx));
        assert!(matches(&contains("\u{00ff}").unwrap(), b"a\xc3\xbfb", &tx));
        assert!(matches(&contains("").unwrap(), b"anything", &tx));
        assert!(matches(&begins_with("a").unwrap(), b"abc", &tx));
        assert!(matches(&ends_with("c").unwrap(), b"abc", &tx));
        assert!(!matches(&begins_with("b").unwrap(), b"abc", &tx));
        assert!(!matches(&ends_with("b").unwrap(), b"abc", &tx));
    }
}
