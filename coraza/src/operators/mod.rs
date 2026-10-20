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

//! Operators that match transaction values.
//!
//! This slice includes common comparison operators and `rx`. Rule compilation,
//! actions, and phase evaluation are not included yet.

mod macros;
mod pattern;
mod simple;

pub use macros::{Macro, MacroError};
pub use pattern::{Rx, rx};
pub use simple::{
    BeginsWith, Contains, EndsWith, Eq, Ge, Gt, Le, Lt, StrEq, begins_with, contains, ends_with, eq, ge, gt, le, lt,
    streq,
};

use crate::transaction::Transaction;

/// An operator evaluates one transaction value without changing the transaction.
pub trait Operator {
    /// Whether `input` matches this operator's configured parameter.
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool;
}

/// Values an operator hands back to its rule, such as regex captures.
#[derive(Debug, Default)]
pub struct Outputs {
    /// Whether the rule asked to record captures.
    capturing: bool,
    /// Captured bytes indexed by regex group number.
    captures: Vec<(usize, Vec<u8>)>,
}

impl Outputs {
    /// Create outputs for a rule that may store captures.
    pub fn new(capturing: bool) -> Self {
        Self {
            capturing,
            ..Self::default()
        }
    }

    /// Whether the rule asked for captures.
    pub fn wants_captures(&self) -> bool {
        self.capturing
    }

    /// Add a capture when the rule requested them.
    pub fn capture(&mut self, index: usize, value: &[u8]) {
        if self.capturing {
            self.captures.push((index, value.to_vec()));
        }
    }

    /// Take the captures in the order they were produced.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by rule evaluation in a later port slice")
    )]
    pub(crate) fn take_captures(&mut self) -> std::vec::Drain<'_, (usize, Vec<u8>)> {
        self.captures.drain(..)
    }
}

/// A supported operator selected by its SecLang name.
#[derive(Debug, Clone)]
pub enum OperatorEnum {
    /// Regular expression matching.
    Rx(Rx),
    /// Numeric equality.
    Eq(Eq),
    /// Numeric less-than comparison.
    Lt(Lt),
    /// Numeric less-than-or-equal comparison.
    Le(Le),
    /// Numeric greater-than comparison.
    Gt(Gt),
    /// Numeric greater-than-or-equal comparison.
    Ge(Ge),
    /// Case-sensitive byte equality.
    StrEq(StrEq),
    /// Byte substring matching.
    Contains(Contains),
    /// Byte prefix matching.
    BeginsWith(BeginsWith),
    /// Byte suffix matching.
    EndsWith(EndsWith),
}

impl OperatorEnum {
    /// Create an operator by its case-insensitive SecLang name, without `@`.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown operator or invalid argument.
    pub fn new(name: &str, argument: &str) -> Result<Self, String> {
        match name.to_ascii_lowercase().as_str() {
            "rx" => rx(argument).map(Self::Rx).map_err(|error| error.to_string()),
            "eq" => eq(argument).map(Self::Eq).map_err(|error| error.to_string()),
            "lt" => lt(argument).map(Self::Lt).map_err(|error| error.to_string()),
            "le" => le(argument).map(Self::Le).map_err(|error| error.to_string()),
            "gt" => gt(argument).map(Self::Gt).map_err(|error| error.to_string()),
            "ge" => ge(argument).map(Self::Ge).map_err(|error| error.to_string()),
            "streq" => streq(argument).map(Self::StrEq).map_err(|error| error.to_string()),
            "contains" => contains(argument)
                .map(Self::Contains)
                .map_err(|error| error.to_string()),
            "beginswith" => begins_with(argument)
                .map(Self::BeginsWith)
                .map_err(|error| error.to_string()),
            "endswith" => ends_with(argument)
                .map(Self::EndsWith)
                .map_err(|error| error.to_string()),
            _ => Err(format!("unknown operator: {name}")),
        }
    }

    /// Evaluate the selected operator.
    pub fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        match self {
            Self::Rx(operator) => operator.evaluate(tx, input, out),
            Self::Eq(operator) => operator.evaluate(tx, input, out),
            Self::Lt(operator) => operator.evaluate(tx, input, out),
            Self::Le(operator) => operator.evaluate(tx, input, out),
            Self::Gt(operator) => operator.evaluate(tx, input, out),
            Self::Ge(operator) => operator.evaluate(tx, input, out),
            Self::StrEq(operator) => operator.evaluate(tx, input, out),
            Self::Contains(operator) => operator.evaluate(tx, input, out),
            Self::BeginsWith(operator) => operator.evaluate(tx, input, out),
            Self::EndsWith(operator) => operator.evaluate(tx, input, out),
        }
    }
}

/// Implement conversions from supported operator types to [`OperatorEnum`].
macro_rules! impl_operator_from {
    ($($operator:ty => $variant:ident),+ $(,)?) => {
        $(
            impl From<$operator> for OperatorEnum {
                fn from(operator: $operator) -> Self {
                    Self::$variant(operator)
                }
            }
        )+
    };
}

impl_operator_from! {
    Rx => Rx,
    Eq => Eq,
    Lt => Lt,
    Le => Le,
    Gt => Gt,
    Ge => Ge,
    StrEq => StrEq,
    Contains => Contains,
    BeginsWith => BeginsWith,
    EndsWith => EndsWith,
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "operator tests use fixed valid parameters")]
mod tests {
    use super::{OperatorEnum, Outputs};
    use crate::transaction::Transaction;

    #[test]
    fn operator_names_are_case_insensitive() {
        assert!(matches!(
            OperatorEnum::new("BeginsWith", "a"),
            Ok(OperatorEnum::BeginsWith(_))
        ));
    }

    #[test]
    fn unknown_operator_names_are_rejected() {
        assert_eq!(
            OperatorEnum::new("noSuchOp", "").unwrap_err(),
            "unknown operator: noSuchOp"
        );
    }

    #[test]
    fn enum_dispatch_evaluates_the_operator() {
        let operator = OperatorEnum::new("contains", "needle").unwrap();
        let tx = Transaction::new("operator-test");
        assert!(operator.evaluate(&tx, b"a needle here", &mut Outputs::default()));
        assert!(!operator.evaluate(&tx, b"no match", &mut Outputs::default()));
    }
}
