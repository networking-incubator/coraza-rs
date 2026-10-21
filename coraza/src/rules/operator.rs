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

//! Operator evaluation and SecLang negation.

use crate::{
    operators::{OperatorEnum, Outputs},
    transaction::Transaction,
};

/// An operator and whether SecLang negates its result.
#[derive(Debug, Clone)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by rule evaluation in a later port slice")
)]
pub(crate) struct RuleOperator {
    /// The selected operator implementation.
    operator: OperatorEnum,
    /// Whether to invert the operator result.
    negated: bool,
}

impl RuleOperator {
    /// Create an operator, optionally negated by a leading `!`.
    pub(crate) fn new(operator: OperatorEnum, negated: bool) -> Self {
        Self { operator, negated }
    }

    /// Evaluate one value, applying SecLang negation after the operator runs.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by rule evaluation in a later port slice")
    )]
    pub(crate) fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        let matched = self.operator.evaluate(tx, input, out);
        if self.negated { !matched } else { matched }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "operator tests use fixed valid parameters")]
mod tests {
    use super::RuleOperator;
    use crate::{
        operators::{OperatorEnum, Outputs},
        transaction::Transaction,
    };

    #[test]
    fn negation_inverts_operator_result() {
        let operator = OperatorEnum::new("streq", "admin").unwrap();
        let operator = RuleOperator::new(operator, true);
        let tx = Transaction::new("test");

        assert!(!operator.evaluate(&tx, b"admin", &mut Outputs::default()));
        assert!(operator.evaluate(&tx, b"user", &mut Outputs::default()));
    }
}
