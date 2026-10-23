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
    operators::{OperatorEnum, OperatorOutcome, Outputs},
    transaction::Transaction,
};

/// An operator and whether SecLang negates its result.
#[derive(Debug, Clone)]
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

    /// Whether the operator matched, applying SecLang negation.
    #[cfg(test)]
    pub(crate) fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        self.evaluate_outcome(tx, input, out) == OperatorOutcome::Matched
    }

    /// Evaluate one value, applying SecLang negation after the operator runs.
    ///
    /// Negation flips [`OperatorOutcome::Matched`] and
    /// [`OperatorOutcome::NotMatched`]. A skipped inspection stays
    /// [`OperatorOutcome::NotInspected`], because a negated operator has no
    /// verdict for the input either.
    pub(crate) fn evaluate_outcome(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> OperatorOutcome {
        match self.operator.evaluate_outcome(tx, input, out) {
            OperatorOutcome::Matched if self.negated => OperatorOutcome::NotMatched,
            OperatorOutcome::NotMatched if self.negated => OperatorOutcome::Matched,
            outcome => outcome,
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "operator tests use fixed valid parameters")]
mod tests {
    use super::RuleOperator;
    use crate::{
        operators::{OperatorEnum, OperatorOutcome, Outputs},
        transaction::Transaction,
    };

    #[test]
    fn negation_inverts_operator_result() {
        let operator = OperatorEnum::new("streq", "admin").unwrap();
        let operator = RuleOperator::new(operator, true);
        let tx = Transaction::new("test");

        assert_eq!(
            operator.evaluate_outcome(&tx, b"admin", &mut Outputs::default()),
            OperatorOutcome::NotMatched
        );
        assert_eq!(
            operator.evaluate_outcome(&tx, b"user", &mut Outputs::default()),
            OperatorOutcome::Matched
        );
    }

    #[test]
    fn negation_keeps_a_skipped_inspection() {
        let operator = OperatorEnum::new("detectSQLi", "").unwrap();
        let operator = RuleOperator::new(operator, true);
        let tx = Transaction::new("test");
        let input = vec![b' '; libperfusion::MAX_INPUT_LEN + 1];

        assert_eq!(
            operator.evaluate_outcome(&tx, &input, &mut Outputs::default()),
            OperatorOutcome::NotInspected
        );
    }
}
