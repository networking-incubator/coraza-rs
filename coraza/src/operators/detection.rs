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

//! SQL injection and XSS detection using libperfusion, as Coraza does with
//! libinjection-go.

use crate::{
    operators::{Operator, OperatorOutcome, Outputs},
    transaction::Transaction,
};

/// SQL injection detection operator.
///
/// Detects SQL injection attempts using libinjection's `SQLi` detection algorithm.
/// Returns true if SQL injection patterns are detected in the input. When a match
/// is found, the SQL fingerprint (such as `s&sos`) is captured in field 0.
///
/// # Arguments
///
/// None. Operates on the target variable specified in the rule.
///
/// # Returns
///
/// `true` if SQL injection detected, `false` otherwise.
#[derive(Debug, Clone, Copy)]
pub struct DetectSQLi;

impl Operator for DetectSQLi {
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        self.evaluate_outcome(tx, input, out) == OperatorOutcome::Matched
    }

    fn evaluate_outcome(&self, _tx: &Transaction, input: &[u8], out: &mut Outputs) -> OperatorOutcome {
        let Some(fingerprint) = libperfusion::sqli_with_limit(input, input.len()) else {
            return OperatorOutcome::NotMatched;
        };
        out.capture(0, fingerprint.as_bytes());
        OperatorOutcome::Matched
    }
}

/// Creates a new `detectSQLi` operator.
pub fn detect_sqli() -> DetectSQLi {
    DetectSQLi
}

/// XSS detection operator.
///
/// Detects cross-site scripting (XSS) attempts using libinjection's XSS detection
/// algorithm. Returns true if XSS patterns are detected in the input.
///
/// # Arguments
///
/// None. Operates on the target variable specified in the rule.
///
/// # Returns
///
/// `true` if XSS detected, `false` otherwise.
#[derive(Debug, Clone, Copy)]
pub struct DetectXSS;

impl Operator for DetectXSS {
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        self.evaluate_outcome(tx, input, out) == OperatorOutcome::Matched
    }

    fn evaluate_outcome(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> OperatorOutcome {
        if libperfusion::xss_with_limit(input, input.len()) {
            OperatorOutcome::Matched
        } else {
            OperatorOutcome::NotMatched
        }
    }
}

/// Creates a new `detectXSS` operator.
pub fn detect_xss() -> DetectXSS {
    DetectXSS
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "operator tests use fixed valid inputs")]
mod tests {
    use super::{Operator as _, OperatorOutcome, Outputs, detect_sqli, detect_xss};
    use crate::transaction::Transaction;

    /// Return `payload` padded with spaces up to exactly `len` bytes.
    fn padded(payload: &[u8], len: usize) -> Vec<u8> {
        let mut value = payload.to_vec();
        value.resize(len, b' ');
        value
    }

    #[test]
    fn detects_sqli_and_captures_its_fingerprint() {
        let tx = Transaction::new("operator-test");
        let mut out = Outputs::new(true);
        assert!(detect_sqli().evaluate(&tx, b"1' OR '1'='1", &mut out));
        assert!(!out.take_captures().next().unwrap().1.is_empty());
        assert!(!detect_sqli().evaluate(&tx, b"hello", &mut Outputs::default()));
    }

    #[test]
    fn detects_xss_in_html_input() {
        let tx = Transaction::new("operator-test");
        assert!(detect_xss().evaluate(&tx, b"<script>alert(1)</script>", &mut Outputs::default()));
        assert!(!detect_xss().evaluate(&tx, b"hello", &mut Outputs::default()));
    }

    #[test]
    fn sqli_scans_an_input_past_the_wrapper_bound() {
        let tx = Transaction::new("operator-test");
        let input = padded(b"1' OR '1'='1", libperfusion::MAX_INPUT_LEN + 1);

        assert_eq!(
            detect_sqli().evaluate_outcome(&tx, &input, &mut Outputs::default()),
            OperatorOutcome::Matched
        );
    }

    #[test]
    fn xss_scans_an_input_past_the_wrapper_bound() {
        let tx = Transaction::new("operator-test");
        let input = padded(b"<script>alert(1)</script>", libperfusion::MAX_INPUT_LEN + 1);

        assert_eq!(
            detect_xss().evaluate_outcome(&tx, &input, &mut Outputs::default()),
            OperatorOutcome::Matched
        );
    }
}
