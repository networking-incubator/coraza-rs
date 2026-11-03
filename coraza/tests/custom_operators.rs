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

#![expect(
    clippy::unwrap_used,
    clippy::tests_outside_test_module,
    reason = "custom operator tests use fixed rules"
)]

//! End-to-end tests for parser-registered custom operators.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use coraza::{
    operators::{Operator, OperatorOutcome, Outputs},
    seclang::Parser,
    transaction::Transaction,
};

struct Uninspected(Arc<AtomicUsize>);

impl Operator for Uninspected {
    fn evaluate(&self, _tx: &Transaction, _input: &[u8], _out: &mut Outputs) -> bool {
        false
    }

    fn evaluate_outcome(&self, _tx: &Transaction, _input: &[u8], _out: &mut Outputs) -> OperatorOutcome {
        self.0.fetch_add(1, Ordering::Relaxed);
        OperatorOutcome::NotInspected
    }
}

#[test]
fn custom_operator_without_a_verdict_is_a_miss_even_when_negated() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut parser = Parser::new();
    parser.register_operator("uninspected", {
        let calls = Arc::clone(&calls);
        Arc::new(move |_| Ok(Box::new(Uninspected(Arc::clone(&calls)))))
    });
    parser
        .from_string(
            "SecRule ARGS:q \"@uninspected\" \"id:1,phase:1,pass\"\n\
             SecRule ARGS:q \"!@uninspected\" \"id:2,phase:1,pass\"\n\
             SecRule ARGS:q \"@streq value\" \"id:3,phase:1,pass\"",
        )
        .unwrap();
    let waf = parser.compile().unwrap();
    let mut tx = waf.new_transaction_with_id("uninspected-custom-operator");
    tx.add_get_argument("q", "value");

    assert!(tx.process_request_headers().is_none());
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(tx.matched_rules().len(), 1);
    assert_eq!(tx.matched_rules().first().map(|matched| matched.rule.id()), Some(3));
}
