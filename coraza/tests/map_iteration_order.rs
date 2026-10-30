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

//! Regression coverage for insertion-ordered keyless variable selections.
//!
//! A keyless `ARGS_NAMES` selection walks the argument map, so its order decides which
//! match `MATCHED_VAR` (and any capture from it) holds afterwards. That order must not
//! change between transactions or processes.

#![expect(
    clippy::unwrap_used,
    clippy::tests_outside_test_module,
    reason = "integration test binary with a fixed local policy"
)]

use std::sync::{Arc, Mutex};

use coraza::{
    actions::{ActionType, CustomAction, RuleMetadata},
    seclang::Parser,
    transaction::Transaction,
    types::RuleVariable,
};

/// The `MATCHED_VAR` value of every match of the rule it is attached to.
#[derive(Default)]
struct MatchLog(Mutex<Vec<String>>);

struct RecordMatchedVar(Arc<MatchLog>);

impl CustomAction for RecordMatchedVar {
    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }

    fn evaluate(&self, _rule: &RuleMetadata, tx: &mut Transaction) {
        let matched = tx.get_variable(RuleVariable::MatchedVar, None).unwrap_or_default();
        self.0.0.lock().unwrap().push(matched);
    }
}

#[test]
fn keyless_args_names_matches_follow_query_order() {
    let log = Arc::new(MatchLog::default());
    let recorder = Arc::clone(&log);
    let mut parser = Parser::new();
    parser
        .register_action(
            "recordmatch",
            Arc::new(move |_| Ok(Box::new(RecordMatchedVar(Arc::clone(&recorder))))),
        )
        .unwrap();
    parser
        .from_string(
            "SecRuleEngine On\n\
             SecRule ARGS_NAMES \"@rx ^f[01]$\" \
             \"id:1,phase:2,pass,nolog,recordmatch,setvar:tx.last=%{MATCHED_VAR}\"\n\
             SecRule TX:last \"@streq f1\" \"id:2,phase:2,deny,status:403,log\"",
        )
        .unwrap();
    let waf = parser.compile().unwrap();

    for _ in 0..50 {
        log.0.lock().unwrap().clear();
        let mut tx = waf.new_transaction();
        tx.process_uri("/s?f0=a&f1=b", "GET", "HTTP/1.1");
        tx.process_request_headers();
        tx.process_request_body(b"");

        assert_eq!(*log.0.lock().unwrap(), ["f0", "f1"]);
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("last")).as_deref(), Some("f1"));
        assert_eq!(tx.interruption().map(|interruption| interruption.status), Some(403));
    }
}
