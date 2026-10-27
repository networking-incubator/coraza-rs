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
    reason = "custom action tests use fixed rules"
)]

//! End-to-end tests for parser-registered custom actions.

use std::sync::Arc;

use coraza::{
    AllowScope, RulePhase,
    actions::{ActionType, CustomAction, CustomActionFactory, RuleMetadata},
    seclang::Parser,
    transaction::Transaction,
    types::RuleVariable,
    waf::Waf,
};

struct SetValue {
    key: String,
    value: String,
    action_type: ActionType,
}

impl CustomAction for SetValue {
    fn action_type(&self) -> ActionType {
        self.action_type
    }

    fn evaluate(&self, _rule: &RuleMetadata, tx: &mut Transaction) {
        tx.set_tx_variable(&self.key, &self.value);
    }
}

struct ObserveMetadata;

impl CustomAction for ObserveMetadata {
    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }

    fn evaluate(&self, rule: &RuleMetadata, tx: &mut Transaction) {
        tx.set_tx_variable(
            "metadata",
            format!(
                "{}:{}:{}:{}:{}",
                rule.id(),
                rule.phase() == RulePhase::RequestHeaders,
                rule.status(),
                rule.log(),
                rule.audit_log()
            ),
        );
    }
}

struct SkipOne;

impl CustomAction for SkipOne {
    fn action_type(&self) -> ActionType {
        ActionType::Flow
    }

    fn evaluate(&self, _rule: &RuleMetadata, tx: &mut Transaction) {
        tx.set_skip(1);
    }
}

struct ObserveInterruption;

impl CustomAction for ObserveInterruption {
    fn action_type(&self) -> ActionType {
        ActionType::Flow
    }

    fn evaluate(&self, _rule: &RuleMetadata, tx: &mut Transaction) {
        tx.set_tx_variable("observed_interruption", tx.interruption().is_some().to_string());
    }
}

struct Allow(AllowScope);

impl CustomAction for Allow {
    fn action_type(&self) -> ActionType {
        ActionType::Disruptive
    }

    fn evaluate(&self, _rule: &RuleMetadata, tx: &mut Transaction) {
        tx.allow(self.0);
    }
}

struct Interrupt;

impl CustomAction for Interrupt {
    fn action_type(&self) -> ActionType {
        ActionType::Disruptive
    }

    fn evaluate(&self, rule: &RuleMetadata, tx: &mut Transaction) {
        tx.interrupt(rule.id(), "custom", rule.status(), "custom action");
    }
}

fn set_value_factory(action_type: ActionType, value: &'static str) -> CustomActionFactory {
    Arc::new(move |key| {
        Ok(Box::new(SetValue {
            key: key.to_owned(),
            value: value.to_owned(),
            action_type,
        }))
    })
}

fn register_interrupt(parser: &mut Parser) {
    parser
        .register_action("hostdeny", Arc::new(|_| Ok(Box::new(Interrupt))))
        .unwrap();
}

fn matched_transaction(waf: &Waf) -> Transaction {
    let mut tx = waf.new_transaction();
    tx.add_get_argument("q", "hit");
    tx.process_request_headers();
    tx
}

#[test]
fn custom_nondisruptive_action_can_read_rule_metadata() {
    let mut parser = Parser::new();
    parser
        .register_action("observe", Arc::new(|_| Ok(Box::new(ObserveMetadata))))
        .unwrap();
    parser
        .from_string("SecRule ARGS \"@streq hit\" \"id:101,phase:1,status:429,log,observe\"")
        .unwrap();

    let tx = matched_transaction(&parser.compile().unwrap());
    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("metadata")).as_deref(),
        Some("101:true:429:true:true")
    );
}

#[test]
fn custom_flow_action_skips_the_next_rule() {
    let mut parser = Parser::new();
    parser
        .register_action("skipone", Arc::new(|_| Ok(Box::new(SkipOne))))
        .unwrap();
    parser
        .from_string(
            "SecRule ARGS \"@streq hit\" \"id:1,phase:1,skipone\"\n\
             SecRule ARGS \"@streq hit\" \"id:2,phase:1,setvar:TX.skipped=1\"\n\
             SecRule ARGS \"@streq hit\" \"id:3,phase:1,setvar:TX.after=1\"",
        )
        .unwrap();

    let tx = matched_transaction(&parser.compile().unwrap());
    assert_eq!(tx.get_variable(RuleVariable::TX, Some("skipped")), None);
    assert_eq!(tx.get_variable(RuleVariable::TX, Some("after")).as_deref(), Some("1"));
}

#[test]
fn custom_disruptive_action_interrupts_with_rule_metadata() {
    let mut parser = Parser::new();
    register_interrupt(&mut parser);
    parser
        .from_string("SecRule ARGS \"@streq hit\" \"id:7,phase:1,status:429,hostdeny\"")
        .unwrap();

    let tx = matched_transaction(&parser.compile().unwrap());
    let interruption = tx.interruption().unwrap();
    assert_eq!(interruption.rule_id, 7);
    assert_eq!(interruption.action, "custom");
    assert_eq!(interruption.status, 429);
    assert_eq!(interruption.data, "custom action");
}

#[test]
fn the_last_disruptive_action_wins_across_builtin_and_custom_actions() {
    for (actions, expected_action) in [("deny,hostdeny", "custom"), ("hostdeny,deny", "deny")] {
        let mut parser = Parser::new();
        register_interrupt(&mut parser);
        parser
            .from_string(&format!(
                "SecRule ARGS \"@streq hit\" \"id:8,phase:1,status:451,{actions}\""
            ))
            .unwrap();

        let tx = matched_transaction(&parser.compile().unwrap());
        let interruption = tx.interruption().unwrap();
        assert_eq!(interruption.action, expected_action);
        assert_eq!(interruption.status, 451);
    }
}

#[test]
fn transaction_allow_scopes_match_their_seclang_actions() {
    fn run_policy(
        allow_action: &str,
        custom_scope: Option<AllowScope>,
    ) -> (Option<String>, Option<String>, Option<String>) {
        let mut parser = Parser::new();
        let action_name = if let Some(scope) = custom_scope {
            parser
                .register_action("hostallow", Arc::new(move |_| Ok(Box::new(Allow(scope)))))
                .unwrap();
            "hostallow"
        } else {
            allow_action
        };
        parser
            .from_string(&format!(
                "SecRule ARGS \"@streq hit\" \"id:401,phase:1,{action_name}\"\n\
                 SecRule ARGS \"@streq hit\" \"id:402,phase:1,setvar:TX.same_phase=ran\"\n\
                 SecRule ARGS \"@streq hit\" \"id:403,phase:2,setvar:TX.next_phase=ran\"\n\
                 SecRule ARGS \"@streq hit\" \"id:404,phase:3,setvar:TX.response_phase=ran\""
            ))
            .unwrap();

        let mut tx = parser.compile().unwrap().new_transaction();
        tx.add_get_argument("q", "hit");
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.process_response_headers(200, "HTTP/1.1");
        (
            tx.get_variable(RuleVariable::TX, Some("same_phase")),
            tx.get_variable(RuleVariable::TX, Some("next_phase")),
            tx.get_variable(RuleVariable::TX, Some("response_phase")),
        )
    }

    for (scope, action) in [
        (AllowScope::All, "allow"),
        (AllowScope::Phase, "allow:phase"),
        (AllowScope::Request, "allow:request"),
    ] {
        assert_eq!(run_policy(action, None), run_policy(action, Some(scope)));
    }
    assert_eq!(run_policy("allow", None), (None, None, None));
    let mut parser = Parser::new();
    assert!(
        parser
            .from_string("SecRule ARGS \"@streq hit\" \"id:405,phase:1,allow:all\"")
            .is_err(),
        "Go rejects allow:all"
    );
    assert_eq!(
        run_policy("allow:phase", None),
        (None, Some("ran".to_owned()), Some("ran".to_owned()))
    );
    assert_eq!(run_policy("allow:request", None), (None, None, Some("ran".to_owned())));
}

#[test]
fn replacing_disruptive_action_preserves_its_position_before_flow_actions() {
    let mut parser = Parser::new();
    register_interrupt(&mut parser);
    parser
        .register_action("observe", Arc::new(|_| Ok(Box::new(ObserveInterruption))))
        .unwrap();
    parser
        .from_string("SecRule ARGS \"@streq hit\" \"id:81,phase:1,deny,observe,hostdeny\"")
        .unwrap();

    let tx = matched_transaction(&parser.compile().unwrap());
    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("observed_interruption"))
            .as_deref(),
        Some("true")
    );
}

#[test]
fn failed_action_update_is_atomic_with_and_without_skip_failed_directives() {
    for skip_failed in [false, true] {
        let mut parser = Parser::new();
        register_interrupt(&mut parser);
        parser
            .register_action("failsecond", Arc::new(|_| Err("second factory failed".to_owned())))
            .unwrap();
        if skip_failed {
            parser.skip_failed_directives();
        }

        let result = parser.from_string(
            "SecRule ARGS \"@streq hit\" \"id:82,phase:1,setvar:TX.original=kept,deny\"\n\
             SecRuleUpdateActionById 82 \"hostdeny,failsecond\"",
        );
        if skip_failed {
            assert!(result.is_ok());
            assert_eq!(parser.skipped().len(), 1);
            assert!(
                parser
                    .skipped()
                    .first()
                    .is_some_and(|error| error.message.contains("second factory failed"))
            );
        } else {
            assert!(result.unwrap_err().message.contains("second factory failed"));
        }

        let tx = matched_transaction(&parser.compile().unwrap());
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("original")).as_deref(),
            Some("kept")
        );
        assert_eq!(tx.interruption().unwrap().action, "deny");
    }
}

#[test]
fn metadata_action_names_cannot_be_registered_and_default_phase_still_works() {
    let mut parser = Parser::new();
    let error = parser
        .register_action("phase", set_value_factory(ActionType::Nondisruptive, "wrong"))
        .unwrap_err();
    assert!(error.contains("phase"));

    parser
        .from_string(
            "SecDefaultAction \"phase:1,deny,status:451\"\n\
             SecRule ARGS \"@streq hit\" \"id:83,phase:1\"",
        )
        .unwrap();
    let tx = matched_transaction(&parser.compile().unwrap());
    assert_eq!(tx.interruption().unwrap().action, "deny");
    assert_eq!(tx.interruption().unwrap().status, 451);
}

#[test]
fn chain_members_reject_custom_disruptive_actions() {
    let mut parser = Parser::new();
    register_interrupt(&mut parser);
    let error = parser
        .from_string(
            "SecRule ARGS \"@streq hit\" \"id:9,phase:1,pass,chain\"\n\
             SecRule ARGS \"@streq hit\" \"id:10,hostdeny\"",
        )
        .unwrap_err();

    assert_eq!(
        error.message,
        "failed to compile directive \"SecRule\": disruptive actions can only be specified in the chain starter rule (parent id: 9)"
    );
}

#[test]
fn default_disruptive_action_merges_with_custom_rule_actions() {
    let mut parser = Parser::new();
    parser
        .register_action("mark", set_value_factory(ActionType::Nondisruptive, "ran"))
        .unwrap();
    parser
        .from_string(
            "SecDefaultAction \"phase:1,deny,status:451\"\n\
             SecRule ARGS \"@streq hit\" \"id:11,phase:1,mark:default_seen\"",
        )
        .unwrap();
    let tx = matched_transaction(&parser.compile().unwrap());

    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("default_seen")).as_deref(),
        Some("ran")
    );
    let interruption = tx.interruption().unwrap();
    assert_eq!(interruption.action, "deny");
    assert_eq!(interruption.status, 451);

    let mut parser = Parser::new();
    parser
        .register_action("block", set_value_factory(ActionType::Nondisruptive, "ran"))
        .unwrap();
    parser
        .from_string(
            "SecDefaultAction \"phase:1,deny,status:451\"\n\
             SecRule ARGS \"@streq hit\" \"id:18,phase:1,block:custom_block\"",
        )
        .unwrap();
    let tx = matched_transaction(&parser.compile().unwrap());
    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("custom_block")).as_deref(),
        Some("ran")
    );
    assert_eq!(tx.interruption().unwrap().action, "deny");

    let mut parser = Parser::new();
    register_interrupt(&mut parser);
    parser
        .from_string(
            "SecDefaultAction \"phase:1,deny,status:451\"\n\
             SecRule ARGS \"@streq hit\" \"id:12,phase:1,hostdeny\"",
        )
        .unwrap();
    let interruption = matched_transaction(&parser.compile().unwrap())
        .interruption()
        .cloned()
        .unwrap();
    assert_eq!(interruption.action, "custom");
    assert_eq!(interruption.status, 451);

    let mut parser = Parser::new();
    register_interrupt(&mut parser);
    parser
        .from_string(
            "SecDefaultAction \"phase:1,hostdeny,status:451\"\n\
             SecRule ARGS \"@streq hit\" \"id:17,phase:1\"",
        )
        .unwrap();
    let interruption = matched_transaction(&parser.compile().unwrap())
        .interruption()
        .cloned()
        .unwrap();
    assert_eq!(interruption.action, "custom");
    assert_eq!(interruption.status, 451);
}

#[test]
fn custom_registration_is_case_insensitive_and_overrides_builtins() {
    let mut parser = Parser::new();
    parser
        .register_action("DENY", set_value_factory(ActionType::Nondisruptive, "custom"))
        .unwrap();
    parser
        .from_string("SecRule ARGS \"@streq hit\" \"id:13,phase:1,DeNy:overridden\"")
        .unwrap();

    let tx = matched_transaction(&parser.compile().unwrap());
    assert!(tx.interruption().is_none());
    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("overridden")).as_deref(),
        Some("custom")
    );
}

#[test]
fn registration_after_compilation_only_affects_later_rules() {
    let mut parser = Parser::new();
    parser
        .register_action("stamp", set_value_factory(ActionType::Nondisruptive, "old"))
        .unwrap();
    parser
        .from_string("SecRule ARGS \"@streq hit\" \"id:14,phase:1,stamp:first\"")
        .unwrap();
    parser
        .register_action("stamp", set_value_factory(ActionType::Nondisruptive, "new"))
        .unwrap();
    parser
        .from_string("SecRule ARGS \"@streq hit\" \"id:15,phase:1,stamp:second\"")
        .unwrap();

    let tx = matched_transaction(&parser.compile().unwrap());
    assert_eq!(tx.get_variable(RuleVariable::TX, Some("first")).as_deref(), Some("old"));
    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("second")).as_deref(),
        Some("new")
    );

    let mut another_parser = Parser::new();
    assert!(
        another_parser
            .from_string("SecRule ARGS \"@streq hit\" \"id:16,phase:1,stamp\"")
            .is_err()
    );
}

#[test]
fn custom_action_factories_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<Arc<dyn CustomAction>>();
    assert_send_sync::<CustomActionFactory>();
}
