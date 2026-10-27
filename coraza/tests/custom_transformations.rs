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

#![expect(clippy::unwrap_used, reason = "custom transformation tests use fixed directives")]
#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]

//! End-to-end tests for parser-registered transformations.

use std::{fs, sync::Arc};

use coraza::{
    seclang::Parser,
    transaction::Transaction,
    transformations::{CustomTransformation, TransformationResult},
};

struct AppendBang;

impl CustomTransformation for AppendBang {
    fn transform(&self, input: &[u8]) -> TransformationResult {
        let mut output = input.to_vec();
        output.push(b'!');
        (output, true, None)
    }
}

struct Fixed(&'static [u8]);

impl CustomTransformation for Fixed {
    fn transform(&self, input: &[u8]) -> TransformationResult {
        (self.0.to_vec(), input != self.0, None)
    }
}

fn matched_ids(transaction: &Transaction) -> Vec<i32> {
    transaction
        .matched_rules()
        .iter()
        .map(coraza::audit_log::MatchedRule::rule_id)
        .collect()
}

fn process_arg(waf: &coraza::Waf, value: &[u8]) -> Vec<i32> {
    let mut transaction = waf.new_transaction();
    transaction.add_get_argument("q", value);
    transaction.process_request_headers();
    matched_ids(&transaction)
}

#[test]
fn custom_transformations_run_from_seclang_in_multimatch_mode() {
    let mut parser = Parser::new();
    parser.register_transformation("AppendBang", Arc::new(AppendBang));
    parser
        .from_string("SecRule ARGS \"@streq original!\" \"id:1,phase:1,t:appendbang,t:APPENDBANG,multiMatch,pass\"")
        .unwrap();

    let waf = parser.compile().unwrap();
    assert_eq!(process_arg(&waf, b"original"), [1]);
}

#[test]
fn custom_transformations_override_builtins_and_registration_is_case_insensitive() {
    let mut parser = Parser::new();
    parser.register_transformation("UPPERCASE", Arc::new(Fixed(b"first")));
    parser.register_transformation("uppercase", Arc::new(Fixed(b"replacement")));
    parser
        .from_string("SecRule ARGS \"@streq replacement\" \"id:2,phase:1,t:UpperCase,pass\"")
        .unwrap();

    let waf = parser.compile().unwrap();
    assert_eq!(process_arg(&waf, b"original"), [2]);
}

#[test]
fn none_clears_the_chain_even_when_a_custom_none_is_registered() {
    let mut parser = Parser::new();
    parser.register_transformation("none", Arc::new(Fixed(b"overridden")));
    parser.register_transformation("appendbang", Arc::new(AppendBang));
    parser
        .from_string(
            r#"SecRule ARGS "@streq ORIGINAL!" "id:7,phase:1,t:lowercase,t:none,t:appendbang,pass"
SecRule ARGS "@streq ORIGINAL" "id:8,phase:1,t:none,pass""#,
        )
        .unwrap();

    let waf = parser.compile().unwrap();
    assert_eq!(process_arg(&waf, b"ORIGINAL"), [7, 8]);
}

#[test]
fn custom_transformation_names_use_unicode_case_folding() {
    let mut parser = Parser::new();
    parser.register_transformation("Åfoo", Arc::new(Fixed(b"unicode")));
    parser
        .from_string("SecRule ARGS \"@streq unicode\" \"id:9,phase:1,t:åFOO,pass\"")
        .unwrap();

    let waf = parser.compile().unwrap();
    assert_eq!(process_arg(&waf, b"input"), [9]);
}

#[test]
fn custom_transformation_resolves_from_sec_action() {
    let mut parser = Parser::new();
    parser.register_transformation("appendbang", Arc::new(AppendBang));
    parser
        .from_string("SecAction \"id:10,phase:1,t:appendbang,pass\"")
        .unwrap();

    assert!(parser.compile().is_ok());
}

#[test]
fn custom_transformation_resolves_from_rule_action_update() {
    let mut parser = Parser::new();
    parser.register_transformation("appendbang", Arc::new(AppendBang));
    parser
        .from_string(
            r#"SecRule ARGS "@streq original!" "id:11,phase:1,pass"
SecRuleUpdateActionById 11 "t:appendbang""#,
        )
        .unwrap();

    let waf = parser.compile().unwrap();
    assert_eq!(process_arg(&waf, b"original"), [11]);
}

#[test]
fn custom_transformation_resolves_from_included_file() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("included.conf"),
        "SecRule ARGS \"@streq original!\" \"id:12,phase:1,t:appendbang,pass\"",
    )
    .unwrap();
    let root = directory.path().join("root.conf");
    fs::write(&root, "Include included.conf").unwrap();

    let mut parser = Parser::new();
    parser.register_transformation("appendbang", Arc::new(AppendBang));
    parser.from_file(root).unwrap();

    let waf = parser.compile().unwrap();
    assert_eq!(process_arg(&waf, b"original"), [12]);
}

#[test]
fn rules_keep_the_transformation_resolved_when_they_were_compiled() {
    let mut parser = Parser::new();
    parser
        .from_string("SecRule ARGS \"@streq original\" \"id:3,phase:1,t:lowercase,pass\"")
        .unwrap();
    parser.register_transformation("LOWERCASE", Arc::new(Fixed(b"registered")));

    let waf = parser.compile().unwrap();
    assert_eq!(process_arg(&waf, b"ORIGINAL"), [3]);
}

#[test]
fn registration_on_another_parser_does_not_rewrite_a_compiled_waf() {
    let mut builtin_parser = Parser::new();
    builtin_parser
        .from_string("SecRule ARGS \"@streq original\" \"id:4,phase:1,t:lowercase,pass\"")
        .unwrap();
    let builtin_waf = builtin_parser.compile().unwrap();

    let mut custom_parser = Parser::new();
    custom_parser.register_transformation("lowercase", Arc::new(Fixed(b"custom")));
    custom_parser
        .from_string("SecRule ARGS \"@streq custom\" \"id:5,phase:1,t:lowercase,pass\"")
        .unwrap();
    let custom_waf = custom_parser.compile().unwrap();

    assert_eq!(process_arg(&builtin_waf, b"ORIGINAL"), [4]);
    assert_eq!(process_arg(&custom_waf, b"ORIGINAL"), [5]);
}

#[test]
fn unknown_transformation_still_fails_rule_compilation() {
    let mut parser = Parser::new();
    let error = parser
        .from_string("SecRule ARGS \"@streq value\" \"id:6,phase:1,t:notRegistered\"")
        .unwrap_err();

    assert!(error.message.contains("unknown transformation: notRegistered"));
}

#[test]
fn custom_transformation_contract_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<AppendBang>();
    assert_send_sync::<Arc<dyn CustomTransformation>>();
}
