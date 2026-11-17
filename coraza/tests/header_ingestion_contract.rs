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
    clippy::tests_outside_test_module,
    clippy::panic,
    clippy::unwrap_used,
    reason = "The connector contract test uses fixed rules and headers."
)]
//! Core-side contract for HTTP headers forwarded by connectors.

use coraza::{RuleVariable, seclang::Parser};

const CONNECTOR_HEADERS: [(&str, &[u8]); 8] = [
    ("Referer", b"https://example.test/path with spaces"),
    ("X-Tab", b"before\tafter"),
    ("x-MiXeD", b"Mixed Case"),
    ("X-Empty", b""),
    ("X-Duplicate", b"first"),
    ("x-dUPLICATE", b"second\t value"),
    ("X-Raw-Bytes", b"\x80\xff raw"),
    ("X-Padded", b"  padded  "),
];

/// Issue #126 contract: connectors forwarding headers must preserve spaces,
/// tabs, original name casing, empty values, duplicates, and raw value bytes when
/// calling `Transaction::add_request_header`; these properties feed
/// `REQUEST_HEADERS` and `REQUEST_HEADERS_NAMES` unchanged.
#[test]
fn request_header_ingestion_preserves_connector_supplied_names_and_values() {
    let mut parser = Parser::new();
    parser
        .from_string(
            "SecRule REQUEST_HEADERS \"@rx ^.*$\" \"id:126,phase:1,pass\"\n\
             SecRule REQUEST_HEADERS_NAMES \"@rx ^.*$\" \"id:127,phase:1,pass\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("issue-126-header-contract");

    for (name, value) in CONNECTOR_HEADERS {
        tx.add_request_header(name, value);
    }

    assert!(tx.process_request_headers().is_none());
    assert_eq!(
        tx.matched_rules()
            .iter()
            .map(coraza::audit_log::MatchedRule::rule_id)
            .collect::<Vec<_>>(),
        [126, 127]
    );

    let request_headers = tx.matched_rules().iter().find(|rule| rule.rule_id() == 126).unwrap();
    assert_eq!(
        request_headers
            .matches
            .iter()
            .map(|matched| (matched.key.as_str(), matched.value.clone()))
            .collect::<Vec<_>>(),
        CONNECTOR_HEADERS
            .iter()
            .map(|(name, value)| (*name, value.to_vec()))
            .collect::<Vec<_>>()
    );

    let request_header_names = tx.matched_rules().iter().find(|rule| rule.rule_id() == 127).unwrap();
    assert_eq!(
        request_header_names
            .matches
            .iter()
            .map(|matched| (matched.key.as_str(), matched.value.clone()))
            .collect::<Vec<_>>(),
        CONNECTOR_HEADERS
            .iter()
            .map(|(name, _)| (*name, name.as_bytes().to_vec()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        tx.get_variable(RuleVariable::RequestHeaders, Some("x-duplicate"))
            .as_deref(),
        Some("first")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::RequestHeadersNames, Some("x-mixed"))
            .as_deref(),
        Some("x-MiXeD")
    );
    let duplicates = match tx.collection(RuleVariable::RequestHeaders).unwrap() {
        coraza::transaction::VariableCollection::Map(headers) => headers.values("X-dUpLiCaTe").collect::<Vec<_>>(),
        _ => panic!("REQUEST_HEADERS must expose a map collection"),
    };
    assert_eq!(duplicates, [b"first".as_slice(), b"second\t value"]);
}

/// The response side of the same contract: `add_response_header` must preserve
/// connector-supplied names and values into `RESPONSE_HEADERS` and
/// `RESPONSE_HEADERS_NAMES` exactly as the request side does.
#[test]
fn response_header_ingestion_preserves_connector_supplied_names_and_values() {
    let mut parser = Parser::new();
    parser
        .from_string(
            "SecRule RESPONSE_HEADERS \"@rx ^.*$\" \"id:128,phase:3,pass\"\n\
             SecRule RESPONSE_HEADERS_NAMES \"@rx ^.*$\" \"id:129,phase:3,pass\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("issue-126-response-header-contract");

    for (name, value) in CONNECTOR_HEADERS {
        tx.add_response_header(name, value);
    }

    assert!(tx.process_response_headers(200, "HTTP/1.1").is_none());
    assert_eq!(
        tx.matched_rules()
            .iter()
            .map(coraza::audit_log::MatchedRule::rule_id)
            .collect::<Vec<_>>(),
        [128, 129]
    );

    let response_headers = tx.matched_rules().iter().find(|rule| rule.rule_id() == 128).unwrap();
    assert_eq!(
        response_headers
            .matches
            .iter()
            .map(|matched| (matched.key.as_str(), matched.value.clone()))
            .collect::<Vec<_>>(),
        CONNECTOR_HEADERS
            .iter()
            .map(|(name, value)| (*name, value.to_vec()))
            .collect::<Vec<_>>()
    );

    let response_header_names = tx.matched_rules().iter().find(|rule| rule.rule_id() == 129).unwrap();
    assert_eq!(
        response_header_names
            .matches
            .iter()
            .map(|matched| (matched.key.as_str(), matched.value.clone()))
            .collect::<Vec<_>>(),
        CONNECTOR_HEADERS
            .iter()
            .map(|(name, _)| (*name, name.as_bytes().to_vec()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseHeaders, Some("x-padded"))
            .as_deref(),
        Some("  padded  ")
    );
}
