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

/// Process a `POST` whose `Content-Type` is `content_type` through the request phases, as a connector does, and
/// return the rule id and status of the interruption, if any. `reject_uploads` is the host ban on file uploads
/// that `envoy-coraza` sets.
fn interrupted_by(rules: &str, reject_uploads: bool, content_type: &str, body: &[u8]) -> Option<(i32, u16)> {
    let mut parser = Parser::new();
    parser
        .from_string(&format!("SecRuleEngine On\nSecRequestBodyAccess On\n{rules}"))
        .unwrap();
    parser.config_mut().reject_multipart_file_uploads = reject_uploads;
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction();
    tx.process_uri("/p", "POST", "HTTP/1.1");
    tx.add_request_header("Content-Type", content_type);
    if tx.process_request_headers().is_none() {
        tx.process_request_body(body);
    }
    tx.interruption()
        .map(|interruption| (interruption.rule_id, interruption.status))
}

/// A3-10: Go Coraza and Go's `mime.ParseMediaType` lower-case with `strings.ToLower`, which maps U+0130 to `i`, so a
/// Go backend parses this body as a form.
#[test]
fn a_content_type_go_folds_to_urlencoded_selects_the_processor() {
    let rule = "SecRule ARGS_POST:m \"@streq MARK\" \"id:1,phase:2,deny,status:403\"";
    assert_eq!(
        interrupted_by(rule, false, "appl\u{130}cation/x-www-form-urlencoded", b"m=MARK"),
        Some((1, 403))
    );
}

/// The same for multipart: Go Coraza and Go `net/http` both read this as `multipart/form-data`, so the file part
/// reaches `FILES`.
#[test]
fn a_content_type_go_folds_to_multipart_selects_the_processor() {
    let rule = "SecRule FILES \"@streq up.bin\" \"id:1,phase:2,deny,status:403\"";
    let body = b"--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"up.bin\"\r\n\r\nMARK\r\n--b--\r\n";
    assert_eq!(
        interrupted_by(rule, false, "mult\u{130}part/form-data; boundary=b", body),
        Some((1, 403))
    );
}

/// A multipart body with a file part, as `envoy-coraza` refuses it.
const UPLOAD: &[u8] =
    b"--a=b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.phtml\"\r\n\r\nhello\r\n--a=b--\r\n";

/// Control: the host's ban on uploads refuses the file part with 413.
#[test]
fn host_upload_ban_refuses_a_multipart_upload() {
    assert_eq!(
        interrupted_by("", true, "multipart/form-data; boundary=\"a=b\"", UPLOAD),
        Some((0, 413))
    );
}

/// A3-10: the U+0130 spelling, which Go reads as multipart, must not get a file past the ban.
#[test]
fn host_upload_ban_refuses_a_multipart_upload_spelled_with_dotted_capital_i() {
    assert_eq!(
        interrupted_by("", true, "mult\u{130}part/form-data; boundary=\"a=b\"", UPLOAD),
        Some((0, 413))
    );
}

/// Rules that report what the multipart processor read: a file named `x.php`, a field named `evil`, and a repeated
/// disposition parameter.
const SEE_PARTS: &str = "SecRule FILES \"@streq x.php\" \"id:1,phase:2,deny,status:403\"\n\
                         SecRule ARGS_POST_NAMES \"@streq evil\" \"id:2,phase:2,deny,status:403\"\n\
                         SecRule MULTIPART_DUPLICATE_PART_HEADER \"@eq 1\" \"id:3,phase:2,deny,status:403\"";

/// A body that is multipart for the boundary `decoy` (one field `x`) and for the boundary `real` (one file part
/// `x.php`, the `decoy` lines being its preamble and epilogue).
const TWO_BOUNDARIES: &[u8] = b"--decoy\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\n\
--real\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.php\"\r\n\r\n<?php\r\n--real--\r\n--decoy--\r\n";

/// A body of one part with this `Content-Disposition`.
fn one_part(disposition: &str) -> Vec<u8> {
    format!("--b\r\nContent-Disposition: {disposition}\r\n\r\n<?php\r\n--b--\r\n").into_bytes()
}

/// Go's `decode2231Enc` lower-cases the charset with `strings.ToLower`, so `us-ascİİ` is `us-ascii` and Go splits
/// the body on the extended boundary `real`. Splitting on `decoy` would hide the file part from `FILES` and from the
/// host's upload ban.
#[test]
fn an_extended_boundary_whose_charset_go_lower_cases_splits_the_body_like_go() {
    let content_type = "multipart/form-data; boundary=decoy; boundary*=\"us-asc\u{130}\u{130}''real\"";
    assert_eq!(
        interrupted_by(SEE_PARTS, false, content_type, TWO_BOUNDARIES),
        Some((1, 403))
    );
    assert_eq!(interrupted_by("", true, content_type, TWO_BOUNDARIES), Some((0, 413)));
}

/// The same charset names the field `evil` in Go.
#[test]
fn an_extended_name_whose_charset_go_lower_cases_names_the_field_like_go() {
    let body = one_part("form-data; name=\"safe\"; name*=\"us-asc\u{130}\u{130}''evil\"");
    assert_eq!(
        interrupted_by(SEE_PARTS, false, "multipart/form-data; boundary=b", &body),
        Some((2, 403))
    );
}

/// A `filename*0*` continuation in that charset is resolved by `mime.ParseMediaType`, so the part is a file in Go.
#[test]
fn a_filename_continuation_whose_charset_go_lower_cases_is_a_file_like_go() {
    let content_type = "multipart/form-data; boundary=b";
    let alone = one_part("form-data; name=\"f\"; filename*0*=\"us-asc\u{130}\u{130}''x.php\"");
    assert_eq!(interrupted_by(SEE_PARTS, false, content_type, &alone), Some((1, 403)));
    assert_eq!(interrupted_by("", true, content_type, &alone), Some((0, 413)));
    let beside_a_plain_name =
        one_part("form-data; name=\"f\"; filename=\"a.txt\"; filename*0*=\"us-asc\u{130}\u{130}''x.php\"");
    assert_eq!(
        interrupted_by(SEE_PARTS, false, content_type, &beside_a_plain_name),
        Some((1, 403))
    );
}

/// The white space Go's `unicode.IsSpace` accepts and a part header can carry: every rune of Go 1.27's set but U+000A
/// to U+000D, which end or reject a header line first.
const HEADER_SPACES: [char; 21] = [
    '\t', ' ', '\u{85}', '\u{a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}', '\u{2005}',
    '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}',
    '\u{3000}',
];

/// Go's `mime.ParseMediaType` and Go Coraza's `findParam` trim Unicode white space around a parameter, so with any of
/// these before the name or the `=` the part is a file upload in Go, and in Go's `net/http`.
#[test]
fn a_disposition_parameter_after_unicode_white_space_is_read_like_go() {
    let content_type = "multipart/form-data; boundary=b";
    for space in HEADER_SPACES {
        for disposition in [
            format!("form-data; name=\"f\";{space}filename=\"x.php\""),
            format!("form-data; name=\"f\"; filename{space}=\"x.php\""),
        ] {
            let body = one_part(&disposition);
            assert_eq!(
                interrupted_by(SEE_PARTS, false, content_type, &body),
                Some((1, 403)),
                "{disposition:?}"
            );
            assert_eq!(
                interrupted_by("", true, content_type, &body),
                Some((0, 413)),
                "{disposition:?}"
            );
        }
        // A `filename` repeated after the white space is a duplicate, as `mime.ParseMediaType` reports it.
        let body = one_part(&format!(
            "form-data; name=\"f\"; filename=\"a.txt\";{space}filename=\"x.php\""
        ));
        assert_eq!(
            interrupted_by(SEE_PARTS, false, content_type, &body),
            Some((3, 403)),
            "U+{:04X}",
            u32::from(space)
        );
    }
}
