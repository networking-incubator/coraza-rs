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

//! Regression cases for the stable libperfusion detection API.

#![expect(
    clippy::tests_outside_test_module,
    reason = "Cargo integration test targets consist of tests."
)]
#![expect(
    clippy::unwrap_used,
    reason = "Missing expected tokens should fail the regression test immediately."
)]

use libperfusion::{HtmlContext, HtmlTokenKind, HtmlTokenizer, xss, xss_in_context};

#[test]
fn sqli_returns_fingerprint_only_on_hit() {
    let hit = libperfusion::sqli(b"1' OR '1'='1").unwrap();
    assert_eq!(hit.as_str(), "s&sos");

    assert!(libperfusion::sqli(b"ordinary text").is_none());
}

#[test]
fn detection_does_not_accept_modern_constructs_outside_libinjection_parity() {
    assert!(libperfusion::sqli(b"1 UNION").is_none());
    assert!(libperfusion::sqli(b"1# blah blah").is_none());
    assert!(libperfusion::sqli(b"1#x").is_none());
    assert!(!xss(b"<!-- ordinary comment -->"));
    assert!(!xss(b"javascript:alert(1)"));
}

#[test]
fn number_followed_by_block_comment_is_detected_after_leading_whitespace() {
    assert!(libperfusion::sqli(b"\t1/*").is_some());
    assert!(libperfusion::sqli(b"1/*").is_some());
    assert!(libperfusion::sqli(b"\t1--").is_some());

    let fingerprint = libperfusion::sqli(b" 0x1/*").unwrap();
    assert_eq!(fingerprint.as_str(), "1c");
}

#[test]
fn sqli_matches_go_literal_and_whitelist_boundaries() {
    let cases: &[(&[u8], bool)] = &[
        (b"1 -- sp_password", true),
        (b"1+1/*comment*/", true),
        (b"1 /*comment*/", true),
        (b"SELECT B0101", false),
        (b"SELECT b", false),
        (b"b'0x", false),
        (b"Q'{hello}'", false),
        (b"q'{hello}'", false),
        (b"Q'<hello>'", true),
        (b"q'<hello>'", true),
        (b"Q'\x01hello'", false),
    ];

    for (input, expected) in cases {
        assert_eq!(libperfusion::sqli(input).is_some(), *expected, "input={input:?}");
    }
}

#[test]
fn high_byte_q_delimiter_does_not_hide_conditional_comment() {
    let fingerprint = libperfusion::sqli(b"q'\xe9' union /*!50000select*/ 1").unwrap();
    assert_eq!(fingerprint.as_str(), "X");
}

#[test]
fn nul_after_variable_does_not_hide_following_union_query() {
    assert!(libperfusion::sqli(b"@\0union select 1").is_some());
}

#[test]
fn nul_after_hex_prefix_does_not_hide_tautology() {
    assert!(libperfusion::sqli(b"1 or 0x\0\x31=1-- ").is_some());
}

#[test]
fn reviewed_sql_improvements_have_benign_controls() {
    for input in [b"1".as_slice(), b"q'\xe9'", b"0x\0\x31", b"@\0name"] {
        assert!(libperfusion::sqli(input).is_none(), "input={input:?}");
    }
}

#[test]
fn namespace_attribute_matching_has_benign_and_attack_controls() {
    for input in [
        b"<div xmlnsfoo=\"safe\">".as_slice(),
        b"<div xlinkfoo=\"safe\">",
        b"<div xmlns:xss=\"safe\">",
    ] {
        assert!(!xss(input), "input={input:?}");
    }
    assert!(xss(b"<div xlink:href=\"javascript:alert(1)\">"));
}

#[test]
fn svg_prefix_matching_keeps_go_behavior_and_bounds_long_names() {
    assert!(xss(b"<svg onload=alert(1)>"));
    assert!(xss(b"<svganimate>"));

    let long_svg = [b"<svg".as_slice(), &[b'x'; 64], b">"].concat();
    assert!(!xss(&long_svg));
}

#[test]
fn html5_tokenizer_matches_go_boundary_tokens() {
    fn assert_tokens(input: &[u8], expected: &[(HtmlTokenKind, &[u8])]) {
        let actual: Vec<_> = HtmlTokenizer::new(input, HtmlContext::Data)
            .map(|token| (token.kind, token.text))
            .collect();
        assert_eq!(actual.as_slice(), expected, "input={input:?}");
    }

    use HtmlTokenKind::{AttrName, DataText, TagComment, TagNameClose, TagNameOpen, TagNameSelfClose};

    assert_tokens(b"<div ", &[(TagNameOpen, b"div")]);
    assert_tokens(b"<div foo ", &[(TagNameOpen, b"div"), (AttrName, b"foo")]);
    assert_tokens(
        b"<div foo />",
        &[(TagNameOpen, b"div"), (AttrName, b"foo"), (TagNameSelfClose, b"/>")],
    );
    assert_tokens(
        b"<div foo >",
        &[(TagNameOpen, b"div"), (AttrName, b"foo"), (TagNameClose, b">")],
    );
    assert_tokens(b"<div href= ", &[(TagNameOpen, b"div"), (AttrName, b"href")]);
    assert_tokens(
        b"<div / foo>",
        &[(TagNameOpen, b"div"), (AttrName, b"foo"), (TagNameClose, b">")],
    );
    assert_tokens(b"<%a%b>", &[(TagComment, b"a%b>")]);
    assert_tokens(b"<!---\0->", &[(TagComment, b"")]);
    assert_tokens(b"<!---\0\0", &[(TagComment, b"-\0\0")]);
    assert_tokens(b"<!---\0-", &[(TagComment, b"-\0-")]);
    assert_tokens(b"</", &[]);
    assert_tokens(b"</0abc>", &[(TagComment, b"0abc")]);
    assert_tokens(b"<\0div>", &[(TagNameOpen, b"\0div"), (TagNameClose, b">")]);
    assert_tokens(b"<1foo>", &[(DataText, b"<"), (DataText, b"1foo>")]);
}

#[test]
fn linear_quote_scanner_keeps_malformed_quote_attack_visible() {
    let fingerprint = libperfusion::sqli(b"-(top<>thendrop1.5\\'--null'--").unwrap();
    assert_eq!(fingerprint.as_str(), "sc");
}

#[test]
fn detection_scans_beyond_the_prefix_api_default() {
    let mut sqli_input = vec![b' '; 9_000];
    sqli_input.extend_from_slice(b"1' OR '1'='1");
    assert!(libperfusion::sqli(&sqli_input).is_some());

    let mut xss_input = vec![b'x'; 9_000];
    xss_input.extend_from_slice(b"<script>alert(1)</script>");
    assert!(xss(&xss_input));
    assert!(!xss_in_context(
        b"<script>alert(1)</script>",
        HtmlContext::ValueBackQuote
    ));
}
