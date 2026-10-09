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

#![cfg(feature = "legacy")]

//! Regression tests for the canonical full-input compatibility API.

#[cfg(test)]
mod tests {
    use libinjection::{Html5TokenKind, XssHtmlContext, detect_sqli, detect_xss, html5_visit};

    #[test]
    fn sql_compatibility_result_has_exact_fingerprint_only_on_hit() {
        let hit = detect_sqli(b"1' OR '1'='1");
        assert!(hit.detected);
        assert_eq!(hit.fingerprint.as_str(), Some("s&sos"));

        let miss = detect_sqli(b"ordinary text");
        assert!(!miss.detected);
        assert!(miss.fingerprint.as_str().is_none());
    }

    #[test]
    fn canonical_detection_does_not_or_in_modern_constructs() {
        // These inputs can set modern construct hints but are benign in the pinned
        // libinjection compatibility algorithm.
        assert!(!detect_sqli(b"1 UNION").detected);
        assert!(!detect_sqli(b"1# blah blah").detected);
        assert!(!detect_sqli(b"1#x").detected);
        assert!(!detect_xss(b"<!-- ordinary comment -->"));
        assert!(!detect_xss(b"javascript:alert(1)"));
    }

    #[test]
    fn number_followed_by_block_comment_is_detected_after_leading_whitespace() {
        assert!(detect_sqli(b"\t1/*").detected);
        assert!(detect_sqli(b"1/*").detected);
        assert!(detect_sqli(b"\t1--").detected);

        let hex = detect_sqli(b" 0x1/*");
        assert!(hex.detected);
        assert_eq!(hex.fingerprint.as_str(), Some("1c"));
    }

    #[test]
    fn sqli_detection_matches_go_literal_and_whitelist_boundaries() {
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
            assert_eq!(detect_sqli(input).detected, *expected, "input={input:?}");
        }
    }

    #[test]
    fn high_byte_q_delimiter_does_not_hide_conditional_comment() {
        let result = detect_sqli(b"q'\xe9' union /*!50000select*/ 1");
        assert!(result.detected);
        assert_eq!(result.fingerprint.as_str(), Some("X"));
    }

    #[test]
    fn nul_after_variable_does_not_hide_following_union_query() {
        assert!(detect_sqli(b"@\0union select 1").detected);
    }

    #[test]
    fn nul_after_hex_prefix_does_not_hide_tautology() {
        assert!(detect_sqli(b"1 or 0x\0\x31=1-- ").detected);
    }

    #[test]
    fn reviewed_sql_improvements_have_benign_controls() {
        assert!(!detect_sqli(b"1").detected);
        assert!(!detect_sqli(b"q'\xe9'").detected);
        assert!(!detect_sqli(b"0x\0\x31").detected);
        assert!(!detect_sqli(b"@\0name").detected);
    }

    #[test]
    fn namespace_attribute_matching_has_benign_and_attack_controls() {
        assert!(!detect_xss(b"<div xmlnsfoo=\"safe\">"));
        assert!(!detect_xss(b"<div xlinkfoo=\"safe\">"));
        assert!(!detect_xss(b"<div xmlns:xss=\"safe\">"));
        assert!(detect_xss(b"<div xlink:href=\"javascript:alert(1)\">"));
    }

    #[test]
    fn svg_prefix_matching_keeps_go_behavior_and_bounds_long_names() {
        assert!(detect_xss(b"<svg onload=alert(1)>"));
        assert!(detect_xss(b"<svganimate>"));

        let long_svg = [b"<svg".as_slice(), &[b'x'; 64], b">"].concat();
        assert!(!detect_xss(&long_svg));
    }

    #[test]
    fn html5_visitor_matches_go_boundary_tokens() {
        fn assert_tokens(input: &[u8], expected: &[(Html5TokenKind, &[u8])]) {
            let mut actual = Vec::new();
            html5_visit(input, XssHtmlContext::Data, |kind, value| {
                actual.push((kind, value.to_vec()));
            });
            let actual: Vec<_> = actual.iter().map(|(kind, value)| (*kind, value.as_slice())).collect();
            assert_eq!(actual.as_slice(), expected, "input={input:?}");
        }

        use Html5TokenKind::{AttrName, DataText, TagComment, TagNameClose, TagNameOpen, TagNameSelfClose};

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
        let result = detect_sqli(b"-(top<>thendrop1.5\\'--null'--");
        assert!(result.detected);
        assert_eq!(result.fingerprint.as_str(), Some("sc"));
    }

    #[test]
    fn canonical_detection_scans_beyond_the_bounded_analysis_default() {
        let mut sqli_input = vec![b' '; 9_000];
        sqli_input.extend_from_slice(b"1' OR '1'='1");
        assert!(detect_sqli(&sqli_input).detected);

        let mut xss_input = vec![b'x'; 9_000];
        xss_input.extend_from_slice(b"<script>alert(1)</script>");
        assert!(detect_xss(&xss_input));
    }
}
