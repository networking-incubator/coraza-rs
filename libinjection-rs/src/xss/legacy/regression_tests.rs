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

use std::{vec, vec::Vec};

use super::{
    Html5Flags, Html5ParseState, Html5State, Html5Token, Html5Type,
    deny::{DenyAttrKind, is_deny_attr, is_deny_comment, is_deny_tag, is_deny_url},
    deny_list::{DENY_ATTRS, DENY_EVENTS},
    detect, is_xss, next_unseen_quote,
};

fn tokens(input: &[u8], flags: Html5Flags) -> Vec<(Html5Type, &[u8])> {
    let mut state = Html5State::new(input, flags);
    let mut result = Vec::new();
    while let Some(Html5Token { kind, value }) = state.next_token() {
        result.push((kind, value));
    }
    result
}

fn assert_tokens(input: &[u8], expected: &[(Html5Type, &[u8])]) {
    assert_eq!(tokens(input, Html5Flags::DataState), expected, "{input:?}");
}

#[test]
fn go_v033_xss_examples_match() {
    let cases: &[(&[u8], bool)] = &[
        (b"<script>alert(1);</script>", true),
        (b"><script>alert(1);</script>", true),
        (b"x ><script>alert(1);</script>", true),
        (b"' ><script>alert(1);</script>", true),
        (b"\"><script>alert(1);</script>", true),
        (b"red;</style><script>alert(1);</script>", true),
        (b"red;}</style><script>alert(1);</script>", true),
        (b"red;\"/><script>alert(1);</script>", true),
        (b"');}</style><script>alert(1);</script>", true),
        (b"onerror=alert(1)>", true),
        (b"x onerror=alert(1);>", true),
        (b"x' onerror=alert(1);>", true),
        (b"x\" onerror=alert(1);>", true),
        (b"<a href=\"javascript:alert(1)\">", true),
        (b"<a href='javascript:alert(1)'>", true),
        (b"<a href=javascript:alert(1)>", true),
        (b"<a href  =   javascript:alert(1); >", true),
        (b"<a href=\"  javascript:alert(1);\" >", true),
        (b"<a href=\"JAVASCRIPT:alert(1);\" >", true),
        (b"<style>@keyframes x{}</style><xss style=\"animation-name:x\" onanimationstart=\"alert(1)\"></xss>", true),
        (b"<noembed><img title=\"</noembed><img src onerror=alert(1)>\"></noembed>", true),
        (b"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>", true),
        (b"<xss class=progress-bar-animated onanimationstart=alert(1)>", true),
        (b"<button popovertarget=x>Click me</button><xss ontoggle=alert(1) popover id=x>XSS</xss>", true),
        (br##"<HTML xmlns:xss><?import namespace="xss" implementation="%(htc)s"><xss:xss>XSS</xss:xss></HTML>""","XML namespace."),("""<XML ID="xss"><I><B>&lt;IMG SRC="javas<!-- -->cript:javascript:alert(1)"&gt;</B></I></XML><SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>"##, true),
        (b"<img onauxclick=alert(1)>", true),
        (b"<img onpagereveal=alert(1)>", true),
        (b"<img onpageswap=alert(1)>", true),
        (b"<img onscrollsnapchange=alert(1)>", true),
        (b"<img onscrollsnapchanging=alert(1)>", true),
        (b"<!--xml -->", true),
        (b"<!--xmlfoo-->", true),
        (b"<!--xml:namespace-->", true),
        (b"<!--XML -->", true),
        (b"<svg>", true),
        (b"<svg onload=alert(1)>", true),
        (b"<svganimate>", true),
        (b"<!--xml-->", false),
        (b"<!--?xml -->", false),
        (b"<!--axml -->", false),
        (b"myvar=onfoobar==", false),
        (b"onY29va2llcw==", false),
        (b"=<a href=\"https://data\">", false),
        (b"<a href=\"https://github.com/Simbiat/database\">", false),
    ];
    assert_eq!(cases.len(), 44);
    for (input, expected) in cases {
        assert_eq!(detect(input), *expected, "input={input:?}");
    }
}

#[test]
fn percent_bogus_comment_uses_the_actual_cursor_and_keeps_later_script_visible() {
    let input = b"<%a%b%><script>alert(1)</script>";
    assert!(detect(input));
    assert_tokens(
        input,
        &[
            (Html5Type::TagComment, b"a%b"),
            (Html5Type::TagNameOpen, b"script"),
            (Html5Type::TagNameClose, b">"),
            (Html5Type::DataText, b"alert(1)"),
            (Html5Type::TagClose, b"script"),
        ],
    );
}

#[test]
fn incomplete_numeric_entities_keep_go_fallback_behavior() {
    assert!(!detect(b"href=&#"));
    assert!(!detect(b"href=&#X"));
}

#[test]
fn html5_transition_regressions_match_go_tokens() {
    assert_tokens(
        b"<a href=x/onerror=1>",
        &[
            (Html5Type::TagNameOpen, b"a"),
            (Html5Type::AttrName, b"href"),
            (Html5Type::AttrValue, b"x/onerror=1"),
            (Html5Type::TagNameClose, b">"),
        ],
    );
    assert_tokens(
        b"<a//onanimationstart=1>",
        &[
            (Html5Type::TagNameOpen, b"a"),
            (Html5Type::AttrName, b"onanimationstart"),
            (Html5Type::AttrValue, b"1"),
            (Html5Type::TagNameClose, b">"),
        ],
    );
    assert_tokens(
        b"<a/ >",
        &[(Html5Type::TagNameOpen, b"a"), (Html5Type::TagNameClose, b">")],
    );
    assert_tokens(
        b"</script/>",
        &[
            (Html5Type::TagNameOpen, b"script"),
            (Html5Type::TagNameSelfClose, b"/>"),
        ],
    );
    assert_tokens(b"<!-DOCTYPE html>", &[(Html5Type::TagComment, b"-DOCTYPE html")]);
    assert_tokens(b"<%a%b%>", &[(Html5Type::TagComment, b"a%b")]);
    assert_tokens(b"<%foo%>", &[(Html5Type::TagComment, b"foo")]);
    assert_tokens(b"</>", &[(Html5Type::DataText, b">")]);
    assert_tokens(b"<?> ", &[(Html5Type::TagComment, b""), (Html5Type::DataText, b" ")]);
    assert_tokens(b"<!>", &[(Html5Type::TagComment, b"")]);
    assert_tokens(b"<?", &[(Html5Type::TagComment, b"")]);
    assert_tokens(b"<", &[]);
    assert_tokens(
        b"<a href=x/onerror=1>",
        &[
            (Html5Type::TagNameOpen, b"a"),
            (Html5Type::AttrName, b"href"),
            (Html5Type::AttrValue, b"x/onerror=1"),
            (Html5Type::TagNameClose, b">"),
        ],
    );
}

#[test]
fn token_boundaries_and_empty_context_values_match_go() {
    assert!(tokens(b"", Html5Flags::DataState).is_empty());
    assert!(tokens(b"", Html5Flags::ValueNoQuote).is_empty());
    for flags in [
        Html5Flags::ValueSingleQuote,
        Html5Flags::ValueDoubleQuote,
        Html5Flags::ValueBackQuote,
    ] {
        let got = tokens(b"", flags);
        assert_eq!(got.len(), 1);
        assert!(
            got.first()
                .is_some_and(|(kind, value)| { *kind == Html5Type::AttrValue && value.is_empty() })
        );
    }
    let got = tokens(b"'", Html5Flags::ValueSingleQuote);
    assert_eq!(got.len(), 1);
    assert!(
        got.first()
            .is_some_and(|(kind, value)| { *kind == Html5Type::AttrValue && value.is_empty() })
    );
}

#[test]
fn attribute_classification_waits_for_a_value_and_resets() {
    for input in [
        b"<a onerror>".as_slice(),
        b"<a onerror=",
        b"<a style>",
        b"<a dataformatas>",
    ] {
        assert!(!is_xss(input, Html5Flags::DataState), "{input:?}");
    }
    for input in [b"<a onerror=>".as_slice(), b"<a style=>", b"<a dataformatas=>"] {
        assert!(is_xss(input, Html5Flags::DataState), "{input:?}");
    }
    assert!(!is_xss(b"<a attributename=style>", Html5Flags::DataState));
    assert!(is_xss(b"<a attributename=onerror>", Html5Flags::DataState));
    assert!(!is_xss(b"<a href javascript:>", Html5Flags::DataState));
}

#[test]
fn data_state_cannot_detect_without_an_opening_angle_byte() {
    for input in [
        b"".as_slice(),
        b"hello onerror=alert(1)",
        b"javascript:alert(1)",
        b"\0\xffENTITY",
    ] {
        assert!(!input.contains(&b'<'));
        assert!(!is_xss(input, Html5Flags::DataState), "{input:?}");
    }
}

#[test]
fn quoted_contexts_without_their_raw_delimiter_cannot_detect() {
    for (flags, delimiter, input) in [
        (
            Html5Flags::ValueSingleQuote,
            b'\'',
            b"\0\xff<unclosed script=onerror=1 \" `".as_slice(),
        ),
        (
            Html5Flags::ValueDoubleQuote,
            b'"',
            b"\0\xff<unclosed script=onerror=1 ' `".as_slice(),
        ),
        (
            Html5Flags::ValueBackQuote,
            b'`',
            b"\0\xff<unclosed script=onerror=1 ' \"".as_slice(),
        ),
    ] {
        assert!(!input.contains(&delimiter), "input={input:?}");
        assert!(!is_xss(input, flags), "input={input:?}");
    }
}

#[test]
fn quote_dispatch_finds_late_raw_delimiters_in_binary_input() {
    for (delimiter, flags) in [
        (b'\'', Html5Flags::ValueSingleQuote),
        (b'"', Html5Flags::ValueDoubleQuote),
        (b'`', Html5Flags::ValueBackQuote),
    ] {
        let mut input = [b'x'; 1024];
        input[17] = 0;
        input[18] = 0xFF;
        input[900] = delimiter;
        input[901..912].copy_from_slice(b" onerror=1>");
        assert!(is_xss(&input, flags), "delimiter={delimiter:?}");
        assert!(detect(&input), "delimiter={delimiter:?}");
    }
}

#[test]
fn quote_dispatch_skips_delimiters_already_seen_and_tracks_each_context() {
    let input = b"abc\"\0\xff'def`";
    assert_eq!(next_unseen_quote(input, 0, 0), Some((4, 2)));
    assert_eq!(next_unseen_quote(input, 4, 2), Some((7, 1)));
    assert_eq!(next_unseen_quote(input, 7, 3), Some((11, 4)));
    assert_eq!(next_unseen_quote(input, 11, 7), None);
    assert_eq!(next_unseen_quote(b"ordinary bytes", 0, 0), None);
    assert_eq!(next_unseen_quote(b"'''''", 1, 1), None);
}

#[test]
fn nul_and_slash_bytes_stay_in_names_and_unquoted_values() {
    assert!(detect(b"<a href=ja\0va:alert(1)>"));
    assert!(detect(b"<a onanima\0tionstart=1>"));
    assert!(!detect(b"<a href=x/onerror=1>"));
}

#[test]
fn comment_prefixes_use_go_raw_positions_and_safe_import_entity_backport() {
    for (body, expected) in [
        (b"[IF x".as_slice(), true),
        (b"[\0IFx", false),
        (b"XMLx", true),
        (b"X\0MLx", false),
        (b"XML\0", true),
        (b"\0IMPORT", true),
        (b"IM\0PORT", true),
        (b"EN\0TITY", true),
    ] {
        assert_eq!(is_deny_comment(body), expected, "body={body:?}");
    }
}

#[test]
fn all_pinned_event_and_named_attribute_classifications_are_preserved() {
    assert!(
        DENY_EVENTS
            .windows(2)
            .all(|pair| pair.first().zip(pair.get(1)).is_some_and(|(a, b)| a < b))
    );
    assert!(DENY_ATTRS.iter().all(|(name, _)| !name.starts_with(b"ON")));
    for &event in DENY_EVENTS {
        let mut name = Vec::from(&b"on"[..]);
        name.extend_from_slice(event);
        assert_eq!(is_deny_attr(&name), DenyAttrKind::Deny, "{name:?}");
    }
    for &(name, expected) in DENY_ATTRS {
        assert_eq!(is_deny_attr(name), expected, "{name:?}");
    }
    assert!(DENY_ATTRS.windows(2).all(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(first, second)| first.0 < second.0)
    }));
    assert_eq!(is_deny_attr(b"xmlnsfoo"), DenyAttrKind::None);
    assert_eq!(is_deny_attr(b"xlink:hrefx"), DenyAttrKind::None);
    assert_eq!(is_deny_attr(b"xlink:href"), DenyAttrKind::Url);
    assert_eq!(is_deny_attr(b"onnotanactualevent"), DenyAttrKind::None);
    assert_eq!(is_deny_attr(b"onzoom"), DenyAttrKind::Deny);
    assert!(is_deny_tag(b"svg"));
    assert!(is_deny_tag(b"svgx"));
}

#[test]
fn svg_prefixes_follow_go_length_limit_and_ignore_nuls() {
    let at_limit = [b"svg".as_slice(), &[b'x'; 61]].concat();
    let over_limit = [b"svg".as_slice(), &[b'x'; 62]].concat();
    assert!(is_deny_tag(&at_limit));
    assert!(!is_deny_tag(&over_limit));

    let nul_padded = [b"svg".as_slice(), &[0; 128]].concat();
    assert!(is_deny_tag(&nul_padded));
    let attr_at_limit = [b"onerror".as_slice(), &[b'x'; 57]].concat();
    let attr_over_limit = [b"onerror".as_slice(), &[b'x'; 58]].concat();
    assert_eq!(is_deny_attr(&attr_at_limit), DenyAttrKind::None);
    assert_eq!(is_deny_attr(&attr_over_limit), DenyAttrKind::None);
    assert_eq!(is_deny_attr(b"onerror"), DenyAttrKind::Deny);
}

#[test]
fn numeric_entity_controls_and_low_byte_masking_follow_go_order() {
    assert!(is_deny_url(b"&#32;java:"));
    assert!(is_deny_url(b"&#x14a;ava:"));
    assert!(!is_deny_url(b"&#x100;avascript:"));
    assert!(!is_deny_url(b"&#x161;ava:"));
    assert!(is_deny_url(b"&#10;java:"));
    assert!(!is_deny_url(b"&#1114112;avascript:"));
}

#[test]
fn repeated_slashes_in_a_ten_million_byte_input_use_iterative_states() {
    let input = vec![b'/'; 10_000_000];
    assert!(!detect(&input));
}

#[test]
fn tokenizer_reaches_eof_after_trailing_tokens() {
    let mut h5 = Html5State::new(b"<script>", Html5Flags::DataState);
    assert_eq!(h5.next_token().map(|t| t.kind), Some(Html5Type::TagNameOpen));
    assert_eq!(h5.state, Html5ParseState::TagNameClose);
    assert_eq!(h5.next_token().map(|t| t.kind), Some(Html5Type::TagNameClose));
    assert_eq!(h5.state, Html5ParseState::Eof);
}
