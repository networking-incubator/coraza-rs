// Copyright (c) 2012-2016, Nick Galbreath
// Copyright (c) 2017-2024, libinjection Contributors
// Copyright 2026 Coraza Kubernetes Operator contributors.
//
// SPDX-License-Identifier: BSD-3-Clause
// See the crate's LICENSE for the complete terms.
//! Cross-site scripting detection: tokenize the input as HTML5 in each of

//! the contexts it could be injected into, and look for tags, attributes
//! and URLs that can run script.

#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "Private XSS scanner helpers implement the documented detection API."
    )
)]
use crate::{
    bytes::contains,
    html5::{Context, TokenKind, Tokenizer},
};

/// Why an attribute is of interest.
#[cfg_attr(
    not(feature = "internals"),
    expect(
        unreachable_pub,
        reason = "The hidden internals feature reexports this type for table tests."
    )
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attribute {
    /// Always banned.
    Black,
    /// Its value is a URL-like object.
    Url,
    /// Its value contains CSS text that needs special handling.
    Style,
    /// Its value names another attribute.
    Indirect,
}

#[cfg_attr(
    not(feature = "internals"),
    expect(
        unreachable_pub,
        reason = "The hidden internals feature reexports these tables for source-integrity tests."
    )
)]
pub(crate) mod tables {
    include!(concat!(env!("OUT_DIR"), "/xss_tables.rs"));
}

use self::tables::{BLACK_ATTR_EVENTS, BLACK_ATTRS, BLACK_TAGS};

/// Where in [`BLACK_ATTR_EVENTS`] the events starting with each letter are:
/// from the first of them to the last. The table has them together, but a
/// stray event would only widen a span, to be ruled out by the comparison.
static EVENT_SPANS: [(usize, usize); 26] = {
    let mut spans = [(0, 0); 26];
    let mut i = 0;
    while i < BLACK_ATTR_EVENTS.len() {
        let letter = (BLACK_ATTR_EVENTS[i].as_bytes()[0] - b'A') as usize;
        if spans[letter].1 == 0 {
            spans[letter].0 = i;
        }
        spans[letter].1 = i + 1;
        i += 1;
    }
    spans
};

/// URL schemes that can run script. "JAVA" covers `java:` and `javascript:`.
const BLACK_URL_SCHEMES: [&[u8]; 4] = [b"DATA", b"VIEW-SOURCE", b"JAVA", b"VBSCRIPT"];

const MAX_NORMALIZED_TOKEN_LEN: usize = 64;

/// Uppercases ASCII and removes NULs into a bounded buffer. `None` means the
/// non-NUL name exceeds the limit and cannot match any supported name.
fn normalize_name(name: &[u8], normalized: &mut [u8; MAX_NORMALIZED_TOKEN_LEN]) -> Option<usize> {
    let mut len = 0;
    for &byte in name {
        if byte == 0 {
            continue;
        }
        let slot = normalized.get_mut(len)?;
        *slot = byte.to_ascii_uppercase();
        len += 1;
    }
    Some(len)
}

/// Whether a comment starts with the first six non-NUL ASCII bytes of a
/// keyword, as Go's `upperRemoveNulls` does for IMPORT and ENTITY.
fn comment_starts_with_keyword(comment: &[u8], keyword: [u8; 6]) -> bool {
    let mut expected = keyword.iter();
    for &byte in comment.iter().filter(|&&byte| byte != 0) {
        let Some(&expected_byte) = expected.next() else {
            return true;
        };
        if byte.to_ascii_uppercase() != expected_byte {
            return false;
        }
    }
    expected.next().is_none()
}

/// Decodes one character of HTML-encoded text, returning it and the number
/// of bytes it took. `None` if `src` is empty.
///
/// Only numeric entities are decoded, decimal (`&#65;`) or hexadecimal
/// (`&#x41;`), with or without the closing ';'. Anything else, a named
/// entity included, is the byte it starts with.
fn html_decode_char_at(src: &[u8]) -> Option<(u32, usize)> {
    const AMPERSAND: (u32, usize) = (b'&' as u32, 1);
    /// Above this, the entity is given up on and read as a plain '&'.
    const MAX: u32 = 0x0010_00FF;

    let &first = src.first()?;
    let is_hex = matches!(src.get(2), Some(b'x' | b'X'));
    if first != b'&' || src.len() < 3 || (is_hex && src.len() < 4) {
        return Some((u32::from(first), 1));
    }
    if src[1] != b'#' {
        return Some(AMPERSAND);
    }

    let (radix, digits_at) = if is_hex { (16, 3) } else { (10, 2) };
    let digit = |ch: u8| char::from(ch).to_digit(radix);

    // The degenerate "&#?" has no digit at all.
    let Some(mut val) = digit(src[digits_at]) else {
        return Some(AMPERSAND);
    };
    for (i, &ch) in src.iter().enumerate().skip(digits_at + 1) {
        if ch == b';' {
            return Some((val, i + 1));
        }
        let Some(d) = digit(ch) else {
            return Some((val, i));
        };
        val = val * radix + d;
        if val > MAX {
            return Some(AMPERSAND);
        }
    }
    Some((val, src.len()))
}

/// Whether the HTML-encoded `src` starts with the upper-case `prefix`,
/// ignoring case, leading whitespace and control characters, and any NUL or
/// newline along the way.
fn htmlencode_startswith(mut prefix: &[u8], mut src: &[u8]) -> bool {
    let mut first = true;
    while let Some((mut cb, consumed)) = html_decode_char_at(src) {
        let Some((&expected, rest)) = prefix.split_first() else {
            return true;
        };
        src = &src[consumed..];

        if first && cb <= 32 {
            continue;
        }
        first = false;

        if cb == 0 || cb == 10 {
            continue;
        }

        if (u32::from(b'a')..=u32::from(b'z')).contains(&cb) {
            cb -= 0x20;
        }

        // Upstream narrows the decoded value to a `char` to compare it, so
        // "&#x144;" is as good a 'D' as "&#x44;".
        if u32::from(expected) != cb & 0xFF {
            return false;
        }
        prefix = rest;
    }
    prefix.is_empty()
}

fn is_black_tag(name: &[u8]) -> bool {
    if name.len() < 3 {
        return false;
    }
    let mut normalized = [0; MAX_NORMALIZED_TOKEN_LEN];
    let Some(len) = normalize_name(name, &mut normalized) else {
        return false;
    };
    let name = &normalized[..len];
    BLACK_TAGS.iter().any(|tag| name == tag.as_bytes())
        // Anything SVG or XSL(T) related.
        || name.starts_with(b"SVG")
        || name.starts_with(b"XSL")
}

fn black_attr(name: &[u8]) -> Option<Attribute> {
    let mut normalized = [0; MAX_NORMALIZED_TOKEN_LEN];
    let len = normalize_name(name, &mut normalized)?;
    let name = &normalized[..len];
    if name.len() < 2 {
        return None;
    }

    if name == b"XMLNS" || name == b"XLINK" {
        return Some(Attribute::Black);
    }

    if name.len() >= 5 && name.starts_with(b"ON") {
        let event = &name[2..];
        let first = event[0];
        if first.is_ascii_uppercase() {
            let (start, end) = EVENT_SPANS[usize::from(first - b'A')];
            if BLACK_ATTR_EVENTS[start..end]
                .iter()
                .any(|known| event == known.as_bytes())
            {
                return Some(Attribute::Black);
            }
        }
    }

    BLACK_ATTRS
        .iter()
        .find(|(known, _)| name == known.as_bytes())
        .map(|&(_, attribute)| attribute)
}

fn is_black_url(url: &[u8]) -> bool {
    // Skip whitespace, and high-bit bytes with it: they are not ASCII, Opera
    // sometimes takes UTF-8 whitespace, and EUC-JP ignores some of them.
    let start = url.iter().position(|&ch| ch > 32 && ch < 127).unwrap_or(url.len());
    let url = &url[start..];

    BLACK_URL_SCHEMES
        .iter()
        .any(|scheme| htmlencode_startswith(scheme, url))
}

pub(crate) fn is_xss(input: &[u8], context: Context) -> bool {
    let mut attr = None;
    for token in Tokenizer::new(input, context) {
        let text = token.text;
        if token.kind != TokenKind::AttrValue {
            attr = None;
        }

        match token.kind {
            TokenKind::Doctype => return true,
            TokenKind::TagNameOpen => {
                if is_black_tag(text) {
                    return true;
                }
            },
            TokenKind::AttrName => attr = black_attr(text),
            TokenKind::AttrValue => {
                let is_black = match attr.take() {
                    None => false,
                    Some(Attribute::Black | Attribute::Style) => true,
                    Some(Attribute::Url) => is_black_url(text),
                    // An attribute name is given in a _value_.
                    Some(Attribute::Indirect) => black_attr(text) == Some(Attribute::Black),
                };
                if is_black {
                    return true;
                }
            },
            TokenKind::TagComment => {
                // IE uses a "`" as a tag ending char.
                if contains(text, b'`') {
                    return true;
                }

                // IE conditional comments, and XML processing instructions.
                if text.len() > 3 && (text[..3].eq_ignore_ascii_case(b"[if") || text[..3].eq_ignore_ascii_case(b"xml"))
                {
                    return true;
                }

                // IE's <?import pseudo-tag, and XML entity definitions.
                if text.len() > 5
                    && (comment_starts_with_keyword(text, *b"IMPORT") || comment_starts_with_keyword(text, *b"ENTITY"))
                {
                    return true;
                }
            },
            TokenKind::DataText | TokenKind::TagNameClose | TokenKind::TagNameSelfClose | TokenKind::TagClose => {},
        }
    }
    false
}

pub(crate) fn detect(input: &[u8]) -> bool {
    detect_with_context(input).is_some()
}

pub(crate) fn detect_with_context(input: &[u8]) -> Option<Context> {
    let has_data_start = input.first() == Some(&b'<') || crate::bytes::find_byte(input, 0, b'<').is_some();
    if has_data_start && is_xss(input, Context::Data) {
        return Some(Context::Data);
    }
    if is_xss(input, Context::ValueNoQuote) {
        return Some(Context::ValueNoQuote);
    }

    for (quote, context) in [
        (b'\'', Context::ValueSingleQuote),
        (b'"', Context::ValueDoubleQuote),
        (b'`', Context::ValueBackQuote),
    ] {
        if crate::bytes::find_byte(input, 0, quote).is_some() && is_xss(input, context) {
            return Some(context);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_spans_hold_every_event() {
        for (i, event) in BLACK_ATTR_EVENTS.iter().enumerate() {
            let (start, end) = EVENT_SPANS[usize::from(event.as_bytes()[0] - b'A')];
            assert!((start..end).contains(&i), "{event}");
        }
    }

    #[test]
    fn attribute_names() {
        assert_eq!(black_attr(b"onclick"), Some(Attribute::Black));
        assert_eq!(black_attr(b"OnClIcKx"), None);
        assert_eq!(black_attr(b"oncli"), None);
        assert_eq!(black_attr(b"on1click"), None);
        assert_eq!(black_attr(b"on\0click"), Some(Attribute::Black));

        assert_eq!(black_attr(b"href"), Some(Attribute::Url));
        assert_eq!(black_attr(b"style"), Some(Attribute::Style));
        assert_eq!(black_attr(b"attributeName"), Some(Attribute::Indirect));
        assert_eq!(black_attr(b"xmlns"), Some(Attribute::Black));
        assert_eq!(black_attr(b"xmlns:x"), None);
        assert_eq!(black_attr(b"xlink"), Some(Attribute::Black));
        assert_eq!(black_attr(b"xlink:href"), Some(Attribute::Url));
        assert_eq!(black_attr(b"xlink:x"), None);
        // NULs are dropped, wherever they are.
        assert_eq!(black_attr(b"h\0REF"), Some(Attribute::Url));
        assert_eq!(black_attr(b"\0href"), Some(Attribute::Url));
        assert_eq!(black_attr(b"hrefs"), None);
        assert_eq!(black_attr(b"title"), None);
        assert_eq!(black_attr(b"h"), None);
    }

    #[test]
    fn black_attribute_candidates_start_with_ascii_letters() {
        for (name, attribute) in BLACK_ATTRS {
            assert!(name.as_bytes()[0].is_ascii_alphabetic(), "{name}");
            assert_eq!(black_attr(name.as_bytes()), Some(attribute), "{name}");
        }
        assert_eq!(black_attr(b"onloadx"), None);
        assert_eq!(black_attr(b"xmlns:x"), None);
        assert_eq!(black_attr(b"xlink:x"), None);
        assert_eq!(black_attr(b"on\0load"), Some(Attribute::Black));
    }

    #[test]
    fn high_bit_attribute_names_are_rejected_after_leading_nuls() {
        assert_eq!(black_attr(b"\0\0\0"), None);
        assert_eq!(black_attr(b"\0\xff\x80\0\xff\x80"), None);
        assert!(!is_xss(b"<p attributeName=\"\0\xff\x80\">", Context::Data));
        assert!(is_xss(b"<p attributeName=onload>", Context::Data));
    }

    fn unpruned_detect_with_context(input: &[u8]) -> Option<Context> {
        [
            Context::Data,
            Context::ValueNoQuote,
            Context::ValueSingleQuote,
            Context::ValueDoubleQuote,
            Context::ValueBackQuote,
        ]
        .into_iter()
        .find(|&context| is_xss(input, context))
    }

    #[test]
    fn context_pruning_preserves_priority_and_results() {
        const ALPHABET: &[u8] = b"<> '\"`= on\0";

        let attack = b"\"onclick=x'onerror=y";
        assert!(!is_xss(attack, Context::Data));
        assert!(!is_xss(attack, Context::ValueNoQuote));
        assert!(is_xss(attack, Context::ValueDoubleQuote));
        assert!(is_xss(attack, Context::ValueSingleQuote));
        // The double quote is encountered first, but the single-quote context
        // still has priority in the original context sequence.
        assert_eq!(detect_with_context(attack), Some(Context::ValueSingleQuote));

        assert_eq!(detect_with_context(b"onload=x"), Some(Context::ValueNoQuote));
        assert_eq!(detect_with_context(b"'onerror=x"), Some(Context::ValueSingleQuote));
        assert_eq!(detect_with_context(b"\"onclick=x"), Some(Context::ValueDoubleQuote));
        assert_eq!(detect_with_context(b"`onclick=x"), Some(Context::ValueBackQuote));
        assert_eq!(detect_with_context(b"hello world"), None);

        for len in 0..=4 {
            let cases = ALPHABET.len().pow(u32::try_from(len).unwrap_or_default());
            for mut encoded in 0..cases {
                let mut storage = [0; 4];
                let input = &mut storage[..len];
                for byte in input.iter_mut() {
                    *byte = ALPHABET[encoded % ALPHABET.len()];
                    encoded /= ALPHABET.len();
                }
                assert_eq!(
                    detect_with_context(input),
                    unpruned_detect_with_context(input),
                    "input {:?}",
                    input.escape_ascii()
                );
            }
        }
    }

    #[test]
    fn tag_names() {
        assert!(is_black_tag(b"script"));
        assert!(is_black_tag(b"ScRiPt"));
        assert!(is_black_tag(b"scr\0ipt"));
        assert!(is_black_tag(b"\0script"));
        assert!(is_black_tag(b"svgfoo"));
        assert!(is_black_tag(b"xsl:template"));
        assert!(!is_black_tag(b"scripts"));
        assert!(!is_black_tag(b"div"));
        assert!(!is_black_tag(b"a"));
        assert!(!is_black_tag(&[b"svg".as_slice(), &[b'x'; 64]].concat()));
    }

    #[test]
    fn indirect_attributes_only_accept_black_attribute_values() {
        assert!(is_xss(b"<a attributename=onclick>", Context::Data));
        assert!(!is_xss(b"<a attributename=href>", Context::Data));
        assert!(!is_xss(b"<a attributename=style>", Context::Data));
    }

    #[test]
    fn embedded_nuls_are_removed_before_name_classification() {
        assert!(is_xss(b"<a on\0error=1>", Context::Data));
        assert!(is_xss(b"<sv\0gload>", Context::Data));
        assert!(is_xss(b"<a xm\0lns=1>", Context::Data));
        assert!(is_xss(b"href=ja\0va:", Context::ValueNoQuote));
        assert!(is_xss(b"<?im\0port namespace=\"t\">", Context::Data));
        assert!(is_xss(b"<!EN\0TITY x SYSTEM \"file:///etc/passwd\">", Context::Data));
    }

    #[test]
    fn decodes_numeric_entities() {
        assert_eq!(html_decode_char_at(b""), None);
        assert_eq!(html_decode_char_at(b"a"), Some((u32::from(b'a'), 1)));
        assert_eq!(html_decode_char_at(b"&#65;x"), Some((65, 5)));
        assert_eq!(html_decode_char_at(b"&#65x"), Some((65, 4)));
        assert_eq!(html_decode_char_at(b"&#65"), Some((65, 4)));
        assert_eq!(html_decode_char_at(b"&#x41;"), Some((0x41, 6)));
        assert_eq!(html_decode_char_at(b"&#X4a"), Some((0x4A, 5)));
        // Named entities and malformed ones are a plain '&'.
        assert_eq!(html_decode_char_at(b"&amp;"), Some((u32::from(b'&'), 1)));
        assert_eq!(html_decode_char_at(b"&#;"), Some((u32::from(b'&'), 1)));
        assert_eq!(html_decode_char_at(b"&#xg"), Some((u32::from(b'&'), 1)));
        assert_eq!(html_decode_char_at(b"&#99999999;"), Some((u32::from(b'&'), 1)));
        // Too short to be an entity.
        assert_eq!(html_decode_char_at(b"&#"), Some((u32::from(b'&'), 1)));
        assert_eq!(html_decode_char_at(b"&#x"), Some((u32::from(b'&'), 1)));
    }

    #[test]
    fn url_schemes() {
        assert!(is_black_url(b"javascript:alert(1)"));
        assert!(is_black_url(b"  \xa0JaVa\0Script:alert(1)"));
        assert!(is_black_url(b"&#106;ava\nscript:"));
        assert!(is_black_url(b"&#x144;ata:"));
        assert!(!is_black_url(b"https://example.com/java"));
        assert!(!is_black_url(b""));
    }
}
