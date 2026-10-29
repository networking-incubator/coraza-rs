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
    bytes::{contains, find_byte},
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
#[expect(
    clippy::indexing_slicing,
    reason = "Const initializer: loop bound guards BLACK_ATTR_EVENTS[i]; events are non-empty \
              &str so .as_bytes()[0] is valid; letter is uppercase ASCII minus b'A' (0..=25) \
              indexing [(_, _); 26]."
)]
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
const BLACK_URL_SCHEMES: [&[u8]; 6] = [
    b"DATA",
    b"VIEW-SOURCE",
    b"JAVA",
    b"VBSCRIPT",
    // Script-capable only in narrow circumstances, but cheap to cover: the
    // scan is linear over six entries.
    b"BLOB",
    b"FILESYSTEM",
];

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
/// Numeric entities are decoded, decimal (`&#65;`) or hexadecimal
/// (`&#x41;`), with or without the closing ';'. The handful of named
/// entities that can smuggle a URL scheme past a prefix comparison are
/// decoded too; any other named entity is the byte it starts with.
///
/// Full HTML5 named-entity support (2 231 entries) is deliberately not
/// provided: it would add meaningful table weight to the Wasm artifact for
/// references that cannot change a scheme match.
fn html_decode_char_at(src: &[u8]) -> Option<(u32, usize)> {
    const AMPERSAND: (u32, usize) = (b'&' as u32, 1);
    /// Above this, the entity is given up on and read as a plain '&'.
    const MAX: u32 = 0x0010_00FF;
    /// Named references a browser honours inside an attribute value, which
    /// therefore split a scheme such as `ja&Tab;vascript:`.
    ///
    /// Matched case-sensitively, with the exact spelling the HTML standard
    /// defines, because named references are case-sensitive and the case
    /// variants are different characters or nothing at all: `&colon;` is
    /// `:` but `&Colon;` is `∷` (U+2237), and `&tab;` is not a reference.
    /// Decoding those as `:` and tab reported schemes a browser does not
    /// see. `&NUL;` is likewise absent: the standard does not define it.
    const NAMED: [(&[u8], u32); 4] = [(b"Tab;", 0x09), (b"NewLine;", 0x0A), (b"colon;", 0x3A), (b"sol;", 0x2F)];

    let &first = src.first()?;
    let is_hex = matches!(src.get(2), Some(b'x' | b'X'));
    if first != b'&' || src.len() < 3 || (is_hex && src.len() < 4) {
        return Some((u32::from(first), 1));
    }
    if src.get(1) != Some(&b'#') {
        // The scan stays O(1): the table is four entries and the longest
        // name bounds how far each comparison reads.
        let rest = src.get(1..).unwrap_or_default();
        for (name, value) in NAMED {
            let Some(candidate) = rest.get(..name.len()) else {
                continue;
            };
            if candidate == name {
                return Some((value, name.len() + 1));
            }
        }
        return Some(AMPERSAND);
    }

    let (radix, digits_at) = if is_hex { (16, 3) } else { (10, 2) };
    let digit = |ch: u8| char::from(ch).to_digit(radix);

    // The degenerate "&#?" has no digit at all.
    let Some(mut val) = src.get(digits_at).and_then(|&ch| digit(ch)) else {
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
        src = src.get(consumed..).unwrap_or_default();

        if first && cb <= 32 {
            continue;
        }
        first = false;

        // Browsers strip tab and newlines while parsing a URL, so they do
        // not break a scheme: "java&Tab;script:" runs. NUL is skipped for
        // the same reason upstream skips it.
        if matches!(cb, 0 | 9 | 10 | 13) {
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
    let name = normalized.get(..len).unwrap_or_default();
    BLACK_TAGS.iter().any(|tag| name == tag.as_bytes())
        // Anything SVG or XSL(T) related.
        || name.starts_with(b"SVG")
        || name.starts_with(b"XSL")
}

/// Which `(first letter, length)` shapes [`BLACK_ATTRS`] contains, one
/// bitmap of lengths per letter.
///
/// [`BLACK_ATTRS`] is scanned linearly because it has to stay in table
/// order: `tests/tables.rs` pins the upstream rows ahead of the local
/// supplement. That makes the cost of every miss proportional to the table
/// length, and the supplement made the table half again as long. A name
/// whose shape is absent cannot be in the table, so this skips the scan and
/// keeps the miss path -- which is every ordinary attribute in ordinary
/// markup -- independent of how many rows the table has.
#[expect(
    clippy::indexing_slicing,
    reason = "Const initializer: the loop bound guards BLACK_ATTRS[i]; names are non-empty \
              upper-case ASCII &str, so .as_bytes()[0] - b'A' is 0..=25 and indexes [u64; 26]. \
              A name outside A-Z or longer than 63 bytes fails to compile."
)]
static ATTR_NAME_SHAPES: [u64; 26] = {
    let mut shapes = [0_u64; 26];
    let mut i = 0;
    while i < BLACK_ATTRS.len() {
        let name = BLACK_ATTRS[i].0.as_bytes();
        shapes[(name[0] - b'A') as usize] |= 1 << name.len();
        i += 1;
    }
    shapes
};

/// Whether [`BLACK_ATTRS`] holds any name of `name`'s letter and length.
fn attr_shape_present(name: &[u8]) -> bool {
    let Some(index) = name.first().and_then(|first| first.checked_sub(b'A')) else {
        return false;
    };
    let Some(&lengths) = ATTR_NAME_SHAPES.get(usize::from(index)) else {
        return false;
    };
    name.len() < u64::BITS as usize && lengths & (1_u64 << name.len()) != 0
}

fn black_attr(name: &[u8]) -> Option<Attribute> {
    let mut normalized = [0; MAX_NORMALIZED_TOKEN_LEN];
    let len = normalize_name(name, &mut normalized)?;
    let name = normalized.get(..len).unwrap_or_default();
    if name.len() < 2 {
        return None;
    }

    if name == b"XMLNS" || name == b"XLINK" {
        return Some(Attribute::Black);
    }

    if name.len() >= 5 && name.starts_with(b"ON") {
        let event = name.get(2..).unwrap_or_default();
        if let Some(&first) = event.first()
            && first.is_ascii_uppercase()
            && let Some(&(start, end)) = EVENT_SPANS.get(usize::from(first - b'A'))
            && BLACK_ATTR_EVENTS
                .get(start..end)
                .is_some_and(|events| events.iter().any(|known| event == known.as_bytes()))
        {
            return Some(Attribute::Black);
        }
    }

    if !attr_shape_present(name) {
        return None;
    }

    BLACK_ATTRS
        .iter()
        .find(|(known, _)| name == known.as_bytes())
        .map(|&(_, attribute)| attribute)
}

/// Schemes that run script from a CSS `url()`.
///
/// `DATA` is deliberately excluded: `url(data:image/png;base64,...)` is
/// ordinary stylesheet content, so treating it as script here would flag
/// benign CSS.
///
/// Each prefix carries its `:`. [`is_black_url`] can match the bare `JAVA`
/// because an HTML URL attribute holds nothing but a URL, so a relative
/// path never reaches it as a scheme to classify; a CSS `url()` does take
/// relative paths, and matching a bare scheme name flagged
/// `url(java-logo.png)`.
const SCRIPT_URL_SCHEMES: [&[u8]; 3] = [b"JAVASCRIPT:", b"VBSCRIPT:", b"VIEW-SOURCE:"];

/// Constructs that execute script from inside a CSS declaration.
///
/// The HTML contexts only see a value once it is inside a tag, so a value
/// reflected straight into a `style="..."` attribute or a `<style>` block is
/// invisible to them: `<div style="x:expression(alert(1))">` is detected but
/// the bare `x:expression(alert(1))` is not. The patterns here are the ones
/// with no benign reading in a stylesheet.
pub(crate) fn is_css_value_xss(input: &[u8]) -> bool {
    const NEEDLES: [&[u8]; 3] = [b"EXPRESSION(", b"-MOZ-BINDING", b"BEHAVIOR:"];

    if NEEDLES.iter().any(|needle| starts_an_identifier(input, needle)) {
        return true;
    }

    // url(...) holding a script-capable scheme, allowing for the whitespace
    // and quoting CSS permits between the paren and the scheme.
    let mut from = 0;
    while let Some(at) = find_ascii_case_insensitive(input.get(from..).unwrap_or_default(), b"URL(") {
        let after = from.saturating_add(at).saturating_add(4);
        let rest = input.get(after..).unwrap_or_default();
        let start = rest
            .iter()
            .position(|&byte| !byte.is_ascii_whitespace() && byte != b'\'' && byte != b'"')
            .unwrap_or(rest.len());
        let value = rest.get(start..).unwrap_or_default();
        if SCRIPT_URL_SCHEMES
            .iter()
            .any(|scheme| htmlencode_startswith(scheme, value))
        {
            return true;
        }
        from = after;
    }
    false
}

/// Whether `input` holds `needle` at the start of a CSS identifier.
///
/// These needles are property names and function names, so a match that
/// continues an identifier is a *different* name: `scroll-behavior:smooth`
/// and `overscroll-behavior:contain` both contain `BEHAVIOR:`, and neither
/// runs script. Every occurrence is tried, so a real one later in the value
/// is still found -- `scroll-behavior:smooth;behavior:url(#x)` flags.
fn starts_an_identifier(input: &[u8], needle: &[u8]) -> bool {
    let mut from = 0;
    while let Some(at) = find_ascii_case_insensitive(input.get(from..).unwrap_or_default(), needle) {
        let at = from.saturating_add(at);
        let continues_identifier = at
            .checked_sub(1)
            .and_then(|before| input.get(before))
            .copied()
            .is_some_and(is_css_identifier_byte);
        if !continues_identifier {
            return true;
        }
        from = at.saturating_add(1);
    }
    false
}

/// Whether `byte` can appear inside a CSS identifier.
///
/// CSS identifiers run over letters, digits, `-`, `_`, and everything
/// non-ASCII; the escape forms cannot produce one of these needles without
/// also producing one of these bytes first.
const fn is_css_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte >= 0x80
}

/// Finds `needle` in `haystack`, comparing ASCII case-insensitively.
fn find_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len().saturating_sub(needle.len())).find(|&at| {
        haystack
            .get(at..at.saturating_add(needle.len()))
            .is_some_and(|window| window.eq_ignore_ascii_case(needle))
    })
}

/// The upper-case first letters of [`BLACK_URL_SCHEMES`], as an A-Z bitmap.
#[expect(
    clippy::indexing_slicing,
    reason = "Const initializer: the loop bound guards BLACK_URL_SCHEMES[i]; every scheme is a \
              non-empty upper-case ASCII literal, so [0] - b'A' is 0..=25. A scheme outside A-Z \
              fails to compile."
)]
const SCHEME_FIRST_LETTERS: u32 = {
    let mut letters = 0_u32;
    let mut i = 0;
    while i < BLACK_URL_SCHEMES.len() {
        letters |= 1 << (BLACK_URL_SCHEMES[i][0] - b'A');
        i += 1;
    }
    letters
};

fn is_black_url(url: &[u8]) -> bool {
    // Skip whitespace, and high-bit bytes with it: they are not ASCII, Opera
    // sometimes takes UTF-8 whitespace, and EUC-JP ignores some of them.
    let start = url.iter().position(|&ch| ch > 32 && ch < 127).unwrap_or(url.len());
    let url = url.get(start..).unwrap_or_default();

    // Every scheme comparison restarts the entity decoder, so a URL that
    // cannot begin any of them is worth ruling out once. Only a literal
    // first byte can be judged here: `&` may decode to any letter, and the
    // bytes `htmlencode_startswith` skips were removed just above.
    match url.first() {
        None => return false,
        Some(&b'&') => {},
        Some(&first) => {
            let letter = first.to_ascii_uppercase().wrapping_sub(b'A');
            if letter >= 26 || SCHEME_FIRST_LETTERS & (1 << letter) == 0 {
                return false;
            }
        },
    }

    BLACK_URL_SCHEMES
        .iter()
        .any(|scheme| htmlencode_startswith(scheme, url))
}

/// Check one context, also trying a NUL-as-space reading when the input has NULs.
///
/// The tokenizer keeps NUL inside attribute names and unquoted values so
/// `black_attr` can fold `on\0error` to `onerror`. That same reading hides
/// `<a href=x\0onerror=...>`, where C treats the NUL as whitespace and sees a new
/// attribute. Trying both readings is a superset of either engine's detection.
pub(crate) fn is_xss(input: &[u8], context: Context, data_start: Option<usize>) -> bool {
    if is_xss_raw(input, context, data_start, false) {
        return true;
    }
    input.contains(&0) && is_xss_raw(input, context, data_start, true)
}

fn is_xss_raw(input: &[u8], context: Context, data_start: Option<usize>, nul_as_space: bool) -> bool {
    let mut attr = None;
    let mut tokenizer = match context {
        Context::Data => {
            // Plain text before the first tag cannot affect Data-context detection.
            let Some(start) = data_start.or_else(|| {
                if input.first() == Some(&b'<') {
                    Some(0)
                } else {
                    find_byte(input, 0, b'<')
                }
            }) else {
                return false;
            };
            if nul_as_space {
                Tokenizer::new_data_at_nul_as_space(input, start)
            } else {
                Tokenizer::new_data_at(input, start)
            }
        },
        _ if nul_as_space => Tokenizer::new_nul_as_space(input, context),
        _ => Tokenizer::new(input, context),
    };
    for token in &mut tokenizer {
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
                if text.len() > 3
                    && text
                        .get(..3)
                        .is_some_and(|p| p.eq_ignore_ascii_case(b"[if") || p.eq_ignore_ascii_case(b"xml"))
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
    let data_start = if input.first() == Some(&b'<') {
        Some(0)
    } else {
        find_byte(input, 0, b'<')
    };
    if let Some(start) = data_start
        && is_xss(input, Context::Data, Some(start))
    {
        return Some(Context::Data);
    }
    if is_xss(input, Context::ValueNoQuote, None) {
        return Some(Context::ValueNoQuote);
    }

    for (quote, context) in [
        (b'\'', Context::ValueSingleQuote),
        (b'"', Context::ValueDoubleQuote),
        (b'`', Context::ValueBackQuote),
    ] {
        if find_byte(input, 0, quote).is_some() && is_xss(input, context, None) {
            return Some(context);
        }
    }
    None
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "Test assertions index known-valid table entries and fixed-size buffers."
)]
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
            assert!(name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic), "{name}");
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
        assert!(!is_xss(b"<p attributeName=\"\0\xff\x80\">", Context::Data, None));
        assert!(is_xss(b"<p attributeName=onload>", Context::Data, None));
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
        .find(|&context| is_xss(input, context, None))
    }

    #[test]
    fn context_pruning_preserves_priority_and_results() {
        const ALPHABET: &[u8] = b"<> '\"`= on\0";

        let attack = b"\"onclick=x'onerror=y";
        assert!(!is_xss(attack, Context::Data, None));
        assert!(!is_xss(attack, Context::ValueNoQuote, None));
        assert!(is_xss(attack, Context::ValueDoubleQuote, None));
        assert!(is_xss(attack, Context::ValueSingleQuote, None));
        // The double quote is encountered first, but the single-quote context
        // still has priority in the original context sequence.
        assert_eq!(detect_with_context(attack), Some(Context::ValueSingleQuote));

        assert_eq!(detect_with_context(b"onload=x"), Some(Context::ValueNoQuote));
        assert_eq!(detect_with_context(b"'onerror=x"), Some(Context::ValueSingleQuote));
        assert_eq!(detect_with_context(b"\"onclick=x"), Some(Context::ValueDoubleQuote));
        assert_eq!(detect_with_context(b"`onclick=x"), Some(Context::ValueBackQuote));
        assert_eq!(detect_with_context(b"hello world"), None);
        assert!(!is_xss(b"plain text", Context::Data, None));
        assert!(is_xss(b"plain text <script>alert(1)</script>", Context::Data, None));
        // C treats NUL as whitespace here, so the event attribute starts a new token.
        assert!(is_xss(b"<a href=x\0onerror=alert(1)>", Context::Data, None));
        assert_eq!(detect_with_context(b"prefix <script>"), Some(Context::Data));

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
        assert!(is_xss(b"<a attributename=onclick>", Context::Data, None));
        assert!(!is_xss(b"<a attributename=href>", Context::Data, None));
        assert!(!is_xss(b"<a attributename=style>", Context::Data, None));
    }

    #[test]
    fn embedded_nuls_are_removed_before_name_classification() {
        assert!(is_xss(b"<a on\0error=1>", Context::Data, None));
        assert!(is_xss(b"<sv\0gload>", Context::Data, None));
        assert!(is_xss(b"<a xm\0lns=1>", Context::Data, None));
        assert!(is_xss(b"href=ja\0va:", Context::ValueNoQuote, None));
        assert!(is_xss(b"<?im\0port namespace=\"t\">", Context::Data, None));
        assert!(is_xss(
            b"<!EN\0TITY x SYSTEM \"file:///etc/passwd\">",
            Context::Data,
            None
        ));
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
