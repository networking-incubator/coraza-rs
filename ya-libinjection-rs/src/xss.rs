//! Cross-site scripting detection: tokenize the input as HTML5 in each of
//! the contexts it could be injected into, and look for tags, attributes
//! and URLs that can run script.

pub(crate) mod events;

use self::events::BLACK_ATTR_EVENTS;
use crate::html5::{Context, TokenKind, Tokenizer};

/// Why an attribute is of interest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attribute {
    /// Always banned.
    Black,
    /// Its value is a URL-like object.
    Url,
    Style,
    /// Its value names another attribute.
    Indirect,
}

pub const BLACK_ATTRS: [(&str, Attribute); 20] = [
    ("ACTION", Attribute::Url),             // form
    ("ATTRIBUTENAME", Attribute::Indirect), // SVG allows indirection of attribute names
    ("BY", Attribute::Url),                 // SVG
    ("BACKGROUND", Attribute::Url),         // IE6, O11
    ("DATAFORMATAS", Attribute::Black),     // IE
    ("DATASRC", Attribute::Black),          // IE
    ("DYNSRC", Attribute::Url),             // obsolete img attribute
    ("FILTER", Attribute::Style),           // Opera, SVG inline style
    ("FORMACTION", Attribute::Url),         // HTML 5
    ("FOLDER", Attribute::Url),             // only on A tags, IE-only
    ("FROM", Attribute::Url),               // SVG
    ("HANDLER", Attribute::Url),            // SVG Tiny, Opera
    ("HREF", Attribute::Url),
    ("LOWSRC", Attribute::Url), // obsolete img attribute
    ("POSTER", Attribute::Url), // Opera 10, 11
    ("SRC", Attribute::Url),
    ("STYLE", Attribute::Style),
    ("TO", Attribute::Url),     // SVG
    ("VALUES", Attribute::Url), // SVG
    ("XLINK:HREF", Attribute::Url),
];

pub const BLACK_TAGS: [&str; 20] = [
    "APPLET", "BASE", "COMMENT", // IE, http://html5sec.org/#38
    "EMBED", "FRAME", "FRAMESET", "HANDLER", // Opera SVG, effectively a script tag
    "IFRAME", "IMPORT", "ISINDEX", "LINK", "LISTENER", "META", "NOSCRIPT", "OBJECT", "SCRIPT",
    "STYLE", "VMLFRAME", "XML", "XSS",
];

/// URL schemes that can run script. "JAVA" covers `java:` and `javascript:`.
const BLACK_URL_SCHEMES: [&[u8]; 4] = [b"DATA", b"VIEW-SOURCE", b"JAVA", b"VBSCRIPT"];

/// Upstream's `cstrcasecmp_with_null`: whether `b`, with its NULs dropped
/// and upper-cased, is exactly the upper-case string `a`.
fn eq_ignoring_nulls(a: &[u8], b: &[u8]) -> bool {
    let mut a = a.iter();
    for cb in b.iter().filter(|&&cb| cb != 0) {
        if a.next() != Some(&cb.to_ascii_uppercase()) {
            return false;
        }
    }
    a.next().is_none()
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
    BLACK_TAGS
        .iter()
        .any(|tag| eq_ignoring_nulls(tag.as_bytes(), name))
        // Anything SVG or XSL(T) related.
        || name[..3].eq_ignore_ascii_case(b"svg")
        || name[..3].eq_ignore_ascii_case(b"xsl")
}

fn black_attr(name: &[u8]) -> Option<Attribute> {
    if name.len() < 2 {
        return None;
    }

    if name.len() >= 5 {
        // JavaScript on.* event handlers: the name after "on" only has to
        // start with a known event.
        if name[..2].eq_ignore_ascii_case(b"on") {
            let event = &name[2..];
            let is_event = BLACK_ATTR_EVENTS.iter().any(|known| {
                let len = event.len().min(known.len());
                eq_ignoring_nulls(known.as_bytes(), &event[..len])
            });
            if is_event {
                return Some(Attribute::Black);
            }
        }

        // XMLNS can be used to create arbitrary tags.
        if eq_ignoring_nulls(b"XMLNS", &name[..5]) || eq_ignoring_nulls(b"XLINK", &name[..5]) {
            return Some(Attribute::Black);
        }
    }

    BLACK_ATTRS
        .iter()
        .find(|(known, _)| eq_ignoring_nulls(known.as_bytes(), name))
        .map(|&(_, attribute)| attribute)
}

fn is_black_url(url: &[u8]) -> bool {
    // Skip whitespace, and high-bit bytes with it: they are not ASCII, Opera
    // sometimes takes UTF-8 whitespace, and EUC-JP ignores some of them.
    let start = url
        .iter()
        .position(|&ch| ch > 32 && ch < 127)
        .unwrap_or(url.len());
    let url = &url[start..];

    BLACK_URL_SCHEMES
        .iter()
        .any(|scheme| htmlencode_startswith(scheme, url))
}

pub fn is_xss(input: &[u8], context: Context) -> bool {
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
            }
            TokenKind::AttrName => attr = black_attr(text),
            TokenKind::AttrValue => {
                let is_black = match attr.take() {
                    None => false,
                    Some(Attribute::Black | Attribute::Style) => true,
                    Some(Attribute::Url) => is_black_url(text),
                    // An attribute name is given in a _value_.
                    Some(Attribute::Indirect) => black_attr(text).is_some(),
                };
                if is_black {
                    return true;
                }
            }
            TokenKind::TagComment => {
                // IE uses a "`" as a tag ending char.
                if text.contains(&b'`') {
                    return true;
                }

                // IE conditional comments, and XML processing instructions.
                if text.len() > 3
                    && (text[..3].eq_ignore_ascii_case(b"[if")
                        || text[..3].eq_ignore_ascii_case(b"xml"))
                {
                    return true;
                }

                // IE's <?import pseudo-tag, and XML entity definitions.
                if text.len() > 5
                    && (eq_ignoring_nulls(b"IMPORT", &text[..6])
                        || eq_ignoring_nulls(b"ENTITY", &text[..6]))
                {
                    return true;
                }
            }
            TokenKind::DataText
            | TokenKind::TagNameClose
            | TokenKind::TagNameSelfClose
            | TokenKind::TagClose => {}
        }
    }
    false
}

pub(crate) fn detect(input: &[u8]) -> bool {
    [
        Context::Data,
        Context::ValueNoQuote,
        Context::ValueSingleQuote,
        Context::ValueDoubleQuote,
        Context::ValueBackQuote,
    ]
    .into_iter()
    .any(|context| is_xss(input, context))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_numeric_entities() {
        assert_eq!(html_decode_char_at(b""), None);
        assert_eq!(html_decode_char_at(b"a"), Some((u32::from(b'a'), 1)));
        assert_eq!(html_decode_char_at(b"&#65;x"), Some((65, 5)));
        assert_eq!(html_decode_char_at(b"&#65x"), Some((65, 4)));
        assert_eq!(html_decode_char_at(b"&#65"), Some((65, 4)));
        assert_eq!(html_decode_char_at(b"&#x41;"), Some((0x41, 6)));
        assert_eq!(html_decode_char_at(b"&#X4a"), Some((0x4a, 5)));
        // Named entities and malformed ones are a plain '&'.
        assert_eq!(html_decode_char_at(b"&amp;"), Some((u32::from(b'&'), 1)));
        assert_eq!(html_decode_char_at(b"&#;"), Some((u32::from(b'&'), 1)));
        assert_eq!(html_decode_char_at(b"&#xg"), Some((u32::from(b'&'), 1)));
        assert_eq!(
            html_decode_char_at(b"&#99999999;"),
            Some((u32::from(b'&'), 1))
        );
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
