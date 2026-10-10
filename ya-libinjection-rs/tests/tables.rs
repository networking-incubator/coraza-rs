//! The tables ported from libinjection, compared with the upstream sources
//! vendored in `tests/upstream/src`: the generated ones (see
//! `tools/gen_tables.py`) and the ones copied by hand.

mod common;

use libperfusion::internals::sqli::{Parser, SQL_KEYWORDS};
use libperfusion::internals::xss::{Attribute, BLACK_ATTR_EVENTS, BLACK_ATTRS, BLACK_TAGS};

/// The body of the C array introduced by `declaration`, comments removed.
fn c_array_body(source: &str, declaration: &str) -> String {
    let start = source
        .find(declaration)
        .unwrap_or_else(|| panic!("no `{declaration}` upstream"))
        + declaration.len();
    let len = source[start..].find("};").expect("unterminated array");
    let mut body = &source[start..start + len];

    let mut stripped = String::new();
    while let Some(open) = body.find("/*") {
        stripped.push_str(&body[..open]);
        let close = body[open..].find("*/").expect("unterminated comment");
        body = &body[open + close + 2..];
    }
    stripped + body
}

/// The quoted strings of a C array body, each with the text that follows
/// it up to the next string.
fn c_strings(body: &str) -> Vec<(&str, &str)> {
    let parts: Vec<&str> = body.split('"').skip(1).collect();
    parts.chunks(2).map(|pair| (pair[0], pair[1])).collect()
}

#[test]
fn sql_keywords() {
    let source = common::upstream_source("src/libinjection_sqli_data.h");
    let body = c_array_body(&source, "sql_keywords[] = {");
    // Each entry reads `{"WORD", 't'},`.
    let upstream: Vec<(&str, u8)> = body
        .lines()
        .filter_map(|line| line.trim().strip_prefix("{\"")?.strip_suffix("'},"))
        .map(|entry| {
            let (word, ty) = entry.rsplit_once("\", '").unwrap();
            (word, ty.as_bytes()[0])
        })
        .collect();

    let table: Vec<(&str, u8)> = SQL_KEYWORDS
        .iter()
        .map(|&(word, ty)| (word, ty.as_byte()))
        .collect();
    assert!(
        table == upstream,
        "src/sqli/keyword_table.rs is out of date"
    );
}

#[test]
fn sql_char_dispatch() {
    let source = common::upstream_source("src/libinjection_sqli_data.h");
    let body = c_array_body(&source, "char_parse_map[] = {");
    // Each entry reads `&parse_white,`, in byte order.
    let upstream: Vec<&str> = body
        .lines()
        .filter_map(|line| line.trim().strip_prefix("&parse_")?.strip_suffix(','))
        .collect();
    assert_eq!(upstream.len(), 256);

    for (byte, name) in (0..=u8::MAX).zip(upstream) {
        let parser = Parser::for_byte(byte);
        if let Parser::Char(ty) = parser {
            assert_eq!((name, ty.as_byte()), ("char", byte));
        } else {
            assert_eq!(format!("{parser:?}").to_lowercase(), name, "byte {byte}");
        }
    }
}

#[test]
fn xss_event_handlers() {
    let source = common::upstream_source("src/libinjection_xss.c");
    let body = c_array_body(&source, "BLACKATTREVENT[] = {");
    let events: Vec<&str> = c_strings(&body).into_iter().map(|(name, _)| name).collect();
    assert!(
        BLACK_ATTR_EVENTS[..] == events[..],
        "src/xss/events.rs is out of date"
    );
}

#[test]
fn xss_attributes() {
    let source = common::upstream_source("src/libinjection_xss.c");
    let body = c_array_body(&source, " BLACKATTR[] = {");
    // Each entry reads `{"NAME", TYPE_ATTR_URL},`.
    let attrs: Vec<(&str, Attribute)> = c_strings(&body)
        .into_iter()
        .map(|(name, rest)| {
            let ty = rest
                .trim_start_matches(|c: char| c == ',' || c.is_whitespace())
                .split('}')
                .next()
                .unwrap();
            let attribute = match ty {
                "TYPE_BLACK" => Attribute::Black,
                "TYPE_ATTR_URL" => Attribute::Url,
                "TYPE_STYLE" => Attribute::Style,
                "TYPE_ATTR_INDIRECT" => Attribute::Indirect,
                other => panic!("unknown attribute type {other}"),
            };
            (name, attribute)
        })
        .collect();
    assert_eq!(BLACK_ATTRS[..], attrs[..]);
}

#[test]
fn xss_tags() {
    let source = common::upstream_source("src/libinjection_xss.c");
    let body = c_array_body(&source, "BLACKTAG[] = {");
    let tags: Vec<&str> = c_strings(&body).into_iter().map(|(name, _)| name).collect();
    assert_eq!(BLACK_TAGS[..], tags[..]);
}
