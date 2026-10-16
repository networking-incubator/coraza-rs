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
//! The tables ported from libinjection, compared with the upstream sources

//! selected by `LIBINJECTION_DIR`: the build-generated ones and the tables
//! kept in the local canonical data files.

#![expect(
    clippy::tests_outside_test_module,
    reason = "Cargo integration test targets consist of tests."
)]
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    reason = "Table checks fail fast when the pinned upstream source is malformed."
)]

#[path = "upstream_common.rs"]
mod common;

use libperfusion::internals::tables::{Attribute, BLACK_ATTR_EVENTS, BLACK_ATTRS, BLACK_TAGS, Parser, SQL_KEYWORDS};

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
    stripped.push_str(body);
    stripped
}

/// The quoted strings of a C array body, each with the text that follows
/// it up to the next string.
fn c_strings(body: &str) -> Vec<(&str, &str)> {
    let parts: Vec<&str> = body.split('"').skip(1).collect();
    parts.chunks(2).map(|pair| (pair[0], pair[1])).collect()
}

/// The non-comment rows of a canonical data file, split on tabs.
///
/// Reads the files the way `build.rs` and `xtask` both do: a trailing `\r`
/// is accepted, any other surrounding whitespace is an error rather than
/// something to trim. Three readers parse these files -- the build script
/// that compiles them in, `xtask` that hashes them, and this test -- so the
/// rule has to be one rule.
fn data_rows(name: &str) -> Vec<Vec<String>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("data").join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        assert_eq!(line.trim(), line, "{name}: surrounding whitespace in row {line:?}");
        rows.push(line.split('\t').map(str::to_owned).collect());
    }
    rows
}

/// `build.rs` merges the upstream-generated tables with the local
/// supplements, so a `tables-refresh` that rewrites only the upstream files
/// must not drop the local rows.
#[test]
fn local_supplements_are_merged_into_the_generated_tables() {
    let sql_local = data_rows("sqli_keywords_local.txt");
    assert!(!sql_local.is_empty(), "no local SQL rows to merge");
    for row in &sql_local {
        let (key, value) = (row[0].as_str(), row[1].as_str());
        let found = SQL_KEYWORDS
            .iter()
            .find(|&&(word, _)| word == key)
            .unwrap_or_else(|| panic!("local SQL row {key} is missing from the generated table"));
        assert_eq!(String::from_utf8(vec![found.1.as_byte()]).unwrap(), value, "{key}");
    }
    for row in data_rows("sqli_keywords.txt") {
        assert!(
            SQL_KEYWORDS.iter().any(|&(word, _)| word == row[0]),
            "upstream SQL row {} is missing from the generated table",
            row[0]
        );
    }
    // The lookup hash table and upstream's binary search both need this.
    assert!(
        SQL_KEYWORDS.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "the merged SQL table is not sorted or has duplicates"
    );

    // Exactly the two files merged, nothing else. `data_rows` reads them
    // under the same whitespace rule `build.rs` applies, so a build script
    // that drifted from it -- keeping a leading space in a key, or taking an
    // indented `#` line for a row -- shows up here as a table that is not
    // what the files say.
    let mut expected: Vec<(String, String)> = data_rows("sqli_keywords.txt")
        .into_iter()
        .chain(sql_local.clone())
        .map(|row| (row[0].clone(), row[1].clone()))
        .collect();
    expected.sort();
    let generated: Vec<(String, String)> = SQL_KEYWORDS
        .iter()
        .map(|&(word, kind)| (word.to_owned(), String::from_utf8(vec![kind.as_byte()]).unwrap()))
        .collect();
    assert_eq!(
        generated, expected,
        "the generated SQL table is not exactly the upstream and local files merged"
    );

    let xss_local = data_rows("xss_tables_local.txt");
    assert!(!xss_local.is_empty(), "no local XSS rows to merge");
    for row in &xss_local {
        match row[0].as_str() {
            "tag" => assert!(BLACK_TAGS.contains(&row[1].as_str()), "local tag {} is missing", row[1]),
            "event" => assert!(
                BLACK_ATTR_EVENTS.contains(&row[1].as_str()),
                "local event {} is missing",
                row[1]
            ),
            "attr" => {
                let attribute = match row[2].as_str() {
                    "Black" => Attribute::Black,
                    "Url" => Attribute::Url,
                    "Style" => Attribute::Style,
                    "Indirect" => Attribute::Indirect,
                    other => panic!("unknown attribute type {other}"),
                };
                assert!(
                    BLACK_ATTRS.contains(&(row[1].as_str(), attribute)),
                    "local attribute {} is missing",
                    row[1]
                );
            },
            other => panic!("unknown local XSS row kind {other}"),
        }
    }
    // The upstream rows come first, so the local ones only extend each table.
    let upstream_xss = data_rows("xss_tables.txt");
    let upstream_tags = upstream_xss.iter().filter(|row| row[0] == "tag").count();
    let upstream_attrs = upstream_xss.iter().filter(|row| row[0] == "attr").count();
    assert_eq!(
        BLACK_TAGS.len(),
        upstream_tags + xss_local.iter().filter(|r| r[0] == "tag").count()
    );
    assert_eq!(
        BLACK_ATTRS.len(),
        upstream_attrs + xss_local.iter().filter(|r| r[0] == "attr").count()
    );
}

#[test]
#[ignore = "exact table comparison; requires upstream sources via LIBINJECTION_DIR"]
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

    // The generated table merges the local supplement in, so compare only
    // the upstream-derived rows; the merge itself is checked above.
    let local: Vec<String> = data_rows("sqli_keywords_local.txt")
        .into_iter()
        .map(|row| row[0].clone())
        .collect();
    let table: Vec<(&str, u8)> = SQL_KEYWORDS
        .iter()
        .filter(|&&(word, _)| !local.iter().any(|key| key == word))
        .map(|&(word, ty)| (word, ty.as_byte()))
        .collect();
    assert!(table == upstream, "src/sqli/keyword_table.rs is out of date");
}

#[test]
#[ignore = "exact table comparison; requires upstream sources via LIBINJECTION_DIR"]
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
#[ignore = "exact table comparison; requires upstream sources via LIBINJECTION_DIR"]
fn xss_event_handlers() {
    let source = common::upstream_source("src/libinjection_xss.c");
    let body = c_array_body(&source, "BLACKATTREVENT[] = {");
    let events: Vec<&str> = c_strings(&body).into_iter().map(|(name, _)| name).collect();
    // Local supplement rows are appended after the upstream ones.
    assert!(
        BLACK_ATTR_EVENTS[..events.len()] == events[..],
        "src/xss/events.rs is out of date"
    );
}

#[test]
#[ignore = "exact table comparison; requires upstream sources via LIBINJECTION_DIR"]
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
    assert_eq!(BLACK_ATTRS[..attrs.len()], attrs[..]);
}

#[test]
#[ignore = "exact table comparison; requires upstream sources via LIBINJECTION_DIR"]
fn xss_tags() {
    let source = common::upstream_source("src/libinjection_xss.c");
    let body = c_array_body(&source, "BLACKTAG[] = {");
    let tags: Vec<&str> = c_strings(&body).into_iter().map(|(name, _)| name).collect();
    assert_eq!(BLACK_TAGS[..tags.len()], tags[..]);
}
