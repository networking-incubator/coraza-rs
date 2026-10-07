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

//! Corpus driver output formatting (Go encoding).
use std::{fs, path::Path};

use libinjection::{
    Html5TokenKind, SqliTokenInfo, XssHtmlContext, detect_sqli, detect_xss, html5_visit, sqli_fold_visit,
    sqli_tokenize_visit,
};

use super::corpus::{DriverKind, parse_corpus_file};

fn html5_type_label(kind: Html5TokenKind) -> &'static str {
    match kind {
        Html5TokenKind::DataText => "DATA_TEXT",
        Html5TokenKind::TagNameOpen => "TAG_NAME_OPEN",
        Html5TokenKind::TagNameClose => "TAG_NAME_CLOSE",
        Html5TokenKind::TagNameSelfClose => "TAG_NAME_SELFCLOSE",
        Html5TokenKind::TagClose => "TAG_CLOSE",
        Html5TokenKind::AttrName => "ATTR_NAME",
        Html5TokenKind::AttrValue => "ATTR_VALUE",
        Html5TokenKind::TagComment => "TAG_COMMENT",
        Html5TokenKind::DocType => "DOCTYPE",
    }
}

/// Go `IsXSS` corpus encoding: detected -> `"1"`, else `"0"`.
#[must_use]
pub(crate) fn format_xss_expected(detected: bool) -> &'static str {
    if detected { "1" } else { "0" }
}

/// Go `SQLi` corpus encoding: fingerprint text, or empty if not `SQLi`.
#[must_use]
pub(crate) fn format_sqli_expected(fingerprint: Option<&str>) -> String {
    fingerprint.unwrap_or("").to_owned()
}

/// Go HTML5 corpus encoding: one token per line `TYPE,len,text`, joined by `\n`.
///
/// Empty token list → empty string (Go `TrimSpace` on no tokens).
#[must_use]
pub(crate) fn format_html5_expected(token_lines: &[String]) -> String {
    token_lines.join("\n")
}

/// Go tokens corpus encoding: one raw token per line, joined by `\n`.
#[must_use]
pub(crate) fn format_tokens_expected(token_lines: &[String]) -> String {
    token_lines.join("\n")
}

/// Go folding corpus encoding: one folded token per line, joined by `\n`.
#[must_use]
pub(crate) fn format_folding_expected(token_lines: &[String]) -> String {
    token_lines.join("\n")
}

pub(crate) fn actual_folding_output(input: &str) -> String {
    let flags = 1 | 8; // FLAG_QUOTE_NONE | FLAG_SQL_ANSI
    let mut lines = Vec::new();
    sqli_fold_visit(input.as_bytes(), flags, |tok| {
        let line = format_token_line(&tok);
        lines.push(line);
    });
    let joined = format_folding_expected(&lines);
    joined.trim().to_owned()
}

pub(crate) fn actual_xss_output(input: &str) -> String {
    let verdict = detect_xss(input.as_bytes());
    format_xss_expected(verdict).to_owned()
}

pub(crate) fn actual_sqli_output(input: &str) -> String {
    let verdict = detect_sqli(input.as_bytes());
    let fingerprint = verdict.fingerprint.as_str();
    format_sqli_expected(fingerprint)
}

pub(crate) fn actual_html5_output(input: &str) -> String {
    let mut lines = Vec::new();
    html5_visit(input.as_bytes(), XssHtmlContext::Data, |kind, value| {
        let text = String::from_utf8_lossy(value);
        lines.push(format!("{},{},{}", html5_type_label(kind), value.len(), text));
    });
    // Go `runXSSTest` applies `strings.TrimSpace` before compare.
    format_html5_expected(&lines).trim().to_owned()
}

pub(crate) fn actual_tokens_output(input: &str) -> String {
    let flags = 1 | 8; // FLAG_QUOTE_NONE | FLAG_SQL_ANSI
    let mut lines = Vec::new();
    sqli_tokenize_visit(input.as_bytes(), flags, |tok| {
        let line = format_token_line(&tok);
        lines.push(line);
    });
    let joined = format_tokens_expected(&lines);
    joined.trim().to_owned()
}

/// Format one SQL token per Go `printToken`.
fn format_token_line(tok: &SqliTokenInfo) -> String {
    let cat = tok.category as char;
    let val = String::from_utf8_lossy(tok.val.get(..tok.len).unwrap_or(&tok.val));

    let mut out = String::new();
    out.push(cat);
    out.push(' ');
    match tok.category {
        b's' => {
            if tok.str_open != 0 {
                out.push(tok.str_open as char);
            }
            out.push_str(&val);
            if tok.str_close != 0 {
                out.push(tok.str_close as char);
            }
        },
        b'v' => {
            if tok.count == 1 {
                out.push('@');
            } else if tok.count == 2 {
                out.push('@');
                out.push('@');
            }
            if tok.str_open != 0 {
                out.push(tok.str_open as char);
            }
            out.push_str(&val);
            if tok.str_close != 0 {
                out.push(tok.str_close as char);
            }
        },
        _ => {
            out.push_str(&val);
        },
    }
    out.trim_end_matches(['\n', '\r']).to_owned()
}

/// Walk vendored fixtures for `kind`, compare stub/engine output to `--EXPECTED--`.
///
/// Returns `(passed, failed)`.
pub(crate) fn run_baseline(kind: DriverKind, actual: impl Fn(&str) -> String) -> (usize, usize) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut passed = 0_usize;
    let mut failed = 0_usize;

    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !(filename.starts_with("test-") && filename.ends_with(".txt")) {
            continue;
        }

        let case = parse_corpus_file(&path).unwrap();
        if DriverKind::from_name(&case.name) != Some(kind) {
            continue;
        }

        let got = actual(&case.input);
        if got == case.expected {
            passed += 1;
        } else {
            eprintln!(
                "{}\n  input:    {:?}\n  expected: {:?}\n  actual:   {:?}",
                path.display(),
                case.input,
                case.expected,
                got
            );
            failed += 1;
        }
    }

    (passed, failed)
}
