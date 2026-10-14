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

use libperfusion::{
    Dialect, HtmlContext, HtmlTokenKind, HtmlTokenizer, Quote, SqlState, SqlToken, SqlTokenType, SqlTokenizer,
};

use super::corpus::{DriverKind, parse_corpus_file};

fn html5_type_label(kind: HtmlTokenKind) -> &'static str {
    match kind {
        HtmlTokenKind::DataText => "DATA_TEXT",
        HtmlTokenKind::TagNameOpen => "TAG_NAME_OPEN",
        HtmlTokenKind::TagNameClose => "TAG_NAME_CLOSE",
        HtmlTokenKind::TagNameSelfClose => "TAG_NAME_SELFCLOSE",
        HtmlTokenKind::TagClose => "TAG_CLOSE",
        HtmlTokenKind::AttrName => "ATTR_NAME",
        HtmlTokenKind::AttrValue => "ATTR_VALUE",
        HtmlTokenKind::TagComment => "TAG_COMMENT",
        HtmlTokenKind::Doctype => "DOCTYPE",
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
    let mut state = SqlState::new(input.as_bytes());
    let lines: Vec<_> = state.fold(Quote::None, Dialect::Ansi).map(format_token_line).collect();
    format_folding_expected(&lines).trim().to_owned()
}

pub(crate) fn actual_xss_output(input: &str) -> String {
    format_xss_expected(libperfusion::xss(input.as_bytes())).to_owned()
}

pub(crate) fn actual_sqli_output(input: &str) -> String {
    let fingerprint = libperfusion::sqli(input.as_bytes());
    format_sqli_expected(fingerprint.as_ref().map(libperfusion::Fingerprint::as_str))
}

pub(crate) fn actual_html5_output(input: &str) -> String {
    let lines: Vec<_> = HtmlTokenizer::new(input.as_bytes(), HtmlContext::Data)
        .map(|token| {
            let text = String::from_utf8_lossy(token.text);
            format!("{},{},{}", html5_type_label(token.kind), token.text.len(), text)
        })
        .collect();
    format_html5_expected(&lines).trim().to_owned()
}

pub(crate) fn actual_tokens_output(input: &str) -> String {
    let lines: Vec<_> = SqlTokenizer::new(input.as_bytes(), Quote::None, Dialect::Ansi)
        .map(format_token_line)
        .collect();
    format_tokens_expected(&lines).trim().to_owned()
}

/// Format one SQL token per Go `printToken`.
fn format_token_line(token: SqlToken) -> String {
    let mut out = String::new();
    out.push(char::from(token.kind().as_byte()));
    out.push(' ');
    match token.kind() {
        SqlTokenType::String | SqlTokenType::Variable => {
            if token.kind() == SqlTokenType::Variable {
                out.extend(std::iter::repeat_n('@', usize::from(token.variable_count().min(2))));
            }
            if let Some(open) = token.string_open() {
                out.push(char::from(open));
            }
            out.push_str(&String::from_utf8_lossy(token.value()));
            if let Some(close) = token.string_close() {
                out.push(char::from(close));
            }
        },
        _ => out.push_str(&String::from_utf8_lossy(token.value())),
    }
    out.trim_end_matches(['\n', '\r']).to_owned()
}

/// Walk vendored fixtures for `kind`, compare engine output to `--EXPECTED--`.
///
/// Returns `(passed, failed)`.
pub(crate) fn run_baseline(kind: DriverKind, actual: impl Fn(&str) -> String) -> (usize, usize) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut passed = 0_usize;
    let mut failed = 0_usize;

    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
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
