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
//! libinjection's own test suite, run against the port.

//! The expected-output files of upstream's `tests/` are checked the way
//! `src/testdriver.c` checks them, and the sample files of `data/` the way
//! `src/reader.c` does. Both are vendored in `tests/upstream`.

#![expect(
    clippy::tests_outside_test_module,
    reason = "Cargo integration test targets consist of tests."
)]

#[path = "upstream_common.rs"]
mod common;

use common::Case;
use libperfusion::{
    Dialect, HtmlContext as Context, HtmlTokenKind as TokenKind, HtmlTokenizer as Tokenizer, Quote, SqlState, SqlToken,
    SqlTokenType as TokenType, SqlTokenizer as Lexer,
};

/// Runs every `tests/<prefix>*.txt` through `actual` and compares the
/// output with the file's expectation.
fn run_cases(prefix: &str, actual: impl Fn(&[u8]) -> Vec<u8>) {
    let cases = common::cases(prefix);
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|Case { name, input, expected }| {
            let got = actual(input);
            let got = common::rtrim(&got);
            (got != expected).then(|| {
                format!(
                    "{name}\n  input:    {}\n  expected: {}\n  got:      {}",
                    input.escape_ascii(),
                    expected.escape_ascii(),
                    got.escape_ascii()
                )
            })
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} {prefix}* cases failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

/// `print_token` in `testdriver.c`. Values go through `%s` there, so they
/// stop at the first NUL.
fn print_token(out: &mut Vec<u8>, token: &SqlToken) {
    out.extend([token.kind().as_byte(), b' ']);
    match token.kind() {
        TokenType::String | TokenType::Variable => {
            if token.kind() == TokenType::Variable {
                out.extend(std::iter::repeat_n(b'@', usize::from(token.variable_count().min(2))));
            }
            if let Some(open) = token.string_open() {
                out.push(open);
            }
            out.extend_from_slice(token.c_value());
            if let Some(close) = token.string_close() {
                out.push(close);
            }
        },
        _ => out.extend_from_slice(token.c_value()),
    }
    out.push(b'\n');
}

#[test]
#[ignore = "upstream corpus comparison; requires upstream test files via LIBINJECTION_DIR"]
fn sqli_tokens() {
    run_cases("test-tokens-", |input| {
        let mut out = Vec::new();
        for token in Lexer::new(input, Quote::None, Dialect::Ansi) {
            print_token(&mut out, &token);
        }
        out
    });
}

#[test]
#[ignore = "upstream corpus comparison; requires upstream test files via LIBINJECTION_DIR"]
fn sqli_folding() {
    run_cases("test-folding-", |input| {
        let mut state = SqlState::new(input);
        let tokens = state.fold(Quote::None, Dialect::Ansi);
        let mut out = Vec::new();
        for token in tokens {
            print_token(&mut out, &token);
        }
        out
    });
}

#[test]
#[ignore = "upstream corpus comparison; requires upstream test files via LIBINJECTION_DIR"]
fn sqli_detection() {
    run_cases("test-sqli-", |input| {
        libperfusion::sqli(input).map_or_else(Vec::new, |fingerprint| fingerprint.as_bytes().to_vec())
    });
}

#[test]
#[ignore = "upstream corpus comparison; requires upstream test files via LIBINJECTION_DIR"]
fn html5_tokens() {
    run_cases("test-html5-", |input| {
        let mut out = Vec::new();
        for token in Tokenizer::new(input, Context::Data) {
            let kind = match token.kind {
                TokenKind::DataText => "DATA_TEXT",
                TokenKind::TagNameOpen => "TAG_NAME_OPEN",
                TokenKind::TagNameClose => "TAG_NAME_CLOSE",
                TokenKind::TagNameSelfClose => "TAG_NAME_SELFCLOSE",
                TokenKind::TagClose => "TAG_CLOSE",
                TokenKind::AttrName => "ATTR_NAME",
                TokenKind::AttrValue => "ATTR_VALUE",
                TokenKind::TagComment => "TAG_COMMENT",
                TokenKind::Doctype => "DOCTYPE",
            };
            // The text goes through `%s`, so it stops at the first NUL.
            let text = token.text.split(|&b| b == 0).next().unwrap_or_default();
            out.extend_from_slice(format!("{kind},{},", token.text.len()).as_bytes());
            out.extend_from_slice(text);
            out.push(b'\n');
        }
        out
    });
}

/// Counts the samples of `data/<prefix>*.txt` that `detect` flags, and
/// those it does not.
fn count_samples(prefix: &str, detect: impl Fn(&[u8]) -> bool) -> (usize, usize) {
    let samples = common::sample_lines(prefix);
    let flagged = samples.iter().filter(|line| detect(&common::url_decode(line))).count();
    (flagged, samples.len() - flagged)
}

// The SQL counts match upstream at d88a8f8. Go v0.3.5 allows nine XSS samples
// that C flags; those exact cases are listed in the parity mismatch ledger.

#[test]
#[ignore = "upstream sample comparison; requires upstream data files via LIBINJECTION_DIR"]
fn sqli_samples() {
    let (flagged, missed) = count_samples("sqli-", |s| libperfusion::sqli(s).is_some());
    assert_eq!((flagged, missed), (85_785, 17));
}

#[test]
#[ignore = "upstream sample comparison; requires upstream data files via LIBINJECTION_DIR"]
fn sqli_false_positive_samples() {
    let (flagged, passed) = count_samples("false_", |s| libperfusion::sqli(s).is_some());
    assert_eq!((flagged, passed), (21, 402));
}

#[test]
#[ignore = "upstream sample comparison; requires upstream data files via LIBINJECTION_DIR"]
fn xss_samples() {
    let (flagged, missed) = count_samples("xss", libperfusion::xss);
    assert_eq!((flagged, missed), (81_388, 29));
}

/// The checks of `src/test_error_handling.c` that carry over: the port has
/// no error result to return, so what is left is not panicking.
#[test]
fn edge_cases() {
    assert!(libperfusion::sqli(b"hello world 123").is_none());
    assert!(libperfusion::sqli(b"1' OR '1'='1").is_some());
    assert!(libperfusion::xss(b"<script>alert('xss')</script>"));
    assert!(!libperfusion::xss(b"<p>Hello World</p>"));
    assert!(libperfusion::xss(b"<script>alert(1)</script>"));
    assert!(!libperfusion::xss(b"hello world"));

    assert!(libperfusion::sqli(b"").is_none());
    assert!(libperfusion::sqli(&vec![b'A'; 99_999]).is_none());
    assert!(libperfusion::sqli(b"\0\0\0\0").is_none());

    for pattern in [
        "'''''''''''",
        "\\\\\\\\\\\\\\\\",
        "////////",
        "{{{{{{{{",
        "}}}}}}}}",
        "[[[[[[[[",
        "]]]]]]]]",
        "<<<<<<<<",
        ">>>>>>>>",
    ] {
        std::hint::black_box(libperfusion::sqli(pattern.as_bytes()));
        std::hint::black_box(libperfusion::xss(pattern.as_bytes()));
    }

    assert_eq!(Tokenizer::new(b"<div<div>", Context::Data).count(), 2);
    let nested = b"<div>".repeat(1000);
    assert_eq!(Tokenizer::new(&nested, Context::Data).count(), 2000);
}
