//! libinjection's own test suite, run against the port.
//!
//! The expected-output files of upstream's `tests/` are checked the way
//! `src/testdriver.c` checks them, and the sample files of `data/` the way
//! `src/reader.c` does. Both are vendored in `tests/upstream`.

mod common;

use common::Case;
use libperfusion::internals::html5::{Context, TokenKind, Tokenizer};
use libperfusion::internals::sqli::{Dialect, Lexer, Quote, State, Token, TokenType};

/// Runs every `tests/<prefix>*.txt` through `actual` and compares the
/// output with the file's expectation.
fn run_cases(prefix: &str, actual: impl Fn(&[u8]) -> Vec<u8>) {
    let cases = common::cases(prefix);
    let failures: Vec<String> = cases
        .iter()
        .filter_map(
            |Case {
                 name,
                 input,
                 expected,
             }| {
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
            },
        )
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
fn print_token(out: &mut Vec<u8>, token: &Token) {
    out.extend([token.ty.as_byte(), b' ']);
    match token.ty {
        TokenType::String | TokenType::Variable => {
            if token.ty == TokenType::Variable {
                out.extend(std::iter::repeat_n(b'@', usize::from(token.count.min(2))));
            }
            out.extend(token.str_open);
            out.extend_from_slice(token.c_str());
            out.extend(token.str_close);
        }
        _ => out.extend_from_slice(token.c_str()),
    }
    out.push(b'\n');
}

#[test]
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
fn sqli_folding() {
    run_cases("test-folding-", |input| {
        let mut state = State::new(input, Quote::None, Dialect::Ansi);
        let count = state.fold();
        let mut out = Vec::new();
        for token in &state.tokens[..count] {
            print_token(&mut out, token);
        }
        out
    });
}

#[test]
fn sqli_detection() {
    run_cases("test-sqli-", |input| {
        libperfusion::sqli(input)
            .map_or_else(Vec::new, |fingerprint| fingerprint.as_bytes().to_vec())
    });
}

#[test]
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
    let flagged = samples
        .iter()
        .filter(|line| detect(&common::url_decode(line)))
        .count();
    (flagged, samples.len() - flagged)
}

// The counts below are what upstream's `reader` reports for these files at
// d88a8f8. Upstream itself only checks them against a threshold (`-m` in
// `src/test-samples-*.sh`); the port has to land on the same samples.

#[test]
fn sqli_samples() {
    let (flagged, missed) = count_samples("sqli-", |s| libperfusion::sqli(s).is_some());
    assert_eq!((flagged, missed), (85_785, 17));
}

#[test]
fn sqli_false_positive_samples() {
    let (flagged, passed) = count_samples("false_", |s| libperfusion::sqli(s).is_some());
    assert_eq!((flagged, passed), (21, 402));
}

#[test]
fn xss_samples() {
    let (flagged, missed) = count_samples("xss", libperfusion::xss);
    assert_eq!((flagged, missed), (81_397, 20));
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
        let _ = libperfusion::sqli(pattern.as_bytes());
        let _ = libperfusion::xss(pattern.as_bytes());
    }

    assert_eq!(Tokenizer::new(b"<div<div>", Context::Data).count(), 2);
    let nested = b"<div>".repeat(1000);
    assert_eq!(Tokenizer::new(&nested, Context::Data).count(), 2000);
}
