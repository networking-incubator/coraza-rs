//! Runs upstream's own test suite against the port: the expected-output
//! files under `tests/`, as `src/testdriver.c` does, and the sample files
//! under `data/`, as `src/reader.c` does.
//!
//! These need a libinjection checkout, in `libinjection/` next to
//! `Cargo.toml` or wherever `LIBINJECTION_DIR` points.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use crate::html5::{Context, TokenKind, Tokenizer};
use crate::sqli::State;
use crate::sqli::lexer::{Dialect, Lexer, Quote};
use crate::sqli::token::{Token, TokenType};

fn upstream() -> PathBuf {
    let dir = env::var_os("LIBINJECTION_DIR").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("libinjection"),
        PathBuf::from,
    );
    assert!(
        dir.join("tests").is_dir(),
        "no libinjection checkout at {}: clone https://github.com/libinjection/libinjection \
         there, or point LIBINJECTION_DIR at one",
        dir.display()
    );
    dir
}

/// Reads a source file of the upstream checkout.
pub(crate) fn upstream_source(path: &str) -> String {
    let path = upstream().join(path);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The body of the C array introduced by `declaration`, comments removed.
pub(crate) fn c_array_body(source: &str, declaration: &str) -> String {
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

/// Upstream's `modp_rtrim`.
fn rtrim(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\n' | b'\t' | b'\r'))
        .map_or(0, |last| last + 1);
    &bytes[..end]
}

struct Case {
    input: Vec<u8>,
    expected: Vec<u8>,
}

/// Splits a test file into its `--TEST--`, `--INPUT--` and `--EXPECTED--`
/// sections, as `read_file` in `testdriver.c` does.
fn parse_case(content: &[u8]) -> Option<Case> {
    let mut sections: [Vec<u8>; 3] = Default::default();
    let mut seen: usize = 0;
    for line in content.split_inclusive(|&b| b == b'\n') {
        match (seen, line) {
            (0, b"--TEST--\n") | (1, b"--INPUT--\n") | (2, b"--EXPECTED--\n") => seen += 1,
            _ => sections[seen.checked_sub(1)?].extend_from_slice(line),
        }
    }
    (seen == 3).then(|| Case {
        input: rtrim(&sections[1]).to_vec(),
        expected: rtrim(&sections[2]).to_vec(),
    })
}

/// Runs every `tests/<prefix>*.txt` through `actual` and compares the
/// output with the file's expectation.
fn run_cases(prefix: &str, actual: impl Fn(&[u8]) -> Vec<u8>) {
    let dir = upstream().join("tests");
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with(prefix) && name.ends_with(".txt"))
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no {prefix}*.txt in {}", dir.display());

    let mut failed = 0;
    let mut report = String::new();
    for name in &names {
        let content = fs::read(dir.join(name)).unwrap();
        let case = parse_case(&content).unwrap_or_else(|| panic!("{name}: malformed"));
        let got = actual(&case.input);
        let got = rtrim(&got);
        if got != case.expected {
            failed += 1;
            writeln!(
                report,
                "{name}\n  input:    {}\n  expected: {}\n  got:      {}",
                case.input.escape_ascii(),
                case.expected.escape_ascii(),
                got.escape_ascii()
            )
            .unwrap();
        }
    }
    assert!(
        failed == 0,
        "{failed} of {} {prefix}* cases failed:\n{report}",
        names.len()
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
        crate::sqli(input).map_or_else(Vec::new, |fingerprint| fingerprint.as_bytes().to_vec())
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
            let text = token.text.split(|&b| b == 0).next().unwrap_or_default();
            out.extend_from_slice(format!("{kind},{},", token.text.len()).as_bytes());
            out.extend_from_slice(text);
            out.push(b'\n');
        }
        out
    });
}

/// `modp_url_decode` in `reader.c`.
fn url_decode(s: &[u8]) -> Vec<u8> {
    let hex = |b: u8| char::from(b).to_digit(16);
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < s.len() => {
                if let (Some(high), Some(low)) = (hex(s[i + 1]), hex(s[i + 2])) {
                    out.push(u8::try_from(high << 4 | low).unwrap());
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            other => out.push(other),
        }
        i += 1;
    }
    out
}

/// Counts the samples in `data/<prefix>*` that `detect` flags, and those it
/// does not. As in `reader.c`, each line is a URL-encoded sample; blank
/// lines and `#` comments are skipped.
fn count_samples(prefix: &str, detect: impl Fn(&[u8]) -> bool) -> (usize, usize) {
    let dir = upstream().join("data");
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with(prefix))
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no {prefix}* in {}", dir.display());

    let (mut flagged, mut passed) = (0, 0);
    for name in &names {
        let content = fs::read(dir.join(name)).unwrap();
        for line in content.split(|&b| b == b'\n') {
            let line = rtrim(line);
            if line.is_empty() || line[0] == b'#' {
                continue;
            }
            if detect(&url_decode(line)) {
                flagged += 1;
            } else {
                passed += 1;
            }
        }
    }
    (flagged, passed)
}

// The counts below are what upstream's `reader` reports for these files at
// d88a8f8. Upstream itself only checks them against a threshold (`-m` in
// `src/test-samples-*.sh`); the port has to land on the same samples.

const SQLI_SAMPLES_FLAGGED: usize = 85_785;
const SQLI_SAMPLES_MISSED: usize = 17;
const BENIGN_SAMPLES_FLAGGED: usize = 21;
const BENIGN_SAMPLES_PASSED: usize = 402;
const XSS_SAMPLES_FLAGGED: usize = 81_397;
const XSS_SAMPLES_MISSED: usize = 20;

#[test]
fn sqli_samples() {
    let (flagged, missed) = count_samples("sqli-", |sample| crate::sqli(sample).is_some());
    assert_eq!(
        (flagged, missed),
        (SQLI_SAMPLES_FLAGGED, SQLI_SAMPLES_MISSED)
    );
}

#[test]
fn sqli_false_positive_samples() {
    let (flagged, passed) = count_samples("false_", |sample| crate::sqli(sample).is_some());
    assert_eq!(
        (flagged, passed),
        (BENIGN_SAMPLES_FLAGGED, BENIGN_SAMPLES_PASSED)
    );
}

#[test]
fn xss_samples() {
    let (flagged, missed) = count_samples("xss", crate::xss);
    assert_eq!((flagged, missed), (XSS_SAMPLES_FLAGGED, XSS_SAMPLES_MISSED));
}

/// The checks of `src/test_error_handling.c` that carry over.
#[test]
fn edge_cases() {
    assert!(crate::sqli(b"hello world 123").is_none());
    assert!(crate::sqli(b"1' OR '1'='1").is_some());
    assert!(crate::xss(b"<script>alert('xss')</script>"));
    assert!(!crate::xss(b"<p>Hello World</p>"));
    assert!(!crate::xss(b"hello world"));

    assert!(crate::sqli(b"").is_none());
    assert!(crate::sqli(&vec![b'A'; 99_999]).is_none());
    assert!(crate::sqli(b"\0\0\0\0").is_none());

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
        let _ = crate::sqli(pattern.as_bytes());
        let _ = crate::xss(pattern.as_bytes());
    }

    assert_eq!(Tokenizer::new(b"<div<div>", Context::Data).count(), 2);
    let nested = b"<div>".repeat(1000);
    assert_eq!(Tokenizer::new(&nested, Context::Data).count(), 2000);
}
