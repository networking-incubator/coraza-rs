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

//! Smoke tests for the corpus file parser.
#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]
#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::panic, reason = "tests")]
#![expect(clippy::print_stderr, reason = "baseline pass/fail reporting")]

mod common;

use std::{fs, path::Path};

use common::{
    corpus::{CorpusCase, DriverKind, ParseError, parse_corpus_file, parse_corpus_str, trim_marker},
    drivers::{
        actual_folding_output, actual_html5_output, actual_sqli_output, actual_tokens_output, actual_xss_output,
        run_baseline,
    },
};
use libinjection::detect_sqli;

#[test]
fn corpus_case_can_be_constructed() {
    let case = CorpusCase {
        name: "test-folding-001".into(),
        description: "strings are merged".into(),
        input: "SELECT 1".into(),
        expected: "E SELECT".into(),
    };
    assert_eq!(case.name, "test-folding-001");
    assert!(case.expected.contains("SELECT"));
}

#[test]
fn parse_error_can_be_constructed() {
    assert_eq!(ParseError::Io("boom".into()), ParseError::Io("boom".into()));
    assert_eq!(
        ParseError::MissingSection { marker: "--INPUT--" },
        ParseError::MissingSection { marker: "--INPUT--" }
    );
    assert_eq!(ParseError::Empty, ParseError::Empty);
}

#[test]
fn section_marker_trims_surrounding_whitespace_like_go() {
    assert_eq!(trim_marker(" \t--INPUT-- \r"), "--INPUT--");
}

#[test]
fn payload_lines_preserve_internal_trailing_spaces_and_carriage_returns() {
    let contents = "--TEST--\ndesc\n--INPUT--\nfirst  \r\nsecond\t\n \n--EXPECTED--\nvalue\n";
    let case = parse_corpus_str("test-sqli-space", contents).unwrap();
    assert_eq!(case.input, "first  \r\nsecond");
}

#[test]
fn parse_minimal_fixture() {
    let contents = "\
--TEST--
desc
--INPUT--
SELECT 1
--EXPECTED--
E SELECT
";
    let case = parse_corpus_str("test-x", contents).unwrap();
    assert_eq!(case.name, "test-x");
    assert_eq!(case.description, "desc");
    assert_eq!(case.input, "SELECT 1");
    assert_eq!(case.expected, "E SELECT");
}

#[test]
fn parse_empty_expected_ok() {
    let contents = "\
--TEST--
sqli
--INPUT--
foo
--EXPECTED--
";
    let case = parse_corpus_str("test-sqli-001", contents).unwrap();
    assert_eq!(case.input, "foo");
    assert_eq!(case.expected, "");
}

#[test]
fn parse_missing_input_errors() {
    let contents = "\
--TEST--
only test
--EXPECTED--
1
";
    assert!(matches!(
        parse_corpus_str("bad", contents),
        Err(ParseError::MissingSection { .. })
    ));
}

#[test]
fn parse_real_folding_001() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/test-folding-001.txt");
    let case = parse_corpus_file(&path).unwrap();
    assert_eq!(case.name, "test-folding-001");
    assert!(case.input.contains("SELECT"));
    assert!(!case.expected.is_empty());
}

#[test]
fn all_corpus_files_parse() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut count = 0_usize;
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !(name.starts_with("test-") && name.ends_with(".txt")) {
            continue;
        }
        parse_corpus_file(&path).unwrap_or_else(|err| {
            panic!("failed to parse {}: {err:?}", path.display());
        });
        count += 1;
    }
    assert_eq!(count, 496, "fixture inventory count drifted");
}

#[test]
fn corpus_fixture_inventory_and_family_counts_match_manifest() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut actual = Vec::new();
    let mut counts = [0_usize; 5];
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !(filename.starts_with("test-") && filename.ends_with(".txt")) {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(kind) = DriverKind::from_name(stem) else {
            panic!("every corpus fixture has a driver kind: {stem}");
        };
        let count_index = match kind {
            DriverKind::Sqli => 0,
            DriverKind::Folding => 1,
            DriverKind::Tokens => 2,
            DriverKind::Html5 => 3,
            DriverKind::Xss => 4,
        };
        if let Some(count) = counts.get_mut(count_index) {
            *count += 1;
        }
        actual.push(filename.to_owned());
    }
    actual.sort();

    let manifest = include_str!("parity/manifest.json");
    let expected: Vec<String> = manifest
        .lines()
        .filter_map(|line| line.trim().strip_prefix("\"name\": \""))
        .filter_map(|name| name.strip_suffix("\","))
        .map(ToOwned::to_owned)
        .collect();
    assert_eq!(expected.len(), 496, "manifest must list every fixture");
    assert_eq!(actual, expected, "fixture filename inventory differs from manifest");
    assert_eq!(counts, [54, 118, 249, 68, 7], "fixture family counts changed");
}

#[test]
fn driver_kind_can_be_constructed() {
    assert_eq!(DriverKind::Folding, DriverKind::Folding);
    assert_eq!(DriverKind::Html5, DriverKind::Html5);
    assert_eq!(DriverKind::Sqli, DriverKind::Sqli);
    assert_eq!(DriverKind::Tokens, DriverKind::Tokens);
    assert_eq!(DriverKind::Xss, DriverKind::Xss);
}

#[test]
fn driver_kind_from_name_examples() {
    assert_eq!(DriverKind::from_name("test-sqli-001"), Some(DriverKind::Sqli));
    assert_eq!(DriverKind::from_name("test-sqli-1e-001"), Some(DriverKind::Sqli));
    assert_eq!(DriverKind::from_name("test-folding-001"), Some(DriverKind::Folding));
    assert_eq!(DriverKind::from_name("test-tokens-words-002"), Some(DriverKind::Tokens));
    assert_eq!(DriverKind::from_name("test-html5-012"), Some(DriverKind::Html5));
    assert_eq!(DriverKind::from_name("test-xss-001"), Some(DriverKind::Xss));
    assert_eq!(DriverKind::from_name("README"), None);
}

#[test]
fn every_corpus_file_has_a_driver_kind() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !(filename.starts_with("test-") && filename.ends_with(".txt")) {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            panic!("corpus filename is not UTF-8: {}", path.display());
        };
        assert!(DriverKind::from_name(stem).is_some(), "no DriverKind for {stem}");
    }
}

#[test]
fn xss_driver_detects_script_fixture() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/test-xss-001.txt");
    let case = parse_corpus_file(&path).unwrap();
    assert_eq!(DriverKind::from_name(&case.name), Some(DriverKind::Xss));

    let actual = actual_xss_output(&case.input);
    assert_eq!(actual, "1");
    assert_eq!(actual, case.expected);
}

#[test]
fn sqli_driver_on_sqli_001() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/test-sqli-001.txt");
    let case = parse_corpus_file(&path).unwrap();
    assert_eq!(DriverKind::from_name(&case.name), Some(DriverKind::Sqli));
    let actual = actual_sqli_output(&case.input);
    assert_eq!(actual, case.expected);
}

#[test]
fn folding_corpus_baseline() {
    let (passed, failed) = run_baseline(DriverKind::Folding, actual_folding_output);
    eprintln!("folding baseline: {passed} passed, {failed} failed");
    assert!(passed + failed > 0, "no folding fixtures found");
    assert_eq!(failed, 0);
}

#[test]
fn html5_corpus_baseline() {
    let (passed, failed) = run_baseline(DriverKind::Html5, actual_html5_output);
    eprintln!("html5 baseline: {passed} passed, {failed} failed");
    assert!(passed + failed > 0, "no HTML5 fixtures found");
    assert_eq!(failed, 0);
}

#[test]
fn sqli_corpus_baseline() {
    let mut count = 0_usize;
    for line in include_str!("parity/sqli_oracle.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 4, "malformed SQL oracle row: {line:?}");
        let filename = fields.first().copied().unwrap();
        let expected_detected = match fields.get(2).copied() {
            Some("0") => false,
            Some("1") => true,
            other => panic!("invalid SQL oracle boolean for {filename}: {other:?}"),
        };
        let expected_fingerprint_hex = fields.get(3).copied().unwrap();
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/corpus")
            .join(filename);
        let case = parse_corpus_file(&path).unwrap_or_else(|err| panic!("failed to parse {filename}: {err:?}"));
        assert_eq!(DriverKind::from_name(&case.name), Some(DriverKind::Sqli));
        assert_eq!(
            hex_encode(case.expected.as_bytes()),
            expected_fingerprint_hex,
            "fixture fingerprint disagrees with independent Go output for {filename}"
        );

        let actual = detect_sqli(case.input.as_bytes());
        assert_eq!(
            actual.detected, expected_detected,
            "SQL boolean mismatch for {filename}: input={:?}",
            case.input
        );
        assert_eq!(
            actual.fingerprint.as_str().unwrap_or(""),
            case.expected,
            "SQL fingerprint mismatch for {filename}: input={:?}",
            case.input
        );
        count += 1;
    }
    assert_eq!(count, 54, "SQL oracle baseline inventory changed");
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX.get(usize::from(byte >> 4)).copied().unwrap_or_default()));
        encoded.push(char::from(
            HEX.get(usize::from(byte & 0x0F)).copied().unwrap_or_default(),
        ));
    }
    encoded
}

#[test]
fn xss_corpus_baseline() {
    let (passed, failed) = run_baseline(DriverKind::Xss, actual_xss_output);
    eprintln!("xss baseline: {passed} passed, {failed} failed");
    assert!(passed + failed > 0, "no XSS fixtures found");
    assert_eq!(failed, 0);
}

#[test]
fn html5_driver_on_ascii_word() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/test-html5-001.txt");
    let case = parse_corpus_file(&path).unwrap();
    assert_eq!(DriverKind::from_name(&case.name), Some(DriverKind::Html5));

    let actual = actual_html5_output(&case.input);
    assert_eq!(case.expected, "DATA_TEXT,3,foo");
    assert_eq!(actual, case.expected);
}

#[test]
fn folding_driver_on_folding_001() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/test-folding-001.txt");
    let case = parse_corpus_file(&path).unwrap();
    assert_eq!(DriverKind::from_name(&case.name), Some(DriverKind::Folding));

    let actual = actual_folding_output(&case.input);
    assert!(case.expected.contains("SELECT"));
    assert_eq!(actual, case.expected);
}

#[test]
fn tokens_driver_on_words_002() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/test-tokens-words-002.txt");
    let case = parse_corpus_file(&path).unwrap();
    assert_eq!(DriverKind::from_name(&case.name), Some(DriverKind::Tokens));

    let actual = actual_tokens_output(&case.input);
    assert!(case.expected.contains("SELECT"));
    assert_eq!(actual, case.expected);
}

#[test]
fn tokens_corpus_baseline() {
    let (passed, failed) = run_baseline(DriverKind::Tokens, actual_tokens_output);
    eprintln!("tokens baseline: {passed} passed, {failed} failed");
    assert!(passed + failed > 0, "no tokens fixtures found");
    assert_eq!(failed, 0);
}
