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

//! Optional differential comparison against the pinned development Go oracle.
#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]
#![expect(
    dead_code,
    reason = "the shared corpus module also contains fixture-specific formatters"
)]
#![expect(clippy::unwrap_used, reason = "differential test fixtures are trusted")]
#![expect(clippy::expect_used, reason = "differential test fixtures are trusted")]
#![expect(clippy::panic, reason = "mismatch report is the test output")]
#![expect(clippy::print_stderr, reason = "mismatch report is the test output")]

mod common;

use std::{fmt::Write as _, fs, io::Write as _, path::Path, process::Command, time::Duration};

use common::{
    corpus::{DriverKind, parse_corpus_file},
    subprocess::run_with_timeout,
};
use libinjection::{
    Html5TokenKind, XssHtmlContext, detect_sqli, detect_xss, html5_visit, sqli_fold_visit, sqli_tokenize_visit,
};

const ORACLE_FIELDS: usize = 22;
const ORACLE_TIMEOUT: Duration = Duration::from_secs(300);
const NUL_COMMENT_CASES: [(&str, &[u8]); 4] = [
    ("xss-nul-import-1", b"<?im\0port namespace=\"t\">"),
    ("xss-nul-import-2", b"<?\0import namespace=\"t\">"),
    ("xss-nul-entity-1", b"<!\0ENTITY x SYSTEM \"file:///etc/passwd\">"),
    ("xss-nul-entity-2", b"<!EN\0TITY x SYSTEM \"file:///etc/passwd\">"),
];
const SQL_FOLD_COLLAPSE_CASES: [(&str, &[u8]); 8] = [
    ("sql-fold-collapse-number-operator-union", b"1=(1) UNION SELECT 1"),
    ("sql-fold-collapse-number-operator-tautology", b"1=(1) OR 1=1"),
    ("sql-fold-collapse-number-comma-union", b"1,(1) UNION SELECT 1"),
    ("sql-fold-collapse-number-comma-stacked", b"1,(1); DROP TABLE users"),
    (
        "sql-fold-collapse-word-operator-union",
        b"x=(x) UNION SELECT password FROM users",
    ),
    ("sql-fold-collapse-number-right-paren-union", b"1),(1) UNION SELECT 1"),
    ("sql-fold-collapse-word-right-paren-union", b"x)=(x) UNION SELECT 1"),
    ("sql-fold-collapse-word-right-paren-tautology", b"x)=(x) OR 1=1"),
];
const SQL_QUOTE_DIVERGENCE_ID: &str = "sql-escape-suffix";
const SQL_QUOTE_DIVERGENCE_INPUT: &[u8] = b"\x27\x5c\x27\x27";
const SQL_QUOTE_DIVERGENCE_GO_STREAM: &str = "1,0,0,0;73:1:3:0:27:00:5c2727";
const SQL_QUOTE_DIVERGENCE_RUST_STREAM: &str = "1,0,0,0;73:1:2:0:27:27:5c27";
const SQL_QUOTE_DIVERGENCE_FIELDS: [usize; 4] = [4, 5, 10, 11];
const SQL_STREAM_EXCEPTION_FIELDS: [usize; 4] = [4, 5, 10, 11];
const SQL_FLAGS: [u32; 6] = [9, 17, 10, 18, 12, 20];
const HTML_CONTEXTS: [XssHtmlContext; 5] = [
    XssHtmlContext::Data,
    XssHtmlContext::AttrUnquoted,
    XssHtmlContext::AttrSingle,
    XssHtmlContext::AttrDouble,
    XssHtmlContext::AttrBacktick,
];

#[test]
#[ignore = "manual development-only test; requires the pinned Go toolchain"]
fn pinned_go_oracle_matches_corpus_and_binary_cases() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::env::var("LIBINJECTION_GO_SOURCE").unwrap_or_else(|_| {
        panic!("set LIBINJECTION_GO_SOURCE to a checkout at f6c336efc0ddac2597fd27d3b1b7db9c87613e8d")
    });
    let oracle = manifest_dir.join("tools/parity/go-oracle");
    let cases = load_cases(manifest_dir);
    let mut request = Vec::new();
    for (id, input) in &cases {
        writeln!(&mut request, "{id}\t{}", hex_encode(input)).expect("write oracle request");
    }

    let mut command = Command::new(oracle);
    command.arg(&source);
    let output = run_with_timeout(&mut command, &request, ORACLE_TIMEOUT)
        .unwrap_or_else(|error| panic!("run pinned Go oracle within deadline: {error}"));
    let oracle_stderr = String::from_utf8_lossy(&output.stderr);
    if !oracle_stderr.is_empty() {
        eprint!("{oracle_stderr}");
    }
    assert!(
        output.status.success(),
        "Go oracle exited unsuccessfully: {oracle_stderr}"
    );

    let output_text = core::str::from_utf8(&output.stdout).expect("oracle protocol is ASCII");
    let responses: Vec<&str> = output_text.lines().collect();
    assert_eq!(
        responses.len(),
        cases.len(),
        "oracle response count differs from request count"
    );

    let mut result = DifferentialResult::default();
    for ((id, input), response) in cases.iter().zip(responses) {
        compare_case(id, input, response, &mut result);
    }
    eprintln!(
        "differential summary: cases={}, defined_comparisons={}, oracle_errors={}, reviewed_exceptions={}, diagnostic_differences={}, public_verdict_misses={}",
        cases.len(),
        result.summary.defined_comparisons,
        result.summary.oracle_errors,
        result.summary.accepted_exceptions,
        result.summary.diagnostic_differences,
        result.mismatches.len(),
    );
    for diagnostic in result.diagnostic_examples {
        eprintln!("diagnostic field difference (not a release verdict gate):\n{diagnostic}");
    }
    assert!(
        result.mismatches.is_empty(),
        "parity mismatches:\n{}",
        result.mismatches.join("\n\n")
    );
    assert_eq!(cases.len(), 843, "pinned differential case inventory changed");
    assert_eq!(
        result.summary.defined_comparisons, 16_860,
        "defined oracle field coverage changed"
    );
    assert_eq!(
        result.summary.oracle_errors, 0,
        "v0.3.3 oracle must complete every result field"
    );
    assert_eq!(
        result.summary.accepted_exceptions, 10,
        "accepted differential exceptions must match the reviewed inventory"
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "keeps the reviewed differential fixture inventory together"
)]
fn load_cases(manifest_dir: &Path) -> Vec<(String, Vec<u8>)> {
    let corpus_dir = manifest_dir.join("tests/corpus");
    let mut paths: Vec<_> = fs::read_dir(&corpus_dir)
        .expect("read corpus directory")
        .map(|entry| entry.expect("read corpus entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("test-") && name.ends_with(".txt"))
        })
        .collect();
    paths.sort();

    let mut cases = Vec::with_capacity(paths.len() + 48);
    for path in paths {
        let case = parse_corpus_file(&path).unwrap_or_else(|error| panic!("parse {}: {error:?}", path.display()));
        assert!(
            DriverKind::from_name(&case.name).is_some(),
            "unknown fixture family: {}",
            case.name
        );
        cases.push((case.name, case.input.into_bytes()));
    }

    for (id, bytes) in [
        (
            "go-test-is-sqli-example",
            b"-1' and 1=1 union/* foo */select load_file('/etc/passwd')--".as_slice(),
        ),
        ("candidate-union-benign", b"1 UNION".as_slice()),
        ("candidate-hash-comment-benign", b"1# blah blah".as_slice()),
        ("candidate-block-comment-benign", b"/* harmless */".as_slice()),
        ("exp-incomplete-1e", b"1e".as_slice()),
        ("exp-incomplete-1e-plus", b"1e+".as_slice()),
        ("exp-incomplete-1-dot-e", b"1.e".as_slice()),
        ("exp-incomplete-dot-e", b".E".as_slice()),
        ("exp-next-union", b"1e 1 union".as_slice()),
        ("whitelist-leading-space", b" 1/*x*/".as_slice()),
        ("whitelist-leading-space-zero-x", b" 0x1/*".as_slice()),
        ("whitelist-leading-space-exponent", b"\n1e5/*".as_slice()),
        ("sql-1c-benign-control", b"1".as_slice()),
        ("sql-q-high-byte-benign-control", b"q'\xe9'".as_slice()),
        ("sql-nul-hex-benign-control", b"0x\0\x31".as_slice()),
        ("sql-nul-variable-benign-control", b"@\0name".as_slice()),
        ("unicode-long-s", b"\xc5\xbf\x65\x6c\x65\x63\x74".as_slice()),
        ("unicode-dotless-i", b"un\xc4\xb1on".as_slice()),
        ("sql-escape-suffix", b"\x27\x5c\x27\x27".as_slice()),
        ("sql-linear-quote-tautology", b"\x27\x5c\x27\x27 OR 1=1 -- ".as_slice()),
        (
            "sql-malformed-quote-verdict",
            b"-(top<>thendrop1.5\\'--null'--".as_slice(),
        ),
        ("sql-quote-reported-false-positive", b"a#'=''\\'\" 1--'".as_slice()),
        (
            "sql-q-high-byte-following-union",
            b"q'\xe9' union /*!50000select*/ 1".as_slice(),
        ),
        ("sql-nul-after-hex-prefix", b"1 or 0x\0\x31=1-- ".as_slice()),
        ("sql-nul-after-hex-prefix-hash", b"'=0X\0#".as_slice()),
        ("xss-namespace-xmlns-prefix", b"<div xmlnsfoo=\"safe\">".as_slice()),
        ("xss-namespace-xlink-prefix", b"<div xlinkfoo=\"safe\">".as_slice()),
        ("xss-svg-prefix-go-control", b"<svganimate>".as_slice()),
        ("xss-xsl-prefix-go-control", b"<xsl:template>".as_slice()),
        (
            "xss-percent-comment-later-script",
            b"<%a%b%><script>alert(1)</script>".as_slice(),
        ),
        ("xss-bare-attribute", b"onerror".as_slice()),
        ("xss-empty-quoted-context", b"".as_slice()),
        ("html-end-tag-slash", b"</script/>".as_slice()),
        ("html-empty-end-tag", b"</>".as_slice()),
        ("html-bogus-percent", b"<x %%%%>".as_slice()),
        ("xss-url-nul", b"href=ja\0va:".as_slice()),
        ("xss-entity-whitespace", b"href=&#32;java:".as_slice()),
        ("xss-url-prefix-data", b"<a href=data:foo>".as_slice()),
        ("xss-url-prefix-javascript", b"<a href=javascript:alert(1)>".as_slice()),
        ("xss-url-prefix-vbscript", b"<a href=vbscript:msgbox>".as_slice()),
        ("xss-url-prefix-no-match", b"<a href=https://example.com>".as_slice()),
        (
            "xss-url-prefix-inside-path",
            b"<a href=https://example.com/javascript-tutorials>".as_slice(),
        ),
        ("xss-url-prefix-at-end", b"<a href=nodata>".as_slice()),
        ("xss-cdata-after-script-hit", b"<script><![CDATA[]]]".as_slice()),
    ] {
        cases.push((id.to_owned(), bytes.to_vec()));
    }
    cases.push(("sql-q-high-byte-unclosed".to_owned(), b"q'\xe9x\xe9'".to_vec()));
    cases.push(("sql-q-utf8-close-advance".to_owned(), b"q'\xe9x\xc3\xa9\x27".to_vec()));
    let mut mixed_quotes = vec![b'\'', b'\\', b'\''];
    mixed_quotes.extend([b'\''; 8]);
    cases.push(("sql-escape-doubled-quotes".to_owned(), mixed_quotes));

    for size in [65_535, 65_536, 65_537] {
        cases.push((format!("sql-hash-{size}"), vec![b'#'; size]));
        let mut comment = Vec::with_capacity(size);
        comment.extend_from_slice(b"/*");
        comment.extend(std::iter::repeat_n(b'x', size - 4));
        comment.extend_from_slice(b"*/");
        cases.push((format!("sql-comment-{size}"), comment));

        let mut arithmetic = Vec::with_capacity(size);
        while arithmetic.len() < size {
            arithmetic.extend_from_slice(b"1+");
        }
        arithmetic.truncate(size);
        cases.push((format!("sql-arithmetic-{size}"), arithmetic));
    }
    cases.push((
        "binary-invalid-utf8".to_owned(),
        vec![0xFF, 0x00, b'\'', 0x80, b'<', b'>'],
    ));
    cases.push(("sql-unary-65535".to_owned(), vec![b'+'; 65_535]));
    cases.push(("sql-unary-65536".to_owned(), vec![b'+'; 65_536]));
    cases.push(("sql-unary-65537".to_owned(), vec![b'+'; 65_537]));

    append_boundary_and_byte_cases(&mut cases);

    for (id, input) in NUL_COMMENT_CASES {
        cases.push((id.to_owned(), input.to_vec()));
    }
    let overlong_svg = [b"<svg".as_slice(), &[b'x'; 64], b">"].concat();
    cases.push(("xss-svg-prefix-overlong-control".to_owned(), overlong_svg));
    let overlong_xsl = [b"<xsl".as_slice(), &[b'x'; 64], b">"].concat();
    cases.push(("xss-xsl-prefix-overlong-control".to_owned(), overlong_xsl));
    cases.push(("xss-cdata-v033-recovery".to_owned(), b"<![CDATA[]]]".to_vec()));
    for (id, input) in SQL_FOLD_COLLAPSE_CASES {
        cases.push((id.to_owned(), input.to_vec()));
    }
    cases
}

fn append_boundary_and_byte_cases(cases: &mut Vec<(String, Vec<u8>)>) {
    for size in [511, 512, 513, 8_191, 8_192, 8_193, 65_535, 65_536] {
        let sql_marker = b" union select 1";
        let mut sql_input = vec![b'x'; size - sql_marker.len()];
        sql_input.extend_from_slice(sql_marker);
        cases.push((format!("sql-boundary-{size}"), sql_input));

        let html_marker = b"<a href=javascript:1>";
        let mut html_input = vec![b'x'; size - html_marker.len()];
        html_input.extend_from_slice(html_marker);
        cases.push((format!("html-boundary-{size}"), html_input));
    }

    for value in 0_u16..=u16::from(u8::MAX) {
        let byte = u8::try_from(value).expect("byte range fits u8");
        cases.push((format!("single-byte-{byte:02x}"), vec![byte]));
    }
}

#[derive(Default)]
struct DifferentialSummary {
    defined_comparisons: usize,
    oracle_errors: usize,
    accepted_exceptions: usize,
    diagnostic_differences: usize,
}

#[derive(Default)]
struct DifferentialResult {
    mismatches: Vec<String>,
    diagnostic_examples: Vec<String>,
    summary: DifferentialSummary,
}

fn compare_case(id: &str, input: &[u8], response: &str, result: &mut DifferentialResult) {
    let fields: Vec<&str> = response.split('\t').collect();
    if fields.len() != ORACLE_FIELDS || fields.first().copied() != Some(id) {
        result.summary.oracle_errors += 1;
        result.mismatches.push(mismatch(
            id,
            input,
            "protocol",
            &format!("{ORACLE_FIELDS} fields for {id}"),
            response,
        ));
        return;
    }

    let mut comparison = CaseComparison {
        id,
        input,
        fields: &fields,
        defined_fields: [true; ORACLE_FIELDS],
        mismatches: &mut result.mismatches,
        diagnostic_examples: &mut result.diagnostic_examples,
        summary: &mut result.summary,
    };
    comparison.defined_fields[0] = false;
    comparison.defined_fields[1] = false;
    comparison.record_oracle_errors(fields.get(1).copied().unwrap_or_default());
    comparison.compare_sqli();
    comparison.compare_html_contexts();
    comparison.compare_xss();
}

struct CaseComparison<'a> {
    id: &'a str,
    input: &'a [u8],
    fields: &'a [&'a str],
    defined_fields: [bool; ORACLE_FIELDS],
    mismatches: &'a mut Vec<String>,
    diagnostic_examples: &'a mut Vec<String>,
    summary: &'a mut DifferentialSummary,
}

impl CaseComparison<'_> {
    fn record_oracle_errors(&mut self, errors: &str) {
        if errors.is_empty() {
            return;
        }
        for encoded_error in errors.split(';') {
            let Some((field_text, error_hex)) = encoded_error.split_once('=') else {
                self.summary.oracle_errors += 1;
                self.mismatches.push(mismatch(
                    self.id,
                    self.input,
                    "oracle-error-protocol",
                    "field-index=hex(stage:panic)",
                    encoded_error,
                ));
                continue;
            };
            let field_index = field_text.parse::<usize>();
            let error_bytes = hex_decode(error_hex);
            let (Ok(field_index), Some(error_bytes)) = (field_index, error_bytes) else {
                self.summary.oracle_errors += 1;
                self.mismatches.push(mismatch(
                    self.id,
                    self.input,
                    "oracle-error-protocol",
                    "valid field index and lowercase hex panic record",
                    encoded_error,
                ));
                continue;
            };
            let message = String::from_utf8_lossy(&error_bytes).into_owned();
            self.summary.oracle_errors += 1;
            if !(2..ORACLE_FIELDS).contains(&field_index) {
                self.mismatches.push(mismatch(
                    self.id,
                    self.input,
                    "oracle-error-protocol",
                    "error attached to result field 2 through 21",
                    encoded_error,
                ));
                continue;
            }
            if let Some(defined) = self.defined_fields.get_mut(field_index) {
                if !*defined {
                    self.mismatches.push(mismatch(
                        self.id,
                        self.input,
                        "oracle-error-protocol",
                        "at most one error record per result field",
                        encoded_error,
                    ));
                    continue;
                }
                *defined = false;
            }
            self.mismatches.push(mismatch(
                self.id,
                self.input,
                "oracle-error",
                "a defined libinjection-go v0.3.3 result",
                &format!("field={field_index}, error={message}"),
            ));
        }
    }

    fn compare_sqli(&mut self) {
        let result = detect_sqli(self.input);
        self.compare_public_verdict(2, if result.detected { "1" } else { "0" }, "sqli-boolean");
        let fingerprint = format!(
            "{}:{:x}",
            hex_encode(
                result
                    .fingerprint
                    .bytes
                    .get(..usize::from(result.fingerprint.len))
                    .unwrap_or_default()
            ),
            result.fingerprint.len
        );
        self.record_diagnostic_field(3, &fingerprint, "sqli-fingerprint");

        for (mode_index, flags) in SQL_FLAGS.iter().enumerate() {
            let mut raw_tokens = Vec::new();
            let raw_stats = sqli_tokenize_visit(self.input, *flags, |token| raw_tokens.push(sql_token(&token)));
            let raw_output = format!("{};{}", sql_stats(&raw_stats), raw_tokens.join(";"));
            self.compare_sql_stream_field(4 + mode_index, &raw_output, "sqli-raw-tokens");

            let mut folded_tokens = Vec::new();
            let folded_stats = sqli_fold_visit(self.input, *flags, |token| folded_tokens.push(sql_token(&token)));
            let folded_output = format!("{};{}", sql_stats(&folded_stats), folded_tokens.join(";"));
            self.compare_sql_stream_field(10 + mode_index, &folded_output, "sqli-folded-tokens");
        }
    }

    fn compare_sql_stream_field(&mut self, field_index: usize, actual: &str, layer: &str) {
        let layer = format!("{layer}[field={field_index}]");
        self.record_diagnostic_field(field_index, actual, &layer);
    }

    fn compare_html_contexts(&mut self) {
        for (context_index, context) in HTML_CONTEXTS.iter().copied().enumerate() {
            let mut tokens = Vec::new();
            html5_visit(self.input, context, |kind, value| {
                tokens.push(format!("{}:{}:{}", html5_kind(kind), value.len(), hex_encode(value)));
            });
            self.record_diagnostic_field(16 + context_index, &tokens.join(";"), "html5-tokens");
        }
    }

    fn compare_xss(&mut self) {
        let xss_value = if detect_xss(self.input) { "1" } else { "0" };
        self.compare_public_verdict(21, xss_value, "xss-boolean");
    }

    fn compare_public_verdict(&mut self, field_index: usize, actual: &str, layer: &str) {
        if !self.is_defined(field_index) {
            return;
        }
        self.summary.defined_comparisons += 1;
        let expected = self.oracle_field(field_index).to_owned();
        if expected == actual {
            return;
        }
        if expected == "1" && actual == "0" {
            self.mismatches.push(mismatch(
                self.id,
                self.input,
                layer,
                "Go true => Rust true",
                "Go true => Rust false",
            ));
            return;
        }
        if expected == "0" && actual == "1" && self.is_reviewed_rust_only_verdict(field_index, actual) {
            return;
        }
        self.mismatches
            .push(mismatch(self.id, self.input, layer, &expected, actual));
    }

    fn record_diagnostic_field(&mut self, field_index: usize, actual: &str, layer: &str) {
        if !self.is_defined(field_index) {
            return;
        }
        self.summary.defined_comparisons += 1;
        let expected = self.oracle_field(field_index).to_owned();
        if expected == actual {
            return;
        }
        if let Some((go_expected, rust_expected, count_exception)) = self.reviewed_deviation(field_index)
            && expected == go_expected
            && actual == rust_expected
        {
            if count_exception {
                self.summary.accepted_exceptions += 1;
            }
            return;
        }

        self.summary.diagnostic_differences += 1;
        if self.diagnostic_examples.len() < 12 {
            self.diagnostic_examples
                .push(mismatch(self.id, self.input, layer, &expected, actual));
        }
    }

    fn is_reviewed_rust_only_verdict(&mut self, field_index: usize, actual: &str) -> bool {
        let Some((go_expected, rust_expected, count_exception)) = self.reviewed_deviation(field_index) else {
            return false;
        };
        if go_expected != "0"
            || rust_expected != "1"
            || self.oracle_field(field_index) != go_expected
            || actual != rust_expected
        {
            return false;
        }
        if count_exception {
            self.summary.accepted_exceptions += 1;
        }
        true
    }

    fn reviewed_deviation(&self, field_index: usize) -> Option<(&'static str, &'static str, bool)> {
        if self.id == SQL_QUOTE_DIVERGENCE_ID
            && self.input == SQL_QUOTE_DIVERGENCE_INPUT
            && SQL_QUOTE_DIVERGENCE_FIELDS.contains(&field_index)
        {
            return Some((
                SQL_QUOTE_DIVERGENCE_GO_STREAM,
                SQL_QUOTE_DIVERGENCE_RUST_STREAM,
                field_index == SQL_QUOTE_DIVERGENCE_FIELDS[0],
            ));
        }
        reviewed_sql_deviation(self.id, self.input, field_index)
            .or_else(|| reviewed_xss_deviation(self.id, self.input, field_index))
    }

    fn is_defined(&self, field_index: usize) -> bool {
        self.defined_fields.get(field_index).copied().unwrap_or(false)
    }

    fn oracle_field(&self, field_index: usize) -> &str {
        self.fields.get(field_index).copied().unwrap_or("<missing>")
    }
}

fn reviewed_sql_deviation(id: &str, input: &[u8], field_index: usize) -> Option<(&'static str, &'static str, bool)> {
    if id == "whitelist-leading-space" && input == b" 1/*x*/"
        || id == "whitelist-leading-space-zero-x" && input == b" 0x1/*"
        || id == "whitelist-leading-space-exponent" && input == b"\n1e5/*"
    {
        return match field_index {
            2 => Some(("0", "1", true)),
            3 => Some((":0", "3163:2", false)),
            _ => None,
        };
    }

    if id == "sql-malformed-quote-verdict" && input == b"-(top<>thendrop1.5\\'--null'--" {
        return match field_index {
            2 => Some(("0", "1", true)),
            3 => Some((":0", "7363:2", false)),
            4 | 5 | 6 | 7 | 10 | 11 | 12 | 13 => Some((
                "1,0,0,0;73:0:29:0:00:00:2d28746f703c3e7468656e64726f70312e355c272d2d6e756c6c272d2d",
                "2,0,0,0;73:0:26:0:00:27:2d28746f703c3e7468656e64726f70312e355c272d2d6e756c6c;63:27:2:0:00:00:2d2d",
                false,
            )),
            _ => None,
        };
    }

    if id == "sql-q-high-byte-following-union" && input == b"q'\xe9' union /*!50000select*/ 1" {
        return match field_index {
            2 => Some(("0", "1", true)),
            3 => Some((":0", "58:1", false)),
            4 | 5 | 10 | 11 => Some((
                "1,0,0,0;73:3:26:0:71:00:2720756e696f6e202f2a21353030303073656c6563742a2f2031",
                "5,0,0,0;6e:0:1:0:00:00:71;73:2:1:0:27:27:e9;55:5:5:0:00:00:756e696f6e;58:11:16:0:00:00:2f2a21353030303073656c6563742a2f;31:28:1:0:00:00:31",
                false,
            )),
            _ => None,
        };
    }

    if id == "sql-nul-after-hex-prefix" && input == b"1 or 0x\x001=1-- " {
        return match field_index {
            2 => Some(("0", "1", true)),
            3 => Some((":0", "31263163:4", false)),
            4 | 5 => Some((
                "7,0,0,0;31:0:1:0:00:00:31;26:2:2:0:00:00:6f72;6e:5:2:0:00:00:3078;31:8:1:0:00:00:31;6f:9:1:0:00:00:3d;31:10:1:0:00:00:31;63:11:3:0:00:00:2d2d20",
                "6,0,0,0;31:0:1:0:00:00:31;26:2:2:0:00:00:6f72;31:5:4:0:00:00:30780031;6f:9:1:0:00:00:3d;31:10:1:0:00:00:31;63:11:3:0:00:00:2d2d20",
                false,
            )),
            10 | 11 => Some((
                "7,0,0,0;31:0:1:0:00:00:31;26:2:2:0:00:00:6f72;6e:5:2:0:00:00:3078;31:8:1:0:00:00:31;63:11:3:0:00:00:2d2d20",
                "6,0,0,0;31:0:1:0:00:00:31;26:2:2:0:00:00:6f72;31:5:4:0:00:00:30780031;63:11:3:0:00:00:2d2d20",
                false,
            )),
            _ => None,
        };
    }

    if id == "sql-nul-after-hex-prefix-hash" && input == b"'=0X\0#" {
        return match field_index {
            2 => Some(("0", "1", true)),
            3 => Some((":0", "736f3163:4", false)),
            6 => Some((
                "4,0,0,1;73:0:0:0:00:27:;6f:1:1:0:00:00:3d;6e:2:2:0:00:00:3058;6f:5:1:0:00:00:23",
                "4,0,0,1;73:0:0:0:00:27:;6f:1:1:0:00:00:3d;31:2:3:0:00:00:305800;6f:5:1:0:00:00:23",
                false,
            )),
            7 | 13 => Some((
                "4,0,0,2;73:0:0:0:00:27:;6f:1:1:0:00:00:3d;6e:2:2:0:00:00:3058;63:5:1:0:00:00:23",
                "4,0,0,2;73:0:0:0:00:27:;6f:1:1:0:00:00:3d;31:2:3:0:00:00:305800;63:5:1:0:00:00:23",
                false,
            )),
            _ => None,
        };
    }

    if id == "sql-q-high-byte-unclosed" && input == b"q'\xe9x\xe9'" {
        return stream_deviation(
            field_index,
            "1,0,0,0;73:3:3:0:71:00:78e927",
            "2,0,0,0;6e:0:1:0:00:00:71;73:2:3:0:27:27:e978e9",
        );
    }

    if id == "sql-q-utf8-close-advance" && input == b"q'\xe9x\xc3\xa9'" {
        return match field_index {
            4 | 5 => Some((
                "2,0,0,0;73:3:1:0:71:71:78;73:7:0:0:27:00:",
                "2,0,0,0;6e:0:1:0:00:00:71;73:2:4:0:27:27:e978c3a9",
                field_index == 4,
            )),
            10 | 11 => Some((
                "2,1,0,0;73:3:1:0:71:71:78",
                "2,0,0,0;6e:0:1:0:00:00:71;73:2:4:0:27:27:e978c3a9",
                false,
            )),
            _ => None,
        };
    }

    None
}

fn stream_deviation(
    field_index: usize,
    go_expected: &'static str,
    rust_expected: &'static str,
) -> Option<(&'static str, &'static str, bool)> {
    SQL_STREAM_EXCEPTION_FIELDS.contains(&field_index).then_some((
        go_expected,
        rust_expected,
        field_index == SQL_STREAM_EXCEPTION_FIELDS[0],
    ))
}

fn reviewed_xss_deviation(id: &str, input: &[u8], field_index: usize) -> Option<(&'static str, &'static str, bool)> {
    if id == "xss-percent-comment-later-script" && input == b"<%a%b%><script>alert(1)</script>" && field_index == 16 {
        return Some((
            "8:30:612562253e3c7363726970743e616c6572742831293c2f7363726970743e",
            "8:3:612562;1:6:736372697074;2:1:3e;0:8:616c657274283129;5:6:736372697074",
            false,
        ));
    }

    match (id, input, field_index) {
        ("xss-percent-comment-later-script", b"<%a%b%><script>alert(1)</script>", 21) => Some(("0", "1", true)),
        _ => None,
    }
}

fn mismatch(id: &str, input: &[u8], layer: &str, expected: &str, actual: &str) -> String {
    format!(
        "case={id}\nlayer={layer}\ninput_hex={}\nexpected={expected:?}\nactual={actual:?}\nassigned_fix=triage",
        hex_encode(input)
    )
}

fn sql_stats(stats: &impl SqlStatistics) -> String {
    format!(
        "{},{},{},{}",
        stats.tokens(),
        stats.folds(),
        stats.comment_ddx(),
        stats.comment_hash()
    )
}

trait SqlStatistics {
    fn tokens(&self) -> usize;
    fn folds(&self) -> usize;
    fn comment_ddx(&self) -> usize;
    fn comment_hash(&self) -> usize;
}

impl SqlStatistics for libinjection::SqliStatistics {
    fn tokens(&self) -> usize {
        self.tokens
    }

    fn folds(&self) -> usize {
        self.folds
    }

    fn comment_ddx(&self) -> usize {
        self.comment_ddx
    }

    fn comment_hash(&self) -> usize {
        self.comment_hash
    }
}

fn sql_token(token: &libinjection::SqliTokenInfo) -> String {
    let value = token.val.get(..token.len).unwrap_or(&token.val);
    format!(
        "{:02x}:{}:{}:{}:{:02x}:{:02x}:{}",
        token.category,
        token.pos,
        token.len,
        token.count,
        token.str_open,
        token.str_close,
        hex_encode(value)
    )
}

fn html5_kind(kind: Html5TokenKind) -> u8 {
    match kind {
        Html5TokenKind::DataText => 0,
        Html5TokenKind::TagNameOpen => 1,
        Html5TokenKind::TagNameClose => 2,
        Html5TokenKind::TagNameSelfClose => 3,
        Html5TokenKind::TagClose => 5,
        Html5TokenKind::AttrName => 6,
        Html5TokenKind::AttrValue => 7,
        Html5TokenKind::TagComment => 8,
        Html5TokenKind::DocType => 9,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("write hex byte");
    }
    out
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(*pair.first()?)?;
        let low = hex_nibble(*pair.get(1)?)?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
