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

//! Optional differential comparison against the Go module pinned in xtask/tools/go.mod.
#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]
#![expect(
    dead_code,
    reason = "the shared corpus module also contains fixture-specific formatters"
)]
#![expect(clippy::unwrap_used, reason = "differential test fixtures are trusted")]
#![expect(clippy::expect_used, reason = "differential test fixtures are trusted")]
#![expect(clippy::panic, reason = "mismatch report is the test output")]
#![expect(clippy::print_stderr, reason = "mismatch report is the test output")]
#![expect(
    clippy::indexing_slicing,
    reason = "Oracle fields are checked for the required count before access."
)]

mod common;

#[path = "upstream_common.rs"]
mod upstream_common;

use std::{fmt::Write as _, fs, io::Write as _, path::Path, process::Command, time::Duration};

use common::{
    corpus::{DriverKind, parse_corpus_file},
    subprocess::run_with_timeout,
};
use libperfusion::{Dialect, HtmlContext, HtmlTokenKind, HtmlTokenizer, Quote, SqlState, SqlToken, SqlTokenizer};

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
const SQL_CONTEXTS: [(Quote, Dialect); 6] = [
    (Quote::None, Dialect::Ansi),
    (Quote::None, Dialect::Mysql),
    (Quote::Single, Dialect::Ansi),
    (Quote::Single, Dialect::Mysql),
    (Quote::Double, Dialect::Ansi),
    (Quote::Double, Dialect::Mysql),
];
const HTML_CONTEXTS: [HtmlContext; 5] = [
    HtmlContext::Data,
    HtmlContext::ValueNoQuote,
    HtmlContext::ValueSingleQuote,
    HtmlContext::ValueDoubleQuote,
    HtmlContext::ValueBackQuote,
];
const C_XSS_DIFFERENCES: [(&str, &[u8], bool, bool); 13] = [
    ("xss-event-name-nul", b"<a on\0error=1>", false, true),
    ("xss-tag-name-nul", b"<sv\0gload>", false, true),
    ("xss-xmlns-name-nul", b"<a xm\0lns=1>", false, true),
    ("xss-event-suffix-control", b"<a onerrorfoo=1>", true, false),
    ("xss-namespace-xmlns-prefix", b"<div xmlnsfoo=\"safe\">", true, false),
    ("xss-namespace-xlink-prefix", b"<div xlinkfoo=\"safe\">", true, false),
    ("xss-indirect-url-control", b"<a attributename=href>", true, false),
    ("xss-indirect-style-control", b"<a attributename=style>", true, false),
    ("xss-url-nul", b"href=ja\0va:", false, true),
    ("xss-nul-import-1", b"<?im\0port namespace=\"t\">", false, true),
    ("xss-nul-import-2", b"<?\0import namespace=\"t\">", false, true),
    (
        "xss-nul-entity-1",
        b"<!\0ENTITY x SYSTEM \"file:///etc/passwd\">",
        false,
        true,
    ),
    (
        "xss-nul-entity-2",
        b"<!EN\0TITY x SYSTEM \"file:///etc/passwd\">",
        false,
        true,
    ),
];
/// Pinned C and libperfusion XSS verdicts for the sample inputs the direct
/// corpus does not carry.
///
/// The booleans are `(C, libperfusion)`. Rows where they differ are the
/// reviewed C deviations; rows where they agree were reviewed deviations
/// that the local XSS table additions closed, and are kept so a regression
/// back to the old verdict fails the gate.
const C_XSS_SAMPLE_VERDICTS: [(&str, &[u8], bool, bool); 9] = [
    (
        "xss-html5secorg.txt:232",
        b"test 83 <x:template xmlns:x=\"http://www.wapforum.org/2001/wml\" x:ontimer=\"$(x:unesc)j$(y:escape)a$(z:noecs)v$(x)a$(y)s$(z)cript$x:alert(1)\"><x:timer value=\"1\"/></x:template>",
        true,
        false,
    ),
    (
        "xss-html5secorg.txt:234",
        b"test 84 <x xmlns:ev=\"http://www.w3.org/2001/xml-events\" ev:event=\"load\" ev:handler=\"javascript:alert(1)//#x",
        true,
        false,
    ),
    (
        "xss-html5secorg.txt:236",
        b"test 85 <x xmlns:ev=\"http://www.w3.org/2001/xml-events\" ev:event=\"load\" ev:handler=\"test.evt#x\"/>",
        true,
        false,
    ),
    (
        "xss-html5secorg.txt:468",
        b"test 132_1 <set attributeName=\"xlink:href\" begin=\"accessKey(a)\" to=\"//example.com/?a\" />",
        true,
        false,
    ),
    (
        "xss-soaj1664ashar-pastebin-u6FY1xDA.txt:78",
        b"74) <math><a xlink:href=\"//jsfiddle.net/t846h/\">click",
        true,
        true,
    ),
    (
        "xss-soaj1664ashar-pastebin-u6FY1xDA.txt:102",
        b"97) <math><a xlink:href=\"//jsfiddle.net/t846h/\">click",
        true,
        true,
    ),
    (
        "xss-xenotix.txt:693",
        b"<math><a xlink:href=\"//XXXxenotixXXX:3555/xss_serve_payloads/bmpz.bmp\">KCF",
        true,
        true,
    ),
    (
        "xss-xenotix.txt:694",
        b"<math><a xlink:href=\"//XXXxenotixXXX:3555/xss_serve_payloads/kcf.js\">KCF",
        true,
        true,
    ),
    (
        "xss-xenotix.txt:1196",
        b"<x:script xmlns:x=\"http://www.w3.org/1999/xhtml\">alert(1);</x:script>",
        true,
        false,
    ),
];

#[test]
#[ignore = "manual differential gate; requires the pinned Go module and 1.27.1 toolchain"]
fn pinned_go_oracle_matches_corpus_and_binary_cases() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = manifest_dir.join("tools/parity/go-oracle");
    let cases = load_cases(manifest_dir);
    let mut request = Vec::new();
    for (id, input) in &cases {
        writeln!(&mut request, "{id}\t{}", hex_encode(input)).expect("write oracle request");
    }

    let mut command = Command::new(oracle);
    let output = run_with_timeout(&mut command, &request, ORACLE_TIMEOUT)
        .unwrap_or_else(|error| panic!("run Go module oracle within deadline: {error}"));
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
        "differential summary: cases={}, comparisons={}, oracle_errors={}, reviewed_exceptions={}, diagnostic_differences={}",
        cases.len(),
        result.comparisons,
        result.oracle_errors,
        result.accepted_exceptions,
        result.diagnostic_differences,
    );
    for diagnostic in result.diagnostic_examples {
        eprintln!("token stream difference (diagnostic only):\n{diagnostic}");
    }
    assert!(
        result.mismatches.is_empty(),
        "libperfusion public parity mismatches:\n{}",
        result.mismatches.join("\n\n")
    );
    assert_eq!(cases.len(), 864, "pinned differential case inventory changed");
    assert_eq!(result.comparisons, 17_280, "defined oracle field coverage changed");
    assert_eq!(
        result.oracle_errors, 0,
        "pinned Go module must complete every result field"
    );
    assert_eq!(
        result.accepted_exceptions, 6,
        "libperfusion deviations must stay reviewed"
    );
}

#[test]
#[ignore = "manual C differential gate; requires the pinned libinjection checkout and a C compiler"]
fn pinned_c_oracle_matches_corpus_and_binary_cases() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cases = load_cases(manifest_dir);
    let mut request = Vec::new();
    for (id, input) in &cases {
        writeln!(&mut request, "{id}\t{}", hex_encode(input)).expect("write C oracle request");
    }

    let driver = upstream_common::build_with_libinjection("tests/c_oracle_driver.c", "-O2");
    let mut command = Command::new(driver);
    let output = run_with_timeout(&mut command, &request, ORACLE_TIMEOUT)
        .unwrap_or_else(|error| panic!("run C libinjection oracle within deadline: {error}"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "C oracle failed: {stderr}");

    let responses: Vec<_> = core::str::from_utf8(&output.stdout)
        .expect("C oracle protocol is ASCII")
        .lines()
        .collect();
    assert_eq!(
        responses.len(),
        cases.len(),
        "C oracle response count differs from request count"
    );
    let mut mismatches = Vec::new();
    let mut reviewed_xss_differences = 0;
    for ((id, input), response) in cases.iter().zip(responses) {
        let fields: Vec<_> = response.split('\t').collect();
        assert_eq!(fields.len(), 4, "{id}: malformed C response {response:?}");
        assert_eq!(fields[0], id, "C oracle case order/id mismatch");
        let expected = libperfusion::sqli(input);
        let expected_sqli = if expected.is_some() { "1" } else { "0" };
        let expected_fingerprint = expected.as_ref().map_or("", |value| value.as_str());
        let expected_xss = if libperfusion::xss(input) { "1" } else { "0" };
        assert!(
            matches!(fields[1], "0" | "1") && matches!(fields[3], "0" | "1"),
            "{id}: invalid C booleans"
        );
        let known_xss_difference = c_xss_difference(id, input, fields[3] == "1", expected_xss == "1");
        if known_xss_difference && fields[1] == expected_sqli && fields[2] == expected_fingerprint {
            reviewed_xss_differences += 1;
            continue;
        }
        if (fields[1] != expected_sqli || fields[2] != expected_fingerprint || fields[3] != expected_xss)
            && mismatches.len() < 40
        {
            mismatches.push(format!(
                "{id} input={} C=({}, {:?}, {}) libperfusion=({}, {:?}, {})",
                hex_encode(input),
                fields[1],
                fields[2],
                fields[3],
                expected_sqli,
                expected_fingerprint,
                expected_xss
            ));
        }
    }
    assert!(mismatches.is_empty(), "C oracle mismatches:\n{}", mismatches.join("\n"));
    assert_eq!(reviewed_xss_differences, 20, "C XSS deviation inventory changed");
    eprintln!(
        "C differential passed: {} public SQL/XSS results, {reviewed_xss_differences} reviewed XSS differences",
        cases.len()
    );
}

fn c_xss_difference(id: &str, input: &[u8], c_result: bool, rust_result: bool) -> bool {
    C_XSS_DIFFERENCES.iter().chain(C_XSS_SAMPLE_VERDICTS.iter()).any(
        |(case_id, expected_input, expected_c, expected_rust)| {
            expected_c != expected_rust
                && id == *case_id
                && input == *expected_input
                && c_result == *expected_c
                && rust_result == *expected_rust
        },
    ) || match id {
        "xss-svg-prefix-overlong-control" => {
            input == [b"<svg".as_slice(), &[b'x'; 64], b">"].concat() && c_result && !rust_result
        },
        "xss-xsl-prefix-overlong-control" => {
            input == [b"<xsl".as_slice(), &[b'x'; 64], b">"].concat() && c_result && !rust_result
        },
        _ => false,
    }
}

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

    append_additional_direct_cases(&mut cases);
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
    cases.push(("xss-cdata-oracle-recovery".to_owned(), b"<![CDATA[]]]".to_vec()));
    for (id, input) in SQL_FOLD_COLLAPSE_CASES {
        cases.push((id.to_owned(), input.to_vec()));
    }
    cases.extend(
        C_XSS_SAMPLE_VERDICTS
            .iter()
            .map(|(id, input, ..)| ((*id).to_owned(), (*input).to_vec())),
    );
    cases
}


fn append_additional_direct_cases(cases: &mut Vec<(String, Vec<u8>)>) {
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
        ("sql-like-select-fingerprint", b"1 LIKE (SELECT 1)".as_slice()),
        (
            "sql-like-operand-attack",
            b"' OR (8459 LIKE (SELECT 8459)) * 4906 -- ".as_slice(),
        ),
        ("xss-event-name-nul", b"<a on\0error=1>".as_slice()),
        ("xss-tag-name-nul", b"<sv\0gload>".as_slice()),
        ("xss-xmlns-name-nul", b"<a xm\0lns=1>".as_slice()),
        ("xss-event-suffix-control", b"<a onerrorfoo=1>".as_slice()),
        ("xss-namespace-xmlns-prefix", b"<div xmlnsfoo=\"safe\">".as_slice()),
        ("xss-namespace-xlink-prefix", b"<div xlinkfoo=\"safe\">".as_slice()),
        ("xss-bare-xlink", b"xlink=1".as_slice()),
        ("xss-indirect-url-control", b"<a attributename=href>".as_slice()),
        ("xss-indirect-style-control", b"<a attributename=style>".as_slice()),
        ("xss-indirect-black-positive", b"<a attributename=onclick>".as_slice()),
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
struct DifferentialResult {
    mismatches: Vec<String>,
    diagnostic_examples: Vec<String>,
    comparisons: usize,
    oracle_errors: usize,
    accepted_exceptions: usize,
    diagnostic_differences: usize,
}

fn compare_case(id: &str, input: &[u8], response: &str, result: &mut DifferentialResult) {
    let fields: Vec<&str> = response.split('\t').collect();
    if fields.len() != ORACLE_FIELDS || fields.first().copied() != Some(id) {
        result.oracle_errors += 1;
        result.mismatches.push(mismatch(
            id,
            input,
            "protocol",
            &format!("{ORACLE_FIELDS} fields for {id}"),
            response,
        ));
        return;
    }
    if !fields[1].is_empty() {
        result.oracle_errors += fields[1].split(';').count();
        result.mismatches.push(mismatch(
            id,
            input,
            "oracle-error",
            "no errors from the pinned Go implementation",
            fields[1],
        ));
    }

    let fingerprint = libperfusion::sqli(input);
    let public_values = [
        if fingerprint.is_some() {
            "1".to_owned()
        } else {
            "0".to_owned()
        },
        fingerprint.as_ref().map_or_else(
            || ":0".to_owned(),
            |value| format!("{}:{:x}", hex_encode(value.as_bytes()), value.as_bytes().len()),
        ),
        if libperfusion::xss(input) {
            "1".to_owned()
        } else {
            "0".to_owned()
        },
    ];
    for (field_index, actual) in [2, 3, 21].into_iter().zip(public_values.iter()) {
        result.comparisons += 1;
        let expected = fields.get(field_index).copied().unwrap_or("<missing>");
        if expected == actual {
            continue;
        }
        if let Some((expected_exception, actual_exception, count_exception)) =
            reviewed_perfusion_deviation(id, input, field_index)
            && expected == expected_exception
            && actual == actual_exception
        {
            if count_exception {
                result.accepted_exceptions += 1;
            }
            continue;
        }
        result.mismatches.push(mismatch(
            id,
            input,
            &format!("public-result[field={field_index}]"),
            expected,
            actual,
        ));
    }

    for (context_index, (quote, dialect)) in SQL_CONTEXTS.into_iter().enumerate() {
        let raw = sql_stream(input, quote, dialect, false);
        record_diagnostic(id, input, 4 + context_index, &fields, &raw, result);
        let folded = sql_stream(input, quote, dialect, true);
        record_diagnostic(id, input, 10 + context_index, &fields, &folded, result);
    }
    for (context_index, context) in HTML_CONTEXTS.into_iter().enumerate() {
        let stream = html_stream(input, context);
        record_diagnostic(id, input, 16 + context_index, &fields, &stream, result);
    }
}

fn reviewed_perfusion_deviation(
    id: &str,
    input: &[u8],
    field_index: usize,
) -> Option<(&'static str, &'static str, bool)> {
    if id == "sql-nul-after-hex-prefix" && input == b"1 or 0x\0\x31=1-- " {
        return match field_index {
            2 => Some(("0", "1", true)),
            3 => Some((":0", "31263163:4", false)),
            _ => None,
        };
    }
    if id == "sql-nul-after-hex-prefix-hash" && input == b"'=0X\0#" {
        return match field_index {
            2 => Some(("0", "1", true)),
            3 => Some((":0", "736f3163:4", false)),
            _ => None,
        };
    }
    // `<math>` is in the local XSS tag supplement, so these four flag where
    // Go main allows. The pinned C reference agrees with libperfusion on all
    // four; see `tests/parity/mismatch-ledger.md`.
    if field_index == 21
        && C_XSS_SAMPLE_VERDICTS
            .iter()
            .any(|(case_id, case_input, c_result, rust_result)| {
                id == *case_id && input == *case_input && *c_result && *rust_result
            })
    {
        return Some(("0", "1", true));
    }
    None
}

fn sql_stream(input: &[u8], quote: Quote, dialect: Dialect, folded: bool) -> String {
    let (stats, tokens) = if folded {
        let mut state = SqlState::new(input);
        let tokens = state.fold(quote, dialect).map(sql_token).collect::<Vec<_>>();
        (state.stats(), tokens)
    } else {
        let mut lexer = SqlTokenizer::new(input, quote, dialect);
        let tokens = lexer.by_ref().map(sql_token).collect::<Vec<_>>();
        (lexer.stats(), tokens)
    };
    format!(
        "{},{},{},{};{}",
        stats.tokens,
        stats.folds,
        stats.comment_ddx,
        stats.comment_hash,
        tokens.join(";")
    )
}

fn sql_token(token: SqlToken) -> String {
    format!(
        "{:02x}:{}:{}:{}:{:02x}:{:02x}:{}",
        token.kind().as_byte(),
        token.pos(),
        token.len(),
        token.variable_count(),
        token.string_open().unwrap_or(0),
        token.string_close().unwrap_or(0),
        hex_encode(token.value())
    )
}

fn html_stream(input: &[u8], context: HtmlContext) -> String {
    HtmlTokenizer::new(input, context)
        .map(|token| {
            let kind = match token.kind {
                HtmlTokenKind::DataText => 0,
                HtmlTokenKind::TagNameOpen => 1,
                HtmlTokenKind::TagNameClose => 2,
                HtmlTokenKind::TagNameSelfClose => 3,
                HtmlTokenKind::TagClose => 5,
                HtmlTokenKind::AttrName => 6,
                HtmlTokenKind::AttrValue => 7,
                HtmlTokenKind::TagComment => 8,
                HtmlTokenKind::Doctype => 9,
            };
            format!("{kind}:{}:{}", token.text.len(), hex_encode(token.text))
        })
        .collect::<Vec<_>>()
        .join(";")
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keeps each oracle comparison value explicit at the call site."
)]
fn record_diagnostic(
    id: &str,
    input: &[u8],
    field_index: usize,
    fields: &[&str],
    actual: &str,
    result: &mut DifferentialResult,
) {
    result.comparisons += 1;
    let expected = fields.get(field_index).copied().unwrap_or("<missing>");
    if expected == actual {
        return;
    }
    result.diagnostic_differences += 1;
    if result.diagnostic_examples.len() < 12 {
        result.diagnostic_examples.push(mismatch(
            id,
            input,
            &format!("token-stream[field={field_index}]"),
            expected,
            actual,
        ));
    }
}

fn mismatch(id: &str, input: &[u8], layer: &str, expected: &str, actual: &str) -> String {
    format!(
        "case={id}\nlayer={layer}\ninput_hex={}\nexpected={expected:?}\nactual={actual:?}",
        hex_encode(input)
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("write hex byte");
    }
    out
}
