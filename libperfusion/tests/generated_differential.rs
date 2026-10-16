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

//! Deterministic generated-input comparison against the Go module pinned in xtask/tools/go.mod.
#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]
#![expect(
    clippy::expect_used,
    reason = "the generated differential harness reports protocol failures"
)]
#![expect(clippy::panic, reason = "failure includes a minimized reproducible case")]
#![expect(clippy::print_stderr, reason = "failure details go to CI logs")]
use std::{io::Write as _, path::Path, process::Command, time::Duration};

#[path = "common/subprocess.rs"]
mod oracle_subprocess;

use oracle_subprocess::run_with_timeout;

const SEED: u64 = 0x947E_5A13_B06C_D281;
const ORACLE_TIMEOUT: Duration = Duration::from_secs(300);
const ALPHABET: &[u8] = b"abcXYZ012 ' \"`<>=/\\#-*;:&%\0\xff\x80\n\r";
const FRAGMENTS: [&[u8]; 23] = [
    b"SELECT",
    b"UNION",
    b"' OR '1'='1",
    b"-- ",
    b"/* comment */",
    b"#line",
    b"1e+",
    b"\\\"",
    b"&&",
    b"||",
    b"<script>",
    b"</script>",
    b"<a href=javascript:",
    b" onerror=alert(1)>",
    b"<!--",
    b"-->",
    b"<![CDATA[",
    b"]]>",
    b"&#x14a;",
    b"\0",
    b"\xff",
    b"/>",
    b"%>",
];

fn bounded_index(value: u64, len: usize) -> usize {
    let modulus = u64::try_from(len).unwrap_or(u64::MAX);
    usize::try_from(value % modulus).unwrap_or_default()
}

fn response_field<'a>(fields: &'a [&'a str], index: usize) -> &'a str {
    fields.get(index).copied().unwrap_or("<missing>")
}

#[derive(Clone)]
struct Case {
    id: String,
    input: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PublicResult {
    sqli: bool,
    fingerprint: String,
    xss: Option<bool>,
}

#[test]
#[ignore = "manual differential gate; requires the pinned Go module and 1.27.1 toolchain"]
fn generated_raw_bytes_and_grammars_match_go_with_minimized_failures() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cases = generated_cases();
    assert_eq!(cases.len(), 770, "generated case inventory changed");
    assert_eq!(cases.iter().filter(|case| case.id.starts_with("raw-")).count(), 384);
    assert_eq!(cases.iter().filter(|case| case.id.starts_with("grammar-")).count(), 384);
    assert_eq!(
        cases
            .iter()
            .filter(|case| case.id.starts_with("cdata-"))
            .map(|case| case.id.as_str())
            .collect::<Vec<_>>(),
        ["cdata-standalone-regression", "cdata-early-xss-regression"]
    );
    let responses = run_oracle(manifest_dir, &cases);
    let mut perfusion_failures = Vec::new();
    let mut perfusion_exceptions = 0_usize;
    let mut perfusion_fingerprint_diagnostics = 0_usize;

    for (case, response) in cases.iter().zip(responses.iter()) {
        let expected = parse_result(case, response);
        let perfusion = perfusion_result(&case.input);
        perfusion_fingerprint_diagnostics += usize::from(expected.fingerprint != perfusion.fingerprint);
        if is_reviewed_c_aligned_sql_improvement(case, &expected, &perfusion)
            || is_reviewed_hash_comment_deviation(case, &expected, &perfusion)
        {
            perfusion_exceptions += 1;
        } else if !results_match(&expected, &perfusion) {
            perfusion_failures.push((case.clone(), expected, perfusion));
        }
    }

    assert_eq!(perfusion_exceptions, 8, "libperfusion Go exception inventory changed");

    if perfusion_failures.is_empty() {
        eprintln!(
            "generated differential passed: {} deterministic raw/grammar/regression cases, libperfusion_exceptions={perfusion_exceptions}, fingerprint_diagnostics={perfusion_fingerprint_diagnostics}, seed=0x{SEED:016x}",
            cases.len(),
        );
        return;
    }

    let mut details = Vec::new();
    for (case, expected, actual) in perfusion_failures {
        let minimized = minimize_mismatch(manifest_dir, &case.input);
        let minimized_case = Case {
            id: "minimized".to_owned(),
            input: minimized.clone(),
        };
        let minimized_expected = parse_result(
            &minimized_case,
            run_oracle(manifest_dir, std::slice::from_ref(&minimized_case))
                .first()
                .map_or("<missing oracle result>", String::as_str),
        );
        let minimized_actual = perfusion_result(&minimized);
        details.push(format!(
            "case={} original_hex={} expected={expected:?} actual={actual:?}\n  minimized_hex={} minimized_expected={minimized_expected:?} minimized_actual={minimized_actual:?}",
            case.id,
            hex(&case.input),
            hex(&minimized),
        ));
    }
    panic!(
        "generated Go differential mismatches; seed=0x{SEED:016x}; add minimized bytes and the Go tool version/GOEXPERIMENT to tests/parity/mismatch-ledger.md:\n{}",
        details.join("\n")
    );
}

/// Generated inputs where the narrowed `#` comment whitelist makes
/// libperfusion report the `sc` fingerprint that Go main suppresses.
///
/// Each one minimizes to `'#` or `"#`, the shape of the `admin'#`
/// authentication bypass. The deviation is deliberate and is described in
/// `tests/parity/mismatch-ledger.md`; the inputs are pinned by hex, so an
/// unrelated new difference still fails the gate.
const HASH_COMMENT_SQL_DEVIATIONS: [(&str, &str); 7] = [
    (
        "raw-0043",
        "20233c5a622a0d603b3a302020583e3b266026ff323a805a5aff2522235920005a5c3222302623302f",
    ),
    ("raw-0060", "303d32ff0a003a22235a305a25005a2d23205c602aff20"),
    ("raw-0075", "27232580630d3e266331ff58633dff632058632023203e592a316332"),
    ("raw-0227", "2320800d3c3a3e253e2d25602223233d592d2259"),
    (
        "raw-0292",
        "62272f260d603b5a5a61585c25ff0d26ff2080302f3032805c603b3b3b2a582223",
    ),
    (
        "raw-0365",
        "2f23800d6100603200303c2f3e235a32318030000a590a3c2f2d32ff632f20582f2560265a5a2060205a3b003e3e30ff63005932270a25592761ff275a003e630d3b3c6127610a2220233e003000592f0d00302d203a0d2062603e",
    ),
    (
        "raw-0373",
        "633a202a26300a302a6120ff3c3d3e3a3b20325858303e5aff3c233222000d5c6031272023625cffff31633d3c5c63268058203b3c63613b3e32263c2d",
    ),
];

fn is_reviewed_c_aligned_sql_improvement(case: &Case, expected: &PublicResult, actual: &PublicResult) -> bool {
    case.id == "raw-0265"
        && case.input
            == [
                0x3D, 0x2F, 0x59, 0x32, 0x20, 0x0A, 0x27, 0x3D, 0x63, 0x30, 0x0A, 0x30, 0x58, 0x00, 0x23, 0x58, 0x59,
                0x2D, 0x62, 0x25, 0x5C, 0x60, 0x3E, 0x59, 0x20, 0x60, 0x20, 0x20, 0x25, 0x61, 0x2A,
            ]
        && !expected.sqli
        && expected.xss == Some(false)
        && actual.sqli
        && actual.xss == Some(false)
}

/// The `'#`/`"#` fingerprint deviations listed in
/// [`HASH_COMMENT_SQL_DEVIATIONS`], and only those.
fn is_reviewed_hash_comment_deviation(case: &Case, expected: &PublicResult, actual: &PublicResult) -> bool {
    HASH_COMMENT_SQL_DEVIATIONS
        .iter()
        .any(|(id, input_hex)| case.id == *id && hex(&case.input) == *input_hex)
        && !expected.sqli
        && actual.sqli
        && actual.fingerprint == "7363:2"
        && expected.xss == actual.xss
}

fn generated_cases() -> Vec<Case> {
    let mut cases = Vec::with_capacity(768);
    let mut state = SEED;
    for index in 0..384 {
        let len = bounded_index(next(&mut state), 129);
        let mut input = Vec::with_capacity(len);
        for _ in 0..len {
            let char_index = bounded_index(next(&mut state), ALPHABET.len());
            input.push(ALPHABET.get(char_index).copied().unwrap_or_default());
        }
        cases.push(Case {
            id: format!("raw-{index:04}"),
            input,
        });
    }
    for index in 0..384 {
        let count = 1 + bounded_index(next(&mut state), 8);
        let mut input = Vec::new();
        for _ in 0..count {
            let fragment_index = bounded_index(next(&mut state), FRAGMENTS.len());
            input.extend_from_slice(FRAGMENTS.get(fragment_index).copied().unwrap_or_default());
            if next(&mut state) & 1 == 0 {
                input.push(b' ');
            }
        }
        cases.push(Case {
            id: format!("grammar-{index:04}"),
            input,
        });
    }
    cases.push(Case {
        id: "cdata-standalone-regression".to_owned(),
        input: b"<![CDATA[]]]".to_vec(),
    });
    cases.push(Case {
        id: "cdata-early-xss-regression".to_owned(),
        input: b"<script><![CDATA[]]]".to_vec(),
    });
    cases
}

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn run_oracle(manifest_dir: &Path, cases: &[Case]) -> Vec<String> {
    let oracle = manifest_dir.join("tools/parity/go-oracle");
    let mut request = Vec::new();
    for case in cases {
        writeln!(&mut request, "{}\t{}", case.id, hex(&case.input)).expect("write request");
    }
    let mut command = Command::new(oracle);
    let output = run_with_timeout(&mut command, &request, ORACLE_TIMEOUT)
        .unwrap_or_else(|error| panic!("run Go oracle within deadline: {error}"));
    assert!(
        output.status.success(),
        "Go oracle failed; version/platform diagnostics follow: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    if !diagnostics.trim().is_empty() {
        eprintln!("Go oracle toolchain/source diagnostics:\n{}", diagnostics.trim());
    }
    let stdout = std::str::from_utf8(&output.stdout).expect("oracle protocol is ASCII");
    let responses: Vec<String> = stdout.lines().map(str::to_owned).collect();
    assert_eq!(responses.len(), cases.len(), "oracle returned a different case count");
    responses
}

fn parse_result(case: &Case, line: &str) -> PublicResult {
    let fields: Vec<&str> = line.split('\t').collect();
    assert_eq!(fields.len(), 22, "{}: malformed Go response: {line:?}", case.id);
    assert_eq!(response_field(&fields, 0), case.id, "case order/id mismatch");
    let errored_fields = assert_known_oracle_errors(case, response_field(&fields, 1));
    for &field in &errored_fields {
        assert!(
            response_field(&fields, field).is_empty(),
            "{}: errored field {field} must be empty",
            case.id
        );
    }
    let fingerprint = response_field(&fields, 3).to_owned();
    assert!(
        response_field(&fields, 2) == "0" || response_field(&fields, 2) == "1",
        "{}: invalid SQL boolean",
        case.id
    );
    let xss = if errored_fields.contains(&21) {
        assert!(
            response_field(&fields, 21).is_empty(),
            "{}: errored XSS field must be empty",
            case.id
        );
        None
    } else {
        assert!(
            response_field(&fields, 21) == "0" || response_field(&fields, 21) == "1",
            "{}: invalid XSS boolean",
            case.id
        );
        Some(response_field(&fields, 21) == "1")
    };
    PublicResult {
        sqli: response_field(&fields, 2) == "1",
        fingerprint,
        xss,
    }
}

fn assert_known_oracle_errors(case: &Case, errors: &str) -> Vec<usize> {
    assert!(
        errors.is_empty(),
        "{}: the pinned libinjection-go module returned an error {errors:?}; input_hex={}",
        case.id,
        hex(&case.input)
    );
    Vec::new()
}

fn perfusion_result(input: &[u8]) -> PublicResult {
    let fingerprint = libperfusion::sqli(input);
    PublicResult {
        sqli: fingerprint.is_some(),
        fingerprint: fingerprint.as_ref().map_or_else(
            || ":0".to_owned(),
            |value| format!("{}:{:x}", hex(value.as_bytes()), value.as_bytes().len()),
        ),
        xss: Some(libperfusion::xss(input)),
    }
}

fn results_match(expected: &PublicResult, actual: &PublicResult) -> bool {
    go_hits_are_rust_hits(expected, actual)
        && expected.sqli == actual.sqli
        && expected.xss.is_none_or(|xss| actual.xss == Some(xss))
}

fn go_hits_are_rust_hits(expected: &PublicResult, actual: &PublicResult) -> bool {
    (!expected.sqli || actual.sqli) && expected.xss.is_none_or(|go_hit| !go_hit || actual.xss == Some(true))
}

#[test]
fn public_verdict_contract_preserves_go_hits_and_keeps_fingerprints_diagnostic() {
    let go_hit = PublicResult {
        sqli: true,
        fingerprint: "go-fingerprint".to_owned(),
        xss: Some(false),
    };
    let rust_superset = PublicResult {
        sqli: true,
        fingerprint: "different-diagnostic-fingerprint".to_owned(),
        xss: Some(true),
    };
    assert!(go_hits_are_rust_hits(&go_hit, &rust_superset));
    assert!(!results_match(&go_hit, &rust_superset));
    assert_ne!(go_hit.fingerprint, rust_superset.fingerprint);

    let rust_miss = PublicResult {
        sqli: false,
        fingerprint: ":0".to_owned(),
        xss: Some(false),
    };
    assert!(!go_hits_are_rust_hits(&go_hit, &rust_miss));
}

fn minimize_mismatch(manifest_dir: &Path, original: &[u8]) -> Vec<u8> {
    let mut current = original.to_vec();
    let mut granularity = 2_usize;
    for _ in 0..32 {
        if current.is_empty() {
            break;
        }
        let chunk_size = current.len().div_ceil(granularity);
        let mut candidates = Vec::new();
        for chunk_start in (0..current.len()).step_by(chunk_size) {
            let chunk_end = (chunk_start + chunk_size).min(current.len());
            let mut candidate = current.get(..chunk_start).unwrap_or_default().to_vec();
            candidate.extend_from_slice(current.get(chunk_end..).unwrap_or_default());
            candidates.push(Case {
                id: format!("shrink-{}", candidates.len()),
                input: candidate,
            });
        }
        let responses = run_oracle(manifest_dir, &candidates);
        let mismatch = candidates.iter().zip(responses.iter()).find(|(case, response)| {
            let expected = parse_result(case, response);
            !results_match(&expected, &perfusion_result(&case.input))
        });
        if let Some((case, _)) = mismatch {
            current.clone_from(&case.input);
            granularity = granularity.saturating_sub(1).max(2);
        } else if granularity >= current.len() {
            break;
        } else {
            granularity = (granularity * 2).min(current.len());
        }
    }
    current
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(
            DIGITS.get(usize::from(byte >> 4)).copied().unwrap_or_default(),
        ));
        output.push(char::from(
            DIGITS.get(usize::from(byte & 0x0F)).copied().unwrap_or_default(),
        ));
    }
    output
}
