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
//
// This port is based on the original Coraza, created by Juan Pablo Tosso and
// the OWASP Coraza contributors.
//
// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Executable replay of Go Coraza's operator corpus.
//!
//! `coraza/tests/go_operators` holds the 29 files Go Coraza v3.8.1 keeps in
//! `internal/operators/testdata`, plus the `op/` data files they reference. Every `type == "op"`
//! case names an operator, its argument, an input, and the verdict Go records for it. This
//! harness builds the operator through the real factory and compares its verdict with the
//! recorded one, so a difference between this port and Go shows up as a test failure instead of
//! an assumption.
//!
//! A case whose operator needs something the fixture does not provide (the schema file) is
//! skipped, and the skips are counted by reason with the total pinned. A case whose expected
//! verdict depends on Go semantics the factory does not implement is skipped the same way: the
//! point is to measure, not to paper over a difference.

#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]
#![expect(
    clippy::unwrap_used,
    reason = "the pinned corpus is trusted; a fixture read failure is the test failing"
)]
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use coraza::{
    Waf,
    operators::{OperatorContext, OperatorEnum, OperatorOutcome, Outputs},
};

/// Number of JSON files Go Coraza v3.8.1 ships in `internal/operators/testdata`.
const FIXTURE_FILES: usize = 29;
/// Number of `type == "op"` cases those 29 files hold.
const FIXTURE_CASES: usize = 3934;
/// Cases that must stay unexecuted: the five operators the factory does not implement, plus the
/// five schema cases Go's testdata cannot load either.
const FIXTURE_SKIPPED: usize = 98;
/// Skip reason for a name [`OperatorEnum::with_context`] does not know.
const UNKNOWN_OPERATOR: &str = "operator name is unknown to the factory";

/// One corpus entry, decoded the way Go's `operators.Test` struct is.
struct Case {
    /// `name`: the operator name, without `@`.
    operator: String,
    /// `param`: the SecLang argument the operator is built with.
    param: String,
    /// `input`: the value the operator evaluates.
    input: String,
    /// `type`: the case kind, `op` for every case in this corpus.
    kind: String,
    /// `ret`: 1 when the case expects a match, 0 when it expects none.
    ret: i64,
}

/// Per-file tally of what the harness did with the cases.
#[derive(Default)]
struct Counts {
    /// Cases the harness evaluated (passed plus failed).
    executed: usize,
    /// Cases the harness did not evaluate.
    skipped: usize,
    /// Evaluated cases whose verdict matched Go's `ret`.
    passed: usize,
    /// Evaluated cases whose verdict differed from Go's `ret`.
    failed: usize,
}

impl Counts {
    /// Fold `other` into this tally.
    fn absorb(&mut self, other: &Self) {
        self.executed += other.executed;
        self.skipped += other.skipped;
        self.passed += other.passed;
        self.failed += other.failed;
    }
}

/// What the harness did with one case.
enum CaseResult {
    /// The operator's verdict agreed with `ret`.
    Passed,
    /// The operator's verdict disagreed with `ret`, or the factory rejected a known name.
    Failed(String),
    /// The case cannot be replayed faithfully; the reason is reported, not asserted.
    Skipped(&'static str),
}

/// Replay the vendored corpus and fail on any case whose verdict differs from Go's.
#[test]
#[expect(
    clippy::print_stdout,
    reason = "the harness prints its per-operator table so the reviewer sees the measurement"
)]
fn go_corpus_matches_go_operator_expectations() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/go_operators");
    let files = fixture_files(&dir).unwrap();
    assert_eq!(files.len(), FIXTURE_FILES, "the vendored corpus inventory changed");

    let waf = Waf::default();
    let operator_dir = dir.join("op");
    let mut context = OperatorContext::default();
    context.base_dir = &operator_dir;
    let mut rows = Vec::with_capacity(files.len());
    let mut skips: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut failures = Vec::new();
    let mut total = Counts::default();
    let mut cases_seen = 0;

    for path in &files {
        let Ok(cases) = read_cases(path) else {
            failures.push(format!("{}: unreadable fixture", path.display()));
            continue;
        };
        cases_seen += cases.len();
        let mut counts = Counts::default();
        for case in &cases {
            match run_case(&waf, &context, case) {
                CaseResult::Passed => {
                    counts.executed += 1;
                    counts.passed += 1;
                },
                CaseResult::Failed(message) => {
                    counts.executed += 1;
                    counts.failed += 1;
                    failures.push(message);
                },
                CaseResult::Skipped(reason) => {
                    counts.skipped += 1;
                    *skips.entry((case.operator.clone(), reason.to_owned())).or_default() += 1;
                },
            }
        }
        total.absorb(&counts);
        rows.push((file_label(path), counts));
    }

    println!(
        "Go Coraza v3.8.1 operator corpus: {cases_seen} cases in {} files",
        files.len()
    );
    println!(
        "{:<22}{:>9}{:>9}{:>8}{:>8}",
        "operator file", "executed", "skipped", "passed", "failed"
    );
    for (label, counts) in &rows {
        println!(
            "{label:<22}{:>9}{:>9}{:>8}{:>8}",
            counts.executed, counts.skipped, counts.passed, counts.failed
        );
    }
    println!(
        "{:<22}{:>9}{:>9}{:>8}{:>8}",
        "total", total.executed, total.skipped, total.passed, total.failed
    );

    if !skips.is_empty() {
        println!("\nskipped cases by operator and reason:");
        for ((operator, reason), count) in &skips {
            println!("  {operator:<16}{count:>5}  {reason}");
        }
    }

    assert_eq!(cases_seen, FIXTURE_CASES, "the vendored corpus size changed");
    assert_eq!(total.skipped, FIXTURE_SKIPPED, "the set of unreplayable cases changed");
    let count = failures.len();
    let details = failures.join("\n  ");
    assert!(
        failures.is_empty(),
        "{count} Go operator corpus mismatches:\n  {details}"
    );
}

/// Replay one case, returning whether it agreed with Go.
fn run_case(waf: &Waf, context: &OperatorContext<'_>, case: &Case) -> CaseResult {
    let Case {
        operator: name,
        param,
        input,
        kind,
        ret,
    } = case;
    if kind != "op" {
        return CaseResult::Skipped("case type is not an operator case");
    }
    if let Some(reason) = skip_reason(name) {
        return CaseResult::Skipped(reason);
    }
    let input = decode_field(input);
    let Ok(param) = String::from_utf8(decode_field(param)) else {
        return CaseResult::Skipped("parameter is not UTF-8 after Go string unquoting");
    };
    let operator = match OperatorEnum::with_context(name, &param, context) {
        Ok(operator) => operator,
        Err(error) if error.starts_with("unknown operator:") => return CaseResult::Skipped(UNKNOWN_OPERATOR),
        Err(error) => return CaseResult::Failed(format!("{name}: param {param:?}: factory error: {error}")),
    };
    let tx = waf.new_transaction();
    let actual = match operator.evaluate_outcome(&tx, &input, &mut Outputs::default()) {
        OperatorOutcome::Matched => 1,
        OperatorOutcome::NotMatched => 0,
        OperatorOutcome::NotInspected => {
            return CaseResult::Skipped("the detector skipped the input as too large to inspect");
        },
    };
    if actual == *ret {
        CaseResult::Passed
    } else {
        let shown = String::from_utf8_lossy(&input);
        CaseResult::Failed(format!(
            "{name}: param {param:?}, input {shown:?}: expected ret {ret}, got {actual}"
        ))
    }
}

/// Why a case cannot be replayed here, or `None` when it can.
fn skip_reason(name: &str) -> Option<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "validateschema" => Some("needs the corpus schema file, which is not vendored"),
        _ => None,
    }
}

/// Decode the Go string escapes a corpus field carries, as Go's test loop does.
///
/// The corpus stores `\u0000` and `\xNN` as literal sequences. Go replaces the former with a NUL
/// byte and then unquotes any field that contains `\x`; fields without `\x` stay literal, including
/// the `\0` that `endsWith.json` uses.
fn decode_field(raw: &str) -> Vec<u8> {
    let replaced = raw.replace("\\u0000", "\0");
    if !replaced.contains("\\x") {
        return replaced.into_bytes();
    }
    decode_hex_escapes(&replaced)
}

/// Decode `\xNN` escapes, leaving every other byte exactly as written.
fn decode_hex_escapes(value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    let mut rest = value.as_bytes();
    while let Some((&first, tail)) = rest.split_first() {
        let hex_escape = (first == b'\\' && tail.first() == Some(&b'x')).then(|| {
            tail.get(1..3)
                .and_then(|digits| std::str::from_utf8(digits).ok())
                .and_then(|digits| u8::from_str_radix(digits, 16).ok())
        });
        if let Some(byte) = hex_escape.flatten() {
            out.push(byte);
            rest = tail.get(3..).unwrap_or_default();
        } else {
            out.push(first);
            rest = tail;
        }
    }
    out
}

/// The fixture files of `dir`, sorted so the printed table is stable.
fn fixture_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = std::fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry.map_err(|error| format!("{}: {error}", dir.display()))?.path();
        if path.extension().is_some_and(|extension| extension == "json") {
            paths.push(path);
        }
    }
    paths.sort_unstable();
    Ok(paths)
}

/// Parse one fixture file into its cases.
#[expect(
    clippy::expect_used,
    reason = "every vendored case carries ret; a missing field means the fixture is corrupt"
)]
fn read_cases(path: &Path) -> Result<Vec<Case>, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let parsed: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    let Some(entries) = parsed.as_array() else {
        return Err(format!("{}: expected a JSON array of cases", path.display()));
    };
    Ok(entries
        .iter()
        .map(|entry| Case {
            operator: text_field(entry, "name"),
            param: text_field(entry, "param"),
            input: text_field(entry, "input"),
            kind: text_field(entry, "type"),
            ret: entry.get("ret").and_then(serde_json::Value::as_i64).expect("ret"),
        })
        .collect())
}

/// Read a string member of one case, defaulting to empty like Go's decoder does.
fn text_field(entry: &serde_json::Value, key: &str) -> String {
    entry
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The operator file name shown in the table, without its directory or extension.
fn file_label(path: &Path) -> String {
    path.file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default()
        .to_owned()
}
