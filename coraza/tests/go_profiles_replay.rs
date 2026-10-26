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

//! Replays Go Coraza's engine test profiles against this crate.
//!
//! The fixture is generated from the Go module pinned in
//! `tests/go_profiles/exporter/go.mod`; see `tests/go_profiles/README.md`. Go builds a
//! WAF per stage; this harness compiles one per profile and reuses it across stages,
//! which is equivalent because `Waf` is immutable and every stage gets a fresh
//! transaction. Each stage mirrors the Go runner's lifecycle (`testing/engine.go`) and
//! compares matched rule IDs, the interruption, and the error-log text.

#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]
#![expect(
    clippy::expect_used,
    reason = "the generated fixture is trusted and stage failures are the test output"
)]
#![expect(
    clippy::print_stdout,
    reason = "the report is the artifact this harness exists to produce"
)]

use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
};

use coraza::{Waf, seclang::Parser};
use serde_json::Value;

const FIXTURE: &str = include_str!("go_profiles/profiles.json");
const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/go_profiles/data");
/// Files the `operators_with_files` profile loads through `@pmFromFile`/`@ipMatchFromFile`.
const DATA_FILES: [&str; 3] = ["netranges-01.dat", "netranges-02.dat", "pmFromFile-01.dat"];
/// Go module release the fixture was exported from.
const FIXTURE_VERSION: &str = "v3.8.1";
/// Build tags of the exported profile set: the upstream default build.
const FIXTURE_BUILD_TAGS: &str = "default";
/// Profiles registered by the default build.
const FIXTURE_PROFILES: usize = 49;
/// Stages those profiles hold.
const FIXTURE_STAGES: usize = 120;

/// One expectation the engine did not meet.
struct Mismatch {
    /// Profile from the fixture.
    profile: String,
    /// Stage label, `test title / stage index`.
    stage: String,
    /// What differed.
    detail: String,
}

/// What the cooked transaction produced for one stage.
struct Actual {
    matched: Vec<i64>,
    logs: Vec<String>,
    interruption: Option<(i64, String, i64, String)>,
}

#[test]
fn replays_go_engine_profiles() {
    let document: Value = serde_json::from_str(FIXTURE).expect("fixture is JSON");
    let profiles = fixture(&document);

    let mut mismatches = Vec::new();
    let mut parse_failures: Vec<(String, String)> = Vec::new();
    let mut stages = 0_usize;
    let mut passed_stages = 0_usize;
    let mut passed_profiles = 0_usize;

    for profile in profiles {
        let name = text(profile, "name").to_owned();
        let rules = text(profile, "rules");
        let logs = Arc::new(Mutex::new(Vec::new()));
        let waf = match compile_profile(&name, rules, Arc::clone(&logs)) {
            Ok(waf) => waf,
            Err(error) => {
                parse_failures.push((name.clone(), error));
                continue;
            },
        };

        let mut failed = false;
        let tests = profile.get("tests").and_then(Value::as_array).expect("tests array");
        for test in tests {
            let title = text(test, "title");
            let test_stages = test.get("stages").and_then(Value::as_array).expect("stages array");
            for (index, stage) in test_stages.iter().enumerate() {
                stages += 1;
                let label = format!("{title} / stage {index}");
                let actual = run_stage(&waf, stage, &logs);
                let stage_mismatches = compare(stage, &actual);
                if stage_mismatches.is_empty() {
                    passed_stages += 1;
                } else {
                    failed = true;
                    for detail in stage_mismatches {
                        mismatches.push(Mismatch {
                            profile: name.clone(),
                            stage: label.clone(),
                            detail,
                        });
                    }
                }
            }
        }
        if failed {
            println!("FAIL {name}");
        } else {
            passed_profiles += 1;
            println!("PASS {name}");
        }
    }

    for failure in &parse_failures {
        println!("FAIL {} (does not compile): {}", failure.0, failure.1);
    }
    for mismatch in &mismatches {
        println!("  {} [{}]: {}", mismatch.profile, mismatch.stage, mismatch.detail);
    }
    println!(
        "go engine profiles: {} profiles, {} parsed, {} passed, {} stages, {} stages passed, {} parser rejections, {} mismatches",
        profiles.len(),
        profiles.len() - parse_failures.len(),
        passed_profiles,
        stages,
        passed_stages,
        parse_failures.len(),
        mismatches.len(),
    );

    assert!(
        mismatches.is_empty() && parse_failures.is_empty(),
        "Go profile replay: {} profiles parsed, {} passed, {} of {} stages passed, {} parser rejections, {} mismatches (above)",
        profiles.len() - parse_failures.len(),
        passed_profiles,
        passed_stages,
        stages,
        parse_failures.len(),
        mismatches.len(),
    );
}

/// Check the fixture's identity and inventory, returning its profiles.
fn fixture(document: &Value) -> &[Value] {
    let source = document.get("source").expect("source");
    assert_eq!(
        text(source, "version"),
        FIXTURE_VERSION,
        "fixture was exported from a different Go module version; regenerate it"
    );
    assert_eq!(
        text(source, "build_tags"),
        FIXTURE_BUILD_TAGS,
        "fixture was exported from a different build-tag set; regenerate it"
    );
    let profiles = document
        .get("profiles")
        .and_then(Value::as_array)
        .expect("profiles array");
    assert_eq!(
        profiles.len(),
        FIXTURE_PROFILES,
        "the fixture profile inventory changed; regenerate it"
    );
    let stages: usize = profiles
        .iter()
        .map(|profile| {
            profile
                .get("tests")
                .and_then(Value::as_array)
                .expect("tests array")
                .iter()
                .map(|test| {
                    test.get("stages")
                        .and_then(Value::as_array)
                        .expect("stages array")
                        .len()
                })
                .sum::<usize>()
        })
        .sum();
    assert_eq!(
        stages, FIXTURE_STAGES,
        "the fixture stage inventory changed; regenerate it"
    );
    profiles
}

/// Compile one profile's rules from a temp directory so file-backed operators resolve.
///
/// Every file-backed operator in the fixture reads its file while compiling, so the
/// directory can be dropped on return.
fn compile_profile(name: &str, rules: &str, logs: Arc<Mutex<Vec<String>>>) -> Result<Waf, String> {
    let dir = tempfile::Builder::new()
        .prefix("coraza-go-profile-")
        .tempdir()
        .map_err(|error| format!("temp dir: {error}"))?;
    for file in DATA_FILES {
        fs::copy(Path::new(DATA_DIR).join(file), dir.path().join(file))
            .map_err(|error| format!("copy {file}: {error}"))?;
    }
    let rules_path = dir.path().join("rules.conf");
    fs::write(&rules_path, rules).map_err(|error| format!("write rules: {error}"))?;

    let mut parser = Parser::new();
    parser.on_error_log(move |matched| {
        logs.lock().expect("log lock").push(matched.error_log());
    });
    parser
        .from_file(&rules_path)
        .map_err(|error| format!("parser rejected {name}: {error}"))?;
    parser.compile().map_err(|error| error.to_string())
}

/// Run one stage through the Go runner's lifecycle.
fn run_stage(waf: &Waf, stage: &Value, logs: &Mutex<Vec<String>>) -> Actual {
    logs.lock().expect("log lock").clear();

    let input = stage.get("input").expect("input");
    let output = stage.get("output").expect("output");
    let uri = defaulted(input, "uri", "/");
    let method = defaulted(input, "method", "GET");
    let request_body = text(input, "data");
    let response_body = text(output, "data");

    let mut transaction = waf.new_transaction();
    // The Go runner always calls ProcessConnection with these fixed request values.
    transaction.set_remote_addr("127.0.0.1");
    transaction.set_remote_port(80);
    transaction.set_server_addr(defaulted(input, "dest_addr", ""));
    transaction.set_server_port(0);
    transaction.process_uri(uri, method, "HTTP/1.1");
    for (key, value) in headers(input, "headers") {
        transaction.add_request_header(&key, value);
    }
    // The Go runner's magic content-length is set whenever a request body exists.
    if !request_body.is_empty() {
        transaction.add_request_header("content-length", request_body.len().to_string());
    }
    transaction.process_request_headers();
    transaction.process_request_body(request_body.as_bytes());
    // The Go runner replaces its default Content-Type only when a stage sets headers.
    let response_headers = headers(output, "headers");
    if response_headers.is_empty() {
        transaction.add_response_header("Content-Type", "text/html");
    } else {
        for (key, value) in response_headers {
            transaction.add_response_header(&key, value);
        }
    }
    transaction.process_response_headers(200, "HTTP/1.1");
    transaction.process_response_body(response_body.as_bytes());
    transaction.process_logging().expect("no audit sink is configured");

    Actual {
        matched: transaction
            .matched_rules()
            .iter()
            .map(|matched| i64::from(matched.rule_id()))
            .collect(),
        logs: logs.lock().expect("log lock").clone(),
        interruption: transaction.interruption().map(|value| {
            (
                i64::from(value.rule_id),
                value.action.clone(),
                i64::from(value.status),
                value.data.clone(),
            )
        }),
    }
}

/// Compare one stage's expectations with what the engine produced.
fn compare(stage: &Value, actual: &Actual) -> Vec<String> {
    let output = stage.get("output").expect("output");
    let mut differences = Vec::new();

    for expected in ids(output, "triggered_rules") {
        if !actual.matched.contains(&expected) {
            differences.push(format!(
                "triggered rule {expected} expected, actual matched {:?}",
                actual.matched
            ));
        }
    }
    for expected in ids(output, "non_triggered_rules") {
        if actual.matched.contains(&expected) {
            differences.push(format!(
                "rule {expected} expected not to match, actual matched {:?}",
                actual.matched
            ));
        }
    }

    let expected_interruption = output.get("interruption");
    match (expected_interruption, &actual.interruption) {
        (None, None) => {},
        (None, Some(interruption)) => differences.push(format!(
            "expected no interruption, actual {} status {} rule {}",
            interruption.1, interruption.2, interruption.0
        )),
        (Some(expected), None) => differences.push(format!(
            "expected interruption {} status {} rule {}, actual none",
            text(expected, "action"),
            number(expected, "status"),
            number(expected, "rule_id"),
        )),
        (Some(expected), Some(interruption)) => {
            if text(expected, "action") != interruption.1 {
                differences.push(format!(
                    "interruption action expected {:?}, actual {:?}",
                    text(expected, "action"),
                    interruption.1
                ));
            }
            if number(expected, "status") != interruption.2 {
                differences.push(format!(
                    "interruption status expected {}, actual {}",
                    number(expected, "status"),
                    interruption.2
                ));
            }
            if number(expected, "rule_id") != interruption.0 {
                differences.push(format!(
                    "interruption rule_id expected {}, actual {}",
                    number(expected, "rule_id"),
                    interruption.0
                ));
            }
            if text(expected, "data") != interruption.3 {
                differences.push(format!(
                    "interruption data expected {:?}, actual {:?}",
                    text(expected, "data"),
                    interruption.3
                ));
            }
        },
    }

    let log_contains = text(output, "log_contains");
    if !log_contains.is_empty() && !actual.logs.iter().any(|line| line.contains(log_contains)) {
        differences.push(format!("expected a log line containing {log_contains:?}"));
    }
    let no_log_contains = text(output, "no_log_contains");
    if !no_log_contains.is_empty() && actual.logs.iter().any(|line| line.contains(no_log_contains)) {
        differences.push(format!("expected no log line containing {no_log_contains:?}"));
    }

    differences
}

/// No fixture stage forbids a log line, so exercise that branch directly.
#[test]
fn no_log_contains_rejects_the_line_it_names() {
    let stage = serde_json::json!({ "output": { "no_log_contains": "forbidden marker" } });
    let mut actual = Actual {
        matched: Vec::new(),
        logs: vec!["a line with the forbidden marker".to_owned()],
        interruption: None,
    };
    let differences = compare(&stage, &actual);
    assert_eq!(
        differences,
        ["expected no log line containing \"forbidden marker\""],
        "a forbidden log line must be a mismatch"
    );

    actual.logs = vec!["an unrelated line".to_owned()];
    assert!(compare(&stage, &actual).is_empty(), "an absent line must pass");
}

/// A string field, or `""`.
fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

/// A string field with a fallback, matching the Go runner's defaults.
fn defaulted<'a>(value: &'a Value, key: &str, fallback: &'a str) -> &'a str {
    let found = text(value, key);
    if found.is_empty() { fallback } else { found }
}

/// An integer field, or zero.
fn number(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}

/// An array of rule IDs, or an empty list.
fn ids(value: &Value, key: &str) -> Vec<i64> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_i64).collect())
        .unwrap_or_default()
}

/// A stage's header map, in sorted order.
fn headers(value: &Value, key: &str) -> Vec<(String, String)> {
    value
        .get(key)
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .map(|(name, value)| (name.clone(), value.as_str().unwrap_or("").to_owned()))
                .collect()
        })
        .unwrap_or_default()
}
