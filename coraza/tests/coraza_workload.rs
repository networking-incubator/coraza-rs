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

//! Focused tests for the shared workload layer and the Rust driver.

#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]
#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions fail the test with the invalid fixture context"
)]
#![expect(clippy::indexing_slicing, reason = "test fixtures are checked before indexing")]

#[path = "../benches/coraza_workload/driver.rs"]
mod driver;

use std::{
    fs,
    path::{Path, PathBuf},
};

use driver::{
    compare_expected, load_workload, outcome_document, parse_case_bytes, parse_iterations, run_case, run_timing,
    sha256_hex, timing_document, write_outcomes, write_timing_document,
};
use serde_json::{Value, json};

/// Directory holding the shared workload.
fn workload_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../benchmarks/coraza/workloads")
}

/// Reads one shipped case as raw bytes.
fn shipped_case(name: &str) -> Vec<u8> {
    let path = workload_root().join("cases").join(name);
    fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// Returns a minimal case that satisfies the canonical lifecycle.
fn minimal_case() -> Value {
    json!({
        "schema_version": 1,
        "case_id": "minimal",
        "fixture_sha256": sha256_hex(b"ok"),
        "reference": {
            "profile": "test",
            "go_commit": "d9cc9befc2721fd217ce1660a0e91aca1157221d",
            "rust_commit": "e078282328dce075ad8b421bf052aa1f7190c6ec"
        },
        "connection": {
            "remote_addr": "203.0.113.7",
            "remote_port": 50000,
            "local_addr": "192.0.2.10",
            "local_port": 8080,
            "tls": false,
            "tls_version": null
        },
        "request": {
            "method": "GET",
            "uri": {"base64": "Lw=="},
            "protocol": "HTTP/1.1",
            "headers": [],
            "body": {"base64": ""},
            "chunks": []
        },
        "response": {
            "status": 200,
            "protocol": "HTTP/1.1",
            "headers": [],
            "body": {"base64": "b2s="},
            "chunks": [{"offset": 0, "length": 2}]
        },
        "processor": {
            "sec_lang": {"utf8": "SecRuleEngine On\n"},
            "request_body_processor": "auto",
            "response_body_processor": "auto",
            "config": {}
        },
        "phase_calls": [
            {"call": "process_connection", "phase": 1},
            {"call": "process_uri", "phase": 1},
            {"call": "process_request_headers", "phase": 1},
            {"call": "process_request_body", "phase": 2},
            {"call": "process_response_headers", "phase": 3},
            {"call": "append_response_body", "phase": 4, "chunk_index": 0},
            {"call": "process_response_body", "phase": 4},
            {"call": "process_logging", "phase": 5}
        ],
        "expected": {
            "matches": [],
            "interruptions": [],
            "captures": [],
            "scores": {},
            "flags": {},
            "collections": [],
            "audit": {"required": false, "parts": "", "entries": 0}
        },
        "normalize": ["timestamps"]
    })
}

#[test]
fn workload_loads_and_validates_hashes_and_ranges() {
    let workload = load_workload(&workload_root()).expect("shipped workload must load");
    let ids = workload
        .cases
        .iter()
        .map(|prepared| prepared.case.case_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        [
            "get-benign",
            "get-attack",
            "form-benign",
            "form-attack",
            "json-benign",
            "json-attack",
        ],
        "the manifest must list the complete common subset in order"
    );
}

#[test]
fn driver_matches_every_expected_outcome() {
    let workload = load_workload(&workload_root()).expect("shipped workload must load");
    for prepared in &workload.cases {
        let outcome = run_case(prepared).expect("case must run");
        compare_expected(&prepared.case, &outcome)
            .unwrap_or_else(|error| panic!("case {}: {error}", prepared.case.case_id));
    }
}

#[test]
fn outcome_documents_are_emitted_as_ndjson() {
    let workload = load_workload(&workload_root()).expect("shipped workload must load");
    let cases = &workload.cases;
    let mut documents = Vec::new();
    for prepared in cases {
        let outcome = run_case(prepared).expect("case must run");
        documents.push(outcome_document(&prepared.case, &outcome));
    }
    let temporary = tempfile::tempdir().expect("create temporary directory");
    let path = temporary.path().join("outcomes.ndjson");
    write_outcomes(&path, &documents).expect("write outcomes");
    let text = fs::read_to_string(&path).expect("read outcomes");

    let lines = text.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), cases.len(), "one outcome line per case");
    for (line, prepared) in lines.iter().zip(cases) {
        let document: Value = serde_json::from_str(line).expect("each line is JSON");
        assert_eq!(document["case_id"], prepared.case.case_id);
        assert!(document["matches"].is_array(), "matches is an array");
        assert!(document["captures"].is_array(), "captures is an array");
        assert!(document["collections"].is_array(), "collections is an array");
        assert!(document.get("scores").is_some(), "scores is present");
        assert!(document.get("flags").is_some(), "flags is present");
        assert!(
            document.get("interruption").is_some(),
            "interruption is present, null when absent"
        );
    }
}

#[test]
fn tampered_manifest_hash_is_rejected() {
    let temporary = tempfile::tempdir().expect("create temporary directory");
    let case_name = "cases/get-benign.json";
    fs::create_dir_all(temporary.path().join("cases")).expect("create cases directory");
    fs::write(temporary.path().join(case_name), shipped_case("get-benign.json")).expect("copy case");
    let manifest = json!({
        "schema_version": 1,
        "workload_id": "tampered",
        "description": "tampered manifest",
        "case_schema": "coraza/conformance/corpus-schema.json",
        "cases": [{"path": case_name, "sha256": "0".repeat(64)}]
    });
    fs::write(temporary.path().join("manifest.json"), manifest.to_string()).expect("write manifest");
    let error = load_workload(temporary.path()).expect_err("tampered hash must fail");
    assert!(
        error.to_string().contains("SHA-256"),
        "error must name the hash mismatch: {error}"
    );
}

#[test]
fn case_path_traversal_is_rejected() {
    let temporary = tempfile::tempdir().expect("create temporary directory");
    let manifest = json!({
        "schema_version": 1,
        "workload_id": "traversal",
        "description": "traversal manifest",
        "case_schema": "coraza/conformance/corpus-schema.json",
        "cases": [{"path": "../get-benign.json", "sha256": "0".repeat(64)}]
    });
    fs::write(temporary.path().join("manifest.json"), manifest.to_string()).expect("write manifest");
    let error = load_workload(temporary.path()).expect_err("parent traversal must fail");
    assert!(
        error.to_string().contains(".. components"),
        "error must reject parent traversal: {error}"
    );
}

#[test]
fn duplicate_case_ids_are_rejected() {
    let temporary = tempfile::tempdir().expect("create temporary directory");
    let first = minimal_case();
    let mut second = minimal_case();
    second["connection"]["remote_port"] = json!(50001);
    let first_bytes = first.to_string();
    let second_bytes = second.to_string();
    fs::write(temporary.path().join("first.json"), &first_bytes).expect("write first case");
    fs::write(temporary.path().join("second.json"), &second_bytes).expect("write second case");
    let manifest = json!({
        "schema_version": 1,
        "workload_id": "duplicate-ids",
        "description": "duplicate case id manifest",
        "case_schema": "coraza/conformance/corpus-schema.json",
        "cases": [
            {"path": "first.json", "sha256": sha256_hex(first_bytes.as_bytes())},
            {"path": "second.json", "sha256": sha256_hex(second_bytes.as_bytes())}
        ]
    });
    fs::write(temporary.path().join("manifest.json"), manifest.to_string()).expect("write manifest");
    let error = load_workload(temporary.path()).expect_err("a duplicate case id must fail");
    let text = error.to_string();
    assert!(
        text.contains("duplicate case id \"minimal\""),
        "error must name the duplicate case id: {text}"
    );
    assert!(text.contains("first.json"), "error must name the first path: {text}");
    assert!(text.contains("second.json"), "error must name the second path: {text}");
}

#[test]
fn an_empty_expected_capture_is_rejected() {
    let mut case = minimal_case();
    case["expected"]["captures"] = json!([{"index": 0, "value": {"base64": ""}}]);
    let error = parse_case_bytes(case.to_string().as_bytes(), Path::new("."))
        .expect_err("an empty capture cannot be observed, so it must not be expected");
    assert!(
        error.to_string().contains("empty capture"),
        "error must name the unsupported empty capture: {error}"
    );
}

#[test]
fn invalid_base64_is_rejected() {
    let mut case = minimal_case();
    case["request"]["body"] = json!({"base64": "not base64!"});
    let error = parse_case_bytes(case.to_string().as_bytes(), Path::new(".")).expect_err("invalid base64 must fail");
    assert!(
        error.to_string().contains("invalid base64"),
        "error must name invalid base64: {error}"
    );
}

#[test]
fn chunk_gap_is_rejected() {
    let mut case = minimal_case();
    case["response"]["chunks"] = json!([{"offset": 0, "length": 1}]);
    let error = parse_case_bytes(case.to_string().as_bytes(), Path::new(".")).expect_err("a chunk gap must fail");
    assert!(
        error.to_string().contains("chunks cover"),
        "error must name coverage: {error}"
    );
}

#[test]
fn wrong_schema_version_is_rejected() {
    let mut case = minimal_case();
    case["schema_version"] = json!(2);
    let error =
        parse_case_bytes(case.to_string().as_bytes(), Path::new(".")).expect_err("an unknown schema version must fail");
    assert!(
        error.to_string().contains("schema_version"),
        "error must name the schema version: {error}"
    );
}

#[test]
fn fixture_ranges_and_hashes_are_validated() {
    let temporary = tempfile::tempdir().expect("create temporary directory");
    let payload = b"0123456789";
    fs::write(temporary.path().join("payload.bin"), payload).expect("write fixture");
    let hash = sha256_hex(payload);
    let mut case = minimal_case();
    case["request"]["body"] = json!({
        "fixture": "payload.bin",
        "sha256": hash,
        "offset": 2,
        "length": 5
    });
    case["request"]["chunks"] = json!([
        {"offset": 0, "length": 2},
        {"offset": 2, "length": 3}
    ]);
    case["phase_calls"] = json!([
        {"call": "process_connection", "phase": 1},
        {"call": "process_uri", "phase": 1},
        {"call": "process_request_headers", "phase": 1},
        {"call": "append_request_body", "phase": 2, "chunk_index": 0},
        {"call": "append_request_body", "phase": 2, "chunk_index": 1},
        {"call": "process_request_body", "phase": 2},
        {"call": "process_response_headers", "phase": 3},
        {"call": "append_response_body", "phase": 4, "chunk_index": 0},
        {"call": "process_response_body", "phase": 4},
        {"call": "process_logging", "phase": 5}
    ]);
    // The schema pins fixture_sha256 to the referenced fixture file, not to the
    // resolved range or the inline response bytes.
    case["fixture_sha256"] = json!(hash);
    let parsed = parse_case_bytes(case.to_string().as_bytes(), temporary.path()).expect("fixture range must load");
    assert_eq!(parsed.request.body, b"23456", "fixture range bytes");
    assert_eq!(parsed.request.chunk_count, 2, "chunk count");

    case["request"]["body"]["offset"] = json!(8);
    case["request"]["body"]["length"] = json!(5);
    let error = parse_case_bytes(case.to_string().as_bytes(), temporary.path())
        .expect_err("a range past the fixture must fail");
    assert!(
        error.to_string().contains("past the end"),
        "error must name the range: {error}"
    );

    let mut tampered = minimal_case();
    tampered["request"]["body"] = json!({
        "fixture": "payload.bin",
        "sha256": "0".repeat(64),
        "offset": 0,
        "length": 2
    });
    tampered["request"]["chunks"] = json!([{"offset": 0, "length": 2}]);
    tampered["fixture_sha256"] = json!("0".repeat(64));
    let error = parse_case_bytes(tampered.to_string().as_bytes(), temporary.path())
        .expect_err("a fixture hash mismatch must fail");
    assert!(
        error.to_string().contains("SHA-256"),
        "error must name the fixture hash: {error}"
    );
}

#[test]
fn timing_document_matches_the_contract_shape_and_order() {
    let workload = load_workload(&workload_root()).expect("shipped workload must load");
    let iterations = 2;
    let samples = run_timing(&workload, iterations).expect("timing run");
    let document = timing_document(&workload, iterations, &samples);

    let object = document.as_object().expect("timing document is an object");
    let mut fields = object.keys().map(String::as_str).collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "cases",
            "engine",
            "iterations",
            "manifest_sha256",
            "schema_version",
            "workload_id",
        ],
        "the timing document must have exactly the contract fields"
    );
    assert_eq!(document["schema_version"], 1, "timing schema version");
    assert_eq!(document["engine"], "rust", "engine name");
    assert_eq!(document["workload_id"], "coraza-common-subset-v1", "workload identity");
    let manifest = fs::read(workload_root().join("manifest.json")).expect("read manifest");
    assert_eq!(
        document["manifest_sha256"],
        sha256_hex(&manifest),
        "manifest hash covers the exact manifest bytes"
    );
    assert_eq!(document["iterations"], 2, "iteration count");

    let cases = document["cases"].as_array().expect("cases is an array");
    let expected_ids = workload
        .cases
        .iter()
        .map(|prepared| prepared.case.case_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), expected_ids.len(), "one entry per manifest case");
    for (entry, expected_id) in cases.iter().zip(&expected_ids) {
        assert_eq!(entry["case_id"].as_str(), Some(*expected_id), "manifest order");
        let samples = entry["samples_ns"].as_array().expect("samples is an array");
        assert_eq!(samples.len(), iterations, "one sample per iteration");
        for sample in samples {
            assert!(sample.as_u64().is_some(), "samples are non-negative integers");
        }
    }
}

#[test]
fn timing_document_is_written_atomically_and_round_trips() {
    let workload = load_workload(&workload_root()).expect("shipped workload must load");
    let iterations = 1;
    let samples = run_timing(&workload, iterations).expect("timing run");
    let document = timing_document(&workload, iterations, &samples);

    let temporary = tempfile::tempdir().expect("create temporary directory");
    let path = temporary.path().join("timing.json");
    write_timing_document(&path, &document).expect("write timing document");
    let text = fs::read_to_string(&path).expect("read timing document");
    let parsed: Value = serde_json::from_str(&text).expect("written timing document is JSON");
    assert_eq!(parsed, document, "the written document matches the timed samples");

    let entries = fs::read_dir(temporary.path())
        .expect("list temporary directory")
        .collect::<Result<Vec<_>, _>>()
        .expect("read temporary directory entries");
    assert_eq!(entries.len(), 1, "the temporary file was renamed, not left behind");
}

#[test]
fn invalid_iterations_are_rejected() {
    for invalid in ["", "0", "-1", "1.5", "ten", "1000001", "18446744073709551616"] {
        let error = parse_iterations(invalid).expect_err("an invalid iteration count must fail");
        assert!(
            error.to_string().contains("--iterations"),
            "error must name the flag: {error}"
        );
    }
    assert_eq!(parse_iterations("1").expect("the minimum is accepted"), 1);
    assert_eq!(
        parse_iterations("1000000").expect("the documented maximum is accepted"),
        1_000_000
    );
}

#[test]
fn timing_document_write_rejects_an_unwritable_path() {
    let temporary = tempfile::tempdir().expect("create temporary directory");
    let path = temporary.path().join("missing").join("timing.json");
    let error = write_timing_document(&path, &json!({"schema_version": 1}))
        .expect_err("a missing destination directory must fail");
    assert!(
        error.to_string().contains("temporary timing file"),
        "error must name the write failure: {error}"
    );
    assert!(!path.exists(), "no document is created on failure");

    let directory = temporary.path().join("destination");
    fs::create_dir(&directory).expect("create destination directory");
    let error = write_timing_document(&directory, &json!({"schema_version": 1}))
        .expect_err("a directory destination must fail");
    assert!(
        error.to_string().contains("cannot replace"),
        "error must name the rename failure: {error}"
    );
}
