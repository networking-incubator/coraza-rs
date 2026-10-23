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

//! Drift checks for the conformance manifest, difference ledger and corpus schema.
#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]
#![expect(clippy::unwrap_used, reason = "conformance fixtures are trusted")]
#![expect(clippy::panic, reason = "validation failures are the test output")]
#![expect(
    clippy::indexing_slicing,
    reason = "small fixed fixtures and bounded byte scans are checked first"
)]

use std::{collections::BTreeSet, fs, path::Path};

use regex::Regex;
use serde_json::Value;

const MANIFEST: &str = include_str!("../conformance/capability-manifest.json");
const LEDGER: &str = include_str!("../conformance/difference-ledger.md");
const SCHEMA: &str = include_str!("../conformance/corpus-schema.json");
const EXAMPLE: &str = include_str!("../conformance/example-case.json");
const ACTIONS_SOURCE: &str = include_str!("../src/actions/mod.rs");
const OPERATORS_SOURCE: &str = include_str!("../src/operators/mod.rs");
const PARSER_SOURCE: &str = include_str!("../src/seclang/parser.rs");
const TRANSACTION_CTL_SOURCE: &str = include_str!("../src/transaction/ctl.rs");
const TRANSACTION_VARIABLES_SOURCE: &str = include_str!("../src/transaction/variables.rs");
const VARIABLES_SOURCE: &str = include_str!("../src/types/variables.rs");

const STATES: [&str; 4] = ["implemented", "rejected", "accepted_without_effect", "unavailable"];
const GO_COMMIT: &str = "d9cc9befc2721fd217ce1660a0e91aca1157221d";
const EXAMPLE_FIXTURE_SHA: &str = "7dfaa62fe41c266f931e9d05fb8cefd7ecba57c929b11f02af0ef8737fc93c04";
const REVIEWED_LEDGER: [(&str, &str); 16] = [
    (
        "sql-nul-after-hex-prefix",
        "ada05d3c4ccbcb21de99ab1609081812dbe7a37e76a516595d44af97cb6ed02e",
    ),
    (
        "sql-nul-after-hex-prefix-hash",
        "74c8cdb374f247b42999a58680292f04fab7bd6e0da6c2d2bf88de41fc2b8f4b",
    ),
    (
        "xss-soaj1664ashar-pastebin-u6FY1xDA.txt:78",
        "86ec68034c98e8a26e01f68db4c2051938b1b38131344c4876d0ad805cd92227",
    ),
    (
        "xss-soaj1664ashar-pastebin-u6FY1xDA.txt:102",
        "9624e59812bd58fedf68d5e0639fc2a966224641bd3b54bed91700ecaeb7dce5",
    ),
    (
        "xss-xenotix.txt:693",
        "779a6aca1d223eb0a63f0362a44841e48b43bbf505679119dcd3cb07b5c2c8f3",
    ),
    (
        "xss-xenotix.txt:694",
        "55841cd4d4f4ad2d2a678fcc29a7a78534eb3ae4a0a9916a8fa22a30673b5194",
    ),
    (
        "raw-0265",
        "8ceda65b55dbd3d4557ea3eef1d140660fb28d983b86b9ce8aa3111aecb3205a",
    ),
    (
        "raw-0043",
        "1cdd835eb77c2bd1acb9003388a4c91e9b294fd01a2fed1b7701b1381f84701a",
    ),
    (
        "raw-0060",
        "f39efb68b9bee584cd30dcf85698b40f92cd709d48dec013d0ab919ca7f412c6",
    ),
    (
        "raw-0075",
        "35d086a03bd3f4508cb19796b772c6faadd39d3aa1e1969ddf130f9ab7a2e06d",
    ),
    (
        "raw-0227",
        "dc7bb8a43bc5b39a14663709e677b83f978ba3c54c1425552de5e83e207cbf81",
    ),
    (
        "raw-0292",
        "245ac590dddc9898908c6d974085e33488a08219c48957278145049618d69b38",
    ),
    (
        "raw-0365",
        "58c14b7bcbc569d32c0a70b54939c2c97aa53d4cfd68e17f7e933d515bf87527",
    ),
    (
        "raw-0373",
        "e27f2dcab16bfa5874e2ef0fc3d7702d363446029fdcab9a6d2c64bc8526d373",
    ),
    (
        "args-get-invalid-utf8-names",
        "3c9133937f99186e0ef69373aef20e1a5382ce02ece6b94936da02a4c07cb95f",
    ),
    (
        "json-invalid-utf8-keys",
        "5475fd660355bbc435ec9208d8cb01b6cb2206e28a7ad500af8ff4b4782d9a05",
    ),
];

fn parse_json(name: &str, source: &str) -> Value {
    serde_json::from_str(source).unwrap_or_else(|error| panic!("{name} is not valid JSON: {error}"))
}

fn function_body<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("missing source symbol {signature}"));
    let open = source
        .get(start..)
        .and_then(|rest| rest.find('{'))
        .map_or_else(|| panic!("missing body for {signature}"), |offset| start + offset);
    let mut depth = 0_usize;
    let mut end = None;
    for (offset, ch) in source.get(open..).unwrap_or_default().char_indices() {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth -= 1;
            if depth == 0 {
                end = Some(open + offset + ch.len_utf8());
                break;
            }
        }
    }
    let end = end.unwrap_or_else(|| panic!("unterminated body for {signature}"));
    source.get(open..end).unwrap_or_default()
}

fn string_literals(line: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut buffer = String::new();
    let mut in_string = false;
    for ch in line.chars() {
        if ch == '"' {
            if in_string {
                literals.push(std::mem::take(&mut buffer));
            }
            in_string = !in_string;
        } else if in_string {
            buffer.push(ch);
        }
    }
    literals
}

fn match_arm_names(body: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut pending = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('"') || trimmed.starts_with('|') {
            pending.extend(string_literals(trimmed));
            if trimmed.contains("=>") {
                for name in pending.drain(..) {
                    names.insert(name.to_ascii_lowercase());
                }
            }
        } else if trimmed.starts_with("_ =>") {
            pending.clear();
        }
    }
    names
}

fn body_processor_names() -> BTreeSet<String> {
    let body = function_body(ACTIONS_SOURCE, "fn is_body_processor");
    let mut names = BTreeSet::new();
    for name in string_literals(body) {
        names.insert(name.to_ascii_lowercase());
    }
    names
}

fn variable_variants() -> Vec<(String, String)> {
    let pattern = Regex::new(r#"\(\s*RuleVariable::(\w+),\s*"([A-Z0-9_]+)"\s*,?\s*\)"#).unwrap();
    pattern
        .captures_iter(VARIABLES_SOURCE)
        .map(|capture| {
            (
                capture.get(1).unwrap().as_str().to_owned(),
                capture.get(2).unwrap().as_str().to_owned(),
            )
        })
        .collect()
}

fn stored_variants() -> BTreeSet<String> {
    let start = TRANSACTION_VARIABLES_SOURCE
        .find("macro_rules! variable_storage")
        .unwrap();
    let end = TRANSACTION_VARIABLES_SOURCE.find("#[derive(Clone, Copy)]").unwrap();
    let body = TRANSACTION_VARIABLES_SOURCE.get(start..end).unwrap();
    let pattern = Regex::new(r"RuleVariable::(\w+)").unwrap();
    pattern
        .captures_iter(body)
        .map(|capture| capture.get(1).unwrap().as_str().to_owned())
        .collect()
}

fn manifest_group<'a>(manifest: &'a Value, group: &str) -> &'a Vec<Value> {
    manifest
        .get("capability_groups")
        .and_then(|groups| groups.get(group))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("manifest group {group} must be an array"))
}

fn manifest_names(manifest: &Value, group: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for entry in manifest_group(manifest, group) {
        let entries = entry
            .get("names")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{group} entry has no names array"));
        for name in entries {
            let name = name.as_str().unwrap_or_else(|| panic!("{group} name is not a string"));
            names.insert(name.to_ascii_lowercase());
        }
    }
    names
}

fn registered_names(manifest: &Value, group: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for entry in manifest_group(manifest, group) {
        if entry.get("state").and_then(Value::as_str) == Some("unavailable") {
            continue;
        }
        for name in entry.get("names").and_then(Value::as_array).unwrap() {
            names.insert(name.as_str().unwrap().to_ascii_lowercase());
        }
    }
    names
}

fn unavailable_names(manifest: &Value, group: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for entry in manifest_group(manifest, group) {
        if entry.get("state").and_then(Value::as_str) != Some("unavailable") {
            continue;
        }
        for name in entry.get("names").and_then(Value::as_array).unwrap() {
            names.insert(name.as_str().unwrap().to_ascii_lowercase());
        }
    }
    names
}

fn variable_state<'a>(manifest: &'a Value, name: &str) -> Option<&'a str> {
    for entry in manifest_group(manifest, "variables") {
        let names = entry.get("names").and_then(Value::as_array)?;
        if names
            .iter()
            .any(|candidate| candidate.as_str().is_some_and(|value| value.eq_ignore_ascii_case(name)))
        {
            return entry.get("state").and_then(Value::as_str);
        }
    }
    None
}

fn check_manifest_entries(manifest: &Value, go_commit: &str) {
    let states = manifest.get("states").and_then(Value::as_array).unwrap();
    let mut advertised = BTreeSet::new();
    for state in states {
        advertised.insert(state.as_str().unwrap().to_owned());
    }
    let mut expected_states = BTreeSet::new();
    for state in STATES {
        expected_states.insert(state.to_owned());
    }
    assert_eq!(
        advertised, expected_states,
        "manifest states must be exactly the four supported states"
    );

    let groups = [
        "operators",
        "transformations",
        "actions",
        "directives",
        "variables",
        "body_processors",
        "runtime_controls",
    ];
    for group in groups {
        let mut group_names = BTreeSet::new();
        for entry in manifest_group(manifest, group) {
            let state = entry.get("state").and_then(Value::as_str).unwrap();
            assert!(STATES.contains(&state), "{group} has unknown state {state}");
            let revision = entry.get("reference_revision").and_then(Value::as_str).unwrap();
            assert_eq!(revision, go_commit, "{group} entry has a different reference revision");
            assert!(
                entry.get("differences").and_then(Value::as_array).is_some(),
                "{group} entry has no differences array"
            );
            assert!(
                entry.get("fixtures").and_then(Value::as_array).is_some(),
                "{group} entry has no fixtures array"
            );
            let producer = entry.get("producer").and_then(Value::as_str);
            let evaluator = entry.get("evaluator").and_then(Value::as_str);
            if state == "unavailable" {
                assert!(producer.is_none(), "{group} unavailable entry has a Rust producer");
                assert!(evaluator.is_none(), "{group} unavailable entry has a Rust evaluator");
                assert!(
                    entry
                        .get("go_reference")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty()),
                    "{group} unavailable entry has no Go reference"
                );
            } else {
                assert!(
                    producer.is_some_and(|value| !value.is_empty()),
                    "{group} entry has no producer"
                );
                assert!(
                    evaluator.is_some_and(|value| !value.is_empty()),
                    "{group} entry has no evaluator"
                );
            }
            for name in entry.get("names").and_then(Value::as_array).unwrap() {
                let name = name.as_str().unwrap().to_ascii_lowercase();
                assert!(!name.is_empty(), "{group} has an empty name");
                assert!(group_names.insert(name), "{group} repeats a capability name");
            }
        }
    }
}

fn check_factories(manifest: &Value) {
    assert_eq!(
        registered_names(manifest, "operators"),
        match_arm_names(function_body(OPERATORS_SOURCE, "pub fn with_context")),
        "operator factory and manifest differ"
    );
    assert_eq!(
        registered_names(manifest, "transformations"),
        match_arm_names(function_body(ACTIONS_SOURCE, "fn transformation_by_name")),
        "transformation factory and manifest differ"
    );
    assert_eq!(
        registered_names(manifest, "actions"),
        match_arm_names(function_body(ACTIONS_SOURCE, "pub(crate) fn compile_action")),
        "action factory and manifest differ"
    );
    let mut directives = match_arm_names(function_body(PARSER_SOURCE, "fn directive_handler"));
    directives.insert("include".to_owned());
    assert_eq!(
        registered_names(manifest, "directives"),
        directives,
        "directive registry and manifest differ"
    );
    let mut controls = match_arm_names(function_body(ACTIONS_SOURCE, "fn validate_ctl"));
    controls.extend(match_arm_names(function_body(
        TRANSACTION_CTL_SOURCE,
        "pub(crate) fn apply_ctl",
    )));
    assert_eq!(
        registered_names(manifest, "runtime_controls"),
        controls,
        "ctl registry and manifest differ"
    );
    assert_eq!(
        registered_names(manifest, "body_processors"),
        body_processor_names(),
        "body processor registry and manifest differ"
    );
    for group in ["operators", "transformations"] {
        let factory = if group == "operators" {
            match_arm_names(function_body(OPERATORS_SOURCE, "pub fn with_context"))
        } else {
            match_arm_names(function_body(ACTIONS_SOURCE, "fn transformation_by_name"))
        };
        for name in unavailable_names(manifest, group) {
            assert!(
                !factory.contains(&name),
                "unavailable {group} capability {name} is registered in the factory"
            );
        }
    }
}

fn check_variables(manifest: &Value) {
    let stored = stored_variants();
    let variants = variable_variants();
    let manifest_variables = manifest_names(manifest, "variables");
    let source_variables = variants
        .iter()
        .map(|(_, name)| name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        manifest_variables, source_variables,
        "variable enum and manifest differ"
    );
    for (variant, name) in &variants {
        let state = variable_state(manifest, name).unwrap_or_else(|| panic!("variable {name} is unclassified"));
        if stored.contains(variant) {
            assert_eq!(state, "implemented", "stored variable {name} is not implemented");
        } else {
            assert_ne!(state, "implemented", "unstored variable {name} claims implemented");
        }
    }
}

#[test]
fn manifest_is_pinned_and_classifies_factories() {
    let manifest = parse_json("capability-manifest.json", MANIFEST);
    let go_commit = manifest
        .get("reference")
        .and_then(|reference| reference.get("go_coraza"))
        .and_then(|go| go.get("commit"))
        .and_then(Value::as_str)
        .unwrap();
    assert_eq!(go_commit, GO_COMMIT);
    check_manifest_entries(&manifest, go_commit);
    check_factories(&manifest);
    check_variables(&manifest);
}

#[test]
fn ledger_rows_are_pinned() {
    let sha = Regex::new("^[0-9a-f]{64}$").unwrap();
    let mut rows = Vec::new();
    let mut in_table = false;
    for line in LEDGER.lines() {
        if line.starts_with("| Case ID | Fixture SHA-256 | Expected Go | Expected Rust | Reason |") {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        if !line.starts_with('|') {
            break;
        }
        let cells = line.trim_matches('|').split('|').map(str::trim).collect::<Vec<_>>();
        if cells.first().is_some_and(|cell| cell.starts_with("---")) {
            continue;
        }
        assert_eq!(cells.len(), 5, "ledger row does not have five columns: {line}");
        let case_id = cells[0];
        let hash = cells[1];
        assert!(
            case_id.len() >= 2 && case_id.starts_with('`'),
            "ledger case ID is not code: {case_id}"
        );
        assert!(
            hash.len() >= 2 && hash.starts_with('`'),
            "ledger hash is not code: {hash}"
        );
        let case_id = case_id.trim_matches('`');
        let hash = hash.trim_matches('`');
        assert!(sha.is_match(hash), "ledger hash is not SHA-256: {hash}");
        assert!(!cells[2].is_empty(), "ledger Go outcome is empty for {case_id}");
        assert!(!cells[3].is_empty(), "ledger Rust outcome is empty for {case_id}");
        assert!(!cells[4].is_empty(), "ledger reason is empty for {case_id}");
        rows.push((case_id.to_owned(), hash.to_owned()));
    }
    assert_eq!(rows.len(), REVIEWED_LEDGER.len(), "ledger row count changed");
    for (case_id, hash) in &rows {
        assert!(
            REVIEWED_LEDGER
                .iter()
                .any(|(expected_id, expected_hash)| expected_id == case_id && expected_hash == hash),
            "unreviewed ledger row {case_id} {hash}"
        );
    }
    for (case_id, hash) in REVIEWED_LEDGER {
        assert!(
            rows.iter()
                .any(|(actual_id, actual_hash)| actual_id == case_id && actual_hash == hash),
            "reviewed ledger row {case_id} {hash} is missing"
        );
    }
}

fn is_base64(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return false;
    }
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 {
        return false;
    }
    let data_len = bytes.len() - padding;
    bytes.get(..data_len).is_some_and(|data| {
        data.iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/')
    })
}

fn decoded_len(value: &str) -> usize {
    let padding = value.as_bytes().iter().rev().take_while(|byte| **byte == b'=').count();
    value.len() / 4 * 3 - padding
}

fn fixture_range(value: &Value, corpus_root: &Path) -> (std::path::PathBuf, usize, usize) {
    let fixture = value
        .get("fixture")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("byte value has neither base64 nor fixture"));
    let sha = value.get("sha256").and_then(Value::as_str).unwrap();
    assert!(
        Regex::new("^[0-9a-f]{64}$").unwrap().is_match(sha),
        "fixture hash is malformed"
    );
    let path = corpus_root.join(fixture);
    let file_len = fs::metadata(&path)
        .unwrap_or_else(|error| panic!("cannot read referenced fixture {path:?}: {error}"))
        .len();
    let file_len = usize::try_from(file_len).unwrap();
    let offset = value
        .get("offset")
        .and_then(Value::as_u64)
        .map_or(0, |offset| usize::try_from(offset).unwrap());
    assert!(offset <= file_len, "fixture offset is past the end of {path:?}");
    let length = value
        .get("length")
        .and_then(Value::as_u64)
        .map_or(file_len - offset, |length| usize::try_from(length).unwrap());
    let end = offset
        .checked_add(length)
        .unwrap_or_else(|| panic!("fixture range overflows for {path:?}"));
    assert!(end <= file_len, "fixture range extends past the end of {path:?}");
    (path, offset, length)
}

fn bytes_length(value: &Value, corpus_root: &Path) -> usize {
    if let Some(encoded) = value.get("base64").and_then(Value::as_str) {
        assert!(is_base64(encoded), "invalid base64 in corpus case");
        decoded_len(encoded)
    } else {
        let (_, _, length) = fixture_range(value, corpus_root);
        length
    }
}

fn check_bytes(value: &Value, corpus_root: &Path) {
    if let Some(encoded) = value.get("base64").and_then(Value::as_str) {
        assert!(is_base64(encoded), "invalid base64 in corpus case: {encoded}");
        return;
    }
    fixture_range(value, corpus_root);
}

fn check_headers(value: &Value, corpus_root: &Path) {
    let headers = value.get("headers").and_then(Value::as_array).unwrap();
    for header in headers {
        let name = header.get("name").and_then(Value::as_str).unwrap();
        assert!(!name.is_empty(), "header name is empty");
        check_bytes(header.get("value").unwrap(), corpus_root);
    }
}

fn check_chunks(value: &Value, body: &Value, corpus_root: &Path) {
    let body_len = bytes_length(body, corpus_root);
    let chunks = value.get("chunks").and_then(Value::as_array).unwrap();
    let mut next = 0_usize;
    for chunk in chunks {
        let offset = usize::try_from(chunk.get("offset").and_then(Value::as_u64).unwrap()).unwrap();
        let length = usize::try_from(chunk.get("length").and_then(Value::as_u64).unwrap()).unwrap();
        assert_eq!(offset, next, "chunk offsets are not contiguous");
        next = offset
            .checked_add(length)
            .unwrap_or_else(|| panic!("chunk length overflows"));
        assert!(next <= body_len, "chunk extends past the body");
    }
    assert_eq!(next, body_len, "chunks do not cover the body");
}

fn check_schema_shape(schema: &Value) {
    assert_eq!(
        schema.get("$schema").and_then(Value::as_str),
        Some("https://json-schema.org/draft/2020-12/schema"),
        "corpus schema must declare draft 2020-12"
    );
    let defs = schema.get("$defs").and_then(Value::as_object).unwrap();
    for definition in [
        "bytes",
        "text",
        "reference",
        "connection",
        "request",
        "response",
        "processor",
        "phase_call",
        "expected",
    ] {
        assert!(defs.contains_key(definition), "$defs is missing {definition}");
    }
    let bytes_variants = defs
        .get("bytes")
        .and_then(|bytes| bytes.get("oneOf"))
        .and_then(Value::as_array)
        .unwrap();
    assert_eq!(
        bytes_variants.len(),
        2,
        "bytes must allow base64 or a fixture reference"
    );
    assert!(
        bytes_variants.iter().any(|variant| {
            variant
                .get("properties")
                .and_then(|props| props.get("base64"))
                .is_some()
        }),
        "bytes must allow inline base64"
    );
    assert!(
        bytes_variants.iter().any(|variant| {
            variant
                .get("properties")
                .and_then(|props| props.get("fixture"))
                .is_some()
        }),
        "bytes must allow a referenced fixture"
    );
    let expected_required = defs
        .get("expected")
        .and_then(|expected| expected.get("required"))
        .and_then(Value::as_array)
        .unwrap();
    for field in [
        "matches",
        "interruptions",
        "captures",
        "scores",
        "flags",
        "collections",
        "audit",
    ] {
        assert!(
            expected_required
                .iter()
                .any(|required| required.as_str() == Some(field)),
            "expected does not require {field}"
        );
    }
}

#[test]
fn corpus_schema_matches_example() {
    let schema = parse_json("corpus-schema.json", SCHEMA);
    check_schema_shape(&schema);

    let case = parse_json("example-case.json", EXAMPLE);
    let required = schema.get("required").and_then(Value::as_array).unwrap();
    for field in required {
        let field = field.as_str().unwrap();
        assert!(case.get(field).is_some(), "example case is missing {field}");
    }
    let sha = Regex::new("^[0-9a-f]{64}$").unwrap();
    let case_sha = case.get("fixture_sha256").and_then(Value::as_str).unwrap();
    assert!(sha.is_match(case_sha));
    assert_eq!(
        case_sha, EXAMPLE_FIXTURE_SHA,
        "example fixture hash changed without review"
    );
    let reference = case.get("reference").unwrap();
    for commit in ["go_commit", "rust_commit"] {
        let value = reference.get(commit).and_then(Value::as_str).unwrap();
        assert_eq!(value.len(), 40, "{commit} is not a full commit hash");
        assert!(
            value.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{commit} is not hexadecimal"
        );
    }

    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance");
    let request = case.get("request").unwrap();
    let response = case.get("response").unwrap();
    check_headers(request, &corpus_root);
    check_headers(response, &corpus_root);
    check_bytes(request.get("uri").unwrap(), &corpus_root);
    check_bytes(request.get("body").unwrap(), &corpus_root);
    check_bytes(response.get("body").unwrap(), &corpus_root);
    if let Some(body_sha) = request
        .get("body")
        .and_then(|body| body.get("sha256"))
        .and_then(Value::as_str)
    {
        assert_eq!(
            body_sha, case_sha,
            "case hash and referenced request fixture hash differ"
        );
    }
    check_chunks(request, request.get("body").unwrap(), &corpus_root);
    check_chunks(response, response.get("body").unwrap(), &corpus_root);

    let mut last_phase = 0_u64;
    for call in case.get("phase_calls").and_then(Value::as_array).unwrap() {
        let phase = call.get("phase").and_then(Value::as_u64).unwrap();
        assert!(phase >= last_phase, "phase calls are not ordered");
        last_phase = phase;
        let call_name = call
            .get("call")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("phase call has no name"));
        if matches!(call_name, "append_request_body" | "append_response_body") {
            assert!(
                call.get("chunk_index").and_then(Value::as_u64).is_some(),
                "{call_name} requires an integer chunk_index"
            );
        }
    }
    let expected = case.get("expected").unwrap();
    for field in [
        "matches",
        "interruptions",
        "captures",
        "scores",
        "flags",
        "collections",
        "audit",
    ] {
        assert!(expected.get(field).is_some(), "expected is missing {field}");
    }
    let normalize = case.get("normalize").and_then(Value::as_array).unwrap();
    for field in normalize {
        let field = field.as_str().unwrap();
        assert!(
            [
                "timestamps",
                "generated_ids",
                "temporary_paths",
                "audit_boundaries",
                "header_order"
            ]
            .contains(&field),
            "unknown normalization {field}"
        );
    }
}

#[test]
fn conformance_files_are_ascii() {
    for (name, contents) in [
        ("capability-manifest.json", MANIFEST),
        ("difference-ledger.md", LEDGER),
        ("corpus-schema.json", SCHEMA),
        ("example-case.json", EXAMPLE),
    ] {
        assert!(
            contents.is_ascii(),
            "{name} contains non-ASCII prose; use printable ASCII instead"
        );
    }
}
