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

//! Generate and verify the conformance capability manifest.
//!
//! Source-derived fields are recomputed on every run. Human decisions live in
//! `capability-overrides.json`; the ledger and example case are hand-maintained
//! contracts that this task validates without rewriting.

#![allow(clippy::missing_docs_in_private_items, reason = "internal xtask implementation")]

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use serde_json::Value;

const MANIFEST: &str = "coraza/conformance/capability-manifest.json";
const OVERRIDES: &str = "coraza/conformance/capability-overrides.json";
const LEDGER: &str = "coraza/conformance/difference-ledger.md";
const EXAMPLE: &str = "coraza/conformance/example-case.json";
const CORPUS_ROOT: &str = "coraza/conformance";
const STATES: [&str; 4] = ["implemented", "rejected", "accepted_without_effect", "unavailable"];
const DESCRIPTION: &str = "Capability inventory derived from the Rust factories and variable storage. States: implemented (registered and effective), rejected (known name refused at compile time), accepted_without_effect (compiled but no runtime effect), unavailable (not present in this build).";
const NEW_CAPABILITY_NOTE: &str = "New source capability; review required before classifying it.";
const REVIEW_GO_REFERENCE: &str = "review required";

pub(crate) fn check_or_exit() {
    if let Err(error) = check(&workspace_root()) {
        eprintln!("conformance check failed: {error}");
        std::process::exit(1);
    }
}

pub(crate) fn refresh_or_exit() {
    if let Err(error) = refresh(&workspace_root()) {
        eprintln!("conformance refresh failed: {error}");
        std::process::exit(1);
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is a workspace member")
        .to_owned()
}

// -----------------------------------------------------------------------------
// Source-derived capabilities
// -----------------------------------------------------------------------------

/// Where a capability group's names come from in the Rust source.
enum Source {
    /// Match arms in one or more functions, plus any names handled elsewhere.
    MatchArms {
        /// Source file and function signature pairs.
        sources: &'static [(&'static str, &'static str)],
        /// Names handled outside the listed match arms.
        extra: &'static [&'static str],
    },
    /// String literals inside a function body.
    StringList {
        /// Source file.
        file: &'static str,
        /// Function signature.
        signature: &'static str,
    },
    /// The `VARIABLES` lookup table.
    Variables,
}

/// One capability group and its registry and dispatch symbols.
struct GroupSpec {
    /// Group key in the manifest.
    key: &'static str,
    /// Rust registry symbol.
    producer: &'static str,
    /// Rust dispatch symbol.
    evaluator: &'static str,
    /// Source of the group's capability names.
    source: Source,
}

const GROUPS: [GroupSpec; 7] = [
    GroupSpec {
        key: "operators",
        producer: "coraza/src/operators/mod.rs:OperatorEnum::with_context",
        evaluator: "coraza/src/operators/mod.rs:OperatorEnum::evaluate",
        source: Source::MatchArms {
            sources: &[("coraza/src/operators/mod.rs", "pub fn with_context")],
            extra: &[],
        },
    },
    GroupSpec {
        key: "transformations",
        producer: "coraza/src/actions/mod.rs:transformation_by_name",
        evaluator: "coraza/src/rules/transformation.rs:TransformationChain::apply",
        source: Source::MatchArms {
            sources: &[("coraza/src/actions/mod.rs", "fn transformation_by_name")],
            extra: &[],
        },
    },
    GroupSpec {
        key: "actions",
        producer: "coraza/src/actions/mod.rs:compile_action",
        evaluator: "coraza/src/actions/mod.rs:CompiledAction::evaluate",
        source: Source::MatchArms {
            sources: &[("coraza/src/actions/mod.rs", "pub(crate) fn compile_action")],
            extra: &[],
        },
    },
    GroupSpec {
        key: "directives",
        producer: "coraza/src/seclang/parser.rs:directive_handler",
        evaluator: "coraza/src/seclang/parser.rs:Parser::evaluate_line",
        source: Source::MatchArms {
            sources: &[("coraza/src/seclang/parser.rs", "fn directive_handler")],
            extra: &["include"],
        },
    },
    GroupSpec {
        key: "variables",
        producer: "coraza/src/types/variables.rs:RuleVariable",
        evaluator: "coraza/src/transaction.rs:variable_storage!",
        source: Source::Variables,
    },
    GroupSpec {
        key: "body_processors",
        producer: "coraza/src/transaction.rs:BodyProcessor::parse",
        evaluator: "coraza/src/transaction.rs:process_request_body",
        source: Source::StringList {
            file: "coraza/src/actions/mod.rs",
            signature: "fn is_body_processor",
        },
    },
    GroupSpec {
        key: "runtime_controls",
        producer: "coraza/src/actions/mod.rs:validate_ctl",
        evaluator: "coraza/src/transaction.rs:Transaction::apply_ctl",
        source: Source::MatchArms {
            sources: &[
                ("coraza/src/actions/mod.rs", "fn validate_ctl"),
                ("coraza/src/transaction.rs", "pub(crate) fn apply_ctl"),
            ],
            extra: &[],
        },
    },
];

/// Reads a workspace-relative source file.
fn read_source(root: &Path, file: &str) -> Result<String, String> {
    fs::read_to_string(root.join(file)).map_err(|error| format!("{file}: {error}"))
}

/// Returns the braced body following `signature`.
fn function_body<'a>(source: &'a str, signature: &str) -> Result<&'a str, String> {
    let start = source
        .find(signature)
        .ok_or_else(|| format!("missing source symbol {signature}"))?;
    let rest = source
        .get(start..)
        .ok_or_else(|| format!("{signature} is not on a character boundary"))?;
    let open = start
        .checked_add(rest.find('{').ok_or_else(|| format!("missing body for {signature}"))?)
        .ok_or_else(|| format!("body offset overflows for {signature}"))?;
    let mut depth = 0_usize;
    let mut end = None;
    for (offset, ch) in source.get(open..).unwrap_or_default().char_indices() {
        match ch {
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    end = open
                        .checked_add(offset)
                        .and_then(|value| value.checked_add(ch.len_utf8()));
                    break;
                }
            },
            _ => {},
        }
    }
    let end = end.ok_or_else(|| format!("unterminated body for {signature}"))?;
    source
        .get(open..end)
        .ok_or_else(|| format!("invalid body range for {signature}"))
}

/// Returns the string literals in one line.
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

/// Returns every string literal in a block.
fn all_string_literals(source: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut buffer = String::new();
    let mut in_string = false;
    for ch in source.chars() {
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

/// Returns the capabilities named in a function's match arms.
fn match_arm_names(source: &str, signature: &str) -> Result<Vec<String>, String> {
    let body = function_body(source, signature)?;
    let mut names = Vec::new();
    let mut pending = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('"') || trimmed.starts_with('|') {
            pending.extend(string_literals(trimmed));
            if trimmed.contains("=>") {
                names.append(&mut pending);
            }
        } else if trimmed.starts_with("_ =>") {
            pending.clear();
        }
    }
    Ok(names)
}

/// Returns the names in the `VARIABLES` lookup table.
fn variable_names(source: &str) -> Result<Vec<String>, String> {
    let start = source.find("const VARIABLES").ok_or("missing VARIABLES table")?;
    let rest = source
        .get(start..)
        .ok_or("VARIABLES table is not on a character boundary")?;
    let end = rest.find("];").ok_or("unterminated VARIABLES table")?;
    let block = rest.get(..end).ok_or("invalid VARIABLES table range")?;
    Ok(all_string_literals(block)
        .into_iter()
        .filter(|name| is_upper_identifier(name))
        .collect())
}

/// Returns true for an upper-case ASCII identifier.
fn is_upper_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Derives a group's capability names from source, preserving source spelling.
fn source_names(root: &Path, spec: &GroupSpec) -> Result<Vec<String>, String> {
    let mut names = match &spec.source {
        Source::MatchArms { sources, extra } => {
            let mut names = Vec::new();
            for (file, signature) in *sources {
                let source = read_source(root, file)?;
                names.extend(match_arm_names(&source, signature)?);
            }
            names.extend(extra.iter().map(|name| (*name).to_owned()));
            names
        },
        Source::StringList { file, signature } => {
            let source = read_source(root, file)?;
            let body = function_body(&source, signature)?;
            all_string_literals(body)
        },
        Source::Variables => {
            let source = read_source(root, "coraza/src/types/variables.rs")?;
            variable_names(&source)?
        },
    };
    let mut seen = BTreeSet::new();
    names.retain(|name| !name.is_empty() && seen.insert(name.to_ascii_lowercase()));
    Ok(names)
}

/// Verifies that a `file:symbol` reference exists in source.
fn verify_symbol(root: &Path, reference: &str) -> Result<(), String> {
    let (file, symbol) = reference
        .split_once(':')
        .ok_or_else(|| format!("symbol reference has no file: {reference}"))?;
    let source = read_source(root, file)?;
    let leaf = symbol.rsplit("::").next().unwrap_or(symbol);
    let markers = leaf.strip_suffix('!').map_or_else(
        || {
            vec![
                format!("fn {leaf}"),
                format!("enum {leaf}"),
                format!("struct {leaf}"),
                format!("type {leaf}"),
            ]
        },
        |name| vec![format!("macro_rules! {name}")],
    );
    if !markers.iter().any(|marker| source.contains(marker)) {
        return Err(format!("{reference} does not match a source symbol"));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Manifest generation
// -----------------------------------------------------------------------------

/// One generated manifest entry.
struct Entry {
    names: Vec<String>,
    state: String,
    reference_revision: String,
    producer: Option<String>,
    evaluator: Option<String>,
    go_reference: Option<String>,
    fixtures: Vec<String>,
    differences: Vec<String>,
}

/// Reads a required string field.
fn required_str<'a>(value: &'a Value, field: &str, context: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context} has no string field {field}"))
}

/// Reads an optional string field.
fn optional_str(value: &Value, field: &str, context: &str) -> Result<Option<String>, String> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(format!("{context} field {field} is not a string")),
    }
}

/// Reads an optional string array field.
fn optional_strings(value: &Value, field: &str, context: &str) -> Result<Vec<String>, String> {
    let Some(items) = value.get(field) else {
        return Ok(Vec::new());
    };
    let items = items
        .as_array()
        .ok_or_else(|| format!("{context} field {field} is not an array"))?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{context} field {field} contains a non-string"))
        })
        .collect()
}

/// Builds one group's entries from source names and human overrides.
fn build_entries(
    spec: &GroupSpec,
    source: &[String],
    overrides: &Value,
    go_commit: &str,
) -> Result<Vec<Entry>, String> {
    let source_lower = source
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let key = spec.key;
    let items = overrides
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{OVERRIDES} has no {key} group object"))?;
    let mut covered = BTreeSet::new();
    let mut entries = Vec::with_capacity(items.len());
    for (name, item) in items {
        let context = format!("{key} entry {name}");
        let state = required_str(item, "state", &context)?;
        if !STATES.contains(&state) {
            return Err(format!("{context} {name} has unknown state {state}"));
        }
        let mut names = vec![name.clone()];
        names.extend(optional_strings(item, "aliases", &context)?);
        let mut present = Vec::with_capacity(names.len());
        for value in &names {
            if value.is_empty() {
                return Err(format!("{context} has an empty name"));
            }
            if !covered.insert(value.to_ascii_lowercase()) {
                return Err(format!("{context} repeats capability name {value}"));
            }
            present.push(source_lower.contains(&value.to_ascii_lowercase()));
        }
        if state != "unavailable" && present.iter().any(|value| !*value) {
            return Err(format!(
                "{context} {name} is marked {state} but is not present in source"
            ));
        }
        let (producer, evaluator) = if state == "unavailable" {
            (None, None)
        } else {
            (Some(spec.producer.to_owned()), Some(spec.evaluator.to_owned()))
        };
        entries.push(Entry {
            names,
            state: state.to_owned(),
            reference_revision: go_commit.to_owned(),
            producer,
            evaluator,
            go_reference: optional_str(item, "go_reference", &context)?,
            fixtures: optional_strings(item, "fixtures", &context)?,
            differences: optional_strings(item, "differences", &context)?,
        });
    }
    for name in source {
        if !covered.contains(&name.to_ascii_lowercase()) {
            entries.push(Entry {
                names: vec![name.clone()],
                state: "unavailable".to_owned(),
                reference_revision: go_commit.to_owned(),
                producer: None,
                evaluator: None,
                go_reference: Some(REVIEW_GO_REFERENCE.to_owned()),
                fixtures: Vec::new(),
                differences: vec![NEW_CAPABILITY_NOTE.to_owned()],
            });
        }
    }
    entries.sort_by_key(|entry| {
        entry
            .names
            .first()
            .map(|name| name.to_ascii_lowercase())
            .unwrap_or_default()
    });
    Ok(entries)
}

/// Generates the manifest text from source and overrides.
fn generate(root: &Path) -> Result<String, String> {
    let overrides_text = fs::read_to_string(root.join(OVERRIDES)).map_err(|error| format!("{OVERRIDES}: {error}"))?;
    let overrides: Value = serde_json::from_str(&overrides_text).map_err(|error| format!("{OVERRIDES}: {error}"))?;
    let reference = overrides
        .get("reference")
        .ok_or_else(|| format!("{OVERRIDES} has no reference block"))?;
    let go_commit = required_str(
        reference
            .get("go_coraza")
            .ok_or_else(|| format!("{OVERRIDES} has no go_coraza reference"))?,
        "commit",
        "go_coraza reference",
    )?;
    let groups = overrides
        .get("groups")
        .ok_or_else(|| format!("{OVERRIDES} has no groups object"))?;
    let group_map = groups
        .as_object()
        .ok_or_else(|| format!("{OVERRIDES} groups is not an object"))?;
    for key in group_map.keys() {
        if !GROUPS.iter().any(|spec| spec.key == key.as_str()) {
            return Err(format!("{OVERRIDES} has unknown group {key}"));
        }
    }
    let mut rendered = Vec::with_capacity(GROUPS.len());
    for spec in &GROUPS {
        verify_symbol(root, spec.producer)?;
        verify_symbol(root, spec.evaluator)?;
        let source = source_names(root, spec)?;
        let entries = build_entries(spec, &source, groups, go_commit)?;
        rendered.push((spec.key, entries));
    }
    render_manifest(reference, &rendered)
}

// -----------------------------------------------------------------------------
// Manifest rendering
// -----------------------------------------------------------------------------

/// Appends a JSON string.
fn push_json_string(out: &mut String, value: &str) {
    out.push_str(&serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned()));
}

/// Appends a string array at the given indent.
fn push_string_array(out: &mut String, values: &[String], indent: usize) {
    if values.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, value) in values.iter().enumerate() {
        out.push_str(&" ".repeat(indent.saturating_add(2)));
        push_json_string(out, value);
        if index.saturating_add(1) < values.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str(&" ".repeat(indent));
    out.push(']');
}

/// Appends an optional string.
fn push_optional_string(out: &mut String, value: Option<&str>) {
    match value {
        Some(value) => push_json_string(out, value),
        None => out.push_str("null"),
    }
}

/// Appends one entry at the given indent.
fn push_entry(out: &mut String, entry: &Entry, indent: usize) {
    let pad = " ".repeat(indent);
    let field_pad = " ".repeat(indent.saturating_add(2));
    out.push_str(&pad);
    out.push_str("{\n");
    out.push_str(&field_pad);
    out.push_str("\"names\": ");
    push_string_array(out, &entry.names, indent.saturating_add(2));
    out.push_str(",\n");
    out.push_str(&field_pad);
    out.push_str("\"state\": ");
    push_json_string(out, &entry.state);
    out.push_str(",\n");
    out.push_str(&field_pad);
    out.push_str("\"reference_revision\": ");
    push_json_string(out, &entry.reference_revision);
    out.push_str(",\n");
    out.push_str(&field_pad);
    out.push_str("\"producer\": ");
    push_optional_string(out, entry.producer.as_deref());
    out.push_str(",\n");
    out.push_str(&field_pad);
    out.push_str("\"evaluator\": ");
    push_optional_string(out, entry.evaluator.as_deref());
    out.push_str(",\n");
    out.push_str(&field_pad);
    out.push_str("\"go_reference\": ");
    push_optional_string(out, entry.go_reference.as_deref());
    out.push_str(",\n");
    out.push_str(&field_pad);
    out.push_str("\"fixtures\": ");
    push_string_array(out, &entry.fixtures, indent.saturating_add(2));
    out.push_str(",\n");
    out.push_str(&field_pad);
    out.push_str("\"differences\": ");
    push_string_array(out, &entry.differences, indent.saturating_add(2));
    out.push('\n');
    out.push_str(&pad);
    out.push('}');
}

/// Appends the reference block.
fn push_reference(out: &mut String, reference: &Value) -> Result<(), String> {
    let profile = required_str(reference, "profile", "reference")?;
    let go = reference.get("go_coraza").ok_or("reference has no go_coraza block")?;
    let rust = reference.get("rust").ok_or("reference has no rust block")?;
    out.push_str("  \"reference\": {\n");
    out.push_str("    \"profile\": ");
    push_json_string(out, profile);
    out.push_str(",\n");
    for (key, block) in [("go_coraza", go), ("rust", rust)] {
        let repository = required_str(block, "repository", key)?;
        let commit = required_str(block, "commit", key)?;
        out.push_str("    ");
        push_json_string(out, key);
        out.push_str(": {\n");
        out.push_str("      \"repository\": ");
        push_json_string(out, repository);
        out.push_str(",\n");
        out.push_str("      \"commit\": ");
        push_json_string(out, commit);
        out.push_str("\n    }");
        if key == "go_coraza" {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  },\n");
    Ok(())
}

/// Renders the complete manifest deterministically.
fn render_manifest(reference: &Value, groups: &[(&str, Vec<Entry>)]) -> Result<String, String> {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"schema_version\": 1,\n");
    out.push_str("  \"description\": ");
    push_json_string(&mut out, DESCRIPTION);
    out.push_str(",\n");
    push_reference(&mut out, reference)?;
    out.push_str("  \"states\": [\n");
    for (index, state) in STATES.iter().enumerate() {
        out.push_str("    ");
        push_json_string(&mut out, state);
        if index.saturating_add(1) < STATES.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ],\n");
    out.push_str("  \"capability_groups\": {\n");
    for (index, (key, entries)) in groups.iter().enumerate() {
        out.push_str("    ");
        push_json_string(&mut out, key);
        out.push_str(": [\n");
        for (entry_index, entry) in entries.iter().enumerate() {
            push_entry(&mut out, entry, 6);
            if entry_index.saturating_add(1) < entries.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("    ]");
        if index.saturating_add(1) < groups.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  }\n}\n");
    Ok(out)
}

// -----------------------------------------------------------------------------
// Checks
// -----------------------------------------------------------------------------

fn check(root: &Path) -> Result<(), String> {
    let expected = generate(root)?;
    let path = root.join(MANIFEST);
    let actual = fs::read_to_string(&path).map_err(|error| format!("{MANIFEST}: {error}"))?;
    if expected != actual {
        return Err(format!(
            "{MANIFEST} is out of date; run `cargo xtask conformance-refresh`"
        ));
    }
    check_ledger(root)?;
    check_example(root)?;
    println!("Conformance manifest, difference ledger and example case are consistent");
    Ok(())
}

fn refresh(root: &Path) -> Result<(), String> {
    let rendered = generate(root)?;
    fs::write(root.join(MANIFEST), rendered).map_err(|error| format!("{MANIFEST}: {error}"))?;
    check(root)?;
    println!("Refreshed {MANIFEST} from source and {OVERRIDES}");
    Ok(())
}

/// Returns true for a lower-case SHA-256 hex string.
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Returns true for a 40-character hexadecimal commit.
fn is_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Strips the surrounding backticks from a ledger cell.
fn code_cell(cell: &str, label: &str) -> Result<String, String> {
    cell.strip_prefix('`')
        .and_then(|value| value.strip_suffix('`'))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("ledger {label} is not a non-empty code span: {cell}"))
}

fn check_ledger(root: &Path) -> Result<(), String> {
    let text = fs::read_to_string(root.join(LEDGER)).map_err(|error| format!("{LEDGER}: {error}"))?;
    let mut in_table = false;
    let mut rows = 0_usize;
    for line in text.lines() {
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
        let mut cells = line.trim_matches('|').split('|').map(str::trim);
        let Some(case_cell) = cells.next() else {
            return Err("ledger row has no cells".to_owned());
        };
        if case_cell.starts_with("---") {
            continue;
        }
        let Some(hash_cell) = cells.next() else {
            return Err(format!("ledger row does not have five columns: {line}"));
        };
        let Some(go_cell) = cells.next() else {
            return Err(format!("ledger row does not have five columns: {line}"));
        };
        let Some(rust_cell) = cells.next() else {
            return Err(format!("ledger row does not have five columns: {line}"));
        };
        let Some(reason_cell) = cells.next() else {
            return Err(format!("ledger row does not have five columns: {line}"));
        };
        if cells.next().is_some() {
            return Err(format!("ledger row does not have five columns: {line}"));
        }
        let case_id = code_cell(case_cell, "case ID")?;
        let hash = code_cell(hash_cell, "fixture hash")?;
        if !is_sha256(&hash) {
            return Err(format!("ledger hash for {case_id} is not SHA-256: {hash}"));
        }
        for (cell, label) in [
            (go_cell, "Go outcome"),
            (rust_cell, "Rust outcome"),
            (reason_cell, "reason"),
        ] {
            if cell.is_empty() {
                return Err(format!("ledger {label} is empty for {case_id}"));
            }
        }
        rows = rows.saturating_add(1);
    }
    if rows == 0 {
        return Err("difference ledger has no reviewed rows".to_owned());
    }
    Ok(())
}

/// Returns true for a well-formed base64 string.
fn is_base64(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return false;
    }
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 {
        return false;
    }
    let data_len = bytes.len().saturating_sub(padding);
    bytes.get(..data_len).is_some_and(|data| {
        data.iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/')
    })
}

/// Returns the decoded length of a valid base64 string.
fn decoded_len(value: &str) -> usize {
    let padding = value.as_bytes().iter().rev().take_while(|byte| **byte == b'=').count();
    value.len() / 4 * 3 - padding
}

/// Resolves an inline byte value or a validated fixture range.
fn fixture_range(value: &Value, corpus_root: &Path) -> Result<(PathBuf, usize, usize), String> {
    let fixture = value
        .get("fixture")
        .and_then(Value::as_str)
        .ok_or("byte value has neither base64 nor fixture")?;
    let sha = value
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("fixture {fixture} has no sha256"))?;
    if !is_sha256(sha) {
        return Err(format!("fixture {fixture} hash is malformed"));
    }
    let path = corpus_root.join(fixture);
    let metadata = fs::metadata(&path).map_err(|error| format!("fixture {fixture}: {error}"))?;
    let file_len =
        usize::try_from(metadata.len()).map_err(|error| format!("fixture {fixture} is too large: {error}"))?;
    let offset = match value.get("offset").and_then(Value::as_u64) {
        Some(offset) => {
            usize::try_from(offset).map_err(|error| format!("fixture {fixture} offset is too large: {error}"))?
        },
        None => 0,
    };
    if offset > file_len {
        return Err(format!("fixture {fixture} offset is past the end of the file"));
    }
    let length = match value.get("length").and_then(Value::as_u64) {
        Some(length) => {
            usize::try_from(length).map_err(|error| format!("fixture {fixture} length is too large: {error}"))?
        },
        None => file_len.saturating_sub(offset),
    };
    let end = offset
        .checked_add(length)
        .ok_or_else(|| format!("fixture {fixture} range overflows"))?;
    if end > file_len {
        return Err(format!("fixture {fixture} range extends past the end of the file"));
    }
    Ok((path, offset, length))
}

fn check_bytes(value: &Value, corpus_root: &Path) -> Result<(), String> {
    if let Some(encoded) = value.get("base64").and_then(Value::as_str) {
        if !is_base64(encoded) {
            return Err("corpus case contains invalid base64".to_owned());
        }
        return Ok(());
    }
    fixture_range(value, corpus_root)?;
    Ok(())
}

fn bytes_length(value: &Value, corpus_root: &Path) -> Result<usize, String> {
    if let Some(encoded) = value.get("base64").and_then(Value::as_str) {
        if !is_base64(encoded) {
            return Err("corpus case contains invalid base64".to_owned());
        }
        return Ok(decoded_len(encoded));
    }
    let (_, _, length) = fixture_range(value, corpus_root)?;
    Ok(length)
}

fn check_headers(value: &Value, corpus_root: &Path) -> Result<(), String> {
    let headers = value
        .get("headers")
        .and_then(Value::as_array)
        .ok_or("corpus message has no headers array")?;
    for header in headers {
        let name = header.get("name").and_then(Value::as_str).ok_or("header has no name")?;
        if name.is_empty() {
            return Err("header name is empty".to_owned());
        }
        check_bytes(header.get("value").ok_or("header has no value")?, corpus_root)?;
    }
    Ok(())
}

fn check_chunks(message: &Value, corpus_root: &Path) -> Result<(), String> {
    let body = message.get("body").ok_or("corpus message has no body")?;
    let body_len = bytes_length(body, corpus_root)?;
    let chunks = message
        .get("chunks")
        .and_then(Value::as_array)
        .ok_or("corpus message has no chunks array")?;
    let mut next = 0_usize;
    for chunk in chunks {
        let offset = chunk
            .get("offset")
            .and_then(Value::as_u64)
            .ok_or("chunk has no offset")?;
        let length = chunk
            .get("length")
            .and_then(Value::as_u64)
            .ok_or("chunk has no length")?;
        let offset = usize::try_from(offset).map_err(|error| format!("chunk offset is too large: {error}"))?;
        let length = usize::try_from(length).map_err(|error| format!("chunk length is too large: {error}"))?;
        if offset != next {
            return Err("chunk offsets are not contiguous".to_owned());
        }
        next = offset.checked_add(length).ok_or("chunk length overflows")?;
        if next > body_len {
            return Err("chunk extends past the body".to_owned());
        }
    }
    if next != body_len {
        return Err("chunks do not cover the body".to_owned());
    }
    Ok(())
}

fn check_phase_calls(case: &Value) -> Result<(), String> {
    let calls = case
        .get("phase_calls")
        .and_then(Value::as_array)
        .ok_or("example case has no phase_calls array")?;
    let mut last_phase = 0_u64;
    for call in calls {
        let phase = call
            .get("phase")
            .and_then(Value::as_u64)
            .ok_or("phase call has no phase")?;
        if phase < last_phase {
            return Err("phase calls are not ordered".to_owned());
        }
        last_phase = phase;
        let name = call
            .get("call")
            .and_then(Value::as_str)
            .ok_or("phase call has no name")?;
        if matches!(name, "append_request_body" | "append_response_body")
            && call.get("chunk_index").and_then(Value::as_u64).is_none()
        {
            return Err(format!("{name} requires an integer chunk_index"));
        }
    }
    Ok(())
}

fn check_expected(case: &Value) -> Result<(), String> {
    let expected = case.get("expected").ok_or("example case has no expected block")?;
    for field in [
        "matches",
        "interruptions",
        "captures",
        "scores",
        "flags",
        "collections",
        "audit",
    ] {
        if expected.get(field).is_none() {
            return Err(format!("expected block is missing {field}"));
        }
    }
    Ok(())
}

fn check_example(root: &Path) -> Result<(), String> {
    let text = fs::read_to_string(root.join(EXAMPLE)).map_err(|error| format!("{EXAMPLE}: {error}"))?;
    let case: Value = serde_json::from_str(&text).map_err(|error| format!("{EXAMPLE}: {error}"))?;
    for field in [
        "schema_version",
        "case_id",
        "fixture_sha256",
        "reference",
        "connection",
        "request",
        "response",
        "processor",
        "phase_calls",
        "expected",
        "normalize",
    ] {
        if case.get(field).is_none() {
            return Err(format!("example case is missing {field}"));
        }
    }
    if case.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("example case schema_version is not 1".to_owned());
    }
    let case_sha = case
        .get("fixture_sha256")
        .and_then(Value::as_str)
        .ok_or("example case has no fixture_sha256")?;
    if !is_sha256(case_sha) {
        return Err("example fixture hash is malformed".to_owned());
    }
    let reference = case.get("reference").ok_or("example has no reference")?;
    for commit in ["go_commit", "rust_commit"] {
        let value = reference
            .get(commit)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("reference has no {commit}"))?;
        if !is_commit(value) {
            return Err(format!("{commit} is not a full commit hash"));
        }
    }
    let corpus_root = root.join(CORPUS_ROOT);
    for message in ["request", "response"] {
        let value = case.get(message).ok_or_else(|| format!("example has no {message}"))?;
        check_headers(value, &corpus_root)?;
        check_bytes(
            value.get("body").ok_or_else(|| format!("{message} has no body"))?,
            &corpus_root,
        )?;
        check_chunks(value, &corpus_root)?;
    }
    check_bytes(
        case.get("request")
            .and_then(|request| request.get("uri"))
            .ok_or("request has no uri")?,
        &corpus_root,
    )?;
    check_phase_calls(&case)?;
    check_expected(&case)?;
    let normalize = case
        .get("normalize")
        .and_then(Value::as_array)
        .ok_or("example has no normalize array")?;
    for value in normalize {
        let value = value.as_str().ok_or("normalize contains a non-string")?;
        if ![
            "timestamps",
            "generated_ids",
            "temporary_paths",
            "audit_boundaries",
            "header_order",
        ]
        .contains(&value)
        {
            return Err(format!("unknown normalization {value}"));
        }
    }
    Ok(())
}
