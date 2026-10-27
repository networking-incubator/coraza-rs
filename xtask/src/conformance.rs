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
    /// Variants of a source enum, excluding non-capability variants.
    EnumVariants {
        /// Source file.
        file: &'static str,
        /// Enum signature.
        signature: &'static str,
        /// Variants that are implementation details rather than writer names.
        excluded: &'static [&'static str],
    },
    /// The `VARIABLES` lookup table.
    Variables,
}

/// Returns true when the group's source names are effective registry entries.
///
/// `VARIABLES` also lists names without a storage arm, so an unavailable
/// variable is not a contradiction; the drift test validates that state.
fn is_registry(spec: &GroupSpec) -> bool {
    !matches!(&spec.source, Source::Variables)
}

/// Registry scopes from which a group's names are derived.
fn registry_scopes(spec: &GroupSpec) -> Vec<(&'static str, &'static str)> {
    match &spec.source {
        Source::MatchArms { sources, .. } => sources.to_vec(),
        Source::StringList { file, signature } | Source::EnumVariants { file, signature, .. } => {
            vec![(*file, *signature)]
        },
        Source::Variables => Vec::new(),
    }
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

const GROUPS: [GroupSpec; 8] = [
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
        evaluator: "coraza/src/transaction/variables.rs:variable_storage!",
        source: Source::Variables,
    },
    GroupSpec {
        key: "body_processors",
        producer: "coraza/src/transaction/variables.rs:BodyProcessor::parse",
        evaluator: "coraza/src/transaction/request_body.rs:process_request_body",
        source: Source::StringList {
            file: "coraza/src/actions/mod.rs",
            signature: "fn is_body_processor",
        },
    },
    GroupSpec {
        key: "runtime_controls",
        producer: "coraza/src/actions/mod.rs:validate_ctl",
        evaluator: "coraza/src/transaction/ctl.rs:Transaction::apply_ctl",
        source: Source::MatchArms {
            sources: &[
                ("coraza/src/actions/mod.rs", "fn validate_ctl"),
                ("coraza/src/transaction/ctl.rs", "pub(crate) fn apply_ctl"),
            ],
            extra: &[],
        },
    },
    GroupSpec {
        key: "audit_writers",
        producer: "coraza/src/audit_log.rs:AuditLogger::prepare",
        evaluator: "coraza/src/audit_log.rs:Writer::write",
        source: Source::EnumVariants {
            file: "coraza/src/audit_log.rs",
            signature: "enum WriterPlan",
            excluded: &["Discard"],
        },
    },
];

/// Explicit source gates for capabilities whose availability depends on a Cargo feature.
///
/// Each row names the registry scope and item that must immediately follow its `cfg`
/// attribute. Keep this map explicit: it makes a changed or removed source gate fail
/// generation instead of silently inferring availability from prose or unrelated cfgs.
struct FeatureGate {
    /// Capability group.
    group: &'static str,
    /// Capability name, compared case-insensitively.
    name: &'static str,
    /// Cargo feature required by the source item.
    feature: &'static str,
    /// Source file containing the gated item.
    file: &'static str,
    /// Function or enum whose body holds the gate.
    scope: &'static str,
    /// Text that starts the gated registry arm or enum variant.
    item: &'static str,
}

const FEATURE_GATES: [FeatureGate; 4] = [
    FeatureGate {
        group: "operators",
        name: "inspectFile",
        feature: "inspect-file",
        file: "coraza/src/operators/mod.rs",
        scope: "pub fn with_context",
        item: "\"inspectfile\"",
    },
    FeatureGate {
        group: "operators",
        name: "rbl",
        feature: "rbl",
        file: "coraza/src/operators/mod.rs",
        scope: "pub fn with_context",
        item: "\"rbl\"",
    },
    FeatureGate {
        group: "operators",
        name: "validateSchema",
        feature: "validate-schema",
        file: "coraza/src/operators/mod.rs",
        scope: "pub fn with_context",
        item: "\"validateschema\"",
    },
    FeatureGate {
        group: "audit_writers",
        name: "https",
        feature: "https-audit",
        file: "coraza/src/audit_log.rs",
        scope: "enum WriterPlan",
        item: "Https {",
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

/// Reads the variant names of an enum, preserving source order.
fn enum_variant_names(source: &str, signature: &str, excluded: &[&str]) -> Result<Vec<String>, String> {
    let body = function_body(source, signature)?;
    let mut names = Vec::new();
    for line in body.lines() {
        let token = line
            .trim_start()
            .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .next()
            .unwrap_or_default();
        if token.chars().next().is_some_and(|ch| ch.is_ascii_uppercase()) && !excluded.contains(&token) {
            names.push(token.to_ascii_lowercase());
        }
    }
    Ok(names)
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
        Source::EnumVariants {
            file,
            signature,
            excluded,
        } => {
            let source = read_source(root, file)?;
            enum_variant_names(&source, signature, excluded)?
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

/// Returns true for a Rust identifier character.
fn is_identifier_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

/// Returns true when no identifier character precedes `index`.
fn has_boundary_before(text: &str, index: usize) -> bool {
    text.get(..index)
        .and_then(|prefix| prefix.chars().next_back())
        .is_none_or(|ch| !is_identifier_char(ch))
}

/// Returns true when no identifier character starts at `index`.
fn has_boundary_after(text: &str, index: usize) -> bool {
    text.get(index..)
        .and_then(|rest| rest.chars().next())
        .is_none_or(|ch| !is_identifier_char(ch))
}

/// Appends one masked character, keeping line breaks so the text stays line-shaped.
fn push_masked(out: &mut String, ch: char) {
    out.push(if ch == '\n' { '\n' } else { ' ' });
}

/// Returns the number of `#` characters in a raw string prefix at `index`.
fn raw_string_hashes(chars: &[char], index: usize) -> Option<usize> {
    if chars.get(index) != Some(&'r') {
        return None;
    }
    if index > 0 {
        let previous = chars.get(index.checked_sub(1)?)?;
        let prefixed = if *previous == 'b' {
            index < 2 || chars.get(index - 2).is_none_or(|ch| !is_identifier_char(*ch))
        } else {
            !is_identifier_char(*previous)
        };
        if !prefixed {
            return None;
        }
    }
    let mut cursor = index.saturating_add(1);
    let mut hashes = 0_usize;
    while chars.get(cursor) == Some(&'#') {
        hashes = hashes.saturating_add(1);
        cursor = cursor.saturating_add(1);
    }
    (chars.get(cursor) == Some(&'"')).then_some(hashes)
}

/// Masks a string literal starting at the opening quote and returns the index after it.
fn mask_string(chars: &[char], mut index: usize, out: &mut String) -> usize {
    push_masked(out, '"');
    index = index.saturating_add(1);
    while let Some(&ch) = chars.get(index) {
        push_masked(out, ch);
        index = index.saturating_add(1);
        if ch == '\\' {
            if let Some(&next) = chars.get(index) {
                push_masked(out, next);
                index = index.saturating_add(1);
            }
        } else if ch == '"' {
            break;
        }
    }
    index
}

/// Masks a raw string body starting at the opening quote and returns the index after it.
fn mask_raw_string(chars: &[char], mut index: usize, hashes: usize, out: &mut String) -> usize {
    push_masked(out, '"');
    index = index.saturating_add(1);
    while let Some(&ch) = chars.get(index) {
        push_masked(out, ch);
        index = index.saturating_add(1);
        if ch != '"' {
            continue;
        }
        let mut seen = 0;
        while seen < hashes {
            let Some(&next) = chars.get(index) else {
                break;
            };
            if next != '#' {
                break;
            }
            push_masked(out, next);
            index = index.saturating_add(1);
            seen = seen.saturating_add(1);
        }
        if seen == hashes {
            break;
        }
    }
    index
}

/// Returns the index of the closing quote when a character literal starts at `index`.
fn char_literal_end(chars: &[char], index: usize) -> Option<usize> {
    if chars.get(index) != Some(&'\'') {
        return None;
    }
    let mut cursor = index.checked_add(1)?;
    if chars.get(cursor) == Some(&'\\') {
        cursor = cursor.checked_add(1)?;
        match chars.get(cursor) {
            Some(&'x') => cursor = cursor.checked_add(3)?,
            Some(&'u') => {
                cursor = cursor.checked_add(1)?;
                while chars.get(cursor).is_some_and(|ch| *ch != '}') {
                    cursor = cursor.checked_add(1)?;
                }
                cursor = cursor.checked_add(1)?;
            },
            Some(_) => cursor = cursor.checked_add(1)?,
            None => return None,
        }
    } else {
        cursor = cursor.checked_add(1)?;
    }
    (chars.get(cursor) == Some(&'\'')).then_some(cursor)
}

/// Returns a copy of `source` with comments and literals replaced by spaces.
fn mask_non_code(source: &str) -> String {
    let chars = source.chars().collect::<Vec<_>>();
    let mut out = String::with_capacity(source.len());
    let mut index = 0;
    while let Some(&ch) = chars.get(index) {
        if ch == '/' && chars.get(index.saturating_add(1)) == Some(&'/') {
            while let Some(&current) = chars.get(index) {
                if current == '\n' {
                    break;
                }
                push_masked(&mut out, current);
                index = index.saturating_add(1);
            }
            continue;
        }
        if ch == '/' && chars.get(index.saturating_add(1)) == Some(&'*') {
            let mut depth = 0_usize;
            while let Some(&current) = chars.get(index) {
                if current == '/' && chars.get(index.saturating_add(1)) == Some(&'*') {
                    depth = depth.saturating_add(1);
                    push_masked(&mut out, '/');
                    push_masked(&mut out, '*');
                    index = index.saturating_add(2);
                } else if current == '*' && chars.get(index.saturating_add(1)) == Some(&'/') {
                    depth = depth.saturating_sub(1);
                    push_masked(&mut out, '*');
                    push_masked(&mut out, '/');
                    index = index.saturating_add(2);
                    if depth == 0 {
                        break;
                    }
                } else {
                    push_masked(&mut out, current);
                    index = index.saturating_add(1);
                }
            }
            continue;
        }
        if ch == 'r'
            && let Some(hashes) = raw_string_hashes(&chars, index)
        {
            push_masked(&mut out, 'r');
            index = index.saturating_add(1);
            for _ in 0..hashes {
                push_masked(&mut out, '#');
                index = index.saturating_add(1);
            }
            index = mask_raw_string(&chars, index, hashes, &mut out);
            continue;
        }
        if ch == '"' {
            index = mask_string(&chars, index, &mut out);
            continue;
        }
        if ch == '\''
            && let Some(end) = char_literal_end(&chars, index)
        {
            while index <= end {
                if let Some(&current) = chars.get(index) {
                    push_masked(&mut out, current);
                }
                index = index.saturating_add(1);
            }
            continue;
        }
        out.push(ch);
        index = index.saturating_add(1);
    }
    out
}

/// Keywords that introduce a named item in Rust source.
const DEFINITION_KEYWORDS: [&str; 8] = ["fn", "struct", "enum", "trait", "type", "const", "static", "mod"];

/// Returns true when `code` contains `keyword name` with identifier boundaries.
fn has_definition(code: &str, keyword: &str, name: &str) -> bool {
    let mut from = 0;
    while let Some(offset) = code.get(from..).and_then(|rest| rest.find(keyword)) {
        let start = from.saturating_add(offset);
        let after_keyword = start.saturating_add(keyword.len());
        let boundary =
            has_boundary_before(code, start) && (keyword.ends_with('!') || has_boundary_after(code, after_keyword));
        if boundary {
            let rest = code.get(after_keyword..).unwrap_or_default();
            let trimmed = rest.trim_start();
            if trimmed.starts_with(name) {
                let skipped = rest.len().saturating_sub(trimmed.len());
                let end = after_keyword.saturating_add(skipped).saturating_add(name.len());
                if has_boundary_after(code, end) {
                    return true;
                }
            }
        }
        from = after_keyword;
    }
    false
}

/// Returns the index just after a leading generic parameter list.
fn skip_generics(text: &str) -> usize {
    let mut depth = 0_i32;
    let mut previous = None;
    for (index, ch) in text.char_indices() {
        if ch == '<' {
            depth = depth.saturating_add(1);
        } else if ch == '>' && previous != Some('-') {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return index.saturating_add(1);
            }
        }
        previous = Some(ch);
    }
    text.len()
}

/// Returns the byte offset of the last top-level `keyword` in `text`.
fn find_top_level_keyword(text: &str, keyword: &str) -> Option<usize> {
    let mut depth = 0_i32;
    let mut previous = None;
    let mut found = None;
    for (index, ch) in text.char_indices() {
        if ch == '<' {
            depth = depth.saturating_add(1);
        } else if ch == '>' && depth > 0 && previous != Some('-') {
            depth = depth.saturating_sub(1);
        } else if depth == 0
            && text.get(index..).is_some_and(|rest| rest.starts_with(keyword))
            && has_boundary_before(text, index)
            && has_boundary_after(text, index.saturating_add(keyword.len()))
        {
            found = Some(index);
        }
        previous = Some(ch);
    }
    found
}

/// Removes generic argument lists from a type expression.
fn strip_generic_groups(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut depth = 0_i32;
    let mut previous = None;
    for ch in text.chars() {
        if ch == '<' {
            depth = depth.saturating_add(1);
        } else if ch == '>' && depth > 0 && previous != Some('-') {
            depth = depth.saturating_sub(1);
        } else if depth == 0 {
            out.push(ch);
        }
        previous = Some(ch);
    }
    out
}

/// Returns the last identifier-like run in `text`.
fn last_identifier(text: &str) -> &str {
    text.rsplit(|ch: char| !is_identifier_char(ch))
        .find(|segment| !segment.is_empty())
        .unwrap_or_default()
}

/// Returns true when a stripped impl type expression names `qualifier`.
fn impl_type_matches(type_text: &str, qualifier: &str) -> bool {
    let compact = type_text.chars().filter(|ch| !ch.is_whitespace()).collect::<String>();
    if compact == qualifier {
        return true;
    }
    if qualifier.contains("::") {
        return compact
            .strip_suffix(qualifier)
            .is_some_and(|prefix| prefix.ends_with("::"));
    }
    last_identifier(compact.rsplit("::").next().unwrap_or_default()) == qualifier
}

/// Returns true when an impl header names `qualifier`.
fn impl_header_names(header: &str, qualifier: &str) -> bool {
    let header = header.trim_start();
    let rest = if header.starts_with('<') {
        header.get(skip_generics(header)..).unwrap_or_default()
    } else {
        header
    };
    let rest = match find_top_level_keyword(rest, "where") {
        Some(index) => rest.get(..index).unwrap_or_default(),
        None => rest,
    };
    let type_text = match find_top_level_keyword(rest, "for") {
        Some(index) => rest.get(index.saturating_add(3)..).unwrap_or_default(),
        None => rest,
    };
    impl_type_matches(&strip_generic_groups(type_text), qualifier)
}

/// Returns the byte index of the `}` matching the `{` at `open`.
fn matching_brace(code: &str, open: usize) -> Option<usize> {
    let mut depth = 0_usize;
    for (offset, ch) in code.get(open..)?.char_indices() {
        if ch == '{' {
            depth = depth.saturating_add(1);
        } else if ch == '}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return open.checked_add(offset);
            }
        }
    }
    None
}

/// Returns true when a matching impl block contains `fn method`.
fn has_impl_method(code: &str, qualifier: &str, method: &str) -> bool {
    let mut from = 0;
    while let Some(offset) = code.get(from..).and_then(|rest| rest.find("impl")) {
        let start = from.saturating_add(offset);
        from = start.saturating_add(4);
        if !has_boundary_before(code, start) || !has_boundary_after(code, from) {
            continue;
        }
        let Some(open_offset) = code.get(from..).and_then(|rest| rest.find('{')) else {
            break;
        };
        let open = from.saturating_add(open_offset);
        let header = code.get(from..open).unwrap_or_default();
        if !impl_header_names(header, qualifier) {
            continue;
        }
        let Some(close) = matching_brace(code, open) else {
            break;
        };
        let block = code.get(open..close).unwrap_or_default();
        if has_definition(block, "fn", method) {
            return true;
        }
    }
    false
}

/// Returns true when `symbol` resolves to a definition in `source`.
fn symbol_defined(source: &str, symbol: &str) -> bool {
    let code = mask_non_code(source);
    if let Some(macro_symbol) = symbol.strip_suffix('!') {
        let name = macro_symbol.rsplit("::").next().unwrap_or(macro_symbol);
        return has_definition(&code, "macro_rules!", name);
    }
    if let Some((qualifier, method)) = symbol.rsplit_once("::") {
        return has_impl_method(&code, qualifier, method);
    }
    DEFINITION_KEYWORDS
        .iter()
        .any(|keyword| has_definition(&code, keyword, symbol))
}

/// Verifies that a `file:symbol` reference exists in source.
fn verify_symbol(root: &Path, reference: &str) -> Result<(), String> {
    let (file, symbol) = reference
        .split_once(':')
        .ok_or_else(|| format!("symbol reference has no file: {reference}"))?;
    let source = read_source(root, file)?;
    if !symbol_defined(&source, symbol) {
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
    requires_features: Vec<String>,
    reference_revision: String,
    producer: Option<String>,
    evaluator: Option<String>,
    go_reference: Option<String>,
    fixtures: Vec<String>,
    differences: Vec<String>,
}

/// Shared profile inputs for entries in one generated manifest.
struct GenerationContext<'a> {
    go_commit: &'a str,
    known_features: &'a BTreeSet<String>,
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

/// Reads the actual feature names declared by `coraza/Cargo.toml`.
fn cargo_feature_names(root: &Path) -> Result<BTreeSet<String>, String> {
    let source = read_source(root, "coraza/Cargo.toml")?;
    let manifest: toml::Value = toml::from_str(&source).map_err(|error| format!("coraza/Cargo.toml: {error}"))?;
    let features = manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .ok_or("coraza/Cargo.toml has no [features] table")?;
    Ok(features.keys().cloned().collect())
}

/// Reads an optional feature array, rejecting empty strings and unknown Cargo features.
fn optional_features(
    value: &Value,
    context: &str,
    known_features: &BTreeSet<String>,
) -> Result<Option<Vec<String>>, String> {
    let Some(items) = value.get("features") else {
        return Ok(None);
    };
    let items = items
        .as_array()
        .ok_or_else(|| format!("{context} field features is not an array"))?;
    let mut features = Vec::with_capacity(items.len());
    for item in items {
        let feature = item
            .as_str()
            .ok_or_else(|| format!("{context} field features contains a non-string"))?;
        if feature.trim().is_empty() {
            return Err(format!("{context} field features contains an empty string"));
        }
        if !known_features.contains(feature) {
            return Err(format!("{context} requires unknown Cargo feature {feature}"));
        }
        features.push(feature.to_owned());
    }
    features.sort();
    features.dedup();
    Ok(Some(features))
}

/// Requires overrides to match the source-gate map exactly.
fn resolve_source_features(
    context: &str,
    declared: Option<Vec<String>>,
    source_features: &BTreeSet<String>,
) -> Result<Vec<String>, String> {
    if !source_features.is_empty() && declared.is_none() {
        return Err(format!("{context} is source-gated and must declare features"));
    }
    let requires_features = declared.unwrap_or_default();
    for feature in &requires_features {
        if !source_features.contains(feature) {
            return Err(format!("{context} claims feature {feature} without a source gate"));
        }
    }
    for feature in source_features {
        if !requires_features.contains(feature) {
            return Err(format!("{context} is missing source-gated feature {feature}"));
        }
    }
    Ok(requires_features)
}

/// Returns whether the named item immediately follows its explicit feature cfg.
fn source_item_has_feature_gate(source: &str, scope: &str, feature: &str, item: &str) -> Result<bool, String> {
    let body = function_body(source, scope)?;
    let gate = format!("#[cfg(feature = \"{feature}\")]");
    let mut lines = body.lines();
    let mut previous = lines.next();
    for line in lines {
        if previous.is_some_and(|attribute| attribute.trim() == gate && line.trim_start().starts_with(item)) {
            return Ok(true);
        }
        previous = Some(line);
    }
    Ok(false)
}

/// Lists adjacent feature-gated arms or variants in one registry scope.
fn source_feature_gates(source: &str, scope: &str) -> Result<BTreeSet<(String, String)>, String> {
    let body = function_body(source, scope)?;
    let mut lines = body.lines();
    let mut previous = lines.next();
    let mut gates = BTreeSet::new();
    for item in lines {
        let Some(attribute) = previous else {
            previous = Some(item);
            continue;
        };
        let attribute = attribute.trim();
        if !attribute.starts_with("#[cfg") {
            previous = Some(item);
            continue;
        }
        let feature = attribute
            .strip_prefix("#[cfg(feature = \"")
            .and_then(|value| value.strip_suffix("\")]"))
            .ok_or_else(|| format!("unrecognized cfg gate in {scope}; update FEATURE_GATES"))?;
        let item = item.trim_start();
        let name = if item.starts_with('"') {
            string_literals(item).into_iter().next().unwrap_or_default()
        } else {
            item.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase()
        };
        if name.is_empty() {
            return Err(format!("feature gate in {scope} has no registry item"));
        }
        gates.insert((feature.to_owned(), name.to_ascii_lowercase()));
        previous = Some(item);
    }
    Ok(gates)
}

/// Fails when a registry scope has a feature gate missing from `FEATURE_GATES`.
fn validate_registry_feature_gates(group: &str, file: &str, scope: &str, source: &str) -> Result<(), String> {
    for (feature, name) in source_feature_gates(source, scope)? {
        if !FEATURE_GATES.iter().any(|gate| {
            gate.group == group
                && gate.file == file
                && gate.scope == scope
                && gate.feature == feature
                && gate.name.eq_ignore_ascii_case(&name)
        }) {
            return Err(format!(
                "{file} registry scope {scope} has unaccounted cfg(feature = \"{feature}\") gate for {name}; update FEATURE_GATES"
            ));
        }
    }
    Ok(())
}

/// Confirms every explicit source-gate map entry still matches source and Cargo metadata.
fn validate_source_feature_gates(
    root: &Path,
    spec: &GroupSpec,
    source_names: &[String],
    known_features: &BTreeSet<String>,
) -> Result<(), String> {
    let source_names = source_names
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    for gate in FEATURE_GATES.iter().filter(|gate| gate.group == spec.key) {
        let context = format!("{} capability {}", spec.key, gate.name);
        if !source_names.contains(&gate.name.to_ascii_lowercase()) {
            return Err(format!("{context} is missing from its source registry"));
        }
        if !known_features.contains(gate.feature) {
            return Err(format!("{context} uses undeclared Cargo feature {}", gate.feature));
        }
        let source = read_source(root, gate.file)?;
        if !source_item_has_feature_gate(&source, gate.scope, gate.feature, gate.item)? {
            return Err(format!("{context} is not gated by source feature {}", gate.feature));
        }
    }
    for (file, scope) in registry_scopes(spec) {
        let source = read_source(root, file)?;
        validate_registry_feature_gates(spec.key, file, scope, &source)?;
    }
    // Keep the exact gate-map check for existing entries after scanning every registry scope.
    let expected = FEATURE_GATES
        .iter()
        .filter(|gate| gate.group == spec.key)
        .map(|gate| (gate.feature.to_owned(), gate.name.to_ascii_lowercase()))
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for gate in FEATURE_GATES.iter().filter(|gate| gate.group == spec.key) {
        let source = read_source(root, gate.file)?;
        actual.extend(source_feature_gates(&source, gate.scope)?);
    }
    if actual != expected {
        return Err(format!(
            "{group} source feature gates differ from FEATURE_GATES: expected {expected:?}, found {actual:?}",
            group = spec.key
        ));
    }
    Ok(())
}

/// Resolves one entry's feature list against the explicit source-gate map.
fn entry_features(
    spec: &GroupSpec,
    names: &[String],
    item: &Value,
    context: &str,
    known_features: &BTreeSet<String>,
) -> Result<Vec<String>, String> {
    let declared = optional_features(item, context, known_features)?;
    let source_features = names
        .iter()
        .flat_map(|name| {
            FEATURE_GATES
                .iter()
                .filter(move |gate| gate.group == spec.key && gate.name.eq_ignore_ascii_case(name))
                .map(|gate| gate.feature.to_owned())
        })
        .collect::<BTreeSet<_>>();
    resolve_source_features(context, declared, &source_features)
}

/// Resolves producer and evaluator overrides for one capability entry.
fn entry_symbols(
    root: &Path,
    spec: &GroupSpec,
    item: &Value,
    state: &str,
    context: &str,
) -> Result<(Option<String>, Option<String>), String> {
    let producer_override = optional_str(item, "producer", context)?;
    let evaluator_override = optional_str(item, "evaluator", context)?;
    if state == "unavailable" && (producer_override.is_some() || evaluator_override.is_some()) {
        return Err(format!(
            "{context} is unavailable and must not override producer or evaluator"
        ));
    }
    if state == "unavailable" {
        return Ok((None, None));
    }
    let producer = match producer_override {
        Some(value) => {
            verify_symbol(root, &value)?;
            value
        },
        None => spec.producer.to_owned(),
    };
    let evaluator = match evaluator_override {
        Some(value) => {
            verify_symbol(root, &value)?;
            value
        },
        None => spec.evaluator.to_owned(),
    };
    Ok((Some(producer), Some(evaluator)))
}

/// Builds one group's entries from source names and human overrides.
fn build_entries(
    root: &Path,
    spec: &GroupSpec,
    source: &[String],
    overrides: &Value,
    generation: &GenerationContext<'_>,
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
        let requires_features = entry_features(spec, &names, item, &context, generation.known_features)?;
        let (producer, evaluator) = entry_symbols(root, spec, item, state, &context)?;
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
        if state == "unavailable" && present.iter().any(|value| *value) && is_registry(spec) {
            return Err(format!(
                "{context} {name} is marked unavailable but is present in source"
            ));
        }
        entries.push(Entry {
            names,
            state: state.to_owned(),
            requires_features,
            reference_revision: generation.go_commit.to_owned(),
            producer,
            evaluator,
            go_reference: optional_str(item, "go_reference", &context)?,
            fixtures: optional_strings(item, "fixtures", &context)?,
            differences: optional_strings(item, "differences", &context)?,
        });
    }
    for gate in FEATURE_GATES.iter().filter(|gate| gate.group == key) {
        if !covered.contains(&gate.name.to_ascii_lowercase()) {
            return Err(format!(
                "{key} source-gated capability {} has no override with features",
                gate.name
            ));
        }
    }
    for name in source {
        if !covered.contains(&name.to_ascii_lowercase()) {
            entries.push(Entry {
                names: vec![name.clone()],
                state: "unavailable".to_owned(),
                requires_features: Vec::new(),
                reference_revision: generation.go_commit.to_owned(),
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
    let known_features = cargo_feature_names(root)?;
    let generation = GenerationContext {
        go_commit,
        known_features: &known_features,
    };
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
        validate_source_feature_gates(root, spec, &source, &known_features)?;
        let entries = build_entries(root, spec, &source, groups, &generation)?;
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
    out.push_str("\"requires_features\": ");
    push_string_array(out, &entry.requires_features, indent.saturating_add(2));
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

/// Returns the affected group and names for entries that still need classification.
fn review_required(rendered: &str) -> Result<Vec<String>, String> {
    let manifest: Value =
        serde_json::from_str(rendered).map_err(|error| format!("generated manifest is not valid JSON: {error}"))?;
    let groups = manifest
        .get("capability_groups")
        .and_then(Value::as_object)
        .ok_or("generated manifest has no capability_groups object")?;
    let mut found = Vec::new();
    for (group, entries) in groups {
        let entries = entries
            .as_array()
            .ok_or_else(|| format!("generated manifest group {group} is not an array"))?;
        for entry in entries {
            if entry.get("go_reference").and_then(Value::as_str) != Some(REVIEW_GO_REFERENCE) {
                continue;
            }
            let names = entry
                .get("names")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("generated manifest {group} entry has no names array"))?
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            found.push(format!("{group}: {names}"));
        }
    }
    Ok(found)
}

fn check(root: &Path) -> Result<(), String> {
    let expected = generate(root)?;
    let path = root.join(MANIFEST);
    let actual = fs::read_to_string(&path).map_err(|error| format!("{MANIFEST}: {error}"))?;
    if expected != actual {
        return Err(format!(
            "{MANIFEST} is out of date; run `cargo xtask conformance-refresh`"
        ));
    }
    let unclassified = review_required(&expected)?;
    if !unclassified.is_empty() {
        return Err(format!(
            "unclassified source capabilities with go_reference \"{REVIEW_GO_REFERENCE}\": {}; add an override",
            unclassified.join("; ")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_required_reports_unclassified_group_and_name() {
        let rendered = r#"{
            "capability_groups": {
                "operators": [
                    {"names": ["newOperator"], "go_reference": "review required"},
                    {"names": ["eq"], "go_reference": "internal/operators/eq.go"}
                ]
            }
        }"#;
        assert_eq!(
            review_required(rendered).unwrap(),
            vec!["operators: newOperator".to_owned()]
        );
    }

    #[test]
    fn review_required_accepts_classified_entries() {
        let rendered = r#"{"capability_groups": {"operators": []}}"#;
        assert!(review_required(rendered).unwrap().is_empty());
    }

    #[test]
    fn override_features_are_known_sorted_and_deduplicated() {
        let known = BTreeSet::from(["inspect-file".to_owned(), "rbl".to_owned()]);
        let value = serde_json::json!({"features": ["rbl", "inspect-file", "rbl"]});
        assert_eq!(
            optional_features(&value, "operators entry inspectFile", &known).unwrap(),
            Some(vec!["inspect-file".to_owned(), "rbl".to_owned()])
        );
        let empty = serde_json::json!({"features": [""]});
        assert!(optional_features(&empty, "operators entry inspectFile", &known).is_err());
        let unknown = serde_json::json!({"features": ["async-server"]});
        assert!(optional_features(&unknown, "operators entry inspectFile", &known).is_err());
    }

    #[test]
    fn feature_claims_must_match_source_gates() {
        let gate = BTreeSet::from(["inspect-file".to_owned()]);
        assert!(resolve_source_features("inspectFile", None, &gate).is_err());
        assert!(resolve_source_features("inspectFile", Some(vec!["rbl".to_owned()]), &gate).is_err());
        assert_eq!(
            resolve_source_features("inspectFile", Some(vec!["inspect-file".to_owned()]), &gate).unwrap(),
            vec!["inspect-file".to_owned()]
        );
    }

    #[test]
    fn source_gate_must_be_adjacent_to_its_named_item() {
        let source = r#"
            fn registry() {
                #[cfg(feature = "inspect-file")]
                "inspectfile" => true,
            }
        "#;
        assert!(source_item_has_feature_gate(source, "fn registry", "inspect-file", "\"inspectfile\"").unwrap());
        assert!(!source_item_has_feature_gate(source, "fn registry", "rbl", "\"inspectfile\"").unwrap());
    }

    #[test]
    fn source_feature_gate_validation_checks_every_registry_scope() {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        const SOURCES: &[(&str, &str)] = &[
            ("coraza/src/operators/mod.rs", "pub fn with_context"),
            ("coraza/src/operators/mod.rs", "fn secondary_registry"),
        ];
        let spec = GroupSpec {
            key: "operators",
            producer: "",
            evaluator: "",
            source: Source::MatchArms {
                sources: SOURCES,
                extra: &[],
            },
        };
        let known_features = BTreeSet::from([
            "inspect-file".to_owned(),
            "rbl".to_owned(),
            "validate-schema".to_owned(),
            "new-action-feature".to_owned(),
        ]);
        let source_path = "coraza/src/operators/mod.rs";
        let source_file = r#"
            pub fn with_context() {
                #[cfg(feature = "inspect-file")]
                "inspectfile" => true,
                #[cfg(feature = "rbl")]
                "rbl" => true,
                #[cfg(feature = "validate-schema")]
                "validateschema" => true,
            }

            fn secondary_registry() {
                #[cfg(feature = "new-action-feature")]
                "newaction" => true,
            }
        "#;
        let accounted_source = r#"
            pub fn with_context() {
                #[cfg(feature = "inspect-file")]
                "inspectfile" => true,
                #[cfg(feature = "rbl")]
                "rbl" => true,
                #[cfg(feature = "validate-schema")]
                "validateschema" => true,
            }

            fn secondary_registry() {
                "existing" => true,
            }
        "#;
        let root = std::env::temp_dir().join(format!(
            "xtask-conformance-feature-gates-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        let source_root = root.join(source_path);
        fs::create_dir_all(source_root.parent().unwrap()).unwrap();
        fs::write(&source_root, source_file).unwrap();
        let rejected = source_names(&root, &spec)
            .and_then(|names| validate_source_feature_gates(&root, &spec, &names, &known_features));

        fs::write(&source_root, accounted_source).unwrap();
        let accepted = source_names(&root, &spec)
            .and_then(|names| validate_source_feature_gates(&root, &spec, &names, &known_features));
        fs::remove_dir_all(&root).unwrap();

        let error = rejected.unwrap_err();
        assert!(error.contains(source_path), "{error}");
        assert!(error.contains("fn secondary_registry"), "{error}");
        assert!(error.contains("new-action-feature"), "{error}");
        accepted.unwrap();
    }

    #[test]
    fn symbol_defined_matches_method_in_named_impl() {
        let source = "
            impl Rx {
                fn evaluate(&self) -> bool { true }
            }
            impl Other {
                fn evaluate(&self) -> bool { false }
            }
        ";
        assert!(
            symbol_defined(source, "Rx::evaluate"),
            "method inside its own impl block"
        );
    }

    #[test]
    fn symbol_defined_rejects_method_from_other_impl() {
        let source = "
            impl Foo {
                fn evaluate(&self) {}
            }
            impl Bar {
                fn collect(&self) {}
            }
        ";
        assert!(!symbol_defined(source, "Bar::evaluate"), "evaluate belongs to Foo");
    }

    #[test]
    fn symbol_defined_matches_generic_and_trait_impls() {
        let source = "
            impl<T> Holder<T> {
                fn evaluate(&self, value: T) {}
            }
            impl std::fmt::Display for Shown {
                fn fmt(&self) {}
            }
            impl crate::ops::PathType {
                fn run(&self) {}
            }
        ";
        assert!(symbol_defined(source, "Holder::evaluate"), "generic impl");
        assert!(symbol_defined(source, "Shown::fmt"), "trait impl");
        assert!(symbol_defined(source, "PathType::run"), "path-qualified impl type");
    }

    #[test]
    fn symbol_defined_requires_identifier_boundaries() {
        let source = "
            impl Rx {
                fn evaluate_extra(&self) {}
            }
            impl RxExtra {
                fn evaluate(&self) {}
                fn collect(&self) {}
            }
        ";
        assert!(!symbol_defined(source, "Rx::evaluate"), "suffix method is not evaluate");
        assert!(!symbol_defined(source, "Rx::collect"), "suffix type is not Rx");
        assert!(symbol_defined(source, "RxExtra::evaluate"), "exact type and method");
    }

    #[test]
    fn symbol_defined_handles_macros() {
        let source = "macro_rules! storage { () => {}; }";
        assert!(symbol_defined(source, "storage!"), "macro definition");
        let source = "macro_rules! storage_extra { () => {}; }";
        assert!(!symbol_defined(source, "storage!"), "macro name boundary");
    }

    #[test]
    fn symbol_defined_matches_bare_definitions() {
        let source = r#"
            fn helper() { let _ = "ok"; }
            pub(crate) enum Kind { A }
            struct Thing;
            type Alias = u8;
            trait Marker {}
            const LIMIT: usize = 1;
            static GLOBAL: u8 = 0;
            mod inner {}
            macro_rules! local { () => {}; }
        "#;
        for reference in [
            "helper", "Kind", "Thing", "Alias", "Marker", "LIMIT", "GLOBAL", "inner", "local!",
        ] {
            assert!(symbol_defined(source, reference), "{reference} should resolve");
        }
    }

    #[test]
    fn symbol_defined_ignores_comments_and_literals() {
        let source = r#"
            // fn hidden() {}
            /* struct Hidden; */
            impl Balanced {
                fn evaluate(&self) {
                    let _brace = '}';
                    let _text = "{";
                    let _raw = r"fn quoted() {}";
                }
            }
        "#;
        assert!(
            symbol_defined(source, "Balanced::evaluate"),
            "real method still resolves"
        );
        assert!(!symbol_defined(source, "hidden"), "line comment");
        assert!(!symbol_defined(source, "Hidden"), "block comment");
        assert!(!symbol_defined(source, "quoted"), "raw string literal");
    }
}
