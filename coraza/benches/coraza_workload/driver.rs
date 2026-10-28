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

//! Shared workload loading, validation and the Rust Coraza driver lifecycle.
//!
//! The workload contract, including which parts of the conformance case schema
//! this driver supports, is documented in `benchmarks/coraza/README.md`.

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Component, Path, PathBuf},
    time::Instant,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use coraza::{
    RuleVariable, Waf,
    seclang::Parser,
    transaction::{Transaction, VariableCollection},
};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

/// Case schema version understood by this driver.
pub(crate) const SCHEMA_VERSION: u64 = 1;

/// Timing document schema version understood by the coordinator.
pub(crate) const TIMING_SCHEMA_VERSION: u64 = 1;

/// Largest accepted `--iterations` value, matching the coordinator's
/// per-case sample bound.
pub(crate) const MAX_ITERATIONS: u64 = 1_000_000;

/// Highest TX index a Coraza capture can occupy.
const MAX_CAPTURE_INDEX: usize = 9;

/// Normalization names permitted by the case schema.
const NORMALIZATIONS: [&str; 5] = [
    "timestamps",
    "generated_ids",
    "temporary_paths",
    "audit_boundaries",
    "header_order",
];

/// A workload, manifest or case validation failure, or an unexpected outcome.
#[derive(Debug)]
pub(crate) enum DriverError {
    /// A workload file or case violates the expected contract.
    Load(String),
    /// A case policy did not compile.
    Policy(String),
    /// A transaction could not be driven or read.
    Run(String),
    /// Observed behavior differs from the case's expected block.
    Mismatch(String),
}

impl std::fmt::Display for DriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Load(message) => write!(f, "invalid workload: {message}"),
            Self::Policy(message) => write!(f, "policy error: {message}"),
            Self::Run(message) => write!(f, "driver error: {message}"),
            Self::Mismatch(message) => write!(f, "outcome mismatch: {message}"),
        }
    }
}

impl std::error::Error for DriverError {}

/// One connection's metadata, as replayed by the driver.
#[derive(Debug)]
pub(crate) struct Connection {
    /// Client address supplied to the transaction.
    pub(crate) remote_addr: String,
    /// Client port supplied to the transaction.
    pub(crate) remote_port: u16,
    /// Server address supplied to the transaction.
    pub(crate) local_addr: String,
    /// Server port supplied to the transaction.
    pub(crate) local_port: u16,
}

/// One header occurrence. Order and repeats are significant.
#[derive(Debug)]
pub(crate) struct Header {
    /// Header name exactly as supplied.
    pub(crate) name: String,
    /// Header value bytes exactly as supplied.
    pub(crate) value: Vec<u8>,
}

/// The request as supplied by the connector.
#[derive(Debug)]
pub(crate) struct Request {
    /// Request method.
    pub(crate) method: String,
    /// Original request target bytes, before any normalization.
    pub(crate) uri: Vec<u8>,
    /// Request protocol, for example `HTTP/1.1`.
    pub(crate) protocol: String,
    /// Ordered header occurrences, repeats included.
    pub(crate) headers: Vec<Header>,
    /// Complete request body bytes.
    pub(crate) body: Vec<u8>,
    /// Number of validated chunk boundaries covering the body.
    pub(crate) chunk_count: usize,
}

/// The response as supplied by the connector.
#[derive(Debug)]
pub(crate) struct Response {
    /// Response status code.
    pub(crate) status: u16,
    /// Response protocol, for example `HTTP/1.1`.
    pub(crate) protocol: String,
    /// Ordered header occurrences, repeats included.
    pub(crate) headers: Vec<Header>,
    /// Complete response body bytes.
    pub(crate) body: Vec<u8>,
    /// Number of validated chunk boundaries covering the body.
    pub(crate) chunk_count: usize,
}

/// One driver call from the case's ordered lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Call {
    /// Apply connection metadata.
    ProcessConnection,
    /// Apply the request target, method and protocol.
    ProcessUri,
    /// Apply request headers and evaluate phase 1.
    ProcessRequestHeaders,
    /// Supply one request body chunk boundary.
    AppendRequestBody,
    /// Supply the request body and evaluate phase 2.
    ProcessRequestBody,
    /// Apply response headers and evaluate phase 3.
    ProcessResponseHeaders,
    /// Supply one response body chunk boundary.
    AppendResponseBody,
    /// Supply the response body and evaluate phase 4.
    ProcessResponseBody,
    /// Evaluate phase 5 and write the audit entry.
    ProcessLogging,
}

/// One ordered lifecycle call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhaseCall {
    /// Which driver call runs.
    pub(crate) call: Call,
    /// Phase the call evaluates, from 1 to 5.
    pub(crate) phase: u8,
    /// Chunk index for append calls.
    pub(crate) chunk_index: Option<usize>,
}

/// One expected rule match.
#[derive(Debug)]
pub(crate) struct ExpectedMatch {
    /// Matched rule ID.
    pub(crate) rule_id: i32,
    /// Phase in which the rule matched.
    pub(crate) phase: u8,
    /// Variable name, for example `ARGS_GET`.
    pub(crate) variable: String,
    /// Collection key when the variable is keyed.
    pub(crate) key: Option<String>,
    /// Matched value bytes.
    pub(crate) value: Vec<u8>,
}

/// One expected effective interruption.
#[derive(Debug)]
pub(crate) struct ExpectedInterruption {
    /// Rule that interrupted the transaction.
    pub(crate) rule_id: i32,
    /// Disruptive action name.
    pub(crate) action: String,
    /// HTTP status associated with the action.
    pub(crate) status: i64,
    /// Action data bytes, such as a redirect target.
    pub(crate) data: Vec<u8>,
}

/// One expected capture value.
#[derive(Debug)]
pub(crate) struct ExpectedCapture {
    /// TX capture index, from 0 through 9.
    pub(crate) index: usize,
    /// Captured bytes.
    pub(crate) value: Vec<u8>,
}

/// One expected collection value.
#[derive(Debug)]
pub(crate) struct ExpectedCollection {
    /// Variable name.
    pub(crate) variable: String,
    /// Collection key when the variable is keyed.
    pub(crate) key: Option<String>,
    /// Expected value bytes.
    pub(crate) value: Vec<u8>,
}

/// The expected observable outcome of one case.
#[derive(Debug)]
pub(crate) struct Expected {
    /// Ordered rule matches.
    pub(crate) matches: Vec<ExpectedMatch>,
    /// Effective interruptions; the engine exposes at most one.
    pub(crate) interruptions: Vec<ExpectedInterruption>,
    /// TX captures in index order.
    pub(crate) captures: Vec<ExpectedCapture>,
    /// Named TX score values.
    pub(crate) scores: BTreeMap<String, i64>,
    /// Named engine flag values.
    pub(crate) flags: BTreeMap<String, String>,
    /// Named collection values.
    pub(crate) collections: Vec<ExpectedCollection>,
}

/// One validated case.
#[derive(Debug)]
pub(crate) struct Case {
    /// Stable case identifier from the manifest.
    pub(crate) case_id: String,
    /// Connection metadata.
    pub(crate) connection: Connection,
    /// Request metadata and bytes.
    pub(crate) request: Request,
    /// Response metadata and bytes.
    pub(crate) response: Response,
    /// Policy directives compiled once before any transaction.
    pub(crate) sec_lang: String,
    /// Ordered lifecycle calls.
    pub(crate) phase_calls: Vec<PhaseCall>,
    /// Expected observable outcome.
    pub(crate) expected: Expected,
}

/// One case with its policy compiled once, outside any transaction.
#[derive(Debug)]
pub(crate) struct PreparedCase {
    /// The validated case.
    pub(crate) case: Case,
    /// Shared compiled policy and configuration.
    waf: Waf,
}

/// One validated workload with every policy compiled once.
#[derive(Debug)]
pub(crate) struct Workload {
    /// Stable workload identifier from the manifest.
    pub(crate) workload_id: String,
    /// Lower-case SHA-256 of the exact manifest file bytes.
    pub(crate) manifest_sha256: String,
    /// Cases in manifest order, each with its policy compiled once.
    pub(crate) cases: Vec<PreparedCase>,
}

/// One case's raw per-transaction durations.
#[derive(Debug)]
pub(crate) struct TimingCase {
    /// Stable case identifier from the manifest.
    pub(crate) case_id: String,
    /// One non-negative duration in nanoseconds per fresh transaction.
    pub(crate) samples_ns: Vec<u64>,
}

/// One observed rule match.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OutcomeMatch {
    /// Matched rule ID.
    pub(crate) rule_id: i32,
    /// Phase in which the match was first observed.
    pub(crate) phase: u8,
    /// Variable name of the matched value.
    pub(crate) variable: String,
    /// Collection key when the variable is keyed.
    pub(crate) key: Option<String>,
    /// Matched value bytes.
    pub(crate) value: Vec<u8>,
}

/// One observed effective interruption.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OutcomeInterruption {
    /// Rule that interrupted the transaction.
    pub(crate) rule_id: i32,
    /// Disruptive action name.
    pub(crate) action: String,
    /// HTTP status associated with the action.
    pub(crate) status: u16,
    /// Action data text.
    pub(crate) data: String,
}

/// One observed capture value.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OutcomeCapture {
    /// TX capture index.
    pub(crate) index: usize,
    /// Captured bytes.
    pub(crate) value: Vec<u8>,
}

/// One observed collection value requested by the case.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OutcomeCollection {
    /// Variable name.
    pub(crate) variable: String,
    /// Collection key when the variable is keyed.
    pub(crate) key: Option<String>,
    /// Observed bytes, or `None` when the value is absent.
    pub(crate) value: Option<Vec<u8>>,
}

/// The observable outcome of one transaction.
#[derive(Debug)]
pub(crate) struct Outcome {
    /// Effective interruption, if any.
    pub(crate) interruption: Option<OutcomeInterruption>,
    /// Ordered rule matches.
    pub(crate) matches: Vec<OutcomeMatch>,
    /// TX captures in index order.
    pub(crate) captures: Vec<OutcomeCapture>,
    /// Named TX score values requested by the case.
    pub(crate) scores: BTreeMap<String, i64>,
    /// Named engine flag values.
    pub(crate) flags: BTreeMap<String, String>,
    /// Named collection values requested by the case.
    pub(crate) collections: Vec<OutcomeCollection>,
}

// -----------------------------------------------------------------------------
// JSON helpers
// -----------------------------------------------------------------------------

/// Returns a JSON object or a descriptive error.
fn as_object<'a>(value: &'a Value, context: &str) -> Result<&'a Map<String, Value>, DriverError> {
    value
        .as_object()
        .ok_or_else(|| DriverError::Load(format!("{context} is not an object")))
}

/// Returns a JSON array or a descriptive error.
fn as_array<'a>(value: &'a Value, context: &str) -> Result<&'a Vec<Value>, DriverError> {
    value
        .as_array()
        .ok_or_else(|| DriverError::Load(format!("{context} is not an array")))
}

/// Rejects fields the schema does not declare.
fn unknown_fields(object: &Map<String, Value>, allowed: &[&str], context: &str) -> Result<(), DriverError> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(DriverError::Load(format!("{context} has unknown field {key}")));
        }
    }
    Ok(())
}

/// Returns a required field.
fn required<'a>(object: &'a Map<String, Value>, field: &str, context: &str) -> Result<&'a Value, DriverError> {
    object
        .get(field)
        .ok_or_else(|| DriverError::Load(format!("{context} is missing {field}")))
}

/// Returns a required string field.
fn string_field<'a>(object: &'a Map<String, Value>, field: &str, context: &str) -> Result<&'a str, DriverError> {
    required(object, field, context)?
        .as_str()
        .ok_or_else(|| DriverError::Load(format!("{context} field {field} is not a string")))
}

/// Returns an optional string field.
fn optional_string_field(
    object: &Map<String, Value>,
    field: &str,
    context: &str,
) -> Result<Option<String>, DriverError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(DriverError::Load(format!(
            "{context} field {field} is not a string or null"
        ))),
    }
}

/// Returns a required string array field.
fn string_array_field(object: &Map<String, Value>, field: &str, context: &str) -> Result<Vec<String>, DriverError> {
    as_array(required(object, field, context)?, &format!("{context} field {field}"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| DriverError::Load(format!("{context} field {field} contains a non-string")))
        })
        .collect()
}

/// Returns a required non-negative integer field.
fn unsigned_field(object: &Map<String, Value>, field: &str, context: &str) -> Result<u64, DriverError> {
    required(object, field, context)?
        .as_u64()
        .ok_or_else(|| DriverError::Load(format!("{context} field {field} is not a non-negative integer")))
}

/// Returns an optional non-negative integer field.
fn optional_unsigned_field(
    object: &Map<String, Value>,
    field: &str,
    context: &str,
) -> Result<Option<u64>, DriverError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| DriverError::Load(format!("{context} field {field} is not a non-negative integer"))),
    }
}

/// Returns a required boolean field.
fn bool_field(object: &Map<String, Value>, field: &str, context: &str) -> Result<bool, DriverError> {
    required(object, field, context)?
        .as_bool()
        .ok_or_else(|| DriverError::Load(format!("{context} field {field} is not a boolean")))
}

/// Converts a JSON non-negative integer into `usize`.
fn to_usize(value: u64, context: &str) -> Result<usize, DriverError> {
    usize::try_from(value).map_err(|error| DriverError::Load(format!("{context} is too large: {error}")))
}

/// Converts a JSON non-negative integer into `u16`.
fn to_u16(value: u64, context: &str) -> Result<u16, DriverError> {
    u16::try_from(value).map_err(|error| DriverError::Load(format!("{context} is out of range: {error}")))
}

/// Converts a JSON integer into `i32`.
fn to_i32(value: i64, context: &str) -> Result<i32, DriverError> {
    i32::try_from(value).map_err(|error| DriverError::Load(format!("{context} is out of range: {error}")))
}

// -----------------------------------------------------------------------------
// Path and hash helpers
// -----------------------------------------------------------------------------

/// Rejects absolute paths and parent traversal in workload references.
fn relative_path(text: &str, context: &str) -> Result<PathBuf, DriverError> {
    if text.is_empty() {
        return Err(DriverError::Load(format!("{context} is empty")));
    }
    let path = Path::new(text);
    if path.is_absolute() {
        return Err(DriverError::Load(format!("{context} must be relative: {text}")));
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(DriverError::Load(format!(
                "{context} must not contain . or .. components: {text}"
            )));
        }
    }
    Ok(path.to_path_buf())
}

/// Returns the lower-case hexadecimal SHA-256 of `bytes`.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut text = String::with_capacity(64);
    for byte in digest {
        for shift in [4_u32, 0] {
            if let Some(digit) = char::from_digit((u32::from(byte) >> shift) & 0x0F, 16) {
                text.push(digit);
            }
        }
    }
    text
}

/// Returns true for a lower-case SHA-256 hex string.
fn is_sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// -----------------------------------------------------------------------------
// Byte resolution
// -----------------------------------------------------------------------------

/// Resolved bytes and, when a fixture file was read, that file's SHA-256.
struct ResolvedBytes {
    /// Resolved value bytes.
    bytes: Vec<u8>,
    /// Hash of the referenced fixture file, when one was read.
    fixture_sha256: Option<String>,
}

/// Decodes inline base64 or reads a validated fixture range.
fn resolve_bytes(value: &Value, corpus_root: &Path, context: &str) -> Result<ResolvedBytes, DriverError> {
    let object = as_object(value, context)?;
    let inline = object.contains_key("base64");
    let fixture = object.contains_key("fixture");
    match (inline, fixture) {
        (true, false) => {
            unknown_fields(object, &["base64"], context)?;
            let encoded = string_field(object, "base64", context)?;
            let bytes = STANDARD
                .decode(encoded)
                .map_err(|error| DriverError::Load(format!("{context} has invalid base64: {error}")))?;
            Ok(ResolvedBytes {
                bytes,
                fixture_sha256: None,
            })
        },
        (false, true) => resolve_fixture(object, corpus_root, context),
        _ => Err(DriverError::Load(format!(
            "{context} must have exactly one of base64 or fixture"
        ))),
    }
}

/// Reads and verifies one fixture range.
fn resolve_fixture(
    object: &Map<String, Value>,
    corpus_root: &Path,
    context: &str,
) -> Result<ResolvedBytes, DriverError> {
    unknown_fields(object, &["fixture", "sha256", "offset", "length"], context)?;
    let fixture = string_field(object, "fixture", context)?;
    let path = corpus_root.join(relative_path(fixture, &format!("{context} fixture"))?);
    let data = fs::read(&path)
        .map_err(|error| DriverError::Load(format!("{context} cannot read fixture {}: {error}", path.display())))?;
    let declared = string_field(object, "sha256", context)?;
    if !is_sha256(declared) {
        return Err(DriverError::Load(format!("{context} fixture hash is malformed")));
    }
    let actual = sha256_hex(&data);
    if actual != declared {
        return Err(DriverError::Load(format!(
            "{context} fixture {} has SHA-256 {actual}, not {declared}",
            path.display()
        )));
    }
    let offset = optional_unsigned_field(object, "offset", context)?
        .map(|value| to_usize(value, &format!("{context} offset")))
        .transpose()?
        .unwrap_or(0);
    let file_len = data.len();
    if offset > file_len {
        return Err(DriverError::Load(format!(
            "{context} fixture offset {offset} is past the end of {}",
            path.display()
        )));
    }
    let end = match optional_unsigned_field(object, "length", context)? {
        Some(length) => {
            let length = to_usize(length, &format!("{context} length"))?;
            offset
                .checked_add(length)
                .ok_or_else(|| DriverError::Load(format!("{context} fixture range overflows")))?
        },
        None => file_len,
    };
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| {
            DriverError::Load(format!(
                "{context} fixture range {offset}..{end} is past the end of {}",
                path.display()
            ))
        })?
        .to_vec();
    Ok(ResolvedBytes {
        bytes,
        fixture_sha256: Some(actual),
    })
}

/// Resolves inline UTF-8 text or a validated fixture range.
fn resolve_text(value: &Value, corpus_root: &Path, context: &str) -> Result<(String, Option<String>), DriverError> {
    let object = as_object(value, context)?;
    if object.contains_key("utf8") {
        unknown_fields(object, &["utf8"], context)?;
        return Ok((string_field(object, "utf8", context)?.to_owned(), None));
    }
    let resolved = resolve_fixture(object, corpus_root, context)?;
    let text = String::from_utf8(resolved.bytes)
        .map_err(|error| DriverError::Load(format!("{context} fixture is not valid UTF-8: {error}")))?;
    Ok((text, resolved.fixture_sha256))
}

/// Records the first fixture hash seen in canonical order.
fn track_fixture(hash: Option<String>, first: &mut Option<String>) {
    if first.is_none() && hash.is_some() {
        *first = hash;
    }
}

// -----------------------------------------------------------------------------
// Case parsing
// -----------------------------------------------------------------------------

/// Parses and validates one case file against the repository schema subset.
pub(crate) fn parse_case_bytes(source: &[u8], corpus_root: &Path) -> Result<Case, DriverError> {
    let value: Value = serde_json::from_slice(source)
        .map_err(|error| DriverError::Load(format!("case is not valid JSON: {error}")))?;
    let case = as_object(&value, "case")?;
    unknown_fields(
        case,
        &[
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
        ],
        "case",
    )?;
    if unsigned_field(case, "schema_version", "case")? != SCHEMA_VERSION {
        return Err(DriverError::Load(format!(
            "case schema_version must be {SCHEMA_VERSION}"
        )));
    }
    let case_id = string_field(case, "case_id", "case")?;
    if case_id.is_empty() {
        return Err(DriverError::Load("case_id is empty".to_owned()));
    }
    let context = format!("case {case_id}");
    parse_reference(required(case, "reference", &context)?, &context)?;
    let connection = parse_connection(required(case, "connection", &context)?, &context)?;
    let mut first_fixture = None;
    let request = parse_request(
        required(case, "request", &context)?,
        corpus_root,
        &context,
        &mut first_fixture,
    )?;
    let response = parse_response(
        required(case, "response", &context)?,
        corpus_root,
        &context,
        &mut first_fixture,
    )?;
    let sec_lang = parse_processor(
        required(case, "processor", &context)?,
        corpus_root,
        &context,
        &mut first_fixture,
    )?;
    let phase_calls = parse_phase_calls(required(case, "phase_calls", &context)?, &request, &response, &context)?;
    let expected = parse_expected(required(case, "expected", &context)?, corpus_root, &context)?;
    let normalize = string_array_field(case, "normalize", &context)?;
    for name in &normalize {
        if !NORMALIZATIONS.contains(&name.as_str()) {
            return Err(DriverError::Load(format!("{context} has unknown normalization {name}")));
        }
    }
    check_fixture_sha(case, &request, &response, first_fixture, &context)?;
    Ok(Case {
        case_id: case_id.to_owned(),
        connection,
        request,
        response,
        sec_lang,
        phase_calls,
        expected,
    })
}

/// Validates the pinned reference block.
fn parse_reference(value: &Value, context: &str) -> Result<(), DriverError> {
    let reference = as_object(value, &format!("{context} reference"))?;
    unknown_fields(reference, &["profile", "go_commit", "rust_commit"], context)?;
    if string_field(reference, "profile", context)?.is_empty() {
        return Err(DriverError::Load(format!("{context} reference profile is empty")));
    }
    for field in ["go_commit", "rust_commit"] {
        let commit = string_field(reference, field, context)?;
        let valid = commit.len() == 40
            && commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !valid {
            return Err(DriverError::Load(format!(
                "{context} reference {field} is not a 40-character hex commit"
            )));
        }
    }
    Ok(())
}

/// Parses connection metadata.
fn parse_connection(value: &Value, context: &str) -> Result<Connection, DriverError> {
    let object = as_object(value, &format!("{context} connection"))?;
    unknown_fields(
        object,
        &[
            "remote_addr",
            "remote_port",
            "local_addr",
            "local_port",
            "tls",
            "tls_version",
        ],
        &format!("{context} connection"),
    )?;
    let _tls = bool_field(object, "tls", &format!("{context} connection"))?;
    let _tls_version = optional_string_field(object, "tls_version", &format!("{context} connection"))?;
    Ok(Connection {
        remote_addr: string_field(object, "remote_addr", &format!("{context} connection"))?.to_owned(),
        remote_port: to_u16(
            unsigned_field(object, "remote_port", &format!("{context} connection"))?,
            &format!("{context} remote_port"),
        )?,
        local_addr: string_field(object, "local_addr", &format!("{context} connection"))?.to_owned(),
        local_port: to_u16(
            unsigned_field(object, "local_port", &format!("{context} connection"))?,
            &format!("{context} local_port"),
        )?,
    })
}

/// Parses ordered headers.
fn parse_headers(
    value: &Value,
    corpus_root: &Path,
    context: &str,
    first: &mut Option<String>,
) -> Result<Vec<Header>, DriverError> {
    let mut headers = Vec::new();
    for (index, item) in as_array(value, context)?.iter().enumerate() {
        let item_context = format!("{context} header {index}");
        let object = as_object(item, &item_context)?;
        unknown_fields(object, &["name", "value"], &item_context)?;
        let name = string_field(object, "name", &item_context)?;
        if name.is_empty() {
            return Err(DriverError::Load(format!("{item_context} name is empty")));
        }
        let resolved = resolve_bytes(required(object, "value", &item_context)?, corpus_root, &item_context)?;
        track_fixture(resolved.fixture_sha256, first);
        headers.push(Header {
            name: name.to_owned(),
            value: resolved.bytes,
        });
    }
    Ok(headers)
}

/// Validates chunk boundaries and returns how many chunks cover the body.
fn parse_chunk_count(value: &Value, body_len: usize, context: &str) -> Result<usize, DriverError> {
    let chunks = as_array(value, context)?;
    let mut next = 0_usize;
    for (index, item) in chunks.iter().enumerate() {
        let item_context = format!("{context} chunk {index}");
        let object = as_object(item, &item_context)?;
        unknown_fields(object, &["offset", "length"], &item_context)?;
        let offset = to_usize(unsigned_field(object, "offset", &item_context)?, &item_context)?;
        let length = to_usize(unsigned_field(object, "length", &item_context)?, &item_context)?;
        if offset != next {
            return Err(DriverError::Load(format!(
                "{context} chunk offsets are not contiguous at chunk {index}"
            )));
        }
        next = offset
            .checked_add(length)
            .ok_or_else(|| DriverError::Load(format!("{context} chunk length overflows")))?;
        if next > body_len {
            return Err(DriverError::Load(format!(
                "{context} chunk {index} extends past the body"
            )));
        }
    }
    if next != body_len {
        return Err(DriverError::Load(format!(
            "{context} chunks cover {next} of {body_len} body bytes"
        )));
    }
    Ok(chunks.len())
}

/// Parses the request block.
fn parse_request(
    value: &Value,
    corpus_root: &Path,
    context: &str,
    first_fixture: &mut Option<String>,
) -> Result<Request, DriverError> {
    let object = as_object(value, &format!("{context} request"))?;
    let request_context = format!("{context} request");
    unknown_fields(
        object,
        &["method", "uri", "protocol", "headers", "body", "chunks"],
        &request_context,
    )?;
    let method = string_field(object, "method", &request_context)?;
    let protocol = string_field(object, "protocol", &request_context)?;
    if method.is_empty() || protocol.is_empty() {
        return Err(DriverError::Load(format!(
            "{request_context} method or protocol is empty"
        )));
    }
    let uri = resolve_bytes(
        required(object, "uri", &request_context)?,
        corpus_root,
        &request_context,
    )?;
    track_fixture(uri.fixture_sha256, first_fixture);
    std::str::from_utf8(&uri.bytes).map_err(|error| {
        DriverError::Load(format!(
            "{request_context} URI is not UTF-8; the Rust public API requires text: {error}"
        ))
    })?;
    let headers = parse_headers(
        required(object, "headers", &request_context)?,
        corpus_root,
        &request_context,
        first_fixture,
    )?;
    let body = resolve_bytes(
        required(object, "body", &request_context)?,
        corpus_root,
        &request_context,
    )?;
    track_fixture(body.fixture_sha256, first_fixture);
    let chunk_count = parse_chunk_count(
        required(object, "chunks", &request_context)?,
        body.bytes.len(),
        &request_context,
    )?;
    Ok(Request {
        method: method.to_owned(),
        uri: uri.bytes,
        protocol: protocol.to_owned(),
        headers,
        body: body.bytes,
        chunk_count,
    })
}

/// Parses the response block.
fn parse_response(
    value: &Value,
    corpus_root: &Path,
    context: &str,
    first_fixture: &mut Option<String>,
) -> Result<Response, DriverError> {
    let object = as_object(value, &format!("{context} response"))?;
    let response_context = format!("{context} response");
    unknown_fields(
        object,
        &["status", "protocol", "headers", "body", "chunks"],
        &response_context,
    )?;
    let status = unsigned_field(object, "status", &response_context)?;
    if !(100..=999).contains(&status) {
        return Err(DriverError::Load(format!("{response_context} status is out of range")));
    }
    let protocol = string_field(object, "protocol", &response_context)?;
    if protocol.is_empty() {
        return Err(DriverError::Load(format!("{response_context} protocol is empty")));
    }
    let headers = parse_headers(
        required(object, "headers", &response_context)?,
        corpus_root,
        &response_context,
        first_fixture,
    )?;
    let body = resolve_bytes(
        required(object, "body", &response_context)?,
        corpus_root,
        &response_context,
    )?;
    track_fixture(body.fixture_sha256, first_fixture);
    let chunk_count = parse_chunk_count(
        required(object, "chunks", &response_context)?,
        body.bytes.len(),
        &response_context,
    )?;
    Ok(Response {
        status: to_u16(status, &format!("{response_context} status"))?,
        protocol: protocol.to_owned(),
        headers,
        body: body.bytes,
        chunk_count,
    })
}

/// Parses the policy block and rejects unsupported host settings.
fn parse_processor(
    value: &Value,
    corpus_root: &Path,
    context: &str,
    first_fixture: &mut Option<String>,
) -> Result<String, DriverError> {
    let object = as_object(value, &format!("{context} processor"))?;
    let processor_context = format!("{context} processor");
    unknown_fields(
        object,
        &[
            "sec_lang",
            "request_body_processor",
            "response_body_processor",
            "config",
        ],
        &processor_context,
    )?;
    let (sec_lang, fixture_sha256) = resolve_text(
        required(object, "sec_lang", &processor_context)?,
        corpus_root,
        &processor_context,
    )?;
    track_fixture(fixture_sha256, first_fixture);
    for (field, supported) in [
        (
            "request_body_processor",
            &["auto", "raw", "urlencoded", "multipart", "json", "xml"][..],
        ),
        ("response_body_processor", &["auto", "raw", "json", "xml"][..]),
    ] {
        let name = string_field(object, field, &processor_context)?;
        if !supported.contains(&name) {
            return Err(DriverError::Load(format!(
                "{processor_context} field {field} has unknown value {name}"
            )));
        }
        if name != "auto" {
            return Err(DriverError::Load(format!(
                "{processor_context} field {field}={name} is not supported by the Rust driver; the common subset uses auto"
            )));
        }
    }
    let config = as_object(
        required(object, "config", &processor_context)?,
        &format!("{processor_context} config"),
    )?;
    if let Some(key) = config.keys().next() {
        return Err(DriverError::Load(format!(
            "{processor_context} config key {key} is not supported by the Rust driver; use SecLang directives"
        )));
    }
    Ok(sec_lang)
}

/// Parses the ordered lifecycle and enforces the canonical phase-1 to phase-5 sequence.
fn parse_phase_calls(
    value: &Value,
    request: &Request,
    response: &Response,
    context: &str,
) -> Result<Vec<PhaseCall>, DriverError> {
    let mut calls = Vec::new();
    for (index, item) in as_array(value, &format!("{context} phase_calls"))?.iter().enumerate() {
        let item_context = format!("{context} phase call {index}");
        let object = as_object(item, &item_context)?;
        unknown_fields(object, &["call", "phase", "chunk_index"], &item_context)?;
        let name = string_field(object, "call", &item_context)?;
        let phase = to_u16(unsigned_field(object, "phase", &item_context)?, &item_context)?;
        let phase = u8::try_from(phase)
            .map_err(|error| DriverError::Load(format!("{item_context} phase is out of range: {error}")))?;
        let chunk_index = optional_unsigned_field(object, "chunk_index", &item_context)?
            .map(|value| to_usize(value, &item_context))
            .transpose()?;
        let call = match name {
            "process_connection" => Call::ProcessConnection,
            "process_uri" => Call::ProcessUri,
            "process_request_headers" => Call::ProcessRequestHeaders,
            "append_request_body" => Call::AppendRequestBody,
            "process_request_body" => Call::ProcessRequestBody,
            "process_response_headers" => Call::ProcessResponseHeaders,
            "append_response_body" => Call::AppendResponseBody,
            "process_response_body" => Call::ProcessResponseBody,
            "process_logging" => Call::ProcessLogging,
            other => return Err(DriverError::Load(format!("{item_context} has unknown call {other}"))),
        };
        calls.push(PhaseCall {
            call,
            phase,
            chunk_index,
        });
    }
    let expected = canonical_calls(request, response);
    if calls != expected {
        return Err(DriverError::Load(format!(
            "{context} phase_calls do not match the canonical lifecycle; the common subset runs connection, URI, headers, one append per chunk, body, response headers, one append per response chunk, response body and logging"
        )));
    }
    Ok(calls)
}

/// Builds the only lifecycle sequence this driver accepts.
fn canonical_calls(request: &Request, response: &Response) -> Vec<PhaseCall> {
    let mut calls = vec![
        PhaseCall {
            call: Call::ProcessConnection,
            phase: 1,
            chunk_index: None,
        },
        PhaseCall {
            call: Call::ProcessUri,
            phase: 1,
            chunk_index: None,
        },
        PhaseCall {
            call: Call::ProcessRequestHeaders,
            phase: 1,
            chunk_index: None,
        },
    ];
    for index in 0..request.chunk_count {
        calls.push(PhaseCall {
            call: Call::AppendRequestBody,
            phase: 2,
            chunk_index: Some(index),
        });
    }
    calls.push(PhaseCall {
        call: Call::ProcessRequestBody,
        phase: 2,
        chunk_index: None,
    });
    calls.push(PhaseCall {
        call: Call::ProcessResponseHeaders,
        phase: 3,
        chunk_index: None,
    });
    for index in 0..response.chunk_count {
        calls.push(PhaseCall {
            call: Call::AppendResponseBody,
            phase: 4,
            chunk_index: Some(index),
        });
    }
    calls.push(PhaseCall {
        call: Call::ProcessResponseBody,
        phase: 4,
        chunk_index: None,
    });
    calls.push(PhaseCall {
        call: Call::ProcessLogging,
        phase: 5,
        chunk_index: None,
    });
    calls
}

/// Parses the expected outcome and rejects parts the Rust driver cannot observe.
fn parse_expected(value: &Value, corpus_root: &Path, context: &str) -> Result<Expected, DriverError> {
    let object = as_object(value, &format!("{context} expected"))?;
    let expected_context = format!("{context} expected");
    unknown_fields(
        object,
        &[
            "matches",
            "interruptions",
            "captures",
            "scores",
            "flags",
            "collections",
            "audit",
        ],
        &expected_context,
    )?;
    let matches = parse_expected_matches(
        required(object, "matches", &expected_context)?,
        corpus_root,
        &expected_context,
    )?;
    let interruptions = parse_expected_interruptions(
        required(object, "interruptions", &expected_context)?,
        corpus_root,
        &expected_context,
    )?;
    if interruptions.len() > 1 {
        return Err(DriverError::Load(format!(
            "{expected_context} declares more than one interruption; the engine exposes only one"
        )));
    }
    let captures = parse_expected_captures(
        required(object, "captures", &expected_context)?,
        corpus_root,
        &expected_context,
    )?;
    let scores = parse_scores(required(object, "scores", &expected_context)?, &expected_context)?;
    let flags = parse_flags(required(object, "flags", &expected_context)?, &expected_context)?;
    let collections = parse_expected_collections(
        required(object, "collections", &expected_context)?,
        corpus_root,
        &expected_context,
    )?;
    let audit = as_object(
        required(object, "audit", &expected_context)?,
        &format!("{expected_context} audit"),
    )?;
    unknown_fields(
        audit,
        &["required", "parts", "entries"],
        &format!("{expected_context} audit"),
    )?;
    let required_audit = bool_field(audit, "required", &format!("{expected_context} audit"))?;
    string_field(audit, "parts", &format!("{expected_context} audit"))?;
    let entries = unsigned_field(audit, "entries", &format!("{expected_context} audit"))?;
    if required_audit || entries != 0 {
        return Err(DriverError::Load(format!(
            "{expected_context} audit required={required_audit} entries={entries} is not supported by the Rust driver; the common subset uses required=false, entries=0"
        )));
    }
    Ok(Expected {
        matches,
        interruptions,
        captures,
        scores,
        flags,
        collections,
    })
}

/// Parses expected matches.
fn parse_expected_matches(value: &Value, corpus_root: &Path, context: &str) -> Result<Vec<ExpectedMatch>, DriverError> {
    let mut matches = Vec::new();
    for (index, item) in as_array(value, &format!("{context} matches"))?.iter().enumerate() {
        let item_context = format!("{context} match {index}");
        let object = as_object(item, &item_context)?;
        unknown_fields(object, &["rule_id", "phase", "variable", "key", "value"], &item_context)?;
        let rule_id = required(object, "rule_id", &item_context)?
            .as_i64()
            .ok_or_else(|| DriverError::Load(format!("{item_context} rule_id is not an integer")))?;
        let phase = to_u16(unsigned_field(object, "phase", &item_context)?, &item_context)?;
        let phase = u8::try_from(phase)
            .map_err(|error| DriverError::Load(format!("{item_context} phase is out of range: {error}")))?;
        if !(1..=5).contains(&phase) {
            return Err(DriverError::Load(format!("{item_context} phase is out of range")));
        }
        let variable = string_field(object, "variable", &item_context)?;
        let key = optional_string_field(object, "key", &item_context)?;
        let value = resolve_bytes(required(object, "value", &item_context)?, corpus_root, &item_context)?;
        matches.push(ExpectedMatch {
            rule_id: to_i32(rule_id, &format!("{item_context} rule_id"))?,
            phase,
            variable: variable.to_owned(),
            key,
            value: value.bytes,
        });
    }
    Ok(matches)
}

/// Parses expected interruptions.
fn parse_expected_interruptions(
    value: &Value,
    corpus_root: &Path,
    context: &str,
) -> Result<Vec<ExpectedInterruption>, DriverError> {
    let mut interruptions = Vec::new();
    for (index, item) in as_array(value, &format!("{context} interruptions"))?.iter().enumerate() {
        let item_context = format!("{context} interruption {index}");
        let object = as_object(item, &item_context)?;
        unknown_fields(object, &["rule_id", "action", "status", "data"], &item_context)?;
        let rule_id = required(object, "rule_id", &item_context)?
            .as_i64()
            .ok_or_else(|| DriverError::Load(format!("{item_context} rule_id is not an integer")))?;
        let action = string_field(object, "action", &item_context)?;
        if action.is_empty() {
            return Err(DriverError::Load(format!("{item_context} action is empty")));
        }
        let status = required(object, "status", &item_context)?
            .as_i64()
            .ok_or_else(|| DriverError::Load(format!("{item_context} status is not an integer")))?;
        let data = resolve_bytes(required(object, "data", &item_context)?, corpus_root, &item_context)?;
        interruptions.push(ExpectedInterruption {
            rule_id: to_i32(rule_id, &format!("{item_context} rule_id"))?,
            action: action.to_owned(),
            status,
            data: data.bytes,
        });
    }
    Ok(interruptions)
}

/// Parses expected captures.
fn parse_expected_captures(
    value: &Value,
    corpus_root: &Path,
    context: &str,
) -> Result<Vec<ExpectedCapture>, DriverError> {
    let mut captures = Vec::new();
    for (position, item) in as_array(value, &format!("{context} captures"))?.iter().enumerate() {
        let item_context = format!("{context} capture {position}");
        let object = as_object(item, &item_context)?;
        unknown_fields(object, &["index", "value"], &item_context)?;
        let index = to_usize(unsigned_field(object, "index", &item_context)?, &item_context)?;
        if index > MAX_CAPTURE_INDEX {
            return Err(DriverError::Load(format!(
                "{item_context} index {index} is above the maximum capture index {MAX_CAPTURE_INDEX}"
            )));
        }
        let value = resolve_bytes(required(object, "value", &item_context)?, corpus_root, &item_context)?;
        // The observation side cannot tell an empty capture from an absent one: `read_captures`
        // drops empty slots because Go seeds TX 0..10 with empty strings. Rejecting an empty
        // expectation keeps that limitation from silently matching or masking a regression.
        if value.bytes.is_empty() {
            return Err(DriverError::Load(format!(
                "{item_context} value is empty; an empty capture cannot be distinguished from an absent one"
            )));
        }
        captures.push(ExpectedCapture {
            index,
            value: value.bytes,
        });
    }
    Ok(captures)
}

/// Parses the named scores object.
fn parse_scores(value: &Value, context: &str) -> Result<BTreeMap<String, i64>, DriverError> {
    let object = as_object(value, &format!("{context} scores"))?;
    let mut scores = BTreeMap::new();
    for (key, item) in object {
        let score = item
            .as_i64()
            .ok_or_else(|| DriverError::Load(format!("{context} score {key} is not an integer")))?;
        scores.insert(key.clone(), score);
    }
    Ok(scores)
}

/// Parses the named flags object.
fn parse_flags(value: &Value, context: &str) -> Result<BTreeMap<String, String>, DriverError> {
    let object = as_object(value, &format!("{context} flags"))?;
    let mut flags = BTreeMap::new();
    for (key, item) in object {
        let flag = item
            .as_str()
            .ok_or_else(|| DriverError::Load(format!("{context} flag {key} is not a string")))?;
        flags.insert(key.clone(), flag.to_owned());
    }
    Ok(flags)
}

/// Parses expected collection values.
fn parse_expected_collections(
    value: &Value,
    corpus_root: &Path,
    context: &str,
) -> Result<Vec<ExpectedCollection>, DriverError> {
    let mut collections = Vec::new();
    for (index, item) in as_array(value, &format!("{context} collections"))?.iter().enumerate() {
        let item_context = format!("{context} collection {index}");
        let object = as_object(item, &item_context)?;
        unknown_fields(object, &["variable", "key", "value"], &item_context)?;
        let variable = string_field(object, "variable", &item_context)?;
        if variable.is_empty() {
            return Err(DriverError::Load(format!("{item_context} variable is empty")));
        }
        variable
            .parse::<RuleVariable>()
            .map_err(|error| DriverError::Load(format!("{item_context}: {error}")))?;
        let key = optional_string_field(object, "key", &item_context)?;
        let value = resolve_bytes(required(object, "value", &item_context)?, corpus_root, &item_context)?;
        collections.push(ExpectedCollection {
            variable: variable.to_owned(),
            key,
            value: value.bytes,
        });
    }
    Ok(collections)
}

/// Checks the case-level fixture hash against the resolved bytes.
fn check_fixture_sha(
    case: &Map<String, Value>,
    request: &Request,
    response: &Response,
    first_fixture: Option<String>,
    context: &str,
) -> Result<(), DriverError> {
    let declared = string_field(case, "fixture_sha256", context)?;
    if !is_sha256(declared) {
        return Err(DriverError::Load(format!("{context} fixture_sha256 is malformed")));
    }
    let expected = if let Some(hash) = first_fixture {
        hash
    } else {
        let mut joined = request.body.clone();
        joined.extend_from_slice(&response.body);
        sha256_hex(&joined)
    };
    if declared != expected {
        return Err(DriverError::Load(format!(
            "{context} fixture_sha256 is {declared}, not {expected}"
        )));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Workload loading
// -----------------------------------------------------------------------------

/// Reads the manifest, verifies every case hash and compiles every policy once.
pub(crate) fn load_workload(root: &Path) -> Result<Workload, DriverError> {
    let manifest_path = root.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| DriverError::Load(format!("cannot read {}: {error}", manifest_path.display())))?;
    let manifest_sha256 = sha256_hex(&manifest_bytes);
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| DriverError::Load(format!("manifest is not valid JSON: {error}")))?;
    let object = as_object(&manifest, "manifest")?;
    unknown_fields(
        object,
        &["schema_version", "workload_id", "description", "case_schema", "cases"],
        "manifest",
    )?;
    if unsigned_field(object, "schema_version", "manifest")? != SCHEMA_VERSION {
        return Err(DriverError::Load(format!(
            "manifest schema_version must be {SCHEMA_VERSION}"
        )));
    }
    let workload_id = string_field(object, "workload_id", "manifest")?;
    if workload_id.is_empty() {
        return Err(DriverError::Load("manifest workload_id is empty".to_owned()));
    }
    let workload_id = workload_id.to_owned();
    if optional_string_field(object, "description", "manifest")?.is_none() {
        return Err(DriverError::Load("manifest description is missing".to_owned()));
    }
    string_field(object, "case_schema", "manifest")?;
    let entries = as_array(required(object, "cases", "manifest")?, "manifest cases")?;
    if entries.is_empty() {
        return Err(DriverError::Load("manifest has no cases".to_owned()));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut seen_ids = BTreeMap::new();
    let mut prepared = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let entry_context = format!("manifest case {index}");
        let entry = as_object(entry, &entry_context)?;
        unknown_fields(entry, &["path", "sha256"], &entry_context)?;
        let path = relative_path(
            string_field(entry, "path", &entry_context)?,
            &format!("{entry_context} path"),
        )?;
        if !seen.insert(path.clone()) {
            return Err(DriverError::Load(format!(
                "{entry_context} repeats case path {}",
                path.display()
            )));
        }
        let declared = string_field(entry, "sha256", &entry_context)?;
        if !is_sha256(declared) {
            return Err(DriverError::Load(format!("{entry_context} sha256 is malformed")));
        }
        let case_path = root.join(&path);
        let source = fs::read(&case_path)
            .map_err(|error| DriverError::Load(format!("cannot read {}: {error}", case_path.display())))?;
        let actual = sha256_hex(&source);
        if actual != declared {
            return Err(DriverError::Load(format!(
                "case {} has SHA-256 {actual}, not {declared}",
                case_path.display()
            )));
        }
        let case = parse_case_bytes(&source, root)?;
        if let Some(first) = seen_ids.insert(case.case_id.clone(), path.clone()) {
            return Err(DriverError::Load(format!(
                "duplicate case id {:?} in {} and {}",
                case.case_id,
                first.display(),
                path.display()
            )));
        }
        let waf = compile_policy(&case.sec_lang, &case.case_id)?;
        prepared.push(PreparedCase { case, waf });
    }
    Ok(Workload {
        workload_id,
        manifest_sha256,
        cases: prepared,
    })
}

/// Compiles one policy outside any transaction.
fn compile_policy(sec_lang: &str, case_id: &str) -> Result<Waf, DriverError> {
    let mut parser = Parser::new();
    parser
        .from_string(sec_lang)
        .map_err(|error| DriverError::Policy(format!("case {case_id}: {error}")))?;
    parser
        .into_waf()
        .map_err(|error| DriverError::Policy(format!("case {case_id}: {error}")))
}

// -----------------------------------------------------------------------------
// Lifecycle
// -----------------------------------------------------------------------------

/// Runs one case through the public transaction lifecycle.
pub(crate) fn run_case(prepared: &PreparedCase) -> Result<Outcome, DriverError> {
    let case = &prepared.case;
    let uri = std::str::from_utf8(&case.request.uri).map_err(|error| {
        DriverError::Run(format!(
            "case {} request URI is not UTF-8; the Rust public API requires text: {error}",
            case.case_id
        ))
    })?;
    let mut matches = Vec::new();
    let mut seen = 0_usize;
    let transaction = drive_lifecycle(prepared, uri, |transaction, phase| {
        absorb_matches(transaction, phase, &mut seen, &mut matches);
    })?;
    let interruption = transaction.interruption().map(|value| OutcomeInterruption {
        rule_id: value.rule_id,
        action: value.action.clone(),
        status: value.status,
        data: value.data.clone(),
    });
    let scores = read_scores(&transaction, &case.expected.scores, &case.case_id)?;
    let collections = read_collections(&transaction, &case.expected.collections, &case.case_id)?;
    Ok(Outcome {
        interruption,
        matches,
        captures: read_captures(&transaction),
        scores,
        flags: read_flags(&transaction, &case.expected.flags),
        collections,
    })
}

/// Drives one fresh transaction through the ordered lifecycle, including logging.
///
/// `after_call` observes the transaction after each call, which the outcome
/// mode uses to attribute matches to phases. Interruption stops later calls
/// and logging always runs. The transaction is returned so the caller decides
/// when it is dropped.
fn drive_lifecycle(
    prepared: &PreparedCase,
    uri: &str,
    mut after_call: impl FnMut(&Transaction, u8),
) -> Result<Transaction, DriverError> {
    let case = &prepared.case;
    let mut transaction = prepared.waf.new_transaction_with_id(case.case_id.clone());
    let mut logging_ran = false;
    for call in &case.phase_calls {
        drive_call(&mut transaction, case, uri, call)?;
        after_call(&transaction, call.phase);
        if call.call == Call::ProcessLogging {
            logging_ran = true;
        }
        if transaction.interruption().is_some() {
            break;
        }
    }
    if !logging_ran {
        transaction
            .process_logging()
            .map_err(|error| DriverError::Run(format!("case {} logging failed: {error}", case.case_id)))?;
        after_call(&transaction, 5);
    }
    Ok(transaction)
}

/// Executes one lifecycle call.
fn drive_call(transaction: &mut Transaction, case: &Case, uri: &str, call: &PhaseCall) -> Result<(), DriverError> {
    match call.call {
        Call::ProcessConnection => {
            transaction.set_remote_addr(&case.connection.remote_addr);
            transaction.set_remote_port(case.connection.remote_port);
            transaction.set_server_addr(&case.connection.local_addr);
            transaction.set_server_port(case.connection.local_port);
        },
        Call::ProcessUri => transaction.process_uri(uri, &case.request.method, &case.request.protocol),
        Call::ProcessRequestHeaders => {
            for header in &case.request.headers {
                transaction.add_request_header(&header.name, &header.value);
            }
            if let Some(host) = case
                .request
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("host"))
            {
                transaction.set_server_name(&host.value);
            }
            transaction.process_request_headers();
        },
        Call::AppendRequestBody | Call::AppendResponseBody => {
            // Chunk boundaries are validated at load time. The Rust public API
            // accepts the whole body, so the same exact bytes are supplied once.
        },
        Call::ProcessRequestBody => {
            transaction.process_request_body(&case.request.body);
        },
        Call::ProcessResponseHeaders => {
            for header in &case.response.headers {
                transaction.add_response_header(&header.name, &header.value);
            }
            transaction.process_response_headers(case.response.status, &case.response.protocol);
        },
        Call::ProcessResponseBody => {
            transaction.process_response_body(&case.response.body);
        },
        Call::ProcessLogging => transaction
            .process_logging()
            .map_err(|error| DriverError::Run(format!("case {} logging failed: {error}", case.case_id)))?,
    }
    Ok(())
}

/// Appends matches observed since the previous call, tagged with the call's phase.
fn absorb_matches(transaction: &Transaction, phase: u8, seen: &mut usize, matches: &mut Vec<OutcomeMatch>) {
    for matched in transaction.matched_rules().iter().skip(*seen) {
        for data in &matched.matches {
            matches.push(OutcomeMatch {
                rule_id: matched.rule_id(),
                phase,
                variable: data.variable.name().to_owned(),
                key: if data.key.is_empty() {
                    None
                } else {
                    Some(data.key.clone())
                },
                value: data.value.clone(),
            });
        }
    }
    *seen = transaction.matched_rules().len();
}

/// Reads TX captures 0 through 9.
fn read_captures(transaction: &Transaction) -> Vec<OutcomeCapture> {
    let Some(VariableCollection::Map(map)) = transaction.collection(RuleVariable::TX) else {
        return Vec::new();
    };
    let mut captures = Vec::new();
    for index in 0..=MAX_CAPTURE_INDEX {
        // Go seeds TX 0..10 with empty strings, so an empty slot is not a capture.
        if let Some(value) = map.first(index.to_string()).filter(|value| !value.is_empty()) {
            captures.push(OutcomeCapture {
                index,
                value: value.to_vec(),
            });
        }
    }
    captures
}

/// Reads the engine flags named by the case. Names the public API does not
/// expose are omitted, so the existing comparison reports them as unobservable.
fn read_flags(transaction: &Transaction, expected: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut flags = BTreeMap::new();
    for name in expected.keys() {
        if let Ok(variable) = name.parse::<RuleVariable>()
            && let Some(value) = transaction.get_variable(variable, None)
        {
            flags.insert(name.clone(), value);
        }
    }
    flags
}

/// Reads the named TX scores, treating a missing score as zero.
fn read_scores(
    transaction: &Transaction,
    expected: &BTreeMap<String, i64>,
    case_id: &str,
) -> Result<BTreeMap<String, i64>, DriverError> {
    let mut scores = BTreeMap::new();
    for name in expected.keys() {
        let value = transaction.get_variable(RuleVariable::TX, Some(name));
        let score = match value {
            None => 0,
            Some(value) => value
                .parse::<i64>()
                .map_err(|error| DriverError::Run(format!("case {case_id} TX:{name} is not an integer: {error}")))?,
        };
        scores.insert(name.clone(), score);
    }
    Ok(scores)
}

/// Reads the collection values named by the case.
fn read_collections(
    transaction: &Transaction,
    expected: &[ExpectedCollection],
    case_id: &str,
) -> Result<Vec<OutcomeCollection>, DriverError> {
    let mut collections = Vec::new();
    for item in expected {
        let variable = item
            .variable
            .parse::<RuleVariable>()
            .map_err(|error| DriverError::Load(format!("case {case_id}: {error}")))?;
        let value = match (transaction.collection(variable), &item.key) {
            (Some(VariableCollection::Single(single)), None) => Some(single.get_bytes().to_vec()),
            (Some(VariableCollection::Map(map)), Some(key)) => map.first(key).map(<[u8]>::to_vec),
            (Some(VariableCollection::Names(_, map)), Some(key)) => {
                map.iter_key(key).next().map(|(key, _)| key.as_bytes().to_vec())
            },
            _ => None,
        };
        collections.push(OutcomeCollection {
            variable: item.variable.clone(),
            key: item.key.clone(),
            value,
        });
    }
    Ok(collections)
}

// -----------------------------------------------------------------------------
// Timing
// -----------------------------------------------------------------------------

/// Parses and bounds the `--iterations` value.
pub(crate) fn parse_iterations(text: &str) -> Result<usize, DriverError> {
    let iterations = text
        .parse::<u64>()
        .map_err(|error| DriverError::Load(format!("--iterations {text} is not a non-negative integer: {error}")))?;
    if iterations == 0 || iterations > MAX_ITERATIONS {
        return Err(DriverError::Load(format!(
            "--iterations must be between 1 and {MAX_ITERATIONS}, got {iterations}"
        )));
    }
    usize::try_from(iterations)
        .map_err(|error| DriverError::Load(format!("--iterations {iterations} is too large: {error}")))
}

/// Runs every case in manifest order for exactly `iterations` fresh transactions.
///
/// The timed section of each iteration covers one complete transaction: the
/// public construction call on the already compiled WAF, every ordered
/// lifecycle call for the case (connection, URI, request headers, request body,
/// response headers, response body and logging), the same interruption
/// short-circuit the outcome mode uses, and the transaction drop that closes
/// it. Workload loading, hash validation, policy compilation, outcome
/// observation and comparison, timing bookkeeping and document serialization
/// stay outside the timed section. No warmup pass runs here; the coordinator
/// owns repetitions.
pub(crate) fn run_timing(workload: &Workload, iterations: usize) -> Result<Vec<TimingCase>, DriverError> {
    let mut cases = Vec::with_capacity(workload.cases.len());
    for prepared in &workload.cases {
        let uri = std::str::from_utf8(&prepared.case.request.uri).map_err(|error| {
            DriverError::Run(format!(
                "case {} request URI is not UTF-8; the Rust public API requires text: {error}",
                prepared.case.case_id
            ))
        })?;
        let mut samples_ns = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            run_timed_transaction(prepared, uri)?;
            let elapsed = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
            samples_ns.push(elapsed);
        }
        cases.push(TimingCase {
            case_id: prepared.case.case_id.clone(),
            samples_ns,
        });
    }
    Ok(cases)
}

/// Drives and closes one fresh transaction; the caller times the call.
// The harness frame holds one transaction plus the lifecycle locals built for it.
// It runs in the benchmark/test binary, never on a proxy worker, and the engine
// types it materializes are sized by the public configuration contract.
#[expect(
    clippy::large_stack_frames,
    reason = "benchmark harness frame, not a proxy execution path"
)]
fn run_timed_transaction(prepared: &PreparedCase, uri: &str) -> Result<(), DriverError> {
    let transaction = drive_lifecycle(prepared, uri, |_, _| {})?;
    drop(transaction);
    Ok(())
}

/// Builds the timing document defined by the coordinator contract.
///
/// The document has exactly the `schema_version`, `engine`, `workload_id`,
/// `manifest_sha256`, `iterations` and `cases` fields. Each case carries its
/// manifest identifier and exactly the configured number of non-negative
/// nanosecond samples.
pub(crate) fn timing_document(workload: &Workload, iterations: usize, cases: &[TimingCase]) -> Value {
    let cases = cases
        .iter()
        .map(|case| {
            json!({
                "case_id": case.case_id,
                "samples_ns": case.samples_ns,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema_version": TIMING_SCHEMA_VERSION,
        "engine": "rust",
        "workload_id": workload.workload_id,
        "manifest_sha256": workload.manifest_sha256,
        "iterations": iterations,
        "cases": cases,
    })
}

/// Writes the timing document by renaming a temporary file over `path`.
///
/// The temporary file lives in the destination directory, so a failed run
/// cannot leave a partial document at `path`.
pub(crate) fn write_timing_document(path: &Path, document: &Value) -> Result<(), DriverError> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let mut file = tempfile::NamedTempFile::new_in(directory).map_err(|error| {
        DriverError::Load(format!(
            "cannot create a temporary timing file in {}: {error}",
            directory.display()
        ))
    })?;
    serde_json::to_writer(&mut file, document)
        .map_err(|error| DriverError::Load(format!("cannot encode the timing document: {error}")))?;
    file.write_all(b"\n")
        .map_err(|error| DriverError::Load(format!("cannot write the timing document: {error}")))?;
    file.persist(path)
        .map_err(|error| DriverError::Load(format!("cannot replace {}: {error}", path.display())))?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Comparison
// -----------------------------------------------------------------------------

/// Compares an observed outcome with the case's expected block.
pub(crate) fn compare_expected(case: &Case, outcome: &Outcome) -> Result<(), DriverError> {
    compare_matches(case, outcome)?;
    compare_interruption(case, outcome)?;
    compare_captures(case, outcome)?;
    compare_scores(case, outcome)?;
    compare_flags(case, outcome)?;
    compare_collections(case, outcome)?;
    Ok(())
}

/// Compares the ordered match list.
fn compare_matches(case: &Case, outcome: &Outcome) -> Result<(), DriverError> {
    if case.expected.matches.len() != outcome.matches.len() {
        return Err(DriverError::Mismatch(format!(
            "case {} matched {} rule occurrences, expected {}",
            case.case_id,
            outcome.matches.len(),
            case.expected.matches.len()
        )));
    }
    for (index, (expected, actual)) in case.expected.matches.iter().zip(&outcome.matches).enumerate() {
        if expected.rule_id != actual.rule_id
            || expected.phase != actual.phase
            || expected.variable != actual.variable
            || expected.key != actual.key
            || expected.value != actual.value
        {
            return Err(DriverError::Mismatch(format!(
                "case {} match {index} is rule {} phase {} {}:{:?} {:?}, expected rule {} phase {} {}:{:?} {:?}",
                case.case_id,
                actual.rule_id,
                actual.phase,
                actual.variable,
                actual.key,
                actual.value,
                expected.rule_id,
                expected.phase,
                expected.variable,
                expected.key,
                expected.value
            )));
        }
    }
    Ok(())
}

/// Compares the effective interruption.
fn compare_interruption(case: &Case, outcome: &Outcome) -> Result<(), DriverError> {
    let expected = case.expected.interruptions.first();
    match (expected, &outcome.interruption) {
        (None, None) => Ok(()),
        (Some(expected), Some(actual)) => {
            let status = i64::from(actual.status);
            if expected.rule_id != actual.rule_id
                || expected.action != actual.action
                || expected.status != status
                || expected.data != actual.data.as_bytes()
            {
                return Err(DriverError::Mismatch(format!(
                    "case {} interrupted by rule {} action {} status {}, expected rule {} action {} status {}",
                    case.case_id,
                    actual.rule_id,
                    actual.action,
                    actual.status,
                    expected.rule_id,
                    expected.action,
                    expected.status
                )));
            }
            Ok(())
        },
        (Some(expected), None) => Err(DriverError::Mismatch(format!(
            "case {} expected interruption by rule {} but none occurred",
            case.case_id, expected.rule_id
        ))),
        (None, Some(actual)) => Err(DriverError::Mismatch(format!(
            "case {} was interrupted by rule {} but the case expected none",
            case.case_id, actual.rule_id
        ))),
    }
}

/// Compares captures exactly.
fn compare_captures(case: &Case, outcome: &Outcome) -> Result<(), DriverError> {
    if case.expected.captures.len() != outcome.captures.len() {
        return Err(DriverError::Mismatch(format!(
            "case {} observed {} captures, expected {}",
            case.case_id,
            outcome.captures.len(),
            case.expected.captures.len()
        )));
    }
    for (index, (expected, actual)) in case.expected.captures.iter().zip(&outcome.captures).enumerate() {
        if expected.index != actual.index || expected.value != actual.value {
            return Err(DriverError::Mismatch(format!(
                "case {} capture {index} is TX:{} {:?}, expected TX:{} {:?}",
                case.case_id, actual.index, actual.value, expected.index, expected.value
            )));
        }
    }
    Ok(())
}

/// Compares every named score.
fn compare_scores(case: &Case, outcome: &Outcome) -> Result<(), DriverError> {
    for (name, expected) in &case.expected.scores {
        let actual = outcome.scores.get(name).copied().unwrap_or(0);
        if *expected != actual {
            return Err(DriverError::Mismatch(format!(
                "case {} score {name} is {actual}, expected {expected}",
                case.case_id
            )));
        }
    }
    Ok(())
}

/// Compares every named flag.
fn compare_flags(case: &Case, outcome: &Outcome) -> Result<(), DriverError> {
    for (name, expected) in &case.expected.flags {
        match outcome.flags.get(name) {
            Some(actual) if actual == expected => {},
            Some(actual) => {
                return Err(DriverError::Mismatch(format!(
                    "case {} flag {name} is {actual}, expected {expected}",
                    case.case_id
                )));
            },
            None => {
                return Err(DriverError::Mismatch(format!(
                    "case {} flag {name} is not observable, expected {expected}",
                    case.case_id
                )));
            },
        }
    }
    Ok(())
}

/// Compares every named collection value.
fn compare_collections(case: &Case, outcome: &Outcome) -> Result<(), DriverError> {
    if case.expected.collections.len() != outcome.collections.len() {
        return Err(DriverError::Mismatch(format!(
            "case {} observed {} collection values, expected {}",
            case.case_id,
            outcome.collections.len(),
            case.expected.collections.len()
        )));
    }
    for (index, (expected, actual)) in case.expected.collections.iter().zip(&outcome.collections).enumerate() {
        let matches = expected.variable == actual.variable
            && expected.key == actual.key
            && actual.value.as_deref() == Some(expected.value.as_slice());
        if !matches {
            return Err(DriverError::Mismatch(format!(
                "case {} collection {index} {}:{:?} is {:?}, expected {:?}",
                case.case_id, actual.variable, actual.key, actual.value, expected.value
            )));
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Language-neutral outcome document
// -----------------------------------------------------------------------------

/// Builds the NDJSON outcome object shared with the Go driver.
///
/// Byte values are standard base64 so arbitrary bytes survive JSON. Rule
/// matches stay in evaluation order, captures in index order and collections
/// in the order the case declares them. The per-match phase is omitted because
/// the Go public API does not expose it.
pub(crate) fn outcome_document(case: &Case, outcome: &Outcome) -> Value {
    let interruption = outcome.interruption.as_ref().map(|interruption| {
        json!({
            "rule_id": interruption.rule_id,
            "action": interruption.action,
            "status": interruption.status,
            "data": STANDARD.encode(interruption.data.as_bytes()),
        })
    });
    let matches = outcome
        .matches
        .iter()
        .map(|matched| {
            json!({
                "rule_id": matched.rule_id,
                "variable": matched.variable,
                "key": matched.key,
                "value": STANDARD.encode(&matched.value),
            })
        })
        .collect::<Vec<_>>();
    // `read_captures` already drops empty slots: the Go transaction seeds TX 0..10 with
    // empty strings and cannot tell an empty slot from an explicitly cleared capture.
    let captures = outcome
        .captures
        .iter()
        .map(|capture| {
            json!({
                "index": capture.index,
                "value": STANDARD.encode(&capture.value),
            })
        })
        .collect::<Vec<_>>();
    let collections = outcome
        .collections
        .iter()
        .map(|collection| {
            json!({
                "variable": collection.variable,
                "key": collection.key,
                "value": collection.value.as_ref().map(|value| STANDARD.encode(value)),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "case_id": case.case_id,
        "interruption": interruption,
        "matches": matches,
        "captures": captures,
        "scores": &outcome.scores,
        "flags": &outcome.flags,
        "collections": collections,
    })
}

/// Writes outcome documents as NDJSON, one object per line.
pub(crate) fn write_outcomes(path: &Path, documents: &[Value]) -> Result<(), DriverError> {
    let file = fs::File::create(path)
        .map_err(|error| DriverError::Load(format!("cannot create outcome file {}: {error}", path.display())))?;
    let mut writer = std::io::BufWriter::new(file);
    for document in documents {
        let line = serde_json::to_vec(document)
            .map_err(|error| DriverError::Load(format!("cannot encode outcome document: {error}")))?;
        writer
            .write_all(&line)
            .and_then(|()| writer.write_all(b"\n"))
            .map_err(|error| DriverError::Load(format!("cannot write {}: {error}", path.display())))?;
    }
    writer
        .flush()
        .map_err(|error| DriverError::Load(format!("cannot flush {}: {error}", path.display())))
}
