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

//! Contract fixture validation and result recording for envoy-coraza.

#![allow(clippy::missing_docs_in_private_items, reason = "internal xtask implementation")]

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fmt, fs,
    fs::OpenOptions,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::Args;
use serde::{Deserialize, de};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const MANIFEST: &str = "envoy-coraza/tests/contracts/manifest.json";
const CASES: &str = "envoy-coraza/tests/contracts/cases.json";
const SOURCE_PROVENANCE: &str = "envoy-coraza/tests/contracts/source-provenance.json";
const SCHEMA_VERSION: u32 = 2;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_CASES_BYTES: usize = 1024 * 1024;
const MAX_SOURCE_PROVENANCE_BYTES: usize = 1024 * 1024;
const MAX_OUTCOMES_BYTES: usize = 4 * 1024 * 1024;
const MAX_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
/// Approved host pins: (host id, manifest field, approved value). The required-host set is
/// derived from this table; every entry must appear in the manifest with exactly this pin.
const APPROVED_HOSTS: &[(&str, &str, &str)] = &[
    (
        "standalone-envoy-1.40.0",
        "image",
        "envoyproxy/envoy:v1.40.0@sha256:459f2a6404c340fe6afccd69d85527012d47f3c036765493e6f8f3113fa384de",
    ),
    (
        "istio-1.30.5",
        "proxy_image_digest",
        "sha256:324ec9f74e9194c43b16e859497d67567c93d3d1e5f0804a88ed48002e668f62",
    ),
    (
        "istio-1.30.7",
        "proxy_image_digest",
        "sha256:340794767464f3d13c9e3df38cc663ecbc8264f00c7022dca53ad5c80336681f",
    ),
];
/// Exact number of contract cases; drift must be a deliberate, reviewed change.
const REQUIRED_CASE_COUNT: usize = 56;
/// SHA-256 over the sorted case IDs, each terminated by one newline. Binding the ID set (not
/// just the count) makes renaming or swapping a case fail even when the count is restored.
const CASE_SET_SHA256: &str = "3f85ad3a82c8d44d2361dbbfb79bc33b65d304a82d9aee77939a9ba0b90a7b56";
/// SHA-256 over the parsed fixture cases sorted by ID: each case contributes its ID and the
/// hex SHA-256 of its semantic fixture JSON (`fixture_semantics` field selection, canonical
/// key-sorted serialization), each terminated by one newline. Anchors fixture content
/// independently of the self-refreshable `contract_sha256`.
const CASES_FILE_SHA256: &str = "ab7eedacc0f84ff292539897d4a8bf0aea9f0abef8a68736ba3b19488fb77650";
/// SHA-256 over the manifest case definitions sorted by ID: each case contributes its ID and
/// the canonical JSON of its semantic fields (id, reference, hosts, `required_outcome_fields`),
/// each terminated by one newline. Anchors case references, host matrices, and required
/// outcome fields against silent weakening.
const MANIFEST_CASES_SHA256: &str = "f9e929e889519fbea108b9ff76d52322f4c96f3d9463db5ccd51931c15981634";
/// Code-side anchor equal to the checked-in `contract_sha256`. The manifest digest is
/// self-refreshable, so this constant is what actually pins the full contract semantics
/// (pins, hosts, case definitions, inventory, coverage, deferred IDs, fixtures) against
/// silent retargeting; the finer-grained anchors only provide more actionable errors.
const CONTRACT_SHA256: &str = "fd11e9408df9f0476b15de8a2d98a828ef68686b84acb2d1638a52503ddb943c";
/// Exact set of manifest `inventory` category keys.
const REQUIRED_INVENTORY_CATEGORIES: &[&str] = &[
    "upstream_configuration_keys",
    "upstream_bundle_aliases",
    "legacy_metrics",
    "pr20_filter_state_fields",
    "lifecycle_outcomes",
    "required_engine_features",
    "diagnostic_only_probes",
    "hostcall failures",
];
/// SHA-256 over the sorted `category<US>claim` pairs (US = ASCII unit separator U+001F), each
/// terminated by one newline. Binding the full claim set makes deleting or moving a single
/// claim fail even when its coverage entry is removed with it.
const INVENTORY_CLAIM_SET_SHA256: &str = "bbe237e068bed7df6d149b2d29175a7aa967c7c8b15bb98a41eb92f6c3ab95ff";
const REQUIRED_DEFERRED_INVENTORY: &[&str] = &[
    "wasm-loading",
    "connection-uri-variables",
    "partial-inspection",
    "transforms",
    "anomaly-score",
    "negative-rule-tests",
    "matched-rule",
    "engine-error",
    "audit",
    "startup-failure",
    "reload-failure",
    "response-limit-boundaries",
    "http2-multiplexing",
    "multiple-workers",
    "hostcall-failure-matrix",
    "resource-exhaustion",
    "rule-data-bounds",
    "rule-data-runtime-resolution",
    "rule-data-validate-schema",
    "pr20-source-commit-binding",
    "crs-exclusions",
    "fragmented-bodies",
    "filter-state-access-log",
    "websocket-tunnels",
    "connect-tunnels",
    "indefinite-streaming",
    "grpc-message-decoding",
    "http3",
    "arbitrary-filesystem-access",
    "external-process-operators",
    "dns-operators",
    "custom-remote-audit-transports",
];
/// SHA-256 over the sorted deferred inventory IDs, each terminated by one newline, so adding
/// or removing a deferred item needs a reviewed constant edit on top of the required-subset
/// check below.
const DEFERRED_INVENTORY_SET_SHA256: &str = "f14d3d19670611a9cf9ed240938ec279b0ff54247b3abc94a96cd2c6583845a1";

#[derive(Debug)]
struct ContractManifest {
    schema_version: u32,
    contract_sha256: String,
    hosts: Vec<Host>,
    cases: Vec<CaseRef>,
    inventory_coverage: BTreeMap<String, Vec<String>>,
    deferred_inventory: Vec<String>,
    pins: Pins,
}

#[derive(Debug)]
struct Host {
    id: String,
    pinned: bool,
}

#[derive(Debug)]
struct CaseRef {
    id: String,
    reference: String,
    hosts: Vec<String>,
    required_outcome_fields: Vec<RequiredObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservationType {
    String,
    OptionalString,
    Boolean,
    NonNegativeInteger,
    HttpStatus,
    Array,
    Object,
    HeaderPairs,
    OptionalHeaderPairs,
    RuleMatches,
}

#[derive(Debug)]
struct RequiredObservation {
    path: String,
    value_type: ObservationType,
}

#[derive(Debug)]
struct Pins {
    upstream_connector: String,
    pr20_head: String,
}

#[derive(Debug)]
struct FixtureCase {
    id: String,
    raw_plugin_configuration: String,
    plugin_configuration: Value,
    duplicate_default_directives: bool,
    request: Option<Value>,
    reload_plugin_configuration: Option<Value>,
    host_scenarios: Vec<String>,
    host_faults: Vec<Value>,
    backend_response: Option<Value>,
    topics: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RecordArgs {
    /// Host identifier from the contract manifest.
    #[arg(long)]
    host: String,
    /// Reference role: upstream, pr20, or candidate.
    #[arg(long)]
    role: String,
    /// Immutable source revision used to build the artifact.
    #[arg(long)]
    revision: String,
    /// SHA-256 of the executed WASM artifact.
    #[arg(long)]
    artifact_sha256: String,
    /// JSON object mapping every contract case ID to one normalized outcome object.
    #[arg(long)]
    outcomes: PathBuf,
    /// Output capture JSON path.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct CompareArgs {
    /// Recorded upstream capture JSON.
    #[arg(long)]
    baseline: PathBuf,
    /// Recorded candidate capture JSON.
    #[arg(long)]
    candidate: PathBuf,
    /// Output mismatch ledger JSON path.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug)]
struct Capture {
    schema_version: u32,
    host: String,
    role: String,
    revision: String,
    artifact_sha256: String,
    contract_sha256: String,
    outcomes: BTreeMap<String, Value>,
}

#[derive(Debug)]
struct Mismatch<'a> {
    case_id: String,
    baseline: Option<&'a Value>,
    candidate: Option<&'a Value>,
}

#[derive(Debug)]
struct StrictOutcomes(BTreeMap<String, Value>);

struct StrictJsonValue(Value);

struct StrictPluginConfiguration(Value, bool);

impl<'de> Deserialize<'de> for StrictOutcomes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct OutcomesVisitor;

        impl<'de> de::Visitor<'de> for OutcomesVisitor {
            type Value = StrictOutcomes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object keyed by unique case IDs")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: de::MapAccess<'de>,
            {
                let mut outcomes = BTreeMap::new();
                while let Some((case_id, outcome)) = map.next_entry::<String, StrictJsonValue>()? {
                    if outcomes.insert(case_id.clone(), outcome.0).is_some() {
                        return Err(de::Error::custom(format!("duplicate outcome case ID {case_id}")));
                    }
                }
                Ok(StrictOutcomes(outcomes))
            }
        }

        deserializer.deserialize_map(OutcomesVisitor)
    }
}

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictValueVisitor;

        impl<'de> de::Visitor<'de> for StrictValueVisitor {
            type Value = StrictJsonValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value with unique object keys")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(Value::Bool(v)))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(Value::from(v)))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(Value::from(v)))
            }

            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                serde_json::Number::from_f64(v)
                    .map(|number| StrictJsonValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictJsonValue(Value::String(v.to_owned())))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(Value::String(v)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(Value::Null))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<StrictJsonValue>()? {
                    values.push(value.0);
                }
                Ok(StrictJsonValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!("duplicate JSON object key {key}")));
                    }
                    let value = map.next_value::<StrictJsonValue>()?;
                    values.insert(key, value.0);
                }
                Ok(StrictJsonValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(StrictValueVisitor)
    }
}

impl<'de> Deserialize<'de> for StrictPluginConfiguration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PluginConfigurationVisitor;

        impl<'de> de::Visitor<'de> for PluginConfigurationVisitor {
            type Value = StrictPluginConfiguration;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object with at most one duplicate default_directives key")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: de::MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                let mut duplicate_default_directives = false;
                while let Some(key) = map.next_key::<String>()? {
                    let value = map.next_value::<StrictJsonValue>()?.0;
                    if values.contains_key(&key) {
                        if key == "default_directives" && !duplicate_default_directives {
                            duplicate_default_directives = true;
                            continue;
                        }
                        return Err(de::Error::custom(format!("duplicate JSON object key {key}")));
                    }
                    values.insert(key, value);
                }
                Ok(StrictPluginConfiguration(
                    Value::Object(values),
                    duplicate_default_directives,
                ))
            }
        }

        deserializer.deserialize_map(PluginConfigurationVisitor)
    }
}

#[derive(Deserialize)]
struct CaptureFile {
    schema_version: u32,
    host: String,
    role: String,
    revision: String,
    artifact_sha256: String,
    contract_sha256: String,
    outcomes: StrictOutcomes,
}

pub(crate) fn check_or_exit() {
    match check_manifest(repository_root()) {
        Ok(manifest) => println!(
            "Envoy Coraza contract manifest valid: {} cases, {} hosts, {} deferred inventory items; baseline remains unrecorded.",
            manifest.cases.len(),
            manifest.hosts.len(),
            manifest.deferred_inventory.len()
        ),
        Err(error) => {
            eprintln!("Envoy Coraza contract check failed: {error}");
            std::process::exit(1);
        },
    }
}

fn repository_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is a workspace member")
}

pub(crate) fn record_or_exit(args: &RecordArgs) {
    if let Err(error) = record(args) {
        eprintln!("Envoy Coraza contract record failed: {error}");
        std::process::exit(1);
    }
}

pub(crate) fn compare_or_exit(args: &CompareArgs) {
    match compare(args) {
        Ok(0) => {
            println!("Recorded Envoy Coraza outcomes match for the selected cases.");
        },
        Ok(mismatch_count) => {
            eprintln!("Envoy Coraza contract mismatches recorded: {mismatch_count}");
            std::process::exit(1);
        },
        Err(error) => {
            eprintln!("Envoy Coraza contract compare failed: {error}");
            std::process::exit(1);
        },
    }
}

fn check_manifest(root: &Path) -> Result<ContractManifest, String> {
    let manifest_path = root.join(MANIFEST);
    let bytes = read_limited(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest_value = parse_strict_json(&bytes, MANIFEST)?;
    let manifest = parse_manifest(&manifest_value)?;
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(format!("unsupported manifest schema {}", manifest.schema_version));
    }
    check_source_provenance(root, manifest_value.get("pins").ok_or("manifest pins are required")?)?;
    let case_path = root.join(CASES);
    let case_bytes = read_limited(&case_path, MAX_CASES_BYTES)?;
    if !is_sha256(&manifest.contract_sha256) {
        return Err("contract_sha256 must be a lowercase SHA-256 digest".to_owned());
    }
    let actual_digest = contract_digest(&manifest_value, &case_bytes)?;
    if manifest.contract_sha256 != actual_digest {
        return Err(format!(
            "contract_sha256 changed: expected {}, got {actual_digest}; after a deliberate contract change, write the computed digest into {MANIFEST}, then update each finer-grained anchor constant the checker names, and finally CONTRACT_SHA256 in xtask/src/envoy_contract.rs, all in the same reviewed change",
            manifest.contract_sha256
        ));
    }
    let case_values = parse_strict_json(&case_bytes, CASES)?;
    let case_values = case_values
        .as_array()
        .ok_or_else(|| format!("{CASES} must be a JSON array"))?;
    let cases: Vec<FixtureCase> = case_values.iter().map(parse_fixture_case).collect::<Result<_, _>>()?;
    let mut fixture_ids = BTreeSet::new();
    for case in &cases {
        if !fixture_ids.insert(case.id.as_str()) {
            return Err(format!("duplicate fixture case ID {}", case.id));
        }
    }
    let case_ids: BTreeSet<_> = manifest.cases.iter().map(|case| case.id.as_str()).collect();
    if case_ids.len() != manifest.cases.len() || case_ids != fixture_ids {
        return Err("manifest case IDs do not match cases.json".to_owned());
    }
    if manifest.cases.len() != REQUIRED_CASE_COUNT {
        return Err(format!(
            "contract must keep exactly {REQUIRED_CASE_COUNT} cases, found {}; update REQUIRED_CASE_COUNT in xtask/src/envoy_contract.rs deliberately in review if the inventory is changing",
            manifest.cases.len()
        ));
    }
    let actual_case_set_digest = sorted_newline_digest(case_ids.iter().map(|id| (*id).to_owned()));
    if actual_case_set_digest != CASE_SET_SHA256 {
        return Err(format!(
            "case ID set changed: expected digest {CASE_SET_SHA256}, got {actual_case_set_digest}; update CASE_SET_SHA256 in xtask/src/envoy_contract.rs deliberately in review after renaming, removing, or adding cases"
        ));
    }
    validate_inventory_coverage(&manifest.inventory_coverage, &cases)?;
    validate_host_ids(&manifest.hosts)?;
    validate_host_pins(&manifest_value)?;
    let host_ids: BTreeSet<_> = manifest.hosts.iter().map(|host| host.id.as_str()).collect();
    let pinned_host_ids: BTreeSet<_> = manifest
        .hosts
        .iter()
        .filter(|host| host.pinned)
        .map(|host| host.id.as_str())
        .collect();
    for case in &manifest.cases {
        if case.reference != "upstream" && case.reference != "pr20" && case.reference != "candidate" {
            return Err(format!("case {} has unknown reference {}", case.id, case.reference));
        }
        if case.hosts.is_empty() || case.hosts.iter().any(|host| !host_ids.contains(host.as_str())) {
            return Err(format!("case {} names an unknown or empty host set", case.id));
        }
        let case_host_ids: BTreeSet<_> = case.hosts.iter().map(String::as_str).collect();
        let missing_pinned_hosts: Vec<_> = pinned_host_ids.difference(&case_host_ids).copied().collect();
        if !missing_pinned_hosts.is_empty() {
            return Err(format!(
                "case {} is missing pinned hosts: {}",
                case.id,
                missing_pinned_hosts.join(", ")
            ));
        }
        let required_paths: BTreeSet<_> = case
            .required_outcome_fields
            .iter()
            .map(|field| field.path.as_str())
            .collect();
        if case.required_outcome_fields.is_empty() || required_paths.len() != case.required_outcome_fields.len() {
            return Err(format!("case {} needs valid required_outcome_fields", case.id));
        }
        validate_backend_request_schema(case)?;
    }
    if !is_commit(&manifest.pins.upstream_connector) || !is_commit(&manifest.pins.pr20_head) {
        return Err("connector and PR #20 pins must be full lowercase commit IDs".to_owned());
    }
    validate_content_anchors(&manifest, &manifest_value, case_values)?;
    Ok(manifest)
}

/// Final content anchors; see each constant's documentation for what it covers. They run last
/// so semantic validations give more actionable errors, and they catch edits that would
/// otherwise pass after a `contract_sha256` refresh.
fn validate_content_anchors(
    manifest: &ContractManifest,
    manifest_value: &Value,
    case_values: &[Value],
) -> Result<(), String> {
    let actual_cases_file_digest = cases_file_digest(case_values)?;
    if actual_cases_file_digest != CASES_FILE_SHA256 {
        return Err(format!(
            "fixture content changed: expected digest {CASES_FILE_SHA256}, got {actual_cases_file_digest}; update CASES_FILE_SHA256 in xtask/src/envoy_contract.rs deliberately in review after changing any fixture case"
        ));
    }
    let actual_manifest_cases_digest = manifest_cases_digest(manifest_value)?;
    if actual_manifest_cases_digest != MANIFEST_CASES_SHA256 {
        return Err(format!(
            "manifest case definitions changed: expected digest {MANIFEST_CASES_SHA256}, got {actual_manifest_cases_digest}; update MANIFEST_CASES_SHA256 in xtask/src/envoy_contract.rs deliberately in review after changing case references, hosts, or required outcome fields"
        ));
    }
    // The broadest anchor runs last: the manifest digest is self-refreshable, so only this
    // code-side constant pins contract semantics that no finer-grained anchor covers.
    if manifest.contract_sha256 != CONTRACT_SHA256 {
        return Err(format!(
            "contract semantics changed: expected digest {CONTRACT_SHA256}, got {}; update CONTRACT_SHA256 in xtask/src/envoy_contract.rs deliberately in review after refreshing the manifest digest",
            manifest.contract_sha256
        ));
    }
    Ok(())
}

fn check_source_provenance(root: &Path, pins: &Value) -> Result<(), String> {
    let provenance = pins
        .get("source_provenance")
        .ok_or("manifest source_provenance pin is required")?;
    let relative_path = string_field(provenance, "path")?;
    if relative_path != SOURCE_PROVENANCE {
        return Err(format!("source_provenance.path must be {SOURCE_PROVENANCE}"));
    }
    let expected_digest = string_field(provenance, "sha256")?;
    if !is_sha256(expected_digest) {
        return Err("source_provenance.sha256 must be a lowercase SHA-256 digest".to_owned());
    }

    let root = fs::canonicalize(root).map_err(|error| format!("{}: {error}", root.display()))?;
    let path =
        fs::canonicalize(root.join(SOURCE_PROVENANCE)).map_err(|error| format!("{SOURCE_PROVENANCE}: {error}"))?;
    if !path.starts_with(&root) {
        return Err(format!("{SOURCE_PROVENANCE} resolves outside the repository"));
    }
    let bytes = read_limited(&path, MAX_SOURCE_PROVENANCE_BYTES)?;
    let actual_digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if expected_digest != actual_digest {
        return Err(format!(
            "source_provenance.sha256 changed: expected {expected_digest}, got {actual_digest}"
        ));
    }
    Ok(())
}

fn validate_host_ids(hosts: &[Host]) -> Result<(), String> {
    let host_ids: BTreeSet<_> = hosts.iter().map(|host| host.id.as_str()).collect();
    if hosts.is_empty() || host_ids.len() != hosts.len() || hosts.iter().any(|host| host.id.trim().is_empty()) {
        return Err("host IDs must be non-empty, non-whitespace, and unique".to_owned());
    }
    Ok(())
}

fn validate_host_pins(manifest: &Value) -> Result<(), String> {
    let hosts = manifest
        .get("hosts")
        .and_then(Value::as_array)
        .ok_or("manifest hosts must be an array")?;
    let approved_ids: BTreeSet<_> = APPROVED_HOSTS.iter().map(|(host_id, ..)| *host_id).collect();
    for host in hosts {
        let host_id = host.get("id").and_then(Value::as_str).unwrap_or_default();
        if !approved_ids.contains(host_id) {
            return Err(format!(
                "manifest host {host_id} is not in the approved host set; update APPROVED_HOSTS in xtask/src/envoy_contract.rs deliberately in review if this host is being added"
            ));
        }
    }
    for (host_id, field, approved) in APPROVED_HOSTS {
        let host = hosts
            .iter()
            .find(|host| host.get("id").and_then(Value::as_str) == Some(*host_id))
            .ok_or_else(|| format!("manifest must pin required host {host_id} with {field} {approved}"))?;
        let observed = host.get(*field).and_then(Value::as_str);
        if observed != Some(*approved) {
            return Err(format!(
                "host {host_id} {field} must be {approved}, got {}; update APPROVED_HOSTS in xtask/src/envoy_contract.rs deliberately in review if this pin change is intended",
                observed.unwrap_or("<missing>")
            ));
        }
    }
    Ok(())
}

/// SHA-256 over already-sorted strings, each terminated by one newline.
fn sorted_newline_digest(items: impl IntoIterator<Item = String>) -> String {
    let mut digest = Sha256::new();
    for item in items {
        digest.update(item.as_bytes());
        digest.update(b"\n");
    }
    digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

/// SHA-256 over the strictly parsed fixture cases sorted by ID: each case contributes its ID
/// and the hex `fixture_sha256` of its semantic fixture JSON, each terminated by one newline.
/// `serde_json` escapes control characters, so the hex digests contain no raw newlines.
fn cases_file_digest(cases: &[Value]) -> Result<String, String> {
    let mut sorted = cases.iter().collect::<Vec<_>>();
    sorted.sort_by_key(|case| case.get("id").and_then(Value::as_str).unwrap_or_default().to_owned());
    let mut digest = Sha256::new();
    for case in sorted {
        let id = case.get("id").and_then(Value::as_str).unwrap_or_default();
        let fixture = fixture_sha256(case)?;
        digest.update(id.as_bytes());
        digest.update(b"\n");
        digest.update(fixture.as_bytes());
        digest.update(b"\n");
    }
    Ok(digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect())
}

/// SHA-256 over the manifest case definitions sorted by ID: each case contributes its ID and
/// the canonical JSON of its semantic fields, each terminated by one newline.
fn manifest_cases_digest(manifest: &Value) -> Result<String, String> {
    let cases = manifest
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("manifest cases must be an array")?;
    let mut sorted = cases
        .iter()
        .map(|case| select_fields(case, &["id", "reference", "hosts", "required_outcome_fields"]))
        .collect::<Vec<_>>();
    sorted.sort_by_key(|case| case.get("id").and_then(Value::as_str).unwrap_or_default().to_owned());
    let mut digest = Sha256::new();
    for case in sorted {
        let id = case.get("id").and_then(Value::as_str).unwrap_or_default();
        let canonical = serde_json::to_vec(&case).map_err(|error| error.to_string())?;
        digest.update(id.as_bytes());
        digest.update(b"\n");
        digest.update(&canonical);
        digest.update(b"\n");
    }
    Ok(digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect())
}

fn record(args: &RecordArgs) -> Result<(), String> {
    let root = repository_root();
    let manifest_path = root.join(MANIFEST);
    let cases_path = root.join(CASES);
    reject_output_alias(&args.output, &[&args.outcomes, &manifest_path, &cases_path])?;
    let manifest = check_manifest(root)?;
    let role_revision = match args.role.as_str() {
        "upstream" => Some(manifest.pins.upstream_connector.as_str()),
        "pr20" => Some(manifest.pins.pr20_head.as_str()),
        "candidate" => None,
        _ => return Err("role must be upstream, pr20, or candidate".to_owned()),
    };
    if let Some(expected) = role_revision {
        if args.revision != expected {
            return Err(format!("{} role must use pinned revision {expected}", args.role));
        }
    } else if !is_commit(&args.revision) {
        return Err("candidate revision must be a full lowercase commit ID".to_owned());
    }
    require_pinned_host(&manifest, &args.host)?;
    if !is_sha256(&args.artifact_sha256) {
        return Err("artifact_sha256 must be a lowercase SHA-256 digest".to_owned());
    }
    let outcome_bytes = read_limited(&args.outcomes, MAX_OUTCOMES_BYTES)?;
    let outcomes: StrictOutcomes =
        serde_json::from_slice(&outcome_bytes).map_err(|error| format!("{}: {error}", args.outcomes.display()))?;
    validate_outcomes(&manifest, &args.host, &args.role, &outcomes.0)?;
    let outcome_count = outcomes.0.len();
    let capture = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "host": args.host,
        "role": args.role,
        "revision": args.revision,
        "artifact_sha256": args.artifact_sha256,
        "contract_sha256": manifest.contract_sha256,
        "outcomes": outcomes.0,
    });
    let output = serialize_capture(&capture)?;
    write_output(&args.output, &[&args.outcomes, &manifest_path, &cases_path], &output)?;
    println!(
        "Recorded {} outcomes for {} on {}.",
        outcome_count, args.role, args.host
    );
    Ok(())
}

fn require_pinned_host(manifest: &ContractManifest, id: &str) -> Result<(), String> {
    let host = manifest
        .hosts
        .iter()
        .find(|host| host.id == id)
        .ok_or_else(|| format!("unknown host {id}"))?;
    if !host.pinned {
        return Err(format!("host {id} has no immutable image digest pin"));
    }
    Ok(())
}

fn compare(args: &CompareArgs) -> Result<usize, String> {
    let root = repository_root();
    let manifest_path = root.join(MANIFEST);
    let cases_path = root.join(CASES);
    reject_output_alias(
        &args.output,
        &[&args.baseline, &args.candidate, &manifest_path, &cases_path],
    )?;
    let manifest = check_manifest(root)?;
    let fixture_hashes = fixture_sha256s(&read_limited(&cases_path, MAX_CASES_BYTES)?)?;
    let baseline = read_capture(&args.baseline)?;
    let candidate = read_capture(&args.candidate)?;
    if baseline.role != "upstream" && baseline.role != "pr20" {
        return Err("baseline capture role must be upstream or pr20".to_owned());
    }
    let pinned_baseline = if baseline.role == "upstream" {
        &manifest.pins.upstream_connector
    } else {
        &manifest.pins.pr20_head
    };
    if baseline.revision != *pinned_baseline {
        return Err(format!(
            "baseline role {} must use pinned revision {pinned_baseline}",
            baseline.role
        ));
    }
    if candidate.role != "candidate" {
        return Err("candidate capture role must be candidate".to_owned());
    }
    if baseline.host != candidate.host {
        return Err("captures use different hosts".to_owned());
    }
    validate_capture_contract_digest("baseline", &baseline, &manifest.contract_sha256)?;
    validate_capture_contract_digest("candidate", &candidate, &manifest.contract_sha256)?;
    require_pinned_host(&manifest, &baseline.host)?;
    validate_outcomes(&manifest, &baseline.host, &baseline.role, &baseline.outcomes)?;
    validate_outcomes(&manifest, &candidate.host, &candidate.role, &candidate.outcomes)?;
    let mismatches = compare_outcomes(&manifest, &baseline, &candidate);
    let count = mismatches.len();
    let ledger = mismatch_ledger(
        &manifest.contract_sha256,
        &baseline,
        &candidate,
        &mismatches,
        &fixture_hashes,
    )?;
    let output = serde_json::to_vec_pretty(&ledger).map_err(|error| error.to_string())?;
    write_output(
        &args.output,
        &[&args.baseline, &args.candidate, &manifest_path, &cases_path],
        &output,
    )?;
    Ok(count)
}

fn read_capture(path: &Path) -> Result<Capture, String> {
    let bytes = read_limited(path, MAX_CAPTURE_BYTES)?;
    let file: CaptureFile = serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    let capture = Capture {
        schema_version: file.schema_version,
        host: file.host,
        role: file.role,
        revision: file.revision,
        artifact_sha256: file.artifact_sha256,
        contract_sha256: file.contract_sha256,
        outcomes: file.outcomes.0,
    };
    if capture.schema_version != SCHEMA_VERSION
        || !is_sha256(&capture.artifact_sha256)
        || !is_sha256(&capture.contract_sha256)
    {
        return Err(format!("{} has invalid schema or artifact digest", path.display()));
    }
    if !is_commit(&capture.revision) {
        return Err(format!("{} revision is not a full commit ID", path.display()));
    }
    Ok(capture)
}

fn validate_outcomes(
    manifest: &ContractManifest,
    host: &str,
    role: &str,
    outcomes: &BTreeMap<String, Value>,
) -> Result<(), String> {
    let expected: BTreeSet<_> = manifest
        .cases
        .iter()
        .filter(|case| case.hosts.iter().any(|case_host| case_host == host))
        .filter(|case| role == "candidate" || case.reference == role)
        .map(|case| case.id.as_str())
        .collect();
    let actual: BTreeSet<_> = outcomes.keys().map(String::as_str).collect();
    if expected != actual {
        let missing: Vec<_> = expected.difference(&actual).copied().collect();
        let extra: Vec<_> = actual.difference(&expected).copied().collect();
        return Err(format!(
            "outcome case inventory differs; missing={missing:?}, extra={extra:?}"
        ));
    }
    for (case_id, outcome) in outcomes {
        if !outcome.as_object().is_some_and(|object| !object.is_empty()) {
            return Err(format!("outcome for case {case_id} must be a non-empty JSON object"));
        }
        let case = manifest
            .cases
            .iter()
            .find(|case| case.id == *case_id)
            .ok_or_else(|| format!("unknown outcome case {case_id}"))?;
        validate_base64_values(&format!("outcome for case {case_id}"), outcome, "")?;
        for field in &case.required_outcome_fields {
            let Some(value) = observation_field(outcome, &field.path) else {
                return Err(format!(
                    "outcome for case {case_id} is missing required field {}",
                    field.path
                ));
            };
            if !observation_has_type(value, field.value_type) {
                return Err(format!(
                    "outcome for case {case_id} field {} must be {}",
                    field.path,
                    field.value_type.name()
                ));
            }
            if observation_field(outcome, "backend.received").and_then(Value::as_bool) == Some(true)
                && field.path.starts_with("backend.request.")
                && value.is_null()
            {
                return Err(format!(
                    "outcome for case {case_id} field {} must not be null when backend.received is true",
                    field.path
                ));
            }
        }
    }
    Ok(())
}

fn validate_base64_values(error_prefix: &str, value: &Value, parent_path: &str) -> Result<(), String> {
    match value {
        Value::Object(fields) => {
            for (field, value) in fields {
                let path = if parent_path.is_empty() {
                    field.clone()
                } else {
                    format!("{parent_path}.{field}")
                };
                if field.ends_with("_base64") && value.as_str().is_some_and(|encoded| BASE64.decode(encoded).is_err()) {
                    return Err(format!("{error_prefix} field {path} must be valid Base64"));
                }
                validate_base64_values(error_prefix, value, &path)?;
            }
        },
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                validate_base64_values(error_prefix, value, &format!("{parent_path}[{index}]"))?;
            }
        },
        _ => {},
    }
    Ok(())
}

fn validate_backend_request_schema(case: &CaseRef) -> Result<(), String> {
    let fields: BTreeMap<_, _> = case
        .required_outcome_fields
        .iter()
        .map(|field| (field.path.as_str(), field.value_type))
        .collect();
    if !fields.keys().any(|path| path.starts_with("backend.request.")) {
        return Ok(());
    }
    for path in ["backend.received", "backend.request.method", "backend.request.path"] {
        if !fields.contains_key(path) {
            return Err(format!(
                "case {} must require {path} with backend request observations",
                case.id
            ));
        }
    }
    for path in ["backend.request.method", "backend.request.path"] {
        if fields.get(path) != Some(&ObservationType::OptionalString) {
            return Err(format!("case {} must type {path} as optional_string", case.id));
        }
    }
    if fields.get("backend.received") != Some(&ObservationType::Boolean) {
        return Err(format!("case {} must type backend.received as boolean", case.id));
    }
    Ok(())
}

fn valid_observation_path(path: &str) -> bool {
    !path.is_empty() && path.split('.').all(|part| !part.is_empty())
}

fn observation_field<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in path.split('.') {
        current = match current {
            Value::Array(values) => values.get(part.parse::<usize>().ok()?)?,
            Value::Object(fields) => fields.get(part)?,
            _ => return None,
        };
    }
    Some(current)
}

fn observation_has_type(value: &Value, value_type: ObservationType) -> bool {
    match value_type {
        ObservationType::String => value.is_string(),
        ObservationType::OptionalString => value.is_null() || value.is_string(),
        ObservationType::Boolean => value.is_boolean(),
        ObservationType::NonNegativeInteger => value.as_u64().is_some(),
        ObservationType::HttpStatus => value.as_u64().is_some_and(|status| (100..=599).contains(&status)),
        ObservationType::Array => value.is_array(),
        ObservationType::Object => value.is_object(),
        ObservationType::HeaderPairs => valid_header_pairs(value),
        ObservationType::OptionalHeaderPairs => value.is_null() || valid_header_pairs(value),
        ObservationType::RuleMatches => value.as_array().is_some_and(|matches| {
            matches.iter().all(|matched| {
                matched.as_object().is_some_and(|matched| {
                    matched.get("id").is_some_and(Value::is_string)
                        && matched.get("phase").and_then(Value::as_u64).is_some()
                        && matched.get("action").is_some_and(Value::is_string)
                })
            })
        }),
    }
}

fn valid_header_pairs(value: &Value) -> bool {
    value.as_array().is_some_and(|pairs| {
        pairs.iter().all(|pair| {
            pair.as_array().is_some_and(|pair| {
                pair.len() == 2
                    && pair
                        .first()
                        .and_then(Value::as_str)
                        .is_some_and(|name| !name.is_empty())
                    && pair.get(1).is_some_and(Value::is_string)
            })
        })
    })
}

impl ObservationType {
    fn name(self) -> &'static str {
        match self {
            Self::String => "a string",
            Self::OptionalString => "a string or null",
            Self::Boolean => "a boolean",
            Self::NonNegativeInteger => "a non-negative integer",
            Self::HttpStatus => "an HTTP status integer",
            Self::Array => "an array",
            Self::Object => "an object",
            Self::HeaderPairs => "an ordered array of header pairs",
            Self::OptionalHeaderPairs => "an ordered array of header pairs or null",
            Self::RuleMatches => "an ordered array of rule-match observations",
        }
    }
}

fn validate_capture_contract_digest(label: &str, capture: &Capture, current_digest: &str) -> Result<(), String> {
    if capture.contract_sha256 != current_digest {
        return Err(format!(
            "{label} capture contract_sha256 does not match the current manifest and {CASES}"
        ));
    }
    Ok(())
}

fn compare_outcomes<'a>(
    manifest: &ContractManifest,
    baseline: &'a Capture,
    candidate: &'a Capture,
) -> Vec<Mismatch<'a>> {
    manifest
        .cases
        .iter()
        .filter(|case| case.reference == baseline.role && case.hosts.iter().any(|host| host == &baseline.host))
        .filter_map(|case| {
            let left = baseline.outcomes.get(&case.id);
            let right = candidate.outcomes.get(&case.id);
            (left != right).then(|| Mismatch {
                case_id: case.id.clone(),
                baseline: left,
                candidate: right,
            })
        })
        .collect()
}

fn mismatch_ledger(
    contract_sha256: &str,
    baseline: &Capture,
    candidate: &Capture,
    mismatches: &[Mismatch<'_>],
    fixture_hashes: &BTreeMap<String, String>,
) -> Result<Value, String> {
    let mismatch_values = mismatches
        .iter()
        .map(|item| {
            let fixture_sha256 = fixture_hashes
                .get(&item.case_id)
                .ok_or_else(|| format!("missing fixture hash for case {}", item.case_id))?;
            Ok(serde_json::json!({
                "case_id": item.case_id,
                "host": baseline.host,
                "contract_sha256": contract_sha256,
                "fixture_sha256": fixture_sha256,
                "baseline": {
                    "role": baseline.role,
                    "revision": baseline.revision,
                    "artifact_sha256": baseline.artifact_sha256,
                    "outcome": item.baseline,
                },
                "candidate": {
                    "role": candidate.role,
                    "revision": candidate.revision,
                    "artifact_sha256": candidate.artifact_sha256,
                    "outcome": item.candidate,
                },
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "host": baseline.host,
        "baseline_role": baseline.role,
        "baseline_revision": baseline.revision,
        "baseline_artifact_sha256": baseline.artifact_sha256,
        "candidate_role": candidate.role,
        "candidate_revision": candidate.revision,
        "candidate_artifact_sha256": candidate.artifact_sha256,
        "contract_sha256": contract_sha256,
        "mismatches": mismatch_values,
    }))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Delimiters that would make the newline- and unit-separator-framed set digests ambiguous.
fn contains_digest_delimiter(value: &str) -> bool {
    value.contains('\n') || value.contains('\r') || value.contains('\u{1f}')
}

fn is_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn contract_digest(manifest: &Value, cases: &[u8]) -> Result<String, String> {
    let cases = parse_strict_json(cases, CASES)?;
    let contract = contract_semantics(manifest, &cases)?;
    let contract_bytes = serde_json::to_vec(&contract).map_err(|error| error.to_string())?;
    let mut digest = Sha256::new();
    digest.update(contract_bytes);
    Ok(digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect())
}

fn contract_semantics(manifest: &Value, cases: &Value) -> Result<Value, String> {
    let mut hosts = manifest
        .get("hosts")
        .and_then(Value::as_array)
        .ok_or("manifest hosts must be an array")?
        .iter()
        .map(|host| {
            if !host.is_object() {
                return Err("manifest host must be an object".to_owned());
            }
            Ok(select_fields(
                host,
                &[
                    "id",
                    "kind",
                    "image",
                    "istio_release",
                    "envoy_version",
                    "proxy_image_digest",
                ],
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    hosts.sort_by_key(|host| host.get("id").and_then(Value::as_str).unwrap_or_default().to_owned());

    let mut manifest_cases = manifest
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("manifest cases must be an array")?
        .clone();
    for case in &mut manifest_cases {
        *case = select_fields(case, &["id", "reference", "hosts", "required_outcome_fields"]);
    }
    manifest_cases.sort_by_key(|case| case.get("id").and_then(Value::as_str).unwrap_or_default().to_owned());

    let mut fixture_cases = cases
        .as_array()
        .ok_or_else(|| format!("{CASES} must be a JSON array"))?
        .iter()
        .map(fixture_semantics)
        .collect::<Vec<_>>();
    fixture_cases.sort_by_key(|case| case.get("id").and_then(Value::as_str).unwrap_or_default().to_owned());

    let deferred_inventory = manifest
        .get("deferred_inventory")
        .and_then(Value::as_array)
        .ok_or("manifest deferred_inventory must be an array")?
        .iter()
        .map(|item| {
            item.get("id")
                .cloned()
                .ok_or_else(|| "deferred inventory item must include id".to_owned())
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut deferred_inventory = deferred_inventory;
    deferred_inventory.sort_by_key(|id| id.as_str().unwrap_or_default().to_owned());

    Ok(serde_json::json!({
        "schema_version": manifest.get("schema_version"),
        "pins": manifest.get("pins"),
        "observed_checkouts": manifest.get("observed_checkouts"),
        "hosts": hosts,
        "cases": manifest_cases,
        "inventory": manifest.get("inventory"),
        "inventory_coverage": manifest.get("inventory_coverage"),
        "deferred_inventory": deferred_inventory,
        "fixtures": fixture_cases,
    }))
}

fn fixture_semantics(case: &Value) -> Value {
    select_fields(
        case,
        &[
            "id",
            "plugin_configuration",
            "request",
            "reload_plugin_configuration",
            "host_scenarios",
            "host_faults",
            "backend_response",
            "topics",
        ],
    )
}

fn select_fields(value: &Value, fields: &[&str]) -> Value {
    let Some(object) = value.as_object() else {
        return value.clone();
    };
    let mut selected = serde_json::Map::new();
    for field in fields {
        if let Some(value) = object.get(*field) {
            selected.insert((*field).to_owned(), value.clone());
        }
    }
    Value::Object(selected)
}

fn fixture_sha256(case: &Value) -> Result<String, String> {
    let bytes = serde_json::to_vec(&fixture_semantics(case)).map_err(|error| error.to_string())?;
    let mut digest = Sha256::new();
    digest.update(bytes);
    Ok(digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect())
}

fn fixture_sha256s(cases: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let cases = parse_strict_json(cases, CASES)?;
    let cases = cases
        .as_array()
        .ok_or_else(|| format!("{CASES} must be a JSON array"))?;
    cases
        .iter()
        .map(|case| {
            let id = string_field(case, "id")?.to_owned();
            Ok((id, fixture_sha256(case)?))
        })
        .collect()
}

fn required_observations(case: &Value) -> Result<Vec<RequiredObservation>, String> {
    case.get("required_outcome_fields")
        .and_then(Value::as_array)
        .ok_or("required_outcome_fields must be an array")?
        .iter()
        .map(|field| {
            let path = string_field(field, "path")?.to_owned();
            if !valid_observation_path(&path) {
                return Err(format!("invalid required outcome path {path}"));
            }
            let value_type = match string_field(field, "type")? {
                "string" => ObservationType::String,
                "optional_string" => ObservationType::OptionalString,
                "boolean" => ObservationType::Boolean,
                "nonnegative_integer" => ObservationType::NonNegativeInteger,
                "http_status" => ObservationType::HttpStatus,
                "array" => ObservationType::Array,
                "object" => ObservationType::Object,
                "header_pairs" => ObservationType::HeaderPairs,
                "optional_header_pairs" => ObservationType::OptionalHeaderPairs,
                "rule_matches" => ObservationType::RuleMatches,
                other => return Err(format!("unknown required outcome type {other}")),
            };
            Ok(RequiredObservation { path, value_type })
        })
        .collect()
}

fn parse_manifest(value: &Value) -> Result<ContractManifest, String> {
    let hosts = value
        .get("hosts")
        .and_then(Value::as_array)
        .ok_or("manifest hosts must be an array")?
        .iter()
        .map(|host| {
            Ok(Host {
                id: string_field(host, "id")?.to_owned(),
                pinned: host_has_immutable_digest(host),
            })
        })
        .collect::<Result<_, String>>()?;
    let cases = value
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("manifest cases must be an array")?
        .iter()
        .map(|case| {
            let id = string_field(case, "id")?.to_owned();
            // Line breaks would make the newline-joined case-ID set digest ambiguous.
            if id.contains('\n') || id.contains('\r') {
                return Err(format!("case ID {id:?} must not contain line breaks"));
            }
            let hosts = case
                .get("hosts")
                .and_then(Value::as_array)
                .ok_or("case hosts must be an array")?
                .iter()
                .map(|host| host.as_str().map(str::to_owned).ok_or("case host must be a string"))
                .collect::<Result<_, _>>()?;
            Ok(CaseRef {
                id,
                reference: string_field(case, "reference")?.to_owned(),
                hosts,
                required_outcome_fields: required_observations(case)?,
            })
        })
        .collect::<Result<_, String>>()?;
    let deferred_inventory = value
        .get("deferred_inventory")
        .and_then(Value::as_array)
        .ok_or("manifest deferred_inventory must be an array")?
        .iter()
        .map(|item| {
            let id = string_field(item, "id")?.to_owned();
            let reason = string_field(item, "reason")?.to_owned();
            if id.is_empty() || reason.trim().is_empty() {
                return Err("deferred inventory items need a non-empty id and reason".to_owned());
            }
            if contains_digest_delimiter(&id) {
                return Err(format!(
                    "deferred inventory ID {id:?} must not contain line breaks or unit separators"
                ));
            }
            Ok(id)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let deferred_ids: BTreeSet<_> = deferred_inventory.iter().map(String::as_str).collect();
    if deferred_ids.len() != deferred_inventory.len() {
        return Err("deferred inventory IDs must be unique".to_owned());
    }
    if let Some(missing) = REQUIRED_DEFERRED_INVENTORY
        .iter()
        .find(|required| !deferred_ids.contains(**required))
    {
        return Err(format!("manifest deferred_inventory is missing {missing}"));
    }
    let actual_deferred_digest = sorted_newline_digest(deferred_ids.iter().map(|id| (*id).to_owned()));
    if actual_deferred_digest != DEFERRED_INVENTORY_SET_SHA256 {
        return Err(format!(
            "deferred inventory set changed: expected digest {DEFERRED_INVENTORY_SET_SHA256}, got {actual_deferred_digest}; update DEFERRED_INVENTORY_SET_SHA256 in xtask/src/envoy_contract.rs deliberately in review after adding or removing a deferred item"
        ));
    }
    let pins = value.get("pins").ok_or("manifest pins are required")?;
    Ok(ContractManifest {
        schema_version: u32_field(value, "schema_version")?,
        contract_sha256: string_field(value, "contract_sha256")?.to_owned(),
        hosts,
        cases,
        inventory_coverage: parse_inventory_coverage(value)?,
        deferred_inventory,
        pins: Pins {
            upstream_connector: string_field(pins, "upstream_connector")?.to_owned(),
            pr20_head: string_field(pins, "pr20_head")?.to_owned(),
        },
    })
}

fn host_has_immutable_digest(host: &Value) -> bool {
    let pinned_image = host
        .get("image")
        .and_then(Value::as_str)
        .and_then(|image| image.rsplit_once("@sha256:").map(|(_, digest)| digest))
        .is_some_and(is_sha256);
    let pinned_proxy = host
        .get("proxy_image_digest")
        .and_then(Value::as_str)
        .and_then(|digest| digest.strip_prefix("sha256:").or(Some(digest)))
        .is_some_and(is_sha256);
    pinned_image || pinned_proxy
}

fn parse_inventory_coverage(value: &Value) -> Result<BTreeMap<String, Vec<String>>, String> {
    let inventory = value
        .get("inventory")
        .and_then(Value::as_object)
        .ok_or("manifest inventory must be an object")?;
    if let Some(category) = inventory.keys().find(|category| contains_digest_delimiter(category)) {
        return Err(format!(
            "inventory category {category:?} must not contain line breaks or unit separators"
        ));
    }
    let categories: BTreeSet<_> = inventory.keys().map(String::as_str).collect();
    let required_categories: BTreeSet<_> = REQUIRED_INVENTORY_CATEGORIES.iter().copied().collect();
    if let Some(missing) = required_categories.difference(&categories).next() {
        return Err(format!(
            "inventory category {missing} is missing; update REQUIRED_INVENTORY_CATEGORIES in xtask/src/envoy_contract.rs deliberately in review if the inventory is changing"
        ));
    }
    if let Some(extra) = categories.difference(&required_categories).next() {
        return Err(format!(
            "inventory category {extra} is not in the required category set; update REQUIRED_INVENTORY_CATEGORIES in xtask/src/envoy_contract.rs deliberately in review if the inventory is changing"
        ));
    }
    let mut claims = BTreeSet::new();
    let mut claim_pairs = BTreeSet::new();
    for (category, values) in inventory {
        let values = values
            .as_array()
            .ok_or_else(|| format!("inventory {category} must be an array"))?;
        let mut seen_in_category = BTreeSet::new();
        for item in values {
            let claim = item
                .as_str()
                .ok_or_else(|| format!("inventory {category} entries must be strings"))?;
            if claim.is_empty() {
                return Err(format!("inventory {category} entries must not be empty"));
            }
            if contains_digest_delimiter(claim) {
                return Err(format!(
                    "inventory claim {claim:?} must not contain line breaks or unit separators"
                ));
            }
            if !seen_in_category.insert(claim.to_owned()) {
                return Err(format!("inventory {category} repeats claim {claim}"));
            }
            claims.insert(claim.to_owned());
            claim_pairs.insert((category.to_owned(), claim.to_owned()));
        }
    }
    let actual_claim_set_digest = sorted_newline_digest(
        claim_pairs
            .iter()
            .map(|(category, claim)| format!("{category}\x1f{claim}")),
    );
    if actual_claim_set_digest != INVENTORY_CLAIM_SET_SHA256 {
        return Err(format!(
            "inventory claim set changed: expected digest {INVENTORY_CLAIM_SET_SHA256}, got {actual_claim_set_digest}; update INVENTORY_CLAIM_SET_SHA256 in xtask/src/envoy_contract.rs deliberately in review after adding, removing, or moving an inventory claim"
        ));
    }

    let coverage = value
        .get("inventory_coverage")
        .and_then(Value::as_object)
        .ok_or("manifest inventory_coverage must be an object")?;
    let mut result = BTreeMap::new();
    let mut topics = BTreeSet::new();
    for (claim, values) in coverage {
        let claim_topics = values
            .as_array()
            .ok_or_else(|| format!("inventory_coverage {claim} must be an array"))?
            .iter()
            .map(|topic| {
                topic
                    .as_str()
                    .filter(|topic| !topic.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| format!("inventory_coverage {claim} topics must be non-empty strings"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if claim_topics.is_empty() {
            return Err(format!("inventory_coverage {claim} must name at least one topic"));
        }
        topics.extend(claim_topics.iter().cloned());
        result.insert(claim.clone(), claim_topics);
    }
    let mapped_claims: BTreeSet<_> = result.keys().cloned().collect();
    if claims != mapped_claims {
        let unmapped: Vec<_> = claims.difference(&mapped_claims).cloned().collect();
        let unknown: Vec<_> = mapped_claims.difference(&claims).cloned().collect();
        return Err(format!(
            "inventory_coverage must map every inventory claim exactly; unmapped={unmapped:?}, unknown={unknown:?}"
        ));
    }
    if topics.is_empty() {
        return Err("inventory_coverage must include at least one topic".to_owned());
    }
    Ok(result)
}

fn directive_strings(value: Option<&Value>) -> Vec<&str> {
    match value {
        Some(Value::String(directive)) => directive_lines(directive).collect(),
        Some(Value::Array(directives)) if directives.iter().all(Value::is_string) => directives
            .iter()
            .filter_map(Value::as_str)
            .flat_map(directive_lines)
            .collect(),
        _ => Vec::new(),
    }
}

fn directive_lines(directive: &str) -> impl Iterator<Item = &str> {
    directive
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

fn validate_directive_arrays(case: &FixtureCase) -> Result<(), String> {
    for (name, configuration) in std::iter::once(("plugin_configuration", Some(&case.plugin_configuration))).chain(
        std::iter::once(("reload_plugin_configuration", case.reload_plugin_configuration.as_ref())),
    ) {
        let Some(configuration) = configuration else {
            continue;
        };
        if let Some(directives) = configuration.get("rules").and_then(Value::as_array)
            && let Some(index) = directives.iter().position(|directive| !directive.is_string())
        {
            return Err(format!(
                "fixture case {} {name} rules[{index}] must be a string",
                case.id
            ));
        }
    }
    Ok(())
}

fn configuration_policy_directives<'a>(configuration: &'a Value, policy: &str) -> Vec<&'a str> {
    if !policy_selectors_well_formed(configuration) {
        return Vec::new();
    }
    if let Some(policies) = configuration
        .get("directives_map")
        .and_then(Value::as_object)
        .filter(|policies| !policies.is_empty())
    {
        return directive_strings(policies.get(policy));
    }
    if policy == "default" {
        directive_strings(configuration.get("rules"))
    } else {
        Vec::new()
    }
}

fn policy_directives<'a>(case: &'a FixtureCase, policy: &str) -> Vec<&'a str> {
    configuration_policy_directives(&case.plugin_configuration, policy)
}

fn default_policy_name_in(configuration: &Value) -> Option<&str> {
    if !policy_selectors_well_formed(configuration) {
        return None;
    }
    let has_directives_map = configuration
        .get("directives_map")
        .and_then(Value::as_object)
        .is_some_and(|policies| !policies.is_empty());
    if has_directives_map {
        configuration.get("default_directives").and_then(Value::as_str)
    } else if configuration.get("rules").is_some() {
        Some("default")
    } else {
        None
    }
}

fn default_policy_name(case: &FixtureCase) -> Option<&str> {
    default_policy_name_in(&case.plugin_configuration)
}

fn default_policy_directives(case: &FixtureCase) -> Vec<&str> {
    default_policy_name(case).map_or_else(Vec::new, |policy| policy_directives(case, policy))
}

fn request_policy_name_in<'a>(case: &FixtureCase, configuration: &'a Value) -> Option<&'a str> {
    if !policy_selectors_well_formed(configuration) {
        return None;
    }
    let authority = request_string(case, "authority").or_else(|| request_string(case, "host"));
    let authorities = configuration.get("per_authority_directives").and_then(Value::as_object);
    let authority_policy = authority.and_then(|authority| authorities?.get(authority)?.as_str());
    if authority.is_some_and(|authority| authorities.is_some_and(|map| map.contains_key(authority)))
        && authority_policy.is_none()
    {
        return None;
    }
    authority_policy.or_else(|| default_policy_name_in(configuration))
}

fn request_policy_name(case: &FixtureCase) -> Option<&str> {
    request_policy_name_in(case, &case.plugin_configuration)
}

fn request_policy_directives(case: &FixtureCase) -> Vec<&str> {
    request_policy_name(case).map_or_else(Vec::new, |policy| policy_directives(case, policy))
}

fn request_policy_directives_in<'a>(case: &FixtureCase, configuration: &'a Value) -> Vec<&'a str> {
    request_policy_name_in(case, configuration).map_or_else(Vec::new, |policy| {
        configuration_policy_directives(configuration, policy)
    })
}

fn includes_file(case: &FixtureCase, file: &str) -> bool {
    default_policy_directives(case)
        .iter()
        .any(|directive| directive.strip_prefix("Include ") == Some(file))
}

fn request_string<'a>(case: &'a FixtureCase, field: &str) -> Option<&'a str> {
    case.request.as_ref()?.get(field)?.as_str()
}

fn request_has_header(case: &FixtureCase, name: &str, value: &str) -> bool {
    case.request
        .as_ref()
        .and_then(|request| request.get("headers"))
        .is_some_and(|headers| has_pair(Some(headers), name, value))
}

fn has_pair(value: Option<&Value>, name: &str, expected: &str) -> bool {
    value.and_then(Value::as_array).is_some_and(|pairs| {
        pairs.iter().any(|pair| {
            pair.as_array().is_some_and(|pair| {
                pair.len() == 2
                    && pair.first().and_then(Value::as_str) == Some(name)
                    && pair.get(1).and_then(Value::as_str) == Some(expected)
            })
        })
    })
}

fn has_ordered_pairs(value: Option<&Value>, expected: &[(&str, &str)]) -> bool {
    value.and_then(Value::as_array).is_some_and(|pairs| {
        pairs.len() == expected.len()
            && pairs.iter().zip(expected).all(|(pair, (name, value))| {
                pair.as_array().is_some_and(|pair| {
                    pair.len() == 2
                        && pair.first().and_then(Value::as_str) == Some(*name)
                        && pair.get(1).and_then(Value::as_str) == Some(*value)
                })
            })
    })
}

fn has_scenario(case: &FixtureCase, scenario: &str) -> bool {
    case.host_scenarios.iter().any(|item| item == scenario)
}

fn take_quoted(value: &str) -> Option<(&str, &str)> {
    let value = value.trim_start();
    if !value.starts_with('"') {
        return None;
    }
    let mut escaped = false;
    for (index, character) in value.char_indices().skip(1) {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some((value.get(1..index)?, value.get(index + 1..)?));
        }
    }
    None
}

// shortcut: only the fixture's quoted SecRule form is parsed; use a SecLang parser if chain probes add other syntax.
fn parse_sec_rule(directive: &str) -> Option<(&str, &str, &str, &str)> {
    let rest = directive.strip_prefix("SecRule ")?;
    let variable_end = rest.find(char::is_whitespace)?;
    let variable = rest.get(..variable_end)?;
    let (operator_and_operand, rest) = take_quoted(rest.get(variable_end..)?)?;
    let operand_start = operator_and_operand.find(char::is_whitespace)?;
    let operator = operator_and_operand.get(..operand_start)?;
    let operand = operator_and_operand.get(operand_start..)?.trim();
    if operand.is_empty() {
        return None;
    }
    let (actions, trailing) = take_quoted(rest)?;
    if !trailing.trim().is_empty() {
        return None;
    }
    Some((variable, operator, operand, actions))
}

fn for_each_action<'a>(actions: &'a str, mut visit: impl FnMut(&'a str)) -> Result<(), ()> {
    let mut start = 0;
    let mut single_quoted = false;
    let mut escaped = false;
    for (index, character) in actions.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '\'' {
            single_quoted = !single_quoted;
        } else if character == ',' && !single_quoted {
            if let Some(action) = actions.get(start..index) {
                visit(action.trim());
            }
            start = index + 1;
        }
    }
    if single_quoted || escaped {
        return Err(());
    }
    if let Some(action) = actions.get(start..) {
        visit(action.trim());
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EffectiveDisruptiveAction {
    Allow,
    Deny,
    Drop,
    Pass,
    Redirect,
    Block,
}

fn is_disruptive_action_name(name: &str) -> bool {
    ["allow", "deny", "drop", "pass", "redirect", "block"]
        .iter()
        .any(|action| name.eq_ignore_ascii_case(action))
}

fn effective_disruptive_action(actions: &str) -> Result<Option<EffectiveDisruptiveAction>, ()> {
    let mut effective = None;
    let mut unsupported = false;
    for_each_action(actions, |action| {
        let (name, argument) = action.split_once(':').unwrap_or((action, ""));
        let name = name.trim();
        let name_lower = name.to_ascii_lowercase();
        let disruptive = match name_lower.as_str() {
            "allow" => Some(EffectiveDisruptiveAction::Allow),
            "deny" => Some(EffectiveDisruptiveAction::Deny),
            "drop" => Some(EffectiveDisruptiveAction::Drop),
            "pass" => Some(EffectiveDisruptiveAction::Pass),
            "redirect" => Some(EffectiveDisruptiveAction::Redirect),
            "block" => Some(EffectiveDisruptiveAction::Block),
            _ => None,
        };
        if let Some(disruptive) = disruptive {
            let argument = unquote_action_argument(argument);
            let valid = match disruptive {
                EffectiveDisruptiveAction::Allow => matches!(argument, "" | "phase" | "request"),
                EffectiveDisruptiveAction::Redirect => !argument.is_empty(),
                EffectiveDisruptiveAction::Deny
                | EffectiveDisruptiveAction::Drop
                | EffectiveDisruptiveAction::Pass
                | EffectiveDisruptiveAction::Block => argument.is_empty(),
            };
            if valid {
                effective = Some(disruptive);
            } else {
                unsupported = true;
            }
            return;
        }
        if !matches!(
            name_lower.as_str(),
            "id" | "msg"
                | "tag"
                | "severity"
                | "rev"
                | "ver"
                | "maturity"
                | "accuracy"
                | "phase"
                | "log"
                | "nolog"
                | "auditlog"
                | "noauditlog"
                | "logdata"
                | "capture"
                | "multimatch"
                | "status"
                | "t"
                | "chain"
                | "exec"
                | "expirevar"
                | "initcol"
                | "skip"
                | "skipafter"
                | "setvar"
                | "ctl"
                | "setenv"
        ) {
            unsupported = true;
        }
    })?;
    if unsupported { Err(()) } else { Ok(effective) }
}

fn unquote_action_argument(argument: &str) -> &str {
    let argument = argument.trim();
    argument
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
        .or_else(|| argument.strip_prefix('"').and_then(|value| value.strip_suffix('"')))
        .unwrap_or(argument)
}

fn action_list_contains(actions: &str, expected: &str) -> bool {
    if is_disruptive_action_name(expected) {
        return effective_disruptive_action(actions).is_ok_and(|effective| {
            disruptive_action_name(effective).is_some_and(|name| name.eq_ignore_ascii_case(expected))
        });
    }
    let (expected_name, expected_value) = expected.split_once(':').unwrap_or((expected, ""));
    if expected_name.eq_ignore_ascii_case("phase") {
        let Some(expected_phase) = parse_phase(expected_value) else {
            return false;
        };
        let (phase, malformed) = effective_directive_phase_from_actions(actions);
        return !malformed && phase == Some(expected_phase);
    }
    let mut found = false;
    if for_each_action(actions, |action| {
        let (name, value) = action.split_once(':').unwrap_or((action, ""));
        found |= name.trim().eq_ignore_ascii_case(expected_name.trim()) && value.trim() == expected_value.trim();
    })
    .is_err()
    {
        return false;
    }
    found
}

fn disruptive_action_name(action: Option<EffectiveDisruptiveAction>) -> Option<&'static str> {
    match action? {
        EffectiveDisruptiveAction::Allow => Some("allow"),
        EffectiveDisruptiveAction::Deny => Some("deny"),
        EffectiveDisruptiveAction::Drop => Some("drop"),
        EffectiveDisruptiveAction::Pass => Some("pass"),
        EffectiveDisruptiveAction::Redirect => Some("redirect"),
        EffectiveDisruptiveAction::Block => Some("block"),
    }
}

fn sec_rule_matches_operator(
    directive: &str,
    variable: &str,
    expected_operator: &str,
    operand: &str,
    required_actions: &[&str],
) -> bool {
    parse_sec_rule(directive).is_some_and(|(actual_variable, operator, actual_operand, actions)| {
        actual_variable == variable
            && operator == expected_operator
            && actual_operand == operand
            && required_actions
                .iter()
                .all(|action| action_list_contains(actions, action))
    })
}

fn sec_rule_matches(directive: &str, variable: &str, operand: &str, required_actions: &[&str]) -> bool {
    sec_rule_matches_operator(directive, variable, "@streq", operand, required_actions)
}

fn directive_actions(directive: &str) -> Option<&str> {
    parse_sec_rule(directive).map(|(_, _, _, actions)| actions).or_else(|| {
        let rest = directive.strip_prefix("SecAction ")?;
        let (actions, trailing) = take_quoted(rest)?;
        trailing.trim().is_empty().then_some(actions)
    })
}

fn parse_phase(phase_text: &str) -> Option<u8> {
    let phase_text = phase_text.trim();
    let phase_text = phase_text
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
        .or_else(|| phase_text.strip_prefix('"').and_then(|value| value.strip_suffix('"')))
        .unwrap_or(phase_text);
    match phase_text {
        "request" => Some(2),
        "response" => Some(4),
        "logging" => Some(5),
        _ => phase_text.parse::<u8>().ok().filter(|phase| (1..=5).contains(phase)),
    }
}

fn effective_directive_phase_from_actions(actions: &str) -> (Option<u8>, bool) {
    let mut effective_phase = None;
    let mut malformed_phase = false;
    if for_each_action(actions, |action| {
        let (key, value) = action.split_once(':').unwrap_or((action, ""));
        if key.trim().eq_ignore_ascii_case("phase") {
            let value = parse_phase(value);
            if let Some(value) = value {
                effective_phase = Some(value);
            } else {
                malformed_phase = true;
            }
        }
    })
    .is_err()
    {
        return (None, true);
    }
    (effective_phase, malformed_phase)
}

fn effective_directive_phase(directive: &str) -> Option<(Option<u8>, bool)> {
    Some(effective_directive_phase_from_actions(directive_actions(directive)?))
}

fn directive_is_request_phase(directive: &str) -> bool {
    let Some((phase, malformed_phase)) = effective_directive_phase(directive) else {
        return false;
    };
    malformed_phase || phase.is_none_or(|phase| phase <= 2)
}

fn directive_is_phase_one(directive: &str) -> bool {
    effective_directive_phase(directive).is_some_and(|(phase, malformed_phase)| !malformed_phase && phase == Some(1))
}

fn actions_are_exact(actions: &str, expected: &[&str]) -> bool {
    let mut actual = Vec::new();
    for_each_action(actions, |action| actual.push(action)).is_ok()
        && actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            if let (Some((actual_name, actual_value)), Some((expected_name, expected_value))) =
                (actual.split_once(':'), expected.split_once(':'))
                && actual_name.trim().eq_ignore_ascii_case("phase")
                && expected_name.trim().eq_ignore_ascii_case("phase")
            {
                matches!((parse_phase(actual_value), parse_phase(expected_value)), (Some(a), Some(b)) if a == b)
            } else {
                *actual == *expected
            }
        })
}

fn sec_rule_has_exact_actions(directive: &str, expected: &[&str]) -> bool {
    parse_sec_rule(directive).is_some_and(|(_, _, _, actions)| actions_are_exact(actions, expected))
}

fn sec_action_has_exact_actions(directive: &str, expected: &[&str]) -> bool {
    let Some(rest) = directive.strip_prefix("SecAction ") else {
        return false;
    };
    let Some((actions, trailing)) = take_quoted(rest) else {
        return false;
    };
    trailing.trim().is_empty() && actions_are_exact(actions, expected)
}

fn policy_has_engine(case: &FixtureCase, policy: &str, engine: &str) -> bool {
    policy_has_engine_in(&case.plugin_configuration, policy, engine)
}

fn policy_has_engine_in(configuration: &Value, policy: &str, engine: &str) -> bool {
    let mut effective = None;
    for directive in configuration_policy_directives(configuration, policy) {
        if !directive_is_named(directive, "SecRuleEngine") {
            continue;
        }
        let mut parts = directive.split_whitespace();
        let _ = parts.next();
        let Some(value) = parts.next() else {
            return false;
        };
        if parts.next().is_some() {
            return false;
        }
        effective = if value.eq_ignore_ascii_case("On") {
            Some("On")
        } else if value.eq_ignore_ascii_case("Off") {
            Some("Off")
        } else if value.eq_ignore_ascii_case("DetectionOnly") {
            Some("DetectionOnly")
        } else {
            return false;
        };
    }
    effective.is_some_and(|effective| effective.eq_ignore_ascii_case(engine))
}

fn request_policy_has_engine(case: &FixtureCase, engine: &str) -> bool {
    request_policy_name(case).is_some_and(|policy| policy_has_engine(case, policy, engine))
}

fn request_policy_has_engine_in(case: &FixtureCase, configuration: &Value, engine: &str) -> bool {
    request_policy_name_in(case, configuration)
        .is_some_and(|policy| policy_has_engine_in(configuration, policy, engine))
}

fn policy_has_rule(case: &FixtureCase, policy: &str, variable: &str, operand: &str, required_actions: &[&str]) -> bool {
    policy_directives(case, policy)
        .iter()
        .any(|directive| sec_rule_matches(directive, variable, operand, required_actions))
}

fn request_policy_has_rule(
    case: &FixtureCase,
    variable: &str,
    operator: &str,
    operand: &str,
    required_actions: &[&str],
) -> bool {
    request_policy_name(case).is_some_and(|policy| {
        policy_directives(case, policy)
            .iter()
            .any(|directive| sec_rule_matches_operator(directive, variable, operator, operand, required_actions))
    })
}

fn request_policy_has_exact_rule(
    case: &FixtureCase,
    variable: &str,
    operator: &str,
    operand: &str,
    actions: &[&str],
) -> bool {
    let directives = request_policy_directives(case);
    matches!(directives.as_slice(), [_, rule]
        if sec_rule_matches_operator(rule, variable, operator, operand, actions)
            && sec_rule_has_exact_actions(rule, actions))
}

fn request_has_identity(case: &FixtureCase, method: &str, path: &str) -> bool {
    request_string(case, "method") == Some(method) && request_string(case, "path") == Some(path)
}

fn backend_response_has(case: &FixtureCase, status: u64, body: &str) -> bool {
    case.backend_response.as_ref().is_some_and(|response| {
        response.get("status").and_then(Value::as_u64) == Some(status)
            && response.get("body_base64").and_then(Value::as_str) == Some(body)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestRuleMatch {
    Match,
    NoMatch,
    Unsupported,
}

fn request_matches_rule(case: &FixtureCase, directive: &str) -> RequestRuleMatch {
    let Some((variable, operator, operand, actions)) = parse_sec_rule(directive) else {
        let Some(actions) = directive_actions(directive) else {
            return RequestRuleMatch::Unsupported;
        };
        return if lifecycle_actions_are_unsupported(actions) {
            RequestRuleMatch::Unsupported
        } else if directive_is_named(directive, "SecAction") {
            RequestRuleMatch::Match
        } else {
            RequestRuleMatch::Unsupported
        };
    };
    if lifecycle_actions_are_unsupported(actions) || effective_directive_phase_from_actions(actions).1 {
        return RequestRuleMatch::Unsupported;
    }
    let matches = match (variable, operator) {
        ("REQUEST_URI", "@streq") => match request_string(case, "path") {
            Some(path) => path == operand,
            None => return RequestRuleMatch::Unsupported,
        },
        ("REQUEST_METHOD", "@streq") => match request_string(case, "method") {
            Some(method) => method == operand,
            None => return RequestRuleMatch::Unsupported,
        },
        ("ARGS", "@streq") => match request_has_form_argument(case, operand) {
            Some(matches) => matches,
            None => return RequestRuleMatch::Unsupported,
        },
        _ => return RequestRuleMatch::Unsupported,
    };
    if matches {
        RequestRuleMatch::Match
    } else {
        RequestRuleMatch::NoMatch
    }
}

fn request_has_form_argument(case: &FixtureCase, value: &str) -> Option<bool> {
    // shortcut: only checked-in form bodies are recognized; add decoding if fixture inputs expand.
    let request = case.request.as_ref()?;
    let headers = request.get("headers")?.as_array()?;
    if headers.iter().any(|header| {
        !header
            .as_array()
            .is_some_and(|pair| pair.len() == 2 && pair.iter().all(|part| part.as_str().is_some()))
    }) {
        return None;
    }
    let content_types: Vec<_> = headers
        .iter()
        .filter_map(|header| {
            let pair = header.as_array()?;
            (pair.first()?.as_str()? == "content-type").then(|| pair.get(1)?.as_str())?
        })
        .collect();
    if content_types.as_slice() != ["application/x-www-form-urlencoded"] {
        return None;
    }
    match request.get("body_base64")?.as_str()? {
        "Y21kPWF0dGFj" | "Y21kPWF0dGFja3g=" => Some(false),
        "Y21kPWF0dGFjaw==" | "dGVybT1hdHRhY2s=" => Some(value == "attack"),
        _ => None,
    }
}

fn directive_is_named(directive: &str, name: &str) -> bool {
    directive
        .split_whitespace()
        .next()
        .is_some_and(|directive_name| directive_name.eq_ignore_ascii_case(name))
}

fn has_sec_lang_continuation(directive: &str) -> bool {
    directive.lines().any(|line| line.trim_end().ends_with('\\'))
}

fn is_rule_mutation(directive: &str) -> bool {
    directive.split_whitespace().next().is_some_and(|name| {
        let name = name.to_ascii_lowercase();
        name.starts_with("secruleupdate") || name.starts_with("secruleremove")
    })
}

fn lifecycle_actions_are_unsupported(actions: &str) -> bool {
    let Ok(effective_action) = effective_disruptive_action(actions) else {
        return true;
    };
    if effective_action == Some(EffectiveDisruptiveAction::Block) {
        return true;
    }
    let mut unsupported = false;
    if for_each_action(actions, |action| {
        let name = action.split_once(':').map_or(action, |(name, _)| name).trim();
        unsupported |= ["skip", "skipafter", "ctl", "t", "chain"]
            .iter()
            .any(|unsupported| name.eq_ignore_ascii_case(unsupported));
    })
    .is_err()
    {
        return true;
    }
    unsupported
}

fn has_unsupported_lifecycle_directive(directives: &[&str]) -> bool {
    directives.iter().any(|directive| {
        if has_sec_lang_continuation(directive)
            || is_rule_mutation(directive)
            || directive_is_named(directive, "SecDefaultAction")
            || directive_is_named(directive, "Include")
        {
            return true;
        }
        if directive_is_named(directive, "SecRule") || directive_is_named(directive, "SecAction") {
            return directive_actions(directive).is_none_or(lifecycle_actions_are_unsupported)
                || effective_directive_phase(directive).is_some_and(|(_, malformed)| malformed);
        }
        !directive_is_named(directive, "SecRuleEngine")
    })
}

fn lifecycle_directives_supported(case: &FixtureCase, directives: &[&str]) -> bool {
    if has_unsupported_lifecycle_directive(directives)
        || directives
            .iter()
            .filter(|directive| directive_is_named(directive, "SecRule") || directive_is_named(directive, "SecAction"))
            .any(|directive| request_matches_rule(case, directive) == RequestRuleMatch::Unsupported)
    {
        return false;
    }
    let rule_indexes: Vec<_> = directives
        .iter()
        .enumerate()
        .filter(|(_, directive)| directive_is_named(directive, "SecRule") || directive_is_named(directive, "SecAction"))
        .map(|(index, _)| index)
        .collect();
    directives.iter().enumerate().all(|(index, directive)| {
        let is_effective_allow = directive_actions(directive)
            .is_some_and(|actions| effective_disruptive_action(actions) == Ok(Some(EffectiveDisruptiveAction::Allow)));
        !is_effective_allow
            || (directive_is_request_phase(directive) && rule_indexes.last().is_some_and(|last| index == *last))
    })
}

fn lifecycle_probe_supported(case: &FixtureCase) -> bool {
    policy_selectors_well_formed(&case.plugin_configuration)
        && lifecycle_directives_supported(case, &request_policy_directives(case))
}

fn directive_collection_well_formed(value: &Value) -> bool {
    value.is_string() || value.as_array().is_some_and(|items| items.iter().all(Value::is_string))
}

fn policy_selectors_well_formed(configuration: &Value) -> bool {
    let policies = match configuration.get("directives_map") {
        None => None,
        Some(Value::Object(policies))
            if policies
                .iter()
                .all(|(name, directives)| !name.is_empty() && directive_collection_well_formed(directives)) =>
        {
            Some(policies)
        },
        Some(_) => return false,
    };
    let legacy_rules_valid = configuration.get("rules").is_none_or(directive_collection_well_formed);
    if !legacy_rules_valid
        || configuration
            .get("default_directives")
            .is_some_and(|value| value.as_str().is_none_or(str::is_empty))
    {
        return false;
    }
    if let Some(default) = configuration.get("default_directives").and_then(Value::as_str) {
        let legacy_policy_exists = configuration.get("rules").is_some_and(directive_collection_well_formed);
        let default_exists = match policies {
            Some(policies) if !policies.is_empty() => policies.contains_key(default),
            _ => legacy_policy_exists && default == "default",
        };
        if !default_exists {
            return false;
        }
    }
    let authorities = match configuration.get("per_authority_directives") {
        None => return true,
        Some(Value::Object(authorities)) => authorities,
        Some(_) => return false,
    };
    let has_legacy_default = policies.is_none_or(serde_json::Map::is_empty)
        && configuration.get("rules").is_some_and(directive_collection_well_formed);
    authorities.iter().all(|(authority, policy)| {
        let Some(policy) = policy.as_str().filter(|policy| !policy.is_empty()) else {
            return false;
        };
        !authority.is_empty() && policies.is_some_and(|policies| policies.contains_key(policy))
            || !authority.is_empty() && has_legacy_default && policy == "default"
    })
}

fn request_has_matching_interruption(case: &FixtureCase, phase_one_only: bool) -> RequestRuleMatch {
    let mut unsupported = false;
    let directives = request_policy_directives(case);
    // shortcut: parser-dependent directives, mutations, chains, and continuations stay unsupported until modeled.
    if !lifecycle_probe_supported(case) {
        return RequestRuleMatch::Unsupported;
    }
    for directive in directives
        .into_iter()
        .filter(|directive| directive_is_named(directive, "SecRule") || directive_is_named(directive, "SecAction"))
    {
        let Some(actions) = directive_actions(directive) else {
            return RequestRuleMatch::Unsupported;
        };
        let Ok(action) = effective_disruptive_action(actions) else {
            return RequestRuleMatch::Unsupported;
        };
        let interrupts = matches!(
            action,
            Some(
                EffectiveDisruptiveAction::Deny | EffectiveDisruptiveAction::Drop | EffectiveDisruptiveAction::Redirect
            )
        );
        let in_scope = if phase_one_only {
            if directive_is_phase_one(directive) {
                true
            } else {
                if (interrupts || action == Some(EffectiveDisruptiveAction::Block))
                    && directive_is_request_phase(directive)
                {
                    unsupported = true;
                }
                false
            }
        } else {
            directive_is_request_phase(directive)
        };
        if !in_scope {
            continue;
        }
        if action == Some(EffectiveDisruptiveAction::Block) {
            unsupported = true;
            continue;
        }
        if !interrupts {
            continue;
        }
        match request_matches_rule(case, directive) {
            RequestRuleMatch::Match => return RequestRuleMatch::Match,
            RequestRuleMatch::NoMatch => {},
            RequestRuleMatch::Unsupported => unsupported = true,
        }
    }
    if unsupported {
        RequestRuleMatch::Unsupported
    } else {
        RequestRuleMatch::NoMatch
    }
}

fn request_has_phase_one_interruption(case: &FixtureCase) -> RequestRuleMatch {
    request_has_matching_interruption(case, true)
}

fn authority_policy_inputs_match(case: &FixtureCase) -> bool {
    policy_has_engine(case, "default", "On")
        && policy_has_rule(
            case,
            "default",
            "REQUEST_URI",
            "/authority-deny",
            &["id:1035", "phase:1", "deny", "status:403"],
        )
        && policy_has_engine(case, "other", "DetectionOnly")
        && policy_has_rule(
            case,
            "other",
            "REQUEST_URI",
            "/authority-deny",
            &["id:1036", "phase:1", "deny", "status:403"],
        )
}

fn directive_text_has_rule(directives: &str, variable: &str, operand: &str, required_actions: &[&str]) -> bool {
    directives
        .lines()
        .any(|line| sec_rule_matches(line, variable, operand, required_actions))
}

fn authority_policy_selection_topic(case: &FixtureCase, topic: &str) -> Option<bool> {
    let config = &case.plugin_configuration;
    let selected_authority = config
        .get("per_authority_directives")
        .and_then(|authorities| authorities.get("waf.example"))
        .and_then(Value::as_str)
        == Some("other");
    let has_default_deny = authority_policy_inputs_match(case);
    let result = match topic {
        "config.authority-host-fallback" => {
            request_string(case, "authority").is_none()
                && request_string(case, "host") == Some("waf.example")
                && request_has_identity(case, "GET", "/authority-deny")
                && selected_authority
                && request_policy_name(case) == Some("other")
                && request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
                && policy_has_engine(case, "default", "DetectionOnly")
                && policy_has_rule(
                    case,
                    "default",
                    "REQUEST_URI",
                    "/authority-deny",
                    &["id:1038", "phase:1", "deny", "status:403"],
                )
                && policy_has_engine(case, "other", "On")
                && policy_has_rule(
                    case,
                    "other",
                    "REQUEST_URI",
                    "/authority-deny",
                    &["id:1037", "phase:1", "deny", "status:403"],
                )
        },
        "config.authority" => {
            selected_authority
                && request_string(case, "authority") == Some("waf.example")
                && request_has_identity(case, "GET", "/authority-deny")
                && request_policy_name(case) == Some("other")
                && request_policy_has_engine(case, "DetectionOnly")
                && lifecycle_probe_supported(case)
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
                && has_default_deny
        },
        "config.authority-case" => {
            selected_authority
                && request_string(case, "authority") == Some("WAF.EXAMPLE")
                && request_has_identity(case, "GET", "/authority-deny")
                && request_policy_name(case) == Some("default")
                && request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
                && has_default_deny
        },
        "config.authority-port" => {
            selected_authority
                && request_string(case, "authority") == Some("waf.example:8443")
                && request_has_identity(case, "GET", "/authority-deny")
                && request_policy_name(case) == Some("default")
                && request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
                && has_default_deny
        },
        _ => return None,
    };
    Some(result)
}

fn policy_selection_topic(case: &FixtureCase, topic: &str) -> Option<bool> {
    let config = &case.plugin_configuration;
    let result = match topic {
        "config.configured-default" => {
            config.get("default_directives").and_then(Value::as_str) == Some("selected")
                && request_policy_name(case) == Some("selected")
                && request_policy_has_engine(case, "DetectionOnly")
                && lifecycle_probe_supported(case)
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
                && policy_has_engine(case, "selected", "DetectionOnly")
                && policy_has_rule(
                    case,
                    "selected",
                    "REQUEST_URI",
                    "/configured-default",
                    &["id:1050", "phase:1", "deny", "status:403"],
                )
                && policy_has_engine(case, "first", "On")
                && policy_has_rule(
                    case,
                    "first",
                    "REQUEST_URI",
                    "/configured-default",
                    &["id:1051", "phase:1", "deny", "status:403"],
                )
                && request_has_identity(case, "GET", "/configured-default")
        },
        "config.absent-default" => {
            config.get("default_directives").is_none()
                && request_policy_name(case).is_none()
                && policy_has_engine(case, "first", "On")
                && policy_has_rule(
                    case,
                    "first",
                    "REQUEST_URI",
                    "/absent-default",
                    &["id:1052", "phase:1", "deny", "status:403"],
                )
                && request_has_identity(case, "GET", "/absent-default")
        },
        _ => return None,
    };
    Some(result)
}

fn configuration_type_topic(case: &FixtureCase, topic: &str) -> Option<bool> {
    let config = &case.plugin_configuration;
    let result = match topic {
        "config.deprecated-rules" => {
            config.get("rules").is_some_and(Value::is_array)
                && config.get("default_directives").is_none()
                && config
                    .get("directives_map")
                    .and_then(Value::as_object)
                    .is_none_or(serde_json::Map::is_empty)
                && request_has_identity(case, "GET", "/deny")
                && request_policy_name(case) == Some("default")
                && request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
                && request_policy_has_exact_rule(
                    case,
                    "REQUEST_URI",
                    "@streq",
                    "/deny",
                    &["id:1001", "phase:1", "deny", "status:403"],
                )
        },
        "config.deprecated-rules-scalar" => {
            config.get("rules").and_then(Value::as_str).is_some_and(|rules| {
                directive_text_has_rule(
                    rules,
                    "REQUEST_URI",
                    "/scalar-rules",
                    &["id:1061", "phase:1", "deny", "status:403"],
                )
            }) && config.get("default_directives").is_none()
                && config
                    .get("directives_map")
                    .and_then(Value::as_object)
                    .is_none_or(serde_json::Map::is_empty)
                && default_policy_directives(case).iter().any(|rules| {
                    directive_text_has_rule(
                        rules,
                        "REQUEST_URI",
                        "/scalar-rules",
                        &["id:1061", "phase:1", "deny", "status:403"],
                    )
                })
                && request_has_identity(case, "GET", "/scalar-rules")
                && request_policy_name(case) == Some("default")
                && request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && request_policy_has_exact_rule(
                    case,
                    "REQUEST_URI",
                    "@streq",
                    "/scalar-rules",
                    &["id:1061", "phase:1", "deny", "status:403"],
                )
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
        },
        "config.directives-map-invalid-type" => config
            .get("directives_map")
            .is_some_and(|directives| !directives.is_object()),
        "config.directives-map-policy-scalar" => {
            config
                .get("directives_map")
                .and_then(Value::as_object)
                .and_then(|policies| policies.get("default"))
                .and_then(Value::as_str)
                .is_some_and(|directives| {
                    directive_text_has_rule(
                        directives,
                        "REQUEST_URI",
                        "/scalar-map",
                        &["id:1060", "phase:1", "deny", "status:403"],
                    )
                })
                && config.get("default_directives").and_then(Value::as_str) == Some("default")
                && config.get("rules").is_none()
                && request_has_identity(case, "GET", "/scalar-map")
                && request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
        },
        "config.default-directives-invalid-type" => {
            config.get("default_directives").is_some_and(Value::is_number)
                && config.get("rules").is_none()
                && config
                    .get("directives_map")
                    .and_then(Value::as_object)
                    .is_some_and(|policies| policies.contains_key("default"))
        },
        "config.rules-null" => config.get("rules").is_some_and(Value::is_null),
        "config.authority-map-invalid-type" => config
            .get("per_authority_directives")
            .is_some_and(|value| !value.is_object()),
        "config.authority-value-invalid-type" => config
            .get("per_authority_directives")
            .and_then(Value::as_object)
            .and_then(|authorities| authorities.get("waf.example"))
            .is_some_and(|value| !value.is_string()),
        _ => return None,
    };
    Some(result)
}

fn configuration_shape_topic(case: &FixtureCase, topic: &str) -> Option<bool> {
    let config = &case.plugin_configuration;
    let result = match topic {
        "config.authority-missing-policy-reference" => {
            config
                .get("per_authority_directives")
                .and_then(Value::as_object)
                .and_then(|authorities| authorities.get("waf.example"))
                .and_then(Value::as_str)
                == Some("missing")
                && config
                    .get("directives_map")
                    .and_then(Value::as_object)
                    .is_some_and(|policies| policies.contains_key("default") && !policies.contains_key("missing"))
                && config.get("default_directives").and_then(Value::as_str) == Some("default")
        },
        "config.directives-map-policy-object" => {
            config
                .get("directives_map")
                .and_then(Value::as_object)
                .and_then(|policies| policies.get("default"))
                .is_some_and(Value::is_object)
                && config.get("default_directives").and_then(Value::as_str) == Some("default")
        },
        "config.directives-map-array-containers" => {
            config
                .get("directives_map")
                .and_then(Value::as_object)
                .and_then(|policies| policies.get("default"))
                .and_then(Value::as_array)
                .is_some_and(|directives| {
                    directives.iter().any(Value::is_object) && directives.iter().any(Value::is_array)
                })
                && config.get("default_directives").and_then(Value::as_str) == Some("default")
        },
        "config.root-scalar" => {
            !case
                .raw_plugin_configuration
                .bytes()
                .all(|byte| byte.is_ascii_whitespace())
                && (config.is_null() || config.is_boolean() || config.is_number() || config.is_string())
                && request_has_identity(case, "GET", "/root-scalar")
                && request_policy_name(case).is_none()
        },
        _ => return None,
    };
    Some(result)
}

fn phase_two_metric_topic(case: &FixtureCase) -> bool {
    let directives = request_policy_directives(case);
    request_policy_has_engine(case, "On")
        && matches!(directives.as_slice(), [_, rule]
            if sec_rule_matches_operator(
                rule,
                "ARGS",
                "@streq",
                "attack",
                &["id:1004", "phase:2", "deny", "status:403"],
            ) && sec_rule_has_exact_actions(rule, &["id:1004", "phase:2", "deny", "status:403"]))
        && request_has_identity(case, "POST", "/")
        && request_has_header(case, "content-type", "application/x-www-form-urlencoded")
        && request_has_form_argument(case, "attack") == Some(true)
        && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
}

fn request_body_limit_boundary_topic(case: &FixtureCase, topic: &str) -> bool {
    let (body, should_match, scenario) = match topic {
        "http.request-body-limit.below" => ("Y21kPWF0dGFj", false, "body-size-9"),
        "http.request-body-limit.at" => ("Y21kPWF0dGFjaw==", true, "body-size-10"),
        "http.request-body-limit.above" => ("Y21kPWF0dGFja3g=", false, "body-size-11"),
        _ => return false,
    };
    let expected_match = if should_match {
        RequestRuleMatch::Match
    } else {
        RequestRuleMatch::NoMatch
    };
    let directives = request_policy_directives(case);
    matches!(directives.as_slice(), [engine, limit, rule]
        if *engine == "SecRuleEngine On"
            && *limit == "SecRequestBodyLimit 10"
            && sec_rule_matches_operator(
                rule,
                "ARGS",
                "@streq",
                "attack",
                &["id:1081", "phase:2", "deny", "status:403"],
            )
            && sec_rule_has_exact_actions(rule, &["id:1081", "phase:2", "deny", "status:403"]))
        && request_policy_has_engine(case, "On")
        && request_has_identity(case, "POST", "/body-limit")
        && request_has_header(case, "content-type", "application/x-www-form-urlencoded")
        && case
            .request
            .as_ref()
            .and_then(|request| request.get("body_base64"))
            .and_then(Value::as_str)
            == Some(body)
        && has_scenario(case, scenario)
        && directives
            .get(2)
            .is_some_and(|rule| request_matches_rule(case, rule) == expected_match)
}

fn additional_contract_topic(case: &FixtureCase, topic: &str) -> Option<bool> {
    let config = &case.plugin_configuration;
    let result = match topic {
        "engine.phase-three" => {
            let directives = request_policy_directives(case);
            matches!(directives.as_slice(), [engine, rule]
                if *engine == "SecRuleEngine On"
                    && sec_rule_matches_operator(
                        rule,
                        "RESPONSE_HEADERS:x-phase",
                        "@streq",
                        "block",
                        &["id:1080", "phase:3", "deny", "status:403"],
                    )
                    && sec_rule_has_exact_actions(rule, &["id:1080", "phase:3", "deny", "status:403"]))
                && request_policy_has_engine(case, "On")
                && request_has_identity(case, "GET", "/phase-three")
                && backend_response_has(case, 200, "cGhhc2UtdGhyZWUtYm9keQ==")
                && has_scenario(case, "pause-after-response-headers-before-body")
                && case.backend_response.as_ref().is_some_and(|response| {
                    response
                        .get("body_base64")
                        .and_then(Value::as_str)
                        .is_some_and(|body| !body.is_empty() && BASE64.decode(body).is_ok())
                        && has_ordered_pairs(
                            response.get("headers"),
                            &[("content-type", "text/plain"), ("x-phase", "block")],
                        )
                })
        },
        "http.request-body-limit.below" | "http.request-body-limit.at" | "http.request-body-limit.above" => {
            request_body_limit_boundary_topic(case, topic)
        },
        "http.response-header-trailer-rewrite" => {
            request_policy_has_engine(case, "On")
                && request_policy_has_exact_rule(
                    case,
                    "RESPONSE_BODY",
                    "@contains",
                    "secret",
                    &["id:1009", "phase:4", "deny", "status:451"],
                )
                && request_has_identity(case, "GET", "/response-secret")
                && backend_response_has(case, 200, "c2VjcmV0")
                && case.backend_response.as_ref().is_some_and(|response| {
                    has_ordered_pairs(
                        response.get("headers"),
                        &[("content-type", "text/plain"), ("x-upstream-secret", "header-secret")],
                    ) && has_ordered_pairs(
                        response.get("trailers"),
                        &[("x-upstream-secret-trailer", "trailer-secret")],
                    )
                })
        },
        "lifecycle.reset-while-held" => {
            request_policy_has_engine(case, "On")
                && request_policy_has_exact_rule(
                    case,
                    "ARGS",
                    "@streq",
                    "attack",
                    &["id:1082", "phase:2", "deny", "status:403"],
                )
                && request_has_identity(case, "POST", "/reset-held")
                && request_has_header(case, "content-type", "application/x-www-form-urlencoded")
                && request_has_form_argument(case, "attack") == Some(true)
                && has_scenario(case, "pause-after-request-headers")
                && has_scenario(case, "reset-while-request-headers-held")
        },
        "ops.hostcall-failure" => {
            request_policy_has_engine(case, "On")
                && config.get("enable_filter_state_logs").and_then(Value::as_bool) == Some(true)
                && request_policy_has_exact_rule(
                    case,
                    "REQUEST_URI",
                    "@streq",
                    "/hostcall-failure",
                    &["id:1083", "phase:1", "deny", "status:403"],
                )
                && request_has_identity(case, "GET", "/hostcall-failure")
                && case.host_faults.iter().any(|fault| {
                    fault.get("operation").and_then(Value::as_str) == Some("set_property")
                        && fault.get("result").and_then(Value::as_str) == Some("failure")
                })
                && has_scenario(case, "fail-filter-state-set-property")
        },
        _ => return None,
    };
    Some(result)
}

fn default_policy_configuration_topic(case: &FixtureCase) -> bool {
    match case.id.as_str() {
        "config-empty" => case.raw_plugin_configuration.is_empty() && case.plugin_configuration.is_null(),
        "config-whitespace" => {
            !case.raw_plugin_configuration.is_empty()
                && case
                    .raw_plugin_configuration
                    .bytes()
                    .all(|byte| byte.is_ascii_whitespace())
                && case.plugin_configuration.is_null()
        },
        "config-empty-object" => {
            case.raw_plugin_configuration == "{}"
                && case
                    .plugin_configuration
                    .as_object()
                    .is_some_and(serde_json::Map::is_empty)
        },
        _ => {
            case.plugin_configuration.is_null()
                || case
                    .plugin_configuration
                    .as_object()
                    .is_some_and(serde_json::Map::is_empty)
        },
    }
}

fn rule_data_ip_match_from_file_topic(case: &FixtureCase) -> bool {
    let directives = request_policy_directives(case);
    matches!(directives.as_slice(), [engine, rule]
        if *engine == "SecRuleEngine On"
            && sec_rule_matches_operator(
                rule,
                "REMOTE_ADDR",
                "@ipMatchFromFile",
                "data/networks.txt",
                &["id:1090", "phase:1", "deny", "status:403"],
            )
            && sec_rule_has_exact_actions(rule, &["id:1090", "phase:1", "deny", "status:403"]))
        && request_policy_has_engine(case, "On")
        && case
            .plugin_configuration
            .get("rule_data")
            .and_then(|files| files.get("data/networks.txt"))
            .and_then(Value::as_str)
            .is_some_and(|contents| contents == "203.0.113.0/24\n")
        && request_has_identity(case, "GET", "/ip-match")
        && request_string(case, "client_ip") == Some("203.0.113.7")
}

fn topic_has_required_input(case: &FixtureCase, topic: &str) -> Option<bool> {
    if topic == "rule-data.ip-match-from-file" {
        return Some(rule_data_ip_match_from_file_topic(case));
    }
    let config = &case.plugin_configuration;
    let request_path = request_string(case, "path");
    if topic == "config.default-policy" {
        return Some(default_policy_configuration_topic(case));
    }
    if let Some(result) = authority_policy_selection_topic(case, topic) {
        return Some(result);
    }
    if let Some(result) = policy_selection_topic(case, topic) {
        return Some(result);
    }
    if let Some(result) = configuration_type_topic(case, topic) {
        return Some(result);
    }
    if let Some(result) = configuration_shape_topic(case, topic) {
        return Some(result);
    }
    if topic == "metrics.phase-two-interruption" {
        return Some(phase_two_metric_topic(case));
    }
    if let Some(result) = additional_contract_topic(case, topic) {
        return Some(result);
    }
    let result = match topic {
        "config.directive-order" => {
            let directives = request_policy_directives(case);
            matches!(directives.as_slice(), [engine, first, second]
                if *engine == "SecRuleEngine On"
                    && sec_rule_matches(first, "REQUEST_URI", "/ordered", &["id:1002", "phase:1", "pass", "log"])
                    && sec_rule_has_exact_actions(first, &["id:1002", "phase:1", "pass", "log", "msg:'first'"])
                    && sec_rule_matches(second, "REQUEST_URI", "/ordered", &["id:1003", "phase:1", "pass", "log"])
                    && sec_rule_has_exact_actions(second, &["id:1003", "phase:1", "pass", "log", "msg:'second'"]))
                && request_policy_has_engine(case, "On")
                && request_has_identity(case, "GET", "/ordered")
        },
        "config.policy-selection" => {
            config.get("default_directives").and_then(Value::as_str) == Some("missing")
                && config
                    .get("directives_map")
                    .and_then(|maps| maps.get("missing"))
                    .is_none()
        },
        "config.unknown-duplicate-keys" => {
            case.duplicate_default_directives
                && config.get("unknown").and_then(Value::as_bool) == Some(true)
                && config.get("default_directives").and_then(Value::as_str) == Some("first")
                && request_policy_name(case) == Some("first")
                && request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
                && policy_has_engine(case, "first", "On")
                && policy_has_rule(
                    case,
                    "first",
                    "REQUEST_URI",
                    "/duplicate-policy",
                    &["id:1021", "phase:1", "deny", "status:403"],
                )
                && policy_has_engine(case, "last", "Off")
                && policy_has_rule(
                    case,
                    "last",
                    "REQUEST_URI",
                    "/duplicate-policy",
                    &["id:1022", "phase:1", "deny", "status:403"],
                )
                && request_has_identity(case, "GET", "/duplicate-policy")
        },
        "bundle.recommended" => includes_file(case, "@recommended-conf"),
        "bundle.crs-setup" => includes_file(case, "@crs-setup-conf"),
        "bundle.owasp" => includes_file(case, "@owasp_crs/*.conf"),
        "bundle.demo" => includes_file(case, "@demo-conf"),
        "bundle.ftw" => includes_file(case, "@ftw-conf"),
        "bundle.crs-setup-demo" => includes_file(case, "@crs-setup-demo-conf"),
        "bundle.relative-data" => {
            let directives = request_policy_directives(case);
            matches!(directives.as_slice(), [engine, include]
                if *engine == "SecRuleEngine On" && *include == "Include rules/relative.conf")
                && request_policy_has_engine(case, "On")
                && config.get("rule_data").is_some_and(Value::is_object)
                && config
                    .get("rule_data")
                    .and_then(|files| files.get("rules/relative.conf"))
                    .and_then(Value::as_str)
                    .is_some_and(|contents| {
                        let rules: Vec<_> = directive_lines(contents).collect();
                        matches!(rules.as_slice(), [rule]
                            if sec_rule_matches_operator(
                                rule,
                                "ARGS",
                                "@pmFromFile",
                                "data/needles.txt",
                                &["id:1033", "phase:2", "deny", "status:403"],
                            ) && sec_rule_has_exact_actions(rule, &["id:1033", "phase:2", "deny", "status:403"]))
                    })
                && config
                    .get("rule_data")
                    .and_then(|files| files.get("data/needles.txt"))
                    .and_then(Value::as_str)
                    .is_some_and(|contents| contents == "attack\n")
                && request_has_identity(case, "POST", "/")
                && request_has_form_argument(case, "attack") == Some(true)
                && request_has_header(case, "content-type", "application/x-www-form-urlencoded")
                && case
                    .request
                    .as_ref()
                    .and_then(|request| request.get("body_base64"))
                    .and_then(Value::as_str)
                    .is_some_and(|body| !body.is_empty())
        },
        "engine.chains-controls" => {
            let directives = request_policy_directives(case);
            matches!(directives.as_slice(), [engine, parent, child, later]
                if *engine == "SecRuleEngine On"
                    && sec_rule_matches(parent, "REQUEST_URI", "/chain", &["id:1005", "phase:1", "pass", "chain"])
                    && sec_rule_has_exact_actions(parent, &["id:1005", "phase:1", "pass", "chain"])
                    && sec_rule_matches(child, "REQUEST_METHOD", "GET", &["ctl:ruleEngine=Off"])
                    && sec_rule_has_exact_actions(child, &["ctl:ruleEngine=Off"])
                    && sec_rule_matches(later, "REQUEST_URI", "/chain", &["id:1006", "phase:1", "deny", "status:403"])
                    && sec_rule_has_exact_actions(later, &["id:1006", "phase:1", "deny", "status:403"]))
                && request_policy_has_engine(case, "On")
                && request_has_identity(case, "GET", "/chain")
        },
        "engine.multiphase" => {
            let directives = request_policy_directives(case);
            matches!(directives.as_slice(), [engine, setup, parent, child]
                if *engine == "SecRuleEngine On"
                    && sec_action_has_exact_actions(setup, &["id:1006", "phase:1", "pass", "setvar:tx.blocking_paranoia_level=1"])
                    && sec_rule_matches_operator(parent, "TX:blocking_paranoia_level", "@eq", "1", &["id:1007", "phase:2", "deny", "status:403", "chain"])
                    && sec_rule_has_exact_actions(parent, &["id:1007", "phase:2", "deny", "status:403", "chain"])
                    && sec_rule_matches(child, "REQUEST_URI", "/early-block", &["t:none"])
                    && sec_rule_has_exact_actions(child, &["t:none"]))
                && request_policy_has_engine(case, "On")
                && request_has_identity(case, "POST", "/early-block")
                && request_has_header(case, "content-type", "text/plain")
                && has_scenario(case, "await-early-response-before-request-body-complete")
        },
        "engine.phase-5" => {
            let directives = request_policy_directives(case);
            directives.len() == 2
                && directives.first() == Some(&"SecRuleEngine On")
                && directives.get(1).is_some_and(|directive| {
                    sec_action_has_exact_actions(
                        directive,
                        &["id:1032", "phase:5", "pass", "log", "msg:'phase-five-ran'"],
                    )
                })
                && request_policy_has_engine(case, "On")
                && request_has_identity(case, "GET", "/")
        },
        "engine.regex-capture" => {
            request_policy_has_engine(case, "On")
                && request_policy_has_exact_rule(
                    case,
                    "REQUEST_URI",
                    "@rx",
                    "^/item-([0-9]+)$",
                    &[
                        "id:1034",
                        "phase:1",
                        "pass",
                        "capture",
                        "setvar:tx.item=%{TX.1}",
                        "logdata:%{TX.item}",
                    ],
                )
                && request_has_identity(case, "GET", "/item-42")
        },
        "lifecycle.allow" => {
            request_policy_has_engine(case, "On")
                && request_string(case, "method").is_some()
                && request_path.is_some()
                && lifecycle_probe_supported(case)
                && request_has_matching_interruption(case, false) == RequestRuleMatch::NoMatch
        },
        "http.byte-exact" => {
            request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && request_has_matching_interruption(case, false) == RequestRuleMatch::NoMatch
                && request_has_identity(case, "POST", "/echo")
                && case
                    .request
                    .as_ref()
                    .and_then(|request| request.get("body_base64"))
                    .and_then(Value::as_str)
                    == Some("AAECAwQ=")
                && has_ordered_pairs(
                    case.request.as_ref().and_then(|request| request.get("headers")),
                    &[("x-repeat", "one"), ("x-repeat", "two")],
                )
        },
        "http.duplicate-headers" => {
            request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && request_has_matching_interruption(case, false) == RequestRuleMatch::NoMatch
                && request_has_identity(case, "GET", "/")
                && case
                    .request
                    .as_ref()
                    .and_then(|request| request.get("body_base64"))
                    .and_then(Value::as_str)
                    == Some("AAECAwQ=")
                && has_ordered_pairs(
                    case.request.as_ref().and_then(|request| request.get("headers")),
                    &[
                        ("cookie", "a=1"),
                        ("cookie", "b=2"),
                        ("x-repeat", "one"),
                        ("x-repeat", "two"),
                    ],
                )
        },
        "lifecycle.detection-only" => {
            request_policy_has_engine(case, "DetectionOnly")
                && lifecycle_probe_supported(case)
                && request_policy_has_rule(
                    case,
                    "REQUEST_URI",
                    "@streq",
                    "/deny",
                    &["id:1008", "phase:1", "deny", "status:403"],
                )
                && request_has_identity(case, "GET", "/deny")
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
        },
        "lifecycle.empty-body" => {
            request_has_identity(case, "POST", "/trailers")
                && case
                    .request
                    .as_ref()
                    .and_then(|request| request.get("body_base64"))
                    .and_then(Value::as_str)
                    == Some("")
        },
        "lifecycle.engine-off" => {
            request_policy_has_engine(case, "Off")
                && lifecycle_probe_supported(case)
                && request_policy_has_rule(
                    case,
                    "REQUEST_URI",
                    "@streq",
                    "/deny",
                    &["id:1031", "phase:1", "deny", "status:403"],
                )
                && request_has_identity(case, "GET", "/deny")
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
        },
        "lifecycle.finalization-failure" => case.host_faults.iter().any(|fault| {
            fault.get("operation").and_then(Value::as_str) == Some("finalization")
                && fault.get("result").and_then(Value::as_str) == Some("failure")
        }),
        "lifecycle.reload" => {
            request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && request_policy_has_rule(
                    case,
                    "REQUEST_URI",
                    "@streq",
                    "/reload-deny",
                    &["id:1040", "phase:1", "deny", "status:403"],
                )
                && case.reload_plugin_configuration.as_ref().is_some_and(|reload| {
                    let directives = request_policy_directives_in(case, reload);
                    request_policy_has_engine_in(case, reload, "DetectionOnly")
                        && lifecycle_directives_supported(case, &directives)
                        && directives.iter().any(|directive| {
                            sec_rule_matches(
                                directive,
                                "REQUEST_URI",
                                "/reload-deny",
                                &["id:1041", "phase:1", "deny", "status:403"],
                            ) && sec_rule_has_exact_actions(directive, &["id:1041", "phase:1", "deny", "status:403"])
                                && request_matches_rule(case, directive) == RequestRuleMatch::Match
                        })
                })
                && request_has_identity(case, "GET", "/reload-deny")
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
                && has_scenario(case, "reload-with-inflight-stream")
                && has_scenario(case, "hold-request-before-reload")
                && has_scenario(case, "repeat-request-after-reload")
        },
        "lifecycle.request-interruption" => {
            request_policy_has_engine(case, "On")
                && request_string(case, "method").is_some()
                && request_path.is_some()
                && lifecycle_probe_supported(case)
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
        },
        "lifecycle.reset-abort" => ["reset", "abort", "local-reply", "normal-finish"]
            .iter()
            .all(|scenario| has_scenario(case, scenario)),
        "lifecycle.response-interruption" => {
            request_policy_has_engine(case, "On")
                && request_policy_has_exact_rule(
                    case,
                    "RESPONSE_BODY",
                    "@contains",
                    "secret",
                    &["id:1009", "phase:4", "deny", "status:451"],
                )
                && request_has_identity(case, "GET", "/response-secret")
                && backend_response_has(case, 200, "c2VjcmV0")
                && case.backend_response.as_ref().is_some_and(|response| {
                    has_ordered_pairs(
                        response.get("headers"),
                        &[("content-type", "text/plain"), ("x-upstream-secret", "header-secret")],
                    ) && has_ordered_pairs(
                        response.get("trailers"),
                        &[("x-upstream-secret-trailer", "trailer-secret")],
                    )
                })
        },
        "lifecycle.response-headers" => {
            request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && request_has_identity(case, "GET", "/response-trailers")
                && backend_response_has(case, 201, "cmVzcG9uc2U=")
                && case.backend_response.as_ref().is_some_and(|response| {
                    has_ordered_pairs(
                        response.get("headers"),
                        &[("content-type", "text/plain"), ("x-response", "one")],
                    )
                })
        },
        "lifecycle.response-trailers" => {
            request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && request_has_identity(case, "GET", "/response-trailers")
                && backend_response_has(case, 201, "cmVzcG9uc2U=")
                && case
                    .backend_response
                    .as_ref()
                    .is_some_and(|response| has_ordered_pairs(response.get("trailers"), &[("x-response-end", "done")]))
        },
        "lifecycle.trailers" => {
            request_has_identity(case, "POST", "/trailers")
                && case
                    .request
                    .as_ref()
                    .and_then(|request| request.get("trailers"))
                    .is_some_and(|trailers| has_ordered_pairs(Some(trailers), &[("x-end", "done")]))
        },
        "metrics.custom-labels" => config.get("metric_labels").is_some_and(|labels| {
            labels.get("suite").and_then(Value::as_str) == Some("contract")
                && labels.get("env").and_then(Value::as_str) == Some("qa")
        }),
        "metrics.tx-total" | "metrics.interruption" => {
            request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && request_has_phase_one_interruption(case) == RequestRuleMatch::Match
                && request_has_identity(case, "GET", "/deny")
        },
        "pr20.category-tag" => {
            request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && config.get("enable_filter_state_logs").and_then(Value::as_bool) == Some(true)
                && request_policy_has_rule(
                    case,
                    "REQUEST_URI",
                    "@streq",
                    "/deny",
                    &[
                        "id:1010",
                        "phase:1",
                        "deny",
                        "status:403",
                        "severity:2",
                        "tag:'attack-SQLi'",
                    ],
                )
                && request_has_identity(case, "GET", "/deny")
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
        },
        "pr20.state-disabled" => {
            request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && config.get("enable_filter_state_logs").and_then(Value::as_bool) == Some(false)
                && request_policy_has_rule(
                    case,
                    "REQUEST_URI",
                    "@streq",
                    "/deny",
                    &["id:1042", "phase:1", "deny", "status:403"],
                )
                && request_has_identity(case, "GET", "/deny")
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
        },
        "pr20.state-published" => {
            request_policy_has_engine(case, "On")
                && lifecycle_probe_supported(case)
                && config.get("enable_filter_state_logs").and_then(Value::as_bool) == Some(true)
                && request_policy_has_rule(
                    case,
                    "REQUEST_URI",
                    "@streq",
                    "/deny",
                    &[
                        "id:1010",
                        "phase:1",
                        "deny",
                        "status:403",
                        "severity:2",
                        "tag:'attack-SQLi'",
                    ],
                )
                && request_has_identity(case, "GET", "/deny")
                && request_has_matching_interruption(case, false) == RequestRuleMatch::Match
                && request_string(case, "client_ip") == Some("192.0.2.5")
        },
        _ => return None,
    };
    Some(result)
}

fn validate_inventory_coverage(coverage: &BTreeMap<String, Vec<String>>, cases: &[FixtureCase]) -> Result<(), String> {
    let required: BTreeSet<_> = coverage.values().flatten().map(String::as_str).collect();
    let mut found = BTreeSet::new();
    for case in cases {
        validate_directive_arrays(case)?;
        if case.topics.is_empty() {
            return Err(format!("fixture case {} must name at least one topic", case.id));
        }
        let mut seen = BTreeSet::new();
        for topic in &case.topics {
            if !required.contains(topic.as_str()) {
                return Err(format!("fixture case {} uses undeclared topic {topic}", case.id));
            }
            if !seen.insert(topic.as_str()) {
                return Err(format!("fixture case {} repeats topic {topic}", case.id));
            }
            match topic_has_required_input(case, topic) {
                Some(true) => {},
                Some(false) => {
                    return Err(format!(
                        "fixture case {} topic {topic} lacks its required input",
                        case.id
                    ));
                },
                None => return Err(format!("fixture topic {topic} has no input validation rule")),
            }
            found.insert(topic.as_str());
        }
    }
    if let Some(topic) = required.difference(&found).next() {
        return Err(format!("inventory topic {topic} has no executable fixture case"));
    }
    Ok(())
}

fn read_limited(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if bytes.len() > max_bytes {
        return Err(format!("{} exceeds the {max_bytes}-byte input limit", path.display()));
    }
    Ok(bytes)
}

fn reject_output_alias(output: &Path, inputs: &[&Path]) -> Result<(), String> {
    for input in inputs {
        if paths_alias(output, input)
            .map_err(|error| format!("cannot compare output path with {}: {error}", input.display()))?
        {
            return Err(format!(
                "output {} aliases input {}; refusing to overwrite it",
                output.display(),
                input.display()
            ));
        }
    }
    Ok(())
}

fn paths_alias(left: &Path, right: &Path) -> std::io::Result<bool> {
    let (left_path, left_metadata) = resolve_path(left)?;
    let (right_path, right_metadata) = resolve_path(right)?;
    if left_path == right_path {
        return Ok(true);
    }
    Ok(match (left_metadata, right_metadata) {
        (Some(left), Some(right)) => same_file(&left, &right),
        _ => false,
    })
}

fn resolve_path(path: &Path) -> std::io::Result<(PathBuf, Option<fs::Metadata>)> {
    match fs::canonicalize(path) {
        Ok(canonical) => {
            let metadata = fs::metadata(&canonical)?;
            Ok((canonical, Some(metadata)))
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let name = path.file_name().ok_or(error)?;
            Ok((fs::canonicalize(parent)?.join(name), None))
        },
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    matches!(
        (
            left.volume_serial_number(),
            left.file_index(),
            right.volume_serial_number(),
            right.file_index()
        ),
        (Some(left_volume), Some(left_index), Some(right_volume), Some(right_index))
            if left_volume == right_volume && left_index == right_index
    )
}

#[cfg(not(any(unix, windows)))]
fn same_file(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}

fn string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))
}

fn u32_field(value: &Value, key: &str) -> Result<u32, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|number| u32::try_from(number).ok())
        .ok_or_else(|| format!("{key} must be an unsigned 32-bit integer"))
}

fn string_array_field(value: &Value, key: &str) -> Result<Vec<String>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} must be an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{key} entries must be strings"))
        })
        .collect()
}

fn parse_fixture_case(case: &Value) -> Result<FixtureCase, String> {
    let id = string_field(case, "id")?.to_owned();
    let raw_plugin_configuration = string_field(case, "plugin_configuration")?.to_owned();
    let topics = string_array_field(case, "topics")?;
    let permits_duplicate_configuration_keys = topics.iter().any(|topic| topic == "config.unknown-duplicate-keys");
    let (plugin_configuration, duplicate_default_directives) = parse_plugin_configuration(
        &raw_plugin_configuration,
        &format!("fixture case {id} plugin_configuration"),
        permits_duplicate_configuration_keys,
    )?;
    let request = case.get("request").cloned();
    if request.as_ref().is_some_and(|request| !request.is_object()) {
        return Err(format!("fixture case {id} request must be an object"));
    }
    if let Some(request) = &request {
        validate_base64_values(&format!("fixture case {id}"), request, "request")?;
    }
    let reload_plugin_configuration = case
        .get("reload_plugin_configuration")
        .map(|configuration| {
            let raw = configuration
                .as_str()
                .ok_or_else(|| format!("fixture case {id} reload_plugin_configuration must be a string"))?;
            parse_plugin_configuration(raw, &format!("fixture case {id} reload_plugin_configuration"), false)
                .map(|(configuration, _)| configuration)
        })
        .transpose()?;
    let host_scenarios = case
        .get("host_scenarios")
        .map_or(Ok(Vec::new()), |_| string_array_field(case, "host_scenarios"))?;
    let host_faults = case
        .get("host_faults")
        .map(|faults| {
            faults
                .as_array()
                .ok_or_else(|| format!("fixture case {id} host_faults must be an array"))?
                .iter()
                .map(|fault| {
                    fault
                        .as_object()
                        .map(|_| fault.clone())
                        .ok_or_else(|| format!("fixture case {id} host_faults entries must be objects"))
                })
                .collect()
        })
        .transpose()?
        .unwrap_or_default();
    let backend_response = case.get("backend_response").cloned();
    if backend_response.as_ref().is_some_and(|response| !response.is_object()) {
        return Err(format!("fixture case {id} backend_response must be an object"));
    }
    if let Some(backend_response) = &backend_response {
        validate_base64_values(&format!("fixture case {id}"), backend_response, "backend_response")?;
    }
    Ok(FixtureCase {
        id,
        raw_plugin_configuration,
        plugin_configuration,
        duplicate_default_directives,
        request,
        reload_plugin_configuration,
        host_scenarios,
        host_faults,
        backend_response,
        topics,
    })
}

fn parse_plugin_configuration(raw: &str, label: &str, permits_duplicate_keys: bool) -> Result<(Value, bool), String> {
    if raw.bytes().all(|byte| byte.is_ascii_whitespace()) {
        return Ok((Value::Null, false));
    }
    let (parsed, duplicate_default_directives) = if permits_duplicate_keys {
        let parsed = serde_json::from_str::<StrictPluginConfiguration>(raw)
            .map_err(|error| format!("{label} must be valid JSON with only the declared duplicate key: {error}"))?;
        (parsed.0, parsed.1)
    } else {
        let parsed = serde_json::from_str::<StrictJsonValue>(raw)
            .map_err(|error| format!("{label} must be valid JSON without duplicate keys: {error}"))?;
        (parsed.0, false)
    };
    Ok((parsed, duplicate_default_directives))
}

fn parse_strict_json(bytes: &[u8], label: &str) -> Result<Value, String> {
    serde_json::from_slice::<StrictJsonValue>(bytes)
        .map(|value| value.0)
        .map_err(|error| format!("{label}: {error}"))
}

fn serialize_capture(capture: &Value) -> Result<Vec<u8>, String> {
    let output = serde_json::to_vec_pretty(capture).map_err(|error| error.to_string())?;
    if output.len() > MAX_CAPTURE_BYTES {
        return Err(format!(
            "serialized capture exceeds the {MAX_CAPTURE_BYTES}-byte output limit"
        ));
    }
    Ok(output)
}

fn write_output(path: &Path, inputs: &[&Path], bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|error| format!("{}: {error}", path.display()))?;
    let name = path
        .file_name()
        .ok_or_else(|| format!("{} has no output file name", path.display()))?;
    let target = parent.join(name);
    reject_output_alias(&target, inputs).map_err(|error| format!("{}: {error}", path.display()))?;

    for attempt in 0..16 {
        let mut temporary_name = OsString::from(".");
        temporary_name.push(name);
        temporary_name.push(format!(".{}.{}.tmp", std::process::id(), attempt));
        let temporary = parent.join(temporary_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = match options.open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        if let Err(error) = file.write_all(bytes) {
            drop(file);
            drop(fs::remove_file(&temporary));
            return Err(format!("{}: {error}", path.display()));
        }
        drop(file);
        if let Err(error) = fs::rename(&temporary, &target) {
            drop(fs::remove_file(&temporary));
            return Err(format!("{}: {error}", path.display()));
        }
        return Ok(());
    }
    Err(format!(
        "{}: could not create a unique temporary output",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use serde_json::{Value, json};

    use super::{
        CASES, Capture, CaseRef, ContractManifest, Host, ObservationType, Pins, RequiredObservation, SOURCE_PROVENANCE,
        StrictOutcomes, compare_outcomes, directive_is_request_phase, is_commit, is_sha256, parse_fixture_case,
        parse_strict_json, read_limited, reject_output_alias, validate_capture_contract_digest, validate_host_ids,
        validate_inventory_coverage, validate_outcomes,
    };

    fn assert_topic_rejected(case_value: &Value) {
        let case = parse_fixture_case(case_value).unwrap();
        let topic = case.topics.first().cloned().unwrap_or_default();
        let coverage = BTreeMap::from([("claim".to_owned(), vec![topic.clone()])]);
        let error = validate_inventory_coverage(&coverage, &[case]).unwrap_err();
        assert!(
            error.contains(&format!("topic {topic} lacks its required input")),
            "{error}"
        );
    }

    fn assert_topic_accepted(case_value: &Value) {
        let case = parse_fixture_case(case_value).unwrap();
        let topic = case.topics.first().cloned().unwrap_or_default();
        let coverage = BTreeMap::from([("claim".to_owned(), vec![topic.clone()])]);
        let result = validate_inventory_coverage(&coverage, &[case]);
        assert!(result.is_ok(), "{result:?}");
    }

    fn remove_object_field(value: &mut Value, object_key: &str, field: &str) {
        let removed = value
            .get_mut(object_key)
            .and_then(Value::as_object_mut)
            .and_then(|object| object.remove(field));
        assert!(removed.is_some(), "{object_key}.{field} must exist");
    }

    fn set_pointer(value: &mut Value, path: &str, replacement: Value) {
        *value.pointer_mut(path).expect("JSON pointer must exist") = replacement;
    }

    fn push_array(value: &mut Value, path: &str, item: Value) {
        value
            .pointer_mut(path)
            .and_then(Value::as_array_mut)
            .expect("JSON pointer must name an array")
            .push(item);
    }

    fn required(path: &str, value_type: ObservationType) -> RequiredObservation {
        RequiredObservation {
            path: path.to_owned(),
            value_type,
        }
    }

    fn manifest_with_fields(case_id: &str, required_outcome_fields: Vec<RequiredObservation>) -> ContractManifest {
        ContractManifest {
            schema_version: 2,
            contract_sha256: String::new(),
            hosts: vec![Host {
                id: "host".to_owned(),
                pinned: false,
            }],
            cases: vec![CaseRef {
                id: case_id.to_owned(),
                reference: "upstream".to_owned(),
                hosts: vec!["host".to_owned()],
                required_outcome_fields,
            }],
            inventory_coverage: BTreeMap::new(),
            deferred_inventory: Vec::new(),
            pins: Pins {
                upstream_connector: String::new(),
                pr20_head: String::new(),
            },
        }
    }

    fn capture(role: &str, case_id: &str, outcome: Value) -> Capture {
        Capture {
            schema_version: 2,
            host: "host".to_owned(),
            role: role.to_owned(),
            revision: String::new(),
            artifact_sha256: String::new(),
            contract_sha256: String::new(),
            outcomes: BTreeMap::from([(case_id.to_owned(), outcome)]),
        }
    }

    #[test]
    fn repository_contract_manifest_matches_fixture_file() {
        let manifest = super::check_manifest(super::repository_root()).unwrap();
        assert_eq!(manifest.cases.len(), 56);
        assert_eq!(manifest.hosts.len(), 3);
        assert!(super::require_pinned_host(&manifest, "standalone-envoy-1.40.0").is_ok());
        for (host, ..) in super::APPROVED_HOSTS {
            assert!(super::require_pinned_host(&manifest, host).is_ok());
            assert!(
                manifest
                    .cases
                    .iter()
                    .all(|case| case.hosts.iter().any(|case_host| case_host == host))
            );
        }
        let state_case = manifest
            .cases
            .iter()
            .find(|case| case.id == "pr20-filter-state-interruption-fields")
            .unwrap();
        for path in [
            "filter_state.event",
            "filter_state.rule_id",
            "filter_state.phase",
            "filter_state.action",
            "filter_state.status",
            "filter_state.severity",
            "filter_state.category",
            "filter_state.client_ip",
            "filter_state.publication_sequence",
            "local_reply.sequence",
        ] {
            assert!(
                state_case
                    .required_outcome_fields
                    .iter()
                    .any(|field| field.path == path)
            );
        }
        for id in ["http-benign-byte-exact", "http-duplicate-headers-cookies"] {
            let case = manifest.cases.iter().find(|case| case.id == id).unwrap();
            for path in ["backend.request.method", "backend.request.path"] {
                assert!(case.required_outcome_fields.iter().any(|field| field.path == path));
            }
        }
        assert_eq!(
            manifest
                .cases
                .iter()
                .find(|case| case.id == "rule-relative-rule-data-files")
                .unwrap()
                .reference,
            "candidate"
        );
        assert_eq!(
            manifest
                .cases
                .iter()
                .find(|case| case.id == "rule-data-ip-match-from-file")
                .unwrap()
                .reference,
            "candidate"
        );
        assert_eq!(
            manifest
                .cases
                .iter()
                .find(|case| case.id == "ops-filter-state-hostcall-failure")
                .unwrap()
                .reference,
            "pr20"
        );
    }

    #[test]
    fn manifest_verifies_exact_source_provenance_bytes() {
        let repository = super::repository_root();
        let root = test_dir();
        for relative in [super::MANIFEST, CASES, SOURCE_PROVENANCE] {
            let target = root.join(relative);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::copy(repository.join(relative), target).unwrap();
        }
        assert!(super::check_manifest(&root).is_ok());

        let provenance_path = root.join(SOURCE_PROVENANCE);
        let mut bytes = fs::read(&provenance_path).unwrap();
        bytes.push(b' ');
        fs::write(&provenance_path, bytes).unwrap();
        assert!(
            super::check_manifest(&root)
                .unwrap_err()
                .contains("source_provenance.sha256 changed")
        );

        fs::copy(repository.join(SOURCE_PROVENANCE), &provenance_path).unwrap();
        fs::remove_file(&provenance_path).unwrap();
        assert!(
            super::check_manifest(&root)
                .unwrap_err()
                .contains("source-provenance.json")
        );

        #[cfg(unix)]
        {
            let outside = root.with_extension("outside.json");
            fs::write(&outside, fs::read(repository.join(SOURCE_PROVENANCE)).unwrap()).unwrap();
            std::os::unix::fs::symlink(&outside, &provenance_path).unwrap();
            assert!(
                super::check_manifest(&root)
                    .unwrap_err()
                    .contains("source-provenance.json resolves outside the repository")
            );
            fs::remove_file(&provenance_path).unwrap();
            fs::copy(repository.join(SOURCE_PROVENANCE), &provenance_path).unwrap();
            fs::remove_file(outside).unwrap();
        }

        let manifest_path = root.join(super::MANIFEST);
        let mut manifest = parse_strict_json(&fs::read(&manifest_path).unwrap(), super::MANIFEST).unwrap();
        *manifest.pointer_mut("/pins/source_provenance/path").unwrap() = Value::String("../manifest.json".to_owned());
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(
            super::check_manifest(&root)
                .unwrap_err()
                .contains("source_provenance.path must be")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_rejects_missing_pinned_host_or_case_coverage_after_digest_refresh() {
        let repository = super::repository_root();
        let root = test_dir();
        for relative in [super::MANIFEST, CASES, SOURCE_PROVENANCE] {
            let target = root.join(relative);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::copy(repository.join(relative), target).unwrap();
        }

        let manifest_path = root.join(super::MANIFEST);
        let original = parse_strict_json(&fs::read(&manifest_path).unwrap(), super::MANIFEST).unwrap();
        let cases = fs::read(root.join(CASES)).unwrap();

        let mut manifest = original.clone();
        *manifest.pointer_mut("/cases/0/hosts").unwrap() =
            serde_json::json!(["standalone-envoy-1.40.0", "istio-1.30.7"]);
        let digest = super::contract_digest(&manifest, &cases).unwrap();
        *manifest.pointer_mut("/contract_sha256").unwrap() = Value::String(digest);
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let error = super::check_manifest(&root).unwrap_err();
        assert!(
            error.contains("case config-empty is missing pinned hosts: istio-1.30.5"),
            "unexpected validation error: {error}"
        );

        let mut manifest = original;
        manifest
            .pointer_mut("/hosts")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .retain(|host| host.get("id").and_then(Value::as_str) != Some("istio-1.30.5"));
        let digest = super::contract_digest(&manifest, &cases).unwrap();
        *manifest.pointer_mut("/contract_sha256").unwrap() = Value::String(digest);
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let error = super::check_manifest(&root).unwrap_err();
        assert!(
            error.contains("manifest must pin required host istio-1.30.5"),
            "unexpected validation error: {error}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn checked_in_contract_copy() -> (PathBuf, PathBuf) {
        let repository = super::repository_root();
        let root = test_dir();
        for relative in [super::MANIFEST, CASES, SOURCE_PROVENANCE] {
            let target = root.join(relative);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::copy(repository.join(relative), target).unwrap();
        }
        let manifest_path = root.join(super::MANIFEST);
        (root, manifest_path)
    }

    fn write_manifest_with_refreshed_digest(root: &Path, manifest: &Value) {
        let cases = fs::read(root.join(CASES)).unwrap();
        let digest = super::contract_digest(manifest, &cases).unwrap();
        let mut manifest = manifest.clone();
        *manifest.get_mut("contract_sha256").unwrap() = Value::String(digest);
        fs::write(root.join(super::MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
    }

    fn find_case_mut<'a>(cases: &'a mut [Value], id: &str) -> &'a mut Value {
        cases
            .iter_mut()
            .find(|case| case.get("id").and_then(Value::as_str) == Some(id))
            .unwrap()
    }

    #[test]
    fn manifest_rejects_retargeted_host_digest_after_digest_refresh() {
        for (host_id, field, approved) in super::APPROVED_HOSTS {
            let (root, manifest_path) = checked_in_contract_copy();
            assert!(super::check_manifest(&root).is_ok());
            let mut manifest = parse_strict_json(&fs::read(&manifest_path).unwrap(), super::MANIFEST).unwrap();
            let host = manifest
                .pointer_mut("/hosts")
                .unwrap()
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|host| host.get("id").and_then(Value::as_str) == Some(*host_id))
                .unwrap();
            // The retargeted pin stays syntactically valid so only the approved-value
            // comparison, not digest syntax checking, can reject it.
            let retargeted = if *field == "image" {
                format!("envoyproxy/envoy:v1.40.0@sha256:{}", "0".repeat(64))
            } else {
                format!("sha256:{}", "0".repeat(64))
            };
            host.as_object_mut()
                .unwrap()
                .insert((*field).to_owned(), json!(retargeted));
            write_manifest_with_refreshed_digest(&root, &manifest);
            let error = super::check_manifest(&root).unwrap_err();
            assert!(
                error.contains(&format!("host {host_id} {field} must be {approved}")),
                "unexpected validation error for {host_id}: {error}"
            );
            assert!(error.contains("update APPROVED_HOSTS"), "{error}");
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn manifest_rejects_hosts_outside_the_approved_set_after_digest_refresh() {
        let (root, manifest_path) = checked_in_contract_copy();
        assert!(super::check_manifest(&root).is_ok());
        let mut manifest = parse_strict_json(&fs::read(&manifest_path).unwrap(), super::MANIFEST).unwrap();
        // Add a fourth host with a syntactically valid digest and name it in every case so
        // the per-case pinned-host coverage alone would accept it.
        manifest
            .pointer_mut("/hosts")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id": "extra-envoy-1.41.0",
                "kind": "standalone-envoy",
                "image": format!("envoyproxy/envoy:v1.41.0@sha256:{}", "0".repeat(64)),
                "status": "pinned"
            }));
        for case in manifest.pointer_mut("/cases").unwrap().as_array_mut().unwrap() {
            case.get_mut("hosts")
                .unwrap()
                .as_array_mut()
                .unwrap()
                .push(json!("extra-envoy-1.41.0"));
        }
        write_manifest_with_refreshed_digest(&root, &manifest);
        let error = super::check_manifest(&root).unwrap_err();
        assert!(
            error.contains("manifest host extra-envoy-1.41.0 is not in the approved host set"),
            "unexpected validation error: {error}"
        );
        assert!(error.contains("update APPROVED_HOSTS"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_rejects_case_removal_and_count_drift_after_digest_refresh() {
        let (root, manifest_path) = checked_in_contract_copy();
        assert!(super::check_manifest(&root).is_ok());
        let original_manifest = parse_strict_json(&fs::read(&manifest_path).unwrap(), super::MANIFEST).unwrap();
        let original_cases = parse_strict_json(&fs::read(root.join(CASES)).unwrap(), CASES).unwrap();
        let mut manifest = original_manifest.clone();
        let mut cases = original_cases.clone();
        manifest
            .pointer_mut("/cases")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .retain(|case| case.get("id").and_then(Value::as_str) != Some("config-whitespace"));
        cases
            .as_array_mut()
            .unwrap()
            .retain(|case| case.get("id").and_then(Value::as_str) != Some("config-whitespace"));
        fs::write(root.join(CASES), serde_json::to_vec(&cases).unwrap()).unwrap();
        write_manifest_with_refreshed_digest(&root, &manifest);
        let error = super::check_manifest(&root).unwrap_err();
        assert!(
            error.contains("contract must keep exactly 56 cases, found 55"),
            "unexpected validation error: {error}"
        );

        let mut manifest = original_manifest;
        let mut cases = original_cases;
        let manifest_cases = manifest.pointer_mut("/cases").unwrap().as_array_mut().unwrap();
        let mut added = manifest_cases.first().unwrap().clone();
        added
            .as_object_mut()
            .unwrap()
            .insert("id".to_owned(), json!("config-cloned-extra"));
        manifest_cases.push(added);
        let fixture_cases = cases.as_array_mut().unwrap();
        let mut added = fixture_cases.first().unwrap().clone();
        added
            .as_object_mut()
            .unwrap()
            .insert("id".to_owned(), json!("config-cloned-extra"));
        fixture_cases.push(added);
        fs::write(root.join(CASES), serde_json::to_vec(&cases).unwrap()).unwrap();
        write_manifest_with_refreshed_digest(&root, &manifest);
        let error = super::check_manifest(&root).unwrap_err();
        assert!(
            error.contains("contract must keep exactly 56 cases, found 57"),
            "unexpected validation error: {error}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_rejects_case_id_set_changes_even_at_the_required_count() {
        let (root, manifest_path) = checked_in_contract_copy();
        assert!(super::check_manifest(&root).is_ok());
        let original_manifest = parse_strict_json(&fs::read(&manifest_path).unwrap(), super::MANIFEST).unwrap();
        let original_cases = parse_strict_json(&fs::read(root.join(CASES)).unwrap(), CASES).unwrap();
        // Swap one case for a differently named clone so the count stays 56 and the ID sets
        // still match; only the case-ID set digest can catch the substitution.
        let mut manifest = original_manifest.clone();
        let mut cases = original_cases.clone();
        for value in [manifest.pointer_mut("/cases").unwrap(), &mut cases] {
            value
                .as_array_mut()
                .unwrap()
                .retain(|case| case.get("id").and_then(Value::as_str) != Some("config-whitespace"));
            let mut renamed = value.as_array().unwrap().first().unwrap().clone();
            renamed
                .as_object_mut()
                .unwrap()
                .insert("id".to_owned(), json!("config-renamed"));
            value.as_array_mut().unwrap().push(renamed);
        }
        fs::write(root.join(CASES), serde_json::to_vec(&cases).unwrap()).unwrap();
        write_manifest_with_refreshed_digest(&root, &manifest);
        let error = super::check_manifest(&root).unwrap_err();
        assert!(
            error.contains("case ID set changed: expected digest"),
            "unexpected validation error: {error}"
        );
        assert!(error.contains("update CASE_SET_SHA256"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_rejects_inventory_category_removal_after_digest_refresh() {
        let (root, manifest_path) = checked_in_contract_copy();
        let mut manifest = parse_strict_json(&fs::read(&manifest_path).unwrap(), super::MANIFEST).unwrap();
        manifest
            .pointer_mut("/inventory")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("legacy_metrics");
        write_manifest_with_refreshed_digest(&root, &manifest);
        let error = super::check_manifest(&root).unwrap_err();
        assert!(
            error.contains("inventory category legacy_metrics is missing"),
            "unexpected validation error: {error}"
        );
        assert!(error.contains("update REQUIRED_INVENTORY_CATEGORIES"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_rejects_inventory_claim_removal_after_digest_refresh() {
        let (root, manifest_path) = checked_in_contract_copy();
        assert!(super::check_manifest(&root).is_ok());
        let mut manifest = parse_strict_json(&fs::read(&manifest_path).unwrap(), super::MANIFEST).unwrap();
        // Delete one claim together with its coverage entry so the claims/coverage mapping
        // stays bijective and the category set is unchanged; only the claim-set digest
        // anchor can catch the shrink.
        manifest
            .pointer_mut("/inventory/legacy_metrics")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .retain(|claim| claim.as_str() != Some("waf_filter_tx_total"));
        manifest
            .pointer_mut("/inventory_coverage")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("waf_filter_tx_total");
        write_manifest_with_refreshed_digest(&root, &manifest);
        let error = super::check_manifest(&root).unwrap_err();
        assert!(
            error.contains("inventory claim set changed: expected digest"),
            "unexpected validation error: {error}"
        );
        assert!(error.contains("update INVENTORY_CLAIM_SET_SHA256"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_rejects_extra_inventory_categories_after_digest_refresh() {
        let (root, manifest_path) = checked_in_contract_copy();
        let mut manifest = parse_strict_json(&fs::read(&manifest_path).unwrap(), super::MANIFEST).unwrap();
        manifest
            .pointer_mut("/inventory")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra-category".to_owned(), json!(["extra claim"]));
        write_manifest_with_refreshed_digest(&root, &manifest);
        let error = super::check_manifest(&root).unwrap_err();
        assert!(
            error.contains("inventory category extra-category is not in the required category set"),
            "unexpected validation error: {error}"
        );
        assert!(error.contains("update REQUIRED_INVENTORY_CATEGORIES"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_rejects_case_ids_with_line_breaks() {
        let path = super::repository_root().join(super::MANIFEST);
        let bytes = read_limited(&path, super::MAX_MANIFEST_BYTES).unwrap();
        let mut manifest = parse_strict_json(&bytes, "manifest").unwrap();
        set_pointer(&mut manifest, "/cases/0/id", json!("config-\nempty"));
        assert!(
            super::parse_manifest(&manifest)
                .unwrap_err()
                .contains("must not contain line breaks")
        );
    }

    #[test]
    fn manifest_rejects_fixture_content_changes_after_digest_refresh() {
        let (root, manifest_path) = checked_in_contract_copy();
        assert!(super::check_manifest(&root).is_ok());
        let mut cases = parse_strict_json(&fs::read(root.join(CASES)).unwrap(), CASES).unwrap();
        // Append one space to config-whitespace's whitespace-only configuration: every
        // semantic and topic check still passes, so only the content anchor can catch it.
        let configuration = find_case_mut(cases.as_array_mut().unwrap(), "config-whitespace")
            .get_mut("plugin_configuration")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        find_case_mut(cases.as_array_mut().unwrap(), "config-whitespace")
            .as_object_mut()
            .unwrap()
            .insert("plugin_configuration".to_owned(), json!(format!("{configuration} ")));
        fs::write(root.join(CASES), serde_json::to_vec(&cases).unwrap()).unwrap();
        let manifest = parse_strict_json(&fs::read(&manifest_path).unwrap(), super::MANIFEST).unwrap();
        write_manifest_with_refreshed_digest(&root, &manifest);
        let error = super::check_manifest(&root).unwrap_err();
        assert!(
            error.contains("fixture content changed: expected digest"),
            "unexpected validation error: {error}"
        );
        assert!(error.contains("update CASES_FILE_SHA256"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_rejects_case_definition_changes_after_digest_refresh() {
        let (root, manifest_path) = checked_in_contract_copy();
        assert!(super::check_manifest(&root).is_ok());
        let mut manifest = parse_strict_json(&fs::read(&manifest_path).unwrap(), super::MANIFEST).unwrap();
        // Drop one required outcome field; the remaining field still passes the per-case
        // shape validation, so only the manifest-cases anchor can catch the weakening.
        find_case_mut(
            manifest.pointer_mut("/cases").unwrap().as_array_mut().unwrap(),
            "config-deprecated-rules",
        )
        .get_mut("required_outcome_fields")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .pop();
        write_manifest_with_refreshed_digest(&root, &manifest);
        let error = super::check_manifest(&root).unwrap_err();
        assert!(
            error.contains("manifest case definitions changed: expected digest"),
            "unexpected validation error: {error}"
        );
        assert!(error.contains("update MANIFEST_CASES_SHA256"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_rejects_contract_semantics_changes_after_digest_refresh() {
        let (root, manifest_path) = checked_in_contract_copy();
        assert!(super::check_manifest(&root).is_ok());
        let original = parse_strict_json(&fs::read(&manifest_path).unwrap(), super::MANIFEST).unwrap();

        // Retarget a source pin to another full commit ID; every other check accepts it
        // after a digest refresh, so only the code-side contract anchor can reject it.
        let mut manifest = original.clone();
        set_pointer(&mut manifest, "/pins/upstream_connector", json!("f".repeat(40)));
        write_manifest_with_refreshed_digest(&root, &manifest);
        let error = super::check_manifest(&root).unwrap_err();
        assert!(
            error.contains("contract semantics changed: expected digest"),
            "unexpected validation error: {error}"
        );
        assert!(error.contains("update CONTRACT_SHA256"), "{error}");

        // Remap one coverage topic (the tx-total claim now points at the interruption
        // topic, which is already declared under another claim, so the required-topic set
        // is unchanged and every semantic check passes); the contract anchor rejects it.
        let mut manifest = original;
        set_pointer(
            &mut manifest,
            "/inventory_coverage/waf_filter_tx_total",
            json!(["metrics.tx-total", "metrics.interruption"]),
        );
        write_manifest_with_refreshed_digest(&root, &manifest);
        assert!(
            super::check_manifest(&root)
                .unwrap_err()
                .contains("contract semantics changed"),
            "remapped coverage topics must be rejected by the contract anchor"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_rejects_observed_checkout_changes_after_digest_refresh() {
        let (root, manifest_path) = checked_in_contract_copy();
        assert!(super::check_manifest(&root).is_ok());
        let mut manifest = parse_strict_json(&fs::read(&manifest_path).unwrap(), super::MANIFEST).unwrap();
        // observed_checkouts is read by no validation code, so a rewritten provenance
        // field is invisible to every check except the contract anchor.
        set_pointer(&mut manifest, "/observed_checkouts/0/dirty", json!(true));
        write_manifest_with_refreshed_digest(&root, &manifest);
        let error = super::check_manifest(&root).unwrap_err();
        assert!(
            error.contains("contract semantics changed: expected digest"),
            "unexpected validation error: {error}"
        );
        assert!(error.contains("update CONTRACT_SHA256"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inventory_claims_and_categories_reject_digest_delimiters() {
        let path = super::repository_root().join(super::MANIFEST);
        let bytes = read_limited(&path, super::MAX_MANIFEST_BYTES).unwrap();
        let mut manifest = parse_strict_json(&bytes, "manifest").unwrap();
        manifest
            .pointer_mut("/inventory/legacy_metrics")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(json!("waf_filter_tx_total\ninjected"));
        assert!(
            super::parse_manifest(&manifest)
                .unwrap_err()
                .contains("must not contain line breaks or unit separators")
        );

        let mut manifest = parse_strict_json(&bytes, "manifest").unwrap();
        manifest
            .pointer_mut("/inventory")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("bad\u{1f}category".to_owned(), json!(["claim"]));
        let error = super::parse_manifest(&manifest).unwrap_err();
        assert!(
            error.contains("inventory category \"bad\\u{1f}category\" must not contain"),
            "unexpected validation error: {error}"
        );
    }

    #[test]
    fn inventory_categories_reject_duplicate_claims() {
        let path = super::repository_root().join(super::MANIFEST);
        let bytes = read_limited(&path, super::MAX_MANIFEST_BYTES).unwrap();
        let mut manifest = parse_strict_json(&bytes, "manifest").unwrap();
        let claims = manifest
            .pointer_mut("/inventory/legacy_metrics")
            .unwrap()
            .as_array_mut()
            .unwrap();
        let duplicated = claims.first().unwrap().clone();
        claims.push(duplicated);
        assert!(
            super::parse_manifest(&manifest)
                .unwrap_err()
                .contains("inventory legacy_metrics repeats claim waf_filter_tx_total")
        );
    }

    #[test]
    fn manifest_rejects_deferred_inventory_set_changes() {
        let path = super::repository_root().join(super::MANIFEST);
        let bytes = read_limited(&path, super::MAX_MANIFEST_BYTES).unwrap();
        // Removing an unlisted extra item keeps the required subset intact; only the set
        // digest catches the shrink.
        let mut manifest = parse_strict_json(&bytes, "manifest").unwrap();
        manifest
            .pointer_mut("/deferred_inventory")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .retain(|item| item.get("id").and_then(Value::as_str) != Some("bundle-file-provenance"));
        assert!(
            super::parse_manifest(&manifest)
                .unwrap_err()
                .contains("deferred inventory set changed")
        );

        let mut manifest = parse_strict_json(&bytes, "manifest").unwrap();
        manifest
            .pointer_mut("/deferred_inventory")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(json!({"id": "new-deferred-item", "reason": "newly deferred"}));
        assert!(
            super::parse_manifest(&manifest)
                .unwrap_err()
                .contains("deferred inventory set changed")
        );
    }

    #[test]
    fn manifest_requires_runtime_rule_data_resolution_to_remain_deferred() {
        let path = super::repository_root().join(super::MANIFEST);
        let bytes = read_limited(&path, super::MAX_MANIFEST_BYTES).unwrap();
        let mut manifest = parse_strict_json(&bytes, "manifest").unwrap();
        manifest
            .get_mut("deferred_inventory")
            .and_then(Value::as_array_mut)
            .unwrap()
            .retain(|item| item.get("id").and_then(Value::as_str) != Some("rule-data-runtime-resolution"));

        assert_eq!(
            super::parse_manifest(&manifest).unwrap_err(),
            "manifest deferred_inventory is missing rule-data-runtime-resolution"
        );
    }

    #[test]
    fn record_and_compare_apply_immutable_host_pins() {
        let manifest = super::check_manifest(super::repository_root()).unwrap();
        let root = test_dir();
        let missing_outcomes = root.join("missing-outcomes.json");
        let record_args = |host: &str| super::RecordArgs {
            host: host.to_owned(),
            role: "upstream".to_owned(),
            revision: manifest.pins.upstream_connector.clone(),
            artifact_sha256: "a".repeat(64),
            outcomes: missing_outcomes.clone(),
            output: root.join("capture.json"),
        };
        assert!(
            super::record(&record_args("standalone-envoy-1.40.0"))
                .unwrap_err()
                .contains("missing-outcomes.json")
        );
        for host in ["istio-1.30.5", "istio-1.30.7"] {
            assert!(
                super::record(&record_args(host))
                    .unwrap_err()
                    .contains("missing-outcomes.json")
            );
        }

        let make_capture = |host: &str, role: &str, revision: &str| {
            json!({
                "schema_version": 2,
                "host": host,
                "role": role,
                "revision": revision,
                "artifact_sha256": "b".repeat(64),
                "contract_sha256": manifest.contract_sha256,
                "outcomes": {}
            })
        };
        for host in ["standalone-envoy-1.40.0", "istio-1.30.5", "istio-1.30.7"] {
            let baseline = root.join(format!("{host}-baseline.json"));
            let candidate = root.join(format!("{host}-candidate.json"));
            fs::write(
                &baseline,
                serde_json::to_vec(&make_capture(host, "upstream", &manifest.pins.upstream_connector)).unwrap(),
            )
            .unwrap();
            fs::write(
                &candidate,
                serde_json::to_vec(&make_capture(host, "candidate", &"c".repeat(40))).unwrap(),
            )
            .unwrap();
            let args = super::CompareArgs {
                baseline,
                candidate,
                output: root.join(format!("{host}-mismatches.json")),
            };
            let error = super::compare(&args).unwrap_err();
            assert!(error.contains("outcome case inventory differs"), "{error}");
            assert!(!error.contains("immutable image digest pin"));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepts_only_lowercase_full_digests() {
        assert!(is_commit(&"a".repeat(40)));
        assert!(!is_commit(&"A".repeat(40)));
        assert!(is_sha256(&"b".repeat(64)));
        assert!(!is_sha256(&"b".repeat(63)));
    }

    #[test]
    fn host_ids_must_be_nonempty_nonwhitespace_and_unique() {
        assert!(validate_host_ids(&[]).is_err());
        for id in ["", " \t\n"] {
            assert!(
                validate_host_ids(&[Host {
                    id: id.to_owned(),
                    pinned: false,
                }])
                .is_err()
            );
        }
        assert!(
            validate_host_ids(&[
                Host {
                    id: "standalone".to_owned(),
                    pinned: true,
                },
                Host {
                    id: "istio".to_owned(),
                    pinned: false,
                },
            ])
            .is_ok()
        );
        assert!(
            validate_host_ids(&[
                Host {
                    id: "same".to_owned(),
                    pinned: false,
                },
                Host {
                    id: "same".to_owned(),
                    pinned: false,
                },
            ])
            .is_err()
        );
    }

    #[test]
    fn response_header_pairs_reject_null_and_compare_leaked_upstream_pairs() {
        let manifest = manifest_with_fields(
            "response",
            vec![required("response.headers", ObservationType::HeaderPairs)],
        );
        let baseline = json!({"response": {"headers": [["content-type", "text/plain"]]}});
        let candidate = json!({"response": {"headers": [
            ["content-type", "text/plain"], ["x-upstream-secret", "header-secret"]
        ]}});
        let baseline_outcomes = BTreeMap::from([("response".to_owned(), baseline.clone())]);
        let candidate_outcomes = BTreeMap::from([("response".to_owned(), candidate.clone())]);
        validate_outcomes(&manifest, "host", "upstream", &baseline_outcomes).unwrap();
        validate_outcomes(&manifest, "host", "candidate", &candidate_outcomes).unwrap();
        assert_eq!(
            compare_outcomes(
                &manifest,
                &capture("upstream", "response", baseline),
                &capture("candidate", "response", candidate),
            )
            .len(),
            1
        );

        let null_headers = BTreeMap::from([("response".to_owned(), json!({"response": {"headers": null}}))]);
        assert!(
            validate_outcomes(&manifest, "host", "candidate", &null_headers)
                .unwrap_err()
                .contains("response.headers must be an ordered array of header pairs")
        );

        let optional_backend = manifest_with_fields(
            "backend",
            vec![required(
                "backend.request.headers",
                ObservationType::OptionalHeaderPairs,
            )],
        );
        let absent_backend =
            BTreeMap::from([("backend".to_owned(), json!({"backend": {"request": {"headers": null}}}))]);
        validate_outcomes(&optional_backend, "host", "candidate", &absent_backend).unwrap();
    }

    #[test]
    fn metric_label_shapes_are_required_but_values_remain_comparable() {
        let manifest = manifest_with_fields(
            "metrics",
            vec![
                required("metrics.interruptions.delta", ObservationType::NonNegativeInteger),
                required("metrics.interruptions.labels.phase", ObservationType::String),
                required("metrics.interruptions.labels.rule_id", ObservationType::String),
                required("metrics.interruptions.labels.suite", ObservationType::String),
                required("metrics.interruptions.labels.env", ObservationType::String),
            ],
        );
        let baseline = json!({"metrics": {"interruptions": {
            "delta": 0,
            "labels": {"phase": "http_request_headers_identifier", "rule_id": "1030", "suite": "contract", "env": "qa"}
        }}});
        let candidate = json!({"metrics": {"interruptions": {
            "delta": 1,
            "labels": {"phase": "wrong-phase", "rule_id": "9999", "suite": "other", "env": "unknown"}
        }}});
        let baseline_outcomes = BTreeMap::from([("metrics".to_owned(), baseline.clone())]);
        let candidate_outcomes = BTreeMap::from([("metrics".to_owned(), candidate.clone())]);
        validate_outcomes(&manifest, "host", "upstream", &baseline_outcomes).unwrap();
        validate_outcomes(&manifest, "host", "candidate", &candidate_outcomes).unwrap();
        assert_eq!(
            compare_outcomes(
                &manifest,
                &capture("upstream", "metrics", baseline),
                &capture("candidate", "metrics", candidate),
            )
            .len(),
            1
        );

        for invalid in [
            json!({"metrics": {"interruptions": {"delta": 0, "labels": {"phase": 2, "rule_id": "1", "suite": "s", "env": "e"}}}}),
            json!({"metrics": {"interruptions": {"delta": "1", "labels": {"phase": "p", "rule_id": "1", "suite": "s", "env": "e"}}}}),
            json!({"metrics": {"interruptions": {"delta": 0, "labels": {"phase": "p", "suite": "s", "env": "e"}}}}),
        ] {
            let outcomes = BTreeMap::from([("metrics".to_owned(), invalid)]);
            assert!(validate_outcomes(&manifest, "host", "candidate", &outcomes).is_err());
        }
    }

    #[test]
    fn pr20_state_values_and_publication_order_are_recorded_without_expected_value_checks() {
        let manifest = manifest_with_fields(
            "state",
            vec![
                required("filter_state.event", ObservationType::String),
                required("filter_state.rule_id", ObservationType::String),
                required("filter_state.phase", ObservationType::String),
                required("filter_state.action", ObservationType::String),
                required("filter_state.status", ObservationType::String),
                required("filter_state.severity", ObservationType::String),
                required("filter_state.category", ObservationType::String),
                required("filter_state.client_ip", ObservationType::String),
                required("filter_state.publication_sequence", ObservationType::NonNegativeInteger),
                required("local_reply.sequence", ObservationType::NonNegativeInteger),
            ],
        );
        let on_time = json!({"filter_state": {
            "event": "coraza_waf_blocked_request", "rule_id": "1010", "phase": "http_request_headers",
            "action": "deny", "status": "403", "severity": "critical", "category": "sqli",
            "client_ip": "192.0.2.5", "publication_sequence": 1
        }, "local_reply": {"sequence": 2}});
        let late_and_wrong = json!({"filter_state": {
            "event": "unexpected", "rule_id": "9999", "phase": "wrong-phase", "action": "pass",
            "status": "200", "severity": "low", "category": "other", "client_ip": "198.51.100.4",
            "publication_sequence": 3
        }, "local_reply": {"sequence": 2}});
        let baseline_outcomes = BTreeMap::from([("state".to_owned(), on_time.clone())]);
        let candidate_outcomes = BTreeMap::from([("state".to_owned(), late_and_wrong.clone())]);
        validate_outcomes(&manifest, "host", "upstream", &baseline_outcomes).unwrap();
        validate_outcomes(&manifest, "host", "candidate", &candidate_outcomes).unwrap();
        assert_eq!(
            compare_outcomes(
                &manifest,
                &capture("upstream", "state", on_time),
                &capture("candidate", "state", late_and_wrong),
            )
            .len(),
            1
        );
    }

    #[test]
    fn json_outcomes_compare_structurally_and_preserve_array_order() {
        let left = BTreeMap::from([("case".to_owned(), json!({"headers": [["x", "1"], ["x", "2"]]}))]);
        let same = BTreeMap::from([("case".to_owned(), json!({"headers": [["x", "1"], ["x", "2"]]}))]);
        let reordered = BTreeMap::from([("case".to_owned(), json!({"headers": [["x", "2"], ["x", "1"]]}))]);
        assert_eq!(left, same);
        assert_ne!(left, reordered);
    }

    #[test]
    fn comparison_reports_only_reference_cases_that_differ() {
        let manifest = ContractManifest {
            schema_version: 2,
            contract_sha256: String::new(),
            hosts: vec![Host {
                id: "host".to_owned(),
                pinned: false,
            }],
            cases: vec![CaseRef {
                id: "case".to_owned(),
                reference: "upstream".to_owned(),
                hosts: vec!["host".to_owned()],
                required_outcome_fields: vec![required("response.status", ObservationType::HttpStatus)],
            }],
            inventory_coverage: BTreeMap::new(),
            deferred_inventory: Vec::new(),
            pins: Pins {
                upstream_connector: String::new(),
                pr20_head: String::new(),
            },
        };
        let baseline = Capture {
            schema_version: 2,
            host: "host".to_owned(),
            role: "upstream".to_owned(),
            revision: String::new(),
            artifact_sha256: String::new(),
            contract_sha256: String::new(),
            outcomes: BTreeMap::from([("case".to_owned(), json!({"status": 403}))]),
        };
        let mut candidate = Capture {
            schema_version: 2,
            host: "host".to_owned(),
            role: "candidate".to_owned(),
            revision: String::new(),
            artifact_sha256: String::new(),
            contract_sha256: String::new(),
            outcomes: BTreeMap::from([("case".to_owned(), json!({"status": 200}))]),
        };
        assert_eq!(compare_outcomes(&manifest, &baseline, &candidate).len(), 1);
        candidate.outcomes.insert("case".to_owned(), json!({"status": 403}));
        assert!(compare_outcomes(&manifest, &baseline, &candidate).is_empty());
    }

    #[test]
    fn mismatch_ledger_rows_include_capture_and_fixture_provenance() {
        let baseline_outcome = json!({"response": {"status": 403}});
        let candidate_outcome = json!({"response": {"status": 200}});
        let mut baseline = capture("upstream", "case", baseline_outcome.clone());
        baseline.host = "standalone".to_owned();
        baseline.revision = "a".repeat(40);
        baseline.artifact_sha256 = "b".repeat(64);
        baseline.contract_sha256 = "c".repeat(64);
        let mut candidate = capture("candidate", "case", candidate_outcome.clone());
        candidate.host = "standalone".to_owned();
        candidate.revision = "d".repeat(40);
        candidate.artifact_sha256 = "e".repeat(64);
        candidate.contract_sha256 = "c".repeat(64);
        let mismatches = [super::Mismatch {
            case_id: "case".to_owned(),
            baseline: Some(&baseline_outcome),
            candidate: Some(&candidate_outcome),
        }];
        let fixture_hashes = BTreeMap::from([("case".to_owned(), "f".repeat(64))]);
        let contract_sha256 = "c".repeat(64);
        let ledger =
            super::mismatch_ledger(&contract_sha256, &baseline, &candidate, &mismatches, &fixture_hashes).unwrap();
        let mismatch = ledger.pointer("/mismatches/0").expect("one mismatch row");
        assert_eq!(
            mismatch.pointer("/fixture_sha256").and_then(Value::as_str),
            Some("f".repeat(64).as_str())
        );
        assert_eq!(
            mismatch.pointer("/contract_sha256").and_then(Value::as_str),
            Some("c".repeat(64).as_str())
        );
        assert_eq!(
            mismatch.pointer("/baseline/artifact_sha256").and_then(Value::as_str),
            Some("b".repeat(64).as_str())
        );
        assert_eq!(
            mismatch.pointer("/candidate/artifact_sha256").and_then(Value::as_str),
            Some("e".repeat(64).as_str())
        );
        assert_eq!(
            mismatch.pointer("/baseline/revision").and_then(Value::as_str),
            Some("a".repeat(40).as_str())
        );
        assert_eq!(
            mismatch.pointer("/candidate/revision").and_then(Value::as_str),
            Some("d".repeat(40).as_str())
        );
        assert_eq!(mismatch.pointer("/baseline/outcome"), Some(&baseline_outcome));
        assert_eq!(mismatch.pointer("/candidate/outcome"), Some(&candidate_outcome));
    }

    #[test]
    fn numeric_observation_path_segments_address_object_keys() {
        let manifest = manifest_with_fields("numeric-key", vec![required("123", ObservationType::String)]);
        let outcomes = BTreeMap::from([("numeric-key".to_owned(), json!({"123": "observed"}))]);
        validate_outcomes(&manifest, "host", "candidate", &outcomes).unwrap();
    }

    #[test]
    fn inventory_topics_require_fixture_coverage() {
        let coverage = BTreeMap::from([(
            "claim".to_owned(),
            vec![
                "lifecycle.allow".to_owned(),
                "lifecycle.request-interruption".to_owned(),
            ],
        )]);
        let cases = vec![
            parse_fixture_case(&json!({
                "id": "case",
                "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On"]},"default_directives":"default"}"#,
                "request": {"method": "GET", "path": "/"},
                "topics": ["lifecycle.allow"]
            }))
            .unwrap(),
        ];
        let error = validate_inventory_coverage(&coverage, &cases).unwrap_err();
        assert!(error.contains("inventory topic lifecycle.request-interruption has no executable fixture case"));
    }

    #[test]
    fn topic_inputs_and_plugin_configuration_are_checked() {
        let coverage = BTreeMap::from([("claim".to_owned(), vec!["engine.multiphase".to_owned()])]);
        let case = parse_fixture_case(&json!({
            "id": "multiphase",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@contains attack\" \"id:1,phase:2,deny\""]}}"#,
            "request": {"method": "POST", "path": "/", "body_base64": "YXR0YWNr"},
            "topics": ["engine.multiphase"]
        }))
        .unwrap();
        let error = validate_inventory_coverage(&coverage, &[case]).unwrap_err();
        assert!(error.contains("topic engine.multiphase lacks its required input"));

        let error = parse_fixture_case(&json!({
            "id": "bad-config",
            "plugin_configuration": "not JSON",
            "topics": ["config.default-policy"]
        }))
        .unwrap_err();
        assert!(error.contains("plugin_configuration must be valid JSON"));

        let error = parse_fixture_case(&json!({
            "id": "duplicate-config-key",
            "plugin_configuration": r#"{"nested":{"key":1,"key":2}}"#,
            "topics": ["config.default-policy"]
        }))
        .unwrap_err();
        assert!(error.contains("duplicate JSON object key key"));
    }

    #[test]
    fn malformed_directive_shapes_are_fixtureable_but_never_rule_evidence() {
        let coverage = BTreeMap::from([("claim".to_owned(), vec!["lifecycle.request-interruption".to_owned()])]);
        for directives in [
            json!(["SecRuleEngine On", {"ignored": "value"}, r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:1,deny""#]),
            json!({"engine": "SecRuleEngine On", "rule": r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:1,deny""#}),
        ] {
            let case = json!({
                "id": "malformed-directive-shape",
                "plugin_configuration": json!({
                    "directives_map": {"default": directives},
                    "default_directives": "default"
                }).to_string(),
                "request": {"method": "GET", "path": "/deny"},
                "topics": ["lifecycle.request-interruption"]
            });
            assert_topic_rejected(&case);
        }

        let case = parse_fixture_case(&json!({
            "id": "container-directive-elements",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On",{"directive":"rule"},["nested"]]},"default_directives":"default"}"#,
            "topics": ["config.directives-map-array-containers"]
        }))
        .unwrap();
        assert!(super::topic_has_required_input(&case, "config.directives-map-array-containers").unwrap());

        let case = parse_fixture_case(&json!({
            "id": "non-string-deprecated-rule",
            "plugin_configuration": r#"{"rules":["SecRuleEngine On",7]}"#,
            "topics": ["config.default-policy"]
        }))
        .unwrap();
        let error = validate_inventory_coverage(&coverage, &[case]).unwrap_err();
        assert!(
            error.contains("fixture case non-string-deprecated-rule plugin_configuration rules[1] must be a string")
        );
    }

    #[test]
    fn malformed_policy_selectors_cannot_fall_back_to_lifecycle_rules() {
        let invalid_directives_map = json!({
            "id": "invalid-directives-map-with-rules",
            "plugin_configuration": json!({
                "directives_map": "not-a-map",
                "rules": ["SecRuleEngine On", r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:1,deny,status:403""#]
            }).to_string(),
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.request-interruption"]
        });
        let case = parse_fixture_case(&invalid_directives_map).unwrap();
        assert!(super::request_policy_name(&case).is_none());
        assert!(super::request_policy_directives(&case).is_empty());
        assert_topic_rejected(&invalid_directives_map);

        let invalid_authority_value = json!({
            "id": "invalid-authority-entry-with-default",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /deny\" \"id:2,phase:1,deny,status:403\""]},"default_directives":"default","per_authority_directives":{"waf.example":{"policy":"default"}}}"#,
            "request": {"method": "GET", "path": "/deny", "authority": "waf.example"},
            "topics": ["lifecycle.request-interruption"]
        });
        let case = parse_fixture_case(&invalid_authority_value).unwrap();
        assert!(super::request_policy_name(&case).is_none());
        assert!(super::request_policy_directives(&case).is_empty());
        assert_topic_rejected(&invalid_authority_value);

        let invalid_authority_map = json!({
            "id": "invalid-authority-map-with-default",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /deny\" \"id:3,phase:1,deny,status:403\""]},"default_directives":"default","per_authority_directives":[]}"#,
            "request": {"method": "GET", "path": "/deny", "authority": "waf.example"},
            "topics": ["lifecycle.request-interruption"]
        });
        let case = parse_fixture_case(&invalid_authority_map).unwrap();
        assert!(super::request_policy_name(&case).is_none());
        assert_topic_rejected(&invalid_authority_map);

        let unused_object_policy = json!({
            "id": "unused-object-policy",
            "plugin_configuration": json!({
                "directives_map": {
                    "default": ["SecRuleEngine On", r#"SecRule REQUEST_URI "@streq /deny" "id:4,phase:1,deny,status:403""#],
                    "unused": {"nested": "policy"}
                },
                "default_directives": "default"
            }).to_string(),
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.request-interruption"]
        });
        let case = parse_fixture_case(&unused_object_policy).unwrap();
        assert!(super::request_policy_directives(&case).is_empty());
        assert_topic_rejected(&unused_object_policy);

        let missing_authority_reference = json!({
            "id": "unused-missing-authority-reference",
            "plugin_configuration": json!({
                "directives_map": {
                    "default": ["SecRuleEngine On", r#"SecRule REQUEST_URI "@streq /deny" "id:5,phase:1,deny,status:403""#]
                },
                "default_directives": "default",
                "per_authority_directives": {"unused.example": "missing"}
            }).to_string(),
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.request-interruption"]
        });
        let case = parse_fixture_case(&missing_authority_reference).unwrap();
        assert!(super::request_policy_directives(&case).is_empty());
        assert_topic_rejected(&missing_authority_reference);

        let object_shape = parse_fixture_case(&json!({
            "id": "object-policy-shape",
            "plugin_configuration": json!({
                "directives_map": {"default": {"nested": "policy"}},
                "default_directives": "default"
            }).to_string(),
            "topics": ["config.directives-map-policy-object"]
        }))
        .unwrap();
        assert_eq!(
            super::topic_has_required_input(&object_shape, "config.directives-map-policy-object"),
            Some(true)
        );

        let reference_shape = parse_fixture_case(&json!({
            "id": "missing-authority-reference-shape",
            "plugin_configuration": json!({
                "directives_map": {"default": ["SecRuleEngine On"]},
                "default_directives": "default",
                "per_authority_directives": {"waf.example": "missing"}
            }).to_string(),
            "topics": ["config.authority-missing-policy-reference"]
        }))
        .unwrap();
        assert_eq!(
            super::topic_has_required_input(&reference_shape, "config.authority-missing-policy-reference"),
            Some(true)
        );
    }

    #[test]
    fn dangling_default_reference_does_not_fall_back_to_legacy_rules() {
        let fixture = json!({
            "id": "legacy-rules-dangling-default-reference",
            "plugin_configuration": json!({
                "rules": [
                    "SecRuleEngine On",
                    r#"SecRule REQUEST_URI "@streq /deny" "id:6,phase:1,deny,status:403""#
                ],
                "default_directives": "missing"
            }).to_string(),
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.request-interruption"]
        });
        let case = parse_fixture_case(&fixture).unwrap();
        assert!(!super::policy_selectors_well_formed(&case.plugin_configuration));
        assert!(super::request_policy_name(&case).is_none());
        assert!(super::request_policy_directives(&case).is_empty());
        assert_topic_rejected(&fixture);
    }

    #[test]
    fn root_scalar_topic_rejects_blank_input_but_keeps_json_scalars() {
        let whitespace = parse_fixture_case(&json!({
            "id": "blank-root-scalar",
            "plugin_configuration": " \n\t ",
            "request": {"method": "GET", "path": "/root-scalar"},
            "topics": ["config.root-scalar"]
        }))
        .unwrap();
        assert!(whitespace.plugin_configuration.is_null());
        assert_eq!(whitespace.raw_plugin_configuration, " \n\t ");
        assert_eq!(
            super::topic_has_required_input(&whitespace, "config.root-scalar"),
            Some(false)
        );

        for raw in ["null", "true", "0", "\"scalar\""] {
            let scalar = parse_fixture_case(&json!({
                "id": "valid-root-scalar",
                "plugin_configuration": raw,
                "request": {"method": "GET", "path": "/root-scalar"},
                "topics": ["config.root-scalar"]
            }))
            .unwrap();
            assert_eq!(
                super::topic_has_required_input(&scalar, "config.root-scalar"),
                Some(true),
                "{raw}"
            );
        }
    }

    #[test]
    fn empty_configuration_topics_keep_the_raw_input_distinct() {
        for (id, raw) in [
            ("config-empty", ""),
            ("config-whitespace", " \n\t "),
            ("config-empty-object", "{}"),
        ] {
            let case = parse_fixture_case(&json!({
                "id": id,
                "plugin_configuration": raw,
                "topics": ["config.default-policy"]
            }))
            .unwrap();
            assert_eq!(case.raw_plugin_configuration, raw);
            assert_eq!(
                super::topic_has_required_input(&case, "config.default-policy"),
                Some(true),
                "{id}"
            );
        }

        let changed_whitespace_case = parse_fixture_case(&json!({
            "id": "config-whitespace",
            "plugin_configuration": "null",
            "topics": ["config.default-policy"]
        }))
        .unwrap();
        assert_eq!(
            super::topic_has_required_input(&changed_whitespace_case, "config.default-policy"),
            Some(false)
        );
    }

    #[test]
    fn ignored_unknown_config_keys_cannot_supply_topic_directives() {
        let coverage = BTreeMap::from([("claim".to_owned(), vec!["engine.regex-capture".to_owned()])]);
        let case = parse_fixture_case(&json!({
            "id": "ignored-directive",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On"]},"unknown":{"value":"@rx ^/item-([0-9]+)$ phase:1,pass,capture"}}"#,
            "request": {"method": "GET", "path": "/item-42"},
            "topics": ["engine.regex-capture"]
        }))
        .unwrap();
        assert!(
            validate_inventory_coverage(&coverage, &[case])
                .unwrap_err()
                .contains("topic engine.regex-capture lacks its required input")
        );

        let inactive_policy = parse_fixture_case(&json!({
            "id": "inactive-directives",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@rx ^/item-([0-9]+)$\" \"id:2,phase:1,pass,capture\""],"selected":["SecRuleEngine On"]},"default_directives":"selected","rules":["SecRule REQUEST_URI \"@rx ^/item-([0-9]+)$\" \"id:3,phase:1,pass,capture\""]}"#,
            "request": {"method": "GET", "path": "/item-42"},
            "topics": ["engine.regex-capture"]
        }))
        .unwrap();
        assert!(
            validate_inventory_coverage(&coverage, &[inactive_policy])
                .unwrap_err()
                .contains("topic engine.regex-capture lacks its required input")
        );

        let reload_coverage = BTreeMap::from([("claim".to_owned(), vec!["lifecycle.reload".to_owned()])]);
        let reload_case = parse_fixture_case(&json!({
            "id": "ignored-reload-directive",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /reload-deny\" \"id:1,phase:1,deny\""]},"default_directives":"default"}"#,
            "reload_plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On"]},"default_directives":"default","unknown":"SecRuleEngine DetectionOnly"}"#,
            "request": {"method": "GET", "path": "/reload-deny"},
            "host_scenarios": ["reload-with-inflight-stream"],
            "topics": ["lifecycle.reload"]
        }))
        .unwrap();
        assert!(
            validate_inventory_coverage(&reload_coverage, &[reload_case])
                .unwrap_err()
                .contains("topic lifecycle.reload lacks its required input")
        );
    }

    #[test]
    fn chain_topic_rejects_request_predicates_spoofed_inside_msg() {
        let coverage = BTreeMap::from([("claim".to_owned(), vec!["engine.chains-controls".to_owned()])]);
        let case = parse_fixture_case(&json!({
            "id": "spoofed-chain",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /never\" \"id:1005,phase:1,pass,chain,msg:'REQUEST_URI @streq /chain'\"","SecRule REQUEST_METHOD \"@streq POST\" \"ctl:ruleEngine=Off,msg:'REQUEST_METHOD @streq GET,ctl:ruleEngine=Off'\"","SecRule REQUEST_URI \"@streq /chain\" \"id:1006,phase:1,deny,status:403\""]}}"#,
            "request": {"method": "GET", "path": "/chain"},
            "topics": ["engine.chains-controls"]
        }))
        .unwrap();
        assert!(
            validate_inventory_coverage(&coverage, &[case])
                .unwrap_err()
                .contains("topic engine.chains-controls lacks its required input")
        );
    }

    #[test]
    fn active_policy_predicates_cannot_be_spoofed_by_msg_actions() {
        assert_topic_rejected(&json!({
            "id": "spoofed-directive-order",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /wrong\" \"id:1002,phase:1,pass,log,msg:'@streq /ordered'\"","SecRule REQUEST_URI \"@streq /ordered\" \"id:1003,phase:1,pass,log\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/ordered"},
            "topics": ["config.directive-order"]
        }));
        assert_topic_rejected(&json!({
            "id": "spoofed-detection-only",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /wrong\" \"id:1008,phase:1,deny,status:403,msg:'SecRuleEngine DetectionOnly @streq /deny'\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.detection-only"]
        }));
        assert_topic_rejected(&json!({
            "id": "spoofed-regex-capture",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /wrong\" \"id:1034,phase:1,pass,capture,setvar:tx.item=%{TX.1},logdata:%{TX.item},msg:'@rx ^/item-([0-9]+)$'\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/item-42"},
            "topics": ["engine.regex-capture"]
        }));
        assert_topic_rejected(&json!({
            "id": "spoofed-phase-five",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecAction \"id:1032,phase:1,pass,log,msg:'phase:5,log,msg:phase-five-ran'\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/"},
            "topics": ["engine.phase-5"]
        }));
        assert_topic_rejected(&json!({
            "id": "unconditional-deny-is-not-benign",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecAction \"id:1,phase:1,deny\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/"},
            "topics": ["lifecycle.allow"]
        }));
        assert_topic_rejected(&json!({
            "id": "unsupported-variable-deny-is-not-benign",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_HEADERS:X \"@streq attack\" \"id:2,phase:1,deny\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/safe", "headers": [["x", "attack"]]},
            "topics": ["lifecycle.allow"]
        }));
        assert_topic_rejected(&json!({
            "id": "spoofed-interruption-metrics",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /deny\" \"id:1030,phase:1,pass,msg:'deny'\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["metrics.interruption"]
        }));
        assert_topic_rejected(&json!({
            "id": "spoofed-relative-rule-data",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","Include rules/relative.conf"]},"default_directives":"default","rule_data":{"rules/relative.conf":"SecRule ARGS \"@streq attack\" \"id:1033,phase:2,deny,status:403,msg:'@pmFromFile data/needles.txt'\"\n","data/needles.txt":"attack\n"}}"#,
            "request": {"method": "POST", "path": "/", "headers": [["content-type", "application/x-www-form-urlencoded"]], "body_base64": "dGVybT1hdHRhY2s="},
            "topics": ["bundle.relative-data"]
        }));
        assert_topic_rejected(&json!({
            "id": "spoofed-multiphase-child",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecAction \"id:1006,phase:1,pass,setvar:tx.blocking_paranoia_level=1\"","SecRule TX:blocking_paranoia_level \"@eq 1\" \"id:1007,phase:2,deny,status:403,chain\"","SecRule REQUEST_URI \"@streq /wrong\" \"t:none,msg:'@streq /early-block'\""]},"default_directives":"default"}"#,
            "request": {"method": "POST", "path": "/early-block", "headers": [["content-type", "text/plain"]]},
            "host_scenarios": ["await-early-response-before-request-body-complete"],
            "topics": ["engine.multiphase"]
        }));
    }

    #[test]
    fn engine_predicate_uses_the_last_ordered_mode() {
        let case = parse_fixture_case(&json!({
            "id": "ordered-engine-mode",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRuleEngine OFF"]},"default_directives":"default"}"#,
            "topics": ["config.default-policy"]
        }))
        .unwrap();
        assert!(!super::policy_has_engine(&case, "default", "On"));
        assert!(super::policy_has_engine(&case, "default", "Off"));
    }

    #[test]
    fn lifecycle_allow_rejects_unsupported_variable_deny_at_default_phase() {
        assert_topic_rejected(&json!({
            "id": "unsupported-variable-deny-default-phase",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_HEADERS:X \"@streq attack\" \"id:3,deny\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/safe", "headers": [["x", "attack"]]},
            "topics": ["lifecycle.allow"]
        }));
    }

    #[test]
    fn lifecycle_allow_rejects_matching_deny_at_default_phase() {
        assert_topic_rejected(&json!({
            "id": "matching-deny-default-phase",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /deny\" \"id:4,deny\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.allow"]
        }));
    }

    #[test]
    fn lifecycle_allow_uses_effective_case_insensitive_disruptive_actions() {
        let rule = |actions: &str| {
            json!({
                "id": "effective-action",
                "plugin_configuration": json!({
                    "directives_map": {"default": [
                        "SecRuleEngine On",
                        format!(r#"SecRule REQUEST_URI "@streq /deny" "id:4,phase:1,{actions}""#)
                    ]},
                    "default_directives": "default"
                }).to_string(),
                "request": {"method": "GET", "path": "/deny"},
                "topics": ["lifecycle.allow"]
            })
        };

        assert_topic_rejected(&rule("redirect:'https://example.test/'"));
        assert_topic_rejected(&rule("DENY"));
        assert_topic_rejected(&rule("pass,DENY"));
        assert_topic_rejected(&rule("deny:bogus"));
        assert_topic_accepted(&rule("deny,pass"));
        assert_topic_accepted(&rule("deny,allow"));
    }

    #[test]
    fn action_splitting_rejects_unbalanced_quotes_and_trailing_escapes() {
        assert!(super::for_each_action("id:1,phase:1,deny,msg:'unterminated,pass", |_| {}).is_err());
        assert!(super::for_each_action("id:1,phase:1,deny,msg:tail\\", |_| {}).is_err());

        assert_topic_rejected(&json!({
            "id": "unbalanced-action-quote",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /deny\" \"id:1,phase:1,deny,status:403,msg:'unterminated,pass\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.request-interruption"]
        }));
    }

    #[test]
    fn disruptive_action_arguments_match_coraza_forms() {
        assert!(matches!(
            super::effective_disruptive_action("allow"),
            Ok(Some(super::EffectiveDisruptiveAction::Allow))
        ));
        assert!(matches!(
            super::effective_disruptive_action("allow:phase"),
            Ok(Some(super::EffectiveDisruptiveAction::Allow))
        ));
        assert!(matches!(
            super::effective_disruptive_action("allow:'request'"),
            Ok(Some(super::EffectiveDisruptiveAction::Allow))
        ));
        assert!(matches!(
            super::effective_disruptive_action("redirect:'https://example.test/'"),
            Ok(Some(super::EffectiveDisruptiveAction::Redirect))
        ));
        for action in [
            "allow:other",
            "redirect",
            "redirect:''",
            "deny:bogus",
            "drop:bogus",
            "pass:bogus",
            "block:bogus",
        ] {
            assert!(super::effective_disruptive_action(action).is_err(), "{action}");
        }
    }

    #[test]
    fn direct_rule_topics_use_the_effective_phase() {
        assert_topic_rejected(&json!({
            "id": "detection-only-effective-phase",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine DetectionOnly","SecRule REQUEST_URI \"@streq /deny\" \"id:1008,phase:1,phase:4,deny,status:403\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.detection-only"]
        }));
        assert_topic_rejected(&json!({
            "id": "multiphase-effective-phase",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecAction \"id:1006,phase:1,pass,setvar:tx.blocking_paranoia_level=1\"","SecRule TX:blocking_paranoia_level \"@eq 1\" \"id:1007,phase:2,phase:4,deny,status:403,chain\"","SecRule REQUEST_URI \"@streq /early-block\" \"t:none\""]},"default_directives":"default"}"#,
            "request": {"method": "POST", "path": "/early-block", "headers": [["content-type", "text/plain"]]},
            "host_scenarios": ["await-early-response-before-request-body-complete"],
            "topics": ["engine.multiphase"]
        }));
    }

    #[test]
    fn lifecycle_engine_and_rule_predicates_share_the_selected_policy() {
        assert_topic_accepted(&json!({
            "id": "authority-selected-detection-only",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /other\" \"id:1008,phase:1,deny,status:403\""],"authority":["SecRuleEngine DetectionOnly","SecRule REQUEST_URI \"@streq /deny\" \"id:1008,phase:1,deny,status:403\""]},"default_directives":"default","per_authority_directives":{"waf.example":"authority"}}"#,
            "request": {"method": "GET", "path": "/deny", "authority": "waf.example"},
            "topics": ["lifecycle.detection-only"]
        }));
    }

    #[test]
    fn lifecycle_matcher_keeps_unmodeled_inputs_unsupported() {
        let cases = [
            (
                "unknown-variable",
                r#"SecRule REQUEST_HEADERS:X "@streq attack" "id:1,phase:1,deny""#,
                json!({"method": "GET", "path": "/safe", "headers": [["x", "attack"]]}),
            ),
            (
                "unknown-operator",
                r#"SecRule REQUEST_URI "@contains deny" "id:1,phase:1,deny""#,
                json!({"method": "GET", "path": "/deny"}),
            ),
            (
                "unsupported-transform",
                r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:1,deny,t:lowercase""#,
                json!({"method": "GET", "path": "/deny"}),
            ),
            (
                "unknown-form-body-encoding",
                r#"SecRule ARGS "@streq attack" "id:1,phase:2,deny""#,
                json!({"method": "POST", "path": "/", "headers": [["content-type", "application/x-www-form-urlencoded"]], "body_base64": "Zm9v"}),
            ),
        ];
        for (id, rule, request) in cases {
            let case_value = json!({
                "id": id,
                "plugin_configuration": json!({"directives_map": {"default": ["SecRuleEngine On", rule]}, "default_directives": "default"}).to_string(),
                "request": request,
                "topics": ["lifecycle.allow"]
            });
            let case = parse_fixture_case(&case_value).unwrap();
            let directive = super::request_policy_directives(&case)
                .into_iter()
                .find(|directive| super::directive_is_named(directive, "SecRule"))
                .unwrap();
            assert_eq!(
                super::request_matches_rule(&case, directive),
                super::RequestRuleMatch::Unsupported
            );
            assert_topic_rejected(&case_value);
        }
    }

    #[test]
    fn byte_exact_and_duplicate_header_topics_require_the_complete_request() {
        let byte_exact = json!({
            "id": "byte-exact-input",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On"]},"default_directives":"default"}"#,
            "request": {"method": "POST", "path": "/echo", "headers": [["x-repeat", "one"], ["x-repeat", "two"]], "body_base64": "AAECAwQ="},
            "topics": ["http.byte-exact"]
        });
        assert_topic_accepted(&byte_exact);
        for field in ["method", "body_base64", "headers"] {
            let mut missing = byte_exact.clone();
            remove_object_field(&mut missing, "request", field);
            assert_topic_rejected(&missing);
        }

        let duplicate_headers = json!({
            "id": "duplicate-header-input",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On"]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/", "headers": [["cookie", "a=1"], ["cookie", "b=2"], ["x-repeat", "one"], ["x-repeat", "two"]], "body_base64": "AAECAwQ="},
            "topics": ["http.duplicate-headers"]
        });
        assert_topic_accepted(&duplicate_headers);
        for field in ["method", "body_base64", "headers"] {
            let mut missing = duplicate_headers.clone();
            remove_object_field(&mut missing, "request", field);
            assert_topic_rejected(&missing);
        }
        let mut reordered = duplicate_headers;
        reordered
            .get_mut("request")
            .and_then(Value::as_object_mut)
            .and_then(|request| request.get_mut("headers"))
            .and_then(Value::as_array_mut)
            .expect("request headers must be an array")
            .swap(0, 1);
        assert_topic_rejected(&reordered);
    }

    #[test]
    fn response_header_and_trailer_topics_require_status_and_body() {
        let base = json!({
            "id": "response-input",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On"]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/response-trailers"},
            "backend_response": {"status": 201, "headers": [["content-type", "text/plain"], ["x-response", "one"]], "body_base64": "cmVzcG9uc2U=", "trailers": [["x-response-end", "done"]]},
            "topics": ["lifecycle.response-headers"]
        });
        assert_topic_accepted(&base);
        for field in ["status", "body_base64"] {
            let mut missing = base.clone();
            remove_object_field(&mut missing, "backend_response", field);
            assert_topic_rejected(&missing);
        }
        let mut trailers = base;
        *trailers.get_mut("topics").expect("topics must be present") = json!(["lifecycle.response-trailers"]);
        assert_topic_accepted(&trailers);
        for field in ["status", "body_base64"] {
            let mut missing = trailers.clone();
            remove_object_field(&mut missing, "backend_response", field);
            assert_topic_rejected(&missing);
        }
    }

    #[test]
    fn phase_three_probe_has_a_response_header_pause_and_nonempty_body() {
        let valid = json!({
            "id": "phase-three-response-header",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule RESPONSE_HEADERS:x-phase \"@streq block\" \"id:1080,phase:3,deny,status:403\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/phase-three"},
            "backend_response": {
                "status": 200,
                "headers": [["content-type", "text/plain"], ["x-phase", "block"]],
                "body_base64": "cGhhc2UtdGhyZWUtYm9keQ=="
            },
            "host_scenarios": ["pause-after-response-headers-before-body"],
            "topics": ["engine.phase-three"]
        });
        assert_topic_accepted(&valid);

        let mut empty_body = valid.clone();
        empty_body
            .get_mut("backend_response")
            .and_then(Value::as_object_mut)
            .unwrap()
            .insert("body_base64".to_owned(), json!(""));
        assert_topic_rejected(&empty_body);

        let mut no_pause = valid;
        no_pause.as_object_mut().unwrap().remove("host_scenarios");
        assert_topic_rejected(&no_pause);
    }

    #[test]
    fn backend_request_schemas_require_method_and_path() {
        let incomplete = CaseRef {
            id: "backend-observations".to_owned(),
            reference: "upstream".to_owned(),
            hosts: vec!["host".to_owned()],
            required_outcome_fields: vec![
                required("backend.received", ObservationType::Boolean),
                required("backend.request.body_base64", ObservationType::OptionalString),
            ],
        };
        assert!(
            super::validate_backend_request_schema(&incomplete)
                .unwrap_err()
                .contains("must require backend.request.method")
        );
    }

    #[test]
    fn backend_request_fields_are_nonnull_when_the_backend_received_the_request() {
        let manifest = manifest_with_fields(
            "backend",
            vec![
                required("backend.received", ObservationType::Boolean),
                required("backend.request.method", ObservationType::OptionalString),
                required("backend.request.path", ObservationType::OptionalString),
                required("backend.request.body_base64", ObservationType::OptionalString),
            ],
        );
        let absent = BTreeMap::from([(
            "backend".to_owned(),
            json!({
                "backend": {
                    "received": false,
                    "request": {"method": null, "path": null, "body_base64": null}
                }
            }),
        )]);
        assert!(validate_outcomes(&manifest, "host", "upstream", &absent).is_ok());

        let received_with_null = BTreeMap::from([(
            "backend".to_owned(),
            json!({
                "backend": {
                    "received": true,
                    "request": {"method": "POST", "path": "/", "body_base64": null}
                }
            }),
        )]);
        assert!(
            validate_outcomes(&manifest, "host", "upstream", &received_with_null)
                .unwrap_err()
                .contains("backend.request.body_base64 must not be null")
        );
    }

    #[test]
    fn outcome_base64_fields_accept_empty_and_payloads_but_reject_bad_alphabet_or_padding() {
        let manifest = manifest_with_fields(
            "encoded",
            vec![required("response.body_base64", ObservationType::OptionalString)],
        );
        for body in ["", "AAECAwQ=", "cGhhc2UtdGhyZWUtYm9keQ=="] {
            let outcomes = BTreeMap::from([("encoded".to_owned(), json!({"response": {"body_base64": body}}))]);
            assert!(
                validate_outcomes(&manifest, "host", "upstream", &outcomes).is_ok(),
                "{body}"
            );
        }
        for body in ["Y$==", "YQ=", "Y==="] {
            let outcomes = BTreeMap::from([("encoded".to_owned(), json!({"response": {"body_base64": body}}))]);
            assert!(
                validate_outcomes(&manifest, "host", "upstream", &outcomes)
                    .unwrap_err()
                    .contains("must be valid Base64"),
                "{body}"
            );
        }
        let null = BTreeMap::from([("encoded".to_owned(), json!({"response": {"body_base64": null}}))]);
        assert!(validate_outcomes(&manifest, "host", "upstream", &null).is_ok());

        let extra_bad_field = BTreeMap::from([(
            "encoded".to_owned(),
            json!({
                "response": {
                    "body_base64": "",
                    "diagnostic_payload_base64": "Y$=="
                }
            }),
        )]);
        assert!(
            validate_outcomes(&manifest, "host", "upstream", &extra_bad_field)
                .unwrap_err()
                .contains("response.diagnostic_payload_base64 must be valid Base64")
        );
    }

    #[test]
    fn fixture_input_base64_fields_are_validated_recursively() {
        let fixture = || {
            json!({
                "id": "fixture-input-base64",
                "plugin_configuration": "{}",
                "request": {
                    "method": "POST",
                    "path": "/",
                    "body_base64": "",
                    "metadata": [{"payload_base64": ""}]
                },
                "backend_response": {"status": 200, "body_base64": ""},
                "topics": ["input.base64"]
            })
        };

        let mut malformed_request = fixture();
        set_pointer(&mut malformed_request, "/request/body_base64", json!("Y$=="));
        let error = parse_fixture_case(&malformed_request).unwrap_err();
        assert!(error.contains("fixture case fixture-input-base64"));
        assert!(error.contains("request.body_base64"));

        let mut malformed_response = fixture();
        set_pointer(&mut malformed_response, "/backend_response/body_base64", json!("Y$=="));
        let error = parse_fixture_case(&malformed_response).unwrap_err();
        assert!(error.contains("fixture case fixture-input-base64"));
        assert!(error.contains("backend_response.body_base64"));

        let mut malformed_nested = fixture();
        set_pointer(
            &mut malformed_nested,
            "/request/metadata/0/payload_base64",
            json!("Y$=="),
        );
        let error = parse_fixture_case(&malformed_nested).unwrap_err();
        assert!(error.contains("request.metadata[0].payload_base64"));

        for body in ["", "AAECAwQ="] {
            let mut valid = fixture();
            set_pointer(&mut valid, "/request/body_base64", json!(body));
            set_pointer(&mut valid, "/backend_response/body_base64", json!(body));
            assert!(parse_fixture_case(&valid).is_ok(), "{body}");
        }
    }

    #[test]
    fn lifecycle_matchers_reject_chains_until_child_conditions_are_modeled() {
        let config = r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /deny\" \"id:4,phase:1,deny,chain\"","SecRule REQUEST_METHOD \"@streq POST\" \"t:none\""]},"default_directives":"default"}"#;
        assert_topic_rejected(&json!({
            "id": "chain-parent-only-match-allow",
            "plugin_configuration": config,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.allow"]
        }));
        assert_topic_rejected(&json!({
            "id": "chain-parent-only-match-metric",
            "plugin_configuration": config,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["metrics.interruption"]
        }));
    }

    #[test]
    fn reload_topic_requires_holding_before_and_repeating_after_reload() {
        let valid = json!({
            "id": "complete-reload-sequence",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /reload-deny\" \"id:1040,phase:1,deny,status:403\""]},"default_directives":"default"}"#,
            "reload_plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine DetectionOnly","SecRule REQUEST_URI \"@streq /reload-deny\" \"id:1041,phase:1,deny,status:403\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/reload-deny"},
            "host_scenarios": ["hold-request-before-reload", "reload-with-inflight-stream", "repeat-request-after-reload"],
            "topics": ["lifecycle.reload"]
        });
        assert_topic_accepted(&valid);

        for required in [
            "hold-request-before-reload",
            "reload-with-inflight-stream",
            "repeat-request-after-reload",
        ] {
            let mut missing_step = valid.clone();
            missing_step
                .get_mut("host_scenarios")
                .and_then(Value::as_array_mut)
                .unwrap()
                .retain(|scenario| scenario.as_str() != Some(required));
            assert_topic_rejected(&missing_step);
        }
    }

    #[test]
    fn lifecycle_interruption_predicates_reject_rule_mutation_families() {
        for (index, mutation) in ["SecRuleUpdateTargetById 4 REQUEST_METHOD", "SecRuleRemoveById 4"]
            .into_iter()
            .enumerate()
        {
            let configuration = json!({
                "directives_map": {"default": [
                    "SecRuleEngine On",
                    r#"SecRule REQUEST_URI "@streq /deny" "id:4,phase:1,deny""#,
                    mutation
                ]},
                "default_directives": "default"
            })
            .to_string();
            assert_topic_rejected(&json!({
                "id": format!("rule-mutator-allow-{index}"),
                "plugin_configuration": configuration.clone(),
                "request": {"method": "GET", "path": "/deny"},
                "topics": ["lifecycle.allow"]
            }));
            assert_topic_rejected(&json!({
                "id": format!("rule-mutator-metric-{index}"),
                "plugin_configuration": configuration,
                "request": {"method": "GET", "path": "/deny"},
                "topics": ["metrics.interruption"]
            }));
        }
    }

    #[test]
    fn lifecycle_allow_rejects_deny_with_invalid_overridden_phase() {
        assert_topic_rejected(&json!({
            "id": "invalid-phase-overridden-by-response",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /deny\" \"id:5,phase:bogus,phase:4,deny\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.allow"]
        }));
    }

    #[test]
    fn lifecycle_allow_rejects_sec_lang_continuation() {
        let configuration = serde_json::to_string(&json!({
            "directives_map": {"default": [
                "SecRuleEngine On",
                "SecRule REQUEST_URI \\\n\"@streq /deny\" \"id:6,phase:1,deny\""
            ]},
            "default_directives": "default"
        }))
        .unwrap();
        assert_topic_rejected(&json!({
            "id": "continued-deny-is-not-benign",
            "plugin_configuration": configuration,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.allow"]
        }));
    }

    #[test]
    fn lifecycle_allow_rejects_inherited_default_deny() {
        assert_topic_rejected(&json!({
            "id": "default-action-deny-is-not-benign",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecDefaultAction \"phase:2,deny,status:403\"","SecRule REQUEST_URI \"@streq /deny\" \"id:7,phase:2\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.allow"]
        }));
    }

    #[test]
    fn interruption_metrics_reject_a_deny_with_overridden_phase_one() {
        assert_topic_rejected(&json!({
            "id": "phase-one-overridden-by-response",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /deny\" \"id:8,phase:1,phase:4,deny,status:403\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["metrics.interruption"]
        }));
    }

    #[test]
    fn interruption_metrics_do_not_treat_request_alias_as_phase_one() {
        assert_topic_rejected(&json!({
            "id": "phase-two-request-alias-is-not-phase-one-metric",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /deny\" \"id:8,phase:request,deny,status:403\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["metrics.interruption"]
        }));
    }

    #[test]
    fn request_phase_classifier_uses_last_valid_phase_and_request_body_default() {
        assert!(directive_is_request_phase(
            r#"SecRule REQUEST_URI "@streq /deny" "id:1,deny""#
        ));
        assert!(directive_is_request_phase(
            r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:4,phase:1,deny""#
        ));
        assert!(!directive_is_request_phase(
            r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:1,phase:4,deny""#
        ));
        assert!(!directive_is_request_phase(
            r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:5,deny""#
        ));

        for (phase, expected) in [("01", true), ("02", true), ("03", false), ("04", false), ("05", false)] {
            assert_eq!(
                directive_is_request_phase(&format!(
                    r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:{phase},deny""#
                )),
                expected,
                "phase {phase}"
            );
        }

        let request_alias = r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:request,deny""#;
        assert!(directive_is_request_phase(request_alias));
        assert!(!super::directive_is_phase_one(request_alias));
        assert_eq!(super::effective_directive_phase(request_alias), Some((Some(2), false)));
        assert!(!directive_is_request_phase(
            r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:response,deny""#
        ));
        let response_alias = r#"SecRule RESPONSE_BODY "@contains secret" "id:1,phase:response,deny""#;
        assert_eq!(super::effective_directive_phase(response_alias), Some((Some(4), false)));
        assert!(super::action_list_contains(
            super::directive_actions(response_alias).unwrap(),
            "phase:4"
        ));
        assert_eq!(
            super::effective_directive_phase(r#"SecAction "id:1,phase:logging,pass""#),
            Some((Some(5), false))
        );
        assert_eq!(
            super::effective_directive_phase(r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:1,deny""#),
            Some((Some(1), false))
        );
        assert!(!directive_is_request_phase(
            r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:logging,deny""#
        ));
        assert!(!directive_is_request_phase(
            r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:'03',deny""#
        ));
        assert!(!directive_is_request_phase(
            r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:4,phase:response,deny""#
        ));
        assert!(directive_is_request_phase(
            r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:response,phase:01,deny""#
        ));
        for phase in ["bogus", "0", "6", "256"] {
            assert!(
                directive_is_request_phase(&format!(
                    r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:{phase},deny""#
                )),
                "invalid phase {phase} is classified conservatively"
            );
        }
        assert!(directive_is_request_phase(
            r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:bogus,phase:4,deny""#
        ));
        assert!(directive_is_request_phase(
            r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:4,phase:bogus,deny""#
        ));
    }

    #[test]
    fn lifecycle_allow_ignores_zero_padded_response_phase_deny() {
        let case = parse_fixture_case(&json!({
            "id": "zero-padded-response-deny",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /deny\" \"id:1,phase:03,deny\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.allow"]
        }))
        .unwrap();
        let coverage = BTreeMap::from([("claim".to_owned(), vec!["lifecycle.allow".to_owned()])]);
        assert!(validate_inventory_coverage(&coverage, &[case]).is_ok());
    }

    #[test]
    fn lifecycle_allow_rejects_action_updates_it_cannot_classify() {
        assert_topic_rejected(&json!({
            "id": "updated-request-deny",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /deny\" \"id:1,phase:4,pass\"","SecRuleUpdateActionById 1 \"phase:1,deny\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.allow"]
        }));

        assert_topic_rejected(&json!({
            "id": "newline-packed-updated-request-deny",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /deny\" \"id:1,phase:4,pass\"\nSecRuleUpdateActionById 1 \"phase:1,deny\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.allow"]
        }));
    }

    #[test]
    fn lifecycle_allow_rejects_includes_it_cannot_inspect() {
        let configuration = json!({
            "directives_map": {"default": ["SecRuleEngine On", "Include rules/deny.conf"]},
            "default_directives": "default",
            "rule_data": {
                "rules/deny.conf": r#"SecRule REQUEST_URI "@streq /deny" "id:1,phase:1,deny""#
            }
        })
        .to_string();
        assert_topic_rejected(&json!({
            "id": "included-request-deny",
            "plugin_configuration": configuration,
            "request": {"method": "GET", "path": "/deny"},
            "topics": ["lifecycle.allow"]
        }));
    }

    #[test]
    fn lifecycle_allow_uses_the_request_authority_policy() {
        let configuration = json!({
            "directives_map": {
                "default": ["SecRuleEngine On", r#"SecRule REQUEST_URI "@streq /other" "id:1,phase:1,pass""#],
                "authority": ["SecRuleEngine On", r#"SecRule REQUEST_URI "@streq /deny" "id:2,phase:1,deny""#]
            },
            "default_directives": "default",
            "per_authority_directives": {"waf.example": "authority"}
        })
        .to_string();
        assert_topic_rejected(&json!({
            "id": "authority-selected-request-deny",
            "plugin_configuration": configuration,
            "request": {"method": "GET", "path": "/deny", "authority": "waf.example"},
            "topics": ["lifecycle.allow"]
        }));
    }

    #[test]
    fn authority_duplicate_reload_and_state_inputs_use_active_directives() {
        assert_topic_rejected(&json!({
            "id": "spoofed-authority-policy",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /wrong\" \"id:1035,phase:1,deny,status:403,msg:'@streq /authority-deny'\""],"other":["SecRuleEngine DetectionOnly","SecRule REQUEST_URI \"@streq /authority-deny\" \"id:1036,phase:1,deny,status:403\""]},"default_directives":"default","per_authority_directives":{"waf.example":"other"}}"#,
            "request": {"method": "GET", "path": "/authority-deny", "authority": "waf.example"},
            "topics": ["config.authority"]
        }));
        assert_topic_rejected(&json!({
            "id": "spoofed-duplicate-policy",
            "plugin_configuration": r#"{"unknown":true,"default_directives":"first","default_directives":"last","directives_map":{"first":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /wrong\" \"id:1021,phase:1,deny,status:403,msg:'@streq /duplicate-policy'\""],"last":["SecRuleEngine Off","SecRule REQUEST_URI \"@streq /duplicate-policy\" \"id:1022,phase:1,deny,status:403\""]}}"#,
            "request": {"method": "GET", "path": "/duplicate-policy"},
            "topics": ["config.unknown-duplicate-keys"]
        }));
        assert_topic_rejected(&json!({
            "id": "spoofed-reload-policy",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /reload-deny\" \"id:1040,phase:1,deny,status:403\""]},"default_directives":"default"}"#,
            "reload_plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /wrong\" \"id:1041,phase:1,deny,status:403,msg:'SecRuleEngine DetectionOnly @streq /reload-deny'\""]},"default_directives":"default"}"#,
            "request": {"method": "GET", "path": "/reload-deny"},
            "host_scenarios": ["reload-with-inflight-stream"],
            "topics": ["lifecycle.reload"]
        }));
        assert_topic_rejected(&json!({
            "id": "spoofed-request-state-policy",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /deny\" \"id:1010,phase:1,pass,msg:'deny'\""]},"default_directives":"default","enable_filter_state_logs":true}"#,
            "request": {"method": "GET", "path": "/deny", "client_ip": "192.0.2.5"},
            "topics": ["lifecycle.request-interruption"]
        }));
        assert_topic_rejected(&json!({
            "id": "spoofed-state-tag",
            "plugin_configuration": r#"{"directives_map":{"default":["SecRuleEngine On","SecRule REQUEST_URI \"@streq /wrong\" \"id:1010,phase:1,deny,status:403,severity:2,tag:'attack-SQLi',msg:'@streq /deny'\""]},"default_directives":"default","enable_filter_state_logs":true}"#,
            "request": {"method": "GET", "path": "/deny", "client_ip": "192.0.2.5"},
            "topics": ["pr20.state-published"]
        }));
    }

    #[test]
    fn contract_manifest_and_cases_reject_recursive_duplicate_keys() {
        for raw in [
            br#"{"schema_version":2,"schema_version":2}"#.as_slice(),
            br#"[{"id":"case","id":"other"}]"#.as_slice(),
            br#"{"nested":{"key":1,"key":2}}"#.as_slice(),
        ] {
            assert!(parse_strict_json(raw, "fixture").is_err());
        }
    }

    #[test]
    fn semantic_outcome_differences_are_recorded_for_comparison() {
        let manifest = ContractManifest {
            schema_version: 2,
            contract_sha256: String::new(),
            hosts: vec![Host {
                id: "host".to_owned(),
                pinned: false,
            }],
            cases: vec![
                CaseRef {
                    id: "withheld".to_owned(),
                    reference: "upstream".to_owned(),
                    hosts: vec!["host".to_owned()],
                    required_outcome_fields: vec![required(
                        "response.upstream_sensitive_pairs_withheld",
                        ObservationType::Boolean,
                    )],
                },
                CaseRef {
                    id: "matches".to_owned(),
                    reference: "upstream".to_owned(),
                    hosts: vec!["host".to_owned()],
                    required_outcome_fields: vec![required("rule_matches", ObservationType::RuleMatches)],
                },
                CaseRef {
                    id: "state-order".to_owned(),
                    reference: "upstream".to_owned(),
                    hosts: vec!["host".to_owned()],
                    required_outcome_fields: vec![
                        required("filter_state.publication_sequence", ObservationType::NonNegativeInteger),
                        required("local_reply.sequence", ObservationType::NonNegativeInteger),
                    ],
                },
            ],
            inventory_coverage: BTreeMap::new(),
            deferred_inventory: Vec::new(),
            pins: Pins {
                upstream_connector: String::new(),
                pr20_head: String::new(),
            },
        };
        let baseline_outcomes = BTreeMap::from([
            (
                "withheld".to_owned(),
                json!({"response": {"upstream_sensitive_pairs_withheld": true}}),
            ),
            ("matches".to_owned(), json!({"rule_matches": []})),
            (
                "state-order".to_owned(),
                json!({"filter_state": {"publication_sequence": 1}, "local_reply": {"sequence": 2}}),
            ),
        ]);
        let candidate_outcomes = BTreeMap::from([
            (
                "withheld".to_owned(),
                json!({"response": {"upstream_sensitive_pairs_withheld": false}}),
            ),
            (
                "matches".to_owned(),
                json!({"rule_matches": [{"id": "1001", "phase": 1, "action": "deny"}]}),
            ),
            (
                "state-order".to_owned(),
                json!({"filter_state": {"publication_sequence": 3}, "local_reply": {"sequence": 2}}),
            ),
        ]);
        validate_outcomes(&manifest, "host", "upstream", &baseline_outcomes).unwrap();
        validate_outcomes(&manifest, "host", "candidate", &candidate_outcomes).unwrap();
        let baseline = Capture {
            schema_version: 2,
            host: "host".to_owned(),
            role: "upstream".to_owned(),
            revision: String::new(),
            artifact_sha256: String::new(),
            contract_sha256: String::new(),
            outcomes: baseline_outcomes,
        };
        let candidate = Capture {
            schema_version: 2,
            host: "host".to_owned(),
            role: "candidate".to_owned(),
            revision: String::new(),
            artifact_sha256: String::new(),
            contract_sha256: String::new(),
            outcomes: candidate_outcomes,
        };
        assert_eq!(compare_outcomes(&manifest, &baseline, &candidate).len(), 3);
    }

    #[test]
    fn duplicate_configuration_exception_is_narrow_and_keeps_the_first_value() {
        let parsed = super::parse_plugin_configuration(
            r#"{"default_directives":"first","default_directives":"last"}"#,
            "fixture",
            true,
        )
        .unwrap();
        assert_eq!(
            parsed.0.get("default_directives").and_then(Value::as_str),
            Some("first")
        );
        assert!(parsed.1);

        for raw in [
            r#"{"default_directives":"first","default_directives":"last","default_directives":"third"}"#,
            r#"{"default_directives":"first","default_directives":"last","nested":{"key":1,"key":2}}"#,
            r#"{"directives_map":{},"directives_map":{}}"#,
        ] {
            assert!(super::parse_plugin_configuration(raw, "fixture", true).is_err());
        }
    }

    #[test]
    fn whitespace_only_plugin_configuration_is_blank() {
        assert!(
            super::parse_plugin_configuration(" \n\t\r ", "fixture", false)
                .unwrap()
                .0
                .is_null()
        );
    }

    #[test]
    fn plugin_configuration_accepts_any_valid_json_root_without_weakening_duplicate_checks() {
        for raw in ["null", "true", "0", "\"scalar\"", "[]"] {
            assert!(
                super::parse_plugin_configuration(raw, "fixture", false).is_ok(),
                "{raw}"
            );
        }
        assert!(super::parse_plugin_configuration(r#"{"nested":{"key":1,"key":2}}"#, "fixture", false).is_err());
    }

    #[test]
    fn outcome_json_rejects_duplicate_ids_and_non_object_values() {
        let duplicate =
            serde_json::from_str::<StrictOutcomes>(r#"{"case":{"status":403},"case":{"status":200}}"#).unwrap_err();
        assert!(duplicate.to_string().contains("duplicate outcome case ID case"));
        let nested_duplicate =
            serde_json::from_str::<StrictOutcomes>(r#"{"case":{"response":{"status":403,"status":200}}}"#).unwrap_err();
        assert!(
            nested_duplicate
                .to_string()
                .contains("duplicate JSON object key status")
        );
        assert!(serde_json::from_str::<StrictOutcomes>("[]").is_err());

        let manifest = ContractManifest {
            schema_version: 2,
            contract_sha256: String::new(),
            hosts: vec![Host {
                id: "host".to_owned(),
                pinned: false,
            }],
            cases: vec![CaseRef {
                id: "case".to_owned(),
                reference: "upstream".to_owned(),
                hosts: vec!["host".to_owned()],
                required_outcome_fields: vec![required("response.status", ObservationType::HttpStatus)],
            }],
            inventory_coverage: BTreeMap::new(),
            deferred_inventory: Vec::new(),
            pins: Pins {
                upstream_connector: String::new(),
                pr20_head: String::new(),
            },
        };
        for invalid in ["null", "[]", "\"status\"", "{}"] {
            let outcomes: StrictOutcomes = serde_json::from_str(&format!("{{\"case\":{invalid}}}")).unwrap();
            let error = validate_outcomes(&manifest, "host", "upstream", &outcomes.0).unwrap_err();
            assert!(error.contains("must be a non-empty JSON object"));
        }
    }

    #[test]
    fn outcomes_must_contain_each_case_specific_observation() {
        let manifest = ContractManifest {
            schema_version: 2,
            contract_sha256: String::new(),
            hosts: vec![Host {
                id: "host".to_owned(),
                pinned: false,
            }],
            cases: vec![CaseRef {
                id: "case".to_owned(),
                reference: "upstream".to_owned(),
                hosts: vec!["host".to_owned()],
                required_outcome_fields: vec![
                    required("response.status", ObservationType::HttpStatus),
                    required("backend.received", ObservationType::Boolean),
                ],
            }],
            inventory_coverage: BTreeMap::new(),
            deferred_inventory: Vec::new(),
            pins: Pins {
                upstream_connector: String::new(),
                pr20_head: String::new(),
            },
        };
        let generic = BTreeMap::from([("case".to_owned(), json!({"ok": true}))]);
        assert!(
            validate_outcomes(&manifest, "host", "upstream", &generic)
                .unwrap_err()
                .contains("missing required field response.status")
        );

        let nulls = BTreeMap::from([(
            "case".to_owned(),
            json!({"response": {"status": null}, "backend": {"received": null}}),
        )]);
        assert!(
            validate_outcomes(&manifest, "host", "upstream", &nulls)
                .unwrap_err()
                .contains("field response.status must be an HTTP status integer")
        );

        let partial = BTreeMap::from([("case".to_owned(), json!({"response": {"status": 403}}))]);
        assert!(
            validate_outcomes(&manifest, "host", "upstream", &partial)
                .unwrap_err()
                .contains("missing required field backend.received")
        );

        let complete = BTreeMap::from([(
            "case".to_owned(),
            json!({"response": {"status": 403}, "backend": {"received": false}}),
        )]);
        assert!(validate_outcomes(&manifest, "host", "upstream", &complete).is_ok());

        let wrong_types = BTreeMap::from([(
            "case".to_owned(),
            json!({"response": {"status": "403"}, "backend": {"received": "false"}}),
        )]);
        assert!(
            validate_outcomes(&manifest, "host", "upstream", &wrong_types)
                .unwrap_err()
                .contains("field response.status must be an HTTP status integer")
        );
    }

    #[test]
    fn absent_backend_request_observations_are_valid_optional_shapes() {
        let manifest = ContractManifest {
            schema_version: 2,
            contract_sha256: String::new(),
            hosts: vec![Host {
                id: "host".to_owned(),
                pinned: false,
            }],
            cases: vec![CaseRef {
                id: "case".to_owned(),
                reference: "upstream".to_owned(),
                hosts: vec!["host".to_owned()],
                required_outcome_fields: vec![
                    required("backend.received", ObservationType::Boolean),
                    required("backend.request.method", ObservationType::OptionalString),
                    required("backend.request.path", ObservationType::OptionalString),
                    required("backend.request.headers", ObservationType::OptionalHeaderPairs),
                    required("backend.request.body_base64", ObservationType::OptionalString),
                ],
            }],
            inventory_coverage: BTreeMap::new(),
            deferred_inventory: Vec::new(),
            pins: Pins {
                upstream_connector: String::new(),
                pr20_head: String::new(),
            },
        };
        let outcomes = BTreeMap::from([(
            "case".to_owned(),
            json!({"backend": {"received": false, "request": {
                "method": null, "path": null, "headers": null, "body_base64": null
            }}}),
        )]);
        assert!(validate_outcomes(&manifest, "host", "upstream", &outcomes).is_ok());
    }

    #[test]
    fn captures_must_match_the_current_fixture_digest() {
        let capture = Capture {
            schema_version: 2,
            host: "host".to_owned(),
            role: "upstream".to_owned(),
            revision: String::new(),
            artifact_sha256: String::new(),
            contract_sha256: "a".repeat(64),
            outcomes: BTreeMap::new(),
        };
        assert!(validate_capture_contract_digest("baseline", &capture, &"a".repeat(64)).is_ok());
        assert!(
            validate_capture_contract_digest("candidate", &capture, &"b".repeat(64))
                .unwrap_err()
                .contains("does not match the current manifest")
        );
    }

    #[test]
    fn contract_digest_changes_when_manifest_requirements_change() {
        let mut manifest = json!({
            "schema_version": 2,
            "contract_sha256": "ignored self hash",
            "status": "open: capture pending",
            "observed_checkouts": [{"path": "../diagnostic", "note": "not a pin"}],
            "pins": {"upstream_connector": "a", "pr20_head": "b"},
            "hosts": [
                {"id": "standalone", "kind": "envoy", "image": "envoy@sha256:abc", "status": "pinned", "note": "diagnostic"},
                {"id": "istio", "kind": "istio", "proxy_image_digest": null, "status": "open"}
            ],
            "cases": [{
                "id": "case", "reference": "upstream", "hosts": ["standalone"],
                "required_outcome_fields": [{"path": "response.status", "type": "http_status"}],
                "note": "diagnostic"
            }],
            "inventory": {"features": ["phase 3"]},
            "inventory_coverage": {"phase 3": ["topic"]},
            "deferred_inventory": [{"id": "gap", "reason": "not probed yet"}]
        });
        let cases = json!([{
            "id": "case", "plugin_configuration": "{}", "topics": ["topic"],
            "assert": "diagnostic prose", "description": "diagnostic"
        }]);
        let cases = serde_json::to_vec(&cases).unwrap();
        let original = super::contract_digest(&manifest, &cases).unwrap();

        set_pointer(
            &mut manifest,
            "/status",
            json!("baseline remains open while captures are unavailable"),
        );
        set_pointer(&mut manifest, "/hosts/0/status", json!("status wording changed"));
        set_pointer(&mut manifest, "/hosts/0/note", json!("new host note"));
        set_pointer(&mut manifest, "/cases/0/note", json!("new case note"));
        set_pointer(
            &mut manifest,
            "/deferred_inventory/0/reason",
            json!("new explanation only"),
        );
        let mut diagnostic_cases: Value = serde_json::from_slice(&cases).unwrap();
        set_pointer(&mut diagnostic_cases, "/0/assert", json!("different diagnostic prose"));
        set_pointer(&mut diagnostic_cases, "/0/description", json!("different note"));
        let diagnostic_cases = serde_json::to_vec(&diagnostic_cases).unwrap();
        assert_eq!(original, super::contract_digest(&manifest, &diagnostic_cases).unwrap());
        let mut changed_fixture: Value = serde_json::from_slice(&cases).unwrap();
        set_pointer(&mut changed_fixture, "/0/plugin_configuration", json!("null"));
        let changed_fixture = serde_json::to_vec(&changed_fixture).unwrap();
        assert_ne!(original, super::contract_digest(&manifest, &changed_fixture).unwrap());

        let mut variants = Vec::new();
        let mut changed = manifest.clone();
        set_pointer(&mut changed, "/hosts/0/image", json!("envoy@sha256:def"));
        variants.push(changed);
        let mut changed = manifest.clone();
        set_pointer(
            &mut changed,
            "/observed_checkouts/0/note",
            json!("changed checkout note"),
        );
        variants.push(changed);
        let mut changed = manifest.clone();
        set_pointer(&mut changed, "/cases/0/hosts", json!(["istio"]));
        variants.push(changed);
        let mut changed = manifest.clone();
        push_array(&mut changed, "/inventory/features", json!("phase 4"));
        variants.push(changed);
        let mut changed = manifest.clone();
        push_array(
            &mut changed,
            "/deferred_inventory",
            json!({"id": "new-gap", "reason": "new"}),
        );
        variants.push(changed);
        let mut changed = manifest.clone();
        set_pointer(&mut changed, "/cases/0/required_outcome_fields/0/type", json!("string"));
        variants.push(changed);
        let changed_digest = super::contract_digest(variants.first().expect("host pin variant"), &cases).unwrap();
        for changed in variants {
            assert_ne!(original, super::contract_digest(&changed, &cases).unwrap());
        }

        let capture = Capture {
            schema_version: 2,
            host: "host".to_owned(),
            role: "upstream".to_owned(),
            revision: String::new(),
            artifact_sha256: String::new(),
            contract_sha256: original,
            outcomes: BTreeMap::new(),
        };
        assert!(
            validate_capture_contract_digest("baseline", &capture, &changed_digest)
                .unwrap_err()
                .contains("does not match")
        );
    }

    #[test]
    fn recorded_capture_size_is_bounded_after_pretty_printing() {
        let body = "x".repeat(super::MAX_OUTCOMES_BYTES - 11);
        let outcomes = json!({"case": body});
        assert_eq!(serde_json::to_vec(&outcomes).unwrap().len(), super::MAX_OUTCOMES_BYTES);
        let capture = json!({"schema_version": 2, "outcomes": outcomes});
        assert!(
            super::serialize_capture(&capture)
                .unwrap_err()
                .contains("serialized capture exceeds the")
        );
    }

    #[test]
    fn inputs_are_bounded_and_output_aliases_are_rejected() {
        let root = test_dir();
        fs::create_dir(root.join("nested")).unwrap();
        let input = root.join("outcomes.json");
        fs::write(&input, b"longer than three bytes").unwrap();
        assert!(read_limited(&input, 3).unwrap_err().contains("3-byte input limit"));

        let lexical_alias = root.join("nested/../outcomes.json");
        assert!(
            reject_output_alias(&lexical_alias, &[&input])
                .unwrap_err()
                .contains("aliases input")
        );
        #[cfg(unix)]
        {
            let hard_link = root.join("hard-link.json");
            fs::hard_link(&input, &hard_link).unwrap();
            assert!(
                reject_output_alias(&hard_link, &[&input])
                    .unwrap_err()
                    .contains("aliases input")
            );

            let symlink = root.join("symbolic-link.json");
            std::os::unix::fs::symlink(&input, &symlink).unwrap();
            assert!(
                reject_output_alias(&symlink, &[&input])
                    .unwrap_err()
                    .contains("aliases input")
            );
        }

        let output = root.join("capture.json");
        super::write_output(&output, &[&input], b"first").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(fs::metadata(&output).unwrap().permissions().mode() & 0o077, 0);
        }
        super::write_output(&output, &[&input], b"replacement").unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"replacement");
        #[cfg(unix)]
        {
            let target = root.join("unrelated.json");
            let symlink = root.join("output-symlink.json");
            fs::write(&target, b"leave alone").unwrap();
            std::os::unix::fs::symlink(&target, &symlink).unwrap();
            super::write_output(&symlink, &[&input], b"capture").unwrap();
            assert_eq!(fs::read(&target).unwrap(), b"leave alone");
            assert_eq!(fs::read(&symlink).unwrap(), b"capture");
            assert!(!fs::symlink_metadata(&symlink).unwrap().file_type().is_symlink());
        }
        fs::remove_dir_all(root).unwrap();
    }

    fn test_dir() -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("envoy-contract-test-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        path
    }
}
