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

//! Plugin configuration, compatible with the Go `coraza-proxy-wasm` connector.
//!
//! The accepted keys are the ones the upstream connector reads at
//! `corazawaf/coraza-proxy-wasm@b1770f5` (`wasmplugin/config.go`), plus the
//! fork's `enable_filter_state_logs` switch and this connector's own
//! `rule_data` map.
//!
//! # Accepted values
//!
//! * Blank or whitespace-only input is an empty [`Config`]: every request then passes uninspected. A document whose top
//!   level is not an object is treated the same way, because upstream reads every key from it as absent.
//! * `directives_map` is an object of policy name to an array of directives, or to a single scalar, which becomes a
//!   one-element list. Array elements are coerced with [`scalar_text`]: strings, numbers, booleans and `null`
//!   contribute their text; an array or object anywhere in a policy's directive list is rejected, naming the policy and
//!   the element index. A policy whose value is an object is rejected. Directives are ordered.
//! * `default_directives` is the fallback policy name. It must be a string; a `null`, array or object is rejected. An
//!   absent value selects no policy: the first configured policy is not used implicitly. The name is resolved during
//!   compilation.
//! * `per_authority_directives` maps an authority to a policy name. Every referenced policy must exist. An empty
//!   authority or an empty policy name is rejected. Scalars are coerced and non-scalars are rejected. At most
//!   [`MAX_AUTHORITIES`] authorities are accepted.
//! * Policy, authority and `rule_data` names are at most [`MAX_NAME_BYTES`] bytes; a configured name over the limit is
//!   rejected rather than embedded in a log line.
//! * `rules` is the deprecated flat directive list. It becomes policy `default`, which also becomes
//!   `default_directives`, only when `directives_map` is empty; otherwise its result is ignored, though the value is
//!   still validated. It must be an array of scalars or a single scalar; `null`, an object or a container inside the
//!   array is rejected.
//! * `metric_labels` is an object of static label name to value, coerced like a directive. Non-scalar values are
//!   skipped. At most [`MAX_METRIC_LABELS`] labels are accepted, with names of at most [`MAX_METRIC_LABEL_NAME_BYTES`]
//!   bytes and values of at most [`MAX_METRIC_LABEL_VALUE_BYTES`] bytes.
//! * `enable_filter_state_logs` is a boolean, `false` by default; any other type also reads as `false`.
//! * `rule_data` is this connector's additive map of file name to file bytes for the file-based operators and
//!   `Include`. Names are bounded like the engine's in-memory rule data source: see [`RULE_DATA_LIMITS`]. A non-string
//!   value is ignored, but its name is still validated.
//! * Unknown keys are ignored.
//!
//! # Known divergences from upstream
//!
//! These are frozen by tests, not parity claims. They either reject a document
//! that upstream would accept, or differ only in how a value is rendered; none
//! turns a document upstream rejects into an accepted one.
//!
//! Runtime authority lookup lowercases the request authority and strips only its scheme's default port before
//! selection, and uses Envoy's `request.host` property when `:authority` is absent. Upstream uses the raw authority
//! string as an exact key and does not use that property fallback. Configure authority keys in lowercase; bracketed
//! IPv6 literals retain their brackets, and non-default ports remain part of the lookup key.
//!
//! * Duplicate JSON keys collapse before this parser sees them, and `serde_json` keeps the last value, so every key
//!   read through `Get` or `ForEach` keeps its last duplicate, where upstream keeps the first. That covers
//!   `directives_map` (including a duplicate policy name inside it), `default_directives`, `per_authority_directives`,
//!   `metric_labels`, `enable_filter_state_logs`, `rules` and `rule_data`. A dropped duplicate `directives_map` entry
//!   can therefore drop an entire policy's rules.
//! * `serde_json` renders a number with its shortest round-trip form, where `gjson`'s `String()` re-renders floats
//!   through `strconv.FormatFloat`, so exponent notation can differ. `1e30` is frozen as `1e+30`.
//! * An array or object inside a `directives_map` directive array is rejected, naming the policy and element index,
//!   where upstream stringifies its raw JSON text into one directive. A policy that silently loses a rule line is a
//!   fail-open, so the document is rejected. `null` becomes the empty string in both.
//! * `SecIgnoreRuleCompilationErrors On` is accepted but ineffective: a configuration that skips any directive,
//!   including one skipped by an include budget, is rejected with the policy name and the first skipped diagnostic.
//!   Upstream would compile the rest of the policy and serve it; a policy that silently loses a rule line is a
//!   fail-open, so this build keeps strict compilation.
//! * A present `directives_map`, `per_authority_directives` or `metric_labels` that is not an object is rejected.
//!   Upstream's `ForEach` on `null` iterates once and on an array iterates its elements, so such a document does
//!   something rather than nothing; rejecting it is stricter, not "treating it as absent". A non-object `rule_data` is
//!   read as empty instead: it is the one object-valued key where a wrong type is not rejected, because the key only
//!   supplies file bytes to this connector's own rule-data sources.
//! * A `directives_map` policy value that is an object is rejected, where upstream's `ForEach` reads it as a single
//!   stringified directive. Drifting into one opaque rule line is a silent fail-open.
//! * `rules` must be an array of scalars or a scalar. `rules: null` is rejected with `rules must be an array or string,
//!   not null`; upstream's `Exists` check is true for an explicit `null`, so it creates and selects a zero-rule
//!   `default` policy and every request passes uninspected. A container inside the array is rejected rather than
//!   stringified.
//! * `default_directives` must be a string; `null`, arrays and objects are rejected where upstream treats them as
//!   absent or stringifies them.
//! * `per_authority_directives` values must be scalars; a non-scalar is rejected where upstream stringifies it. The
//!   document is rejected because an unusable authority entry would otherwise drop enforcement for that authority.
//! * `metric_labels` values must be scalars; non-scalars are skipped as before, but a label over its cap is rejected
//!   rather than truncated.
//! * `serde_json` rejects JSON nested deeper than 128 levels, invalid UTF-8 and numbers outside its range, where
//!   `gjson` accepts them or re-renders them. The failure is reported as `invalid json: `.
//! * Error text is this crate's: it names the offending policy, authority, label or file and the bound that failed,
//!   with names quoted and truncated to [`MAX_DISPLAY_NAME_BYTES`], while upstream may log a looser `gjson` diagnostic
//!   or silently continue.
//! * Bounds that upstream does not enforce, by constant: `MAX_POLICIES` policies; `MAX_JSON_VALUES` value separators
//!   per document, checked before `serde_json` builds a `Value` tree; `MAX_CONFIGURATION_BYTES` of plugin
//!   configuration, which also bounds the directive text it can carry; `MAX_RULES_PER_POLICY` (30,000) and
//!   `MAX_RULES_PER_GENERATION` (60,000) rules, passed to the engine parser as a rule budget so an `Include` expansion
//!   or a newline-packed directive string stops at the limit; `MAX_RULE_DATA_FILES`, `MAX_RULE_DATA_FILE_BYTES`,
//!   `MAX_RULE_DATA_TOTAL_BYTES`, `MAX_RULE_DATA_READ_BYTES` and `MAX_NAME_BYTES` (4096, with the engine's 64-component
//!   rule) for rule-data names; `MAX_AUTHORITIES`; `MAX_METRIC_LABELS`, `MAX_METRIC_LABEL_NAME_BYTES` and
//!   `MAX_METRIC_LABEL_VALUE_BYTES`; and `MAX_REQUEST_BODY_LIMIT`/`MAX_RESPONSE_BODY_LIMIT`. The engine's
//!   `MAX_INCLUDED_FILES` is per top-level parse, so here it applies per policy. Stock CRS's `SecRequestBodyLimit
//!   13107200` is under the `MAX_REQUEST_BODY_LIMIT` WASM ceiling, so it is accepted as written. The rule caps are low
//!   because rule insertion scans for duplicate ids, so collecting one policy is quadratic: 30,000 flat rules measured
//!   about 0.8 s natively (1.2 s with a realistic shape) and 3.3 s of configure-plus-start in an Envoy 1.40 V8 worker,
//!   with 5.4 s at the generation cap. Re-measure before raising them. Stock CRS is about 6,000 rules, so the cap is
//!   ample.
//! * The body ceilings are host policy, not policy syntax: they are installed as
//!   `WafConfig::max_request_body_limit`/`max_response_body_limit` so a request-time `ctl:requestBodyLimit`,
//!   `ctl:responseBodyLimit`, `ctl:requestBodyAccess=On` or `ctl:responseBodyAccess=On` cannot raise the effective
//!   limit above what the host buffers, and cannot reintroduce body spill above a positive in-memory limit.
//! * The audit-engine lock is host policy too: `WafConfig::audit_engine_locked` is installed so a request-time
//!   `ctl:auditEngine` cannot enable auditing when this build has no sink. Without it the engine would retain an audit
//!   copy of the request body with nowhere to write it.
//! * Every configured policy is compiled, referenced or not, so a broken policy cannot hide behind an authority table
//!   that happens never to select it.
//! * A compile reads at most `MAX_RULE_DATA_READ_BYTES` of rule data per generation, across every policy that shares
//!   the source.

use std::{
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
    path::Path,
};

use serde_json::{Map, Value};

/// Policy name the deprecated `rules` list creates, as upstream.
const DEPRECATED_POLICY: &str = "default";

/// Longest policy, authority or `rule_data` name, in bytes.
const MAX_NAME_BYTES: usize = 4096;

/// Longest config-controlled name embedded in an error or warning, in bytes.
const MAX_DISPLAY_NAME_BYTES: usize = 128;

/// Most JSON value separators and structural bytes one configuration may hold.
///
/// `serde_json` parses into a `Value` tree, which costs far more than the input
/// text: 16 `MiB` of one-byte numeric elements measured about 739 `MB` peak.
/// Rejecting before the parse bounds that amplification. The remaining profile
/// is the input plus its `Value` tree for at most this many values (a few
/// `MiB`), then the directive text copied out of it.
const MAX_JSON_VALUES: usize = 262_144;

/// Most `rule_data` files one configuration may carry.
const MAX_RULE_DATA_FILES: usize = 1024;

/// Largest single `rule_data` value, in bytes.
const MAX_RULE_DATA_FILE_BYTES: usize = 1024 * 1024;

/// Largest total of every `rule_data` value, in bytes.
const MAX_RULE_DATA_TOTAL_BYTES: usize = 8 * 1024 * 1024;

/// Most authorities one configuration may map.
const MAX_AUTHORITIES: usize = 4096;

/// Most static metric labels one configuration may set.
const MAX_METRIC_LABELS: usize = 64;

/// Longest metric label name, in bytes.
const MAX_METRIC_LABEL_NAME_BYTES: usize = 128;

/// Longest metric label value, in bytes.
const MAX_METRIC_LABEL_VALUE_BYTES: usize = 256;

/// Bounds applied while reading `rule_data`.
///
/// A value rather than bare constants so the checks can be exercised with small
/// limits instead of allocating the production ceilings in every test.
#[derive(Debug, Clone, Copy)]
struct RuleDataLimits {
    /// Most files.
    files: usize,
    /// Largest single value, in bytes.
    file_bytes: usize,
    /// Largest total of every value, in bytes.
    total_bytes: usize,
}

/// The production [`RuleDataLimits`].
const RULE_DATA_LIMITS: RuleDataLimits = RuleDataLimits {
    files: MAX_RULE_DATA_FILES,
    file_bytes: MAX_RULE_DATA_FILE_BYTES,
    total_bytes: MAX_RULE_DATA_TOTAL_BYTES,
};

/// A validated plugin configuration.
#[derive(Debug, Default)]
pub(crate) struct Config {
    /// Policy name to ordered `SecLang` directives.
    pub(crate) directives_map: BTreeMap<String, Vec<String>>,
    /// Policy used for an authority with no entry of its own.
    pub(crate) default_directives: Option<String>,
    /// Authority to policy name.
    pub(crate) per_authority_directives: BTreeMap<String, String>,
    /// Static metric labels.
    pub(crate) metric_labels: BTreeMap<String, String>,
    /// Whether the fork's filter-state log lines are enabled.
    pub(crate) enable_filter_state_logs: bool,
    /// File name to file bytes, for file-based rule operators.
    pub(crate) rule_data: BTreeMap<String, Vec<u8>>,
}

/// A configuration that cannot be used.
#[derive(Debug)]
pub(crate) enum ConfigError {
    /// The input is not valid JSON.
    InvalidJson(serde_json::Error),
    /// `directives_map` is present but not an object.
    DirectivesMapNotObject,
    /// A `directives_map` policy value is an object.
    PolicyValueNotArrayOrScalar {
        /// Policy whose value cannot be read.
        policy: String,
    },
    /// An element of a policy's directive array is an array or object.
    PolicyDirectiveNotScalar {
        /// Policy whose directive list holds the element.
        policy: String,
        /// Index of the offending element.
        index: usize,
    },
    /// The JSON document holds more values than [`MAX_JSON_VALUES`].
    TooManyValues,
    /// A policy, authority or `rule_data` name is over [`MAX_NAME_BYTES`].
    NameTooLong {
        /// Field the name came from.
        field: &'static str,
        /// Offending name.
        name: String,
    },
    /// `rules` is present but is neither an array nor a scalar.
    RulesNotArrayOrString {
        /// JSON type that was found.
        found: &'static str,
    },
    /// An element of the `rules` array is an array or object.
    RulesElementNotScalar {
        /// Index of the offending element.
        index: usize,
    },
    /// `default_directives` is present but not a string.
    DefaultDirectivesNotString {
        /// JSON type that was found.
        found: &'static str,
    },
    /// `per_authority_directives` is present but not an object.
    PerAuthorityNotObject,
    /// An authority value is an array or object.
    AuthorityValueNotScalar {
        /// Authority the entry is for.
        authority: String,
        /// JSON type that was found.
        found: &'static str,
    },
    /// The authority table is over its cap.
    TooManyAuthorities,
    /// An authority key is empty.
    EmptyAuthority,
    /// An authority entry names an empty policy.
    EmptyPolicyName {
        /// Authority the entry is for.
        authority: String,
    },
    /// `metric_labels` is present but not an object.
    MetricLabelsNotObject,
    /// A metric label breaks a bound.
    MetricLabel {
        /// Offending label name.
        name: String,
        /// Which bound it breaks.
        reason: String,
    },
    /// A `rule_data` entry breaks a bound.
    RuleData {
        /// Offending file name.
        name: String,
        /// Which bound it breaks.
        reason: String,
    },
}

impl Display for ConfigError {
    /// Formats the error for an operator-facing configure failure.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(error) => write!(f, "invalid json: {error}"),
            Self::DirectivesMapNotObject => f.write_str("directives_map must be an object"),
            Self::PolicyValueNotArrayOrScalar { policy } => {
                write!(
                    f,
                    "directives_map policy {} must be an array or scalar",
                    display_name(policy)
                )
            },
            Self::PolicyDirectiveNotScalar { policy, index } => {
                write!(
                    f,
                    "directives_map policy {} element {index} must be a scalar",
                    display_name(policy)
                )
            },
            Self::TooManyValues => write!(
                f,
                "json document exceeds the limit of {MAX_JSON_VALUES} value separators or structural bytes"
            ),
            Self::NameTooLong { field, name } => write!(
                f,
                "{field} name {} is {} bytes, over the {MAX_NAME_BYTES}-byte limit",
                display_name(name),
                name.len()
            ),
            Self::RulesNotArrayOrString { found } => {
                write!(f, "rules must be an array or string, not {found}")
            },
            Self::RulesElementNotScalar { index } => {
                write!(f, "rules[{index}] must be a scalar")
            },
            Self::DefaultDirectivesNotString { found } => {
                write!(f, "default_directives must be a string, not {found}")
            },
            Self::PerAuthorityNotObject => f.write_str("per_authority_directives must be an object"),
            Self::AuthorityValueNotScalar { authority, found } => {
                write!(
                    f,
                    "per_authority_directives for authority {} must be a string, not {found}",
                    display_name(authority)
                )
            },
            Self::TooManyAuthorities => {
                write!(
                    f,
                    "per_authority_directives exceeds the limit of {MAX_AUTHORITIES} authorities"
                )
            },
            Self::EmptyAuthority => f.write_str("per_authority_directives has an empty authority"),
            Self::EmptyPolicyName { authority } => {
                write!(
                    f,
                    "per_authority_directives for authority {} names an empty policy",
                    display_name(authority)
                )
            },
            Self::MetricLabelsNotObject => f.write_str("metric_labels must be an object"),
            Self::MetricLabel { name, reason } => {
                write!(f, "metric_labels {}: {reason}", display_name(name))
            },
            Self::RuleData { name, reason } => write!(f, "rule_data {}: {reason}", display_name(name)),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Parses a plugin configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidJson`] for malformed JSON, or a typed error
    /// for a key whose shape, authority, label or `rule_data` entry breaks a
    /// bound. Policy references are resolved during compilation, not here.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self::default());
        }
        check_json_value_count(bytes)?;
        let value: Value = serde_json::from_slice(bytes).map_err(ConfigError::InvalidJson)?;
        let Some(object) = value.as_object() else {
            // Every key upstream reads from a non-object document is absent.
            return Ok(Self::default());
        };

        let deprecated = parse_deprecated_rules(object)?;
        let mut config = Self {
            directives_map: parse_directives_map(object)?,
            default_directives: parse_default_directives(object)?,
            per_authority_directives: parse_per_authority_directives(object)?,
            metric_labels: parse_metric_labels(object)?,
            enable_filter_state_logs: object
                .get("enable_filter_state_logs")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            rule_data: parse_rule_data(object)?,
        };
        if config.directives_map.is_empty() {
            if let Some(directives) = deprecated {
                config.directives_map.insert(DEPRECATED_POLICY.to_owned(), directives);
                config.default_directives = Some(DEPRECATED_POLICY.to_owned());
            }
        }
        Ok(config)
    }
}

/// Renders a JSON scalar the way upstream's `gjson` `String()` reads it.
///
/// Arrays and objects have no text form here and return `None`, so a directive
/// list rejects them instead of stringifying raw JSON.
fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Null => Some(String::new()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

/// The JSON type name used in rejection messages.
fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Renders a config-controlled name for a log line: quoted, escaping control
/// characters, and truncated to [`MAX_DISPLAY_NAME_BYTES`] on a UTF-8 boundary.
pub(crate) fn display_name(name: &str) -> String {
    let mut end = name.len().min(MAX_DISPLAY_NAME_BYTES);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    let Some(prefix) = name.get(..end) else {
        return "\"\"".to_owned();
    };
    if prefix.len() == name.len() {
        return format!("{prefix:?}");
    }
    format!("{:?}", format!("{prefix}…"))
}

/// Rejects a configured name over [`MAX_NAME_BYTES`].
fn check_name(field: &'static str, name: &str) -> Result<(), ConfigError> {
    if name.len() > MAX_NAME_BYTES {
        return Err(ConfigError::NameTooLong {
            field,
            name: name.to_owned(),
        });
    }
    Ok(())
}

/// Counts JSON separators and structure outside strings before `serde_json`
/// builds a `Value` tree; see [`MAX_JSON_VALUES`].
fn check_json_value_count(bytes: &[u8]) -> Result<(), ConfigError> {
    let mut values = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b',' | b':' | b'[' | b']' | b'{' | b'}' => {
                values += 1;
                if values > MAX_JSON_VALUES {
                    return Err(ConfigError::TooManyValues);
                }
            },
            _ => {},
        }
    }
    Ok(())
}

/// Reads `directives_map`, accepting an array or one scalar per policy.
fn parse_directives_map(object: &Map<String, Value>) -> Result<BTreeMap<String, Vec<String>>, ConfigError> {
    let Some(value) = object.get("directives_map") else {
        return Ok(BTreeMap::new());
    };
    let Some(entries) = value.as_object() else {
        return Err(ConfigError::DirectivesMapNotObject);
    };
    let mut directives_map = BTreeMap::new();
    for (name, value) in entries {
        check_name("directives_map policy", name)?;
        let directives = match value {
            Value::Array(items) => items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    scalar_text(item).ok_or_else(|| ConfigError::PolicyDirectiveNotScalar {
                        policy: name.clone(),
                        index,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
            Value::Object(_) => {
                return Err(ConfigError::PolicyValueNotArrayOrScalar { policy: name.clone() });
            },
            scalar => vec![scalar_text(scalar).unwrap_or_default()],
        };
        directives_map.insert(name.clone(), directives);
    }
    Ok(directives_map)
}

/// Reads `default_directives`; its policy reference is checked at compile time.
fn parse_default_directives(object: &Map<String, Value>) -> Result<Option<String>, ConfigError> {
    let Some(value) = object.get("default_directives") else {
        return Ok(None);
    };
    match value {
        Value::String(policy) => {
            check_name("default_directives policy", policy)?;
            Ok(Some(policy.clone()))
        },
        other => Err(ConfigError::DefaultDirectivesNotString { found: kind(other) }),
    }
}

/// Reads `per_authority_directives`; its policy references are checked at compile time.
fn parse_per_authority_directives(object: &Map<String, Value>) -> Result<BTreeMap<String, String>, ConfigError> {
    let Some(value) = object.get("per_authority_directives") else {
        return Ok(BTreeMap::new());
    };
    let Some(entries) = value.as_object() else {
        return Err(ConfigError::PerAuthorityNotObject);
    };
    let mut authorities = BTreeMap::new();
    for (authority, value) in entries {
        check_name("per_authority_directives authority", authority)?;
        let Some(policy) = scalar_text(value) else {
            return Err(ConfigError::AuthorityValueNotScalar {
                authority: authority.clone(),
                found: kind(value),
            });
        };
        if authority.is_empty() {
            return Err(ConfigError::EmptyAuthority);
        }
        if policy.is_empty() {
            return Err(ConfigError::EmptyPolicyName {
                authority: authority.clone(),
            });
        }
        check_name("per_authority_directives policy", &policy)?;
        if authorities.len() >= MAX_AUTHORITIES {
            return Err(ConfigError::TooManyAuthorities);
        }
        authorities.insert(authority.clone(), policy);
    }
    Ok(authorities)
}

/// Reads `metric_labels`, bounded by the label caps.
fn parse_metric_labels(object: &Map<String, Value>) -> Result<BTreeMap<String, String>, ConfigError> {
    let Some(value) = object.get("metric_labels") else {
        return Ok(BTreeMap::new());
    };
    let Some(entries) = value.as_object() else {
        return Err(ConfigError::MetricLabelsNotObject);
    };
    let mut labels = BTreeMap::new();
    for (name, value) in entries {
        let Some(text) = scalar_text(value) else {
            continue;
        };
        let reject = |reason: String| ConfigError::MetricLabel {
            name: name.clone(),
            reason,
        };
        if labels.len() >= MAX_METRIC_LABELS {
            return Err(reject(format!("more than {MAX_METRIC_LABELS} labels")));
        }
        if name.len() > MAX_METRIC_LABEL_NAME_BYTES {
            return Err(reject(format!(
                "name is {} bytes, over the {MAX_METRIC_LABEL_NAME_BYTES}-byte limit",
                name.len()
            )));
        }
        if text.len() > MAX_METRIC_LABEL_VALUE_BYTES {
            return Err(reject(format!(
                "value is {} bytes, over the {MAX_METRIC_LABEL_VALUE_BYTES}-byte limit",
                text.len()
            )));
        }
        labels.insert(name.clone(), text);
    }
    Ok(labels)
}

/// Reads and validates `rules`, returning its directives even when it is ignored.
fn parse_deprecated_rules(object: &Map<String, Value>) -> Result<Option<Vec<String>>, ConfigError> {
    let Some(value) = object.get("rules") else {
        return Ok(None);
    };
    match value {
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(index, item)| scalar_text(item).ok_or(ConfigError::RulesElementNotScalar { index }))
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Value::Object(_) => Err(ConfigError::RulesNotArrayOrString { found: "object" }),
        Value::Null => Err(ConfigError::RulesNotArrayOrString { found: "null" }),
        scalar => Ok(Some(vec![scalar_text(scalar).unwrap_or_default()])),
    }
}

/// Reads `rule_data` within [`RULE_DATA_LIMITS`].
fn parse_rule_data(object: &Map<String, Value>) -> Result<BTreeMap<String, Vec<u8>>, ConfigError> {
    let mut files = BTreeMap::new();
    let Some(entries) = object.get("rule_data").and_then(Value::as_object) else {
        return Ok(files);
    };
    let mut total = 0_usize;
    let mut normalized_names = BTreeMap::new();
    for (name, value) in entries {
        let normalized = check_rule_data_name(name)?;
        if let Some(existing) = normalized_names.insert(normalized.clone(), name.clone()) {
            return Err(ConfigError::RuleData {
                name: name.clone(),
                reason: format!(
                    "name normalizes to {}, which key {} already uses",
                    display_name(&normalized),
                    display_name(&existing)
                ),
            });
        }
        let Some(bytes) = value.as_str() else {
            // The value carries no bytes, but a broken name must not hide behind it.
            continue;
        };
        add_rule_data(&mut files, &mut total, name, bytes.as_bytes(), RULE_DATA_LIMITS)?;
    }
    Ok(files)
}

/// Adds one `rule_data` file after checking every bound.
fn add_rule_data(
    files: &mut BTreeMap<String, Vec<u8>>,
    total: &mut usize,
    name: &str,
    bytes: &[u8],
    limits: RuleDataLimits,
) -> Result<(), ConfigError> {
    let reject = |reason: String| ConfigError::RuleData {
        name: name.to_owned(),
        reason,
    };
    if files.len() >= limits.files {
        return Err(reject(format!("the file list already holds {} files", limits.files)));
    }
    if bytes.len() > limits.file_bytes {
        return Err(reject(format!(
            "value is {} bytes, over the {}-byte per-file limit",
            bytes.len(),
            limits.file_bytes
        )));
    }
    let new_total = total.saturating_add(bytes.len());
    if new_total > limits.total_bytes {
        return Err(reject(format!(
            "the rule data total would be {new_total} bytes, over the {}-byte limit",
            limits.total_bytes
        )));
    }
    *total = new_total;
    files.insert(name.to_owned(), bytes.to_vec());
    Ok(())
}

/// Rejects a `rule_data` name that is empty, absolute, traversing or normalizes to empty.
///
/// Returns the name the engine's `Memory` source will store.
fn check_rule_data_name(name: &str) -> Result<String, ConfigError> {
    let reject = |reason: String| ConfigError::RuleData {
        name: name.to_owned(),
        reason,
    };
    if name.is_empty() {
        return Err(reject("name is empty".to_owned()));
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(reject(format!(
            "name is {} bytes, over the {MAX_NAME_BYTES}-byte limit",
            name.len()
        )));
    }
    if Path::new(name).is_absolute() {
        return Err(reject("name is absolute".to_owned()));
    }
    if name.split('/').any(|component| component == "..") {
        return Err(reject("name contains a '..' component".to_owned()));
    }
    let normalized = normalize_rule_data_name(name);
    if normalized.is_empty() {
        return Err(reject("name normalizes to an empty name".to_owned()));
    }
    Ok(normalized)
}

/// The `Memory` name a key stores, after dropping `.` and repeated separators.
///
/// This must stay identical to `coraza::rule_data::Memory`'s normalization, or a
/// name validated here would resolve to a different key at read time.
fn normalize_rule_data_name(name: &str) -> String {
    name.split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Configuration tests use fixed fixtures.")]
/// Configuration parsing tests.
mod tests {
    use std::collections::BTreeMap;

    use super::{
        add_rule_data, check_json_value_count, check_rule_data_name, display_name, Config, ConfigError, RuleDataLimits,
        MAX_AUTHORITIES, MAX_DISPLAY_NAME_BYTES, MAX_JSON_VALUES, MAX_METRIC_LABELS, MAX_METRIC_LABEL_NAME_BYTES,
        MAX_METRIC_LABEL_VALUE_BYTES, MAX_NAME_BYTES, MAX_RULE_DATA_FILES, MAX_RULE_DATA_FILE_BYTES, RULE_DATA_LIMITS,
    };

    /// Parses a document that must be accepted.
    fn parse(json: &str) -> Config {
        Config::parse(json.as_bytes()).unwrap()
    }

    /// Renders a parsed configuration error.
    fn parse_error(json: &str) -> String {
        Config::parse(json.as_bytes()).unwrap_err().to_string()
    }

    /// The directive list of `name`, for readable assertions.
    fn directives<'a>(config: &'a Config, name: &str) -> Vec<&'a str> {
        config
            .directives_map
            .get(name)
            .map(|list| list.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// A JSON document with `count` one-byte-rule-data files.
    fn many_rule_data_files(count: usize) -> Vec<u8> {
        let rule_data = (0..count)
            .map(|index| (format!("file{index}.txt"), serde_json::Value::String("x".to_owned())))
            .collect::<serde_json::Map<_, _>>();
        serde_json::json!({"rule_data": rule_data}).to_string().into_bytes()
    }

    #[test]
    fn blank_input_is_accepted_as_an_empty_configuration() {
        for input in ["", " ", "\n\t ", "  \r\n"] {
            let config = parse(input);
            assert!(config.directives_map.is_empty(), "blank input selects no policy");
            assert!(config.default_directives.is_none(), "blank input has no default");
            assert!(
                config.per_authority_directives.is_empty(),
                "blank input has no authorities"
            );
            assert!(config.rule_data.is_empty(), "blank input has no rule data");
            assert!(!config.enable_filter_state_logs, "blank input keeps state logs off");
        }
    }

    #[test]
    fn invalid_json_reports_the_upstream_prefix() {
        let message = parse_error("{");
        assert!(message.starts_with("invalid json: "), "message was {message:?}");
    }

    #[test]
    fn serde_rejections_are_reported_as_invalid_json() {
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        assert!(
            parse_error(&deep).starts_with("invalid json: "),
            "nesting over the serde_json recursion limit is rejected"
        );

        let invalid_utf8 = [b'{', b'"', 0xFF, b'"', b':', b'1', b'}'];
        assert!(
            Config::parse(&invalid_utf8)
                .unwrap_err()
                .to_string()
                .starts_with("invalid json: "),
            "invalid UTF-8 is rejected"
        );

        let out_of_range = parse_error(r#"{"metric_labels": {"n": 1e400}}"#);
        assert!(
            out_of_range.starts_with("invalid json: "),
            "an out-of-range number is rejected: {out_of_range:?}"
        );
    }

    #[test]
    fn non_object_documents_are_accepted_as_empty() {
        for input in ["[]", "\"text\"", "5", "true", "null"] {
            assert!(
                Config::parse(input.as_bytes()).is_ok(),
                "upstream reads a non-object document as empty: {input}"
            );
        }
    }

    #[test]
    fn parses_all_keys() {
        let config = parse(
            r#"{
                "directives_map": {"p1": ["SecRuleEngine On", "SecAction \"id:1\""], "p2": []},
                "default_directives": "p2",
                "per_authority_directives": {"a.example": "p1"},
                "metric_labels": {"env": "test", "weight": 3},
                "enable_filter_state_logs": true,
                "rule_data": {"data.txt": "attack\n"}
            }"#,
        );
        assert_eq!(
            directives(&config, "p1"),
            ["SecRuleEngine On", "SecAction \"id:1\""],
            "directives keep their order"
        );
        assert_eq!(config.default_directives.as_deref(), Some("p2"), "default policy");
        assert_eq!(
            config.per_authority_directives.get("a.example").map(String::as_str),
            Some("p1"),
            "authority policy"
        );
        assert_eq!(
            config.metric_labels.get("env").map(String::as_str),
            Some("test"),
            "label"
        );
        assert_eq!(
            config.metric_labels.get("weight").map(String::as_str),
            Some("3"),
            "number label"
        );
        assert!(config.enable_filter_state_logs, "state logs enabled");
        assert_eq!(
            config.rule_data.get("data.txt").map(Vec::as_slice),
            Some(b"attack\n".as_slice()),
            "rule data bytes"
        );
    }

    #[test]
    fn enable_filter_state_logs_defaults_to_false_and_tolerates_other_types() {
        assert!(!parse("{}").enable_filter_state_logs, "absent is false");
        assert!(
            parse(r#"{"enable_filter_state_logs": true}"#).enable_filter_state_logs,
            "true"
        );
        assert!(
            !parse(r#"{"enable_filter_state_logs": "true"}"#).enable_filter_state_logs,
            "a string is not a boolean, so the switch stays off"
        );
        assert!(
            !parse(r#"{"enable_filter_state_logs": 1}"#).enable_filter_state_logs,
            "a number is not a boolean"
        );
    }

    #[test]
    fn directives_coerce_scalars() {
        let config = parse(r#"{"directives_map": {"p": ["a", 1, 1.5, true, null, 1e30]}}"#);
        assert_eq!(
            directives(&config, "p"),
            ["a", "1", "1.5", "true", "", "1e+30"],
            "scalars stringify, null is empty and 1e30 is frozen as rendered"
        );
    }

    #[test]
    fn a_container_in_a_policy_directive_array_is_rejected() {
        for (value, expected_index) in [("[[\"x\"]]", 0), ("[\"ok\", {\"y\": 1}]", 1)] {
            let error = parse_error(&format!(r#"{{"directives_map": {{"p": {value}}}}}"#));
            assert_eq!(
                error,
                format!("directives_map policy \"p\" element {expected_index} must be a scalar"),
                "a container must not be silently dropped"
            );
        }
    }

    #[test]
    fn directives_map_must_be_an_object() {
        assert_eq!(
            parse_error(r#"{"directives_map": 7}"#),
            "directives_map must be an object"
        );
        assert_eq!(
            parse_error(r#"{"directives_map": null}"#),
            "directives_map must be an object"
        );
    }

    #[test]
    fn a_scalar_policy_value_becomes_one_directive() {
        let config = parse(r#"{"directives_map": {"p": "SecRuleEngine On", "q": null}}"#);
        assert_eq!(
            directives(&config, "p"),
            ["SecRuleEngine On"],
            "a scalar policy value is one directive"
        );
        assert_eq!(
            directives(&config, "q"),
            [""],
            "null is a scalar that renders as the empty directive"
        );
    }

    #[test]
    fn an_object_policy_value_is_rejected() {
        let error = parse_error(r#"{"directives_map": {"p": {"a": 1}}}"#);
        assert_eq!(error, "directives_map policy \"p\" must be an array or scalar");
    }

    #[test]
    fn deprecated_rules_create_the_default_policy_only_without_a_directive_map() {
        let legacy = parse(r#"{"rules": ["SecRuleEngine On", "SecRule ARGS \"@contains x\" \"id:1\""]}"#);
        assert_eq!(
            directives(&legacy, "default"),
            ["SecRuleEngine On", "SecRule ARGS \"@contains x\" \"id:1\""],
            "the deprecated list becomes the default policy"
        );
        assert_eq!(
            legacy.default_directives.as_deref(),
            Some("default"),
            "the deprecated list becomes the default selection"
        );

        let scalar_rules = parse(r#"{"rules": "SecRuleEngine On"}"#);
        assert_eq!(
            directives(&scalar_rules, "default"),
            ["SecRuleEngine On"],
            "a scalar rules value is one directive"
        );

        let with_map = parse(r#"{"directives_map": {"p": []}, "rules": ["SecRuleEngine On"]}"#);
        assert!(
            with_map.default_directives.is_none(),
            "rules are ignored beside a directive map"
        );
        assert!(
            !with_map.directives_map.contains_key("default"),
            "no synthetic policy is created beside a directive map"
        );
    }

    #[test]
    fn null_and_container_rules_are_rejected() {
        assert_eq!(
            parse_error(r#"{"rules": null}"#),
            "rules must be an array or string, not null"
        );
        assert_eq!(
            parse_error(r#"{"rules": {"a": 1}}"#),
            "rules must be an array or string, not object"
        );
        assert_eq!(
            parse_error(r#"{"rules": ["ok", ["nested"]]}"#),
            "rules[1] must be a scalar"
        );
    }

    #[test]
    fn default_directives_must_be_a_string() {
        for value in ["null", "[]", "{}", "7"] {
            let error = parse_error(&format!(
                r#"{{"directives_map": {{"p": []}}, "default_directives": {value}}}"#
            ));
            assert!(
                error.starts_with("default_directives must be a string, not "),
                "message was {error:?}"
            );
        }
        assert_eq!(
            parse(r#"{"directives_map": {"p": []}, "default_directives": "p"}"#)
                .default_directives
                .as_deref(),
            Some("p"),
            "a string is kept for compile-time resolution"
        );
        assert!(
            parse(r#"{"directives_map": {"p": []}, "default_directives": "missing"}"#)
                .default_directives
                .is_some(),
            "an unresolved name is kept so compilation can reject it"
        );
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let config = parse(r#"{"unknown": {"nested": true}, "enable_filter_state_logs": true}"#);
        assert!(config.directives_map.is_empty(), "no policy is configured");
        assert!(config.enable_filter_state_logs, "known keys are still read");
    }

    #[test]
    fn per_authority_directives_must_be_an_object_of_scalars() {
        assert_eq!(
            parse_error(r#"{"directives_map": {"p": []}, "per_authority_directives": "a.example"}"#),
            "per_authority_directives must be an object"
        );
        assert_eq!(
            parse_error(r#"{"directives_map": {"p": []}, "per_authority_directives": {"a": {"b": 1}}}"#),
            "per_authority_directives for authority \"a\" must be a string, not object"
        );
        assert_eq!(
            parse_error(r#"{"directives_map": {"p": []}, "per_authority_directives": {"": "p"}}"#),
            "per_authority_directives has an empty authority"
        );
        assert_eq!(
            parse_error(r#"{"directives_map": {"p": []}, "per_authority_directives": {"a.example": ""}}"#),
            "per_authority_directives for authority \"a.example\" names an empty policy"
        );

        let config =
            parse(r#"{"directives_map": {"p": []}, "per_authority_directives": {"a.example": "p", "b.example": 2}}"#);
        assert_eq!(
            config.per_authority_directives.get("b.example").map(String::as_str),
            Some("2"),
            "scalar values coerce"
        );
        assert!(
            parse(r#"{"directives_map": {"p": []}, "per_authority_directives": {"a": "missing"}}"#)
                .per_authority_directives
                .contains_key("a"),
            "an unresolved authority is kept so compilation can reject it"
        );
    }

    #[test]
    fn duplicate_keys_keep_the_last_value() {
        // Frozen divergence: serde_json collapses duplicates before this parser
        // runs, while upstream's directives_map keeps the first policy.
        let config = parse(r#"{"directives_map": {"p": ["first"], "p": ["last"]}}"#);
        assert_eq!(directives(&config, "p"), ["last"], "the last duplicate wins");
    }

    #[test]
    fn metric_labels_skip_containers_and_are_capped() {
        let config = parse(r#"{"metric_labels": {"env": "test", "nested": {"a": 1}, "list": [1]}}"#);
        assert_eq!(config.metric_labels.get("env").map(String::as_str), Some("test"));
        assert_eq!(config.metric_labels.len(), 1, "non-scalar values are skipped");

        assert_eq!(
            parse_error(r#"{"metric_labels": 7}"#),
            "metric_labels must be an object"
        );

        let mut labels = serde_json::Map::new();
        for index in 0..=MAX_METRIC_LABELS {
            labels.insert(format!("l{index}"), serde_json::Value::String("v".to_owned()));
        }
        let error = Config::parse(serde_json::json!({"metric_labels": labels}).to_string().as_bytes())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("more than {MAX_METRIC_LABELS} labels")),
            "the cap names the label: {error:?}"
        );
        assert!(
            error.starts_with("metric_labels \""),
            "the cap names the label: {error:?}"
        );

        let long_name = "a".repeat(MAX_METRIC_LABEL_NAME_BYTES + 1);
        let error = parse_error(&format!(r#"{{"metric_labels": {{"{long_name}": "v"}}}}"#));
        assert!(
            error.contains(&format!("over the {MAX_METRIC_LABEL_NAME_BYTES}-byte limit")),
            "message was {error:?}"
        );

        let long_value = "a".repeat(MAX_METRIC_LABEL_VALUE_BYTES + 1);
        let error = parse_error(&format!(r#"{{"metric_labels": {{"k": "{long_value}"}}}}"#));
        assert!(
            error.contains(&format!("over the {MAX_METRIC_LABEL_VALUE_BYTES}-byte limit")),
            "message was {error:?}"
        );
    }

    #[test]
    fn authority_table_is_capped() {
        let mut authorities = serde_json::Map::new();
        for index in 0..MAX_AUTHORITIES {
            authorities.insert(format!("a{index}.example"), serde_json::Value::String("p".to_owned()));
        }
        let at_limit = serde_json::json!({
            "directives_map": {"p": []},
            "per_authority_directives": authorities
        });
        assert!(
            Config::parse(at_limit.to_string().as_bytes()).is_ok(),
            "exactly {MAX_AUTHORITIES} authorities are accepted"
        );

        authorities.insert("one.too.many".to_owned(), serde_json::Value::String("p".to_owned()));
        let error = Config::parse(
            serde_json::json!({
                "directives_map": {"p": []},
                "per_authority_directives": authorities
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains(&format!("limit of {MAX_AUTHORITIES} authorities")),
            "message was {error:?}"
        );
    }

    #[test]
    fn rule_data_is_read_as_file_bytes() {
        let config = parse(r#"{"rule_data": {"data.txt": "attack\nscanner\n", "rules/a.conf": ""}}"#);
        assert_eq!(
            config.rule_data.get("data.txt").map(Vec::as_slice),
            Some(b"attack\nscanner\n".as_slice()),
            "the JSON string is the file"
        );
        assert_eq!(
            config.rule_data.get("rules/a.conf").map(Vec::as_slice),
            Some(b"".as_slice()),
            "an empty file is kept"
        );
    }

    #[test]
    fn rule_data_names_are_confined() {
        for (name, expected) in [
            ("", "name is empty"),
            ("/etc/passwd", "name is absolute"),
            ("../secret", "name contains a '..' component"),
            ("rules/../../secret", "name contains a '..' component"),
            (".", "name normalizes to an empty name"),
            ("./", "name normalizes to an empty name"),
        ] {
            let error = check_rule_data_name(name).unwrap_err().to_string();
            assert!(error.contains(expected), "name {name:?} reported {error:?}");
            assert!(
                error.contains(&format!("{name:?}")),
                "the error names the key: {error:?}"
            );
        }
    }

    #[test]
    fn rule_data_names_that_normalize_together_are_rejected() {
        let error = parse_error(r#"{"rule_data": {"a//b.txt": "x", "./a/b.txt": "y"}}"#);
        assert!(
            error.contains("name normalizes to \"a/b.txt\""),
            "message was {error:?}"
        );
        assert!(error.contains("\"a//b.txt\""), "message was {error:?}");
        assert!(error.contains("\"./a/b.txt\""), "message was {error:?}");
    }

    #[test]
    fn an_accepted_rule_data_name_is_the_name_memory_stores() {
        use coraza::rule_data::{Memory, RuleData as _};

        let deep = vec!["a"; 64].join("/");
        for name in [
            "data.txt",
            "./data.txt",
            "rules//data.txt",
            "rules/nested/data.txt",
            "Règles/Üñí.txt",
            deep.as_str(),
        ] {
            let accepted = check_rule_data_name(name).unwrap();
            let memory = Memory::new([(name.to_owned(), b"x".to_vec())]);
            assert_eq!(
                memory.read(std::path::Path::new(&accepted)).unwrap(),
                b"x",
                "the connector's normalized name {accepted:?} must be the one Memory stores for {name:?}"
            );
            // `read` normalizes its query too, so the stored name is checked by a glob, which
            // reports the names as stored.
            assert_eq!(
                memory.glob(&accepted).unwrap(),
                [std::path::PathBuf::from(&accepted)],
                "Memory must store {name:?} as {accepted:?}, not as a re-normalized name"
            );
        }
    }

    #[test]
    fn rule_data_caps_accept_the_boundary_and_reject_one_more() {
        assert!(
            Config::parse(&many_rule_data_files(MAX_RULE_DATA_FILES)).is_ok(),
            "exactly {MAX_RULE_DATA_FILES} files are accepted"
        );
        let error = Config::parse(&many_rule_data_files(MAX_RULE_DATA_FILES + 1))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("already holds {MAX_RULE_DATA_FILES} files")),
            "message was {error:?}"
        );

        let at_limit = serde_json::json!({"rule_data": {"a.txt": "a".repeat(MAX_RULE_DATA_FILE_BYTES)}});
        assert!(
            Config::parse(at_limit.to_string().as_bytes()).is_ok(),
            "exactly {MAX_RULE_DATA_FILE_BYTES} bytes are accepted"
        );
        let over = serde_json::json!({"rule_data": {"a.txt": "a".repeat(MAX_RULE_DATA_FILE_BYTES + 1)}});
        let error = Config::parse(over.to_string().as_bytes()).unwrap_err().to_string();
        assert!(
            error.contains(&format!("over the {MAX_RULE_DATA_FILE_BYTES}-byte per-file limit")),
            "message was {error:?}"
        );
    }

    #[test]
    fn total_rule_data_cap_accepts_the_boundary_and_rejects_one_more() {
        let file = "a".repeat(MAX_RULE_DATA_FILE_BYTES);
        let mut rule_data = serde_json::Map::new();
        for index in 0..RULE_DATA_LIMITS.total_bytes / MAX_RULE_DATA_FILE_BYTES {
            rule_data.insert(format!("f{index}.txt"), serde_json::Value::String(file.clone()));
        }
        let at_limit = serde_json::json!({"rule_data": rule_data});
        assert!(
            Config::parse(at_limit.to_string().as_bytes()).is_ok(),
            "exactly {} total bytes are accepted",
            RULE_DATA_LIMITS.total_bytes
        );

        rule_data.insert("one-more.txt".to_owned(), serde_json::Value::String("a".to_owned()));
        let error = Config::parse(serde_json::json!({"rule_data": rule_data}).to_string().as_bytes())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("over the {}-byte limit", RULE_DATA_LIMITS.total_bytes)),
            "message was {error:?}"
        );
    }

    #[test]
    fn rule_data_size_bounds_are_checked_with_small_limits() {
        let limits = RuleDataLimits {
            files: 2,
            file_bytes: 4,
            total_bytes: 6,
        };
        let mut files = BTreeMap::new();
        let mut total = 0;

        let error = add_rule_data(&mut files, &mut total, "a.txt", b"12345", limits)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("over the 4-byte per-file limit"),
            "message was {error:?}"
        );

        add_rule_data(&mut files, &mut total, "a.txt", b"123", limits).unwrap();
        let error = add_rule_data(&mut files, &mut total, "b.txt", b"1234", limits)
            .unwrap_err()
            .to_string();
        assert!(error.contains("over the 6-byte limit"), "message was {error:?}");

        add_rule_data(&mut files, &mut total, "b.txt", b"123", limits).unwrap();
        let error = add_rule_data(&mut files, &mut total, "c.txt", b"1", limits)
            .unwrap_err()
            .to_string();
        assert!(error.contains("already holds 2 files"), "message was {error:?}");
    }

    #[test]
    fn non_string_rule_data_values_are_ignored_but_named() {
        let config = parse(r#"{"rule_data": {"data.txt": 7, "other.txt": "kept"}}"#);
        assert_eq!(config.rule_data.len(), 1, "only string values carry bytes");
        assert!(config.rule_data.contains_key("other.txt"), "the string value is kept");

        let error = Config::parse(br#"{"rule_data": {"../x": 7}}"#).unwrap_err();
        assert!(
            matches!(error, ConfigError::RuleData { .. }),
            "a wrong-typed value does not bypass the name check"
        );
    }

    #[test]
    fn configured_names_are_capped_at_the_boundary() {
        let at_limit = "a".repeat(MAX_NAME_BYTES);
        assert!(
            Config::parse(format!(r#"{{"directives_map": {{"{at_limit}": []}}}}"#).as_bytes()).is_ok(),
            "exactly {MAX_NAME_BYTES} bytes are accepted"
        );
        let over = "a".repeat(MAX_NAME_BYTES + 1);
        let error = Config::parse(format!(r#"{{"directives_map": {{"{over}": []}}}}"#).as_bytes())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("over the {MAX_NAME_BYTES}-byte limit")),
            "message was {error:?}"
        );

        let error = Config::parse(format!(r#"{{"per_authority_directives": {{"{over}": "p"}}}}"#).as_bytes())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("over the {MAX_NAME_BYTES}-byte limit")),
            "message was {error:?}"
        );
        assert!(error.len() < 4096, "the message is bounded: {} bytes", error.len());

        let error = Config::parse(format!(r#"{{"default_directives": "{over}"}}"#).as_bytes())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("over the {MAX_NAME_BYTES}-byte limit")),
            "message was {error:?}"
        );

        let error = Config::parse(format!(r#"{{"rule_data": {{"{over}": "x"}}}}"#).as_bytes())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("over the {MAX_NAME_BYTES}-byte limit")),
            "message was {error:?}"
        );
    }

    #[test]
    fn display_names_are_quoted_truncated_and_escaped() {
        assert_eq!(display_name("plain"), "\"plain\"");
        assert_eq!(display_name("a\nb"), "\"a\\nb\"", "a newline cannot break the log line");

        let long = "é".repeat(MAX_DISPLAY_NAME_BYTES);
        let shown = display_name(&long);
        assert!(shown.starts_with('"') && shown.ends_with('"'), "quoted: {shown:?}");
        assert!(shown.ends_with("…\""), "truncated with an ellipsis: {shown:?}");
        assert!(
            shown.len() <= MAX_DISPLAY_NAME_BYTES + '…'.len_utf8() + 2,
            "the name is capped: {} bytes",
            shown.len()
        );
        assert!(!shown.contains('\n'), "no raw separators");
    }

    #[test]
    fn json_value_count_ignores_string_contents_and_tracks_structure() {
        let benign = br#"{"directives_map": {"p": ["a,b[c]{d}\"e\"\\", "f"]}}"#;
        assert!(
            check_json_value_count(benign).is_ok(),
            "commas and brackets inside strings are not values"
        );

        let mut crowded = String::from("[");
        for _ in 0..MAX_JSON_VALUES {
            crowded.push_str("1,");
        }
        crowded.push('1');
        crowded.push(']');
        assert!(
            matches!(
                check_json_value_count(crowded.as_bytes()),
                Err(ConfigError::TooManyValues)
            ),
            "the separator budget is enforced"
        );

        let invalid_utf8 = [0xFF, b',', 0xFF];
        assert!(
            check_json_value_count(&invalid_utf8).is_ok(),
            "arbitrary bytes are treated as untrusted input, not decoded"
        );
    }

    #[test]
    fn the_numeric_array_amplification_is_rejected_before_parsing() {
        // 16 MiB of one-byte numbers: about 739 MB as a serde_json Value tree.
        let mut json = String::with_capacity(16 * 1024 * 1024);
        json.push('[');
        while json.len() < 16 * 1024 * 1024 {
            json.push_str("1,");
        }
        json.push_str("1]");

        let error = Config::parse(json.as_bytes()).unwrap_err().to_string();
        assert!(
            error.contains(&format!("limit of {MAX_JSON_VALUES} value separators")),
            "the pre-scan rejects before serde builds a Config: {error:?}"
        );
        assert!(!error.starts_with("invalid json: "), "serde was not the rejecter");
    }

    #[test]
    fn long_directive_text_with_few_values_is_accepted() {
        let text = "a".repeat(8 * 1024 * 1024);
        let json = serde_json::json!({"directives_map": {"p": [text.clone()]}}).to_string();
        let config = Config::parse(json.as_bytes()).unwrap();
        assert_eq!(directives(&config, "p"), [text], "the 8 MiB directive survived");
    }

    #[test]
    fn directive_strings_with_structure_and_escaped_quotes_round_trip() {
        let directive = "a,b[c]{d} \"quoted\" \\ end";
        let json = serde_json::json!({"directives_map": {"p": [directive]}}).to_string();
        let config = Config::parse(json.as_bytes()).unwrap();
        assert_eq!(directives(&config, "p"), [directive]);
    }
}
