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

//! Transaction variable storage and lookup.
//!
//! This module stores values supplied by a connector and evaluates request and response
//! phases. Body bytes are retained in a bounded buffer that spills to a temporary file,
//! and each transaction exposes counters for what it supplied, retained and inspected.

mod body_buffer;
mod ctl;
mod request_body;
mod response_body;
mod variables;

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    ops::RangeInclusive,
    path::PathBuf,
    sync::Arc,
    time::SystemTime,
};

use body_buffer::BodyBuffer;
pub use body_buffer::BodyIngestionStats;
use request_body::parse_urlencoded;
use variables::BodyProcessor;
pub use variables::VariableCollection;

pub use crate::{actions::RuleMetadata, audit_log::MatchedRule};
use crate::{
    audit_log::{
        AuditFile, AuditLog, AuditLogger, AuditMessage, AuditMessageData, AuditProducer, AuditRequest, AuditResponse,
        AuditTransaction, ErrorLog, mime_type_of,
    },
    collection::{Map, MatchData, Single},
    config::{DetectorInspectionAction, WafConfig},
    operators::Macro,
    rules::{RuleGroup, VariableException},
    transformations::text_of,
    types::{AuditEngineStatus, AuditLogPart, AuditLogParts, RuleEngineStatus, RulePhase, RuleSeverity, RuleVariable},
    utils::time::UtcTime,
};

/// URI derivatives and start-time values, boxed so `Transaction` stays small.
struct ComputedVariables {
    /// The request URI as received, including any fragment.
    request_uri_raw: Single,
    /// The full request line supplied by the connector.
    request_line: Single,
    /// The decoded request path.
    request_filename: Single,
    /// The last path segment.
    request_basename: Single,
    /// The raw query string.
    query_string: Single,
    /// Whether the request URI could not be parsed.
    uri_parse_error: Single,
    /// Transaction start time as `hh:mm:ss`.
    time: Single,
    /// Transaction start day of month.
    time_day: Single,
    /// Transaction start time in seconds since the Unix epoch.
    time_epoch: Single,
    /// Transaction start hour of day.
    time_hour: Single,
    /// Transaction start minute of hour.
    time_min: Single,
    /// Transaction start month of year.
    time_mon: Single,
    /// Transaction start second of minute.
    time_sec: Single,
    /// Transaction start weekday, with Sunday as zero.
    time_wday: Single,
    /// Transaction start four-digit year.
    time_year: Single,
}

/// A disruptive action selected by a matching rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interruption {
    /// ID of the rule that interrupted the transaction.
    pub rule_id: i32,
    /// Disruptive action name.
    pub action: String,
    /// HTTP status associated with the action, or zero for `drop`.
    pub status: u16,
    /// Action data, such as a redirect URL.
    pub data: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Scope selected by an `allow` action.
enum AllowType {
    /// No allow action ran.
    Unset,
    /// Skip all later rules in this and subsequent phases.
    All,
    /// Skip later rules in the current phase.
    Phase,
    /// Skip later request phases.
    Request,
}

/// A transaction's input collections, rule state, and phase evaluation.
#[expect(
    clippy::struct_excessive_bools,
    reason = "fields mirror independent request and response controls"
)]
pub struct Transaction {
    /// The settings used to enforce transaction limits.
    config: Arc<WafConfig>,
    /// Compiled rules inherited from the WAF, possibly empty.
    rules: Arc<RuleGroup>,
    /// Rule-engine mode, which `ctl` actions may change per transaction.
    rule_engine: RuleEngineStatus,
    /// Whether this transaction inspects request bodies.
    request_body_access: bool,
    /// Maximum body size for this transaction, in bytes.
    request_body_limit: i64,
    /// Bounded retention of the request body supplied to this transaction.
    request_body_buffer: BodyBuffer,
    /// Whether to process a body without a recognized content type.
    force_request_body_variable: bool,
    /// Processor chosen by the first content type or a `ctl` action.
    request_body_processor: Option<BodyProcessor>,
    /// Whether this transaction inspects response bodies.
    response_body_access: bool,
    /// Maximum response body size for this transaction, in bytes.
    response_body_limit: i64,
    /// Bounded retention of the response body supplied to this transaction.
    response_body_buffer: BodyBuffer,
    /// Whether to inspect a response body without a configured MIME type.
    force_response_body_variable: bool,
    /// Processor selected by a `ctl` action for the response body.
    response_body_processor: Option<BodyProcessor>,
    /// Audit mode and parts, which `ctl` actions may change per transaction.
    audit_engine: AuditEngineStatus,
    /// Parts selected for this transaction's audit entry.
    audit_log_parts: AuditLogParts,
    /// Audit resources inherited from the WAF.
    audit_logger: Option<Arc<AuditLogger>>,
    /// Optional connector callback for rules with the `log` action.
    error_log: Option<ErrorLog>,
    /// Rules matched by this transaction.
    matched_rules: Vec<MatchedRule>,
    /// Transaction start time, used in audit records.
    started: SystemTime,
    /// Raw bodies retained only when an enabled audit entry requests them.
    audit_request_body: Vec<u8>,
    /// Retained response bytes for selected audit parts.
    audit_response_body: Vec<u8>,
    /// The last phase evaluated.
    last_phase: Option<RulePhase>,
    /// A disruptive action applied while the engine is on.
    interruption: Option<Interruption>,
    /// The first disruptive action that would apply in detection-only mode.
    would_be_interruption: Option<Interruption>,
    /// Number of following same-phase rules to skip.
    skip: i32,
    /// Rule IDs excluded for this transaction by `ctl`.
    removed_rule_ids: BTreeSet<i32>,
    /// Rule ID ranges excluded for this transaction by `ctl`.
    removed_rule_id_ranges: Vec<RangeInclusive<i32>>,
    /// Targets excluded for each rule ID by `ctl`.
    removed_rule_targets: BTreeMap<i32, Vec<(RuleVariable, VariableException)>>,
    /// Monotonic rule-removal controls already applied in this transaction.
    applied_rule_removals: BTreeSet<String>,
    /// Marker label to skip through, if any.
    skip_after: Option<String>,
    /// Rule allowance scope set by an `allow` action.
    allow: AllowType,
    /// The unique transaction identifier.
    unique_id: Single,
    /// The accumulated combined key and value size of GET and POST arguments.
    args_combined_size: usize,
    /// The combined size exposed to rule variables.
    args_combined_size_value: Single,
    /// Whether the argument limit dropped an input value.
    arguments_limit_reached: Single,
    /// All GET, POST, and path arguments.
    args: Map,
    /// Query string arguments.
    args_get: Map,
    /// Request body arguments supplied by the connector.
    args_post: Map,
    /// Parsed request XML attributes and text.
    request_xml: Map,
    /// Parsed JSON response body arguments.
    response_args: Map,
    /// Response XML collection, not populated by the supported response processors.
    response_xml: Map,
    /// Uploaded file names and temporary paths.
    files: Map,
    /// Form field names associated with uploaded files.
    files_names: Map,
    /// Uploaded file sizes indexed by file name.
    files_sizes: Map,
    /// Temporary paths exposed through `FILES_TMPNAMES`.
    files_tmp_names: Map,
    /// Native paths for uploads, retained so cleanup also works with non-UTF-8 paths.
    uploaded_paths: Vec<PathBuf>,
    /// Combined size of all parsed multipart parts.
    files_combined_size: Single,
    /// Multipart metadata indexed by each part name.
    multipart_name: Map,
    /// Original and extended filenames from `Content-Disposition`.
    multipart_filename: Map,
    /// Charset from the extended filename parameter.
    multipart_filename_charset: Map,
    /// Language from the extended filename parameter.
    multipart_filename_language: Map,
    /// Canonicalized headers from each multipart part.
    multipart_part_headers: Map,
    /// Multipart parser status and diagnostics.
    multipart_strict_error: Single,
    /// Whether any part repeated a header or disposition parameter.
    multipart_duplicate_part_header: Single,
    /// Whether any part quoted its extended filename parameter.
    multipart_invalid_quoting: Single,
    /// Path arguments supplied by the connector.
    args_path: Map,
    /// Indices of path arguments in the combined `ARGS` map, in insertion order.
    args_path_indices: Vec<(Vec<u8>, usize)>,
    /// Request headers supplied by the connector.
    request_headers: Map,
    /// Request cookies supplied by a connector that parsed them.
    request_cookies: Map,
    /// Response headers supplied by the connector.
    response_headers: Map,
    /// Transaction variables set by rule actions or the caller.
    tx: Map,
    /// Variables set by `setenv` for this transaction.
    env: Map,
    /// Latest matched input value.
    matched_var: Single,
    /// Name of the latest matched variable.
    matched_var_name: Single,
    /// Values matched by the current rule and its chain.
    matched_vars: Map,
    /// Metadata of the rule currently being evaluated.
    rule: Map,
    /// The request URI supplied by the connector.
    request_uri: Single,
    /// URI derivatives and start-time values computed for this transaction.
    computed: Box<ComputedVariables>,
    /// The request method supplied by the connector.
    request_method: Single,
    /// The request protocol supplied by the connector.
    request_protocol: Single,
    /// The client address supplied by the connector.
    remote_addr: Single,
    /// The client port supplied by the connector.
    remote_port: Single,
    /// The server address supplied by the connector.
    server_addr: Single,
    /// The server port supplied by the connector.
    server_port: Single,
    /// The server name supplied by the connector.
    server_name: Single,
    /// The response status supplied by the connector.
    response_status: Single,
    /// The response content type supplied by the connector.
    response_content_type: Single,
    /// The response protocol supplied by the connector.
    response_protocol: Single,
    /// Request body bytes supplied to phase 2.
    request_body: Single,
    /// Length of the body passed to its processor.
    request_body_length: Single,
    /// Whether the request body reached its configured limit.
    inbound_data_error: Single,
    /// Whether the request body processor reported an error.
    reqbody_error: Single,
    /// Error message from the request body processor.
    reqbody_error_msg: Single,
    /// Name of the selected request body processor.
    reqbody_processor: Single,
    /// Whether the request body processor reported an error.
    reqbody_processor_error: Single,
    /// Processor-specific error message.
    reqbody_processor_error_msg: Single,
    /// Response body bytes supplied to phase 4 when no parser is selected.
    response_body: Single,
    /// Length of the response body passed to its processor.
    response_content_length: Single,
    /// Whether the response body reached its configured limit.
    outbound_data_error: Single,
    /// Whether the response body processor reported an error.
    res_body_error: Single,
    /// Error message from the response body processor.
    res_body_error_msg: Single,
    /// Name of the selected response body processor.
    res_body_processor: Single,
    /// Whether the response body processor reported an error.
    res_body_processor_error: Single,
    /// Processor-specific response error message.
    res_body_processor_error_msg: Single,
    /// Highest matched rule severity, or 255 when none matched.
    highest_severity: Single,
    /// Whether a detector operator skipped an input as too large to inspect.
    inspection_incomplete: bool,
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "transaction impl blocks are split across submodules"
)]
impl Transaction {
    /// Create a transaction with the default WAF configuration.
    pub fn new(id: impl Into<String>) -> Self {
        Self::with_config(id, Arc::new(WafConfig::default()))
    }

    /// Create a transaction with the supplied WAF configuration.
    pub fn with_config(id: impl Into<String>, config: Arc<WafConfig>) -> Self {
        Self::with_rules(config, Arc::new(RuleGroup::new()), id)
    }

    /// Create a transaction with shared WAF configuration and compiled rules.
    #[expect(
        clippy::too_many_lines,
        reason = "initializes the transaction's typed variable collections"
    )]
    pub(crate) fn with_rules(config: Arc<WafConfig>, rules: Arc<RuleGroup>, id: impl Into<String>) -> Self {
        let case_sensitive_args_keys = config.case_sensitive_args_keys;
        let map = |variable: RuleVariable| {
            if case_sensitive_args_keys && variable.has_case_sensitive_keys() {
                Map::new_case_sensitive(variable)
            } else {
                Map::new(variable)
            }
        };
        let flag = |variable: RuleVariable| {
            let mut value = Single::new(variable);
            value.set("0");
            value
        };
        let text = |variable: RuleVariable, value: String| {
            let mut single = Single::new(variable);
            single.set(value);
            single
        };
        let mut unique_id = Single::new(RuleVariable::UniqueID);
        unique_id.set(id.into());

        let started = SystemTime::now();
        let epoch = started
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let at = UtcTime::from_unix(epoch);

        Self {
            rule_engine: config.rule_engine,
            request_body_access: config.request_body_access,
            request_body_limit: config.request_body_limit,
            request_body_buffer: BodyBuffer::default(),
            force_request_body_variable: false,
            request_body_processor: None,
            response_body_access: config.response_body_access,
            response_body_limit: config.response_body_limit,
            response_body_buffer: BodyBuffer::default(),
            force_response_body_variable: false,
            response_body_processor: None,
            audit_engine: config.audit_engine,
            audit_log_parts: config.audit_log_parts.clone(),
            audit_logger: None,
            error_log: None,
            matched_rules: Vec::new(),
            started,
            audit_request_body: Vec::new(),
            audit_response_body: Vec::new(),
            config,
            rules,
            last_phase: None,
            interruption: None,
            would_be_interruption: None,
            skip: 0,
            removed_rule_ids: BTreeSet::new(),
            removed_rule_id_ranges: Vec::new(),
            removed_rule_targets: BTreeMap::new(),
            applied_rule_removals: BTreeSet::new(),
            skip_after: None,
            allow: AllowType::Unset,
            unique_id,
            args_combined_size: 0,
            args_combined_size_value: flag(RuleVariable::ArgsCombinedSize),
            arguments_limit_reached: flag(RuleVariable::ArgumentsLimitReached),
            args: map(RuleVariable::Args),
            args_get: map(RuleVariable::ArgsGet),
            args_post: map(RuleVariable::ArgsPost),
            request_xml: map(RuleVariable::RequestXML),
            response_args: map(RuleVariable::ResponseArgs),
            response_xml: map(RuleVariable::ResponseXML),
            files: map(RuleVariable::Files),
            files_names: map(RuleVariable::FilesNames),
            files_sizes: map(RuleVariable::FilesSizes),
            files_tmp_names: map(RuleVariable::FilesTmpNames),
            uploaded_paths: Vec::new(),
            files_combined_size: flag(RuleVariable::FilesCombinedSize),
            multipart_name: map(RuleVariable::MultipartName),
            multipart_filename: map(RuleVariable::MultipartFilename),
            multipart_filename_charset: map(RuleVariable::MultipartFilenameCharset),
            multipart_filename_language: map(RuleVariable::MultipartFilenameLanguage),
            multipart_part_headers: map(RuleVariable::MultipartPartHeaders),
            multipart_strict_error: flag(RuleVariable::MultipartStrictError),
            multipart_duplicate_part_header: flag(RuleVariable::MultipartDuplicatePartHeader),
            multipart_invalid_quoting: flag(RuleVariable::MultipartInvalidQuoting),
            args_path: map(RuleVariable::ArgsPath),
            args_path_indices: Vec::new(),
            request_headers: map(RuleVariable::RequestHeaders),
            request_cookies: map(RuleVariable::RequestCookies),
            response_headers: map(RuleVariable::ResponseHeaders),
            tx: map(RuleVariable::TX),
            env: map(RuleVariable::Env),
            matched_var: Single::new(RuleVariable::MatchedVar),
            matched_var_name: Single::new(RuleVariable::MatchedVarName),
            matched_vars: map(RuleVariable::MatchedVars),
            rule: map(RuleVariable::Rule),
            request_uri: Single::new(RuleVariable::RequestURI),
            computed: Box::new(ComputedVariables {
                request_uri_raw: Single::new(RuleVariable::RequestURIRaw),
                request_line: Single::new(RuleVariable::RequestLine),
                request_filename: Single::new(RuleVariable::RequestFilename),
                request_basename: Single::new(RuleVariable::RequestBasename),
                query_string: Single::new(RuleVariable::QueryString),
                uri_parse_error: flag(RuleVariable::URIParseError),
                time: text(
                    RuleVariable::Time,
                    format!("{:02}:{:02}:{:02}", at.hour, at.minute, at.second),
                ),
                time_day: text(RuleVariable::TimeDay, at.day.to_string()),
                time_epoch: text(RuleVariable::TimeEpoch, epoch.to_string()),
                time_hour: text(RuleVariable::TimeHour, format!("{:02}", at.hour)),
                time_min: text(RuleVariable::TimeMin, format!("{:02}", at.minute)),
                time_mon: text(RuleVariable::TimeMon, at.month.to_string()),
                time_sec: text(RuleVariable::TimeSec, format!("{:02}", at.second)),
                time_wday: text(RuleVariable::TimeWday, at.weekday.to_string()),
                time_year: text(RuleVariable::TimeYear, at.year.to_string()),
            }),
            request_method: Single::new(RuleVariable::RequestMethod),
            request_protocol: Single::new(RuleVariable::RequestProtocol),
            remote_addr: Single::new(RuleVariable::RemoteAddr),
            remote_port: Single::new(RuleVariable::RemotePort),
            server_addr: Single::new(RuleVariable::ServerAddr),
            server_port: Single::new(RuleVariable::ServerPort),
            server_name: Single::new(RuleVariable::ServerName),
            response_status: Single::new(RuleVariable::ResponseStatus),
            response_content_type: Single::new(RuleVariable::ResponseContentType),
            response_protocol: Single::new(RuleVariable::ResponseProtocol),
            request_body: Single::new(RuleVariable::RequestBody),
            request_body_length: flag(RuleVariable::RequestBodyLength),
            inbound_data_error: flag(RuleVariable::InboundDataError),
            reqbody_error: flag(RuleVariable::ReqbodyError),
            reqbody_error_msg: Single::new(RuleVariable::ReqbodyErrorMsg),
            reqbody_processor: Single::new(RuleVariable::ReqbodyProcessor),
            reqbody_processor_error: flag(RuleVariable::ReqbodyProcessorError),
            reqbody_processor_error_msg: Single::new(RuleVariable::ReqbodyProcessorErrorMsg),
            response_body: Single::new(RuleVariable::ResponseBody),
            response_content_length: Single::new(RuleVariable::ResponseContentLength),
            outbound_data_error: flag(RuleVariable::OutboundDataError),
            // Go leaves the response body parser error variables unset until an
            // error occurs (internal/corazawaf/waf.go:274-283).
            res_body_error: Single::new(RuleVariable::ResBodyError),
            res_body_error_msg: Single::new(RuleVariable::ResBodyErrorMsg),
            res_body_processor: Single::new(RuleVariable::ResBodyProcessor),
            res_body_processor_error: Single::new(RuleVariable::ResBodyProcessorError),
            res_body_processor_error_msg: Single::new(RuleVariable::ResBodyProcessorErrorMsg),
            highest_severity: {
                let mut value = Single::new(RuleVariable::HighestSeverity);
                value.set("255");
                value
            },
            inspection_incomplete: false,
        }
    }

    /// The transaction ID as text.
    pub fn id(&self) -> Cow<'_, str> {
        self.unique_id.get()
    }

    /// Attach the WAF's shared audit writer.
    pub(crate) fn set_audit_logger(&mut self, logger: Arc<AuditLogger>) {
        self.audit_logger = Some(logger);
    }

    /// Attach the connector's matched-rule callback.
    pub(crate) fn set_error_log(&mut self, log: ErrorLog) {
        self.error_log = Some(log);
    }

    /// Rules that matched during this transaction, in evaluation order.
    pub fn matched_rules(&self) -> &[MatchedRule] {
        &self.matched_rules
    }

    /// Record a matched rule, notifying the connector and retaining it for audit output.
    pub(crate) fn record_match(
        &mut self,
        rule: RuleMetadata,
        matches: Vec<MatchData>,
        disruptive_action: Option<&'static str>,
    ) {
        let matched = MatchedRule {
            rule,
            matches,
            disruptive_action,
            disruptive: disruptive_action.is_some() && self.rule_engine == RuleEngineStatus::On,
            client_ip: self.remote_addr.get().into_owned(),
            server_ip: self.server_addr.get().into_owned(),
            uri: self.request_uri.get().into_owned(),
            transaction_id: self.unique_id.get().into_owned(),
        };
        if let Some(error_log) = self.error_log.as_ref().filter(|_| matched.rule.log) {
            error_log.write(&matched);
        }
        self.matched_rules.push(matched);
    }

    /// Update the transaction's most severe matched rule.
    pub(crate) fn raise_highest_severity(&mut self, severity: RuleSeverity) {
        let highest = self.highest_severity.get().parse::<u8>().unwrap_or(u8::MAX);
        if severity.as_int() < highest {
            self.highest_severity.set(severity.as_int().to_string());
        }
    }

    /// Return the rule-engine mode currently applied to this transaction.
    pub fn rule_engine(&self) -> RuleEngineStatus {
        self.rule_engine
    }

    /// Whether this transaction currently inspects response bodies.
    pub fn response_body_access(&self) -> bool {
        self.response_body_access
    }

    /// Return the request body limit currently applied to this transaction.
    pub fn request_body_limit(&self) -> i64 {
        self.request_body_limit
    }

    /// Return counters for the request body bytes this transaction received.
    pub fn request_body_stats(&self) -> BodyIngestionStats {
        self.request_body_buffer.stats()
    }

    /// Return counters for the response body bytes this transaction received.
    pub fn response_body_stats(&self) -> BodyIngestionStats {
        self.response_body_buffer.stats()
    }

    /// Return the request body spill file path, if the body spilled, for cleanup tests.
    #[cfg(test)]
    fn request_body_spill_path(&self) -> Option<&std::path::Path> {
        self.request_body_buffer.spill_path()
    }

    /// Evaluate request-header rules once using the values already stored on this
    /// transaction. Returns the disruptive interruption, if any.
    pub fn process_request_headers(&mut self) -> Option<Interruption> {
        if self.begin_phase(RulePhase::RequestHeaders) {
            self.run_phase(RulePhase::RequestHeaders);
        }
        self.interruption.clone()
    }

    /// Begin a phase once and only after its required predecessor.
    fn begin_phase(&mut self, phase: RulePhase) -> bool {
        if self.rule_engine == RuleEngineStatus::Off || self.interruption.is_some() {
            return false;
        }
        let in_order = match phase {
            RulePhase::RequestBody => self.last_phase == Some(RulePhase::RequestHeaders),
            RulePhase::ResponseBody => self.last_phase == Some(RulePhase::ResponseHeaders),
            _ => self.last_phase.is_none_or(|last| last < phase),
        };
        if in_order {
            self.last_phase = Some(phase);
        }
        in_order
    }

    /// Return the interruption applied by a matching disruptive action.
    pub fn interruption(&self) -> Option<&Interruption> {
        self.interruption.as_ref()
    }

    /// Return the first interruption that would have applied in detection-only mode.
    pub fn would_be_interruption(&self) -> Option<&Interruption> {
        self.would_be_interruption.as_ref()
    }

    /// Return the last phase evaluated by this transaction.
    pub fn last_phase(&self) -> Option<RulePhase> {
        self.last_phase
    }

    /// Evaluate response-header rules once after all response headers are stored.
    pub fn process_response_headers(&mut self, status_code: u16, protocol: &str) -> Option<Interruption> {
        if !self.begin_phase(RulePhase::ResponseHeaders) {
            return self.interruption.clone();
        }
        self.response_status.set(status_code.to_string());
        self.response_protocol.set(protocol);
        self.run_phase(RulePhase::ResponseHeaders);
        self.interruption.clone()
    }

    /// Run logging rules and write this transaction's audit entry once.
    ///
    /// Call this after response processing when the caller needs to observe write errors.
    /// Dropping a transaction also runs the logging phase and ignores any write error.
    ///
    /// # Errors
    ///
    /// Returns an error if the configured audit writer fails.
    pub fn process_logging(&mut self) -> std::io::Result<()> {
        if self.last_phase == Some(RulePhase::Logging) {
            return Ok(());
        }
        self.last_phase = Some(RulePhase::Logging);
        if self.rule_engine != RuleEngineStatus::Off {
            self.run_phase(RulePhase::Logging);
        }

        let Some(logger) = self.audit_logger.clone() else {
            return Ok(());
        };
        let should_log = match self.audit_engine {
            AuditEngineStatus::Off => false,
            AuditEngineStatus::On => true,
            AuditEngineStatus::RelevantOnly => {
                let status = self
                    .interruption
                    .as_ref()
                    .or(self.would_be_interruption.as_ref())
                    .map_or_else(
                        || self.response_status.get().into_owned(),
                        |value| value.status.to_string(),
                    );
                let audited = self.matched_rules.iter().any(|matched| matched.rule.audit_log);
                logger.is_relevant(audited, &status)
            },
        };
        if should_log {
            logger.write(&self.audit_log())?;
        }
        Ok(())
    }

    /// Build this transaction's audit entry using the current audit parts.
    #[expect(
        clippy::too_many_lines,
        reason = "builds the typed record from all selected transaction fields"
    )]
    pub fn audit_log(&self) -> AuditLog {
        let elapsed = self.started.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let at = UtcTime::from_unix(elapsed.as_secs());
        let mut transaction = AuditTransaction {
            timestamp: format!(
                "{:04}/{:02}/{:02} {:02}:{:02}:{:02}",
                at.year, at.month, at.day, at.hour, at.minute, at.second
            ),
            unix_timestamp: i64::try_from(elapsed.as_nanos()).unwrap_or(i64::MAX),
            id: self.unique_id.get().into_owned(),
            client_ip: self.remote_addr.get().into_owned(),
            client_port: self.remote_port.get().parse().unwrap_or(0),
            host_ip: self.server_addr.get().into_owned(),
            host_port: self.server_port.get().parse().unwrap_or(0),
            server_id: self.server_name.get().into_owned(),
            request: AuditRequest {
                method: self.request_method.get().into_owned(),
                protocol: self.request_protocol.get().into_owned(),
                uri: self.request_uri.get().into_owned(),
                length: i32::try_from(self.audit_request_body.len()).unwrap_or(i32::MAX),
                args: self
                    .args
                    .iter()
                    .map(|(key, value)| (key.to_owned(), text_of(value).into_owned()))
                    .collect(),
                ..AuditRequest::default()
            },
            highest_severity: self.highest_severity.get().into_owned(),
            is_interrupted: self.interruption.is_some(),
            ..AuditTransaction::default()
        };

        let has = |part| self.audit_log_parts.contains(&part);
        if has(AuditLogPart::RequestHeaders) {
            transaction.request.headers = Some(self.request_headers.entries());
        }
        if has(AuditLogPart::RequestBody) {
            transaction.request.body = text_of(&self.audit_request_body).into_owned();
        }
        if has(AuditLogPart::UploadedFiles) {
            transaction.request.files = Some(
                self.files
                    .iter()
                    .map(|(_, filename)| {
                        let name = text_of(filename).into_owned();
                        AuditFile {
                            size: self
                                .files_sizes
                                .get(&name)
                                .first()
                                .and_then(|size| size.parse().ok())
                                .unwrap_or(0),
                            mime: mime_type_of(&name).to_owned(),
                            name,
                        }
                    })
                    .collect(),
            );
        }
        if has(AuditLogPart::IntermediaryResponseBody)
            || has(AuditLogPart::ResponseBody)
            || has(AuditLogPart::ResponseHeaders)
        {
            let mut response = AuditResponse {
                protocol: self.response_protocol.get().into_owned(),
                ..AuditResponse::default()
            };
            if has(AuditLogPart::IntermediaryResponseBody) || has(AuditLogPart::ResponseBody) {
                response.body = text_of(&self.audit_response_body).into_owned();
            }
            if has(AuditLogPart::ResponseHeaders) {
                response.status = self.response_status.get().parse().unwrap_or(0);
                response.headers = Some(self.response_headers.entries());
            }
            transaction.response = Some(response);
        }
        let trailer = has(AuditLogPart::Trailer);
        if trailer {
            let elapsed_ns = SystemTime::now()
                .duration_since(self.started)
                .map_or(0, |duration| duration.as_nanos());
            transaction.producer = Some(AuditProducer {
                rule_engine: self.rule_engine.as_str().to_owned(),
                stopwatch: format!(
                    "{} {elapsed_ns}; combined=0, p1=0, p2=0, p3=0, p4=0, p5=0",
                    transaction.unix_timestamp
                ),
                rulesets: self.config.component_names.clone(),
                ..AuditProducer::default()
            });
        }

        let audited = self.matched_rules.iter().filter(|matched| matched.rule.audit_log);
        let messages = if has(AuditLogPart::RulesMatched) {
            audited
                .flat_map(|matched| {
                    matched.matches.iter().map(move |data| {
                        let rule = &matched.rule;
                        AuditMessage {
                            actionset: self.config.component_names.join(" "),
                            message: data.message.clone(),
                            error_message: if trailer { matched.error_log() } else { String::new() },
                            data: AuditMessageData {
                                file: rule.file.clone(),
                                line: rule.line,
                                id: rule.id,
                                rev: rule.rev.clone(),
                                msg: data.message.clone(),
                                data: data.data.clone(),
                                severity: rule.severity.map_or(-1, |severity| severity.as_int().cast_signed()),
                                ver: rule.ver.clone(),
                                maturity: rule.maturity,
                                accuracy: rule.accuracy,
                                tags: rule.tags.clone(),
                                raw: rule.raw.clone(),
                            },
                        }
                    })
                })
                .collect()
        } else if trailer {
            audited
                .map(|matched| AuditMessage {
                    error_message: matched.error_log(),
                    ..AuditMessage::default()
                })
                .collect()
        } else {
            Vec::new()
        };

        AuditLog {
            parts: self.audit_log_parts.clone(),
            transaction,
            messages,
        }
    }

    /// Evaluate rules assigned to `phase` in directive order.
    fn run_phase(&mut self, phase: RulePhase) {
        let rules = Arc::clone(&self.rules);

        for rule in rules.iter() {
            if (phase != RulePhase::Logging && self.interruption.is_some()) || self.is_allowed(phase) {
                break;
            }
            if rule.metadata().phase != RulePhase::Unknown && rule.metadata().phase != phase {
                continue;
            }
            if (!self.removed_rule_ids.is_empty() || !self.removed_rule_id_ranges.is_empty())
                && self.is_rule_removed(rule.metadata().id)
            {
                continue;
            }
            if let Some(marker) = &self.skip_after {
                let reached_marker = rule.metadata().sec_mark.as_deref() == Some(marker);
                if reached_marker {
                    self.skip_after = None;
                }
                continue;
            }
            if self.skip > 0 {
                self.skip -= 1;
                continue;
            }

            self.reset_matched_vars();
            rule.evaluate(self);
        }
        self.skip = 0;
        if self.allow == AllowType::Phase {
            self.allow = AllowType::Unset;
        }
    }

    /// Whether an earlier allow action skips rules in `phase`.
    fn is_allowed(&self, phase: RulePhase) -> bool {
        match self.allow {
            AllowType::Unset => false,
            AllowType::All | AllowType::Phase => phase != RulePhase::Logging,
            AllowType::Request => matches!(phase, RulePhase::RequestHeaders | RulePhase::RequestBody),
        }
    }

    /// Apply a disruptive action according to the transaction's engine mode.
    pub(crate) fn interrupt(&mut self, rule_id: i32, action: &str, status: i32, data: &str) {
        let interruption = Interruption {
            rule_id,
            action: action.to_owned(),
            status: u16::try_from(status).unwrap_or(0),
            data: data.to_owned(),
        };
        match self.rule_engine {
            RuleEngineStatus::On => self.interruption = Some(interruption),
            RuleEngineStatus::DetectionOnly => {
                self.would_be_interruption.get_or_insert(interruption);
            },
            RuleEngineStatus::Off => {},
        }
    }

    /// Set the rule-skip scope for an `allow` action.
    pub(crate) fn allow(&mut self, scope: &str) {
        if self.rule_engine != RuleEngineStatus::On {
            return;
        }
        self.allow = match scope {
            "phase" => AllowType::Phase,
            "request" => AllowType::Request,
            _ => AllowType::All,
        };
    }

    /// Skip the next `count` rules in the current phase.
    pub(crate) fn set_skip(&mut self, count: i32) {
        self.skip = count;
    }

    /// Skip rules through the named marker.
    pub(crate) fn set_skip_after(&mut self, marker: &str) {
        self.skip_after = Some(marker.to_owned());
    }

    /// Apply the supported TX collection form of `setvar`.
    pub(crate) fn apply_setvar(&mut self, expression: &str) {
        let (remove, expression) = expression
            .strip_prefix('!')
            .map_or((false, expression), |rest| (true, rest));
        let Some((collection, assignment)) = expression.split_once('.') else {
            return;
        };
        if !collection.eq_ignore_ascii_case("TX") {
            return;
        }
        let (key, value) = assignment.split_once('=').unwrap_or((assignment, ""));
        let Ok(key) = Macro::new(key) else {
            return;
        };
        let key = key.expand(self).to_ascii_lowercase();
        if remove {
            self.tx.remove(&key);
            return;
        }
        let Ok(value) = Macro::new(value) else {
            return;
        };
        let value = value.expand(self);
        let arithmetic = value
            .strip_prefix('+')
            .map(|number| (true, number))
            .or_else(|| value.strip_prefix('-').map(|number| (false, number)));
        if let Some((add, number)) = arithmetic
            && let Ok(number) = number.parse::<i64>()
        {
            let current = self
                .get_variable(RuleVariable::TX, Some(&key))
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(0);
            let result = if add {
                current.saturating_add(number)
            } else {
                current.saturating_sub(number)
            };
            self.set_tx_variable(&key, result.to_string());
            return;
        }
        self.set_tx_variable(&key, value);
    }

    /// Set a transaction-scoped `ENV` value without changing the process environment.
    pub(crate) fn apply_setenv(&mut self, expression: &str) {
        let Some((key, value)) = expression.split_once('=') else {
            return;
        };
        let Ok(value) = Macro::new(value) else {
            return;
        };
        self.env.set(key.trim(), [value.expand(self)]);
    }

    /// Set the request URI supplied by the connector.
    pub fn set_request_uri(&mut self, value: impl AsRef<[u8]>) {
        self.set_single(RuleVariable::RequestURI, value);
    }

    /// Set the request method supplied by the connector.
    pub fn set_request_method(&mut self, value: impl AsRef<[u8]>) {
        self.set_single(RuleVariable::RequestMethod, value);
    }

    /// Set the request protocol supplied by the connector.
    pub fn set_request_protocol(&mut self, value: impl AsRef<[u8]>) {
        self.set_single(RuleVariable::RequestProtocol, value);
    }

    /// Set the client address supplied by the connector.
    pub fn set_remote_addr(&mut self, value: impl AsRef<[u8]>) {
        self.set_single(RuleVariable::RemoteAddr, value);
    }

    /// Set the client port supplied by the connector.
    pub fn set_remote_port(&mut self, value: u16) {
        self.set_single(RuleVariable::RemotePort, value.to_string());
    }

    /// Set the server address supplied by the connector.
    pub fn set_server_addr(&mut self, value: impl AsRef<[u8]>) {
        self.set_single(RuleVariable::ServerAddr, value);
    }

    /// Set the server port supplied by the connector.
    pub fn set_server_port(&mut self, value: u16) {
        self.set_single(RuleVariable::ServerPort, value.to_string());
    }

    /// Set the server name supplied by the connector.
    pub fn set_server_name(&mut self, value: impl AsRef<[u8]>) {
        self.set_single(RuleVariable::ServerName, value);
    }

    /// Set the response status supplied by the connector.
    pub fn set_response_status(&mut self, status: u16) {
        self.set_single(RuleVariable::ResponseStatus, status.to_string());
    }

    /// Set the request line fields and populate the URI and query variables.
    ///
    /// This mirrors Go Coraza's `ProcessURI`: the target is parsed as an absolute URI or
    /// absolute path, URI derivatives come from the parsed form, and a target Go would
    /// reject still populates `QUERY_STRING` and `ARGS_GET` from a best-effort split.
    pub fn process_uri(&mut self, uri: &str, method: &str, protocol: &str) {
        self.set_single(RuleVariable::RequestLine, format!("{method} {uri} {protocol}"));
        self.set_single(RuleVariable::RequestURIRaw, uri);
        self.set_request_method(method);
        self.set_request_protocol(protocol);

        let target = uri.split_once('#').map_or(uri, |(target, _)| target);
        if let Some(parsed) = parse_request_target(target) {
            self.set_single(RuleVariable::RequestURI, &parsed.request_uri);
            self.set_single(RuleVariable::QueryString, &parsed.raw_query);
            self.set_request_path(&parsed.path);
            self.add_query_arguments(&parsed.raw_query);
        } else {
            self.set_single(RuleVariable::URIParseError, "1");
            self.set_single(RuleVariable::RequestURI, target);
            let (path, query) = target.split_once('?').unwrap_or((target, ""));
            self.set_single(RuleVariable::QueryString, query);
            self.set_request_path(path.as_bytes());
            self.add_query_arguments(query);
        }
    }

    /// Store `REQUEST_FILENAME` and `REQUEST_BASENAME` for a decoded path.
    fn set_request_path(&mut self, path: &[u8]) {
        let basename = path
            .iter()
            .rposition(|&byte| matches!(byte, b'/' | b'\\'))
            .filter(|offset| path.len() > offset.saturating_add(1))
            .and_then(|offset| path.get(offset.saturating_add(1)..))
            .unwrap_or(path);
        self.set_single(RuleVariable::RequestBasename, basename);
        self.set_single(RuleVariable::RequestFilename, path);
    }

    /// Add the decoded pairs of a raw query string to the GET collections.
    fn add_query_arguments(&mut self, query: &str) {
        for (key, value) in parse_urlencoded(query.as_bytes()) {
            self.add_get_argument(key, value);
        }
    }

    /// Add a query argument to `ARGS_GET` and `ARGS`, keeping the decoded name bytes.
    pub fn add_get_argument(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        let key = key.as_ref();
        let value = value.as_ref();
        if self.within_argument_limit(self.args_get.value_count()) {
            self.args_get.add_bytes(key, value);
            self.args.add_bytes(key, value);
            self.update_args_combined_size(key, value);
        }
    }

    /// Add a request body argument to `ARGS_POST` and `ARGS`, keeping the decoded name bytes.
    pub fn add_post_argument(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        let key = key.as_ref();
        let value = value.as_ref();
        if self.within_argument_limit(self.args_post.value_count()) {
            self.args_post.add_bytes(key, value);
            self.args.add_bytes(key, value);
            self.update_args_combined_size(key, value);
        }
    }

    /// Add a connector-supplied path argument to `ARGS_PATH` and `ARGS`, keeping the name bytes.
    pub fn add_path_argument(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        let key = key.as_ref();
        let value = value.as_ref();
        if self.within_argument_limit(self.args_path.value_count()) {
            let args_index = self.args.values(key).count();
            self.args_path.add_bytes(key, value);
            self.args.add_bytes(key, value);
            self.args_path_indices.push((key.to_vec(), args_index));
        }
    }

    /// Store a request header value as supplied by the connector.
    ///
    /// `Cookie` headers are also parsed into `REQUEST_COOKIES`, as Go Coraza does.
    /// Connectors that already split cookies may keep using [`Transaction::add_request_cookie`];
    /// both paths accumulate values.
    pub fn add_request_header(&mut self, key: &str, value: impl AsRef<[u8]>) {
        let value = value.as_ref();
        let first_content_type =
            key.eq_ignore_ascii_case("content-type") && self.request_headers.first("content-type").is_none();
        self.request_headers.add(key, value);
        if key.eq_ignore_ascii_case("cookie") {
            self.parse_request_cookies(value);
        }
        if first_content_type && let Some(processor) = BodyProcessor::for_content_type(value) {
            self.set_request_body_processor(processor.name());
        }
    }

    /// Split one `Cookie` header into `REQUEST_COOKIES` the way Go's parser does.
    fn parse_request_cookies(&mut self, value: &[u8]) {
        for part in value.split(|&byte| byte == b';') {
            let part = trim_cookie(part);
            if part.is_empty() {
                continue;
            }
            let (name, value) = match part.iter().position(|&byte| byte == b'=') {
                Some(index) => (
                    part.get(..index).unwrap_or_default(),
                    part.get(index.saturating_add(1)..).unwrap_or_default(),
                ),
                None => (part, &b""[..]),
            };
            let name = trim_cookie(name);
            let value = trim_cookie(value);
            // Go keeps a pair with an empty name but a non-empty value, such as "=payload".
            if name.is_empty() && value.is_empty() {
                continue;
            }
            self.request_cookies.add(&text_of(name), value);
        }
    }

    /// Store a request cookie supplied by a connector that already parsed cookies.
    pub fn add_request_cookie(&mut self, key: &str, value: impl AsRef<[u8]>) {
        self.request_cookies.add(key, value);
    }

    /// Store a response header value as supplied by the connector.
    pub fn add_response_header(&mut self, key: &str, value: impl AsRef<[u8]>) {
        let value = value.as_ref();
        let first_content_type =
            key.eq_ignore_ascii_case("content-type") && self.response_headers.first("content-type").is_none();
        self.response_headers.add(key, value);
        if first_content_type {
            self.response_content_type.set("");
            if let Ok(value) = std::str::from_utf8(value) {
                self.response_content_type
                    .set(value.split(';').next().unwrap_or(value).trim());
            }
        }
    }

    /// Clear captures and matched values from the rule evaluated previously.
    fn reset_matched_vars(&mut self) {
        self.matched_vars.reset();
        for index in 0..10 {
            self.tx.remove(&index.to_string());
        }
    }

    /// Whether an argument was dropped because the configured limit was reached.
    pub fn arguments_limit_reached(&self) -> bool {
        self.arguments_limit_reached.get_bytes() == b"1"
    }

    /// Whether a detector operator skipped an input because it was too large to inspect.
    ///
    /// The `detectSQLi` and `detectXSS` operators scan values up to
    /// [`libperfusion::MAX_INPUT_LEN`] bytes, the bound of libperfusion's public
    /// detection wrappers. A longer value has no verdict, so the operator reports
    /// [`OperatorOutcome::NotInspected`](crate::operators::OperatorOutcome::NotInspected)
    /// instead of matching. This method returns `true` once at least one detector
    /// operator skipped an input, and the transaction variable
    /// `TX.inspection_incomplete` is set to `"1"`; both stay clear otherwise.
    ///
    /// By default the affected rule continues as a miss. Set
    /// [`WafConfig::detector_inspection_action`] to
    /// [`DetectorInspectionAction::FailClosed`] to interrupt the transaction instead.
    pub fn inspection_incomplete(&self) -> bool {
        self.inspection_incomplete
    }

    /// Record that a detector operator skipped an input and apply the configured policy.
    ///
    /// The signal is recorded once, but `FailClosed` applies on every skipped input,
    /// including after a `ctl` switches the rule engine from `DetectionOnly` to `On`.
    /// An interruption that is already set is never replaced, so the first disruptive
    /// action keeps its rule, status and data.
    pub(crate) fn record_inspection_incomplete(&mut self, rule_id: i32) {
        if !self.inspection_incomplete {
            self.inspection_incomplete = true;
            self.set_tx_variable("inspection_incomplete", "1");
        }
        if self.config.detector_inspection_action == DetectorInspectionAction::FailClosed && self.interruption.is_none()
        {
            self.interrupt(rule_id, "deny", 500, "detector input exceeds the inspection bound");
        }
    }

    /// Check the per-collection argument limit and set its flag when reached.
    fn within_argument_limit(&mut self, current_count: usize) -> bool {
        let within = current_count < self.config.argument_limit;
        if !within {
            self.arguments_limit_reached.set("1");
        }
        within
    }

    /// Add one GET or POST argument's byte lengths to the combined size.
    fn update_args_combined_size(&mut self, key: &[u8], value: &[u8]) {
        self.args_combined_size = self
            .args_combined_size
            .saturating_add(key.len())
            .saturating_add(value.len());
        self.args_combined_size_value.set(self.args_combined_size.to_string());
    }
}

/// Trim the ASCII control bytes and spaces Go trims around a cookie name or value.
fn trim_cookie(bytes: &[u8]) -> &[u8] {
    let kept = |byte: &u8| *byte > 0x20 && *byte != 0x7F;
    let start = bytes.iter().position(kept).unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(kept)
        .map_or(start, |index| index.saturating_add(1));
    bytes.get(start..end).unwrap_or_default()
}

/// A request target parsed the way Go's `net/url.ParseRequestURI` parses one.
struct ParsedRequestTarget {
    /// `REQUEST_URI`, rendered the way Go's `URL.String` renders the parsed URL.
    request_uri: Vec<u8>,
    /// `REQUEST_FILENAME`, the decoded path.
    path: Vec<u8>,
    /// `QUERY_STRING`, without the leading `?`.
    raw_query: String,
}

/// The URL components that decide how Go re-encodes a value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EscapeMode {
    /// A URL path.
    Path,
    /// A host name.
    Host,
    /// An IPv6 zone identifier.
    Zone,
    /// A userinfo user name or password.
    UserPassword,
}

/// Parse an absolute URI or absolute path as Go's `ParseRequestURI` does.
///
/// Returns `None` for targets Go rejects, including empty targets, relative paths,
/// raw control bytes, malformed escapes, malformed ports and invalid IP literals.
fn parse_request_target(target: &str) -> Option<ParsedRequestTarget> {
    if target.bytes().any(|byte| byte < 0x20 || byte == 0x7F) {
        return None;
    }
    if target.is_empty() {
        return None;
    }
    if target == "*" {
        return Some(ParsedRequestTarget {
            request_uri: b"*".to_vec(),
            path: b"*".to_vec(),
            raw_query: String::new(),
        });
    }

    let (scheme, rest) = split_scheme(target)?;
    let (rest, raw_query, force_query) = split_query(rest);

    if !rest.starts_with('/') {
        // A rootless target after a scheme is opaque; without a scheme it is invalid.
        if scheme.is_empty() {
            return None;
        }
        let mut request_uri = scheme.into_bytes();
        request_uri.push(b':');
        request_uri.extend_from_slice(rest.as_bytes());
        if force_query || !raw_query.is_empty() {
            request_uri.push(b'?');
            request_uri.extend_from_slice(raw_query.as_bytes());
        }
        return Some(ParsedRequestTarget {
            request_uri,
            path: Vec::new(),
            raw_query: raw_query.to_owned(),
        });
    }

    let (host, userinfo, path_source, omit_host) = if !scheme.is_empty() && rest.starts_with("//") {
        let after_slashes = rest.strip_prefix("//").unwrap_or_default();
        let (authority, path) = match after_slashes.find('/') {
            Some(index) => (
                after_slashes.get(..index).unwrap_or_default(),
                after_slashes.get(index..).unwrap_or_default(),
            ),
            None => (after_slashes, ""),
        };
        let (userinfo, host) = parse_authority(authority)?;
        (Some(host), userinfo, path, false)
    } else if !scheme.is_empty() {
        (None, None, rest, true)
    } else {
        (None, None, rest, false)
    };

    let path = unescape(path_source.as_bytes(), EscapeMode::Path)?;
    let escaped = escape(&path, EscapeMode::Path);
    let raw_path = (path_source.as_bytes() != escaped.as_slice()).then_some(path_source.as_bytes());
    let request_uri = match raw_path {
        Some(raw) if valid_encoded(raw) && unescape(raw, EscapeMode::Path).as_deref() == Some(path.as_slice()) => raw,
        _ => escaped.as_slice(),
    };

    let mut rendered = Vec::new();
    if !scheme.is_empty() {
        rendered.extend_from_slice(scheme.as_bytes());
        rendered.push(b':');
    }
    if scheme.is_empty() && host.is_none() && userinfo.is_none() {
        rendered.extend_from_slice(request_uri);
    } else if omit_host {
        match request_uri.strip_prefix(b"//") {
            Some(path) => {
                rendered.extend_from_slice(b"%2F");
                rendered.extend_from_slice(path);
            },
            None => rendered.extend_from_slice(request_uri),
        }
    } else {
        let host_present = host.as_ref().is_some_and(|value| !value.is_empty());
        if host_present || !request_uri.is_empty() || userinfo.is_some() {
            rendered.extend_from_slice(b"//");
        }
        if let Some((username, password)) = userinfo {
            rendered.extend_from_slice(&escape(&username, EscapeMode::UserPassword));
            if let Some(password) = password {
                rendered.push(b':');
                rendered.extend_from_slice(&escape(&password, EscapeMode::UserPassword));
            }
            rendered.push(b'@');
        }
        if let Some(host) = host {
            rendered.extend_from_slice(&escape(&host, EscapeMode::Host));
        }
        if !request_uri.is_empty() && !request_uri.starts_with(b"/") && host_present {
            rendered.push(b'/');
        }
        rendered.extend_from_slice(request_uri);
    }
    if force_query || !raw_query.is_empty() {
        rendered.push(b'?');
        rendered.extend_from_slice(raw_query.as_bytes());
    }

    Some(ParsedRequestTarget {
        request_uri: rendered,
        path,
        raw_query: raw_query.to_owned(),
    })
}

/// Split the scheme from a target, lowercased, following Go's `getScheme`.
fn split_scheme(target: &str) -> Option<(String, &str)> {
    for (index, byte) in target.bytes().enumerate() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => {},
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if index == 0 {
                    return Some((String::new(), target));
                }
            },
            b':' => {
                if index == 0 {
                    return None;
                }
                return Some((
                    target.get(..index).unwrap_or_default().to_ascii_lowercase(),
                    target.get(index.saturating_add(1)..)?,
                ));
            },
            _ => return Some((String::new(), target)),
        }
    }
    Some((String::new(), target))
}

/// Split a trailing query from the rest of the target.
fn split_query(rest: &str) -> (&str, &str, bool) {
    if rest.ends_with('?') && rest.bytes().filter(|&byte| byte == b'?').count() == 1 {
        (rest.get(..rest.len().saturating_sub(1)).unwrap_or_default(), "", true)
    } else {
        match rest.split_once('?') {
            Some((before, query)) => (before, query, false),
            None => (rest, "", false),
        }
    }
}

/// A user name and optional password, both decoded.
type UserInfo = (Vec<u8>, Option<Vec<u8>>);

/// Parse an authority into optional userinfo and a host.
fn parse_authority(authority: &str) -> Option<(Option<UserInfo>, Vec<u8>)> {
    let at = authority.rfind('@');
    let host_part = at.map_or(authority, |index| {
        authority.get(index.saturating_add(1)..).unwrap_or_default()
    });
    let host = parse_host(host_part)?;
    let Some(at) = at else {
        return Some((None, host));
    };
    let userinfo = authority.get(..at).unwrap_or_default();
    if !valid_userinfo(userinfo) {
        return None;
    }
    let userinfo = match userinfo.split_once(':') {
        None => (unescape(userinfo.as_bytes(), EscapeMode::UserPassword)?, None),
        Some((username, password)) => (
            unescape(username.as_bytes(), EscapeMode::UserPassword)?,
            Some(unescape(password.as_bytes(), EscapeMode::UserPassword)?),
        ),
    };
    Some((Some(userinfo), host))
}

/// Validate and decode a host, rejecting the malformed ports and IP literals Go rejects.
fn parse_host(host: &str) -> Option<Vec<u8>> {
    if let Some(open) = host.rfind('[') {
        if open > 0 {
            return None;
        }
        let close = host.rfind(']')?;
        let colon_port = host.get(close.saturating_add(1)..).unwrap_or_default();
        if !valid_optional_port(colon_port.as_bytes()) {
            return None;
        }
        let colon_port = unescape(colon_port.as_bytes(), EscapeMode::Host)?;
        let literal = host.get(1..close)?;
        let literal = match literal.find("%25") {
            Some(zone) => {
                let mut hostname = unescape(literal.get(..zone)?.as_bytes(), EscapeMode::Host)?;
                hostname.extend_from_slice(&unescape(literal.get(zone..)?.as_bytes(), EscapeMode::Zone)?);
                hostname
            },
            None => unescape(literal.as_bytes(), EscapeMode::Host)?,
        };
        if !valid_ip_literal(&literal) {
            return None;
        }
        let mut host = Vec::new();
        host.push(b'[');
        host.extend_from_slice(&literal);
        host.push(b']');
        host.extend_from_slice(&colon_port);
        return Some(host);
    }
    if let Some(colon) = host.rfind(':') {
        // The pinned Coraza module declares Go 1.25, so net/url keeps its historical
        // last-colon port split instead of the stricter Go 1.26 multi-colon rule.
        if !valid_optional_port(host.get(colon..).unwrap_or_default().as_bytes()) {
            return None;
        }
    }
    unescape(host.as_bytes(), EscapeMode::Host)
}

/// Whether `text` contains only the characters Go accepts before an `@` in a URL.
fn valid_userinfo(text: &str) -> bool {
    text.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(
                character,
                '-' | '.'
                    | '_'
                    | ':'
                    | '~'
                    | '!'
                    | '$'
                    | '&'
                    | '\''
                    | '('
                    | ')'
                    | '*'
                    | '+'
                    | ','
                    | ';'
                    | '='
                    | '%'
                    | '@'
            )
    })
}

/// Whether a bracketed host is an IPv6 literal, optionally with a non-empty zone.
fn valid_ip_literal(hostname: &[u8]) -> bool {
    let Ok(hostname) = std::str::from_utf8(hostname) else {
        return false;
    };
    match hostname.split_once('%') {
        Some((address, zone)) if !zone.is_empty() => address.parse::<std::net::Ipv6Addr>().is_ok(),
        Some(_) => false,
        None => hostname.parse::<std::net::Ipv6Addr>().is_ok(),
    }
}

/// Whether `port` is empty or a colon followed by digits.
fn valid_optional_port(port: &[u8]) -> bool {
    match port {
        [] => true,
        [b':', digits @ ..] => digits.iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

/// Whether bytes form an escaped path Go would return unchanged from `EscapedPath`.
fn valid_encoded(bytes: &[u8]) -> bool {
    bytes.iter().all(|&byte| {
        matches!(
            byte,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'['
                | b']'
                | b'%'
        ) || !should_escape(byte, EscapeMode::Path)
    })
}

/// Whether `byte` must be percent-encoded in `mode`, following Go's `shouldEscape`.
fn should_escape(byte: u8, mode: EscapeMode) -> bool {
    if byte.is_ascii_alphanumeric() {
        return false;
    }
    if matches!(mode, EscapeMode::Host | EscapeMode::Zone)
        && matches!(
            byte,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        )
    {
        return false;
    }
    match byte {
        b'-' | b'_' | b'.' | b'~' => false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            EscapeMode::Path => byte == b'?',
            EscapeMode::UserPassword => matches!(byte, b'@' | b'/' | b'?' | b':'),
            EscapeMode::Host | EscapeMode::Zone => true,
        },
        _ => true,
    }
}

/// Percent-encode `bytes` for `mode` with upper-case hex digits.
fn escape(bytes: &[u8], mode: EscapeMode) -> Vec<u8> {
    let mut escaped = Vec::with_capacity(bytes.len());
    for &byte in bytes {
        if should_escape(byte, mode) {
            escaped.push(b'%');
            escaped.push(hex_digit(byte >> 4));
            escaped.push(hex_digit(byte & 0x0F));
        } else {
            escaped.push(byte);
        }
    }
    escaped
}

/// The upper-case hex digit of a nibble.
const fn hex_digit(value: u8) -> u8 {
    if value < 10 { b'0' + value } else { b'A' + value - 10 }
}

/// Percent-decode `bytes`, enforcing the mode-specific restrictions Go applies.
fn unescape(bytes: &[u8], mode: EscapeMode) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut offset = 0;
    while let Some(&byte) = bytes.get(offset) {
        match byte {
            b'%' => {
                let high = *bytes.get(offset.saturating_add(1))?;
                let low = *bytes.get(offset.saturating_add(2))?;
                if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
                    return None;
                }
                let value = (unhex(high) << 4) | unhex(low);
                let escaped = bytes.get(offset..offset.saturating_add(3));
                if mode == EscapeMode::Host && unhex(high) < 8 && escaped != Some(&b"%25"[..]) {
                    return None;
                }
                if mode == EscapeMode::Zone
                    && escaped != Some(&b"%25"[..])
                    && value != b' '
                    && should_escape(value, EscapeMode::Host)
                {
                    return None;
                }
                decoded.push(value);
                offset = offset.saturating_add(3);
            },
            byte => {
                if matches!(mode, EscapeMode::Host | EscapeMode::Zone) && byte < 0x80 && should_escape(byte, mode) {
                    return None;
                }
                decoded.push(byte);
                offset = offset.saturating_add(1);
            },
        }
    }
    Some(decoded)
}

/// The value of one hex digit.
const fn unhex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            drop(self.process_logging());
        }
        if self.config.upload_keep_files {
            return;
        }
        for path in &self.uploaded_paths {
            drop(std::fs::remove_file(path));
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "transaction tests use fixed valid inputs")]
mod tests {
    use std::sync::Arc;

    use super::{
        BodyIngestionStats, Transaction, VariableCollection,
        body_buffer::{BufferFailure, inject_failure},
    };
    use crate::{
        Waf,
        config::{DetectorInspectionAction, WafConfig},
        operators::Outputs,
        rules::VariableSpec,
        types::{AuditEngineStatus, AuditLogPart, BodyLimitAction, RuleEngineStatus, RulePhase, RuleVariable},
    };

    /// The byte keys and values of a map collection, sorted so the test does not depend on
    /// hash-map iteration order.
    fn byte_entries(tx: &Transaction, variable: RuleVariable) -> Vec<(Vec<u8>, Vec<u8>)> {
        let map = match tx.collection(variable) {
            Some(VariableCollection::Map(map)) => Some(map),
            _ => None,
        }
        .unwrap();
        let mut entries: Vec<_> = map
            .iter_bytes()
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        entries.sort();
        entries
    }

    #[test]
    fn process_uri_keeps_decoded_argument_name_bytes() {
        let waf = Waf::new(WafConfig::default()).unwrap();
        let mut tx = waf.new_transaction();
        tx.process_uri("/?%ff=a&%fe=b", "GET", "HTTP/1.1");

        let expected = vec![(vec![0xFE], b"b".to_vec()), (vec![0xFF], b"a".to_vec())];
        assert_eq!(byte_entries(&tx, RuleVariable::ArgsGet), expected);
        assert_eq!(byte_entries(&tx, RuleVariable::Args), expected);
    }

    #[test]
    fn urlencoded_body_keeps_decoded_argument_name_bytes() {
        let config = WafConfig {
            request_body_access: true,
            ..WafConfig::default()
        };
        let waf = Waf::new(config).unwrap();
        let mut tx = waf.new_transaction();
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
        tx.process_request_headers();
        assert_eq!(tx.process_request_body(b"%ff=a&%fe=b"), None);

        let expected = vec![(vec![0xFE], b"b".to_vec()), (vec![0xFF], b"a".to_vec())];
        assert_eq!(byte_entries(&tx, RuleVariable::ArgsPost), expected);
        assert_eq!(byte_entries(&tx, RuleVariable::Args), expected);
    }

    #[test]
    fn json_body_keeps_decoded_argument_name_bytes() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecAction \"id:160,phase:1,ctl:requestBodyProcessor=JSON,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("json-byte-keys");
        tx.process_request_headers();
        assert_eq!(tx.process_request_body(b"{\"k\xff\":1,\"k\xfe\":2}"), None);

        let expected = vec![
            (b"json.k\xfe".to_vec(), b"2".to_vec()),
            (b"json.k\xff".to_vec(), b"1".to_vec()),
        ];
        assert_eq!(byte_entries(&tx, RuleVariable::ArgsPost), expected);
        assert_eq!(byte_entries(&tx, RuleVariable::Args), expected);
    }

    #[test]
    fn json_response_body_keeps_decoded_argument_name_bytes() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecResponseBodyAccess On\n\
                 SecResponseBodyMimeType application/json\n\
                 SecAction \"id:161,phase:3,ctl:responseBodyProcessor=JSON,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("json-response-byte-keys");
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "application/json");
        tx.process_response_headers(200, "HTTP/1.1");
        assert_eq!(tx.process_response_body(b"{\"k\xff\":1,\"k\xfe\":2}"), None);

        let expected = vec![
            (b"json.k\xfe".to_vec(), b"2".to_vec()),
            (b"json.k\xff".to_vec(), b"1".to_vec()),
        ];
        assert_eq!(byte_entries(&tx, RuleVariable::ResponseArgs), expected);
    }

    #[test]
    fn args_key_lookup_folds_case_and_reports_the_original_name() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string("SecRule ARGS:name \"@contains attack\" \"id:170,phase:1,deny,status:403\"")
            .unwrap();
        let waf = parser.into_waf().unwrap();

        for supplied in ["Name", "NAME", "nAmE"] {
            let mut tx = waf.new_transaction_with_id("args-case");
            tx.add_get_argument(supplied, b"an attack");

            assert_eq!(tx.process_request_headers().map(|item| item.rule_id), Some(170));
            assert_eq!(
                tx.get_variable(RuleVariable::MatchedVarName, None).as_deref(),
                Some(format!("ARGS:{supplied}").as_str())
            );
            let matched = tx.matched_rules().first().unwrap();
            assert_eq!(matched.matches.len(), 1);
            assert_eq!(matched.matches.first().map(|item| item.key.as_str()), Some(supplied));
            assert_eq!(
                matched.matches.first().map(|item| item.value.as_slice()),
                Some(&b"an attack"[..])
            );

            let entries = byte_entries(&tx, RuleVariable::Args);
            assert_eq!(entries, [(supplied.as_bytes().to_vec(), b"an attack".to_vec())]);
        }
    }

    #[test]
    fn args_names_keep_the_original_spellings() {
        let mut tx = Transaction::new("args-names-case");
        tx.add_get_argument("Name", b"1");
        tx.add_get_argument("NAME", b"2");
        tx.add_get_argument("other", b"3");

        let matches = tx.find_matches(&VariableSpec::new(RuleVariable::ArgsNames));
        let mut names: Vec<_> = matches.iter().map(|item| item.value.clone()).collect();
        names.sort();
        assert_eq!(names, [b"NAME".to_vec(), b"Name".to_vec(), b"other".to_vec()]);
        assert!(matches.iter().all(|item| item.variable == RuleVariable::ArgsNames));
    }

    #[test]
    fn args_post_key_lookup_folds_case() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecRule ARGS_POST:password \"@contains secret\" \"id:171,phase:2,deny,status:403\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("args-post-case");
        tx.add_request_header("Content-Type", b"application/x-www-form-urlencoded");
        tx.process_request_headers();

        assert_eq!(
            tx.process_request_body(b"Password=mysecret").map(|item| item.rule_id),
            Some(171)
        );
        assert_eq!(
            tx.matched_rules()
                .first()
                .and_then(|matched| matched.matches.first())
                .map(|item| item.key.as_str()),
            Some("Password")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("password")).as_deref(),
            Some("mysecret")
        );
    }

    #[test]
    fn args_path_key_lookup_folds_case() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string("SecRule ARGS_PATH:route \"@contains admin\" \"id:172,phase:1,deny,status:403\"")
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("args-path-case");
        tx.add_path_argument("Route", b"admin area");

        assert_eq!(tx.process_request_headers().map(|item| item.rule_id), Some(172));
        assert_eq!(
            tx.matched_rules()
                .first()
                .and_then(|matched| matched.matches.first())
                .map(|item| item.key.as_str()),
            Some("Route")
        );
    }

    #[test]
    fn multipart_names_and_file_sizes_fold_case() {
        let upload_dir = tempfile::tempdir().unwrap();
        let mut parser = crate::seclang::Parser::new();
        let rules = format!("SecRequestBodyAccess On\nSecUploadDir {}", upload_dir.path().display());
        parser.from_string(&rules).unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("multipart-case");
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=boundary");
        tx.process_request_headers();

        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"Message\"; filename=\"Legacy.TXT\"\r\n\
Content-Type: application/octet-stream\r\n\
\r\n\
payload\r\n\
--boundary--";
        assert_eq!(tx.process_request_body(body), None);

        assert_eq!(
            tx.get_variable(RuleVariable::MultipartName, Some("message")).as_deref(),
            Some("Message")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::FilesSizes, Some("legacy.txt")).as_deref(),
            Some("7")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::FilesSizes, Some("LEGACY.TXT")).as_deref(),
            Some("7")
        );
    }

    #[test]
    fn request_xml_key_lookup_folds_case() {
        let mut tx = Transaction::new("xml-case");
        tx.request_xml.add("Secret", b"value");

        let matches = tx.find_matches(&VariableSpec::new_string(RuleVariable::RequestXML, "secret".to_owned()));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches.first().map(|item| item.key.as_str()), Some("Secret"));
        assert_eq!(matches.first().map(|item| item.value.as_slice()), Some(&b"value"[..]));
    }

    #[test]
    fn response_args_key_lookup_folds_case() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecResponseBodyAccess On\n\
                 SecResponseBodyMimeType application/json\n\
                 SecAction \"id:173,phase:3,ctl:responseBodyProcessor=JSON,pass\"\n\
                 SecRule RESPONSE_ARGS:json.admin \"@streq true\" \"id:174,phase:4,deny,status:403\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("response-args-case");
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "application/json");
        tx.process_response_headers(200, "HTTP/1.1");

        assert_eq!(
            tx.process_response_body(br#"{"Admin":true}"#).map(|item| item.rule_id),
            Some(174)
        );
        assert_eq!(
            tx.matched_rules()
                .iter()
                .find(|matched| matched.rule_id() == 174)
                .and_then(|matched| matched.matches.first())
                .map(|item| item.key.as_str()),
            Some("json.Admin")
        );
    }

    #[test]
    fn case_sensitive_args_keys_option_limits_sensitivity_to_arguments() {
        let rule = "SecRule ARGS:password \"@contains secret\" \"id:175,phase:1,deny,status:403\"";

        let mut parser = crate::seclang::Parser::new();
        parser.from_string(rule).unwrap();
        let default_waf = parser.into_waf().unwrap();

        let mut parser = crate::seclang::Parser::new();
        parser.config_mut().case_sensitive_args_keys = true;
        parser.from_string(rule).unwrap();
        let strict_waf = parser.into_waf().unwrap();

        let mut tx = default_waf.new_transaction_with_id("args-default-case");
        tx.add_get_argument("Password", b"a secret");
        assert_eq!(tx.process_request_headers().map(|item| item.rule_id), Some(175));

        let mut tx = strict_waf.new_transaction_with_id("args-strict-case");
        tx.add_get_argument("Password", b"a secret");
        tx.add_request_header("X-Trace", b"value");

        assert_eq!(tx.process_request_headers(), None);
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsGet, Some("Password")).as_deref(),
            Some("a secret")
        );
        assert_eq!(tx.get_variable(RuleVariable::ArgsGet, Some("password")), None);
        let exact = VariableSpec::new_string(RuleVariable::Args, "Password".to_owned());
        let folded = VariableSpec::new_string(RuleVariable::Args, "password".to_owned());
        assert_eq!(tx.find_matches(&exact).len(), 1);
        assert!(tx.find_matches(&folded).is_empty());
        // Collections other than the arguments stay case-insensitive, as in Go.
        assert_eq!(
            tx.get_variable(RuleVariable::RequestHeaders, Some("x-trace"))
                .as_deref(),
            Some("value")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::RequestHeaders, Some("X-TRACE"))
                .as_deref(),
            Some("value")
        );
    }

    #[test]
    fn args_regex_key_selector_folds_case_in_default_mode() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string("SecRule ARGS:/^userId$/ \"@contains attack\" \"id:176,phase:1,deny,status:403\"")
            .unwrap();
        let waf = parser.into_waf().unwrap();

        for supplied in ["USERID", "UserId"] {
            let mut tx = waf.new_transaction_with_id("args-regex-default");
            tx.add_get_argument(supplied, b"an attack");

            assert_eq!(tx.process_request_headers().map(|item| item.rule_id), Some(176));
            assert_eq!(
                tx.matched_rules()
                    .first()
                    .and_then(|matched| matched.matches.first())
                    .map(|item| item.key.as_str()),
                Some(supplied)
            );
        }
    }

    #[test]
    fn args_regex_key_selector_is_exact_in_strict_mode() {
        let mut parser = crate::seclang::Parser::new();
        parser.config_mut().case_sensitive_args_keys = true;
        parser
            .from_string("SecRule ARGS:/^userId$/ \"@contains attack\" \"id:177,phase:1,deny,status:403\"")
            .unwrap();
        let waf = parser.into_waf().unwrap();

        for supplied in ["USERID", "UserId"] {
            let mut tx = waf.new_transaction_with_id("args-regex-strict-miss");
            tx.add_get_argument(supplied, b"an attack");
            assert_eq!(tx.process_request_headers(), None, "{supplied}");
        }

        let mut tx = waf.new_transaction_with_id("args-regex-strict-hit");
        tx.add_get_argument("userId", b"an attack");
        assert_eq!(tx.process_request_headers().map(|item| item.rule_id), Some(177));
    }

    #[test]
    fn case_folding_keeps_invalid_utf8_keys_distinct() {
        let mut tx = Transaction::new("invalid-utf8-case");
        tx.add_get_argument(b"Id\xff", b"one");
        tx.add_get_argument(b"ID\xff", b"two");
        tx.add_get_argument(b"Id\xfe", b"three");

        let entries = byte_entries(&tx, RuleVariable::ArgsGet);
        assert_eq!(
            entries,
            [
                (b"ID\xff".to_vec(), b"two".to_vec()),
                (b"Id\xfe".to_vec(), b"three".to_vec()),
                (b"Id\xff".to_vec(), b"one".to_vec()),
            ]
        );

        let map = match tx.collection(RuleVariable::ArgsGet) {
            Some(VariableCollection::Map(map)) => Some(map),
            _ => None,
        }
        .unwrap();
        // The two ASCII case variants fold into one lookup bucket but stay separate entries.
        assert_eq!(map.len(), 2);
        assert_eq!(map.values(b"id\xff").count(), 2);
        assert_eq!(map.values(b"ID\xff").count(), 2);
        assert_eq!(map.values(b"id\xfe").count(), 1);
        // Distinct invalid byte sequences are not merged by lowercasing.
        assert_eq!(map.values(b"id\xfd").count(), 0);
    }

    #[test]
    fn stores_and_matches_byte_arguments() {
        let mut tx = Transaction::new("tx-1");
        tx.add_get_argument("id", b"\xff");
        tx.add_path_argument("route", "admin");
        let spec = VariableSpec::new_string(RuleVariable::Args, "id".to_owned());
        tx.set_request_uri(b"/\xff");
        let uri_spec = VariableSpec::new(RuleVariable::RequestURI);

        assert_eq!(tx.id(), "tx-1");
        assert_eq!(
            tx.find_matches(&spec).first().map(|matched| matched.value.as_slice()),
            Some(&b"\xff"[..])
        );
        assert_eq!(
            tx.get_variable(RuleVariable::Args, Some("id")).as_deref(),
            Some("\u{fffd}")
        );
        assert_eq!(
            tx.find_matches(&uri_spec)
                .first()
                .map(|matched| matched.value.as_slice()),
            Some(&b"/\xff"[..])
        );
        assert_eq!(
            tx.get_variable(RuleVariable::RequestURI, None).as_deref(),
            Some("/\u{fffd}")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsCombinedSize, None).as_deref(),
            Some("3")
        );
    }

    #[test]
    fn enforces_argument_limit_and_tracks_dropped_arguments() {
        let config = WafConfig {
            argument_limit: 1,
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("tx-2", Arc::new(config));
        tx.add_get_argument("id", "1");
        tx.add_get_argument("dropped", "2");
        tx.add_post_argument("name", "a");

        assert!(tx.arguments_limit_reached());
        assert_eq!(tx.get_variable(RuleVariable::ArgsGet, Some("dropped")), None);
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("name")).as_deref(),
            Some("a")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsCombinedSize, None).as_deref(),
            Some("8")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgumentsLimitReached, None).as_deref(),
            Some("1")
        );
    }

    #[test]
    fn operator_outputs_clear_stale_tx_capture_variables() {
        let mut tx = Transaction::new("tx-captures");
        for index in 0..10 {
            tx.set_tx_variable(&index.to_string(), b"stale");
        }
        let mut outputs = Outputs::new(true);
        outputs.capture(0, b"current");

        tx.store_operator_outputs(&mut outputs);

        assert_eq!(tx.get_variable(RuleVariable::TX, Some("0")).as_deref(), Some("current"));
        for index in 1..10 {
            assert_eq!(tx.get_variable(RuleVariable::TX, Some(&index.to_string())), None);
        }
    }

    #[test]
    fn headers_are_case_insensitive_and_name_variables_select_keys() {
        let mut tx = Transaction::new("tx-3");
        tx.add_request_header("X-Trace", b"\xff");
        let spec = VariableSpec::new_string(RuleVariable::RequestHeaders, "x-trace".to_owned());
        let names_spec = VariableSpec::new_string(RuleVariable::RequestHeadersNames, "x-trace".to_owned());

        assert_eq!(
            tx.find_matches(&spec).first().map(|matched| matched.value.as_slice()),
            Some(&b"\xff"[..])
        );
        assert_eq!(
            tx.get_variable(RuleVariable::RequestHeadersNames, Some("x-trace"))
                .as_deref(),
            Some("X-Trace")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::RequestHeadersNames, Some("missing")),
            None
        );
        assert_eq!(
            tx.find_matches(&names_spec)
                .first()
                .map(|matched| matched.value.as_slice()),
            Some(&b"X-Trace"[..])
        );
        assert!(matches!(
            tx.collection(RuleVariable::RequestHeaders),
            Some(VariableCollection::Map(_))
        ));
        assert!(matches!(
            tx.collection(RuleVariable::RequestBody),
            Some(VariableCollection::Single(_))
        ));
        assert_eq!(
            tx.get_variable(RuleVariable::RequestBodyLength, None).as_deref(),
            Some("0")
        );
    }

    #[test]
    fn urlencoded_body_populates_arguments_and_runs_phase_two_rules() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecRule ARGS_POST \"@contains attack\" \"id:30,phase:2,deny,status:403\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("urlencoded-body");
        tx.add_request_header("Content-Type", b"application/x-www-form-urlencoded; charset=UTF-8");
        tx.process_request_headers();

        let body = b"name=attack&bin=%FF&bad=%G0&empty";
        let interruption = tx.process_request_body(body).unwrap();

        assert_eq!(interruption.rule_id, 30);
        assert_eq!(interruption.status, 403);
        assert_eq!(tx.last_phase(), Some(RulePhase::RequestBody));
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
            Some("URLENCODED")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::RequestBody, None).as_deref(),
            Some("name=attack&bin=%FF&bad=%G0&empty")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::RequestBodyLength, None),
            Some(body.len().to_string())
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("name")).as_deref(),
            Some("attack")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("empty")).as_deref(),
            Some("")
        );

        let binary = VariableSpec::new_string(RuleVariable::ArgsPost, "bin".to_owned());
        assert_eq!(
            tx.find_matches(&binary).first().map(|matched| matched.value.as_slice()),
            Some(&b"\xff"[..])
        );
        let invalid_escape = VariableSpec::new_string(RuleVariable::ArgsPost, "bad".to_owned());
        assert_eq!(
            tx.find_matches(&invalid_escape)
                .first()
                .map(|matched| matched.value.as_slice()),
            Some(&b"%G0"[..])
        );
    }

    #[test]
    fn multipart_body_populates_fields_metadata_and_temporary_uploads() {
        let upload_dir = tempfile::tempdir().unwrap();
        let mut parser = crate::seclang::Parser::new();
        let rules = format!(
            "SecRequestBodyAccess On\nSecUploadDir {}\nSecRule ARGS_POST \"@contains hello\" \"id:77,phase:2,deny,status:403\"",
            upload_dir.path().display()
        );
        parser.from_string(&rules).unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("multipart-body");
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=boundary");
        tx.process_request_headers();

        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"message\"\r\n\
\r\n\
hello\r\n\
--boundary\r\n\
Content-Disposition: form-data; name=\"upload\"; filename=\"legacy.txt\"; filename*=UTF-8'en'payload.txt\r\n\
Content-Type: application/octet-stream\r\n\
\r\n\
payload\r\n\
--boundary--";
        assert_eq!(tx.process_request_body(body).unwrap().rule_id, 77);

        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
            Some("MULTIPART")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("message")).as_deref(),
            Some("hello")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::Files, Some("")).as_deref(),
            Some("payload.txt")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::FilesNames, Some("")).as_deref(),
            Some("upload")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::FilesSizes, Some("payload.txt"))
                .as_deref(),
            Some("7")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::FilesSizes, Some("legacy.txt")).as_deref(),
            Some("7")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::MultipartFilenameCharset, Some("upload"))
                .as_deref(),
            Some("UTF-8")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::MultipartFilenameLanguage, Some("upload"))
                .as_deref(),
            Some("en")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::MultipartName, Some("message")).as_deref(),
            Some("message")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::MultipartPartHeaders, Some("upload"))
                .as_deref(),
            Some(
                "Content-Disposition: form-data; name=\"upload\"; filename=\"legacy.txt\"; filename*=UTF-8'en'payload.txt"
            )
        );
        assert_eq!(
            tx.get_variable(RuleVariable::FilesCombinedSize, None).as_deref(),
            Some("12")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::MultipartStrictError, None).as_deref(),
            Some("0")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::MultipartDuplicatePartHeader, None)
                .as_deref(),
            Some("0")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::MultipartInvalidQuoting, None).as_deref(),
            Some("0")
        );

        let path = tx.get_variable(RuleVariable::FilesTmpNames, Some("")).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
        assert!(std::path::Path::new(&path).exists());
        drop(tx);
        assert!(!std::path::Path::new(&path).exists());
    }

    #[test]
    fn multipart_upload_limit_skips_extra_files_and_continues_fields() {
        let upload_dir = tempfile::tempdir().unwrap();
        let config = WafConfig {
            request_body_access: true,
            upload_dir: upload_dir.path().to_string_lossy().into_owned(),
            upload_file_limit: 1,
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("multipart-upload-limit", Arc::new(config));
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=boundary");
        tx.process_request_headers();

        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"first\"; filename=\"first.txt\"\r\n\
\r\n\
first\r\n\
--boundary\r\n\
Content-Disposition: form-data; name=\"second\"; filename=\"second.txt\"\r\n\
\r\n\
second\r\n\
--boundary\r\n\
Content-Disposition: form-data; name=\"after\"\r\n\
\r\n\
field value\r\n\
--boundary--";
        assert_eq!(tx.process_request_body(body), None);

        let files = tx.find_matches(&VariableSpec::new_string(RuleVariable::Files, String::new()));
        assert_eq!(files.len(), 1);
        assert_eq!(
            files.first().map(|matched| matched.value.as_slice()),
            Some(&b"first.txt"[..])
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("after")).as_deref(),
            Some("field value")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::MultipartStrictError, None).as_deref(),
            Some("1")
        );
    }

    #[test]
    fn malformed_multipart_sets_processor_and_strict_errors() {
        let config = WafConfig {
            request_body_access: true,
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("malformed-multipart", Arc::new(config));
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=boundary");
        tx.process_request_headers();

        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"field\"\r\n\
\r\n\
value";
        assert_eq!(tx.process_request_body(body), None);
        assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("1"));
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessorError, None).as_deref(),
            Some("1")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::MultipartStrictError, None).as_deref(),
            Some("1")
        );
    }

    #[test]
    fn multipart_upload_keep_files_preserves_files_after_transaction_drop() {
        let upload_dir = tempfile::tempdir().unwrap();
        let config = WafConfig {
            request_body_access: true,
            upload_dir: upload_dir.path().to_string_lossy().into_owned(),
            upload_keep_files: true,
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("kept-multipart-upload", Arc::new(config));
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=boundary");
        tx.process_request_headers();
        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"upload\"; filename=\"file.txt\"\r\n\
\r\n\
payload\r\n\
--boundary--";
        assert_eq!(tx.process_request_body(body), None);

        let path = tx.get_variable(RuleVariable::FilesTmpNames, Some("")).unwrap();
        drop(tx);
        assert!(std::path::Path::new(&path).exists());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn raw_body_is_selected_by_ctl_and_matches_original_bytes() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecAction \"id:31,phase:1,ctl:requestBodyProcessor=RAW,pass\"\n\
                 SecRule REQUEST_BODY \"@contains attack\" \"id:32,phase:2,deny,status:403\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("raw-body");
        tx.add_request_header("Content-Type", b"text/plain");
        tx.process_request_headers();

        let body = b"xx\xffattack";
        assert_eq!(tx.process_request_body(body).unwrap().rule_id, 32);

        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
            Some("RAW")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::RequestBodyLength, None).as_deref(),
            Some("9")
        );
        assert_eq!(
            tx.find_matches(&VariableSpec::new(RuleVariable::RequestBody))
                .first()
                .map(|matched| matched.value.as_slice()),
            Some(&body[..])
        );
    }

    #[test]
    fn request_body_limit_rejects_at_the_limit_and_processes_partial_bodies() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecAction \"id:33,phase:1,ctl:requestBodyLimit=4,ctl:requestBodyProcessor=RAW,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("body-limit-reject");
        tx.process_request_headers();
        assert_eq!(tx.request_body_limit(), 4);

        let interruption = tx.process_request_body(b"body").unwrap();

        assert_eq!(interruption.rule_id, 0);
        assert_eq!(interruption.action, "deny");
        assert_eq!(interruption.status, 413);
        assert_eq!(
            tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
            Some("1")
        );
        assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some(""));

        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecRequestBodyLimit 4\n\
                 SecRequestBodyLimitAction ProcessPartial\n\
                 SecAction \"id:34,phase:1,ctl:requestBodyProcessor=RAW,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("body-limit-partial");
        tx.process_request_headers();

        assert_eq!(tx.process_request_body(b"attack"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::RequestBody, None).as_deref(),
            Some("atta")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::RequestBodyLength, None).as_deref(),
            Some("4")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
            Some("1")
        );
    }

    /// Build a transaction that inspects a RAW request body with the supplied limits.
    fn request_body_transaction(id: &str, limit: i64, action: BodyLimitAction) -> Transaction {
        let config = WafConfig {
            request_body_access: true,
            request_body_limit: limit,
            request_body_limit_action: action,
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config(id, Arc::new(config));
        tx.process_request_headers();
        tx.set_request_body_processor("RAW");
        tx
    }

    #[test]
    fn request_body_limit_reject_boundaries() {
        let mut tx = request_body_transaction("request-limit-below", 4, BodyLimitAction::Reject);
        assert_eq!(tx.process_request_body(b"abc"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
            Some("0")
        );
        assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some("abc"));
        assert_eq!(
            tx.request_body_stats(),
            BodyIngestionStats {
                supplied: 3,
                retained: 3,
                inspected: 3,
                truncated: false,
                spilled: false,
            }
        );

        let mut tx = request_body_transaction("request-limit-equal", 4, BodyLimitAction::Reject);
        assert_eq!(tx.process_request_body(b"abcd").map(|item| item.status), Some(413));
        assert_eq!(
            tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
            Some("1")
        );
        assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some(""));
        assert_eq!(
            tx.request_body_stats(),
            BodyIngestionStats {
                supplied: 4,
                retained: 0,
                inspected: 0,
                truncated: true,
                spilled: false,
            }
        );

        let mut tx = request_body_transaction("request-limit-above", 4, BodyLimitAction::Reject);
        assert_eq!(tx.process_request_body(b"abcde").map(|item| item.status), Some(413));
        assert_eq!(tx.request_body_stats().supplied, 5);
        assert_eq!(tx.request_body_stats().retained, 0);
        assert!(tx.request_body_stats().truncated);

        let mut tx = request_body_transaction("request-limit-zero", 0, BodyLimitAction::Reject);
        assert_eq!(tx.process_request_body(b"a").map(|item| item.status), Some(413));
        assert_eq!(
            tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
            Some("1")
        );
        assert_eq!(tx.request_body_stats().retained, 0);
        assert!(tx.request_body_stats().truncated);

        // An empty body never crosses the limit, even at zero.
        let mut tx = request_body_transaction("request-limit-zero-empty", 0, BodyLimitAction::Reject);
        assert_eq!(tx.process_request_body(b""), None);
        assert_eq!(
            tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
            Some("0")
        );
        assert_eq!(tx.request_body_stats(), BodyIngestionStats::default());
    }

    #[test]
    fn request_body_limit_process_partial_boundaries() {
        let mut tx = request_body_transaction("request-partial-below", 4, BodyLimitAction::ProcessPartial);
        assert_eq!(tx.process_request_body(b"abc"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
            Some("0")
        );
        assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some("abc"));
        assert_eq!(tx.request_body_stats().inspected, 3);
        assert!(!tx.request_body_stats().truncated);

        let mut tx = request_body_transaction("request-partial-equal", 4, BodyLimitAction::ProcessPartial);
        assert_eq!(tx.process_request_body(b"abcd"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
            Some("1")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::RequestBody, None).as_deref(),
            Some("abcd")
        );
        assert_eq!(tx.request_body_stats().retained, 4);
        assert_eq!(tx.request_body_stats().inspected, 4);
        assert!(!tx.request_body_stats().truncated);

        let mut tx = request_body_transaction("request-partial-above", 4, BodyLimitAction::ProcessPartial);
        assert_eq!(tx.process_request_body(b"abcde"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
            Some("1")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::RequestBody, None).as_deref(),
            Some("abcd")
        );
        assert_eq!(tx.request_body_stats().supplied, 5);
        assert_eq!(tx.request_body_stats().retained, 4);
        assert_eq!(tx.request_body_stats().inspected, 4);
        assert!(tx.request_body_stats().truncated);

        let mut tx = request_body_transaction("request-partial-zero", 0, BodyLimitAction::ProcessPartial);
        assert_eq!(tx.process_request_body(b"a"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
            Some("1")
        );
        assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some(""));
        assert_eq!(tx.request_body_stats().supplied, 1);
        assert_eq!(tx.request_body_stats().retained, 0);
        assert_eq!(tx.request_body_stats().inspected, 0);
        assert!(tx.request_body_stats().truncated);

        let mut tx = request_body_transaction("request-partial-zero-empty", 0, BodyLimitAction::ProcessPartial);
        assert_eq!(tx.process_request_body(b""), None);
        assert_eq!(
            tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
            Some("0")
        );
        assert_eq!(tx.request_body_stats(), BodyIngestionStats::default());
    }

    #[test]
    fn detection_only_process_partial_request_limit_inspects_the_truncated_prefix() {
        // Go sets INBOUND_DATA_ERROR and truncates under ProcessPartial without
        // interrupting (`internal/corazawaf/transaction.go:992-1003`); DetectionOnly
        // only changes whether an interruption would be enforced.
        let config = WafConfig {
            rule_engine: RuleEngineStatus::DetectionOnly,
            request_body_access: true,
            request_body_limit: 4,
            request_body_limit_action: BodyLimitAction::ProcessPartial,
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("detection-only-partial", Arc::new(config));
        tx.process_request_headers();
        tx.set_request_body_processor("RAW");

        assert_eq!(tx.process_request_body(b"attack"), None);
        assert_eq!(tx.would_be_interruption(), None);
        assert_eq!(
            tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
            Some("1")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::RequestBody, None).as_deref(),
            Some("atta")
        );
        assert_eq!(tx.request_body_stats().inspected, 4);
        assert!(tx.request_body_stats().truncated);
    }

    #[test]
    fn request_body_ingestion_is_single_shot_unlike_go_chunked_writes() {
        // Go appends every WriteRequestBody chunk to one buffer
        // (`internal/corazawaf/transaction.go:992`). This runtime takes the whole body
        // in one call and ignores a later one because phase 2 already ran, so the limit
        // boundary is always crossed inside a single call.
        let mut tx = request_body_transaction("single-shot", 8, BodyLimitAction::Reject);
        assert_eq!(tx.process_request_body(b"abcd"), None);
        assert_eq!(tx.process_request_body(b"efgh"), None);

        assert_eq!(
            tx.get_variable(RuleVariable::RequestBody, None).as_deref(),
            Some("abcd")
        );
        assert_eq!(tx.request_body_stats().supplied, 4);
        assert!(!tx.request_body_stats().truncated);
    }

    #[test]
    fn request_body_without_a_processor_is_retained_but_not_inspected() {
        // The one-byte memory limit forces a spill, so a replay would read the file.
        let config = WafConfig {
            request_body_access: true,
            request_body_limit: 8,
            request_body_in_memory_limit: 1,
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("request-no-processor", Arc::new(config));
        tx.process_request_headers();

        assert_eq!(tx.process_request_body(b"abc"), None);
        assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some(""));
        assert_eq!(
            tx.request_body_stats(),
            BodyIngestionStats {
                supplied: 3,
                retained: 3,
                inspected: 0,
                truncated: false,
                spilled: true,
            }
        );
        assert_eq!(tx.request_body_buffer.replay_count(), 0);
    }

    #[test]
    fn request_body_is_not_buffered_or_audited_when_access_is_off() {
        // A one-byte in-memory limit makes any retained byte spill, so a missing spill
        // path proves admission never happened.
        let config = WafConfig {
            request_body_access: false,
            request_body_limit: 16,
            request_body_in_memory_limit: 1,
            audit_engine: AuditEngineStatus::On,
            audit_log_parts: vec![AuditLogPart::Header, AuditLogPart::RequestBody, AuditLogPart::EndMarker],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("request-audit-access-off", Arc::new(config));
        tx.process_request_headers();

        assert_eq!(tx.process_request_body(b"audited"), None);
        assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some(""));
        assert_eq!(tx.request_body_stats(), BodyIngestionStats::default());
        assert_eq!(tx.audit_log().transaction.request.body, "");
        assert!(tx.request_body_spill_path().is_none());
    }

    #[test]
    fn request_body_limit_is_not_applied_when_access_is_off() {
        for action in [BodyLimitAction::Reject, BodyLimitAction::ProcessPartial] {
            let config = WafConfig {
                request_body_access: false,
                request_body_limit: 4,
                request_body_limit_action: action,
                ..WafConfig::default()
            };
            let mut tx = Transaction::with_config("request-limit-access-off", Arc::new(config));
            tx.process_request_headers();

            assert_eq!(tx.process_request_body(b"attack"), None);
            assert_eq!(
                tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
                Some("0")
            );
            assert_eq!(tx.request_body_stats(), BodyIngestionStats::default());
            assert!(!tx.request_body_stats().truncated);
        }
    }

    #[test]
    fn request_body_is_not_buffered_when_the_rule_engine_is_off() {
        let config = WafConfig {
            rule_engine: RuleEngineStatus::Off,
            request_body_access: true,
            request_body_limit: 16,
            request_body_in_memory_limit: 1,
            audit_engine: AuditEngineStatus::On,
            audit_log_parts: vec![AuditLogPart::Header, AuditLogPart::RequestBody, AuditLogPart::EndMarker],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("request-engine-off", Arc::new(config));
        // `begin_phase` returns false while the rule engine is off, so no phase starts.
        tx.process_request_headers();
        assert_eq!(tx.last_phase(), None);

        assert_eq!(tx.process_request_body(b"audited"), None);
        assert_eq!(tx.request_body_stats(), BodyIngestionStats::default());
        assert_eq!(tx.audit_log().transaction.request.body, "");
        assert!(tx.request_body_spill_path().is_none());
    }

    #[test]
    fn response_body_with_access_off_is_not_buffered_audited_or_limited() {
        let config = WafConfig {
            response_body_access: false,
            response_body_limit: 4,
            response_body_limit_action: BodyLimitAction::Reject,
            response_body_mime_types: vec!["text/plain".to_owned()],
            audit_engine: AuditEngineStatus::On,
            audit_log_parts: vec![
                AuditLogPart::Header,
                AuditLogPart::ResponseBody,
                AuditLogPart::EndMarker,
            ],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("response-access-off", Arc::new(config));
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");

        assert_eq!(tx.process_response_body(b"attack"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
            Some("0")
        );
        assert_eq!(tx.response_body_stats(), BodyIngestionStats::default());
        assert_eq!(tx.audit_log().transaction.response.unwrap().body, "");
    }

    #[test]
    fn request_body_spills_to_a_temporary_file_and_replays_to_processor_and_audit() {
        let config = WafConfig {
            request_body_access: true,
            request_body_limit: 16,
            request_body_in_memory_limit: 2,
            audit_engine: AuditEngineStatus::On,
            audit_log_parts: vec![AuditLogPart::Header, AuditLogPart::RequestBody, AuditLogPart::EndMarker],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("request-spill", Arc::new(config));
        tx.process_request_headers();
        tx.set_request_body_processor("RAW");

        assert_eq!(tx.process_request_body(b"0123456789"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::RequestBody, None).as_deref(),
            Some("0123456789")
        );
        assert_eq!(
            tx.request_body_stats(),
            BodyIngestionStats {
                supplied: 10,
                retained: 10,
                inspected: 10,
                truncated: false,
                spilled: true,
            }
        );
        assert_eq!(tx.audit_log().transaction.request.body, "0123456789");

        let path = tx.request_body_spill_path().unwrap().to_owned();
        assert!(path.exists(), "spill file {path:?} should exist");
        drop(tx);
        assert!(
            !path.exists(),
            "spill file {path:?} should be removed with the transaction"
        );
    }

    #[test]
    fn default_in_memory_limit_keeps_a_body_above_128_kib_in_memory() {
        // The unset default follows the raised body limit, so a body above 128 KiB stays
        // in memory instead of spilling at a fixed 128 KiB threshold.
        let config = WafConfig {
            request_body_access: true,
            request_body_limit: 1024 * 1024,
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("request-default-memory", Arc::new(config));
        tx.process_request_headers();
        tx.set_request_body_processor("RAW");

        let body = vec![b'a'; 128 * 1024 + 1];
        assert_eq!(tx.process_request_body(&body), None);
        assert!(!tx.request_body_stats().spilled);
        assert_eq!(tx.request_body_stats().retained, u64::try_from(body.len()).unwrap());
        assert_eq!(tx.request_body_stats().inspected, u64::try_from(body.len()).unwrap());
        assert!(!tx.request_body_stats().truncated);
    }

    #[test]
    fn explicit_in_memory_limit_spills_above_the_configured_value() {
        let config = WafConfig {
            request_body_access: true,
            request_body_limit: 1024 * 1024,
            request_body_in_memory_limit: 131_072,
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("request-explicit-memory", Arc::new(config));
        tx.process_request_headers();
        tx.set_request_body_processor("RAW");

        let body = vec![b'a'; 131_073];
        assert_eq!(tx.process_request_body(&body), None);
        assert!(tx.request_body_stats().spilled);
        assert_eq!(tx.request_body_stats().retained, u64::try_from(body.len()).unwrap());
        assert_eq!(tx.request_body_stats().inspected, u64::try_from(body.len()).unwrap());
    }

    #[test]
    fn explicit_zero_in_memory_limit_follows_the_body_limit() {
        let config = WafConfig {
            request_body_access: true,
            request_body_limit: 1024 * 1024,
            request_body_in_memory_limit: 0,
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("request-zero-memory", Arc::new(config));
        tx.process_request_headers();

        let body = vec![b'a'; 128 * 1024 + 1];
        assert_eq!(tx.process_request_body(&body), None);
        assert!(!tx.request_body_stats().spilled);
        assert_eq!(tx.request_body_stats().retained, u64::try_from(body.len()).unwrap());
        assert_eq!(tx.request_body_stats().inspected, 0);
        assert_eq!(tx.request_body_buffer.replay_count(), 0);
    }

    #[test]
    fn spilled_request_body_replays_through_the_json_processor() {
        let config = WafConfig {
            request_body_access: true,
            request_body_limit: 64,
            request_body_in_memory_limit: 2,
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("request-spill-json", Arc::new(config));
        tx.process_request_headers();
        tx.set_request_body_processor("JSON");

        let body = br#"{"user":"attack"}"#;
        assert_eq!(tx.process_request_body(body), None);
        assert!(tx.request_body_stats().spilled);
        assert_eq!(tx.request_body_stats().inspected, u64::try_from(body.len()).unwrap());
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("json.user")).as_deref(),
            Some("attack")
        );
    }

    #[test]
    fn detection_only_records_body_limit_rejection_and_processes_partial_body() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRuleEngine DetectionOnly\n\
                 SecRequestBodyAccess On\n\
                 SecRequestBodyLimit 4\n\
                 SecAction \"id:39,phase:1,ctl:requestBodyProcessor=RAW,pass\"\n\
                 SecRule REQUEST_BODY \"@contains atta\" \"id:40,phase:2,setvar:TX.body=+1,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("detect-only-body-limit");
        tx.process_request_headers();

        // Deliberate difference: Go's Reject path sets the interruption directly
        // (`internal/corazawaf/transaction.go:948-955`, called from 995-997), so even
        // DetectionOnly drops the body there, while this runtime records the would-be
        // interruption and still inspects the truncated prefix.
        assert_eq!(tx.process_request_body(b"attack"), None);
        assert!(tx.interruption().is_none());
        let would_be = tx.would_be_interruption().unwrap();
        assert_eq!(would_be.rule_id, 0);
        assert_eq!(would_be.action, "deny");
        assert_eq!(would_be.status, 413);
        assert_eq!(
            tx.get_variable(RuleVariable::RequestBody, None).as_deref(),
            Some("atta")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::RequestBodyLength, None).as_deref(),
            Some("4")
        );
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("body")).as_deref(), Some("1"));
    }

    #[test]
    fn request_body_phase_runs_without_body_access_and_only_once_after_headers() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess Off\n\
                 SecAction \"id:35,phase:2,setvar:TX.body=+1,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("body-phase-order");
        tx.add_get_argument("q", "attack");

        assert_eq!(tx.process_request_body(b"ignored=value"), None);
        assert_eq!(tx.last_phase(), None);
        tx.process_request_headers();
        assert_eq!(tx.process_request_body(b""), None);
        assert_eq!(tx.last_phase(), Some(RulePhase::RequestBody));
        assert_eq!(tx.process_request_body(b"again=value"), None);

        assert_eq!(tx.get_variable(RuleVariable::TX, Some("body")).as_deref(), Some("1"));
        assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("ignored")), None);
        assert_eq!(
            tx.get_variable(RuleVariable::RequestBodyLength, None).as_deref(),
            Some("0")
        );
    }

    #[test]
    fn ctl_can_enable_body_access_and_force_urlencoded_processing() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess Off\n\
                 SecAction \"id:36,phase:1,ctl:requestBodyAccess=On,ctl:forceRequestBodyVariable=On,pass\"\n\
                 SecRule ARGS_POST \"@contains attack\" \"id:37,phase:2,deny\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("body-access-ctl");
        tx.process_request_headers();

        assert_eq!(tx.process_request_body(b"q=attack").unwrap().rule_id, 37);
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
            Some("URLENCODED")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("q")).as_deref(),
            Some("attack")
        );
    }

    #[test]
    fn force_body_variable_does_not_override_an_explicit_json_processor() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecAction \"id:38,phase:1,ctl:forceRequestBodyVariable=On,ctl:requestBodyProcessor=JSON,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("explicit-json-processor");
        tx.process_request_headers();

        assert_eq!(tx.process_request_body(br#"{"q":"attack"}"#), None);
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
            Some("JSON")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("json.q")).as_deref(),
            Some("attack")
        );
        assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some(""));
    }

    #[test]
    fn json_body_populates_flattened_post_arguments_and_runs_phase_two_rules() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecAction \"id:41,phase:1,ctl:requestBodyProcessor=JSON,pass\"\n\
                 SecRule ARGS_POST \"@contains admin\" \"id:42,phase:2,deny,status:403\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("json-body");
        tx.process_request_headers();

        let body = br#"{"user":{"name":"admin","enabled":true},"ids":[10,20],"nothing":null}"#;
        let interruption = tx.process_request_body(body).unwrap();

        assert_eq!(interruption.rule_id, 42);
        assert_eq!(interruption.status, 403);
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
            Some("JSON")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("json.user.name"))
                .as_deref(),
            Some("admin")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("json.user.enabled"))
                .as_deref(),
            Some("true")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("json.ids")).as_deref(),
            Some("2")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("json.ids.0")).as_deref(),
            Some("10")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("json.nothing")).as_deref(),
            Some("")
        );
        assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some(""));
        assert_eq!(
            tx.get_variable(RuleVariable::RequestBodyLength, None).as_deref(),
            Some("0")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("json_request_body")).as_deref(),
            std::str::from_utf8(body).ok()
        );
    }

    #[test]
    fn json_body_errors_are_exposed_and_phase_two_still_runs() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecRequestBodyJsonDepthLimit 1\n\
                 SecAction \"id:43,phase:1,ctl:requestBodyProcessor=JSON,pass\"\n\
                 SecRule REQBODY_ERROR \"@eq 1\" \"id:44,phase:2,setvar:TX.error_seen=+1,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();

        for (id, body, expected_error) in [
            ("invalid-json", b"{invalid}".as_slice(), "JSON:"),
            (
                "deep-json",
                br#"{"a":{"b":1}}"#.as_slice(),
                "JSON: max recursion reached while reading json object",
            ),
        ] {
            let mut tx = waf.new_transaction_with_id(id);
            tx.process_request_headers();

            assert_eq!(tx.process_request_body(body), None);
            assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("1"));
            assert!(
                tx.get_variable(RuleVariable::ReqbodyErrorMsg, None)
                    .is_some_and(|message| message.starts_with(expected_error))
            );
            assert_eq!(
                tx.get_variable(RuleVariable::ReqbodyProcessorError, None).as_deref(),
                Some("1")
            );
            assert!(
                tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None)
                    .is_some_and(|message| !message.is_empty())
            );
            assert_eq!(
                tx.get_variable(RuleVariable::TX, Some("error_seen")).as_deref(),
                Some("1")
            );
            assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("json.a")), None);
        }
    }

    #[test]
    fn xml_body_populates_request_xml_and_runs_phase_two_rules() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecAction \"id:45,phase:1,ctl:requestBodyProcessor=XML,pass\"\n\
                 SecRule XML:/* \"@contains superuser\" \"id:46,phase:2,deny,status:403\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("xml-body");
        tx.process_request_headers();

        let body = br#"<user name="admin"><role>superuser &amp; guest</role></user>"#;
        let interruption = tx.process_request_body(body).unwrap();

        assert_eq!(interruption.rule_id, 46);
        assert_eq!(interruption.status, 403);
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
            Some("XML")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::RequestXML, Some("//@*")).as_deref(),
            Some("admin")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::XML, Some("/*")).as_deref(),
            Some("superuser & guest")
        );
        assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some(""));
    }

    #[test]
    fn xml_truncated_body_keeps_values_parsed_before_eof() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecAction \"id:49,phase:1,ctl:requestBodyProcessor=XML,pass\"\n\
                 SecRule XML:/* \"@contains partial\" \"id:50,phase:2,deny\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("truncated-xml");
        tx.process_request_headers();

        assert_eq!(tx.process_request_body(b"<root><item>partial").unwrap().rule_id, 50);
        assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("0"));
        assert_eq!(
            tx.get_variable(RuleVariable::XML, Some("/*")).as_deref(),
            Some("partial")
        );
    }

    #[test]
    fn xml_body_errors_are_exposed_and_phase_two_still_runs() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecAction \"id:47,phase:1,ctl:requestBodyProcessor=XML,pass\"\n\
                 SecRule REQBODY_ERROR \"@eq 1\" \"id:48,phase:2,setvar:TX.xml_error=+1,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("invalid-xml");
        tx.process_request_headers();

        assert_eq!(tx.process_request_body(b"<root><1bad>secret</1bad></root>"), None);
        assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("1"));
        assert!(
            tx.get_variable(RuleVariable::ReqbodyErrorMsg, None)
                .is_some_and(|message| message.starts_with("XML: malformed xml:"))
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessorError, None).as_deref(),
            Some("1")
        );
        assert!(
            tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None)
                .is_some_and(|message| message.starts_with("malformed xml:"))
        );
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("xml_error")).as_deref(),
            Some("1")
        );
        assert_eq!(tx.get_variable(RuleVariable::RequestXML, Some("/*")), None);
    }

    #[test]
    fn xml_content_type_does_not_select_the_processor_automatically() {
        let mut parser = crate::seclang::Parser::new();
        parser.from_string("SecRequestBodyAccess On").unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("xml-content-type");
        tx.add_request_header("Content-Type", b"application/xml");
        tx.process_request_headers();

        assert_eq!(tx.process_request_body(b"<root>text</root>"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
            Some("")
        );
        assert_eq!(tx.get_variable(RuleVariable::RequestXML, Some("/*")), None);
    }

    #[test]
    fn only_the_first_content_type_selects_a_body_processor() {
        let mut parser = crate::seclang::Parser::new();
        parser.from_string("SecRequestBodyAccess On").unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("first-content-type");
        tx.add_request_header("Content-Type", b"application/json");
        tx.add_request_header("content-type", b"application/x-www-form-urlencoded");
        tx.process_request_headers();

        assert_eq!(tx.process_request_body(b"key=value"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
            Some("")
        );
        assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("key")), None);
        assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some(""));
    }

    #[test]
    fn content_type_selection_matches_go_media_type_prefixes() {
        // Go trims the header value and prefix-matches both media types, ignoring
        // case (`internal/corazawaf/transaction.go:411-416`), so a parameter list, a
        // malformed suffix, or invalid bytes never suppress the selection. PHP's
        // `sapi_read_post_data` prefix-matches the same way.
        let cases: &[(&[u8], &str)] = &[
            (b"application/x-www-form-urlencoded", "URLENCODED"),
            (b"APPLICATION/X-WWW-FORM-URLENCODED", "URLENCODED"),
            (b"application/x-www-form-urlencoded; charset=UTF-8", "URLENCODED"),
            (b"application/x-www-form-urlencoded;charset", "URLENCODED"),
            (b"  \tapplication/x-www-form-urlencoded\r\n", "URLENCODED"),
            ("\u{a0}application/x-www-form-urlencoded".as_bytes(), "URLENCODED"),
            ("\u{3000}application/x-www-form-urlencoded".as_bytes(), "URLENCODED"),
            (b"application/x-www-form-urlencodedevil", "URLENCODED"),
            (b"application/x-www-form-urlencoded=", "URLENCODED"),
            (b"application/x-www-form-urlencoded\xff", "URLENCODED"),
            (b"\xc2\xa0application/x-www-form-urlencoded\xff", "URLENCODED"),
            (b"multipart/form-data", "MULTIPART"),
            (b"MULTIPART/FORM-DATA; boundary=b", "MULTIPART"),
            (b"multipart/form-datax", "MULTIPART"),
            // Go only recognizes the form-data prefix, so other multipart subtypes
            // stay unselected until ctl:requestBodyProcessor selects MULTIPART.
            (b"multipart/mixed; boundary=b", ""),
            (b"application/xwww-form-urlencoded", ""),
            (b"application/json", ""),
            (b"text/plain", ""),
            ("\u{1F600}application/x-www-form-urlencoded".as_bytes(), ""),
            (b"\xffapplication/x-www-form-urlencoded", ""),
            (b"", ""),
        ];
        for (content_type, expected) in cases {
            let config = WafConfig {
                request_body_access: true,
                ..WafConfig::default()
            };
            let mut tx = Transaction::with_config("content-type-prefix", Arc::new(config));
            tx.add_request_header("Content-Type", *content_type);
            tx.process_request_headers();
            assert_eq!(
                tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
                Some(*expected),
                "content type {:?}",
                String::from_utf8_lossy(content_type)
            );
        }
    }

    #[test]
    fn malformed_urlencoded_content_type_still_parses_arguments() {
        // Go selects on the prefix (`internal/corazawaf/transaction.go:412`), so a
        // Content-Type that a strict MIME parser rejects still selects URLENCODED.
        let config = WafConfig {
            request_body_access: true,
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("urlencoded-suffix", Arc::new(config));
        tx.add_request_header("Content-Type", b"application/x-www-form-urlencoded\xff");
        tx.process_request_headers();

        assert_eq!(tx.process_request_body(b"key=value"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
            Some("URLENCODED")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("key")).as_deref(),
            Some("value")
        );
    }

    #[test]
    fn multipart_mixed_is_parsed_only_when_ctl_selects_multipart() {
        // Go recognizes only the `multipart/form-data` prefix
        // (`internal/corazawaf/transaction.go:414`), while its multipart processor
        // accepts any `multipart/` media type
        // (`internal/bodyprocessors/multipart.go:32`).
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"k\"\r\n\
\r\n\
v\r\n\
--b--";

        let mut parser = crate::seclang::Parser::new();
        parser.from_string("SecRequestBodyAccess On").unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("multipart-mixed-auto");
        tx.add_request_header("Content-Type", b"multipart/mixed; boundary=b");
        tx.process_request_headers();

        assert_eq!(tx.process_request_body(body), None);
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
            Some("")
        );
        assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("k")), None);

        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecAction \"id:36,phase:1,ctl:requestBodyProcessor=MULTIPART,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("multipart-mixed-ctl");
        tx.add_request_header("Content-Type", b"multipart/mixed; boundary=b");
        tx.process_request_headers();

        assert_eq!(tx.process_request_body(body), None);
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
            Some("MULTIPART")
        );
        assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("k")).as_deref(), Some("v"));
    }

    #[test]
    fn evaluates_request_header_rules_from_a_compiled_waf() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string("SecRule ARGS \"@contains attack\" \"id:10,phase:1,deny,status:403\"")
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("blocked");
        tx.add_get_argument("q", b"an attack");

        let interruption = tx.process_request_headers().unwrap();

        assert_eq!(interruption.rule_id, 10);
        assert_eq!(interruption.action, "deny");
        assert_eq!(interruption.status, 403);
        assert_eq!(tx.last_phase(), Some(RulePhase::RequestHeaders));
        assert_eq!(tx.process_request_headers(), Some(interruption));
    }

    #[test]
    fn detection_only_records_a_would_be_interruption() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string("SecRuleEngine DetectionOnly\nSecRule ARGS \"@contains attack\" \"id:11,phase:1,deny\"")
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("detect-only");
        tx.add_get_argument("q", b"attack");

        assert_eq!(tx.process_request_headers(), None);
        assert!(tx.interruption().is_none());
        let would_be = tx.would_be_interruption().unwrap();
        assert_eq!(would_be.rule_id, 11);
        assert_eq!(would_be.status, 403);
    }

    #[test]
    fn response_phases_parse_json_and_evaluate_response_rules() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecResponseBodyAccess On\n\
                 SecResponseBodyMimeType application/json\n\
                 SecAction \"id:70,phase:3,ctl:responseBodyProcessor=JSON,pass\"\n\
                 SecRule RESPONSE_STATUS \"@streq 200\" \"id:71,phase:3,pass,setvar:TX.response_status=seen\"\n\
                 SecRule RESPONSE_ARGS:json.admin \"@streq true\" \"id:72,phase:4,deny,status:403\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("response-json");
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "application/json; charset=utf-8");

        assert_eq!(tx.process_response_headers(200, "HTTP/1.1"), None);
        assert_eq!(tx.last_phase(), Some(RulePhase::ResponseHeaders));
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("response_status")).as_deref(),
            Some("seen")
        );
        assert!(tx.is_response_body_processable());
        assert!(tx.response_body_access());

        let interruption = tx.process_response_body(br#"{"admin":true}"#).unwrap();
        assert_eq!(interruption.rule_id, 72);
        assert_eq!(interruption.status, 403);
        assert_eq!(tx.last_phase(), Some(RulePhase::ResponseBody));
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseArgs, Some("json.admin"))
                .as_deref(),
            Some("true")
        );
        // Go's JSON processor stores the raw body in TX and leaves RESPONSE_BODY unset.
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("json_response_body")).as_deref(),
            Some(r#"{"admin":true}"#)
        );
        assert_eq!(tx.get_variable(RuleVariable::ResponseBody, None).as_deref(), Some(""));
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseContentLength, None).as_deref(),
            Some("14")
        );
    }

    #[test]
    fn response_raw_processor_populates_response_body() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecResponseBodyAccess On\n\
                 SecResponseBodyMimeType text/plain\n\
                 SecAction \"id:73,phase:3,ctl:responseBodyProcessor=RAW,pass\"\n\
                 SecRule RESPONSE_BODY \"@contains attack\" \"id:74,phase:4,deny\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("response-raw");
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");

        assert_eq!(tx.process_response_body(b"attack").unwrap().rule_id, 74);
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseBody, None).as_deref(),
            Some("attack")
        );
    }

    #[test]
    fn response_body_mime_uses_the_first_content_type_header() {
        let config = WafConfig {
            response_body_access: true,
            response_body_mime_types: vec!["text/plain".to_owned()],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("response-content-type", Arc::new(config));
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "application/json");
        tx.add_response_header("content-type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");

        assert!(!tx.is_response_body_processable());
        tx.process_response_body(b"body");
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseContentLength, None).as_deref(),
            Some("")
        );
    }

    #[test]
    fn response_body_limit_reject_records_detection_only_and_processes_partial_body() {
        let config = WafConfig {
            rule_engine: RuleEngineStatus::DetectionOnly,
            response_body_access: true,
            response_body_limit: 3,
            response_body_limit_action: BodyLimitAction::Reject,
            response_body_mime_types: vec!["text/plain".to_owned()],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("response-limit-detection-only", Arc::new(config));
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");

        // Deliberate difference: Go's Reject path sets the interruption directly
        // (`internal/corazawaf/transaction.go:948-955`, called from 1266-1268), so even
        // DetectionOnly drops the response body there, while this runtime records the
        // would-be interruption and still inspects the truncated prefix.
        assert_eq!(tx.process_response_body(b"attack"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
            Some("1")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseBody, None).as_deref(),
            Some("att")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseContentLength, None).as_deref(),
            Some("6")
        );
        assert_eq!(tx.would_be_interruption().map(|item| item.status), Some(500));

        let config = WafConfig {
            rule_engine: RuleEngineStatus::On,
            response_body_access: true,
            response_body_limit: 3,
            response_body_limit_action: BodyLimitAction::Reject,
            response_body_mime_types: vec!["text/plain".to_owned()],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("response-limit-reject", Arc::new(config));
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");

        assert_eq!(tx.process_response_body(b"attack").map(|item| item.status), Some(500));
        assert_eq!(tx.get_variable(RuleVariable::ResponseBody, None).as_deref(), Some(""));
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseContentLength, None).as_deref(),
            Some("6")
        );
    }

    #[test]
    fn response_body_limit_boundaries_match_go_write_semantics() {
        // Go WriteResponseBody uses `>=`, so a body exactly at the limit is rejected by
        // the Reject action and partially inspected by ProcessPartial.
        let config = WafConfig {
            response_body_access: true,
            response_body_limit: 3,
            response_body_limit_action: BodyLimitAction::Reject,
            response_body_mime_types: vec!["text/plain".to_owned()],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("response-limit-equal-reject", Arc::new(config));
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");

        assert_eq!(tx.process_response_body(b"abc").map(|item| item.status), Some(500));
        assert_eq!(
            tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
            Some("1")
        );
        assert_eq!(tx.get_variable(RuleVariable::ResponseBody, None).as_deref(), Some(""));
        assert_eq!(tx.response_body_stats().supplied, 3);
        assert_eq!(tx.response_body_stats().retained, 0);
        assert_eq!(tx.response_body_stats().inspected, 0);
        assert!(tx.response_body_stats().truncated);

        let config = WafConfig {
            response_body_access: true,
            response_body_limit: 3,
            response_body_limit_action: BodyLimitAction::ProcessPartial,
            response_body_mime_types: vec!["text/plain".to_owned()],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("response-limit-equal-partial", Arc::new(config));
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");

        assert_eq!(tx.process_response_body(b"abc"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
            Some("1")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseBody, None).as_deref(),
            Some("abc")
        );
        assert_eq!(tx.response_body_stats().retained, 3);
        assert_eq!(tx.response_body_stats().inspected, 3);
        assert!(!tx.response_body_stats().truncated);
        assert!(!tx.response_body_stats().spilled);

        // One byte below the limit is neither rejected nor flagged.
        let config = WafConfig {
            response_body_access: true,
            response_body_limit: 3,
            response_body_limit_action: BodyLimitAction::Reject,
            response_body_mime_types: vec!["text/plain".to_owned()],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("response-limit-below", Arc::new(config));
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");

        assert_eq!(tx.process_response_body(b"ab"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
            Some("0")
        );
        assert_eq!(tx.get_variable(RuleVariable::ResponseBody, None).as_deref(), Some("ab"));

        // One byte above the limit truncates and flags the body.
        let config = WafConfig {
            response_body_access: true,
            response_body_limit: 3,
            response_body_limit_action: BodyLimitAction::ProcessPartial,
            response_body_mime_types: vec!["text/plain".to_owned()],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("response-limit-above", Arc::new(config));
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");

        assert_eq!(tx.process_response_body(b"abcd"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseBody, None).as_deref(),
            Some("abc")
        );
        assert!(tx.response_body_stats().truncated);
        assert_eq!(tx.response_body_stats().supplied, 4);
        assert_eq!(tx.response_body_stats().retained, 3);
    }

    #[test]
    fn zero_response_limit_rejects_only_non_empty_bodies() {
        for action in [BodyLimitAction::Reject, BodyLimitAction::ProcessPartial] {
            let config = WafConfig {
                response_body_access: true,
                response_body_limit: 0,
                response_body_limit_action: action,
                response_body_mime_types: vec!["text/plain".to_owned()],
                ..WafConfig::default()
            };
            let mut tx = Transaction::with_config("response-limit-zero", Arc::new(config));
            tx.process_request_headers();
            tx.process_request_body(b"");
            tx.add_response_header("Content-Type", "text/plain");
            tx.process_response_headers(200, "HTTP/1.1");

            assert_eq!(tx.process_response_body(b""), None);
            assert_eq!(
                tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
                Some("0")
            );
            assert_eq!(tx.response_body_stats().supplied, 0);

            let config = WafConfig {
                response_body_access: true,
                response_body_limit: 0,
                response_body_limit_action: action,
                response_body_mime_types: vec!["text/plain".to_owned()],
                ..WafConfig::default()
            };
            let mut tx = Transaction::with_config("response-limit-zero-body", Arc::new(config));
            tx.process_request_headers();
            tx.process_request_body(b"");
            tx.add_response_header("Content-Type", "text/plain");
            tx.process_response_headers(200, "HTTP/1.1");

            let interruption = tx.process_response_body(b"a");
            assert_eq!(
                interruption.map(|item| item.status),
                (action == BodyLimitAction::Reject).then_some(500)
            );
            assert_eq!(
                tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
                Some("1")
            );
            assert_eq!(tx.response_body_stats().retained, 0);
            assert_eq!(tx.response_body_stats().supplied, 1);
            assert!(tx.response_body_stats().truncated);
        }
    }

    #[test]
    fn empty_response_body_bypasses_zero_body_limit() {
        let config = WafConfig {
            response_body_access: true,
            response_body_limit: 0,
            response_body_limit_action: BodyLimitAction::Reject,
            response_body_mime_types: vec!["text/plain".to_owned()],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("empty-response-limit", Arc::new(config));
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");

        assert_eq!(tx.process_response_body(b""), None);
        assert_eq!(
            tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
            Some("0")
        );
        assert_eq!(tx.would_be_interruption(), None);
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseContentLength, None).as_deref(),
            Some("0")
        );
    }

    #[test]
    fn response_body_limit_process_partial_below_the_limit_keeps_the_body() {
        // One byte under the limit never reaches the `>=` comparison
        // (`internal/corazawaf/transaction.go:1263`), under either action.
        let config = WafConfig {
            response_body_access: true,
            response_body_limit: 3,
            response_body_limit_action: BodyLimitAction::ProcessPartial,
            response_body_mime_types: vec!["text/plain".to_owned()],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("response-limit-below-partial", Arc::new(config));
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");

        assert_eq!(tx.process_response_body(b"ab"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
            Some("0")
        );
        assert_eq!(tx.get_variable(RuleVariable::ResponseBody, None).as_deref(), Some("ab"));
        assert!(!tx.response_body_stats().truncated);
        assert_eq!(tx.response_body_stats().inspected, 2);
    }

    #[test]
    fn response_body_limit_is_not_applied_when_the_rule_engine_is_off() {
        // Go returns before the limit check when the rule engine is off
        // (`internal/corazawaf/transaction.go:1239-1241`).
        let config = WafConfig {
            rule_engine: RuleEngineStatus::Off,
            response_body_access: true,
            response_body_limit: 3,
            response_body_limit_action: BodyLimitAction::Reject,
            response_body_mime_types: vec!["text/plain".to_owned()],
            audit_engine: AuditEngineStatus::On,
            audit_log_parts: vec![AuditLogPart::ResponseBody],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("response-engine-off", Arc::new(config));
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");
        assert_eq!(tx.last_phase(), None);

        assert_eq!(tx.process_response_body(b"attack"), None);
        assert_eq!(tx.response_body_stats(), BodyIngestionStats::default());
        assert_eq!(
            tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
            Some("0")
        );
        assert_eq!(tx.get_variable(RuleVariable::ResponseBody, None).as_deref(), Some(""));
        assert_eq!(tx.would_be_interruption(), None);
        assert!(
            tx.audit_log()
                .transaction
                .response
                .is_none_or(|response| response.body.is_empty())
        );
    }

    #[test]
    fn ctl_rule_target_removal_only_changes_the_selected_transaction() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecAction \"id:80,phase:1,ctl:ruleRemoveTargetById=81;ARGS:/^USER$/,pass\"\n\
                 SecRule ARGS \"@contains bad\" \"id:81,phase:1,deny\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();

        let mut excluded = waf.new_transaction_with_id("target-excluded");
        excluded.add_get_argument("user", "bad");
        excluded.process_request_headers();
        assert_eq!(excluded.interruption(), None);

        let mut other_key = waf.new_transaction_with_id("target-other-key");
        other_key.add_get_argument("user", "good");
        other_key.add_get_argument("query", "bad");
        let interruption = other_key.process_request_headers().unwrap();
        assert_eq!(interruption.rule_id, 81);
    }

    #[test]
    fn ctl_rule_target_removal_by_tag_and_message_skips_matching_keys() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecAction \"id:86,phase:1,ctl:ruleRemoveTargetByTag=removed-tag;ARGS:tagged,ctl:ruleRemoveTargetByMsg=removed message;ARGS:message,pass\"\n\
                 SecRule ARGS:tagged \"@contains bad\" \"id:87,phase:1,tag:removed-tag,deny\"\n\
                 SecRule ARGS:message \"@contains bad\" \"id:88,phase:1,msg:removed message,deny\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("target-tag-message");
        tx.add_get_argument("tagged", "bad");
        tx.add_get_argument("message", "bad");

        assert_eq!(tx.process_request_headers(), None);
    }

    #[test]
    fn response_body_controls_enable_forcing_and_limit_processing() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecResponseBodyAccess Off\n\
                 SecAction \"id:84,phase:3,ctl:responseBodyAccess=On,ctl:forceResponseBodyVariable=On,ctl:responseBodyLimit=3,pass\"\n\
                 SecRule RESPONSE_BODY \"@contains sec\" \"id:85,phase:4,deny\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("response-controls");
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");

        assert!(tx.response_body_access());
        assert!(tx.is_response_body_processable());
        assert_eq!(tx.process_response_body(b"secret").unwrap().rule_id, 85);
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseBody, None).as_deref(),
            Some("sec")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
            Some("1")
        );
    }

    #[test]
    fn response_body_requires_response_headers_and_runs_only_once() {
        let config = WafConfig {
            response_body_access: true,
            response_body_mime_types: vec!["text/plain".to_owned()],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("response-order", Arc::new(config));
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");

        assert_eq!(tx.process_response_body(b"too early"), None);
        assert_eq!(tx.last_phase(), Some(RulePhase::RequestBody));
        tx.process_response_headers(200, "HTTP/1.1");
        assert_eq!(tx.process_response_body(b"first"), None);
        assert_eq!(tx.process_response_body(b"second"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseBody, None).as_deref(),
            Some("first")
        );
    }

    #[test]
    fn malformed_response_json_sets_processor_error_variables() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecResponseBodyAccess On\n\
                 SecResponseBodyMimeType application/json\n\
                 SecAction \"id:89,phase:3,ctl:responseBodyProcessor=JSON,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("response-json-error");
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "application/json");
        tx.process_response_headers(200, "HTTP/1.1");

        assert_eq!(tx.process_response_body(b"not json"), None);
        assert_eq!(tx.get_variable(RuleVariable::ResBodyError, None).as_deref(), Some("1"));
        assert_eq!(
            tx.get_variable(RuleVariable::ResBodyErrorMsg, None).as_deref(),
            Some("JSON: invalid JSON")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ResBodyProcessorError, None).as_deref(),
            Some("1")
        );
        assert!(
            tx.get_variable(RuleVariable::ResBodyProcessorErrorMsg, None)
                .is_some_and(|message| !message.is_empty())
        );
    }

    #[test]
    fn ctl_rule_removal_by_id_tag_and_message_skips_matching_rules() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecAction \"id:90,phase:1,ctl:ruleRemoveById=91,ctl:ruleRemoveByTag=disabled,ctl:ruleRemoveByMsg=disabled message,pass\"\n\
                 SecAction \"id:91,phase:1,deny\"\n\
                 SecAction \"id:92,phase:1,tag:disabled,deny\"\n\
                 SecAction \"id:93,phase:1,msg:disabled message,deny\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("rule-removals");

        assert_eq!(tx.process_request_headers(), None);
    }

    #[test]
    fn setenv_writes_macro_expanded_values_to_env_collection() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string("SecAction \"id:100,phase:1,setvar:TX.user=alice,setenv:request.user=%{TX.user},pass\"")
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("setenv");

        assert_eq!(tx.process_request_headers(), None);
        assert_eq!(
            tx.get_variable(RuleVariable::Env, Some("request.user")).as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn chained_rules_only_apply_disruptive_actions_when_every_link_matches() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRule ARGS \"@contains first\" \"id:12,phase:1,deny,chain\"\n\
                 SecRule ARGS \"@contains second\" \"\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("chain");
        tx.add_get_argument("q", b"first only");

        assert_eq!(tx.process_request_headers(), None);

        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRule ARGS \"@contains first\" \"id:13,phase:1,deny,chain\"\n\
                 SecRule ARGS \"@contains second\" \"\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("chain-match");
        tx.add_get_argument("q", b"first and second");

        assert_eq!(tx.process_request_headers().unwrap().rule_id, 13);
    }

    #[test]
    fn setvar_updates_tx_during_rule_evaluation() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string("SecAction \"id:14,phase:1,setvar:TX.score=+5,pass\"")
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("setvar");
        tx.set_tx_variable("score", b"2");

        tx.process_request_headers();

        assert_eq!(tx.get_variable(RuleVariable::TX, Some("score")).as_deref(), Some("7"));
    }

    #[test]
    fn match_variables_are_available_to_action_macros() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRule ARGS \"@contains attack\" \"id:19,phase:1,setvar:TX.value=%{MATCHED_VAR},setvar:TX.name=%{MATCHED_VAR_NAME},deny\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("matched-vars");
        tx.add_get_argument("q", b"an attack");

        tx.process_request_headers();

        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("value")).as_deref(),
            Some("an attack")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("name")).as_deref(),
            Some("ARGS:q")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::MatchedVar, None).as_deref(),
            Some("an attack")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::MatchedVars, Some("ARGS:q")).as_deref(),
            Some("an attack")
        );
    }

    #[test]
    fn rule_variables_describe_the_rule_being_evaluated() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecAction \"id:21,phase:1,rev:3,severity:WARNING,msg:'blocked',logdata:'data',setvar:TX.rule=%{RULE.id}/%{RULE.msg}/%{RULE.rev}/%{RULE.severity}/%{RULE.logdata},pass\"\n\\
                 SecAction \"id:22,phase:1,setvar:TX.previous=%{RULE.msg}/%{RULE.logdata},pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("rule-vars");

        tx.process_request_headers();

        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("rule")).as_deref(),
            Some("21/blocked/3/warning/data")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("previous")).as_deref(),
            Some("blocked/data")
        );
    }

    #[test]
    fn captures_are_stored_even_when_negation_makes_the_rule_miss() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string("SecRule ARGS \"!@rx (attack)\" \"id:20,phase:1,capture,pass\"")
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("negated-capture");
        tx.add_get_argument("q", b"attack");

        assert_eq!(tx.process_request_headers(), None);
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("1")).as_deref(), Some("attack"));
    }

    #[test]
    fn captures_survive_chain_links_without_captures() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRule ARGS \"@rx (attack)\" \"id:24,phase:1,capture,chain,pass\"\n\\
                 SecRule ARGS \"@streq attack\" \"setvar:TX.saved=%{TX.1},pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("chain-captures");
        tx.add_get_argument("q", b"attack");

        tx.process_request_headers();

        assert_eq!(tx.get_variable(RuleVariable::TX, Some("1")).as_deref(), Some("attack"));
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("saved")).as_deref(),
            Some("attack")
        );
    }

    #[test]
    fn transformations_run_before_operator_matching() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string("SecRule ARGS \"@streq admin\" \"id:15,phase:1,t:lowercase,deny\"")
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("transformed");
        tx.add_get_argument("user", b"ADMIN");

        assert_eq!(tx.process_request_headers().unwrap().rule_id, 15);
    }

    #[test]
    fn block_uses_phase_defaults_and_is_inert_without_them() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string("SecRule ARGS \"@contains attack\" \"id:16,phase:1,block\"")
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("block-without-default");
        tx.add_get_argument("q", b"attack");

        assert_eq!(tx.process_request_headers(), None);

        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecDefaultAction \"phase:1,deny\"\n\
                 SecRule ARGS \"@contains attack\" \"id:17,phase:1,block\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("block-with-default");
        tx.add_get_argument("q", b"attack");

        assert_eq!(tx.process_request_headers().unwrap().rule_id, 17);
    }

    #[test]
    fn skip_after_skips_through_and_including_its_marker() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecAction \"id:16,phase:1,skipAfter:END,pass\"\n\
                 SecAction \"id:17,phase:1,deny\"\n\
                 SecMarker END\n\
                 SecAction \"id:18,phase:1,deny\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("skip-after");

        assert_eq!(tx.process_request_headers().unwrap().rule_id, 18);
    }

    #[test]
    fn audit_logging_records_matches_and_request_response_data_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.json");
        let callback_lines = Arc::new(std::sync::Mutex::new(Vec::new()));
        let callback_output = Arc::clone(&callback_lines);
        let mut parser = crate::seclang::Parser::new();
        *parser.config_mut() = WafConfig {
            audit_engine: AuditEngineStatus::On,
            audit_log: path.to_string_lossy().into_owned(),
            audit_log_format: crate::types::AuditLogFormat::Json,
            audit_log_parts: crate::types::parse_audit_log_parts("ABCFGHKZ").unwrap(),
            request_body_access: true,
            response_body_access: true,
            response_body_mime_types: vec!["text/plain".to_owned()],
            ..WafConfig::default()
        };
        parser.on_error_log(move |matched| {
            callback_output.lock().unwrap().push(matched.error_log());
        });
        parser
            .from_string(
                "SecRule ARGS \"@contains attack\" \"id:71,phase:1,log,msg:'found %{MATCHED_VAR}',logdata:'value %{MATCHED_VAR}',severity:WARNING\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("audit-1");
        tx.process_uri("/?q=attack#fragment", "GET", "HTTP/1.1");
        tx.set_remote_addr("192.0.2.1");
        tx.set_remote_port(1234);
        assert_eq!(tx.process_request_headers(), None);
        tx.add_request_header("Content-Type", "text/plain");
        tx.process_request_body(b"request-body");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");
        tx.process_response_body(b"response-body");
        tx.process_logging().unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let entry: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(
            entry.pointer("/transaction/id").and_then(serde_json::Value::as_str),
            Some("audit-1")
        );
        assert_eq!(
            entry
                .pointer("/transaction/request/uri")
                .and_then(serde_json::Value::as_str),
            Some("/?q=attack")
        );
        assert_eq!(
            entry
                .pointer("/transaction/request/body")
                .and_then(serde_json::Value::as_str),
            Some("request-body")
        );
        assert_eq!(
            entry
                .pointer("/transaction/response/body")
                .and_then(serde_json::Value::as_str),
            Some("response-body")
        );
        assert_eq!(
            entry.pointer("/messages/0/data/id").and_then(serde_json::Value::as_i64),
            Some(71)
        );
        assert_eq!(
            entry.pointer("/messages/0/message").and_then(serde_json::Value::as_str),
            Some("found attack")
        );
        assert_eq!(callback_lines.lock().unwrap().len(), 1);

        drop(tx);
        assert_eq!(std::fs::read_to_string(path).unwrap().lines().count(), 1);
    }

    #[test]
    fn relevant_only_audits_matches_when_the_transaction_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut parser = crate::seclang::Parser::new();
        *parser.config_mut() = WafConfig {
            audit_engine: AuditEngineStatus::RelevantOnly,
            audit_log: path.to_string_lossy().into_owned(),
            audit_log_parts: crate::types::parse_audit_log_parts("ABFHKZ").unwrap(),
            ..WafConfig::default()
        };
        parser
            .from_string("SecRule ARGS:q \"@streq evil\" \"id:81,phase:1,deny,status:403,log,auditlog,msg:'Evil'\"")
            .unwrap();
        let waf = parser.into_waf().unwrap();

        let mut benign = waf.new_transaction_with_id("tx-benign");
        benign.process_uri("/?q=fine", "GET", "HTTP/1.1");
        drop(benign.process_request_headers());
        drop(benign);

        let mut matched = waf.new_transaction_with_id("tx-evil");
        matched.process_uri("/?q=evil", "GET", "HTTP/1.1");
        assert_eq!(matched.process_request_headers().map(|item| item.rule_id), Some(81));
        drop(matched);

        let log = std::fs::read_to_string(path).unwrap();
        assert!(!log.contains("tx-benign"), "{log}");
        assert!(log.contains("tx-evil"), "{log}");
        assert!(log.contains("[id \"81\"]"), "{log}");
    }

    #[test]
    fn logging_phase_runs_after_a_disruptive_request_match() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRule ARGS \"@contains attack\" \"id:72,phase:1,deny\"\n\
                 SecRule ARGS \"@contains attack\" \"id:73,phase:5,setvar:TX.logged=yes,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("logging-after-deny");
        tx.add_get_argument("q", "attack");

        assert_eq!(tx.process_request_headers().unwrap().rule_id, 72);
        tx.process_logging().unwrap();

        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("logged")).as_deref(),
            Some("yes")
        );
    }

    #[test]
    fn process_uri_populates_decoded_query_arguments_without_the_fragment() {
        let mut tx = Transaction::new("process-uri");
        tx.process_uri("/search?q=hello+world&encoded=%ff#section", "GET", "HTTP/1.1");

        assert_eq!(
            tx.get_variable(RuleVariable::RequestURI, None).as_deref(),
            Some("/search?q=hello+world&encoded=%ff")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsGet, Some("q")).as_deref(),
            Some("hello world")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsGet, Some("encoded")).as_deref(),
            Some("\u{fffd}")
        );
        assert_eq!(tx.get_variable(RuleVariable::RemotePort, None), Some(String::new()));
    }

    /// The URI derivatives Go's `ProcessURI` produces for each kind of request target.
    #[test]
    #[expect(clippy::too_many_lines, reason = "one reviewed row per Go request-target shape")]
    fn process_uri_populates_go_uri_derivatives() {
        struct Case {
            target: &'static str,
            request_uri: &'static str,
            request_uri_raw: &'static str,
            filename: &'static str,
            basename: &'static str,
            query: &'static str,
            parse_error: &'static str,
        }

        let cases = [
            Case {
                target: "/search?q=hello+world&encoded=%ff#section",
                request_uri: "/search?q=hello+world&encoded=%ff",
                request_uri_raw: "/search?q=hello+world&encoded=%ff#section",
                filename: "/search",
                basename: "search",
                query: "q=hello+world&encoded=%ff",
                parse_error: "0",
            },
            Case {
                target: "/foo%20bar",
                request_uri: "/foo%20bar",
                request_uri_raw: "/foo%20bar",
                filename: "/foo bar",
                basename: "foo bar",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "/foo/bar/",
                request_uri: "/foo/bar/",
                request_uri_raw: "/foo/bar/",
                filename: "/foo/bar/",
                basename: "/foo/bar/",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "//foo/bar",
                request_uri: "//foo/bar",
                request_uri_raw: "//foo/bar",
                filename: "//foo/bar",
                basename: "bar",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "///foo/bar",
                request_uri: "///foo/bar",
                request_uri_raw: "///foo/bar",
                filename: "///foo/bar",
                basename: "bar",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "/a%2Fb",
                request_uri: "/a%2Fb",
                request_uri_raw: "/a%2Fb",
                filename: "/a/b",
                basename: "b",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "/a\\b",
                request_uri: "/a%5Cb",
                request_uri_raw: "/a\\b",
                filename: "/a\\b",
                basename: "b",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "/foo bar",
                request_uri: "/foo%20bar",
                request_uri_raw: "/foo bar",
                filename: "/foo bar",
                basename: "foo bar",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "/h%C3%A9llo",
                request_uri: "/h%C3%A9llo",
                request_uri_raw: "/h%C3%A9llo",
                filename: "/héllo",
                basename: "héllo",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "/héllo",
                request_uri: "/h%C3%A9llo",
                request_uri_raw: "/héllo",
                filename: "/héllo",
                basename: "héllo",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "*",
                request_uri: "*",
                request_uri_raw: "*",
                filename: "*",
                basename: "*",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "",
                request_uri: "",
                request_uri_raw: "",
                filename: "",
                basename: "",
                query: "",
                parse_error: "1",
            },
            Case {
                target: "foo",
                request_uri: "foo",
                request_uri_raw: "foo",
                filename: "foo",
                basename: "foo",
                query: "",
                parse_error: "1",
            },
            Case {
                target: "foo/bar",
                request_uri: "foo/bar",
                request_uri_raw: "foo/bar",
                filename: "foo/bar",
                basename: "bar",
                query: "",
                parse_error: "1",
            },
            Case {
                target: "?a=b",
                request_uri: "?a=b",
                request_uri_raw: "?a=b",
                filename: "",
                basename: "",
                query: "a=b",
                parse_error: "1",
            },
            Case {
                target: "/foo%zz?a=b",
                request_uri: "/foo%zz?a=b",
                request_uri_raw: "/foo%zz?a=b",
                filename: "/foo%zz",
                basename: "foo%zz",
                query: "a=b",
                parse_error: "1",
            },
            Case {
                target: "/foo?bar=baz#qux",
                request_uri: "/foo?bar=baz",
                request_uri_raw: "/foo?bar=baz#qux",
                filename: "/foo",
                basename: "foo",
                query: "bar=baz",
                parse_error: "0",
            },
            Case {
                target: "http://example.com/path/to/file.html?query=string&other=value",
                request_uri: "http://example.com/path/to/file.html?query=string&other=value",
                request_uri_raw: "http://example.com/path/to/file.html?query=string&other=value",
                filename: "/path/to/file.html",
                basename: "file.html",
                query: "query=string&other=value",
                parse_error: "0",
            },
            Case {
                target: "HTTP://Example.COM/A?b=1",
                request_uri: "http://Example.COM/A?b=1",
                request_uri_raw: "HTTP://Example.COM/A?b=1",
                filename: "/A",
                basename: "A",
                query: "b=1",
                parse_error: "0",
            },
            Case {
                target: "http://example.com",
                request_uri: "http://example.com",
                request_uri_raw: "http://example.com",
                filename: "",
                basename: "",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "http://example.com/",
                request_uri: "http://example.com/",
                request_uri_raw: "http://example.com/",
                filename: "/",
                basename: "/",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "http://user:pass@example.com/a",
                request_uri: "http://user:pass@example.com/a",
                request_uri_raw: "http://user:pass@example.com/a",
                filename: "/a",
                basename: "a",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "http://user:pa%73s@example.com/a",
                request_uri: "http://user:pass@example.com/a",
                request_uri_raw: "http://user:pa%73s@example.com/a",
                filename: "/a",
                basename: "a",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "http://user:p%40ss@example.com/a",
                request_uri: "http://user:p%40ss@example.com/a",
                request_uri_raw: "http://user:p%40ss@example.com/a",
                filename: "/a",
                basename: "a",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "http://example.com:bad/path?q=1",
                request_uri: "http://example.com:bad/path?q=1",
                request_uri_raw: "http://example.com:bad/path?q=1",
                filename: "http://example.com:bad/path",
                basename: "path",
                query: "q=1",
                parse_error: "1",
            },
            Case {
                target: "http://example.com:8080/path",
                request_uri: "http://example.com:8080/path",
                request_uri_raw: "http://example.com:8080/path",
                filename: "/path",
                basename: "path",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "http://[::1]:8080/a?b=1",
                request_uri: "http://[::1]:8080/a?b=1",
                request_uri_raw: "http://[::1]:8080/a?b=1",
                filename: "/a",
                basename: "a",
                query: "b=1",
                parse_error: "0",
            },
            Case {
                target: "http://[1.2.3.4]/a",
                request_uri: "http://[1.2.3.4]/a",
                request_uri_raw: "http://[1.2.3.4]/a",
                filename: "http://[1.2.3.4]/a",
                basename: "a",
                query: "",
                parse_error: "1",
            },
            Case {
                target: "http://[fe80::1%25eth0]/a",
                request_uri: "http://[fe80::1%25eth0]/a",
                request_uri_raw: "http://[fe80::1%25eth0]/a",
                filename: "/a",
                basename: "a",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "http://[::1/a",
                request_uri: "http://[::1/a",
                request_uri_raw: "http://[::1/a",
                filename: "http://[::1/a",
                basename: "a",
                query: "",
                parse_error: "1",
            },
            Case {
                target: "http:/foo",
                request_uri: "http:/foo",
                request_uri_raw: "http:/foo",
                filename: "/foo",
                basename: "foo",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "mailto:user@example.com",
                request_uri: "mailto:user@example.com",
                request_uri_raw: "mailto:user@example.com",
                filename: "",
                basename: "",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "/foo?",
                request_uri: "/foo?",
                request_uri_raw: "/foo?",
                filename: "/foo",
                basename: "foo",
                query: "",
                parse_error: "0",
            },
            Case {
                target: "/a?b?c",
                request_uri: "/a?b?c",
                request_uri_raw: "/a?b?c",
                filename: "/a",
                basename: "a",
                query: "b?c",
                parse_error: "0",
            },
            Case {
                target: "http://exa mple.com/a",
                request_uri: "http://exa mple.com/a",
                request_uri_raw: "http://exa mple.com/a",
                filename: "http://exa mple.com/a",
                basename: "a",
                query: "",
                parse_error: "1",
            },
            Case {
                target: "http://a:b:c/d",
                request_uri: "http://a:b:c/d",
                request_uri_raw: "http://a:b:c/d",
                filename: "http://a:b:c/d",
                basename: "d",
                query: "",
                parse_error: "1",
            },
            Case {
                target: "/?",
                request_uri: "/?",
                request_uri_raw: "/?",
                filename: "/",
                basename: "/",
                query: "",
                parse_error: "0",
            },
            // The pinned Coraza module declares Go 1.25, where net/url keeps splitting
            // the port at the last colon even for http(s) hosts with several colons.
            Case {
                target: "https://127.0:.0.1:80/a/./b?a=?b#",
                request_uri: "https://127.0:.0.1:80/a/./b?a=?b",
                request_uri_raw: "https://127.0:.0.1:80/a/./b?a=?b#",
                filename: "/a/./b",
                basename: "b",
                query: "a=?b",
                parse_error: "0",
            },
            Case {
                target: "HTTP://K::1/é?=x#?a=b",
                request_uri: "http://K::1/%C3%A9?=x",
                request_uri_raw: "HTTP://K::1/é?=x#?a=b",
                filename: "/é",
                basename: "é",
                query: "=x",
                parse_error: "0",
            },
            Case {
                target: "http://a:b:/a\\b?a=b;c=d#f",
                request_uri: "http://a:b:/a%5Cb?a=b;c=d",
                request_uri_raw: "http://a:b:/a\\b?a=b;c=d#f",
                filename: "/a\\b",
                basename: "b",
                query: "a=b;c=d",
                parse_error: "0",
            },
            Case {
                target: "https://a:b:/#",
                request_uri: "https://a:b:/",
                request_uri_raw: "https://a:b:/#",
                filename: "/",
                basename: "/",
                query: "",
                parse_error: "0",
            },
            // A non-numeric segment after the last colon is still an invalid port.
            Case {
                target: "http://a:b:bad/x",
                request_uri: "http://a:b:bad/x",
                request_uri_raw: "http://a:b:bad/x",
                filename: "http://a:b:bad/x",
                basename: "x",
                query: "",
                parse_error: "1",
            },
        ];

        for case in cases {
            let mut tx = Transaction::new("uri-derivatives");
            tx.process_uri(case.target, "GET", "HTTP/1.1");
            let value = |variable| tx.get_variable(variable, None);
            assert_eq!(
                value(RuleVariable::RequestURI).as_deref(),
                Some(case.request_uri),
                "target {:?}",
                case.target
            );
            assert_eq!(
                value(RuleVariable::RequestURIRaw).as_deref(),
                Some(case.request_uri_raw),
                "target {:?}",
                case.target
            );
            assert_eq!(
                value(RuleVariable::RequestFilename).as_deref(),
                Some(case.filename),
                "target {:?}",
                case.target
            );
            assert_eq!(
                value(RuleVariable::RequestBasename).as_deref(),
                Some(case.basename),
                "target {:?}",
                case.target
            );
            assert_eq!(
                value(RuleVariable::QueryString).as_deref(),
                Some(case.query),
                "target {:?}",
                case.target
            );
            assert_eq!(
                value(RuleVariable::URIParseError).as_deref(),
                Some(case.parse_error),
                "target {:?}",
                case.target
            );
            assert_eq!(
                value(RuleVariable::RequestLine).as_deref(),
                Some(format!("GET {} HTTP/1.1", case.target).as_str()),
                "target {:?}",
                case.target
            );
        }
    }

    #[test]
    fn process_uri_recovers_query_arguments_and_byte_values() {
        let mut tx = Transaction::new("uri-recovery");
        tx.process_uri("/search?q=ATTACK%00&y=1", "GET", "HTTP/1.1");
        let spec = VariableSpec::new_string(RuleVariable::ArgsGet, "q".to_owned());
        assert_eq!(
            tx.find_matches(&spec).first().map(|matched| matched.value.as_slice()),
            Some(&b"ATTACK\0"[..])
        );
        assert_eq!(
            tx.get_variable(RuleVariable::QueryString, None).as_deref(),
            Some("q=ATTACK%00&y=1")
        );

        let mut raw = Transaction::new("uri-control-byte");
        raw.process_uri("/search?q=a\x00&y=1", "GET", "HTTP/1.1");
        assert_eq!(
            raw.get_variable(RuleVariable::URIParseError, None).as_deref(),
            Some("1")
        );
        assert_eq!(
            raw.get_variable(RuleVariable::QueryString, None).as_deref(),
            Some("q=a\x00&y=1")
        );
        let spec = VariableSpec::new_string(RuleVariable::ArgsGet, "q".to_owned());
        assert_eq!(
            raw.find_matches(&spec).first().map(|matched| matched.value.as_slice()),
            Some(&b"a\0"[..])
        );

        let mut port = Transaction::new("uri-bad-port");
        port.process_uri("http://example.com:bad/path?q=attack", "GET", "HTTP/1.1");
        assert_eq!(
            port.get_variable(RuleVariable::URIParseError, None).as_deref(),
            Some("1")
        );
        assert_eq!(
            port.get_variable(RuleVariable::ArgsGet, Some("q")).as_deref(),
            Some("attack")
        );
    }

    /// Compile one phase-1 rule and report whether `target` makes it interrupt.
    fn uri_rule_matches(rule: &str, target: &str) -> bool {
        let mut parser = crate::seclang::Parser::new();
        parser.from_string(rule).unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("uri-rule");
        tx.process_uri(target, "GET", "HTTP/1.1");
        tx.process_request_headers().is_some()
    }

    #[test]
    fn uri_derivative_rules_match_go_producer_values() {
        assert!(uri_rule_matches(
            "SecRule REQUEST_FILENAME \"@contains /admin\" \"id:101,phase:1,deny\"",
            "/admin"
        ));
        assert!(!uri_rule_matches(
            "SecRule REQUEST_FILENAME \"@contains /admin\" \"id:101,phase:1,deny\"",
            "/public"
        ));
        assert!(uri_rule_matches(
            "SecRule REQUEST_BASENAME \"@streq passwd\" \"id:102,phase:1,deny\"",
            "/etc/passwd"
        ));
        assert!(uri_rule_matches(
            "SecRule QUERY_STRING \"@contains attack\" \"id:103,phase:1,deny\"",
            "/?q=attack"
        ));
        assert!(uri_rule_matches(
            "SecRule REQUEST_URI_RAW \"@contains fragment\" \"id:104,phase:1,deny\"",
            "/a#fragment"
        ));
        assert!(!uri_rule_matches(
            "SecRule REQUEST_URI \"@contains fragment\" \"id:105,phase:1,deny\"",
            "/a#fragment"
        ));
        assert!(uri_rule_matches(
            "SecRule REQUEST_LINE \"@beginsWith GET /a HTTP/1.1\" \"id:106,phase:1,deny\"",
            "/a"
        ));
        assert!(uri_rule_matches(
            "SecRule URI_PARSE_ERROR \"@eq 1\" \"id:107,phase:1,deny\"",
            "relative-only"
        ));
        assert!(!uri_rule_matches(
            "SecRule URI_PARSE_ERROR \"@eq 1\" \"id:107,phase:1,deny\"",
            "/valid"
        ));
        assert!(uri_rule_matches(
            "SecRule URI_PARSE_ERROR \"@eq 1\" \"id:110,phase:1,deny\"",
            "/foo%zz?a=b"
        ));
        assert!(uri_rule_matches(
            "SecRule ARGS_GET:q \"@contains attack\" \"id:108,phase:1,deny\"",
            "/search?q=attack\x00"
        ));
        assert!(uri_rule_matches(
            "SecRule REQUEST_FILENAME \"@contains admin\" \"id:109,phase:1,deny\"",
            "http://example.com:bad/admin"
        ));
        assert!(uri_rule_matches(
            "SecRule REQUEST_FILENAME \"@contains /a/./b\" \"id:111,phase:1,deny\"",
            "https://127.0:.0.1:80/a/./b"
        ));
    }

    #[test]
    fn cookie_headers_populate_request_cookies_like_go() {
        let mut tx = Transaction::new("cookies");
        tx.add_request_header("Cookie", "a=1; b=2; a=3");
        tx.add_request_header("cookie", " a=4 ;");
        let values = |tx: &Transaction, key: &str| {
            let spec = VariableSpec::new_string(RuleVariable::RequestCookies, key.to_owned());
            tx.find_matches(&spec)
                .into_iter()
                .map(|matched| String::from_utf8_lossy(&matched.value).into_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(values(&tx, "a"), ["1", "3", "4"]);
        assert_eq!(values(&tx, "b"), ["2"]);
        assert_eq!(
            tx.get_variable(RuleVariable::RequestCookiesNames, Some("a")).as_deref(),
            Some("a")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::RequestCookiesNames, Some("b")).as_deref(),
            Some("b")
        );
        assert_eq!(tx.get_variable(RuleVariable::RequestCookiesNames, Some("c")), None);

        // The explicit connector path still accumulates values.
        tx.add_request_cookie("a", "5");
        assert_eq!(values(&tx, "a"), ["1", "3", "4", "5"]);
    }

    #[test]
    fn cookie_parsing_keeps_go_edge_cases() {
        let mut tx = Transaction::new("cookie-edges");
        tx.add_request_header("Cookie", "=payload");
        tx.add_request_header("Cookie", "= ");
        tx.add_request_header("Cookie", "\x01=trimmed");
        tx.add_request_header("Cookie", "flag");
        tx.add_request_header("Cookie", "b=1;b=2;c=");
        assert!(matches!(
            tx.collection(RuleVariable::RequestCookies),
            Some(VariableCollection::Map(_))
        ));
        if let Some(VariableCollection::Map(cookies)) = tx.collection(RuleVariable::RequestCookies) {
            assert_eq!(cookies.get(""), ["payload", "trimmed"]);
            assert_eq!(cookies.get("flag"), [""]);
            assert_eq!(cookies.get("b"), ["1", "2"]);
            assert_eq!(cookies.get("c"), [""]);
        }
    }

    #[test]
    fn cookie_headers_drive_rule_outcomes() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string("SecRule REQUEST_COOKIES:session \"@streq attack\" \"id:120,phase:1,deny\"")
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("cookie-rule");
        tx.add_request_header("X-Other", "1");
        tx.process_uri("/", "GET", "HTTP/1.1");
        assert!(tx.process_request_headers().is_none());
        let mut tx = waf.new_transaction_with_id("cookie-rule-match");
        tx.add_request_header("Cookie", "session=attack");
        tx.process_uri("/", "GET", "HTTP/1.1");
        assert!(tx.process_request_headers().is_some());
    }

    #[test]
    fn time_variables_are_populated_and_match_rules() {
        let tx = Transaction::new("time");
        let epoch = tx.get_variable(RuleVariable::TimeEpoch, None).unwrap();
        assert!(epoch.parse::<u64>().is_ok());
        let value = |variable| tx.get_variable(variable, None).unwrap();
        assert!(
            regex::Regex::new("^[0-9]{2}:[0-9]{2}:[0-9]{2}$")
                .unwrap()
                .is_match(&value(RuleVariable::Time))
        );
        assert!(
            regex::Regex::new("^[0-9]{2}$")
                .unwrap()
                .is_match(&value(RuleVariable::TimeHour))
        );
        assert!(
            regex::Regex::new("^[0-9]{2}$")
                .unwrap()
                .is_match(&value(RuleVariable::TimeMin))
        );
        assert!(
            regex::Regex::new("^[0-9]{2}$")
                .unwrap()
                .is_match(&value(RuleVariable::TimeSec))
        );
        assert!((1..=31).contains(&value(RuleVariable::TimeDay).parse::<u8>().unwrap()));
        assert!((1..=12).contains(&value(RuleVariable::TimeMon).parse::<u8>().unwrap()));
        assert!((0..=6).contains(&value(RuleVariable::TimeWday).parse::<u8>().unwrap()));
        assert!(value(RuleVariable::TimeYear).parse::<u32>().unwrap() >= 2024);

        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRule TIME \"@rx ^[0-9]{2}:[0-9]{2}:[0-9]{2}$\" \"id:130,phase:1,deny\"\n\
             SecRule TIME_EPOCH \"@rx ^[0-9]+$\" \"id:131,phase:5,pass\"\n\
             SecRule TIME_WDAY \"@rx ^[0-6]$\" \"id:132,phase:5,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("time-rule");
        assert_eq!(tx.process_request_headers().unwrap().rule_id, 130);
    }

    #[test]
    fn json_request_tx_variable_follows_successful_processing() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecAction \"id:140,phase:1,ctl:requestBodyProcessor=JSON,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();

        let body = br#"{"user":"coraza"}"#;
        let mut tx = waf.new_transaction_with_id("json-tx");
        tx.process_request_headers();
        assert_eq!(tx.process_request_body(body), None);
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("json_request_body")).as_deref(),
            Some(r#"{"user":"coraza"}"#)
        );
        assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("0"));

        // A parse error still publishes the valid prefix but no raw body variable.
        let mut tx = waf.new_transaction_with_id("json-tx-error");
        tx.process_request_headers();
        assert_eq!(tx.process_request_body(br#"{"a":1} trailing"#), None);
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("json_request_body")), None);
        assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("1"));
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyErrorMsg, None).as_deref(),
            Some("JSON: invalid JSON")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("json.a")).as_deref(),
            Some("1")
        );

        // Go's ProcessRequestBody skips empty request bodies entirely.
        let mut tx = waf.new_transaction_with_id("json-tx-empty");
        tx.process_request_headers();
        assert_eq!(tx.process_request_body(b""), None);
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("json_request_body")), None);
        assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("0"));
    }

    #[test]
    fn json_response_tx_variable_replaces_the_response_body_contract() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecResponseBodyAccess On\n\
                 SecResponseBodyMimeType application/json\n\
                 SecAction \"id:141,phase:3,ctl:responseBodyProcessor=JSON,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();

        let body = br#"{"user":"coraza"}"#;
        let mut tx = waf.new_transaction_with_id("json-res-tx");
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "application/json");
        tx.process_response_headers(200, "HTTP/1.1");
        assert_eq!(tx.process_response_body(body), None);
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("json_response_body")).as_deref(),
            Some(r#"{"user":"coraza"}"#)
        );
        assert_eq!(tx.get_variable(RuleVariable::ResponseBody, None).as_deref(), Some(""));
        assert_eq!(tx.get_variable(RuleVariable::ResBodyError, None).as_deref(), Some(""));
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseArgs, Some("json.user"))
                .as_deref(),
            Some("coraza")
        );

        let mut tx = waf.new_transaction_with_id("json-res-error");
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "application/json");
        tx.process_response_headers(200, "HTTP/1.1");
        assert_eq!(tx.process_response_body(br#"{"a":1} trailing"#), None);
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("json_response_body")), None);
        assert_eq!(tx.get_variable(RuleVariable::ResBodyError, None).as_deref(), Some("1"));
        assert_eq!(
            tx.get_variable(RuleVariable::ResBodyErrorMsg, None).as_deref(),
            Some("JSON: invalid JSON")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseArgs, Some("json.a")).as_deref(),
            Some("1")
        );

        // Go runs the selected processor even for an empty response body.
        let mut tx = waf.new_transaction_with_id("json-res-empty");
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "application/json");
        tx.process_response_headers(200, "HTTP/1.1");
        assert_eq!(tx.process_response_body(b""), None);
        assert_eq!(tx.get_variable(RuleVariable::ResBodyError, None).as_deref(), Some("1"));
        assert_eq!(
            tx.get_variable(RuleVariable::ResBodyErrorMsg, None).as_deref(),
            Some("JSON: invalid JSON")
        );
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("json_response_body")), None);
    }

    #[test]
    fn json_response_argument_limit_sets_the_flag() {
        let config = WafConfig {
            response_body_access: true,
            response_body_mime_types: vec!["application/json".to_owned()],
            argument_limit: 5,
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("json-res-limit", Arc::new(config));
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "application/json");
        tx.process_response_headers(200, "HTTP/1.1");
        tx.set_response_body_processor("JSON");
        assert_eq!(tx.process_response_body(b"[1,1,1,1,1,1,1]"), None);
        assert!(tx.arguments_limit_reached());
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("json_response_body")).as_deref(),
            Some("[1,1,1,1,1,1,1]")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseArgs, Some("json.4")).as_deref(),
            Some("1")
        );
        assert_eq!(tx.get_variable(RuleVariable::ResponseArgs, Some("json.5")), None);
    }

    #[test]
    fn request_body_phase_runs_after_ingest_failure_in_detection_only() {
        for failure in [BufferFailure::Accept, BufferFailure::Replay] {
            for (engine, detection_only) in [("On", false), ("DetectionOnly", true)] {
                let mut parser = crate::seclang::Parser::new();
                parser
                    .from_string(&format!(
                        "SecRuleEngine {engine}\n\
                         SecRequestBodyAccess On\n\
                         SecAction \"id:150,phase:1,ctl:requestBodyProcessor=JSON,pass\"\n\
                         SecAction \"id:151,phase:2,deny,status:403\""
                    ))
                    .unwrap();
                let waf = parser.into_waf().unwrap();
                let mut tx = waf.new_transaction_with_id(format!("ingest-{engine}-{failure:?}"));
                tx.process_request_headers();
                inject_failure(failure);

                let interruption = tx.process_request_body(br#"{"a":1}"#);
                assert_eq!(
                    tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
                    Some("1")
                );
                let phase_ran = tx.matched_rules().iter().any(|matched| matched.rule.id == 151);
                if detection_only {
                    assert_eq!(interruption, None);
                    assert_eq!(tx.interruption(), None);
                    assert!(tx.would_be_interruption().is_some());
                    assert!(phase_ran);
                    assert_eq!(tx.last_phase(), Some(RulePhase::RequestBody));
                } else {
                    assert_eq!(interruption.map(|value| value.status), Some(500));
                    assert!(!phase_ran);
                }
            }
        }
    }

    /// Build a WAF from SecLang rules with one detector inspection policy.
    fn detector_waf(rules: &str, detector_inspection_action: DetectorInspectionAction) -> Waf {
        let mut parser = crate::seclang::Parser::new();
        parser.from_string(rules).unwrap();
        parser.config_mut().detector_inspection_action = detector_inspection_action;
        parser.into_waf().unwrap()
    }

    /// Return `payload` padded with spaces up to exactly `len` bytes.
    fn detector_input(payload: &[u8], len: usize) -> Vec<u8> {
        let mut value = payload.to_vec();
        value.resize(len, b' ');
        value
    }

    #[test]
    fn detector_scans_an_input_at_the_wrapper_bound() {
        for (operator, payload, rule_id) in [
            ("detectSQLi", b"1' OR '1'='1".as_slice(), 610),
            ("detectXSS", b"<script>alert(1)</script>".as_slice(), 611),
        ] {
            let waf = detector_waf(
                &format!("SecRule ARGS:q \"@{operator}\" \"id:{rule_id},phase:1,pass\""),
                DetectorInspectionAction::RecordOnly,
            );
            let mut tx = waf.new_transaction_with_id(format!("detector-bound-{operator}"));
            tx.add_get_argument("q", detector_input(payload, libperfusion::MAX_INPUT_LEN));

            assert!(tx.process_request_headers().is_none());
            assert!(!tx.inspection_incomplete());
            assert!(tx.matched_rules().iter().any(|matched| matched.rule.id == rule_id));
        }
    }

    #[test]
    fn detector_reports_an_over_bound_input_as_not_inspected() {
        for (operator, payload, rule_id) in [
            ("detectSQLi", b"1' OR '1'='1".as_slice(), 612),
            ("detectXSS", b"<script>alert(1)</script>".as_slice(), 613),
        ] {
            let waf = detector_waf(
                &format!("SecRule ARGS:q \"@{operator}\" \"id:{rule_id},phase:1,pass\""),
                DetectorInspectionAction::RecordOnly,
            );
            let mut tx = waf.new_transaction_with_id(format!("detector-over-bound-{operator}"));
            tx.add_get_argument("q", detector_input(payload, libperfusion::MAX_INPUT_LEN + 1));

            assert!(tx.process_request_headers().is_none());
            assert!(!tx.matched_rules().iter().any(|matched| matched.rule.id == rule_id));
            assert!(tx.inspection_incomplete());
            assert_eq!(
                tx.get_variable(RuleVariable::TX, Some("inspection_incomplete"))
                    .as_deref(),
                Some("1")
            );
        }
    }

    #[test]
    fn in_bounds_detector_inputs_leave_the_signal_clear() {
        let waf = detector_waf(
            "SecRule ARGS \"@detectSQLi\" \"id:614,phase:1,pass\"\n\
             SecRule ARGS \"@detectXSS\" \"id:615,phase:1,pass\"",
            DetectorInspectionAction::RecordOnly,
        );
        let mut tx = waf.new_transaction_with_id("detector-in-bounds");
        tx.add_get_argument("q", detector_input(b"1' OR '1'='1", libperfusion::MAX_INPUT_LEN));
        tx.add_get_argument("r", detector_input(b"<script>alert(1)</script>", 1024));

        tx.process_request_headers();
        assert!(!tx.inspection_incomplete());
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("inspection_incomplete")), None);
        assert_eq!(tx.matched_rules().len(), 2);
    }

    #[test]
    fn fail_closed_interrupts_when_a_detector_cannot_inspect() {
        for (operator, payload, rule_id) in [
            ("detectSQLi", b"1' OR '1'='1".as_slice(), 616),
            ("detectXSS", b"<script>alert(1)</script>".as_slice(), 617),
        ] {
            let waf = detector_waf(
                &format!("SecRule ARGS:q \"@{operator}\" \"id:{rule_id},phase:1,pass\""),
                DetectorInspectionAction::FailClosed,
            );
            let mut tx = waf.new_transaction_with_id(format!("detector-fail-closed-{operator}"));
            tx.add_get_argument("q", detector_input(payload, libperfusion::MAX_INPUT_LEN + 1));

            let interruption = tx.process_request_headers().unwrap();
            assert_eq!(interruption.rule_id, rule_id);
            assert_eq!(interruption.action, "deny");
            assert!(interruption.data.contains("inspection bound"));
            assert!(tx.inspection_incomplete());
        }
    }

    #[test]
    fn fail_closed_does_not_interrupt_in_bounds_inputs() {
        let waf = detector_waf(
            "SecRule ARGS:q \"@detectSQLi\" \"id:618,phase:1,pass\"",
            DetectorInspectionAction::FailClosed,
        );
        let mut tx = waf.new_transaction_with_id("detector-fail-closed-in-bounds");
        tx.add_get_argument("q", detector_input(b"1' OR '1'='1", libperfusion::MAX_INPUT_LEN));

        assert!(tx.process_request_headers().is_none());
        assert!(!tx.inspection_incomplete());
        assert!(tx.matched_rules().iter().any(|matched| matched.rule.id == 618));
    }

    #[test]
    fn fail_closed_interrupts_after_ctl_switches_from_detection_only() {
        let waf = detector_waf(
            "SecRuleEngine DetectionOnly\n\
             SecRule ARGS:q \"@detectSQLi\" \"id:630,phase:1,pass\"\n\
             SecRule ARGS:q \"@detectXSS\" \"id:631,phase:1,pass\"\n\
             SecAction \"id:632,phase:1,ctl:ruleEngine=On,pass\"\n\
             SecRule ARGS:q \"@detectSQLi\" \"id:633,phase:1,pass\"",
            DetectorInspectionAction::FailClosed,
        );
        let mut tx = waf.new_transaction_with_id("detector-fail-closed-ctl-on");
        tx.add_get_argument("q", detector_input(b"1' OR '1'='1", libperfusion::MAX_INPUT_LEN + 1));

        let interruption = tx.process_request_headers().unwrap();
        assert_eq!(interruption.rule_id, 633);
        assert_eq!(interruption.action, "deny");
        assert_eq!(interruption.status, 500);
        assert!(interruption.data.contains("inspection bound"));
        // Detection-only mode keeps the first would-be interruption from rule 630.
        let would_be = tx.would_be_interruption().unwrap();
        assert_eq!(would_be.rule_id, 630);
        assert!(tx.inspection_incomplete());
    }

    #[test]
    fn fail_closed_does_not_replace_an_existing_interruption() {
        let config = WafConfig {
            detector_inspection_action: DetectorInspectionAction::FailClosed,
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("detector-fail-closed-existing", Arc::new(config));
        tx.interrupt(7, "deny", 403, "original action data");
        tx.record_inspection_incomplete(9);

        let interruption = tx.interruption().unwrap();
        assert_eq!(interruption.rule_id, 7);
        assert_eq!(interruption.status, 403);
        assert_eq!(interruption.data, "original action data");
        assert!(tx.inspection_incomplete());
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("inspection_incomplete"))
                .as_deref(),
            Some("1")
        );
    }

    #[test]
    fn record_only_keeps_repeated_skipped_inputs_non_blocking() {
        let waf = detector_waf(
            "SecRule ARGS:q \"@detectSQLi\" \"id:634,phase:1,pass\"\n\
             SecRule ARGS:r \"@detectXSS\" \"id:635,phase:1,pass\"",
            DetectorInspectionAction::RecordOnly,
        );
        let mut tx = waf.new_transaction_with_id("detector-record-only-repeated");
        tx.add_get_argument("q", detector_input(b"1' OR '1'='1", libperfusion::MAX_INPUT_LEN + 1));
        tx.add_get_argument(
            "r",
            detector_input(b"<script>alert(1)</script>", libperfusion::MAX_INPUT_LEN + 1),
        );

        assert!(tx.process_request_headers().is_none());
        assert!(tx.inspection_incomplete());
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("inspection_incomplete"))
                .as_deref(),
            Some("1")
        );
        assert!(tx.matched_rules().is_empty());
    }

    #[test]
    fn inspection_signal_survives_a_rule_chain() {
        let waf = detector_waf(
            "SecRule ARGS:q \"@contains needle\" \"id:619,phase:1,pass,chain\"\n\
             SecRule ARGS:q \"@detectSQLi\" \"\"\n\
             SecRule TX:inspection_incomplete \"@streq 1\" \"id:620,phase:1,pass\"",
            DetectorInspectionAction::RecordOnly,
        );
        let mut tx = waf.new_transaction_with_id("detector-chain-signal");
        tx.add_get_argument(
            "q",
            detector_input(b"needle 1' OR '1'='1", libperfusion::MAX_INPUT_LEN + 1),
        );

        assert!(tx.process_request_headers().is_none());
        assert!(tx.inspection_incomplete());
        assert!(!tx.matched_rules().iter().any(|matched| matched.rule.id == 619));
        assert!(tx.matched_rules().iter().any(|matched| matched.rule.id == 620));
    }

    #[test]
    fn response_body_phase_runs_after_ingest_failure_in_detection_only() {
        for failure in [BufferFailure::Accept, BufferFailure::Replay] {
            for (engine, detection_only) in [("On", false), ("DetectionOnly", true)] {
                let mut parser = crate::seclang::Parser::new();
                parser
                    .from_string(&format!(
                        "SecRuleEngine {engine}\n\
                         SecResponseBodyAccess On\n\
                         SecResponseBodyMimeType text/plain\n\
                         SecAction \"id:152,phase:4,deny,status:403\""
                    ))
                    .unwrap();
                let waf = parser.into_waf().unwrap();
                let mut tx = waf.new_transaction_with_id(format!("res-ingest-{engine}-{failure:?}"));
                tx.process_request_headers();
                tx.process_request_body(b"");
                tx.add_response_header("Content-Type", "text/plain");
                tx.process_response_headers(200, "HTTP/1.1");
                inject_failure(failure);

                let interruption = tx.process_response_body(b"response");
                assert_eq!(
                    tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
                    Some("1")
                );
                let phase_ran = tx.matched_rules().iter().any(|matched| matched.rule.id == 152);
                if detection_only {
                    assert_eq!(interruption, None);
                    assert_eq!(tx.interruption(), None);
                    assert!(tx.would_be_interruption().is_some());
                    assert!(phase_ran);
                    assert_eq!(tx.last_phase(), Some(RulePhase::ResponseBody));
                } else {
                    assert_eq!(interruption.map(|value| value.status), Some(500));
                    assert!(!phase_ran);
                }
            }
        }
    }
}
