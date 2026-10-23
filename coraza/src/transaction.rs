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
//! phases. Callers must apply transport limits before passing a body.

mod ctl;
mod request_body;
mod response_body;
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "transaction tests use fixed valid inputs")]
mod tests;
mod variables;

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    ops::RangeInclusive,
    path::PathBuf,
    sync::Arc,
    time::SystemTime,
};

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
    config::WafConfig,
    operators::Macro,
    rules::{RuleGroup, VariableException},
    transformations::text_of,
    types::{AuditEngineStatus, AuditLogPart, AuditLogParts, RuleEngineStatus, RulePhase, RuleSeverity, RuleVariable},
    utils::time::UtcTime,
};

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
    /// Whether to process a body without a recognized content type.
    force_request_body_variable: bool,
    /// Processor chosen by the first content type or a `ctl` action.
    request_body_processor: Option<BodyProcessor>,
    /// Whether this transaction inspects response bodies.
    response_body_access: bool,
    /// Maximum response body size for this transaction, in bytes.
    response_body_limit: i64,
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
    args_path_indices: Vec<(String, usize)>,
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
        let map = |variable: RuleVariable| {
            if variable.has_case_sensitive_keys() {
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
        let mut unique_id = Single::new(RuleVariable::UniqueID);
        unique_id.set(id.into());

        Self {
            rule_engine: config.rule_engine,
            request_body_access: config.request_body_access,
            request_body_limit: config.request_body_limit,
            force_request_body_variable: false,
            request_body_processor: None,
            response_body_access: config.response_body_access,
            response_body_limit: config.response_body_limit,
            force_response_body_variable: false,
            response_body_processor: None,
            audit_engine: config.audit_engine,
            audit_log_parts: config.audit_log_parts.clone(),
            audit_logger: None,
            error_log: None,
            matched_rules: Vec::new(),
            started: SystemTime::now(),
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
            res_body_error: flag(RuleVariable::ResBodyError),
            res_body_error_msg: Single::new(RuleVariable::ResBodyErrorMsg),
            res_body_processor: Single::new(RuleVariable::ResBodyProcessor),
            res_body_processor_error: flag(RuleVariable::ResBodyProcessorError),
            res_body_processor_error_msg: Single::new(RuleVariable::ResBodyProcessorErrorMsg),
            highest_severity: {
                let mut value = Single::new(RuleVariable::HighestSeverity);
                value.set("255");
                value
            },
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

    /// Set the request line fields and populate query arguments from `uri`.
    pub fn process_uri(&mut self, uri: &str, method: &str, protocol: &str) {
        let uri = uri.split_once('#').map_or(uri, |(uri, _)| uri);
        self.set_request_uri(uri);
        self.set_request_method(method);
        self.set_request_protocol(protocol);
        if let Some((_, query)) = uri.split_once('?') {
            for (key, value) in parse_urlencoded(query.as_bytes()) {
                self.add_get_argument(&key, value);
            }
        }
    }

    /// Add a query argument to `ARGS_GET` and `ARGS`.
    pub fn add_get_argument(&mut self, key: &str, value: impl AsRef<[u8]>) {
        let value = value.as_ref();
        if self.within_argument_limit(self.args_get.value_count()) {
            self.args_get.add(key, value);
            self.args.add(key, value);
            self.update_args_combined_size(key, value);
        }
    }

    /// Add a request body argument to `ARGS_POST` and `ARGS`.
    pub fn add_post_argument(&mut self, key: &str, value: impl AsRef<[u8]>) {
        let value = value.as_ref();
        if self.within_argument_limit(self.args_post.value_count()) {
            self.args_post.add(key, value);
            self.args.add(key, value);
            self.update_args_combined_size(key, value);
        }
    }

    /// Add a connector-supplied path argument to `ARGS_PATH` and `ARGS`.
    pub fn add_path_argument(&mut self, key: &str, value: impl AsRef<[u8]>) {
        let value = value.as_ref();
        if self.within_argument_limit(self.args_path.value_count()) {
            let args_index = self.args.values(key).count();
            self.args_path.add(key, value);
            self.args.add(key, value);
            self.args_path_indices.push((key.to_owned(), args_index));
        }
    }

    /// Store a request header value as supplied by the connector.
    pub fn add_request_header(&mut self, key: &str, value: impl AsRef<[u8]>) {
        let value = value.as_ref();
        let first_content_type =
            key.eq_ignore_ascii_case("content-type") && self.request_headers.first("content-type").is_none();
        self.request_headers.add(key, value);
        if first_content_type && let Some(processor) = BodyProcessor::for_content_type(value) {
            self.set_request_body_processor(processor.name());
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

    /// Check the per-collection argument limit and set its flag when reached.
    fn within_argument_limit(&mut self, current_count: usize) -> bool {
        let within = current_count < self.config.argument_limit;
        if !within {
            self.arguments_limit_reached.set("1");
        }
        within
    }

    /// Add one GET or POST argument's byte lengths to the combined size.
    fn update_args_combined_size(&mut self, key: &str, value: &[u8]) {
        self.args_combined_size = self
            .args_combined_size
            .saturating_add(key.len())
            .saturating_add(value.len());
        self.args_combined_size_value.set(self.args_combined_size.to_string());
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
