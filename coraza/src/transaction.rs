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

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    io::Write as _,
    ops::RangeInclusive,
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use regex::RegexBuilder;

pub use crate::{actions::RuleMetadata, audit_log::MatchedRule};
use crate::{
    audit_log::{
        AuditFile, AuditLog, AuditLogger, AuditMessage, AuditMessageData, AuditProducer, AuditRequest, AuditResponse,
        AuditTransaction, ErrorLog, mime_type_of,
    },
    body_processors::{multipart, xml},
    collection::{Map, MatchData, Single},
    config::WafConfig,
    operators::{Macro, Outputs},
    rules::{CollectionView, RuleGroup, VariableException, VariableSpec},
    transformations::{text_of, url_decode},
    types::{
        AuditEngineStatus, AuditLogPart, AuditLogParts, BodyLimitAction, RuleEngineStatus, RulePhase, RuleSeverity,
        RuleVariable,
    },
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

/// The data behind one rule variable in a transaction.
///
/// `S` and `M` are references to [`Single`] and [`Map`], including mutable
/// references for internal updates.
#[derive(Debug)]
pub enum VariableCollection<S, M> {
    /// A single value, such as `REQUEST_URI`.
    Single(S),
    /// A key-value collection, such as `ARGS`.
    Map(M),
    /// The keys of a collection, exposed as both keys and values.
    Names(RuleVariable, M),
}

/// Maps supported rule variables to their transaction storage.
macro_rules! variable_storage {
    ($tx:expr, $variable:expr, $($borrow:tt)+) => {{
        use VariableCollection::{Map, Names, Single};

        match $variable {
            RuleVariable::Args => Some(Map($($borrow)+ $tx.args)),
            RuleVariable::ArgsGet => Some(Map($($borrow)+ $tx.args_get)),
            RuleVariable::ArgsPost => Some(Map($($borrow)+ $tx.args_post)),
            RuleVariable::ArgsPath => Some(Map($($borrow)+ $tx.args_path)),
            RuleVariable::RequestXML | RuleVariable::XML => Some(Map($($borrow)+ $tx.request_xml)),
            RuleVariable::RequestHeaders => Some(Map($($borrow)+ $tx.request_headers)),
            RuleVariable::RequestCookies => Some(Map($($borrow)+ $tx.request_cookies)),
            RuleVariable::ResponseHeaders => Some(Map($($borrow)+ $tx.response_headers)),
            RuleVariable::TX => Some(Map($($borrow)+ $tx.tx)),
            RuleVariable::ArgsNames => Some(Names(RuleVariable::ArgsNames, $($borrow)+ $tx.args)),
            RuleVariable::ArgsGetNames => {
                Some(Names(RuleVariable::ArgsGetNames, $($borrow)+ $tx.args_get))
            }
            RuleVariable::ArgsPostNames => {
                Some(Names(RuleVariable::ArgsPostNames, $($borrow)+ $tx.args_post))
            }
            RuleVariable::RequestHeadersNames => Some(Names(
                RuleVariable::RequestHeadersNames,
                $($borrow)+ $tx.request_headers,
            )),
            RuleVariable::RequestCookiesNames => Some(Names(
                RuleVariable::RequestCookiesNames,
                $($borrow)+ $tx.request_cookies,
            )),
            RuleVariable::ResponseHeadersNames => Some(Names(
                RuleVariable::ResponseHeadersNames,
                $($borrow)+ $tx.response_headers,
            )),
            RuleVariable::MatchedVars => Some(Map($($borrow)+ $tx.matched_vars)),
            RuleVariable::MatchedVarsNames => {
                Some(Names(RuleVariable::MatchedVarsNames, $($borrow)+ $tx.matched_vars))
            }
            RuleVariable::MatchedVar => Some(Single($($borrow)+ $tx.matched_var)),
            RuleVariable::MatchedVarName => Some(Single($($borrow)+ $tx.matched_var_name)),
            RuleVariable::InboundDataError => Some(Single($($borrow)+ $tx.inbound_data_error)),
            RuleVariable::FilesCombinedSize => Some(Single($($borrow)+ $tx.files_combined_size)),
            RuleVariable::Files => Some(Map($($borrow)+ $tx.files)),
            RuleVariable::FilesNames => Some(Map($($borrow)+ $tx.files_names)),
            RuleVariable::FilesSizes => Some(Map($($borrow)+ $tx.files_sizes)),
            RuleVariable::FilesTmpNames => Some(Map($($borrow)+ $tx.files_tmp_names)),
            RuleVariable::MultipartFilename => Some(Map($($borrow)+ $tx.multipart_filename)),
            RuleVariable::MultipartFilenameCharset => {
                Some(Map($($borrow)+ $tx.multipart_filename_charset))
            }
            RuleVariable::MultipartFilenameLanguage => {
                Some(Map($($borrow)+ $tx.multipart_filename_language))
            }
            RuleVariable::MultipartName => Some(Map($($borrow)+ $tx.multipart_name)),
            RuleVariable::MultipartPartHeaders => {
                Some(Map($($borrow)+ $tx.multipart_part_headers))
            }
            RuleVariable::MultipartStrictError => {
                Some(Single($($borrow)+ $tx.multipart_strict_error))
            }
            RuleVariable::MultipartDuplicatePartHeader => {
                Some(Single($($borrow)+ $tx.multipart_duplicate_part_header))
            }
            RuleVariable::MultipartInvalidQuoting => {
                Some(Single($($borrow)+ $tx.multipart_invalid_quoting))
            }
            RuleVariable::ReqbodyError => Some(Single($($borrow)+ $tx.reqbody_error)),
            RuleVariable::ReqbodyErrorMsg => Some(Single($($borrow)+ $tx.reqbody_error_msg)),
            RuleVariable::ReqbodyProcessor => Some(Single($($borrow)+ $tx.reqbody_processor)),
            RuleVariable::ReqbodyProcessorError => {
                Some(Single($($borrow)+ $tx.reqbody_processor_error))
            }
            RuleVariable::ReqbodyProcessorErrorMsg => {
                Some(Single($($borrow)+ $tx.reqbody_processor_error_msg))
            }
            RuleVariable::Rule => Some(Map($($borrow)+ $tx.rule)),
            RuleVariable::UniqueID => Some(Single($($borrow)+ $tx.unique_id)),
            RuleVariable::ArgsCombinedSize => Some(Single($($borrow)+ $tx.args_combined_size_value)),
            RuleVariable::ArgumentsLimitReached => {
                Some(Single($($borrow)+ $tx.arguments_limit_reached))
            }
            RuleVariable::RequestURI => Some(Single($($borrow)+ $tx.request_uri)),
            RuleVariable::RequestMethod => Some(Single($($borrow)+ $tx.request_method)),
            RuleVariable::RequestProtocol => Some(Single($($borrow)+ $tx.request_protocol)),
            RuleVariable::RequestBody => Some(Single($($borrow)+ $tx.request_body)),
            RuleVariable::RequestBodyLength => Some(Single($($borrow)+ $tx.request_body_length)),
            RuleVariable::ResponseBody => Some(Single($($borrow)+ $tx.response_body)),
            RuleVariable::ResponseContentLength => Some(Single($($borrow)+ $tx.response_content_length)),
            RuleVariable::RemoteAddr => Some(Single($($borrow)+ $tx.remote_addr)),
            RuleVariable::RemotePort => Some(Single($($borrow)+ $tx.remote_port)),
            RuleVariable::ServerAddr => Some(Single($($borrow)+ $tx.server_addr)),
            RuleVariable::ServerName => Some(Single($($borrow)+ $tx.server_name)),
            RuleVariable::ServerPort => Some(Single($($borrow)+ $tx.server_port)),
            RuleVariable::HighestSeverity => Some(Single($($borrow)+ $tx.highest_severity)),
            RuleVariable::ResponseStatus => Some(Single($($borrow)+ $tx.response_status)),
            RuleVariable::ResponseContentType => Some(Single($($borrow)+ $tx.response_content_type)),
            RuleVariable::ResponseProtocol => Some(Single($($borrow)+ $tx.response_protocol)),
            RuleVariable::OutboundDataError => Some(Single($($borrow)+ $tx.outbound_data_error)),
            RuleVariable::ResBodyError => Some(Single($($borrow)+ $tx.res_body_error)),
            RuleVariable::ResBodyErrorMsg => Some(Single($($borrow)+ $tx.res_body_error_msg)),
            RuleVariable::ResBodyProcessor => Some(Single($($borrow)+ $tx.res_body_processor)),
            RuleVariable::ResBodyProcessorError => Some(Single($($borrow)+ $tx.res_body_processor_error)),
            RuleVariable::ResBodyProcessorErrorMsg => {
                Some(Single($($borrow)+ $tx.res_body_processor_error_msg))
            }
            RuleVariable::ResponseArgs => Some(Map($($borrow)+ $tx.response_args)),
            RuleVariable::ResponseXML => Some(Map($($borrow)+ $tx.response_xml)),
            RuleVariable::Env => Some(Map($($borrow)+ $tx.env)),
            _ => None,
        }
    }};
}

#[derive(Clone, Copy)]
/// Body processor types used by request and response handling.
enum BodyProcessor {
    /// Preserve the body bytes without parsing arguments.
    Raw,
    /// Parse `application/x-www-form-urlencoded` arguments.
    UrlEncoded,
    /// Parse `multipart/form-data` fields and file uploads.
    Multipart,
    /// Parse JSON bodies into flattened POST arguments.
    Json,
    /// Parse XML bodies into `REQUEST_XML`.
    Xml,
}

impl BodyProcessor {
    /// Parse a processor name supported by this runtime slice.
    fn parse(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("RAW") {
            Some(Self::Raw)
        } else if name.eq_ignore_ascii_case("URLENCODED") {
            Some(Self::UrlEncoded)
        } else if name.eq_ignore_ascii_case("MULTIPART") {
            Some(Self::Multipart)
        } else if name.eq_ignore_ascii_case("JSON") {
            Some(Self::Json)
        } else if name.eq_ignore_ascii_case("XML") {
            Some(Self::Xml)
        } else {
            None
        }
    }

    /// Detect a body processor from a content type, if present.
    fn for_content_type(content_type: &[u8]) -> Option<Self> {
        let content_type = std::str::from_utf8(content_type).ok()?.trim();
        let media_type = content_type.split(';').next()?.trim();
        if media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
            Some(Self::UrlEncoded)
        } else if media_type.eq_ignore_ascii_case("multipart/form-data") {
            Some(Self::Multipart)
        } else {
            None
        }
    }

    /// Return the canonical processor name.
    const fn name(self) -> &'static str {
        match self {
            Self::Raw => "RAW",
            Self::UrlEncoded => "URLENCODED",
            Self::Multipart => "MULTIPART",
            Self::Json => "JSON",
            Self::Xml => "XML",
        }
    }
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

    /// Evaluate request-header rules once using the values already stored on this
    /// transaction. Returns the disruptive interruption, if any.
    pub fn process_request_headers(&mut self) -> Option<Interruption> {
        if self.begin_phase(RulePhase::RequestHeaders) {
            self.run_phase(RulePhase::RequestHeaders);
        }
        self.interruption.clone()
    }

    /// Process a request body and evaluate phase 2 rules.
    ///
    /// Call this once after [`Transaction::process_request_headers`], including for an
    /// empty body. The first `Content-Type` header selects URLENCODED or MULTIPART;
    /// `ctl:requestBodyProcessor` selects RAW, JSON, or XML. Phase 2 rules still run when
    /// body access is disabled or no processor is selected.
    pub fn process_request_body(&mut self, body: &[u8]) -> Option<Interruption> {
        if !self.begin_phase(RulePhase::RequestBody) {
            return self.interruption.clone();
        }

        if self.audit_engine != AuditEngineStatus::Off && self.audit_log_parts.contains(&AuditLogPart::RequestBody) {
            let limit = usize::try_from(self.request_body_limit).unwrap_or(0);
            self.audit_request_body.clear();
            self.audit_request_body
                .extend_from_slice(body.get(..body.len().min(limit)).unwrap_or_default());
        }

        if self.request_body_access && !body.is_empty() {
            if self.force_request_body_variable && self.reqbody_processor.get_bytes().is_empty() {
                self.set_request_body_processor("URLENCODED");
            }

            let limit = usize::try_from(self.request_body_limit).unwrap_or(0);
            let mut body = body;
            if body.len() >= limit {
                self.inbound_data_error.set("1");
                if self.config.request_body_limit_action == BodyLimitAction::Reject {
                    self.interrupt(0, "deny", 413, "");
                    if self.interruption.is_some() {
                        return self.interruption.clone();
                    }
                }
                body = body.get(..limit).unwrap_or_default();
            }

            self.inspect_request_body(body);
        }

        self.run_phase(RulePhase::RequestBody);
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

    /// Store and parse the body with the selected processor.
    fn inspect_request_body(&mut self, body: &[u8]) {
        let Some(processor) = self.request_body_processor else {
            return;
        };

        match processor {
            BodyProcessor::Raw => {
                self.request_body.set(body);
                self.request_body_length.set(body.len().to_string());
            },
            BodyProcessor::UrlEncoded => {
                self.request_body.set(body);
                self.request_body_length.set(body.len().to_string());
                for (key, value) in parse_urlencoded(body) {
                    self.add_post_argument(&key, value);
                }
            },
            BodyProcessor::Multipart => {
                if let Err(message) = self.process_multipart_body(body) {
                    self.reqbody_error.set("1");
                    self.reqbody_error_msg.set(format!("MULTIPART: {message}"));
                    self.reqbody_processor_error.set("1");
                    self.reqbody_processor_error_msg.set(message);
                }
            },
            BodyProcessor::Json => {
                let depth_limit = self.config.request_body_json_depth_limit;
                match parse_json(body, depth_limit) {
                    Ok(value) => flatten_json_value(&value, &mut String::from("json"), self, false),
                    Err(message) => {
                        self.reqbody_error.set("1");
                        self.reqbody_error_msg.set(format!("JSON: {message}"));
                        self.reqbody_processor_error.set("1");
                        self.reqbody_processor_error_msg.set(message);
                    },
                }
            },
            BodyProcessor::Xml => match xml::parse(body) {
                Ok(document) => {
                    for value in document.attribute_values {
                        self.request_xml.add("//@*", value);
                    }
                    for value in document.text {
                        self.request_xml.add("/*", value);
                    }
                },
                Err(message) => {
                    let error = format!("malformed xml: {message}");
                    self.reqbody_error.set("1");
                    self.reqbody_error_msg.set(format!("XML: {error}"));
                    self.reqbody_processor_error.set("1");
                    self.reqbody_processor_error_msg.set(error);
                },
            },
        }
    }

    /// Populate multipart fields, metadata, and temporary upload files.
    fn process_multipart_body(&mut self, body: &[u8]) -> Result<(), String> {
        let content_type = self
            .request_headers
            .first("content-type")
            .map(|value| text_of(value).into_owned())
            .unwrap_or_default();
        let parts = multipart::parse(&content_type, body).inspect_err(|_| self.multipart_strict_error.set("1"))?;
        let upload_dir = if self.config.upload_dir.is_empty() {
            std::env::temp_dir()
        } else {
            PathBuf::from(&self.config.upload_dir)
        };
        let mut total_size = 0_u64;

        for part in parts {
            if part.repeats_header {
                self.multipart_duplicate_part_header.set("1");
                self.multipart_strict_error.set("1");
            }
            if part.invalid_quoting {
                self.multipart_invalid_quoting.set("1");
                self.multipart_strict_error.set("1");
            }

            for (name, value) in &part.headers {
                self.multipart_part_headers
                    .add(&part.name, format!("{}: {value}", canonical_header_name(name)));
            }
            self.multipart_name.add(&part.name, &part.name);
            if let Some(filename) = &part.filename {
                self.multipart_filename.add(&part.name, filename);
            }
            if let Some(filename) = &part.alt_filename {
                self.multipart_filename.add(&part.name, filename);
            }
            if let Some(encoding) = &part.filename_encoding {
                self.multipart_filename_charset.add(&part.name, &encoding.charset);
                self.multipart_filename_language.add(&part.name, &encoding.language);
            }
            if part.malformed_filename {
                self.multipart_strict_error.set("1");
            }

            let size = u64::try_from(part.data.len()).map_err(|error| format!("multipart size overflow: {error}"))?;
            total_size = total_size
                .checked_add(size)
                .ok_or_else(|| "multipart size overflow".to_owned())?;

            if let Some(filename) = &part.filename {
                if self.uploaded_paths.len() >= self.config.upload_file_limit {
                    self.multipart_strict_error.set("1");
                    continue;
                }
                let path =
                    save_to_temp(&upload_dir, part.data).inspect_err(|_| self.multipart_strict_error.set("1"))?;
                self.files_tmp_names.add("", path.to_string_lossy().as_bytes());
                self.uploaded_paths.push(path);
                self.files.add("", filename);
                self.files_sizes.set_index(filename, 0, size.to_string());
                if let Some(alt_filename) = &part.alt_filename {
                    self.files.add("", alt_filename);
                    self.files_sizes.set_index(alt_filename, 0, size.to_string());
                }
                self.files_names.add("", &part.name);
            } else {
                self.add_post_argument(&part.name, part.data);
            }
        }

        self.files_combined_size.set(total_size.to_string());
        Ok(())
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

    /// Whether the response body matches the configured MIME types or is forced on.
    pub fn is_response_body_processable(&self) -> bool {
        self.force_response_body_variable
            || self
                .config
                .response_body_mime_types
                .iter()
                .any(|mime| mime.eq_ignore_ascii_case(&self.response_content_type.get()))
    }

    /// Process an eligible response body and evaluate response-body rules.
    pub fn process_response_body(&mut self, body: &[u8]) -> Option<Interruption> {
        if !self.begin_phase(RulePhase::ResponseBody) {
            return self.interruption.clone();
        }

        if self.audit_engine != AuditEngineStatus::Off
            && (self.audit_log_parts.contains(&AuditLogPart::IntermediaryResponseBody)
                || self.audit_log_parts.contains(&AuditLogPart::ResponseBody))
        {
            let limit = usize::try_from(self.response_body_limit).unwrap_or(0);
            self.audit_response_body.clear();
            self.audit_response_body
                .extend_from_slice(body.get(..body.len().min(limit)).unwrap_or_default());
        }

        if self.response_body_access && self.is_response_body_processable() {
            self.response_content_length.set(body.len().to_string());
            if !body.is_empty() {
                let limit = usize::try_from(self.response_body_limit).unwrap_or(0);
                let mut body = body;
                if body.len() > limit {
                    self.outbound_data_error.set("1");
                    if self.config.response_body_limit_action == BodyLimitAction::Reject {
                        self.interrupt(0, "deny", 500, "");
                        if self.interruption.is_some() {
                            return self.interruption.clone();
                        }
                    }
                    body = body.get(..limit).unwrap_or_default();
                }
                self.inspect_response_body(body);
            }
        }

        self.run_phase(RulePhase::ResponseBody);
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

    /// Parse or store response body data before phase 4 rules run.
    fn inspect_response_body(&mut self, body: &[u8]) {
        self.response_body.set(body);
        if let Some(BodyProcessor::Json) = self.response_body_processor {
            match parse_json(body, self.config.response_body_json_depth_limit) {
                Ok(value) => flatten_json_value(&value, &mut String::from("json"), self, true),
                Err(message) => {
                    self.res_body_error.set("1");
                    self.res_body_error_msg.set(format!("JSON: malformed json: {message}"));
                    self.res_body_processor_error.set("1");
                    self.res_body_processor_error_msg.set(message);
                },
            }
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

    /// Apply transaction-scoped `ctl` settings supported by this runtime slice.
    pub(crate) fn apply_ctl(&mut self, expression: &str) {
        let Some((name, value)) = expression.split_once('=') else {
            return;
        };
        match name {
            "auditEngine" => {
                if let Ok(audit_engine) = value.parse::<AuditEngineStatus>() {
                    self.audit_engine = audit_engine;
                }
            },
            "auditLogParts" => {
                if let Ok(parts) = crate::types::apply_audit_log_parts(&self.audit_log_parts, value) {
                    self.audit_log_parts = parts;
                }
            },
            "ruleEngine" => {
                if let Ok(rule_engine) = value.parse::<RuleEngineStatus>() {
                    self.rule_engine = rule_engine;
                }
            },
            "requestBodyAccess" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::RequestBody) {
                    self.request_body_access = value.eq_ignore_ascii_case("on");
                }
            },
            "requestBodyLimit" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::RequestBody)
                    && let Ok(limit) = value.parse::<i64>()
                    && limit >= 0
                {
                    self.request_body_limit = limit;
                }
            },
            "forceRequestBodyVariable" => {
                self.force_request_body_variable = value.eq_ignore_ascii_case("on");
            },
            "requestBodyProcessor" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::RequestBody) {
                    self.set_request_body_processor(value);
                }
            },
            "responseBodyAccess" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::ResponseBody) {
                    self.response_body_access = value.eq_ignore_ascii_case("on");
                }
            },
            "responseBodyLimit" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::ResponseBody)
                    && let Ok(limit) = value.parse::<i64>()
                    && limit >= 0
                {
                    self.response_body_limit = limit;
                }
            },
            "forceResponseBodyVariable" => {
                self.force_response_body_variable = value.eq_ignore_ascii_case("on");
            },
            "responseBodyProcessor" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::ResponseBody) {
                    self.set_response_body_processor(value);
                }
            },
            "ruleRemoveById" => {
                if let Some(ids) = parse_id_range(value) {
                    if ids.start() == ids.end() {
                        self.removed_rule_ids.insert(*ids.start());
                    } else if !self.removed_rule_id_ranges.contains(&ids) {
                        self.removed_rule_id_ranges.push(ids);
                    }
                }
            },
            "ruleRemoveByTag" => {
                if self.applied_rule_removals.insert(expression.to_owned()) {
                    let ids = self
                        .rules
                        .iter()
                        .filter(|rule| rule.metadata().tags.iter().any(|tag| tag == value))
                        .map(|rule| rule.metadata().id)
                        .collect::<Vec<_>>();
                    self.removed_rule_ids.extend(ids);
                }
            },
            "ruleRemoveByMsg" => {
                if self.applied_rule_removals.insert(expression.to_owned()) {
                    let ids = self
                        .rules
                        .iter()
                        .filter(|rule| rule.metadata().msg.as_ref().is_some_and(|msg| msg.as_str() == value))
                        .map(|rule| rule.metadata().id)
                        .collect::<Vec<_>>();
                    self.removed_rule_ids.extend(ids);
                }
            },
            "ruleRemoveTargetById" | "ruleRemoveTargetByTag" | "ruleRemoveTargetByMsg" => {
                self.apply_rule_target_removal(name, value, expression);
            },
            _ => {},
        }
    }

    /// Select rules and targets for the `ctl:ruleRemoveTarget*` commands.
    fn apply_rule_target_removal(&mut self, command: &str, value: &str, expression: &str) {
        if !self.applied_rule_removals.insert(expression.to_owned()) {
            return;
        }
        let Some((selector, target)) = value.split_once(';') else {
            return;
        };
        let (variable, key) = target.split_once(':').unwrap_or((target, ""));
        let Ok(variable) = variable.trim().parse::<RuleVariable>() else {
            return;
        };
        let key = key.trim();
        let exception = match key.strip_prefix('/').and_then(|key| key.strip_suffix('/')) {
            Some(pattern) if !pattern.is_empty() => {
                let Ok(regex) = RegexBuilder::new(pattern).case_insensitive(true).build() else {
                    return;
                };
                VariableException::new_regex(regex)
            },
            Some(_) => return,
            None => VariableException::new_string(key),
        };
        let ids = match command {
            "ruleRemoveTargetById" => parse_id_range(selector)
                .map(|range| {
                    self.rules
                        .iter()
                        .filter(|rule| range.contains(&rule.metadata().id))
                        .map(|rule| rule.metadata().id)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            "ruleRemoveTargetByTag" => self
                .rules
                .iter()
                .filter(|rule| rule.metadata().tags.iter().any(|tag| tag == selector))
                .map(|rule| rule.metadata().id)
                .collect(),
            "ruleRemoveTargetByMsg" => self
                .rules
                .iter()
                .filter(|rule| rule.metadata().msg.as_ref().is_some_and(|msg| msg.as_str() == selector))
                .map(|rule| rule.metadata().id)
                .collect(),
            _ => Vec::new(),
        };
        for id in ids {
            let targets = self.removed_rule_targets.entry(id).or_default();
            let target = (variable, exception.clone());
            if !targets.contains(&target) {
                targets.push(target);
            }
        }
    }

    /// Select a response body processor for phase 4.
    fn set_response_body_processor(&mut self, name: &str) {
        self.response_body_processor = BodyProcessor::parse(name);
        self.res_body_processor.set(name.to_ascii_uppercase());
    }

    /// Whether `ctl` excluded a rule for this transaction.
    fn is_rule_removed(&self, id: i32) -> bool {
        self.removed_rule_ids.contains(&id) || self.removed_rule_id_ranges.iter().any(|range| range.contains(&id))
    }

    /// Whether `ctl` excluded this variable key from a rule for this transaction.
    fn is_rule_target_removed(&self, id: i32, variable: RuleVariable, key: &str) -> bool {
        self.removed_rule_targets.get(&id).is_some_and(|targets| {
            targets
                .iter()
                .any(|(removed_variable, exception)| *removed_variable == variable && exception.matches_key(key))
        })
    }

    /// Select a request body processor, retaining its name even when this slice does not
    /// implement that processor.
    fn set_request_body_processor(&mut self, name: &str) {
        self.request_body_processor = BodyProcessor::parse(name);
        self.reqbody_processor.set(name.to_ascii_uppercase());
    }

    /// The collection a rule variable reads, or `None` when this storage layer
    /// does not populate it.
    pub fn collection(&self, variable: RuleVariable) -> Option<VariableCollection<&Single, &Map>> {
        variable_storage!(self, variable, &)
    }

    /// The mutable storage for a rule variable.
    fn collection_mut(&mut self, variable: RuleVariable) -> Option<VariableCollection<&mut Single, &mut Map>> {
        variable_storage!(self, variable, &mut)
    }

    /// The value of a single-value variable or the first value under `key`.
    ///
    /// Values with invalid UTF-8 are converted lossily. Rule matching uses the original
    /// bytes.
    pub fn get_variable(&self, variable: RuleVariable, key: Option<&str>) -> Option<String> {
        match (self.collection(variable)?, key) {
            (VariableCollection::Single(single), None) => Some(single.get().into_owned()),
            (VariableCollection::Map(map), Some(key)) => map.first(key).map(text_of).map(Cow::into_owned),
            (VariableCollection::Names(_, map), Some(key)) => {
                map.iter_key(key).next().map(|(stored_key, _)| stored_key.to_owned())
            },
            _ => None,
        }
    }

    /// Find the byte-preserving matches selected by a parsed variable spec.
    pub(crate) fn find_matches(&self, spec: &VariableSpec) -> Vec<MatchData> {
        let collection = self.collection(spec.variable()).map(|collection| match collection {
            VariableCollection::Single(single) => CollectionView::Single(single),
            VariableCollection::Map(map) => CollectionView::Map(map),
            VariableCollection::Names(variable, map) => CollectionView::Names(variable, map),
        });
        spec.get_matches(collection)
    }

    /// Find the values selected by a rule after applying transaction-local target removals.
    pub(crate) fn find_matches_for_rule(&self, spec: &VariableSpec, id: i32) -> Vec<MatchData> {
        if !self.removed_rule_targets.contains_key(&id) {
            return self.find_matches(spec);
        }
        let mut matches = self.find_matches(spec);
        matches.retain(|matched| !self.is_rule_target_removed(id, matched.variable, &matched.key));
        matches
    }

    /// Set one stored single-value variable.
    fn set_single(&mut self, variable: RuleVariable, value: impl AsRef<[u8]>) {
        if let Some(VariableCollection::Single(single)) = self.collection_mut(variable) {
            single.set(value);
        }
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

    /// Add a parsed response body argument to `RESPONSE_ARGS`.
    fn add_response_argument(&mut self, key: &str, value: impl AsRef<[u8]>) {
        let value = value.as_ref();
        if self.within_argument_limit(self.response_args.value_count()) {
            self.response_args.add(key, value);
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

    /// Store captures and path arguments produced by an operator.
    pub(crate) fn store_operator_outputs(&mut self, outputs: &mut Outputs) {
        {
            let mut captures = outputs.take_captures();
            if let Some((index, value)) = captures.next() {
                for index in 0..10 {
                    self.tx.remove(&index.to_string());
                }
                self.set_tx_variable(&index.to_string(), value);
                for (index, value) in captures {
                    self.set_tx_variable(&index.to_string(), value);
                }
            }
        }
        for (key, value) in outputs.take_path_arguments() {
            self.set_path_argument(&key, value.as_bytes());
        }
    }

    /// Replace the first stored path argument and its corresponding ARGS value.
    fn set_path_argument(&mut self, key: &str, value: impl AsRef<[u8]>) {
        let args_index = self
            .args_path_indices
            .iter()
            .find(|(path_key, _)| path_key == key)
            .map(|(_, index)| *index);
        let Some(args_index) = args_index else {
            self.add_path_argument(key, value);
            return;
        };
        self.args_path.set_index(key, 0, value.as_ref());
        self.args.set_index(key, args_index, value);
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

    /// Replace the value of a transaction variable.
    pub fn set_tx_variable(&mut self, key: &str, value: impl AsRef<[u8]>) {
        self.tx.set(key, [value]);
    }

    /// Clear captures and matched values from the rule evaluated previously.
    fn reset_matched_vars(&mut self) {
        self.matched_vars.reset();
        for index in 0..10 {
            self.tx.remove(&index.to_string());
        }
    }

    /// Record the value and variable name matched by an operator.
    pub(crate) fn record_matched_variable(&mut self, matched: &MatchData) {
        let name = if matched.key.is_empty() {
            matched.variable.name().to_owned()
        } else {
            format!("{}:{}", matched.variable.name(), matched.key)
        };
        self.matched_vars.add(&name, &matched.value);
        self.matched_var.set(&matched.value);
        self.matched_var_name.set(name);
    }

    /// Update `RULE` values before evaluating a compiled rule.
    #[expect(clippy::too_many_arguments, reason = "fields mirror the RULE collection")]
    pub(crate) fn set_rule_variables(
        &mut self,
        id: i32,
        message: Option<String>,
        revision: &str,
        log_data: Option<String>,
        severity: &str,
    ) {
        self.rule.set_index("id", 0, id.to_string());
        if let Some(message) = message {
            self.rule.set_index("msg", 0, message);
        }
        self.rule.set_index("rev", 0, revision);
        if let Some(log_data) = log_data {
            self.rule.set_index("logdata", 0, log_data);
        }
        self.rule.set_index("severity", 0, severity);
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

/// Store an upload in a new private temporary file and return its path.
fn save_to_temp(upload_dir: &Path, data: &[u8]) -> Result<PathBuf, String> {
    let mut file = tempfile::Builder::new()
        .prefix("crzmp")
        .tempfile_in(upload_dir)
        .map_err(|error| format!("I/O error: {error}"))?;
    file.write_all(data).map_err(|error| format!("I/O error: {error}"))?;
    let (_, path) = file.keep().map_err(|error| format!("I/O error: {}", error.error))?;
    Ok(path)
}

/// Parse a single rule ID or an inclusive rule ID range.
fn parse_id_range(value: &str) -> Option<RangeInclusive<i32>> {
    let (start, end) = value.split_once('-').unwrap_or((value, value));
    let start = start.parse::<i32>().ok()?;
    let end = end.parse::<i32>().ok()?;
    let range = start..=end;
    (!range.is_empty()).then_some(range)
}

/// Format a valid MIME header name as Go's canonical header key.
fn canonical_header_name(name: &str) -> String {
    let is_token = |character: char| character.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(character);
    if !name.chars().all(is_token) {
        return name.to_owned();
    }
    let mut starts_word = true;
    name.chars()
        .map(|character| {
            let character = if starts_word {
                character.to_ascii_uppercase()
            } else {
                character.to_ascii_lowercase()
            };
            starts_word = character == '-';
            character
        })
        .collect()
}

/// Parses URLENCODED pairs in order, preserving decoded value bytes.
fn parse_urlencoded(body: &[u8]) -> impl Iterator<Item = (String, Vec<u8>)> + '_ {
    body.split(|&byte| byte == b'&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = match pair.iter().position(|&byte| byte == b'=') {
                Some(equals) => (
                    pair.get(..equals).unwrap_or_default(),
                    pair.get(equals.saturating_add(1)..).unwrap_or_default(),
                ),
                None => (pair, &b""[..]),
            };
            let key = text_of(&url_decode(key).0).into_owned();
            let value = url_decode(value).0;
            (key, value)
        })
}

/// Parse JSON and enforce the configured nesting limit.
fn parse_json(body: &[u8], depth_limit: usize) -> Result<serde_json::Value, String> {
    let body = String::from_utf8_lossy(body);
    // shortcut: serde_json caps nesting at 128; replace it if configured limits above 128 must work.
    let value = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    if json_depth(&value) > depth_limit {
        return Err(format!("nesting deeper than the limit of {depth_limit}"));
    }
    Ok(value)
}

/// Return the deepest object or array nesting, with scalars at depth zero.
fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Flatten JSON values into the dot-separated `ARGS_POST` names used by Coraza.
fn flatten_json_value(value: &serde_json::Value, key: &mut String, tx: &mut Transaction, response: bool) {
    match value {
        serde_json::Value::Object(values) => {
            for (name, value) in values {
                let previous_len = key.len();
                key.push('.');
                key.push_str(name);
                flatten_json_value(value, key, tx, response);
                key.truncate(previous_len);
            }
        },
        serde_json::Value::Array(values) => {
            if !values.is_empty() {
                let length = values.len().to_string();
                if response {
                    tx.add_response_argument(key, length.as_bytes());
                } else {
                    tx.add_post_argument(key, length.as_bytes());
                }
                for (index, value) in values.iter().enumerate() {
                    let previous_len = key.len();
                    key.push('.');
                    key.push_str(&index.to_string());
                    flatten_json_value(value, key, tx, response);
                    key.truncate(previous_len);
                }
            }
        },
        serde_json::Value::String(value) => {
            if response {
                tx.add_response_argument(key, value.as_bytes());
            } else {
                tx.add_post_argument(key, value.as_bytes());
            }
        },
        serde_json::Value::Number(value) => {
            let value = value.to_string();
            if response {
                tx.add_response_argument(key, value.as_bytes());
            } else {
                tx.add_post_argument(key, value.as_bytes());
            }
        },
        serde_json::Value::Bool(value) => {
            let value = value.to_string();
            if response {
                tx.add_response_argument(key, value.as_bytes());
            } else {
                tx.add_post_argument(key, value.as_bytes());
            }
        },
        serde_json::Value::Null => {
            if response {
                tx.add_response_argument(key, b"");
            } else {
                tx.add_post_argument(key, b"");
            }
        },
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "transaction tests use fixed valid inputs")]
mod tests {
    use std::sync::Arc;

    use super::{Transaction, VariableCollection};
    use crate::{
        config::WafConfig,
        operators::Outputs,
        rules::VariableSpec,
        types::{BodyLimitAction, RuleEngineStatus, RulePhase, RuleVariable},
    };

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
                "JSON: nesting deeper than the limit of 1",
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
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseBody, None).as_deref(),
            Some(r#"{"admin":true}"#)
        );
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
    fn response_body_equal_to_limit_is_not_rejected() {
        let config = WafConfig {
            response_body_access: true,
            response_body_limit: 3,
            response_body_limit_action: BodyLimitAction::Reject,
            response_body_mime_types: vec!["text/plain".to_owned()],
            ..WafConfig::default()
        };
        let mut tx = Transaction::with_config("response-limit-equal", Arc::new(config));
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");

        assert_eq!(tx.process_response_body(b"abc"), None);
        assert_eq!(
            tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
            Some("0")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseBody, None).as_deref(),
            Some("abc")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseContentLength, None).as_deref(),
            Some("3")
        );
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
        assert!(
            tx.get_variable(RuleVariable::ResBodyErrorMsg, None)
                .is_some_and(|message| message.starts_with("JSON: malformed json:"))
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
            audit_engine: crate::types::AuditEngineStatus::On,
            audit_log: path.to_string_lossy().into_owned(),
            audit_log_format: crate::types::AuditLogFormat::Json,
            audit_log_parts: crate::types::parse_audit_log_parts("ABCFGHKZ").unwrap(),
            request_body_access: true,
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
            audit_engine: crate::types::AuditEngineStatus::RelevantOnly,
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
}
