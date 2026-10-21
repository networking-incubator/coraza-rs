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
//! This module stores values supplied by a connector and evaluates request-header and
//! request-body rules. Callers must apply transport limits before passing a body.

use std::{
    borrow::Cow,
    io::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    body_processors::{multipart, xml},
    collection::{Map, MatchData, Single},
    config::WafConfig,
    operators::{Macro, Outputs},
    rules::{CollectionView, RuleGroup, VariableSpec},
    transformations::{text_of, url_decode},
    types::{BodyLimitAction, RuleEngineStatus, RulePhase, RuleVariable},
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
            RuleVariable::RemoteAddr => Some(Single($($borrow)+ $tx.remote_addr)),
            RuleVariable::ServerName => Some(Single($($borrow)+ $tx.server_name)),
            RuleVariable::ResponseStatus => Some(Single($($borrow)+ $tx.response_status)),
            _ => None,
        }
    }};
}

#[derive(Clone, Copy)]
/// Request body processors implemented by this runtime slice.
enum RequestBodyProcessor {
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

impl RequestBodyProcessor {
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

/// A transaction's input collections, rule state, and request-phase evaluation.
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
    request_body_processor: Option<RequestBodyProcessor>,
    /// The last phase evaluated.
    last_phase: Option<RulePhase>,
    /// A disruptive action applied while the engine is on.
    interruption: Option<Interruption>,
    /// The first disruptive action that would apply in detection-only mode.
    would_be_interruption: Option<Interruption>,
    /// Number of following same-phase rules to skip.
    skip: i32,
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
    /// The server name supplied by the connector.
    server_name: Single,
    /// The response status supplied by the connector.
    response_status: Single,
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
            config,
            rules,
            last_phase: None,
            interruption: None,
            would_be_interruption: None,
            skip: 0,
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
            matched_var: Single::new(RuleVariable::MatchedVar),
            matched_var_name: Single::new(RuleVariable::MatchedVarName),
            matched_vars: map(RuleVariable::MatchedVars),
            rule: map(RuleVariable::Rule),
            request_uri: Single::new(RuleVariable::RequestURI),
            request_method: Single::new(RuleVariable::RequestMethod),
            request_protocol: Single::new(RuleVariable::RequestProtocol),
            remote_addr: Single::new(RuleVariable::RemoteAddr),
            server_name: Single::new(RuleVariable::ServerName),
            response_status: Single::new(RuleVariable::ResponseStatus),
            request_body: Single::new(RuleVariable::RequestBody),
            request_body_length: flag(RuleVariable::RequestBodyLength),
            inbound_data_error: flag(RuleVariable::InboundDataError),
            reqbody_error: flag(RuleVariable::ReqbodyError),
            reqbody_error_msg: Single::new(RuleVariable::ReqbodyErrorMsg),
            reqbody_processor: Single::new(RuleVariable::ReqbodyProcessor),
            reqbody_processor_error: flag(RuleVariable::ReqbodyProcessorError),
            reqbody_processor_error_msg: Single::new(RuleVariable::ReqbodyProcessorErrorMsg),
        }
    }

    /// The transaction ID as text.
    pub fn id(&self) -> Cow<'_, str> {
        self.unique_id.get()
    }

    /// Return the rule-engine mode currently applied to this transaction.
    pub fn rule_engine(&self) -> RuleEngineStatus {
        self.rule_engine
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
            RequestBodyProcessor::Raw => {
                self.request_body.set(body);
                self.request_body_length.set(body.len().to_string());
            },
            RequestBodyProcessor::UrlEncoded => {
                self.request_body.set(body);
                self.request_body_length.set(body.len().to_string());
                for (key, value) in parse_urlencoded(body) {
                    self.add_post_argument(&key, value);
                }
            },
            RequestBodyProcessor::Multipart => {
                if let Err(message) = self.process_multipart_body(body) {
                    self.reqbody_error.set("1");
                    self.reqbody_error_msg.set(format!("MULTIPART: {message}"));
                    self.reqbody_processor_error.set("1");
                    self.reqbody_processor_error_msg.set(message);
                }
            },
            RequestBodyProcessor::Json => {
                let depth_limit = self.config.request_body_json_depth_limit;
                match parse_json(body, depth_limit) {
                    Ok(value) => flatten_json_value(&value, &mut String::from("json"), self),
                    Err(message) => {
                        self.reqbody_error.set("1");
                        self.reqbody_error_msg.set(format!("JSON: {message}"));
                        self.reqbody_processor_error.set("1");
                        self.reqbody_processor_error_msg.set(message);
                    },
                }
            },
            RequestBodyProcessor::Xml => match xml::parse(body) {
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

    /// Evaluate rules assigned to `phase` in directive order.
    fn run_phase(&mut self, phase: RulePhase) {
        let rules = Arc::clone(&self.rules);

        for rule in rules.iter() {
            if self.interruption.is_some() || self.is_allowed(phase) {
                break;
            }
            if rule.metadata().phase != RulePhase::Unknown && rule.metadata().phase != phase {
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

    /// Apply transaction-scoped `ctl` settings supported by this runtime slice.
    pub(crate) fn apply_ctl(&mut self, expression: &str) {
        let Some((name, value)) = expression.split_once('=') else {
            return;
        };
        match name {
            "ruleEngine" => {
                if let Ok(rule_engine) = value.parse::<RuleEngineStatus>() {
                    self.rule_engine = rule_engine;
                }
            },
            "requestBodyAccess" => self.request_body_access = value.eq_ignore_ascii_case("on"),
            "requestBodyLimit" => {
                if let Ok(limit) = value.parse::<i64>() {
                    self.request_body_limit = limit;
                }
            },
            "forceRequestBodyVariable" => {
                self.force_request_body_variable = value.eq_ignore_ascii_case("on");
            },
            "requestBodyProcessor" => self.set_request_body_processor(value),
            _ => {},
        }
    }

    /// Select a request body processor, retaining its name even when this slice does not
    /// implement that processor.
    fn set_request_body_processor(&mut self, name: &str) {
        self.request_body_processor = RequestBodyProcessor::parse(name);
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

    /// Set the server name supplied by the connector.
    pub fn set_server_name(&mut self, value: impl AsRef<[u8]>) {
        self.set_single(RuleVariable::ServerName, value);
    }

    /// Set the response status supplied by the connector.
    pub fn set_response_status(&mut self, status: u16) {
        self.set_single(RuleVariable::ResponseStatus, status.to_string());
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
        if first_content_type && let Some(processor) = RequestBodyProcessor::for_content_type(value) {
            self.set_request_body_processor(processor.name());
        }
    }

    /// Store a request cookie supplied by a connector that already parsed cookies.
    pub fn add_request_cookie(&mut self, key: &str, value: impl AsRef<[u8]>) {
        self.request_cookies.add(key, value);
    }

    /// Store a response header value as supplied by the connector.
    pub fn add_response_header(&mut self, key: &str, value: impl AsRef<[u8]>) {
        self.response_headers.add(key, value);
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
fn flatten_json_value(value: &serde_json::Value, key: &mut String, tx: &mut Transaction) {
    match value {
        serde_json::Value::Object(values) => {
            for (name, value) in values {
                let previous_len = key.len();
                key.push('.');
                key.push_str(name);
                flatten_json_value(value, key, tx);
                key.truncate(previous_len);
            }
        },
        serde_json::Value::Array(values) => {
            if !values.is_empty() {
                let length = values.len().to_string();
                tx.add_post_argument(key, length.as_bytes());
                for (index, value) in values.iter().enumerate() {
                    let previous_len = key.len();
                    key.push('.');
                    key.push_str(&index.to_string());
                    flatten_json_value(value, key, tx);
                    key.truncate(previous_len);
                }
            }
        },
        serde_json::Value::String(value) => tx.add_post_argument(key, value.as_bytes()),
        serde_json::Value::Number(value) => {
            let value = value.to_string();
            tx.add_post_argument(key, value.as_bytes());
        },
        serde_json::Value::Bool(value) => {
            let value = value.to_string();
            tx.add_post_argument(key, value.as_bytes());
        },
        serde_json::Value::Null => tx.add_post_argument(key, b""),
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
        types::{RulePhase, RuleVariable},
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
}
