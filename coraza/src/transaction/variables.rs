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

use std::borrow::Cow;

use super::Transaction;
use crate::{
    collection::{Map, MatchData, Single},
    operators::Outputs,
    rules::{CollectionView, VariableSpec},
    transformations::text_of,
    types::RuleVariable,
};

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
            RuleVariable::RequestURIRaw => Some(Single($($borrow)+ $tx.computed.request_uri_raw)),
            RuleVariable::RequestLine => Some(Single($($borrow)+ $tx.computed.request_line)),
            RuleVariable::RequestFilename => Some(Single($($borrow)+ $tx.computed.request_filename)),
            RuleVariable::RequestBasename => Some(Single($($borrow)+ $tx.computed.request_basename)),
            RuleVariable::QueryString => Some(Single($($borrow)+ $tx.computed.query_string)),
            RuleVariable::URIParseError => Some(Single($($borrow)+ $tx.computed.uri_parse_error)),
            RuleVariable::Time => Some(Single($($borrow)+ $tx.computed.time)),
            RuleVariable::TimeDay => Some(Single($($borrow)+ $tx.computed.time_day)),
            RuleVariable::TimeEpoch => Some(Single($($borrow)+ $tx.computed.time_epoch)),
            RuleVariable::TimeHour => Some(Single($($borrow)+ $tx.computed.time_hour)),
            RuleVariable::TimeMin => Some(Single($($borrow)+ $tx.computed.time_min)),
            RuleVariable::TimeMon => Some(Single($($borrow)+ $tx.computed.time_mon)),
            RuleVariable::TimeSec => Some(Single($($borrow)+ $tx.computed.time_sec)),
            RuleVariable::TimeWday => Some(Single($($borrow)+ $tx.computed.time_wday)),
            RuleVariable::TimeYear => Some(Single($($borrow)+ $tx.computed.time_year)),
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
pub(super) enum BodyProcessor {
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
    pub(super) fn parse(name: &str) -> Option<Self> {
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
    pub(super) fn for_content_type(content_type: &[u8]) -> Option<Self> {
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
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Raw => "RAW",
            Self::UrlEncoded => "URLENCODED",
            Self::Multipart => "MULTIPART",
            Self::Json => "JSON",
            Self::Xml => "XML",
        }
    }
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "transaction impl blocks are split across submodules"
)]
impl Transaction {
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
    pub(super) fn set_single(&mut self, variable: RuleVariable, value: impl AsRef<[u8]>) {
        if let Some(VariableCollection::Single(single)) = self.collection_mut(variable) {
            single.set(value);
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

    /// Replace the value of a transaction variable.
    pub fn set_tx_variable(&mut self, key: &str, value: impl AsRef<[u8]>) {
        self.tx.set(key, [value]);
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
}
