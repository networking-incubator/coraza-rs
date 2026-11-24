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

use std::{borrow::Cow, mem::size_of};

use super::{TX_CAPTURE_KEYS, Transaction, TransactionInner};
use crate::{
    body_processors::budget,
    collection::{Growth, Map, MatchData, MatchLocation, MatchRef, Single, allocation_bytes},
    operators::Outputs,
    rules::{CollectionView, VariableSpec},
    transformations::{text_of, text_of_prefix},
    types::RuleVariable,
    utils::lowercase::lowercase_char,
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
            RuleVariable::UrlencodedError => Some(Single($($borrow)+ $tx.computed.urlencoded_error)),
            RuleVariable::FullRequestLength => Some(Single($($borrow)+ $tx.computed.full_request_length)),
            RuleVariable::MultipartDataAfter => Some(Single($($borrow)+ $tx.computed.multipart_data_after)),
            RuleVariable::Duration => Some(Single($($borrow)+ $tx.computed.duration)),
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
    ///
    /// Go trims the header value, lower-cases it with `strings.ToLower` and
    /// prefix-matches both media types (`internal/corazawaf/transaction.go:411-416`),
    /// so parameters, a malformed suffix, and invalid bytes after the prefix never
    /// suppress the selection, and `multİpart/form-data` (U+0130) selects multipart.
    /// Matching a parsed MIME value instead would skip bodies that a prefix-matching
    /// backend such as PHP's `sapi_read_post_data` still parses.
    pub(super) fn for_content_type(content_type: &[u8]) -> Option<Self> {
        let content_type = trim_leading_space(content_type);
        if starts_with_folded(content_type, "application/x-www-form-urlencoded") {
            Some(Self::UrlEncoded)
        } else if starts_with_folded(content_type, "multipart/form-data") {
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

/// Return `value` without the leading whitespace `strings.TrimSpace` removes.
///
/// A prefix match only looks at the start, so trailing whitespace is irrelevant.
/// Bytes that are not valid UTF-8 are data, as they are for Go's rune decoder, so
/// they are never trimmed and stop the scan.
fn trim_leading_space(value: &[u8]) -> &[u8] {
    let valid_up_to = match std::str::from_utf8(value) {
        Ok(_) => value.len(),
        Err(error) => error.valid_up_to(),
    };
    let valid = std::str::from_utf8(value.get(..valid_up_to).unwrap_or_default()).unwrap_or_default();
    let start = valid_up_to.saturating_sub(valid.trim_start().len());
    value.get(start..).unwrap_or_default()
}

/// Whether `value`, lower-cased the way Go's `strings.ToLower` does, starts with the lower-case `prefix`.
///
/// Go reads an invalid byte as U+FFFD, which no prefix character equals, so one before the end of the
/// prefix ends the match. Walks the value in place, without a lower-cased copy.
fn starts_with_folded(value: &[u8], prefix: &str) -> bool {
    // Only U+0130 and U+212A lower-case into ASCII, so an ASCII head, the common case, folds as ASCII.
    if let Some(head) = value.get(..prefix.len())
        && head.is_ascii()
    {
        return head.eq_ignore_ascii_case(prefix.as_bytes());
    }
    let mut expected = prefix.chars();
    for chunk in value.utf8_chunks() {
        for character in chunk.valid().chars() {
            match expected.next() {
                None => return true,
                Some(wanted) if lowercase_char(character) == wanted => {},
                Some(_) => return false,
            }
        }
        if !chunk.invalid().is_empty() {
            break;
        }
    }
    expected.next().is_none()
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

    /// Borrow a valid UTF-8 variable value for read-only operator parameter expansion.
    pub(crate) fn get_variable_cow(&self, variable: RuleVariable, key: Option<&str>) -> Option<Cow<'_, str>> {
        self.get_variable_cow_capped(variable, key, usize::MAX)
    }

    /// [`Transaction::get_variable_cow`] for the first `room` bytes of the text, see [`text_of_prefix`]: a value that is
    /// not UTF-8 is converted as far as it is read, not whole.
    pub(crate) fn get_variable_cow_capped(
        &self,
        variable: RuleVariable,
        key: Option<&str>,
        room: usize,
    ) -> Option<Cow<'_, str>> {
        match (self.collection(variable)?, key) {
            (VariableCollection::Single(single), None) => Some(text_of_prefix(single.get_bytes(), room)),
            (VariableCollection::Map(map), Some(key)) => map.first(key).map(|value| text_of_prefix(value, room)),
            (VariableCollection::Names(_, map), Some(key)) => map
                .iter_key(key)
                .next()
                .map(|(stored_key, _)| Cow::Borrowed(stored_key)),
            _ => None,
        }
    }

    /// Find the byte-preserving matches selected by a parsed variable spec.
    #[cfg(test)]
    pub(crate) fn find_matches(&self, spec: &VariableSpec) -> Vec<MatchData> {
        let collection = self.collection(spec.variable()).map(|collection| match collection {
            VariableCollection::Single(single) => CollectionView::Single(single),
            VariableCollection::Map(map) => CollectionView::Map(map),
            VariableCollection::Names(variable, map) => CollectionView::Names(variable, map),
        });
        spec.get_matches(collection)
    }

    /// Find the values selected by a rule after applying transaction-local target removals.
    ///
    /// Exclusions are applied while selecting, before a `&VAR` count is taken, as Go does
    /// (`internal/corazawaf/transaction.go:681-712`, v3.8.1): a removed key is not counted,
    /// and a count-mode match is never dropped.
    pub(crate) fn find_matches_for_rule(&self, spec: &VariableSpec, id: i32) -> Vec<MatchData> {
        let selected = self.find_match_refs_for_rule(spec, id);
        // A copy of every value, which lives as long as the rule does: charged before they are made. A selection
        // that did not fit the budget was cut short and stopped it, which fails this charge too: nothing is copied.
        let budget = &self.computed.rule_budget;
        if budget.is_armed()
            && !budget.charge_scratch(selected.iter().fold(0_usize, |total, value| {
                total
                    .saturating_add(size_of::<MatchData>())
                    .saturating_add(allocation_bytes(value.key().len()))
                    .saturating_add(allocation_bytes(value.value().len()))
            }))
        {
            return Vec::new();
        }
        selected.into_iter().map(MatchRef::into_owned).collect()
    }

    /// Select borrowed values and defer copying until a rule can match them.
    pub(crate) fn find_match_refs_for_rule<'a>(&'a self, spec: &'a VariableSpec, id: i32) -> Vec<MatchRef<'a>> {
        if !self.removed_rule_targets.contains_key(&id) {
            let collection = self.collection(spec.variable()).map(|collection| match collection {
                VariableCollection::Single(single) => CollectionView::Single(single),
                VariableCollection::Map(map) => CollectionView::Map(map),
                VariableCollection::Names(variable, map) => CollectionView::Names(variable, map),
            });
            return spec.get_match_refs(collection, &self.computed.rule_budget);
        }
        let collection = self.collection(spec.variable()).map(|collection| match collection {
            VariableCollection::Single(single) => CollectionView::Single(single),
            VariableCollection::Map(map) => CollectionView::Map(map),
            VariableCollection::Names(variable, map) => CollectionView::Names(variable, map),
        });
        spec.get_match_refs_filter(
            collection,
            |variable, key| self.is_rule_target_removed(id, variable, key),
            &self.computed.rule_budget,
        )
    }

    /// Fetch one selected value by its stable source position.
    pub(crate) fn find_match_ref_at(&self, variable: RuleVariable, location: MatchLocation) -> Option<MatchRef<'_>> {
        match location {
            MatchLocation::Map {
                source,
                entry_index,
                value_index,
                names,
            } => {
                let map = match self.collection(source)? {
                    VariableCollection::Map(map) | VariableCollection::Names(_, map) => map,
                    VariableCollection::Single(_) => return None,
                };
                let (key, value) = map.value_at(entry_index, value_index, names)?;
                Some(MatchRef {
                    variable,
                    key,
                    value: Cow::Borrowed(value),
                    location: Some(location),
                })
            },
            MatchLocation::Single { variable: source } => {
                let Some(VariableCollection::Single(single)) = self.collection(source) else {
                    return None;
                };
                Some(MatchRef {
                    variable,
                    key: "",
                    value: Cow::Borrowed(single.get_bytes()),
                    location: Some(location),
                })
            },
        }
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
                let removed = self.computed.rule_budget.take_removed_captures();
                if removed != 0 && !self.make_removed_capture_keys(removed) {
                    return;
                }
                // Clear the captures of the value matched previously in this rule. Go leaves
                // them alone: its `resetCaptures` is only used by its tests, so this is a
                // deliberate deviation, and the seeded keys make it allocation-free.
                for key in TX_CAPTURE_KEYS.iter().take(10) {
                    self.tx.set_index(key, 0, "");
                }
                self.set_tx_variable_in_rule(&index.to_string(), value);
                for (index, value) in captures {
                    self.set_tx_variable_in_rule(&index.to_string(), value);
                }
            }
        }
        // A capture the budget refused ended the evaluation: nothing the operator made is written after it, and no
        // write after a path argument it refused, which would set `ARGUMENTS_LIMIT_REACHED` for an argument at the
        // limit.
        for (key, value) in outputs.take_path_arguments() {
            if self.computed.rule_budget.is_stopped() {
                break;
            }
            self.set_path_argument(&key, value.as_bytes());
        }
    }

    /// Replace the first stored path argument and its corresponding ARGS value.
    fn set_path_argument(&mut self, key: &str, value: impl AsRef<[u8]>) {
        let value = value.as_ref();
        let args_index = self
            .args_path_indices
            .iter()
            .find(|(path_key, _)| path_key.as_slice() == key.as_bytes())
            .map(|(_, index)| *index);
        // What a rule writes is charged before it is, nothing is written when it does not fit.
        if self.computed.rule_budget.is_armed() && !self.charge_path_argument(key, value.len(), args_index) {
            return;
        }
        let Some(args_index) = args_index else {
            self.add_path_argument(key, value);
            return;
        };
        self.args_path.set_index(key, 0, value);
        self.args.set_index(key, args_index, value);
    }

    /// Reserves what [`Transaction::set_path_argument`] allocates for a value of `len` bytes under `key`, whose value
    /// in `ARGS` is at `args_index` if it holds one: the value in each of `ARGS_PATH` and `ARGS` with the entries that
    /// keep it and the key beside the list of indices for a new argument, only the growth of the buffers for one that
    /// is rewritten. Kept out of line, as the other charges of a write are.
    #[inline(never)]
    fn charge_path_argument(&self, key: &str, len: usize, args_index: Option<usize>) -> bool {
        let key = key.as_bytes();
        let growth = match args_index {
            // The value is rewritten in its buffer, and under the spelling of the name it is written with: a new one
            // is allocated beside the one it replaces, which is given back once it is gone (it was charged, or it was
            // there before the budget was armed, which counted it).
            Some(index) => Growth {
                grown: buffer_growth(self.args_path.value_capacity(key, 0), len)
                    .saturating_add(buffer_growth(self.args.value_capacity(key, index), len)),
                freed: 0,
            }
            .plus(self.args_path.rewrite_spelling_growth(key, 0))
            .plus(self.args.rewrite_spelling_growth(key, index)),
            // An argument past the limit is dropped, and takes nothing.
            None if self.args_path.value_count() >= self.config.argument_limit => return true,
            None => budget::insert_growth(&[&self.args_path, &self.args], key, len)
                .plus(budget::push_growth(
                    self.args_path_indices.len(),
                    self.args_path_indices.capacity(),
                    size_of::<(Vec<u8>, usize)>(),
                ))
                .plus(Growth {
                    grown: allocation_bytes(key.len()),
                    freed: 0,
                }),
        };
        let budget = &self.computed.rule_budget;
        if !budget.charge(growth.grown) {
            return false;
        }
        budget.refund(growth.freed);
        true
    }

    /// Replace the value of a transaction variable.
    pub fn set_tx_variable(&mut self, key: &str, value: impl AsRef<[u8]>) {
        self.matched_vars_dirty = true;
        self.tx.set(key, [value]);
    }

    /// [`Transaction::set_tx_variable`] for what a rule writes (`setvar`, `capture`): with a budget in force the
    /// entry is charged first, the list that replaces the key's values and the value beside the ones they replace,
    /// and what they replace is given back once they are. Nothing is written when the charge does not fit.
    pub(crate) fn set_tx_variable_in_rule(&mut self, key: &str, value: impl AsRef<[u8]>) {
        if self.computed.rule_budget.is_armed() {
            self.set_tx_variable_within_budget(key, value.as_ref());
        } else {
            self.set_tx_variable(key, value);
        }
    }

    /// The charged write of [`Transaction::set_tx_variable_in_rule`], kept out of line so that the write without a
    /// budget does not carry it.
    #[inline(never)]
    fn set_tx_variable_within_budget(&mut self, key: &str, value: &[u8]) {
        let Some(inner) = self.inner.as_deref_mut() else {
            return;
        };
        if set_within_budget(&mut inner.tx, &inner.computed.rule_budget, key, value) {
            inner.matched_vars_dirty = true;
        }
    }

    /// Write one `ENV` value for `setenv`: with a budget in force it is charged as the write of a `TX` entry is, and
    /// nothing is written when the charge does not fit.
    pub(crate) fn set_env_variable_in_rule(&mut self, key: &str, value: &[u8]) {
        if !self.computed.rule_budget.is_armed() {
            self.env.set(key, [value]);
            return;
        }
        let Some(inner) = self.inner.as_deref_mut() else {
            return;
        };
        set_within_budget(&mut inner.env, &inner.computed.rule_budget, key, value);
    }

    /// Record the value and variable name matched by an operator.
    pub(crate) fn record_matched_variable(&mut self, matched: &MatchData) {
        let Some(inner) = self.inner.as_deref_mut() else {
            return;
        };
        inner.matched_vars_dirty = true;
        let variable = matched.variable.name().as_bytes();
        if inner.computed.rule_budget.is_armed() && !charge_matched_var_name(inner, variable, &matched.key) {
            return;
        }
        if matched.key.is_empty() {
            inner.matched_var_name.set(variable);
        } else {
            inner
                .matched_var_name
                .set_joined(variable, b":", matched.key.as_bytes());
        }
        if inner.computed.rule_budget.is_armed() {
            record_matched_value_within_budget(inner, &matched.value);
        } else {
            inner
                .matched_vars
                .add_bytes(inner.matched_var_name.get_bytes(), &matched.value);
            inner.matched_var.set(&matched.value);
        }
    }

    /// Makes the capture keys of `removed` (one bit for each, lowest for `TX:0`) that are not there, which a rule
    /// removed and a later capture or `reset_matched_vars` may need to make again: each is charged first, what it takes
    /// is the key and its list of one empty value, and a key the budget has no room for is not made. Returns whether
    /// they all were. Kept out of line, as the other charges of a write are.
    #[inline(never)]
    pub(super) fn make_removed_capture_keys(&mut self, removed: u16) -> bool {
        let mut bit = 1_u16;
        for key in TX_CAPTURE_KEYS.iter().take(10) {
            if removed & bit != 0 && self.tx.first(key).is_none() {
                let growth = budget::set_growth(&self.tx, key.as_bytes(), 0);
                let budget = &self.computed.rule_budget;
                if !budget.charge(growth.grown) {
                    return false;
                }
                budget.refund(growth.freed);
                self.tx.set_index(key, 0, "");
            }
            bit = bit.wrapping_shl(1);
        }
        true
    }

    /// Update `RULE` values before evaluating a compiled rule.
    #[expect(clippy::too_many_arguments, reason = "fields mirror the RULE collection")]
    pub(crate) fn set_rule_variables(
        &mut self,
        id: i32,
        message: Option<Cow<'_, str>>,
        revision: &str,
        log_data: Option<Cow<'_, str>>,
        severity: &str,
    ) {
        self.rule.set_index("id", 0, id.to_string());
        if let Some(message) = message {
            self.rule.set_index("msg", 0, message.as_bytes());
        }
        self.rule.set_index("rev", 0, revision);
        if let Some(log_data) = log_data {
            self.rule.set_index("logdata", 0, log_data.as_bytes());
        }
        self.rule.set_index("severity", 0, severity);
    }
}

/// [`Map::set`] of one value for a rule under a budget: the list that replaces the key's values, the value and the
/// key's entry are charged first, and the list and values they replace given back once they are gone. Nothing is
/// written when the charge does not fit.
fn set_within_budget(map: &mut Map, budget: &budget::RuleBudget, key: &str, value: &[u8]) -> bool {
    let growth = budget::set_growth(map, key.as_bytes(), value.len());
    if !budget.charge(growth.grown) {
        return false;
    }
    let replaced = map.set(key, [value]);
    budget.refund(growth.freed.saturating_add(replaced));
    true
}

/// What a buffer of `held` bytes allocates to hold `needed`: nothing when it does, and otherwise what it grows to,
/// which is what is needed or twice what it holds.
fn buffer_growth(held: usize, needed: usize) -> usize {
    if needed > held {
        allocation_bytes(needed.max(held.saturating_mul(2))).saturating_sub(allocation_bytes(held))
    } else {
        0
    }
}

/// Reserves what `MATCHED_VAR_NAME` grows by for the name of `variable` and `key`: one buffer that keeps the capacity
/// of the longest key, like `MATCHED_VAR`'s, so it stays charged as `MATCHED_VAR`'s does: it is not one of the entries
/// of `MATCHED_VARS` that the next rule's clearing frees. Kept out of line, as the charges of a matched value are.
#[inline(never)]
fn charge_matched_var_name(inner: &TransactionInner, variable: &[u8], key: &str) -> bool {
    let needed = variable.len() + if key.is_empty() { 0 } else { 1 + key.len() };
    let growth = buffer_growth(inner.matched_var_name.allocated_bytes(), needed);
    growth == 0 || inner.computed.rule_budget.charge(growth)
}

/// The copies of a matched value that rule evaluation keeps, charged to the rule budget before they are made, kept out
/// of line so that recording a match without a budget does not carry it. The entry in `MATCHED_VARS` is a second copy
/// of the value, which the next rule's clearing frees; `MATCHED_VAR` is a third, which is rewritten in place and keeps
/// the capacity of the largest value.
#[inline(never)]
fn record_matched_value_within_budget(inner: &mut TransactionInner, value: &[u8]) {
    let name = inner.matched_var_name.get_bytes();
    let budget = &inner.computed.rule_budget;
    let var_growth = buffer_growth(inner.matched_var.allocated_bytes(), value.len());
    let lookup = inner.matched_vars.lookup_key(name);
    let growth = budget::values_growth_filed(&inner.matched_vars, name, &lookup, [value.len()]);
    let added = budget.charge_matched_vars(growth);
    if added {
        inner.matched_vars.add_filed(name, &lookup, value);
    }
    if added && (var_growth == 0 || budget.charge(var_growth)) {
        inner.matched_var.set(value);
    }
}

#[cfg(test)]
mod tests {
    use super::{BodyProcessor, MatchData, RuleVariable, allocation_bytes, buffer_growth};
    use crate::transaction::Transaction;

    /// `MATCHED_VAR_NAME` is charged for what it grows by, to the byte: a name longer than the buffer that holds the
    /// last one is built by three appends, which grew it twice, the second time past what was charged.
    #[test]
    fn the_matched_variable_name_buffer_grows_by_what_it_is_charged() {
        let (forty, two_hundred, long) = ("k".repeat(40), "k".repeat(200), "k".repeat(5_000));
        let sequences: [&[(RuleVariable, &str)]; 4] = [
            &[(RuleVariable::RequestHeaders, "a")],
            &[
                (RuleVariable::Args, "a"),
                (RuleVariable::RequestHeadersNames, "x"),
                (RuleVariable::RequestCookiesNames, "y"),
            ],
            &[
                (RuleVariable::Args, "a"),
                (RuleVariable::Args, &forty),
                (RuleVariable::RequestHeaders, &two_hundred),
                (RuleVariable::Args, &long),
            ],
            &[(RuleVariable::RequestHeaders, ""), (RuleVariable::Args, "a")],
        ];
        for sequence in sequences {
            let mut tx = Transaction::new("matched-var-name-growth");
            tx.computed.rule_budget.arm(1 << 30, 0);
            for (variable, key) in sequence {
                let held = tx.matched_var_name.allocated_bytes();
                let needed = variable.name().len() + if key.is_empty() { 0 } else { 1 + key.len() };
                let charged = buffer_growth(held, needed);
                tx.record_matched_variable(&MatchData::new(*variable, *key, b"v".to_vec()));
                let grown = allocation_bytes(tx.matched_var_name.allocated_bytes()) - allocation_bytes(held);
                assert_eq!(grown, charged, "{}:{} after {held} bytes", variable.name(), key.len());
            }
        }
    }

    #[test]
    fn content_type_selection_folds_case_like_go() {
        // Go lower-cases with `strings.ToLower`, whose simple mapping turns U+0130 into `i`, so
        // `multİpart/form-data` selects multipart there (`internal/corazawaf/transaction.go:411-416`).
        let cases: &[(&[u8], Option<&str>)] = &[
            ("appl\u{130}cation/x-www-form-urlencoded".as_bytes(), Some("URLENCODED")),
            ("applicat\u{130}on/x-www-form-urlencoded".as_bytes(), Some("URLENCODED")),
            (
                "APPL\u{130}CAT\u{130}ON/X-WWW-FORM-URLENCODED".as_bytes(),
                Some("URLENCODED"),
            ),
            ("mult\u{130}part/form-data; boundary=b".as_bytes(), Some("MULTIPART")),
            (b"MULTIPART/FORM-DATA", Some("MULTIPART")),
            (" \t\u{a0}mult\u{130}part/form-data".as_bytes(), Some("MULTIPART")),
            // What follows the prefix is not read, whatever it is.
            ("multipart/form-data\u{130}".as_bytes(), Some("MULTIPART")),
            (b"multipart/form-data\xff\xc4", Some("MULTIPART")),
            // An invalid byte inside the prefix ends the match: Go reads it as U+FFFD.
            (b"mul\xfftipart/form-data", None),
            (b"appl\xc4cation/x-www-form-urlencoded", None),
            (b"mult\xc4", None),
            // A value cut short of the prefix.
            ("mult\u{130}part/form-dat".as_bytes(), None),
            (b"application/x-www-form-urlencode", None),
            // U+212A folds to `k`, which neither media type has; Go keeps U+0131 (dotless `ı`) as it is.
            ("mult\u{212A}part/form-data".as_bytes(), None),
            ("\u{212A}multipart/form-data".as_bytes(), None),
            ("mult\u{131}part/form-data".as_bytes(), None),
            (b"", None),
        ];
        for (content_type, expected) in cases {
            assert_eq!(
                BodyProcessor::for_content_type(content_type).map(BodyProcessor::name),
                *expected,
                "content type {:?}",
                String::from_utf8_lossy(content_type)
            );
        }
    }
}
