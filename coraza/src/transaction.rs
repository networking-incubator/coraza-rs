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
//! This module stores values supplied by a connector. It does not parse HTTP
//! requests, process bodies, or evaluate rules.
//! Callers must apply transport and body size limits before storing values.

use std::{borrow::Cow, sync::Arc};

use crate::{
    collection::{Map, MatchData, Single},
    config::WafConfig,
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
            RuleVariable::UniqueID => Some(Single($($borrow)+ $tx.unique_id)),
            RuleVariable::ArgsCombinedSize => Some(Single($($borrow)+ $tx.args_combined_size_value)),
            RuleVariable::ArgumentsLimitReached => {
                Some(Single($($borrow)+ $tx.arguments_limit_reached))
            }
            RuleVariable::RequestURI => Some(Single($($borrow)+ $tx.request_uri)),
            RuleVariable::RequestMethod => Some(Single($($borrow)+ $tx.request_method)),
            RuleVariable::RequestProtocol => Some(Single($($borrow)+ $tx.request_protocol)),
            RuleVariable::RemoteAddr => Some(Single($($borrow)+ $tx.remote_addr)),
            RuleVariable::ServerName => Some(Single($($borrow)+ $tx.server_name)),
            RuleVariable::ResponseStatus => Some(Single($($borrow)+ $tx.response_status)),
            _ => None,
        }
    }};
}

/// A transaction's core input collections and values.
///
/// This type is the storage layer used by rule variable selection. HTTP
/// parsing, body processing, and rule execution are not included yet.
pub struct Transaction {
    /// The settings used to enforce transaction limits.
    config: Arc<WafConfig>,
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
}

impl Transaction {
    /// Create a transaction with the default WAF configuration.
    pub fn new(id: impl Into<String>) -> Self {
        Self::with_config(id, Arc::new(WafConfig::default()))
    }

    /// Create a transaction with the supplied WAF configuration.
    pub fn with_config(id: impl Into<String>, config: Arc<WafConfig>) -> Self {
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
            config,
            unique_id,
            args_combined_size: 0,
            args_combined_size_value: flag(RuleVariable::ArgsCombinedSize),
            arguments_limit_reached: flag(RuleVariable::ArgumentsLimitReached),
            args: map(RuleVariable::Args),
            args_get: map(RuleVariable::ArgsGet),
            args_post: map(RuleVariable::ArgsPost),
            args_path: map(RuleVariable::ArgsPath),
            args_path_indices: Vec::new(),
            request_headers: map(RuleVariable::RequestHeaders),
            request_cookies: map(RuleVariable::RequestCookies),
            response_headers: map(RuleVariable::ResponseHeaders),
            tx: map(RuleVariable::TX),
            request_uri: Single::new(RuleVariable::RequestURI),
            request_method: Single::new(RuleVariable::RequestMethod),
            request_protocol: Single::new(RuleVariable::RequestProtocol),
            remote_addr: Single::new(RuleVariable::RemoteAddr),
            server_name: Single::new(RuleVariable::ServerName),
            response_status: Single::new(RuleVariable::ResponseStatus),
        }
    }

    /// The transaction ID as text.
    pub fn id(&self) -> Cow<'_, str> {
        self.unique_id.get()
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by rule evaluation in a later port slice")
    )]
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by rule evaluation in a later port slice")
    )]
    pub(crate) fn store_operator_outputs(&mut self, outputs: &mut Outputs) {
        for index in 0..10 {
            self.tx.remove(&index.to_string());
        }
        for (index, value) in outputs.take_captures() {
            self.set_tx_variable(&index.to_string(), value);
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
        self.request_headers.add(key, value);
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{Transaction, VariableCollection};
    use crate::{config::WafConfig, operators::Outputs, rules::VariableSpec, types::RuleVariable};

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
        assert!(tx.collection(RuleVariable::RequestBody).is_none());
    }
}
