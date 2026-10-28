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

//! Per-stream policy selection, body gating and transaction finalization.

#![allow(
    clippy::missing_docs_in_private_items,
    reason = "Private adapter details are documented by their callbacks and enclosing types."
)]

use std::{
    cell::Cell,
    net::{IpAddr, SocketAddr},
    rc::Rc,
    str,
};

use coraza::{
    transaction::{Interruption, Transaction},
    types::RuleEngineStatus,
};
use proxy_wasm::{
    hostcalls,
    traits::{Context, HttpContext},
    types::{Action, BufferType, LogLevel, MapType, Status},
};

use crate::{
    observability::{self, HealthState, InterruptionPhase},
    policy::{Generation, Policy},
};

/// Largest request body held by the connector or Envoy before a body verdict.
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Largest response body held by the connector or Envoy before a body verdict.
const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

/// Maximum retained body bytes shared by streams in one Proxy-Wasm root context.
/// Each worker has its own root context and counter; this is not a worker-wide cap.
const MAX_ROOT_RETAINED_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Header count accepted in either direction.
const MAX_HEADER_COUNT: usize = 1024;

/// Maximum bytes accepted in one HTTP header value.
const MAX_HEADER_VALUE_BYTES: usize = 64 * 1024;

/// Maximum bytes accepted across one direction's headers.
const MAX_HEADERS_BYTES: usize = 1024 * 1024;

const REQUEST_BLOCK_BODY: &[u8] = b"Request blocked by security policy\n";
const RESPONSE_BLOCK_BODY: &[u8] = b"Upstream response blocked\n";
const REQUEST_INCOMPLETE_BODY: &[u8] = b"Request inspection unavailable\n";
const RESPONSE_INCOMPLETE_BODY: &[u8] = b"Response inspection unavailable\n";
const UNSUPPORTED_BODY: &[u8] = b"Request feature is not supported\n";

/// Terminal or explicitly incomplete outcome retained for Stage E publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TerminalOutcome {
    /// No configured policy matched; traffic continued uninspected.
    UnmatchedAuthority,
    /// The selected policy has `SecRuleEngine Off`.
    EngineOff,
    /// The request or response used an unsupported feature.
    Unsupported(&'static str),
    /// A WAF rule interrupted a request or response.
    Denied { phase: &'static str, status: u16 },
    /// An incomplete body was rejected.
    Incomplete { phase: &'static str, status: u16 },
    /// A host or policy body ceiling was reached.
    BodyTooLarge { phase: &'static str, status: u16 },
    /// Coraza processed the configured prefix and allowed the request to continue.
    BodyPartiallyInspected { phase: &'static str },
    /// The per-root retained-body cap was exhausted.
    RetainedBodyBudgetExhausted { phase: &'static str },
    /// A callback sequence or host response made inspection impossible.
    InvalidLifecycle { phase: &'static str, status: u16 },
    /// The request authority was not valid UTF-8 or a valid authority value.
    InvalidAuthority { status: u16 },
    /// The stream ended before a complete response; SDK 0.2.5 does not report the cause.
    UpstreamFailureOrCancellation,
    /// The transaction reached a complete response.
    Completed,
}

impl TerminalOutcome {
    fn inspection_reason(&self) -> &'static str {
        match self {
            Self::UnmatchedAuthority => "unmatched_authority",
            Self::EngineOff => "engine_off",
            Self::Unsupported(_) => "unsupported",
            Self::Denied { .. } => "denied",
            Self::Incomplete { .. } => "incomplete",
            Self::BodyTooLarge { .. } => "body_too_large",
            Self::BodyPartiallyInspected { .. } => "body_partially_inspected",
            Self::RetainedBodyBudgetExhausted { .. } => "retained_body_budget_exhausted",
            Self::InvalidLifecycle { .. } => "invalid_lifecycle",
            Self::InvalidAuthority { .. } => "invalid_authority",
            Self::UpstreamFailureOrCancellation => "upstream_failure_or_cancellation",
            Self::Completed => "complete",
        }
    }

    fn terminal_name(&self) -> &'static str {
        match self {
            Self::UnmatchedAuthority | Self::EngineOff => "uninspected",
            Self::Unsupported(_) => "unsupported",
            Self::Denied { .. } => "denied",
            Self::Incomplete { .. } | Self::BodyPartiallyInspected { .. } => "incomplete",
            Self::BodyTooLarge { .. }
            | Self::RetainedBodyBudgetExhausted { .. }
            | Self::InvalidLifecycle { .. }
            | Self::InvalidAuthority { .. } => "error",
            Self::UpstreamFailureOrCancellation => "upstream_failure_or_cancellation",
            Self::Completed => "completed",
        }
    }

    #[cfg(test)]
    fn is_error(&self) -> bool {
        matches!(
            self,
            Self::Incomplete { .. }
                | Self::BodyTooLarge { .. }
                | Self::RetainedBodyBudgetExhausted { .. }
                | Self::InvalidLifecycle { .. }
                | Self::InvalidAuthority { .. }
                | Self::UpstreamFailureOrCancellation
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestStage {
    New,
    Headers,
    Body,
    Complete,
    Bypassed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseStage {
    Waiting,
    Headers,
    Body,
    Complete,
}

/// Request handling mode selected for this stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestMode {
    /// A configured policy inspects the request.
    Inspect,
    /// No policy or an off engine deliberately bypasses inspection.
    Uninspected,
    /// The connector has already sent a local response.
    Replied,
}

/// Whether upstream response content must be replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseMode {
    /// Preserve response bytes unless a later phase denies them.
    Inspect,
    /// Replace the response body and headers before they reach the client.
    Blocked,
}

/// Request metadata collected from Envoy before opening the transaction.
struct RequestMetadata {
    method: String,
    uri: Vec<u8>,
    protocol: String,
    has_host: bool,
}

/// Result of the transaction's one finalization attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalizationResult {
    /// The transaction has not been finalized yet.
    Pending,
    /// `Transaction::finish` completed successfully.
    Succeeded,
    /// `Transaction::finish` reported an error.
    Failed,
}

/// Guards request/response phases against repeated and impossible callbacks.
#[derive(Debug)]
struct Lifecycle {
    request: RequestStage,
    response: ResponseStage,
    finalized: bool,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            request: RequestStage::New,
            response: ResponseStage::Waiting,
            finalized: false,
        }
    }
}

impl Lifecycle {
    fn begin_request(&mut self) -> bool {
        if self.request != RequestStage::New || self.finalized {
            return false;
        }
        self.request = RequestStage::Headers;
        true
    }

    fn request_body(&mut self) -> bool {
        if self.finalized || self.request == RequestStage::Complete {
            return false;
        }
        match self.request {
            RequestStage::Headers | RequestStage::Body => {
                self.request = RequestStage::Body;
                true
            },
            _ => false,
        }
    }

    fn complete_request(&mut self) -> bool {
        if self.finalized {
            return false;
        }
        if !matches!(self.request, RequestStage::Headers | RequestStage::Body) {
            return false;
        }
        self.request = RequestStage::Complete;
        true
    }

    fn bypass_request(&mut self) {
        self.request = RequestStage::Bypassed;
    }

    fn begin_response(&mut self) -> bool {
        if self.finalized || self.response != ResponseStage::Waiting || self.request != RequestStage::Complete {
            return false;
        }
        self.response = ResponseStage::Headers;
        true
    }

    fn response_body(&mut self) -> bool {
        if self.finalized || self.response == ResponseStage::Complete {
            return false;
        }
        match self.response {
            ResponseStage::Headers | ResponseStage::Body => {
                self.response = ResponseStage::Body;
                true
            },
            _ => false,
        }
    }

    fn complete_response(&mut self) -> bool {
        if self.finalized {
            return false;
        }
        if !matches!(self.response, ResponseStage::Headers | ResponseStage::Body) {
            return false;
        }
        self.response = ResponseStage::Complete;
        true
    }

    fn finish_once(&mut self) -> bool {
        if self.finalized {
            return false;
        }
        self.finalized = true;
        true
    }
}

/// One HTTP stream, sharing the generation that was current when it started.
#[expect(
    clippy::struct_excessive_bools,
    reason = "Independent callback outcomes and truncation flags are tracked across host events."
)]
pub(crate) struct CorazaHttp {
    generation: Option<Rc<Generation>>,
    root_retained_bytes: Rc<Cell<usize>>,
    retained_bytes: usize,
    selected_policy: Option<String>,
    tx: Option<Box<Transaction>>,
    lifecycle: Lifecycle,
    outcome: Option<TerminalOutcome>,
    final_outcome: Option<TerminalOutcome>,
    finalization_result: FinalizationResult,
    telemetry_publish_failed: bool,
    request_body_truncated: bool,
    response_body_truncated: bool,
    request_mode: RequestMode,
    request_method: String,
    request_protocol: String,
    request_body_size: usize,
    response_body_size: usize,
    request_host_bytes: usize,
    response_host_bytes: usize,
    request_copy_bytes: usize,
    response_copy_bytes: usize,
    request_engine_bytes: usize,
    response_engine_bytes: usize,
    response_mode: ResponseMode,
    response_mutation_failed: bool,
    response_block_body: &'static [u8],
    response_interruption: Option<Interruption>,
}

impl CorazaHttp {
    pub(crate) fn new(generation: Option<Rc<Generation>>, root_retained_bytes: Rc<Cell<usize>>) -> Self {
        Self {
            generation,
            root_retained_bytes,
            retained_bytes: 0,
            selected_policy: None,
            tx: None,
            lifecycle: Lifecycle::default(),
            outcome: None,
            final_outcome: None,
            finalization_result: FinalizationResult::Pending,
            telemetry_publish_failed: false,
            request_body_truncated: false,
            response_body_truncated: false,
            request_mode: RequestMode::Inspect,
            request_method: String::new(),
            request_protocol: String::new(),
            request_body_size: 0,
            response_body_size: 0,
            request_host_bytes: 0,
            response_host_bytes: 0,
            request_copy_bytes: 0,
            response_copy_bytes: 0,
            request_engine_bytes: 0,
            response_engine_bytes: 0,
            response_mode: ResponseMode::Inspect,
            response_mutation_failed: false,
            response_block_body: RESPONSE_BLOCK_BODY,
            response_interruption: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn pinned_generation(&self) -> Option<Rc<Generation>> {
        self.generation.clone()
    }

    #[expect(dead_code, reason = "Stage E publishes the selected policy and finalization result")]
    pub(crate) fn selected_policy(&self) -> Option<&str> {
        self.selected_policy.as_deref()
    }

    #[expect(dead_code, reason = "Stage E publishes the selected policy and finalization result")]
    pub(crate) fn finalization_failed(&self) -> bool {
        self.finalization_result == FinalizationResult::Failed
    }

    fn diagnostic_count(&self) -> Option<u64> {
        self.generation
            .as_ref()
            .map(|generation| generation.diagnostics().failure_count())
    }

    fn mark_diagnostic_change(&mut self, before: Option<u64>) {
        if before.is_some_and(|before| {
            self.generation
                .as_ref()
                .is_some_and(|generation| generation.diagnostics().failure_count() > before)
        }) {
            self.telemetry_publish_failed = true;
        }
    }

    fn record_interruption(
        generation: &Generation,
        transaction: &Transaction,
        interruption: &Interruption,
        phase: InterruptionPhase,
    ) -> bool {
        observability::interruption(
            generation.enable_filter_state_logs(),
            transaction,
            interruption,
            phase,
            generation.diagnostics(),
        )
    }

    fn begin_request(&mut self, num_headers: usize, end_of_stream: bool) -> Action {
        if self.request_mode == RequestMode::Replied {
            return Action::Pause;
        }
        if !self.lifecycle.begin_request() {
            return if matches!(self.lifecycle.request, RequestStage::Headers | RequestStage::Body) {
                Action::Pause
            } else {
                Action::Continue
            };
        }
        let Some(generation) = self.generation.clone() else {
            return self.reject_request(
                503,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::InvalidLifecycle {
                    phase: "configuration",
                    status: 503,
                },
            );
        };
        if num_headers > MAX_HEADER_COUNT {
            return self.reject_request(
                431,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "request-headers",
                    status: 431,
                },
            );
        }

        let Ok(headers) = hostcalls::get_map_bytes(MapType::HttpRequestHeaders) else {
            return self.reject_request(
                503,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "request-headers-hostcall",
                    status: 503,
                },
            );
        };
        if !headers_within_limits(&headers, num_headers) {
            return self.reject_request(
                431,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "request-headers",
                    status: 431,
                },
            );
        }

        self.prepare_request(&generation, &headers, end_of_stream)
    }

    fn prepare_request(
        &mut self,
        generation: &Generation,
        headers: &[(String, Vec<u8>)],
        end_of_stream: bool,
    ) -> Action {
        let fallback_authority = property(vec!["request", "host"]);
        let raw_authority = request_authority(headers, fallback_authority.as_deref());
        let scheme = find_header(headers, ":scheme")
            .map(<[u8]>::to_vec)
            .or_else(|| property(vec!["request", "scheme"]))
            .unwrap_or_default();
        let authority = raw_authority.as_slice();
        let Some(authority_text) = str::from_utf8(authority).ok() else {
            return self.reject_request(
                400,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::InvalidAuthority { status: 400 },
            );
        };
        let Some(normalized_authority) = normalize_authority(authority, &scheme) else {
            return self.reject_request(
                400,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::InvalidAuthority { status: 400 },
            );
        };
        let Some((policy_name, policy)) = generation.select_named(&normalized_authority) else {
            self.lifecycle.bypass_request();
            self.request_mode = RequestMode::Uninspected;
            self.outcome = Some(TerminalOutcome::UnmatchedAuthority);
            log_warn("envoy-coraza: no authority policy matched; request passed uninspected");
            return Action::Continue;
        };
        self.selected_policy = Some(policy_name.to_owned());
        self.tx = Some(Box::new(policy.waf.new_transaction()));

        let Some(metadata) = request_metadata(headers) else {
            return self.reject_request(
                503,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "request-metadata",
                    status: 503,
                },
            );
        };
        metadata.method.clone_into(&mut self.request_method);
        metadata.protocol.clone_into(&mut self.request_protocol);
        let diagnostics_before = self.diagnostic_count();
        let (interruption, engine_off, body_access) =
            prepare_transaction(self, policy, authority_text, headers, &metadata);
        self.mark_diagnostic_change(diagnostics_before);

        if let Some(interruption) = interruption {
            return self.reject_interruption(&interruption, "request-headers", InterruptionPhase::RequestHeaders);
        }
        if engine_off {
            self.lifecycle.bypass_request();
            self.request_mode = RequestMode::Uninspected;
            self.outcome = Some(TerminalOutcome::EngineOff);
            return Action::Continue;
        }
        if metadata.method.eq_ignore_ascii_case("CONNECT") || has_upgrade(headers) {
            return self.reject_request(
                501,
                UNSUPPORTED_BODY,
                TerminalOutcome::Unsupported("upgrade-or-connect"),
            );
        }
        if body_access && has_unsupported_content_encoding(headers) {
            return self.reject_request(
                415,
                UNSUPPORTED_BODY,
                TerminalOutcome::Unsupported("request-content-encoding"),
            );
        }
        self.request_body_action_after_headers(body_access, end_of_stream)
    }

    /// Complete phase 2 at headers when the engine will not ingest the request body.
    fn request_body_action_after_headers(&mut self, body_access: bool, end_of_stream: bool) -> Action {
        if !body_access || end_of_stream {
            self.complete_request_body(0)
        } else {
            Action::Pause
        }
    }

    fn complete_request_body(&mut self, body_size: usize) -> Action {
        if self.lifecycle.finalized || self.request_mode == RequestMode::Uninspected {
            return Action::Continue;
        }
        if body_size < self.request_body_size {
            return self.reject_request(
                503,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::InvalidLifecycle {
                    phase: "request-body-size-regressed",
                    status: 503,
                },
            );
        }
        self.request_body_size = body_size;
        let Some(tx) = self.tx.as_deref() else {
            return Action::Continue;
        };
        let body_access = tx.request_body_access();
        if body_size > MAX_REQUEST_BODY_BYTES {
            return self.reject_request(
                413,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::BodyTooLarge {
                    phase: "request-body",
                    status: 413,
                },
            );
        }
        if !self.lifecycle.complete_request() {
            return Action::Continue;
        }

        let interruption = match self.inspect_request_body(body_size, body_access) {
            Ok(interruption) => interruption,
            Err(outcome) => return self.reject_request(503, REQUEST_INCOMPLETE_BODY, outcome),
        };
        if let Some(interruption) = interruption {
            return self.reject_interruption(&interruption, "request-body", InterruptionPhase::RequestBody);
        }
        if self.tx.as_deref().is_some_and(request_inspection_incomplete) {
            return self.reject_request(
                413,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "request-body-inspection",
                    status: 413,
                },
            );
        }
        if self.tx.as_ref().is_some_and(|tx| tx.request_body_stats().truncated) {
            self.outcome
                .get_or_insert(TerminalOutcome::BodyPartiallyInspected { phase: "request-body" });
        }
        Action::Continue
    }

    fn inspect_request_body(
        &mut self,
        body_size: usize,
        body_access: bool,
    ) -> Result<Option<Interruption>, TerminalOutcome> {
        self.request_host_bytes = body_size;
        if body_access && body_size > 0 {
            self.request_copy_bytes = body_size;
            self.request_engine_bytes = body_size;
        }
        if !self.update_accounting() {
            return Err(TerminalOutcome::RetainedBodyBudgetExhausted { phase: "request-body" });
        }
        let body = if body_access && body_size > 0 {
            Self::copy_request_body(body_size).map_err(|phase| TerminalOutcome::Incomplete { phase, status: 503 })?
        } else {
            Vec::new()
        };
        let diagnostics_before = self.diagnostic_count();
        let interruption = self.tx.as_deref_mut().and_then(|tx| tx.process_request_body(&body));
        self.mark_diagnostic_change(diagnostics_before);
        drop(body);
        self.request_host_bytes = 0;
        self.request_copy_bytes = 0;
        self.request_engine_bytes = self.tx.as_deref().map_or(0, Transaction::body_memory_bytes);
        if !self.update_accounting() {
            return Err(TerminalOutcome::RetainedBodyBudgetExhausted {
                phase: "request-body-retention",
            });
        }
        Ok(interruption)
    }

    fn copy_request_body(body_size: usize) -> Result<Vec<u8>, &'static str> {
        let Some(body) = hostcalls::get_buffer(BufferType::HttpRequestBody, 0, body_size)
            .map_err(|_error| "request-body-buffer-hostcall-failed")?
        else {
            return Err("request-body-buffer-unavailable");
        };
        if body.len() != body_size {
            return Err("request-body-buffer-short");
        }
        Ok(body)
    }

    fn request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if self.lifecycle.finalized {
            return if self.request_mode == RequestMode::Replied {
                Action::Pause
            } else {
                Action::Continue
            };
        }
        if self.request_mode == RequestMode::Uninspected {
            return Action::Continue;
        }
        if self.lifecycle.request == RequestStage::Complete {
            return Action::Continue;
        }
        if !self.lifecycle.request_body() {
            return self.reject_request(
                503,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::InvalidLifecycle {
                    phase: "request-body-before-headers",
                    status: 503,
                },
            );
        }
        if body_size < self.request_body_size {
            return self.reject_request(
                503,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::InvalidLifecycle {
                    phase: "request-body-size-regressed",
                    status: 503,
                },
            );
        }
        self.request_body_size = body_size;
        if self.tx.is_none() {
            return self.reject_request(
                503,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::InvalidLifecycle {
                    phase: "request-transaction-missing",
                    status: 503,
                },
            );
        }
        if body_size > MAX_REQUEST_BODY_BYTES {
            return self.reject_request(
                413,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::BodyTooLarge {
                    phase: "request-body",
                    status: 413,
                },
            );
        }
        self.request_host_bytes = body_size;
        if !self.update_accounting() {
            return self.reject_request(
                503,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::RetainedBodyBudgetExhausted { phase: "request-body" },
            );
        }
        if end_of_stream {
            return self.complete_request_body(body_size);
        }
        Action::Pause
    }

    fn request_trailers(&mut self, num_trailers: usize) -> Action {
        if self.lifecycle.finalized {
            return if self.request_mode == RequestMode::Replied {
                Action::Pause
            } else {
                Action::Continue
            };
        }
        if self.request_mode == RequestMode::Uninspected {
            return Action::Continue;
        }
        let request_complete = self.lifecycle.request == RequestStage::Complete;
        if !request_complete && !matches!(self.lifecycle.request, RequestStage::Headers | RequestStage::Body) {
            return self.reject_request(
                503,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::InvalidLifecycle {
                    phase: "request-trailers-order",
                    status: 503,
                },
            );
        }
        if num_trailers > MAX_HEADER_COUNT {
            return self.reject_request(
                431,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "request-trailers",
                    status: 431,
                },
            );
        }
        let Ok(trailers) = hostcalls::get_map_bytes(MapType::HttpRequestTrailers) else {
            return self.reject_request(
                503,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "request-trailers-hostcall",
                    status: 503,
                },
            );
        };
        if !headers_within_limits(&trailers, num_trailers) {
            return self.reject_request(
                431,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "request-trailers",
                    status: 431,
                },
            );
        }
        if request_complete {
            Action::Continue
        } else {
            self.complete_request_body(self.request_body_size)
        }
    }

    fn response_headers(&mut self, num_headers: usize, end_of_stream: bool) -> Action {
        if self.lifecycle.finalized {
            return if self.response_mutation_failed {
                Action::Pause
            } else {
                Action::Continue
            };
        }
        if self.request_mode != RequestMode::Inspect || self.tx.is_none() {
            return Action::Continue;
        }
        if self.lifecycle.response != ResponseStage::Waiting {
            return if matches!(self.lifecycle.response, ResponseStage::Headers | ResponseStage::Body) {
                Action::Pause
            } else {
                Action::Continue
            };
        }
        if num_headers > MAX_HEADER_COUNT {
            return self.reject_response(
                502,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "response-headers",
                    status: 502,
                },
            );
        }
        let Ok(headers) = hostcalls::get_map_bytes(MapType::HttpResponseHeaders) else {
            return self.reject_response(
                502,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "response-headers-hostcall",
                    status: 502,
                },
            );
        };
        if !headers_within_limits(&headers, num_headers) {
            return self.reject_response(
                502,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "response-headers",
                    status: 502,
                },
            );
        }
        let status = find_header(&headers, ":status")
            .and_then(|value| str::from_utf8(value).ok())
            .and_then(|value| value.parse::<u16>().ok())
            .or_else(|| {
                property(vec!["response", "code"]).and_then(|value| str::from_utf8(&value).ok()?.parse::<u16>().ok())
            });
        let Some(status) = status else {
            return self.reject_response(
                502,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "response-status",
                    status: 502,
                },
            );
        };
        if (100..200).contains(&status) && status != 101 {
            return Action::Continue;
        }
        if status == 101 {
            self.request_mode = RequestMode::Replied;
            self.finish_once(TerminalOutcome::Unsupported("response-upgrade"));
            return Self::send_local_response(
                501,
                vec![
                    ("content-type", "text/plain; charset=utf-8"),
                    ("cache-control", "no-store"),
                ],
                Some(UNSUPPORTED_BODY),
            );
        }
        if !self.lifecycle.begin_response() {
            return self.reject_response(
                503,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::InvalidLifecycle {
                    phase: "response-headers-order",
                    status: 503,
                },
            );
        }
        self.inspect_response_headers(status, &headers, end_of_stream)
    }

    fn inspect_response_headers(&mut self, status: u16, headers: &[(String, Vec<u8>)], end_of_stream: bool) -> Action {
        for (name, value) in headers {
            if let Some(tx) = self.tx.as_mut() {
                tx.add_response_header(name, value);
            }
        }
        let diagnostics_before = self.diagnostic_count();
        let interruption = self
            .tx
            .as_mut()
            .and_then(|tx| tx.process_response_headers(status, &self.request_protocol));
        self.mark_diagnostic_change(diagnostics_before);
        if let Some(interruption) = interruption {
            if let (Some(generation), Some(transaction)) = (self.generation.clone(), self.tx.as_deref()) {
                if Self::record_interruption(
                    &generation,
                    transaction,
                    &interruption,
                    InterruptionPhase::ResponseHeaders,
                ) {
                    self.telemetry_publish_failed = true;
                }
            }
            self.response_mode = ResponseMode::Blocked;
            self.response_interruption = Some(interruption.clone());
            self.response_block_body = if interruption.action == "redirect" {
                &[]
            } else {
                RESPONSE_BLOCK_BODY
            };
            if let Err(status) = self.set_response_block_headers(&interruption, self.response_block_body) {
                self.finish_once(TerminalOutcome::Denied {
                    phase: "response-headers",
                    status: valid_status(interruption.status),
                });
                return self.response_mutation_action(Err(status));
            }
        }
        let body_access = self.tx.as_deref().is_some_and(Transaction::response_body_access);
        let processable = self
            .tx
            .as_deref()
            .is_some_and(Transaction::is_response_body_processable);
        if self.response_mode == ResponseMode::Inspect
            && body_access
            && processable
            && has_unsupported_content_encoding(headers)
        {
            return self.reject_response(
                502,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::Unsupported("response-content-encoding"),
            );
        }
        if end_of_stream {
            return self.complete_response_body(0);
        }
        if self.response_mode == ResponseMode::Inspect && !(body_access && processable) {
            let action = self.complete_response_body(0);
            return if self.response_mode == ResponseMode::Blocked {
                Action::Pause
            } else {
                action
            };
        }
        Action::Pause
    }

    fn response_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if self.request_mode == RequestMode::Replied {
            return if self.lifecycle.finalized && !self.response_mutation_failed {
                Action::Continue
            } else {
                Action::Pause
            };
        }
        if self.request_mode != RequestMode::Inspect {
            return Action::Continue;
        }
        if self.lifecycle.finalized {
            if self.response_mutation_failed {
                return Action::Pause;
            }
            if self.response_mode == ResponseMode::Blocked {
                return self.response_mutation_action(hostcalls::set_buffer(
                    BufferType::HttpResponseBody,
                    0,
                    body_size,
                    if end_of_stream { self.response_block_body } else { &[] },
                ));
            }
            return Action::Continue;
        }
        if self.tx.is_none() {
            return Action::Continue;
        }
        if self.lifecycle.response == ResponseStage::Complete {
            return Action::Continue;
        }
        if !self.lifecycle.response_body() {
            return self.reject_response(
                503,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::InvalidLifecycle {
                    phase: "response-body-before-headers",
                    status: 503,
                },
            );
        }
        if body_size < self.response_body_size {
            return self.reject_response(
                502,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::InvalidLifecycle {
                    phase: "response-body-size-regressed",
                    status: 502,
                },
            );
        }
        self.response_body_size = body_size;
        let body_access = self.tx.as_deref().is_some_and(Transaction::response_body_access);
        let processable = self
            .tx
            .as_deref()
            .is_some_and(Transaction::is_response_body_processable);
        if self.response_mode == ResponseMode::Inspect
            && body_access
            && processable
            && body_size > MAX_RESPONSE_BODY_BYTES
        {
            return self.reject_response(
                502,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::BodyTooLarge {
                    phase: "response-body",
                    status: 502,
                },
            );
        }
        self.response_host_bytes = body_size;
        if !self.update_accounting() {
            return self.reject_response(
                503,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::RetainedBodyBudgetExhausted { phase: "response-body" },
            );
        }
        if end_of_stream {
            return self.complete_response_body(body_size);
        }
        Action::Pause
    }

    fn response_trailers(&mut self, num_trailers: usize) -> Action {
        if self.request_mode == RequestMode::Replied {
            return if self.lifecycle.finalized && !self.response_mutation_failed {
                Action::Continue
            } else {
                Action::Pause
            };
        }
        if self.request_mode != RequestMode::Inspect {
            return Action::Continue;
        }
        if self.lifecycle.finalized {
            if self.response_mutation_failed {
                return Action::Pause;
            }
            if self.response_mode == ResponseMode::Blocked {
                if self.response_mutation_action(hostcalls::set_buffer(
                    BufferType::HttpResponseBody,
                    0,
                    self.response_body_size,
                    self.response_block_body,
                )) == Action::Pause
                {
                    return Action::Pause;
                }
                return self
                    .response_mutation_action(hostcalls::set_map_bytes(MapType::HttpResponseTrailers, Vec::new()));
            }
            return Action::Continue;
        }
        if self.tx.is_none() {
            return Action::Continue;
        }
        if self.lifecycle.response == ResponseStage::Complete {
            return Action::Continue;
        }
        if !matches!(self.lifecycle.response, ResponseStage::Headers | ResponseStage::Body) {
            return self.reject_response(
                503,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::InvalidLifecycle {
                    phase: "response-trailers-order",
                    status: 503,
                },
            );
        }
        if num_trailers > MAX_HEADER_COUNT {
            return self.reject_response(
                502,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "response-trailers",
                    status: 502,
                },
            );
        }
        let Ok(trailers) = hostcalls::get_map_bytes(MapType::HttpResponseTrailers) else {
            return self.reject_response(
                502,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "response-trailers-hostcall",
                    status: 502,
                },
            );
        };
        if !headers_within_limits(&trailers, num_trailers) {
            return self.reject_response(
                502,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "response-trailers",
                    status: 502,
                },
            );
        }
        self.complete_response_body(self.response_body_size)
    }

    fn complete_response_body(&mut self, body_size: usize) -> Action {
        if self.lifecycle.finalized {
            return Action::Continue;
        }
        if !self.lifecycle.complete_response() {
            return Action::Continue;
        }
        if self.response_mode == ResponseMode::Blocked {
            return self.complete_blocked_response(body_size);
        }

        let body_access = self.tx.as_deref().is_some_and(Transaction::response_body_access);
        let processable = self
            .tx
            .as_deref()
            .is_some_and(Transaction::is_response_body_processable);
        let interruption = match self.inspect_response_body(body_size, body_access, processable) {
            Ok(interruption) => interruption,
            Err(outcome) => return self.reject_response(503, RESPONSE_INCOMPLETE_BODY, outcome),
        };
        if let Some(interruption) = interruption {
            if let (Some(generation), Some(transaction)) = (self.generation.clone(), self.tx.as_deref()) {
                if Self::record_interruption(&generation, transaction, &interruption, InterruptionPhase::ResponseBody) {
                    self.telemetry_publish_failed = true;
                }
            }
            self.finish_once(TerminalOutcome::Denied {
                phase: "response-body",
                status: valid_status(interruption.status),
            });
            let result = self.replace_interruption(&interruption, body_size);
            return self.response_mutation_action(result);
        }
        if self.tx.as_deref().is_some_and(response_inspection_incomplete) {
            return self.reject_response(
                502,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "response-body-inspection",
                    status: 502,
                },
            );
        }
        if self.tx.as_ref().is_some_and(|tx| tx.response_body_stats().truncated) {
            self.outcome
                .get_or_insert(TerminalOutcome::BodyPartiallyInspected { phase: "response-body" });
        }
        self.finish_once(TerminalOutcome::Completed);
        Action::Continue
    }

    fn inspect_response_body(
        &mut self,
        body_size: usize,
        body_access: bool,
        processable: bool,
    ) -> Result<Option<Interruption>, TerminalOutcome> {
        let mut body = Vec::new();
        if body_access && processable && body_size > 0 {
            self.response_copy_bytes = body_size;
            self.response_engine_bytes = body_size;
        }
        if !self.update_accounting() {
            return Err(TerminalOutcome::RetainedBodyBudgetExhausted {
                phase: "response-body-copy",
            });
        }
        if body_access && processable && body_size > 0 {
            let Some(bytes) = hostcalls::get_buffer(BufferType::HttpResponseBody, 0, body_size).map_err(|_error| {
                TerminalOutcome::Incomplete {
                    phase: "response-body-buffer-hostcall",
                    status: 503,
                }
            })?
            else {
                return Err(TerminalOutcome::Incomplete {
                    phase: "response-body-buffer-unavailable",
                    status: 503,
                });
            };
            if bytes.len() != body_size {
                return Err(TerminalOutcome::Incomplete {
                    phase: "response-body-buffer-short",
                    status: 503,
                });
            }
            body = bytes;
        }
        let diagnostics_before = self.diagnostic_count();
        let interruption = self.tx.as_deref_mut().and_then(|tx| tx.process_response_body(&body));
        self.mark_diagnostic_change(diagnostics_before);
        drop(body);
        self.response_host_bytes = 0;
        self.response_copy_bytes = 0;
        self.response_engine_bytes = self.response_engine_memory_bytes();
        if !self.update_accounting() {
            return Err(TerminalOutcome::RetainedBodyBudgetExhausted {
                phase: "response-body-retention",
            });
        }
        Ok(interruption)
    }

    fn complete_blocked_response(&mut self, body_size: usize) -> Action {
        drop(self.tx.as_mut().map(|tx| tx.process_response_body(&[])));
        let Some(interruption) = self.response_interruption.clone() else {
            return self.reject_response(
                502,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::InvalidLifecycle {
                    phase: "response-block-missing-interruption",
                    status: 502,
                },
            );
        };
        self.finish_once(TerminalOutcome::Denied {
            phase: "response-headers",
            status: valid_status(interruption.status),
        });
        let result = self.replace_interruption(&interruption, body_size);
        self.response_mutation_action(result)
    }

    fn send_local_response(status: u32, headers: Vec<(&str, &str)>, body: Option<&[u8]>) -> Action {
        // Keep the request held if Envoy cannot construct the local reply.
        if let Err(status) = hostcalls::send_http_response(status, headers, body) {
            log_error(&format!("envoy-coraza: failed to send local response: {status:?}"));
        }
        Action::Pause
    }

    fn response_mutation_action(&mut self, result: Result<(), Status>) -> Action {
        if self.response_mutation_failed || result.is_err() {
            self.response_mutation_failed = true;
            Action::Pause
        } else {
            Action::Continue
        }
    }

    fn reject_interruption(
        &mut self,
        interruption: &Interruption,
        phase: &'static str,
        state_phase: InterruptionPhase,
    ) -> Action {
        let status = valid_status(interruption.status);
        let mut headers = vec![
            ("content-type", "text/plain; charset=utf-8"),
            ("cache-control", "no-store"),
        ];
        if interruption.action == "redirect" && !interruption.data.is_empty() {
            headers.push(("location", interruption.data.as_str()));
        }
        let body = if interruption.action == "redirect" || self.request_method.eq_ignore_ascii_case("HEAD") {
            &[][..]
        } else {
            REQUEST_BLOCK_BODY
        };
        self.request_mode = RequestMode::Replied;
        if let (Some(generation), Some(transaction)) = (self.generation.clone(), self.tx.as_deref()) {
            if Self::record_interruption(&generation, transaction, interruption, state_phase) {
                self.telemetry_publish_failed = true;
            }
        }
        self.finish_once(TerminalOutcome::Denied { phase, status });
        Self::send_local_response(u32::from(status), headers, Some(body))
    }

    fn reject_request(&mut self, status: u16, body: &[u8], outcome: TerminalOutcome) -> Action {
        self.request_mode = RequestMode::Replied;
        self.finish_once(outcome);
        Self::send_local_response(
            u32::from(status),
            vec![
                ("content-type", "text/plain; charset=utf-8"),
                ("cache-control", "no-store"),
            ],
            Some(if self.request_method.eq_ignore_ascii_case("HEAD") {
                &[]
            } else {
                body
            }),
        )
    }

    fn reject_response(&mut self, status: u16, body: &'static [u8], outcome: TerminalOutcome) -> Action {
        self.finish_once(outcome);
        let result = self.replace_response(status, body, self.response_body_size);
        self.response_mutation_action(result)
    }

    fn set_response_block_headers(&self, interruption: &Interruption, body: &[u8]) -> Result<(), Status> {
        let status = valid_status(interruption.status);
        let status_text = status.to_string();
        let body_length = body.len().to_string();
        let mut headers: Vec<(&str, &[u8])> = vec![(":status", status_text.as_bytes()), ("cache-control", b"no-store")];
        if interruption.action == "redirect" && !interruption.data.is_empty() {
            headers.push(("location", interruption.data.as_bytes()));
        } else if status != 204 && status != 304 && !self.request_method.eq_ignore_ascii_case("HEAD") {
            headers.push(("content-type", b"text/plain; charset=utf-8"));
            headers.push(("content-length", body_length.as_bytes()));
        }
        hostcalls::set_map_bytes(MapType::HttpResponseHeaders, headers)
    }

    fn replace_interruption(&mut self, interruption: &Interruption, prior_body_size: usize) -> Result<(), Status> {
        let status = valid_status(interruption.status);
        let body = if interruption.action == "redirect" {
            &[][..]
        } else {
            RESPONSE_BLOCK_BODY
        };
        self.response_mode = ResponseMode::Blocked;
        self.response_interruption = Some(interruption.clone());
        self.response_block_body = body;
        let no_body = status == 204 || status == 304 || self.request_method.eq_ignore_ascii_case("HEAD");
        let response_body = if no_body || interruption.action == "redirect" {
            &[][..]
        } else {
            body
        };
        self.response_block_body = response_body;
        self.set_response_block_headers(interruption, response_body)?;
        hostcalls::set_buffer(BufferType::HttpResponseBody, 0, prior_body_size, response_body)?;
        hostcalls::set_map_bytes(MapType::HttpResponseTrailers, Vec::new())
    }

    fn replace_response(&mut self, status: u16, body: &'static [u8], prior_body_size: usize) -> Result<(), Status> {
        let status = valid_status(status);
        let no_body = status == 204 || status == 304 || self.request_method.eq_ignore_ascii_case("HEAD");
        let response_body = if no_body { &[][..] } else { body };
        self.response_mode = ResponseMode::Blocked;
        self.response_block_body = response_body;
        let interruption = Interruption {
            rule_id: 0,
            action: "deny".to_owned(),
            status,
            data: String::new(),
        };
        self.set_response_block_headers(&interruption, response_body)?;
        hostcalls::set_buffer(BufferType::HttpResponseBody, 0, prior_body_size, response_body)?;
        hostcalls::set_map_bytes(MapType::HttpResponseTrailers, Vec::new())
    }

    fn finish_once(&mut self, outcome: TerminalOutcome) {
        let terminal = match self.outcome.as_ref() {
            Some(TerminalOutcome::UnmatchedAuthority | TerminalOutcome::EngineOff) => {
                self.outcome.as_ref().cloned().unwrap_or(outcome)
            },
            _ => outcome,
        };
        let diagnostics_before = self.diagnostic_count();
        let Some(failed) = self.finish_state(terminal, |tx| tx.finish().is_err()) else {
            return;
        };
        self.finalization_result = if failed {
            FinalizationResult::Failed
        } else {
            FinalizationResult::Succeeded
        };
        if failed {
            log_error("envoy-coraza: transaction finalization failed");
        }
        self.mark_diagnostic_change(diagnostics_before);
        self.publish_terminal();
    }

    fn publish_terminal(&mut self) {
        let (Some(generation), Some(final_outcome)) = (self.generation.clone(), self.final_outcome.clone()) else {
            return;
        };
        let inspection_complete = matches!(
            final_outcome,
            TerminalOutcome::Completed | TerminalOutcome::Denied { .. }
        ) && !self.request_body_truncated
            && !self.response_body_truncated;
        let reason = if self.finalization_result == FinalizationResult::Failed {
            "finalization_error"
        } else {
            self.outcome.as_ref().unwrap_or(&final_outcome).inspection_reason()
        };
        let terminal = if self.finalization_result == FinalizationResult::Failed {
            "error"
        } else {
            final_outcome.terminal_name()
        };
        if observability::health(
            generation.enable_filter_state_logs(),
            HealthState {
                inspection_complete,
                inspection_reason: reason,
                generation: generation.generation_id(),
                request_body_truncated: self.request_body_truncated,
                response_body_truncated: self.response_body_truncated,
                terminal_outcome: terminal,
                telemetry_publish_failed: self.telemetry_publish_failed,
            },
            generation.diagnostics(),
        ) {
            self.telemetry_publish_failed = true;
        }
    }

    /// Run the transaction finalizer once, retain its first outcome and release the body lease.
    /// The closure keeps this state transition testable without invoking a Proxy-Wasm hostcall.
    fn finish_state(
        &mut self,
        outcome: TerminalOutcome,
        finish_transaction: impl FnOnce(&mut Transaction) -> bool,
    ) -> Option<bool> {
        if !self.lifecycle.finish_once() {
            return None;
        }
        if let Some(tx) = self.tx.as_deref() {
            self.request_body_truncated |= tx.request_body_stats().truncated;
            self.response_body_truncated |= tx.response_body_stats().truncated;
        }
        self.final_outcome = Some(outcome.clone());
        self.outcome.get_or_insert(outcome);
        let finalization_failed = self.tx.as_deref_mut().is_some_and(finish_transaction);
        self.tx.take();
        self.release_accounting();
        Some(finalization_failed)
    }

    fn account_total(&self) -> Option<usize> {
        [
            self.request_host_bytes,
            self.response_host_bytes,
            self.request_copy_bytes,
            self.response_copy_bytes,
            self.request_engine_bytes,
            self.response_engine_bytes,
        ]
        .into_iter()
        .try_fold(0_usize, usize::checked_add)
    }

    fn response_engine_memory_bytes(&self) -> usize {
        self.tx
            .as_deref()
            .map_or(0, Transaction::body_memory_bytes)
            .saturating_sub(self.request_engine_bytes)
    }

    fn update_accounting(&mut self) -> bool {
        let Some(next) = self.account_total() else {
            return false;
        };
        let used = self.root_retained_bytes.get();
        let Some(other_streams) = used.checked_sub(self.retained_bytes) else {
            return false;
        };
        let Some(total) = other_streams.checked_add(next) else {
            return false;
        };
        if total > MAX_ROOT_RETAINED_BODY_BYTES {
            return false;
        }
        self.root_retained_bytes.set(total);
        self.retained_bytes = next;
        true
    }

    fn release_accounting(&mut self) {
        let used = self.root_retained_bytes.get();
        self.root_retained_bytes.set(used.saturating_sub(self.retained_bytes));
        self.retained_bytes = 0;
        self.request_host_bytes = 0;
        self.response_host_bytes = 0;
        self.request_copy_bytes = 0;
        self.response_copy_bytes = 0;
        self.request_engine_bytes = 0;
        self.response_engine_bytes = 0;
    }

    fn incomplete_outcome(&self) -> TerminalOutcome {
        match (self.lifecycle.request, self.lifecycle.response) {
            (RequestStage::Headers | RequestStage::Body, _) => TerminalOutcome::Incomplete {
                phase: "request-body-aborted",
                status: 503,
            },
            (_, ResponseStage::Headers | ResponseStage::Body) => TerminalOutcome::Incomplete {
                phase: "response-body-aborted",
                status: 502,
            },
            (RequestStage::Complete, ResponseStage::Waiting) => TerminalOutcome::UpstreamFailureOrCancellation,
            _ => TerminalOutcome::Completed,
        }
    }
}

impl Context for CorazaHttp {
    /// Proxy-Wasm SDK 0.2.5 exposes stream completion as `on_done`.
    fn on_done(&mut self) -> bool {
        self.finish_once(self.incomplete_outcome());
        true
    }
}

impl HttpContext for CorazaHttp {
    fn on_http_request_headers(&mut self, num_headers: usize, end_of_stream: bool) -> Action {
        self.begin_request(num_headers, end_of_stream)
    }

    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        self.request_body(body_size, end_of_stream)
    }

    fn on_http_request_trailers(&mut self, num_trailers: usize) -> Action {
        self.request_trailers(num_trailers)
    }

    fn on_http_response_headers(&mut self, num_headers: usize, end_of_stream: bool) -> Action {
        self.response_headers(num_headers, end_of_stream)
    }

    fn on_http_response_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        self.response_body(body_size, end_of_stream)
    }

    fn on_http_response_trailers(&mut self, num_trailers: usize) -> Action {
        self.response_trailers(num_trailers)
    }
}

impl Drop for CorazaHttp {
    fn drop(&mut self) {
        if !self.lifecycle.finalized {
            self.finish_once(self.incomplete_outcome());
        }
        self.tx.take();
        self.release_accounting();
    }
}

fn property(path: Vec<&str>) -> Option<Vec<u8>> {
    hostcalls::get_property(path).unwrap_or_default()
}

fn apply_connection_metadata(tx: &mut Transaction, authority: &str) {
    let (source_addr, source_port) = connection_endpoint("source");
    let (destination_addr, destination_port) = connection_endpoint("destination");
    tx.set_remote_addr(source_addr.as_bytes());
    tx.set_remote_port(source_port);
    tx.set_server_addr(destination_addr.as_bytes());
    tx.set_server_port(destination_port);
    tx.set_server_name(authority_host(authority).as_bytes());
}

fn connection_endpoint(direction: &str) -> (String, u16) {
    let address = property(vec![direction, "address"]).unwrap_or_default();
    let parsed = str::from_utf8(&address).ok().and_then(|value| {
        value
            .parse::<SocketAddr>()
            .ok()
            .map(|socket| (socket.ip(), socket.port()))
            .or_else(|| value.parse::<IpAddr>().ok().map(|ip| (ip, 0)))
    });
    let port = property(vec![direction, "port"])
        .and_then(|bytes| {
            let bytes: [u8; 8] = bytes.try_into().ok()?;
            Some(u64::from_le_bytes(bytes))
        })
        .and_then(|port| u16::try_from(port).ok())
        .or_else(|| parsed.map(|(_, port)| port))
        .unwrap_or(0);
    let ip = parsed.map(|(ip, _)| ip.to_string()).unwrap_or_default();
    (ip, port)
}

fn find_header<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_slice())
}

fn request_authority(headers: &[(String, Vec<u8>)], fallback: Option<&[u8]>) -> Vec<u8> {
    find_header(headers, ":authority")
        .or(fallback)
        .unwrap_or_default()
        .to_vec()
}

fn request_metadata(headers: &[(String, Vec<u8>)]) -> Option<RequestMetadata> {
    let method = find_header(headers, ":method")
        .map(<[u8]>::to_vec)
        .or_else(|| property(vec!["request", "method"]))?;
    let uri = find_header(headers, ":path")
        .map(<[u8]>::to_vec)
        .or_else(|| property(vec!["request", "path"]))?;
    let method = str::from_utf8(&method).ok()?.to_owned();
    let protocol = property(vec!["request", "protocol"])?;
    let protocol = str::from_utf8(&protocol).ok()?.to_owned();
    if method.is_empty() || protocol.is_empty() {
        return None;
    }
    let has_host = headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host"));
    Some(RequestMetadata {
        method,
        uri,
        protocol,
        has_host,
    })
}

fn prepare_transaction(
    stream: &mut CorazaHttp,
    policy: &Policy,
    authority: &str,
    headers: &[(String, Vec<u8>)],
    metadata: &RequestMetadata,
) -> (Option<Interruption>, bool, bool) {
    let transaction = stream.tx.get_or_insert_with(|| Box::new(policy.waf.new_transaction()));
    apply_connection_metadata(transaction, authority);
    transaction.process_uri(&metadata.uri, &metadata.method, &metadata.protocol);
    for (name, value) in headers {
        transaction.add_request_header(name, value);
    }
    if !metadata.has_host && !authority.is_empty() {
        transaction.add_request_header("host", authority.as_bytes());
    }
    let interruption = transaction.process_request_headers();
    let engine_off = transaction.rule_engine() == RuleEngineStatus::Off;
    let body_access = transaction.request_body_access();
    (interruption, engine_off, body_access)
}

fn headers_within_limits(headers: &[(String, Vec<u8>)], reported_count: usize) -> bool {
    if headers.len() > MAX_HEADER_COUNT || headers.len() > reported_count {
        return false;
    }
    headers
        .iter()
        .try_fold(0_usize, |total, (name, value)| {
            if value.len() > MAX_HEADER_VALUE_BYTES {
                return None;
            }
            total.checked_add(name.len())?.checked_add(value.len())
        })
        .is_some_and(|total| total <= MAX_HEADERS_BYTES)
}

pub(crate) fn normalize_authority(authority: &[u8], scheme: &[u8]) -> Option<String> {
    let authority = str::from_utf8(authority).ok()?;
    if authority.is_empty() {
        return Some(String::new());
    }
    let lower = authority.to_ascii_lowercase();
    let (host, port) = authority_parts(&lower)?;
    let default_port = if scheme.eq_ignore_ascii_case(b"http") {
        Some("80")
    } else if scheme.eq_ignore_ascii_case(b"https") {
        Some("443")
    } else {
        None
    };
    if port == default_port {
        Some(host.to_owned())
    } else {
        Some(lower)
    }
}

fn authority_parts(authority: &str) -> Option<(&str, Option<&str>)> {
    if authority.starts_with('[') {
        let close = authority.find(']')?;
        let host = authority.get(..=close)?;
        let address = authority.get(1..close)?.parse::<std::net::Ipv6Addr>().ok()?;
        let _ = address;
        let suffix = authority.get(close.saturating_add(1)..)?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(valid_authority_port(suffix.strip_prefix(':')?)?)
        };
        Some((host, port))
    } else {
        let mut colons = authority.match_indices(':');
        let Some((index, _)) = colons.next() else {
            return valid_reg_name(authority).then_some((authority, None));
        };
        if colons.next().is_some() {
            return None;
        }
        let host = authority.get(..index)?;
        let port = valid_authority_port(authority.get(index.saturating_add(1)..)?)?;
        valid_reg_name(host).then_some((host, Some(port)))
    }
}

fn valid_authority_port(port: &str) -> Option<&str> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    port.parse::<u16>().ok().map(|_| port)
}

fn valid_reg_name(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    let bytes = host.as_bytes();
    let mut index = 0;
    while let Some(byte) = bytes.get(index).copied() {
        if byte == b'%' {
            if !bytes
                .get(index.saturating_add(1)..index.saturating_add(3))
                .is_some_and(|escape| escape.len() == 2 && escape.iter().all(u8::is_ascii_hexdigit))
            {
                return false;
            }
            index += 3;
            continue;
        }
        if !(byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&byte)) {
            return false;
        }
        index += 1;
    }
    true
}

fn authority_host(authority: &str) -> &str {
    if authority.starts_with('[') {
        authority
            .find(']')
            .and_then(|close| authority.get(1..close))
            .unwrap_or_default()
    } else {
        authority.split_once(':').map_or(authority, |(host, _)| host)
    }
}

fn has_unsupported_content_encoding(headers: &[(String, Vec<u8>)]) -> bool {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .flat_map(|(_, value)| value.split(|byte| *byte == b','))
        .map(trim_ascii)
        .any(|encoding| !encoding.eq_ignore_ascii_case(b"identity"))
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = value.get(1..).unwrap_or_default();
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = value.get(..value.len().saturating_sub(1)).unwrap_or_default();
    }
    value
}

fn has_upgrade(headers: &[(String, Vec<u8>)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("upgrade")
            || (name.eq_ignore_ascii_case("connection")
                && value
                    .split(|byte| *byte == b',')
                    .map(trim_ascii)
                    .any(|token| token.eq_ignore_ascii_case(b"upgrade")))
    })
}

fn request_inspection_incomplete(tx: &Transaction) -> bool {
    tx.inspection_incomplete() || tx.arguments_limit_reached()
}

fn response_inspection_incomplete(tx: &Transaction) -> bool {
    tx.inspection_incomplete()
}

fn valid_status(status: u16) -> u16 {
    if (200..=599).contains(&status) {
        status
    } else {
        403
    }
}

fn log_error(message: &str) {
    hostcalls::log(LogLevel::Error, message).unwrap_or_default();
}

fn log_warn(message: &str) {
    hostcalls::log(LogLevel::Warn, message).unwrap_or_default();
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "Lifecycle tests use fixed values.")]
mod tests {
    use std::{cell::Cell, rc::Rc};

    use proxy_wasm::types::{Action, Status};

    use super::{
        normalize_authority, request_authority, CorazaHttp, Lifecycle, RequestMode, RequestStage, ResponseStage,
        TerminalOutcome, MAX_HEADER_COUNT, MAX_REQUEST_BODY_BYTES, MAX_ROOT_RETAINED_BODY_BYTES,
    };
    use crate::{config::Config, policy::Generation};

    #[test]
    fn lifecycle_runs_each_http_phase_and_finalization_once() {
        let mut state = Lifecycle::default();
        assert!(state.begin_request());
        assert!(!state.begin_request(), "duplicate request headers are ignored");
        assert!(state.request_body());
        assert!(state.request_body(), "cumulative body callbacks remain permitted");
        assert!(state.complete_request());
        assert!(!state.complete_request(), "phase 2 is once-only");
        assert!(state.begin_response());
        assert!(state.response_body());
        assert!(state.complete_response());
        assert!(!state.complete_response(), "phase 4 is once-only");
        assert!(state.finish_once());
        assert!(!state.finish_once(), "phase 5 is once-only");
    }

    #[test]
    fn failed_response_mutations_stay_paused() {
        let mut stream = CorazaHttp::new(None, Rc::new(Cell::new(0)));
        assert_eq!(
            stream.response_mutation_action(Err(Status::InternalFailure)),
            Action::Pause
        );
        assert!(stream.response_mutation_failed);
        assert_eq!(
            stream.response_mutation_action(Ok(())),
            Action::Pause,
            "a later callback cannot release a response after a partial rewrite failed"
        );
    }

    #[test]
    fn finalized_local_reply_continues_but_failed_response_mutation_stays_paused() {
        let mut local_reply = CorazaHttp::new(None, Rc::new(Cell::new(0)));
        local_reply.lifecycle.finalized = true;
        local_reply.request_mode = RequestMode::Replied;
        assert_eq!(local_reply.response_headers(0, true), Action::Continue);
        assert_eq!(local_reply.response_body(35, true), Action::Continue);
        assert_eq!(local_reply.response_trailers(0), Action::Continue);

        let mut failed_mutation = CorazaHttp::new(None, Rc::new(Cell::new(0)));
        failed_mutation.lifecycle.finalized = true;
        failed_mutation.response_mutation_failed = true;
        assert_eq!(failed_mutation.response_headers(0, true), Action::Pause);
        assert_eq!(failed_mutation.response_body(35, true), Action::Pause);
        assert_eq!(failed_mutation.response_trailers(0), Action::Pause);
    }

    #[test]
    fn impossible_callbacks_do_not_advance_the_lifecycle() {
        let mut state = Lifecycle::default();
        assert!(!state.request_body(), "body cannot precede request headers");
        assert!(!state.begin_response(), "response cannot precede request completion");
        assert!(state.begin_request());
        assert!(!state.begin_response(), "response cannot precede phase 2");
        assert!(state.request_body());
        assert!(state.complete_request());
        assert!(!state.response_body(), "body cannot precede response headers");
        assert!(state.begin_response());
        assert!(state.complete_response());
        assert_eq!(state.request, RequestStage::Complete);
        assert_eq!(state.response, ResponseStage::Complete);
    }

    #[test]
    fn request_body_access_off_completes_phase_two_at_headers_without_retaining_body() {
        let config = Config::parse(
            br#"{"directives_map":{"p":["SecRequestBodyAccess Off","SecRule REQUEST_METHOD \"@streq POST\" \"id:91,phase:2,pass\""]},"default_directives":"p"}"#,
        )
        .expect("configuration is valid");
        let generation = Rc::new(Generation::compile(config).expect("policy compiles"));
        let policy = generation.select("example.test").expect("default policy selected");
        let mut transaction = policy.waf.new_transaction();
        transaction.process_uri("/", "POST", "HTTP/1.1");
        transaction.process_request_headers();

        let root = Rc::new(Cell::new(0));
        let mut stream = CorazaHttp::new(Some(generation), Rc::clone(&root));
        stream.tx = Some(Box::new(transaction));
        assert!(stream.lifecycle.begin_request());

        assert_eq!(stream.request_body_action_after_headers(false, false), Action::Continue);
        assert_eq!(stream.lifecycle.request, RequestStage::Complete);
        let tx = stream.tx.as_deref().expect("transaction remains available");
        assert!(
            tx.matched_rules().iter().any(|matched| matched.rule_id() == 91),
            "phase 2 ran with the empty body"
        );
        assert_eq!(tx.request_body_stats().retained, 0, "the request body was not retained");
        assert_eq!(stream.request_host_bytes, 0, "no host body buffer is charged");
        assert_eq!(stream.request_copy_bytes, 0, "no guest body copy is charged");
        let retained_before = root.get();

        let matches_before = tx.matched_rules().len();
        assert_eq!(stream.request_body(MAX_REQUEST_BODY_BYTES + 1, true), Action::Continue);
        assert_eq!(
            stream
                .tx
                .as_deref()
                .expect("transaction remains available")
                .matched_rules()
                .len(),
            matches_before
        );
        assert_eq!(
            root.get(),
            retained_before,
            "later body callbacks add no retained bytes"
        );
    }

    #[test]
    fn request_trailers_are_validated_after_body_phase_completed() {
        let mut stream = CorazaHttp::new(None, Rc::new(Cell::new(0)));
        stream.lifecycle.request = RequestStage::Complete;

        let action = stream.request_trailers(MAX_HEADER_COUNT + 1);

        assert_eq!(action, Action::Pause, "failed local reply mutation stays paused");
        assert_eq!(
            stream.final_outcome,
            Some(TerminalOutcome::Incomplete {
                phase: "request-trailers",
                status: 431,
            }),
            "the trailer limit is checked even after phase 2 completed"
        );
        assert!(stream.lifecycle.finalized);
    }

    #[test]
    fn authority_normalization_covers_case_default_ports_and_ipv6() {
        assert_eq!(
            normalize_authority(b"a.example:80", b"https").as_deref(),
            Some("a.example:80"),
            "port 80 is not default for HTTPS"
        );
        assert_eq!(
            normalize_authority(b"a.example:443", b"http").as_deref(),
            Some("a.example:443"),
            "port 443 is not default for HTTP"
        );
        assert_eq!(
            normalize_authority(b"WAF.EXAMPLE:80", b"http").as_deref(),
            Some("waf.example")
        );
        assert_eq!(
            normalize_authority(b"WAF.EXAMPLE:8443", b"https").as_deref(),
            Some("waf.example:8443")
        );
        assert_eq!(
            normalize_authority(b"[2001:DB8::1]:443", b"https").as_deref(),
            Some("[2001:db8::1]")
        );
        assert_eq!(
            normalize_authority(b"[2001:DB8::1]", b"http").as_deref(),
            Some("[2001:db8::1]")
        );
    }

    #[test]
    fn malformed_and_missing_authority_paths_are_explicit() {
        assert_eq!(
            normalize_authority(b"\xff", b"http"),
            None,
            "invalid UTF-8 fails closed"
        );
        assert_eq!(
            normalize_authority(b"a.example/path", b"http"),
            None,
            "path syntax is invalid"
        );
        assert_eq!(
            normalize_authority(b"a.example:65536", b"http"),
            None,
            "port is out of range"
        );
        assert_eq!(normalize_authority(b"", b"http").as_deref(), Some(""));

        let headers = vec![(":method".to_owned(), b"GET".to_vec())];
        assert_eq!(
            request_authority(&headers, Some(b"fallback.example")),
            b"fallback.example"
        );
        assert_eq!(
            request_authority(&headers, None),
            b"",
            "an absent authority stays empty"
        );
    }

    #[test]
    fn production_accounting_caps_each_root_context_and_releases_on_finish() {
        let root = Rc::new(Cell::new(0_usize));
        let mut first = CorazaHttp::new(None, Rc::clone(&root));
        let mut second = CorazaHttp::new(None, Rc::clone(&root));
        first.request_host_bytes = MAX_ROOT_RETAINED_BODY_BYTES / 2;
        second.request_host_bytes = MAX_ROOT_RETAINED_BODY_BYTES / 2;
        assert!(first.update_accounting());
        assert!(second.update_accounting());
        assert_eq!(root.get(), MAX_ROOT_RETAINED_BODY_BYTES);

        second.request_host_bytes += 1;
        assert!(!second.update_accounting());
        second.request_host_bytes -= 1;
        assert_eq!(first.finish_state(TerminalOutcome::Completed, |_| false), Some(false));
        second.request_host_bytes += 1;
        assert!(second.update_accounting());
        assert_eq!(second.finish_state(TerminalOutcome::Completed, |_| false), Some(false));
        assert_eq!(root.get(), 0);
    }

    #[test]
    fn terminal_outcome_is_retained_and_finish_releases_accounting_once() {
        let root = Rc::new(Cell::new(0_usize));
        let mut stream = CorazaHttp::new(None, Rc::clone(&root));
        stream.response_host_bytes = 4096;
        assert!(stream.update_accounting());

        let incomplete = TerminalOutcome::Incomplete {
            phase: "response-body-aborted",
            status: 502,
        };
        assert_eq!(stream.finish_state(incomplete.clone(), |_| false), Some(false));
        assert_eq!(stream.finish_state(TerminalOutcome::Completed, |_| false), None);
        assert_eq!(stream.outcome.as_ref(), Some(&incomplete));
        assert_eq!(stream.final_outcome.as_ref(), Some(&incomplete));
        assert_eq!(root.get(), 0);
    }

    #[test]
    fn terminal_health_values_are_closed_and_keep_the_final_outcome() {
        let partial = TerminalOutcome::BodyPartiallyInspected { phase: "request-body" };
        assert_eq!(partial.inspection_reason(), "body_partially_inspected");
        assert_eq!(partial.terminal_name(), "incomplete");
        assert!(!partial.is_error());

        let reset = TerminalOutcome::UpstreamFailureOrCancellation;
        assert_eq!(reset.inspection_reason(), "upstream_failure_or_cancellation");
        assert_eq!(reset.terminal_name(), "upstream_failure_or_cancellation");
        assert!(reset.is_error());

        let root = Rc::new(Cell::new(0_usize));
        let mut stream = CorazaHttp::new(None, root);
        stream.outcome = Some(partial.clone());
        let denied = TerminalOutcome::Denied {
            phase: "response-headers",
            status: 403,
        };
        assert_eq!(stream.finish_state(denied.clone(), |_| false), Some(false));
        assert_eq!(
            stream.outcome.as_ref(),
            Some(&partial),
            "first inspection reason is retained"
        );
        assert_eq!(
            stream.final_outcome.as_ref(),
            Some(&denied),
            "the terminal result stays distinct"
        );
        assert_eq!(denied.terminal_name(), "denied");
    }

    #[test]
    fn incomplete_finish_finalizes_once_before_releasing_the_root_charge() {
        let config = Config::parse(
            br#"{"directives_map":{"p":["SecRequestBodyAccess On","SecRequestBodyLimit 64"]},"default_directives":"p"}"#,
        )
        .expect("the body policy is valid");
        let generation = Rc::new(Generation::compile(config).expect("the policy compiles"));
        let policy = generation
            .select("example.test")
            .expect("the default policy is selected");
        let mut transaction = policy.waf.new_transaction();
        transaction.process_uri("/", "POST", "HTTP/1.1");
        transaction.add_request_header("content-type", b"application/x-www-form-urlencoded");
        transaction.process_request_headers();
        transaction.process_request_body(b"field=value");

        let retained = usize::try_from(transaction.request_body_stats().retained).expect("small test body");
        let engine_bytes = transaction.body_memory_bytes();
        assert!(
            engine_bytes > retained,
            "raw and parsed variables remain beside the body buffer"
        );

        let root = Rc::new(Cell::new(0_usize));
        let mut stream = CorazaHttp::new(Some(generation), Rc::clone(&root));
        stream.tx = Some(Box::new(transaction));
        stream.request_host_bytes = retained;
        stream.request_copy_bytes = retained;
        stream.request_engine_bytes = engine_bytes;
        assert!(stream.update_accounting());
        assert_eq!(root.get(), engine_bytes + retained * 2);

        stream.request_host_bytes = 0;
        stream.request_copy_bytes = 0;
        assert!(stream.update_accounting());
        {
            let tx = stream.tx.as_mut().expect("the transaction is retained");
            assert!(tx.process_response_headers(200, "HTTP/1.1").is_none());
            assert!(tx.process_response_body(b"response").is_none());
        }
        let all_engine_bytes = stream
            .tx
            .as_ref()
            .expect("the transaction is retained")
            .body_memory_bytes();
        stream.response_host_bytes = 8;
        stream.response_copy_bytes = 8;
        stream.response_engine_bytes = stream.response_engine_memory_bytes();
        assert_eq!(
            stream.request_engine_bytes + stream.response_engine_bytes,
            all_engine_bytes
        );
        assert!(stream.update_accounting());
        assert_eq!(
            root.get(),
            all_engine_bytes + 16,
            "request allocations are not charged twice"
        );

        let aborted = TerminalOutcome::Incomplete {
            phase: "response-body-aborted",
            status: 502,
        };
        stream.lifecycle.request = RequestStage::Complete;
        stream.lifecycle.response = ResponseStage::Body;
        assert_eq!(stream.incomplete_outcome(), aborted);
        let finish_calls = Cell::new(0);
        assert_eq!(
            stream.finish_state(aborted.clone(), |tx| {
                finish_calls.set(finish_calls.get() + 1);
                assert_eq!(
                    root.get(),
                    all_engine_bytes + 16,
                    "the lease remains charged during finish"
                );
                assert!(tx.finish().is_ok());
                assert_eq!(tx.request_body_stats().retained, 0, "finish clears the body buffer");
                assert!(
                    tx.body_memory_bytes() > 0,
                    "raw and parsed variables are still live after finish"
                );
                false
            }),
            Some(false)
        );

        assert_eq!(
            stream.finish_state(TerminalOutcome::Completed, |tx| {
                finish_calls.set(finish_calls.get() + 1);
                tx.finish().is_err()
            }),
            None
        );
        assert_eq!(
            finish_calls.get(),
            1,
            "a repeated terminal callback does not finish again"
        );
        assert_eq!(stream.outcome.as_ref(), Some(&aborted));
        assert!(stream.tx.is_none(), "the charged transaction is dropped before release");
        assert_eq!(root.get(), 0, "the charge is released only after that drop");
    }

    #[test]
    fn on_done_classifies_incomplete_body_and_unobserved_upstream_end() {
        let mut request = CorazaHttp::new(None, Rc::new(Cell::new(0)));
        request.lifecycle.request = RequestStage::Body;
        assert_eq!(
            request.incomplete_outcome(),
            TerminalOutcome::Incomplete {
                phase: "request-body-aborted",
                status: 503,
            }
        );

        let mut response = CorazaHttp::new(None, Rc::new(Cell::new(0)));
        response.lifecycle.request = RequestStage::Complete;
        response.lifecycle.response = ResponseStage::Body;
        assert_eq!(
            response.incomplete_outcome(),
            TerminalOutcome::Incomplete {
                phase: "response-body-aborted",
                status: 502,
            }
        );

        let mut upstream = CorazaHttp::new(None, Rc::new(Cell::new(0)));
        upstream.lifecycle.request = RequestStage::Complete;
        assert_eq!(
            upstream.incomplete_outcome(),
            TerminalOutcome::UpstreamFailureOrCancellation
        );
    }

    #[test]
    fn drop_releases_retained_bytes_when_done_callback_is_missing() {
        let root = Rc::new(Cell::new(0_usize));
        let mut stream = CorazaHttp::new(None, Rc::clone(&root));
        stream.request_host_bytes = 1024;
        assert!(stream.update_accounting());
        assert_eq!(root.get(), 1024);
        drop(stream);
        assert_eq!(root.get(), 0);
    }
}
