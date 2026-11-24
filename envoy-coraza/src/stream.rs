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
    borrow::Cow,
    cell::Cell,
    fmt::Write as _,
    io::Write as _,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    rc::Rc,
    str,
};

use coraza::{
    transaction::{BodyCopy, Interruption, Transaction},
    types::{RuleEngineStatus, RuleVariable},
};
use proxy_wasm::{
    hostcalls,
    traits::{Context, HttpContext},
    types::{Action, BufferType, LogLevel, MapType, Status},
};

use crate::{
    observability::{self, HealthState, InterruptionPhase},
    policy::{split_port, Generation, Policy},
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

const REQUEST_BLOCK_BODY: &[u8] = b"";
const RESPONSE_BLOCK_BODY: &[u8] = b"Upstream response blocked\n";
const REQUEST_INCOMPLETE_BODY: &[u8] = b"Request inspection unavailable\n";
const RESPONSE_INCOMPLETE_BODY: &[u8] = b"Response inspection unavailable\n";
const UNSUPPORTED_BODY: &[u8] = b"Request feature is not supported\n";

/// Whether a body processor reported an error on the request body of `tx`: it stopped where it failed, so what
/// follows was not inspected, and the XML processor, which drops a document it refuses whole, kept none of it.
fn body_processor_failed(tx: &Transaction) -> bool {
    tx.get_variable(RuleVariable::ReqbodyError, None).as_deref() == Some("1")
}

/// Whether the request body of `tx` has the XML processor, which drops a document it refuses whole.
fn xml_processor(tx: &Transaction) -> bool {
    tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref() == Some("XML")
}

/// Terminal or explicitly incomplete outcome retained for Stage E publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TerminalOutcome {
    /// No configured policy matched; traffic continued uninspected.
    UnmatchedAuthority,
    /// No configured policy matched, and the configuration refuses such requests.
    UnmatchedAuthorityRefused,
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
    /// A body processor or the rules of the body phase stopped at the memory budget the root left them, so only what
    /// the parser had parsed was inspected, or the rules after the stop were not evaluated.
    BodyMemoryBudgetStopped { phase: &'static str },
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
            Self::UnmatchedAuthority | Self::UnmatchedAuthorityRefused => "unmatched_authority",
            Self::EngineOff => "engine_off",
            Self::Unsupported(_) => "unsupported",
            Self::Denied { .. } => "denied",
            Self::Incomplete { .. } => "incomplete",
            Self::BodyTooLarge { .. } => "body_too_large",
            Self::BodyPartiallyInspected { .. } => "body_partially_inspected",
            Self::BodyMemoryBudgetStopped { .. } => "body_memory_budget_stopped",
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
            Self::Incomplete { .. } | Self::BodyPartiallyInspected { .. } | Self::BodyMemoryBudgetStopped { .. } => {
                "incomplete"
            },
            Self::UnmatchedAuthorityRefused
            | Self::BodyTooLarge { .. }
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
                | Self::UnmatchedAuthorityRefused
                | Self::BodyMemoryBudgetStopped { .. }
                | Self::BodyTooLarge { .. }
                | Self::RetainedBodyBudgetExhausted { .. }
                | Self::InvalidLifecycle { .. }
                | Self::InvalidAuthority { .. }
                | Self::UpstreamFailureOrCancellation
        )
    }
}

/// Whether a policy with request body access off let request body bytes through unread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnreadRequestBody {
    /// The policy reads the body, or the request ended without one.
    Absent,
    /// The headers did not end the request, so body bytes may still follow.
    Pending,
    /// The filter released body bytes; a later Envoy filter could still hold them, so they may not have reached the
    /// backend.
    Passed,
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

/// Whether the connector has refused the upstream response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseMode {
    /// Preserve response bytes unless a later phase denies them.
    Inspect,
    /// A local reply answered the response: nothing upstream sends is released, whether or not the reply was sent.
    Refused,
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
    request_body_failed: bool,
    unread_request_body: UnreadRequestBody,
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
            request_body_failed: false,
            unread_request_body: UnreadRequestBody::Absent,
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

    fn record_interruption(&mut self, interruption: &Interruption, phase: InterruptionPhase) {
        if let (Some(generation), Some(transaction)) = (self.generation.as_deref(), self.tx.as_deref()) {
            if observability::interruption(
                generation.enable_filter_state_logs(),
                transaction,
                interruption,
                phase,
                generation.diagnostics(),
            ) {
                self.telemetry_publish_failed = true;
            }
        }
    }

    /// What a request callback answers once the stream no longer inspects it: only a request the filter already
    /// released goes on. One it still held stays held, so a stream finalized on the response side (Envoy's own timeout
    /// reply) or by the filter's own reply never lets an uninspected request through. After a refusal in either
    /// direction nothing more of the request goes on, even when the reply could not be sent, so the unread rest of a
    /// body never reaches the backend.
    fn released_request_action(&self) -> Action {
        if self.request_mode != RequestMode::Replied
            && self.response_mode != ResponseMode::Refused
            && matches!(self.lifecycle.request, RequestStage::Complete | RequestStage::Bypassed)
        {
            Action::Continue
        } else {
            Action::Pause
        }
    }

    fn begin_request(&mut self, num_headers: usize, end_of_stream: bool) -> Action {
        if self.request_mode == RequestMode::Replied || !self.lifecycle.begin_request() {
            return self.released_request_action();
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
        // A host failure on a property that feeds inspection must not read as an absent value.
        let fallback_authority = match find_header(headers, ":authority") {
            Some(_) => None,
            None => match property(vec!["request", "host"]) {
                Ok(host) => host,
                Err(error) => return self.reject_property_hostcall(&error),
            },
        };
        let raw_authority = request_authority(headers, fallback_authority.as_deref());
        let scheme = match find_header(headers, ":scheme") {
            Some(scheme) => scheme.to_vec(),
            None => match property(vec!["request", "scheme"]) {
                Ok(scheme) => scheme.unwrap_or_default(),
                Err(error) => return self.reject_property_hostcall(&error),
            },
        };
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
            return self.unmatched_authority(generation);
        };
        self.selected_policy = Some(policy_name.to_owned());
        self.tx = Some(Box::new(policy.waf.new_transaction()));

        let metadata = match request_metadata(headers) {
            Ok(Some(metadata)) => metadata,
            Err(error) => return self.reject_property_hostcall(&error),
            Ok(None) => {
                return self.reject_request(
                    503,
                    REQUEST_INCOMPLETE_BODY,
                    TerminalOutcome::Incomplete {
                        phase: "request-metadata",
                        status: 503,
                    },
                );
            },
        };
        metadata.method.clone_into(&mut self.request_method);
        metadata.protocol.clone_into(&mut self.request_protocol);
        let diagnostics_before = self.diagnostic_count();
        let prepared = prepare_transaction(self, policy, authority_text, headers, &metadata);
        self.mark_diagnostic_change(diagnostics_before);
        let (interruption, engine_off, body_access) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return self.reject_property_hostcall(&error),
        };

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

    /// Refuses a request whose authority selects no policy with 421, or passes it uninspected when the configuration
    /// allows that or has no policies.
    fn unmatched_authority(&mut self, generation: &Generation) -> Action {
        if generation.refuses_unmatched() {
            if generation.first_unmatched_request() {
                log_warn(
                    "envoy-coraza: no authority policy matched; request refused with 421 (set \
                     \"unmatched_authority\": \"allow\" to pass such requests uninspected; further such requests in \
                     this configuration generation are logged at debug level)",
                );
            } else {
                log_debug("envoy-coraza: no authority policy matched; request refused with 421");
            }
            return self.reject_request(421, REQUEST_INCOMPLETE_BODY, TerminalOutcome::UnmatchedAuthorityRefused);
        }
        self.lifecycle.bypass_request();
        self.request_mode = RequestMode::Uninspected;
        self.outcome = Some(TerminalOutcome::UnmatchedAuthority);
        if generation.first_unmatched_request() {
            log_warn(
                "envoy-coraza: no authority policy matched; request passed uninspected \
                 (further such requests in this configuration generation are logged at debug level)",
            );
        } else {
            log_debug("envoy-coraza: no authority policy matched; request passed uninspected");
        }
        Action::Continue
    }

    /// Complete phase 2 at headers when the engine will not ingest the request body.
    fn request_body_action_after_headers(&mut self, body_access: bool, end_of_stream: bool) -> Action {
        if !body_access && !end_of_stream {
            self.unread_request_body = UnreadRequestBody::Pending;
        }
        if !body_access || end_of_stream {
            self.complete_request_body(0)
        } else {
            Action::Pause
        }
    }

    fn complete_request_body(&mut self, body_size: usize) -> Action {
        if self.lifecycle.finalized {
            return self.released_request_action();
        }
        if self.request_mode == RequestMode::Uninspected {
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
        // The rules of the phase were stopped by the budget the root left them: the rules after the stop were not
        // evaluated, so the request is refused whatever the engine mode, as the engine's own interruption would say
        // in the default mode and a would-be one in `DetectionOnly` does not.
        if self
            .tx
            .as_ref()
            .is_some_and(|tx| tx.rule_evaluation_stopped_by_memory_budget())
        {
            return self.reject_request(
                503,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::BodyMemoryBudgetStopped { phase: "request-body" },
            );
        }
        if let Some(interruption) = interruption {
            return self.reject_interruption(&interruption, "request-body", InterruptionPhase::RequestBody);
        }
        // The budget is the connector's own limit: what the parser did not reach was not inspected, whatever the
        // policy's rules or engine mode, so the body is not forwarded.
        if self
            .tx
            .as_ref()
            .is_some_and(|tx| tx.request_body_stopped_by_memory_budget())
        {
            return self.reject_request(
                503,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::BodyMemoryBudgetStopped { phase: "request-body" },
            );
        }
        if self.tx.as_ref().is_some_and(|tx| tx.arguments_limit_reached()) {
            return self.reject_request(
                413,
                REQUEST_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "request-body-inspection",
                    status: 413,
                },
            );
        }
        // A processor that failed part way, and no rule denied: the budget and the argument limit are refused above,
        // and a rule that denies on `REQBODY_ERROR` has refused the request, so the policy lets it pass, and the
        // part of the body the processor did not read, or all of an XML document, was not inspected. A body the limit
        // cut keeps the truncation as its reason: its parse error comes from the cut, and what the processor read
        // before it stays inspected. The XML processor keeps nothing of a document it refuses, so for it the failure
        // is the reason, whatever its cause.
        let truncated = self.tx.as_ref().is_some_and(|tx| tx.request_body_stats().truncated);
        self.request_body_failed = self
            .tx
            .as_deref()
            .is_some_and(|tx| body_processor_failed(tx) && (!truncated || xml_processor(tx)));
        if truncated {
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
        let ingests = body_access && body_size > 0;
        let lease = match self.tx.as_deref() {
            Some(tx) => BodyLease::new(
                ingests,
                body_size,
                tx.request_body_limit(),
                tx.request_body_copy(),
                tx.body_memory_bytes(),
            ),
            None => BodyLease::default(),
        };
        self.request_host_bytes = body_size;
        if ingests {
            self.request_copy_bytes = body_size;
        }
        self.request_engine_bytes = lease.engine_before_parsing;
        if !self.update_accounting() {
            return Err(TerminalOutcome::RetainedBodyBudgetExhausted { phase: "request-body" });
        }
        let body = if ingests {
            Self::copy_request_body(body_size).map_err(|phase| TerminalOutcome::Incomplete { phase, status: 503 })?
        } else {
            Vec::new()
        };
        let budget = self.parse_budget(lease.after_parsing);
        let diagnostics_before = self.diagnostic_count();
        let interruption = self.tx.as_deref_mut().and_then(|tx| {
            tx.set_body_memory_budget(Some(budget));
            tx.process_request_body(&body)
        });
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
            return self.released_request_action();
        }
        if self.request_mode == RequestMode::Uninspected {
            return Action::Continue;
        }
        if self.lifecycle.request == RequestStage::Complete {
            // Only a policy that does not read the body completes the request before its body ends.
            self.unread_request_body = match self.unread_request_body {
                UnreadRequestBody::Pending if body_size > 0 => UnreadRequestBody::Passed,
                // An HTTP/2 request can end with an empty DATA frame: its body was empty, so nothing went unread.
                UnreadRequestBody::Pending if end_of_stream => UnreadRequestBody::Absent,
                unread => unread,
            };
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
            return self.released_request_action();
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
            // Trailers end a request whose body never came, so nothing went unread.
            if self.unread_request_body == UnreadRequestBody::Pending {
                self.unread_request_body = UnreadRequestBody::Absent;
            }
            Action::Continue
        } else {
            self.complete_request_body(self.request_body_size)
        }
    }

    fn response_headers(&mut self, num_headers: usize, end_of_stream: bool) -> Action {
        if self.response_mode == ResponseMode::Refused {
            return Action::Pause;
        }
        if self.lifecycle.finalized || self.request_mode != RequestMode::Inspect || self.tx.is_none() {
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
            return self.refuse_response(
                502,
                None,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "response-headers",
                    status: 502,
                },
            );
        }
        let Ok(headers) = hostcalls::get_map_bytes(MapType::HttpResponseHeaders) else {
            return self.refuse_response(
                502,
                None,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "response-headers-hostcall",
                    status: 502,
                },
            );
        };
        if !headers_within_limits(&headers, num_headers) {
            return self.refuse_response(
                502,
                None,
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
                // An unreadable status property already fails closed as a missing status.
                property(vec!["response", "code"])
                    .ok()
                    .flatten()
                    .and_then(|value| str::from_utf8(&value).ok()?.parse::<u16>().ok())
            });
        let Some(status) = status else {
            return self.refuse_response(
                502,
                None,
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
        if matches!(self.lifecycle.request, RequestStage::Headers | RequestStage::Body) {
            // The filter still holds the request, so no upstream saw it: this is Envoy's own reply, such as the 408 of
            // a timeout. It reaches the client as Envoy wrote it, and the held request stays held.
            self.request_mode = RequestMode::Replied;
            self.finish_once(self.incomplete_outcome());
            return Action::Continue;
        }
        if status == 101 {
            return self.refuse_response(
                501,
                None,
                UNSUPPORTED_BODY,
                TerminalOutcome::Unsupported("response-upgrade"),
            );
        }
        if !self.lifecycle.begin_response() {
            return self.refuse_response(
                503,
                None,
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
            return self.refuse_response_interruption(
                &interruption,
                "response-headers",
                InterruptionPhase::ResponseHeaders,
            );
        }
        let inspects_body = self
            .tx
            .as_deref()
            .is_some_and(|tx| tx.response_body_access() && tx.is_response_body_processable());
        if inspects_body && has_unsupported_content_encoding(headers) {
            return self.refuse_response(
                502,
                None,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::Unsupported("response-content-encoding"),
            );
        }
        // Phase 4 runs now when no body will be inspected; otherwise the headers wait for the body's verdict.
        if end_of_stream || !inspects_body {
            return self.complete_response_body(0);
        }
        Action::Pause
    }

    fn response_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if self.response_mode == ResponseMode::Refused {
            return Action::Pause;
        }
        if self.request_mode == RequestMode::Replied {
            return if self.lifecycle.finalized {
                Action::Continue
            } else {
                Action::Pause
            };
        }
        if self.request_mode != RequestMode::Inspect
            || self.lifecycle.finalized
            || self.tx.is_none()
            || self.lifecycle.response == ResponseStage::Complete
        {
            return Action::Continue;
        }
        if !self.lifecycle.response_body() {
            return self.refuse_response(
                503,
                None,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::InvalidLifecycle {
                    phase: "response-body-before-headers",
                    status: 503,
                },
            );
        }
        if body_size < self.response_body_size {
            return self.refuse_response(
                502,
                None,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::InvalidLifecycle {
                    phase: "response-body-size-regressed",
                    status: 502,
                },
            );
        }
        self.response_body_size = body_size;
        // Only a body the policy inspects is held, so every body seen here is one.
        if body_size > MAX_RESPONSE_BODY_BYTES {
            return self.refuse_response(
                502,
                None,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::BodyTooLarge {
                    phase: "response-body",
                    status: 502,
                },
            );
        }
        self.response_host_bytes = body_size;
        if !self.update_accounting() {
            return self.refuse_response(
                503,
                None,
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
        if self.response_mode == ResponseMode::Refused {
            return Action::Pause;
        }
        if self.request_mode == RequestMode::Replied {
            return if self.lifecycle.finalized {
                Action::Continue
            } else {
                Action::Pause
            };
        }
        if self.request_mode != RequestMode::Inspect
            || self.lifecycle.finalized
            || self.tx.is_none()
            || self.lifecycle.response == ResponseStage::Complete
        {
            return Action::Continue;
        }
        if !matches!(self.lifecycle.response, ResponseStage::Headers | ResponseStage::Body) {
            return self.refuse_response(
                503,
                None,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::InvalidLifecycle {
                    phase: "response-trailers-order",
                    status: 503,
                },
            );
        }
        if num_trailers > MAX_HEADER_COUNT {
            return self.refuse_response(
                502,
                None,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "response-trailers",
                    status: 502,
                },
            );
        }
        let Ok(trailers) = hostcalls::get_map_bytes(MapType::HttpResponseTrailers) else {
            return self.refuse_response(
                502,
                None,
                RESPONSE_INCOMPLETE_BODY,
                TerminalOutcome::Incomplete {
                    phase: "response-trailers-hostcall",
                    status: 502,
                },
            );
        };
        if !headers_within_limits(&trailers, num_trailers) {
            return self.refuse_response(
                502,
                None,
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

        let body_access = self.tx.as_deref().is_some_and(Transaction::response_body_access);
        let processable = self
            .tx
            .as_deref()
            .is_some_and(Transaction::is_response_body_processable);
        let fetch = |size| hostcalls::get_buffer(BufferType::HttpResponseBody, 0, size);
        let inspected = self.inspect_response_body(body_size, body_access, processable, fetch);
        let rules_stopped = self
            .tx
            .as_deref()
            .is_some_and(Transaction::rule_evaluation_stopped_by_memory_budget);
        let interruption = match inspected {
            Ok(interruption) => interruption,
            // The check of the root after the phase can fail first when the rules were stopped (the reserve a stopped
            // parse leaves them can outlast the body copies that are released), which is still the stop of the rules.
            Err(_) if rules_stopped => return self.refuse_response_budget_stopped(),
            Err(outcome) => return self.refuse_response(503, None, RESPONSE_INCOMPLETE_BODY, outcome),
        };
        // The rules of the phase were stopped by the budget the root left them: the response is replaced, whatever the
        // engine mode, as a request is refused.
        if rules_stopped {
            return self.refuse_response_budget_stopped();
        }
        if let Some(interruption) = interruption {
            return self.refuse_response_interruption(&interruption, "response-body", InterruptionPhase::ResponseBody);
        }
        // The budget is the connector's own limit, not a policy's: a response its parser stopped in has been inspected
        // only in part, and no rule need read `RES_BODY_ERROR` (the recommended configuration's reads only
        // `REQBODY_ERROR`), so it is not forwarded as if it had been inspected.
        if self
            .tx
            .as_ref()
            .is_some_and(|tx| tx.response_body_stopped_by_memory_budget())
        {
            return self.refuse_response_budget_stopped();
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
        fetch: impl FnOnce(usize) -> Result<Option<Vec<u8>>, Status>,
    ) -> Result<Option<Interruption>, TerminalOutcome> {
        let mut body = Vec::new();
        let ingests = body_access && processable && body_size > 0;
        let lease = match self.tx.as_deref() {
            Some(tx) => BodyLease::new(
                ingests,
                body_size,
                tx.response_body_limit(),
                tx.response_body_copy(),
                self.response_engine_memory_bytes(),
            ),
            None => BodyLease::default(),
        };
        if ingests {
            self.response_copy_bytes = body_size;
        }
        self.response_engine_bytes = lease.engine_before_parsing;
        if !self.update_accounting() {
            return Err(TerminalOutcome::RetainedBodyBudgetExhausted {
                phase: "response-body-copy",
            });
        }
        if ingests {
            let Some(bytes) = fetch(body_size).map_err(|_error| TerminalOutcome::Incomplete {
                phase: "response-body-buffer-hostcall",
                status: 503,
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
        let budget = self.parse_budget(lease.after_parsing);
        let diagnostics_before = self.diagnostic_count();
        let interruption = self.tx.as_deref_mut().and_then(|tx| {
            tx.set_body_memory_budget(Some(budget));
            tx.process_response_body(&body)
        });
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

    fn send_local_response(status: u32, headers: Vec<(&str, &str)>, body: Option<&[u8]>) -> Action {
        // Keep the stream held if Envoy cannot construct the local reply.
        if let Err(status) = hostcalls::send_http_response(status, headers, body) {
            log_error(&format!("envoy-coraza: failed to send local response: {status:?}"));
        }
        Action::Pause
    }

    /// Sends the local reply that refuses this stream, without a body for a `HEAD` request, a 204 or 304, or a
    /// redirect.
    fn send_refusal(&self, status: u16, location: Option<&str>, body: &[u8]) -> Action {
        let mut headers = vec![
            ("content-type", "text/plain; charset=utf-8"),
            ("cache-control", "no-store"),
        ];
        if let Some(location) = location {
            headers.push(("location", location));
        }
        let no_body =
            location.is_some() || status == 204 || status == 304 || self.request_method.eq_ignore_ascii_case("HEAD");
        Self::send_local_response(u32::from(status), headers, Some(if no_body { &[] } else { body }))
    }

    fn reject_interruption(
        &mut self,
        interruption: &Interruption,
        phase: &'static str,
        state_phase: InterruptionPhase,
    ) -> Action {
        let (status, location) = interruption_reply(interruption);
        self.request_mode = RequestMode::Replied;
        self.record_interruption(interruption, state_phase);
        self.finish_once(TerminalOutcome::Denied { phase, status });
        self.send_refusal(status, location, REQUEST_BLOCK_BODY)
    }

    fn reject_request(&mut self, status: u16, body: &[u8], outcome: TerminalOutcome) -> Action {
        self.request_mode = RequestMode::Replied;
        self.finish_once(outcome);
        self.send_refusal(status, None, body)
    }

    /// Fails the request closed after a hostcall error on a property that feeds inspection.
    ///
    /// A missing property (`Ok(None)`) is not an error. A host failure is, and must not
    /// read as an absent value: an empty `REMOTE_ADDR` would let an IP rule be bypassed.
    fn reject_property_hostcall(&mut self, error: &PropertyError) -> Action {
        log_error(&format!(
            "envoy-coraza: cannot read property {}: {:?}; rejecting the request",
            error.path, error.status
        ));
        self.reject_request(
            503,
            REQUEST_INCOMPLETE_BODY,
            TerminalOutcome::Incomplete {
                phase: "request-property-hostcall",
                status: 503,
            },
        )
    }

    /// Refuses the upstream response with a local reply, which Envoy sends to the client in its place: the response
    /// headers are still held, so nothing of the response has reached the client. From here on every response callback
    /// pauses, also when the reply could not be sent, since what arrives is upstream's.
    fn refuse_response(
        &mut self,
        status: u16,
        location: Option<&str>,
        body: &'static [u8],
        outcome: TerminalOutcome,
    ) -> Action {
        self.response_mode = ResponseMode::Refused;
        self.finish_once(outcome);
        self.send_refusal(status, location, body)
    }

    /// Refuses a response that the memory budget stopped the inspection of, whether its parser or its rules.
    fn refuse_response_budget_stopped(&mut self) -> Action {
        self.refuse_response(
            502,
            None,
            RESPONSE_INCOMPLETE_BODY,
            TerminalOutcome::BodyMemoryBudgetStopped { phase: "response-body" },
        )
    }

    fn refuse_response_interruption(
        &mut self,
        interruption: &Interruption,
        phase: &'static str,
        state_phase: InterruptionPhase,
    ) -> Action {
        let (status, location) = interruption_reply(interruption);
        self.record_interruption(interruption, state_phase);
        self.refuse_response(
            status,
            location,
            RESPONSE_BLOCK_BODY,
            TerminalOutcome::Denied { phase, status },
        )
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
        // A request body the filter released unread was not inspected, whatever ended the stream, as a truncated one
        // is; "released" is not "delivered", since a later Envoy filter could still hold the bytes, so this reports
        // conservatively. One that had not come yet can still be released only after a response that completed: a
        // refusal's local reply ends the stream, and the filter holds whatever of the request still arrives after it.
        // A body a processor failed on, which no rule denied, is reported as not inspected too.
        let request_body_unread = self.request_body_failed
            || match self.unread_request_body {
                UnreadRequestBody::Passed => true,
                UnreadRequestBody::Pending => final_outcome == TerminalOutcome::Completed,
                UnreadRequestBody::Absent => false,
            };
        let inspection_complete = matches!(
            final_outcome,
            TerminalOutcome::Completed | TerminalOutcome::Denied { .. }
        ) && !self.request_body_truncated
            && !self.response_body_truncated
            && !request_body_unread;
        let reason = if self.finalization_result == FinalizationResult::Failed {
            "finalization_error"
        } else if request_body_unread {
            "request_body_not_inspected"
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

    /// What the engine may retain while it parses a body: whatever the root has left once this stream's own charges are
    /// in (the host's buffer, the guest's copy, and the engine's buffer with what the transaction already held, and
    /// the copy the processor makes before it parses), less `after_parsing`, the copy it makes once it is done.
    /// Streams that retain bytes concurrently have already taken theirs out of the root, so the peak of this parse and
    /// theirs together cannot pass [`MAX_ROOT_RETAINED_BODY_BYTES`]. Charging after the parse stays the authority on
    /// what was kept.
    fn parse_budget(&self, after_parsing: usize) -> usize {
        MAX_ROOT_RETAINED_BODY_BYTES
            .saturating_sub(self.root_retained_bytes.get())
            .saturating_sub(after_parsing)
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

/// What the engine holds for a body before it parses it, in the units the root's retained-body cap counts.
///
/// The engine retains the prefix of the body its limit allows, not all of what the host holds, and a processor
/// keeps a copy of that prefix only if it is one that stores the raw body (see [`BodyCopy`]).
#[derive(Debug, Default)]
struct BodyLease {
    /// The engine's share while it parses: what the transaction already held, the prefix of the body its buffer
    /// retains, and a copy of that prefix made first.
    engine_before_parsing: usize,
    /// The copy of that prefix made after the parse, which the parse must leave room for.
    after_parsing: usize,
}

impl BodyLease {
    /// The lease for a body of `body_size` bytes under `limit`, when `ingests` says the engine takes it, beside the
    /// `existing` bytes the transaction holds.
    fn new(ingests: bool, body_size: usize, limit: i64, copy: BodyCopy, existing: usize) -> Self {
        let prefix = if ingests {
            usize::try_from(limit).map_or(body_size, |limit| body_size.min(limit))
        } else {
            0
        };
        Self {
            engine_before_parsing: existing
                .saturating_add(prefix)
                .saturating_add(if copy == BodyCopy::BeforeParsing { prefix } else { 0 }),
            after_parsing: if copy == BodyCopy::AfterParsing { prefix } else { 0 },
        }
    }
}

/// A property hostcall that failed, as opposed to a property the host does not have.
#[derive(Debug)]
struct PropertyError {
    /// Dotted property path.
    path: String,
    /// Status the host returned.
    status: Status,
}

/// Reads a host property: `Ok(None)` when the host has no such property, `Err` when the hostcall itself failed.
fn property(path: Vec<&str>) -> Result<Option<Vec<u8>>, PropertyError> {
    let dotted = path.join(".");
    hostcalls::get_property(path).map_err(|status| PropertyError { path: dotted, status })
}

fn apply_connection_metadata(tx: &mut Transaction, authority: &str) -> Result<(), PropertyError> {
    let (source_addr, source_port) = connection_endpoint("source")?;
    let (destination_addr, destination_port) = connection_endpoint("destination")?;
    tx.set_remote_addr(source_addr.as_bytes());
    tx.set_remote_port(source_port);
    tx.set_server_addr(destination_addr.as_bytes());
    tx.set_server_port(destination_port);
    tx.set_server_name(authority_host(authority).as_bytes());
    Ok(())
}

fn connection_endpoint(direction: &str) -> Result<(String, u16), PropertyError> {
    let address = property(vec![direction, "address"])?.unwrap_or_default();
    let parsed = str::from_utf8(&address).ok().and_then(|value| {
        value
            .parse::<SocketAddr>()
            .ok()
            .map(|socket| (socket.ip(), socket.port()))
            .or_else(|| value.parse::<IpAddr>().ok().map(|ip| (ip, 0)))
    });
    let port = property(vec![direction, "port"])?
        .and_then(|bytes| {
            let bytes: [u8; 8] = bytes.try_into().ok()?;
            Some(u64::from_le_bytes(bytes))
        })
        .and_then(|port| u16::try_from(port).ok())
        .or_else(|| parsed.map(|(_, port)| port))
        .unwrap_or(0);
    let ip = parsed.map(|(ip, _)| ip.to_string()).unwrap_or_default();
    Ok((ip, port))
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

/// Reads the request line fields.
///
/// `Ok(None)` means a field is missing or malformed; `Err` means a property hostcall failed.
fn request_metadata(headers: &[(String, Vec<u8>)]) -> Result<Option<RequestMetadata>, PropertyError> {
    let method = match find_header(headers, ":method") {
        Some(method) => Some(method.to_vec()),
        None => property(vec!["request", "method"])?,
    };
    let uri = match find_header(headers, ":path") {
        Some(uri) => Some(uri.to_vec()),
        None => property(vec!["request", "path"])?,
    };
    let protocol = property(vec!["request", "protocol"])?;
    let Some(method) = method.and_then(|bytes| str::from_utf8(&bytes).ok().map(str::to_owned)) else {
        return Ok(None);
    };
    let Some(protocol) = protocol.and_then(|bytes| str::from_utf8(&bytes).ok().map(str::to_owned)) else {
        return Ok(None);
    };
    let Some(uri) = uri else {
        return Ok(None);
    };
    if method.is_empty() || protocol.is_empty() {
        return Ok(None);
    }
    let has_host = headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host"));
    Ok(Some(RequestMetadata {
        method,
        uri,
        protocol,
        has_host,
    }))
}

fn prepare_transaction(
    stream: &mut CorazaHttp,
    policy: &Policy,
    authority: &str,
    headers: &[(String, Vec<u8>)],
    metadata: &RequestMetadata,
) -> Result<(Option<Interruption>, bool, bool), PropertyError> {
    let transaction = stream.tx.get_or_insert_with(|| Box::new(policy.waf.new_transaction()));
    apply_connection_metadata(transaction, authority)?;
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
    Ok((interruption, engine_off, body_access))
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

/// The policy lookup key of a request authority over `scheme`, or `None` when it is not a valid authority.
///
/// The key is lowercase, drops one trailing dot of a registered name and the scheme's default port, writes an IPv6
/// literal in its compressed form, an IPv4-mapped one (`[::ffff:10.0.0.1]`, `[::ffff:a00:1]`) as the dotted-decimal
/// IPv4 address it holds, and a port without leading zeros. A registered name is limited to letters, digits, `-`, `.`
/// and `_` with no empty label, so percent-encoding and sub-delimiters, such as the `,` Envoy joins repeated `Host`
/// headers with, are refused rather than decoded. A host made only of numbers is an IPv4 address and must be written
/// in dotted-decimal form. Configuration keys are validated with the same function, so they are in this form too. The
/// key borrows from `authority` unless it must differ from it in more than a dropped part: a lowercased letter, a
/// rewritten IPv6 literal (an IPv4-mapped one that ends with its dotted address is borrowed), or a port after a
/// changed host or without its leading zeros.
pub(crate) fn normalize_authority<'a>(authority: &'a [u8], scheme: &[u8]) -> Option<Cow<'a, str>> {
    let authority = str::from_utf8(authority).ok()?;
    if authority.is_empty() {
        return Some(Cow::Borrowed(""));
    }
    let (host, port) = split_port(authority).map_or((authority, None), |(host, port)| (host, Some(port)));
    let default_port = if scheme.eq_ignore_ascii_case(b"http") {
        Some(80)
    } else if scheme.eq_ignore_ascii_case(b"https") {
        Some(443)
    } else {
        None
    };
    let port = match port {
        Some(text) => {
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let number = text.parse::<u16>().ok()?;
            (Some(number) != default_port).then_some((number, text.len() == 1 || !text.starts_with('0')))
        },
        None => None,
    };
    let canonical = canonical_host(host)?;
    let host_unchanged = matches!(canonical, Cow::Borrowed(name) if name.len() == host.len());
    Some(match port {
        None => canonical,
        Some((_, true)) if host_unchanged => Cow::Borrowed(authority),
        Some((number, _)) => {
            let mut key = match canonical {
                Cow::Owned(key) => key,
                Cow::Borrowed(name) => {
                    let mut key = String::with_capacity(name.len() + PORT_SUFFIX_BYTES);
                    key.push_str(name);
                    key
                },
            };
            write!(key, ":{number}").ok()?;
            Cow::Owned(key)
        },
    })
}

/// Longest `:port` suffix, which a copied lookup key leaves room for.
const PORT_SUFFIX_BYTES: usize = ":65535".len();

/// Longest IPv6 literal: the longest text form of an address (`INET6_ADDRSTRLEN` less its NUL) in brackets.
const MAX_IPV6_LITERAL_BYTES: usize = "[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]".len();

/// The lookup form of a host: an IPv6 literal in its compressed form, a dotted-decimal IPv4 address (which an
/// IPv4-mapped IPv6 literal becomes), or a lowercase registered name, each without one trailing dot; `None` when it is
/// none of them.
fn canonical_host(host: &str) -> Option<Cow<'_, str>> {
    if let Some(literal) = host.strip_prefix('[') {
        // The parse is the validation, and its text, written on the stack to compare it, is the canonical form.
        let literal = literal.strip_suffix(']')?;
        let address = literal.parse::<Ipv6Addr>().ok()?;
        let mut text = [0_u8; MAX_IPV6_LITERAL_BYTES];
        let mut unwritten = text.as_mut_slice();
        // An IPv4-mapped literal names the IPv4 address it holds (RFC 4291, 2.5.5.2), so it is that address's key;
        // its dotted text, when the literal ends with it, is borrowed.
        let own = if let Some(ipv4) = address.to_ipv4_mapped() {
            write!(unwritten, "{ipv4}").ok()?;
            literal.rsplit_once(':').map_or(literal, |(_, tail)| tail)
        } else {
            write!(unwritten, "[{address}]").ok()?;
            host
        };
        let written = MAX_IPV6_LITERAL_BYTES.checked_sub(unwritten.len())?;
        let canonical = str::from_utf8(text.get(..written)?).ok()?;
        return Some(if canonical == own {
            Cow::Borrowed(own)
        } else {
            let mut key = String::with_capacity(canonical.len() + PORT_SUFFIX_BYTES);
            key.push_str(canonical);
            Cow::Owned(key)
        });
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    // Labels of letters, digits, `-` and `_`, separated by single dots.
    let mut label_empty = true;
    let mut uppercase = false;
    for byte in name.bytes() {
        match byte {
            b'.' if label_empty => return None,
            b'.' => label_empty = true,
            b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => label_empty = false,
            b'A'..=b'Z' => {
                label_empty = false;
                uppercase = true;
            },
            _ => return None,
        }
    }
    if label_empty {
        return None;
    }
    // Resolvers and backends read a host of numbers only as an IPv4 address in one of its other spellings
    // (`010.0.0.1`, `10.0.0.01`, `10.1`, `167772161`, `0xa000001`), which could reach an address key's backend under
    // the default policy; only the dotted-decimal form can match a key, so the others are refused.
    if name.split('.').all(numeric_label) {
        return name.parse::<Ipv4Addr>().is_ok().then_some(Cow::Borrowed(name));
    }
    Some(if uppercase {
        let mut lower = String::with_capacity(name.len() + PORT_SUFFIX_BYTES);
        lower.push_str(name);
        lower.make_ascii_lowercase();
        Cow::Owned(lower)
    } else {
        Cow::Borrowed(name)
    })
}

/// Whether a host label is a number as an IPv4 parser reads one: decimal, octal with a leading zero, or `0x` hex.
fn numeric_label(label: &str) -> bool {
    match label.strip_prefix("0x").or_else(|| label.strip_prefix("0X")) {
        Some(hex) => hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        None => label.bytes().all(|byte| byte.is_ascii_digit()),
    }
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

/// The status and `location` of the reply that refuses `interruption`. A redirect whose target cannot be a `location`
/// value is refused with 403 instead: an empty target (a macro that expanded to nothing), or one an embedder built with
/// a control byte.
fn interruption_reply(interruption: &Interruption) -> (u16, Option<&str>) {
    if interruption.action != "redirect" {
        return (valid_status(interruption.status), None);
    }
    location_value(&interruption.data).map_or((403, None), |location| {
        (valid_status(interruption.status), Some(location))
    })
}

/// `data` as a `location` header value: not empty, and without a control byte, which could end the header line.
fn location_value(data: &str) -> Option<&str> {
    (!data.is_empty() && !data.bytes().any(|byte| byte.is_ascii_control())).then_some(data)
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

fn log_debug(message: &str) {
    hostcalls::log(LogLevel::Debug, message).unwrap_or_default();
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "Lifecycle tests use fixed values.")]
mod tests {
    use std::{cell::Cell, rc::Rc};

    use coraza::types::RuleVariable;
    use proxy_wasm::types::Action;

    use super::{
        normalize_authority, request_authority, CorazaHttp, Cow, Ipv4Addr, Lifecycle, RequestMode, RequestStage,
        ResponseMode, ResponseStage, TerminalOutcome, MAX_HEADER_COUNT, MAX_REQUEST_BODY_BYTES,
        MAX_ROOT_RETAINED_BODY_BYTES,
    };
    use crate::{
        config::Config,
        policy::{split_port, Generation},
    };

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
    fn a_refused_response_stays_paused_whether_or_not_its_reply_was_sent() {
        // The scripted host refuses every local reply, as Envoy does for a second one.
        let mut stream = CorazaHttp::new(None, Rc::new(Cell::new(0)));
        let outcome = TerminalOutcome::Incomplete {
            phase: "response-headers",
            status: 502,
        };
        assert_eq!(stream.refuse_response(502, None, b"", outcome.clone()), Action::Pause);
        assert_eq!(stream.response_mode, ResponseMode::Refused);
        assert_eq!(stream.final_outcome, Some(outcome));
        assert_eq!(stream.response_headers(0, false), Action::Pause, "upstream headers");
        assert_eq!(stream.response_body(35, false), Action::Pause, "upstream body");
        assert_eq!(stream.response_body(35, true), Action::Pause, "upstream body end");
        assert_eq!(stream.response_trailers(0), Action::Pause, "upstream trailers");
    }

    #[test]
    fn a_request_side_reply_passes_through_but_a_refused_response_stays_paused() {
        // The filter's own request-side reply runs through its response callbacks.
        let mut local_reply = CorazaHttp::new(None, Rc::new(Cell::new(0)));
        local_reply.lifecycle.finalized = true;
        local_reply.request_mode = RequestMode::Replied;
        assert_eq!(local_reply.response_headers(0, true), Action::Continue);
        assert_eq!(local_reply.response_body(35, true), Action::Continue);
        assert_eq!(local_reply.response_trailers(0), Action::Continue);

        let mut refused = CorazaHttp::new(None, Rc::new(Cell::new(0)));
        refused.lifecycle.finalized = true;
        refused.response_mode = ResponseMode::Refused;
        assert_eq!(refused.response_headers(0, true), Action::Pause);
        assert_eq!(refused.response_body(35, true), Action::Pause);
        assert_eq!(refused.response_trailers(0), Action::Pause);
    }

    #[test]
    fn a_finalized_request_goes_on_only_if_the_filter_already_released_it() {
        let stages = [
            RequestStage::New,
            RequestStage::Headers,
            RequestStage::Body,
            RequestStage::Complete,
            RequestStage::Bypassed,
        ];
        // A refused response holds the rest of the request too, whether or not its reply was sent.
        let modes = [
            (RequestMode::Inspect, ResponseMode::Inspect),
            (RequestMode::Replied, ResponseMode::Inspect),
            (RequestMode::Inspect, ResponseMode::Refused),
        ];
        for (stage, (mode, response)) in stages.into_iter().flat_map(|stage| modes.map(|mode| (stage, mode))) {
            let finalized = || {
                let mut stream = CorazaHttp::new(None, Rc::new(Cell::new(0)));
                stream.lifecycle.request = stage;
                stream.lifecycle.finalized = true;
                stream.request_mode = mode;
                stream.response_mode = response;
                stream
            };
            let expected = if mode == RequestMode::Inspect
                && response == ResponseMode::Inspect
                && matches!(stage, RequestStage::Complete | RequestStage::Bypassed)
            {
                Action::Continue
            } else {
                Action::Pause
            };
            let label = format!("{stage:?} {mode:?} {response:?}");
            assert_eq!(finalized().begin_request(0, true), expected, "{label} headers");
            assert_eq!(finalized().request_body(3, true), expected, "{label} body");
            assert_eq!(finalized().request_trailers(0), expected, "{label} trailers");
            assert_eq!(finalized().complete_request_body(3), expected, "{label} phase 2");
        }
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
    fn a_response_body_is_parsed_within_what_the_root_has_left() {
        let config = Config::parse(
            br#"{"directives_map":{"p":["SecRuleEngine On","SecResponseBodyAccess On","SecResponseBodyMimeType application/json","SecResponseBodyLimit 1048576","SecRule RESPONSE_CONTENT_TYPE \"^application/json\" \"id:200001,phase:3,t:none,pass,nolog,ctl:responseBodyProcessor=JSON\""]},"default_directives":"p"}"#,
        )
        .expect("the response policy is valid");
        let generation = Rc::new(Generation::compile(config).expect("the policy compiles"));
        let policy = generation
            .select("example.test")
            .expect("the default policy is selected");
        let mut transaction = policy.waf.new_transaction();
        transaction.process_uri("/", "GET", "HTTP/1.1");
        transaction.process_request_headers();
        assert!(transaction.process_request_body(b"").is_none());
        transaction.add_response_header("content-type", b"application/json");
        assert!(transaction.process_response_headers(200, "HTTP/1.1").is_none());
        let already_held = transaction.body_memory_bytes();

        // Three quarters of a megabyte of nested arrays: its container index alone is charged some 7 MiB, which is
        // more than the root has left.
        let mut body = b"[".to_vec();
        body.extend(b"[[]],".repeat(150_000));
        body.extend_from_slice(b"[]]");
        let others = 58 * 1024 * 1024;
        let root = Rc::new(Cell::new(others));
        let mut stream = CorazaHttp::new(Some(generation), Rc::clone(&root));
        stream.tx = Some(Box::new(transaction));

        let size = body.len();
        stream.response_host_bytes = size;
        let outcome = stream.inspect_response_body(size, true, true, move |_| Ok(Some(body)));

        assert!(
            matches!(outcome, Ok(None)),
            "a body error does not interrupt by itself: {outcome:?}"
        );
        let tx = stream.tx.as_deref().expect("the transaction is retained");
        assert_eq!(
            tx.body_memory_budget(),
            Some(MAX_ROOT_RETAINED_BODY_BYTES - others - 4 * size - already_held),
            "the parser got what the root had left after this response's charges and what the transaction held"
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ResBodyError, None).as_deref(),
            Some("1"),
            "the parse stopped at the budget and reported it"
        );
        assert!(others + tx.body_memory_bytes() <= MAX_ROOT_RETAINED_BODY_BYTES);
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
        for (authority, scheme, expected) in [
            // One trailing dot names the same host.
            ("a.example.", "http", "a.example"),
            ("A.Example.:8080", "http", "a.example:8080"),
            ("a.example.:80", "http", "a.example"),
            // A port is a number: leading zeros neither hide the default port nor make another one.
            ("a.example:080", "http", "a.example"),
            ("a.example:08080", "http", "a.example:8080"),
            ("a.example:00", "http", "a.example:0"),
            // An IPv6 literal is looked up in its canonical text form.
            ("[0:0:0:0:0:0:0:1]", "http", "[::1]"),
            ("[2001:0db8:0:0:0:0:0:0001]:8443", "https", "[2001:db8::1]:8443"),
            // An IPv4-mapped literal is looked up as its IPv4 address.
            ("[::ffff:192.0.2.1]", "http", "192.0.2.1"),
            ("[::FFFF:c000:201]:8080", "http", "192.0.2.1:8080"),
            ("[::ffff:192.0.2.1]:80", "http", "192.0.2.1"),
            ("[::192.0.2.1]", "http", "[::c000:201]"),
            ("192.0.2.1.", "http", "192.0.2.1"),
            ("under_score.example", "http", "under_score.example"),
        ] {
            assert_eq!(
                normalize_authority(authority.as_bytes(), scheme.as_bytes()).as_deref(),
                Some(expected),
                "{scheme}://{authority}"
            );
        }
    }

    #[test]
    fn an_authority_already_in_normal_form_is_not_copied() {
        for (authority, scheme) in [
            ("a.example", "http"),
            ("a.example:8080", "http"),
            ("a.example:80", "http"),
            ("a.example.", "http"),
            ("[::1]", "http"),
            ("[::1]:8080", "http"),
            ("[::1]:80", "http"),
            ("[::ffff:192.0.2.1]", "http"),
            ("[0:0:0:0:0:FFFF:192.0.2.1]", "http"),
            // The longest IPv6 text form still fits the buffer its canonical form is written to.
            ("[1111:2222:3333:4444:5555:6666:7777:8888]:8443", "https"),
            ("10.0.0.1", "http"),
            ("10.0.0.1.:80", "http"),
            ("", "http"),
        ] {
            assert!(
                matches!(
                    normalize_authority(authority.as_bytes(), scheme.as_bytes()),
                    Some(Cow::Borrowed(_))
                ),
                "{authority} is borrowed"
            );
        }
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
        for authority in [
            // Percent-encoding and sub-delimiters are no part of a host name, whatever a backend makes of them.
            "a%2eexample",
            "a.example,a.example",
            "a.example;x",
            "a~b.example",
            "a!b.example",
            "a'b.example",
            // Empty labels: only one trailing dot is the root.
            "a.example..",
            ".a.example",
            "a..example",
            ".",
            // IPv6 literals parse as addresses or not at all.
            "[fe80::1%25eth0]",
            "[v1.x]",
            "[::1]x",
            "[::1]:",
            "a.example:",
            "a.example:1:2",
            // A host of numbers only is a dotted-decimal IPv4 address or nothing.
            "010.0.0.1",
            "10.0.0.01",
            "10.1",
            "167772161",
            "0xa000001",
            "0Xa.0.0.1",
            "256.0.0.1",
            "1.2.3.4.5",
            "1.2.3.4..",
        ] {
            assert_eq!(normalize_authority(authority.as_bytes(), b"http"), None, "{authority}");
        }

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

    /// A xorshift64 generator with a fixed seed, so that a failing input reproduces.
    struct Xorshift(u64);

    impl Xorshift {
        /// A number below `bound`, which is not 0.
        fn below(&mut self, bound: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            usize::try_from(self.0 % u64::try_from(bound).unwrap_or(u64::MAX)).unwrap_or_default()
        }

        /// One of `items`, which is not empty.
        fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
            items.get(self.below(items.len())).copied().unwrap_or_default()
        }
    }

    /// Checks what every lookup key holds for `authority` over `scheme`, whatever the input.
    fn check_lookup_key(authority: &[u8], scheme: &str) {
        let key = normalize_authority(authority, scheme.as_bytes());
        let Ok(text) = std::str::from_utf8(authority) else {
            assert_eq!(key, None, "{authority:?} is not UTF-8");
            return;
        };
        assert_eq!(
            normalize_authority(text.to_ascii_uppercase().as_bytes(), scheme.as_bytes()),
            normalize_authority(text.to_ascii_lowercase().as_bytes(), scheme.as_bytes()),
            "{scheme}://{text}: case does not matter"
        );
        let Some(key) = key.filter(|key| !key.is_empty()) else {
            return;
        };
        assert!(
            matches!(normalize_authority(key.as_bytes(), scheme.as_bytes()), Some(Cow::Borrowed(again)) if again == key),
            "{scheme}://{text}: the key {key} is its own key, and borrowed"
        );
        assert!(
            key.bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b':' | b'[' | b']')),
            "{scheme}://{text}: the key {key} is lowercase"
        );
        let (host, port) = split_port(&key).map_or((&*key, None), |(host, port)| (host, Some(port)));
        if let Some(port) = port {
            assert!(port == "0" || !port.starts_with('0'), "{key}: no leading zeros");
            let default_port = match scheme {
                "http" => "80",
                "https" => "443",
                _ => "",
            };
            assert_ne!(port, default_port, "{scheme}://{text}: the default port is dropped");
            assert!(
                matches!(normalize_authority(host.as_bytes(), scheme.as_bytes()), Some(Cow::Borrowed(bare)) if bare == host),
                "the bare host of {key} is a key"
            );
        }
        assert!(!host.ends_with('.'), "{key}: no trailing dot");
        let numeric = |label: &str| {
            label.strip_prefix("0x").map_or_else(
                || label.bytes().all(|byte| byte.is_ascii_digit()),
                |hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
            )
        };
        if !host.starts_with('[') && host.split('.').all(numeric) {
            assert!(
                host.parse::<Ipv4Addr>()
                    .is_ok_and(|address| address.to_string() == host),
                "{text}: a numeric host is a dotted-decimal IPv4 address"
            );
        }
        if !text.contains([':', '[']) && !text.ends_with('.') {
            assert_eq!(
                normalize_authority(format!("{text}.").as_bytes(), scheme.as_bytes()).as_deref(),
                Some(&*key),
                "{text}: one trailing dot names the same host"
            );
        }
    }

    #[test]
    fn lookup_keys_hold_their_properties_for_every_short_authority() {
        const ALPHABET: &[u8] = b"aZ09fx.:[]%,-_";
        let mut authority = Vec::new();
        for length in 0..=4_u32 {
            for mut index in 0..ALPHABET.len().pow(length) {
                authority.clear();
                for _ in 0..length {
                    authority.push(ALPHABET.get(index % ALPHABET.len()).copied().unwrap_or_default());
                    index /= ALPHABET.len();
                }
                for scheme in ["http", "https", ""] {
                    check_lookup_key(&authority, scheme);
                }
            }
        }
    }

    #[test]
    fn lookup_keys_hold_their_properties_for_random_authorities() {
        const TOKENS: [&str; 26] = [
            "a", "B", "0", "1", "9", "f", "x", "0x", "example", ".", "..", ":", "::", "[", "]", "%", "%2e", ",", "-",
            "_", "~", "\0", "80", "443", "080", "\u{e9}",
        ];
        const GROUPS: [&str; 10] = ["0", "00", "0000", "1", "db8", "FFFF", "fe80", "2001", "abcd", "1.2.3.4"];
        const PORTS: [&str; 9] = ["", ":80", ":080", ":443", ":8080", ":0", ":65535", ":65536", ":"];
        let mut random = Xorshift(0x2545_F491_4F6C_DD1D);
        for _ in 0..100_000 {
            let mut text = String::new();
            for _ in 0..random.below(9) {
                text.push_str(random.pick(&TOKENS));
            }
            // An IPv6 literal, more or less well formed, with or without a port.
            let mut literal = String::from("[");
            for group in 0..random.below(10) {
                if group > 0 {
                    literal.push_str(if random.below(8) == 0 { "::" } else { ":" });
                }
                literal.push_str(random.pick(&GROUPS));
            }
            literal.push(']');
            literal.push_str(random.pick(&PORTS));
            for scheme in ["http", "https", ""] {
                check_lookup_key(text.as_bytes(), scheme);
                check_lookup_key(literal.as_bytes(), scheme);
            }
        }
        check_lookup_key(b"a.example\xff", "http");
    }

    #[test]
    fn ipv4_spellings_are_keys_only_in_dotted_decimal_form() {
        // Independent of the parser: four decimal labels up to 255 without leading zeros.
        let dotted_decimal = |text: &str| {
            text.split('.').count() == 4
                && text.split('.').all(|label| {
                    !label.is_empty()
                        && label.bytes().all(|byte| byte.is_ascii_digit())
                        && (label == "0" || !label.starts_with('0'))
                        && label.parse::<u16>().is_ok_and(|value| value <= 255)
                })
        };
        let mut random = Xorshift(0x9E37_79B9_7F4A_7C15);
        for _ in 0..50_000 {
            let mut text = String::new();
            for index in 0..=random.below(5) {
                if index > 0 {
                    text.push('.');
                }
                let value = random.below(300);
                let label = match random.below(4) {
                    0 => format!("{value}"),
                    1 => format!("0{value}"),
                    2 => format!("0x{value:x}"),
                    _ => format!("{value:03}"),
                };
                text.push_str(&label);
            }
            assert_eq!(
                normalize_authority(text.as_bytes(), b"http").as_deref(),
                dotted_decimal(&text).then_some(text.as_str()),
                "{text}"
            );
        }
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

        // A stop of the memory budget in the response phase is the same: the earlier reason is kept, and the terminal
        // outcome says the stream ended incomplete.
        let mut stream = CorazaHttp::new(None, Rc::new(Cell::new(0_usize)));
        stream.outcome = Some(partial.clone());
        let stopped = TerminalOutcome::BodyMemoryBudgetStopped { phase: "response-body" };
        assert_eq!(stream.finish_state(stopped.clone(), |_| false), Some(false));
        assert_eq!(stream.outcome.as_ref(), Some(&partial));
        assert_eq!(stream.final_outcome.as_ref(), Some(&stopped));
        assert_eq!(stopped.inspection_reason(), "body_memory_budget_stopped");
        assert_eq!(stopped.terminal_name(), "incomplete");
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

/// Request-header tests that drive a stream through the scripted Proxy-Wasm host.
#[cfg(test)]
#[expect(clippy::expect_used, reason = "Stream tests use fixed fixtures.")]
mod scripted_host_tests {
    use std::{cell::Cell, rc::Rc};

    use proxy_wasm::{
        traits::HttpContext as _,
        types::{Action, Status},
    };

    use super::{
        CorazaHttp, Interruption, InterruptionPhase, TerminalOutcome, MAX_HEADER_COUNT, MAX_REQUEST_BODY_BYTES,
        MAX_RESPONSE_BODY_BYTES, MAX_ROOT_RETAINED_BODY_BYTES, REQUEST_BLOCK_BODY, RESPONSE_BLOCK_BODY,
        RESPONSE_INCOMPLETE_BODY, UNSUPPORTED_BODY,
    };
    use crate::{config::Config, policy::Generation, test_hostcalls};

    /// One mebibyte.
    const MIB: usize = 1024 * 1024;

    /// Denies the source address 1.2.3.4 and nothing else.
    const DENY_SOURCE: &str = r#"SecRule REMOTE_ADDR \"@ipMatch 1.2.3.4\" \"id:200,phase:1,deny,status:403\""#;

    /// A stream pinned to the generation `config` compiles to.
    fn stream(config: &str) -> CorazaHttp {
        stream_beside(config, 0).0
    }

    /// A stream whose default policy denies source address 1.2.3.4.
    fn ip_deny_stream() -> CorazaHttp {
        stream(&format!(
            r#"{{"directives_map": {{"p": ["SecRuleEngine On", "{DENY_SOURCE}"]}}, "default_directives": "p"}}"#
        ))
    }

    /// Scripts a complete GET request from 1.2.3.4 to `authority` over `scheme`; returns its header count.
    fn script_request(authority: &str, scheme: &str) -> usize {
        test_hostcalls::reset();
        let headers: [(&str, &[u8]); 4] = [
            (":authority", authority.as_bytes()),
            (":scheme", scheme.as_bytes()),
            (":method", b"GET"),
            (":path", b"/"),
        ];
        test_hostcalls::set_request_headers(&headers);
        script_connection_properties();
        headers.len()
    }

    /// Scripts the properties of a connection from 1.2.3.4:5555 to 10.0.0.1:8080 over HTTP/1.1.
    fn script_connection_properties() {
        test_hostcalls::set_property("request.protocol", b"HTTP/1.1");
        test_hostcalls::set_property("source.address", b"1.2.3.4:5555");
        test_hostcalls::set_property("source.port", &5555_u64.to_le_bytes());
        test_hostcalls::set_property("destination.address", b"10.0.0.1:8080");
        test_hostcalls::set_property("destination.port", &8080_u64.to_le_bytes());
    }

    /// The policy an `authority` request over `scheme` selects.
    fn selected_policy(config: &str, authority: &str, scheme: &str) -> Option<String> {
        let mut stream = stream(config);
        let count = script_request(authority, scheme);
        stream.on_http_request_headers(count, true);
        stream.selected_policy.clone()
    }

    /// Two policies, `strict` for the authority table and `open` for the default.
    fn authority_config(key: &str) -> String {
        format!(
            r#"{{"directives_map": {{"strict": ["SecRuleEngine On"], "open": ["SecRuleEngine On"]}},
                "default_directives": "open", "per_authority_directives": {{"{key}": "strict"}}}}"#
        )
    }

    #[test]
    fn a_non_default_port_key_matches_a_request_to_that_port() {
        let config = authority_config("b.example:8080");
        assert_eq!(
            selected_policy(&config, "b.example:8080", "http").as_deref(),
            Some("strict"),
            "the port stays part of the lookup key"
        );
        assert_eq!(
            selected_policy(&config, "b.example", "http").as_deref(),
            Some("open"),
            "the bare host is a different authority"
        );
        assert_eq!(
            selected_policy(&config, "b.example:08080", "http").as_deref(),
            Some("strict"),
            "leading zeros do not make another port"
        );
    }

    #[test]
    fn a_bare_host_key_matches_requests_carrying_the_default_port() {
        let config = authority_config("b.example");
        for (authority, scheme) in [
            ("b.example:80", "http"),
            ("b.example:443", "https"),
            ("B.Example:80", "http"),
            ("b.example", "http"),
        ] {
            assert_eq!(
                selected_policy(&config, authority, scheme).as_deref(),
                Some("strict"),
                "{authority} over {scheme}"
            );
        }
        assert_eq!(
            selected_policy(&config, "b.example:8080", "http").as_deref(),
            Some("strict"),
            "a port without a key of its own falls back to the bare host's key, not to the default"
        );
    }

    /// Runs a bodyless GET for `authority` over `scheme` against `config`; returns the action, the selected policy
    /// and the local replies.
    fn get_for(config: &str, authority: &str, scheme: &str) -> (Action, Option<String>, Vec<u32>) {
        let mut get = stream(config);
        let count = script_request(authority, scheme);
        let action = get.on_http_request_headers(count, true);
        (
            action,
            get.selected_policy.clone(),
            test_hostcalls::local_reply_statuses(),
        )
    }

    /// The only policy denies every request, and only its authority selects it: there is no default.
    const STRICT_ONLY: &str = r#"{"directives_map": {"strict": ["SecRuleEngine On",
        "SecAction \"id:1,phase:1,deny,status:403\""]},
        "per_authority_directives": {"victim.example": "strict"}, "enable_filter_state_logs": true}"#;

    /// The same, with a default that inspects nothing.
    const STRICT_AND_OPEN: &str = r#"{"directives_map": {"strict": ["SecRuleEngine On",
        "SecAction \"id:1,phase:1,deny,status:403\""], "open": ["SecRuleEngine On"]},
        "default_directives": "open", "per_authority_directives": {"victim.example": "strict"}}"#;

    /// Spellings of `victim.example` that a backend serves as that host.
    const RESPELLINGS: [(&str, &str); 6] = [
        ("victim.example.", "http"),
        ("VICTIM.example.", "http"),
        ("victim.example:8080", "http"),
        ("victim.example:443", "http"),
        ("victim.example:80", "https"),
        ("victim.example:0", "http"),
    ];

    /// Spellings that are no registered name: a percent-encoded dot and what Envoy joins two `Host` headers into.
    const NOT_A_REGISTERED_NAME: [&str; 2] = ["victim%2eexample", "victim.example,x"];

    #[test]
    fn authority_spellings_must_not_dodge_the_only_policy() {
        assert_eq!(
            get_for(STRICT_ONLY, "victim.example", "http"),
            (Action::Pause, Some("strict".to_owned()), vec![403])
        );
        for (authority, scheme) in RESPELLINGS {
            assert_eq!(
                get_for(STRICT_ONLY, authority, scheme),
                (Action::Pause, Some("strict".to_owned()), vec![403]),
                "{scheme}://{authority} selects the policy of its host"
            );
        }
        for authority in NOT_A_REGISTERED_NAME {
            assert_eq!(
                get_for(STRICT_ONLY, authority, "http"),
                (Action::Pause, None, vec![400]),
                "{authority} is refused as an invalid authority"
            );
        }
        // Without a default, a host the configuration does not list is refused, not passed uninspected.
        assert_eq!(
            get_for(STRICT_ONLY, "other.example", "http"),
            (Action::Pause, None, vec![421])
        );
        assert_eq!(
            test_hostcalls::published_property("io.coraza.waf.v1.inspection_reason").as_deref(),
            Some("unmatched_authority")
        );
        assert_eq!(
            test_hostcalls::published_property("io.coraza.waf.v1.terminal_outcome").as_deref(),
            Some("error")
        );
        assert_eq!(
            test_hostcalls::published_property("io.coraza.waf.v1.inspection_complete").as_deref(),
            Some("false")
        );
    }

    #[test]
    fn authority_spellings_must_not_fall_to_the_weaker_default() {
        for (authority, scheme) in RESPELLINGS {
            assert_eq!(
                get_for(STRICT_AND_OPEN, authority, scheme),
                (Action::Pause, Some("strict".to_owned()), vec![403]),
                "{scheme}://{authority} selects the policy of its host"
            );
        }
        for authority in NOT_A_REGISTERED_NAME {
            assert_eq!(
                get_for(STRICT_AND_OPEN, authority, "http"),
                (Action::Pause, None, vec![400]),
                "{authority} is refused as an invalid authority"
            );
        }
        assert_eq!(
            get_for(STRICT_AND_OPEN, "other.example", "http"),
            (Action::Continue, Some("open".to_owned()), vec![]),
            "an unlisted host gets the default"
        );
    }

    #[test]
    fn an_uncompressed_ipv6_literal_selects_its_compressed_key() {
        let config = authority_config("[::1]");
        for authority in ["[0:0:0:0:0:0:0:1]", "[::1]", "[0:0::1]:8080", "[::0001]"] {
            assert_eq!(
                selected_policy(&config, authority, "http").as_deref(),
                Some("strict"),
                "{authority}"
            );
        }
    }

    #[test]
    fn another_spelling_of_an_ipv4_key_is_refused_rather_than_given_the_default() {
        let config = STRICT_AND_OPEN.replace("victim.example", "10.0.0.1");
        for authority in ["10.0.0.1", "10.0.0.1.", "10.0.0.1:80", "10.0.0.1:8080"] {
            assert_eq!(
                get_for(&config, authority, "http"),
                (Action::Pause, Some("strict".to_owned()), vec![403]),
                "{authority} selects the address's policy"
            );
        }
        for authority in [
            "010.0.0.1",
            "10.0.0.01",
            "10.000.0.1",
            "10.1",
            "10.0.1",
            "167772161",
            "0xa000001",
            "0XA000001",
            "0xa.0.0.1",
            "0x0a.0x00.0x00.0x01",
            "012.0.0.1:80",
            "10.0.0.1.0",
            "0x",
        ] {
            assert_eq!(
                get_for(&config, authority, "http"),
                (Action::Pause, None, vec![400]),
                "{authority} is refused as an invalid authority"
            );
        }
        // Digits are ordinary in a host name that is not numbers only, and such a host gets the default.
        for authority in [
            "10.0.0.1.example",
            "1.example",
            "0x1.example",
            "123abc",
            "example.10",
            "10-0-0-1",
        ] {
            assert_eq!(
                get_for(&config, authority, "http"),
                (Action::Continue, Some("open".to_owned()), vec![]),
                "{authority} is a host name"
            );
        }
    }

    #[test]
    fn an_ipv4_mapped_literal_selects_the_policy_of_its_ipv4_key() {
        let config = STRICT_AND_OPEN.replace("victim.example", "10.0.0.1");
        for authority in [
            "[::ffff:10.0.0.1]",
            "[::ffff:a00:1]",
            "[::FFFF:10.0.0.1]:8080",
            "[0:0:0:0:0:ffff:10.0.0.1]:80",
        ] {
            assert_eq!(
                get_for(&config, authority, "http"),
                (Action::Pause, Some("strict".to_owned()), vec![403]),
                "{authority} selects the address's policy"
            );
        }
        // A deprecated IPv4-compatible literal is not IPv4-mapped, so it stays an IPv6 address.
        assert_eq!(
            get_for(&config, "[::10.0.0.1]", "http"),
            (Action::Continue, Some("open".to_owned()), vec![]),
        );
        // With no default, the mapped literal is no unlisted host either.
        let strict_only = STRICT_ONLY.replace("victim.example", "10.0.0.1");
        assert_eq!(
            get_for(&strict_only, "[::ffff:a00:1]", "http"),
            (Action::Pause, Some("strict".to_owned()), vec![403]),
        );
    }

    #[test]
    fn unmatched_authority_allow_and_an_empty_policy_map_keep_passing_uninspected() {
        let allow = r#"{"directives_map": {"strict": ["SecRuleEngine On", "SecAction \"id:1,phase:1,deny,status:403\""]},
            "per_authority_directives": {"victim.example": "strict"}, "unmatched_authority": "allow"}"#;
        for config in [allow, r#"{"directives_map": {}}"#] {
            assert_eq!(
                get_for(config, "other.example", "http"),
                (Action::Continue, None, vec![]),
                "{config}"
            );
        }
        assert_eq!(
            get_for(allow, "victim.example.", "http"),
            (Action::Pause, Some("strict".to_owned()), vec![403]),
            "the listed host is still enforced in every spelling"
        );
    }

    #[test]
    fn a_default_port_key_is_refused_so_it_can_never_silently_miss() {
        for key in ["b.example:80", "b.example:443"] {
            let config = authority_config(key);
            assert!(
                Config::parse(config.as_bytes()).is_err(),
                "{key} would never be looked up, so it is rejected"
            );
        }
    }

    #[test]
    fn a_source_address_is_enforced_when_the_host_reports_it() {
        let mut stream = ip_deny_stream();
        let count = script_request("a.example", "http");
        assert_eq!(stream.on_http_request_headers(count, true), Action::Pause);
        assert_eq!(test_hostcalls::local_reply_statuses(), [403], "the IP rule denies");
    }

    #[test]
    fn a_missing_property_keeps_its_previous_behavior() {
        // The host reports no source address: REMOTE_ADDR is empty and the request is still inspected.
        let mut stream = ip_deny_stream();
        let count = script_request("a.example", "http");
        test_hostcalls::remove_property("source.address");
        assert_eq!(stream.on_http_request_headers(count, true), Action::Continue);
        assert!(test_hostcalls::local_reply_statuses().is_empty());
        assert_eq!(stream.selected_policy.as_deref(), Some("p"), "the request is inspected");

        // A missing port falls back to the address's own port and never loses the address.
        let mut stream = ip_deny_stream();
        let count = script_request("a.example", "http");
        test_hostcalls::remove_property("source.port");
        test_hostcalls::remove_property("destination.port");
        assert_eq!(stream.on_http_request_headers(count, true), Action::Pause);
        assert_eq!(
            test_hostcalls::local_reply_statuses(),
            [403],
            "the IP rule still denies"
        );
    }

    #[test]
    fn a_property_hostcall_failure_fails_closed_instead_of_clearing_the_value() {
        for property in [
            "source.address",
            "source.port",
            "destination.address",
            "destination.port",
            "request.protocol",
        ] {
            for status in [
                Status::InternalFailure,
                Status::SerializationFailure,
                Status::BadArgument,
            ] {
                let mut stream = ip_deny_stream();
                let count = script_request("a.example", "http");
                test_hostcalls::fail_property(property, status);
                assert_eq!(
                    stream.on_http_request_headers(count, true),
                    Action::Pause,
                    "{property} {status:?}: the request is held"
                );
                assert_eq!(test_hostcalls::local_reply_statuses(), [503], "{property} {status:?}");
                assert_eq!(
                    stream.final_outcome,
                    Some(TerminalOutcome::Incomplete {
                        phase: "request-property-hostcall",
                        status: 503,
                    }),
                    "{property} {status:?}"
                );
            }
        }
    }

    #[test]
    fn the_host_and_scheme_fallbacks_fail_closed_only_when_they_are_consulted() {
        let strip = |name: &str| -> Vec<(&'static str, Vec<u8>)> {
            let all: [(&'static str, &[u8]); 4] = [
                (":authority", b"a.example"),
                (":scheme", b"http"),
                (":method", b"GET"),
                (":path", b"/"),
            ];
            all.iter()
                .filter(|(header, _)| *header != name)
                .map(|(header, value)| (*header, value.to_vec()))
                .collect()
        };
        for (absent_header, property) in [(":authority", "request.host"), (":scheme", "request.scheme")] {
            let headers = strip(absent_header);
            let borrowed: Vec<(&str, &[u8])> = headers.iter().map(|(name, value)| (*name, value.as_slice())).collect();

            let mut stream = ip_deny_stream();
            let count = script_request("a.example", "http");
            test_hostcalls::set_request_headers(&borrowed);
            test_hostcalls::fail_property(property, Status::InternalFailure);
            assert_eq!(
                stream.on_http_request_headers(borrowed.len(), true),
                Action::Pause,
                "{property} is needed because {absent_header} is absent"
            );
            assert_eq!(test_hostcalls::local_reply_statuses(), [503], "{property}");

            // With the header present the property is never read, so its failure is irrelevant.
            let mut stream = ip_deny_stream();
            script_request("a.example", "http");
            test_hostcalls::fail_property(property, Status::InternalFailure);
            assert_eq!(stream.on_http_request_headers(count, true), Action::Pause);
            assert_eq!(
                test_hostcalls::local_reply_statuses(),
                [403],
                "{property} is not consulted: the IP rule decides"
            );
        }
    }
    /// The rule that denies a failed parse, as CRS rule 200002 does.
    const DENY_BODY_ERRORS: &str =
        r#", "SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,t:none,deny,status:400\"""#;

    /// A stream over `config` whose root context already holds `other_streams` bytes for its siblings, and that
    /// root.
    fn stream_beside(config: &str, other_streams: usize) -> (CorazaHttp, Rc<Cell<usize>>) {
        let config = Config::parse(config.as_bytes()).expect("configuration is valid");
        let generation = Generation::compile(config).expect("policy compiles");
        let root = Rc::new(Cell::new(other_streams));
        (CorazaHttp::new(Some(Rc::new(generation)), Rc::clone(&root)), root)
    }

    /// Scripts a POST of `body` to the host, and runs the stream through its request headers; returns the body size.
    fn begin_post(stream: &mut CorazaHttp, content_type: &str, body: &[u8]) -> usize {
        test_hostcalls::reset();
        let length = body.len().to_string();
        let headers: [(&str, &[u8]); 6] = [
            (":authority", b"a.example"),
            (":scheme", b"http"),
            (":method", b"POST"),
            (":path", b"/"),
            ("content-type", content_type.as_bytes()),
            ("content-length", length.as_bytes()),
        ];
        test_hostcalls::set_request_headers(&headers);
        script_connection_properties();
        test_hostcalls::set_request_body(body);
        assert_eq!(
            stream.on_http_request_headers(headers.len(), false),
            Action::Pause,
            "the headers wait for the body"
        );
        body.len()
    }

    /// A dense XML list of `size` bytes, the densest ordinary body.
    fn xml_list(size: usize) -> Vec<u8> {
        let mut body = b"<r>".to_vec();
        while body.len() < size - 4 {
            body.extend_from_slice(b"<i>1</i>");
        }
        body.extend_from_slice(b"</r>");
        body
    }

    #[test]
    fn an_xml_body_beside_retaining_streams_is_a_body_error_instead_of_an_overshoot() {
        let config = policy(LIMITS, DENY_BODY_ERRORS);
        let body = xml_list(2 * MIB);

        // The same body alone parses cleanly: only what the others hold stops it.
        let (mut alone, _) = stream_beside(&config, 0);
        let size = begin_post(&mut alone, "text/xml", &body);
        assert_eq!(alone.on_http_request_body(size, true), Action::Continue);
        assert!(test_hostcalls::local_reply_statuses().is_empty());

        // Concurrent streams hold 50 MiB of the root's 64, which leaves 14 for this body's three charges (host buffer,
        // copy and engine buffer, 2 MiB each) and what its parser may retain; or they leave room for the three charges
        // and what the transaction holds, and a kilobyte or nothing to parse in.
        for spare in [None, Some(1024), Some(0)] {
            let (mut stream, root) = stream_beside(&config, 50 * MIB);
            let size = begin_post(&mut stream, "text/xml", &body);
            if let Some(spare) = spare {
                // Held by this very transaction: ids come from a process-wide counter and can grow a digit.
                root.set(MAX_ROOT_RETAINED_BODY_BYTES - 3 * size - held(&stream) - spare);
            }
            let others = root.get();
            assert_eq!(stream.on_http_request_body(size, true), Action::Pause);

            assert_eq!(
                test_hostcalls::local_reply_statuses(),
                [400],
                "the failed parse reaches rule 200002, which denies"
            );
            assert_eq!(
                stream.final_outcome,
                Some(TerminalOutcome::Denied {
                    phase: "request-body",
                    status: 400
                })
            );
            // Without the budget the parser would have kept some 25 MiB for this body, and the check after it would
            // have answered 503 for a body the engine had already allocated.
            assert_eq!(root.get(), others, "the stream's charges are released with it");
        }
    }

    #[test]
    fn an_xml_error_whose_message_does_not_fit_the_budget_is_refused_by_the_connector_where_no_rule_denies_first() {
        // `&unknown;` quotes the document in its error, which needs room in the budget. Where there is none the parse
        // stops for the budget instead: the connector answers 503 then, in every engine mode, unless a rule denies the
        // body error first, as rule 200002 of `@recommended-conf` does with 400. With room the error is the XML's own.
        let body = b"<r a=\"1\"><i>x</i>&unknown;</r>";
        let default_on = policy(LIMITS, "");
        let detection_only = policy(LIMITS, r#", "SecRuleEngine DetectionOnly""#);
        let backstop = policy(LIMITS, DENY_BODY_ERRORS);
        // The statuses of the replies to `body` where the root leaves the stream `spare` bytes to parse in.
        let statuses = |config: &str, spare: usize| {
            let (mut stream, root) = stream_beside(config, 0);
            let size = begin_post(&mut stream, "text/xml", body);
            // What this very transaction holds is not known before the stream is built.
            root.set(MAX_ROOT_RETAINED_BODY_BYTES - 3 * size - held(&stream) - spare);
            stream.on_http_request_body(size, true);
            test_hostcalls::local_reply_statuses()
        };
        let (mut stopped_then_denied, mut parsed_then_denied) = (0, 0);
        for spare in (0..=16 * 1024).step_by(128) {
            let (default, only, denying) = (
                statuses(&default_on, spare),
                statuses(&detection_only, spare),
                statuses(&backstop, spare),
            );
            assert_eq!(default, only, "{spare}: DetectionOnly answers as the default does");
            if default == [503] {
                // Rule 200002 answers first once the stopped parse leaves what the check after it needs; below that
                // the check answers 503, as it does for any body.
                assert!(denying == [400] || denying == [503], "{spare}: {denying:?}");
                stopped_then_denied += usize::from(denying == [400]);
            } else {
                assert_eq!(
                    default,
                    Vec::<u32>::new(),
                    "{spare}: the error is the XML's own, and nothing denies it"
                );
                assert_eq!(denying, [400], "{spare}: rule 200002");
                parsed_then_denied += 1;
            }
        }
        assert!(
            stopped_then_denied > 0 && parsed_then_denied > 0,
            "{stopped_then_denied} budgets stop the parse and are denied, {parsed_then_denied} reach the error"
        );
    }

    /// A policy with `rules` beside the body policy a connector gets from CRS: XML, JSON and URL-encoded bodies are
    /// parsed as their content types select, and nothing reads `REQBODY_ERROR`, unless `rules` does.
    fn policy(limits: &str, rules: &str) -> String {
        format!(
            r#"{{"directives_map": {{"p": ["SecRuleEngine On", "SecRequestBodyAccess On", "SecResponseBodyAccess On",
            "SecResponseBodyMimeType application/json", "SecResponseBodyLimit 1048576", {limits}
            "SecRule REQUEST_HEADERS:Content-Type \"^text/xml\" \"id:200000,phase:1,t:none,pass,nolog,ctl:requestBodyProcessor=XML\"",
            "SecRule REQUEST_HEADERS:Content-Type \"^application/json\" \"id:200001,phase:1,t:none,pass,nolog,ctl:requestBodyProcessor=JSON\"",
            "SecRule REQUEST_HEADERS:Content-Type \"^application/x-www-form-urlencoded\" \"id:200006,phase:1,t:none,pass,nolog,ctl:requestBodyProcessor=URLENCODED\"",
            "SecRule RESPONSE_CONTENT_TYPE \"^application/json\" \"id:200007,phase:3,t:none,pass,nolog,ctl:responseBodyProcessor=JSON\""
            {rules}]}},
            "default_directives": "p", "enable_filter_state_logs": true}}"#
        )
    }

    /// The body limits of the policies above, with an argument limit the dense XML lists never reach, so that only the
    /// budget stops them.
    const LIMITS: &str =
        r#""SecRequestBodyLimit 8388608", "SecRequestBodyInMemoryLimit 8388608", "SecArgumentsLimit 100000000","#;

    /// What the transaction of `stream` holds, which the engine's share of the root's cap starts from.
    fn held(stream: &CorazaHttp) -> usize {
        stream
            .tx
            .as_deref()
            .expect("the transaction is kept")
            .body_memory_bytes()
    }

    /// The memory budget the parser of the request body of `stream` was given.
    fn parser_budget(stream: &CorazaHttp) -> Option<usize> {
        stream
            .tx
            .as_deref()
            .expect("the transaction is kept")
            .body_memory_budget()
    }

    /// A URL-encoded body of `size` bytes: one long value.
    fn pairs_of(size: usize) -> Vec<u8> {
        let mut body = b"a=".to_vec();
        body.resize(size, b'b');
        body
    }

    #[test]
    fn the_engine_is_leased_the_copies_its_processor_makes_and_not_those_it_does_not() {
        let size = MIB;
        let cases: [(&str, &[u8], usize); 3] = [
            // An XML body keeps no copy of itself.
            ("text/xml", &xml_list(size), 3),
            // A URL-encoded one stores the raw body in `REQUEST_BODY` before it parses, which the lease holds beside
            // the buffer, and the JSON text of a JSON body is kept once it is parsed, which the parser leaves room
            // for.
            ("application/x-www-form-urlencoded", &pairs_of(size), 4),
            ("application/json", br#"{"a":1}"#, 0),
        ];
        for (content_type, body, copies) in cases {
            let (mut stream, root) = stream_beside(&policy(LIMITS, ""), 0);
            let size = begin_post(&mut stream, content_type, body);
            let before = held(&stream);
            assert_eq!(
                stream.on_http_request_body(size, true),
                Action::Continue,
                "{content_type}"
            );
            let expected = if copies == 0 {
                // The JSON text copy is as long as the body, which here is tiny.
                MAX_ROOT_RETAINED_BODY_BYTES - 4 * size - before
            } else {
                MAX_ROOT_RETAINED_BODY_BYTES - copies * size - before
            };
            assert_eq!(parser_budget(&stream), Some(expected), "{content_type}");
            assert!(root.get() <= MAX_ROOT_RETAINED_BODY_BYTES);
        }
    }

    #[test]
    fn what_the_transaction_already_holds_is_taken_out_of_the_parsers_budget() {
        let body = xml_list(MIB);
        let budget = |rules: &str| {
            let (mut stream, _) = stream_beside(&policy(LIMITS, rules), 0);
            let size = begin_post(&mut stream, "text/xml", &body);
            assert_eq!(stream.on_http_request_body(size, true), Action::Continue);
            parser_budget(&stream).expect("the parser was given a budget")
        };
        let plain = budget("");
        // A rule of phase 1 that leaves half a megabyte in `TX`, as CRS's initialisation does in smaller amounts.
        let held_in_tx = 512 * 1024;
        let inflating = format!(
            r#", "SecAction \"id:1,phase:1,pass,nolog,setvar:'tx.held={}'\"""#,
            "x".repeat(held_in_tx)
        );
        let inflated = budget(&inflating);
        assert!(
            plain - inflated >= held_in_tx,
            "the parser had {plain} bytes, and {inflated} with {held_in_tx} bytes held in TX"
        );
    }

    #[test]
    fn a_body_the_engine_keeps_a_prefix_of_is_leased_the_prefix_and_not_the_whole_of_what_the_host_holds() {
        const LIMIT: usize = 8 * MIB;
        let limits = r#""SecRequestBodyLimit 8388608", "SecRequestBodyInMemoryLimit 8388608", "SecArgumentsLimit 100000000", "SecRequestBodyLimitAction ProcessPartial","#;
        // The host holds 16 MiB and the engine retains 8: with the host's buffer and the guest's copy that is 40 MiB,
        // where charging the whole body three times and a fourth for a copy asked for 64 and left nothing to parse.
        let body = xml_list(2 * LIMIT - 64);
        let (mut stream, _) = stream_beside(&policy(limits, ""), 0);
        let size = begin_post(&mut stream, "text/xml", &body);
        let before = held(&stream);
        assert_eq!(
            parse_only(&mut stream, size),
            Some(MAX_ROOT_RETAINED_BODY_BYTES - 2 * size - LIMIT - before)
        );
        assert!(test_hostcalls::local_reply_statuses().is_empty());
        refused_as_budget_stopped(&policy(limits, ""), "text/xml", &body);

        // A URL-encoded body of the same size also holds a copy of the 8 MiB prefix while it parses.
        let body = pairs_of(2 * LIMIT - 64);
        let (mut stream, _) = stream_beside(&policy(limits, ""), 0);
        let size = begin_post(&mut stream, "application/x-www-form-urlencoded", &body);
        let before = held(&stream);
        assert_eq!(
            parse_only(&mut stream, size),
            Some(MAX_ROOT_RETAINED_BODY_BYTES - 2 * size - 2 * LIMIT - before)
        );
        refused_as_budget_stopped(&policy(limits, ""), "application/x-www-form-urlencoded", &body);
    }

    /// Asserts that a POST of `body` on an idle root is refused because the parser stopped at what the root left it:
    /// both 8 `MiB` prefixes above parse into more than that, and the part not parsed is not forwarded.
    fn refused_as_budget_stopped(config: &str, content_type: &str, body: &[u8]) {
        let (mut stream, _) = stream_beside(config, 0);
        let size = begin_post(&mut stream, content_type, body);
        assert_eq!(stream.on_http_request_body(size, true), Action::Pause, "{content_type}");
        assert_eq!(test_hostcalls::local_reply_statuses(), [503], "{content_type}");
        assert_eq!(
            stream.final_outcome,
            Some(TerminalOutcome::BodyMemoryBudgetStopped { phase: "request-body" }),
            "{content_type}"
        );
    }

    /// Runs the request body of `stream`, whose headers wait for it, through the engine as `on_http_request_body`
    /// does but without drawing its verdict, and returns the memory budget the parser was given.
    fn parse_only(stream: &mut CorazaHttp, size: usize) -> Option<usize> {
        stream.request_host_bytes = size;
        assert!(stream.update_accounting(), "the body fits the root");
        assert!(stream.inspect_request_body(size, true).is_ok());
        parser_budget(stream)
    }

    #[test]
    fn a_urlencoded_body_whose_extra_copy_does_not_fit_is_refused_before_the_engine_copies_it() {
        let body = pairs_of(2 * MIB);
        let probe_policy = policy(LIMITS, "");
        let xml = xml_list(2 * MIB);
        let (mut probe, _) = stream_beside(&probe_policy, 0);
        begin_post(&mut probe, "text/xml", &xml);
        let before = held(&probe);

        // The host's buffer, the guest's copy and the engine's buffer fit with a mebibyte to spare, and the copy the
        // URL-encoded parser makes of the body first (two) does not.
        let others = MAX_ROOT_RETAINED_BODY_BYTES - 3 * body.len() - before - MIB;
        let (mut stream, root) = stream_beside(&probe_policy, others);
        let size = begin_post(&mut stream, "application/x-www-form-urlencoded", &body);
        assert_eq!(stream.on_http_request_body(size, true), Action::Pause);
        assert_eq!(test_hostcalls::local_reply_statuses(), [503]);
        assert_eq!(
            stream.final_outcome,
            Some(TerminalOutcome::RetainedBodyBudgetExhausted { phase: "request-body" })
        );
        assert_eq!(root.get(), others);

        // The same bytes with a processor that keeps no copy go to the engine, with nothing to parse in.
        let (mut stream, _) = stream_beside(&probe_policy, others);
        let size = begin_post(&mut stream, "text/xml", &xml);
        let left = parse_only(&mut stream, size).expect("the parser was given a budget");
        assert!(
            left.abs_diff(MIB) < 4096,
            "a mebibyte, less what the transaction held in between: {left}"
        );
        // The parser stops in that mebibyte, so the body is refused rather than forwarded.
        let (mut stream, _) = stream_beside(&probe_policy, others);
        begin_post(&mut stream, "text/xml", &xml);
        assert_eq!(stream.on_http_request_body(size, true), Action::Pause);
        assert_eq!(test_hostcalls::local_reply_statuses(), [503]);
        assert_eq!(
            stream.final_outcome,
            Some(TerminalOutcome::BodyMemoryBudgetStopped { phase: "request-body" })
        );
    }

    /// Runs the response of `stream`, whose request has been completed, with `body` as JSON, and returns what the
    /// filter answered.
    fn respond(stream: &mut CorazaHttp, body: &[u8]) -> Action {
        test_hostcalls::set_response_headers(&[(":status", b"200"), ("content-type", b"application/json")]);
        test_hostcalls::set_response_body(body);
        assert_eq!(stream.on_http_response_headers(2, false), Action::Pause);
        stream.on_http_response_body(body.len(), true)
    }

    /// A stream whose GET request is complete, beside streams that hold `others` bytes of the root.
    fn get_beside(config: &str, others: usize) -> CorazaHttp {
        let (mut stream, _) = stream_beside(config, others);
        let count = script_request("a.example", "http");
        assert_eq!(stream.on_http_request_headers(count, true), Action::Continue);
        stream
    }

    /// A dense JSON array of about `size` bytes.
    fn json_list(size: usize) -> Vec<u8> {
        let mut body = b"[".to_vec();
        while body.len() < size {
            body.extend_from_slice(b"1,");
        }
        body.push(b'1');
        body.push(b']');
        body
    }

    #[test]
    fn a_response_the_budget_stopped_the_parser_in_is_not_forwarded_as_inspected_but_an_ordinary_body_error_is() {
        let body = json_list(200 * 1024);
        let config = policy(LIMITS, "");
        // The root leaves the response parser a few kilobytes, which a body of 100,000 values does not fit.
        let probe = get_beside(&config, 0);
        let others = MAX_ROOT_RETAINED_BODY_BYTES - 4 * body.len() - held(&probe) - 16 * 1024;
        let mut stream = get_beside(&config, others);
        assert_eq!(respond(&mut stream, &body), Action::Pause);

        assert_eq!(
            test_hostcalls::local_reply_statuses(),
            [502],
            "the response is refused, as the connector does for a response it cannot inspect"
        );
        assert_eq!(
            stream.final_outcome,
            Some(TerminalOutcome::BodyMemoryBudgetStopped { phase: "response-body" })
        );
        assert_eq!(
            test_hostcalls::published_property("io.coraza.waf.v1.inspection_complete").as_deref(),
            Some("false")
        );
        assert_eq!(
            test_hostcalls::published_property("io.coraza.waf.v1.inspection_reason").as_deref(),
            Some("body_memory_budget_stopped")
        );

        // The same body with room to parse in is forwarded, and a body that is not JSON is a body error that the
        // policy's rules decide, as they always did: nothing is refused.
        for (others, body) in [(0, body.clone()), (0, b"[1,".to_vec())] {
            let mut stream = get_beside(&config, others);
            assert_eq!(respond(&mut stream, &body), Action::Continue);
            assert!(test_hostcalls::local_reply_statuses().is_empty(), "{body:?}");
            assert_eq!(stream.final_outcome, Some(TerminalOutcome::Completed));
            assert_eq!(
                test_hostcalls::published_property("io.coraza.waf.v1.inspection_complete").as_deref(),
                Some("true")
            );
        }
    }

    /// `count` rules, as CRS's are, that match every value of a list and keep it, its name and a message and data
    /// that expand it, in the form of the policy's JSON.
    fn flood_rules(count: usize, variable: &str, phase: u8) -> String {
        (0..count)
            .map(|index| {
                format!(
                    r#", "SecRule {variable} \"@rx .\" \"id:{},phase:{phase},t:none,pass,nolog,msg:'Matched',logdata:'%{{MATCHED_VAR_NAME}}: %{{MATCHED_VAR}}'\"""#,
                    3000 + index
                )
            })
            .collect()
    }

    #[test]
    fn a_flood_of_matches_the_root_cannot_hold_is_stopped_by_the_rules_budget_in_every_engine_mode() {
        // A list of about 200,000 values the parser fits in the root, which thirty rules would each match, keeping
        // about 90 MB of matches per rule where the root has 39 MiB left. Without a limit on what rules keep,
        // the first rule would have allocated that before the check after the phase refused it.
        let body = xml_list(MIB);
        for mode in ["", r#", "SecRuleEngine DetectionOnly""#] {
            let config = policy(LIMITS, &format!("{mode}{}", flood_rules(30, "XML:/*", 2)));
            let (mut stream, root) = stream_beside(&config, 0);
            let size = begin_post(&mut stream, "text/xml", &body);
            assert_eq!(stream.on_http_request_body(size, true), Action::Pause, "{mode:?}");
            assert_eq!(test_hostcalls::local_reply_statuses(), [503], "{mode:?}");
            assert_eq!(
                stream.final_outcome,
                Some(TerminalOutcome::BodyMemoryBudgetStopped { phase: "request-body" }),
                "{mode:?}: the budget the rules were given stopped them, not the check after them"
            );
            // The stop is reported: the engine's transaction was finished, and the telemetry says why it was refused.
            for (property, expected) in [
                ("inspection_complete", "false"),
                ("inspection_reason", "body_memory_budget_stopped"),
                ("terminal_outcome", "incomplete"),
            ] {
                assert_eq!(
                    test_hostcalls::published_property(&format!("io.coraza.waf.v1.{property}")).as_deref(),
                    Some(expected),
                    "{mode:?}: {property}"
                );
            }
            assert_eq!(root.get(), 0, "{mode:?}: the stream's charges are released with it");
        }

        // The same rules on an ordinary document are evaluated as before: nothing is refused.
        let config = policy(LIMITS, &flood_rules(30, "XML:/*", 2));
        let (mut stream, root) = stream_beside(&config, 0);
        let ordinary = b"<r><a>1</a><b c=\"2\">3</b></r>";
        let size = begin_post(&mut stream, "text/xml", ordinary);
        assert_eq!(stream.on_http_request_body(size, true), Action::Continue);
        assert!(test_hostcalls::local_reply_statuses().is_empty());
        assert!(root.get() <= MAX_ROOT_RETAINED_BODY_BYTES);

        // A flood the root can hold is evaluated whole, and what its matches keep is what the root's accounting then
        // holds for the stream, within the 64 MiB.
        let config = policy(LIMITS, &flood_rules(2, "XML:/*", 2));
        let (mut stream, root) = stream_beside(&config, 0);
        let body = xml_list(MIB / 8);
        let size = begin_post(&mut stream, "text/xml", &body);
        assert_eq!(stream.on_http_request_body(size, true), Action::Continue);
        assert!(test_hostcalls::local_reply_statuses().is_empty());
        assert!(
            (8 * MIB..=MAX_ROOT_RETAINED_BODY_BYTES).contains(&root.get()),
            "the matches are held in the root: {} bytes",
            root.get()
        );
    }

    #[test]
    fn a_response_whose_rules_the_root_cannot_hold_is_replaced_in_every_engine_mode() {
        // About 100,000 values the response parser fits, which thirty rules of phase 4 match each.
        let body = json_list(200 * 1024);
        for mode in ["", r#", "SecRuleEngine DetectionOnly""#] {
            let config = policy(LIMITS, &format!("{mode}{}", flood_rules(30, "RESPONSE_ARGS", 4)));
            let mut stream = get_beside(&config, 0);
            assert_eq!(respond(&mut stream, &body), Action::Pause, "{mode:?}");
            assert_eq!(test_hostcalls::local_reply_statuses(), [502], "{mode:?}");
            assert_eq!(
                stream.final_outcome,
                Some(TerminalOutcome::BodyMemoryBudgetStopped { phase: "response-body" }),
                "{mode:?}"
            );
            assert_eq!(
                test_hostcalls::published_property("io.coraza.waf.v1.inspection_reason").as_deref(),
                Some("body_memory_budget_stopped"),
                "{mode:?}"
            );
        }

        // An ordinary response under the same rules is forwarded.
        let config = policy(LIMITS, &flood_rules(30, "RESPONSE_ARGS", 4));
        let mut stream = get_beside(&config, 0);
        assert_eq!(respond(&mut stream, b"[1,2,3]"), Action::Continue);
        assert!(test_hostcalls::local_reply_statuses().is_empty());
        assert_eq!(stream.final_outcome, Some(TerminalOutcome::Completed));
    }

    #[test]
    fn a_response_whose_rules_the_budget_stopped_is_a_502_even_when_the_retention_check_after_the_phase_fails_first() {
        // A small response, and a root with a few kilobytes to spare beside it: the parse leaves the rules the 64 KiB
        // reserve, thirty rules match every value and the budget stops them, and what they kept is still held when the
        // phase ends, which is more than the root has left (the check after the phase fails too).
        let body = json_list(512);
        for mode in ["", r#", "SecRuleEngine DetectionOnly""#] {
            let config = policy(LIMITS, &format!("{mode}{}", flood_rules(30, "RESPONSE_ARGS", 4)));
            let base = held(&get_beside(&config, 0));
            for slack in [8 * 1024, 32 * 1024] {
                let others = MAX_ROOT_RETAINED_BODY_BYTES - 4 * body.len() - base - slack;
                let mut stream = get_beside(&config, others);
                assert_eq!(respond(&mut stream, &body), Action::Pause, "{mode:?} {slack}");
                assert_eq!(test_hostcalls::local_reply_statuses(), [502], "{mode:?} {slack}");
                assert_eq!(
                    stream.final_outcome,
                    Some(TerminalOutcome::BodyMemoryBudgetStopped { phase: "response-body" }),
                    "{mode:?} {slack}: the stop of the rules is the reason, not the check that came after it"
                );
                assert_eq!(
                    test_hostcalls::published_property("io.coraza.waf.v1.inspection_reason").as_deref(),
                    Some("body_memory_budget_stopped"),
                    "{mode:?} {slack}"
                );
            }
        }
    }

    #[test]
    fn a_request_the_budget_stopped_the_parser_in_is_refused_even_when_no_rule_denies() {
        let body = xml_list(MIB);
        let config = policy(LIMITS, "");
        let finish = |others: usize| {
            let (mut stream, _) = stream_beside(&config, 0);
            let size = begin_post(&mut stream, "text/xml", &body);
            let before = held(&stream);
            drop(stream);
            let (mut stream, _) = stream_beside(&config, others.saturating_sub(before));
            begin_post(&mut stream, "text/xml", &body);
            let action = stream.on_http_request_body(size, true);
            if action == Action::Continue {
                test_hostcalls::set_response_headers(&[(":status", b"200")]);
                assert_eq!(stream.on_http_response_headers(1, true), Action::Continue);
            }
            (
                action,
                test_hostcalls::local_reply_statuses(),
                test_hostcalls::published_property("io.coraza.waf.v1.inspection_complete"),
                test_hostcalls::published_property("io.coraza.waf.v1.inspection_reason"),
                test_hostcalls::published_property("io.coraza.waf.v1.terminal_outcome"),
            )
        };
        // Room for the three charges and a few kilobytes: the parser gets that far and no further, and the part it
        // did not parse is not forwarded.
        let tight = MAX_ROOT_RETAINED_BODY_BYTES - 3 * body.len() - 8 * 1024;
        assert_eq!(
            finish(tight),
            (
                Action::Pause,
                vec![503],
                Some("false".to_owned()),
                Some("body_memory_budget_stopped".to_owned()),
                Some("incomplete".to_owned())
            ),
            "no rule reads REQBODY_ERROR, and the connector refuses the body its budget stopped"
        );
        assert_eq!(
            finish(0),
            (
                Action::Continue,
                vec![],
                Some("true".to_owned()),
                Some("complete".to_owned()),
                Some("completed".to_owned())
            )
        );
    }

    /// `content-type` of a URL-encoded form.
    const FORM: &str = "application/x-www-form-urlencoded";

    /// What the filter answered a POST of `body` as `content_type`, beside streams that hold `others` bytes of the
    /// root: the action, the local replies and the published inspection reason.
    fn post_beside(config: &str, others: usize, content_type: &str, body: &[u8]) -> (Action, Vec<u32>, Option<String>) {
        let (mut stream, _) = stream_beside(config, others);
        begin_post(&mut stream, content_type, body);
        let action = stream.on_http_request_body(body.len(), true);
        (
            action,
            test_hostcalls::local_reply_statuses(),
            test_hostcalls::published_property("io.coraza.waf.v1.inspection_reason"),
        )
    }

    /// A custom body policy without the baseline, as a CRS-only policy is for `REQBODY_ERROR`: it denies `attack` in
    /// any argument and reads no body error.
    const NO_BASELINE: &str = r#"{"directives_map": {"p": ["SecRuleEngine On", "SecRequestBodyAccess On",
        "SecRequestBodyLimit 16777216", "SecRequestBodyInMemoryLimit 16777216",
        "SecRule REQUEST_HEADERS:Content-Type \"^application/x-www-form-urlencoded\" \"id:10,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED\"",
        "SecRule REQUEST_HEADERS:Content-Type \"^application/json\" \"id:11,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON\"",
        "SecRule ARGS \"@contains attack\" \"id:900,phase:2,deny,status:403\""]},
        "default_directives": "p", "enable_filter_state_logs": true}"#;

    /// The reference deployment's baseline in front of the same rule.
    const WITH_BASELINE: &str = r#"{"directives_map": {"p": ["Include @recommended-conf", "SecRuleEngine On",
        "SecRule ARGS \"@contains attack\" \"id:900,phase:2,deny,status:403\""]},
        "default_directives": "p", "enable_filter_state_logs": true}"#;

    /// `pairs` URL-encoded pairs with values of `value_len` bytes, then the attack as the last argument.
    fn urlencoded(pairs: usize, value_len: usize) -> Vec<u8> {
        let value = "v".repeat(value_len);
        let mut body = Vec::new();
        for index in 0..pairs {
            body.extend_from_slice(format!("k{index}={value}&").as_bytes());
        }
        body.extend_from_slice(b"x=attack");
        body
    }

    /// A JSON object of `pairs` members with values of `value_len` bytes, then the attack as the last member.
    fn json_object(pairs: usize, value_len: usize) -> Vec<u8> {
        let value = "v".repeat(value_len);
        let mut body = b"{".to_vec();
        for index in 0..pairs {
            body.extend_from_slice(format!("\"k{index}\":\"{value}\",").as_bytes());
        }
        body.extend_from_slice(b"\"x\":\"attack\"}");
        body
    }

    /// Whether a POST answer is the refusal of a body the budget stopped.
    fn budget_refusal(answer: &(Action, Vec<u32>, Option<String>)) -> bool {
        *answer == (Action::Pause, vec![503], Some("body_memory_budget_stopped".to_owned()))
    }

    #[test]
    fn a_body_the_budget_stopped_must_not_be_forwarded() {
        // About 256 KiB in 500 benign pairs, under SecArgumentsLimit, then the attack.
        let body = urlencoded(500, 512);
        assert_eq!(
            post_beside(NO_BASELINE, 0, FORM, &body).1,
            [403],
            "an idle root: the attack is denied"
        );
        let mut stopped = 0;
        for slack in [512 * 1024, 256 * 1024, 128 * 1024, 64 * 1024, 32 * 1024, 16 * 1024] {
            // What the other streams of this root hold: everything but four copies of this body and `slack`.
            let others = MAX_ROOT_RETAINED_BODY_BYTES - 4 * body.len() - slack;
            let answer = post_beside(NO_BASELINE, others, FORM, &body);
            assert!(
                answer.1 == [403] || budget_refusal(&answer),
                "slack {slack}: the body was denied or refused, not forwarded: {answer:?}"
            );
            stopped += usize::from(budget_refusal(&answer));
        }
        assert!(stopped > 0, "at least one slack value stopped the parser");
    }

    #[test]
    fn a_single_large_body_on_an_idle_root_is_denied_or_refused() {
        // 500 pairs stay under SecArgumentsLimit, whose 413 would otherwise mask the budget. The two larger bodies
        // fill the idle root on their own: their host buffer, guest copy and parse copies take most of it.
        for value_len in [8_000_usize, 16_000, 24_000, 32_000] {
            let body = urlencoded(500, value_len);
            let answer = post_beside(NO_BASELINE, 0, FORM, &body);
            assert!(
                answer.1 == [403] || budget_refusal(&answer),
                "a {} byte body was denied or refused, not forwarded: {answer:?}",
                body.len()
            );
            if value_len >= 24_000 {
                assert!(budget_refusal(&answer), "{} bytes: {answer:?}", body.len());
            }
        }
    }

    #[test]
    fn a_body_the_budget_stopped_is_refused_in_detection_only_too() {
        // The budget is the connector's limit, not a rule's: the engine mode does not let the unread part through.
        let detection_only = NO_BASELINE.replace("SecRuleEngine On", "SecRuleEngine DetectionOnly");
        let body = urlencoded(500, 32_000);
        assert!(
            budget_refusal(&post_beside(&detection_only, 0, FORM, &body)),
            "the body was refused"
        );
    }

    #[test]
    fn a_json_body_on_a_busy_root_is_refused() {
        let body = json_object(500, 512);
        assert_eq!(
            post_beside(NO_BASELINE, 0, "application/json", &body).1,
            [403],
            "control: an idle root denies"
        );
        for slack in [512 * 1024, 64 * 1024, 16 * 1024] {
            let others = MAX_ROOT_RETAINED_BODY_BYTES - 4 * body.len() - slack;
            let answer = post_beside(NO_BASELINE, others, "application/json", &body);
            assert!(budget_refusal(&answer), "slack {slack}: {answer:?}");
        }
    }

    #[test]
    fn baseline_rule_200002_backstops_the_budget_stop() {
        // A rule that denies on the body error still answers first: 400 from rule 200002, not the connector's 503.
        let body = urlencoded(500, 512);
        assert_eq!(post_beside(WITH_BASELINE, 0, FORM, &body).1, [403]);
        for slack in [512 * 1024, 64 * 1024, 16 * 1024] {
            let others = MAX_ROOT_RETAINED_BODY_BYTES - 4 * body.len() - slack;
            assert_eq!(
                post_beside(WITH_BASELINE, others, FORM, &body),
                (Action::Pause, vec![400], Some("denied".to_owned())),
                "slack {slack}"
            );
        }
    }

    #[test]
    fn a_response_the_budget_stopped_under_process_partial_is_refused_not_forwarded() {
        // With ProcessPartial and a limit the body fits in, a parse the budget stopped is not reported as a truncation
        // that lets the response through.
        let body = json_list(200 * 1024);
        let config = policy(LIMITS, r#", "SecResponseBodyLimitAction ProcessPartial""#);
        let probe = get_beside(&config, 0);
        let others = MAX_ROOT_RETAINED_BODY_BYTES - 4 * body.len() - held(&probe) - 16 * 1024;
        let mut stream = get_beside(&config, others);
        assert_eq!(respond(&mut stream, &body), Action::Pause);
        assert_eq!(test_hostcalls::local_reply_statuses(), [502]);
        assert_eq!(
            stream.final_outcome,
            Some(TerminalOutcome::BodyMemoryBudgetStopped { phase: "response-body" })
        );
    }

    #[test]
    fn a_request_body_the_policy_does_not_read_is_reported_as_not_inspected() {
        let config = r#"{"directives_map": {"p": ["SecRuleEngine On", "SecRequestBodyAccess Off"]},
            "default_directives": "p", "enable_filter_state_logs": true}"#;
        let body = b"q=1' UNION SELECT password FROM users--";
        let mut post = stream(config);
        test_hostcalls::reset();
        let length = body.len().to_string();
        let headers: [(&str, &[u8]); 6] = [
            (":authority", b"a.example"),
            (":scheme", b"http"),
            (":method", b"POST"),
            (":path", b"/"),
            ("content-type", FORM.as_bytes()),
            ("content-length", length.as_bytes()),
        ];
        test_hostcalls::set_request_headers(&headers);
        script_connection_properties();
        test_hostcalls::set_request_body(body);
        assert_eq!(post.on_http_request_headers(headers.len(), false), Action::Continue);
        assert_eq!(post.on_http_request_body(body.len(), true), Action::Continue);
        test_hostcalls::set_response_headers(&[(":status", b"200")]);
        assert_eq!(post.on_http_response_headers(1, true), Action::Continue);
        assert_eq!(
            test_hostcalls::published_property("io.coraza.waf.v1.inspection_complete").as_deref(),
            Some("false")
        );
        assert_eq!(
            test_hostcalls::published_property("io.coraza.waf.v1.inspection_reason").as_deref(),
            Some("request_body_not_inspected")
        );

        // A request without a body loses nothing.
        let mut get = stream(config);
        let count = script_request("a.example", "http");
        assert_eq!(get.on_http_request_headers(count, true), Action::Continue);
        test_hostcalls::set_response_headers(&[(":status", b"200")]);
        assert_eq!(get.on_http_response_headers(1, true), Action::Continue);
        assert_eq!(
            test_hostcalls::published_property("io.coraza.waf.v1.inspection_complete").as_deref(),
            Some("true")
        );
    }

    /// A policy that does not read request bodies.
    const BODY_OFF: &str = r#"{"directives_map": {"p": ["SecRuleEngine On", "SecRequestBodyAccess Off",
        "SecRule RESPONSE_STATUS \"@streq 201\" \"id:6,phase:3,deny,status:502\""]},
        "default_directives": "p", "enable_filter_state_logs": true}"#;

    /// Scripts the headers of a POST whose body follows in `frames` (size, end of stream), runs the stream through
    /// them, then answers `status`; returns the request actions and the published reason, outcome and completeness.
    fn post_in_frames(config: &str, frames: &[(usize, bool)], status: &[u8]) -> (Vec<Action>, [Option<String>; 3]) {
        let mut post = stream(config);
        test_hostcalls::reset();
        let headers: [(&str, &[u8]); 5] = [
            (":authority", b"a.example"),
            (":scheme", b"http"),
            (":method", b"POST"),
            (":path", b"/"),
            ("content-type", b"application/octet-stream"),
        ];
        test_hostcalls::set_request_headers(&headers);
        script_connection_properties();
        let mut actions = vec![post.on_http_request_headers(headers.len(), false)];
        let mut held = 0;
        for &(size, end_of_stream) in frames {
            // A paused body accumulates in the host's buffer; a continued one is passed on.
            held = if actions.last() == Some(&Action::Pause) {
                held + size
            } else {
                size
            };
            test_hostcalls::set_request_body(&vec![b'x'; held]);
            actions.push(post.on_http_request_body(held, end_of_stream));
        }
        if test_hostcalls::local_reply_statuses().is_empty() {
            test_hostcalls::set_response_headers(&[(":status", status)]);
            post.on_http_response_headers(1, true);
        }
        (actions, published())
    }

    /// The reason, outcome and completeness the stream published.
    fn published() -> [Option<String>; 3] {
        ["inspection_reason", "terminal_outcome", "inspection_complete"]
            .map(|name| test_hostcalls::published_property(&format!("io.coraza.waf.v1.{name}")))
    }

    /// The published reason, outcome and completeness.
    fn health(reason: &str, outcome: &str, complete: &str) -> [Option<String>; 3] {
        [reason, outcome, complete].map(|value| Some(value.to_owned()))
    }

    /// [`BODY_OFF`]'s phase-3 rule, on a policy that inspects only a 1-byte prefix of the request body.
    const BODY_CUT: &str = r#"{"directives_map": {"p": ["SecRuleEngine On", "SecRequestBodyLimit 1",
        "SecRequestBodyLimitAction ProcessPartial",
        "SecRule RESPONSE_STATUS \"@streq 201\" \"id:6,phase:3,deny,status:502\""]},
        "default_directives": "p", "enable_filter_state_logs": true}"#;

    /// Whether the stream answered with one local reply, of `status`.
    fn refused_with(status: u32) -> bool {
        test_hostcalls::local_reply_statuses() == [status]
    }

    #[test]
    fn a_response_phase_denial_after_an_unread_request_body_reports_both() {
        let (actions, published) = post_in_frames(BODY_OFF, &[(3, true)], b"201");
        assert_eq!(actions, [Action::Continue, Action::Continue], "the body is not held");
        assert!(refused_with(502), "the denial refuses the response");
        assert_eq!(
            published,
            health("request_body_not_inspected", "denied", "false"),
            "the body reached the backend unread, and the stream was denied"
        );
        // As a truncated body is reported beside the same denial.
        let (_, published) = post_in_frames(BODY_CUT, &[(3, true)], b"201");
        assert!(refused_with(502), "the denial refuses the response");
        assert_eq!(published, health("body_partially_inspected", "denied", "false"));
        // Without the denial, the unread body is reported beside the completed stream.
        let (_, published) = post_in_frames(BODY_OFF, &[(3, true)], b"200");
        assert!(test_hostcalls::local_reply_statuses().is_empty(), "nothing is refused");
        assert_eq!(published, health("request_body_not_inspected", "completed", "false"));
        // A response-phase denial before any body byte came ends the stream, so none of the body reaches the backend.
        let (_, published) = post_in_frames(BODY_OFF, &[], b"201");
        assert!(refused_with(502), "the denial refuses the response");
        assert_eq!(published, health("denied", "denied", "true"));
    }

    #[test]
    fn a_response_refusal_holds_the_rest_of_an_unread_request_body() {
        // Without response body inspection, phase 4 runs at the response headers. Its denial is a local reply that
        // ends the stream, over HTTP/1.1 and HTTP/2 alike, so what the request body had not yet sent never reaches the
        // backend; the filter holds it too, so it stays held when the reply could not be sent, as on this host.
        let config = r#"{"directives_map": {"p": ["SecRuleEngine On", "SecRequestBodyAccess Off",
            "SecAction \"id:6,phase:4,deny,status:502\""]},
            "default_directives": "p", "enable_filter_state_logs": true}"#;
        let refuse = |post: &mut CorazaHttp| {
            test_hostcalls::set_response_headers(&[(":status", b"200"), ("content-type", b"text/plain")]);
            assert_eq!(post.on_http_response_headers(2, false), Action::Pause);
            assert!(
                post.lifecycle.finalized,
                "the denial ended the stream at the response headers"
            );
            assert!(refused_with(502), "the denial refuses the response");
        };

        // Refused before any body byte came: none went to the backend unread.
        let mut post = stream(config);
        let count = script_request("a.example", "http");
        assert_eq!(post.on_http_request_headers(count, false), Action::Continue);
        refuse(&mut post);
        let denied = health("denied", "denied", "true");
        assert_eq!(published(), denied, "nothing of the body went through");
        test_hostcalls::set_request_body(b"abc");
        assert_eq!(post.on_http_request_body(3, true), Action::Pause, "the body is held");
        assert_eq!(post.on_http_request_trailers(0), Action::Pause, "and its trailers");
        assert_eq!(published(), denied);

        // Refused after body bytes went through: those reached the backend unread, and the rest is held.
        let mut post = stream(config);
        let count = script_request("a.example", "http");
        assert_eq!(post.on_http_request_headers(count, false), Action::Continue);
        test_hostcalls::set_request_body(b"abc");
        assert_eq!(
            post.on_http_request_body(3, false),
            Action::Continue,
            "the body is not held"
        );
        refuse(&mut post);
        assert_eq!(published(), health("request_body_not_inspected", "denied", "false"));
        assert_eq!(post.on_http_request_body(3, true), Action::Pause, "the rest is held");

        // A request-phase denial is the filter's own reply, so no body follows it.
        let config = r#"{"directives_map": {"p": ["SecRuleEngine On", "SecRequestBodyAccess Off",
            "SecAction \"id:7,phase:2,deny,status:403\""]},
            "default_directives": "p", "enable_filter_state_logs": true}"#;
        let mut post = stream(config);
        let count = script_request("a.example", "http");
        post.on_http_request_headers(count, false);
        assert_eq!(test_hostcalls::local_reply_statuses(), [403]);
        assert_eq!(published(), health("denied", "denied", "true"));
    }

    #[test]
    fn a_request_that_ends_with_trailers_and_no_body_is_not_an_unread_one() {
        // HTTP/2 can end a request with trailers alone, after headers without END_STREAM.
        let mut post = stream(BODY_OFF);
        let count = script_request("a.example", "http");
        assert_eq!(post.on_http_request_headers(count, false), Action::Continue);
        test_hostcalls::set_request_trailers(&[("x-checksum", b"0")]);
        assert_eq!(post.on_http_request_trailers(1), Action::Continue);
        test_hostcalls::set_response_headers(&[(":status", b"200")]);
        assert_eq!(post.on_http_response_headers(1, true), Action::Continue);
        assert_eq!(published(), health("complete", "completed", "true"), "no body");
        // Bytes before the trailers stay unread.
        let mut post = stream(BODY_OFF);
        let count = script_request("a.example", "http");
        assert_eq!(post.on_http_request_headers(count, false), Action::Continue);
        test_hostcalls::set_request_body(b"abc");
        assert_eq!(post.on_http_request_body(3, false), Action::Continue);
        test_hostcalls::set_request_trailers(&[("x-checksum", b"0")]);
        assert_eq!(post.on_http_request_trailers(1), Action::Continue);
        test_hostcalls::set_response_headers(&[(":status", b"200")]);
        assert_eq!(post.on_http_response_headers(1, true), Action::Continue);
        assert_eq!(
            test_hostcalls::published_property("io.coraza.waf.v1.inspection_reason").as_deref(),
            Some("request_body_not_inspected")
        );
    }

    #[test]
    fn an_empty_last_data_frame_is_an_empty_body_and_not_an_unread_one() {
        // HTTP/2 can end a request with an empty DATA frame after headers without END_STREAM.
        let (actions, published) = post_in_frames(BODY_OFF, &[(0, true)], b"200");
        assert_eq!(actions, [Action::Continue, Action::Continue], "nothing is held");
        assert_eq!(published, health("complete", "completed", "true"), "an empty body");
        // Bytes in an earlier frame stay unread when the last one is empty.
        let (_, published) = post_in_frames(BODY_OFF, &[(3, false), (0, true)], b"200");
        assert_eq!(
            published,
            health("request_body_not_inspected", "completed", "false"),
            "bytes went through"
        );
        // A response that completes while the body may still come is not reported as having seen it.
        let (_, published) = post_in_frames(BODY_OFF, &[], b"200");
        assert_eq!(
            published,
            health("request_body_not_inspected", "completed", "false"),
            "the body had not ended"
        );
    }

    /// Runs a POST of `body` to `path`, with `headers` after its pseudo-headers, through the stream to a 200 response
    /// unless the filter replies first; returns the local replies and the published reason, outcome and completeness.
    fn post_with(config: &str, path: &str, headers: &[(&str, &[u8])], body: &[u8]) -> (Vec<u32>, [Option<String>; 3]) {
        let mut post = stream(config);
        test_hostcalls::reset();
        let mut all: Vec<(&str, &[u8])> = vec![
            (":authority", b"a.example"),
            (":scheme", b"http"),
            (":method", b"POST"),
            (":path", path.as_bytes()),
        ];
        all.extend_from_slice(headers);
        test_hostcalls::set_request_headers(&all);
        script_connection_properties();
        test_hostcalls::set_request_body(body);
        post.on_http_request_headers(all.len(), false);
        if test_hostcalls::local_reply_statuses().is_empty() {
            post.on_http_request_body(body.len(), true);
        }
        if test_hostcalls::local_reply_statuses().is_empty() {
            test_hostcalls::set_response_headers(&[(":status", b"200")]);
            post.on_http_response_headers(1, true);
        }
        (test_hostcalls::local_reply_statuses(), published())
    }

    /// `fields` multipart text parts, then a file part when `file` is set.
    fn multipart(fields: usize, file: bool) -> Vec<u8> {
        let mut body = Vec::new();
        for index in 0..fields {
            body.extend_from_slice(
                format!("--b\r\nContent-Disposition: form-data; name=\"k{index}\"\r\n\r\nv\r\n").as_bytes(),
            );
        }
        if file {
            body.extend_from_slice(
                b"--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\nhello\r\n",
            );
        }
        body.extend_from_slice(b"--b--\r\n");
        body
    }

    #[test]
    fn a_policy_without_a_body_access_line_refuses_uploads_large_forms_and_encoded_bodies() {
        let policy = |directives: &str| {
            format!(
                r#"{{"directives_map": {{"p": ["SecRuleEngine On"{directives}]}}, "default_directives": "p",
                "enable_filter_state_logs": true}}"#
            )
        };
        let default_on = policy("");
        let form: &[(&str, &[u8])] = &[("content-type", FORM.as_bytes())];
        let upload: &[(&str, &[u8])] = &[("content-type", b"multipart/form-data; boundary=b")];
        let gzip: &[(&str, &[u8])] = &[("content-type", FORM.as_bytes()), ("content-encoding", b"gzip")];
        let refused =
            |status, reason: &str, outcome: &str, complete: &str| (vec![status], health(reason, outcome, complete));
        let passed = || (vec![], health("complete", "completed", "true"));
        // A file part: the engine's host ban on uploads, an interruption with no rule.
        assert_eq!(
            post_with(&default_on, "/upload", upload, &multipart(1, true)),
            refused(413, "denied", "denied", "true")
        );
        assert_eq!(
            ["rule_id", "status"].map(|name| test_hostcalls::published_property(&format!("io.coraza.waf.{name}"))),
            [Some("0".to_owned()), Some("413".to_owned())]
        );
        assert_eq!(
            post_with(&default_on, "/upload", upload, &multipart(1, false)),
            passed()
        );
        // More than `SecArgumentsLimit` (1000) fields. A multipart body the limit stopped could hide a file part in
        // what it did not read, so the upload ban refuses it.
        assert_eq!(
            post_with(&default_on, "/upload", form, &urlencoded(999, 1)),
            passed(),
            "1000 fields"
        );
        assert_eq!(
            post_with(&default_on, "/upload", form, &urlencoded(1000, 1)),
            refused(413, "incomplete", "incomplete", "false")
        );
        // A JSON body that a rule parses as JSON, as CRS rules 901360 and 901370 do for `application/*+json`.
        let json_rule = policy(
            r#", "SecRule REQUEST_HEADERS:Content-Type \"@contains +json\" \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON\"""#,
        );
        let json_api: &[(&str, &[u8])] = &[("content-type", b"application/vnd.api+json")];
        assert_eq!(
            post_with(&json_rule, "/upload", json_api, &json_object(998, 1)),
            passed(),
            "999 members"
        );
        assert_eq!(
            post_with(&json_rule, "/upload", json_api, &json_object(999, 1)),
            passed(),
            "1000 members"
        );
        assert_eq!(
            post_with(&json_rule, "/upload", json_api, &json_object(1000, 1)),
            refused(413, "incomplete", "incomplete", "false"),
            "1001 members"
        );
        assert_eq!(
            post_with(&default_on, "/upload", upload, &multipart(1001, false)),
            refused(413, "denied", "denied", "true")
        );
        // Any `Content-Encoding` but `identity`.
        assert_eq!(
            post_with(&default_on, "/upload", gzip, b"a=1"),
            refused(415, "unsupported", "unsupported", "false")
        );
        // A body of `SecRequestBodyLimit` bytes or more, under the engine default `Reject`, which reads none of it.
        assert_eq!(
            post_with(&policy(r#", "SecRequestBodyLimit 4""#), "/upload", form, b"a=1"),
            passed(),
            "under the limit"
        );
        assert_eq!(
            post_with(&policy(r#", "SecRequestBodyLimit 4""#), "/upload", form, b"a=12"),
            refused(413, "denied", "denied", "false")
        );

        // The upload ban and the limit are the engine's interruptions, which `DetectionOnly` does not enforce; the
        // argument limit and the encoding are the connector's own refusals, in every mode but `Off`.
        let detection_only = policy(r#", "SecRuleEngine DetectionOnly""#);
        assert_eq!(
            post_with(&detection_only, "/upload", upload, &multipart(1, true)),
            passed()
        );
        assert_eq!(
            post_with(&detection_only, "/upload", form, &urlencoded(1000, 1)),
            refused(413, "incomplete", "incomplete", "false")
        );
        assert_eq!(
            post_with(&detection_only, "/upload", gzip, b"a=1"),
            refused(415, "unsupported", "unsupported", "false")
        );

        // `SecRequestBodyAccess Off` passes each of them on unread.
        let unread = || (vec![], health("request_body_not_inspected", "completed", "false"));
        let body_off = policy(r#", "SecRequestBodyAccess Off""#);
        assert_eq!(post_with(&body_off, "/upload", upload, &multipart(1, true)), unread());
        assert_eq!(post_with(&body_off, "/upload", form, &urlencoded(1000, 1)), unread());
        assert_eq!(post_with(&body_off, "/upload", gzip, b"a=1"), unread());
        // A higher `SecArgumentsLimit` reads a larger form.
        assert_eq!(
            post_with(
                &policy(r#", "SecArgumentsLimit 2000""#),
                "/upload",
                form,
                &urlencoded(1000, 1)
            ),
            passed()
        );
    }

    /// Runs a GET that ends at its headers, with one `cookie` header of `n` cookies for each `n` in `per_header`,
    /// through the stream to a 200 response unless the filter replies first; returns the local replies and the
    /// published reason, outcome and completeness.
    fn get_with_cookies(config: &str, per_header: &[usize]) -> (Vec<u32>, [Option<String>; 3]) {
        let mut get = stream(config);
        test_hostcalls::reset();
        let mut first = 0;
        let cookies: Vec<String> = per_header
            .iter()
            .map(|&count| {
                let header = (first..first + count)
                    .map(|index| format!("c{index}=v"))
                    .collect::<Vec<_>>()
                    .join("; ");
                first += count;
                header
            })
            .collect();
        let mut all: Vec<(&str, &[u8])> = vec![
            (":authority", b"a.example"),
            (":scheme", b"http"),
            (":method", b"GET"),
            (":path", b"/"),
        ];
        all.extend(cookies.iter().map(|header| ("cookie", header.as_bytes())));
        test_hostcalls::set_request_headers(&all);
        script_connection_properties();
        get.on_http_request_headers(all.len(), true);
        if test_hostcalls::local_reply_statuses().is_empty() {
            test_hostcalls::set_response_headers(&[(":status", b"200")]);
            get.on_http_response_headers(1, true);
        }
        (test_hostcalls::local_reply_statuses(), published())
    }

    #[test]
    fn more_than_the_argument_limit_of_cookies_is_refused_even_when_the_request_has_no_body() {
        let policy = |directives: &str| {
            format!(
                r#"{{"directives_map": {{"p": ["SecRuleEngine On"{directives}]}}, "default_directives": "p",
                "enable_filter_state_logs": true}}"#
            )
        };
        let plain = policy("");
        let refused = (vec![413], health("incomplete", "incomplete", "false"));
        let passed = (vec![], health("complete", "completed", "true"));
        // `SecArgumentsLimit` is 1000: the first cookie past it is dropped, and the filter refuses the request in
        // every engine mode but `Off`, as it does for a body field past the limit.
        assert_eq!(get_with_cookies(&plain, &[1000]), passed, "1000 cookies");
        assert_eq!(get_with_cookies(&plain, &[1001]), refused, "1001 cookies");
        assert_eq!(
            get_with_cookies(&plain, &[500, 501]),
            refused,
            "cookies count across `cookie` headers, as HTTP/2 sends them"
        );
        assert_eq!(
            get_with_cookies(&policy(r#", "SecRuleEngine DetectionOnly""#), &[1001]),
            refused
        );
        assert_eq!(
            get_with_cookies(&policy(r#", "SecRuleEngine Off""#), &[1001]).0,
            Vec::<u32>::new()
        );
        assert_eq!(
            get_with_cookies(&policy(r#", "SecArgumentsLimit 2000""#), &[1001]),
            passed
        );
        // A body left unread under `SecRequestBodyAccess Off` does not excuse the cookies.
        let cookies = (0..1001)
            .map(|index| format!("c{index}=v"))
            .collect::<Vec<_>>()
            .join("; ");
        assert_eq!(
            post_with(
                &policy(r#", "SecRequestBodyAccess Off""#),
                "/",
                &[("cookie", cookies.as_bytes())],
                b"a=b"
            ),
            refused,
            "a request with a body, which is not read, still has its cookies counted"
        );
        // With the baseline, its rule 200004 answers 400 first.
        assert_eq!(
            get_with_cookies(WITH_BASELINE, &[1001]),
            (vec![400], health("denied", "denied", "true"))
        );
        assert_eq!(
            test_hostcalls::published_property("io.coraza.waf.rule_id").as_deref(),
            Some("200004")
        );
        assert_eq!(get_with_cookies(WITH_BASELINE, &[1000]), passed);
    }

    /// An XML document of `values` text values, the last of them `last`.
    fn xml_values(values: usize, last: &str) -> Vec<u8> {
        let mut body = b"<r>".to_vec();
        for _ in 1..values {
            body.extend_from_slice(b"<i>1</i>");
        }
        body.extend_from_slice(format!("<i>{last}</i></r>").as_bytes());
        body
    }

    #[test]
    fn an_xml_body_past_the_argument_limit_or_not_well_formed_is_never_reported_complete_unless_a_rule_denies_it() {
        let policy = |directives: &str| {
            format!(
                r#"{{"directives_map": {{"p": ["SecRuleEngine On",
                "SecRule REQUEST_HEADERS:Content-Type \"@contains xml\" \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=XML\"",
                "SecRule REQUEST_HEADERS:Content-Type \"@contains json\" \"id:2,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON\"",
                "SecRule XML:/* \"@contains attack\" \"id:900,phase:2,deny,status:403\""{directives}]}},
                "default_directives": "p", "enable_filter_state_logs": true}}"#
            )
        };
        let xml: &[(&str, &[u8])] = &[("content-type", b"application/xml")];
        let default_on = policy("");
        let refused =
            |status, reason: &str, outcome: &str, complete: &str| (vec![status], health(reason, outcome, complete));
        let passed = || (vec![], health("complete", "completed", "true"));
        // `SecArgumentsLimit` (1000) values are read whole, and a rule reads the last of them.
        assert_eq!(
            post_with(&default_on, "/", xml, &xml_values(1000, "benign")),
            passed(),
            "1000 values"
        );
        assert_eq!(
            post_with(&default_on, "/", xml, &xml_values(1000, "attack")),
            refused(403, "denied", "denied", "true"),
            "the 1000th value is inspected"
        );
        // The 1001st is not: the parser stops, and the connector refuses the body as incomplete whatever the policy
        // says, in every engine mode but `Off`, instead of passing what it did not read. A flood of attributes in
        // one tag, the stop that keeps nothing of the tag, is refused the same way.
        let attributes = format!("<r{}/>", " b".repeat(1001));
        let detection_only = policy(r#", "SecRuleEngine DetectionOnly""#);
        let partial = policy(r#", "SecRequestBodyLimitAction ProcessPartial""#);
        for (config, body) in [
            (&default_on, xml_values(1001, "attack")),
            (&default_on, xml_values(1001, "benign")),
            (&default_on, attributes.clone().into_bytes()),
            (&detection_only, xml_values(1001, "attack")),
            (&detection_only, attributes.into_bytes()),
            (&partial, xml_values(1001, "attack")),
        ] {
            assert_eq!(
                post_with(config, "/", xml, &body),
                refused(413, "incomplete", "incomplete", "false"),
                "{} bytes",
                body.len()
            );
        }
        // A rule that denies on the body error or on the dropped argument answers first, as for any denial.
        let backstop = policy(r#", "SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,t:none,deny,status:400\"""#);
        assert_eq!(
            post_with(&backstop, "/", xml, &xml_values(1001, "attack")),
            refused(400, "denied", "denied", "true")
        );
        // A raised limit reads the larger document.
        assert_eq!(
            post_with(
                &policy(r#", "SecArgumentsLimit 2000""#),
                "/",
                xml,
                &xml_values(1001, "benign")
            ),
            passed()
        );
        // A document that is not well formed, which the parser drops whole, is the policy's to refuse: it sets
        // `REQBODY_ERROR`, and the connector refuses it only where a rule denies on that. Where none does the request
        // passes, and none of its values was inspected, which is reported as for a body released unread.
        let not_well_formed = b"<r><i>attack</i>&p;</r>";
        assert_eq!(
            post_with(&backstop, "/", xml, not_well_formed),
            refused(400, "denied", "denied", "true")
        );
        let unread = || (vec![], health("request_body_not_inspected", "completed", "false"));
        assert_eq!(post_with(&default_on, "/", xml, not_well_formed), unread());
        assert_eq!(post_with(&detection_only, "/", xml, not_well_formed), unread());
    }

    #[test]
    fn a_request_body_a_processor_failed_on_part_way_is_reported_as_not_inspected_unless_a_rule_denies_it() {
        let policy = |directives: &str| {
            format!(
                r#"{{"directives_map": {{"p": ["SecRuleEngine On",
                "SecRule REQUEST_HEADERS:Content-Type \"@contains xml\" \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=XML\"",
                "SecRule REQUEST_HEADERS:Content-Type \"@contains json\" \"id:2,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON\"",
                "SecRule ARGS_POST|XML:/* \"@contains attack\" \"id:900,phase:2,deny,status:403\""{directives}]}},
                "default_directives": "p", "enable_filter_state_logs": true}}"#
            )
        };
        let default_on = policy("");
        let detection_only = policy(r#", "SecRuleEngine DetectionOnly""#);
        let backstop = policy(r#", "SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,t:none,deny,status:400\"""#);
        let xml: &[(&str, &[u8])] = &[("content-type", b"application/xml")];
        let json: &[(&str, &[u8])] = &[("content-type", b"application/json")];
        let form_data: &[(&str, &[u8])] = &[("content-type", b"multipart/form-data; boundary=b")];
        let passed = || (vec![], health("complete", "completed", "true"));
        let unread = || (vec![], health("request_body_not_inspected", "completed", "false"));
        let refused =
            |status, reason: &str, outcome: &str, complete: &str| (vec![status], health(reason, outcome, complete));
        // A multipart body of two fields, the header of the second as given.
        let multipart_with = |first: &str, second: &str, header: &str| {
            format!(
                "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n{first}\r\n--b\r\n{header}\r\n\r\n{second}\r\n--b--\r\n"
            )
            .into_bytes()
        };
        let bodies = [
            // A syntax error part way: the processor keeps `a` and never reads the rest, which a backend that
            // reads single quotes would see.
            (json, &br#"{"a":"benign"}"#[..], &br#"{"a":"benign",'c':"attack"}"#[..]),
            (json, &br#"{"a":"benign"}"#[..], &br#"{"a":"#[..]),
            (
                xml,
                &b"<r><i>benign</i></r>"[..],
                &b"<r><i>benign</i><i>attack</i>&p;</r>"[..],
            ),
        ];
        for (headers, whole, cut) in bodies {
            let name = String::from_utf8_lossy(cut);
            assert_eq!(
                post_with(&default_on, "/", headers, whole),
                passed(),
                "{name}: well formed"
            );
            assert_eq!(post_with(&default_on, "/", headers, cut), unread(), "{name}");
            assert_eq!(
                post_with(&detection_only, "/", headers, cut),
                unread(),
                "{name}: DetectionOnly"
            );
            // A rule that denies on the error refuses first, and is reported as any denial is.
            assert_eq!(
                post_with(&backstop, "/", headers, cut),
                refused(400, "denied", "denied", "true"),
                "{name}: rule 200002"
            );
        }
        // A body `ProcessPartial` cut fails to parse because of the cut, not the client: it keeps the truncation as
        // its reason, as a cut URL-encoded, XML or multipart body does, and the status does not change.
        let cut = policy(r#", "SecRequestBodyLimit 12", "SecRequestBodyLimitAction ProcessPartial""#);
        assert_eq!(
            post_with(&cut, "/", json, br#"{"a":"benign","b":"benign"}"#),
            (vec![], health("body_partially_inspected", "completed", "false"))
        );
        // The XML processor drops a document it refuses whole, so a syntax error that a retained prefix holds leaves
        // none of its values inspected, and that is the reason, where the cut alone would be the partial one, as with
        // JSON above. A cut prefix that parses keeps the truncation as its reason, and a cut that is itself the
        // error (in a CDATA section) drops the document too. A rule that denies on the error answers first.
        let cut_xml = |directives: &str| {
            policy(&format!(
                r#", "SecRequestBodyLimit 24", "SecRequestBodyLimitAction ProcessPartial"{directives}"#
            ))
        };
        let partial = || (vec![], health("body_partially_inspected", "completed", "false"));
        let detection_only_cut = cut_xml(r#", "SecRuleEngine DetectionOnly""#);
        for (body, expected, name) in [
            (
                &b"<r><i>x</i>&p;</r><i>attack</i><i>attack</i>"[..],
                unread(),
                "a syntax error in the prefix",
            ),
            (
                b"<r><i>x</i><i>benign benign</i><i>attack</i>",
                partial(),
                "a prefix that parses",
            ),
            (
                b"<r><![CDATA[benign benign benign]]></r>",
                unread(),
                "a cut in a CDATA section",
            ),
        ] {
            let name = format!("{} ({name})", String::from_utf8_lossy(body));
            assert_eq!(post_with(&cut_xml(""), "/", xml, body), expected, "{name}");
            assert_eq!(
                post_with(&detection_only_cut, "/", xml, body),
                expected,
                "{name}: DetectionOnly"
            );
        }
        assert_eq!(
            post_with(
                &cut_xml(r#", "SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,t:none,deny,status:400\"""#),
                "/",
                xml,
                b"<r><i>x</i>&p;</r><i>attack</i><i>attack</i>"
            ),
            // A denial is the reason, as for any request, and the body the limit cut is still not complete.
            refused(400, "denied", "denied", "false"),
            "rule 200002"
        );
        // What the processor read before it failed is still inspected: a rule that denies on it answers, and the
        // denial is what is reported, complete, as for a parser stop that a rule denies.
        assert_eq!(
            post_with(&default_on, "/", json, br#"{"a":"attack",'c':"benign"}"#),
            refused(403, "denied", "denied", "true")
        );
        // A multipart body whose second part has a header that is no header: a parse error with the first part kept.
        // The host's ban on uploads refuses the body the parser stopped in, with 413, where the engine enforces; in
        // `DetectionOnly` nothing does, and it passes, the same.
        let field = r#"Content-Disposition: form-data; name="c""#;
        let well_formed = multipart_with("benign", "benign", field);
        let malformed = multipart_with("benign", "attack", "no colon here");
        assert_eq!(post_with(&default_on, "/", form_data, &well_formed), passed());
        assert_eq!(
            post_with(&default_on, "/", form_data, &malformed),
            refused(413, "denied", "denied", "true")
        );
        assert_eq!(post_with(&detection_only, "/", form_data, &malformed), unread());
        assert_eq!(
            post_with(&backstop, "/", form_data, &malformed),
            refused(400, "denied", "denied", "true")
        );
    }

    #[test]
    fn the_readmes_path_scoped_opt_outs_let_through_only_the_bodies_of_the_paths_they_name() {
        // The upgrade notes' `ctl:requestBodyAccess=Off` rules, exactly.
        let ctl_off = r#"{"directives_map": {"p": ["SecRuleEngine On",
            "SecRule REQUEST_FILENAME \"@streq /upload\" \"id:1,phase:1,pass,nolog,chain\"",
            "SecRule REQUEST_HEADERS:Content-Type \"@beginsWith multipart/form-data\" \"ctl:requestBodyAccess=Off\"",
            "SecRule REQUEST_FILENAME \"@streq /import\" \"id:2,phase:1,pass,nolog,chain\"",
            "SecRule &REQUEST_HEADERS:Content-Encoding \"@gt 0\" \"ctl:requestBodyAccess=Off\""]},
            "default_directives": "p", "enable_filter_state_logs": true}"#;
        let form: &[(&str, &[u8])] = &[("content-type", FORM.as_bytes())];
        let upload: &[(&str, &[u8])] = &[("content-type", b"multipart/form-data; boundary=b")];
        let gzip: &[(&str, &[u8])] = &[("content-type", FORM.as_bytes()), ("content-encoding", b"gzip")];
        let unread = (vec![], health("request_body_not_inspected", "completed", "false"));
        assert_eq!(post_with(ctl_off, "/upload", upload, &multipart(1, true)), unread);
        assert_eq!(post_with(ctl_off, "/import", gzip, b"a=1"), unread);
        assert_eq!(
            post_with(ctl_off, "/upload", form, &urlencoded(1000, 1)),
            (vec![413], health("incomplete", "incomplete", "false")),
            "a form the rules do not match is still read"
        );
        // The client chooses its headers, not the endpoint a path names: the same headers elsewhere switch nothing off.
        let upload_refused = (vec![413], health("denied", "denied", "true"));
        assert_eq!(
            post_with(ctl_off, "/import", upload, &multipart(1, true)),
            upload_refused
        );
        assert_eq!(post_with(ctl_off, "/", upload, &multipart(1, true)), upload_refused);
        assert_eq!(
            post_with(ctl_off, "/upload", gzip, b"a=1"),
            (vec![415], health("unsupported", "unsupported", "false"))
        );
    }

    #[test]
    fn a_policy_without_a_body_access_line_holds_a_streamed_body_until_it_ends() {
        // The default reads request bodies, so every frame waits for the last one: a streamed body (a gRPC stream, a
        // long chunked upload) reaches the backend only when it is complete, and is inspected then.
        let default_on = r#"{"directives_map": {"p": ["SecRuleEngine On"]}, "default_directives": "p",
            "enable_filter_state_logs": true}"#;
        let (actions, published) = post_in_frames(default_on, &[(3, false), (3, false), (3, true)], b"200");
        assert_eq!(
            actions,
            [Action::Pause, Action::Pause, Action::Pause, Action::Continue],
            "held to the end"
        );
        assert_eq!(published, health("complete", "completed", "true"), "inspected whole");
        // A body over the 16 MiB the host buffers is refused rather than passed on.
        let (actions, _) = post_in_frames(default_on, &[(MAX_REQUEST_BODY_BYTES + 1, false)], b"200");
        assert_eq!(actions, [Action::Pause, Action::Pause], "refused");
        assert_eq!(test_hostcalls::local_reply_statuses(), [413], "too large");
        // `SecRequestBodyAccess Off` passes every frame on as it comes.
        let (actions, _) = post_in_frames(BODY_OFF, &[(3, false), (3, false), (3, true)], b"200");
        assert_eq!(
            actions,
            [Action::Continue, Action::Continue, Action::Continue, Action::Continue],
            "streamed"
        );
    }

    /// A policy that inspects `text/plain` response bodies, with `rules`.
    fn response_policy(rules: &str) -> String {
        format!(
            r#"{{"directives_map": {{"p": ["SecRuleEngine On", "SecRequestBodyAccess On", "SecResponseBodyAccess On",
            "SecResponseBodyMimeType text/plain", "SecResponseBodyLimit 1048576",
            "SecRule ARGS \"@contains attack\" \"id:900,phase:2,deny,status:403\""{rules}]}},
            "default_directives": "p", "enable_filter_state_logs": true}}"#
        )
    }

    /// Response rules keyed on an `x-deny` response header: a phase-3 denial, a phase-4 denial decided in phase 3 as
    /// the harness's `p4` policy does, a phase-4 body denial, a phase-3 redirect, and phase-3 denials with the
    /// bodyless statuses 204 and 304.
    const RESPONSE_RULES: &str = r#",
        "SecRule RESPONSE_HEADERS:x-deny \"@streq 3\" \"id:1,phase:3,deny,status:502\"",
        "SecRule RESPONSE_HEADERS:x-deny \"@streq 4\" \"id:2,phase:3,pass,nolog,setvar:tx.deny=1\"",
        "SecRule TX:deny \"@eq 1\" \"id:3,phase:4,deny,status:502\"",
        "SecRule RESPONSE_BODY \"@contains secret\" \"id:4,phase:4,deny,status:502\"",
        "SecRule RESPONSE_HEADERS:x-deny \"@streq redirect\" \"id:5,phase:3,redirect:/blocked,status:302\"",
        "SecRule RESPONSE_HEADERS:x-deny \"@streq 204\" \"id:6,phase:3,deny,status:204\"",
        "SecRule RESPONSE_HEADERS:x-deny \"@streq 304\" \"id:7,phase:3,deny,status:304\"""#;

    /// A stream over [`RESPONSE_RULES`] whose bodyless `method` request is complete, beside streams that hold
    /// `others` bytes of the root, and that root.
    fn requested_beside(method: &str, others: usize) -> (CorazaHttp, Rc<Cell<usize>>) {
        let (mut stream, root) = stream_beside(&response_policy(RESPONSE_RULES), others);
        test_hostcalls::reset();
        let headers: [(&str, &[u8]); 4] = [
            (":authority", b"a.example"),
            (":scheme", b"http"),
            (":method", method.as_bytes()),
            (":path", b"/"),
        ];
        test_hostcalls::set_request_headers(&headers);
        script_connection_properties();
        assert_eq!(stream.on_http_request_headers(headers.len(), true), Action::Continue);
        (stream, root)
    }

    /// [`requested_beside`] on an idle root.
    fn requested(method: &str) -> CorazaHttp {
        requested_beside(method, 0).0
    }

    /// The one local reply the stream sent.
    fn only_reply(label: &str) -> test_hostcalls::LocalReply {
        let replies = test_hostcalls::local_replies();
        assert_eq!(replies.len(), 1, "{label}: {replies:?}");
        replies.into_iter().next().expect("one reply")
    }

    /// Asserts that `stream` answered `action` with exactly one local reply, of `status` and `body`, that can be
    /// cached by no one, and that no response callback after it lets anything through: what follows is upstream's.
    fn refused_once(stream: &mut CorazaHttp, action: Action, status: u32, body: &[u8], label: &str) {
        assert_eq!(action, Action::Pause, "{label}");
        let reply = only_reply(label);
        assert_eq!((reply.status, reply.body.as_slice()), (status, body), "{label}");
        assert!(
            reply
                .headers
                .contains(&("cache-control".to_owned(), b"no-store".to_vec())),
            "{label}: {reply:?}"
        );
        assert!(
            !reply.headers.iter().any(|(name, _)| name == "location"),
            "{label}: {reply:?}"
        );
        assert!(stream.lifecycle.finalized, "{label}");
        test_hostcalls::set_response_headers(&[(":status", b"200"), ("content-type", b"text/plain")]);
        test_hostcalls::set_response_body(b"secret");
        assert_eq!(stream.on_http_response_headers(2, false), Action::Pause, "{label}");
        assert_eq!(stream.on_http_response_body(6, false), Action::Pause, "{label}");
        assert_eq!(stream.on_http_response_body(6, true), Action::Pause, "{label}");
        assert_eq!(stream.on_http_response_trailers(0), Action::Pause, "{label}");
        assert_eq!(test_hostcalls::local_replies().len(), 1, "{label}: one reply only");
    }

    #[test]
    fn every_refusal_at_the_response_headers_is_one_local_reply() {
        type Case<'a> = (&'a str, &'a str, &'a [(&'a str, &'a [u8])], bool, u32, &'a [u8]);
        let cases: [Case<'_>; 10] = [
            (
                "phase-3 denial",
                "GET",
                &[(":status", b"200"), ("content-type", b"text/plain"), ("x-deny", b"3")],
                false,
                502,
                RESPONSE_BLOCK_BODY,
            ),
            (
                "phase-3 denial of a HEAD response",
                "HEAD",
                &[(":status", b"200"), ("content-type", b"text/plain"), ("x-deny", b"3")],
                true,
                502,
                b"",
            ),
            (
                "phase-3 denial of a 204",
                "GET",
                &[(":status", b"204"), ("x-deny", b"3")],
                true,
                502,
                RESPONSE_BLOCK_BODY,
            ),
            (
                "phase-3 denial of a 304",
                "GET",
                &[(":status", b"304"), ("x-deny", b"3")],
                true,
                502,
                RESPONSE_BLOCK_BODY,
            ),
            (
                "phase-3 denial of an empty 200",
                "GET",
                &[(":status", b"200"), ("content-length", b"0"), ("x-deny", b"3")],
                true,
                502,
                RESPONSE_BLOCK_BODY,
            ),
            (
                "compressed body of an inspected type",
                "GET",
                &[
                    (":status", b"200"),
                    ("content-type", b"text/plain"),
                    ("content-encoding", b"gzip"),
                ],
                false,
                502,
                RESPONSE_INCOMPLETE_BODY,
            ),
            (
                "phase-4 denial of a body that is not inspected",
                "GET",
                &[
                    (":status", b"200"),
                    ("content-type", b"application/octet-stream"),
                    ("x-deny", b"4"),
                ],
                false,
                502,
                RESPONSE_BLOCK_BODY,
            ),
            (
                "phase-4 denial of a HEAD response",
                "HEAD",
                &[(":status", b"200"), ("content-type", b"text/plain"), ("x-deny", b"4")],
                true,
                502,
                b"",
            ),
            ("upgrade", "GET", &[(":status", b"101")], false, 501, UNSUPPORTED_BODY),
            (
                "no status",
                "GET",
                &[("content-type", b"text/plain")],
                false,
                502,
                RESPONSE_INCOMPLETE_BODY,
            ),
        ];
        for (label, method, headers, end_of_stream, status, body) in cases {
            let mut stream = requested(method);
            test_hostcalls::set_response_headers(headers);
            let action = stream.on_http_response_headers(headers.len(), end_of_stream);
            refused_once(&mut stream, action, status, body, label);
        }
    }

    #[test]
    fn a_denial_with_status_204_or_304_is_answered_without_a_body() {
        for status in [204_u32, 304] {
            let mut stream = requested("GET");
            let deny = status.to_string();
            let headers: [(&str, &[u8]); 3] = [
                (":status", b"200"),
                ("content-type", b"text/plain"),
                ("x-deny", deny.as_bytes()),
            ];
            test_hostcalls::set_response_headers(&headers);
            let action = stream.on_http_response_headers(headers.len(), false);
            refused_once(&mut stream, action, status, b"", &deny);
        }
    }

    #[test]
    fn response_headers_that_cannot_be_read_are_refused_with_one_local_reply() {
        let mut stream = requested("GET");
        let action = stream.on_http_response_headers(MAX_HEADER_COUNT + 1, false);
        refused_once(&mut stream, action, 502, RESPONSE_INCOMPLETE_BODY, "too many headers");
        // The scripted host has no response header map to hand over.
        let mut stream = requested("GET");
        let action = stream.on_http_response_headers(1, false);
        refused_once(
            &mut stream,
            action,
            502,
            RESPONSE_INCOMPLETE_BODY,
            "header hostcall failed",
        );
    }

    #[test]
    fn every_refusal_in_the_response_body_or_trailers_is_one_local_reply() {
        let inspected: [(&str, &[u8]); 2] = [(":status", b"200"), ("content-type", b"text/plain")];
        let begin = |method: &str| {
            let mut stream = requested(method);
            test_hostcalls::set_response_headers(&inspected);
            assert_eq!(
                stream.on_http_response_headers(2, false),
                Action::Pause,
                "held for its body"
            );
            stream
        };

        let mut stream = begin("GET");
        test_hostcalls::set_response_body(b"a secret");
        let action = stream.on_http_response_body(8, true);
        refused_once(&mut stream, action, 502, RESPONSE_BLOCK_BODY, "phase-4 body denial");

        let mut stream = begin("GET");
        let action = stream.on_http_response_body(MAX_RESPONSE_BODY_BYTES + 1, false);
        refused_once(
            &mut stream,
            action,
            502,
            RESPONSE_INCOMPLETE_BODY,
            "over the connector's ceiling",
        );

        let mut stream = begin("GET");
        assert_eq!(stream.on_http_response_body(10, false), Action::Pause, "held");
        let action = stream.on_http_response_body(5, false);
        refused_once(&mut stream, action, 502, RESPONSE_INCOMPLETE_BODY, "a body that shrank");

        // The scripted host has no response body to hand over.
        let mut stream = begin("GET");
        let action = stream.on_http_response_body(8, true);
        refused_once(
            &mut stream,
            action,
            503,
            RESPONSE_INCOMPLETE_BODY,
            "body hostcall failed",
        );

        let (mut stream, root) = requested_beside("GET", 0);
        test_hostcalls::set_response_headers(&inspected);
        assert_eq!(
            stream.on_http_response_headers(2, false),
            Action::Pause,
            "held for its body"
        );
        root.set(MAX_ROOT_RETAINED_BODY_BYTES);
        let action = stream.on_http_response_body(8, false);
        refused_once(
            &mut stream,
            action,
            503,
            RESPONSE_INCOMPLETE_BODY,
            "a root without room",
        );

        let mut stream = requested("GET");
        let action = stream.on_http_response_body(8, true);
        refused_once(
            &mut stream,
            action,
            503,
            RESPONSE_INCOMPLETE_BODY,
            "a body before its headers",
        );

        let mut stream = requested("GET");
        let action = stream.on_http_response_trailers(0);
        refused_once(
            &mut stream,
            action,
            503,
            RESPONSE_INCOMPLETE_BODY,
            "trailers before headers",
        );

        let mut stream = begin("GET");
        let action = stream.on_http_response_trailers(MAX_HEADER_COUNT + 1);
        refused_once(&mut stream, action, 502, RESPONSE_INCOMPLETE_BODY, "too many trailers");

        // The scripted host has no response trailer map to hand over.
        let mut stream = begin("GET");
        let action = stream.on_http_response_trailers(1);
        refused_once(
            &mut stream,
            action,
            502,
            RESPONSE_INCOMPLETE_BODY,
            "trailer hostcall failed",
        );

        // A HEAD request gets no body in its reply.
        let mut stream = begin("HEAD");
        let action = stream.on_http_response_body(MAX_RESPONSE_BODY_BYTES + 1, false);
        refused_once(&mut stream, action, 502, b"", "HEAD over the connector's ceiling");
    }

    #[test]
    fn a_response_of_the_connectors_ceiling_is_inspected_and_released() {
        let mut stream = requested("GET");
        test_hostcalls::set_response_headers(&[(":status", b"200"), ("content-type", b"text/plain")]);
        assert_eq!(
            stream.on_http_response_headers(2, false),
            Action::Pause,
            "held for its body"
        );
        test_hostcalls::set_response_body(&vec![b'a'; MAX_RESPONSE_BODY_BYTES]);
        assert_eq!(
            stream.on_http_response_body(MAX_RESPONSE_BODY_BYTES / 2, false),
            Action::Pause
        );
        assert_eq!(
            stream.on_http_response_body(MAX_RESPONSE_BODY_BYTES, true),
            Action::Continue
        );
        assert!(test_hostcalls::local_replies().is_empty(), "nothing is refused");
        assert_eq!(stream.final_outcome, Some(TerminalOutcome::Completed));
    }

    #[test]
    fn a_compressed_response_of_a_type_the_policy_does_not_inspect_passes() {
        let mut stream = requested("GET");
        test_hostcalls::set_response_headers(&[
            (":status", b"200"),
            ("content-type", b"application/octet-stream"),
            ("content-encoding", b"gzip"),
        ]);
        assert_eq!(stream.on_http_response_headers(3, false), Action::Continue);
        assert_eq!(stream.on_http_response_body(8, true), Action::Continue);
        assert!(test_hostcalls::local_replies().is_empty(), "nothing is refused");
        assert_eq!(stream.final_outcome, Some(TerminalOutcome::Completed));
    }

    #[test]
    fn a_redirect_reply_carries_its_target_and_no_body() {
        let mut stream = requested("GET");
        test_hostcalls::set_response_headers(&[(":status", b"200"), ("x-deny", b"redirect")]);
        assert_eq!(stream.on_http_response_headers(2, false), Action::Pause);
        let reply = only_reply("redirect");
        assert_eq!((reply.status, reply.body.as_slice()), (302, &b""[..]));
        assert!(
            reply.headers.contains(&("location".to_owned(), b"/blocked".to_vec())),
            "{reply:?}"
        );
    }

    /// The local reply of a request-side redirect to `target`, built as an embedder could build it, and the stream's
    /// terminal outcome.
    fn request_redirect(target: &str) -> (test_hostcalls::LocalReply, Option<TerminalOutcome>) {
        let mut stream = requested("GET");
        let interruption = Interruption {
            rule_id: 1,
            action: "redirect".to_owned(),
            status: 302,
            data: target.to_owned(),
        };
        assert_eq!(
            stream.reject_interruption(&interruption, "request-headers", InterruptionPhase::RequestHeaders),
            Action::Pause
        );
        (only_reply(target), stream.final_outcome.take())
    }

    /// The legacy interruption properties the stream published: rule, phase, action and status.
    fn legacy_interruption() -> [Option<String>; 4] {
        ["rule_id", "phase", "action", "status"]
            .map(|name| test_hostcalls::published_property(&format!("io.coraza.waf.{name}")))
    }

    /// The legacy interruption properties of rule 1 redirecting with 302 in `phase`.
    fn redirect_properties(phase: &str) -> [Option<String>; 4] {
        ["1", phase, "redirect", "302"].map(|value| Some(value.to_owned()))
    }

    #[test]
    fn a_request_side_redirect_target_that_is_no_header_value_is_refused_with_403() {
        let (reply, outcome) = request_redirect("/login?next=a%0D%0ASet-Cookie: x=1");
        assert_eq!((reply.status, reply.body.as_slice()), (302, &b""[..]));
        assert!(
            reply
                .headers
                .contains(&("location".to_owned(), b"/login?next=a%0D%0ASet-Cookie: x=1".to_vec())),
            "{reply:?}"
        );
        assert_eq!(
            outcome,
            Some(TerminalOutcome::Denied {
                phase: "request-headers",
                status: 302
            })
        );
        assert_eq!(legacy_interruption(), redirect_properties("http_request_headers"));
        for target in [
            "/a\r\nSet-Cookie: x=1",
            "/a\nb",
            "/a\rb",
            "/a\0b",
            "/a\tb",
            "/a\u{7f}b",
            "",
        ] {
            let (reply, outcome) = request_redirect(target);
            assert_eq!(
                (reply.status, reply.body.as_slice()),
                (403, REQUEST_BLOCK_BODY),
                "{target:?}"
            );
            assert!(
                !reply.headers.iter().any(|(name, _)| name == "location"),
                "{target:?}: {reply:?}"
            );
            assert_eq!(
                outcome,
                Some(TerminalOutcome::Denied {
                    phase: "request-headers",
                    status: 403
                }),
                "{target:?}: the record names the status the client got"
            );
            assert_eq!(
                legacy_interruption(),
                redirect_properties("http_request_headers"),
                "{target:?}: the interruption properties keep the rule's redirect and status"
            );
        }
    }

    #[test]
    fn a_response_side_redirect_target_that_is_no_header_value_is_refused_with_403() {
        for (target, status, location, body) in [
            ("/login?next=a%0D%0A", 302, Some(&b"/login?next=a%0D%0A"[..]), &b""[..]),
            ("/a\r\nSet-Cookie: x=1", 403, None, RESPONSE_BLOCK_BODY),
            ("/a\nb", 403, None, RESPONSE_BLOCK_BODY),
            ("/a\0b", 403, None, RESPONSE_BLOCK_BODY),
            ("", 403, None, RESPONSE_BLOCK_BODY),
        ] {
            let mut stream = requested("GET");
            let interruption = Interruption {
                rule_id: 1,
                action: "redirect".to_owned(),
                status: 302,
                data: target.to_owned(),
            };
            assert_eq!(
                stream.refuse_response_interruption(
                    &interruption,
                    "response-headers",
                    InterruptionPhase::ResponseHeaders
                ),
                Action::Pause
            );
            let reply = only_reply(target);
            assert_eq!((reply.status, reply.body.as_slice()), (status, body), "{target:?}");
            let sent = reply
                .headers
                .iter()
                .find(|(name, _)| name == "location")
                .map(|(_, value)| value.as_slice());
            assert_eq!(sent, location, "{target:?}");
            assert_eq!(
                stream.final_outcome,
                Some(TerminalOutcome::Denied {
                    phase: "response-headers",
                    status: u16::try_from(status).expect("a status")
                }),
                "the record names the status the client got"
            );
            assert_eq!(
                legacy_interruption(),
                redirect_properties("http_response_headers"),
                "{target:?}: the interruption properties keep the rule's redirect and status"
            );
        }
    }

    #[test]
    fn the_request_body_stays_held_after_envoys_own_reply() {
        let config = response_policy("");
        let mut stream = stream(&config);
        let body = b"x=attack";
        begin_post(&mut stream, FORM, body);
        assert_eq!(
            stream.on_http_request_body(3, false),
            Action::Pause,
            "partial body is held"
        );

        // Envoy's own local reply (408 "stream timeout") runs through the encoder filters.
        test_hostcalls::set_response_headers(&[(":status", b"408"), ("content-length", b"14")]);
        assert_eq!(
            stream.on_http_response_headers(2, false),
            Action::Continue,
            "Envoy's reply reaches the client"
        );
        assert_eq!(
            stream.on_http_response_body(14, true),
            Action::Continue,
            "with its body"
        );
        assert!(
            test_hostcalls::local_replies().is_empty(),
            "the filter adds no reply of its own"
        );
        assert_eq!(
            published(),
            health("incomplete", "incomplete", "false"),
            "the request body was never inspected"
        );

        // The client now sends the rest of the body: the attack.
        assert_eq!(
            stream.on_http_request_body(body.len(), true),
            Action::Pause,
            "phase 2 never ran on `x=attack`, so the request must not be released to the router"
        );
    }

    #[test]
    fn an_informational_response_while_the_request_is_held_is_not_taken_for_envoys_reply() {
        let mut stream = stream(&response_policy(""));
        begin_post(&mut stream, FORM, b"x=attack");
        test_hostcalls::set_response_headers(&[(":status", b"100")]);
        assert_eq!(stream.on_http_response_headers(1, false), Action::Continue);
        assert!(!stream.lifecycle.finalized, "the request is still inspected");
        assert_eq!(stream.on_http_request_body(8, true), Action::Pause);
        assert_eq!(test_hostcalls::local_reply_statuses(), [403], "phase 2 ran and denied");
    }

    #[test]
    fn the_request_trailers_stay_held_after_envoys_own_reply() {
        let mut stream = stream(&response_policy(""));
        begin_post(&mut stream, FORM, b"x=attack");
        assert_eq!(stream.on_http_request_body(8, false), Action::Pause);
        test_hostcalls::set_response_headers(&[(":status", b"408")]);
        assert_eq!(stream.on_http_response_headers(1, false), Action::Continue);
        assert_eq!(stream.on_http_request_trailers(0), Action::Pause);
        assert_eq!(stream.on_http_request_headers(4, true), Action::Pause);
    }

    #[test]
    fn a_phase4_header_rule_is_refused_at_the_response_headers() {
        // Multiphase evaluation runs a phase-4 rule that reads only response headers in phase 3, so a response it
        // denies is answered at its headers even when an inspected body follows.
        let config = response_policy(
            r#", "SecRule RESPONSE_HEADERS:x-deny-response \"@streq yes\" \"id:104,phase:4,deny,status:502\"""#,
        );
        let mut stream = stream(&config);
        let count = script_request("a.example", "http");
        assert_eq!(stream.on_http_request_headers(count, true), Action::Continue);
        test_hostcalls::set_response_headers(&[
            (":status", b"200"),
            ("content-type", b"text/plain"),
            ("x-deny-response", b"yes"),
        ]);
        let action = stream.on_http_response_headers(3, false);
        refused_once(&mut stream, action, 502, RESPONSE_BLOCK_BODY, "phase-4 header rule");
    }

    #[test]
    fn a_response_denied_at_its_headers_charges_nothing_for_its_discarded_body() {
        let (mut stream, root) = requested_beside("GET", 0);
        test_hostcalls::set_response_headers(&[(":status", b"200"), ("content-type", b"text/plain"), ("x-deny", b"3")]);
        assert_eq!(stream.on_http_response_headers(3, false), Action::Pause);
        // 48 MiB of a body that is already condemned: far past the 1 MiB response ceiling.
        assert_eq!(stream.on_http_response_body(48 * MIB, false), Action::Pause);
        assert_eq!(
            root.get(),
            0,
            "a discarded response body holds nothing of the 64 MiB every stream of this root shares"
        );
    }
}
