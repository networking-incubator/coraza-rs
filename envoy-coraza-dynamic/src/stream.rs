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

//! Request-side policy selection, body gating and enforcement.

#![allow(
    clippy::missing_docs_in_private_items,
    reason = "Private adapter details are documented by their callbacks and enclosing types."
)]

use std::{
    cell::{Cell, RefCell},
    net::{IpAddr, SocketAddr},
    str,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use coraza::{
    transaction::{Interruption, Transaction},
    types::RuleEngineStatus,
};
use envoy_coraza_common::{
    authority::{
        authority_host, find_header, has_unsupported_content_encoding, has_upgrade, headers_within_limits,
        normalize_authority, request_authority, safe_location, valid_status, MAX_HEADERS_BYTES, MAX_HEADER_COUNT,
        MAX_HEADER_VALUE_BYTES,
    },
    observability::{interruption_fields, HealthState, InterruptionPhase, TerminalOutcome},
    policy::{Generation, Policy},
};
use envoy_proxy_dynamic_modules_rust_sdk::{
    abi::{
        envoy_dynamic_module_type_attribute_id as AttributeId,
        envoy_dynamic_module_type_on_http_filter_local_reply_status as LocalReplyStatus,
        envoy_dynamic_module_type_on_http_filter_request_body_status as RequestBodyStatus,
        envoy_dynamic_module_type_on_http_filter_request_headers_status as RequestHeadersStatus,
        envoy_dynamic_module_type_on_http_filter_request_trailers_status as RequestTrailersStatus,
        envoy_dynamic_module_type_on_http_filter_response_body_status as ResponseBodyStatus,
        envoy_dynamic_module_type_on_http_filter_response_headers_status as ResponseHeadersStatus,
        envoy_dynamic_module_type_on_http_filter_response_trailers_status as ResponseTrailersStatus,
    },
    CatchUnwind, EnvoyBuffer, EnvoyHttpFilter, HttpFilter,
};

/// Hard request body bound, independent of SecLang controls and Envoy limits.
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_REQUEST_BODY_BYTES_U64: u64 = 16 * 1024 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
/// Aggregate retained body bytes shared by the loaded native module.
const MAX_RETAINED_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Process-wide for this loaded module, across filter configs, generations and workers.
static RETAINED_BODY_BYTES: AtomicUsize = AtomicUsize::new(0);
const EMPTY_BODY: &[u8] = b"";
const REQUEST_DENY_BODY: &[u8] = b"Request denied\n";
const REQUEST_ERROR_BODY: &[u8] = b"Request inspection unavailable\n";
const RESPONSE_DENY_BODY: &[u8] = b"Upstream response blocked\n";
const RESPONSE_ERROR_BODY: &[u8] = b"Response inspection unavailable\n";
const UNSUPPORTED_BODY: &[u8] = b"Request feature is not supported\n";

type OwnedHeaders = Vec<(String, Vec<u8>)>;
type EnvoyHeaders<'a> = Vec<(EnvoyBuffer<'a>, EnvoyBuffer<'a>)>;

/// One immutable generation-backed filter configuration.
pub(crate) struct FilterConfig {
    generation: Arc<Generation>,
}

impl FilterConfig {
    pub(crate) fn new(generation: Arc<Generation>) -> Self {
        Self { generation }
    }

    fn new_stream(&self) -> RequestFilter {
        RequestFilter::new(Arc::clone(&self.generation))
    }
}

impl<EHF: EnvoyHttpFilter> envoy_proxy_dynamic_modules_rust_sdk::HttpFilterConfig<EHF> for FilterConfig {
    fn new_http_filter(&self, _envoy: &mut EHF) -> Box<dyn HttpFilter<EHF>> {
        Box::new(CatchUnwind::new(self.new_stream()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    New,
    Held,
    Complete,
    Bypassed,
    Terminal,
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "Independent request/response access, completion, truncation, and telemetry facts span callbacks."
)]
struct StreamState {
    generation: Arc<Generation>,
    stage: Stage,
    transaction: Option<Box<Transaction>>,
    method: String,
    protocol: String,
    body_access: bool,
    phase2_done: bool,
    body_bytes: usize,
    response_stage: ResponseStage,
    response_body_bytes: usize,
    response_body_access: bool,
    response_body_processable: bool,
    #[cfg(feature = "panic-probe")]
    response_panic_probe: bool,
    finalized: bool,
    request_body_truncated: bool,
    response_body_truncated: bool,
    telemetry_publish_failed: bool,
    outcome: Option<TerminalOutcome>,
    reservation: BodyReservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseStage {
    Waiting,
    Headers,
    Body,
    Complete,
}

impl StreamState {
    fn new(generation: Arc<Generation>) -> Self {
        Self {
            generation,
            stage: Stage::New,
            transaction: None,
            method: String::new(),
            protocol: String::new(),
            body_access: false,
            phase2_done: false,
            body_bytes: 0,
            response_stage: ResponseStage::Waiting,
            response_body_bytes: 0,
            response_body_access: false,
            response_body_processable: false,
            #[cfg(feature = "panic-probe")]
            response_panic_probe: false,
            finalized: false,
            request_body_truncated: false,
            response_body_truncated: false,
            telemetry_publish_failed: false,
            outcome: None,
            reservation: BodyReservation::default(),
        }
    }

    fn finish(&mut self, fallback: TerminalOutcome) -> Option<(TerminalOutcome, bool)> {
        if self.finalized {
            return None;
        }
        self.finalized = true;
        let outcome = match self.outcome.take() {
            Some(outcome) => outcome,
            None => fallback,
        };
        if let Some(transaction) = self.transaction.as_deref() {
            self.request_body_truncated |= transaction.request_body_stats().truncated;
            self.response_body_truncated |= transaction.response_body_stats().truncated;
        }
        let failed = self
            .transaction
            .as_deref_mut()
            .is_some_and(|transaction| transaction.finish().is_err());
        self.transaction.take();
        let _ = self.reservation.resize(0);
        Some((outcome, failed))
    }
}

impl Drop for StreamState {
    fn drop(&mut self) {
        let _ = self.finish(TerminalOutcome::UpstreamFailureOrCancellation);
    }
}

/// Per-stream body admission reservation; releasing it is independent of callbacks.
#[derive(Default)]
struct BodyReservation {
    bytes: usize,
}

struct RequestMetadata {
    method: String,
    uri: Vec<u8>,
    protocol: String,
}

impl BodyReservation {
    fn resize(&mut self, target: usize) -> bool {
        if target > self.bytes {
            let additional = target.saturating_sub(self.bytes);
            if !try_reserve(&RETAINED_BODY_BYTES, additional, MAX_RETAINED_BODY_BYTES) {
                return false;
            }
        } else {
            RETAINED_BODY_BYTES.fetch_sub(self.bytes.saturating_sub(target), Ordering::AcqRel);
        }
        self.bytes = target;
        true
    }
}

impl Drop for BodyReservation {
    fn drop(&mut self) {
        RETAINED_BODY_BYTES.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Atomically reserves bytes without a load-then-add race.
fn try_reserve(counter: &AtomicUsize, additional: usize, limit: usize) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let Some(next) = current.checked_add(additional) else {
            return false;
        };
        if next > limit {
            return false;
        }
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

enum Reply {
    Status {
        status: u16,
        body: &'static [u8],
        outcome: TerminalOutcome,
    },
    Interruption(Interruption),
}

impl Reply {
    fn incomplete(status: u16, phase: &'static str) -> Self {
        Self::Status {
            status,
            body: REQUEST_ERROR_BODY,
            outcome: TerminalOutcome::Incomplete { phase, status },
        }
    }

    fn invalid_lifecycle(status: u16, phase: &'static str) -> Self {
        Self::Status {
            status,
            body: REQUEST_ERROR_BODY,
            outcome: TerminalOutcome::InvalidLifecycle { phase, status },
        }
    }

    fn invalid_authority() -> Self {
        Self::Status {
            status: 400,
            body: REQUEST_ERROR_BODY,
            outcome: TerminalOutcome::InvalidAuthority { status: 400 },
        }
    }

    fn unsupported(status: u16, phase: &'static str) -> Self {
        Self::Status {
            status,
            body: UNSUPPORTED_BODY,
            outcome: TerminalOutcome::Unsupported(phase),
        }
    }

    fn body_too_large(phase: &'static str) -> Self {
        Self::Status {
            status: 413,
            body: REQUEST_ERROR_BODY,
            outcome: TerminalOutcome::BodyTooLarge { phase, status: 413 },
        }
    }

    fn retained_body_budget_exhausted(phase: &'static str) -> Self {
        Self::Status {
            status: 503,
            body: REQUEST_ERROR_BODY,
            outcome: TerminalOutcome::RetainedBodyBudgetExhausted { phase },
        }
    }
}

#[derive(Clone, Copy)]
enum HeadersAction {
    Continue,
    Hold,
}

enum BodyAction {
    Continue,
    Buffer,
}

struct ResponseReply {
    status: u16,
    body: &'static [u8],
    details: &'static str,
    head: bool,
    redirect: bool,
    location: Option<Vec<u8>>,
    interruption_fields: Option<Vec<(&'static str, String)>>,
}

impl ResponseReply {
    fn failure(status: u16, _phase: &'static str, head: bool) -> Self {
        Self {
            status,
            body: RESPONSE_ERROR_BODY,
            details: "coraza_dynamic_response_error",
            head,
            redirect: false,
            location: None,
            interruption_fields: None,
        }
    }

    fn interruption(state: &mut StreamState, interruption: &Interruption, phase: InterruptionPhase) -> Self {
        let status = valid_status(interruption.status);
        let redirect_action = interruption.action == "redirect";
        let location = (redirect_action && !interruption.data.is_empty() && safe_location(&interruption.data))
            .then(|| interruption.data.as_bytes().to_vec());
        let redirect = redirect_action && (interruption.data.is_empty() || location.is_some());
        let head = state.method.eq_ignore_ascii_case("HEAD");
        let fields = state
            .generation
            .enable_filter_state_logs()
            .then(|| {
                state
                    .transaction
                    .as_deref()
                    .map(|tx| interruption_fields(tx, interruption, phase))
            })
            .flatten();
        state.stage = Stage::Terminal;
        state.response_stage = ResponseStage::Complete;
        state.outcome = Some(TerminalOutcome::Denied {
            phase: match phase {
                InterruptionPhase::ResponseHeaders => "response-headers",
                InterruptionPhase::ResponseBody => "response-body",
                InterruptionPhase::RequestHeaders => "request-headers",
                InterruptionPhase::RequestBody => "request-body",
            },
            status,
        });
        Self {
            status,
            body: if redirect { EMPTY_BODY } else { RESPONSE_DENY_BODY },
            details: "coraza_dynamic_response_denied",
            head,
            redirect,
            location,
            interruption_fields: fields,
        }
    }

    fn body(&self) -> &'static [u8] {
        if self.head || matches!(self.status, 204 | 304) {
            EMPTY_BODY
        } else {
            self.body
        }
    }
}

/// One request stream, pinning the generation selected when Envoy creates it.
pub(crate) struct RequestFilter {
    generation: Arc<Generation>,
    state: RefCell<Option<StreamState>>,
    terminal: Cell<bool>,
}

impl RequestFilter {
    fn new(generation: Arc<Generation>) -> Self {
        Self {
            generation,
            state: RefCell::new(None),
            terminal: Cell::new(false),
        }
    }

    fn reject(&self, envoy: &mut impl EnvoyHttpFilter, status: u16, body: &'static [u8], outcome: TerminalOutcome) {
        self.terminal.set(true);
        if let Ok(mut state) = self.state.try_borrow_mut() {
            if let Some(state) = state.as_mut() {
                state.stage = Stage::Terminal;
                state.outcome = Some(outcome);
            }
        }
        let is_head = self.is_head();
        envoy.send_response(
            u32::from(status),
            &[
                ("content-type", b"text/plain; charset=utf-8"),
                ("cache-control", b"no-store"),
            ],
            Some(if is_head { EMPTY_BODY } else { body }),
            Some("coraza_dynamic_request_error"),
        );
    }

    fn is_head(&self) -> bool {
        self.state.try_borrow().is_ok_and(|state| {
            state
                .as_ref()
                .is_some_and(|state| state.method.eq_ignore_ascii_case("HEAD"))
        })
    }

    fn send_interruption(&self, envoy: &mut impl EnvoyHttpFilter, interruption: &Interruption) {
        let status = valid_status(interruption.status);
        let redirect_action = interruption.action == "redirect";
        let location = (redirect_action && !interruption.data.is_empty() && safe_location(&interruption.data))
            .then_some(interruption.data.as_bytes());
        let redirect = redirect_action && (interruption.data.is_empty() || location.is_some());
        let no_body_status = matches!(status, 204 | 304);
        let head = self.is_head();
        let fields = self.state.try_borrow().ok().and_then(|slot| {
            let state = slot.as_ref()?;
            if !state.generation.enable_filter_state_logs() {
                return None;
            }
            let phase = if state.phase2_done {
                InterruptionPhase::RequestBody
            } else {
                InterruptionPhase::RequestHeaders
            };
            state
                .transaction
                .as_deref()
                .map(|transaction| interruption_fields(transaction, interruption, phase))
        });
        let mut headers: Vec<(&str, &[u8])> = vec![
            ("content-type", b"text/plain; charset=utf-8"),
            ("cache-control", b"no-store"),
        ];
        if let Some(location) = location {
            headers.push(("location", location));
        }
        self.terminal.set(true);
        if let Ok(mut state) = self.state.try_borrow_mut() {
            if let Some(state) = state.as_mut() {
                state.stage = Stage::Terminal;
                state.outcome = Some(TerminalOutcome::Denied {
                    phase: "request",
                    status,
                });
            }
        }
        if let Some(fields) = fields {
            let failed = crate::observability::publish_interruption(envoy, &fields);
            if failed {
                if let Ok(mut state) = self.state.try_borrow_mut() {
                    if let Some(state) = state.as_mut() {
                        state.telemetry_publish_failed = true;
                        state.generation.diagnostics().record_failure();
                    }
                }
            }
        }
        envoy.send_response(
            u32::from(status),
            &headers,
            Some(if redirect || no_body_status || head {
                EMPTY_BODY
            } else {
                REQUEST_DENY_BODY
            }),
            Some("coraza_dynamic_request_denied"),
        );
    }

    fn fail_closed(&self, envoy: &mut impl EnvoyHttpFilter, reply: Reply) {
        match reply {
            Reply::Status { status, body, outcome } => self.reject(envoy, status, body, outcome),
            Reply::Interruption(interruption) => self.send_interruption(envoy, &interruption),
        }
    }

    fn on_headers(&self, envoy: &mut impl EnvoyHttpFilter, end_of_stream: bool) -> Result<HeadersAction, Reply> {
        let mut slot = self
            .state
            .try_borrow_mut()
            .map_err(|_error| Reply::invalid_lifecycle(503, "request-headers-state-borrow"))?;
        let state = slot.get_or_insert_with(|| StreamState::new(Arc::clone(&self.generation)));
        if state.stage != Stage::New {
            return Err(Reply::invalid_lifecycle(503, "request-headers-order"));
        }
        let headers =
            copy_headers(envoy.get_request_headers()).map_err(|_error| Reply::incomplete(431, "request-headers"))?;
        if !headers_within_limits(&headers, headers.len()) {
            return Err(Reply::incomplete(431, "request-headers"));
        }
        #[cfg(feature = "panic-probe")]
        check_panic_probe(state, &headers);
        let fallback_authority = attribute_bytes(envoy, AttributeId::RequestHost);
        let raw_authority = request_authority(&headers, fallback_authority.as_deref());
        let scheme = find_header(&headers, ":scheme")
            .map(<[u8]>::to_vec)
            .or_else(|| attribute_bytes(envoy, AttributeId::RequestScheme))
            .unwrap_or_default();
        let Some(authority) = normalize_authority(&raw_authority, &scheme) else {
            return Err(Reply::invalid_authority());
        };
        let generation = Arc::clone(&state.generation);
        let Some((_name, policy)) = generation.select_named(&authority) else {
            state.stage = Stage::Bypassed;
            state.outcome = Some(TerminalOutcome::UnmatchedAuthority);
            envoy_proxy_dynamic_modules_rust_sdk::envoy_log_warn!(
                "envoy-coraza-dynamic: no authority policy matched; request passed uninspected"
            );
            return Ok(HeadersAction::Continue);
        };
        let Some(metadata) = request_metadata(envoy, &headers, &raw_authority) else {
            return Err(Reply::incomplete(400, "request-metadata"));
        };
        state.method.clone_from(&metadata.method);
        state.protocol.clone_from(&metadata.protocol);
        let (transaction, interruption) = create_transaction(envoy, policy, &authority, &headers, &metadata);
        state.body_access = transaction.request_body_access();
        state.transaction = Some(transaction);
        if let Some(interruption) = interruption {
            return Err(Reply::Interruption(interruption));
        }
        if state
            .transaction
            .as_ref()
            .is_some_and(|tx| tx.rule_engine() == RuleEngineStatus::Off)
        {
            state.stage = Stage::Bypassed;
            state.outcome = Some(TerminalOutcome::EngineOff);
            return Ok(HeadersAction::Continue);
        }
        if metadata.method.eq_ignore_ascii_case("CONNECT") {
            return Err(Reply::unsupported(501, "request-connect"));
        }
        if has_upgrade(&headers) {
            return Err(Reply::unsupported(501, "request-upgrade"));
        }
        if state.body_access && has_unsupported_content_encoding(&headers) {
            return Err(Reply::unsupported(415, "request-content-encoding"));
        }
        if state.body_access && !end_of_stream {
            let current = envoy.get_buffer_limit();
            let limit = MAX_REQUEST_BODY_BYTES_U64;
            if current == 0 || current > limit {
                envoy.set_buffer_limit(limit);
            }
            state.stage = Stage::Held;
            return Ok(HeadersAction::Hold);
        }
        state.phase2_done = true;
        state.stage = Stage::Complete;
        let result = phase2(state, EMPTY_BODY);
        let retained = state.transaction.as_ref().map_or(0, |tx| tx.body_memory_bytes());
        if !state.reservation.resize(retained) {
            return Err(Reply::retained_body_budget_exhausted("request-body"));
        }
        result.map(|()| HeadersAction::Continue)
    }

    fn on_body(&self, envoy: &mut impl EnvoyHttpFilter, end_of_stream: bool) -> Result<BodyAction, Reply> {
        let mut slot = self
            .state
            .try_borrow_mut()
            .map_err(|_error| Reply::invalid_lifecycle(503, "request-body-state-borrow"))?;
        let Some(state) = slot.as_mut() else {
            return Ok(BodyAction::Continue);
        };
        if self.terminal.get() || matches!(state.stage, Stage::Bypassed | Stage::Complete | Stage::Terminal) {
            return Ok(BodyAction::Continue);
        }
        if state.stage != Stage::Held || state.phase2_done {
            return Err(Reply::invalid_lifecycle(503, "request-body-order"));
        }
        let received_buffered = envoy.received_buffered_request_body();
        let received_size = envoy.get_received_request_body_size();
        let buffered_size = envoy.get_buffered_request_body_size();
        let body_size = if received_buffered {
            received_size
        } else {
            buffered_size
                .checked_add(received_size)
                .ok_or_else(|| Reply::body_too_large("request-body-size-overflow"))?
        };
        if body_size < state.body_bytes {
            return Err(Reply::invalid_lifecycle(503, "request-body-size-regressed"));
        }
        if body_size > MAX_REQUEST_BODY_BYTES {
            return Err(Reply::body_too_large("request-body"));
        }
        if !state.reservation.resize(body_size) {
            return Err(Reply::retained_body_budget_exhausted("request-body"));
        }
        state.body_bytes = body_size;
        if !end_of_stream {
            return Ok(BodyAction::Buffer);
        }
        let prior_engine_bytes = state.transaction.as_ref().map_or(0, |tx| tx.body_memory_bytes());
        let scratch_and_engine = body_size
            .checked_mul(2)
            .and_then(|size| size.checked_add(prior_engine_bytes));
        let target = scratch_and_engine.and_then(|size| body_size.checked_add(size));
        if !target.is_some_and(|target| state.reservation.resize(target)) {
            return Err(Reply::retained_body_budget_exhausted("request-body-inspection"));
        }
        let body = copy_terminal_body(envoy, received_buffered, body_size, false)
            .ok_or_else(|| Reply::incomplete(503, "request-body-buffer"))?;
        drop(slot);
        let mut slot = self
            .state
            .try_borrow_mut()
            .map_err(|_error| Reply::invalid_lifecycle(503, "request-body-state-borrow"))?;
        let Some(state) = slot.as_mut() else {
            return Err(Reply::invalid_lifecycle(503, "request-body-state-missing"));
        };
        state.phase2_done = true;
        state.stage = Stage::Complete;
        let result = phase2(state, &body);
        drop(body);
        let retained = state.transaction.as_ref().map_or(0, |tx| tx.body_memory_bytes());
        let host_and_engine = state.body_bytes.checked_add(retained);
        if !host_and_engine.is_some_and(|target| state.reservation.resize(target)) {
            return Err(Reply::retained_body_budget_exhausted("request-body"));
        }
        result.map(|()| BodyAction::Continue)
    }

    fn on_trailers(&self, envoy: &mut impl EnvoyHttpFilter) -> Result<(), Reply> {
        let mut slot = self
            .state
            .try_borrow_mut()
            .map_err(|_error| Reply::invalid_lifecycle(503, "request-trailers-state-borrow"))?;
        let Some(state) = slot.as_mut() else {
            return Ok(());
        };
        if self.terminal.get() || matches!(state.stage, Stage::Bypassed | Stage::Terminal) {
            return Ok(());
        }
        let trailers =
            copy_headers(envoy.get_request_trailers()).map_err(|_error| Reply::incomplete(431, "request-trailers"))?;
        if !headers_within_limits(&trailers, trailers.len()) {
            return Err(Reply::incomplete(431, "request-trailers"));
        }
        if state.stage == Stage::Complete {
            return Ok(());
        }
        if state.stage != Stage::Held || state.phase2_done {
            return Err(Reply::invalid_lifecycle(503, "request-trailers-order"));
        }
        let body_size = envoy.get_buffered_request_body_size();
        if body_size < state.body_bytes {
            return Err(Reply::invalid_lifecycle(503, "request-body-size-regressed"));
        }
        if body_size > MAX_REQUEST_BODY_BYTES {
            return Err(Reply::body_too_large("request-body"));
        }
        if !state.reservation.resize(body_size) {
            return Err(Reply::retained_body_budget_exhausted("request-body"));
        }
        let prior_engine_bytes = state.transaction.as_ref().map_or(0, |tx| tx.body_memory_bytes());
        let target = body_size
            .checked_mul(2)
            .and_then(|size| size.checked_add(prior_engine_bytes))
            .and_then(|size| body_size.checked_add(size));
        if !target.is_some_and(|target| state.reservation.resize(target)) {
            return Err(Reply::retained_body_budget_exhausted("request-body-inspection"));
        }
        let body = copy_terminal_body(envoy, false, body_size, true)
            .ok_or_else(|| Reply::incomplete(503, "request-body-buffer"))?;
        state.phase2_done = true;
        state.stage = Stage::Complete;
        let result = phase2(state, &body);
        drop(body);
        let retained = state.transaction.as_ref().map_or(0, |tx| tx.body_memory_bytes());
        let host_and_engine = state.body_bytes.max(body_size).checked_add(retained);
        if !host_and_engine.is_some_and(|target| state.reservation.resize(target)) {
            return Err(Reply::retained_body_budget_exhausted("request-body"));
        }
        state.body_bytes = body_size;
        result
    }

    fn response_headers(
        &self,
        envoy: &mut impl EnvoyHttpFilter,
        end_of_stream: bool,
    ) -> Result<ResponseHeadersStatus, ResponseReply> {
        let mut slot = self
            .state
            .try_borrow_mut()
            .map_err(|_error| ResponseReply::failure(502, "response-state-borrow", false))?;
        let Some(state) = slot.as_mut() else {
            return Ok(ResponseHeadersStatus::Continue);
        };
        if self.terminal.get() || matches!(state.stage, Stage::Bypassed | Stage::Terminal) {
            return Ok(ResponseHeadersStatus::Continue);
        }
        if state.transaction.is_none() {
            return Ok(ResponseHeadersStatus::Continue);
        }
        if state.stage != Stage::Complete || state.response_stage != ResponseStage::Waiting {
            return Err(Self::response_failure(state, 502, "response-headers-order"));
        }
        let headers = copy_headers(envoy.get_response_headers())
            .map_err(|_error| Self::response_failure(state, 502, "response-headers"))?;
        if !headers_within_limits(&headers, headers.len()) {
            return Err(Self::response_failure(state, 502, "response-headers"));
        }
        let status = find_header(&headers, ":status")
            .and_then(|value| str::from_utf8(value).ok())
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| Self::response_failure(state, 502, "response-status"))?;
        if (100..200).contains(&status) && status != 101 {
            return Ok(ResponseHeadersStatus::Continue);
        }
        if status == 101 {
            let mut reply = Self::response_failure(state, 501, "response-upgrade");
            reply.body = UNSUPPORTED_BODY;
            reply.details = "coraza_dynamic_response_unsupported";
            state.outcome = Some(TerminalOutcome::Unsupported("response-upgrade"));
            return Err(reply);
        }
        for (name, value) in &headers {
            if let Some(transaction) = state.transaction.as_mut() {
                transaction.add_response_header(name, value);
            }
        }
        let interruption = state
            .transaction
            .as_mut()
            .and_then(|transaction| transaction.process_response_headers(status, &state.protocol));
        if let Some(interruption) = interruption {
            return Err(ResponseReply::interruption(
                state,
                &interruption,
                InterruptionPhase::ResponseHeaders,
            ));
        }
        let Some(transaction) = state.transaction.as_deref() else {
            return Err(Self::response_failure(state, 502, "response-transaction-missing"));
        };
        state.response_body_access = transaction.response_body_access();
        state.response_body_processable = transaction.is_response_body_processable();
        if state.response_body_access && state.response_body_processable && has_unsupported_content_encoding(&headers) {
            return Err(Self::response_failure(state, 502, "response-content-encoding"));
        }
        state.response_stage = ResponseStage::Headers;
        if end_of_stream || !(state.response_body_access && state.response_body_processable) {
            state.response_stage = ResponseStage::Complete;
            let interruption = state
                .transaction
                .as_mut()
                .and_then(|transaction| transaction.process_response_body(EMPTY_BODY));
            if let Some(interruption) = interruption {
                return Err(ResponseReply::interruption(
                    state,
                    &interruption,
                    InterruptionPhase::ResponseBody,
                ));
            }
            state.response_body_truncated = state
                .transaction
                .as_ref()
                .is_some_and(|transaction| transaction.response_body_stats().truncated);
            if state.response_body_truncated {
                state.outcome = Some(TerminalOutcome::BodyPartiallyInspected { phase: "response-body" });
            }
            return Ok(ResponseHeadersStatus::Continue);
        }
        let current_limit = envoy.get_buffer_limit();
        if current_limit == 0 || current_limit > MAX_RESPONSE_BODY_BYTES as u64 {
            envoy.set_buffer_limit(MAX_RESPONSE_BODY_BYTES as u64);
        }
        Ok(ResponseHeadersStatus::StopIteration)
    }

    fn response_body(&self, envoy: &mut impl EnvoyHttpFilter, end_of_stream: bool) -> ResponseBodyStatus {
        if self.terminal.get() {
            return ResponseBodyStatus::Continue;
        }
        let result = (|| {
            let mut slot = self
                .state
                .try_borrow_mut()
                .map_err(|_error| ResponseReply::failure(502, "response-state-borrow", false))?;
            let Some(state) = slot.as_mut() else {
                return Ok(None);
            };
            if matches!(state.stage, Stage::Bypassed | Stage::Terminal)
                || state.response_stage == ResponseStage::Complete
                || !state.response_body_access
                || !state.response_body_processable
            {
                return Ok(None);
            }
            if !matches!(state.response_stage, ResponseStage::Headers | ResponseStage::Body) {
                return Err(Self::response_failure(state, 502, "response-body-order"));
            }
            let received_buffered = envoy.received_buffered_response_body();
            let received_size = envoy.get_received_response_body_size();
            let buffered_size = envoy.get_buffered_response_body_size();
            let body_size = if received_buffered {
                buffered_size
            } else {
                buffered_size
                    .checked_add(received_size)
                    .ok_or_else(|| Self::response_failure(state, 502, "response-body-size-overflow"))?
            };
            if body_size < state.response_body_bytes {
                return Err(Self::response_failure(state, 502, "response-body-size-regressed"));
            }
            if body_size > MAX_RESPONSE_BODY_BYTES {
                return Err(Self::response_failure(state, 502, "response-body-limit"));
            }
            if !Self::reserve_response_body(state, body_size, end_of_stream) {
                return Err(Self::response_failure(state, 502, "response-body-admission"));
            }
            state.response_body_bytes = body_size;
            state.response_stage = if end_of_stream {
                ResponseStage::Complete
            } else {
                ResponseStage::Body
            };
            if !end_of_stream {
                return Ok(Some(ResponseBodyStatus::StopIterationAndBuffer));
            }
            let body = copy_terminal_response_body(envoy, received_buffered, body_size, false)
                .ok_or_else(|| Self::response_failure(state, 502, "response-body-buffer"))?;
            let interruption = state
                .transaction
                .as_mut()
                .and_then(|transaction| transaction.process_response_body(&body));
            drop(body);
            if let Some(interruption) = interruption {
                return Err(ResponseReply::interruption(
                    state,
                    &interruption,
                    InterruptionPhase::ResponseBody,
                ));
            }
            state.response_body_truncated = state
                .transaction
                .as_ref()
                .is_some_and(|transaction| transaction.response_body_stats().truncated);
            if state.response_body_truncated {
                state.outcome = Some(TerminalOutcome::BodyPartiallyInspected { phase: "response-body" });
            }
            let retained = state
                .transaction
                .as_ref()
                .map_or(0, |transaction| transaction.body_memory_bytes());
            let target = state.body_bytes.checked_add(retained);
            if !target.is_some_and(|target| state.reservation.resize(target)) {
                return Err(Self::response_failure(state, 502, "response-body-retention"));
            }
            Ok(Some(ResponseBodyStatus::Continue))
        })();
        match result {
            Ok(Some(status)) => status,
            Ok(None) => ResponseBodyStatus::Continue,
            Err(reply) => {
                self.send_response_reply(envoy, &reply);
                ResponseBodyStatus::StopIterationNoBuffer
            },
        }
    }

    fn response_trailers(&self, envoy: &mut impl EnvoyHttpFilter) -> ResponseTrailersStatus {
        if self.terminal.get() {
            return ResponseTrailersStatus::Continue;
        }
        let result = (|| {
            let mut slot = self
                .state
                .try_borrow_mut()
                .map_err(|_error| ResponseReply::failure(502, "response-state-borrow", false))?;
            let Some(state) = slot.as_mut() else {
                return Ok(());
            };
            if matches!(state.stage, Stage::Bypassed | Stage::Terminal)
                || state.response_stage == ResponseStage::Complete
                || !state.response_body_access
                || !state.response_body_processable
            {
                return Ok(());
            }
            if !matches!(state.response_stage, ResponseStage::Headers | ResponseStage::Body) {
                return Err(Self::response_failure(state, 502, "response-trailers-order"));
            }
            let trailers = copy_headers(envoy.get_response_trailers())
                .map_err(|_error| Self::response_failure(state, 502, "response-trailers"))?;
            if !headers_within_limits(&trailers, trailers.len()) {
                return Err(Self::response_failure(state, 502, "response-trailers"));
            }
            let body_size = envoy.get_buffered_response_body_size();
            if body_size < state.response_body_bytes {
                return Err(Self::response_failure(state, 502, "response-body-size-regressed"));
            }
            if body_size > MAX_RESPONSE_BODY_BYTES {
                return Err(Self::response_failure(state, 502, "response-body-limit"));
            }
            if !Self::reserve_response_body(state, body_size, true) {
                return Err(Self::response_failure(state, 502, "response-body-admission"));
            }
            let body = copy_terminal_response_body(envoy, false, body_size, true)
                .ok_or_else(|| Self::response_failure(state, 502, "response-body-buffer"))?;
            state.response_stage = ResponseStage::Complete;
            let interruption = state
                .transaction
                .as_mut()
                .and_then(|transaction| transaction.process_response_body(&body));
            drop(body);
            if let Some(interruption) = interruption {
                return Err(ResponseReply::interruption(
                    state,
                    &interruption,
                    InterruptionPhase::ResponseBody,
                ));
            }
            state.response_body_truncated = state
                .transaction
                .as_ref()
                .is_some_and(|transaction| transaction.response_body_stats().truncated);
            if state.response_body_truncated {
                state.outcome = Some(TerminalOutcome::BodyPartiallyInspected { phase: "response-body" });
            }
            let retained = state
                .transaction
                .as_ref()
                .map_or(0, |transaction| transaction.body_memory_bytes());
            let target = state.body_bytes.checked_add(retained);
            if !target.is_some_and(|target| state.reservation.resize(target)) {
                return Err(Self::response_failure(state, 502, "response-body-retention"));
            }
            state.response_body_bytes = body_size;
            Ok(())
        })();
        match result {
            Ok(()) => ResponseTrailersStatus::Continue,
            Err(reply) => {
                self.send_response_reply(envoy, &reply);
                ResponseTrailersStatus::StopIteration
            },
        }
    }

    fn response_failure(state: &mut StreamState, status: u16, phase: &'static str) -> ResponseReply {
        state.stage = Stage::Terminal;
        state.response_stage = ResponseStage::Complete;
        state.outcome = Some(match phase {
            "response-content-encoding" | "response-upgrade" => TerminalOutcome::Unsupported(phase),
            "response-body-limit" => TerminalOutcome::BodyTooLarge {
                phase: "response-body",
                status,
            },
            "response-body-admission" | "response-body-retention" => {
                TerminalOutcome::RetainedBodyBudgetExhausted { phase: "response-body" }
            },
            "response-headers-order"
            | "response-body-order"
            | "response-trailers-order"
            | "response-body-size-regressed" => TerminalOutcome::InvalidLifecycle { phase, status },
            _ => TerminalOutcome::Incomplete { phase, status },
        });
        ResponseReply::failure(status, phase, state.method.eq_ignore_ascii_case("HEAD"))
    }

    fn reserve_response_body(state: &mut StreamState, body_size: usize, copying: bool) -> bool {
        let retained = state
            .transaction
            .as_ref()
            .map_or(0, |transaction| transaction.body_memory_bytes());
        let held = if copying {
            body_size.checked_mul(2)
        } else {
            Some(body_size)
        };
        held.and_then(|held| state.body_bytes.checked_add(held))
            .and_then(|held| retained.checked_add(held))
            .is_some_and(|target| state.reservation.resize(target))
    }

    fn send_response_reply(&self, envoy: &mut impl EnvoyHttpFilter, reply: &ResponseReply) {
        self.terminal.set(true);
        if let Some(fields) = reply.interruption_fields.as_deref() {
            let failed = crate::observability::publish_interruption(envoy, fields);
            if let Ok(mut slot) = self.state.try_borrow_mut() {
                if let Some(state) = slot.as_mut() {
                    state.telemetry_publish_failed |= failed;
                    if failed {
                        state.generation.diagnostics().record_failure();
                    }
                }
            }
        }
        let mut headers: Vec<(&str, &[u8])> = vec![("cache-control", b"no-store")];
        if !reply.head
            && !matches!(reply.status, 204 | 304)
            && (reply.body != EMPTY_BODY || (reply.redirect && reply.location.is_none()))
        {
            headers.push(("content-type", b"text/plain; charset=utf-8"));
        }
        if let Some(location) = reply.location.as_deref() {
            headers.push(("location", location));
        }
        envoy.send_response(
            u32::from(reply.status),
            &headers,
            Some(reply.body()),
            Some(reply.details),
        );
    }
}

impl<EHF: EnvoyHttpFilter> HttpFilter<EHF> for RequestFilter {
    fn on_request_headers(&self, envoy: &mut EHF, end_of_stream: bool) -> RequestHeadersStatus {
        if self.terminal.get() {
            return RequestHeadersStatus::StopIteration;
        }
        let result = self.on_headers(envoy, end_of_stream);
        match result {
            Ok(HeadersAction::Continue) => RequestHeadersStatus::Continue,
            Ok(HeadersAction::Hold) => RequestHeadersStatus::StopIteration,
            Err(reply) => {
                self.fail_closed(envoy, reply);
                RequestHeadersStatus::StopIteration
            },
        }
    }

    fn on_request_body(&self, envoy: &mut EHF, end_of_stream: bool) -> RequestBodyStatus {
        if self.terminal.get() {
            return RequestBodyStatus::StopIterationNoBuffer;
        }
        match self.on_body(envoy, end_of_stream) {
            Ok(BodyAction::Buffer) => RequestBodyStatus::StopIterationAndBuffer,
            Ok(BodyAction::Continue) => RequestBodyStatus::Continue,
            Err(reply) => {
                self.fail_closed(envoy, reply);
                RequestBodyStatus::StopIterationNoBuffer
            },
        }
    }

    fn on_request_trailers(&self, envoy: &mut EHF) -> RequestTrailersStatus {
        if self.terminal.get() {
            return RequestTrailersStatus::StopIteration;
        }
        match self.on_trailers(envoy) {
            Ok(()) => RequestTrailersStatus::Continue,
            Err(reply) => {
                self.fail_closed(envoy, reply);
                RequestTrailersStatus::StopIteration
            },
        }
    }

    fn on_local_reply(
        &self,
        _envoy: &mut EHF,
        response_code: u32,
        _details: EnvoyBuffer<'_>,
        _reset_imminent: bool,
    ) -> LocalReplyStatus {
        self.terminal.set(true);
        if let Ok(mut slot) = self.state.try_borrow_mut() {
            if let Some(state) = slot.as_mut() {
                if state.stage == Stage::Held {
                    state.stage = Stage::Terminal;
                    let status = u16::try_from(response_code)
                        .ok()
                        .filter(|status| (100..=599).contains(status))
                        .unwrap_or(503);
                    state.outcome.get_or_insert(TerminalOutcome::Incomplete {
                        phase: "local-reply",
                        status,
                    });
                }
            }
        }
        LocalReplyStatus::Continue
    }

    fn on_response_headers(&self, envoy: &mut EHF, end_of_stream: bool) -> ResponseHeadersStatus {
        match self.response_headers(envoy, end_of_stream) {
            Ok(status) => status,
            Err(reply) => {
                self.send_response_reply(envoy, &reply);
                ResponseHeadersStatus::StopIteration
            },
        }
    }

    fn on_response_body(&self, envoy: &mut EHF, end_of_stream: bool) -> ResponseBodyStatus {
        #[cfg(feature = "panic-probe")]
        if !self.terminal.get() {
            let probe = self
                .state
                .try_borrow()
                .ok()
                .and_then(|slot| slot.as_ref().map(|state| state.response_panic_probe))
                .is_some_and(|probe| probe);
            // This assertion deliberately panics to test the SDK callback unwind boundary.
            assert!(!probe, "feature-gated response panic probe");
        }
        self.response_body(envoy, end_of_stream)
    }

    fn on_response_trailers(&self, envoy: &mut EHF) -> ResponseTrailersStatus {
        self.response_trailers(envoy)
    }

    fn on_stream_complete(&self, envoy: &mut EHF) {
        let publication = {
            let Ok(mut slot) = self.state.try_borrow_mut() else {
                return;
            };
            let Some(state) = slot.as_mut() else {
                return;
            };
            let fallback = terminal_outcome(state);
            let Some((outcome, finalization_failed)) = state.finish(fallback) else {
                return;
            };
            let inspection_complete = matches!(outcome, TerminalOutcome::Completed | TerminalOutcome::Denied { .. })
                && !state.request_body_truncated
                && !state.response_body_truncated;
            let generation = Arc::clone(&state.generation);
            let health = HealthState {
                inspection_complete,
                inspection_reason: if finalization_failed {
                    "finalization_error"
                } else {
                    outcome.inspection_reason()
                },
                generation: generation.generation_id(),
                request_body_truncated: state.request_body_truncated,
                response_body_truncated: state.response_body_truncated,
                terminal_outcome: if finalization_failed {
                    "error"
                } else {
                    outcome.terminal_name()
                },
                telemetry_publish_failed: state.telemetry_publish_failed,
            };
            Some((generation, health))
        };
        if let Some((generation, health)) = publication {
            if crate::observability::publish_health(envoy, generation.enable_filter_state_logs(), health)
                && !health.telemetry_publish_failed
            {
                generation.diagnostics().record_failure();
            }
        }
    }
}

fn terminal_outcome(state: &StreamState) -> TerminalOutcome {
    if let Some(outcome) = state.outcome.as_ref() {
        return outcome.clone();
    }
    match (state.stage, state.response_stage) {
        (Stage::Held, _) => TerminalOutcome::Incomplete {
            phase: "request-body-aborted",
            status: 503,
        },
        (Stage::Complete, ResponseStage::Headers | ResponseStage::Body) => TerminalOutcome::Incomplete {
            phase: "response-body-aborted",
            status: 502,
        },
        (Stage::Complete, ResponseStage::Complete) => TerminalOutcome::Completed,
        (Stage::Complete, ResponseStage::Waiting) => TerminalOutcome::UpstreamFailureOrCancellation,
        (Stage::Bypassed, _) => TerminalOutcome::UnmatchedAuthority,
        _ => TerminalOutcome::InvalidLifecycle {
            phase: "stream-complete",
            status: 503,
        },
    }
}

fn phase2(state: &mut StreamState, body: &[u8]) -> Result<(), Reply> {
    let Some(transaction) = state.transaction.as_mut() else {
        return Err(Reply::invalid_lifecycle(503, "request-transaction-missing"));
    };
    if let Some(interruption) = transaction.process_request_body(body) {
        return Err(Reply::Interruption(interruption));
    }
    if transaction.arguments_limit_reached() {
        return Err(Reply::incomplete(413, "request-arguments-limit"));
    }
    Ok(())
}

#[cfg(feature = "panic-probe")]
fn check_panic_probe(state: &mut StreamState, headers: &OwnedHeaders) {
    if let Some(probe) = find_header(headers, "x-coraza-probe") {
        state.response_panic_probe = probe == b"panic-response";
        if probe == b"worker" {
            envoy_proxy_dynamic_modules_rust_sdk::envoy_log_info!(
                "envoy-coraza-dynamic: worker probe thread_id={:?}",
                std::thread::current().id()
            );
        }
        assert_ne!(probe, b"panic", "feature-gated request panic probe");
    }
}

fn create_transaction<EHF: EnvoyHttpFilter>(
    envoy: &EHF,
    policy: &Policy,
    authority: &str,
    headers: &OwnedHeaders,
    metadata: &RequestMetadata,
) -> (Box<Transaction>, Option<Interruption>) {
    let mut transaction = Box::new(policy.waf.new_transaction());
    apply_connection_metadata(envoy, &mut transaction, authority);
    transaction.process_uri(&metadata.uri, &metadata.method, &metadata.protocol);
    for (name, value) in headers {
        transaction.add_request_header(name, value);
    }
    if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) && !authority.is_empty() {
        transaction.add_request_header("host", authority.as_bytes());
    }
    let interruption = transaction.process_request_headers();
    (transaction, interruption)
}

fn copy_headers(headers: EnvoyHeaders<'_>) -> Result<OwnedHeaders, ()> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(());
    }
    let mut total = 0_usize;
    let mut copied = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let name = str::from_utf8(name.as_slice()).map_err(|_error| ())?.to_owned();
        let value = value.as_slice();
        if value.len() > MAX_HEADER_VALUE_BYTES {
            return Err(());
        }
        total = total
            .checked_add(name.len())
            .and_then(|size| size.checked_add(value.len()))
            .ok_or(())?;
        if total > MAX_HEADERS_BYTES {
            return Err(());
        }
        copied.push((name, value.to_vec()));
    }
    Ok(copied)
}

fn attribute_bytes<EHF: EnvoyHttpFilter>(envoy: &EHF, id: AttributeId) -> Option<Vec<u8>> {
    envoy.get_attribute_string(id).map(|value| value.as_slice().to_vec())
}

fn request_metadata<EHF: EnvoyHttpFilter>(
    envoy: &EHF,
    headers: &[(String, Vec<u8>)],
    connect_target: &[u8],
) -> Option<RequestMetadata> {
    let method = find_header(headers, ":method")
        .map(<[u8]>::to_vec)
        .or_else(|| attribute_bytes(envoy, AttributeId::RequestMethod))?;
    let method = str::from_utf8(&method).ok()?.to_owned();
    let uri = find_header(headers, ":path")
        .map(<[u8]>::to_vec)
        .or_else(|| attribute_bytes(envoy, AttributeId::RequestPath))
        .or_else(|| method.eq_ignore_ascii_case("CONNECT").then(|| connect_target.to_vec()))?;
    let protocol = attribute_bytes(envoy, AttributeId::RequestProtocol)?;
    let protocol = str::from_utf8(&protocol).ok()?.to_owned();
    if method.is_empty() || protocol.is_empty() {
        return None;
    }
    Some(RequestMetadata { method, uri, protocol })
}

fn apply_connection_metadata<EHF: EnvoyHttpFilter>(envoy: &EHF, tx: &mut Transaction, authority: &str) {
    let remote = envoy
        .get_downstream_direct_remote_address()
        .map(|value| value.as_slice().to_vec())
        .or_else(|| attribute_bytes(envoy, AttributeId::SourceAddress))
        .unwrap_or_default();
    let (remote_addr, remote_port) = endpoint(&remote);
    tx.set_remote_addr(remote_addr);
    let remote_port = match envoy
        .get_attribute_int(AttributeId::SourcePort)
        .and_then(|port| u16::try_from(port).ok())
    {
        Some(port) => port,
        None => remote_port,
    };
    tx.set_remote_port(remote_port);
    let server = attribute_bytes(envoy, AttributeId::DestinationAddress).unwrap_or_default();
    let (server_addr, server_port) = endpoint(&server);
    tx.set_server_addr(server_addr);
    let server_port = match envoy
        .get_attribute_int(AttributeId::DestinationPort)
        .and_then(|port| u16::try_from(port).ok())
    {
        Some(port) => port,
        None => server_port,
    };
    tx.set_server_port(server_port);
    tx.set_server_name(authority_host(authority).as_bytes());
}

fn endpoint(bytes: &[u8]) -> (Vec<u8>, u16) {
    let Ok(address) = str::from_utf8(bytes) else {
        return (Vec::new(), 0);
    };
    let parsed = address
        .parse::<SocketAddr>()
        .map(|socket| (socket.ip().to_string(), socket.port()))
        .or_else(|_| address.parse::<IpAddr>().map(|ip| (ip.to_string(), 0)));
    match parsed {
        Ok((ip, port)) => (ip.into_bytes(), port),
        Err(_) => (bytes.to_vec(), 0),
    }
}

fn copy_terminal_body<EHF: EnvoyHttpFilter>(
    envoy: &mut EHF,
    received_buffered: bool,
    expected: usize,
    trailers: bool,
) -> Option<Vec<u8>> {
    let mut body = Vec::with_capacity(expected);
    if trailers || !received_buffered {
        if let Some(buffered) = envoy.get_buffered_request_body() {
            for fragment in &buffered {
                body.extend_from_slice(fragment.as_slice());
            }
            drop(buffered);
        }
    }
    if !trailers {
        if let Some(received) = envoy.get_received_request_body() {
            for fragment in &received {
                body.extend_from_slice(fragment.as_slice());
            }
            drop(received);
        }
    }
    (body.len() == expected).then_some(body)
}

fn copy_terminal_response_body<EHF: EnvoyHttpFilter>(
    envoy: &mut EHF,
    received_buffered: bool,
    expected: usize,
    trailers: bool,
) -> Option<Vec<u8>> {
    let mut body = Vec::with_capacity(expected);
    if let Some(buffered) = envoy.get_buffered_response_body() {
        for fragment in &buffered {
            body.extend_from_slice(fragment.as_slice());
        }
        drop(buffered);
    }
    if !trailers && !received_buffered {
        if let Some(received) = envoy.get_received_response_body() {
            for fragment in &received {
                body.extend_from_slice(fragment.as_slice());
            }
            drop(received);
        }
    }
    (body.len() == expected).then_some(body)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Native stream tests use fixed valid fixtures.")]
#[expect(
    unsafe_code,
    reason = "The SDK mock body view aliases fixed test-only static storage."
)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use coraza::transaction::Interruption;
    use envoy_coraza_common::{
        config::Config,
        observability::{Diagnostics, TerminalOutcome},
        policy::Generation,
    };
    use envoy_proxy_dynamic_modules_rust_sdk::{
        abi::{
            envoy_dynamic_module_type_attribute_id as AttributeId,
            envoy_dynamic_module_type_on_http_filter_local_reply_status as LocalReplyStatus,
            envoy_dynamic_module_type_on_http_filter_request_body_status as RequestBodyStatus,
            envoy_dynamic_module_type_on_http_filter_request_headers_status as RequestHeadersStatus,
            envoy_dynamic_module_type_on_http_filter_request_trailers_status as RequestTrailersStatus,
            envoy_dynamic_module_type_on_http_filter_response_body_status as ResponseBodyStatus,
            envoy_dynamic_module_type_on_http_filter_response_headers_status as ResponseHeadersStatus,
            envoy_dynamic_module_type_on_http_filter_response_trailers_status as ResponseTrailersStatus,
        },
        EnvoyBuffer, EnvoyMutBuffer, HttpFilter as _, MockEnvoyHttpFilter,
    };

    use super::{
        terminal_outcome, try_reserve, BodyReservation, FilterConfig, InterruptionPhase, ResponseReply, ResponseStage,
        Stage, StreamState, MAX_HEADER_VALUE_BYTES, RETAINED_BODY_BYTES,
    };

    fn generation(directive: &str) -> Arc<Generation> {
        Arc::new(
            Generation::compile(
                Config::parse(
                    format!(r#"{{"directives_map":{{"p":[{directive:?}]}},"default_directives":"p"}}"#).as_bytes(),
                )
                .unwrap(),
                Arc::new(Diagnostics::default()),
                |_| {},
                |_, _| {},
            )
            .unwrap(),
        )
    }

    fn logged_generation(directive: &str) -> Arc<Generation> {
        Arc::new(
            Generation::compile(
                Config::parse(
                    format!(
                        r#"{{"directives_map":{{"p":[{directive:?}]}} ,"default_directives":"p","enable_filter_state_logs":true}}"#,
                    )
                    .as_bytes(),
                )
                .unwrap(),
                Arc::new(Diagnostics::default()),
                |_| {},
                |_, _| {},
            )
            .unwrap(),
        )
    }

    fn prepare_header_mock(envoy: &mut MockEnvoyHttpFilter, method: &'static [u8], uri: &'static [u8]) {
        prepare_header_mock_with_remote(envoy, method, uri, None);
    }

    fn prepare_header_mock_with_remote(
        envoy: &mut MockEnvoyHttpFilter,
        method: &'static [u8],
        uri: &'static [u8],
        remote: Option<&'static [u8]>,
    ) {
        envoy.expect_get_request_headers().returning(move || {
            let mut headers = vec![
                (EnvoyBuffer::new(b":method"), EnvoyBuffer::new(method)),
                (EnvoyBuffer::new(b":path"), EnvoyBuffer::new(uri)),
                (EnvoyBuffer::new(b":scheme"), EnvoyBuffer::new(b"http")),
                (EnvoyBuffer::new(b":authority"), EnvoyBuffer::new(b"example.test")),
            ];
            if method == b"POST" {
                headers.push((EnvoyBuffer::new(b"content-type"), EnvoyBuffer::new(b"text/plain")));
            }
            headers
        });
        envoy.expect_get_attribute_string().returning(|id| match id {
            AttributeId::RequestProtocol => Some(EnvoyBuffer::new(b"HTTP/2")),
            _ => None,
        });
        envoy.expect_get_attribute_int().returning(|_| None);
        envoy
            .expect_get_downstream_direct_remote_address()
            .returning_st(move || remote.map(EnvoyBuffer::new));
    }

    fn prepare_connect_mock(envoy: &mut MockEnvoyHttpFilter) {
        envoy.expect_get_request_headers().returning(|| {
            vec![
                (EnvoyBuffer::new(b":method"), EnvoyBuffer::new(b"CONNECT")),
                (EnvoyBuffer::new(b":scheme"), EnvoyBuffer::new(b"https")),
                (EnvoyBuffer::new(b":authority"), EnvoyBuffer::new(b"example.test:443")),
            ]
        });
        envoy.expect_get_attribute_string().returning(|id| match id {
            AttributeId::RequestProtocol => Some(EnvoyBuffer::new(b"HTTP/2")),
            _ => None,
        });
        envoy.expect_get_attribute_int().returning(|_| None);
        envoy
            .expect_get_downstream_direct_remote_address()
            .returning_st(|| None);
    }

    fn prepare_body_hold(envoy: &mut MockEnvoyHttpFilter) {
        envoy.expect_get_buffer_limit().return_const(16_u64 * 1024 * 1024);
    }

    fn expect_inline_reply(envoy: &mut MockEnvoyHttpFilter, filter: Rc<super::RequestFilter>, expected: u32) {
        envoy
            .expect_send_response()
            .returning_st(move |status, _headers, body, _details| {
                assert_eq!(status, expected);
                assert!(
                    filter.terminal.get(),
                    "terminal state is published before the re-entrant host call"
                );
                if expected == 409 {
                    assert_eq!(body, Some(b"Request denied\n".as_slice()));
                }
                let mut callback_envoy = MockEnvoyHttpFilter::default();
                assert_eq!(
                    filter.on_local_reply(&mut callback_envoy, status, EnvoyBuffer::new(b""), false),
                    LocalReplyStatus::Continue,
                    "the inline local reply is ignored by request inspection"
                );
            });
    }

    fn body_rule_generation() -> Arc<Generation> {
        Arc::new(Generation::compile(
            Config::parse(
                br#"{"directives_map":{"p":["SecRuleEngine On","SecRequestBodyAccess On","SecRequestBodyLimit 100","SecAction \"id:1,phase:1,ctl:requestBodyProcessor=RAW,pass\"","SecRule REQUEST_BODY \"@contains attack\" \"id:2,phase:2,deny,status:409\""]},"default_directives":"p"}"#,
            )
            .unwrap(),
            Arc::new(Diagnostics::default()),
            |_| {},
            |_, _| {},
        )
        .unwrap())
    }

    fn response_body_rule_generation() -> Arc<Generation> {
        Arc::new(Generation::compile(
            Config::parse(
                br#"{"directives_map":{"p":["SecRuleEngine On","SecResponseBodyAccess On","SecResponseBodyLimit 100","SecResponseBodyMimeType text/plain","SecRule RESPONSE_BODY \"@contains secret\" \"id:44,phase:4,deny,status:451\""]},"default_directives":"p"}"#,
            )
            .unwrap(),
            Arc::new(Diagnostics::default()),
            |_| {},
            |_, _| {},
        )
        .unwrap())
    }

    fn response_header_rule_generation(directives: &str) -> Arc<Generation> {
        Arc::new(Generation::compile(
            Config::parse(
                format!(
                    r#"{{"directives_map":{{"p":["SecRuleEngine On",{directives:?},"SecRule RESPONSE_HEADERS:x-deny-response \"@streq yes\" \"id:45,phase:4,deny,status:452\""]}},"default_directives":"p"}}"#,
                )
                .as_bytes(),
            )
            .unwrap(),
            Arc::new(Diagnostics::default()),
            |_| {},
            |_, _| {},
        )
        .unwrap())
    }

    fn attack_view() -> EnvoyMutBuffer<'static> {
        static mut BODY: [u8; 6] = *b"attack";
        // SAFETY: the mock only reads the immutable static bytes during the synchronous hook.
        unsafe { EnvoyMutBuffer::new(&raw mut BODY) }
    }

    fn secret_view() -> EnvoyMutBuffer<'static> {
        static mut BODY: [u8; 13] = *b"public-secret";
        // SAFETY: the mock only reads the immutable static bytes during the synchronous hook.
        unsafe { EnvoyMutBuffer::new(&raw mut BODY) }
    }

    fn oversized_header_value() -> EnvoyBuffer<'static> {
        static VALUE: [u8; MAX_HEADER_VALUE_BYTES + 1] = [b'a'; MAX_HEADER_VALUE_BYTES + 1];
        EnvoyBuffer::new(&VALUE)
    }

    #[test]
    fn admission_reservation_is_checked_and_released_on_drop() {
        let counter = AtomicUsize::new(0);
        assert!(try_reserve(&counter, 7, 10));
        assert!(!try_reserve(&counter, 4, 10));
        assert_eq!(counter.load(Ordering::Acquire), 7);
        assert!(!try_reserve(&counter, usize::MAX, 10));

        let initial = RETAINED_BODY_BYTES.load(Ordering::Acquire);
        let mut reservation = BodyReservation::default();
        assert!(reservation.resize(17));
        assert_eq!(RETAINED_BODY_BYTES.load(Ordering::Acquire), initial + 17);
        drop(reservation);
        assert_eq!(RETAINED_BODY_BYTES.load(Ordering::Acquire), initial);
    }

    #[test]
    fn concurrent_reservations_never_cross_the_shared_limit() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let counter = Arc::clone(&counter);
            workers.push(std::thread::spawn(move || {
                (0..100).filter(|_| try_reserve(&counter, 1, 10)).count()
            }));
        }
        let reserved: usize = workers.into_iter().map(|worker| worker.join().unwrap()).sum();
        assert_eq!(reserved, 10);
        assert_eq!(counter.load(Ordering::Acquire), 10);
    }

    #[test]
    fn streams_pin_the_generation_across_config_replacement() {
        let old_config = FilterConfig::new(generation("SecRuleEngine On"));
        let old_stream = old_config.new_stream();
        let old_ptr = Arc::as_ptr(&old_stream.generation);
        drop(old_config);

        let new_config = FilterConfig::new(generation("SecRuleEngine DetectionOnly"));
        let new_stream = new_config.new_stream();
        let new_ptr = Arc::as_ptr(&new_stream.generation);

        assert_ne!(old_ptr, new_ptr);
        assert_eq!(Arc::as_ptr(&old_stream.generation), old_ptr);
        assert!(old_stream.state.borrow().is_none());
    }

    #[test]
    fn phase_one_interruption_uses_rule_status_and_stops_before_forwarding() {
        let filter = Rc::new(
            FilterConfig::new(generation(
                r#"SecRule REQUEST_URI "@contains attack" "id:1,phase:1,deny,status:418""#,
            ))
            .new_stream(),
        );
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_header_mock(&mut envoy, b"GET", b"/attack");
        expect_inline_reply(&mut envoy, Rc::clone(&filter), 418);

        assert_eq!(
            filter.on_request_headers(&mut envoy, true),
            RequestHeadersStatus::StopIteration,
        );
    }

    #[test]
    fn oversized_request_header_returns_431_before_inspection() {
        let filter = FilterConfig::new(generation("SecRuleEngine On")).new_stream();
        let mut envoy = MockEnvoyHttpFilter::default();
        envoy.expect_get_request_headers().returning(|| {
            vec![
                (EnvoyBuffer::new(b":method"), EnvoyBuffer::new(b"GET")),
                (EnvoyBuffer::new(b":path"), EnvoyBuffer::new(b"/")),
                (EnvoyBuffer::new(b":scheme"), EnvoyBuffer::new(b"http")),
                (EnvoyBuffer::new(b":authority"), EnvoyBuffer::new(b"example.test")),
                (EnvoyBuffer::new(b"x-large"), oversized_header_value()),
            ]
        });
        envoy
            .expect_send_response()
            .returning_st(|status, _, _, _| assert_eq!(status, 431));

        assert_eq!(
            filter.on_request_headers(&mut envoy, true),
            RequestHeadersStatus::StopIteration
        );
    }

    #[test]
    fn invalid_authority_rejection_retains_its_terminal_outcome() {
        let filter = FilterConfig::new(generation("SecRuleEngine On")).new_stream();
        let mut envoy = MockEnvoyHttpFilter::default();
        envoy.expect_get_request_headers().returning(|| {
            vec![
                (EnvoyBuffer::new(b":method"), EnvoyBuffer::new(b"GET")),
                (EnvoyBuffer::new(b":path"), EnvoyBuffer::new(b"/")),
                (EnvoyBuffer::new(b":scheme"), EnvoyBuffer::new(b"http")),
                (EnvoyBuffer::new(b":authority"), EnvoyBuffer::new(b"bad host")),
            ]
        });
        envoy.expect_get_attribute_string().returning(|id| match id {
            AttributeId::RequestProtocol => Some(EnvoyBuffer::new(b"HTTP/2")),
            _ => None,
        });
        envoy.expect_get_attribute_int().returning(|_| None);
        envoy
            .expect_get_downstream_direct_remote_address()
            .returning_st(|| None);
        envoy
            .expect_send_response()
            .returning_st(|status, _, _, _| assert_eq!(status, 400));

        assert_eq!(
            filter.on_request_headers(&mut envoy, true),
            RequestHeadersStatus::StopIteration
        );
        assert!(filter.state.borrow().as_ref().is_some_and(|state| {
            matches!(
                state.outcome.as_ref(),
                Some(TerminalOutcome::InvalidAuthority { status: 400 })
            )
        }));
    }

    #[test]
    fn local_reply_terminates_a_held_request_before_response_callbacks() {
        let filter = FilterConfig::new(generation(
            "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 16777216",
        ))
        .new_stream();
        let mut request_envoy = MockEnvoyHttpFilter::default();
        prepare_header_mock(&mut request_envoy, b"POST", b"/local-reply");
        prepare_body_hold(&mut request_envoy);
        assert_eq!(
            filter.on_request_headers(&mut request_envoy, false),
            RequestHeadersStatus::StopIteration
        );
        #[cfg(feature = "panic-probe")]
        if let Some(state) = filter.state.borrow_mut().as_mut() {
            state.response_panic_probe = true;
        }

        let mut reply_envoy = MockEnvoyHttpFilter::default();
        assert_eq!(
            filter.on_local_reply(&mut reply_envoy, 503, EnvoyBuffer::new(b"upstream failure"), false),
            LocalReplyStatus::Continue
        );
        assert!(filter.terminal.get());
        assert!(filter.state.borrow().as_ref().is_some_and(|state| {
            state.stage == Stage::Terminal
                && matches!(
                    state.outcome.as_ref(),
                    Some(TerminalOutcome::Incomplete {
                        phase: "local-reply",
                        status: 503
                    })
                )
        }));
        assert_eq!(
            filter.on_response_headers(&mut reply_envoy, false),
            ResponseHeadersStatus::Continue
        );
        assert_eq!(
            filter.on_response_body(&mut reply_envoy, true),
            ResponseBodyStatus::Continue
        );
    }

    #[test]
    fn oversized_request_trailer_returns_431_before_body_inspection() {
        let filter = Rc::new(
            FilterConfig::new(generation(
                "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 16777216",
            ))
            .new_stream(),
        );
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_header_mock(&mut envoy, b"POST", b"/upload");
        prepare_body_hold(&mut envoy);
        assert_eq!(
            filter.on_request_headers(&mut envoy, false),
            RequestHeadersStatus::StopIteration
        );
        envoy
            .expect_get_request_trailers()
            .returning(|| vec![(EnvoyBuffer::new(b"x-large"), oversized_header_value())]);
        envoy
            .expect_send_response()
            .returning_st(|status, _, _, _| assert_eq!(status, 431));

        assert_eq!(
            filter.on_request_trailers(&mut envoy),
            RequestTrailersStatus::StopIteration
        );
    }

    #[test]
    fn oversized_response_trailer_returns_generic_502() {
        let filter = Rc::new(FilterConfig::new(response_body_rule_generation()).new_stream());
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_header_mock(&mut envoy, b"GET", b"/response-trailer-budget");
        assert_eq!(
            filter.on_request_headers(&mut envoy, true),
            RequestHeadersStatus::Continue
        );
        envoy.expect_get_response_headers().returning(|| {
            vec![
                (EnvoyBuffer::new(b":status"), EnvoyBuffer::new(b"200")),
                (EnvoyBuffer::new(b"content-type"), EnvoyBuffer::new(b"text/plain")),
            ]
        });
        envoy.expect_get_buffer_limit().return_const(16_u64 * 1024 * 1024);
        envoy.expect_set_buffer_limit().return_const(());
        assert_eq!(
            filter.on_response_headers(&mut envoy, false),
            ResponseHeadersStatus::StopIteration
        );

        envoy.expect_received_buffered_response_body().return_const(false);
        envoy.expect_get_received_response_body_size().return_const(0_usize);
        envoy.expect_get_buffered_response_body_size().return_const(0_usize);
        assert_eq!(
            filter.on_response_body(&mut envoy, false),
            ResponseBodyStatus::StopIterationAndBuffer
        );
        envoy
            .expect_get_response_trailers()
            .returning(|| vec![(EnvoyBuffer::new(b"x-large"), oversized_header_value())]);
        envoy.expect_send_response().returning_st(|status, _, body, _| {
            assert_eq!(status, 502);
            assert_eq!(body, Some(super::RESPONSE_ERROR_BODY));
        });

        assert_eq!(
            filter.on_response_trailers(&mut envoy),
            ResponseTrailersStatus::StopIteration
        );
    }

    #[test]
    fn request_body_reject_limit_returns_413_for_n_plus_one() {
        let policy = generation(
            "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 5\nSecRequestBodyLimitAction Reject\nSecAction \"id:90,phase:1,ctl:requestBodyProcessor=RAW,pass\"",
        );
        let filter = Rc::new(FilterConfig::new(policy).new_stream());
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_header_mock(&mut envoy, b"POST", b"/upload");
        prepare_body_hold(&mut envoy);
        assert_eq!(
            filter.on_request_headers(&mut envoy, false),
            RequestHeadersStatus::StopIteration
        );

        envoy.expect_received_buffered_request_body().return_const(false);
        envoy.expect_get_received_request_body_size().return_const(6_usize);
        envoy.expect_get_buffered_request_body_size().return_const(0_usize);
        let body = attack_view();
        envoy.expect_get_buffered_request_body().returning_st(|| None);
        envoy
            .expect_get_received_request_body()
            .returning_st(move || Some(vec![body]));
        expect_inline_reply(&mut envoy, Rc::clone(&filter), 413);

        assert_eq!(
            filter.on_request_body(&mut envoy, true),
            RequestBodyStatus::StopIterationNoBuffer
        );
        assert!(filter.state.borrow().as_ref().is_some_and(|state| {
            matches!(
                state.outcome.as_ref(),
                Some(TerminalOutcome::Denied {
                    phase: "request",
                    status: 413
                })
            )
        }));
    }

    #[test]
    fn host_request_body_ceiling_uses_body_too_large_outcome() {
        let filter = FilterConfig::new(generation(
            "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 16777216",
        ))
        .new_stream();
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_header_mock(&mut envoy, b"POST", b"/upload");
        prepare_body_hold(&mut envoy);
        assert_eq!(
            filter.on_request_headers(&mut envoy, false),
            RequestHeadersStatus::StopIteration
        );

        envoy.expect_received_buffered_request_body().return_const(false);
        envoy
            .expect_get_received_request_body_size()
            .return_const(super::MAX_REQUEST_BODY_BYTES + 1);
        envoy.expect_get_buffered_request_body_size().return_const(0_usize);
        envoy
            .expect_send_response()
            .returning_st(|status, _, _, _| assert_eq!(status, 413));

        assert_eq!(
            filter.on_request_body(&mut envoy, true),
            RequestBodyStatus::StopIterationNoBuffer
        );
        assert!(filter.state.borrow().as_ref().is_some_and(|state| {
            matches!(
                state.outcome.as_ref(),
                Some(TerminalOutcome::BodyTooLarge {
                    phase: "request-body",
                    status: 413
                })
            )
        }));
    }

    #[test]
    fn request_process_partial_inspects_only_the_configured_prefix() {
        let policy = generation(
            "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 5\nSecRequestBodyLimitAction ProcessPartial\nSecAction \"id:91,phase:1,ctl:requestBodyProcessor=RAW,pass\"\nSecRule REQUEST_BODY \"@contains attack\" \"id:92,phase:2,deny,status:409\"",
        );
        let filter = Rc::new(FilterConfig::new(policy).new_stream());
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_header_mock(&mut envoy, b"POST", b"/upload");
        prepare_body_hold(&mut envoy);
        assert_eq!(
            filter.on_request_headers(&mut envoy, false),
            RequestHeadersStatus::StopIteration
        );

        envoy.expect_received_buffered_request_body().return_const(false);
        envoy.expect_get_received_request_body_size().return_const(6_usize);
        envoy.expect_get_buffered_request_body_size().return_const(0_usize);
        let body = attack_view();
        envoy.expect_get_buffered_request_body().returning_st(|| None);
        envoy
            .expect_get_received_request_body()
            .returning_st(move || Some(vec![body]));

        assert_eq!(filter.on_request_body(&mut envoy, true), RequestBodyStatus::Continue);
        assert!(filter
            .state
            .borrow()
            .as_ref()
            .and_then(|state| state.transaction.as_deref())
            .is_some_and(|tx| tx.request_body_stats().truncated));
    }

    #[test]
    fn request_interruption_state_is_published_before_local_reply_even_if_it_fails() {
        let filter = Rc::new(
            FilterConfig::new(logged_generation(
                r#"SecRule REQUEST_URI "@contains attack" "id:99,phase:1,deny,status:418""#,
            ))
            .new_stream(),
        );
        let fields_written = Rc::new(Cell::new(0_usize));
        let callback_fields = Rc::clone(&fields_written);
        let callback_filter = Rc::clone(&filter);
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_header_mock(&mut envoy, b"GET", b"/attack");
        envoy.expect_set_filter_state_bytes().returning_st(move |key, _| {
            assert!(key.starts_with(b"wasm.io.coraza.waf."));
            callback_fields.set(callback_fields.get() + 1);
            false
        });
        envoy
            .expect_send_response()
            .returning_st(move |status, _headers, _body, _details| {
                assert_eq!(status, 418);
                assert!(
                    fields_written.get() > 0,
                    "interruption state is published before the local reply"
                );
                assert!(callback_filter.terminal.get());
            });

        assert_eq!(
            filter.on_request_headers(&mut envoy, true),
            RequestHeadersStatus::StopIteration
        );
        assert!(filter
            .state
            .borrow()
            .as_ref()
            .is_some_and(|state| state.telemetry_publish_failed));
    }

    #[test]
    fn redirect_action_keeps_an_empty_body_even_without_a_location() {
        let filter = FilterConfig::new(generation("SecRuleEngine On")).new_stream();
        let mut envoy = MockEnvoyHttpFilter::default();
        envoy
            .expect_send_response()
            .returning_st(|status, headers, body, _details| {
                assert_eq!(status, 302);
                assert_eq!(body, Some(super::EMPTY_BODY));
                assert!(!headers.iter().any(|(name, _)| *name == "location"));
            });
        let interruption = Interruption {
            rule_id: 1,
            action: "redirect".to_owned(),
            status: 302,
            data: String::new(),
        };

        filter.send_interruption(&mut envoy, &interruption);
        assert!(filter.terminal.get());
    }

    #[test]
    fn request_redirect_with_control_bytes_falls_back_to_a_denial() {
        let filter = FilterConfig::new(generation("SecRuleEngine On")).new_stream();
        let mut envoy = MockEnvoyHttpFilter::default();
        envoy
            .expect_send_response()
            .returning_st(|status, headers, body, _details| {
                assert_eq!(status, 307);
                assert_eq!(body, Some(super::REQUEST_DENY_BODY));
                assert!(!headers.iter().any(|(name, _)| *name == "location"));
                assert!(!headers
                    .iter()
                    .any(|(_, value)| value.contains(&b'\r') || value.contains(&b'\n')));
            });
        let interruption = Interruption {
            rule_id: 2,
            action: "redirect".to_owned(),
            status: 307,
            data: "https://example.test/blocked\r\nSet-Cookie: injected=1".to_owned(),
        };

        filter.send_interruption(&mut envoy, &interruption);
        assert!(filter.terminal.get());
    }

    #[test]
    fn response_redirect_with_control_bytes_falls_back_to_a_denial() {
        let policy_generation = generation("SecRuleEngine On");
        let mut state = StreamState::new(Arc::clone(&policy_generation));
        state.method = "GET".to_owned();
        let interruption = Interruption {
            rule_id: 3,
            action: "redirect".to_owned(),
            status: 307,
            data: "https://example.test/blocked\r\nSet-Cookie: injected=1".to_owned(),
        };
        let reply = ResponseReply::interruption(&mut state, &interruption, InterruptionPhase::ResponseBody);
        assert!(!reply.redirect);
        assert!(reply.location.is_none());
        assert_eq!(reply.body, super::RESPONSE_DENY_BODY);

        let filter = FilterConfig::new(generation("SecRuleEngine On")).new_stream();
        let mut envoy = MockEnvoyHttpFilter::default();
        envoy
            .expect_send_response()
            .returning_st(|status, headers, body, _details| {
                assert_eq!(status, 307);
                assert_eq!(body, Some(super::RESPONSE_DENY_BODY));
                assert!(!headers.iter().any(|(name, _)| *name == "location"));
                assert!(!headers
                    .iter()
                    .any(|(_, value)| value.contains(&b'\r') || value.contains(&b'\n')));
            });
        filter.send_response_reply(&mut envoy, &reply);
    }

    #[test]
    fn phase_one_uses_the_host_protocol_and_direct_client_address() {
        for (directive, remote, status) in [
            (
                "SecRule REQUEST_PROTOCOL \"@streq HTTP/2\" \"id:20,phase:1,deny,status:419\"",
                None,
                419,
            ),
            (
                "SecRule REMOTE_ADDR \"@streq 203.0.113.7\" \"id:21,phase:1,deny,status:420\"",
                Some(b"203.0.113.7:41234".as_slice()),
                420,
            ),
        ] {
            let filter = Rc::new(FilterConfig::new(generation(directive)).new_stream());
            let mut envoy = MockEnvoyHttpFilter::default();
            prepare_header_mock_with_remote(&mut envoy, b"GET", b"/metadata", remote);
            expect_inline_reply(&mut envoy, Rc::clone(&filter), status);

            assert_eq!(
                filter.on_request_headers(&mut envoy, true),
                RequestHeadersStatus::StopIteration,
                "the SDK supplies the actual protocol and direct client address to Coraza"
            );
        }
    }

    #[test]
    fn connect_without_a_path_fails_with_the_unsupported_status() {
        let filter = Rc::new(FilterConfig::new(generation("SecRuleEngine On")).new_stream());
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_connect_mock(&mut envoy);
        expect_inline_reply(&mut envoy, Rc::clone(&filter), 501);

        assert_eq!(
            filter.on_request_headers(&mut envoy, true),
            RequestHeadersStatus::StopIteration
        );
        assert!(filter.state.borrow().as_ref().is_some_and(|state| {
            matches!(
                state.outcome.as_ref(),
                Some(TerminalOutcome::Unsupported("request-connect"))
            )
        }));
    }

    #[test]
    fn unsupported_request_encoding_keeps_its_terminal_outcome() {
        let filter = FilterConfig::new(generation(
            "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 16777216",
        ))
        .new_stream();
        let mut envoy = MockEnvoyHttpFilter::default();
        envoy.expect_get_request_headers().returning(|| {
            vec![
                (EnvoyBuffer::new(b":method"), EnvoyBuffer::new(b"POST")),
                (EnvoyBuffer::new(b":path"), EnvoyBuffer::new(b"/upload")),
                (EnvoyBuffer::new(b":scheme"), EnvoyBuffer::new(b"http")),
                (EnvoyBuffer::new(b":authority"), EnvoyBuffer::new(b"example.test")),
                (EnvoyBuffer::new(b"content-type"), EnvoyBuffer::new(b"text/plain")),
                (EnvoyBuffer::new(b"content-encoding"), EnvoyBuffer::new(b"gzip")),
            ]
        });
        envoy.expect_get_attribute_string().returning(|id| match id {
            AttributeId::RequestProtocol => Some(EnvoyBuffer::new(b"HTTP/2")),
            _ => None,
        });
        envoy.expect_get_attribute_int().returning(|_| None);
        envoy
            .expect_get_downstream_direct_remote_address()
            .returning_st(|| None);
        envoy
            .expect_send_response()
            .returning_st(|status, _, _, _| assert_eq!(status, 415));

        assert_eq!(
            filter.on_request_headers(&mut envoy, false),
            RequestHeadersStatus::StopIteration
        );
        assert!(filter.state.borrow().as_ref().is_some_and(|state| {
            matches!(
                state.outcome.as_ref(),
                Some(TerminalOutcome::Unsupported("request-content-encoding"))
            )
        }));
    }

    #[test]
    fn request_body_callback_order_failure_keeps_its_terminal_outcome() {
        let filter = FilterConfig::new(generation("SecRuleEngine On")).new_stream();
        let mut state = StreamState::new(Arc::clone(&filter.generation));
        state.stage = Stage::Held;
        state.phase2_done = true;
        *filter.state.borrow_mut() = Some(state);
        let mut envoy = MockEnvoyHttpFilter::default();
        envoy
            .expect_send_response()
            .returning_st(|status, _, _, _| assert_eq!(status, 503));

        assert_eq!(
            filter.on_request_body(&mut envoy, true),
            RequestBodyStatus::StopIterationNoBuffer
        );
        assert!(filter.state.borrow().as_ref().is_some_and(|state| {
            matches!(
                state.outcome.as_ref(),
                Some(TerminalOutcome::InvalidLifecycle {
                    phase: "request-body-order",
                    status: 503
                })
            )
        }));
    }

    #[test]
    fn body_phase_denial_reads_the_complete_buffer_once_and_is_terminal_before_reply() {
        let filter = Rc::new(FilterConfig::new(body_rule_generation()).new_stream());
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_header_mock(&mut envoy, b"POST", b"/upload");
        prepare_body_hold(&mut envoy);
        assert_eq!(
            filter.on_request_headers(&mut envoy, false),
            RequestHeadersStatus::StopIteration,
        );

        envoy.expect_received_buffered_request_body().return_const(false);
        envoy.expect_get_received_request_body_size().return_const(0_usize);
        envoy.expect_get_buffered_request_body_size().return_const(6_usize);
        let attack = attack_view();
        envoy
            .expect_get_buffered_request_body()
            .returning_st(move || Some(vec![attack]));
        envoy.expect_get_received_request_body().returning_st(|| None);
        expect_inline_reply(&mut envoy, Rc::clone(&filter), 409);

        assert_eq!(
            filter.on_request_body(&mut envoy, true),
            RequestBodyStatus::StopIterationNoBuffer,
        );
        assert_eq!(
            filter.state.borrow().as_ref().map(|state| state.stage),
            Some(Stage::Terminal)
        );
    }

    #[test]
    fn trailer_termination_assembles_the_buffered_prefix_and_checks_trailers() {
        let filter = Rc::new(FilterConfig::new(body_rule_generation()).new_stream());
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_header_mock(&mut envoy, b"POST", b"/upload");
        prepare_body_hold(&mut envoy);
        assert_eq!(
            filter.on_request_headers(&mut envoy, false),
            RequestHeadersStatus::StopIteration,
        );

        envoy.expect_received_buffered_request_body().return_const(false);
        envoy.expect_get_received_request_body_size().return_const(6_usize);
        envoy
            .expect_get_buffered_request_body_size()
            .return_const(0_usize)
            .times(1);
        assert_eq!(
            filter.on_request_body(&mut envoy, false),
            RequestBodyStatus::StopIterationAndBuffer,
        );

        envoy
            .expect_get_request_trailers()
            .returning(|| vec![(EnvoyBuffer::new(b"x-client-trailer"), EnvoyBuffer::new(b"preserved"))]);
        envoy
            .expect_get_buffered_request_body_size()
            .return_const(6_usize)
            .times(1);
        let attack = attack_view();
        envoy
            .expect_get_buffered_request_body()
            .returning_st(move || Some(vec![attack]));
        expect_inline_reply(&mut envoy, Rc::clone(&filter), 409);

        assert_eq!(
            filter.on_request_trailers(&mut envoy),
            RequestTrailersStatus::StopIteration,
        );
        assert!(filter.terminal.get());
    }

    #[test]
    fn detection_only_and_body_access_off_complete_phase_two_without_holding_headers() {
        for directives in [
            "SecRuleEngine DetectionOnly\nSecRule REQUEST_URI \"@contains attack\" \"id:1,phase:1,deny,status:403\"",
            "SecRuleEngine On\nSecRequestBodyAccess Off",
        ] {
            let filter = FilterConfig::new(generation(directives)).new_stream();
            let mut envoy = MockEnvoyHttpFilter::default();
            prepare_header_mock(&mut envoy, b"GET", b"/attack");
            assert_eq!(
                filter.on_request_headers(&mut envoy, false),
                RequestHeadersStatus::Continue,
            );
            assert_eq!(
                filter.state.borrow().as_ref().map(|state| state.stage),
                Some(Stage::Complete)
            );
            assert!(filter.state.borrow().as_ref().is_some_and(|state| state.phase2_done));
            assert!(!filter.terminal.get());
        }
    }

    #[test]
    fn never_decoded_stream_response_callbacks_pass_without_creating_state() {
        let filter = FilterConfig::new(generation("SecRuleEngine On")).new_stream();
        let mut envoy = MockEnvoyHttpFilter::default();

        assert_eq!(
            filter.on_response_headers(&mut envoy, false),
            ResponseHeadersStatus::Continue
        );
        assert_eq!(filter.on_response_body(&mut envoy, true), ResponseBodyStatus::Continue);
        assert_eq!(
            filter.on_response_trailers(&mut envoy),
            ResponseTrailersStatus::Continue
        );
        filter.on_stream_complete(&mut envoy);

        assert!(filter.state.borrow().is_none());
        assert!(!filter.terminal.get());
    }

    #[test]
    fn response_body_rule_uses_local_reply_from_encode_body_without_upstream_leakage() {
        let filter = Rc::new(FilterConfig::new(response_body_rule_generation()).new_stream());
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_header_mock(&mut envoy, b"GET", b"/response-deny");
        assert_eq!(
            filter.on_request_headers(&mut envoy, true),
            RequestHeadersStatus::Continue
        );

        envoy.expect_get_response_headers().returning(|| {
            vec![
                (EnvoyBuffer::new(b":status"), EnvoyBuffer::new(b"200")),
                (EnvoyBuffer::new(b"content-type"), EnvoyBuffer::new(b"text/plain")),
                (
                    EnvoyBuffer::new(b"x-upstream-secret"),
                    EnvoyBuffer::new(b"must-not-leak"),
                ),
            ]
        });
        envoy.expect_get_buffer_limit().return_const(16_u64 * 1024 * 1024);
        envoy.expect_set_buffer_limit().return_const(());
        assert_eq!(
            filter.on_response_headers(&mut envoy, false),
            ResponseHeadersStatus::StopIteration
        );

        envoy.expect_received_buffered_response_body().return_const(false);
        envoy.expect_get_received_response_body_size().return_const(13_usize);
        envoy.expect_get_buffered_response_body_size().return_const(0_usize);
        envoy.expect_get_buffered_response_body().returning_st(|| None);
        let secret = secret_view();
        envoy
            .expect_get_received_response_body()
            .returning_st(move || Some(vec![secret]));
        let reply_filter = Rc::clone(&filter);
        envoy
            .expect_send_response()
            .returning_st(move |status, headers, body, _details| {
                assert_eq!(status, 451);
                assert_eq!(body, Some(b"Upstream response blocked\n".as_slice()));
                assert!(headers.iter().all(|(name, _)| *name != "x-upstream-secret"));
                assert!(
                    reply_filter.terminal.get(),
                    "the stream is terminal before the re-entrant local reply"
                );
                let mut callback_envoy = MockEnvoyHttpFilter::default();
                assert_eq!(
                    reply_filter.on_local_reply(&mut callback_envoy, status, EnvoyBuffer::new(b""), false),
                    LocalReplyStatus::Continue
                );
                assert!(reply_filter.state.borrow().as_ref().is_some_and(|state| {
                    matches!(
                        state.outcome.as_ref(),
                        Some(TerminalOutcome::Denied {
                            phase: "response-body",
                            status: 451
                        })
                    )
                }));
            });

        assert_eq!(
            filter.on_response_body(&mut envoy, true),
            ResponseBodyStatus::StopIterationNoBuffer
        );
    }

    #[test]
    fn response_header_budget_failure_returns_generic_502() {
        let filter = FilterConfig::new(generation("SecRuleEngine On")).new_stream();
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_header_mock(&mut envoy, b"GET", b"/large-response-header");
        assert_eq!(
            filter.on_request_headers(&mut envoy, true),
            RequestHeadersStatus::Continue
        );
        envoy.expect_get_response_headers().returning(|| {
            vec![
                (EnvoyBuffer::new(b":status"), EnvoyBuffer::new(b"200")),
                (EnvoyBuffer::new(b"x-large"), oversized_header_value()),
            ]
        });
        envoy
            .expect_send_response()
            .returning_st(|status, headers, body, _details| {
                assert_eq!(status, 502);
                assert_eq!(body, Some(b"Response inspection unavailable\n".as_slice()));
                assert!(!headers.iter().any(|(name, _)| *name == "x-large"));
            });

        assert_eq!(
            filter.on_response_headers(&mut envoy, false),
            ResponseHeadersStatus::StopIteration
        );
    }

    #[test]
    fn phase_four_header_rules_run_at_headers_for_mime_excluded_and_body_off_responses() {
        for policy in [
            response_header_rule_generation("SecResponseBodyAccess On\nSecResponseBodyMimeType text/plain"),
            response_header_rule_generation("SecResponseBodyAccess Off"),
        ] {
            let filter = Rc::new(FilterConfig::new(policy).new_stream());
            let mut envoy = MockEnvoyHttpFilter::default();
            prepare_header_mock(&mut envoy, b"GET", b"/phase-four-header");
            assert_eq!(
                filter.on_request_headers(&mut envoy, true),
                RequestHeadersStatus::Continue
            );
            envoy.expect_get_response_headers().returning(|| {
                vec![
                    (EnvoyBuffer::new(b":status"), EnvoyBuffer::new(b"200")),
                    (
                        EnvoyBuffer::new(b"content-type"),
                        EnvoyBuffer::new(b"application/octet-stream"),
                    ),
                    (EnvoyBuffer::new(b"x-deny-response"), EnvoyBuffer::new(b"yes")),
                ]
            });
            envoy
                .expect_send_response()
                .returning_st(move |status, _headers, _body, _details| assert_eq!(status, 452));

            assert_eq!(
                filter.on_response_headers(&mut envoy, false),
                ResponseHeadersStatus::StopIteration
            );
        }
    }

    #[test]
    fn stream_completion_finishes_once_releases_admission_and_publishes_health_before_host_flush() {
        let generation = Arc::new(
            Generation::compile(
                Config::parse(
                    br#"{"directives_map":{"p":["SecRuleEngine On"]},"default_directives":"p","enable_filter_state_logs":true}"#,
                )
                .unwrap(),
                Arc::new(Diagnostics::default()),
                |_| {},
                |_, _| {},
            )
            .unwrap(),
        );
        let policy = generation.select("example.test").unwrap();
        let filter = Rc::new(FilterConfig::new(Arc::clone(&generation)).new_stream());
        let mut state = StreamState::new(Arc::clone(&generation));
        state.stage = Stage::Complete;
        state.response_stage = ResponseStage::Complete;
        state.transaction = Some(Box::new(policy.waf.new_transaction()));
        assert!(state.reservation.resize(19));
        *filter.state.borrow_mut() = Some(state);

        let keys = Rc::new(RefCell::new(Vec::new()));
        let expected_keys = Rc::clone(&keys);
        let callback_filter = Rc::clone(&filter);
        let mut envoy = MockEnvoyHttpFilter::default();
        envoy
            .expect_set_filter_state_bytes()
            .times(7)
            .returning_st(move |key, value| {
                let key = std::str::from_utf8(key).unwrap().to_owned();
                let value = std::str::from_utf8(value).unwrap().to_owned();
                let state = callback_filter.state.borrow();
                let state = state.as_ref().unwrap();
                assert!(state.finalized, "health state is set after transaction finalization");
                assert!(state.transaction.is_none());
                assert_eq!(
                    state.reservation.bytes, 0,
                    "retained memory is released before access-log state"
                );
                expected_keys.borrow_mut().push((key, value));
                true
            });

        filter.on_stream_complete(&mut envoy);
        filter.on_stream_complete(&mut envoy);

        let keys = keys.borrow();
        assert_eq!(keys.len(), 7);
        assert!(keys.contains(&(
            "wasm.io.coraza.waf.v1.inspection_reason".to_owned(),
            "complete".to_owned()
        )));
        assert!(keys.contains(&(
            "wasm.io.coraza.waf.v1.terminal_outcome".to_owned(),
            "completed".to_owned()
        )));
        assert!(keys.contains(&(
            "wasm.io.coraza.waf.v1.telemetry_publish_failed".to_owned(),
            "false".to_owned()
        )));
    }

    #[test]
    fn terminal_outcomes_distinguish_denial_completion_and_cancellation() {
        let generation = generation("SecRuleEngine On");
        let mut denied = StreamState::new(Arc::clone(&generation));
        denied.stage = Stage::Terminal;
        denied.outcome = Some(TerminalOutcome::Denied {
            phase: "response-body",
            status: 451,
        });
        assert_eq!(terminal_outcome(&denied).terminal_name(), "denied");

        let mut complete = StreamState::new(Arc::clone(&generation));
        complete.stage = Stage::Complete;
        complete.response_stage = ResponseStage::Complete;
        assert_eq!(terminal_outcome(&complete).terminal_name(), "completed");

        let mut reset = StreamState::new(generation);
        reset.stage = Stage::Complete;
        assert_eq!(
            terminal_outcome(&reset).terminal_name(),
            "upstream_failure_or_cancellation"
        );
    }

    #[test]
    fn drop_finalizes_transaction_when_completion_callback_is_missing() {
        struct FinishLogger(Arc<AtomicUsize>);

        impl coraza::debug_log::DebugLogger for FinishLogger {
            fn enabled(&self, _level: coraza::debug_log::DebugLevel) -> bool {
                true
            }

            fn log(&self, _level: coraza::debug_log::DebugLevel, event: &coraza::debug_log::DebugEvent<'_>) {
                if event.message == "Transaction finalized" {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let finalized = Arc::new(AtomicUsize::new(0));
        let generation = Arc::new(
            Generation::compile_with_debug_logger(
                Config::parse(
                    br#"{"directives_map":{"p":["SecRuleEngine On","SecDebugLogLevel 4"]},"default_directives":"p"}"#,
                )
                .unwrap(),
                Arc::new(Diagnostics::default()),
                |_| {},
                |_, _| {},
                Arc::new(FinishLogger(Arc::clone(&finalized))),
            )
            .unwrap(),
        );
        let policy = generation.select("example.test").unwrap();
        let mut state = StreamState::new(Arc::clone(&generation));
        state.transaction = Some(Box::new(policy.waf.new_transaction()));

        drop(state);

        assert_eq!(finalized.load(Ordering::Relaxed), 1);
    }
}
