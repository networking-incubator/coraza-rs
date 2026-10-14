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

#![forbid(unsafe_code)]
#![expect(missing_docs, reason = "The Proxy-Wasm SDK generates the Wasm ABI entry point.")]
//! Envoy's Proxy-Wasm HTTP filter for bounded libperfusion inspection.

/// Configuration schema and validation.
mod config;
/// HTTP surface parsing and detector invocation.
mod inspect;

use config::{Config, Mode};
use inspect::{BodyFormat, Incomplete, Inspection};
use proxy_wasm::{
    traits::{Context, HttpContext, RootContext},
    types::{Action, ContextType, LogLevel},
};

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Warn);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(LibperfusionRoot { config: Config::default() })
    });
}}

/// Owns validated configuration and constructs stream contexts.
struct LibperfusionRoot {
    /// Current immutable filter configuration.
    config: Config,
}

impl Context for LibperfusionRoot {}

impl RootContext for LibperfusionRoot {
    /// Registers the HTTP filter context type.
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    /// Loads Envoy configuration, using defaults when none is supplied.
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        let Some(configuration) = self.get_plugin_configuration() else {
            self.config = Config::default();
            return true;
        };
        match Config::parse(&configuration) {
            Ok(config) => {
                self.config = config;
                true
            },
            Err(error) => {
                log::error!("libperfusion: invalid plugin configuration: {error}");
                false
            },
        }
    }

    /// Creates a stream context with a snapshot of the current configuration.
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(LibperfusionHttp::new(self.config)))
    }
}

/// Tracks whether request inspection is active, incomplete or terminal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RequestState {
    /// The request is held while the body is inspected.
    Inspecting,
    /// The request is streaming and only headers/trailers can be inspected.
    Streaming,
    /// The request reached a terminal policy outcome.
    Done,
}

/// Tracks whether response inspection is active, incomplete or terminal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponseState {
    /// The response is held while the body is inspected.
    Inspecting,
    /// The response is streaming and only headers/trailers can be inspected.
    Streaming,
    /// A generic 502 is replacing the response while its headers are held.
    BlockedHeld,
    /// A generic 502 has been released and later body chunks only need stripping.
    BlockedReleased,
    /// The response reached a terminal policy outcome.
    Done,
}

impl ResponseState {
    /// Advances a blocked response after a body callback releases the current chunk.
    fn after_blocked_body(end_of_stream: bool) -> Self {
        if end_of_stream {
            Self::Done
        } else {
            Self::BlockedReleased
        }
    }

    /// Ends a blocked response when trailers arrive after release.
    fn after_blocked_trailers(self) -> Option<Self> {
        matches!(self, Self::BlockedHeld | Self::BlockedReleased).then_some(Self::Done)
    }
}

/// Holds request and response inspection state for one HTTP stream.
struct LibperfusionHttp {
    /// Configuration snapshot for this stream.
    config: Config,
    /// Request-side findings accumulated through body completion.
    request: Option<Inspection>,
    /// Parser chosen from request content type.
    request_format: BodyFormat,
    /// Most recent cumulative request body size.
    request_body_size: usize,
    /// Lifecycle state for request inspection.
    request_state: RequestState,
    /// Response-side findings accumulated through body completion.
    response: Option<Inspection>,
    /// Parser chosen from response content type.
    response_format: BodyFormat,
    /// Most recent cumulative response body size.
    response_body_size: usize,
    /// Lifecycle state for response inspection.
    response_state: ResponseState,
}

impl LibperfusionHttp {
    /// Creates an HTTP context with a configuration snapshot.
    fn new(config: Config) -> Self {
        Self {
            config,
            request: None,
            request_format: BodyFormat::Raw,
            request_body_size: 0,
            request_state: RequestState::Inspecting,
            response: None,
            response_format: BodyFormat::Raw,
            response_body_size: 0,
            response_state: ResponseState::Inspecting,
        }
    }

    /// Returns request mode.
    fn request_mode(&self) -> Mode {
        self.config.request_mode
    }

    /// Returns response mode.
    fn response_mode(&self) -> Mode {
        self.config.response_mode
    }

    /// Returns whether incomplete inspection must reject traffic.
    fn reject_incomplete(&self, mode: Mode) -> bool {
        self.config.rejects_incomplete(mode)
    }

    /// Sends a generic request-side rejection and marks the stream terminal.
    fn reject_request(&mut self, status: u32, message: &'static [u8]) -> Action {
        log::warn!("libperfusion: request outcome=reject status={status}");
        self.send_http_response(
            status,
            vec![
                ("content-type", "text/plain; charset=utf-8"),
                ("cache-control", "no-store"),
            ],
            Some(message),
        );
        self.request_state = RequestState::Done;
        Action::Pause
    }

    /// Sends the configured request attack response.
    fn block_request(&mut self) -> Action {
        self.reject_request(403, b"Request blocked by security policy\n")
    }

    /// Rewrites held response headers before the response is released.
    fn block_response_headers(&self) {
        for (name, _) in self.get_http_response_headers_bytes() {
            if name != ":status" {
                self.set_http_response_header(&name, None);
            }
        }
        self.set_http_response_header(":status", Some("502"));
        self.set_http_response_header("content-type", Some("text/plain; charset=utf-8"));
        self.set_http_response_header("cache-control", Some("no-store"));
    }

    /// Replaces the held response body with a generic message.
    fn replace_blocked_response_body(&self, size: usize) {
        self.set_http_response_body(0, size, b"Upstream response blocked\n");
    }

    /// Applies a response rejection and logs the terminal outcome.
    fn apply_response_block(&mut self, size: usize) {
        self.block_response_headers();
        self.replace_blocked_response_body(size);
        self.response_state = ResponseState::Done;
        log::warn!("libperfusion: response outcome=blocked status=502");
    }

    /// Strips the held or released body chunk after blocking a response.
    fn continue_blocked_response_body(&mut self, body_size: usize, end_of_stream: bool) {
        if end_of_stream {
            if body_size > 0 {
                self.replace_blocked_response_body(body_size);
            }
        } else {
            self.set_http_response_body(0, body_size, b"");
        }
        self.response_state = ResponseState::after_blocked_body(end_of_stream);
        if end_of_stream {
            log::warn!("libperfusion: response outcome=blocked status=502");
        }
    }

    /// Logs detector and incomplete-inspection outcomes without request data.
    fn report_inspection(direction: &str, mode: Mode, inspection: &Inspection) {
        if inspection.has_sqli() {
            log::warn!("libperfusion: direction={direction} detector=sqli mode={mode:?}");
        }
        if inspection.has_xss() {
            log::warn!("libperfusion: direction={direction} detector=xss mode={mode:?}");
        }
        if let Some(reason) = inspection.incomplete() {
            log::warn!("libperfusion: direction={direction} inspection=incomplete reason={reason:?}");
        }
    }

    /// Applies request mode and incomplete-coverage policy after inspection.
    fn finish_request(&mut self) -> Action {
        let Some(inspection) = self.request.as_ref() else {
            return Action::Continue;
        };
        let has_detection = inspection.has_sqli() || inspection.has_xss();
        if has_detection && self.request_mode() == Mode::Block {
            return self.block_request();
        }
        if let Some(reason) = inspection.incomplete() {
            if self.reject_incomplete(self.request_mode()) {
                return self.reject_request(reason.status_code(), b"Request inspection incomplete\n");
            }
        }
        Self::report_inspection("request", self.request_mode(), inspection);
        self.request_state = RequestState::Done;
        Action::Continue
    }

    /// Applies response mode and incomplete-coverage policy after inspection.
    fn finish_response(&mut self, body_size: usize) -> Action {
        let Some(inspection) = self.response.as_ref() else {
            return Action::Continue;
        };
        if self.response_state == ResponseState::BlockedHeld {
            self.replace_blocked_response_body(body_size);
            self.response_state = ResponseState::Done;
            log::warn!("libperfusion: response outcome=blocked status=502");
            return Action::Continue;
        }
        if self.should_block_response() {
            self.apply_response_block(body_size);
            return Action::Continue;
        }
        Self::report_inspection("response", self.response_mode(), inspection);
        self.response_state = ResponseState::Done;
        Action::Continue
    }

    /// Applies the configured response policy to accumulated findings.
    fn should_block_response(&self) -> bool {
        self.response.as_ref().is_some_and(|inspection| {
            (self.response_mode() == Mode::Block && (inspection.has_sqli() || inspection.has_xss()))
                || (self.reject_incomplete(self.response_mode()) && inspection.incomplete().is_some())
        })
    }

    /// Reads and inspects a completed request body within its configured bound.
    fn scan_request_body(&mut self, body_size: usize) -> bool {
        if body_size > self.config.max_request_body_bytes {
            if let Some(inspection) = self.request.as_mut() {
                inspection.mark_incomplete(Incomplete::BodyTooLarge);
            }
            return false;
        }
        let Some(body) = self.get_http_request_body(0, body_size) else {
            if let Some(inspection) = self.request.as_mut() {
                inspection.mark_incomplete(Incomplete::BodyUnavailable);
            }
            return false;
        };
        if !body.is_empty() {
            if let Some(inspection) = self.request.as_mut() {
                inspection.body(body, &self.request_format);
            }
        }
        true
    }

    /// Reads and inspects a completed response body within its configured bound.
    fn scan_response_body(&mut self, body_size: usize) -> bool {
        if body_size > self.config.max_response_body_bytes {
            if let Some(inspection) = self.response.as_mut() {
                inspection.mark_incomplete(Incomplete::BodyTooLarge);
            }
            return false;
        }
        let Some(body) = self.get_http_response_body(0, body_size) else {
            if let Some(inspection) = self.response.as_mut() {
                inspection.mark_incomplete(Incomplete::BodyUnavailable);
            }
            return false;
        };
        if !body.is_empty() {
            if let Some(inspection) = self.response.as_mut() {
                inspection.body(body, &self.response_format);
            }
        }
        true
    }
}

impl Context for LibperfusionHttp {}

impl HttpContext for LibperfusionHttp {
    /// Inspects request headers and applies the configured body-hold strategy.
    fn on_http_request_headers(&mut self, _num_headers: usize, end_of_stream: bool) -> Action {
        if self.request_mode() == Mode::Off {
            return Action::Continue;
        }

        let headers = self.get_http_request_headers_bytes();
        let mut inspection = Inspection::new(&self.config);
        self.request_format = inspection.headers(&headers);
        let incomplete = inspection.incomplete();
        let has_detection = inspection.has_sqli() || inspection.has_xss();
        self.request_state = if inspection.is_streaming() {
            RequestState::Streaming
        } else {
            RequestState::Inspecting
        };
        self.request = Some(inspection);

        if has_detection && self.request_mode() == Mode::Block {
            return self.block_request();
        }
        if let Some(reason) = incomplete {
            if self.reject_incomplete(self.request_mode()) {
                return self.reject_request(reason.status_code(), b"Request inspection incomplete\n");
            }
        }
        if self.request_state == RequestState::Streaming {
            if let Some(inspection) = self.request.as_ref() {
                Self::report_inspection("request", self.request_mode(), inspection);
            }
            return Action::Continue;
        }
        if end_of_stream {
            return self.finish_request();
        }
        if !self.config.allow_request_headers_before_body_verdict {
            return Action::Pause;
        }
        Action::Continue
    }

    /// Tracks buffered request bodies and inspects them when complete.
    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if self.request_mode() == Mode::Off || self.request_state != RequestState::Inspecting {
            return Action::Continue;
        }
        self.request_body_size = body_size;
        if body_size > self.config.max_request_body_bytes {
            if let Some(inspection) = self.request.as_mut() {
                inspection.mark_incomplete(Incomplete::BodyTooLarge);
            }
            if self.reject_incomplete(self.request_mode()) {
                let reason = self
                    .request
                    .as_ref()
                    .and_then(Inspection::incomplete)
                    .unwrap_or(Incomplete::BodyUnavailable);
                return self.reject_request(reason.status_code(), b"Request inspection incomplete\n");
            }
            if let Some(inspection) = self.request.as_ref() {
                Self::report_inspection("request", self.request_mode(), inspection);
            }
            self.request_state = RequestState::Streaming;
            return Action::Continue;
        }
        if !end_of_stream {
            return Action::Pause;
        }
        if !self.scan_request_body(body_size) {
            if self.reject_incomplete(self.request_mode()) {
                let reason = self
                    .request
                    .as_ref()
                    .and_then(Inspection::incomplete)
                    .unwrap_or(Incomplete::BodyUnavailable);
                return self.reject_request(reason.status_code(), b"Request inspection incomplete\n");
            }
            if let Some(inspection) = self.request.as_ref() {
                Self::report_inspection("request", self.request_mode(), inspection);
            }
            self.request_state = RequestState::Streaming;
            return Action::Continue;
        }
        self.finish_request()
    }

    /// Inspects request trailers and applies the final request policy.
    fn on_http_request_trailers(&mut self, _num_trailers: usize) -> Action {
        if self.request_mode() == Mode::Off {
            return Action::Continue;
        }
        if self.request_state == RequestState::Streaming {
            let trailers = self.get_http_request_trailers_bytes();
            if let Some(inspection) = self.request.as_mut() {
                inspection.trailers(&trailers);
            }
            return self.finish_request();
        }
        if self.request_state == RequestState::Done {
            return Action::Continue;
        }
        if self.request_body_size <= self.config.max_request_body_bytes {
            let _ = self.scan_request_body(self.request_body_size);
        }
        let trailers = self.get_http_request_trailers_bytes();
        if let Some(inspection) = self.request.as_mut() {
            inspection.trailers(&trailers);
        }
        self.finish_request()
    }

    /// Inspects response headers and holds buffered responses for body inspection.
    fn on_http_response_headers(&mut self, _num_headers: usize, end_of_stream: bool) -> Action {
        if self.response_mode() == Mode::Off {
            return Action::Continue;
        }

        let headers = self.get_http_response_headers_bytes();
        let mut inspection = Inspection::new(&self.config);
        self.response_format = inspection.headers(&headers);
        let incomplete = inspection.incomplete();
        let has_detection = inspection.has_sqli() || inspection.has_xss();
        let streaming = inspection.is_streaming();
        self.response = Some(inspection);

        let reject_headers = has_detection && self.response_mode() == Mode::Block
            || incomplete.is_some() && self.reject_incomplete(self.response_mode());
        if reject_headers && streaming && !end_of_stream {
            self.response_state = ResponseState::Done;
            self.send_http_response(
                502,
                vec![
                    ("content-type", "text/plain; charset=utf-8"),
                    ("cache-control", "no-store"),
                ],
                Some(b"Upstream response blocked\n"),
            );
            log::warn!("libperfusion: response outcome=blocked status=502");
            return Action::Pause;
        }
        if reject_headers {
            self.response_state = ResponseState::BlockedHeld;
            self.block_response_headers();
        }
        if end_of_stream {
            return self.finish_response(0);
        }
        if streaming
            && !self.reject_incomplete(self.response_mode())
            && self.response_state != ResponseState::BlockedHeld
        {
            if let Some(inspection) = self.response.as_ref() {
                Self::report_inspection("response", self.response_mode(), inspection);
            }
            self.response_state = ResponseState::Streaming;
            return Action::Continue;
        }
        Action::Pause
    }

    /// Tracks buffered response bodies and inspects them when complete.
    fn on_http_response_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if self.response_mode() == Mode::Off
            || self.response_state == ResponseState::Done
            || self.response_state == ResponseState::Streaming
        {
            return Action::Continue;
        }
        self.response_body_size = body_size;

        if matches!(
            self.response_state,
            ResponseState::BlockedHeld | ResponseState::BlockedReleased
        ) {
            self.continue_blocked_response_body(body_size, end_of_stream);
            return Action::Continue;
        }

        if body_size > self.config.max_response_body_bytes {
            if let Some(inspection) = self.response.as_mut() {
                inspection.mark_incomplete(Incomplete::BodyTooLarge);
            }
            if self.reject_incomplete(self.response_mode()) {
                self.response_state = ResponseState::BlockedHeld;
                self.block_response_headers();
                self.continue_blocked_response_body(body_size, end_of_stream);
                return Action::Continue;
            }
            self.response_state = ResponseState::Streaming;
            if let Some(inspection) = self.response.as_ref() {
                Self::report_inspection("response", self.response_mode(), inspection);
            }
            return Action::Continue;
        }

        if !end_of_stream {
            return Action::Pause;
        }

        if !self.scan_response_body(body_size) && self.reject_incomplete(self.response_mode()) {
            self.response_state = ResponseState::BlockedHeld;
            self.block_response_headers();
            self.continue_blocked_response_body(body_size, end_of_stream);
            return Action::Continue;
        }
        self.finish_response(body_size)
    }

    /// Inspects response trailers and completes or reports response inspection.
    fn on_http_response_trailers(&mut self, _num_trailers: usize) -> Action {
        if self.response_mode() == Mode::Off {
            return Action::Continue;
        }
        if self.response_state == ResponseState::Streaming {
            let trailers = self.get_http_response_trailers_bytes();
            if let Some(inspection) = self.response.as_mut() {
                inspection.trailers(&trailers);
            }
            if self.should_block_response() {
                self.set_http_response_trailers(Vec::new());
                self.response_state = ResponseState::Done;
                log::warn!("libperfusion: response outcome=blocked_trailers");
                return Action::Continue;
            }
            if let Some(inspection) = self.response.as_ref() {
                Self::report_inspection("response", self.response_mode(), inspection);
            }
            return Action::Continue;
        }
        if let Some(state) = self.response_state.after_blocked_trailers() {
            self.set_http_response_trailers(Vec::new());
            self.response_state = state;
            log::warn!("libperfusion: response outcome=blocked status=502");
            return Action::Continue;
        }
        if self.response_state == ResponseState::Done {
            return Action::Continue;
        }
        if self.response_body_size <= self.config.max_response_body_bytes {
            let _ = self.scan_response_body(self.response_body_size);
        }
        let trailers = self.get_http_response_trailers_bytes();
        if let Some(inspection) = self.response.as_mut() {
            inspection.trailers(&trailers);
        }
        if self.should_block_response() {
            self.set_http_response_trailers(Vec::new());
        }
        self.finish_response(self.response_body_size)
    }
}

#[cfg(test)]
/// Response lifecycle tests.
mod tests {
    use super::ResponseState;

    /// Leaves a blocked response in a released state until more body callbacks or trailers arrive.
    #[test]
    fn blocked_response_body_transitions_follow_stream_release() {
        assert!(matches!(
            ResponseState::after_blocked_body(false),
            ResponseState::BlockedReleased
        ));
        assert!(matches!(ResponseState::after_blocked_body(true), ResponseState::Done));
        let released = ResponseState::after_blocked_body(false);
        assert!(matches!(released.after_blocked_trailers(), Some(ResponseState::Done)));
    }
}
