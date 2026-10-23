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

//! Response body ingestion and processing.

use super::{
    Interruption, Transaction,
    body_buffer::BodyBuffer,
    request_body::{publish_json_arguments, read_json_body},
    variables::BodyProcessor,
};
use crate::types::{AuditEngineStatus, AuditLogPart, BodyLimitAction, RulePhase};

#[expect(
    clippy::multiple_inherent_impl,
    reason = "transaction impl blocks are split across submodules"
)]
impl Transaction {
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
    ///
    /// When the body is eligible, bytes are retained in a bounded buffer truncated to
    /// [`Transaction::response_body_limit`]. Like Go Coraza v3.8.1 `WriteResponseBody`
    /// (`internal/corazawaf/transaction.go:1263`), reaching the limit itself sets
    /// `OUTBOUND_DATA_ERROR`, so the boundary is `>=`. The response buffer never spills:
    /// its memory limit equals the response body limit, as in Go. An I/O failure while
    /// retaining or replaying the body fails closed with a 500 interruption.
    pub fn process_response_body(&mut self, body: &[u8]) -> Option<Interruption> {
        if !self.begin_phase(RulePhase::ResponseBody) {
            return self.interruption.clone();
        }

        let mut ingest_error = false;
        let processable = self.response_body_access && self.is_response_body_processable();
        if processable {
            self.response_content_length.set(body.len().to_string());
            if !body.is_empty() {
                let limit = usize::try_from(self.response_body_limit).unwrap_or(0);
                self.response_body_buffer = BodyBuffer::new(limit, limit);
                if body.len() >= limit.saturating_sub(self.response_body_buffer.len()) {
                    self.outbound_data_error.set("1");
                    if self.config.response_body_limit_action == BodyLimitAction::Reject {
                        self.interrupt(0, "deny", 500, "");
                        if self.interruption.is_some() {
                            self.response_body_buffer.refuse(body.len());
                            return self.interruption.clone();
                        }
                    }
                }
                if self.response_body_buffer.accept(body).is_err() {
                    ingest_error = true;
                }
            }
        }

        if self.audit_engine != AuditEngineStatus::Off
            && (self.audit_log_parts.contains(&AuditLogPart::IntermediaryResponseBody)
                || self.audit_log_parts.contains(&AuditLogPart::ResponseBody))
        {
            self.audit_response_body.clear();
            match self.response_body_buffer.contiguous() {
                Ok(retained) => self.audit_response_body.extend_from_slice(&retained),
                Err(_) => ingest_error = true,
            }
        }

        if ingest_error {
            self.outbound_data_error.set("1");
            self.interrupt(0, "deny", 500, "");
            // Detection-only records a would-be interruption; the body phase
            // must still evaluate its rules rather than being skipped.
            if self.interruption.is_some() {
                return self.interruption.clone();
            }
        } else if processable {
            // Go runs the selected processor even for an empty response body
            // (`internal/corazawaf/transaction.go:1389-1423`).
            let mut buffer = std::mem::take(&mut self.response_body_buffer);
            let inspected = buffer.contiguous().map(|body| {
                let length = body.len();
                self.inspect_response_body(&body);
                length
            });
            self.response_body_buffer = buffer;
            if let Ok(length) = inspected {
                self.response_body_buffer.set_inspected(length);
            } else {
                self.outbound_data_error.set("1");
                self.interrupt(0, "deny", 500, "");
                if self.interruption.is_some() {
                    return self.interruption.clone();
                }
            }
        }

        self.run_phase(RulePhase::ResponseBody);
        self.interruption.clone()
    }

    /// Parse or store response body data before phase 4 rules run.
    ///
    /// With the JSON processor, Go Coraza stores the raw body in
    /// `TX.json_response_body` after a successful parse and leaves
    /// `RESPONSE_BODY` unset (`internal/bodyprocessors/json.go:92-99`,
    /// `internal/corazawaf/transaction.go:1399-1423`). Other processors keep the
    /// existing contract.
    fn inspect_response_body(&mut self, body: &[u8]) {
        if let Some(BodyProcessor::Json) = self.response_body_processor {
            // Arguments are published before the error is checked so a valid
            // prefix stays inspectable; see Go Coraza `json.go:74-97`.
            let parsed = read_json_body(
                body,
                self.config.response_body_json_depth_limit,
                self.config.argument_limit,
            );
            publish_json_arguments(self, &parsed.arguments, true);
            if parsed.truncated {
                self.arguments_limit_reached.set("1");
            }
            match parsed.error {
                Some(message) => {
                    self.res_body_error.set("1");
                    self.res_body_error_msg.set(format!("JSON: {message}"));
                    self.res_body_processor_error.set("1");
                    self.res_body_processor_error_msg.set(message);
                },
                None => self.set_tx_variable("json_response_body", body),
            }
        } else {
            self.response_body.set(body);
        }
    }

    /// Select a response body processor for phase 4.
    pub(super) fn set_response_body_processor(&mut self, name: &str) {
        self.response_body_processor = BodyProcessor::parse(name);
        self.res_body_processor.set(name.to_ascii_uppercase());
    }
}
