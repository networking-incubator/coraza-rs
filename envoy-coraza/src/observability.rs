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

//! Bounded Proxy-Wasm filter-state and log publication.

use coraza::{
    audit_log::{AuditLog, MatchedRule},
    transaction::{Interruption, Transaction},
    types::AuditLogFormat,
};
use envoy_coraza_common::observability::{
    bounded, interruption_fields, sanitize_audit, Diagnostics, HealthState, InterruptionPhase, MAX_AUDIT_LOG_BYTES,
    MAX_ERROR_LOG_BYTES,
};
use proxy_wasm::{hostcalls, types::LogLevel};

/// Records telemetry hostcall failures and rate-limits secondary diagnostics.
pub(crate) fn hostcall_failure(diagnostics: &Diagnostics, operation: &'static str) {
    let count = diagnostics.record_failure();
    if count == 1 || count.is_power_of_two() {
        let message = format!("envoy-coraza: telemetry hostcall failed ({operation}; failures={count})");
        if hostcalls::log(LogLevel::Error, &message).is_err() {
            diagnostics.record_failure();
        }
    }
}

/// Publishes the PR #20 interruption properties before local replies or response rewriting.
pub(crate) fn interruption(
    enabled: bool,
    transaction: &Transaction,
    interruption: &Interruption,
    phase: InterruptionPhase,
    diagnostics: &Diagnostics,
) -> bool {
    let mut failed = false;
    if !enabled {
        return false;
    }

    let fields = interruption_fields(transaction, interruption, phase);
    for (field, value) in fields {
        if value.is_empty() {
            continue;
        }
        let path = format!("io.coraza.waf.{field}");
        if hostcalls::set_property(vec![path.as_str()], Some(value.as_bytes())).is_err() {
            failed = true;
            hostcall_failure(diagnostics, "filter state property");
        }
    }
    failed
}

/// Publishes the additive v1 fields; failures do not affect enforcement.
pub(crate) fn health(enabled: bool, state: HealthState<'_>, diagnostics: &Diagnostics) -> bool {
    if !enabled {
        return state.telemetry_publish_failed;
    }
    let mut failed = state.telemetry_publish_failed;
    let fields = [
        ("inspection_complete", state.inspection_complete.to_string()),
        ("inspection_reason", state.inspection_reason.to_owned()),
        ("policy_generation", state.generation.to_string()),
        ("request_body_truncated", state.request_body_truncated.to_string()),
        ("response_body_truncated", state.response_body_truncated.to_string()),
        ("terminal_outcome", state.terminal_outcome.to_owned()),
    ];
    for (field, value) in fields {
        if publish_property("io.coraza.waf.v1", field, &value).is_err() {
            failed = true;
            hostcall_failure(diagnostics, "health state property");
        }
    }
    if publish_property("io.coraza.waf.v1", "telemetry_publish_failed", &failed.to_string()).is_err() {
        failed = true;
        hostcall_failure(diagnostics, "telemetry failure property");
    }
    failed
}

/// Sets one filter-state property under a fixed namespace.
fn publish_property(prefix: &str, field: &str, value: &str) -> Result<(), proxy_wasm::types::Status> {
    let path = format!("{prefix}.{field}");
    hostcalls::set_property(vec![path.as_str()], Some(value.as_bytes()))
}

/// Emits Coraza's existing bounded and sanitized rule error log line.
pub(crate) fn error_log(matched: &MatchedRule, diagnostics: &Diagnostics) {
    let message = bounded(&matched.error_log(), MAX_ERROR_LOG_BYTES);
    if hostcalls::log(LogLevel::Warn, &message).is_err() {
        hostcall_failure(diagnostics, "rule error log");
    }
}

/// Emits one selected Coraza audit entry using configured parts and format.
pub(crate) fn audit_log(entry: &AuditLog, format: AuditLogFormat, diagnostics: &Diagnostics) {
    let (formatted, truncated) = entry.format_bounded(format, MAX_AUDIT_LOG_BYTES);
    if formatted.is_empty() {
        return;
    }
    let message = sanitize_audit(&formatted, MAX_AUDIT_LOG_BYTES, truncated);
    if hostcalls::log(LogLevel::Critical, &message).is_err() {
        hostcall_failure(diagnostics, "audit log");
    }
}
