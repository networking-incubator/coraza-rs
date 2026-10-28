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

//! Bounded, per-generation Proxy-Wasm state, metric, and log publication.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    },
};

use coraza::{
    audit_log::{AuditLog, MatchedRule},
    transaction::{Interruption, Transaction},
    types::AuditLogFormat,
};
#[cfg(target_arch = "wasm32")]
use proxy_wasm::types::MetricType;
use proxy_wasm::{hostcalls, types::LogLevel};

/// Maximum rule-error log message size in bytes.
const MAX_ERROR_LOG_BYTES: usize = 4096;
/// Maximum audit log message size in bytes.
const MAX_AUDIT_LOG_BYTES: usize = 16 * 1024;
/// Marker appended when a published log message was truncated.
const TRUNCATION_MARKER: &str = " [truncated]";

/// Counts telemetry hostcall failures and rate-limits secondary diagnostics.
#[derive(Debug, Default)]
pub(crate) struct Diagnostics {
    /// Count of observed telemetry hostcall failures.
    failures: AtomicU64,
}

impl Diagnostics {
    /// Emits a bounded diagnostic at failure counts 1, 2, 4, 8, and so on.
    pub(crate) fn hostcall_failure(&self, operation: &'static str) {
        let count = self.failures.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if count == 1 || count.is_power_of_two() {
            let message = format!("envoy-coraza: telemetry hostcall failed ({operation}; failures={count})");
            if hostcalls::log(LogLevel::Error, &message).is_err() {
                self.failures.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Returns the number of hostcall failures observed so far.
    pub(crate) fn failure_count(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Default)]
/// Metric IDs defined by one policy generation.
struct MetricIds {
    /// Total transactions.
    tx_total: Option<u32>,
    /// Transactions ending with an error.
    errors_total: Option<u32>,
    /// Transactions with incomplete inspection.
    incomplete_total: Option<u32>,
    /// Telemetry publication failures.
    telemetry_failures_total: Option<u32>,
    /// Currently active streams.
    active_streams: Option<u32>,
    /// Bytes retained for request and response inspection.
    retained_body_bytes: Option<u32>,
    /// Interruption counters keyed by phase and rule ID.
    #[cfg(target_arch = "wasm32")]
    interruptions: BTreeMap<(String, i32), u32>,
}

/// Metric names use only configured static labels and IDs compiled into the generation.
#[derive(Debug)]
pub(crate) struct Metrics {
    /// Configured labels appended to interruption metric names.
    #[cfg(target_arch = "wasm32")]
    labels: Vec<(String, String)>,
    /// IDs of the bounded counters and gauges.
    ids: Mutex<MetricIds>,
    /// Whether any metric definition failed during initialization.
    initialization_failed: AtomicBool,
}

impl Metrics {
    /// Creates metric state for one generation.
    pub(crate) fn new(labels: &BTreeMap<String, String>) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let _ = labels;
        Self {
            #[cfg(target_arch = "wasm32")]
            labels: labels.iter().map(|(key, value)| (key.clone(), value.clone())).collect(),
            ids: Mutex::new(MetricIds::default()),
            initialization_failed: AtomicBool::new(false),
        }
    }

    /// Defines the bounded counters and gauges once for this generation.
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn initialize(&self, diagnostics: &Diagnostics) {
        let mut ids = self.ids.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        ids.tx_total = Self::define(MetricType::Counter, "waf_filter.tx.total", diagnostics);
        ids.errors_total = Self::define(MetricType::Counter, "waf_filter_errors_total", diagnostics);
        ids.incomplete_total = Self::define(
            MetricType::Counter,
            "waf_filter_incomplete_inspections_total",
            diagnostics,
        );
        ids.telemetry_failures_total =
            Self::define(MetricType::Counter, "waf_filter_telemetry_failures_total", diagnostics);
        ids.active_streams = Self::define(MetricType::Gauge, "waf_filter_active_streams", diagnostics);
        ids.retained_body_bytes = Self::define(MetricType::Gauge, "waf_filter_retained_body_bytes", diagnostics);
        let failed = [
            ids.tx_total,
            ids.errors_total,
            ids.incomplete_total,
            ids.telemetry_failures_total,
            ids.active_streams,
            ids.retained_body_bytes,
        ]
        .into_iter()
        .any(|id| id.is_none());
        self.initialization_failed.store(failed, Ordering::Relaxed);
        if failed {
            if let Some(id) = ids.telemetry_failures_total {
                if hostcalls::increment_metric(id, 1).is_err() {
                    diagnostics.hostcall_failure("metric definition failure counter");
                }
            }
        }
    }

    /// Returns whether any metric definition failed during initialization.
    pub(crate) fn initialization_failed(&self) -> bool {
        self.initialization_failed.load(Ordering::Relaxed)
    }

    #[cfg(target_arch = "wasm32")]
    /// Defines one host metric and records a diagnostic on failure.
    fn define(kind: MetricType, name: &str, diagnostics: &Diagnostics) -> Option<u32> {
        if let Ok(id) = hostcalls::define_metric(kind, name) {
            Some(id)
        } else {
            diagnostics.hostcall_failure("metric definition");
            None
        }
    }

    /// Increments the transaction counter.
    pub(crate) fn transaction(&self, diagnostics: &Diagnostics) -> bool {
        Self::increment(self.metric_id(|ids| ids.tx_total), diagnostics, "transaction metric")
    }

    /// Increments the phase and rule interruption counter.
    pub(crate) fn interruption(metrics: &Self, phase: &'static str, rule_id: i32, diagnostics: &Diagnostics) -> bool {
        let key = (phase.to_owned(), rule_id);
        #[cfg(target_arch = "wasm32")]
        let id = {
            // Do not hold the id lock across the define hostcall.
            let cached = metrics
                .ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .interruptions
                .get(&key)
                .copied();
            if let Some(id) = cached {
                Some(id)
            } else {
                let name = interruption_metric_name(phase, rule_id, &metrics.labels);
                if let Ok(id) = hostcalls::define_metric(MetricType::Counter, &name) {
                    metrics
                        .ids
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .interruptions
                        .insert(key, id);
                    Some(id)
                } else {
                    diagnostics.hostcall_failure("interruption metric definition");
                    None
                }
            }
        };
        #[cfg(not(target_arch = "wasm32"))]
        let id = {
            drop((metrics, key));
            None
        };
        Self::increment(id, diagnostics, "interruption metric")
    }

    /// Increments terminal error and incomplete-inspection counters as needed.
    pub(crate) fn terminal(&self, inspection_complete: bool, is_error: bool, diagnostics: &Diagnostics) -> bool {
        let mut success = true;
        if is_error {
            success &= Self::increment(self.metric_id(|ids| ids.errors_total), diagnostics, "error metric");
        }
        if !inspection_complete {
            success &= Self::increment(
                self.metric_id(|ids| ids.incomplete_total),
                diagnostics,
                "incomplete inspection metric",
            );
        }
        success
    }

    /// Increments the telemetry-failure counter.
    pub(crate) fn telemetry_failure(&self, diagnostics: &Diagnostics) -> bool {
        Self::increment(
            self.metric_id(|ids| ids.telemetry_failures_total),
            diagnostics,
            "telemetry failure metric",
        )
    }

    /// Adjusts the active-stream gauge.
    pub(crate) fn active_stream_delta(&self, delta: i64, diagnostics: &Diagnostics) -> bool {
        Self::adjust(
            self.metric_id(|ids| ids.active_streams),
            delta,
            diagnostics,
            "active stream gauge",
        )
    }

    /// Adjusts the retained-body-byte gauge.
    pub(crate) fn retained_body_delta(&self, delta: i64, diagnostics: &Diagnostics) -> bool {
        Self::adjust(
            self.metric_id(|ids| ids.retained_body_bytes),
            delta,
            diagnostics,
            "retained body gauge",
        )
    }

    /// Reads one metric ID while holding the ID map lock.
    fn metric_id(&self, get: impl FnOnce(&MetricIds) -> Option<u32>) -> Option<u32> {
        let ids = self.ids.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        get(&ids)
    }

    /// Adds one to a metric when its host ID is available.
    fn increment(id: Option<u32>, diagnostics: &Diagnostics, operation: &'static str) -> bool {
        Self::adjust(id, 1, diagnostics, operation)
    }

    /// Applies a signed metric delta and reports hostcall failures.
    fn adjust(id: Option<u32>, delta: i64, diagnostics: &Diagnostics, operation: &'static str) -> bool {
        #[cfg(target_arch = "wasm32")]
        {
            let Some(id) = id else {
                return false;
            };
            if hostcalls::increment_metric(id, delta).is_err() {
                diagnostics.hostcall_failure(operation);
                return false;
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (id, delta, diagnostics, operation);
        }
        true
    }
}

/// One of the four legacy interruption phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InterruptionPhase {
    /// Request headers are being inspected.
    RequestHeaders,
    /// Request body is being inspected.
    RequestBody,
    /// Response headers are being inspected.
    ResponseHeaders,
    /// Response body is being inspected.
    ResponseBody,
}

impl InterruptionPhase {
    /// Returns the legacy filter-state value for this phase.
    fn state(self) -> &'static str {
        match self {
            Self::RequestHeaders => "http_request_headers",
            Self::RequestBody => "http_request_body",
            Self::ResponseHeaders => "http_response_headers",
            Self::ResponseBody => "http_response_body",
        }
    }

    /// Returns the legacy metric tag for this phase.
    fn metric(self) -> &'static str {
        match self {
            Self::RequestHeaders => "http_request_headers_identifier",
            Self::RequestBody => "http_request_body_identifier",
            Self::ResponseHeaders => "http_response_headers_identifier",
            Self::ResponseBody => "http_response_body_identifier",
        }
    }
}

/// Publishes the PR #20 interruption properties before local replies or response rewriting.
#[expect(
    clippy::too_many_arguments,
    reason = "The pinned interruption callback needs its transaction, phase, metric, and diagnostics values explicitly."
)]
pub(crate) fn interruption(
    enabled: bool,
    transaction: &Transaction,
    interruption: &Interruption,
    phase: InterruptionPhase,
    metrics: &Metrics,
    diagnostics: &Diagnostics,
) -> bool {
    let mut failed = !Metrics::interruption(metrics, phase.metric(), interruption.rule_id, diagnostics);
    if !enabled {
        return failed;
    }

    let matched = transaction
        .matched_rules()
        .iter()
        .find(|matched| matched.rule_id() == interruption.rule_id);
    let mut fields = vec![
        ("event", "coraza_waf_blocked_request".to_owned()),
        ("rule_id", interruption.rule_id.to_string()),
        ("phase", phase.state().to_owned()),
        ("action", interruption.action.clone()),
        (
            "status",
            if interruption.status == 0 {
                403
            } else {
                interruption.status
            }
            .to_string(),
        ),
    ];
    if let Some(matched) = matched {
        if let Some(severity) = matched.severity() {
            fields.push(("severity", severity.as_str().to_owned()));
        }
        fields.push(("category", category(matched.tags())));
        if !matched.client_ip.is_empty() {
            fields.push(("client_ip", matched.client_ip.clone()));
        }
    }
    for (field, value) in fields {
        if value.is_empty() {
            continue;
        }
        let path = format!("io.coraza.waf.{field}");
        if hostcalls::set_property(vec![path.as_str()], Some(value.as_bytes())).is_err() {
            failed = true;
            diagnostics.hostcall_failure("filter state property");
        }
    }
    if failed {
        let _ = metrics.telemetry_failure(diagnostics);
    }
    failed
}

/// Additive health fields with only bounded values and closed outcome strings.
#[expect(
    clippy::struct_excessive_bools,
    reason = "These fields mirror the approved v1 health property schema and stay independently observable."
)]
#[derive(Clone, Copy)]
pub(crate) struct HealthState<'a> {
    /// Whether all configured request and response inspection completed.
    pub(crate) inspection_complete: bool,
    /// Closed reason for inspection completion or bypass.
    pub(crate) inspection_reason: &'a str,
    /// Successful policy generation assigned to the stream.
    pub(crate) generation: u64,
    /// Whether request body inspection reached its cap.
    pub(crate) request_body_truncated: bool,
    /// Whether response body inspection reached its cap.
    pub(crate) response_body_truncated: bool,
    /// Closed terminal result for the stream.
    pub(crate) terminal_outcome: &'a str,
    /// Whether any telemetry publication failed for the stream.
    pub(crate) telemetry_publish_failed: bool,
}

/// Publishes the additive v1 fields; failures are counted without affecting enforcement.
pub(crate) fn health(enabled: bool, state: HealthState<'_>, metrics: &Metrics, diagnostics: &Diagnostics) -> bool {
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
            diagnostics.hostcall_failure("health state property");
        }
    }
    if publish_property("io.coraza.waf.v1", "telemetry_publish_failed", &failed.to_string()).is_err() {
        failed = true;
        diagnostics.hostcall_failure("telemetry failure property");
    }
    if failed && !state.telemetry_publish_failed {
        let _ = metrics.telemetry_failure(diagnostics);
    }
    failed
}

/// Sets one filter-state property under a fixed namespace.
fn publish_property(prefix: &str, field: &str, value: &str) -> Result<(), proxy_wasm::types::Status> {
    let path = format!("{prefix}.{field}");
    hostcalls::set_property(vec![path.as_str()], Some(value.as_bytes()))
}

/// Emits Coraza's existing bounded and sanitized rule error log line.
pub(crate) fn error_log(matched: &MatchedRule, metrics: &Metrics, diagnostics: &Diagnostics) {
    let message = bounded(&matched.error_log(), MAX_ERROR_LOG_BYTES);
    if hostcalls::log(LogLevel::Warn, &message).is_err() {
        let _ = metrics.telemetry_failure(diagnostics);
        diagnostics.hostcall_failure("rule error log");
    }
}

/// Emits one selected Coraza audit entry using configured parts and format.
pub(crate) fn audit_log(entry: &AuditLog, format: AuditLogFormat, metrics: &Metrics, diagnostics: &Diagnostics) {
    let (formatted, truncated) = entry.format_bounded(format, MAX_AUDIT_LOG_BYTES);
    if formatted.is_empty() {
        return;
    }
    let message = sanitize_audit(&formatted, MAX_AUDIT_LOG_BYTES, truncated);
    if hostcalls::log(LogLevel::Critical, &message).is_err() {
        let _ = metrics.telemetry_failure(diagnostics);
        diagnostics.hostcall_failure("audit log");
    }
}

/// Escapes audit controls while retaining a bounded prefix and truncation marker.
fn sanitize_audit(input: &str, limit: usize, input_truncated: bool) -> String {
    let sanitized_len = input.chars().fold(0_usize, |len, character| {
        len.saturating_add(sanitized_char_len(character))
    });
    let truncated = input_truncated || sanitized_len > limit;
    let content_limit = if truncated {
        limit.saturating_sub(TRUNCATION_MARKER.len())
    } else {
        limit
    };
    let marker_len = TRUNCATION_MARKER.len().min(limit);
    let mut sanitized = String::with_capacity(limit);
    let mut truncated_during_write = false;
    for character in input.chars() {
        let escaped_len = sanitized_char_len(character);
        if sanitized.len().saturating_add(escaped_len) > content_limit {
            truncated_during_write = true;
            break;
        }
        if character == '\n' {
            sanitized.push(character);
        } else if character.is_control() {
            write!(sanitized, "\\u{{{:x}}}", character as u32).unwrap_or(());
        } else {
            sanitized.push(character);
        }
    }
    if truncated || truncated_during_write {
        sanitized.push_str(TRUNCATION_MARKER.get(..marker_len).unwrap_or_default());
    }
    sanitized
}

/// Returns the escaped byte length for one audit character.
fn sanitized_char_len(character: char) -> usize {
    if character.is_control() && character != '\n' {
        let value = character as u32;
        let digits = if value <= 0xF {
            1
        } else if value <= 0xFF {
            2
        } else if value <= 0xFFF {
            3
        } else if value <= 0xFFFF {
            4
        } else if value <= 0xFFFFF {
            5
        } else {
            6
        };
        4 + digits
    } else {
        character.len_utf8()
    }
}

/// Returns a UTF-8-safe, bounded prefix with the truncation marker when needed.
fn bounded(input: &str, limit: usize) -> String {
    if input.len() <= limit {
        return input.to_owned();
    }
    let end = utf8_boundary(input, limit.saturating_sub(TRUNCATION_MARKER.len()));
    let mut output = input.get(..end).unwrap_or_default().to_owned();
    output.push_str(TRUNCATION_MARKER);
    output
}

/// Finds the greatest character boundary at or below the byte limit.
fn utf8_boundary(input: &str, max: usize) -> usize {
    (0..=max.min(input.len()))
        .rev()
        .find(|index| input.is_char_boundary(*index))
        .unwrap_or(0)
}

/// Derives a bounded category slug from the first recognized attack tag.
fn category(tags: &[String]) -> String {
    for tag in tags {
        let Some(suffix) = tag.strip_prefix("attack-") else {
            continue;
        };
        let candidate = suffix.to_ascii_lowercase();
        let bytes = candidate.as_bytes();
        if (1..=63).contains(&bytes.len())
            && bytes.first().is_some_and(u8::is_ascii_lowercase)
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return candidate;
        }
    }
    "other".to_owned()
}

/// Keep the metric FQN used by the pinned connector; Envoy extracts the tags from its suffix.
#[cfg(any(target_arch = "wasm32", test))]
fn interruption_metric_name(phase: &str, rule_id: i32, labels: &[(String, String)]) -> String {
    let mut name = format!("waf_filter.tx.interruptions_ruleid={rule_id}_phase={phase}");
    for (key, value) in labels {
        write!(name, "_{key}={value}").unwrap_or(());
    }
    name
}

#[cfg(test)]
mod tests {
    use super::{
        bounded, category, interruption_metric_name, sanitize_audit, InterruptionPhase, MAX_AUDIT_LOG_BYTES,
        MAX_ERROR_LOG_BYTES, TRUNCATION_MARKER,
    };

    #[test]
    fn category_uses_the_first_valid_case_sensitive_attack_tag() {
        let tags = [
            "Attack-sqli".to_owned(),
            "attack-".to_owned(),
            "attack-1st".to_owned(),
            "attack-sqli".to_owned(),
            "attack-xss".to_owned(),
        ];
        assert_eq!(category(&tags), "sqli");
        assert_eq!(category(&["attack-SQLi".to_owned()]), "sqli");
    }

    #[test]
    fn category_rejects_empty_non_ascii_and_overlong_suffixes() {
        let non_ascii = format!("attack-{}", "é");
        let too_long = format!("attack-{}", "a".repeat(64));
        for tag in ["Attack-sqli", "attack-", "attack-1st", &non_ascii, &too_long] {
            assert_eq!(category(&[tag.to_owned()]), "other", "tag={tag:?}");
        }
        assert_eq!(category(&[format!("attack-{}", "a".repeat(63))]), "a".repeat(63));
    }

    #[test]
    fn legacy_interruption_metric_fqn_preserves_upstream_separator_and_tags() {
        let labels = vec![("suite".to_owned(), "contract".to_owned())];
        assert_eq!(
            interruption_metric_name("http_request_headers_identifier", 1042, &labels),
            "waf_filter.tx.interruptions_ruleid=1042_phase=http_request_headers_identifier_suite=contract"
        );
        assert_eq!(
            interruption_metric_name("http_response_body_identifier", -2, &[]),
            "waf_filter.tx.interruptions_ruleid=-2_phase=http_response_body_identifier"
        );
    }

    #[test]
    fn interruption_phase_values_keep_state_and_stat_tag_semantics_distinct() {
        assert_eq!(InterruptionPhase::RequestHeaders.state(), "http_request_headers");
        assert_eq!(
            InterruptionPhase::RequestHeaders.metric(),
            "http_request_headers_identifier"
        );
        assert_eq!(InterruptionPhase::RequestBody.state(), "http_request_body");
        assert_eq!(InterruptionPhase::RequestBody.metric(), "http_request_body_identifier");
        assert_eq!(InterruptionPhase::ResponseHeaders.state(), "http_response_headers");
        assert_eq!(
            InterruptionPhase::ResponseHeaders.metric(),
            "http_response_headers_identifier"
        );
        assert_eq!(InterruptionPhase::ResponseBody.state(), "http_response_body");
        assert_eq!(
            InterruptionPhase::ResponseBody.metric(),
            "http_response_body_identifier"
        );
    }

    #[test]
    fn proxy_log_serialization_is_bounded_and_keeps_utf8_boundaries() {
        let input = format!("{}é", "x".repeat(MAX_AUDIT_LOG_BYTES));
        let output = bounded(&input, MAX_AUDIT_LOG_BYTES);
        assert!(output.len() <= MAX_AUDIT_LOG_BYTES);
        assert!(output.ends_with(TRUNCATION_MARKER));
        assert!(std::str::from_utf8(output.as_bytes()).is_ok());

        let error = bounded(&"x".repeat(MAX_ERROR_LOG_BYTES + 1), MAX_ERROR_LOG_BYTES);
        assert_eq!(error.len(), MAX_ERROR_LOG_BYTES);
        assert!(error.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn audit_log_sanitizing_is_bounded_and_escapes_controls_except_section_newlines() {
        assert_eq!(
            sanitize_audit("header\nbody\u{0007}", MAX_AUDIT_LOG_BYTES, false),
            "header\nbody\\u{7}"
        );
        assert_eq!(
            sanitize_audit("header", MAX_AUDIT_LOG_BYTES, true),
            format!("header{TRUNCATION_MARKER}")
        );
        let control_heavy = sanitize_audit(&"\u{0007}".repeat(MAX_AUDIT_LOG_BYTES * 10), MAX_AUDIT_LOG_BYTES, false);
        assert!(control_heavy.len() <= MAX_AUDIT_LOG_BYTES);
        assert!(control_heavy.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn audit_truncation_does_not_split_a_multibyte_character_at_the_cutoff() {
        let content_limit = MAX_AUDIT_LOG_BYTES - TRUNCATION_MARKER.len();
        let input = format!("{}é{}", "x".repeat(content_limit - 1), "y".repeat(MAX_AUDIT_LOG_BYTES));
        let output = sanitize_audit(&input, MAX_AUDIT_LOG_BYTES, false);
        assert!(output.len() <= MAX_AUDIT_LOG_BYTES);
        assert!(output.ends_with(TRUNCATION_MARKER));
        assert!(!output.contains('é'));
        assert!(std::str::from_utf8(output.as_bytes()).is_ok());
    }
}
