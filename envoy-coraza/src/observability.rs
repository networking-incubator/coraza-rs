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

use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering},
};

use coraza::{
    audit_log::{AuditLog, MatchedRule},
    transaction::{Interruption, Transaction},
    types::AuditLogFormat,
};
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
            diagnostics.hostcall_failure("health state property");
        }
    }
    if publish_property("io.coraza.waf.v1", "telemetry_publish_failed", &failed.to_string()).is_err() {
        failed = true;
        diagnostics.hostcall_failure("telemetry failure property");
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
        diagnostics.hostcall_failure("rule error log");
    }
}

/// Emits one selected Coraza audit entry using configured parts and format.
pub(crate) fn audit_log(entry: &AuditLog, format: AuditLogFormat, diagnostics: &Diagnostics) {
    let Some(message) = audit_message(entry, format) else {
        return;
    };
    if hostcalls::log(LogLevel::Critical, &message).is_err() {
        diagnostics.hostcall_failure("audit log");
    }
}

/// The bounded, sanitized log line for one audit entry, or `None` when there is nothing to log.
fn audit_message(entry: &AuditLog, format: AuditLogFormat) -> Option<String> {
    let (formatted, truncated) = entry.format_bounded(format, MAX_AUDIT_LOG_BYTES);
    if formatted.is_empty() {
        return None;
    }
    // The JSON formats come back whole and within the cap, with a `truncated` member when they were reduced; a
    // plain-text marker would make them invalid JSON, so only the native text gets one.
    Some(sanitize_audit(
        &formatted,
        MAX_AUDIT_LOG_BYTES,
        truncated && format == AuditLogFormat::Native,
    ))
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "audit tests use fixed fixtures")]
mod tests {
    use std::sync::{Arc, Mutex};

    use coraza::types::AuditLogFormat;

    use super::{
        audit_message, bounded, category, sanitize_audit, InterruptionPhase, MAX_AUDIT_LOG_BYTES, MAX_ERROR_LOG_BYTES,
        TRUNCATION_MARKER,
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
    fn interruption_phase_values_match_filter_state_contract() {
        assert_eq!(InterruptionPhase::RequestHeaders.state(), "http_request_headers");
        assert_eq!(InterruptionPhase::RequestBody.state(), "http_request_body");
        assert_eq!(InterruptionPhase::ResponseHeaders.state(), "http_response_headers");
        assert_eq!(InterruptionPhase::ResponseBody.state(), "http_response_body");
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

    /// The value at the path of object keys, if every step exists.
    fn at<'a>(document: &'a serde_json::Value, path: &[&str]) -> Option<&'a serde_json::Value> {
        path.iter().try_fold(document, |value, key| value.get(*key))
    }

    /// The rule ids of the messages under `path`, which hold their rule data directly or as a JSON string.
    fn rule_ids(document: &serde_json::Value, path: &[&str], nested: bool) -> Vec<i64> {
        at(document, path)
            .and_then(serde_json::Value::as_array)
            .unwrap()
            .iter()
            .map(|message| {
                let data = message.get("data").unwrap();
                let id = if nested {
                    let text: serde_json::Value = serde_json::from_str(data.as_str().unwrap()).unwrap();
                    text.get("id").and_then(serde_json::Value::as_i64)
                } else {
                    data.get("id").and_then(serde_json::Value::as_i64)
                };
                id.unwrap()
            })
            .collect()
    }

    /// A transaction that matches rule 1 and is denied by rule 949110, with `pad` bytes in its URI and a header.
    fn audit_entry(pad: usize) -> coraza::audit_log::AuditLog {
        let entries = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&entries);
        let mut parser = coraza::seclang::Parser::new();
        parser.on_audit_log(move |entry| sink.lock().unwrap().push(entry.clone()));
        parser
            .from_string(
                "SecRuleEngine On\nSecAuditEngine RelevantOnly\nSecAuditLogParts ABHKZ\n\
                 SecRule ARGS:q \"@contains attack\" \"id:1,phase:1,pass,log,auditlog,msg:'first rule'\"\n\
                 SecRule ARGS:q \"@contains attack\" \"id:949110,phase:1,deny,status:403,log,auditlog,msg:'blocking rule'\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction();
        tx.process_uri(format!("/?q=attack&pad={}", "A".repeat(pad)), "GET", "HTTP/1.1");
        tx.add_request_header("X-Pad", "B".repeat(pad).as_bytes());
        assert!(tx.process_request_headers().is_some(), "the blocking rule interrupts");
        tx.finish().unwrap();
        let entry = entries.lock().unwrap().pop().unwrap();
        entry
    }

    /// The three JSON audit formats.
    const JSON_FORMATS: [AuditLogFormat; 3] = [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf];

    #[test]
    fn oversized_json_audit_records_stay_valid_json_marked_truncated_and_keep_the_matched_rules() {
        for pad in [0_usize, 100, 8_000, 16_000, 64_000, 1 << 20] {
            let entry = audit_entry(pad);
            for format in JSON_FORMATS {
                let line = audit_message(&entry, format).unwrap();
                assert!(
                    line.len() <= MAX_AUDIT_LOG_BYTES,
                    "pad={pad} {format:?}: {} bytes",
                    line.len()
                );
                let document: serde_json::Value = serde_json::from_str(&line)
                    .unwrap_or_else(|error| unreachable!("pad={pad} {format:?} is not JSON: {error}"));

                let marker = if format == AuditLogFormat::Ocsf {
                    at(&document, &["unmapped", "truncated"])
                } else {
                    at(&document, &["truncated"])
                };
                assert_eq!(
                    marker == Some(&serde_json::Value::Bool(true)),
                    pad >= 8_000,
                    "pad={pad} {format:?}: the marker says whether it was reduced"
                );
                assert!(!line.contains(TRUNCATION_MARKER), "no plain-text marker inside JSON");

                // The interrupting rule outlives the padding in every format. The legacy format carries
                // only rule messages; the others carry the rule id as well.
                match format {
                    AuditLogFormat::Json => {
                        assert_eq!(rule_ids(&document, &["messages"], false), [1, 949_110], "pad={pad}");
                    },
                    AuditLogFormat::JsonLegacy => {
                        assert_eq!(
                            at(&document, &["audit_data", "messages"]),
                            Some(&serde_json::json!(["first rule", "blocking rule"])),
                            "pad={pad}"
                        );
                    },
                    _ => {
                        assert_eq!(rule_ids(&document, &["enrichments"], true), [1, 949_110], "pad={pad}");
                    },
                }
            }
        }
    }

    #[test]
    fn a_header_only_audit_trailer_keeps_the_interrupting_rule_id_in_the_error_message() {
        // Part `H` without `K` carries the rule only in its error log line.
        let entries = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&entries);
        let mut parser = coraza::seclang::Parser::new();
        parser.on_audit_log(move |entry| sink.lock().unwrap().push(entry.clone()));
        parser
            .from_string(
                "SecRuleEngine On\nSecAuditEngine RelevantOnly\nSecAuditLogParts ABHZ\n\
                 SecRule ARGS:q \"@contains attack\" \"id:949110,phase:1,deny,status:403,log,auditlog,msg:'blocking rule'\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction();
        tx.process_uri(format!("/?q=attack&pad={}", "A".repeat(64_000)), "GET", "HTTP/1.1");
        assert!(tx.process_request_headers().is_some());
        tx.finish().unwrap();
        let entry = entries.lock().unwrap().pop().unwrap();

        let line = audit_message(&entry, AuditLogFormat::Json).unwrap();
        assert!(line.len() <= MAX_AUDIT_LOG_BYTES);
        let document: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(at(&document, &["truncated"]), Some(&serde_json::Value::Bool(true)));
        assert!(line.contains("949110"), "the rule id survives in the error message");
    }

    #[test]
    fn oversized_json_audit_records_escape_every_control_character() {
        let mut entry = audit_entry(0);
        // DEL and a C1 control are raw in JSON; the line must carry them as escapes.
        "A\u{7f}B\u{85}\u{7}C\n"
            .repeat(4000)
            .clone_into(&mut entry.transaction.request.uri);
        for format in JSON_FORMATS {
            let line = audit_message(&entry, format).unwrap();
            assert!(line.len() <= MAX_AUDIT_LOG_BYTES, "{format:?}");
            assert!(serde_json::from_str::<serde_json::Value>(&line).is_ok(), "{format:?}");
            assert!(
                !line.chars().any(char::is_control),
                "{format:?} carries a raw control character"
            );
        }
    }

    #[test]
    fn a_record_that_fits_is_unchanged_and_unmarked() {
        let entry = audit_entry(10);
        for format in JSON_FORMATS {
            let line = audit_message(&entry, format).unwrap();
            let (formatted, truncated) = entry.format_bounded(format, MAX_AUDIT_LOG_BYTES);
            assert!(!truncated, "{format:?}");
            if format != AuditLogFormat::Ocsf {
                // OCSF stamps the time it was formatted at.
                assert_eq!(line, formatted);
            }
            assert!(!line.contains("truncated"), "{format:?}");
        }
    }

    #[test]
    fn many_oversized_messages_keep_the_first_and_last_rule() {
        let mut entry = audit_entry(0);
        let template = entry.messages.last().unwrap().clone();
        entry.messages = (0..400)
            .map(|index| {
                let mut message = template.clone();
                message.data.id = 1000 + index;
                message.data.raw = "R".repeat(2000);
                message.data.msg = format!("rule {index}");
                message.message = format!("rule {index}");
                message
            })
            .collect();
        for format in JSON_FORMATS {
            let line = audit_message(&entry, format).unwrap();
            assert!(line.len() <= MAX_AUDIT_LOG_BYTES, "{format:?}");
            assert!(serde_json::from_str::<serde_json::Value>(&line).is_ok(), "{format:?}");
            assert!(line.contains("rule 0"), "{format:?} keeps the first message");
            assert!(line.contains("rule 399"), "{format:?} keeps the last message");
        }
    }
}
