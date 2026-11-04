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

//! Host-independent bounds and formatting for adapter diagnostics and state.

use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering},
};

use coraza::transaction::{Interruption, Transaction};

/// Maximum rule-error log message size in bytes.
pub const MAX_ERROR_LOG_BYTES: usize = 4096;

/// Maximum audit log message size in bytes.
pub const MAX_AUDIT_LOG_BYTES: usize = 16 * 1024;

/// Marker appended when a published log message was truncated.
pub const TRUNCATION_MARKER: &str = " [truncated]";

/// Counts telemetry publication failures for one compiled generation.
#[derive(Debug, Default)]
pub struct Diagnostics {
    /// Number of telemetry publication failures recorded so far.
    failures: AtomicU64,
}

impl Diagnostics {
    /// Records a failure and returns the resulting count.
    pub fn record_failure(&self) -> u64 {
        self.failures.fetch_add(1, Ordering::Relaxed).saturating_add(1)
    }

    /// Returns the number of failures recorded so far.
    pub fn failure_count(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }
}

/// One of the four legacy interruption phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptionPhase {
    /// Request headers are being inspected.
    RequestHeaders,
    /// Request body is being inspected.
    RequestBody,
    /// Response headers are being inspected.
    ResponseHeaders,
    /// Response body is being inspected.
    ResponseBody,
}

/// Builds the legacy interruption fields shared by the Envoy adapters.
pub fn interruption_fields(
    transaction: &Transaction,
    interruption: &Interruption,
    phase: InterruptionPhase,
) -> Vec<(&'static str, String)> {
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
    fields
}

/// Terminal or explicitly incomplete result retained for filter-state publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalOutcome {
    /// No configured policy matched; traffic continued uninspected.
    UnmatchedAuthority,
    /// The selected policy has `SecRuleEngine Off`.
    EngineOff,
    /// The request or response used an unsupported feature.
    Unsupported(&'static str),
    /// A WAF rule interrupted a request or response.
    Denied {
        /// Request/response phase that denied the message.
        phase: &'static str,
        /// Rule-selected response status.
        status: u16,
    },
    /// An incomplete body was rejected.
    Incomplete {
        /// Inspection boundary that could not be completed.
        phase: &'static str,
        /// Connector failure status.
        status: u16,
    },
    /// A host or policy body ceiling was reached.
    BodyTooLarge {
        /// Body boundary that exceeded its host ceiling.
        phase: &'static str,
        /// Connector status for the size failure.
        status: u16,
    },
    /// Coraza processed the configured prefix and allowed the request to continue.
    BodyPartiallyInspected {
        /// Body phase whose configured engine limit allowed a prefix.
        phase: &'static str,
    },
    /// The module-wide retained-body cap was exhausted.
    RetainedBodyBudgetExhausted {
        /// Body phase unable to reserve module-wide retained memory.
        phase: &'static str,
    },
    /// A callback sequence or host response made inspection impossible.
    InvalidLifecycle {
        /// Callback boundary whose ordering was invalid.
        phase: &'static str,
        /// Connector failure status.
        status: u16,
    },
    /// The request authority was invalid.
    InvalidAuthority {
        /// Request status for invalid authority.
        status: u16,
    },
    /// The stream ended before a complete response; the host did not report the cause.
    UpstreamFailureOrCancellation,
    /// The transaction reached a complete response.
    Completed,
}

impl TerminalOutcome {
    /// Closed inspection-reason value for compatibility filter state.
    pub fn inspection_reason(&self) -> &'static str {
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

    /// Closed terminal outcome value for compatibility filter state.
    pub fn terminal_name(&self) -> &'static str {
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

    /// Whether the outcome denotes an inspection or host error.
    pub fn is_error(&self) -> bool {
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

impl InterruptionPhase {
    /// Returns the legacy filter-state value for this phase.
    pub fn state(self) -> &'static str {
        match self {
            Self::RequestHeaders => "http_request_headers",
            Self::RequestBody => "http_request_body",
            Self::ResponseHeaders => "http_response_headers",
            Self::ResponseBody => "http_response_body",
        }
    }
}

/// Additive health fields with only bounded values and closed outcome strings.
#[expect(
    clippy::struct_excessive_bools,
    reason = "These fields mirror the approved v1 health property schema and stay independently observable."
)]
#[derive(Clone, Copy)]
pub struct HealthState<'a> {
    /// Whether all configured request and response inspection completed.
    pub inspection_complete: bool,
    /// Closed reason for inspection completion or bypass.
    pub inspection_reason: &'a str,
    /// Successful policy generation assigned to the stream.
    pub generation: u64,
    /// Whether request body inspection reached its cap.
    pub request_body_truncated: bool,
    /// Whether response body inspection reached its cap.
    pub response_body_truncated: bool,
    /// Closed terminal result for the stream.
    pub terminal_outcome: &'a str,
    /// Whether any telemetry publication failed for the stream.
    pub telemetry_publish_failed: bool,
}

/// Escapes audit controls while retaining a bounded prefix and truncation marker.
pub fn sanitize_audit(input: &str, limit: usize, input_truncated: bool) -> String {
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
pub fn sanitized_char_len(character: char) -> usize {
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
pub fn bounded(input: &str, limit: usize) -> String {
    if input.len() <= limit {
        return input.to_owned();
    }
    let end = utf8_boundary(input, limit.saturating_sub(TRUNCATION_MARKER.len()));
    let mut output = input.get(..end).unwrap_or_default().to_owned();
    output.push_str(TRUNCATION_MARKER);
    output
}

/// Finds the greatest character boundary at or below the byte limit.
pub fn utf8_boundary(input: &str, max: usize) -> usize {
    (0..=max.min(input.len()))
        .rev()
        .find(|index| input.is_char_boundary(*index))
        .unwrap_or(0)
}

/// Derives a bounded category slug from the first recognized attack tag.
pub fn category(tags: &[String]) -> String {
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
#[expect(clippy::expect_used, reason = "Formatting tests use a fixed default WAF config.")]
mod tests {
    use coraza::transaction::Interruption;

    use super::{
        Diagnostics, InterruptionPhase, MAX_AUDIT_LOG_BYTES, MAX_ERROR_LOG_BYTES, TRUNCATION_MARKER, bounded, category,
        interruption_fields, sanitize_audit,
    };

    #[test]
    fn interruption_fields_preserve_legacy_phase_and_default_status() {
        let transaction = coraza::Waf::new(coraza::config::WafConfig::default())
            .expect("fixed default WAF config should compile")
            .new_transaction();
        let interruption = Interruption {
            rule_id: 42,
            action: "deny".to_owned(),
            status: 0,
            data: String::new(),
        };
        let fields = interruption_fields(&transaction, &interruption, InterruptionPhase::ResponseBody);
        assert_eq!(
            fields.first().map(|(key, value)| (*key, value.as_str())),
            Some(("event", "coraza_waf_blocked_request"))
        );
        assert_eq!(
            fields.get(2).map(|(key, value)| (*key, value.as_str())),
            Some(("phase", "http_response_body"))
        );
        assert_eq!(
            fields.get(4).map(|(key, value)| (*key, value.as_str())),
            Some(("status", "403"))
        );
    }

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

    #[test]
    fn diagnostics_count_failures_with_shared_atomic_state() {
        let diagnostics = Diagnostics::default();
        assert_eq!(diagnostics.failure_count(), 0);
        assert_eq!(diagnostics.record_failure(), 1);
        assert_eq!(diagnostics.failure_count(), 1);
    }
}
