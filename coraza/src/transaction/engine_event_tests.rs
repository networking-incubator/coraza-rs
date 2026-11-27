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

//! Engine-stop regressions that need the body-buffer failure seam.

#![expect(
    clippy::unwrap_used,
    reason = "tests use fixed rules and injected body-buffer failures"
)]

use std::sync::Arc;

use super::{
    MAX_ENGINE_EVENT_DETAILS, RuleGroup, Transaction, TransactionPool,
    body_buffer::{BufferFailure, inject_failure},
};
use crate::{
    config::WafConfig,
    seclang::Parser,
    types::{AuditEngineStatus, AuditLogFormat, BodyLimitAction, RuleEngineStatus, parse_audit_log_parts},
    waf::Waf,
};

fn assert_engine_event(tx: &Transaction, state: &str) {
    let tag = format!("coraza-rs/engine/{state}");
    assert_eq!(tx.engine_events().len(), 1, "{state}");
    assert_eq!(tx.engine_events().first().unwrap().rule_id(), 0, "{state}");
    assert!(tx.engine_events().first().unwrap().tags().contains(&tag), "{state}");
    assert!(
        tx.matched_rules().iter().all(|matched| matched.rule_id() != 0),
        "engine events stay outside matched rules"
    );
}

#[test]
fn pooled_transaction_does_not_reuse_engine_events() {
    let config = Arc::new(WafConfig {
        request_body_access: true,
        request_body_limit: 4,
        request_body_in_memory_limit: 4,
        request_body_limit_action: BodyLimitAction::Reject,
        audit_engine: AuditEngineStatus::Off,
        ..WafConfig::default()
    });
    let rules = Arc::new(RuleGroup::new());
    let pool = Arc::new(TransactionPool::new());
    let mut stopped = Transaction::with_pool(
        Arc::clone(&config),
        Arc::clone(&rules),
        "pooled-engine-event",
        Arc::clone(&pool),
    );
    stopped.process_request_headers();
    assert_eq!(
        stopped
            .process_request_body(b"1234")
            .map(|interruption| (interruption.rule_id, interruption.status)),
        Some((0, 413))
    );
    assert_eq!(stopped.engine_events().len(), 1);

    drop(stopped);
    assert_eq!(pool.len(), 1);
    let reused = Transaction::with_pool(config, rules, "fresh-engine-event", Arc::clone(&pool));
    assert_eq!(pool.len(), 0);
    assert!(reused.engine_events().is_empty());
    assert!(reused.matched_rules().is_empty());
    assert!(reused.interruption().is_none());
}

#[test]
fn pooled_transaction_resets_a_bounded_engine_event_summary() {
    const DETAIL_LIMIT: usize = MAX_ENGINE_EVENT_DETAILS;
    const EXTRA_EVENTS: usize = 5;
    let config = Arc::new(WafConfig {
        rule_engine: RuleEngineStatus::DetectionOnly,
        audit_engine: AuditEngineStatus::Off,
        ..WafConfig::default()
    });
    let rules = Arc::new(RuleGroup::new());
    let pool = Arc::new(TransactionPool::new());
    let mut stopped = Transaction::with_pool(
        Arc::clone(&config),
        Arc::clone(&rules),
        "pooled-engine-summary",
        Arc::clone(&pool),
    );

    for _ in 0..DETAIL_LIMIT + EXTRA_EVENTS {
        stopped.engine_stop(
            901,
            "OperatorNotInspected",
            500,
            "host operator refused to inspect input",
        );
    }
    assert_eq!(stopped.engine_events().len(), DETAIL_LIMIT + 1);
    assert!(
        stopped
            .engine_events()
            .last()
            .unwrap()
            .message()
            .contains("5 additional engine stop events"),
        "the final event summarizes the excess"
    );
    assert_eq!(
        stopped
            .would_be_interruption()
            .map(|value| (value.rule_id, value.status, value.data.as_str())),
        Some((901, 500, "host operator refused to inspect input")),
        "capping evidence does not change the first would-be interruption"
    );

    drop(stopped);
    assert_eq!(pool.len(), 1);
    let mut reused = Transaction::with_pool(config, rules, "fresh-engine-summary", Arc::clone(&pool));
    assert_eq!(pool.len(), 0);
    assert!(reused.engine_events().is_empty());
    assert!(reused.would_be_interruption().is_none());

    for _ in 0..=DETAIL_LIMIT {
        reused.engine_stop(
            902,
            "OperatorNotInspected",
            500,
            "host operator refused to inspect input",
        );
    }
    assert!(
        reused
            .engine_events()
            .last()
            .unwrap()
            .message()
            .contains("1 additional engine stop event"),
        "the pooled overflow count starts fresh"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "Checks overflow callback, typed and serialized markers, and bounded output together."
)]
fn an_enforcing_engine_stop_after_the_detail_cap_is_named_only_by_the_omission_summary() {
    use std::sync::Mutex;

    use crate::audit_log::ErrorLog;

    const SUMMARY_TAG: &str = "coraza-rs/engine/EventsOmitted";
    const ENFORCED_OMITTED_TAG: &str = "coraza-rs/engine/EnforcedStopOmitted";
    let logged = Arc::new(Mutex::new(Vec::new()));
    let callback_log = Arc::clone(&logged);
    let config = Arc::new(WafConfig {
        rule_engine: RuleEngineStatus::DetectionOnly,
        audit_engine: AuditEngineStatus::On,
        audit_log_parts: parse_audit_log_parts("AKZ").unwrap(),
        ..WafConfig::default()
    });
    let mut tx = Transaction::with_pool(
        config,
        Arc::new(RuleGroup::new()),
        "overflowed-enforcing-engine-stop",
        Arc::new(TransactionPool::new()),
    );
    tx.error_log = Some(ErrorLog::new(move |event| {
        callback_log
            .lock()
            .unwrap()
            .push((event.message().to_owned(), event.error_log(), event.tags().to_vec()));
    }));
    tx.process_uri(format!("/{}", "p".repeat(16 * 1024)), "POST", "HTTP/1.1");

    for _ in 0..MAX_ENGINE_EVENT_DETAILS {
        tx.engine_stop(0, "RequestBodyLimit", 413, "");
    }
    tx.rule_engine = RuleEngineStatus::On;
    tx.engine_stop(0, "ResponseBodyLimit", 500, "");

    assert_eq!(
        tx.interruption().map(|value| (value.rule_id, value.status)),
        Some((0, 500)),
        "the post-cap response stop is enforced"
    );
    assert_eq!(
        tx.would_be_interruption().map(|value| (value.rule_id, value.status)),
        Some((0, 413)),
        "the earlier DetectionOnly would-be stop remains first"
    );
    assert_eq!(tx.engine_events().len(), MAX_ENGINE_EVENT_DETAILS + 1);
    let summary_message = tx.engine_events().last().unwrap().message();
    assert!(
        summary_message.contains("1 additional engine stop event summarized after the first 16 individual events")
            && summary_message.contains("the enforced stop is among omitted details"),
        "the bounded transaction record preserves its exact count and omitted enforcing outcome: {summary_message}"
    );

    let logged = logged.lock().unwrap();
    assert_eq!(
        logged.len(),
        MAX_ENGINE_EVENT_DETAILS + 1,
        "one callback at first overflow"
    );
    let callback_summary = logged.last().unwrap();
    assert!(
        callback_summary
            .0
            .contains("the enforced stop is among omitted details")
            && callback_summary.0.contains("final count may be higher"),
        "the first-overflow callback names the enforced omission without claiming a final count: {}",
        callback_summary.0
    );
    assert!(
        !callback_summary
            .0
            .contains("1 additional engine stop event summarized after the first 16"),
        "the callback is a snapshot, not the later exact summary"
    );
    drop(logged);

    let audit = tx.audit_log();
    assert_eq!(audit.messages.len(), MAX_ENGINE_EVENT_DETAILS + 1);
    assert_eq!(
        audit.messages.last().unwrap().data.tags,
        [SUMMARY_TAG, ENFORCED_OMITTED_TAG],
        "the typed K record marks the omitted enforcing stop"
    );
    let full_document: serde_json::Value = serde_json::from_str(&audit.format(AuditLogFormat::Json)).unwrap();
    assert_eq!(
        full_document
            .pointer("/messages/16/data/tags")
            .and_then(serde_json::Value::as_array)
            .unwrap(),
        &[
            serde_json::Value::String(SUMMARY_TAG.to_owned()),
            serde_json::Value::String(ENFORCED_OMITTED_TAG.to_owned())
        ],
        "serialized K data exposes the omitted-enforcement marker"
    );
    let (formatted, truncated) = audit.format_bounded(AuditLogFormat::Json, 1024);
    assert!(truncated, "the long URI and event list force reduction");
    assert!(formatted.len() <= 1024);
    let document: serde_json::Value = serde_json::from_str(&formatted).unwrap();
    let messages = document.get("messages").and_then(serde_json::Value::as_array).unwrap();
    assert!(
        messages.iter().any(|message| {
            message.pointer("/data/id").and_then(serde_json::Value::as_i64) == Some(0)
                && message
                    .pointer("/data/msg")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|text| {
                        text.contains("1 additional engine stop event")
                            && text.contains("enforced stop is among omitted details")
                    })
        }),
        "the retained summary truthfully says the enforcing detail was omitted: {formatted}"
    );
    assert!(
        document
            .pointer("/messages")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|messages| {
                messages.iter().any(|message| {
                    message
                        .pointer("/data/tags")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some(ENFORCED_OMITTED_TAG)))
                })
            }),
        "bounded serialized K keeps the enforcement marker when the summary is retained: {formatted}"
    );
    assert!(
        !formatted.contains("ResponseBodyLimit"),
        "the omitted response stop is not invented as an individually retained cause: {formatted}"
    );
}

#[test]
fn a_nonzero_source_rule_does_not_displace_an_enforcing_omission_summary() {
    const SOURCE_RULE_ID: i32 = 901;
    const ENFORCED_OMITTED_TAG: &str = "coraza-rs/engine/EnforcedStopOmitted";

    let mut parser = Parser::new();
    parser.config_mut().audit_log_parts = parse_audit_log_parts("AKZ").unwrap();
    parser
        .from_string(&format!(
            "SecRuleEngine DetectionOnly\n\
             SecAction \"id:{SOURCE_RULE_ID},phase:1,pass,log,auditlog,msg:'source rule'\""
        ))
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("source-rule-and-omitted-stop");
    tx.process_uri(format!("/{}", "p".repeat(16 * 1024)), "POST", "HTTP/1.1");
    assert!(tx.process_request_headers().is_none());
    assert_eq!(
        tx.matched_rules()
            .iter()
            .map(crate::audit_log::MatchedRule::rule_id)
            .collect::<Vec<_>>(),
        [SOURCE_RULE_ID],
        "the source rule is audited before the engine events"
    );

    for _ in 0..MAX_ENGINE_EVENT_DETAILS {
        tx.engine_stop(SOURCE_RULE_ID, "RequestBodyLimit", 413, "");
    }
    tx.rule_engine = RuleEngineStatus::On;
    tx.engine_stop(SOURCE_RULE_ID, "ResponseBodyLimit", 500, "");
    assert_eq!(
        tx.interruption()
            .map(|interruption| (interruption.rule_id, interruption.status)),
        Some((SOURCE_RULE_ID, 500))
    );

    let audit = tx.audit_log();
    assert_eq!(audit.transaction.interruption_rule_id, Some(SOURCE_RULE_ID));
    assert_eq!(audit.messages.first().unwrap().rule_id, SOURCE_RULE_ID);
    assert_eq!(
        audit.messages.last().unwrap().data.tags,
        ["coraza-rs/engine/EventsOmitted", ENFORCED_OMITTED_TAG]
    );

    let (tight, truncated) = audit.format_bounded(AuditLogFormat::Json, 768);
    assert!(truncated, "the long URI forces bounded reduction");
    assert!(tight.len() <= 768);
    let document: serde_json::Value = serde_json::from_str(&tight).unwrap();
    let messages = document
        .pointer("/messages")
        .and_then(serde_json::Value::as_array)
        .unwrap();
    assert_eq!(messages.len(), 1, "{tight}");
    assert_eq!(
        messages
            .first()
            .unwrap()
            .pointer("/data/id")
            .and_then(serde_json::Value::as_i64),
        Some(0),
        "when one message fits, the omitted enforcing stop outranks its matching source ID"
    );
    assert_eq!(
        messages
            .first()
            .unwrap()
            .pointer("/data/raw")
            .and_then(serde_json::Value::as_str),
        Some("coraza-rs/engine/EventsOmitted"),
        "the retained message is the omission summary: {tight}"
    );

    let (roomy, truncated) = audit.format_bounded(AuditLogFormat::Json, 32 * 1024);
    assert!(!truncated, "the larger cap fits the source rule and all summaries");
    let document: serde_json::Value = serde_json::from_str(&roomy).unwrap();
    assert_eq!(
        document
            .pointer("/messages")
            .and_then(serde_json::Value::as_array)
            .unwrap()
            .iter()
            .map(|message| message.pointer("/data/id").and_then(serde_json::Value::as_i64))
            .collect::<Vec<_>>(),
        std::iter::once(Some(i64::from(SOURCE_RULE_ID)))
            .chain(std::iter::repeat_n(Some(0), MAX_ENGINE_EVENT_DETAILS + 1))
            .collect::<Vec<_>>(),
        "the extra space restores all messages in chronological order"
    );
}

#[test]
fn sec_rule_engine_off_does_not_record_or_log_engine_events() {
    use std::sync::Mutex;

    let logged = Arc::new(Mutex::new(Vec::new()));
    let callback_log = Arc::clone(&logged);
    let mut parser = Parser::new();
    parser.on_error_log(move |event| callback_log.lock().unwrap().push(event.error_log()));
    parser.from_string("SecRuleEngine Off").unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("engine-event-off");

    tx.engine_stop(
        901,
        "OperatorNotInspected",
        500,
        "host operator refused to inspect input",
    );

    assert!(tx.engine_events().is_empty());
    assert!(logged.lock().unwrap().is_empty());
    assert!(tx.interruption().is_none());
    assert!(tx.would_be_interruption().is_none());
}

#[test]
fn bounded_engine_fallback_preserves_a_nonzero_interruption_rule_id() {
    const INTERRUPTION_RULE_ID: i32 = 901;
    const STATE: &str = "coraza-rs/engine/OperatorNotInspected";
    const MESSAGE: &str = "host operator refused to inspect input";
    const OUTPUT_LIMIT: usize = 4096;

    let config = Arc::new(WafConfig {
        rule_engine: RuleEngineStatus::On,
        audit_engine: AuditEngineStatus::On,
        audit_log_parts: parse_audit_log_parts("AHKZ").unwrap(),
        ..WafConfig::default()
    });
    let mut tx = Transaction::with_pool(
        config,
        Arc::new(RuleGroup::new()),
        "nonzero-engine-interruption",
        Arc::new(TransactionPool::new()),
    );
    tx.engine_stop(INTERRUPTION_RULE_ID, "OperatorNotInspected", 500, MESSAGE);

    assert!(tx.matched_rules().is_empty(), "no source rule audit message exists");
    assert_eq!(
        tx.interruption().map(|interruption| interruption.rule_id),
        Some(INTERRUPTION_RULE_ID),
        "the engine stop retains the host-operator source rule ID"
    );
    let mut audit = tx.audit_log();
    assert_eq!(
        audit.transaction.interruption_rule_id,
        Some(INTERRUPTION_RULE_ID),
        "the public audit field keeps the source rule ID"
    );
    assert_eq!(audit.messages.len(), 1, "only the synthetic event is audited");
    assert_eq!(
        audit.messages.first().map(|message| message.rule_id),
        Some(0),
        "the synthetic event keeps ID zero"
    );
    assert!(
        audit
            .messages
            .iter()
            .all(|message| message.rule_id != INTERRUPTION_RULE_ID),
        "the source rule has no matching audit message"
    );
    let producer = audit.transaction.producer.as_mut().unwrap();
    producer.connector = "c".repeat(16 * 1024);
    producer.rulesets = vec!["r".repeat(16 * 1024)];

    for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
        let (formatted, truncated) = audit.format_bounded(format, OUTPUT_LIMIT);
        assert!(truncated, "{format:?}: producer forces reduction");
        assert!(formatted.len() <= OUTPUT_LIMIT, "{format:?}: {} bytes", formatted.len());
        let document: serde_json::Value = serde_json::from_str(&formatted).unwrap();
        let identity = match format {
            AuditLogFormat::Json => document
                .pointer("/messages/0/error_message")
                .and_then(serde_json::Value::as_str),
            AuditLogFormat::JsonLegacy => document
                .pointer("/audit_data/messages/0")
                .and_then(serde_json::Value::as_str),
            AuditLogFormat::Ocsf => document.get("message").and_then(serde_json::Value::as_str),
            AuditLogFormat::Native => unreachable!(),
        };
        assert!(
            identity.is_some_and(|identity| {
                identity.contains(STATE)
                    && identity.contains(MESSAGE)
                    && identity.contains("[id \"0\"]")
                    && !identity.contains("[id \"901\"]")
            }),
            "{format:?}: the event identifies its own state, not the interrupted rule: {formatted}"
        );
        assert_eq!(
            audit.transaction.interruption_rule_id,
            Some(INTERRUPTION_RULE_ID),
            "{format:?}: formatting must not rewrite the public interruption ID"
        );
    }
}

#[test]
fn request_body_buffer_failures_emit_engine_events_in_both_modes() {
    for failure in [BufferFailure::Accept, BufferFailure::Replay] {
        for (engine, enforced) in [("On", true), ("DetectionOnly", false)] {
            let mut parser = Parser::new();
            parser
                .from_string(&format!(
                    "SecRuleEngine {engine}\n\
                     SecRequestBodyAccess On\n\
                     SecAction \"id:150,phase:1,ctl:requestBodyProcessor=JSON,pass\"\n\
                     SecAction \"id:151,phase:2,setvar:tx.request_body_phase=continued,deny,status:403\""
                ))
                .unwrap();
            let waf = parser.into_waf().unwrap();
            let mut tx = waf.new_transaction_with_id(format!("request-buffer-{engine}-{failure:?}"));
            tx.process_request_headers();
            inject_failure(failure);

            let interruption = tx.process_request_body(br#"{"a":1}"#);
            assert_eq!(
                tx.get_variable(crate::types::RuleVariable::InboundDataError, None)
                    .as_deref(),
                Some("1")
            );
            let state = match failure {
                BufferFailure::Accept => "RequestBodyBuffer",
                BufferFailure::Replay => "RequestBodyBufferRead",
                BufferFailure::Reset => "unexpected",
            };
            assert_engine_event(&tx, state);
            if enforced {
                assert_eq!(
                    interruption.map(|value| (value.rule_id, value.action, value.status, value.data)),
                    Some((0, "deny".to_owned(), 500, String::new()))
                );
                assert!(
                    tx.get_variable(crate::types::RuleVariable::TX, Some("request_body_phase"))
                        .is_none(),
                    "On mode stops before the phase-2 rule after {failure:?}"
                );
            } else {
                assert!(interruption.is_none());
                assert_eq!(
                    tx.would_be_interruption().map(|value| (
                        value.rule_id,
                        value.action.as_str(),
                        value.status,
                        value.data.as_str()
                    )),
                    Some((0, "deny", 500, "")),
                    "the first engine would-be interruption survives the later phase-2 403 after {failure:?}"
                );
                assert_eq!(
                    tx.get_variable(crate::types::RuleVariable::TX, Some("request_body_phase"))
                        .as_deref(),
                    Some("continued"),
                    "DetectionOnly continues to phase 2 after {failure:?}"
                );
            }
        }
    }
}

#[test]
fn response_body_buffer_failures_emit_engine_events_in_both_modes() {
    for failure in [BufferFailure::Accept, BufferFailure::Replay] {
        for (engine, enforced) in [("On", true), ("DetectionOnly", false)] {
            let mut parser = Parser::new();
            parser
                .from_string(&format!(
                    "SecRuleEngine {engine}\n\
                     SecResponseBodyAccess On\n\
                     SecResponseBodyMimeType text/plain\n\
                     SecAction \"id:152,phase:4,setvar:tx.response_body_phase=continued,deny,status:403\""
                ))
                .unwrap();
            let waf: Waf = parser.into_waf().unwrap();
            let mut tx = waf.new_transaction_with_id(format!("response-buffer-{engine}-{failure:?}"));
            tx.process_request_headers();
            tx.process_request_body(b"");
            tx.add_response_header("Content-Type", "text/plain");
            tx.process_response_headers(200, "HTTP/1.1");
            inject_failure(failure);

            let interruption = tx.process_response_body(b"response");
            assert_eq!(
                tx.get_variable(crate::types::RuleVariable::OutboundDataError, None)
                    .as_deref(),
                Some("1")
            );
            let state = match failure {
                BufferFailure::Accept => "ResponseBodyBuffer",
                BufferFailure::Replay => "ResponseBodyBufferRead",
                BufferFailure::Reset => "unexpected",
            };
            assert_engine_event(&tx, state);
            if enforced {
                assert_eq!(
                    interruption.map(|value| (value.rule_id, value.action, value.status, value.data)),
                    Some((0, "deny".to_owned(), 500, String::new()))
                );
                assert!(
                    tx.get_variable(crate::types::RuleVariable::TX, Some("response_body_phase"))
                        .is_none(),
                    "On mode stops before the phase-4 rule after {failure:?}"
                );
            } else {
                assert!(interruption.is_none());
                assert_eq!(
                    tx.would_be_interruption().map(|value| (
                        value.rule_id,
                        value.action.as_str(),
                        value.status,
                        value.data.as_str()
                    )),
                    Some((0, "deny", 500, "")),
                    "the first engine would-be interruption survives the later phase-4 403 after {failure:?}"
                );
                assert_eq!(
                    tx.get_variable(crate::types::RuleVariable::TX, Some("response_body_phase"))
                        .as_deref(),
                    Some("continued"),
                    "DetectionOnly continues to phase 4 after {failure:?}"
                );
            }
        }
    }
}
