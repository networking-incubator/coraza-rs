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

//! Engine-stop logging and audit behavior at public transaction seams.

#![expect(
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "engine event tests use fixed policies, bounded fixtures, and a callback-panic regression"
)]

use std::sync::{Arc, Mutex};

use coraza::{
    audit_log::{AuditMessage, AuditMessageData, AuditMessageProvenance},
    config::WafConfig,
    seclang::Parser,
    transaction::Transaction,
    types::{
        AuditEngineStatus, AuditLogFormat, BodyLimitAction, RuleEngineStatus, RuleSeverity, parse_audit_log_parts,
    },
    waf::Waf,
};

fn serialized_audit_entries(format: AuditLogFormat, document: &serde_json::Value) -> &[serde_json::Value] {
    let path = match format {
        AuditLogFormat::Json => "/messages",
        AuditLogFormat::JsonLegacy => "/audit_data/messages",
        AuditLogFormat::Ocsf => "/enrichments",
        AuditLogFormat::Native => unreachable!(),
    };
    document.pointer(path).and_then(serde_json::Value::as_array).unwrap()
}

fn serialized_audit_entry_data(format: AuditLogFormat, entry: &serde_json::Value) -> serde_json::Value {
    match format {
        AuditLogFormat::Json => entry.get("data").unwrap().clone(),
        AuditLogFormat::Ocsf => {
            serde_json::from_str(entry.get("data").and_then(serde_json::Value::as_str).unwrap()).unwrap()
        },
        AuditLogFormat::JsonLegacy | AuditLogFormat::Native => unreachable!(),
    }
}

fn assert_json_formats_serialize_engine_events(audit: &coraza::audit_log::AuditLog, rule: &str) {
    for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
        let output = audit.format(format);
        let document: serde_json::Value = serde_json::from_str(&output).unwrap();
        let messages = serialized_audit_entries(format, &document);
        match format {
            AuditLogFormat::Json => {
                let engine = messages
                    .iter()
                    .find(|message| message.pointer("/data/id").and_then(serde_json::Value::as_i64) == Some(0))
                    .unwrap();
                assert_eq!(
                    engine.get("message").and_then(serde_json::Value::as_str),
                    Some("RequestBodyLimit"),
                    "JSON serializes the engine message"
                );
                assert!(
                    engine
                        .pointer("/data/tags")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|tags| {
                            tags.iter()
                                .any(|tag| tag.as_str() == Some("coraza-rs/engine/RequestBodyLimit"))
                        }),
                    "JSON serializes the engine state tag"
                );
                let ordinary = messages
                    .iter()
                    .find(|message| message.pointer("/data/id").and_then(serde_json::Value::as_i64) == Some(90))
                    .unwrap();
                assert_eq!(
                    ordinary.get("message").and_then(serde_json::Value::as_str),
                    Some("before engine stop"),
                    "JSON preserves ordinary rule messages"
                );
                assert_eq!(
                    ordinary.pointer("/data/raw").and_then(serde_json::Value::as_str),
                    Some(rule),
                    "ordinary rule output is unchanged"
                );
            },
            AuditLogFormat::JsonLegacy => {
                assert!(
                    messages.iter().any(|message| {
                        message.as_str().is_some_and(|text| {
                            text.contains("coraza-rs/engine/RequestBodyLimit") && text.contains("RequestBodyLimit")
                        })
                    }),
                    "JSONLegacy serializes the engine identity and message"
                );
                assert!(
                    messages
                        .iter()
                        .any(|message| message.as_str() == Some("before engine stop")),
                    "JSONLegacy preserves ordinary rule messages"
                );
            },
            AuditLogFormat::Ocsf => {
                let engine = messages
                    .iter()
                    .find(|enrichment| {
                        enrichment.get("name").and_then(serde_json::Value::as_str) == Some("RequestBodyLimit")
                    })
                    .unwrap();
                let engine_data = serialized_audit_entry_data(format, engine);
                assert_eq!(
                    engine_data.get("id").and_then(serde_json::Value::as_i64),
                    Some(0),
                    "OCSF serializes the synthetic event ID"
                );
                assert!(
                    engine_data
                        .get("tags")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|tags| {
                            tags.iter()
                                .any(|tag| tag.as_str() == Some("coraza-rs/engine/RequestBodyLimit"))
                        }),
                    "OCSF serializes the engine state tag"
                );
                let ordinary = messages
                    .iter()
                    .find(|enrichment| {
                        enrichment.get("name").and_then(serde_json::Value::as_str) == Some("before engine stop")
                    })
                    .unwrap();
                let ordinary_data = serialized_audit_entry_data(format, ordinary);
                assert_eq!(
                    ordinary_data.get("id").and_then(serde_json::Value::as_i64),
                    Some(90),
                    "OCSF preserves ordinary rule IDs"
                );
                assert_eq!(
                    ordinary_data.get("raw").and_then(serde_json::Value::as_str),
                    Some(rule),
                    "ordinary rule output is unchanged"
                );
            },
            AuditLogFormat::Native => unreachable!(),
        }
    }
}

#[expect(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    reason = "The JSON, legacy, and OCSF formats have distinct public message shapes."
)]
fn assert_engine_identity_and_ordinary_rule_output(format: AuditLogFormat, output: &str, k_selected: bool, rule: &str) {
    const STATE: &str = "coraza-rs/engine/RequestBodyLimit";
    let document: serde_json::Value = serde_json::from_str(output).unwrap();
    assert_audit_text_has_no_nul(output, "serialized JSON output");
    let messages = serialized_audit_entries(format, &document);

    match format {
        AuditLogFormat::Json => {
            assert_eq!(messages.len(), 2, "{output}");
            let ordinary = messages.first().unwrap();
            if k_selected {
                assert_eq!(
                    ordinary.pointer("/data/id").and_then(serde_json::Value::as_i64),
                    Some(90),
                    "{output}"
                );
                assert_eq!(
                    ordinary.get("message").and_then(serde_json::Value::as_str),
                    Some("before engine stop"),
                    "{output}"
                );
                assert_eq!(
                    ordinary.pointer("/data/raw").and_then(serde_json::Value::as_str),
                    Some(rule),
                    "{output}"
                );
            } else {
                assert_eq!(
                    ordinary.get("message").and_then(serde_json::Value::as_str),
                    Some(""),
                    "{output}"
                );
                assert!(
                    ordinary
                        .get("error_message")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|line| line.contains("[id \"90\"]")),
                    "H-only ordinary rule output is unchanged: {output}"
                );
            }

            let event = messages.get(1).unwrap();
            assert_eq!(
                event.pointer("/data/id").and_then(serde_json::Value::as_i64),
                Some(0),
                "{output}"
            );
            assert_eq!(
                event.pointer("/data/severity").and_then(serde_json::Value::as_i64),
                Some(2),
                "a synthetic Critical event keeps severity 2 in full JSON: {output}"
            );
            if k_selected {
                assert!(
                    event
                        .pointer("/data/tags")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|tags| { tags.iter().any(|tag| tag.as_str() == Some(STATE)) }),
                    "the K-selected state tag is structured: {output}"
                );
            } else {
                assert!(
                    event
                        .get("error_message")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|line| line.contains(STATE)),
                    "the H-only JSON error line carries the engine state: {output}"
                );
                assert_eq!(
                    event.pointer("/data/raw").and_then(serde_json::Value::as_str),
                    Some(""),
                    "H-only JSON does not serialize the engine K field: {output}"
                );
                assert!(
                    event
                        .pointer("/data/tags")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(Vec::is_empty),
                    "H-only JSON does not serialize engine tags: {output}"
                );
            }
        },
        AuditLogFormat::JsonLegacy => {
            assert_eq!(messages.len(), 2, "{output}");
            assert_eq!(
                messages.first().unwrap().as_str(),
                Some(if k_selected { "before engine stop" } else { "" }),
                "normal H-only/K-selected rule message stays unchanged: {output}"
            );
            assert!(
                messages
                    .get(1)
                    .unwrap()
                    .as_str()
                    .is_some_and(|message| message.contains(STATE)),
                "the synthetic event state is visible in JSONLegacy: {output}"
            );
        },
        AuditLogFormat::Ocsf => {
            assert_eq!(messages.len(), 2, "{output}");
            let ordinary = messages.first().unwrap();
            assert_eq!(
                ordinary
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default(),
                if k_selected { "before engine stop" } else { "" },
                "normal H-only/K-selected rule name stays unchanged: {output}"
            );
            if k_selected {
                let data = serialized_audit_entry_data(format, messages.get(1).unwrap());
                assert_eq!(data.get("id").and_then(serde_json::Value::as_i64), Some(0), "{output}");
                assert_eq!(
                    data.get("severity").and_then(serde_json::Value::as_i64),
                    Some(2),
                    "a synthetic Critical event keeps severity 2 in full OCSF: {output}"
                );
                assert!(
                    data.get("tags")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|tags| { tags.iter().any(|tag| tag.as_str() == Some(STATE)) }),
                    "the K-selected state tag is structured: {output}"
                );
                let ordinary_data = serialized_audit_entry_data(format, ordinary);
                assert_eq!(
                    ordinary_data.get("raw").and_then(serde_json::Value::as_str),
                    Some(rule),
                    "ordinary OCSF enrichment is unchanged"
                );
            } else {
                assert!(
                    messages
                        .get(1)
                        .unwrap()
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|name| name.contains(STATE)),
                    "the H-only OCSF enrichment names the engine event: {output}"
                );
                let data = serialized_audit_entry_data(format, messages.get(1).unwrap());
                assert_eq!(
                    data.get("severity").and_then(serde_json::Value::as_i64),
                    Some(2),
                    "H-only OCSF keeps the synthetic Critical severity: {output}"
                );
                assert_eq!(
                    data.get("raw").and_then(serde_json::Value::as_str),
                    Some(""),
                    "H-only OCSF does not serialize the engine K field: {output}"
                );
                assert!(
                    data.get("tags")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(Vec::is_empty),
                    "H-only OCSF does not serialize engine tags: {output}"
                );
            }
        },
        AuditLogFormat::Native => unreachable!(),
    }
}

fn assert_audit_text_has_no_nul(value: &str, field: &str) {
    assert!(!value.contains('\0'), "{field} contains a NUL: {value:?}");
    if let Ok(document) = serde_json::from_str::<serde_json::Value>(value) {
        assert!(
            !json_value_contains_nul(&document),
            "{field} contains a NUL in a decoded JSON string: {value:?}"
        );
    }
}

fn json_value_contains_nul(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => {
            text.contains('\0')
                || serde_json::from_str::<serde_json::Value>(text).is_ok_and(|nested| json_value_contains_nul(&nested))
        },
        serde_json::Value::Array(values) => values.iter().any(json_value_contains_nul),
        serde_json::Value::Object(values) => values.values().any(json_value_contains_nul),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => false,
    }
}

#[test]
fn serialized_json_nul_checks_decode_escaped_and_nested_ocsf_strings() {
    let json: serde_json::Value = serde_json::from_str(r#"{"message":"\u0000"}"#).unwrap();
    assert!(json_value_contains_nul(&json));

    let ocsf: serde_json::Value =
        serde_json::from_str(r#"{"enrichments":[{"data":"{\"message\":\"\\u0000\"}"}]}"#).unwrap();
    assert!(json_value_contains_nul(&ocsf));
}

fn assert_typed_engine_message(message: &AuditMessage, state: &str) {
    let enforced = message.data.tags.iter().any(|tag| tag == "coraza-rs/engine/Enforced");
    let enforced_omitted = message
        .data
        .tags
        .iter()
        .any(|tag| tag == "coraza-rs/engine/EnforcedStopOmitted");
    match message.provenance {
        Some(AuditMessageProvenance::EngineEvent { enforced: marker }) => {
            assert_ne!(
                state, "EventsOmitted",
                "summary text uses the summary provenance variant"
            );
            assert_eq!(marker, enforced, "typed enforcement matches data.tags");
        },
        Some(AuditMessageProvenance::EventsOmitted { enforced_stop_omitted }) => {
            assert_eq!(
                state, "EventsOmitted",
                "summary provenance uses the reserved summary state"
            );
            assert_eq!(
                enforced_stop_omitted, enforced_omitted,
                "typed summary marker matches data.tags"
            );
        },
        None => panic!("synthetic audit records carry typed provenance"),
    }
    for (field, value) in [
        ("actionset", message.actionset.as_str()),
        ("message", message.message.as_str()),
        ("error_message", message.error_message.as_str()),
        ("rule_message", message.rule_message.as_str()),
        ("data.file", message.data.file.as_str()),
        ("data.rev", message.data.rev.as_str()),
        ("data.msg", message.data.msg.as_str()),
        ("data.data", message.data.data.as_str()),
        ("data.ver", message.data.ver.as_str()),
        ("data.raw", message.data.raw.as_str()),
    ] {
        assert_audit_text_has_no_nul(value, field);
    }
    for tag in &message.data.tags {
        assert_audit_text_has_no_nul(tag, "data.tags");
    }

    let tag = format!("coraza-rs/engine/{state}");
    assert_eq!(message.rule_id, 0, "synthetic messages use reserved ID zero");
    assert_eq!(message.data.id, 0, "synthetic message data uses ID zero");
    assert_eq!(
        message.data.tags.first().map(String::as_str),
        Some(tag.as_str()),
        "the state tag leads the synthetic tags: {:?}",
        message.data.tags
    );
    assert!(
        message.data.tags.get(1).is_none_or(|marker| {
            marker == "coraza-rs/engine/Enforced" || marker == "coraza-rs/engine/EnforcedStopOmitted"
        }) && message.data.tags.len() <= 2,
        "only a valid enforcement marker may follow the state tag: {:?}",
        message.data.tags
    );
    assert_eq!(
        message.data.raw, tag,
        "the structured raw label is the true engine state"
    );
    assert!(
        message.rule_message.starts_with(&format!("{tag}: ")),
        "the visible compact identity carries the true engine state: {:?}",
        message.rule_message
    );
}

fn assert_typed_engine_messages(audit: &coraza::audit_log::AuditLog, state: &str) {
    let events: Vec<_> = audit.messages.iter().filter(|message| message.rule_id == 0).collect();
    assert_eq!(events.len(), 1, "one synthetic {state} audit message");
    for message in events {
        assert_typed_engine_message(message, state);
    }
}

fn assert_normal_engine_output(format: AuditLogFormat, output: &str, state: &str, k_selected: bool, enforced: bool) {
    const ENFORCED: &str = "coraza-rs/engine/Enforced";
    let tag = format!("coraza-rs/engine/{state}");
    assert_audit_text_has_no_nul(output, "formatted audit output");
    assert!(
        output.contains(&tag),
        "{format:?} lost the visible state identity: {output}"
    );
    if format == AuditLogFormat::Native {
        return;
    }

    let document: serde_json::Value = serde_json::from_str(output).unwrap();
    let messages = serialized_audit_entries(format, &document);
    match format {
        AuditLogFormat::Json => {
            let message = messages
                .first()
                .unwrap_or_else(|| panic!("JSON has no engine message: {output}"));
            let data = serialized_audit_entry_data(format, message);
            let tags = data.get("tags").and_then(serde_json::Value::as_array).unwrap();
            if k_selected {
                assert!(
                    tags.iter().any(|candidate| candidate.as_str() == Some(&tag)),
                    "{output}"
                );
                assert_eq!(
                    tags.iter().filter_map(serde_json::Value::as_str).collect::<Vec<_>>(),
                    if enforced {
                        vec![tag.as_str(), ENFORCED]
                    } else {
                        vec![tag.as_str()]
                    },
                    "K-selected JSON preserves the enforcement marker: {output}"
                );
                assert_eq!(
                    data.get("raw").and_then(serde_json::Value::as_str),
                    Some(tag.as_str()),
                    "K-selected JSON keeps the structured engine label"
                );
            } else {
                assert!(
                    tags.iter().all(|candidate| candidate.as_str() != Some(&tag)),
                    "{output}"
                );
                assert_ne!(
                    data.get("raw").and_then(serde_json::Value::as_str),
                    Some(tag.as_str()),
                    "H-only JSON does not serialize K-only engine metadata"
                );
            }
        },
        AuditLogFormat::JsonLegacy => {
            assert!(
                messages
                    .iter()
                    .any(|message| message.as_str().is_some_and(|text| text.contains(&tag))),
                "{output}"
            );
        },
        AuditLogFormat::Ocsf => {
            let data = serialized_audit_entry_data(format, messages.first().unwrap());
            let tags = data.get("tags").and_then(serde_json::Value::as_array);
            if k_selected {
                assert!(
                    tags.is_some_and(|tags| tags.iter().any(|candidate| candidate.as_str() == Some(&tag))),
                    "{output}"
                );
                assert_eq!(
                    tags.unwrap()
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>(),
                    if enforced {
                        vec![tag.as_str(), ENFORCED]
                    } else {
                        vec![tag.as_str()]
                    },
                    "K-selected OCSF preserves the enforcement marker: {output}"
                );
                assert_eq!(
                    data.get("raw").and_then(serde_json::Value::as_str),
                    Some(tag.as_str()),
                    "K-selected OCSF keeps the structured engine label"
                );
            } else {
                assert!(
                    tags.is_none_or(|tags| tags.iter().all(|candidate| candidate.as_str() != Some(&tag))),
                    "{output}"
                );
                assert_ne!(
                    data.get("raw").and_then(serde_json::Value::as_str),
                    Some(tag.as_str()),
                    "H-only OCSF does not serialize K-only engine metadata"
                );
            }
        },
        AuditLogFormat::Native => unreachable!(),
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "Checks caller-owned H-only fields across full, reduced, and compacted formats."
)]
fn hand_built_h_only_id_zero_messages_keep_caller_tags_and_raw() {
    const STATE: &str = "coraza-rs/engine/CallerSupplied";
    const OUTPUT_LIMIT: usize = 1024;
    let audit = coraza::audit_log::AuditLog {
        parts: parse_audit_log_parts("AHZ").unwrap(),
        transaction: coraza::audit_log::AuditTransaction {
            producer: Some(coraza::audit_log::AuditProducer {
                connector: "c".repeat(16 * 1024),
                rulesets: vec!["r".repeat(16 * 1024)],
                ..coraza::audit_log::AuditProducer::default()
            }),
            ..coraza::audit_log::AuditTransaction::default()
        },
        messages: vec![AuditMessage {
            message: "ordinary caller message".to_owned(),
            error_message: "ordinary caller error line".to_owned(),
            rule_id: 0,
            rule_message: "ordinary caller identity".to_owned(),
            data: AuditMessageData {
                id: 0,
                msg: "ordinary caller message".to_owned(),
                tags: vec![STATE.to_owned()],
                raw: STATE.to_owned(),
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        }],
    };

    for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
        let output = audit.format(format);
        assert_audit_text_has_no_nul(&output, "full hand-built audit output");
        let document: serde_json::Value = serde_json::from_str(&output).unwrap();
        match format {
            AuditLogFormat::Json | AuditLogFormat::Ocsf => {
                let nested_data = if format == AuditLogFormat::Json {
                    document.pointer("/messages/0/data").cloned().unwrap()
                } else {
                    serde_json::from_str(
                        document
                            .pointer("/enrichments/0/data")
                            .and_then(serde_json::Value::as_str)
                            .unwrap(),
                    )
                    .unwrap()
                };
                assert_eq!(
                    nested_data.get("raw").and_then(serde_json::Value::as_str),
                    Some(STATE),
                    "{format:?} preserves caller-supplied raw data: {output}"
                );
                assert!(
                    nested_data
                        .get("tags")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some(STATE))),
                    "{format:?} preserves caller-supplied tags: {output}"
                );
            },
            AuditLogFormat::JsonLegacy => assert_eq!(
                document
                    .pointer("/audit_data/messages/0")
                    .and_then(serde_json::Value::as_str),
                Some("ordinary caller message"),
                "JSONLegacy does not infer an engine event from caller data: {output}"
            ),
            AuditLogFormat::Native => unreachable!(),
        }
    }

    let mut reduced = audit.clone();
    reduced.transaction.producer = None;
    reduced.transaction.request.uri = format!("/{}", "p".repeat(16 * 1024));
    for format in [AuditLogFormat::Json, AuditLogFormat::Ocsf] {
        let (output, truncated) = reduced.format_bounded(format, OUTPUT_LIMIT);
        assert!(truncated, "{format:?}: the request URI forces reduction");
        assert!(output.len() <= OUTPUT_LIMIT, "{format:?}: {} bytes", output.len());
        assert_audit_text_has_no_nul(&output, "reduced hand-built audit output");
        let document: serde_json::Value = serde_json::from_str(&output).unwrap();
        let nested_data = if format == AuditLogFormat::Json {
            document.pointer("/messages/0/data").cloned().unwrap()
        } else {
            serde_json::from_str(
                document
                    .pointer("/enrichments/0/data")
                    .and_then(serde_json::Value::as_str)
                    .unwrap(),
            )
            .unwrap()
        };
        assert_eq!(
            nested_data.get("raw").and_then(serde_json::Value::as_str),
            Some(STATE),
            "{format:?} reduction preserves caller-supplied raw data: {output}"
        );
        assert!(
            nested_data
                .get("tags")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some(STATE))),
            "{format:?} reduction preserves caller-supplied tags: {output}"
        );
    }

    for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
        let (output, truncated) = audit.format_bounded(format, OUTPUT_LIMIT);
        assert!(truncated, "{format:?}: the large producer forces reduction");
        assert!(output.len() <= OUTPUT_LIMIT, "{format:?}: {} bytes", output.len());
        assert_audit_text_has_no_nul(&output, "reduced hand-built audit output");
        let document: serde_json::Value = serde_json::from_str(&output).unwrap();
        let compacted = match format {
            AuditLogFormat::Json => document.pointer("/transaction/producer").is_none(),
            AuditLogFormat::JsonLegacy => document
                .pointer("/audit_data/producer")
                .is_some_and(serde_json::Value::is_null),
            AuditLogFormat::Ocsf => document.pointer("/metadata/log_provider").is_none(),
            AuditLogFormat::Native => unreachable!(),
        };
        assert!(compacted, "{format:?}: the fixture reaches audit compaction: {output}");
        match format {
            AuditLogFormat::Json => {
                let message = document.pointer("/messages/0").unwrap();
                assert_eq!(
                    message.pointer("/data/msg").and_then(serde_json::Value::as_str),
                    Some("ordinary caller message"),
                    "reduction preserves ordinary caller text: {output}"
                );
                assert!(
                    !output.contains(&format!("{STATE}: ")),
                    "reduction does not prefix a synthetic identity: {output}"
                );
            },
            AuditLogFormat::JsonLegacy => assert_eq!(
                document
                    .pointer("/audit_data/messages/0")
                    .and_then(serde_json::Value::as_str),
                Some("ordinary caller message"),
                "reduction does not rewrite caller text as an engine event: {output}"
            ),
            AuditLogFormat::Ocsf => {
                assert_eq!(
                    document
                        .pointer("/enrichments/0/name")
                        .and_then(serde_json::Value::as_str),
                    Some("ordinary caller message"),
                    "reduction does not substitute a synthetic identity: {output}"
                );
                assert!(
                    !output.contains(&format!("{STATE}: ")),
                    "reduction does not prefix a synthetic identity: {output}"
                );
            },
            AuditLogFormat::Native => unreachable!(),
        }
    }
}

#[derive(Debug)]
struct LoggedEvent {
    rule_id: i32,
    disruptive: bool,
    severity: Option<RuleSeverity>,
    message: String,
    tags: Vec<String>,
    transaction_id: String,
    line: String,
    status: i32,
}

#[derive(Clone, Copy)]
struct ExpectedEngineStop {
    state: &'static str,
    status: i32,
    message: &'static str,
    disruptive: bool,
    transaction_id: &'static str,
}

fn capture_error_logs(parser: &mut Parser, events: Arc<Mutex<Vec<LoggedEvent>>>) {
    parser.on_error_log(move |matched| {
        events.lock().unwrap().push(LoggedEvent {
            rule_id: matched.rule_id(),
            disruptive: matched.disruptive,
            severity: matched.severity(),
            message: matched.message().to_owned(),
            tags: matched.tags().to_vec(),
            transaction_id: matched.transaction_id.clone(),
            line: matched.error_log(),
            status: matched.rule.status(),
        });
    });
}

fn request_config(engine: RuleEngineStatus, limit: i64) -> WafConfig {
    WafConfig {
        rule_engine: engine,
        request_body_access: true,
        request_body_limit: limit,
        request_body_in_memory_limit: limit,
        request_body_limit_action: BodyLimitAction::Reject,
        audit_engine: AuditEngineStatus::On,
        audit_log_parts: parse_audit_log_parts("ABHKZ").unwrap(),
        ..WafConfig::default()
    }
}

fn build_waf(config: WafConfig, rules: &str, events: Arc<Mutex<Vec<LoggedEvent>>>) -> Waf {
    let mut parser = Parser::new();
    *parser.config_mut() = config;
    capture_error_logs(&mut parser, events);
    parser.from_string(rules).unwrap();
    parser.into_waf().unwrap()
}

fn request(waf: &Waf, budget: Option<usize>) -> Transaction {
    let mut tx = waf.new_transaction_with_id("engine-event-request");
    tx.set_body_memory_budget(budget);
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    tx.process_request_headers();
    tx
}

fn assert_logged_and_audited_stop(
    tx: &Transaction,
    events: &Arc<Mutex<Vec<LoggedEvent>>>,
    expected: ExpectedEngineStop,
) {
    let tag = format!("coraza-rs/engine/{}", expected.state);
    let engine_event = tx.engine_events().first().unwrap();
    assert_eq!(tx.engine_events().len(), 1, "one event for {}", expected.state);
    assert_eq!(engine_event.rule_id(), 0, "engine events use rule id zero");
    assert_eq!(
        engine_event.rule.status(),
        expected.status,
        "event status for {}",
        expected.state
    );
    assert_eq!(
        engine_event.severity(),
        Some(RuleSeverity::Critical),
        "engine event severity"
    );
    assert_eq!(
        engine_event.message(),
        expected.message,
        "event message for {}",
        expected.state
    );
    assert!(engine_event.tags().contains(&tag), "engine state tag");
    assert_eq!(
        engine_event.transaction_id, expected.transaction_id,
        "engine event keeps the expected transaction ID"
    );

    let logged = events.lock().unwrap();
    let logged_event = logged.iter().find(|event| event.rule_id == 0).unwrap();
    assert_eq!(
        logged_event.disruptive, expected.disruptive,
        "log outcome for {}",
        expected.state
    );
    assert_eq!(
        logged_event.status, expected.status,
        "callback status for {}",
        expected.state
    );
    assert_eq!(logged_event.severity, Some(RuleSeverity::Critical), "callback severity");
    assert_eq!(
        logged_event.message, expected.message,
        "callback message for {}",
        expected.state
    );
    assert!(logged_event.tags.contains(&tag), "callback state tag");
    assert_eq!(
        logged_event.transaction_id, expected.transaction_id,
        "callback keeps the expected transaction ID"
    );
    assert!(
        logged_event.line.contains(expected.transaction_id),
        "formatted callback line includes the transaction ID"
    );
    assert!(logged_event.line.contains(&tag), "formatted error log state tag");
    drop(logged);

    let audit = tx.audit_log();
    let audited = audit.messages.iter().find(|message| message.rule_id == 0).unwrap();
    assert_eq!(audited.data.id, 0, "audit rule id for {}", expected.state);
    assert_eq!(
        audited.message, expected.message,
        "audit message for {}",
        expected.state
    );
    assert!(audited.data.tags.contains(&tag), "audit state tag");
    assert!(audited.error_message.contains(&tag), "audit part H state tag");
}

#[test]
fn a_request_body_reject_stop_is_logged_and_audited_in_both_enforcing_modes() {
    let rule = "SecAction \"id:90,phase:1,pass,log,auditlog,msg:'before engine stop'\"";
    for (engine, enforced) in [(RuleEngineStatus::On, true), (RuleEngineStatus::DetectionOnly, false)] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let waf = build_waf(request_config(engine, 4), rule, Arc::clone(&events));
        let mut tx = request(&waf, None);

        let interruption = tx.process_request_body(b"1234");
        if enforced {
            assert_eq!(
                interruption.map(|value| (value.rule_id, value.status, value.action, value.data)),
                Some((0, 413, "deny".to_owned(), String::new()))
            );
            assert!(tx.would_be_interruption().is_none());
        } else {
            assert!(interruption.is_none());
            assert!(tx.interruption().is_none());
            assert_eq!(
                tx.would_be_interruption().map(|value| (
                    value.rule_id,
                    value.status,
                    value.action.as_str(),
                    value.data.as_str()
                )),
                Some((0, 413, "deny", ""))
            );
        }
        assert_eq!(tx.matched_rules().len(), 1);
        assert_eq!(tx.matched_rules().first().unwrap().rule_id(), 90);
        let stats = tx.request_body_stats();
        assert_eq!(stats.supplied, 4, "the limit-boundary body is counted once");
        assert_eq!(
            stats.retained,
            if enforced { 0 } else { 4 },
            "On refuses the body; DetectionOnly still ingests it"
        );
        assert_eq!(
            stats.truncated, enforced,
            "only the enforced Reject path marks the exact-limit bytes refused"
        );
        assert_logged_and_audited_stop(
            &tx,
            &events,
            ExpectedEngineStop {
                state: "RequestBodyLimit",
                status: 413,
                message: "RequestBodyLimit",
                disruptive: enforced,
                transaction_id: "engine-event-request",
            },
        );

        let audit = tx.audit_log();
        assert_eq!(
            audit.messages.iter().map(|message| message.rule_id).collect::<Vec<_>>(),
            [90, 0],
            "engine events follow matched-rule messages in audit output"
        );
        assert_json_formats_serialize_engine_events(&audit, rule);
    }
}

#[test]
fn body_limit_engine_identity_is_visible_in_full_h_only_and_k_selected_json_formats() {
    let rule = "SecAction \"id:90,phase:1,pass,log,auditlog,msg:'before engine stop'\"";
    for (engine, enforced) in [(RuleEngineStatus::On, true), (RuleEngineStatus::DetectionOnly, false)] {
        for (parts, k_selected) in [("AHZ", false), ("AKZ", true)] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut config = request_config(engine, 4);
            config.audit_log_parts = parse_audit_log_parts(parts).unwrap();
            let waf = build_waf(config, rule, events);
            let mut tx = request(&waf, None);

            let interruption = tx.process_request_body(b"1234");
            if enforced {
                assert_eq!(interruption.map(|value| (value.rule_id, value.status)), Some((0, 413)));
                assert!(tx.would_be_interruption().is_none());
            } else {
                assert!(interruption.is_none());
                assert_eq!(
                    tx.would_be_interruption().map(|value| (value.rule_id, value.status)),
                    Some((0, 413))
                );
            }
            assert_eq!(
                tx.matched_rules()
                    .iter()
                    .map(coraza::audit_log::MatchedRule::rule_id)
                    .collect::<Vec<_>>(),
                [90],
                "{engine} {parts}: ordinary matches stay separate from the engine event"
            );

            let audit = tx.audit_log();
            assert_eq!(
                audit.messages.iter().map(|message| message.rule_id).collect::<Vec<_>>(),
                [90, 0],
                "{engine} {parts}: the real engine event follows the ordinary rule"
            );
            for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
                let full = audit.format(format);
                assert_engine_identity_and_ordinary_rule_output(format, &full, k_selected, rule);

                let (bounded, truncated) = audit.format_bounded(format, 16 * 1024);
                assert!(!truncated, "{engine} {parts} {format:?}: the large cap fits");
                assert!(bounded.len() <= 16 * 1024, "{engine} {parts} {format:?}");
                assert_engine_identity_and_ordinary_rule_output(format, &bounded, k_selected, rule);
            }
        }
    }
}

#[test]
fn synthetic_audit_messages_have_clean_structured_state_at_public_seams() {
    const STATE: &str = "RequestBodyLimit";
    const OUTPUT_LIMIT: usize = 1024;

    for engine in [RuleEngineStatus::On, RuleEngineStatus::DetectionOnly] {
        for (parts, k_selected) in [("AKZ", true), ("AHZ", false)] {
            let audits = Arc::new(Mutex::new(Vec::new()));
            let callback_audits = Arc::clone(&audits);
            let mut config = request_config(engine, 4);
            config.audit_log_parts = parse_audit_log_parts(parts).unwrap();
            let mut parser = Parser::new();
            *parser.config_mut() = config;
            parser.on_audit_log(move |audit| callback_audits.lock().unwrap().push(audit.clone()));
            parser.from_string("").unwrap();
            let waf = parser.into_waf().unwrap();
            let mut tx = request(&waf, None);
            assert_eq!(
                tx.process_request_body(b"1234")
                    .map(|interruption| (interruption.rule_id, interruption.status)),
                (engine == RuleEngineStatus::On).then_some((0, 413))
            );

            let audit = tx.audit_log();
            assert_typed_engine_messages(&audit, STATE);
            assert_eq!(
                audit.messages.first().unwrap().data.tags,
                if engine == RuleEngineStatus::On {
                    vec![
                        format!("coraza-rs/engine/{STATE}"),
                        "coraza-rs/engine/Enforced".to_owned(),
                    ]
                } else {
                    vec![format!("coraza-rs/engine/{STATE}")]
                },
                "{engine:?} {parts}: typed K distinguishes the enforced event"
            );
            for format in [
                AuditLogFormat::Native,
                AuditLogFormat::Json,
                AuditLogFormat::JsonLegacy,
                AuditLogFormat::Ocsf,
            ] {
                assert_normal_engine_output(
                    format,
                    &audit.format(format),
                    STATE,
                    k_selected,
                    engine == RuleEngineStatus::On,
                );
            }

            let mut reduced = audit.clone();
            let producer = reduced
                .transaction
                .producer
                .get_or_insert_with(coraza::audit_log::AuditProducer::default);
            producer.connector = "c".repeat(16 * 1024);
            producer.rulesets = vec!["r".repeat(16 * 1024)];
            for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
                let (output, truncated) = reduced.format_bounded(format, OUTPUT_LIMIT);
                assert!(truncated, "{engine:?} {parts} {format:?}: producer forces reduction");
                assert!(output.len() <= OUTPUT_LIMIT, "{engine:?} {parts} {format:?}");
                let document: serde_json::Value = serde_json::from_str(&output).unwrap();
                assert!(document.is_object(), "{engine:?} {parts} {format:?}: {output}");
                assert_audit_text_has_no_nul(&output, "reduced audit output");
                assert!(output.contains("coraza-rs/engine/RequestBodyLimit"), "{output}");
                if matches!(format, AuditLogFormat::Json | AuditLogFormat::Ocsf) {
                    assert_eq!(
                        bounded_engine_event_data(format, &output)
                            .get("severity")
                            .and_then(serde_json::Value::as_i64),
                        Some(2),
                        "{engine:?} {parts} {format:?}: compact synthetic data keeps Critical severity"
                    );
                }
            }

            let mut native = audit.clone();
            native.transaction.id = "t".repeat(16 * 1024);
            let (output, truncated) = native.format_bounded(AuditLogFormat::Native, OUTPUT_LIMIT);
            assert!(truncated, "{engine:?} {parts}: large native header forces reduction");
            assert!(
                output.len() <= OUTPUT_LIMIT,
                "{engine:?} {parts}: {} bytes",
                output.len()
            );
            assert_audit_text_has_no_nul(&output, "bounded Native output");

            tx.finish().unwrap();
            let callbacks = audits.lock().unwrap();
            assert_eq!(callbacks.len(), 1, "{engine:?} {parts}: one audit callback");
            assert_typed_engine_messages(callbacks.first().unwrap(), STATE);
            assert_eq!(
                callbacks.first().unwrap().transaction.interruption_rule_id,
                (engine == RuleEngineStatus::On).then_some(0),
                "{engine:?}: only an enforced interruption ID is public"
            );
        }
    }
}

#[test]
fn detection_only_rule_has_no_public_enforced_interruption_id() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let rule = "SecAction \"id:90,phase:1,deny,status:403,log,auditlog,msg:'would deny'\"";
    let waf = build_waf(request_config(RuleEngineStatus::DetectionOnly, 64), rule, events);
    let tx = request(&waf, None);

    assert_eq!(
        tx.would_be_interruption().map(|value| (value.rule_id, value.status)),
        Some((90, 403)),
        "the real rule still records its would-be interruption"
    );
    let audit = tx.audit_log();
    assert!(!audit.transaction.is_interrupted);
    assert_eq!(audit.transaction.interruption_rule_id, None);
}

#[test]
fn detection_only_engine_stop_has_no_public_enforced_interruption_id() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let waf = build_waf(request_config(RuleEngineStatus::DetectionOnly, 4), "", events);
    let mut tx = request(&waf, None);

    assert!(
        tx.process_request_body(b"1234").is_none(),
        "DetectionOnly does not block"
    );
    assert_eq!(
        tx.would_be_interruption().map(|value| (value.rule_id, value.status)),
        Some((0, 413)),
        "the engine stop remains the would-be interruption"
    );
    assert_eq!(tx.engine_events().len(), 1);
    let audit = tx.audit_log();
    assert!(!audit.transaction.is_interrupted);
    assert_eq!(audit.transaction.interruption_rule_id, None);
}

#[test]
fn an_idless_parsed_rule_does_not_create_an_audit_message() {
    const MESSAGE: &str = "coraza-rs/engine/RequestBodyLimit: id-less rule content";

    let config = WafConfig {
        rule_engine: RuleEngineStatus::On,
        audit_engine: AuditEngineStatus::On,
        audit_log_parts: parse_audit_log_parts("AHZ").unwrap(),
        ..WafConfig::default()
    };
    let mut parser = Parser::new();
    *parser.config_mut() = config;
    parser
        .from_string(&format!(
            "SecRule ARGS:q \"@streq hit\" \"phase:1,pass,log,auditlog,setvar:tx.idless=matched,msg:'{MESSAGE}'\""
        ))
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("idless-lookalike");
    tx.process_uri("/?q=hit", "GET", "HTTP/1.1");
    tx.process_request_headers();

    assert_eq!(
        tx.get_variable(coraza::types::RuleVariable::TX, Some("idless"))
            .as_deref(),
        Some("matched"),
        "the parsed id-less rule did run"
    );
    assert!(
        tx.matched_rules().is_empty(),
        "a parsed rule without an ID is not recorded"
    );
    assert!(
        tx.audit_log().messages.is_empty(),
        "an id-less rule with engine-looking text does not create a synthetic audit message"
    );
}

#[test]
fn ordinary_rule_identity_is_retained_only_for_h_only_audits() {
    const RULE_ID: i32 = 901;
    const MESSAGE: &str = "ordinary rule message";

    for (parts, expected_identity) in [("AKZ", ""), ("AHZ", MESSAGE), ("AHKZ", "")] {
        let config = WafConfig {
            rule_engine: RuleEngineStatus::On,
            audit_engine: AuditEngineStatus::On,
            audit_log_parts: parse_audit_log_parts(parts).unwrap(),
            ..WafConfig::default()
        };
        let mut parser = Parser::new();
        *parser.config_mut() = config;
        parser
            .from_string(&format!(
                "SecRule ARGS \"@streq hit\" \
                 \"id:{RULE_ID},phase:1,pass,log,auditlog,msg:'{MESSAGE}'\""
            ))
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("ordinary-rule-audit-identity");
        tx.process_uri("/", "GET", "HTTP/1.1");
        tx.add_get_argument("q", "hit");
        tx.add_get_argument("r", "hit");
        tx.process_request_headers();

        assert_eq!(
            tx.matched_rules().first().map(|matched| matched
                .matches
                .iter()
                .map(|matched| matched.key.as_str())
                .collect::<Vec<_>>()),
            Some(vec!["q", "r"]),
            "{parts}: one matched rule should retain both values"
        );
        let audit = tx.audit_log();
        assert_eq!(
            audit.messages.len(),
            if parts.contains('K') { 2 } else { 1 },
            "{parts}: K emits one typed record per match; H emits one rule line"
        );
        for message in &audit.messages {
            assert_eq!(message.rule_id, RULE_ID, "{parts}");
            assert_eq!(message.provenance, None, "{parts}: real rules stay unmarked");
            assert_eq!(message.rule_message, expected_identity, "{parts}");
        }
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "Covers public full and reduced H/K output across every built-in format."
)]
fn an_unmarked_audit_lookalike_is_not_an_engine_event() {
    const STATE: &str = "coraza-rs/engine/RequestBodyLimit";
    let message = |text: &str, k_selected: bool, provenance| AuditMessage {
        message: if k_selected { text.to_owned() } else { String::new() },
        error_message: format!("[id \"0\"] [msg \"{STATE}: {text}\"]"),
        rule_id: 0,
        rule_message: format!("{STATE}: {text}"),
        provenance,
        data: AuditMessageData {
            id: 0,
            severity: 2,
            msg: if k_selected { text.to_owned() } else { String::new() },
            tags: vec![STATE.to_owned(), "coraza-rs/engine/Enforced".to_owned()],
            raw: STATE.to_owned(),
            ..AuditMessageData::default()
        },
        ..AuditMessage::default()
    };

    for (parts, k_selected) in [("AHZ", false), ("AKZ", true)] {
        let audit = coraza::audit_log::AuditLog {
            parts: parse_audit_log_parts(parts).unwrap(),
            transaction: coraza::audit_log::AuditTransaction {
                is_interrupted: true,
                interruption_rule_id: Some(0),
                ..coraza::audit_log::AuditTransaction::default()
            },
            messages: vec![
                message("caller-built lookalike", k_selected, None),
                message(
                    "explicitly marked event",
                    k_selected,
                    Some(AuditMessageProvenance::EngineEvent { enforced: true }),
                ),
            ],
        };

        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            let output = audit.format(format);
            let document: serde_json::Value = serde_json::from_str(&output).unwrap();
            let entries = serialized_audit_entries(format, &document);
            assert_eq!(entries.len(), 2, "{parts} {format:?}: {output}");
            match format {
                AuditLogFormat::Json => {
                    let ordinary = serialized_audit_entry_data(format, entries.first().unwrap());
                    let event = serialized_audit_entry_data(format, entries.get(1).unwrap());
                    assert_eq!(
                        ordinary.get("raw").and_then(serde_json::Value::as_str),
                        Some(STATE),
                        "{parts}: unmarked content remains ordinary: {output}"
                    );
                    assert_eq!(
                        event.get("raw").and_then(serde_json::Value::as_str),
                        Some(if k_selected { STATE } else { "" }),
                        "{parts}: only an explicit event gets H-only K suppression: {output}"
                    );
                },
                AuditLogFormat::JsonLegacy => {
                    let event_identity = format!("{STATE}: explicitly marked event");
                    assert_eq!(
                        entries.first().and_then(serde_json::Value::as_str),
                        Some(if k_selected { "caller-built lookalike" } else { "" }),
                        "{parts}: unmarked text uses the ordinary message field: {output}"
                    );
                    assert_eq!(
                        entries.get(1).and_then(serde_json::Value::as_str),
                        Some(event_identity.as_str()),
                        "explicit event identity survives without K: {output}"
                    );
                },
                AuditLogFormat::Ocsf => {
                    assert_eq!(
                        entries
                            .first()
                            .and_then(|entry| entry.get("name"))
                            .and_then(serde_json::Value::as_str),
                        k_selected.then_some("caller-built lookalike"),
                        "{parts}: unmarked content is not given an OCSF engine name: {output}"
                    );
                    assert_eq!(
                        entries
                            .get(1)
                            .and_then(|entry| entry.get("name"))
                            .and_then(serde_json::Value::as_str),
                        Some(if k_selected {
                            "explicitly marked event"
                        } else {
                            "coraza-rs/engine/RequestBodyLimit: explicitly marked event"
                        }),
                        "explicit provenance controls the H-only OCSF identity: {output}"
                    );
                },
                AuditLogFormat::Native => unreachable!(),
            }
        }

        let mut reduced = audit.clone();
        reduced.transaction.request.uri = format!("/{}", "p".repeat(8 * 1024));
        reduced.transaction.producer = Some(coraza::audit_log::AuditProducer {
            connector: "c".repeat(8 * 1024),
            rulesets: vec!["r".repeat(8 * 1024)],
            ..coraza::audit_log::AuditProducer::default()
        });
        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            let (output, truncated) = reduced.format_bounded(format, 4096);
            assert!(truncated, "{parts} {format:?}: metadata forces a reduced copy");
            assert!(output.len() <= 4096, "{parts} {format:?}: {} bytes", output.len());
            let document: serde_json::Value = serde_json::from_str(&output).unwrap();
            let entries = serialized_audit_entries(format, &document);
            let event = entries
                .iter()
                .find(|entry| {
                    if format == AuditLogFormat::Ocsf && !k_selected {
                        entry
                            .get("name")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|name| name.starts_with(STATE))
                    } else {
                        entry.to_string().contains("explicitly marked event")
                    }
                })
                .unwrap_or_else(|| panic!("{parts} {format:?}: the marked event survives: {output}"));
            if format != AuditLogFormat::JsonLegacy {
                let event = serialized_audit_entry_data(format, event);
                assert_eq!(
                    event.get("raw").and_then(serde_json::Value::as_str),
                    Some(if k_selected { STATE } else { "" }),
                    "{parts}: provenance survives the bounded copy: {output}"
                );
            }
        }

        let native = audit.format(AuditLogFormat::Native);
        assert!(
            native.contains(STATE) || native.contains("explicitly marked event"),
            "{parts}: selected Native evidence remains visible: {native}"
        );
        let (bounded, truncated) = audit.format_bounded(AuditLogFormat::Native, 64);
        assert!(truncated, "{parts}: Native retains its separate final hard-cut");
        assert!(bounded.len() <= 64, "{parts}: {} bytes", bounded.len());
        assert_audit_text_has_no_nul(&bounded, "bounded Native lookalike output");
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "Checks typed cause priority and K suppression with hostile public records."
)]
fn bounded_audit_pins_typed_enforcement_over_a_textual_lookalike() {
    const STATE: &str = "coraza-rs/engine/RequestBodyLimit";
    let audit = |parts: &str, enforced: bool| {
        let k_selected = parts.contains('K');
        let h_selected = parts.contains('H');
        let mut lookalike_tags = vec![STATE.to_owned(), "coraza-rs/engine/Enforced".to_owned()];
        lookalike_tags.extend((0..48).map(|index| format!("caller tag {index} {}", "x".repeat(128))));
        let lookalike = AuditMessage {
            message: if k_selected {
                "caller-built lookalike".to_owned()
            } else {
                String::new()
            },
            error_message: if h_selected {
                format!("[id \"0\"] [msg \"{STATE}: caller-built lookalike\"]")
            } else {
                String::new()
            },
            rule_id: 0,
            rule_message: format!("{STATE}: caller-built lookalike"),
            data: AuditMessageData {
                id: 0,
                msg: if k_selected {
                    "caller-built lookalike".to_owned()
                } else {
                    String::new()
                },
                tags: lookalike_tags,
                raw: STATE.to_owned(),
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        };
        let description = format!("explicitly marked event \"\\\0{}", "x".repeat(4096));
        let visible_text = if h_selected {
            description.as_str()
        } else {
            "explicitly marked event"
        };
        let event = AuditMessage {
            message: if k_selected {
                "explicitly marked event".to_owned()
            } else {
                String::new()
            },
            error_message: if h_selected {
                format!("[id \"0\"] [msg \"{STATE}: {description}\"]")
            } else {
                String::new()
            },
            rule_id: 0,
            rule_message: format!("{STATE}: {visible_text}"),
            provenance: Some(AuditMessageProvenance::EngineEvent { enforced }),
            data: AuditMessageData {
                id: 0,
                severity: 2,
                msg: if k_selected {
                    "explicitly marked event".to_owned()
                } else {
                    String::new()
                },
                data: if k_selected {
                    "hostile \"\\\0 data".to_owned()
                } else {
                    String::new()
                },
                tags: if enforced {
                    vec![STATE.to_owned(), "coraza-rs/engine/Enforced".to_owned()]
                } else {
                    vec![STATE.to_owned()]
                },
                raw: STATE.to_owned(),
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        };
        coraza::audit_log::AuditLog {
            parts: parse_audit_log_parts(parts).unwrap(),
            transaction: coraza::audit_log::AuditTransaction {
                is_interrupted: enforced,
                interruption_rule_id: enforced.then_some(0),
                ..coraza::audit_log::AuditTransaction::default()
            },
            messages: vec![lookalike, event],
        }
    };

    for (parts, k_selected) in [("AHZ", false), ("AKZ", true)] {
        let entry = audit(parts, true);
        let output_limit = if k_selected { 960 } else { 768 };
        let (output, truncated) = entry.format_bounded(AuditLogFormat::Json, output_limit);
        assert!(truncated, "{parts}: hostile messages force reduction");
        assert!(output.len() <= output_limit, "{parts}: {} bytes", output.len());
        assert_audit_text_has_no_nul(&output, "bounded explicitly marked event");
        let document: serde_json::Value = serde_json::from_str(&output).unwrap();
        let messages = serialized_audit_entries(AuditLogFormat::Json, &document);
        assert!(
            messages.iter().any(|message| message.to_string().contains(STATE)),
            "{parts}: the marked event identity survives: {output}"
        );
        assert!(output.contains(STATE), "{parts}: {output}");
        assert!(
            !output.contains("caller-built lookalike"),
            "{parts}: the enforcing event wins the tight slot"
        );

        let message = messages
            .iter()
            .find(|message| {
                serialized_audit_entry_data(AuditLogFormat::Json, message)
                    .get("severity")
                    .and_then(serde_json::Value::as_i64)
                    == Some(2)
            })
            .unwrap_or_else(|| panic!("{parts}: no marked event data: {output}"));
        let data = serialized_audit_entry_data(AuditLogFormat::Json, message);
        assert_eq!(
            data.get("severity").and_then(serde_json::Value::as_i64),
            Some(2),
            "{output}"
        );
        if k_selected {
            let tags = data.get("tags").and_then(serde_json::Value::as_array).unwrap();
            assert_eq!(
                tags.iter().filter_map(serde_json::Value::as_str).collect::<Vec<_>>(),
                [STATE, "coraza-rs/engine/Enforced"],
                "{output}"
            );
            assert_eq!(
                data.get("raw").and_then(serde_json::Value::as_str),
                Some(STATE),
                "{output}"
            );
        } else {
            assert!(
                data.get("tags")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(Vec::is_empty),
                "{output}"
            );
            assert_eq!(
                data.get("raw").and_then(serde_json::Value::as_str),
                Some(""),
                "{output}"
            );
        }
    }
}

#[test]
fn an_explicit_event_with_hostile_identity_text_stays_bounded() {
    const PREFIX: &str = "coraza-rs/engine/";
    let identity = format!("{PREFIX}{}", "s".repeat(64 * 1024));
    let audit = coraza::audit_log::AuditLog {
        parts: parse_audit_log_parts("AHZ").unwrap(),
        transaction: coraza::audit_log::AuditTransaction {
            is_interrupted: true,
            interruption_rule_id: Some(0),
            ..coraza::audit_log::AuditTransaction::default()
        },
        messages: vec![AuditMessage {
            error_message: identity.clone(),
            rule_id: 0,
            rule_message: identity.clone(),
            provenance: Some(AuditMessageProvenance::EngineEvent { enforced: true }),
            data: AuditMessageData {
                id: 0,
                severity: 2,
                tags: vec![identity.clone(), "coraza-rs/engine/Enforced".to_owned()],
                raw: identity,
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        }],
    };

    let (output, truncated) = audit.format_bounded(AuditLogFormat::Json, 2048);
    assert!(truncated);
    assert!(output.len() <= 2048);
    assert_audit_text_has_no_nul(&output, "bounded hostile engine identity");
    let document: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(
        document.pointer("/messages/0").is_none() && !output.contains(PREFIX),
        "a malformed, unbounded identity without a delimiter is omitted, not prefix-truncated: {output}"
    );

    let mut fitting = audit;
    let identity = format!("{PREFIX}malformed");
    let message = fitting.messages.first_mut().unwrap();
    message.error_message.clone_from(&identity);
    message.rule_message.clone_from(&identity);
    let (output, truncated) = fitting.format_bounded(AuditLogFormat::Json, 2048);
    assert!(!truncated, "a complete malformed identity still fits");
    assert!(output.contains(&identity), "{output}");
}

#[test]
fn bounded_explicit_engine_identities_never_emit_partial_long_states() {
    const ENGINE_PREFIX: &str = "coraza-rs/engine/";
    let states = [
        "s".repeat(127),
        format!("{}é", "s".repeat(126)),
        format!("{}é", "s".repeat(127)),
    ];

    for (state, expected_len) in states.into_iter().zip([127, 128, 129]) {
        assert_eq!(state.len(), expected_len);
        let tag = format!("{ENGINE_PREFIX}{state}");
        let state_prefix = format!("{tag}: ");
        let identity = format!("{state_prefix}{}", "d".repeat(4096));
        let audit = coraza::audit_log::AuditLog {
            parts: parse_audit_log_parts("AHZ").unwrap(),
            transaction: coraza::audit_log::AuditTransaction {
                producer: Some(coraza::audit_log::AuditProducer {
                    connector: "c".repeat(16 * 1024),
                    ..coraza::audit_log::AuditProducer::default()
                }),
                ..coraza::audit_log::AuditTransaction::default()
            },
            messages: vec![AuditMessage {
                error_message: format!("[id \"0\"] [msg \"{identity}\"]"),
                rule_id: 0,
                rule_message: identity,
                provenance: Some(AuditMessageProvenance::EngineEvent { enforced: false }),
                data: AuditMessageData {
                    id: 0,
                    severity: 2,
                    tags: vec![tag.clone()],
                    raw: tag,
                    ..AuditMessageData::default()
                },
                ..AuditMessage::default()
            }],
        };

        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            let (full, truncated) = audit.format_bounded(format, 64 * 1024);
            assert!(!truncated, "{format:?}: the full typed identity fits");
            assert!(full.contains(&state_prefix), "{format:?}: {full}");

            let (adequate, truncated) = audit.format_bounded(format, 4096);
            assert!(truncated, "{format:?}: the producer forces reduction");
            assert!(adequate.len() <= 4096, "{format:?}: {} bytes", adequate.len());
            assert!(adequate.contains(&state_prefix), "{format:?}: {adequate}");

            let (tight, truncated) = audit.format_bounded(format, 512);
            assert!(truncated, "{format:?}: the state prefix cannot fit");
            assert!(tight.len() <= 512, "{format:?}: {} bytes", tight.len());
            assert!(
                serde_json::from_str::<serde_json::Value>(&tight).is_ok(),
                "{format:?}: {tight}"
            );
            assert!(
                !tight.contains(ENGINE_PREFIX),
                "{format:?} retained a typed event without its complete state: {tight}"
            );
        }
    }
}

#[test]
fn native_h_only_audit_contains_engine_and_ordinary_error_lines() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut config = request_config(RuleEngineStatus::On, 4);
    config.audit_log_parts = parse_audit_log_parts("AHZ").unwrap();
    let rule = "SecAction \"id:90,phase:1,pass,log,auditlog,msg:'before engine stop'\"";
    let waf = build_waf(config, rule, Arc::clone(&events));
    let mut tx = waf.new_transaction_with_id("engine-event-h-only");
    tx.process_uri(format!("/{}", "p".repeat(16 * 1024)), "POST", "HTTP/1.1");
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    tx.process_request_headers();

    assert_eq!(
        tx.process_request_body(b"1234")
            .map(|interruption| (interruption.rule_id, interruption.status)),
        Some((0, 413))
    );
    let audit = tx.audit_log();
    assert_eq!(audit.parts, parse_audit_log_parts("AHZ").unwrap());
    let ordinary_line = audit
        .messages
        .iter()
        .find(|message| message.rule_id == 90)
        .unwrap()
        .error_message
        .clone();
    let engine_line = audit
        .messages
        .iter()
        .find(|message| message.rule_id == 0)
        .unwrap()
        .error_message
        .clone();
    let output = audit.format(AuditLogFormat::Native);
    assert!(
        output.lines().any(|line| line == ordinary_line),
        "native H retains the ordinary rule error line: {output:?}"
    );
    assert!(
        output.lines().any(|line| line == engine_line),
        "native H serializes the engine-stop error line: {output:?}"
    );
    assert!(engine_line.contains("coraza-rs/engine/RequestBodyLimit"));
    assert!(!output.contains(rule), "H-only output does not add K rule source");

    for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
        let (bounded, truncated) = audit.format_bounded(format, 1024);
        assert!(truncated, "{format:?}: request header forces reduction");
        assert!(bounded.len() <= 1024, "{format:?}: {} bytes", bounded.len());
        let document: serde_json::Value = serde_json::from_str(&bounded).unwrap();
        assert!(document.is_object(), "{format:?}: expected a JSON object");
        assert!(
            bounded.contains("coraza-rs/engine/RequestBodyLimit"),
            "{format:?}: reduced H-only event lost its state identity: {bounded}"
        );
    }
}

#[test]
fn bounded_h_only_json_keeps_each_real_engine_stop_visible_without_k_metadata() {
    const EXPECTED_STATES: [&str; 2] = ["RequestBodyLimit", "ResponseBodyLimit"];

    let mut config = request_config(RuleEngineStatus::DetectionOnly, 4);
    config.audit_log_parts = parse_audit_log_parts("AHZ").unwrap();
    config.response_body_access = true;
    config.response_body_limit = 4;
    config.response_body_limit_action = BodyLimitAction::Reject;
    config.response_body_mime_types = vec!["text/plain".to_owned()];
    let waf = build_waf(config, "", Arc::new(Mutex::new(Vec::new())));
    let mut tx = waf.new_transaction_with_id("two-h-only-engine-stops");
    tx.process_uri(format!("/{}", "p".repeat(16 * 1024)), "POST", "HTTP/1.1");
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    tx.process_request_headers();
    assert!(
        tx.process_request_body(b"1234").is_none(),
        "DetectionOnly continues after request limit"
    );
    assert_eq!(tx.request_body_stats().supplied, 4);
    assert_eq!(tx.request_body_stats().retained, 4);
    assert!(!tx.request_body_stats().truncated);
    tx.add_response_header("Content-Type", "text/plain");
    tx.process_response_headers(200, "HTTP/1.1");
    assert!(
        tx.process_response_body(b"1234").is_none(),
        "DetectionOnly continues after response limit"
    );
    assert_eq!(tx.response_body_stats().supplied, 4);
    assert_eq!(tx.response_body_stats().retained, 4);
    assert!(!tx.response_body_stats().truncated);
    assert_eq!(tx.engine_events().len(), EXPECTED_STATES.len());

    let audit = tx.audit_log();
    assert_eq!(audit.parts, parse_audit_log_parts("AHZ").unwrap());
    assert_eq!(audit.messages.len(), EXPECTED_STATES.len());
    for (output_limit, retained_count) in [(1024, 1), (1536, 2)] {
        let (output, truncated) = audit.format_bounded(AuditLogFormat::Json, output_limit);
        assert!(truncated, "the real request URI forces bounded reduction");
        assert!(output.len() <= output_limit, "{} bytes", output.len());
        let document: serde_json::Value = serde_json::from_str(&output).unwrap();
        let messages = document
            .pointer("/messages")
            .and_then(serde_json::Value::as_array)
            .unwrap();
        assert_eq!(messages.len(), retained_count, "{output_limit}: {output}");

        for (message, state) in messages.iter().zip(EXPECTED_STATES) {
            let tag = format!("coraza-rs/engine/{state}");
            let data = message.get("data").unwrap();
            assert_eq!(data.get("id").and_then(serde_json::Value::as_i64), Some(0), "{output}");
            assert!(
                message
                    .get("error_message")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|line| line.starts_with(&format!("[id \"0\"] [msg \"{tag}: "))),
                "each retained H-only event starts with its true state identity: {output}"
            );
            assert!(
                data.get("tags")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(Vec::is_empty),
                "H-only output does not leak unselected K tags: {output}"
            );
            assert_eq!(
                data.get("raw").and_then(serde_json::Value::as_str),
                Some(""),
                "H-only output does not leak unselected K raw text: {output}"
            );
        }
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "Exercises the real phase-2 DetectionOnly stop and phase-4 enforcing stop through public transactions."
)]
fn bounded_audits_pin_the_actual_stop_after_rule_engine_is_enabled_in_a_later_phase() {
    const REQUEST_STATE: &str = "coraza-rs/engine/RequestBodyLimit";
    const RESPONSE_STATE: &str = "coraza-rs/engine/ResponseBodyLimit";
    const ENFORCED_TAG: &str = "coraza-rs/engine/Enforced";
    const RULES: &str = "SecAction \"id:901,phase:3,pass,ctl:ruleEngine=On\"";

    for (parts, k_selected) in [("AHZ", false), ("AKZ", true)] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut config = request_config(RuleEngineStatus::DetectionOnly, 4);
        config.audit_log_parts = parse_audit_log_parts(parts).unwrap();
        config.response_body_access = true;
        config.response_body_limit = 4;
        config.response_body_limit_action = BodyLimitAction::Reject;
        config.response_body_mime_types = vec!["text/plain".to_owned()];
        let waf = build_waf(config, RULES, Arc::clone(&events));
        let mut tx = waf.new_transaction_with_id("bounded-enforced-engine-stop");
        tx.process_uri(format!("/{}", "p".repeat(16 * 1024)), "POST", "HTTP/1.1");
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
        tx.process_request_headers();

        assert!(
            tx.process_request_body(b"1234").is_none(),
            "DetectionOnly records the request-body stop without interrupting"
        );
        assert_eq!(
            tx.would_be_interruption().map(|value| (value.rule_id, value.status)),
            Some((0, 413))
        );
        assert!(tx.interruption().is_none());

        tx.add_response_header("Content-Type", "text/plain");
        assert!(tx.process_response_headers(200, "HTTP/1.1").is_none());
        assert!(
            tx.process_response_body(b"1234")
                .is_some_and(|value| (value.rule_id, value.status) == (0, 500)),
            "phase 3 enabled enforcement before the response-body stop"
        );
        assert_eq!(
            tx.would_be_interruption().map(|value| (value.rule_id, value.status)),
            Some((0, 413)),
            "the first DetectionOnly would-be interruption remains unchanged"
        );
        assert_eq!(
            tx.engine_events()
                .iter()
                .map(|event| event.tags().first().map(String::as_str).unwrap_or_default())
                .collect::<Vec<_>>(),
            [REQUEST_STATE, RESPONSE_STATE],
            "transaction events remain in chronological order"
        );
        let logged = events.lock().unwrap();
        assert_eq!(
            logged
                .iter()
                .map(|event| event.tags.first().map(String::as_str).unwrap_or_default())
                .collect::<Vec<_>>(),
            [REQUEST_STATE, RESPONSE_STATE],
            "callback order remains chronological"
        );
        assert_eq!(
            logged.iter().map(|event| event.disruptive).collect::<Vec<_>>(),
            [false, true],
            "only the response-body event actually enforced the stop"
        );
        drop(logged);

        let audit = tx.audit_log();
        assert!(audit.transaction.is_interrupted);
        assert_eq!(audit.transaction.interruption_rule_id, Some(0));
        assert_eq!(
            audit.messages.iter().map(|message| message.rule_id).collect::<Vec<_>>(),
            [0, 0],
            "the public typed audit order stays chronological"
        );

        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            let output_limit = match (format, k_selected) {
                (AuditLogFormat::Json, false) | (AuditLogFormat::Ocsf, true) => 1024,
                (AuditLogFormat::Json, true) => 768,
                (AuditLogFormat::JsonLegacy, _) => 540,
                (AuditLogFormat::Ocsf, false) => 960,
                (AuditLogFormat::Native, _) => unreachable!(),
            };
            let (output, truncated) = audit.format_bounded(format, output_limit);
            assert!(truncated, "{parts} {format:?}: the long URI forces reduction");
            assert!(
                output.len() <= output_limit,
                "{parts} {format:?}: {} bytes",
                output.len()
            );
            assert_audit_text_has_no_nul(&output, "bounded JSON-family audit");
            let document: serde_json::Value = serde_json::from_str(&output).unwrap();
            let messages = match format {
                AuditLogFormat::Json => document.pointer("/messages").and_then(serde_json::Value::as_array),
                AuditLogFormat::JsonLegacy => document
                    .pointer("/audit_data/messages")
                    .and_then(serde_json::Value::as_array),
                AuditLogFormat::Ocsf => document.get("enrichments").and_then(serde_json::Value::as_array),
                AuditLogFormat::Native => unreachable!(),
            };
            assert_eq!(
                messages.map(Vec::len),
                Some(1),
                "{parts} {format:?}: only the actual enforcing event fits: {output}"
            );
            assert!(
                output.contains(RESPONSE_STATE),
                "{parts} {format:?}: bounded output retained the actual event: {output}"
            );
            assert!(
                !output.contains(REQUEST_STATE),
                "{parts} {format:?}: the earlier would-be stop was not misrepresented as the cause: {output}"
            );
        }
        assert!(
            audit
                .messages
                .get(1)
                .unwrap()
                .data
                .tags
                .iter()
                .any(|tag| tag == ENFORCED_TAG),
            "the typed event carries an explicit, public enforcement tag"
        );
    }
}

#[test]
fn bounded_multi_event_ocsf_keeps_h_only_engine_names_visible() {
    const EXPECTED_STATES: [&str; 2] = ["RequestBodyLimit", "ResponseBodyLimit"];

    for (parts, k_selected, output_limit) in [("AHZ", false, 1160), ("AKZ", true, 1536)] {
        let mut config = request_config(RuleEngineStatus::DetectionOnly, 4);
        config.audit_log_parts = parse_audit_log_parts(parts).unwrap();
        config.response_body_access = true;
        config.response_body_limit = 4;
        config.response_body_limit_action = BodyLimitAction::Reject;
        config.response_body_mime_types = vec!["text/plain".to_owned()];
        let waf = build_waf(config, "", Arc::new(Mutex::new(Vec::new())));
        let mut tx = waf.new_transaction_with_id("two-ocsf-engine-stops");
        tx.process_uri(format!("/{}", "p".repeat(16 * 1024)), "POST", "HTTP/1.1");
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
        tx.process_request_headers();
        assert!(tx.process_request_body(b"1234").is_none());
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");
        assert!(tx.process_response_body(b"1234").is_none());
        assert_eq!(tx.engine_events().len(), EXPECTED_STATES.len());

        let audit = tx.audit_log();
        assert_eq!(audit.parts, parse_audit_log_parts(parts).unwrap());
        assert_eq!(audit.messages.len(), EXPECTED_STATES.len());
        let (output, truncated) = audit.format_bounded(AuditLogFormat::Ocsf, output_limit);
        assert!(truncated, "{parts}: the long request URI forces reduction");
        assert!(output.len() <= output_limit, "{parts}: {} bytes", output.len());
        let document: serde_json::Value = serde_json::from_str(&output).unwrap();
        let enrichments = document
            .get("enrichments")
            .and_then(serde_json::Value::as_array)
            .unwrap();
        assert_eq!(enrichments.len(), EXPECTED_STATES.len(), "{parts}: {output}");

        for (enrichment, state) in enrichments.iter().zip(EXPECTED_STATES) {
            let name = enrichment
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            assert!(!name.is_empty(), "{parts}: retained {state} has no name: {output}");
            let tag = format!("coraza-rs/engine/{state}");
            let data: serde_json::Value =
                serde_json::from_str(enrichment.get("data").and_then(serde_json::Value::as_str).unwrap()).unwrap();
            assert_eq!(data.get("id").and_then(serde_json::Value::as_i64), Some(0), "{output}");

            if k_selected {
                let tags = data
                    .get("tags")
                    .and_then(serde_json::Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let raw = data.get("raw").and_then(serde_json::Value::as_str).unwrap_or_default();
                assert!(
                    raw == tag || tags.iter().any(|candidate| candidate.as_str() == Some(&tag)),
                    "{parts}: selected K retains one complete state label: {output}"
                );
            } else {
                assert!(
                    name.starts_with(&format!("{tag}: ")),
                    "{parts}: retained H-only event has a complete state-first prefix: {output}"
                );
                assert!(
                    data.get("tags")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(Vec::is_empty),
                    "{parts}: H-only output does not leak unselected K tags: {output}"
                );
                assert_eq!(
                    data.get("raw").and_then(serde_json::Value::as_str),
                    Some(""),
                    "{parts}: H-only output does not leak unselected K raw text: {output}"
                );
                assert_eq!(
                    data.get("msg").and_then(serde_json::Value::as_str),
                    Some(""),
                    "{parts}: H-only output does not expose K message data: {output}"
                );
            }
        }

        if !k_selected {
            let (tiny, tiny_truncated) = audit.format_bounded(AuditLogFormat::Ocsf, 31);
            assert!(tiny_truncated);
            assert_eq!(tiny, r#"{"unmapped":{"truncated":true}}"#);
            assert!(!tiny.contains("enrichments"), "no unidentified event fits: {tiny}");
        }
    }
}

#[test]
fn bounded_h_only_json_keeps_a_real_rule_fallback_before_a_real_engine_event() {
    const OUTPUT_LIMIT: usize = 1536;
    const STATE: &str = "coraza-rs/engine/RequestBodyLimit";
    const RULE: &str = "SecAction \"id:90,phase:1,pass,log,auditlog,msg:'before engine stop'\"";

    let mut config = request_config(RuleEngineStatus::DetectionOnly, 4);
    config.audit_log_parts = parse_audit_log_parts("AHZ").unwrap();
    let waf = build_waf(config, RULE, Arc::new(Mutex::new(Vec::new())));
    let mut tx = waf.new_transaction_with_id("real-rule-and-engine-stop");
    tx.process_uri(format!("/{}", "p".repeat(16 * 1024)), "POST", "HTTP/1.1");
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    tx.process_request_headers();
    assert_eq!(
        tx.matched_rules()
            .iter()
            .map(coraza::audit_log::MatchedRule::rule_id)
            .collect::<Vec<_>>(),
        [90],
        "the ordinary phase-one rule matched before the body limit"
    );
    assert!(
        tx.process_request_body(b"1234").is_none(),
        "DetectionOnly records but does not block"
    );

    let audit = tx.audit_log();
    assert_eq!(
        audit.messages.iter().map(|message| message.rule_id).collect::<Vec<_>>(),
        [90, 0],
        "the synthetic stop follows the real rule message"
    );
    let (output, truncated) = audit.format_bounded(AuditLogFormat::Json, OUTPUT_LIMIT);
    assert!(truncated, "the real request URI forces reduction");
    assert!(output.len() <= OUTPUT_LIMIT);
    let document: serde_json::Value = serde_json::from_str(&output).unwrap();
    let messages = document
        .pointer("/messages")
        .and_then(serde_json::Value::as_array)
        .unwrap();
    assert_eq!(messages.len(), 2, "{output}");
    let pinned = messages.first().unwrap();
    let event = messages.get(1).unwrap();
    assert!(
        pinned
            .get("error_message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|line| line.contains("[id \"90\"]")),
        "the real-rule fallback remains pinned: {output}"
    );
    assert!(
        event
            .get("error_message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|line| line.starts_with(&format!("[id \"0\"] [msg \"{STATE}: "))),
        "the non-pinned engine event keeps its state-first identity: {output}"
    );
    assert!(
        event
            .pointer("/data/tags")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty),
        "H-only output does not copy unselected K tags"
    );
    assert_eq!(
        event.pointer("/data/raw").and_then(serde_json::Value::as_str),
        Some(""),
        "H-only output does not copy unselected K raw data"
    );
}

#[test]
fn native_k_only_audit_has_a_line_for_an_engine_stop() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut config = request_config(RuleEngineStatus::On, 4);
    config.audit_log_parts = parse_audit_log_parts("AKZ").unwrap();
    let rule = "SecAction \"id:90,phase:1,pass,log,auditlog,msg:'before engine stop'\"";
    let waf = build_waf(config, rule, Arc::clone(&events));
    let mut tx = waf.new_transaction_with_id("engine-event-k-only");
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    tx.process_request_headers();
    assert_eq!(tx.matched_rules().len(), 1);

    assert_eq!(
        tx.process_request_body(b"1234")
            .map(|interruption| (interruption.rule_id, interruption.status)),
        Some((0, 413))
    );
    let audit = tx.audit_log();
    assert_eq!(audit.parts, parse_audit_log_parts("AKZ").unwrap());
    let output = audit.format(AuditLogFormat::Native);
    let real_rule = audit.messages.first().unwrap().data.raw.as_str();
    assert_eq!(real_rule, rule, "audit data preserves the real rule source");
    assert!(
        output.lines().any(|line| line == real_rule),
        "native K rendering of real rule entries is unchanged: {output:?}"
    );
    assert!(
        output.lines().any(|line| line == "coraza-rs/engine/RequestBodyLimit"),
        "native K output should identify the synthetic stop, not emit a blank line: {output:?}"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "Checks H/K selection, all formats, and compact retention from a real transaction."
)]
fn bounded_formats_pin_a_real_id_zero_engine_event_ahead_of_an_ordinary_id_zero_message() {
    const OUTPUT_LIMIT: usize = 1024;
    const ORDINARY_MESSAGE: &str = "ordinary id-zero rule";
    const ENGINE_IDENTITY: &str = "coraza-rs/engine/RequestBodyLimit";

    for (parts, k_selected) in [("AHKZ", true), ("AHZ", false)] {
        let mut config = request_config(RuleEngineStatus::On, 4);
        config.audit_log_parts = parse_audit_log_parts(parts).unwrap();
        let waf = build_waf(config, "", Arc::new(Mutex::new(Vec::new())));
        let mut tx = request(&waf, None);
        assert_eq!(
            tx.process_request_body(b"1234")
                .map(|interruption| interruption.rule_id),
            Some(0),
            "{parts}: the real engine stop interrupts"
        );

        let mut audit = tx.audit_log();
        assert_eq!(audit.messages.len(), 1, "{parts}: one real engine event");
        let engine_event = audit.messages.pop().unwrap();
        if k_selected {
            assert!(
                engine_event.data.tags.iter().any(|tag| tag == ENGINE_IDENTITY),
                "{parts}: the retained message came from the engine"
            );
        } else {
            assert!(
                engine_event.error_message.contains(ENGINE_IDENTITY),
                "{parts}: the retained message came from the engine"
            );
        }
        audit.messages.push(AuditMessage {
            message: if k_selected {
                ORDINARY_MESSAGE.to_owned()
            } else {
                String::new()
            },
            error_message: format!("[id \"0\"] [msg \"{ORDINARY_MESSAGE}\"]"),
            data: if k_selected {
                AuditMessageData {
                    id: 0,
                    msg: ORDINARY_MESSAGE.to_owned(),
                    tags: vec![ENGINE_IDENTITY.to_owned()],
                    raw: ENGINE_IDENTITY.to_owned(),
                    ..AuditMessageData::default()
                }
            } else {
                AuditMessageData {
                    id: 0,
                    tags: vec![ENGINE_IDENTITY.to_owned()],
                    raw: ENGINE_IDENTITY.to_owned(),
                    ..AuditMessageData::default()
                }
            },
            rule_id: 0,
            rule_message: ORDINARY_MESSAGE.to_owned(),
            ..AuditMessage::default()
        });
        audit.messages.push(engine_event);
        let producer = audit.transaction.producer.as_mut().unwrap();
        producer.connector = "c".repeat(16 * 1024);
        producer.rulesets = vec!["r".repeat(16 * 1024)];

        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            let (formatted, truncated) = audit.format_bounded(format, OUTPUT_LIMIT);
            assert!(truncated, "{parts} {format:?}: producer forces reduction");
            assert!(
                formatted.len() <= OUTPUT_LIMIT,
                "{parts} {format:?}: {} bytes",
                formatted.len()
            );
            let document: serde_json::Value = serde_json::from_str(&formatted).unwrap();
            let messages = match format {
                AuditLogFormat::Json => document.pointer("/messages").and_then(serde_json::Value::as_array),
                AuditLogFormat::JsonLegacy => document
                    .pointer("/audit_data/messages")
                    .and_then(serde_json::Value::as_array),
                AuditLogFormat::Ocsf => document.get("enrichments").and_then(serde_json::Value::as_array),
                AuditLogFormat::Native => unreachable!(),
            };
            assert_eq!(
                messages.map(Vec::len),
                Some(1),
                "{parts} {format:?}: the fixture must reduce to one pinned message: {formatted}"
            );
            let identity = match format {
                AuditLogFormat::Json => document
                    .pointer("/messages/0/error_message")
                    .and_then(serde_json::Value::as_str),
                AuditLogFormat::JsonLegacy => document
                    .pointer("/audit_data/messages/0")
                    .and_then(serde_json::Value::as_str),
                AuditLogFormat::Ocsf if !k_selected => document
                    .pointer("/enrichments/0/name")
                    .and_then(serde_json::Value::as_str),
                AuditLogFormat::Ocsf => document.get("message").and_then(serde_json::Value::as_str),
                AuditLogFormat::Native => unreachable!(),
            };
            assert!(
                identity.is_some_and(|identity| identity.contains(ENGINE_IDENTITY)),
                "{parts} {format:?}: ordinary ID zero displaced the real engine event: {formatted}"
            );
            if k_selected {
                let tags = match format {
                    AuditLogFormat::Json => document
                        .pointer("/messages/0/data/tags")
                        .and_then(serde_json::Value::as_array)
                        .cloned(),
                    AuditLogFormat::Ocsf => {
                        let data: serde_json::Value = serde_json::from_str(
                            document
                                .pointer("/enrichments/0/data")
                                .and_then(serde_json::Value::as_str)
                                .unwrap(),
                        )
                        .unwrap();
                        data.get("tags").and_then(serde_json::Value::as_array).cloned()
                    },
                    AuditLogFormat::JsonLegacy | AuditLogFormat::Native => None,
                };
                assert!(
                    tags.is_none_or(|tags| tags.is_empty()),
                    "{format:?}: reduction may omit structured state tags while keeping textual identity: {formatted}"
                );
            }
        }
    }
}

#[test]
fn a_response_body_reject_stop_is_logged_and_audited_in_both_enforcing_modes() {
    for (engine, enforced) in [(RuleEngineStatus::On, true), (RuleEngineStatus::DetectionOnly, false)] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut config = request_config(engine, 4);
        config.request_body_access = false;
        config.response_body_access = true;
        config.response_body_limit = 4;
        config.response_body_limit_action = BodyLimitAction::Reject;
        config.response_body_mime_types = vec!["text/plain".to_owned()];
        let waf = build_waf(config, "", Arc::clone(&events));
        let mut tx = waf.new_transaction_with_id("engine-event-response");
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");

        let interruption = tx.process_response_body(b"1234");
        if enforced {
            assert_eq!(
                interruption.map(|value| (value.rule_id, value.status, value.action, value.data)),
                Some((0, 500, "deny".to_owned(), String::new()))
            );
            assert!(tx.would_be_interruption().is_none());
        } else {
            assert!(interruption.is_none());
            assert!(tx.interruption().is_none());
            assert_eq!(
                tx.would_be_interruption().map(|value| (
                    value.rule_id,
                    value.status,
                    value.action.as_str(),
                    value.data.as_str()
                )),
                Some((0, 500, "deny", ""))
            );
        }
        let stats = tx.response_body_stats();
        assert_eq!(stats.supplied, 4, "the limit-boundary body is counted once");
        assert_eq!(
            stats.retained,
            if enforced { 0 } else { 4 },
            "On refuses the body; DetectionOnly still ingests it"
        );
        assert_eq!(
            stats.truncated, enforced,
            "only the enforced Reject path marks the exact-limit bytes refused"
        );
        assert!(tx.matched_rules().is_empty(), "engine events are not rule matches");
        assert_logged_and_audited_stop(
            &tx,
            &events,
            ExpectedEngineStop {
                state: "ResponseBodyLimit",
                status: 500,
                message: "ResponseBodyLimit",
                disruptive: enforced,
                transaction_id: "engine-event-response",
            },
        );
    }
}

#[test]
fn relevant_only_audits_an_engine_event_without_a_rule_match() {
    for (engine, enforced) in [(RuleEngineStatus::On, true), (RuleEngineStatus::DetectionOnly, false)] {
        let audits = Arc::new(Mutex::new(Vec::new()));
        let callback_audits = Arc::clone(&audits);
        let mut config = request_config(engine, 4);
        config.audit_engine = AuditEngineStatus::RelevantOnly;
        let mut parser = Parser::new();
        *parser.config_mut() = config;
        parser.on_audit_log(move |entry| {
            callback_audits.lock().unwrap().push(
                entry
                    .messages
                    .iter()
                    .map(|message| (message.rule_id, message.data.tags.clone()))
                    .collect::<Vec<_>>(),
            );
        });
        let waf = parser.into_waf().unwrap();
        let mut tx = request(&waf, None);
        let interruption = tx.process_request_body(b"1234");
        if enforced {
            assert_eq!(interruption.map(|value| (value.rule_id, value.status)), Some((0, 413)));
            assert!(tx.would_be_interruption().is_none());
        } else {
            assert!(interruption.is_none(), "DetectionOnly does not interrupt");
            assert!(tx.interruption().is_none());
            assert_eq!(
                tx.would_be_interruption().map(|value| (value.rule_id, value.status)),
                Some((0, 413))
            );
        }
        let audit = tx.audit_log();
        assert_eq!(audit.transaction.is_interrupted, enforced, "{engine:?}");
        assert_eq!(
            audit.transaction.interruption_rule_id,
            enforced.then_some(0),
            "{engine:?}: DetectionOnly keeps the public enforced interruption ID unset"
        );
        assert!(tx.matched_rules().is_empty(), "the transaction has no rule match");
        tx.finish().unwrap();

        let expected_tags = if enforced {
            vec![
                "coraza-rs/engine/RequestBodyLimit".to_owned(),
                "coraza-rs/engine/Enforced".to_owned(),
            ]
        } else {
            vec!["coraza-rs/engine/RequestBodyLimit".to_owned()]
        };
        assert_eq!(
            audits.lock().unwrap().as_slice(),
            [vec![(0, expected_tags)]],
            "{engine:?}: an engine-stop-only transaction is relevant without a status filter"
        );
    }
}

#[test]
fn a_relevant_status_filter_still_overrides_engine_event_relevance() {
    for (engine, enforced) in [(RuleEngineStatus::On, true), (RuleEngineStatus::DetectionOnly, false)] {
        for (status_filter, should_audit) in [("^413$", true), ("^403$", false)] {
            let audits = Arc::new(Mutex::new(Vec::new()));
            let callback_audits = Arc::clone(&audits);
            let mut config = request_config(engine, 4);
            config.audit_engine = AuditEngineStatus::RelevantOnly;
            config.audit_log_relevant_status = status_filter.to_owned();
            let mut parser = Parser::new();
            *parser.config_mut() = config;
            parser.on_audit_log(move |entry| {
                callback_audits.lock().unwrap().push(
                    entry
                        .messages
                        .iter()
                        .map(|message| (message.rule_id, message.data.tags.clone()))
                        .collect::<Vec<_>>(),
                );
            });
            let waf = parser.into_waf().unwrap();
            let mut tx = request(&waf, None);
            let interruption = tx.process_request_body(b"1234");
            if enforced {
                assert_eq!(interruption.map(|value| (value.rule_id, value.status)), Some((0, 413)));
                assert!(tx.would_be_interruption().is_none());
            } else {
                assert!(interruption.is_none(), "DetectionOnly does not interrupt");
                assert!(tx.interruption().is_none());
                assert_eq!(
                    tx.would_be_interruption().map(|value| (value.rule_id, value.status)),
                    Some((0, 413))
                );
            }
            let audit = tx.audit_log();
            assert_eq!(audit.transaction.is_interrupted, enforced, "{engine:?}");
            assert_eq!(
                audit.transaction.interruption_rule_id,
                enforced.then_some(0),
                "{engine:?} with {status_filter}: DetectionOnly keeps the public enforced interruption ID unset"
            );
            assert!(tx.matched_rules().is_empty());
            tx.finish().unwrap();

            let audits = audits.lock().unwrap();
            if should_audit {
                let expected_tags = if enforced {
                    vec![
                        "coraza-rs/engine/RequestBodyLimit".to_owned(),
                        "coraza-rs/engine/Enforced".to_owned(),
                    ]
                } else {
                    vec!["coraza-rs/engine/RequestBodyLimit".to_owned()]
                };
                assert_eq!(
                    audits.as_slice(),
                    [vec![(0, expected_tags)]],
                    "{engine:?} with {status_filter}: matching status audits the engine event"
                );
            } else {
                assert!(
                    audits.is_empty(),
                    "{engine:?} with {status_filter}: nonmatching status excludes the event"
                );
            }
            drop(audits);
        }
    }
}

#[test]
fn a_panicking_error_log_callback_cannot_suppress_an_engine_interruption_or_its_body_stats() {
    for (is_request, body, expected_status) in [
        (true, &b"1234"[..], 413),
        (true, &b"12345"[..], 413),
        (false, &b"1234"[..], 500),
        (false, &b"12345"[..], 500),
    ] {
        let mut config = request_config(RuleEngineStatus::On, 4);
        config.request_body_access = is_request;
        config.response_body_access = !is_request;
        config.response_body_limit = 4;
        config.response_body_limit_action = BodyLimitAction::Reject;
        config.response_body_mime_types = vec!["text/plain".to_owned()];
        let mut parser = Parser::new();
        *parser.config_mut() = config;
        parser.on_error_log(|_| std::panic::panic_any("engine stop callback"));
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("panicking-body-reject");
        if is_request {
            tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
            tx.process_request_headers();
        } else {
            tx.add_response_header("Content-Type", "text/plain");
            tx.process_response_headers(200, "HTTP/1.1");
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if is_request {
                tx.process_request_body(body);
            } else {
                tx.process_response_body(body);
            }
        }));
        assert!(result.is_err(), "the host callback still unwinds");
        assert_eq!(
            tx.interruption().map(|value| (value.rule_id, value.status)),
            Some((0, expected_status)),
            "the event and interruption are stored before the callback"
        );
        assert_eq!(tx.engine_events().len(), 1);
        assert!(tx.matched_rules().is_empty());

        let stats = if is_request {
            tx.request_body_stats()
        } else {
            tx.response_body_stats()
        };
        assert_eq!(stats.supplied, body.len() as u64, "refused bytes are recorded first");
        assert_eq!(stats.retained, 0, "On rejects rather than retaining bytes");
        assert_eq!(stats.inspected, 0);
        assert!(stats.truncated);

        let retry = if is_request {
            tx.process_request_body(b"ignored")
        } else {
            tx.process_response_body(b"ignored")
        };
        assert_eq!(
            retry.map(|value| (value.rule_id, value.status)),
            Some((0, expected_status)),
            "a retry cannot replace the first interruption"
        );
        assert_eq!(
            if is_request {
                tx.request_body_stats()
            } else {
                tx.response_body_stats()
            },
            stats,
            "begin_phase ignores bytes after the stored interruption"
        );
    }
}

#[test]
fn a_multipart_upload_ban_is_logged_and_audited_in_both_enforcing_modes() {
    const BODY: &[u8] =
        b"--b\r\nContent-Disposition: form-data; name=\"up\"; filename=\"x.txt\"\r\n\r\nPAYLOAD\r\n--b--\r\n";
    for (engine, enforced) in [(RuleEngineStatus::On, true), (RuleEngineStatus::DetectionOnly, false)] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut config = request_config(engine, 1 << 20);
        config.reject_multipart_file_uploads = true;
        let waf = build_waf(config, "", Arc::clone(&events));
        let mut tx = waf.new_transaction_with_id("engine-event-upload");
        tx.add_request_header("Content-Type", "multipart/form-data; boundary=b");
        tx.process_request_headers();

        let interruption = tx.process_request_body(BODY);
        if enforced {
            assert_eq!(
                interruption.map(|value| (value.rule_id, value.status, value.action, value.data)),
                Some((
                    0,
                    413,
                    "deny".to_owned(),
                    "multipart file uploads are unavailable on this host".to_owned()
                ))
            );
        } else {
            assert!(interruption.is_none());
            assert_eq!(
                tx.would_be_interruption()
                    .map(|value| (value.rule_id, value.status, value.data.as_str())),
                Some((0, 413, "multipart file uploads are unavailable on this host"))
            );
        }
        assert!(tx.matched_rules().is_empty(), "engine events are not rule matches");

        assert_logged_and_audited_stop(
            &tx,
            &events,
            ExpectedEngineStop {
                state: "MultipartUploadBan",
                status: 413,
                message: "multipart file uploads are unavailable on this host",
                disruptive: enforced,
                transaction_id: "engine-event-upload",
            },
        );
    }
}

#[test]
fn detection_only_logs_later_engine_stops_without_replacing_the_first_interruption() {
    const BODY: &[u8] =
        b"--b\r\nContent-Disposition: form-data; name=\"up\"; filename=\"x.txt\"\r\n\r\nPAYLOAD\r\n--b--\r\n";
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut config = request_config(RuleEngineStatus::DetectionOnly, 4);
    config.reject_multipart_file_uploads = true;
    let waf = build_waf(config, "", Arc::clone(&events));
    let mut tx = waf.new_transaction_with_id("engine-event-first-stop");
    tx.add_request_header("Content-Type", "multipart/form-data; boundary=b");
    tx.process_request_headers();

    assert!(tx.process_request_body(BODY).is_none());
    let stats = tx.request_body_stats();
    assert_eq!(stats.supplied, BODY.len() as u64, "DetectionOnly ingests the body once");
    assert_eq!(stats.retained, 4);
    assert!(stats.truncated, "the processor retains the bounded prefix");
    assert_eq!(
        tx.would_be_interruption()
            .map(|value| (value.rule_id, value.status, value.data.as_str())),
        Some((0, 413, ""))
    );
    assert!(tx.interruption().is_none());
    assert!(tx.matched_rules().is_empty());
    assert_eq!(tx.engine_events().len(), 2);
    assert!(
        tx.engine_events()
            .first()
            .unwrap()
            .tags()
            .iter()
            .any(|tag| tag == "coraza-rs/engine/RequestBodyLimit")
    );
    assert!(
        tx.engine_events()
            .get(1)
            .unwrap()
            .tags()
            .iter()
            .any(|tag| tag == "coraza-rs/engine/MultipartUploadBan")
    );
    assert_eq!(
        events
            .lock()
            .unwrap()
            .iter()
            .map(|event| event.tags.first().unwrap().as_str())
            .collect::<Vec<_>>(),
        [
            "coraza-rs/engine/RequestBodyLimit",
            "coraza-rs/engine/MultipartUploadBan"
        ]
    );

    let audit = tx.audit_log();
    assert_eq!(
        audit
            .messages
            .iter()
            .map(|message| message.data.tags.first().unwrap().as_str())
            .collect::<Vec<_>>(),
        [
            "coraza-rs/engine/RequestBodyLimit",
            "coraza-rs/engine/MultipartUploadBan"
        ]
    );
}

#[test]
fn a_reduced_detection_only_audit_uses_the_legacy_rule_fallback_before_a_later_engine_stop() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let config = request_config(RuleEngineStatus::DetectionOnly, 4);
    let rule = "SecAction \"id:90,phase:1,deny,status:403,log,auditlog,msg:'would deny'\"";
    let waf = build_waf(config, rule, events);
    let mut tx = waf.new_transaction_with_id("engine-event-request");
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    tx.add_request_header("X-Pad", "p".repeat(16 * 1024));
    tx.process_request_headers();

    assert!(tx.process_request_body(b"1234").is_none());
    assert_eq!(
        tx.would_be_interruption().map(|value| (value.rule_id, value.status)),
        Some((90, 403)),
        "the rule's would-be interruption happened before the engine stop"
    );
    assert!(tx.interruption().is_none(), "DetectionOnly did not interrupt");

    let audit = tx.audit_log();
    assert!(!audit.transaction.is_interrupted, "DetectionOnly stays non-interrupted");
    assert_eq!(
        audit.transaction.interruption_rule_id, None,
        "the public audit record exposes only enforced interruption IDs"
    );
    assert_eq!(
        audit.messages.iter().map(|message| message.rule_id).collect::<Vec<_>>(),
        [90, 0],
        "the realistic K-selected audit has the rule followed by the later engine event"
    );

    let (formatted, truncated) = audit.format_bounded(AuditLogFormat::Json, 768);
    assert!(truncated, "the large request header forces bounded reduction");
    assert!(formatted.len() <= 768);
    let document: serde_json::Value = serde_json::from_str(&formatted).unwrap();
    assert_eq!(
        document.pointer("/transaction/is_interrupted"),
        Some(&serde_json::Value::Bool(false)),
        "the would-be rule ID does not make DetectionOnly look interrupted"
    );
    let messages = document
        .get("messages")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("reduced output has no messages: {formatted}"));
    assert_eq!(
        messages.len(),
        1,
        "the budget can retain one of the two messages: {formatted}"
    );
    assert!(
        messages.iter().any(|message| {
            message.pointer("/data/id").and_then(serde_json::Value::as_i64) == Some(90)
                && message.get("message").and_then(serde_json::Value::as_str) == Some("would deny")
        }),
        "the legacy last-rule fallback keeps the rule message ahead of the appended event: {formatted}"
    );
}

#[test]
fn bounded_json_k_only_keeps_an_interrupted_hand_built_rules_compact_identity() {
    const OUTPUT_LIMIT: usize = 4096;
    const EXPECTED: &str = "[id \"4242\"] [msg \"denied\"]";
    let rule = |id, message: &str| AuditMessage {
        message: String::new(),
        error_message: format!(
            "[client 192.0.2.1] ModSecurity: Access denied with code 403 (phase 2). {} [id \"{id}\"] [msg \"{message}\"]",
            "request context ".repeat(256),
        ),
        rule_id: id,
        rule_message: message.to_owned(),
        data: AuditMessageData {
            raw: format!("SecRule ARGS:q \"@contains denied\" \"id:{id},phase:2,deny\""),
            ..AuditMessageData::default()
        },
        ..AuditMessage::default()
    };
    let audit = coraza::audit_log::AuditLog {
        parts: parse_audit_log_parts("AKZ").unwrap(),
        transaction: coraza::audit_log::AuditTransaction {
            id: "tx-hand-built-k-only".to_owned(),
            is_interrupted: true,
            interruption_rule_id: Some(4242),
            producer: Some(coraza::audit_log::AuditProducer {
                connector: "c".repeat(16 * 1024),
                rulesets: vec!["r".repeat(16 * 1024)],
                ..coraza::audit_log::AuditProducer::default()
            }),
            ..coraza::audit_log::AuditTransaction::default()
        },
        messages: vec![rule(4242, "denied"), rule(9001, "later rule")],
    };

    let (output, truncated) = audit.format_bounded(AuditLogFormat::Json, OUTPUT_LIMIT);
    assert!(truncated, "the producer and long error lines force reduction");
    assert!(output.len() <= OUTPUT_LIMIT);
    let document: serde_json::Value = serde_json::from_str(&output).unwrap();
    let messages = document
        .pointer("/messages")
        .and_then(serde_json::Value::as_array)
        .unwrap();
    assert_eq!(messages.len(), 1, "the interruption cause is the retained message");
    let message = messages.first().unwrap();
    assert_eq!(
        message.pointer("/data/id").and_then(serde_json::Value::as_i64),
        Some(4242),
        "K-only JSON preserves the rule ID from the public fallback field"
    );
    assert_eq!(
        message.get("error_message").and_then(serde_json::Value::as_str),
        Some(EXPECTED),
        "the baseline compact identity remains available without selected part H"
    );
}

#[test]
fn bounded_json_k_only_keeps_the_last_hand_built_rules_id_only_fallback() {
    const OUTPUT_LIMIT: usize = 4096;
    const EXPECTED: &str = "[id \"4243\"]";
    let rule = |id| AuditMessage {
        message: String::new(),
        error_message: format!(
            "[client 192.0.2.1] ModSecurity: Access denied with code 403 (phase 2). {} [id \"{id}\"] [msg \"caller-side message\"]",
            "request context ".repeat(256),
        ),
        rule_id: id,
        rule_message: String::new(),
        data: AuditMessageData {
            raw: format!("SecRule ARGS:q \"@contains denied\" \"id:{id},phase:2,deny\""),
            ..AuditMessageData::default()
        },
        ..AuditMessage::default()
    };
    for interruption_rule_id in [None, Some(9000)] {
        let audit = coraza::audit_log::AuditLog {
            parts: parse_audit_log_parts("AKZ").unwrap(),
            transaction: coraza::audit_log::AuditTransaction {
                id: "tx-hand-built-no-cause".to_owned(),
                is_interrupted: interruption_rule_id.is_some(),
                interruption_rule_id,
                producer: Some(coraza::audit_log::AuditProducer {
                    connector: "c".repeat(16 * 1024),
                    rulesets: vec!["r".repeat(16 * 1024)],
                    ..coraza::audit_log::AuditProducer::default()
                }),
                ..coraza::audit_log::AuditTransaction::default()
            },
            messages: vec![rule(4242), rule(4243)],
        };

        let (output, truncated) = audit.format_bounded(AuditLogFormat::Json, OUTPUT_LIMIT);
        assert!(truncated, "the long error lines force reduction");
        assert!(output.len() <= OUTPUT_LIMIT);
        let document: serde_json::Value = serde_json::from_str(&output).unwrap();
        let messages = document
            .pointer("/messages")
            .and_then(serde_json::Value::as_array)
            .unwrap();
        assert_eq!(
            messages.len(),
            1,
            "the no-ID or unmatched-ID fallback keeps the last rule message"
        );
        let message = messages.first().unwrap();
        assert_eq!(
            message.pointer("/data/id").and_then(serde_json::Value::as_i64),
            Some(4243),
            "the rule ID survives when no expanded identity text is available"
        );
        assert_eq!(
            message.get("error_message").and_then(serde_json::Value::as_str),
            Some(EXPECTED),
            "the legacy last-rule fallback still emits its ID-only compact identity"
        );
    }
}

#[test]
fn bounded_native_k_only_keeps_visible_engine_labels_and_overflow_count_when_they_fit() {
    const DETAIL_LIMIT: usize = 16;
    // Three selected parts and all details plus the summary fit the per-entry copy allowance.
    const OUTPUT_LIMIT: usize = 64 * (DETAIL_LIMIT + 4);
    const DETAIL_TAG: &str = "coraza-rs/engine/OperatorNotInspected";
    const SUMMARY_TAG: &str = "coraza-rs/engine/EventsOmitted";
    const SUMMARY_TEXT: &str = "48 additional engine stop events summarized after the first 16 individual events";
    let event = |state: &str, message: &str| {
        let tag = format!("coraza-rs/engine/{state}");
        AuditMessage {
            message: message.to_owned(),
            rule_id: 0,
            rule_message: format!("{tag}: {message}"),
            provenance: Some(if state == "EventsOmitted" {
                AuditMessageProvenance::EventsOmitted {
                    enforced_stop_omitted: false,
                }
            } else {
                AuditMessageProvenance::EngineEvent { enforced: false }
            }),
            data: AuditMessageData {
                id: 0,
                msg: message.to_owned(),
                tags: vec![tag.clone()],
                raw: tag,
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        }
    };
    let mut messages: Vec<_> = (0..DETAIL_LIMIT)
        .map(|index| event("OperatorNotInspected", &format!("refused input {index}")))
        .collect();
    messages.push(event("EventsOmitted", SUMMARY_TEXT));
    let audit = coraza::audit_log::AuditLog {
        parts: parse_audit_log_parts("AKZ").unwrap(),
        transaction: coraza::audit_log::AuditTransaction::default(),
        messages,
    };
    let unbounded = audit.format(AuditLogFormat::Native);
    assert!(
        unbounded.len() <= OUTPUT_LIMIT,
        "fixture output fits without internal copies"
    );

    let (bounded, truncated) = audit.format_bounded(AuditLogFormat::Native, OUTPUT_LIMIT);
    assert!(!truncated, "only visible K fields consume the bounded copy budget");
    assert_eq!(bounded.len(), unbounded.len());
    assert_eq!(
        bounded.lines().filter(|line| *line == DETAIL_TAG).count(),
        DETAIL_LIMIT,
        "all individual event labels stay visible"
    );
    assert!(
        bounded
            .lines()
            .any(|line| line == format!("{SUMMARY_TAG}: {SUMMARY_TEXT}")),
        "the summary label and exact count stay visible"
    );
    assert!(!bounded.contains('\0'));
}

fn h_only_engine_audit(description: &str) -> coraza::audit_log::AuditLog {
    const STATE: &str = "coraza-rs/engine/RequestBodyLimit";
    let identity = format!("{STATE}: {description}");
    coraza::audit_log::AuditLog {
        parts: parse_audit_log_parts("AHZ").unwrap(),
        transaction: coraza::audit_log::AuditTransaction {
            id: "near-cap-h-only".to_owned(),
            is_interrupted: true,
            interruption_rule_id: Some(0),
            request: coraza::audit_log::AuditRequest {
                uri: format!("/{}", "p".repeat(16 * 1024)),
                ..coraza::audit_log::AuditRequest::default()
            },
            producer: Some(coraza::audit_log::AuditProducer {
                connector: "c".repeat(16 * 1024),
                rulesets: vec!["r".repeat(16 * 1024)],
                ..coraza::audit_log::AuditProducer::default()
            }),
            ..coraza::audit_log::AuditTransaction::default()
        },
        messages: vec![AuditMessage {
            error_message: format!("[id \"0\"] [msg \"{identity}\"]"),
            rule_id: 0,
            rule_message: identity,
            provenance: Some(AuditMessageProvenance::EngineEvent { enforced: true }),
            data: AuditMessageData {
                id: 0,
                severity: 2,
                tags: vec![STATE.to_owned(), "coraza-rs/engine/Enforced".to_owned()],
                raw: STATE.to_owned(),
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        }],
    }
}

fn compact_marked_document_len(audit: &coraza::audit_log::AuditLog, format: AuditLogFormat) -> usize {
    let mut compact = audit.clone();
    compact.transaction.producer = None;
    compact.transaction.response = None;
    compact.transaction.request = coraza::audit_log::AuditRequest::default();
    compact.transaction.timestamp.clear();
    compact.transaction.client_ip.clear();
    compact.transaction.host_ip.clear();
    compact.transaction.server_id.clear();
    compact.transaction.highest_severity.clear();
    for message in &mut compact.messages {
        message.data.tags.clear();
    }

    let mut document: serde_json::Value = serde_json::from_str(&compact.format(format)).unwrap();
    document
        .as_object_mut()
        .unwrap()
        .insert("truncated".to_owned(), serde_json::Value::Bool(true));
    serde_json::to_vec(&document).unwrap().len()
}

#[test]
fn reduced_h_only_json_and_jsonlegacy_keep_the_state_prefix_when_shortening_engine_descriptions() {
    const STATE: &str = "coraza-rs/engine/RequestBodyLimit";
    const IDENTITY_PREFIX: &str = "[id \"0\"] [msg \"coraza-rs/engine/RequestBodyLimit: ";

    let description = "x".repeat(128);
    for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy] {
        let audit = h_only_engine_audit(&description);
        let output_limit = compact_marked_document_len(&audit, format) - 16;
        let (output, truncated) = audit.format_bounded(format, output_limit);
        assert!(truncated, "{format:?}: the producer and URI force reduction");
        assert!(output.len() <= output_limit, "{format:?}: {} bytes", output.len());
        assert_audit_text_has_no_nul(&output, "near-cap H-only JSON output");
        let document: serde_json::Value = serde_json::from_str(&output).unwrap();
        let visible = match format {
            AuditLogFormat::Json => document
                .pointer("/messages/0/error_message")
                .and_then(serde_json::Value::as_str),
            AuditLogFormat::JsonLegacy => document
                .pointer("/audit_data/messages/0")
                .and_then(serde_json::Value::as_str),
            AuditLogFormat::Ocsf | AuditLogFormat::Native => unreachable!(),
        }
        .unwrap_or_else(|| panic!("{format:?}: no compact engine identity: {output}"));
        assert!(
            visible.starts_with(IDENTITY_PREFIX),
            "{format:?}: the complete state prefix must survive: {output}"
        );
        let shortened = visible
            .strip_prefix(IDENTITY_PREFIX)
            .and_then(|text| text.strip_suffix("\"]"))
            .unwrap_or_else(|| panic!("{format:?}: incomplete compact identity: {visible}"));
        assert!(
            shortened.len() < description.len(),
            "{format:?}: the description, not the state prefix, is shortened: {output}"
        );
        assert!(visible.contains(STATE), "{format:?}: {output}");

        let prefix_only = h_only_engine_audit("");
        let small_limit = compact_marked_document_len(&prefix_only, format) - 1;
        let (small, small_truncated) = prefix_only.format_bounded(format, small_limit);
        assert!(small_truncated, "{format:?}: the complete identity no longer fits");
        assert_eq!(
            small, r#"{"truncated":true}"#,
            "{format:?}: a partial state prefix must not be emitted"
        );
    }
}

fn real_request_body_limit_audit(parts: &str) -> coraza::audit_log::AuditLog {
    let rule = "SecAction \"id:90,phase:1,pass,log,auditlog,msg:'before engine stop'\"";
    let mut config = request_config(RuleEngineStatus::DetectionOnly, 4);
    config.audit_log_parts = parse_audit_log_parts(parts).unwrap();
    let waf = build_waf(config, rule, Arc::new(Mutex::new(Vec::new())));
    let mut tx = waf.new_transaction_with_id("bounded-request-body-limit");
    tx.process_uri(format!("/{}", "p".repeat(16 * 1024)), "POST", "HTTP/1.1");
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    tx.process_request_headers();

    assert!(
        tx.process_request_body(b"1234").is_none(),
        "DetectionOnly does not block"
    );
    let audit = tx.audit_log();
    assert_eq!(
        audit.messages.iter().map(|message| message.rule_id).collect::<Vec<_>>(),
        [90, 0],
        "the real rule is retained before its engine event"
    );
    audit
}

fn real_multipart_upload_ban_audit(parts: &str) -> coraza::audit_log::AuditLog {
    const BODY: &[u8] =
        b"--b\r\nContent-Disposition: form-data; name=\"up\"; filename=\"x.txt\"\r\n\r\nPAYLOAD\r\n--b--\r\n";
    let rule = "SecAction \"id:90,phase:1,pass,log,auditlog,msg:'before engine stop'\"";
    let mut config = request_config(RuleEngineStatus::DetectionOnly, 1 << 20);
    config.audit_log_parts = parse_audit_log_parts(parts).unwrap();
    config.reject_multipart_file_uploads = true;
    let waf = build_waf(config, rule, Arc::new(Mutex::new(Vec::new())));
    let mut tx = waf.new_transaction_with_id("bounded-multipart-upload-ban");
    tx.process_uri(format!("/{}", "p".repeat(16 * 1024)), "POST", "HTTP/1.1");
    tx.add_request_header("Content-Type", "multipart/form-data; boundary=b");
    tx.process_request_headers();

    assert!(tx.process_request_body(BODY).is_none(), "DetectionOnly does not block");
    assert_eq!(
        tx.engine_events().first().unwrap().tags().first().map(String::as_str),
        Some("coraza-rs/engine/MultipartUploadBan"),
        "the public multipart parser records the upload-ban state"
    );
    let audit = tx.audit_log();
    assert_eq!(
        audit.messages.iter().map(|message| message.rule_id).collect::<Vec<_>>(),
        [90, 0],
        "the real rule is retained before its engine event"
    );
    audit
}

#[test]
fn reduced_h_only_ocsf_keeps_the_fallback_rule_and_engine_event() {
    const OUTPUT_LIMIT: usize = 1144;
    const STATE: &str = "coraza-rs/engine/MultipartUploadBan";
    let audit = real_multipart_upload_ban_audit("AHZ");

    let (output, truncated) = audit.format_bounded(AuditLogFormat::Ocsf, OUTPUT_LIMIT);

    assert!(truncated, "the long URI forces reduction");
    assert!(output.len() <= OUTPUT_LIMIT);
    let document: serde_json::Value = serde_json::from_str(&output).unwrap();
    let enrichments = document
        .get("enrichments")
        .and_then(serde_json::Value::as_array)
        .unwrap();
    assert_eq!(enrichments.len(), 2, "{output}");
    let rule = enrichments.first().unwrap();
    let event = enrichments.get(1).unwrap();
    let rule_data: serde_json::Value =
        serde_json::from_str(rule.get("data").and_then(serde_json::Value::as_str).unwrap()).unwrap();
    let event_data: serde_json::Value =
        serde_json::from_str(event.get("data").and_then(serde_json::Value::as_str).unwrap()).unwrap();
    assert_eq!(rule_data.get("id").and_then(serde_json::Value::as_i64), Some(90));
    assert_eq!(event_data.get("id").and_then(serde_json::Value::as_i64), Some(0));
    assert!(
        event
            .get("name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|name| name.starts_with(&format!("{STATE}: "))),
        "the retained engine event stays named after the rule fallback: {output}"
    );
    assert!(
        event_data
            .get("tags")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty)
    );
    assert_eq!(event_data.get("raw").and_then(serde_json::Value::as_str), Some(""));
    assert_eq!(event_data.get("msg").and_then(serde_json::Value::as_str), Some(""));
}

fn bounded_engine_event_data(format: AuditLogFormat, output: &str) -> serde_json::Value {
    let document: serde_json::Value = serde_json::from_str(output).unwrap();
    match format {
        AuditLogFormat::Json => document
            .pointer("/messages")
            .and_then(serde_json::Value::as_array)
            .unwrap()
            .iter()
            .find(|message| message.pointer("/data/id").and_then(serde_json::Value::as_i64) == Some(0))
            .unwrap()
            .get("data")
            .unwrap()
            .clone(),
        AuditLogFormat::Ocsf => document
            .pointer("/enrichments")
            .and_then(serde_json::Value::as_array)
            .unwrap()
            .iter()
            .find_map(|enrichment| {
                let data = serde_json::from_str::<serde_json::Value>(
                    enrichment.get("data").and_then(serde_json::Value::as_str)?,
                )
                .ok()?;
                (data.get("id").and_then(serde_json::Value::as_i64) == Some(0)).then_some(data)
            })
            .unwrap(),
        AuditLogFormat::JsonLegacy | AuditLogFormat::Native => unreachable!(),
    }
}

fn assert_bounded_k_state_is_whole(format: AuditLogFormat, output: &str, state: &str) {
    let data = bounded_engine_event_data(format, output);
    let tags = data
        .get("tags")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let raw = data.get("raw").and_then(serde_json::Value::as_str).unwrap_or_default();
    assert!(
        tags.iter().all(|tag| tag.as_str() == Some(state)),
        "{format:?}: synthetic tags are complete or omitted: {output}"
    );
    assert!(
        raw.is_empty() || raw == state,
        "{format:?}: synthetic raw identity is complete or omitted: {output}"
    );
    assert!(
        raw == state || tags.iter().any(|tag| tag.as_str() == Some(state)),
        "{format:?}: selected K retains one full state identity: {output}"
    );
}

fn constructed_summary_priority_audit(parts: &str, include_summary: bool) -> coraza::audit_log::AuditLog {
    const SUMMARY_STATE: &str = "coraza-rs/engine/EventsOmitted";
    const SUMMARY_TEXT: &str = "1 additional engine stop event summarized after the first 16 individual events";
    let cause_state = "coraza-rs/engine/RequestBodyBuffer";
    let cause_text = "request body buffer failed";
    let k_selected = parts.contains('K');
    let cause = AuditMessage {
        error_message: format!("[id \"0\"] [msg \"{cause_state}: {cause_text}\"] [data \"\"]"),
        message: if k_selected {
            cause_text.to_owned()
        } else {
            String::new()
        },
        rule_id: 0,
        rule_message: format!("{cause_state}: {cause_text}"),
        provenance: Some(AuditMessageProvenance::EngineEvent { enforced: true }),
        data: AuditMessageData {
            id: 0,
            severity: 2,
            msg: if k_selected {
                cause_text.to_owned()
            } else {
                String::new()
            },
            tags: vec![cause_state.to_owned(), "coraza-rs/engine/Enforced".to_owned()],
            raw: cause_state.to_owned(),
            ..AuditMessageData::default()
        },
        ..AuditMessage::default()
    };
    let summary = AuditMessage {
        error_message: format!("[id \"0\"] [msg \"{SUMMARY_STATE}: {SUMMARY_TEXT}\"]"),
        message: if k_selected {
            SUMMARY_TEXT.to_owned()
        } else {
            String::new()
        },
        rule_id: 0,
        rule_message: format!("{SUMMARY_STATE}: {SUMMARY_TEXT}"),
        provenance: Some(AuditMessageProvenance::EventsOmitted {
            enforced_stop_omitted: false,
        }),
        data: AuditMessageData {
            id: 0,
            severity: 2,
            msg: if k_selected {
                SUMMARY_TEXT.to_owned()
            } else {
                String::new()
            },
            tags: vec![SUMMARY_STATE.to_owned()],
            raw: SUMMARY_STATE.to_owned(),
            ..AuditMessageData::default()
        },
        ..AuditMessage::default()
    };

    let mut messages = vec![cause];
    if include_summary {
        messages.push(summary);
    }
    coraza::audit_log::AuditLog {
        parts: parse_audit_log_parts(parts).unwrap(),
        transaction: coraza::audit_log::AuditTransaction {
            timestamp: "2026/11/26 10:00:00".to_owned(),
            unix_timestamp: 1_800_000_000_000_000_000,
            id: "tx-pr204".to_owned(),
            client_ip: "192.0.2.10".to_owned(),
            client_port: 41234,
            host_ip: "192.0.2.20".to_owned(),
            host_port: 443,
            server_id: "example.test".to_owned(),
            request: coraza::audit_log::AuditRequest {
                method: "POST".to_owned(),
                protocol: "HTTP/1.1".to_owned(),
                uri: "/submit".to_owned(),
                http_version: "HTTP/1.1".to_owned(),
                length: 7,
                ..coraza::audit_log::AuditRequest::default()
            },
            producer: Some(coraza::audit_log::AuditProducer {
                rule_engine: "On".to_owned(),
                stopwatch: "1800000000000000000 5000; combined=0".to_owned(),
                rulesets: vec!["coraza-rs/test".to_owned()],
                ..coraza::audit_log::AuditProducer::default()
            }),
            highest_severity: "2".to_owned(),
            is_interrupted: true,
            interruption_rule_id: Some(0),
            ..coraza::audit_log::AuditTransaction::default()
        },
        messages,
    }
}

#[test]
fn reduced_real_request_body_events_omit_unfitting_tags_and_keep_them_whole_when_possible() {
    let audit = real_request_body_limit_audit("AKZ");

    let (too_small, truncated) = audit.format_bounded(AuditLogFormat::Json, 820);
    assert!(truncated);
    assert!(too_small.len() <= 820);
    let data = bounded_engine_event_data(AuditLogFormat::Json, &too_small);
    assert_eq!(
        data.get("msg").and_then(serde_json::Value::as_str),
        Some("RequestBodyLimit"),
        "the too-small control retains a meaningful event message"
    );
    assert!(
        data.get("tags")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty),
        "a tag that cannot fit is omitted, not emitted as an empty string"
    );
    assert_eq!(data.get("raw").and_then(serde_json::Value::as_str), Some(""));

    for (format, cap) in [(AuditLogFormat::Json, 896), (AuditLogFormat::Ocsf, 1144)] {
        let (output, truncated) = audit.format_bounded(format, cap);
        assert!(truncated, "{format:?}: long URI forces reduction");
        assert!(output.len() <= cap);
        assert_bounded_k_state_is_whole(format, &output, "coraza-rs/engine/RequestBodyLimit");
    }
}

#[test]
fn reduced_descriptive_engine_events_keep_k_state_with_a_pinned_real_rule_in_json_and_ocsf() {
    for (parts, format, cap) in [
        ("AKZ", AuditLogFormat::Json, 1024),
        ("AHKZ", AuditLogFormat::Json, 1280),
        ("AHKZ", AuditLogFormat::Json, 1536),
        ("AKZ", AuditLogFormat::Ocsf, 1144),
        ("AHKZ", AuditLogFormat::Ocsf, 1144),
    ] {
        let audit = real_multipart_upload_ban_audit(parts);
        let (output, truncated) = audit.format_bounded(format, cap);
        assert!(truncated, "{parts} {format:?}: long URI forces reduction");
        assert!(output.len() <= cap, "{parts} {format:?}");
        let document: serde_json::Value = serde_json::from_str(&output).unwrap();
        match format {
            AuditLogFormat::Json => {
                let messages = document
                    .pointer("/messages")
                    .and_then(serde_json::Value::as_array)
                    .unwrap();
                assert_eq!(messages.len(), 2, "{parts}: keep the pinned rule and event");
                assert_eq!(
                    messages.first().unwrap().pointer("/data/id"),
                    Some(&serde_json::Value::from(90)),
                    "{parts}: the real rule remains first"
                );
                assert_eq!(
                    messages.get(1).unwrap().pointer("/data/id"),
                    Some(&serde_json::Value::from(0)),
                    "{parts}: the synthetic event is retained"
                );
                if parts == "AHKZ" {
                    let h_identity = messages
                        .get(1)
                        .unwrap()
                        .get("error_message")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    assert!(
                        h_identity.is_empty() || h_identity.contains("coraza-rs/engine/MultipartUploadBan"),
                        "H must not expose a partial synthetic state identity: {output}"
                    );
                    if cap == 1536 {
                        assert!(
                            h_identity.contains("coraza-rs/engine/MultipartUploadBan"),
                            "H identity is retained when its full state fits: {output}"
                        );
                    }
                }
            },
            AuditLogFormat::Ocsf => {
                let enrichments = document
                    .get("enrichments")
                    .and_then(serde_json::Value::as_array)
                    .unwrap();
                assert_eq!(enrichments.len(), 2, "{parts}: keep the pinned rule and event");
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(
                        enrichments
                            .first()
                            .unwrap()
                            .get("data")
                            .and_then(serde_json::Value::as_str)
                            .unwrap()
                    )
                    .unwrap()
                    .get("id"),
                    Some(&serde_json::Value::from(90)),
                    "{parts}: the real rule remains first"
                );
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(
                        enrichments
                            .get(1)
                            .unwrap()
                            .get("data")
                            .and_then(serde_json::Value::as_str)
                            .unwrap()
                    )
                    .unwrap()
                    .get("id"),
                    Some(&serde_json::Value::from(0)),
                    "{parts}: the synthetic event is retained"
                );
                assert!(
                    document.get("error_message").is_none(),
                    "OCSF uses enrichment data/name, not JSON's error_message"
                );
            },
            AuditLogFormat::JsonLegacy | AuditLogFormat::Native => unreachable!(),
        }
        assert_bounded_k_state_is_whole(format, &output, "coraza-rs/engine/MultipartUploadBan");
    }
}

#[test]
fn bounded_public_audits_keep_the_enforcing_event_and_omission_summary_before_metadata() {
    const SUMMARY_TEXT: &str = "1 additional engine stop event summarized after the first 16 individual events";
    const SUMMARY_FALLBACK: &str = "additional engine stop details omitted";

    for (parts, format, max_bytes) in [
        ("AHZ", AuditLogFormat::Json, 908),
        ("AHZ", AuditLogFormat::JsonLegacy, 583),
        ("AHZ", AuditLogFormat::Ocsf, 1114),
        ("AKZ", AuditLogFormat::Json, 1011),
        ("AKZ", AuditLogFormat::JsonLegacy, 583),
        ("AKZ", AuditLogFormat::Ocsf, 1500),
    ] {
        let audit = constructed_summary_priority_audit(parts, true);
        let (output, truncated) = audit.format_bounded(format, max_bytes);
        assert!(truncated, "{parts} {format:?}: the full record is reduced");
        assert!(output.len() <= max_bytes, "{parts} {format:?}: {} bytes", output.len());
        let document: serde_json::Value = serde_json::from_str(&output).unwrap();
        let messages = serialized_audit_entries(format, &document);
        assert_eq!(
            messages.len(),
            2,
            "{parts} {format:?}: retain the enforcing event and summary before other metadata: {output}"
        );
        assert!(
            messages
                .first()
                .unwrap()
                .to_string()
                .contains("coraza-rs/engine/RequestBodyBuffer"),
            "{parts} {format:?}: the enforcing event stays first: {output}"
        );
        let summary = messages.get(1).unwrap().to_string();
        assert!(summary.contains("coraza-rs/engine/EventsOmitted"), "{output}");
        match (parts, format) {
            ("AHZ", AuditLogFormat::Json) => {
                assert!(summary.contains(SUMMARY_TEXT), "the exact count fits: {output}");
            },
            ("AHZ", AuditLogFormat::JsonLegacy) => {
                assert!(
                    summary.contains(SUMMARY_FALLBACK),
                    "the exact count is replaced by the fixed fallback: {output}"
                );
            },
            _ => {},
        }
        assert!(
            summary.contains(SUMMARY_TEXT) || summary.contains(SUMMARY_FALLBACK),
            "{parts} {format:?}: the exact summary or honest fixed fallback follows it: {output}"
        );
    }
}

#[test]
fn reduced_ocsf_k_summary_without_identity_uses_a_fixed_name() {
    const CAUSE_TEXT: &str = "request body buffer failed";
    const FALLBACK: &str = "additional engine stop details omitted";

    let mut audit = constructed_summary_priority_audit("AKZ", true);
    let summary = audit.messages.get_mut(1).unwrap();
    summary.error_message.clear();
    summary.message.clear();
    summary.rule_message.clear();
    summary.data.msg.clear();
    summary.data.data.clear();
    summary.data.tags.clear();
    summary.data.raw.clear();
    audit.transaction.request.uri = format!("/{}", "p".repeat(8 * 1024));

    let (output, truncated) = audit.format_bounded(AuditLogFormat::Ocsf, 2048);
    assert!(truncated, "the long URI forces a bounded reduction");
    assert!(output.len() <= 2048, "{}", output.len());
    let document: serde_json::Value = serde_json::from_str(&output).unwrap();
    let messages = serialized_audit_entries(AuditLogFormat::Ocsf, &document);
    assert_eq!(
        messages.len(),
        2,
        "the fixed fallback fits after the useful cause: {output}"
    );
    let cause_name = messages
        .first()
        .and_then(|message| message.get("name"))
        .and_then(serde_json::Value::as_str);
    assert!(
        cause_name.is_some_and(|name| name.contains(CAUSE_TEXT)),
        "the useful cause remains ahead of the malformed summary: {output}"
    );
    assert_eq!(
        messages
            .get(1)
            .and_then(|summary| summary.get("name"))
            .and_then(serde_json::Value::as_str),
        Some(FALLBACK),
        "a reduced typed summary without a usable identity has an honest name: {output}"
    );
}

#[test]
fn bounded_summary_pair_retry_keeps_full_fit_no_summary_and_cause_only_controls() {
    let audit = constructed_summary_priority_audit("AHZ", true);
    for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
        let (full, truncated) = audit.format_bounded(format, 64 * 1024);
        assert!(!truncated, "{format:?}: the full record fits");
        if format != AuditLogFormat::Ocsf {
            assert_eq!(full, audit.format(format), "{format:?}: full-fit bytes stay unchanged");
        }
    }
    let k_audit = constructed_summary_priority_audit("AKZ", true);
    for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy] {
        let (full, truncated) = k_audit.format_bounded(format, 64 * 1024);
        assert!(!truncated, "{format:?}: the K-selected full record fits");
        assert_eq!(
            full,
            k_audit.format(format),
            "{format:?}: K-selected full-fit bytes stay unchanged"
        );
    }

    let no_summary = constructed_summary_priority_audit("AHZ", false);
    let (without_summary, truncated) = no_summary.format_bounded(AuditLogFormat::Json, 850);
    assert!(truncated);
    let document: serde_json::Value = serde_json::from_str(&without_summary).unwrap();
    let transaction = document.get("transaction").cloned();
    let messages = serialized_audit_entries(AuditLogFormat::Json, &document);
    assert_eq!(messages.len(), 1, "{without_summary}");
    assert!(
        messages
            .first()
            .unwrap()
            .to_string()
            .contains("coraza-rs/engine/RequestBodyBuffer"),
        "{without_summary}"
    );
    assert!(!without_summary.contains("EventsOmitted"), "{without_summary}");

    let (cause_only, truncated) = audit.format_bounded(AuditLogFormat::Json, 850);
    assert!(truncated);
    assert!(cause_only.len() <= 850);
    let cause_document: serde_json::Value = serde_json::from_str(&cause_only).unwrap();
    assert_eq!(
        cause_document.get("transaction"),
        transaction.as_ref(),
        "a compact pair that does not fit must preserve the original fitting cause-only view"
    );
    let messages = serialized_audit_entries(AuditLogFormat::Json, &cause_document);
    assert_eq!(messages.len(), 1, "{cause_only}");
    assert!(
        messages
            .first()
            .unwrap()
            .to_string()
            .contains("coraza-rs/engine/RequestBodyBuffer"),
        "{cause_only}"
    );
    assert!(
        !cause_only.contains("EventsOmitted"),
        "when the pair does not fit, keep the cause-only output: {cause_only}"
    );
}
