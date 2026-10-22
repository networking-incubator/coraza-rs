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

//! Audit logging, as Go Coraza does it: what a transaction's entry holds ([`AuditLog`],
//! built by [`crate::transaction::Transaction::audit_log`]), how it is written out
//! ([`AuditLogFormat`]) and where to ([`AuditLogType`]).

use std::{
    collections::BTreeMap,
    fmt::{self, Write as _},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use regex::Regex;
use serde_json::{Value, json};

use crate::{
    actions::RuleMetadata,
    collection::MatchData,
    config::WafConfig,
    types::{AuditLogFormat, AuditLogPart, AuditLogParts, AuditLogType},
    utils::time::UtcTime,
};

/// Next process-local suffix for concurrent audit log filenames.
static NEXT_AUDIT_FILE_ID: AtomicU64 = AtomicU64::new(1);

/// A transaction's audit log entry.
#[derive(Debug, Clone, Default)]
pub struct AuditLog {
    /// The parts the entry holds, in the order they are written
    pub parts: AuditLogParts,
    /// The transaction, as far as `parts` include it
    pub transaction: AuditTransaction,
    /// What the rules with `auditlog` that matched have to say: one per value they
    /// matched with part `K`, or one per rule with only part `H`
    pub messages: Vec<AuditMessage>,
}

/// The transaction an [`AuditLog`] is about.
#[derive(Debug, Clone, Default)]
pub struct AuditTransaction {
    /// When the transaction started, as `2006/01/02 15:04:05`, in UTC
    pub timestamp: String,
    /// When the transaction started, in nanoseconds since the Unix epoch
    pub unix_timestamp: i64,
    /// `UNIQUE_ID`.
    pub id: String,
    /// `REMOTE_ADDR`.
    pub client_ip: String,
    /// `REMOTE_PORT`; 0 if unknown.
    pub client_port: u16,
    /// `SERVER_ADDR`.
    pub host_ip: String,
    /// `SERVER_PORT`; 0 if unknown.
    pub host_port: u16,
    /// `SERVER_NAME`.
    pub server_id: String,
    /// The request
    pub request: AuditRequest,
    /// The response, with part `E` or `F`
    pub response: Option<AuditResponse>,
    /// Who logged it, with part `H`
    pub producer: Option<AuditProducer>,
    /// `HIGHEST_SEVERITY`.
    pub highest_severity: String,
    /// Whether a disruptive action interrupted the transaction
    pub is_interrupted: bool,
}

/// The request of an [`AuditTransaction`].
#[derive(Debug, Clone, Default)]
pub struct AuditRequest {
    /// `REQUEST_METHOD`.
    pub method: String,
    /// `REQUEST_PROTOCOL`, e.g. `HTTP/1.1`.
    pub protocol: String,
    /// `REQUEST_URI`.
    pub uri: String,
    /// Empty, as in Go Coraza, which never sets it
    pub http_version: String,
    /// The headers by lowercase name, with part `B`
    pub headers: Option<BTreeMap<String, Vec<String>>>,
    /// `REQUEST_BODY`, with part `C`.
    pub body: String,
    /// The uploaded files, with part `J`
    pub files: Option<Vec<AuditFile>>,
    /// `FULL_REQUEST_LENGTH`.
    pub length: i32,
    /// ARGS, as key and value pairs
    pub args: Vec<(String, String)>,
}

/// A file uploaded with an [`AuditRequest`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFile {
    /// Its name, as the client gave it
    pub name: String,
    /// Its size, in bytes
    pub size: i64,
    /// Its MIME type, from its name's extension; empty if unknown
    pub mime: String,
}

/// The response of an [`AuditTransaction`].
#[derive(Debug, Clone, Default)]
pub struct AuditResponse {
    /// Empty, as in Go Coraza, which never sets it; the native format writes `HTTP/1.1`
    pub protocol: String,
    /// `RESPONSE_STATUS`, with part `F`; 0 otherwise.
    pub status: u16,
    /// The headers by lowercase name, with part `F`
    pub headers: Option<BTreeMap<String, Vec<String>>>,
    /// `RESPONSE_BODY`, with part `E`.
    pub body: String,
}

/// Who wrote an [`AuditLog`].
#[derive(Debug, Clone, Default)]
pub struct AuditProducer {
    /// The connector; empty here
    pub connector: String,
    /// The connector's version; empty here
    pub version: String,
    /// Empty, as in Go Coraza
    pub server: String,
    /// The transaction's rule engine status, e.g. `On`
    pub rule_engine: String,
    /// When the transaction started and how long it has taken, both in nanoseconds,
    /// then the time spent in each phase, as Go Coraza writes them (0: not measured)
    pub stopwatch: String,
    /// `SecComponentSignature`s
    pub rulesets: Vec<String>,
}

/// One message of an [`AuditLog`].
#[derive(Debug, Clone, Default)]
pub struct AuditMessage {
    /// `SecComponentSignature`s, space-separated
    pub actionset: String,
    /// The rule's `msg`, as expanded for this match
    pub message: String,
    /// The rule's error log line, with part `H`
    pub error_message: String,
    /// The rule and match
    pub data: AuditMessageData,
}

/// The rule and match behind an [`AuditMessage`].
#[derive(Debug, Clone, Default)]
pub struct AuditMessageData {
    /// The rule's file
    pub file: String,
    /// The rule's line
    pub line: usize,
    /// The rule's id
    pub id: i32,
    /// The rule's `rev`
    pub rev: String,
    /// The rule's `msg`, as expanded for this match
    pub msg: String,
    /// The rule's `logdata`, as expanded for this match
    pub data: String,
    /// The rule's severity, 0 (emergency) to 7 (debug); -1 if unset
    pub severity: i8,
    /// The rule's `ver`
    pub ver: String,
    /// The rule's `maturity`; 0 if unset
    pub maturity: u8,
    /// The rule's `accuracy`; 0 if unset
    pub accuracy: u8,
    /// The rule's tags
    pub tags: Vec<String>,
    /// The rule's directives, its chain's included
    pub raw: String,
}

#[derive(Debug, Clone)]
/// A rule match recorded for connector logs and audit entries.
pub struct MatchedRule {
    /// The rule as compiled; its raw text includes all chain links.
    pub rule: RuleMetadata,
    /// Values matched by the rule and its chain.
    pub matches: Vec<MatchData>,
    /// The selected disruptive action, if any.
    pub disruptive_action: Option<&'static str>,
    /// Whether the disruptive action took effect.
    pub disruptive: bool,
    /// Client address when the match occurred.
    pub client_ip: String,
    /// Server address when the match occurred.
    pub server_ip: String,
    /// Request URI when the match occurred.
    pub uri: String,
    /// Transaction identifier.
    pub transaction_id: String,
}

/// Maximum message bytes included in a Coraza error log line.
const MAX_LOG_MESSAGE: usize = 280;

impl MatchedRule {
    /// The first expanded rule message, or an empty string when none was set.
    pub fn message(&self) -> &str {
        self.first_with_message().map_or("", |matched| &matched.message)
    }

    /// The expanded log data paired with [`MatchedRule::message`].
    pub fn data(&self) -> &str {
        self.first_with_message().map_or("", |matched| &matched.data)
    }

    /// The ID of the matched rule.
    pub fn rule_id(&self) -> i32 {
        self.rule.id
    }

    /// First match with an expanded message.
    fn first_with_message(&self) -> Option<&MatchData> {
        self.matches.iter().find(|matched| !matched.message.is_empty())
    }

    /// Format this match as a Coraza-compatible error log line.
    pub fn error_log(&self) -> String {
        let first = self.matches.first();
        let mut log = format!("[client {}] {}", go_quote(&self.client_ip), self.outcome());
        log.push_str(&escape_log_message(truncated(self.message(), MAX_LOG_MESSAGE)));
        log.push(' ');
        let (message, data) = first.map_or(("", ""), |matched| (matched.message.as_str(), matched.data.as_str()));
        self.write_details(&mut log, message, data);
        for (number, extra) in self.matches.iter().enumerate().skip(1) {
            if !extra.message.is_empty() || !extra.data.is_empty() {
                write!(
                    log,
                    " [msg_match_{number} {}] [data_match_{number} {}]",
                    go_quote(truncated(&extra.message, MAX_LOG_MESSAGE)),
                    go_quote(truncated(&extra.data, MAX_LOG_MESSAGE)),
                )
                .unwrap_or(());
            }
        }
        log
    }

    /// Coraza's prefix describing the action taken for this match.
    fn outcome(&self) -> String {
        let phase = self.rule.phase.as_int();
        match self.disruptive_action.filter(|_| self.disruptive) {
            None | Some("pass") => "Coraza: Warning. ".to_owned(),
            Some("allow") => format!("Coraza: Access allowed (phase {phase}). "),
            Some("deny") => format!("Coraza: Access denied (phase {phase}). "),
            Some("drop") => format!("Coraza: Access dropped (phase {phase}). "),
            Some("redirect") => format!("Coraza: Access redirected (phase {phase}). "),
            Some(_) => format!("Coraza: Custom disruptive action triggered (phase {phase}). "),
        }
    }

    /// Append quoted rule and transaction details to `log`.
    fn write_details(&self, log: &mut String, message: &str, data: &str) {
        let rule = &self.rule;
        let severity = rule.severity.map_or("unknown", |severity| severity.as_str());
        write!(
            log,
            "[file {}] [line {}] [id {}] [rev {}] [msg {}] [data {}] [severity {}] [ver {}] [maturity {}] [accuracy {}]",
            go_quote(&rule.file),
            go_quote(&rule.line.to_string()),
            go_quote(&rule.id.to_string()),
            go_quote(&rule.rev),
            go_quote(truncated(message, MAX_LOG_MESSAGE)),
            go_quote(truncated(data, MAX_LOG_MESSAGE)),
            go_quote(severity),
            go_quote(&rule.ver),
            go_quote(&rule.maturity.to_string()),
            go_quote(&rule.accuracy.to_string()),
        )
        .unwrap_or(());
        for tag in &rule.tags {
            write!(log, " [tag {}]", go_quote(tag)).unwrap_or(());
        }
        write!(
            log,
            " [hostname {}] [uri {}] [unique_id {}]",
            go_quote(&self.server_ip),
            go_quote(&self.uri),
            go_quote(&self.transaction_id),
        )
        .unwrap_or(());
    }
}

/// Truncate `text` to at most `max` bytes without splitting a UTF-8 code point.
fn truncated(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let end = (0..=max).rev().find(|&index| text.is_char_boundary(index)).unwrap_or(0);
    text.get(..end).unwrap_or(text)
}

/// Escape control characters that could split a connector error log line.
fn escape_log_message(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            character if character.is_control() => {
                write!(escaped, "\\u{{{:x}}}", character as u32).unwrap_or(());
            },
            character => escaped.push(character),
        }
    }
    escaped
}

/// Quote a string using Go's `strconv.Quote` conventions.
fn go_quote(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for character in text.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\u{07}' => quoted.push_str("\\a"),
            '\u{08}' => quoted.push_str("\\b"),
            '\u{0c}' => quoted.push_str("\\f"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            '\u{0b}' => quoted.push_str("\\v"),
            character if (character as u32) < 0x20 || character as u32 == 0x7F => {
                write!(quoted, "\\x{:02x}", character as u32).unwrap_or(());
            },
            character if character.is_control() => {
                write!(quoted, "\\u{:04x}", character as u32).unwrap_or(());
            },
            character => quoted.push(character),
        }
    }
    quoted.push('"');
    quoted
}

/// Callback used to emit rules with the `log` action.
#[derive(Clone)]
pub(crate) struct ErrorLog(std::sync::Arc<ErrorLogCallback>);

/// Thread-safe callback invoked for each matching logged rule.
type ErrorLogCallback = dyn Fn(&MatchedRule) + Send + Sync;

impl ErrorLog {
    /// Wrap a callback for sharing across transactions.
    pub(crate) fn new(log: impl Fn(&MatchedRule) + Send + Sync + 'static) -> Self {
        Self(std::sync::Arc::new(log))
    }

    /// Invoke the callback for a matched rule.
    pub(crate) fn write(&self, matched: &MatchedRule) {
        (self.0)(matched);
    }
}

impl fmt::Debug for ErrorLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ErrorLog")
    }
}

impl AuditLog {
    /// The entry written out in `format`; empty when there is nothing to write.
    pub fn format(&self, format: AuditLogFormat) -> String {
        match format {
            AuditLogFormat::Native => self.native(),
            AuditLogFormat::Json => self.json().to_string(),
            AuditLogFormat::JsonLegacy => self.json_legacy().to_string(),
            AuditLogFormat::Ocsf => self.ocsf().to_string(),
        }
    }

    /// ModSecurity's native format: a section per part, each opened by a boundary.
    #[expect(clippy::too_many_lines, reason = "all native log parts are serialized in order")]
    fn native(&self) -> String {
        if self.parts.is_empty() {
            return String::new();
        }
        let tx = &self.transaction;
        let mut rng = fastrand::Rng::new();
        let boundary = format!("--{}-", (0..16).map(|_| rng.alphanumeric()).collect::<String>());
        let mut out = String::new();
        for part in &self.parts {
            out.push_str(&boundary);
            out.push(*part as u8 as char);
            out.push_str("--\n");
            match part {
                AuditLogPart::Header => {
                    writeln!(
                        out,
                        "[{}] {} {} {} {} {}",
                        tx.timestamp,
                        escape(&tx.id),
                        escape(&tx.client_ip),
                        tx.client_port,
                        escape(&tx.host_ip),
                        tx.host_port
                    )
                    .unwrap_or(());
                },
                AuditLogPart::RequestHeaders => {
                    let request = &tx.request;
                    write!(
                        out,
                        "{} {} {}",
                        escape(&request.method),
                        escape(&request.uri),
                        escape(&request.protocol)
                    )
                    .unwrap_or(());
                    for (name, values) in request.headers.iter().flatten() {
                        for value in values {
                            write!(out, "\n{}: {}", escape(name), escape(value)).unwrap_or(());
                        }
                    }
                    out.push('\n');
                },
                AuditLogPart::RequestBody if !tx.request.body.is_empty() => {
                    out.push_str(&escape(&tx.request.body));
                    out.push('\n');
                },
                AuditLogPart::IntermediaryResponseBody | AuditLogPart::ResponseBody => {
                    if let Some(response) = tx.response.as_ref().filter(|r| !r.body.is_empty()) {
                        out.push_str(&escape(&response.body));
                        out.push('\n');
                    }
                },
                AuditLogPart::ResponseHeaders => {
                    if let Some(response) = &tx.response {
                        let protocol = match response.protocol.as_str() {
                            "" => "HTTP/1.1",
                            protocol => protocol,
                        };
                        writeln!(
                            out,
                            "{} {} {}",
                            escape(protocol),
                            response.status,
                            status_text(response.status)
                        )
                        .unwrap_or(());
                        for (name, values) in response.headers.iter().flatten() {
                            for value in values {
                                writeln!(out, "{}: {}", escape(name), escape(value)).unwrap_or(());
                            }
                        }
                    }
                },
                AuditLogPart::Trailer => {
                    for message in self.messages.iter().filter(|m| !m.error_message.is_empty()) {
                        out.push_str(&escape(&message.error_message));
                        out.push('\n');
                    }
                },
                AuditLogPart::UploadedFiles => {
                    let files = tx.request.files.as_deref().unwrap_or_default();
                    for (index, file) in files.iter().enumerate() {
                        let mime = match file.mime.as_str() {
                            "" => "<Unknown Content-Type>",
                            mime => mime,
                        };
                        writeln!(out, "{},{},{:?},{:?}", index + 1, file.size, file.name, mime).unwrap_or(());
                    }
                    let total: i64 = files.iter().map(|file| file.size).sum();
                    writeln!(out, "Total,{total}").unwrap_or(());
                },
                AuditLogPart::RulesMatched => {
                    for message in &self.messages {
                        out.push_str(&escape(&message.data.raw));
                        out.push('\n');
                    }
                },
                _ => {},
            }
            if *part != AuditLogPart::Header {
                out.push('\n');
            }
        }
        out
    }

    /// Go Coraza's JSON format.
    fn json(&self) -> Value {
        let tx = &self.transaction;
        let request = &tx.request;
        let mut transaction = json!({
            "timestamp": tx.timestamp,
            "unix_timestamp": tx.unix_timestamp,
            "id": tx.id,
            "client_ip": tx.client_ip,
            "client_port": tx.client_port,
            "host_ip": tx.host_ip,
            "host_port": tx.host_port,
            "server_id": tx.server_id,
            "request": {
                "method": request.method,
                "protocol": request.protocol,
                "uri": request.uri,
                "http_version": request.http_version,
                "headers": request.headers,
                "body": request.body,
                "files": request.files.as_ref().map(|files| {
                    files
                        .iter()
                        .map(|file| json!({"name": file.name, "size": file.size, "mime": file.mime}))
                        .collect::<Vec<_>>()
                }),
                // Go Coraza serializes its argument collection as an empty object
                "args": {},
                "length": request.length,
            },
            "highest_severity": tx.highest_severity,
            "is_interrupted": tx.is_interrupted,
        });
        if let Some(response) = &tx.response
            && let Some(object) = transaction.as_object_mut()
        {
            object.insert(
                "response".to_owned(),
                json!({
                    "protocol": response.protocol,
                    "status": response.status,
                    "headers": response.headers,
                    "body": response.body,
                }),
            );
        }
        if let Some(producer) = &tx.producer
            && let Some(object) = transaction.as_object_mut()
        {
            object.insert(
                "producer".to_owned(),
                json!({
                    "connector": producer.connector,
                    "version": producer.version,
                    "server": producer.server,
                    "rule_engine": producer.rule_engine,
                    "stopwatch": producer.stopwatch,
                    "rulesets": producer.rulesets,
                }),
            );
        }

        let mut entry = json!({ "transaction": transaction });
        if !self.messages.is_empty() {
            let messages = self
                .messages
                .iter()
                .map(|message| {
                    let data = &message.data;
                    json!({
                        "actionset": message.actionset,
                        "message": message.message,
                        "error_message": message.error_message,
                        "data": message_data_json(data),
                    })
                })
                .collect();
            if let Some(object) = entry.as_object_mut() {
                object.insert("messages".to_owned(), Value::Array(messages));
            }
        }
        entry
    }

    /// The Open Cybersecurity Schema Framework's Web Resources Activity event (OCSF
    /// 1.2.0), as Go Coraza fills it in, without the fields that are zero or empty, as
    /// its protobuf types leave them out.
    ///
    /// Its severity is the transaction's highest: Go Coraza always writes `emergency`, as
    /// it never sets the highest severity of its entries.
    #[expect(
        clippy::too_many_lines,
        reason = "all OCSF event fields are mapped in one serializer"
    )]
    fn ocsf(&self) -> Value {
        let tx = &self.transaction;
        let request = &tx.request;
        let header_values = |headers: &Option<BTreeMap<String, Vec<String>>>, name: &str| {
            headers
                .iter()
                .flatten()
                .find(|(header, _)| *header == name)
                .map(|(_, values)| values.clone())
                .unwrap_or_default()
        };
        let header_list = |headers: &Option<BTreeMap<String, Vec<String>>>| {
            headers
                .iter()
                .flatten()
                .flat_map(|(name, values)| values.iter().map(move |value| json!({"name": name, "value": value})))
                .collect::<Vec<_>>()
        };
        let producer = tx.producer.clone().unwrap_or_default();
        let (action_id, action) = if tx.is_interrupted {
            (2, "Denied")
        } else {
            (1, "Allowed")
        };
        // As Go Coraza writes them, each followed by a comma
        let args: String = request
            .args
            .iter()
            .map(|(key, value)| format!("{key}={value},"))
            .collect();
        let logged_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_micros());
        // As Go's ParseRuleSeverity reads it, falling back to its zero value
        let severity = tx
            .highest_severity
            .parse::<crate::types::RuleSeverity>()
            .map_or("emergency", |severity| severity.as_str());
        let response = tx.response.clone().unwrap_or_default();

        let mut observables = Vec::new();
        if !tx.server_id.is_empty() {
            observables.push(json!({
                "name": "ServerID", "type": "ServerID", "type_id": 99, "value": tx.server_id,
            }));
        }
        for file in request.files.iter().flatten() {
            observables.push(json!({
                "name": file.name, "type": "File Name", "type_id": 7, "value": file.name,
            }));
            observables.push(json!({
                "name": file.name, "type": "Size", "type_id": 99, "value": file.size.to_string(),
            }));
            observables.push(json!({
                "name": file.name, "type": "Mime", "type_id": 99, "value": file.mime,
            }));
        }

        omit_empty(json!({
            "activity_id": 2,
            "activity_name": "Read",
            "category_name": "Application Activity",
            "class_name": "Web Resources Activity",
            "category_uid": 6,
            "class_uid": 6001,
            "time": tx.unix_timestamp,
            "action_id": action_id,
            "action": action,
            "metadata": {
                "log_provider": producer.connector,
                "log_version": producer.version,
                "logged_time": logged_time,
                "product": {"vendor_name": "OWASP Coraza Web Application Firewall"},
                "version": "1.2.0",
            },
            "type_uid": 600_102,
            "enrichments": self.messages.iter().map(|message| json!({
                "data": message_data_json(&message.data).to_string(),
                "name": message.data.msg,
                "value": message.data.data,
            })).collect::<Vec<_>>(),
            "http_request": {
                "version": request.protocol,
                "args": args,
                "http_method": request.method,
                "uid": tx.id,
                "url": {"url_string": request.uri},
                "http_headers": header_list(&request.headers),
                "length": request.length,
                "user_agent": header_values(&request.headers, "user-agent").first(),
                "referrer": header_values(&request.headers, "referer").first(),
                "x_forwarded_for": header_values(&request.headers, "x-forwarded-for"),
            },
            "http_response": {
                "code": response.status,
                "http_headers": header_list(&response.headers),
            },
            "src_endpoint": {"ip": tx.client_ip, "port": tx.client_port},
            "dst_endpoint": {"ip": tx.host_ip, "port": tx.host_port},
            "web_resources": [{"url_string": request.uri}],
            "message": self.messages.first().map(|message| &message.message),
            "severity": severity,
            "severity_id": 99,
            "start_time": tx.unix_timestamp,
            "type_name": "Read",
            "observables": observables,
        }))
    }

    /// The JSON format of ModSecurity 2, as Go Coraza writes it.
    fn json_legacy(&self) -> Value {
        let tx = &self.transaction;
        let joined = |headers: &Option<BTreeMap<String, Vec<String>>>| {
            headers
                .iter()
                .flatten()
                .map(|(name, values)| (name.clone(), Value::from(values.join(", "))))
                .collect::<serde_json::Map<_, _>>()
        };
        let request = &tx.request;
        let mut entry = json!({
            "transaction": {
                "time": tx.timestamp,
                "transaction_id": tx.id,
                "remote_address": tx.client_ip,
                "remote_port": tx.client_port,
                "local_address": tx.host_ip,
                "local_port": tx.host_port,
            },
            "request": {
                "request_line": format!("{} {} {}", request.method, request.uri, request.http_version),
                "headers": joined(&request.headers),
            },
        });
        if let Some(response) = &tx.response
            && let Some(object) = entry.as_object_mut()
        {
            object.insert(
                "response".to_owned(),
                json!({
                    "status": response.status,
                    "protocol": response.protocol,
                    "headers": joined(&response.headers),
                }),
            );
        }

        let messages: Vec<&str> = self.messages.iter().map(|m| m.message.as_str()).collect();
        if tx.producer.is_some() || !messages.is_empty() {
            let producer = tx.producer.clone().unwrap_or_default();
            let producers: Vec<&str> = std::iter::once(producer.connector.as_str())
                .filter(|connector| !connector.is_empty())
                .chain(producer.rulesets.iter().map(String::as_str))
                .collect();
            let stopwatch: serde_json::Map<_, _> = ["Combined", "P1", "P2", "P3", "P4", "P5", "Sr", "Sw", "L", "Gc"]
                .into_iter()
                .map(|name| (name.to_owned(), Value::from(0)))
                .collect();
            if let Some(object) = entry.as_object_mut() {
                object.insert(
                    "audit_data".to_owned(),
                    json!({
                        "messages": if messages.is_empty() { Value::Null } else { json!(messages) },
                        "error_messages": null,
                        "handler": "",
                        "stopwatch": stopwatch,
                        "response_body_dechunked": false,
                        "producer": if producers.is_empty() { Value::Null } else { json!(producers) },
                        "server": "",
                        "engine_mode": producer.rule_engine,
                    }),
                );
            }
        }
        entry
    }
}

/// The data of a message, as Go Coraza writes it in JSON.
fn message_data_json(data: &AuditMessageData) -> Value {
    json!({
        "file": data.file,
        "line": data.line,
        "id": data.id,
        "rev": data.rev,
        "msg": data.msg,
        "data": data.data,
        "severity": data.severity,
        "ver": data.ver,
        "maturity": data.maturity,
        "accuracy": data.accuracy,
        "tags": data.tags,
        "raw": data.raw,
    })
}

/// `value` without the object fields that are null, `""`, `0`, `false` or `[]`, at any
/// depth, as protobuf's JSON tags leave them out in Go.
fn omit_empty(value: Value) -> Value {
    let is_empty = |value: &Value| match value {
        Value::Null => true,
        Value::Bool(set) => !set,
        Value::Number(number) => number.as_f64() == Some(0.0),
        Value::String(text) => text.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(_) => false,
    };
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .map(|(name, value)| (name, omit_empty(value)))
                .filter(|(_, value)| !is_empty(value))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(omit_empty).collect()),
        other => other,
    }
}

/// `text` with `\`, CR and LF escaped, as the native format writes values.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('\r', "\\r").replace('\n', "\\n")
}

/// The reason phrase of an HTTP status code, as Go's `http.StatusText` gives it; empty
/// for an unknown code.
fn status_text(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "",
    }
}

/// The MIME type of a file named `name`, from its extension, as Go's built-in table has
/// it; empty if unknown.
pub(crate) fn mime_type_of(name: &str) -> &'static str {
    let extension = name.rsplit_once('.').map(|(_, ext)| ext.to_ascii_lowercase());
    match extension.as_deref() {
        Some("avif") => "image/avif",
        Some("css") => "text/css; charset=utf-8",
        Some("gif") => "image/gif",
        Some("htm" | "html") => "text/html; charset=utf-8",
        Some("jpeg" | "jpg") => "image/jpeg",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("wasm") => "application/wasm",
        Some("webp") => "image/webp",
        Some("xml") => "text/xml; charset=utf-8",
        _ => "",
    }
}

/// Writes audit log entries in `SecAuditLogFormat` where `SecAuditLogType` says, and
/// knows which transactions `SecAuditEngine RelevantOnly` keeps.
#[derive(Debug)]
pub(crate) struct AuditLogger {
    /// Format used for each audit entry.
    format: AuditLogFormat,
    /// `SecAuditLogRelevantStatus`, if set
    relevant_status: Option<Regex>,
    /// Writer selected from `SecAuditLogType` and `SecAuditLog`.
    writer: Writer,
}

/// Where audit log entries go.
enum Writer {
    /// Nowhere: without `SecAuditLog`, as in Go Coraza
    Discard,
    /// One after the other, into one file or stream
    Serial(Mutex<Box<dyn Write + Send>>),
    /// One file each, under `dir`, listed in an index
    Concurrent {
        /// Append-only index file.
        index: Mutex<File>,
        /// Root directory containing dated entry directories.
        dir: PathBuf,
        /// Permission bits for created directories.
        dir_mode: u32,
        /// Permission bits for each created entry.
        file_mode: u32,
    },
    /// One message each, to syslog
    Syslog(Mutex<Syslog>),
}

impl fmt::Debug for Writer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discard => f.write_str("Discard"),
            Self::Serial(_) => f.write_str("Serial"),
            Self::Concurrent { dir, .. } => f.debug_struct("Concurrent").field("dir", dir).finish(),
            Self::Syslog(_) => f.write_str("Syslog"),
        }
    }
}

impl AuditLogger {
    /// Create a logger that discards audit entries.
    pub(crate) fn discard() -> Self {
        Self {
            format: AuditLogFormat::Native,
            relevant_status: None,
            writer: Writer::Discard,
        }
    }

    /// Opens the audit log `config` describes: its file is created if missing.
    ///
    /// # Errors
    ///
    /// If the file or syslog can't be opened, `SecAuditLogRelevantStatus` isn't a
    /// regular expression, or the writer is `HTTPS`, which isn't supported here.
    pub(crate) fn open(config: &WafConfig) -> Result<Self, String> {
        let relevant_status = match config.audit_log_relevant_status.as_str() {
            "" => None,
            pattern => {
                Some(Regex::new(pattern).map_err(|e| format!("invalid SecAuditLogRelevantStatus {pattern:?}: {e}"))?)
            },
        };
        let target = config.audit_log.as_str();
        if config.audit_log_type == AuditLogType::Concurrent
            && !target.is_empty()
            && config.audit_log_storage_dir.is_empty()
        {
            return Err("SecAuditLogStorageDir is required for concurrent audit logs".to_owned());
        }
        let writer = match (config.audit_log_type, target) {
            // HTTPS needs an HTTP client with TLS, which no dependency provides
            (AuditLogType::Https, _) => {
                return Err("audit log type HTTPS is not supported".to_owned());
            },
            (AuditLogType::Syslog, target) => Writer::Syslog(Mutex::new(
                Syslog::connect(target).map_err(|e| format!("syslog dial failure: {e}"))?,
            )),
            (_, "") => Writer::Discard,
            (AuditLogType::Serial, "/dev/stdout") => Writer::Serial(Mutex::new(Box::new(io::stdout()))),
            (AuditLogType::Serial, "/dev/stderr") => Writer::Serial(Mutex::new(Box::new(io::stderr()))),
            (AuditLogType::Serial, path) => {
                Writer::Serial(Mutex::new(Box::new(open_append(path, config.audit_log_file_mode)?)))
            },
            (AuditLogType::Concurrent, path) => Writer::Concurrent {
                index: Mutex::new(open_append(path, config.audit_log_file_mode)?),
                dir: PathBuf::from(&config.audit_log_storage_dir),
                dir_mode: config.audit_log_dir_mode,
                file_mode: config.audit_log_file_mode,
            },
        };
        Ok(Self {
            format: config.audit_log_format,
            relevant_status,
            writer,
        })
    }

    /// Whether a `RelevantOnly` audit engine logs a transaction: one where a rule with
    /// `auditlog` matched (`audited`) is logged unless its `status` falls outside
    /// `SecAuditLogRelevantStatus`; any other only if its status falls inside it.
    pub(crate) fn is_relevant(&self, audited: bool, status: &str) -> bool {
        match &self.relevant_status {
            Some(relevant) => relevant.is_match(status),
            None => audited,
        }
    }

    /// Writes `entry`.
    ///
    /// # Errors
    ///
    /// If writing fails.
    pub(crate) fn write(&self, entry: &AuditLog) -> io::Result<()> {
        let formatted = entry.format(self.format);
        if formatted.is_empty() {
            return Ok(());
        }
        match &self.writer {
            Writer::Discard => Ok(()),
            Writer::Syslog(syslog) => syslog
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .send(&formatted, entry.transaction.is_interrupted),
            Writer::Serial(output) => {
                let mut output = output.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                writeln!(output, "{formatted}")?;
                output.flush()
            },
            Writer::Concurrent {
                index,
                dir,
                dir_mode,
                file_mode,
            } => {
                let tx = &entry.transaction;
                let seconds = u64::try_from(tx.unix_timestamp / 1_000_000_000).unwrap_or_default();
                let at = UtcTime::from_unix(seconds);
                let day = format!("{:04}{:02}{:02}", at.year, at.month, at.day);
                let minute = format!("{day}-{:02}{:02}", at.hour, at.minute);
                let entry_dir = dir.join(&day).join(&minute);
                create_dir_all(&entry_dir, *dir_mode)?;
                let sequence = NEXT_AUDIT_FILE_ID.fetch_add(1, Ordering::Relaxed);
                let id = safe_file_component(&tx.id);
                let path = entry_dir.join(format!(
                    "{minute}{:02}-{id}-{}-{sequence}",
                    at.second,
                    std::process::id()
                ));
                write_new(&path, formatted.as_bytes(), *file_mode)?;

                // The index lines, as Go Coraza's logger writes them
                let mut index = index.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                writeln!(
                    index,
                    "{} {} - - [{}]",
                    index_field(&tx.client_ip),
                    index_field(&tx.host_ip),
                    index_field(&tx.timestamp)
                )?;
                let request = &tx.request;
                writeln!(
                    index,
                    " \"{} {} {}\"",
                    index_field(&request.method),
                    index_field(&request.uri),
                    index_field(&request.http_version)
                )?;
                if let Some(response) = &tx.response {
                    writeln!(index, " {}", response.status)?;
                }
                writeln!(
                    index,
                    "{} - {}",
                    index_field(&tx.id),
                    index_field(&path.display().to_string())
                )?;
                index.flush()
            },
        }
    }
}

/// A connection to syslog, as Go's `log/syslog` dials it with facility `local0` and tag
/// `com.coraza.waf`.
struct Syslog {
    /// Connected socket.
    socket: SyslogSocket,
    /// Whether it is the local syslog, which takes a shorter header
    local: bool,
}

/// Socket types supported by the Go-compatible syslog target syntax.
enum SyslogSocket {
    /// UDP datagram socket.
    Udp(std::net::UdpSocket),
    /// TCP stream socket.
    Tcp(std::net::TcpStream),
    #[cfg(unix)]
    /// Unix domain stream socket.
    UnixStream(std::os::unix::net::UnixStream),
    #[cfg(unix)]
    /// Unix domain datagram socket.
    UnixDatagram(std::os::unix::net::UnixDatagram),
}

impl Syslog {
    /// Connects to `target` as Go Coraza reads it: `scheme://address`, where the scheme
    /// is `udp`, `tcp`, `unix` or `unixgram`; an address alone, over TCP; or, empty, the
    /// local syslog.
    fn connect(target: &str) -> io::Result<Self> {
        let unsupported =
            |network: &str| io::Error::new(io::ErrorKind::Unsupported, format!("unsupported network {network:?}"));
        let (network, address) = match target.split_once("://") {
            Some((network, address)) => (network, address),
            None => ("tcp", target),
        };
        let socket = match (network, address) {
            #[cfg(unix)]
            (_, "") => return Self::connect_local(),
            ("udp" | "udp4" | "udp6", address) => {
                let socket = std::net::UdpSocket::bind(if address.starts_with('[') {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                })?;
                socket.connect(address)?;
                SyslogSocket::Udp(socket)
            },
            ("tcp" | "tcp4" | "tcp6", address) => SyslogSocket::Tcp(std::net::TcpStream::connect(address)?),
            #[cfg(unix)]
            ("unix", path) => SyslogSocket::UnixStream(std::os::unix::net::UnixStream::connect(path)?),
            #[cfg(unix)]
            ("unixgram", path) => {
                let socket = std::os::unix::net::UnixDatagram::unbound()?;
                socket.connect(path)?;
                SyslogSocket::UnixDatagram(socket)
            },
            (network, _) => return Err(unsupported(network)),
        };
        Ok(Self { socket, local: false })
    }

    /// The local syslog, at the first of Go's known socket paths that answers.
    #[cfg(unix)]
    fn connect_local() -> io::Result<Self> {
        let mut last_error = io::Error::new(io::ErrorKind::NotFound, "no local syslog");
        for path in ["/dev/log", "/var/run/syslog", "/var/run/log"] {
            let datagram =
                std::os::unix::net::UnixDatagram::unbound().and_then(|socket| socket.connect(path).map(|()| socket));
            let socket = match datagram {
                Ok(socket) => SyslogSocket::UnixDatagram(socket),
                Err(_) => match std::os::unix::net::UnixStream::connect(path) {
                    Ok(stream) => SyslogSocket::UnixStream(stream),
                    Err(e) => {
                        last_error = e;
                        continue;
                    },
                },
            };
            return Ok(Self { socket, local: true });
        }
        Err(last_error)
    }

    /// Sends `message` at severity `err` if `error`, `info` otherwise, framed as Go's
    /// `log/syslog` does.
    fn send(&mut self, message: &str, error: bool) -> io::Result<()> {
        // local0 (16) times 8, plus the severity
        let priority = 16 * 8 + if error { 3 } else { 6 };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let at = UtcTime::from_unix(now);
        let tag = format!("com.coraza.waf[{}]", std::process::id());
        let newline = if message.ends_with('\n') { "" } else { "\n" };
        let framed = if self.local {
            const MONTHS: [&str; 12] = [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ];
            let month_index = at
                .month
                .checked_sub(1)
                .and_then(|month| usize::try_from(month).ok())
                .unwrap_or_default();
            let month = MONTHS.get(month_index).copied().unwrap_or("Jan");
            format!(
                "<{priority}>{} {:>2} {:02}:{:02}:{:02} {tag}: {message}{newline}",
                month, at.day, at.hour, at.minute, at.second
            )
        } else {
            format!(
                "<{priority}>{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z {} {tag}: {message}{newline}",
                at.year,
                at.month,
                at.day,
                at.hour,
                at.minute,
                at.second,
                hostname()
            )
        };
        match &mut self.socket {
            SyslogSocket::Udp(socket) => socket.send(framed.as_bytes()).map(|_| ()),
            SyslogSocket::Tcp(stream) => stream.write_all(framed.as_bytes()),
            #[cfg(unix)]
            SyslogSocket::UnixStream(stream) => stream.write_all(framed.as_bytes()),
            #[cfg(unix)]
            SyslogSocket::UnixDatagram(socket) => socket.send(framed.as_bytes()).map(|_| ()),
        }
    }
}

/// This host's name, as the kernel has it; `localhost` if unknown.
fn hostname() -> String {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .into_iter()
        .find_map(|path| fs::read_to_string(path).ok())
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "localhost".to_owned())
}

/// Open `path` for append, creating it with `mode` when needed.
fn open_append(path: &str, mode: u32) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
    #[cfg(not(unix))]
    let _ = mode;
    options
        .open(path)
        .map_err(|e| format!("cannot open audit log {path}: {e}"))
}

/// Recursively create `dir` with the configured permission bits.
fn create_dir_all(dir: &Path, mode: u32) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, mode);
    #[cfg(not(unix))]
    let _ = mode;
    builder.create(dir)
}

/// Create a new file without following or replacing an existing path.
fn write_new(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
    #[cfg(not(unix))]
    let _ = mode;
    options.open(path)?.write_all(contents)
}

/// Return a transaction ID that is safe for use as one filename component.
fn safe_file_component(id: &str) -> &str {
    if !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        id
    } else {
        "transaction"
    }
}

/// Escape fields written to the concurrent audit index.
fn index_field(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\r' => escaped.push_str("\\r"),
            '\n' => escaped.push_str("\\n"),
            character if character.is_control() => {
                write!(escaped, "\\u{{{:x}}}", character as u32).unwrap_or(());
            },
            character => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "audit log tests use fixed temporary paths")]
mod tests {
    use super::{AuditLog, AuditLogger, AuditTransaction, index_field, safe_file_component, write_new};
    use crate::{
        actions::RuleMetadata,
        collection::MatchData,
        config::WafConfig,
        types::{AuditEngineStatus, AuditLogFormat, AuditLogType, RulePhase, parse_audit_log_parts},
    };

    #[test]
    fn concurrent_file_components_reject_paths_and_long_ids() {
        assert_eq!(safe_file_component("request-1"), "request-1");
        assert_eq!(safe_file_component("../../audit"), "transaction");
        assert_eq!(safe_file_component(&"x".repeat(65)), "transaction");
    }

    #[test]
    fn index_fields_escape_log_delimiters_and_controls() {
        assert_eq!(index_field("a\"b\\c\r\n\u{0001}"), "a\\\"b\\\\c\\r\\n\\u{1}");
    }

    #[test]
    fn relevant_status_overrides_match_audit_flags_when_configured() {
        let logger = AuditLogger::open(&WafConfig::default()).unwrap();
        assert!(!logger.is_relevant(false, "403"));
        assert!(logger.is_relevant(true, "200"));

        let config = WafConfig {
            audit_log_relevant_status: "^(403|5[0-9]{2})$".to_owned(),
            ..WafConfig::default()
        };
        let logger = AuditLogger::open(&config).unwrap();
        assert!(logger.is_relevant(false, "403"));
        assert!(!logger.is_relevant(true, "200"));
    }

    #[test]
    fn all_audit_formats_produce_records() {
        let entry = AuditLog {
            parts: parse_audit_log_parts("ABFHZ").unwrap(),
            transaction: AuditTransaction {
                timestamp: "2023/11/14 22:13:20".to_owned(),
                unix_timestamp: 1_700_000_000_000_000_000,
                id: "tx-1".to_owned(),
                ..AuditTransaction::default()
            },
            ..AuditLog::default()
        };

        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            let formatted = entry.format(format);
            assert!(serde_json::from_str::<serde_json::Value>(&formatted).is_ok());
        }
        let native = entry.format(AuditLogFormat::Native);
        assert!(native.contains("-A--\n"));
        assert!(native.contains("-Z--\n"));
    }

    #[test]
    fn error_log_quotes_fields_and_separates_chain_matches() {
        let mut rule = RuleMetadata::new();
        rule.id = 71;
        rule.file = "rules.conf".to_owned();
        rule.line = 4;
        rule.phase = RulePhase::RequestHeaders;
        let mut first = MatchData::new_empty();
        first.message = "found\nvalue".to_owned();
        first.data = "first".to_owned();
        let mut second = MatchData::new_empty();
        second.message = "linked".to_owned();
        second.data = "second".to_owned();
        let matched = super::MatchedRule {
            rule,
            matches: vec![first, second],
            disruptive_action: Some("deny"),
            disruptive: true,
            client_ip: "192.0.2.1".to_owned(),
            server_ip: "192.0.2.2".to_owned(),
            uri: "/path".to_owned(),
            transaction_id: "tx-1".to_owned(),
        };

        let formatted = matched.error_log();
        assert!(formatted.contains("[msg_match_1 \"linked\"] [data_match_1 \"second\"]"));
        assert!(!formatted.contains('\n'), "{formatted:?}");
    }

    #[test]
    fn concurrent_writer_uses_safe_unique_names_and_escapes_index_fields() {
        let dir = tempfile::tempdir().unwrap();
        let index = dir.path().join("index.log");
        let storage = dir.path().join("entries");
        let config = WafConfig {
            audit_engine: AuditEngineStatus::On,
            audit_log: index.to_string_lossy().into_owned(),
            audit_log_type: AuditLogType::Concurrent,
            audit_log_storage_dir: storage.to_string_lossy().into_owned(),
            ..WafConfig::default()
        };
        let logger = AuditLogger::open(&config).unwrap();
        let entry = AuditLog {
            parts: parse_audit_log_parts("AZ").unwrap(),
            transaction: AuditTransaction {
                timestamp: "2023/11/14 22:13:20".to_owned(),
                unix_timestamp: 1_700_000_000_000_000_000,
                id: "../../unsafe\nid".to_owned(),
                client_ip: "192.0.2.1\r\nforged".to_owned(),
                ..AuditTransaction::default()
            },
            ..AuditLog::default()
        };

        logger.write(&entry).unwrap();
        logger.write(&entry).unwrap();

        let day = storage.join("20231114").join("20231114-2213");
        let mut files = std::fs::read_dir(day)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        files.sort();
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|name| name.contains("-transaction-")));
        assert_eq!(std::fs::read_to_string(index).unwrap().lines().count(), 6);
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_file_creation_does_not_follow_symlinks_or_truncate() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("entry");
        std::fs::write(&target, b"preserve").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(write_new(&link, b"replace", 0o600).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"preserve");
    }
}
