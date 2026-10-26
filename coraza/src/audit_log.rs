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
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use regex::Regex;
use serde_json::{Value, json};

use crate::{
    actions::RuleMetadata,
    collection::MatchData,
    config::WafConfig,
    types::{AuditLogFormat, AuditLogPart, AuditLogParts, AuditLogType},
    utils::time::LocalTime,
};

/// Next process-local suffix for concurrent audit log filenames.
static NEXT_AUDIT_FILE_ID: AtomicU64 = AtomicU64::new(1);

/// How long an internal caller waits before retrying a failed audit activation.
///
/// A failed sink may recover without an explicit [`AuditLogger::activate`], so the
/// first write after this delay tries again instead of failing for the WAF's lifetime.
const ACTIVATION_RETRY_BACKOFF: Duration = Duration::from_secs(30);

/// Longest wait between two internal activation attempts.
///
/// The backoff doubles on every failure up to this cap, so a sink that stays down costs
/// at most one bounded attempt every five minutes.
const ACTIVATION_RETRY_BACKOFF_MAX: Duration = Duration::from_secs(300);

/// Deadline an internal activation attempt applies when the configuration sets none.
///
/// A deliberate safety deviation: Go Coraza's syslog dial is unbounded, so a blackholed
/// peer parks a request thread for the kernel's SYN timeout (about two minutes). The
/// explicit [`AuditLogger::activate`] path keeps the unbounded default.
const ACTIVATION_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// When the transaction started, as `2006/01/02 15:04:05`, in the process-local time zone
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
pub(crate) struct ErrorLog(Arc<ErrorLogCallback>);

/// Thread-safe callback invoked for each matching logged rule.
type ErrorLogCallback = dyn Fn(&MatchedRule) + Send + Sync;

impl ErrorLog {
    /// Wrap a callback for sharing across transactions.
    pub(crate) fn new(log: impl Fn(&MatchedRule) + Send + Sync + 'static) -> Self {
        Self(Arc::new(log))
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
    /// How the writer is built when first needed, validated without opening it.
    plan: WriterPlan,
    /// Serialises writer construction, so concurrent first uses open exactly one writer.
    gate: Mutex<()>,
    /// The opened writer and the memoised activation failure.
    state: RwLock<ActivationState>,
}

/// A terminal I/O failure, kept so a later call can report it again.
#[derive(Debug, Clone)]
pub(crate) struct Failure {
    /// The original error kind.
    kind: io::ErrorKind,
    /// The original error message.
    message: String,
}

impl Failure {
    /// Remember `error`.
    pub(crate) fn new(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    /// A new error carrying the remembered kind and message.
    pub(crate) fn to_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

/// The writer slot, the last activation failure and its retry deadline.
#[derive(Debug)]
struct ActivationState {
    /// The opened writer, shared so a write never holds an activation lock.
    writer: Option<Arc<Writer>>,
    /// The last activation failure, cleared by a successful attempt.
    failure: Option<Failure>,
    /// Earliest time an internal caller may retry after `failure`; `None` when any
    /// internal caller may try again.
    retry_at: Option<Instant>,
    /// Wait scheduled after the next failure; doubles up to `ACTIVATION_RETRY_BACKOFF_MAX`.
    backoff: Duration,
    /// Number of activation attempts, for tests that count attempts per window.
    #[cfg(test)]
    attempts: usize,
}

impl Default for ActivationState {
    fn default() -> Self {
        Self {
            writer: None,
            failure: None,
            retry_at: None,
            backoff: ACTIVATION_RETRY_BACKOFF,
            #[cfg(test)]
            attempts: 0,
        }
    }
}

/// The wait scheduled after a failure that followed one of `current`.
fn next_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(ACTIVATION_RETRY_BACKOFF_MAX)
}

/// The connect deadline one attempt applies: the configured one, else the internal default.
fn connect_deadline(configured: Option<Duration>, internal: bool) -> Option<Duration> {
    configured.or_else(|| internal.then_some(ACTIVATION_CONNECT_TIMEOUT))
}

/// How to build the audit writer once, without opening or connecting anything yet.
#[derive(Debug)]
enum WriterPlan {
    /// Nowhere: without `SecAuditLog`, as in Go Coraza
    Discard,
    /// One after the other, into one file or stream
    Serial {
        /// File path or standard stream.
        target: SerialTarget,
        /// Permission bits for a created file.
        file_mode: u32,
    },
    /// One file each, under `dir`, listed in an index
    Concurrent {
        /// Append-only index path.
        index: String,
        /// Root directory containing dated entry directories.
        dir: PathBuf,
        /// Permission bits for created directories.
        dir_mode: u32,
        /// Permission bits for each created entry.
        file_mode: u32,
    },
    /// One message each, to syslog
    Syslog {
        /// Configured target.
        target: String,
        /// Deadline for connecting, `None` for no deadline.
        connect_timeout: Option<Duration>,
        /// Deadline for each write, `None` for no deadline.
        write_timeout: Option<Duration>,
    },
    /// One POST each, to an HTTP endpoint
    #[cfg(feature = "https-audit")]
    Https {
        /// Configured target.
        target: String,
    },
}

/// Where a serial audit writer sends its entries.
#[derive(Debug)]
enum SerialTarget {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// A file opened for append.
    File(String),
}

impl WriterPlan {
    /// Open the planned writer, creating files and connecting sockets as needed.
    ///
    /// `internal` selects the connect default: an internal activation attempt bounds a
    /// syslog dial the configuration left unbounded.
    fn open(&self, format: AuditLogFormat, internal: bool) -> io::Result<Writer> {
        #[cfg(not(feature = "https-audit"))]
        let _ = format;
        Ok(match self {
            Self::Discard => Writer::Discard,
            Self::Serial { target, file_mode } => Writer::Serial(Mutex::new(match target {
                SerialTarget::Stdout => Box::new(io::stdout()),
                SerialTarget::Stderr => Box::new(io::stderr()),
                SerialTarget::File(path) => Box::new(open_append(path, *file_mode)?),
            })),
            Self::Concurrent {
                index,
                dir,
                dir_mode,
                file_mode,
            } => Writer::Concurrent {
                index: Mutex::new(open_append(index, *file_mode)?),
                dir: dir.clone(),
                dir_mode: *dir_mode,
                file_mode: *file_mode,
            },
            Self::Syslog {
                target,
                connect_timeout,
                write_timeout,
            } => {
                // Keep the dial error's kind, like the file and index paths above.
                let syslog = Syslog::connect(target, connect_deadline(*connect_timeout, internal), *write_timeout)
                    .map_err(|error| io::Error::new(error.kind(), format!("syslog dial failure: {error}")))?;
                Writer::Syslog(Mutex::new(syslog))
            },
            #[cfg(feature = "https-audit")]
            Self::Https { target } => {
                Writer::Https(https::HttpsWriter::open(target, format).map_err(io::Error::other)?)
            },
        })
    }
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
    /// One POST each, to an HTTP endpoint
    #[cfg(feature = "https-audit")]
    Https(https::HttpsWriter),
}

impl fmt::Debug for Writer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discard => f.write_str("Discard"),
            Self::Serial(_) => f.write_str("Serial"),
            Self::Concurrent { dir, .. } => f.debug_struct("Concurrent").field("dir", dir).finish(),
            Self::Syslog(_) => f.write_str("Syslog"),
            #[cfg(feature = "https-audit")]
            Self::Https(_) => f.write_str("Https"),
        }
    }
}

impl Writer {
    /// Write one formatted entry to this writer.
    fn write(&self, formatted: &str, entry: &AuditLog) -> io::Result<()> {
        match self {
            Self::Discard => Ok(()),
            #[cfg(feature = "https-audit")]
            Self::Https(https) => https.write(formatted),
            Self::Syslog(syslog) => syslog
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .send(formatted, entry.transaction.is_interrupted),
            Self::Serial(output) => {
                let mut output = output.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                writeln!(output, "{formatted}")?;
                output.flush()
            },
            Self::Concurrent {
                index,
                dir,
                dir_mode,
                file_mode,
            } => {
                let tx = &entry.transaction;
                let at = LocalTime::from_unix(tx.unix_timestamp / 1_000_000_000);
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

impl AuditLogger {
    /// Create a logger that discards audit entries.
    pub(crate) fn discard() -> Self {
        Self {
            format: AuditLogFormat::Native,
            relevant_status: None,
            plan: WriterPlan::Discard,
            gate: Mutex::new(()),
            state: RwLock::new(ActivationState::default()),
        }
    }

    /// Build the audit log `config` describes without opening or connecting its writer.
    ///
    /// The target syntax is validated here; files and sockets are only created or
    /// connected by [`AuditLogger::activate`].
    ///
    /// # Errors
    ///
    /// If `SecAuditLogRelevantStatus` isn't a regular expression, the storage directory
    /// of a concurrent log is missing, a syslog target has an unsupported scheme or an
    /// empty address, or the writer is `HTTPS` and the `https-audit` feature is disabled
    /// or the target isn't a valid URI.
    pub(crate) fn prepare(config: &WafConfig) -> Result<Self, String> {
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
        let plan = match (config.audit_log_type, target) {
            #[cfg(feature = "https-audit")]
            (AuditLogType::Https, target) => {
                https::validate_target(target)?;
                WriterPlan::Https {
                    target: target.to_owned(),
                }
            },
            #[cfg(not(feature = "https-audit"))]
            (AuditLogType::Https, _) => {
                return Err(
                    "audit log type HTTPS is not supported in this build; enable the \"https-audit\" crate feature"
                        .to_owned(),
                );
            },
            (AuditLogType::Syslog, target) => {
                validate_syslog_target(target)?;
                WriterPlan::Syslog {
                    target: target.to_owned(),
                    connect_timeout: config.audit_log_connect_timeout,
                    write_timeout: config.audit_log_write_timeout,
                }
            },
            (_, "") => WriterPlan::Discard,
            (AuditLogType::Serial, "/dev/stdout") => WriterPlan::Serial {
                target: SerialTarget::Stdout,
                file_mode: config.audit_log_file_mode,
            },
            (AuditLogType::Serial, "/dev/stderr") => WriterPlan::Serial {
                target: SerialTarget::Stderr,
                file_mode: config.audit_log_file_mode,
            },
            (AuditLogType::Serial, path) => WriterPlan::Serial {
                target: SerialTarget::File(path.to_owned()),
                file_mode: config.audit_log_file_mode,
            },
            (AuditLogType::Concurrent, path) => WriterPlan::Concurrent {
                index: path.to_owned(),
                dir: PathBuf::from(&config.audit_log_storage_dir),
                dir_mode: config.audit_log_dir_mode,
                file_mode: config.audit_log_file_mode,
            },
        };
        Ok(Self {
            format: config.audit_log_format,
            relevant_status,
            plan,
            gate: Mutex::new(()),
            state: RwLock::new(ActivationState::default()),
        })
    }

    /// Open or connect the planned writer once, retrying a memoised failure.
    ///
    /// Explicit activation is the only path that retries immediately: after a failure,
    /// internal callers keep reporting the memoised error until the backoff has passed.
    /// A configured connect deadline applies as it does internally; without one, this
    /// path leaves a syslog dial unbounded, as Go Coraza does.
    ///
    /// # Errors
    ///
    /// If the file, syslog socket or HTTP client cannot be opened.
    pub(crate) fn activate(&self) -> io::Result<()> {
        let _gate = self.gate.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.writer().is_some() {
            return Ok(());
        }
        self.install(false)
    }

    /// Open the writer if it was never activated, retrying a failure after its backoff.
    ///
    /// A syslog dial the configuration left unbounded gets
    /// [`ACTIVATION_CONNECT_TIMEOUT`], so one failing attempt cannot park a request
    /// thread for the kernel's SYN timeout.
    ///
    /// # Errors
    ///
    /// If an activation is due and fails, or a previous failure is still inside its
    /// retry backoff.
    pub(crate) fn ensure_activated(&self) -> io::Result<()> {
        {
            let state = self.state.read().unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.writer.is_some() {
                return Ok(());
            }
            if let Some(failure) = &state.failure
                && Self::in_backoff(&state)
            {
                return Err(failure.to_error());
            }
        }
        let _gate = self.gate.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        {
            let state = self.state.read().unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.writer.is_some() {
                return Ok(());
            }
            if let Some(failure) = &state.failure
                && Self::in_backoff(&state)
            {
                return Err(failure.to_error());
            }
        }
        self.install(true)
    }

    /// Whether a failed activation may not be retried yet.
    fn in_backoff(state: &ActivationState) -> bool {
        state.retry_at.is_some_and(|retry_at| Instant::now() < retry_at)
    }

    /// Open the planned writer outside the state lock; the activation gate is held.
    fn install(&self, internal: bool) -> io::Result<()> {
        let opened = self.plan.open(self.format, internal);
        let mut state = self.state.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(test)]
        {
            state.attempts = state.attempts.saturating_add(1);
        }
        match opened {
            Ok(writer) => {
                state.writer = Some(Arc::new(writer));
                state.failure = None;
                state.retry_at = None;
                state.backoff = ACTIVATION_RETRY_BACKOFF;
                drop(state);
                Ok(())
            },
            Err(error) => {
                state.failure = Some(Failure::new(&error));
                state.retry_at = Instant::now().checked_add(state.backoff);
                state.backoff = next_backoff(state.backoff);
                drop(state);
                Err(error)
            },
        }
    }

    /// The failure from the last activation attempt, unless a later attempt succeeded.
    ///
    /// The kind is kept so a caller can tell a dial failure from a configuration one.
    pub(crate) fn activation_error(&self) -> Option<(io::ErrorKind, String)> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .failure
            .as_ref()
            .map(|failure| (failure.kind, failure.message.clone()))
    }

    /// Allow the next internal activation attempt immediately, as if the backoff passed.
    #[cfg(test)]
    pub(crate) fn expire_backoff(&self) {
        self.state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retry_at = None;
    }

    /// The number of activation attempts so far.
    #[cfg(test)]
    pub(crate) fn attempts(&self) -> usize {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .attempts
    }

    /// The wait the next internal failure will schedule.
    #[cfg(test)]
    pub(crate) fn next_backoff_window(&self) -> Duration {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .backoff
    }

    /// The opened writer, if activation succeeded.
    fn writer(&self) -> Option<Arc<Writer>> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .writer
            .clone()
    }

    /// Build and activate the audit log `config` describes, creating its file if missing.
    ///
    /// # Errors
    ///
    /// If [`AuditLogger::prepare`] or [`AuditLogger::activate`] fails.
    #[cfg(test)]
    pub(crate) fn open(config: &WafConfig) -> Result<Self, String> {
        let logger = Self::prepare(config)?;
        logger.activate().map_err(|error| error.to_string())?;
        Ok(logger)
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

    /// Write `entry`, activating the writer first if it is not open.
    ///
    /// # Errors
    ///
    /// If the writer cannot be activated or writing fails.
    pub(crate) fn write(&self, entry: &AuditLog) -> io::Result<()> {
        let formatted = entry.format(self.format);
        if formatted.is_empty() {
            return Ok(());
        }
        self.ensure_activated()?;
        let Some(writer) = self.writer() else {
            return Err(io::Error::other("audit log writer is not activated"));
        };
        writer.write(&formatted, entry)
    }
}

/// Validate a syslog target's syntax without dialing it.
///
/// An empty target selects the local syslog, which only exists on Unix, and a target
/// without `scheme://` is a TCP address, as [`Syslog::connect`] reads it. Only syntax is
/// checked: reachability is deferred to activation.
fn validate_syslog_target(target: &str) -> Result<(), String> {
    if target.is_empty() {
        return if cfg!(unix) {
            Ok(())
        } else {
            Err("invalid syslog target \"\": the local syslog is only available on Unix".to_owned())
        };
    }
    let Some((network, address)) = target.split_once("://") else {
        return Ok(());
    };
    match network {
        "udp" | "udp4" | "udp6" | "tcp" | "tcp4" | "tcp6" => {
            if address.is_empty() {
                return Err(format!("invalid syslog target {target:?}: {network} needs an address"));
            }
        },
        #[cfg(unix)]
        "unix" | "unixgram" => {
            if address.is_empty() {
                return Err(format!(
                    "invalid syslog target {target:?}: {network} needs a socket path"
                ));
            }
        },
        other => {
            return Err(format!(
                "invalid syslog target {target:?}: unsupported network {other:?}"
            ));
        },
    }
    Ok(())
}

/// A connection to syslog, as Go's `log/syslog` dials it with facility `local0` and tag
/// `com.coraza.waf`.
struct Syslog {
    /// Connected socket.
    socket: SyslogSocket,
    /// Original target, used if the socket needs to reconnect.
    target: String,
    /// Whether it is the local syslog, which takes a shorter header
    local: bool,
    /// Deadline for reconnecting a TCP socket, `None` for no deadline.
    connect_timeout: Option<Duration>,
    /// Deadline for each write, `None` for no deadline.
    write_timeout: Option<Duration>,
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

impl SyslogSocket {
    /// Apply `timeout` to writes on this socket; `None` restores the default.
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Udp(socket) => socket.set_write_timeout(timeout),
            Self::Tcp(stream) => stream.set_write_timeout(timeout),
            #[cfg(unix)]
            Self::UnixStream(stream) => stream.set_write_timeout(timeout),
            #[cfg(unix)]
            Self::UnixDatagram(socket) => socket.set_write_timeout(timeout),
        }
    }

    /// Write one already-framed syslog message to this socket.
    fn write_frame(&mut self, framed: &[u8]) -> io::Result<()> {
        match self {
            Self::Udp(socket) => socket.send(framed).map(|_| ()),
            Self::Tcp(stream) => stream.write_all(framed),
            #[cfg(unix)]
            Self::UnixStream(stream) => stream.write_all(framed),
            #[cfg(unix)]
            Self::UnixDatagram(socket) => socket.send(framed).map(|_| ()),
        }
    }
}

impl Syslog {
    /// Connects to `target` as Go Coraza reads it: `scheme://address`, where the scheme
    /// is `udp`, `tcp`, `unix` or `unixgram`; an address alone, over TCP; or, empty, the
    /// local syslog.
    ///
    /// `connect_timeout` bounds a TCP connection attempt; `write_timeout` is applied to
    /// the connected socket.
    fn connect(target: &str, connect_timeout: Option<Duration>, write_timeout: Option<Duration>) -> io::Result<Self> {
        let unsupported =
            |network: &str| io::Error::new(io::ErrorKind::Unsupported, format!("unsupported network {network:?}"));
        let (network, address) = match target.split_once("://") {
            Some((network, address)) => (network, address),
            None => ("tcp", target),
        };
        let socket = match (network, address) {
            #[cfg(unix)]
            (_, "") => return Self::connect_local(target, write_timeout),
            ("udp" | "udp4" | "udp6", address) => {
                let socket = std::net::UdpSocket::bind(if address.starts_with('[') {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                })?;
                socket.connect(address)?;
                SyslogSocket::Udp(socket)
            },
            ("tcp" | "tcp4" | "tcp6", address) => SyslogSocket::Tcp(connect_tcp(address, connect_timeout)?),
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
        socket.set_write_timeout(write_timeout)?;
        Ok(Self {
            socket,
            target: target.to_owned(),
            local: false,
            connect_timeout,
            write_timeout,
        })
    }

    /// The local syslog, at the first of Go's known socket paths that answers.
    ///
    /// Local connections are not bounded: [`Self::connect`]'s `connect_timeout` applies
    /// to TCP only, and a local reconnect ignores it.
    #[cfg(unix)]
    fn connect_local(target: &str, write_timeout: Option<Duration>) -> io::Result<Self> {
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
            // Applied only after a candidate answered, so a timeout error cannot abort
            // the search through the remaining paths.
            socket.set_write_timeout(write_timeout)?;
            return Ok(Self {
                socket,
                target: target.to_owned(),
                local: true,
                connect_timeout: None,
                write_timeout,
            });
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
            .map_or(0, |since| i64::try_from(since.as_secs()).unwrap_or(i64::MAX));
        let at = LocalTime::from_unix(now);
        let tag = format!("com.coraza.waf[{}]", std::process::id());
        let newline = if message.ends_with('\n') { "" } else { "\n" };
        let framed = if self.local {
            format!("<{priority}>{} {tag}: {message}{newline}", at.syslog_stamp())
        } else {
            format!("<{priority}>{} {} {tag}: {message}{newline}", at.rfc3339(), hostname())
        };
        if self.socket.write_frame(framed.as_bytes()).is_err() {
            *self = Self::connect(&self.target, self.connect_timeout, self.write_timeout)?;
            self.socket.write_frame(framed.as_bytes())?;
        }
        Ok(())
    }
}

/// Connects to a TCP syslog address, bounding the whole attempt when `timeout` is set.
///
/// DNS resolution is not bounded. Go's `net.DialTimeout` includes it, but bounding it
/// needs a resolver thread; the deadline starts once addresses are known.
fn connect_tcp(address: &str, timeout: Option<Duration>) -> io::Result<std::net::TcpStream> {
    use std::net::{TcpStream, ToSocketAddrs as _};
    let Some(timeout) = timeout else {
        return TcpStream::connect(address);
    };
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TCP connect timeout overflows the clock"))?;
    let mut last_error = io::Error::new(io::ErrorKind::TimedOut, "TCP connect timed out");
    for address in address.to_socket_addrs()? {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&address, remaining) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
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

/// The writer Go Coraza selects for `SecAuditLogType HTTPS`: one blocking POST per
/// entry, with the Go writer's headers, MIME type and one-second client timeout.
#[cfg(feature = "https-audit")]
mod https {
    use std::{io, time::Duration};

    use crate::types::AuditLogFormat;

    /// `User-Agent` Go Coraza's HTTPS writer sends with every entry.
    const USER_AGENT: &str = "Coraza+v3";

    /// Whole-request timeout Go Coraza's HTTPS client applies, in seconds.
    const TIMEOUT: Duration = Duration::from_secs(1);

    /// One audit entry POST, as Go Coraza's HTTPS writer sends it.
    struct HttpPost<'a> {
        /// The method; always `POST`, as in Go Coraza.
        method: &'static str,
        /// The configured target.
        url: &'a str,
        /// The `User-Agent` header value.
        user_agent: &'static str,
        /// The formatter's MIME type, sent as `Content-Type`.
        content_type: &'a str,
        /// The formatted audit entry.
        body: &'a [u8],
        /// The whole-request timeout, as Go Coraza's client applies it.
        timeout: Duration,
    }

    /// Performs the HTTP exchange for one audit entry, so tests need no network.
    trait HttpExchange: Send + Sync {
        /// POSTs `post` and returns the response status, draining the response body.
        fn post(&self, post: &HttpPost<'_>) -> Result<u16, String>;
    }

    /// The writer selected by `SecAuditLogType HTTPS`.
    pub(super) struct HttpsWriter {
        /// The configured target.
        url: String,
        /// The `Content-Type` of entries, from the configured format.
        content_type: &'static str,
        /// The HTTP client, or a test double.
        exchange: Box<dyn HttpExchange>,
    }

    impl HttpsWriter {
        /// Opens the writer `target` describes.
        ///
        /// `http` targets are accepted and send entries unencrypted, as Go Coraza
        /// accepts them. The target is parsed here, as Go Coraza parses it at
        /// `Init`.
        ///
        /// # Errors
        ///
        /// If `target` isn't a valid URI, or if it isn't an absolute `http` or
        /// `https` URL with a host and a port that parses as a `u16`. Go Coraza
        /// only parses the target at `Init` and fails on the first write; this
        /// writer is built with the WAF, and a dropped transaction ignores audit
        /// writer errors, so a target that cannot be posted to would silently
        /// lose entries.
        pub(super) fn open(target: &str, format: AuditLogFormat) -> Result<Self, String> {
            validate_target(target)?;
            Ok(Self::with_exchange(target, format, Box::new(UreqExchange::new())))
        }

        /// A writer sending through `exchange`.
        fn with_exchange(target: &str, format: AuditLogFormat, exchange: Box<dyn HttpExchange>) -> Self {
            Self {
                url: target.to_owned(),
                content_type: format_mime(format),
                exchange,
            }
        }

        /// POSTs one formatted entry, as Go Coraza's HTTPS writer does.
        ///
        /// # Errors
        ///
        /// If the request fails or the response status isn't 2xx.
        pub(super) fn write(&self, body: &str) -> io::Result<()> {
            let post = HttpPost {
                method: "POST",
                url: &self.url,
                user_agent: USER_AGENT,
                content_type: self.content_type,
                body: body.as_bytes(),
                timeout: TIMEOUT,
            };
            let status = self.exchange.post(&post).map_err(io::Error::other)?;
            if (200..300).contains(&status) {
                Ok(())
            } else {
                Err(io::Error::other(format!("unexpected status code {status}")))
            }
        }
    }

    /// Whether `target` is an absolute `http` or `https` URL with a host and a valid
    /// explicit port, as Go Coraza's HTTPS writer requires.
    pub(super) fn validate_target(target: &str) -> Result<(), String> {
        let uri = target
            .parse::<ureq::http::Uri>()
            .map_err(|error| format!("invalid HTTPS audit log target {target:?}: {error}"))?;
        if !is_http_target(&uri) {
            return Err(format!(
                "invalid HTTPS audit log target {target:?}: expected an absolute http:// or https:// URL with a host and a valid port"
            ));
        }
        Ok(())
    }

    /// Whether `uri` is an absolute `http` or `https` URL with a host and a valid
    /// explicit port.
    fn is_http_target(uri: &ureq::http::Uri) -> bool {
        let scheme = uri.scheme_str().unwrap_or_default();
        let is_http = scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https");
        is_http && uri.host().is_some_and(|host| !host.is_empty()) && !has_invalid_port(uri)
    }

    /// Whether `uri` carries an explicit port that is not a valid `u16`.
    ///
    /// [`ureq::http::Uri::port_u16`] is `None` both without a port and for a port
    /// it cannot parse, so the authority text is inspected instead.
    fn has_invalid_port(uri: &ureq::http::Uri) -> bool {
        let Some(authority) = uri.authority() else {
            return false;
        };
        // Userinfo may contain colons; host and port follow the last `@`.
        let host_port = authority
            .as_str()
            .rsplit_once('@')
            .map_or(authority.as_str(), |(_, host_port)| host_port);
        if host_port.ends_with(']') {
            return false; // An IPv6 literal with no port.
        }
        match host_port.rsplit_once(':') {
            // Go accepts an empty port and resolves it to the scheme default. Any
            // other port must be ASCII digits only, which `parse` alone doesn't
            // enforce: it accepts a leading `+`.
            Some((_, port)) => {
                !port.is_empty() && (port.bytes().any(|byte| !byte.is_ascii_digit()) || port.parse::<u16>().is_err())
            },
            None => false,
        }
    }

    /// [`HttpExchange`] backed by the `ureq` blocking client with rustls.
    struct UreqExchange(ureq::Agent);

    impl UreqExchange {
        /// The client Go Coraza's HTTPS writer uses, except that statuses are
        /// returned instead of turned into errors, so every non-2xx status fails the
        /// write.
        fn new() -> Self {
            let config = ureq::Agent::config_builder().http_status_as_error(false).build();
            Self(ureq::Agent::new_with_config(config))
        }
    }

    impl HttpExchange for UreqExchange {
        fn post(&self, post: &HttpPost<'_>) -> Result<u16, String> {
            let request = ureq::http::Request::builder()
                .method(post.method)
                .uri(post.url)
                .header("User-Agent", post.user_agent)
                .header("Content-Type", post.content_type)
                .body(post.body)
                .map_err(|error| format!("invalid HTTPS audit log request: {error}"))?;
            // Go Coraza sets the budget on its client; ureq applies it per request.
            let request = self
                .0
                .configure_request(request)
                .timeout_global(Some(post.timeout))
                .build();
            let response = self
                .0
                .run(request)
                .map_err(|error| format!("HTTPS audit log request failed: {error}"))?;
            let status = response.status().as_u16();
            // As in Go, a response body that fails to drain does not fail the write.
            let mut body = response.into_body().into_reader();
            drop(io::copy(&mut body, &mut io::sink()));
            Ok(status)
        }
    }

    /// The `Content-Type` of entries in `format`, as Go Coraza's formatters report it.
    fn format_mime(format: AuditLogFormat) -> &'static str {
        match format {
            AuditLogFormat::Native => "application/x-coraza-auditlog-native",
            AuditLogFormat::Json | AuditLogFormat::JsonLegacy => "application/json; charset=utf-8",
            AuditLogFormat::Ocsf => "application/json",
        }
    }

    #[cfg(test)]
    #[expect(clippy::unwrap_used, reason = "HTTPS audit log tests use scripted exchanges")]
    mod tests {
        use std::{
            collections::VecDeque,
            sync::{Arc, Mutex},
            time::Duration,
        };

        use super::{HttpExchange, HttpPost, HttpsWriter, TIMEOUT};
        use crate::types::AuditLogFormat;

        /// An [`HttpExchange`] that records requests and returns scripted responses.
        #[derive(Clone, Default)]
        struct ScriptedExchange {
            /// Responses to return, in order; success when empty.
            responses: Arc<Mutex<VecDeque<Result<u16, String>>>>,
            /// Requests received, in order.
            requests: Arc<Mutex<Vec<RecordedPost>>>,
        }

        /// A request recorded by [`ScriptedExchange`].
        #[derive(Clone, Debug)]
        struct RecordedPost {
            /// The request method.
            method: String,
            /// The target URL.
            url: String,
            /// The `User-Agent` header.
            user_agent: String,
            /// The `Content-Type` header.
            content_type: String,
            /// The request body.
            body: Vec<u8>,
            /// The whole-request timeout.
            timeout: Duration,
        }

        impl ScriptedExchange {
            /// An exchange returning `responses`, in order.
            fn new(responses: impl IntoIterator<Item = Result<u16, String>>) -> Self {
                Self {
                    responses: Arc::new(Mutex::new(responses.into_iter().collect())),
                    requests: Arc::new(Mutex::new(Vec::new())),
                }
            }

            /// The requests received so far.
            fn recorded(&self) -> Vec<RecordedPost> {
                self.requests.lock().unwrap().clone()
            }
        }

        impl HttpExchange for ScriptedExchange {
            fn post(&self, post: &HttpPost<'_>) -> Result<u16, String> {
                let request = RecordedPost {
                    method: post.method.to_owned(),
                    url: post.url.to_owned(),
                    user_agent: post.user_agent.to_owned(),
                    content_type: post.content_type.to_owned(),
                    body: post.body.to_vec(),
                    timeout: post.timeout,
                };
                self.requests.lock().unwrap().push(request);
                self.responses.lock().unwrap().pop_front().unwrap_or(Ok(200))
            }
        }

        /// A writer using an exchange scripted with `responses`, and that exchange.
        fn scripted_writer(
            target: &str,
            format: AuditLogFormat,
            responses: impl IntoIterator<Item = Result<u16, String>>,
        ) -> (HttpsWriter, ScriptedExchange) {
            let exchange = ScriptedExchange::new(responses);
            (
                HttpsWriter::with_exchange(target, format, Box::new(exchange.clone())),
                exchange,
            )
        }

        #[test]
        fn writer_posts_the_entry_as_go_does() {
            let (writer, exchange) = scripted_writer("http://127.0.0.1:8080/audit", AuditLogFormat::Json, [Ok(200)]);
            writer.write("{\"transaction\":{}}").unwrap();

            let requests = exchange.recorded();
            assert_eq!(requests.len(), 1);
            let request = requests.first().unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.url, "http://127.0.0.1:8080/audit");
            assert_eq!(request.user_agent, "Coraza+v3");
            assert_eq!(request.content_type, "application/json; charset=utf-8");
            assert_eq!(request.body.as_slice(), b"{\"transaction\":{}}");
            assert_eq!(request.timeout, Duration::from_secs(1));
        }

        #[test]
        fn content_type_is_the_go_formatter_mime() {
            for (format, mime) in [
                (AuditLogFormat::Native, "application/x-coraza-auditlog-native"),
                (AuditLogFormat::Json, "application/json; charset=utf-8"),
                (AuditLogFormat::JsonLegacy, "application/json; charset=utf-8"),
                (AuditLogFormat::Ocsf, "application/json"),
            ] {
                let (writer, exchange) = scripted_writer("https://example.com/audit", format, [Ok(200)]);
                writer.write("entry").unwrap();
                let requests = exchange.recorded();
                let request = requests.first().unwrap();
                assert_eq!(request.content_type, mime);
            }
        }

        #[test]
        fn success_is_only_2xx() {
            for status in [200, 201, 204, 299] {
                let (writer, _exchange) =
                    scripted_writer("https://example.com/audit", AuditLogFormat::Native, [Ok(status)]);
                writer.write("entry").unwrap();
            }
        }

        #[test]
        fn non_2xx_statuses_fail_as_in_go() {
            for status in [199, 300, 301, 400, 404, 500] {
                let (writer, _exchange) =
                    scripted_writer("https://example.com/audit", AuditLogFormat::Native, [Ok(status)]);
                let error = writer.write("entry").unwrap_err();
                assert_eq!(error.to_string(), format!("unexpected status code {status}"));
            }
        }

        #[test]
        fn transport_errors_propagate() {
            let (writer, _exchange) = scripted_writer(
                "https://example.com/audit",
                AuditLogFormat::Native,
                [Err("connection refused".to_owned())],
            );
            let error = writer.write("entry").unwrap_err();
            assert!(error.to_string().contains("connection refused"), "{error}");
        }

        #[test]
        fn timeout_is_the_go_second() {
            assert_eq!(TIMEOUT, Duration::from_secs(1));
        }

        #[test]
        fn open_accepts_https_and_plaintext_http_targets() {
            for target in [
                "https://example.com/audit",
                "http://127.0.0.1:8080/audit",
                "http://collector.example:65535/audit",
                "https://example.com:/audit",
                "http://[::1]:8080/audit",
                "http://[::1]/audit",
                "http://user:pass@collector.example/audit",
            ] {
                assert!(HttpsWriter::open(target, AuditLogFormat::Json).is_ok(), "{target}");
            }
        }

        #[test]
        fn open_accepts_an_uppercase_scheme() {
            assert!(HttpsWriter::open("HTTP://example.com/audit", AuditLogFormat::Json).is_ok());
            assert!(HttpsWriter::open("HtTpS://example.com/audit", AuditLogFormat::Json).is_ok());
        }

        #[test]
        fn open_rejects_non_http_targets() {
            for target in [
                "/var/log/audit.log",
                "ftp://example.com/audit",
                "htps://example.com/audit",
                "//example.com/audit",
                "https://:8080/audit",
            ] {
                let error = HttpsWriter::open(target, AuditLogFormat::Json).err().unwrap();
                assert!(
                    error.starts_with(&format!("invalid HTTPS audit log target {target:?}:")),
                    "{error}"
                );
                assert!(
                    error.contains("expected an absolute http:// or https:// URL with a host"),
                    "{error}"
                );
            }
        }

        #[test]
        fn open_rejects_malformed_ports() {
            for target in [
                "http://collector.example:abc/audit",
                "https://collector.example:65536/audit",
                "http://collector.example:+80/audit",
                "http://[::1]:abc/audit",
                "http://user:pass@collector.example:abc/audit",
            ] {
                let error = HttpsWriter::open(target, AuditLogFormat::Json).err().unwrap();
                assert!(
                    error.starts_with(&format!("invalid HTTPS audit log target {target:?}:")),
                    "{error}"
                );
                assert!(
                    error.contains("expected an absolute http:// or https:// URL with a host and a valid port"),
                    "{error}"
                );
            }
        }

        #[test]
        fn open_rejects_an_invalid_target() {
            let error = HttpsWriter::open("http://exa mple.com/audit", AuditLogFormat::Json)
                .err()
                .unwrap();
            assert!(error.contains("invalid HTTPS audit log target"), "{error}");
        }
    }
}

/// Open `path` for append, creating it with `mode` when needed.
///
/// The error keeps its kind so a caller can tell a missing directory from a permission
/// failure; the message names the path.
fn open_append(path: &str, mode: u32) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
    #[cfg(not(unix))]
    let _ = mode;
    options
        .open(path)
        .map_err(|error| io::Error::new(error.kind(), format!("cannot open audit log {path}: {error}")))
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
    use super::{
        ACTIVATION_CONNECT_TIMEOUT, ACTIVATION_RETRY_BACKOFF, ACTIVATION_RETRY_BACKOFF_MAX, AuditLog, AuditLogger,
        AuditTransaction, Syslog, connect_deadline, connect_tcp, index_field, next_backoff, safe_file_component,
        write_new,
    };
    use crate::{
        actions::RuleMetadata,
        collection::MatchData,
        config::WafConfig,
        types::{AuditEngineStatus, AuditLogFormat, AuditLogType, RulePhase, parse_audit_log_parts},
    };

    #[test]
    fn default_internal_connect_timeout_is_finite() {
        assert_eq!(connect_deadline(None, true), Some(ACTIVATION_CONNECT_TIMEOUT));
        assert!(
            connect_deadline(None, true).is_some_and(|timeout| timeout <= std::time::Duration::from_secs(5)),
            "an internal dial must never be unbounded"
        );
        // The explicit activation path keeps Go's unbounded default, and a configured
        // deadline wins on both paths.
        assert_eq!(connect_deadline(None, false), None);
        assert_eq!(
            connect_deadline(Some(std::time::Duration::from_millis(7)), false),
            Some(std::time::Duration::from_millis(7))
        );
        assert_eq!(
            connect_deadline(Some(std::time::Duration::from_millis(7)), true),
            Some(std::time::Duration::from_millis(7))
        );
    }

    #[test]
    fn activation_backoff_grows_and_caps() {
        let mut backoff = ACTIVATION_RETRY_BACKOFF;
        let mut seen = Vec::new();
        for _ in 0..6 {
            seen.push(backoff);
            backoff = next_backoff(backoff);
        }
        assert_eq!(
            seen,
            [
                std::time::Duration::from_secs(30),
                std::time::Duration::from_secs(60),
                std::time::Duration::from_secs(120),
                std::time::Duration::from_secs(240),
                ACTIVATION_RETRY_BACKOFF_MAX,
                ACTIVATION_RETRY_BACKOFF_MAX,
            ]
        );
        assert_eq!(next_backoff(std::time::Duration::MAX), ACTIVATION_RETRY_BACKOFF_MAX);
    }

    #[test]
    fn a_failed_activation_schedules_an_exponentially_longer_window() {
        let config = WafConfig {
            audit_engine: AuditEngineStatus::On,
            audit_log_type: AuditLogType::Syslog,
            audit_log: "unix:///nonexistent/coraza-audit.sock".to_owned(),
            ..WafConfig::default()
        };
        let logger = AuditLogger::prepare(&config).unwrap();
        assert_eq!(
            logger.next_backoff_window(),
            ACTIVATION_RETRY_BACKOFF,
            "the first failure schedules the base window"
        );

        // Each internal failure doubles the window the next failure will schedule; an
        // explicit activation retries at once, so only the internal path waits.
        for expected in [
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(120),
            std::time::Duration::from_secs(240),
            ACTIVATION_RETRY_BACKOFF_MAX,
        ] {
            assert!(logger.ensure_activated().is_err());
            assert_eq!(logger.next_backoff_window(), expected);
            logger.expire_backoff();
        }
        assert_eq!(logger.attempts(), 4);
    }

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

    #[cfg(not(feature = "https-audit"))]
    #[test]
    fn https_audit_log_requires_the_https_audit_feature() {
        let config = WafConfig {
            audit_log_type: AuditLogType::Https,
            audit_log: "https://127.0.0.1:8080/audit".to_owned(),
            ..WafConfig::default()
        };
        let error = AuditLogger::open(&config).unwrap_err();
        assert!(error.contains("https-audit"), "{error}");
    }

    #[cfg(feature = "https-audit")]
    #[test]
    fn https_audit_log_opens_with_the_https_audit_feature() {
        let config = WafConfig {
            audit_log_type: AuditLogType::Https,
            audit_log: "http://127.0.0.1:8080/audit".to_owned(),
            ..WafConfig::default()
        };
        assert!(AuditLogger::open(&config).is_ok());
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

        // Go names the entry's directory and file after the local time of its instant.
        let at = crate::utils::time::LocalTime::from_unix(1_700_000_000);
        let day = format!("{:04}{:02}{:02}", at.year, at.month, at.day);
        let minute = format!("{day}-{:02}{:02}", at.hour, at.minute);
        let mut files = std::fs::read_dir(storage.join(day).join(&minute))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        files.sort();
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|name| name.contains("-transaction-")));
        assert!(files.iter().all(|name| name.starts_with(&minute)));
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

    #[cfg(unix)]
    #[test]
    fn syslog_reconnects_to_its_original_target_after_a_write_failure() {
        use std::{
            io::{self, Read as _},
            os::unix::net::UnixListener,
            sync::mpsc,
            thread,
            time::Duration,
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("syslog.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let target = format!("unix://{}", path.display());
        let (closed_tx, closed_rx) = mpsc::channel();
        let server = thread::spawn(move || -> io::Result<Vec<u8>> {
            let (connection, _) = listener.accept()?;
            drop(connection);
            closed_tx
                .send(())
                .map_err(|error| io::Error::other(error.to_string()))?;

            listener.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            let (mut retry, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock && std::time::Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(10));
                    },
                    Err(error) => return Err(error),
                }
            };
            let mut message = Vec::new();
            let mut byte = [0; 1];
            loop {
                if retry.read(&mut byte)? == 0 {
                    break;
                }
                let Some(value) = byte.first().copied() else {
                    break;
                };
                message.push(value);
                if value == b'\n' {
                    break;
                }
            }
            Ok(message)
        });

        let mut syslog = Syslog::connect(&target, None, None).unwrap();
        closed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        syslog.send("reconnected", false).unwrap();

        let message = server.join().unwrap().unwrap();
        assert!(message.ends_with(b"reconnected\n"));
    }

    #[test]
    fn tcp_connect_uses_the_configured_deadline() {
        use std::time::{Duration, Instant};

        // TEST-NET-1 is not routed, so the attempt has to wait for its whole budget. A host
        // without a default route rejects it at once instead; either way the attempt stays
        // bounded, so only the upper bound is asserted.
        let started = Instant::now();
        let result = connect_tcp("192.0.2.1:9", Some(Duration::from_millis(10)));
        let elapsed = started.elapsed();

        assert!(result.is_err(), "a non-routable target must not connect");
        assert!(
            elapsed < Duration::from_secs(2),
            "the deadline was not applied: {elapsed:?}"
        );
    }

    #[test]
    fn tcp_connect_rejects_a_deadline_that_overflows_the_clock() {
        let error = connect_tcp("127.0.0.1:1", Some(std::time::Duration::MAX)).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");
    }

    #[test]
    fn tcp_syslog_write_times_out_against_a_peer_that_does_not_read() {
        use std::{
            io,
            net::TcpListener,
            time::{Duration, Instant},
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = format!("tcp://{}", listener.local_addr().unwrap());
        let mut syslog = Syslog::connect(
            &target,
            Some(Duration::from_millis(200)),
            Some(Duration::from_millis(100)),
        )
        .unwrap();
        // Hold the accepted connection without reading it, and drop the listener so a
        // reconnect fails instead of draining a fresh socket buffer.
        let (_connection, _) = listener.accept().unwrap();
        drop(listener);

        let bound = Duration::from_secs(3);
        let started = Instant::now();
        let chunk = "x".repeat(64 * 1024);
        let mut result: io::Result<()> = Ok(());
        // Bounded chunks keep the test independent of the platform's socket buffers.
        while started.elapsed() < bound {
            result = syslog.send(&chunk, false);
            if result.is_err() {
                break;
            }
        }
        let elapsed = started.elapsed();

        assert!(result.is_err(), "a blocked write must fail instead of hanging");
        let error = result.unwrap_err();
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::WouldBlock
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionRefused
            ),
            "{error}"
        );
        assert!(elapsed < bound, "{elapsed:?}");
    }

    #[test]
    fn syslog_target_syntax_is_validated_without_dialing() {
        for target in [
            "tcp://",
            "udp://",
            "unix://",
            "unixgram://",
            "kafka://broker:9092",
            "http://collector:514",
        ] {
            let config = WafConfig {
                audit_log_type: AuditLogType::Syslog,
                audit_log: target.to_owned(),
                ..WafConfig::default()
            };
            let error = AuditLogger::prepare(&config).err().unwrap();
            assert!(error.contains("invalid syslog target"), "{target}: {error}");
        }
    }

    #[test]
    fn syslog_target_syntax_accepts_the_documented_forms() {
        for target in ["", "127.0.0.1:514", "tcp://127.0.0.1:514", "udp://127.0.0.1:514"] {
            let config = WafConfig {
                audit_log_type: AuditLogType::Syslog,
                audit_log: target.to_owned(),
                ..WafConfig::default()
            };
            assert!(AuditLogger::prepare(&config).is_ok(), "{target}");
        }
        #[cfg(unix)]
        for target in ["unix:///dev/log", "unixgram:///dev/log"] {
            let config = WafConfig {
                audit_log_type: AuditLogType::Syslog,
                audit_log: target.to_owned(),
                ..WafConfig::default()
            };
            assert!(AuditLogger::prepare(&config).is_ok(), "{target}");
        }
    }
}
