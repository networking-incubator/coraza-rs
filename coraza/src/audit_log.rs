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
    utils::{
        strings::{go_quote, push_go_quoted},
        time::LocalTime,
    },
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
    /// The configured parts, in the order built-in formatters write them.
    pub parts: AuditLogParts,
    /// The transaction fields captured for this entry; custom code can see fields beyond `parts`.
    pub transaction: AuditTransaction,
    /// What the rules with `auditlog` that matched have to say: one per value they
    /// matched with part `K`, or one per rule with only part `H`
    pub messages: Vec<AuditMessage>,
}

/// Formats an audit entry for an embedder-provided audit sink.
///
/// **Security:** `SecAuditLogParts` is not a confidentiality boundary for custom
/// formatters or writers. They receive the full [`AuditLog`] entry, including fields
/// such as `ARGS` even when those parts are not selected. The host is trusted code and
/// must redact sensitive data itself.
pub trait AuditLogFormatter: Send + Sync {
    /// Return the serialized entry.
    fn format(&self, entry: &AuditLog) -> Vec<u8>;

    /// MIME type associated with the serialized entry.
    ///
    /// This must remain stable for the formatter's lifetime: built-in sinks capture it
    /// at activation and pair it with later bytes. Varying it violates the contract.
    fn mime(&self) -> &'static str;
}

/// Writes an audit entry produced by [`AuditLogFormatter`].
///
/// The engine drops this writer when its audit logger is dropped; it does not call a
/// teardown method. A host that needs fallible teardown must own the sink outside this
/// trait.
pub trait AuditLogWriter: Send + Sync {
    /// Write `formatted`, while retaining access to the source entry's metadata.
    ///
    /// `mime` is the declared payload type returned by the formatter that produced
    /// `formatted`.
    ///
    /// # Errors
    ///
    /// Return the sink's I/O failure so `Transaction::finish` can report it.
    fn write(&self, entry: &AuditLog, formatted: &[u8], mime: &'static str) -> io::Result<()>;
}

/// Builds a custom writer when the WAF activates its audit sink.
///
/// The factory receives the resolved WAF configuration and must defer opening files or
/// sockets until it is called; it is called only by `Waf::activate` or the first audit
/// write.
pub type AuditLogWriterFactory = Arc<dyn Fn(&WafConfig) -> io::Result<Box<dyn AuditLogWriter>> + Send + Sync>;

/// Parser-scoped audit extensions; resolved selections are cloned into the WAF.
#[derive(Clone, Default)]
pub(crate) struct AuditLogRegistry {
    /// Writer factories keyed by lower-case SecLang name.
    writers: BTreeMap<String, AuditLogWriterFactory>,
    /// Formatters keyed by lower-case SecLang name.
    formatters: BTreeMap<String, Arc<dyn AuditLogFormatter>>,
}

impl AuditLogRegistry {
    /// Register a writer factory, replacing a case-insensitive duplicate.
    pub(crate) fn register_writer(&mut self, name: &str, factory: AuditLogWriterFactory) {
        self.writers.insert(name.to_ascii_lowercase(), factory);
    }

    /// Register a formatter, replacing a case-insensitive duplicate.
    pub(crate) fn register_formatter(&mut self, name: &str, formatter: Arc<dyn AuditLogFormatter>) {
        self.formatters.insert(name.to_ascii_lowercase(), formatter);
    }

    /// The writer factory registered under `name`.
    pub(crate) fn writer(&self, name: &str) -> Option<&AuditLogWriterFactory> {
        self.writers.get(&name.to_ascii_lowercase())
    }

    /// The formatter registered under `name`.
    pub(crate) fn formatter(&self, name: &str) -> Option<&Arc<dyn AuditLogFormatter>> {
        self.formatters.get(&name.to_ascii_lowercase())
    }
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
    /// The id of the rule whose disruptive action interrupted the transaction, if one did. Formatters that
    /// have to drop messages keep this rule's, since logging rules can match after it.
    pub interruption_rule_id: Option<i32>,
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
    /// `REQUEST_PROTOCOL`, e.g. `HTTP/1.1`.
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
    /// The id of the rule behind this message, which bounded formatting uses to keep the interrupting
    /// rule's message. It is never written out, and it is set even when `data` is not (part `H` without `K`).
    #[doc(hidden)]
    pub rule_id: i32,
    /// The rule's first expanded `msg`, kept only for a message with part `H` and without `K`, which has no
    /// `data`. A reduced bounded record writes it beside `rule_id`, as the error log text's own prefix may not
    /// fit. It is never written out in a record that fits.
    #[doc(hidden)]
    pub rule_message: String,
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

/// Maximum `msg_match_N` and `data_match_N` pairs the error log lists after the first match; the rest are counted.
///
/// Go lists every match. With audit parts `H` and `K` each of a rule's matches carries that line, so an unbounded
/// list made the entry quadratic in the matches of one rule.
const MAX_ERROR_LOG_EXTRA_MATCHES: usize = 8;

/// Maximum request URI bytes in a Coraza error log line; Go copies it whole. Every message of a rule carries the line,
/// so an attacker-sized URI made the entry its length times the rule's matches. Part `B` has the whole request line.
const MAX_LOG_URI: usize = 1024;

impl MatchedRule {
    /// The first expanded rule message, or an empty string when none was set.
    pub fn message(&self) -> &str {
        self.first_with_message().map_or("", |matched| &matched.message)
    }

    /// [`MatchedRule::message`] cut as the error log cuts it, for an audit message that has no rule data.
    pub(crate) fn short_message(&self) -> String {
        truncated(self.message(), MAX_LOG_MESSAGE).to_owned()
    }

    /// The expanded log data paired with [`MatchedRule::message`].
    pub fn data(&self) -> &str {
        self.first_with_message().map_or("", |matched| &matched.data)
    }

    /// The ID of the matched rule.
    pub fn rule_id(&self) -> i32 {
        self.rule.id
    }

    /// The severity configured on the matched rule, if any.
    pub fn severity(&self) -> Option<crate::types::RuleSeverity> {
        self.rule.severity
    }

    /// The rule's tags in source order.
    pub fn tags(&self) -> &[String] {
        &self.rule.tags
    }

    /// First match with an expanded message.
    fn first_with_message(&self) -> Option<&MatchData> {
        self.matches.iter().find(|matched| !matched.message.is_empty())
    }

    /// Format this match as a Coraza-compatible error log line.
    ///
    /// Beyond the first match, the line lists the first eight matches that have a message
    /// or data as `msg_match_N`/`data_match_N` pairs and ends with `[+N more matches]` for the others. Go lists
    /// them all. The `[uri]` is cut at 1024 bytes and followed by `[+N uri bytes]` when it was.
    pub fn error_log(&self) -> String {
        let first = self.matches.first();
        let mut log = format!("[client {}] {}", go_quote(&self.client_ip), self.outcome());
        log.push_str(&escape_log_message(truncated(self.message(), MAX_LOG_MESSAGE)));
        log.push(' ');
        let (message, data) = first.map_or(("", ""), |matched| (matched.message.as_str(), matched.data.as_str()));
        self.write_details(&mut log, message, data);
        let (mut listed, mut hidden) = (0_usize, 0_usize);
        for (number, extra) in self.matches.iter().enumerate().skip(1) {
            if extra.message.is_empty() && extra.data.is_empty() {
                continue;
            }
            if listed == MAX_ERROR_LOG_EXTRA_MATCHES {
                hidden += 1;
                continue;
            }
            listed += 1;
            write!(
                log,
                " [msg_match_{number} {}] [data_match_{number} {}]",
                go_quote(truncated(&extra.message, MAX_LOG_MESSAGE)),
                go_quote(truncated(&extra.data, MAX_LOG_MESSAGE)),
            )
            .unwrap_or(());
        }
        if hidden > 0 {
            write!(log, " [+{hidden} more matches]").unwrap_or(());
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
        let uri = truncated(&self.uri, MAX_LOG_URI);
        write!(log, " [hostname {}] [uri {}]", go_quote(&self.server_ip), go_quote(uri)).unwrap_or(());
        if uri.len() < self.uri.len() {
            write!(log, " [+{} uri bytes]", self.uri.len() - uri.len()).unwrap_or(());
        }
        write!(log, " [unique_id {}]", go_quote(&self.transaction_id)).unwrap_or(());
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

/// Callback used to emit selected audit entries through a connector-owned sink.
#[derive(Clone)]
pub(crate) struct AuditLogCallback(Arc<AuditLogCallbackFn>);

/// Thread-safe callback invoked for each selected audit entry.
type AuditLogCallbackFn = dyn Fn(&AuditLog) + Send + Sync;

impl AuditLogCallback {
    /// Wrap a callback for sharing across transactions.
    pub(crate) fn new(log: impl Fn(&AuditLog) + Send + Sync + 'static) -> Self {
        Self(Arc::new(log))
    }

    /// Invoke the callback for one selected entry.
    pub(crate) fn write(&self, entry: &AuditLog) {
        (self.0)(entry);
    }
}

impl fmt::Debug for AuditLogCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuditLogCallback")
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

    /// Formats an audit entry for a bounded sink, returning whether source data was cut.
    ///
    /// This hidden connector seam leaves [`AuditLog::format`] unchanged. Native output copies a temporary
    /// view of at most `max_bytes` of text and `ceil(max_bytes / 64)` collection entries before formatting,
    /// and is cut at `max_bytes`.
    ///
    /// The JSON formats are never cut mid-token: the output is always one valid JSON document of at most
    /// `max_bytes` bytes, carrying the same data as [`AuditLog::format`] when that fits (the bytes can differ:
    /// DEL and the C1 controls, which `format` leaves raw, are escaped here, and OCSF's `logged_time` is read
    /// again at each call), and otherwise reduced and marked
    /// with `"truncated": true` (`JSON` and `JSONLegacy`) or `"unmapped": {"truncated": true}` (OCSF). Their
    /// copy is bounded by `max_bytes` too, whatever the entry holds: text, and entries at most half as many as
    /// bytes, since an entry takes at least three bytes of output. Reduction keeps what an investigation needs
    /// first: the matched rules, with their ids and messages, outlast the request's headers, URI and bodies,
    /// and the rule that interrupted the transaction outlasts the other rules. A document too small for even
    /// the marker (31 bytes for OCSF, 18 for the others) is empty. Control characters are escaped, so the
    /// output is one line.
    #[doc(hidden)]
    pub fn format_bounded(&self, format: AuditLogFormat, max_bytes: usize) -> (String, bool) {
        if format != AuditLogFormat::Native {
            return self.format_json_bounded(format, max_bytes);
        }
        let mut budget = AuditCopyBudget::new(max_bytes);
        let view = self.bounded_copy(format, &mut budget);
        let mut output = view.native();
        let truncated = output.len() > max_bytes;
        if truncated {
            output.truncate(utf8_boundary(&output, max_bytes));
        }
        (output, budget.truncated || truncated)
    }

    /// Formats one of the JSON formats as a valid document within `max_bytes`.
    ///
    /// The first attempt keeps everything, within allowances that any record that fits `max_bytes` stays inside
    /// of: the request's text has a pool of its own, apart from the messages' pool, which is shared by all of
    /// them, so a short message leaves its unused bytes to the others and request padding takes none of them.
    /// Only a real overflow shrinks the next attempt, in this order: the request's text (URI, headers, bodies,
    /// arguments), then the text each message may keep, then the number of messages. Dropped messages are the
    /// later ones, except the one whose rule interrupted the transaction, which is always kept. A record that
    /// still does not fit is reduced to its transaction id and pinned message, and one that cannot fit even
    /// then becomes a bare marker. The result is reported cut only when content was reduced.
    fn format_json_bounded(&self, format: AuditLogFormat, max_bytes: usize) -> (String, bool) {
        /// The smallest text each message keeps before messages themselves are dropped.
        const MIN_MESSAGE_BYTES: usize = 32;

        let total = self.messages.len();
        let mut plan = AuditShrinkPlan {
            request_bytes: max_bytes,
            message_bytes: max_bytes,
            message_each: None,
            // Every message is at least three bytes of output, so a record that fits holds fewer than this.
            message_count: total.min(AuditCopyBudget::generous(max_bytes).items_left),
            reduced: false,
        };
        let mut shrunk = false;
        loop {
            let mut budget = AuditCopyBudget::generous(max_bytes);
            let view = self.bounded_copy_planned(format, &mut budget, Some(plan));
            let truncated = shrunk || budget.truncated;
            let mut document = match format {
                AuditLogFormat::JsonLegacy => view.json_legacy(),
                AuditLogFormat::Ocsf => view.ocsf(),
                _ => view.json(),
            };
            if truncated {
                mark_truncated(&mut document, format);
            }
            let text = escape_json_controls(&document.to_string());
            if text.len() <= max_bytes {
                return (text, truncated);
            }
            shrunk = true;
            plan.reduced = true;
            if plan.request_bytes > 0 {
                // Halve what the request really took, not its allowance, so a request with little text does
                // not cost an attempt per halving of an allowance it never used.
                plan.request_bytes = if budget.request_bytes_used < 64 {
                    0
                } else {
                    budget.request_bytes_used / 2
                };
            } else if plan.message_each.is_none_or(|each| each > MIN_MESSAGE_BYTES) {
                let each = plan
                    .message_each
                    .unwrap_or_else(|| max_bytes / plan.message_count.max(1));
                plan.message_each = Some((each / 2).max(MIN_MESSAGE_BYTES));
            } else if plan.message_count > 1 {
                // Keep the share of the messages that the record is over its limit by, so a record a little
                // over loses a little and one far over takes few attempts to get under.
                let share = u128::try_from(plan.message_count)
                    .unwrap_or(u128::MAX)
                    .saturating_mul(u128::try_from(max_bytes).unwrap_or(u128::MAX))
                    / u128::try_from(text.len()).unwrap_or(1).max(1);
                plan.message_count = usize::try_from(share)
                    .unwrap_or(usize::MAX)
                    .clamp(1, plan.message_count - 1);
            } else {
                // Even one message does not fit beside the record's own metadata, which a huge producer entry
                // can fill. Keep what identifies the record and the rule that mattered, and drop the rest.
                let mut budget = AuditCopyBudget::generous(max_bytes);
                let mut view = self.bounded_copy_planned(format, &mut budget, Some(plan));
                view.compact();
                let mut document = match format {
                    AuditLogFormat::JsonLegacy => view.json_legacy(),
                    AuditLogFormat::Ocsf => view.ocsf(),
                    _ => view.json(),
                };
                mark_truncated(&mut document, format);
                let compact = escape_json_controls(&document.to_string());
                if compact.len() <= max_bytes {
                    return (compact, true);
                }
                let minimal = bare_truncation_marker(format);
                let fits = minimal.len() <= max_bytes;
                return (if fits { minimal.to_owned() } else { String::new() }, true);
            }
        }
    }

    /// Drops what is not needed to identify the record and its pinned rule: the producer, the request, the
    /// response and the connection's text, and the rules' tags. The transaction id, the interruption and the
    /// messages stay.
    fn compact(&mut self) {
        let transaction = &mut self.transaction;
        transaction.producer = None;
        transaction.response = None;
        transaction.request = AuditRequest::default();
        transaction.timestamp.clear();
        transaction.client_ip.clear();
        transaction.host_ip.clear();
        transaction.server_id.clear();
        transaction.highest_severity.clear();
        // The rules' tags are optional too: one-byte tags still cost an array entry each, which OCSF escapes a
        // second time inside the enrichment's `data` string, so thousands of them can outweigh the whole budget.
        for message in &mut self.messages {
            message.data.tags.clear();
        }
    }

    /// Copies only the fields used by `format`, within `budget`.
    fn bounded_copy(&self, format: AuditLogFormat, budget: &mut AuditCopyBudget) -> Self {
        self.bounded_copy_planned(format, budget, None)
    }

    /// Copies only the fields used by `format`, within `budget`, or within `plan` when there is one.
    ///
    /// A plan gives the request's text a pool of its own, apart from `budget`, which then holds the
    /// identifying fields; the messages share a pool of their own too, and only some of them are kept when the
    /// plan says so. Shrinking the request's pool therefore never costs a message any of its text.
    #[expect(
        clippy::too_many_lines,
        reason = "each audit format uses a distinct bounded field view"
    )]
    fn bounded_copy_planned(
        &self,
        format: AuditLogFormat,
        budget: &mut AuditCopyBudget,
        plan: Option<AuditShrinkPlan>,
    ) -> Self {
        let mut request_pool = plan.map(|plan| AuditCopyBudget::generous(plan.request_bytes));
        let native = format == AuditLogFormat::Native;
        let native_headers = native && self.parts.contains(&AuditLogPart::RequestHeaders);
        let native_request_body = native && self.parts.contains(&AuditLogPart::RequestBody);
        let native_response_headers = native && self.parts.contains(&AuditLogPart::ResponseHeaders);
        let native_response_body = native && self.parts.contains(&AuditLogPart::IntermediaryResponseBody);
        let native_files = native && self.parts.contains(&AuditLogPart::UploadedFiles);
        let native_trailer = native && self.parts.contains(&AuditLogPart::Trailer);
        let native_rules = native && self.parts.contains(&AuditLogPart::RulesMatched);
        let native_header = native && self.parts.contains(&AuditLogPart::Header);
        let parts = if native {
            budget.sequence(&self.parts, |_, part| *part)
        } else {
            Vec::new()
        };

        let json = format == AuditLogFormat::Json;
        let legacy = format == AuditLogFormat::JsonLegacy;
        let ocsf = format == AuditLogFormat::Ocsf;
        let transaction = &self.transaction;
        let timestamp = if json || legacy || native_header {
            budget.string(&transaction.timestamp)
        } else {
            String::new()
        };
        let unix_timestamp = if json || ocsf { transaction.unix_timestamp } else { 0 };
        let id = if json || legacy || ocsf || native_header {
            budget.string(&transaction.id)
        } else {
            String::new()
        };
        let client_ip = if json || legacy || ocsf || native_header {
            budget.string(&transaction.client_ip)
        } else {
            String::new()
        };
        let client_port = transaction.client_port;
        let host_ip = if json || legacy || ocsf || native_header {
            budget.string(&transaction.host_ip)
        } else {
            String::new()
        };
        let host_port = transaction.host_port;
        let server_id = if json || ocsf {
            budget.string(&transaction.server_id)
        } else {
            String::new()
        };
        let highest_severity = if json || ocsf {
            budget.string(&transaction.highest_severity)
        } else {
            String::new()
        };
        let is_interrupted = if json || ocsf {
            transaction.is_interrupted
        } else {
            false
        };
        let interruption_rule_id = transaction.interruption_rule_id;
        let request_budget: &mut AuditCopyBudget = match request_pool.as_mut() {
            Some(pool) => pool,
            None => &mut *budget,
        };
        let request = &transaction.request;
        let bounded_request = AuditRequest {
            method: if !native || native_headers {
                request_budget.string(&request.method)
            } else {
                String::new()
            },
            protocol: if json || ocsf || native_headers {
                request_budget.string(&request.protocol)
            } else {
                String::new()
            },
            uri: if !native || native_headers {
                request_budget.string(&request.uri)
            } else {
                String::new()
            },
            http_version: if json || legacy {
                request_budget.string(&request.http_version)
            } else {
                String::new()
            },
            headers: if json || legacy || ocsf || native_headers {
                request_budget.headers(&request.headers)
            } else {
                None
            },
            body: if json || native_request_body {
                request_budget.string(&request.body)
            } else {
                String::new()
            },
            files: if json || ocsf || native_files {
                request_budget.files(&request.files)
            } else {
                None
            },
            length: if json || ocsf { request.length } else { 0 },
            args: if ocsf {
                request_budget.args(&request.args)
            } else {
                Vec::new()
            },
        };

        let response = transaction.response.as_ref().map(|response| AuditResponse {
            protocol: if json || legacy || native_response_headers {
                request_budget.string(&response.protocol)
            } else {
                String::new()
            },
            status: if json || legacy || ocsf || native_response_headers {
                response.status
            } else {
                0
            },
            headers: if json || legacy || ocsf || native_response_headers {
                request_budget.headers(&response.headers)
            } else {
                None
            },
            body: if json || native_response_body {
                request_budget.string(&response.body)
            } else {
                String::new()
            },
        });

        let producer = if json || legacy || ocsf {
            transaction
                .producer
                .as_ref()
                .map(|producer| budget.producer(producer, format))
        } else {
            None
        };

        let message_mode = if json {
            AuditMessageCopy::Json
        } else if legacy {
            AuditMessageCopy::Legacy
        } else if ocsf {
            AuditMessageCopy::Ocsf
        } else if native_trailer || native_rules {
            AuditMessageCopy::Native {
                error: native_trailer,
                raw: native_rules,
            }
        } else {
            AuditMessageCopy::None
        };
        if let Some(pool) = &request_pool {
            budget.request_bytes_used = pool.bytes_used;
            budget.truncated |= pool.truncated;
            budget.bytes_used += pool.bytes_used;
            budget.items_used += pool.items_used;
        }
        let messages = if message_mode == AuditMessageCopy::None {
            Vec::new()
        } else if let Some(plan) = plan {
            budget.planned_messages(&self.messages, message_mode, plan, transaction.interruption_rule_id)
        } else {
            let mut mode = message_mode;
            budget.sequence(&self.messages, |budget, message| {
                let copied = budget.message(message, mode);
                mode = mode.after_first();
                copied
            })
        };

        Self {
            parts,
            transaction: AuditTransaction {
                timestamp,
                unix_timestamp,
                id,
                client_ip,
                client_port,
                host_ip,
                host_port,
                server_id,
                request: bounded_request,
                response,
                producer,
                highest_severity,
                is_interrupted,
                interruption_rule_id,
            },
            messages,
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
                AuditLogPart::IntermediaryResponseBody => {
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
    /// Its severity is the highest explicit rule severity, omitted when none is set.
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
        // As Go's ParseRuleSeverity reads it; an unset value is omitted.
        let severity = tx
            .highest_severity
            .parse::<crate::types::RuleSeverity>()
            .map_or("", |severity| severity.as_str());
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

#[derive(Clone, Copy, PartialEq, Eq)]
/// Selects the fields to retain for each audit format.
enum AuditMessageCopy {
    /// The native format has no message section in this entry.
    None,
    /// Copy every message field used by JSON.
    Json,
    /// Copy only the expanded text used by `JSONLegacy`.
    Legacy,
    /// Copy the OCSF message and nested rule data: the first message, whose text OCSF writes.
    Ocsf,
    /// Copy the nested rule data only, for the messages after the first, whose text OCSF never writes.
    OcsfEnrichment,
    /// Copy the native trailer and/or rules section.
    Native {
        /// Copy the message's error log text for part H.
        error: bool,
        /// Copy the matched rule text for part K.
        raw: bool,
    },
}

#[cfg(test)]
thread_local! {
    /// Messages copied by the formatter on this thread, which tests read to bound its work.
    static MESSAGES_COPIED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl AuditMessageCopy {
    /// The mode for the messages after the first: OCSF writes only the first message's text.
    fn after_first(self) -> Self {
        if self == Self::Ocsf { Self::OcsfEnrichment } else { self }
    }
}

/// How much of an entry a bounded JSON attempt keeps, see [`AuditLog::format_json_bounded`].
#[derive(Clone, Copy)]
struct AuditShrinkPlan {
    /// Text bytes for the request and response: URI, headers, bodies, arguments and files.
    request_bytes: usize,
    /// Text bytes all the messages share.
    message_bytes: usize,
    /// Text bytes one message may take from the shared ones; unlimited until the record has overflowed.
    message_each: Option<usize>,
    /// Messages kept: the interrupting one (or the last) and the first others.
    message_count: usize,
    /// Whether an earlier attempt overflowed, so this one is reduced in some way: a record that fits whole is
    /// left as it is, and only a reduced one gets its interrupting rule's identity written compactly.
    reduced: bool,
}

/// Limits owned strings and collection entries while preparing an audit formatter view.
struct AuditCopyBudget {
    /// Remaining bytes available for copied string contents.
    bytes_left: usize,
    /// Remaining list and map entries.
    items_left: usize,
    /// Bytes copied so far, used by regression tests.
    bytes_used: usize,
    /// Entries copied so far, used by regression tests.
    items_used: usize,
    /// Whether any source content exceeded the copy budget.
    truncated: bool,
    /// Bytes of the request's and response's text the plan's request pool copied.
    request_bytes_used: usize,
}

impl AuditCopyBudget {
    /// Sets text and collection budgets derived from the output limit.
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes_left: max_bytes,
            items_left: max_bytes.saturating_add(63) / 64,
            bytes_used: 0,
            items_used: 0,
            truncated: false,
            request_bytes_used: 0,
        }
    }

    /// A pool for a record bound to `max_bytes` of output, which cannot be reduced by its entry count.
    ///
    /// Every entry takes at least three bytes of JSON, so a record that fits holds fewer than half as many
    /// entries as bytes, and nothing that fits is refused for having too many. The copy stays linear in
    /// `max_bytes`, as the text is.
    fn generous(max_bytes: usize) -> Self {
        Self {
            items_left: max_bytes / 2 + 1,
            ..Self::new(max_bytes)
        }
    }

    /// Copies the longest UTF-8 prefix that fits the remaining text budget.
    fn string(&mut self, value: &str) -> String {
        let mut end = value.len().min(self.bytes_left);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        if end < value.len() {
            self.truncated = true;
        }
        self.bytes_left -= end;
        self.bytes_used += end;
        value.get(..end).unwrap_or_default().to_owned()
    }

    /// Reserves up to the remaining number of collection entries.
    fn item_count(&mut self, len: usize) -> usize {
        let count = len.min(self.items_left);
        if count < len {
            self.truncated = true;
        }
        self.items_left -= count;
        self.items_used += count;
        count
    }

    /// Copies a sequence while charging each retained element against the item budget.
    fn sequence<T, U>(&mut self, values: &[T], mut copy: impl FnMut(&mut Self, &T) -> U) -> Vec<U> {
        let count = self.item_count(values.len());
        values.iter().take(count).map(|value| copy(self, value)).collect()
    }

    /// Copies the messages `plan` keeps out of one shared pool.
    ///
    /// Only the kept messages are visited and copied. They are the one whose rule interrupted the
    /// transaction (the last message when none did), found without copying, and the first of the others: the
    /// first matches say how the request started to go wrong, and a logging rule that runs after the
    /// interruption must not displace it. The pinned message is copied first, so it has its text however the
    /// pool is used.
    fn planned_messages(
        &mut self,
        messages: &[AuditMessage],
        mode: AuditMessageCopy,
        plan: AuditShrinkPlan,
        interrupting: Option<i32>,
    ) -> Vec<AuditMessage> {
        let kept = plan.message_count.min(messages.len());
        if kept < messages.len() {
            self.truncated = true;
        }
        let pinned = interrupting
            .and_then(|id| {
                messages
                    .iter()
                    .rposition(|message| message.rule_id == id || message.data.id == id)
            })
            // Without an interruption the last message is the one kept, as the one most likely to be the blocking
            // rule's.
            .or_else(|| messages.len().checked_sub(1))
            .filter(|_| kept > 0);
        let mut pool = Self::generous(plan.message_bytes);
        // The message written first is the first one kept: the first of them, unless only the pinned one is.
        let head_count = kept - usize::from(pinned.is_some());
        let first = if head_count == 0 { pinned } else { Some(0) };
        let reduced = plan.reduced;
        let mut copy_one = |index: usize| {
            let before = pool.bytes_left;
            pool.bytes_left = before.min(plan.message_each.unwrap_or(usize::MAX));
            let allowed = pool.bytes_left;
            let mode = if Some(index) == first { mode } else { mode.after_first() };
            let copy = messages.get(index).map(|message| {
                if reduced && Some(index) == pinned {
                    pool.pinned_message(message, mode)
                } else {
                    pool.message(message, mode)
                }
            });
            pool.bytes_left = before - (allowed - pool.bytes_left);
            copy
        };
        let pinned_copy = pinned.and_then(&mut copy_one);
        let mut out: Vec<AuditMessage> = (0..messages.len())
            .filter(|index| Some(*index) != pinned)
            .take(head_count)
            .filter_map(&mut copy_one)
            .collect();
        if let (Some(index), Some(copy)) = (pinned, pinned_copy) {
            // Back in its place among the others, which are the first ones.
            let position = index.min(out.len());
            out.insert(position, copy);
        }
        self.truncated |= pool.truncated;
        self.bytes_used += pool.bytes_used;
        self.items_used += pool.items_used;
        out
    }

    /// Copies the interrupting message of a reduced record, so that it still names its rule.
    ///
    /// A message with part `H` and without `K` carries its rule only inside the error log text, behind a
    /// prefix (the client address and the outcome) that a tight allowance is spent on before the rule's `id`
    /// and `msg` are reached, and the legacy and OCSF documents do not write that text at all. So when the
    /// allowance cannot hold the text, the rule's `id` and `msg` are written in a compact form instead, from
    /// `rule_id`, which is set whether or not the message has `data`. Any other message is copied as usual.
    fn pinned_message(&mut self, message: &AuditMessage, mode: AuditMessageCopy) -> AuditMessage {
        let identity_missing = message.rule_id != 0
            && message.data.id == 0
            && message.data.msg.is_empty()
            && message.message.is_empty()
            && message.data.data.is_empty();
        let limit = self.bytes_left;
        let needs_identity = match mode {
            AuditMessageCopy::Json => message.error_message.len() > limit,
            AuditMessageCopy::Legacy | AuditMessageCopy::Ocsf | AuditMessageCopy::OcsfEnrichment => true,
            AuditMessageCopy::None | AuditMessageCopy::Native { .. } => false,
        };
        if !identity_missing || !needs_identity {
            return self.message(message, mode);
        }
        #[cfg(test)]
        MESSAGES_COPIED.with(|copied| copied.set(copied.get() + 1));
        let mut copy = AuditMessage {
            rule_id: message.rule_id,
            ..AuditMessage::default()
        };
        match mode {
            AuditMessageCopy::Json => {
                copy.data.id = message.rule_id;
                copy.error_message = self.string(&reduced_identity(message.rule_id, &message.rule_message, limit));
            },
            AuditMessageCopy::Legacy => {
                copy.message = self.string(&reduced_identity(message.rule_id, &message.rule_message, limit));
            },
            _ => {
                // OCSF names a rule by its enrichment (`id` in the data, `msg` as the name); the first message's
                // text is written beside, and takes what the name leaves.
                copy.data.id = message.rule_id;
                copy.data.msg = self.string(truncated(&message.rule_message, limit / 2));
                if mode == AuditMessageCopy::Ocsf {
                    copy.message = self.string(&reduced_identity(
                        message.rule_id,
                        &message.rule_message,
                        self.bytes_left,
                    ));
                }
            },
        }
        copy
    }

    /// Copies string entries in a list.
    fn strings(&mut self, values: &[String]) -> Vec<String> {
        self.sequence(values, |budget, value| budget.string(value))
    }

    /// Copies header names and values without retaining unbounded maps or strings.
    fn headers(&mut self, headers: &Option<BTreeMap<String, Vec<String>>>) -> Option<BTreeMap<String, Vec<String>>> {
        headers.as_ref().map(|headers| {
            let count = self.item_count(headers.len());
            headers
                .iter()
                .take(count)
                .map(|(name, values)| (self.string(name), self.strings(values)))
                .collect()
        })
    }

    /// Copies uploaded-file metadata within both budgets.
    fn files(&mut self, files: &Option<Vec<AuditFile>>) -> Option<Vec<AuditFile>> {
        files.as_ref().map(|files| {
            self.sequence(files, |budget, file| AuditFile {
                name: budget.string(&file.name),
                size: file.size,
                mime: budget.string(&file.mime),
            })
        })
    }

    /// Copies OCSF request arguments within both budgets.
    fn args(&mut self, args: &[(String, String)]) -> Vec<(String, String)> {
        self.sequence(args, |budget, (key, value)| (budget.string(key), budget.string(value)))
    }

    /// Copies only producer fields used by the selected JSON format.
    fn producer(&mut self, producer: &AuditProducer, format: AuditLogFormat) -> AuditProducer {
        let json = format == AuditLogFormat::Json;
        let legacy = format == AuditLogFormat::JsonLegacy;
        let ocsf = format == AuditLogFormat::Ocsf;
        AuditProducer {
            connector: self.string(&producer.connector),
            version: if json || ocsf {
                self.string(&producer.version)
            } else {
                String::new()
            },
            server: if json {
                self.string(&producer.server)
            } else {
                String::new()
            },
            rule_engine: if json || legacy {
                self.string(&producer.rule_engine)
            } else {
                String::new()
            },
            stopwatch: if json {
                self.string(&producer.stopwatch)
            } else {
                String::new()
            },
            rulesets: if json || legacy {
                self.strings(&producer.rulesets)
            } else {
                Vec::new()
            },
        }
    }

    /// Copies only message fields used by the selected audit format.
    fn message(&mut self, message: &AuditMessage, mode: AuditMessageCopy) -> AuditMessage {
        #[cfg(test)]
        MESSAGES_COPIED.with(|copied| copied.set(copied.get() + 1));
        let json = mode == AuditMessageCopy::Json;
        let legacy = mode == AuditMessageCopy::Legacy;
        let ocsf = matches!(mode, AuditMessageCopy::Ocsf | AuditMessageCopy::OcsfEnrichment);
        let (native_error, native_raw) = match mode {
            AuditMessageCopy::Native { error, raw } => (error, raw),
            _ => (false, false),
        };
        let all_data = json || ocsf;
        let data = &message.data;
        // A tight allowance, which a message's text shares with its siblings, must cut the long and the
        // duplicated fields (the rule's `raw` text, its file, `message` repeating `data.msg`) before the
        // text that says what matched, so that is copied first.
        let msg = if all_data {
            self.string(&data.msg)
        } else {
            String::new()
        };
        let matched_data = if all_data {
            self.string(&data.data)
        } else {
            String::new()
        };
        // OCSF writes the text of its first message only; `OcsfEnrichment` copies the data of the others.
        let text = if json || legacy || mode == AuditMessageCopy::Ocsf {
            self.string(&message.message)
        } else {
            String::new()
        };
        let file = if all_data {
            self.string(&data.file)
        } else {
            String::new()
        };
        let rev = if all_data {
            self.string(&data.rev)
        } else {
            String::new()
        };
        let ver = if all_data {
            self.string(&data.ver)
        } else {
            String::new()
        };
        let tags = if all_data { self.strings(&data.tags) } else { Vec::new() };
        let actionset = if json {
            self.string(&message.actionset)
        } else {
            String::new()
        };
        let error_message = if json || native_error {
            self.string(&message.error_message)
        } else {
            String::new()
        };
        let raw = if all_data || native_raw {
            self.string(&data.raw)
        } else {
            String::new()
        };
        AuditMessage {
            actionset,
            message: text,
            error_message,
            rule_id: message.rule_id,
            rule_message: String::new(),
            data: AuditMessageData {
                file,
                line: if all_data { data.line } else { 0 },
                id: if all_data { data.id } else { 0 },
                rev,
                msg,
                data: matched_data,
                severity: if all_data { data.severity } else { 0 },
                ver,
                maturity: if all_data { data.maturity } else { 0 },
                accuracy: if all_data { data.accuracy } else { 0 },
                tags,
                raw,
            },
        }
    }
}

/// A rule's identity in the compact form of the error log, `[id "N"] [msg "…"]`, within `limit` bytes.
///
/// The `msg` keeps the longest prefix whose quoted form fits, so quoting never cuts the closing `"]` off: the
/// prefix is chosen by its quoted length, character by character, and an escape sequence is never split. A
/// message of which no character fits leaves the `msg` out.
fn reduced_identity(id: i32, msg: &str, limit: usize) -> String {
    let mut identity = format!("[id \"{id}\"]");
    // ` [msg ""]` around the quoted text.
    let room = limit.saturating_sub(identity.len() + 9);
    let mut quoted = String::new();
    for character in msg.chars() {
        let before = quoted.len();
        push_go_quoted(&mut quoted, character);
        if quoted.len() > room {
            quoted.truncate(before);
            break;
        }
    }
    if !quoted.is_empty() {
        identity.push_str(" [msg \"");
        identity.push_str(&quoted);
        identity.push_str("\"]");
    }
    identity
}

/// Returns the longest UTF-8 boundary no later than `max_bytes`.
fn utf8_boundary(value: &str, max_bytes: usize) -> usize {
    (0..=max_bytes.min(value.len()))
        .rev()
        .find(|index| value.is_char_boundary(*index))
        .unwrap_or(0)
}

/// The smallest valid document for `format` that says its record was reduced: the member goes where
/// [`mark_truncated`] puts it. OCSF has no root-level members of its own to spare, so its marker is longer.
fn bare_truncation_marker(format: AuditLogFormat) -> &'static str {
    if format == AuditLogFormat::Ocsf {
        r#"{"unmapped":{"truncated":true}}"#
    } else {
        r#"{"truncated":true}"#
    }
}

/// Records on `document` that it was reduced: a top-level `truncated` member, or `unmapped.truncated` for OCSF,
/// whose schema keeps members it does not define under `unmapped`.
fn mark_truncated(document: &mut Value, format: AuditLogFormat) {
    let Some(object) = document.as_object_mut() else {
        return;
    };
    if format == AuditLogFormat::Ocsf {
        object.insert("unmapped".to_owned(), json!({"truncated": true}));
    } else {
        object.insert("truncated".to_owned(), Value::Bool(true));
    }
}

/// Escapes what JSON leaves raw but a log line should not carry: DEL and the C1 controls.
///
/// `serde_json` already writes every control below U+0020 as an escape. These can only occur inside strings,
/// where `\u00XX` is a valid escape.
fn escape_json_controls(json: &str) -> String {
    use std::fmt::Write as _;

    if !json.chars().any(|character| ('\u{7f}'..='\u{9f}').contains(&character)) {
        return json.to_owned();
    }
    let mut escaped = String::with_capacity(json.len());
    for character in json.chars() {
        if ('\u{7f}'..='\u{9f}').contains(&character) {
            write!(escaped, "\\u{:04x}", u32::from(character)).unwrap_or(());
        } else {
            escaped.push(character);
        }
    }
    escaped
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

/// The MIME type returned by each built-in audit formatter.
const fn audit_log_mime(format: AuditLogFormat) -> &'static str {
    match format {
        AuditLogFormat::Native => "application/x-coraza-auditlog-native",
        AuditLogFormat::Json | AuditLogFormat::JsonLegacy => "application/json; charset=utf-8",
        AuditLogFormat::Ocsf => "application/json",
    }
}

/// One formatted audit entry, retaining whether built-in output is already UTF-8.
enum FormattedAudit {
    /// Built-in formatters produce a `String`.
    Text(String),
    /// Custom formatters may produce arbitrary bytes.
    Bytes(Vec<u8>),
}

impl FormattedAudit {
    /// The serialized bytes shared with every writer.
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Text(text) => text.as_bytes(),
            Self::Bytes(bytes) => bytes,
        }
    }
}

/// The selected formatter; built-ins retain their allocation-compatible path.
#[derive(Clone)]
enum SelectedFormatter {
    /// The built-in formatter retains its existing path.
    Builtin(AuditLogFormat),
    /// The formatter selected from the parser registry.
    Custom(Arc<dyn AuditLogFormatter>),
}

impl fmt::Debug for SelectedFormatter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Builtin(format) => f.debug_tuple("Builtin").field(format).finish(),
            Self::Custom(_) => f.write_str("Custom"),
        }
    }
}

impl SelectedFormatter {
    /// Format one entry, reusing the built-in String allocation as its byte buffer.
    fn format(&self, entry: &AuditLog) -> FormattedAudit {
        match self {
            Self::Builtin(format) => FormattedAudit::Text(entry.format(*format)),
            Self::Custom(formatter) => FormattedAudit::Bytes(formatter.format(entry)),
        }
    }

    /// The MIME type of this formatter.
    fn mime(&self) -> &'static str {
        match self {
            Self::Builtin(format) => audit_log_mime(*format),
            Self::Custom(formatter) => formatter.mime(),
        }
    }
}

/// Writes audit log entries in `SecAuditLogFormat` where `SecAuditLogType` says, and
/// knows which transactions `SecAuditEngine RelevantOnly` keeps.
#[derive(Debug)]
pub(crate) struct AuditLogger {
    /// Format used for each audit entry.
    formatter: SelectedFormatter,
    /// `SecAuditLogRelevantStatus`, if set
    relevant_status: Option<Regex>,
    /// Custom writer factory selected from the parser registry, if any.
    custom_writer: Option<CustomWriterPlan>,
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

impl fmt::Debug for WriterPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discard => f.write_str("Discard"),
            Self::Serial { .. } => f.write_str("Serial"),
            Self::Concurrent { .. } => f.write_str("Concurrent"),
            Self::Syslog { .. } => f.write_str("Syslog"),
            #[cfg(feature = "https-audit")]
            Self::Https { .. } => f.write_str("Https"),
        }
    }
}

/// A custom writer factory and its configuration, kept separate from built-in plans so
/// the source-derived audit-writer manifest remains limited to built-ins.
struct CustomWriterPlan {
    /// Factory selected while the parser's registry was frozen into the WAF.
    factory: AuditLogWriterFactory,
    /// Configuration passed to the factory when the sink is activated.
    config: Box<WafConfig>,
}

impl fmt::Debug for CustomWriterPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Custom")
    }
}

impl CustomWriterPlan {
    /// Construct the custom sink only when the audit logger activates it.
    fn open(&self, activation_mime: &'static str) -> io::Result<Writer> {
        (self.factory)(self.config.as_ref()).map(|writer| Writer::Custom {
            writer,
            activation_mime,
        })
    }
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
    fn open(&self, mime: &'static str, internal: bool) -> io::Result<Writer> {
        #[cfg(not(feature = "https-audit"))]
        let _ = mime;
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
            Self::Https { target } => Writer::Https(https::HttpsWriter::open(target, mime).map_err(io::Error::other)?),
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
    /// An embedder-provided sink and the MIME captured when it was activated.
    Custom {
        /// The embedder's writer.
        writer: Box<dyn AuditLogWriter>,
        /// Formatter MIME declared when activation opened the writer.
        activation_mime: &'static str,
    },
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
            Self::Custom { .. } => f.write_str("Custom"),
        }
    }
}

impl Writer {
    /// Write one formatted entry to this writer.
    fn write(&self, formatted: &FormattedAudit, entry: &AuditLog, mime: &'static str) -> io::Result<()> {
        let bytes = formatted.as_bytes();
        match self {
            Self::Discard => Ok(()),
            #[cfg(feature = "https-audit")]
            Self::Https(https) => https.write(bytes),
            Self::Syslog(syslog) => {
                let mut syslog = syslog.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                syslog.send(bytes, entry.transaction.is_interrupted)
            },
            Self::Serial(output) => {
                let mut output = output.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                output.write_all(bytes)?;
                output.write_all(b"\n")?;
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
                write_new(&path, bytes, *file_mode)?;

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
            Self::Custom {
                writer,
                activation_mime,
            } => {
                debug_assert_eq!(
                    mime, *activation_mime,
                    "AuditLogFormatter::mime() must remain stable for its lifetime"
                );
                writer.write(entry, bytes, mime)
            },
        }
    }
}

/// Resolve the custom or built-in sink plan without opening it.
///
/// # Errors
///
/// Returns a configuration error for an unregistered custom writer name.
fn prepare_writer_plan(
    config: &WafConfig,
    registry: &AuditLogRegistry,
) -> Result<(Option<CustomWriterPlan>, WriterPlan), String> {
    let Some(name) = &config.audit_log_custom_type else {
        return Ok((None, prepare_builtin_writer_plan(config)?));
    };
    let factory = registry
        .writer(name)
        .ok_or_else(|| format!("invalid audit log type: {name}"))?;
    Ok((
        Some(CustomWriterPlan {
            factory: Arc::clone(factory),
            config: Box::new(config.clone()),
        }),
        WriterPlan::Discard,
    ))
}

/// Build a built-in sink plan without opening its target.
///
/// # Errors
///
/// Returns configuration errors for invalid syslog or HTTPS targets and missing
/// concurrent storage directories.
fn prepare_builtin_writer_plan(config: &WafConfig) -> Result<WriterPlan, String> {
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
                write_timeout: syslog_write_timeout(target, config.audit_log_write_timeout),
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
    Ok(plan)
}

impl AuditLogger {
    /// Create a logger that discards audit entries.
    pub(crate) fn discard() -> Self {
        Self {
            formatter: SelectedFormatter::Builtin(AuditLogFormat::Native),
            relevant_status: None,
            custom_writer: None,
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
    pub(crate) fn prepare(config: &WafConfig, registry: &AuditLogRegistry) -> Result<Self, String> {
        let relevant_status = match config.audit_log_relevant_status.as_str() {
            "" => None,
            pattern => {
                Some(Regex::new(pattern).map_err(|e| format!("invalid SecAuditLogRelevantStatus {pattern:?}: {e}"))?)
            },
        };
        let formatter = match &config.audit_log_custom_format {
            Some(name) => SelectedFormatter::Custom(Arc::clone(
                registry
                    .formatter(name)
                    .ok_or_else(|| format!("invalid audit log format: {name}"))?,
            )),
            None => SelectedFormatter::Builtin(config.audit_log_format),
        };
        let (custom_writer, plan) = prepare_writer_plan(config, registry)?;
        Ok(Self {
            formatter,
            relevant_status,
            custom_writer,
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
    /// The activation gate is only tried, never waited for: a concurrent explicit
    /// activation may be inside an unbounded dial, and a request thread must not join it.
    ///
    /// # Errors
    ///
    /// If an activation is due and fails, a previous failure is still inside its retry
    /// backoff, or another activation is in progress before this logger has a writer.
    /// The last case reports [`io::ErrorKind::WouldBlock`], so the caller's audit write is
    /// not attempted instead of waiting for an activation that may take an unbounded dial.
    pub(crate) fn ensure_activated(&self) -> io::Result<()> {
        if let Some(result) = self.activated_or_in_backoff() {
            return result;
        }
        let _gate = match self.gate.try_lock() {
            Ok(gate) => gate,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return self.activation_in_progress(),
        };
        if let Some(result) = self.activated_or_in_backoff() {
            return result;
        }
        self.install(true)
    }

    /// `Some` when no attempt is needed now: a writer exists, or a failure is inside its
    /// retry backoff.
    fn activated_or_in_backoff(&self) -> Option<io::Result<()>> {
        let state = self.state.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = if state.writer.is_some() {
            Some(Ok(()))
        } else if let Some(failure) = &state.failure
            && Self::in_backoff(&state)
        {
            Some(Err(failure.to_error()))
        } else {
            None
        };
        drop(state);
        result
    }

    /// The result for a caller that found the activation gate busy.
    fn activation_in_progress(&self) -> io::Result<()> {
        let state = self.state.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = if state.writer.is_some() {
            Ok(())
        } else if let Some(failure) = &state.failure {
            Err(failure.to_error())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "audit log activation is in progress",
            ))
        };
        drop(state);
        result
    }

    /// Whether a failed activation may not be retried yet.
    fn in_backoff(state: &ActivationState) -> bool {
        state.retry_at.is_some_and(|retry_at| Instant::now() < retry_at)
    }

    /// Open the planned writer outside the state lock; the activation gate is held.
    fn install(&self, internal: bool) -> io::Result<()> {
        let activation_mime = self.formatter.mime();
        let opened = match &self.custom_writer {
            Some(custom_writer) => custom_writer.open(activation_mime),
            None => self.plan.open(activation_mime, internal),
        };
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
        let logger = Self::prepare(config, &AuditLogRegistry::default())?;
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
        // A discard plan with no custom writer has nothing to format or activate.
        if self.custom_writer.is_none() && matches!(&self.plan, WriterPlan::Discard) {
            return Ok(());
        }
        let formatted = self.formatter.format(entry);
        if formatted.as_bytes().is_empty() {
            return Ok(());
        }
        self.ensure_activated()?;
        let Some(writer) = self.writer() else {
            return Err(io::Error::other("audit log writer is not activated"));
        };
        writer.write(&formatted, entry, self.formatter.mime())
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

/// Default deadline for a write to a stream syslog socket.
///
/// A `write_all` on a full TCP or Unix-stream send buffer parks the writer's mutex, and
/// every transaction waiting on it, until the peer reads. A few seconds bounds that; a
/// configured `SecAuditLogWriteTimeout` stays authoritative.
const DEFAULT_SYSLOG_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// The write deadline for `target`: the configured one, or a default for a stream socket,
/// whose writes can block until the peer reads.
///
/// Only TCP and Unix-stream targets default: a datagram write does not block on the peer,
/// and the empty target resolves to whichever local socket answers, so its type is not
/// known before the dial.
fn syslog_write_timeout(target: &str, configured: Option<Duration>) -> Option<Duration> {
    if configured.is_some() || target.is_empty() {
        return configured;
    }
    let stream = match target.split_once("://") {
        // A bare address is a TCP address, as `Syslog::connect` reads it.
        None | Some(("tcp" | "tcp4" | "tcp6" | "unix", _)) => true,
        Some(_) => false,
    };
    stream.then_some(DEFAULT_SYSLOG_WRITE_TIMEOUT)
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
    /// Deadline for a TCP connection attempt. `None` only on an explicit initial dial,
    /// which may leave it unbounded; every reconnect stores the internal default instead.
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
    /// `connect_timeout` bounds a TCP connection attempt and is stored for reconnects;
    /// `write_timeout` is applied to the connected socket. An explicit caller may pass
    /// `None`, but [`Self::send`] reconnects with [`ACTIVATION_CONNECT_TIMEOUT`] when the
    /// stored deadline is unset, so a dropped socket cannot block a request thread.
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
    fn send(&mut self, message: &[u8], error: bool) -> io::Result<()> {
        // shortcut: syslog validates UTF-8 for each audit entry and that added pass is
        // unmeasured; revisit if audit throughput becomes a target.
        if let Ok(message) = std::str::from_utf8(message) {
            return self.send_text(message, error);
        }

        // Custom formatters may emit arbitrary bytes; preserve those without lossy UTF-8 conversion.
        let priority = 16 * 8 + if error { 3 } else { 6 };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| i64::try_from(since.as_secs()).unwrap_or(i64::MAX));
        let at = LocalTime::from_unix(now);
        let tag = format!("com.coraza.waf[{}]", std::process::id());
        let prefix = if self.local {
            format!("<{priority}>{} {tag}: ", at.syslog_stamp())
        } else {
            format!("<{priority}>{} {} {tag}: ", at.rfc3339(), hostname())
        };
        let mut framed = Vec::with_capacity(prefix.len() + message.len() + 1);
        framed.extend_from_slice(prefix.as_bytes());
        framed.extend_from_slice(message);
        if !message.ends_with(b"\n") {
            framed.push(b'\n');
        }
        self.send_frame(&framed)
    }

    /// Frames UTF-8 messages after `send` has validated their bytes.
    fn send_text(&mut self, message: &str, error: bool) -> io::Result<()> {
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
        self.send_frame(framed.as_bytes())
    }

    /// Send one framed message, reconnecting once when the original socket fails.
    fn send_frame(&mut self, framed: &[u8]) -> io::Result<()> {
        if self.socket.write_frame(framed).is_err() {
            // A reconnect happens on the request path, so it is always bounded even when
            // the explicit initial dial was not; the new socket stores that deadline.
            let connect_timeout = connect_deadline(self.connect_timeout, true);
            *self = Self::connect(&self.target, connect_timeout, self.write_timeout)?;
            self.socket.write_frame(framed)?;
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

    #[cfg(test)]
    use super::audit_log_mime;
    #[cfg(test)]
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
        pub(super) fn open(target: &str, content_type: &'static str) -> Result<Self, String> {
            validate_target(target)?;
            Ok(Self::with_exchange(target, content_type, Box::new(UreqExchange::new())))
        }

        /// A writer sending through `exchange`.
        fn with_exchange(target: &str, content_type: &'static str, exchange: Box<dyn HttpExchange>) -> Self {
            Self {
                url: target.to_owned(),
                content_type,
                exchange,
            }
        }

        /// POSTs one formatted entry, as Go Coraza's HTTPS writer does.
        ///
        /// # Errors
        ///
        /// If the request fails or the response status isn't 2xx.
        pub(super) fn write(&self, body: &[u8]) -> io::Result<()> {
            let post = HttpPost {
                method: "POST",
                url: &self.url,
                user_agent: USER_AGENT,
                content_type: self.content_type,
                body,
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
    ///
    /// Only the HTTPS writer tests need it: built-in sinks take the MIME from
    /// [`super::FormattedAudit`], so without this gate an all-features library build
    /// reports it as dead code.
    #[cfg(test)]
    fn format_mime(format: AuditLogFormat) -> &'static str {
        audit_log_mime(format)
    }

    #[cfg(test)]
    #[expect(clippy::unwrap_used, reason = "HTTPS audit log tests use scripted exchanges")]
    mod tests {
        use std::{
            collections::VecDeque,
            sync::{Arc, Mutex},
            time::Duration,
        };

        use super::{HttpExchange, HttpPost, HttpsWriter, TIMEOUT, format_mime};
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
                HttpsWriter::with_exchange(target, format_mime(format), Box::new(exchange.clone())),
                exchange,
            )
        }

        #[test]
        fn writer_posts_the_entry_as_go_does() {
            let (writer, exchange) = scripted_writer("http://127.0.0.1:8080/audit", AuditLogFormat::Json, [Ok(200)]);
            writer.write(b"{\"transaction\":{}}").unwrap();

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
                writer.write(b"entry").unwrap();
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
                writer.write(b"entry").unwrap();
            }
        }

        #[test]
        fn non_2xx_statuses_fail_as_in_go() {
            for status in [199, 300, 301, 400, 404, 500] {
                let (writer, _exchange) =
                    scripted_writer("https://example.com/audit", AuditLogFormat::Native, [Ok(status)]);
                let error = writer.write(b"entry").unwrap_err();
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
            let error = writer.write(b"entry").unwrap_err();
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
                assert!(
                    HttpsWriter::open(target, format_mime(AuditLogFormat::Json)).is_ok(),
                    "{target}"
                );
            }
        }

        #[test]
        fn open_accepts_an_uppercase_scheme() {
            assert!(HttpsWriter::open("HTTP://example.com/audit", format_mime(AuditLogFormat::Json)).is_ok());
            assert!(HttpsWriter::open("HtTpS://example.com/audit", format_mime(AuditLogFormat::Json)).is_ok());
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
                let error = HttpsWriter::open(target, format_mime(AuditLogFormat::Json))
                    .err()
                    .unwrap();
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
                let error = HttpsWriter::open(target, format_mime(AuditLogFormat::Json))
                    .err()
                    .unwrap();
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
            let error = HttpsWriter::open("http://exa mple.com/audit", format_mime(AuditLogFormat::Json))
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
pub(crate) mod tests {
    use super::{
        ACTIVATION_CONNECT_TIMEOUT, ACTIVATION_RETRY_BACKOFF, ACTIVATION_RETRY_BACKOFF_MAX, AuditCopyBudget, AuditLog,
        AuditLogger, AuditMessage, AuditMessageData, AuditRequest, AuditTransaction, DEFAULT_SYSLOG_WRITE_TIMEOUT,
        FormattedAudit, MAX_LOG_URI, Syslog, SyslogSocket, Writer, WriterPlan, connect_deadline, connect_tcp,
        index_field, next_backoff, prepare_builtin_writer_plan, safe_file_component, syslog_write_timeout, write_new,
    };
    use crate::{
        actions::RuleMetadata,
        collection::MatchData,
        config::WafConfig,
        types::{AuditEngineStatus, AuditLogFormat, AuditLogType, RulePhase, parse_audit_log_parts},
        utils::strings::go_quote,
    };

    #[test]
    fn stream_syslog_targets_get_a_default_write_timeout() {
        let default = Some(DEFAULT_SYSLOG_WRITE_TIMEOUT);
        for target in [
            "tcp://127.0.0.1:514",
            "tcp4://127.0.0.1:514",
            "tcp6://[::1]:514",
            // A bare address is a TCP address.
            "127.0.0.1:514",
        ] {
            assert_eq!(syslog_write_timeout(target, None), default, "{target}");
        }
        for target in ["udp://127.0.0.1:514", "udp6://[::1]:514", "unixgram:///dev/log"] {
            assert_eq!(syslog_write_timeout(target, None), None, "{target}");
        }
        assert_eq!(syslog_write_timeout("", None), None, "the local syslog type is unknown");

        #[cfg(unix)]
        assert_eq!(syslog_write_timeout("unix:///dev/log", None), default);

        let configured = Some(std::time::Duration::from_secs(1));
        for target in ["tcp://127.0.0.1:514", "udp://127.0.0.1:514"] {
            assert_eq!(
                syslog_write_timeout(target, configured),
                configured,
                "{target}: an explicit value stays authoritative"
            );
        }

        let plan = prepare_builtin_writer_plan(&WafConfig {
            audit_log_type: AuditLogType::Syslog,
            audit_log: "tcp://127.0.0.1:514".to_owned(),
            ..WafConfig::default()
        })
        .unwrap();
        assert!(
            matches!(plan, WriterPlan::Syslog { write_timeout, .. } if write_timeout == default),
            "the prepared plan carries the default"
        );
    }

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

    /// Run `run` on another thread, giving up after `timeout` instead of hanging the suite.
    fn within<T: Send + 'static>(timeout: std::time::Duration, run: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(sender.send(run()));
        });
        receiver.recv_timeout(timeout).ok()
    }

    #[test]
    fn a_held_gate_does_not_block_an_installed_writer() {
        let logger = std::sync::Arc::new(AuditLogger::discard());
        logger.ensure_activated().unwrap();
        let gate = logger.gate.lock().unwrap();
        let started = std::time::Instant::now();
        let result = within(std::time::Duration::from_secs(1), {
            let logger = std::sync::Arc::clone(&logger);
            move || logger.ensure_activated()
        });
        assert!(
            result.is_some(),
            "an installed writer must not wait for the activation gate"
        );
        let result = result.unwrap();
        let elapsed = started.elapsed();
        drop(gate);

        assert!(result.is_ok());
        assert!(elapsed < std::time::Duration::from_secs(1), "{elapsed:?}");
    }

    #[test]
    fn a_held_gate_without_a_writer_reports_would_block() {
        let logger = std::sync::Arc::new(AuditLogger::discard());
        let gate = logger.gate.lock().unwrap();
        let started = std::time::Instant::now();
        let result = within(std::time::Duration::from_secs(1), {
            let logger = std::sync::Arc::clone(&logger);
            move || logger.ensure_activated()
        });
        assert!(
            result.is_some(),
            "ensure_activated must not wait for the activation gate"
        );
        let result = result.unwrap();
        let elapsed = started.elapsed();
        let attempts = logger.attempts();
        drop(gate);

        assert!(result.is_err(), "no writer and a busy gate cannot succeed");
        let error = result.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock, "{error}");
        assert!(error.to_string().contains("activation is in progress"), "{error}");
        assert!(elapsed < std::time::Duration::from_secs(1), "{elapsed:?}");
        assert_eq!(attempts, 0, "a caller that lost the gate must not attempt activation");
    }

    #[test]
    fn a_held_gate_reports_a_memoised_failure_instead_of_would_block() {
        let config = WafConfig {
            audit_engine: AuditEngineStatus::On,
            audit_log_type: AuditLogType::Syslog,
            audit_log: "unix:///nonexistent/coraza-audit.sock".to_owned(),
            ..WafConfig::default()
        };
        let logger = std::sync::Arc::new(AuditLogger::prepare(&config, &super::AuditLogRegistry::default()).unwrap());
        assert!(logger.ensure_activated().is_err());
        logger.expire_backoff();
        let gate = logger.gate.lock().unwrap();
        let result = within(std::time::Duration::from_secs(1), {
            let logger = std::sync::Arc::clone(&logger);
            move || logger.ensure_activated()
        });
        assert!(
            result.is_some(),
            "ensure_activated must not wait for the activation gate"
        );
        let result = result.unwrap();
        let attempts = logger.attempts();
        drop(gate);

        assert!(result.is_err(), "the memoised failure is reported, not a new attempt");
        let error = result.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound, "{error}");
        assert_eq!(attempts, 1, "the memoised failure is reused inside a held gate");
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
        let logger = AuditLogger::prepare(&config, &super::AuditLogRegistry::default()).unwrap();
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
    fn bounded_format_caps_control_heavy_entries_in_every_configured_format() {
        const OUTPUT_LIMIT: usize = 16 * 1024;
        let control_heavy = "\u{0007}".repeat(1024 * 1024);
        let entry = AuditLog {
            parts: parse_audit_log_parts("ACHKZ").unwrap(),
            transaction: AuditTransaction {
                request: AuditRequest {
                    body: control_heavy.clone(),
                    args: vec![("body".to_owned(), control_heavy.clone())],
                    ..AuditRequest::default()
                },
                ..AuditTransaction::default()
            },
            messages: vec![AuditMessage {
                message: control_heavy.clone(),
                data: AuditMessageData {
                    data: control_heavy.clone(),
                    raw: control_heavy,
                    ..AuditMessageData::default()
                },
                ..AuditMessage::default()
            }],
        };

        for format in [
            AuditLogFormat::Native,
            AuditLogFormat::Json,
            AuditLogFormat::JsonLegacy,
            AuditLogFormat::Ocsf,
        ] {
            let mut budget = AuditCopyBudget::new(OUTPUT_LIMIT);
            let view = entry.bounded_copy(format, &mut budget);
            assert!(budget.bytes_used <= OUTPUT_LIMIT);
            assert!(budget.items_used <= OUTPUT_LIMIT.saturating_add(63) / 64);
            assert!(view.format(format).len() <= OUTPUT_LIMIT * 48);

            let (formatted, truncated) = entry.format_bounded(format, OUTPUT_LIMIT);
            assert!(truncated, "format={format:?}");
            assert!(formatted.len() <= OUTPUT_LIMIT, "format={format:?}");
        }
    }

    #[test]
    fn bounded_copy_caps_collection_items() {
        let entry = AuditLog {
            transaction: AuditTransaction {
                request: AuditRequest {
                    args: vec![("k".to_owned(), "v".to_owned()), ("k".to_owned(), "v".to_owned())],
                    ..AuditRequest::default()
                },
                ..AuditTransaction::default()
            },
            ..AuditLog::default()
        };
        let mut budget = AuditCopyBudget::new(64);

        let view = entry.bounded_copy(AuditLogFormat::Ocsf, &mut budget);

        assert_eq!(view.transaction.request.args.len(), 1);
        assert_eq!(budget.items_used, 1);
        assert!(budget.truncated);
    }

    #[test]
    fn bounded_json_formats_are_valid_json_at_every_size_down_to_the_bare_marker() {
        let entry = AuditLog {
            parts: parse_audit_log_parts("ACHKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-1".to_owned(),
                request: AuditRequest {
                    uri: format!("/{}", "u".repeat(5000)),
                    body: "b".repeat(5000),
                    ..AuditRequest::default()
                },
                ..AuditTransaction::default()
            },
            messages: vec![AuditMessage {
                message: "blocked".to_owned(),
                data: AuditMessageData {
                    id: 949_110,
                    msg: "blocked".to_owned(),
                    ..AuditMessageData::default()
                },
                ..AuditMessage::default()
            }],
        };
        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            for limit in [0_usize, 10, 18, 40, 300, 1000, 4000, 16 * 1024] {
                let (formatted, truncated) = entry.format_bounded(format, limit);
                assert!(
                    formatted.len() <= limit,
                    "{format:?} limit {limit}: {} bytes",
                    formatted.len()
                );
                if limit < super::bare_truncation_marker(format).len() {
                    assert!(formatted.is_empty(), "{format:?} limit {limit}: nothing valid fits");
                    continue;
                }
                assert!(
                    serde_json::from_str::<serde_json::Value>(&formatted).is_ok(),
                    "{format:?} limit {limit}: {formatted}"
                );
                assert_eq!(
                    truncated,
                    limit < 16 * 1024,
                    "{format:?} limit {limit}: only a record that did not fit whole is reported cut"
                );
            }
        }
    }

    #[test]
    fn the_tiny_limit_fallback_is_valid_for_each_format_and_marks_ocsf_under_unmapped() {
        let entry = AuditLog {
            parts: parse_audit_log_parts("ACHKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-1".to_owned(),
                request: AuditRequest {
                    uri: "/".repeat(500),
                    ..AuditRequest::default()
                },
                ..AuditTransaction::default()
            },
            ..AuditLog::default()
        };
        for (format, marker) in [
            (AuditLogFormat::Json, r#"{"truncated":true}"#),
            (AuditLogFormat::JsonLegacy, r#"{"truncated":true}"#),
            (AuditLogFormat::Ocsf, r#"{"unmapped":{"truncated":true}}"#),
        ] {
            let (formatted, truncated) = entry.format_bounded(format, marker.len());
            assert_eq!(formatted, marker, "{format:?}");
            assert!(truncated, "{format:?}");
            let (formatted, truncated) = entry.format_bounded(format, marker.len() - 1);
            assert!(formatted.is_empty(), "{format:?}: the marker does not fit: {formatted}");
            assert!(truncated, "{format:?}");
        }
    }

    /// The rule ids and message texts a formatted JSON document keeps, in order; `JSONLegacy` has no ids.
    pub(crate) fn kept_messages(format: AuditLogFormat, formatted: &str) -> Vec<(Option<i64>, String)> {
        let value: serde_json::Value = serde_json::from_str(formatted).unwrap();
        let text = |value: &serde_json::Value, pointer: &str| {
            // An empty text is left out of the document.
            value
                .pointer(pointer)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let list = |pointer: &str| value.pointer(pointer).unwrap().as_array().unwrap().clone();
        match format {
            AuditLogFormat::Json => list("/messages")
                .iter()
                .map(|message| {
                    (
                        message.pointer("/data/id").and_then(serde_json::Value::as_i64),
                        text(message, "/message"),
                    )
                })
                .collect(),
            AuditLogFormat::JsonLegacy => list("/audit_data/messages")
                .iter()
                .map(|message| (None, message.as_str().unwrap().to_owned()))
                .collect(),
            _ => list("/enrichments")
                .iter()
                .map(|enrichment| {
                    let data: serde_json::Value = serde_json::from_str(&text(enrichment, "/data")).unwrap();
                    (
                        data.pointer("/id").and_then(serde_json::Value::as_i64),
                        text(enrichment, "/name"),
                    )
                })
                .collect(),
        }
    }

    /// The `[msg "…"]` field of a compact identity, which must be there whole: the closing quote and bracket
    /// present, and the quoted text a valid string that decodes to a prefix of `message`.
    fn compact_msg_prefix(identity: &str, message: &str) -> String {
        let field = identity.split_once(" [msg ").map(|(_, field)| field).unwrap();
        let quoted = field.strip_suffix(']');
        assert!(quoted.is_some(), "no closing bracket: {identity}");
        let decoded = serde_json::from_str::<String>(quoted.unwrap());
        assert!(decoded.is_ok(), "not a quoted string: {identity}");
        let decoded = decoded.unwrap();
        assert!(
            message.starts_with(&decoded),
            "{decoded:?} is not a prefix of {message:?}"
        );
        decoded
    }

    #[test]
    fn a_compact_identity_keeps_its_msg_field_whole_when_quoting_expands_the_text() {
        // Rule 4242 at a 32-byte allowance leaves 12 bytes for the quoted message.
        for message in [
            "\\".repeat(40),
            "\"".repeat(40),
            format!("a{}", "\\".repeat(40)),
            // An escape sequence is never split, nor a character: 3-byte characters do not fit in 12 bytes
            // as anything but whole ones.
            "\u{20ac}\\".repeat(20),
            "ab\"cd\\ef".repeat(10),
        ] {
            for limit in [32, 31, 30, 29, 33, 64] {
                let identity = super::reduced_identity(4242, &message, limit);
                assert!(identity.starts_with("[id \"4242\"]"), "{identity}");
                assert!(identity.len() <= limit, "{limit}: {identity}");
                assert!(identity.ends_with("\"]"), "{limit}: {identity}");
                let decoded = compact_msg_prefix(&identity, &message);
                assert!(!decoded.is_empty(), "{limit}: some of the message fits: {identity}");
            }
        }
        // A message that fits is written whole, and one with nothing that fits leaves the field out.
        let identity = super::reduced_identity(4242, "a\\b", 64);
        assert_eq!(identity, "[id \"4242\"] [msg \"a\\\\b\"]");
        assert_eq!(super::reduced_identity(4242, "\\", 20), "[id \"4242\"]");
    }

    #[test]
    fn a_pinned_message_with_escapes_keeps_its_compact_msg_field_whole() {
        for message in ["\\".repeat(40), "\"".repeat(40)] {
            let source = AuditMessage {
                rule_id: 4242,
                rule_message: message.clone(),
                error_message: "e".repeat(500),
                ..AuditMessage::default()
            };
            for mode in [super::AuditMessageCopy::Json, super::AuditMessageCopy::Legacy] {
                let mut budget = AuditCopyBudget::generous(32);
                let copy = budget.pinned_message(&source, mode);
                let identity = if mode == super::AuditMessageCopy::Json {
                    copy.error_message
                } else {
                    copy.message
                };
                assert!(
                    identity.starts_with("[id \"4242\"]") && identity.ends_with("\"]"),
                    "{identity}"
                );
                compact_msg_prefix(&identity, &message);
            }
        }
    }

    /// A message of `text` bytes of message text for rule `id`.
    fn message_of(id: i32, text: usize) -> AuditMessage {
        AuditMessage {
            message: "m".repeat(text),
            data: AuditMessageData {
                id,
                msg: "m".repeat(text),
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        }
    }

    #[test]
    fn a_record_that_fits_is_the_unbounded_serialisation_with_no_marker() {
        // One long message among short ones: an even split of the cap over the messages (about 800 bytes each)
        // used to cut the long one, although the whole record is far under the 16 KiB.
        let mut messages = vec![message_of(1, 10), message_of(2, 5600), message_of(3, 10)];
        messages.extend((4..12).map(|id| message_of(id, 20)));
        let entry = AuditLog {
            parts: parse_audit_log_parts("ABCHKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-1".to_owned(),
                request: AuditRequest {
                    uri: "/path".to_owned(),
                    body: "b".repeat(100),
                    ..AuditRequest::default()
                },
                ..AuditTransaction::default()
            },
            messages,
        };
        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            let whole = entry.format(format);
            assert!(
                whole.len() > 5600 && whole.len() < 16 * 1024,
                "{format:?}: {}",
                whole.len()
            );
            let (formatted, truncated) = entry.format_bounded(format, 16 * 1024);
            assert!(!truncated, "{format:?}: nothing was reduced");
            if format == AuditLogFormat::Ocsf {
                // Every OCSF record carries the time it was formatted at.
                let without_time = |text: &str| {
                    let mut value: serde_json::Value = serde_json::from_str(text).unwrap();
                    value
                        .pointer_mut("/metadata")
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .remove("logged_time");
                    value
                };
                assert_eq!(without_time(&formatted), without_time(&whole), "{format:?}");
            } else {
                assert_eq!(formatted, whole, "{format:?}");
            }
            assert!(!formatted.contains("truncated"), "{format:?}: no marker");
        }
    }

    /// `text` parsed, with the time OCSF stamps on each formatting taken out.
    fn parsed_without_time(text: &str) -> serde_json::Value {
        let mut value: serde_json::Value = serde_json::from_str(text).unwrap();
        if let Some(metadata) = value
            .pointer_mut("/metadata")
            .and_then(serde_json::Value::as_object_mut)
        {
            metadata.remove("logged_time");
        }
        value
    }

    #[test]
    fn a_record_that_fits_keeps_its_data_though_its_bytes_may_differ() {
        // DEL and the C1 controls are left raw by `format` and escaped by the bounded formatter.
        let text = "a\u{85}b\u{7f}c\u{9f}d";
        let entry = AuditLog {
            parts: parse_audit_log_parts("ABCHKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-1".to_owned(),
                request: AuditRequest {
                    uri: format!("/{text}"),
                    ..AuditRequest::default()
                },
                ..AuditTransaction::default()
            },
            messages: vec![AuditMessage {
                message: text.to_owned(),
                data: AuditMessageData {
                    id: 5,
                    msg: text.to_owned(),
                    data: text.to_owned(),
                    ..AuditMessageData::default()
                },
                ..AuditMessage::default()
            }],
        };
        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            let whole = entry.format(format);
            let (formatted, truncated) = entry.format_bounded(format, 16 * 1024);
            assert!(!truncated, "{format:?}");
            assert!(
                whole.contains('\u{85}'),
                "{format:?}: the unbounded output leaves it raw"
            );
            assert!(
                !formatted.contains('\u{85}') && formatted.contains("\\u0085"),
                "{format:?}: {formatted}"
            );
            assert_eq!(
                parsed_without_time(&formatted),
                parsed_without_time(&whole),
                "{format:?}: the escaped output decodes to the same value"
            );
        }
    }

    #[test]
    fn a_huge_producer_entry_leaves_a_compact_record_with_the_id_and_the_interrupting_rule() {
        // Every attempt overflowed on the producer, and the record fell to the bare marker.
        let entry = AuditLog {
            parts: parse_audit_log_parts("AHKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-compact".to_owned(),
                is_interrupted: true,
                interruption_rule_id: Some(4242),
                producer: Some(super::AuditProducer {
                    connector: "c".repeat(16 * 1024),
                    rulesets: vec!["r".repeat(16 * 1024)],
                    ..super::AuditProducer::default()
                }),
                ..AuditTransaction::default()
            },
            messages: vec![AuditMessage {
                message: "DENY-RULE".to_owned(),
                data: AuditMessageData {
                    id: 4242,
                    msg: "DENY-RULE".to_owned(),
                    ..AuditMessageData::default()
                },
                ..AuditMessage::default()
            }],
        };
        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            let (formatted, truncated) = entry.format_bounded(format, 4096);
            assert!(truncated && formatted.len() <= 4096, "{format:?}");
            let document: serde_json::Value = serde_json::from_str(&formatted).unwrap();
            let marker = if format == AuditLogFormat::Ocsf {
                "/unmapped/truncated"
            } else {
                "/truncated"
            };
            assert_eq!(
                document.pointer(marker),
                Some(&serde_json::Value::Bool(true)),
                "{format:?}"
            );
            let kept = kept_messages(format, &formatted);
            assert!(
                kept.iter()
                    .any(|(id, text)| text == "DENY-RULE" && id.is_none_or(|id| id == 4242)),
                "{format:?}: the interrupting rule is kept: {formatted}"
            );
            if format == AuditLogFormat::JsonLegacy {
                assert!(formatted.contains("tx-compact"), "{formatted}");
            } else {
                let id_pointer = if format == AuditLogFormat::Ocsf {
                    "/http_request/uid"
                } else {
                    "/transaction/id"
                };
                assert_eq!(
                    document.pointer(id_pointer).and_then(serde_json::Value::as_str),
                    Some("tx-compact"),
                    "{format:?}: the transaction id is kept"
                );
            }
        }
    }

    #[test]
    fn ocsf_is_not_charged_for_message_text_it_never_writes() {
        // OCSF writes the first message's text only; a long `message` on a later one is never serialised.
        let entry = AuditLog {
            parts: parse_audit_log_parts("AKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-1".to_owned(),
                ..AuditTransaction::default()
            },
            messages: vec![
                AuditMessage {
                    message: "first message text".to_owned(),
                    data: AuditMessageData {
                        id: 1,
                        msg: "first".to_owned(),
                        ..AuditMessageData::default()
                    },
                    ..AuditMessage::default()
                },
                AuditMessage {
                    message: "x".repeat(16 * 1024),
                    data: AuditMessageData {
                        id: 2,
                        msg: "second".to_owned(),
                        ..AuditMessageData::default()
                    },
                    ..AuditMessage::default()
                },
            ],
        };
        let whole = entry.format(AuditLogFormat::Ocsf);
        assert!(whole.len() < 2048, "{}", whole.len());
        let (formatted, truncated) = entry.format_bounded(AuditLogFormat::Ocsf, 16 * 1024);
        assert!(!truncated, "{formatted}");
        let document: serde_json::Value = serde_json::from_str(&formatted).unwrap();
        assert_eq!(
            document.pointer("/message").and_then(serde_json::Value::as_str),
            Some("first message text")
        );
        assert_eq!(kept_messages(AuditLogFormat::Ocsf, &formatted).len(), 2);
    }

    #[test]
    fn many_tiny_messages_that_fit_are_all_kept() {
        // 3000 empty messages are `""` each in JSONLegacy, 9 KB in all: far more entries than the 64-byte-per-entry
        // allowance of the native copy would admit, and they fit.
        let entry = AuditLog {
            parts: parse_audit_log_parts("AKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-1".to_owned(),
                ..AuditTransaction::default()
            },
            messages: (1..=3000).map(|id| message_of(id, 0)).collect(),
        };
        let whole = entry.format(AuditLogFormat::JsonLegacy);
        assert!(whole.len() < 16 * 1024, "{}", whole.len());
        let (formatted, truncated) = entry.format_bounded(AuditLogFormat::JsonLegacy, 16 * 1024);
        assert!(!truncated);
        assert_eq!(formatted, whole);
    }

    #[test]
    fn request_padding_does_not_consume_message_text() {
        let entry = AuditLog {
            parts: parse_audit_log_parts("ACKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-1".to_owned(),
                request: AuditRequest {
                    body: "b".repeat(20_000),
                    ..AuditRequest::default()
                },
                ..AuditTransaction::default()
            },
            messages: vec![message_of(1, 3000), message_of(2, 3000)],
        };
        let (formatted, truncated) = entry.format_bounded(AuditLogFormat::Json, 16 * 1024);
        assert!(truncated);
        assert!(formatted.len() <= 16 * 1024);
        assert!(
            formatted.contains(&"m".repeat(3000)),
            "message text survives the padding"
        );
        assert_eq!(kept_messages(AuditLogFormat::Json, &formatted).len(), 2);
    }

    #[test]
    fn the_interrupting_message_is_kept_when_messages_are_dropped() {
        // The interrupting rule is neither first nor last: a logging rule matches after it.
        let tagged = |id: i32| AuditMessage {
            message: format!("msg-{id} {}", "m".repeat(200)),
            data: AuditMessageData {
                id,
                msg: format!("msg-{id}"),
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        };
        let mut messages: Vec<_> = (1..=100).map(tagged).collect();
        messages.push(tagged(900));
        messages.extend((1..=100).map(|id| tagged(1000 + id)));
        let entry = AuditLog {
            parts: parse_audit_log_parts("AKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-1".to_owned(),
                is_interrupted: true,
                interruption_rule_id: Some(900),
                ..AuditTransaction::default()
            },
            messages,
        };
        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            let (formatted, truncated) = entry.format_bounded(format, 4096);
            assert!(truncated && formatted.len() <= 4096, "{format:?}");
            let kept = kept_messages(format, &formatted);
            assert!(kept.len() < 201, "{format:?}: messages were dropped");
            assert!(
                kept.iter().any(|(_, text)| text.starts_with("msg-900")),
                "{format:?}: the interrupting rule's message is kept: {kept:?}"
            );
            if format != AuditLogFormat::JsonLegacy {
                let ids: Vec<_> = kept.iter().map(|(id, _)| *id).collect();
                assert!(ids.contains(&Some(900)), "{format:?}: {ids:?}");
                assert!(ids.is_sorted(), "{format:?}: kept messages stay in order: {ids:?}");
            }
        }
    }

    #[test]
    fn a_record_full_of_rule_tags_keeps_its_identity_and_deny_rule_when_reduced() {
        // One short deny and thousands of one-byte tags: text reduction cannot remove the array entries, and
        // OCSF escapes the array again inside the enrichment's `data` string, so only dropping the tags fits.
        let deny = AuditMessage {
            message: "DENY-RULE".to_owned(),
            rule_id: 900,
            data: AuditMessageData {
                id: 900,
                msg: "DENY-RULE".to_owned(),
                tags: vec!["t".to_owned(); 4000],
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        };
        let entry = AuditLog {
            parts: parse_audit_log_parts("AKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-many-tags".to_owned(),
                is_interrupted: true,
                interruption_rule_id: Some(900),
                ..AuditTransaction::default()
            },
            messages: vec![deny],
        };
        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            // JSONLegacy does not write tags, so its record fits whole.
            assert_eq!(
                entry.format(format).len() > 16 * 1024,
                format != AuditLogFormat::JsonLegacy,
                "{format:?}"
            );
            let (formatted, truncated) = entry.format_bounded(format, 16 * 1024);
            assert_eq!(truncated, format != AuditLogFormat::JsonLegacy, "{format:?}");
            assert!(formatted.len() <= 16 * 1024, "{format:?}");
            assert_ne!(
                formatted,
                super::bare_truncation_marker(format),
                "{format:?}: more than the bare marker"
            );
            assert!(
                formatted.contains("tx-many-tags"),
                "{format:?}: the transaction id: {formatted}"
            );
            let kept = kept_messages(format, &formatted);
            assert!(
                kept.iter().any(|(_, text)| text == "DENY-RULE"),
                "{format:?}: the deny rule's message: {kept:?}"
            );
            if format != AuditLogFormat::JsonLegacy {
                assert!(kept.iter().any(|(id, _)| *id == Some(900)), "{format:?}: {kept:?}");
            }
        }

        // A record that fits keeps its tags.
        let mut small = entry.clone();
        if let Some(message) = small.messages.first_mut() {
            message.data.tags = vec!["tag-a".to_owned(), "tag-b".to_owned()];
        }
        let (formatted, truncated) = small.format_bounded(AuditLogFormat::Json, 16 * 1024);
        assert!(!truncated && formatted.contains("tag-b"), "{formatted}");
    }

    #[test]
    fn the_last_message_is_kept_when_nothing_interrupted_the_transaction() {
        let entry = AuditLog {
            parts: parse_audit_log_parts("AKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-1".to_owned(),
                ..AuditTransaction::default()
            },
            messages: (1..=300).map(|id| message_of(id, 100)).collect(),
        };
        let (formatted, truncated) = entry.format_bounded(AuditLogFormat::Json, 4096);
        assert!(truncated);
        let ids: Vec<_> = kept_messages(AuditLogFormat::Json, &formatted)
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(ids.first(), Some(&Some(1)));
        assert_eq!(ids.last(), Some(&Some(300)));
    }

    #[test]
    fn the_formatter_copies_a_bounded_number_of_messages_out_of_a_huge_list() {
        let mut messages: Vec<_> = (1..=100_000).map(|id| message_of(id, 0)).collect();
        messages.push(message_of(7, 5));
        let entry = AuditLog {
            parts: parse_audit_log_parts("AKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-1".to_owned(),
                interruption_rule_id: Some(7),
                ..AuditTransaction::default()
            },
            messages,
        };
        let plan = super::AuditShrinkPlan {
            request_bytes: 16 * 1024,
            message_bytes: 16 * 1024,
            message_each: None,
            message_count: 100_001_usize.min(AuditCopyBudget::generous(16 * 1024).items_left),
            reduced: false,
        };
        let mut budget = AuditCopyBudget::generous(16 * 1024);
        let view = entry.bounded_copy_planned(AuditLogFormat::Json, &mut budget, Some(plan));
        assert!(view.messages.len() <= 16 * 1024 / 2 + 1, "{}", view.messages.len());
        assert!(budget.items_used <= 16 * 1024 / 2 + 1);
        assert!(
            view.messages.iter().any(|message| message.data.id == 7),
            "the interrupting message"
        );
        assert!(budget.truncated);

        // The whole path, which copies and serialises only what it keeps, in every format. Its work is
        // bounded by the messages it copies, counted at the copy: a bounded number per attempt, however many
        // the entry holds. Copying all 100001 of them even once would exceed the bound.
        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            super::MESSAGES_COPIED.with(|copied| copied.set(0));
            let (formatted, truncated) = entry.format_bounded(format, 16 * 1024);
            let copies = super::MESSAGES_COPIED.with(std::cell::Cell::get);
            assert!(truncated && formatted.len() <= 16 * 1024, "{format:?}");
            assert!(
                serde_json::from_str::<serde_json::Value>(&formatted).is_ok(),
                "{format:?}"
            );
            assert!(
                copies > 0 && copies <= 50_000,
                "{format:?}: {copies} message copies for 100001 messages"
            );
            // Id 7 is also an earlier, empty message: the pinned one is told apart by its text.
            let kept = kept_messages(format, &formatted);
            assert!(
                kept.iter()
                    .any(|(id, text)| text == "mmmmm" && id.is_none_or(|id| id == 7)),
                "{format:?}: the pinned message with its text is kept: {} kept",
                kept.len()
            );
        }
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

    /// A rule that matched `count` times, each with a short message and data except the `blank` ones.
    fn matched_rule_with(count: usize, blank: &[usize]) -> super::MatchedRule {
        let mut rule = RuleMetadata::new();
        rule.id = 72;
        rule.phase = RulePhase::RequestHeaders;
        let matches = (0..count)
            .map(|number| {
                let mut matched = MatchData::new_empty();
                if !blank.contains(&number) {
                    matched.message = format!("m{number}");
                    matched.data = format!("d{number}");
                }
                matched
            })
            .collect();
        super::MatchedRule {
            rule,
            matches,
            disruptive_action: None,
            disruptive: false,
            client_ip: "192.0.2.1".to_owned(),
            server_ip: "192.0.2.2".to_owned(),
            uri: "/path".to_owned(),
            transaction_id: "tx-1".to_owned(),
        }
    }

    #[test]
    fn error_log_lists_the_first_eight_extra_matches_and_counts_the_rest() {
        // Go lists every match; this engine stops at eight pairs so the line cannot grow with the rule's matches.
        for (matches, listed, hidden) in [(1, 0, 0), (2, 1, 0), (9, 8, 0), (10, 8, 1), (13, 8, 4), (1000, 8, 991)] {
            let formatted = matched_rule_with(matches, &[]).error_log();
            assert_eq!(formatted.matches("[msg_match_").count(), listed, "{matches} matches");
            assert_eq!(formatted.matches("[data_match_").count(), listed, "{matches} matches");
            for number in 1..=listed {
                assert!(
                    formatted.contains(&format!(
                        "[msg_match_{number} \"m{number}\"] [data_match_{number} \"d{number}\"]"
                    )),
                    "{matches} matches: pair {number} in {formatted}"
                );
            }
            assert!(!formatted.contains("[msg_match_9 "), "{matches} matches");
            if hidden == 0 {
                assert!(!formatted.contains("more matches"), "{matches} matches: {formatted}");
            } else {
                assert!(
                    formatted.ends_with(&format!(" [+{hidden} more matches]")),
                    "{matches} matches: {formatted}"
                );
                assert_eq!(formatted.matches("more matches").count(), 1);
            }
        }
    }

    #[test]
    fn error_log_cap_ignores_matches_without_a_message_or_data() {
        // Only a match that would have a pair counts toward the cap and the marker; the number stays its index.
        let formatted = matched_rule_with(12, &[2, 3, 11]).error_log();
        assert_eq!(formatted.matches("[msg_match_").count(), 8);
        assert!(formatted.contains("[msg_match_10 "), "{formatted}");
        assert!(!formatted.contains("[msg_match_2 ") && !formatted.contains("[msg_match_3 "));
        assert!(!formatted.contains("more matches"), "{formatted}");

        let formatted = matched_rule_with(14, &[5]).error_log();
        assert!(!formatted.contains("[msg_match_5 "));
        assert!(formatted.ends_with(" [+4 more matches]"), "{formatted}");
    }

    /// Audit one rule that matches `count` arguments under parts `ABHKZ`: the formatted entry's size and the
    /// bytes the messages' error lines hold.
    fn audited_hk_entry(count: usize, path_len: usize) -> (usize, usize) {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(&format!(
                "SecArgumentsLimit {count}\nSecAuditLogParts ABHKZ\n\
                 SecRule ARGS \"@rx ^v\" \"id:1,phase:1,pass,log,auditlog,msg:'value seen',\
                 logdata:'%{{MATCHED_VAR_NAME}}=%{{MATCHED_VAR}}'\""
            ))
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("audit-hk");
        tx.process_uri(format!("/{}", "p".repeat(path_len)), "GET", "HTTP/1.1");
        for index in 0..count {
            tx.add_get_argument(format!("a{index}"), "v");
        }
        assert!(tx.process_request_headers().is_none());
        assert_eq!(tx.matched_rules().first().map(|rule| rule.matches.len()), Some(count));
        let entry = tx.audit_log();
        assert_eq!(entry.messages.len(), count, "part K keeps one message per match");
        let error_lines = entry.messages.iter().map(|message| message.error_message.len()).sum();
        (entry.format(AuditLogFormat::Native).len(), error_lines)
    }

    #[test]
    fn audit_parts_h_and_k_keep_the_entry_linear_in_the_matches_of_one_rule() {
        let (size, lines) = audited_hk_entry(2_000, 0);
        assert!(
            size <= 2_000 * 1024,
            "an entry of {size} bytes for 2000 matches, over 1 KiB each"
        );
        // Doubling the matches doubles the entry; one quadratic term would quadruple it.
        let (half_size, half_lines) = audited_hk_entry(1_000, 0);
        assert!(
            size * 10 <= half_size * 25,
            "{half_size} bytes for 1000 matches, {size} for 2000"
        );
        assert!(
            lines * 10 <= half_lines * 25,
            "{half_lines} error line bytes for 1000 matches, {lines} for 2000"
        );
    }

    #[test]
    fn audit_entry_does_not_grow_with_the_request_uri_times_the_matches() {
        // The `[uri]` of every message's error line is cut, so a 50 KB path adds a constant per match.
        let (short_size, short_lines) = audited_hk_entry(1_000, 0);
        let (long_size, long_lines) = audited_hk_entry(1_000, 50_000);
        assert!(
            long_size <= short_size + 1_000 * 1_100 && long_lines <= short_lines + 1_000 * 1_100,
            "{short_size} bytes with a short path, {long_size} with 50000 path bytes (error lines {short_lines}, {long_lines})"
        );
    }

    #[test]
    fn error_log_cuts_a_long_uri_and_keeps_a_short_one_byte_identical() {
        let mut rule = matched_rule_with(1, &[]);
        for uri in ["/path".to_owned(), format!("/{}", "u".repeat(MAX_LOG_URI - 1))] {
            rule.uri = uri.clone();
            let formatted = rule.error_log();
            assert!(
                formatted.contains(&format!("[uri {}] [unique_id ", go_quote(&uri))),
                "{formatted}"
            );
            assert!(!formatted.contains("uri bytes]"), "{formatted}");
        }
        // 1025 bytes: the first 1024 stay, the marker counts the rest; the cut never splits a code point.
        rule.uri = format!("/{}", "u".repeat(MAX_LOG_URI));
        assert!(rule.error_log().contains(&format!(
            "[uri \"/{}\"] [+1 uri bytes] [unique_id ",
            "u".repeat(MAX_LOG_URI - 1)
        )));
        rule.uri = format!("/{}", "\u{e9}".repeat(MAX_LOG_URI));
        let formatted = rule.error_log();
        let kept = (MAX_LOG_URI - 1) / 2;
        assert!(
            formatted.contains(&format!(
                "{}\"] [+{} uri bytes] [unique_id ",
                "\u{e9}".repeat(kept),
                rule.uri.len() - 1 - 2 * kept
            )),
            "{formatted}"
        );
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
        syslog.send(b"reconnected", false).unwrap();

        let message = server.join().unwrap().unwrap();
        assert!(message.ends_with(b"reconnected\n"));
    }

    #[test]
    fn syslog_builtin_text_keeps_framing_and_custom_bytes_are_preserved() {
        use std::{net::UdpSocket, time::Duration};

        fn payload(frame: &[u8]) -> &[u8] {
            let delimiter = frame.windows(2).position(|window| window == b": ").unwrap();
            frame.get(delimiter + 2..).unwrap_or_default()
        }

        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.connect(receiver.local_addr().unwrap()).unwrap();
        let syslog = Syslog {
            socket: SyslogSocket::Udp(sender),
            target: "udp://127.0.0.1:0".to_owned(),
            local: false,
            connect_timeout: None,
            write_timeout: None,
        };
        let writer = Writer::Syslog(std::sync::Mutex::new(syslog));
        let entry = AuditLog::default();
        let mut received = [0; 512];

        writer
            .write(&FormattedAudit::Text("formatted π\n".to_owned()), &entry, "")
            .unwrap();
        let text_len = receiver.recv(&mut received).unwrap();
        let text_frame = received.get(..text_len).unwrap_or_default().to_vec();
        writer
            .write(&FormattedAudit::Bytes("formatted π\n".as_bytes().to_vec()), &entry, "")
            .unwrap();
        let bytes_len = receiver.recv(&mut received).unwrap();
        let bytes_frame = received.get(..bytes_len).unwrap_or_default();
        assert_eq!(payload(&text_frame), payload(bytes_frame));

        writer
            .write(&FormattedAudit::Bytes(b"raw\xff\n".to_vec()), &entry, "")
            .unwrap();
        let raw_len = receiver.recv(&mut received).unwrap();
        assert_eq!(payload(received.get(..raw_len).unwrap_or_default()), b"raw\xff\n");
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "AuditLogFormatter::mime() must remain stable for its lifetime")]
    fn custom_writer_checks_mime_stability() {
        struct NoopWriter;

        impl super::AuditLogWriter for NoopWriter {
            fn write(&self, _entry: &AuditLog, _formatted: &[u8], _mime: &'static str) -> std::io::Result<()> {
                Ok(())
            }
        }

        let writer = Writer::Custom {
            writer: Box::new(NoopWriter),
            activation_mime: "application/activation",
        };
        writer
            .write(
                &FormattedAudit::Bytes(Vec::new()),
                &AuditLog::default(),
                "application/later",
            )
            .unwrap();
    }

    #[test]
    fn an_unbounded_explicit_dial_still_reconnects_with_the_internal_deadline() {
        use std::{
            net::{Shutdown, TcpListener},
            time::Duration,
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = format!("tcp://{}", listener.local_addr().unwrap());
        let mut syslog = Syslog::connect(&target, None, None).unwrap();
        let (connection, _) = listener.accept().unwrap();
        assert_eq!(
            syslog.connect_timeout, None,
            "an explicit activation keeps Go's unbounded initial dial"
        );
        connection.shutdown(Shutdown::Both).unwrap();
        drop(connection);

        // The reset may reach the writer after a frame already fit in the send buffer, so
        // send until the failure triggers the reconnect; the listener keeps accepting.
        let mut result = Ok(());
        for _ in 0..50 {
            result = syslog.send(b"reconnect", false);
            if syslog.connect_timeout.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            syslog.connect_timeout.is_some(),
            "the writer did not reconnect: {result:?}"
        );
        assert_eq!(syslog.connect_timeout, Some(ACTIVATION_CONNECT_TIMEOUT));
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
            result = syslog.send(chunk.as_bytes(), false);
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
            let error = AuditLogger::prepare(&config, &super::AuditLogRegistry::default())
                .err()
                .unwrap();
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
            assert!(
                AuditLogger::prepare(&config, &super::AuditLogRegistry::default()).is_ok(),
                "{target}"
            );
        }
        #[cfg(unix)]
        for target in ["unix:///dev/log", "unixgram:///dev/log"] {
            let config = WafConfig {
                audit_log_type: AuditLogType::Syslog,
                audit_log: target.to_owned(),
                ..WafConfig::default()
            };
            assert!(
                AuditLogger::prepare(&config, &super::AuditLogRegistry::default()).is_ok(),
                "{target}"
            );
        }
    }
}
