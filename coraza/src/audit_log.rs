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

/// Visible audit tag used to distinguish the engine event that enforced an interruption.
pub(crate) const ENGINE_ENFORCED_TAG: &str = "coraza-rs/engine/Enforced";
/// Visible audit tag used when the enforcing engine event fell beyond the individual-detail cap.
pub(crate) const ENGINE_ENFORCED_OMITTED_TAG: &str = "coraza-rs/engine/EnforcedStopOmitted";
/// State tag for the bounded aggregate of engine stops beyond the individual-detail cap.
pub(crate) const ENGINE_EVENTS_OMITTED_TAG: &str = "coraza-rs/engine/EventsOmitted";
/// Honest bounded description when the exact count and its qualifiers do not fit.
const ENGINE_EVENTS_OMITTED_FALLBACK: &str = "additional engine stop details omitted";

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
    /// What logged rule matches and engine-originated stops have to say: one per
    /// rule-match value and retained engine event/summary with part `K`, or one
    /// per logged item with only part `H`.
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
    /// The ID associated with the enforced interruption. An engine-only stop uses `Some(0)`; a fail-closed
    /// `@inspectFile`/`@rbl` refusal can retain its source rule ID. `DetectionOnly` and other unenforced stops use
    /// `None`. Bounded formatters use this ID to retain the corresponding cause when available.
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

/// One rule-match or engine-stop message of an [`AuditLog`].
#[derive(Debug, Clone, Default)]
pub struct AuditMessage {
    /// `SecComponentSignature`s, space-separated
    pub actionset: String,
    /// The expanded rule or engine-stop message for part `K`; empty when `K` is not selected. Part `H` carries its
    /// visible text in [`AuditMessage::error_message`], with an H-only compact identity in `rule_message`.
    pub message: String,
    /// The rule-match or engine-stop error log line, with part `H`.
    pub error_message: String,
    /// The rule-match or synthetic engine-stop data.
    pub data: AuditMessageData,
    /// The id behind this message, which bounded formatting uses to keep the interrupting item. Engine stops use
    /// `0`. It is never written out, and it is set even when `data` is not (part `H` without `K`).
    #[doc(hidden)]
    pub rule_id: i32,
    /// Compact identity retained for bounded audit formatting. A real rule with `H` but not `K` stores its first
    /// expanded `msg`; explicitly marked engine events keep their visible state-prefixed identity here. Reduced H-only
    /// JSON writes that identity in `error_message`; selected K data remains in `data.raw` and `data.msg`.
    #[doc(hidden)]
    pub rule_message: String,
    /// Typed provenance for synthetic engine records. Unmarked messages are ordinary, regardless of their text.
    #[doc(hidden)]
    pub provenance: Option<AuditMessageProvenance>,
}

/// Typed classification for engine-generated audit messages.
///
/// This public marker is forgeable by trusted in-process callers; it is not an authenticity boundary.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditMessageProvenance {
    /// An individual engine stop; `enforced` means it caused the enforced interruption.
    EngineEvent { enforced: bool },
    /// The aggregate for stops beyond the individual detail cap.
    EventsOmitted { enforced_stop_omitted: bool },
}

impl AuditMessage {
    /// A visible engine state label; `max_bytes` bounds parsing to the remaining copy budget.
    fn engine_state_tag(&self, max_bytes: usize) -> Option<&str> {
        const ENGINE_TAG_PREFIX: &str = "coraza-rs/engine/";
        match self.provenance? {
            AuditMessageProvenance::EventsOmitted { .. } => self
                .rule_message
                .strip_prefix(ENGINE_EVENTS_OMITTED_TAG)
                .filter(|suffix| suffix.starts_with(": "))
                .map(|_| ENGINE_EVENTS_OMITTED_TAG),
            AuditMessageProvenance::EngineEvent { .. } => {
                let identity = self.rule_message.strip_prefix(ENGINE_TAG_PREFIX)?;
                let prefix_end = utf8_boundary(identity, max_bytes);
                let (state, _) = identity.get(..prefix_end)?.split_once(": ")?;
                if state.is_empty() {
                    return None;
                }
                let tag_end = ENGINE_TAG_PREFIX.len().checked_add(state.len())?;
                self.rule_message.get(..tag_end)
            },
        }
    }

    /// The visible content for an explicitly marked synthetic event.
    fn engine_identity(&self) -> Option<&str> {
        self.is_engine_event()
            .then_some(self.rule_message.as_str())
            .filter(|identity| !identity.is_empty())
    }

    /// Whether this message came from a synthetic engine stop, not a real ID-0 rule.
    fn is_engine_event(&self) -> bool {
        self.provenance.is_some()
    }

    /// Whether this synthetic event is the bounded aggregate of excess engine stops.
    fn is_events_omitted_summary(&self) -> bool {
        matches!(self.provenance, Some(AuditMessageProvenance::EventsOmitted { .. }))
    }

    /// Whether this retained engine event's disruptive action actually interrupted the transaction.
    fn is_enforced_engine_event(&self) -> bool {
        matches!(
            self.provenance,
            Some(AuditMessageProvenance::EngineEvent { enforced: true })
        )
    }

    /// Whether an omitted engine detail, rather than one of the retained events, enforced the stop.
    fn is_enforced_stop_omitted_summary(&self) -> bool {
        matches!(
            self.provenance,
            Some(AuditMessageProvenance::EventsOmitted {
                enforced_stop_omitted: true
            })
        )
    }
}

/// The rule-match or engine-stop data behind an [`AuditMessage`].
#[derive(Debug, Clone, Default)]
pub struct AuditMessageData {
    /// The rule's file
    pub file: String,
    /// The rule's line
    pub line: usize,
    /// The rule's id, or `0` for an engine stop.
    pub id: i32,
    /// The rule's `rev`
    pub rev: String,
    /// The expanded rule or engine-stop message for part `K`; empty when `K` is not selected. For H-only entries,
    /// see [`AuditMessage::error_message`] and `rule_message`.
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
    /// The rule's tags; synthetic engine stops retain their state tag even without part `K`. An enforced event adds
    /// `coraza-rs/engine/Enforced`, or `coraza-rs/engine/EnforcedStopOmitted` when its detail was summarized.
    pub tags: Vec<String>,
    /// The rule's directives, its chain's included; engine stops use their state label even without part `K`.
    pub raw: String,
}

#[derive(Debug, Clone)]
/// A logged rule match or synthetic engine stop recorded for connector logs and audit entries.
pub struct MatchedRule {
    /// The rule as compiled; its raw text includes all chain links, or synthetic engine-stop metadata.
    pub rule: RuleMetadata,
    /// Values matched by the rule and its chain, or one engine-stop message.
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
    /// Transaction identifier. Normal rule matches keep the caller's full ID; synthetic engine events copy at most
    /// 128 bytes and suffix overlong IDs with `...`.
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
    /// The first expanded rule or engine-stop message, or an empty string when none was set.
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

    /// The rule ID, or `0` for an engine-originated stop.
    pub fn rule_id(&self) -> i32 {
        self.rule.id
    }

    /// The configured rule severity, or `CRITICAL` for an engine-originated stop.
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

    /// Format this rule match or engine stop as a Coraza-compatible error log line.
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

/// Callback used to emit rules with the `log` action and retained engine events/summaries.
#[derive(Clone)]
pub(crate) struct ErrorLog(Arc<ErrorLogCallback>);

/// Thread-safe callback invoked for each matching logged rule and retained engine event or summary.
type ErrorLogCallback = dyn Fn(&MatchedRule) + Send + Sync;

impl ErrorLog {
    /// Wrap a callback for sharing across transactions.
    pub(crate) fn new(log: impl Fn(&MatchedRule) + Send + Sync + 'static) -> Self {
        Self(Arc::new(log))
    }

    /// Invoke the callback for a logged rule match, retained engine event, or overflow summary.
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
    /// then is cut at `max_bytes`. Its final hard-cut does not pin H/K message lines, so it does not guarantee
    /// that any such line survives.
    ///
    /// The JSON formats are never cut mid-token: the output is always one valid JSON document of at most
    /// `max_bytes` bytes, carrying the same data as [`AuditLog::format`] when that fits (the bytes can differ:
    /// DEL and the C1 controls, which `format` leaves raw, are escaped here, and OCSF's `logged_time` is read
    /// again at each call), and otherwise reduced and marked
    /// with `"truncated": true` (`JSON` and `JSONLegacy`) or `"unmapped": {"truncated": true}` (OCSF). Their
    /// copy is bounded by `max_bytes` too, whatever the entry holds: text, and entries at most half as many as
    /// bytes, since an entry takes at least three bytes of output. Reduction keeps what an investigation needs
    /// first: logged rule matches and engine events, with their ids and messages, outlast the request's headers,
    /// URI and bodies. The enforced interruption's matching message is pinned when present. For ID-zero engine stops,
    /// typed `AuditMessage::provenance` pins an enforced event; when the enforcing detail fell beyond the 16-event cap,
    /// the typed `EventsOmitted` summary is pinned instead and explicitly reports that the enforcing detail was
    /// omitted. The summary is not itself presented as the cause. A host-operator refusal can keep its nonzero source
    /// rule ID; its typed enforcing event or omission summary is pinned ahead of even an audited same-ID source-rule
    /// message. If no marked cause is available, a nonzero
    /// interruption ID first uses its last matching audited message, then the existing first-engine-event fallback,
    /// then the last message.
    /// With no enforced ID, the previous fallback is preserved: the last non-synthetic rule message, or the first
    /// engine event when there are no rule messages. When a different message is pinned, the `EventsOmitted` count is
    /// next priority when a second message fits, including after compacting the producer; if only one fits, the pinned
    /// message wins. `DetectionOnly` keeps `interruption_rule_id` as `None`, so this record cannot identify an exact
    /// would-be rule when that differs from the fallback. Reduced JSON and JSONLegacy engine identities preserve the
    /// complete state prefix while shortening ordinary descriptions; if the prefix itself cannot fit, the event is
    /// omitted. An omission summary keeps its full count and enforcement clause when they fit, otherwise it uses the
    /// fixed text `additional engine stop details omitted` or is omitted. Native part-K summary copies apply the same
    /// all-or-fixed-text rule before their separate final hard cut; the summary's part-H error line is copied whole or
    /// omitted.
    /// Compact JSON-family formatting retries the complete summary, then that fixed text, before dropping it. OCSF has
    /// no `error_message`; H-only OCSF uses `enrichments[].name` for its visible identity. A retained reduced H-only
    /// OCSF engine event keeps its complete state-and-delimiter prefix there; if that prefix does not fit, the event
    /// is omitted rather than emitted without a name. When `K` is selected, JSON and OCSF give the complete state
    /// label in `data.raw` priority; synthetic `data.tags` entries are copied whole or omitted. With both `H` and `K`,
    /// JSON retains the compact H identity when its complete state fits too.
    /// H-only JSON and H-only OCSF formatter copies do not charge for, or serialize, synthetic `data.tags` and
    /// `data.raw`; `JSONLegacy` uses visible message text and has no structured tags. Other event details may be
    /// omitted or their text identity may be shortened.
    /// Consumers should check the returned truncation flag or serialized marker and inspect visible identity text,
    /// rather than infer event absence from missing tags. Native's final hard-cut does not carry this pinning
    /// guarantee. A document too small for even the marker (31 bytes for OCSF, 18 for the others) is empty and carries
    /// no messages. Control characters are escaped, so the output is one line.
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
    /// arguments), then the text each message may keep, then the number of messages. The existing pinned
    /// evidence wins, including a typed enforcing event or omission summary over an earlier same-ID source rule;
    /// when a second message fits, the `EventsOmitted` count is kept before other messages. With no enforced ID, the
    /// last real rule message is pinned, or the first engine event if no rule message exists. At the compact fallback,
    /// the formatter tries the pinned evidence with the full summary, then with its fixed omission text, then the
    /// pinned evidence alone; one that cannot fit even then becomes a bare marker. The result is reported cut only
    /// when content was reduced.
    #[expect(
        clippy::too_many_lines,
        reason = "Retries keep marker, cause, and omitted-summary priorities under one byte limit."
    )]
    fn format_json_bounded(&self, format: AuditLogFormat, max_bytes: usize) -> (String, bool) {
        /// The smallest text each message keeps before messages themselves are dropped.
        const MIN_MESSAGE_BYTES: usize = 32;

        let total = self.messages.len();
        let mut plan = AuditShrinkPlan {
            request_bytes: max_bytes,
            message_bytes: max_bytes,
            message_each: None,
            summary_each: None,
            // Every message is at least three bytes of output, so a record that fits holds fewer than this.
            message_count: total.min(AuditCopyBudget::generous(max_bytes).items_left),
            reduced: false,
        };
        let mut shrunk = false;
        let render = |view: &AuditLog, truncated| {
            let mut document = match format {
                AuditLogFormat::JsonLegacy => view.json_legacy(),
                AuditLogFormat::Ocsf => view.ocsf(),
                _ => view.json(),
            };
            if truncated {
                mark_truncated(&mut document, format);
            }
            escape_json_controls(&document.to_string())
        };
        let try_compact_plan = |compact_plan: AuditShrinkPlan, expected_messages: Option<usize>| {
            let mut budget = AuditCopyBudget::generous(max_bytes);
            let view = self.bounded_copy_planned(format, &mut budget, Some(compact_plan), AuditCompaction::Compact);
            if expected_messages.is_some_and(|expected| view.messages.len() != expected) {
                return None;
            }
            let compact = render(&view, true);
            (compact.len() <= max_bytes).then_some(compact)
        };
        let summary_floor_for = |index: usize| {
            self.messages.get(index).and_then(|message| {
                reduced_summary_fallback_bytes(
                    message,
                    format,
                    self.parts.contains(&AuditLogPart::RulesMatched),
                    max_bytes,
                )
            })
        };
        loop {
            let mut budget = AuditCopyBudget::generous(max_bytes);
            let view = self.bounded_copy_planned(format, &mut budget, Some(plan), AuditCompaction::Full);
            let retained_messages = view.messages.len();
            let truncated = shrunk || budget.truncated;
            let text = render(&view, truncated);
            if text.len() <= max_bytes {
                if truncated
                    && retained_messages == 1
                    && total > 1
                    && let Some(summary_index) = self.messages.iter().position(AuditMessage::is_events_omitted_summary)
                    && Some(summary_index)
                        != AuditCopyBudget::pinned_message_index(&self.messages, self.transaction.interruption_rule_id)
                {
                    let mut pair_plan = plan;
                    pair_plan.request_bytes = 0;
                    pair_plan.message_count = 2;
                    pair_plan.reduced = true;

                    let compact_pair = |pair_plan| try_compact_plan(pair_plan, Some(2));

                    if let Some(pair) = compact_pair(pair_plan) {
                        return (pair, true);
                    }

                    if let Some(summary_each) = summary_floor_for(summary_index) {
                        pair_plan.summary_each = Some(summary_each);
                        if let Some(pair) = compact_pair(pair_plan) {
                            return (pair, true);
                        }
                    }
                }
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
                // Drop metadata, then retry the cause with its summary before falling back to the cause alone.
                let summary_index = self.messages.iter().position(AuditMessage::is_events_omitted_summary);
                let keep_summary = total > 1 && summary_index.is_some();
                let compact_counts = if keep_summary { [2, 1] } else { [1, 0] };
                let pinned =
                    AuditCopyBudget::pinned_message_index(&self.messages, self.transaction.interruption_rule_id);
                let shrink_engine_identity = (format == AuditLogFormat::JsonLegacy
                    || (format == AuditLogFormat::Json
                        && self.parts.contains(&AuditLogPart::Trailer)
                        && !self.parts.contains(&AuditLogPart::RulesMatched)))
                    && pinned
                        .and_then(|index| self.messages.get(index))
                        .is_some_and(AuditMessage::is_engine_event);
                let shrink_summary = summary_index.is_some();
                let summary_fallback_bytes = summary_index.and_then(summary_floor_for);
                let identity_prefix_bytes = pinned
                    .and_then(|index| self.messages.get(index))
                    .filter(|_| shrink_engine_identity)
                    .and_then(|message| reduced_engine_identity_prefix_bytes(message, max_bytes));
                let shrink_compact_message = shrink_engine_identity || shrink_summary;
                for message_count in compact_counts {
                    if message_count == 0 {
                        break;
                    }
                    let mut message_each = None;
                    loop {
                        let mut compact_plan = plan;
                        compact_plan.message_count = message_count;
                        if shrink_engine_identity {
                            compact_plan.message_each = message_each;
                        }
                        if shrink_summary {
                            compact_plan.summary_each = message_each;
                        }
                        if let Some(compact) = try_compact_plan(compact_plan, None) {
                            return (compact, true);
                        }
                        if !shrink_compact_message {
                            break;
                        }
                        let summary_selected =
                            summary_index.is_some_and(|index| message_count > 1 || Some(index) == pinned);
                        let minimum_message_each = if summary_selected {
                            summary_fallback_bytes.or(identity_prefix_bytes)
                        } else {
                            identity_prefix_bytes
                        };
                        let Some(minimum_message_each) = minimum_message_each else {
                            break;
                        };
                        let current = message_each.unwrap_or_else(|| max_bytes / message_count.max(1));
                        if current <= minimum_message_each {
                            break;
                        }
                        let next = (current / 2).max(minimum_message_each);
                        if next == current {
                            break;
                        }
                        message_each = Some(next);
                    }
                }
                let minimal = bare_truncation_marker(format);
                let fits = minimal.len() <= max_bytes;
                return (if fits { minimal.to_owned() } else { String::new() }, true);
            }
        }
    }

    /// Copies only the fields used by `format`, within `budget`.
    fn bounded_copy(&self, format: AuditLogFormat, budget: &mut AuditCopyBudget) -> Self {
        self.bounded_copy_planned(format, budget, None, AuditCompaction::Full)
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
        compaction: AuditCompaction,
    ) -> Self {
        let compact = compaction == AuditCompaction::Compact;
        let mut request_pool = plan.map(|plan| AuditCopyBudget::generous(plan.request_bytes));
        let native = format == AuditLogFormat::Native;
        let native_headers = native && self.parts.contains(&AuditLogPart::RequestHeaders);
        let native_request_body = native && self.parts.contains(&AuditLogPart::RequestBody);
        let native_response_headers = native && self.parts.contains(&AuditLogPart::ResponseHeaders);
        let native_response_body = native && self.parts.contains(&AuditLogPart::IntermediaryResponseBody);
        let native_files = native && self.parts.contains(&AuditLogPart::UploadedFiles);
        let native_trailer = native && self.parts.contains(&AuditLogPart::Trailer);
        let rules_selected = self.parts.contains(&AuditLogPart::RulesMatched);
        let native_rules = native && rules_selected;
        let native_header = native && self.parts.contains(&AuditLogPart::Header);
        let parts = if native {
            budget.sequence(&self.parts, |_, part| *part)
        } else if rules_selected {
            vec![AuditLogPart::RulesMatched]
        } else {
            Vec::new()
        };

        let json = format == AuditLogFormat::Json;
        let legacy = format == AuditLogFormat::JsonLegacy;
        let ocsf = format == AuditLogFormat::Ocsf;
        let transaction = &self.transaction;
        let timestamp = if !compact && (json || legacy || native_header) {
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
        let client_ip = if !compact && (json || legacy || ocsf || native_header) {
            budget.string(&transaction.client_ip)
        } else {
            String::new()
        };
        let client_port = transaction.client_port;
        let host_ip = if !compact && (json || legacy || ocsf || native_header) {
            budget.string(&transaction.host_ip)
        } else {
            String::new()
        };
        let host_port = transaction.host_port;
        let server_id = if !compact && (json || ocsf) {
            budget.string(&transaction.server_id)
        } else {
            String::new()
        };
        let highest_severity = if !compact && (json || ocsf) {
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
        let bounded_request = if compact {
            AuditRequest::default()
        } else {
            AuditRequest {
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
            }
        };

        let response = (!compact)
            .then_some(transaction.response.as_ref())
            .flatten()
            .map(|response| AuditResponse {
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

        let producer = if !compact && (json || legacy || ocsf) {
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
            budget.planned_messages(
                &self.messages,
                message_mode,
                plan,
                AuditMessageSelection {
                    interruption_rule_id: transaction.interruption_rule_id,
                    trailer_selected: self.parts.contains(&AuditLogPart::Trailer),
                    rules_selected,
                    compaction,
                },
            )
        } else {
            let mut mode = message_mode;
            budget.sequence(&self.messages, |budget, message| {
                let copied = budget.message(message, mode, rules_selected);
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
                        if message.is_events_omitted_summary()
                            && message.data.raw == ENGINE_EVENTS_OMITTED_TAG
                            && !message.data.msg.is_empty()
                        {
                            out.push_str(": ");
                            out.push_str(&escape(&message.data.msg));
                        }
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
                    let include_engine_state =
                        self.parts.contains(&AuditLogPart::RulesMatched) || !message.is_engine_event();
                    json!({
                        "actionset": message.actionset,
                        "message": message.message,
                        "error_message": message.error_message,
                        "data": message_data_json(data, include_engine_state),
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
                "data": message_data_json(
                    &message.data,
                    self.parts.contains(&AuditLogPart::RulesMatched) || !message.is_engine_event(),
                )
                .to_string(),
                "name": message
                    .engine_identity()
                    .filter(|_| message.data.msg.is_empty())
                    .unwrap_or(&message.data.msg),
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

        let messages: Vec<&str> = self
            .messages
            .iter()
            .map(|message| message.engine_identity().unwrap_or(&message.message))
            .collect();
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
fn message_data_json(data: &AuditMessageData, include_engine_state: bool) -> Value {
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
        "tags": if include_engine_state { data.tags.as_slice() } else { &[] },
        "raw": if include_engine_state { data.raw.as_str() } else { "" },
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
        /// Copy rule text or a synthetic engine-stop label for part K.
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
    /// Text bytes the compact retry gives an omission summary; `None` first tries its full text.
    summary_each: Option<usize>,
    /// Messages kept: the enforced interruption's message or compatible fallback, then the overflow summary when
    /// another slot fits, then the first remaining messages.
    message_count: usize,
    /// Whether an earlier attempt overflowed, so this one is reduced in some way: a record that fits whole is
    /// left as it is, and only a reduced one gets its pinned rule or engine event's identity written compactly.
    reduced: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// Whether a bounded formatter copies metadata before or after compacting its view.
enum AuditCompaction {
    /// Keep fields through the first bounded formatting attempt.
    Full,
    /// Omit producer/request metadata before copying the selected message.
    Compact,
}

/// Selection semantics needed while retaining messages from a reduced record.
#[derive(Clone, Copy)]
struct AuditMessageSelection {
    /// Public audit interruption ID used to pin the existing cause.
    interruption_rule_id: Option<i32>,
    /// Whether part H is selected for synthetic compact JSON identity; real-rule fallback stays part of the baseline.
    trailer_selected: bool,
    /// Whether part K is selected for structured synthetic identity.
    rules_selected: bool,
    /// Whether the bounded view drops producer/request metadata before formatting.
    compaction: AuditCompaction,
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

    /// Copies a complete identity field or omits it, never leaving a partial label.
    fn complete_string(&mut self, value: &str) -> String {
        if value.len() > self.bytes_left {
            self.truncated = true;
            String::new()
        } else {
            self.string(value)
        }
    }

    /// Copies a whole omission summary, or a fixed statement that withholds its exact count.
    fn summary_text(&mut self, message: &AuditMessage, value: &str) -> String {
        if !message.is_events_omitted_summary() || value.len() <= self.bytes_left {
            return self.string(value);
        }
        self.truncated = true;
        self.complete_string(ENGINE_EVENTS_OMITTED_FALLBACK)
    }

    /// Copies a synthetic event's identity without cutting its complete state-and-delimiter prefix.
    fn state_first_engine_identity(&mut self, message: &AuditMessage) -> String {
        let Some(identity) = message.engine_identity() else {
            return String::new();
        };
        let Some(state) = message.engine_state_tag(self.bytes_left) else {
            if message.is_events_omitted_summary() && identity.len() > self.bytes_left {
                self.truncated = true;
                return self.complete_string(ENGINE_EVENTS_OMITTED_FALLBACK);
            }
            return self.complete_string(identity);
        };
        let prefix_len = state.len().saturating_add(2);
        let Some(prefix) = identity.get(..prefix_len) else {
            self.truncated = true;
            return String::new();
        };
        if message.is_events_omitted_summary() {
            if identity.len() <= self.bytes_left {
                return self.string(identity);
            }
            self.truncated = true;
            let required = prefix.len().saturating_add(ENGINE_EVENTS_OMITTED_FALLBACK.len());
            if required > self.bytes_left {
                return String::new();
            }
            let mut copied = self.string(prefix);
            copied.push_str(&self.string(ENGINE_EVENTS_OMITTED_FALLBACK));
            return copied;
        }
        let mut copied = self.complete_string(prefix);
        if !copied.is_empty() {
            copied.push_str(&self.string(identity.get(prefix_len..).unwrap_or_default()));
        }
        copied
    }

    /// Copies a compact engine identity without cutting its state prefix.
    fn compact_engine_identity(&mut self, message: &AuditMessage) -> String {
        let Some((identity, shortened)) = reduced_engine_identity(message, self.bytes_left) else {
            self.truncated = true;
            return String::new();
        };
        self.truncated |= shortened;
        self.string(&identity)
    }

    /// Reserves the synthetic state label before copying descriptive message text.
    fn engine_state_fields(&mut self, message: &AuditMessage, compaction: AuditCompaction) -> (Vec<String>, String) {
        let Some(state) = message.engine_state_tag(self.bytes_left) else {
            return (Vec::new(), String::new());
        };
        let raw = if message.data.raw == state {
            self.complete_string(state)
        } else {
            if !message.data.raw.is_empty() {
                self.truncated = true;
            }
            String::new()
        };
        if compaction == AuditCompaction::Compact {
            return (Vec::new(), raw);
        }
        let mut tags = Vec::new();
        match message.data.tags.first() {
            Some(tag) if tag == state && tag.len() <= self.bytes_left && self.items_left > 0 => {
                self.item_count(1);
                tags.push(self.string(tag));
            },
            Some(tag) if tag == state || !tag.is_empty() => self.truncated = true,
            _ => {},
        }
        if !tags.is_empty()
            && let Some(tag) = message
                .data
                .tags
                .get(1)
                .filter(|tag| tag.as_str() == ENGINE_ENFORCED_TAG || tag.as_str() == ENGINE_ENFORCED_OMITTED_TAG)
        {
            if tag.len() <= self.bytes_left && self.items_left > 0 {
                self.item_count(1);
                tags.push(self.string(tag));
            } else {
                self.truncated = true;
            }
        }
        (tags, raw)
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

    /// Chooses the message to pin before copying: enforced ID, or the compatible no-ID fallback.
    fn pinned_message_index(messages: &[AuditMessage], interrupting: Option<i32>) -> Option<usize> {
        let pinned = match interrupting {
            Some(0) => messages
                .iter()
                .position(AuditMessage::is_enforced_engine_event)
                .or_else(|| messages.iter().position(AuditMessage::is_enforced_stop_omitted_summary))
                // Preserve the historical fallback for caller-built/legacy ID-zero messages.
                .or_else(|| messages.iter().position(AuditMessage::is_engine_event))
                .or_else(|| {
                    messages
                        .iter()
                        .rposition(|message| message.rule_id == 0 || message.data.id == 0)
                }),
            Some(id) => messages
                .iter()
                .position(AuditMessage::is_enforced_engine_event)
                .or_else(|| messages.iter().position(AuditMessage::is_enforced_stop_omitted_summary))
                .or_else(|| {
                    messages
                        .iter()
                        .rposition(|message| message.rule_id == id || message.data.id == id)
                })
                // Preserve engine-stop context; it does not identify the interrupted rule.
                .or_else(|| messages.iter().position(AuditMessage::is_engine_event)),
            None => messages
                .iter()
                .rposition(|message| !message.is_engine_event())
                .or_else(|| messages.iter().position(AuditMessage::is_engine_event)),
        };
        pinned.or_else(|| messages.len().checked_sub(1))
    }

    /// Copies the messages `plan` keeps out of one shared pool.
    ///
    /// Only kept messages are copied. The enforced ID or compatible no-ID fallback stays first priority; the
    /// `EventsOmitted` summary is retained next when another message fits, before the first remaining messages.
    /// Without an enforced ID, the fallback remains the last real rule message, or the first engine event when no
    /// rule messages exist. `DetectionOnly` has no public would-be ID, so the exact would-be rule cannot be promised.
    /// Native does not run this plan and uses its separate final hard-cut.
    #[expect(
        clippy::too_many_lines,
        reason = "The bounded selection keeps cause, summary, budgets, and chronological order coordinated."
    )]
    fn planned_messages(
        &mut self,
        messages: &[AuditMessage],
        mode: AuditMessageCopy,
        plan: AuditShrinkPlan,
        selection: AuditMessageSelection,
    ) -> Vec<AuditMessage> {
        let kept = plan.message_count.min(messages.len());
        if kept < messages.len() {
            self.truncated = true;
        }
        let pinned = Self::pinned_message_index(messages, selection.interruption_rule_id).filter(|_| kept > 0);
        let summary = if kept > 1 {
            messages
                .iter()
                .position(AuditMessage::is_events_omitted_summary)
                .filter(|index| Some(*index) != pinned)
        } else {
            None
        };
        let mut selected = Vec::with_capacity(kept);
        if let Some(index) = pinned {
            selected.push(index);
        }
        if let Some(index) = summary {
            selected.push(index);
        }
        for index in 0..messages.len() {
            if Some(index) == pinned || Some(index) == summary {
                continue;
            }
            if selected.len() >= kept {
                break;
            }
            selected.push(index);
        }

        let first = selected.iter().copied().min();
        let mut pool = Self::generous(plan.message_bytes);
        let reduced = plan.reduced;
        let mut copy_one =
            |index: usize| {
                let message = messages.get(index)?;
                let before = pool.bytes_left;
                let copy_mode = if Some(index) == first { mode } else { mode.after_first() };
                let h_only_ocsf_engine = selection.trailer_selected
                    && !selection.rules_selected
                    && matches!(copy_mode, AuditMessageCopy::Ocsf | AuditMessageCopy::OcsfEnrichment)
                    && message.data.msg.is_empty()
                    && message.is_engine_event();
                let h_only_json_engine = selection.trailer_selected
                    && !selection.rules_selected
                    && copy_mode == AuditMessageCopy::Json
                    && message.is_engine_event();
                let legacy_engine = copy_mode == AuditMessageCopy::Legacy && message.is_engine_event();
                let identity_prefix_len = message
                    .engine_state_tag(before)
                    .map_or(0, |state| state.len().saturating_add(2));
                let identity_floor = if message.is_events_omitted_summary() {
                    identity_prefix_len.saturating_add(ENGINE_EVENTS_OMITTED_FALLBACK.len())
                } else {
                    identity_prefix_len
                };
                let compact_identity_prefix_bytes = if (h_only_json_engine || legacy_engine) && reduced {
                    reduced_engine_identity_prefix_bytes(message, before)
                } else {
                    None
                };
                let identity_bytes_before = message.engine_identity().map_or(0, str::len).saturating_add(
                    message
                        .data
                        .data
                        .len()
                        .saturating_add(if copy_mode == AuditMessageCopy::Ocsf {
                            message.message.len()
                        } else {
                            0
                        }),
                );
                let compact_h_ocsf_identity = h_only_ocsf_engine && (reduced || identity_bytes_before > before);
                let compact_h_json_identity = h_only_json_engine && reduced;
                let compact_h_legacy_identity = legacy_engine && reduced;
                let compact_h_text_identity = compact_h_json_identity || compact_h_legacy_identity;
                // The omission count gets the remaining text pool before ordinary detail.
                let compact_summary =
                    selection.compaction == AuditCompaction::Compact && message.is_events_omitted_summary();
                let allowance = if compact_summary {
                    match plan.summary_each {
                        None => usize::MAX,
                        Some(each) if compact_h_ocsf_identity => each.max(identity_floor),
                        Some(each) if compact_h_text_identity => each.max(compact_identity_prefix_bytes.unwrap_or(0)),
                        Some(each) => each,
                    }
                } else if Some(index) == summary {
                    usize::MAX
                } else if compact_h_ocsf_identity {
                    plan.message_each
                        .unwrap_or_else(|| before / kept.max(1))
                        .max(identity_floor)
                } else if compact_h_text_identity {
                    plan.message_each
                        .unwrap_or_else(|| before / kept.max(1))
                        .max(compact_identity_prefix_bytes.unwrap_or(0))
                } else if Some(index) == pinned && message.is_engine_event() {
                    usize::MAX
                } else {
                    plan.message_each.unwrap_or(usize::MAX)
                };
                pool.bytes_left = before.min(allowance);
                let allowed = pool.bytes_left;
                if compact_h_ocsf_identity && pool.bytes_left < identity_prefix_len {
                    pool.truncated = true;
                    return None;
                }
                if compact_h_text_identity && compact_identity_prefix_bytes.is_none() {
                    pool.truncated = true;
                    return None;
                }
                if compact_h_legacy_identity && pool.bytes_left < identity_prefix_len {
                    pool.truncated = true;
                    return None;
                }
                let compact_h_identity = reduced
                    && mode == AuditMessageCopy::Json
                    && selection.trailer_selected
                    && message.is_engine_event();
                let unlabeled_ocsf_k_summary = reduced
                    && selection.rules_selected
                    && matches!(copy_mode, AuditMessageCopy::Ocsf | AuditMessageCopy::OcsfEnrichment)
                    && message.is_events_omitted_summary()
                    && message.data.msg.is_empty()
                    && message.engine_state_tag(before).is_none();
                let copy = if !unlabeled_ocsf_k_summary
                    && ((reduced && (Some(index) == pinned || compact_h_identity || compact_h_legacy_identity))
                        || compact_h_ocsf_identity)
                {
                    pool.pinned_message_with_compaction(message, copy_mode, selection)
                } else {
                    pool.message_with_state_priority(message, copy_mode, selection, reduced)
                };
                pool.bytes_left = before - (allowed - pool.bytes_left);
                if (compact_h_json_identity && copy.error_message.is_empty())
                    || (h_only_json_engine && message.is_events_omitted_summary() && copy.error_message.is_empty())
                    || (compact_h_legacy_identity && copy.message.is_empty())
                    || (legacy_engine && message.is_events_omitted_summary() && copy.message.is_empty())
                    || (compact_h_ocsf_identity && copy.rule_message.is_empty())
                    || (reduced
                        && selection.rules_selected
                        && matches!(copy_mode, AuditMessageCopy::Ocsf | AuditMessageCopy::OcsfEnrichment)
                        && message.is_events_omitted_summary()
                        && copy.data.msg.is_empty()
                        && copy.rule_message.is_empty())
                {
                    pool.truncated = true;
                    return None;
                }
                Some(copy)
            };
        let mut copied = Vec::with_capacity(selected.len());
        for index in selected {
            if let Some(copy) = copy_one(index) {
                copied.push((index, copy));
            }
        }
        copied.sort_unstable_by_key(|(index, _)| *index);
        let out = copied.into_iter().map(|(_, message)| message).collect();
        self.truncated |= pool.truncated;
        self.bytes_used += pool.bytes_used;
        self.items_used += pool.items_used;
        out
    }

    /// Copies a reduced message's compact identity, so that it still names its rule or engine state.
    ///
    /// H-only JSON carries a real rule inside its error log text, behind a prefix that a tight allowance spends
    /// before the rule's `id` and `msg`; `JSONLegacy` and OCSF do not write that text. This compact fallback remains
    /// part of the baseline JSON behavior even when H is not selected. A reduced synthetic event writes its
    /// state-first identity to the selected H/K view without copying the hidden `rule_message` prefix. H-only JSON
    /// and `JSONLegacy` keep the full state prefix and shorten only its description; if the prefix itself cannot fit,
    /// the event is omitted. H-only JSON and OCSF omit the event's unselected K tags/raw; H-only OCSF preserves a
    /// complete state prefix in the name or omits the event if it cannot fit. K-selected JSON keeps the raw label and
    /// message when space permits.
    /// Pinned-message copy with collections omitted when the caller will compact the resulting view.
    #[expect(
        clippy::too_many_lines,
        reason = "The reduced identity fields differ by format but share one bounded-copy budget."
    )]
    fn pinned_message_with_compaction(
        &mut self,
        message: &AuditMessage,
        mode: AuditMessageCopy,
        selection: AuditMessageSelection,
    ) -> AuditMessage {
        let trailer_selected = selection.trailer_selected;
        let rules_selected = selection.rules_selected;
        let engine_event = message.is_engine_event();
        let original_limit = self.bytes_left;
        let identity_missing = message.rule_id != 0
            && message.data.id == 0
            && message.data.msg.is_empty()
            && message.message.is_empty()
            && message.data.data.is_empty();
        let needs_identity = match mode {
            AuditMessageCopy::Json => {
                (!engine_event && message.error_message.len() > original_limit)
                    || (engine_event && (trailer_selected || rules_selected))
            },
            AuditMessageCopy::Legacy | AuditMessageCopy::Ocsf | AuditMessageCopy::OcsfEnrichment => true,
            AuditMessageCopy::None | AuditMessageCopy::Native { .. } => false,
        };
        if !needs_identity || (!identity_missing && !engine_event) {
            return self.message_with_state_priority(message, mode, selection, false);
        }
        #[cfg(test)]
        MESSAGES_COPIED.with(|copied| copied.set(copied.get() + 1));
        let mut copy = AuditMessage {
            rule_id: message.rule_id,
            provenance: message.provenance,
            ..AuditMessage::default()
        };
        if engine_event
            && matches!(
                mode,
                AuditMessageCopy::Json | AuditMessageCopy::Ocsf | AuditMessageCopy::OcsfEnrichment
            )
        {
            copy.data.severity = message.data.severity;
        }
        let identity = if engine_event {
            message.engine_identity().unwrap_or_default()
        } else {
            &message.rule_message
        };
        if engine_event
            && rules_selected
            && matches!(
                mode,
                AuditMessageCopy::Json | AuditMessageCopy::Ocsf | AuditMessageCopy::OcsfEnrichment
            )
        {
            (copy.data.tags, copy.data.raw) = self.engine_state_fields(message, selection.compaction);
        }
        if engine_event
            && !rules_selected
            && message.data.msg.is_empty()
            && matches!(mode, AuditMessageCopy::Ocsf | AuditMessageCopy::OcsfEnrichment)
        {
            copy.data.id = message.rule_id;
            copy.rule_message = self.state_first_engine_identity(message);
            return copy;
        }
        match mode {
            AuditMessageCopy::Json => {
                copy.data.id = message.rule_id;
                if trailer_selected || !engine_event {
                    if engine_event && trailer_selected && !rules_selected {
                        copy.error_message = self.compact_engine_identity(message);
                    } else {
                        let compact = if message.is_events_omitted_summary() {
                            reduced_engine_identity(message, self.bytes_left).map(|(compact, shortened)| {
                                self.truncated |= shortened;
                                compact
                            })
                        } else {
                            Some(reduced_identity(message.rule_id, identity, self.bytes_left))
                        };
                        if let Some(compact) = compact {
                            if !engine_event
                                || !rules_selected
                                || message
                                    .engine_state_tag(self.bytes_left)
                                    .is_some_and(|tag| compact.contains(tag))
                            {
                                copy.error_message = self.string(&compact);
                            } else {
                                self.truncated = true;
                            }
                        } else {
                            self.truncated = true;
                        }
                    }
                }
                if engine_event && rules_selected {
                    copy.data.msg = self.summary_text(message, &message.data.msg);
                }
            },
            AuditMessageCopy::Legacy => {
                if engine_event {
                    copy.message = self.compact_engine_identity(message);
                } else {
                    copy.message = self.string(&reduced_identity(message.rule_id, identity, self.bytes_left));
                }
            },
            _ => {
                // OCSF names a rule by its enrichment (`id` in the data, `msg` as the name); the first message's
                // text is written beside, and takes what the name leaves.
                copy.data.id = message.rule_id;
                let limit = self.bytes_left;
                if message.is_events_omitted_summary() && rules_selected {
                    let name = reduced_summary_identity(message, limit / 2);
                    if let Some((name, shortened)) = name {
                        self.truncated |= shortened;
                        copy.data.msg = self.complete_string(&name);
                    } else if copy.data.raw == message.engine_state_tag(limit).unwrap_or_default()
                        || copy
                            .data
                            .tags
                            .iter()
                            .any(|tag| Some(tag.as_str()) == message.engine_state_tag(limit))
                    {
                        copy.data.msg = self.summary_text(message, &message.data.msg);
                    } else {
                        self.truncated = true;
                    }
                } else {
                    let name = truncated(identity, limit / 2);
                    if engine_event
                        && rules_selected
                        && !message
                            .engine_state_tag(limit / 2)
                            .is_some_and(|tag| name.contains(tag))
                    {
                        copy.data.msg = self.summary_text(message, &message.data.msg);
                    } else {
                        copy.data.msg = self.string(name);
                    }
                }
                if mode == AuditMessageCopy::Ocsf {
                    if message.is_events_omitted_summary() {
                        copy.message = self.compact_engine_identity(message);
                    } else {
                        let compact = reduced_identity(message.rule_id, identity, self.bytes_left);
                        if engine_event
                            && rules_selected
                            && !message
                                .engine_state_tag(self.bytes_left)
                                .is_some_and(|tag| compact.contains(tag))
                        {
                            copy.message = self.summary_text(message, &message.message);
                        } else {
                            copy.message = self.string(&compact);
                        }
                    }
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
    fn message(&mut self, message: &AuditMessage, mode: AuditMessageCopy, rules_selected: bool) -> AuditMessage {
        self.message_with_state_priority(
            message,
            mode,
            AuditMessageSelection {
                interruption_rule_id: None,
                trailer_selected: false,
                rules_selected,
                compaction: AuditCompaction::Full,
            },
            false,
        )
    }

    /// Copies a message, giving a reduced synthetic event's selected K identity first claim on its text allowance.
    #[expect(
        clippy::too_many_lines,
        clippy::cognitive_complexity,
        reason = "Field copy order and summary evidence share one bounded budget across audit formats."
    )]
    fn message_with_state_priority(
        &mut self,
        message: &AuditMessage,
        mode: AuditMessageCopy,
        selection: AuditMessageSelection,
        reduced: bool,
    ) -> AuditMessage {
        let rules_selected = selection.rules_selected;
        let compact = selection.compaction == AuditCompaction::Compact;
        #[cfg(test)]
        MESSAGES_COPIED.with(|copied| copied.set(copied.get() + 1));
        let json = mode == AuditMessageCopy::Json;
        let legacy = mode == AuditMessageCopy::Legacy;
        let ocsf = matches!(mode, AuditMessageCopy::Ocsf | AuditMessageCopy::OcsfEnrichment);
        let engine_event = message.is_engine_event();
        let (native_error, native_raw) = match mode {
            AuditMessageCopy::Native { error, raw } => (error, raw),
            _ => (false, false),
        };
        let engine_identity = message.engine_identity();
        let native_summary = native_raw && message.is_events_omitted_summary();
        let include_engine_state = rules_selected || !engine_event;
        let all_data = json || ocsf;
        let data = &message.data;
        let reduced_ocsf_k_summary_needs_fallback = (reduced || compact)
            && ocsf
            && rules_selected
            && message.is_events_omitted_summary()
            && data.msg.is_empty()
            && message.engine_state_tag(self.bytes_left).is_none();
        let prioritize_engine_state = reduced && all_data && include_engine_state && engine_event;
        let (state_tags, state_raw) = if prioritize_engine_state {
            self.engine_state_fields(message, selection.compaction)
        } else {
            (Vec::new(), String::new())
        };
        // A tight allowance, which a message's text shares with its siblings, must cut the long and the
        // duplicated fields (the rule's `raw` text, its file, `message` repeating `data.msg`) before the
        // text that says what matched, so that is copied first.
        let msg = if reduced_ocsf_k_summary_needs_fallback {
            self.complete_string(ENGINE_EVENTS_OMITTED_FALLBACK)
        } else if all_data || native_summary {
            self.summary_text(message, &data.msg)
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
            if legacy && message.is_events_omitted_summary() {
                self.state_first_engine_identity(message)
            } else if message.is_events_omitted_summary() {
                self.summary_text(message, &message.message)
            } else {
                self.string(if legacy {
                    engine_identity.unwrap_or(&message.message)
                } else {
                    &message.message
                })
            }
        } else {
            String::new()
        };
        let rule_message = if native_summary {
            message
                .engine_state_tag(self.bytes_left)
                .and_then(|tag| message.rule_message.get(..tag.len().saturating_add(2)))
                .map_or_else(String::new, |prefix| self.string(prefix))
        } else if ocsf && data.msg.is_empty() && !reduced_ocsf_k_summary_needs_fallback {
            if message.is_events_omitted_summary() {
                self.state_first_engine_identity(message)
            } else {
                engine_identity.map_or_else(String::new, |identity| self.string(identity))
            }
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
        let tags = if all_data && include_engine_state {
            if prioritize_engine_state {
                state_tags
            } else if compact {
                Vec::new()
            } else {
                self.strings(&data.tags)
            }
        } else {
            Vec::new()
        };
        let actionset = if json {
            self.string(&message.actionset)
        } else {
            String::new()
        };
        let error_message = if json || native_error {
            if message.is_events_omitted_summary() {
                self.complete_string(&message.error_message)
            } else {
                self.string(&message.error_message)
            }
        } else {
            String::new()
        };
        let raw = if (all_data && include_engine_state) || native_raw {
            if prioritize_engine_state {
                state_raw
            } else if native_raw && engine_event {
                match message.engine_state_tag(self.bytes_left) {
                    Some(state) if data.raw.as_str() == state => self.complete_string(state),
                    _ => {
                        if !data.raw.is_empty() {
                            self.truncated = true;
                        }
                        String::new()
                    },
                }
            } else {
                self.string(&data.raw)
            }
        } else {
            String::new()
        };
        AuditMessage {
            actionset,
            message: text,
            error_message,
            rule_id: message.rule_id,
            rule_message,
            provenance: message.provenance,
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

/// The copy budget needed to retain an engine identity's state and, for a summary, its fixed omission statement.
///
/// Quoting is measured incrementally so a caller-built public audit record cannot make the formatter allocate an
/// unbounded prefix while checking a bounded view.
fn reduced_engine_identity_prefix_bytes(message: &AuditMessage, max_bytes: usize) -> Option<usize> {
    let Some(state) = message.engine_state_tag(max_bytes) else {
        if message.is_events_omitted_summary() {
            return Some(reduced_identity(message.rule_id, ENGINE_EVENTS_OMITTED_FALLBACK, max_bytes).len());
        }
        return reduced_engine_identity(message, max_bytes).map(|(identity, _)| identity.len());
    };
    let prefix_len = state.len().checked_add(2)?;
    let prefix = message.rule_message.get(..prefix_len)?;
    let overhead = format!("[id \"{}\"]", message.rule_id).len().saturating_add(9);
    let quote_limit = max_bytes.saturating_sub(overhead);
    let mut quoted_len = 0_usize;
    let mut quoted = String::new();
    let suffix = if message.is_events_omitted_summary() {
        ENGINE_EVENTS_OMITTED_FALLBACK
    } else {
        ""
    };
    for character in prefix.chars().chain(suffix.chars()) {
        quoted.clear();
        push_go_quoted(&mut quoted, character);
        quoted_len = quoted_len.saturating_add(quoted.len());
        if quoted_len > quote_limit {
            return None;
        }
    }
    Some(overhead.saturating_add(quoted_len))
}

/// The text budget needed for an omission summary's fixed fallback in a reduced format.
fn reduced_summary_fallback_bytes(
    message: &AuditMessage,
    format: AuditLogFormat,
    rules_selected: bool,
    max_bytes: usize,
) -> Option<usize> {
    let Some(state) = message.engine_state_tag(max_bytes) else {
        return Some(match (format, rules_selected) {
            (AuditLogFormat::Json, true) | (AuditLogFormat::Ocsf, _) => ENGINE_EVENTS_OMITTED_FALLBACK.len(),
            _ => reduced_engine_identity_prefix_bytes(message, max_bytes)?,
        });
    };
    Some(match (format, rules_selected) {
        (AuditLogFormat::Ocsf, false) => state
            .len()
            .saturating_add(2)
            .saturating_add(ENGINE_EVENTS_OMITTED_FALLBACK.len()),
        (AuditLogFormat::Json | AuditLogFormat::Ocsf, true) => {
            state.len().saturating_add(ENGINE_EVENTS_OMITTED_FALLBACK.len())
        },
        _ => reduced_engine_identity_prefix_bytes(message, max_bytes)?,
    })
}

/// A complete summary identity when it fits, or one fixed statement that withholds the exact count.
fn reduced_summary_identity(message: &AuditMessage, limit: usize) -> Option<(String, bool)> {
    if !message.is_events_omitted_summary() {
        return None;
    }
    let identity = message.engine_identity()?;
    if identity.len() <= limit {
        return Some((identity.to_owned(), false));
    }
    let Some(state) = message.engine_state_tag(limit) else {
        return Some((
            reduced_identity(message.rule_id, ENGINE_EVENTS_OMITTED_FALLBACK, limit),
            true,
        ));
    };
    let prefix_len = state.len().checked_add(2)?;
    let prefix = identity.get(..prefix_len)?;
    let fallback_len = prefix.len().saturating_add(ENGINE_EVENTS_OMITTED_FALLBACK.len());
    if fallback_len > limit {
        return None;
    }
    let mut fallback = String::with_capacity(fallback_len);
    fallback.push_str(prefix);
    fallback.push_str(ENGINE_EVENTS_OMITTED_FALLBACK);
    Some((fallback, true))
}

/// Quotes a complete value and suffix only when the complete encoding fits.
fn quoted_complete(value: &str, suffix: &str, limit: usize) -> Option<String> {
    let mut quoted = String::new();
    for character in value.chars().chain(suffix.chars()) {
        push_go_quoted(&mut quoted, character);
        if quoted.len() > limit {
            return None;
        }
    }
    Some(quoted)
}

/// Compact ID/message identity with a complete synthetic state prefix.
fn reduced_engine_identity(message: &AuditMessage, limit: usize) -> Option<(String, bool)> {
    let identity = message.engine_identity()?;
    let Some(state) = message.engine_state_tag(limit) else {
        if message.is_events_omitted_summary() {
            return Some((
                reduced_identity(message.rule_id, ENGINE_EVENTS_OMITTED_FALLBACK, limit),
                true,
            ));
        }
        let mut compact = format!("[id \"{}\"]", message.rule_id);
        let room = limit.saturating_sub(compact.len().saturating_add(9));
        compact.push_str(" [msg \"");
        compact.push_str(&quoted_complete(identity, "", room)?);
        compact.push_str("\"]");
        return Some((compact, false));
    };
    let prefix_len = state.len().checked_add(2)?;
    let prefix = identity.get(..prefix_len)?;
    let description = identity.get(prefix_len..)?;
    let mut compact = format!("[id \"{}\"]", message.rule_id);
    let room = limit.saturating_sub(compact.len().saturating_add(9));
    if message.is_events_omitted_summary() {
        let (quoted, shortened) = quoted_complete(identity, "", room)
            .map(|quoted| (quoted, false))
            .or_else(|| quoted_complete(prefix, ENGINE_EVENTS_OMITTED_FALLBACK, room).map(|quoted| (quoted, true)))?;
        compact.push_str(" [msg \"");
        compact.push_str(&quoted);
        compact.push_str("\"]");
        return Some((compact, shortened));
    }
    let mut quoted = String::new();
    for character in prefix.chars() {
        push_go_quoted(&mut quoted, character);
        if quoted.len() > room {
            return None;
        }
    }
    let mut shortened = false;
    for character in description.chars() {
        let before = quoted.len();
        push_go_quoted(&mut quoted, character);
        if quoted.len() > room {
            quoted.truncate(before);
            shortened = true;
            break;
        }
    }
    compact.push_str(" [msg \"");
    compact.push_str(&quoted);
    compact.push_str("\"]");
    Some((compact, shortened))
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

    /// Whether a `RelevantOnly` audit engine logs a transaction. A configured
    /// `SecAuditLogRelevantStatus` filter is authoritative; without one, only a transaction
    /// with an audited match is logged.
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
                let copy = budget.pinned_message_with_compaction(
                    &source,
                    mode,
                    super::AuditMessageSelection {
                        interruption_rule_id: None,
                        trailer_selected: true,
                        rules_selected: false,
                        compaction: super::AuditCompaction::Full,
                    },
                );
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
            rule_id: id,
            data: AuditMessageData {
                id,
                msg: "m".repeat(text),
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        }
    }

    fn engine_event_message(message: &str) -> AuditMessage {
        engine_event_message_with_state("Test", message)
    }

    fn engine_event_message_with_state(state: &str, message: &str) -> AuditMessage {
        let tag = format!("coraza-rs/engine/{state}");
        AuditMessage {
            message: message.to_owned(),
            error_message: format!("[id \"0\"] [msg \"{message}\"]"),
            rule_id: 0,
            rule_message: format!("{tag}: {message}"),
            provenance: Some(if state == "EventsOmitted" {
                super::AuditMessageProvenance::EventsOmitted {
                    enforced_stop_omitted: false,
                }
            } else {
                super::AuditMessageProvenance::EngineEvent { enforced: false }
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
    }

    fn enforced_events_omitted_audit() -> AuditLog {
        let message_text = "987654321 additional engine stop events summarized after the first 16 individual events; \
                            the enforced stop is among omitted details";
        let mut summary = engine_event_message_with_state("EventsOmitted", message_text);
        summary.error_message.clear();
        summary.data.tags.push(super::ENGINE_ENFORCED_OMITTED_TAG.to_owned());
        summary.provenance = Some(super::AuditMessageProvenance::EventsOmitted {
            enforced_stop_omitted: true,
        });
        AuditLog {
            parts: parse_audit_log_parts("AKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-omitted-summary".to_owned(),
                is_interrupted: true,
                interruption_rule_id: Some(901),
                request: AuditRequest {
                    uri: format!("/{}", "u".repeat(4096)),
                    ..AuditRequest::default()
                },
                producer: Some(super::AuditProducer {
                    connector: "c".repeat(4096),
                    rulesets: vec!["r".repeat(4096)],
                    ..super::AuditProducer::default()
                }),
                ..AuditTransaction::default()
            },
            messages: vec![summary],
        }
    }

    fn h_only_enforced_events_omitted_audit() -> AuditLog {
        const MESSAGE: &str = "987654321 additional engine stop events summarized after the first 16 individual events; \
                               the enforced stop is among omitted details";
        const STATE: &str = "coraza-rs/engine/EventsOmitted";

        let mut audit = enforced_events_omitted_audit();
        audit.parts = parse_audit_log_parts("AHZ").unwrap();
        let summary = audit.messages.first_mut().unwrap();
        summary.message.clear();
        summary.data.msg.clear();
        summary.error_message = format!(
            "[client 192.0.2.1] Coraza: Warning. [file \"\"] [line \"0\"] [id \"0\"] [msg \"{MESSAGE}\"] \
             [data \"\"] [severity \"CRITICAL\"] [ver \"\"] [maturity \"0\"] [accuracy \"0\"] [tag \"{STATE}\"]"
        );
        audit
    }

    fn summary_event_audit(
        parts: &str,
        summary_text: &str,
        enforcement_omitted: bool,
        source_rule_id: Option<i32>,
    ) -> AuditLog {
        const SOURCE_RULE_TEXT: &str = "earlier source rule";
        let h_selected = parts.contains('H');
        let k_selected = parts.contains('K');
        let error_log = |id: i32, message: &str, state: Option<&str>| {
            let tag = state.map_or_else(String::new, |state| format!(" [tag \"coraza-rs/engine/{state}\"]"));
            format!(
                "[client \"192.0.2.1\"] Coraza: Warning. [file \"\"] [line \"0\"] [id \"{id}\"] \
                 [msg \"{message}\"] [data \"\"] [severity \"CRITICAL\"] [ver \"\"] [maturity \"0\"] \
                 [accuracy \"0\"]{tag}"
            )
        };
        let mut messages = Vec::with_capacity(18);
        if let Some(id) = source_rule_id {
            messages.push(AuditMessage {
                message: if k_selected {
                    SOURCE_RULE_TEXT.to_owned()
                } else {
                    String::new()
                },
                error_message: if h_selected {
                    error_log(id, SOURCE_RULE_TEXT, None)
                } else {
                    String::new()
                },
                rule_id: id,
                data: if k_selected {
                    AuditMessageData {
                        id,
                        msg: SOURCE_RULE_TEXT.to_owned(),
                        ..AuditMessageData::default()
                    }
                } else {
                    AuditMessageData::default()
                },
                ..AuditMessage::default()
            });
        }
        for index in 0..16 {
            let message_text = format!("RequestBodyLimit {index}");
            let mut event = engine_event_message_with_state("RequestBodyLimit", &message_text);
            if !k_selected {
                event.message.clear();
                event.data.msg.clear();
            }
            event.error_message = if h_selected {
                error_log(0, &message_text, Some("RequestBodyLimit"))
            } else {
                String::new()
            };
            messages.push(event);
        }
        let mut summary = engine_event_message_with_state("EventsOmitted", summary_text);
        if !k_selected {
            summary.message.clear();
            summary.data.msg.clear();
        }
        summary.error_message = if h_selected {
            error_log(0, summary_text, Some("EventsOmitted"))
        } else {
            String::new()
        };
        if enforcement_omitted {
            summary.data.tags.push(super::ENGINE_ENFORCED_OMITTED_TAG.to_owned());
            summary.provenance = Some(super::AuditMessageProvenance::EventsOmitted {
                enforced_stop_omitted: true,
            });
        }
        messages.push(summary);

        AuditLog {
            parts: parse_audit_log_parts(parts).unwrap(),
            transaction: AuditTransaction {
                id: "tx-overflow-summary".to_owned(),
                is_interrupted: enforcement_omitted || source_rule_id.is_some(),
                interruption_rule_id: source_rule_id.or_else(|| enforcement_omitted.then_some(0)),
                request: AuditRequest {
                    uri: format!("/{}", "p".repeat(16 * 1024)),
                    ..AuditRequest::default()
                },
                producer: Some(super::AuditProducer {
                    connector: "c".repeat(4096),
                    rulesets: vec!["r".repeat(4096)],
                    ..super::AuditProducer::default()
                }),
                ..AuditTransaction::default()
            },
            messages,
        }
    }

    fn bounded_summary_visible_fields(
        format: AuditLogFormat,
        document: &serde_json::Value,
        h_only: bool,
    ) -> Option<(Vec<String>, Option<serde_json::Value>)> {
        match format {
            AuditLogFormat::Json => {
                let message = document.pointer("/messages/0")?;
                let visible = [
                    message.get("message").and_then(serde_json::Value::as_str),
                    message.get("error_message").and_then(serde_json::Value::as_str),
                    message.pointer("/data/msg").and_then(serde_json::Value::as_str),
                ]
                .into_iter()
                .flatten()
                .map(str::to_owned)
                .collect();
                Some((
                    visible,
                    if h_only {
                        Some(message.get("data").unwrap().clone())
                    } else {
                        message.get("data").cloned()
                    },
                ))
            },
            AuditLogFormat::JsonLegacy => Some((
                document
                    .pointer("/audit_data/messages/0")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .into_iter()
                    .collect(),
                None,
            )),
            AuditLogFormat::Ocsf => {
                let enrichment = document.pointer("/enrichments/0")?;
                let data = if h_only {
                    Some(
                        serde_json::from_str(enrichment.get("data").and_then(serde_json::Value::as_str).unwrap())
                            .unwrap(),
                    )
                } else {
                    enrichment
                        .get("data")
                        .and_then(serde_json::Value::as_str)
                        .map(|text| serde_json::from_str::<serde_json::Value>(text).unwrap())
                };
                let visible = if h_only {
                    [
                        enrichment.get("name").and_then(serde_json::Value::as_str),
                        document.get("message").and_then(serde_json::Value::as_str),
                    ]
                    .into_iter()
                    .flatten()
                    .map(str::to_owned)
                    .collect()
                } else {
                    [
                        document.get("message").and_then(serde_json::Value::as_str),
                        enrichment.get("name").and_then(serde_json::Value::as_str),
                        data.as_ref()
                            .and_then(|data| data.get("msg"))
                            .and_then(serde_json::Value::as_str),
                    ]
                    .into_iter()
                    .flatten()
                    .map(str::to_owned)
                    .collect()
                };
                Some((visible, data))
            },
            AuditLogFormat::Native => unreachable!(),
        }
    }

    fn full_summary_text(format: AuditLogFormat, document: &serde_json::Value, h_only: bool) -> Option<&str> {
        match format {
            AuditLogFormat::Json if h_only => document
                .pointer("/messages/0/error_message")
                .and_then(serde_json::Value::as_str),
            AuditLogFormat::Json => document
                .pointer("/messages/0/data/msg")
                .and_then(serde_json::Value::as_str),
            AuditLogFormat::JsonLegacy => document
                .pointer("/audit_data/messages/0")
                .and_then(serde_json::Value::as_str),
            AuditLogFormat::Ocsf => document
                .pointer("/enrichments/0/name")
                .and_then(serde_json::Value::as_str),
            AuditLogFormat::Native => unreachable!(),
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "The bounded and full-fit summary matrices share format-specific identity expectations."
    )]
    fn assert_bounded_summary_formats(
        audit: &AuditLog,
        message: &str,
        fallback: &str,
        h_only: bool,
        full_error: Option<&str>,
    ) {
        const STATE: &str = "coraza-rs/engine/EventsOmitted";
        let full_identity = format!("{STATE}: {message}");
        let fallback_identity = format!("{STATE}: {fallback}");
        let compact_identity = |identity: &str| format!("[id \"0\"] [msg \"{identity}\"]");
        let acceptable = |text: &str| {
            text.is_empty()
                || (!h_only && (text == message || text == fallback))
                || text == full_identity
                || text == fallback_identity
                || text == compact_identity(&full_identity)
                || text == compact_identity(&fallback_identity)
                || full_error.is_some_and(|full_error| text == full_error)
        };

        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            for max_bytes in [482, 494] {
                let (output, truncated) = audit.format_bounded(format, max_bytes);
                assert!(truncated, "{format:?} at {max_bytes} bytes");
                assert!(output.len() <= max_bytes, "{format:?} at {max_bytes} bytes: {output}");
                if output.is_empty() {
                    continue;
                }
                let document: serde_json::Value = serde_json::from_str(&output).unwrap();
                assert_eq!(
                    if format == AuditLogFormat::Ocsf {
                        document.pointer("/unmapped/truncated")
                    } else {
                        document.get("truncated")
                    },
                    Some(&serde_json::Value::Bool(true)),
                    "{format:?} carries its truncation marker: {output}"
                );
                let Some((visible, data)) = bounded_summary_visible_fields(format, &document, h_only) else {
                    continue;
                };
                for text in visible {
                    if h_only {
                        assert!(
                            acceptable(&text),
                            "{format:?} at {max_bytes} bytes emitted partial H-only summary text {text:?}: {output}"
                        );
                    } else {
                        assert!(
                            acceptable(&text),
                            "{format:?} at {max_bytes} bytes emitted a partial count/detail: {text:?}; {output}"
                        );
                    }
                }
                if h_only && let Some(data) = data {
                    assert!(
                        data.get("tags")
                            .and_then(serde_json::Value::as_array)
                            .is_some_and(Vec::is_empty),
                        "{format:?} leaked unselected K tags: {output}"
                    );
                    assert_eq!(
                        data.get("raw").and_then(serde_json::Value::as_str),
                        Some(""),
                        "{format:?} leaked unselected K raw data: {output}"
                    );
                }
            }

            let (full, truncated) = audit.format_bounded(format, 64 * 1024);
            assert!(!truncated, "{format:?}: full summary fits");
            let document: serde_json::Value = serde_json::from_str(&full).unwrap();
            let summary_text = full_summary_text(format, &document, h_only);
            if h_only {
                assert!(
                    summary_text.is_some_and(|text| text.contains(message)),
                    "{format:?}: full fit retains the count and enforcement clause: {full}"
                );
            } else {
                assert!(
                    summary_text.is_some_and(|text| text.contains(message)),
                    "{format:?}: full fit retains the exact count and enforcement clause: {full}"
                );
            }

            if !h_only && format == AuditLogFormat::Json {
                assert!(
                    document
                        .pointer("/messages/0/data/tags")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|tags| {
                            tags.iter()
                                .any(|tag| tag.as_str() == Some(super::ENGINE_ENFORCED_OMITTED_TAG))
                        }),
                    "K-selected JSON includes the enforcement marker: {full}"
                );
            } else if !h_only && format == AuditLogFormat::Ocsf {
                let data: serde_json::Value = serde_json::from_str(
                    document
                        .pointer("/enrichments/0/data")
                        .and_then(serde_json::Value::as_str)
                        .unwrap(),
                )
                .unwrap();
                assert!(
                    data.get("tags")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|tags| {
                            tags.iter()
                                .any(|tag| tag.as_str() == Some(super::ENGINE_ENFORCED_OMITTED_TAG))
                        }),
                    "K-selected OCSF includes the enforcement marker: {full}"
                );
            }
        }
    }

    #[test]
    fn h_only_ocsf_keeps_an_enforced_omission_summary_at_a_tight_reduced_budget() {
        const STATE: &str = "coraza-rs/engine/EventsOmitted";
        const SUMMARY: &str = "1 additional engine stop event summarized after the first 16 individual events; the enforced stop is among omitted details";
        const PLAIN_SUMMARY: &str = "1 additional engine stop event summarized after the first 16 individual events";
        const SOURCE_RULE_ID: i32 = 901;

        let audit = summary_event_audit("AHZ", SUMMARY, true, Some(SOURCE_RULE_ID));
        let (bounded, truncated) = audit.format_bounded(AuditLogFormat::Ocsf, 1024);

        assert!(truncated, "the padded real-shaped 16+1 event record is reduced");
        assert!(bounded.len() <= 1024, "{}", bounded.len());
        assert!(serde_json::from_str::<serde_json::Value>(&bounded).unwrap().is_object());
        assert!(
            bounded.contains(&format!("{STATE}: {SUMMARY}"))
                || bounded.contains(&format!("{STATE}: {}", super::ENGINE_EVENTS_OMITTED_FALLBACK)),
            "the omitted enforcing summary is preferred to the earlier same-ID rule and complete when retained: {bounded}"
        );

        let (full, truncated) = audit.format_bounded(AuditLogFormat::Ocsf, 64 * 1024);
        assert!(!truncated, "the full record fits");
        assert!(full.contains(&format!("{STATE}: {SUMMARY}")), "{full}");

        let plain = summary_event_audit("AHZ", PLAIN_SUMMARY, false, None);
        let (plain_full, truncated) = plain.format_bounded(AuditLogFormat::Ocsf, 64 * 1024);
        assert!(!truncated, "the unmarked summary is an ordinary full-fit record");
        assert!(
            plain_full.contains(&format!("{STATE}: {PLAIN_SUMMARY}")),
            "{plain_full}"
        );
        assert!(!plain_full.contains(super::ENGINE_ENFORCED_OMITTED_TAG), "{plain_full}");

        let (tiny, truncated) = audit.format_bounded(AuditLogFormat::Ocsf, 31);
        assert!(truncated);
        assert_eq!(tiny, super::bare_truncation_marker(AuditLogFormat::Ocsf));
    }

    #[test]
    fn compact_retry_keeps_a_complete_omission_summary_fallback_when_it_fits() {
        const ENFORCED_SUMMARY: &str = "1 additional engine stop event summarized after the first 16 individual events; the enforced stop is among omitted details";
        const PLAIN_SUMMARY: &str = "1 additional engine stop event summarized after the first 16 individual events";
        const FALLBACK: &str = "additional engine stop details omitted";

        for (parts, format, limit, summary_text, enforced, source_rule_id) in [
            ("AKZ", AuditLogFormat::Json, 600, ENFORCED_SUMMARY, true, None),
            ("AKZ", AuditLogFormat::Ocsf, 1000, ENFORCED_SUMMARY, true, None),
            ("AKZ", AuditLogFormat::JsonLegacy, 600, ENFORCED_SUMMARY, true, None),
            ("AKZ", AuditLogFormat::Json, 850, PLAIN_SUMMARY, false, None),
            ("AKZ", AuditLogFormat::Ocsf, 1280, PLAIN_SUMMARY, false, None),
        ] {
            let candidate = summary_event_audit(parts, summary_text, enforced, source_rule_id);
            let fallback = summary_event_audit(parts, FALLBACK, enforced, source_rule_id);
            let (fallback_output, fallback_truncated) = fallback.format_bounded(format, limit);
            assert!(fallback_truncated, "{parts} {format:?}: the long record is reduced");
            assert!(
                !fallback_output.is_empty() && fallback_output.len() <= limit,
                "{parts} {format:?}: the fixed fallback fits in {limit} bytes: {fallback_output}"
            );
            assert!(
                serde_json::from_str::<serde_json::Value>(&fallback_output)
                    .unwrap()
                    .is_object()
            );
            assert!(
                fallback_output.contains(FALLBACK),
                "{parts} {format:?}: the fallback candidate keeps its visible summary: {fallback_output}"
            );
            assert!(
                fallback_output.contains("coraza-rs/engine/EventsOmitted"),
                "{parts} {format:?}: the selected K identity remains visible: {fallback_output}"
            );

            let (output, truncated) = candidate.format_bounded(format, limit);
            assert!(truncated, "{parts} {format:?}: the long record is reduced");
            assert!(output.len() <= limit, "{parts} {format:?}: {output}");
            assert!(serde_json::from_str::<serde_json::Value>(&output).unwrap().is_object());
            assert!(
                output.contains(summary_text) || output.contains(FALLBACK),
                "{parts} {format:?}: the summary or its complete fixed fallback is preferred to a bare marker: {output}"
            );
            assert!(
                output.contains("coraza-rs/engine/EventsOmitted"),
                "{parts} {format:?}: the selected K identity remains visible: {output}"
            );
            if !enforced {
                assert!(
                    output.contains(FALLBACK),
                    "{parts} {format:?}: the non-pinned summary uses the full fallback at this cap: {output}"
                );
                assert!(
                    !output.contains("the enforced stop is among omitted details"),
                    "{parts} {format:?}: a plain summary does not invent an enforcement cause: {output}"
                );
            }
        }
    }

    fn h_only_body_limit_overflow_audit(with_summary: bool) -> AuditLog {
        const STATE: &str = "coraza-rs/engine/RequestBodyLimit";
        const CAUSE: &str = "request body of 1048577 bytes exceeds the configured SecRequestBodyLimit of 1048576 bytes and processing was stopped";
        const SUMMARY: &str = "1 additional engine stop event summarized after the first 16 individual events";

        let mut audit = summary_event_audit("AHZ", SUMMARY, false, None);
        audit.transaction.id = "tx-engine-stop".to_owned();
        audit.transaction.is_interrupted = true;
        audit.transaction.interruption_rule_id = Some(0);
        audit.transaction.request = AuditRequest::default();
        let producer = audit.transaction.producer.as_mut().unwrap();
        producer.connector = "c".repeat(16 * 1024);
        producer.rulesets = vec!["r".repeat(16 * 1024)];

        let cause_event = audit.messages.first_mut().unwrap();
        cause_event.rule_message = format!("{STATE}: {CAUSE}");
        cause_event.error_message = format!("[id \"0\"] [msg \"{}\"]", cause_event.rule_message);
        cause_event.provenance = Some(super::AuditMessageProvenance::EngineEvent { enforced: true });
        cause_event.data.tags.push(super::ENGINE_ENFORCED_TAG.to_owned());
        if !with_summary {
            audit.messages.pop();
        }
        audit
    }

    #[test]
    fn an_unselected_summary_does_not_starve_the_pinned_h_only_cause_identity() {
        const STATE: &str = "coraza-rs/engine/RequestBodyLimit";
        const IDENTITY_PREFIX: &str = "[id \"0\"] [msg \"coraza-rs/engine/RequestBodyLimit: ";
        let with_summary = h_only_body_limit_overflow_audit(true);
        let without_summary = h_only_body_limit_overflow_audit(false);

        for (format, limits, pointer) in [
            (AuditLogFormat::Json, [579, 613], "/messages/0/error_message"),
            (AuditLogFormat::JsonLegacy, [481, 515], "/audit_data/messages/0"),
        ] {
            for limit in limits {
                let (with, truncated) = with_summary.format_bounded(format, limit);
                assert!(truncated, "{format:?} at {limit} bytes");
                assert!(with.len() <= limit, "{format:?} at {limit} bytes");
                assert_ne!(
                    with, r#"{"truncated":true}"#,
                    "{format:?} must keep the fitting cause despite its unselected summary"
                );
                let document: serde_json::Value = serde_json::from_str(&with).unwrap();
                let identity = document.pointer(pointer).and_then(serde_json::Value::as_str).unwrap();
                assert!(
                    identity.starts_with(IDENTITY_PREFIX) && identity.ends_with("\"]"),
                    "{format:?} at {limit}: the complete cause state prefix survives: {with}"
                );
                assert!(identity.contains(STATE), "{format:?} at {limit}: {with}");

                let (without, truncated) = without_summary.format_bounded(format, limit);
                assert!(truncated, "{format:?} no-summary control at {limit} bytes");
                assert!(without.len() <= limit);
                let document: serde_json::Value = serde_json::from_str(&without).unwrap();
                let identity = document.pointer(pointer).and_then(serde_json::Value::as_str).unwrap();
                assert!(
                    identity.starts_with(IDENTITY_PREFIX) && identity.ends_with("\"]"),
                    "{format:?} no-summary control at {limit}: {without}"
                );
            }
        }
    }

    #[test]
    fn a_pinned_single_omission_summary_keeps_its_fixed_fallback_when_it_fits() {
        const SUMMARY: &str = "987654321 additional engine stop events summarized after the first 16 individual events; the enforced stop is among omitted details";
        const FALLBACK: &str = "additional engine stop details omitted";
        const STATE: &str = "coraza-rs/engine/EventsOmitted";

        let mut h_only = h_only_enforced_events_omitted_audit();
        h_only.transaction.id = "tx-engine-stop".to_owned();
        let mut k_selected = enforced_events_omitted_audit();
        k_selected.transaction.id = "tx-engine-stop".to_owned();

        for (audit, format, limit) in [
            (&h_only, AuditLogFormat::Ocsf, 786),
            (&k_selected, AuditLogFormat::Ocsf, 990),
            (&k_selected, AuditLogFormat::Json, 640),
        ] {
            assert_eq!(audit.messages.len(), 1, "the summary is the only pinned message");
            let (output, truncated) = audit.format_bounded(format, limit);
            assert!(truncated, "{format:?}: the long summary is reduced");
            assert!(output.len() <= limit, "{format:?}: {output}");
            assert!(
                output.contains(FALLBACK),
                "{format:?} keeps the complete fixed summary fallback: {output}"
            );
            assert!(
                output.contains(STATE),
                "{format:?} keeps the summary state identity: {output}"
            );
            let document: serde_json::Value = serde_json::from_str(&output).unwrap();
            if format == AuditLogFormat::Json {
                assert_eq!(
                    document
                        .pointer("/messages/0/data/msg")
                        .and_then(serde_json::Value::as_str),
                    Some(FALLBACK),
                    "K-selected JSON keeps the complete fallback message: {output}"
                );
            } else {
                assert_eq!(
                    document
                        .pointer("/enrichments")
                        .and_then(serde_json::Value::as_array)
                        .map(Vec::len),
                    Some(1),
                    "{format:?} keeps the pinned summary as its one enrichment: {output}"
                );
            }
        }

        for (audit, format, marker) in [
            (&h_only, AuditLogFormat::Ocsf, r#"{"unmapped":{"truncated":true}}"#),
            (&k_selected, AuditLogFormat::Json, r#"{"truncated":true}"#),
        ] {
            let (tiny, truncated) = audit.format_bounded(format, marker.len());
            assert!(truncated, "{format:?} tiny control");
            assert_eq!(tiny, marker, "{format:?} tiny control");
            let (full, truncated) = audit.format_bounded(format, 64 * 1024);
            assert!(!truncated, "{format:?} full-fit control");
            assert!(full.contains(SUMMARY), "{format:?}: {full}");
        }
    }

    #[test]
    fn a_compacted_summary_identity_keeps_unicode_and_escapes_whole() {
        const STATE: &str = "coraza-rs/engine/EventsOmitted";
        const MESSAGE: &str =
            "987654321 additional engine stop events summarized after the first 16 individual events — café\0";
        const FALLBACK: &str = "additional engine stop details omitted";
        let summary = engine_event_message_with_state("EventsOmitted", MESSAGE);
        let full = format!(
            "[id \"0\"] [msg \"{STATE}: 987654321 additional engine stop events summarized after the first 16 individual events — café\\x00\"]"
        );
        let fallback = format!("[id \"0\"] [msg \"{STATE}: {FALLBACK}\"]");

        assert_eq!(
            super::reduced_engine_identity(&summary, fallback.len() - 1),
            None,
            "one byte short cannot leave a partial fallback"
        );
        assert_eq!(
            super::reduced_engine_identity(&summary, fallback.len()),
            Some((fallback.clone(), true)),
            "the generic summary is retained whole at its exact byte limit"
        );
        for limit in fallback.len() + 1..full.len() {
            assert_eq!(
                super::reduced_engine_identity(&summary, limit),
                Some((fallback.clone(), true)),
                "{limit}: no decimal, UTF-8 character, or escape is prefix-truncated"
            );
        }
        assert_eq!(
            super::reduced_engine_identity(&summary, full.len()),
            Some((full, false)),
            "the exact count and Unicode text are retained at their exact byte limit"
        );
    }

    #[test]
    fn a_reduced_enforcement_summary_never_presents_one_digit_as_its_exact_count() {
        const STATE: &str = "coraza-rs/engine/EventsOmitted";
        const MESSAGE: &str = "987654321 additional engine stop events summarized after the first 16 individual events; \
                               the enforced stop is among omitted details";

        let mut summary = engine_event_message_with_state("EventsOmitted", MESSAGE);
        summary.data.tags.push(super::ENGINE_ENFORCED_OMITTED_TAG.to_owned());
        summary.provenance = Some(super::AuditMessageProvenance::EventsOmitted {
            enforced_stop_omitted: true,
        });
        let prefix = format!("[id \"0\"] [msg \"{STATE}: ");
        let one_digit_limit = format!("{prefix}9\"]").len();
        let exact = format!("[id \"0\"] [msg \"{STATE}: {MESSAGE}\"]");
        let fallback = format!("[id \"0\"] [msg \"{STATE}: additional engine stop details omitted\"]");

        let compact = super::reduced_engine_identity(&summary, one_digit_limit);

        assert!(
            compact
                .as_ref()
                .is_none_or(|(identity, _)| identity == &exact || identity == &fallback),
            "a decimal prefix must not look like the exact omitted count: {compact:?}"
        );
    }

    #[test]
    fn bounded_formats_never_render_an_omission_count_or_enforcement_clause_as_a_prefix() {
        const MESSAGE: &str = "987654321 additional engine stop events summarized after the first 16 individual events; \
                               the enforced stop is among omitted details";
        const FALLBACK: &str = "additional engine stop details omitted";

        assert_bounded_summary_formats(&enforced_events_omitted_audit(), MESSAGE, FALLBACK, false, None);
    }

    #[test]
    fn bounded_h_only_summary_keeps_its_identity_without_serializing_k_fields() {
        const MESSAGE: &str = "987654321 additional engine stop events summarized after the first 16 individual events; \
                               the enforced stop is among omitted details";
        const FALLBACK: &str = "additional engine stop details omitted";

        let audit = h_only_enforced_events_omitted_audit();
        let full_error = audit.messages.first().unwrap().error_message.clone();
        assert_bounded_summary_formats(&audit, MESSAGE, FALLBACK, true, Some(&full_error));
    }

    #[test]
    fn engine_identity_prefix_budget_counts_go_quoted_bytes_at_exact_fit() {
        let source = engine_event_message_with_state("Quoted\"slash\\\t\u{7f}\u{85}é", "");
        let identity = super::reduced_engine_identity(&source, usize::MAX).unwrap().0;

        assert_eq!(
            super::reduced_engine_identity_prefix_bytes(&source, identity.len()),
            Some(identity.len())
        );
        assert_eq!(
            super::reduced_engine_identity_prefix_bytes(&source, identity.len() - 1),
            None,
            "the complete quoted state prefix does not fit one byte below its exact size"
        );
    }

    #[test]
    fn compact_planned_copy_skips_pinned_rule_tags_before_budgeting() {
        const RULE_ID: i32 = 4242;
        const ERROR_MESSAGE: &str = "[id \"4242\"] [msg \"blocked\"]";

        let entry = AuditLog {
            parts: parse_audit_log_parts("AHKZ").unwrap(),
            transaction: AuditTransaction {
                is_interrupted: true,
                interruption_rule_id: Some(RULE_ID),
                producer: Some(super::AuditProducer {
                    connector: "large producer".repeat(256),
                    ..super::AuditProducer::default()
                }),
                request: AuditRequest {
                    uri: "large request".repeat(256),
                    ..AuditRequest::default()
                },
                ..AuditTransaction::default()
            },
            messages: vec![AuditMessage {
                error_message: ERROR_MESSAGE.to_owned(),
                rule_id: RULE_ID,
                data: AuditMessageData {
                    id: RULE_ID,
                    tags: vec!["unselected tag".to_owned()],
                    ..AuditMessageData::default()
                },
                ..AuditMessage::default()
            }],
        };
        let mut budget = AuditCopyBudget::generous(128);

        let view = entry.bounded_copy_planned(
            AuditLogFormat::Json,
            &mut budget,
            Some(super::AuditShrinkPlan {
                request_bytes: 0,
                message_bytes: 128,
                message_each: None,
                summary_each: None,
                message_count: 1,
                reduced: true,
            }),
            super::AuditCompaction::Compact,
        );

        assert!(view.transaction.producer.is_none());
        assert!(view.transaction.request.uri.is_empty());
        let message = view.messages.first().unwrap();
        assert_eq!(message.error_message, ERROR_MESSAGE);
        assert!(message.data.tags.is_empty());
        assert_eq!(budget.items_used, 0, "omitted metadata and tags consume no item budget");
    }

    fn native_audit(parts: &str, body: &str, message: AuditMessage) -> AuditLog {
        AuditLog {
            parts: parse_audit_log_parts(parts).unwrap(),
            transaction: AuditTransaction {
                request: AuditRequest {
                    body: body.to_owned(),
                    ..AuditRequest::default()
                },
                ..AuditTransaction::default()
            },
            messages: vec![message],
        }
    }

    fn bounded_native_copy(audit: &AuditLog, max_bytes: usize) -> (AuditLog, bool) {
        let mut budget = AuditCopyBudget::new(max_bytes);
        let copy = audit.bounded_copy(AuditLogFormat::Native, &mut budget);
        (copy, budget.truncated)
    }

    fn native_lines_without_boundaries(output: &str) -> Vec<&str> {
        output.lines().filter(|line| !line.starts_with("--")).collect()
    }

    fn h_only_engine_event_message_with_state(state: &str, message: &str) -> AuditMessage {
        let tag = format!("coraza-rs/engine/{state}");
        AuditMessage {
            error_message: format!("visible H line for {state}: {message}"),
            rule_id: 0,
            rule_message: format!("{tag}: {message}"),
            provenance: Some(if state == "EventsOmitted" {
                super::AuditMessageProvenance::EventsOmitted {
                    enforced_stop_omitted: false,
                }
            } else {
                super::AuditMessageProvenance::EngineEvent { enforced: false }
            }),
            data: AuditMessageData {
                id: 0,
                tags: vec![tag.clone()],
                raw: tag,
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        }
    }

    #[test]
    fn k_selected_json_message_copy_does_not_charge_the_hidden_event_identity() {
        let mut source =
            engine_event_message_with_state("OperatorNotInspected", "host operator refused to inspect input");
        source.error_message.clear();
        let visible_bytes = source.message.len()
            + source.data.msg.len()
            + source.data.tags.iter().map(String::len).sum::<usize>()
            + source.data.raw.len();
        let mut budget = AuditCopyBudget::generous(visible_bytes);

        let copy = budget.message(&source, super::AuditMessageCopy::Json, true);

        assert!(!budget.truncated, "all serialized K fields fit exactly");
        assert_eq!(copy.message, source.message);
        assert_eq!(copy.data.msg, source.data.msg);
        assert_eq!(copy.data.tags, source.data.tags);
        assert_eq!(copy.data.raw, source.data.raw);
        assert_eq!(
            budget.bytes_used, visible_bytes,
            "only serialized fields consume the budget"
        );
    }

    #[test]
    fn k_selected_json_pinned_message_keeps_visible_event_identity_at_its_exact_budget() {
        let source = engine_event_message_with_state("OperatorNotInspected", "host operator refused to inspect input");
        let visible_bytes =
            source.data.msg.len() + source.data.raw.len() + source.data.tags.iter().map(String::len).sum::<usize>();
        let mut budget = AuditCopyBudget::generous(visible_bytes);

        let copy = budget.pinned_message_with_compaction(
            &source,
            super::AuditMessageCopy::Json,
            super::AuditMessageSelection {
                interruption_rule_id: None,
                trailer_selected: false,
                rules_selected: true,
                compaction: super::AuditCompaction::Full,
            },
        );

        assert!(
            !budget.truncated,
            "the visible K identity fits without the hidden prefix"
        );
        assert_eq!(copy.error_message, "", "K-only JSON does not synthesize part H");
        assert_eq!(
            copy.rule_message, "",
            "K-only JSON does not retain a hidden identity copy"
        );
        assert_eq!(copy.data.msg, source.data.msg);
        assert_eq!(copy.data.tags, source.data.tags);
        assert_eq!(copy.data.raw, source.data.raw);
        assert_eq!(
            budget.bytes_used, visible_bytes,
            "only serialized K fields consume the budget"
        );
    }

    #[test]
    fn h_only_json_message_copy_spends_its_exact_budget_on_visible_error_text() {
        let source = h_only_engine_event_message_with_state("OperatorNotInspected", "refused input");
        let mut budget = AuditCopyBudget::generous(source.error_message.len());

        let copy = budget.message(&source, super::AuditMessageCopy::Json, false);

        assert!(!budget.truncated, "the visible H line fits exactly");
        assert_eq!(copy.error_message, source.error_message);
        assert!(copy.data.tags.is_empty(), "unselected K tags are not copied");
        assert!(copy.data.raw.is_empty(), "unselected K raw text is not copied");
        assert_eq!(
            budget.bytes_used,
            source.error_message.len(),
            "the hidden identity prefix and K fields consume no H budget"
        );
    }

    #[test]
    fn h_only_event_identity_is_visible_in_ocsf_and_jsonlegacy_without_copying_k_fields() {
        let source = h_only_engine_event_message_with_state("RequestBodyLimit", "RequestBodyLimit");
        let identity = source.engine_identity().unwrap();

        for (mode, mode_name) in [
            (super::AuditMessageCopy::Legacy, "JSONLegacy"),
            (super::AuditMessageCopy::Ocsf, "OCSF"),
        ] {
            let mut budget = AuditCopyBudget::generous(identity.len());
            let copy = budget.message(&source, mode, false);

            assert!(!budget.truncated, "{mode_name}: the visible identity fits exactly");
            assert!(
                copy.message == identity || copy.rule_message == identity,
                "{mode_name}: the visible identity survives: {copy:?}"
            );
            assert!(copy.data.tags.is_empty(), "{mode_name}: no hidden K tags");
            assert!(copy.data.raw.is_empty(), "{mode_name}: no hidden K raw text");
            assert_eq!(
                budget.bytes_used,
                identity.len(),
                "{mode_name}: only the serialized identity consumes the budget"
            );
        }
    }

    #[test]
    fn native_bounded_copy_omits_an_unfitting_synthetic_k_label() {
        const OUTPUT_LIMIT: usize = 260;
        const STATE: &str = "coraza-rs/engine/OperatorNotInspected";
        let mut event = engine_event_message_with_state("OperatorNotInspected", "host operator refused input");
        event.error_message = "H".repeat(OUTPUT_LIMIT - (STATE.len() - 1));
        assert!(event.is_engine_event(), "the fixture has explicit provenance");
        let audit = native_audit("AHKZ", "", event);

        let (copy, truncated) = bounded_native_copy(&audit, OUTPUT_LIMIT);

        assert!(truncated, "the K label does not fit in the remaining copy budget");
        assert_eq!(
            copy.messages.first().unwrap().data.raw,
            "",
            "a genuine synthetic K label is copied whole or omitted, never prefix-truncated"
        );
        assert!(
            copy.native().len() > OUTPUT_LIMIT,
            "the assertion inspects the bounded copy before Native's separately documented final hard-cut"
        );
    }

    #[test]
    fn native_bounded_copy_only_appends_an_events_omitted_count_with_its_full_label() {
        const SUMMARY_TAG: &str = "coraza-rs/engine/EventsOmitted";
        const SUMMARY_TEXT: &str = "48 additional engine stop events summarized after the first 16 individual events";
        let mut summary = engine_event_message_with_state("EventsOmitted", SUMMARY_TEXT);
        let before_raw = 300;
        summary.error_message = "H".repeat(before_raw - summary.data.msg.len() - SUMMARY_TAG.len() - 2);

        for remaining in [0, SUMMARY_TAG.len() - 1, SUMMARY_TAG.len()] {
            let audit = native_audit("AHKZ", "", summary.clone());
            let (copy, truncated) = bounded_native_copy(&audit, before_raw + remaining);
            let copied_summary = copy.messages.first().unwrap();
            let output = copy.native();

            if remaining < SUMMARY_TAG.len() {
                assert!(truncated, "the incomplete label marks the copy truncated");
                assert_eq!(
                    copied_summary.data.raw, "",
                    "no-space and one-byte-short copies omit the complete state label"
                );
                assert!(
                    !output.contains(SUMMARY_TEXT),
                    "Native does not leave an orphan or partial summary line without its label: {output:?}"
                );
            } else {
                assert!(!truncated, "the complete label and count fit exactly");
                assert_eq!(copied_summary.data.raw, SUMMARY_TAG);
                assert!(
                    output
                        .lines()
                        .any(|line| line == format!("{SUMMARY_TAG}: {SUMMARY_TEXT}")),
                    "the complete summary line survives when its label fits: {output:?}"
                );
            }
        }
    }

    #[test]
    fn native_bounded_copy_omits_a_body_heavy_summary_label_before_the_final_hard_cut() {
        const OUTPUT_LIMIT: usize = 16_384;
        const BODY_LEN: usize = 16_000;
        const SUMMARY_TAG: &str = "coraza-rs/engine/EventsOmitted";
        const SUMMARY_TEXT: &str = "48 additional engine stop events summarized after the first 16 individual events";
        let mut summary = engine_event_message_with_state("EventsOmitted", SUMMARY_TEXT);
        let body = "b".repeat(BODY_LEN);
        let h_len = OUTPUT_LIMIT - BODY_LEN - summary.data.msg.len() - SUMMARY_TAG.len() - 2;
        summary.error_message = "H".repeat(h_len);
        let audit = native_audit("ACHKZ", &body, summary);

        let (copy, truncated) = bounded_native_copy(&audit, OUTPUT_LIMIT);

        assert!(
            truncated,
            "the complete K state label cannot fit after the body and H text"
        );
        assert_eq!(
            copy.transaction.request.body.len(),
            BODY_LEN,
            "the body consumes the earlier budget"
        );
        assert_eq!(
            copy.messages.first().unwrap().data.raw,
            "",
            "a body-heavy K label is omitted rather than prefix-truncated"
        );
        let uncut_copy_output = copy.native();
        assert!(
            uncut_copy_output.len() > OUTPUT_LIMIT,
            "this is still before the final hard-cut"
        );
        assert!(
            !uncut_copy_output.contains(SUMMARY_TEXT),
            "the bounded copy does not make an orphan summary line"
        );
    }

    #[test]
    fn native_bounded_copy_matches_unbounded_content_when_the_cap_is_generous() {
        const OUTPUT_LIMIT: usize = 16 * 1024;
        const SUMMARY_TEXT: &str = "48 additional engine stop events summarized after the first 16 individual events";
        for mut event in [
            engine_event_message_with_state("OperatorNotInspected", "host operator refused input"),
            engine_event_message_with_state("EventsOmitted", SUMMARY_TEXT),
        ] {
            event.error_message = "H".repeat(120);
            let audit = native_audit("AHKZ", "", event);
            let unbounded = audit.format(AuditLogFormat::Native);

            let (bounded, truncated) = audit.format_bounded(AuditLogFormat::Native, OUTPUT_LIMIT);

            assert!(!truncated, "the cap leaves the native record unchanged");
            assert_eq!(
                native_lines_without_boundaries(&bounded),
                native_lines_without_boundaries(&unbounded),
                "bounded Native output matches the unbounded content apart from its random boundary"
            );
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "Checks Native summary identity, final hard-cut, and bounded JSON prioritization."
    )]
    fn unmarked_events_omitted_lookalike_is_not_a_summary() {
        const SUMMARY_TAG: &str = "coraza-rs/engine/EventsOmitted";
        const CALLER_MESSAGE: &str = "caller-owned ordinary message";
        let ordinary = AuditMessage {
            rule_id: 0,
            data: AuditMessageData {
                id: 0,
                msg: CALLER_MESSAGE.to_owned(),
                raw: SUMMARY_TAG.to_owned(),
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        };
        assert!(
            !ordinary.is_events_omitted_summary(),
            "an unmarked message remains ordinary"
        );
        let audit = AuditLog {
            parts: parse_audit_log_parts("AKZ").unwrap(),
            transaction: AuditTransaction::default(),
            messages: vec![ordinary],
        };

        let output = audit.format(AuditLogFormat::Native);
        assert!(
            output.lines().any(|line| line == SUMMARY_TAG),
            "Native: the raw label remains unchanged: {output:?}"
        );
        assert!(
            !output.contains(&format!("{SUMMARY_TAG}: {CALLER_MESSAGE}")),
            "Native: caller data is not appended as an engine count: {output:?}"
        );
        let (bounded, truncated) = audit.format_bounded(AuditLogFormat::Native, 1024);
        assert!(!truncated, "Native: the hand-built record fits");
        assert!(
            bounded.lines().any(|line| line == SUMMARY_TAG),
            "Native: bounded output keeps the raw label only: {bounded:?}"
        );
        assert!(
            !bounded.contains(&format!("{SUMMARY_TAG}: {CALLER_MESSAGE}")),
            "Native: bounded output does not infer a summary from raw: {bounded:?}"
        );
        let padded = AuditLog {
            parts: parse_audit_log_parts("ACKZ").unwrap(),
            transaction: AuditTransaction {
                request: AuditRequest {
                    body: "p".repeat(100),
                    ..AuditRequest::default()
                },
                ..AuditTransaction::default()
            },
            messages: std::iter::once(audit.messages.first().unwrap().clone())
                .chain((0..6).map(|_| AuditMessage {
                    data: AuditMessageData {
                        raw: "r".repeat(80),
                        ..AuditMessageData::default()
                    },
                    ..AuditMessage::default()
                }))
                .collect(),
        };
        let (reduced, truncated) = padded.format_bounded(AuditLogFormat::Native, 512);
        assert!(truncated, "Native output hits its existing final hard-cut");
        assert!(reduced.len() <= 512);
        assert!(
            reduced.lines().any(|line| line == SUMMARY_TAG),
            "the hand-built K line remains visible before the hard-cut: {reduced:?}"
        );
        assert!(
            !reduced.contains(&format!("{SUMMARY_TAG}: {CALLER_MESSAGE}")),
            "bounded/reduced Native output does not infer a summary from raw: {reduced:?}"
        );

        let cause = AuditMessage {
            rule_id: 900,
            data: AuditMessageData {
                id: 900,
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        };
        let first_other = AuditMessage {
            rule_id: 901,
            data: AuditMessageData {
                id: 901,
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        };
        let last = AuditMessage {
            rule_id: 902,
            data: AuditMessageData {
                id: 902,
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        };
        let mut budget = AuditCopyBudget::generous(512);
        let selected = budget.planned_messages(
            &[cause, first_other, audit.messages.first().unwrap().clone(), last],
            super::AuditMessageCopy::Json,
            super::AuditShrinkPlan {
                request_bytes: 0,
                message_bytes: 512,
                message_each: None,
                summary_each: None,
                message_count: 2,
                reduced: true,
            },
            super::AuditMessageSelection {
                interruption_rule_id: Some(900),
                trailer_selected: false,
                rules_selected: true,
                compaction: super::AuditCompaction::Full,
            },
        );
        assert_eq!(
            selected.iter().map(|message| message.rule_id).collect::<Vec<_>>(),
            [900, 901],
            "the hand-built message does not get summary priority"
        );
    }

    #[test]
    fn a_reduced_non_pinned_h_only_event_keeps_state_beside_a_pinned_real_rule() {
        const CAUSE_ID: i32 = 900;
        const STATE: &str = "coraza-rs/engine/OperatorNotInspected";

        let cause = AuditMessage {
            error_message: "long pinned H line".repeat(32),
            rule_id: CAUSE_ID,
            rule_message: "real blocking rule".to_owned(),
            ..AuditMessage::default()
        };
        let event = h_only_engine_event_message_with_state("OperatorNotInspected", "host refused input");
        let mut budget = AuditCopyBudget::generous(512);

        let copies = budget.planned_messages(
            &[cause, event],
            super::AuditMessageCopy::Json,
            super::AuditShrinkPlan {
                request_bytes: 0,
                message_bytes: 512,
                message_each: Some(96),
                summary_each: None,
                message_count: 2,
                reduced: true,
            },
            super::AuditMessageSelection {
                interruption_rule_id: Some(CAUSE_ID),
                trailer_selected: true,
                rules_selected: false,
                compaction: super::AuditCompaction::Full,
            },
        );

        assert_eq!(copies.len(), 2);
        let pinned = copies.first().unwrap();
        let event = copies.get(1).unwrap();
        assert_eq!(pinned.rule_id, CAUSE_ID, "the real interruption cause stays first");
        assert!(
            pinned.error_message.starts_with("[id \"900\"]"),
            "the pinned rule keeps its compact H identity: {:?}",
            pinned.error_message
        );
        assert!(
            event.error_message.starts_with(&format!("[id \"0\"] [msg \"{STATE}: ")),
            "the non-pinned event keeps a state-first H identity when it fits: {:?}",
            event.error_message
        );
        assert!(event.data.tags.is_empty());
        assert!(event.data.raw.is_empty());
    }

    #[test]
    fn a_tight_h_only_event_allowance_never_leaks_a_truncated_internal_k_prefix() {
        const CAUSE_ID: i32 = 900;
        const STATE: &str = "coraza-rs/engine/OperatorNotInspected";

        let cause = AuditMessage {
            rule_id: CAUSE_ID,
            data: AuditMessageData {
                id: CAUSE_ID,
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        };
        let event = h_only_engine_event_message_with_state("OperatorNotInspected", "refused");
        let mut budget = AuditCopyBudget::generous(128);
        let copies = budget.planned_messages(
            &[cause, event],
            super::AuditMessageCopy::Json,
            super::AuditShrinkPlan {
                request_bytes: 0,
                message_bytes: 128,
                message_each: Some(32),
                summary_each: None,
                message_count: 2,
                reduced: true,
            },
            super::AuditMessageSelection {
                interruption_rule_id: Some(CAUSE_ID),
                trailer_selected: true,
                rules_selected: false,
                compaction: super::AuditCompaction::Full,
            },
        );

        assert_eq!(copies.len(), 2);
        let event = copies.get(1).unwrap();
        assert!(
            event.error_message.starts_with(&format!("[id \"0\"] [msg \"{STATE}: "))
                && event.error_message.ends_with("\"]"),
            "the complete H-only state prefix and closing quote survive: {:?}",
            event.error_message
        );
        assert!(event.data.tags.is_empty(), "no truncated tag entry is exposed");
        assert!(event.data.raw.is_empty(), "no truncated raw prefix is exposed");
    }

    #[test]
    fn bounded_h_only_json_keeps_a_pinned_rule_and_non_pinned_engine_event_when_they_fit() {
        const OUTPUT_LIMIT: usize = 1536;
        const CAUSE_ID: i32 = 900;
        const STATE: &str = "coraza-rs/engine/OperatorNotInspected";

        let cause = AuditMessage {
            error_message: "long real-rule H line".repeat(128),
            rule_id: CAUSE_ID,
            rule_message: "real blocking rule".to_owned(),
            ..AuditMessage::default()
        };
        let mut event = h_only_engine_event_message_with_state("OperatorNotInspected", "host refused input");
        event.error_message = "long engine H line".repeat(128);
        let audit = AuditLog {
            parts: parse_audit_log_parts("AHZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-pinned-rule-and-event".to_owned(),
                is_interrupted: true,
                interruption_rule_id: Some(CAUSE_ID),
                request: AuditRequest {
                    uri: format!("/{}", "p".repeat(16 * 1024)),
                    ..AuditRequest::default()
                },
                ..AuditTransaction::default()
            },
            messages: vec![cause, event],
        };

        let (output, truncated) = audit.format_bounded(AuditLogFormat::Json, OUTPUT_LIMIT);
        assert!(truncated, "the long URI and H lines force reduction");
        assert!(output.len() <= OUTPUT_LIMIT);
        let document: serde_json::Value = serde_json::from_str(&output).unwrap();
        let messages = document
            .pointer("/messages")
            .and_then(serde_json::Value::as_array)
            .unwrap();
        assert_eq!(messages.len(), 2, "{output}");
        let pinned = messages.first().unwrap();
        let event = messages.get(1).unwrap();
        assert_eq!(
            pinned.pointer("/data/id").and_then(serde_json::Value::as_i64),
            Some(i64::from(CAUSE_ID)),
            "the real interruption cause remains pinned: {output}"
        );
        assert!(
            pinned
                .get("error_message")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|line| line.starts_with("[id \"900\"]")),
            "the pinned real rule remains named: {output}"
        );
        assert_eq!(
            event.pointer("/data/id").and_then(serde_json::Value::as_i64),
            Some(0),
            "the non-pinned synthetic event keeps its own ID: {output}"
        );
        assert!(
            event
                .get("error_message")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|line| line.starts_with(&format!("[id \"0\"] [msg \"{STATE}: "))),
            "the retained event's identity begins with its actual state: {output}"
        );
        assert!(
            event
                .pointer("/data/tags")
                .and_then(serde_json::Value::as_array)
                .is_some_and(Vec::is_empty),
            "H-only does not serialize the event's K tags: {output}"
        );
        assert_eq!(
            event.pointer("/data/raw").and_then(serde_json::Value::as_str),
            Some(""),
            "H-only does not serialize the event's K raw label: {output}"
        );
    }

    #[test]
    fn a_reduced_h_and_k_event_keeps_state_in_each_selected_view() {
        const CAUSE_ID: i32 = 900;
        const STATE: &str = "coraza-rs/engine/OperatorNotInspected";
        const EVENT_MESSAGE: &str = "host operator refused to inspect input";

        let cause = AuditMessage {
            error_message: "long pinned H line".repeat(32),
            rule_id: CAUSE_ID,
            rule_message: "real blocking rule".to_owned(),
            ..AuditMessage::default()
        };
        let mut event = engine_event_message_with_state("OperatorNotInspected", EVENT_MESSAGE);
        event.error_message = "long engine H line".repeat(32);
        let mut budget = AuditCopyBudget::generous(1024);

        let copies = budget.planned_messages(
            &[cause, event],
            super::AuditMessageCopy::Json,
            super::AuditShrinkPlan {
                request_bytes: 0,
                message_bytes: 1024,
                message_each: Some(256),
                summary_each: None,
                message_count: 2,
                reduced: true,
            },
            super::AuditMessageSelection {
                interruption_rule_id: Some(CAUSE_ID),
                trailer_selected: true,
                rules_selected: true,
                compaction: super::AuditCompaction::Full,
            },
        );

        assert_eq!(copies.len(), 2);
        let event = copies.get(1).unwrap();
        assert!(
            event.error_message.starts_with(&format!("[id \"0\"] [msg \"{STATE}: ")),
            "H carries the state-first identity: {:?}",
            event.error_message
        );
        assert_eq!(event.data.msg, EVENT_MESSAGE, "K keeps the event message");
        assert_eq!(event.data.raw, STATE, "K keeps the event state label");
        assert_eq!(
            event.data.tags,
            [STATE],
            "K keeps a whole structured state tag when it fits"
        );
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
    #[expect(
        clippy::too_many_lines,
        reason = "Covers bounded identities across formats, parts, and engine modes."
    )]
    fn a_reduced_record_keeps_the_state_of_a_pinned_id_zero_engine_event() {
        const OUTPUT_LIMIT: usize = 1024;
        const STATE: &str = "coraza-rs/engine/RequestBodyLimit";
        const MESSAGE: &str = "RequestBodyLimit";
        let entry = |parts: &str, k_selected: bool, is_interrupted, interruption_rule_id| AuditLog {
            parts: parse_audit_log_parts(parts).unwrap(),
            transaction: AuditTransaction {
                id: "tx-engine".to_owned(),
                is_interrupted,
                interruption_rule_id,
                producer: Some(super::AuditProducer {
                    connector: "c".repeat(16 * 1024),
                    rulesets: vec!["r".repeat(16 * 1024)],
                    ..super::AuditProducer::default()
                }),
                ..AuditTransaction::default()
            },
            messages: vec![AuditMessage {
                message: if k_selected { MESSAGE.to_owned() } else { String::new() },
                error_message: format!("[id \"0\"] [msg \"{MESSAGE}\"]"),
                rule_id: 0,
                rule_message: format!("{STATE}: {MESSAGE}"),
                provenance: Some(super::AuditMessageProvenance::EngineEvent {
                    enforced: is_interrupted,
                }),
                data: AuditMessageData {
                    id: 0,
                    msg: if k_selected { MESSAGE.to_owned() } else { String::new() },
                    tags: if is_interrupted {
                        vec![STATE.to_owned(), super::ENGINE_ENFORCED_TAG.to_owned()]
                    } else {
                        vec![STATE.to_owned()]
                    },
                    raw: STATE.to_owned(),
                    ..AuditMessageData::default()
                },
                ..AuditMessage::default()
            }],
        };

        for (parts, shape, k_selected) in [("AKZ", "K-selected", true), ("AHZ", "H-only", false)] {
            for (mode, is_interrupted, interruption_rule_id) in [("On", true, Some(0)), ("DetectionOnly", false, None)]
            {
                let audit = entry(parts, k_selected, is_interrupted, interruption_rule_id);
                for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
                    let (formatted, truncated) = audit.format_bounded(format, OUTPUT_LIMIT);
                    assert!(truncated, "{mode} {shape} {format:?}: producer forces reduction");
                    assert!(
                        formatted.len() <= OUTPUT_LIMIT,
                        "{mode} {shape} {format:?}: {} bytes",
                        formatted.len()
                    );
                    let document: serde_json::Value = serde_json::from_str(&formatted).unwrap();
                    let identity = format!("[id \"0\"] [msg \"{STATE}: {MESSAGE}\"]");
                    if format == AuditLogFormat::Json && k_selected {
                        assert_eq!(
                            document
                                .pointer("/messages/0/error_message")
                                .and_then(serde_json::Value::as_str),
                            Some(""),
                            "{mode} {shape}: K-only output must not synthesize part H: {formatted}"
                        );
                        assert_eq!(
                            document
                                .pointer("/messages/0/data/msg")
                                .and_then(serde_json::Value::as_str),
                            Some(MESSAGE),
                            "{mode} {shape}: K keeps the event message: {formatted}"
                        );
                        assert_eq!(
                            document
                                .pointer("/messages/0/data/raw")
                                .and_then(serde_json::Value::as_str),
                            Some(STATE),
                            "{mode} {shape}: K keeps the synthetic state label: {formatted}"
                        );
                        continue;
                    }
                    let written_identity = match format {
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
                    let expected_identity = if format == AuditLogFormat::Ocsf && !k_selected {
                        format!("{STATE}: ")
                    } else {
                        identity.clone()
                    };
                    assert_eq!(
                        written_identity,
                        Some(expected_identity.as_str()),
                        "{mode} {shape} {format:?}: compact id-zero event lost its state/message: {formatted}"
                    );
                }
            }
        }
    }

    #[test]
    fn native_bounded_copy_keeps_omission_counts_whole_before_its_final_hard_cut() {
        const SUMMARY_TAG: &str = "coraza-rs/engine/EventsOmitted";
        const SUMMARY_TEXT: &str = "987654321 additional engine stop events summarized after the first 16 individual events; \
                                    the enforced stop is among omitted details";
        const FALLBACK: &str = "additional engine stop details omitted";
        const OUTPUT_LIMIT: usize = 320;

        let mut summary = engine_event_message_with_state("EventsOmitted", SUMMARY_TEXT);
        summary.data.tags.push(super::ENGINE_ENFORCED_OMITTED_TAG.to_owned());
        summary.provenance = Some(super::AuditMessageProvenance::EventsOmitted {
            enforced_stop_omitted: true,
        });
        let audit = native_audit("ACKZ", &"b".repeat(200), summary);
        let exact = audit.format(AuditLogFormat::Native);
        assert!(exact.contains(&format!("{SUMMARY_TAG}: {SUMMARY_TEXT}")));

        let (copy, truncated) = bounded_native_copy(&audit, OUTPUT_LIMIT);
        assert!(truncated, "the exact count does not fit the copy budget");
        let summary = copy.messages.first().unwrap();
        assert_eq!(summary.data.msg, FALLBACK);
        assert_eq!(summary.data.raw, SUMMARY_TAG);
        let before_hard_cut = copy.format(AuditLogFormat::Native);
        assert!(
            before_hard_cut.len() > OUTPUT_LIMIT,
            "this inspects the bounded copy before Native's separate final hard cut"
        );
        assert!(
            before_hard_cut.contains(&format!("{SUMMARY_TAG}: {FALLBACK}")),
            "Native uses a fixed statement instead of a partial count: {before_hard_cut:?}"
        );
        assert!(!before_hard_cut.contains("987654321"));
        assert!(!before_hard_cut.contains("the enforced stop is among omitted details"));

        let h_only = h_only_enforced_events_omitted_audit();
        let count_end = h_only
            .messages
            .first()
            .unwrap()
            .error_message
            .find("987654321")
            .unwrap()
            + 1;
        let mut budget = AuditCopyBudget::generous(count_end);
        let copied = budget.message(
            h_only.messages.first().unwrap(),
            super::AuditMessageCopy::Native {
                error: true,
                raw: false,
            },
            false,
        );
        assert!(budget.truncated, "the H error line cannot fit whole");
        assert!(copied.error_message.is_empty());
        assert!(
            !native_audit("AHZ", "", copied)
                .format(AuditLogFormat::Native)
                .contains("987654321"),
            "a part-H summary is omitted instead of ending after its first count digit"
        );

        let (full_copy, full_truncated) = bounded_native_copy(&audit, 16 * 1024);
        assert!(!full_truncated, "the full count and clause fit");
        assert!(
            full_copy
                .format(AuditLogFormat::Native)
                .contains(&format!("{SUMMARY_TAG}: {SUMMARY_TEXT}"))
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "The padded overflow fixture checks all three formats, both engine modes, and one-slot priority."
    )]
    fn a_reduced_audit_keeps_the_events_omitted_count_after_its_pinned_rule_when_two_fit() {
        const OUTPUT_LIMIT: usize = 2048;
        const CAUSE_ID: i32 = 900;
        const CAUSE_TEXT: &str = "interrupting rule 900";
        const SUMMARY_TEXT: &str = "48 additional engine stop events summarized after the first 16 individual events";
        const SUMMARY_TAG: &str = "coraza-rs/engine/EventsOmitted";

        let cause = AuditMessage {
            message: CAUSE_TEXT.to_owned(),
            error_message: format!("[id \"{CAUSE_ID}\"] [msg \"{CAUSE_TEXT}\"]"),
            rule_id: CAUSE_ID,
            rule_message: CAUSE_TEXT.to_owned(),
            data: AuditMessageData {
                id: CAUSE_ID,
                msg: CAUSE_TEXT.to_owned(),
                raw: "SecRule ARGS:q \"@contains blocked\" \"id:900,phase:1,deny\"".to_owned(),
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        };
        let mut messages = vec![cause];
        messages.extend((0..16).map(|index| {
            engine_event_message_with_state(
                "OperatorNotInspected",
                &format!("host operator refused to inspect input {index}: {}", "x".repeat(96)),
            )
        }));
        messages.push(engine_event_message_with_state("EventsOmitted", SUMMARY_TEXT));

        for (mode, is_interrupted, interruption_rule_id) in
            [("On", true, Some(CAUSE_ID)), ("DetectionOnly", false, None)]
        {
            let entry = AuditLog {
                parts: parse_audit_log_parts("ABHKZ").unwrap(),
                transaction: AuditTransaction {
                    id: format!("tx-overflow-{mode}"),
                    is_interrupted,
                    interruption_rule_id,
                    request: AuditRequest {
                        uri: format!("/{}", "p".repeat(16 * 1024)),
                        ..AuditRequest::default()
                    },
                    ..AuditTransaction::default()
                },
                messages: messages.clone(),
            };

            for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
                let (formatted, truncated) = entry.format_bounded(format, OUTPUT_LIMIT);
                assert!(truncated, "{mode} {format:?}: request padding forces reduction");
                assert!(
                    formatted.len() <= OUTPUT_LIMIT,
                    "{mode} {format:?}: {} bytes",
                    formatted.len()
                );
                let document: serde_json::Value = serde_json::from_str(&formatted).unwrap();
                assert!(document.is_object(), "{mode} {format:?}: {formatted}");

                let cause_kept = match format {
                    AuditLogFormat::Json => document
                        .pointer("/messages")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|messages| {
                            messages.iter().any(|message| {
                                message.pointer("/data/id").and_then(serde_json::Value::as_i64)
                                    == Some(i64::from(CAUSE_ID))
                                    && [
                                        message.pointer("/data/msg").and_then(serde_json::Value::as_str),
                                        message.get("message").and_then(serde_json::Value::as_str),
                                        message.get("error_message").and_then(serde_json::Value::as_str),
                                    ]
                                    .into_iter()
                                    .flatten()
                                    .any(|text| text.contains(CAUSE_TEXT))
                            })
                        }),
                    AuditLogFormat::JsonLegacy => document
                        .pointer("/audit_data/messages")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|messages| {
                            messages
                                .iter()
                                .any(|message| message.as_str().is_some_and(|text| text.contains(CAUSE_TEXT)))
                        }),
                    AuditLogFormat::Ocsf => document
                        .pointer("/enrichments")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|enrichments| {
                            enrichments.iter().any(|enrichment| {
                                let data = enrichment
                                    .get("data")
                                    .and_then(serde_json::Value::as_str)
                                    .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok());
                                data.as_ref()
                                    .and_then(|data| data.get("id"))
                                    .and_then(serde_json::Value::as_i64)
                                    == Some(i64::from(CAUSE_ID))
                                    && enrichment
                                        .get("name")
                                        .and_then(serde_json::Value::as_str)
                                        .is_some_and(|text| text.contains(CAUSE_TEXT))
                            })
                        }),
                    AuditLogFormat::Native => unreachable!(),
                };
                assert!(
                    cause_kept,
                    "{mode} {format:?}: the pinned cause keeps priority: {formatted}"
                );

                let summary_kept = match format {
                    AuditLogFormat::Json => document
                        .pointer("/messages")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|messages| {
                            messages.iter().any(|message| {
                                message.pointer("/data/id").and_then(serde_json::Value::as_i64) == Some(0)
                                    && message
                                        .pointer("/data/msg")
                                        .and_then(serde_json::Value::as_str)
                                        .is_some_and(|text| text == SUMMARY_TEXT)
                            })
                        }),
                    AuditLogFormat::JsonLegacy => document
                        .pointer("/audit_data/messages")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|messages| {
                            messages.iter().any(|message| {
                                message
                                    .as_str()
                                    .is_some_and(|text| text.contains(SUMMARY_TAG) && text.contains(SUMMARY_TEXT))
                            })
                        }),
                    AuditLogFormat::Ocsf => document
                        .pointer("/enrichments")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|enrichments| {
                            enrichments.iter().any(|enrichment| {
                                let data = enrichment
                                    .get("data")
                                    .and_then(serde_json::Value::as_str)
                                    .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok());
                                enrichment
                                    .get("name")
                                    .and_then(serde_json::Value::as_str)
                                    .is_some_and(|name| name == SUMMARY_TEXT)
                                    && data
                                        .as_ref()
                                        .and_then(|data| data.get("id"))
                                        .and_then(serde_json::Value::as_i64)
                                        == Some(0)
                            })
                        }),
                    AuditLogFormat::Native => unreachable!(),
                };
                assert!(
                    summary_kept,
                    "{mode} {format:?}: the exact EventsOmitted count fits after the pinned cause: {formatted}"
                );
            }
        }

        let mut budget = AuditCopyBudget::generous(512);
        let kept = budget.planned_messages(
            &messages,
            super::AuditMessageCopy::Json,
            super::AuditShrinkPlan {
                request_bytes: 0,
                message_bytes: 512,
                message_each: None,
                summary_each: None,
                message_count: 1,
                reduced: true,
            },
            super::AuditMessageSelection {
                interruption_rule_id: Some(CAUSE_ID),
                trailer_selected: true,
                rules_selected: true,
                compaction: super::AuditCompaction::Full,
            },
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(
            kept.first().map(|message| message.rule_id),
            Some(CAUSE_ID),
            "when one message fits, the summary cannot displace the interruption cause"
        );
    }

    #[test]
    fn compact_output_retries_the_events_omitted_summary_after_dropping_a_large_producer() {
        const OUTPUT_LIMIT: usize = 2048;
        const CAUSE_ID: i32 = 900;
        const SUMMARY_TEXT: &str = "48 additional engine stop events summarized after the first 16 individual events";

        let cause_text = "c".repeat(554);
        let cause = AuditMessage {
            message: cause_text.clone(),
            error_message: format!("[id \"{CAUSE_ID}\"] [msg \"cause\"]"),
            rule_id: CAUSE_ID,
            rule_message: "cause".to_owned(),
            data: AuditMessageData {
                id: CAUSE_ID,
                msg: cause_text,
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        };
        let mut messages = vec![cause];
        messages.extend((0..16).map(|index| {
            engine_event_message_with_state(
                "OperatorNotInspected",
                &format!("refused input {index}: {}", "x".repeat(320)),
            )
        }));
        messages.push(engine_event_message_with_state("EventsOmitted", SUMMARY_TEXT));

        let entry = AuditLog {
            parts: parse_audit_log_parts("ABHKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-large-producer".to_owned(),
                is_interrupted: true,
                interruption_rule_id: Some(CAUSE_ID),
                producer: Some(super::AuditProducer {
                    connector: "c".repeat(16 * 1024),
                    rulesets: vec!["r".repeat(16 * 1024)],
                    ..super::AuditProducer::default()
                }),
                ..AuditTransaction::default()
            },
            messages,
        };

        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            let (formatted, truncated) = entry.format_bounded(format, OUTPUT_LIMIT);
            assert!(truncated, "{format:?}: the large producer forces reduction");
            assert!(formatted.len() <= OUTPUT_LIMIT, "{format:?}: {} bytes", formatted.len());
            let document: serde_json::Value = serde_json::from_str(&formatted).unwrap();
            assert!(document.is_object(), "{format:?}: {formatted}");
            assert!(
                formatted.contains(&"c".repeat(32)),
                "{format:?}: the pinned 554-byte cause survives compaction: {formatted}"
            );
            assert!(
                formatted.contains(SUMMARY_TEXT),
                "{format:?}: compaction should retain the exact EventsOmitted summary when it fits: {formatted}"
            );
        }

        let (cause_only, truncated) = entry.format_bounded(AuditLogFormat::Json, 768);
        assert!(truncated, "the large producer forces compact fallback");
        assert!(cause_only.len() <= 768);
        let document: serde_json::Value = serde_json::from_str(&cause_only).unwrap();
        let kept = document
            .pointer("/messages")
            .and_then(serde_json::Value::as_array)
            .unwrap();
        assert_eq!(kept.len(), 1, "only the pinned cause fits: {cause_only}");
        assert_eq!(
            kept.first()
                .and_then(|message| message.pointer("/data/id"))
                .and_then(serde_json::Value::as_i64),
            Some(i64::from(CAUSE_ID)),
            "the summary never displaces the cause when only one message fits: {cause_only}"
        );
        assert!(!cause_only.contains(SUMMARY_TEXT), "{cause_only}");
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
    fn no_enforced_id_keeps_the_last_real_rule_before_appended_engine_events() {
        let mut messages: Vec<_> = (1..=999)
            .map(|id| AuditMessage {
                message: format!("rule-{id} {}", "m".repeat(200)),
                rule_id: id,
                rule_message: format!("rule-{id}"),
                data: AuditMessageData {
                    id,
                    msg: format!("rule-{id}"),
                    ..AuditMessageData::default()
                },
                ..AuditMessage::default()
            })
            .collect();
        let id_zero_rule = AuditMessage {
            message: "legitimate rule zero".to_owned(),
            rule_id: 0,
            rule_message: "coraza-rs/engine/RequestBodyLimit: legitimate rule zero".to_owned(),
            data: AuditMessageData {
                id: 0,
                msg: "legitimate rule zero".to_owned(),
                tags: vec!["coraza-rs/engine/RequestBodyLimit".to_owned()],
                raw: "SecAction \"id:0,phase:1,pass\"".to_owned(),
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        };
        assert!(
            !id_zero_rule.is_engine_event(),
            "a legitimate ID-zero rule is not synthetic"
        );
        messages.push(id_zero_rule);
        messages.push(engine_event_message("first engine stop"));
        messages.push(engine_event_message("later engine stop"));
        let entry = AuditLog {
            parts: parse_audit_log_parts("AHKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-detection-only".to_owned(),
                is_interrupted: false,
                interruption_rule_id: None,
                ..AuditTransaction::default()
            },
            messages,
        };

        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            let (formatted, truncated) = entry.format_bounded(format, 4096);
            assert!(truncated, "{format:?}: fixture must exercise reduction");
            assert!(formatted.len() <= 4096, "{format:?}: {} bytes", formatted.len());
            let document: serde_json::Value = serde_json::from_str(&formatted).unwrap();
            assert!(document.is_object(), "{format:?}: expected a JSON object");
            let kept = kept_messages(format, &formatted);
            assert!(
                kept.iter()
                    .any(|(id, text)| id.is_none_or(|id| id == 0) && text.starts_with("legitimate")),
                "{format:?}: the legacy last-rule fallback was displaced: {kept:?}"
            );
            assert!(
                !formatted.contains("first engine stop") && !formatted.contains("later engine stop"),
                "{format:?}: appended events displaced prior rule evidence: {formatted}"
            );
        }
    }

    #[test]
    fn enforced_id_zero_keeps_the_last_public_id_match_in_hand_built_records() {
        const EXPECTED: &str = "last-partial";
        let message = |text: &str, rule_id, data_id, k_selected| AuditMessage {
            message: if k_selected { text.to_owned() } else { String::new() },
            error_message: format!("[id \"{rule_id}\"] [msg \"{text}\"]"),
            rule_id,
            rule_message: text.to_owned(),
            data: AuditMessageData {
                id: data_id,
                msg: if k_selected { text.to_owned() } else { String::new() },
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        };

        for (parts, k_selected) in [("AHZ", false), ("AKZ", true)] {
            let entry = AuditLog {
                parts: parse_audit_log_parts(parts).unwrap(),
                transaction: AuditTransaction {
                    id: "tx-hand-built-zero".to_owned(),
                    is_interrupted: true,
                    interruption_rule_id: Some(0),
                    producer: Some(super::AuditProducer {
                        connector: "c".repeat(16 * 1024),
                        rulesets: vec!["r".repeat(16 * 1024)],
                        ..super::AuditProducer::default()
                    }),
                    ..AuditTransaction::default()
                },
                messages: vec![
                    message("ordinary-id-zero-first", 0, 0, k_selected),
                    message("ordinary-id-zero-second", 0, 0, k_selected),
                    message("rule-id-only-zero", 0, 7, k_selected),
                    message(EXPECTED, 7, 0, k_selected),
                    message("neither-id-zero", 8, 9, k_selected),
                ],
            };

            for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
                let (formatted, truncated) = entry.format_bounded(format, 4096);
                assert!(truncated, "{parts} {format:?}: producer forces reduction");
                assert!(formatted.len() <= 4096, "{parts} {format:?}: {} bytes", formatted.len());
                let document: serde_json::Value = serde_json::from_str(&formatted).unwrap();
                assert!(document.is_object(), "{parts} {format:?}: {formatted}");
                assert_eq!(
                    kept_messages(format, &formatted).len(),
                    1,
                    "{parts} {format:?}: the fixture must reduce to one pinned message: {formatted}"
                );
                assert!(
                    formatted.contains(EXPECTED),
                    "{parts} {format:?}: the last `rule_id == 0 || data.id == 0` message must remain: {formatted}"
                );
                assert!(
                    !formatted.contains("ordinary-id-zero-first")
                        && !formatted.contains("ordinary-id-zero-second")
                        && !formatted.contains("rule-id-only-zero")
                        && !formatted.contains("neither-id-zero"),
                    "{parts} {format:?}: a different hand-built message was pinned: {formatted}"
                );
            }
        }
    }

    #[test]
    fn enforced_id_zero_keeps_a_hand_built_id_zero_rule_when_there_is_no_engine_event() {
        const MESSAGE: &str = "hand-built ID zero";
        let later_rule = |id| AuditMessage {
            message: format!("later rule {id} {}", "m".repeat(200)),
            rule_id: id,
            rule_message: format!("later rule {id}"),
            data: AuditMessageData {
                id,
                msg: format!("later rule {id}"),
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        };
        let id_zero_rule = AuditMessage {
            message: MESSAGE.to_owned(),
            rule_id: 0,
            rule_message: MESSAGE.to_owned(),
            data: AuditMessageData {
                id: 0,
                msg: MESSAGE.to_owned(),
                raw: "SecAction \"id:0,phase:1,pass\"".to_owned(),
                ..AuditMessageData::default()
            },
            ..AuditMessage::default()
        };
        let mut messages: Vec<_> = (1..=300).map(later_rule).collect();
        messages.insert(150, id_zero_rule);
        assert!(
            messages.iter().all(|message| !message.is_engine_event()),
            "the hand-built ID-zero rule is not a synthetic event"
        );
        let entry = AuditLog {
            parts: parse_audit_log_parts("AKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-hand-built-zero".to_owned(),
                is_interrupted: true,
                interruption_rule_id: Some(0),
                ..AuditTransaction::default()
            },
            messages,
        };

        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            let (formatted, truncated) = entry.format_bounded(format, 4096);
            assert!(truncated, "{format:?}: fixture must exercise reduction");
            assert!(formatted.len() <= 4096, "{format:?}: {} bytes", formatted.len());
            let kept = kept_messages(format, &formatted);
            assert!(
                kept.iter()
                    .any(|(id, text)| id.is_none_or(|id| id == 0) && text.starts_with("hand-built")),
                "{format:?}: ID-zero fallback was displaced: {kept:?}"
            );
        }
    }

    #[test]
    fn the_first_engine_event_is_kept_when_there_are_no_rule_messages() {
        let mut messages = vec![engine_event_message_with_state(
            "First",
            &format!("first engine stop {}", "m".repeat(200)),
        )];
        messages.extend((1..100).map(|index| {
            engine_event_message_with_state(
                &format!("Later{index}"),
                &format!("engine stop {index} {}", "m".repeat(200)),
            )
        }));
        let entry = AuditLog {
            parts: parse_audit_log_parts("AHKZ").unwrap(),
            transaction: AuditTransaction {
                id: "tx-engine-only".to_owned(),
                is_interrupted: false,
                interruption_rule_id: None,
                ..AuditTransaction::default()
            },
            messages,
        };

        for format in [AuditLogFormat::Json, AuditLogFormat::JsonLegacy, AuditLogFormat::Ocsf] {
            let (formatted, truncated) = entry.format_bounded(format, 4096);
            assert!(truncated, "{format:?}: fixture must exercise reduction");
            assert!(formatted.len() <= 4096, "{format:?}: {} bytes", formatted.len());
            let document: serde_json::Value = serde_json::from_str(&formatted).unwrap();
            assert!(document.is_object(), "{format:?}: expected a JSON object");
            assert!(
                formatted.contains("coraza-rs/engine/First"),
                "{format:?}: no engine identity was retained: {formatted}"
            );
            assert!(
                !formatted.contains("coraza-rs/engine/Later99"),
                "{format:?}: a later engine event displaced the first: {formatted}"
            );
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
            summary_each: None,
            message_count: 100_001_usize.min(AuditCopyBudget::generous(16 * 1024).items_left),
            reduced: false,
        };
        let mut budget = AuditCopyBudget::generous(16 * 1024);
        let view = entry.bounded_copy_planned(
            AuditLogFormat::Json,
            &mut budget,
            Some(plan),
            super::AuditCompaction::Full,
        );
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
