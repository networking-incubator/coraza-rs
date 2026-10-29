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

//! WAF configuration and transaction creation.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use crate::{
    audit_log::{AuditLogCallback, AuditLogRegistry, AuditLogger, ErrorLog},
    config::{UploadKeepFiles, WafConfig},
    debug_log::{DebugEvent, DebugLevel, DebugLogger, Writer, noop_logger},
    rules::RuleGroup,
    transaction::Transaction,
};

/// Next process-unique transaction identifier suffix.
static NEXT_TRANSACTION_ID: AtomicU64 = AtomicU64::new(1);

/// An invalid WAF configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid WAF configuration: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// A thread-safe WAF containing compiled SecLang rules and configuration.
///
/// The runtime evaluates request and response header/body rules. Request bodies support
/// RAW, URLENCODED, JSON, XML, and multipart/form-data processing, including temporary
/// upload files. Response bodies support raw storage and JSON argument parsing. Audit
/// logging is available through the configured writer. The deferred `exec`,
/// `initcol`, and `expirevar` effects are not implemented.
pub struct Waf {
    /// Configuration inherited by each transaction.
    config: Arc<WafConfig>,
    /// Compiled rules shared by each transaction.
    rules: Arc<RuleGroup>,
    /// Writer shared by transactions created by this WAF.
    audit_logger: Arc<AuditLogger>,
    /// Optional connector callback for rules with the `log` action.
    error_log: Option<ErrorLog>,
    /// Debug sink shared with transactions.
    debug_logger: Arc<dyn DebugLogger>,
    /// Built-in file sink, retained so activation failures can be returned and inspected.
    debug_writer: Option<Arc<Writer>>,
    /// Delay the construction event until after `Parser::compile` has returned.
    construction_logged: AtomicBool,
    /// Optional connector-owned audit entry sink.
    audit_log: Option<AuditLogCallback>,
}

impl std::fmt::Debug for Waf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Waf")
            .field("config", &self.config)
            .field("rules", &self.rules)
            .field("audit_logger", &self.audit_logger)
            .field("error_log", &self.error_log)
            .field("debug_writer", &self.debug_writer)
            .finish_non_exhaustive()
    }
}

impl Waf {
    /// Create a WAF without rules.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits, incompatible upload settings, or invalid
    /// audit logging configuration. Log sinks are not opened here.
    pub fn new(config: WafConfig) -> Result<Self, ConfigError> {
        Self::with_rules(config, RuleGroup::new(), None, None, None, &AuditLogRegistry::default())
    }

    /// Create a WAF from configuration and compiled rules.
    ///
    /// `RuleGroup` is crate-private, so this is the only place a compiled rule set is
    /// paired with a configuration; embedders cannot bypass it. The parser records the
    /// `case_sensitive_args_keys` mode the rules were compiled under because it selects
    /// the transaction's argument maps; a configuration with a different mode is rejected
    /// so those maps cannot disagree with the rule set. Key selectors are compiled from
    /// their variable alone, independently of the mode. The multiphase setting is also
    /// recorded when rules are compiled and cannot be changed for the resulting WAF.
    ///
    /// Audit sinks are validated but not opened: [`Waf::activate`] or the first
    /// [`Transaction::finish`] that writes an entry opens them. The debug sink is also
    /// deferred until activation or its first enabled event, so a candidate policy can be
    /// compiled and discarded without creating log files or connecting.
    // Callers are the parser and `Waf::new`; each optional sink stays a distinct
    // parameter so none can be silently dropped or reordered.
    #[expect(clippy::too_many_arguments, reason = "host sinks are distinct constructor inputs")]
    pub(crate) fn with_rules(
        config: WafConfig,
        rules: RuleGroup,
        error_log: Option<ErrorLog>,
        debug_logger: Option<Arc<dyn DebugLogger>>,
        audit_log: Option<AuditLogCallback>,
        audit_log_registry: &AuditLogRegistry,
    ) -> Result<Self, ConfigError> {
        validate_config(&config)?;
        if let Some(compiled) = rules.compiled_case_sensitive_args_keys()
            && compiled != config.case_sensitive_args_keys
        {
            return Err(ConfigError(format!(
                "case_sensitive_args_keys was {compiled} when the rules were compiled but is {} in the \
                 configuration",
                config.case_sensitive_args_keys
            )));
        }
        if let Some(compiled) = rules.compiled_multiphase_evaluation()
            && compiled != config.multiphase_evaluation
        {
            return Err(ConfigError(format!(
                "multiphase_evaluation was {compiled} when the rules were compiled but is {} in the \
                 configuration",
                config.multiphase_evaluation
            )));
        }
        let audit_logger = AuditLogger::prepare(&config, audit_log_registry).map_err(ConfigError)?;
        let debug_writer = (debug_logger.is_none() && !config.debug_log.is_empty())
            .then(|| Arc::new(Writer::new(config.debug_log.clone())));
        let debug_logger: Arc<dyn DebugLogger> = match debug_logger {
            Some(logger) => logger,
            None => match &debug_writer {
                Some(writer) => {
                    let writer = Arc::clone(writer);
                    let logger: Arc<dyn DebugLogger> = writer;
                    logger
                },
                None => noop_logger(),
            },
        };
        Ok(Self {
            config: Arc::new(config),
            rules: Arc::new(rules),
            audit_logger: Arc::new(audit_logger),
            error_log,
            debug_logger,
            debug_writer,
            construction_logged: AtomicBool::new(false),
            audit_log,
        })
    }

    /// Use a host-provided debug sink instead of the configured file sink.
    ///
    /// The configured `debug_log_level` remains the WAF-wide threshold. Transactions
    /// created before this call retain their existing logger.
    #[must_use]
    pub fn with_debug_logger(mut self, logger: Arc<dyn DebugLogger>) -> Self {
        self.debug_logger = logger;
        self.debug_writer = None;
        self
    }

    /// Open configured debug and audit sinks without creating a transaction.
    ///
    /// Idempotent and thread-safe. The debug file opens once; audit activation retains its
    /// existing retry behavior: this explicit path retries a failed audit activation
    /// immediately, while internal callers wait for the audit writer's backoff. A syslog
    /// dial the configuration leaves unbounded stays unbounded here, unlike the internal
    /// path, which bounds it.
    ///
    /// # Errors
    ///
    /// Returns the sink's own [`std::io::Error`], with its kind, when a configured debug
    /// or audit sink cannot be opened or connected. A sink failure is not a configuration
    /// error: those are reported by [`Waf::new`] and [`Parser::compile`].
    ///
    /// [`Parser::compile`]: crate::seclang::Parser::compile
    pub fn activate(&self) -> std::io::Result<()> {
        let debug_result = self.debug_writer.as_ref().map_or(Ok(()), |writer| writer.activate());
        let audit_result = self.audit_logger.activate();
        if audit_result.is_err() {
            self.log_waf_event(DebugLevel::Error, "Audit log activation failed");
        }
        audit_result?;
        if let Err(error) = debug_result {
            self.log_waf_event(DebugLevel::Error, "Debug log activation failed");
            return Err(error);
        }
        if !self.config.audit_log.is_empty() {
            self.log_waf_event(DebugLevel::Info, "Audit log activated");
        }
        self.log_waf_created_once();
        Ok(())
    }

    /// The most recent built-in debug sink open or write failure, if any.
    pub fn debug_log_error(&self) -> Option<(std::io::ErrorKind, String)> {
        self.debug_writer.as_ref().and_then(|writer| writer.activation_error())
    }

    /// The audit writer failure from the last activation attempt, with its error kind.
    ///
    /// Returns `Some` while the configured sink cannot be opened, and `None` before any
    /// attempt and after one succeeds. [`Waf::activate`] or the first
    /// [`Transaction::finish`] that writes an entry attempts activation, so an embedder
    /// that never calls either sees `None`; a failure reported by `finish` or discarded by
    /// `Drop` stays visible here until a later attempt succeeds.
    pub fn activation_error(&self) -> Option<(std::io::ErrorKind, String)> {
        self.audit_logger.activation_error()
    }

    /// Create a transaction with a process-unique identifier.
    pub fn new_transaction(&self) -> Transaction {
        let id = NEXT_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed);
        self.new_transaction_with_id(format!("coraza-{id}"))
    }

    /// Create a transaction with a caller-supplied identifier.
    ///
    /// Does not open the audit writer: [`Transaction::finish`] activates it on the first
    /// entry it writes, and [`Waf::activate`] opens it explicitly. A configured debug
    /// writer opens only if this transaction's first enabled event is logged. Creating a
    /// transaction never blocks on an audit connection.
    ///
    /// Audit activation failures surface from [`Transaction::finish`] or through
    /// [`Waf::activation_error`]. Debug sink failures are available through
    /// [`Waf::debug_log_error`]. The transaction layer does not retry audit activation:
    /// internal callers wait for the writer's growing retry backoff, and the syslog
    /// writer reconnects and re-sends a frame after a write failure.
    pub fn new_transaction_with_id(&self, id: impl Into<String>) -> Transaction {
        self.log_waf_created_once();
        let mut transaction = Transaction::with_rules(Arc::clone(&self.config), Arc::clone(&self.rules), id);
        transaction.set_audit_logger(Arc::clone(&self.audit_logger));
        transaction.set_debug_logger(Arc::clone(&self.debug_logger));
        if let Some(error_log) = &self.error_log {
            transaction.set_error_log(error_log.clone());
        }
        transaction.debug_log(DebugLevel::Debug, "Transaction started", || []);
        if let Some(audit_log) = &self.audit_log {
            transaction.set_audit_log_callback(audit_log.clone());
        }
        transaction
    }

    /// Whether the WAF's configured threshold and sink accept `level`.
    fn debug_level_enabled(&self, level: DebugLevel) -> bool {
        self.config.debug_log_level >= level.as_u8() && self.debug_logger.enabled(level)
    }

    /// Emit a WAF event without constructing fields when it is filtered out.
    fn log_waf_event(&self, level: DebugLevel, message: &'static str) {
        if self.debug_level_enabled(level) {
            self.debug_logger.log(level, &DebugEvent { message, fields: &[] });
        }
    }

    /// Defer the WAF-created event until activation or the first transaction.
    fn log_waf_created_once(&self) {
        if !self.construction_logged.swap(true, Ordering::AcqRel) {
            self.log_waf_event(DebugLevel::Debug, "A new WAF instance was created");
        }
    }

    /// Return the WAF configuration.
    pub fn config(&self) -> &WafConfig {
        &self.config
    }

    /// Return the number of top-level compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rules.count()
    }
}

impl Default for Waf {
    fn default() -> Self {
        let config = Arc::new(WafConfig::default());
        Self {
            config,
            rules: Arc::new(RuleGroup::new()),
            audit_logger: Arc::new(AuditLogger::discard()),
            error_log: None,
            debug_logger: noop_logger(),
            debug_writer: None,
            construction_logged: AtomicBool::new(false),
            audit_log: None,
        }
    }
}

/// Go's `_1gib`: the largest body limit a configuration may set
/// (`internal/corazawaf/waf.go:322,443-464`, v3.8.1).
const MAX_BODY_LIMIT: i64 = 1_073_741_824;

/// Validate settings enforced by WAF and transaction construction.
fn validate_config(config: &WafConfig) -> Result<(), ConfigError> {
    if config.request_body_limit <= 0 {
        return Err(ConfigError("request body limit must be greater than 0".to_owned()));
    }
    if config.request_body_limit > MAX_BODY_LIMIT {
        return Err(ConfigError("request body limit must be at most 1GiB".to_owned()));
    }
    if config.response_body_limit <= 0 {
        return Err(ConfigError("response body limit must be greater than 0".to_owned()));
    }
    if config.response_body_limit > MAX_BODY_LIMIT {
        return Err(ConfigError("response body limit must be at most 1GiB".to_owned()));
    }
    if config.request_body_in_memory_limit < 0 {
        return Err(ConfigError(
            "request body in-memory limit must be non-negative".to_owned(),
        ));
    }
    // Zero means unset; a positive limit may not exceed the body limit. This matches Go
    // (internal/corazawaf/waf.go:448-457).
    if config.request_body_in_memory_limit > config.request_body_limit {
        return Err(ConfigError(
            "request body limit must be at least the in-memory limit".to_owned(),
        ));
    }
    if config.request_body_no_files_limit < 0 {
        return Err(ConfigError(
            "request body no-files limit must be non-negative".to_owned(),
        ));
    }
    if config.collection_timeout < 0 {
        return Err(ConfigError("collection timeout must be non-negative".to_owned()));
    }
    if config.debug_log_level > 9 {
        return Err(ConfigError("debug log level must be between 0 and 9".to_owned()));
    }
    if config.argument_limit == 0 {
        return Err(ConfigError("argument limit must be greater than 0".to_owned()));
    }
    if config.upload_keep_files != UploadKeepFiles::Off && config.upload_dir.is_empty() {
        return Err(ConfigError(
            "upload directory is required when uploaded files are kept".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "WAF tests use fixed valid configurations")]
mod tests {
    use super::Waf;
    use crate::{
        config::WafConfig,
        types::{AuditEngineStatus, AuditLogType},
    };

    fn audit_file_config(path: &std::path::Path) -> WafConfig {
        WafConfig {
            audit_engine: AuditEngineStatus::On,
            audit_log: path.to_string_lossy().into_owned(),
            ..WafConfig::default()
        }
    }

    #[test]
    fn activation_is_explicit_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let waf = Waf::new(audit_file_config(&path)).unwrap();

        // Construction validates the target without creating it.
        assert!(!path.exists());
        waf.activate().unwrap();
        assert!(path.exists());
        waf.activate().unwrap();
    }

    #[test]
    fn new_transaction_does_not_open_the_audit_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let waf = Waf::new(audit_file_config(&path)).unwrap();

        let mut transaction = waf.new_transaction_with_id("opens-on-finish");
        assert!(!path.exists(), "creating a transaction opened the audit writer");
        assert!(
            waf.activation_error().is_none(),
            "creating a transaction attempted activation"
        );

        transaction.finish().unwrap();
        assert!(path.exists(), "finish did not open the audit writer");
    }

    #[cfg(unix)]
    #[test]
    fn creating_transactions_against_an_unreachable_sink_does_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("syslog.sock");
        let waf = Waf::new(WafConfig {
            audit_engine: AuditEngineStatus::On,
            audit_log_type: AuditLogType::Syslog,
            audit_log: format!("unix://{}", socket.display()),
            ..WafConfig::default()
        })
        .unwrap();

        let mut transaction = waf.new_transaction_with_id("no-dial-on-create");
        assert!(
            waf.activation_error().is_none(),
            "creating a transaction dialed the audit sink"
        );

        let error = transaction.finish().unwrap_err();
        assert!(error.to_string().contains("syslog dial failure"), "{error}");
        assert!(
            waf.activation_error()
                .is_some_and(|(_, error)| error.contains("syslog dial failure")),
            "finish did not record the activation failure"
        );
    }

    #[cfg(unix)]
    #[test]
    fn activating_twice_connects_a_syslog_writer_once() {
        use std::{io, os::unix::net::UnixListener};

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("syslog.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let waf = Waf::new(WafConfig {
            audit_log_type: AuditLogType::Syslog,
            audit_log: format!("unix://{}", socket.display()),
            ..WafConfig::default()
        })
        .unwrap();

        listener.set_nonblocking(true).unwrap();
        let waiting = listener.accept();
        assert!(
            matches!(&waiting, Err(error) if error.kind() == io::ErrorKind::WouldBlock),
            "{waiting:?}"
        );
        drop(waiting);
        listener.set_nonblocking(false).unwrap();

        waf.activate().unwrap();
        drop(listener.accept().unwrap());
        waf.activate().unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(listener.accept().is_err(), "activation connected twice");
    }

    #[cfg(unix)]
    #[test]
    fn activation_failure_is_memoised_until_its_backoff_passes() {
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("syslog.sock");
        let waf = Waf::new(WafConfig {
            audit_engine: AuditEngineStatus::On,
            audit_log_type: AuditLogType::Syslog,
            audit_log: format!("unix://{}", socket.display()),
            ..WafConfig::default()
        })
        .unwrap();

        let mut before = waf.new_transaction_with_id("before-listener");
        assert!(before.finish().is_err(), "activation has no socket to connect");
        let failure = waf.activation_error().unwrap();

        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut memoised = waf.new_transaction_with_id("memoised-failure");
        assert!(
            memoised
                .finish()
                .is_err_and(|error| error.to_string().contains("syslog dial failure")),
            "a transaction inside the backoff must reuse the memoised failure"
        );
        assert!(
            listener.accept().is_err(),
            "a transaction inside the backoff retried the activation"
        );
        assert_eq!(
            waf.activation_error(),
            Some(failure),
            "an internal retry replaced the stored failure"
        );

        waf.audit_logger.expire_backoff();
        let mut retried = waf.new_transaction_with_id("after-backoff");
        retried.finish().unwrap();
        let (connection, _) = listener.accept().unwrap();
        assert!(
            waf.activation_error().is_none(),
            "a successful retry must clear the stored failure"
        );

        waf.activate().unwrap();
        drop(connection);
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_activation_opens_one_syslog_connection() {
        use std::{
            os::unix::net::UnixListener,
            sync::{Arc, Barrier},
        };

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("syslog.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let waf = Arc::new(
            Waf::new(WafConfig {
                audit_log_type: AuditLogType::Syslog,
                audit_log: format!("unix://{}", socket.display()),
                ..WafConfig::default()
            })
            .unwrap(),
        );

        let barrier = Arc::new(Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let waf = Arc::clone(&waf);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    waf.activate()
                })
            })
            .collect();

        drop(listener.accept().unwrap());
        for thread in threads {
            thread.join().unwrap().unwrap();
        }

        listener.set_nonblocking(true).unwrap();
        assert!(
            listener.accept().is_err(),
            "concurrent activation opened more than one connection"
        );
    }

    #[test]
    fn rejects_a_syslog_target_go_cannot_dial() {
        for target in ["tcp://", "udp://", "unix://", "kafka://broker:9092"] {
            let config = WafConfig {
                audit_log_type: AuditLogType::Syslog,
                audit_log: target.to_owned(),
                ..WafConfig::default()
            };
            assert!(Waf::new(config).is_err(), "{target}");
        }
    }

    #[cfg(not(unix))]
    #[test]
    fn rejects_an_empty_syslog_target() {
        // An empty target selects the local syslog, which only exists on Unix; accepting it
        // here would build a WAF whose every audit write fails.
        let config = WafConfig {
            audit_log_type: AuditLogType::Syslog,
            audit_log: String::new(),
            ..WafConfig::default()
        };
        assert!(Waf::new(config).is_err());
    }

    #[test]
    fn an_activation_failure_keeps_its_error_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing").join("audit.log");
        let waf = Waf::new(audit_file_config(&path)).unwrap();

        let mut transaction = waf.new_transaction_with_id("missing-directory");
        let error = transaction.finish().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound, "{error}");
        assert!(error.to_string().contains("cannot open audit log"), "{error}");

        // The explicit path reports the same dial failure as an I/O error, not as a
        // configuration error, and the memoised copy keeps the kind.
        assert_eq!(waf.activate().unwrap_err().kind(), std::io::ErrorKind::NotFound);
        assert_eq!(
            waf.activation_error().map(|(kind, _)| kind),
            Some(std::io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn a_failure_costs_one_bounded_attempt_per_window() {
        use std::time::{Duration, Instant};

        // TEST-NET-1 is not routable, so an unbounded dial would wait for the kernel's SYN
        // timeout. A host without a default route fails at once, which is equally fine: the
        // attempt must be bounded, not slow.
        let waf = Waf::new(WafConfig {
            audit_engine: AuditEngineStatus::On,
            audit_log_type: AuditLogType::Syslog,
            audit_log: "tcp://192.0.2.1:9".to_owned(),
            ..WafConfig::default()
        })
        .unwrap();

        let started = Instant::now();
        let mut first = waf.new_transaction_with_id("bounded-dial");
        assert!(first.finish().is_err(), "an unroutable peer cannot connect");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(7),
            "the internal dial was not bounded: {elapsed:?}"
        );
        assert_eq!(waf.audit_logger.attempts(), 1);

        let started = Instant::now();
        let mut second = waf.new_transaction_with_id("inside-the-window");
        assert!(second.finish().is_err());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "an attempt inside the window waited: {:?}",
            started.elapsed()
        );
        assert_eq!(
            waf.audit_logger.attempts(),
            1,
            "an attempt inside the window dialed again"
        );
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_finish_calls_attempt_once_per_window() {
        use std::sync::{Arc, Barrier};

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("syslog.sock");
        let waf = Arc::new(
            Waf::new(WafConfig {
                audit_engine: AuditEngineStatus::On,
                audit_log_type: AuditLogType::Syslog,
                audit_log: format!("unix://{}", socket.display()),
                ..WafConfig::default()
            })
            .unwrap(),
        );

        let barrier = Arc::new(Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|index| {
                let waf = Arc::clone(&waf);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    waf.new_transaction_with_id(format!("concurrent-{index}")).finish()
                })
            })
            .collect();

        for thread in threads {
            assert!(thread.join().unwrap().is_err(), "no listener is bound");
        }
        assert_eq!(
            waf.audit_logger.attempts(),
            1,
            "concurrent finishes dialed more than once in one window"
        );
    }

    #[test]
    fn validates_request_body_memory_limit_against_the_body_limit() {
        assert!(
            Waf::new(WafConfig {
                request_body_in_memory_limit: -1,
                ..WafConfig::default()
            })
            .is_err()
        );
        assert!(
            Waf::new(WafConfig {
                request_body_limit: 1024,
                request_body_in_memory_limit: 2048,
                ..WafConfig::default()
            })
            .is_err()
        );
        assert!(
            Waf::new(WafConfig {
                request_body_limit: 1024,
                request_body_in_memory_limit: 1024,
                ..WafConfig::default()
            })
            .is_ok()
        );
        assert!(
            Waf::new(WafConfig {
                request_body_limit: 1024,
                request_body_in_memory_limit: 0,
                ..WafConfig::default()
            })
            .is_ok()
        );
    }

    #[test]
    fn rejects_body_limits_outside_go_range() {
        for limit in [0, -1, 1_073_741_825] {
            assert!(
                Waf::new(WafConfig {
                    request_body_limit: limit,
                    ..WafConfig::default()
                })
                .is_err(),
                "request body limit {limit}"
            );
        }
        assert!(
            Waf::new(WafConfig {
                response_body_limit: 0,
                ..WafConfig::default()
            })
            .is_err()
        );
        assert!(
            Waf::new(WafConfig {
                response_body_limit: -1,
                ..WafConfig::default()
            })
            .is_err()
        );
        assert!(
            Waf::new(WafConfig {
                response_body_limit: 1_073_741_825,
                ..WafConfig::default()
            })
            .is_err()
        );

        for limit in [1, 1024, 1_073_741_824] {
            assert!(
                Waf::new(WafConfig {
                    request_body_limit: limit,
                    response_body_limit: limit,
                    request_body_in_memory_limit: 0,
                    ..WafConfig::default()
                })
                .is_ok(),
                "body limit {limit}"
            );
        }
    }

    #[test]
    fn validates_configuration_and_creates_transactions() {
        assert!(
            Waf::new(WafConfig {
                argument_limit: 0,
                ..WafConfig::default()
            })
            .is_err()
        );

        let waf = Waf::new(WafConfig::default()).unwrap();
        assert_eq!(waf.rule_count(), 0);
        assert_eq!(waf.new_transaction_with_id("request-1").id(), "request-1");
        assert_ne!(waf.new_transaction().id(), waf.new_transaction().id());
    }
}
