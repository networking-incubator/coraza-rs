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
    atomic::{AtomicU64, Ordering},
};

use crate::{
    audit_log::{AuditLogger, ErrorLog},
    config::{UploadKeepFiles, WafConfig},
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
#[derive(Debug)]
pub struct Waf {
    /// Configuration inherited by each transaction.
    config: Arc<WafConfig>,
    /// Compiled rules shared by each transaction.
    rules: Arc<RuleGroup>,
    /// Writer shared by transactions created by this WAF.
    audit_logger: Arc<AuditLogger>,
    /// Optional connector callback for rules with the `log` action.
    error_log: Option<ErrorLog>,
}

impl Waf {
    /// Create a WAF without rules.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits, incompatible upload settings, or invalid
    /// audit logging configuration. Audit writers are not opened here.
    pub fn new(config: WafConfig) -> Result<Self, ConfigError> {
        Self::with_rules(config, RuleGroup::new(), None)
    }

    /// Create a WAF from configuration and compiled rules.
    ///
    /// `RuleGroup` is crate-private, so this is the only place a compiled rule set is
    /// paired with a configuration; embedders cannot bypass it. Rules compiled by the
    /// SecLang parser carry the `case_sensitive_args_keys` mode their key selectors were
    /// compiled under, and a configuration with a different mode is rejected so compiled
    /// selectors and transaction maps cannot disagree.
    ///
    /// Audit sinks are validated but not opened: [`Waf::activate`] or the first
    /// [`Waf::new_transaction`] opens them, so a candidate policy can be compiled and
    /// discarded without creating files or connecting.
    pub(crate) fn with_rules(
        config: WafConfig,
        rules: RuleGroup,
        error_log: Option<ErrorLog>,
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
        let audit_logger = AuditLogger::prepare(&config).map_err(ConfigError)?;
        Ok(Self {
            config: Arc::new(config),
            rules: Arc::new(rules),
            audit_logger: Arc::new(audit_logger),
            error_log,
        })
    }

    /// Open the audit writer, if one is configured, without creating a transaction.
    ///
    /// Idempotent and thread-safe: the first successful call opens the writer and later
    /// calls return `Ok(())` without opening it again. A failed call leaves it unopened,
    /// so a later call retries.
    ///
    /// # Errors
    ///
    /// If the configured audit writer cannot be opened or connected.
    pub fn activate(&self) -> Result<(), ConfigError> {
        self.audit_logger
            .activate()
            .map_err(|error| ConfigError(error.to_string()))
    }

    /// Create a transaction with a process-unique identifier.
    pub fn new_transaction(&self) -> Transaction {
        let id = NEXT_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed);
        self.new_transaction_with_id(format!("coraza-{id}"))
    }

    /// Create a transaction with a caller-supplied identifier.
    ///
    /// Activates the audit writer first, as Go Coraza initializes its writer lazily.
    /// The constructor is infallible, so an activation failure is recorded nowhere here
    /// and surfaces from [`Transaction::finish`] when the entry is written.
    pub fn new_transaction_with_id(&self, id: impl Into<String>) -> Transaction {
        // Best effort: a failure stays observable from `Transaction::finish`.
        drop(self.audit_logger.activate());
        let mut transaction = Transaction::with_rules(Arc::clone(&self.config), Arc::clone(&self.rules), id);
        transaction.set_audit_logger(Arc::clone(&self.audit_logger));
        if let Some(error_log) = &self.error_log {
            transaction.set_error_log(error_log.clone());
        }
        transaction
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
        }
    }
}

/// Validate settings enforced by WAF and transaction construction.
fn validate_config(config: &WafConfig) -> Result<(), ConfigError> {
    if config.request_body_limit < 0 {
        return Err(ConfigError("request body limit must be non-negative".to_owned()));
    }
    if config.response_body_limit < 0 {
        return Err(ConfigError("response body limit must be non-negative".to_owned()));
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
    fn new_transaction_activates_the_audit_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let waf = Waf::new(audit_file_config(&path)).unwrap();
        assert!(!path.exists());

        drop(waf.new_transaction_with_id("activates-on-create"));
        assert!(path.exists());
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
