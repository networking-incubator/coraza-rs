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

use crate::{config::WafConfig, rules::RuleGroup, transaction::Transaction};

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
/// The current runtime evaluates request-header and request-body rules. Request bodies
/// support RAW and URLENCODED processing; other body processors and response phases,
/// audit logging, and remaining compiled action effects are not implemented yet.
#[derive(Debug)]
pub struct Waf {
    /// Configuration inherited by each transaction.
    config: Arc<WafConfig>,
    /// Compiled rules shared by each transaction.
    rules: Arc<RuleGroup>,
}

impl Waf {
    /// Create a WAF without rules.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits or incompatible upload settings.
    pub fn new(config: WafConfig) -> Result<Self, ConfigError> {
        Self::with_rules(config, RuleGroup::new())
    }

    /// Create a WAF from configuration and compiled rules.
    pub(crate) fn with_rules(config: WafConfig, rules: RuleGroup) -> Result<Self, ConfigError> {
        validate_config(&config)?;
        Ok(Self {
            config: Arc::new(config),
            rules: Arc::new(rules),
        })
    }

    /// Create a transaction with a process-unique identifier.
    pub fn new_transaction(&self) -> Transaction {
        let id = NEXT_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed);
        self.new_transaction_with_id(format!("coraza-{id}"))
    }

    /// Create a transaction with a caller-supplied identifier.
    pub fn new_transaction_with_id(&self, id: impl Into<String>) -> Transaction {
        Transaction::with_rules(Arc::clone(&self.config), Arc::clone(&self.rules), id)
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
        Self {
            config: Arc::new(WafConfig::default()),
            rules: Arc::new(RuleGroup::new()),
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
    if config.upload_keep_files && config.upload_dir.is_empty() {
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
    use crate::config::WafConfig;

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
