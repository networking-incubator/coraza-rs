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

//! WAF configuration.
//!
//! [`WafConfig`] holds settings for the separate Rust Coraza implementation.

use crate::types::{
    AuditEngineStatus, AuditLogFormat, AuditLogPart, AuditLogParts, AuditLogType, BodyLimitAction, RuleEngineStatus,
};

/// Default maximum number of arguments per collection (`SecArgumentsLimit`), as in Go
/// Coraza.
pub const DEFAULT_ARGUMENT_LIMIT: usize = 1000;

/// Default deepest nesting of a JSON body (`SecRequestBodyJsonDepthLimit` and
/// `SecResponseBodyJsonDepthLimit`), as in Go Coraza.
pub const DEFAULT_JSON_DEPTH_LIMIT: usize = 1024;

/// What happens when a detector operator cannot inspect a value.
///
/// The `detectSQLi` and `detectXSS` operators scan values up to
/// [`libperfusion::MAX_INPUT_LEN`] bytes, the bound of libperfusion's public detection
/// wrappers. A longer value has no verdict, so the operator reports a skipped
/// inspection. There is no SecLang directive for this setting, as in Go Coraza.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DetectorInspectionAction {
    /// Record the skipped inspection on the transaction and treat the value as not
    /// matched.
    ///
    /// This is the default and keeps detection compatible with earlier releases: a
    /// value above the bound is a miss. The transaction sets `TX.inspection_incomplete`
    /// to `"1"` and
    /// [`Transaction::inspection_incomplete`](crate::transaction::Transaction::inspection_incomplete)
    /// returns `true`, so an embedder can still tell that inspection did not run.
    #[default]
    RecordOnly,
    /// Interrupt the transaction when a detector operator cannot inspect a value.
    ///
    /// This is the safer setting: it fails closed instead of letting an uninspected
    /// value through. The interruption follows the rule engine mode, like any
    /// disruptive action.
    FailClosed,
}

/// Whether uploaded files are kept after the transaction ends (`SecUploadKeepFiles`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UploadKeepFiles {
    /// Delete temporary files, the default.
    #[default]
    Off,
    /// Keep every temporary file.
    On,
    /// Keep temporary files only when a matched rule has the `log` action enabled
    /// (excluding `nolog`), as Go Coraza's `hasLogRelevantMatchedRules` decides.
    RelevantOnly,
}

/// Configuration for a WAF instance.
///
/// A plain set of settings, built with struct-update syntax over [`Default`].
/// A WAF validates these settings at construction and transactions inherit them.
///
/// # Examples
///
/// ```
/// use coraza::{config::WafConfig, types::RuleEngineStatus};
///
/// let config = WafConfig {
///     rule_engine: RuleEngineStatus::DetectionOnly,
///     request_body_access: true,
///     request_body_limit: 1048576,
///     ..WafConfig::default()
/// };
///
/// assert_eq!(config.rule_engine, RuleEngineStatus::DetectionOnly);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "fields mirror independent SecLang boolean directives"
)]
pub struct WafConfig {
    /// Whether rules are evaluated, and whether disruptive actions apply (`SecRuleEngine`).
    pub rule_engine: RuleEngineStatus,

    /// Whether transactions buffer and inspect the request body (`SecRequestBodyAccess`).
    pub request_body_access: bool,

    /// Maximum request body size, in bytes (`SecRequestBodyLimit`).
    pub request_body_limit: i64,

    /// Request body bytes kept in memory before spilling to a private temporary file
    /// (`SecRequestBodyInMemoryLimit`).
    ///
    /// `0` means unset: the effective limit follows [`Self::request_body_limit`], as in
    /// Go Coraza when the directive is unset, so the default path never spills. A positive
    /// value is used as configured and must not exceed [`Self::request_body_limit`].
    pub request_body_in_memory_limit: i64,

    /// Maximum request body size excluding uploaded files, in bytes
    /// (`SecRequestBodyNoFilesLimit`).
    ///
    /// Parsed and validated for compatibility, but **not enforced**: Go Coraza v3.8.1
    /// also accepts this directive without implementing it
    /// (<https://github.com/corazawaf/coraza/issues/896>). No request admission decision
    /// depends on this field.
    pub request_body_no_files_limit: i64,

    /// What happens when the request body exceeds its limit (`SecRequestBodyLimitAction`).
    pub request_body_limit_action: BodyLimitAction,

    /// Whether transactions buffer and inspect the response body (`SecResponseBodyAccess`).
    pub response_body_access: bool,

    /// Maximum response body size, in bytes (`SecResponseBodyLimit`).
    pub response_body_limit: i64,

    /// What happens when the response body exceeds its limit (`SecResponseBodyLimitAction`).
    pub response_body_limit_action: BodyLimitAction,

    /// Response content types, without parameters, whose body is inspected; none by
    /// default, as in Go Coraza (`SecResponseBodyMimeType`).
    pub response_body_mime_types: Vec<String>,

    /// Deepest nesting of objects and arrays a JSON request body may have
    /// (`SecRequestBodyJsonDepthLimit`).
    pub request_body_json_depth_limit: usize,

    /// Deepest nesting of objects and arrays a JSON response body may have
    /// (`SecResponseBodyJsonDepthLimit`).
    pub response_body_json_depth_limit: usize,

    /// Audit logging mode (`SecAuditEngine`).
    pub audit_engine: AuditEngineStatus,

    /// Target of the audit log, empty when unset (`SecAuditLog`): a file path for
    /// `Serial` and `Concurrent`, a syslog target for `Syslog`, and an endpoint URL
    /// for `HTTPS`, which accepts both `https://` and plaintext `http://` targets as
    /// Go Coraza does and requires the `https-audit` crate feature.
    pub audit_log: String,

    /// Format of audit log entries (`SecAuditLogFormat`).
    pub audit_log_format: AuditLogFormat,

    /// Parts each audit log entry holds, `A` and `Z` included (`SecAuditLogParts`).
    pub audit_log_parts: AuditLogParts,

    /// Where audit log entries are written (`SecAuditLogType`).
    pub audit_log_type: AuditLogType,

    /// Regular expression of the response statuses that make a transaction relevant to
    /// `SecAuditEngine RelevantOnly`; empty for none (`SecAuditLogRelevantStatus`).
    pub audit_log_relevant_status: String,

    /// Permission bits for directories of `Concurrent` audit logs, e.g. `0o755`
    /// (`SecAuditLogDirMode`).
    pub audit_log_dir_mode: u32,

    /// Permission bits for audit log files, e.g. `0o644` (`SecAuditLogFileMode`).
    pub audit_log_file_mode: u32,

    /// Directory of `Concurrent` audit logs; empty when unset (`SecAuditLogStorageDir`).
    pub audit_log_storage_dir: String,

    /// Deadline for connecting a TCP syslog audit writer; `None` (the default) waits
    /// indefinitely, as Go Coraza does.
    ///
    /// There is no SecLang directive for this. It applies to `SecAuditLogType Syslog`
    /// targets with a `tcp` scheme, including the reconnect after a failed write. DNS
    /// resolution is not bounded. File and HTTPS writers ignore it: file writes never
    /// connect, and HTTPS keeps its one-second whole-request budget.
    pub audit_log_connect_timeout: Option<std::time::Duration>,

    /// Deadline for one audit log write; `None` (the default) waits indefinitely, as Go
    /// Coraza does.
    ///
    /// There is no SecLang directive for this. It applies to syslog writes over TCP,
    /// UDP and, where the platform supports socket write deadlines, Unix sockets. File
    /// writes have no deadline, as a regular file write cannot time out. HTTPS keeps its
    /// one-second whole-request budget.
    pub audit_log_write_timeout: Option<std::time::Duration>,

    /// Path of the debug log, for the embedder: the library writes none; empty when
    /// unset (`SecDebugLog`).
    pub debug_log: String,

    /// Lifetime of persistent collection entries, in seconds (`SecCollectionTimeout`).
    pub collection_timeout: i64,

    /// Debug log verbosity, 0 to 9 inclusive (`SecDebugLogLevel`).
    pub debug_log_level: u8,

    /// Maximum number of ARGS processed per transaction (`SecArgumentsLimit`).
    pub argument_limit: usize,

    /// Whether argument collection keys are matched case-sensitively.
    ///
    /// Applies to `ARGS`, `ARGS_GET`, `ARGS_POST`, `ARGS_PATH` and their `*_NAMES`
    /// views. `false`, the default, matches Go Coraza's default behavior, where keyed
    /// lookups fold case. `true` is equivalent to Go's
    /// `coraza.rule.case_sensitive_args_keys` build tag. Other collections stay
    /// case-insensitive, as in Go. There is no SecLang directive for this, as in Go.
    pub case_sensitive_args_keys: bool,

    /// What happens when a detector operator cannot inspect a value that exceeds
    /// libperfusion's input bound.
    ///
    /// [`DetectorInspectionAction::RecordOnly`], the default, keeps the miss and records
    /// the skipped inspection. [`DetectorInspectionAction::FailClosed`] interrupts the
    /// transaction instead. There is no SecLang directive for this, as in Go Coraza.
    pub detector_inspection_action: DetectorInspectionAction,

    /// Application id; apps sharing it share persistent collections (`SecWebAppId`).
    pub web_app_id: String,

    /// Identifies this sensor in a cluster (`SecSensorId`).
    pub sensor_id: String,

    /// Value for the `Server` response header; empty leaves it untouched (`SecServerSignature`).
    pub server_signature: String,

    /// Component signatures appended to the WAF signature (`SecComponentSignature`).
    pub component_names: Vec<String>,

    /// Directory for persistent data (`SecDataDir`).
    pub data_dir: String,

    /// Directory where uploaded files are stored (`SecUploadDir`); empty for the system's
    /// temporary directory (`std::env::temp_dir`), as in Go Coraza.
    pub upload_dir: String,

    /// Maximum number of uploaded files processed per transaction (`SecUploadFileLimit`).
    pub upload_file_limit: usize,

    /// Permission bits for stored uploaded files, e.g. `0o600` (`SecUploadFileMode`).
    pub upload_file_mode: u32,

    /// Whether uploaded files are kept after the transaction ends
    /// (`SecUploadKeepFiles`).
    pub upload_keep_files: UploadKeepFiles,
}

impl Default for WafConfig {
    /// Defaults match the Go implementation.
    fn default() -> Self {
        Self {
            rule_engine: RuleEngineStatus::On,
            request_body_access: false,
            request_body_limit: 128 * 1024 * 1024,
            // Unset; the effective limit follows request_body_limit, as in Go
            // (internal/corazawaf/waf.go:242-247), so the default path never spills.
            request_body_in_memory_limit: 0,
            request_body_no_files_limit: 64 * 1024,
            request_body_limit_action: BodyLimitAction::Reject,
            response_body_access: false,
            response_body_limit: 512 * 1024,
            response_body_limit_action: BodyLimitAction::ProcessPartial,
            response_body_mime_types: Vec::new(),
            request_body_json_depth_limit: DEFAULT_JSON_DEPTH_LIMIT,
            response_body_json_depth_limit: DEFAULT_JSON_DEPTH_LIMIT,
            audit_engine: AuditEngineStatus::Off,
            audit_log: String::new(),
            audit_log_format: AuditLogFormat::Native,
            audit_log_parts: vec![
                AuditLogPart::Header,
                AuditLogPart::RequestHeaders,
                AuditLogPart::RequestBody,
                AuditLogPart::ResponseHeaders,
                AuditLogPart::Trailer,
                AuditLogPart::EndMarker,
            ],
            audit_log_type: AuditLogType::Serial,
            audit_log_relevant_status: String::new(),
            audit_log_dir_mode: 0o755,
            audit_log_file_mode: 0o644,
            audit_log_storage_dir: String::new(),
            audit_log_connect_timeout: None,
            audit_log_write_timeout: None,
            debug_log: String::new(),
            collection_timeout: 3600,
            debug_log_level: 0,
            argument_limit: DEFAULT_ARGUMENT_LIMIT,
            case_sensitive_args_keys: false,
            detector_inspection_action: DetectorInspectionAction::RecordOnly,
            web_app_id: String::new(),
            sensor_id: String::new(),
            server_signature: String::new(),
            component_names: Vec::new(),
            data_dir: String::new(),
            upload_dir: String::new(),
            upload_file_limit: 100,
            upload_file_mode: 0o600,
            upload_keep_files: UploadKeepFiles::Off,
        }
    }
}

impl WafConfig {
    /// Creates a configuration with default values; same as [`WafConfig::default`].
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_coraza_values() {
        let config = WafConfig::default();
        assert_eq!(config.rule_engine, RuleEngineStatus::On);
        assert_eq!(config.request_body_limit, 134_217_728);
        assert_eq!(config.request_body_in_memory_limit, 0);
        assert_eq!(config.response_body_limit, 524_288);
        assert_eq!(config.audit_engine, AuditEngineStatus::Off);
        assert_eq!(config.argument_limit, 1000);
        assert!(!config.case_sensitive_args_keys);
        assert_eq!(config.detector_inspection_action, DetectorInspectionAction::RecordOnly);
        assert_eq!(config.audit_log_format, AuditLogFormat::Native);
        assert_eq!(config.audit_log_type, AuditLogType::Serial);
        assert!(!config.request_body_access);
        assert!(!config.response_body_access);
        assert_eq!(config.upload_file_mode, 0o600);
        assert_eq!(config.upload_keep_files, UploadKeepFiles::Off);
        assert_eq!(config.audit_log_connect_timeout, None);
        assert_eq!(config.audit_log_write_timeout, None);
        assert_eq!(
            config.audit_log_parts,
            [
                AuditLogPart::Header,
                AuditLogPart::RequestHeaders,
                AuditLogPart::RequestBody,
                AuditLogPart::ResponseHeaders,
                AuditLogPart::Trailer,
                AuditLogPart::EndMarker,
            ]
        );
    }

    #[test]
    fn new_returns_default_configuration() {
        assert_eq!(WafConfig::new(), WafConfig::default());
    }
}
