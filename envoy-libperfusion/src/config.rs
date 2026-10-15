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

use std::fmt::{self, Display, Formatter};

use serde::Deserialize;

/// Maximum request or response body buffered by the plugin.
///
/// The host copies the whole buffer into Wasm linear memory, and the
/// percent-decode scratch buffers hold further copies, so the ceiling has to
/// fit the VM's configured memory budget with room to spare. An allocation
/// failure in a Proxy-Wasm filter aborts the VM rather than degrading, which
/// would take the filter and the traffic it protects offline, so this is
/// deliberately far below what wasm32 could address.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Maximum size of one extracted field.
const MAX_FIELD_BYTES: usize = 1024 * 1024;
/// Maximum number of extracted fields in one message.
const MAX_FIELDS: usize = 65_536;
/// Maximum JSON nesting depth accepted by the plugin.
///
/// Each level adds serde's `deserialize_any` dispatch frame plus
/// `serde_json`'s own recursion. The default `wasm32` stack is one mebibyte
/// and a stack overflow in Wasm is an unrecoverable trap, so the ceiling is
/// held well inside it; raising `max_json_depth` toward it should be
/// validated against the deployment's configured stack size.
const MAX_JSON_DEPTH: usize = 64;

/// Chooses what to do with a direction's detections.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mode {
    /// Skip inspection for this direction.
    Off,
    /// Report detections and pass the message.
    Detect,
    /// Reject a message with any detection.
    Block,
}

/// Sets the outcome when complete inspection is unavailable.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IncompletePolicy {
    /// Report incomplete coverage and pass the message.
    Report,
    /// Reject incomplete messages.
    Reject,
}

/// Validated configuration shared by stream contexts.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Config {
    /// Request inspection mode.
    pub(crate) request_mode: Mode,
    /// Allow clean request headers upstream before the body verdict; for hosts without header-stop support.
    pub(crate) allow_request_headers_before_body_verdict: bool,
    /// Response inspection mode.
    pub(crate) response_mode: Mode,
    /// Policy for messages the plugin cannot fully inspect.
    pub(crate) incomplete_inspection_policy: IncompletePolicy,
    /// Maximum buffered request body size.
    pub(crate) max_request_body_bytes: usize,
    /// Maximum buffered response body size.
    pub(crate) max_response_body_bytes: usize,
    /// Maximum number of extracted header or structured fields.
    pub(crate) max_fields: usize,
    /// Maximum size of an extracted field.
    pub(crate) max_field_bytes: usize,
    /// Maximum JSON object or array nesting depth.
    pub(crate) max_json_depth: usize,
}

/// A configuration parse or validation error.
#[derive(Debug)]
pub(crate) enum ConfigError {
    /// The JSON was malformed or contained unknown fields.
    Json(serde_json::Error),
    /// One or more resource limits were zero.
    InvalidLimit,
    /// One or more resource limits exceeded the supported maximum.
    LimitTooLarge,
}

impl Display for ConfigError {
    /// Formats configuration errors for startup diagnostics.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "invalid JSON: {error}"),
            Self::InvalidLimit => f.write_str("inspection limits must be non-zero"),
            Self::LimitTooLarge => f.write_str("inspection limits exceed the supported maximum"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Parses and validates a JSON configuration value.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, ConfigError> {
        let config: Self = serde_json::from_slice(bytes).map_err(ConfigError::Json)?;
        if config.max_request_body_bytes == 0
            || config.max_response_body_bytes == 0
            || config.max_fields == 0
            || config.max_field_bytes == 0
            || config.max_json_depth == 0
        {
            return Err(ConfigError::InvalidLimit);
        }
        if config.max_request_body_bytes > MAX_BODY_BYTES
            || config.max_response_body_bytes > MAX_BODY_BYTES
            || config.max_field_bytes > MAX_FIELD_BYTES
            || config.max_field_bytes > config.max_request_body_bytes
            || config.max_field_bytes > config.max_response_body_bytes
            || config.max_fields > MAX_FIELDS
            || config.max_json_depth > MAX_JSON_DEPTH
        {
            return Err(ConfigError::LimitTooLarge);
        }
        if config.has_inert_incomplete_policy() {
            log::warn!(
                "libperfusion: incomplete_inspection_policy=reject has no effect while request_mode={:?} \
                 and response_mode={:?}; incomplete messages will be forwarded. Set mode=block in the \
                 direction that must fail closed.",
                config.request_mode,
                config.response_mode
            );
        }
        Ok(config)
    }

    /// Rejects incomplete inspection only when that direction is blocking.
    pub(crate) fn rejects_incomplete(&self, mode: Mode) -> bool {
        mode == Mode::Block && self.incomplete_inspection_policy == IncompletePolicy::Reject
    }

    /// Reports a reject policy that no direction can ever act on.
    ///
    /// `rejects_incomplete` requires `Mode::Block`, so pairing the strict
    /// policy with two non-blocking modes reduces every incomplete signal to
    /// a log line. That combination is the shipped default, which invites
    /// operators to believe they have fail-closed behaviour when they do not.
    pub(crate) fn has_inert_incomplete_policy(&self) -> bool {
        self.incomplete_inspection_policy == IncompletePolicy::Reject
            && self.request_mode != Mode::Block
            && self.response_mode != Mode::Block
    }
}

impl Default for Config {
    /// Provides bounded detection defaults for both directions.
    fn default() -> Self {
        Self {
            request_mode: Mode::Detect,
            allow_request_headers_before_body_verdict: false,
            response_mode: Mode::Detect,
            incomplete_inspection_policy: IncompletePolicy::Reject,
            max_request_body_bytes: 1024 * 1024,
            max_response_body_bytes: 1024 * 1024,
            // Header name and value each count as a field, so a budget in the
            // low thousands is consumed quickly by header-heavy meshes.
            max_fields: 8192,
            max_field_bytes: 64 * 1024,
            max_json_depth: 32,
        }
    }
}

#[cfg(test)]
/// Configuration tests.
mod tests {
    use super::{Config, ConfigError, IncompletePolicy, Mode};

    /// Checks defaults and configuration validation.
    #[test]
    fn defaults_are_bounded_and_detect_both_directions() {
        let parsed = Config::parse(b"{}");
        assert!(parsed.is_ok(), "default plugin configuration should parse");
        let config = parsed.unwrap_or_default();

        assert_eq!(config.request_mode, Mode::Detect, "request mode default");
        assert!(
            !config.allow_request_headers_before_body_verdict,
            "request headers are held for the body verdict by default"
        );
        assert_eq!(config.response_mode, Mode::Detect, "response mode default");
        assert_eq!(
            config.incomplete_inspection_policy,
            IncompletePolicy::Reject,
            "incomplete inspection default"
        );
        assert_eq!(config.max_request_body_bytes, 1024 * 1024, "request body bound");
        assert_eq!(config.max_response_body_bytes, 1024 * 1024, "response body bound");
    }

    /// Parses the opt-in for forwarding request headers before the body verdict.
    #[test]
    fn allows_early_request_headers_only_when_opted_in() {
        let parsed = Config::parse(br#"{"allow_request_headers_before_body_verdict":true}"#);
        assert!(parsed.is_ok(), "request header flow setting should parse");
        assert!(
            parsed.unwrap_or_default().allow_request_headers_before_body_verdict,
            "true should release clean headers before the body verdict"
        );
    }

    /// Ensures unknown fields and invalid resource bounds fail parsing.
    #[test]
    fn rejects_unknown_fields_and_unbounded_limits() {
        assert!(
            Config::parse(br#"{"unknown":true}"#).is_err(),
            "unknown configuration fields must be rejected"
        );
        assert!(
            Config::parse(br#"{"max_request_body_bytes":0}"#).is_err(),
            "zero body limits must be rejected"
        );
    }

    /// Rejects configured limits above the supported memory and parser bounds.
    #[test]
    fn rejects_limits_above_supported_maxima() {
        for configuration in [
            br#"{"max_request_body_bytes":67108865}"#.as_slice(),
            br#"{"max_response_body_bytes":67108865}"#,
            br#"{"max_field_bytes":1048577}"#,
            br#"{"max_request_body_bytes":64,"max_field_bytes":65}"#,
            br#"{"max_fields":65537}"#,
            br#"{"max_json_depth":129}"#,
        ] {
            assert!(
                matches!(Config::parse(configuration), Err(ConfigError::LimitTooLarge)),
                "configuration must exceed a supported maximum"
            );
        }
    }

    /// Flags a reject policy that no configured direction can act on.
    #[test]
    fn detects_inert_incomplete_policy_combination() {
        assert!(
            Config::default().has_inert_incomplete_policy(),
            "the shipped default pairs a reject policy with two detect modes"
        );

        let blocking = Config {
            request_mode: Mode::Block,
            ..Config::default()
        };
        assert!(
            !blocking.has_inert_incomplete_policy(),
            "a blocking direction makes the reject policy effective"
        );

        let reporting = Config {
            incomplete_inspection_policy: IncompletePolicy::Report,
            ..Config::default()
        };
        assert!(
            !reporting.has_inert_incomplete_policy(),
            "a report policy is self-consistent in detect mode"
        );
    }

    /// Keeps incomplete messages passable in detect mode despite a reject policy.
    #[test]
    fn rejects_incomplete_only_in_block_mode() {
        let config = Config::default();
        assert!(!config.rejects_incomplete(Mode::Detect));
        assert!(config.rejects_incomplete(Mode::Block));

        let report = Config {
            incomplete_inspection_policy: IncompletePolicy::Report,
            ..config
        };
        assert!(!report.rejects_incomplete(Mode::Block));
    }
}
