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
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Maximum size of one extracted field.
const MAX_FIELD_BYTES: usize = 1024 * 1024;
/// Maximum number of extracted fields in one message.
const MAX_FIELDS: usize = 65_536;
/// Maximum JSON nesting depth accepted by the plugin.
const MAX_JSON_DEPTH: usize = 128;

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
            || config.max_fields > MAX_FIELDS
            || config.max_json_depth > MAX_JSON_DEPTH
        {
            return Err(ConfigError::LimitTooLarge);
        }
        Ok(config)
    }

    /// Rejects incomplete inspection only when that direction is blocking.
    pub(crate) fn rejects_incomplete(&self, mode: Mode) -> bool {
        mode == Mode::Block && self.incomplete_inspection_policy == IncompletePolicy::Reject
    }
}

impl Default for Config {
    /// Provides bounded detection defaults for both directions.
    fn default() -> Self {
        Self {
            request_mode: Mode::Detect,
            response_mode: Mode::Detect,
            incomplete_inspection_policy: IncompletePolicy::Reject,
            max_request_body_bytes: 1024 * 1024,
            max_response_body_bytes: 1024 * 1024,
            max_fields: 1024,
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
        assert_eq!(config.response_mode, Mode::Detect, "response mode default");
        assert_eq!(
            config.incomplete_inspection_policy,
            IncompletePolicy::Reject,
            "incomplete inspection default"
        );
        assert_eq!(config.max_request_body_bytes, 1024 * 1024, "request body bound");
        assert_eq!(config.max_response_body_bytes, 1024 * 1024, "response body bound");
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
