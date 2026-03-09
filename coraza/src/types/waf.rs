// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! WAF engine configuration types.
//!
//! This module contains types for configuring the WAF engine behavior,
//! audit logging, and rule processing.

use std::fmt;
use std::str::FromStr;

/// Status of the audit logging engine.
///
/// Controls whether and when transactions are logged for audit purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AuditEngineStatus {
    /// Audit each auditable event
    On = 0,
    /// Do not audit any event
    Off = 1,
    /// Audit only relevant events (events that trigger rules)
    RelevantOnly = 2,
}

impl AuditEngineStatus {
    /// Returns the string representation of the audit engine status.
    pub const fn as_str(&self) -> &'static str {
        match self {
            AuditEngineStatus::On => "On",
            AuditEngineStatus::Off => "Off",
            AuditEngineStatus::RelevantOnly => "RelevantOnly",
        }
    }
}

impl fmt::Display for AuditEngineStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error type for invalid audit engine status parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseAuditEngineStatusError {
    input: String,
}

impl fmt::Display for ParseAuditEngineStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid audit engine status: {}", self.input)
    }
}

impl std::error::Error for ParseAuditEngineStatusError {}

impl FromStr for AuditEngineStatus {
    type Err = ParseAuditEngineStatusError;

    /// Parses an audit engine status from a string (case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza_rs::types::AuditEngineStatus;
    /// use std::str::FromStr;
    ///
    /// assert_eq!(AuditEngineStatus::from_str("on").unwrap(), AuditEngineStatus::On);
    /// assert_eq!(AuditEngineStatus::from_str("OFF").unwrap(), AuditEngineStatus::Off);
    /// assert_eq!(AuditEngineStatus::from_str("RelevantOnly").unwrap(), AuditEngineStatus::RelevantOnly);
    /// assert!(AuditEngineStatus::from_str("invalid").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "on" => Ok(AuditEngineStatus::On),
            "off" => Ok(AuditEngineStatus::Off),
            "relevantonly" => Ok(AuditEngineStatus::RelevantOnly),
            _ => Err(ParseAuditEngineStatusError {
                input: s.to_string(),
            }),
        }
    }
}

/// Status of the rule processing engine.
///
/// Controls whether rules are processed and whether they can generate disruptive actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RuleEngineStatus {
    /// Process each rule and may generate disruptive actions (block, deny, etc.)
    On = 0,
    /// Process each rule but only log matches, no disruptive actions
    DetectionOnly = 1,
    /// Do not process any rules
    Off = 2,
}

impl RuleEngineStatus {
    /// Returns the string representation of the rule engine status.
    pub const fn as_str(&self) -> &'static str {
        match self {
            RuleEngineStatus::On => "On",
            RuleEngineStatus::DetectionOnly => "DetectionOnly",
            RuleEngineStatus::Off => "Off",
        }
    }
}

impl fmt::Display for RuleEngineStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error type for invalid rule engine status parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseRuleEngineStatusError {
    input: String,
}

impl fmt::Display for ParseRuleEngineStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid rule engine status: {}", self.input)
    }
}

impl std::error::Error for ParseRuleEngineStatusError {}

impl FromStr for RuleEngineStatus {
    type Err = ParseRuleEngineStatusError;

    /// Parses a rule engine status from a string (case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza_rs::types::RuleEngineStatus;
    /// use std::str::FromStr;
    ///
    /// assert_eq!(RuleEngineStatus::from_str("on").unwrap(), RuleEngineStatus::On);
    /// assert_eq!(RuleEngineStatus::from_str("DetectionOnly").unwrap(), RuleEngineStatus::DetectionOnly);
    /// assert_eq!(RuleEngineStatus::from_str("OFF").unwrap(), RuleEngineStatus::Off);
    /// assert!(RuleEngineStatus::from_str("invalid").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "on" => Ok(RuleEngineStatus::On),
            "detectiononly" => Ok(RuleEngineStatus::DetectionOnly),
            "off" => Ok(RuleEngineStatus::Off),
            _ => Err(ParseRuleEngineStatusError {
                input: s.to_string(),
            }),
        }
    }
}

/// Action to take when body size exceeds configured limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BodyLimitAction {
    /// Process the body up to the limit and ignore remaining bytes
    ProcessPartial = 0,
    /// Reject the connection when body size exceeds the limit
    Reject = 1,
}

impl BodyLimitAction {
    /// Returns the string representation of the body limit action.
    pub const fn as_str(&self) -> &'static str {
        match self {
            BodyLimitAction::ProcessPartial => "ProcessPartial",
            BodyLimitAction::Reject => "Reject",
        }
    }

    /// Returns the numeric value.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl fmt::Display for BodyLimitAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parts of an audit log entry.
///
/// Audit logs are divided into sections identified by letters A-K and Z.
/// Parts A (header) and Z (end marker) are mandatory.
///
/// See ModSecurity documentation for details on each part:
/// <https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#secauditlogparts>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AuditLogPart {
    /// A: Audit log header (mandatory)
    Header = b'A',
    /// B: Request headers
    RequestHeaders = b'B',
    /// C: Request body
    RequestBody = b'C',
    /// D: Intermediary response headers (reserved, not implemented)
    IntermediaryResponseHeaders = b'D',
    /// E: Intermediary response body (reserved, not implemented)
    IntermediaryResponseBody = b'E',
    /// F: Final response headers
    ResponseHeaders = b'F',
    /// G: Response body (reserved, not fully implemented)
    ResponseBody = b'G',
    /// H: Audit log trailer
    Trailer = b'H',
    /// I: Request body alternative (replacement for C)
    RequestBodyAlternative = b'I',
    /// J: Uploaded files information (multipart/form-data)
    UploadedFiles = b'J',
    /// K: List of matched rules
    RulesMatched = b'K',
    /// Z: Final boundary, end of entry (mandatory)
    EndMarker = b'Z',
}

impl AuditLogPart {
    /// Returns the character representation of the audit log part.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza_rs::types::AuditLogPart;
    ///
    /// assert_eq!(AuditLogPart::Header.as_char(), 'A');
    /// assert_eq!(AuditLogPart::RequestHeaders.as_char(), 'B');
    /// assert_eq!(AuditLogPart::EndMarker.as_char(), 'Z');
    /// ```
    pub const fn as_char(&self) -> char {
        *self as u8 as char
    }

    /// Returns the byte representation of the audit log part.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Creates an AuditLogPart from a character.
    ///
    /// Returns None if the character doesn't correspond to a valid part.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza_rs::types::AuditLogPart;
    ///
    /// assert_eq!(AuditLogPart::from_char('A'), Some(AuditLogPart::Header));
    /// assert_eq!(AuditLogPart::from_char('B'), Some(AuditLogPart::RequestHeaders));
    /// assert_eq!(AuditLogPart::from_char('X'), None);
    /// ```
    pub const fn from_char(c: char) -> Option<Self> {
        match c {
            'A' => Some(AuditLogPart::Header),
            'B' => Some(AuditLogPart::RequestHeaders),
            'C' => Some(AuditLogPart::RequestBody),
            'D' => Some(AuditLogPart::IntermediaryResponseHeaders),
            'E' => Some(AuditLogPart::IntermediaryResponseBody),
            'F' => Some(AuditLogPart::ResponseHeaders),
            'G' => Some(AuditLogPart::ResponseBody),
            'H' => Some(AuditLogPart::Trailer),
            'I' => Some(AuditLogPart::RequestBodyAlternative),
            'J' => Some(AuditLogPart::UploadedFiles),
            'K' => Some(AuditLogPart::RulesMatched),
            'Z' => Some(AuditLogPart::EndMarker),
            _ => None,
        }
    }

    /// Returns true if this part is mandatory (A or Z).
    pub const fn is_mandatory(&self) -> bool {
        matches!(self, AuditLogPart::Header | AuditLogPart::EndMarker)
    }
}

impl fmt::Display for AuditLogPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_char())
    }
}

/// Error type for invalid audit log part parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseAuditLogPartError {
    input: char,
}

impl fmt::Display for ParseAuditLogPartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid audit log part: {}", self.input)
    }
}

impl std::error::Error for ParseAuditLogPartError {}

impl TryFrom<char> for AuditLogPart {
    type Error = ParseAuditLogPartError;

    fn try_from(c: char) -> Result<Self, Self::Error> {
        Self::from_char(c).ok_or(ParseAuditLogPartError { input: c })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_engine_status_as_str() {
        assert_eq!(AuditEngineStatus::On.as_str(), "On");
        assert_eq!(AuditEngineStatus::Off.as_str(), "Off");
        assert_eq!(AuditEngineStatus::RelevantOnly.as_str(), "RelevantOnly");
    }

    #[test]
    fn test_audit_engine_status_display() {
        assert_eq!(format!("{}", AuditEngineStatus::On), "On");
        assert_eq!(format!("{}", AuditEngineStatus::Off), "Off");
        assert_eq!(
            format!("{}", AuditEngineStatus::RelevantOnly),
            "RelevantOnly"
        );
    }

    #[test]
    fn test_audit_engine_status_parse() {
        assert_eq!(
            "on".parse::<AuditEngineStatus>().unwrap(),
            AuditEngineStatus::On
        );
        assert_eq!(
            "OFF".parse::<AuditEngineStatus>().unwrap(),
            AuditEngineStatus::Off
        );
        assert_eq!(
            "RelevantOnly".parse::<AuditEngineStatus>().unwrap(),
            AuditEngineStatus::RelevantOnly
        );
        assert_eq!(
            "relevantonly".parse::<AuditEngineStatus>().unwrap(),
            AuditEngineStatus::RelevantOnly
        );
    }

    #[test]
    fn test_audit_engine_status_parse_invalid() {
        assert!("invalid".parse::<AuditEngineStatus>().is_err());
        assert!("".parse::<AuditEngineStatus>().is_err());
    }

    #[test]
    fn test_rule_engine_status_as_str() {
        assert_eq!(RuleEngineStatus::On.as_str(), "On");
        assert_eq!(RuleEngineStatus::DetectionOnly.as_str(), "DetectionOnly");
        assert_eq!(RuleEngineStatus::Off.as_str(), "Off");
    }

    #[test]
    fn test_rule_engine_status_display() {
        assert_eq!(format!("{}", RuleEngineStatus::On), "On");
        assert_eq!(
            format!("{}", RuleEngineStatus::DetectionOnly),
            "DetectionOnly"
        );
        assert_eq!(format!("{}", RuleEngineStatus::Off), "Off");
    }

    #[test]
    fn test_rule_engine_status_parse() {
        assert_eq!(
            "on".parse::<RuleEngineStatus>().unwrap(),
            RuleEngineStatus::On
        );
        assert_eq!(
            "DetectionOnly".parse::<RuleEngineStatus>().unwrap(),
            RuleEngineStatus::DetectionOnly
        );
        assert_eq!(
            "detectiononly".parse::<RuleEngineStatus>().unwrap(),
            RuleEngineStatus::DetectionOnly
        );
        assert_eq!(
            "OFF".parse::<RuleEngineStatus>().unwrap(),
            RuleEngineStatus::Off
        );
    }

    #[test]
    fn test_rule_engine_status_parse_invalid() {
        assert!("invalid".parse::<RuleEngineStatus>().is_err());
        assert!("detection".parse::<RuleEngineStatus>().is_err());
    }

    #[test]
    fn test_body_limit_action_as_str() {
        assert_eq!(BodyLimitAction::ProcessPartial.as_str(), "ProcessPartial");
        assert_eq!(BodyLimitAction::Reject.as_str(), "Reject");
    }

    #[test]
    fn test_body_limit_action_as_u8() {
        assert_eq!(BodyLimitAction::ProcessPartial.as_u8(), 0);
        assert_eq!(BodyLimitAction::Reject.as_u8(), 1);
    }

    #[test]
    fn test_body_limit_action_display() {
        assert_eq!(
            format!("{}", BodyLimitAction::ProcessPartial),
            "ProcessPartial"
        );
        assert_eq!(format!("{}", BodyLimitAction::Reject), "Reject");
    }

    #[test]
    fn test_audit_log_part_as_char() {
        assert_eq!(AuditLogPart::Header.as_char(), 'A');
        assert_eq!(AuditLogPart::RequestHeaders.as_char(), 'B');
        assert_eq!(AuditLogPart::RequestBody.as_char(), 'C');
        assert_eq!(AuditLogPart::ResponseHeaders.as_char(), 'F');
        assert_eq!(AuditLogPart::RulesMatched.as_char(), 'K');
        assert_eq!(AuditLogPart::EndMarker.as_char(), 'Z');
    }

    #[test]
    fn test_audit_log_part_from_char() {
        assert_eq!(AuditLogPart::from_char('A'), Some(AuditLogPart::Header));
        assert_eq!(
            AuditLogPart::from_char('B'),
            Some(AuditLogPart::RequestHeaders)
        );
        assert_eq!(AuditLogPart::from_char('Z'), Some(AuditLogPart::EndMarker));
        assert_eq!(AuditLogPart::from_char('X'), None);
        assert_eq!(AuditLogPart::from_char('a'), None); // Case sensitive
    }

    #[test]
    fn test_audit_log_part_try_from() {
        assert_eq!(AuditLogPart::try_from('A').unwrap(), AuditLogPart::Header);
        assert_eq!(
            AuditLogPart::try_from('K').unwrap(),
            AuditLogPart::RulesMatched
        );
        assert!(AuditLogPart::try_from('X').is_err());
    }

    #[test]
    fn test_audit_log_part_is_mandatory() {
        assert!(AuditLogPart::Header.is_mandatory());
        assert!(AuditLogPart::EndMarker.is_mandatory());
        assert!(!AuditLogPart::RequestHeaders.is_mandatory());
        assert!(!AuditLogPart::RequestBody.is_mandatory());
        assert!(!AuditLogPart::RulesMatched.is_mandatory());
    }

    #[test]
    fn test_audit_log_part_display() {
        assert_eq!(format!("{}", AuditLogPart::Header), "A");
        assert_eq!(format!("{}", AuditLogPart::RequestHeaders), "B");
        assert_eq!(format!("{}", AuditLogPart::EndMarker), "Z");
    }

    #[test]
    fn test_audit_log_part_roundtrip() {
        let parts = [
            AuditLogPart::Header,
            AuditLogPart::RequestHeaders,
            AuditLogPart::RequestBody,
            AuditLogPart::IntermediaryResponseHeaders,
            AuditLogPart::IntermediaryResponseBody,
            AuditLogPart::ResponseHeaders,
            AuditLogPart::ResponseBody,
            AuditLogPart::Trailer,
            AuditLogPart::RequestBodyAlternative,
            AuditLogPart::UploadedFiles,
            AuditLogPart::RulesMatched,
            AuditLogPart::EndMarker,
        ];

        for part in &parts {
            let c = part.as_char();
            let parsed = AuditLogPart::from_char(c).unwrap();
            assert_eq!(parsed, *part);
        }
    }
}
