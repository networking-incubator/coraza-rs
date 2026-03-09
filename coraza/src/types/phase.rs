// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Processing phases for WAF rules.
//!
//! Rules are evaluated at different phases of request/response processing.
//! Each phase provides access to different parts of the HTTP transaction.

use std::fmt;
use std::str::FromStr;

/// Represents the phase of rule execution.
///
/// Rules are processed at different stages of the HTTP transaction lifecycle:
/// - Phase 1: Request Headers - After receiving request headers
/// - Phase 2: Request Body - After receiving request body
/// - Phase 3: Response Headers - After receiving response headers
/// - Phase 4: Response Body - After receiving response body
/// - Phase 5: Logging - After the transaction completes (always runs)
///
/// Phase 0 (Unknown) is reserved for unrecognized or invalid phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RulePhase {
    /// Unknown or invalid phase (used for error cases)
    Unknown = 0,
    /// Request Headers phase - processes after request headers are received
    RequestHeaders = 1,
    /// Request Body phase - processes after request body is received
    RequestBody = 2,
    /// Response Headers phase - processes after response headers are received
    ResponseHeaders = 3,
    /// Response Body phase - processes after response body is received
    ResponseBody = 4,
    /// Logging phase - processes after the request is sent (always runs)
    Logging = 5,
}

impl RulePhase {
    /// Returns the string representation of the phase.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza_rs::types::RulePhase;
    ///
    /// assert_eq!(RulePhase::RequestHeaders.as_str(), "request_headers");
    /// assert_eq!(RulePhase::Logging.as_str(), "logging");
    /// ```
    pub const fn as_str(&self) -> &'static str {
        match self {
            RulePhase::Unknown => "unknown",
            RulePhase::RequestHeaders => "request_headers",
            RulePhase::RequestBody => "request_body",
            RulePhase::ResponseHeaders => "response_headers",
            RulePhase::ResponseBody => "response_body",
            RulePhase::Logging => "logging",
        }
    }

    /// Returns the numeric value of the phase (0-5).
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza_rs::types::RulePhase;
    ///
    /// assert_eq!(RulePhase::Unknown.as_int(), 0);
    /// assert_eq!(RulePhase::RequestHeaders.as_int(), 1);
    /// assert_eq!(RulePhase::Logging.as_int(), 5);
    /// ```
    pub const fn as_int(&self) -> u8 {
        *self as u8
    }

    /// Returns true if this is a valid phase (not Unknown).
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza_rs::types::RulePhase;
    ///
    /// assert!(!RulePhase::Unknown.is_valid());
    /// assert!(RulePhase::RequestHeaders.is_valid());
    /// assert!(RulePhase::Logging.is_valid());
    /// ```
    pub const fn is_valid(&self) -> bool {
        !matches!(self, RulePhase::Unknown)
    }
}

impl fmt::Display for RulePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error type for invalid phase parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsePhaseError {
    input: String,
}

impl fmt::Display for ParsePhaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid phase {}", self.input)
    }
}

impl std::error::Error for ParsePhaseError {}

impl FromStr for RulePhase {
    type Err = ParsePhaseError;

    /// Parses a string into a RulePhase.
    ///
    /// Accepts:
    /// - Numeric values 1-5 (as strings)
    /// - "request" → Phase 2 (RequestBody)
    /// - "response" → Phase 4 (ResponseBody)
    /// - "logging" → Phase 5 (Logging)
    ///
    /// Note: Phase 0 (Unknown) cannot be parsed and values outside 1-5 return an error.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza_rs::types::RulePhase;
    /// use std::str::FromStr;
    ///
    /// assert_eq!(RulePhase::from_str("1").unwrap(), RulePhase::RequestHeaders);
    /// assert_eq!(RulePhase::from_str("2").unwrap(), RulePhase::RequestBody);
    /// assert_eq!(RulePhase::from_str("request").unwrap(), RulePhase::RequestBody);
    /// assert_eq!(RulePhase::from_str("response").unwrap(), RulePhase::ResponseBody);
    /// assert_eq!(RulePhase::from_str("logging").unwrap(), RulePhase::Logging);
    /// assert!(RulePhase::from_str("0").is_err());
    /// assert!(RulePhase::from_str("6").is_err());
    /// assert!(RulePhase::from_str("invalid").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // First, check for named phases
        let phase_num = match s {
            "request" => 2,
            "response" => 4,
            "logging" => 5,
            _ => {
                // Try to parse as a number
                s.parse::<u8>().unwrap_or(0)
            }
        };

        // Validate the phase number (must be 1-5)
        if !(1..=5).contains(&phase_num) {
            return Err(ParsePhaseError {
                input: s.to_string(),
            });
        }

        // Convert to enum
        Ok(match phase_num {
            1 => RulePhase::RequestHeaders,
            2 => RulePhase::RequestBody,
            3 => RulePhase::ResponseHeaders,
            4 => RulePhase::ResponseBody,
            5 => RulePhase::Logging,
            _ => unreachable!(), // Already validated above
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_str() {
        assert_eq!(RulePhase::Unknown.as_str(), "unknown");
        assert_eq!(RulePhase::RequestHeaders.as_str(), "request_headers");
        assert_eq!(RulePhase::RequestBody.as_str(), "request_body");
        assert_eq!(RulePhase::ResponseHeaders.as_str(), "response_headers");
        assert_eq!(RulePhase::ResponseBody.as_str(), "response_body");
        assert_eq!(RulePhase::Logging.as_str(), "logging");
    }

    #[test]
    fn test_as_int() {
        assert_eq!(RulePhase::Unknown.as_int(), 0);
        assert_eq!(RulePhase::RequestHeaders.as_int(), 1);
        assert_eq!(RulePhase::RequestBody.as_int(), 2);
        assert_eq!(RulePhase::ResponseHeaders.as_int(), 3);
        assert_eq!(RulePhase::ResponseBody.as_int(), 4);
        assert_eq!(RulePhase::Logging.as_int(), 5);
    }

    #[test]
    fn test_is_valid() {
        assert!(!RulePhase::Unknown.is_valid());
        assert!(RulePhase::RequestHeaders.is_valid());
        assert!(RulePhase::RequestBody.is_valid());
        assert!(RulePhase::ResponseHeaders.is_valid());
        assert!(RulePhase::ResponseBody.is_valid());
        assert!(RulePhase::Logging.is_valid());
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", RulePhase::Unknown), "unknown");
        assert_eq!(format!("{}", RulePhase::RequestHeaders), "request_headers");
        assert_eq!(format!("{}", RulePhase::Logging), "logging");
    }

    #[test]
    fn test_parse_from_number() {
        assert_eq!("1".parse::<RulePhase>().unwrap(), RulePhase::RequestHeaders);
        assert_eq!("2".parse::<RulePhase>().unwrap(), RulePhase::RequestBody);
        assert_eq!(
            "3".parse::<RulePhase>().unwrap(),
            RulePhase::ResponseHeaders
        );
        assert_eq!("4".parse::<RulePhase>().unwrap(), RulePhase::ResponseBody);
        assert_eq!("5".parse::<RulePhase>().unwrap(), RulePhase::Logging);
    }

    #[test]
    fn test_parse_from_name() {
        assert_eq!(
            "request".parse::<RulePhase>().unwrap(),
            RulePhase::RequestBody
        );
        assert_eq!(
            "response".parse::<RulePhase>().unwrap(),
            RulePhase::ResponseBody
        );
        assert_eq!("logging".parse::<RulePhase>().unwrap(), RulePhase::Logging);
    }

    #[test]
    fn test_parse_invalid() {
        // Phase 0 (Unknown) cannot be parsed
        assert!("0".parse::<RulePhase>().is_err());

        // Out of range
        assert!("6".parse::<RulePhase>().is_err());
        assert!("7".parse::<RulePhase>().is_err());
        assert!("-1".parse::<RulePhase>().is_err());

        // Invalid strings
        assert!("invalid".parse::<RulePhase>().is_err());
        assert!("unknown".parse::<RulePhase>().is_err());
        assert!("".parse::<RulePhase>().is_err());

        // These named phases don't exist
        assert!("request_headers".parse::<RulePhase>().is_err());
        assert!("request_body".parse::<RulePhase>().is_err());
    }

    #[test]
    fn test_ordering() {
        assert!(RulePhase::Unknown < RulePhase::RequestHeaders);
        assert!(RulePhase::RequestHeaders < RulePhase::RequestBody);
        assert!(RulePhase::RequestBody < RulePhase::ResponseHeaders);
        assert!(RulePhase::ResponseHeaders < RulePhase::ResponseBody);
        assert!(RulePhase::ResponseBody < RulePhase::Logging);
    }
}
