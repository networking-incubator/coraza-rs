// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Rule severity levels for the WAF.
//!
//! Severity levels range from Emergency (0, most severe) to Debug (7, least severe).
//! These are used to categorize the importance of rule matches and determine logging behavior.

use std::fmt;
use std::str::FromStr;

/// Represents the severity of a triggered rule.
///
/// There are 8 levels of severity, from most to least severe:
/// - Emergency (0) - System is unusable, should exit immediately
/// - Alert (1) - Action must be taken immediately
/// - Critical (2) - Critical conditions
/// - Error (3) - Error conditions
/// - Warning (4) - Warning conditions
/// - Notice (5) - Normal but significant condition
/// - Info (6) - Informational messages
/// - Debug (7) - Debug-level messages
///
/// RuleSeverity is used by error callbacks to determine whether to log an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RuleSeverity {
    /// Emergency - System is unusable, should exit immediately
    Emergency = 0,
    /// Alert - Action must be taken immediately
    Alert = 1,
    /// Critical - Critical conditions
    Critical = 2,
    /// Error - Error conditions
    Error = 3,
    /// Warning - Warning conditions
    Warning = 4,
    /// Notice - Normal but significant condition
    Notice = 5,
    /// Info - Informational messages
    Info = 6,
    /// Debug - Debug-level messages
    Debug = 7,
}

impl RuleSeverity {
    /// Returns the string representation of the severity level.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza_rs::types::RuleSeverity;
    ///
    /// assert_eq!(RuleSeverity::Emergency.as_str(), "emergency");
    /// assert_eq!(RuleSeverity::Warning.as_str(), "warning");
    /// ```
    pub const fn as_str(&self) -> &'static str {
        match self {
            RuleSeverity::Emergency => "emergency",
            RuleSeverity::Alert => "alert",
            RuleSeverity::Critical => "critical",
            RuleSeverity::Error => "error",
            RuleSeverity::Warning => "warning",
            RuleSeverity::Notice => "notice",
            RuleSeverity::Info => "info",
            RuleSeverity::Debug => "debug",
        }
    }

    /// Returns the integer value of the severity (0-7).
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza_rs::types::RuleSeverity;
    ///
    /// assert_eq!(RuleSeverity::Emergency.as_int(), 0);
    /// assert_eq!(RuleSeverity::Debug.as_int(), 7);
    /// ```
    pub const fn as_int(&self) -> u8 {
        *self as u8
    }
}

impl fmt::Display for RuleSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error type for invalid severity parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseSeverityError {
    input: String,
}

impl fmt::Display for ParseSeverityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid severity: {}", self.input)
    }
}

impl std::error::Error for ParseSeverityError {}

impl FromStr for RuleSeverity {
    type Err = ParseSeverityError;

    /// Parses a string into a RuleSeverity.
    ///
    /// Accepts either numeric values (0-7) or string names (case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza_rs::types::RuleSeverity;
    /// use std::str::FromStr;
    ///
    /// assert_eq!(RuleSeverity::from_str("0").unwrap(), RuleSeverity::Emergency);
    /// assert_eq!(RuleSeverity::from_str("emergency").unwrap(), RuleSeverity::Emergency);
    /// assert_eq!(RuleSeverity::from_str("Warning").unwrap(), RuleSeverity::Warning);
    /// assert!(RuleSeverity::from_str("invalid").is_err());
    /// assert!(RuleSeverity::from_str("8").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try parsing as a single digit number first
        if s.len() == 1
            && let Ok(n) = s.parse::<u8>()
        {
            return match n {
                0 => Ok(RuleSeverity::Emergency),
                1 => Ok(RuleSeverity::Alert),
                2 => Ok(RuleSeverity::Critical),
                3 => Ok(RuleSeverity::Error),
                4 => Ok(RuleSeverity::Warning),
                5 => Ok(RuleSeverity::Notice),
                6 => Ok(RuleSeverity::Info),
                7 => Ok(RuleSeverity::Debug),
                _ => Err(ParseSeverityError {
                    input: s.to_string(),
                }),
            };
        }

        // Try parsing as a severity name (case-insensitive)
        match s.to_lowercase().as_str() {
            "emergency" => Ok(RuleSeverity::Emergency),
            "alert" => Ok(RuleSeverity::Alert),
            "critical" => Ok(RuleSeverity::Critical),
            "error" => Ok(RuleSeverity::Error),
            "warning" => Ok(RuleSeverity::Warning),
            "notice" => Ok(RuleSeverity::Notice),
            "info" => Ok(RuleSeverity::Info),
            "debug" => Ok(RuleSeverity::Debug),
            _ => Err(ParseSeverityError {
                input: s.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_str() {
        assert_eq!(RuleSeverity::Emergency.as_str(), "emergency");
        assert_eq!(RuleSeverity::Alert.as_str(), "alert");
        assert_eq!(RuleSeverity::Critical.as_str(), "critical");
        assert_eq!(RuleSeverity::Error.as_str(), "error");
        assert_eq!(RuleSeverity::Warning.as_str(), "warning");
        assert_eq!(RuleSeverity::Notice.as_str(), "notice");
        assert_eq!(RuleSeverity::Info.as_str(), "info");
        assert_eq!(RuleSeverity::Debug.as_str(), "debug");
    }

    #[test]
    fn test_as_int() {
        assert_eq!(RuleSeverity::Emergency.as_int(), 0);
        assert_eq!(RuleSeverity::Alert.as_int(), 1);
        assert_eq!(RuleSeverity::Critical.as_int(), 2);
        assert_eq!(RuleSeverity::Error.as_int(), 3);
        assert_eq!(RuleSeverity::Warning.as_int(), 4);
        assert_eq!(RuleSeverity::Notice.as_int(), 5);
        assert_eq!(RuleSeverity::Info.as_int(), 6);
        assert_eq!(RuleSeverity::Debug.as_int(), 7);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", RuleSeverity::Emergency), "emergency");
        assert_eq!(format!("{}", RuleSeverity::Warning), "warning");
        assert_eq!(format!("{}", RuleSeverity::Debug), "debug");
    }

    #[test]
    fn test_parse_from_number() {
        assert_eq!(
            "0".parse::<RuleSeverity>().unwrap(),
            RuleSeverity::Emergency
        );
        assert_eq!("1".parse::<RuleSeverity>().unwrap(), RuleSeverity::Alert);
        assert_eq!("2".parse::<RuleSeverity>().unwrap(), RuleSeverity::Critical);
        assert_eq!("3".parse::<RuleSeverity>().unwrap(), RuleSeverity::Error);
        assert_eq!("4".parse::<RuleSeverity>().unwrap(), RuleSeverity::Warning);
        assert_eq!("5".parse::<RuleSeverity>().unwrap(), RuleSeverity::Notice);
        assert_eq!("6".parse::<RuleSeverity>().unwrap(), RuleSeverity::Info);
        assert_eq!("7".parse::<RuleSeverity>().unwrap(), RuleSeverity::Debug);
    }

    #[test]
    fn test_parse_from_string() {
        assert_eq!(
            "emergency".parse::<RuleSeverity>().unwrap(),
            RuleSeverity::Emergency
        );
        assert_eq!(
            "alert".parse::<RuleSeverity>().unwrap(),
            RuleSeverity::Alert
        );
        assert_eq!(
            "critical".parse::<RuleSeverity>().unwrap(),
            RuleSeverity::Critical
        );
        assert_eq!(
            "error".parse::<RuleSeverity>().unwrap(),
            RuleSeverity::Error
        );
        assert_eq!(
            "warning".parse::<RuleSeverity>().unwrap(),
            RuleSeverity::Warning
        );
        assert_eq!(
            "notice".parse::<RuleSeverity>().unwrap(),
            RuleSeverity::Notice
        );
        assert_eq!("info".parse::<RuleSeverity>().unwrap(), RuleSeverity::Info);
        assert_eq!(
            "debug".parse::<RuleSeverity>().unwrap(),
            RuleSeverity::Debug
        );
    }

    #[test]
    fn test_parse_case_insensitive() {
        assert_eq!(
            "EMERGENCY".parse::<RuleSeverity>().unwrap(),
            RuleSeverity::Emergency
        );
        assert_eq!(
            "Warning".parse::<RuleSeverity>().unwrap(),
            RuleSeverity::Warning
        );
        assert_eq!(
            "DeBuG".parse::<RuleSeverity>().unwrap(),
            RuleSeverity::Debug
        );
    }

    #[test]
    fn test_parse_invalid() {
        assert!("8".parse::<RuleSeverity>().is_err());
        assert!("9".parse::<RuleSeverity>().is_err());
        assert!("-1".parse::<RuleSeverity>().is_err());
        assert!("invalid".parse::<RuleSeverity>().is_err());
        assert!("unknown".parse::<RuleSeverity>().is_err());
        assert!("".parse::<RuleSeverity>().is_err());
    }

    #[test]
    fn test_ordering() {
        assert!(RuleSeverity::Emergency < RuleSeverity::Alert);
        assert!(RuleSeverity::Warning < RuleSeverity::Debug);
        assert!(RuleSeverity::Critical < RuleSeverity::Error);
    }
}
