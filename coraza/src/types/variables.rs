// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Variable identifiers for WAF rule matching.
//!
//! Variables identify specific pieces of information from an HTTP transaction
//! that can be inspected by rules (e.g., ARGS, HEADERS, REQUEST_URI).

use std::fmt;
use std::str::FromStr;

/// Identifies information from a transaction that can be inspected by rules.
///
/// Variables are used in SecLang rules to specify what data to inspect.
/// For example: `SecRule ARGS "@rx attack" ...` inspects all arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RuleVariable {
    /// Unknown/invalid variable (error placeholder)
    Unknown = 0,
    /// RESPONSE_CONTENT_TYPE - Content type of the response
    ResponseContentType,
    /// UNIQUE_ID - Unique ID of the transaction
    UniqueID,
    /// ARGS_COMBINED_SIZE - Combined size of all arguments
    ArgsCombinedSize,
    /// FILES_COMBINED_SIZE - Combined size of uploaded files
    FilesCombinedSize,
    /// FULL_REQUEST_LENGTH - Length of the full request
    FullRequestLength,
    /// INBOUND_DATA_ERROR - Set to 1 when request body size exceeds SecRequestBodyLimit
    InboundDataError,
    /// MATCHED_VAR - Value of the matched variable
    MatchedVar,
    /// MATCHED_VAR_NAME - Name of the matched variable
    MatchedVarName,
    /// MULTIPART_DATA_AFTER - Kept for compatibility
    MultipartDataAfter,
    /// OUTBOUND_DATA_ERROR - Set to 1 when response body size exceeds SecResponseBodyLimit
    OutboundDataError,
    /// QUERY_STRING - Raw query string part of request URI
    QueryString,
    /// REMOTE_ADDR - Remote address of the connection
    RemoteAddr,
    /// REMOTE_HOST - Remote host of the connection (not implemented)
    RemoteHost,
    /// REMOTE_PORT - Remote port of the connection
    RemotePort,
    /// REQBODY_ERROR - Request body processor error status (0=no error, 1=error)
    ReqbodyError,
    /// REQBODY_ERROR_MSG - Error message from request body processor
    ReqbodyErrorMsg,
    /// REQBODY_PROCESSOR_ERROR - Same as ReqbodyError
    ReqbodyProcessorError,
    /// REQBODY_PROCESSOR_ERROR_MSG - Same as ReqbodyErrorMsg
    ReqbodyProcessorErrorMsg,
    /// REQBODY_PROCESSOR - Name of request body processor (URLENCODED, MULTIPART, XML)
    ReqbodyProcessor,
    /// REQUEST_BASENAME - Name after last slash in request URI
    RequestBasename,
    /// REQUEST_BODY - Full request body (urlencoded only by default)
    RequestBody,
    /// REQUEST_BODY_LENGTH - Length of request body in bytes
    RequestBodyLength,
    /// REQUEST_FILENAME - Relative request URL without query string
    RequestFilename,
    /// REQUEST_LINE - Complete request line (method, URI, HTTP version)
    RequestLine,
    /// REQUEST_METHOD - HTTP request method
    RequestMethod,
    /// REQUEST_PROTOCOL - HTTP protocol version
    RequestProtocol,
    /// REQUEST_URI - Full request URL with query string (without domain)
    RequestURI,
    /// REQUEST_URI_RAW - Same as REQUEST_URI but with domain if provided
    RequestURIRaw,
    /// RESPONSE_BODY - Full response body
    ResponseBody,
    /// RESPONSE_CONTENT_LENGTH - Length of response body in bytes
    ResponseContentLength,
    /// RESPONSE_PROTOCOL - HTTP response protocol version
    ResponseProtocol,
    /// RESPONSE_STATUS - HTTP response status code
    ResponseStatus,
    /// SERVER_ADDR - Server address
    ServerAddr,
    /// SERVER_NAME - Server name
    ServerName,
    /// SERVER_PORT - Server port
    ServerPort,
    /// HIGHEST_SEVERITY - Highest severity from all matched rules
    HighestSeverity,
    /// STATUS_LINE - Status line of response
    StatusLine,
    /// DURATION - Time in milliseconds from transaction start
    Duration,
    /// RESPONSE_HEADERS_NAMES - Names of response headers (collection)
    ResponseHeadersNames,
    /// REQUEST_HEADERS_NAMES - Names of request headers (collection)
    RequestHeadersNames,
    /// ARGS - All arguments (GET and POST combined, collection)
    Args,
    /// ARGS_GET - GET (URL) arguments (collection)
    ArgsGet,
    /// ARGS_POST - POST (body) arguments (collection)
    ArgsPost,
    /// ARGS_PATH - URL path parts (collection)
    ArgsPath,
    /// FILES_SIZES - Sizes of uploaded files (collection)
    FilesSizes,
    /// FILES_NAMES - Names of uploaded files (collection)
    FilesNames,
    /// FILES_TMP_CONTENT - Not supported (collection)
    FilesTmpContent,
    /// MULTIPART_FILENAME - Multipart FILENAME field (collection)
    MultipartFilename,
    /// MULTIPART_NAME - Multipart NAME field (collection)
    MultipartName,
    /// MATCHED_VARS_NAMES - All matched variable names for current operator (collection)
    MatchedVarsNames,
    /// MATCHED_VARS - All matched variable values for current operator (collection)
    MatchedVars,
    /// FILES - Original file names from multipart/form-data (collection)
    Files,
    /// REQUEST_COOKIES - Request cookie values (collection)
    RequestCookies,
    /// REQUEST_HEADERS - Request headers (collection)
    RequestHeaders,
    /// RESPONSE_HEADERS - Response headers (collection)
    ResponseHeaders,
    /// RESPONSE_BODY_PROCESSOR - Name of response body processor
    ResBodyProcessor,
    /// GEO - Geographic location information of client (collection)
    Geo,
    /// REQUEST_COOKIES_NAMES - Names of request cookies (collection)
    RequestCookiesNames,
    /// FILES_TMP_NAMES - Names of temporary uploaded files (collection)
    FilesTmpNames,
    /// ARGS_NAMES - Names of all arguments (POST and GET, collection)
    ArgsNames,
    /// ARGS_GET_NAMES - Names of GET arguments (collection)
    ArgsGetNames,
    /// ARGS_POST_NAMES - Names of POST arguments (collection)
    ArgsPostNames,
    /// TX - Transaction-specific variables (created with setvar, collection)
    TX,
    /// RULE - Rule metadata (collection)
    Rule,
    /// JSON - JSON data (collection, may be removed)
    JSON,
    /// ENV - Process environment variables (collection)
    Env,
    /// URLENCODED_ERROR - Set to 1 if URL parsing failed
    UrlencodedError,
    /// RESPONSE_ARGS - Response parsed arguments (collection)
    ResponseArgs,
    /// RESPONSE_XML - Response parsed XML (collection)
    ResponseXML,
    /// REQUEST_XML - Request parsed XML (collection)
    RequestXML,
    /// XML - Pointer to RESPONSE_XML (collection)
    XML,
    /// MULTIPART_PART_HEADERS - Multipart part headers (collection)
    MultipartPartHeaders,

    // Unsupported variables (kept for compatibility)
    /// AUTH_TYPE - Authentication type (unsupported)
    AuthType,
    /// FULL_REQUEST - Full request (unsupported)
    FullRequest,
    /// MULTIPART_BOUNDARY_QUOTED - Kept for compatibility (unsupported)
    MultipartBoundaryQuoted,
    /// MULTIPART_BOUNDARY_WHITESPACE - Kept for compatibility (unsupported)
    MultipartBoundaryWhitespace,
    /// MULTIPART_CRLF_LF_LINES - Kept for compatibility (unsupported)
    MultipartCrlfLfLines,
    /// MULTIPART_DATA_BEFORE - Kept for compatibility (unsupported)
    MultipartDataBefore,
    /// MULTIPART_FILE_LIMIT_EXCEEDED - Kept for compatibility (unsupported)
    MultipartFileLimitExceeded,
    /// MULTIPART_HEADER_FOLDING - Kept for compatibility (unsupported)
    MultipartHeaderFolding,
    /// MULTIPART_INVALID_HEADER_FOLDING - Kept for compatibility (unsupported)
    MultipartInvalidHeaderFolding,
    /// MULTIPART_INVALID_PART - Kept for compatibility (unsupported)
    MultipartInvalidPart,
    /// MULTIPART_INVALID_QUOTING - Kept for compatibility (unsupported)
    MultipartInvalidQuoting,
    /// MULTIPART_LF_LINE - Kept for compatibility (unsupported)
    MultipartLfLine,
    /// MULTIPART_MISSING_SEMICOLON - Kept for compatibility (unsupported)
    MultipartMissingSemicolon,
    /// MULTIPART_STRICT_ERROR - Multipart parsing error flag
    MultipartStrictError,
    /// MULTIPART_UNMATCHED_BOUNDARY - Kept for compatibility (unsupported)
    MultipartUnmatchedBoundary,
    /// PATH_INFO - Kept for compatibility (unsupported)
    PathInfo,
    /// SESSIONID - Not supported
    Sessionid,
    /// USERID - Not supported
    Userid,
    /// IP - Kept for compatibility (unsupported)
    IP,
    /// RESBODY_ERROR - Response body processor error flag
    ResBodyError,
    /// RESBODY_ERROR_MSG - Response body processor error message
    ResBodyErrorMsg,
    /// RESBODY_PROCESSOR_ERROR - Response body processor error flag
    ResBodyProcessorError,
    /// RESBODY_PROCESSOR_ERROR_MSG - Response body processor error message
    ResBodyProcessorErrorMsg,
    /// TIME - Formatted time string (hour:minute:second)
    Time,
    /// TIME_DAY - Current day of month (1-31)
    TimeDay,
    /// TIME_EPOCH - Time in seconds since 1970
    TimeEpoch,
    /// TIME_HOUR - Current hour of day (0-23)
    TimeHour,
    /// TIME_MIN - Current minute of hour (0-59)
    TimeMin,
    /// TIME_MON - Current month of year (0-11)
    TimeMon,
    /// TIME_SEC - Current second of minute (0-59)
    TimeSec,
    /// TIME_WDAY - Current weekday value (1-7, Monday=1)
    TimeWday,
    /// TIME_YEAR - Current four-digit year
    TimeYear,
}

/// Lookup table of all variable names in enum order.
/// This is the single source of truth for variable string representations.
const VARIABLE_NAMES: &[&str] = &[
    "UNKNOWN",
    "RESPONSE_CONTENT_TYPE",
    "UNIQUE_ID",
    "ARGS_COMBINED_SIZE",
    "FILES_COMBINED_SIZE",
    "FULL_REQUEST_LENGTH",
    "INBOUND_DATA_ERROR",
    "MATCHED_VAR",
    "MATCHED_VAR_NAME",
    "MULTIPART_DATA_AFTER",
    "OUTBOUND_DATA_ERROR",
    "QUERY_STRING",
    "REMOTE_ADDR",
    "REMOTE_HOST",
    "REMOTE_PORT",
    "REQBODY_ERROR",
    "REQBODY_ERROR_MSG",
    "REQBODY_PROCESSOR_ERROR",
    "REQBODY_PROCESSOR_ERROR_MSG",
    "REQBODY_PROCESSOR",
    "REQUEST_BASENAME",
    "REQUEST_BODY",
    "REQUEST_BODY_LENGTH",
    "REQUEST_FILENAME",
    "REQUEST_LINE",
    "REQUEST_METHOD",
    "REQUEST_PROTOCOL",
    "REQUEST_URI",
    "REQUEST_URI_RAW",
    "RESPONSE_BODY",
    "RESPONSE_CONTENT_LENGTH",
    "RESPONSE_PROTOCOL",
    "RESPONSE_STATUS",
    "SERVER_ADDR",
    "SERVER_NAME",
    "SERVER_PORT",
    "HIGHEST_SEVERITY",
    "STATUS_LINE",
    "DURATION",
    "RESPONSE_HEADERS_NAMES",
    "REQUEST_HEADERS_NAMES",
    "ARGS",
    "ARGS_GET",
    "ARGS_POST",
    "ARGS_PATH",
    "FILES_SIZES",
    "FILES_NAMES",
    "FILES_TMP_CONTENT",
    "MULTIPART_FILENAME",
    "MULTIPART_NAME",
    "MATCHED_VARS_NAMES",
    "MATCHED_VARS",
    "FILES",
    "REQUEST_COOKIES",
    "REQUEST_HEADERS",
    "RESPONSE_HEADERS",
    "RESBODY_PROCESSOR",
    "GEO",
    "REQUEST_COOKIES_NAMES",
    "FILES_TMP_NAMES",
    "ARGS_NAMES",
    "ARGS_GET_NAMES",
    "ARGS_POST_NAMES",
    "TX",
    "RULE",
    "JSON",
    "ENV",
    "URLENCODED_ERROR",
    "RESPONSE_ARGS",
    "RESPONSE_XML",
    "REQUEST_XML",
    "XML",
    "MULTIPART_PART_HEADERS",
    "AUTH_TYPE",
    "FULL_REQUEST",
    "MULTIPART_BOUNDARY_QUOTED",
    "MULTIPART_BOUNDARY_WHITESPACE",
    "MULTIPART_CRLF_LF_LINES",
    "MULTIPART_DATA_BEFORE",
    "MULTIPART_FILE_LIMIT_EXCEEDED",
    "MULTIPART_HEADER_FOLDING",
    "MULTIPART_INVALID_HEADER_FOLDING",
    "MULTIPART_INVALID_PART",
    "MULTIPART_INVALID_QUOTING",
    "MULTIPART_LF_LINE",
    "MULTIPART_MISSING_SEMICOLON",
    "MULTIPART_STRICT_ERROR",
    "MULTIPART_UNMATCHED_BOUNDARY",
    "PATH_INFO",
    "SESSIONID",
    "USERID",
    "IP",
    "RESBODY_ERROR",
    "RESBODY_ERROR_MSG",
    "RESBODY_PROCESSOR_ERROR",
    "RESBODY_PROCESSOR_ERROR_MSG",
    "TIME",
    "TIME_DAY",
    "TIME_EPOCH",
    "TIME_HOUR",
    "TIME_MIN",
    "TIME_MON",
    "TIME_SEC",
    "TIME_WDAY",
    "TIME_YEAR",
];

impl RuleVariable {
    /// Returns the SCREAMING_SNAKE_CASE name of the variable.
    ///
    /// Used for audit logging and string representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza_rs::types::RuleVariable;
    ///
    /// assert_eq!(RuleVariable::RequestURI.name(), "REQUEST_URI");
    /// assert_eq!(RuleVariable::Args.name(), "ARGS");
    /// ```
    pub const fn name(&self) -> &'static str {
        VARIABLE_NAMES[*self as usize]
    }

    /// Creates a RuleVariable from a u8 discriminant.
    ///
    /// Returns None if the value is out of range.
    ///
    /// # Safety
    ///
    /// This function is safe because it validates the input is within the valid range.
    const fn from_u8(value: u8) -> Option<Self> {
        if (value as usize) < VARIABLE_NAMES.len() {
            // SAFETY: We've verified the value is within the valid range.
            // The enum has repr(u8) and variants are numbered sequentially from 0.
            Some(unsafe { std::mem::transmute::<u8, Self>(value) })
        } else {
            None
        }
    }

    /// Returns the numeric value of the variable.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza_rs::types::RuleVariable;
    ///
    /// assert_eq!(RuleVariable::Unknown.as_u8(), 0);
    /// assert_eq!(RuleVariable::ResponseContentType.as_u8(), 1);
    /// ```
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl fmt::Display for RuleVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Error type for invalid variable parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseVariableError {
    input: String,
}

impl fmt::Display for ParseVariableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown variable: {}", self.input)
    }
}

impl std::error::Error for ParseVariableError {}

impl FromStr for RuleVariable {
    type Err = ParseVariableError;

    /// Parses a variable name (case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza_rs::types::RuleVariable;
    /// use std::str::FromStr;
    ///
    /// assert_eq!(RuleVariable::from_str("REQUEST_URI").unwrap(), RuleVariable::RequestURI);
    /// assert_eq!(RuleVariable::from_str("args").unwrap(), RuleVariable::Args);
    /// assert_eq!(RuleVariable::from_str("Request_Method").unwrap(), RuleVariable::RequestMethod);
    /// assert!(RuleVariable::from_str("invalid").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let upper = s.to_uppercase();

        VARIABLE_NAMES
            .iter()
            .position(|&name| name == upper.as_str())
            .and_then(|idx| Self::from_u8(idx as u8))
            .ok_or_else(|| ParseVariableError {
                input: s.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        assert_eq!(RuleVariable::Unknown.name(), "UNKNOWN");
        assert_eq!(RuleVariable::RequestURI.name(), "REQUEST_URI");
        assert_eq!(RuleVariable::Args.name(), "ARGS");
        assert_eq!(RuleVariable::RequestMethod.name(), "REQUEST_METHOD");
        assert_eq!(RuleVariable::TX.name(), "TX");
    }

    #[test]
    fn test_as_u8() {
        assert_eq!(RuleVariable::Unknown.as_u8(), 0);
        assert_eq!(RuleVariable::ResponseContentType.as_u8(), 1);
        // Verify they're sequential
        assert_eq!(RuleVariable::UniqueID.as_u8(), 2);
        assert_eq!(RuleVariable::ArgsCombinedSize.as_u8(), 3);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", RuleVariable::Unknown), "UNKNOWN");
        assert_eq!(format!("{}", RuleVariable::RequestURI), "REQUEST_URI");
        assert_eq!(format!("{}", RuleVariable::Args), "ARGS");
    }

    #[test]
    fn test_parse_exact() {
        assert_eq!(
            "REQUEST_URI".parse::<RuleVariable>().unwrap(),
            RuleVariable::RequestURI
        );
        assert_eq!("ARGS".parse::<RuleVariable>().unwrap(), RuleVariable::Args);
        assert_eq!(
            "REQUEST_METHOD".parse::<RuleVariable>().unwrap(),
            RuleVariable::RequestMethod
        );
        assert_eq!("TX".parse::<RuleVariable>().unwrap(), RuleVariable::TX);
    }

    #[test]
    fn test_parse_case_insensitive() {
        assert_eq!(
            "request_uri".parse::<RuleVariable>().unwrap(),
            RuleVariable::RequestURI
        );
        assert_eq!("args".parse::<RuleVariable>().unwrap(), RuleVariable::Args);
        assert_eq!(
            "Request_Method".parse::<RuleVariable>().unwrap(),
            RuleVariable::RequestMethod
        );
        assert_eq!("tx".parse::<RuleVariable>().unwrap(), RuleVariable::TX);
    }

    #[test]
    fn test_parse_invalid() {
        assert!("invalid".parse::<RuleVariable>().is_err());
        assert!("not_a_variable".parse::<RuleVariable>().is_err());
        assert!("".parse::<RuleVariable>().is_err());
    }

    #[test]
    fn test_parse_all_variables() {
        // Test a sampling of variables to ensure they all parse correctly
        let variables = [
            ("UNKNOWN", RuleVariable::Unknown),
            ("RESPONSE_CONTENT_TYPE", RuleVariable::ResponseContentType),
            ("UNIQUE_ID", RuleVariable::UniqueID),
            ("QUERY_STRING", RuleVariable::QueryString),
            ("REMOTE_ADDR", RuleVariable::RemoteAddr),
            ("REQUEST_HEADERS", RuleVariable::RequestHeaders),
            ("RESPONSE_HEADERS", RuleVariable::ResponseHeaders),
            ("GEO", RuleVariable::Geo),
            ("ENV", RuleVariable::Env),
            ("TIME", RuleVariable::Time),
            ("TIME_YEAR", RuleVariable::TimeYear),
        ];

        for (name, expected) in &variables {
            assert_eq!(name.parse::<RuleVariable>().unwrap(), *expected);
        }
    }

    #[test]
    fn test_roundtrip_all_variants() {
        // Test that every variant can roundtrip through name() -> parse()
        // This ensures VARIABLE_NAMES stays in sync with the enum
        let all_variants = [
            RuleVariable::Unknown,
            RuleVariable::ResponseContentType,
            RuleVariable::UniqueID,
            RuleVariable::ArgsCombinedSize,
            RuleVariable::FilesCombinedSize,
            RuleVariable::FullRequestLength,
            RuleVariable::InboundDataError,
            RuleVariable::MatchedVar,
            RuleVariable::MatchedVarName,
            RuleVariable::MultipartDataAfter,
            RuleVariable::OutboundDataError,
            RuleVariable::QueryString,
            RuleVariable::RemoteAddr,
            RuleVariable::RemoteHost,
            RuleVariable::RemotePort,
            RuleVariable::ReqbodyError,
            RuleVariable::ReqbodyErrorMsg,
            RuleVariable::ReqbodyProcessorError,
            RuleVariable::ReqbodyProcessorErrorMsg,
            RuleVariable::ReqbodyProcessor,
            RuleVariable::RequestBasename,
            RuleVariable::RequestBody,
            RuleVariable::RequestBodyLength,
            RuleVariable::RequestFilename,
            RuleVariable::RequestLine,
            RuleVariable::RequestMethod,
            RuleVariable::RequestProtocol,
            RuleVariable::RequestURI,
            RuleVariable::RequestURIRaw,
            RuleVariable::ResponseBody,
            RuleVariable::ResponseContentLength,
            RuleVariable::ResponseProtocol,
            RuleVariable::ResponseStatus,
            RuleVariable::ServerAddr,
            RuleVariable::ServerName,
            RuleVariable::ServerPort,
            RuleVariable::HighestSeverity,
            RuleVariable::StatusLine,
            RuleVariable::Duration,
            RuleVariable::ResponseHeadersNames,
            RuleVariable::RequestHeadersNames,
            RuleVariable::Args,
            RuleVariable::ArgsGet,
            RuleVariable::ArgsPost,
            RuleVariable::ArgsPath,
            RuleVariable::FilesSizes,
            RuleVariable::FilesNames,
            RuleVariable::FilesTmpContent,
            RuleVariable::MultipartFilename,
            RuleVariable::MultipartName,
            RuleVariable::MatchedVarsNames,
            RuleVariable::MatchedVars,
            RuleVariable::Files,
            RuleVariable::RequestCookies,
            RuleVariable::RequestHeaders,
            RuleVariable::ResponseHeaders,
            RuleVariable::ResBodyProcessor,
            RuleVariable::Geo,
            RuleVariable::RequestCookiesNames,
            RuleVariable::FilesTmpNames,
            RuleVariable::ArgsNames,
            RuleVariable::ArgsGetNames,
            RuleVariable::ArgsPostNames,
            RuleVariable::TX,
            RuleVariable::Rule,
            RuleVariable::JSON,
            RuleVariable::Env,
            RuleVariable::UrlencodedError,
            RuleVariable::ResponseArgs,
            RuleVariable::ResponseXML,
            RuleVariable::RequestXML,
            RuleVariable::XML,
            RuleVariable::MultipartPartHeaders,
            RuleVariable::AuthType,
            RuleVariable::FullRequest,
            RuleVariable::MultipartBoundaryQuoted,
            RuleVariable::MultipartBoundaryWhitespace,
            RuleVariable::MultipartCrlfLfLines,
            RuleVariable::MultipartDataBefore,
            RuleVariable::MultipartFileLimitExceeded,
            RuleVariable::MultipartHeaderFolding,
            RuleVariable::MultipartInvalidHeaderFolding,
            RuleVariable::MultipartInvalidPart,
            RuleVariable::MultipartInvalidQuoting,
            RuleVariable::MultipartLfLine,
            RuleVariable::MultipartMissingSemicolon,
            RuleVariable::MultipartStrictError,
            RuleVariable::MultipartUnmatchedBoundary,
            RuleVariable::PathInfo,
            RuleVariable::Sessionid,
            RuleVariable::Userid,
            RuleVariable::IP,
            RuleVariable::ResBodyError,
            RuleVariable::ResBodyErrorMsg,
            RuleVariable::ResBodyProcessorError,
            RuleVariable::ResBodyProcessorErrorMsg,
            RuleVariable::Time,
            RuleVariable::TimeDay,
            RuleVariable::TimeEpoch,
            RuleVariable::TimeHour,
            RuleVariable::TimeMin,
            RuleVariable::TimeMon,
            RuleVariable::TimeSec,
            RuleVariable::TimeWday,
            RuleVariable::TimeYear,
        ];

        for variant in &all_variants {
            let name = variant.name();
            let parsed = name.parse::<RuleVariable>().unwrap();
            assert_eq!(
                parsed, *variant,
                "Roundtrip failed for variant {:?} (name: {})",
                variant, name
            );
        }

        // Verify we tested all variants by checking the count
        assert_eq!(
            all_variants.len(),
            VARIABLE_NAMES.len(),
            "Number of tested variants doesn't match VARIABLE_NAMES length"
        );
    }
}
