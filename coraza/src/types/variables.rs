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

//! Variable identifiers for WAF rule matching.
//!
//! Variables identify specific pieces of information from an HTTP transaction
//! that can be inspected by rules (e.g., ARGS, HEADERS, `REQUEST_URI`).

use std::{fmt, str::FromStr};

use super::RulePhase;

/// Identifies information from a transaction that can be inspected by rules.
///
/// Variables are used in SecLang rules to specify what data to inspect.
/// For example: `SecRule ARGS "@rx attack" ...` inspects all arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RuleVariable {
    /// Unknown/invalid variable (error placeholder)
    Unknown = 0,
    /// `RESPONSE_CONTENT_TYPE` - Content type of the response
    ResponseContentType,
    /// `UNIQUE_ID` - Unique ID of the transaction
    UniqueID,
    /// `ARGS_COMBINED_SIZE` - Combined size of all arguments
    ArgsCombinedSize,
    /// `FILES_COMBINED_SIZE` - Combined size of uploaded files
    FilesCombinedSize,
    /// `FULL_REQUEST_LENGTH` - Length of the full request
    FullRequestLength,
    /// `INBOUND_DATA_ERROR` - Set to 1 when request body size reaches `SecRequestBodyLimit`
    InboundDataError,
    /// `MATCHED_VAR` - Value of the matched variable
    MatchedVar,
    /// `MATCHED_VAR_NAME` - Name of the matched variable
    MatchedVarName,
    /// `MULTIPART_DATA_AFTER` - Kept for compatibility
    MultipartDataAfter,
    /// `OUTBOUND_DATA_ERROR` - Set to 1 when response body size exceeds `SecResponseBodyLimit`
    OutboundDataError,
    /// `QUERY_STRING` - Raw query string part of request URI
    QueryString,
    /// `REMOTE_ADDR` - Remote address of the connection
    RemoteAddr,
    /// `REMOTE_HOST` - Remote host of the connection (not implemented)
    RemoteHost,
    /// `REMOTE_PORT` - Remote port of the connection
    RemotePort,
    /// `REQBODY_ERROR` - Request body processor error status (0=no error, 1=error)
    ReqbodyError,
    /// `REQBODY_ERROR_MSG` - Error message from request body processor
    ReqbodyErrorMsg,
    /// `REQBODY_PROCESSOR_ERROR` - Same as `ReqbodyError`
    ReqbodyProcessorError,
    /// `REQBODY_PROCESSOR_ERROR_MSG` - Same as `ReqbodyErrorMsg`
    ReqbodyProcessorErrorMsg,
    /// `REQBODY_PROCESSOR` - Name of the selected request body processor (RAW, URLENCODED, etc.)
    ReqbodyProcessor,
    /// `REQUEST_BASENAME` - Name after last slash in request URI
    RequestBasename,
    /// `REQUEST_BODY` - Request body bytes when a supported body processor is selected
    RequestBody,
    /// `REQUEST_BODY_LENGTH` - Length of request body in bytes
    RequestBodyLength,
    /// `REQUEST_FILENAME` - Relative request URL without query string
    RequestFilename,
    /// `REQUEST_LINE` - Complete request line (method, URI, HTTP version)
    RequestLine,
    /// `REQUEST_METHOD` - HTTP request method
    RequestMethod,
    /// `REQUEST_PROTOCOL` - HTTP protocol version
    RequestProtocol,
    /// `REQUEST_URI` - Full request URL with query string (without domain)
    RequestURI,
    /// `REQUEST_URI_RAW` - Same as `REQUEST_URI` but with domain if provided
    RequestURIRaw,
    /// `RESPONSE_BODY` - Full response body
    ResponseBody,
    /// `RESPONSE_CONTENT_LENGTH` - Length of response body in bytes
    ResponseContentLength,
    /// `RESPONSE_PROTOCOL` - HTTP response protocol version
    ResponseProtocol,
    /// `RESPONSE_STATUS` - HTTP response status code
    ResponseStatus,
    /// `SERVER_ADDR` - Server address
    ServerAddr,
    /// `SERVER_NAME` - Server name
    ServerName,
    /// `SERVER_PORT` - Server port
    ServerPort,
    /// `HIGHEST_SEVERITY` - Highest severity from all matched rules
    HighestSeverity,
    /// `STATUS_LINE` - Status line of response
    StatusLine,
    /// `DURATION` - Time in milliseconds from transaction start
    Duration,
    /// `RESPONSE_HEADERS_NAMES` - Names of response headers (collection)
    ResponseHeadersNames,
    /// `REQUEST_HEADERS_NAMES` - Names of request headers (collection)
    RequestHeadersNames,
    /// `ARGS` - All arguments (GET and POST combined, collection)
    Args,
    /// `ARGS_GET` - GET (URL) arguments (collection)
    ArgsGet,
    /// `ARGS_POST` - POST (body) arguments (collection)
    ArgsPost,
    /// `ARGS_PATH` - URL path parts (collection)
    ArgsPath,
    /// `FILES_SIZES` - Sizes of uploaded files (collection)
    FilesSizes,
    /// `FILES_NAMES` - Names of uploaded files (collection)
    FilesNames,
    /// `FILES_TMP_CONTENT` - Not supported (collection)
    FilesTmpContent,
    /// `MULTIPART_FILENAME` - Multipart FILENAME field (collection)
    MultipartFilename,
    /// `MULTIPART_NAME` - Multipart NAME field (collection)
    MultipartName,
    /// `MATCHED_VARS_NAMES` - All matched variable names for current operator (collection)
    MatchedVarsNames,
    /// `MATCHED_VARS` - All matched variable values for current operator (collection)
    MatchedVars,
    /// `FILES` - Original file names from multipart/form-data (collection)
    Files,
    /// `REQUEST_COOKIES` - Request cookie values (collection)
    RequestCookies,
    /// `REQUEST_HEADERS` - Request headers (collection)
    RequestHeaders,
    /// `RESPONSE_HEADERS` - Response headers (collection)
    ResponseHeaders,
    /// `RES_BODY_PROCESSOR` - Name of response body processor
    ResBodyProcessor,
    /// `GEO` - Geographic location information of client (collection)
    Geo,
    /// `REQUEST_COOKIES_NAMES` - Names of request cookies (collection)
    RequestCookiesNames,
    /// `FILES_TMPNAMES` - Names of temporary uploaded files (collection)
    FilesTmpNames,
    /// `ARGS_NAMES` - Names of all arguments (POST and GET, collection)
    ArgsNames,
    /// `ARGS_GET_NAMES` - Names of GET arguments (collection)
    ArgsGetNames,
    /// `ARGS_POST_NAMES` - Names of POST arguments (collection)
    ArgsPostNames,
    /// `TX` - Transaction-specific variables (created with setvar, collection)
    TX,
    /// `RULE` - Rule metadata (collection)
    Rule,
    /// `JSON` - JSON data (collection, may be removed)
    #[expect(clippy::upper_case_acronyms, reason = "matches the SecLang variable name")]
    JSON,
    /// `ENV` - Process environment variables (collection)
    Env,
    /// `URLENCODED_ERROR` - Set to 1 if URL parsing failed
    UrlencodedError,
    /// `RESPONSE_ARGS` - Response parsed arguments (collection)
    ResponseArgs,
    /// `RESPONSE_XML` - Response parsed XML (collection)
    ResponseXML,
    /// `REQUEST_XML` - Request parsed XML (collection)
    RequestXML,
    /// `XML` - Pointer to `REQUEST_XML` (collection)
    #[expect(clippy::upper_case_acronyms, reason = "matches the SecLang variable name")]
    XML,
    /// `MULTIPART_PART_HEADERS` - Multipart part headers (collection)
    MultipartPartHeaders,

    // Compatibility variables; some remain unsupported by this runtime.
    /// `AUTH_TYPE` - Authentication type (unsupported)
    AuthType,
    /// `FULL_REQUEST` - Full request (unsupported)
    FullRequest,
    /// `MULTIPART_BOUNDARY_QUOTED` - Kept for compatibility (unsupported)
    MultipartBoundaryQuoted,
    /// `MULTIPART_BOUNDARY_WHITESPACE` - Kept for compatibility (unsupported)
    MultipartBoundaryWhitespace,
    /// `MULTIPART_CRLF_LF_LINES` - Kept for compatibility (unsupported)
    MultipartCrlfLfLines,
    /// `MULTIPART_DATA_BEFORE` - Kept for compatibility (unsupported)
    MultipartDataBefore,
    /// `MULTIPART_FILE_LIMIT_EXCEEDED` - Kept for compatibility (unsupported)
    MultipartFileLimitExceeded,
    /// `MULTIPART_HEADER_FOLDING` - Kept for compatibility (unsupported)
    MultipartHeaderFolding,
    /// `MULTIPART_INVALID_HEADER_FOLDING` - Kept for compatibility (unsupported)
    MultipartInvalidHeaderFolding,
    /// `MULTIPART_INVALID_PART` - Kept for compatibility (unsupported)
    MultipartInvalidPart,
    /// `MULTIPART_INVALID_QUOTING` - Set when filename* is quoted
    MultipartInvalidQuoting,
    /// `MULTIPART_LF_LINE` - Kept for compatibility (unsupported)
    MultipartLfLine,
    /// `MULTIPART_MISSING_SEMICOLON` - Kept for compatibility (unsupported)
    MultipartMissingSemicolon,
    /// `MULTIPART_STRICT_ERROR` - Multipart parsing error flag
    MultipartStrictError,
    /// `MULTIPART_UNMATCHED_BOUNDARY` - Kept for compatibility (unsupported)
    MultipartUnmatchedBoundary,
    /// `PATH_INFO` - Kept for compatibility (unsupported)
    PathInfo,
    /// `SESSIONID` - Not supported
    Sessionid,
    /// `USERID` - Not supported
    Userid,
    /// `IP` - Kept for compatibility (unsupported)
    IP,
    /// `RES_BODY_ERROR` - Response body processor error flag
    ResBodyError,
    /// `RES_BODY_ERROR_MSG` - Response body processor error message
    ResBodyErrorMsg,
    /// `RES_BODY_PROCESSOR_ERROR` - Response body processor error flag
    ResBodyProcessorError,
    /// `RES_BODY_PROCESSOR_ERROR_MSG` - Response body processor error message
    ResBodyProcessorErrorMsg,
    /// `TIME` - Formatted time string (hour:minute:second)
    Time,
    /// `TIME_DAY` - Current day of month (1-31)
    TimeDay,
    /// `TIME_EPOCH` - Time in seconds since 1970
    TimeEpoch,
    /// `TIME_HOUR` - Current hour of day (0-23)
    TimeHour,
    /// `TIME_MIN` - Current minute of hour (0-59)
    TimeMin,
    /// `TIME_MON` - Current month of year (1-12, January=1)
    TimeMon,
    /// `TIME_SEC` - Current second of minute (0-59)
    TimeSec,
    /// `TIME_WDAY` - Current weekday value (0-6, Sunday=0)
    TimeWday,
    /// `TIME_YEAR` - Current four-digit year
    TimeYear,
    // New variables stay after existing entries to preserve their as_u8 values.
    /// `ARGUMENTS_LIMIT_REACHED` - Set to 1 when the argument limit drops a value
    ArgumentsLimitReached,
    /// `MULTIPART_DUPLICATE_PART_HEADER` - Set when a part repeats a header or parameter
    MultipartDuplicatePartHeader,
    /// `MULTIPART_FILENAME_CHARSET` - Charset from the filename* parameter (collection)
    MultipartFilenameCharset,
    /// `MULTIPART_FILENAME_LANGUAGE` - Language from the filename* parameter (collection)
    MultipartFilenameLanguage,
    /// `URI_PARSE_ERROR` - Set to 1 when the request URI could not be parsed
    URIParseError,
}

/// Lookup table of variable variants and names in enum order.
const VARIABLES: &[(RuleVariable, &str)] = &[
    (RuleVariable::Unknown, "UNKNOWN"),
    (RuleVariable::ResponseContentType, "RESPONSE_CONTENT_TYPE"),
    (RuleVariable::UniqueID, "UNIQUE_ID"),
    (RuleVariable::ArgsCombinedSize, "ARGS_COMBINED_SIZE"),
    (RuleVariable::FilesCombinedSize, "FILES_COMBINED_SIZE"),
    (RuleVariable::FullRequestLength, "FULL_REQUEST_LENGTH"),
    (RuleVariable::InboundDataError, "INBOUND_DATA_ERROR"),
    (RuleVariable::MatchedVar, "MATCHED_VAR"),
    (RuleVariable::MatchedVarName, "MATCHED_VAR_NAME"),
    (RuleVariable::MultipartDataAfter, "MULTIPART_DATA_AFTER"),
    (RuleVariable::OutboundDataError, "OUTBOUND_DATA_ERROR"),
    (RuleVariable::QueryString, "QUERY_STRING"),
    (RuleVariable::RemoteAddr, "REMOTE_ADDR"),
    (RuleVariable::RemoteHost, "REMOTE_HOST"),
    (RuleVariable::RemotePort, "REMOTE_PORT"),
    (RuleVariable::ReqbodyError, "REQBODY_ERROR"),
    (RuleVariable::ReqbodyErrorMsg, "REQBODY_ERROR_MSG"),
    (RuleVariable::ReqbodyProcessorError, "REQBODY_PROCESSOR_ERROR"),
    (RuleVariable::ReqbodyProcessorErrorMsg, "REQBODY_PROCESSOR_ERROR_MSG"),
    (RuleVariable::ReqbodyProcessor, "REQBODY_PROCESSOR"),
    (RuleVariable::RequestBasename, "REQUEST_BASENAME"),
    (RuleVariable::RequestBody, "REQUEST_BODY"),
    (RuleVariable::RequestBodyLength, "REQUEST_BODY_LENGTH"),
    (RuleVariable::RequestFilename, "REQUEST_FILENAME"),
    (RuleVariable::RequestLine, "REQUEST_LINE"),
    (RuleVariable::RequestMethod, "REQUEST_METHOD"),
    (RuleVariable::RequestProtocol, "REQUEST_PROTOCOL"),
    (RuleVariable::RequestURI, "REQUEST_URI"),
    (RuleVariable::RequestURIRaw, "REQUEST_URI_RAW"),
    (RuleVariable::ResponseBody, "RESPONSE_BODY"),
    (RuleVariable::ResponseContentLength, "RESPONSE_CONTENT_LENGTH"),
    (RuleVariable::ResponseProtocol, "RESPONSE_PROTOCOL"),
    (RuleVariable::ResponseStatus, "RESPONSE_STATUS"),
    (RuleVariable::ServerAddr, "SERVER_ADDR"),
    (RuleVariable::ServerName, "SERVER_NAME"),
    (RuleVariable::ServerPort, "SERVER_PORT"),
    (RuleVariable::HighestSeverity, "HIGHEST_SEVERITY"),
    (RuleVariable::StatusLine, "STATUS_LINE"),
    (RuleVariable::Duration, "DURATION"),
    (RuleVariable::ResponseHeadersNames, "RESPONSE_HEADERS_NAMES"),
    (RuleVariable::RequestHeadersNames, "REQUEST_HEADERS_NAMES"),
    (RuleVariable::Args, "ARGS"),
    (RuleVariable::ArgsGet, "ARGS_GET"),
    (RuleVariable::ArgsPost, "ARGS_POST"),
    (RuleVariable::ArgsPath, "ARGS_PATH"),
    (RuleVariable::FilesSizes, "FILES_SIZES"),
    (RuleVariable::FilesNames, "FILES_NAMES"),
    (RuleVariable::FilesTmpContent, "FILES_TMP_CONTENT"),
    (RuleVariable::MultipartFilename, "MULTIPART_FILENAME"),
    (RuleVariable::MultipartName, "MULTIPART_NAME"),
    (RuleVariable::MatchedVarsNames, "MATCHED_VARS_NAMES"),
    (RuleVariable::MatchedVars, "MATCHED_VARS"),
    (RuleVariable::Files, "FILES"),
    (RuleVariable::RequestCookies, "REQUEST_COOKIES"),
    (RuleVariable::RequestHeaders, "REQUEST_HEADERS"),
    (RuleVariable::ResponseHeaders, "RESPONSE_HEADERS"),
    (RuleVariable::ResBodyProcessor, "RES_BODY_PROCESSOR"),
    (RuleVariable::Geo, "GEO"),
    (RuleVariable::RequestCookiesNames, "REQUEST_COOKIES_NAMES"),
    (RuleVariable::FilesTmpNames, "FILES_TMPNAMES"),
    (RuleVariable::ArgsNames, "ARGS_NAMES"),
    (RuleVariable::ArgsGetNames, "ARGS_GET_NAMES"),
    (RuleVariable::ArgsPostNames, "ARGS_POST_NAMES"),
    (RuleVariable::TX, "TX"),
    (RuleVariable::Rule, "RULE"),
    (RuleVariable::JSON, "JSON"),
    (RuleVariable::Env, "ENV"),
    (RuleVariable::UrlencodedError, "URLENCODED_ERROR"),
    (RuleVariable::ResponseArgs, "RESPONSE_ARGS"),
    (RuleVariable::ResponseXML, "RESPONSE_XML"),
    (RuleVariable::RequestXML, "REQUEST_XML"),
    (RuleVariable::XML, "XML"),
    (RuleVariable::MultipartPartHeaders, "MULTIPART_PART_HEADERS"),
    (RuleVariable::AuthType, "AUTH_TYPE"),
    (RuleVariable::FullRequest, "FULL_REQUEST"),
    (RuleVariable::MultipartBoundaryQuoted, "MULTIPART_BOUNDARY_QUOTED"),
    (
        RuleVariable::MultipartBoundaryWhitespace,
        "MULTIPART_BOUNDARY_WHITESPACE",
    ),
    (RuleVariable::MultipartCrlfLfLines, "MULTIPART_CRLF_LF_LINES"),
    (RuleVariable::MultipartDataBefore, "MULTIPART_DATA_BEFORE"),
    (
        RuleVariable::MultipartFileLimitExceeded,
        "MULTIPART_FILE_LIMIT_EXCEEDED",
    ),
    (RuleVariable::MultipartHeaderFolding, "MULTIPART_HEADER_FOLDING"),
    (
        RuleVariable::MultipartInvalidHeaderFolding,
        "MULTIPART_INVALID_HEADER_FOLDING",
    ),
    (RuleVariable::MultipartInvalidPart, "MULTIPART_INVALID_PART"),
    (RuleVariable::MultipartInvalidQuoting, "MULTIPART_INVALID_QUOTING"),
    (RuleVariable::MultipartLfLine, "MULTIPART_LF_LINE"),
    (RuleVariable::MultipartMissingSemicolon, "MULTIPART_MISSING_SEMICOLON"),
    (RuleVariable::MultipartStrictError, "MULTIPART_STRICT_ERROR"),
    (RuleVariable::MultipartUnmatchedBoundary, "MULTIPART_UNMATCHED_BOUNDARY"),
    (RuleVariable::PathInfo, "PATH_INFO"),
    (RuleVariable::Sessionid, "SESSIONID"),
    (RuleVariable::Userid, "USERID"),
    (RuleVariable::IP, "IP"),
    (RuleVariable::ResBodyError, "RES_BODY_ERROR"),
    (RuleVariable::ResBodyErrorMsg, "RES_BODY_ERROR_MSG"),
    (RuleVariable::ResBodyProcessorError, "RES_BODY_PROCESSOR_ERROR"),
    (RuleVariable::ResBodyProcessorErrorMsg, "RES_BODY_PROCESSOR_ERROR_MSG"),
    (RuleVariable::Time, "TIME"),
    (RuleVariable::TimeDay, "TIME_DAY"),
    (RuleVariable::TimeEpoch, "TIME_EPOCH"),
    (RuleVariable::TimeHour, "TIME_HOUR"),
    (RuleVariable::TimeMin, "TIME_MIN"),
    (RuleVariable::TimeMon, "TIME_MON"),
    (RuleVariable::TimeSec, "TIME_SEC"),
    (RuleVariable::TimeWday, "TIME_WDAY"),
    (RuleVariable::TimeYear, "TIME_YEAR"),
    (RuleVariable::ArgumentsLimitReached, "ARGUMENTS_LIMIT_REACHED"),
    (
        RuleVariable::MultipartDuplicatePartHeader,
        "MULTIPART_DUPLICATE_PART_HEADER",
    ),
    (RuleVariable::MultipartFilenameCharset, "MULTIPART_FILENAME_CHARSET"),
    (RuleVariable::MultipartFilenameLanguage, "MULTIPART_FILENAME_LANGUAGE"),
    (RuleVariable::URIParseError, "URI_PARSE_ERROR"),
];

impl RuleVariable {
    /// Earliest transaction phase in which Go Coraza v3.8.1 can populate this variable.
    ///
    /// `None` represents Go's `PhaseUnknown`; those variables may depend on rule state
    /// or are only useful for logging. This mapping is used by multiphase inference and
    /// variable skipping.
    #[expect(
        clippy::too_many_lines,
        reason = "the exhaustive Go variable phase table stays in one match"
    )]
    pub const fn min_phase(self) -> Option<RulePhase> {
        use RulePhase::{RequestBody, RequestHeaders, ResponseBody, ResponseHeaders};

        match self {
            Self::ResponseContentType
            | Self::ResponseProtocol
            | Self::ResponseStatus
            | Self::StatusLine
            | Self::ResponseHeadersNames
            | Self::ResponseHeaders => Some(ResponseHeaders),
            Self::FilesCombinedSize
            | Self::FullRequestLength
            | Self::InboundDataError
            | Self::MultipartDataAfter
            | Self::MultipartDuplicatePartHeader
            | Self::MultipartInvalidQuoting
            | Self::ReqbodyError
            | Self::ReqbodyErrorMsg
            | Self::ReqbodyProcessorError
            | Self::ReqbodyProcessorErrorMsg
            | Self::RequestBody
            | Self::RequestBodyLength
            | Self::Args
            | Self::ArgsPost
            | Self::ArgsNames
            | Self::ArgsPostNames
            | Self::FilesSizes
            | Self::FilesNames
            | Self::FilesTmpContent
            | Self::MultipartFilename
            | Self::MultipartFilenameCharset
            | Self::MultipartFilenameLanguage
            | Self::MultipartName
            | Self::Files
            | Self::FilesTmpNames
            | Self::JSON
            | Self::RequestXML
            | Self::XML
            | Self::MultipartPartHeaders => Some(RequestBody),
            Self::OutboundDataError
            | Self::ResponseBody
            | Self::ResponseContentLength
            | Self::ResponseArgs
            | Self::ResponseXML => Some(ResponseBody),
            Self::UniqueID
            | Self::ArgsCombinedSize
            | Self::QueryString
            | Self::RemoteAddr
            | Self::RemoteHost
            | Self::RemotePort
            | Self::RequestBasename
            | Self::RequestFilename
            | Self::RequestLine
            | Self::RequestMethod
            | Self::RequestProtocol
            | Self::RequestURI
            | Self::RequestURIRaw
            | Self::ServerAddr
            | Self::ServerName
            | Self::ServerPort
            | Self::RequestHeadersNames
            | Self::ArgsGet
            | Self::ArgsGetNames
            | Self::ArgsPath
            | Self::RequestCookies
            | Self::RequestHeaders
            | Self::Geo
            | Self::RequestCookiesNames
            | Self::Env
            | Self::UrlencodedError
            | Self::URIParseError
            | Self::Time
            | Self::TimeDay
            | Self::TimeEpoch
            | Self::TimeHour
            | Self::TimeMin
            | Self::TimeMon
            | Self::TimeSec
            | Self::TimeWday
            | Self::TimeYear => Some(RequestHeaders),
            Self::Unknown
            | Self::MatchedVar
            | Self::MatchedVarName
            | Self::ReqbodyProcessor
            | Self::HighestSeverity
            | Self::Duration
            | Self::MatchedVarsNames
            | Self::MatchedVars
            | Self::ResBodyProcessor
            | Self::TX
            | Self::Rule
            | Self::AuthType
            | Self::FullRequest
            | Self::MultipartBoundaryQuoted
            | Self::MultipartBoundaryWhitespace
            | Self::MultipartCrlfLfLines
            | Self::MultipartDataBefore
            | Self::MultipartFileLimitExceeded
            | Self::MultipartHeaderFolding
            | Self::MultipartInvalidHeaderFolding
            | Self::MultipartInvalidPart
            | Self::MultipartLfLine
            | Self::MultipartMissingSemicolon
            | Self::MultipartStrictError
            | Self::MultipartUnmatchedBoundary
            | Self::PathInfo
            | Self::Sessionid
            | Self::Userid
            | Self::IP
            | Self::ResBodyError
            | Self::ResBodyErrorMsg
            | Self::ResBodyProcessorError
            | Self::ResBodyProcessorErrorMsg
            | Self::ArgumentsLimitReached => None,
        }
    }

    /// Returns the `SCREAMING_SNAKE_CASE` name of the variable.
    ///
    /// Used for audit logging and string representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::types::RuleVariable;
    ///
    /// assert_eq!(RuleVariable::RequestURI.name(), "REQUEST_URI");
    /// assert_eq!(RuleVariable::Args.name(), "ARGS");
    /// ```
    pub fn name(self) -> &'static str {
        match VARIABLES.get(self as usize) {
            Some((_, name)) => name,
            None => "UNKNOWN",
        }
    }

    /// Returns the numeric value of the variable.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::types::RuleVariable;
    ///
    /// assert_eq!(RuleVariable::Unknown.as_u8(), 0);
    /// assert_eq!(RuleVariable::ResponseContentType.as_u8(), 1);
    /// ```
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether the variable accepts a collection key selector.
    pub const fn can_be_selected(self) -> bool {
        matches!(
            self,
            Self::ResponseHeadersNames
                | Self::RequestHeadersNames
                | Self::Args
                | Self::ArgsGet
                | Self::ArgsPost
                | Self::ArgsPath
                | Self::FilesSizes
                | Self::FilesNames
                | Self::FilesTmpContent
                | Self::MultipartFilename
                | Self::MultipartName
                | Self::MatchedVarsNames
                | Self::MatchedVars
                | Self::Files
                | Self::RequestCookies
                | Self::RequestHeaders
                | Self::ResponseHeaders
                | Self::Geo
                | Self::RequestCookiesNames
                | Self::FilesTmpNames
                | Self::ArgsNames
                | Self::ArgsGetNames
                | Self::ArgsPostNames
                | Self::TX
                | Self::Rule
                | Self::JSON
                | Self::XML
                | Self::Env
                | Self::ResponseArgs
                | Self::RequestXML
                | Self::ResponseXML
                | Self::IP
                | Self::MultipartPartHeaders
                | Self::MultipartFilenameCharset
                | Self::MultipartFilenameLanguage
        )
    }

    /// Whether this variable's keys can be matched case-sensitively.
    ///
    /// Only the argument collections can: they use case-sensitive keys when
    /// `WafConfig::case_sensitive_args_keys` is set, matching Go's
    /// `coraza.rule.case_sensitive_args_keys` build tag. Every other collection
    /// stores case-insensitive keys, as Go does by default.
    pub const fn has_case_sensitive_keys(self) -> bool {
        matches!(
            self,
            Self::Args
                | Self::ArgsGet
                | Self::ArgsPost
                | Self::ArgsPath
                | Self::ArgsNames
                | Self::ArgsGetNames
                | Self::ArgsPostNames
        )
    }

    /// Whether this variable's key selectors keep their written case.
    ///
    /// Go lower-cases both the selector text and its regex source for every variable
    /// outside `caseSensitiveVariable` (`internal/corazawaf/rule.go:548-570`), then
    /// compiles the pattern without the case-insensitive flag. `ARGS_PATH` is absent
    /// from Go's list even though its map is case-sensitive under
    /// `coraza.rule.case_sensitive_args_keys`, so its literal selectors are lowered
    /// against a map that keeps stored keys as written.
    pub const fn has_case_sensitive_selectors(self) -> bool {
        matches!(
            self,
            Self::Args | Self::ArgsGet | Self::ArgsPost | Self::ArgsNames | Self::ArgsGetNames | Self::ArgsPostNames
        )
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
    /// Original value that failed to parse.
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
    /// use std::str::FromStr;
    ///
    /// use coraza::types::RuleVariable;
    ///
    /// assert_eq!(
    ///     RuleVariable::from_str("REQUEST_URI").unwrap(),
    ///     RuleVariable::RequestURI
    /// );
    /// assert_eq!(RuleVariable::from_str("args").unwrap(), RuleVariable::Args);
    /// assert_eq!(
    ///     RuleVariable::from_str("Request_Method").unwrap(),
    ///     RuleVariable::RequestMethod
    /// );
    /// assert!(RuleVariable::from_str("invalid").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let upper = s.to_uppercase();
        VARIABLES
            .iter()
            .find_map(|(variable, name)| (*name).eq(upper.as_str()).then_some(*variable))
            .ok_or_else(|| ParseVariableError { input: s.to_owned() })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert successful parsing")]
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
        assert_eq!("REQUEST_URI".parse::<RuleVariable>().unwrap(), RuleVariable::RequestURI);
        assert_eq!("ARGS".parse::<RuleVariable>().unwrap(), RuleVariable::Args);
        assert_eq!(
            "REQUEST_METHOD".parse::<RuleVariable>().unwrap(),
            RuleVariable::RequestMethod
        );
        assert_eq!("TX".parse::<RuleVariable>().unwrap(), RuleVariable::TX);
    }

    #[test]
    fn test_parse_case_insensitive() {
        assert_eq!("request_uri".parse::<RuleVariable>().unwrap(), RuleVariable::RequestURI);
        assert_eq!("args".parse::<RuleVariable>().unwrap(), RuleVariable::Args);
        assert_eq!(
            "Request_Method".parse::<RuleVariable>().unwrap(),
            RuleVariable::RequestMethod
        );
        assert_eq!("tx".parse::<RuleVariable>().unwrap(), RuleVariable::TX);
        assert_eq!("REQUEſT_URI".parse::<RuleVariable>().unwrap(), RuleVariable::RequestURI);
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
            ("ARGUMENTS_LIMIT_REACHED", RuleVariable::ArgumentsLimitReached),
        ];

        for (name, expected) in &variables {
            assert_eq!(name.parse::<RuleVariable>().unwrap(), *expected);
        }
    }

    #[test]
    fn test_parse_coraza_canonical_names() {
        let variables = [
            ("RES_BODY_PROCESSOR", RuleVariable::ResBodyProcessor),
            ("FILES_TMPNAMES", RuleVariable::FilesTmpNames),
            ("RES_BODY_ERROR", RuleVariable::ResBodyError),
            ("RES_BODY_ERROR_MSG", RuleVariable::ResBodyErrorMsg),
            ("RES_BODY_PROCESSOR_ERROR", RuleVariable::ResBodyProcessorError),
            ("RES_BODY_PROCESSOR_ERROR_MSG", RuleVariable::ResBodyProcessorErrorMsg),
        ];

        for (name, expected) in variables {
            let parsed = name.parse::<RuleVariable>().unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.name(), name);
            assert_eq!(name.to_lowercase().parse::<RuleVariable>().unwrap(), expected);
        }
    }

    #[test]
    fn test_case_sensitive_key_variables() {
        for variable in [
            RuleVariable::Args,
            RuleVariable::ArgsGet,
            RuleVariable::ArgsPost,
            RuleVariable::ArgsPath,
            RuleVariable::ArgsNames,
            RuleVariable::ArgsGetNames,
            RuleVariable::ArgsPostNames,
        ] {
            assert!(variable.has_case_sensitive_keys(), "{variable:?}");
        }
        for variable in [
            RuleVariable::Files,
            RuleVariable::FilesNames,
            RuleVariable::FilesSizes,
            RuleVariable::FilesTmpNames,
            RuleVariable::MultipartPartHeaders,
            RuleVariable::MultipartName,
            RuleVariable::MultipartFilename,
            RuleVariable::MultipartFilenameCharset,
            RuleVariable::MultipartFilenameLanguage,
            RuleVariable::RequestXML,
            RuleVariable::ResponseArgs,
            RuleVariable::ResponseXML,
            RuleVariable::Env,
        ] {
            assert!(!variable.has_case_sensitive_keys(), "{variable:?}");
        }
    }

    #[test]
    fn test_case_sensitive_selector_variables() {
        for variable in [
            RuleVariable::Args,
            RuleVariable::ArgsGet,
            RuleVariable::ArgsPost,
            RuleVariable::ArgsNames,
            RuleVariable::ArgsGetNames,
            RuleVariable::ArgsPostNames,
        ] {
            assert!(variable.has_case_sensitive_selectors(), "{variable:?}");
        }
        // Go's `caseSensitiveVariable` leaves ARGS_PATH out even though the map itself is
        // case-sensitive under its build tag.
        for variable in [
            RuleVariable::ArgsPath,
            RuleVariable::RequestHeaders,
            RuleVariable::RequestXML,
            RuleVariable::XML,
        ] {
            assert!(!variable.has_case_sensitive_selectors(), "{variable:?}");
        }
    }

    #[test]
    fn test_roundtrip_all_variants() {
        for (index, (variant, name)) in VARIABLES.iter().enumerate() {
            assert_eq!(usize::from(variant.as_u8()), index);
            assert_eq!(variant.name(), *name);
            assert_eq!(
                name.parse::<RuleVariable>().unwrap(),
                *variant,
                "Roundtrip failed for variant {variant:?} (name: {name})"
            );
        }

        assert_eq!(usize::from(RuleVariable::URIParseError.as_u8()) + 1, VARIABLES.len());
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one table asserts the phase of every RuleVariable variant"
    )]
    fn min_phase_covers_every_variable_variant() {
        use RulePhase::{RequestBody, RequestHeaders, ResponseBody, ResponseHeaders};

        let cases: &[(Option<RulePhase>, &[RuleVariable])] = &[
            (
                Some(RequestHeaders),
                &[
                    RuleVariable::UniqueID,
                    RuleVariable::ArgsCombinedSize,
                    RuleVariable::QueryString,
                    RuleVariable::RemoteAddr,
                    RuleVariable::RemoteHost,
                    RuleVariable::RemotePort,
                    RuleVariable::RequestBasename,
                    RuleVariable::RequestFilename,
                    RuleVariable::RequestLine,
                    RuleVariable::RequestMethod,
                    RuleVariable::RequestProtocol,
                    RuleVariable::RequestURI,
                    RuleVariable::RequestURIRaw,
                    RuleVariable::ServerAddr,
                    RuleVariable::ServerName,
                    RuleVariable::ServerPort,
                    RuleVariable::RequestHeadersNames,
                    RuleVariable::ArgsGet,
                    RuleVariable::ArgsGetNames,
                    RuleVariable::ArgsPath,
                    RuleVariable::RequestCookies,
                    RuleVariable::RequestHeaders,
                    RuleVariable::Geo,
                    RuleVariable::RequestCookiesNames,
                    RuleVariable::Env,
                    RuleVariable::UrlencodedError,
                    RuleVariable::URIParseError,
                    RuleVariable::Time,
                    RuleVariable::TimeDay,
                    RuleVariable::TimeEpoch,
                    RuleVariable::TimeHour,
                    RuleVariable::TimeMin,
                    RuleVariable::TimeMon,
                    RuleVariable::TimeSec,
                    RuleVariable::TimeWday,
                    RuleVariable::TimeYear,
                ],
            ),
            (
                Some(RequestBody),
                &[
                    RuleVariable::FilesCombinedSize,
                    RuleVariable::FullRequestLength,
                    RuleVariable::InboundDataError,
                    RuleVariable::MultipartDataAfter,
                    RuleVariable::MultipartDuplicatePartHeader,
                    RuleVariable::MultipartInvalidQuoting,
                    RuleVariable::ReqbodyError,
                    RuleVariable::ReqbodyErrorMsg,
                    RuleVariable::ReqbodyProcessorError,
                    RuleVariable::ReqbodyProcessorErrorMsg,
                    RuleVariable::RequestBody,
                    RuleVariable::RequestBodyLength,
                    RuleVariable::Args,
                    RuleVariable::ArgsPost,
                    RuleVariable::ArgsNames,
                    RuleVariable::ArgsPostNames,
                    RuleVariable::FilesSizes,
                    RuleVariable::FilesNames,
                    RuleVariable::FilesTmpContent,
                    RuleVariable::MultipartFilename,
                    RuleVariable::MultipartFilenameCharset,
                    RuleVariable::MultipartFilenameLanguage,
                    RuleVariable::MultipartName,
                    RuleVariable::Files,
                    RuleVariable::FilesTmpNames,
                    RuleVariable::JSON,
                    RuleVariable::RequestXML,
                    RuleVariable::XML,
                    RuleVariable::MultipartPartHeaders,
                ],
            ),
            (
                Some(ResponseHeaders),
                &[
                    RuleVariable::ResponseContentType,
                    RuleVariable::ResponseProtocol,
                    RuleVariable::ResponseStatus,
                    RuleVariable::StatusLine,
                    RuleVariable::ResponseHeadersNames,
                    RuleVariable::ResponseHeaders,
                ],
            ),
            (
                Some(ResponseBody),
                &[
                    RuleVariable::OutboundDataError,
                    RuleVariable::ResponseBody,
                    RuleVariable::ResponseContentLength,
                    RuleVariable::ResponseArgs,
                    RuleVariable::ResponseXML,
                ],
            ),
            (
                None,
                &[
                    RuleVariable::Unknown,
                    RuleVariable::MatchedVar,
                    RuleVariable::MatchedVarName,
                    RuleVariable::ReqbodyProcessor,
                    RuleVariable::HighestSeverity,
                    RuleVariable::Duration,
                    RuleVariable::MatchedVarsNames,
                    RuleVariable::MatchedVars,
                    RuleVariable::ResBodyProcessor,
                    RuleVariable::TX,
                    RuleVariable::Rule,
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
                    RuleVariable::ArgumentsLimitReached,
                ],
            ),
        ];

        let mut seen = Vec::new();
        for (expected, variables) in cases {
            for variable in *variables {
                assert_eq!(variable.min_phase(), *expected, "{variable:?}");
                assert!(!seen.contains(variable), "duplicate min_phase case: {variable:?}");
                seen.push(*variable);
            }
        }
        assert_eq!(seen.len(), VARIABLES.len());
        for (variable, _) in VARIABLES {
            assert!(seen.contains(variable), "missing min_phase case: {variable:?}");
        }
    }
}
