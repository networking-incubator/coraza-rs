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

//! Multipart/form-data parser (RFC 7578).
//!
//! A standalone, synchronous parser for multipart/form-data bodies.
//! This implementation follows the Go stdlib mime/multipart closely
//! for maximum compatibility.

/// An error from parsing a multipart body.
#[derive(Debug)]
pub(super) enum ParseError {
    /// A part has missing or malformed headers.
    MalformedHeaders(String),
    /// The body is not a complete multipart message.
    Parse(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::MalformedHeaders(msg) => write!(f, "malformed headers: {msg}"),
            ParseError::Parse(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// The charset and language of an RFC 5987 `filename*` parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilenameEncoding {
    /// e.g. `UTF-8`
    pub(crate) charset: String,
    /// e.g. `en`; may be empty
    pub(crate) language: String,
}

/// A single part in a multipart message
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "these flags report independent Coraza multipart conditions"
)]
pub(crate) struct Part<'a> {
    /// Form field name (from Content-Disposition name parameter)
    pub(crate) name: String,

    /// Filename, if this is a file upload: from the Content-Disposition `filename*`
    /// parameter, decoded, or else from `filename`
    pub(crate) filename: Option<String>,

    /// The `filename` parameter, when `filename*` gave a different name
    pub(crate) alt_filename: Option<String>,

    /// The charset and language of the `filename*` parameter
    pub(crate) filename_encoding: Option<FilenameEncoding>,

    /// Whether the `filename*` parameter is malformed
    pub(crate) malformed_filename: bool,

    /// Its headers, in order: each name as sent, and its value
    pub(crate) headers: Vec<(String, String)>,

    /// Whether the part repeats a header, or a parameter of its Content-Disposition
    pub(crate) repeats_header: bool,

    /// Whether its Content-Disposition `filename*` is quoted, which RFC 5987 forbids
    pub(crate) invalid_quoting: bool,

    /// The part body data
    pub(crate) data: &'a [u8],
}

/// Multipart parser for RFC 7578 multipart/form-data
pub(super) struct MultipartParser<'a> {
    /// Boundary marker from the content type.
    boundary: Vec<u8>,
    /// Complete request body borrowed for parsing.
    data: &'a [u8],
}

impl<'a> MultipartParser<'a> {
    /// Create a new multipart parser
    ///
    /// # Arguments
    ///
    /// * `boundary` - The boundary string (without leading dashes)
    /// * `data` - The complete multipart body
    pub(super) fn new(boundary: impl Into<String>, data: &'a [u8]) -> Self {
        Self {
            boundary: boundary.into().into_bytes(),
            data,
        }
    }

    /// Parse all parts from the multipart body
    ///
    /// Returns a vector of parsed parts, or an error if parsing fails.
    pub(super) fn parse(&self) -> Result<Vec<Part<'a>>, ParseError> {
        let mut parts = Vec::new();

        // Build boundary markers
        // Initial boundary: --{boundary}
        // Subsequent boundaries: \r\n--{boundary} or \n--{boundary}
        // Final boundary: --{boundary}--
        let mut boundary_marker = b"--".to_vec();
        boundary_marker.extend_from_slice(&self.boundary);

        // Look for first boundary (may have leading data before it)
        let mut pos = if let Some(first_boundary) = find_subsequence(self.data, &boundary_marker) {
            let after_boundary = first_boundary
                .checked_add(boundary_marker.len())
                .ok_or_else(|| ParseError::Parse("boundary position overflow".to_owned()))?;
            // Skip line ending after first boundary
            skip_line_ending(self.data, after_boundary)
        } else {
            return Err(ParseError::Parse("no boundary found".to_owned()));
        };

        let mut closed = self
            .data
            .get(pos..)
            .is_some_and(|remaining| remaining.starts_with(b"--"));

        // Parse each part
        while !closed {
            let remaining = self
                .data
                .get(pos..)
                .ok_or_else(|| ParseError::Parse("missing final boundary".to_owned()))?;
            let (part_end, boundary_start) = find_next_boundary(remaining, &boundary_marker)
                .ok_or_else(|| ParseError::Parse("missing final boundary".to_owned()))?;
            let next_boundary_pos = pos
                .checked_add(part_end)
                .ok_or_else(|| ParseError::Parse("boundary position overflow".to_owned()))?;
            let boundary_marker_pos = pos
                .checked_add(boundary_start)
                .ok_or_else(|| ParseError::Parse("boundary position overflow".to_owned()))?;

            // Extract part data (from current pos to boundary)
            let part_data = self
                .data
                .get(pos..next_boundary_pos)
                .ok_or_else(|| ParseError::Parse("invalid part range".to_owned()))?;

            // Parse this part (propagate errors)
            let part = parse_part(part_data)?;
            parts.push(part);

            // Move past the boundary
            pos = boundary_marker_pos
                .checked_add(boundary_marker.len())
                .ok_or_else(|| ParseError::Parse("boundary position overflow".to_owned()))?;

            // Check if this is the final boundary (ends with --)
            if self
                .data
                .get(pos..)
                .is_some_and(|remaining| remaining.starts_with(b"--"))
            {
                closed = true;
                break;
            }

            // Skip line ending after boundary
            pos = skip_line_ending(self.data, pos);
        }

        if closed {
            Ok(parts)
        } else {
            Err(ParseError::Parse("missing final boundary".to_owned()))
        }
    }
}

/// Parse a single part (headers + body)
fn parse_part(data: &[u8]) -> Result<Part<'_>, ParseError> {
    // Find the blank line that separates headers from body
    let (header_end, separator_len) =
        find_header_end(data).ok_or_else(|| ParseError::MalformedHeaders("no blank line after headers".to_owned()))?;

    // Split headers and body
    let header_data = data
        .get(..header_end)
        .ok_or_else(|| ParseError::MalformedHeaders("invalid header range".to_owned()))?;
    let body_start = header_end
        .checked_add(separator_len)
        .ok_or_else(|| ParseError::MalformedHeaders("invalid body offset".to_owned()))?;

    // The boundary prefix is excluded from part_data, so preserve all part bytes.
    let body_data = data
        .get(body_start..)
        .ok_or_else(|| ParseError::MalformedHeaders("invalid body range".to_owned()))?;

    // Parse headers
    let headers = parse_headers(header_data)?;

    let disposition = extract_content_disposition(&headers)?;
    let mut seen_headers = std::collections::HashSet::with_capacity(headers.len());
    let repeats_header = disposition.repeats_param
        || headers
            .iter()
            .any(|(name, _)| !seen_headers.insert(name.to_ascii_lowercase()));

    Ok(Part {
        name: disposition.name,
        filename: disposition.filename,
        alt_filename: disposition.alt_filename,
        filename_encoding: disposition.filename_encoding,
        malformed_filename: disposition.malformed_extended_filename,
        headers,
        repeats_header,
        invalid_quoting: disposition.quoted_extended_filename,
        data: body_data,
    })
}

/// The value of the first header named `name`, whatever its case.
fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Parse headers from header data, in order, each name as sent
fn parse_headers(data: &[u8]) -> Result<Vec<(String, String)>, ParseError> {
    let mut headers = Vec::new();
    let header_str = String::from_utf8_lossy(data);

    for line in header_str.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            return Err(ParseError::MalformedHeaders(
                "folded header lines are not supported".to_owned(),
            ));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| ParseError::MalformedHeaders("invalid header line".to_owned()))?;
        if name.is_empty()
            || name.trim() != name
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return Err(ParseError::MalformedHeaders("invalid header name".to_owned()));
        }
        let value = value.trim();
        if value.bytes().any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7F) {
            return Err(ParseError::MalformedHeaders("invalid header value".to_owned()));
        }
        headers.push((name.to_owned(), value.to_owned()));
    }

    Ok(headers)
}

/// What a part's Content-Disposition header says.
#[expect(
    clippy::struct_excessive_bools,
    reason = "these flags report independent Coraza multipart conditions"
)]
struct ContentDisposition {
    /// The part name from `Content-Disposition`.
    name: String,
    /// `filename*` decoded, or else `filename`
    filename: Option<String>,
    /// `filename`, when `filename*` gave a different one
    alt_filename: Option<String>,
    /// The charset and language of `filename*`
    filename_encoding: Option<FilenameEncoding>,
    /// Whether `filename*` isn't `charset'language'value` or holds an invalid escape
    malformed_extended_filename: bool,
    /// Whether a parameter appears more than once; the last one counts
    repeats_param: bool,
    /// Whether `filename*` is a quoted string
    quoted_extended_filename: bool,
}

/// Extract name and filename from Content-Disposition header
///
/// Example: `form-data; name="field"; filename="file.txt"`
fn extract_content_disposition(headers: &[(String, String)]) -> Result<ContentDisposition, ParseError> {
    let disposition = header(headers, "content-disposition")
        .ok_or_else(|| ParseError::MalformedHeaders("missing Content-Disposition".to_owned()))?;

    let params = parse_header_params(disposition);
    let param = |name: &str| params.iter().rev().find(|p| p.name == name).map(|p| p.value.clone());
    let mut seen_params = std::collections::HashSet::with_capacity(params.len());
    let repeats_param = params.iter().any(|param| !seen_params.insert(param.name.as_str()));
    let quoted_extended_filename = params.iter().any(|p| p.name == "filename*" && p.quoted);

    let name =
        param("name").ok_or_else(|| ParseError::MalformedHeaders("missing name in Content-Disposition".to_owned()))?;

    // As Go Coraza reads RFC 5987's `filename*=charset'language'value`
    let plain = param("filename");
    let mut disposition = ContentDisposition {
        name,
        filename: plain.clone(),
        alt_filename: None,
        filename_encoding: None,
        malformed_extended_filename: false,
        repeats_param,
        quoted_extended_filename,
    };
    if let Some(extended) = param("filename*") {
        match extended.splitn(3, '\'').collect::<Vec<_>>().as_slice() {
            [charset, language, value] => {
                let (decoded, invalid_escape) = percent_decode_lenient(value);
                disposition.alt_filename = plain.filter(|plain| !plain.is_empty() && *plain != decoded);
                disposition.filename = Some(decoded);
                disposition.filename_encoding = Some(FilenameEncoding {
                    charset: (*charset).to_owned(),
                    language: (*language).to_owned(),
                });
                disposition.malformed_extended_filename = invalid_escape;
            },
            _ => disposition.malformed_extended_filename = true,
        }
    }
    Ok(disposition)
}

/// `value` with its `%XX` escapes decoded, and whether it held an invalid one, which is
/// kept as written.
fn percent_decode_lenient(value: &str) -> (String, bool) {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut invalid = false;
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        let escaped = (byte == b'%')
            .then(|| {
                i.checked_add(1)
                    .and_then(|start| bytes.get(start..start.checked_add(2)?))
            })
            .flatten()
            .and_then(|hex| u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok());
        if let Some(escaped) = escaped {
            decoded.push(escaped);
            i += 3;
        } else {
            invalid |= byte == b'%';
            decoded.push(byte);
            i += 1;
        }
    }
    (String::from_utf8_lossy(&decoded).into_owned(), invalid)
}

/// One `name=value` parameter of a header.
#[derive(Debug, PartialEq)]
struct HeaderParam {
    /// Lowercase name
    name: String,
    /// Value, without its quotes
    value: String,
    /// Whether the value was a quoted string
    quoted: bool,
}

/// Parse header parameters like: `form-data; name="value"; filename="file.txt"`, in order
///
/// As in Go Coraza, a `;` inside a quoted string doesn't end the parameter, and a
/// quoted value is unquoted as Go's `mime` package does it.
fn parse_header_params(header: &str) -> Vec<HeaderParam> {
    let mut params = Vec::new();

    for part in split_header_params(header) {
        let part = part.trim();

        if let Some((name, value)) = part.split_once('=') {
            let name = name.trim().to_lowercase();
            let value = value.trim();
            let unquoted = unquote(value);
            params.push(HeaderParam {
                name,
                quoted: unquoted.is_some(),
                value: unquoted.unwrap_or_else(|| value.to_owned()),
            });
        }
    }

    params
}

/// The `;`-separated parts of `header`, a `;` in a quoted string (where a backslash
/// escapes the next character) not separating them.
fn split_header_params(header: &str) -> Vec<&str> {
    let bytes = header.as_bytes();
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes.get(i).copied() {
            Some(b'\\') if in_quotes => i += 1,
            Some(b'"') => in_quotes = !in_quotes,
            Some(b';') if !in_quotes => {
                if let Some(part) = header.get(start..i) {
                    parts.push(part);
                }
                start = i.saturating_add(1);
            },
            _ => {},
        }
        i += 1;
    }
    if let Some(part) = header.get(start..) {
        parts.push(part);
    }
    parts
}

/// The content of `value` if it is a quoted string, with a backslash before one of
/// RFC 2045's special characters removed; other backslashes are kept, as Go's `mime`
/// package keeps them for the paths MSIE sends unescaped (`"C:\dev\x.txt"`).
fn unquote(value: &str) -> Option<String> {
    const SPECIALS: &str = "()<>@,;:\\\"/[]?=";
    let inner = value.strip_prefix('"')?.strip_suffix('"')?;
    let mut unquoted = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match chars.peek() {
            Some(&next) if c == '\\' && SPECIALS.contains(next) => {
                unquoted.push(next);
                chars.next();
            },
            _ => unquoted.push(c),
        }
    }
    Some(unquoted)
}

/// Find the end of headers (blank line)
///
/// Returns a tuple of (`position`, `separator_length`), or `None` if not found.
fn find_header_end(data: &[u8]) -> Option<(usize, usize)> {
    // Look for \r\n\r\n or \n\n
    find_subsequence(data, b"\r\n\r\n")
        .map(|pos| (pos, 4))
        .or_else(|| find_subsequence(data, b"\n\n").map(|pos| (pos, 2)))
}

/// Skip a line ending (CRLF or LF) at the given position
///
/// Returns the position after the line ending
fn skip_line_ending(data: &[u8], pos: usize) -> usize {
    let Some(remaining) = data.get(pos..) else {
        return data.len();
    };
    if remaining.starts_with(b"\r\n") {
        pos.saturating_add(2)
    } else if remaining.starts_with(b"\n") {
        pos.saturating_add(1)
    } else {
        pos
    }
}

/// Find the next boundary in the data
///
/// Looks for \r\n--boundary or \n--boundary
fn find_next_boundary(data: &[u8], boundary: &[u8]) -> Option<(usize, usize)> {
    let mut crlf_boundary = b"\r\n".to_vec();
    crlf_boundary.extend_from_slice(boundary);
    let mut lf_boundary = b"\n".to_vec();
    lf_boundary.extend_from_slice(boundary);

    match (
        find_valid_boundary(data, &crlf_boundary, 2),
        find_valid_boundary(data, &lf_boundary, 1),
    ) {
        (Some(crlf), Some(lf)) => Some(if crlf.0 <= lf.0 { crlf } else { lf }),
        (Some(boundary), None) | (None, Some(boundary)) => Some(boundary),
        (None, None) => None,
    }
}

/// Find a boundary prefix followed by a line ending or a closing marker.
fn find_valid_boundary(data: &[u8], pattern: &[u8], prefix_len: usize) -> Option<(usize, usize)> {
    data.windows(pattern.len()).enumerate().find_map(|(pos, window)| {
        if window != pattern {
            return None;
        }
        let marker_pos = pos.checked_add(prefix_len)?;
        let suffix_start = pos.checked_add(pattern.len())?;
        let suffix = data.get(suffix_start..)?;
        (suffix.starts_with(b"--") || suffix.starts_with(b"\r\n") || suffix.starts_with(b"\n"))
            .then_some((pos, marker_pos))
    })
}

/// Find a subsequence in a byte slice
///
/// Returns the position of the first occurrence, or None
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "parser tests use fixed multipart fixtures")]
mod tests {
    use super::*;

    #[test]
    fn test_simple_multipart() {
        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"field\"\r\n\
\r\n\
value\r\n\
--boundary--";

        let parser = MultipartParser::new("boundary", body);
        let parts = parser.parse().unwrap();

        assert_eq!(parts.len(), 1);
        let part = parts.first().unwrap();
        assert_eq!(part.name, "field");
        assert_eq!(part.filename, None);
        assert_eq!(part.data, b"value");
    }

    #[test]
    fn test_multipart_with_file() {
        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\
Content-Type: text/plain\r\n\
\r\n\
file content\r\n\
--boundary--";

        let parser = MultipartParser::new("boundary", body);
        let parts = parser.parse().unwrap();

        assert_eq!(parts.len(), 1);
        let part = parts.first().unwrap();
        assert_eq!(part.name, "file");
        assert_eq!(part.filename.as_deref(), Some("test.txt"));
        assert_eq!(header(&part.headers, "Content-Type"), Some("text/plain"));
        assert_eq!(part.data, b"file content");
    }

    #[test]
    fn test_multiple_parts() {
        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"field1\"\r\n\
\r\n\
value1\r\n\
--boundary\r\n\
Content-Disposition: form-data; name=\"field2\"\r\n\
\r\n\
value2\r\n\
--boundary--";

        let parser = MultipartParser::new("boundary", body);
        let parts = parser.parse().unwrap();

        assert_eq!(parts.len(), 2);
        let first = parts.first().unwrap();
        let second = parts.get(1).unwrap();
        assert_eq!(first.name, "field1");
        assert_eq!(first.data, b"value1");
        assert_eq!(second.name, "field2");
        assert_eq!(second.data, b"value2");
    }

    #[test]
    fn preserves_part_line_endings_and_boundary_like_payload_bytes() {
        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"field\"\r\n\
\r\n\
value\r\n--boundary-not-a-delimiter\r\n\r\n\
--boundary--";

        let parts = MultipartParser::new("boundary", body).parse().unwrap();

        assert_eq!(parts.first().unwrap().data, b"value\r\n--boundary-not-a-delimiter\r\n");
    }

    #[test]
    fn rejects_a_body_without_its_closing_boundary() {
        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"field\"\r\n\
\r\n\
value";

        assert!(MultipartParser::new("boundary", body).parse().is_err());
    }

    #[test]
    fn test_lf_line_endings() {
        let body = b"--boundary\n\
Content-Disposition: form-data; name=\"field\"\n\
\n\
value\n\
--boundary--";

        let parser = MultipartParser::new("boundary", body);
        let parts = parser.parse().unwrap();

        assert_eq!(parts.len(), 1);
        let part = parts.first().unwrap();
        assert_eq!(part.name, "field");
        assert_eq!(part.data, b"value");
    }

    #[test]
    fn test_empty_part() {
        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"empty\"\r\n\
\r\n\
\r\n\
--boundary--";

        let parser = MultipartParser::new("boundary", body);
        let parts = parser.parse().unwrap();

        assert_eq!(parts.len(), 1);
        let part = parts.first().unwrap();
        assert_eq!(part.name, "empty");
        assert_eq!(part.data, b"");
    }

    #[test]
    fn test_no_boundary() {
        let body = b"some random data";

        let parser = MultipartParser::new("boundary", body);
        let result = parser.parse();

        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_content_disposition() {
        let body = b"--boundary\r\n\
Content-Type: text/plain\r\n\
\r\n\
value\r\n\
--boundary--";

        let parser = MultipartParser::new("boundary", body);
        let result = parser.parse();

        // Should fail due to missing Content-Disposition
        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_and_folded_part_headers() {
        assert!(parse_headers(b"Content-Disposition: form-data; name=field\r\ninvalid\r\n").is_err());
        assert!(parse_headers(b" Content-Disposition: form-data; name=field\r\n").is_err());
        assert!(parse_headers(b"Bad Name: value\r\n").is_err());
    }

    #[test]
    fn test_find_subsequence() {
        assert_eq!(find_subsequence(b"hello world", b"world"), Some(6));
        assert_eq!(find_subsequence(b"hello world", b"foo"), None);
        assert_eq!(find_subsequence(b"hello", b"hello world"), None);
        assert_eq!(find_subsequence(b"abc", b""), Some(0));
    }

    #[test]
    fn test_parse_header_params() {
        let header = "form-data; name=\"field\"; filename=\"file.txt\"";
        let params = parse_header_params(header);

        let quoted = |name: &str, value: &str| HeaderParam {
            name: name.to_owned(),
            value: value.to_owned(),
            quoted: true,
        };
        assert_eq!(params, [quoted("name", "field"), quoted("filename", "file.txt")]);
    }

    #[test]
    fn test_parse_header_params_quoted_strings() {
        // A ';' or an escaped quote inside a quoted string is part of the value, as in Go
        let params = parse_header_params(r#"form-data; name="zzz&auml;&euml;zzz"; filename="a\"b;c"; x=1"#);
        let values: Vec<_> = params.iter().map(|p| (p.name.as_str(), p.value.as_str())).collect();
        assert_eq!(
            values,
            [("name", "zzz&auml;&euml;zzz"), ("filename", "a\"b;c"), ("x", "1")]
        );
        // A backslash escapes only a special character: MSIE sends paths unescaped
        let params = parse_header_params(r#"form-data; filename="C:\dev\x.txt""#);
        assert_eq!(params.first().unwrap().value, r"C:\dev\x.txt");
    }

    #[test]
    fn test_complex_boundary() {
        let body = b"-----------------------------9051914041544843365972754266\r\n\
Content-Disposition: form-data; name=\"text\"\r\n\
\r\n\
text default\r\n\
-----------------------------9051914041544843365972754266\r\n\
Content-Disposition: form-data; name=\"file1\"; filename=\"a.txt\"\r\n\
Content-Type: text/plain\r\n\
\r\n\
Content of a.txt.\r\n\
-----------------------------9051914041544843365972754266--";

        let parser = MultipartParser::new("---------------------------9051914041544843365972754266", body);
        let parts = parser.parse().unwrap();

        assert_eq!(parts.len(), 2);
        let first = parts.first().unwrap();
        let second = parts.get(1).unwrap();
        assert_eq!(first.name, "text");
        assert_eq!(first.data, b"text default");
        assert_eq!(second.name, "file1");
        assert_eq!(second.filename.as_deref(), Some("a.txt"));
        assert_eq!(second.data, b"Content of a.txt.");
    }
}
