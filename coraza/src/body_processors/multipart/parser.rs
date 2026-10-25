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
    /// The body exceeds one of the parser's resource budgets.
    Limit(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::MalformedHeaders(msg) => write!(f, "malformed headers: {msg}"),
            ParseError::Parse(msg) => write!(f, "parse error: {msg}"),
            ParseError::Limit(msg) => write!(f, "limit exceeded: {msg}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// The charset and language of an RFC 5987 `filename*` parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilenameEncoding {
    /// e.g. `UTF-8`
    pub(crate) charset: Vec<u8>,
    /// e.g. `en`; may be empty
    pub(crate) language: Vec<u8>,
}

/// A part's headers, in order: each name as sent, and its value bytes.
pub(crate) type Headers = Vec<(String, Vec<u8>)>;

/// A single part in a multipart message
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "these flags report independent Coraza multipart conditions"
)]
pub(crate) struct Part<'a> {
    /// Form field name (from Content-Disposition name parameter), exactly as sent
    pub(crate) name: Vec<u8>,

    /// Filename, if this is a file upload: from the Content-Disposition `filename*`
    /// parameter, decoded, or else from `filename`
    pub(crate) filename: Option<Vec<u8>>,

    /// The `filename` parameter, when `filename*` gave a different name
    pub(crate) alt_filename: Option<Vec<u8>>,

    /// The charset and language of the `filename*` parameter
    pub(crate) filename_encoding: Option<FilenameEncoding>,

    /// Whether the `filename*` parameter is malformed
    pub(crate) malformed_filename: bool,

    /// Its headers, in order: each name as sent, and its value bytes
    pub(crate) headers: Headers,

    /// Whether the part repeats a header, or a parameter of its Content-Disposition
    pub(crate) repeats_header: bool,

    /// Whether its Content-Disposition `filename*` is quoted, which RFC 5987 forbids
    pub(crate) invalid_quoting: bool,

    /// The part body data
    pub(crate) data: &'a [u8],
}

/// Maximum boundary length in bytes.
///
/// RFC 2046 requires a boundary of at most 70 characters. Go's
/// `mime/multipart` has no explicit length check, but its 4096-byte read
/// buffer makes a delimiter line much longer than about 4090 bytes fail.
/// This is a Rust-only hardening limit, well above real clients and RFC 2046.
const MAX_BOUNDARY_LEN: usize = 1024;

/// Maximum number of parts in one body.
///
/// Go Coraza reads parts with `mime/multipart.Reader.NextPart`, which has no
/// part limit. Go's `ReadForm` caps a form at 1000 parts; this parser adopts
/// that constant as a Rust-only budget.
const MAX_PARTS: usize = 1000;

/// Maximum raw bytes in one part's header block.
///
/// This is Go's `maxMIMEHeaderSize` (`10 << 20`). Go charges that budget as
/// key bytes, value bytes and 200 bytes per distinct header; this parser caps
/// the raw header block with the same constant.
const MAX_HEADER_BLOCK: usize = 10 << 20;

/// Maximum header lines in one part.
///
/// This is the default of Go's `multipartmaxheaders` setting.
const MAX_PART_HEADERS: usize = 10_000;

/// Maximum raw header bytes across every part in one body.
///
/// Rust-only hardening: Go Coraza accumulates each part's headers in
/// `MULTIPART_PART_HEADERS` without a whole-body budget.
const MAX_TOTAL_HEADER_BYTES: usize = 10 << 20;

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
        if self.boundary.is_empty() {
            return Err(ParseError::Parse("boundary is empty".to_owned()));
        }
        if self.boundary.len() > MAX_BOUNDARY_LEN {
            let length = self.boundary.len();
            return Err(ParseError::Limit(format!(
                "boundary length {length} exceeds {MAX_BOUNDARY_LEN}"
            )));
        }

        let mut parts = Vec::new();

        // Build boundary markers
        // Initial boundary: --{boundary}
        // Subsequent boundaries: \r\n--{boundary} or \n--{boundary}
        // Final boundary: --{boundary}--
        let mut boundary_marker = Vec::with_capacity(self.boundary.len().saturating_add(2));
        boundary_marker.extend_from_slice(b"--");
        boundary_marker.extend_from_slice(&self.boundary);
        let boundary_table = prefix_table(&boundary_marker);

        // The first delimiter must begin a line. Go's mime/multipart reads
        // complete preamble lines and skips them, so a marker inside one is
        // preamble text, not a delimiter.
        let first_boundary = find_first_boundary(self.data, &boundary_marker, &boundary_table)
            .ok_or_else(|| ParseError::Parse("no boundary found".to_owned()))?;
        let after_boundary = first_boundary
            .checked_add(boundary_marker.len())
            .ok_or_else(|| ParseError::Parse("boundary position overflow".to_owned()))?;
        // Skip the linear whitespace Go allows between a boundary and its
        // line ending, then look for a closing marker before the line ending.
        let mut pos = skip_lwsp(self.data, after_boundary);

        let mut closed = self
            .data
            .get(pos..)
            .is_some_and(|remaining| remaining.starts_with(b"--"));
        if !closed {
            // Skip line ending after first boundary
            pos = skip_line_ending(self.data, pos);
        }
        let mut total_header_bytes = 0_usize;

        // Parse each part
        while !closed {
            if parts.len() >= MAX_PARTS {
                return Err(ParseError::Limit(format!("body has more than {MAX_PARTS} parts")));
            }

            let remaining = self
                .data
                .get(pos..)
                .ok_or_else(|| ParseError::Parse("missing final boundary".to_owned()))?;
            let (part_end, boundary_start) = find_next_boundary(remaining, &boundary_marker, &boundary_table)
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
            let part = parse_part(part_data, &mut total_header_bytes)?;
            parts.push(part);

            // Move past the boundary and the linear whitespace that may
            // separate it from the line ending or a closing marker.
            pos = boundary_marker_pos
                .checked_add(boundary_marker.len())
                .ok_or_else(|| ParseError::Parse("boundary position overflow".to_owned()))?;
            pos = skip_lwsp(self.data, pos);

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
///
/// `total_header_bytes` accumulates the raw header bytes of every part parsed
/// from the same body.
fn parse_part<'a>(data: &'a [u8], total_header_bytes: &mut usize) -> Result<Part<'a>, ParseError> {
    // Find the blank line that separates headers from body
    let (header_end, separator_len) =
        find_header_end(data).ok_or_else(|| ParseError::MalformedHeaders("no blank line after headers".to_owned()))?;

    if header_end > MAX_HEADER_BLOCK {
        return Err(ParseError::Limit(format!(
            "part header block is {header_end} bytes, limit is {MAX_HEADER_BLOCK}"
        )));
    }
    *total_header_bytes = total_header_bytes
        .checked_add(header_end)
        .ok_or_else(|| ParseError::Limit("total header bytes overflow".to_owned()))?;
    if *total_header_bytes > MAX_TOTAL_HEADER_BYTES {
        return Err(ParseError::Limit(format!(
            "total header bytes exceed {MAX_TOTAL_HEADER_BYTES}"
        )));
    }

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
fn header<'a>(headers: &'a Headers, name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_slice())
}

/// `bytes` without the ASCII whitespace Go's `textproto` trims around a header
/// name or value.
fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    trim_ascii_end(bytes.get(start..).unwrap_or_default())
}

/// `bytes` without its trailing ASCII whitespace.
fn trim_ascii_end(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(0, |index| index.saturating_add(1));
    bytes.get(..end).unwrap_or_default()
}

/// Parse headers from header data, in order, each name as sent.
///
/// Values keep their exact bytes, as Go's `textproto` keeps them: an invalid
/// UTF-8 value must not collapse into another one.
fn parse_headers(data: &[u8]) -> Result<Headers, ParseError> {
    let mut headers = Vec::new();

    for line in data.split(|&byte| byte == b'\n') {
        let line = trim_ascii_end(line);
        if line.is_empty() {
            continue;
        }
        if headers.len() >= MAX_PART_HEADERS {
            return Err(ParseError::Limit(format!(
                "part has more than {MAX_PART_HEADERS} headers"
            )));
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            return Err(ParseError::MalformedHeaders(
                "folded header lines are not supported".to_owned(),
            ));
        }
        let colon = line
            .iter()
            .position(|&byte| byte == b':')
            .ok_or_else(|| ParseError::MalformedHeaders("invalid header line".to_owned()))?;
        let name = line.get(..colon).unwrap_or_default();
        if name.is_empty()
            || trim_ascii(name) != name
            || !name
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
        {
            return Err(ParseError::MalformedHeaders("invalid header name".to_owned()));
        }
        let value = trim_ascii(line.get(colon.saturating_add(1)..).unwrap_or_default());
        if value.iter().any(|&byte| (byte < 0x20 && byte != b'\t') || byte == 0x7F) {
            return Err(ParseError::MalformedHeaders("invalid header value".to_owned()));
        }
        // A header name is confined to token bytes, which are ASCII.
        let Ok(name) = std::str::from_utf8(name) else {
            return Err(ParseError::MalformedHeaders("invalid header name".to_owned()));
        };
        headers.push((name.to_owned(), value.to_vec()));
    }

    Ok(headers)
}

/// What a part's Content-Disposition header says.
#[expect(
    clippy::struct_excessive_bools,
    reason = "these flags report independent Coraza multipart conditions"
)]
struct ContentDisposition {
    /// The part name from `Content-Disposition`, exactly as sent.
    name: Vec<u8>,
    /// `filename*` decoded, or else `filename`
    filename: Option<Vec<u8>>,
    /// `filename`, when `filename*` gave a different one
    alt_filename: Option<Vec<u8>>,
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
fn extract_content_disposition(headers: &Headers) -> Result<ContentDisposition, ParseError> {
    let disposition = header(headers, "content-disposition")
        .ok_or_else(|| ParseError::MalformedHeaders("missing Content-Disposition".to_owned()))?;

    let params = parse_header_params(disposition);
    let param = |name: &[u8]| {
        params
            .iter()
            .rev()
            .find(|param| param.name.as_slice() == name)
            .map(|param| param.value.clone())
    };
    let mut seen_params = std::collections::HashSet::with_capacity(params.len());
    let repeats_param = params.iter().any(|param| !seen_params.insert(param.name.as_slice()));
    let quoted_extended_filename = params
        .iter()
        .any(|param| param.name.as_slice() == b"filename*" && param.quoted);

    let name =
        param(b"name").ok_or_else(|| ParseError::MalformedHeaders("missing name in Content-Disposition".to_owned()))?;

    // As Go Coraza reads RFC 5987's `filename*=charset'language'value`
    let plain = param(b"filename");
    let mut disposition = ContentDisposition {
        name,
        filename: plain.clone(),
        alt_filename: None,
        filename_encoding: None,
        malformed_extended_filename: false,
        repeats_param,
        quoted_extended_filename,
    };
    if let Some(extended) = param(b"filename*") {
        let segments: Vec<&[u8]> = extended.splitn(3, |&byte| byte == b'\'').collect();
        match segments.as_slice() {
            [charset, language, value] => {
                let (decoded, invalid_escape) = percent_decode_lenient(value);
                disposition.alt_filename = plain.filter(|plain| !plain.is_empty() && *plain != decoded);
                disposition.filename = Some(decoded);
                disposition.filename_encoding = Some(FilenameEncoding {
                    charset: (*charset).to_vec(),
                    language: (*language).to_vec(),
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
fn percent_decode_lenient(value: &[u8]) -> (Vec<u8>, bool) {
    let mut decoded = Vec::with_capacity(value.len());
    let mut invalid = false;
    let mut i = 0;
    while let Some(&byte) = value.get(i) {
        let escaped = (byte == b'%')
            .then(|| {
                i.checked_add(1)
                    .and_then(|start| value.get(start..start.checked_add(2)?))
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
    (decoded, invalid)
}

/// One `name=value` parameter of a header.
#[derive(Debug, PartialEq)]
struct HeaderParam {
    /// Lowercase name
    name: Vec<u8>,
    /// Value, without its quotes
    value: Vec<u8>,
    /// Whether the value was a quoted string
    quoted: bool,
}

/// Parse header parameters like: `form-data; name="value"; filename="file.txt"`, in order
///
/// As in Go Coraza, a `;` inside a quoted string doesn't end the parameter, and a
/// quoted value is unquoted as Go's `mime` package does it.
fn parse_header_params(header: &[u8]) -> Vec<HeaderParam> {
    let mut params = Vec::new();

    for part in split_header_params(header) {
        let part = trim_ascii(part);

        if let Some(equals) = part.iter().position(|&byte| byte == b'=') {
            let name = trim_ascii(part.get(..equals).unwrap_or_default()).to_ascii_lowercase();
            let value = trim_ascii(part.get(equals.saturating_add(1)..).unwrap_or_default());
            let unquoted = unquote(value);
            params.push(HeaderParam {
                name,
                quoted: unquoted.is_some(),
                value: unquoted.unwrap_or_else(|| value.to_vec()),
            });
        }
    }

    params
}

/// The `;`-separated parts of `header`, a `;` in a quoted string (where a backslash
/// escapes the next character) not separating them.
fn split_header_params(header: &[u8]) -> Vec<&[u8]> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    let mut i = 0;
    while i < header.len() {
        match header.get(i).copied() {
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
fn unquote(value: &[u8]) -> Option<Vec<u8>> {
    const SPECIALS: &[u8] = b"()<>@,;:\\\"/[]?=";
    let inner = value.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    let mut unquoted = Vec::with_capacity(inner.len());
    let mut i = 0;
    while let Some(&byte) = inner.get(i) {
        match inner.get(i.saturating_add(1)) {
            Some(&next) if byte == b'\\' && SPECIALS.contains(&next) => {
                unquoted.push(next);
                i += 1;
            },
            _ => unquoted.push(byte),
        }
        i += 1;
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

/// Skip linear whitespace (spaces and tabs) at the given position.
///
/// Go's `mime/multipart` accepts optional linear whitespace after a boundary
/// marker and after a closing marker's dashes (`skipLWSPChar`).
fn skip_lwsp(data: &[u8], pos: usize) -> usize {
    let mut end = pos;
    while data.get(end).is_some_and(|byte| matches!(*byte, b' ' | b'\t')) {
        end = end.saturating_add(1);
    }
    end
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

/// Find the first boundary marker that begins a line and is followed by a
/// line ending or a closing marker.
///
/// Go's `mime/multipart` skips complete preamble lines, so a marker inside a
/// preamble line is not a delimiter.
fn find_first_boundary(data: &[u8], marker: &[u8], table: &[usize]) -> Option<usize> {
    find_subsequence_where(data, marker, table, |data, start| {
        let starts_line = start == 0
            || start
                .checked_sub(1)
                .and_then(|before| data.get(before))
                .is_some_and(|byte| *byte == b'\n');
        starts_line
            && start
                .checked_add(marker.len())
                .is_some_and(|end| boundary_suffix_is_valid(data, end))
    })
}

/// Find the next boundary in the data
///
/// Looks for a line-feed-prefixed boundary, consuming a preceding carriage return too.
fn find_next_boundary(data: &[u8], marker: &[u8], table: &[usize]) -> Option<(usize, usize)> {
    let marker_pos = find_subsequence_where(data, marker, table, |data, start| {
        start
            .checked_sub(1)
            .and_then(|before| data.get(before))
            .is_some_and(|byte| *byte == b'\n')
            && start
                .checked_add(marker.len())
                .is_some_and(|end| boundary_suffix_is_valid(data, end))
    })?;
    let line_feed_pos = marker_pos.checked_sub(1)?;
    let part_end = line_feed_pos
        .checked_sub(1)
        .filter(|&carriage_return_pos| data.get(carriage_return_pos) == Some(&b'\r'))
        .unwrap_or(line_feed_pos);
    Some((part_end, marker_pos))
}

/// Whether the bytes after a boundary marker form a delimiter suffix:
/// optional linear whitespace and a line ending, or a closing `--` marker with
/// optional whitespace and a line ending (or end of input).
fn boundary_suffix_is_valid(data: &[u8], marker_end: usize) -> bool {
    let Some(suffix) = data.get(marker_end..) else {
        return false;
    };
    // Go's isFinalBoundary requires the closing dashes immediately after the
    // boundary; whitespace before them makes this an ordinary delimiter, not a
    // closing one.
    let is_final = suffix.starts_with(b"--");
    let rest_start = if is_final {
        marker_end.saturating_add(2)
    } else {
        marker_end
    };
    let rest = data.get(skip_lwsp(data, rest_start)..).unwrap_or(&[]);
    let has_line_ending = rest.starts_with(b"\r\n") || rest.starts_with(b"\n");
    if is_final {
        rest.is_empty() || has_line_ending
    } else {
        has_line_ending
    }
}

/// Find a subsequence in a byte slice
///
/// Returns the position of the first occurrence, or None.
///
/// Only used for the fixed 2- and 4-byte blank-line separators, so the scan is
/// bounded by a small constant factor of `haystack`. Boundary markers, which
/// are attacker-sized, use [`find_subsequence_where`] instead.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Build the prefix-function table of `pattern` for a linear-time search.
fn prefix_table(pattern: &[u8]) -> Vec<usize> {
    let mut table = vec![0; pattern.len()];
    let mut matched = 0_usize;
    for index in 1..pattern.len() {
        let byte = pattern.get(index).copied().unwrap_or_default();
        while matched > 0 && pattern.get(matched).copied() != Some(byte) {
            matched = table.get(matched.saturating_sub(1)).copied().unwrap_or(0);
        }
        if pattern.get(matched).copied() == Some(byte) {
            matched = matched.saturating_add(1);
        }
        if let Some(slot) = table.get_mut(index) {
            *slot = matched;
        }
    }
    table
}

/// Find the first occurrence of `needle` in `haystack` that `accept` approves,
/// in O(haystack + needle) time with a precomputed [`prefix_table`].
fn find_subsequence_where(
    haystack: &[u8],
    needle: &[u8],
    table: &[usize],
    mut accept: impl FnMut(&[u8], usize) -> bool,
) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    let mut matched = 0_usize;
    for (index, byte) in haystack.iter().copied().enumerate() {
        while matched > 0 && needle.get(matched).copied() != Some(byte) {
            matched = table.get(matched.saturating_sub(1)).copied().unwrap_or(0);
        }
        if needle.get(matched).copied() == Some(byte) {
            matched = matched.saturating_add(1);
        }
        if matched == needle.len() {
            let start = index.saturating_add(1).saturating_sub(needle.len());
            if accept(haystack, start) {
                return Some(start);
            }
            matched = table.get(matched.saturating_sub(1)).copied().unwrap_or(0);
        }
    }
    None
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
        assert_eq!(part.name.as_slice(), b"field");
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
        assert_eq!(part.name.as_slice(), b"file");
        assert_eq!(part.filename.as_deref(), Some(&b"test.txt"[..]));
        assert_eq!(header(&part.headers, "Content-Type"), Some(&b"text/plain"[..]));
        assert_eq!(part.data, b"file content");
    }

    #[test]
    fn find_next_boundary_preserves_crlf_and_lf_positions() {
        let marker = b"--boundary";
        let table = prefix_table(marker);
        assert_eq!(
            find_next_boundary(b"payload\r\n--boundary\r\n", marker, &table),
            Some((7, 9))
        );
        assert_eq!(
            find_next_boundary(b"payload\n--boundary\r\n", marker, &table),
            Some((7, 8))
        );
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
        assert_eq!(first.name.as_slice(), b"field1");
        assert_eq!(first.data, b"value1");
        assert_eq!(second.name.as_slice(), b"field2");
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
        assert_eq!(part.name.as_slice(), b"field");
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
        assert_eq!(part.name.as_slice(), b"empty");
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
    fn linear_search_finds_the_same_match_as_the_naive_scan() {
        fn random_bytes(len: usize) -> Vec<u8> {
            (0..len)
                .map(|_| match fastrand::u8(0..4) {
                    0 => b'a',
                    1 => b'b',
                    2 => b'\n',
                    _ => b'-',
                })
                .collect()
        }

        fastrand::seed(7);
        for _ in 0..2000 {
            let haystack = random_bytes(fastrand::usize(..64));
            let needle = random_bytes(fastrand::usize(..8));
            let table = prefix_table(&needle);
            assert_eq!(
                find_subsequence_where(&haystack, &needle, &table, |_, _| true),
                find_subsequence(&haystack, &needle),
                "needle={needle:?} haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn test_parse_header_params() {
        let header = "form-data; name=\"field\"; filename=\"file.txt\"";
        let params = parse_header_params(header.as_bytes());

        let quoted = |name: &str, value: &str| HeaderParam {
            name: name.as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
            quoted: true,
        };
        assert_eq!(params, [quoted("name", "field"), quoted("filename", "file.txt")]);
    }

    #[test]
    fn test_parse_header_params_quoted_strings() {
        // A ';' or an escaped quote inside a quoted string is part of the value, as in Go
        let params = parse_header_params(br#"form-data; name="zzz&auml;&euml;zzz"; filename="a\"b;c"; x=1"#);
        let values: Vec<_> = params
            .iter()
            .map(|p| {
                (
                    std::str::from_utf8(&p.name).unwrap(),
                    std::str::from_utf8(&p.value).unwrap(),
                )
            })
            .collect();
        assert_eq!(
            values,
            [("name", "zzz&auml;&euml;zzz"), ("filename", "a\"b;c"), ("x", "1")]
        );
        // A backslash escapes only a special character: MSIE sends paths unescaped
        let params = parse_header_params(br#"form-data; filename="C:\dev\x.txt""#);
        assert_eq!(params.first().unwrap().value.as_slice(), br"C:\dev\x.txt");
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
        assert_eq!(first.name.as_slice(), b"text");
        assert_eq!(first.data, b"text default");
        assert_eq!(second.name.as_slice(), b"file1");
        assert_eq!(second.filename.as_deref(), Some(&b"a.txt"[..]));
        assert_eq!(second.data, b"Content of a.txt.");
    }

    #[test]
    fn initial_marker_inside_a_preamble_line_is_not_a_delimiter() {
        // Go 1.27.3 mime/multipart skips complete preamble lines, so it parses
        // this body as zero parts: the only delimiter is the final boundary.
        let body = b"junk--b\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nattack\r\n--b--";
        let parts = MultipartParser::new("b", body).parse().unwrap();
        assert!(parts.is_empty());
    }

    #[test]
    fn initial_marker_after_a_preamble_line_starts_the_first_part() {
        // Go skips the preamble line that holds a mid-line marker and starts
        // the part at the next line that begins with a delimiter.
        let body = b"junk--b\r\nignored\r\n\r\nx\r\n--b\r\n\
Content-Disposition: form-data; name=\"r\"\r\n\
\r\n\
ok\r\n\
--b--";
        let parts = MultipartParser::new("b", body).parse().unwrap();
        assert_eq!(parts.len(), 1);
        let part = parts.first().unwrap();
        assert_eq!(part.name.as_slice(), b"r");
        assert_eq!(part.data, b"ok");
    }

    #[test]
    fn invalid_first_boundary_line_is_skipped() {
        // A line that starts with the marker but continues with other text is
        // preamble, not a delimiter; the search must keep going.
        let body = b"--b-not-a-delimiter\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"q\"\r\n\
\r\n\
v\r\n\
--b--";
        let parts = MultipartParser::new("b", body).parse().unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().data, b"v");
    }

    #[test]
    fn boundary_at_the_very_start_is_accepted() {
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"q\"\r\n\
\r\n\
attack\r\n\
--b--";
        let parts = MultipartParser::new("b", body).parse().unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().data, b"attack");
    }

    #[test]
    fn first_boundary_with_trailing_space_and_crlf_is_accepted() {
        let body = b"--b \r\n\
Content-Disposition: form-data; name=\"q\"\r\n\
\r\n\
v\r\n\
--b--";
        let parts = MultipartParser::new("b", body).parse().unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().data, b"v");
    }

    #[test]
    fn first_boundary_with_trailing_tab_and_lf_is_accepted() {
        let body = b"--b\t\n\
Content-Disposition: form-data; name=\"q\"\n\
\n\
v\n\
--b--";
        let parts = MultipartParser::new("b", body).parse().unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().data, b"v");
    }

    #[test]
    fn later_boundary_with_trailing_spaces_and_crlf_is_accepted() {
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"a\"\r\n\
\r\n\
one\r\n\
--b  \r\n\
Content-Disposition: form-data; name=\"b\"\r\n\
\r\n\
two\r\n\
--b--";
        let parts = MultipartParser::new("b", body).parse().unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts.first().unwrap().data, b"one");
        assert_eq!(parts.get(1).unwrap().data, b"two");
    }

    #[test]
    fn closing_boundary_with_trailing_space_and_crlf_is_accepted() {
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"q\"\r\n\
\r\n\
v\r\n\
--b-- \r\n";
        let parts = MultipartParser::new("b", body).parse().unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().data, b"v");
    }

    #[test]
    fn closing_boundary_with_trailing_tab_at_end_of_input_is_accepted() {
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"q\"\r\n\
\r\n\
v\r\n\
--b--\t";
        let parts = MultipartParser::new("b", body).parse().unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().data, b"v");
    }

    #[test]
    fn space_before_the_closing_dashes_is_not_a_final_boundary() {
        // Go requires the two closing dashes immediately after the boundary.
        let body = b"--b --\r\n\
Content-Disposition: form-data; name=\"q\"\r\n\
\r\n\
v";
        let error = MultipartParser::new("b", body).parse().unwrap_err();
        assert!(matches!(error, ParseError::Parse(message) if message == "no boundary found"));

        // The line is preamble, not a delimiter: the later final boundary is
        // the first delimiter, as in Go.
        let body = b"--b --\r\n\
Content-Disposition: form-data; name=\"q\"\r\n\
\r\n\
v\r\n\
--b--";
        let parts = MultipartParser::new("b", body).parse().unwrap();
        assert!(parts.is_empty());
    }

    #[test]
    fn ordinary_delimiter_with_trailing_whitespace_without_line_ending_is_rejected() {
        assert!(MultipartParser::new("b", b"--b ").parse().is_err());

        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"q\"\r\n\
\r\n\
v\r\n\
--b ";
        let error = MultipartParser::new("b", body).parse().unwrap_err();
        assert!(matches!(error, ParseError::Parse(message) if message == "missing final boundary"));
    }

    #[test]
    fn boundary_like_payload_with_trailing_space_is_not_a_delimiter() {
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"q\"\r\n\
\r\n\
v\r\n\
--b x\r\n\
more\r\n\
--b--";
        let parts = MultipartParser::new("b", body).parse().unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().data, b"v\r\n--b x\r\nmore");
    }

    #[test]
    fn empty_boundary_is_rejected() {
        let error = MultipartParser::new("", b"--\r\n--").parse().unwrap_err();
        assert!(matches!(error, ParseError::Parse(message) if message == "boundary is empty"));
    }

    #[test]
    fn boundary_length_budget_is_enforced() {
        let boundary = "a".repeat(MAX_BOUNDARY_LEN);
        let body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nv\r\n--{boundary}--");
        let parts = MultipartParser::new(boundary, body.as_bytes()).parse().unwrap();
        assert_eq!(parts.len(), 1);

        let boundary = "a".repeat(MAX_BOUNDARY_LEN.saturating_add(1));
        let error = MultipartParser::new(boundary, b"irrelevant").parse().unwrap_err();
        assert!(matches!(error, ParseError::Limit(_)));
    }

    #[test]
    fn long_dash_run_before_the_first_boundary_terminates() {
        // The concrete worst case for a naive delimiter scan: a boundary made
        // of dashes followed by 'b' against a preamble of dash runs. Each line
        // stays below Go's 4096-byte read buffer, so Go accepts this body too.
        let boundary = format!("{}b", "-".repeat(1023));
        let mut body = Vec::new();
        for _ in 0..1024 {
            body.extend(std::iter::repeat_n(b'-', 1023));
            body.push(b'\n');
        }
        body.extend_from_slice(format!("--{boundary}--").as_bytes());

        let parts = MultipartParser::new(boundary, &body).parse().unwrap();
        assert!(parts.is_empty());
    }

    #[test]
    fn long_dash_run_inside_a_part_body_is_preserved() {
        let boundary = format!("{}b", "-".repeat(1023));
        let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n").into_bytes();
        let payload_start = body.len();
        body.extend(std::iter::repeat_n(b'-', 256 * 1024));
        body.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());

        let parts = MultipartParser::new(boundary, &body).parse().unwrap();
        let part = parts.first().unwrap();
        let payload = body
            .get(payload_start..payload_start.saturating_add(256 * 1024))
            .unwrap();
        assert_eq!(part.data, payload);
    }

    #[test]
    fn part_count_budget_is_enforced() {
        fn parse_parts(count: usize) -> Result<usize, ParseError> {
            let mut body = Vec::new();
            for index in 0..count {
                body.extend_from_slice(
                    format!("--b\r\nContent-Disposition: form-data; name=\"f{index}\"\r\n\r\nv\r\n").as_bytes(),
                );
            }
            body.extend_from_slice(b"--b--");
            MultipartParser::new("b", &body).parse().map(|parts| parts.len())
        }

        assert_eq!(parse_parts(MAX_PARTS).unwrap(), MAX_PARTS);
        let error = parse_parts(MAX_PARTS.saturating_add(1)).unwrap_err();
        assert!(matches!(error, ParseError::Limit(_)));
    }

    #[test]
    fn header_block_budget_is_enforced() {
        let mut body = b"--b\r\nContent-Disposition: form-data; name=\"q\"\r\nX: ".to_vec();
        body.extend(std::iter::repeat_n(b'a', MAX_HEADER_BLOCK));
        body.extend_from_slice(b"\r\n\r\nv\r\n--b--");

        let error = MultipartParser::new("b", &body).parse().unwrap_err();
        assert!(matches!(error, ParseError::Limit(_)));
    }

    #[test]
    fn header_count_budget_is_enforced() {
        let mut body = b"--b\r\nContent-Disposition: form-data; name=\"q\"\r\n".to_vec();
        for index in 0..MAX_PART_HEADERS {
            body.extend_from_slice(format!("X{index}: v\r\n").as_bytes());
        }
        body.extend_from_slice(b"\r\nv\r\n--b--");

        let error = MultipartParser::new("b", &body).parse().unwrap_err();
        assert!(matches!(error, ParseError::Limit(_)));
    }

    #[test]
    fn truncated_part_headers_are_rejected() {
        let body = b"--b\r\nContent-Disposition: form-data; name=\"q\"";
        let error = MultipartParser::new("b", body).parse().unwrap_err();
        assert!(matches!(error, ParseError::Parse(message) if message.contains("missing final boundary")));
    }

    #[test]
    fn non_utf8_header_bytes_are_kept_as_sent() {
        // Go's textproto keeps the raw bytes in the value; so does this parser.
        let body = b"--b\r\nContent-Disposition: form-data; name=\"q\"\r\nX: \xff\xfe\r\n\r\nv\r\n--b--";
        let parts = MultipartParser::new("b", body).parse().unwrap();
        assert_eq!(header(&parts.first().unwrap().headers, "X"), Some(&b"\xff\xfe"[..]));

        // A non-UTF-8 header name is not a valid token and is rejected.
        let body = b"--b\r\nContent-Disposition: form-data; name=\"q\"\r\n\xff: v\r\n\r\nv\r\n--b--";
        assert!(MultipartParser::new("b", body).parse().is_err());
    }

    #[test]
    fn part_names_that_are_not_utf8_stay_distinct() {
        // Two names whose lossy text views are both U+FFFD, as Go's
        // `mime.ParseMediaType` keeps them distinct.
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"\xff\"\r\n\
\r\n\
one\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"\xfe\"\r\n\
\r\n\
two\r\n\
--b--";
        let parts = MultipartParser::new("b", body).parse().unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts.first().unwrap().name.as_slice(), b"\xff");
        assert_eq!(parts.first().unwrap().data, b"one");
        assert_eq!(parts.get(1).unwrap().name.as_slice(), b"\xfe");
        assert_eq!(parts.get(1).unwrap().data, b"two");
    }

    #[test]
    fn utf8_part_names_are_unchanged() {
        let body = "--b\r\n\
Content-Disposition: form-data; name=\"na\u{ef}me\"\r\n\
\r\n\
v\r\n\
--b--"
            .as_bytes();
        let parts = MultipartParser::new("b", body).parse().unwrap();
        assert_eq!(parts.first().unwrap().name.as_slice(), "na\u{ef}me".as_bytes());
    }

    #[test]
    fn duplicate_part_names_stay_repeated_values() {
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"\xff\"\r\n\
\r\n\
one\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"\xff\"\r\n\
\r\n\
two\r\n\
--b--";
        let parts = MultipartParser::new("b", body).parse().unwrap();
        assert_eq!(parts.len(), 2);
        assert!(parts.iter().all(|part| part.name.as_slice() == b"\xff"));
        assert_eq!(parts.first().unwrap().data, b"one");
        assert_eq!(parts.get(1).unwrap().data, b"two");
    }
}
