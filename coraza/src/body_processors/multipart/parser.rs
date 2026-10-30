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

use super::{is_token_name, media_type};

/// An error from parsing a multipart body.
#[derive(Debug)]
pub(super) enum ParseError {
    /// A part header line has an invalid name or value; holds the offending
    /// logical line, quoted.
    MalformedHeaderLine(String),
    /// A part header line has no colon; holds the offending first physical
    /// line, quoted.
    MissingColon(String),
    /// A part's header block starts with a folded line; holds that line, quoted.
    InitialLine(String),
    /// A delimiter line Go's reader expected to open a part; holds the line, quoted.
    UnexpectedLine(String),
    /// A folded first header line is longer than Go's `textproto` reads for it.
    MessageTooLarge,
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
            ParseError::MalformedHeaderLine(line) => write!(f, "malformed MIME header line: {line}"),
            ParseError::MissingColon(line) => write!(f, "malformed MIME header: missing colon: {line}"),
            ParseError::InitialLine(line) => write!(f, "malformed MIME header initial line: {line}"),
            ParseError::UnexpectedLine(line) => write!(f, "expecting a new Part; got line {line}"),
            ParseError::MessageTooLarge => write!(f, "message too large"),
            ParseError::MalformedHeaders(msg) => write!(f, "malformed headers: {msg}"),
            ParseError::Parse(msg) => write!(f, "parse error: {msg}"),
            ParseError::Limit(msg) => write!(f, "limit exceeded: {msg}"),
        }
    }
}

impl ParseError {
    /// Render this failure the way Go's `mime/multipart` reports it, when it has an
    /// equivalent there. Go returns these strings from `NextPart` unchanged, so they
    /// reach `REQBODY_PROCESSOR_ERROR_MSG`.
    pub(super) fn go_message(&self) -> String {
        match self {
            ParseError::MalformedHeaderLine(line) => format!("malformed MIME header line: {line}"),
            ParseError::MissingColon(line) => format!("malformed MIME header: missing colon: {line}"),
            ParseError::InitialLine(line) => format!("malformed MIME header initial line: {line}"),
            // Go's `nextPart` reports this one directly, without the `NextPart` prefix.
            ParseError::UnexpectedLine(line) => format!("multipart: expecting a new Part; got line {line}"),
            // Go's `multipart.ErrMessageTooLarge`, which `textproto` reports for a folded
            // first header line longer than its 80-byte probe.
            ParseError::MessageTooLarge => "multipart: message too large".to_owned(),
            ParseError::MalformedHeaders(message) => format!("malformed MIME header: {message}"),
            ParseError::Parse(message) => match message.as_str() {
                "boundary is empty" => "multipart: boundary is empty".to_owned(),
                // No delimiter line, or a body that ends mid-content: Go's `NextPart`
                // wraps `io.EOF` this way.
                "no boundary found" | "missing final boundary" => "multipart: NextPart: EOF".to_owned(),
                _ => format!("multipart: NextPart: {message}"),
            },
            // Rust-only hardening budgets; the conformance ledger records the prefix.
            ParseError::Limit(message) => format!("malformed multipart: limit exceeded: {message}"),
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
    /// Form field name (from Content-Disposition name parameter), exactly as sent;
    /// empty when the disposition is not `form-data` or was rejected
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
/// This is a Rust-only hardening limit at that same effective bound, well above
/// real clients and RFC 2046.
const MAX_BOUNDARY_LEN: usize = 4090;

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

/// Longest folded first header line Go's `textproto` quotes in its error.
///
/// `readMIMEHeader` reads that line with `readLineSlice(errorLimit)`, whose
/// `errorLimit` is 80 bytes, so a longer one fails with `message too large` instead
/// (`net/textproto/reader.go`, go1.27.3).
const TEXT_PROTO_INITIAL_LINE_LIMIT: usize = 80;

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
    /// Whether `data` holds only the prefix a body limit retained.
    truncated: bool,
}

impl<'a> MultipartParser<'a> {
    /// Create a new multipart parser
    ///
    /// # Arguments
    ///
    /// * `boundary` - The boundary string (without leading dashes)
    /// * `data` - The complete multipart body
    pub(super) fn new(boundary: impl AsRef<[u8]>, data: &'a [u8]) -> Self {
        Self {
            boundary: boundary.as_ref().to_vec(),
            data,
            truncated: false,
        }
    }

    /// Mark `data` as the prefix a body limit retained under `ProcessPartial`.
    ///
    /// Go's body processor then sees `io.ErrUnexpectedEOF` instead of a final
    /// boundary and inspects the parts it has (`flagUnexpectedEOF`).
    pub(super) fn truncated(mut self, truncated: bool) -> Self {
        self.truncated = truncated;
        self
    }

    /// Parse all parts from the multipart body
    ///
    /// Returns the parts read before parsing stopped, and why it stopped: Go's
    /// `NextPart` loop publishes each part as it reads it, so an error on a later
    /// part must not discard the parts before it.
    pub(super) fn parse(&self) -> (Vec<Part<'a>>, Option<ParseError>) {
        let mut parts = Vec::new();
        let error = self.collect_parts(&mut parts).err();
        (parts, error)
    }

    /// `parse` for a fixture that either parses cleanly or whose error is all the
    /// test reads: the parts an error collected are dropped.
    #[cfg(test)]
    fn parse_ok(&self) -> Result<Vec<Part<'a>>, ParseError> {
        match self.parse() {
            (_parts, Some(error)) => Err(error),
            (parts, None) => Ok(parts),
        }
    }

    /// Append every part to `parts`, returning why parsing stopped.
    fn collect_parts(&self, parts: &mut Vec<Part<'a>>) -> Result<(), ParseError> {
        if self.boundary.is_empty() {
            return Err(ParseError::Parse("boundary is empty".to_owned()));
        }
        if self.boundary.len() > MAX_BOUNDARY_LEN {
            let length = self.boundary.len();
            return Err(ParseError::Limit(format!(
                "boundary length {length} exceeds {MAX_BOUNDARY_LEN}"
            )));
        }

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
        let Some((first_boundary, nl)) = find_first_boundary(self.data, &boundary_marker, &boundary_table) else {
            // A body cut by the limit can end before any complete delimiter; Go's
            // `NextPart` wraps that `io.EOF` and the processor keeps zero parts.
            return if self.truncated {
                Ok(())
            } else {
                Err(ParseError::Parse("no boundary found".to_owned()))
            };
        };
        let after_boundary = first_boundary
            .checked_add(boundary_marker.len())
            .ok_or_else(|| ParseError::Parse("boundary position overflow".to_owned()))?;
        // Skip the linear whitespace Go allows between a boundary and its
        // line ending, then look for a closing marker before the line ending.
        let mut pos = skip_lwsp(self.data, after_boundary);
        // Go fixes the line ending at the first delimiter and keeps it for every later
        // one: it starts in CRLF mode, and a first delimiter line that ends in a bare LF
        // switches it to LF (`mime/multipart/multipart.go`, `isBoundaryDelimiterLine`,
        // go1.27.3).
        let mut nl_boundary_marker = nl.to_vec();
        nl_boundary_marker.extend_from_slice(&boundary_marker);

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
            if remaining.is_empty() {
                // A body that ends right after a delimiter line is not truncated: Go's
                // `NextPart` reports a plain `io.EOF` and the processor ends without a
                // strict error.
                return Ok(());
            }
            let (part_end, boundary_start) = match find_next_boundary(remaining, &boundary_marker, &boundary_table, nl)
            {
                Some(found) => found,
                None if self.truncated => {
                    // Go reads this last part until the limit's `io.ErrUnexpectedEOF`,
                    // trims the partial delimiter it stopped on, and keeps the part.
                    if let Some(mut part) = parse_truncated_part(remaining, &mut total_header_bytes)? {
                        part.data = trim_truncated_part_data(part.data, &boundary_marker, &nl_boundary_marker);
                        parts.push(part);
                    }
                    return Ok(());
                },
                None => {
                    // A body that stops before its final delimiter still publishes the
                    // part in progress: Go's `NextPart` returns it, and only reading it
                    // fails with `io.ErrUnexpectedEOF`. A partial delimiter at the end is
                    // trimmed like the limit-truncated case.
                    if let Some(mut part) = parse_truncated_part(remaining, &mut total_header_bytes)? {
                        part.data = trim_truncated_part_data(part.data, &boundary_marker, &nl_boundary_marker);
                        parts.push(part);
                    }
                    return Err(ParseError::Parse("missing final boundary".to_owned()));
                },
            };
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
            // The line ending before the marker belongs to the delimiter, unless it is the
            // blank line that ended the headers: Go reads that as the header terminator
            // and then an empty body (`scanUntilBoundary`'s `total == 0` case).
            let part_data = if find_header_end(part_data).is_some() {
                part_data
            } else {
                self.data
                    .get(pos..boundary_marker_pos)
                    .ok_or_else(|| ParseError::Parse("invalid part range".to_owned()))?
            };

            // Parse this part (propagate errors)
            let part = parse_part(part_data, &mut total_header_bytes)?;
            parts.push(part);

            // Go reports a bad delimiter line only after the part before it was read, so
            // the strict error follows a published part.
            let delimiter = delimiter_kind(self.data, boundary_marker_pos, &boundary_marker, nl)?;
            if matches!(delimiter, Delimiter::Final) {
                closed = true;
                break;
            }

            // Move past the boundary and the linear whitespace that may
            // separate it from the line ending.
            pos = boundary_marker_pos
                .checked_add(boundary_marker.len())
                .ok_or_else(|| ParseError::Parse("boundary position overflow".to_owned()))?;
            pos = skip_lwsp(self.data, pos);

            // Skip line ending after boundary
            pos = skip_line_ending(self.data, pos);
        }

        if closed {
            Ok(())
        } else {
            Err(ParseError::Parse("missing final boundary".to_owned()))
        }
    }
}

/// Parse the part a body limit cut before its closing delimiter.
///
/// Go's `NextPart` reports the unfinished header block as `io.EOF`, which the
/// multipart body processor treats as the end of a partial body, while a malformed
/// complete header line is still an error.
fn parse_truncated_part<'a>(data: &'a [u8], total_header_bytes: &mut usize) -> Result<Option<Part<'a>>, ParseError> {
    if find_header_end(data).is_none() {
        if let Some(end) = data.iter().rposition(|&byte| byte == b'\n') {
            let complete = data.get(..end.saturating_add(1)).unwrap_or_default();
            if complete.len() > MAX_HEADER_BLOCK {
                return Err(ParseError::Limit(format!(
                    "part header block is {} bytes, limit is {MAX_HEADER_BLOCK}",
                    complete.len()
                )));
            }
            parse_headers(complete)?;
        }
        return Ok(None);
    }
    parse_part(data, total_header_bytes).map(Some)
}

/// Strip the partial delimiter Go's `scanUntilBoundary` withholds from a part cut
/// by the limit, so a truncated closing boundary is not part of the field value.
fn trim_truncated_part_data<'a>(data: &'a [u8], dash_boundary: &[u8], nl_boundary: &[u8]) -> &'a [u8] {
    if dash_boundary.starts_with(data) {
        return data.get(..0).unwrap_or_default();
    }
    let Some(newline) = data
        .iter()
        .rposition(|&byte| byte == nl_boundary.first().copied().unwrap_or_default())
    else {
        return data;
    };
    let suffix = data.get(newline..).unwrap_or_default();
    if nl_boundary.starts_with(suffix) {
        return data.get(..newline).unwrap_or_default();
    }
    data
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

    let disposition = extract_content_disposition(&headers);
    // Go stores each part header under its canonical key, or under its raw name when it
    // holds a space (`canonicalMIMEHeaderKey`'s `noCanon` path), so only token names
    // fold case: `Content- Disposition` and `content- disposition` are distinct keys.
    let mut seen_headers = std::collections::HashSet::with_capacity(headers.len());
    let repeats_header =
        disposition.repeats_param || headers.iter().any(|(name, _)| !seen_headers.insert(header_key(name)));

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

/// The key Go's part header map holds `name` under, for comparison only: a token name
/// folds case, while a name with a space stays as sent
/// (`canonicalMIMEHeaderKey`'s `noCanon` path).
fn header_key(name: &str) -> String {
    if is_token_name(name) {
        name.to_ascii_lowercase()
    } else {
        name.to_owned()
    }
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
/// Go's `textproto.ReadMIMEHeader` folds a line that starts with a space or a tab
/// into the previous header's value, joined by one space, and trims spaces and tabs
/// from the ends of every physical line (`net/textproto/reader.go`,
/// `readContinuedLineSlice`, go1.27.3). It also accepts a space inside a header
/// name and keeps the name raw instead of canonicalizing it
/// (`net/textproto/reader.go`, `canonicalMIMEHeaderKey`, go.dev/issue/34540), which
/// is how CRS 922130 sees a `Content- Disposition` part header.
///
/// Values keep their exact bytes, as Go's `textproto` keeps them: an invalid
/// UTF-8 value must not collapse into another one.
fn parse_headers(data: &[u8]) -> Result<Headers, ParseError> {
    let mut headers = Vec::new();
    let mut lines = physical_lines(data).peekable();

    // The first line cannot be a fold: `ReadMIMEHeader` peeks for a leading space or
    // tab before it reads any header line.
    if let Some(first) = lines.peek()
        && is_fold(first)
    {
        if first.len() > TEXT_PROTO_INITIAL_LINE_LIMIT {
            return Err(ParseError::MessageTooLarge);
        }
        return Err(ParseError::InitialLine(quoted(first)));
    }

    while let Some(line) = lines.next() {
        // A truly empty line ends the header block; a line of only spaces or tabs is
        // a fold, which Go's reader joins to the previous value.
        if line.is_empty() {
            break;
        }
        // One logical header line: the first physical line, plus every fold after it.
        let first = trim_space_tab(line);
        let mut folded: Option<Vec<u8>> = None;
        while let Some(continuation) = lines.next_if(|next| is_fold(next)) {
            let joined = folded.get_or_insert_with(|| first.to_vec());
            joined.push(b' ');
            joined.extend_from_slice(trim_space_tab(continuation));
        }
        let logical = folded.as_deref().unwrap_or(first);

        if headers.len() >= MAX_PART_HEADERS {
            return Err(ParseError::Limit(format!(
                "part has more than {MAX_PART_HEADERS} headers"
            )));
        }
        // Go's `mustHaveFieldNameColon` requires the field name on the first line,
        // before any continuation is read.
        if !line.contains(&b':') {
            return Err(ParseError::MissingColon(quoted(line)));
        }
        let colon = logical
            .iter()
            .position(|&byte| byte == b':')
            .ok_or_else(|| ParseError::MissingColon(quoted(line)))?;
        let name = logical.get(..colon).unwrap_or_default();
        // A name is token bytes and spaces, as `canonicalMIMEHeaderKey` accepts them;
        // surrounding spaces stay unless they are the whole name, which Go's
        // `bytes.Cut` leaves empty and rejects.
        if name.is_empty()
            || !name
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~ ".contains(byte))
        {
            return Err(ParseError::MalformedHeaderLine(quoted(logical)));
        }
        let value = logical.get(colon.saturating_add(1)..).unwrap_or_default();
        if value.iter().any(|&byte| (byte < 0x20 && byte != b'\t') || byte == 0x7F) {
            return Err(ParseError::MalformedHeaderLine(quoted(logical)));
        }
        // A header name is confined to token bytes and spaces, which are ASCII.
        let Ok(name) = std::str::from_utf8(name) else {
            return Err(ParseError::MalformedHeaderLine(quoted(logical)));
        };
        // Only the leading whitespace goes, as in Go's `TrimLeft`: the physical lines
        // were already trimmed at both ends, and a trailing fold leaves one space.
        headers.push((name.to_owned(), trim_space_tab_start(value).to_vec()));
    }

    Ok(headers)
}

/// The physical lines of `data`, without their line endings, split as Go's
/// `bufio.Reader.ReadLine` splits them: it drops the `\r` of a CRLF ending only, so a
/// bare `\r` stays in the line.
fn physical_lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.split_inclusive(|&byte| byte == b'\n')
        .map(|line| match line.strip_suffix(b"\n") {
            Some(line) => strip_carriage_return(line),
            None => line,
        })
}

/// `line` without the `\r` of a CRLF ending.
fn strip_carriage_return(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Whether `line` continues the previous header line: Go's `textproto` folds a line
/// that starts with a space or a tab into that header's value.
fn is_fold(line: &[u8]) -> bool {
    line.first().is_some_and(|byte| matches!(byte, b' ' | b'\t'))
}

/// `bytes` without its leading spaces and tabs.
fn trim_space_tab_start(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !matches!(*byte, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    bytes.get(start..).unwrap_or_default()
}

/// `bytes` without the leading and trailing spaces and tabs Go's `textproto` `trim`
/// removes from a header line.
fn trim_space_tab(bytes: &[u8]) -> &[u8] {
    let rest = trim_space_tab_start(bytes);
    let end = rest
        .iter()
        .rposition(|byte| !matches!(*byte, b' ' | b'\t'))
        .map_or(0, |index| index.saturating_add(1));
    rest.get(..end).unwrap_or_default()
}

/// `bytes` quoted the way Go's `%q` quotes a header line, byte-exactly: printable text
/// stays, control characters use Go's escapes, and bytes that are not valid UTF-8 become
/// `\xNN`.
fn quoted(bytes: &[u8]) -> String {
    crate::utils::strings::go_quote_bytes(bytes)
}

/// What a part's Content-Disposition header says.
#[expect(
    clippy::struct_excessive_bools,
    reason = "these flags report independent Coraza multipart conditions"
)]
struct ContentDisposition {
    /// The part name from `Content-Disposition`, exactly as sent; empty unless the
    /// disposition parses as `form-data` and carries a name.
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

/// Extract the part name, filename and metadata from the Content-Disposition header.
///
/// Example: `form-data; name="field"; filename="file.txt"`
///
/// Go reads all of it from `mime.ParseMediaType`. `Part.parseContentDisposition` empties
/// the parameters when that parse fails, so neither the name nor a filename survives a
/// rejected header, and `Part.FormName` returns the name only when the media type is
/// exactly `form-data` (`mime/multipart/multipart.go:76-111`, go1.27.3). Coraza's
/// `originFileName` does not check the media type, so a part with any other disposition
/// still keeps its filename (`internal/bodyprocessors/multipart.go:285-300`, v3.8.1).
fn extract_content_disposition(headers: &Headers) -> ContentDisposition {
    let disposition = header(headers, "content-disposition").unwrap_or_default();
    let params = parse_header_params(disposition);
    let param = |name: &[u8]| {
        params
            .iter()
            .rev()
            .find(|param| param.name.as_slice() == name)
            .map(|param| param.value.clone())
    };
    let mut seen_params = std::collections::HashSet::with_capacity(params.len());
    let has_duplicate_param = params.iter().any(|param| !seen_params.insert(param.name.as_slice()));
    let quoted_extended_filename = params
        .iter()
        .any(|param| param.name.as_slice() == b"filename*" && param.quoted);

    // Go reads the name from `mime.ParseMediaType`, which resolves RFC 2231
    // `name*` and `name*0`/`name*1*` continuations (`mime/mediatype.go:160-230`).
    let Some(parsed) = media_type::parse(disposition).ok() else {
        // A part with no Content-Disposition simply carries no name, filename or
        // metadata. Only a header that is present but unparseable is a discrepancy
        // worth reporting, which is what Go's `originFileName` flags.
        return ContentDisposition {
            name: Vec::new(),
            filename: None,
            alt_filename: None,
            filename_encoding: None,
            malformed_extended_filename: !disposition.is_empty(),
            repeats_param: !disposition.is_empty() && has_duplicate_param,
            quoted_extended_filename: false,
        };
    };
    let resolved = |name: &[u8]| parsed.param(name).map(<[u8]>::to_vec);
    let name = if parsed.media_type() == b"form-data" {
        resolved(b"name").unwrap_or_default()
    } else {
        Vec::new()
    };

    // As Go Coraza reads RFC 5987's `filename*=charset'language'value`
    let plain = param(b"filename");
    // Go Coraza reads the plain `filename` a second time straight from the header with
    // `findParam`, and `unquoteIfQuoted` then drops every backslash rather than only the
    // ones before a `tspecial`, which is not what the stdlib quoted-string unquoter does.
    // The `filename*` and continuation branches below use that reading, so
    // `filename="C:\dev\x.txt"` reaches `FILES` as `C:devx.txt` when a `filename*` wins
    // (`internal/bodyprocessors/multipart.go:findParam`, `unquoteIfQuoted`, v3.8.1).
    let raw_plain = raw_param(disposition, b"filename").map(coraza_unquote);
    let continuation = has_filename_continuation(&params);
    let mut content_disposition = ContentDisposition {
        name,
        filename: plain.clone(),
        alt_filename: None,
        filename_encoding: None,
        malformed_extended_filename: continuation,
        repeats_param: false,
        quoted_extended_filename,
    };
    if let Some(extended) = raw_param(disposition, b"filename*").map(coraza_unquote) {
        let segments: Vec<&[u8]> = extended.splitn(3, |&byte| byte == b'\'').collect();
        match segments.as_slice() {
            [charset, language, value] => {
                let (decoded, invalid_escape) = percent_decode_lenient(value);
                content_disposition.alt_filename =
                    raw_plain.filter(|raw| !raw.is_empty() && raw.as_slice() != decoded.as_slice());
                content_disposition.filename = Some(decoded);
                content_disposition.filename_encoding = Some(FilenameEncoding {
                    charset: (*charset).to_vec(),
                    language: (*language).to_vec(),
                });
                content_disposition.malformed_extended_filename |= invalid_escape;
            },
            _ => content_disposition.malformed_extended_filename = true,
        }
    } else if continuation {
        // Go does not reassemble a `filename*N` continuation itself
        // (`internal/bodyprocessors/multipart.go:originFileName`). It keeps the raw
        // plain `filename` as the primary reading and exposes ParseMediaType's
        // continuation-resolved value as `altFilename` when it differs.
        if let Some(raw) = raw_plain {
            content_disposition.filename = Some(raw);
        }
        if let Some(resolved) = parsed.param(b"filename")
            && !resolved.is_empty()
            && content_disposition.filename.as_deref() != Some(resolved)
        {
            content_disposition.alt_filename = Some(resolved.to_vec());
        }
    }
    content_disposition
}

/// The raw value of the first parameter named `name`, unquoted by Go Coraza's
/// `findParam`: surrounding space is trimmed, and the quoted string, if any, is kept.
fn raw_param<'a>(header: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    split_header_params(header).into_iter().find_map(|part| {
        let part = trim_ascii(part);
        let equals = part.iter().position(|&byte| byte == b'=')?;
        let key = trim_ascii(part.get(..equals).unwrap_or_default());
        key.eq_ignore_ascii_case(name)
            .then(|| trim_ascii(part.get(equals.saturating_add(1)..).unwrap_or_default()))
    })
}

/// Go Coraza's `unquoteIfQuoted`: strip a surrounding quoted string and drop every
/// backslash, unlike the stdlib unquoter that keeps one before a `tspecial`. A value
/// that is not a quoted string is returned as sent.
fn coraza_unquote(value: &[u8]) -> Vec<u8> {
    let Some(inner) = value.strip_prefix(b"\"").and_then(|inner| inner.strip_suffix(b"\"")) else {
        return value.to_vec();
    };
    let mut unquoted = Vec::with_capacity(inner.len());
    let mut index = 0;
    while let Some(&byte) = inner.get(index) {
        if byte == b'\\' && index.saturating_add(1) < inner.len() {
            index = index.saturating_add(1);
        }
        if let Some(&byte) = inner.get(index) {
            unquoted.push(byte);
        }
        index = index.saturating_add(1);
    }
    unquoted
}

/// Whether a parameter continues `filename` under RFC 2231 (`filename*0`,
/// `filename*1*`, ...).
fn has_filename_continuation(params: &[HeaderParam]) -> bool {
    params.iter().any(|param| {
        let key = param.name.as_slice();
        let key = key.strip_suffix(b"*").unwrap_or(key);
        key.strip_prefix(b"filename*")
            .is_some_and(|digits| !digits.is_empty() && digits.iter().all(u8::is_ascii_digit))
    })
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
            // Only ASCII hex digits, as Go's `fromHex` accepts: `u8::from_str_radix`
            // would also take the leading `+` of `%+1`.
            .and_then(crate::utils::strings::x2c);
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
    // The first blank physical line ends the headers, so scan left to right: searching
    // for `\r\n\r\n` first would pick a later one inside a body whose headers ended
    // with a bare `\n\n` and start the part data past the real separator.
    for (pos, &byte) in data.iter().enumerate() {
        let rest = data.get(pos..).unwrap_or_default();
        let separator_len = match byte {
            b'\r' if rest.starts_with(b"\r\n\r\n") => 4,
            b'\r' if rest.starts_with(b"\r\n\n") => 3,
            b'\n' if rest.starts_with(b"\n\r\n") => 3,
            b'\n' if rest.starts_with(b"\n\n") => 2,
            _ => continue,
        };
        return Some((pos, separator_len));
    }
    None
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

/// A delimiter line Go's `mime/multipart` accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delimiter {
    /// `--boundary` followed by linear whitespace and the body's line ending.
    Part,
    /// `--boundary--` followed by linear whitespace and the line ending or end of input.
    Final,
}

/// Find the first delimiter, with the line ending it fixes for the whole body.
///
/// Go's `mime/multipart` skips complete preamble lines, so a marker inside one is
/// preamble text, not a delimiter. It starts in CRLF mode: only a first delimiter that
/// ends in a bare LF switches the reader to LF, and a closing marker must end in CRLF or
/// the input, so a first line such as `--b--\n` stays preamble
/// (`isBoundaryDelimiterLine`, go1.27.3).
fn find_first_boundary(data: &[u8], marker: &[u8], table: &[usize]) -> Option<(usize, &'static [u8])> {
    let start = find_subsequence_where(data, marker, table, |data, start| {
        let starts_line = start == 0
            || start
                .checked_sub(1)
                .and_then(|before| data.get(before))
                .is_some_and(|byte| *byte == b'\n');
        starts_line && first_delimiter_nl(data, start, marker).is_some()
    })?;
    Some((start, first_delimiter_nl(data, start, marker)?))
}

/// The line ending the first delimiter at `marker_start` fixes for the body, if that line
/// is the first delimiter at all.
fn first_delimiter_nl(data: &[u8], marker_start: usize, marker: &[u8]) -> Option<&'static [u8]> {
    let after_marker = marker_start.checked_add(marker.len())?;
    let tail = data.get(after_marker..)?;
    let ended = skip_lwsp_slice(tail);
    if ended.starts_with(b"\r\n") {
        return Some(b"\r\n");
    }
    if ended.starts_with(b"\n") {
        return Some(b"\n");
    }
    // Go's `isFinalBoundary` requires the closing dashes right after the marker:
    // linear whitespace before them makes the line no delimiter at all.
    let closing = skip_lwsp_slice(tail.strip_prefix(b"--")?);
    (closing.is_empty() || closing.starts_with(b"\r\n")).then_some(&b"\r\n"[..])
}

/// Find the next delimiter, returning the end of the part body and the marker position.
///
/// `nl` is the line ending of the body's first delimiter: Go's part reader ends a part
/// where such a line ending is followed by the marker, so a marker behind another line
/// ending stays part of the body.
fn find_next_boundary(data: &[u8], marker: &[u8], table: &[usize], nl: &[u8]) -> Option<(usize, usize)> {
    let marker_pos = find_subsequence_where(data, marker, table, |data, start| {
        is_delimiter_candidate(data, start, marker, nl)
    })?;
    let line_feed_pos = marker_pos.checked_sub(1)?;
    // In CRLF mode the carriage return belongs to the delimiter; in LF mode Go's reader
    // looks for a bare LF, so the carriage return stays in the part body.
    let part_end = if nl == b"\r\n" {
        line_feed_pos
            .checked_sub(1)
            .filter(|&carriage_return_pos| data.get(carriage_return_pos) == Some(&b'\r'))
            .unwrap_or(line_feed_pos)
    } else {
        line_feed_pos
    };
    Some((part_end, marker_pos))
}

/// Whether the line at `marker_start` is where Go's part reader ends a part: it starts
/// after `nl`, and the marker is followed by a byte that can begin a delimiter
/// (`matchAfterPrefix`). Whether the line really is a delimiter is
/// [`delimiter_kind`]'s decision.
///
/// A line that never ends is not a candidate: Go's reader ends there with `io.EOF`, and
/// only a closing marker may end the input.
fn is_delimiter_candidate(data: &[u8], marker_start: usize, marker: &[u8], nl: &[u8]) -> bool {
    let starts_line = marker_start
        .checked_sub(nl.len())
        .and_then(|before| data.get(before..marker_start))
        .is_some_and(|ending| ending == nl);
    if !starts_line {
        return false;
    }
    let Some(tail) = marker_start
        .checked_add(marker.len())
        .and_then(|after| data.get(after..))
    else {
        return false;
    };
    // `matchAfterPrefix`: a space, tab or line ending can follow the marker, and so can a
    // closing `--`, but a single dash cannot.
    let can_follow = match tail.first() {
        Some(b' ' | b'\t' | b'\r' | b'\n') => true,
        Some(b'-') => tail.get(1) == Some(&b'-'),
        _ => false,
    };
    if !can_follow {
        return false;
    }
    tail.contains(&b'\n') || closing_marker_at_eof(tail)
}

/// Whether `tail`, which starts just after a boundary marker, is `--` followed by linear
/// whitespace and the end of the input, which Go accepts as the final boundary.
fn closing_marker_at_eof(tail: &[u8]) -> bool {
    let Some(closing) = tail.strip_prefix(b"--") else {
        return false;
    };
    skip_lwsp_slice(closing).is_empty()
}

/// Classify the delimiter line at `marker_start`, which [`is_delimiter_candidate`] found.
///
/// A line that is no delimiter under `nl` is one Go reports as
/// `multipart: expecting a new Part; got line "<line>"`, quoted as sent.
fn delimiter_kind(data: &[u8], marker_start: usize, marker: &[u8], nl: &[u8]) -> Result<Delimiter, ParseError> {
    let after_marker = marker_start.saturating_add(marker.len());
    let tail = data.get(after_marker..).unwrap_or_default();
    if skip_lwsp_slice(tail).starts_with(nl) {
        return Ok(Delimiter::Part);
    }
    // The closing dashes must follow the marker directly, as in Go's `isFinalBoundary`.
    if let Some(closing) = tail.strip_prefix(b"--") {
        let closing = skip_lwsp_slice(closing);
        if closing.is_empty() || closing.starts_with(nl) {
            return Ok(Delimiter::Final);
        }
    }
    let line = data.get(marker_start..).unwrap_or_default();
    let line_len = line
        .iter()
        .position(|&byte| byte == b'\n')
        .map_or(line.len(), |index| index.saturating_add(1));
    Err(ParseError::UnexpectedLine(quoted(
        line.get(..line_len).unwrap_or_default(),
    )))
}

/// `bytes` without its leading spaces and tabs.
fn skip_lwsp_slice(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !matches!(*byte, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    bytes.get(start..).unwrap_or_default()
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
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "parser tests use fixed multipart fixtures"
)]
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
        let parts = parser.parse_ok().unwrap();

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
        let parts = parser.parse_ok().unwrap();

        assert_eq!(parts.len(), 1);
        let part = parts.first().unwrap();
        assert_eq!(part.name.as_slice(), b"file");
        assert_eq!(part.filename.as_deref(), Some(&b"test.txt"[..]));
        assert_eq!(header(&part.headers, "Content-Type"), Some(&b"text/plain"[..]));
        assert_eq!(part.data, b"file content");
    }

    /// The fields RFC 2231 affects in one part.
    type Rfc2231Fields = (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, bool);

    /// Parse one part and return the fields RFC 2231 affects.
    fn rfc2231_fields(disposition: &str) -> Rfc2231Fields {
        let body = format!("--b\r\nContent-Disposition: {disposition}\r\n\r\nv\r\n--b--");
        let parts = MultipartParser::new("b", body.as_bytes()).parse_ok().unwrap();
        let part = parts.first().unwrap();
        (
            part.name.clone(),
            part.filename.clone(),
            part.alt_filename.clone(),
            part.malformed_filename,
        )
    }

    #[test]
    fn decodes_rfc_2231_names_like_go() {
        for (disposition, expected) in [
            ("form-data; name*=utf-8''field", b"field".as_slice()),
            ("form-data; name*0=long; name*1=name", b"longname"),
            ("form-data; name=\"plain\"; name*=utf-8''extended", b"extended"),
            ("form-data; name=\"plain\"; name*=iso-8859-1''field", b"plain"),
            // Go's percent decoding keeps the raw byte; it does not transcode.
            ("form-data; name*=utf-8''%FF", b"\xff"),
        ] {
            assert_eq!(rfc2231_fields(disposition).0, expected, "{disposition}");
        }
    }

    #[test]
    fn a_quoted_extended_filename_uses_coraza_unquoting() {
        // Go Coraza resolves `filename*` with `findParam` and `unquoteIfQuoted`, which
        // drops every backslash, so a quoted value resolves as if unquoted.
        let (_, filename, alt, _) = rfc2231_fields(r#"form-data; name=f; filename*="utf-8''x.p\hp""#);
        assert_eq!(filename.as_deref(), Some(&b"x.php"[..]));
        assert_eq!(alt, None);
    }

    #[test]
    fn decodes_rfc_2231_filenames_and_keeps_continuation_readings() {
        let (_, filename, alt, malformed) = rfc2231_fields("form-data; name=f; filename*=utf-8''%FF.txt");
        assert_eq!(filename.as_deref(), Some(&b"\xff.txt"[..]));
        assert_eq!(alt, None);
        assert!(!malformed);

        // An unsupported extended charset is still decoded, as Coraza's own
        // originFileName does; the charset is exposed verbatim.
        let (_, filename, _, malformed) = rfc2231_fields("form-data; name=f; filename*=iso-8859-1''%FF.txt");
        assert_eq!(filename.as_deref(), Some(&b"\xff.txt"[..]));
        assert!(!malformed);

        // Go does not reassemble a continuation itself for the primary filename.
        // It keeps the raw plain `filename` and exposes ParseMediaType's resolved
        // reading as altFilename.
        let (_, filename, alt, malformed) =
            rfc2231_fields("form-data; name=f; filename=\"plain.txt\"; filename*0=\"long\"; filename*1=\".txt\"");
        assert_eq!(filename.as_deref(), Some(&b"plain.txt"[..]));
        assert_eq!(alt.as_deref(), Some(&b"long.txt"[..]));
        assert!(malformed);
    }

    #[test]
    fn a_plain_filename_fallback_uses_coraza_unquoting() {
        // Go Coraza reads the plain `filename` with `findParam` and `unquoteIfQuoted`,
        // which drops every backslash, so `C:\dev\x.txt` becomes `C:devx.txt`
        // (`internal/bodyprocessors/multipart.go`, v3.8.1); the stdlib reading keeps them.
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"f\"; filename=\"C:\\dev\\x.txt\"; filename*=utf-8''a.txt\r\n\
\r\n\
DATA\r\n\
--b--\r\n";
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
        let part = parts.first().unwrap();
        assert_eq!(part.filename.as_deref(), Some(&b"a.txt"[..]));
        assert_eq!(part.alt_filename.as_deref(), Some(&b"C:devx.txt"[..]));

        // The continuation reading keeps the raw plain filename as its primary reading,
        // with ParseMediaType's resolved value as the alternate one.
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"f\"; filename=\"C:\\dev\\x.txt\"; filename*0=\"long\"; filename*1=\".txt\"\r\n\
\r\n\
DATA\r\n\
--b--\r\n";
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
        let part = parts.first().unwrap();
        assert_eq!(part.filename.as_deref(), Some(&b"C:devx.txt"[..]));
        assert_eq!(part.alt_filename.as_deref(), Some(&b"long.txt"[..]));
    }

    #[test]
    fn repeated_filename_parameters_yield_no_filename_like_go() {
        // `mime.ParseMediaType` rejects the repeated parameter, so
        // `Part.parseContentDisposition` empties the parameters: Go's `FormName` and
        // `originFileName` return nothing at all (`mime/multipart/multipart.go:76-111`,
        // `internal/bodyprocessors/multipart.go:285-300`). The discrepancy still reaches
        // MULTIPART_DUPLICATE_PART_HEADER and MULTIPART_STRICT_ERROR.
        let headers = vec![(
            "Content-Disposition".to_owned(),
            br#"form-data; name="upload"; filename="safe.jpg"; filename="shell.php""#.to_vec(),
        )];
        let disposition = extract_content_disposition(&headers);
        assert!(disposition.name.is_empty());
        assert_eq!(disposition.filename, None);
        assert_eq!(disposition.alt_filename, None);
        assert!(disposition.malformed_extended_filename);
        assert!(disposition.repeats_param);

        // Repeated identical values are not a parse error for Go either.
        let headers = vec![(
            "Content-Disposition".to_owned(),
            br#"form-data; name="upload"; filename="same.jpg"; filename="same.jpg""#.to_vec(),
        )];
        let disposition = extract_content_disposition(&headers);
        assert_eq!(disposition.name.as_slice(), b"upload");
        assert_eq!(disposition.filename.as_deref(), Some(&b"same.jpg"[..]));
        assert!(!disposition.malformed_extended_filename);
        assert!(!disposition.repeats_param);
    }

    #[test]
    fn truncated_bodies_keep_the_parts_read_before_the_limit() {
        let file_body = b"--a\n\
Content-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\n\
Content-Type: text/plain\n\
\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
--a--\n";
        let parts = MultipartParser::new("a", &file_body[..150])
            .truncated(true)
            .parse_ok()
            .unwrap();
        let part = parts.first().unwrap();
        assert_eq!(part.name.as_slice(), b"f");
        assert_eq!(part.filename.as_deref(), Some(&b"x.txt"[..]));
        assert!(part.data.iter().all(|&byte| byte == b'A'));

        let field_body = b"--a\n\
Content-Disposition: form-data; name=\"t\"\n\
\n\
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n\
--a--\n";
        let parts = MultipartParser::new("a", &field_body[..150])
            .truncated(true)
            .parse_ok()
            .unwrap();
        assert_eq!(parts.first().unwrap().data, b"B".repeat(104).as_slice());

        // The closing boundary itself was cut: the partial delimiter is not part
        // of the field value.
        let closing_body = b"--a\n\
Content-Disposition: form-data; name=\"u\"\n\
\n\
DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\n\
--a--\n";
        let parts = MultipartParser::new("a", &closing_body[..150])
            .truncated(true)
            .parse_ok()
            .unwrap();
        assert_eq!(parts.first().unwrap().data, b"D".repeat(100).as_slice());
    }

    #[test]
    fn truncated_bodies_still_reject_malformed_headers() {
        let body = b"--a\nBad Header\n\nvalue";
        assert!(MultipartParser::new("a", body).truncated(true).parse_ok().is_err());

        // A header block cut before its blank line is discarded, as Go's reader
        // reports no part for it.
        let body = b"--a\nContent-Disposition: form-data; name=\"t\"";
        let parts = MultipartParser::new("a", body).truncated(true).parse_ok().unwrap();
        assert!(parts.is_empty());
    }

    #[test]
    fn find_next_boundary_follows_the_bodys_line_ending() {
        let marker = b"--boundary";
        let table = prefix_table(marker);
        // CRLF mode: the carriage return belongs to the delimiter.
        assert_eq!(
            find_next_boundary(b"payload\r\n--boundary\r\n", marker, &table, b"\r\n"),
            Some((7, 9))
        );
        // LF mode: it stays in the body, as Go's reader looks for a bare LF.
        assert_eq!(
            find_next_boundary(b"payload\r\n--boundary\n", marker, &table, b"\n"),
            Some((8, 9))
        );
        // A marker behind another line ending is body text, as in Go.
        assert_eq!(
            find_next_boundary(b"payload\n--boundary\r\n", marker, &table, b"\r\n"),
            None
        );
    }

    #[test]
    fn find_header_end_stops_at_the_first_blank_line() {
        assert_eq!(find_header_end(b"X: y\r\n\r\nATTACK\r\n\r\n"), Some((4, 4)));
        // A bare-LF terminator must win over a CRLF sequence inside the body; picking
        // the later one starts the part data past the real separator.
        assert_eq!(find_header_end(b"X: y\n\nATTACK\r\n\r\n"), Some((4, 2)));
        // The blank line's two line endings need not match.
        assert_eq!(find_header_end(b"X: y\r\n\nATTACK"), Some((4, 3)));
        assert_eq!(find_header_end(b"X: y\n\r\nATTACK"), Some((4, 3)));
        assert_eq!(find_header_end(b"X: y\r\n"), None);
    }

    #[test]
    fn a_part_without_a_blank_line_still_fails() {
        let mut total_header_bytes = 0;
        let error = parse_part(
            b"Content-Disposition: form-data; name=\"a\"\r\n",
            &mut total_header_bytes,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ParseError::MalformedHeaders(message) if message == "no blank line after headers"
        ));
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
        let parts = parser.parse_ok().unwrap();

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

        let parts = MultipartParser::new("boundary", body).parse_ok().unwrap();

        assert_eq!(parts.first().unwrap().data, b"value\r\n--boundary-not-a-delimiter\r\n");
    }

    #[test]
    fn rejects_a_body_without_its_closing_boundary() {
        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"field\"\r\n\
\r\n\
value";

        assert!(MultipartParser::new("boundary", body).parse_ok().is_err());
    }

    #[test]
    fn test_lf_line_endings() {
        let body = b"--boundary\n\
Content-Disposition: form-data; name=\"field\"\n\
\n\
value\n\
--boundary--";

        let parser = MultipartParser::new("boundary", body);
        let parts = parser.parse_ok().unwrap();

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
        let parts = parser.parse_ok().unwrap();

        assert_eq!(parts.len(), 1);
        let part = parts.first().unwrap();
        assert_eq!(part.name.as_slice(), b"empty");
        assert_eq!(part.data, b"");
    }

    #[test]
    fn test_no_boundary() {
        let body = b"some random data";

        let parser = MultipartParser::new("boundary", body);
        let result = parser.parse_ok();

        assert!(result.is_err());
    }

    #[test]
    fn a_part_without_content_disposition_is_an_anonymous_field() {
        // Go's `Part.FormName` returns "" and `originFileName` no filename when the part
        // has no Content-Disposition, so the part is still published
        // (`internal/bodyprocessors/multipart.go:182`, v3.8.1).
        let body = b"--boundary\r\n\
Content-Type: text/plain\r\n\
\r\n\
value\r\n\
--boundary--";

        let parts = MultipartParser::new("boundary", body).parse_ok().unwrap();
        let part = parts.first().unwrap();
        assert!(part.name.is_empty());
        assert_eq!(part.filename, None);
        assert!(!part.malformed_filename);
        assert_eq!(part.data, b"value");
    }

    #[test]
    fn part_header_names_follow_go_textproto_leniency() {
        // Go accepts a space inside a header name and keeps the name as sent, which is
        // the shape CRS test 922130-4 sends. A name with a trailing space is kept raw
        // as well: `canonicalMIMEHeaderKey` takes its `noCanon` path for it
        // (`net/textproto/reader.go`, go.dev/issue/34540).
        let headers =
            parse_headers(b"Content- Disposition: form-data\r\nBad  Name:value\r\nContent-Disposition : form-data\r\n")
                .unwrap();
        assert_eq!(
            headers,
            [
                ("Content- Disposition".to_owned(), b"form-data".to_vec()),
                ("Bad  Name".to_owned(), b"value".to_vec()),
                ("Content-Disposition ".to_owned(), b"form-data".to_vec()),
            ]
        );

        // Control bytes, an empty name, a tab in a name and a first line that starts
        // with a space (a fold, which Go rejects as the initial line) stay rejected.
        for rejected in [
            b"Content-Disposition\x0E: form-data\r\n".as_slice(),
            b"\x0EContent-Disposition: form-data\r\n",
            b"Content\x7F-Disposition: form-data\r\n",
            b"Content-Disposition\t: form-data\r\n",
            b"X: a\r\r\n",
            b" Content-Disposition: form-data\r\n",
            b": value\r\n",
            b"invalid\r\n",
        ] {
            assert!(parse_headers(rejected).is_err(), "{rejected:?} was accepted");
        }
    }

    #[test]
    fn folded_header_lines_are_joined_like_go() {
        // Go's `readContinuedLineSlice` trims spaces and tabs from each physical line,
        // joins a continuation to the previous value with one space, and folds a
        // whitespace-only line too.
        let headers = parse_headers(b"X: a\r\n b\r\n\tc\r\n Y \t\r\n").unwrap();
        assert_eq!(headers, [("X".to_owned(), b"a b c Y".to_vec())]);

        // Folding keeps the value bytes as sent, invalid UTF-8 included.
        let headers = parse_headers(b"X: \xff\r\n \xfe\r\n").unwrap();
        assert_eq!(headers, [("X".to_owned(), b"\xff \xfe".to_vec())]);

        // A whitespace-only line is a fold with nothing to add, so the single space
        // the join inserted stays: Go yields `a ` for this header block.
        let headers = parse_headers(b"X: a\r\n  ").unwrap();
        assert_eq!(headers, [("X".to_owned(), b"a ".to_vec())]);
    }

    #[test]
    fn malformed_header_errors_use_go_textproto_wording() {
        let error = parse_headers(b"Bad Header\r\n").unwrap_err();
        assert_eq!(
            error.go_message(),
            r#"malformed MIME header: missing colon: "Bad Header""#
        );

        // The missing-colon message quotes the first physical line, before folding.
        let error = parse_headers(b"Bad Header\r\n cont: x\r\n").unwrap_err();
        assert_eq!(
            error.go_message(),
            r#"malformed MIME header: missing colon: "Bad Header""#
        );

        // An invalid name or value is one message in Go, quoting the whole logical
        // line with Go's escapes; bytes that are not UTF-8 are `\xNN`, as Go's `%q`
        // prints them.
        let error = parse_headers(b"\x0eBad: v\r\n").unwrap_err();
        assert_eq!(error.go_message(), r#"malformed MIME header line: "\x0eBad: v""#);
        let error = parse_headers(b"X\xffY\x01: v\r\n").unwrap_err();
        assert_eq!(error.go_message(), r#"malformed MIME header line: "X\xffY\x01: v""#);
        let error = parse_headers(b": value\r\n").unwrap_err();
        assert_eq!(error.go_message(), r#"malformed MIME header line: ": value""#);

        let error = parse_headers(b" Content-Disposition: v\r\n").unwrap_err();
        assert_eq!(
            error.go_message(),
            r#"malformed MIME header initial line: " Content-Disposition: v""#
        );
    }

    #[test]
    fn a_folded_content_disposition_line_yields_the_filename() {
        // The exact part a working bypass sent: Go folds the leading-space line into
        // the Content-Disposition value, so the part has `filename="shell.php"`.
        let body = b"--b\r\nContent-Disposition: form-data; name=\"u\";\r\n filename=\"shell.php\"\r\nContent-Type: application/octet-stream\r\n\r\nPAYLOAD\r\n--b--\r\n";
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
        let part = parts.first().unwrap();
        assert_eq!(part.name.as_slice(), b"u");
        assert_eq!(part.filename.as_deref(), Some(&b"shell.php"[..]));
        assert_eq!(part.data, b"PAYLOAD");
        assert_eq!(
            header(&part.headers, "content-disposition"),
            Some(b"form-data; name=\"u\"; filename=\"shell.php\"".as_slice())
        );

        // A fold inside the filename joins its halves with one space, as in Go.
        let body =
            b"--b\r\nContent-Disposition: form-data; name=\"u\"; filename=\"sh\r\n\tell.php\"\r\n\r\nP\r\n--b--\r\n";
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
        assert_eq!(parts.first().unwrap().filename.as_deref(), Some(&b"sh ell.php"[..]));
    }

    #[test]
    fn parts_before_an_invalid_part_are_returned_with_the_error() {
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"ok\"\r\n\
\r\n\
GOOD\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"bad\"\r\n\
Bad Header\r\n\
\r\n\
P\r\n\
--b--\r\n";
        let (parts, error) = MultipartParser::new("b", body).parse();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().name.as_slice(), b"ok");
        assert_eq!(parts.first().unwrap().data, b"GOOD");
        assert!(matches!(error, Some(ParseError::MissingColon(_))), "{error:?}");
    }

    #[test]
    fn part_with_a_space_in_a_header_name_is_parsed() {
        let body = b"--boundary\r\n\
Content- Disposition: form-data; name=\"file\"; filename=\"1.php\"\r\n\
Content-Disposition: form-data; name=\"post\"\r\n\
\r\n\
value\r\n\
--boundary--\r\n";

        let parts = MultipartParser::new("boundary", body).parse_ok().unwrap();

        let part = parts.first().unwrap();
        assert_eq!(part.name.as_slice(), b"post");
        assert!(part.headers.iter().any(|(name, _)| name == "Content- Disposition"));
        // Two distinct header names, so Go's header map holds no duplicate.
        assert!(!part.repeats_header);
    }

    #[test]
    fn linear_search_finds_the_same_match_as_the_naive_scan() {
        /// The naive scan the linear-time search replaced, kept as the test's oracle.
        fn naive_find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            if needle.is_empty() {
                return Some(0);
            }
            haystack.windows(needle.len()).position(|window| window == needle)
        }

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
                naive_find_subsequence(&haystack, &needle),
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
        let parts = parser.parse_ok().unwrap();

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
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
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
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
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
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
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
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
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
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
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
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
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
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
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
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
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
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
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
        let error = MultipartParser::new("b", body).parse_ok().unwrap_err();
        assert!(matches!(error, ParseError::Parse(message) if message == "no boundary found"));

        // The line is preamble, not a delimiter: the later final boundary is
        // the first delimiter, as in Go.
        let body = b"--b --\r\n\
Content-Disposition: form-data; name=\"q\"\r\n\
\r\n\
v\r\n\
--b--";
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
        assert!(parts.is_empty());
    }

    #[test]
    fn ordinary_delimiter_with_trailing_whitespace_without_line_ending_is_rejected() {
        assert!(MultipartParser::new("b", b"--b ").parse_ok().is_err());

        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"q\"\r\n\
\r\n\
v\r\n\
--b ";
        let error = MultipartParser::new("b", body).parse_ok().unwrap_err();
        assert!(matches!(error, ParseError::Parse(message) if message == "missing final boundary"));
    }

    #[test]
    fn boundary_like_payload_with_trailing_space_errors_like_go() {
        // Go's part reader ends the part at the line that starts with the marker, then
        // reads it as the next delimiter: `--b x` is not one, so `NextPart` reports it
        // instead of keeping it in the body (`mime/multipart/multipart.go:391-424`).
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"q\"\r\n\
\r\n\
v\r\n\
--b x\r\n\
more\r\n\
--b--";
        let (parts, error) = MultipartParser::new("b", body).parse();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().data, b"v");
        let error = error.expect("the delimiter line must be reported");
        assert_eq!(
            error.go_message(),
            r#"multipart: expecting a new Part; got line "--b x\r\n""#
        );
    }

    #[test]
    fn a_delimiter_right_after_the_headers_ends_an_empty_part() {
        // Go's part reader accepts a delimiter at the very start of a body, where no line
        // ending precedes it (`scanUntilBoundary`'s `total == 0` case).
        let body = b"--b\r\nContent-Disposition: form-data; name=\"e\"\r\n\r\n--b--\r\n";
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().name.as_slice(), b"e");
        assert_eq!(parts.first().unwrap().data, b"");
    }

    #[test]
    fn mixed_delimiter_line_endings_error_like_go() {
        // Go fixes the line ending at the first delimiter and rejects a later delimiter
        // that uses another one, after the parts before it were read
        // (`mime/multipart/multipart.go`, `isBoundaryDelimiterLine`, go1.27.3).
        let crlf_then_lf = b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\none\r\n--b\nContent-Disposition: form-data; name=\"b\"\r\n\r\ntwo\r\n--b--\r\n";
        let (parts, error) = MultipartParser::new("b", crlf_then_lf).parse();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().data, b"one");
        let error = error.expect("the LF delimiter must be reported");
        assert_eq!(
            error.go_message(),
            r#"multipart: expecting a new Part; got line "--b\n""#
        );

        let lf_then_crlf = b"--b\nContent-Disposition: form-data; name=\"a\"\n\none\n--b\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\ntwo\r\n--b--\r\n";
        let (parts, error) = MultipartParser::new("b", lf_then_crlf).parse();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().data, b"one");
        let error = error.expect("the CRLF delimiter must be reported");
        assert_eq!(
            error.go_message(),
            r#"multipart: expecting a new Part; got line "--b\r\n""#
        );

        // A closing marker with the other ending is rejected the same way.
        let crlf_then_lf_final = b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\none\r\n--b--\n";
        let (parts, error) = MultipartParser::new("b", crlf_then_lf_final).parse();
        assert_eq!(parts.len(), 1);
        let error = error.expect("the LF closing marker must be reported");
        assert_eq!(
            error.go_message(),
            r#"multipart: expecting a new Part; got line "--b--\n""#
        );
    }

    #[test]
    fn an_lf_body_keeps_a_carriage_return_before_its_delimiter() {
        // LF mode looks for a bare LF before the marker, so the carriage return in front
        // of it stays in the part body, as in Go.
        let body = b"--b\nContent-Disposition: form-data; name=\"a\"\n\none\r\n--b\nContent-Disposition: form-data; name=\"b\"\n\ntwo\n--b--\n";
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts.first().unwrap().data, b"one\r");
        assert_eq!(parts.get(1).unwrap().data, b"two");
    }

    #[test]
    fn a_long_folded_initial_line_is_message_too_large_like_go() {
        // `readMIMEHeader` probes the first line with an 80-byte limit, so a longer folded
        // line fails before it can be quoted (`net/textproto/reader.go`, go1.27.3).
        fn folded(len: usize) -> Vec<u8> {
            let mut header = vec![b' '];
            header.extend(std::iter::repeat_n(b'a', len.saturating_sub(1)));
            header
        }
        let at_limit = folded(TEXT_PROTO_INITIAL_LINE_LIMIT);
        let error = parse_headers(&at_limit).unwrap_err();
        assert_eq!(
            error.go_message(),
            format!(
                "malformed MIME header initial line: {:?}",
                String::from_utf8_lossy(&at_limit)
            )
        );

        let error = parse_headers(&folded(TEXT_PROTO_INITIAL_LINE_LIMIT.saturating_add(1))).unwrap_err();
        assert_eq!(error.go_message(), "multipart: message too large");
    }

    #[test]
    fn empty_boundary_is_rejected() {
        let error = MultipartParser::new("", b"--\r\n--").parse_ok().unwrap_err();
        assert!(matches!(error, ParseError::Parse(message) if message == "boundary is empty"));
    }

    #[test]
    fn boundary_length_budget_is_enforced() {
        let boundary = "a".repeat(MAX_BOUNDARY_LEN);
        let body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nv\r\n--{boundary}--");
        let parts = MultipartParser::new(boundary, body.as_bytes()).parse_ok().unwrap();
        assert_eq!(parts.len(), 1);

        let boundary = "a".repeat(MAX_BOUNDARY_LEN.saturating_add(1));
        let error = MultipartParser::new(boundary, b"irrelevant").parse_ok().unwrap_err();
        assert!(matches!(error, ParseError::Limit(_)));
    }

    #[test]
    fn a_boundary_go_accepts_is_not_rejected() {
        // Go's only implicit boundary bound is its 4096-byte read buffer, so a
        // 1025-byte boundary parses there and must parse here too.
        let boundary = "a".repeat(1025);
        let body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nv\r\n--{boundary}--");
        let parts = MultipartParser::new(boundary, body.as_bytes()).parse_ok().unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().data, b"v");
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

        let parts = MultipartParser::new(boundary, &body).parse_ok().unwrap();
        assert!(parts.is_empty());
    }

    #[test]
    fn long_dash_run_inside_a_part_body_is_preserved() {
        let boundary = format!("{}b", "-".repeat(1023));
        let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n").into_bytes();
        let payload_start = body.len();
        body.extend(std::iter::repeat_n(b'-', 256 * 1024));
        body.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());

        let parts = MultipartParser::new(boundary, &body).parse_ok().unwrap();
        let part = parts.first().unwrap();
        let payload = body
            .get(payload_start..payload_start.saturating_add(256 * 1024))
            .unwrap();
        assert_eq!(part.data, payload);
    }

    #[test]
    fn part_count_budget_is_enforced() {
        fn parse_parts(count: usize) -> (usize, Option<ParseError>) {
            let mut body = Vec::new();
            for index in 0..count {
                body.extend_from_slice(
                    format!("--b\r\nContent-Disposition: form-data; name=\"f{index}\"\r\n\r\nv\r\n").as_bytes(),
                );
            }
            body.extend_from_slice(b"--b--");
            let (parts, error) = MultipartParser::new("b", &body).parse();
            (parts.len(), error)
        }

        let (parts, error) = parse_parts(MAX_PARTS);
        assert_eq!(parts, MAX_PARTS);
        assert!(error.is_none());
        let (parts, error) = parse_parts(MAX_PARTS.saturating_add(1));
        assert_eq!(parts, MAX_PARTS, "the parts parsed before the budget are published");
        assert!(matches!(error, Some(ParseError::Limit(_))));
    }

    #[test]
    fn a_header_budget_hit_keeps_the_parts_parsed_before_it() {
        let mut body = b"--b\r\nContent-Disposition: form-data; name=\"ok\"\r\n\r\nv\r\n\
--b\r\nContent-Disposition: form-data; name=\"q\"\r\nX: "
            .to_vec();
        body.extend(std::iter::repeat_n(b'a', MAX_HEADER_BLOCK));
        body.extend_from_slice(b"\r\n\r\nv\r\n--b--");

        let (parts, error) = MultipartParser::new("b", &body).parse();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().name.as_slice(), b"ok");
        assert!(matches!(error, Some(ParseError::Limit(_))));
    }

    #[test]
    fn header_block_budget_is_enforced() {
        let mut body = b"--b\r\nContent-Disposition: form-data; name=\"q\"\r\nX: ".to_vec();
        body.extend(std::iter::repeat_n(b'a', MAX_HEADER_BLOCK));
        body.extend_from_slice(b"\r\n\r\nv\r\n--b--");

        let error = MultipartParser::new("b", &body).parse_ok().unwrap_err();
        assert!(matches!(error, ParseError::Limit(_)));
    }

    #[test]
    fn header_count_budget_is_enforced() {
        let mut body = b"--b\r\nContent-Disposition: form-data; name=\"q\"\r\n".to_vec();
        for index in 0..MAX_PART_HEADERS {
            body.extend_from_slice(format!("X{index}: v\r\n").as_bytes());
        }
        body.extend_from_slice(b"\r\nv\r\n--b--");

        let error = MultipartParser::new("b", &body).parse_ok().unwrap_err();
        assert!(matches!(error, ParseError::Limit(_)));
    }

    #[test]
    fn a_body_ending_after_a_delimiter_is_not_malformed() {
        // Go's `NextPart` sees a plain `io.EOF` after a delimiter line and reports no
        // strict error; only a cut part is `io.ErrUnexpectedEOF`.
        for body in [
            b"--b\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nv\r\n--b\r\n".as_slice(),
            b"--b\r\n".as_slice(),
        ] {
            let (parts, error) = MultipartParser::new("b", body).parse();
            assert!(parts.is_empty() || parts.first().is_some_and(|part| part.data == b"v"));
            assert!(error.is_none(), "{error:?}");
        }
    }

    #[test]
    fn a_body_without_a_final_boundary_keeps_its_last_part() {
        // Go's `NextPart` returns the part in progress and only reading it fails with
        // `io.ErrUnexpectedEOF`, so the part is still inspected.
        let body = b"--b\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nattack";
        let (parts, error) = MultipartParser::new("b", body).parse();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().name.as_slice(), b"q");
        assert_eq!(parts.first().unwrap().data, b"attack");
        assert!(matches!(error, Some(ParseError::Parse(message)) if message == "missing final boundary"));
    }

    #[test]
    fn a_partial_delimiter_at_the_end_is_not_part_of_the_last_part() {
        let body = b"--b\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nattack\r\n--";
        let (parts, error) = MultipartParser::new("b", body).parse();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts.first().unwrap().data, b"attack");
        assert!(matches!(error, Some(ParseError::Parse(message)) if message == "missing final boundary"));
    }

    #[test]
    fn truncated_part_headers_are_rejected() {
        let body = b"--b\r\nContent-Disposition: form-data; name=\"q\"";
        let error = MultipartParser::new("b", body).parse_ok().unwrap_err();
        assert!(matches!(error, ParseError::Parse(message) if message.contains("missing final boundary")));
    }

    #[test]
    fn non_utf8_header_bytes_are_kept_as_sent() {
        // Go's textproto keeps the raw bytes in the value; so does this parser.
        let body = b"--b\r\nContent-Disposition: form-data; name=\"q\"\r\nX: \xff\xfe\r\n\r\nv\r\n--b--";
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
        assert_eq!(header(&parts.first().unwrap().headers, "X"), Some(&b"\xff\xfe"[..]));

        // A non-UTF-8 header name is not a valid token and is rejected.
        let body = b"--b\r\nContent-Disposition: form-data; name=\"q\"\r\n\xff: v\r\n\r\nv\r\n--b--";
        assert!(MultipartParser::new("b", body).parse_ok().is_err());
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
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
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
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
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
        let parts = MultipartParser::new("b", body).parse_ok().unwrap();
        assert_eq!(parts.len(), 2);
        assert!(parts.iter().all(|part| part.name.as_slice() == b"\xff"));
        assert_eq!(parts.first().unwrap().data, b"one");
        assert_eq!(parts.get(1).unwrap().data, b"two");
    }

    /// Go's `percentDecodeLenient` and `fromHex`
    /// (`internal/bodyprocessors/multipart.go:519-555`).
    #[test]
    fn percent_decode_accepts_only_ascii_hex_digits() {
        // A sign is not a hex digit, though `u8::from_str_radix` would take `+`.
        assert_eq!(percent_decode_lenient(b"%+1"), (b"%+1".to_vec(), true));
        assert_eq!(percent_decode_lenient(b"%-1"), (b"%-1".to_vec(), true));
        assert_eq!(percent_decode_lenient(b"%zz"), (b"%zz".to_vec(), true));

        // A truncated escape stays literal and is reported.
        assert_eq!(percent_decode_lenient(b"%1"), (b"%1".to_vec(), true));
        assert_eq!(percent_decode_lenient(b"%A"), (b"%A".to_vec(), true));
        assert_eq!(percent_decode_lenient(b"a%2"), (b"a%2".to_vec(), true));
        assert_eq!(percent_decode_lenient(b"%"), (b"%".to_vec(), true));

        // Two digits decode, in either case, including at the end of input.
        assert_eq!(percent_decode_lenient(b"%41%6a%6A"), (b"Ajj".to_vec(), false));
        assert_eq!(percent_decode_lenient(b"%41"), (b"A".to_vec(), false));
        assert_eq!(percent_decode_lenient(b"%ff"), (vec![0xFF], false));
        assert_eq!(percent_decode_lenient(b"plain"), (b"plain".to_vec(), false));
    }
}
