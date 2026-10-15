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
//! Message inspection: field extraction, decoding and detector dispatch.
//!
//! # Documented detection limits
//!
//! These are properties of the detector this filter wraps, not defects to be
//! worked around here. Operators cannot compensate for limits they do not
//! know about, so they are recorded where the dispatch happens.
//!
//! - **Injection into a statement, not a statement as a value.** libinjection and therefore libperfusion detect a
//!   fragment injected into an existing SQL statement. A *complete* statement supplied as a parameter value -- `SELECT
//!   * FROM users`, `DROP TABLE users`, `DELETE FROM users` -- is not reported, because its shape is not an injection
//!   shape. This matters in front of GraphQL resolvers, report builders and admin consoles, where a whole statement in
//!   a parameter is itself the attack. Detecting it needs an opt-in signal with a separate false-positive profile and
//!   is deliberately not enabled here.
//! - **No XML parsing.** An XML body is scanned raw and marked [`Incomplete::UnsupportedContentType`]; its elements are
//!   not decoded.
//! - **No `Content-Encoding` decoding.** A compressed body that reaches the filter is marked
//!   [`Incomplete::UnsupportedContentEncoding`] rather than decompressed; Envoy is expected to have decoded it first.
//! - **Binary file parts are not semantically parsed.** A multipart part that both carries a filename and declares an
//!   image, audio, video or octet-stream type gets raw-body scanning only.
//!
//! Every limit above produces an [`Incomplete`] reason except the first,
//! whose shape is simply not recognised. Whether an incomplete message is
//! rejected depends on the mode and policy pair; see [`crate::config`].

use std::{convert::Infallible, str};

use bytes::Bytes;
use serde::{
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserializer,
};

use crate::config::Config;

/// shortcut: stops at four layers; raise the bound if a supported app decodes more.
const MAX_PERCENT_DECODE_LAYERS: usize = 4;
/// Bytes per detector window: the largest input libperfusion accepts whole.
///
/// Scanning in byte windows rather than token windows keeps every detector
/// call library-equivalent: a window is a contiguous byte range, so a leading
/// string delimiter stays in frame and folding sees the same context the
/// library would.
const WINDOW_BYTES: usize = libperfusion::MAX_INPUT_LEN;
/// Overlap between consecutive windows.
///
/// A fingerprint spans at most five folded tokens and a token holds at most
/// `TOKEN_SIZE` (32) bytes, so this is far more than a payload straddling a
/// window boundary can need to land wholly inside one window.
const WINDOW_OVERLAP: usize = 4 * 1024;
/// Distance between consecutive window starts.
const WINDOW_STRIDE: usize = WINDOW_BYTES - WINDOW_OVERLAP;
/// Largest window that also gets token-anchored restarts.
///
/// A benign SQL prefix changes the folded state of the whole input, so a
/// payload after one can need a restart to surface. Restarts cost one
/// detector call each, so they are confined to windows small enough that the
/// extra calls stay cheap; larger inputs rely on the overlapping windows.
const RESTART_MAX_BYTES: usize = 8 * 1024;
/// Upper bound on token-anchored restarts per window.
const MAX_RESTARTS: usize = 16;
/// Upgrade tokens that really do switch the connection to a protocol whose
/// body this filter cannot inspect as a single HTTP message.
///
/// An upgrade the proxy has not negotiated is only a client proposal: Envoy
/// forwards an unmatched `Upgrade` as an ordinary request, which the upstream
/// then parses as ordinary HTTP. Treating any value as streaming let one
/// header turn off body inspection entirely.
const STREAMING_UPGRADES: [&[u8]; 3] = [b"websocket", b"h2c", b"connect"];

/// A reason a message could not be fully inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Incomplete {
    /// The extracted field count exceeded its limit.
    FieldLimit,
    /// An extracted field exceeded its byte limit.
    FieldTooLarge,
    /// The content type was malformed or ambiguous.
    MalformedContentType,
    /// A URL-encoded field had malformed percent escapes or invalid UTF-8.
    MalformedEncoding,
    /// A value still contains percent escapes beyond the inspection depth.
    EncodedValueRemains,
    /// The declared media type has no semantic parser.
    UnsupportedContentType,
    /// A content encoding remained after Envoy decompression.
    UnsupportedContentEncoding,
    /// The message body exceeded its configured limit.
    BodyTooLarge,
    /// A structured body was malformed or exceeded its parser budget.
    MalformedBody,
    /// The host did not provide the held body buffer.
    BodyUnavailable,
    /// The message uses an unbounded or opaque streaming protocol.
    StreamingBody,
}

impl Incomplete {
    /// Returns the request rejection status for this reason.
    pub(crate) fn status_code(self) -> u32 {
        match self {
            Self::UnsupportedContentType | Self::UnsupportedContentEncoding | Self::StreamingBody => 415,
            Self::MalformedContentType
            | Self::MalformedEncoding
            | Self::EncodedValueRemains
            | Self::MalformedBody
            | Self::BodyUnavailable => 400,
            Self::BodyTooLarge | Self::FieldLimit | Self::FieldTooLarge => 413,
        }
    }
}

/// The body parser selected from the HTTP content type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BodyFormat {
    /// Scan the body as raw bytes.
    Raw,
    /// Parse URL-encoded name/value pairs.
    UrlEncoded,
    /// Parse JSON strings and object keys.
    Json,
    /// Parse multipart fields using this boundary.
    Multipart(String),
    /// Scan raw bytes but mark semantic coverage incomplete.
    Unsupported,
}

/// Accumulates SQLi/XSS findings and enforces extraction budgets.
#[derive(Debug, Default)]
pub(crate) struct Inspection {
    /// Detector results for the message.
    findings: Findings,
    /// Number of decoded fields inspected in the current surface.
    ///
    /// Reset when body scanning starts so headers and body each get the full
    /// budget and neither can starve the other.
    fields: usize,
    /// Maximum number of decoded fields per surface.
    max_fields: usize,
    /// Maximum size of one decoded field.
    max_field_bytes: usize,
    /// Maximum JSON nesting level.
    max_json_depth: usize,
    /// First reason semantic coverage was incomplete.
    incomplete: Option<Incomplete>,
    /// Whether this message must bypass full-body buffering.
    streaming: bool,
}

/// Results from the two detectors provided by libperfusion.
#[derive(Debug, Default)]
struct Findings {
    /// Whether `SQLi` was found.
    sqli: bool,
    /// Whether XSS was found.
    xss: bool,
}

/// Runs `detect` over overlapping byte windows of the input.
///
/// Windows are anchored at byte offsets, starting at zero, so no leading byte
/// is ever skipped and every call sees a contiguous range the detector can
/// take whole. The number of calls is `O(len / WINDOW_STRIDE)` rather than
/// `O(tokens)`.
fn scan_overlapping_windows(bytes: &[u8], detect: impl Fn(&[u8]) -> bool) -> bool {
    if bytes.is_empty() {
        return false;
    }

    let mut start = 0_usize;
    loop {
        let end = start.saturating_add(WINDOW_BYTES).min(bytes.len());
        let Some(window) = bytes.get(start..end) else {
            return false;
        };
        if detect(window) {
            return true;
        }
        if end == bytes.len() {
            return false;
        }
        start = start.saturating_add(WINDOW_STRIDE);
    }
}

/// Reports whether any window of `bytes` reads as `SQLi`.
///
/// Each window is first tested whole, which reproduces the verdict
/// `libperfusion::sqli()` would give for that range, and then from a bounded
/// set of token-anchored restarts so a benign SQL prefix cannot mask a
/// payload that follows it.
fn has_sqli_in_overlapping_windows(bytes: &[u8]) -> bool {
    scan_overlapping_windows(bytes, |window| {
        libperfusion::sqli(window).is_some() || has_sqli_from_token_restart(window)
    })
}

/// Reports whether any window of `bytes` reads as XSS.
///
/// `xss_with_limit` skips libperfusion's own input-length guard, so bounding
/// the scan here is what keeps a large body from being scanned unbounded.
fn has_xss_in_overlapping_windows(bytes: &[u8]) -> bool {
    scan_overlapping_windows(bytes, |window| libperfusion::xss_with_limit(window, window.len()))
}

/// Re-tests a window from a bounded, evenly spread set of token starts.
///
/// Each restart backs up over an opening string delimiter so the quote stays
/// in frame: `SqlToken::pos()` points at a string's body, one byte past the
/// delimiter that opened it.
fn has_sqli_from_token_restart(window: &[u8]) -> bool {
    if window.len() > RESTART_MAX_BYTES {
        return false;
    }

    let tokens = tokenizer(window).count();
    if tokens < 2 {
        return false;
    }
    let step = tokens.div_ceil(MAX_RESTARTS).max(1);

    tokenizer(window)
        .enumerate()
        .skip(1)
        .filter(|(index, _)| index % step == 0)
        .take(MAX_RESTARTS)
        .any(|(_, token)| {
            let start = token.pos().saturating_sub(usize::from(token.string_open().is_some()));
            window
                .get(start..)
                .is_some_and(|tail| libperfusion::sqli(tail).is_some())
        })
}

/// Builds the tokenizer used to locate restart offsets.
fn tokenizer(window: &[u8]) -> libperfusion::SqlTokenizer<'_> {
    libperfusion::SqlTokenizer::new(window, libperfusion::Quote::None, libperfusion::Dialect::Ansi)
}

impl Inspection {
    /// Creates a scanner using the configured field budgets.
    pub(crate) fn new(config: &Config) -> Self {
        Self {
            max_fields: config.max_fields,
            max_field_bytes: config.max_field_bytes,
            max_json_depth: config.max_json_depth,
            ..Self::default()
        }
    }

    /// Reports whether `SQLi` was found.
    pub(crate) fn has_sqli(&self) -> bool {
        self.findings.sqli
    }

    /// Reports whether XSS was found.
    pub(crate) fn has_xss(&self) -> bool {
        self.findings.xss
    }

    /// Returns the first incomplete-coverage reason, if any.
    pub(crate) fn incomplete(&self) -> Option<Incomplete> {
        self.incomplete
    }

    /// Reports whether this message must continue without full-body buffering.
    pub(crate) fn is_streaming(&self) -> bool {
        self.streaming
    }

    /// Scans headers and returns the body parser inferred from content type.
    pub(crate) fn headers(&mut self, headers: &[(String, Vec<u8>)]) -> BodyFormat {
        let mut content_type = None;

        for (name, value) in headers {
            self.scan_field(name.as_bytes());
            self.scan_field(value);

            if (name.eq_ignore_ascii_case(":method") && value.eq_ignore_ascii_case(b"CONNECT"))
                || (name.eq_ignore_ascii_case(":status") && value.as_slice() == b"101")
            {
                self.mark_streaming();
            } else if name.eq_ignore_ascii_case("upgrade") {
                let token = trim_ascii(value);
                if STREAMING_UPGRADES
                    .iter()
                    .any(|protocol| token.eq_ignore_ascii_case(protocol))
                {
                    self.mark_streaming();
                } else {
                    // The body still has to be inspected: the upstream will
                    // read it as ordinary HTTP whatever this header claims.
                    self.mark_incomplete(Incomplete::MalformedContentType);
                }
            } else if name.eq_ignore_ascii_case(":path") {
                self.scan_path(value);
                self.scan_query(value);
            } else if name.eq_ignore_ascii_case("cookie") || name.eq_ignore_ascii_case("set-cookie") {
                self.scan_cookie(value);
            } else if name.eq_ignore_ascii_case("content-type") {
                if content_type.replace(value.as_slice()).is_some() {
                    self.mark_incomplete(Incomplete::MalformedContentType);
                }
            } else if name.eq_ignore_ascii_case("content-encoding") && !value.eq_ignore_ascii_case(b"identity") {
                self.mark_incomplete(Incomplete::UnsupportedContentEncoding);
            }
        }

        match content_type {
            Some(value) => self.body_format(value),
            None => BodyFormat::Raw,
        }
    }

    /// Scans raw body bytes and extracts supported structured values.
    ///
    /// The raw bytes are always scanned before dispatching to a format
    /// parser. That unconditional pass is what makes the filter resistant to
    /// content-type confusion, so it must not be made conditional on the
    /// selected format.
    pub(crate) fn body(&mut self, bytes: Vec<u8>, format: &BodyFormat) {
        // Headers and body draw on separate field budgets. Sharing one
        // counter let padding headers exhaust it before the body parser ran,
        // which silently hid every structured field in the body.
        self.fields = 0;
        self.scan_bytes(&bytes);
        self.scan_percent_encoded_views(&bytes);
        self.scan_normalized_view(&bytes);

        match format {
            BodyFormat::Raw | BodyFormat::Unsupported => {},
            BodyFormat::UrlEncoded => {
                self.scan_form_fields(&bytes);
            },
            BodyFormat::Json => self.scan_json(&bytes),
            BodyFormat::Multipart(boundary) => self.scan_multipart(bytes, boundary),
        }
    }

    /// Scans trailers as additional header fields.
    pub(crate) fn trailers(&mut self, headers: &[(String, Vec<u8>)]) {
        for (name, value) in headers {
            self.scan_field(name.as_bytes());
            self.scan_field(value);
            if name.eq_ignore_ascii_case("cookie") || name.eq_ignore_ascii_case("set-cookie") {
                self.scan_cookie(value);
            }
        }
    }

    /// Records the first reason full inspection was unavailable.
    pub(crate) fn mark_incomplete(&mut self, reason: Incomplete) {
        if self.incomplete.is_none() {
            self.incomplete = Some(reason);
        }
    }

    /// Marks an unbounded protocol whose complete body cannot be buffered.
    fn mark_streaming(&mut self) {
        self.streaming = true;
        self.mark_incomplete(Incomplete::StreamingBody);
    }

    /// Counts and scans one extracted field.
    fn scan_field(&mut self, bytes: &[u8]) {
        if self.fields >= self.max_fields {
            self.mark_incomplete(Incomplete::FieldLimit);
            return;
        }
        self.fields += 1;
        self.scan_value(bytes);
    }

    /// Scans field bytes and decoded views subject to the per-field byte bound.
    fn scan_value(&mut self, bytes: &[u8]) {
        if bytes.len() > self.max_field_bytes {
            self.mark_incomplete(Incomplete::FieldTooLarge);
            // Coverage is genuinely partial, but padding a parameter past the
            // limit must not buy complete invisibility. Inspect a bounded
            // head and tail; total cost stays bounded by max_field_bytes.
            let half = self.max_field_bytes / 2;
            if let Some(head) = bytes.get(..half) {
                self.scan_bytes(head);
                self.scan_percent_encoded_views(head);
            }
            if let Some(tail) = bytes.get(bytes.len().saturating_sub(half)..) {
                self.scan_bytes(tail);
                self.scan_percent_encoded_views(tail);
            }
            return;
        }
        self.scan_bytes(bytes);
        self.scan_percent_encoded_views(bytes);
        self.scan_normalized_view(bytes);
    }

    /// Runs both detectors over this byte slice in bounded overlapping windows.
    fn scan_bytes(&mut self, bytes: &[u8]) {
        self.findings.sqli |= has_sqli_in_overlapping_windows(bytes);
        self.findings.xss |= has_xss_in_overlapping_windows(bytes);
    }

    /// Scans a view with NULs removed and Unicode whitespace folded to space.
    ///
    /// libperfusion keeps upstream's byte-level behaviour: a NUL inside a SQL
    /// keyword defeats the lookup, and UTF-8 NBSP (`C2 A0`) is not
    /// whitespace although the Latin-1 byte `A0` is. Neither parses on a
    /// mainstream engine directly, but middleware that strips NULs or applies
    /// Unicode normalisation before the query is built closes that gap for
    /// the attacker. Scanning a normalised view costs one extra pass and
    /// closes the whole differential class.
    fn scan_normalized_view(&mut self, bytes: &[u8]) {
        let Some(view) = normalize_separators(bytes) else {
            return;
        };
        self.scan_bytes(&view);
    }

    /// Scans bounded percent-decoded views while retaining the original bytes.
    fn scan_percent_encoded_views(&mut self, bytes: &[u8]) {
        if !contains_percent_escape(bytes) {
            return;
        }

        let mut decoded = Vec::new();
        let mut scratch = Vec::new();
        let mut input = bytes;
        for _ in 0..MAX_PERCENT_DECODE_LAYERS {
            decode_percent_escapes(input, &mut scratch);
            // A layer that reproduced its own input cannot reveal anything a
            // further layer would, so stop instead of rescanning it.
            //
            // Note the escape *count* is deliberately not used as a progress
            // signal: "%253C" decodes to "%3C", which is genuine progress
            // with the count unchanged, so requiring a strict decrease would
            // abandon ordinary double-encoded input one layer early.
            if scratch == input {
                return;
            }
            self.scan_bytes(&scratch);
            std::mem::swap(&mut decoded, &mut scratch);
            input = &decoded;
            if !contains_percent_escape(input) {
                return;
            }
        }
        self.mark_incomplete(Incomplete::EncodedValueRemains);
    }

    /// Decodes and scans query parameters from a request path.
    fn scan_query(&mut self, path: &[u8]) {
        let Some(query_start) = path.iter().position(|byte| *byte == b'?') else {
            return;
        };
        let query = path.get(query_start.saturating_add(1)..).unwrap_or_default();
        self.scan_form_fields(query);
    }

    /// Marks malformed percent escapes in the URI path incomplete.
    fn scan_path(&mut self, path: &[u8]) {
        let path_end = path.iter().position(|byte| *byte == b'?').unwrap_or(path.len());
        let Some(path) = path.get(..path_end) else {
            self.mark_incomplete(Incomplete::MalformedEncoding);
            return;
        };
        if path.contains(&b'%') && !has_valid_percent_escapes(path) {
            self.mark_incomplete(Incomplete::MalformedEncoding);
        }
    }

    /// Decodes URL-encoded fields and records malformed encodings.
    fn scan_form_fields(&mut self, bytes: &[u8]) {
        if !has_valid_percent_escapes(bytes) {
            self.mark_incomplete(Incomplete::MalformedEncoding);
        }
        for (name, value) in form_urlencoded::parse(bytes) {
            if self.fields >= self.max_fields {
                self.mark_incomplete(Incomplete::FieldLimit);
                break;
            }
            if name.contains('\u{fffd}') || value.contains('\u{fffd}') {
                self.mark_incomplete(Incomplete::MalformedEncoding);
            }
            self.scan_field(name.as_bytes());
            self.scan_field(value.as_bytes());
        }
    }

    /// Scans semicolon-separated cookie names and values.
    fn scan_cookie(&mut self, cookie: &[u8]) {
        for pair in cookie.split(|byte| *byte == b';') {
            if self.fields >= self.max_fields {
                self.mark_incomplete(Incomplete::FieldLimit);
                break;
            }
            let pair = trim_ascii(pair);
            let mut parts = pair.splitn(2, |byte| *byte == b'=');
            let name = trim_ascii(parts.next().unwrap_or_default());
            let value = trim_ascii(parts.next().unwrap_or_default());
            self.scan_field(name);
            self.scan_field(value);
        }
    }

    /// Selects a parser and marks unsupported structured types incomplete.
    fn body_format(&mut self, value: &[u8]) -> BodyFormat {
        let Ok(content_type) = str::from_utf8(value) else {
            self.mark_incomplete(Incomplete::MalformedContentType);
            return BodyFormat::Raw;
        };
        let media_type = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();

        if media_type == "application/x-www-form-urlencoded" {
            BodyFormat::UrlEncoded
        } else if media_type == "application/json"
            || media_type == "text/json"
            || media_type == "text/x-json"
            || media_type.ends_with("+json")
        {
            BodyFormat::Json
        } else if media_type == "multipart/form-data" {
            if let Ok(boundary) = multer::parse_boundary(content_type) {
                BodyFormat::Multipart(boundary)
            } else {
                self.mark_incomplete(Incomplete::MalformedContentType);
                BodyFormat::Raw
            }
        } else if media_type == "application/grpc" || media_type.starts_with("application/grpc+") {
            self.mark_streaming();
            self.mark_incomplete(Incomplete::UnsupportedContentType);
            BodyFormat::Unsupported
        } else if media_type == "text/event-stream" {
            self.mark_streaming();
            BodyFormat::Raw
        } else if media_type == "application/octet-stream"
            || media_type == "application/javascript"
            || media_type == "application/ecmascript"
            || media_type.starts_with("text/") && media_type != "text/xml"
            || media_type.starts_with("image/")
            || media_type.starts_with("audio/")
            || media_type.starts_with("video/")
        {
            BodyFormat::Raw
        } else if media_type == "text/xml"
            || media_type == "application/xml"
            || media_type.starts_with("application/")
            || media_type.starts_with("multipart/")
        {
            self.mark_incomplete(Incomplete::UnsupportedContentType);
            BodyFormat::Unsupported
        } else {
            BodyFormat::Raw
        }
    }

    /// Decodes JSON strings and keys without discarding duplicate object keys.
    fn scan_json(&mut self, bytes: &[u8]) {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let result = JsonScan {
            inspection: self,
            depth: 0,
        }
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end());
        if result.is_err() {
            self.mark_incomplete(Incomplete::MalformedBody);
        }
    }

    /// Parses multipart framing and scans names and bounded part bodies.
    ///
    /// shortcut: file parts get raw-body scanning only; add a bounded format parser if applications decode uploads.
    fn scan_multipart(&mut self, bytes: Vec<u8>, boundary: &str) {
        let whole_stream_limit = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let content = Bytes::from(bytes);
        let stream = futures::stream::once(async move { Ok::<Bytes, Infallible>(content) });
        let constraints = multer::Constraints::new().size_limit(
            multer::SizeLimit::new()
                .whole_stream(whole_stream_limit)
                // Bound each part by configuration rather than by the length
                // of the body being parsed, which no part can ever exceed and
                // so disabled the constraint entirely.
                .per_field(u64::try_from(self.max_field_bytes).unwrap_or(u64::MAX)),
        );

        // The stream is a single already-materialised chunk, so this future
        // cannot pend. That matters: the Wasm VM is single-threaded with no
        // reactor, so a genuinely streaming source here would deadlock the
        // worker thread permanently.
        let parsed = futures::executor::block_on(async {
            let mut multipart = multer::Multipart::with_constraints(stream, boundary, constraints);
            let mut field_count = 0_usize;
            let mut field_body = Vec::new();
            while let Some(mut field) = multipart
                .next_field()
                .await
                .map_err(|error| size_aware_reason(&error))?
            {
                field_count += 1;
                if field_count > self.max_fields {
                    self.mark_incomplete(Incomplete::FieldLimit);
                    break;
                }
                if let Some(name) = field.name() {
                    self.scan_field(name.as_bytes());
                } else {
                    self.mark_incomplete(Incomplete::MalformedBody);
                }
                let part_type = field.content_type();
                // `filename` is attacker-controlled, so keying "do not parse
                // this" on its presence alone let `; filename="x"` on an
                // ordinary text field downgrade it to raw-only scanning.
                // Skip the body only when the part also declares a type that
                // is genuinely binary.
                let declared_binary = part_type.is_some_and(|content_type| {
                    let media_type = content_type.essence_str();
                    media_type.starts_with("image/")
                        || media_type.starts_with("audio/")
                        || media_type.starts_with("video/")
                        || media_type == "application/octet-stream"
                });
                let is_file = field.file_name().is_some() && declared_binary;
                let json_part = part_type.is_some_and(|content_type| {
                    let media_type = content_type.essence_str();
                    media_type == "application/json"
                        || media_type.starts_with("application/") && media_type.ends_with("+json")
                });
                let form_part = part_type
                    .is_some_and(|content_type| content_type.essence_str() == "application/x-www-form-urlencoded");
                let unsupported_part = part_type.is_some_and(|content_type| {
                    let media_type = content_type.essence_str();
                    (media_type.starts_with("application/")
                        && !json_part
                        && !form_part
                        && !matches!(
                            media_type,
                            "application/octet-stream" | "application/javascript" | "application/ecmascript"
                        ))
                        || media_type == "text/xml"
                        || media_type.starts_with("multipart/")
                });
                if let Some(filename) = field.file_name() {
                    self.scan_field(filename.as_bytes());
                }
                field_body.clear();
                let mut field_too_large = false;
                while let Some(chunk) = field.chunk().await.map_err(|error| size_aware_reason(&error))? {
                    if is_file || field_too_large || self.fields >= self.max_fields {
                        continue;
                    }
                    let remaining = self.max_field_bytes.saturating_sub(field_body.len());
                    if chunk.len() > remaining {
                        self.mark_incomplete(Incomplete::FieldTooLarge);
                        field_too_large = true;
                        continue;
                    }
                    field_body.extend_from_slice(&chunk);
                }
                if !is_file && !field_too_large {
                    if json_part {
                        self.scan_json(&field_body);
                    } else if form_part {
                        self.scan_form_fields(&field_body);
                    } else {
                        if unsupported_part {
                            self.mark_incomplete(Incomplete::UnsupportedContentType);
                        }
                        self.scan_field(&field_body);
                    }
                }
            }
            Ok::<usize, Incomplete>(field_count)
        });

        match parsed {
            Err(reason) => self.mark_incomplete(reason),
            Ok(0) => self.mark_incomplete(Incomplete::MalformedBody),
            Ok(_) => {},
        }
    }
}

/// Returns whether each percent sign begins a two-digit hexadecimal escape.
fn has_valid_percent_escapes(bytes: &[u8]) -> bool {
    let mut index = 0;
    while let Some(byte) = bytes.get(index) {
        if *byte == b'%' {
            let Some(high) = bytes.get(index.saturating_add(1)).copied() else {
                return false;
            };
            let Some(low) = bytes.get(index.saturating_add(2)).copied() else {
                return false;
            };
            if hex_value(high).is_none() || hex_value(low).is_none() {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

/// Maps a multipart parse failure to the reason that describes it.
///
/// `per_field` is bound to `max_field_bytes`, so multer refuses an oversized
/// part before it is buffered. That is a size refusal, not malformed
/// framing, and it carries a different status code.
fn size_aware_reason(error: &multer::Error) -> Incomplete {
    match *error {
        multer::Error::FieldSizeExceeded { .. } | multer::Error::StreamSizeExceeded { .. } => Incomplete::FieldTooLarge,
        _ => Incomplete::MalformedBody,
    }
}

/// Removes NULs and folds Unicode whitespace to a space.
///
/// Returns `None` when the input holds neither, so the common case costs one
/// scan and no allocation. The folded set is the Unicode whitespace a
/// normalising middleware is liable to turn into an ASCII space: `U+00A0`,
/// `U+1680`, `U+2000`-`U+200A`, `U+2028`, `U+2029`, `U+202F`, `U+205F` and
/// `U+3000`.
fn normalize_separators(bytes: &[u8]) -> Option<Vec<u8>> {
    if !bytes.iter().any(|byte| matches!(byte, 0 | 0xC2 | 0xE1 | 0xE2 | 0xE3)) {
        return None;
    }

    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut changed = false;
    while let Some(&byte) = bytes.get(index) {
        if byte == 0 {
            index += 1;
            changed = true;
            continue;
        }
        let rest = bytes.get(index..).unwrap_or_default();
        if let Some(width) = unicode_space_width(rest) {
            out.push(b' ');
            index += width;
            changed = true;
            continue;
        }
        out.push(byte);
        index += 1;
    }
    changed.then_some(out)
}

/// Returns the encoded length of a Unicode whitespace character at the front.
fn unicode_space_width(rest: &[u8]) -> Option<usize> {
    match *rest.first()? {
        0xC2 if rest.get(1) == Some(&0xA0) => Some(2),
        0xE1 if rest.get(1) == Some(&0x9A) && rest.get(2) == Some(&0x80) => Some(3),
        0xE2 if rest.get(1) == Some(&0x80) => match rest.get(2)? {
            0x80..=0x8A | 0xA8 | 0xA9 | 0xAF => Some(3),
            _ => None,
        },
        0xE2 if rest.get(1) == Some(&0x81) && rest.get(2) == Some(&0x9F) => Some(3),
        0xE3 if rest.get(1) == Some(&0x80) && rest.get(2) == Some(&0x80) => Some(3),
        _ => None,
    }
}

/// Returns whether a byte slice contains a valid percent escape.
fn contains_percent_escape(bytes: &[u8]) -> bool {
    bytes.windows(3).any(|escape| {
        escape.first() == Some(&b'%')
            && escape.get(1).and_then(|byte| hex_value(*byte)).is_some()
            && escape.get(2).and_then(|byte| hex_value(*byte)).is_some()
    })
}

/// Decodes valid percent escapes once and leaves other bytes unchanged.
fn decode_percent_escapes(bytes: &[u8], decoded: &mut Vec<u8>) {
    decoded.clear();
    decoded.reserve(bytes.len());
    let mut index = 0;
    while let Some(byte) = bytes.get(index) {
        if *byte == b'%' {
            if let (Some(high), Some(low)) = (
                bytes.get(index.saturating_add(1)).and_then(|byte| hex_value(*byte)),
                bytes.get(index.saturating_add(2)).and_then(|byte| hex_value(*byte)),
            ) {
                decoded.push(high << 4 | low);
                index += 3;
                continue;
            }
        }
        decoded.push(*byte);
        index += 1;
    }
}

/// Returns a hexadecimal digit's numeric value.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Trims HTTP whitespace from both ends of a byte slice.
fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = value.get(1..).unwrap_or_default();
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = value.get(..value.len().saturating_sub(1)).unwrap_or_default();
    }
    value
}

/// Visits JSON values while carrying the inspection budget.
struct JsonScan<'a> {
    /// The active message inspection.
    inspection: &'a mut Inspection,
    /// Current JSON nesting depth.
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for JsonScan<'_> {
    type Value = ();

    /// Recursively visits one JSON value.
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonVisitor {
            inspection: self.inspection,
            depth: self.depth,
        })
    }
}

/// Inspects every JSON string and object member as it is deserialized.
struct JsonVisitor<'a> {
    /// The active message inspection.
    inspection: &'a mut Inspection,
    /// Current JSON nesting depth.
    depth: usize,
}

impl<'de> Visitor<'de> for JsonVisitor<'_> {
    type Value = ();

    /// Describes the values accepted by this visitor.
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    /// Scans a borrowed JSON string.
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.inspection.scan_field(v.as_bytes());
        Ok(())
    }

    /// Scans an owned JSON string through the borrowed-string path.
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v)
    }

    /// Ignores booleans because they contain no string payload.
    fn visit_bool<E>(self, _v: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    /// Ignores signed numbers because they contain no string payload.
    fn visit_i64<E>(self, _v: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    /// Ignores unsigned numbers because they contain no string payload.
    fn visit_u64<E>(self, _v: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    /// Ignores floating-point numbers because they contain no string payload.
    fn visit_f64<E>(self, _v: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    /// Accepts JSON null.
    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    /// Visits array elements recursively within the nesting limit.
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if self.depth >= self.inspection.max_json_depth {
            return Err(serde::de::Error::custom("JSON nesting limit exceeded"));
        }
        while seq
            .next_element_seed(JsonScan {
                inspection: self.inspection,
                depth: self.depth.saturating_add(1),
            })?
            .is_some()
        {}
        Ok(())
    }

    /// Visits all JSON members, including repeated keys.
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.depth >= self.inspection.max_json_depth {
            return Err(serde::de::Error::custom("JSON nesting limit exceeded"));
        }
        while map
            .next_key_seed(JsonKeyScan {
                inspection: &mut *self.inspection,
            })?
            .is_some()
        {
            map.next_value_seed(JsonScan {
                inspection: self.inspection,
                depth: self.depth.saturating_add(1),
            })?;
        }
        Ok(())
    }
}

/// Scans JSON object keys while serde borrows unescaped strings from the body.
struct JsonKeyScan<'a> {
    /// The active message inspection.
    inspection: &'a mut Inspection,
}

impl<'de> DeserializeSeed<'de> for JsonKeyScan<'_> {
    type Value = ();

    /// Deserializes one object key without allocating a `String` for borrowed keys.
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(JsonKeyVisitor {
            inspection: self.inspection,
        })
    }
}

/// Inspects one decoded JSON object key.
struct JsonKeyVisitor<'a> {
    /// The active message inspection.
    inspection: &'a mut Inspection,
}

impl<'de> Visitor<'de> for JsonKeyVisitor<'_> {
    type Value = ();

    /// Describes the object key accepted by this visitor.
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON object key")
    }

    /// Scans a borrowed object key.
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.inspection.scan_field(v.as_bytes());
        Ok(())
    }

    /// Scans a key borrowed directly from the JSON body.
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(v)
    }

    /// Scans an owned key when JSON escapes require decoding it.
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v)
    }
}

#[cfg(test)]
/// Inspection tests for decoded and bounded HTTP inputs.
mod tests {
    use super::Inspection;
    use crate::{config::Config, inspect::Incomplete};

    /// Builds byte-valued HTTP headers for scanner tests.
    fn headers(entries: &[(&str, &str)]) -> Vec<(String, Vec<u8>)> {
        entries
            .iter()
            .map(|(name, value)| (String::from(*name), value.as_bytes().to_vec()))
            .collect()
    }

    /// Copies a static test fixture into the SDK's owned body type.
    fn scan_body(inspection: &mut Inspection, bytes: &[u8], format: &super::BodyFormat) {
        inspection.body(bytes.to_vec(), format);
    }

    /// Checks decoded query and form representations.
    #[test]
    fn scans_encoded_query_and_form_fields() {
        let config = Config::default();
        let mut inspection = Inspection::new(&config);
        let format = inspection.headers(&headers(&[
            (
                ":path",
                "/?value=%3Cscript%3Ealert(1)%3C%2Fscript%3E&query=1%27%20OR%20%271%27=%271",
            ),
            ("cookie", "safe=1; next=benign"),
            ("content-type", "application/x-www-form-urlencoded"),
        ]));

        scan_body(&mut inspection, b"comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E", &format);

        assert!(inspection.has_xss(), "decoded query and form XSS must be found");
        assert!(inspection.has_sqli(), "decoded query SQLi must be found");
        assert_eq!(inspection.incomplete(), None, "supported form must be complete");
    }

    /// Marks malformed form escapes and invalid decoded UTF-8 incomplete.
    #[test]
    fn reports_malformed_url_encoding() {
        let config = Config::default();
        let mut inspection = Inspection::new(&config);
        let format = inspection.headers(&headers(&[
            (":path", "/?bad=%ZZ"),
            ("content-type", "application/x-www-form-urlencoded"),
        ]));
        scan_body(&mut inspection, b"bad=%E0%80", &format);

        assert_eq!(inspection.incomplete(), Some(Incomplete::MalformedEncoding));
    }

    /// Scans encoded paths through the limit and marks malformed or excess layers incomplete.
    #[test]
    fn scans_encoded_path_once_and_reports_remaining_or_malformed_escapes() {
        let config = Config::default();
        let mut inspection = Inspection::new(&config);
        inspection.headers(&headers(&[(":path", "/%3Cscript%3Ealert(1)%3C/script%3E")]));
        assert!(inspection.has_xss(), "encoded path XSS must be inspected");

        let mut nested = Inspection::new(&config);
        nested.headers(&headers(&[(":path", "/%253Cscript%253E")]));
        assert!(nested.has_xss(), "nested path XSS must be inspected");
        assert_eq!(nested.incomplete(), None, "covered layers are complete");

        let mut excessive = Inspection::new(&config);
        excessive.headers(&headers(&[(":path", "/%252525253Cscript%252525253E")]));
        assert_eq!(excessive.incomplete(), Some(Incomplete::EncodedValueRemains));

        let mut malformed = Inspection::new(&config);
        malformed.headers(&headers(&[(":path", "/%ZZ")]));
        assert_eq!(malformed.incomplete(), Some(Incomplete::MalformedEncoding));
    }

    /// Scans encoded cookies, response cookies and arbitrary headers.
    #[test]
    fn scans_percent_encoded_cookie_and_header_values() {
        let config = Config::default();
        let mut inspection = Inspection::new(&config);
        inspection.headers(&headers(&[
            ("cookie", "payload=%253Cscript%253Ealert(1)%253C%252Fscript%253E"),
            ("set-cookie", "preview=%253Cscript%253Ealert(1)%253C%252Fscript%253E"),
            ("x-untrusted", "query=1%2527%2520OR%2520%25271%2527=%25271"),
        ]));

        assert!(inspection.has_xss(), "encoded cookies must be inspected");
        assert!(inspection.has_sqli(), "encoded header SQLi must be inspected");
        assert_eq!(inspection.incomplete(), None, "covered layers are complete");
    }

    /// Scans percent-encoded raw bodies through the configured layer bound.
    #[test]
    fn scans_percent_encoded_raw_body() {
        let config = Config::default();
        let mut inspection = Inspection::new(&config);
        let format = inspection.headers(&headers(&[("content-type", "text/plain")]));
        scan_body(
            &mut inspection,
            b"%253Cscript%253Ealert(1)%253C%252Fscript%253E",
            &format,
        );

        assert!(inspection.has_xss(), "encoded raw-body XSS must be inspected");
        assert_eq!(inspection.incomplete(), None, "covered layers are complete");
    }

    /// Payloads whose first byte is the string delimiter that opens the injection.
    ///
    /// These are the canonical boolean-blind strings. An earlier token-anchored
    /// scanner dropped the opening quote, because a string token's position is
    /// its body, so none of them were detected.
    const LEADING_QUOTE_PAYLOADS: [&[u8]; 4] = [b"' OR ''='", b"' OR 'x'='x", b"\" OR \"\"=\"", b"'IS UNIONb<NULL"];

    /// Detects leading-delimiter `SQLi` in headers, raw bodies and multipart parts.
    #[test]
    fn detects_leading_quote_payloads_on_every_surface() {
        let config = Config::default();

        for payload in LEADING_QUOTE_PAYLOADS {
            let text = String::from_utf8_lossy(payload).into_owned();

            let mut header = Inspection::new(&config);
            header.headers(&headers(&[("x-search", &text)]));
            assert!(
                header.has_sqli(),
                "header value starting with a delimiter must be detected: {text:?}"
            );

            let mut raw = Inspection::new(&config);
            let format = raw.headers(&headers(&[("content-type", "text/plain")]));
            scan_body(&mut raw, payload, &format);
            assert!(
                raw.has_sqli(),
                "raw body starting with a delimiter must be detected: {text:?}"
            );

            let mut multipart = Inspection::new(&config);
            let format = multipart.headers(&headers(&[("content-type", "multipart/form-data; boundary=BOUNDARY")]));
            let mut body = b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n".to_vec();
            body.extend_from_slice(payload);
            body.extend_from_slice(b"\r\n--BOUNDARY--\r\n");
            scan_body(&mut multipart, &body, &format);
            assert!(
                multipart.has_sqli(),
                "multipart part starting with a delimiter must be detected: {text:?}"
            );
        }
    }

    /// The window scanner must never be less sensitive than the library it wraps.
    ///
    /// Holding this property is what keeps the filter's verdict equivalent to
    /// `libperfusion::sqli()` for every input the library accepts whole.
    #[test]
    fn window_scan_is_never_weaker_than_whole_input_sqli() {
        let mut corpus: Vec<&[u8]> = vec![
            b"1' OR '1'='1",
            b"1 UNION SELECT password FROM users",
            b"admin'--",
            b"1; EXEC xp_cmdshell('dir')",
            b"1' AND substr(a,1,1)='a",
            // Inputs the report recorded as lost by the token-window scanner.
            b"'--FROM&& 1bCAST*LIKE,1 ",
            b"NOT*1,|| INT<passwordLIKEANDCASTNULL/ISBETWEENIS --, '=' WHERE/",
            b"1,users)*INTWHERE1users IS - UNIONWHERE|| ",
            b"\"IS UNIONb<NULL",
            b"BETWEEN ||EXECpassword+ */ OR)INTSELECT <*/ INTb<#\"=AS\"\"/*&&",
        ];
        corpus.extend_from_slice(&LEADING_QUOTE_PAYLOADS);

        for case in corpus {
            if case.len() <= libperfusion::MAX_INPUT_LEN && libperfusion::sqli(case).is_some() {
                assert!(
                    super::has_sqli_in_overlapping_windows(case),
                    "window scan lost a detection the library makes: {:?}",
                    String::from_utf8_lossy(case)
                );
            }
        }
    }

    /// Keeps whole-message inspection off the pathological per-token path.
    ///
    /// This is a tripwire for order-of-magnitude regressions, not a
    /// measurement: the bound is far above the expected cost so it stays
    /// stable on a loaded or unoptimised builder.
    #[test]
    fn inspects_dense_token_body_within_time_budget() {
        let config = Config::default();
        let mut inspection = Inspection::new(&config);
        let format = inspection.headers(&headers(&[("content-type", "text/plain")]));
        let body = vec![b','; 1024 * 1024];

        let started = std::time::Instant::now();
        scan_body(&mut inspection, &body, &format);
        let elapsed = started.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "1 MiB of dense tokens took {elapsed:?}; the per-token scanner cost ~221 ms in release"
        );
    }

    /// Inspects bodies whose request carried an upgrade the proxy never negotiated.
    #[test]
    fn inspects_body_unless_the_upgrade_is_a_known_streaming_protocol() {
        let config = Config::default();
        let payload = b"u=1%27+OR+%271%27%3D%271+UNION+SELECT+password+FROM+users";

        for upgrade in ["bogus", "", "anything-at-all"] {
            let mut inspection = Inspection::new(&config);
            let format = inspection.headers(&headers(&[
                (":method", "POST"),
                ("upgrade", upgrade),
                ("content-type", "application/x-www-form-urlencoded"),
            ]));
            assert!(
                !inspection.is_streaming(),
                "an unnegotiated upgrade {upgrade:?} must not skip body inspection"
            );

            scan_body(&mut inspection, payload, &format);
            assert!(
                inspection.has_sqli(),
                "body SQLi must be found despite Upgrade: {upgrade:?}"
            );
        }

        for upgrade in ["websocket", "WebSocket", " h2c "] {
            let mut inspection = Inspection::new(&config);
            inspection.headers(&headers(&[(":method", "GET"), ("upgrade", upgrade)]));
            assert!(
                inspection.is_streaming(),
                "a real streaming upgrade {upgrade:?} must bypass full-body buffering"
            );
        }
    }

    /// Matches the switching-protocols status exactly rather than by prefix.
    #[test]
    fn treats_only_an_exact_101_status_as_streaming() {
        let config = Config::default();

        let mut switching = Inspection::new(&config);
        switching.headers(&headers(&[(":status", "101")]));
        assert!(switching.is_streaming(), "101 switches protocols");

        let mut other = Inspection::new(&config);
        other.headers(&headers(&[(":status", "1015")]));
        assert!(!other.is_streaming(), "1015 is not a switching-protocols status");
    }

    /// Keeps the body parser funded when headers consume their whole budget.
    #[test]
    fn header_flood_does_not_blind_the_body_parser() {
        let config = Config {
            max_fields: 8,
            ..Config::default()
        };
        let mut inspection = Inspection::new(&config);

        let mut entries = vec![(String::from("content-type"), b"application/json".to_vec())];
        for index in 0..32 {
            entries.push((format!("x-pad-{index}"), b"pad".to_vec()));
        }
        let format = inspection.headers(&entries);

        // The attack exists only after JSON unescaping, so the raw pass
        // cannot see it and only the body parser can.
        scan_body(&mut inspection, br#"{"u":"<script>alert(1)</script>"}"#, &format);

        assert!(
            inspection.has_xss(),
            "a JSON-escaped payload must stay visible behind a header flood"
        );
    }

    /// Parses JSON bodies declared with the text/json family.
    #[test]
    fn treats_text_json_as_a_json_body() {
        let config = Config::default();

        for media_type in ["text/json", "text/x-json", "model/gltf+json"] {
            let mut inspection = Inspection::new(&config);
            let format = inspection.headers(&headers(&[("content-type", media_type)]));
            assert_eq!(
                format,
                super::BodyFormat::Json,
                "{media_type} should select the JSON parser"
            );

            scan_body(&mut inspection, br#"{"u":"<script>alert(1)</script>"}"#, &format);
            assert!(inspection.has_xss(), "{media_type} bodies must be JSON-decoded");
        }
    }

    /// Inspects a bounded head and tail of a field that exceeds its byte bound.
    #[test]
    fn oversized_fields_are_truncated_not_discarded() {
        let config = Config {
            max_field_bytes: 64,
            ..Config::default()
        };
        let mut inspection = Inspection::new(&config);
        let format = inspection.headers(&headers(&[("content-type", "application/json")]));

        let mut value = "a".repeat(200);
        value.push_str("1 UNION SELECT password FROM users");
        let body = format!("{{\"u\":\"{value}\"}}");
        scan_body(&mut inspection, body.as_bytes(), &format);

        assert!(
            inspection.has_sqli(),
            "padding a field past the limit must not hide its contents"
        );
        assert_eq!(
            inspection.incomplete(),
            Some(Incomplete::FieldTooLarge),
            "coverage is still partial and must be reported"
        );
    }

    /// Scans text multipart parts even when they carry a filename.
    #[test]
    fn multipart_inspects_textual_parts_that_declare_a_filename() {
        let config = Config::default();
        let mut inspection = Inspection::new(&config);
        let format = inspection.headers(&headers(&[("content-type", "multipart/form-data; boundary=BOUNDARY")]));
        // The payload only exists after JSON unescaping, so the raw pass
        // cannot see it: only semantic parsing of the part can.
        let body = b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"q\"; filename=\"x.json\"\r\nContent-Type: application/json\r\n\r\n{\"u\":\"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\"}\r\n--BOUNDARY--\r\n";

        scan_body(&mut inspection, body, &format);

        assert!(
            inspection.has_xss(),
            "a filename must not downgrade a textual part to raw-only scanning"
        );
    }

    /// Scans views with NULs removed and Unicode whitespace folded to space.
    #[test]
    fn scans_nul_stripped_and_unicode_whitespace_normalised_views() {
        let config = Config::default();

        let mut nul = Inspection::new(&config);
        nul.headers(&headers(&[("x-q", "UNI\0ON SELECT a FROM b")]));
        assert!(nul.has_sqli(), "a NUL inside a SQL keyword must not hide it");

        let mut nbsp = Inspection::new(&config);
        nbsp.headers(&headers(&[("x-q", "1'\u{a0}OR\u{a0}'1'='1")]));
        assert!(nbsp.has_sqli(), "UTF-8 NBSP must not hide a logic operator");

        let mut clean = Inspection::new(&config);
        clean.headers(&headers(&[("x-q", "an ordinary value")]));
        assert!(!clean.has_sqli(), "normalisation must not invent detections");
    }

    /// Scans `SQLi` at the end of a raw body longer than libperfusion's input limit.
    #[test]
    fn scans_sqli_at_end_of_large_raw_body() {
        let config = Config::default();
        let mut inspection = Inspection::new(&config);
        let format = inspection.headers(&headers(&[("content-type", "text/plain")]));
        let mut body = vec![b' '; libperfusion::MAX_INPUT_LEN];
        body.extend_from_slice(b"1 UNION SELECT password FROM users");

        scan_body(&mut inspection, &body, &format);

        assert!(
            inspection.has_sqli(),
            "SQLi at the end of a large body must be inspected"
        );
    }

    /// Restarts raw-body `SQLi` scanning after benign SQL tokens.
    #[test]
    fn scans_sqli_after_benign_sql_tokens_in_raw_body() {
        let config = Config::default();
        let mut inspection = Inspection::new(&config);
        let format = inspection.headers(&headers(&[("content-type", "text/plain")]));

        scan_body(
            &mut inspection,
            b"SELECT 1; SELECT 2; SELECT 3; SELECT 4; SELECT 5; 1 UNION SELECT password FROM users",
            &format,
        );

        assert!(inspection.has_sqli(), "SQLi after benign SQL tokens must be found");
    }

    /// Scans XSS at the end of a raw body longer than libperfusion's input limit.
    #[test]
    fn scans_xss_at_end_of_large_raw_body() {
        let config = Config::default();
        let mut inspection = Inspection::new(&config);
        let format = inspection.headers(&headers(&[("content-type", "text/plain")]));
        let mut body = vec![b' '; libperfusion::MAX_INPUT_LEN];
        body.extend_from_slice(b"<script>alert(1)</script>");

        scan_body(&mut inspection, &body, &format);

        assert!(inspection.has_xss(), "XSS at the end of a large body must be inspected");
    }

    /// Scans findings after NUL padding in a raw body.
    #[test]
    fn scans_findings_after_nul_padding() {
        let config = Config::default();
        let mut inspection = Inspection::new(&config);
        let format = inspection.headers(&[]);
        let mut body = vec![0; libperfusion::MAX_INPUT_LEN];
        body.extend_from_slice(b"1 UNION SELECT password FROM users <script>alert(1)</script>");

        scan_body(&mut inspection, &body, &format);

        assert!(inspection.has_sqli(), "SQLi after NUL bytes must be inspected");
        assert!(inspection.has_xss(), "XSS after NUL bytes must be inspected");
    }

    /// Checks JSON escapes and duplicate object members.
    #[test]
    fn json_scans_escaped_strings_and_duplicate_keys() {
        let config = Config::default();
        let mut inspection = Inspection::new(&config);
        let format = inspection.headers(&headers(&[("content-type", "application/json")]));

        scan_body(
            &mut inspection,
            br#"{"\u003cscript\u003ealert(1)\u003c/script\u003e":"safe","x":"safe","x":"1 OR 1=1"}"#,
            &format,
        );

        assert!(inspection.has_xss(), "JSON escapes must be inspected after decoding");
        assert!(inspection.has_sqli(), "duplicate JSON members must all be inspected");
        assert_eq!(inspection.incomplete(), None, "valid JSON should be complete");
    }

    /// Checks multipart filename inspection and malformed framing.
    #[test]
    fn multipart_scans_file_names_and_rejects_malformed_parts() {
        let config = Config::default();
        let mut inspection = Inspection::new(&config);
        let format = inspection.headers(&headers(&[("content-type", "multipart/form-data; boundary=BOUNDARY")]));
        let body = b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"<script>.txt\"\r\nContent-Type: application/octet-stream\r\n\r\nbenign\r\n--BOUNDARY--\r\n";

        scan_body(&mut inspection, body, &format);

        assert!(inspection.has_xss(), "multipart filenames must be inspected");
        assert_eq!(inspection.incomplete(), None, "valid multipart should be complete");

        let mut malformed = Inspection::new(&config);
        scan_body(&mut malformed, b"not multipart", &format);
        assert_eq!(
            malformed.incomplete(),
            Some(Incomplete::MalformedBody),
            "malformed multipart must be incomplete"
        );
    }

    /// Scans `SQLi` and XSS in multipart part bodies.
    #[test]
    fn multipart_scans_field_bodies() {
        let config = Config::default();
        let body = b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"query\"\r\n\r\n1 UNION SELECT password FROM users\r\n--BOUNDARY\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\n<script>alert(1)</script>\r\n--BOUNDARY--\r\n";
        let mut raw = Inspection::new(&config);
        raw.scan_bytes(body);
        assert!(
            raw.has_sqli(),
            "SQLi after multipart framing must be found by raw scanning"
        );

        let mut inspection = Inspection::new(&config);
        let format = inspection.headers(&headers(&[("content-type", "multipart/form-data; boundary=BOUNDARY")]));

        scan_body(&mut inspection, body, &format);

        assert!(inspection.has_sqli(), "multipart SQLi fields must be inspected");
        assert!(inspection.has_xss(), "multipart XSS fields must be inspected");
        assert_eq!(inspection.incomplete(), None, "valid multipart should be complete");
    }

    /// Parses nested JSON fields and marks unparsed structured part types incomplete.
    #[test]
    fn multipart_checks_nested_json_and_unknown_structured_parts() {
        let config = Config::default();
        let mut json = Inspection::new(&config);
        let format = json.headers(&headers(&[("content-type", "multipart/form-data; boundary=BOUNDARY")]));
        let body = b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"payload\"\r\nContent-Type: application/json\r\n\r\n{\"comment\":\"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\"}\r\n--BOUNDARY--\r\n";

        scan_body(&mut json, body, &format);

        assert!(json.has_xss(), "nested JSON escapes must be inspected");
        assert_eq!(json.incomplete(), None, "supported nested JSON should be complete");

        let mut unsupported = Inspection::new(&config);
        let format = unsupported.headers(&headers(&[("content-type", "multipart/form-data; boundary=BOUNDARY")]));
        let body = b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"document\"\r\nContent-Type: application/pdf\r\n\r\nbenign\r\n--BOUNDARY--\r\n";

        scan_body(&mut unsupported, body, &format);

        assert_eq!(
            unsupported.incomplete(),
            Some(Incomplete::UnsupportedContentType),
            "unparsed structured part types must not be treated as complete"
        );
    }

    /// Enforces field byte and count limits for multipart parts.
    #[test]
    fn multipart_enforces_field_size_and_count_limits() {
        let size_limited = Config {
            max_field_bytes: 64,
            ..Config::default()
        };
        let format = Inspection::new(&size_limited).body_format(b"multipart/form-data; boundary=BOUNDARY");
        let mut oversized_body = b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"payload\"\r\n\r\n".to_vec();
        oversized_body.extend_from_slice(&[b'a'; 65]);
        oversized_body.extend_from_slice(b"\r\n--BOUNDARY--\r\n");
        let mut oversized = Inspection::new(&size_limited);

        scan_body(&mut oversized, &oversized_body, &format);

        assert_eq!(oversized.incomplete(), Some(Incomplete::FieldTooLarge));

        // The body carries its own field budget, so this has to be low enough
        // to be exhausted by the parts themselves rather than by the headers.
        let count_limited = Config {
            max_fields: 3,
            ..Config::default()
        };
        let mut too_many = Inspection::new(&count_limited);
        let format = too_many.headers(&headers(&[("content-type", "multipart/form-data; boundary=BOUNDARY")]));
        let body = b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nfirst\r\n--BOUNDARY\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nsecond\r\n--BOUNDARY--\r\n";

        scan_body(&mut too_many, body, &format);

        assert_eq!(too_many.incomplete(), Some(Incomplete::FieldLimit));
    }

    /// Checks unsupported content and JSON nesting outcomes.
    #[test]
    fn reports_unsupported_types_and_bounded_json_depth() {
        let config = Config {
            max_json_depth: 1,
            ..Config::default()
        };
        let mut inspection = Inspection::new(&config);
        let format = inspection.headers(&headers(&[("content-type", "application/xml")]));
        assert_eq!(
            inspection.incomplete(),
            Some(Incomplete::UnsupportedContentType),
            "unparsed structured formats must be incomplete"
        );
        assert_eq!(format, super::BodyFormat::Unsupported, "XML needs a parser");

        let mut json = Inspection::new(&config);
        let format = json.headers(&headers(&[("content-type", "application/json")]));
        scan_body(&mut json, br#"{"x":{"y":"<script>"}}"#, &format);
        assert_eq!(
            json.incomplete(),
            Some(Incomplete::MalformedBody),
            "JSON nesting beyond the configured depth must be incomplete"
        );
    }

    /// Marks streaming protocols incomplete without requiring an unbounded buffer.
    #[test]
    fn identifies_streaming_http_surfaces() {
        let config = Config::default();
        let mut grpc = Inspection::new(&config);
        grpc.headers(&headers(&[("content-type", "application/grpc")]));
        assert!(grpc.is_streaming(), "gRPC bodies must not be fully buffered");
        assert_eq!(
            grpc.incomplete(),
            Some(Incomplete::StreamingBody),
            "gRPC requires an application-aware parser"
        );

        let mut events = Inspection::new(&config);
        events.headers(&headers(&[("content-type", "text/event-stream")]));
        assert!(events.is_streaming(), "event streams must not be fully buffered");
    }
}
