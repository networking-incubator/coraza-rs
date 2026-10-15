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

use std::{collections::VecDeque, convert::Infallible, str};

use bytes::Bytes;
use serde::{
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserializer,
};

use crate::config::Config;

/// shortcut: stops at four layers; raise the bound if a supported app decodes more.
const MAX_PERCENT_DECODE_LAYERS: usize = 4;
/// Keeps each `SQLi` detector call bounded while overlapping later token starts.
const SQLI_WINDOW_TOKENS: usize = 8;

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
    /// Number of decoded fields inspected so far.
    fields: usize,
    /// Maximum number of decoded fields.
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

/// Scans bounded windows anchored at each SQL token start.
fn has_sqli_in_overlapping_windows(bytes: &[u8]) -> bool {
    let mut tokenizer = libperfusion::SqlTokenizer::new(bytes, libperfusion::Quote::None, libperfusion::Dialect::Ansi);
    let mut starts = VecDeque::with_capacity(SQLI_WINDOW_TOKENS + 1);
    starts.extend(tokenizer.by_ref().take(SQLI_WINDOW_TOKENS + 1).map(|token| token.pos()));

    while let Some(start) = starts.front().copied() {
        let end = starts
            .get(SQLI_WINDOW_TOKENS)
            .copied()
            .unwrap_or(bytes.len())
            .min(start.saturating_add(libperfusion::MAX_INPUT_LEN));
        if let Some(window) = bytes.get(start..end) {
            if libperfusion::sqli(window).is_some() {
                return true;
            }
        }

        starts.pop_front();
        let Some(token) = tokenizer.next() else {
            break;
        };
        starts.push_back(token.pos());
    }

    false
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
                || name.eq_ignore_ascii_case("upgrade")
                || name.eq_ignore_ascii_case(":status") && value.starts_with(b"101")
            {
                self.mark_streaming();
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
    pub(crate) fn body(&mut self, bytes: Vec<u8>, format: &BodyFormat) {
        self.scan_bytes(&bytes);
        self.scan_percent_encoded_views(&bytes);

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
            return;
        }
        self.scan_bytes(bytes);
        self.scan_percent_encoded_views(bytes);
    }

    /// Runs both detectors over this byte slice, which is bounded by adapter limits.
    fn scan_bytes(&mut self, bytes: &[u8]) {
        self.findings.sqli |= has_sqli_in_overlapping_windows(bytes);
        self.findings.xss |= libperfusion::xss_with_limit(bytes, bytes.len());
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
            || (media_type.starts_with("application/") && media_type.ends_with("+json"))
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
                .per_field(whole_stream_limit),
        );

        let parsed = futures::executor::block_on(async {
            let mut multipart = multer::Multipart::with_constraints(stream, boundary, constraints);
            let mut field_count = 0_usize;
            let mut field_body = Vec::new();
            while let Some(mut field) = multipart.next_field().await.map_err(|_error| ())? {
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
                let is_file = field.file_name().is_some();
                let part_type = field.content_type();
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
                while let Some(chunk) = field.chunk().await.map_err(|_error| ())? {
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
            Ok::<usize, ()>(field_count)
        });

        if parsed.is_err() || parsed.is_ok_and(|field_count| field_count == 0) {
            self.mark_incomplete(Incomplete::MalformedBody);
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

        let count_limited = Config {
            max_fields: 4,
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
