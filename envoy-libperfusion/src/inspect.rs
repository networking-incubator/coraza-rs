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

use std::{convert::Infallible, str};

use bytes::Bytes;
use serde::{
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserializer,
};

use crate::config::Config;

/// shortcut: stops at four layers; raise the bound if a supported app decodes more.
const MAX_PERCENT_DECODE_LAYERS: usize = 4;

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
    pub(crate) fn body(&mut self, bytes: &[u8], format: &BodyFormat) {
        self.scan_bytes(bytes);
        self.scan_percent_encoded_views(bytes);

        match format {
            BodyFormat::Raw | BodyFormat::Unsupported => {},
            BodyFormat::UrlEncoded => {
                self.scan_form_fields(bytes);
            },
            BodyFormat::Json => self.scan_json(bytes),
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

    /// Runs both libperfusion detectors on a byte sequence.
    fn scan_bytes(&mut self, bytes: &[u8]) {
        self.findings.sqli |= libperfusion::sqli(bytes).is_some();
        self.findings.xss |= libperfusion::xss(bytes);
    }

    /// Scans bounded percent-decoded views while retaining the original bytes.
    fn scan_percent_encoded_views(&mut self, bytes: &[u8]) {
        if !contains_percent_escape(bytes) {
            return;
        }

        let mut decoded = bytes.to_vec();
        for _ in 0..MAX_PERCENT_DECODE_LAYERS {
            if !contains_percent_escape(&decoded) {
                return;
            }
            decoded = decode_percent_escapes(&decoded);
            self.scan_bytes(&decoded);
        }
        if contains_percent_escape(&decoded) {
            self.mark_incomplete(Incomplete::EncodedValueRemains);
        }
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

    /// Parses multipart framing and scans field names and file names.
    fn scan_multipart(&mut self, bytes: &[u8], boundary: &str) {
        let whole_stream_limit = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let content = Bytes::copy_from_slice(bytes);
        let stream = futures::stream::once(async move { Ok::<Bytes, Infallible>(content) });
        let constraints = multer::Constraints::new().size_limit(
            multer::SizeLimit::new()
                .whole_stream(whole_stream_limit)
                .per_field(whole_stream_limit),
        );

        let parsed = futures::executor::block_on(async {
            let mut multipart = multer::Multipart::with_constraints(stream, boundary, constraints);
            let mut field_count = 0_usize;
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
                if let Some(filename) = field.file_name() {
                    self.scan_field(filename.as_bytes());
                }
                while field.chunk().await.map_err(|_error| ())?.is_some() {}
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
fn decode_percent_escapes(bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(bytes.len());
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
    decoded
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
        while let Some(key) = map.next_key::<String>()? {
            self.inspection.scan_field(key.as_bytes());
            map.next_value_seed(JsonScan {
                inspection: self.inspection,
                depth: self.depth.saturating_add(1),
            })?;
        }
        Ok(())
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

        inspection.body(b"comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E", &format);

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
        inspection.body(b"bad=%E0%80", &format);

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
        inspection.body(b"%253Cscript%253Ealert(1)%253C%252Fscript%253E", &format);

        assert!(inspection.has_xss(), "encoded raw-body XSS must be inspected");
        assert_eq!(inspection.incomplete(), None, "covered layers are complete");
    }

    /// Checks JSON escapes and duplicate object members.
    #[test]
    fn json_scans_escaped_strings_and_duplicate_keys() {
        let config = Config::default();
        let mut inspection = Inspection::new(&config);
        let format = inspection.headers(&headers(&[("content-type", "application/json")]));

        inspection.body(
            br#"{"comment":"\u003cscript\u003ealert(1)\u003c/script\u003e","x":"safe","x":"1 OR 1=1"}"#,
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

        inspection.body(body, &format);

        assert!(inspection.has_xss(), "multipart filenames must be inspected");
        assert_eq!(inspection.incomplete(), None, "valid multipart should be complete");

        let mut malformed = Inspection::new(&config);
        malformed.body(b"not multipart", &format);
        assert_eq!(
            malformed.incomplete(),
            Some(Incomplete::MalformedBody),
            "malformed multipart must be incomplete"
        );
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
        json.body(br#"{"x":{"y":"<script>"}}"#, &format);
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
