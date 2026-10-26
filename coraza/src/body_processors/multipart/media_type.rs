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

//! The parameter parsing Go's `mime.ParseMediaType` applies to multipart headers.
//!
//! Go parses `Content-Type` and each part's `Content-Disposition` with
//! `mime.ParseMediaType` (`mime/mediatype.go`). That includes RFC 2231 extended
//! values (`name*=utf-8''value`) and numbered continuations (`name*0`, `name*1*`).
//! This port keeps the media type and parameter values as bytes and reproduces
//! Go's error strings, because a multipart body processor error reaches
//! `REQBODY_PROCESSOR_ERROR_MSG` unchanged.

use std::collections::HashMap;

/// Go's `errNoMediaType`.
const NO_MEDIA_TYPE: &str = "mime: no media type";
/// Go's `errNoSlashAfterFirstToken`.
const NO_SLASH_AFTER_FIRST_TOKEN: &str = "mime: expected slash after first token";
/// Go's `errNoTokenAfterSlash`.
const NO_TOKEN_AFTER_SLASH: &str = "mime: expected token after slash";
/// Go's `errUnexpectedContentAfterMediaSubtype`.
const UNEXPECTED_CONTENT_AFTER_MEDIA_SUBTYPE: &str = "mime: unexpected content after media subtype";
/// Go's `ErrInvalidMediaParameter`.
pub(super) const INVALID_MEDIA_PARAMETER: &str = "mime: invalid media parameter";
/// Go's `errDuplicateParamName`.
const DUPLICATE_PARAMETER_NAME: &str = "mime: duplicate parameter name";

/// Parameters in first-discovery order, indexed by name.
///
/// Go indexes media type parameters with a map (`mime/mediatype.go`,
/// `ParseMediaType`), so a lookup is constant time, and one attacker-sized
/// `Content-Disposition` line can carry a million parameters: a linear scan per
/// parameter is quadratic in the header length. Ordinary parts carry a handful of
/// parameters, where a hash table costs more than a scan, so the index is built only
/// once a list grows past `INDEX_THRESHOLD`.
#[derive(Debug, Default)]
struct Indexed<V> {
    /// The entries, in first-discovery order.
    entries: Vec<(Vec<u8>, V)>,
    /// Row in `entries` for each name; empty until the index is worth building.
    rows: HashMap<Vec<u8>, usize>,
}

/// Entry count above which `Indexed` builds its name index.
const INDEX_THRESHOLD: usize = 8;

impl<V> Indexed<V> {
    /// Insert `value` under `name`, rejecting a repeated name whose value differs, as
    /// Go does.
    fn insert(&mut self, name: &[u8], value: V) -> Result<(), &'static str>
    where
        V: PartialEq,
    {
        if let Some(row) = self.row(name) {
            return match self.entries.get(row) {
                Some((_, existing)) if *existing != value => Err(DUPLICATE_PARAMETER_NAME),
                _ => Ok(()),
            };
        }
        self.push(name.to_vec(), value);
        Ok(())
    }

    /// Set `name` to `value`, overwriting an entry of the same name.
    fn set(&mut self, name: Vec<u8>, value: V) {
        if let Some(row) = self.row(name.as_slice()) {
            if let Some((_, existing)) = self.entries.get_mut(row) {
                *existing = value;
            }
            return;
        }
        self.push(name, value);
    }

    /// The value stored under `name`.
    fn get(&self, name: &[u8]) -> Option<&V> {
        self.entries.get(self.row(name)?).map(|(_, value)| value)
    }

    /// The value stored under `name`, for mutation.
    fn get_mut(&mut self, name: &[u8]) -> Option<&mut V> {
        let row = self.row(name)?;
        self.entries.get_mut(row).map(|(_, value)| value)
    }

    /// Append an entry whose name is not present yet.
    fn push(&mut self, name: Vec<u8>, value: V) {
        let row = self.entries.len();
        self.entries.push((name, value));
        if self.rows.is_empty() {
            // Small lists are scanned; build the index once it is worth it.
            if self.entries.len() > INDEX_THRESHOLD {
                self.rows = self
                    .entries
                    .iter()
                    .enumerate()
                    .map(|(row, (name, _))| (name.clone(), row))
                    .collect();
            }
            return;
        }
        if let Some((name, _)) = self.entries.get(row) {
            self.rows.insert(name.clone(), row);
        }
    }

    /// The row of `name`, by scan while the index is empty.
    fn row(&self, name: &[u8]) -> Option<usize> {
        if self.rows.is_empty() {
            return self.entries.iter().position(|(key, _)| key.as_slice() == name);
        }
        self.rows.get(name).copied()
    }
}

/// A parsed media type and its parameters.
#[derive(Debug)]
pub(super) struct MediaType {
    /// The lowercased, trimmed media type, before the first `;`.
    media_type: Vec<u8>,
    /// Parameters, in first-discovery order.
    params: Indexed<Vec<u8>>,
}

impl MediaType {
    /// The lowercased, trimmed media type.
    pub(super) fn media_type(&self) -> &[u8] {
        &self.media_type
    }

    /// The value of the parameter named `name`, which must be lowercase.
    pub(super) fn param(&self, name: &[u8]) -> Option<&[u8]> {
        self.params.get(name).map(Vec::as_slice)
    }
}

/// Parse a media type value the way Go's `mime.ParseMediaType` does.
///
/// # Errors
///
/// Returns Go's `mime` error string when the value or one of its parameters is
/// malformed, repeats a name with a different value, or cannot be decoded.
pub(super) fn parse(value: &[u8]) -> Result<MediaType, &'static str> {
    let base_end = value.iter().position(|&byte| byte == b';').unwrap_or(value.len());
    let base = value.get(..base_end).unwrap_or_default();
    let media_type = trim_space(base).to_ascii_lowercase();
    check_media_type_disposition(&media_type)?;

    let mut params: Indexed<Vec<u8>> = Indexed::default();
    let mut continuation: Indexed<Indexed<Vec<u8>>> = Indexed::default();
    let mut rest = value.get(base_end..).unwrap_or_default();
    loop {
        rest = trim_space(rest);
        if rest.is_empty() {
            break;
        }
        let (key, param_value, next) = consume_media_param(rest);
        if key.is_empty() {
            // Go ignores trailing semicolons.
            if trim_space(next) == b";" {
                break;
            }
            return Err(INVALID_MEDIA_PARAMETER);
        }
        if let Some(star) = key.iter().position(|&byte| byte == b'*') {
            let base_name = key.get(..star).unwrap_or_default();
            if continuation.get(base_name).is_none() {
                continuation.push(base_name.to_vec(), Indexed::default());
            }
            if let Some(pieces) = continuation.get_mut(base_name) {
                pieces.insert(&key, param_value)?;
            }
        } else {
            params.insert(&key, param_value)?;
        }
        rest = next;
    }

    stitch_continuations(&mut params, continuation);
    Ok(MediaType { media_type, params })
}

/// Validate a lowercased, trimmed media type as Go's `checkMediaTypeDisposition`.
fn check_media_type_disposition(media_type: &[u8]) -> Result<(), &'static str> {
    let (first, rest) = consume_token(media_type);
    if first.is_empty() {
        return Err(NO_MEDIA_TYPE);
    }
    if rest.is_empty() {
        return Ok(());
    }
    let Some(rest) = rest.strip_prefix(b"/") else {
        return Err(NO_SLASH_AFTER_FIRST_TOKEN);
    };
    let (second, rest) = consume_token(rest);
    if second.is_empty() {
        return Err(NO_TOKEN_AFTER_SLASH);
    }
    if !rest.is_empty() {
        return Err(UNEXPECTED_CONTENT_AFTER_MEDIA_SUBTYPE);
    }
    Ok(())
}

/// Resolve RFC 2231 extended values and continuations into `params`.
fn stitch_continuations(params: &mut Indexed<Vec<u8>>, continuation: Indexed<Indexed<Vec<u8>>>) {
    for (base_name, pieces) in continuation.entries {
        let single_part = with_suffix(&base_name, b"");
        if let Some(value) = pieces.get(&single_part) {
            if let Some(decoded) = decode_2231(value) {
                params.set(base_name, decoded);
            }
            continue;
        }

        let mut assembled = Vec::new();
        let mut valid = false;
        let mut index = 0_usize;
        loop {
            let simple = with_index(&base_name, index, b"");
            if let Some(value) = pieces.get(&simple) {
                valid = true;
                assembled.extend_from_slice(value);
                index = index.saturating_add(1);
                continue;
            }
            let encoded = with_index(&base_name, index, b"*");
            let Some(value) = pieces.get(&encoded) else {
                break;
            };
            valid = true;
            if index == 0 {
                if let Some(decoded) = decode_2231(value) {
                    assembled.extend_from_slice(&decoded);
                }
            } else if let Some(decoded) = percent_decode_strict(value) {
                assembled.extend_from_slice(&decoded);
            }
            index = index.saturating_add(1);
        }
        if valid {
            params.set(base_name, assembled);
        }
    }
}

/// `base` followed by `*` and `suffix`.
fn with_suffix(base: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(base.len().saturating_add(1).saturating_add(suffix.len()));
    key.extend_from_slice(base);
    key.push(b'*');
    key.extend_from_slice(suffix);
    key
}

/// `base` followed by `*`, a decimal index and `suffix`.
fn with_index(base: &[u8], index: usize, suffix: &[u8]) -> Vec<u8> {
    let digits = index.to_string();
    let mut key = Vec::with_capacity(base.len().saturating_add(1).saturating_add(digits.len()));
    key.extend_from_slice(base);
    key.push(b'*');
    key.extend_from_slice(digits.as_bytes());
    key.extend_from_slice(suffix);
    key
}

/// Go's `decode2231Enc`: `charset'[language]'value`, percent-decoded.
fn decode_2231(value: &[u8]) -> Option<Vec<u8>> {
    let quote = value.iter().position(|&byte| byte == b'\'')?;
    let charset = value.get(..quote)?;
    let rest = value.get(quote.saturating_add(1)..)?;
    let second = rest.iter().position(|&byte| byte == b'\'').unwrap_or(rest.len());
    let extended = rest.get(second.saturating_add(1)..)?;
    let charset = charset.to_ascii_lowercase();
    if charset != b"us-ascii" && charset != b"utf-8" {
        return None;
    }
    percent_decode_strict(extended)
}

/// Go's `percentHexUnescape`; `None` when a `%` escape is malformed.
fn percent_decode_strict(value: &[u8]) -> Option<Vec<u8>> {
    if !value.contains(&b'%') {
        return Some(value.to_vec());
    }
    let mut decoded = Vec::with_capacity(value.len());
    let mut offset = 0_usize;
    while let Some(&byte) = value.get(offset) {
        if byte == b'%' {
            let escaped = value.get(offset.saturating_add(1)..offset.saturating_add(3))?;
            decoded.push(crate::utils::strings::x2c(escaped)?);
            offset = offset.saturating_add(3);
        } else {
            decoded.push(byte);
            offset = offset.saturating_add(1);
        }
    }
    Some(decoded)
}

/// Trim the Unicode whitespace Go's `strings.TrimSpace` removes from both ends.
fn trim_space(value: &[u8]) -> &[u8] {
    let mut start = 0_usize;
    while let Some((character, len)) = decode_first(value.get(start..).unwrap_or_default()) {
        if !character.is_whitespace() {
            break;
        }
        start = start.saturating_add(len);
    }
    let mut end = value.len();
    while let Some((character, len)) = decode_last(value.get(..end).unwrap_or_default()) {
        if !character.is_whitespace() {
            break;
        }
        end = end.saturating_sub(len);
    }
    if start > end {
        return &[];
    }
    value.get(start..end).unwrap_or_default()
}

/// Decode the first UTF-8 character of `value`, if it starts with a valid one.
fn decode_first(value: &[u8]) -> Option<(char, usize)> {
    for len in 1..=value.len().min(4) {
        if let Some(character) = value
            .get(..len)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .and_then(|text| text.chars().next())
        {
            return Some((character, len));
        }
    }
    None
}

/// Decode the last UTF-8 character of `value`, if it ends with a valid one.
fn decode_last(value: &[u8]) -> Option<(char, usize)> {
    for len in 1..=value.len().min(4) {
        let start = value.len().saturating_sub(len);
        if let Some(character) = value
            .get(start..)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .and_then(|text| text.chars().next())
        {
            return Some((character, len));
        }
    }
    None
}

/// Consume an RFC 2045 token, returning it and the rest.
fn consume_token(value: &[u8]) -> (&[u8], &[u8]) {
    let end = value
        .iter()
        .position(|&byte| !is_token_char(byte))
        .unwrap_or(value.len());
    (
        value.get(..end).unwrap_or_default(),
        value.get(end..).unwrap_or_default(),
    )
}

/// Consume one `;name=value` parameter; an empty name reports a parse failure.
fn consume_media_param(value: &[u8]) -> (Vec<u8>, Vec<u8>, &[u8]) {
    let rest = trim_space(value);
    let Some(rest) = rest.strip_prefix(b";") else {
        return (Vec::new(), Vec::new(), value);
    };
    let rest = trim_space(rest);
    let (name, rest) = consume_token(rest);
    let name = name.to_ascii_lowercase();
    if name.is_empty() {
        return (Vec::new(), Vec::new(), value);
    }
    let rest = trim_space(rest);
    let Some(rest) = rest.strip_prefix(b"=") else {
        return (Vec::new(), Vec::new(), value);
    };
    let rest = trim_space(rest);
    let (param_value, next) = consume_value(rest);
    match param_value {
        Some(param_value) => (name, param_value, next),
        None => (Vec::new(), Vec::new(), value),
    }
}

/// Consume a token or quoted-string value, returning it and the rest.
fn consume_value(value: &[u8]) -> (Option<Vec<u8>>, &[u8]) {
    if value.is_empty() {
        return (None, value);
    }
    if value.first() != Some(&b'"') {
        let (token, rest) = consume_token(value);
        return if token.is_empty() {
            (None, value)
        } else {
            (Some(token.to_vec()), rest)
        };
    }
    let mut unquoted = Vec::new();
    let mut offset = 1_usize;
    while let Some(&byte) = value.get(offset) {
        if byte == b'"' {
            return (
                Some(unquoted),
                value.get(offset.saturating_add(1)..).unwrap_or_default(),
            );
        }
        // An unescaped backslash before a tspecial is MSIE's literal path
        // separator; Go keeps it (`mime/mediatype.go:consumeValue`).
        if byte == b'\\'
            && let Some(&next) = value.get(offset.saturating_add(1))
            && is_tspecial(next)
        {
            unquoted.push(next);
            offset = offset.saturating_add(2);
            continue;
        }
        if byte == b'\r' || byte == b'\n' {
            return (None, value);
        }
        unquoted.push(byte);
        offset = offset.saturating_add(1);
    }
    (None, value)
}

/// Whether `byte` is an RFC 2045 token character.
fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Whether `byte` is one of RFC 2045's tspecials.
fn is_tspecial(byte: u8) -> bool {
    b"()<>@,;:\\\"/[]?=".contains(&byte)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "parser tests use fixed media type fixtures")]
mod tests {
    use super::parse;

    #[test]
    fn parses_media_type_and_plain_parameters_like_go() {
        let parsed = parse(b" Multipart/Form-Data ; Boundary=b; name=field ").unwrap();
        assert_eq!(parsed.media_type(), b"multipart/form-data");
        assert_eq!(parsed.param(b"boundary"), Some(&b"b"[..]));
        assert_eq!(parsed.param(b"name"), Some(&b"field"[..]));
        assert_eq!(
            parse(b"multipart/form-data; boundary=b;").unwrap().param(b"boundary"),
            Some(&b"b"[..])
        );
        assert_eq!(
            parse(b"multipart/form-data; name=a; name=a").unwrap().param(b"name"),
            Some(&b"a"[..])
        );
    }

    #[test]
    fn reports_go_media_type_errors() {
        for (value, message) in [
            (b"".as_slice(), "mime: no media type"),
            (b"multipart/", "mime: expected token after slash"),
            (b"/form-data", "mime: no media type"),
            (
                b"multipart/form-data boundary=b",
                "mime: unexpected content after media subtype",
            ),
            (b"multipart/form-data; boundary", "mime: invalid media parameter"),
            (b"multipart/form-data; boundary=b;;", "mime: invalid media parameter"),
            (b"multipart/form-data; =b", "mime: invalid media parameter"),
            (
                b"multipart/form-data; boundary=b; boundary=c",
                "mime: duplicate parameter name",
            ),
        ] {
            assert_eq!(parse(value).err(), Some(message), "{value:?}");
        }
    }

    #[test]
    fn decodes_rfc_2231_extended_values_and_continuations_like_go() {
        for (value, expected) in [
            (b"name*=utf-8''field".as_slice(), b"field".as_slice()),
            (b"name*0=long; name*1=name", b"longname"),
            (b"name*0*=utf-8''a%20b; name*1*=%FF", b"a b\xff"),
            (b"name=plain; name*=utf-8''extended", b"extended"),
            (b"name*=utf-8''%FF", b"\xff"),
        ] {
            let value = [b"multipart/form-data; ".as_slice(), value].concat();
            assert_eq!(parse(&value).unwrap().param(b"name"), Some(expected), "{value:?}");
        }
        // An unsupported charset leaves the plain name in place.
        let value = b"multipart/form-data; name=plain; name*=iso-8859-1''field";
        assert_eq!(parse(value).unwrap().param(b"name"), Some(&b"plain"[..]));
        // Without a plain name, Go stores no name at all.
        let value = b"multipart/form-data; name*=iso-8859-1''field";
        assert_eq!(parse(value).unwrap().param(b"name"), None);
    }

    #[test]
    fn parses_a_mebibyte_of_parameters_in_linear_time() {
        // One `Content-Disposition` line is bounded by `MAX_HEADER_BLOCK`, not by a
        // parameter count, so an attacker can carry a million distinct parameters in
        // one header. Go indexes them with a map; a linear scan per parameter made this
        // parser take 12.8 s and 30 MB at 128k parameters.
        fn measure(value: &[u8]) -> std::time::Duration {
            let started = std::time::Instant::now();
            let parsed = parse(value).unwrap();
            let elapsed = started.elapsed();
            assert!(!parsed.params.entries.is_empty());
            elapsed
        }

        let mut plain = b"form-data".to_vec();
        for index in 0..120_000 {
            plain.extend_from_slice(b"; p");
            plain.extend_from_slice(index.to_string().as_bytes());
            plain.extend_from_slice(b"=v");
        }
        assert!(plain.len() > 1 << 20, "header is {} bytes", plain.len());
        let plain_elapsed = measure(&plain);
        let parsed = parse(&plain).unwrap();
        assert_eq!(parsed.params.entries.len(), 120_000);
        assert_eq!(parsed.param(b"p119999"), Some(&b"v"[..]));

        // The same shape through RFC 2231 continuations, one base name each.
        let mut continuations = b"form-data".to_vec();
        for index in 0..16_384 {
            continuations.extend_from_slice(b"; c");
            continuations.extend_from_slice(index.to_string().as_bytes());
            continuations.extend_from_slice(b"*=utf-8''v");
        }
        let continuation_elapsed = measure(&continuations);

        // A quadratic implementation took seconds for the first shape alone; linear
        // parsing takes milliseconds, leaving room for a loaded test runner.
        for (shape, elapsed) in [("plain", plain_elapsed), ("continuation", continuation_elapsed)] {
            assert!(
                elapsed < std::time::Duration::from_secs(5),
                "{shape} parse took {elapsed:?}"
            );
        }
    }
}
