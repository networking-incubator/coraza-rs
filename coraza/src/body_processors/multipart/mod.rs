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

//! Multipart request body parsing.

mod media_type;
mod parser;

pub(crate) use parser::Part;

/// Whether `name` is one MIME token, the shape Go's `textproto` canonicalizes. A name
/// that holds a space is not a token, and Go keeps it as sent (go.dev/issue/34540).
fn is_token_name(name: &str) -> bool {
    name.chars()
        .all(|character| character.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(character))
}

/// Format a valid MIME header name as Go's canonical header key.
///
/// Go's `textproto` canonicalizes a name that is one token (`net/textproto/reader.go`,
/// `canonicalMIMEHeaderKey`, go1.27.3) and keeps the name as sent when it holds a space
/// (go.dev/issue/34540), which is what a part header map is keyed by.
pub(crate) fn canonical_header_name(name: &str) -> String {
    if !is_token_name(name) {
        return name.to_owned();
    }
    let mut starts_word = true;
    name.chars()
        .map(|character| {
            let character = if starts_word {
                character.to_ascii_uppercase()
            } else {
                character.to_ascii_lowercase()
            };
            starts_word = character == '-';
            character
        })
        .collect()
}

/// Why a multipart body could not be parsed.
pub(crate) struct ParseFailure {
    /// The error Go's body processor returns, which reaches
    /// `REQBODY_PROCESSOR_ERROR_MSG` unchanged.
    pub(crate) message: String,
    /// Whether Go also sets `MULTIPART_STRICT_ERROR`. Its processor sets it for a
    /// `mime.ParseMediaType` failure and for every `multipart.Reader` error, but not for
    /// a body that is not multipart at all
    /// (`internal/bodyprocessors/multipart.go:22-34`, v3.8.1).
    pub(crate) strict: bool,
}

/// Parse a multipart body using the boundary in its content type.
///
/// Returns the parts read before parsing stopped, and why it stopped: Go's body processor
/// publishes each part as `mime/multipart.Reader.NextPart` returns it, so a malformed part
/// later in the body keeps the parts before it.
///
/// `truncated` reports that `body` is only the prefix a `ProcessPartial` body limit
/// retained, which Go's body processor inspects up to the last complete part.
pub(crate) fn parse<'a>(content_type: &[u8], body: &'a [u8], truncated: bool) -> (Vec<Part<'a>>, Option<ParseFailure>) {
    let content_type = match media_type::parse(content_type) {
        Ok(content_type) => content_type,
        Err(error) => {
            return (
                Vec::new(),
                Some(ParseFailure {
                    message: error.to_owned(),
                    strict: true,
                }),
            );
        },
    };
    // Go checks the parsed media type with `strings.HasPrefix(mediaType, "multipart/")`
    // and reports this exact error otherwise, without the strict flag
    // (`internal/bodyprocessors/multipart.go:31-34`, v3.8.1).
    if !content_type.media_type().starts_with(b"multipart/") {
        return (
            Vec::new(),
            Some(ParseFailure {
                message: "not a multipart body".to_owned(),
                strict: false,
            }),
        );
    }
    // A missing boundary reaches `multipart.NewReader` as the empty string in Go, whose
    // first `NextPart` reports `multipart: boundary is empty`.
    let boundary = content_type.param(b"boundary").unwrap_or_default();
    let (parts, error) = parser::MultipartParser::new(boundary, body)
        .truncated(truncated)
        .parse();
    let failure = error.map(|error| ParseFailure {
        message: error.go_message(),
        strict: true,
    });
    (parts, failure)
}
