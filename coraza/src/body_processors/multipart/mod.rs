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

use std::collections::LinkedList;

pub(crate) use parser::Part;

use crate::body_processors::budget::MemoryBudget;

/// Whether `name` is one MIME token, the shape Go's `textproto` canonicalizes. A name
/// that holds a space is not a token, and Go keeps it as sent (go.dev/issue/34540).
fn is_token_name(name: &str) -> bool {
    name.chars()
        .all(|character| character.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(character))
}

/// A part header as `MULTIPART_PART_HEADERS` holds it, `Name: value`, in a buffer of its length, its name as Go's
/// canonical header key.
///
/// Go's `textproto` canonicalizes a name that is one token (`net/textproto/reader.go`,
/// `canonicalMIMEHeaderKey`, go1.27.3) and keeps the name as sent when it holds a space
/// (go.dev/issue/34540), which is what a part header map is keyed by.
pub(crate) fn header_line(name: &str, value: &[u8]) -> Vec<u8> {
    let mut line = Vec::with_capacity(header_line_len(name, value));
    line.extend_from_slice(name.as_bytes());
    if is_token_name(name) {
        // A token is ASCII, so its case changes byte by byte.
        let mut starts_word = true;
        for byte in &mut line {
            *byte = if starts_word {
                byte.to_ascii_uppercase()
            } else {
                byte.to_ascii_lowercase()
            };
            starts_word = *byte == b'-';
        }
    }
    line.extend_from_slice(b": ");
    line.extend_from_slice(value);
    line
}

/// The length of the [`header_line`] of `name` and `value`, which is what it allocates.
pub(crate) fn header_line_len(name: &str, value: &[u8]) -> usize {
    name.len().saturating_add(2).saturating_add(value.len())
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
    /// What stopped the parser.
    pub(crate) cause: FailureCause,
}

/// What stopped a multipart parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureCause {
    /// The body is not what it should be, or hit one of the parser's own limits.
    Malformed,
    /// The host's memory budget.
    MemoryBudget,
}

/// Parse a multipart body using the boundary in its content type.
///
/// Returns the parts read before parsing stopped, and why it stopped, and whether a body cut by the limit ended
/// before its closing delimiter without an error, so that a part may follow the last one read: Go's body processor
/// publishes each part as `mime/multipart.Reader.NextPart` returns it, so a malformed part
/// later in the body keeps the parts before it.
///
/// `truncated` reports that `body` is only the prefix a `ProcessPartial` body limit
/// retained, which Go's body processor inspects up to the last complete part.
///
/// The parts it returns are charged to `memory`, with the list that holds them, and reading stops, as for any other
/// parse failure, when they would take more than it has left. The caller gives each part's [`Part::owned_bytes`]
/// back as it drops the part.
pub(crate) fn parse<'a>(
    content_type: &[u8],
    body: &'a [u8],
    truncated: bool,
    memory: &mut MemoryBudget,
) -> (LinkedList<Part<'a>>, Option<ParseFailure>, bool) {
    // The parsed media type and the parser's boundary markers are held while it reads: charged from the header.
    let setup = if memory.is_limited() {
        parser::setup_cost(content_type)
    } else {
        0
    };
    if !memory.charge(setup) {
        let failure = ParseFailure {
            message: parser::ParseError::Budget.go_message(),
            strict: false,
            cause: FailureCause::MemoryBudget,
        };
        return (LinkedList::new(), Some(failure), false);
    }
    let parsed = parse_charged(content_type, body, truncated, memory);
    memory.refund(setup);
    parsed
}

/// [`parse`] once what its setup holds is charged to `memory`.
fn parse_charged<'a>(
    content_type: &[u8],
    body: &'a [u8],
    truncated: bool,
    memory: &mut MemoryBudget,
) -> (LinkedList<Part<'a>>, Option<ParseFailure>, bool) {
    let content_type = match media_type::parse(content_type) {
        Ok(content_type) => content_type,
        Err(error) => {
            return (
                LinkedList::new(),
                Some(ParseFailure {
                    message: error.to_owned(),
                    strict: true,
                    cause: FailureCause::Malformed,
                }),
                false,
            );
        },
    };
    // Go checks the parsed media type with `strings.HasPrefix(mediaType, "multipart/")`
    // and reports this exact error otherwise, without the strict flag
    // (`internal/bodyprocessors/multipart.go:31-34`, v3.8.1).
    if !content_type.media_type().starts_with(b"multipart/") {
        return (
            LinkedList::new(),
            Some(ParseFailure {
                message: "not a multipart body".to_owned(),
                strict: false,
                cause: FailureCause::Malformed,
            }),
            false,
        );
    }
    // A missing boundary reaches `multipart.NewReader` as the empty string in Go, whose
    // first `NextPart` reports `multipart: boundary is empty`.
    let boundary = content_type.param(b"boundary").unwrap_or_default();
    let parser = parser::MultipartParser::new(boundary, body)
        .truncated(truncated)
        .with_memory_budget(*memory);
    let (parts, error) = parser.parse();
    *memory = parser.memory_left();
    let failure = error.map(|error| ParseFailure {
        // The host's memory budget is not one of Go's reader errors.
        strict: !error.is_budget(),
        cause: if error.is_budget() {
            FailureCause::MemoryBudget
        } else {
            FailureCause::Malformed
        },
        // The line a failure quotes is cut short under a budget, as the message is kept long after the parse.
        message: if memory.is_limited() { error.bounded() } else { error }.go_message(),
    });
    (parts, failure, parser.cut_open())
}
