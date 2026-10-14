// Copyright (c) 2012-2016, Nick Galbreath
// Copyright (c) 2017-2024, libinjection Contributors
// Copyright 2026 Coraza Kubernetes Operator contributors.
//
// SPDX-License-Identifier: BSD-3-Clause
// See the crate's LICENSE for the complete terms.
//! A pure Rust port of [libinjection], which detects SQL injection and

//! cross-site scripting in user input by tokenizing it rather than matching
//! regular expressions.
//!
//! The port follows libinjection 4.0.0 (`d88a8f8`) and aims to give the same
//! verdict as the C library on every input. It uses `std` for accelerated byte
//! searches and does not allocate while detecting.
//!
//! Inputs are bytes: decode them (URL-decoding, for instance) the way the
//! application that will consume them does before checking them.
//!
//! ```
//! let fingerprint = libperfusion::sqli(b"1' OR '1'='1").unwrap();
//! assert_eq!(fingerprint, "s&sos");
//! assert!(libperfusion::sqli(b"hello world 123").is_none());
//!
//! assert!(libperfusion::xss(b"<script>alert('xss')</script>"));
//! assert!(!libperfusion::xss(b"<p>Hello World</p>"));
//! ```
//!
//! # License
//!
//! Being derived from libinjection, this crate is distributed under the same
//! BSD 3-Clause license, with libinjection's copyright notice: see `LICENSE`.
//!
//! [libinjection]: https://github.com/libinjection/libinjection

#![forbid(unsafe_code)]

#[expect(
    clippy::indexing_slicing,
    reason = "The byte helpers check their slice bounds before accessing them."
)]
mod bytes;
#[expect(
    clippy::indexing_slicing,
    reason = "The HTML tokenizer advances through bounds-checked byte positions."
)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "HTML state handlers share Option<Token> so EOF transitions compose directly."
)]
mod html5;
#[expect(
    clippy::indexing_slicing,
    reason = "The SQL scanner and fixed token window maintain bounded byte and slot positions."
)]
mod sqli;
#[expect(
    clippy::indexing_slicing,
    reason = "The XSS scanner bounds normalized names and table spans before access."
)]
mod xss;

pub use html5::{Context as HtmlContext, Token as HtmlToken, TokenKind as HtmlTokenKind, Tokenizer as HtmlTokenizer};
pub use sqli::{
    BuiltinSqlLookup, Dialect, Fingerprint, Quote, SqlLookup, SqlState, SqlStatistics, SqlToken, SqlTokenType,
    SqlTokenizer,
};

/// Ported table constants for exact source-integrity tests. Not stable API.
#[cfg(feature = "internals")]
#[doc(hidden)]
pub mod internals {
    /// Ported tables, exposed only for source-integrity tests.
    pub mod tables {
        pub use crate::{
            sqli::{keyword_table::SQL_KEYWORDS, lexer::Parser},
            xss::{
                Attribute,
                tables::{BLACK_ATTR_EVENTS, BLACK_ATTRS, BLACK_TAGS},
            },
        };
    }
}

/// Checks `input` for SQL injection.
///
/// The input is tested as-is, and as if it continued a single- or
/// double-quoted string. Returns the fingerprint of the first of these
/// readings that matches a known SQL injection pattern, or `None` if the
/// input looks benign.
#[must_use]
pub fn sqli(input: &[u8]) -> Option<Fingerprint> {
    sqli::detect(input)
}

/// Like [`sqli()`], but also returns which [`Dialect`] the match was found in.
#[must_use]
pub fn sqli_with_dialect(input: &[u8]) -> Option<(Fingerprint, Dialect)> {
    sqli::detect_with_dialect(input)
}

/// Checks `input` for SQL injection, scanning at most `max_bytes`.
///
/// Equivalent to `sqli(&input[..max_bytes.min(input.len())])`.
#[must_use]
pub fn sqli_with_limit(input: &[u8], max_bytes: usize) -> Option<Fingerprint> {
    sqli::detect(input.get(..max_bytes.min(input.len())).unwrap_or_default())
}

/// Checks `input` for cross-site scripting.
///
/// The input is tested as HTML, and as if it continued an attribute value,
/// unquoted or quoted with `'`, `"` or a backtick. Returns `true` if any of
/// these readings holds a tag, attribute or URL that can run script.
#[must_use]
pub fn xss(input: &[u8]) -> bool {
    xss::detect(input)
}

/// Like [`xss()`], but also returns which [`HtmlContext`] the match was found in.
///
/// Returns `None` if the input looks benign.
#[must_use]
pub fn xss_with_context(input: &[u8]) -> Option<HtmlContext> {
    xss::detect_with_context(input)
}

/// Checks `input` for cross-site scripting in one caller-selected HTML context.
#[must_use]
pub fn xss_in_context(input: &[u8], context: HtmlContext) -> bool {
    xss::is_xss(input, context, None)
}

/// Checks `input` for cross-site scripting, scanning at most `max_bytes`.
///
/// Equivalent to `xss(&input[..max_bytes.min(input.len())])`.
#[must_use]
pub fn xss_with_limit(input: &[u8], max_bytes: usize) -> bool {
    xss::detect(input.get(..max_bytes.min(input.len())).unwrap_or_default())
}
