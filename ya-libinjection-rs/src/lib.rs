//! A pure Rust port of [libinjection], which detects SQL injection and
//! cross-site scripting in user input by tokenizing it rather than matching
//! regular expressions.
//!
//! The port follows libinjection 4.0.0 (`d88a8f8`) and aims to give the same
//! verdict as the C library on every input. It needs neither `std` nor an
//! allocator.
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

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod bytes;
mod html5;
mod sqli;
mod xss;

pub use sqli::Fingerprint;

/// Implementation details, for this crate's own tests and their differential
/// oracle. Not part of the API: anything in here can change in any release.
#[cfg(feature = "internals")]
#[doc(hidden)]
pub mod internals {
    pub mod html5 {
        pub use crate::html5::{Context, Token, TokenKind, Tokenizer};
    }

    pub mod sqli {
        pub use crate::sqli::State;
        pub use crate::sqli::keyword_table::SQL_KEYWORDS;
        pub use crate::sqli::lexer::{Dialect, Lexer, Parser, Quote, Stats};
        pub use crate::sqli::token::{Token, TokenType};
    }

    pub mod xss {
        pub use crate::xss::events::BLACK_ATTR_EVENTS;
        pub use crate::xss::{Attribute, BLACK_ATTRS, BLACK_TAGS, is_xss};
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

/// Checks `input` for cross-site scripting.
///
/// The input is tested as HTML, and as if it continued an attribute value,
/// unquoted or quoted with `'`, `"` or a backtick. Returns `true` if any of
/// these readings holds a tag, attribute or URL that can run script.
#[must_use]
pub fn xss(input: &[u8]) -> bool {
    xss::detect(input)
}
