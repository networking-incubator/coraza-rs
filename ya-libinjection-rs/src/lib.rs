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
//! let fingerprint = libinjection_rs::sqli(b"1' OR '1'='1").unwrap();
//! assert_eq!(fingerprint, "s&sos");
//! assert!(libinjection_rs::sqli(b"hello world 123").is_none());
//!
//! assert!(libinjection_rs::xss(b"<script>alert('xss')</script>"));
//! assert!(!libinjection_rs::xss(b"<p>Hello World</p>"));
//! ```
//!
//! [libinjection]: https://github.com/libinjection/libinjection

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod bytes;
mod html5;
mod sqli;
mod xss;

#[cfg(test)]
mod corpus;

pub use sqli::Fingerprint;

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
