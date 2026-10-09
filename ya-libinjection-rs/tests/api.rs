//! Tests for the extended public API: dialect, html context, and input limits.

use libperfusion::{Dialect, HtmlContext};

#[test]
fn sqli_with_limit_detects_full_input() {
    let attack = b"1' OR '1'='1";
    assert_eq!(
        libperfusion::sqli_with_limit(attack, attack.len()),
        libperfusion::sqli(attack),
    );
}

#[test]
fn sqli_with_limit_overlarge_limit_is_same_as_no_limit() {
    let attack = b"1' OR '1'='1";
    assert_eq!(
        libperfusion::sqli_with_limit(attack, usize::MAX),
        libperfusion::sqli(attack),
    );
}

#[test]
fn sqli_with_limit_truncation_prevents_detection() {
    // "1'" alone is not injection.
    assert!(libperfusion::sqli_with_limit(b"1' OR '1'='1", 2).is_none());
}

#[test]
fn sqli_with_limit_zero_is_none() {
    assert!(libperfusion::sqli_with_limit(b"1' OR '1'='1", 0).is_none());
}

#[test]
fn xss_with_limit_detects_full_input() {
    let attack = b"<script>alert(1)</script>";
    assert_eq!(
        libperfusion::xss_with_limit(attack, attack.len()),
        libperfusion::xss(attack),
    );
}

#[test]
fn xss_with_limit_overlarge_limit_is_same_as_no_limit() {
    let attack = b"<script>alert(1)</script>";
    assert_eq!(
        libperfusion::xss_with_limit(attack, usize::MAX),
        libperfusion::xss(attack),
    );
}

#[test]
fn xss_with_limit_truncation_prevents_detection() {
    // "<sc" is not an XSS payload.
    assert!(!libperfusion::xss_with_limit(
        b"<script>alert(1)</script>",
        3
    ));
}

#[test]
fn xss_with_limit_zero_is_false() {
    assert!(!libperfusion::xss_with_limit(
        b"<script>alert(1)</script>",
        0
    ));
}

#[test]
fn sqli_dialect_ansi() {
    let attack = b"1' OR '1'='1";
    let (fp, dialect) = libperfusion::sqli_with_dialect(attack).unwrap();
    assert_eq!(fp, libperfusion::sqli(attack).unwrap());
    assert_eq!(dialect, Dialect::Ansi);
}

#[test]
fn sqli_dialect_mysql_via_double_quote() {
    // MySQL is the only dialect that uses `"` as a string delimiter.
    let attack = b"1\" OR \"1\"=\"1";
    let (fp, dialect) = libperfusion::sqli_with_dialect(attack).unwrap();
    assert_eq!(fp, libperfusion::sqli(attack).unwrap());
    assert_eq!(dialect, Dialect::Mysql);
}

#[test]
fn sqli_dialect_benign_is_none() {
    assert!(libperfusion::sqli_with_dialect(b"hello world 123").is_none());
}

#[test]
fn xss_context_data() {
    // A script tag in data position: the first context tested, and the one that fires.
    assert_eq!(
        libperfusion::xss_with_context(b"<script>alert(1)</script>"),
        Some(HtmlContext::Data),
    );
}

#[test]
fn xss_context_attribute_value() {
    // The leading space terminates the unquoted attribute value; the tokenizer
    // then sees `onclick` as an attribute name and flags it. The same input in
    // Data context is just text (no enclosing tag), so Data does not fire.
    assert_eq!(
        libperfusion::xss_with_context(b" onclick=x"),
        Some(HtmlContext::ValueNoQuote),
    );
}

#[test]
fn xss_context_benign_is_none() {
    assert!(libperfusion::xss_with_context(b"hello world").is_none());
    assert!(libperfusion::xss_with_context(b"<p>Hello World</p>").is_none());
}

#[test]
fn xss_context_consistent_with_xss() {
    let cases: &[&[u8]] = &[
        b"<script>alert(1)</script>",
        b"javascript:alert(1)",
        b"<p>Hello</p>",
        b"",
    ];
    for &case in cases {
        assert_eq!(
            libperfusion::xss_with_context(case).is_some(),
            libperfusion::xss(case),
            "mismatch for {:?}",
            case.escape_ascii(),
        );
    }
}
