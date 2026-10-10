//! Inputs that upstream libinjection misses, and this port detects.

#[test]
fn sqli_number_comment_after_leading_whitespace() {
    // The byte after the number is read at its offset, not at its length.
    assert!(libperfusion::sqli(b"\t1--").is_some());
    assert!(libperfusion::sqli(b"  1--").is_some());
    assert!(libperfusion::sqli(b"1--").is_some());
}

#[test]
fn xss_byte_ff_is_not_the_end_of_the_input() {
    assert!(libperfusion::xss(b"<img \xff onerror=alert(1)>"));
    assert!(libperfusion::xss(b"<img \xff\xff onerror=alert(1)>"));
    // Nothing to detect once the handler is gone.
    assert!(!libperfusion::xss(b"<img \xff alt=x>"));
}
