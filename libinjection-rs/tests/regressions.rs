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
//! Inputs that upstream libinjection misses, and this port detects.

#![expect(
    clippy::tests_outside_test_module,
    reason = "Cargo integration test targets consist of tests."
)]
#![expect(
    clippy::unwrap_used,
    reason = "Missing expected tokens should fail the test immediately."
)]


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

#[test]
fn xss_ignores_nuls_inside_go_normalized_names_values_and_comments() {
    for input in [
        b"<a on\0error=1>".as_slice(),
        b"<sv\0gload>",
        b"<a xm\0lns=1>",
        b"href=ja\0va:",
        b"<?im\0port namespace=\"t\">",
        b"<!EN\0TITY x SYSTEM \"file:///etc/passwd\">",
    ] {
        assert!(libperfusion::xss(input), "{:?}", input.escape_ascii());
    }
}

#[test]
fn xss_uses_exact_normalized_attribute_names() {
    let overlong_svg = [b"<svg".as_slice(), &[b'x'; 64], b">"].concat();
    for input in [
        b"<a onerrorfoo=1>".as_slice(),
        b"<a xmlnsfoo=1>",
        b"<a xlinkfoo=1>",
        b"<a attributename=href>",
        b"<a attributename=style>",
    ] {
        assert!(!libperfusion::xss(input), "{:?}", input.escape_ascii());
    }

    assert!(!libperfusion::xss(&overlong_svg));
    assert!(libperfusion::xss(b"<a attributename=onclick>"));
    assert!(libperfusion::xss(b"xlink=1"));
}

#[test]
fn sqli_unicode_uppercase_matches_go_keywords() {
    assert_eq!(
        libperfusion::sqli("1 UNıON SELECT 1".as_bytes()).unwrap().as_str(),
        "1UE1"
    );
    assert_eq!(
        libperfusion::sqli("1 UNION ſELECT 1".as_bytes()).unwrap().as_str(),
        "1UE1"
    );
}

#[test]
fn sqli_uses_current_like_operator_folding() {
    assert_eq!(libperfusion::sqli(b"1 LIKE (SELECT 1)").unwrap().as_str(), "1o(E1");
    assert_eq!(
        libperfusion::sqli(b"' OR (8459 LIKE (SELECT 8459)) * 4906 -- ")
            .unwrap()
            .as_str(),
        "s&(1o"
    );
}
