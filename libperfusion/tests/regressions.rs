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

#[test]
fn sqli_mysql_hash_comment_terminates_an_injected_string() {
    // Upstream suppresses every "sc" whose comment starts with '#', which
    // makes "admin'#" -- a complete MySQL login bypass -- invisible.
    assert_eq!(libperfusion::sqli(b"admin'#").unwrap().as_str(), "sc");
    assert_eq!(libperfusion::sqli(b"admin'#x").unwrap().as_str(), "sc");
    assert_eq!(libperfusion::sqli(b"1'#").unwrap().as_str(), "sc");

    // The suppression is kept for text that merely contains a '#', and for a
    // self-contained literal the input opened itself.
    assert!(libperfusion::sqli(b"1# blah blah").is_none());
    assert!(libperfusion::sqli(b"issue #42 is open").is_none());
    assert!(libperfusion::sqli(b"'abc' #note").is_none());
}

#[test]
fn sqli_ansi_comment_with_trailing_whitespace_terminates_the_statement() {
    // ANSI SQL and MySQL both require whitespace after "--", so "admin'-- "
    // is the more canonical terminator; upstream suppresses it and keeps the
    // rarer "admin'--".
    assert_eq!(libperfusion::sqli(b"admin'-- ").unwrap().as_str(), "sc");
    assert_eq!(libperfusion::sqli(b"admin'--\t").unwrap().as_str(), "sc");
    assert_eq!(libperfusion::sqli(b"admin'--").unwrap().as_str(), "sc");

    // Prose after the comment is still treated as prose.
    assert!(libperfusion::sqli(b"admin'-- see note").is_none());
    assert!(libperfusion::sqli(b"foo--").is_none());
    assert!(libperfusion::sqli(b"--blah").is_none());
}

#[test]
fn sqli_detects_short_stacked_statements() {
    // Length-4 fingerprints are thinly covered upstream, so a stacked
    // statement that ends cleanly passed while the same payload with one
    // trailing byte was caught.
    for payload in [
        b"1;WAITFOR DELAY '0:0:5'".as_slice(),
        b"1;SHUTDOWN",
        b"1;SHUTDOWN--",
        b"1;USE master",
        b"1; ATTACH DATABASE '/tmp/x' AS x",
        b"1; VACUUM INTO '/tmp/x'",
        b"1; COPY t FROM PROGRAM 'id'",
    ] {
        assert!(
            libperfusion::sqli(payload).is_some(),
            "stacked statement not detected: {:?}",
            String::from_utf8_lossy(payload)
        );
    }
}

#[test]
fn sqli_classifies_modern_dialect_functions() {
    // A callable absent from the table becomes a Bareword, which moves the
    // fingerprint from the listed "s&f(" family to an unlisted one.
    for payload in [
        b"1' OR JSON_EXTRACT(a,'$.b')='x".as_slice(),
        b"1' OR JSON_VALUE(a,'$.b')='x",
        b"1' AND GTID_SUBSET(version(),1)--",
        b"1' OR LO_IMPORT('/etc/passwd')='x",
        b"1' OR OPENJSON(a)='x",
        b"1' OR STRING_SPLIT(a,',')='x",
        b"1; EXEC xp_cmdshell('dir')",
    ] {
        assert!(
            libperfusion::sqli(payload).is_some(),
            "modern dialect call not detected: {:?}",
            String::from_utf8_lossy(payload)
        );
    }
}

#[test]
fn sqli_keeps_qualified_oracle_package_calls() {
    // The table carries these as fully qualified names, so the bare package
    // name must not be classified separately: that would stop the lexer
    // merging the dotted form and lose the detection.
    for payload in [
        b"1' OR UTL_INADDR.GET_HOST_ADDRESS('x')='y".as_slice(),
        b"1' OR DBMS_PIPE.RECEIVE_MESSAGE('a',1)='b",
    ] {
        assert!(
            libperfusion::sqli(payload).is_some(),
            "qualified package call not detected: {:?}",
            String::from_utf8_lossy(payload)
        );
    }
}

#[test]
fn sqli_added_keywords_do_not_flag_ordinary_prose() {
    // The additions above are only safe if they leave English text alone.
    for text in [
        b"please copy the program to the new window".as_slice(),
        b"I will attach the file and detach the drive",
        b"Please detach the trailer, then vacuum it",
        b"print this copy for me",
        b"a copy of the attached program",
        b"hard copy requested",
        b"Copy, print, and vacuum.",
        b"name=copy&action=print",
    ] {
        assert!(
            libperfusion::sqli(text).is_none(),
            "ordinary prose flagged as SQLi: {:?}",
            String::from_utf8_lossy(text)
        );
    }
}

#[test]
fn xss_detects_url_bearing_attributes() {
    // These attributes carry a URL but were absent from the table, and
    // neither IMG nor SOURCE is a black tag, so there was no backstop.
    for payload in [
        br#"<img srcset="javascript:alert(1)">"#.as_slice(),
        br#"<source srcset="javascript:alert(1)">"#,
        br#"<a ping="javascript:alert(1)">"#,
        br#"<blockquote cite="javascript:alert(1)">"#,
        br#"<img longdesc="javascript:alert(1)">"#,
        br#"<html manifest="javascript:alert(1)">"#,
    ] {
        assert!(
            libperfusion::xss(payload),
            "URL attribute not detected: {:?}",
            String::from_utf8_lossy(payload)
        );
    }

    // A Url-typed attribute only flags a script-capable scheme, so ordinary
    // markup is untouched.
    for benign in [
        br#"<img srcset="photo-2x.png 2x, photo.png 1x">"#.as_slice(),
        br#"<a ping="/track">ok</a>"#,
        br#"<blockquote cite="https://example.com/post">hi</blockquote>"#,
        br#"<div data="/model.swf">"#,
    ] {
        assert!(
            !libperfusion::xss(benign),
            "ordinary markup flagged: {:?}",
            String::from_utf8_lossy(benign)
        );
    }
}

#[test]
fn xss_decodes_scheme_relevant_named_entities() {
    // &Tab; and friends are valid HTML5 named references that browsers
    // honour inside an attribute value, so they split a scheme.
    for payload in [
        br#"<a href="ja&Tab;vascript:alert(1)">"#.as_slice(),
        br#"<a href="java&NewLine;script:alert(1)">"#,
        br#"<a href="javascript&colon;alert(1)">"#,
    ] {
        assert!(
            libperfusion::xss(payload),
            "named-entity scheme not detected: {:?}",
            String::from_utf8_lossy(payload)
        );
    }

    // Unrelated named entities still read as a literal '&'.
    assert!(!libperfusion::xss(b"<p>Tom &amp; Jerry</p>"));
    assert!(!libperfusion::xss(b"a &lt; b and c &gt; d"));
}

#[test]
fn xss_covers_blob_filesystem_and_mathml() {
    assert!(libperfusion::xss(br#"<a href="blob:https://x/y">"#));
    assert!(libperfusion::xss(br#"<a href="filesystem:http://x/y">"#));
    assert!(libperfusion::xss(
        b"<math><maction actiontype=statusline#javascript:alert(1)>x</maction></math>"
    ));
    assert!(!libperfusion::xss(br#"<a href="https://example.com/">link</a>"#));
}

#[test]
fn xss_detects_script_in_a_standalone_css_value() {
    // The HTML contexts only see a value once it is inside a tag, so a value
    // reflected straight into style="..." reaches them in the one form they
    // cannot read.
    for payload in [
        b"background:url(javascript:alert(1))".as_slice(),
        b"width:expression(alert(1))",
        b"x:EXPRESSION(alert(1))",
        b"-moz-binding:url(http://x/x.xml#x)",
        b"behavior:url(#default#time2)",
        b"background:url('javascript:alert(1)')",
        b"background:url(JaVaScRiPt:alert(1))",
    ] {
        assert!(
            libperfusion::xss_in_css_value(payload),
            "CSS payload not detected: {:?}",
            String::from_utf8_lossy(payload)
        );
    }

    // Ordinary stylesheet content, including the data: URLs that make up
    // most inline images, must not flag.
    for benign in [
        b"background:url(/img/bg.png)".as_slice(),
        b"background:url(data:image/png;base64,iVBORw0KGgo=)",
        b"color:red; font-weight:bold",
        b"background:url('https://cdn.example.com/x.png')",
        b"a normal sentence about expression and behaviour",
        b"My expression of gratitude",
        b"url(",
        b"",
    ] {
        assert!(
            !libperfusion::xss_in_css_value(benign),
            "ordinary CSS flagged: {:?}",
            String::from_utf8_lossy(benign)
        );
    }
}
