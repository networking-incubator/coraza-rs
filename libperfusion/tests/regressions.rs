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
fn sqli_keeps_extended_stored_procedures_as_barewords() {
    // `XP_CMDSHELL` was added to the dialect table as a Function and that
    // *lost* detections: the listed `s&1Tn` and `s;Tns` fingerprints became
    // the unlisted `s&1Tf` and `s;Tfs`. `EXEC`/`EXECUTE` already carries the
    // Tsql classification that makes the shape recognisable, so the
    // procedure name is left as a Bareword, exactly as the qualified Oracle
    // package names are. The first payload is sqli-phpids.txt:264 of the
    // pinned upstream sample data.
    for payload in [
        b"'AND 1.-1LIKE.1 EXEC xp_cmdshell 'dir ".as_slice(),
        b"'; EXEC xp_cmdshell 'dir'--",
        b"1; EXEC xp_cmdshell('dir')",
    ] {
        assert!(
            libperfusion::sqli(payload).is_some(),
            "extended stored procedure call not detected: {:?}",
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

    // Named references are case-sensitive, so the case variants are other
    // characters or no reference at all: `&Colon;` is U+2237 PROPORTION,
    // and neither `&tab;` nor `&NUL;` is defined. Decoding them as `:`,
    // tab and NUL reported schemes a browser never resolves.
    for benign in [
        br#"<a href="ja&tab;vascript:alert(1)">"#.as_slice(),
        br#"<a href="ja&TAB;vascript:alert(1)">"#,
        br#"<a href="ja&NUL;vascript:alert(1)">"#,
    ] {
        assert!(
            !libperfusion::xss(benign),
            "undefined or differently-cased named reference decoded: {:?}",
            String::from_utf8_lossy(benign)
        );
    }

    // The CSS check is where the colon itself has to decode, so it is what
    // shows `&Colon;` (U+2237) apart from `&colon;` (U+003A). A URL
    // attribute cannot: it matches the bare `JAVA` prefix upstream uses,
    // whatever follows it.
    assert!(libperfusion::xss_in_css_value(
        b"background:url(javascript&colon;alert(1))"
    ));
    assert!(!libperfusion::xss_in_css_value(
        b"background:url(javascript&Colon;alert(1))"
    ));
    assert!(!libperfusion::xss_in_css_value(
        b"background:url(javascript&COLON;alert(1))"
    ));
    assert!(libperfusion::xss_in_css_value(
        b"background:url(java&NewLine;script:alert(1))"
    ));
    assert!(!libperfusion::xss_in_css_value(
        b"background:url(java&newline;script:alert(1))"
    ));

    // The defined spellings keep working, in their own case.
    assert!(libperfusion::xss(br#"<a href="ja&Tab;vascript:alert(1)">"#));
    assert!(libperfusion::xss(br#"<a href="java&NewLine;script:alert(1)">"#));
}

#[test]
fn xss_lookup_fast_paths_do_not_lose_encoded_or_odd_shaped_names() {
    // `black_attr` skips the table scan for a `(first letter, length)` shape
    // the table does not hold, and `is_black_url` skips the scheme scan for
    // a first byte no scheme starts with. Neither may be reachable by an
    // attacker: an entity-encoded first byte is still `&`, the leading
    // bytes the URL comparison ignores are stripped before the check, and a
    // NUL anywhere in a name is removed before its length is taken.
    for payload in [
        // An entity hides the scheme's first letter behind `&`.
        br#"<a href="&#106;avascript:alert(1)">"#.as_slice(),
        br#"<a href="&#x6a;avascript:alert(1)">"#,
        br#"<a href="&#0000106;avascript:alert(1)">"#,
        // Leading control bytes and NULs inside the scheme.
        b"<a href=\"\x01\x02javascript:alert(1)\">",
        b"<a href=\"ja\0vascript:alert(1)\">",
        // NULs inside the attribute name change its byte length.
        b"<a h\0ref=\"javascript:alert(1)\">",
        b"<a \0\0href=\"javascript:alert(1)\">",
        b"<a s\0rc=\"javascript:alert(1)\">",
        // Mixed case reaches the table through the same normalisation.
        br#"<a HrEf="JaVaScRiPt:alert(1)">"#,
        // A local supplement row, to cover the widened table.
        br#"<img srcset="javascript:alert(1)">"#,
    ] {
        assert!(
            libperfusion::xss(payload),
            "fast path lost a detection: {:?}",
            String::from_utf8_lossy(payload)
        );
    }

    // `href="java-logo.png"` is deliberately absent: `is_black_url` matches
    // the bare `JAVA` upstream uses to cover `java:` and `javascript:`, so
    // the pinned references flag it too. Only the CSS `url()` check, which
    // does take relative paths, requires the colon.
    for benign in [
        br#"<a href="/docs/javadoc/index.html">"#.as_slice(),
        br#"<a hreflang="en" lang="en">text</a>"#,
        br#"<div data-javascript="no">"#,
        br#"<img srcset="/img/a.png 1x, /img/b.png 2x">"#,
    ] {
        assert!(
            !libperfusion::xss(benign),
            "fast path gained a false positive: {:?}",
            String::from_utf8_lossy(benign)
        );
    }
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
        // The colon may be encoded; the scheme name may be split by the
        // bytes a URL parser drops.
        b"background:url(javascript&#58;alert(1))",
        b"background:url(java\nscript:alert(1))",
        b"background:url(vbscript:msgbox(1))",
        b"background:url(view-source:https://example.com/)",
        // The identifier-boundary rule must not hide a real one that
        // follows a benign property of the same ending.
        b"scroll-behavior:smooth;behavior:url(#default#time2)",
        b"overscroll-behavior:contain;x:expression(alert(1))",
        // At the very start, and after separators that end an identifier.
        b"behavior:url(#default#time2)",
        b"x:EXPRESSION(alert(1))",
        b"{expression(alert(1))}",
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
        // Real properties that end with one of the needles. Matching
        // `BEHAVIOR:` anywhere flagged every one of these.
        b"scroll-behavior:smooth",
        b"overscroll-behavior:contain",
        b"overscroll-behavior-y:none",
        b"-webkit-overflow-scrolling:touch;scroll-behavior:auto",
        b"--my-expression:1",
        b"foo-moz-binding:1",
        // A relative path is the common case a bare scheme name got wrong:
        // matching "JAVA" without its colon flagged every java-* asset.
        b"background:url(java-logo.png)",
        b"background:url('javascript-hints.svg')",
        b"background:url(/assets/javastuff/sprite.png)",
        b"background:url(vbscript-tutorial.gif)",
        b"background:url(view-source-icon.png)",
    ] {
        assert!(
            !libperfusion::xss_in_css_value(benign),
            "ordinary CSS flagged: {:?}",
            String::from_utf8_lossy(benign)
        );
    }
}
