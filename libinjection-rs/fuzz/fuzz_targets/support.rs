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

use libinjection::{
    AnalysisSnapshot, Html5TokenKind, XssHtmlContext, analyze_sqli, analyze_xss, detect_sqli, detect_xss, html5_visit,
    sqli_fold_visit, sqli_tokenize_visit,
};

const SQL_FLAGS: [u32; 6] = [9, 17, 10, 18, 12, 20];
const HTML_CONTEXTS: [XssHtmlContext; 5] = [
    XssHtmlContext::Data,
    XssHtmlContext::AttrUnquoted,
    XssHtmlContext::AttrSingle,
    XssHtmlContext::AttrDouble,
    XssHtmlContext::AttrBacktick,
];
const SQL_FRAGMENTS: [&[u8]; 18] = [
    b"SELECT",
    b"UNION SELECT",
    b"' OR '1'='1",
    b"-- ",
    b"/* comment */",
    b"# comment",
    b"WAITFOR DELAY",
    b"xp_cmdshell",
    b"1e+",
    b"\\\"",
    b"%75%6e%69%6f%6e",
    b"un\0ion",
    b"`identifier`",
    b"; DROP TABLE users",
    b"=",
    b"<",
    b"\xff",
    b"\0",
];
const HTML_FRAGMENTS: [&[u8]; 18] = [
    b"<script>",
    b"</script>",
    b"<img src=x onerror=alert(1)>",
    b"<a href=javascript:",
    b" onload=alert(1)>",
    b"<!--",
    b"-->",
    b"<![CDATA[",
    b"]]>",
    b"&#x3c;script&#x3e;",
    b"<svg/onload=alert(1)>",
    b"<iframe srcdoc=",
    b"<x ",
    b"=\"javascript:alert(1)\"",
    b"`",
    b"%3cscript%3e",
    b"\xff",
    b"\0",
];

pub(crate) fn exercise_raw(input: &[u8]) {
    exercise_sql(input);
    exercise_html(input);
}

pub(crate) fn exercise_sql(input: &[u8]) {
    assert_snapshot(analyze_sqli(input), input);
    std::hint::black_box(detect_sqli(input));

    for flags in SQL_FLAGS {
        let mut count = 0_usize;
        sqli_tokenize_visit(input, flags, |token| {
            count = count.saturating_add(1);
            assert!(count <= input.len().saturating_add(2));
            assert!(token.pos.checked_add(token.len).is_some_and(|end| end <= input.len()));
        });
        count = 0;
        sqli_fold_visit(input, flags, |token| {
            count = count.saturating_add(1);
            assert!(count <= input.len().saturating_add(2));
            assert!(token.pos.checked_add(token.len).is_some_and(|end| end <= input.len()));
        });
    }
}

pub(crate) fn exercise_html(input: &[u8]) {
    assert_snapshot(analyze_xss(input), input);
    std::hint::black_box(detect_xss(input));

    for context in HTML_CONTEXTS {
        let start = input.as_ptr() as usize;
        let end = start.saturating_add(input.len());
        let mut count = 0_usize;
        html5_visit(input, context, |kind: Html5TokenKind, value| {
            count = count.saturating_add(1);
            assert!(count <= input.len().saturating_mul(2).saturating_add(16));
            let token_start = value.as_ptr() as usize;
            let token_end = token_start.saturating_add(value.len());
            assert!(
                token_start >= start && token_end <= end,
                "{kind:?} token left input range"
            );
        });
    }
}

fn assert_snapshot(snapshot: AnalysisSnapshot, input: &[u8]) {
    for span in &snapshot.evidence.spans {
        let start = span.offset;
        let end = start
            .checked_add(span.len)
            .expect("evidence span length overflow");
        assert!(end <= input.len());
    }
}

pub(crate) fn compose_grammar(input: &[u8], fragments: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len().min(4096).saturating_mul(4));
    for controls in input.chunks(2).take(256) {
        let Some(selector) = controls.first().copied() else {
            continue;
        };
        let fragment_index = usize::from(selector) % fragments.len();
        if let Some(fragment) = fragments.get(fragment_index) {
            output.extend_from_slice(fragment);
        }
        if controls.get(1).is_some_and(|separator| *separator & 1 == 1) {
            output.push(match (controls.get(1).copied().unwrap_or_default() >> 1) & 0b111 {
                0 => b' ',
                1 => b'\0',
                2 => b'/',
                3 => b';',
                4 => b'\'',
                5 => b'`',
                6 => b'\xff',
                _ => b'=',
            });
        }
    }
    output
}

pub(crate) fn sql_grammar(input: &[u8]) -> Vec<u8> {
    compose_grammar(input, &SQL_FRAGMENTS)
}

pub(crate) fn html_grammar(input: &[u8]) -> Vec<u8> {
    compose_grammar(input, &HTML_FRAGMENTS)
}
