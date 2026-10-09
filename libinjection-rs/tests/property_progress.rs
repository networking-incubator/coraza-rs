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

//! Deterministic raw-byte/property checks for parser progress and span bounds.
#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]

use libinjection::{AnalysisSnapshot, analyze_sqli, analyze_xss};
#[cfg(feature = "legacy")]
use libinjection::{Html5TokenKind, XssHtmlContext, html5_visit, sqli_fold_visit, sqli_tokenize_visit};

const SEED: u64 = 0x8D26_4F73_0AB1_C5E9;
const FRAGMENTS: [&[u8]; 23] = [
    b"SELECT",
    b"UNION",
    b"' OR '1'='1",
    b"-- ",
    b"/* comment */",
    b"#line",
    b"1e+",
    b"\\\"",
    b"&&",
    b"||",
    b"<script>",
    b"</script>",
    b"<a href=javascript:",
    b" onerror=alert(1)>",
    b"<!--",
    b"-->",
    b"<![CDATA[",
    b"]]>",
    b"&#x14a;",
    b"\0",
    b"\xff",
    b"/>",
    b"%>",
];
const RAW_ALPHABET: &[u8] = b"abcXYZ012 ' \"`<>=/\\#-*;:&%\0\xff\x80\n\r";

fn bounded_index(value: u64, len: usize) -> usize {
    let modulus = u64::try_from(len).unwrap_or(u64::MAX);
    usize::try_from(value % modulus).unwrap_or_default()
}

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn generated_inputs() -> Vec<(String, Vec<u8>)> {
    let mut cases = Vec::with_capacity(768);
    let mut state = SEED;

    for case_index in 0..384 {
        let len = bounded_index(next(&mut state), 193);
        let mut input = Vec::with_capacity(len);
        for _ in 0..len {
            let index = bounded_index(next(&mut state), RAW_ALPHABET.len());
            input.push(RAW_ALPHABET.get(index).copied().unwrap_or_default());
        }
        cases.push((format!("raw-{case_index:04}"), input));
    }

    for case_index in 0..384 {
        let pieces = 1 + bounded_index(next(&mut state), 10);
        let mut input = Vec::new();
        for _ in 0..pieces {
            let index = bounded_index(next(&mut state), FRAGMENTS.len());
            input.extend_from_slice(FRAGMENTS.get(index).copied().unwrap_or_default());
            if next(&mut state) & 1 == 0 {
                input.push(b' ');
            }
        }
        cases.push((format!("grammar-{case_index:04}"), input));
    }
    cases
}

fn assert_snapshot_spans(snapshot: &AnalysisSnapshot, input: &[u8], case_id: &str, label: &str, input_hex: &str) {
    for span in &snapshot.evidence.spans {
        let start = span.offset;
        let end = start.saturating_add(span.len);
        assert!(
            start < end,
            "{case_id} ({input_hex}): {label} evidence span must identify at least one input byte"
        );
        assert!(
            end <= input.len(),
            "{case_id} ({input_hex}): {label} evidence span {start}..{end} exceeds input length {}",
            input.len()
        );
    }
}

fn hex(input: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        output.push(char::from(
            DIGITS.get(usize::from(byte >> 4)).copied().unwrap_or_default(),
        ));
        output.push(char::from(
            DIGITS.get(usize::from(byte & 0x0F)).copied().unwrap_or_default(),
        ));
    }
    output
}

#[test]
fn deterministic_raw_and_grammar_inputs_preserve_parser_invariants() {
    let cases = generated_inputs();
    assert_eq!(cases.len(), 768);
    for (case_id, input) in cases {
        let input_hex = hex(&input);
        let sqli = analyze_sqli(&input);
        let xss = analyze_xss(&input);
        assert_snapshot_spans(&sqli, &input, &case_id, "SQL", &input_hex);
        assert_snapshot_spans(&xss, &input, &case_id, "XSS", &input_hex);

        #[cfg(feature = "legacy")]
        {
            let contexts = [
                XssHtmlContext::Data,
                XssHtmlContext::AttrUnquoted,
                XssHtmlContext::AttrSingle,
                XssHtmlContext::AttrDouble,
                XssHtmlContext::AttrBacktick,
            ];
            // Calling the complete public detectors exercises their internal
            // multi-context and parser loops. Token callbacks additionally cap
            // emitted records so a future zero-width loop fails this test.
            std::hint::black_box(libinjection::detect_sqli(&input));
            std::hint::black_box(libinjection::detect_xss(&input));
            for flags in [9_u32, 17, 10, 18, 12, 20] {
                let mut count = 0_usize;
                sqli_tokenize_visit(&input, flags, |token| {
                    count += 1;
                    assert!(
                        count <= input.len() + 2,
                        "{case_id} ({input_hex}): SQL tokenizer stopped progressing"
                    );
                    assert!(
                        token.pos.checked_add(token.len).is_some_and(|end| end <= input.len()),
                        "{case_id} ({input_hex}): SQL token span exceeds the input"
                    );
                });
                count = 0;
                sqli_fold_visit(&input, flags, |token| {
                    count += 1;
                    assert!(
                        count <= input.len() + 2,
                        "{case_id} ({input_hex}): SQL folder stopped progressing"
                    );
                    assert!(
                        token.pos.checked_add(token.len).is_some_and(|end| end <= input.len()),
                        "{case_id} ({input_hex}): folded SQL token span exceeds the input"
                    );
                });
            }
            for context in contexts {
                let mut count = 0_usize;
                let input_start = input.as_ptr() as usize;
                let input_end = input_start + input.len();
                html5_visit(&input, context, |kind: Html5TokenKind, value| {
                    count += 1;
                    assert!(
                        count <= input.len() * 2 + 16,
                        "{case_id} ({input_hex}): HTML5 tokenizer stopped progressing"
                    );
                    let token_start = value.as_ptr() as usize;
                    let token_end = token_start + value.len();
                    assert!(
                        token_start >= input_start && token_end <= input_end,
                        "{case_id} ({input_hex}): {kind:?} token is not a slice of the original input"
                    );
                });
            }
        }
    }
}
