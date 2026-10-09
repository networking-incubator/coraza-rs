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

//! Safety and optional expected-verdict checks for promoted fuzz findings.
#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]
#![expect(clippy::panic, reason = "malformed regression fixtures should fail loudly")]

use std::collections::HashSet;

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

#[derive(Debug)]
struct Regression<'a> {
    name: &'a str,
    input: Vec<u8>,
    expected_sqli: Option<bool>,
    expected_xss: Option<bool>,
}

#[test]
fn promoted_fuzz_findings_preserve_parser_safety_and_expected_verdicts() {
    let manifest = include_str!("fuzz_regressions/inputs.hex");
    let mut seen = HashSet::new();
    let regressions = manifest
        .lines()
        .enumerate()
        .filter_map(|(line_index, line)| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let fields: Vec<_> = line.split('\t').collect();
            assert!(
                (2..=4).contains(&fields.len()),
                "line {}: expected name, hex, optional verdicts",
                line_index + 1
            );
            let name = fields.first().copied().unwrap_or_default();
            assert!(!name.is_empty(), "line {}: empty regression name", line_index + 1);
            assert!(
                seen.insert(name),
                "line {}: duplicate regression name {name:?}",
                line_index + 1
            );
            let encoded = fields.get(1).copied().unwrap_or_default();
            let input =
                decode_hex(encoded).unwrap_or_else(|| panic!("line {}: malformed hexadecimal input", line_index + 1));
            let mut regression = Regression {
                name,
                input,
                expected_sqli: None,
                expected_xss: None,
            };
            for expectation in fields.iter().skip(2) {
                match expectation.split_once('=') {
                    Some(("sqli", value)) => {
                        assert!(
                            regression.expected_sqli.is_none(),
                            "line {}: duplicate SQL expectation",
                            line_index + 1
                        );
                        regression.expected_sqli = Some(parse_bool(value, line_index + 1));
                    },
                    Some(("xss", value)) => {
                        assert!(
                            regression.expected_xss.is_none(),
                            "line {}: duplicate XSS expectation",
                            line_index + 1
                        );
                        regression.expected_xss = Some(parse_bool(value, line_index + 1));
                    },
                    _ => panic!("line {}: malformed expectation {expectation:?}", line_index + 1),
                }
            }
            Some(regression)
        })
        .collect::<Vec<_>>();

    assert!(!regressions.is_empty(), "fuzz regression manifest is empty");
    for regression in regressions {
        exercise_safety(&regression);
        if let Some(expected) = regression.expected_sqli {
            assert_eq!(
                detect_sqli(&regression.input).detected,
                expected,
                "{} SQL verdict",
                regression.name
            );
        }
        if let Some(expected) = regression.expected_xss {
            assert_eq!(
                detect_xss(&regression.input),
                expected,
                "{} XSS verdict",
                regression.name
            );
        }
    }
}

fn exercise_safety(regression: &Regression<'_>) {
    let input = regression.input.as_slice();
    assert_snapshot(&analyze_sqli(input), regression);
    assert_snapshot(&analyze_xss(input), regression);
    std::hint::black_box(detect_sqli(input));
    std::hint::black_box(detect_xss(input));

    for flags in SQL_FLAGS {
        let mut count = 0_usize;
        sqli_tokenize_visit(input, flags, |token| {
            count = count.saturating_add(1);
            assert!(
                count <= input.len().saturating_add(2),
                "{} SQL tokenizer progress",
                regression.name
            );
            assert!(
                token.pos.checked_add(token.len).is_some_and(|end| end <= input.len()),
                "{} SQL token outside input",
                regression.name
            );
        });
        count = 0;
        sqli_fold_visit(input, flags, |token| {
            count = count.saturating_add(1);
            assert!(
                count <= input.len().saturating_add(2),
                "{} SQL folder progress",
                regression.name
            );
            assert!(
                token.pos.checked_add(token.len).is_some_and(|end| end <= input.len()),
                "{} folded SQL token outside input",
                regression.name
            );
        });
    }

    for context in HTML_CONTEXTS {
        let start = input.as_ptr() as usize;
        let end = start.saturating_add(input.len());
        let mut count = 0_usize;
        html5_visit(input, context, |kind: Html5TokenKind, value| {
            count = count.saturating_add(1);
            assert!(
                count <= input.len().saturating_mul(2).saturating_add(16),
                "{} HTML tokenizer progress",
                regression.name
            );
            let token_start = value.as_ptr() as usize;
            let token_end = token_start.saturating_add(value.len());
            assert!(
                token_start >= start && token_end <= end,
                "{} {kind:?} token left input range",
                regression.name
            );
        });
    }
}

fn assert_snapshot(snapshot: &AnalysisSnapshot, regression: &Regression<'_>) {
    for span in &snapshot.evidence.spans {
        let start = span.offset;
        assert!(
            start
                .checked_add(span.len)
                .is_some_and(|end| end <= regression.input.len()),
            "{} evidence span outside input",
            regression.name
        );
    }
}

fn parse_bool(value: &str, line_index: usize) -> bool {
    match value {
        "0" => false,
        "1" => true,
        _ => panic!("line {line_index}: expected boolean 0 or 1, found {value:?}"),
    }
}

fn decode_hex(encoded: &str) -> Option<Vec<u8>> {
    if !encoded.len().is_multiple_of(2) {
        return None;
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = char::from(*pair.first()?).to_digit(16)?;
            let low = char::from(*pair.get(1)?).to_digit(16)?;
            u8::try_from((high << 4) | low).ok()
        })
        .collect()
}
