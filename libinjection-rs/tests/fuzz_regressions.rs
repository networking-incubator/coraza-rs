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

#[path = "common/safety.rs"]
mod safety;

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
                libperfusion::sqli(&regression.input).is_some(),
                expected,
                "{} SQL verdict",
                regression.name
            );
        }
        if let Some(expected) = regression.expected_xss {
            assert_eq!(
                libperfusion::xss(&regression.input),
                expected,
                "{} XSS verdict",
                regression.name
            );
        }
    }
}

fn exercise_safety(regression: &Regression<'_>) {
    safety::exercise(&regression.input, regression.name);
    std::hint::black_box(libperfusion::sqli(&regression.input));
    std::hint::black_box(libperfusion::xss(&regression.input));
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
