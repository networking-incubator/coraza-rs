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

//! Deterministic raw-byte checks for parser progress and token bounds.

#![expect(
    clippy::tests_outside_test_module,
    reason = "Cargo integration test targets consist of tests."
)]

#[path = "common/safety.rs"]
mod safety;

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

#[test]
fn deterministic_raw_and_grammar_inputs_preserve_parser_progress() {
    let cases = generated_inputs();
    assert_eq!(cases.len(), 768);
    for (case_id, input) in cases {
        std::hint::black_box(libperfusion::sqli(&input));
        std::hint::black_box(libperfusion::xss(&input));
        safety::exercise(&input, &case_id);
    }
}
