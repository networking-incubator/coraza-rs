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

//! The reviewed oracle differences of `tests/parity/reviewed-differences.tsv`,
//! shared by the two differential tests and the `speed` benchmark.

use std::collections::HashSet;

const HEADER: &str = "oracle\tsuite\tid\tinput_hex\toracle_verdict\tlibperfusion_verdict\treason";
const VERDICTS: [&str; 4] = ["sqli:0", "sqli:1", "xss:0", "xss:1"];

/// One reviewed difference: the exact input and both verdicts.
pub(crate) struct Reviewed {
    pub(crate) oracle: &'static str,
    pub(crate) suite: &'static str,
    pub(crate) id: &'static str,
    pub(crate) input: Vec<u8>,
    pub(crate) oracle_verdict: &'static str,
    pub(crate) libperfusion_verdict: &'static str,
}

impl Reviewed {
    /// Whether an observed difference is this row: same bytes, same verdicts.
    pub(crate) fn matches(&self, input: &[u8], oracle_verdict: &str, libperfusion_verdict: &str) -> bool {
        self.input == input
            && self.oracle_verdict == oracle_verdict
            && self.libperfusion_verdict == libperfusion_verdict
    }
}

/// Every row of the file. Panics on a malformed row or on an id repeated
/// within its suite.
pub(crate) fn all() -> Vec<Reviewed> {
    let mut lines = include_str!("../parity/reviewed-differences.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'));
    assert_eq!(lines.next(), Some(HEADER), "reviewed-differences.tsv header changed");
    let mut keys = HashSet::new();
    lines
        .map(|line| {
            let fields: Vec<&'static str> = line.split('\t').collect();
            assert_eq!(
                fields.len(),
                7,
                "reviewed difference needs 7 tab-separated fields: {line:?}"
            );
            let field = |index: usize| fields.get(index).copied().unwrap_or_default();
            let (oracle, suite, id, input_hex) = (field(0), field(1), field(2), field(3));
            let (oracle_verdict, libperfusion_verdict, reason) = (field(4), field(5), field(6));
            assert!(matches!(oracle, "go" | "c"), "unknown oracle: {line:?}");
            assert!(
                matches!(suite, "direct" | "generated") || suite.starts_with("speed:"),
                "unknown suite: {line:?}"
            );
            assert!(!id.is_empty() && !reason.is_empty(), "empty id or reason: {line:?}");
            assert!(
                input_hex.len() % 2 == 0 && input_hex.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
                "input_hex must be lower-case hex bytes: {line:?}"
            );
            let input = input_hex
                .as_bytes()
                .chunks(2)
                .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap_or_default(), 16).unwrap_or_default())
                .collect();
            assert!(
                VERDICTS.contains(&oracle_verdict)
                    && VERDICTS.contains(&libperfusion_verdict)
                    && oracle_verdict != libperfusion_verdict
                    && oracle_verdict.split(':').next() == libperfusion_verdict.split(':').next(),
                "verdicts must be two different <detector>:<0|1> values of one detector: {line:?}"
            );
            assert!(keys.insert((oracle, suite, id)), "id repeated in its suite: {line:?}");
            Reviewed {
                oracle,
                suite,
                id,
                input,
                oracle_verdict,
                libperfusion_verdict,
            }
        })
        .collect()
}

/// The rows one oracle's suite must observe.
pub(crate) fn rows(oracle: &str, suite: &str) -> Vec<Reviewed> {
    all()
        .into_iter()
        .filter(|row| row.oracle == oracle && row.suite == suite)
        .collect()
}
