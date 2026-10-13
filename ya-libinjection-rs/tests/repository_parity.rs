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

//! Compare this port with the in-repository libinjection crate and its pinned
//! corpus, without requiring a separate upstream checkout.

#[path = "../../libinjection-rs/tests/common/corpus.rs"]
#[allow(dead_code)]
mod corpus;

use std::{fs, path::Path};

use corpus::{DriverKind, parse_corpus_file};

fn cases() -> Vec<corpus::CorpusCase> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../libinjection-rs/tests/corpus");
    let mut paths: Vec<_> = fs::read_dir(dir)
        .expect("read repository corpus")
        .map(|entry| entry.expect("read corpus entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("test-") && name.ends_with(".txt"))
        })
        .collect();
    paths.sort_unstable();
    paths
        .iter()
        .map(|path| parse_corpus_file(path).unwrap_or_else(|error| panic!("{}: {error:?}", path.display())))
        .collect()
}

#[test]
fn corpus_verdicts_match_fixtures_and_sibling_crate() {
    let cases = cases();
    let mut sqli_fixtures = 0;
    let mut xss_fixtures = 0;

    assert!(!cases.is_empty(), "repository corpus has no fixtures");
    for case in cases {
        let input = case.input.as_bytes();
        let ours_sqli = libperfusion::sqli(input);
        let ours_fingerprint = ours_sqli.as_ref().map_or("", |fingerprint| fingerprint.as_str());
        let reference_sqli = libinjection::detect_sqli(input);
        let reference_fingerprint = reference_sqli.fingerprint.as_str().unwrap_or("");
        assert_eq!(
            ours_fingerprint,
            reference_fingerprint,
            "SQLi mismatch in {} for {:?}",
            case.name,
            input.escape_ascii()
        );

        let ours_xss = libperfusion::xss(input);
        let reference_xss = libinjection::detect_xss(input);
        assert_eq!(
            ours_xss,
            reference_xss,
            "XSS mismatch in {} for {:?}",
            case.name,
            input.escape_ascii()
        );

        match DriverKind::from_name(&case.name) {
            Some(DriverKind::Sqli) => {
                sqli_fixtures += 1;
                assert_eq!(ours_fingerprint, case.expected, "SQLi fixture {}", case.name);
            },
            Some(DriverKind::Xss) => {
                xss_fixtures += 1;
                let expected = match case.expected.as_str() {
                    "0" => false,
                    "1" => true,
                    other => panic!("invalid XSS expectation in {}: {other:?}", case.name),
                };
                assert_eq!(ours_xss, expected, "XSS fixture {}", case.name);
            },
            _ => {},
        }
    }

    assert!(sqli_fixtures > 0, "repository corpus has no SQLi fixtures");
    assert!(xss_fixtures > 0, "repository corpus has no XSS fixtures");
}
