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

//! Compare capped and caller-bounded libperfusion APIs on the repository corpus:
//! `cargo bench -p libperfusion --bench compare`.

#![expect(
    clippy::missing_docs_in_private_items,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    reason = "This private benchmark harness reports timings and fails fast on invalid local fixtures."
)]

#[path = "../tests/common/corpus.rs"]
#[expect(
    dead_code,
    reason = "This benchmark uses only the corpus parser and detector selector."
)]
mod corpus;

use std::{
    fs,
    hint::black_box,
    path::Path,
    time::{Duration, Instant},
};

use corpus::{DriverKind, parse_corpus_file};

const SAMPLE_COUNT: usize = 5;
const SAMPLE_TIME: Duration = Duration::from_millis(100);
const CHECK_EVERY_PASSES: usize = 64;

#[derive(Clone, Copy)]
enum Detector {
    Sqli,
    Xss,
}

struct Workload {
    name: &'static str,
    detector: Detector,
    inputs: Vec<Vec<u8>>,
}

fn workloads() -> Vec<Workload> {
    let mut workloads = [
        Workload {
            name: "SQLi hit",
            detector: Detector::Sqli,
            inputs: Vec::new(),
        },
        Workload {
            name: "SQLi miss",
            detector: Detector::Sqli,
            inputs: Vec::new(),
        },
        Workload {
            name: "XSS hit",
            detector: Detector::Xss,
            inputs: Vec::new(),
        },
        Workload {
            name: "XSS miss",
            detector: Detector::Xss,
            inputs: Vec::new(),
        },
    ];

    let corpus_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut paths: Vec<_> = fs::read_dir(corpus_dir)
        .expect("read repository corpus")
        .map(|entry| entry.expect("read corpus entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("test-") && name.ends_with(".txt"))
        })
        .collect();
    paths.sort_unstable();

    for path in &paths {
        let case = parse_corpus_file(path).unwrap_or_else(|error| panic!("{}: {error:?}", path.display()));
        let input = case.input.into_bytes();
        let sqli = libperfusion::sqli(&input);
        let xss = libperfusion::xss(&input);

        match DriverKind::from_name(&case.name) {
            Some(DriverKind::Sqli) => {
                assert_eq!(
                    sqli.as_ref().map_or("", |value| value.as_str()),
                    case.expected,
                    "{}",
                    case.name
                );
            },
            Some(DriverKind::Xss) => {
                let expected = match case.expected.as_str() {
                    "0" => false,
                    "1" => true,
                    other => panic!("invalid XSS expectation in {}: {other:?}", case.name),
                };
                assert_eq!(xss, expected, "{}", case.name);
            },
            _ => {},
        }

        let sqli_workload = if sqli.is_some() { 0 } else { 1 };
        workloads[sqli_workload].inputs.push(input.clone());
        let xss_workload = if xss { 2 } else { 3 };
        workloads[xss_workload].inputs.push(input);
    }

    for workload in &workloads {
        assert!(!workload.inputs.is_empty(), "no fixtures for {}", workload.name);
    }
    println!("Using all {} repository corpus inputs.", paths.len());
    workloads.into_iter().collect()
}

fn measure<T>(inputs: &[Vec<u8>], detect: impl Fn(&[u8]) -> T) -> f64 {
    let started = Instant::now();
    let mut calls: u64 = 0;
    while started.elapsed() < SAMPLE_TIME {
        for _ in 0..CHECK_EVERY_PASSES {
            for input in inputs {
                black_box(detect(black_box(input)));
                calls += 1;
            }
        }
    }
    started.elapsed().as_secs_f64() * 1e9 / calls as f64
}

fn median(samples: &mut [f64]) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

fn benchmark<T>(inputs: &[Vec<u8>], detect: impl Fn(&[u8]) -> T) -> f64 {
    let mut samples = Vec::with_capacity(SAMPLE_COUNT);
    for _ in 0..SAMPLE_COUNT {
        samples.push(measure(inputs, &detect));
    }
    median(&mut samples)
}

fn main() {
    for workload in workloads() {
        let (capped, caller_bounded) = match workload.detector {
            Detector::Sqli => (
                benchmark(&workload.inputs, libperfusion::sqli),
                benchmark(&workload.inputs, |input| {
                    libperfusion::sqli_with_limit(input, input.len())
                }),
            ),
            Detector::Xss => (
                benchmark(&workload.inputs, libperfusion::xss),
                benchmark(&workload.inputs, |input| {
                    libperfusion::xss_with_limit(input, input.len())
                }),
            ),
        };
        println!(
            "{:<10} {:>5} inputs | capped {:>8.1} ns/input | caller-bounded {:>8.1} ns/input",
            workload.name,
            workload.inputs.len(),
            capped,
            caller_bounded
        );
    }
}
