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

//! Compare the public legacy SQLi and XSS detectors on the shared repository
//! corpus: `cargo bench -p libperfusion --bench compare`.

#[path = "../../libinjection-rs/tests/common/corpus.rs"]
#[allow(dead_code)]
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

struct Workload {
    name: &'static str,
    inputs: Vec<Vec<u8>>,
}

fn workloads() -> Vec<Workload> {
    let mut sqli_hits = Workload {
        name: "SQLi hit",
        inputs: Vec::new(),
    };
    let mut sqli_misses = Workload {
        name: "SQLi miss",
        inputs: Vec::new(),
    };
    let mut xss_hits = Workload {
        name: "XSS hit",
        inputs: Vec::new(),
    };
    let mut xss_misses = Workload {
        name: "XSS miss",
        inputs: Vec::new(),
    };

    let corpus_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../libinjection-rs/tests/corpus");
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
    let fixture_count = paths.len();

    for path in paths {
        let case = parse_corpus_file(&path).unwrap_or_else(|error| panic!("{}: {error:?}", path.display()));
        let input = case.input.into_bytes();
        let port_sqli = libperfusion::sqli(&input);
        let reference_sqli = libinjection::detect_sqli(&input);
        let port_fingerprint = port_sqli.as_ref().map_or("", |fp| fp.as_str());
        let reference_fingerprint = reference_sqli.fingerprint.as_str().unwrap_or("");
        assert_eq!(port_fingerprint, reference_fingerprint, "SQLi parity in {}", case.name);
        assert_eq!(
            reference_sqli.detected,
            port_sqli.is_some(),
            "SQLi verdict in {}",
            case.name
        );

        let port_xss = libperfusion::xss(&input);
        let reference_xss = libinjection::detect_xss(&input);
        assert_eq!(port_xss, reference_xss, "XSS parity in {}", case.name);

        match DriverKind::from_name(&case.name) {
            Some(DriverKind::Sqli) => assert_eq!(port_fingerprint, case.expected, "SQLi fixture {}", case.name),
            Some(DriverKind::Xss) => {
                let expected = match case.expected.as_str() {
                    "0" => false,
                    "1" => true,
                    other => panic!("invalid XSS expectation in {}: {other:?}", case.name),
                };
                assert_eq!(port_xss, expected, "XSS fixture {}", case.name);
            },
            _ => {},
        }

        if port_sqli.is_some() {
            sqli_hits.inputs.push(input.clone());
        } else {
            sqli_misses.inputs.push(input.clone());
        }
        if port_xss {
            xss_hits.inputs.push(input);
        } else {
            xss_misses.inputs.push(input);
        }
    }

    let workloads = vec![sqli_hits, sqli_misses, xss_hits, xss_misses];
    for workload in &workloads {
        assert!(!workload.inputs.is_empty(), "no fixtures for {}", workload.name);
    }
    println!("Using all {fixture_count} repository corpus inputs.");
    workloads
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

fn compare_detectors<Port, Reference, PortOutput, ReferenceOutput>(
    workload: &Workload,
    port_detect: Port,
    reference_detect: Reference,
) where
    Port: Fn(&[u8]) -> PortOutput,
    Reference: Fn(&[u8]) -> ReferenceOutput,
{
    for input in &workload.inputs {
        black_box(port_detect(black_box(input)));
        black_box(reference_detect(black_box(input)));
    }

    let mut port = Vec::with_capacity(SAMPLE_COUNT);
    let mut reference = Vec::with_capacity(SAMPLE_COUNT);

    for sample in 0..SAMPLE_COUNT {
        if sample % 2 == 0 {
            port.push(measure(&workload.inputs, &port_detect));
            reference.push(measure(&workload.inputs, &reference_detect));
        } else {
            reference.push(measure(&workload.inputs, &reference_detect));
            port.push(measure(&workload.inputs, &port_detect));
        }
    }

    let port_ns = median(&mut port);
    let reference_ns = median(&mut reference);
    let (faster, ratio) = if port_ns <= reference_ns {
        ("libperfusion", reference_ns / port_ns)
    } else {
        ("libinjection-rs", port_ns / reference_ns)
    };

    println!(
        "{:<10} {:>5} inputs | libperfusion {:>8.1} ns/input | libinjection-rs {:>8.1} ns/input | {faster} {ratio:.2}x",
        workload.name,
        workload.inputs.len(),
        port_ns,
        reference_ns,
    );
}

fn compare(workload: &Workload) {
    if workload.name.starts_with("SQLi") {
        compare_detectors(workload, libperfusion::sqli, libinjection::detect_sqli);
    } else {
        compare_detectors(workload, libperfusion::xss, libinjection::detect_xss);
    }
}

fn main() {
    let workloads = workloads();
    println!(
        "Shared repository corpus; {} samples of {:?} per detector.",
        SAMPLE_COUNT, SAMPLE_TIME
    );
    println!("Both implementations matched every fixture verdict before timing.");
    for workload in &workloads {
        compare(workload);
    }
}
