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

//! Compare detector latency across input sizes and shapes:
//! `cargo bench -p libperfusion --bench scaling`.

use std::{hint::black_box, time::Instant};

const SIZES: &[usize] = &[64, 256, 1_024, 4_096, 16_384, 65_536, 262_144, 1_048_576];
const LARGE_XSS_SIZES: &[usize] = &[1_048_576, 5_242_880, 10_485_760];
// This reproduces the historical hostile-scaling suffix at the same byte sizes.
const QUOTE_COUNTS: &[usize] = &[1_600, 3_200, 6_400, 12_800, 25_600, 51_200];
const SAMPLE_COUNT: usize = 5;
const SAMPLE_TIME: std::time::Duration = std::time::Duration::from_millis(15);
const LONG_INPUT: usize = 4_096;

#[derive(Clone, Copy)]
enum Detector {
    Sqli,
    Xss,
}

struct Workload {
    detector: Detector,
    shape: &'static str,
    input: Vec<u8>,
    expected_hit: bool,
}

fn repeated(pattern: &[u8], size: usize) -> Vec<u8> {
    assert!(!pattern.is_empty());
    (0..size).map(|i| pattern[i % pattern.len()]).collect()
}

fn prose() -> Vec<u8> {
    include_bytes!("../LICENSE")
        .iter()
        .copied()
        .cycle()
        .take(LONG_INPUT)
        .collect()
}

fn json() -> Vec<u8> {
    const PADDING: &str = r#"],"padding":""#;
    const END: &str = r#""}"#;

    let mut document = String::from(r#"{"users":["#);
    for id in 1.. {
        let comma = if id == 1 { "" } else { "," };
        let record = format!(
            r#"{comma}{{"id":{id},"name":"user {id}","email":"user{id}@example.com","active":true,"roles":["admin","dev"]}}"#
        );
        if document.len() + record.len() + PADDING.len() + END.len() > LONG_INPUT {
            break;
        }
        document.push_str(&record);
    }
    document.push_str(PADDING);
    while document.len() + END.len() < LONG_INPUT {
        document.push('x');
    }
    document.push_str(END);
    document.into_bytes()
}

fn base64() -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    (0..LONG_INPUT)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            ALPHABET[(state >> 58) as usize]
        })
        .collect()
}

fn padded(payload: &[u8], size: usize, at_end: bool) -> Vec<u8> {
    padded_with(payload, size, at_end, b'x')
}

fn padded_with(payload: &[u8], size: usize, at_end: bool, filler: u8) -> Vec<u8> {
    assert!(payload.len() <= size);
    let mut input = vec![filler; size];
    let offset = if at_end { size - payload.len() } else { 0 };
    input[offset..offset + payload.len()].copy_from_slice(payload);
    input
}

fn add(workloads: &mut Vec<Workload>, detector: Detector, shape: &'static str, input: Vec<u8>, expected_hit: bool) {
    workloads.push(Workload {
        detector,
        shape,
        input,
        expected_hit,
    });
}

fn workloads() -> Vec<Workload> {
    let mut workloads = Vec::new();
    let xss_head = b"<script>alert(1)</script>";
    let xss_tail = b"<a href='&#x6a;avascript:alert(1)'>x</a>";

    for &size in SIZES {
        add(&mut workloads, Detector::Xss, "plain_miss", repeated(b"a", size), false);
        add(
            &mut workloads,
            Detector::Xss,
            "benign_tags_miss",
            repeated(b"<div title=x>plain</div>", size),
            false,
        );
        add(
            &mut workloads,
            Detector::Xss,
            "event_near_miss",
            repeated(b"<img onerrx=1 src=x>", size),
            false,
        );
        add(
            &mut workloads,
            Detector::Xss,
            "comment_miss",
            repeated(b"<!-- ordinary comment -->", size),
            false,
        );
        add(
            &mut workloads,
            Detector::Xss,
            "unclosed_comment_miss",
            [b"<!--".as_slice(), &vec![b'a'; size.saturating_sub(4)]].concat(),
            false,
        );
        add(
            &mut workloads,
            Detector::Xss,
            "angle_noise_miss",
            repeated(b"<", size),
            false,
        );
        add(
            &mut workloads,
            Detector::Xss,
            "quote_noise_miss",
            repeated(b"\"", size),
            false,
        );
        add(
            &mut workloads,
            Detector::Xss,
            "binary_noise_miss",
            repeated(b"\0\xff\x80", size),
            false,
        );
        add(
            &mut workloads,
            Detector::Xss,
            "attack_at_start",
            padded(xss_head, size, false),
            true,
        );
        add(
            &mut workloads,
            Detector::Xss,
            "encoded_url_at_end",
            padded(xss_tail, size, true),
            true,
        );

        add(
            &mut workloads,
            Detector::Sqli,
            "plain_miss",
            repeated(b"x", size),
            false,
        );
        add(
            &mut workloads,
            Detector::Sqli,
            "operator_noise_miss",
            repeated(b"+", size),
            false,
        );
        add(
            &mut workloads,
            Detector::Sqli,
            "attack_at_start",
            padded_with(b"1 OR 1=1 -- ", size, false, b' '),
            true,
        );
        add(
            &mut workloads,
            Detector::Sqli,
            "attack_after_whitespace",
            padded_with(b"1 OR 1=1 -- ", size, true, b' '),
            true,
        );
    }

    for &size in LARGE_XSS_SIZES {
        add(
            &mut workloads,
            Detector::Xss,
            "slashes_miss",
            repeated(b"/", size),
            false,
        );
        add(
            &mut workloads,
            Detector::Xss,
            "large_tag_stream_miss",
            repeated(b"<div title=x>plain</div>", size),
            false,
        );
    }

    for (shape, input) in [
        ("prose_4k_miss", prose()),
        ("json_4k_miss", json()),
        ("base64_4k_miss", base64()),
    ] {
        add(&mut workloads, Detector::Xss, shape, input.clone(), false);
        add(&mut workloads, Detector::Sqli, shape, input, false);
    }

    for &quotes in QUOTE_COUNTS {
        let input = [b"'\\".as_slice(), &vec![b'\''; quotes]].concat();
        add(
            &mut workloads,
            Detector::Sqli,
            "mixed_escaped_quote_suffix",
            input,
            false,
        );
    }

    workloads
}

fn verify(workload: &Workload) -> String {
    match workload.detector {
        Detector::Sqli => {
            let port = libperfusion::sqli(&workload.input);
            let reference = libinjection::detect_sqli(&workload.input);
            let port_fp = port.as_ref().map_or("", |fp| fp.as_str());
            let reference_fp = reference.fingerprint.as_str().unwrap_or("");
            assert_eq!(
                port_fp,
                reference_fp,
                "SQLi fingerprint parity for {} at {} bytes",
                workload.shape,
                workload.input.len()
            );
            assert_eq!(
                !port_fp.is_empty(),
                workload.expected_hit,
                "SQLi verdict for {} at {} bytes",
                workload.shape,
                workload.input.len()
            );
            assert_eq!(reference.detected, workload.expected_hit);
            port_fp.to_owned()
        },
        Detector::Xss => {
            let port = libperfusion::xss(&workload.input);
            let reference = libinjection::detect_xss(&workload.input);
            assert_eq!(
                port,
                reference,
                "XSS parity for {} at {} bytes",
                workload.shape,
                workload.input.len()
            );
            assert_eq!(
                port,
                workload.expected_hit,
                "XSS verdict for {} at {} bytes",
                workload.shape,
                workload.input.len()
            );
            if port { "hit".to_owned() } else { "miss".to_owned() }
        },
    }
}

fn measure<T>(input: &[u8], detect: impl Fn(&[u8]) -> T) -> f64 {
    let checks_per_sample = (65_536 / input.len().max(1)).clamp(1, 64);
    let started = Instant::now();
    let mut calls = 0_u64;
    while started.elapsed() < SAMPLE_TIME {
        for _ in 0..checks_per_sample {
            black_box(detect(black_box(input)));
            calls += 1;
        }
    }
    started.elapsed().as_secs_f64() * 1e9 / calls as f64
}

fn summary(samples: &mut [f64]) -> (f64, f64, f64) {
    samples.sort_by(f64::total_cmp);
    (samples[0], samples[samples.len() / 2], samples[samples.len() - 1])
}

fn run<T, U>(
    workload: &Workload,
    detector_name: &str,
    port: impl Fn(&[u8]) -> T,
    reference: impl Fn(&[u8]) -> U,
    outcome: &str,
) {
    black_box(port(black_box(&workload.input)));
    black_box(reference(black_box(&workload.input)));

    let mut port_samples = Vec::with_capacity(SAMPLE_COUNT);
    let mut reference_samples = Vec::with_capacity(SAMPLE_COUNT);
    for sample in 0..SAMPLE_COUNT {
        if sample % 2 == 0 {
            port_samples.push(measure(&workload.input, &port));
            reference_samples.push(measure(&workload.input, &reference));
        } else {
            reference_samples.push(measure(&workload.input, &reference));
            port_samples.push(measure(&workload.input, &port));
        }
    }

    let (port_min, port_median, port_max) = summary(&mut port_samples);
    let (reference_min, reference_median, reference_max) = summary(&mut reference_samples);
    let size = workload.input.len();
    println!(
        "RESULT\t{}\t{}\t{}\t{}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.2}",
        detector_name,
        workload.shape,
        size,
        outcome,
        port_median,
        reference_median,
        port_min,
        port_max,
        reference_min,
        reference_max,
        reference_median / port_median,
    );
}

fn main() {
    println!(
        "Optimized synthetic scaling sweep; {} x {:?} samples per detector/input.",
        SAMPLE_COUNT, SAMPLE_TIME
    );
    println!(
        "RESULT\tdetector\tshape\tbytes\tverdict\tYA_median_ns\tlibinjection_rs_median_ns\tYA_min_ns\tYA_max_ns\tref_min_ns\tref_max_ns\tref/YA_speedup"
    );
    let workloads = workloads();
    let outcomes: Vec<_> = workloads.iter().map(verify).collect();
    println!(
        "Verified parity and expected hit/miss for all {} generated inputs.",
        workloads.len()
    );
    for (workload, outcome) in workloads.iter().zip(&outcomes) {
        match workload.detector {
            Detector::Sqli => run(workload, "SQLi", libperfusion::sqli, libinjection::detect_sqli, outcome),
            Detector::Xss => run(workload, "XSS", libperfusion::xss, libinjection::detect_xss, outcome),
        }
    }
}
