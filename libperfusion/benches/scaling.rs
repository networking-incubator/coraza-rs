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

//! Measure detector latency across input sizes and shapes:
//! `cargo bench -p libperfusion --bench scaling`.

#![expect(
    clippy::missing_docs_in_private_items,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    reason = "This private benchmark harness reports measured timing data."
)]

use std::{hint::black_box, time::Instant};

const SIZES: &[usize] = &[64, 256, 1_024, 4_096, 16_384, 65_536, 262_144, 1_048_576];
const LARGE_XSS_SIZES: &[usize] = &[1_048_576, 5_242_880, 10_485_760];
// This reproduces the historical hostile-scaling suffix at the same byte sizes.
const QUOTE_COUNTS: &[usize] = &[1_600, 3_200, 6_400, 12_800, 25_600, 51_200];
const SAMPLE_COUNT: usize = 5;
const SAMPLE_TIME: std::time::Duration = std::time::Duration::from_millis(15);
const LONG_INPUT: usize = 4_096;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Detector {
    Sqli,
    Xss,
}

pub(crate) struct Workload {
    pub(crate) detector: Detector,
    pub(crate) shape: &'static str,
    pub(crate) input: Vec<u8>,
    pub(crate) expected_hit: bool,
}

fn repeated(pattern: &[u8], size: usize) -> Vec<u8> {
    assert!(!pattern.is_empty(), "repeat pattern must not be empty");
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
    assert!(payload.len() <= size, "payload must fit its benchmark input");
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

#[expect(
    clippy::too_many_lines,
    reason = "The workload matrix keeps each generated input shape beside its detector and expected verdict."
)]
pub(crate) fn workloads() -> Vec<Workload> {
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

fn verify(workload: &Workload) -> &'static str {
    let detected = match workload.detector {
        Detector::Sqli => libperfusion::sqli_with_limit(&workload.input, workload.input.len()).is_some(),
        Detector::Xss => libperfusion::xss_with_limit(&workload.input, workload.input.len()),
    };
    assert_eq!(
        detected,
        workload.expected_hit,
        "{:?} verdict for {} at {} bytes",
        workload.detector,
        workload.shape,
        workload.input.len()
    );
    if detected { "hit" } else { "miss" }
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

fn run<T>(workload: &Workload, detector_name: &str, detect: impl Fn(&[u8]) -> T, outcome: &str) {
    black_box(detect(black_box(&workload.input)));

    let mut samples = Vec::with_capacity(SAMPLE_COUNT);
    for _ in 0..SAMPLE_COUNT {
        samples.push(measure(&workload.input, &detect));
    }

    let (minimum, median, maximum) = summary(&mut samples);
    let size = workload.input.len();
    println!(
        "RESULT\t{}\t{}\t{}\t{}\t{:.1}\t{:.1}\t{:.1}",
        detector_name, workload.shape, size, outcome, median, minimum, maximum,
    );
}

fn main() {
    println!("libperfusion synthetic scaling sweep; {SAMPLE_COUNT} x {SAMPLE_TIME:?} samples per detector/input.");
    println!("RESULT\tdetector\tshape\tbytes\tverdict\tmedian_ns\tmin_ns\tmax_ns");
    let workloads = workloads();
    let outcomes: Vec<_> = workloads.iter().map(verify).collect();
    println!(
        "Verified expected hit/miss for all {} generated inputs.",
        workloads.len()
    );
    for (workload, outcome) in workloads.iter().zip(&outcomes) {
        match workload.detector {
            Detector::Sqli => run(
                workload,
                "SQLi",
                |input| libperfusion::sqli_with_limit(input, input.len()),
                outcome,
            ),
            Detector::Xss => run(
                workload,
                "XSS",
                |input| libperfusion::xss_with_limit(input, input.len()),
                outcome,
            ),
        }
    }
}
