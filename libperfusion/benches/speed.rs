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
//! `cargo bench`: how fast the port is, next to libinjection itself.

//! Both are run over the same inputs and timed the same way: the port
//! here, and the C library by `benches/speed.c`, which is built from the
//! sources vendored in `tests/upstream/src`. That needs a C compiler:
//! `CC` (default `cc`) with `CFLAGS` (default `-O3`, what upstream's
//! `--enable-optimize` builds with).
//!
//! The workloads are the inputs of upstream's two speed tests,
//! `src/test_speed_sqli.c` and `src/test_speed_xss.c`, and its sample
//! corpora, the SQL ones through the XSS detection as well: it has no
//! samples of its own that are not attacks. Each measurement is the best of a
//! second's worth of rounds over a workload, each calling the detection once
//! per input. Two measurements alternate which implementation runs first.
//!
//! This is for a feel of where the port stands, not for small differences:
//! nothing is pinned to a core, so order-labelled ratios still contain noise.

#![expect(
    clippy::missing_docs_in_private_items,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::string_slice,
    clippy::cast_precision_loss,
    clippy::print_stdout,
    reason = "This private benchmark parses pinned C fixtures and prints timing results."
)]

#[path = "../tests/upstream_common.rs"]
mod common;

use std::{
    env,
    fmt::Write as _,
    hint::black_box,
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// Rounds are made long enough for the clock not to matter.
const MIN_ROUND: Duration = Duration::from_millis(10);
const MEASUREMENTS: usize = 2;

#[derive(Clone, Copy)]
enum Detection {
    Sqli,
    Xss,
}

impl Detection {
    fn name(self) -> &'static str {
        match self {
            Detection::Sqli => "sqli",
            Detection::Xss => "xss",
        }
    }

    fn port(self, input: &[u8]) -> bool {
        match self {
            Detection::Sqli => libperfusion::sqli(input).is_some(),
            Detection::Xss => libperfusion::xss(input),
        }
    }
}

struct Workload {
    name: &'static str,
    detection: Detection,
    inputs: Vec<Vec<u8>>,
}

struct Timing {
    nanos_per_input: f64,
    /// One verdict per input, in the order the inputs were given.
    verdicts: Vec<bool>,
}

/// The strings of the `s[]` array of one of upstream's speed tests. As in
/// C, string literals with no comma between them are a single string.
fn speed_test_inputs(path: &str) -> Vec<Vec<u8>> {
    let source = common::upstream_source(path);
    let start = source.find("s[] = {").expect("no s[] array") + "s[] = {".len();
    let end = start + source[start..].find("NULL}").expect("unterminated array");

    let mut inputs = Vec::new();
    let mut string: Option<Vec<u8>> = None;
    let mut bytes = source[start..end].bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'"' => {
                let string = string.get_or_insert_default();
                loop {
                    match bytes.next().expect("unterminated string") {
                        b'"' => break,
                        b'\\' => match bytes.next() {
                            Some(escaped @ (b'"' | b'\'' | b'\\')) => string.push(escaped),
                            other => panic!("unsupported escape {other:?} in {path}"),
                        },
                        other => string.push(other),
                    }
                }
            },
            b',' => inputs.extend(string.take()),
            _ => {},
        }
    }
    inputs.extend(string);
    assert!(!inputs.is_empty(), "no inputs in {path}");
    inputs
}

/// The samples of `data/<prefix>*.txt`, URL-decoded as `reader.c` does.
fn samples(prefix: &str) -> Vec<Vec<u8>> {
    common::sample_lines(prefix)
        .iter()
        .map(|line| common::url_decode(line))
        .collect()
}

/// Times the port. The C side, `benches/speed.c`, does exactly the same.
fn time_port(workload: &Workload, budget: Duration) -> Timing {
    let detection = workload.detection;
    let inputs = &workload.inputs;
    let run_round = |passes: usize| {
        let start = Instant::now();
        let mut hits = 0;
        for _ in 0..passes {
            for input in inputs {
                hits += usize::from(black_box(detection.port(black_box(input))));
            }
        }
        (start.elapsed(), hits)
    };

    let mut passes = 1;
    while run_round(passes).0 < MIN_ROUND {
        passes *= 2;
    }

    let started = Instant::now();
    let mut rounds = 0;
    let mut best = Duration::MAX;
    while rounds < 3 || started.elapsed() < budget {
        best = best.min(run_round(passes).0);
        rounds += 1;
    }

    Timing {
        nanos_per_input: best.as_secs_f64() * 1e9 / (passes * inputs.len()) as f64,
        // Taken outside the timed rounds, as the C side does.
        verdicts: inputs.iter().map(|input| detection.port(input)).collect(),
    }
}

/// Times libinjection, through `benches/speed.c`.
fn time_libinjection(driver: &Path, workload: &Workload, budget: Duration) -> Timing {
    let mut child = Command::new(driver)
        .arg(workload.detection.name())
        .arg(budget.as_secs_f64().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("cannot run the C benchmark");

    // The driver reads all of its input before it prints anything.
    let mut hex = String::new();
    for input in &workload.inputs {
        for byte in input {
            write!(hex, "{byte:02x}").unwrap();
        }
        hex.push('\n');
    }
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(hex.as_bytes())
        .expect("cannot feed the C benchmark");

    let output = child.wait_with_output().expect("the C benchmark died");
    assert!(output.status.success(), "the C benchmark failed");
    let output = String::from_utf8(output.stdout).expect("output is text");
    let mut fields = output.split_whitespace();
    let mut field = || fields.next().expect("output has three fields");
    let nanos_per_input = field().parse().expect("a time");
    let hits: usize = field().parse().expect("a count");
    let verdicts: Vec<bool> = field()
        .bytes()
        .map(|byte| match byte {
            b'1' => true,
            b'0' => false,
            other => panic!("the C benchmark emitted {other:?} as a verdict"),
        })
        .collect();
    assert_eq!(
        verdicts.len(),
        workload.inputs.len(),
        "{}: the C benchmark returned {} verdicts for {} inputs",
        workload.name,
        verdicts.len(),
        workload.inputs.len()
    );
    assert_eq!(
        verdicts.iter().filter(|hit| **hit).count(),
        hits,
        "{}: the C benchmark's verdicts and its own hit count disagree",
        workload.name
    );
    Timing {
        nanos_per_input,
        verdicts,
    }
}

/// Inputs on which libinjection and this port are known to disagree.
///
/// Each row is `(workload, hex input, libinjection, libperfusion)`, keyed by
/// the exact bytes so an unrelated new difference cannot hide behind a
/// reviewed one. Every row is a sample of the pinned upstream data and is
/// accounted for in `tests/parity/mismatch-ledger.md`.
///
/// This replaced a per-workload hit *count* delta. A count only says the two
/// sides disagree about as many inputs as expected; it is satisfied just as
/// well by one new false positive cancelling one lost detection, which is
/// exactly the pair of changes correctness checking before timing exists to
/// catch.
const REVIEWED_DIFFERENCES: [(&str, &str, bool, bool); 9] = [
    // The narrowed `#` comment whitelist: these four catalogue strings have
    // the exact token shape of the `admin'#` authentication bypass.
    (
        "sqli: benign samples",
        "37222023322043495243554c4152204e4545444c45",
        false,
        true,
    ), // 7" #2 CIRCULAR NEEDLE
    ("sqli: benign samples", "222332204d4f4d22", false, true), // "#2 MOM"
    (
        "sqli: benign samples",
        "42414d424f4f2043484152434f414c20534f41502031202723",
        false,
        true,
    ), // BAMBOO CHARCOAL SOAP 1 '#
    ("sqli: benign samples", "464f4f20424152272320424c4148", false, true), // FOO BAR'# BLAH
    // The five C-only XSS detections left after the local `MATH` tag row
    // closed four of the original nine. Each contains a prefixed XML or SVG
    // element that C over-matches on; the pinned Go reference agrees with
    // this port on all five.
    // xss-html5secorg.txt:232 -- prefixed XML template with a split scheme
    (
        "xss: attack samples",
        "74657374203833203c783a74656d706c61746520786d6c6e733a783d22687474703a2f2f7777772e776170666f72756d2e6f72672f323030312f776d6c2220783a6f6e74696d65723d222428783a756e657363296a2428793a657363617065296124287a3a6e6f65637329762428782961242879297324287a29637269707424783a616c657274283129223e3c783a74696d65722076616c75653d2231222f3e3c2f783a74656d706c6174653e",
        true,
        false,
    ),
    // xss-html5secorg.txt:234 -- xml-events handler on a prefixed element
    (
        "xss: attack samples",
        "74657374203834203c7820786d6c6e733a65763d22687474703a2f2f7777772e77332e6f72672f323030312f786d6c2d6576656e7473222065763a6576656e743d226c6f6164222065763a68616e646c65723d226a6176617363726970743a616c6572742831292f2f2378",
        true,
        false,
    ),
    // xss-html5secorg.txt:236 -- xml-events handler, no scheme
    (
        "xss: attack samples",
        "74657374203835203c7820786d6c6e733a65763d22687474703a2f2f7777772e77332e6f72672f323030312f786d6c2d6576656e7473222065763a6576656e743d226c6f6164222065763a68616e646c65723d22746573742e6576742378222f3e",
        true,
        false,
    ),
    // xss-html5secorg.txt:468 -- SVG `set` writing `xlink:href`
    (
        "xss: attack samples",
        "74657374203133325f31203c736574206174747269627574654e616d653d22786c696e6b3a687265662220626567696e3d226163636573734b65792861292220746f3d222f2f6578616d706c652e636f6d2f3f6122202f3e",
        true,
        false,
    ),
    // xss-xenotix.txt:1196 -- prefixed `x:script` element
    (
        "xss: attack samples",
        "3c783a73637269707420786d6c6e733a783d22687474703a2f2f7777772e77332e6f72672f313939392f7868746d6c223e616c6572742831293b3c2f783a7363726970743e",
        true,
        false,
    ),
];

/// Lower-case hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

/// Checks the two verdicts input by input, allowing only reviewed rows.
fn compare_verdicts(workload: &Workload, theirs: &[bool], ours: &[bool]) {
    let mut reviewed = 0_usize;
    let mut unreviewed = Vec::new();
    for ((input, &c_verdict), &port_verdict) in workload.inputs.iter().zip(theirs).zip(ours) {
        if c_verdict == port_verdict {
            continue;
        }
        let encoded = hex(input);
        let known = REVIEWED_DIFFERENCES.iter().any(|&(name, bytes, c_hit, port_hit)| {
            name == workload.name && bytes == encoded && c_hit == c_verdict && port_hit == port_verdict
        });
        if known {
            reviewed += 1;
        } else if unreviewed.len() < 16 {
            unreviewed.push(format!(
                "  (\"{}\", \"{encoded}\", {c_verdict}, {port_verdict}),  // {:?}",
                workload.name,
                String::from_utf8_lossy(input)
            ));
        }
    }
    assert!(
        unreviewed.is_empty(),
        "{}: unreviewed detection differences:\n{}",
        workload.name,
        unreviewed.join("\n")
    );
    let expected = REVIEWED_DIFFERENCES
        .iter()
        .filter(|&&(name, ..)| name == workload.name)
        .count();
    assert_eq!(
        reviewed, expected,
        "{}: reviewed difference inventory changed",
        workload.name
    );
}

fn main() {
    // `cargo bench` passes `--bench`. Without it, under `cargo test
    // --benches` for instance, this only checks that everything runs: on a
    // few inputs, briefly, and probably unoptimized.
    let benchmarking = env::args().any(|arg| arg == "--bench");
    let budget = if benchmarking {
        Duration::from_secs(1)
    } else {
        Duration::ZERO
    };

    let mut workloads = [
        Workload {
            name: "sqli: upstream's speed test",
            detection: Detection::Sqli,
            inputs: speed_test_inputs("src/test_speed_sqli.c"),
        },
        Workload {
            name: "sqli: attack samples",
            detection: Detection::Sqli,
            inputs: samples("sqli-"),
        },
        Workload {
            name: "sqli: benign samples",
            detection: Detection::Sqli,
            inputs: samples("false_"),
        },
        Workload {
            name: "xss: upstream's speed test",
            detection: Detection::Xss,
            inputs: speed_test_inputs("src/test_speed_xss.c"),
        },
        Workload {
            name: "xss: attack samples",
            detection: Detection::Xss,
            inputs: samples("xss"),
        },
        // What is not XSS is the expensive case: nothing stops the search
        // before every context has been tried.
        Workload {
            name: "xss: sqli attack samples",
            detection: Detection::Xss,
            inputs: samples("sqli-"),
        },
        Workload {
            name: "xss: benign samples",
            detection: Detection::Xss,
            inputs: samples("false_"),
        },
    ];

    if !benchmarking {
        for workload in &mut workloads {
            workload.inputs.truncate(50);
        }
        println!("not run by `cargo bench`: a quick check, the times mean nothing\n");
    }

    let driver = common::build_with_libinjection("benches/speed.c", "-O3");
    println!(
        "libinjection built with `{} {}`, time per input in nanoseconds\n",
        common::c_compiler(),
        common::c_flags("-O3")
    );
    println!(
        "{:<28} {:>7} {:>9} {:>6} {:>12} {:>13} {:>9} {:>8}",
        "workload", "inputs", "avg bytes", "sample", "order", "libinjection", "port", "port / C"
    );

    for workload in &workloads {
        let bytes: usize = workload.inputs.iter().map(Vec::len).sum();
        for sample in 0..MEASUREMENTS {
            let (theirs, ours, order) = if sample % 2 == 0 {
                let theirs = time_libinjection(&driver, workload, budget);
                let ours = time_port(workload, budget);
                (theirs, ours, "C first")
            } else {
                let ours = time_port(workload, budget);
                let theirs = time_libinjection(&driver, workload, budget);
                (theirs, ours, "port first")
            };
            compare_verdicts(workload, &theirs.verdicts, &ours.verdicts);

            println!(
                "{:<28} {:>7} {:>9.0} {:>6} {:>12} {:>13.1} {:>9.1} {:>7.2}x",
                workload.name,
                workload.inputs.len(),
                bytes as f64 / workload.inputs.len() as f64,
                sample + 1,
                order,
                theirs.nanos_per_input,
                ours.nanos_per_input,
                ours.nanos_per_input / theirs.nanos_per_input
            );
        }
    }
}
