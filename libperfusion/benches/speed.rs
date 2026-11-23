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

#[path = "../tests/common/reviewed.rs"]
mod reviewed;

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

/// Lower-case hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

/// Checks the two verdicts input by input, allowing only reviewed rows.
///
/// The reviewed rows are the `speed:<workload>` rows of
/// `tests/parity/reviewed-differences.tsv`, keyed by the exact bytes so an
/// unrelated new difference cannot hide behind a reviewed one. A hit *count*
/// would be satisfied just as well by one new false positive cancelling one
/// lost detection. Every row whose input the workload holds must be hit; a
/// full run (`complete`) holds them all.
fn compare_verdicts(workload: &Workload, theirs: &[bool], ours: &[bool], complete: bool) {
    let rows = reviewed::rows("c", &format!("speed:{}", workload.name));
    let detection = workload.detection.name();
    let mut seen = vec![false; rows.len()];
    let mut unreviewed = Vec::new();
    for ((input, &c_verdict), &port_verdict) in workload.inputs.iter().zip(theirs).zip(ours) {
        if c_verdict == port_verdict {
            continue;
        }
        let c_verdict = format!("{detection}:{}", u8::from(c_verdict));
        let port_verdict = format!("{detection}:{}", u8::from(port_verdict));
        let known = rows
            .iter()
            .position(|row| row.matches(input, &c_verdict, &port_verdict));
        if let Some(index) = known.and_then(|index| seen.get_mut(index)) {
            *index = true;
        } else if unreviewed.len() < 16 {
            unreviewed.push(format!(
                "c\tspeed:{}\t<id>\t{}\t{c_verdict}\t{port_verdict}\t<reason>  # {:?}",
                workload.name,
                hex(input),
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
    let missed: Vec<&str> = rows
        .iter()
        .zip(&seen)
        .filter(|&(row, &seen)| !seen && (complete || workload.inputs.contains(&row.input)))
        .map(|(row, _)| row.id)
        .collect();
    assert!(
        missed.is_empty(),
        "{}: reviewed difference inventory changed; rows not observed: {missed:?}",
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
            compare_verdicts(workload, &theirs.verdicts, &ours.verdicts, benchmarking);

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
