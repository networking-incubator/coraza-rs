//! `cargo bench`: how fast the port is, next to libinjection itself.
//!
//! Both are run over the same inputs and timed the same way: the port
//! here, and the C library by `benches/speed.c`, which is built from the
//! sources vendored in `tests/upstream/src`. That needs a C compiler:
//! `CC` (default `cc`) with `CFLAGS` (default `-O3`, what upstream's
//! `--enable-optimize` builds with).
//!
//! The workloads are the inputs of upstream's two speed tests,
//! `src/test_speed_sqli.c` and `src/test_speed_xss.c`, and its sample
//! corpora. A time is that of the best of a second's worth of rounds over a
//! workload, each calling the detection once per input.
//!
//! This is for a feel of where the port stands, not for small differences:
//! nothing is pinned to a core, and the two sides run one after the other.

#[path = "../tests/common/mod.rs"]
mod common;

use std::env;
use std::fmt::Write as _;
use std::hint::black_box;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Rounds are made long enough for the clock not to matter.
const MIN_ROUND: Duration = Duration::from_millis(10);

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
            Detection::Sqli => libinjection_rs::sqli(input).is_some(),
            Detection::Xss => libinjection_rs::xss(input),
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
    /// How many of the inputs were detected.
    hits: usize,
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
            }
            b',' => inputs.extend(string.take()),
            _ => {}
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
    let mut hits = 0;
    while rounds < 3 || started.elapsed() < budget {
        let (took, round_hits) = run_round(passes);
        best = best.min(took);
        hits = round_hits;
        rounds += 1;
    }

    Timing {
        nanos_per_input: best.as_secs_f64() * 1e9 / (passes * inputs.len()) as f64,
        hits: hits / passes,
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
    let mut field = || fields.next().expect("output has two fields");
    Timing {
        nanos_per_input: field().parse().expect("a time"),
        hits: field().parse().expect("a count"),
    }
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
        "{:<28} {:>7} {:>9} {:>13} {:>9} {:>9}",
        "workload", "inputs", "avg bytes", "libinjection", "port", "port / C"
    );

    for workload in &workloads {
        let theirs = time_libinjection(&driver, workload, budget);
        let ours = time_port(workload, budget);
        assert_eq!(
            theirs.hits, ours.hits,
            "{}: the two sides disagree on what is an attack",
            workload.name
        );

        let bytes: usize = workload.inputs.iter().map(Vec::len).sum();
        println!(
            "{:<28} {:>7} {:>9.0} {:>13.1} {:>9.1} {:>8.2}x",
            workload.name,
            workload.inputs.len(),
            bytes as f64 / workload.inputs.len() as f64,
            theirs.nanos_per_input,
            ours.nanos_per_input,
            ours.nanos_per_input / theirs.nanos_per_input
        );
    }
}
