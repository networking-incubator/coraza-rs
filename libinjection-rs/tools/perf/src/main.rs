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

use std::{
    fs::File,
    hint::black_box,
    io::{BufRead, BufReader, BufWriter, Write},
    time::Instant,
};

struct Case {
    size: usize,
    name: String,
    bytes: Vec<u8>,
}

struct Outcome {
    detected: bool,
    fingerprint: [u8; 8],
    fingerprint_len: u8,
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("input hex has odd length".to_owned());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let value = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        let high = value(pair[0]).ok_or_else(|| "invalid hex digit".to_owned())?;
        let low = value(pair[1]).ok_or_else(|| "invalid hex digit".to_owned())?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn read_cases(path: &str, detector: &str) -> Result<Vec<Case>, String> {
    let input = File::open(path).map_err(|error| format!("open cases: {error}"))?;
    let mut cases = Vec::new();
    for line in BufReader::new(input).lines() {
        let line = line.map_err(|error| format!("read case: {error}"))?;
        let mut columns = line.split('\t');
        let row_detector = columns.next().ok_or_else(|| "missing detector".to_owned())?;
        let size = columns
            .next()
            .ok_or_else(|| "missing input size".to_owned())?
            .parse::<usize>()
            .map_err(|error| format!("invalid input size: {error}"))?;
        let name = columns.next().ok_or_else(|| "missing case name".to_owned())?;
        let hex = columns.next().ok_or_else(|| "missing input hex".to_owned())?;
        if columns.next().is_some() {
            return Err("unexpected extra case column".to_owned());
        }
        if row_detector == detector {
            let bytes = hex_decode(hex)?;
            if bytes.len() != size {
                return Err(format!("{} case length was {}, expected {size}", name, bytes.len()));
            }
            cases.push(Case {
                size,
                name: name.to_owned(),
                bytes,
            });
        }
    }
    if cases.is_empty() {
        return Err(format!("no input rows for detector {detector}"));
    }
    Ok(cases)
}

fn sql_call(input: &[u8]) -> Outcome {
    let result = black_box(libinjection::detect_sqli(black_box(input)));
    Outcome {
        detected: result.detected,
        fingerprint: result.fingerprint.bytes,
        fingerprint_len: result.fingerprint.len,
    }
}

fn xss_call(input: &[u8]) -> Outcome {
    Outcome {
        detected: black_box(libinjection::detect_xss(black_box(input))),
        fingerprint: [0; 8],
        fingerprint_len: 0,
    }
}

fn fingerprint_hex(outcome: &Outcome) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(usize::from(outcome.fingerprint_len) * 2);
    for byte in outcome.fingerprint.iter().take(usize::from(outcome.fingerprint_len)) {
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 0x0F)]));
    }
    hex
}

fn parse_usize(value: Option<String>, name: &str) -> Result<usize, String> {
    value
        .ok_or_else(|| format!("missing {name}"))?
        .parse::<usize>()
        .map_err(|error| format!("invalid {name}: {error}"))
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let detector = args
        .next()
        .ok_or_else(|| "usage: perf-driver <sqli|xss> <cases.tsv> <samples> <warmup> <raw.csv>".to_owned())?;
    if detector != "sqli" && detector != "xss" {
        return Err("detector must be sqli or xss".to_owned());
    }
    let cases_path = args.next().ok_or_else(|| "missing cases file".to_owned())?;
    let sample_count = parse_usize(args.next(), "sample count")?;
    let warmup_count = parse_usize(args.next(), "warmup count")?;
    let raw_path = args.next().ok_or_else(|| "missing raw sample output".to_owned())?;
    if args.next().is_some() {
        return Err("unexpected extra argument".to_owned());
    }
    let cases = read_cases(&cases_path, &detector)?;
    let mut results = Vec::with_capacity(cases.len());
    for case in cases {
        let mut durations = Vec::with_capacity(sample_count);
        let outcome = if detector == "sqli" {
            let mut last = Outcome {
                detected: false,
                fingerprint: [0; 8],
                fingerprint_len: 0,
            };
            for _ in 0..warmup_count {
                last = sql_call(&case.bytes);
            }
            for _ in 0..sample_count {
                let start = Instant::now();
                let result = sql_call(&case.bytes);
                let elapsed = start.elapsed().as_nanos();
                last = result;
                durations.push(elapsed);
            }
            last
        } else {
            let mut last = Outcome {
                detected: false,
                fingerprint: [0; 8],
                fingerprint_len: 0,
            };
            for _ in 0..warmup_count {
                last = xss_call(&case.bytes);
            }
            for _ in 0..sample_count {
                let start = Instant::now();
                let result = xss_call(&case.bytes);
                let elapsed = start.elapsed().as_nanos();
                last = result;
                durations.push(elapsed);
            }
            last
        };
        let mut sorted = durations.clone();
        sorted.sort_unstable();
        let percentile = |percent: usize| -> u128 {
            let rank = (sample_count * percent).div_ceil(100).saturating_sub(1);
            sorted[rank]
        };
        results.push((case, outcome, durations, percentile(50), percentile(90), percentile(99)));
    }

    let raw = File::create(raw_path).map_err(|error| format!("create raw output: {error}"))?;
    let mut raw = BufWriter::new(raw);
    writeln!(raw, "detector\tsize\tcase\titeration\tnanos").map_err(|error| format!("write raw header: {error}"))?;
    for (case, _, durations, ..) in &results {
        for (iteration, nanos) in durations.iter().enumerate() {
            writeln!(raw, "{detector}\t{}\t{}\t{iteration}\t{nanos}", case.size, case.name)
                .map_err(|error| format!("write raw sample: {error}"))?;
        }
    }
    raw.flush().map_err(|error| format!("flush raw output: {error}"))?;

    print!("{{\"detector\":\"{detector}\",\"samples\":{sample_count},\"warmup\":{warmup_count},\"cases\":[");
    for (index, (case, outcome, _, p50, p90, p99)) in results.iter().enumerate() {
        if index != 0 {
            print!(",");
        }
        print!(
            "{{\"size\":{},\"case\":\"{}\",\"detected\":{},\"fingerprint\":\"{}\",\"p50_ns\":{},\"p90_ns\":{},\"p99_ns\":{}}}",
            case.size,
            case.name,
            outcome.detected,
            fingerprint_hex(outcome),
            p50,
            p90,
            p99
        );
    }
    println!("]}}");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("perf driver failed: {error}");
        std::process::exit(2);
    }
}
