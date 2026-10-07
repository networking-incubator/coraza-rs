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
    fs::{self, File},
    hint::black_box,
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
    time::Instant,
};

struct Input {
    detector: String,
    api: String,
    name: String,
    size: usize,
    path: String,
}

struct Row {
    input: Input,
    samples: Vec<u128>,
    outcome: Outcome,
}

struct Outcome {
    detected: bool,
    fingerprint: [u8; 8],
    fingerprint_len: u8,
}

fn parse_input(line: &str) -> Result<Input, String> {
    let mut columns = line.split('\t');
    let detector = columns.next().ok_or_else(|| "missing detector".to_owned())?.to_owned();
    let api = columns.next().ok_or_else(|| "missing API".to_owned())?.to_owned();
    let name = columns.next().ok_or_else(|| "missing case name".to_owned())?.to_owned();
    let size = columns
        .next()
        .ok_or_else(|| "missing size".to_owned())?
        .parse::<usize>()
        .map_err(|error| format!("invalid size: {error}"))?;
    let path = columns
        .next()
        .ok_or_else(|| "missing input path".to_owned())?
        .to_owned();
    if columns.next().is_none() || columns.next().is_some() {
        return Err("input row must have six columns".to_owned());
    }
    Ok(Input {
        detector,
        api,
        name,
        size,
        path,
    })
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

fn analysis_call(input: &[u8]) -> Outcome {
    let options = libinjection::AnalyzeOptions::with_max_input_len(usize::MAX);
    let snapshot = black_box(libinjection::analyze_sqli_with(black_box(input), options));
    Outcome {
        detected: snapshot.verdict_hint == libinjection::snapshot::VerdictHint::Decisive,
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

fn main_run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let manifest = args
        .next()
        .ok_or_else(|| "usage: scaling <input-manifest.tsv> <sample-count> <warmup-count> <raw.tsv>".to_owned())?;
    let sample_count = args
        .next()
        .ok_or_else(|| "missing sample count".to_owned())?
        .parse::<usize>()
        .map_err(|error| format!("invalid sample count: {error}"))?;
    let warmup_count = args
        .next()
        .ok_or_else(|| "missing warmup count".to_owned())?
        .parse::<usize>()
        .map_err(|error| format!("invalid warmup count: {error}"))?;
    let raw_path = args.next().ok_or_else(|| "missing raw sample path".to_owned())?;
    if args.next().is_some() || sample_count == 0 {
        return Err("unexpected argument or empty sample count".to_owned());
    }
    let manifest_path = Path::new(&manifest);
    let manifest_directory = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let source = File::open(manifest_path).map_err(|error| format!("open manifest: {error}"))?;
    let mut rows = Vec::new();
    for line in BufReader::new(source).lines() {
        let mut input = parse_input(&line.map_err(|error| format!("read manifest: {error}"))?)?;
        let input_path = Path::new(&input.path);
        if !input_path.is_absolute() {
            input.path = manifest_directory.join(input_path).to_string_lossy().into_owned();
        }
        let bytes = fs::read(&input.path).map_err(|error| format!("read {}: {error}", input.path))?;
        if bytes.len() != input.size {
            return Err(format!(
                "{} was {} bytes, manifest says {}",
                input.path,
                bytes.len(),
                input.size
            ));
        }
        if input.detector != "rust" {
            rows.push((input, bytes));
        } else if input.api == "analyze_sqli" {
            rows.push((input, bytes));
        }
    }

    let mut results = Vec::with_capacity(rows.len());
    for (input, bytes) in rows {
        if input.api == "detect_sqli" {
            let mut outcome = Outcome {
                detected: false,
                fingerprint: [0; 8],
                fingerprint_len: 0,
            };
            for _ in 0..warmup_count {
                outcome = sql_call(&bytes);
            }
            let mut samples = Vec::with_capacity(sample_count);
            for _ in 0..sample_count {
                let start = Instant::now();
                let value = black_box(sql_call(&bytes));
                let nanos = start.elapsed().as_nanos();
                outcome = value;
                samples.push(nanos);
            }
            results.push(Row {
                input,
                samples,
                outcome,
            });
        } else if input.api == "detect_xss" {
            let mut outcome = Outcome {
                detected: false,
                fingerprint: [0; 8],
                fingerprint_len: 0,
            };
            for _ in 0..warmup_count {
                outcome = xss_call(&bytes);
            }
            let mut samples = Vec::with_capacity(sample_count);
            for _ in 0..sample_count {
                let start = Instant::now();
                let value = black_box(xss_call(&bytes));
                let nanos = start.elapsed().as_nanos();
                outcome = value;
                samples.push(nanos);
            }
            results.push(Row {
                input,
                samples,
                outcome,
            });
        } else {
            let mut outcome = Outcome {
                detected: false,
                fingerprint: [0; 8],
                fingerprint_len: 0,
            };
            for _ in 0..warmup_count {
                outcome = analysis_call(&bytes);
            }
            let mut samples = Vec::with_capacity(sample_count);
            for _ in 0..sample_count {
                let start = Instant::now();
                outcome = black_box(analysis_call(&bytes));
                let nanos = start.elapsed().as_nanos();
                samples.push(nanos);
            }
            results.push(Row {
                input,
                samples,
                outcome,
            });
        }
    }

    let raw = File::create(raw_path).map_err(|error| format!("create raw output: {error}"))?;
    let mut raw = BufWriter::new(raw);
    writeln!(
        raw,
        "detector\tapi\tcase\tinput_bytes\titeration\tnanos\tdetected\tfingerprint"
    )
    .map_err(|error| format!("write raw header: {error}"))?;
    for row in &results {
        for (iteration, nanos) in row.samples.iter().enumerate() {
            writeln!(
                raw,
                "{}\t{}\t{}\t{}\t{iteration}\t{nanos}\t{}\t{}",
                row.input.detector,
                row.input.api,
                row.input.name,
                row.input.size,
                row.outcome.detected,
                fingerprint_hex(&row.outcome)
            )
            .map_err(|error| format!("write raw sample: {error}"))?;
        }
    }
    raw.flush().map_err(|error| format!("flush raw output: {error}"))?;

    print!("{{\"cases\":[");
    for (index, row) in results.iter_mut().enumerate() {
        row.samples.sort_unstable();
        let median = row.samples[row.samples.len() / 2];
        if index != 0 {
            print!(",");
        }
        print!(
            "{{\"detector\":\"{}\",\"api\":\"{}\",\"case\":\"{}\",\"input_bytes\":{},\"detected\":{},\"fingerprint\":\"{}\",\"median_ns\":{}}}",
            row.input.detector,
            row.input.api,
            row.input.name,
            row.input.size,
            row.outcome.detected,
            fingerprint_hex(&row.outcome),
            median
        );
    }
    println!("]}}");
    Ok(())
}

fn main() {
    if let Err(error) = main_run() {
        eprintln!("scaling driver failed: {error}");
        std::process::exit(2);
    }
}
