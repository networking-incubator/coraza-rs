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

//! Micro-benchmarks for the coraza rule-engine hot path.
//!
//! `cargo bench -p coraza --bench micro [-- --iterations N --repetitions R --json FILE --crs DIR]`
//!
//! Three groups, one per performance-gate axis in `docs/open-findings.md` §4:
//!
//! - `transform`: [`TransformationChain::apply`] over a CRS-length chain
//!   (`t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls`), the prefix CRS shares across hundreds
//!   of rules, plus the empty-chain case that isolates the unconditional input copy (gates P-01 and P-03).
//! - `select`: variable selection over a 20-entry ARGS map through the public lifecycle. `txn_baseline` (no rules)
//!   measures transaction construction and body ingestion; `txn_streq` and `txn_rx` add one non-matching rule over
//!   `ARGS`. The streq delta is the per-rule selection + materialisation cost that P-02 targets; the rx delta
//!   additionally carries the UTF-8 validation pass that P-06 targets.
//! - `crs`: a full phase-1+2 pass with the real CRS ruleset (aggregate gate for every per-rule multiplier). Skipped
//!   with a message when the CRS checkout is absent: fetch it with `envoy-coraza/crs-fetch.sh` or pass `--crs DIR`.
//!
//! Every benchmark reports ns/iteration as median/min/max over `--repetitions`
//! timed runs of `--iterations` iterations after a warm-up, matching the paired
//! before/after protocol the repository's performance gate requires.
//! `--json FILE` writes the same numbers for mechanical comparison.

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the driver prints the timing table and errors to the console"
)]

use std::{env, fs, hint::black_box, path::PathBuf, process::ExitCode, time::Instant};

use coraza::{
    TransformationChain, Waf,
    seclang::Parser,
    transformations::{Transformation, css_decode, html_entity_decode, js_decode, remove_nulls, url_decode_uni},
};
use serde_json::json;

/// Default CRS checkout, fetched next to the workspace by `crs-fetch.sh`.
const DEFAULT_CRS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../envoy-coraza/crs");

/// Default iterations per benchmark group.
const DEFAULT_ITERATIONS: usize = 5_000;

/// Default timed repetitions per benchmark.
const DEFAULT_REPETITIONS: usize = 5;

/// One benchmark row: ns per iteration, median over the repetitions.
struct Timings {
    /// Iterations per timed repetition.
    iterations: usize,
    /// Fastest ns/iteration observed.
    ns_min: u64,
    /// Median ns/iteration over the repetitions.
    ns_median: u64,
    /// Slowest ns/iteration observed.
    ns_max: u64,
}

/// Parsed command line.
struct Args {
    /// Iterations per timed repetition.
    iterations: usize,
    /// Timed repetitions per benchmark.
    repetitions: usize,
    /// Optional JSON results path.
    json: Option<PathBuf>,
    /// CRS checkout for the `crs` group.
    crs: PathBuf,
}

/// Parses the command line, or reports the offending argument.
fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        iterations: DEFAULT_ITERATIONS,
        repetitions: DEFAULT_REPETITIONS,
        json: None,
        crs: PathBuf::from(DEFAULT_CRS),
    };
    let mut raw = env::args().skip(1);
    while let Some(flag) = raw.next() {
        let value = raw.next();
        match (flag.as_str(), value) {
            ("--iterations", Some(value)) => {
                args.iterations = value
                    .parse()
                    .map_err(|error| format!("invalid --iterations {value}: {error}"))?;
            },
            ("--repetitions", Some(value)) => {
                args.repetitions = value
                    .parse()
                    .map_err(|error| format!("invalid --repetitions {value}: {error}"))?;
            },
            ("--json", Some(value)) => args.json = Some(PathBuf::from(value)),
            ("--crs", Some(value)) => args.crs = PathBuf::from(value),
            // Cargo passes `--bench` to custom-harness executables; it selects
            // nothing here because this driver is a single benchmark.
            ("--bench", None) => {},
            (..) => return Err(format!("unknown or incomplete argument: {flag}")),
        }
    }
    if args.iterations == 0 || args.repetitions == 0 {
        return Err("--iterations and --repetitions must be positive".to_owned());
    }
    Ok(args)
}

/// Times `iterations` calls of `body`, `repetitions` times after a warm-up.
fn time_repetitions(iterations: usize, repetitions: usize, mut body: impl FnMut()) -> Timings {
    for _ in 0..(iterations / 10).max(10) {
        body();
    }
    let mut samples: Vec<u64> = Vec::with_capacity(repetitions);
    for _ in 0..repetitions {
        let start = Instant::now();
        for _ in 0..iterations {
            body();
        }
        let elapsed = start.elapsed().as_nanos();
        samples.push(u64::try_from(elapsed).unwrap_or(u64::MAX) / u64::try_from(iterations).unwrap_or(1));
    }
    samples.sort_unstable();
    let median = samples.get(samples.len() / 2).copied().unwrap_or_default();
    Timings {
        iterations,
        ns_min: samples.first().copied().unwrap_or_default(),
        ns_median: median,
        ns_max: samples.last().copied().unwrap_or_default(),
    }
}

/// The CRS-canonical transformation prefix shared by hundreds of rules.
fn crs_chain() -> TransformationChain {
    let steps: [(&str, Transformation); 5] = [
        ("urlDecodeUni", url_decode_uni),
        ("htmlEntityDecode", html_entity_decode),
        ("jsDecode", js_decode),
        ("cssDecode", css_decode),
        ("removeNulls", remove_nulls),
    ];
    let mut chain = TransformationChain::new();
    for (name, function) in steps {
        // Names are fixed non-empty literals; insertion cannot fail.
        if chain.add(name, function).is_err() {
            unreachable!("fixed transformation names are never empty");
        }
    }
    chain
}

/// A representative small argument value with decodable content.
const SMALL_INPUT: &[u8] = b"userName=%61dmin&tag=<h1&amp;%3B&gt;&action=%2flogin";

/// A `2 KiB` mixed-decode workload built by repeating the small pattern.
fn two_kib_input() -> Vec<u8> {
    SMALL_INPUT.repeat(64 / 2 + 1024 / SMALL_INPUT.len())
}

/// A 20-entry urlencoded body with ~64-byte values.
fn twenty_arg_body() -> Vec<u8> {
    let mut body = Vec::new();
    for index in 0..20 {
        if index > 0 {
            body.push(b'&');
        }
        body.extend_from_slice(format!("arg{index:02}=").as_bytes());
        body.extend_from_slice(format!("value-{index:02}-").as_bytes());
        body.extend_from_slice(b"abcdefghij".repeat(6).as_slice());
    }
    body
}

/// A benign 10-argument body with realistic mixed content for the CRS pass.
fn crs_body() -> Vec<u8> {
    let mut body = String::new();
    for (key, value) in [
        ("username", "katz"),
        ("email", "katz@example.com"),
        ("action", "save"),
        ("comment", "Fixed the parser &amp; added tests; see #42."),
        ("path", "/var/log/app.log"),
        ("query", "select the theme named default"),
        ("lang", "en-US"),
        ("token", "0123456789abcdef"),
        ("page", "3"),
        ("debug", "false"),
    ] {
        if !body.is_empty() {
            body.push('&');
        }
        body.push_str(&form_encode(key));
        body.push('=');
        body.push_str(&form_encode(value));
    }
    body.into_bytes()
}

/// Percent-encode the characters that change urlencoded structure — `%` (escape
/// prefix), `&` and `=` (delimiters) and `+` (decodes to space) — so each pair
/// parses back to its original value. Everything else, including spaces and
/// `;`/`#`/`@`, passes through unchanged in both engines.
fn form_encode(component: &str) -> String {
    let mut out = String::with_capacity(component.len());
    for byte in component.bytes() {
        match byte {
            b'%' => out.push_str("%25"),
            b'&' => out.push_str("%26"),
            b'+' => out.push_str("%2B"),
            b'=' => out.push_str("%3D"),
            _ => out.push(char::from(byte)),
        }
    }
    out
}

/// Compiles a SecLang document into a Waf.
fn compile(sec_lang: &str, label: &str) -> Result<Waf, String> {
    let mut parser = Parser::new();
    parser
        .from_string(sec_lang)
        .map_err(|error| format!("{label}: {error}"))?;
    parser.into_waf().map_err(|error| format!("{label}: {error}"))
}

/// Drives one fresh transaction through phase 1 and 2 with the given body.
fn run_phase12(waf: &Waf, uri: &str, body: &[u8]) {
    let mut transaction = Box::new(waf.new_transaction());
    transaction.process_uri(uri, "POST", "HTTP/1.1");
    transaction.add_request_header("Host", "bench.example.com");
    transaction.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    transaction.add_request_header("Content-Length", body.len().to_string());
    transaction.add_request_header("User-Agent", "micro-bench/1.0");
    transaction.add_request_header("Accept", "text/html,application/xhtml+xml");
    transaction.add_request_header("Accept-Language", "en-US,en;q=0.9");
    transaction.add_request_header("Referer", "https://bench.example.com/form");
    transaction.add_request_header("Origin", "https://bench.example.com");
    transaction.add_request_header("Connection", "keep-alive");
    transaction.add_request_header("X-Request-Id", "0123456789abcdef");
    transaction.add_request_header("X-Forwarded-For", "192.0.2.1");
    transaction.add_request_header("X-Forwarded-Proto", "https");
    transaction.add_request_header("Accept-Encoding", "gzip, deflate");
    transaction.add_request_header("Cache-Control", "no-cache");
    transaction.add_request_header(
        "Cookie",
        "session=abcdef0123456789; theme=light; lang=en; tz=UTC; flag=1",
    );
    transaction.set_server_name("bench.example.com");
    transaction.process_request_headers();
    black_box(transaction.process_request_body(body));
}

/// Runs the `transform` group.
fn bench_transform(args: &Args, rows: &mut Vec<(&'static str, Timings)>) {
    let chain = crs_chain();
    let empty = TransformationChain::new();
    let small = SMALL_INPUT;
    let large = two_kib_input();

    rows.push((
        "transform/crs_chain_24b",
        time_repetitions(args.iterations, args.repetitions, || {
            black_box(chain.apply(black_box(small)));
        }),
    ));
    rows.push((
        "transform/crs_chain_2k",
        time_repetitions(args.iterations, args.repetitions, || {
            black_box(chain.apply(black_box(&large)));
        }),
    ));
    rows.push((
        "transform/empty_chain_2k",
        time_repetitions(args.iterations, args.repetitions, || {
            black_box(empty.apply(black_box(&large)));
        }),
    ));
}

/// Runs the `select` group: baseline vs one non-matching ARGS rule.
fn bench_select(args: &Args, rows: &mut Vec<(&'static str, Timings)>) -> Result<(), String> {
    let baseline = compile("SecRuleEngine On\nSecRequestBodyAccess On\n", "select baseline")?;
    let streq = compile(
        "SecRuleEngine On\nSecRequestBodyAccess On\nSecRule ARGS \"@streq zzz-not-present-needle\" \"id:2,phase:2,pass,nolog\"",
        "select streq",
    )?;
    let rx = compile(
        "SecRuleEngine On\nSecRequestBodyAccess On\nSecRule ARGS \"@rx ^zzz-not-present\" \"id:3,phase:2,pass,nolog\"",
        "select rx",
    )?;
    let body = twenty_arg_body();
    let uri = "/bench/form";

    rows.push((
        "select/txn_baseline_20args",
        time_repetitions(args.iterations, args.repetitions, || {
            run_phase12(&baseline, uri, &body);
        }),
    ));
    rows.push((
        "select/txn_streq_20args",
        time_repetitions(args.iterations, args.repetitions, || {
            run_phase12(&streq, uri, &body);
        }),
    ));
    rows.push((
        "select/txn_rx_20args",
        time_repetitions(args.iterations, args.repetitions, || {
            run_phase12(&rx, uri, &body);
        }),
    ));
    Ok(())
}

/// Runs the `crs` group against the real CRS checkout.
fn bench_crs(args: &Args, rows: &mut Vec<(&'static str, Timings)>) -> Result<(), String> {
    let crs = &args.crs;
    if !crs.join("rules").is_dir() {
        println!(
            "crs: skipped (no CRS checkout at {}; run envoy-coraza/crs-fetch.sh or pass --crs DIR)",
            crs.display()
        );
        return Ok(());
    }
    let sec_lang = format!(
        "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 13107200\n\
         Include {setup}\nInclude {rules}",
        setup = crs.join("crs-setup.conf.example").display(),
        rules = crs.join("rules/*.conf").display(),
    );
    let waf = compile(&sec_lang, "crs")?;
    let body = crs_body();
    let uri = "/bench/form?page=3&lang=en-US";

    rows.push((
        "crs/phase12_10args",
        time_repetitions(args.iterations, args.repetitions, || {
            run_phase12(&waf, uri, &body);
        }),
    ));
    Ok(())
}

/// Runs the driver.
fn run(args: &Args) -> Result<(), String> {
    let mut rows: Vec<(&'static str, Timings)> = Vec::new();

    bench_transform(args, &mut rows);
    bench_select(args, &mut rows)?;
    bench_crs(args, &mut rows)?;

    println!(
        "{:<28} {:>10} {:>12} {:>12} {:>12}",
        "benchmark", "iterations", "ns/iter med", "ns/iter min", "ns/iter max"
    );
    for (name, timings) in &rows {
        println!(
            "{:<28} {:>10} {:>12} {:>12} {:>12}",
            name, timings.iterations, timings.ns_median, timings.ns_min, timings.ns_max
        );
    }

    if let Some(path) = &args.json {
        let document = json!({
            "tool": "coraza-micro",
            "rows": rows.iter().map(|(name, timings)| json!({
                "benchmark": name,
                "iterations": timings.iterations,
                "ns_min": timings.ns_min,
                "ns_median": timings.ns_median,
                "ns_max": timings.ns_max,
            })).collect::<Vec<_>>(),
        });
        let text = document.to_string();
        fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match parse_args() {
        Ok(args) => match run(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("coraza micro benchmark driver failed: {error}");
                ExitCode::FAILURE
            },
        },
        Err(error) => {
            eprintln!("coraza micro benchmark driver failed: {error}");
            ExitCode::FAILURE
        },
    }
}
