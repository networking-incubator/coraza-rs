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
//! Focused groups covering isolated hot paths, load-time work, and full-CRS execution:
//!
//! - `transform`: [`TransformationChain::apply`] over a CRS-length chain
//!   (`t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls`) and its empty-chain API baseline
//!   (P-03).
//! - `select`: variable selection over a 20-entry ARGS map through the public lifecycle. `txn_baseline` (no rules)
//!   measures transaction construction and body ingestion; `txn_streq` and `txn_rx` add one non-matching rule over
//!   `ARGS`. The streq delta is the per-rule selection + materialisation cost that P-02 targets; the rx delta
//!   additionally carries the UTF-8 validation pass that P-06 targets. The shared-prefix row measures P-01.
//! - `contains`: direct `@contains %{ARGS.n}` on a request-backed 64 `KiB` near miss, plus `@within %{ARGS.pattern}`
//!   over a 128 `KiB` inspected value and request-backed short parameter (P-08).
//! - `operators` and `configure`: focused macro, phrase, regex, `SQLi` fallback, repeated action-update, indexed target
//!   updates, 30k-rule load, transaction reuse, and representative request workloads.
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
    RuleVariable, TransformationChain, Waf,
    operators::{Operator as _, Outputs, contains, pm, rx, streq, within},
    seclang::Parser,
    transaction::Transaction,
    transformations::{Transformation, css_decode, html_entity_decode, js_decode, remove_nulls, url_decode_uni},
};
use serde_json::json;

/// Default CRS checkout, fetched next to the workspace by `crs-fetch.sh`.
const DEFAULT_CRS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../envoy-coraza/crs");

/// Default iterations per benchmark group.
const DEFAULT_ITERATIONS: usize = 5_000;

/// Default timed repetitions per benchmark.
const DEFAULT_REPETITIONS: usize = 5;
/// Miss-path rule count for the matched-variable reset workload.
const UNMATCHED_RULES: usize = 128;
/// Rule count in the repeated action-update configure workload.
const UPDATE_RULES: usize = 668;
/// Number of updates in the repeated action-update configure workload.
const ACTION_UPDATES: usize = 800;
/// Rule count in the rule-id indexing configure workload.
const CONFIGURE_RULES: usize = 30_000;
/// Large-collection early-hit workload for borrowed variable selection.
const EARLY_MATCH_ARGUMENTS: usize = 1_000;
/// Size of each non-matching value in the early-hit workload.
const EARLY_MATCH_VALUE_BYTES: usize = 8 * 1024;

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
fn time_repetitions(iterations: usize, repetitions: usize, body: impl FnMut()) -> Timings {
    time_repetitions_with_warmup(iterations, repetitions, (iterations / 10).max(10), body)
}

/// Times a workload with a caller-selected warm-up, including one-shot load benchmarks.
fn time_repetitions_with_warmup(
    iterations: usize,
    repetitions: usize,
    warmup_iterations: usize,
    mut body: impl FnMut(),
) -> Timings {
    for _ in 0..warmup_iterations {
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
        ("comment", "Hello from a normal account."),
        ("path", "/home/katz/profile"),
        ("query", "plain"),
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

/// A 20-entry request where every argument matches one rule.
fn twenty_match_arg_body() -> Vec<u8> {
    let mut body = Vec::new();
    for index in 0..20 {
        if index > 0 {
            body.push(b'&');
        }
        body.extend_from_slice(format!("arg{index:02}=hit").as_bytes());
    }
    body
}

/// Add 1,000 large arguments with hits at the start, middle, and end.
fn add_early_match_arguments(transaction: &mut Transaction, large_value: &[u8]) {
    for index in 0..EARLY_MATCH_ARGUMENTS {
        let value = if matches!(index, 0 | 500 | 999) {
            b"hit".as_slice()
        } else {
            large_value
        };
        transaction.add_get_argument(format!("arg{index:04}"), value);
    }
}

/// Verify the early-hit workload's match order and per-match action count.
fn verify_early_match(waf: &Waf, large_value: &[u8]) -> Result<(), String> {
    let mut transaction = waf.new_transaction();
    add_early_match_arguments(&mut transaction, large_value);
    if transaction.process_request_headers().is_some() {
        return Err("early-match benchmark was unexpectedly interrupted".to_owned());
    }
    let matches = transaction.matched_rules().first().map(|rule| {
        rule.matches
            .iter()
            .map(|matched| matched.key.as_str())
            .collect::<Vec<_>>()
    });
    if matches.as_deref() != Some(["arg0000", "arg0500", "arg0999"].as_slice())
        || transaction.get_variable(RuleVariable::TX, Some("hits")).as_deref() != Some("3")
    {
        return Err("early-match benchmark changed match order or per-match actions".to_owned());
    }
    Ok(())
}

/// Generate `count` rules with the same variable/operator shape.
fn unmatched_rules(count: usize, actions: &str) -> String {
    let mut sec_lang = String::from("SecRuleEngine On\nSecRequestBodyAccess On\n");
    for id in 1..=count {
        sec_lang.push_str("SecRule ARGS \"@streq absent\" \"id:");
        sec_lang.push_str(&id.to_string());
        sec_lang.push_str(",phase:2,pass,nolog");
        if !actions.is_empty() {
            sec_lang.push(',');
            sec_lang.push_str(actions);
        }
        sec_lang.push_str("\"\n");
    }
    sec_lang
}

/// Rules with a common five-step transform prefix, as in a CRS rule group.
fn shared_prefix_rules(count: usize) -> String {
    let mut sec_lang = String::from("SecRuleEngine On\nSecRequestBodyAccess On\n");
    for id in 1..=count {
        sec_lang.push_str("SecRule ARGS \"@streq absent\" \"id:");
        sec_lang.push_str(&id.to_string());
        sec_lang
            .push_str(",phase:2,pass,nolog,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls\"\n");
    }
    sec_lang
}

/// The action-update load workload used by the earlier 668-rule measurement.
fn update_action_rules() -> String {
    let mut sec_lang = String::from("SecRuleEngine On\n");
    let message = "m".repeat(256);
    let log_data = "d".repeat(256);
    for id in 1..=UPDATE_RULES {
        sec_lang.push_str("SecRule ARGS:q \"@rx ^attack[0-9]+$\" \"id:");
        sec_lang.push_str(&id.to_string());
        sec_lang.push_str(",phase:1,log,pass,msg:'");
        sec_lang.push_str(&message);
        sec_lang.push_str("',logdata:'");
        sec_lang.push_str(&log_data);
        sec_lang.push_str("',tag:'performance-batch-d',t:urlDecodeUni,t:lowercase,setvar:TX.bench=+1\"\n");
    }
    for index in 0..ACTION_UPDATES {
        let id = index % UPDATE_RULES + 1;
        sec_lang.push_str("SecRuleUpdateActionById ");
        sec_lang.push_str(&id.to_string());
        sec_lang.push_str(" \"nolog\"\n");
    }
    sec_lang
}

/// Generate the load-time duplicate-check workload.
fn configure_rules() -> String {
    let mut sec_lang = String::with_capacity(CONFIGURE_RULES.saturating_mul(32));
    for id in 1..=CONFIGURE_RULES {
        sec_lang.push_str("SecAction \"id:");
        sec_lang.push_str(&id.to_string());
        sec_lang.push_str(",phase:1,pass\"\n");
    }
    sec_lang
}

/// Repeated ID-bearing action updates that previously cloned every compiled rule.
fn update_id_action_rules() -> String {
    let mut sec_lang = String::from("SecRuleEngine On\n");
    for id in 1..=UPDATE_RULES {
        sec_lang.push_str("SecAction \"id:");
        sec_lang.push_str(&id.to_string());
        sec_lang.push_str(",phase:1,log,pass\"\n");
    }
    for index in 0..ACTION_UPDATES {
        let id = index % UPDATE_RULES + 1;
        sec_lang.push_str("SecRuleUpdateActionById ");
        sec_lang.push_str(&id.to_string());
        sec_lang.push_str(" \"id:");
        sec_lang.push_str(&id.to_string());
        sec_lang.push_str(",nolog\"\n");
    }
    sec_lang
}

/// Repeated narrow target ranges over a larger rule group.
fn update_target_range_rules() -> String {
    let mut sec_lang = String::with_capacity(CONFIGURE_RULES.saturating_mul(64));
    for id in 1..=CONFIGURE_RULES {
        sec_lang.push_str("SecRule ARGS:q \"@streq absent\" \"id:");
        sec_lang.push_str(&id.to_string());
        sec_lang.push_str(",phase:2,pass\"\n");
    }
    for index in 0..ACTION_UPDATES {
        let start = index * 10 + 1;
        let end = start + 7;
        sec_lang.push_str("SecRuleUpdateTargetById ");
        sec_lang.push_str(&start.to_string());
        sec_lang.push('-');
        sec_lang.push_str(&end.to_string());
        sec_lang.push_str(" \"ARGS:target\"\n");
    }
    sec_lang
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
fn phase12(waf: &Waf, uri: &str, body: &[u8]) -> Transaction {
    let mut transaction = waf.new_transaction();
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
    transaction
}

/// Drives and drops one request transaction, as the timed request rows do.
fn run_phase12(waf: &Waf, uri: &str, body: &[u8]) {
    black_box(phase12(waf, uri, body));
}

/// Runs the `transform` group.
fn bench_transform(args: &Args, rows: &mut Vec<(&'static str, Timings)>) -> Result<(), String> {
    let chain = crs_chain();
    let empty = TransformationChain::new();
    let small = SMALL_INPUT;
    let large = two_kib_input();
    let (transformed, errors) = chain.apply(small);
    if !errors.is_empty() || transformed == small {
        return Err("transform benchmark precheck failed".to_owned());
    }
    if empty.apply(&large).0 != large {
        return Err("empty transformation benchmark precheck failed".to_owned());
    }

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
    Ok(())
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
    let unmatched = compile(&unmatched_rules(UNMATCHED_RULES, ""), "select unmatched rules")?;
    let shared_prefix = compile(&shared_prefix_rules(32), "select shared transform prefix")?;
    let message = compile(&unmatched_rules(1, "msg:'uri=%{REQUEST_URI}'"), "select message macro")?;
    let matching = compile(
        "SecRuleEngine On\nSecRequestBodyAccess On\n\
         SecRule ARGS \"@streq hit\" \"id:4,phase:2,pass,nolog\"",
        "select matching",
    )?;
    let early_match = compile(
        "SecRuleEngine On\nSecRule ARGS \"@streq hit\" \"id:5,phase:1,pass,nolog,setvar:TX.hits=+1\"",
        "select early match with large ARGS",
    )?;
    let body = twenty_arg_body();
    let hit_body = twenty_match_arg_body();
    let large_value = vec![b'x'; EARLY_MATCH_VALUE_BYTES];
    let uri = "/bench/form";
    let parsed = phase12(&baseline, uri, &body);
    if parsed.get_variable(RuleVariable::ArgsPost, Some("arg00")).is_none() {
        return Err("baseline request benchmark did not parse its 20 arguments".to_owned());
    }
    if !parsed.matched_rules().is_empty()
        || !phase12(&streq, uri, &body).matched_rules().is_empty()
        || !phase12(&rx, uri, &body).matched_rules().is_empty()
        || !phase12(&unmatched, uri, &body).matched_rules().is_empty()
        || !phase12(&shared_prefix, uri, &body).matched_rules().is_empty()
        || !phase12(&message, uri, &body).matched_rules().is_empty()
    {
        return Err("non-matching request benchmark unexpectedly matched".to_owned());
    }
    let matched = phase12(&matching, uri, &hit_body);
    if matched.matched_rules().first().map(|rule| rule.matches.len()) != Some(20) {
        return Err("matching request benchmark did not record all 20 arguments".to_owned());
    }
    verify_early_match(&early_match, &large_value)?;

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
    rows.push((
        "select/txn_128_unmatched_rules_20args",
        time_repetitions(args.iterations, args.repetitions, || {
            run_phase12(&unmatched, uri, &body);
        }),
    ));
    rows.push((
        "transform/txn_shared_prefix_32rules_20args",
        time_repetitions(args.iterations, args.repetitions, || {
            run_phase12(&shared_prefix, uri, &body);
        }),
    ));
    rows.push((
        "select/txn_message_macro_miss_20args",
        time_repetitions(args.iterations, args.repetitions, || {
            run_phase12(&message, uri, &body);
        }),
    ));
    rows.push((
        "select/txn_match_20args",
        time_repetitions(args.iterations, args.repetitions, || {
            run_phase12(&matching, uri, &hit_body);
        }),
    ));
    rows.push((
        "select/txn_early_match_1000_args_8k",
        time_repetitions_with_warmup(1, args.repetitions, 1, || {
            let mut transaction = early_match.new_transaction();
            add_early_match_arguments(&mut transaction, &large_value);
            black_box(transaction.process_request_headers());
            black_box(transaction.matched_rules());
        }),
    ));
    bench_transaction_pool(args, rows)
}

/// Check pooled state isolation and measure transaction creation and drop.
fn bench_transaction_pool(args: &Args, rows: &mut Vec<(&'static str, Timings)>) -> Result<(), String> {
    let no_rules = Waf::new(coraza::config::WafConfig::default()).map_err(|error| error.to_string())?;
    let mut dirty = no_rules.new_transaction();
    dirty.set_tx_variable("pool-probe", "must-not-leak");
    drop(dirty);
    let fresh = no_rules.new_transaction();
    if fresh.get_variable(RuleVariable::TX, Some("pool-probe")).is_some() {
        return Err("transaction pool precheck leaked a TX value".to_owned());
    }
    drop(fresh);
    rows.push((
        "transaction/create_drop",
        time_repetitions(args.iterations, args.repetitions, || {
            black_box(no_rules.new_transaction());
        }),
    ));
    Ok(())
}

/// Isolated collection insertion and repeated single-value replacement workloads.
fn bench_collections(args: &Args, rows: &mut Vec<(&'static str, Timings)>) -> Result<(), String> {
    let waf = Waf::new(coraza::config::WafConfig::default()).map_err(|error| error.to_string())?;
    let entries: Vec<_> = (0..20)
        .map(|index| (format!("arg{index:02}"), format!("value-{index:02}")))
        .collect();
    let mut check = waf.new_transaction();
    for (key, value) in &entries {
        check.add_get_argument(key, value);
    }
    if check.get_variable(RuleVariable::ArgsGet, Some("arg00")).as_deref() != Some("value-00") {
        return Err("map insertion benchmark did not retain its first argument".to_owned());
    }
    rows.push((
        "map/20_get_argument_insertions",
        time_repetitions(args.iterations, args.repetitions, || {
            let mut transaction = waf.new_transaction();
            for (key, value) in &entries {
                transaction.add_get_argument(key, value);
            }
            black_box(transaction.get_variable(RuleVariable::ArgsGet, Some("arg00")));
        }),
    ));

    let long_value = vec![b'x'; 2048];
    let short_value = b"/short";
    let mut check = Transaction::new("single-set-check");
    check.set_request_uri(&long_value);
    for _ in 0..64 {
        check.set_request_uri(short_value);
    }
    if check.get_variable(RuleVariable::RequestURI, None).as_deref() != Some("/short") {
        return Err("single replacement benchmark returned the wrong final value".to_owned());
    }
    rows.push((
        "single/repeated_request_uri_set",
        time_repetitions(args.iterations, args.repetitions, || {
            let mut transaction = Transaction::new("single-set-bench");
            transaction.set_request_uri(black_box(&long_value));
            for _ in 0..64 {
                transaction.set_request_uri(black_box(short_value));
            }
            black_box(transaction.get_variable(RuleVariable::RequestURI, None));
        }),
    ));
    Ok(())
}

/// Runs isolated P-08 near-match workloads with request-backed macro operands.
fn bench_contains(args: &Args, rows: &mut Vec<(&'static str, Timings)>) -> Result<(), String> {
    let mut tx = Transaction::new("micro-bench-contains");
    let mut needle = vec![b'a'; 64 * 1024];
    needle.push(b'b');
    tx.add_get_argument("n", &needle);
    tx.add_get_argument("pattern", b"needle");
    let haystack = vec![b'a'; 128 * 1024];
    let operator = contains("%{ARGS.n}").map_err(|error| format!("contains: {error}"))?;
    let mut outputs = Outputs::default();
    if operator.evaluate(&tx, &haystack, &mut outputs) {
        return Err("contains near-match benchmark unexpectedly matched".to_owned());
    }

    rows.push((
        "contains/args_macro_near_miss_128k",
        // One timed call per sample keeps the quadratic pre-fix practical to measure.
        time_repetitions(1, args.repetitions, || {
            black_box(operator.evaluate(black_box(&tx), black_box(&haystack), &mut outputs));
        }),
    ));

    let operator = within("%{ARGS.pattern}").map_err(|error| format!("within: {error}"))?;
    if tx.get_variable(RuleVariable::Args, Some("pattern")).as_deref() != Some("needle") {
        return Err("within macro parameter did not expand to the expected short string".to_owned());
    }
    let input = vec![b'a'; 128 * 1024];
    if operator.evaluate(&tx, &input, &mut outputs) {
        return Err("within short-parameter benchmark unexpectedly matched".to_owned());
    }
    rows.push((
        "within/short_param_128k",
        // One timed call per sample keeps the reversed-argument case cheap to measure.
        time_repetitions(1, args.repetitions, || {
            black_box(operator.evaluate(black_box(&tx), black_box(&input), &mut outputs));
        }),
    ));
    Ok(())
}

/// Times dynamic phrase caching, constant macro expansion, short-input `@pm`, and `@rx`.
fn bench_operators(args: &Args, rows: &mut Vec<(&'static str, Timings)>) -> Result<(), String> {
    let mut tx = Transaction::new("micro-bench-operators");
    tx.add_get_argument("pattern", b"needle phrase");
    let dynamic_pm = pm("%{ARGS.pattern}").map_err(|error| format!("pm: {error}"))?;
    let mut outputs = Outputs::default();
    if !dynamic_pm.evaluate(&tx, b"needle", &mut outputs) {
        return Err("dynamic @pm benchmark did not match its request-backed phrase".to_owned());
    }
    rows.push((
        "pm/dynamic_macro_reuse",
        time_repetitions(args.iterations, args.repetitions, || {
            black_box(dynamic_pm.evaluate(black_box(&tx), b"needle", &mut outputs));
        }),
    ));

    let long_phrase = "p".repeat(8 * 1024);
    let short_pm = pm(&long_phrase).map_err(|error| format!("pm: {error}"))?;
    let short_input = vec![b'x'; 4 * 1024];
    if short_pm.evaluate(&tx, &short_input, &mut outputs) {
        return Err("short @pm benchmark unexpectedly matched".to_owned());
    }
    rows.push((
        "pm/short_input_long_phrase_4k",
        time_repetitions(args.iterations, args.repetitions, || {
            black_box(short_pm.evaluate(black_box(&tx), black_box(&short_input), &mut outputs));
        }),
    ));

    let constant_streq = streq("constant-parameter").map_err(|error| format!("streq: {error}"))?;
    if !constant_streq.evaluate(&tx, b"constant-parameter", &mut outputs) {
        return Err("constant @streq benchmark did not match".to_owned());
    }
    rows.push((
        "macro/constant_streq",
        time_repetitions(args.iterations, args.repetitions, || {
            black_box(constant_streq.evaluate(black_box(&tx), b"constant-parameter", &mut outputs));
        }),
    ));

    let regex = rx("^needle$").map_err(|error| format!("rx: {error}"))?;
    let regex_tx = Transaction::new("micro-bench-rx");
    let valid_input = vec![b'x'; 4096];
    let invalid_input = vec![0xFF; 4096];
    if regex.evaluate(&regex_tx, &valid_input, &mut outputs) || regex.evaluate(&regex_tx, &invalid_input, &mut outputs)
    {
        return Err("@rx miss benchmark unexpectedly matched".to_owned());
    }
    rows.push((
        "rx/valid_utf8_miss_4k",
        time_repetitions(args.iterations, args.repetitions, || {
            black_box(regex.evaluate(black_box(&regex_tx), black_box(&valid_input), &mut outputs));
        }),
    ));
    rows.push((
        "rx/invalid_utf8_miss_4k",
        time_repetitions(args.iterations, args.repetitions, || {
            black_box(regex.evaluate(black_box(&regex_tx), black_box(&invalid_input), &mut outputs));
        }),
    ));
    Ok(())
}

/// Times the default-plus-strict `SQLi` API without weakening its detection union.
fn bench_sqli_fallback(args: &Args, rows: &mut Vec<(&'static str, Timings)>) -> Result<(), String> {
    let cases = [
        ("sqli/plain_miss", b"ordinary request parameter".as_slice(), false),
        (
            "sqli/strict_word_prose_miss",
            b"the JSON_EXTRACT function returns a value",
            false,
        ),
        (
            "sqli/statement_word_prose_miss",
            b"please copy the report and attach the file",
            false,
        ),
        (
            "sqli/mixed_strict_words_prose_miss",
            b"JSON_EXTRACT and GTID_SUBSET are database functions",
            false,
        ),
        ("sqli/strict_fallback_hit", b"1 AND JSON_EXTRACT(a,b)=1--", true),
        (
            "sqli/default_union_hit",
            b"-2 union select 1,2 copy,version() from x",
            true,
        ),
    ];
    for (name, input, expected) in cases {
        let detected = libperfusion::sqli_with_strict_fallback(input).is_some();
        if detected != expected {
            return Err(format!("{name} verdict changed before timing"));
        }
        if name == "sqli/default_union_hit" && libperfusion::sqli(input).is_none() {
            return Err("the default SQLi control must remain a hit".to_owned());
        }
        rows.push((
            name,
            time_repetitions(args.iterations, args.repetitions, || {
                black_box(libperfusion::sqli_with_strict_fallback(black_box(input)));
            }),
        ));
    }
    Ok(())
}

/// Times repeated `SecRuleUpdateActionById` directives and 30k-rule configure.
fn bench_configure(args: &Args, rows: &mut Vec<(&'static str, Timings)>) -> Result<(), String> {
    let updates = update_action_rules();
    let update_waf = compile(&updates, "action update benchmark")?;
    if update_waf.rule_count() != UPDATE_RULES {
        return Err("action update benchmark loaded the wrong number of rules".to_owned());
    }
    let mut check = update_waf.new_transaction_with_id("action-update-check");
    check.add_get_argument("q", "attack1");
    if check.process_request_headers().is_some()
        || check.matched_rules().len() != UPDATE_RULES
        || check.matched_rules().iter().any(|rule| rule.rule.log())
    {
        return Err("action update benchmark did not update every matched rule".to_owned());
    }
    rows.push((
        "configure/update_action_668_rules_800_directives",
        time_repetitions_with_warmup(1, args.repetitions, 1, || {
            black_box(compile(&updates, "action update benchmark").is_ok());
        }),
    ));

    let id_updates = update_id_action_rules();
    let id_update_waf = compile(&id_updates, "ID-bearing action update benchmark")?;
    if id_update_waf.rule_count() != UPDATE_RULES {
        return Err("ID-bearing action update benchmark loaded the wrong number of rules".to_owned());
    }
    let mut id_update_check = id_update_waf.new_transaction_with_id("id-action-update-check");
    if id_update_check.process_request_headers().is_some()
        || id_update_check.matched_rules().len() != UPDATE_RULES
        || id_update_check.matched_rules().iter().any(|rule| rule.rule.log())
    {
        return Err("ID-bearing action update benchmark did not update every rule".to_owned());
    }
    rows.push((
        "configure/update_id_action_668_rules_800_directives",
        time_repetitions_with_warmup(1, args.repetitions, 1, || {
            black_box(compile(&id_updates, "ID-bearing action update benchmark").is_ok());
        }),
    ));

    let rules = configure_rules();
    let configured = compile(&rules, "30k rule configure benchmark")?;
    if configured.rule_count() != CONFIGURE_RULES {
        return Err("30k rule benchmark loaded the wrong number of rules".to_owned());
    }
    rows.push((
        "configure/30000_rules",
        time_repetitions_with_warmup(1, args.repetitions, 1, || {
            black_box(compile(&rules, "30k rule configure benchmark").is_ok());
        }),
    ));

    let target_updates = update_target_range_rules();
    let target_update_waf = compile(&target_updates, "range target update benchmark")?;
    if target_update_waf.rule_count() != CONFIGURE_RULES {
        return Err("range target update benchmark loaded the wrong number of rules".to_owned());
    }
    rows.push((
        "configure/update_target_30000_rules_800_ranges",
        time_repetitions_with_warmup(1, args.repetitions, 1, || {
            black_box(compile(&target_updates, "range target update benchmark").is_ok());
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
    let checked = phase12(&waf, uri, &body);
    let username = checked.get_variable(RuleVariable::ArgsPost, Some("username"));
    if username.as_deref() != Some("katz") {
        return Err(format!(
            "CRS request precheck did not parse username: {username:?}, interruption={:?}",
            checked.interruption()
        ));
    }
    if checked.interruption().is_some() {
        return Err(format!(
            "CRS request benchmark interrupted: {:?}; matched rules: {:?}",
            checked.interruption(),
            checked
                .matched_rules()
                .iter()
                .map(|matched| matched.rule.id())
                .collect::<Vec<_>>()
        ));
    }

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

    bench_transform(args, &mut rows)?;
    bench_contains(args, &mut rows)?;
    bench_select(args, &mut rows)?;
    bench_collections(args, &mut rows)?;
    bench_operators(args, &mut rows)?;
    bench_sqli_fallback(args, &mut rows)?;
    bench_configure(args, &mut rows)?;
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
