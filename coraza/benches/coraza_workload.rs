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

//! Validate and time the shared Coraza workload against the Rust engine.
//!
//! `cargo bench -p coraza --bench coraza_workload -- [--workloads <dir>] [--outcome <file>]`
//!
//! `cargo bench -p coraza --bench coraza_workload -- [--workloads <dir>] --timing <file> --iterations <n>`
//!
//! Without `--timing`, the driver loads and validates the workload once, runs
//! every case through the public lifecycle and compares the observable outcome
//! with the case's expected block. `--outcome` additionally writes the
//! language-neutral NDJSON outcome document consumed by the correctness parity
//! runner. With `--timing`, the driver loads and compiles the workload once and
//! times exactly `--iterations` fresh transactions per case, then writes the
//! timing document described by the coordinator contract. The timed section is
//! documented on `driver::run_timing`.

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the driver reports validation results to the coordinator"
)]

#[path = "coraza_workload/driver.rs"]
mod driver;

use std::{env, path::PathBuf, process::ExitCode};

use driver::{
    DriverError, compare_expected, load_workload, outcome_document, parse_iterations, run_case, run_timing,
    timing_document, write_outcomes, write_timing_document,
};

/// Workload directory shipped next to the coraza crate.
const DEFAULT_WORKLOADS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../benchmarks/coraza/workloads");

/// Runs the driver and maps a validation failure to a non-zero exit code.
fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("coraza workload driver failed: {error}");
            ExitCode::FAILURE
        },
    }
}

/// Arguments accepted by the driver.
struct Arguments {
    /// Workload directory to load.
    workloads: PathBuf,
    /// How the loaded workload is exercised.
    mode: Mode,
}

/// How the loaded workload is exercised.
enum Mode {
    /// Validate each case once and optionally write the NDJSON outcome document.
    Outcome {
        /// Optional NDJSON outcome document path.
        outcome: Option<PathBuf>,
    },
    /// Time every case through the lifecycle and write the timing document.
    Timing {
        /// Timing document path.
        timing: PathBuf,
        /// Fresh transactions per case.
        iterations: usize,
    },
}

/// Loads, validates and runs the complete workload.
fn run(args: impl Iterator<Item = String>) -> Result<(), DriverError> {
    let arguments = parse_args(args)?;
    let workload = load_workload(&arguments.workloads)?;
    match &arguments.mode {
        Mode::Outcome { outcome } => {
            let mut documents = Vec::new();
            for prepared in &workload.cases {
                let observed = run_case(prepared)?;
                compare_expected(&prepared.case, &observed)?;
                if outcome.is_some() {
                    documents.push(outcome_document(&prepared.case, &observed));
                }
                println!("case {}: pass", prepared.case.case_id);
            }
            if let Some(path) = outcome {
                write_outcomes(path, &documents)?;
            }
            println!("{} cases passed", workload.cases.len());
        },
        Mode::Timing { timing, iterations } => {
            let cases = run_timing(&workload, *iterations)?;
            let document = timing_document(&workload, *iterations, &cases);
            write_timing_document(timing, &document)?;
            println!("{} cases timed for {iterations} iterations each", workload.cases.len());
        },
    }
    Ok(())
}

/// Parses the optional workload directory and the selected output mode.
fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Arguments, DriverError> {
    let mut workloads = PathBuf::from(DEFAULT_WORKLOADS);
    let mut outcome = None;
    let mut timing = None;
    let mut iterations = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            // Cargo passes this marker to harness-less benchmark binaries.
            "--bench" | "--test" => {},
            "--workloads" => {
                let value = args
                    .next()
                    .ok_or_else(|| DriverError::Load("--workloads requires a directory".to_owned()))?;
                workloads = PathBuf::from(value);
            },
            "--outcome" => {
                let value = args
                    .next()
                    .ok_or_else(|| DriverError::Load("--outcome requires a file path".to_owned()))?;
                outcome = Some(PathBuf::from(value));
            },
            "--timing" => {
                let value = args
                    .next()
                    .ok_or_else(|| DriverError::Load("--timing requires a file path".to_owned()))?;
                timing = Some(PathBuf::from(value));
            },
            "--iterations" => {
                let value = args
                    .next()
                    .ok_or_else(|| DriverError::Load("--iterations requires a count".to_owned()))?;
                iterations = Some(value);
            },
            other => {
                return Err(DriverError::Load(format!(
                    "unknown argument {other}; usage: [--workloads <dir>] [--outcome <file>] or [--workloads <dir>] --timing <file> --iterations <n>"
                )));
            },
        }
    }
    let mode = match (timing, iterations, outcome) {
        (Some(_), _, Some(_)) => {
            return Err(DriverError::Load(
                "--outcome and --timing are mutually exclusive".to_owned(),
            ));
        },
        (None, Some(_), _) => {
            return Err(DriverError::Load("--iterations requires --timing".to_owned()));
        },
        (Some(_), None, _) => {
            return Err(DriverError::Load("--timing requires --iterations".to_owned()));
        },
        (Some(timing), Some(iterations), None) => Mode::Timing {
            timing,
            iterations: parse_iterations(&iterations)?,
        },
        (None, None, outcome) => Mode::Outcome { outcome },
    };
    Ok(Arguments { workloads, mode })
}
