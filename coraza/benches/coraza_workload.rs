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

//! Validate the shared Coraza workload against the Rust engine.
//!
//! `cargo bench -p coraza --bench coraza_workload -- [--workloads <dir>] [--outcome <file>]`
//!
//! The same executable is the future measurement driver. This wave only loads
//! and validates the workload once, runs every case through the public
//! lifecycle and compares the observable outcome with the case's expected
//! block. `--outcome` additionally writes the language-neutral NDJSON outcome
//! document consumed by the correctness parity runner. There is no timing code
//! here.

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the driver reports validation results to the coordinator"
)]

#[path = "coraza_workload/driver.rs"]
mod driver;

use std::{env, path::PathBuf, process::ExitCode};

use driver::{DriverError, compare_expected, load_workload, outcome_document, run_case, write_outcomes};

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
    /// Optional NDJSON outcome document path.
    outcome: Option<PathBuf>,
}

/// Loads, validates and runs the complete workload.
fn run(args: impl Iterator<Item = String>) -> Result<(), DriverError> {
    let arguments = parse_args(args)?;
    let cases = load_workload(&arguments.workloads)?;
    let mut documents = Vec::new();
    for prepared in &cases {
        let outcome = run_case(prepared)?;
        compare_expected(&prepared.case, &outcome)?;
        if arguments.outcome.is_some() {
            documents.push(outcome_document(&prepared.case, &outcome));
        }
        println!("case {}: pass", prepared.case.case_id);
    }
    if let Some(path) = &arguments.outcome {
        write_outcomes(path, &documents)?;
    }
    println!("{} cases passed", cases.len());
    Ok(())
}

/// Parses the optional workload directory and outcome overrides.
fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Arguments, DriverError> {
    let mut workloads = PathBuf::from(DEFAULT_WORKLOADS);
    let mut outcome = None;
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
            other => {
                return Err(DriverError::Load(format!(
                    "unknown argument {other}; usage: [--workloads <dir>] [--outcome <file>]"
                )));
            },
        }
    }
    Ok(Arguments { workloads, outcome })
}
