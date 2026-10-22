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
//! `cargo bench -p coraza --bench coraza_workload -- [--workloads <dir>]`
//!
//! The same executable is the future measurement driver. This wave only loads
//! and validates the workload once, runs every case through the public
//! lifecycle and compares the observable outcome with the case's expected
//! block. There is no timing code here.

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the driver reports validation results to the coordinator"
)]

#[path = "coraza_workload/driver.rs"]
mod driver;

use std::{env, path::PathBuf, process::ExitCode};

use driver::{DriverError, compare_expected, load_workload, run_case};

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

/// Loads, validates and runs the complete workload.
fn run(args: impl Iterator<Item = String>) -> Result<(), DriverError> {
    let root = parse_args(args)?;
    let cases = load_workload(&root)?;
    for prepared in &cases {
        let outcome = run_case(prepared)?;
        compare_expected(&prepared.case, &outcome)?;
        println!("case {}: pass", prepared.case.case_id);
    }
    println!("{} cases passed", cases.len());
    Ok(())
}

/// Parses the optional workload directory override.
fn parse_args(mut args: impl Iterator<Item = String>) -> Result<PathBuf, DriverError> {
    let mut root = PathBuf::from(DEFAULT_WORKLOADS);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            // Cargo passes this marker to harness-less benchmark binaries.
            "--bench" | "--test" => {},
            "--workloads" => {
                let value = args
                    .next()
                    .ok_or_else(|| DriverError::Load("--workloads requires a directory".to_owned()))?;
                root = PathBuf::from(value);
            },
            other => {
                return Err(DriverError::Load(format!(
                    "unknown argument {other}; usage: [--workloads <dir>]"
                )));
            },
        }
    }
    Ok(root)
}
