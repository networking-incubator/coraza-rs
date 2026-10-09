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

//! Development tasks for coraza-rs.

#![allow(
    clippy::exit,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unused_result_ok,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "development tooling"
)]

mod corpus;
mod lint_license;

use clap::{Parser, Subcommand};

// -----------------------------------------------------------------------------
// CLI Definition
// -----------------------------------------------------------------------------

/// Top-level CLI for xtask development commands.
#[derive(Parser)]
#[command(name = "xtask", about = "coraza-rs development tasks")]
struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    command: Command,
}

/// Available xtask subcommands.
#[derive(Subcommand)]
enum Command {
    /// Check that every tracked `.rs` file starts with the required
    /// copyright header.
    LintLicense(lint_license::Args),
    /// Verify fixture hashes and the SQL oracle inputs.
    CorpusCheck,
    /// Refresh fixtures and the SQL oracle from the pinned Go module version.
    CorpusRefresh,
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

/// Dispatch the CLI subcommand to its handler.
fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::LintLicense(args) => lint_license::run(args),
        Command::CorpusCheck => corpus::check_or_exit(),
        Command::CorpusRefresh => corpus::refresh_or_exit(),
    }
}
