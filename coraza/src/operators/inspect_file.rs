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
//
// This port is based on the original Coraza, created by Juan Pablo Tosso and
// the OWASP Coraza contributors.
//
// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! The `@inspectFile` operator: run an external program over each value.
//!
//! Ported from `internal/operators/inspect_file.go` in Coraza v3.8.1. The
//! program receives the inspected value as its only argument and prints its
//! verdict: a first output byte of `1` means no match, any other non-empty
//! output means match. A missed deadline, a spawn failure, or a non-zero exit
//! status means no match.

use std::{
    io::Read,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

use crate::{
    operators::{Operator, Outputs},
    transaction::Transaction,
};

/// Go's `10*time.Second` deadline for the command in `inspect_file.go`.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// Runs an external program for every inspected value.
#[derive(Debug, Clone)]
pub struct InspectFile {
    /// Program or script path, as written in the operator argument.
    path: String,
}

impl InspectFile {
    /// Create the operator for the program or script at `path`.
    pub fn new(path: &str) -> Self {
        Self { path: path.to_owned() }
    }
}

impl Operator for InspectFile {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        run(&self.path, input).is_some_and(|output| output.first().is_some_and(|first| *first != b'1'))
    }
}

/// Creates a new `inspectFile` operator.
pub fn inspect_file(path: &str) -> InspectFile {
    InspectFile::new(path)
}

/// Run `path` with the value as its argument, bounded by [`COMMAND_TIMEOUT`].
///
/// Returns the combined output when the program exited successfully.
fn run(path: &str, input: &[u8]) -> Option<Vec<u8>> {
    run_with_timeout(path, input, COMMAND_TIMEOUT)
}

/// Run `path` with the value as its argument, bounded by `timeout`.
///
/// Go passes the value as a byte string. Bytes that are not UTF-8 are replaced
/// when building the argument.
fn run_with_timeout(path: &str, input: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let mut child = Command::new(path)
        .arg(String::from_utf8_lossy(input).as_ref())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let (sender, receiver) = mpsc::channel();
    if let Some(pipe) = child.stdout.take() {
        read_output(pipe, false, sender.clone());
    }
    if let Some(pipe) = child.stderr.take() {
        read_output(pipe, true, sender.clone());
    }
    drop(sender);

    let deadline = Instant::now() + timeout;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    for _ in 0..2 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Ok((is_stderr, bytes)) = receiver.recv_timeout(remaining) else {
            kill_and_reap(&mut child);
            return None;
        };
        if is_stderr {
            stderr = bytes;
        } else {
            stdout = bytes;
        }
    }

    // The pipes reached end-of-file, so the program exited and `wait` reaps it.
    let status = child.wait().ok()?;
    if !status.success() {
        return None;
    }
    // Go reads one combined stream. Here stdout precedes stderr, so the first
    // byte differs from Go only when both streams carried output.
    stdout.extend_from_slice(&stderr);
    Some(stdout)
}

/// Kill a program that overran its deadline and reap it, leaving no zombie.
fn kill_and_reap(child: &mut Child) {
    drop(child.kill());
    drop(child.wait());
}

/// Read one output pipe to its end on a worker thread.
///
/// A descendant that keeps the pipe open after the kill can outlive the
/// deadline; that reader thread is abandoned until the pipe closes.
fn read_output(mut pipe: impl Read + Send + 'static, is_stderr: bool, sender: mpsc::Sender<(bool, Vec<u8>)>) {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if pipe.read_to_end(&mut bytes).is_err() {
            bytes.clear();
        }
        // A timeout drops the receiver, and the output is unusable then.
        drop(sender.send((is_stderr, bytes)));
    });
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "inspectFile tests use fixed scripts they create")]
mod tests {
    use std::{path::Path, time::Duration};

    use super::{InspectFile, run_with_timeout};
    use crate::{
        operators::{Operator as _, Outputs},
        transaction::Transaction,
    };

    /// Whether the host has the `sh` and `echo` programs these tests need.
    #[cfg(unix)]
    fn shell_available() -> bool {
        Path::new("/bin/sh").exists() && Path::new("/bin/echo").exists()
    }

    /// Write a `#!/bin/sh` script and return its path.
    ///
    /// A temp script is run as `sh <path>` rather than executed directly: the
    /// script is then only read, which keeps the test independent of exec
    /// permissions and of the parallel harness.
    #[cfg(unix)]
    fn script(dir: &Path, body: &str) -> String {
        let path = dir.join("inspect.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn evaluates(program: &str, input: &[u8]) -> bool {
        let operator = InspectFile::new(program);
        operator.evaluate(&Transaction::new("inspect-file"), input, &mut Outputs::default())
    }

    /// Run `body` under `sh` and report the operator's verdict.
    #[cfg(unix)]
    fn evaluates_script(body: &str) -> bool {
        let dir = tempfile::tempdir().unwrap();
        let path = script(dir.path(), body);
        evaluates("/bin/sh", path.as_bytes())
    }

    #[test]
    fn command_not_found_is_no_match() {
        assert!(!evaluates("/nonexistent/coraza-inspect-file-test", b"value"));
    }

    #[cfg(unix)]
    #[test]
    fn the_value_is_passed_as_the_argument() {
        if !shell_available() {
            return;
        }
        assert!(!evaluates("/bin/echo", b"1 clamscan: OK"));
        assert!(evaluates("/bin/echo", b"0 clamscan: FOUND"));
    }

    #[cfg(unix)]
    #[test]
    fn first_output_byte_one_is_no_match() {
        if !shell_available() {
            return;
        }
        assert!(!evaluates_script("printf '1 clamscan: OK'"));
    }

    #[cfg(unix)]
    #[test]
    fn any_other_first_output_byte_is_match() {
        if !shell_available() {
            return;
        }
        assert!(evaluates_script("printf '0 clamscan: FOUND'"));
        assert!(evaluates_script("printf 'x'"));
    }

    #[cfg(unix)]
    #[test]
    fn empty_output_is_no_match() {
        if !shell_available() {
            return;
        }
        assert!(!evaluates_script("exit 0"));
    }

    #[cfg(unix)]
    #[test]
    fn stderr_is_part_of_the_combined_output() {
        if !shell_available() {
            return;
        }
        assert!(evaluates_script("printf '0' >&2"));
    }

    #[cfg(unix)]
    #[test]
    fn nonzero_exit_status_is_no_match() {
        if !shell_available() {
            return;
        }
        assert!(!evaluates_script("printf '0'\nexit 3"));
    }

    #[cfg(unix)]
    #[test]
    fn a_program_that_overruns_the_deadline_is_killed() {
        if !shell_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = script(dir.path(), "exec sleep 5");
        assert_eq!(
            run_with_timeout("/bin/sh", path.as_bytes(), Duration::from_millis(50)),
            None
        );
    }
}
