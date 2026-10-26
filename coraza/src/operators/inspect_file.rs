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
//! output means match.
//!
//! Divergences from Go, all of them fail-closed for the rule:
//!
//! - A missed deadline, a spawn failure, a failed wait, or output beyond [`OUTPUT_CAP`] reports
//!   [`OperatorOutcome::NotInspected`](crate::operators::OperatorOutcome::NotInspected) rather than a plain non-match.
//!   Rules treat both as not matched; the transaction records which one happened.
//! - A non-zero exit status stays a non-match, as in Go.
//! - On Unix both streams share one socket, so the combined output keeps the program's write order like Go's
//!   `CombinedOutput`. On other platforms the streams are separate pipes and stdout is read before stderr.
//! - On Unix the value is passed as its raw bytes; elsewhere it is converted lossily, because those platforms have no
//!   byte path form.
//!
//! Resource bounds: the whole spawn-to-exit window is bounded by
//! [`COMMAND_TIMEOUT`], the retained output is capped at [`OUTPUT_CAP`], and a
//! single reader thread per stream is used. A descendant that survives the
//! kill keeps its reader thread blocked until the last write end closes; that
//! thread holds one descriptor and never more than the cap, and once the cap
//! is reached the read end is dropped so the writer gets `EPIPE`.

use std::{
    borrow::Cow,
    ffi::OsStr,
    io::{self, Read},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

use crate::{
    operators::{Operator, OperatorOutcome, Outputs},
    transaction::Transaction,
};

/// Go's `10*time.Second` deadline for the command in `inspect_file.go`.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest combined output retained from one run.
///
/// A program that writes more is killed and reports no verdict, and its writer
/// then fails on the closed pipe instead of growing this process' memory.
const OUTPUT_CAP: usize = 1024 * 1024;

/// Stack size for the output reader threads, which only run a read loop.
const READER_STACK: usize = 64 * 1024;

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
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        self.evaluate_outcome(tx, input, out) == OperatorOutcome::Matched
    }

    fn evaluate_outcome(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> OperatorOutcome {
        match run(&self.path, input) {
            Run::Completed(output) if first_byte_is_verdict(&output) => OperatorOutcome::Matched,
            Run::Completed(_) => OperatorOutcome::NotMatched,
            Run::Skipped => OperatorOutcome::NotInspected,
        }
    }
}

/// Creates a new `inspectFile` operator.
pub fn inspect_file(path: &str) -> InspectFile {
    InspectFile::new(path)
}

/// Go's verdict on a combined output: non-empty, first byte not `1`.
fn first_byte_is_verdict(output: &[u8]) -> bool {
    output.first().is_some_and(|first| *first != b'1')
}

/// What one bounded run produced.
#[derive(Debug)]
enum Run {
    /// The program exited on its own; the bytes are its combined output.
    Completed(Vec<u8>),
    /// The program could not be run to completion, so there is no verdict.
    Skipped,
}

/// One output stream reader; `true` marks the stderr stream.
type Reader = (bool, Box<dyn Read + Send>);

/// Run `path` with the value as its argument, bounded by [`COMMAND_TIMEOUT`].
fn run(path: &str, input: &[u8]) -> Run {
    run_with_timeout(path, input, COMMAND_TIMEOUT)
}

/// Run `path` with the value as its argument, bounded by `timeout`.
fn run_with_timeout(path: &str, input: &[u8], timeout: Duration) -> Run {
    let deadline = Instant::now() + timeout;
    let Some((mut child, readers)) = spawn_captured(path, &value_argument(input)) else {
        return Run::Skipped;
    };

    let expected = readers.len();
    let (sender, receiver) = mpsc::channel();
    for (is_stderr, reader) in readers {
        if !spawn_reader(reader, is_stderr, sender.clone()) {
            kill_and_reap(&mut child);
            return Run::Skipped;
        }
    }
    drop(sender);

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    for _ in 0..expected {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Ok((is_stderr, bytes)) = receiver.recv_timeout(remaining) else {
            kill_and_reap(&mut child);
            return Run::Skipped;
        };
        let Some(bytes) = bytes else {
            // The cap or a read error leaves no usable verdict.
            kill_and_reap(&mut child);
            return Run::Skipped;
        };
        if is_stderr {
            stderr = bytes;
        } else {
            stdout = bytes;
        }
    }

    // End-of-file only means every write end closed: the program can still be
    // running, so the exit status needs the same deadline.
    let Some(status) = wait_until(&mut child, deadline) else {
        kill_and_reap(&mut child);
        return Run::Skipped;
    };
    if !status.success() {
        // Go reports a non-zero exit status as no match.
        return Run::Completed(Vec::new());
    }
    // On Unix `stderr` is empty: both streams arrived through one socket.
    stdout.extend_from_slice(&stderr);
    Run::Completed(stdout)
}

/// The value as the program's only argument.
///
/// Go passes the value as a byte string. On Unix the argument is those exact
/// bytes; elsewhere a path has no byte form, so the value is converted lossily.
fn value_argument(input: &[u8]) -> Cow<'_, OsStr> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        Cow::Borrowed(OsStr::from_bytes(input))
    }
    #[cfg(not(unix))]
    {
        Cow::Owned(std::ffi::OsString::from(String::from_utf8_lossy(input).into_owned()))
    }
}

/// Spawn the program with its output captured, returning the readers to wait on.
///
/// On Unix both `Stdio`s are ends of the same socket, so the combined output
/// keeps the program's write order, as Go's `CombinedOutput` does.
///
/// `Command` keeps its own copy of each `Stdio` until it is dropped, so it is
/// scoped to the spawn: a surviving copy of the write end would keep the reader
/// from ever seeing end-of-file.
#[cfg(unix)]
fn spawn_captured(path: &str, value: &OsStr) -> Option<(Child, Vec<Reader>)> {
    use std::os::{fd::OwnedFd, unix::net::UnixStream};

    let (read_end, write_end) = UnixStream::pair().ok()?;
    let stderr_end = write_end.try_clone().ok()?;
    let child = {
        let mut command = Command::new(path);
        command
            .arg(value)
            .stdin(Stdio::null())
            .stdout(Stdio::from(OwnedFd::from(write_end)))
            .stderr(Stdio::from(OwnedFd::from(stderr_end)));
        command.spawn().ok()?
    };
    let reader: Box<dyn Read + Send> = Box::new(read_end);
    Some((child, vec![(false, reader)]))
}

/// Spawn the program with its output captured, returning the readers to wait on.
///
/// Without a shared socket the streams stay separate pipes; the caller reads
/// stdout before stderr, which differs from Go only when both carry output.
/// The `Command` is scoped to the spawn for the reason given on the Unix form.
#[cfg(not(unix))]
fn spawn_captured(path: &str, value: &OsStr) -> Option<(Child, Vec<Reader>)> {
    let mut child = {
        let mut command = Command::new(path);
        command
            .arg(value)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.spawn().ok()?
    };
    let mut readers: Vec<Reader> = Vec::with_capacity(2);
    if let Some(pipe) = child.stdout.take() {
        readers.push((false, Box::new(pipe)));
    }
    if let Some(pipe) = child.stderr.take() {
        readers.push((true, Box::new(pipe)));
    }
    Some((child, readers))
}

/// Read `pipe` to its end on a worker thread, reporting `None` when the output
/// is unusable or beyond [`OUTPUT_CAP`].
///
/// A spawn failure is reported to the caller instead of panicking. A descendant
/// that keeps the pipe open after the deadline leaves this thread blocked until
/// the last write end closes; dropping the pipe on the cap closes the read end,
/// so further writes get `EPIPE`.
fn spawn_reader(pipe: Box<dyn Read + Send>, is_stderr: bool, sender: mpsc::Sender<(bool, Option<Vec<u8>>)>) -> bool {
    std::thread::Builder::new()
        .name("coraza-inspect-file".to_owned())
        .stack_size(READER_STACK)
        .spawn(move || {
            // A deadline drops the receiver, and the output is unusable then.
            drop(sender.send((is_stderr, read_capped(pipe))));
        })
        .is_ok()
}

/// Read `pipe` to its end, giving up on [`OUTPUT_CAP`] or a read error.
fn read_capped(mut pipe: impl Read) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) => return Some(bytes),
            Ok(read) => {
                if bytes.len() + read > OUTPUT_CAP {
                    return None;
                }
                let chunk = buffer.get(..read)?;
                bytes.extend_from_slice(chunk);
            },
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
            Err(_) => return None,
        }
    }
}

/// Wait for the program to exit, without passing `deadline`.
fn wait_until(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {},
            Err(_) => return None,
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Kill a program that overran its deadline and reap it, leaving no zombie.
fn kill_and_reap(child: &mut Child) {
    drop(child.kill());
    drop(child.wait());
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "inspectFile tests use fixed scripts they create")]
mod tests {
    use std::{
        io::Read as _,
        path::Path,
        time::{Duration, Instant},
    };

    use super::{InspectFile, OUTPUT_CAP, Run, read_capped, run_with_timeout};
    use crate::{
        operators::{Operator as _, OperatorOutcome, Outputs},
        transaction::Transaction,
    };

    /// Whether the host has the `sh` and `echo` programs these tests need.
    #[cfg(unix)]
    fn shell_available() -> bool {
        sh_available() && Path::new("/bin/echo").exists()
    }

    /// Whether the host has the `sh` program the script tests need.
    #[cfg(unix)]
    fn sh_available() -> bool {
        Path::new("/bin/sh").exists()
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

    /// Write an executable `#!/bin/sh` script and return its path.
    ///
    /// Executable scripts are the only way to receive the inspected value as
    /// `$1`: `sh <path>` would pass the script path instead.
    #[cfg(unix)]
    fn executable_script(dir: &Path, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt as _;

        let path = dir.join("inspect-exec.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn evaluates(program: &str, input: &[u8]) -> bool {
        let operator = InspectFile::new(program);
        operator.evaluate(&Transaction::new("inspect-file"), input, &mut Outputs::default())
    }

    fn outcome(program: &str, input: &[u8]) -> OperatorOutcome {
        let operator = InspectFile::new(program);
        operator.evaluate_outcome(&Transaction::new("inspect-file"), input, &mut Outputs::default())
    }

    /// Run `body` under `sh` and report the operator's verdict.
    #[cfg(unix)]
    fn evaluates_script(body: &str) -> bool {
        let dir = tempfile::tempdir().unwrap();
        let path = script(dir.path(), body);
        evaluates("/bin/sh", path.as_bytes())
    }

    /// Run an executable `body` script and return its completed output.
    #[cfg(unix)]
    fn output_of_script(body: &str, input: &[u8]) -> Option<Vec<u8>> {
        let dir = tempfile::tempdir().unwrap();
        let program = executable_script(dir.path(), body);
        match run_with_timeout(&program, input, Duration::from_secs(5)) {
            Run::Completed(bytes) => Some(bytes),
            Run::Skipped => None,
        }
    }

    #[test]
    fn command_not_found_is_no_match() {
        assert!(!evaluates("/nonexistent/coraza-inspect-file-test", b"value"));
    }

    #[test]
    fn a_spawn_failure_reports_no_verdict() {
        assert_eq!(
            outcome("/nonexistent/coraza-inspect-file-test", b"value"),
            OperatorOutcome::NotInspected
        );
    }

    #[test]
    fn a_value_that_cannot_be_an_argument_reports_no_verdict() {
        // A NUL byte makes exec fail, which must not panic.
        assert_eq!(outcome("/bin/echo", b"value\0"), OperatorOutcome::NotInspected);
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
    fn the_value_is_one_argument_and_is_never_shell_expanded() {
        if !sh_available() {
            return;
        }
        let value = b"; $(id)\nsecond line";
        assert_eq!(
            output_of_script("printf '%s|%s' \"$#\" \"$1\"", value),
            Some(b"1|; $(id)\nsecond line".to_vec()),
            "the value must arrive as a single, unexpanded argument"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_value_bytes_reach_the_program_unchanged() {
        if !sh_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let captured = dir.path().join("captured");
        let program = executable_script(dir.path(), &format!("printf '%s' \"$1\" > '{}'", captured.display()));
        let value = b"a\xffb";
        assert!(matches!(
            run_with_timeout(&program, value, Duration::from_secs(5)),
            Run::Completed(_)
        ));
        assert_eq!(
            std::fs::read(&captured).unwrap(),
            value.to_vec(),
            "the argument must be byte-exact"
        );
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
    fn both_streams_keep_the_write_order() {
        if !sh_available() {
            return;
        }
        // Go's CombinedOutput reads one pipe, so the stderr byte comes first
        // and the verdict is "no match". Reading stdout first would flip it.
        assert_eq!(
            output_of_script("printf '1' >&2\nprintf '0'", b"value"),
            Some(b"10".to_vec())
        );
        assert!(!evaluates_script("printf '1' >&2\nprintf '0'"));
    }

    #[cfg(unix)]
    #[test]
    fn nonzero_exit_status_is_no_match() {
        if !shell_available() {
            return;
        }
        assert!(!evaluates_script("printf '0'\nexit 3"));
        let dir = tempfile::tempdir().unwrap();
        let path = script(dir.path(), "printf '0'\nexit 3");
        assert!(
            matches!(outcome("/bin/sh", path.as_bytes()), OperatorOutcome::NotMatched),
            "a clean run with a failing status is inspected but not a match"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_program_that_overruns_the_deadline_is_killed() {
        if !sh_available() {
            return;
        }
        if !shell_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = script(dir.path(), "exec sleep 5");
        assert!(
            matches!(
                run_with_timeout("/bin/sh", path.as_bytes(), Duration::from_millis(50)),
                Run::Skipped
            ),
            "an overrun has no verdict"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_clean_run_reports_a_verdict() {
        if !sh_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = script(dir.path(), "printf '1'");
        assert_eq!(
            outcome("/bin/sh", path.as_bytes()),
            OperatorOutcome::NotMatched,
            "a clean run stays a plain non-match"
        );
    }

    #[cfg(unix)]
    #[test]
    fn closing_both_pipes_then_sleeping_is_bounded() {
        if !sh_available() {
            return;
        }
        // End-of-file arrives at once, so the exit wait must use the deadline
        // too; otherwise this parks a request thread for the whole sleep.
        let dir = tempfile::tempdir().unwrap();
        let program = executable_script(dir.path(), "exec 1>&- 2>&-\nsleep 5");
        let started = Instant::now();
        let run = run_with_timeout(&program, b"value", Duration::from_millis(100));
        assert!(matches!(run, Run::Skipped), "an overrun has no verdict");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the deadline must bound the exit wait, took {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_descendant_that_outlives_the_program_is_bounded_by_the_cap() {
        if !sh_available() {
            return;
        }
        // The descendant inherits the shared socket and keeps writing after the
        // program exits, so only the cap ends the read.
        let dir = tempfile::tempdir().unwrap();
        let program = executable_script(
            dir.path(),
            "( i=0; while [ \"$i\" -lt 4000 ]; do printf '%0500d' 0; i=$((i+1)); done ) &\nexit 0",
        );
        let started = Instant::now();
        let run = run_with_timeout(&program, b"value", Duration::from_secs(5));
        assert!(matches!(run, Run::Skipped), "output beyond the cap has no verdict");
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the cap must end the read without waiting for the deadline"
        );
    }

    #[test]
    fn the_output_cap_is_enforced() {
        assert_eq!(
            read_capped(std::io::repeat(b'0').take(OUTPUT_CAP as u64)).map(|bytes| bytes.len()),
            Some(OUTPUT_CAP)
        );
        assert!(
            read_capped(std::io::repeat(b'0').take(OUTPUT_CAP as u64 + 1)).is_none(),
            "output beyond the cap is unusable"
        );
    }
}
