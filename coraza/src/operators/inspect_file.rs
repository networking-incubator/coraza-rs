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
//! Divergences from Go:
//!
//! - A missed deadline, a spawn failure, a failed wait, or a read error reports [`OperatorOutcome::NotMatched`], as
//!   Go's `Evaluate` returns `false` for every error. A negated `!@inspectFile` therefore matches on failure, exactly
//!   as in Go.
//! - Output beyond [`OUTPUT_CAP`] keeps the collected prefix and applies Go's first-byte verdict to it: the reader
//!   stops and the run is abandoned, so a program that writes a huge output cannot pin the caller. An over-cap run with
//!   no output at all is a non-match.
//! - A non-zero exit status stays a non-match, as in Go.
//! - The number of runs in flight in a process is capped at [`MAX_IN_FLIGHT`]; a run above that cap reports
//!   [`OperatorOutcome::NotMatched`] rather than queueing.
//! - On Unix both streams share one socket, so the combined output keeps the program's write order like Go's
//!   `CombinedOutput`. On other platforms the streams are separate pipes and stdout is read before stderr.
//! - On Unix the value is passed as its raw bytes; elsewhere it is converted lossily, because those platforms have no
//!   byte path form.
//! - An empty or whitespace-only program is rejected when the rule loads, where Go accepts it and fails on every value.
//!
//! Resource bounds: the whole spawn-to-exit window is bounded by
//! [`COMMAND_TIMEOUT`], the retained output is capped at [`OUTPUT_CAP`], at most
//! [`MAX_IN_FLIGHT`] runs execute at once in a process, and a single reader
//! thread per stream is used. When a run is abandoned the readers are stopped
//! before the call returns, so a descendant that survives the kill cannot pin a
//! thread and a descriptor: on Unix the read end is shut down, which also makes a
//! descendant that keeps writing fail with `EPIPE`, the reader polls a stop flag
//! every [`READ_POLL`], and the call joins it. Elsewhere a read on a pipe
//! cannot be interrupted, so a reader that a surviving descendant keeps blocked is
//! detached instead: it holds one descriptor and never more than the cap, and it
//! ends when the last write end closes. A killed program is reaped within a short
//! grace; one stuck in uninterruptible sleep stays a zombie until the process exits
//! rather than parking the caller past its deadline.

use std::{
    borrow::Cow,
    ffi::OsStr,
    io::{self, Read},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use crate::{
    operators::{Operator, OperatorOutcome, Outputs},
    transaction::Transaction,
};

/// Go's `10*time.Second` deadline for the command in `inspect_file.go`.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest combined output retained from one run.
///
/// A program that writes more is killed and reports no verdict, and its writer
/// then fails on the closed pipe instead of growing this process' memory.
pub const OUTPUT_CAP: usize = 1024 * 1024;

/// Stack size for the output reader threads, which only run a read loop.
const READER_STACK: usize = 64 * 1024;

/// How long a reader blocks in `read` before it checks the stop flag.
///
/// This bounds how long an abandoned reader outlives the call on Unix.
pub const READ_POLL: Duration = Duration::from_millis(50);

/// Executions allowed to run at once in one process.
///
/// A run holds its slot from spawn to reap, so this bounds the programs, reader
/// threads and descriptors a hostile rule set can pin.
pub const MAX_IN_FLIGHT: usize = 64;

/// Runs currently executing, process-wide.
static LIMITER: Limiter = Limiter {
    in_flight: AtomicUsize::new(0),
};

/// Counts runs in flight against [`MAX_IN_FLIGHT`].
struct Limiter {
    /// Slots currently held.
    in_flight: AtomicUsize,
}

/// One reserved run slot, released when dropped.
struct InFlight<'a> {
    /// The limiter the slot was taken from.
    limiter: &'a Limiter,
}

impl Limiter {
    /// Reserve a slot, or report `None` when the cap is already reached.
    fn acquire(&self) -> Option<InFlight<'_>> {
        if self.in_flight.fetch_add(1, Ordering::AcqRel) >= MAX_IN_FLIGHT {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(InFlight { limiter: self })
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.limiter.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// How long a killed program gets to die before the reap gives up.
///
/// A child in uninterruptible sleep does not die promptly; the caller must not
/// park past its own deadline for it.
const REAP_GRACE: Duration = Duration::from_millis(100);

/// Longest pause between two exit checks.
const POLL_MAX: Duration = Duration::from_millis(100);

/// Runs an external program for every inspected value.
#[derive(Debug, Clone)]
pub struct InspectFile {
    /// Program or script path, as written in the operator argument.
    path: String,
}

impl InspectFile {
    /// Create the operator for the program or script at `path`.
    ///
    /// `path` is used verbatim, including any whitespace around it.
    ///
    /// # Errors
    ///
    /// Returns an error for a path that is empty or only whitespace. Go accepts
    /// such a rule and fails on every value, so it is rejected when the rule
    /// compiles instead.
    pub fn new(path: &str) -> Result<Self, String> {
        if path.trim().is_empty() {
            return Err("missing inspectFile program".to_owned());
        }
        Ok(Self { path: path.to_owned() })
    }
}

impl Operator for InspectFile {
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        self.evaluate_outcome(tx, input, out) == OperatorOutcome::Matched
    }

    fn evaluate_outcome(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> OperatorOutcome {
        verdict(run(&self.path, input))
    }
}

/// Creates a new `inspectFile` operator.
///
/// # Errors
///
/// Returns an error for an empty program; see [`InspectFile::new`].
pub fn inspect_file(path: &str) -> Result<InspectFile, String> {
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
    /// The output passed [`OUTPUT_CAP`]; the bytes are the collected prefix.
    OverCap(Vec<u8>),
    /// The program could not be run at all.
    Failed,
}

/// The output one reader collected before end-of-file or the cap.
#[derive(Debug)]
struct ReadOutput {
    /// The bytes read before the end or the cap.
    bytes: Vec<u8>,
    /// Whether reading stopped because the output passed [`OUTPUT_CAP`].
    over_cap: bool,
}

/// Map a run onto Go's first-byte verdict.
///
/// Go returns `false` on every operational error, so a failed run is a plain
/// non-match: a negated rule then matches exactly as it does in Go. An over-cap
/// run still has a first byte whenever it has output, and that byte is the whole
/// verdict, so the collected prefix decides it.
fn verdict(run: Run) -> OperatorOutcome {
    match run {
        Run::Completed(output) | Run::OverCap(output) if first_byte_is_verdict(&output) => OperatorOutcome::Matched,
        Run::Completed(_) | Run::OverCap(_) | Run::Failed => OperatorOutcome::NotMatched,
    }
}

/// One captured output stream: the end the reader uses and a way to shut it
/// down.
struct Captured {
    /// `true` marks the stderr stream.
    is_stderr: bool,
    /// The read end handed to the reader thread.
    pipe: Box<dyn Read + Send>,
    /// The read end kept so an abandoned run can interrupt the reader.
    shutdown: Shutdown,
}

/// Shuts down the read side of a captured stream.
struct Shutdown {
    /// A second reference to the read end, held by the caller.
    #[cfg(unix)]
    stream: std::os::unix::net::UnixStream,
}

/// Wake a reader blocked in `read`, so it observes the stop flag.
#[cfg(unix)]
fn shutdown_read(shutdown: &Shutdown) {
    drop(shutdown.stream.shutdown(std::net::Shutdown::Read));
}

/// A pipe's read cannot be interrupted, so there is nothing to wake: the reader
/// ends when the last write end closes.
#[cfg(not(unix))]
fn shutdown_read(_shutdown: &Shutdown) {}

/// Stops the output readers of an abandoned run.
#[derive(Debug, Default)]
struct Stop(AtomicBool);

impl Stop {
    /// Ask every reader to return.
    fn stop(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Whether a reader was asked to return.
    fn is_stopped(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Run `path` with the value as its argument, bounded by [`COMMAND_TIMEOUT`].
fn run(path: &str, input: &[u8]) -> Run {
    run_with_timeout(path, input, COMMAND_TIMEOUT)
}

/// Run `path` with the value as its argument, bounded by `timeout`.
fn run_with_timeout(path: &str, input: &[u8], timeout: Duration) -> Run {
    let Some(_slot) = LIMITER.acquire() else {
        return Run::Failed;
    };
    let deadline = Instant::now() + timeout;
    let Some((mut child, readers)) = spawn_captured(path, &value_argument(input)) else {
        return Run::Failed;
    };

    let expected = readers.len();
    let stop = Arc::new(Stop::default());
    let mut shutdowns = Vec::with_capacity(expected);
    let mut workers = Vec::with_capacity(expected);
    let (sender, receiver) = mpsc::channel();
    for captured in readers {
        let Captured {
            is_stderr,
            pipe,
            shutdown,
        } = captured;
        shutdowns.push(shutdown);
        let Some(worker) = spawn_reader(pipe, is_stderr, Arc::clone(&stop), sender.clone()) else {
            abandon(&mut child, &stop, &shutdowns, &mut workers);
            return Run::Failed;
        };
        workers.push(worker);
    }
    drop(sender);

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    for _ in 0..expected {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Ok((is_stderr, output)) = receiver.recv_timeout(remaining) else {
            abandon(&mut child, &stop, &shutdowns, &mut workers);
            return Run::Failed;
        };
        let Some(ReadOutput { bytes, over_cap }) = output else {
            // A read error or a stop leaves no usable verdict.
            abandon(&mut child, &stop, &shutdowns, &mut workers);
            return Run::Failed;
        };
        if over_cap {
            // Go's verdict is only the first output byte, so the collected
            // prefix decides it without waiting for the rest. `abandon` shuts
            // the read end down, so a descendant still writing gets `EPIPE`.
            abandon(&mut child, &stop, &shutdowns, &mut workers);
            return Run::OverCap(bytes);
        }
        if is_stderr {
            stderr = bytes;
        } else {
            stdout = bytes;
        }
    }

    // End-of-file only means every write end closed: the program can still be
    // running, so the exit status needs the same deadline.
    let Some(status) = wait_until(&mut child, deadline) else {
        abandon(&mut child, &stop, &shutdowns, &mut workers);
        return Run::Failed;
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
fn spawn_captured(path: &str, value: &OsStr) -> Option<(Child, Vec<Captured>)> {
    use std::os::{fd::OwnedFd, unix::net::UnixStream};

    let (read_end, write_end) = UnixStream::pair().ok()?;
    // A blocked read returns within `READ_POLL`, which is how the reader sees
    // the stop flag when a descendant holds the other end open. Shutting the
    // read end down also wakes it, so a refused timeout is not fatal.
    drop(read_end.set_read_timeout(Some(READ_POLL)));
    let shutdown = Shutdown {
        stream: read_end.try_clone().ok()?,
    };
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
    Some((
        child,
        vec![Captured {
            is_stderr: false,
            pipe: reader,
            shutdown,
        }],
    ))
}

/// Spawn the program with its output captured, returning the readers to wait on.
///
/// Without a shared socket the streams stay separate pipes; the caller reads
/// stdout before stderr, which differs from Go only when both carry output.
/// The `Command` is scoped to the spawn for the reason given on the Unix form.
#[cfg(not(unix))]
fn spawn_captured(path: &str, value: &OsStr) -> Option<(Child, Vec<Captured>)> {
    let mut child = {
        let mut command = Command::new(path);
        command
            .arg(value)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.spawn().ok()?
    };
    let mut readers: Vec<Captured> = Vec::with_capacity(2);
    if let Some(pipe) = child.stdout.take() {
        readers.push(Captured {
            is_stderr: false,
            pipe: Box::new(pipe),
            shutdown: Shutdown {},
        });
    }
    if let Some(pipe) = child.stderr.take() {
        readers.push(Captured {
            is_stderr: true,
            pipe: Box::new(pipe),
            shutdown: Shutdown {},
        });
    }
    Some((child, readers))
}

/// Read `pipe` on a worker thread, reporting `None` when the output is unusable
/// or stopped.
///
/// A spawn failure is reported to the caller instead of panicking.
fn spawn_reader(
    pipe: Box<dyn Read + Send>,
    is_stderr: bool,
    stop: Arc<Stop>,
    sender: mpsc::Sender<(bool, Option<ReadOutput>)>,
) -> Option<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("coraza-inspect-file".to_owned())
        .stack_size(READER_STACK)
        .spawn(move || {
            // A deadline drops the receiver, and the output is unusable then.
            drop(sender.send((is_stderr, read_capped(pipe, &stop))));
        })
        .ok()
}

/// Read `pipe` to its end or up to [`OUTPUT_CAP`].
///
/// `None` reports a read error or a stop. The cap keeps the collected prefix and
/// sets [`ReadOutput::over_cap`], so the caller can apply Go's first-byte verdict
/// even when the output is huge.
fn read_capped(mut pipe: impl Read, stop: &Stop) -> Option<ReadOutput> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        if stop.is_stopped() {
            return None;
        }
        match pipe.read(&mut buffer) {
            Ok(0) => {
                return Some(ReadOutput { bytes, over_cap: false });
            },
            Ok(read) => {
                let remaining = OUTPUT_CAP.saturating_sub(bytes.len());
                if read > remaining {
                    if let Some(chunk) = buffer.get(..remaining) {
                        bytes.extend_from_slice(chunk);
                    }
                    return Some(ReadOutput { bytes, over_cap: true });
                }
                let chunk = buffer.get(..read)?;
                bytes.extend_from_slice(chunk);
            },
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
            // The read timeout that lets a blocked reader notice the stop flag.
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {},
            Err(_) => return None,
        }
    }
}

/// Stop an abandoned run's readers, kill the program, and reap what exits.
///
/// The readers can be joined on Unix because shutting the read end down wakes
/// them; elsewhere a blocked read cannot be interrupted, so the threads are
/// detached and end when the last write end closes.
fn abandon(child: &mut Child, stop: &Stop, shutdowns: &[Shutdown], workers: &mut Vec<JoinHandle<()>>) {
    stop.stop();
    for shutdown in shutdowns {
        shutdown_read(shutdown);
    }
    kill_and_reap(child);
    for worker in workers.drain(..) {
        // The read end is down, so the reader is at most one poll from done and
        // the join cannot outlive the call.
        #[cfg(unix)]
        drop(worker.join());
        #[cfg(not(unix))]
        drop(worker);
    }
}

/// Wait for the program to exit, without passing `deadline`.
///
/// Exit is polled with a short first pause that backs off to [`POLL_MAX`], so a
/// fast program costs one `try_wait` and the pause never overruns the deadline.
fn wait_until(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    let mut pause = Duration::from_micros(200);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {},
            Err(_) => return None,
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        std::thread::sleep(pause.min(remaining));
        pause = (pause * 2).min(POLL_MAX);
    }
}

/// Kill a program that overran its deadline and reap it within [`REAP_GRACE`].
///
/// A child in uninterruptible sleep does not die promptly. Rather than park the
/// caller past its deadline, the reap gives up after the grace and leaves the
/// zombie to be reaped at process exit.
fn kill_and_reap(child: &mut Child) {
    drop(child.kill());
    let _ = wait_until(child, Instant::now() + REAP_GRACE);
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "inspectFile tests use fixed scripts they create")]
mod tests {
    use std::io::Read as _;
    #[cfg(unix)]
    use std::{
        path::Path,
        time::{Duration, Instant},
    };

    #[cfg(unix)]
    use super::run_with_timeout;
    use super::{InspectFile, OUTPUT_CAP, Run, read_capped, verdict};
    use crate::{
        operators::{Operator as _, OperatorEnum, OperatorOutcome, Outputs},
        transaction::Transaction,
    };

    /// Report a test that cannot run because a host program is missing.
    ///
    /// A silent early return would read as a pass, so the reason is printed.
    #[cfg(unix)]
    #[expect(clippy::print_stderr, reason = "a skipped test must say why it did not run")]
    fn skip(program: &str) {
        eprintln!("skipping: {program} is not available on this host");
    }

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
        let operator = InspectFile::new(program).unwrap();
        operator.evaluate(&Transaction::new("inspect-file"), input, &mut Outputs::default())
    }

    fn outcome(program: &str, input: &[u8]) -> OperatorOutcome {
        let operator = InspectFile::new(program).unwrap();
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
            Run::OverCap(_) | Run::Failed => None,
        }
    }

    #[test]
    fn command_not_found_is_no_match() {
        assert!(!evaluates("/nonexistent/coraza-inspect-file-test", b"value"));
    }

    #[test]
    fn a_spawn_failure_is_no_match() {
        assert_eq!(
            outcome("/nonexistent/coraza-inspect-file-test", b"value"),
            OperatorOutcome::NotMatched
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_value_that_cannot_be_an_argument_is_no_match() {
        // A NUL byte makes exec fail, which must not panic.
        assert_eq!(outcome("/bin/echo", b"value\0"), OperatorOutcome::NotMatched);
    }

    #[test]
    fn a_negated_rule_matches_when_the_program_cannot_run() {
        use crate::seclang::Parser;

        // Go's `Evaluate` returns false on a spawn failure and the rule negates
        // that result, so `!@inspectFile` matches. Observed against Coraza
        // v3.8.1 with the same missing program.
        let mut parser = Parser::new();
        parser
            .from_string(
                "SecRule ARGS:q \"!@inspectFile /nonexistent/coraza-inspect-file-test\" \"id:961,phase:1,pass\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("inspect-file-negated");
        tx.add_get_argument("q", b"value");

        assert!(tx.process_request_headers().is_none(), "pass does not interrupt");
        assert_eq!(
            tx.matched_rules().len(),
            1,
            "the negated rule must match on the failed run"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_value_is_passed_as_the_argument() {
        if !shell_available() {
            return skip("/bin/sh or /bin/echo");
        }
        assert!(!evaluates("/bin/echo", b"1 clamscan: OK"));
        assert!(evaluates("/bin/echo", b"0 clamscan: FOUND"));
    }

    #[cfg(unix)]
    #[test]
    fn the_value_is_one_argument_and_is_never_shell_expanded() {
        if !sh_available() {
            return skip("/bin/sh");
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
            return skip("/bin/sh");
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
            return skip("/bin/sh or /bin/echo");
        }
        assert!(!evaluates_script("printf '1 clamscan: OK'"));
    }

    #[cfg(unix)]
    #[test]
    fn any_other_first_output_byte_is_match() {
        if !shell_available() {
            return skip("/bin/sh or /bin/echo");
        }
        assert!(evaluates_script("printf '0 clamscan: FOUND'"));
        assert!(evaluates_script("printf 'x'"));
    }

    #[cfg(unix)]
    #[test]
    fn empty_output_is_no_match() {
        if !shell_available() {
            return skip("/bin/sh or /bin/echo");
        }
        assert!(!evaluates_script("exit 0"));
    }

    #[cfg(unix)]
    #[test]
    fn stderr_is_part_of_the_combined_output() {
        if !shell_available() {
            return skip("/bin/sh or /bin/echo");
        }
        assert!(evaluates_script("printf '0' >&2"));
    }

    #[cfg(unix)]
    #[test]
    fn both_streams_keep_the_write_order() {
        if !sh_available() {
            return skip("/bin/sh");
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
            return skip("/bin/sh or /bin/echo");
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
            return skip("/bin/sh");
        }
        if !shell_available() {
            return skip("/bin/sh or /bin/echo");
        }
        let dir = tempfile::tempdir().unwrap();
        let path = script(dir.path(), "exec sleep 5");
        assert_eq!(
            verdict(run_with_timeout("/bin/sh", path.as_bytes(), Duration::from_millis(50))),
            OperatorOutcome::NotMatched,
            "an overrun is a plain miss, as Go returns false on its deadline"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_clean_run_reports_a_verdict() {
        if !sh_available() {
            return skip("/bin/sh");
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
            return skip("/bin/sh");
        }
        // End-of-file arrives at once, so the exit wait must use the deadline
        // too; otherwise this parks a request thread for the whole sleep.
        let dir = tempfile::tempdir().unwrap();
        let program = executable_script(dir.path(), "exec 1>&- 2>&-\nsleep 5");
        let started = Instant::now();
        let run = run_with_timeout(&program, b"value", Duration::from_millis(100));
        assert_eq!(verdict(run), OperatorOutcome::NotMatched, "an overrun is a plain miss");
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
            return skip("/bin/sh");
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
        assert_eq!(
            verdict(run),
            OperatorOutcome::Matched,
            "the first output byte is 0, so the huge output still matches"
        );
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the cap must end the read without waiting for the deadline"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_descendant_that_stalls_without_writing_is_bounded() {
        if !sh_available() {
            return skip("/bin/sh");
        }
        // The descendant inherits the shared socket and neither writes nor
        // closes it, so end-of-file never arrives and only the stop flag and
        // the shut-down read end can end the read. `run_with_timeout` joins its
        // readers, so returning at all proves the reader stopped.
        let dir = tempfile::tempdir().unwrap();
        let program = executable_script(dir.path(), "( exec sleep 5 ) &\nexit 0");
        let started = Instant::now();
        assert_eq!(
            verdict(run_with_timeout(&program, b"value", Duration::from_millis(100))),
            OperatorOutcome::NotMatched,
            "a stalled descendant leaves no output, so it is a plain miss"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the deadline must bound the read, took {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_stalled_peer_stops_the_reader() {
        use std::{
            os::unix::net::UnixStream,
            sync::{Arc, mpsc},
        };

        use super::{READ_POLL, Stop};

        let (read_end, _writer) = UnixStream::pair().unwrap();
        read_end.set_read_timeout(Some(READ_POLL)).unwrap();
        let stop = Arc::new(Stop::default());
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn({
            let stop = Arc::clone(&stop);
            move || drop(sender.send(read_capped(read_end, &stop)))
        });
        // Let the reader block in `read`, then stop it as `abandon` does.
        std::thread::sleep(READ_POLL);
        stop.stop();
        assert!(
            receiver.recv_timeout(Duration::from_secs(2)).unwrap().is_none(),
            "a stopped reader keeps no output"
        );
        worker.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn abandoning_a_run_stops_and_joins_its_readers() {
        use std::{
            os::unix::net::UnixStream,
            process::Command,
            sync::{Arc, mpsc},
        };

        use super::{READ_POLL, Shutdown, Stop, abandon, spawn_reader};

        // The writer stays open and silent, so only `abandon` can end the read.
        let (read_end, _writer) = UnixStream::pair().unwrap();
        read_end.set_read_timeout(Some(READ_POLL)).unwrap();
        let shutdown = Shutdown {
            stream: read_end.try_clone().unwrap(),
        };
        let stop = Arc::new(Stop::default());
        let (sender, _receiver) = mpsc::channel();
        let pipe: Box<dyn std::io::Read + Send> = Box::new(read_end);
        let mut workers = vec![spawn_reader(pipe, false, Arc::clone(&stop), sender).unwrap()];
        let mut child = Command::new("/bin/sh").arg("-c").arg("true").spawn().unwrap();

        let started = Instant::now();
        abandon(&mut child, &stop, &[shutdown], &mut workers);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "abandon must not wait for the writer, took {:?}",
            started.elapsed()
        );
        assert!(workers.is_empty(), "abandon must join every reader");
        assert!(stop.is_stopped(), "abandon must stop the readers first");
    }

    #[test]
    fn an_empty_program_is_rejected() {
        // Go runs such a rule and fails on every value, so it is refused here.
        for argument in ["", "   ", "\t\n"] {
            assert_eq!(
                InspectFile::new(argument).unwrap_err(),
                "missing inspectFile program",
                "{argument:?} must not compile"
            );
        }
        assert_eq!(
            OperatorEnum::new("inspectFile", "").unwrap_err(),
            "missing inspectFile program"
        );
    }

    #[test]
    fn a_failed_run_is_no_match() {
        // Go's `Evaluate` returns false for every error, so a negated rule matches.
        assert_eq!(verdict(Run::Failed), OperatorOutcome::NotMatched);
    }

    #[test]
    fn the_output_cap_keeps_the_prefix() {
        let stop = super::Stop::default();
        let collected = read_capped(std::io::repeat(b'0').take(OUTPUT_CAP as u64), &stop).unwrap();
        assert_eq!(collected.bytes.len(), OUTPUT_CAP);
        assert!(!collected.over_cap, "exactly the cap is not over it");

        let collected = read_capped(std::io::repeat(b'0').take(OUTPUT_CAP as u64 + 1), &stop).unwrap();
        assert_eq!(collected.bytes.len(), OUTPUT_CAP);
        assert!(collected.over_cap, "output beyond the cap is flagged");
    }

    #[test]
    fn an_over_cap_run_still_applies_the_first_byte_verdict() {
        assert_eq!(
            verdict(Run::OverCap(b"0 and a huge tail".to_vec())),
            OperatorOutcome::Matched
        );
        assert_eq!(
            verdict(Run::OverCap(b"1 and a huge tail".to_vec())),
            OperatorOutcome::NotMatched
        );
        assert_eq!(verdict(Run::OverCap(Vec::new())), OperatorOutcome::NotMatched);
    }

    #[cfg(unix)]
    #[test]
    fn an_over_cap_output_starting_with_zero_matches() {
        if !sh_available() {
            return skip("/bin/sh");
        }
        // Go keeps the whole output and reads only its first byte, so a `0`
        // followed by more than the cap must match.
        let dir = tempfile::tempdir().unwrap();
        let program = executable_script(
            dir.path(),
            "printf '0'\ni=0\nwhile [ \"$i\" -lt 4000 ]; do printf '%0500d' 0; i=$((i+1)); done",
        );
        assert!(evaluates(&program, b"value"));
    }

    #[test]
    fn the_in_flight_cap_is_enforced_and_released() {
        use std::sync::atomic::AtomicUsize;

        use super::{Limiter, MAX_IN_FLIGHT};

        let limiter = Limiter {
            in_flight: AtomicUsize::new(0),
        };
        let slots: Vec<_> = (0..MAX_IN_FLIGHT).filter_map(|_| limiter.acquire()).collect();
        assert_eq!(slots.len(), MAX_IN_FLIGHT, "the cap grants every slot once");
        assert!(limiter.acquire().is_none(), "runs above the cap are refused");
        drop(slots);
        assert!(limiter.acquire().is_some(), "a released slot can be taken again");
    }
}
