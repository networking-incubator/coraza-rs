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

//! Bounded subprocess support for optional external parity oracles.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        drop(fs::remove_file(&self.0));
    }
}

fn create_temp_file(label: &str) -> io::Result<(TempFile, File)> {
    for _ in 0..128 {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("libinjection-oracle-{}-{id}-{label}", std::process::id()));
        match OpenOptions::new().read(true).write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((TempFile(path), file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique oracle temporary file",
    ))
}

/// Run an oracle with file-backed streams and a deadline.
///
/// File-backed standard streams prevent pipe-buffer deadlocks while the test
/// waits for the child. On Unix the child gets its own process group, so a
/// timeout also terminates compiler/oracle descendants.
pub(crate) fn run_with_timeout(command: &mut Command, request: &[u8], timeout: Duration) -> io::Result<Output> {
    let (request_path, mut request_file) = create_temp_file("request")?;
    request_file.write_all(request)?;
    request_file.flush()?;
    drop(request_file);

    let (stdout_path, stdout_file) = create_temp_file("stdout")?;
    let (stderr_path, stderr_file) = create_temp_file("stderr")?;
    command
        .stdin(Stdio::from(File::open(&request_path.0)?))
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }

    let mut child = command.spawn()?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            terminate_process_group(&mut child);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("oracle exceeded its {:.1}s deadline", timeout.as_secs_f64()),
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };

    Ok(Output {
        status,
        stdout: fs::read(&stdout_path.0)?,
        stderr: fs::read(&stderr_path.0)?,
    })
}

fn terminate_process_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let group_id = format!("-{}", child.id());
        drop(
            Command::new("/bin/kill")
                .args(["-KILL", "--", group_id.as_str()])
                .status(),
        );
    }
    drop(child.kill());
    drop(child.wait());
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "the timeout regression expects the child to exceed its deadline"
    )]

    use std::{process::Command, time::Duration};

    use super::run_with_timeout;

    #[cfg(unix)]
    #[test]
    fn oracle_timeout_terminates_process_group() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 5"]);
        let error = run_with_timeout(&mut command, b"", Duration::from_millis(30))
            .expect_err("sleeping oracle must hit its deadline");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }
}
