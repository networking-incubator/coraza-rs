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

//! Level-filtered debug logging for the Coraza engine.

use std::{
    fmt::Write as _,
    fs::{File, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, PoisonError},
};

use crate::audit_log::Failure;

/// Debug log levels, matching Go Coraza's numeric levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DebugLevel {
    /// Errors only.
    Error = 1,
    /// Warnings and errors.
    Warn = 2,
    /// Informational messages and above.
    Info = 3,
    /// Debug messages and above (configuration values 4 through 8).
    Debug = 4,
    /// Trace messages, including inspected values.
    Trace = 9,
}

impl DebugLevel {
    /// Numeric level used by `SecDebugLogLevel`.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Uppercase label used by the built-in writer.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }
}

/// A small, allocation-free field for a debug event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugField<'a> {
    /// Compiled rule identifier.
    RuleId(i32),
    /// Processing phase number.
    Phase(u8),
    /// Selected variable name.
    Variable(&'a str),
    /// Other text, including values at Trace level only.
    Text(&'a str),
}

/// One static message and its borrowed typed fields.
#[derive(Debug, Clone, Copy)]
pub struct DebugEvent<'a> {
    /// Static event message.
    pub message: &'static str,
    /// Borrowed fields; callers build them only after `enabled` succeeds.
    pub fields: &'a [DebugField<'a>],
}

/// A thread-safe debug log sink.
pub trait DebugLogger: Send + Sync {
    /// Whether an event at `level` would be accepted.
    fn enabled(&self, level: DebugLevel) -> bool;

    /// Write an event previously accepted by [`DebugLogger::enabled`].
    fn log(&self, level: DebugLevel, event: &DebugEvent<'_>);
}

/// A logger that discards all events.
#[derive(Debug, Clone, Copy, Default)]
pub struct Noop;

impl DebugLogger for Noop {
    fn enabled(&self, _level: DebugLevel) -> bool {
        false
    }

    fn log(&self, _level: DebugLevel, _event: &DebugEvent<'_>) {}
}

/// Share the allocation-free no-op logger across default WAFs and transactions.
pub(crate) fn noop_logger() -> Arc<dyn DebugLogger> {
    static NOOP: OnceLock<Arc<dyn DebugLogger>> = OnceLock::new();
    Arc::clone(NOOP.get_or_init(|| Arc::new(Noop)))
}

/// A lazily opened append-only debug log file or standard stream path.
///
/// The file is opened by [`Writer::activate`] or the first enabled event, not when the
/// writer is constructed. `/dev/stdout` and `/dev/stderr` are accepted as paths.
pub struct Writer {
    /// Destination path or standard stream path.
    path: PathBuf,
    /// Open stream and cached failure, synchronized across transactions.
    state: Mutex<WriterState>,
}

/// State shared by concurrent writes to one sink.
#[derive(Debug, Default)]
struct WriterState {
    /// Open destination, initialized on activation or the first event.
    output: Option<Output>,
    /// Most recent open or write error.
    failure: Option<Failure>,
}

/// An open log destination.
#[derive(Debug)]
enum Output {
    /// Append-only file sink.
    File(File),
    /// Process standard output.
    Stdout,
    /// Process standard error.
    Stderr,
}

impl Output {
    /// Write one complete event line to this destination.
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::File(file) => file.write_all(bytes),
            Self::Stdout => io::stdout().write_all(bytes),
            Self::Stderr => io::stderr().write_all(bytes),
        }
    }
}

impl Writer {
    /// Create a writer for `path`; opening is deferred until activation or first use.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            state: Mutex::new(WriterState::default()),
        }
    }

    /// Create a writer for `/dev/stdout`.
    pub fn stdout() -> Self {
        Self::new("/dev/stdout")
    }

    /// Create a writer for `/dev/stderr`.
    pub fn stderr() -> Self {
        Self::new("/dev/stderr")
    }

    /// Open the configured sink now.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when the path cannot be opened.
    pub fn activate(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.output.is_some() {
            return state.failure.as_ref().map_or(Ok(()), |failure| Err(failure.to_error()));
        }
        state.failure = None;
        match Self::open(&self.path) {
            Ok(output) => {
                state.output = Some(output);
                Ok(())
            },
            Err(error) => {
                state.failure = Some(Failure::new(&error));
                drop(state);
                Err(error)
            },
        }
    }

    /// The most recent open or write failure, if any.
    pub fn activation_error(&self) -> Option<(io::ErrorKind, String)> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.failure.as_ref().map(|failure| {
            let error = failure.to_error();
            (error.kind(), error.to_string())
        })
    }

    /// The path used by this writer.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Resolve standard stream paths or open an append-only file.
    fn open(path: &Path) -> io::Result<Output> {
        match path {
            path if path == Path::new("/dev/stdout") => Ok(Output::Stdout),
            path if path == Path::new("/dev/stderr") => Ok(Output::Stderr),
            path => OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map(Output::File),
        }
    }

    /// Open the sink lazily and retain any write failure without panicking.
    fn log_line(&self, line: &[u8]) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.failure.is_some() {
            return;
        }
        if state.output.is_none() {
            match Self::open(&self.path) {
                Ok(output) => state.output = Some(output),
                Err(error) => {
                    state.failure = Some(Failure::new(&error));
                    return;
                },
            }
        }
        let Some(output) = state.output.as_mut() else {
            return;
        };
        if let Err(error) = output.write_all(line) {
            state.failure = Some(Failure::new(&error));
        }
    }
}

impl std::fmt::Debug for Writer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Writer")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl DebugLogger for Writer {
    fn enabled(&self, _level: DebugLevel) -> bool {
        true
    }

    fn log(&self, level: DebugLevel, event: &DebugEvent<'_>) {
        let mut line = String::new();
        if write!(line, "[{}] {}", level.as_str(), event.message).is_err() {
            return;
        }
        for field in event.fields {
            match field {
                DebugField::RuleId(id) => {
                    if write!(line, " rule_id={id}").is_err() {
                        return;
                    }
                },
                DebugField::Phase(phase) => {
                    if write!(line, " phase={phase}").is_err() {
                        return;
                    }
                },
                DebugField::Variable(variable) => {
                    if write!(line, " variable={variable:?}").is_err() {
                        return;
                    }
                },
                DebugField::Text(text) => {
                    if write!(line, " text={text:?}").is_err() {
                        return;
                    }
                },
            }
        }
        line.push('\n');
        self.log_line(line.as_bytes());
    }
}

/// A level threshold that can wrap any debug logger.
pub struct LevelFilter {
    /// Sink wrapped by this threshold.
    logger: Arc<dyn DebugLogger>,
    /// Highest accepted `SecDebugLogLevel` value.
    max_level: u8,
}

impl LevelFilter {
    /// Wrap `logger`, accepting numeric levels through `max_level` (0 through 9).
    pub fn new(logger: Arc<dyn DebugLogger>, max_level: u8) -> Self {
        Self {
            logger,
            max_level: max_level.min(9),
        }
    }
}

impl std::fmt::Debug for LevelFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LevelFilter")
            .field("max_level", &self.max_level)
            .finish_non_exhaustive()
    }
}

impl DebugLogger for LevelFilter {
    fn enabled(&self, level: DebugLevel) -> bool {
        self.max_level >= level.as_u8() && self.logger.enabled(level)
    }

    fn log(&self, level: DebugLevel, event: &DebugEvent<'_>) {
        if self.enabled(level) {
            self.logger.log(level, event);
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "logger tests use fixed local paths")]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::{DebugEvent, DebugField, DebugLevel, DebugLogger, LevelFilter, Noop, Writer};

    struct Capture(Arc<AtomicUsize>);

    impl DebugLogger for Capture {
        fn enabled(&self, _level: DebugLevel) -> bool {
            true
        }

        fn log(&self, _level: DebugLevel, _event: &DebugEvent<'_>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn noop_disables_events_and_level_filter_maps_numeric_levels() {
        let noop = Noop;
        assert!(!noop.enabled(DebugLevel::Error));

        let logged = Arc::new(AtomicUsize::new(0));
        let capture: Arc<dyn DebugLogger> = Arc::new(Capture(Arc::clone(&logged)));
        for (maximum, level, expected) in [
            (0, DebugLevel::Error, false),
            (1, DebugLevel::Error, true),
            (1, DebugLevel::Warn, false),
            (2, DebugLevel::Warn, true),
            (2, DebugLevel::Info, false),
            (3, DebugLevel::Info, true),
            (4, DebugLevel::Debug, true),
            (5, DebugLevel::Debug, true),
            (6, DebugLevel::Debug, true),
            (7, DebugLevel::Debug, true),
            (8, DebugLevel::Debug, true),
            (8, DebugLevel::Trace, false),
            (9, DebugLevel::Trace, true),
        ] {
            assert_eq!(LevelFilter::new(Arc::clone(&capture), maximum).enabled(level), expected);
        }
        let filter = LevelFilter::new(Arc::clone(&capture), 5);
        let event = DebugEvent {
            message: "accepted",
            fields: &[],
        };
        filter.log(DebugLevel::Trace, &event);
        filter.log(DebugLevel::Debug, &event);
        assert_eq!(logged.load(Ordering::Relaxed), 1);
    }

    #[cfg(unix)]
    #[test]
    fn writer_appends_a_typed_event_and_opens_standard_streams() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("debug.log");
        let writer = Writer::new(&path);
        assert!(!path.exists(), "constructing a writer opened its path");
        let fields = [DebugField::RuleId(42), DebugField::Phase(1)];
        writer.log(
            DebugLevel::Info,
            &DebugEvent {
                message: "test event",
                fields: &fields,
            },
        );
        let contents = std::fs::read_to_string(path).unwrap();
        assert!(contents.contains("[INFO] test event rule_id=42 phase=1"));

        let stderr = Writer::stderr();
        stderr.activate().unwrap();
        Writer::stdout().activate().unwrap();
    }

    #[test]
    fn writer_reports_open_failures_without_panicking() {
        let directory = tempfile::tempdir().unwrap();
        let writer = Writer::new(directory.path().join("missing/debug.log"));
        let event = DebugEvent {
            message: "cannot open",
            fields: &[],
        };
        assert!(writer.enabled(DebugLevel::Error));
        writer.log(DebugLevel::Error, &event);
        assert_eq!(
            writer.activation_error().map(|(kind, _)| kind),
            Some(std::io::ErrorKind::NotFound)
        );
    }
}
