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

//! Bounded retention of request and response body bytes.
//!
//! Bytes stay in memory up to the memory limit and spill to a private temporary file
//! above it, mirroring Go Coraza's `BodyBuffer`. The temporary file is created with
//! `tempfile` and removed when the buffer is dropped, including after a failed write.

use std::{
    borrow::Cow,
    io::{self, Read as _, Seek as _, SeekFrom, Write as _},
};
#[cfg(test)]
use std::{cell::Cell, path::Path};

/// A body-buffer operation a test can force to fail.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BufferFailure {
    /// Fail the next `accept`.
    Accept,
    /// Fail the next `contiguous`.
    Replay,
    /// Fail the next `reset`.
    Reset,
}

#[cfg(test)]
thread_local! {
    /// Failure injection for ingestion tests, scoped to the calling thread.
    static INJECTED_FAILURE: Cell<Option<BufferFailure>> = const { Cell::new(None) };
}

/// Force the next matching body-buffer operation on this thread to fail.
#[cfg(test)]
pub(super) fn inject_failure(failure: BufferFailure) {
    INJECTED_FAILURE.with(|slot| slot.set(Some(failure)));
}

/// Consume a pending failure injection for `failure`, if it matches.
#[cfg(test)]
fn take_injected_failure(failure: BufferFailure) -> bool {
    INJECTED_FAILURE.with(|slot| {
        if slot.get() != Some(failure) {
            return false;
        }
        slot.set(None);
        true
    })
}

/// Counters describing the bytes offered to a transaction and what the engine did with them.
///
/// The counters do not overlap: `supplied` counts what the connector offered, `retained`
/// counts what the body limit allowed into the buffer, and `inspected` counts what the
/// selected body processor consumed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BodyIngestionStats {
    /// Bytes the connector supplied, including bytes the body limit discarded.
    pub supplied: u64,
    /// Bytes kept in memory or in the spill file; never more than the body limit.
    pub retained: u64,
    /// Bytes handed to the selected body processor, or zero when none ran.
    pub inspected: u64,
    /// Whether supplied bytes were discarded because the body limit was reached.
    pub truncated: bool,
    /// Whether retained bytes were moved to a temporary file.
    pub spilled: bool,
}

/// A bounded body store that keeps bytes in memory or in a private temporary file.
pub(super) struct BodyBuffer {
    /// Bytes retained in memory before spilling to a file.
    memory_limit: usize,
    /// Maximum number of bytes the buffer retains.
    limit: usize,
    /// Retained bytes while they fit in memory.
    memory: Vec<u8>,
    /// Spill file used once `memory_limit` is exceeded.
    spill: Option<tempfile::NamedTempFile>,
    /// Number of retained bytes, in memory or on disk.
    length: usize,
    /// Bytes supplied by the connector, including discarded bytes.
    supplied: u64,
    /// Bytes handed to a body processor.
    inspected: u64,
    /// Whether the body limit discarded supplied bytes.
    truncated: bool,
    /// Number of replay reads performed, for tests.
    #[cfg(test)]
    replays: usize,
}

impl Default for BodyBuffer {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl BodyBuffer {
    /// Create a buffer limited to `limit` retained bytes that spills above `memory_limit`.
    ///
    /// A memory limit above the body limit has no effect, so it is capped at `limit`.
    pub(super) fn new(memory_limit: usize, limit: usize) -> Self {
        Self {
            memory_limit: memory_limit.min(limit),
            limit,
            memory: Vec::new(),
            spill: None,
            length: 0,
            supplied: 0,
            inspected: 0,
            truncated: false,
            #[cfg(test)]
            replays: 0,
        }
    }

    /// Return the number of retained bytes.
    pub(super) fn len(&self) -> usize {
        self.length
    }

    /// Return whether no bytes are retained.
    pub(super) fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Count `bytes` supplied bytes that the limit action refused to retain.
    pub(super) fn refuse(&mut self, bytes: usize) {
        self.supplied = self.supplied.saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        self.truncated = self.truncated || bytes > 0;
    }

    /// Retain `data`, truncated to the remaining body limit, and count it as supplied.
    ///
    /// Returns the number of bytes retained. A write failure discards retained bytes and
    /// removes the spill file before the error is returned.
    ///
    /// # Errors
    ///
    /// Returns an error when the body cannot be retained in memory or spilled to disk.
    pub(super) fn accept(&mut self, data: &[u8]) -> io::Result<usize> {
        #[cfg(test)]
        if take_injected_failure(BufferFailure::Accept) {
            return Err(io::Error::other("injected body buffer failure"));
        }
        self.supplied = self
            .supplied
            .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        let room = self.limit.saturating_sub(self.length);
        let retained = data.get(..data.len().min(room)).unwrap_or_default();
        if retained.len() < data.len() {
            self.truncated = true;
        }
        if let Err(error) = self.write(retained) {
            self.discard();
            return Err(error);
        }
        Ok(retained.len())
    }

    /// Append exactly `data`, spilling to a file above the memory limit.
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let target = self
            .length
            .checked_add(data.len())
            .ok_or_else(|| io::Error::other("body length overflow"))?;
        if target > self.limit {
            return Err(io::Error::other("body limit exceeded"));
        }
        if target > self.memory_limit {
            if self.spill.is_none() {
                let mut file = tempfile::Builder::new().prefix("coraza-body").tempfile()?;
                file.write_all(&self.memory)?;
                self.memory.clear();
                self.memory.shrink_to_fit();
                self.spill = Some(file);
            }
            let file = self
                .spill
                .as_mut()
                .ok_or_else(|| io::Error::other("body buffer has no spill file"))?;
            let handle = file.as_file_mut();
            handle.seek(SeekFrom::End(0))?;
            handle.write_all(data)?;
        } else {
            self.memory.extend_from_slice(data);
        }
        self.length = target;
        Ok(())
    }

    /// Drop retained bytes and the spill file, keeping the supplied and inspected counts.
    fn discard(&mut self) {
        self.memory.clear();
        self.memory.shrink_to_fit();
        self.spill = None;
        self.length = 0;
    }

    /// Drop retained bytes and remove the spill file, reporting a removal failure.
    ///
    /// Mirrors Go's `BodyBuffer.Reset`, which closes and removes its temporary file and
    /// returns that error. Like Go, the reset zeroes `length`, so `retained` falls to
    /// zero and `spilled` clears; `supplied`, `inspected` and `truncated` stay unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error when the spill file cannot be closed and removed.
    pub(super) fn reset(&mut self) -> io::Result<()> {
        #[cfg(test)]
        if take_injected_failure(BufferFailure::Reset) {
            return Err(io::Error::other("injected body buffer failure"));
        }
        self.memory.clear();
        self.memory.shrink_to_fit();
        self.length = 0;
        match self.spill.take() {
            Some(file) => file.close(),
            None => Ok(()),
        }
    }

    /// Return all retained bytes as one contiguous slice.
    ///
    /// An in-memory body is borrowed. A spilled body is read back from the temporary file
    /// into an owned copy bounded by the body limit, which is the copy body processors and
    /// audit logging consume. Repeated calls replay the same retained bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the spill file cannot be read.
    pub(super) fn contiguous(&mut self) -> io::Result<Cow<'_, [u8]>> {
        #[cfg(test)]
        {
            if take_injected_failure(BufferFailure::Replay) {
                return Err(io::Error::other("injected body buffer failure"));
            }
            self.replays = self.replays.saturating_add(1);
        }
        let Some(file) = self.spill.as_mut() else {
            return Ok(Cow::Borrowed(&self.memory));
        };
        let mut bytes = vec![0_u8; self.length];
        let handle = file.as_file_mut();
        handle.seek(SeekFrom::Start(0))?;
        handle.read_exact(&mut bytes)?;
        Ok(Cow::Owned(bytes))
    }

    /// Record how many retained bytes the body processor consumed.
    pub(super) fn set_inspected(&mut self, bytes: usize) {
        self.inspected = u64::try_from(bytes).unwrap_or(u64::MAX);
    }

    /// Return the counters for this buffer.
    pub(super) fn stats(&self) -> BodyIngestionStats {
        BodyIngestionStats {
            supplied: self.supplied,
            retained: u64::try_from(self.length).unwrap_or(u64::MAX),
            inspected: self.inspected,
            truncated: self.truncated,
            spilled: self.spill.is_some(),
        }
    }

    /// Bytes held by the in-memory body allocation.
    pub(super) fn allocated_bytes(&self) -> usize {
        self.memory.capacity()
    }

    /// Return the spill file path, if the body spilled, for cleanup tests.
    #[cfg(test)]
    pub(super) fn spill_path(&self) -> Option<&Path> {
        self.spill.as_ref().map(tempfile::NamedTempFile::path)
    }

    /// Return how many replay reads the buffer served, for tests.
    #[cfg(test)]
    pub(super) fn replay_count(&self) -> usize {
        self.replays
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "body buffer tests use fixed valid inputs")]
mod tests {
    use super::BodyBuffer;

    #[test]
    fn keeps_bytes_in_memory_up_to_and_including_the_memory_limit() {
        let mut buffer = BodyBuffer::new(4, 8);
        assert_eq!(buffer.accept(b"abcd").unwrap(), 4);
        assert_eq!(buffer.contiguous().unwrap().as_ref(), b"abcd");
        assert!(buffer.spill_path().is_none());
        assert_eq!(buffer.stats().retained, 4);
        assert!(!buffer.stats().spilled);

        assert_eq!(buffer.accept(b"e").unwrap(), 1);
        assert!(buffer.spill_path().is_some());
        assert!(buffer.stats().spilled);
    }

    #[test]
    fn spills_above_the_memory_limit_and_replays_retained_bytes() {
        let mut buffer = BodyBuffer::new(2, 16);
        assert_eq!(buffer.accept(b"abcdefgh").unwrap(), 8);
        assert!(buffer.stats().spilled);
        assert_eq!(buffer.len(), 8);
        assert_eq!(buffer.contiguous().unwrap().as_ref(), b"abcdefgh");
        assert_eq!(buffer.contiguous().unwrap().as_ref(), b"abcdefgh");
    }

    #[test]
    fn truncates_at_the_body_limit_and_counts_supplied_bytes() {
        let mut buffer = BodyBuffer::new(4, 4);
        assert_eq!(buffer.accept(b"abcdef").unwrap(), 4);
        assert_eq!(buffer.contiguous().unwrap().as_ref(), b"abcd");
        assert_eq!(
            buffer.stats(),
            super::BodyIngestionStats {
                supplied: 6,
                retained: 4,
                inspected: 0,
                truncated: true,
                spilled: false,
            }
        );
    }

    #[test]
    fn records_refused_bytes_without_retaining_them() {
        let mut buffer = BodyBuffer::new(4, 4);
        buffer.refuse(6);
        assert_eq!(
            buffer.stats(),
            super::BodyIngestionStats {
                supplied: 6,
                retained: 0,
                inspected: 0,
                truncated: true,
                spilled: false,
            }
        );
        assert!(buffer.contiguous().unwrap().is_empty());
    }

    #[test]
    fn zero_limit_retains_nothing() {
        let mut buffer = BodyBuffer::new(0, 0);
        assert_eq!(buffer.accept(b"abc").unwrap(), 0);
        assert_eq!(buffer.stats().supplied, 3);
        assert_eq!(buffer.stats().retained, 0);
        assert!(buffer.stats().truncated);
        assert_eq!(buffer.accept(b"").unwrap(), 0);
    }

    #[test]
    fn temporary_file_is_removed_when_the_buffer_is_dropped() {
        let path = {
            let mut buffer = BodyBuffer::new(2, 8);
            buffer.accept(b"abcd").unwrap();
            let path = buffer.spill_path().unwrap().to_owned();
            assert!(path.exists(), "spill file {path:?} should exist");
            path
        };
        assert!(!path.exists(), "spill file {path:?} should be removed on drop");
    }
}
