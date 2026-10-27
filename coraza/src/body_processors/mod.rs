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

//! Built-in body decoders and the custom body-processor API.

use std::{mem::size_of, path::Path, sync::Arc};

use crate::config::UploadKeepFiles;

/// Whether a custom body processor is handling request or response bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyDirection {
    /// Request-body processing, which populates POST argument collections.
    Request,
    /// Response-body processing, which populates response argument collections.
    Response,
}

/// Limits and resolved upload policy for one body-processing call.
///
/// These are values already selected by the transaction, not a reference to the
/// WAF configuration. The body itself has already been bounded by the applicable
/// request or response body limit. If `truncated` is true, `body` is only the prefix
/// retained by the engine. Recursion limits are advisory for custom processors; only
/// built-in processors enforce them.
#[derive(Debug, Clone, Copy)]
pub struct BodyProcessorOptions<'a> {
    /// The original Content-Type bytes, or an empty slice when unavailable.
    pub mime: &'a [u8],
    /// Resolved directory used by the engine for temporary uploaded files.
    pub upload_dir: &'a Path,
    /// Maximum number of uploaded files for this transaction.
    pub upload_file_limit: usize,
    /// Configured permission bits for stored uploaded files.
    pub upload_file_mode: u32,
    /// Whether temporary files are removed or kept when the transaction ends.
    pub upload_keep_files: UploadKeepFiles,
    /// Maximum arguments accepted by one argument collection.
    pub argument_limit: usize,
    /// Whether the engine discarded bytes beyond the retained body prefix.
    pub truncated: bool,
    /// Whether request or response body ingestion reported a data error.
    pub data_error: bool,
    /// Request JSON-style recursion limit.
    pub request_body_recursion_limit: usize,
    /// Response JSON-style recursion limit.
    pub response_body_recursion_limit: usize,
}

/// A processor for a body selected by a SecLang `ctl` action.
///
/// The processor is called synchronously on the transaction path with attacker-controlled
/// bytes. The engine has no timeout and does not catch panics. Implementations must not
/// panic, must bound their own work, and must honor the limits and storage policy in
/// `options`. Recursion limits are advisory for custom processors; only built-ins enforce
/// them. The factory is retained by compiled rules and runs only if the selected body is
/// actually processed.
pub trait BodyProcessor: Send + Sync {
    /// Parse `body` and append supported values to `out`.
    ///
    /// # Errors
    ///
    /// Return a processor error. Any output already appended is still merged into the
    /// transaction before the error variables are set.
    fn process(
        &self,
        body: &[u8],
        direction: BodyDirection,
        options: &BodyProcessorOptions<'_>,
        out: &mut BodyProcessorOutput,
    ) -> Result<(), String>;
}

/// Creates a body processor on the first processing call for a processor selected by a
/// compiled `ctl:requestBodyProcessor` or `ctl:responseBodyProcessor` action.
///
/// The zero-argument factory does not receive body bytes.
pub type BodyProcessorFactory = Arc<dyn Fn() -> Box<dyn BodyProcessor> + Send + Sync>;

/// Values a custom body processor can publish without direct transaction access.
///
/// Its fields are private so processors can only add supported arguments, files, XML
/// values, processor names, and errors through the methods below.
#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent limit and storage flags describe processor-output state"
)]
pub struct BodyProcessorOutput {
    /// Buffered argument values waiting for transaction insertion.
    pub(crate) arguments: Vec<(Vec<u8>, Vec<u8>)>,
    /// Buffered file values waiting for engine-managed storage.
    pub(crate) files: Vec<BodyProcessorFile>,
    /// Buffered XML values waiting for collection insertion.
    pub(crate) xml: Vec<(Vec<u8>, Vec<u8>)>,
    /// Optional reported processor name.
    pub(crate) processor: Option<String>,
    /// Optional processor error.
    pub(crate) error: Option<String>,
    /// Whether an argument exceeded the allowed collection count.
    pub(crate) argument_limit_reached: bool,
    /// Whether a file exceeded the allowed upload count.
    pub(crate) file_limit_reached: bool,
    /// Remaining argument capacity resolved by the transaction.
    argument_capacity: usize,
    /// Remaining file capacity resolved by the transaction.
    file_capacity: usize,
    /// Whether the current target has an engine-managed file storage sink.
    file_storage_available: bool,
    /// Maximum staged-output bytes, including copied data and per-entry storage.
    byte_capacity: usize,
    /// Bytes already accepted by the output methods.
    output_bytes: usize,
    /// Whether an output entry exceeded the cumulative byte budget.
    pub(crate) byte_limit_reached: bool,
}

/// Error reported when a custom processor exceeds its cumulative output budget.
const OUTPUT_BYTE_LIMIT_ERROR: &str = "custom body processor output exceeded byte limit";

/// 256 bytes preserves useful diagnostic context while bounding transaction and log storage.
pub(crate) const CUSTOM_BODY_PROCESSOR_TEXT_LIMIT: usize = 256;

/// Copy at most the configured byte limit without splitting a UTF-8 character.
pub(crate) fn truncate_custom_body_text(value: &str) -> String {
    let mut end = value.len().min(CUSTOM_BODY_PROCESSOR_TEXT_LIMIT);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.get(..end).unwrap_or_default().to_owned()
}

/// One file staged for transaction-managed temporary storage.
pub(crate) struct BodyProcessorFile {
    /// Form field name associated with the file.
    pub(crate) name: Vec<u8>,
    /// Original file name reported to `FILES`.
    pub(crate) filename: Vec<u8>,
    /// Original file Content-Type bytes.
    pub(crate) content_type: Vec<u8>,
    /// File content bytes.
    pub(crate) bytes: Vec<u8>,
}

impl BodyProcessorOutput {
    /// Build an output limited to the transaction's remaining capacity.
    pub(crate) fn new(
        argument_capacity: usize,
        file_capacity: usize,
        byte_capacity: usize,
        file_storage_available: bool,
    ) -> Self {
        Self {
            argument_capacity,
            file_capacity,
            file_storage_available,
            byte_capacity,
            ..Self::default()
        }
    }

    /// Reserve output bytes before copying any caller-provided slices.
    fn reserve_bytes(&mut self, parts: &[&[u8]], entry_storage: usize) -> bool {
        if self.byte_limit_reached {
            return false;
        }
        let additional = parts
            .iter()
            .try_fold(entry_storage, |total, part| total.checked_add(part.len()));
        let total = additional.and_then(|additional| self.output_bytes.checked_add(additional));
        let Some(total) = total.filter(|total| *total <= self.byte_capacity) else {
            self.byte_limit_reached = true;
            self.error = Some(OUTPUT_BYTE_LIMIT_ERROR.to_owned());
            return false;
        };
        self.output_bytes = total;
        true
    }

    /// Add an argument to `ARGS_POST` or `RESPONSE_ARGS`.
    ///
    /// Values beyond the resolved argument limit are dropped and set
    /// `ARGUMENTS_LIMIT_REACHED` when the output is merged.
    pub fn add_argument(&mut self, name: &[u8], value: &[u8]) {
        if self.arguments.len() >= self.argument_capacity {
            self.argument_limit_reached = true;
            return;
        }
        if !self.reserve_bytes(&[name, value], size_of::<(Vec<u8>, Vec<u8>)>()) {
            return;
        }
        self.arguments.push((name.to_vec(), value.to_vec()));
    }

    /// Add a file whose bytes the engine will write to its private temporary-file path.
    ///
    /// The processor cannot select or invent the path. Files beyond the resolved upload
    /// limit are dropped. Unlike the built-in multipart processor, custom files cannot
    /// reproduce wire part headers: this deliberately narrow API has no raw-header input,
    /// so `MULTIPART_PART_HEADERS` contains only `Content-Type: <content_type>`. Rules
    /// that depend on wire part headers, including `Content-Disposition`, must use the
    /// built-in multipart processor. WASI targets reject file output until a connector
    /// provides a memory-backed sink.
    pub fn add_file(&mut self, name: &[u8], filename: &[u8], content_type: &[u8], bytes: &[u8]) {
        if !self.file_storage_available {
            self.set_error("file-producing body processors are unavailable on WASI without a connector memory sink");
            return;
        }
        if self.files.len() >= self.file_capacity {
            self.file_limit_reached = true;
            return;
        }
        if !self.reserve_bytes(&[name, filename, content_type, bytes], size_of::<BodyProcessorFile>()) {
            return;
        }
        self.files.push(BodyProcessorFile {
            name: name.to_vec(),
            filename: filename.to_vec(),
            content_type: content_type.to_vec(),
            bytes: bytes.to_vec(),
        });
    }

    /// Add a value to the request or response XML collection under `path`.
    pub fn add_xml(&mut self, path: &[u8], value: &[u8]) {
        if !self.reserve_bytes(&[path, value], size_of::<(Vec<u8>, Vec<u8>)>()) {
            return;
        }
        self.xml.push((path.to_vec(), value.to_vec()));
    }

    /// Set the processor name reported by `REQBODY_PROCESSOR` or
    /// `RES_BODY_PROCESSOR`. This is host-reported, not authoritative: it can differ from
    /// the name selected by `ctl` and is also used in body-error message prefixes.
    pub fn set_processor(&mut self, name: &str) {
        let name = truncate_custom_body_text(name);
        self.processor = Some(truncate_custom_body_text(&name.to_uppercase()));
    }

    /// Report a processor-specific error while retaining any output already added.
    pub fn set_error(&mut self, message: &str) {
        if !self.byte_limit_reached {
            self.error = Some(truncate_custom_body_text(message));
        }
    }
}

pub(crate) mod multipart;
pub(crate) mod xml;

#[cfg(test)]
mod tests {
    use super::BodyProcessorOutput;

    #[test]
    fn file_output_is_rejected_without_a_storage_sink() {
        let mut output = BodyProcessorOutput::new(1, 1, 4, false);
        output.add_file(b"upload", b"file.txt", b"text/plain", b"bytes");

        assert!(output.files.is_empty());
        assert!(output.error.as_deref().is_some_and(|message| message.contains("WASI")));
    }

    #[test]
    fn output_byte_budget_is_cumulative_and_stops_before_copying_more() {
        let capacity = 2 * size_of::<(Vec<u8>, Vec<u8>)>() + 5;
        let mut output = BodyProcessorOutput::new(4, 4, capacity, true);
        output.add_argument(b"a", b"12");
        output.add_xml(b"/", b"3");
        output.add_file(b"f", b"n", b"t", b"x");

        assert_eq!(output.output_bytes, capacity);
        assert!(output.output_bytes <= output.byte_capacity);
        assert_eq!(output.arguments.len(), 1);
        assert_eq!(output.xml.len(), 1);
        assert!(output.files.is_empty());
        assert!(output.byte_limit_reached);
        assert_eq!(
            output.error.as_deref(),
            Some("custom body processor output exceeded byte limit")
        );

        output.add_argument(b"later", b"ignored");
        assert_eq!(output.output_bytes, capacity);
        assert_eq!(output.arguments.len(), 1);
    }

    #[test]
    fn empty_entries_still_consume_the_output_byte_budget() {
        let capacity = size_of::<(Vec<u8>, Vec<u8>)>();
        let mut output = BodyProcessorOutput::new(1, 1, capacity, true);
        for _ in 0..10_000 {
            output.add_xml(b"", b"");
        }

        assert_eq!(output.xml.len(), 1);
        assert!(output.byte_limit_reached);
        assert_eq!(output.output_bytes, capacity);
    }
}
