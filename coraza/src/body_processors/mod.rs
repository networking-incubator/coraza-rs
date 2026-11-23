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

use std::{
    mem::size_of,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    collection::{
        FIRST_INSERT_OVERHEAD_BYTES, INSERT_OVERHEAD_BYTES, KEY_COPIES_PER_INSERT, KEY_RETAINED_BYTES_PER_BYTE,
    },
    config::UploadKeepFiles,
};

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
    /// Maximum staged content bytes: argument and XML names and values with their per-entry storage, and
    /// file content. It is the body limit, so content that fits the limit is never refused for its metadata.
    byte_capacity: usize,
    /// Content bytes already accepted by the output methods.
    output_bytes: usize,
    /// Maximum bytes for file metadata, which has its own allowance: see [`metadata_capacity`].
    metadata_capacity: usize,
    /// File metadata bytes already accepted.
    metadata_bytes: usize,
    /// Bytes the path of one temporary file occupies in `FILES_TMPNAMES` and in the transaction's own list.
    upload_path_bytes: usize,
    /// Collections each staged argument is copied into when published: `ARGS_POST` and `ARGS` for a request,
    /// `RESPONSE_ARGS` for a response.
    argument_copies: usize,
    /// Whether an output entry exceeded a cumulative budget.
    pub(crate) byte_limit_reached: bool,
    /// The error for the budget that was exceeded.
    pub(crate) limit_error: &'static str,
}

/// Error reported when a custom processor exceeds its cumulative content budget.
const OUTPUT_BYTE_LIMIT_ERROR: &str = "custom body processor output exceeded byte limit";

/// Error reported when a custom processor exceeds its cumulative file-metadata budget.
const METADATA_BYTE_LIMIT_ERROR: &str = "custom body processor file metadata exceeded byte limit";

/// Error reported when the collection copies of a processor's arguments and XML values exceed the same budget.
const COLLECTION_BYTE_LIMIT_ERROR: &str = "custom body processor collection copies exceeded byte limit";

/// Metadata, which is what the engine retains beyond the staged content, may use this multiple of the content
/// budget: many small files with long names, and many tiny arguments or XML values, are bounded relative to the
/// body that produced them without costing the content any of its own allowance.
const METADATA_BUDGET_FACTOR: usize = 4;

/// Keeps small body limits usable: one file's metadata is several kilobytes however small its content is,
/// because every collection it touches allocates its first table.
const METADATA_BUDGET_FLOOR: usize = 32 * 1024;

/// The file-metadata allowance for a content budget of `byte_capacity` bytes.
fn metadata_capacity(byte_capacity: usize) -> usize {
    byte_capacity
        .saturating_mul(METADATA_BUDGET_FACTOR)
        .max(METADATA_BUDGET_FLOOR)
}

/// Bytes the engine retains in `copies` collections for one staged name/value entry beyond the staged copy,
/// charged conservatively with the model [`file_metadata_bytes`] uses for each insertion.
///
/// A processor emitting minimal entries pays little for them staged, but each publication into a collection costs
/// hundreds of bytes of tables and a copy of its key at least twice, and a request argument goes into two.
fn collection_copy_bytes(name: usize, value: usize, copies: usize, first: bool) -> usize {
    /// Key bytes retained per input key byte by one insertion.
    const KEY: usize = KEY_COPIES_PER_INSERT * KEY_RETAINED_BYTES_PER_BYTE;

    let first_allocations = if first { FIRST_INSERT_OVERHEAD_BYTES } else { 0 };
    INSERT_OVERHEAD_BYTES
        .saturating_add(first_allocations)
        .saturating_add(name.saturating_mul(KEY))
        .saturating_add(value)
        .saturating_mul(copies)
}

/// Bytes the engine retains for one custom file beyond its content, charged conservatively.
///
/// `add_body_processor_file` inserts a file into `MULTIPART_PART_HEADERS` (the content type with its
/// `Content-Type: ` prefix), `FILES` and `FILES_NAMES` (under an empty key), `MULTIPART_NAME`,
/// `MULTIPART_FILENAME`, `FILES_SIZES` (the size as decimal text) and `FILES_TMPNAMES` (the temporary path),
/// and keeps the native `PathBuf` of the temporary file in the transaction's list for cleanup.
/// Each insertion keeps its key twice, once as the lookup key and once beside the value, and an invalid UTF-8
/// key byte can cost four bytes per copy, so every insertion is charged `INSERT_OVERHEAD_BYTES` plus its
/// key bytes times the copies and expansion plus its value. The staged struct and its three byte strings are
/// added on top. The first file also pays for the initial allocation of the seven collections it touches.
fn file_metadata_bytes(name: usize, filename: usize, content_type: usize, upload_path: usize, first: bool) -> usize {
    /// Longest decimal rendering of a `u64`, the value in `FILES_SIZES`.
    const SIZE_TEXT_BYTES: usize = 20;
    /// The `Content-Type: ` prefix stored with the content type.
    const CONTENT_TYPE_PREFIX_BYTES: usize = 14;
    /// Key bytes retained per input key byte by one insertion.
    const KEY: usize = KEY_COPIES_PER_INSERT * KEY_RETAINED_BYTES_PER_BYTE;

    // (key bytes, value bytes) of each insertion; the empty key is held for free.
    let insertions = [
        (name, CONTENT_TYPE_PREFIX_BYTES.saturating_add(content_type)),
        (0, filename),
        (name, name),
        (name, filename),
        (filename, SIZE_TEXT_BYTES),
        (0, name),
        (0, upload_path),
    ];
    let first_allocations = if first {
        FIRST_INSERT_OVERHEAD_BYTES.saturating_mul(insertions.len())
    } else {
        0
    };
    insertions
        .into_iter()
        .fold(
            size_of::<BodyProcessorFile>().saturating_add(first_allocations),
            |total, (key, value)| {
                total
                    .saturating_add(INSERT_OVERHEAD_BYTES)
                    .saturating_add(key.saturating_mul(KEY))
                    .saturating_add(value)
            },
        )
        .saturating_add(name)
        .saturating_add(filename)
        .saturating_add(content_type)
        // The `PathBuf` kept for cleanup: its bytes, and its slot in a list that may have doubled.
        .saturating_add(upload_path)
        .saturating_add(2 * size_of::<PathBuf>())
}

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
    ///
    /// `byte_capacity` bounds content; file metadata has its own, larger allowance derived from it.
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
            metadata_capacity: metadata_capacity(byte_capacity),
            // A request's, which is the larger; the transaction narrows it for a response.
            argument_copies: 2,
            ..Self::default()
        }
    }

    /// The files staged so far.
    #[cfg(test)]
    pub(crate) fn staged_files(&self) -> &[BodyProcessorFile] {
        &self.files
    }

    /// The metadata allowance this output was given.
    #[cfg(test)]
    pub(crate) fn metadata_allowance(&self) -> usize {
        self.metadata_capacity
    }

    /// File metadata bytes charged so far.
    #[cfg(test)]
    pub(crate) fn metadata_charged(&self) -> usize {
        self.metadata_bytes
    }

    /// Account for the copies of an argument's collections: one for a response, two for a request.
    pub(crate) fn with_argument_copies(mut self, copies: usize) -> Self {
        self.argument_copies = copies;
        self
    }

    /// Account for the path length of a temporary upload file, which `FILES_TMPNAMES` and the transaction's
    /// cleanup list retain.
    pub(crate) fn with_upload_path_bytes(mut self, bytes: usize) -> Self {
        // The file name `tempfile` appends to the directory is a fixed-length random one.
        const TEMP_NAME_BYTES: usize = 32;
        self.upload_path_bytes = bytes.saturating_add(TEMP_NAME_BYTES);
        self
    }

    /// Reserve content bytes, then file metadata bytes, before copying any caller-provided slices.
    ///
    /// Nothing is reserved unless both fit, so a refused entry leaves both budgets as they were.
    fn reserve(&mut self, content: Option<usize>, metadata: usize, metadata_error: &'static str) -> bool {
        if self.byte_limit_reached {
            return false;
        }
        let content_total = content.and_then(|content| self.output_bytes.checked_add(content));
        let content_total = content_total.filter(|total| *total <= self.byte_capacity);
        let metadata_total = self
            .metadata_bytes
            .checked_add(metadata)
            .filter(|total| *total <= self.metadata_capacity);
        let (Some(content_total), Some(metadata_total)) = (content_total, metadata_total) else {
            self.byte_limit_reached = true;
            self.limit_error = if content_total.is_none() {
                OUTPUT_BYTE_LIMIT_ERROR
            } else {
                metadata_error
            };
            self.error = Some(self.limit_error.to_owned());
            return false;
        };
        self.output_bytes = content_total;
        self.metadata_bytes = metadata_total;
        true
    }

    /// Reserve the content bytes of one name/value entry and its staged storage, and the metadata bytes of the
    /// collection copies the engine makes of it later.
    fn reserve_entry(&mut self, name: &[u8], value: &[u8], copies: usize, first: bool) -> bool {
        let staged = size_of::<(Vec<u8>, Vec<u8>)>()
            .checked_add(name.len())
            .and_then(|total| total.checked_add(value.len()));
        let metadata = collection_copy_bytes(name.len(), value.len(), copies, first);
        self.reserve(
            Some(staged.unwrap_or(usize::MAX)),
            metadata,
            COLLECTION_BYTE_LIMIT_ERROR,
        )
    }

    /// Add an argument to `ARGS_POST` or `RESPONSE_ARGS`.
    ///
    /// Its staged bytes count against the content budget and the copies the engine makes in its collections
    /// against the metadata budget, so a raised argument limit does not let tiny arguments retain far more
    /// than the body. Exhausting either budget refuses the argument and every later output, and reports an
    /// error.
    ///
    /// Values beyond the resolved argument limit are dropped and set
    /// `ARGUMENTS_LIMIT_REACHED` when the output is merged.
    pub fn add_argument(&mut self, name: &[u8], value: &[u8]) {
        if self.arguments.len() >= self.argument_capacity {
            self.argument_limit_reached = true;
            return;
        }
        if !self.reserve_entry(name, value, self.argument_copies, self.arguments.is_empty()) {
            return;
        }
        self.arguments.push((name.to_vec(), value.to_vec()));
    }

    /// Add a file whose bytes the engine will write to its private temporary-file path.
    ///
    /// The file content counts against the body-limit byte budget shared with arguments and XML values.
    /// Its names, content type and the engine-side `FILES*` and `MULTIPART_*` entries count against a separate
    /// metadata budget of four times the body limit (at least 32768 bytes), so metadata never reduces the largest
    /// content a file can have. Exhausting either budget refuses the file and every later output, and reports
    /// an error.
    ///
    /// The processor cannot select or invent the path. Files beyond the resolved upload
    /// limit are still recorded and flagged, so the engine still publishes `FILES`,
    /// `FILES_SIZES` and `FILES_NAMES`; only the temporary-file write and the
    /// `FILES_TMPNAMES` entry stop. Unlike the built-in
    /// multipart processor, custom files cannot reproduce wire part headers: this
    /// deliberately narrow API has no raw-header input, so `MULTIPART_PART_HEADERS`
    /// contains only `Content-Type: <content_type>`. Rules that depend on wire part
    /// headers, including `Content-Disposition`, must use the built-in multipart
    /// processor. WASI targets reject file output until a connector provides a
    /// memory-backed sink.
    pub fn add_file(&mut self, name: &[u8], filename: &[u8], content_type: &[u8], bytes: &[u8]) {
        if !self.file_storage_available {
            self.set_error("file-producing body processors are unavailable on WASI without a connector memory sink");
            return;
        }
        if self.files.len() >= self.file_capacity {
            self.file_limit_reached = true;
        }
        // The content is charged against the content budget, which is the body limit. Everything else the
        // engine retains for the file, the staged struct and the copies `add_body_processor_file` makes later
        // in the `FILES*` and `MULTIPART_*` collections, is charged against the separate metadata budget, so
        // a file that fits the body limit is not refused for its names. Both are reserved before any copy.
        let metadata = file_metadata_bytes(
            name.len(),
            filename.len(),
            content_type.len(),
            self.upload_path_bytes,
            self.files.is_empty(),
        );
        if !self.reserve(Some(bytes.len()), metadata, METADATA_BYTE_LIMIT_ERROR) {
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
    ///
    /// Charged like an argument: its staged bytes against the content budget and its collection copy against the
    /// metadata budget. When the output is merged, values past `SecArgumentsLimit`, counted with those the
    /// collection already holds, are dropped: `ARGUMENTS_LIMIT_REACHED` is set and a body error is reported for the
    /// direction.
    pub fn add_xml(&mut self, path: &[u8], value: &[u8]) {
        if !self.reserve_entry(path, value, 1, self.xml.is_empty()) {
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

pub(crate) mod budget;
pub(crate) mod multipart;
pub(crate) mod xml;

#[cfg(test)]
mod tests {
    use super::{BodyProcessorOutput, FIRST_INSERT_OVERHEAD_BYTES, file_metadata_bytes};

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

    /// The metadata charge of the file the tests below stage, as the first file of an output.
    fn first_file_metadata() -> usize {
        file_metadata_bytes(b"name".len(), b"file.txt".len(), b"text/plain".len(), 0, true)
    }

    #[test]
    fn file_metadata_counts_against_its_own_budget_with_an_accepted_boundary() {
        // The content budget is ample, so only the metadata charge can refuse the file.
        let charge = first_file_metadata();
        let mut output = BodyProcessorOutput::new(4, 4, 1 << 20, true);
        output.metadata_capacity = charge;
        output.add_file(b"name", b"file.txt", b"text/plain", b"data");
        assert_eq!(
            output.files.len(),
            1,
            "a metadata budget of exactly the charge accepts the file"
        );
        assert_eq!(output.metadata_bytes, charge);
        assert!(!output.byte_limit_reached);

        let mut output = BodyProcessorOutput::new(4, 4, 1 << 20, true);
        output.metadata_capacity = charge - 1;
        output.add_file(b"name", b"file.txt", b"text/plain", b"data");
        assert!(output.files.is_empty(), "one byte under the charge refuses the file");
        assert!(output.byte_limit_reached);
        assert_eq!(output.output_bytes, 0, "a refused file reserves no content bytes");
        assert_eq!(output.metadata_bytes, 0, "a refused file reserves no metadata bytes");
        assert_eq!(
            output.error.as_deref(),
            Some("custom body processor file metadata exceeded byte limit")
        );
    }

    #[test]
    fn file_content_is_charged_against_the_content_budget_alone() {
        // The metadata allowance is ample, so only the content can refuse the file, and exactly at its length.
        let mut output = BodyProcessorOutput::new(4, 4, 4, true);
        output.add_file(b"name", b"file.txt", b"text/plain", b"data");
        assert_eq!(output.files.len(), 1, "content of exactly the budget is accepted");
        assert_eq!(
            output.output_bytes, 4,
            "names and metadata did not consume content bytes"
        );

        let mut output = BodyProcessorOutput::new(4, 4, 3, true);
        output.add_file(b"name", b"file.txt", b"text/plain", b"data");
        assert!(
            output.files.is_empty(),
            "one content byte over the budget refuses the file"
        );
        assert_eq!(
            output.error.as_deref(),
            Some("custom body processor output exceeded byte limit")
        );
    }

    #[test]
    fn metadata_charge_grows_with_every_retained_copy_and_only_the_first_file_pays_for_new_tables() {
        let base = file_metadata_bytes(1, 1, 1, 0, false);
        // `name` is the key of three insertions (two copies each, up to four times as large for invalid UTF-8)
        // and a value of two, plus the staged copy; `filename` is the key of one insertion, a value of two and
        // staged once. The charge must grow at least that fast.
        let more_name = file_metadata_bytes(101, 1, 1, 0, false);
        assert!(
            more_name - base >= 100 * (3 * 2 * 4 + 3),
            "name bytes are charged per copy"
        );
        let more_filename = file_metadata_bytes(1, 101, 1, 0, false);
        assert!(
            more_filename - base >= 100 * (2 * 4 + 3),
            "filename bytes are charged per copy"
        );
        assert!(file_metadata_bytes(1, 1, 1, 0, true) > base);
        assert_eq!(
            file_metadata_bytes(1, 1, 1, 0, true) - base,
            FIRST_INSERT_OVERHEAD_BYTES * 7,
            "the first file pays for the initial allocation of its seven collections"
        );
    }

    #[test]
    fn the_native_path_copy_of_an_upload_is_charged_beside_its_collection_entry() {
        // The path is held in `FILES_TMPNAMES` and again as a `PathBuf` in the transaction's cleanup list, so each
        // path byte costs twice.
        let without = file_metadata_bytes(1, 1, 1, 0, false);
        let with = file_metadata_bytes(1, 1, 1, 1000, false);
        assert!(with - without >= 2 * 1000, "1000 path bytes added {}", with - without);
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
