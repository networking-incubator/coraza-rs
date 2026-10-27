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

use std::{path::Path, sync::Arc};

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
/// request or response body limit.
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
    /// Request JSON-style recursion limit.
    pub request_body_recursion_limit: usize,
    /// Response JSON-style recursion limit.
    pub response_body_recursion_limit: usize,
}

/// A processor for a body selected by a SecLang `ctl` action.
///
/// The processor is called synchronously on the request path with attacker-controlled
/// bytes. The engine has no timeout and does not catch panics. Implementations must not
/// panic, must bound their own work, and must honor the limits and storage policy in
/// `options`. The factory is retained by compiled rules and runs when the `ctl` action
/// selects this processor.
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

/// Creates a body processor when a compiled `ctl:requestBodyProcessor` or
/// `ctl:responseBodyProcessor` action runs.
pub type BodyProcessorFactory = Arc<dyn Fn() -> Box<dyn BodyProcessor> + Send + Sync>;

/// Values a custom body processor can publish without direct transaction access.
///
/// Its fields are private so processors can only add supported arguments, files, XML
/// values, processor names, and errors through the methods below.
#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the two independent truncation flags and target storage capability describe output state"
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
    pub(crate) fn new(argument_capacity: usize, file_capacity: usize, file_storage_available: bool) -> Self {
        Self {
            argument_capacity,
            file_capacity,
            file_storage_available,
            ..Self::default()
        }
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
        self.arguments.push((name.to_vec(), value.to_vec()));
    }

    /// Add a file whose bytes the engine will write to its private temporary-file path.
    ///
    /// The processor cannot select or invent the path. Files beyond the resolved upload
    /// limit are dropped. WASI targets reject file output until a connector provides a
    /// memory-backed sink.
    pub fn add_file(&mut self, name: &[u8], filename: &[u8], content_type: &[u8], bytes: &[u8]) {
        if !self.file_storage_available {
            self.set_error("file-producing body processors are unavailable on WASI without a connector memory sink");
            return;
        }
        if self.files.len() >= self.file_capacity {
            self.file_limit_reached = true;
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
        self.xml.push((path.to_vec(), value.to_vec()));
    }

    /// Set the processor name reported by `REQBODY_PROCESSOR` or
    /// `RES_BODY_PROCESSOR`.
    pub fn set_processor(&mut self, name: &str) {
        self.processor = Some(name.to_uppercase());
    }

    /// Report a processor-specific error while retaining any output already added.
    pub fn set_error(&mut self, message: &str) {
        self.error = Some(message.to_owned());
    }
}

pub(crate) mod multipart;
pub(crate) mod xml;

#[cfg(test)]
mod tests {
    use super::BodyProcessorOutput;

    #[test]
    fn file_output_is_rejected_without_a_storage_sink() {
        let mut output = BodyProcessorOutput::new(1, 1, false);
        output.add_file(b"upload", b"file.txt", b"text/plain", b"bytes");

        assert!(output.files.is_empty());
        assert!(output.error.as_deref().is_some_and(|message| message.contains("WASI")));
    }
}
