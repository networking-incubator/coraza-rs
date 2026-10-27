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

//! Request body ingestion and request body processor parsing.

use std::{
    borrow::Cow,
    collections::HashMap,
    io::Write as _,
    path::{Path, PathBuf},
};

use super::{Interruption, Transaction, body_buffer::BodyBuffer, variables::BodyProcessor};
use crate::{
    body_processors::{
        BodyDirection, BodyProcessor as CustomBodyProcessor, BodyProcessorFactory, BodyProcessorFile,
        BodyProcessorOptions, BodyProcessorOutput, multipart, truncate_custom_body_text, xml,
    },
    transformations::url_decode,
    types::{AuditEngineStatus, AuditLogPart, BodyLimitAction, RulePhase},
};

#[expect(
    clippy::multiple_inherent_impl,
    reason = "transaction impl blocks are split across submodules"
)]
impl Transaction {
    /// Process a request body and evaluate phase 2 rules.
    ///
    /// Call this once after [`Transaction::process_request_headers`], including for an
    /// empty body. The first `Content-Type` header selects URLENCODED or MULTIPART;
    /// `ctl:requestBodyProcessor` selects RAW, JSON, or XML. Phase 2 rules still run when
    /// body access is disabled or no processor is selected.
    ///
    /// When body access is enabled, bytes are retained in a bounded buffer, truncated to
    /// [`Transaction::request_body_limit`], and spilled to a private temporary file above
    /// `SecRequestBodyInMemoryLimit`. Like Go Coraza v3.8.1 `WriteRequestBody`
    /// (`internal/corazawaf/transaction.go:965-967`), a disabled rule engine or disabled
    /// body access returns without buffering, limit checks or audit capture, and the `>=`
    /// comparison at the limit matches `WriteRequestBody` (`transaction.go:992`). A
    /// processor that requires one contiguous slice receives a copy read back from the
    /// spill file, bounded by the body limit. An I/O failure while retaining or replaying
    /// the body fails closed with a 500 interruption.
    pub fn process_request_body(&mut self, body: &[u8]) -> Option<Interruption> {
        if !self.begin_phase(RulePhase::RequestBody) {
            return self.interruption.clone();
        }

        let mut ingest_error = false;
        if self.request_body_access && !body.is_empty() {
            let limit = usize::try_from(self.request_body_limit).unwrap_or(0);
            let configured_memory = usize::try_from(self.config.request_body_in_memory_limit).unwrap_or(0);
            // Zero means unset: follow the body limit, as in Go
            // (internal/corazawaf/waf.go:242-247).
            let memory_limit = if configured_memory == 0 {
                limit
            } else {
                configured_memory
            };
            self.request_body_buffer = BodyBuffer::new(memory_limit, limit);
            if body.len() >= limit.saturating_sub(self.request_body_buffer.len()) {
                self.inbound_data_error.set("1");
                if self.config.request_body_limit_action == BodyLimitAction::Reject {
                    self.interrupt(0, "deny", 413, "");
                    if self.interruption.is_some() {
                        self.request_body_buffer.refuse(body.len());
                        return self.interruption.clone();
                    }
                }
            }
            if self.request_body_buffer.accept(body).is_err() {
                ingest_error = true;
            }
        }

        if self.audit_engine != AuditEngineStatus::Off && self.audit_log_parts.contains(&AuditLogPart::RequestBody) {
            self.audit_request_body.clear();
            match self.request_body_buffer.contiguous() {
                Ok(retained) => self.audit_request_body.extend_from_slice(&retained),
                Err(_) => ingest_error = true,
            }
        }

        if ingest_error {
            self.inbound_data_error.set("1");
            self.interrupt(0, "deny", 500, "");
            // Detection-only records a would-be interruption; the body phase
            // must still evaluate its rules rather than being skipped.
            if self.interruption.is_some() {
                return self.interruption.clone();
            }
        } else if self.request_body_access && !self.request_body_buffer.is_empty() {
            if self.force_request_body_variable && self.reqbody_processor.get_bytes().is_empty() {
                self.set_request_body_processor("URLENCODED");
            }

            // Without a selected processor there is nothing to replay the buffer for;
            // audit capture above reads the retained bytes independently.
            if self.request_body_processor.is_some()
                || self
                    .computed
                    .custom_body_processors
                    .as_ref()
                    .is_some_and(|processors| processors.request.is_some())
            {
                let stats = self.request_body_stats();
                let truncated = stats.truncated;
                // Go's multipart processor treats any >= limit hit as partial, even when
                // no bytes were discarded. Keep that separate from the custom option.
                let partial = stats.truncated || stats.supplied >= u64::try_from(self.request_body_limit).unwrap_or(0);
                let mut buffer = std::mem::take(&mut self.request_body_buffer);
                let inspected = buffer.contiguous().map(|body| {
                    let length = body.len();
                    self.inspect_request_body(&body, truncated, partial);
                    length
                });
                self.request_body_buffer = buffer;
                if let Ok(length) = inspected {
                    self.request_body_buffer.set_inspected(length);
                } else {
                    self.inbound_data_error.set("1");
                    self.interrupt(0, "deny", 500, "");
                    if self.interruption.is_some() {
                        return self.interruption.clone();
                    }
                }
            }
        }

        self.run_phase(RulePhase::RequestBody);
        self.interruption.clone()
    }

    /// Store and parse the body with the selected processor.
    ///
    /// `truncated` reports discarded bytes; `partial` preserves multipart's limit-hit
    /// handling, including an exact `>=` boundary with no discarded bytes.
    fn inspect_request_body(&mut self, body: &[u8], truncated: bool, partial: bool) {
        if let Some(processor) = selected_custom_body_processor(self, BodyDirection::Request) {
            process_custom_body_processor(self, body, BodyDirection::Request, truncated, processor.as_ref());
            return;
        }
        let Some(processor) = self.request_body_processor else {
            return;
        };

        match processor {
            BodyProcessor::Raw => {
                self.request_body.set(body);
                self.request_body_length.set(body.len().to_string());
            },
            BodyProcessor::UrlEncoded => {
                self.request_body.set(body);
                self.request_body_length.set(body.len().to_string());
                for (key, value) in parse_urlencoded(body) {
                    self.add_post_argument(key, value);
                }
            },
            BodyProcessor::Multipart => {
                if let Err(message) = self.process_multipart_body(body, partial) {
                    self.log_body_processor_error(true, "MULTIPART", &message);
                    self.reqbody_error.set("1");
                    self.reqbody_error_msg.set(format!("MULTIPART: {message}"));
                    self.reqbody_processor_error.set("1");
                    self.reqbody_processor_error_msg.set(message);
                }
            },
            BodyProcessor::Json => {
                // Arguments are published before the error is checked so a valid
                // prefix stays inspectable; see Go Coraza `json.go:34-62`.
                let parsed = read_json_body(
                    body,
                    self.config.request_body_json_depth_limit,
                    self.config.argument_limit,
                );
                publish_json_arguments(self, &parsed.arguments, false);
                if parsed.truncated {
                    self.arguments_limit_reached.set("1");
                }
                match parsed.error {
                    Some(message) => {
                        self.log_body_processor_error(true, "JSON", &message);
                        self.reqbody_error.set("1");
                        self.reqbody_error_msg.set(format!("JSON: {message}"));
                        self.reqbody_processor_error.set("1");
                        self.reqbody_processor_error_msg.set(message);
                    },
                    None => self.set_tx_variable("json_request_body", body),
                }
            },
            BodyProcessor::Xml => match xml::parse(body) {
                Ok(document) => {
                    for value in document.attribute_values {
                        self.request_xml.add("//@*", value);
                    }
                    for value in document.text {
                        self.request_xml.add("/*", value);
                    }
                },
                Err(message) => {
                    self.log_body_processor_error(true, "XML", &message);
                    // Go stores the processor's own error unchanged, which for XML is
                    // `encoding/xml`'s `XML syntax error on line N: ...`
                    // (`internal/corazawaf/transaction.go:1780-1786`, v3.8.1).
                    self.reqbody_error.set("1");
                    self.reqbody_error_msg.set(format!("XML: {message}"));
                    self.reqbody_processor_error.set("1");
                    self.reqbody_processor_error_msg.set(message);
                },
            },
        }
    }

    /// Populate multipart fields, metadata, and temporary upload files.
    fn process_multipart_body(&mut self, body: &[u8], truncated: bool) -> Result<(), String> {
        let content_type = self.request_headers.first("content-type").unwrap_or_default().to_vec();
        let (parts, failure) = multipart::parse(&content_type, body, truncated);
        // Go's `NextPart` loop sets the strict error as soon as a part fails, but it
        // has already published the parts before it (`internal/bodyprocessors/multipart.go:52-70`,
        // v3.8.1), so publishing continues here and the error is reported afterwards.
        if failure.as_ref().is_some_and(|failure| failure.strict) {
            self.multipart_strict_error.set("1");
        }
        let upload_dir = if self.config.upload_dir.is_empty() {
            std::env::temp_dir()
        } else {
            PathBuf::from(&self.config.upload_dir)
        };
        let mut total_size = 0_u64;

        for part in parts {
            if part.repeats_header {
                self.multipart_duplicate_part_header.set("1");
                self.multipart_strict_error.set("1");
            }
            if part.invalid_quoting {
                self.multipart_invalid_quoting.set("1");
                self.multipart_strict_error.set("1");
            }

            for (name, value) in &part.headers {
                // Go Coraza v3.8.1 `multipart.go:70` stores the header value's raw bytes;
                // a lossy text view would make distinct invalid-UTF-8 values equal.
                let mut header = multipart::canonical_header_name(name).into_bytes();
                header.extend_from_slice(b": ");
                header.extend_from_slice(value);
                self.multipart_part_headers.add_bytes(&part.name, header);
            }
            self.multipart_name.add_bytes(&part.name, &part.name);
            // Go publishes only non-empty filenames, while a `filename*` that decoded to
            // nothing still contributes its charset and language
            // (`internal/bodyprocessors/multipart.go:88-105`, v3.8.1).
            let filename = part.filename.as_deref().filter(|filename| !filename.is_empty());
            let alt_filename = part.alt_filename.as_deref().filter(|filename| !filename.is_empty());
            if let Some(filename) = filename {
                self.multipart_filename.add_bytes(&part.name, filename);
            }
            if let Some(filename) = alt_filename {
                self.multipart_filename.add_bytes(&part.name, filename);
            }
            if let Some(encoding) = &part.filename_encoding {
                self.multipart_filename_charset.add_bytes(&part.name, &encoding.charset);
                self.multipart_filename_language
                    .add_bytes(&part.name, &encoding.language);
            }
            if part.malformed_filename {
                self.multipart_strict_error.set("1");
            }

            let size = u64::try_from(part.data.len()).map_err(|error| format!("multipart size overflow: {error}"))?;
            total_size = total_size
                .checked_add(size)
                .ok_or_else(|| "multipart size overflow".to_owned())?;

            // Go promotes `altFilename` when the primary filename is empty and treats a
            // part with no non-empty filename as a field, which is what an empty file
            // input sends (`internal/bodyprocessors/multipart.go:106-115`, v3.8.1).
            if let Some(filename) = filename.or(alt_filename) {
                if self.uploaded_paths.len() >= self.config.upload_file_limit {
                    self.multipart_strict_error.set("1");
                    continue;
                }
                let path =
                    save_to_temp(&upload_dir, part.data).inspect_err(|_| self.multipart_strict_error.set("1"))?;
                self.files_tmp_names.add("", path.to_string_lossy().as_bytes());
                self.uploaded_paths.push(path);
                self.files.add("", filename);
                self.files_sizes.set_index(filename, 0, size.to_string());
                if let Some(alt_filename) = alt_filename.filter(|&alt| alt != filename) {
                    self.files.add("", alt_filename);
                    self.files_sizes.set_index(alt_filename, 0, size.to_string());
                }
                self.files_names.add("", &part.name);
            } else {
                self.add_post_argument(&part.name, part.data);
            }
        }

        self.files_combined_size.set(total_size.to_string());
        match failure {
            Some(failure) => Err(failure.message),
            None => Ok(()),
        }
    }

    /// Select a request body processor, retaining its name even when this slice does not
    /// implement that processor.
    pub(super) fn set_request_body_processor(&mut self, name: &str) {
        self.request_body_processor = BodyProcessor::parse(name);
        if let Some(processors) = &mut self.computed.custom_body_processors {
            processors.request = None;
        }
        self.reqbody_processor
            .set(truncate_custom_body_text(&name.to_ascii_uppercase()));
    }

    /// Select a parser-resolved custom processor for request bodies.
    pub(super) fn set_request_custom_body_processor(&mut self, name: &str, factory: BodyProcessorFactory) {
        self.request_body_processor = None;
        let processors = self
            .computed
            .custom_body_processors
            .get_or_insert_with(|| Box::new(super::CustomBodyProcessors::default()));
        processors.request = Some(super::CustomBodyProcessorSelection {
            factory,
            processor: None,
        });
        self.reqbody_processor
            .set(truncate_custom_body_text(&name.to_ascii_uppercase()));
    }
}

/// Process a custom body and merge its narrow output through transaction insertion paths.
pub(super) fn process_custom_body_processor(
    tx: &mut Transaction,
    body: &[u8],
    direction: BodyDirection,
    truncated: bool,
    processor: &dyn CustomBodyProcessor,
) {
    let upload_dir = if tx.config.upload_dir.is_empty() {
        std::env::temp_dir()
    } else {
        PathBuf::from(&tx.config.upload_dir)
    };
    // Both directions pass the raw `Content-Type` header, parameters included, so a
    // custom processor sees the same shape the built-in processors and Go receive
    // (`internal/corazawaf/transaction.go:1132-1135`). `RESPONSE_CONTENT_TYPE` is a
    // different variable: it keeps the value before the first `;`.
    let mime = match direction {
        BodyDirection::Request => tx.request_headers.first("content-type").unwrap_or_default(),
        BodyDirection::Response => tx.response_headers.values("content-type").last().unwrap_or_default(),
    };
    let current_argument_count = match direction {
        BodyDirection::Request => tx.args_post.value_count(),
        BodyDirection::Response => tx.response_args.value_count(),
    };
    let byte_capacity = match direction {
        BodyDirection::Request => usize::try_from(tx.request_body_limit).unwrap_or(0),
        BodyDirection::Response => usize::try_from(tx.response_body_limit).unwrap_or(0),
    };
    let mut output = BodyProcessorOutput::new(
        tx.config.argument_limit.saturating_sub(current_argument_count),
        tx.config.upload_file_limit.saturating_sub(tx.uploaded_paths.len()),
        byte_capacity,
        !cfg!(target_os = "wasi"),
    );
    let options = BodyProcessorOptions {
        mime,
        upload_dir: &upload_dir,
        upload_file_limit: tx.config.upload_file_limit,
        upload_file_mode: tx.config.upload_file_mode,
        upload_keep_files: tx.config.upload_keep_files,
        argument_limit: tx.config.argument_limit,
        truncated,
        data_error: match direction {
            BodyDirection::Request => tx.inbound_data_error.get_bytes() == b"1",
            BodyDirection::Response => tx.outbound_data_error.get_bytes() == b"1",
        },
        request_body_recursion_limit: tx.config.request_body_json_depth_limit,
        response_body_recursion_limit: tx.config.response_body_json_depth_limit,
    };
    let processor_error = processor
        .process(body, direction, &options, &mut output)
        .err()
        .map(|message| truncate_custom_body_text(&message));
    let mut error = if output.byte_limit_reached {
        Some("custom body processor output exceeded byte limit".to_owned())
    } else {
        processor_error.or_else(|| output.error.take())
    };

    if output.byte_limit_reached {
        match direction {
            BodyDirection::Request => tx.inbound_data_error.set("1"),
            BodyDirection::Response => tx.outbound_data_error.set("1"),
        }
    }

    if let Some(name) = output.processor.take() {
        match direction {
            BodyDirection::Request => tx.reqbody_processor.set(name),
            BodyDirection::Response => tx.res_body_processor.set(name),
        }
    }
    if output.argument_limit_reached {
        tx.arguments_limit_reached.set("1");
    }
    if output.file_limit_reached {
        tx.multipart_strict_error.set("1");
    }

    for (name, value) in output.arguments {
        match direction {
            BodyDirection::Request => tx.add_post_argument(name, value),
            BodyDirection::Response => add_response_body_argument(tx, &name, &value),
        }
    }
    for (path, value) in output.xml {
        match direction {
            BodyDirection::Request => tx.request_xml.add_bytes(&path, &value),
            BodyDirection::Response => tx.response_xml.add_bytes(&path, &value),
        }
    }
    for file in &output.files {
        if let Err(message) = add_body_processor_file(tx, &upload_dir, file) {
            if error.is_none() {
                error = Some(message);
            }
            break;
        }
    }

    if let Some(message) = error {
        record_custom_body_processor_error(tx, direction, &message);
    }
}

/// Set the matching request or response processor error variables.
fn record_custom_body_processor_error(tx: &mut Transaction, direction: BodyDirection, message: &str) {
    let request = direction == BodyDirection::Request;
    let processor_name = match direction {
        BodyDirection::Request => truncate_custom_body_text(&tx.reqbody_processor.get()),
        BodyDirection::Response => truncate_custom_body_text(&tx.res_body_processor.get()),
    };
    let message = truncate_custom_body_text(message);
    tx.log_body_processor_error(request, &processor_name, &message);
    match direction {
        BodyDirection::Request => {
            tx.reqbody_error.set("1");
            tx.reqbody_error_msg.set(format!("{processor_name}: {message}"));
            tx.reqbody_processor_error.set("1");
            tx.reqbody_processor_error_msg.set(message);
        },
        BodyDirection::Response => {
            tx.res_body_error.set("1");
            tx.res_body_error_msg.set(format!("{processor_name}: {message}"));
            tx.res_body_processor_error.set("1");
            tx.res_body_processor_error_msg.set(message);
        },
    }
}

/// Create the selected custom processor once, on the first body-processing call.
pub(super) fn selected_custom_body_processor(
    tx: &mut Transaction,
    direction: BodyDirection,
) -> Option<std::sync::Arc<dyn CustomBodyProcessor>> {
    let processors = tx.computed.custom_body_processors.as_mut()?;
    let selection = match direction {
        BodyDirection::Request => processors.request.as_mut(),
        BodyDirection::Response => processors.response.as_mut(),
    }?;
    if selection.processor.is_none() {
        selection.processor = Some(std::sync::Arc::from((selection.factory)()));
    }
    selection.processor.as_ref().map(std::sync::Arc::clone)
}

/// Publish response arguments under the same per-collection argument limit as JSON.
fn add_response_body_argument(tx: &mut Transaction, name: &[u8], value: &[u8]) {
    if tx.response_args.value_count() < tx.config.argument_limit {
        tx.response_args.add_bytes(name, value);
    } else {
        tx.arguments_limit_reached.set("1");
    }
}

/// Store a custom file using the same private temporary-file path as multipart uploads.
fn add_body_processor_file(tx: &mut Transaction, upload_dir: &Path, file: &BodyProcessorFile) -> Result<(), String> {
    if tx.uploaded_paths.len() >= tx.config.upload_file_limit {
        tx.multipart_strict_error.set("1");
        return Ok(());
    }
    let size = u64::try_from(file.bytes.len()).map_err(|error| format!("upload size overflow: {error}"))?;
    let current_size = std::str::from_utf8(tx.files_combined_size.get_bytes())
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let total_size = current_size
        .checked_add(size)
        .ok_or_else(|| "upload size overflow".to_owned())?;
    let path = save_to_temp(upload_dir, &file.bytes)?;

    let mut content_type = Vec::with_capacity(file.content_type.len().saturating_add(14));
    content_type.extend_from_slice(b"Content-Type: ");
    content_type.extend_from_slice(&file.content_type);
    tx.multipart_part_headers.add_bytes(&file.name, content_type);
    tx.files_tmp_names.add_bytes(b"", path.to_string_lossy().as_bytes());
    tx.uploaded_paths.push(path);
    tx.files.add_bytes(b"", &file.filename);
    tx.multipart_name.add_bytes(&file.name, &file.name);
    tx.multipart_filename.add_bytes(&file.name, &file.filename);
    tx.files_sizes.set_index(&file.filename, 0, size.to_string());
    tx.files_names.add_bytes(b"", &file.name);
    tx.files_combined_size.set(total_size.to_string());
    Ok(())
}

/// Store an upload in a new private temporary file and return its path.
fn save_to_temp(upload_dir: &Path, data: &[u8]) -> Result<PathBuf, String> {
    let mut file = tempfile::Builder::new()
        .prefix("crzmp")
        .tempfile_in(upload_dir)
        .map_err(|error| format!("I/O error: {error}"))?;
    file.write_all(data).map_err(|error| format!("I/O error: {error}"))?;
    let (_, path) = file.keep().map_err(|error| format!("I/O error: {}", error.error))?;
    Ok(path)
}

/// Parses URLENCODED pairs in order, preserving decoded name and value bytes.
pub(super) fn parse_urlencoded(body: &[u8]) -> impl Iterator<Item = (Vec<u8>, Vec<u8>)> + '_ {
    body.split(|&byte| byte == b'&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = match pair.iter().position(|&byte| byte == b'=') {
                Some(equals) => (
                    pair.get(..equals).unwrap_or_default(),
                    pair.get(equals.saturating_add(1)..).unwrap_or_default(),
                ),
                None => (pair, &b""[..]),
            };
            let key = url_decode(key).0;
            let value = url_decode(value).0;
            (key, value)
        })
}

/// Bounds the flattened form relative to the body that produced it.
///
/// `SecArgumentsLimit` counts entries, not bytes, and the flattened key is the
/// full path rewritten for every leaf, so memory grows with depth times leaves
/// while the entry count grows only with leaves. Go Coraza uses the same factor
/// (`internal/bodyprocessors/json.go:113`); see the comment there.
const FLATTEN_BYTES_FACTOR: usize = 8;

/// Keeps small bodies unaffected, where a few long keys can legitimately
/// outweigh the input (`internal/bodyprocessors/json.go:117`).
const FLATTEN_BYTES_FLOOR: usize = 4096;

/// Why flattening stopped with an error, as Go Coraza reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonFlattenError {
    /// The configured container depth was exhausted.
    Recursion,
    /// The flattened form outgrew its byte budget.
    Budget,
}

/// A JSON body flattened the way Go Coraza's `readJSON` does.
pub(super) struct JsonBody {
    /// Dot-separated paths, in first-discovery order.
    pub(super) arguments: JsonArguments,
    /// Whether the argument or array-length cap stopped the walk.
    pub(super) truncated: bool,
    /// The parser error message, after any best-effort arguments were collected.
    pub(super) error: Option<String>,
}

/// Flattened arguments in first-discovery order.
///
/// Hash-map iteration order depends on `RandomState`, so publishing straight
/// from one would make the insertion order of distinct keys in `ARGS_POST`,
/// `ARGS` and `RESPONSE_ARGS` change between runs, and with it first-match
/// results and audit argument order. Entries are kept in a vector instead;
/// the map only indexes a path to its row.
pub(super) struct JsonArguments {
    /// Paths in first-discovery order, with each path's values in discovery order.
    entries: Vec<JsonArgument>,
    /// Row of each path in `entries`.
    rows: HashMap<Vec<u8>, usize>,
}

/// One flattened path with its values, in discovery order.
type JsonArgument = (Vec<u8>, Vec<Vec<u8>>);

impl JsonArguments {
    /// Create an empty set of arguments.
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            rows: HashMap::new(),
        }
    }

    /// Append `value` under `key`, creating the row on first discovery.
    fn push(&mut self, key: &[u8], value: Vec<u8>) {
        if let Some(row) = self.rows.get(key).copied()
            && let Some((_, values)) = self.entries.get_mut(row)
        {
            values.push(value);
            return;
        }
        let row = self.entries.len();
        let key = key.to_vec();
        self.rows.insert(key.clone(), row);
        self.entries.push((key, vec![value]));
    }

    /// Values stored under `key`, in discovery order.
    #[cfg(test)]
    pub(super) fn get(&self, key: &[u8]) -> Option<&[Vec<u8>]> {
        let row = self.rows.get(key).copied()?;
        self.entries.get(row).map(|(_, values)| values.as_slice())
    }

    /// Paths and values in first-discovery order.
    pub(super) fn iter(&self) -> impl Iterator<Item = (&[u8], &[Vec<u8>])> + '_ {
        self.entries
            .iter()
            .map(|(key, values)| (key.as_slice(), values.as_slice()))
    }

    /// Whether no argument was flattened.
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of distinct paths.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// A JSON value as gjson sees it while flattening.
enum JsonValue<'a> {
    /// An object or array.
    Json {
        /// Raw text of the container.
        raw: &'a [u8],
        /// Offset of `raw[0]` in the body.
        base: usize,
    },
    /// A string, holding its unescaped content.
    String(Cow<'a, [u8]>),
    /// A null, which Go Coraza flattens to an empty string.
    Null,
    /// A `true` literal, holding its raw token.
    True(&'a [u8]),
    /// A `false` literal, holding its raw token.
    False(&'a [u8]),
    /// A number, holding its raw token so its spelling survives.
    Number(&'a [u8]),
}

/// A child of an object, an array element, or the single value of a scalar root.
enum JsonKey<'a> {
    /// An object member name, unescaped.
    Name(Cow<'a, [u8]>),
    /// An array element index, or the zero key gjson gives a scalar root.
    Index(usize),
}

/// Reads one object or array the way gjson's `Result.ForEach` does.
struct JsonChildScanner<'a> {
    /// The container text, when the value is an object or array.
    raw: Option<&'a [u8]>,
    /// Offset of `raw[0]` in the body, for absolute container lookup.
    base: usize,
    /// Byte offset of the next candidate child.
    offset: usize,
    /// Whether `raw` holds an object rather than an array.
    object: bool,
    /// Index the next array element reports.
    index: usize,
    /// A scalar root, reported once as a child.
    single: Option<JsonValue<'a>>,
}

impl<'a> JsonChildScanner<'a> {
    /// Build a scanner for a parsed value.
    fn new(value: Option<JsonValue<'a>>) -> Self {
        match value {
            Some(JsonValue::Json { raw, base }) => Self::container(raw, base),
            Some(other) => Self {
                raw: None,
                base: 0,
                offset: 0,
                object: false,
                index: 0,
                single: Some(other),
            },
            None => Self::empty(),
        }
    }

    /// Build a scanner with nothing to report.
    fn empty() -> Self {
        Self {
            raw: None,
            base: 0,
            offset: 0,
            object: false,
            index: 0,
            single: None,
        }
    }

    /// Build a scanner over container text starting at `base` in the body.
    fn container(raw: &'a [u8], base: usize) -> Self {
        let mut offset = 0_usize;
        let mut object = true;
        loop {
            match raw.get(offset).copied() {
                Some(b'{') => {
                    offset += 1;
                    break;
                },
                Some(b'[') => {
                    object = false;
                    offset += 1;
                    break;
                },
                Some(byte) if byte > b' ' => {
                    // gjson's ForEach stops on anything but a container or whitespace.
                    return Self::empty();
                },
                Some(_) => offset += 1,
                None => return Self::empty(),
            }
        }
        Self {
            raw: Some(raw),
            base,
            offset,
            object,
            index: 0,
            single: None,
        }
    }

    /// The next child, with its key, in document order.
    fn next(&mut self, containers: &ContainerIndex) -> Option<(JsonKey<'a>, JsonValue<'a>)> {
        if let Some(single) = self.single.take() {
            return Some((JsonKey::Index(0), single));
        }
        let raw = self.raw?;
        if self.object {
            loop {
                if raw.get(self.offset).copied() != Some(b'"') {
                    raw.get(self.offset)?;
                    self.offset += 1;
                    continue;
                }
                let key_start = self.offset;
                let (end, escaped, ok) = scan_json_string(raw, key_start + 1);
                if !ok {
                    return None;
                }
                let content = raw.get(key_start + 1..end.checked_sub(1)?).unwrap_or_default();
                let name = if escaped {
                    Cow::Owned(unescape_json_string(content))
                } else {
                    Cow::Borrowed(content)
                };
                self.offset = end;
                self.skip_separators(raw);
                let (end, value) = parse_any_value(raw, self.offset, self.base, containers)?;
                // gjson's ForEach advances one more byte after each pair.
                self.offset = end.saturating_add(1);
                return Some((JsonKey::Name(name), value));
            }
        }
        self.skip_separators(raw);
        let index = self.index;
        self.index += 1;
        let (end, value) = parse_any_value(raw, self.offset, self.base, containers)?;
        // gjson's ForEach advances one more byte after each element.
        self.offset = end.saturating_add(1);
        Some((JsonKey::Index(index), value))
    }

    /// Skip the whitespace, commas and colons gjson skips before a value.
    fn skip_separators(&mut self, raw: &[u8]) {
        while raw
            .get(self.offset)
            .is_some_and(|byte| *byte <= b' ' || *byte == b',' || *byte == b':')
        {
            self.offset += 1;
        }
    }
}

/// One open container in the flattening walk.
struct JsonFrame<'a> {
    /// Reads this container's children.
    scanner: JsonChildScanner<'a>,
    /// Path length of this container's own key.
    base_len: usize,
    /// Path length to restore when the container ends.
    restore_len: usize,
    /// Container levels still allowed below this one.
    depth_remaining: usize,
    /// Array elements reported at this level.
    array_len: usize,
}

/// The state of one gjson-compatible flattening walk.
struct JsonFlattener {
    /// Flattened paths and their values, in discovery order.
    values: JsonArguments,
    /// Bytes retained in `values` so far.
    used_bytes: usize,
    /// Values counted against the argument limit.
    argument_count: usize,
    /// Array-length entries counted against their own cap.
    length_count: usize,
    /// Configured argument limit; zero means unlimited.
    argument_limit: usize,
    /// Maximum key and value bytes the flattened form may retain.
    byte_budget: usize,
}

impl JsonFlattener {
    /// Start a walk with the given caps.
    fn new(argument_limit: usize, byte_budget: usize) -> Self {
        Self {
            values: JsonArguments::new(),
            used_bytes: 0,
            argument_count: 0,
            length_count: 0,
            argument_limit,
            byte_budget,
        }
    }

    /// Flatten `root`, returning whether the argument or length cap was hit.
    fn flatten<'a>(
        &mut self,
        root: Option<JsonValue<'a>>,
        max_recursion: usize,
        containers: &ContainerIndex,
    ) -> Result<bool, JsonFlattenError> {
        if max_recursion == 0 {
            return Err(JsonFlattenError::Recursion);
        }
        let mut path = b"json".to_vec();
        let mut frames: Vec<JsonFrame<'a>> = vec![JsonFrame {
            scanner: JsonChildScanner::new(root),
            base_len: path.len(),
            restore_len: path.len(),
            depth_remaining: max_recursion,
            array_len: 0,
        }];
        let mut truncated = false;
        loop {
            let next = match frames.last_mut() {
                Some(frame) => frame.scanner.next(containers),
                None => return Ok(truncated),
            };
            match next {
                None => {
                    let Some(frame) = frames.pop() else {
                        return Ok(truncated);
                    };
                    if frame.array_len > 0 {
                        // Go checks the length cap only when this level was not
                        // already truncated by a nested call.
                        if self.argument_limit > 0 && self.length_count >= self.argument_limit {
                            truncated = true;
                        } else {
                            self.write_array_length(&path, &frame)?;
                        }
                    }
                    path.truncate(frame.restore_len);
                },
                Some((key, value)) => {
                    // Go checks the cap when its ForEach callback is invoked, so
                    // exactly filling the limit without another item is not
                    // truncation. Once it is hit no level writes anything more
                    // (json.go:254-257), so ending the walk is equivalent.
                    if self.argument_limit > 0 && self.argument_count >= self.argument_limit {
                        return Ok(true);
                    }
                    self.flatten_item(&mut frames, &mut path, key, value)?;
                },
            }
        }
    }

    /// Write one container's array-length entry.
    fn write_array_length(&mut self, path: &[u8], frame: &JsonFrame<'_>) -> Result<(), JsonFlattenError> {
        let length = frame.array_len.to_string();
        let key = path.get(..frame.base_len).unwrap_or_default();
        self.record(key, length.as_bytes())?;
        self.length_count += 1;
        Ok(())
    }

    /// Flatten one child.
    fn flatten_item<'a>(
        &mut self,
        frames: &mut Vec<JsonFrame<'a>>,
        path: &mut Vec<u8>,
        key: JsonKey<'a>,
        value: JsonValue<'a>,
    ) -> Result<(), JsonFlattenError> {
        let Some(frame) = frames.last_mut() else {
            return Ok(());
        };
        let depth_remaining = frame.depth_remaining;
        let previous_len = path.len();
        path.push(b'.');
        match key {
            JsonKey::Name(name) => path.extend_from_slice(name.as_ref()),
            JsonKey::Index(index) => {
                path.extend_from_slice(index.to_string().as_bytes());
                frame.array_len += 1;
            },
        }
        let value: Cow<'_, [u8]> = match value {
            JsonValue::Json { raw, base } => {
                let depth = depth_remaining.saturating_sub(1);
                if depth == 0 {
                    return Err(JsonFlattenError::Recursion);
                }
                frames.push(JsonFrame {
                    scanner: JsonChildScanner::container(raw, base),
                    base_len: path.len(),
                    restore_len: previous_len,
                    depth_remaining: depth,
                    array_len: 0,
                });
                return Ok(());
            },
            JsonValue::String(text) => text,
            JsonValue::Null => Cow::Borrowed(b""),
            JsonValue::True(raw) | JsonValue::False(raw) | JsonValue::Number(raw) => Cow::Borrowed(raw),
        };
        self.record(path, value.as_ref())?;
        self.argument_count += 1;
        path.truncate(previous_len);
        Ok(())
    }

    /// Retain one flattened entry, enforcing the byte budget.
    fn record(&mut self, key: &[u8], value: &[u8]) -> Result<(), JsonFlattenError> {
        let used = self.used_bytes.saturating_add(key.len()).saturating_add(value.len());
        if used > self.byte_budget {
            return Err(JsonFlattenError::Budget);
        }
        self.used_bytes = used;
        self.values.push(key, value.to_vec());
        Ok(())
    }
}

/// Whether the quote at `quote` is escaped by an odd run of backslashes.
///
/// `lowest` is the first index gjson's run counter may read: `1` for
/// `parseString` and the quote's next byte for `parseSquash`.
fn is_escaped_quote(input: &[u8], quote: usize, lowest: usize) -> bool {
    if quote.checked_sub(1).and_then(|index| input.get(index)) != Some(&b'\\') {
        return false;
    }
    let mut run = 0_usize;
    let mut index = quote.saturating_sub(2);
    while index >= lowest {
        if input.get(index) != Some(&b'\\') {
            break;
        }
        run += 1;
        let Some(previous) = index.checked_sub(1) else {
            break;
        };
        index = previous;
    }
    run.is_multiple_of(2)
}

/// Scans a JSON string whose opening quote is just before `start`.
///
/// Mirrors gjson's `parseString`: it stops at the first quote that is not
/// escaped by an odd run of backslashes and does not validate the content.
/// Returns where scanning stopped, whether an escape was seen, and whether a
/// closing quote was found.
fn scan_json_string(input: &[u8], start: usize) -> (usize, bool, bool) {
    let mut index = start;
    while let Some(&byte) = input.get(index) {
        if byte > b'\\' {
            index += 1;
            continue;
        }
        if byte == b'"' {
            return (index + 1, false, true);
        }
        if byte == b'\\' {
            index += 1;
            while let Some(&escaped) = input.get(index) {
                if escaped > b'\\' {
                    index += 1;
                    continue;
                }
                if escaped == b'"' && !is_escaped_quote(input, index, 1) {
                    return (index + 1, true, true);
                }
                index += 1;
            }
            break;
        }
        index += 1;
    }
    (index, false, false)
}

/// Finds the end of a string inside a squashed container.
///
/// Mirrors the string scan in gjson's `parseSquash` and returns the index just
/// past its closing quote, or the input length when there is none.
fn skip_squashed_string(input: &[u8], quote: usize) -> usize {
    let lowest = quote + 1;
    let mut index = lowest;
    while let Some(&byte) = input.get(index) {
        if byte != b'"' {
            index += 1;
            continue;
        }
        if !is_escaped_quote(input, index, lowest) {
            return index + 1;
        }
        index += 1;
    }
    index
}

/// Container end offsets computed in one pass before flattening.
///
/// `squash_json_value` would otherwise rescan every nested container once per
/// enclosing container, so a body nested `d` deep costs `d` times its size to
/// flatten. Only containers that themselves hold another container are stored:
/// their end lets an enclosing scan skip a subtree it already covered, while a
/// leaf container's scan is its own size and happens once.
struct ContainerIndex {
    /// Absolute start offsets, in increasing order.
    starts: Vec<usize>,
    /// End offsets, one past the closing byte, parallel to `starts`.
    ends: Vec<usize>,
}

impl ContainerIndex {
    /// Build an index from `input`, capturing containers up to `max_recursion + 1`.
    fn build(input: &[u8], max_recursion: usize) -> Self {
        /// One container still open while the index is built.
        struct Open {
            /// Absolute offset of the opening bracket.
            start: usize,
            /// Row in the index, allocated when a nested container appears.
            row: Option<usize>,
        }

        // A container one level past the configured depth is still squashed
        // before the walk reports the recursion error, so its end is useful.
        let capture_depth = max_recursion.saturating_add(1);
        let mut index = Self {
            starts: Vec::new(),
            ends: Vec::new(),
        };
        let mut open: Vec<Open> = Vec::new();
        // Opens past `capture_depth`; their closes are absorbed here so the
        // captured stack stays bounded however deep the input nests.
        let mut deeper = 0_usize;
        let mut position = 0_usize;
        while let Some(&byte) = input.get(position) {
            match byte {
                b'"' => position = skip_squashed_string(input, position),
                b'{' | b'(' | b'[' => {
                    if let Some(top) = open.last_mut()
                        && top.row.is_none()
                    {
                        top.row = Some(index.starts.len());
                        index.starts.push(top.start);
                        index.ends.push(0);
                    }
                    if deeper > 0 {
                        deeper += 1;
                    } else if open.len() == capture_depth {
                        deeper = 1;
                    } else {
                        open.push(Open {
                            start: position,
                            row: None,
                        });
                    }
                    position += 1;
                },
                b'}' | b')' | b']' => {
                    if deeper > 0 {
                        deeper -= 1;
                    } else if let Some(container) = open.pop()
                        && let Some(row) = container.row
                        && let Some(end) = index.ends.get_mut(row)
                    {
                        *end = position.saturating_add(1);
                    }
                    position += 1;
                },
                _ => position += 1,
            }
        }
        for container in open {
            if let Some(row) = container.row
                && let Some(end) = index.ends.get_mut(row)
            {
                *end = input.len();
            }
        }
        index
    }

    /// An index with no entries.
    fn empty() -> Self {
        Self {
            starts: Vec::new(),
            ends: Vec::new(),
        }
    }

    /// The end offset of the container starting at `start`, if captured.
    fn end(&self, start: usize) -> Option<usize> {
        let row = self.starts.binary_search(&start).ok()?;
        let end = self.ends.get(row).copied()?;
        (end > start).then_some(end)
    }
}

/// Finds the end of an object or array token, as gjson's `parseSquash` does.
///
/// `base` is the body offset of `input[0]`, so the lookup shares coordinates
/// with [`ContainerIndex`].
fn squash_json_value<'a>(input: &'a [u8], start: usize, base: usize, containers: &ContainerIndex) -> (usize, &'a [u8]) {
    let absolute = base.saturating_add(start);
    if let Some(end) = containers.end(absolute) {
        let end = end.saturating_sub(base);
        if end > start && end <= input.len() {
            return (end, input.get(start..end).unwrap_or_default());
        }
    }
    squash_json_value_scanning(input, start)
}

/// Scans an object or array token not covered by [`ContainerIndex`].
fn squash_json_value_scanning(input: &[u8], start: usize) -> (usize, &[u8]) {
    let mut index = start + 1;
    let mut depth = 1_usize;
    while let Some(&byte) = input.get(index) {
        match byte {
            b'"' => index = skip_squashed_string(input, index),
            b'{' | b'(' | b'[' => {
                depth += 1;
                index += 1;
            },
            b'}' | b')' | b']' => {
                depth -= 1;
                if depth == 0 {
                    let end = index + 1;
                    return (end, input.get(start..end).unwrap_or_default());
                }
                index += 1;
            },
            _ => index += 1,
        }
    }
    (index, input.get(start..).unwrap_or_default())
}

/// Scans a number token the way gjson's `parseNumber` does.
fn scan_number(input: &[u8], start: usize) -> (usize, &[u8]) {
    let mut index = start + 1;
    while let Some(&byte) = input.get(index) {
        if byte <= b' ' || byte == b',' || byte == b']' || byte == b'}' {
            return (index, input.get(start..index).unwrap_or_default());
        }
        index += 1;
    }
    (index, input.get(start..).unwrap_or_default())
}

/// Scans a lowercase literal token the way gjson's `tolit` does.
fn scan_literal(input: &[u8], start: usize) -> (usize, &[u8]) {
    let mut index = start + 1;
    while input.get(index).is_some_and(u8::is_ascii_lowercase) {
        index += 1;
    }
    (index, input.get(start..index).unwrap_or_default())
}

/// Scans the number token gjson's `Parse` reads at the start of the input.
fn scan_root_number(input: &[u8], start: usize) -> (usize, &[u8]) {
    let mut index = start + 1;
    while let Some(&byte) = input.get(index) {
        if byte <= b'-' {
            if byte <= b' ' || byte == b',' {
                return (index, input.get(start..index).unwrap_or_default());
            }
        } else if byte == b']' || byte == b'}' {
            return (index, input.get(start..index).unwrap_or_default());
        }
        index += 1;
    }
    (index, input.get(start..).unwrap_or_default())
}

/// Parses the next value gjson's `parseAny` would read at `start`.
fn parse_any_value<'a>(
    input: &'a [u8],
    start: usize,
    base: usize,
    containers: &ContainerIndex,
) -> Option<(usize, JsonValue<'a>)> {
    let mut index = start;
    while let Some(&byte) = input.get(index) {
        if byte == b'{' || byte == b'[' {
            let (end, raw) = squash_json_value(input, index, base, containers);
            return Some((
                end,
                JsonValue::Json {
                    raw,
                    base: base.saturating_add(index),
                },
            ));
        }
        if byte <= b' ' {
            index += 1;
            continue;
        }
        if byte == b'"' {
            let (end, escaped, ok) = scan_json_string(input, index + 1);
            if !ok {
                return None;
            }
            let content = input.get(index + 1..end.checked_sub(1)?).unwrap_or_default();
            let value = if escaped {
                Cow::Owned(unescape_json_string(content))
            } else {
                Cow::Borrowed(content)
            };
            return Some((end, JsonValue::String(value)));
        }
        match byte {
            b'n' if input.get(index + 1).is_some_and(|next| *next != b'u') => {
                let (end, raw) = scan_number(input, index);
                return Some((end, JsonValue::Number(raw)));
            },
            b'n' | b't' | b'f' => {
                let (end, raw) = scan_literal(input, index);
                let value = match byte {
                    b't' => JsonValue::True(raw),
                    b'f' => JsonValue::False(raw),
                    _ => JsonValue::Null,
                };
                return Some((end, value));
            },
            b'+' | b'-' | b'0'..=b'9' | b'i' | b'I' | b'N' => {
                let (end, raw) = scan_number(input, index);
                return Some((end, JsonValue::Number(raw)));
            },
            _ => index += 1,
        }
    }
    None
}

/// Parses the single value gjson's `Parse` reads at the start of the input.
fn parse_json_root(input: &[u8]) -> Option<JsonValue<'_>> {
    let mut index = 0_usize;
    while let Some(&byte) = input.get(index) {
        match byte {
            b'{' | b'[' => {
                return Some(JsonValue::Json {
                    raw: input.get(index..).unwrap_or_default(),
                    base: index,
                });
            },
            _ if byte <= b' ' => index += 1,
            b'+' | b'-' | b'0'..=b'9' | b'i' | b'I' | b'N' => {
                let (_, raw) = scan_root_number(input, index);
                return Some(JsonValue::Number(raw));
            },
            b'n' => {
                if input.get(index + 1).is_some_and(|next| *next != b'u') {
                    let (_, number) = scan_root_number(input, index);
                    return Some(JsonValue::Number(number));
                }
                return Some(JsonValue::Null);
            },
            b't' => {
                let (_, raw) = scan_literal(input, index);
                return Some(JsonValue::True(raw));
            },
            b'f' => {
                let (_, raw) = scan_literal(input, index);
                return Some(JsonValue::False(raw));
            },
            b'"' => return Some(JsonValue::String(scan_root_string(input, index))),
            _ => return None,
        }
    }
    None
}

/// Reads the string gjson's `Parse` returns for a document that is one string.
fn scan_root_string(input: &[u8], start: usize) -> Cow<'_, [u8]> {
    let mut index = start + 1;
    while let Some(&byte) = input.get(index) {
        if byte > b'\\' {
            index += 1;
            continue;
        }
        if byte == b'"' {
            return Cow::Borrowed(input.get(start + 1..index).unwrap_or_default());
        }
        if byte == b'\\' {
            index += 1;
            while let Some(&escaped) = input.get(index) {
                if escaped > b'\\' {
                    index += 1;
                    continue;
                }
                if escaped == b'"' && !is_escaped_quote(input, index, 1) {
                    return Cow::Owned(unescape_json_string(input.get(start + 1..index).unwrap_or_default()));
                }
                index += 1;
            }
            return Cow::Owned(unescape_json_string(input.get(start + 1..).unwrap_or_default()));
        }
        index += 1;
    }
    Cow::Borrowed(input.get(start + 1..).unwrap_or_default())
}

/// Parses the first four hexadecimal digits as Go's `runeit` does.
fn parse_hex_rune(input: &[u8]) -> i32 {
    let mut value = 0_u32;
    for byte in input.iter().take(4) {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'f' => u32::from(byte - b'a') + 10,
            b'A'..=b'F' => u32::from(byte - b'A') + 10,
            _ => return 0,
        };
        value = value * 16 + digit;
    }
    i32::try_from(value).unwrap_or(0)
}

/// Decodes a UTF-16 surrogate pair the way Go's `utf16.DecodeRune` does.
fn decode_surrogate_pair(first: i32, second: i32) -> i32 {
    if !(0xD800..=0xDBFF).contains(&first) || !(0xDC00..=0xDFFF).contains(&second) {
        return 0xFFFD;
    }
    0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
}

/// Appends one rune's UTF-8 encoding, replacing invalid runes like Go does.
fn push_encoded_rune(output: &mut Vec<u8>, rune: i32) {
    let character = u32::try_from(rune).ok().and_then(char::from_u32).unwrap_or('\u{FFFD}');
    let mut buffer = [0_u8; 4];
    output.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
}

/// Unescapes a JSON string body the way gjson's `unescape` does.
///
/// Like Go, it stops at a control byte or an unknown escape instead of failing.
fn unescape_json_string(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0_usize;
    while let Some(&byte) = input.get(index) {
        if byte < b' ' {
            return output;
        }
        if byte != b'\\' {
            output.push(byte);
            index += 1;
            continue;
        }
        index += 1;
        let Some(&escape) = input.get(index) else {
            return output;
        };
        match escape {
            b'\\' => output.push(b'\\'),
            b'/' => output.push(b'/'),
            b'b' => output.push(0x08),
            b'f' => output.push(0x0C),
            b'n' => output.push(b'\n'),
            b'r' => output.push(b'\r'),
            b't' => output.push(b'\t'),
            b'"' => output.push(b'"'),
            b'u' => {
                if index + 5 > input.len() {
                    return output;
                }
                let mut rune = parse_hex_rune(input.get(index + 1..).unwrap_or_default());
                index += 5;
                if (0xD800..=0xDFFF).contains(&rune)
                    && input.len().saturating_sub(index) >= 6
                    && input.get(index) == Some(&b'\\')
                    && input.get(index + 1) == Some(&b'u')
                {
                    let second = parse_hex_rune(input.get(index + 2..).unwrap_or_default());
                    rune = decode_surrogate_pair(rune, second);
                    index += 6;
                }
                push_encoded_rune(&mut output, rune);
                index -= 1;
            },
            _ => return output,
        }
        index += 1;
    }
    output
}

/// Reports whether the raw input nests containers deeper than `limit`.
///
/// This is gjson's `jsonNestingExceedsLimit`: one pass with a depth counter and
/// no recursion, so it is safe to run on any input before validation.
fn json_nesting_exceeds_limit(input: &[u8], limit: usize) -> bool {
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut depth = 0_i64;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in input {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > limit {
                    return true;
                }
            },
            b'}' | b']' => depth -= 1,
            _ => {},
        }
    }
    false
}

/// Index of the first non-whitespace byte at or after `index`, if any.
fn skip_whitespace(input: &[u8], index: usize) -> Option<usize> {
    let mut index = index;
    while input
        .get(index)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
    {
        index += 1;
    }
    (index < input.len()).then_some(index)
}

/// Reports whether the whole input is valid JSON, as gjson's `Valid` does.
fn valid_json_document(input: &[u8]) -> bool {
    let Some(start) = skip_whitespace(input, 0) else {
        return false;
    };
    scan_valid_value(input, start).is_some_and(|end| skip_whitespace(input, end).is_none())
}

/// Validates one JSON value without recursion, returning where it ends.
fn scan_valid_value(input: &[u8], start: usize) -> Option<usize> {
    let mut containers: Vec<bool> = Vec::new();
    let mut index = start;
    'value: loop {
        index = skip_whitespace(input, index)?;
        match input.get(index).copied()? {
            b'{' => {
                index = skip_whitespace(input, index + 1)?;
                if input.get(index).copied() == Some(b'}') {
                    index += 1;
                } else {
                    index = scan_valid_member_header(input, index)?;
                    containers.push(true);
                    continue 'value;
                }
            },
            b'[' => {
                index = skip_whitespace(input, index + 1)?;
                if input.get(index).copied() == Some(b']') {
                    index += 1;
                } else {
                    containers.push(false);
                    continue 'value;
                }
            },
            b'"' => index = scan_valid_string(input, index + 1)?,
            b'-' | b'0'..=b'9' => index = scan_valid_number(input, index)?,
            b't' => index = scan_valid_literal(input, index, b"true")?,
            b'f' => index = scan_valid_literal(input, index, b"false")?,
            b'n' => index = scan_valid_literal(input, index, b"null")?,
            _ => return None,
        }
        loop {
            let Some(object) = containers.last().copied() else {
                return Some(index);
            };
            index = skip_whitespace(input, index)?;
            match input.get(index).copied()? {
                b',' => {
                    index += 1;
                    if object {
                        index = skip_whitespace(input, index)?;
                        index = scan_valid_member_header(input, index)?;
                    }
                    continue 'value;
                },
                b'}' if object => {
                    index += 1;
                    containers.pop();
                },
                b']' if !object => {
                    index += 1;
                    containers.pop();
                },
                _ => return None,
            }
        }
    }
}

/// Reads an object member's quoted name and colon, as `validobject` does.
fn scan_valid_member_header(input: &[u8], index: usize) -> Option<usize> {
    if input.get(index).copied() != Some(b'"') {
        return None;
    }
    let index = scan_valid_string(input, index + 1)?;
    let index = skip_whitespace(input, index)?;
    if input.get(index).copied() != Some(b':') {
        return None;
    }
    Some(index + 1)
}

/// Validates a string token, as gjson's `validstring` does.
fn scan_valid_string(input: &[u8], start: usize) -> Option<usize> {
    let mut index = start;
    while let Some(&byte) = input.get(index) {
        if byte < b' ' {
            return None;
        }
        if byte == b'\\' {
            index += 1;
            let escape = input.get(index).copied()?;
            match escape {
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {},
                b'u' => {
                    for _ in 0..4 {
                        index += 1;
                        if !input.get(index).is_some_and(u8::is_ascii_hexdigit) {
                            return None;
                        }
                    }
                },
                _ => return None,
            }
        } else if byte == b'"' {
            return Some(index + 1);
        }
        index += 1;
    }
    None
}

/// Validates a number token, as gjson's `validnumber` does.
fn scan_valid_number(input: &[u8], mut index: usize) -> Option<usize> {
    if input.get(index).copied() == Some(b'-') {
        index += 1;
        if !input.get(index).is_some_and(u8::is_ascii_digit) {
            return None;
        }
    }
    if index >= input.len() {
        return None;
    }
    if input.get(index).copied() == Some(b'0') {
        index += 1;
    } else {
        while input.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
    }
    if index >= input.len() {
        return Some(index);
    }
    if input.get(index).copied() == Some(b'.') {
        index += 1;
        if !input.get(index).is_some_and(u8::is_ascii_digit) {
            return None;
        }
        index += 1;
        while input.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
    }
    if index >= input.len() {
        return Some(index);
    }
    if matches!(input.get(index).copied(), Some(b'e' | b'E')) {
        index += 1;
        if matches!(input.get(index).copied(), Some(b'+' | b'-')) {
            index += 1;
        }
        if !input.get(index).is_some_and(u8::is_ascii_digit) {
            return None;
        }
        index += 1;
        while input.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
    }
    Some(index)
}

/// Matches one literal, as `validtrue`, `validfalse` and `validnull` do.
fn scan_valid_literal(input: &[u8], index: usize, literal: &[u8]) -> Option<usize> {
    let end = index.checked_add(literal.len())?;
    (input.get(index..end) == Some(literal)).then_some(end)
}

/// Flattens a JSON body the way Go Coraza's `readJSON` does.
///
/// The walk runs before validation so a valid prefix still populates arguments
/// on a best-effort basis (`internal/bodyprocessors/json.go:141-179`).
pub(super) fn read_json_body(body: &[u8], max_recursion: usize, argument_limit: usize) -> JsonBody {
    let containers = if max_recursion == 0 {
        ContainerIndex::empty()
    } else {
        ContainerIndex::build(body, max_recursion)
    };
    read_json_with_index(body, max_recursion, argument_limit, &containers)
}

/// Flatten with the given container index; an empty index scans every container.
fn read_json_with_index(
    body: &[u8],
    max_recursion: usize,
    argument_limit: usize,
    containers: &ContainerIndex,
) -> JsonBody {
    let byte_budget = body.len().saturating_mul(FLATTEN_BYTES_FACTOR).max(FLATTEN_BYTES_FLOOR);
    let mut flattener = JsonFlattener::new(argument_limit, byte_budget);
    let (truncated, error) = match flattener.flatten(parse_json_root(body), max_recursion, containers) {
        Ok(truncated) => (truncated, json_error_after_walk(body, max_recursion)),
        Err(JsonFlattenError::Recursion) => (
            false,
            Some("max recursion reached while reading json object".to_owned()),
        ),
        Err(JsonFlattenError::Budget) => (
            false,
            Some(format!(
                "flattened form exceeds the {byte_budget} byte budget for a {} byte body",
                body.len()
            )),
        ),
    };
    JsonBody {
        arguments: flattener.values,
        truncated,
        error,
    }
}

/// The error Go Coraza reports after a best-effort walk, if any.
fn json_error_after_walk(body: &[u8], max_recursion: usize) -> Option<String> {
    if json_nesting_exceeds_limit(body, max_recursion) {
        Some("max recursion reached while reading json object".to_owned())
    } else if valid_json_document(body) {
        None
    } else {
        Some("invalid JSON".to_owned())
    }
}

/// Visit flattened arguments in first-discovery order.
///
/// This is the publication order for both request and response arguments.
fn for_each_argument(arguments: &JsonArguments, mut visit: impl FnMut(&[u8], &[u8])) {
    for (key, values) in arguments.iter() {
        for value in values {
            visit(key, value);
        }
    }
}

/// Publish flattened JSON arguments to the request or response collection.
///
/// Keys are stored exactly as the JSON document encoded them, so keys that are
/// not valid UTF-8 stay distinct; values stay byte-exact.
pub(super) fn publish_json_arguments(tx: &mut Transaction, arguments: &JsonArguments, response: bool) {
    for_each_argument(arguments, |key, value| {
        if response {
            tx.response_args.add_bytes(key, value);
        } else {
            tx.args_post.add_bytes(key, value);
            tx.args.add_bytes(key, value);
            tx.update_args_combined_size(key, value);
        }
    });
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "multipart tests use fixed fixtures")]
mod multipart_tests {
    use crate::transaction::Transaction;

    /// Process `body` as `multipart/form-data` and return the transaction.
    fn process(body: &[u8]) -> Transaction {
        let tx = process_with_rules(body, "SecRequestBodyAccess On");
        assert!(tx.interruption().is_none());
        tx
    }

    /// Process `body` as `multipart/form-data` under `rules` and return the transaction.
    fn process_with_rules(body: &[u8], rules: &str) -> Transaction {
        let mut parser = crate::seclang::Parser::new();
        parser.from_string(rules).unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("multipart-byte-names");
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=b");
        tx.process_request_headers();
        tx.process_request_body(body);
        tx
    }

    /// Process `body` under the profile's `ProcessPartial` limit and return the transaction.
    fn process_partial(body: &[u8]) -> Transaction {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecRequestBodyLimit 150\n\
                 SecRequestBodyLimitAction ProcessPartial",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("multipart-partial");
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=a");
        tx.process_request_headers();
        assert_eq!(tx.process_request_body(body), None);
        tx
    }

    #[test]
    fn a_folded_filename_line_publishes_the_file_and_is_detected() {
        // Go's `textproto` folds the leading-space line into the Content-Disposition
        // value, so Go's `NextPart` loop sees `filename="shell.php"` and publishes it
        // in `FILES`. Without folding no part was published and the rule below missed.
        let body = b"--b\r\nContent-Disposition: form-data; name=\"u\";\r\n filename=\"shell.php\"\r\nContent-Type: application/octet-stream\r\n\r\nPAYLOAD\r\n--b--\r\n";
        let tx = process_with_rules(
            body,
            "SecRequestBodyAccess On\n\
             SecRule FILES \"@rx shell\" \"id:1,phase:2,deny,status:403\"",
        );

        assert_eq!(tx.reqbody_error.get(), "0");
        assert_eq!(tx.multipart_strict_error.get(), "0");
        assert_eq!(tx.files.first(""), Some(&b"shell.php"[..]));
        assert_eq!(tx.files_names.first(""), Some(&b"u"[..]));
        assert_eq!(tx.multipart_filename.first(b"u"), Some(&b"shell.php"[..]));
        assert_eq!(tx.args_post.first(b"u"), None);
        assert_eq!(tx.interruption().map(|interruption| interruption.status), Some(403));
    }

    #[test]
    fn a_bare_lf_header_end_does_not_swallow_a_crlf_blank_line_in_the_body() {
        // The headers end with `\n\n` while the body holds `\r\n\r\n`. Picking the
        // later separator dropped everything before it from the field value and the
        // saved upload.
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"field\"\n\
\n\
ATTACK\r\n\r\nTAIL\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"upload\"; filename=\"x.txt\"\n\
\n\
ATTACK\r\n\r\nTAIL\r\n\
--b--\r\n";
        let tx = process(body);

        assert_eq!(tx.args_post.first(b"field"), Some(&b"ATTACK\r\n\r\nTAIL"[..]));
        assert_eq!(tx.reqbody_error.get(), "0");
        assert_eq!(tx.files_names.first(""), Some(&b"upload"[..]));
        let path = tx
            .get_variable(crate::types::RuleVariable::FilesTmpNames, Some(""))
            .unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"ATTACK\r\n\r\nTAIL");
    }

    #[test]
    fn a_mixed_delimiter_ending_is_a_body_error() {
        // Go fixes the line ending at the first delimiter, so a later delimiter with the
        // other one fails after the part before it was published
        // (`mime/multipart/multipart.go`, `isBoundaryDelimiterLine`, go1.27.3).
        let body = b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\none\r\n--b\nContent-Disposition: form-data; name=\"b\"\r\n\r\ntwo\r\n--b--\r\n";
        let tx = process(body);

        assert_eq!(tx.args_post.first(b"a"), Some(&b"one"[..]));
        assert_eq!(tx.args_post.first(b"b"), None);
        assert_eq!(tx.reqbody_error.get(), "1");
        assert_eq!(tx.multipart_strict_error.get(), "1");
        assert_eq!(
            tx.reqbody_processor_error_msg.get(),
            r#"multipart: expecting a new Part; got line "--b\n""#
        );
    }

    #[test]
    fn a_backslashed_plain_filename_reaches_files_after_coraza_unquoting() {
        // Go Coraza's `unquoteIfQuoted` drops every backslash in the plain `filename`
        // reading, so the alternate filename in `FILES` is `C:devx.txt`
        // (`internal/bodyprocessors/multipart.go`, v3.8.1).
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"f\"; filename=\"C:\\dev\\x.txt\"; filename*=utf-8''a.txt\r\n\
\r\n\
DATA\r\n\
--b--\r\n";
        let tx = process(body);

        let files: Vec<&[u8]> = tx.files.values("").collect();
        assert_eq!(files, [b"a.txt".as_slice(), b"C:devx.txt"]);
        let filenames: Vec<&[u8]> = tx.multipart_filename.values(b"f").collect();
        assert_eq!(filenames, [b"a.txt".as_slice(), b"C:devx.txt"]);
        assert_eq!(tx.files_names.first(""), Some(&b"f"[..]));
    }

    #[test]
    fn a_part_before_an_invalid_part_is_published_before_the_body_error() {
        // Go publishes each part as `NextPart` returns it, so the error on the second
        // part leaves the first one in `ARGS_POST` (`internal/bodyprocessors/multipart.go:52-70`).
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"ok\"\r\n\
\r\n\
GOOD\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"bad\"\r\n\
Bad Header\r\n\
\r\n\
P\r\n\
--b--\r\n";
        let tx = process(body);

        assert_eq!(tx.args_post.first(b"ok"), Some(&b"GOOD"[..]));
        assert_eq!(tx.args_post.first(b"bad"), None);
        assert_eq!(tx.reqbody_error.get(), "1");
        assert_eq!(tx.multipart_strict_error.get(), "1");
        assert_eq!(
            tx.reqbody_processor_error_msg.get(),
            r#"malformed MIME header: missing colon: "Bad Header""#
        );
    }

    #[test]
    fn a_repeated_filename_parameter_has_no_name_and_fails_strict_validation() {
        // Exact part from Go's `multipart_filename_star.yaml` profile.
        let body = b"\n----0000\n\
Content-Disposition: form-data; name=\"upload\"; filename=\"safe.jpg\"; filename=\"shell.php\"\n\
\n\
file content\n\
----0000--\n";
        let mut parser = crate::seclang::Parser::new();
        parser.from_string("SecRequestBodyAccess On").unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("multipart-repeated-filename");
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=--0000");
        tx.process_request_headers();
        assert_eq!(tx.process_request_body(body), None);

        assert_eq!(tx.multipart_strict_error.get(), "1");
        assert_eq!(tx.multipart_duplicate_part_header.get(), "1");
        assert_eq!(tx.reqbody_error.get(), "0");
        assert_eq!(tx.files.value_count(), 0);
        assert_eq!(tx.multipart_filename.value_count(), 0);
        // A rejected Content-Disposition leaves no usable name, so Go's `FormName`
        // returns "" and the field lands in `ARGS_POST[""]`
        // (`mime/multipart/multipart.go:76-111`).
        assert_eq!(tx.args_post.first(b"upload"), None);
        assert_eq!(tx.args_post.first(b""), Some(&b"file content"[..]));
    }

    #[test]
    fn an_empty_filename_is_a_field_and_a_non_empty_filename_star_promotes_the_part() {
        // What a browser sends for an empty file input: Go promotes `altFilename`, and a
        // part whose effective filename is still empty is a field
        // (`internal/bodyprocessors/multipart.go:106-115`, v3.8.1).
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"f\"; filename=\"\"\r\n\
\r\n\
DATA\r\n\
--b--\r\n";
        let tx = process(body);
        assert_eq!(tx.args_post.first(b"f"), Some(&b"DATA"[..]));
        assert_eq!(tx.files.value_count(), 0);
        assert_eq!(tx.files_names.value_count(), 0);
        assert_eq!(tx.files_tmp_names.value_count(), 0);
        assert_eq!(tx.multipart_filename.value_count(), 0);
        assert_eq!(tx.reqbody_error.get(), "0");
        assert_eq!(tx.multipart_strict_error.get(), "0");

        // A non-empty `filename*` is the effective filename, so the part is a file.
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"f\"; filename=\"\"; filename*=utf-8''shell.php\r\n\
\r\n\
DATA\r\n\
--b--\r\n";
        let tx = process(body);
        assert_eq!(tx.args_post.value_count(), 0);
        assert_eq!(tx.files.first(""), Some(&b"shell.php"[..]));
        assert_eq!(tx.files_names.first(""), Some(&b"f"[..]));
        assert_eq!(tx.multipart_filename.first(b"f"), Some(&b"shell.php"[..]));
        assert_eq!(tx.multipart_filename_charset.first(b"f"), Some(&b"utf-8"[..]));

        // A `filename*` that decodes to nothing keeps the part a field, and still
        // publishes the charset and language Go records for it.
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"f\"; filename=\"\"; filename*=utf-8''\r\n\
\r\n\
DATA\r\n\
--b--\r\n";
        let tx = process(body);
        assert_eq!(tx.args_post.first(b"f"), Some(&b"DATA"[..]));
        assert_eq!(tx.files.value_count(), 0);
        assert_eq!(tx.multipart_filename.value_count(), 0);
        assert_eq!(tx.multipart_filename_charset.first(b"f"), Some(&b"utf-8"[..]));
    }

    #[test]
    fn only_form_data_keeps_the_part_name() {
        // Go's `Part.FormName` returns the name only for a `form-data` disposition
        // (`mime/multipart/multipart.go:76-86`). `originFileName` does not check the
        // media type, so the filename still reaches `FILES` under the empty name.
        let body = b"--b\r\n\
Content-Disposition: attachment; name=\"f\"; filename=\"x.txt\"\r\n\
\r\n\
DATA\r\n\
--b--\r\n";
        let tx = process(body);
        assert_eq!(tx.args_post.value_count(), 0);
        assert_eq!(tx.files.first(""), Some(&b"x.txt"[..]));
        assert_eq!(tx.files_names.first(""), Some(&b""[..]));
        assert_eq!(tx.multipart_name.first(b""), Some(&b""[..]));
        assert_eq!(tx.multipart_filename.first(b""), Some(&b"x.txt"[..]));

        // Without a filename it is an anonymous field.
        let body = b"--b\r\nContent-Disposition: attachment; name=\"f\"\r\n\r\nDATA\r\n--b--\r\n";
        let tx = process(body);
        assert_eq!(tx.args_post.first(b""), Some(&b"DATA"[..]));
        assert_eq!(tx.args_post.first(b"f"), None);

        // The media type is lowercased first, as Go does.
        let body = b"--b\r\nContent-Disposition: Form-Data; name=\"f\"\r\n\r\nDATA\r\n--b--\r\n";
        let tx = process(body);
        assert_eq!(tx.args_post.first(b"f"), Some(&b"DATA"[..]));
    }

    #[test]
    fn a_content_disposition_name_with_a_space_is_an_anonymous_field() {
        // Go's header map keeps this name raw (`noCanon`), so `Header.Get` finds no
        // Content-Disposition and the part is still published as an anonymous field
        // (`internal/bodyprocessors/multipart.go:182`, v3.8.1).
        let body = b"--b\r\n\
Content-Disposition : form-data; name=\"f\"; filename=\"x.txt\"\r\n\
\r\n\
DATA\r\n\
--b--\r\n";
        let tx = process(body);
        assert_eq!(tx.args_post.first(b""), Some(&b"DATA"[..]));
        assert_eq!(tx.files.value_count(), 0);
        assert_eq!(tx.reqbody_error.get(), "0");
        assert_eq!(tx.multipart_strict_error.get(), "0");
    }

    #[test]
    fn non_canonical_part_header_names_are_distinct_keys() {
        // A header name with a space is kept raw (`canonicalMIMEHeaderKey`'s `noCanon`
        // path), so these two names differ only in case are still distinct keys and
        // neither repeats the other.
        let body = b"--b\r\n\
Content- Disposition: one\r\n\
content- disposition: two\r\n\
Content-Disposition: form-data; name=\"f\"\r\n\
\r\n\
DATA\r\n\
--b--\r\n";
        let tx = process(body);
        assert_eq!(tx.args_post.first(b"f"), Some(&b"DATA"[..]));
        assert_eq!(tx.multipart_strict_error.get(), "0");
        assert_eq!(tx.multipart_duplicate_part_header.get(), "0");
        let headers: Vec<&[u8]> = tx.multipart_part_headers.values(b"f").collect();
        assert!(
            headers.contains(&b"Content- Disposition: one".as_slice()),
            "{headers:?}"
        );
        assert!(
            headers.contains(&b"content- disposition: two".as_slice()),
            "{headers:?}"
        );

        // A repeated canonical name is still a duplicate.
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"f\"\r\n\
Content-Disposition: form-data; name=\"f\"\r\n\
\r\n\
DATA\r\n\
--b--\r\n";
        let tx = process(body);
        assert_eq!(tx.multipart_strict_error.get(), "1");
        assert_eq!(tx.multipart_duplicate_part_header.get(), "1");
    }

    #[test]
    fn an_inbound_data_error_alone_does_not_make_a_body_partial() {
        // INBOUND_DATA_ERROR also reports ingest and replay I/O failures, which do not
        // cut the body, so only the limit counters decide whether a body is partial.
        let body = b"--b\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nv";
        let mut parser = crate::seclang::Parser::new();
        parser.from_string("SecRequestBodyAccess On").unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("multipart-io-error");
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=b");
        tx.process_request_headers();
        tx.inbound_data_error.set("1");

        tx.inspect_request_body(body, false, false);
        assert_eq!(tx.reqbody_error.get(), "1");
        assert_eq!(tx.multipart_strict_error.get(), "1");

        // The same body read as a partial one keeps the part and no error.
        let mut tx = waf.new_transaction_with_id("multipart-partial");
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=b");
        tx.process_request_headers();
        tx.inspect_request_body(body, true, true);
        assert_eq!(tx.reqbody_error.get(), "0");
        assert_eq!(tx.multipart_strict_error.get(), "0");
        assert_eq!(tx.args_post.first(b"q"), Some(&b"v"[..]));
    }

    #[test]
    fn a_body_cut_by_process_partial_keeps_inspecting_parts() {
        let file_body = b"--a\n\
Content-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\n\
Content-Type: text/plain\n\
\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
--a--\n";
        let tx = process_partial(file_body);

        assert_eq!(tx.inbound_data_error.get(), "1");
        assert_eq!(tx.reqbody_error.get(), "0");
        assert_eq!(tx.multipart_strict_error.get(), "0");
        assert_eq!(tx.files.first(""), Some(&b"x.txt"[..]));
        assert_eq!(tx.files_names.first(""), Some(&b"f"[..]));

        let field_body = b"--a\n\
Content-Disposition: form-data; name=\"t\"\n\
\n\
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n\
--a--\n";
        let tx = process_partial(field_body);

        assert_eq!(tx.reqbody_error.get(), "0");
        assert_eq!(tx.multipart_strict_error.get(), "0");
        assert_eq!(tx.args_post.first(b"t"), Some(b"B".repeat(104).as_slice()));
    }

    #[test]
    fn field_names_that_are_not_utf8_are_distinct_keys() {
        // Go Coraza v3.8.1 `p.FormName()` returns the raw parameter bytes, so
        // these are two `ARGS_POST` keys, not one.
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"\xff\"\r\n\
\r\n\
one\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"\xfe\"\r\n\
\r\n\
two\r\n\
--b--";
        let tx = process(body);

        assert_eq!(tx.args_post.len(), 2);
        assert_eq!(tx.args_post.first(b"\xff"), Some(&b"one"[..]));
        assert_eq!(tx.args_post.first(b"\xfe"), Some(&b"two"[..]));
        // The lossy text view is not a key: it matches neither byte name.
        assert!(tx.args_post.first("\u{fffd}").is_none());
        assert_eq!(tx.multipart_name.first(b"\xff"), Some(&b"\xff"[..]));
        assert_eq!(tx.multipart_name.first(b"\xfe"), Some(&b"\xfe"[..]));
    }

    #[test]
    fn rfc_2231_values_reach_arguments_and_files() {
        let body = b"--b\r\n\
Content-Disposition: form-data; name*0=long; name*1=name\r\n\
\r\n\
one\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"plain\"; name*=utf-8''extended\r\n\
\r\n\
two\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"upload\"; filename*=utf-8''%FF%2Etxt\r\n\
\r\n\
file\r\n\
--b--";
        let tx = process(body);

        assert_eq!(tx.args_post.first(b"longname"), Some(&b"one"[..]));
        assert_eq!(tx.args_post.first(b"extended"), Some(&b"two"[..]));
        assert_eq!(tx.args_post.first(b"plain"), None);
        assert_eq!(tx.files.first(""), Some(&b"\xff.txt"[..]));
        assert_eq!(tx.multipart_filename.first(b"upload"), Some(&b"\xff.txt"[..]));
        assert_eq!(tx.multipart_filename_charset.first(b"upload"), Some(&b"utf-8"[..]));
    }

    #[test]
    fn file_part_names_that_are_not_utf8_are_distinct_keys() {
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"\xff\"; filename=\"a.txt\"\r\n\
\r\n\
one\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"\xfe\"; filename=\"b.txt\"\r\n\
\r\n\
two\r\n\
--b--";
        let tx = process(body);

        assert_eq!(tx.files_names.value_count(), 2);
        assert_eq!(tx.files_names.first(""), Some(&b"\xff"[..]));
        assert_eq!(tx.files_names.values("").nth(1), Some(&b"\xfe"[..]));
        assert_eq!(tx.multipart_name.first(b"\xff"), Some(&b"\xff"[..]));
        assert_eq!(tx.multipart_name.first(b"\xfe"), Some(&b"\xfe"[..]));
        assert_eq!(tx.multipart_filename.first(b"\xff"), Some(&b"a.txt"[..]));
        assert_eq!(tx.multipart_filename.first(b"\xfe"), Some(&b"b.txt"[..]));
    }

    #[test]
    fn part_header_values_that_are_not_utf8_are_distinct_bytes() {
        // Go Coraza v3.8.1 `internal/bodyprocessors/multipart.go:70` formats the raw
        // header value, so these stay two distinct `MULTIPART_PART_HEADERS` values
        // instead of collapsing into one U+FFFD text view.
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"field\"\r\n\
X: \xff\r\n\
\r\n\
one\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"field\"\r\n\
X: \xfe\r\n\
\r\n\
two\r\n\
--b--";
        let tx = process(body);

        let x_values: Vec<&[u8]> = tx
            .multipart_part_headers
            .values(b"field")
            .filter(|value| value.starts_with(b"X: "))
            .collect();
        assert_eq!(x_values, [b"X: \xff".as_slice(), b"X: \xfe".as_slice()]);
    }

    #[test]
    fn part_header_names_with_a_space_reach_part_headers() {
        // Go's textproto keeps a space inside a header name, so CRS 922130 sees the raw
        // `Content- Disposition:` part header of test 922130-4. A trailing space is kept
        // raw too (`canonicalMIMEHeaderKey`'s `noCanon` path, go.dev/issue/34540).
        let body = b"--b\r\n\
Content- Disposition: form-data; name=\"file\"; filename=\"1.php\"\r\n\
Content-Disposition: form-data; name=\"post\"\r\n\
Content-Type : text/plain\r\n\
\r\n\
one\r\n\
--b--";
        let tx = process(body);

        let headers: Vec<&[u8]> = tx.multipart_part_headers.values(b"post").collect();
        assert_eq!(
            headers,
            [
                b"Content- Disposition: form-data; name=\"file\"; filename=\"1.php\"".as_slice(),
                b"Content-Disposition: form-data; name=\"post\"".as_slice(),
                b"Content-Type : text/plain".as_slice(),
            ]
        );
        // Distinct header names, as Go's header map, so no duplicate-header flag.
        assert_eq!(tx.multipart_strict_error.get_bytes(), b"0");
    }

    #[test]
    fn part_header_values_keep_their_exact_bytes() {
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"field\"\r\n\
x-request: value\r\n\
\r\n\
one\r\n\
--b--";
        let tx = process(body);

        let x_request: Vec<&[u8]> = tx
            .multipart_part_headers
            .values(b"field")
            .filter(|value| value.starts_with(b"X-Request: "))
            .collect();
        assert_eq!(x_request, [b"X-Request: value".as_slice()]);
    }

    #[test]
    fn utf8_field_names_and_duplicates_are_unchanged() {
        let body = "--b\r\n\
Content-Disposition: form-data; name=\"na\u{ef}me\"\r\n\
\r\n\
one\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"na\u{ef}me\"\r\n\
\r\n\
two\r\n\
--b--"
            .as_bytes();
        let tx = process(body);

        assert_eq!(tx.args_post.len(), 1);
        assert_eq!(
            tx.args_post.values("na\u{ef}me").collect::<Vec<_>>(),
            [b"one".as_slice(), b"two".as_slice()]
        );
    }
}

#[cfg(test)]
mod json_tests {
    use super::{ContainerIndex, JsonBody, json_nesting_exceeds_limit, read_json_body, read_json_with_index};

    /// Tokens for the deterministic malformed-document generator.
    const TOKENS: [&[u8]; 16] = [
        b"{", b"}", b"[", b"]", b",", b":", b"\"a\"", b"\"[{\"", b"\"x\"", b"1", b"-2", b"null", b"true", b" ", b"\\",
        b"\"",
    ];

    /// Flatten with Go Coraza's test limits: no argument cap, generous depth.
    fn flatten(body: &[u8]) -> JsonBody {
        read_json_body(body, 10_000, 0)
    }

    /// Values stored under `key`, in discovery order.
    fn values(parsed: &JsonBody, key: &str) -> Vec<Vec<u8>> {
        parsed
            .arguments
            .get(key.as_bytes())
            .map(<[Vec<u8>]>::to_vec)
            .unwrap_or_default()
    }

    /// Text form of [`values`], for readable assertions.
    fn text(parsed: &JsonBody, key: &str) -> Vec<String> {
        values(parsed, key)
            .iter()
            .map(|value| String::from_utf8_lossy(value).into_owned())
            .collect()
    }

    /// Total flattened values, counting collisions separately.
    fn total_values(parsed: &JsonBody) -> usize {
        parsed.arguments.iter().map(|(_, values)| values.len()).sum()
    }

    /// Ordered paths and values, for equivalence comparisons.
    type Snapshot = Vec<(Vec<u8>, Vec<Vec<u8>>)>;

    /// Ordered paths and values, for equivalence comparisons.
    fn snapshot(parsed: &JsonBody) -> Snapshot {
        parsed
            .arguments
            .iter()
            .map(|(key, values)| (key.to_vec(), values.to_vec()))
            .collect()
    }

    /// Paths in publication order.
    fn published_keys(parsed: &JsonBody) -> Vec<String> {
        let mut keys = Vec::new();
        super::for_each_argument(&parsed.arguments, |key, _| {
            let key = String::from_utf8_lossy(key).into_owned();
            if keys.last() != Some(&key) {
                keys.push(key);
            }
        });
        keys
    }

    fn nested_objects(depth: usize) -> Vec<u8> {
        let mut body = b"{\"a\":".repeat(depth);
        body.push(b'1');
        body.extend(std::iter::repeat_n(b'}', depth));
        body
    }

    #[test]
    fn duplicate_members_and_dotted_keys_append_values() {
        let parsed = flatten(br#"{"x":{"a":"attack"},"x":{"b":"safe"}}"#);
        assert_eq!(parsed.error, None);
        assert_eq!(text(&parsed, "json.x.a"), ["attack"]);
        assert_eq!(text(&parsed, "json.x.b"), ["safe"]);

        // A nested path and a literal dotted name collide; both values survive in order.
        let parsed = flatten(br#"{"account":{"role":"ATTACK"},"account.role":"SAFE"}"#);
        assert_eq!(parsed.error, None);
        assert_eq!(text(&parsed, "json.account.role"), ["ATTACK", "SAFE"]);

        let parsed = flatten(br#"{"a":1,"a":2,"a":3}"#);
        assert_eq!(text(&parsed, "json.a"), ["1", "2", "3"]);
    }

    #[test]
    fn argument_publication_order_is_first_discovery_order() {
        let body = br#"{"b":1,"a":2,"c":{"d":3},"b":4,"c":{"d":5}}"#;
        let parsed = flatten(body);
        assert_eq!(published_keys(&parsed), ["json.b", "json.a", "json.c.d"]);
        assert_eq!(text(&parsed, "json.b"), ["1", "4"]);
        assert_eq!(text(&parsed, "json.c.d"), ["3", "5"]);

        // Publication order must not depend on map iteration order.
        let again = flatten(body);
        assert_eq!(published_keys(&again), published_keys(&parsed));
    }

    #[test]
    fn container_index_matches_scanning_squash() {
        let mut bodies: Vec<Vec<u8>> = vec![
            br#"{"a":1,"b":[2,3],"c":{"d":"e"}}"#.to_vec(),
            br#"[[{"a":[1,2]}],{"b":{}}]"#.to_vec(),
            br#"{"a":"[[[[]]]]","b":"{\"x\":[}"}"#.to_vec(),
            br#"{"a":[1,2,3}"#.to_vec(),
            b"[{]}]]".to_vec(),
            b"}[[[]]]{".to_vec(),
            br#"{"a":{"b":{"c":[1,{"d":[]}]}}}"#.to_vec(),
            br#"{"account":{"role":"x"},"account.role":"y","account":{"role":"z"}}"#.to_vec(),
            b"[]".repeat(64),
            b"{}[[".repeat(32),
        ];
        let mut deep = vec![b'['; 1023];
        deep.push(b'1');
        deep.extend(std::iter::repeat_n(b']', 1023));
        bodies.push(deep);

        // Token soup exercises unbalanced, mismatched and string-embedded brackets.
        let mut state = 0x1234_5678_9ABC_DEF0_u64;
        for _ in 0..300 {
            let mut body = Vec::new();
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let count = usize::try_from(state >> 60).unwrap_or(0) + 1;
            for _ in 0..count {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let token = usize::try_from(state >> 40).unwrap_or(0) % TOKENS.len();
                if let Some(bytes) = TOKENS.get(token) {
                    body.extend_from_slice(bytes);
                }
            }
            bodies.push(body);
        }

        for body in bodies {
            for (depth, limit) in [(1024, 1000), (3, 5), (0, 0)] {
                let indexed = read_json_body(&body, depth, limit);
                let scanned = read_json_with_index(&body, depth, limit, &ContainerIndex::empty());
                assert_eq!(snapshot(&indexed), snapshot(&scanned));
                assert_eq!(indexed.truncated, scanned.truncated);
                assert_eq!(indexed.error, scanned.error);
            }
        }
    }

    #[test]
    fn numeric_tokens_keep_their_raw_spelling() {
        let parsed =
            flatten(br#"{"big":123456789012345678901234567890,"exp":1e2,"neg":-0,"frac":1.500,"sci":-2.5E+10}"#);
        assert_eq!(parsed.error, None);
        assert_eq!(text(&parsed, "json.big"), ["123456789012345678901234567890"]);
        assert_eq!(text(&parsed, "json.exp"), ["1e2"]);
        assert_eq!(text(&parsed, "json.neg"), ["-0"]);
        assert_eq!(text(&parsed, "json.frac"), ["1.500"]);
        assert_eq!(text(&parsed, "json.sci"), ["-2.5E+10"]);
    }

    #[test]
    fn best_effort_prefix_is_kept_before_the_error() {
        for (body, expected) in [
            (br#"{"a": 1} trailing garbage"#.as_slice(), ("json.a", "1")),
            (br#"{"a":1,"b":"#.as_slice(), ("json.a", "1")),
            (br#"{"a":[1,2"#.as_slice(), ("json.a", "2")),
        ] {
            let parsed = flatten(body);
            assert_eq!(parsed.error.as_deref(), Some("invalid JSON"));
            assert_eq!(text(&parsed, expected.0), [expected.1]);
        }

        // Truncated array members are published before the parser error.
        let parsed = flatten(br#"{"a":[1,2"#);
        assert_eq!(text(&parsed, "json.a.0"), ["1"]);
        assert_eq!(text(&parsed, "json.a.1"), ["2"]);
    }

    #[test]
    fn argument_and_array_length_caps_are_counted_separately() {
        const LIMIT: usize = 5;
        let exact = b"[1,1,1,1,1]".to_vec();
        let longer = b"[1,1,1,1,1,1]".to_vec();
        let mut padded = Vec::new();
        padded.extend_from_slice(b"{");
        for index in 0..LIMIT {
            padded.extend_from_slice(format!(r#""p{index}":[{{}}],"#).as_bytes());
        }
        padded.extend_from_slice(br#""items":[1,2,3]}"#);

        let cases: [(&[u8], bool, usize); 4] = [
            (b"[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]", true, LIMIT + 1),
            (&exact, false, LIMIT + 1),
            (&longer, true, LIMIT),
            (&padded, true, LIMIT + 3),
        ];
        for (body, truncated, expected_values) in cases {
            let parsed = read_json_body(body, 10_000, LIMIT);
            assert_eq!(parsed.error, None);
            assert_eq!(parsed.truncated, truncated);
            assert_eq!(total_values(&parsed), expected_values);
        }
    }

    #[test]
    fn byte_budget_stops_the_flattened_form() {
        const LIMIT: usize = 1000;
        let mut long_paths = Vec::new();
        for index in 0..8 {
            long_paths.extend_from_slice(format!(r#"{{"{}{index}":"#, "p".repeat(200)).as_bytes());
        }
        long_paths.push(b'{');
        for index in 0..999 {
            if index > 0 {
                long_paths.push(b',');
            }
            long_paths.extend_from_slice(format!(r#""leaf{index}":"{}""#, "v".repeat(20)).as_bytes());
        }
        long_paths.push(b'}');
        long_paths.extend(std::iter::repeat_n(b'}', 8));

        let mut long_key = b"{\"".to_vec();
        long_key.extend(std::iter::repeat_n(b'a', 20_000));
        long_key.extend_from_slice(br#"":"#);
        long_key.extend(std::iter::repeat_n(b'[', 200));
        long_key.extend(std::iter::repeat_n(b']', 200));
        long_key.push(b'}');

        for body in [long_paths, long_key] {
            let parsed = read_json_body(&body, 10_000, LIMIT);
            let message = parsed.error.as_deref().unwrap_or_default();
            assert!(message.contains("flattened form exceeds"), "{message}");
            assert!(!parsed.truncated);
            assert!(!parsed.arguments.is_empty());
            assert!(parsed.arguments.len() < LIMIT);
            let budget = (body.len() * 8).max(4096);
            let stored: usize = parsed
                .arguments
                .iter()
                .map(|(key, values)| key.len() + values.iter().map(Vec::len).sum::<usize>())
                .sum();
            assert!(stored <= budget);
        }

        // An ordinary API payload stays well inside the budget.
        let mut ordinary = br#"{"users":["#.to_vec();
        for index in 0..200 {
            if index > 0 {
                ordinary.push(b',');
            }
            ordinary.extend_from_slice(
                format!(r#"{{"id":{index},"name":"user{index}","email":"u{index}@example.com","active":true}}"#)
                    .as_bytes(),
            );
        }
        ordinary.extend_from_slice(b"]}");
        let parsed = read_json_body(&ordinary, 10_000, LIMIT);
        assert_eq!(parsed.error, None);
        assert!(!parsed.truncated);
    }

    #[test]
    fn depth_uses_the_configured_limit_not_serde_default() {
        // 300 container levels exceed serde_json's default recursion limit of 128.
        let body = nested_objects(300);
        let parsed = read_json_body(&body, 300, 0);
        assert_eq!(parsed.error, None);
        assert_eq!(text(&parsed, &format!("json.{}a", "a.".repeat(299))), ["1"]);

        let parsed = read_json_body(&body, 299, 0);
        assert_eq!(
            parsed.error.as_deref(),
            Some("max recursion reached while reading json object")
        );

        // 5,000 levels are flattened iteratively without exhausting the stack.
        let parsed = read_json_body(&nested_objects(5_000), 5_000, 0);
        assert_eq!(parsed.error, None);
    }

    #[test]
    fn deep_bomb_stops_at_the_recursion_limit() {
        let mut body = b"{\"a\":".repeat(15_000);
        body.push(b'1');
        body.extend(std::iter::repeat_n(b'}', 15_000));
        let parsed = read_json_body(&body, 10_000, 0);
        assert_eq!(
            parsed.error.as_deref(),
            Some("max recursion reached while reading json object")
        );
        assert!(parsed.arguments.is_empty());
    }

    #[test]
    fn nesting_check_ignores_string_contents() {
        assert!(!json_nesting_exceeds_limit(br#"{"a":"[[[[[[[[[[[["}"#, 10));
        assert!(!json_nesting_exceeds_limit(br#"{"a":"\"[[[[[[[[[[["}"#, 10));
        assert!(json_nesting_exceeds_limit(&b"[".repeat(11), 10));
        assert!(!json_nesting_exceeds_limit(&b"[".repeat(10), 10));
        assert!(json_nesting_exceeds_limit(&b"[".repeat(11), 10));
        // Unbalanced closers still move the signed depth, as in Go.
        assert!(!json_nesting_exceeds_limit(b"}[[[", 2));
    }

    #[test]
    fn invalid_utf8_bytes_survive_in_keys_and_values() {
        let parsed = flatten(b"{\"k\xff\":\"v\xfe\"}");
        assert_eq!(parsed.error, None);
        assert_eq!(
            parsed.arguments.get(b"json.k\xff".as_slice()),
            Some([b"v\xfe".to_vec()].as_slice())
        );
    }

    #[test]
    fn empty_containers_and_scalar_roots_match_gjson() {
        let parsed = flatten(b"{}");
        assert_eq!(parsed.error, None);
        assert!(parsed.arguments.is_empty());

        let parsed = flatten(br#"{"a": {}, "b": []}"#);
        assert_eq!(parsed.error, None);
        assert!(parsed.arguments.is_empty());

        let parsed = flatten(b"1");
        assert_eq!(parsed.error, None);
        assert_eq!(text(&parsed, "json.0"), ["1"]);
        assert_eq!(text(&parsed, "json"), ["1"]);

        let parsed = flatten(br#""s""#);
        assert_eq!(text(&parsed, "json.0"), ["s"]);

        let parsed = flatten(b"null");
        assert_eq!(parsed.error, None);
        assert_eq!(text(&parsed, "json.0"), [""]);
    }

    #[test]
    fn malformed_traversal_matches_gjson_foreach() {
        // gjson's ForEach advances one byte past each value, so malformed input
        // is traversed exactly this way; keep the differential pins.
        let parsed = flatten(br#"["x","y"{],"account.role":"z"}"#);
        assert_eq!(parsed.error.as_deref(), Some("invalid JSON"));
        assert_eq!(text(&parsed, "json.0"), ["x"]);
        assert_eq!(text(&parsed, "json.1"), ["y"]);
        assert_eq!(text(&parsed, "json.2"), ["account.role"]);
        assert_eq!(text(&parsed, "json.3"), ["z"]);
        assert_eq!(text(&parsed, "json"), ["4"]);

        let parsed = flatten(br#"[1,2,"3]},{"+":null}]"#);
        assert_eq!(text(&parsed, "json.2"), ["3]},{"]);
        assert_eq!(text(&parsed, "json"), ["3"]);

        let parsed = flatten(br#"{"a":[1,2,3],}{"b":null}"#);
        assert_eq!(text(&parsed, "json.a.2"), ["3"]);
        assert_eq!(text(&parsed, "json.b"), [""]);

        let mut body = b"{\"a\":\"".to_vec();
        body.extend(std::iter::repeat_n(b'\\', 10));
        body.extend_from_slice(b"\"\",\"b\":\"x");
        body.extend(std::iter::repeat_n(b'\\', 7));
        body.extend_from_slice(b"\"y\"}");
        let parsed = flatten(&body);
        assert_eq!(values(&parsed, "json.a"), vec![vec![b'\\'; 5]]);
        let mut expected_b = b"x".to_vec();
        expected_b.extend(std::iter::repeat_n(b'\\', 3));
        expected_b.extend_from_slice(b"\"y");
        assert_eq!(values(&parsed, "json.b"), vec![expected_b]);
    }

    #[test]
    fn escaped_unicode_matches_go_unescaping() {
        let parsed =
            flatten(b"{\"a\":\"\\u0041\\u00e9\",\"b\":\"\\ud83d\\ude00\",\"c\":\"\\ud83d\",\"d\":\"\\ud83d\\u0041\"}");
        assert_eq!(parsed.error, None);
        assert_eq!(text(&parsed, "json.a"), ["Aé"]);
        assert_eq!(text(&parsed, "json.b"), ["😀"]);
        assert_eq!(text(&parsed, "json.c"), ["\u{fffd}"]);
        assert_eq!(text(&parsed, "json.d"), ["\u{fffd}"]);
    }
}
