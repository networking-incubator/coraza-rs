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
    collections::LinkedList,
    io::Write as _,
    path::{Path, PathBuf},
};

use indexmap::IndexMap;

use super::{Interruption, Transaction, body_buffer::BodyBuffer, variables::BodyProcessor};
use crate::{
    body_processors::{
        BodyDirection, BodyProcessor as CustomBodyProcessor, BodyProcessorFactory, BodyProcessorFile,
        BodyProcessorOptions, BodyProcessorOutput, budget,
        budget::MemoryBudget,
        multipart::{self, FailureCause},
        truncate_custom_body_text, xml,
    },
    collection::{
        ALLOCATION_OVERHEAD_BYTES, Growth, Map, allocation_bytes, fold_scratch_bytes, index_capacity_for, index_growth,
        index_table_bytes, key_bytes, map_capacity_bytes, vec_grown_capacity,
    },
    transformations::url_decode,
    types::{BodyLimitAction, RulePhase},
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

        let held_before = self.processor_memory_before_body();
        let mut ingest_error = false;
        if self.request_body_access && !body.is_empty() {
            // A conversion failure must not disable inspection: fail closed with the
            // largest usable bound instead of retaining nothing.
            let limit = usize::try_from(self.request_body_limit).unwrap_or(usize::MAX);
            let configured_memory = usize::try_from(self.config.request_body_in_memory_limit).unwrap_or(usize::MAX);
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
                let buffer = std::mem::take(&mut self.request_body_buffer);
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

        self.arm_rule_budget(held_before, true);
        self.run_phase(RulePhase::RequestBody);
        self.computed.rule_budget.disarm();
        if self.computed.unchecked_multipart_upload {
            self.computed.unchecked_multipart_upload = false;
            if self.interruption.is_none() {
                self.multipart_strict_error.set("1");
                self.inbound_data_error.set("1");
                self.interrupt(0, "deny", 413, "multipart file uploads are unavailable on this host");
            }
        }
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
                // Check each raw pair against the limit before decoding it, so pairs past
                // the limit are never decoded or allocated.
                let mut count = self.args_post.value_count();
                let mut memory = self.memory_budget();
                for (raw_key, raw_value) in split_urlencoded(body) {
                    if !self.within_argument_limit(count) {
                        break;
                    }
                    // The decoded pair, no longer than the raw one, is charged before it is decoded.
                    let scratch = raw_key
                        .len()
                        .saturating_add(raw_value.len())
                        .saturating_add(2 * ALLOCATION_OVERHEAD_BYTES);
                    if !memory.charge(scratch) {
                        self.report_body_error(true, "URLENCODED", MEMORY_BUDGET_ERROR.to_owned(), true);
                        break;
                    }
                    let (key, value) = decode_pair(raw_key, raw_value);
                    let mut transient = scratch;
                    if memory.is_limited() {
                        let destinations = [&self.args_post, &self.args];
                        // The lowercase copy a lookup makes of a name with a capital is charged before it is made.
                        let fold = budget::lookup_scratch_bytes(&destinations, &key);
                        if !memory.charge(fold) {
                            self.report_body_error(true, "URLENCODED", MEMORY_BUDGET_ERROR.to_owned(), true);
                            break;
                        }
                        let growth = self.post_argument_growth(&key, &[value.len()]);
                        if !memory.charge(growth.grown) {
                            self.report_body_error(true, "URLENCODED", MEMORY_BUDGET_ERROR.to_owned(), true);
                            break;
                        }
                        transient = transient.saturating_add(fold).saturating_add(growth.freed);
                    }
                    self.insert_post_argument(&key, &value);
                    // The decoded pair, the copy, what a growth replaced and the text are gone once the pair is in.
                    memory.refund(transient);
                    count = count.saturating_add(1);
                }
            },
            BodyProcessor::Multipart => {
                if let Err(message) = self.process_multipart_body(body, partial, truncated) {
                    // A stop for the budget was noted when it happened, whichever error is reported.
                    self.report_body_error(true, "MULTIPART", message, false);
                }
            },
            BodyProcessor::Json => {
                // Arguments are published before the error is checked so a valid
                // prefix stays inspectable; see Go Coraza `json.go:34-62`.
                let parsed = read_json_body_within(
                    body,
                    self.config.request_body_json_depth_limit,
                    self.config.argument_limit,
                    self.memory_budget(),
                    &[&self.args_post, &self.args],
                );
                publish_json_arguments(self, &parsed.arguments, false);
                if parsed.truncated {
                    self.arguments_limit_reached.set("1");
                }
                match parsed.error {
                    Some(message) => self.report_body_error(true, "JSON", message, parsed.memory_stopped),
                    None => self.set_tx_variable("json_request_body", body),
                }
            },
            BodyProcessor::Xml => {
                let parsed = xml::parse_into(
                    body,
                    self.memory_budget(),
                    self.config.argument_limit,
                    truncated,
                    &mut self.request_xml,
                );
                let (error, budget_stopped) = match parsed {
                    Ok(None) => (None, false),
                    Ok(Some(xml::Stop::MemoryBudget(message))) => (Some(message), true),
                    // Go has no limit here. Each value is one more evaluation of every rule that reads XML, so past
                    // the limit the body is an error, the values before it still inspected.
                    Ok(Some(xml::Stop::ArgumentLimit(message))) => {
                        self.arguments_limit_reached.set("1");
                        (Some(message), false)
                    },
                    // Go stores the processor's own error unchanged, which for XML is
                    // `encoding/xml`'s `XML syntax error on line N: ...`
                    // (`internal/corazawaf/transaction.go:1780-1786`, v3.8.1). Its text quotes the document, so it
                    // says nothing about the budget.
                    Err(message) => (Some(message), false),
                };
                if let Some(message) = error {
                    self.report_body_error(true, "XML", message, budget_stopped);
                }
            },
        }
    }

    /// Report a request or response body processor that failed or stopped early through `REQBODY_ERROR` or
    /// `RES_BODY_ERROR` and their companions. `budget_stopped` is the processor's own word that it stopped for the
    /// memory budget.
    pub(super) fn report_body_error(&mut self, request: bool, processor: &str, message: String, budget_stopped: bool) {
        self.log_body_processor_error(request, processor, &message);
        self.note_budget_stop(request, budget_stopped);
        let tagged = format!("{processor}: {message}");
        if request {
            self.reqbody_error.set("1");
            self.reqbody_error_msg.set(tagged);
            self.reqbody_processor_error.set("1");
            self.reqbody_processor_error_msg.set(message);
        } else {
            self.res_body_error.set("1");
            self.res_body_error_msg.set(tagged);
            self.res_body_processor_error.set("1");
            self.res_body_processor_error_msg.set(message);
        }
    }

    /// Applies the host's ban on file uploads to a multipart body, where the policy has one. Returns whether the
    /// parts that were read hold an upload, or `None` when that has interrupted the transaction.
    fn ban_multipart_uploads(
        &mut self,
        parts: &LinkedList<multipart::Part<'_>>,
        failure: Option<&multipart::ParseFailure>,
        cut_open: bool,
    ) -> Option<bool> {
        let published_upload = self.config.reject_multipart_file_uploads
            && parts
                .iter()
                .any(|part| part.published_filenames().iter().any(Option::is_some));
        if published_upload {
            self.multipart_strict_error.set("1");
            self.inbound_data_error.set("1");
            self.interrupt(0, "deny", 413, "multipart file uploads are unavailable on this host");
            if self.interruption.is_some() {
                return None;
            }
        }
        // A parser that stopped before the end of the body has not looked at what follows its last part, and a
        // file part could be there. Where uploads are refused such a body cannot be let through on the strength
        // of the parts that were read, so it is refused as one with an upload once the rules of the body phase had
        // their say: the stop is a body error that a rule may deny with its own status, and the ban must not depend
        // on there being one. A body that was not multipart at all has no parts for an upload to hide in.
        // A body that a `ProcessPartial` limit cut before its closing delimiter is the same without a failure to
        // say so: what the limit discarded could be a file, and it ends the parse as no error.
        let parts_unread = failure.is_some_and(|failure| failure.strict || failure.cause == FailureCause::MemoryBudget);
        if self.config.reject_multipart_file_uploads && !published_upload && (cut_open || parts_unread) {
            self.computed.unchecked_multipart_upload = true;
        }
        Some(published_upload)
    }

    /// Populate multipart fields, metadata, and temporary upload files.
    ///
    /// `partial` is how the parser reads a body that reached the limit, as Go's does; `discarded` is whether bytes
    /// really were left out, which is what the ban on uploads depends on. A stop for the memory budget is noted as
    /// it happens, whatever error or interruption follows it.
    fn process_multipart_body(&mut self, body: &[u8], partial: bool, discarded: bool) -> Result<(), String> {
        let mut memory = self.memory_budget();
        let content_type = self.request_headers.first("content-type").unwrap_or_default();
        let (mut parts, failure, cut_open) = multipart::parse(content_type, body, partial, &mut memory);
        let parse_stopped = failure
            .as_ref()
            .is_some_and(|failure| failure.cause == FailureCause::MemoryBudget);
        self.note_budget_stop(true, parse_stopped);
        // A body that ends exactly at the limit is read as cut by it, but nothing of it was left out, so no part
        // can be hiding past its end.
        let Some(reject_uploads) = self.ban_multipart_uploads(&parts, failure.as_ref(), cut_open && discarded) else {
            return Ok(());
        };
        // Go's `NextPart` loop sets the strict error as soon as a part fails, but it
        // has already published the parts before it (`internal/bodyprocessors/multipart.go:52-70`,
        // v3.8.1), so publishing continues here and the error is reported afterwards.
        if failure.as_ref().is_some_and(|failure| failure.strict) {
            self.multipart_strict_error.set("1");
        }
        let mut total_size = 0_u64;
        let mut file_count = self.uploaded_paths.len();
        // The values published a second time, which `SecArgumentsLimit` does not count: see [`Part::as_sent`].
        let mut repeated_fields = 0_usize;

        // What the part just published held, freed by the time the next is taken.
        let mut release_previous = 0_usize;
        // The bytes a temporary upload's path takes, worked out once and only when a file needs one.
        let mut upload_path_bytes = None;
        while let Some(part) = parts.pop_front() {
            memory.refund(release_previous);
            // Past the limit, as when rejected, an upload is still recorded (as Go does) but not written.
            let over_limit = file_count >= self.config.upload_file_limit;
            let written = !over_limit && !reject_uploads;
            // Everything the part adds is charged before any of it is, so a part that does not fit adds nothing.
            if memory.is_limited() {
                // Lookups fold one name at a time (metadata maps always), so the largest copy is charged once.
                let lookup = part
                    .published_filenames()
                    .into_iter()
                    .flatten()
                    .map(fold_scratch_bytes)
                    .fold(fold_scratch_bytes(&part.name), usize::max);
                if !self.charge_dropping_last(&mut memory, &mut parts, lookup) {
                    break;
                }
                let cost = self.multipart_publish_cost(&part, repeated_fields, || {
                    if written {
                        *upload_path_bytes.get_or_insert_with(|| upload_path_bytes_of(&self.config.upload_dir))
                    } else {
                        0
                    }
                });
                if !self.charge_dropping_last(&mut memory, &mut parts, cost.grown) {
                    break;
                }
                release_previous = part.owned_bytes().saturating_add(lookup).saturating_add(cost.freed);
            }
            self.flag_part(&part);
            self.publish_part_metadata(&part);
            // Go publishes only non-empty filenames, while a `filename*` that decoded to nothing still contributes
            // its charset and language (`internal/bodyprocessors/multipart.go:88-105`, v3.8.1).
            let [filename, alt_filename] = part.published_filenames();

            // A part decoded from quoted-printable is published twice, as Go publishes it and as it was sent.
            let (first, second) = published_values(&part);
            let size = u64::try_from(first.len()).map_err(|error| format!("multipart size overflow: {error}"))?;
            // Go adds the length of a field's data to the total as it does a file's
            // (`internal/bodyprocessors/multipart.go:150-185`, go-coraza 1cfa4f955a19), so `FILES_COMBINED_SIZE` is
            // the size of every part. A part Go decodes counts as sent here, which is the larger of the two sizes: a
            // rule that limits the size of a body must not see less than the text a backend that does not decode it
            // receives.
            let counted =
                u64::try_from(part.data.len()).map_err(|error| format!("multipart size overflow: {error}"))?;
            total_size = total_size
                .checked_add(counted)
                .ok_or_else(|| "multipart size overflow".to_owned())?;

            // Go promotes `altFilename` when the primary filename is empty and treats a
            // part with no non-empty filename as a field, which is what an empty file
            // input sends (`internal/bodyprocessors/multipart.go:106-115`, v3.8.1).
            if let Some(filename) = filename.or(alt_filename) {
                if over_limit {
                    self.multipart_strict_error.set("1");
                }
                self.files.add("", filename);
                let second_size = second.map(<[u8]>::len);
                set_file_sizes(&mut self.files_sizes, filename, size, second_size);
                if let Some(alt_filename) = alt_filename.filter(|&alt| alt != filename) {
                    self.files.add("", alt_filename);
                    set_file_sizes(&mut self.files_sizes, alt_filename, size, second_size);
                }
                self.files_names.add("", &part.name);
                file_count += 1;
                if !written {
                    continue;
                }
                // Compute the fallback only when a file actually needs a temporary file.
                // `std::env::temp_dir()` aborts on WASI, and a field-only multipart body
                // never has to touch the filesystem.
                let Some(upload_dir) = upload_directory(&self.config.upload_dir) else {
                    self.multipart_strict_error.set("1");
                    continue;
                };
                for content in std::iter::once(first).chain(second) {
                    let path =
                        save_to_temp(&upload_dir, content).inspect_err(|_| self.multipart_strict_error.set("1"))?;
                    self.files_tmp_names.add("", path.to_string_lossy().as_bytes());
                    self.uploaded_paths.push(path);
                }
            } else if self.within_argument_limit(self.args_post.value_count().saturating_sub(repeated_fields)) {
                self.insert_post_argument(&part.name, first);
                if let Some(second) = second {
                    self.insert_post_argument(&part.name, second);
                    repeated_fields = repeated_fields.saturating_add(1);
                }
            }
        }

        self.files_combined_size.set(total_size.to_string());
        match failure {
            Some(failure) => Err(failure.message),
            None if self.request_body_stopped_by_memory_budget() => Err(MULTIPART_MEMORY_BUDGET_ERROR.to_owned()),
            None => Ok(()),
        }
    }

    /// Sets the duplicate-header, quoting and strict errors that `part` carries.
    fn flag_part(&mut self, part: &multipart::Part<'_>) {
        if part.repeats_header {
            self.multipart_duplicate_part_header.set("1");
            self.multipart_strict_error.set("1");
        }
        if part.invalid_quoting {
            self.multipart_invalid_quoting.set("1");
            self.multipart_strict_error.set("1");
        }
        // Go's `flagUnexpectedEOF`: a part that ended inside its body is a strict error, unless the limit cut the
        // body, which is the end of what was buffered and not a malformed body.
        if part.unexpected_eof && self.inbound_data_error.get() != "1" {
            self.multipart_strict_error.set("1");
        }
        if part.malformed_filename {
            self.multipart_strict_error.set("1");
        }
    }

    /// Charges `bytes` to `memory`, dropping the last of the multipart `parts` waiting to be published until they
    /// fit, as reading fewer would have left room for them: a larger budget then never publishes fewer. A drop is a
    /// stop for the budget, noted as it happens; false when no part is left to drop.
    fn charge_dropping_last(
        &mut self,
        memory: &mut MemoryBudget,
        parts: &mut LinkedList<multipart::Part<'_>>,
        bytes: usize,
    ) -> bool {
        while !memory.charge(bytes) {
            self.note_budget_stop(true, true);
            let Some(last) = parts.pop_back() else {
                return false;
            };
            memory.refund(last.owned_bytes());
        }
        true
    }

    /// Publishes a multipart part's headers, name, filenames and the charset and language of its `filename*`.
    fn publish_part_metadata(&mut self, part: &multipart::Part<'_>) {
        for (name, value) in &part.headers {
            // Go Coraza v3.8.1 `multipart.go:70` stores the header value's raw bytes;
            // a lossy text view would make distinct invalid-UTF-8 values equal.
            self.multipart_part_headers
                .add_owned(&part.name, multipart::header_line(name, value));
        }
        self.multipart_name.add_bytes(&part.name, &part.name);
        for filename in part.published_filenames().into_iter().flatten() {
            self.multipart_filename.add_bytes(&part.name, filename);
        }
        if let Some(encoding) = &part.filename_encoding {
            self.multipart_filename_charset.add_bytes(&part.name, &encoding.charset);
            self.multipart_filename_language
                .add_bytes(&part.name, &encoding.language);
        }
    }

    /// What `insert_post_argument` allocates for values of the lengths `value_lens` under `key`, added in turn: their
    /// entries in `ARGS_POST` and `ARGS`, and the text `ARGS_COMBINED_SIZE` is then set from.
    fn post_argument_growth(&self, key: &[u8], value_lens: &[usize]) -> Growth {
        [&self.args_post, &self.args]
            .into_iter()
            .fold(Growth::default(), |sum, map| {
                sum.plus(budget::values_growth(map, key, value_lens.iter().copied()))
            })
            .plus(SIZE_TEXT)
    }

    /// What publishing `part` allocates, its file's path `upload_path_bytes` long (0 when none is written), when
    /// `repeated_fields` of the values in `ARGS_POST` are second values, which the argument limit does not count.
    fn multipart_publish_cost(
        &self,
        part: &multipart::Part<'_>,
        repeated_fields: usize,
        upload_path_bytes: impl FnOnce() -> usize,
    ) -> Growth {
        let name = part.name.as_slice();
        let (first, second) = published_values(part);
        let [filename, alt_filename] = part.published_filenames();
        let headers = part
            .headers
            .iter()
            .map(|(header, value)| multipart::header_line_len(header, value));
        let headers = budget::values_growth(&self.multipart_part_headers, name, headers);
        let mut cost = headers.plus(budget::values_growth(&self.multipart_name, name, [name.len()]));
        if let Some(encoding) = &part.filename_encoding {
            cost = cost
                .plus(budget::values_growth(
                    &self.multipart_filename_charset,
                    name,
                    [encoding.charset.len()],
                ))
                .plus(budget::values_growth(
                    &self.multipart_filename_language,
                    name,
                    [encoding.language.len()],
                ));
        }
        let Some(file) = filename.or(alt_filename) else {
            // The test the field is published under: one past the argument limit is dropped, and costs nothing.
            if self.args_post.value_count().saturating_sub(repeated_fields) < self.config.argument_limit {
                let lens = [first.len(), second.map_or(0, <[u8]>::len)];
                let lens = lens.get(..1 + usize::from(second.is_some())).unwrap_or_default();
                cost = cost.plus(self.post_argument_growth(name, lens));
            }
            return cost;
        };
        let filenames = filename.into_iter().chain(alt_filename).map(<[u8]>::len);
        let files = [Some(file), alt_filename.filter(|&alt| alt != file)];
        cost = cost
            .plus(budget::values_growth(&self.multipart_filename, name, filenames))
            .plus(budget::values_growth(
                &self.files,
                b"",
                files.into_iter().flatten().map(<[u8]>::len),
            ))
            .plus(budget::first_values_growth(
                &self.files_sizes,
                files.into_iter().flatten(),
                SIZE_TEXT_BYTES,
            ))
            .plus(budget::values_growth(&self.files_names, b"", [name.len()]))
            .plus(SIZE_TEXT);
        // The size of a second value is added after the first is set; two values from a key that is not held yet
        // cost more than the second does, which is the safe side.
        for file in files.into_iter().flatten().filter(|_| second.is_some()) {
            cost = cost.plus(budget::values_growth(
                &self.files_sizes,
                file,
                [SIZE_TEXT_BYTES, SIZE_TEXT_BYTES],
            ));
        }
        let path = upload_path_bytes();
        if path > 0 {
            // Each file is kept in `FILES_TMPNAMES` and for cleanup; writing holds 3 more (tempfile 3.27 doubles its
            // buffer), one file at a time.
            let uploads = (self.uploaded_paths.len(), self.uploaded_paths.capacity());
            let writing = allocation_bytes(path).saturating_mul(3);
            let written = 1 + usize::from(second.is_some());
            cost = cost
                .plus(budget::values_growth(
                    &self.files_tmp_names,
                    b"",
                    std::iter::repeat_n(path, written),
                ))
                .plus(Growth {
                    grown: allocation_bytes(path).saturating_mul(written).saturating_add(writing),
                    freed: writing,
                });
            for added in 0..written {
                cost = cost.plus(budget::list_growth(
                    uploads,
                    added,
                    size_of::<PathBuf>(),
                    vec_grown_capacity,
                ));
            }
        }
        cost
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

/// The error reported when a body would take its processor past the memory budget the host set.
const MEMORY_BUDGET_ERROR: &str = "parsed arguments exceed the body memory budget";

/// The error reported when the parts of a multipart body would take it past the memory budget the host set.
const MULTIPART_MEMORY_BUDGET_ERROR: &str = "published parts exceed the body memory budget";

/// Sets the sizes of an upload under `name`. A later part with the same filename replaces them, as in Go, so a second
/// size an earlier decoded part left is dropped: the values of a name always come from one part.
fn set_file_sizes(sizes: &mut Map, name: &[u8], size: u64, second: Option<usize>) {
    sizes.set_index(name, 0, size.to_string());
    match second {
        Some(second) => sizes.set_index(name, 1, second.to_string()),
        // Only an earlier decoded part leaves a second size, and then some name holds two values: no lookup, so no
        // lowercase copy of a name with uppercase letters, for a body that decodes nothing.
        None if sizes.value_count() > sizes.len() => sizes.truncate_values(name, 1),
        None => {},
    }
}

/// What `part` publishes: its body as Go publishes it and, for a part decoded from quoted-printable, what was sent
/// after it. A rule that reads the part sees both, so a backend that decodes the body, as Go's does, and one that
/// takes it as sent are both inspected.
fn published_values<'p>(part: &'p multipart::Part<'_>) -> (&'p [u8], Option<&'p [u8]>) {
    (part.body(), part.as_sent())
}

/// Longest decimal rendering of a `u64`: the text of a size, which `FILES_SIZES` keeps and `ARGS_COMBINED_SIZE` is
/// set from.
const SIZE_TEXT_BYTES: usize = 20;

/// The buffer the text of a size is built in, which is given back once the text is stored.
const SIZE_TEXT: Growth = Growth {
    grown: allocation_bytes(SIZE_TEXT_BYTES),
    freed: allocation_bytes(SIZE_TEXT_BYTES),
};

/// The bytes the path of one temporary upload takes: the directory the file is written under, which is the one
/// [`upload_directory`] resolves and not the configured text, as the lossy text `FILES_TMPNAMES` keeps of it, and
/// the file name added to it. 0 for a host that has no directory, which writes no file.
fn upload_path_bytes_of(configured: &str) -> usize {
    /// The file name `tempfile` appends to the directory is a fixed-length random one.
    const TEMP_NAME_BYTES: usize = 32;

    upload_directory(configured).map_or(0, |dir| dir.to_string_lossy().len().saturating_add(TEMP_NAME_BYTES))
}

/// Process a custom body and merge its narrow output through transaction insertion paths.
pub(super) fn process_custom_body_processor(
    tx: &mut Transaction,
    body: &[u8],
    direction: BodyDirection,
    truncated: bool,
    processor: &dyn CustomBodyProcessor,
) {
    let upload_dir = upload_directory(&tx.config.upload_dir);
    process_custom_body_in(tx, body, direction, truncated, processor, upload_dir.as_deref());
}

/// [`process_custom_body_processor`] with the upload directory already chosen.
#[expect(
    clippy::too_many_arguments,
    reason = "the body processor inputs and the chosen upload directory are all explicit"
)]
fn process_custom_body_in(
    tx: &mut Transaction,
    body: &[u8],
    direction: BodyDirection,
    truncated: bool,
    processor: &dyn CustomBodyProcessor,
    upload_dir: Option<&Path>,
) {
    let options_upload_dir = upload_dir.unwrap_or_else(|| Path::new(""));
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
    )
    // `FILES_TMPNAMES` stores the path lossily (an invalid byte becomes U+FFFD, three bytes), so the lossy length
    // is the one retained; it is never shorter than the native one.
    .with_upload_path_bytes(options_upload_dir.to_string_lossy().len())
    .with_argument_copies(match direction {
        BodyDirection::Request => 2,
        BodyDirection::Response => 1,
    });
    let options = BodyProcessorOptions {
        mime,
        upload_dir: options_upload_dir,
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
        Some(output.limit_error.to_owned())
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
    let xml_error = publish_custom_xml(tx, direction, output.xml);
    error = error.or(xml_error);
    for file in &output.files {
        let Some(upload_dir) = upload_dir else {
            if error.is_none() {
                error = Some("file uploads are unavailable on this host".to_owned());
            }
            break;
        };
        if let Err(message) = add_body_processor_file(tx, upload_dir, file) {
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

/// Publishes a custom processor's XML values into the direction's collection up to the argument limit, past which,
/// as for the built-in processor, the values before it stay and the rest is an error, which it returns.
fn publish_custom_xml(
    tx: &mut Transaction,
    direction: BodyDirection,
    values: Vec<(Vec<u8>, Vec<u8>)>,
) -> Option<String> {
    let limit = tx.config.argument_limit;
    let xml = match direction {
        BodyDirection::Request => &mut tx.request_xml,
        BodyDirection::Response => &mut tx.response_xml,
    };
    for (path, value) in values {
        if xml.value_count() >= limit {
            tx.arguments_limit_reached.set("1");
            return Some(format!(
                "custom body processor XML output exceeded the {limit} value argument limit"
            ));
        }
        xml.add_bytes(&path, &value);
    }
    None
}

/// Set the matching request or response processor error variables.
fn record_custom_body_processor_error(tx: &mut Transaction, direction: BodyDirection, message: &str) {
    let request = direction == BodyDirection::Request;
    let processor_name = match direction {
        BodyDirection::Request => truncate_custom_body_text(&tx.reqbody_processor.get()),
        BodyDirection::Response => truncate_custom_body_text(&tx.res_body_processor.get()),
    };
    tx.report_body_error(request, &processor_name, truncate_custom_body_text(message), false);
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

/// The directory for temporary uploads, or `None` when WASI has no configured one.
///
/// `std::env::temp_dir()` aborts on WASI. Callers use this only when they actually
/// need to write a file; a field-only body or a rejected upload never calls it.
///
/// A relative directory is made absolute against the current directory, which is where `tempfile` resolves
/// it, so the length used to charge the retained file paths is the one of the paths actually created.
fn upload_directory(configured: &str) -> Option<PathBuf> {
    if !configured.is_empty() {
        let configured = PathBuf::from(configured);
        return Some(std::path::absolute(&configured).unwrap_or(configured));
    }
    if cfg!(target_os = "wasi") {
        return None;
    }
    Some(std::env::temp_dir())
}

/// Store a custom file using the same private temporary-file path as multipart uploads.
fn add_body_processor_file(tx: &mut Transaction, upload_dir: &Path, file: &BodyProcessorFile) -> Result<(), String> {
    let size = u64::try_from(file.bytes.len()).map_err(|error| format!("upload size overflow: {error}"))?;
    let current_size = std::str::from_utf8(tx.files_combined_size.get_bytes())
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let total_size = current_size
        .checked_add(size)
        .ok_or_else(|| "upload size overflow".to_owned())?;

    tx.multipart_part_headers
        .add_bytes(&file.name, multipart::header_line("Content-Type", &file.content_type));
    // Past the limit `FILES`, `FILES_SIZES` and `FILES_NAMES` still record the upload,
    // as the built-in multipart processor does: only the temporary file write stops.
    tx.files.add_bytes(b"", &file.filename);
    tx.multipart_name.add_bytes(&file.name, &file.name);
    tx.multipart_filename.add_bytes(&file.name, &file.filename);
    tx.files_sizes.set_index(&file.filename, 0, size.to_string());
    tx.files_names.add_bytes(b"", &file.name);
    tx.files_combined_size.set(total_size.to_string());

    if tx.uploaded_paths.len() >= tx.config.upload_file_limit {
        tx.multipart_strict_error.set("1");
        return Ok(());
    }
    let path = save_to_temp(upload_dir, &file.bytes)?;
    tx.files_tmp_names.add_bytes(b"", path.to_string_lossy().as_bytes());
    tx.uploaded_paths.push(path);
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

/// Splits URLENCODED pairs in order into raw name and value bytes, skipping empty pairs.
pub(super) fn split_urlencoded(body: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> + '_ {
    body.split(|&byte| byte == b'&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.iter().position(|&byte| byte == b'=') {
            Some(equals) => (
                pair.get(..equals).unwrap_or_default(),
                pair.get(equals.saturating_add(1)..).unwrap_or_default(),
            ),
            None => (pair, &b""[..]),
        })
}

/// URL-decodes the name and value of one raw pair from `split_urlencoded`.
pub(super) fn decode_pair(key: &[u8], value: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (url_decode(key).0, url_decode(value).0)
}

/// Bounds the flattened form relative to the body that produced it.
///
/// `SecArgumentsLimit` counts entries, not bytes, and the flattened key is the
/// full path rewritten for every leaf, so memory grows with depth times leaves
/// while the entry count grows only with leaves. Go Coraza uses the same factor
/// (`internal/bodyprocessors/json.go:113`); see the comment there. It is the only limit without a host
/// memory budget: what the transaction holds beyond it, the copies and the entries, is for that budget to bound.
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
    /// Flattening, or the scratch it works in, would outgrow the memory budget the host set.
    Memory,
}

/// A JSON body flattened the way Go Coraza's `readJSON` does.
pub(super) struct JsonBody {
    /// Dot-separated paths, in first-discovery order.
    pub(super) arguments: JsonArguments,
    /// Whether the argument or array-length cap stopped the walk.
    pub(super) truncated: bool,
    /// The parser error message, after any best-effort arguments were collected.
    pub(super) error: Option<String>,
    /// Whether the host's memory budget is why the walk stopped, which `error` then says.
    pub(super) memory_stopped: bool,
}

/// Flattened arguments in first-discovery order.
///
/// Hash-map iteration order depends on `RandomState`, so publishing straight
/// from one would make the insertion order of distinct keys in `ARGS_POST`,
/// `ARGS` and `RESPONSE_ARGS` change between runs, and with it first-match
/// results and audit argument order. Entries are kept in a vector instead;
/// the map only indexes a path to its row.
pub(super) struct JsonArguments {
    /// Each path with its values in discovery order, in first-discovery order.
    ///
    /// The path is held once: the index map is both the order and the row lookup.
    entries: IndexMap<Vec<u8>, Vec<Vec<u8>>, ahash::RandomState>,
}

impl JsonArguments {
    /// Create an empty set of arguments.
    fn new() -> Self {
        Self {
            entries: IndexMap::with_hasher(ahash::RandomState::new()),
        }
    }

    /// Append `value` under `key`, creating the row on first discovery.
    fn push(&mut self, key: &[u8], value: Vec<u8>) {
        if let Some(values) = self.entries.get_mut(key) {
            values.push(value);
            return;
        }
        self.entries.insert(key.to_vec(), vec![value]);
    }

    /// Values stored under `key`, in discovery order.
    #[cfg(test)]
    pub(super) fn get(&self, key: &[u8]) -> Option<&[Vec<u8>]> {
        self.entries.get(key).map(Vec::as_slice)
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
    fn next(&mut self, containers: &ContainerIndex, scratch: &mut JsonScratch) -> Option<(JsonKey<'a>, JsonValue<'a>)> {
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
                let name = if escaped && scratch.materialize {
                    if !scratch.reserve_unescaped(content.len()) {
                        return None;
                    }
                    Cow::Owned(unescape_json_string(content))
                } else {
                    Cow::Borrowed(content)
                };
                self.offset = end;
                self.skip_separators(raw);
                let (end, value) = parse_any_value(raw, self.offset, self.base, containers, scratch)?;
                // gjson's ForEach advances one more byte after each pair.
                self.offset = end.saturating_add(1);
                return Some((JsonKey::Name(name), value));
            }
        }
        self.skip_separators(raw);
        let index = self.index;
        self.index += 1;
        let (end, value) = parse_any_value(raw, self.offset, self.base, containers, scratch)?;
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

/// What the host's memory budget has left, and the transient buffers charged to it that the walk gives back after
/// each entry.
struct JsonScratch {
    /// The budget; unlimited unless the host set one.
    memory: MemoryBudget,
    /// Transient bytes charged since the last entry ended.
    pending: usize,
    /// Set when a charge was refused, which ends the walk: the scanners that charge report it as the end of the
    /// input, and the walk reads this to tell the two apart.
    exhausted: bool,
    /// Whether the scanners unescape the strings they read. The walk turns it off once the argument limit is
    /// full, when all it asks of them is whether another member exists, which is not worth the buffer.
    materialize: bool,
}

impl JsonScratch {
    /// Reserves the buffer an escaped string unescapes into, which is as long as the string at most.
    fn reserve_unescaped(&mut self, escaped_len: usize) -> bool {
        if !self.memory.is_limited() {
            return true;
        }
        let bytes = escaped_len.saturating_add(ALLOCATION_OVERHEAD_BYTES);
        if self.memory.charge(bytes) {
            self.pending = self.pending.saturating_add(bytes);
            true
        } else {
            self.exhausted = true;
            false
        }
    }

    /// Gives back the transient bytes of the entry that ended.
    fn release(&mut self) {
        self.memory.refund(self.pending);
        self.pending = 0;
    }
}

impl TableLedger {
    /// A ledger for a walk published into `held`, whose tables are as they are before the walk.
    fn new(held: &[&Map]) -> Self {
        let mut ledger = Self::default();
        for (target, map) in ledger.targets.iter_mut().zip(held) {
            target.base_len = map.len();
            target.capacity = map.key_table_capacity();
        }
        ledger
    }

    /// What the tables grow by when a path that makes `distinct` of them is added, and is new to the targets that
    /// `new_to` flags: the grown tables, each held beside its old one while the entries move. Nothing for a table
    /// that has room.
    fn growth(&self, distinct: usize, copies: usize, new_to: [bool; MAX_TARGETS]) -> usize {
        let walk = if index_capacity_for(distinct) > self.walk_capacity {
            JsonFlattener::walk_table_bytes(distinct)
        } else {
            0
        };
        // A collection's table of two generations back is never allocated beside the new one, so it is given back.
        self.targets
            .iter()
            .zip(new_to)
            .take(copies)
            .filter(|(_, new)| *new)
            .filter_map(|(target, _)| {
                Some(map_capacity_bytes(target.grown_capacity()?).saturating_sub(target.charged[0]))
            })
            .fold(walk, usize::saturating_add)
    }

    /// Records that the tables hold the path now, once the growth that [`TableLedger::growth`] reported was
    /// charged: what the walk's old table was charged is given back.
    fn advance(&mut self, memory: &mut MemoryBudget, distinct: usize, copies: usize, new_to: [bool; MAX_TARGETS]) {
        let capacity = index_capacity_for(distinct);
        if capacity > self.walk_capacity {
            memory.refund(self.walk);
            self.walk = JsonFlattener::walk_table_bytes(distinct);
            self.walk_capacity = capacity;
        }
        for (target, new) in self.targets.iter_mut().zip(new_to).take(copies) {
            if !new {
                continue;
            }
            if let Some(capacity) = target.grown_capacity() {
                target.charged = [target.charged[1], map_capacity_bytes(capacity)];
                target.capacity = capacity;
            }
            target.added = target.added.saturating_add(1);
        }
    }
}

/// The state of one gjson-compatible flattening walk.
struct JsonFlattener<'m> {
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
    /// The host's memory budget and the walk's transient charges to it.
    scratch: JsonScratch,
    /// Bytes of the path buffer already charged: its high-water mark, as it keeps its capacity.
    path_charged: usize,
    /// The collections each entry is published into as they are before the walk: `ARGS_POST` and `ARGS` for a
    /// request, `RESPONSE_ARGS` for a response. A query string can have filled a list of them already.
    held: &'m [&'m Map],
    /// Values of paths that a case-insensitive collection files under another spelling, by that spelling: they
    /// join the list of every path that folds alike. It is made for the first of them, and dropped when the walk ends.
    folded: Option<IndexMap<Vec<u8>, usize, ahash::RandomState>>,
    /// The bytes `folded` holds.
    folded_bytes: usize,
    /// What has been charged for the collections' values, lists and keys, which they allocate only after the walk.
    unfilled: usize,
    /// What has been charged for the old allocation of a list while it grows, the buffer a key's text is built in, or
    /// the text `ARGS_COMBINED_SIZE` is set from as an entry is published into `ARGS_POST` and `ARGS`, the most of
    /// them: they are not held together, so one is reserved for every growth. It also covers what `folded`, and the
    /// old allocation of the walk's list while it grows, take beyond `unfilled`.
    transient: usize,
    /// The capacity the stack of open containers has been charged for.
    frames_charged: usize,
    /// The largest lowercase copy of a path that a collection has made so far, which is charged once: they are not
    /// held together.
    fold_charged: usize,
    /// What the tables of the walk's list and of the collections hold, charged as the number of distinct paths
    /// grows into a bigger one.
    tables: TableLedger,
}

/// The hash tables the walk's list and the collections it feeds grow, charged as the number of distinct paths takes
/// them past their capacity.
///
/// A table that is full is replaced by one about twice as big, and both are held while its entries are moved. The
/// walk's list grows while it walks, so its old table is given back at once; the collections grow when the entries
/// are published, after the walk, and the old table of the last growth must have been charged by then, so the
/// previous generation stays charged and the ones before it are given back.
#[derive(Default)]
struct TableLedger {
    /// The capacity the walk's table has grown to.
    walk_capacity: usize,
    /// What the walk's list was charged for its table.
    walk: usize,
    /// The collections the entries are published into.
    targets: [TargetTable; MAX_TARGETS],
}

/// The most collections a walk is published into: `ARGS_POST` and `ARGS`.
const MAX_TARGETS: usize = 2;

/// One collection's table of keys as the walk grows it, starting from the table the collection has.
#[derive(Default, Clone, Copy)]
struct TargetTable {
    /// Keys the collection held before the walk.
    base_len: usize,
    /// The capacity of its table: what it had, or what the walk has charged it growing to.
    capacity: usize,
    /// Keys the walk has added that the collection did not hold.
    added: usize,
    /// What the table was charged in the previous and in the current generation.
    charged: [usize; 2],
}

impl TargetTable {
    /// The capacity the table grows to when one more key is added, none while it has room.
    fn grown_capacity(&self) -> Option<usize> {
        let keys = self.base_len.saturating_add(self.added).saturating_add(1);
        (keys > self.capacity).then(|| index_capacity_for(keys))
    }
}

impl<'m> JsonFlattener<'m> {
    /// Start a walk with the given caps, for entries published into `held`.
    fn new(argument_limit: usize, byte_budget: usize, memory: MemoryBudget, held: &'m [&'m Map]) -> Self {
        let held = held.get(..MAX_TARGETS).unwrap_or(held);
        Self {
            scratch: JsonScratch {
                memory,
                pending: 0,
                exhausted: false,
                materialize: true,
            },
            path_charged: 0,
            held,
            folded: None,
            folded_bytes: 0,
            unfilled: 0,
            transient: 0,
            frames_charged: 0,
            fold_charged: 0,
            tables: TableLedger::new(held),
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
        if self.scratch.exhausted {
            // The root was a string that did not fit the scratch to unescape it in.
            return Err(JsonFlattenError::Memory);
        }
        self.reserve_frames(0)?;
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
            // With the argument limit full all that matters is whether another member follows, and that is read
            // without unescaping it: a member the scratch could not hold must still end the walk as one past the limit.
            let capped = self.argument_limit > 0 && self.argument_count >= self.argument_limit;
            self.scratch.materialize = !capped;
            let next = match frames.last_mut() {
                Some(frame) => frame.scanner.next(containers, &mut self.scratch),
                None => return Ok(truncated),
            };
            match next {
                None => {
                    if self.scratch.exhausted {
                        return Err(JsonFlattenError::Memory);
                    }
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
                    self.scratch.release();
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
        // The path keeps the capacity it grew to, which doubles: charge what it adds to its high-water mark twice.
        // An index is at most twenty digits.
        let growth = match &key {
            JsonKey::Name(name) => name.len(),
            JsonKey::Index(_) => 20,
        };
        self.reserve_path(previous_len.saturating_add(1).saturating_add(growth))?;
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
                self.reserve_frames(frames.len())?;
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

    /// Reserves path buffer room for a path of `len` bytes, beyond what the buffer has had so far.
    fn reserve_path(&mut self, len: usize) -> Result<(), JsonFlattenError> {
        if len > self.path_charged {
            let growth = len - self.path_charged;
            if !self.scratch.memory.charge(growth.saturating_mul(2)) {
                return Err(JsonFlattenError::Memory);
            }
            self.path_charged = len;
        }
        Ok(())
    }

    /// Reserves the stack of open containers room for one more when it holds `len`, before it grows: a vector that is
    /// full is replaced by one twice as big, and both are held while the frames are moved.
    fn reserve_frames(&mut self, len: usize) -> Result<(), JsonFlattenError> {
        if !self.scratch.memory.is_limited() || len < self.frames_charged {
            return Ok(());
        }
        // The vector starts with its one frame, and grows to four at least.
        let capacity = if len == 0 { 1 } else { len.saturating_mul(2).max(4) };
        let bytes = allocation_bytes(capacity.saturating_mul(size_of::<JsonFrame<'_>>()));
        if !self.scratch.memory.charge(bytes) {
            return Err(JsonFlattenError::Memory);
        }
        // The old buffer is freed once the frames are moved, which is when the entry ends.
        let old = allocation_bytes(self.frames_charged.saturating_mul(size_of::<JsonFrame<'_>>()));
        self.scratch.pending = self.scratch.pending.saturating_add(old);
        self.frames_charged = capacity;
        Ok(())
    }

    /// Reserves the memory budget for one entry: its row in the walk's list, and its rows in each collection it is
    /// published into, each with its key and value. Nothing is reserved unless all of it fits.
    ///
    /// The tables that hold the rows grow by doubling, which is charged when a new path takes a table past its
    /// capacity (see [`TableLedger`]); what an entry adds beyond that is its own allocations. A value added to a
    /// list a collection has, or will have from the walk's earlier values, adds the list's growth when it is full.
    fn reserve_entry(&mut self, key: &[u8], value_len: usize) -> Result<(), JsonFlattenError> {
        if !self.scratch.memory.is_limited() {
            return Ok(());
        }
        let copies = self.held.len();
        // A collection that files a path with a capital in it makes a lowercase copy of it for every lookup, which
        // is charged, once and at its largest, before the first lookup.
        let fold = budget::lookup_scratch_bytes(self.held, key);
        if fold > self.fold_charged {
            if !self.scratch.memory.charge(fold - self.fold_charged) {
                return Err(JsonFlattenError::Memory);
            }
            self.fold_charged = fold;
        }
        // The key the collections file the path under, which they fold alike: `ARGS_POST` and `ARGS` follow one
        // setting. Paths spelled apart from it share its list.
        let lookup = self.held.first().map_or(Cow::Borrowed(key), |map| map.lookup_key(key));
        let spelled_apart = lookup.as_ref() != key;
        let walk_list = self.values.entries.get(key).map(Vec::len);
        let others = self
            .folded
            .as_ref()
            .and_then(|folded| folded.get(lookup.as_ref()))
            .copied();
        // Values the walk has for that list already: those of the path spelled as it, and of the others.
        let walked = self
            .values
            .entries
            .get(lookup.as_ref())
            .map_or(0, Vec::len)
            .saturating_add(others.unwrap_or(0));
        // The value is copied for the walk's list and for each collection.
        let value = allocation_bytes(value_len);
        // A list that grows is held beside the one it replaces, which is freed after: only the new one stays charged,
        // and the largest old one, which is held beside the finished lists when the collections are filled. A key's
        // text is built in a buffer that is freed alike, and so is the text a request's entry, published into
        // `ARGS_POST` and `ARGS`, then sets `ARGS_COMBINED_SIZE` from.
        let walk_growth = walk_list.map_or_else(Growth::default, |values| {
            budget::list_growth(
                (1, 1),
                values.saturating_sub(1),
                size_of::<Vec<u8>>(),
                vec_grown_capacity,
            )
        });
        let mut collections = Growth::default();
        let mut largest = if copies == MAX_TARGETS { SIZE_TEXT.freed } else { 0 };
        let mut add = |growth: Growth| {
            collections = collections.plus(growth);
            largest = largest.max(growth.freed);
        };
        // Collections the path is new to, whose tables of keys take it.
        let mut new_to = [false; MAX_TARGETS];
        for (map, new) in self.held.iter().zip(new_to.iter_mut()) {
            // The walk's earlier values of the path are published before this one, into the same list.
            let (list, first) = budget::value_list_growth(map.value_list_shape(&lookup), walked);
            *new = first;
            add(list);
            add(key_bytes(key, &lookup, *new));
        }
        // What the collections are charged: a copy of the value each, and their lists and keys.
        let filled = value
            .saturating_mul(copies)
            .saturating_add(collections.grown)
            .saturating_sub(collections.freed);
        let mut bytes = value
            .saturating_add(walk_growth.grown)
            .saturating_sub(walk_growth.freed)
            .saturating_add(filled);
        let distinct = self.values.entries.len().saturating_add(1);
        if walk_list.is_none() {
            bytes = bytes
                .saturating_add(allocation_bytes(key.len()))
                // The one-element value list of the walk.
                .saturating_add(allocation_bytes(size_of::<Vec<u8>>()))
                .saturating_add(self.tables.growth(distinct, copies, new_to));
        }
        // Reserve what `folded` and the walk list's old allocation take beyond `unfilled`.
        let counted = self.folded_growth(&lookup, spelled_apart && others.is_none());
        let unfilled = self.unfilled.saturating_add(filled);
        let walking = self
            .folded_bytes
            .saturating_add(counted.grown)
            .saturating_add(walk_growth.freed)
            .saturating_sub(unfilled);
        let reserved = largest.max(walking).saturating_sub(self.transient);
        if !self.scratch.memory.charge(bytes.saturating_add(reserved)) {
            return Err(JsonFlattenError::Memory);
        }
        self.transient = self.transient.saturating_add(reserved);
        self.unfilled = unfilled;
        if walk_list.is_none() {
            self.tables.advance(&mut self.scratch.memory, distinct, copies, new_to);
        }
        if spelled_apart {
            let folded = self.folded.get_or_insert_with(IndexMap::default);
            if let Some(count) = folded.get_mut(lookup.as_ref()) {
                *count = count.saturating_add(1);
            } else {
                let mut kept = lookup.into_owned();
                // Kept at its length, which is what was counted for it.
                kept.shrink_to_fit();
                folded.insert(kept, 1);
                self.folded_bytes = self
                    .folded_bytes
                    .saturating_add(counted.grown)
                    .saturating_sub(counted.freed);
            }
        }
        Ok(())
    }

    /// What counting a path under `lookup` in [`JsonFlattener::folded`] takes when it is `new` there: a copy of the
    /// key, and a full table's growth.
    fn folded_growth(&self, lookup: &[u8], new: bool) -> Growth {
        if !new {
            return Growth::default();
        }
        let (len, capacity) = self
            .folded
            .as_ref()
            .map_or((0, 0), |folded| (folded.len(), folded.capacity()));
        let table = index_growth::<(Vec<u8>, usize)>(len, capacity);
        Growth {
            grown: allocation_bytes(lookup.len()).saturating_add(table.grown),
            ..table
        }
    }

    /// The bytes of the table of the walk's list holding `distinct` paths.
    fn walk_table_bytes(distinct: usize) -> usize {
        index_table_bytes::<(Vec<u8>, Vec<Vec<u8>>)>(index_capacity_for(distinct))
    }

    /// Retain one flattened entry, enforcing the byte budget.
    fn record(&mut self, key: &[u8], value: &[u8]) -> Result<(), JsonFlattenError> {
        let used = self.used_bytes.saturating_add(key.len()).saturating_add(value.len());
        if used > self.byte_budget {
            return Err(JsonFlattenError::Budget);
        }
        // Only a host's memory budget bounds what the entry costs beyond Go's raw budget above.
        self.reserve_entry(key, value.len())?;
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
    ///
    /// Each row, and each level of the stack the index is built with, is charged to `memory` before it is stored.
    /// There is no partial index to walk with: a body that outgrows the budget is refused whole.
    ///
    /// # Errors
    ///
    /// [`JsonFlattenError::Memory`] when the index would outgrow `memory`.
    fn build(input: &[u8], max_recursion: usize, memory: &mut MemoryBudget) -> Result<Self, JsonFlattenError> {
        /// What one row costs: two offsets, in vectors that may hold a quarter or more spare and, while one grows,
        /// its old buffer as well.
        const ROW_BYTES: usize = 3 * 2 * size_of::<usize>();
        /// What one level of the stack costs, with the same slack.
        const LEVEL_BYTES: usize = 3 * size_of::<usize>() * 2;

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
        let mut levels_charged = 0_usize;
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
                        if !memory.charge(ROW_BYTES) {
                            return Err(JsonFlattenError::Memory);
                        }
                        top.row = Some(index.starts.len());
                        index.starts.push(top.start);
                        index.ends.push(0);
                    }
                    if deeper > 0 {
                        deeper += 1;
                    } else if open.len() == capture_depth {
                        deeper = 1;
                    } else {
                        if open.len() >= levels_charged {
                            if !memory.charge(LEVEL_BYTES) {
                                return Err(JsonFlattenError::Memory);
                            }
                            levels_charged = open.len().saturating_add(1);
                        }
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
        for container in &open {
            if let Some(row) = container.row
                && let Some(end) = index.ends.get_mut(row)
            {
                *end = input.len();
            }
        }
        // The stack is dropped with the build; a refused build ends the walk, and its budget with it.
        memory.refund(levels_charged.saturating_mul(LEVEL_BYTES));
        Ok(index)
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
    scratch: &mut JsonScratch,
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
            let value = if escaped && scratch.materialize {
                if !scratch.reserve_unescaped(content.len()) {
                    return None;
                }
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
fn parse_json_root<'a>(input: &'a [u8], scratch: &mut JsonScratch) -> Option<JsonValue<'a>> {
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
            b'"' => return scan_root_string(input, index, scratch).map(JsonValue::String),
            _ => return None,
        }
    }
    None
}

/// Reads the string gjson's `Parse` returns for a document that is one string, or `None` when the buffer it
/// unescapes into does not fit `scratch`: the buffer is as long as the string and reserved before it is made, and a
/// string with no escape is borrowed.
fn scan_root_string<'a>(input: &'a [u8], start: usize, scratch: &mut JsonScratch) -> Option<Cow<'a, [u8]>> {
    let mut unescaped = |content: &'a [u8]| {
        scratch
            .reserve_unescaped(content.len())
            .then(|| Cow::Owned(unescape_json_string(content)))
    };
    let mut index = start + 1;
    while let Some(&byte) = input.get(index) {
        if byte > b'\\' {
            index += 1;
            continue;
        }
        if byte == b'"' {
            return Some(Cow::Borrowed(input.get(start + 1..index).unwrap_or_default()));
        }
        if byte == b'\\' {
            index += 1;
            while let Some(&escaped) = input.get(index) {
                if escaped > b'\\' {
                    index += 1;
                    continue;
                }
                if escaped == b'"' && !is_escaped_quote(input, index, 1) {
                    return unescaped(input.get(start + 1..index).unwrap_or_default());
                }
                index += 1;
            }
            return unescaped(input.get(start + 1..).unwrap_or_default());
        }
        index += 1;
    }
    Some(Cow::Borrowed(input.get(start + 1..).unwrap_or_default()))
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
///
/// With a memory budget, the container index, the walk's scratch and every entry it keeps are charged to it
/// before they are allocated, and the walk stops, with the entries before that point, when one would not fit.
pub(super) fn read_json_body_within(
    body: &[u8],
    max_recursion: usize,
    argument_limit: usize,
    mut memory: MemoryBudget,
    held: &[&Map],
) -> JsonBody {
    let containers = if max_recursion == 0 {
        ContainerIndex::empty()
    } else {
        match ContainerIndex::build(body, max_recursion, &mut memory) {
            Ok(containers) => containers,
            Err(_) => {
                return JsonBody {
                    arguments: JsonArguments::new(),
                    truncated: false,
                    error: Some(memory_budget_message(memory.limit())),
                    memory_stopped: true,
                };
            },
        }
    };
    read_json_budgeted(body, max_recursion, argument_limit, &containers, memory, held)
}

/// [`read_json_body_within`] without a memory budget, which is what the engine does by default.
#[cfg(test)]
pub(super) fn read_json_body(body: &[u8], max_recursion: usize, argument_limit: usize) -> JsonBody {
    read_json_body_within(body, max_recursion, argument_limit, MemoryBudget::default(), &[])
}

/// The error for a JSON body that outgrew the host's memory budget.
fn memory_budget_message(limit: usize) -> String {
    format!("flattened form exceeds the {limit} byte body memory budget")
}

/// Flatten with the given container index, which an empty one makes scan every container, under the host's memory
/// budget with the index already charged to it, for a walk whose entries are published into `held`.
#[expect(
    clippy::too_many_arguments,
    reason = "the limits, the index and the budget are all explicit, as for the readers above"
)]
fn read_json_budgeted(
    body: &[u8],
    max_recursion: usize,
    argument_limit: usize,
    containers: &ContainerIndex,
    memory: MemoryBudget,
    held: &[&Map],
) -> JsonBody {
    let byte_budget = body.len().saturating_mul(FLATTEN_BYTES_FACTOR).max(FLATTEN_BYTES_FLOOR);
    let mut flattener = JsonFlattener::new(argument_limit, byte_budget, memory, held);
    // A document that is one string with an escape unescapes it into a buffer, which is reserved first.
    let root = parse_json_root(body, &mut flattener.scratch);
    let walked = flattener.flatten(root, max_recursion, containers);
    let (truncated, error) = match walked {
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
        Err(JsonFlattenError::Memory) => (false, Some(memory_budget_message(flattener.scratch.memory.limit()))),
    };
    JsonBody {
        arguments: flattener.values,
        truncated,
        error,
        memory_stopped: walked == Err(JsonFlattenError::Memory),
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

    /// Process `body` under a `ProcessPartial` limit of `limit` bytes, with the boundary `b`.
    fn process_cut_at(body: &[u8], limit: usize) -> Transaction {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(&format!(
                "SecRequestBodyAccess On\nSecRequestBodyLimit {limit}\nSecRequestBodyLimitAction ProcessPartial"
            ))
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("multipart-cut");
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=b");
        tx.process_request_headers();
        assert_eq!(tx.process_request_body(body), None);
        tx
    }

    /// A field, a file and a last field.
    const FIELD_FILE_FIELD: &[u8] = b"--b\r\nContent-Disposition: form-data; name=\"f1\"\r\n\r\n0123456789\r\n\
--b\r\nContent-Disposition: form-data; name=\"u\"; filename=\"x.bin\"\r\n\r\nABCDEFGHIJ\r\n\
--b\r\nContent-Disposition: form-data; name=\"f2\"\r\n\r\nLASTFIELD\r\n--b--\r\n";

    /// The offset after the first `needle` in `body`.
    fn after(body: &[u8], needle: &[u8]) -> usize {
        body.windows(needle.len()).position(|window| window == needle).unwrap() + needle.len()
    }

    #[test]
    fn files_combined_size_counts_field_data_as_go_does() {
        // Go's processor adds a field's length to the running total as well as a file's
        // (`internal/bodyprocessors/multipart.go:175-183`, go-coraza 1cfa4f955a19), so a size rule such as
        // CRS 920410 sees every part's bytes, not only the files'. Each value below is what Go's processor sets.
        let field = |name: &str, data: &str| {
            format!("--b\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{data}\r\n")
        };
        let file = |data: &str| {
            format!("--b\r\nContent-Disposition: form-data; name=\"u\"; filename=\"a.txt\"\r\n\r\n{data}\r\n")
        };
        let cases: [(&str, String, &str); 7] = [
            ("field only", [field("f", "12345"), CLOSE.into()].concat(), "5"),
            ("file only", [file("12345"), CLOSE.into()].concat(), "5"),
            (
                "mixed",
                [field("f", "12345"), file("abc"), field("g", ""), CLOSE.into()].concat(),
                "8",
            ),
            ("empty parts", [field("f", ""), file(""), CLOSE.into()].concat(), "0"),
            (
                "an empty filename is a field",
                "--b\r\nContent-Disposition: form-data; name=\"u\"; filename=\"\"\r\n\r\nabcd\r\n--b--\r\n".to_owned(),
                "4",
            ),
            (
                "no disposition is a field",
                "--b\r\nX: y\r\n\r\nabcd\r\n--b--\r\n".to_owned(),
                "4",
            ),
            (
                "whole body",
                String::from_utf8(FIELD_FILE_FIELD.to_vec()).unwrap(),
                "29",
            ),
        ];
        for (what, body, want) in cases {
            let tx = process(body.as_bytes());
            assert_eq!(tx.files_combined_size.get(), want, "{what}");
        }
    }

    #[test]
    fn files_combined_size_of_a_body_cut_by_the_limit_counts_what_go_read() {
        // Cut inside the file: the first field and the file's first 5 bytes. Cut inside the last field: both whole
        // parts and its first 4 bytes. Values from Go's processor on the same prefixes, with `INBOUND_DATA_ERROR`.
        let in_file = after(FIELD_FILE_FIELD, b"ABCDE");
        let in_last_field = after(FIELD_FILE_FIELD, b"LAST");
        for (what, limit, want) in [
            ("inside the file", in_file, "15"),
            ("inside the last field", in_last_field, "24"),
        ] {
            let tx = process_cut_at(FIELD_FILE_FIELD, limit);
            assert_eq!(tx.files_combined_size.get(), want, "{what}");
            assert_eq!(tx.multipart_strict_error.get(), "0", "{what}");
        }
    }

    /// One part with `headers` (after its `Content-Disposition`) and `data`, as a body of its own.
    fn part_body(disposition: &str, headers: &[&str], data: &[u8]) -> Vec<u8> {
        let mut body = format!("--b\r\nContent-Disposition: form-data; {disposition}\r\n").into_bytes();
        for header in headers {
            body.extend_from_slice(header.as_bytes());
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n--b--\r\n");
        body
    }

    /// The part headers of `field`, in `Name: value` form.
    fn part_headers(tx: &Transaction, field: &str) -> Vec<String> {
        tx.multipart_part_headers
            .values(field)
            .map(|value| String::from_utf8_lossy(value).into_owned())
            .collect()
    }

    /// The values `map` holds under `key`, in order.
    fn values(map: &crate::collection::Map, key: &str) -> Vec<Vec<u8>> {
        map.values(key).map(<[u8]>::to_vec).collect()
    }

    /// What a part decoded from quoted-printable publishes under its name: the decoded body, as Go publishes it, and
    /// what was sent after it.
    fn decoded_and_sent(decoded: &[u8], sent: &[u8]) -> Vec<Vec<u8>> {
        vec![decoded.to_vec(), sent.to_vec()]
    }

    const QP: &str = "Content-Transfer-Encoding: quoted-printable";

    /// The closing delimiter of a body.
    const CLOSE: &str = "--b--\r\n";

    /// What a quoted-printable body is, and decodes to.
    type DecodeCase<'a> = (&'a str, &'a [u8], &'a [u8]);

    /// What a quoted-printable body is, the error Go reports for it, and what is published of the part.
    type FailureCase<'a> = (&'a str, &'a [u8], &'a str, &'a [u8]);

    #[test]
    fn a_quoted_printable_field_is_decoded_and_published_as_sent() {
        // Go's `NextPart` decodes `Content-Transfer-Encoding: quoted-printable` as the part is read
        // (`mime/multipart/multipart.go`, go1.27.4), so `cmd=3Bcat=20/etc/passwd` is `cmd;cat /etc/passwd` to the
        // rules, and so to a backend that decodes it. A backend that takes the body as sent acts on the encoded
        // text, so that is published under the same name as a second value.
        let encoded = b"cmd=3Bcat=20/etc/passwd";
        let decoded = b"cmd;cat /etc/passwd";
        let rules = "SecRequestBodyAccess On\n\
                     SecRule ARGS_POST \"@contains ;cat /etc/passwd\" \"id:1,phase:2,deny,status:403\"\n\
                     SecRule ARGS_POST \"@contains =3Bcat\" \"id:2,phase:2,deny,status:403\"";
        let tx = process_with_rules(&part_body(r#"name="f""#, &[QP], encoded), rules);

        assert_eq!(tx.reqbody_error.get(), "0");
        assert_eq!(tx.multipart_strict_error.get(), "0");
        assert_eq!(values(&tx.args_post, "f"), decoded_and_sent(decoded, encoded));
        assert_eq!(values(&tx.args, "f"), decoded_and_sent(decoded, encoded));
        // The size counts what was sent: the larger, so a limit on it sees no less than before.
        assert_eq!(tx.files_combined_size.get(), "23");
        assert_eq!(tx.args_combined_size, 44);
        assert_eq!(
            part_headers(&tx, "f"),
            [r#"Content-Disposition: form-data; name="f""#, QP],
            "the encoding header stays a part header, as before the body was decoded"
        );
        assert_eq!(tx.interruption().map(|interruption| interruption.rule_id), Some(1));
        // Each rule alone denies: one reads the decoded text, the other what was sent.
        for (rule, id) in [("@contains ;cat /etc/passwd", 1), ("@contains =3Bcat", 2)] {
            let tx = process_with_rules(
                &part_body(r#"name="f""#, &[QP], encoded),
                &format!("SecRequestBodyAccess On\nSecRule ARGS \"{rule}\" \"id:{id},phase:2,deny,status:403\""),
            );
            assert_eq!(
                tx.interruption().map(|interruption| interruption.rule_id),
                Some(id),
                "{rule}"
            );
        }
    }

    #[test]
    fn a_rule_sees_the_text_a_quoted_printable_field_sent_when_decoding_changes_it() {
        // `=fe` is the byte 0xFE once decoded, so `onfocus=fetch(` is not in the decoded text. A backend that takes
        // the field as sent acts on it (busboy, Starlette's `MultipartParser`, PHP): the rule must match it too.
        let sent = b" autofocus onfocus=fetch('//evil.example') x=";
        let tx = process_with_rules(
            &part_body(r#"name="f""#, &[QP], sent),
            "SecRequestBodyAccess On\nSecRule ARGS \"@contains onfocus=fetch(\" \"id:1,phase:2,deny,status:403\"",
        );

        let [decoded, as_sent] = <[Vec<u8>; 2]>::try_from(values(&tx.args_post, "f")).unwrap();
        assert_eq!(as_sent, sent);
        assert!(!decoded.windows(13).any(|window| window == b"onfocus=fetch"));
        assert_eq!(tx.interruption().map(|interruption| interruption.status), Some(403));
    }

    #[test]
    fn a_quoted_printable_file_is_uploaded_decoded_and_as_sent() {
        let upload_dir = tempfile::tempdir().unwrap();
        let rules = format!("SecRequestBodyAccess On\nSecUploadDir {}", upload_dir.path().display());
        let tx = process_with_rules(
            &part_body(r#"name="u"; filename="a.txt""#, &[QP], b"<?php =65cho 1; ?>=0D=0Aline2"),
            &rules,
        );

        // The decoded upload is first, as in Go, and the file as sent is a second upload with its own path and size.
        assert_eq!(
            values(&tx.files_sizes, "a.txt"),
            [b"23".to_vec(), b"29".to_vec()],
            "decoded size, then sent size"
        );
        assert_eq!(tx.files_combined_size.get(), "29");
        assert_eq!(tx.files.values("").collect::<Vec<_>>(), [&b"a.txt"[..]]);
        assert_eq!(tx.files_names.values("").collect::<Vec<_>>(), [&b"u"[..]]);
        let paths: Vec<_> = tx
            .files_tmp_names
            .values("")
            .map(|path| String::from_utf8(path.to_vec()).unwrap())
            .collect();
        let [decoded, as_sent] = <[String; 2]>::try_from(paths).unwrap();
        assert_eq!(std::fs::read(decoded).unwrap(), b"<?php echo 1; ?>\r\nline2");
        assert_eq!(std::fs::read(as_sent).unwrap(), b"<?php =65cho 1; ?>=0D=0Aline2");
        assert_eq!(
            part_headers(&tx, "u"),
            [r#"Content-Disposition: form-data; name="u"; filename="a.txt""#, QP]
        );
    }

    #[test]
    fn a_quoted_printable_part_that_decoding_does_not_change_is_published_once() {
        let upload_dir = tempfile::tempdir().unwrap();
        let rules = format!("SecRequestBodyAccess On\nSecUploadDir {}", upload_dir.path().display());
        let tx = process_with_rules(
            &part_body(r#"name="f""#, &[QP], b"plain text, nothing to decode"),
            &rules,
        );
        assert_eq!(values(&tx.args_post, "f"), [b"plain text, nothing to decode".to_vec()]);
        assert_eq!(tx.args_combined_size, 30);

        let tx = process_with_rules(
            &part_body(r#"name="u"; filename="a.txt""#, &[QP], b"plain text, nothing to decode"),
            &rules,
        );
        assert_eq!(tx.files_tmp_names.values("").count(), 1);
        assert_eq!(values(&tx.files_sizes, "a.txt"), [b"29".to_vec()]);
    }

    #[test]
    fn the_second_value_of_a_quoted_printable_field_is_not_counted_by_the_argument_limit() {
        // Counting it would let a body of fields that decode drop the fields after it that the base inspected.
        let field = |name: &str, data: &str| {
            format!("--b\r\nContent-Disposition: form-data; name=\"{name}\"\r\n{QP}\r\n\r\n{data}\r\n")
        };
        let body = format!(
            "{}{}{}{CLOSE}",
            field("a", "x=3D1"),
            field("b", "y=3D2"),
            field("c", "plain")
        );
        let process_limited = |limit: usize| {
            process_with_rules(
                body.as_bytes(),
                &format!("SecRequestBodyAccess On\nSecArgumentsLimit {limit}"),
            )
        };
        let tx = process_limited(3);
        assert_eq!(tx.arguments_limit_reached.get(), "0");
        assert_eq!(
            tx.args_post.value_count(),
            5,
            "two fields with two values, and one with one"
        );
        assert_eq!(values(&tx.args_post, "c"), [b"plain".to_vec()]);

        let tx = process_limited(2);
        assert_eq!(tx.arguments_limit_reached.get(), "1");
        assert_eq!(values(&tx.args_post, "a"), decoded_and_sent(b"x=1", b"x=3D1"));
        assert_eq!(values(&tx.args_post, "b"), decoded_and_sent(b"y=2", b"y=3D2"));
        assert!(
            values(&tx.args_post, "c").is_empty(),
            "the third field is past the limit of two"
        );
    }

    #[test]
    fn a_quoted_printable_body_decodes_as_go_does() {
        // Each expectation is what Go's `mime/quotedprintable` hands the processor for the same part body: soft
        // breaks (`=` and the white space after it, then a line end), lowercase hex, `=` kept literally when no two
        // hex digits follow, trailing white space dropped from a line, and bytes of 0x80 and above passed through.
        let cases: [DecodeCase<'_>; 10] = [
            ("lowercase hex", b"cmd=3bcat=2f=2e=2E", b"cmd;cat/.."),
            ("soft breaks", b"a=\r\nb=\nc= \r\nd=\t\r\ne", b"abcde"),
            ("soft break at the end", b"abc=", b"abc"),
            ("invalid escapes stay", b"a=ZZb=4 c=4", b"a=ZZb=4 c=4"),
            ("trailing white space", b"a  \r\nb \t\r\nc  ", b"a\r\nb\r\nc"),
            ("bare CR and LF", b"a\rb\nc\r\nd", b"a\rb\nc\r\nd"),
            ("high bytes", b"a\x80\xffb", b"a\x80\xffb"),
            ("escaped control bytes", b"=00=01=7F=FF", b"\x00\x01\x7f\xff"),
            ("empty", b"", b""),
            (
                "an escape across what a soft break joins",
                b"=\r\n=41=\r\n4=\r\n2",
                b"A42",
            ),
        ];
        for (what, encoded, decoded) in cases {
            let tx = process(&part_body(r#"name="f""#, &[QP], encoded));
            assert_eq!(tx.reqbody_error.get(), "0", "{what}");
            assert_eq!(tx.multipart_strict_error.get(), "0", "{what}");
            // What Go publishes is the first value; the encoded text follows it when decoding changed it.
            let want = if decoded == encoded {
                vec![decoded.to_vec()]
            } else {
                decoded_and_sent(decoded, encoded)
            };
            assert_eq!(values(&tx.args_post, "f"), want, "{what}");
            assert_eq!(tx.files_combined_size.get(), encoded.len().to_string(), "{what}");
        }
    }

    #[test]
    fn the_header_that_selects_decoding_is_matched_as_go_matches_it() {
        // `strings.EqualFold(Header.Get("Content-Transfer-Encoding"), "quoted-printable")`: any spelling of the
        // name, any case of the value, and the value as `textproto` leaves it after trimming. Anything else, a
        // parameter, a folded value or another encoding, is not decoded. Go hides the header of a part it decodes;
        // here every part keeps it, which is what rules that match it read.
        let decoded: [(&str, &str); 3] = [
            ("mixed case", "content-TRANSFER-encoding: Quoted-Printable"),
            ("padded value", "Content-Transfer-Encoding:   quoted-printable  "),
            ("no space after the colon", "Content-Transfer-Encoding:quoted-printable"),
        ];
        for (what, header) in decoded {
            let tx = process(&part_body(r#"name="f""#, &[header], b"a=3Db"));
            assert_eq!(values(&tx.args_post, "f"), decoded_and_sent(b"a=b", b"a=3Db"), "{what}");
            assert_eq!(part_headers(&tx, "f").len(), 2, "{what}: the header stays");
        }
        let kept: [(&str, &str); 5] = [
            ("a parameter", "Content-Transfer-Encoding: quoted-printable; x=y"),
            ("a folded value", "Content-Transfer-Encoding: quoted-\r\n printable"),
            ("7bit", "Content-Transfer-Encoding: 7bit"),
            ("base64", "Content-Transfer-Encoding: base64"),
            ("a name with a space", "Content-Transfer- Encoding: quoted-printable"),
        ];
        for (what, header) in kept {
            let tx = process(&part_body(r#"name="f""#, &[header], b"a=3Db"));
            assert_eq!(values(&tx.args_post, "f"), [b"a=3Db".to_vec()], "{what}");
            assert_eq!(part_headers(&tx, "f").len(), 2, "{what}: the header stays");
        }
    }

    #[test]
    fn a_repeated_encoding_header_stays_and_is_flagged_as_any_repeated_header() {
        // `Header.Get` reads the first value, so the first `quoted-printable` decides. Go deletes every copy before its
        // processor looks for repeated headers; here every copy stays, so rules that match the header still see the
        // payload a second copy carries, and the repeat is flagged as it is for any other header.
        for (what, headers) in [
            ("twice", [QP, QP]),
            ("quoted-printable then 7bit", [QP, "Content-Transfer-Encoding: 7bit"]),
        ] {
            let tx = process(&part_body(r#"name="f""#, &headers, b"a=3Db"));
            assert_eq!(values(&tx.args_post, "f"), decoded_and_sent(b"a=b", b"a=3Db"), "{what}");
            assert_eq!(tx.multipart_strict_error.get(), "1", "{what}");
            assert_eq!(tx.multipart_duplicate_part_header.get(), "1", "{what}");
            assert_eq!(part_headers(&tx, "f").len(), 3, "{what}");
        }
        let tx = process(&part_body(
            r#"name="f""#,
            &["Content-Transfer-Encoding: 7bit", QP],
            b"a=3Db",
        ));
        assert_eq!(values(&tx.args_post, "f"), [b"a=3Db".to_vec()]);
        assert_eq!(tx.multipart_strict_error.get(), "1");
        assert_eq!(tx.multipart_duplicate_part_header.get(), "1");
        assert_eq!(part_headers(&tx, "f").len(), 3);

        // A payload in a second copy of the header is a part header, as before.
        let tx = process(&part_body(
            r#"name="f""#,
            &[QP, "Content-Transfer-Encoding: ;cat /etc/passwd"],
            b"x",
        ));
        assert!(part_headers(&tx, "f").contains(&"Content-Transfer-Encoding: ;cat /etc/passwd".to_owned()));
    }

    #[test]
    fn a_quoted_printable_part_cut_by_the_limit_is_published_decoded_as_far_as_it_was_read() {
        // Go reads the part up to `io.ErrUnexpectedEOF`, which under `ProcessPartial` is the end of what was
        // buffered and not a strict error; the decoded bytes are published (`cmd;cat /etc/pass`, 17) with what was
        // read as sent (21).
        let body = part_body(r#"name="f""#, &[QP], b"cmd=3Bcat=20/etc/passwd");
        let tx = process_cut_at(&body, after(&body, b"/etc/pass"));

        assert_eq!(
            values(&tx.args_post, "f"),
            decoded_and_sent(b"cmd;cat /etc/pass", b"cmd=3Bcat=20/etc/pass")
        );
        assert_eq!(tx.files_combined_size.get(), "21");
        assert_eq!(tx.multipart_strict_error.get(), "0");
        assert_eq!(tx.reqbody_error.get(), "0");
    }

    #[test]
    fn a_doubled_equals_ends_the_decoded_part_and_is_a_strict_error_but_the_parts_after_it_are_read() {
        // Go's reader reports `io.ErrUnexpectedEOF` for the second `=` of `==` before a line end, and its processor
        // flags the strict error and reads no further part. This engine flags it too, and still publishes the
        // parts that follow: they are what a backend that decodes the body differently would act on. What follows
        // the `==` in the part itself is published as sent.
        let mut body = part_body(r#"name="f""#, &[QP], b"a==\r\nb;cat /etc/passwd");
        body.truncate(body.len() - CLOSE.len());
        body.extend_from_slice(b"--b\r\nContent-Disposition: form-data; name=\"g\"\r\n\r\nlater\r\n--b--\r\n");
        let tx = process(&body);

        assert_eq!(
            values(&tx.args_post, "f"),
            decoded_and_sent(b"a", b"a==\r\nb;cat /etc/passwd")
        );
        assert_eq!(values(&tx.args_post, "g"), [b"later".to_vec()]);
        assert_eq!(tx.multipart_strict_error.get(), "1");
        assert_eq!(tx.reqbody_error.get(), "0");
    }

    #[test]
    fn a_later_upload_with_the_same_filename_replaces_both_sizes() {
        // The decoded upload leaves two sizes; the plain one after it, with the same filename and alternate name,
        // must not keep the earlier part's second size beside its own.
        let disposition = r#"name="u"; filename="d.txt"; filename*=UTF-8''r%2Ephp"#;
        let mut body = part_body(disposition, &[QP], b"=41");
        body.truncate(body.len() - CLOSE.len());
        body.extend_from_slice(&part_body(disposition, &[], b"BBBB"));
        let tx = process_with_rules(&body, "SecRequestBodyAccess On");

        for name in ["r.php", "d.txt"] {
            assert_eq!(values(&tx.files_sizes, name), [b"4".to_vec()], "{name}");
        }
    }

    #[test]
    fn a_quoted_printable_part_with_an_extended_filename_is_decoded() {
        let upload_dir = tempfile::tempdir().unwrap();
        let rules = format!("SecRequestBodyAccess On\nSecUploadDir {}", upload_dir.path().display());
        let tx = process_with_rules(
            &part_body(
                r#"name="u"; filename="d.txt"; filename*=UTF-8''r%2Ephp"#,
                &[QP],
                b"x=3Dy",
            ),
            &rules,
        );

        assert_eq!(tx.files.values("").collect::<Vec<_>>(), [&b"r.php"[..], &b"d.txt"[..]]);
        for name in ["r.php", "d.txt"] {
            assert_eq!(values(&tx.files_sizes, name), [b"3".to_vec(), b"5".to_vec()], "{name}");
        }
        assert_eq!(tx.files_combined_size.get(), "5");
        let paths: Vec<_> = tx
            .files_tmp_names
            .values("")
            .map(|path| String::from_utf8(path.to_vec()).unwrap())
            .collect();
        let [decoded, as_sent] = <[String; 2]>::try_from(paths).unwrap();
        assert_eq!(std::fs::read(decoded).unwrap(), b"x=y");
        assert_eq!(std::fs::read(as_sent).unwrap(), b"x=3Dy");
    }

    #[test]
    fn a_quoted_printable_body_go_cannot_read_is_an_error_with_go_s_message() {
        // Go's processor returns the reader's error from the copy, so it reaches `REQBODY_PROCESSOR_ERROR_MSG` as
        // it is, with `MULTIPART_STRICT_ERROR`. The part is published up to the byte that failed, then as sent.
        // Go reads no further part; here the parts after it are read, as a backend that does not stop there would.
        let long = "a".repeat(4097);
        let cases: [FailureCase<'_>; 6] = [
            ("a lone =", b"=", "quotedprintable: invalid bytes after =: \"\"", b""),
            (
                "= before a bare CR",
                b"a=\rb",
                "quotedprintable: invalid hex byte 0x0d",
                b"a",
            ),
            (
                "a control byte",
                b"ok=3Dpart\x01bad",
                "quotedprintable: invalid unescaped byte 0x01 in body",
                b"ok=part",
            ),
            (
                "DEL",
                b"a\x7fb",
                "quotedprintable: invalid unescaped byte 0x7f in body",
                b"a",
            ),
            (
                "a soft break before a bare CR",
                b"a=\r \nb",
                "quotedprintable: invalid bytes after =: \"\\r \\n\"",
                b"a",
            ),
            (
                "a line longer than the 4096 bytes Go reads at once",
                long.as_bytes(),
                "bufio: buffer full",
                long.as_bytes().get(..4096).unwrap(),
            ),
        ];
        for (what, encoded, message, published) in cases {
            let mut body = part_body(r#"name="f""#, &[QP], encoded);
            body.splice(
                0..0,
                b"--b\r\nContent-Disposition: form-data; name=\"before\"\r\n\r\nok\r\n"
                    .iter()
                    .copied(),
            );
            body.truncate(body.len() - CLOSE.len());
            body.extend_from_slice(b"--b\r\nContent-Disposition: form-data; name=\"after\"\r\n\r\nlater\r\n--b--\r\n");
            let tx = process_with_rules(&body, "SecRequestBodyAccess On");
            assert_eq!(tx.reqbody_error.get(), "1", "{what}");
            assert_eq!(tx.reqbody_processor_error_msg.get(), message, "{what}");
            assert_eq!(tx.multipart_strict_error.get(), "1", "{what}");
            assert_eq!(tx.args_post.first(b"before"), Some(&b"ok"[..]), "{what}");
            assert_eq!(
                values(&tx.args_post, "f"),
                decoded_and_sent(published, encoded),
                "{what}: published as far as it was decoded, then as sent"
            );
            assert_eq!(values(&tx.args_post, "after"), [b"later".to_vec()], "{what}");
        }
    }

    #[test]
    fn the_first_quoted_printable_error_is_the_one_reported() {
        // Go stops at the first part it cannot decode, so its message is the one that reaches the rules even when
        // another part after it fails too.
        let mut body = part_body(r#"name="one""#, &[QP], b"a\x01b");
        body.truncate(body.len() - CLOSE.len());
        body.extend_from_slice(&part_body(r#"name="two""#, &[QP], b"c=\rd"));
        let tx = process(&body);
        assert_eq!(tx.reqbody_error.get(), "1");
        assert_eq!(
            tx.reqbody_processor_error_msg.get(),
            "quotedprintable: invalid unescaped byte 0x01 in body"
        );
        assert_eq!(values(&tx.args_post, "two"), decoded_and_sent(b"c", b"c=\rd"));
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

    /// The field after an empty-header part, which a rule must still inspect.
    const SQLI_FIELD: &[u8] = b"1' UNION SELECT password FROM users--";

    /// Rules that deny a SQL injection in any multipart field.
    const SQLI_RULES: &str = "SecRequestBodyAccess On\n\
                              SecRule ARGS_POST \"@detectSQLi\" \"id:1,phase:2,deny,status:403\"";

    #[test]
    fn an_empty_header_part_does_not_hide_the_fields_after_it() {
        // RFC 2046 allows a part with no header fields. Go Coraza publishes it as the
        // nameless field `ARGS_POST[""]` and inspects every part after it. Rejecting
        // it as malformed used to stop parsing there, so `q` was never inspected and
        // a policy without a rule on the error flags let the injection through.
        let body = b"--b\r\n\r\nx\r\n--b\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n1' UNION SELECT password FROM users--\r\n--b--\r\n";
        let tx = process_with_rules(body, SQLI_RULES);

        assert_eq!(tx.reqbody_error.get(), "0");
        assert_eq!(tx.multipart_strict_error.get(), "0");
        assert_eq!(tx.args_post.first(b""), Some(&b"x"[..]));
        assert_eq!(tx.args_post.first(b"q"), Some(SQLI_FIELD));
        assert_eq!(
            tx.interruption()
                .map(|interruption| (interruption.rule_id, interruption.status)),
            Some((1, 403))
        );
    }

    #[test]
    fn an_empty_header_part_in_lf_mode_does_not_hide_the_fields_after_it() {
        // The same shape with bare LF line endings, as the mutation campaign sent it.
        let body = b"--b\n\nMARK1 headerless\n--b\nContent-Disposition: form-data; name=\"q\"\n\n1' UNION SELECT password FROM users--\n--b--\n";
        let tx = process_with_rules(body, SQLI_RULES);

        assert_eq!(tx.reqbody_error.get(), "0");
        assert_eq!(tx.multipart_strict_error.get(), "0");
        assert_eq!(tx.args_post.first(b""), Some(&b"MARK1 headerless"[..]));
        assert_eq!(tx.args_post.first(b"q"), Some(SQLI_FIELD));
        assert_eq!(
            tx.interruption()
                .map(|interruption| (interruption.rule_id, interruption.status)),
            Some((1, 403))
        );
    }

    #[test]
    fn braces_in_content_disposition_parameters_preserve_upload_detection() {
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"up\"; filename=\"shell.php\"; x=y{z}\r\n\
\r\n\
PAYLOAD\r\n\
--b--\r\n";
        let tx = process_with_rules(
            body,
            "SecRequestBodyAccess On\n\
             SecRule FILES \"@streq shell.php\" \"id:1,phase:2,deny,status:403\"",
        );

        assert_eq!(tx.files.first(""), Some(&b"shell.php"[..]));
        assert_eq!(tx.files_names.first(""), Some(&b"up"[..]));
        assert_eq!(tx.multipart_filename.first(b"up"), Some(&b"shell.php"[..]));
        assert_eq!(tx.interruption().map(|interruption| interruption.status), Some(403));
    }

    #[test]
    fn braces_in_content_type_boundary_select_the_multipart_processor() {
        let mut parser = crate::seclang::Parser::new();
        parser.from_string("SecRequestBodyAccess On").unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("multipart-brace-boundary");
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=ab{c");
        tx.process_request_headers();

        assert_eq!(
            tx.process_request_body(
                b"--ab{c\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n--ab{c--\r\n",
            ),
            None
        );
        assert_eq!(tx.args_post.first(b"field"), Some(&b"value"[..]));
        assert_eq!(tx.reqbody_error.get(), "0");
    }

    #[test]
    fn upload_directory_follows_the_platform() {
        #[cfg(target_os = "wasi")]
        assert!(super::upload_directory("").is_none());
        #[cfg(not(target_os = "wasi"))]
        assert!(super::upload_directory("").is_some());
        assert_eq!(super::upload_directory("/tmp/uploads"), Some("/tmp/uploads".into()));
    }

    #[test]
    fn an_upload_path_is_charged_from_the_resolved_directory() {
        // A relative directory is written under the current directory, so that is the path that is retained.
        let resolved = std::path::absolute("relative").unwrap();
        assert_eq!(
            super::upload_path_bytes_of("relative"),
            resolved.to_string_lossy().len() + 32
        );
        let long = format!("/{}", "d".repeat(400));
        assert_eq!(super::upload_path_bytes_of(&long), 401 + 32);
    }

    #[test]
    fn field_only_multipart_does_not_need_an_upload_directory() {
        // A field-only body must not touch `std::env::temp_dir()`, which aborts on WASI.
        let mut parser = crate::seclang::Parser::new();
        parser.from_string("SecRequestBodyAccess On").unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("multipart-field-only");
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=X");
        tx.process_request_headers();

        assert_eq!(
            tx.process_request_body(b"--X\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nAlice\r\n--X--\r\n",),
            None
        );
        assert_eq!(tx.args_post.first(b"name"), Some(&b"Alice"[..]));
        assert_eq!(tx.files.value_count(), 0);
    }

    #[test]
    fn host_policy_rejects_multipart_files_before_creating_a_temporary_upload() {
        let mut parser = crate::seclang::Parser::new();
        parser.from_string("SecRequestBodyAccess On").unwrap();
        parser.config_mut().reject_multipart_file_uploads = true;
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("multipart-file-rejected");
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=b");
        tx.process_request_headers();

        let interruption = tx
            .process_request_body(
                b"--b\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"x.txt\"\r\n\r\nPAYLOAD\r\n--b--\r\n",
            )
            .unwrap();

        assert_eq!(interruption.status, 413);
        assert_eq!(interruption.rule_id, 0);
        assert!(tx.uploaded_paths.is_empty(), "no temporary upload was created");
        assert!(!tx.request_body_stats().spilled, "the body stayed in memory");
        assert_eq!(tx.multipart_strict_error.get(), "1");
    }

    #[test]
    fn detection_only_host_rejection_publishes_parts_without_temporary_uploads() {
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"before\"\r\n\
\r\n\
pre-attack\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"upload\"; filename=\"x.txt\"\r\n\
Content-Type: application/octet-stream\r\n\
\r\n\
PAYLOAD\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"second-upload\"; filename=\"y.txt\"\r\n\
\r\n\
OTHER\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"after\"\r\n\
\r\n\
post-attack\r\n\
--b--\r\n";
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecRuleEngine DetectionOnly\n\
                 SecRule ARGS_POST \"@contains attack\" \"id:2,phase:2,deny,status:403\"",
            )
            .unwrap();
        parser.config_mut().reject_multipart_file_uploads = true;
        parser.config_mut().upload_file_limit = 1;
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("multipart-detection-only-host-policy");
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=b");
        tx.process_request_headers();

        assert_eq!(tx.process_request_body(body), None);

        assert_eq!(tx.args_post.first(b"before"), Some(&b"pre-attack"[..]));
        assert_eq!(tx.args_post.first(b"after"), Some(&b"post-attack"[..]));
        assert!(tx.matched_rules().iter().any(|matched| matched.rule_id() == 2));
        assert_eq!(tx.interruption(), None);
        assert_eq!(
            tx.would_be_interruption().map(|interruption| interruption.status),
            Some(413)
        );
        assert_eq!(tx.files.first(""), Some(&b"x.txt"[..]));
        assert_eq!(tx.files_names.first(""), Some(&b"upload"[..]));
        assert_eq!(
            tx.files.values("").collect::<Vec<_>>(),
            [&b"x.txt"[..], &b"y.txt"[..]],
            "past the file limit FILES still records every upload"
        );
        assert_eq!(tx.files_sizes.value_count(), 2);
        assert_eq!(tx.files_names.value_count(), 2);
        // Both files (7 and 5 bytes) and both fields (10 and 11 bytes), as Go's total.
        assert_eq!(tx.files_combined_size.get(), "33");
        assert_eq!(tx.files_tmp_names.value_count(), 0);
        assert!(tx.uploaded_paths.is_empty());
        assert_eq!(
            tx.multipart_part_headers.first(b"upload"),
            Some(&b"Content-Disposition: form-data; name=\"upload\"; filename=\"x.txt\""[..])
        );
        assert_eq!(tx.multipart_name.first(b"before"), Some(&b"before"[..]));
        assert_eq!(tx.multipart_name.first(b"upload"), Some(&b"upload"[..]));
        assert_eq!(tx.multipart_name.first(b"second-upload"), Some(&b"second-upload"[..]));
        assert_eq!(tx.multipart_name.first(b"after"), Some(&b"after"[..]));
        assert_eq!(tx.multipart_strict_error.get(), "1");
    }

    #[test]
    fn uploads_past_the_file_limit_still_reach_the_files_collections() {
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"decoy\"; filename=\"decoy.txt\"\r\n\
\r\n\
x\r\n\
--b\r\n\
Content-Disposition: form-data; name=\"real\"; filename=\"shell.php\"\r\n\
\r\n\
<?php ?>\r\n\
--b--\r\n";
        let mut parser = crate::seclang::Parser::new();
        parser.from_string("SecRequestBodyAccess On").unwrap();
        parser.config_mut().upload_file_limit = 1;
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("upload-limit-files");
        tx.add_request_header("Content-Type", b"multipart/form-data; boundary=b");
        tx.process_request_headers();

        assert_eq!(tx.process_request_body(body), None);
        assert_eq!(
            tx.files.values("").collect::<Vec<_>>(),
            [&b"decoy.txt"[..], &b"shell.php"[..]]
        );
        assert_eq!(
            tx.files_sizes.value_count(),
            2,
            "the decoy must not hide the real upload's size"
        );
        assert_eq!(
            tx.files_names.values("").collect::<Vec<_>>(),
            [&b"decoy"[..], &b"real"[..]]
        );
        assert_eq!(
            tx.files_tmp_names.value_count(),
            1,
            "only the first upload is written to disk"
        );
        assert_eq!(tx.multipart_strict_error.get(), "1");
    }

    #[test]
    fn a_body_without_a_final_boundary_publishes_its_last_field() {
        let body = b"--b\r\n\
Content-Disposition: form-data; name=\"q\"\r\n\
\r\n\
attack";
        let tx = process(body);

        assert_eq!(
            tx.args_post.first(b"q"),
            Some(&b"attack"[..]),
            "the last part must reach ARGS_POST"
        );
        assert_eq!(tx.reqbody_error.get(), "1", "the missing boundary is still reported");
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
    use super::{
        ContainerIndex, JsonBody, JsonFlattener, json_nesting_exceeds_limit, read_json_body, read_json_body_within,
        read_json_budgeted,
    };
    use crate::{body_processors::budget::MemoryBudget, collection::Map, types::RuleVariable};

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

    #[test]
    fn the_stack_an_index_is_built_with_is_given_back_once_it_is_dropped() {
        // A chain of arrays holds a row for each container that holds another, and the stack of open ones, which
        // is gone when the build ends, was charged a level for each. Only the rows stay charged.
        let depth = 1_000_usize;
        let body = [vec![b'['; depth], vec![b']'; depth]].concat();
        let mut memory = MemoryBudget::new(Some(1 << 20));
        let built = ContainerIndex::build(&body, 10_000, &mut memory);
        assert!(built.is_ok());
        let index = built.unwrap_or_else(|_| ContainerIndex::empty());
        assert_eq!(index.starts.len(), depth - 1);
        let row = 3 * 2 * size_of::<usize>();
        assert_eq!(memory.remaining(), Some((1 << 20) - (depth - 1) * row));
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
                let scanned = read_json_budgeted(
                    &body,
                    depth,
                    limit,
                    &ContainerIndex::empty(),
                    MemoryBudget::default(),
                    &[],
                );
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
    fn without_a_host_budget_only_gos_raw_budget_refuses_a_body() {
        // Go's budget is 8x the body (4096 at least) of the key and value bytes the walk keeps. This transaction
        // adds no limit of its own beyond it: a body is refused exactly when Go would refuse it, whatever the
        // copies it goes on to make, so a valid long-key document is never an error the engine invents.
        let digits = |n: usize| n.to_string().len();
        for key_len in [1_usize, 10, 100, 300, 660, 1000, 5000] {
            for leaves in [1_usize, 2, 5, 12, 20, 50, 100, 500] {
                let key = "k".repeat(key_len);
                let mut body = format!("{{\"{key}\":[").into_bytes();
                body.extend(std::iter::repeat_n(*b"1,", leaves - 1).flatten());
                body.extend_from_slice(b"1]}");

                // `json.<key>.<index>` and the value `1` for each leaf, then the array's length entry.
                let kept: usize = (0..leaves)
                    .map(|index| 4 + 1 + key_len + 1 + digits(index) + 1)
                    .sum::<usize>()
                    + (4 + 1 + key_len)
                    + digits(leaves);
                let budget = (8 * body.len()).max(4096);
                let parsed = read_json_body(&body, 10_000, 0);
                let message = parsed.error.clone().unwrap_or_default();
                assert_eq!(
                    message.starts_with("flattened form exceeds the"),
                    kept > budget,
                    "{key_len} byte key over {leaves} leaves: {kept} kept bytes against {budget}: {message}"
                );
                assert!(!message.contains("retained"), "{message}");
                if kept <= budget {
                    assert_eq!(parsed.error, None);
                    assert_eq!(total_values(&parsed), leaves + 1);
                }
            }
        }
    }

    #[test]
    fn an_invalid_utf8_key_is_charged_its_bytes_and_every_lossy_copy_the_collections_keep() {
        let (post, args) = (Map::new(RuleVariable::ArgsPost), Map::new(RuleVariable::Args));
        // The smallest budget under which the walk is not stopped for memory (the body itself is not valid JSON
        // when its key is not UTF-8, which is reported after the walk and is not the budget's concern).
        let smallest = |body: &[u8]| {
            let stopped = |budget: usize| {
                read_json_body_within(body, 10_000, 0, MemoryBudget::new(Some(budget)), &[&post, &args])
                    .error
                    .is_some_and(|message| message.contains("body memory budget"))
            };
            let (mut low, mut high) = (0_usize, 1 << 24);
            assert!(!stopped(high));
            while low + 1 < high {
                let middle = low + (high - low) / 2;
                if stopped(middle) {
                    low = middle;
                } else {
                    high = middle;
                }
            }
            high
        };
        let key_len = 300_usize;
        let ascii = [&b"{\""[..], &vec![b'k'; key_len], b"\":1}"].concat();
        // Each 0xC3 is not a character alone: one byte in the key, three in its U+FFFD text view.
        let invalid = [&b"{\""[..], &vec![0xC3; key_len], b"\":1}"].concat();
        let (ascii_cost, invalid_cost) = (smallest(&ascii), smallest(&invalid));
        // The flattened key once, and in each of `ARGS_POST` and `ARGS` its bytes and its text view: the key is its
        // own lowercase form, so the value shares it.
        let held_by_invalid_key = key_len * (1 + 2 * (1 + 3));
        assert!(
            invalid_cost >= held_by_invalid_key,
            "{invalid_cost} bytes do not cover the {held_by_invalid_key} the key is held in"
        );
        assert!(
            invalid_cost >= ascii_cost + 2 * 3 * key_len,
            "an invalid key ({invalid_cost}) costs its text views more than a valid one ({ascii_cost})"
        );
        // A key as long as can be asked about does not wrap the arithmetic around.
        let held = [&post, &args];
        let mut flattener = JsonFlattener::new(0, usize::MAX, MemoryBudget::new(Some(usize::MAX)), &held);
        assert!(flattener.reserve_entry(&vec![0xC3; 1024], usize::MAX).is_err());
    }

    #[test]
    fn a_dense_array_is_not_limited_beyond_gos_budget() {
        // The densest ordinary body: single-digit numbers, a leaf per two bytes.
        let body = format!("[{}1]", "1,".repeat(200_000));
        let parsed = read_json_body(body.as_bytes(), 10_000, 0);
        assert_eq!(parsed.error, None);
        assert_eq!(total_values(&parsed), 200_002);
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "custom file tests use fixed fixtures")]
mod custom_file_metadata_tests {
    use std::path::{Path, PathBuf};

    use super::{add_body_processor_file, process_custom_body_processor};
    use crate::{
        body_processors::{
            BodyDirection, BodyProcessor as CustomBodyProcessor, BodyProcessorOptions, BodyProcessorOutput,
        },
        transaction::Transaction,
    };

    /// Bytes the collections `add_body_processor_file` writes hold, by the engine's own estimate.
    fn file_collection_bytes(tx: &Transaction) -> usize {
        [
            &tx.files,
            &tx.files_names,
            &tx.files_sizes,
            &tx.files_tmp_names,
            &tx.multipart_name,
            &tx.multipart_filename,
            &tx.multipart_part_headers,
        ]
        .into_iter()
        .map(crate::collection::Map::allocated_bytes)
        .sum()
    }

    /// A custom file's name, filename and content type.
    type CustomFile = (Vec<u8>, Vec<u8>, Vec<u8>);

    /// Stages `files` in an output with ample budgets, publishes them as the engine does, and returns the metadata
    /// bytes charged with the bytes the collections grew by.
    fn charged_and_measured(files: &[CustomFile], upload_file_limit: usize) -> (usize, usize) {
        let directory = tempfile::tempdir().unwrap();
        let mut output = BodyProcessorOutput::new(0, files.len(), 1 << 30, true)
            .with_upload_path_bytes(directory.path().as_os_str().len());
        for (name, filename, content_type) in files {
            output.add_file(name, filename, content_type, b"x");
        }
        assert_eq!(output.staged_files().len(), files.len(), "every file was staged");

        let config = crate::config::WafConfig {
            upload_file_limit,
            ..crate::config::WafConfig::default()
        };
        let mut tx = Transaction::with_config("custom-file-metadata", std::sync::Arc::new(config));
        let before = file_collection_bytes(&tx);
        for file in output.staged_files() {
            add_body_processor_file(&mut tx, directory.path(), file).unwrap();
        }
        // The native copies of the temporary paths the transaction keeps for cleanup.
        let paths = tx
            .uploaded_paths
            .capacity()
            .saturating_mul(size_of::<PathBuf>())
            .saturating_add(tx.uploaded_paths.iter().map(PathBuf::capacity).sum::<usize>());
        let measured = file_collection_bytes(&tx).saturating_sub(before).saturating_add(paths);
        tx.finish().unwrap();
        (output.metadata_charged(), measured)
    }

    #[test]
    fn the_metadata_charge_covers_what_the_collections_retain() {
        let long_ascii = vec![(vec![b'n'; 4096], vec![b'f'; 4096], vec![b'c'; 512])];
        // Every byte invalid: each copy of the key is held raw and as three-byte replacement characters.
        let invalid_utf8 = vec![(vec![0xFF; 2048], vec![0xFE; 2048], b"text/plain".to_vec())];
        let invalid_names_only = vec![(vec![0x80; 1], vec![0x80; 1], b"t".to_vec())];
        let many_files: Vec<_> = (0..500)
            .map(|index| {
                (
                    format!("field-{index}").into_bytes(),
                    format!("file-{index}.txt").into_bytes(),
                    b"text/plain".to_vec(),
                )
            })
            .collect();
        // The same name for every file: one entry per collection with many values.
        let repeated: Vec<_> = (0..500)
            .map(|_| (b"upload".to_vec(), b"same.txt".to_vec(), b"text/plain".to_vec()))
            .collect();

        for (label, files, upload_file_limit) in [
            ("long ASCII names", long_ascii, 100),
            ("invalid UTF-8 names", invalid_utf8, 100),
            ("a one-byte invalid name", invalid_names_only, 100),
            ("many files", many_files.clone(), 1_000),
            ("many files past the upload limit", many_files, 2),
            ("repeated names", repeated, 1_000),
        ] {
            let (charged, measured) = charged_and_measured(&files, upload_file_limit);
            assert!(
                charged >= measured,
                "{label}: the collections grew by {measured} bytes but only {charged} were charged"
            );
        }
    }

    /// A transaction that accepts `arguments` arguments, so only the output's own budgets can stop a flood.
    fn roomy_transaction(arguments: usize) -> Transaction {
        let config = crate::config::WafConfig {
            argument_limit: arguments,
            ..crate::config::WafConfig::default()
        };
        Transaction::with_config("custom-flood", std::sync::Arc::new(config))
    }

    #[test]
    fn an_xml_flood_stops_at_the_metadata_allowance_with_the_collection_retained_inside_it() {
        // A body of a few bytes can make a processor emit minimal entries without end: staged, each is a few dozen
        // bytes and the content budget (the body limit) admits tens of thousands, but each costs the XML collection
        // hundreds of bytes.
        let mut output = BodyProcessorOutput::new(0, 0, 1 << 20, true);
        for _ in 0..300_000 {
            output.add_xml(b"/*", b"");
        }
        assert!(output.byte_limit_reached);
        assert_eq!(
            output.limit_error,
            "custom body processor collection copies exceeded byte limit"
        );
        assert!(output.xml.len() < 300_000, "staged {}", output.xml.len());

        let mut tx = roomy_transaction(1000);
        for (path, value) in &output.xml {
            tx.request_xml.add_bytes(path, value);
        }
        let retained = tx.request_xml.allocated_bytes();
        assert!(
            retained <= output.metadata_charged() && output.metadata_charged() <= output.metadata_allowance(),
            "{retained} bytes retained, {} charged, {} allowed",
            output.metadata_charged(),
            output.metadata_allowance()
        );
        assert!(
            retained <= 4 << 20,
            "{retained} bytes retained under a 1 MiB body limit"
        );
    }

    #[test]
    fn a_raised_argument_limit_does_not_let_tiny_arguments_retain_more_than_the_allowance() {
        for (copies, label) in [(2, "request"), (1, "response")] {
            let mut output = BodyProcessorOutput::new(300_000, 0, 1 << 20, true).with_argument_copies(copies);
            for index in 0..300_000_u32 {
                output.add_argument(&index.to_le_bytes(), b"");
            }
            assert!(output.byte_limit_reached, "{label}");
            assert_eq!(
                output.limit_error, "custom body processor collection copies exceeded byte limit",
                "{label}"
            );
            assert!(
                !output.argument_limit_reached,
                "{label}: the budget, not the count, stopped it"
            );

            let mut tx = roomy_transaction(300_000);
            for (name, value) in &output.arguments {
                if copies == 2 {
                    tx.add_post_argument(name, value);
                } else {
                    tx.response_args.add_bytes(name, value);
                }
            }
            let retained = if copies == 2 {
                tx.args_post.allocated_bytes() + tx.args.allocated_bytes()
            } else {
                tx.response_args.allocated_bytes()
            };
            assert!(
                retained <= output.metadata_charged() && output.metadata_charged() <= output.metadata_allowance(),
                "{label}: {retained} bytes retained, {} charged, {} allowed",
                output.metadata_charged(),
                output.metadata_allowance()
            );
            assert!(
                retained <= 4 << 20,
                "{label}: {retained} bytes retained under a 1 MiB body limit"
            );
            assert!(
                output.arguments.len() > 1000,
                "{label}: ordinary argument counts still fit"
            );
        }
    }

    /// A processor that stages one file and records the upload directory it was given and what the file cost.
    struct ChargeProbe(std::sync::Mutex<Option<(PathBuf, usize)>>);

    impl CustomBodyProcessor for ChargeProbe {
        fn process(
            &self,
            _body: &[u8],
            _direction: BodyDirection,
            options: &BodyProcessorOptions<'_>,
            out: &mut BodyProcessorOutput,
        ) -> Result<(), String> {
            out.add_file(b"f", b"f.txt", b"text/plain", b"x");
            *self.0.lock().unwrap() = Some((options.upload_dir.to_path_buf(), out.metadata_charged()));
            Ok(())
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_upload_directory_that_is_not_utf8_is_charged_by_its_lossy_path_length() {
        use std::os::unix::ffi::OsStrExt as _;

        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join(std::ffi::OsStr::from_bytes(b"up\xFF\xFEloads"));
        std::fs::create_dir(&directory).unwrap();
        assert!(directory.to_str().is_none(), "the directory is not UTF-8");
        assert!(
            directory.to_string_lossy().len() > directory.as_os_str().len(),
            "the lossy form is longer than the native one"
        );
        let mut tx = Transaction::with_config(
            "lossy-upload-dir",
            std::sync::Arc::new(crate::config::WafConfig::default()),
        );
        let probe = ChargeProbe(std::sync::Mutex::new(None));

        super::process_custom_body_in(&mut tx, b"", BodyDirection::Request, false, &probe, Some(&directory));

        let (_, charged) = probe.0.lock().unwrap().take().unwrap();
        let stored_len = tx.files_tmp_names.first(b"").unwrap().len();
        assert_eq!(
            stored_len,
            tx.uploaded_paths.first().unwrap().to_string_lossy().len(),
            "FILES_TMPNAMES holds the lossy path"
        );
        let mut reference = BodyProcessorOutput::new(0, 1, 1 << 20, true)
            .with_upload_path_bytes(directory.to_string_lossy().len())
            .with_argument_copies(2);
        reference.add_file(b"f", b"f.txt", b"text/plain", b"x");
        assert_eq!(
            charged,
            reference.metadata_charged(),
            "the charge is the lossy directory length plus the file name"
        );
        assert!(
            stored_len <= directory.to_string_lossy().len() + 32,
            "the charge covers the stored path: {stored_len}"
        );
        tx.finish().unwrap();
    }

    #[test]
    fn a_relative_upload_directory_is_charged_by_its_absolute_path_length() {
        // `tempfile` resolves a relative directory against the current directory, so the retained paths carry
        // that prefix. The directory is made inside it, and its name alone is the configured value.
        let current = std::env::current_dir().unwrap();
        let directory = tempfile::tempdir_in(&current).unwrap();
        let relative = directory.path().file_name().unwrap().to_string_lossy().into_owned();
        assert!(Path::new(&relative).is_relative());
        let config = crate::config::WafConfig {
            upload_dir: relative.clone(),
            ..crate::config::WafConfig::default()
        };
        let mut tx = Transaction::with_config("relative-upload-dir", std::sync::Arc::new(config));
        let probe = ChargeProbe(std::sync::Mutex::new(None));

        process_custom_body_processor(&mut tx, b"", BodyDirection::Request, false, &probe);

        let (upload_dir, charged) = probe.0.lock().unwrap().take().unwrap();
        let absolute = current.join(&relative);
        assert_eq!(
            upload_dir, absolute,
            "the processor and the file write share the absolute directory"
        );
        let mut reference = BodyProcessorOutput::new(0, 1, 1 << 20, true)
            // The lossy length, as the production charge uses.
            .with_upload_path_bytes(absolute.to_string_lossy().len())
            .with_argument_copies(2);
        reference.add_file(b"f", b"f.txt", b"text/plain", b"x");
        assert_eq!(charged, reference.metadata_charged());
        let created = tx.uploaded_paths.first().cloned().unwrap();
        assert!(created.starts_with(&absolute), "{created:?}");
        assert!(
            created.as_os_str().len() <= absolute.as_os_str().len() + 32 + 1,
            "the charge covers the retained path"
        );
        tx.finish().unwrap();
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "XML limit tests use fixed fixtures")]
mod xml_limit_tests {
    use std::sync::Arc;

    use super::process_custom_body_processor;
    use crate::{
        body_processors::{
            BodyDirection, BodyProcessor as CustomBodyProcessor, BodyProcessorOptions, BodyProcessorOutput,
        },
        config::WafConfig,
        transaction::Transaction,
        types::RuleVariable,
    };

    /// Whether `variable` is `1`.
    fn raised(tx: &Transaction, variable: RuleVariable) -> bool {
        tx.get_variable(variable, None).as_deref() == Some("1")
    }

    #[test]
    fn an_xml_body_past_the_argument_limit_keeps_the_values_before_it_and_reports_the_limit() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string("SecRequestBodyAccess On\nSecAction \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=XML\"")
            .unwrap();
        let waf = parser.into_waf().unwrap();
        for (count, over) in [(1000, false), (1001, true)] {
            let mut tx = waf.new_transaction();
            tx.add_request_header("Content-Type", "application/xml");
            tx.process_request_headers();
            tx.process_request_body(format!("<r>{}</r>", "<i>1</i>".repeat(count)).as_bytes());
            assert_eq!(raised(&tx, RuleVariable::ArgumentsLimitReached), over, "{count}");
            assert_eq!(raised(&tx, RuleVariable::ReqbodyError), over, "{count}");
            assert_eq!(raised(&tx, RuleVariable::ReqbodyProcessorError), over, "{count}");
            assert_eq!(
                tx.request_xml.value_count(),
                1000,
                "{count}: the prefix stays inspected"
            );
            assert!(
                !tx.request_body_stopped_by_memory_budget(),
                "{count}: the limit is not the budget"
            );
            if over {
                assert_eq!(
                    tx.get_variable(RuleVariable::ReqbodyErrorMsg, None).as_deref(),
                    Some("XML: parsed XML exceeds the 1000 value argument limit")
                );
            }
        }
    }

    #[test]
    fn an_xml_body_that_ends_in_a_tag_is_an_error_unless_a_process_partial_limit_cut_it_there() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRequestBodyAccess On\nSecRequestBodyLimit 19\nSecRequestBodyLimitAction ProcessPartial\n\
                 SecAction \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=XML\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        // The limit keeps `<r a="1"><i b="2" c` of the second body, as Go reads it. The rest was never inspected,
        // but the complete attributes of the tag the cut ended in are published. A body that ends there itself is
        // not well formed, and the tag it ends in would be read by a lenient backend.
        for (body, error, published) in [
            (&b"<r a=\"1\"><i b=\"2\""[..], true, 0),
            (b"<r a=\"1\"><i b=\"2\" c=\"3\"/></r>", false, 2),
        ] {
            let mut tx = waf.new_transaction();
            tx.add_request_header("Content-Type", "application/xml");
            tx.process_request_headers();
            tx.process_request_body(body);
            assert_eq!(raised(&tx, RuleVariable::ReqbodyError), error, "{error}");
            assert_eq!(raised(&tx, RuleVariable::InboundDataError), !error, "{error}");
            assert_eq!(tx.request_xml.value_count(), published, "{error}");
            if error {
                assert_eq!(
                    tx.get_variable(RuleVariable::ReqbodyErrorMsg, None).as_deref(),
                    Some("XML: XML syntax error on line 1: unexpected EOF")
                );
            }
        }
    }

    #[test]
    fn a_process_partial_cut_inside_an_xml_token_inspects_what_the_token_had_read() {
        // The backend gets the whole body, and `PWNED` is before the limit in every one of these. The limit lands
        // in the start tag after a complete attribute, in an attribute's value, or in a reference in text or in an
        // attribute, wherever the padding after the payload puts it.
        let pad = "x".repeat(5000);
        let reference = "&amp;".repeat(1000);
        let bodies = [
            (
                "attribute then a long one",
                format!("<r a=\"PWNED\" b=\"{pad}\"/>"),
                100,
            ),
            (
                "attribute then a long one, deeper",
                format!("<r><i a=\"PWNED\" b=\"{pad}\"/></r>"),
                1000,
            ),
            ("value", format!("<r a=\"PWNED{pad}\"/>"), 12),
            ("attribute then a name", "<r a=\"PWNED\" b=\"x\"/>".to_owned(), 14),
            (
                "attribute then an equal sign",
                "<r a=\"PWNED\" b=\"x\"/>".to_owned(),
                15,
            ),
            ("attribute then a slash", "<r a=\"PWNED\"/>".to_owned(), 13),
            ("reference in an attribute", "<r a=\"PWNED &amp;\"/>".to_owned(), 16),
            ("reference in text", format!("<r>PWNED {reference}</r>"), 10),
            ("html entity", "<r>PWNED &nbsp;</r>".to_owned(), 11),
            ("numeric reference", "<r>PWNED &#x41;</r>".to_owned(), 13),
            // libxml2 in recover mode reads the value and what follows as the parent's text, so a tag that has a
            // parent hides it from the rule if the cut drops it.
            ("unquoted value", format!("<r a=PWNED{pad}/>"), 100),
            ("unquoted value, nested", format!("<p><r a=PWNED{pad}/></p>"), 100),
            (
                "unquoted value, nested, cut after it",
                "<p><r a=PWNED/></p>".to_owned(),
                13,
            ),
            (
                "unquoted value, deeper, after an attribute",
                format!("<a><b><r x=\"1\" a=PWNED{pad}/>"),
                30,
            ),
            ("text, which the cut never hid", "<r>PWNED x</r>".to_owned(), 8),
        ];
        let mut missed = Vec::new();
        for (what, body, limit) in bodies {
            let mut parser = crate::seclang::Parser::new();
            parser
                .from_string(&format!(
                    "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit {limit}\n\
                     SecRequestBodyLimitAction ProcessPartial\n\
                     SecAction \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=XML\"\n\
                     SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,deny,status:400\"\n\
                     SecRule XML:/*|XML://@* \"@contains PWNED\" \"id:2,phase:2,deny,status:403\""
                ))
                .unwrap();
            let waf = parser.into_waf().unwrap();
            let mut tx = waf.new_transaction();
            tx.add_request_header("Content-Type", "application/xml");
            tx.process_request_headers();
            let interruption = tx.process_request_body(body.as_bytes());
            if interruption.map(|i| (i.rule_id, i.status)) != Some((2, 403))
                || !raised(&tx, RuleVariable::InboundDataError)
                || raised(&tx, RuleVariable::ReqbodyError)
            {
                missed.push(format!("{what}: cut at {limit}"));
            }
        }
        assert!(missed.is_empty(), "not detected, or refused: {missed:?}");
        // A cut inside a CDATA section or a UTF-8 character is the syntax error Go gives, a 400.
        for (what, body, limit) in [
            ("CDATA", "<r><![CDATA[PWNED]]></r>".to_owned(), 17),
            ("UTF-8 in text", "<r>PWNED \u{e9}</r>".to_owned(), 10),
            ("UTF-8 in an attribute", "<r a=\"PWNED \u{e9}\"/>".to_owned(), 13),
        ] {
            let mut parser = crate::seclang::Parser::new();
            parser
                .from_string(&format!(
                    "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit {limit}\n\
                     SecRequestBodyLimitAction ProcessPartial\n\
                     SecAction \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=XML\"\n\
                     SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,deny,status:400\""
                ))
                .unwrap();
            let waf = parser.into_waf().unwrap();
            let mut tx = waf.new_transaction();
            tx.add_request_header("Content-Type", "application/xml");
            tx.process_request_headers();
            let interruption = tx.process_request_body(body.as_bytes());
            assert_eq!(
                interruption.map(|i| (i.rule_id, i.status)),
                Some((200_002, 400)),
                "{what}"
            );
        }
    }

    /// Emits its count of XML values.
    struct XmlValues(usize);

    impl CustomBodyProcessor for XmlValues {
        fn process(
            &self,
            _body: &[u8],
            _direction: BodyDirection,
            _options: &BodyProcessorOptions<'_>,
            out: &mut BodyProcessorOutput,
        ) -> Result<(), String> {
            for _ in 0..self.0 {
                out.add_xml(b"/v", b"1");
            }
            Ok(())
        }
    }

    #[test]
    fn custom_xml_values_past_the_argument_limit_are_reported_in_both_directions() {
        for direction in [BodyDirection::Request, BodyDirection::Response] {
            for (count, over) in [(1000, false), (1001, true)] {
                let mut tx = Transaction::with_config("custom-xml-limit", Arc::new(WafConfig::default()));
                process_custom_body_processor(&mut tx, b"", direction, false, &XmlValues(count));
                let (xml, error, message) = match direction {
                    BodyDirection::Request => (
                        &tx.request_xml,
                        RuleVariable::ReqbodyError,
                        RuleVariable::ReqbodyErrorMsg,
                    ),
                    BodyDirection::Response => (
                        &tx.response_xml,
                        RuleVariable::ResBodyError,
                        RuleVariable::ResBodyErrorMsg,
                    ),
                };
                assert_eq!(xml.value_count(), 1000, "{direction:?} {count}");
                assert_eq!(
                    raised(&tx, RuleVariable::ArgumentsLimitReached),
                    over,
                    "{direction:?} {count}"
                );
                assert_eq!(raised(&tx, error), over, "{direction:?} {count}");
                if over {
                    let message = tx.get_variable(message, None).unwrap();
                    assert!(
                        message.ends_with("custom body processor XML output exceeded the 1000 value argument limit"),
                        "{message}"
                    );
                }
            }
        }
    }
}
