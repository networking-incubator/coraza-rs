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
    io::Write as _,
    path::{Path, PathBuf},
};

use super::{Interruption, Transaction, variables::BodyProcessor};
use crate::{
    body_processors::{multipart, xml},
    transformations::{text_of, url_decode},
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
    pub fn process_request_body(&mut self, body: &[u8]) -> Option<Interruption> {
        if !self.begin_phase(RulePhase::RequestBody) {
            return self.interruption.clone();
        }

        if self.audit_engine != AuditEngineStatus::Off && self.audit_log_parts.contains(&AuditLogPart::RequestBody) {
            let limit = usize::try_from(self.request_body_limit).unwrap_or(0);
            self.audit_request_body.clear();
            self.audit_request_body
                .extend_from_slice(body.get(..body.len().min(limit)).unwrap_or_default());
        }

        if self.request_body_access && !body.is_empty() {
            if self.force_request_body_variable && self.reqbody_processor.get_bytes().is_empty() {
                self.set_request_body_processor("URLENCODED");
            }

            let limit = usize::try_from(self.request_body_limit).unwrap_or(0);
            let mut body = body;
            if body.len() >= limit {
                self.inbound_data_error.set("1");
                if self.config.request_body_limit_action == BodyLimitAction::Reject {
                    self.interrupt(0, "deny", 413, "");
                    if self.interruption.is_some() {
                        return self.interruption.clone();
                    }
                }
                body = body.get(..limit).unwrap_or_default();
            }

            self.inspect_request_body(body);
        }

        self.run_phase(RulePhase::RequestBody);
        self.interruption.clone()
    }

    /// Store and parse the body with the selected processor.
    fn inspect_request_body(&mut self, body: &[u8]) {
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
                    self.add_post_argument(&key, value);
                }
            },
            BodyProcessor::Multipart => {
                if let Err(message) = self.process_multipart_body(body) {
                    self.reqbody_error.set("1");
                    self.reqbody_error_msg.set(format!("MULTIPART: {message}"));
                    self.reqbody_processor_error.set("1");
                    self.reqbody_processor_error_msg.set(message);
                }
            },
            BodyProcessor::Json => {
                let depth_limit = self.config.request_body_json_depth_limit;
                match parse_json(body, depth_limit) {
                    Ok(value) => flatten_json_value(&value, &mut String::from("json"), self, false),
                    Err(message) => {
                        self.reqbody_error.set("1");
                        self.reqbody_error_msg.set(format!("JSON: {message}"));
                        self.reqbody_processor_error.set("1");
                        self.reqbody_processor_error_msg.set(message);
                    },
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
                    let error = format!("malformed xml: {message}");
                    self.reqbody_error.set("1");
                    self.reqbody_error_msg.set(format!("XML: {error}"));
                    self.reqbody_processor_error.set("1");
                    self.reqbody_processor_error_msg.set(error);
                },
            },
        }
    }

    /// Populate multipart fields, metadata, and temporary upload files.
    fn process_multipart_body(&mut self, body: &[u8]) -> Result<(), String> {
        let content_type = self
            .request_headers
            .first("content-type")
            .map(|value| text_of(value).into_owned())
            .unwrap_or_default();
        let parts = multipart::parse(&content_type, body).inspect_err(|_| self.multipart_strict_error.set("1"))?;
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
                self.multipart_part_headers
                    .add(&part.name, format!("{}: {value}", canonical_header_name(name)));
            }
            self.multipart_name.add(&part.name, &part.name);
            if let Some(filename) = &part.filename {
                self.multipart_filename.add(&part.name, filename);
            }
            if let Some(filename) = &part.alt_filename {
                self.multipart_filename.add(&part.name, filename);
            }
            if let Some(encoding) = &part.filename_encoding {
                self.multipart_filename_charset.add(&part.name, &encoding.charset);
                self.multipart_filename_language.add(&part.name, &encoding.language);
            }
            if part.malformed_filename {
                self.multipart_strict_error.set("1");
            }

            let size = u64::try_from(part.data.len()).map_err(|error| format!("multipart size overflow: {error}"))?;
            total_size = total_size
                .checked_add(size)
                .ok_or_else(|| "multipart size overflow".to_owned())?;

            if let Some(filename) = &part.filename {
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
                if let Some(alt_filename) = &part.alt_filename {
                    self.files.add("", alt_filename);
                    self.files_sizes.set_index(alt_filename, 0, size.to_string());
                }
                self.files_names.add("", &part.name);
            } else {
                self.add_post_argument(&part.name, part.data);
            }
        }

        self.files_combined_size.set(total_size.to_string());
        Ok(())
    }

    /// Select a request body processor, retaining its name even when this slice does not
    /// implement that processor.
    pub(super) fn set_request_body_processor(&mut self, name: &str) {
        self.request_body_processor = BodyProcessor::parse(name);
        self.reqbody_processor.set(name.to_ascii_uppercase());
    }
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

/// Format a valid MIME header name as Go's canonical header key.
fn canonical_header_name(name: &str) -> String {
    let is_token = |character: char| character.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(character);
    if !name.chars().all(is_token) {
        return name.to_owned();
    }
    let mut starts_word = true;
    name.chars()
        .map(|character| {
            let character = if starts_word {
                character.to_ascii_uppercase()
            } else {
                character.to_ascii_lowercase()
            };
            starts_word = character == '-';
            character
        })
        .collect()
}

/// Parses URLENCODED pairs in order, preserving decoded value bytes.
pub(super) fn parse_urlencoded(body: &[u8]) -> impl Iterator<Item = (String, Vec<u8>)> + '_ {
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
            let key = text_of(&url_decode(key).0).into_owned();
            let value = url_decode(value).0;
            (key, value)
        })
}

/// Parse JSON and enforce the configured nesting limit.
pub(super) fn parse_json(body: &[u8], depth_limit: usize) -> Result<serde_json::Value, String> {
    let body = String::from_utf8_lossy(body);
    // shortcut: serde_json caps nesting at 128; replace it if configured limits above 128 must work.
    let value = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    if json_depth(&value) > depth_limit {
        return Err(format!("nesting deeper than the limit of {depth_limit}"));
    }
    Ok(value)
}

/// Return the deepest object or array nesting, with scalars at depth zero.
fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Flatten JSON values into the dot-separated `ARGS_POST` names used by Coraza.
pub(super) fn flatten_json_value(value: &serde_json::Value, key: &mut String, tx: &mut Transaction, response: bool) {
    match value {
        serde_json::Value::Object(values) => {
            for (name, value) in values {
                let previous_len = key.len();
                key.push('.');
                key.push_str(name);
                flatten_json_value(value, key, tx, response);
                key.truncate(previous_len);
            }
        },
        serde_json::Value::Array(values) => {
            if !values.is_empty() {
                let length = values.len().to_string();
                if response {
                    tx.add_response_argument(key, length.as_bytes());
                } else {
                    tx.add_post_argument(key, length.as_bytes());
                }
                for (index, value) in values.iter().enumerate() {
                    let previous_len = key.len();
                    key.push('.');
                    key.push_str(&index.to_string());
                    flatten_json_value(value, key, tx, response);
                    key.truncate(previous_len);
                }
            }
        },
        serde_json::Value::String(value) => {
            if response {
                tx.add_response_argument(key, value.as_bytes());
            } else {
                tx.add_post_argument(key, value.as_bytes());
            }
        },
        serde_json::Value::Number(value) => {
            let value = value.to_string();
            if response {
                tx.add_response_argument(key, value.as_bytes());
            } else {
                tx.add_post_argument(key, value.as_bytes());
            }
        },
        serde_json::Value::Bool(value) => {
            let value = value.to_string();
            if response {
                tx.add_response_argument(key, value.as_bytes());
            } else {
                tx.add_post_argument(key, value.as_bytes());
            }
        },
        serde_json::Value::Null => {
            if response {
                tx.add_response_argument(key, b"");
            } else {
                tx.add_post_argument(key, b"");
            }
        },
    }
}
