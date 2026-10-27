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

//! Byte-oriented transformations for WAF rule processing.
//!
//! Transformations accept and return bytes so decoding can preserve values
//! that are not valid UTF-8.

mod complex;
mod encoding;
mod escape;
mod html_entities;
mod simple;
mod unicode_bestfit;

pub use complex::{html_entity_decode, normalise_path, normalise_path_win};
pub use encoding::{
    base64_decode, base64_decode_ext, base64_encode, hex_decode, hex_encode, length, md5_hash, none, remove_nulls,
    replace_nulls, sha1_hash, url_encode,
};
pub use escape::{css_decode, escape_seq_decode, js_decode, url_decode_uni, utf8_to_unicode};
pub use simple::{
    cmd_line, compress_whitespace, lowercase, remove_comments, remove_comments_char, remove_whitespace,
    replace_comments, trim, trim_left, trim_right, uppercase, url_decode,
};

/// Result returned by a transformation.
///
/// The tuple contains the transformed bytes, whether the transformation
/// changed the input, and an optional error for logging.
pub type TransformationResult = (Vec<u8>, bool, Option<TransformationError>);

/// A transformation function used by a rule's transformation chain.
pub type Transformation = fn(&[u8]) -> TransformationResult;

/// A transformation supplied by an embedder and selected with a SecLang `t:` action.
///
/// Implementations receive untrusted input bytes. An error leaves the current value
/// unchanged and does not stop later transformations in the chain. Custom
/// transformations run synchronously on the request path; the engine enforces no
/// timeout or output-size bound, and an implementation can panic or block its caller.
/// This trait is for trusted host code, which must bound its own work and output and
/// avoid panics.
pub trait CustomTransformation: Send + Sync {
    /// Transform `input`, returning bytes, whether they changed, and an optional error.
    fn transform(&self, input: &[u8]) -> TransformationResult;
}

/// Returns bytes as text, borrowing valid UTF-8 and replacing invalid sequences.
pub(crate) fn text_of(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    match std::str::from_utf8(bytes) {
        Ok(text) => std::borrow::Cow::Borrowed(text),
        Err(_) => String::from_utf8_lossy(bytes),
    }
}

/// Error reported by a transformation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformationError {
    /// Message describing the transformation error.
    message: String,
}

impl TransformationError {
    /// Creates an error from a message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for TransformationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "transformation error: {}", self.message)
    }
}

impl std::error::Error for TransformationError {}

#[cfg(test)]
#[expect(clippy::panic, reason = "reachability test uses fixed rules")]
mod tests {
    use crate::seclang::Parser;

    /// Proves each new transformation is reachable from a `SecRule` and affects detection.
    #[test]
    fn new_transformations_are_reachable_from_seclang() {
        for (name, argument, operator) in [
            ("cmdLine", b"C^OMMAND".as_slice(), "@streq command"),
            ("removeComments", b"at/**/tack", "@streq attack"),
            ("removeCommentsChar", b"at/**/tack", "@streq attack"),
            ("replaceComments", b"at/**/tack", "@streq at tack"),
        ] {
            let mut parser = Parser::new();
            parser
                .from_string(&format!("SecRule ARGS \"{operator}\" \"id:90,phase:1,t:{name},deny\""))
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            let waf = parser.into_waf().unwrap_or_else(|error| panic!("{name}: {error:?}"));
            let mut transaction = waf.new_transaction_with_id("transform-reachability");
            transaction.add_get_argument("q", argument);
            let interruption = transaction
                .process_request_headers()
                .unwrap_or_else(|| panic!("{name} did not interrupt"));
            assert_eq!(interruption.rule_id, 90, "{name}");
        }
    }
}
