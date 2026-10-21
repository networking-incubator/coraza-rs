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

//! XML body parsing with the behavior of Go Coraza's XML body processor.

mod decoder;
mod tables;

use decoder::{Decoder, Token};

/// XML attributes and text exposed by `REQUEST_XML`.
#[derive(Debug, Default)]
pub(crate) struct Document {
    /// Attribute values in document order.
    pub(crate) attribute_values: Vec<String>,
    /// Non-empty text segments, trimmed and in document order.
    pub(crate) text: Vec<String>,
}

/// Parse a request body, accepting truncated documents as partial input.
pub(crate) fn parse(body: &[u8]) -> Result<Document, String> {
    Document::read(body).map_err(|error| error.to_string())
}

impl Document {
    /// Read as far as the decoder permits; Go Coraza accepts unexpected EOF.
    fn read(xml: &[u8]) -> Result<Self, decoder::DecodeError> {
        let mut decoder = Decoder::new(xml);
        let mut document = Self::default();
        loop {
            match decoder.token() {
                Ok(Some(Token::Start { attribute_values, .. })) => document.attribute_values.extend(attribute_values),
                Ok(Some(Token::CharData(text))) => {
                    let text = text.trim();
                    if !text.is_empty() {
                        document.text.push(text.to_owned());
                    }
                },
                Ok(Some(Token::End(_) | Token::Other)) => {},
                Ok(None) | Err(decoder::DecodeError::UnexpectedEof { .. }) => return Ok(document),
                Err(error) => return Err(error),
            }
        }
    }
}
