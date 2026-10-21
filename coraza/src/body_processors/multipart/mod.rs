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

//! Multipart request body parsing.

mod parser;

pub(crate) use parser::Part;

/// Parse a multipart body using the boundary in its content type.
pub(crate) fn parse<'a>(content_type: &str, body: &'a [u8]) -> Result<Vec<Part<'a>>, String> {
    let content_type = content_type
        .parse::<mime::Mime>()
        .map_err(|error| format!("invalid multipart encoding: invalid content-type: {error}"))?;
    if content_type.type_() != mime::MULTIPART {
        return Err("malformed multipart: not a multipart body".to_owned());
    }
    let boundary = content_type
        .get_param(mime::BOUNDARY)
        .ok_or_else(|| "malformed multipart: missing boundary parameter".to_owned())?;
    parser::MultipartParser::new(boundary.as_str(), body)
        .parse()
        .map_err(|error| format!("malformed multipart: {error}"))
}
