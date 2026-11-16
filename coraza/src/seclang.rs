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

//! SecLang parsing helpers.

mod action_parser;
mod operator_parser;
mod parser;
mod rule_compiler;
mod variable_parser;

pub(crate) use action_parser::parse_actions;
pub use parser::{ParseError, Parser};

/// Go Coraza's recommended engine configuration, `coraza.conf-recommended`.
///
/// This is a verbatim copy of the file that the pinned Go Coraza release ships;
/// `cargo xtask go-fixtures-check` compares it with that release byte for byte. Load
/// it before a rule set such as the OWASP CRS, then set `SecRuleEngine On`: like
/// upstream, it starts in `DetectionOnly`.
///
/// Its rules turn the engine's error flags into blocks: 200002 (`REQBODY_ERROR`),
/// 200003 (`MULTIPART_STRICT_ERROR`), 200004 and 200005 (`ARGUMENTS_LIMIT_REACHED`)
/// and 200009 (`URI_PARSE_ERROR`); 200000, 200001 and 200006 select the XML and
/// JSON body processors. The CRS reads none of those flags, so without these rules a
/// body that could not be parsed is neither inspected nor blocked.
///
/// The file sets `SecRequestBodyInMemoryLimit` and `SecDataDir`, which need a
/// filesystem. The envoy-coraza filter ships a copy without them as
/// `@recommended-conf`.
pub const RECOMMENDED_CONF: &str = include_str!("../coraza.conf-recommended");

/// Error returned while compiling a SecLang value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompileError {
    /// Human-readable explanation of the parse failure.
    pub(crate) message: String,
}

impl CompileError {
    /// Construct an error with its user-facing message.
    pub(crate) fn new(message: String) -> Self {
        Self { message }
    }
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CompileError {}

impl From<crate::actions::ActionError> for CompileError {
    fn from(error: crate::actions::ActionError) -> Self {
        Self::new(error.to_string())
    }
}
