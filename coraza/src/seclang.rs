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
pub(crate) use variable_parser::parse_variables_in;

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
