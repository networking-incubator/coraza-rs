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

mod operator_parser;
mod variable_parser;

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
