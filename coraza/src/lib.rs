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

//! WAF configuration, SecLang rule compilation, request-header and request-body
//! evaluation, transaction variable storage, operators, and transformations for a
//! separate Rust implementation based on Coraza.
//!
//! This crate is not the upstream Go implementation or a complete WAF engine.
//! The port is based on the original Coraza, created by Juan Pablo Tosso and
//! the OWASP Coraza contributors.

mod actions;
pub mod collection;
pub mod config;
pub mod operators;
mod rules;
pub mod seclang;
pub mod transaction;
pub mod transformations;
pub mod types;
pub mod utils;
pub mod waf;

pub use rules::TransformationChain;
pub use types::{
    AuditEngineStatus, AuditLogPart, AuditLogParts, BodyLimitAction, RuleEngineStatus, RulePhase, RuleSeverity,
    RuleVariable,
};
pub use waf::{ConfigError, Waf};
