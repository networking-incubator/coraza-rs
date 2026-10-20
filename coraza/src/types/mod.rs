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

//! Core type definitions for Coraza WAF.
//!
//! This module contains fundamental types used throughout the WAF including
//! severity levels, processing phases, variable identifiers, and engine configuration.

mod phase;
mod severity;
mod variables;
mod waf;

pub use phase::{ParsePhaseError, RulePhase};
pub use severity::{ParseSeverityError, RuleSeverity};
pub use variables::{ParseVariableError, RuleVariable};
pub use waf::{
    AuditEngineStatus, AuditLogFormat, AuditLogPart, AuditLogParts, AuditLogType, BodyLimitAction,
    ParseAuditEngineStatusError, ParseAuditLogFormatError, ParseAuditLogPartError, ParseAuditLogPartsError,
    ParseAuditLogTypeError, ParseRuleEngineStatusError, RuleEngineStatus, apply_audit_log_parts, parse_audit_log_parts,
};
