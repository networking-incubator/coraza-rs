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
    AuditEngineStatus, AuditLogPart, BodyLimitAction, ParseAuditEngineStatusError,
    ParseAuditLogPartError, ParseRuleEngineStatusError, RuleEngineStatus,
};
