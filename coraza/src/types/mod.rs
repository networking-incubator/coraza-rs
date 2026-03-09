// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Core type definitions for Coraza WAF.
//!
//! This module contains fundamental types used throughout the WAF including
//! severity levels, processing phases, and variable identifiers.

mod severity;

pub use severity::{ParseSeverityError, RuleSeverity};
