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
// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! The `@validateSchema` operator: validate a JSON document against a schema.
//!
//! Ported from `internal/operators/validate_schema.go` in Coraza v3.8.1. A
//! match means the document violates the schema. The document comes from
//! `TX.json_response_body` from phase 4 on, otherwise from
//! `TX.json_request_body` from phase 2 on, and otherwise from the inspected
//! value; an empty document is never a violation.
//!
//! `shortcut:` each operator compiles its own schema, where Go shares one
//! compilation per schema content through its memoizer; upgrade if rules
//! reference large schemas many times.

use std::path::Path;

use jsonschema::Validator;
use serde_json::Value;

use crate::{
    operators::{Operator, Outputs},
    transaction::Transaction,
    types::{RulePhase, RuleVariable},
};

/// Validates JSON documents against a compiled JSON Schema.
#[derive(Debug, Clone)]
pub struct ValidateSchema {
    /// The schema compiled once, as Go does when it creates the operator.
    validator: Validator,
}

impl ValidateSchema {
    /// Load and compile the JSON Schema at `base_dir/argument`.
    ///
    /// # Errors
    ///
    /// Returns an error when `argument` is empty, names a file whose extension
    /// is not `.json`, cannot be read, or does not contain a valid JSON Schema.
    pub fn new(base_dir: &Path, argument: &str) -> Result<Self, String> {
        if argument.is_empty() {
            return Err("missing schema file path".to_owned());
        }

        let path = base_dir.join(argument);
        let extension = path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if extension != "json" {
            return Err(format!("unsupported schema type: {extension}, only JSON is supported"));
        }

        let bytes = std::fs::read(&path).map_err(|error| format!("reading schema from root FS: {error}"))?;
        let schema: Value =
            serde_json::from_slice(&bytes).map_err(|error| format!("validating schema as JSON: {error}"))?;
        let validator =
            jsonschema::validator_for(&schema).map_err(|error| format!("compiling JSON schema: {error}"))?;
        Ok(Self { validator })
    }
}

impl Operator for ValidateSchema {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        if let Some(body) = current_json_body(tx) {
            return !is_valid(&self.validator, body.as_bytes());
        }
        !input.is_empty() && !is_valid(&self.validator, input)
    }
}

/// Creates a new `validateSchema` operator.
///
/// # Errors
///
/// Returns an error for an invalid schema path or schema; see [`ValidateSchema::new`].
pub fn validate_schema(base_dir: &Path, argument: &str) -> Result<ValidateSchema, String> {
    ValidateSchema::new(base_dir, argument)
}

/// The JSON document stored on the transaction for the current phase.
///
/// Mirrors Go's phase checks: the response body is read from phase 4 on, and
/// the request body from phase 2 on when no response body is stored.
fn current_json_body(tx: &Transaction) -> Option<String> {
    let phase = tx.last_phase()?;
    if phase >= RulePhase::ResponseBody
        && let Some(body) = tx.get_variable(RuleVariable::TX, Some("json_response_body"))
        && !body.is_empty()
    {
        return Some(body);
    }
    if phase >= RulePhase::RequestBody
        && let Some(body) = tx.get_variable(RuleVariable::TX, Some("json_request_body"))
        && !body.is_empty()
    {
        return Some(body);
    }
    None
}

/// Whether `data` is JSON that satisfies `validator`.
fn is_valid(validator: &Validator, data: &[u8]) -> bool {
    serde_json::from_slice::<Value>(data).is_ok_and(|instance| validator.is_valid(&instance))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "validateSchema tests use fixed schemas")]
mod tests {
    use super::{ValidateSchema, validate_schema};
    use crate::{
        operators::{Operator as _, OperatorContext, OperatorEnum, Outputs},
        transaction::Transaction,
        types::RulePhase,
    };

    const SCHEMA: &str = r#"{
        "type": "object",
        "properties": {"name": {"type": "string"}, "age": {"type": "number"}},
        "required": ["name", "age"]
    }"#;
    const VALID: &[u8] = br#"{"name": "John", "age": 30}"#;
    const MISSING_AGE: &[u8] = br#"{"name": "John"}"#;

    /// Write `contents` to `schema.json` in a fresh directory and load it.
    fn load(contents: &str) -> (tempfile::TempDir, ValidateSchema) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("schema.json"), contents).unwrap();
        let operator = validate_schema(dir.path(), "schema.json").unwrap();
        (dir, operator)
    }

    fn evaluate(operator: &ValidateSchema, input: &[u8]) -> bool {
        evaluate_on(operator, &Transaction::new("validate-schema"), input)
    }

    fn evaluate_on(operator: &ValidateSchema, tx: &Transaction, input: &[u8]) -> bool {
        operator.evaluate(tx, input, &mut Outputs::default())
    }

    #[test]
    fn a_valid_document_is_no_violation() {
        let (_dir, operator) = load(SCHEMA);
        assert!(!evaluate(&operator, VALID), "valid document must not match");
    }

    #[test]
    fn a_missing_required_property_is_a_violation() {
        let (_dir, operator) = load(SCHEMA);
        assert!(evaluate(&operator, MISSING_AGE), "missing age must match");
    }

    #[test]
    fn invalid_json_is_a_violation() {
        let (_dir, operator) = load(SCHEMA);
        assert!(evaluate(&operator, b"{oops"), "malformed JSON must match");
    }

    #[test]
    fn an_empty_document_is_no_violation() {
        let (_dir, operator) = load(SCHEMA);
        assert!(!evaluate(&operator, b""), "empty document must not match");
    }

    #[test]
    fn a_missing_schema_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let error = validate_schema(dir.path(), "missing.json").unwrap_err();
        assert!(error.starts_with("reading schema from root FS:"), "{error}");
    }

    #[test]
    fn an_empty_schema_path_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(validate_schema(dir.path(), "").unwrap_err(), "missing schema file path");
    }

    #[test]
    fn a_non_json_schema_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("schema.xml"), "").unwrap();
        assert_eq!(
            validate_schema(dir.path(), "schema.xml").unwrap_err(),
            "unsupported schema type: xml, only JSON is supported"
        );
    }

    #[test]
    fn a_malformed_schema_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("schema.json"), r#"{"type": "#).unwrap();
        let error = validate_schema(dir.path(), "schema.json").unwrap_err();
        assert!(error.starts_with("validating schema as JSON:"), "{error}");
    }

    #[test]
    fn a_schema_that_does_not_compile_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("schema.json"), r#"{"type": 42}"#).unwrap();
        let error = validate_schema(dir.path(), "schema.json").unwrap_err();
        assert!(error.starts_with("compiling JSON schema:"), "{error}");
    }

    #[test]
    fn the_operator_is_registered_under_its_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("schema.json"), SCHEMA).unwrap();
        let datasets = crate::operators::Datasets::new();
        let context = OperatorContext {
            base_dir: dir.path(),
            datasets: &datasets,
            custom: None,
        };
        assert!(matches!(
            OperatorEnum::with_context("validateSchema", "schema.json", &context),
            Ok(OperatorEnum::ValidateSchema(_))
        ));
    }

    #[test]
    fn the_phase_selects_the_stored_json_body() {
        let (_dir, operator) = load(SCHEMA);
        let mut tx = Transaction::new("validate-schema");
        tx.set_tx_variable("json_request_body", MISSING_AGE);
        tx.process_request_headers();

        // Phase 1 does not read the stored request body.
        assert_eq!(tx.last_phase(), Some(RulePhase::RequestHeaders));
        assert!(
            !evaluate_on(&operator, &tx, b""),
            "phase 1 must ignore TX.json_request_body"
        );

        tx.process_request_body(b"");
        assert_eq!(tx.last_phase(), Some(RulePhase::RequestBody));
        assert!(
            evaluate_on(&operator, &tx, b""),
            "phase 2 must read the stored request body"
        );
    }

    #[test]
    fn the_response_body_wins_from_phase_four() {
        let (_dir, operator) = load(SCHEMA);
        let mut tx = Transaction::new("validate-schema");
        tx.set_tx_variable("json_request_body", VALID);
        tx.set_tx_variable("json_response_body", MISSING_AGE);
        tx.process_request_headers();
        tx.process_request_body(b"");

        // Phase 2 reads only the request body, which is valid.
        assert!(!evaluate_on(&operator, &tx, b""), "phase 2 must read the request body");

        tx.process_response_headers(200, "HTTP/1.1");
        assert_eq!(tx.last_phase(), Some(RulePhase::ResponseHeaders));
        assert!(
            !evaluate_on(&operator, &tx, b""),
            "phase 3 must not read the response body"
        );

        tx.process_response_body(b"");
        assert_eq!(tx.last_phase(), Some(RulePhase::ResponseBody));
        assert!(
            evaluate_on(&operator, &tx, b""),
            "phase 4 must prefer the stored response body"
        );
    }

    #[test]
    fn the_inspected_value_is_used_when_no_body_is_stored() {
        let (_dir, operator) = load(SCHEMA);
        let mut tx = Transaction::new("validate-schema");
        tx.process_request_headers();
        tx.process_request_body(b"");
        assert!(!evaluate(&operator, VALID), "valid value must not match");
        assert!(evaluate(&operator, MISSING_AGE), "invalid value must match");
    }

    #[test]
    fn the_schema_path_is_relative_to_the_base_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("schemas")).unwrap();
        std::fs::write(dir.path().join("schemas").join("api.json"), SCHEMA).unwrap();
        let operator = validate_schema(dir.path(), "schemas/api.json").unwrap();
        assert!(!evaluate(&operator, VALID), "nested schema must load");
    }
}
