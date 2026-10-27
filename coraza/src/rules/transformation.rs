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

//! Transformation pipeline for rule evaluation.
//!
//! This module implements transformation chains that apply multiple transformations
//! sequentially to input values before operator matching. Transformations can be
//! chained together (e.g., `t:lowercase,urlDecode`) and are applied in order.
//!
//! Values pass from one transformation to the next as bytes, so that one can produce
//! bytes that aren't UTF-8 (`t:sha1`, `t:urlDecode` of `%ff`) for the next
//! (`t:hexEncode`). The chain returns bytes to the operator; lossy UTF-8 conversion
//! applies only when a text view is needed, not before matching.
//!
//! # Modes
//!
//! - **Simple Mode**: Apply transformations in sequence, returning the final value
//! - **Multi-Match Mode**: Collect all intermediate transformed values for matching

use std::sync::Arc;

use crate::transformations::{CustomTransformation, Transformation, TransformationError};

/// Built-in function pointers stay direct; dynamic dispatch is limited to custom entries.
#[derive(Clone)]
pub(crate) enum TransformationFunction {
    /// A built-in function pointer, with no dynamic dispatch.
    Builtin(Transformation),
    /// An embedder-supplied transformation.
    Custom(Arc<dyn CustomTransformation>),
}

impl TransformationFunction {
    /// Apply the selected implementation to one value.
    fn apply(&self, input: &[u8]) -> crate::transformations::TransformationResult {
        match self {
            Self::Builtin(function) => function(input),
            Self::Custom(transformation) => transformation.transform(input),
        }
    }
}

/// A transformation in the chain with its name for identification.
#[derive(Clone)]
struct NamedTransformation {
    /// Name used by SecLang and log output.
    name: String,
    /// Function that performs the transformation.
    function: TransformationFunction,
}

/// The transformation's name, as `t:` gives it, rather than a function address.
impl std::fmt::Debug for NamedTransformation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

/// A chain of transformations to apply sequentially.
///
/// Transformations are applied in the order they were added. The output of one
/// transformation becomes the input to the next. Errors are collected but don't
/// stop the chain from executing.
#[derive(Debug, Clone)]
pub struct TransformationChain {
    /// Transformations in application order.
    transformations: Vec<NamedTransformation>,
}

impl TransformationChain {
    /// Create a new empty transformation chain.
    pub fn new() -> Self {
        Self {
            transformations: Vec::new(),
        }
    }

    /// Add a transformation to the chain.
    ///
    /// Transformations are applied in the order they are added.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the transformation (for logging/debugging)
    /// * `function` - The transformation function to apply
    ///
    /// # Returns
    ///
    /// Result indicating success or error if name is empty.
    ///
    /// # Errors
    ///
    /// Returns an error when `name` is empty.
    pub fn add(&mut self, name: impl Into<String>, function: Transformation) -> Result<(), String> {
        let name = name.into();
        if name.is_empty() {
            return Err("transformation name cannot be empty".to_owned());
        }

        self.transformations.push(NamedTransformation {
            name,
            function: TransformationFunction::Builtin(function),
        });
        Ok(())
    }

    /// Add a custom transformation to the chain.
    ///
    /// # Errors
    ///
    /// Returns an error when `name` is empty.
    pub fn add_custom(
        &mut self,
        name: impl Into<String>,
        transformation: Arc<dyn CustomTransformation>,
    ) -> Result<(), String> {
        let name = name.into();
        if name.is_empty() {
            return Err("transformation name cannot be empty".to_owned());
        }

        self.transformations.push(NamedTransformation {
            name,
            function: TransformationFunction::Custom(transformation),
        });
        Ok(())
    }

    /// Clear all transformations from the chain.
    pub fn clear(&mut self) {
        self.transformations.clear();
    }

    /// Get the number of transformations in the chain.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.transformations.len()
    }

    /// Check if the chain is empty.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.transformations.is_empty()
    }

    /// Get the names of all transformations in the chain.
    #[cfg(test)]
    pub fn names(&self) -> Vec<&str> {
        self.transformations.iter().map(|t| t.name.as_str()).collect()
    }

    /// Apply all transformations in the chain sequentially.
    ///
    /// Each transformation's output becomes the next transformation's input.
    /// Errors are collected but don't stop execution.
    ///
    /// # Arguments
    ///
    /// * `input` - The input string to transform
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The final transformed string
    /// - A vector of transformation errors encountered (if any)
    pub fn apply(&self, input: &[u8]) -> (Vec<u8>, Vec<TransformationError>) {
        if self.transformations.is_empty() {
            return (input.to_vec(), Vec::new());
        }

        let mut value = input.to_vec();
        let mut errors = Vec::new();

        for t in &self.transformations {
            let (transformed, _changed, err) = t.function.apply(&value);
            if let Some(e) = err {
                errors.push(e);
                continue;
            }
            value = transformed;
        }

        (value, errors)
    }

    /// Apply all transformations in multi-match mode.
    ///
    /// In multi-match mode, the chain collects all intermediate values that
    /// were changed by transformations. This allows operators to match against
    /// both the original value and all transformed values.
    ///
    /// # Arguments
    ///
    /// * `input` - The input string to transform
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - A vector of all values (original + all changed intermediate values)
    /// - A vector of transformation errors encountered (if any)
    pub fn apply_multimatch(&self, input: &[u8]) -> (Vec<Vec<u8>>, Vec<TransformationError>) {
        // Always include the original value
        let mut values = vec![input.to_vec()];
        let mut errors = Vec::new();

        if self.transformations.is_empty() {
            return (values, errors);
        }

        let mut value = input.to_vec();

        for t in &self.transformations {
            let (transformed, changed, err) = t.function.apply(&value);
            if let Some(e) = err {
                errors.push(e);
                continue;
            }

            // Only collect values that changed
            if changed {
                values.push(transformed.clone());
                value = transformed;
            }
        }

        (values, errors)
    }
}

impl Default for TransformationChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::transformations::{
        CustomTransformation, TransformationResult, hex_encode, lowercase, sha1_hash, uppercase, url_decode,
    };

    // Helper transformations for testing
    fn append_a(input: &[u8]) -> TransformationResult {
        ([input, b"A"].concat(), true, None)
    }

    fn append_b(input: &[u8]) -> TransformationResult {
        ([input, b"B"].concat(), true, None)
    }

    fn error_a(_input: &[u8]) -> TransformationResult {
        (Vec::new(), false, Some(TransformationError::new("errorA")))
    }

    fn error_b(_input: &[u8]) -> TransformationResult {
        (Vec::new(), false, Some(TransformationError::new("errorB")))
    }

    struct ErrorWithOutput;

    impl CustomTransformation for ErrorWithOutput {
        fn transform(&self, _input: &[u8]) -> TransformationResult {
            (
                b"discarded".to_vec(),
                true,
                Some(TransformationError::new("custom error")),
            )
        }
    }

    fn add(chain: &mut TransformationChain, name: &str, function: fn(&[u8]) -> TransformationResult) {
        assert!(
            chain.add(name, function).is_ok(),
            "valid test transformation was rejected"
        );
    }

    // Ported from: coraza/internal/corazawaf/rule_test.go::TestAddTransformation
    #[test]
    fn test_add_transformation() {
        let mut chain = TransformationChain::new();
        let result = chain.add("transformation", append_a);

        assert!(result.is_ok());
        assert_eq!(chain.len(), 1);
    }

    // Ported from: coraza/internal/corazawaf/rule_test.go::TestAddTransformationEmpty
    #[test]
    fn test_add_transformation_empty_name() {
        let mut chain = TransformationChain::new();
        let result = chain.add("", append_a);

        assert!(result.is_err());
        assert_eq!(result.err().as_deref(), Some("transformation name cannot be empty"));
    }

    // Ported from: coraza/internal/corazawaf/rule_test.go::TestClearTransformation
    #[test]
    fn test_clear_transformation() {
        let mut chain = TransformationChain::new();
        add(&mut chain, "trans", append_a);

        assert_eq!(chain.len(), 1);

        chain.clear();

        assert_eq!(chain.len(), 0);
        assert!(chain.is_empty());
    }

    // Ported from: coraza/internal/corazawaf/rule_test.go::TestExecuteTransformations
    #[test]
    fn test_execute_transformations() {
        let mut chain = TransformationChain::new();
        add(&mut chain, "AppendA", append_a);
        add(&mut chain, "AppendB", append_b);

        let (result, errors) = chain.apply(b"input");

        assert_eq!(result, b"inputAB");
        assert!(errors.is_empty());
    }

    // Ported from: coraza/internal/corazawaf/rule_test.go::TestExecuteTransformationsReturnsMultipleErrors
    #[test]
    fn test_execute_transformations_returns_multiple_errors() {
        let mut chain = TransformationChain::new();
        add(&mut chain, "AppendA", error_a);
        add(&mut chain, "AppendB", error_b);

        let (_result, errors) = chain.apply(b"arg");

        assert_eq!(errors.len(), 2);
        assert_eq!(
            errors.iter().map(TransformationError::message).collect::<Vec<_>>(),
            ["errorA", "errorB"]
        );
    }

    #[test]
    fn custom_transform_error_keeps_previous_value_in_both_modes() {
        let mut chain = TransformationChain::new();
        assert!(chain.add_custom("custom", Arc::new(ErrorWithOutput)).is_ok());
        add(&mut chain, "AppendA", append_a);

        let (result, errors) = chain.apply(b"input");
        assert_eq!(result, b"inputA");
        assert_eq!(
            errors.iter().map(TransformationError::message).collect::<Vec<_>>(),
            ["custom error"]
        );

        let (values, errors) = chain.apply_multimatch(b"input");
        assert_eq!(values, [b"input".to_vec(), b"inputA".to_vec()]);
        assert_eq!(
            errors.iter().map(TransformationError::message).collect::<Vec<_>>(),
            ["custom error"]
        );
    }

    // Ported from: coraza/internal/corazawaf/rule_test.go::TestExecuteTransformationsMultiMatch
    #[test]
    fn test_execute_transformations_multimatch() {
        let mut chain = TransformationChain::new();
        add(&mut chain, "AppendA", append_a);
        add(&mut chain, "AppendB", append_b);

        let (values, errors) = chain.apply_multimatch(b"input");

        assert!(errors.is_empty());
        assert_eq!(values.len(), 3);
        assert_eq!(values, vec![b"input".to_vec(), b"inputA".to_vec(), b"inputAB".to_vec()]);
    }

    #[test]
    fn test_empty_chain_apply() {
        let chain = TransformationChain::new();
        let (result, errors) = chain.apply(b"test");

        assert_eq!(result, b"test");
        assert!(errors.is_empty());
    }

    #[test]
    fn test_empty_chain_multimatch() {
        let chain = TransformationChain::new();
        let (values, errors) = chain.apply_multimatch(b"test");

        assert_eq!(values, vec![b"test".to_vec()]);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_real_transformations() {
        let mut chain = TransformationChain::new();
        add(&mut chain, "uppercase", uppercase);
        add(&mut chain, "lowercase", lowercase);

        let (result, errors) = chain.apply(b"HeLLo");

        assert_eq!(result, b"hello");
        assert!(errors.is_empty());
    }

    #[test]
    fn test_multimatch_no_change() {
        // If a transformation doesn't change the value, it shouldn't be included
        fn no_change(input: &[u8]) -> TransformationResult {
            (input.to_vec(), false, None)
        }

        let mut chain = TransformationChain::new();
        add(&mut chain, "append", append_a);
        add(&mut chain, "nochange", no_change);
        add(&mut chain, "append2", append_b);

        let (values, errors) = chain.apply_multimatch(b"input");

        assert!(errors.is_empty());
        // Should have: original "input", changed "inputA", changed "inputAB"
        // The no_change transformation doesn't add a value since changed=false
        assert_eq!(values.len(), 3);
        assert_eq!(values, vec![b"input".to_vec(), b"inputA".to_vec(), b"inputAB".to_vec()]);
    }

    #[test]
    fn test_error_doesnt_stop_chain() {
        let mut chain = TransformationChain::new();
        add(&mut chain, "AppendA", append_a);
        add(&mut chain, "Error", error_a);
        add(&mut chain, "AppendB", append_b);

        let (result, errors) = chain.apply(b"input");

        // Chain should continue despite error
        assert_eq!(result, b"inputAB");
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors.iter().map(TransformationError::message).collect::<Vec<_>>(),
            ["errorA"]
        );
    }

    #[test]
    fn test_names() {
        let mut chain = TransformationChain::new();
        add(&mut chain, "lowercase", lowercase);
        add(&mut chain, "uppercase", uppercase);
        add(&mut chain, "custom", append_a);

        let names = chain.names();
        assert_eq!(names, vec!["lowercase", "uppercase", "custom"]);
    }

    #[test]
    fn test_empty_names() {
        let chain = TransformationChain::new();
        let names = chain.names();
        assert!(names.is_empty());
    }

    #[test]
    fn test_bytes_pass_between_transformations() {
        let mut chain = TransformationChain::new();
        add(&mut chain, "sha1", sha1_hash);
        add(&mut chain, "hexEncode", hex_encode);
        let (result, errors) = chain.apply(b"hello");

        #[cfg(all(feature = "hash-transformations", not(feature = "fips")))]
        {
            assert_eq!(result, b"aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
            assert!(errors.is_empty());
        }
        #[cfg(feature = "fips")]
        {
            assert_eq!(result, b"68656c6c6f");
            assert_eq!(
                errors.iter().map(TransformationError::message).collect::<Vec<_>>(),
                ["sha1 transformation is unavailable in FIPS 140-3 mode"]
            );
        }
        #[cfg(not(any(feature = "fips", feature = "hash-transformations")))]
        {
            assert_eq!(result, b"68656c6c6f");
            assert_eq!(
                errors.iter().map(TransformationError::message).collect::<Vec<_>>(),
                ["sha1 transformation requires the hash-transformations feature"]
            );
        }

        #[cfg(feature = "fips")]
        {
            let mut chain = TransformationChain::new();
            add(&mut chain, "md5", crate::transformations::md5_hash);
            add(&mut chain, "hexEncode", hex_encode);
            let (result, errors) = chain.apply(b"hello");
            assert_eq!(result, b"68656c6c6f");
            assert_eq!(
                errors.iter().map(TransformationError::message).collect::<Vec<_>>(),
                ["md5 transformation is unavailable in FIPS 140-3 mode"]
            );
        }

        let mut chain = TransformationChain::new();
        add(&mut chain, "urlDecode", url_decode);
        add(&mut chain, "hexEncode", hex_encode);
        assert_eq!(chain.apply(b"%ff").0, b"ff");
        // The operator gets each value's bytes, UTF-8 or not, as in Go Coraza
        assert_eq!(
            chain.apply_multimatch(b"%ff").0,
            vec![b"%ff".to_vec(), vec![0xFF], b"ff".to_vec()]
        );
    }

    /// The doc example of `rules::transformation`, before it became internal.
    #[test]
    fn doc_module() {
        use crate::{
            rules::TransformationChain,
            transformations::{lowercase, url_decode},
        };

        let mut chain = TransformationChain::new();
        add(&mut chain, "lowercase", lowercase);
        add(&mut chain, "urlDecode", url_decode);

        let (result, _errors) = chain.apply(b"HELLO%20WORLD");
        assert_eq!(result, b"hello world");
    }

    /// The doc example of `rules::transformation::TransformationChain`, before it became internal.
    #[test]
    fn doc_transformation_chain_type() {
        use crate::{rules::TransformationChain, transformations::lowercase};

        let mut chain = TransformationChain::new();
        add(&mut chain, "lowercase", lowercase);

        let (result, errors) = chain.apply(b"HELLO");
        assert_eq!(result, b"hello");
        assert!(errors.is_empty());
    }

    /// The doc example of `rules::transformation::TransformationChain::clear`, before it became internal.
    #[test]
    fn doc_transformation_chain_clear() {
        use crate::{rules::TransformationChain, transformations::lowercase};

        let mut chain = TransformationChain::new();
        add(&mut chain, "lowercase", lowercase);
        chain.clear();
        assert_eq!(chain.len(), 0);
    }

    /// The doc example of `rules::transformation::TransformationChain::names`, before it became internal.
    #[test]
    fn doc_transformation_chain_names() {
        use crate::{rules::TransformationChain, transformations::lowercase};

        let mut chain = TransformationChain::new();
        add(&mut chain, "lowercase", lowercase);
        add(&mut chain, "urlDecode", lowercase);

        assert_eq!(chain.names(), vec!["lowercase", "urlDecode"]);
    }

    /// The doc example of `rules::transformation::TransformationChain::apply`, before it became internal.
    #[test]
    fn doc_transformation_chain_apply() {
        use crate::{rules::TransformationChain, transformations::lowercase};

        let mut chain = TransformationChain::new();
        add(&mut chain, "lowercase", lowercase);

        let (result, errors) = chain.apply(b"HELLO");
        assert_eq!(result, b"hello");
        assert!(errors.is_empty());
    }

    /// The doc example of `rules::transformation::TransformationChain::apply_multimatch`, before it became internal.
    #[test]
    fn doc_transformation_chain_apply_multimatch() {
        use crate::{rules::TransformationChain, transformations::lowercase};

        let mut chain = TransformationChain::new();
        add(&mut chain, "lowercase", lowercase);

        let (values, errors) = chain.apply_multimatch(b"HELLO");
        assert_eq!(values, vec![b"HELLO".to_vec(), b"hello".to_vec()]);
        assert!(errors.is_empty());
    }
}
