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

//! Parses operator expressions used by `SecRule` directives.

use winnow::{
    combinator::{alt, opt, preceded},
    error::EmptyError,
    prelude::*,
    token::{rest, take_till},
};

use crate::{
    operators::{OperatorContext, OperatorEnum},
    rules::RuleOperator,
    seclang::CompileError,
};

/// The result of parsing an operator expression.
type ParseResult<T> = Result<T, CompileError>;

/// Parse an operator expression with default file and dataset settings.
#[cfg(test)]
fn parse_operator(input: &str) -> ParseResult<RuleOperator> {
    parse_operator_in(input, &OperatorContext::default())
}

/// Parse an operator expression using the provided file and dataset settings.
pub(crate) fn parse_operator_in(input: &str, context: &OperatorContext<'_>) -> ParseResult<RuleOperator> {
    let OperatorSpec {
        function,
        name,
        argument,
    } = operator_spec
        .parse(input.trim())
        .map_err(|_error| CompileError::new("failed to parse operator syntax".to_owned()))?;

    let operator = OperatorEnum::with_context(name, argument, context)
        .map_err(|error| CompileError::new(format!("failed to create @{name} operator: {error}")))?;

    Ok(RuleOperator::new(operator, function.starts_with('!')))
}

/// Operator syntax after splitting its function name from its argument.
#[derive(Debug, PartialEq, Eq)]
struct OperatorSpec<'a> {
    /// `@NAME` or `!@NAME`, or the implicit `@rx` form.
    function: &'a str,
    /// Operator name without `@`.
    name: &'a str,
    /// Trimmed operator argument.
    argument: &'a str,
}

/// Parse `[!]@NAME[ ARGUMENT]`, or `[!]ARGUMENT` as an implicit `@rx`.
///
/// The operator name ends at the first ASCII space, matching Go Coraza.
fn operator_spec<'i>(input: &mut &'i str) -> winnow::Result<OperatorSpec<'i>, EmptyError> {
    let explicit = (
        preceded((opt('!'), '@'), take_till(0.., ' ')).with_taken(),
        opt(preceded(' ', rest)),
    )
        .map(
            |((name, function), argument): ((&str, &str), Option<&str>)| OperatorSpec {
                function: function.trim_end(),
                name: name.trim_end(),
                argument: argument.unwrap_or_default().trim(),
            },
        );
    let implicit = (opt('!'), rest).map(|(negation, argument): (Option<_>, &str)| OperatorSpec {
        function: if negation.is_some() { "!@rx" } else { "@rx" },
        name: "rx",
        argument: argument.trim(),
    });
    alt((explicit, implicit)).parse_next(input)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "operator parser tests use fixed valid inputs")]
mod tests {
    use winnow::Parser as _;

    use super::{operator_spec, parse_operator};
    use crate::{operators::Outputs, transaction::Transaction};

    fn matches(input: &str, value: &str) -> bool {
        parse_operator(input)
            .unwrap()
            .evaluate(&Transaction::new("test"), value.as_bytes(), &mut Outputs::default())
    }

    fn spec(input: &str) -> (&str, &str, &str) {
        let spec = operator_spec.parse(input).unwrap();
        (spec.function, spec.name, spec.argument)
    }

    #[test]
    fn parses_implicit_rx_and_negation() {
        assert_eq!(spec(""), ("@rx", "rx", ""));
        assert_eq!(spec("attack"), ("@rx", "rx", "attack"));
        assert_eq!(spec("!"), ("!@rx", "rx", ""));
        assert_eq!(spec("! attack"), ("!@rx", "rx", "attack"));
        assert!(matches("attack", "an attack"));
        assert!(matches("!attack", "benign"));
        assert!(!matches("!attack", "an attack"));
    }

    #[test]
    fn parses_explicit_operator_and_preserves_argument_spaces() {
        assert_eq!(spec("@rx attack"), ("@rx", "rx", "attack"));
        assert_eq!(spec("!@rx attack"), ("!@rx", "rx", "attack"));
        assert_eq!(spec("@pm"), ("@pm", "pm", ""));
        assert!(matches("@rx   attack   pattern  ", "attack   pattern"));
        assert!(!matches("@rx   attack   pattern  ", "attack pattern"));
    }

    #[test]
    fn operator_name_ends_at_ascii_space() {
        assert_eq!(spec("@rx\tattack"), ("@rx\tattack", "rx\tattack", ""));
        assert_eq!(spec("@rx\t attack"), ("@rx", "rx", "attack"));
    }

    #[test]
    fn unknown_explicit_operator_returns_compile_error() {
        let error = parse_operator("@unknownop test").unwrap_err();
        assert!(error.message.contains("unknown operator"));
    }

    #[test]
    fn operator_lookup_is_case_insensitive() {
        for expression in ["@RX attack", "@rx attack", "@Rx attack"] {
            assert!(matches(expression, "an attack"), "{expression}");
        }
    }
}
