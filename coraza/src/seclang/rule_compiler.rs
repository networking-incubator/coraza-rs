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

//! Rule compilation from SecLang directives.
//!
//! Compiles `SecRule`, `SecAction`, and `SecMarker` directives into rule structures.

use std::{borrow::Cow, collections::BTreeMap};

use winnow::{
    combinator::{alt, delimited, repeat},
    error::EmptyError,
    prelude::*,
    token::{any, take_till},
};

use crate::{
    actions::{ActionType, RuleMetadata, compile_action},
    operators::OperatorContext,
    rules::Rule,
    seclang::{
        CompileError, action_parser::ParsedAction, operator_parser::parse_operator_in, parse_actions,
        parse_variables_in,
    },
    types::RulePhase,
};

/// Fallible result returned while compiling a rule.
type CompileResult<T> = Result<T, CompileError>;

/// [`compile_sec_rule_in`] in the default [`OperatorContext`], where a relative data file
/// is relative to the working directory, and with the built-in default actions, as in a
/// configuration without `SecDefaultAction`.
#[cfg(test)]
pub(crate) fn compile_sec_rule(input: &str) -> CompileResult<Rule> {
    compile_sec_rule_in(input, &OperatorContext::default(), &DefaultActions::default())
}

/// Compiles the arguments of a `SecRule` directive (`VARIABLES OPERATOR ACTIONS`, without
/// `SecRule`) into a rule, creating the operator in `context` and merging the actions
/// with `defaults`.
pub(crate) fn compile_sec_rule_in(
    input: &str,
    context: &OperatorContext<'_>,
    defaults: &DefaultActions,
) -> CompileResult<Rule> {
    let RuleArguments {
        variables: vars,
        operator,
        actions,
    } = RuleArguments::parse(input)?;

    // Parse variables
    let variable_specs = parse_variables_in(vars)
        .map_err(|error| CompileError::new(format!("failed to parse variables '{vars}': {error}")))?;

    // Parse operator
    let rule_operator = parse_operator_in(operator, context)
        .map_err(|error| CompileError::new(format!("failed to parse operator '{operator}': {error}")))?;

    // Parse actions (none if empty)
    let parsed_actions = parse_actions(actions)
        .map_err(|error| CompileError::new(format!("failed to parse actions '{actions}': {error}")))?;

    // Build rule
    let mut rule = Rule::new();

    // Add variables
    for var_spec in variable_specs {
        rule = rule.add_variable(var_spec);
    }

    rule = rule.with_operator(rule_operator);

    add_actions(rule, &parsed_actions, defaults)
}

/// [`compile_sec_action_in`] with the built-in default actions, as in a configuration
/// without `SecDefaultAction`.
#[cfg(test)]
pub(crate) fn compile_sec_action(input: &str) -> CompileResult<Rule> {
    compile_sec_action_in(input, &DefaultActions::default())
}

/// Compiles the actions of a `SecAction` directive (without `SecAction`) into a rule
/// without operator, which always matches, merging them with `defaults`.
pub(crate) fn compile_sec_action_in(input: &str, defaults: &DefaultActions) -> CompileResult<Rule> {
    // Remove quotes from actions
    let actions = remove_matching_quotes(input.trim());

    // Parse actions
    let parsed_actions = parse_actions(actions)
        .map_err(|error| CompileError::new(format!("failed to parse actions '{actions}': {error}")))?;

    // Build rule (no operator, no variables)
    add_actions(Rule::new(), &parsed_actions, defaults)
}

/// Applies a rule's parsed actions to `rule`, merged with the defaults of its phase.
///
/// As in Go Coraza, the defaults' actions other than the disruptive one apply first,
/// then the rule's own, but for `block`. The defaults' disruptive action applies last,
/// if the rule has no other. Without defaults for its phase, a rule keeps its actions
/// as written, `block` included (which then does nothing).
fn add_actions(mut rule: Rule, parsed_actions: &[ParsedAction], defaults: &DefaultActions) -> CompileResult<Rule> {
    let Some(defaults) = defaults.for_phase(phase_of(parsed_actions)?) else {
        apply_actions(&mut rule, parsed_actions)?;
        return Ok(rule);
    };

    apply_actions(&mut rule, &defaults.others)?;
    apply_actions(&mut rule, parsed_actions.iter().filter(|a| a.key != "block"))?;
    if !rule
        .actions()
        .iter()
        .any(|action| action.action_type() == ActionType::Disruptive)
    {
        apply_actions(&mut rule, [&defaults.disruptive])?;
    }
    Ok(rule)
}

/// Applies parsed actions to `rule` in order: metadata actions update its metadata,
/// the others are added to it (a later disruptive action replaces an earlier one).
pub(crate) fn apply_actions<'a>(
    rule: &mut Rule,
    parsed_actions: impl IntoIterator<Item = &'a ParsedAction>,
) -> CompileResult<()> {
    for parsed in parsed_actions {
        if let Some(action) = compile_action(&parsed.key, &parsed.value, rule.metadata_mut())? {
            rule.push_action(action);
        }
    }
    Ok(())
}

/// The phase that the `phase` action among `actions` gives a rule (2 without one).
fn phase_of(actions: &[ParsedAction]) -> CompileResult<RulePhase> {
    let mut metadata = RuleMetadata::new();
    for action in actions.iter().filter(|a| a.key == "phase") {
        compile_action(&action.key, &action.value, &mut metadata)?;
    }
    Ok(metadata.phase)
}

/// The actions `SecDefaultAction` gives the rules of each phase, which rules compiled
/// after it inherit; see `add_actions`.
///
/// Phase 2 has built-in defaults, `phase:2,log,auditlog,pass`, until a
/// `SecDefaultAction` sets its own; the other phases have none.
#[derive(Debug, Clone, Default)]
pub(crate) struct DefaultActions {
    /// Default actions by rule phase.
    phases: BTreeMap<RulePhase, PhaseDefaults>,
}

/// The defaults of one phase.
#[derive(Debug, Clone)]
struct PhaseDefaults {
    /// Actions applied before the rule's own, in order
    others: Vec<ParsedAction>,
    /// Applies when the rule has no disruptive action, or `block`
    disruptive: ParsedAction,
}

impl DefaultActions {
    /// Adds the defaults of one `SecDefaultAction`.
    ///
    /// # Errors
    ///
    /// If `actions` is not valid, names no phase or no disruptive action, holds metadata
    /// actions (`id`, `msg`, `tag`, ...) or transformations, or its phase already has
    /// defaults.
    pub(crate) fn add(&mut self, actions: &str) -> CompileResult<()> {
        const METADATA: [&str; 8] = ["accuracy", "id", "maturity", "msg", "rev", "severity", "tag", "ver"];

        let mut metadata = RuleMetadata::new();
        let mut has_phase = false;
        let mut others = Vec::new();
        let mut disruptive = None;
        for parsed in parse_actions(actions)? {
            if METADATA.contains(&parsed.key.as_str()) {
                return Err(CompileError::new(format!(
                    "SecDefaultAction must not contain metadata actions: {}",
                    parsed.key
                )));
            }
            if parsed.key == "t" {
                return Err(CompileError::new(
                    "SecDefaultAction must not contain transformations (t)".to_owned(),
                ));
            }
            let action = compile_action(&parsed.key, &parsed.value, &mut metadata)?;
            if parsed.key == "phase" {
                has_phase = true;
            } else if action.is_some_and(|a| a.action_type() == ActionType::Disruptive) {
                disruptive = Some(parsed);
            } else {
                others.push(parsed);
            }
        }

        if !has_phase {
            return Err(CompileError::new("SecDefaultAction must contain a phase".to_owned()));
        }
        let disruptive = disruptive
            .ok_or_else(|| CompileError::new("SecDefaultAction must contain a disruptive action".to_owned()))?;
        if self.phases.contains_key(&metadata.phase) {
            return Err(CompileError::new(format!(
                "SecDefaultAction already defined for phase {}",
                metadata.phase
            )));
        }
        self.phases.insert(metadata.phase, PhaseDefaults { others, disruptive });
        Ok(())
    }

    /// Returns configured defaults, or the built-in phase 2 defaults.
    fn for_phase(&self, phase: RulePhase) -> Option<Cow<'_, PhaseDefaults>> {
        match self.phases.get(&phase) {
            Some(defaults) => Some(Cow::Borrowed(defaults)),
            None if phase == RulePhase::RequestBody => {
                let action = |key: &str| ParsedAction {
                    key: key.to_owned(),
                    value: String::new(),
                };
                Some(Cow::Owned(PhaseDefaults {
                    others: vec![action("log"), action("auditlog")],
                    disruptive: action("pass"),
                }))
            },
            None => None,
        }
    }
}

/// Compiles a `SecMarker` directive into a rule.
///
/// Parses the format: `SecMarker LABEL`
///
/// `SecMarker` creates a flow control marker with no evaluation logic.
///
/// # Arguments
///
/// * `input` - Marker label
pub(crate) fn compile_sec_marker(input: &str) -> CompileResult<Rule> {
    let label = remove_matching_quotes(input.trim());
    if label.is_empty() {
        return Err(CompileError::new("SecMarker requires a label".to_owned()));
    }

    // Create marker rule with ID 0 and phase Unknown (matches all phases)
    let mut rule = Rule::new();

    // Set marker label in metadata
    rule.metadata_mut().sec_mark = Some(label.to_owned());
    rule.metadata_mut().phase = RulePhase::Unknown;

    Ok(rule)
}

/// Removes a matching pair of single or double quotes.
fn remove_matching_quotes(input: &str) -> &str {
    input
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .or_else(|| input.strip_prefix('\'').and_then(|rest| rest.strip_suffix('\'')))
        .unwrap_or(input)
}

/// The arguments of a `SecRule`, as written: `VARIABLES "OPERATOR" ["ACTIONS"]`.
#[derive(Debug, PartialEq, Eq)]
struct RuleArguments<'a> {
    /// Variables to inspect, before the operator and its argument.
    variables: &'a str,
    /// Between the quotes, escapes kept
    operator: &'a str,
    /// Between the quotes; empty without actions
    actions: &'a str,
}

impl<'a> RuleArguments<'a> {
    /// Splits `data`: VARIABLES runs to the first space, then OPERATOR is double-quoted, a
    /// backslash escaping the character after it, and ACTIONS takes all that follows, in
    /// double quotes.
    fn parse(data: &'a str) -> CompileResult<Self> {
        let data = data.trim();
        let invalid = |part: &str| CompileError::new(format!("invalid {part} for rule with operator: {data:?}"));

        let (variables, rest) = data.split_once(' ').ok_or_else(|| invalid("format"))?;
        let rest = rest.trim_start();
        if !rest.starts_with('"') {
            return Err(invalid("operator"));
        }
        let (rest, operator) = double_quoted
            .parse_peek(rest)
            .map_err(|_error| CompileError::new(format!("expected terminating quote: {rest:?}")))?;
        let actions = match rest.trim_start() {
            "" => "",
            rest => rest
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
                .ok_or_else(|| invalid("actions"))?,
        };

        Ok(Self {
            variables,
            operator,
            actions,
        })
    }
}

/// Whether a `SecRule` or `SecAction` directive declares another chain link.
pub(super) fn directive_chain_status(line: &str) -> Option<bool> {
    let line = line.trim_start();
    let (directive, options) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    let actions = if directive.eq_ignore_ascii_case("SecRule") {
        RuleArguments::parse(options).map_or("", |args| args.actions)
    } else if directive.eq_ignore_ascii_case("SecAction") {
        remove_matching_quotes(options.trim())
    } else {
        return None;
    };

    Some(parse_actions(actions).is_ok_and(|actions| actions.iter().any(|action| action.key == "chain")))
}

/// `"..."`, in which a backslash escapes the character after it; returns what's between
/// the quotes, escapes kept.
fn double_quoted<'i>(input: &mut &'i str) -> winnow::Result<&'i str, EmptyError> {
    let inside = repeat::<_, _, (), _, _>(0.., alt((('\\', any).void(), take_till(1.., ['\\', '"']).void())));
    delimited('"', inside.take(), '"').parse_next(input)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "rule compiler tests use fixed inputs")]
mod tests {
    use super::*;

    /// `(variables, operator, actions)` of `data`.
    fn split(data: &str) -> CompileResult<(&str, &str, &str)> {
        RuleArguments::parse(data).map(|args| (args.variables, args.operator, args.actions))
    }

    #[test]
    fn test_double_quoted() {
        assert_eq!(double_quoted.parse_peek("\"value\" rest"), Ok((" rest", "value")));
        assert_eq!(
            double_quoted.parse_peek("\"val\\\"ue\" rest"),
            Ok((" rest", "val\\\"ue"))
        );
        // An even number of backslashes doesn't escape the quote
        assert_eq!(double_quoted.parse_peek("\"a\\\\\"b"), Ok(("b", "a\\\\")));
        assert!(double_quoted.parse_peek("\"unclosed").is_err());
        assert!(double_quoted.parse_peek("\"unclosed\\\"").is_err());
        assert!(double_quoted.parse_peek("value\"").is_err());
    }

    #[test]
    fn test_split_rule_arguments() {
        assert_eq!(
            split("ARGS \"@rx attack\" \"id:1,deny\""),
            Ok(("ARGS", "@rx attack", "id:1,deny"))
        );
        assert_eq!(split("ARGS \"@rx attack\""), Ok(("ARGS", "@rx attack", "")));
        assert_eq!(
            split("ARGS \"@rx \\\"quoted\\\"\" \"id:1\""),
            Ok(("ARGS", "@rx \\\"quoted\\\"", "id:1"))
        );
        assert_eq!(
            split("ARGS|REQUEST_HEADERS  \t\"@rx attack\"\t\"id:1\""),
            Ok(("ARGS|REQUEST_HEADERS", "@rx attack", "id:1"))
        );
    }

    #[test]
    fn test_split_rule_arguments_errors() {
        let message = |data| split(data).unwrap_err().message;
        assert_eq!(message("ARGS"), "invalid format for rule with operator: \"ARGS\"");
        assert_eq!(
            message("ARGS @rx"),
            "invalid operator for rule with operator: \"ARGS @rx\""
        );
        assert_eq!(message("ARGS  \"@rx"), "expected terminating quote: \"\\\"@rx\"");
        assert_eq!(
            message("ARGS \"@rx\" id:1"),
            "invalid actions for rule with operator: \"ARGS \\\"@rx\\\" id:1\""
        );
    }

    #[test]
    fn test_compile_sec_rule_simple() {
        let rule = compile_sec_rule("ARGS \"@rx attack\" \"id:1,deny,log\"").unwrap();
        assert_eq!(rule.metadata().id, 1);
        assert!(rule.has_operator());
    }

    #[test]
    fn test_compile_sec_action_simple() {
        let rule = compile_sec_action("\"id:100,nolog\"").unwrap();
        assert_eq!(rule.metadata().id, 100);
        assert!(!rule.has_operator());
    }

    #[test]
    fn test_compile_sec_marker_simple() {
        let rule = compile_sec_marker("BEGIN_TESTS").unwrap();
        assert_eq!(rule.metadata().id, 0);
        assert!(!rule.has_operator());
        assert_eq!(rule.metadata().sec_mark, Some("BEGIN_TESTS".to_owned()));
    }

    #[test]
    fn test_compile_sec_marker_empty() {
        let result = compile_sec_marker("");
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_sec_marker_lone_quote() {
        // Not a pair of quotes around the label, which is the quote
        let rule = compile_sec_marker("\"").unwrap();
        assert_eq!(rule.metadata().sec_mark.as_deref(), Some("\""));
    }

    #[test]
    fn test_unknown_action_is_a_compile_error() {
        let err = compile_sec_action("id:1,unknownaction").unwrap_err();
        assert!(err.message.contains("unknown action"), "{}", err.message);
    }

    #[test]
    fn test_last_disruptive_action_wins() {
        let rule = compile_sec_action("id:1,deny,setvar:tx.a=1,drop").unwrap();
        let names: Vec<&str> = rule.actions().iter().map(|action| action.name.as_str()).collect();
        assert_eq!(names, ["setvar", "drop"]);
    }

    #[test]
    fn test_default_actions_apply_to_explicit_and_builtin_phases() {
        let mut defaults = DefaultActions::default();
        defaults.add("phase:1,log,auditlog,deny,status:403").unwrap();
        let context = OperatorContext::default();

        let rule =
            compile_sec_rule_in("ARGS \"@contains attack\" \"id:1,phase:1,block\"", &context, &defaults).unwrap();
        let names: Vec<&str> = rule.actions().iter().map(|action| action.name.as_str()).collect();
        assert_eq!(names, ["deny"]);
        assert!(rule.metadata().log);
        assert!(rule.metadata().audit_log);
        assert_eq!(rule.metadata().status, 403);

        let rule = compile_sec_rule_in("ARGS \"@contains attack\" \"id:2\"", &context, &defaults).unwrap();
        let names: Vec<&str> = rule.actions().iter().map(|action| action.name.as_str()).collect();
        assert_eq!(names, ["pass"]);
        assert!(rule.metadata().log);
        assert!(rule.metadata().audit_log);
    }
}
