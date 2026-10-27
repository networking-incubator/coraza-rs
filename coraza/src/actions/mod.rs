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

//! SecLang action compilation and transaction-phase runtime effects.

use std::{collections::BTreeMap, fmt, sync::Arc};

use crate::{
    body_processors::BodyProcessorFactory,
    operators::{Macro, MacroError},
    rules::TransformationChain,
    transaction::{AllowScope, Transaction},
    transformations::{self, CustomTransformation},
    types::{RulePhase, RuleSeverity},
};

/// An action supplied by an embedder and selected by a SecLang action name.
///
/// Actions run synchronously on the transaction thread. The engine does not catch
/// panics or impose a timeout, so register only trusted implementations that do
/// not panic or block indefinitely.
pub trait CustomAction: Send + Sync {
    /// Returns when this action runs in rule evaluation.
    ///
    /// This is a scheduling class, not a capability boundary: the engine does not
    /// prevent an action from having effects inconsistent with its declared class.
    /// The host must keep the implementation's effects consistent with this value.
    fn action_type(&self) -> ActionType;

    /// Applies the action to a matched rule and its transaction.
    fn evaluate(&self, rule: &RuleMetadata, tx: &mut Transaction);
}

/// Creates a fresh custom action from its SecLang argument.
pub type CustomActionFactory = Arc<dyn Fn(&str) -> Result<Box<dyn CustomAction>, String> + Send + Sync>;

/// Parser-scoped host implementations visible while actions are compiled.
#[derive(Clone, Copy, Default)]
pub(crate) struct ActionCompileContext<'a> {
    /// Registered transformations to consult before built-ins, when compiling parser rules.
    custom_transformations: Option<&'a BTreeMap<String, Arc<dyn CustomTransformation>>>,
    /// Registered actions to consult before built-ins, when compiling parser rules.
    custom_actions: Option<&'a BTreeMap<String, CustomActionFactory>>,
    /// Registered body processors that can be selected by a `ctl` action.
    custom_body_processors: Option<&'a BTreeMap<String, BodyProcessorFactory>>,
}

impl<'a> ActionCompileContext<'a> {
    /// Builds a context over the parser's registered transformations.
    pub(crate) fn with_transformations(
        custom_transformations: &'a BTreeMap<String, Arc<dyn CustomTransformation>>,
    ) -> Self {
        Self {
            custom_transformations: Some(custom_transformations),
            custom_actions: None,
            custom_body_processors: None,
        }
    }

    /// Adds the parser's custom actions to this compile context.
    pub(crate) fn with_actions(mut self, custom_actions: &'a BTreeMap<String, CustomActionFactory>) -> Self {
        self.custom_actions = Some(custom_actions);
        self
    }

    /// Adds body processors that can be selected by a `ctl` action.
    pub(crate) fn with_body_processors(
        mut self,
        custom_body_processors: &'a BTreeMap<String, BodyProcessorFactory>,
    ) -> Self {
        self.custom_body_processors = Some(custom_body_processors);
        self
    }
}

/// Errors while compiling an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActionError {
    /// The action requires a value.
    MissingArguments,
    /// The action does not accept a value.
    UnexpectedArguments,
    /// The value is malformed.
    InvalidArguments(String),
    /// The name is not supported.
    UnknownAction(String),
}

impl fmt::Display for ActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingArguments => f.write_str("missing arguments"),
            Self::UnexpectedArguments => f.write_str("unexpected arguments"),
            Self::InvalidArguments(message) => write!(f, "invalid arguments: {message}"),
            Self::UnknownAction(name) => write!(f, "unknown action: {name}"),
        }
    }
}

impl std::error::Error for ActionError {}

impl From<MacroError> for ActionError {
    fn from(error: MacroError) -> Self {
        Self::InvalidArguments(error.to_string())
    }
}

/// When a compiled action runs in the rule engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionType {
    /// Runs for each matching variable value.
    ///
    /// Custom actions are not restricted to nondisruptive effects by the engine; the
    /// host must keep their effects consistent with this scheduling class.
    Nondisruptive,
    /// Runs after the whole rule chain matches.
    ///
    /// This is a scheduling class, not an enforced capability boundary for custom actions.
    Flow,
    /// Runs after the whole rule chain matches and may interrupt processing.
    ///
    /// This is a scheduling class, not an enforced capability boundary for custom actions.
    Disruptive,
}

/// A runtime action after its name and value have been validated.
#[derive(Clone)]
pub(crate) struct CompiledAction {
    /// Lowercase SecLang action name.
    pub(crate) name: String,
    /// Parsed action argument.
    pub(crate) argument: String,
    /// Point in rule evaluation where the action runs.
    pub(crate) action_type: ActionType,
    /// Built-in name dispatch or a parser-resolved host implementation.
    pub(crate) implementation: ActionImplementation,
}

/// Runtime implementation selected while compiling an action.
#[derive(Clone)]
pub(crate) enum ActionImplementation {
    /// Dispatch through the existing built-in name match.
    Builtin,
    /// Dispatch to the parser-resolved host action.
    Custom(Arc<dyn CustomAction>),
    /// Dispatch a processor factory captured by a compiled `ctl` action.
    BodyProcessor(BodyProcessorFactory),
}

impl fmt::Debug for CompiledAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledAction")
            .field("name", &self.name)
            .field("argument", &self.argument)
            .field("action_type", &self.action_type)
            .finish()
    }
}

impl PartialEq for CompiledAction {
    fn eq(&self, other: &Self) -> bool {
        // Host implementation identity is not comparable; retain name-based equality.
        self.name == other.name
    }
}

impl Eq for CompiledAction {}

impl CompiledAction {
    /// Returns when the action runs.
    pub(crate) fn action_type(&self) -> ActionType {
        self.action_type
    }

    /// Apply the runtime effect of a compiled action.
    pub(crate) fn evaluate(&self, rule: &RuleMetadata, tx: &mut Transaction) {
        match &self.implementation {
            ActionImplementation::Builtin => {},
            ActionImplementation::Custom(action) => {
                action.evaluate(rule, tx);
                return;
            },
            ActionImplementation::BodyProcessor(factory) => {
                tx.apply_ctl_with_body_processor(&self.argument, factory);
                return;
            },
        }

        match self.name.as_str() {
            "deny" => {
                let status = if rule.status == 0 { 403 } else { rule.status };
                tx.interrupt(rule.id, "deny", status, "");
            },
            "drop" => tx.interrupt(rule.id, "drop", rule.status, ""),
            "redirect" => {
                let data = Macro::new(&self.argument).map_or_else(|_| self.argument.clone(), |value| value.expand(tx));
                // Go's `redirect.go` only honors a status a client can redirect with;
                // any other value falls back to 302.
                let status = if matches!(rule.status, 301 | 302 | 303 | 307) {
                    rule.status
                } else {
                    302
                };
                tx.interrupt(rule.id, "redirect", status, &data);
            },
            "allow" => match self.argument.as_str() {
                "" | "all" => tx.allow(AllowScope::All),
                "phase" => tx.allow(AllowScope::Phase),
                "request" => tx.allow(AllowScope::Request),
                _ => {},
            },
            "skip" => {
                if let Ok(count) = self.argument.parse::<i32>() {
                    tx.set_skip(count);
                }
            },
            "skipafter" => tx.set_skip_after(&self.argument),
            "setvar" => tx.apply_setvar(&self.argument),
            "ctl" => tx.apply_ctl(&self.argument),
            "setenv" => tx.apply_setenv(&self.argument),
            // shortcut: process execution and persistent collection effects are deferred.
            _ => {},
        }
    }
}

/// Rule metadata populated while SecLang actions are compiled.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "fields mirror independent SecLang rule actions"
)]
pub struct RuleMetadata {
    /// Rule id set by the `id` action.
    pub(crate) id: i32,
    /// Message template set by the `msg` action.
    pub(crate) msg: Option<Macro>,
    /// Severity set by the `severity` action.
    pub(crate) severity: Option<RuleSeverity>,
    /// Classification tags set by `tag` actions.
    pub(crate) tags: Vec<String>,
    /// Revision set by the `rev` action.
    pub(crate) rev: String,
    /// Rule set version set by the `ver` action.
    pub(crate) ver: String,
    /// Maturity rating set by the `maturity` action.
    pub(crate) maturity: u8,
    /// Accuracy rating set by the `accuracy` action.
    pub(crate) accuracy: u8,
    /// Additional log data template set by the `logdata` action.
    pub(crate) log_data: Option<Macro>,
    /// Response status set by the `status` action.
    pub(crate) status: i32,
    /// Whether matches should be logged.
    pub(crate) log: bool,
    /// Whether matches should be sent to the audit log.
    pub(crate) audit_log: bool,
    /// Whether the rule expects another link in its chain.
    pub(crate) has_chain: bool,
    /// Whether regex captures should be stored.
    pub(crate) capture: bool,
    /// Whether intermediate transformation results should be matched.
    pub(crate) multi_match: bool,
    /// Transformations applied before operator matching.
    pub(crate) transformations: TransformationChain,
    /// Label for a `SecMarker` rule.
    pub(crate) sec_mark: Option<String>,
    /// Rule processing phase.
    pub(crate) phase: RulePhase,
    /// Source file containing the rule.
    pub(crate) file: String,
    /// Line where the rule directive ends.
    pub(crate) line: usize,
    /// Original SecLang directive text.
    pub(crate) raw: String,
}

impl RuleMetadata {
    /// Creates metadata with the built-in rule defaults.
    pub(crate) fn new() -> Self {
        Self {
            id: 0,
            msg: None,
            severity: None,
            tags: Vec::new(),
            rev: String::new(),
            ver: String::new(),
            maturity: 0,
            accuracy: 0,
            log_data: None,
            status: 0,
            log: false,
            audit_log: false,
            has_chain: false,
            capture: false,
            multi_match: false,
            transformations: TransformationChain::new(),
            sec_mark: None,
            phase: RulePhase::RequestBody,
            file: String::new(),
            line: 0,
            raw: String::new(),
        }
    }

    /// Returns the rule id.
    pub fn id(&self) -> i32 {
        self.id
    }

    /// Returns the rule processing phase.
    pub fn phase(&self) -> RulePhase {
        self.phase
    }

    /// Returns the response status configured by the `status` action, or zero when unset.
    pub fn status(&self) -> i32 {
        self.status
    }

    /// Whether matching this rule should be logged.
    pub fn log(&self) -> bool {
        self.log
    }

    /// Whether matching this rule should be included in the audit log.
    pub fn audit_log(&self) -> bool {
        self.audit_log
    }

    /// Returns the rule tags in source order.
    pub(crate) fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Returns the message template as written.
    pub(crate) fn msg(&self) -> Option<&str> {
        self.msg.as_ref().map(Macro::as_str)
    }
}

/// Compile a parsed action, resolving custom implementations before built-ins.
#[expect(
    clippy::too_many_lines,
    reason = "one dispatch keeps SecLang action validation in source order"
)]
pub(crate) fn compile_action(
    name: &str,
    argument: &str,
    metadata: &mut RuleMetadata,
    context: ActionCompileContext<'_>,
) -> Result<Option<CompiledAction>, ActionError> {
    let name = name.to_lowercase();
    if let Some(factory) = context.custom_actions.and_then(|registry| registry.get(&name)) {
        let action = factory(argument).map_err(ActionError::InvalidArguments)?;
        let action_type = action.action_type();
        return Ok(Some(CompiledAction {
            name,
            argument: argument.to_owned(),
            action_type,
            implementation: ActionImplementation::Custom(Arc::from(action)),
        }));
    }

    let action = match name.as_str() {
        "id" => {
            metadata.id = parse_positive_i32(argument, "id")?;
            None
        },
        "msg" => {
            require_argument(argument)?;
            metadata.msg = Some(Macro::new(argument)?);
            None
        },
        "tag" => {
            require_argument(argument)?;
            metadata.tags.push(argument.to_owned());
            None
        },
        "severity" => {
            require_argument(argument)?;
            metadata.severity =
                Some(argument.parse().map_err(|error: crate::types::ParseSeverityError| {
                    ActionError::InvalidArguments(error.to_string())
                })?);
            None
        },
        "rev" => {
            require_argument(argument)?;
            argument.clone_into(&mut metadata.rev);
            None
        },
        "ver" => {
            require_argument(argument)?;
            argument.clone_into(&mut metadata.ver);
            None
        },
        "maturity" => {
            metadata.maturity = parse_level(argument, "maturity")?;
            None
        },
        "accuracy" => {
            metadata.accuracy = parse_level(argument, "accuracy")?;
            None
        },
        "phase" => {
            require_argument(argument)?;
            metadata.phase = argument
                .parse::<RulePhase>()
                .map_err(|error| ActionError::InvalidArguments(error.to_string()))?;
            None
        },
        "log" => {
            require_no_argument(argument)?;
            metadata.log = true;
            metadata.audit_log = true;
            None
        },
        "nolog" => {
            require_no_argument(argument)?;
            metadata.log = false;
            metadata.audit_log = false;
            None
        },
        "auditlog" => {
            require_no_argument(argument)?;
            metadata.audit_log = true;
            None
        },
        "noauditlog" => {
            require_no_argument(argument)?;
            metadata.audit_log = false;
            None
        },
        "logdata" => {
            require_argument(argument)?;
            metadata.log_data = Some(Macro::new(argument)?);
            None
        },
        "capture" => {
            require_no_argument(argument)?;
            metadata.capture = true;
            None
        },
        "multimatch" => {
            require_no_argument(argument)?;
            metadata.multi_match = true;
            None
        },
        "status" => {
            require_argument(argument)?;
            metadata.status = argument
                .parse()
                .map_err(|error| ActionError::InvalidArguments(format!("invalid status code: {error}")))?;
            None
        },
        "t" => {
            require_argument(argument)?;
            if argument.eq_ignore_ascii_case("none") {
                metadata.transformations.clear();
            } else if let Some(transformation) = context
                .custom_transformations
                .and_then(|registry| registry.get(&argument.to_lowercase()))
            {
                metadata
                    .transformations
                    .add_custom(argument, Arc::clone(transformation))
                    .map_err(ActionError::InvalidArguments)?;
            } else {
                let function = transformation_by_name(argument)
                    .ok_or_else(|| ActionError::InvalidArguments(format!("unknown transformation: {argument}")))?;
                metadata
                    .transformations
                    .add(argument, function)
                    .map_err(ActionError::InvalidArguments)?;
            }
            None
        },
        "chain" => {
            require_no_argument(argument)?;
            metadata.has_chain = true;
            None
        },
        "exec" => {
            require_argument(argument)?;
            None
        },
        "expirevar" => {
            let (_, seconds) = argument.split_once('=').ok_or_else(|| {
                ActionError::InvalidArguments("expirevar requires format: variable=seconds".to_owned())
            })?;
            seconds
                .parse::<i64>()
                .map_err(|_error| ActionError::InvalidArguments(format!("invalid expiration time: {seconds}")))?;
            None
        },
        "initcol" => {
            require_argument(argument)?;
            argument
                .split_once('=')
                .ok_or_else(|| ActionError::InvalidArguments("initcol requires format: collection=key".to_owned()))?;
            None
        },
        "deny" | "drop" | "block" | "pass" => {
            require_no_argument(argument)?;
            Some(compiled(name, argument, ActionType::Disruptive))
        },
        "allow" => {
            if !matches!(argument, "" | "phase" | "request") {
                return Err(ActionError::InvalidArguments(format!("invalid argument {argument:?}")));
            }
            Some(compiled(name, argument, ActionType::Disruptive))
        },
        "redirect" => {
            require_argument(argument)?;
            Some(compiled(name, argument, ActionType::Disruptive))
        },
        "skip" => {
            parse_positive_i32(argument, "skip count")?;
            Some(compiled(name, argument, ActionType::Flow))
        },
        "skipafter" => {
            require_argument(argument)?;
            Some(compiled(name, argument, ActionType::Flow))
        },
        "setvar" => {
            validate_setvar(argument)?;
            Some(compiled(name, argument, ActionType::Nondisruptive))
        },
        "ctl" => {
            validate_ctl(argument, context.custom_body_processors)?;
            let mut action = compiled(name, argument, ActionType::Nondisruptive);
            if let Some(factory) = custom_body_processor_for_ctl(argument, context.custom_body_processors) {
                action.implementation = ActionImplementation::BodyProcessor(Arc::clone(factory));
            }
            Some(action)
        },
        "setenv" => {
            require_argument(argument)?;
            let (key, value) = argument
                .split_once('=')
                .ok_or_else(|| ActionError::InvalidArguments("setenv requires format: key=value".to_owned()))?;
            if key.trim().is_empty() || value.is_empty() {
                return Err(ActionError::InvalidArguments("missing env key or value".to_owned()));
            }
            Macro::new(value)?;
            Some(compiled(name, argument, ActionType::Nondisruptive))
        },
        _ => return Err(ActionError::UnknownAction(name)),
    };
    Ok(action)
}

/// Stores a validated action for execution in a later engine layer.
fn compiled(name: String, argument: &str, action_type: ActionType) -> CompiledAction {
    CompiledAction {
        name,
        argument: argument.to_owned(),
        action_type,
        implementation: ActionImplementation::Builtin,
    }
}

/// Rejects actions that require an argument when the parser found none.
fn require_argument(argument: &str) -> Result<(), ActionError> {
    if argument.is_empty() {
        Err(ActionError::MissingArguments)
    } else {
        Ok(())
    }
}

/// Rejects arguments for actions that do not accept them.
fn require_no_argument(argument: &str) -> Result<(), ActionError> {
    if argument.is_empty() {
        Ok(())
    } else {
        Err(ActionError::UnexpectedArguments)
    }
}

/// Parses a positive rule id or flow-control count.
fn parse_positive_i32(value: &str, label: &str) -> Result<i32, ActionError> {
    require_argument(value)?;
    let parsed = value
        .parse::<i32>()
        .map_err(|error| ActionError::InvalidArguments(format!("invalid {label}: {error}")))?;
    if parsed <= 0 {
        return Err(ActionError::InvalidArguments(format!("{label} must be positive")));
    }
    Ok(parsed)
}

/// Parses a SecLang rating from 1 through 9.
fn parse_level(value: &str, label: &str) -> Result<u8, ActionError> {
    let level = value
        .parse::<u8>()
        .map_err(|error| ActionError::InvalidArguments(format!("invalid {label}: {error}")))?;
    if !(1..=9).contains(&level) {
        return Err(ActionError::InvalidArguments(format!(
            "{label} must be between 1 and 9"
        )));
    }
    Ok(level)
}

/// Validates the syntax supported by this port for `setvar`.
fn validate_setvar(argument: &str) -> Result<(), ActionError> {
    require_argument(argument)?;
    let argument = argument.strip_prefix('!').unwrap_or(argument);
    let (collection, key_and_value) = argument
        .split_once('.')
        .ok_or_else(|| ActionError::InvalidArguments("expected syntax TX.{key}={value}".to_owned()))?;
    if !collection.eq_ignore_ascii_case("TX") {
        return Err(ActionError::InvalidArguments("expected collection TX".to_owned()));
    }
    let (key, value) = key_and_value.split_once('=').unwrap_or((key_and_value, ""));
    if key.trim().is_empty() {
        return Err(ActionError::InvalidArguments("expected a non-empty TX key".to_owned()));
    }
    Macro::new(key)?;
    if !value.is_empty() {
        Macro::new(value)?;
    }
    Ok(())
}

/// Validates a `ctl` command without applying its runtime effect.
fn validate_ctl(
    argument: &str,
    custom_body_processors: Option<&BTreeMap<String, BodyProcessorFactory>>,
) -> Result<(), ActionError> {
    require_argument(argument)?;
    let (name, value) = argument
        .split_once('=')
        .ok_or_else(|| ActionError::InvalidArguments("expected command=value".to_owned()))?;
    let valid = match name {
        "ruleEngine" => value.parse::<crate::types::RuleEngineStatus>().is_ok(),
        "requestBodyAccess" | "forceRequestBodyVariable" | "responseBodyAccess" | "forceResponseBodyVariable" => {
            is_on_or_off(value)
        },
        "requestBodyLimit" | "responseBodyLimit" => value.parse::<i64>().is_ok_and(|limit| limit >= 0),
        "requestBodyProcessor" | "responseBodyProcessor" => {
            is_body_processor(value)
                || custom_body_processors.is_some_and(|registry| registry.contains_key(&value.to_lowercase()))
        },
        "ruleRemoveById" => parse_id_range(value).is_ok(),
        // Go reports malformed debug levels at runtime instead of rejecting the rule.
        "ruleRemoveByTag" | "ruleRemoveByMsg" | "hashEngine" | "hashEnforcement" | "debugLogLevel" => true,
        "ruleRemoveTargetById" => value
            .split_once(';')
            .is_some_and(|(ids, target)| parse_id_range(ids).is_ok() && valid_rule_target(target)),
        "ruleRemoveTargetByTag" | "ruleRemoveTargetByMsg" => value
            .split_once(';')
            .is_some_and(|(_, target)| valid_rule_target(target)),
        "auditEngine" => value.parse::<crate::types::AuditEngineStatus>().is_ok(),
        "auditLogParts" => crate::types::apply_audit_log_parts(&[], value).is_ok(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(ActionError::InvalidArguments(format!("invalid ctl command: {name}")))
    }
}

/// Resolve a custom factory for a literal body-processor `ctl` during rule compilation.
fn custom_body_processor_for_ctl<'a>(
    argument: &str,
    custom_body_processors: Option<&'a BTreeMap<String, BodyProcessorFactory>>,
) -> Option<&'a BodyProcessorFactory> {
    let (command, value) = argument.split_once('=')?;
    if !matches!(command, "requestBodyProcessor" | "responseBodyProcessor") {
        return None;
    }
    custom_body_processors?.get(&value.to_lowercase())
}

/// Checks for the accepted `On` and `Off` values.
fn is_on_or_off(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "on" | "off")
}

/// Checks a built-in body processor name.
fn is_body_processor(value: &str) -> bool {
    ["raw", "urlencoded", "multipart", "json", "xml"]
        .iter()
        .any(|name| value.eq_ignore_ascii_case(name))
}

/// Validates a collection selector used by `ruleRemoveTarget`.
fn valid_rule_target(target: &str) -> bool {
    let (collection, key) = target.split_once(':').unwrap_or((target, ""));
    let Ok(variable) = collection.trim().parse::<crate::types::RuleVariable>() else {
        return false;
    };
    let key = key.trim();
    if !key.is_empty() && !variable.can_be_selected() {
        return false;
    }
    let Some(pattern) = key.strip_prefix('/').and_then(|key| key.strip_suffix('/')) else {
        return true;
    };
    !pattern.is_empty() && regex::Regex::new(pattern).is_ok()
}

/// Parses an inclusive rule id range.
fn parse_id_range(value: &str) -> Result<std::ops::RangeInclusive<i32>, ()> {
    let parse = |id: &str| id.parse::<i32>().map_err(|_error| ());
    let range = if let Some((start, end)) = value.split_once('-') {
        parse(start)?..=parse(end)?
    } else {
        let id = parse(value)?;
        id..=id
    };
    (!range.is_empty()).then_some(range).ok_or(())
}

/// Resolves a SecLang transformation name to its implementation.
fn transformation_by_name(name: &str) -> Option<transformations::Transformation> {
    match name.to_ascii_lowercase().as_str() {
        "base64decode" => Some(transformations::base64_decode),
        "base64decodeext" => Some(transformations::base64_decode_ext),
        "base64encode" => Some(transformations::base64_encode),
        "cmdline" => Some(transformations::cmd_line),
        "compresswhitespace" => Some(transformations::compress_whitespace),
        "cssdecode" => Some(transformations::css_decode),
        "escapeseqdecode" => Some(transformations::escape_seq_decode),
        "hexdecode" => Some(transformations::hex_decode),
        "hexencode" => Some(transformations::hex_encode),
        "htmlentitydecode" => Some(transformations::html_entity_decode),
        "jsdecode" => Some(transformations::js_decode),
        "length" => Some(transformations::length),
        "lowercase" => Some(transformations::lowercase),
        "md5" => Some(transformations::md5_hash),
        "none" => Some(transformations::none),
        "normalisepath" | "normalizepath" => Some(transformations::normalise_path),
        "normalisepathwin" | "normalizepathwin" => Some(transformations::normalise_path_win),
        "removecomments" => Some(transformations::remove_comments),
        "removecommentschar" => Some(transformations::remove_comments_char),
        "removenulls" => Some(transformations::remove_nulls),
        "removewhitespace" => Some(transformations::remove_whitespace),
        "replacecomments" => Some(transformations::replace_comments),
        "replacenulls" => Some(transformations::replace_nulls),
        "sha1" => Some(transformations::sha1_hash),
        "trim" => Some(transformations::trim),
        "trimleft" => Some(transformations::trim_left),
        "trimright" => Some(transformations::trim_right),
        "uppercase" => Some(transformations::uppercase),
        "urldecode" => Some(transformations::url_decode),
        "urldecodeuni" => Some(transformations::url_decode_uni),
        "urlencode" => Some(transformations::url_encode),
        "utf8tounicode" => Some(transformations::utf8_to_unicode),
        _ => None,
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "action tests use fixed inputs")]
mod tests {
    use super::{ActionCompileContext, ActionType, RuleMetadata, compile_action};
    use crate::types::{RulePhase, RuleSeverity};

    #[test]
    fn metadata_actions_update_rule_metadata() {
        let mut metadata = RuleMetadata::new();
        let context = ActionCompileContext::default();
        assert!(compile_action("ID", "15", &mut metadata, context).unwrap().is_none());
        assert!(compile_action("phase", "1", &mut metadata, context).unwrap().is_none());
        assert!(
            compile_action("severity", "CRITICAL", &mut metadata, context)
                .unwrap()
                .is_none()
        );
        assert!(
            compile_action("tag", "attack", &mut metadata, context)
                .unwrap()
                .is_none()
        );
        assert!(
            compile_action("t", "lowercase", &mut metadata, context)
                .unwrap()
                .is_none()
        );
        assert_eq!(metadata.id, 15);
        assert_eq!(metadata.phase, RulePhase::RequestHeaders);
        assert_eq!(metadata.severity, Some(RuleSeverity::Critical));
        assert_eq!(metadata.tags, ["attack"]);
        assert_eq!(metadata.transformations.names(), ["lowercase"]);
    }

    #[test]
    fn runtime_actions_are_validated_and_classified() {
        let mut metadata = RuleMetadata::new();
        let context = ActionCompileContext::default();
        let action = compile_action("deny", "", &mut metadata, context).unwrap().unwrap();
        assert_eq!(action.action_type(), ActionType::Disruptive);
        let action = compile_action("skipAfter", "NEXT", &mut metadata, context)
            .unwrap()
            .unwrap();
        assert_eq!(action.action_type(), ActionType::Flow);
        let action = compile_action("setvar", "TX.score=+1", &mut metadata, context)
            .unwrap()
            .unwrap();
        assert_eq!(action.action_type(), ActionType::Nondisruptive);
        assert!(compile_action("deny", "403", &mut metadata, context).is_err());
        assert!(compile_action("skip", "0", &mut metadata, context).is_err());
        assert!(compile_action("unknown", "", &mut metadata, context).is_err());
    }

    #[test]
    fn ctl_validates_body_processors_and_rule_targets() {
        let mut metadata = RuleMetadata::new();
        let context = ActionCompileContext::default();
        for argument in [
            "requestBodyProcessor=JSON",
            "responseBodyLimit=0",
            "ruleRemoveTargetById=1-5;ARGS:user",
            "ruleRemoveTargetByTag=attack;REQUEST_HEADERS:/^x-/",
            "ruleRemoveByTag=",
            "hashEngine=anything",
        ] {
            assert!(
                compile_action("ctl", argument, &mut metadata, context).is_ok(),
                "{argument}"
            );
        }
        for argument in [
            "requestBodyProcessor=YAML",
            "requestBodyLimit=-1",
            "responseBodyLimit=-1",
            "ruleRemoveTargetById=bad;ARGS:user",
            "ruleRemoveTargetByTag=attack;NOT_A_COLLECTION:x",
            "ruleRemoveTargetByTag=attack;REQUEST_URI:key",
            "ruleRemoveTargetByTag=attack;ARGS:/[/",
        ] {
            assert!(
                compile_action("ctl", argument, &mut metadata, context).is_err(),
                "{argument}"
            );
        }
    }

    #[test]
    fn redirect_accepts_the_written_target_without_macro_parsing() {
        let mut metadata = RuleMetadata::new();
        assert!(
            compile_action(
                "redirect",
                "%{unfinished",
                &mut metadata,
                ActionCompileContext::default()
            )
            .is_ok()
        );
    }

    #[test]
    fn redirect_uses_only_client_redirect_statuses() {
        for (configured, expected) in [
            (None, 302),
            (Some(301), 301),
            (Some(302), 302),
            (Some(303), 303),
            (Some(307), 307),
            (Some(401), 302),
            (Some(500), 302),
        ] {
            let status = configured.map_or_else(String::new, |status| format!(",status:{status}"));
            let mut parser = crate::seclang::Parser::new();
            parser
                .from_string(&format!(
                    "SecRule REQUEST_URI \"@rx ^/redirect$\" \
                     \"phase:1,id:1{status},redirect:https://www.example.com\""
                ))
                .unwrap();
            let waf = parser.into_waf().unwrap();
            let mut tx = waf.new_transaction();
            tx.process_uri("/redirect", "GET", "HTTP/1.1");
            tx.process_request_headers();

            assert_eq!(
                tx.interruption().map(|interruption| interruption.status),
                Some(expected),
                "configured status {configured:?}"
            );
        }
    }
}
