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

use std::fmt;

use crate::{
    operators::{Macro, MacroError},
    rules::TransformationChain,
    transaction::Transaction,
    transformations,
    types::{RulePhase, RuleSeverity},
};

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
pub(crate) enum ActionType {
    /// Runs for each matching variable value.
    Nondisruptive,
    /// Runs after the whole rule chain matches.
    Flow,
    /// Runs after the whole rule chain matches and may interrupt processing.
    Disruptive,
}

/// A runtime action after its name and value have been validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledAction {
    /// Lowercase SecLang action name.
    pub(crate) name: String,
    /// Parsed action argument.
    pub(crate) argument: String,
    /// Point in rule evaluation where the action runs.
    pub(crate) action_type: ActionType,
}

impl CompiledAction {
    /// Returns when the action runs.
    pub(crate) fn action_type(&self) -> ActionType {
        self.action_type
    }

    /// Apply the runtime effect of a compiled action.
    pub(crate) fn evaluate(&self, rule: &RuleMetadata, tx: &mut Transaction) {
        match self.name.as_str() {
            "deny" => {
                let status = if rule.status == 0 { 403 } else { rule.status };
                tx.interrupt(rule.id, "deny", status, "");
            },
            "drop" => tx.interrupt(rule.id, "drop", rule.status, ""),
            "redirect" => {
                let data = Macro::new(&self.argument).map_or_else(|_| self.argument.clone(), |value| value.expand(tx));
                let status = if rule.status == 0 { 302 } else { rule.status };
                tx.interrupt(rule.id, "redirect", status, &data);
            },
            "allow" => tx.allow(&self.argument),
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
    pub(crate) fn id(&self) -> i32 {
        self.id
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

/// Compile a parsed action, updating rule metadata or retaining a runtime action.
#[expect(
    clippy::too_many_lines,
    reason = "one dispatch keeps SecLang action validation in source order"
)]
pub(crate) fn compile_action(
    name: &str,
    argument: &str,
    metadata: &mut RuleMetadata,
) -> Result<Option<CompiledAction>, ActionError> {
    let name = name.to_ascii_lowercase();
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
            validate_ctl(argument)?;
            Some(compiled(name, argument, ActionType::Nondisruptive))
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
fn validate_ctl(argument: &str) -> Result<(), ActionError> {
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
        "requestBodyProcessor" | "responseBodyProcessor" => is_body_processor(value),
        "ruleRemoveById" => parse_id_range(value).is_ok(),
        "ruleRemoveByTag" | "ruleRemoveByMsg" | "hashEngine" | "hashEnforcement" => true,
        "ruleRemoveTargetById" => value
            .split_once(';')
            .is_some_and(|(ids, target)| parse_id_range(ids).is_ok() && valid_rule_target(target)),
        "ruleRemoveTargetByTag" | "ruleRemoveTargetByMsg" => value
            .split_once(';')
            .is_some_and(|(_, target)| valid_rule_target(target)),
        "auditEngine" => value.parse::<crate::types::AuditEngineStatus>().is_ok(),
        "auditLogParts" => crate::types::apply_audit_log_parts(&[], value).is_ok(),
        "debugLogLevel" => value.parse::<u8>().is_ok_and(|level| level <= 9),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(ActionError::InvalidArguments(format!("invalid ctl command: {name}")))
    }
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
    !pattern.is_empty() && regex::RegexBuilder::new(pattern).case_insensitive(true).build().is_ok()
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
        "removenulls" => Some(transformations::remove_nulls),
        "removewhitespace" => Some(transformations::remove_whitespace),
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
    use super::{ActionType, RuleMetadata, compile_action};
    use crate::types::{RulePhase, RuleSeverity};

    #[test]
    fn metadata_actions_update_rule_metadata() {
        let mut metadata = RuleMetadata::new();
        assert!(compile_action("ID", "15", &mut metadata).unwrap().is_none());
        assert!(compile_action("phase", "1", &mut metadata).unwrap().is_none());
        assert!(compile_action("severity", "CRITICAL", &mut metadata).unwrap().is_none());
        assert!(compile_action("tag", "attack", &mut metadata).unwrap().is_none());
        assert!(compile_action("t", "lowercase", &mut metadata).unwrap().is_none());
        assert_eq!(metadata.id, 15);
        assert_eq!(metadata.phase, RulePhase::RequestHeaders);
        assert_eq!(metadata.severity, Some(RuleSeverity::Critical));
        assert_eq!(metadata.tags, ["attack"]);
        assert_eq!(metadata.transformations.names(), ["lowercase"]);
    }

    #[test]
    fn runtime_actions_are_validated_and_classified() {
        let mut metadata = RuleMetadata::new();
        let action = compile_action("deny", "", &mut metadata).unwrap().unwrap();
        assert_eq!(action.action_type(), ActionType::Disruptive);
        let action = compile_action("skipAfter", "NEXT", &mut metadata).unwrap().unwrap();
        assert_eq!(action.action_type(), ActionType::Flow);
        let action = compile_action("setvar", "TX.score=+1", &mut metadata).unwrap().unwrap();
        assert_eq!(action.action_type(), ActionType::Nondisruptive);
        assert!(compile_action("deny", "403", &mut metadata).is_err());
        assert!(compile_action("skip", "0", &mut metadata).is_err());
        assert!(compile_action("unknown", "", &mut metadata).is_err());
    }

    #[test]
    fn ctl_validates_body_processors_and_rule_targets() {
        let mut metadata = RuleMetadata::new();
        for argument in [
            "requestBodyProcessor=JSON",
            "responseBodyLimit=0",
            "ruleRemoveTargetById=1-5;ARGS:user",
            "ruleRemoveTargetByTag=attack;REQUEST_HEADERS:/^x-/",
            "ruleRemoveByTag=",
            "hashEngine=anything",
        ] {
            assert!(compile_action("ctl", argument, &mut metadata).is_ok(), "{argument}");
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
            assert!(compile_action("ctl", argument, &mut metadata).is_err(), "{argument}");
        }
    }

    #[test]
    fn redirect_accepts_the_written_target_without_macro_parsing() {
        let mut metadata = RuleMetadata::new();
        assert!(compile_action("redirect", "%{unfinished", &mut metadata).is_ok());
    }
}
