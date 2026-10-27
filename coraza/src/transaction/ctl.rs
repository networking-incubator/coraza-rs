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

//! Transaction-scoped `ctl` action handling.

use std::ops::RangeInclusive;

use regex::Regex;

use super::Transaction;
use crate::{
    debug_log::{DebugField, DebugLevel},
    rules::{VariableException, lowercase_like_go},
    types::{AuditEngineStatus, RuleEngineStatus, RulePhase, RuleVariable},
};

impl Transaction {
    /// Apply transaction-scoped `ctl` settings supported by this runtime slice.
    pub(crate) fn apply_ctl(&mut self, expression: &str) {
        let Some((name, value)) = expression.split_once('=') else {
            return;
        };
        match name {
            "auditEngine" => {
                if let Ok(audit_engine) = value.parse::<AuditEngineStatus>() {
                    self.audit_engine = audit_engine;
                }
            },
            "auditLogParts" => {
                if let Ok(parts) = crate::types::apply_audit_log_parts(&self.audit_log_parts, value) {
                    self.audit_log_parts = parts;
                }
            },
            "debugLogLevel" => self.set_debug_log_level(value),
            "ruleEngine" => {
                if let Ok(rule_engine) = value.parse::<RuleEngineStatus>() {
                    self.rule_engine = rule_engine;
                }
            },
            "requestBodyAccess" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::RequestBody) {
                    self.request_body_access = value.eq_ignore_ascii_case("on");
                }
            },
            "requestBodyLimit" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::RequestBody)
                    && let Ok(limit) = value.parse::<i64>()
                    && limit >= 0
                {
                    self.request_body_limit = limit;
                }
            },
            "forceRequestBodyVariable" => {
                self.force_request_body_variable = value.eq_ignore_ascii_case("on");
            },
            "requestBodyProcessor" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::RequestBody) {
                    self.set_request_body_processor(value);
                }
            },
            "responseBodyAccess" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::ResponseBody) {
                    self.response_body_access = value.eq_ignore_ascii_case("on");
                }
            },
            "responseBodyLimit" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::ResponseBody)
                    && let Ok(limit) = value.parse::<i64>()
                    && limit >= 0
                {
                    self.response_body_limit = limit;
                }
            },
            "forceResponseBodyVariable" => {
                self.force_response_body_variable = value.eq_ignore_ascii_case("on");
            },
            "responseBodyProcessor" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::ResponseBody) {
                    self.set_response_body_processor(value);
                }
            },
            "ruleRemoveById" => {
                if let Some(ids) = parse_id_range(value) {
                    if ids.start() == ids.end() {
                        self.removed_rule_ids.insert(*ids.start());
                    } else if !self.removed_rule_id_ranges.contains(&ids) {
                        self.removed_rule_id_ranges.push(ids);
                    }
                }
            },
            "ruleRemoveByTag" => {
                if self.applied_rule_removals.insert(expression.to_owned()) {
                    let ids = self
                        .rules
                        .iter()
                        .filter(|rule| rule.metadata().tags.iter().any(|tag| tag == value))
                        .map(|rule| rule.metadata().id)
                        .collect::<Vec<_>>();
                    self.removed_rule_ids.extend(ids);
                }
            },
            "ruleRemoveByMsg" => {
                if self.applied_rule_removals.insert(expression.to_owned()) {
                    let ids = self
                        .rules
                        .iter()
                        .filter(|rule| rule.metadata().msg.as_ref().is_some_and(|msg| msg.as_str() == value))
                        .map(|rule| rule.metadata().id)
                        .collect::<Vec<_>>();
                    self.removed_rule_ids.extend(ids);
                }
            },
            "ruleRemoveTargetById" | "ruleRemoveTargetByTag" | "ruleRemoveTargetByMsg" => {
                self.apply_rule_target_removal(name, value, expression);
            },
            _ => {},
        }
    }

    /// Set this transaction's level override, warning and keeping the old level if invalid.
    fn set_debug_log_level(&mut self, value: &str) {
        match value.parse::<u8>() {
            Ok(level) if level <= 9 => self.debug_log_level = Some(level),
            _ => self.debug_log(DebugLevel::Warn, "Invalid ctl debug log level", || {
                [DebugField::Text(value)]
            }),
        }
    }

    /// Select rules and targets for the `ctl:ruleRemoveTarget*` commands.
    fn apply_rule_target_removal(&mut self, command: &str, value: &str, expression: &str) {
        if !self.applied_rule_removals.insert(expression.to_owned()) {
            return;
        }
        let Some((selector, target)) = value.split_once(';') else {
            return;
        };
        let (variable, key) = target.split_once(':').unwrap_or((target, ""));
        let Ok(variable) = variable.trim().parse::<RuleVariable>() else {
            return;
        };
        let key = key.trim();
        let exception = match key.strip_prefix('/').and_then(|key| key.strip_suffix('/')) {
            Some(pattern) if !pattern.is_empty() => {
                // Go compiles the pattern as written and lower-cases the key instead.
                let Ok(regex) = Regex::new(pattern) else {
                    return;
                };
                VariableException::new_regex(regex)
            },
            Some(_) => return,
            None => VariableException::new_string(key),
        };
        let (target_variables, target_count) = if self.multiphase_evaluation() {
            match variable {
                RuleVariable::Args => ([RuleVariable::ArgsGet, RuleVariable::ArgsPost], 2),
                RuleVariable::ArgsNames => ([RuleVariable::ArgsGetNames, RuleVariable::ArgsPostNames], 2),
                _ => ([variable, variable], 1),
            }
        } else {
            ([variable, variable], 1)
        };
        let ids = match command {
            "ruleRemoveTargetById" => parse_id_range(selector)
                .map(|range| {
                    self.rules
                        .iter()
                        .filter(|rule| range.contains(&rule.metadata().id))
                        .map(|rule| rule.metadata().id)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            "ruleRemoveTargetByTag" => self
                .rules
                .iter()
                .filter(|rule| rule.metadata().tags.iter().any(|tag| tag == selector))
                .map(|rule| rule.metadata().id)
                .collect(),
            "ruleRemoveTargetByMsg" => self
                .rules
                .iter()
                .filter(|rule| rule.metadata().msg.as_ref().is_some_and(|msg| msg.as_str() == selector))
                .map(|rule| rule.metadata().id)
                .collect(),
            _ => Vec::new(),
        };
        for id in ids {
            let targets = self.removed_rule_targets.entry(id).or_default();
            for target_variable in target_variables.iter().copied().take(target_count) {
                let target = (target_variable, exception.clone());
                if !targets.contains(&target) {
                    targets.push(target);
                }
            }
        }
    }

    /// Whether `ctl` excluded a rule for this transaction.
    pub(super) fn is_rule_removed(&self, id: i32) -> bool {
        self.removed_rule_ids.contains(&id) || self.removed_rule_id_ranges.iter().any(|range| range.contains(&id))
    }

    /// Whether `ctl` excluded this variable key from a rule for this transaction.
    pub(super) fn is_rule_target_removed(&self, id: i32, variable: RuleVariable, key: &str) -> bool {
        let Some(targets) = self.removed_rule_targets.get(&id) else {
            return false;
        };
        // Go lower-cases the key with its simple mapping, so a pattern keeps the case it was written with.
        let key = lowercase_like_go(key);
        targets
            .iter()
            .any(|(removed_variable, exception)| *removed_variable == variable && exception.matches_lowered(&key))
    }
}

/// Parse a single rule ID or an inclusive rule ID range.
fn parse_id_range(value: &str) -> Option<RangeInclusive<i32>> {
    let (start, end) = value.split_once('-').unwrap_or((value, value));
    let start = start.parse::<i32>().ok()?;
    let end = end.parse::<i32>().ok()?;
    let range = start..=end;
    (!range.is_empty()).then_some(range)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "ctl tests use fixed valid rules")]
mod tests {
    use super::Transaction;

    /// Run `rules` against one request and return the ID of the rule that interrupted it.
    fn interrupting_rule(rules: &str, setup: impl FnOnce(&mut Transaction)) -> Option<i32> {
        let mut parser = crate::seclang::Parser::new();
        parser.from_string(rules).unwrap();
        let waf = parser.into_waf().unwrap();
        let mut transaction = waf.new_transaction_with_id("ctl-target");
        setup(&mut transaction);
        transaction
            .process_request_headers()
            .map(|interruption| interruption.rule_id)
    }

    #[test]
    fn lowercase_regex_target_removes_matching_keys() {
        let rules = "SecAction \"id:80,phase:1,ctl:ruleRemoveTargetById=81;ARGS:/^user$/,pass\"\n\
                     SecRule ARGS \"@contains bad\" \"id:81,phase:1,deny\"";

        assert_eq!(
            interrupting_rule(rules, |transaction| transaction.add_get_argument("user", "bad")),
            None,
            "a lower-case pattern matches the lower-cased key"
        );
        assert_eq!(
            interrupting_rule(rules, |transaction| {
                transaction.add_get_argument("user", "good");
                transaction.add_get_argument("query", "bad");
            }),
            Some(81),
            "only the removed key is skipped"
        );
    }

    #[test]
    fn multiphase_ctl_splits_args_and_args_names_targets() {
        let rules = "SecRequestBodyAccess On\n\
                     SecAction \"id:80,phase:1,pass,ctl:ruleRemoveTargetById=81;ARGS:fbclid,ctl:ruleRemoveTargetById=82;ARGS_NAMES:fbclid\"\n\
                     SecRule ARGS \"@contains bad\" \"id:81,phase:2,deny\"\n\
                     SecRule ARGS_NAMES \"@contains fbclid\" \"id:82,phase:2,deny\"";
        let mut parser = crate::seclang::Parser::new();
        parser.config_mut().multiphase_evaluation = true;
        parser.from_string(rules).unwrap();
        let waf = parser.into_waf().unwrap();
        let mut transaction = waf.new_transaction_with_id("ctl-multiphase-target");
        transaction.process_uri("/?fbclid=bad", "POST", "HTTP/1.1");
        transaction.add_request_header("content-type", "application/x-www-form-urlencoded");
        transaction.process_request_headers();
        transaction.process_request_body(b"fbclid=bad");

        assert!(transaction.interruption().is_none());
        assert!(transaction.matched_rules().iter().any(|matched| matched.rule.id == 80));
        assert!(!transaction.matched_rules().iter().any(|matched| matched.rule.id == 81));
        assert!(!transaction.matched_rules().iter().any(|matched| matched.rule.id == 82));
    }

    #[test]
    fn uppercase_character_class_keeps_its_meaning() {
        let rules = "SecAction \"id:80,phase:1,ctl:ruleRemoveTargetById=81;ARGS:/^[A-Z]+$/,pass\"\n\
                     SecRule ARGS \"@contains bad\" \"id:81,phase:1,deny\"";

        assert_eq!(
            interrupting_rule(rules, |transaction| transaction.add_get_argument("ABC", "bad")),
            Some(81),
            "the key is lower-cased, so an upper-case class does not match it"
        );
    }

    #[test]
    fn literal_targets_lower_case_but_regex_targets_keep_their_case() {
        let literal = "SecAction \"id:80,phase:1,ctl:ruleRemoveTargetById=81;ARGS:User,pass\"\n\
                       SecRule ARGS \"@contains bad\" \"id:81,phase:1,deny\"";
        let regex = "SecAction \"id:80,phase:1,ctl:ruleRemoveTargetById=81;ARGS:/^User$/,pass\"\n\
                     SecRule ARGS \"@contains bad\" \"id:81,phase:1,deny\"";

        assert_eq!(
            interrupting_rule(literal, |transaction| transaction.add_get_argument("user", "bad")),
            None,
            "a literal target is lower-cased like Go's"
        );
        assert_eq!(
            interrupting_rule(regex, |transaction| transaction.add_get_argument("user", "bad")),
            Some(81),
            "a regex target is compiled as written like Go's"
        );
    }

    #[test]
    fn argument_and_non_argument_collections_match_lowercased_keys() {
        let arguments = "SecAction \"id:80,phase:1,ctl:ruleRemoveTargetById=81;ARGS:/^user$/,pass\"\n\
                         SecRule ARGS:user \"@contains bad\" \"id:81,phase:1,deny\"";
        let headers = "SecAction \"id:80,phase:1,ctl:ruleRemoveTargetById=81;REQUEST_HEADERS:/^x-secret$/,pass\"\n\
                       SecRule REQUEST_HEADERS:X-Secret \"@contains bad\" \"id:81,phase:1,deny\"";

        assert_eq!(
            interrupting_rule(arguments, |transaction| transaction.add_get_argument("user", "bad")),
            None,
            "argument collection keys are lower-cased"
        );
        assert_eq!(
            interrupting_rule(headers, |transaction| transaction.add_request_header("X-Secret", "bad")),
            None,
            "non-argument collection keys are lower-cased"
        );
    }

    #[test]
    fn chained_child_rules_use_the_parent_target_removal() {
        let rules = "SecAction \"id:80,phase:1,ctl:ruleRemoveTargetById=81;ARGS:/^user$/,pass\"\n\
                     SecRule ARGS:trigger \"@contains go\" \"id:81,phase:1,chain,deny\"\n\
                     SecRule ARGS \"@contains bad\" \"\"";

        assert_eq!(
            interrupting_rule(rules, |transaction| {
                transaction.add_get_argument("trigger", "go");
                transaction.add_get_argument("user", "bad");
            }),
            None,
            "the chain child inherits the parent's target removal"
        );
        assert_eq!(
            interrupting_rule(rules, |transaction| {
                transaction.add_get_argument("trigger", "go");
                transaction.add_get_argument("query", "bad");
            }),
            Some(81),
            "other keys still reach the chain child"
        );
    }

    #[test]
    fn full_lowercase_expansion_does_not_widen_target_removal() {
        // Go lowers `İ` (U+0130) to `i`, so the ambiguous `i` + U+0307 pattern excludes nothing;
        // Rust's full mapping would lower the key to exactly those two code points.
        let rules = "SecAction \"id:80,phase:1,ctl:ruleRemoveTargetById=81;ARGS:/^i\u{307}$/,pass\"\n\
                     SecRule ARGS \"@contains bad\" \"id:81,phase:1,deny\"";

        assert_eq!(
            interrupting_rule(rules, |transaction| transaction.add_get_argument("\u{130}", "bad")),
            Some(81),
            "the key is inspected, matching Go's simple lowercase mapping"
        );
    }

    #[test]
    fn simple_lowercase_mapping_still_removes_keys() {
        let rules = "SecAction \"id:80,phase:1,ctl:ruleRemoveTargetById=81;ARGS:/^i$/,pass\"\n\
                     SecRule ARGS \"@contains bad\" \"id:81,phase:1,deny\"";

        assert_eq!(
            interrupting_rule(rules, |transaction| transaction.add_get_argument("\u{130}", "bad")),
            None,
            "Go lowers `İ` to `i`, so the plain pattern excludes it"
        );
    }

    #[test]
    fn non_ascii_lowercase_still_removes_keys() {
        let rules = "SecAction \"id:80,phase:1,ctl:ruleRemoveTargetById=81;ARGS:/^\u{00e4}$/,pass\"\n\
                     SecRule ARGS \"@contains bad\" \"id:81,phase:1,deny\"";

        assert_eq!(
            interrupting_rule(rules, |transaction| transaction.add_get_argument("\u{00c4}", "bad")),
            None,
            "single-character lowercase mappings still apply"
        );
    }
}
