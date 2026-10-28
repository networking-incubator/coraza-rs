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

use std::{ops::RangeInclusive, sync::Arc};

use regex::Regex;

use super::Transaction;
use crate::{
    body_processors::BodyProcessorFactory,
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
                // Host policy: an embedder with no audit sink locks the engine so a
                // request cannot make it retain an audit body copy with none to write.
                if !self.config.audit_engine_locked
                    && let Ok(audit_engine) = value.parse::<AuditEngineStatus>()
                {
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
            "requestBodyAccess" | "requestBodyLimit" | "responseBodyAccess" | "responseBodyLimit" => {
                self.apply_body_ctl(name, value);
            },
            "forceRequestBodyVariable" => {
                self.force_request_body_variable = value.eq_ignore_ascii_case("on");
            },
            "requestBodyProcessor" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::RequestBody) {
                    self.set_request_body_processor(value);
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

    /// Select a processor factory captured while compiling this custom body-processor ctl.
    pub(crate) fn apply_ctl_with_body_processor(&mut self, expression: &str, factory: &BodyProcessorFactory) {
        let Some((name, value)) = expression.split_once('=') else {
            return;
        };
        match name {
            "requestBodyProcessor" if self.last_phase.is_none_or(|last| last < RulePhase::RequestBody) => {
                self.set_request_custom_body_processor(value, Arc::clone(factory));
            },
            "responseBodyProcessor" if self.last_phase.is_none_or(|last| last < RulePhase::ResponseBody) => {
                self.set_response_custom_body_processor(value, Arc::clone(factory));
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

    /// Apply a `ctl` body setting, clamped to the host ceilings.
    fn apply_body_ctl(&mut self, name: &str, value: &str) {
        match name {
            "requestBodyAccess" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::RequestBody) {
                    self.request_body_access = value.eq_ignore_ascii_case("on");
                    if self.request_body_access {
                        self.request_body_limit = clamp_limit(
                            self.request_body_limit,
                            self.config.max_request_body_limit,
                            self.config.request_body_in_memory_limit,
                        );
                    }
                }
            },
            "requestBodyLimit" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::RequestBody)
                    && let Ok(limit) = value.parse::<i64>()
                    && limit >= 0
                {
                    self.request_body_limit = clamp_limit(
                        limit,
                        self.config.max_request_body_limit,
                        self.config.request_body_in_memory_limit,
                    );
                }
            },
            "responseBodyAccess" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::ResponseBody) {
                    self.response_body_access = value.eq_ignore_ascii_case("on");
                    if self.response_body_access {
                        self.response_body_limit =
                            clamp_limit(self.response_body_limit, self.config.max_response_body_limit, 0);
                    }
                }
            },
            "responseBodyLimit" => {
                if self.last_phase.is_none_or(|last| last < RulePhase::ResponseBody)
                    && let Ok(limit) = value.parse::<i64>()
                    && limit >= 0
                {
                    self.response_body_limit = clamp_limit(limit, self.config.max_response_body_limit, 0);
                }
            },
            _ => {},
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

/// Clamp a `ctl` body limit to a positive host ceiling and, when positive, an
/// in-memory limit; `0` means unset for either.
///
/// A positive ceiling also clamps the limit to a positive in-memory limit, so a
/// `ctl` cannot reintroduce body spill; the response path passes `0` there.
/// Without a positive ceiling the host has no policy, so the limit is left as
/// configured and native behavior is unchanged.
fn clamp_limit(limit: i64, ceiling: i64, in_memory_limit: i64) -> i64 {
    if ceiling <= 0 {
        return limit;
    }
    let limit = limit.min(ceiling);
    if in_memory_limit > 0 {
        limit.min(in_memory_limit)
    } else {
        limit
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
    fn multiphase_count_applies_target_removal_before_aggregation() {
        let rules = "SecRequestBodyAccess On\n\
                     SecAction \"id:80,phase:1,pass,ctl:ruleRemoveTargetById=81;ARGS:skip\"\n\
                     SecRule &ARGS \"@eq 1\" \"id:81,phase:2,deny,status:403\"";

        for (multiphase, expected_match) in [(false, false), (true, true)] {
            let mut parser = crate::seclang::Parser::new();
            parser.config_mut().multiphase_evaluation = multiphase;
            parser.from_string(rules).unwrap();
            let waf = parser.into_waf().unwrap();
            let mut transaction = waf.new_transaction_with_id("ctl-count-target");
            transaction.add_get_argument("skip", "1");
            transaction.add_get_argument("keep", "2");

            let mut interruption = transaction.process_request_headers();
            if interruption.is_none() {
                interruption = transaction.process_request_body(b"");
            }
            let matched = transaction.matched_rules().iter().any(|rule| rule.rule.id == 81);
            assert_eq!(matched, expected_match, "multiphase={multiphase}");
            assert_eq!(interruption.is_some(), expected_match, "multiphase={multiphase}");
        }
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

    /// Build a transaction after applying `configure` to the parser's WAF config.
    fn transaction_with_config(rules: &str, configure: impl FnOnce(&mut crate::config::WafConfig)) -> Transaction {
        let mut parser = crate::seclang::Parser::new();
        configure(parser.config_mut());
        parser.from_string(rules).unwrap();
        parser.into_waf().unwrap().new_transaction_with_id("ctl-limits")
    }

    #[test]
    fn ctl_request_body_limit_is_clamped_to_the_host_ceiling() {
        let rules = "SecAction \"id:80,phase:1,ctl:requestBodyLimit=1073741824\"";
        let mut transaction = transaction_with_config(rules, |config| {
            config.max_request_body_limit = 16 * 1024 * 1024;
        });
        transaction.process_request_headers();
        assert_eq!(transaction.request_body_limit, 16 * 1024 * 1024);
    }

    #[test]
    fn a_zero_ceiling_leaves_the_ctl_limit_unchanged() {
        let rules = "SecAction \"id:80,phase:1,ctl:requestBodyLimit=1073741824\"";
        let mut transaction = transaction_with_config(rules, |_config| {});
        transaction.process_request_headers();
        assert_eq!(transaction.request_body_limit, 1_073_741_824);
    }

    #[test]
    fn ctl_enabling_body_access_uses_the_ceiling() {
        let rules = "SecAction \"id:80,phase:1,ctl:requestBodyAccess=On\"";
        let mut transaction = transaction_with_config(rules, |config| {
            config.request_body_access = false;
            config.request_body_limit = 128 * 1024 * 1024;
            config.max_request_body_limit = 16 * 1024 * 1024;
        });
        transaction.process_request_headers();
        assert!(transaction.request_body_access);
        assert_eq!(transaction.request_body_limit, 16 * 1024 * 1024);
    }

    #[test]
    fn ctl_never_raises_the_request_limit_above_a_positive_in_memory_limit() {
        let rules = "SecAction \"id:80,phase:1,ctl:requestBodyLimit=1073741824\"";
        let mut transaction = transaction_with_config(rules, |config| {
            config.request_body_access = true;
            config.request_body_limit = 4;
            config.request_body_in_memory_limit = 4;
            config.max_request_body_limit = 16 * 1024 * 1024;
            config.request_body_limit_action = crate::types::BodyLimitAction::ProcessPartial;
        });
        transaction.process_request_headers();
        assert_eq!(transaction.request_body_limit, 4, "the in-memory limit wins");
        transaction.process_request_body(b"0123456789");
        assert!(
            transaction.request_body_buffer.spill_path().is_none(),
            "a clamped limit cannot spill the body to a file"
        );
    }

    #[test]
    fn ctl_response_body_limit_is_clamped_to_the_host_ceiling() {
        let rules = "SecAction \"id:80,phase:1,ctl:responseBodyLimit=1073741824\"";
        let mut transaction = transaction_with_config(rules, |config| {
            config.max_response_body_limit = 1024 * 1024;
        });
        transaction.process_request_headers();
        assert_eq!(transaction.response_body_limit, 1024 * 1024);
    }

    #[test]
    fn ctl_enabling_response_body_access_uses_the_ceiling() {
        let rules = "SecAction \"id:80,phase:1,ctl:responseBodyAccess=On\"";
        let mut transaction = transaction_with_config(rules, |config| {
            config.response_body_access = false;
            config.response_body_limit = 512 * 1024;
            config.max_response_body_limit = 1024 * 1024;
        });
        transaction.process_request_headers();
        assert!(transaction.response_body_access);
        assert_eq!(transaction.response_body_limit, 512 * 1024, "already below the ceiling");
    }

    #[test]
    fn a_locked_audit_engine_ignores_ctl_and_retains_no_audit_body() {
        let rules = "SecAction \"id:80,phase:1,ctl:auditEngine=On\"";
        let mut transaction = transaction_with_config(rules, |config| {
            config.audit_engine_locked = true;
            config.request_body_access = true;
            config.request_body_limit = 1024;
        });
        transaction.process_request_headers();
        transaction.process_request_body(b"attack");
        assert_eq!(
            transaction.audit_engine,
            crate::types::AuditEngineStatus::Off,
            "the host lock keeps the engine off"
        );
        assert!(
            transaction.audit_request_body.is_empty(),
            "a locked engine must not copy the body into an audit entry"
        );
    }

    #[test]
    fn an_unlocked_audit_engine_still_applies_ctl() {
        let rules = "SecAction \"id:80,phase:1,ctl:auditEngine=On\"";
        let mut transaction = transaction_with_config(rules, |config| {
            config.audit_engine_locked = false;
            config.request_body_access = true;
            config.request_body_limit = 1024;
        });
        transaction.process_request_headers();
        transaction.process_request_body(b"attack");
        assert_eq!(transaction.audit_engine, crate::types::AuditEngineStatus::On);
        assert_eq!(transaction.audit_request_body, b"attack");
    }
}
