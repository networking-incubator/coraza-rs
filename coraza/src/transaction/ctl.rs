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

use regex::RegexBuilder;

use super::Transaction;
use crate::{
    rules::VariableException,
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
                let Ok(regex) = RegexBuilder::new(pattern).case_insensitive(true).build() else {
                    return;
                };
                VariableException::new_regex(regex)
            },
            Some(_) => return,
            None => VariableException::new_string(key),
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
            let target = (variable, exception.clone());
            if !targets.contains(&target) {
                targets.push(target);
            }
        }
    }

    /// Whether `ctl` excluded a rule for this transaction.
    pub(super) fn is_rule_removed(&self, id: i32) -> bool {
        self.removed_rule_ids.contains(&id) || self.removed_rule_id_ranges.iter().any(|range| range.contains(&id))
    }

    /// Whether `ctl` excluded this variable key from a rule for this transaction.
    pub(super) fn is_rule_target_removed(&self, id: i32, variable: RuleVariable, key: &str) -> bool {
        self.removed_rule_targets.get(&id).is_some_and(|targets| {
            targets
                .iter()
                .any(|(removed_variable, exception)| *removed_variable == variable && exception.matches_key(key))
        })
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
