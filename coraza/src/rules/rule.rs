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

//! Compiled SecLang rule data.

use crate::{
    actions::{ActionType, CompiledAction, RuleMetadata},
    collection::MatchData,
    operators::Outputs,
    rules::{RuleOperator, VariableSpec},
    transaction::Transaction,
};

/// A rule compiled from SecLang for transaction evaluation.
#[derive(Debug)]
pub(crate) struct Rule {
    /// Rule metadata compiled from actions.
    metadata: RuleMetadata,
    /// Variables inspected by this rule.
    variables: Vec<VariableSpec>,
    /// Operator that checks selected variable values.
    operator: Option<RuleOperator>,
    /// Actions retained for transaction evaluation.
    actions: Vec<CompiledAction>,
    /// Following rules in a chain.
    pub(crate) chain: Vec<Rule>,
}

impl Rule {
    /// Creates an empty rule.
    pub(crate) fn new() -> Self {
        Self {
            metadata: RuleMetadata::new(),
            variables: Vec::new(),
            operator: None,
            actions: Vec::new(),
            chain: Vec::new(),
        }
    }

    /// Adds a variable to the rule.
    pub(crate) fn add_variable(mut self, variable: VariableSpec) -> Self {
        self.variables.push(variable);
        self
    }

    /// Sets the rule's operator.
    pub(crate) fn with_operator(mut self, operator: RuleOperator) -> Self {
        self.operator = Some(operator);
        self
    }

    #[cfg(test)]
    /// Reports whether an operator was compiled.
    pub(crate) fn has_operator(&self) -> bool {
        self.operator.is_some()
    }

    /// Adds an action, replacing any earlier disruptive action.
    pub(crate) fn push_action(&mut self, action: CompiledAction) {
        if action.action_type() == ActionType::Disruptive {
            self.actions
                .retain(|existing| existing.action_type() != ActionType::Disruptive);
        }
        self.actions.push(action);
    }

    /// Returns the rule metadata.
    pub(crate) fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    /// Returns mutable rule metadata.
    pub(crate) fn metadata_mut(&mut self) -> &mut RuleMetadata {
        &mut self.metadata
    }

    /// Returns the actions in source order.
    pub(crate) fn actions(&self) -> &[CompiledAction] {
        &self.actions
    }

    /// Evaluate this rule and its chain against a transaction.
    pub(crate) fn evaluate(&self, tx: &mut Transaction) {
        let matched_values = self.matches_chain(tx, self.metadata.id);
        if matched_values.is_empty() {
            return;
        }

        if self.metadata.id != 0 {
            let mut rule = self.metadata.clone();
            for link in &self.chain {
                rule.raw.push_str(" \n");
                rule.raw.push_str(&link.metadata.raw);
            }
            let disruptive_action = self
                .actions
                .iter()
                .find(|action| action.action_type() == ActionType::Disruptive)
                .map(|action| match action.name.as_str() {
                    "allow" => "allow",
                    "deny" => "deny",
                    "drop" => "drop",
                    "pass" => "pass",
                    "redirect" => "redirect",
                    "block" => "block",
                    _ => "custom",
                });
            tx.record_match(rule, matched_values, disruptive_action);
            if let Some(severity) = self.metadata.severity {
                tx.raise_highest_severity(severity);
            }
        }

        for action in &self.actions {
            if action.action_type() != ActionType::Nondisruptive {
                action.evaluate(&self.metadata, tx);
            }
        }
    }

    /// Match this rule and its chain, running nondisruptive actions at each link.
    fn matches_chain(&self, tx: &mut Transaction, id: i32) -> Vec<MatchData> {
        if self.metadata.sec_mark.is_some() {
            return Vec::new();
        }
        let mut matched_values = self.match_values(tx, id);
        if matched_values.is_empty() {
            return matched_values;
        }
        let own_matches = matched_values.len();

        for link in &self.chain {
            let link_matches = link.matches_chain(tx, id);
            if link_matches.is_empty() {
                return Vec::new();
            }
            matched_values.extend(link_matches);
        }
        if !self.chain.is_empty() {
            let (message, data) = self.describe_match(tx);
            for matched in matched_values.iter_mut().take(own_matches) {
                matched.message.clone_from(&message);
                matched.data.clone_from(&data);
            }
        }
        matched_values
    }

    /// Match the values selected by this rule and run per-match actions.
    fn match_values(&self, tx: &mut Transaction, id: i32) -> Vec<MatchData> {
        let message = self.metadata.msg.as_ref().map(|value| value.expand(tx));
        let log_data = self.metadata.log_data.as_ref().map(|value| value.expand(tx));
        let severity = self.metadata.severity.map_or("unknown", |value| value.as_str());
        tx.set_rule_variables(id, message.clone(), &self.metadata.rev, log_data.clone(), severity);

        let Some(operator) = &self.operator else {
            if !self.variables.is_empty() || self.metadata.sec_mark.is_some() {
                return Vec::new();
            }
            let mut matched = MatchData::new_empty();
            tx.record_matched_variable(&matched);
            self.run_nondisruptive_actions(tx);
            if self.chain.is_empty() {
                (matched.message, matched.data) = self.describe_match(tx);
            }
            return vec![matched];
        };

        let mut matched_values = Vec::new();
        for variable in &self.variables {
            for value in tx.find_matches_for_rule(variable, id) {
                let candidates = if self.metadata.multi_match {
                    self.metadata.transformations.apply_multimatch(&value.value).0
                } else {
                    vec![self.metadata.transformations.apply(&value.value).0]
                };
                for candidate in candidates {
                    let mut outputs = Outputs::new(self.metadata.capture);
                    let operator_matched = operator.evaluate(tx, &candidate, &mut outputs);
                    tx.store_operator_outputs(&mut outputs);
                    if operator_matched {
                        let mut matched = MatchData::new(value.variable, value.key.clone(), candidate);
                        tx.record_matched_variable(&matched);
                        self.run_nondisruptive_actions(tx);
                        if self.chain.is_empty() {
                            (matched.message, matched.data) = self.describe_match(tx);
                        }
                        matched_values.push(matched);
                    }
                }
            }
        }
        matched_values
    }

    /// Expand this rule's `msg` and `logdata` against the current matched variables.
    fn describe_match(&self, tx: &Transaction) -> (String, String) {
        let expand =
            |value: &Option<crate::operators::Macro>| value.as_ref().map(|value| value.expand(tx)).unwrap_or_default();
        (expand(&self.metadata.msg), expand(&self.metadata.log_data))
    }

    /// Run actions that apply as each rule in a chain matches.
    fn run_nondisruptive_actions(&self, tx: &mut Transaction) {
        for action in &self.actions {
            if action.action_type() == ActionType::Nondisruptive {
                action.evaluate(&self.metadata, tx);
            }
        }
    }

    /// Returns mutable rule variables.
    pub(crate) fn variables_mut(&mut self) -> &mut Vec<VariableSpec> {
        &mut self.variables
    }
}

#[cfg(test)]
mod tests {
    use super::Rule;
    use crate::actions::{ActionType, CompiledAction};

    #[test]
    fn later_disruptive_action_replaces_the_previous_one() {
        let mut rule = Rule::new();
        rule.push_action(CompiledAction {
            name: "deny".to_owned(),
            argument: String::new(),
            action_type: ActionType::Disruptive,
        });
        rule.push_action(CompiledAction {
            name: "setvar".to_owned(),
            argument: "TX.count=1".to_owned(),
            action_type: ActionType::Nondisruptive,
        });
        rule.push_action(CompiledAction {
            name: "pass".to_owned(),
            argument: String::new(),
            action_type: ActionType::Disruptive,
        });

        assert_eq!(
            rule.actions()
                .iter()
                .map(|action| action.name.as_str())
                .collect::<Vec<_>>(),
            ["setvar", "pass"]
        );
    }
}
