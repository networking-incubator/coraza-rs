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
    rules::{RuleOperator, VariableSpec},
};

/// A rule compiled from SecLang, before transaction evaluation is wired in.
#[derive(Debug)]
pub(crate) struct Rule {
    /// Rule metadata compiled from actions.
    metadata: RuleMetadata,
    /// Variables inspected by this rule.
    variables: Vec<VariableSpec>,
    /// Operator that checks selected variable values.
    operator: Option<RuleOperator>,
    /// Actions retained for later transaction evaluation.
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
