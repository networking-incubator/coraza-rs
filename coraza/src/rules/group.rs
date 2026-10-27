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

//! Ordered storage and mutation of compiled rules.

use crate::{actions::RuleMetadata, rules::Rule};

/// Callback invoked synchronously after a rule is inserted.
pub(crate) type RuleObserver = dyn Fn(&RuleMetadata) + Send + Sync;

/// Rules compiled so far, in SecLang order.
#[derive(Debug, Default)]
pub(crate) struct RuleGroup {
    /// Top-level rules in directive order.
    rules: Vec<Rule>,
    /// The argument-map mode recorded when these rules were compiled.
    ///
    /// Key selectors do not depend on it: the variable parser lowers a selector from its
    /// variable alone (`RuleVariable::has_case_sensitive_selectors`), as Go's
    /// `caseSensitiveVariable` does. This records only the `case_sensitive_args_keys`
    /// setting the compiled rules were built under, so `Waf::with_rules` can reject a
    /// configuration that changed afterwards.
    case_sensitive_args_keys: Option<bool>,
    /// The multiphase mode under which this group was compiled, when any rule exists.
    multiphase_evaluation: Option<bool>,
}

impl RuleGroup {
    /// Creates an empty rule group.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record the argument-map mode for a variable compilation.
    ///
    /// Returns an error when rules were already compiled under a different mode, so a
    /// rule set is never paired with a configuration that would build its argument maps
    /// the other way. Selectors are compiled independently of this mode.
    pub(crate) fn record_case_sensitive_args_keys(&mut self, case_sensitive_args_keys: bool) -> Result<(), String> {
        match self.case_sensitive_args_keys {
            Some(compiled) if compiled != case_sensitive_args_keys => Err(format!(
                "case_sensitive_args_keys changed after rules were compiled (was {compiled}, now \
                 {case_sensitive_args_keys}); compile all rules under one setting"
            )),
            _ => {
                self.case_sensitive_args_keys = Some(case_sensitive_args_keys);
                Ok(())
            },
        }
    }

    /// The argument-map mode recorded at compile time, if any.
    pub(crate) fn compiled_case_sensitive_args_keys(&self) -> Option<bool> {
        self.case_sensitive_args_keys
    }

    /// Record the multiphase setting that affects rule compilation.
    pub(crate) fn record_multiphase_evaluation(&mut self, multiphase_evaluation: bool) -> Result<(), String> {
        match self.multiphase_evaluation {
            Some(compiled) if compiled != multiphase_evaluation => Err(format!(
                "multiphase_evaluation changed after rules were compiled (was {compiled}, now \
                 {multiphase_evaluation}); compile all rules under one setting"
            )),
            _ => {
                self.multiphase_evaluation = Some(multiphase_evaluation);
                Ok(())
            },
        }
    }

    /// The multiphase setting recorded at compile time, if any.
    pub(crate) fn compiled_multiphase_evaluation(&self) -> Option<bool> {
        self.multiphase_evaluation
    }

    /// Finalize phase metadata once all chain links and target updates are present.
    pub(crate) fn finalize_multiphase(&mut self, multiphase_evaluation: bool) {
        if multiphase_evaluation {
            for rule in &mut self.rules {
                rule.finalize_multiphase();
            }
        }
    }

    /// Add a rule, attaching it to an open chain when needed.
    pub(crate) fn add(
        &mut self,
        mut rule: Rule,
        multiphase_evaluation: bool,
        observer: Option<&RuleObserver>,
    ) -> Result<(), String> {
        if multiphase_evaluation {
            rule.split_args_variables();
        }
        let is_marker = rule.metadata().sec_mark.is_some();
        let open_parent_id = if is_marker {
            None
        } else {
            self.open_chain().map(|parent| parent.metadata().id())
        };
        if let Some(parent_id) = open_parent_id
            && rule.explicit_disruptive
        {
            self.discard_open_chain();
            return Err(format!(
                "disruptive actions can only be specified in the chain starter rule (parent id: {parent_id})"
            ));
        }

        let id = rule.metadata().id();
        if id != 0 && self.find_by_id(id).is_some() {
            return Err(format!("duplicated rule id {id}"));
        }

        let inserted = if is_marker {
            self.rules.push(rule);
            self.rules.last()
        } else if let Some(parent) = self.open_chain() {
            parent.chain.push(rule);
            None
        } else {
            self.rules.push(rule);
            self.rules.last()
        };
        if let (Some(observer), Some(inserted)) = (observer, inserted) {
            observer(inserted.metadata());
        }
        Ok(())
    }

    /// Drop an unfinished chain after a skipped compilation error.
    pub(crate) fn discard_open_chain(&mut self) -> bool {
        if self.open_chain().is_some() {
            self.rules.pop();
            true
        } else {
            false
        }
    }

    /// Returns the top-level rule when its last chain link still expects another rule.
    fn open_chain(&mut self) -> Option<&mut Rule> {
        let parent = self.rules.last_mut()?;
        let tail = parent.chain.last().unwrap_or(parent);
        let is_open = tail.metadata().has_chain;
        is_open.then_some(parent)
    }

    /// Finds a top-level rule by id.
    pub(crate) fn find_by_id(&self, id: i32) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.metadata().id() == id)
    }

    /// Removes rules with ids in the inclusive range.
    pub(crate) fn delete_by_range(&mut self, start: i32, end: i32) {
        self.rules.retain(|rule| !(start..=end).contains(&rule.metadata().id()));
    }

    /// Removes rules whose message equals `message`.
    pub(crate) fn delete_by_msg(&mut self, message: &str) {
        self.rules.retain(|rule| rule.metadata().msg() != Some(message));
    }

    /// Removes rules tagged with `tag`.
    pub(crate) fn delete_by_tag(&mut self, tag: &str) {
        self.rules
            .retain(|rule| !rule.metadata().tags().iter().any(|item| item == tag));
    }

    /// Updates rules tagged with `tag` and returns their count.
    pub(crate) fn update_by_tag(&mut self, tag: &str, mut update: impl FnMut(&mut Rule)) -> usize {
        let mut count = 0;
        for rule in &mut self.rules {
            if rule.metadata().tags().iter().any(|item| item == tag) {
                update(rule);
                count += 1;
            }
        }
        count
    }

    /// Iterates over top-level rules mutably.
    pub(crate) fn iter_mut(&mut self) -> std::slice::IterMut<'_, Rule> {
        self.rules.iter_mut()
    }

    /// Iterates over top-level rules in directive order.
    pub(crate) fn iter(&self) -> std::slice::Iter<'_, Rule> {
        self.rules.iter()
    }

    #[cfg(test)]
    /// Returns the top-level rules for tests.
    fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Returns the number of top-level rules.
    pub(crate) fn count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "rule group tests use fixed valid inputs"
)]
mod tests {
    use super::RuleGroup;
    use crate::{
        actions::{ActionCompileContext, compile_action},
        rules::{Rule, VariableSpec},
        types::{RulePhase, RuleVariable},
    };

    fn rule(id: &str, action: &str) -> Rule {
        let mut rule = Rule::new();
        if !id.is_empty() {
            compile_action("id", id, rule.metadata_mut(), ActionCompileContext::default()).unwrap();
        }
        if !action.is_empty() {
            compile_action(action, "", rule.metadata_mut(), ActionCompileContext::default()).unwrap();
        }
        rule
    }

    #[test]
    fn rejects_duplicate_nonzero_ids() {
        let mut group = RuleGroup::new();
        group.add(rule("1", ""), false, None).unwrap();
        assert!(
            group
                .add(rule("1", ""), false, None)
                .unwrap_err()
                .contains("duplicated rule id 1")
        );
    }

    #[test]
    fn duplicate_chain_member_id_leaves_the_open_chain_unchanged() {
        let mut group = RuleGroup::new();
        group.add(rule("1", "chain"), false, None).unwrap();

        assert!(
            group
                .add(rule("1", ""), false, None)
                .unwrap_err()
                .contains("duplicated rule id 1")
        );
        assert_eq!(group.count(), 1);
        assert!(group.discard_open_chain());
    }

    #[test]
    fn chains_rules_and_discards_an_incomplete_chain() {
        let mut group = RuleGroup::new();
        group.add(rule("1", "chain"), false, None).unwrap();
        assert!(group.discard_open_chain());
        assert_eq!(group.count(), 0);

        group.add(rule("1", "chain"), false, None).unwrap();
        group.add(rule("", ""), false, None).unwrap();
        assert_eq!(group.count(), 1);
        assert_eq!(group.rules()[0].chain.len(), 1);
        assert!(!group.discard_open_chain());
    }

    #[test]
    fn disruptive_chain_member_error_precedes_duplicate_id() {
        let mut group = RuleGroup::new();
        group.add(rule("42", "chain"), false, None).unwrap();
        let mut member = rule("42", "deny");
        member.explicit_disruptive = true;

        assert_eq!(
            group.add(member, false, None).unwrap_err(),
            "disruptive actions can only be specified in the chain starter rule (parent id: 42)"
        );
        assert_eq!(group.count(), 0);
    }

    #[test]
    fn removes_rules_by_id_message_and_tag() {
        let mut group = RuleGroup::new();
        let mut tagged = rule("2", "");
        tagged.metadata_mut().msg = Some(crate::operators::Macro::new("blocked").unwrap());
        tagged.metadata_mut().tags.push("attack".to_owned());
        group.add(tagged, false, None).unwrap();
        group.add(rule("3", ""), false, None).unwrap();

        group.delete_by_msg("blocked");
        assert!(group.find_by_id(2).is_none());
        group.delete_by_range(3, 3);
        assert_eq!(group.count(), 0);
    }

    #[test]
    fn finalizes_chain_minimum_and_phase_unknown_metadata() {
        let mut group = RuleGroup::new();
        let mut parent = rule("1", "chain");
        parent.metadata_mut().phase = RulePhase::RequestBody;
        parent = parent.add_variable(VariableSpec::new(RuleVariable::RequestURI));
        group.add(parent, true, None).unwrap();

        let mut first_link = Rule::new();
        first_link.metadata_mut().has_chain = true;
        first_link = first_link
            .add_variable(VariableSpec::new(RuleVariable::TX))
            .add_variable(VariableSpec::new(RuleVariable::RequestBody));
        group.add(first_link, true, None).unwrap();

        let last_link = Rule::new().add_variable(VariableSpec::new(RuleVariable::ResponseHeaders));
        group.add(last_link, true, None).unwrap();
        group.finalize_multiphase(true);

        let root = group.rules().first().expect("parent rule exists");
        assert_eq!(root.chain_min_phase, RulePhase::ResponseHeaders);
        assert!(!root.has_phase_unknown_variable);
        assert!(root.chain[0].has_phase_unknown_variable);
        assert_eq!(root.inferred_phases, (1 << 1) | (1 << 2));
    }
}
