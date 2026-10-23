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

use crate::rules::Rule;

/// Rules compiled so far, in SecLang order.
#[derive(Debug, Default)]
pub(crate) struct RuleGroup {
    /// Top-level rules in directive order.
    rules: Vec<Rule>,
    /// `case_sensitive_args_keys` the variable parser used for these rules.
    ///
    /// `None` until a variable list is compiled. `Waf::with_rules` rejects a
    /// configuration whose setting differs, so compiled selectors and transaction maps
    /// cannot disagree.
    case_sensitive_args_keys: Option<bool>,
}

impl RuleGroup {
    /// Creates an empty rule group.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record the key mode for a variable compilation.
    ///
    /// Returns an error when rules were already compiled under a different mode, so a
    /// rule set can never silently mix selector modes.
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

    /// The key mode these rules were compiled with, if any.
    pub(crate) fn compiled_case_sensitive_args_keys(&self) -> Option<bool> {
        self.case_sensitive_args_keys
    }

    /// Add a rule, attaching it to an open chain when needed.
    pub(crate) fn add(&mut self, rule: Rule) -> Result<(), String> {
        let id = rule.metadata().id();
        if id != 0 && self.find_by_id(id).is_some() {
            return Err(format!("duplicated rule id {id}"));
        }

        match self.open_chain() {
            Some(parent) => parent.chain.push(rule),
            None => self.rules.push(rule),
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
    clippy::indexing_slicing,
    reason = "rule group tests use fixed valid inputs"
)]
mod tests {
    use super::RuleGroup;
    use crate::{actions::compile_action, rules::Rule};

    fn rule(id: &str, action: &str) -> Rule {
        let mut rule = Rule::new();
        if !id.is_empty() {
            compile_action("id", id, rule.metadata_mut()).unwrap();
        }
        if !action.is_empty() {
            compile_action(action, "", rule.metadata_mut()).unwrap();
        }
        rule
    }

    #[test]
    fn rejects_duplicate_nonzero_ids() {
        let mut group = RuleGroup::new();
        group.add(rule("1", "")).unwrap();
        assert!(group.add(rule("1", "")).unwrap_err().contains("duplicated rule id 1"));
    }

    #[test]
    fn chains_rules_and_discards_an_incomplete_chain() {
        let mut group = RuleGroup::new();
        group.add(rule("1", "chain")).unwrap();
        assert!(group.discard_open_chain());
        assert_eq!(group.count(), 0);

        group.add(rule("1", "chain")).unwrap();
        group.add(rule("", "")).unwrap();
        assert_eq!(group.count(), 1);
        assert_eq!(group.rules()[0].chain.len(), 1);
        assert!(!group.discard_open_chain());
    }

    #[test]
    fn removes_rules_by_id_message_and_tag() {
        let mut group = RuleGroup::new();
        let mut tagged = rule("2", "");
        tagged.metadata_mut().msg = Some(crate::operators::Macro::new("blocked").unwrap());
        tagged.metadata_mut().tags.push("attack".to_owned());
        group.add(tagged).unwrap();
        group.add(rule("3", "")).unwrap();

        group.delete_by_msg("blocked");
        assert!(group.find_by_id(2).is_none());
        group.delete_by_range(3, 3);
        assert_eq!(group.count(), 0);
    }
}
