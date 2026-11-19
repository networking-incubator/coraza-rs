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

use std::{
    collections::{BTreeMap, HashMap},
    ops::RangeInclusive,
};

use crate::{
    actions::RuleMetadata,
    rules::{Rule, VariableSpec},
};

/// Callback invoked synchronously after a rule is inserted.
pub(crate) type RuleObserver = dyn Fn(&RuleMetadata) + Send + Sync;

/// Rules compiled so far, in SecLang order.
#[derive(Debug, Clone, Default)]
pub(crate) struct RuleGroup {
    /// Top-level rules in directive order.
    rules: Vec<Rule>,
    /// Indices of top-level rules by current id, in directive order.
    id_index: BTreeMap<i32, Vec<usize>>,
    /// Every rule retained right now, chain members included.
    total: usize,
    /// Rule compilation attempts, including failed attempts and chain members.
    ///
    /// Never decreases: removing or discarding a rule does not refund compilation
    /// work, so a configuration cannot compile an unbounded number of rules and then
    /// delete them to stay under a rule budget.
    compiled: usize,
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
        if id != 0 && self.id_index.contains_key(&id) {
            return Err(format!("duplicated rule id {id}"));
        }

        let inserted = if is_marker {
            self.rules.push(rule);
            self.index_rule(self.rules.len().saturating_sub(1));
            self.rules.last()
        } else if let Some(parent) = self.open_chain() {
            parent.chain.push(rule);
            None
        } else {
            self.rules.push(rule);
            self.index_rule(self.rules.len().saturating_sub(1));
            self.rules.last()
        };
        if let (Some(observer), Some(inserted)) = (observer, inserted) {
            observer(inserted.metadata());
        }
        self.total += 1;
        Ok(())
    }

    /// Drop an unfinished chain after a skipped compilation error.
    pub(crate) fn discard_open_chain(&mut self) -> bool {
        if self.open_chain().is_some() {
            if let Some(rule) = self.rules.pop() {
                let index = self.rules.len();
                self.remove_index(rule.metadata().id, index);
                self.total = self.total.saturating_sub(1 + rule.chain.len());
            }
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
    #[cfg(test)]
    pub(crate) fn find_by_id(&self, id: i32) -> Option<&Rule> {
        let index = self.id_index.get(&id)?.first()?;
        self.rules.get(*index)
    }

    /// Finds the indices of top-level rules in an inclusive id range.
    pub(crate) fn indices_by_id_range(&self, start: i32, end: i32) -> Vec<usize> {
        if start > end {
            return Vec::new();
        }
        if start == end {
            return self.id_index.get(&start).cloned().unwrap_or_default();
        }
        let mut indices: Vec<_> = self
            .id_index
            .range(start..=end)
            .flat_map(|(_, indices)| indices.iter().copied())
            .collect();
        indices.sort_unstable();
        indices
    }

    /// Stage updates by current id, so sequential ranges observe earlier staged id changes.
    ///
    /// Only touched rules are cloned. The live group and index remain unchanged if `update`
    /// fails.
    pub(crate) fn update_by_id_ranges(
        &mut self,
        ranges: &[RangeInclusive<i32>],
        mut update: impl FnMut(&mut Rule) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut staged_rules = Vec::new();
        let mut staged_indices = HashMap::new();
        let mut staged_ids = HashMap::new();
        let mut staged_by_id = BTreeMap::<i32, Vec<usize>>::new();

        for range in ranges {
            let start = *range.start();
            let end = *range.end();
            if start > end {
                return Err(format!("invalid rule id range: {start}-{end}"));
            }
            let mut indices = Vec::new();
            for (id, positions) in self.id_index.range(start..=end) {
                for &index in positions {
                    if staged_ids.get(&index).is_none_or(|&current| current == *id) {
                        indices.push(index);
                    }
                }
            }
            for (_, positions) in staged_by_id.range(start..=end) {
                indices.extend(positions.iter().copied());
            }
            indices.sort_unstable();
            if indices.is_empty() && start == end {
                return Err(format!("rule {start} not found"));
            }

            for index in indices {
                let staged_index = if let Some(&staged_index) = staged_indices.get(&index) {
                    staged_index
                } else {
                    let Some(rule) = self.rule_at(index).cloned() else {
                        continue;
                    };
                    let staged_index = staged_rules.len();
                    staged_rules.push((index, rule));
                    staged_indices.insert(index, staged_index);
                    staged_index
                };
                let Some((_, rule)) = staged_rules.get_mut(staged_index) else {
                    continue;
                };
                let old_id = rule.metadata().id();
                let original_id = self.rule_at(index).map_or(old_id, |rule| rule.metadata().id());
                update(rule)?;
                let new_id = rule.metadata().id();

                if old_id != new_id {
                    if old_id != original_id {
                        Self::remove_index_from(&mut staged_by_id, old_id, index);
                    }
                    if new_id != original_id {
                        Self::insert_index_in(&mut staged_by_id, new_id, index);
                    }
                }
                if new_id == original_id {
                    staged_ids.remove(&index);
                } else {
                    staged_ids.insert(index, new_id);
                }
            }
        }

        for (index, rule) in staged_rules {
            self.replace_rule(index, rule);
        }
        Ok(())
    }

    /// Returns one top-level rule by its stable position.
    pub(crate) fn rule_at(&self, index: usize) -> Option<&Rule> {
        self.rules.get(index)
    }

    /// Returns the variables of one top-level rule by its position.
    ///
    /// Only the variables are exposed: a rule's id can change only through [`Self::replace_rule`],
    /// which keeps the id index in step.
    pub(crate) fn variables_at_mut(&mut self, index: usize) -> Option<&mut Vec<VariableSpec>> {
        self.rules.get_mut(index).map(Rule::variables_mut)
    }

    /// Replace a top-level rule staged by a load-time update.
    pub(crate) fn replace_rule(&mut self, index: usize, rule: Rule) {
        let Some(slot) = self.rules.get_mut(index) else {
            return;
        };
        let old_id = slot.metadata().id();
        let new_id = rule.metadata().id();
        *slot = rule;
        if old_id != new_id {
            self.remove_index(old_id, index);
            self.insert_index(new_id, index);
        }
    }

    /// Rebuild the id index from the rules; the oracle the incremental updates must match.
    #[cfg(test)]
    fn rebuild_id_index(&mut self) {
        self.id_index.clear();
        for index in 0..self.rules.len() {
            let Some(id) = self.rules.get(index).map(|rule| rule.metadata().id()) else {
                continue;
            };
            self.insert_index(id, index);
        }
    }

    /// Add one top-level rule position to the id index.
    fn index_rule(&mut self, index: usize) {
        if let Some(rule) = self.rules.get(index) {
            self.insert_index(rule.metadata().id(), index);
        }
    }

    /// Insert an index in directive order for an id.
    fn insert_index(&mut self, id: i32, index: usize) {
        Self::insert_index_in(&mut self.id_index, id, index);
    }

    /// Insert one directive-order position into an id index.
    fn insert_index_in(index: &mut BTreeMap<i32, Vec<usize>>, id: i32, position: usize) {
        let indices = index.entry(id).or_default();
        let insertion = indices.binary_search(&position).unwrap_or_else(|insertion| insertion);
        indices.insert(insertion, position);
    }

    /// Remove one position from an id's index.
    fn remove_index(&mut self, id: i32, index: usize) {
        Self::remove_index_from(&mut self.id_index, id, index);
    }

    /// Remove one directive-order position from an id index.
    fn remove_index_from(index_map: &mut BTreeMap<i32, Vec<usize>>, id: i32, index: usize) {
        let remove_id = if let Some(indices) = index_map.get_mut(&id) {
            indices.retain(|&candidate| candidate != index);
            indices.is_empty()
        } else {
            false
        };
        if remove_id {
            index_map.remove(&id);
        }
    }

    /// Removes rules with ids in the inclusive range.
    pub(crate) fn delete_by_range(&mut self, start: i32, end: i32) {
        self.remove_where(|rule| (start..=end).contains(&rule.metadata().id()));
    }

    /// Removes rules whose message equals `message`.
    pub(crate) fn delete_by_msg(&mut self, message: &str) {
        self.remove_where(|rule| rule.metadata().msg() == Some(message));
    }

    /// Removes rules tagged with `tag`.
    pub(crate) fn delete_by_tag(&mut self, tag: &str) {
        self.remove_where(|rule| rule.metadata().tags().iter().any(|item| item == tag));
    }

    /// Removes every top-level rule `matches` selects and keeps the id index and total in step.
    ///
    /// The index is shifted in place instead of rebuilt, so a directive that removes nothing
    /// leaves it untouched and one that removes some pays no per-id allocation.
    fn remove_where(&mut self, mut matches: impl FnMut(&Rule) -> bool) {
        let mut removed = Vec::new();
        let mut removed_ids = Vec::new();
        let mut removed_total = 0_usize;
        let mut position = 0_usize;
        self.rules.retain(|rule| {
            let index = position;
            position += 1;
            if matches(rule) {
                removed.push(index);
                removed_ids.push(rule.metadata().id());
                removed_total = removed_total.saturating_add(1 + rule.chain.len());
                false
            } else {
                true
            }
        });
        let Some(&first_removed) = removed.first() else {
            return;
        };
        self.total = self.total.saturating_sub(removed_total);
        // Only the ids of removed rules lose positions; drop those and any id left empty.
        removed_ids.sort_unstable();
        removed_ids.dedup();
        for id in removed_ids {
            if let Some(positions) = self.id_index.get_mut(&id) {
                positions.retain(|position| removed.binary_search(position).is_err());
                if positions.is_empty() {
                    self.id_index.remove(&id);
                }
            }
        }
        // `removed` is ascending, so the number of removed positions below a survivor is how far
        // it moves down, and every id's list stays ascending.
        for position in self.id_index.values_mut().flatten() {
            if *position > first_removed {
                let shift = removed.partition_point(|&index| index < *position);
                *position = position.saturating_sub(shift);
            }
        }
    }

    /// Updates the variables of rules tagged with `tag` and returns their count.
    pub(crate) fn update_by_tag(&mut self, tag: &str, mut update: impl FnMut(&mut Vec<VariableSpec>)) -> usize {
        let mut count = 0;
        for rule in &mut self.rules {
            if rule.metadata().tags().iter().any(|item| item == tag) {
                update(rule.variables_mut());
                count += 1;
            }
        }
        count
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

    /// Count an attempt before compiling, including attempts that fail.
    pub(crate) fn record_compilation(&mut self) {
        self.compiled = self.compiled.saturating_add(1);
    }

    /// Returns the number of compilation attempts, chain members included.
    pub(crate) fn total_count(&self) -> usize {
        self.compiled
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
    fn id_index_tracks_replacement_discard_and_removal() {
        let mut group = RuleGroup::new();
        group.add(rule("1", ""), false, None).unwrap();
        group.add(rule("2", ""), false, None).unwrap();
        assert!(group.find_by_id(1).is_some());

        group.replace_rule(0, rule("3", ""));
        assert!(group.find_by_id(1).is_none());
        assert!(group.find_by_id(3).is_some());

        group.delete_by_range(2, 3);
        assert!(group.find_by_id(2).is_none());
        assert!(group.find_by_id(3).is_none());
        group.add(rule("3", ""), false, None).unwrap();
        assert!(group.find_by_id(3).is_some());

        group.add(rule("4", "chain"), false, None).unwrap();
        assert!(group.discard_open_chain());
        assert!(group.find_by_id(4).is_none());
        group.add(rule("4", ""), false, None).unwrap();
        assert!(group.find_by_id(4).is_some());
    }

    #[test]
    fn id_range_index_returns_rules_in_directive_order() {
        let mut group = RuleGroup::new();
        group.add(rule("30", ""), false, None).unwrap();
        group.add(rule("10", ""), false, None).unwrap();
        group.add(rule("20", ""), false, None).unwrap();

        assert_eq!(group.indices_by_id_range(10, 30), [0, 1, 2]);
    }

    #[test]
    fn id_update_can_return_to_its_original_id_and_keep_order() {
        let mut group = RuleGroup::new();
        group.add(rule("5", ""), false, None).unwrap();
        group.add(rule("10", ""), false, None).unwrap();
        group.add(rule("30", ""), false, None).unwrap();
        let mut update_count = 0;

        group
            .update_by_id_ranges(&[10..=10, 20..=20], |rule| {
                let id = if update_count == 0 { "20" } else { "10" };
                update_count += 1;
                compile_action("id", id, rule.metadata_mut(), ActionCompileContext::default())
                    .map_err(|error| error.to_string())?;
                Ok(())
            })
            .unwrap();

        assert_eq!(group.indices_by_id_range(10, 10), [1]);
        assert!(group.indices_by_id_range(20, 20).is_empty());
        assert_eq!(
            group.iter().map(|rule| rule.metadata().id()).collect::<Vec<_>>(),
            [5, 10, 30]
        );
        assert_eq!(group.indices_by_id_range(5, 30), [0, 1, 2]);
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
    fn discarding_a_chain_does_not_refund_the_compiled_count() {
        let mut group = RuleGroup::new();
        group.record_compilation();
        group.add(rule("1", "chain"), false, None).unwrap();
        let compiled = group.total_count();
        assert_eq!(compiled, 1);
        assert!(group.discard_open_chain());
        assert_eq!(group.count(), 0, "the chain is no longer retained");
        assert_eq!(group.total_count(), compiled, "compilation work is not refunded");
    }

    #[test]
    fn removing_rules_does_not_refund_the_compiled_count() {
        let mut group = RuleGroup::new();
        group.record_compilation();
        group.add(rule("1", ""), false, None).unwrap();
        group.record_compilation();
        group.add(rule("2", ""), false, None).unwrap();
        let compiled = group.total_count();
        assert_eq!(compiled, 2);
        group.delete_by_range(1, 2);
        assert_eq!(group.count(), 0, "both rules are gone");
        assert_eq!(group.total_count(), compiled, "compilation work is not refunded");
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

    fn tagged(id: &str, action: &str, tag: &str, msg: &str) -> Rule {
        let mut rule = rule(id, action);
        if !tag.is_empty() {
            rule.metadata_mut().tags.push(tag.to_owned());
        }
        if !msg.is_empty() {
            rule.metadata_mut().msg = Some(crate::operators::Macro::new(msg).unwrap());
        }
        rule
    }

    fn marker(label: &str) -> Rule {
        let mut rule = Rule::new();
        rule.metadata_mut().sec_mark = Some(label.to_owned());
        rule
    }

    fn live_total(group: &RuleGroup) -> usize {
        group.rules().iter().map(|rule| 1 + rule.chain.len()).sum()
    }

    /// The incrementally maintained index and total must equal a fresh recomputation.
    fn assert_consistent(group: &RuleGroup) {
        let mut oracle = group.clone();
        oracle.rebuild_id_index();
        assert_eq!(group.id_index, oracle.id_index, "id index diverged from a full rebuild");
        assert_eq!(group.total, live_total(group), "total diverged from the retained rules");
    }

    /// Ids 1, 2, 3, marker (id 0), 4, chain parent 5 with one member, 6, 7; odd ids tagged
    /// `odd`, even ids `even`; the message is `m<id>`.
    fn sample_group() -> RuleGroup {
        let mut group = RuleGroup::new();
        group.add(tagged("1", "", "odd", "m1"), false, None).unwrap();
        group.add(tagged("2", "", "even", "m2"), false, None).unwrap();
        group.add(tagged("3", "", "odd", "m3"), false, None).unwrap();
        group.add(marker("MID"), false, None).unwrap();
        group.add(tagged("4", "", "even", "m4"), false, None).unwrap();
        group.add(tagged("5", "chain", "odd", "m5"), false, None).unwrap();
        group.add(rule("", ""), false, None).unwrap();
        group.add(tagged("6", "", "even", "m6"), false, None).unwrap();
        group.add(tagged("7", "", "odd", "m7"), false, None).unwrap();
        assert_consistent(&group);
        group
    }

    /// `sample_group` with a second rule that carries id 2, as `replace_rule` can produce.
    fn sample_group_with_duplicate_id() -> RuleGroup {
        let mut group = sample_group();
        group.replace_rule(6, tagged("2", "", "dup", "dup"));
        assert_eq!(group.indices_by_id_range(2, 2), [1, 6]);
        assert_consistent(&group);
        group
    }

    fn ids(group: &RuleGroup) -> Vec<i32> {
        group.iter().map(|rule| rule.metadata().id()).collect()
    }

    #[test]
    fn range_removal_keeps_the_index_equal_to_a_rebuild() {
        let ranges = [
            (100, 200),
            (5, 3),
            (1, 1),
            (7, 7),
            (4, 4),
            (0, 0),
            (2, 3),
            (1, 7),
            (1, 2),
            (6, 7),
            (3, 6),
        ];
        for (start, end) in ranges {
            for mut group in [sample_group(), sample_group_with_duplicate_id()] {
                let before = ids(&group);
                group.delete_by_range(start, end);
                let expected: Vec<_> = before.into_iter().filter(|id| !(start..=end).contains(id)).collect();
                assert_eq!(ids(&group), expected, "range {start}..={end}");
                assert_consistent(&group);
            }
        }
    }

    #[test]
    fn tag_removal_keeps_the_index_equal_to_a_rebuild() {
        for tag in ["none", "odd", "even", "dup"] {
            for mut group in [sample_group(), sample_group_with_duplicate_id()] {
                group.delete_by_tag(tag);
                assert!(
                    group
                        .iter()
                        .all(|rule| !rule.metadata().tags().iter().any(|item| item == tag)),
                    "tag {tag}"
                );
                assert_consistent(&group);
            }
        }
    }

    #[test]
    fn message_removal_keeps_the_index_equal_to_a_rebuild() {
        for message in ["none", "m1", "m7", "m4", "m5", "dup", "m2"] {
            for mut group in [sample_group(), sample_group_with_duplicate_id()] {
                group.delete_by_msg(message);
                assert!(group.iter().all(|rule| rule.metadata().msg() != Some(message)));
                assert_consistent(&group);
            }
        }
    }

    #[test]
    fn removing_nothing_leaves_the_group_untouched() {
        let mut group = sample_group_with_duplicate_id();
        let (index, total, rules) = (group.id_index.clone(), group.total, ids(&group));
        group.delete_by_range(100, 200);
        group.delete_by_tag("none");
        group.delete_by_msg("none");
        assert_eq!(group.id_index, index);
        assert_eq!(group.total, total);
        assert_eq!(ids(&group), rules);
    }

    #[test]
    fn removed_ids_can_be_added_again_but_surviving_ids_cannot() {
        let mut group = sample_group();
        group.delete_by_range(2, 3);
        group.delete_by_tag("even");
        group.delete_by_msg("m7");
        assert_consistent(&group);

        group.add(rule("2", ""), false, None).unwrap();
        group.add(rule("7", ""), false, None).unwrap();
        assert_consistent(&group);
        assert_eq!(group.indices_by_id_range(2, 2), [group.count() - 2]);
        for surviving in ["1", "5", "7"] {
            assert!(
                group
                    .add(rule(surviving, ""), false, None)
                    .unwrap_err()
                    .contains(&format!("duplicated rule id {surviving}"))
            );
        }
        assert_consistent(&group);
    }

    fn next_random(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn random_below(state: &mut u64, bound: usize) -> usize {
        usize::try_from(next_random(state) % u64::try_from(bound).unwrap()).unwrap()
    }

    #[test]
    fn random_mutation_sequences_keep_the_index_and_total_consistent() {
        const TAGS: [&str; 3] = ["", "a", "b"];
        const MESSAGES: [&str; 3] = ["", "x", "y"];
        for seed in [0x9E37_79B9_7F4A_7C15_u64, 0x1234_5678_9ABC_DEF1, 0xDEAD_BEEF_CAFE_F00D] {
            let mut state = seed;
            let mut group = RuleGroup::new();
            for _ in 0..1500 {
                match random_below(&mut state, 8) {
                    0..=2 => {
                        let id = random_below(&mut state, 14);
                        let id = if id == 0 { String::new() } else { id.to_string() };
                        let action = if random_below(&mut state, 4) == 0 { "chain" } else { "" };
                        let tag = TAGS[random_below(&mut state, 3)];
                        let msg = MESSAGES[random_below(&mut state, 3)];
                        let new_rule = if random_below(&mut state, 10) == 0 {
                            marker("M")
                        } else {
                            tagged(&id, action, tag, msg)
                        };
                        drop(group.add(new_rule, false, None));
                    },
                    3 => {
                        let start = i32::try_from(random_below(&mut state, 15)).unwrap();
                        let end = start + i32::try_from(random_below(&mut state, 4)).unwrap();
                        group.delete_by_range(start, end);
                    },
                    4 => group.delete_by_tag(TAGS[random_below(&mut state, 3)]),
                    5 => group.delete_by_msg(MESSAGES[random_below(&mut state, 3)]),
                    6 => {
                        let index = random_below(&mut state, group.count() + 1);
                        if let Some(mut replacement) = group.rule_at(index).cloned() {
                            let id = random_below(&mut state, 14);
                            if id != 0 {
                                replacement.metadata_mut().id = i32::try_from(id).unwrap();
                            }
                            group.replace_rule(index, replacement);
                        }
                    },
                    _ => {
                        group.discard_open_chain();
                    },
                }
                assert_consistent(&group);
            }
        }
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
