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

use std::{borrow::Cow, mem::size_of};

use crate::{
    actions::{ActionImplementation, ActionType, CompiledAction, RuleMetadata},
    collection::{MATCH_SLOT_BYTES, MatchData, MatchLocation, allocation_bytes},
    debug_log::{DebugEvent, DebugField, DebugLevel},
    operators::{OperatorOutcome, Outputs},
    rules::{
        RuleOperator, TransformationValue, VariableSpec,
        multiphase::{CollectiveMatches, is_multiphase_double_evaluation, multiphase_skip_variable},
    },
    transaction::Transaction,
    types::{RulePhase, RuleVariable},
};

/// A rule compiled from SecLang for transaction evaluation.
#[derive(Debug, Clone)]
pub(crate) struct Rule {
    /// Rule metadata compiled from actions.
    metadata: RuleMetadata,
    /// Variables inspected by this rule.
    variables: Vec<VariableSpec>,
    /// Operator that checks selected variable values.
    operator: Option<RuleOperator>,
    /// Actions retained for transaction evaluation.
    actions: Vec<CompiledAction>,
    /// Phases inferred from the declared phase and selected variables.
    pub(crate) inferred_phases: u8,
    /// Earliest phase at which a complete chain can be evaluated.
    pub(crate) chain_min_phase: RulePhase,
    /// Whether this rule's own variables include a phase-unknown variable.
    pub(crate) has_phase_unknown_variable: bool,
    /// Whether this rule explicitly declares a disruptive action, excluding inherited defaults.
    pub(crate) explicit_disruptive: bool,
    /// Following rules in a chain.
    pub(crate) chain: Vec<Rule>,
}

/// The most bytes of an expanded `msg` or `logdata` kept for one match.
const MAX_MATCH_TEXT_BYTES: usize = 4096;

/// A selected value deferred until its transaction borrow has ended.
enum PendingMatch {
    /// The candidate already evaluated before releasing the selection borrow.
    PreEvaluated {
        /// Variable name used for reporting the result.
        variable: RuleVariable,
        /// Captures or path arguments produced by the operator.
        outputs: Outputs,
        /// Outcome from the first candidate evaluation.
        outcome: OperatorOutcome,
        /// Materialized candidate only when it matched.
        matched: Option<MatchData>,
    },
    /// A snapshot needed because actions or outputs can mutate the selected source.
    Owned(MatchData),
    /// A stable collection position that can be resolved after each prior result.
    Located {
        /// Variable name used for reporting the result.
        variable: RuleVariable,
        /// Source collection and entry position.
        location: MatchLocation,
    },
}

impl Rule {
    /// Creates an empty rule.
    pub(crate) fn new() -> Self {
        Self {
            metadata: RuleMetadata::new(),
            variables: Vec::new(),
            operator: None,
            actions: Vec::new(),
            inferred_phases: 0,
            chain_min_phase: RulePhase::Unknown,
            has_phase_unknown_variable: false,
            explicit_disruptive: false,
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
        if action.action_type() == ActionType::Disruptive
            && let Some(existing) = self
                .actions
                .iter_mut()
                .find(|existing| existing.action_type() == ActionType::Disruptive)
        {
            *existing = action;
            return;
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

    /// Split `ARGS` and `ARGS_NAMES` after the entire variable expression, including
    /// its negations, has been compiled.
    pub(crate) fn split_args_variables(&mut self) {
        let mut variables = Vec::with_capacity(self.variables.len());
        for variable in self.variables.drain(..) {
            match variable.split_args() {
                Ok(split) => variables.extend(split),
                Err(variable) => variables.push(variable),
            }
        }
        self.variables = variables;
    }

    /// Calculate per-rule inferred phases and return whether this rule has an
    /// unknown-phase variable.
    pub(crate) fn finalize_multiphase(&mut self) -> bool {
        self.inferred_phases = 1_u8 << self.metadata.phase.as_int();
        self.has_phase_unknown_variable = false;
        for variable in &self.variables {
            match variable.variable().min_phase() {
                Some(phase) => self.inferred_phases |= 1_u8 << phase.as_int(),
                None => self.has_phase_unknown_variable = true,
            }
        }

        let mut chain_min_phase = RulePhase::Unknown;
        for link in &mut self.chain {
            link.finalize_multiphase();
            if let Some(minimum) = link
                .variables
                .iter()
                .filter_map(|variable| variable.variable().min_phase())
                .min()
            {
                chain_min_phase = chain_min_phase.max(minimum);
            }
        }
        self.chain_min_phase = chain_min_phase;
        self.has_phase_unknown_variable
    }

    /// Whether the Go multiphase phase gate selects this rule for `phase`.
    pub(crate) fn should_evaluate_in_phase(&self, phase: RulePhase, multiphase: bool) -> bool {
        if self.metadata.phase == RulePhase::Unknown || self.metadata.phase == phase {
            return true;
        }
        if !multiphase {
            return false;
        }
        if !self.metadata.has_chain {
            return self.inferred_phases & (1_u8 << phase.as_int()) != 0;
        }

        self.chain_min_phase <= phase
            && phase <= self.metadata.phase
            && (self.inferred_phases & ((1_u8 << (phase.as_int() + 1)) - 2) != 0 || self.has_phase_unknown_variable)
    }

    /// Evaluate this rule and its chain against a transaction.
    pub(crate) fn evaluate(&self, tx: &mut Transaction, phase: RulePhase) {
        self.evaluate_and_record(tx, phase);
        // What the rule held and did not record, its dropped matches and its copies, is given back.
        tx.end_rule_memory();
    }

    /// [`Rule::evaluate`] up to what it must give back once it is done.
    fn evaluate_and_record(&self, tx: &mut Transaction, phase: RulePhase) {
        tx.debug_log(DebugLevel::Debug, "Evaluating rule", || {
            [DebugField::RuleId(self.metadata.id), DebugField::Phase(phase.as_int())]
        });
        let mut collective_matched_values = CollectiveMatches::default();
        let mut inspection_refused = false;
        let matched_values = self.matches_chain(
            tx,
            self.metadata.id,
            phase,
            true,
            0,
            &mut collective_matched_values,
            &mut inspection_refused,
        );
        // The memory budget ended the evaluation: nothing is recorded for the rule, and no rule runs after it.
        if tx.rule_memory_stopped() {
            return;
        }
        // A refused inspection leaves a chain incomplete: the links matched so
        // far are not a match of the rule, so nothing is recorded for it. A
        // rule without a chain keeps the values it matched before the refusal.
        if matched_values.is_empty() || (inspection_refused && !self.chain.is_empty()) {
            tx.debug_log(DebugLevel::Debug, "Rule evaluation finished without a match", || {
                [DebugField::RuleId(self.metadata.id)]
            });
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
            // The record did not fit: the rule is not recorded, so it does not score or deny either, and the phase
            // stops with the memory 503 instead of a denial that `matched_rules()` cannot show.
            if tx.rule_memory_stopped() {
                return;
            }
            if let Some(severity) = self.metadata.severity {
                tx.raise_highest_severity(severity);
            }
        }

        if !inspection_refused {
            for action in &self.actions {
                if action.action_type() != ActionType::Nondisruptive {
                    tx.debug_log(DebugLevel::Debug, "Evaluating action", || {
                        [DebugField::RuleId(self.metadata.id), DebugField::Text(&action.name)]
                    });
                    action.evaluate(&self.metadata, tx);
                }
            }
        }
        tx.debug_log(DebugLevel::Debug, "Finished rule evaluation", || {
            [DebugField::RuleId(self.metadata.id)]
        });
    }

    /// Match this rule and its chain, running nondisruptive actions at each link.
    #[expect(
        clippy::too_many_arguments,
        reason = "phase and shared chain state are explicit across recursive rule evaluation"
    )]
    fn matches_chain(
        &self,
        tx: &mut Transaction,
        id: i32,
        phase: RulePhase,
        top_level: bool,
        chain_level: usize,
        collective_matched_values: &mut CollectiveMatches,
        inspection_refused: &mut bool,
    ) -> Vec<MatchData> {
        if !top_level {
            Self::log_chain_evaluation(tx, "Evaluating chain link", id, self.metadata.id, chain_level);
        }
        let matched_values = (|| {
            if self.metadata.sec_mark.is_some() {
                return Vec::new();
            }
            if tx.multiphase_evaluation() && top_level && self.metadata.has_chain && phase < self.chain_min_phase {
                return Vec::new();
            }
            let mut matched_values = self.match_values(
                tx,
                id,
                phase,
                top_level,
                chain_level,
                collective_matched_values,
                inspection_refused,
            );
            if matched_values.is_empty() || *inspection_refused || tx.rule_memory_stopped() {
                return matched_values;
            }
            let own_matches = matched_values.len();

            let mut chain_level = chain_level;
            for link in &self.chain {
                if tx.rule_engine() == crate::types::RuleEngineStatus::Off {
                    return Vec::new();
                }
                chain_level += 1;
                let link_matches = link.matches_chain(
                    tx,
                    id,
                    phase,
                    false,
                    chain_level,
                    collective_matched_values,
                    inspection_refused,
                );
                // The budget ended the evaluation: nothing is recorded for the rule, so the merge that would grow the
                // list of its matches is not made.
                if tx.rule_memory_stopped() {
                    return Vec::new();
                }
                if *inspection_refused {
                    matched_values.extend(link_matches);
                    return matched_values;
                }
                if link_matches.is_empty() {
                    return Vec::new();
                }
                matched_values.extend(link_matches);
            }
            if !self.chain.is_empty() {
                let (message, data) = self.describe_match(tx);
                // Each match keeps its own copy of the text.
                let text_bytes = allocation_bytes(message.len()).saturating_add(allocation_bytes(data.len()));
                for matched in matched_values.iter_mut().take(own_matches) {
                    if !tx.charge_rule_matches(text_bytes) {
                        break;
                    }
                    matched.message.clone_from(&message);
                    matched.data.clone_from(&data);
                }
            }
            matched_values
        })();
        if !top_level {
            Self::log_chain_evaluation(tx, "Finished chain link evaluation", id, self.metadata.id, chain_level);
        }
        matched_values
    }

    /// Log a chain link with both its compiled ID and its position under the parent rule.
    fn log_chain_evaluation(tx: &Transaction, message: &'static str, parent_id: i32, link_id: i32, level: usize) {
        tx.debug_log_with(DebugLevel::Debug, |logger| {
            let identity = format!("parent_rule_id={parent_id} chain_level={level}");
            let fields = [DebugField::RuleId(link_id), DebugField::Text(&identity)];
            logger.log(
                DebugLevel::Debug,
                &DebugEvent {
                    message,
                    fields: &fields,
                },
            );
        });
    }

    /// Match the values selected by this rule and run per-match actions.
    #[expect(
        clippy::too_many_arguments,
        reason = "phase and shared chain state are explicit across recursive rule evaluation"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Borrowed misses and owned matches share one ordered operator/action loop."
    )]
    fn match_values(
        &self,
        tx: &mut Transaction,
        id: i32,
        phase: RulePhase,
        top_level: bool,
        chain_level: usize,
        collective_matched_values: &mut CollectiveMatches,
        inspection_refused: &mut bool,
    ) -> Vec<MatchData> {
        // What `RULE` keeps of them is cut like what a match keeps: the expansion reads the previous rule's matched
        // value, and the collection holds its buffers for as long as the transaction lives.
        let message = self
            .metadata
            .msg
            .as_ref()
            .map(|value| value.expand_capped(tx, MAX_MATCH_TEXT_BYTES));
        let log_data = self
            .metadata
            .log_data
            .as_ref()
            .map(|value| value.expand_capped(tx, MAX_MATCH_TEXT_BYTES));
        let severity = self.metadata.severity.map_or("unknown", |value| value.as_str());
        tx.set_rule_variables(id, message, &self.metadata.rev, log_data, severity);

        let Some(operator) = &self.operator else {
            if !self.variables.is_empty() || self.metadata.sec_mark.is_some() {
                return Vec::new();
            }
            // Go zero-values the match of an operatorless link instead of assigning
            // its chain depth (internal/corazawaf/rule.go:215-233).
            let mut matched = MatchData::new_empty();
            if !tx.charge_rule_matches(MATCH_SLOT_BYTES) {
                return Vec::new();
            }
            if tx.multiphase_evaluation() {
                collective_matched_values.push(matched.clone());
            }
            tx.record_matched_variable(&matched);
            // The record did not fit: the evaluation is over, and the rule's actions do not run.
            if tx.rule_memory_stopped() {
                return Vec::new();
            }
            self.run_nondisruptive_actions(tx);
            if tx.rule_memory_stopped() {
                return Vec::new();
            }
            if self.chain.is_empty() {
                (matched.message, matched.data) = self.describe_match(tx);
                if !Self::charge_text(tx, &matched) {
                    return Vec::new();
                }
            }
            return vec![matched];
        };

        let mut matched_values = Vec::new();
        for variable in &self.variables {
            if tx.multiphase_evaluation() && top_level && multiphase_skip_variable(self, variable.variable(), phase) {
                continue;
            }
            tx.debug_log(DebugLevel::Debug, "Selecting rule variable", || {
                [DebugField::RuleId(id), DebugField::Variable(variable.variable().name())]
            });
            let pending = if self.metadata.multi_match {
                let owned = tx.find_matches_for_rule(variable, id);
                // The list that holds them pending; a selection the budget cut short has stopped it.
                if !tx.charge_rule_scratch(allocation_bytes(owned.len().saturating_mul(size_of::<PendingMatch>()))) {
                    return matched_values;
                }
                owned.into_iter().map(PendingMatch::Owned).collect()
            } else {
                // The list of the selected values is charged as it grows, and gone with the rule. A selection that
                // did not fit the budget is cut short, and has stopped the evaluation.
                let borrowed_values = tx.find_match_refs_for_rule(variable, id);
                if tx.rule_memory_stopped() {
                    return matched_values;
                }
                let mut pending = Vec::new();
                let snapshot_rest = self.must_snapshot_match_values(variable.variable());
                for (index, value) in borrowed_values.iter().enumerate() {
                    let candidates = self.transform_candidates(tx, id, value.variable(), value.value());
                    let Some(candidate) = candidates.into_iter().next() else {
                        continue;
                    };
                    Self::log_operator_argument(tx, id, value.variable(), candidate.as_bytes());
                    let mut outputs = Outputs::new(self.metadata.capture);
                    let outcome = operator.evaluate_outcome(tx, candidate.as_bytes(), &mut outputs);
                    if outcome == OperatorOutcome::NotMatched && outputs.is_empty() {
                        Self::log_operator_outcome(tx, id, value.variable(), outcome);
                        continue;
                    }

                    let matched = (outcome == OperatorOutcome::Matched)
                        .then(|| Self::new_match(tx, value.variable(), value.key(), candidate))
                        .flatten();
                    // The list that holds this value and those after it is made at once, to the size it is charged:
                    // it is gone with the rule, like the list of the selected values.
                    let left = borrowed_values.len().saturating_sub(index);
                    if tx.rule_budget_is_armed()
                        && !tx.charge_rule_scratch(allocation_bytes(left.saturating_mul(size_of::<PendingMatch>())))
                    {
                        return matched_values;
                    }
                    pending.reserve_exact(left);
                    pending.push(PendingMatch::PreEvaluated {
                        variable: value.variable(),
                        outputs,
                        outcome,
                        matched,
                    });
                    for remaining in borrowed_values.iter().skip(index + 1) {
                        if snapshot_rest {
                            // A copy of each value that is left, which lives as long as the rule does.
                            if !tx.charge_rule_scratch(
                                allocation_bytes(remaining.key().len())
                                    .saturating_add(allocation_bytes(remaining.value().len())),
                            ) {
                                return matched_values;
                            }
                            pending.push(PendingMatch::Owned(remaining.to_owned()));
                        } else if let Some(location) = remaining.location() {
                            pending.push(PendingMatch::Located {
                                variable: remaining.variable(),
                                location,
                            });
                        } else {
                            pending.push(PendingMatch::Owned(remaining.to_owned()));
                        }
                    }
                    break;
                }
                pending
            };
            for value in pending {
                match value {
                    PendingMatch::PreEvaluated {
                        variable,
                        outputs,
                        outcome,
                        matched,
                    } => {
                        if !self.apply_operator_result(
                            tx,
                            id,
                            chain_level,
                            collective_matched_values,
                            inspection_refused,
                            &mut matched_values,
                            variable,
                            outputs,
                            outcome,
                            matched,
                        ) {
                            return matched_values;
                        }
                    },
                    PendingMatch::Owned(value) => {
                        let candidates = self.transform_candidates(tx, id, value.variable, &value.value);
                        for candidate in candidates {
                            Self::log_operator_argument(tx, id, value.variable, candidate.as_bytes());
                            let mut outputs = Outputs::new(self.metadata.capture);
                            let outcome = operator.evaluate_outcome(tx, candidate.as_bytes(), &mut outputs);
                            let matched = (outcome == OperatorOutcome::Matched)
                                .then(|| Self::new_match(tx, value.variable, &value.key, candidate))
                                .flatten();
                            if !self.apply_operator_result(
                                tx,
                                id,
                                chain_level,
                                collective_matched_values,
                                inspection_refused,
                                &mut matched_values,
                                value.variable,
                                outputs,
                                outcome,
                                matched,
                            ) {
                                return matched_values;
                            }
                        }
                    },
                    PendingMatch::Located { variable, location } => {
                        let result = {
                            let Some(value) = tx.find_match_ref_at(variable, location) else {
                                continue;
                            };
                            let candidates = self.transform_candidates(tx, id, value.variable(), value.value());
                            let Some(candidate) = candidates.into_iter().next() else {
                                continue;
                            };
                            Self::log_operator_argument(tx, id, value.variable(), candidate.as_bytes());
                            let mut outputs = Outputs::new(self.metadata.capture);
                            let outcome = operator.evaluate_outcome(tx, candidate.as_bytes(), &mut outputs);
                            let matched = (outcome == OperatorOutcome::Matched)
                                .then(|| Self::new_match(tx, value.variable(), value.key(), candidate))
                                .flatten();
                            (value.variable(), outputs, outcome, matched)
                        };
                        if !self.apply_operator_result(
                            tx,
                            id,
                            chain_level,
                            collective_matched_values,
                            inspection_refused,
                            &mut matched_values,
                            result.0,
                            result.1,
                            result.2,
                            result.3,
                        ) {
                            return matched_values;
                        }
                    },
                }
            }
        }
        matched_values
    }

    /// Transform one selected value and warn once with all transformation errors.
    fn transform_candidates<'a>(
        &self,
        tx: &Transaction,
        rule_id: i32,
        variable: RuleVariable,
        input: &'a [u8],
    ) -> Vec<TransformationValue<'a>> {
        let (candidates, errors) = if self.metadata.multi_match {
            let (candidates, errors) = self.metadata.transformations.apply_multimatch_cow(input);
            let candidates = candidates
                .into_iter()
                .map(|candidate| match candidate {
                    Cow::Borrowed(value) => TransformationValue::Borrowed(value),
                    Cow::Owned(value) => TransformationValue::Owned(value),
                })
                .collect();
            (candidates, errors)
        } else {
            let (candidate, errors) = self.metadata.transformations.apply_cow(input);
            let candidate = match candidate {
                Cow::Borrowed(value) => TransformationValue::Borrowed(value),
                Cow::Owned(value) => TransformationValue::Owned(value),
            };
            (vec![candidate], errors)
        };
        if !errors.is_empty() {
            tx.debug_log_fields(DebugLevel::Warn, "Error transforming argument for rule", || {
                let mut fields = Vec::with_capacity(errors.len().saturating_add(2));
                fields.push(DebugField::RuleId(rule_id));
                fields.push(DebugField::Variable(variable.name()));
                fields.extend(errors.iter().map(|error| DebugField::Text(error.message())));
                fields
            });
        }
        candidates
    }

    /// Log an operator argument only at Trace level, where value exposure is explicit.
    fn log_operator_argument(tx: &Transaction, rule_id: i32, variable: RuleVariable, input: &[u8]) {
        tx.debug_log_with(DebugLevel::Trace, |logger| {
            let text = crate::transformations::text_of(input);
            let fields = [
                DebugField::RuleId(rule_id),
                DebugField::Variable(variable.name()),
                DebugField::Text(&text),
            ];
            logger.log(
                DebugLevel::Trace,
                &DebugEvent {
                    message: "Evaluating operator argument",
                    fields: &fields,
                },
            );
        });
    }

    /// Record the operator's match verdict without including the inspected value.
    fn log_operator_outcome(tx: &Transaction, rule_id: i32, variable: RuleVariable, outcome: OperatorOutcome) {
        let message = match outcome {
            OperatorOutcome::Matched => "Evaluating operator: MATCH",
            OperatorOutcome::NotMatched => "Evaluating operator: NO MATCH",
            OperatorOutcome::NotInspected => "Evaluating operator: NOT INSPECTED",
        };
        tx.debug_log(DebugLevel::Debug, message, || {
            [DebugField::RuleId(rule_id), DebugField::Variable(variable.name())]
        });
    }

    /// Expand this rule's `msg` and `logdata` against the current matched variables, each cut to
    /// [`MAX_MATCH_TEXT_BYTES`].
    ///
    /// CRS's `logdata` expands `%{MATCHED_VAR}`, so a match of a large value would keep a second copy of it in its
    /// data, and one more in its message where that expands it too. Go keeps both whole; here they are what the
    /// audit log's part `K` and `matched_rules()` report, and every match keeps its own. The matched value
    /// (`MatchData::value`) is not cut: the multiphase duplicate check compares it by equality.
    fn describe_match(&self, tx: &Transaction) -> (String, String) {
        let expand = |value: &Option<crate::operators::Macro>| {
            value
                .as_ref()
                .map(|value| value.expand_capped(tx, MAX_MATCH_TEXT_BYTES).into_owned())
                .unwrap_or_default()
        };
        (expand(&self.metadata.msg), expand(&self.metadata.log_data))
    }

    /// Whether per-match actions can change the collection selected by this rule.
    fn must_snapshot_match_values(&self, variable: RuleVariable) -> bool {
        // Locators require immutable sources during per-match effects; add future ARGS/header writers here.
        matches!(
            variable,
            RuleVariable::TX
                | RuleVariable::Env
                | RuleVariable::MatchedVar
                | RuleVariable::MatchedVarName
                | RuleVariable::MatchedVars
                | RuleVariable::MatchedVarsNames
        ) || self
            .operator
            .as_ref()
            .is_some_and(RuleOperator::may_write_path_arguments)
            || self.actions.iter().any(|action| {
                action.action_type() == ActionType::Nondisruptive
                    && !matches!(&action.implementation, ActionImplementation::Builtin)
            })
    }

    /// Apply one already-evaluated operator result in the rule's existing action order.
    #[expect(
        clippy::too_many_arguments,
        reason = "Rule evaluation state remains explicit across each candidate result."
    )]
    fn apply_operator_result(
        &self,
        tx: &mut Transaction,
        id: i32,
        chain_level: usize,
        collective_matched_values: &mut CollectiveMatches,
        inspection_refused: &mut bool,
        matched_values: &mut Vec<MatchData>,
        variable: RuleVariable,
        mut outputs: Outputs,
        outcome: OperatorOutcome,
        matched: Option<MatchData>,
    ) -> bool {
        if tx.rule_memory_stopped() {
            return false;
        }
        tx.store_operator_outputs(&mut outputs);
        if tx.rule_memory_stopped() {
            return false;
        }
        Self::log_operator_outcome(tx, id, variable, outcome);
        if outcome == OperatorOutcome::NotInspected
            && self
                .operator
                .as_ref()
                .is_some_and(RuleOperator::fails_closed_on_not_inspected)
        {
            tx.interrupt(id, "deny", 500, "host operator refused to inspect input");
            *inspection_refused = true;
            return false;
        }
        if outcome == OperatorOutcome::Matched {
            let Some(mut matched) = matched else {
                // No match was made when the budget refused it, and the evaluation is over.
                return !tx.rule_memory_stopped();
            };
            matched.chain_level = chain_level;
            if tx.multiphase_evaluation() {
                // The duplicate check keeps a copy of every match until the rule is done.
                if !tx.charge_rule_scratch(Self::match_bytes(&matched)) {
                    return false;
                }
                if is_multiphase_double_evaluation(tx, id, collective_matched_values, &matched) {
                    tx.release_rule_matches(Self::match_bytes(&matched));
                    // The check dropped its copy of the key and value, which is freed: what stays is its slot in the
                    // list, which keeps its room.
                    tx.release_rule_scratch(Self::copied_bytes(&matched));
                    return true;
                }
            }
            tx.record_matched_variable(&matched);
            if tx.rule_memory_stopped() {
                return false;
            }
            self.run_nondisruptive_actions(tx);
            if tx.rule_memory_stopped() {
                return false;
            }
            if self.chain.is_empty() {
                (matched.message, matched.data) = self.describe_match(tx);
                if !Self::charge_text(tx, &matched) {
                    return false;
                }
            }
            matched_values.push(matched);
        }
        true
    }

    /// What a match holds, beside its text: its slot in the list of matches, the key and the value.
    fn match_bytes(matched: &MatchData) -> usize {
        MATCH_SLOT_BYTES.saturating_add(Self::copied_bytes(matched))
    }

    /// What a copy of a match holds in the buffers it owns: the key and the value.
    fn copied_bytes(matched: &MatchData) -> usize {
        allocation_bytes(matched.key.capacity()).saturating_add(allocation_bytes(matched.value.capacity()))
    }

    /// The record of a match of `candidate`, or `None` when its bytes do not fit what the budget has left: they are
    /// charged before the value is copied, since the copy of a large value is what the budget is there to prevent.
    fn new_match(
        tx: &Transaction,
        variable: RuleVariable,
        key: &str,
        candidate: TransformationValue<'_>,
    ) -> Option<MatchData> {
        if tx.rule_budget_is_armed() {
            let value_bytes = match &candidate {
                TransformationValue::Borrowed(bytes) => bytes.len(),
                TransformationValue::Owned(bytes) => bytes.capacity(),
            };
            let bytes = MATCH_SLOT_BYTES
                .saturating_add(allocation_bytes(key.len()))
                .saturating_add(allocation_bytes(value_bytes));
            if !tx.charge_rule_matches(bytes) {
                return None;
            }
        }
        Some(MatchData::new(variable, key, candidate.into_owned()))
    }

    /// Reserves what the text of `matched` takes, which `describe_match` has just made; the text is cut to a size
    /// that does not need to be reserved before it is, and what it expands from is gone when it is.
    fn charge_text(tx: &Transaction, matched: &MatchData) -> bool {
        tx.charge_rule_matches(
            allocation_bytes(matched.message.capacity()).saturating_add(allocation_bytes(matched.data.capacity())),
        )
    }

    /// Run actions that apply as each rule in a chain matches.
    fn run_nondisruptive_actions(&self, tx: &mut Transaction) {
        for action in &self.actions {
            // An action that did not fit the budget ended the evaluation: nothing runs after it.
            if tx.rule_memory_stopped() {
                break;
            }
            if action.action_type() == ActionType::Nondisruptive {
                tx.debug_log(DebugLevel::Debug, "Evaluating action", || {
                    [DebugField::RuleId(self.metadata.id), DebugField::Text(&action.name)]
                });
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
#[expect(clippy::unwrap_used, reason = "rule tests use fixed valid rules")]
mod tests {
    use std::sync::Arc;

    use super::{CollectiveMatches, MAX_MATCH_TEXT_BYTES, Rule};
    use crate::{
        actions::{ActionImplementation, ActionType, CompiledAction, CustomAction, RuleMetadata},
        collection::MatchData,
        operators::OperatorEnum,
        seclang::Parser,
        transaction::Transaction,
        types::{RulePhase, RuleVariable},
        waf::Waf,
    };

    struct AppendArgumentAction;

    impl CustomAction for AppendArgumentAction {
        fn action_type(&self) -> ActionType {
            ActionType::Nondisruptive
        }

        fn evaluate(&self, _rule: &RuleMetadata, tx: &mut Transaction) {
            tx.add_get_argument("appended", "hit");
        }
    }

    fn build_waf(rules: &str) -> Waf {
        let mut parser = Parser::new();
        parser.from_string(rules).unwrap();
        parser.into_waf().unwrap()
    }

    #[test]
    fn later_disruptive_action_replaces_the_previous_one_in_place() {
        let mut rule = Rule::new();
        rule.push_action(CompiledAction {
            name: "deny".to_owned(),
            argument: String::new(),
            action_type: ActionType::Disruptive,
            implementation: ActionImplementation::Builtin,
        });
        rule.push_action(CompiledAction {
            name: "setvar".to_owned(),
            argument: "TX.count=1".to_owned(),
            action_type: ActionType::Nondisruptive,
            implementation: ActionImplementation::Builtin,
        });
        rule.push_action(CompiledAction {
            name: "pass".to_owned(),
            argument: String::new(),
            action_type: ActionType::Disruptive,
            implementation: ActionImplementation::Builtin,
        });

        assert_eq!(
            rule.actions()
                .iter()
                .map(|action| action.name.as_str())
                .collect::<Vec<_>>(),
            ["pass", "setvar"]
        );
    }

    #[test]
    fn borrowed_selection_materializes_a_snapshot_at_the_first_match() {
        let waf = build_waf("SecRule ARGS:q \"@streq hit\" \"id:969,phase:1,pass,setvar:TX.last=%{MATCHED_VAR}\"");
        let mut tx = waf.new_transaction_with_id("borrowed-selection");
        for value in ["miss", "hit", "hit"] {
            tx.add_get_argument("q", value);
        }

        assert!(tx.process_request_headers().is_none());

        let matched = tx.matched_rules().first().unwrap();
        assert_eq!(
            matched
                .matches
                .iter()
                .map(|item| item.value.as_slice())
                .collect::<Vec<_>>(),
            [b"hit".as_slice(), b"hit"]
        );
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("last")).as_deref(), Some("hit"));
    }

    #[test]
    fn an_early_match_with_large_arguments_keeps_only_matches_in_order() {
        let waf = build_waf("SecRule ARGS \"@streq hit\" \"id:970,phase:1,pass,setvar:TX.hits=+1\"");
        let mut tx = waf.new_transaction_with_id("early-large-args");
        let large_value = vec![b'x'; 8 * 1024];
        for index in 0..1_000 {
            let value: &[u8] = if matches!(index, 0 | 500 | 999) {
                b"hit"
            } else {
                &large_value
            };
            tx.add_get_argument(format!("arg{index:04}"), value);
        }

        assert!(tx.process_request_headers().is_none());

        let matched = tx.matched_rules().first().unwrap();
        assert_eq!(
            matched.matches.iter().map(|item| item.key.as_str()).collect::<Vec<_>>(),
            ["arg0000", "arg0500", "arg0999"]
        );
        assert!(matched.matches.iter().all(|item| item.value == b"hit"));
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("hits")).as_deref(), Some("3"));
    }

    #[test]
    fn selected_tx_values_survive_per_match_tx_mutation() {
        // The first match rewrites or deletes a later selected key; that key must still be
        // evaluated as it was when the rule selected it.
        for effect in ["setvar:TX.second=miss", "setvar:!TX.second"] {
            let waf = build_waf(&format!(
                "SecRule TX \"@streq hit\" \"id:971,phase:1,pass,{effect},setvar:TX.visits=+1\""
            ));
            let mut tx = waf.new_transaction_with_id("tx-snapshot");
            tx.set_tx_variable("first", "hit");
            tx.set_tx_variable("second", "hit");

            assert!(tx.process_request_headers().is_none());

            let matched = tx.matched_rules().first().unwrap();
            assert_eq!(
                matched.matches.iter().map(|item| item.key.as_str()).collect::<Vec<_>>(),
                ["first", "second"],
                "{effect}"
            );
            assert!(matched.matches.iter().all(|item| item.value == b"hit"), "{effect}");
            assert_eq!(
                tx.get_variable(RuleVariable::TX, Some("visits")).as_deref(),
                Some("2"),
                "{effect}"
            );
        }
    }

    #[test]
    fn selected_env_values_survive_per_match_env_mutation() {
        let waf = build_waf(
            "SecAction \"id:972,phase:1,pass,setenv:first=hit,setenv:second=hit\"\n\
             SecRule ENV \"@streq hit\" \"id:973,phase:1,pass,setenv:second=miss\"",
        );
        let mut tx = waf.new_transaction_with_id("env-snapshot");

        assert!(tx.process_request_headers().is_none());

        let matched = tx.matched_rules().iter().find(|rule| rule.rule.id() == 973).unwrap();
        assert_eq!(
            matched.matches.iter().map(|item| item.key.as_str()).collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert!(matched.matches.iter().all(|item| item.value == b"hit"));
        assert_eq!(
            tx.get_variable(RuleVariable::Env, Some("second")).as_deref(),
            Some("miss")
        );
    }

    /// The text a match keeps of its expanded `msg` and `logdata`, which CRS's `logdata` fills with the matched value.
    fn match_text_of(rules: &str, value: &[u8]) -> Vec<(usize, usize)> {
        let waf = build_waf(rules);
        let mut tx = waf.new_transaction_with_id("match-text");
        tx.add_get_argument("q", value);
        assert!(tx.process_request_headers().is_none());
        tx.matched_rules()
            .iter()
            .flat_map(|rule| rule.matches.iter().map(|item| (item.message.len(), item.data.len())))
            .collect()
    }

    #[test]
    fn the_expanded_msg_and_logdata_a_match_keeps_are_capped_where_the_matched_value_is_not() {
        let rules = "SecRule ARGS:q \"@rx .\" \
                     \"id:980,phase:1,pass,msg:'%{MATCHED_VAR}',logdata:'%{MATCHED_VAR} %{MATCHED_VAR}'\"";
        let value = vec![b'v'; 400_000];
        let waf = build_waf(rules);
        let mut tx = waf.new_transaction_with_id("match-text-cap");
        tx.add_get_argument("q", &value);
        assert!(tx.process_request_headers().is_none());

        let matched = tx.matched_rules().first().unwrap().matches.first().unwrap();
        assert_eq!(
            matched.value.len(),
            400_000,
            "the value is kept whole: the duplicate check compares it"
        );
        assert_eq!(matched.message.len(), MAX_MATCH_TEXT_BYTES);
        assert_eq!(matched.data.len(), MAX_MATCH_TEXT_BYTES);
        assert!(
            matched.message.bytes().all(|byte| byte == b'v'),
            "the first bytes are kept"
        );
        // What the RULE collection exposes of the same expansions is capped alike.
        for key in ["msg", "logdata"] {
            let text = tx.get_variable(RuleVariable::Rule, Some(key)).unwrap();
            assert!(
                text.len() <= MAX_MATCH_TEXT_BYTES,
                "RULE:{key} holds {} bytes",
                text.len()
            );
        }
    }

    #[test]
    fn a_cap_on_the_expanded_text_cuts_between_characters_and_leaves_what_fits_alone() {
        let rules = "SecRule ARGS:q \"@rx .\" \"id:981,phase:1,pass,msg:'%{MATCHED_VAR}',logdata:'x%{MATCHED_VAR}'\"";
        // Three-byte characters: a cut at 4096 would land inside one, so it falls back to 4095.
        let euro = "\u{20ac}".repeat(2_000);
        assert_eq!(match_text_of(rules, euro.as_bytes()), [(4095, 4096)]);
        // Exactly the cap, and below it: nothing is cut.
        assert_eq!(match_text_of(rules, &vec![b'v'; MAX_MATCH_TEXT_BYTES]), [(4096, 4096)]);
        assert_eq!(
            match_text_of(rules, &vec![b'v'; MAX_MATCH_TEXT_BYTES - 1]),
            [(4095, 4096)]
        );
        assert_eq!(match_text_of(rules, b"hit"), [(3, 4)]);
        // A constant text over the cap is cut too: what a match keeps is bounded, whatever its source.
        let long_msg = format!(
            "SecRule ARGS:q \"@rx .\" \"id:982,phase:1,pass,msg:'{}'\"",
            "m".repeat(5_000)
        );
        assert_eq!(match_text_of(&long_msg, b"hit"), [(MAX_MATCH_TEXT_BYTES, 0)]);
    }

    #[test]
    fn the_msg_and_logdata_of_every_link_of_a_chain_are_capped() {
        let rules = "SecRule ARGS:q \"@rx .\" \"id:983,phase:1,pass,chain,msg:'%{MATCHED_VAR}',logdata:'%{MATCHED_VAR}'\"\n\
                     SecRule ARGS:q \"@rx .\" \"t:none,msg:'%{MATCHED_VAR}'\"";
        let texts = match_text_of(rules, &vec![b'v'; 400_000]);
        assert!(!texts.is_empty());
        for (message, data) in texts {
            assert!(
                message <= MAX_MATCH_TEXT_BYTES && data <= MAX_MATCH_TEXT_BYTES,
                "{message} {data}"
            );
        }
    }

    #[test]
    fn operator_macros_read_current_rule_msg_and_logdata() {
        let waf = build_waf(
            "SecRule ARGS:q \"@streq %{RULE.msg}\" \"id:977,phase:1,pass,msg:'hit'\"\n\
             SecRule ARGS:q \"@streq %{RULE.logdata}\" \"id:978,phase:1,pass,logdata:'hit'\"",
        );
        let mut tx = waf.new_transaction_with_id("rule-macro-values");
        tx.add_get_argument("q", "hit");

        assert!(tx.process_request_headers().is_none());

        assert_eq!(
            tx.matched_rules().iter().map(|rule| rule.rule.id()).collect::<Vec<_>>(),
            [977, 978]
        );
    }

    /// Recording a match only appends to `MATCHED_VARS`; it never moves or rewrites an entry that is
    /// already selected, and `reset_matched_vars` runs between rules, not within one. No effect
    /// reachable today distinguishes a snapshot from a re-fetch here, so this checks the selection
    /// and its order, not the snapshot.
    #[test]
    fn matched_vars_selection_lists_every_recorded_value_in_order() {
        let mut tx = Transaction::new("matched-vars-snapshot");
        tx.record_matched_variable(&MatchData::new(RuleVariable::Args, "first", b"hit".to_vec()));
        tx.record_matched_variable(&MatchData::new(RuleVariable::Args, "second", b"hit".to_vec()));
        let rule = Rule::new()
            .add_variable(crate::rules::VariableSpec::new(RuleVariable::MatchedVars))
            .with_operator(crate::rules::RuleOperator::new(
                OperatorEnum::new("streq", "hit").unwrap(),
                false,
            ));
        let mut inspection_refused = false;

        let matched = rule.match_values(
            &mut tx,
            974,
            RulePhase::RequestHeaders,
            true,
            0,
            &mut CollectiveMatches::default(),
            &mut inspection_refused,
        );

        assert!(!inspection_refused);
        assert_eq!(
            matched.iter().map(|item| item.key.as_str()).collect::<Vec<_>>(),
            ["ARGS:first", "ARGS:second"]
        );
    }

    /// The public `Transaction` mutators a custom action can call only append to maps (or replace
    /// single values, which have no later selected values), so no custom action can change an
    /// already-selected entry today. This checks that an appending action leaves the selection
    /// intact, not the snapshot itself.
    #[test]
    fn custom_per_match_action_appending_an_argument_leaves_the_selection_intact() {
        let mut parser = Parser::new();
        parser
            .register_action("appendarg", Arc::new(|_| Ok(Box::new(AppendArgumentAction))))
            .unwrap();
        parser
            .from_string("SecRule ARGS \"@streq hit\" \"id:975,phase:1,pass,appendarg\"")
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction_with_id("custom-action-snapshot");
        tx.add_get_argument("first", "hit");
        tx.add_get_argument("second", "hit");

        assert!(tx.process_request_headers().is_none());

        let matched = tx.matched_rules().first().unwrap();
        assert_eq!(
            matched.matches.iter().map(|item| item.key.as_str()).collect::<Vec<_>>(),
            ["first", "second"]
        );
    }

    #[test]
    fn restpath_operator_snapshots_args_before_adding_path_arguments() {
        let waf = build_waf("SecRule ARGS \"@restpath /users/{id}\" \"id:976,phase:1,pass\"");
        let mut tx = waf.new_transaction_with_id("restpath-snapshot");
        tx.add_get_argument("first", "/users/42");
        // The first match rewrites this existing path argument in `ARGS`; it was selected as
        // a matching value and must still be evaluated as such.
        tx.add_path_argument("id", "/users/43");

        assert!(tx.process_request_headers().is_none());

        let matched = tx.matched_rules().first().unwrap();
        assert_eq!(
            matched.matches.iter().map(|item| item.key.as_str()).collect::<Vec<_>>(),
            ["first", "id"]
        );
        assert_eq!(matched.matches.get(1).unwrap().value, b"/users/43");
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPath, Some("id")).as_deref(),
            Some("43")
        );
    }

    #[test]
    fn phase_gate_matches_default_and_multiphase_rules() {
        let mut rule = Rule::new();
        rule.metadata_mut().phase = RulePhase::RequestBody;
        rule.inferred_phases = (1 << RulePhase::RequestHeaders.as_int()) | (1 << RulePhase::RequestBody.as_int());

        assert!(!rule.should_evaluate_in_phase(RulePhase::RequestHeaders, false));
        assert!(rule.should_evaluate_in_phase(RulePhase::RequestHeaders, true));
        assert!(rule.should_evaluate_in_phase(RulePhase::RequestBody, false));
        assert!(!rule.should_evaluate_in_phase(RulePhase::ResponseHeaders, true));

        rule.metadata_mut().has_chain = true;
        rule.chain_min_phase = RulePhase::RequestBody;
        assert!(!rule.should_evaluate_in_phase(RulePhase::RequestHeaders, true));
        assert!(rule.should_evaluate_in_phase(RulePhase::RequestBody, true));
        assert!(!rule.should_evaluate_in_phase(RulePhase::ResponseHeaders, true));

        rule.chain_min_phase = RulePhase::RequestHeaders;
        rule.inferred_phases = 1 << RulePhase::RequestBody.as_int();
        assert!(!rule.should_evaluate_in_phase(RulePhase::RequestHeaders, true));
        rule.has_phase_unknown_variable = true;
        assert!(rule.should_evaluate_in_phase(RulePhase::RequestHeaders, true));

        rule.metadata_mut().phase = RulePhase::Unknown;
        assert!(rule.should_evaluate_in_phase(RulePhase::RequestHeaders, false));
    }

    #[cfg(feature = "inspect-file")]
    #[test]
    fn a_host_operator_that_cannot_run_is_a_miss() {
        let waf =
            build_waf("SecRule ARGS:q \"@inspectFile /nonexistent/coraza-inspect-file-test\" \"id:960,phase:1,pass\"");
        let mut tx = waf.new_transaction_with_id("inspect-file-spawn-failure");
        tx.add_get_argument("q", b"value");

        assert!(
            tx.process_request_headers().is_none(),
            "a spawn failure is not a verdict, so it must not interrupt"
        );
        assert!(tx.matched_rules().is_empty());
    }

    #[cfg(feature = "rbl")]
    #[test]
    fn a_resolver_error_is_a_miss() {
        let waf = build_waf("SecRule ARGS:q \"@rbl zen.spamhaus.org\" \"id:961,phase:1,pass\"");
        let mut tx = waf.new_transaction_with_id("rbl-resolver-error");
        // A NUL byte cannot be part of a resolver request, so this fails without
        // reaching the network, as `LookupHost` does for the same value in Go.
        tx.add_get_argument("q", b"192.0.2.1\0");

        assert!(
            tx.process_request_headers().is_none(),
            "a not-listed value must not interrupt"
        );
        assert!(tx.matched_rules().is_empty());
    }

    #[test]
    fn a_detector_input_over_the_old_bound_is_still_inspected() {
        let waf = build_waf("SecRule ARGS:q \"@detectSQLi\" \"id:962,phase:1,pass\"");
        let mut tx = waf.new_transaction_with_id("detector-input-bound");
        let mut input = b"1' OR '1'='1".to_vec();
        input.resize(libperfusion::MAX_INPUT_LEN + 1, b' ');
        tx.add_get_argument("q", input);

        assert!(tx.process_request_headers().is_none());
        assert!(tx.matched_rules().iter().any(|matched| matched.rule.id == 962));
    }

    #[test]
    fn detect_sqli_keeps_default_and_strict_dialect_detections() {
        let waf = build_waf("SecRule ARGS:q \"@detectSQLi\" \"id:967,phase:1,pass\"");
        for (transaction_id, input) in [
            (
                "sqli-default-lookup",
                b"-2 union select 1,2 copy,version() from x".as_slice(),
            ),
            ("sqli-strict-fallback", b"1 AND JSON_EXTRACT(a,b)=1--"),
        ] {
            let mut tx = waf.new_transaction_with_id(transaction_id);
            tx.add_get_argument("q", input);

            assert!(tx.process_request_headers().is_none());
            assert!(
                tx.matched_rules().iter().any(|matched| matched.rule.id == 967),
                "@detectSQLi missed {transaction_id}"
            );
        }
    }

    #[test]
    fn count_mode_reports_go_key_str_as_the_matched_name() {
        let waf = build_waf("SecRule &REQUEST_HEADERS:X-Foo \"@ge 1\" \"id:963,phase:1,pass\"");
        let mut tx = waf.new_transaction_with_id("count-header-name");
        tx.add_request_header("X-Foo", b"bar");
        assert!(tx.process_request_headers().is_none());
        // Go reports the compile-time `KeyStr`, not the written selector
        // (`internal/corazawaf/transaction.go:698-704`).
        assert_eq!(
            tx.get_variable(RuleVariable::MatchedVarName, None).as_deref(),
            Some("REQUEST_HEADERS:x-foo")
        );

        let waf = build_waf("SecRule &ARGS:/re/ \"@ge 1\" \"id:964,phase:1,pass\"");
        let mut tx = waf.new_transaction_with_id("count-args-name");
        tx.add_get_argument("re1", b"one");
        assert!(tx.process_request_headers().is_none());
        assert_eq!(
            tx.get_variable(RuleVariable::MatchedVarName, None).as_deref(),
            Some("ARGS:/re/")
        );
    }
}
