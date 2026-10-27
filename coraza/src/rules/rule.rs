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
    debug_log::{DebugEvent, DebugField, DebugLevel},
    operators::{OperatorOutcome, Outputs},
    rules::{
        RuleOperator, VariableSpec,
        multiphase::{is_multiphase_double_evaluation, multiphase_skip_variable},
    },
    transaction::Transaction,
    types::{RulePhase, RuleVariable},
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
        tx.debug_log(DebugLevel::Debug, "Evaluating rule", || {
            [DebugField::RuleId(self.metadata.id), DebugField::Phase(phase.as_int())]
        });
        let mut collective_matched_values = Vec::new();
        let matched_values = self.matches_chain(tx, self.metadata.id, phase, true, 0, &mut collective_matched_values);
        if matched_values.is_empty() {
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
            if let Some(severity) = self.metadata.severity {
                tx.raise_highest_severity(severity);
            }
        }

        for action in &self.actions {
            if action.action_type() != ActionType::Nondisruptive {
                tx.debug_log(DebugLevel::Debug, "Evaluating action", || {
                    [DebugField::RuleId(self.metadata.id), DebugField::Text(&action.name)]
                });
                action.evaluate(&self.metadata, tx);
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
        chain_level: u16,
        collective_matched_values: &mut Vec<MatchData>,
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
            let mut matched_values =
                self.match_values(tx, id, phase, top_level, chain_level, collective_matched_values);
            if matched_values.is_empty() {
                return matched_values;
            }
            let own_matches = matched_values.len();

            let mut chain_level = chain_level;
            for link in &self.chain {
                chain_level += 1;
                let link_matches = link.matches_chain(tx, id, phase, false, chain_level, collective_matched_values);
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
        })();
        if !top_level {
            Self::log_chain_evaluation(tx, "Finished chain link evaluation", id, self.metadata.id, chain_level);
        }
        matched_values
    }

    /// Log a chain link with both its compiled ID and its position under the parent rule.
    fn log_chain_evaluation(tx: &Transaction, message: &'static str, parent_id: i32, link_id: i32, level: u16) {
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
    fn match_values(
        &self,
        tx: &mut Transaction,
        id: i32,
        phase: RulePhase,
        top_level: bool,
        chain_level: u16,
        collective_matched_values: &mut Vec<MatchData>,
    ) -> Vec<MatchData> {
        let message = self.metadata.msg.as_ref().map(|value| value.expand(tx));
        let log_data = self.metadata.log_data.as_ref().map(|value| value.expand(tx));
        let severity = self.metadata.severity.map_or("unknown", |value| value.as_str());
        tx.set_rule_variables(id, message.clone(), &self.metadata.rev, log_data.clone(), severity);

        let Some(operator) = &self.operator else {
            if !self.variables.is_empty() || self.metadata.sec_mark.is_some() {
                return Vec::new();
            }
            let mut matched = MatchData::new_empty();
            matched.chain_level = chain_level;
            if tx.multiphase_evaluation() {
                collective_matched_values.push(matched.clone());
            }
            tx.record_matched_variable(&matched);
            self.run_nondisruptive_actions(tx);
            if self.chain.is_empty() {
                (matched.message, matched.data) = self.describe_match(tx);
            }
            return vec![matched];
        };

        let multiphase = tx.multiphase_evaluation();
        let mut matched_values = Vec::new();
        for variable in &self.variables {
            if multiphase && top_level && multiphase_skip_variable(self, variable.variable(), phase) {
                continue;
            }
            tx.debug_log(DebugLevel::Debug, "Selecting rule variable", || {
                [DebugField::RuleId(id), DebugField::Variable(variable.variable().name())]
            });
            for value in tx.find_matches_for_rule(variable, id) {
                let candidates = self.transform_candidates(tx, id, value.variable, &value.value);
                for candidate in candidates {
                    Self::log_operator_argument(tx, id, value.variable, &candidate);
                    let mut outputs = Outputs::new(self.metadata.capture);
                    let outcome = operator.evaluate_outcome(tx, &candidate, &mut outputs);
                    tx.store_operator_outputs(&mut outputs);
                    Self::log_operator_outcome(tx, id, value.variable, outcome);
                    match outcome {
                        OperatorOutcome::Matched => {
                            let mut matched = MatchData::new(value.variable, value.key.clone(), candidate);
                            matched.chain_level = chain_level;
                            if multiphase
                                && is_multiphase_double_evaluation(tx, id, collective_matched_values, &matched)
                            {
                                continue;
                            }
                            tx.record_matched_variable(&matched);
                            self.run_nondisruptive_actions(tx);
                            if self.chain.is_empty() {
                                (matched.message, matched.data) = self.describe_match(tx);
                            }
                            matched_values.push(matched);
                        },
                        // A detector skip records the transaction's inspection signal. A
                        // host operator reports `NotMatched` for the same failure, so this
                        // arm stays as defence for an embedder operator whose skip is not
                        // over-long detector input and must not raise that signal.
                        OperatorOutcome::NotInspected if operator.is_detector() => tx.record_inspection_incomplete(id),
                        OperatorOutcome::NotMatched | OperatorOutcome::NotInspected => {},
                    }
                }
            }
        }
        matched_values
    }

    /// Transform one selected value and warn once with all transformation errors.
    fn transform_candidates(
        &self,
        tx: &Transaction,
        rule_id: i32,
        variable: RuleVariable,
        input: &[u8],
    ) -> Vec<Vec<u8>> {
        let (candidates, errors) = if self.metadata.multi_match {
            self.metadata.transformations.apply_multimatch(input)
        } else {
            let (candidate, errors) = self.metadata.transformations.apply(input);
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
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "rule tests use fixed valid rules"
)]
mod tests {
    use super::Rule;
    use crate::{
        actions::{ActionImplementation, ActionType, CompiledAction},
        config::DetectorInspectionAction,
        seclang::Parser,
        types::{RulePhase, RuleVariable},
        waf::Waf,
    };

    fn build_waf(rules: &str, detector_inspection_action: DetectorInspectionAction) -> Waf {
        let mut parser = Parser::new();
        parser.from_string(rules).unwrap();
        parser.config_mut().detector_inspection_action = detector_inspection_action;
        parser.into_waf().unwrap()
    }

    #[test]
    fn later_disruptive_action_replaces_the_previous_one() {
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
            ["setvar", "pass"]
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
    fn a_host_operator_that_cannot_run_is_a_miss_under_fail_closed() {
        let waf = build_waf(
            "SecRule ARGS:q \"@inspectFile /nonexistent/coraza-inspect-file-test\" \"id:960,phase:1,pass\"",
            DetectorInspectionAction::FailClosed,
        );
        let mut tx = waf.new_transaction_with_id("inspect-file-spawn-failure");
        tx.add_get_argument("q", b"value");

        assert!(
            tx.process_request_headers().is_none(),
            "a spawn failure is not over-long detector input, so it must not interrupt"
        );
        assert!(!tx.inspection_incomplete());
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("inspection_incomplete")), None);
    }

    #[cfg(feature = "rbl")]
    #[test]
    fn a_resolver_error_is_a_miss_under_fail_closed() {
        let waf = build_waf(
            "SecRule ARGS:q \"@rbl zen.spamhaus.org\" \"id:961,phase:1,pass\"",
            DetectorInspectionAction::FailClosed,
        );
        let mut tx = waf.new_transaction_with_id("rbl-resolver-error");
        // A NUL byte cannot be part of a resolver request, so this fails without
        // reaching the network, as `LookupHost` does for the same value in Go.
        tx.add_get_argument("q", b"192.0.2.1\0");

        assert!(
            tx.process_request_headers().is_none(),
            "a not-listed value must not interrupt"
        );
        assert!(!tx.inspection_incomplete());
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("inspection_incomplete")), None);
    }

    #[test]
    fn a_detector_over_the_input_bound_still_fails_closed() {
        let waf = build_waf(
            "SecRule ARGS:q \"@detectSQLi\" \"id:962,phase:1,pass\"",
            DetectorInspectionAction::FailClosed,
        );
        let mut tx = waf.new_transaction_with_id("detector-input-bound");
        tx.add_get_argument("q", vec![b' '; libperfusion::MAX_INPUT_LEN + 1]);

        let interruption = tx
            .process_request_headers()
            .expect("a skipped detector input interrupts");
        assert_eq!(interruption.status, 500);
        assert!(tx.inspection_incomplete());
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("inspection_incomplete"))
                .as_deref(),
            Some("1")
        );
    }

    #[test]
    fn count_mode_reports_go_key_str_as_the_matched_name() {
        let waf = build_waf(
            "SecRule &REQUEST_HEADERS:X-Foo \"@ge 1\" \"id:963,phase:1,pass\"",
            DetectorInspectionAction::RecordOnly,
        );
        let mut tx = waf.new_transaction_with_id("count-header-name");
        tx.add_request_header("X-Foo", b"bar");
        assert!(tx.process_request_headers().is_none());
        // Go reports the compile-time `KeyStr`, not the written selector
        // (`internal/corazawaf/transaction.go:698-704`).
        assert_eq!(
            tx.get_variable(RuleVariable::MatchedVarName, None).as_deref(),
            Some("REQUEST_HEADERS:x-foo")
        );

        let waf = build_waf(
            "SecRule &ARGS:/re/ \"@ge 1\" \"id:964,phase:1,pass\"",
            DetectorInspectionAction::RecordOnly,
        );
        let mut tx = waf.new_transaction_with_id("count-args-name");
        tx.add_get_argument("re1", b"one");
        assert!(tx.process_request_headers().is_none());
        assert_eq!(
            tx.get_variable(RuleVariable::MatchedVarName, None).as_deref(),
            Some("ARGS:/re/")
        );
    }
}
