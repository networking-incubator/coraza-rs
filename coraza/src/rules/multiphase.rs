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

//! Compile-time and evaluation helpers for Go-compatible multiphase rules.

use crate::{
    collection::MatchData,
    rules::Rule,
    transaction::Transaction,
    types::{RulePhase, RuleVariable},
};

/// Whether a top-level variable must be skipped during this phase.
pub(crate) fn multiphase_skip_variable(rule: &Rule, variable: RuleVariable, phase: RulePhase) -> bool {
    let has_chain = rule.metadata().has_chain;
    if !has_chain || phase >= rule.chain_min_phase {
        if let Some(minimum) = variable.min_phase() {
            if has_chain {
                if minimum < rule.chain_min_phase && phase != rule.chain_min_phase {
                    return true;
                }
                // Chained variables stay eligible in later phases so later links can match.
            } else if minimum != phase {
                return true;
            }
        }
    } else if has_chain && phase < rule.chain_min_phase {
        return true;
    }
    false
}

/// The last chain level represented in `matched_values`.
pub(crate) fn matched_chain_depth(matched_values: &[MatchData]) -> u16 {
    matched_values
        .iter()
        .map(|matched| matched.chain_level)
        .max()
        .unwrap_or(0)
}

/// Build every ordered chain from matches grouped by their chain level.
pub(crate) fn generate_chain_matches(
    matched_values: &[MatchData],
    current_depth: u16,
    building: &mut Vec<MatchData>,
    result: &mut Vec<Vec<MatchData>>,
) {
    let final_depth = matched_chain_depth(matched_values);
    for matched in matched_values
        .iter()
        .filter(|matched| matched.chain_level == current_depth)
    {
        building.push(matched.clone());
        if current_depth == final_depth {
            result.push(building.clone());
        } else {
            generate_chain_matches(matched_values, current_depth + 1, building, result);
        }
        drop(building.pop());
    }
}

/// Whether `new_chain` is already present as a prefix of one of the completed chains.
pub(crate) fn chain_part_of(new_chain: &[MatchData], matched_chains: &[Vec<MatchData>]) -> bool {
    matched_chains.iter().any(|matched_chain| {
        new_chain.len() <= matched_chain.len()
            && new_chain
                .iter()
                .zip(matched_chain)
                .all(|(new, matched)| new.variable == matched.variable && new.value == matched.value)
    })
}

/// Append a match to this evaluation's candidate chains, removing it if it duplicates a
/// completed chain already recorded by the transaction.
pub(crate) fn is_multiphase_double_evaluation(
    tx: &Transaction,
    parent_rule_id: i32,
    collective_matched_values: &mut Vec<MatchData>,
    matched: &MatchData,
) -> bool {
    collective_matched_values.push(matched.clone());
    if matched.chain_level == 0 {
        return false;
    }
    let depth = matched_chain_depth(collective_matched_values);
    for previous in tx.matched_rules() {
        if previous.rule.id != parent_rule_id || matched_chain_depth(&previous.matches) != depth {
            continue;
        }

        let mut matched_chains = Vec::new();
        let mut building = Vec::new();
        generate_chain_matches(&previous.matches, 0, &mut building, &mut matched_chains);
        let mut collective_chains = Vec::new();
        let mut building = Vec::new();
        generate_chain_matches(collective_matched_values, 0, &mut building, &mut collective_chains);
        if collective_chains
            .iter()
            .any(|new_chain| chain_part_of(new_chain, &matched_chains))
        {
            drop(collective_matched_values.pop());
            return true;
        }
    }
    false
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "multiphase helper tests use fixed rules and known matched chains"
)]
mod tests {
    use super::{chain_part_of, generate_chain_matches, matched_chain_depth, multiphase_skip_variable};
    use crate::{
        collection::MatchData,
        rules::{Rule, multiphase::is_multiphase_double_evaluation},
        seclang::Parser,
        types::{RulePhase, RuleVariable},
    };

    #[test]
    fn skips_known_variables_outside_their_phase_and_holds_early_chain_inputs() {
        let mut rule = Rule::new();
        rule.metadata_mut().has_chain = true;
        rule.chain_min_phase = RulePhase::RequestBody;

        assert!(multiphase_skip_variable(
            &rule,
            RuleVariable::RequestURI,
            RulePhase::RequestHeaders
        ));
        assert!(!multiphase_skip_variable(
            &rule,
            RuleVariable::RequestURI,
            RulePhase::RequestBody
        ));
        assert!(!multiphase_skip_variable(
            &rule,
            RuleVariable::RequestBody,
            RulePhase::RequestBody
        ));
        assert!(!multiphase_skip_variable(
            &rule,
            RuleVariable::RequestBody,
            RulePhase::ResponseHeaders
        ));
        assert!(multiphase_skip_variable(
            &rule,
            RuleVariable::TX,
            RulePhase::RequestHeaders
        ));
        assert!(!multiphase_skip_variable(
            &rule,
            RuleVariable::TX,
            RulePhase::RequestBody
        ));

        rule.metadata_mut().has_chain = false;
        assert!(!multiphase_skip_variable(
            &rule,
            RuleVariable::RequestURI,
            RulePhase::RequestHeaders
        ));
        assert!(multiphase_skip_variable(
            &rule,
            RuleVariable::RequestURI,
            RulePhase::RequestBody
        ));
        assert!(!multiphase_skip_variable(
            &rule,
            RuleVariable::TX,
            RulePhase::RequestBody
        ));
    }

    #[test]
    fn generated_chain_matches_are_grouped_by_level_and_compared_by_value() {
        let mut parent_a = MatchData::new(RuleVariable::RequestURI, "", b"/a".to_vec());
        let mut parent_b = MatchData::new(RuleVariable::RequestURI, "", b"/b".to_vec());
        let mut child_a = MatchData::new(RuleVariable::RequestBody, "", b"body".to_vec());
        let mut child_b = MatchData::new(RuleVariable::RequestHeaders, "x", b"body".to_vec());
        parent_a.chain_level = 0;
        parent_b.chain_level = 0;
        child_a.chain_level = 1;
        child_b.chain_level = 1;
        let matches = [parent_a.clone(), parent_b, child_a.clone(), child_b];
        let mut chains = Vec::new();
        generate_chain_matches(&matches, 0, &mut Vec::new(), &mut chains);

        assert_eq!(matched_chain_depth(&matches), 1);
        assert_eq!(chains.len(), 4);
        assert!(chain_part_of(&[parent_a.clone(), child_a.clone()], &chains));
        let other = [
            MatchData::new(RuleVariable::RequestURI, "", b"/other".to_vec()),
            child_a,
        ];
        assert!(!chain_part_of(&other, &chains));
    }

    #[test]
    fn duplicate_chain_evaluation_is_removed_from_the_collective_matches() {
        let mut parser = Parser::new();
        parser.config_mut().multiphase_evaluation = true;
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecRule REQUEST_URI \"@contains /\" \"id:1,phase:2,pass,chain\"\n\
                 SecRule REQUEST_BODY \"@contains x\" \"t:none\"",
            )
            .expect("test rules are valid");
        let waf = parser.into_waf().expect("test WAF compiles");
        let mut tx = waf.new_transaction_with_id("duplicate-chain");
        tx.process_uri("/", "POST", "HTTP/1.1");
        tx.add_request_header("content-type", "application/x-www-form-urlencoded");
        tx.process_request_headers();
        tx.process_request_body(b"x");

        let matched = tx.matched_rules().first().expect("chain matched");
        assert_eq!(matched.matches.len(), 2);
        let mut collective = vec![matched.matches[0].clone()];
        assert!(is_multiphase_double_evaluation(
            &tx,
            1,
            &mut collective,
            &matched.matches[1]
        ));
        assert_eq!(collective.len(), 1, "a duplicate was removed from the candidate chain");

        let mut changed = matched.matches[1].clone();
        changed.value = b"different".to_vec();
        assert!(!is_multiphase_double_evaluation(&tx, 1, &mut collective, &changed));
        assert_eq!(collective.len(), 2);
    }

    #[test]
    fn duplicate_chain_match_does_not_repeat_nondisruptive_actions() {
        let mut parser = Parser::new();
        parser.config_mut().multiphase_evaluation = true;
        parser
            .from_string(
                "SecRule REQUEST_URI \"@contains /\" \"id:1,phase:2,pass,chain\"\n\
                 SecRule REQUEST_URI \"@contains /\" \"setvar:tx.counter=+1\"\n\
                 SecRule TX:counter \"@eq 1\" \"id:2,phase:2,deny,status:403\"\n\
                 SecRule TX:counter \"@eq 2\" \"id:3,phase:2,deny,status:500\"",
            )
            .expect("test rules are valid");
        let waf = parser.into_waf().expect("test WAF compiles");
        let mut tx = waf.new_transaction_with_id("duplicate-chain-actions");
        tx.process_uri("/", "GET", "HTTP/1.1");
        tx.process_request_headers();
        let interruption = tx.process_request_body(b"").expect("counter rule interrupts");

        assert_eq!(interruption.rule_id, 2);
        assert_eq!(interruption.status, 403);
        assert_eq!(
            tx.matched_rules()
                .iter()
                .map(|matched| matched.rule.id)
                .collect::<Vec<_>>(),
            [1, 2]
        );
    }

    #[test]
    fn top_level_match_runs_nondisruptive_actions_in_each_phase() {
        let mut parser = Parser::new();
        parser.config_mut().multiphase_evaluation = true;
        parser
            .from_string(
                "SecRule REQUEST_URI \"@streq /\" \"id:1,phase:1,pass,setvar:tx.flag=yes\"\n\
                 SecRule REQUEST_URI|TX:flag \"@streq yes\" \"id:2,phase:2,pass,setvar:tx.count=+1\"\n\
                 SecRule TX:count \"@eq 2\" \"id:3,phase:2,deny,status:403\"",
            )
            .expect("test rules are valid");
        let waf = parser.into_waf().expect("test WAF compiles");
        let mut tx = waf.new_transaction_with_id("top-level-multiphase-actions");
        tx.process_uri("/", "GET", "HTTP/1.1");
        tx.process_request_headers();

        let interruption = tx.process_request_body(b"").expect("counter rule interrupts");
        assert_eq!(interruption.rule_id, 3);
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("count")).as_deref(), Some("2"));
    }

    #[test]
    fn chain_phase_unknown_variable_does_not_open_the_root_gate() {
        let mut parser = Parser::new();
        parser.config_mut().multiphase_evaluation = true;
        parser
            .from_string(
                "SecRequestBodyAccess On\n\
                 SecRule REQUEST_URI \"@streq /\" \"id:10,phase:1,pass,setvar:tx.flag=yes\"\n\
                 SecRule ARGS_POST:foo \"@streq yes\" \"id:11,phase:2,pass,chain,setvar:tx.count=+1\"\n\
                 SecRule TX:flag \"@streq yes\" \"t:none\"",
            )
            .expect("test rules are valid");
        let waf = parser.into_waf().expect("test WAF compiles");
        let mut tx = waf.new_transaction_with_id("chain-phase-unknown-gate");
        tx.process_uri("/", "GET", "HTTP/1.1");
        tx.add_post_argument("foo", "yes");

        tx.process_request_headers();
        assert!(tx.matched_rules().iter().all(|matched| matched.rule_id() != 11));
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("count")), None);

        tx.process_request_body(b"");
        assert!(tx.matched_rules().iter().any(|matched| matched.rule_id() == 11));
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("count")).as_deref(), Some("1"));
    }
}
