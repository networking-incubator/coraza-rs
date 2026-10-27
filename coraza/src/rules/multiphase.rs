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
pub(crate) fn matched_chain_depth(matched_values: &[MatchData]) -> usize {
    matched_values
        .iter()
        .map(|matched| matched.chain_level)
        .max()
        .unwrap_or(0)
}

/// Whether every level of the candidate chain already has an equal recorded part.
///
/// Go compares the Cartesian products of the per-level matches, but the levels are
/// independent: a candidate chain repeats an earlier one exactly when each of its
/// levels holds a variable and value already recorded at that level. Checking the
/// per-level intersections gives Go's answer without building every ordered
/// combination, so repeated evaluation of a wide chain stays bounded.
fn chain_already_matched(candidate: &[MatchData], recorded: &[MatchData], depth: usize) -> bool {
    (0..=depth).all(|level| {
        candidate
            .iter()
            .filter(|matched| matched.chain_level == level)
            .any(|matched| {
                recorded.iter().any(|previous| {
                    previous.chain_level == level
                        && previous.variable == matched.variable
                        && previous.value == matched.value
                })
            })
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

        if chain_already_matched(collective_matched_values, &previous.matches, depth) {
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
    use super::{chain_already_matched, matched_chain_depth, multiphase_skip_variable};
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
    fn chain_parts_are_compared_per_level_by_variable_and_value() {
        let mut parent_a = MatchData::new(RuleVariable::RequestURI, "", b"/a".to_vec());
        let mut parent_b = MatchData::new(RuleVariable::RequestURI, "", b"/b".to_vec());
        let mut child_a = MatchData::new(RuleVariable::RequestBody, "", b"body".to_vec());
        let mut child_b = MatchData::new(RuleVariable::RequestHeaders, "x", b"body".to_vec());
        parent_a.chain_level = 0;
        parent_b.chain_level = 0;
        child_a.chain_level = 1;
        child_b.chain_level = 1;
        let recorded = [parent_a.clone(), parent_b, child_a.clone(), child_b];

        assert_eq!(matched_chain_depth(&recorded), 1);
        assert!(chain_already_matched(
            &[parent_a.clone(), child_a.clone()],
            &recorded,
            1
        ));
        let other = [
            MatchData::new(RuleVariable::RequestURI, "", b"/other".to_vec()),
            child_a,
        ];
        assert!(!chain_already_matched(&other, &recorded, 1));

        // A level with no candidate parts, as left by an operatorless link that keeps
        // level 0, can never repeat an earlier chain: Go's generated chain set is empty.
        let mut deep = MatchData::new(RuleVariable::RequestBody, "", b"deep".to_vec());
        deep.chain_level = 2;
        assert!(!chain_already_matched(&[parent_a, deep], &recorded, 2));
    }

    #[test]
    fn operatorless_chain_link_keeps_level_zero_and_is_never_a_duplicate() {
        let mut parser = Parser::new();
        parser.config_mut().multiphase_evaluation = true;
        parser
            .from_string(
                "SecRule REQUEST_URI \"@streq /\" \"id:1,phase:2,pass,chain\"\n\
                 SecAction \"chain\"\n\
                 SecRule REQUEST_URI \"@streq /\" \"setvar:tx.count=+1\"\n\
                 SecRule TX:count \"@eq 2\" \"id:2,phase:2,deny,status:403\"",
            )
            .expect("test rules are valid");
        let waf = parser.into_waf().expect("test WAF compiles");
        let mut tx = waf.new_transaction_with_id("operatorless-chain-level");
        tx.process_uri("/", "GET", "HTTP/1.1");
        tx.process_request_headers();

        let matched = tx.matched_rules().first().expect("chain matches at request headers");
        assert_eq!(
            matched
                .matches
                .iter()
                .map(|matched| matched.chain_level)
                .collect::<Vec<_>>(),
            [0, 0, 2],
            "an operatorless link records level 0 like Go's zero-valued match"
        );
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("count")).as_deref(), Some("1"));

        // The level 0 short-circuit keeps the link itself out of the suppression path,
        // and the missing level 1 part means no completed chain can repeat, so the
        // re-evaluation runs the inner actions again, as in Go.
        let interruption = tx.process_request_body(b"").expect("count reaches 2 and rule 2 fires");
        assert_eq!(interruption.rule_id, 2);
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("count")).as_deref(), Some("2"));
    }

    #[test]
    fn duplicate_check_stays_bounded_for_wide_chains() {
        // Eight chain levels with ten values each: the recorded rule holds 80 matches
        // and the Cartesian product of the per-level values would hold 10^8 chains.
        // Finishing this test under the default timeout is the bound on the work; the
        // duplicate decision itself is asserted exactly.
        let mut rules = String::from("SecRule ARGS \"@contains hit\" \"id:1,phase:2,pass,chain\"\n");
        for _ in 1..7 {
            rules.push_str("SecRule ARGS \"@contains hit\" \"chain\"\n");
        }
        rules.push_str("SecRule ARGS \"@contains hit\" \"setvar:tx.hits=+1\"\n");

        let mut parser = Parser::new();
        parser.config_mut().multiphase_evaluation = true;
        parser.from_string(&rules).expect("stress chain compiles");
        let waf = parser.into_waf().expect("stress WAF compiles");
        let mut tx = waf.new_transaction_with_id("multiphase-wide-chain");
        for index in 0..10 {
            tx.add_get_argument(format!("key{index}"), "hit");
        }

        tx.process_request_headers();
        let recorded = tx.matched_rules().first().expect("wide chain matches");
        assert_eq!(recorded.matches.len(), 80);
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("hits")).as_deref(), Some("10"));

        tx.process_request_body(b"");
        assert_eq!(tx.matched_rules().len(), 1, "the repeated chain is suppressed");
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("hits")).as_deref(), Some("10"));
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
