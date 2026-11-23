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

use std::collections::{HashMap, HashSet};

use ahash::RandomState;

use crate::{
    collection::MatchData,
    rules::Rule,
    transaction::{MatchedRule, Transaction},
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

/// The matches one rule evaluation collects for the multiphase duplicate check.
///
/// Go compares the Cartesian products of the per-level matches, but the levels are
/// independent: a candidate chain repeats an earlier record exactly when each of its
/// levels holds a variable and value recorded at that level. Rescanning the collected
/// matches for the depth and comparing every candidate with every recorded match made
/// a link with N matches cost N squared, times M recorded matches. The counts
/// kept here give the same answer with one hash lookup per match and earlier record.
#[derive(Default)]
pub(crate) struct CollectiveMatches {
    /// Every match collected so far, in order.
    values: Vec<MatchData>,
    /// The counts, built at the first chain-link match of the evaluation, so that an
    /// evaluation without one (a chainless rule, or multiphase off) pays nothing for them.
    index: Option<ChainIndex>,
}

impl CollectiveMatches {
    /// Collect a match, updating the counts once they exist.
    pub(crate) fn push(&mut self, matched: MatchData) {
        #[cfg(test)]
        charge_check_work(1);
        if let Some(index) = &mut self.index {
            index.count(&matched, true);
        }
        self.values.push(matched);
    }

    /// Remove the match collected last.
    fn pop(&mut self) {
        if let (Some(matched), Some(index)) = (self.values.pop(), &mut self.index) {
            index.count(&matched, false);
        }
    }
}

/// The per-level counts of the collected matches and the earlier records of the rule.
struct ChainIndex {
    /// `tx.matched_rules().len()` when built. Records are only appended, so a different
    /// length means a rule was recorded during this evaluation and the index is rebuilt.
    records_seen: usize,
    /// Collected matches per chain level without trailing zeros, so the depth is the last
    /// index and falls again when a duplicate is popped.
    level_counts: Vec<usize>,
    /// The earlier records of the rule being evaluated.
    recorded: Vec<RecordedChain>,
}

impl ChainIndex {
    /// Index the earlier records of `parent_rule_id` and count the matches collected so far.
    fn new(records: &[MatchedRule], parent_rule_id: i32, collected: &[MatchData]) -> Self {
        let mut index = Self {
            records_seen: records.len(),
            level_counts: Vec::new(),
            recorded: records
                .iter()
                .filter(|previous| previous.rule.id == parent_rule_id)
                .map(|previous| RecordedChain::new(&previous.matches))
                .collect(),
        };
        for matched in collected {
            index.count(matched, true);
        }
        index
    }

    /// Count a match in (`collected`) or out of the level counts and the hits of the records.
    fn count(&mut self, matched: &MatchData, collected: bool) {
        let level = matched.chain_level;
        if collected {
            if self.level_counts.len() <= level {
                self.level_counts.resize(level.saturating_add(1), 0);
            }
            if let Some(count) = self.level_counts.get_mut(level) {
                *count = count.saturating_add(1);
            }
        } else {
            if let Some(count) = self.level_counts.get_mut(level) {
                *count = count.saturating_sub(1);
            }
            while self.level_counts.last() == Some(&0) {
                self.level_counts.pop();
            }
        }
        for chain in &mut self.recorded {
            chain.count(matched, collected);
        }
    }

    /// The highest chain level collected so far.
    fn depth(&self) -> usize {
        self.level_counts.len().saturating_sub(1)
    }
}

/// The values recorded at one chain level for one variable.
type RecordedValues = HashSet<Vec<u8>, RandomState>;

/// One earlier record of the rule and how many collected matches repeat its parts.
struct RecordedChain {
    /// The record's chain depth; only a candidate chain of the same depth can repeat it.
    depth: usize,
    /// Recorded values by chain level and variable.
    parts: HashMap<(usize, RuleVariable), RecordedValues, RandomState>,
    /// Collected matches at each level `0..=depth` equal to a recorded part of that level.
    hits: Vec<usize>,
    /// Levels in `0..=depth` with at least one hit.
    levels_hit: usize,
}

impl RecordedChain {
    /// Index a record's matches.
    fn new(matches: &[MatchData]) -> Self {
        #[cfg(test)]
        charge_check_work(matches.len());
        let mut parts: HashMap<_, RecordedValues, RandomState> = HashMap::default();
        for matched in matches {
            parts
                .entry((matched.chain_level, matched.variable))
                .or_default()
                .insert(matched.value.clone());
        }
        let depth = matched_chain_depth(matches);
        Self {
            depth,
            parts,
            hits: vec![0; depth.saturating_add(1)],
            levels_hit: 0,
        }
    }

    /// Count a collected match in (`collected`) or out of the hits, if it repeats a part.
    fn count(&mut self, matched: &MatchData, collected: bool) {
        #[cfg(test)]
        charge_check_work(1);
        let repeated = self
            .parts
            .get(&(matched.chain_level, matched.variable))
            .is_some_and(|values| values.contains(matched.value.as_slice()));
        if !repeated {
            return;
        }
        let Some(hits) = self.hits.get_mut(matched.chain_level) else {
            return;
        };
        if collected {
            *hits = hits.saturating_add(1);
            if *hits == 1 {
                self.levels_hit = self.levels_hit.saturating_add(1);
            }
        } else if *hits > 0 {
            *hits -= 1;
            if *hits == 0 {
                self.levels_hit = self.levels_hit.saturating_sub(1);
            }
        }
    }

    /// Whether the collected matches, at `depth`, hold a recorded part at every level.
    fn is_repeated_at(&self, depth: usize) -> bool {
        self.depth == depth && self.levels_hit > depth
    }
}

/// Append a match to this evaluation's candidate chains, removing it if it duplicates a
/// completed chain already recorded by the transaction.
pub(crate) fn is_multiphase_double_evaluation(
    tx: &Transaction,
    parent_rule_id: i32,
    collective_matched_values: &mut CollectiveMatches,
    matched: &MatchData,
) -> bool {
    collective_matched_values.push(matched.clone());
    if matched.chain_level == 0 {
        return false;
    }
    let records = tx.matched_rules();
    if collective_matched_values
        .index
        .as_ref()
        .is_some_and(|index| index.records_seen != records.len())
    {
        collective_matched_values.index = None;
    }
    let index = collective_matched_values
        .index
        .get_or_insert_with(|| ChainIndex::new(records, parent_rule_id, &collective_matched_values.values));
    let depth = index.depth();
    if index.recorded.iter().any(|chain| chain.is_repeated_at(depth)) {
        collective_matched_values.pop();
        return true;
    }
    false
}

#[cfg(test)]
thread_local! {
    /// Duplicate-check work on this thread: matches collected, looked up or indexed.
    static CHECK_WORK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Count duplicate-check work, which tests read to bound its growth without a clock.
#[cfg(test)]
fn charge_check_work(units: usize) {
    CHECK_WORK.with(|work| work.set(work.get().saturating_add(units)));
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "multiphase helper tests use fixed rules and known matched chains"
)]
mod tests {
    use super::{CHECK_WORK, CollectiveMatches, matched_chain_depth, multiphase_skip_variable};
    use crate::{
        actions::RuleMetadata,
        collection::MatchData,
        rules::{Rule, multiphase::is_multiphase_double_evaluation},
        seclang::Parser,
        transaction::Transaction,
        types::{RulePhase, RuleVariable},
    };

    /// The quadratic duplicate check the counts replaced, kept as their oracle: whether every
    /// level of the candidate chain already has an equal recorded part.
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

    /// The `is_multiphase_double_evaluation` the counts replaced, quadratic in the collected matches.
    fn oracle_double_evaluation(
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
        fn part(variable: RuleVariable, value: &str, level: usize) -> MatchData {
            let mut matched = MatchData::new(variable, "", value);
            matched.chain_level = level;
            matched
        }
        // Whether the last match of `candidate`, checked after the others were collected, repeats
        // a recorded chain of rule 1, asserted equal on the counted check and its quadratic oracle.
        fn repeats(tx: &Transaction, candidate: &[MatchData]) -> bool {
            let (last, earlier) = candidate.split_last().expect("candidate has a link match");
            let mut collective = CollectiveMatches::default();
            for matched in earlier {
                collective.push(matched.clone());
            }
            let mut oracle = earlier.to_vec();
            let expected = oracle_double_evaluation(tx, 1, &mut oracle, last);
            let actual = is_multiphase_double_evaluation(tx, 1, &mut collective, last);
            assert_eq!(actual, expected, "counted check and oracle disagree on {candidate:?}");
            actual
        }

        let parent_a = part(RuleVariable::RequestURI, "/a", 0);
        let parent_b = part(RuleVariable::RequestURI, "/b", 0);
        let child_a = part(RuleVariable::RequestBody, "body", 1);
        let child_b = part(RuleVariable::RequestHeaders, "body", 1);
        let deep = part(RuleVariable::RequestBody, "deep", 2);
        let recorded = vec![parent_a.clone(), parent_b, child_a.clone(), child_b];
        assert_eq!(matched_chain_depth(&recorded), 1);

        let waf = Parser::new().into_waf().expect("empty WAF compiles");
        let mut tx = waf.new_transaction_with_id("multiphase-chain-parts");
        let mut rule = RuleMetadata::new();
        rule.id = 1;
        tx.record_match(rule.clone(), recorded, None);
        tx.record_match(rule, vec![parent_a.clone(), child_a.clone(), deep.clone()], None);

        assert!(repeats(&tx, &[parent_a.clone(), child_a.clone()]));
        let other = part(RuleVariable::RequestURI, "/other", 0);
        assert!(!repeats(&tx, &[other, child_a.clone()]), "level 0 differs");
        let other_variable = part(RuleVariable::ArgsGet, "body", 1);
        assert!(
            !repeats(&tx, &[parent_a.clone(), other_variable]),
            "same value, other variable"
        );
        let other_level = part(RuleVariable::RequestURI, "/a", 1);
        assert!(
            !repeats(&tx, &[parent_a.clone(), other_level]),
            "a level 0 part at level 1"
        );

        // A level with no candidate parts, as left by an operatorless link that keeps
        // level 0, can never repeat an earlier chain: Go's generated chain set is empty.
        assert!(repeats(&tx, &[parent_a.clone(), child_a, deep.clone()]));
        assert!(!repeats(&tx, &[parent_a, deep]), "level 1 is missing");
    }

    #[test]
    fn chain_depth_represents_more_than_a_widened_u16() {
        let mut matched = MatchData::new(RuleVariable::RequestURI, "", b"/a".to_vec());

        matched.chain_level = usize::from(u16::MAX) + 1;

        assert_eq!(matched_chain_depth(&[matched]), usize::from(u16::MAX) + 1);
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
        let mut collective = CollectiveMatches::default();
        collective.push(matched.matches[0].clone());
        assert!(is_multiphase_double_evaluation(
            &tx,
            1,
            &mut collective,
            &matched.matches[1]
        ));
        assert_eq!(
            collective.values.len(),
            1,
            "a duplicate was removed from the candidate chain"
        );
        assert_eq!(
            collective.index.as_ref().map(|index| index.level_counts.as_slice()),
            Some([1].as_slice()),
            "the depth falls back with the removed duplicate"
        );

        let mut changed = matched.matches[1].clone();
        changed.value = b"different".to_vec();
        assert!(!is_multiphase_double_evaluation(&tx, 1, &mut collective, &changed));
        assert_eq!(collective.values.len(), 2);
    }

    #[test]
    fn counted_duplicate_check_matches_the_quadratic_oracle() {
        // Generated chains of 1 to 4 levels over few variables and values, so parts repeat: records
        // of the rule, of another rule and of other depths, missing levels, operatorless level 0
        // parts on both sides, duplicates popped mid-sequence and a rule recorded during the evaluation.
        const PARENT: i32 = 7;
        const VARIABLES: [RuleVariable; 3] = [RuleVariable::ArgsGet, RuleVariable::ArgsPost, RuleVariable::Unknown];
        const VALUES: [&str; 2] = ["a", ""];
        fn part(rng: &mut fastrand::Rng, level: usize) -> MatchData {
            if rng.u8(..10) == 0 {
                // Go's zero-valued match of an operatorless link, recorded and collected at level 0.
                return MatchData::new_empty();
            }
            let mut matched = MatchData::new(
                VARIABLES[rng.usize(..VARIABLES.len())],
                "k",
                VALUES[rng.usize(..VALUES.len())],
            );
            matched.chain_level = level;
            matched
        }
        fn record(tx: &mut Transaction, rng: &mut fastrand::Rng, depth: usize) {
            let mut rule = RuleMetadata::new();
            rule.id = if rng.u8(..4) == 0 { PARENT + 1 } else { PARENT };
            let depth = if rng.u8(..4) == 0 { rng.usize(..4) } else { depth };
            let mut matches = Vec::new();
            for level in 0..=depth {
                // One level in six is missing, as an operatorless link leaves it.
                let parts = if rng.u8(..6) == 0 { 0 } else { rng.usize(1..=3) };
                matches.extend((0..parts).map(|_| part(rng, level)));
            }
            if !matches.is_empty() {
                tx.record_match(rule, matches, None);
            }
        }

        let waf = Parser::new().into_waf().expect("empty WAF compiles");
        let mut rng = fastrand::Rng::with_seed(0x0058_3308);
        let (mut checks, mut duplicates) = (0_usize, 0_usize);
        for case in 0..3_000 {
            let mut tx = waf.new_transaction_with_id("multiphase-differential");
            let depth = rng.usize(1..4);
            for _ in 0..rng.usize(..=3) {
                record(&mut tx, &mut rng, depth);
            }
            let mut oracle = Vec::new();
            let mut collective = CollectiveMatches::default();
            for step in 0..rng.usize(1..=24) {
                match rng.u8(..12) {
                    0 => {
                        let matched = MatchData::new_empty();
                        oracle.push(matched.clone());
                        collective.push(matched);
                    },
                    1 => record(&mut tx, &mut rng, depth),
                    _ => {
                        let level = rng.usize(..=depth);
                        let matched = part(&mut rng, level);
                        let expected = oracle_double_evaluation(&tx, PARENT, &mut oracle, &matched);
                        let actual = is_multiphase_double_evaluation(&tx, PARENT, &mut collective, &matched);
                        assert_eq!(actual, expected, "case {case} step {step}: {matched:?}");
                        checks += 1;
                        duplicates += usize::from(expected);
                    },
                }
                assert_eq!(collective.values, oracle, "case {case} step {step}");
                if let Some(index) = &collective.index {
                    assert_eq!(
                        index.depth(),
                        matched_chain_depth(&oracle),
                        "case {case} step {step}: depth"
                    );
                }
            }
        }
        assert!(
            duplicates > 1_000 && checks - duplicates > 1_000,
            "the generated inputs exercise both answers: {duplicates} duplicates in {checks} checks"
        );
    }

    /// Duplicate-check work for the phase 2 pass of `rules` over `get` query and `post` body arguments.
    fn phase_two_check_work(rules: &str, get: usize, post: usize, value: &str) -> usize {
        let mut parser = Parser::new();
        parser.config_mut().multiphase_evaluation = true;
        parser.from_string(rules).expect("test rules are valid");
        let waf = parser.into_waf().expect("test WAF compiles");
        let mut tx = waf.new_transaction_with_id("multiphase-linear");
        tx.process_uri("/", "POST", "HTTP/1.1");
        for index in 0..get {
            tx.add_get_argument(format!("g{index}"), format!("{value}g{index}"));
        }
        tx.process_request_headers();
        for index in 0..post {
            tx.add_post_argument(format!("p{index}"), format!("{value}p{index}"));
        }
        CHECK_WORK.with(|work| work.set(0));
        tx.process_request_body(b"");
        CHECK_WORK.with(std::cell::Cell::get)
    }

    #[test]
    fn multiphase_chain_link_cost_must_be_linear_in_matches() {
        // Work units per argument. Each argument is collected at most twice (parent and link match),
        // looked up once in each of the rule's few earlier records and indexed once per record:
        // 1.0 to 4.8 units at the sizes below. Re-indexing the records at every link match instead
        // of once per evaluation costs about M units per argument (over 100 here).
        const PER_ARGUMENT: usize = 8;

        // A chain link matching N values, with no earlier record of the rule.
        let single = "SecRule REQUEST_URI \"@rx .\" \"id:2,phase:2,pass,nolog,chain\"\n\
                      SecRule ARGS_POST \"@rx 1\" \"t:none\"";
        let base = phase_two_check_work(single, 0, 300, "1");
        let doubled = phase_two_check_work(single, 0, 600, "1");
        assert!(base > 300, "every link match is checked: {base}");
        assert!(
            doubled <= base.saturating_mul(5) / 2 && doubled <= PER_ARGUMENT * 600,
            "doubling the link matches took the duplicate-check work from {base} to {doubled}"
        );

        // M values recorded in phase 1, then N new link matches in phase 2: N squared x M before.
        // Doubling N and M together catches N x M work, which grows only 2x per dimension.
        let across = "SecRule ARGS_GET|ARGS_POST \"@rx x\" \"id:3,phase:2,pass,nolog,chain\"\n\
                      SecRule MATCHED_VARS \"@rx x\" \"t:none\"";
        let base = phase_two_check_work(across, 50, 300, "x");
        assert!(base <= PER_ARGUMENT * 350, "M=50 N=300: {base}");
        for (get, post) in [(50, 600), (100, 300), (100, 600)] {
            let work = phase_two_check_work(across, get, post, "x");
            assert!(
                work <= base.saturating_mul(5) / 2 && work <= PER_ARGUMENT * (get + post),
                "M={get} N={post}: doubling took the duplicate-check work from {base} to {work}"
            );
        }
    }

    #[test]
    fn flood_is_blocked_in_both_modes() {
        // CRS 944120 and the 949110 threshold, reduced: cookies and XML values that match the parent
        // and its MATCHED_VARS link, the flood that made the quadratic duplicate check take seconds.
        // The verdict does not depend on the mode.
        let rules = "SecRuleEngine On\nSecRequestBodyAccess On\n\
            SecAction \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=XML\"\n\
            SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_BODY|REQUEST_HEADERS|\
            !REQUEST_HEADERS:Cookie|XML:/*|XML://@* \
            \"@rx (?:clonetransform|xmldecod)er|f(?:orclosure|ilewriter)|in(?:stantiate(?:factory|transformer)|\
            vokertransformer)|(?:prototype(?:clone|serialization)factor|getpropert)y|whileclosure\" \
            \"id:944120,phase:2,block,t:none,t:lowercase,chain\"\n\
            SecRule MATCHED_VARS \"@rx (?:runtime|processbuilder)\" \
            \"setvar:'tx.rce_score=+5',setvar:'tx.inbound_anomaly_score_pl1=+5'\"\n\
            SecRule TX:INBOUND_ANOMALY_SCORE_PL1 \"@ge 5\" \"id:949110,phase:2,deny,status:403\"";
        let cookie: String = (0..100).map(|index| format!("a=xmldecoder runtime{index}; ")).collect();
        let inner: String = (0..400)
            .map(|index| format!("xmldecoder runtime v{index}<i/>"))
            .collect();
        let body = format!("<r>{inner}</r>");
        for multiphase in [false, true] {
            let mut parser = Parser::new();
            parser.config_mut().multiphase_evaluation = multiphase;
            parser.from_string(rules).expect("reduced CRS rules are valid");
            let waf = parser.into_waf().expect("reduced CRS WAF compiles");
            let mut tx = waf.new_transaction_with_id("multiphase-flood");
            tx.process_uri("/x", "POST", "HTTP/1.1");
            tx.add_request_header("Content-Type", "application/xml");
            tx.add_request_header("Cookie", &cookie);
            tx.process_request_headers();
            tx.process_request_body(body.as_bytes());
            let interruption = tx.interruption().expect("the flood is blocked");
            assert_eq!(
                (interruption.rule_id, interruption.status),
                (949_110, 403),
                "multiphase={multiphase}"
            );
        }
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
