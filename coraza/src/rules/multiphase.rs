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
    rules::Rule,
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

#[cfg(test)]
mod tests {
    use super::multiphase_skip_variable;
    use crate::{
        rules::Rule,
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
}
