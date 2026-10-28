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

#![no_main]

use libfuzzer_sys::fuzz_target;

mod rules {
    use coraza::types::RuleVariable;
    use regex::Regex;

    #[derive(Clone)]
    pub(crate) enum VariableKey {
        String(String),
        Regex(Regex),
    }

    #[derive(Clone)]
    pub(crate) struct VariableSpec {
        variable: RuleVariable,
        key: Option<VariableKey>,
        count: bool,
        exceptions: Vec<VariableKey>,
    }

    impl VariableSpec {
        pub(crate) fn new(variable: RuleVariable) -> Self {
            Self {
                variable,
                key: None,
                count: false,
                exceptions: Vec::new(),
            }
        }

        pub(crate) fn new_string(variable: RuleVariable, key: String) -> Self {
            let mut spec = Self::new(variable);
            spec.key = Some(VariableKey::String(key));
            spec
        }

        pub(crate) fn new_regex(variable: RuleVariable, regex: Regex, _count_key: String) -> Self {
            let mut spec = Self::new(variable);
            spec.key = Some(VariableKey::Regex(regex));
            spec
        }

        pub(crate) fn set_count(&mut self, count: bool) {
            self.count = count;
        }

        pub(crate) fn add_exception_string(&mut self, key: &str) {
            self.exceptions.push(VariableKey::String(key.to_owned()));
        }

        pub(crate) fn add_exception_regex(&mut self, regex: Regex) {
            self.exceptions.push(VariableKey::Regex(regex));
        }

        pub(crate) fn variable(&self) -> RuleVariable {
            self.variable
        }

        pub(crate) fn split_args(self) -> Result<[Self; 2], Self> {
            let variables = match self.variable {
                RuleVariable::Args => [RuleVariable::ArgsGet, RuleVariable::ArgsPost],
                RuleVariable::ArgsNames => [RuleVariable::ArgsGetNames, RuleVariable::ArgsPostNames],
                _ => return Err(self),
            };
            let mut get = self.clone();
            get.variable = variables[0];
            let mut post = self;
            post.variable = variables[1];
            Ok([get, post])
        }

        pub(crate) fn fingerprint(&self) -> usize {
            let selected_key_len = self.key.as_ref().map_or(0, key_len);
            let exception_len = self.exceptions.iter().map(key_len).sum::<usize>();
            usize::from(self.variable.as_u8())
                .saturating_add(selected_key_len)
                .saturating_add(exception_len)
                .saturating_add(usize::from(self.count))
        }
    }

    fn key_len(key: &VariableKey) -> usize {
        match key {
            VariableKey::String(key) => key.len(),
            VariableKey::Regex(regex) => regex.as_str().len(),
        }
    }
}

mod seclang {
    #[derive(Debug)]
    pub(crate) struct CompileError {
        pub(crate) message: String,
    }

    impl CompileError {
        pub(crate) fn new(message: String) -> Self {
            Self { message }
        }
    }
}

mod types {
    pub(crate) use coraza::types::RuleVariable;
}

/// The crate's folding helper is `pub(crate)`, so the shim keeps a copy of the
/// one-line simple mapping: U+0130 folds to `i`, as Go's `strings.ToLower` does.
mod utils {
    pub(crate) fn lowercase_like_go(value: &str) -> String {
        value
            .chars()
            .map(|character| character.to_lowercase().next().unwrap_or(character))
            .collect()
    }
}

#[allow(unfulfilled_lint_expectations)]
#[path = "../../src/seclang/variable_parser.rs"]
mod variable_parser;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let outcome = variable_parser::parse_variables_in_mode(&input, false).map(|specs| {
        specs
            .iter()
            .map(rules::VariableSpec::fingerprint)
            .fold(0_usize, usize::saturating_add)
    });
    let multiphase_outcome = variable_parser::parse_variables_in_mode(&input, true).map(|specs| {
        specs
            .iter()
            .map(rules::VariableSpec::fingerprint)
            .fold(0_usize, usize::saturating_add)
    });
    let outcome = outcome.map_err(|error| error.message.len());
    let multiphase_outcome = multiphase_outcome.map_err(|error| error.message.len());
    let _ = std::hint::black_box((outcome, multiphase_outcome));
});
