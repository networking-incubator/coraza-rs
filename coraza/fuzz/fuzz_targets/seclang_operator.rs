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
    use coraza::{
        operators::{OperatorEnum, Outputs},
        transaction::Transaction,
    };

    pub(crate) struct RuleOperator {
        operator: OperatorEnum,
        negated: bool,
    }

    impl RuleOperator {
        pub(crate) fn new(operator: OperatorEnum, negated: bool) -> Self {
            Self { operator, negated }
        }

        pub(crate) fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
            let matched = self.operator.evaluate(tx, input, out);
            if self.negated { !matched } else { matched }
        }
    }
}

mod operators {
    pub(crate) use coraza::operators::{OperatorContext, OperatorEnum};
}

mod seclang {
    pub(crate) struct CompileError {
        pub(crate) message: String,
    }

    impl CompileError {
        pub(crate) fn new(message: String) -> Self {
            Self { message }
        }
    }
}

#[path = "../../src/seclang/operator_parser.rs"]
mod operator_parser;

fuzz_target!(|data: &[u8]| {
    let (mode, parameter) = data.split_first().map_or((0, &data[..]), |(mode, rest)| (*mode, rest));
    let parameter = String::from_utf8_lossy(parameter);
    let expression = match mode % 4 {
        0 => format!("@rx {parameter}"),
        1 => format!("!@rx {parameter}"),
        2 => format!("x{parameter}"),
        _ => format!("!x{parameter}"),
    };

    let parsed = operator_parser::parse_operator_in(&expression, &operators::OperatorContext::default());
    let outcome = match parsed {
        Ok(operator) => {
            let tx = coraza::transaction::Transaction::new("fuzz");
            let mut outputs = coraza::operators::Outputs::default();
            usize::from(operator.evaluate(&tx, b"", &mut outputs))
        },
        Err(error) => error.message.len(),
    };
    let _ = std::hint::black_box(outcome);
});
