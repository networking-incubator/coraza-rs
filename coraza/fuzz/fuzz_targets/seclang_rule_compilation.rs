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

use coraza::seclang::Parser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (mode, input) = data.split_first().map_or((0, data), |(mode, rest)| (*mode, rest));
    let input = String::from_utf8_lossy(input);
    // Keep input inside one known directive and prevent rule syntax injection.
    let value: String = input
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '"')
        .take(4096)
        .collect();

    let directive = match mode % 2 {
        0 => format!("SecRuleEngine {value}"),
        _ => format!("SecRule {value} \"@contains fixed\" \"id:1,phase:1,pass\""),
    };
    let mut parser = Parser::new();
    let outcome = parser
        .from_string(&directive)
        .map(|()| parser.rule_count())
        .map_err(|error| error.message.len());
    let _ = std::hint::black_box(outcome);
});
