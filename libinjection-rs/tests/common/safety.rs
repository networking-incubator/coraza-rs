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

use libperfusion::{Dialect, HtmlContext, HtmlTokenizer, Quote, SqlState, SqlTokenizer};

const SQL_CONTEXTS: [(Quote, Dialect); 6] = [
    (Quote::None, Dialect::Ansi),
    (Quote::None, Dialect::Mysql),
    (Quote::Single, Dialect::Ansi),
    (Quote::Single, Dialect::Mysql),
    (Quote::Double, Dialect::Ansi),
    (Quote::Double, Dialect::Mysql),
];
const HTML_CONTEXTS: [HtmlContext; 5] = [
    HtmlContext::Data,
    HtmlContext::ValueNoQuote,
    HtmlContext::ValueSingleQuote,
    HtmlContext::ValueDoubleQuote,
    HtmlContext::ValueBackQuote,
];

pub(crate) fn exercise(input: &[u8], case_id: &str) {
    for (quote, dialect) in SQL_CONTEXTS {
        let mut count = 0_usize;
        for token in SqlTokenizer::new(input, quote, dialect) {
            count = count.saturating_add(1);
            assert!(
                count <= input.len().saturating_add(2),
                "{case_id}: SQL tokenizer stalled"
            );
            assert!(
                token
                    .pos()
                    .checked_add(token.len())
                    .is_some_and(|end| end <= input.len()),
                "{case_id}: SQL token escaped the input"
            );
        }

        let mut state = SqlState::new(input);
        count = 0;
        for token in state.fold(quote, dialect) {
            count = count.saturating_add(1);
            assert!(count <= input.len().saturating_add(2), "{case_id}: SQL fold stalled");
            assert!(
                token
                    .pos()
                    .checked_add(token.len())
                    .is_some_and(|end| end <= input.len()),
                "{case_id}: folded SQL token escaped the input"
            );
        }
    }

    let start = input.as_ptr() as usize;
    let end = start.saturating_add(input.len());
    for context in HTML_CONTEXTS {
        let mut count = 0_usize;
        for token in HtmlTokenizer::new(input, context) {
            count = count.saturating_add(1);
            assert!(
                count <= input.len().saturating_mul(2).saturating_add(16),
                "{case_id}: HTML tokenizer stalled"
            );
            let token_start = token.text.as_ptr() as usize;
            let token_end = token_start.saturating_add(token.text.len());
            assert!(
                token_start >= start && token_end <= end,
                "{case_id}: HTML token escaped the input"
            );
        }
    }
}
