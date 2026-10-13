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

use libperfusion::{
    BuiltinSqlLookup, Dialect, HtmlContext, HtmlTokenizer, Quote, SqlLookup, SqlState, SqlTokenType, SqlTokenizer,
    xss_in_context,
};

#[test]
fn selected_sql_contexts_have_distinct_quote_and_dialect_behavior() {
    let input = b"1--x";
    let contexts = [
        (Quote::None, Dialect::Ansi),
        (Quote::None, Dialect::Mysql),
        (Quote::Single, Dialect::Ansi),
        (Quote::Single, Dialect::Mysql),
        (Quote::Double, Dialect::Ansi),
        (Quote::Double, Dialect::Mysql),
    ];

    for (quote, dialect) in contexts {
        let mut state = SqlState::new(input);
        let fingerprint = state.fingerprint(quote, dialect);
        assert!(!fingerprint.as_bytes().is_empty(), "{quote:?} {dialect:?}");
        assert!(state.stats().tokens > 0, "{quote:?} {dialect:?}");
    }

    let ansi: Vec<_> = SqlTokenizer::new(input, Quote::None, Dialect::Ansi).collect();
    assert_eq!(ansi.len(), 2);
    assert_eq!(ansi[1].kind(), SqlTokenType::Comment);

    let mysql: Vec<_> = SqlTokenizer::new(input, Quote::None, Dialect::Mysql).collect();
    assert_eq!(mysql.len(), 4);
    assert!(mysql.iter().all(|token| token.kind() != SqlTokenType::Comment));

    for quote in [Quote::Single, Quote::Double] {
        for dialect in [Dialect::Ansi, Dialect::Mysql] {
            let mut state = SqlState::new(input);
            assert_eq!(state.fingerprint(quote, dialect).as_str(), "s");
        }
    }
}

#[derive(Clone, Copy)]
struct CustomLookup;

impl SqlLookup for CustomLookup {
    fn lookup_word(&self, word: &[u8]) -> Option<SqlTokenType> {
        match word {
            b"XOR" => Some(SqlTokenType::LogicOperator),
            b"PRIVATE PHRASE" => Some(SqlTokenType::Union),
            _ => BuiltinSqlLookup.lookup_word(word),
        }
    }

    fn lookup_operator(&self, operator: &[u8]) -> Option<SqlTokenType> {
        if operator == b"<=" {
            Some(SqlTokenType::LogicOperator)
        } else {
            BuiltinSqlLookup.lookup_operator(operator)
        }
    }

    fn is_fingerprint(&self, fingerprint: &[u8]) -> bool {
        fingerprint == b"U"
            || fingerprint == b"nn"
            || fingerprint == b"s"
            || BuiltinSqlLookup.is_fingerprint(fingerprint)
    }
}

#[test]
fn custom_lookup_controls_words_operators_phrases_and_fingerprints_after_reset() {
    let tokens: Vec<_> = SqlTokenizer::with_lookup(b"XOR <= value", Quote::None, Dialect::Ansi, CustomLookup).collect();
    assert_eq!(tokens[0].kind(), SqlTokenType::LogicOperator);
    assert_eq!(tokens[1].kind(), SqlTokenType::LogicOperator);

    let mut phrase = SqlState::with_lookup(b"PRIVATE PHRASE", CustomLookup);
    assert_eq!(phrase.fingerprint(Quote::None, Dialect::Ansi).as_str(), "U");
    assert!(phrase.check_fingerprint());
    assert_eq!(phrase.tokens().next().unwrap().kind(), SqlTokenType::Union);
    phrase.reset();
    assert_eq!(phrase.fingerprint(Quote::None, Dialect::Ansi).as_str(), "U");
    assert!(phrase.check_fingerprint());

    let mut custom_fingerprint = SqlState::with_lookup(b"hello world", CustomLookup);
    assert_eq!(
        custom_fingerprint.fingerprint(Quote::None, Dialect::Ansi).as_str(),
        "nn"
    );
    assert!(custom_fingerprint.check_fingerprint());

    let mut custom_reparse = SqlState::with_lookup(b"abc'", CustomLookup);
    let (fingerprint, dialect) = custom_reparse.detect().unwrap();
    assert_eq!(fingerprint.as_str(), "s");
    assert_eq!(dialect, Dialect::Ansi);
}

#[test]
fn explicit_xss_checks_and_html_iteration_cover_each_context() {
    let cases = [
        (b"<script>x</script>".as_slice(), HtmlContext::Data),
        (b" onclick=x", HtmlContext::ValueNoQuote),
        (b"'><svg/onload=x>", HtmlContext::ValueSingleQuote),
        (b"\"><svg/onload=x>", HtmlContext::ValueDoubleQuote),
        (b"`><svg/onload=x>", HtmlContext::ValueBackQuote),
    ];

    for (input, context) in cases {
        assert!(xss_in_context(input, context), "{context:?}: {input:?}");
        assert!(!HtmlTokenizer::new(input, context).collect::<Vec<_>>().is_empty());
    }
    assert!(!xss_in_context(b"<p>safe</p>", HtmlContext::Data));
}

#[test]
fn default_sql_tokens_and_statistics_match_the_reference_api() {
    let inputs: &[&[u8]] = &[
        b"1; ; 2",
        b"select a,b from t where id=1",
        b"'x' 'y'",
        b"1::integer",
        b"1--x",
        b"@@version # comment",
        b"select {foo bar}",
    ];
    let contexts = [
        (Quote::None, Dialect::Ansi, 1 | 8),
        (Quote::None, Dialect::Mysql, 1 | 16),
        (Quote::Single, Dialect::Ansi, 2 | 8),
        (Quote::Single, Dialect::Mysql, 2 | 16),
        (Quote::Double, Dialect::Ansi, 4 | 8),
        (Quote::Double, Dialect::Mysql, 4 | 16),
    ];

    for input in inputs {
        for (quote, dialect, flags) in contexts {
            let mut actual_lexer = SqlTokenizer::new(input, quote, dialect);
            let actual_raw: Vec<_> = actual_lexer.by_ref().collect();
            let mut expected_raw = Vec::new();
            let expected_stats = libinjection::sqli_tokenize_visit(input, flags, |token| expected_raw.push(token));
            assert_eq!(
                actual_raw.len(),
                expected_raw.len(),
                "raw {input:?} {quote:?} {dialect:?}"
            );
            for (actual, expected) in actual_raw.iter().zip(&expected_raw) {
                assert_eq!(actual.kind().as_byte(), expected.category);
                assert_eq!(actual.pos(), expected.pos);
                assert_eq!(actual.len(), expected.len);
                assert_eq!(actual.variable_count(), expected.count);
                assert_eq!(actual.string_open().unwrap_or(0), expected.str_open);
                assert_eq!(actual.string_close().unwrap_or(0), expected.str_close);
                assert_eq!(actual.value(), &expected.val[..expected.len]);
            }
            assert_eq!(actual_lexer.stats().tokens, expected_stats.tokens);
            assert_eq!(actual_lexer.stats().folds, expected_stats.folds);
            assert_eq!(actual_lexer.stats().comment_ddx, expected_stats.comment_ddx);
            assert_eq!(actual_lexer.stats().comment_hash, expected_stats.comment_hash);

            let mut actual_state = SqlState::new(input);
            let actual_folded: Vec<_> = actual_state.fold(quote, dialect).collect();
            let mut expected_folded = Vec::new();
            let expected_stats = libinjection::sqli_fold_visit(input, flags, |token| expected_folded.push(token));
            assert_eq!(
                actual_folded.len(),
                expected_folded.len(),
                "fold {input:?} {quote:?} {dialect:?}"
            );
            for (actual, expected) in actual_folded.iter().zip(&expected_folded) {
                assert_eq!(actual.kind().as_byte(), expected.category);
                assert_eq!(actual.pos(), expected.pos);
                assert_eq!(actual.len(), expected.len);
                assert_eq!(actual.variable_count(), expected.count);
                assert_eq!(actual.string_open().unwrap_or(0), expected.str_open);
                assert_eq!(actual.string_close().unwrap_or(0), expected.str_close);
                assert_eq!(actual.value(), &expected.val[..expected.len]);
            }
            assert_eq!(actual_state.stats().tokens, expected_stats.tokens);
            assert_eq!(actual_state.stats().folds, expected_stats.folds);
            assert_eq!(actual_state.stats().comment_ddx, expected_stats.comment_ddx);
            assert_eq!(actual_state.stats().comment_hash, expected_stats.comment_hash);
        }
    }
}
