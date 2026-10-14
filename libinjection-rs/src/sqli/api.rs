// Copyright (c) 2012-2016, Nick Galbreath
// Copyright (c) 2017-2024, libinjection Contributors
// Copyright 2026 Coraza Kubernetes Operator contributors.
//
// SPDX-License-Identifier: BSD-3-Clause
// See the crate's LICENSE for the complete terms.
//! Supported read-only SQL token and parser APIs.

#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "Private API backing state is documented through the public token and parser types."
    )
)]
use super::{
    Dialect, Fingerprint, State,
    keywords::{BuiltinSqlLookup, SqlLookup},
    lexer::{Lexer, Quote, Stats},
    token::{Token, TokenType},
};

/// SQL token information with immutable access to its bounded value buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlToken(Token);

impl SqlToken {
    /// The token category, whose byte is also its fingerprint character.
    #[must_use]
    pub const fn kind(&self) -> TokenType {
        self.0.ty
    }

    /// Byte offset in the original input.
    #[must_use]
    pub const fn pos(&self) -> usize {
        self.0.pos
    }

    /// Length of the token value, capped at 31 bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len
    }

    /// Whether this token value is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.len == 0
    }

    /// Number of leading `@` bytes for a variable token.
    #[must_use]
    pub const fn variable_count(&self) -> u8 {
        self.0.count
    }

    /// Opening string delimiter, if present.
    #[must_use]
    pub const fn string_open(&self) -> Option<u8> {
        self.0.str_open
    }

    /// Closing string delimiter, if present.
    #[must_use]
    pub const fn string_close(&self) -> Option<u8> {
        self.0.str_close
    }

    /// Token value bytes, at most 31 bytes long.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        self.0.value()
    }

    /// Token value as C string functions see it: bytes before the first NUL.
    #[must_use]
    pub fn c_value(&self) -> &[u8] {
        self.0.c_str()
    }
}

/// SQL tokenizer and counters for one selected quote/dialect context.
pub struct SqlTokenizer<'a, L = BuiltinSqlLookup> {
    lexer: Lexer<'a, L>,
}

impl<'a> SqlTokenizer<'a> {
    /// Tokenizes `input` with the built-in keyword and operator tables.
    #[must_use]
    pub fn new(input: &'a [u8], quote: Quote, dialect: Dialect) -> Self {
        Self {
            lexer: Lexer::new(input, quote, dialect),
        }
    }
}

impl<'a, L: SqlLookup> SqlTokenizer<'a, L> {
    /// Tokenizes `input` with a caller-provided lookup.
    #[must_use]
    pub fn with_lookup(input: &'a [u8], quote: Quote, dialect: Dialect, lookup: L) -> Self {
        Self {
            lexer: Lexer::with_lookup(input, quote, dialect, lookup),
        }
    }

    /// Statistics accumulated while reading tokens.
    #[must_use]
    pub const fn stats(&self) -> SqlStatistics {
        self.lexer.stats
    }
}

impl<L: SqlLookup> Iterator for SqlTokenizer<'_, L> {
    type Item = SqlToken;

    fn next(&mut self) -> Option<Self::Item> {
        self.lexer.next().map(SqlToken)
    }
}

/// SQL token and fold counters from a tokenizer or parser pass.
pub type SqlStatistics = Stats;

/// SQL parser state for selected-context fingerprints and folded tokens.
pub struct SqlState<'a, L = BuiltinSqlLookup> {
    state: State<'a, L>,
}

impl<'a> SqlState<'a> {
    /// Creates a parser using libperfusion's built-in lookup.
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            state: State::new(input, Quote::None, Dialect::Ansi),
        }
    }
}

impl<'a, L: SqlLookup> SqlState<'a, L> {
    /// Creates a parser using a caller-provided lookup.
    #[must_use]
    pub fn with_lookup(input: &'a [u8], lookup: L) -> Self {
        Self {
            state: State::with_lookup(input, Quote::None, Dialect::Ansi, lookup),
        }
    }

    /// Resets this parser while retaining its input and lookup configuration.
    pub fn reset(&mut self) {
        self.state.reset();
    }

    /// Tokenizes and folds the input in the selected context.
    pub fn fold(&mut self, quote: Quote, dialect: Dialect) -> impl ExactSizeIterator<Item = SqlToken> + '_ {
        self.state.fold_in_context(quote, dialect);
        self.state.folded_tokens().iter().copied().map(SqlToken)
    }

    /// Parses the input in the selected context and returns its fingerprint,
    /// including when the fingerprint is not classified as SQL injection.
    pub fn fingerprint(&mut self, quote: Quote, dialect: Dialect) -> Fingerprint {
        self.state.fingerprint(quote, dialect)
    }

    /// Runs libperfusion's multi-context detector with this parser's lookup.
    /// The custom lookup is retained for every quote and dialect reparse.
    pub fn detect(&mut self) -> Option<(Fingerprint, Dialect)> {
        super::detect_state(&mut self.state)
    }

    /// Whether the most recently parsed fingerprint is a known SQL injection.
    #[must_use]
    pub fn check_fingerprint(&self) -> bool {
        self.state.check_fingerprint()
    }

    /// Tokens retained by the most recent folding pass.
    pub fn tokens(&self) -> impl ExactSizeIterator<Item = SqlToken> + '_ {
        self.state.folded_tokens().iter().copied().map(SqlToken)
    }

    /// Statistics from the most recent parse. A reset state has zero counts.
    #[must_use]
    pub fn stats(&self) -> SqlStatistics {
        self.state.stats()
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "The test requires a string token in a fixed SQL example."
    )]

    use super::*;

    #[test]
    fn token_accessors_expose_bounded_values_without_mutation() {
        let token = SqlTokenizer::new(b"SELECT 'value'", Quote::None, Dialect::Ansi)
            .find(|token| token.kind() == TokenType::String)
            .unwrap();
        assert_eq!(token.pos(), 8);
        assert_eq!(token.len(), 5);
        assert!(!token.is_empty());
        assert_eq!(token.value(), b"value");
        assert_eq!(token.c_value(), b"value");
        assert_eq!(token.string_open(), Some(b'\''));
        assert_eq!(token.string_close(), Some(b'\''));
    }

    #[test]
    fn parser_retains_a_fingerprint_and_folded_tokens_for_benign_input() {
        let mut state = SqlState::new(b"hello world");
        assert_eq!(state.fingerprint(Quote::None, Dialect::Ansi).as_str(), "nn");
        assert!(!state.check_fingerprint());
        assert_eq!(state.tokens().count(), 2);
        state.reset();
        assert_eq!(state.tokens().count(), 0);
        assert_eq!(state.fingerprint(Quote::None, Dialect::Ansi).as_str(), "nn");
    }

    #[test]
    fn parser_exposes_fold_and_tokenizer_statistics() {
        let mut state = SqlState::new(b"1; ; 2");
        state.fingerprint(Quote::None, Dialect::Ansi);
        assert_eq!(state.stats().tokens, 4);
        assert_eq!(state.stats().folds, 1);

        let mut tokenizer = SqlTokenizer::new(b"# value", Quote::None, Dialect::Ansi);
        assert_eq!(tokenizer.by_ref().count(), 2);
        assert_eq!(tokenizer.stats().tokens, 2);
        assert_eq!(tokenizer.stats().folds, 0);
        assert_eq!(tokenizer.stats().comment_hash, 1);
    }
}
