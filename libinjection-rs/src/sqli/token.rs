// Copyright (c) 2012-2016, Nick Galbreath
// Copyright (c) 2017-2024, libinjection Contributors
// Copyright 2026 Coraza Kubernetes Operator contributors.
//
// SPDX-License-Identifier: BSD-3-Clause
// See the crate's LICENSE for the complete terms.
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "Private token fields and helpers are covered by the public SqlToken API."
    )
)]
use core::cmp::Ordering;

use super::keywords::cstrcasecmp;

/// Size of upstream's `val` buffer, trailing NUL included.
pub(crate) const TOKEN_SIZE: usize = 32;

/// The kind of a token; its discriminant is the byte it contributes to a
/// fingerprint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum TokenType {
    /// A cleared token slot (upstream's `CHAR_NULL`). Folding works on a fixed
    /// array of slots, so "no token here" has to be representable.
    #[default]
    Null = 0,
    /// A recognized SQL keyword.
    Keyword = b'k',
    /// A `UNION` construct.
    Union = b'U',
    /// A grouped expression.
    Group = b'B',
    /// An expression token.
    Expression = b'E',
    /// A SQL type name.
    SqlType = b't',
    /// A function name.
    Function = b'f',
    /// An unclassified word.
    Bareword = b'n',
    /// A numeric literal.
    Number = b'1',
    /// A variable.
    Variable = b'v',
    /// A string literal.
    String = b's',
    /// An operator.
    Operator = b'o',
    /// A logical operator.
    LogicOperator = b'&',
    /// A SQL comment.
    Comment = b'c',
    /// A collation expression.
    Collate = b'A',
    /// An opening parenthesis.
    LeftParens = b'(',
    /// A closing parenthesis.
    RightParens = b')',
    /// An opening brace.
    LeftBrace = b'{',
    /// A closing brace.
    RightBrace = b'}',
    /// A dot.
    Dot = b'.',
    /// A comma.
    Comma = b',',
    /// A colon.
    Colon = b':',
    /// A semicolon.
    Semicolon = b';',
    /// Start of a T-SQL statement.
    Tsql = b'T',
    /// An otherwise unclassified token.
    Unknown = b'?',
    /// Unparsable input; the whole fingerprint collapses to `X`.
    Evil = b'X',
    /// Marks fingerprint entries in the keyword table; not really a token.
    Fingerprint = b'F',
    /// A backslash token.
    Backslash = b'\\',
}

impl TokenType {
    /// Returns the byte used for this type in a fingerprint.
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Token {
    /// Offset of the token in the input.
    pub pos: usize,
    /// Length of the (possibly truncated) value.
    pub len: usize,
    /// Number of leading `@` on a variable.
    pub count: u8,
    pub ty: TokenType,
    /// Opening delimiter of a string, if it had one.
    pub str_open: Option<u8>,
    /// Closing delimiter of a string, if it had one.
    pub str_close: Option<u8>,
    val: [u8; TOKEN_SIZE],
}

impl Token {
    /// Upstream's `st_assign`: values longer than the buffer are truncated,
    /// and `len` with them.
    pub(crate) fn assign(&mut self, ty: TokenType, pos: usize, value: &[u8]) {
        let last = value.len().min(TOKEN_SIZE - 1);
        self.ty = ty;
        self.pos = pos;
        self.len = last;
        self.val = [0; TOKEN_SIZE];
        self.val[..last].copy_from_slice(&value[..last]);
    }

    /// Upstream's `st_assign_char`.
    pub(crate) fn assign_char(&mut self, ty: TokenType, pos: usize, value: u8) {
        self.assign(ty, pos, &[value]);
    }

    pub(crate) fn value(&self) -> &[u8] {
        &self.val[..self.len]
    }

    /// The value as C string functions see it: cut at the first NUL.
    pub(crate) fn c_str(&self) -> &[u8] {
        let value = self.value();
        let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
        &value[..end]
    }

    /// `val[index]`, which reads as NUL past the end of the value.
    pub(crate) fn byte(&self, index: usize) -> u8 {
        self.val[index]
    }

    /// Case-insensitive comparison against an upper-case keyword.
    pub(crate) fn is_word(&self, upper: &[u8]) -> bool {
        cstrcasecmp(upper, self.value()) == Ordering::Equal
    }

    pub(crate) fn is_arithmetic_op(&self) -> bool {
        self.ty == TokenType::Operator && self.len == 1 && matches!(self.val[0], b'*' | b'/' | b'-' | b'+' | b'%')
    }

    pub(crate) fn is_unary_op(&self) -> bool {
        if self.ty != TokenType::Operator {
            return false;
        }
        match self.value() {
            [b'+' | b'-' | b'!' | b'~'] | b"!!" => true,
            [_, _, _] => self.is_word(b"NOT"),
            _ => false,
        }
    }

    /// Collapses the token to the lone `X` of an unparsable input. As
    /// upstream, the length is left alone.
    pub(crate) fn mark_evil(&mut self) {
        self.val = [0; TOKEN_SIZE];
        self.val[0] = TokenType::Evil.as_byte();
        self.ty = TokenType::Evil;
    }
}
