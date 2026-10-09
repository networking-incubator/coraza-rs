use core::cmp::Ordering;

use super::keywords::cstrcasecmp;

/// Size of upstream's `val` buffer, trailing NUL included.
pub(crate) const TOKEN_SIZE: usize = 32;

/// The kind of a token; its discriminant is the byte it contributes to a
/// fingerprint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum TokenType {
    /// A cleared token slot (upstream's `CHAR_NULL`). Folding works on a fixed
    /// array of slots, so "no token here" has to be representable.
    #[default]
    Null = 0,
    Keyword = b'k',
    Union = b'U',
    Group = b'B',
    Expression = b'E',
    SqlType = b't',
    Function = b'f',
    Bareword = b'n',
    Number = b'1',
    Variable = b'v',
    String = b's',
    Operator = b'o',
    LogicOperator = b'&',
    Comment = b'c',
    Collate = b'A',
    LeftParens = b'(',
    RightParens = b')',
    LeftBrace = b'{',
    RightBrace = b'}',
    Dot = b'.',
    Comma = b',',
    Colon = b':',
    Semicolon = b';',
    /// Start of a T-SQL statement.
    Tsql = b'T',
    Unknown = b'?',
    /// Unparsable input; the whole fingerprint collapses to `X`.
    Evil = b'X',
    /// Marks fingerprint entries in the keyword table; not really a token.
    Fingerprint = b'F',
    Backslash = b'\\',
}

impl TokenType {
    pub(crate) const fn as_byte(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Token {
    /// Offset of the token in the input.
    pub(crate) pos: usize,
    /// Length of the (possibly truncated) value.
    pub(crate) len: usize,
    /// Number of leading `@` on a variable.
    pub(crate) count: u8,
    pub(crate) ty: TokenType,
    /// Opening delimiter of a string, if it had one.
    pub(crate) str_open: Option<u8>,
    /// Closing delimiter of a string, if it had one.
    pub(crate) str_close: Option<u8>,
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
        self.ty == TokenType::Operator
            && self.len == 1
            && matches!(self.val[0], b'*' | b'/' | b'-' | b'+' | b'%')
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
