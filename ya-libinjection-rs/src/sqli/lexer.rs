//! The SQL tokenizer: a first-byte dispatch into one small scanner per
//! token shape, kept function-for-function with upstream's `parse_*`.

use super::keywords::lookup_word;
use super::token::{TOKEN_SIZE, Token, TokenType};
use crate::bytes::{byte_set, cspan, find_byte, find_pair, find_slice, span};

/// How the input is assumed to sit inside the surrounding SQL statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Quote {
    /// The input is taken as-is.
    None,
    /// The input continues a string opened with `'` before it.
    Single,
    /// The input continues a string opened with `"` before it.
    Double,
}

impl Quote {
    fn delimiter(self) -> Option<u8> {
        match self {
            Quote::None => None,
            Quote::Single => Some(b'\''),
            Quote::Double => Some(b'"'),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dialect {
    Ansi,
    Mysql,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Stats {
    /// `--x` comments: a comment in ANSI SQL, two unary operators in MySQL.
    pub(crate) comment_ddx: usize,
    /// `#`: an operator in ANSI SQL, an end-of-line comment in MySQL.
    pub(crate) comment_hash: usize,
    /// Tokens produced, before any folding.
    pub(crate) tokens: usize,
}

/// The scanner a token's first byte selects (upstream's `char_parse_map`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Parser {
    White,
    Operator1,
    Operator2,
    Other,
    /// A single byte that is its own token type.
    Char(TokenType),
    Hash,
    Dash,
    Slash,
    Backslash,
    String,
    Word,
    Var,
    Number,
    Tick,
    Ustring,
    Qstring,
    Nqstring,
    Xstring,
    Bstring,
    Estring,
    Bword,
    Money,
}

impl Parser {
    pub(crate) const fn for_byte(ch: u8) -> Self {
        match ch {
            0..=32 | 127 | 0xA0 => Parser::White,
            b'!' | b'&' | b'*' | b':' | b'<' | b'=' | b'>' | b'|' => Parser::Operator2,
            b'"' | b'\'' => Parser::String,
            b'#' => Parser::Hash,
            b'$' => Parser::Money,
            b'%' | b'+' | b'^' | b'~' => Parser::Operator1,
            b'(' => Parser::Char(TokenType::LeftParens),
            b')' => Parser::Char(TokenType::RightParens),
            b',' => Parser::Char(TokenType::Comma),
            b';' => Parser::Char(TokenType::Semicolon),
            b'{' => Parser::Char(TokenType::LeftBrace),
            b'}' => Parser::Char(TokenType::RightBrace),
            b'-' => Parser::Dash,
            b'.' | b'0'..=b'9' => Parser::Number,
            b'/' => Parser::Slash,
            b'?' | b']' => Parser::Other,
            b'@' => Parser::Var,
            b'B' | b'b' => Parser::Bstring,
            b'E' | b'e' => Parser::Estring,
            b'N' | b'n' => Parser::Nqstring,
            b'Q' | b'q' => Parser::Qstring,
            b'U' | b'u' => Parser::Ustring,
            b'X' | b'x' => Parser::Xstring,
            b'[' => Parser::Bword,
            b'\\' => Parser::Backslash,
            b'`' => Parser::Tick,
            b'A'..=b'Z' | b'a'..=b'z' | b'_' | 128..=255 => Parser::Word,
        }
    }
}

static WHITE: [bool; 256] = byte_set(b" \t\n\x0b\x0c\r\xa0");
static WORD_END: [bool; 256] = byte_set(b" []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r\"\xa0");
static VARIABLE_END: [bool; 256] = byte_set(b" <>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r'`\"");
static MONEY_DIGITS: [bool; 256] = byte_set(b"0123456789.,");
static LETTERS: [bool; 256] = byte_set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
static HEX_DIGITS: [bool; 256] = byte_set(b"0123456789ABCDEFabcdef");
static BINARY_DIGITS: [bool; 256] = byte_set(b"01");

fn is_white(ch: u8) -> bool {
    WHITE[usize::from(ch)]
}

/// Whether the byte after `preceding` is escaped: an odd run of backslashes
/// ends `preceding`.
fn is_backslash_escaped(preceding: &[u8]) -> bool {
    preceding.iter().rev().take_while(|&&b| b == b'\\').count() % 2 == 1
}

/// Whether the delimiter at `at` is doubled (`''`), which escapes it.
fn is_double_delim_escaped(s: &[u8], at: usize) -> bool {
    s.get(at + 1) == Some(&s[at])
}

/// Scans a `delim`-quoted string whose body starts `offset` bytes after
/// `pos`. With `offset == 0` the opening quote is the simulated one of
/// [`Quote`].
fn parse_string_core(s: &[u8], pos: usize, st: &mut Token, delim: u8, offset: usize) -> usize {
    let start = pos + offset;
    st.str_open = (offset > 0).then_some(delim);

    let mut qpos = find_byte(s, start, delim);
    loop {
        match qpos {
            None => {
                // No closing quote: the string runs to the end of input.
                st.assign(TokenType::String, start, &s[start..]);
                st.str_close = None;
                return s.len();
            }
            Some(q) if is_backslash_escaped(&s[start..q]) => qpos = find_byte(s, q + 1, delim),
            Some(q) if is_double_delim_escaped(s, q) => qpos = find_byte(s, q + 2, delim),
            Some(q) => {
                st.assign(TokenType::String, start, &s[start..q]);
                st.str_close = Some(delim);
                return q + 1;
            }
        }
    }
}

pub(crate) struct Lexer<'a> {
    s: &'a [u8],
    pos: usize,
    quote: Quote,
    dialect: Dialect,
    pub(crate) stats: Stats,
}

impl<'a> Lexer<'a> {
    pub(crate) fn new(s: &'a [u8], quote: Quote, dialect: Dialect) -> Self {
        Self {
            s,
            pos: 0,
            quote,
            dialect,
            stats: Stats::default(),
        }
    }

    fn parse_operator1(&self, pos: usize, cur: &mut Token) -> usize {
        cur.assign_char(TokenType::Operator, pos, self.s[pos]);
        pos + 1
    }

    fn parse_other(&self, pos: usize, cur: &mut Token) -> usize {
        cur.assign_char(TokenType::Unknown, pos, self.s[pos]);
        pos + 1
    }

    fn parse_char(&self, pos: usize, cur: &mut Token, ty: TokenType) -> usize {
        cur.assign_char(ty, pos, self.s[pos]);
        pos + 1
    }

    fn parse_eol_comment(&self, pos: usize, cur: &mut Token) -> usize {
        let s = self.s;
        match find_byte(s, pos, b'\n') {
            None => {
                cur.assign(TokenType::Comment, pos, &s[pos..]);
                s.len()
            }
            Some(end) => {
                cur.assign(TokenType::Comment, pos, &s[pos..end]);
                end + 1
            }
        }
    }

    /// In ANSI mode `#` is an operator; in MySQL mode it starts an
    /// end-of-line comment, like `--`.
    fn parse_hash(&mut self, pos: usize, cur: &mut Token) -> usize {
        self.stats.comment_hash += 1;
        if self.dialect == Dialect::Mysql {
            self.stats.comment_hash += 1;
            self.parse_eol_comment(pos, cur)
        } else {
            cur.assign_char(TokenType::Operator, pos, b'#');
            pos + 1
        }
    }

    fn parse_dash(&mut self, pos: usize, cur: &mut Token) -> usize {
        let s = self.s;

        // Five cases:
        // 1) --[white]    always a SQL comment
        // 2) --[EOF]      a comment
        // 3) --[notwhite] in MySQL, not a comment but two unary operators
        // 4) --[notwhite] a comment for everyone else
        // 5) -[not dash]  '-' is a unary operator
        let double_dash = s.get(pos + 1) == Some(&b'-');
        if double_dash && s.get(pos + 2).is_none_or(|&next| is_white(next)) {
            self.parse_eol_comment(pos, cur)
        } else if double_dash && self.dialect == Dialect::Ansi {
            self.stats.comment_ddx += 1;
            self.parse_eol_comment(pos, cur)
        } else {
            cur.assign_char(TokenType::Operator, pos, b'-');
            pos + 1
        }
    }

    fn parse_slash(&self, pos: usize, cur: &mut Token) -> usize {
        let s = self.s;
        let slen = s.len();
        if pos + 1 == slen || s[pos + 1] != b'*' {
            return self.parse_operator1(pos, cur);
        }

        // Skip over the initial "/*".
        let body = pos + 2;
        let close = find_pair(&s[body..], b'*', b'/').map(|i| body + i);
        let clen = match close {
            // Runs to the end of input.
            None => slen - pos,
            Some(close) => close + 2 - pos,
        };

        // PostgreSQL allows nested comments, which cannot be tokenized this
        // way, and MySQL's "/*!" conditional comments are an automatic ban.
        // The nested-comment scan covers the '*' of the closing "*/" too.
        let nested = close.is_some_and(|close| find_pair(&s[body..=close], b'/', b'*').is_some());
        let mysql_conditional = s.get(body) == Some(&b'!');
        let ty = if nested || mysql_conditional {
            TokenType::Evil
        } else {
            TokenType::Comment
        };

        cur.assign(ty, pos, &s[pos..pos + clen]);
        pos + clen
    }

    fn parse_backslash(&self, pos: usize, cur: &mut Token) -> usize {
        let s = self.s;
        // MySQL's alias for NULL, "\N" (capital N only).
        if s.get(pos + 1) == Some(&b'N') {
            cur.assign(TokenType::Number, pos, &s[pos..pos + 2]);
            pos + 2
        } else {
            cur.assign_char(TokenType::Backslash, pos, s[pos]);
            pos + 1
        }
    }

    fn parse_operator2(&self, pos: usize, cur: &mut Token) -> usize {
        let s = self.s;
        let slen = s.len();
        if pos + 1 >= slen {
            return self.parse_operator1(pos, cur);
        }

        if s[pos..].starts_with(b"<=>") {
            cur.assign(TokenType::Operator, pos, &s[pos..pos + 3]);
            return pos + 3;
        }

        let pair = &s[pos..pos + 2];
        if let Some(ty) = lookup_word(pair) {
            cur.assign(ty, pos, pair);
            return pos + 2;
        }

        if s[pos] == b':' {
            // ':' alone is not an operator.
            cur.assign_char(TokenType::Colon, pos, b':');
            pos + 1
        } else {
            self.parse_operator1(pos, cur)
        }
    }

    /// A string opened by the `'` or `"` at `pos`.
    fn parse_string(&self, pos: usize, cur: &mut Token) -> usize {
        parse_string_core(self.s, pos, cur, self.s[pos], 1)
    }

    /// PostgreSQL's `E'escaped'` and MySQL's `N'national'` strings.
    fn parse_estring(&self, pos: usize, cur: &mut Token) -> usize {
        let s = self.s;
        if pos + 2 >= s.len() || s[pos + 1] != b'\'' {
            return self.parse_word(pos, cur);
        }
        parse_string_core(s, pos, cur, b'\'', 2)
    }

    /// `U&'unicode'` strings.
    fn parse_ustring(&self, pos: usize, cur: &mut Token) -> usize {
        let s = self.s;
        if pos + 2 < s.len() && s[pos + 1] == b'&' && s[pos + 2] == b'\'' {
            let end = self.parse_string(pos + 2, cur);
            cur.str_open = Some(b'u');
            if cur.str_close == Some(b'\'') {
                cur.str_close = Some(b'u');
            }
            end
        } else {
            self.parse_word(pos, cur)
        }
    }

    /// Oracle's `q'[...]'` strings, `offset` bytes after `start`.
    fn parse_qstring_core(&self, start: usize, offset: usize, cur: &mut Token) -> usize {
        let s = self.s;
        let slen = s.len();
        let pos = start + offset;

        if pos >= slen
            || (s[pos] != b'q' && s[pos] != b'Q')
            || pos + 2 >= slen
            || s[pos + 1] != b'\''
        {
            return self.parse_word(start, cur);
        }

        let open = s[pos + 2];
        // Upstream compares a `char`, signed on its reference platform, so
        // bytes above 127 are rejected along with the control characters.
        if open.cast_signed() < 33 {
            return self.parse_word(start, cur);
        }
        let close = match open {
            b'(' => b')',
            b'[' => b']',
            b'{' => b'}',
            b'<' => b'>',
            other => other,
        };

        let body = pos + 3;
        cur.str_open = Some(b'q');
        match find_pair(&s[body..], close, b'\'') {
            None => {
                cur.assign(TokenType::String, body, &s[body..]);
                cur.str_close = None;
                slen
            }
            Some(end) => {
                cur.assign(TokenType::String, body, &s[body..body + end]);
                cur.str_close = Some(b'q');
                body + end + 2
            }
        }
    }

    fn parse_qstring(&self, pos: usize, cur: &mut Token) -> usize {
        self.parse_qstring_core(pos, 0, cur)
    }

    /// MySQL's `N'string'` or Oracle's `nq'[...]'`.
    fn parse_nqstring(&self, pos: usize, cur: &mut Token) -> usize {
        let s = self.s;
        if pos + 2 < s.len() && s[pos + 1] == b'\'' {
            return self.parse_estring(pos, cur);
        }
        self.parse_qstring_core(pos, 1, cur)
    }

    /// `b'0101'` and `x'ff'` literals: a number if every byte up to the
    /// closing quote is in `digits`, a plain word otherwise.
    fn parse_radix_string(&self, pos: usize, cur: &mut Token, digits: &[bool; 256]) -> usize {
        let s = self.s;
        let slen = s.len();
        if pos + 2 >= slen || s[pos + 1] != b'\'' {
            return self.parse_word(pos, cur);
        }

        let wlen = span(&s[pos + 2..], digits);
        if pos + 2 + wlen >= slen || s[pos + 2 + wlen] != b'\'' {
            return self.parse_word(pos, cur);
        }
        cur.assign(TokenType::Number, pos, &s[pos..pos + wlen + 3]);
        pos + wlen + 3
    }

    /// SQL Server's `[bracketed words]`.
    fn parse_bword(&self, pos: usize, cur: &mut Token) -> usize {
        let s = self.s;
        match find_byte(s, pos, b']') {
            None => {
                cur.assign(TokenType::Bareword, pos, &s[pos..]);
                s.len()
            }
            Some(end) => {
                cur.assign(TokenType::Bareword, pos, &s[pos..=end]);
                end + 1
            }
        }
    }

    fn parse_word(&self, pos: usize, cur: &mut Token) -> usize {
        let s = self.s;
        let wlen = cspan(&s[pos..], &WORD_END);
        cur.assign(TokenType::Bareword, pos, &s[pos..pos + wlen]);

        // Look inside the word for '.' and '`': if what precedes one is a
        // keyword ("SELECT.1", "SELECT`column`"), the token ends there.
        for i in 0..cur.len {
            let delim = cur.byte(i);
            if delim == b'.' || delim == b'`' {
                match lookup_word(&cur.value()[..i]) {
                    Some(ty) if ty != TokenType::Bareword => {
                        *cur = Token::default();
                        cur.assign(ty, pos, &s[pos..pos + i]);
                        return pos + i;
                    }
                    _ => {}
                }
            }
        }

        // Otherwise look up the whole word, '.' included. A word too long
        // for the token buffer was truncated and is left a bareword.
        if wlen < TOKEN_SIZE {
            cur.ty = lookup_word(cur.value()).unwrap_or(TokenType::Bareword);
        }
        pos + wlen
    }

    /// MySQL backticks: a cross between a string and a bareword.
    fn parse_tick(&self, pos: usize, cur: &mut Token) -> usize {
        let end = parse_string_core(self.s, pos, cur, b'`', 1);
        cur.ty = if lookup_word(cur.value()) == Some(TokenType::Function) {
            TokenType::Function
        } else {
            TokenType::Bareword
        };
        end
    }

    fn parse_var(&self, start: usize, cur: &mut Token) -> usize {
        let s = self.s;
        let mut pos = start + 1;

        // Move past an optional second '@'.
        if s.get(pos) == Some(&b'@') {
            pos += 1;
            cur.count = 2;
        } else {
            cur.count = 1;
        }

        // MySQL allows @@`version` and @'quoted' names.
        match s.get(pos) {
            Some(b'`') => {
                let end = self.parse_tick(pos, cur);
                cur.ty = TokenType::Variable;
                return end;
            }
            Some(b'\'' | b'"') => {
                let end = self.parse_string(pos, cur);
                cur.ty = TokenType::Variable;
                return end;
            }
            _ => {}
        }

        let xlen = cspan(&s[pos..], &VARIABLE_END);
        cur.assign(TokenType::Variable, pos, &s[pos..pos + xlen]);
        pos + xlen
    }

    fn parse_money(&self, pos: usize, cur: &mut Token) -> usize {
        let s = self.s;
        let slen = s.len();

        if pos + 1 == slen {
            cur.assign_char(TokenType::Bareword, pos, b'$');
            return slen;
        }

        // $1,000.00 or $1.000,00 are fine; so is $....,,,111.
        let xlen = span(&s[pos + 1..], &MONEY_DIGITS);
        if xlen == 1 && s[pos + 1] == b'.' {
            // "$." is parsed as a word.
            return self.parse_word(pos, cur);
        }
        if xlen > 0 {
            cur.assign(TokenType::Number, pos, &s[pos..pos + 1 + xlen]);
            return pos + 1 + xlen;
        }

        if s[pos + 1] == b'$' {
            // "$$": a string that runs to the next "$$".
            let body = pos + 2;
            cur.str_open = Some(b'$');
            return match find_pair(&s[body..], b'$', b'$') {
                None => {
                    cur.assign(TokenType::String, body, &s[body..]);
                    cur.str_close = None;
                    slen
                }
                Some(end) => {
                    cur.assign(TokenType::String, body, &s[body..body + end]);
                    cur.str_close = Some(b'$');
                    body + end + 2
                }
            };
        }

        // Neither a number nor "$$": maybe a PostgreSQL "$tag$ ... $tag$".
        let xlen = span(&s[pos + 1..], &LETTERS);
        if xlen == 0 || pos + xlen + 1 == slen || s[pos + xlen + 1] != b'$' {
            // "$" followed by something else: emit it alone and move on.
            cur.assign_char(TokenType::Bareword, pos, b'$');
            return pos + 1;
        }

        let body = pos + xlen + 2;
        let tag = &s[pos..body];
        cur.str_open = Some(b'$');
        match find_slice(&s[body..], tag) {
            None => {
                cur.assign(TokenType::String, body, &s[body..]);
                cur.str_close = None;
                slen
            }
            Some(end) => {
                cur.assign(TokenType::String, body, &s[body..body + end]);
                cur.str_close = Some(b'$');
                body + end + tag.len()
            }
        }
    }

    fn parse_number(&self, start: usize, cur: &mut Token) -> usize {
        let s = self.s;
        let slen = s.len();
        let mut pos = start;

        if s[pos] == b'0' && pos + 1 < slen {
            let digits = match s[pos + 1] {
                b'X' | b'x' => Some(&HEX_DIGITS),
                b'B' | b'b' => Some(&BINARY_DIGITS),
                _ => None,
            };
            if let Some(digits) = digits {
                let xlen = span(&s[pos + 2..], digits);
                let ty = if xlen == 0 {
                    TokenType::Bareword
                } else {
                    TokenType::Number
                };
                cur.assign(ty, pos, &s[pos..pos + 2 + xlen]);
                return pos + 2 + xlen;
            }
        }

        while pos < slen && s[pos].is_ascii_digit() {
            pos += 1;
        }

        if pos < slen && s[pos] == b'.' {
            pos += 1;
            while pos < slen && s[pos].is_ascii_digit() {
                pos += 1;
            }
            if pos - start == 1 {
                // Only the '.' was read.
                cur.assign_char(TokenType::Dot, start, b'.');
                return pos;
            }
        }

        let mut have_e = false;
        let mut have_exp = false;
        if pos < slen && (s[pos] == b'E' || s[pos] == b'e') {
            have_e = true;
            pos += 1;
            if pos < slen && (s[pos] == b'+' || s[pos] == b'-') {
                pos += 1;
            }
            while pos < slen && s[pos].is_ascii_digit() {
                have_exp = true;
                pos += 1;
            }
        }

        // Oracle's float and double suffixes. "1.2f" at the end of input,
        // before whitespace or ';' keeps the suffix; "1fUNION" is read as
        // "1f UNION"; anything else ("123FROM") leaves it for the next token.
        if pos < slen && matches!(s[pos], b'd' | b'D' | b'f' | b'F') {
            let keeps_suffix = match s.get(pos + 1) {
                None => true,
                Some(&next) => is_white(next) || matches!(next, b';' | b'u' | b'U'),
            };
            if keeps_suffix {
                pos += 1;
            }
        }

        // "1.e", "10.10E" and ".E" have an exponent marker but no exponent.
        // MySQL ignores them while parsing ("1.e(1)" is "(1)"), so they are
        // dropped here too rather than turned into a number.
        if !have_e || have_exp {
            cur.assign(TokenType::Number, start, &s[start..pos]);
        }
        pos
    }
}

impl Iterator for Lexer<'_> {
    type Item = Token;

    fn next(&mut self) -> Option<Token> {
        let s = self.s;
        let mut cur = Token::default();

        // At the start of input in a quoted context, pretend the input
        // opens with that quote.
        if self.pos == 0
            && !s.is_empty()
            && let Some(delim) = self.quote.delimiter()
        {
            self.pos = parse_string_core(s, 0, &mut cur, delim, 0);
            self.stats.tokens += 1;
            return Some(cur);
        }

        while self.pos < s.len() {
            let pos = self.pos;
            self.pos = match Parser::for_byte(s[pos]) {
                Parser::White => pos + 1,
                Parser::Operator1 => self.parse_operator1(pos, &mut cur),
                Parser::Operator2 => self.parse_operator2(pos, &mut cur),
                Parser::Other => self.parse_other(pos, &mut cur),
                Parser::Char(ty) => self.parse_char(pos, &mut cur, ty),
                Parser::Hash => self.parse_hash(pos, &mut cur),
                Parser::Dash => self.parse_dash(pos, &mut cur),
                Parser::Slash => self.parse_slash(pos, &mut cur),
                Parser::Backslash => self.parse_backslash(pos, &mut cur),
                Parser::String => self.parse_string(pos, &mut cur),
                Parser::Word => self.parse_word(pos, &mut cur),
                Parser::Var => self.parse_var(pos, &mut cur),
                Parser::Number => self.parse_number(pos, &mut cur),
                Parser::Tick => self.parse_tick(pos, &mut cur),
                Parser::Ustring => self.parse_ustring(pos, &mut cur),
                Parser::Qstring => self.parse_qstring(pos, &mut cur),
                Parser::Nqstring => self.parse_nqstring(pos, &mut cur),
                Parser::Xstring => self.parse_radix_string(pos, &mut cur, &HEX_DIGITS),
                Parser::Bstring => self.parse_radix_string(pos, &mut cur, &BINARY_DIGITS),
                Parser::Estring => self.parse_estring(pos, &mut cur),
                Parser::Bword => self.parse_bword(pos, &mut cur),
                Parser::Money => self.parse_money(pos, &mut cur),
            };

            if cur.ty != TokenType::Null {
                self.stats.tokens += 1;
                return Some(cur);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_matches_upstream() {
        let source = crate::corpus::upstream_source("src/libinjection_sqli_data.h");
        let body = crate::corpus::c_array_body(&source, "char_parse_map[] = {");
        // Each entry reads `&parse_white,`, in byte order.
        let upstream: Vec<&str> = body
            .lines()
            .filter_map(|line| line.trim().strip_prefix("&parse_")?.strip_suffix(','))
            .collect();
        assert_eq!(upstream.len(), 256);

        for (byte, name) in (0..=u8::MAX).zip(upstream) {
            let parser = Parser::for_byte(byte);
            if let Parser::Char(ty) = parser {
                assert_eq!((name, ty.as_byte()), ("char", byte));
            } else {
                assert_eq!(format!("{parser:?}").to_lowercase(), name, "byte {byte}");
            }
        }
    }
}
