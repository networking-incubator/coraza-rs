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

//! Per-byte token parsers and dispatch — ported from `sqli_parse.go` + `sqli_data.go`.

use super::{
    consts::{
        BYTE_NULL, BYTE_SINGLE, BYTE_TICK, FLAG_SQL_ANSI, FLAG_SQL_MYSQL, LOOKUP_OPERATOR, LOOKUP_WORD, TOKEN_SIZE,
        TT_BACKSLASH, TT_BAREWORD, TT_COLON, TT_COMMENT, TT_DOT, TT_EVIL, TT_FUNCTION, TT_NONE, TT_NUMBER, TT_OPERATOR,
        TT_STRING, TT_UNKNOWN, TT_VARIABLE,
    },
    helpers::{VAR_ACCEPT_TABLE, WORD_ACCEPT_TABLE, is_byte_white, is_mysql_comment, str_len_cspn, str_len_spn},
    state::SqliState,
    token::SqliToken,
};

/// Go `parseByteFunctions` — dispatch `input[pos]` to the right parser.
///
/// Returns the new position.
pub(crate) fn dispatch(s: &mut SqliState<'_>) -> usize {
    let Some(&ch) = s.input.get(s.pos) else {
        return s.length;
    };
    match ch {
        0..=32 | 127 | 160 => parse_white(s),
        b'!' | b'&' | b'*' | b':' | b'<' | b'=' | b'>' | b'|' => parse_operator2(s),
        b'"' | b'\'' => parse_string(s),
        b'#' => parse_hash(s),
        b'$' => parse_money(s),
        b'%' | b'+' | b'^' | b'~' => parse_operator1(s),
        b'(' | b')' | b',' | b';' | b'{' | b'}' => parse_byte(s),
        b'-' => parse_dash(s),
        b'.' | b'0'..=b'9' => parse_number(s),
        b'/' => parse_slash(s),
        b'?' | b']' => parse_other(s),
        b'@' => parse_var(s),
        b'B' | b'b' => parse_bstring(s),
        b'E' | b'e' => parse_estring(s),
        b'N' | b'n' => parse_nqstring(s),
        b'Q' | b'q' => parse_qstring(s),
        b'U' | b'u' => parse_ustring(s),
        b'X' | b'x' => parse_xstring(s),
        b'[' => parse_bword(s),
        b'\\' => parse_backslash(s),
        b'`' => parse_tick(s),
        _ => parse_word(s),
    }
}

// -- Helpers to work around borrow-checker: get input slices directly --

/// `input[from..]` (never panics).
fn inp<'a>(s: &SqliState<'a>, from: usize) -> &'a [u8] {
    s.input.get(from..).unwrap_or(b"")
}

/// `input[from..to]` (never panics).
fn inp2<'a>(s: &SqliState<'a>, from: usize, to: usize) -> &'a [u8] {
    s.input.get(from..to).unwrap_or(b"")
}

// -- Individual parsers (match Go line-for-line) --

/// Go `parseWhite`.
fn parse_white(s: &SqliState<'_>) -> usize {
    s.pos + 1
}

/// Go `parseOperator1`.
fn parse_operator1(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    let v = inp(s, pos);
    s.current_mut().assign(TT_OPERATOR, pos, 1, v);
    pos + 1
}

/// Go `parseByte`.
fn parse_byte(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    let ch = s.input.get(pos).copied().unwrap_or(0);
    let v = inp(s, pos);
    s.current_mut().assign(ch, pos, 1, v);
    pos + 1
}

/// Go `parseOther`.
fn parse_other(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    let v = inp(s, pos);
    s.current_mut().assign(TT_UNKNOWN, pos, 1, v);
    pos + 1
}

/// Go `parseHash`.
fn parse_hash(s: &mut SqliState<'_>) -> usize {
    s.stats_comment_hash += 1;
    if (s.flags & FLAG_SQL_MYSQL) != 0 {
        s.stats_comment_hash += 1;
        return parse_eol_comment(s);
    }
    let pos = s.pos;
    s.current_mut().assign(TT_OPERATOR, pos, 1, b"#");
    pos + 1
}

/// Go `parseDash`.
fn parse_dash(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    let input = s.input;
    let flags = s.flags;

    if input.get(pos + 1).copied() == Some(b'-') && input.get(pos + 2).is_some_and(|&b| is_byte_white(b)) {
        return parse_eol_comment(s);
    }
    if pos + 2 == s.length && input.get(pos + 1).copied() == Some(b'-') {
        return parse_eol_comment(s);
    }
    if input.get(pos + 1).copied() == Some(b'-') && (flags & FLAG_SQL_ANSI) != 0 {
        s.stats_comment_ddx += 1;
        return parse_eol_comment(s);
    }
    s.current_mut().assign(TT_OPERATOR, pos, 1, b"-");
    pos + 1
}

/// Go `parseSlash`.
fn parse_slash(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    let length = s.length;
    let input = s.input;

    if pos + 1 == length || input.get(pos + 1).copied() != Some(b'*') {
        return parse_operator1(s);
    }

    let after_open = input.get(pos + 2..).unwrap_or(b"");
    let close_idx = find_subslice(after_open, b"*/");
    let block_len = match close_idx {
        None => length - pos,
        Some(i) => 2 + i + 2,
    };

    let mut ctype = TT_COMMENT;

    if let Some(i) = close_idx {
        let inner = input.get(pos + 2..pos + 2 + i + 1).unwrap_or(b"");
        if find_subslice(inner, b"/*").is_some() || is_mysql_comment(input, pos) {
            ctype = TT_EVIL;
        }
    } else if is_mysql_comment(input, pos) {
        ctype = TT_EVIL;
    }

    let v = inp(s, pos);
    s.current_mut().assign(ctype, pos, block_len, v);
    pos + block_len
}

/// Go `parseBackslash`.
fn parse_backslash(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    if s.input.get(pos + 1).copied() == Some(b'N') {
        let v = inp(s, pos);
        s.current_mut().assign(TT_NUMBER, pos, 2, v);
        return pos + 2;
    }
    let v = inp(s, pos);
    s.current_mut().assign(TT_BACKSLASH, pos, 1, v);
    pos + 1
}

/// Go `parseOperator2`.
fn parse_operator2(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    if pos + 1 >= s.length {
        return parse_operator1(s);
    }

    let input = s.input;
    if input.get(pos).copied() == Some(b'<')
        && input.get(pos + 1).copied() == Some(b'=')
        && input.get(pos + 2).copied() == Some(b'>')
    {
        let v = inp(s, pos);
        s.current_mut().assign(TT_OPERATOR, pos, 3, v);
        return pos + 3;
    }

    let two = inp2(s, pos, pos + 2);
    let ch = super::data::lookup_word(LOOKUP_OPERATOR, two);
    if ch != BYTE_NULL {
        let v = inp(s, pos);
        s.current_mut().assign(ch, pos, 2, v);
        return pos + 2;
    }

    if input.get(pos).copied() == Some(b':') {
        let v = inp(s, pos);
        s.current_mut().assign(TT_COLON, pos, 1, v);
        return pos + 1;
    }
    parse_operator1(s)
}

/// Go `parseString`.
fn parse_string(s: &mut SqliState<'_>) -> usize {
    let Some(&delim) = s.input.get(s.pos) else {
        return s.length;
    };
    let input = s.input;
    let length = s.length;
    let pos = s.pos;
    s.current_mut().parse_string_core(input, length, pos, 1, delim)
}

/// Go `parseEOLComment`.
fn parse_eol_comment(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    let length = s.length;
    let haystack = s.input.get(pos..).unwrap_or(b"");
    let v = inp(s, pos);
    let idx = memchr::memchr(b'\n', haystack);
    match idx {
        None => {
            s.current_mut().assign(TT_COMMENT, pos, length - pos, v);
            length
        },
        Some(i) => {
            s.current_mut().assign(TT_COMMENT, pos, i, v);
            pos + i + 1
        },
    }
}

/// Go `parseWord`.
fn parse_word(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    let remaining = inp(s, pos);
    let length = str_len_cspn(remaining, s.length - pos, &WORD_ACCEPT_TABLE);
    let v = inp(s, pos);
    s.current_mut().assign(TT_BAREWORD, pos, length, v);

    let val_len = s.current().len;
    let val_bytes: [u8; 32] = {
        let mut buf = [0_u8; 32];
        let copy_len = val_len.min(32);
        let src = s.current().val_slice();
        if let (Some(dst), Some(s_slice)) = (buf.get_mut(..copy_len), src.get(..copy_len)) {
            dst.copy_from_slice(s_slice);
        }
        buf
    };

    for i in 0..val_len {
        let delimiter = val_bytes.get(i).copied().unwrap_or(0);
        if delimiter == b'.' || delimiter == b'`' {
            let ch = super::data::lookup_word(LOOKUP_WORD, val_bytes.get(..i).unwrap_or(&[]));
            if ch != TT_NONE && ch != TT_BAREWORD {
                *s.current_mut() = SqliToken::default();
                let v2 = inp(s, pos);
                s.current_mut().assign(ch, pos, i, v2);
                return pos + i;
            }
        }
    }

    if length < TOKEN_SIZE {
        let word = inp2(s, pos, pos + length);
        let mut ch = super::data::lookup_word(LOOKUP_WORD, word);
        if ch == BYTE_NULL {
            ch = TT_BAREWORD;
        }
        s.current_mut().category = ch;
    }
    pos + length
}

/// Go `parseVar`.
fn parse_var(s: &mut SqliState<'_>) -> usize {
    let mut pos = s.pos + 1;

    if s.input.get(pos).copied() == Some(b'@') {
        pos += 1;
        s.current_mut().count = 2;
    } else {
        s.current_mut().count = 1;
    }

    match s.input.get(pos).copied() {
        Some(b'`') => {
            s.pos = pos;
            pos = parse_tick(s);
            s.current_mut().category = TT_VARIABLE;
            return pos;
        },
        Some(b) if b == BYTE_SINGLE || b == super::consts::BYTE_DOUBLE => {
            s.pos = pos;
            pos = parse_string(s);
            s.current_mut().category = TT_VARIABLE;
            return pos;
        },
        _ => {},
    }

    let remaining = inp(s, pos);
    let length = str_len_cspn(remaining, s.length - pos, &VAR_ACCEPT_TABLE);
    let v = inp(s, pos);
    if length == 0 {
        s.current_mut().assign(TT_VARIABLE, pos, 0, v);
        return pos;
    }
    s.current_mut().assign(TT_VARIABLE, pos, length, v);
    pos + length
}

/// Go `parseNumber`.
fn parse_number(s: &mut SqliState<'_>) -> usize {
    let input = s.input;
    let length = s.length;
    let start = s.pos;
    let mut have_e = false;
    let mut have_exp = false;

    if input.get(start).copied() == Some(b'0') && start + 1 < length {
        let next = input.get(start + 1).copied().unwrap_or(0);
        let digits: &[u8] = if next == b'X' || next == b'x' {
            b"0123456789ABCDEFabcdef"
        } else if next == b'B' || next == b'b' {
            b"01"
        } else {
            b""
        };

        if !digits.is_empty() {
            let dlen = str_len_spn(inp(s, start + 2), length - start - 2, digits);
            if dlen == 0 {
                let v = inp(s, start);
                s.current_mut().assign(TT_BAREWORD, start, 2, v);
                return start + 2;
            }
            let v = inp(s, start);
            s.current_mut().assign(TT_NUMBER, start, 2 + dlen, v);
            return start + 2 + dlen;
        }
    }

    let mut pos = start;
    while input.get(pos).is_some_and(|&b| b.wrapping_sub(b'0') <= 9) {
        pos += 1;
    }

    if input.get(pos).copied() == Some(b'.') {
        pos += 1;
        while input.get(pos).is_some_and(|&b| b.wrapping_sub(b'0') <= 9) {
            pos += 1;
        }
        if pos - start == 1 && input.get(pos).is_none_or(|&b| !matches!(b, b'E' | b'e')) {
            s.current_mut().assign(TT_DOT, start, 1, b".");
            return pos;
        }
    }

    if input.get(pos).is_some_and(|&b| b == b'E' || b == b'e') {
        have_e = true;
        pos += 1;
        if input.get(pos).is_some_and(|&b| b == b'+' || b == b'-') {
            pos += 1;
        }
        while input.get(pos).is_some_and(|&b| b.wrapping_sub(b'0') <= 9) {
            have_exp = true;
            pos += 1;
        }
    }

    if input.get(pos).is_some_and(|&b| matches!(b, b'd' | b'D' | b'f' | b'F'))
        && (pos + 1 == length
            || input
                .get(pos + 1)
                .is_some_and(|&b| is_byte_white(b) || b == b';' || b == b'u' || b == b'U'))
    {
        pos += 1;
    }

    // Intentional hardening deviation from current libinjection-go: retain a
    // malformed exponent as a visible bareword instead of dropping its token.
    let category = if have_e && !have_exp { TT_BAREWORD } else { TT_NUMBER };
    let v = inp(s, start);
    s.current_mut().assign(category, start, pos - start, v);

    pos
}

/// Go `parseTick`.
fn parse_tick(s: &mut SqliState<'_>) -> usize {
    let input = s.input;
    let length = s.length;
    let pos = s.pos;
    let new_pos = s.current_mut().parse_string_core(input, length, pos, 1, BYTE_TICK);

    let val_len = s.current().len;
    let mut word_buf = [0_u8; 32];
    let copy_len = val_len.min(32);
    let val = s.current().val_slice();
    if let (Some(dst), Some(src)) = (word_buf.get_mut(..copy_len), val.get(..copy_len)) {
        dst.copy_from_slice(src);
    }

    let ch = super::data::lookup_word(LOOKUP_WORD, word_buf.get(..copy_len).unwrap_or(&[]));
    if ch == TT_FUNCTION {
        s.current_mut().category = TT_FUNCTION;
    } else {
        s.current_mut().category = TT_BAREWORD;
    }
    new_pos
}

/// Go `parseUString`.
fn parse_ustring(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    if s.input.get(pos + 1).copied() == Some(b'&') && s.input.get(pos + 2).copied() == Some(BYTE_SINGLE) {
        s.pos += 2;
        let new_pos = parse_string(s);
        s.current_mut().str_open = b'u';
        if s.current().str_close == BYTE_SINGLE {
            s.current_mut().str_close = b'u';
        }
        return new_pos;
    }
    parse_word(s)
}

/// Go `parseQString`.
fn parse_qstring(s: &mut SqliState<'_>) -> usize {
    parse_qstring_core(s, 0)
}

/// Go `parseNQString`.
fn parse_nqstring(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    if s.input.get(pos + 1).copied() == Some(BYTE_SINGLE) && pos + 2 < s.length {
        return parse_estring(s);
    }
    parse_qstring_core(s, 1)
}

/// Go `parseQStringCore`.
fn parse_qstring_core(s: &mut SqliState<'_>, offset: usize) -> usize {
    let pos = s.pos + offset;
    let input = s.input;
    let length = s.length;

    if pos >= length {
        return parse_word(s);
    }
    let Some(&first) = input.get(pos) else {
        return parse_word(s);
    };
    if first != b'q' && first != b'Q' {
        return parse_word(s);
    }
    if pos + 2 >= length || input.get(pos + 1).copied() != Some(BYTE_SINGLE) {
        return parse_word(s);
    }

    let mut ch = match input.get(pos + 2).copied() {
        Some(b) if b >= 33 => b,
        _ => return parse_word(s),
    };

    ch = match ch {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        b'<' => b'>',
        _ => ch,
    };

    let needle = [ch, BYTE_SINGLE];
    let haystack = input.get(pos + 3..).unwrap_or(b"");
    let idx = find_subslice(haystack, &needle);
    let v = inp(s, pos + 3);
    match idx {
        None => {
            s.current_mut().assign(TT_STRING, pos + 3, length - pos - 3, v);
            s.current_mut().str_open = b'q';
            s.current_mut().str_close = BYTE_NULL;
            length
        },
        Some(i) => {
            s.current_mut().assign(TT_STRING, pos + 3, i, v);
            s.current_mut().str_open = b'q';
            s.current_mut().str_close = b'q';
            pos + 3 + i + 2
        },
    }
}

/// Go `parseXString`.
fn parse_xstring(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    if pos + 2 >= s.length || s.input.get(pos + 1).copied() != Some(BYTE_SINGLE) {
        return parse_word(s);
    }

    let dlen = str_len_spn(inp(s, pos + 2), s.length - pos - 2, b"0123456789abcdefABCDEF");
    if pos + 2 + dlen >= s.length || s.input.get(pos + 2 + dlen).copied() != Some(BYTE_SINGLE) {
        return parse_word(s);
    }

    let v = inp(s, pos);
    s.current_mut().assign(TT_NUMBER, pos, dlen + 3, v);
    pos + 2 + dlen + 1
}

/// Go `parseBString`.
fn parse_bstring(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    if pos + 2 >= s.length || s.input.get(pos + 1).copied() != Some(BYTE_SINGLE) {
        return parse_word(s);
    }

    let dlen = str_len_spn(inp(s, pos + 2), s.length - pos - 2, b"01");
    if pos + 2 + dlen >= s.length || s.input.get(pos + 2 + dlen).copied() != Some(BYTE_SINGLE) {
        return parse_word(s);
    }

    let v = inp(s, pos);
    s.current_mut().assign(TT_NUMBER, pos, dlen + 3, v);
    pos + 2 + dlen + 1
}

/// Go `parseEString`.
fn parse_estring(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    if pos + 2 >= s.length || s.input.get(pos + 1).copied() != Some(BYTE_SINGLE) {
        return parse_word(s);
    }
    let input = s.input;
    let length = s.length;
    s.current_mut().parse_string_core(input, length, pos, 2, BYTE_SINGLE)
}

/// Go `parseBWord`.
fn parse_bword(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    let length = s.length;
    let haystack = inp(s, pos);
    let idx = memchr::memchr(b']', haystack);
    let v = inp(s, pos);
    match idx {
        None => {
            s.current_mut().assign(TT_BAREWORD, pos, length - pos, v);
            length
        },
        Some(i) => {
            s.current_mut().assign(TT_BAREWORD, pos, i + 1, v);
            pos + i + 1
        },
    }
}

/// Go `parseMoney`.
fn parse_money(s: &mut SqliState<'_>) -> usize {
    let pos = s.pos;
    let length = s.length;
    let input = s.input;

    if pos + 1 == length {
        s.current_mut().assign(TT_BAREWORD, pos, 1, b"$");
        return length;
    }

    let dlen = str_len_spn(inp(s, pos + 1), length - pos - 1, b"0123456789.,");

    if dlen == 0 {
        if input.get(pos + 1).copied() == Some(b'$') {
            let haystack = input.get(pos + 2..).unwrap_or(b"");
            let idx = find_subslice(haystack, b"$$");
            let v = inp(s, pos + 2);
            return match idx {
                None => {
                    s.current_mut().assign(TT_STRING, pos + 2, length - (pos + 2), v);
                    s.current_mut().str_open = b'$';
                    s.current_mut().str_close = BYTE_NULL;
                    length
                },
                Some(i) => {
                    s.current_mut().assign(TT_STRING, pos + 2, i, v);
                    s.current_mut().str_open = b'$';
                    s.current_mut().str_close = b'$';
                    pos + 2 + i + 2
                },
            };
        }

        let xlen = str_len_spn(
            inp(s, pos + 1),
            length - pos - 1,
            b"abcdefghjiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        );
        if xlen == 0 {
            s.current_mut().assign(TT_BAREWORD, pos, 1, b"$");
            return pos + 1;
        }

        if pos + xlen + 1 == length || input.get(pos + xlen + 1).copied() != Some(b'$') {
            s.current_mut().assign(TT_BAREWORD, pos, 1, b"$");
            return pos + 1;
        }

        let tag = input.get(pos..pos + xlen + 2).unwrap_or(b"");
        let haystack = input.get(pos + xlen + 2..).unwrap_or(b"");
        let idx = find_subslice(haystack, tag);
        let v = inp(s, pos + xlen + 2);
        return match idx {
            None => {
                s.current_mut()
                    .assign(TT_STRING, pos + xlen + 2, length - pos - xlen - 2, v);
                s.current_mut().str_open = b'$';
                s.current_mut().str_close = BYTE_NULL;
                length
            },
            Some(i) => {
                s.current_mut().assign(TT_STRING, pos + xlen + 2, i, v);
                s.current_mut().str_open = b'$';
                s.current_mut().str_close = b'$';
                pos + xlen + 2 + i + xlen + 2
            },
        };
    }

    if dlen == 1 && input.get(pos + 1).copied() == Some(b'.') {
        return parse_word(s);
    }

    let v = inp(s, pos);
    s.current_mut().assign(TT_NUMBER, pos, dlen + 1, v);
    pos + dlen + 1
}

/// Find `needle` in `haystack` (byte subslice search).
/// Locate `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqli::legacy::consts::{TT_BAREWORD, TT_NUMBER};

    #[test]
    fn missing_exponents_are_barewords() {
        for input in [b"1e".as_slice(), b"1234.e", b"10.10E", b".E"] {
            let mut state = SqliState::new(input, 0);
            assert!(state.tokenize());
            assert_eq!(state.current().category, TT_BAREWORD, "input={input:?}");
            assert_eq!(state.current().val_slice(), input);
            assert_eq!(state.stats_tokens, 1);
        }
    }

    #[test]
    fn valid_exponents_remain_numbers() {
        let mut state = SqliState::new(b"10.10E2", 0);
        assert!(state.tokenize());
        assert_eq!(state.current().category, TT_NUMBER);
        assert_eq!(state.current().val_slice(), b"10.10E2");
    }
}
