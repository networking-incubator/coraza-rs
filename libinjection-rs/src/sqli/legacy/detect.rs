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

//! SQLi detection: fingerprint, blacklist, whitelist, multi-pass check.
//!
//! Ported from `sqli.go`: `sqliFingerprint`, `blacklist`, `notWhitelist`,
//! `checkFingerprint`, `check`, `IsSQLi`.

use super::{
    consts::{
        BYTE_DOUBLE, BYTE_NULL, BYTE_SINGLE, BYTE_TICK, FLAG_QUOTE_DOUBLE, FLAG_QUOTE_NONE, FLAG_QUOTE_SINGLE,
        FLAG_SQL_ANSI, FLAG_SQL_MYSQL, MAX_TOKENS, TT_BAREWORD, TT_COMMENT, TT_EVIL, TT_FINGERPRINT, TT_KEYWORD,
        TT_LOGIC_OPERATOR, TT_LPAREN, TT_NUMBER, TT_STRING, TT_UNION, TT_VARIABLE,
    },
    data::search_keyword,
    helpers::to_upper_cmp,
    state::SqliState,
};

impl SqliState<'_> {
    /// Go `sqliFingerprint`: reset with flags, fold, build fingerprint string.
    pub(crate) fn sqli_fingerprint(&mut self, flags: u32) {
        self.reset(flags);
        let length = self.fold();

        // PHP backtick edge case: last token is bareword with backtick-open,
        // empty, unclosed → reclassify as comment.
        if length > 2 {
            let last_idx = length - 1;
            let last_cat = self.tc(last_idx);
            let last_str_open = self.token_str_open(last_idx);
            let last_len = self.token_len(last_idx);
            let last_str_close = self.token_str_close(last_idx);
            if last_cat == TT_BAREWORD && last_str_open == BYTE_TICK && last_len == 0 && last_str_close == BYTE_NULL {
                self.set_tc(last_idx, TT_COMMENT);
            }
        }

        // Build fingerprint from token categories
        self.fingerprint_len = 0;
        let skip_incomplete_exponent = length == 5
            && self.tc(0) == TT_STRING
            && self.tc(1) == TT_LOGIC_OPERATOR
            && self.tc(2) == TT_BAREWORD
            && self.tc(3) == TT_LPAREN
            && self.tc(4) == TT_NUMBER
            && is_incomplete_exponent(self.token_val_slice(2));
        let mut fingerprint_pos = 0;
        for i in 0..length {
            if skip_incomplete_exponent && i == 2 {
                continue;
            }
            let c = self.tc(i);
            if c == TT_EVIL {
                self.set_fp(0, TT_EVIL);
                self.fingerprint_len = 1;
                self.set_tc(0, TT_EVIL);
                return;
            }
            if fingerprint_pos < 5 {
                self.set_fp(fingerprint_pos, c);
                if let Ok(len) = u8::try_from(fingerprint_pos + 1) {
                    self.fingerprint_len = len;
                }
                fingerprint_pos += 1;
            }
        }
        if skip_incomplete_exponent && self.input.last() == Some(&b')') {
            self.set_fp(4, b')');
            self.fingerprint_len = 5;
        }
    }

    /// Go `blacklist`: check if fingerprint is in the blacklist.
    pub(crate) fn blacklist(&self) -> bool {
        let length = self.fingerprint_len as usize;
        if length < 1 {
            return false;
        }

        // Build key: '0' + uppercase fingerprint
        let mut buf = [0_u8; MAX_TOKENS + 1];
        if let Some(slot) = buf.first_mut() {
            *slot = b'0';
        }
        for i in 0..length {
            let mut ch = self.fp(i);
            if ch.is_ascii_lowercase() {
                ch -= 0x20;
            }
            if let Some(slot) = buf.get_mut(i + 1) {
                *slot = ch;
            }
        }

        let key = buf.get(..=length).unwrap_or(&buf);
        let val = search_keyword(key);
        val == TT_FINGERPRINT
    }

    /// Go `notWhitelist`: returns `true` to confirm `SQLi` (not a false positive).
    pub(crate) fn not_whitelist(&self) -> bool {
        let length = self.fingerprint_len as usize;

        // sp_password in trailing comment → force SQLi
        if length > 1 && self.fp(length - 1) == TT_COMMENT && contains_sp_password(self.input) {
            return true;
        }

        match length {
            2 => {
                // ?U: "1 union" — only SQLi if stats_tokens != 2
                if self.fp(1) == TT_UNION {
                    return self.stats_tokens != 2;
                }

                // token[1] starts with '#' → false positive
                if self.token_val_byte(1, 0) == Some(b'#') {
                    return false;
                }

                // nc: bareword + comment not starting with '/'
                if self.tc(0) == TT_BAREWORD && self.tc(1) == TT_COMMENT && self.token_val_byte(1, 0) != Some(b'/') {
                    return false;
                }

                // 1c: number + comment not starting with '/'
                if self.tc(0) == TT_NUMBER && self.tc(1) == TT_COMMENT && self.token_val_byte(1, 0) != Some(b'/') {
                    return true;
                }

                // 1c base64 check (comment starts with '/')
                if self.tc(0) == TT_NUMBER && self.tc(1) == TT_COMMENT {
                    if self.stats_tokens > 2 {
                        return true;
                    }

                    // Check character after the number in the ORIGINAL input
                    let num_end = self.token_pos(0).saturating_add(self.token_len(0));
                    if num_end < self.input.len() {
                        let ch = self.input.get(num_end).copied().unwrap_or(0);
                        if ch <= 32 {
                            return true;
                        }
                        if ch == b'/' && self.input.get(num_end + 1).copied() == Some(b'*') {
                            return true;
                        }
                        if ch == b'-' && self.input.get(num_end + 1).copied() == Some(b'-') {
                            return true;
                        }
                    }

                    return false;
                }

                // "--" comment with content > 2 chars starting with '-'
                if self.token_len(1) > 2 && self.token_val_byte(1, 0) == Some(b'-') {
                    return false;
                }
            },
            3 => {
                // "sos" / "s&s" string concatenation
                let fp0 = self.fp(0);
                let fp1 = self.fp(1);
                let fp2 = self.fp(2);

                if (fp0 == TT_STRING && fp1 == b'o' && fp2 == TT_STRING)
                    || (fp0 == TT_STRING && fp1 == TT_LOGIC_OPERATOR && fp2 == TT_STRING)
                {
                    if self.token_str_open(0) == BYTE_NULL
                        && self.token_str_close(2) == BYTE_NULL
                        && self.token_str_close(0) == self.token_str_open(2)
                    {
                        return true;
                    }
                    if self.stats_tokens == 3 {
                        return false;
                    }
                    return false;
                }

                // "s&n", "n&1", "1&1", "1&v", "1&s"
                let is_benign_3 = (fp0 == TT_STRING && fp1 == TT_LOGIC_OPERATOR && fp2 == TT_BAREWORD)
                    || (fp0 == TT_BAREWORD && fp1 == TT_LOGIC_OPERATOR && fp2 == TT_NUMBER)
                    || (fp0 == TT_NUMBER && fp1 == TT_LOGIC_OPERATOR && fp2 == TT_NUMBER)
                    || (fp0 == TT_NUMBER && fp1 == TT_LOGIC_OPERATOR && fp2 == TT_VARIABLE)
                    || (fp0 == TT_NUMBER && fp1 == TT_LOGIC_OPERATOR && fp2 == TT_STRING);

                if is_benign_3 && self.stats_tokens == 3 {
                    return false;
                }

                // keyword (not INTO) in middle → false positive
                if self.tc(1) == TT_KEYWORD {
                    let val = self.token_val_slice(1);
                    let len = self.token_len(1);
                    if len < 5 || !to_upper_cmp(b"INTO", val.get(..4).unwrap_or(val)) {
                        return false;
                    }
                }
            },
            _ => {},
        }

        true
    }

    /// Go `checkFingerprint`: blacklist AND notWhitelist.
    pub(crate) fn check_fingerprint(&self) -> bool {
        self.blacklist() && self.not_whitelist()
    }

    /// Go `check`: multi-pass `SQLi` detection.
    pub(crate) fn check(&mut self) -> bool {
        if self.length == 0 {
            return false;
        }

        // Pass 1: ANSI, no quote
        self.sqli_fingerprint(FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
        if self.check_fingerprint() {
            return true;
        }

        // Pass 2: MySQL reparse (if --X or # seen)
        if self.reparse_as_mysql() {
            self.sqli_fingerprint(FLAG_QUOTE_NONE | FLAG_SQL_MYSQL);
            if self.check_fingerprint() {
                return true;
            }
        }

        // Pass 3: single-quote context
        if memchr::memchr(BYTE_SINGLE, self.input).is_some() {
            self.sqli_fingerprint(FLAG_QUOTE_SINGLE | FLAG_SQL_ANSI);
            if self.check_fingerprint() {
                return true;
            }

            // Pass 4: single-quote + MySQL
            if self.reparse_as_mysql() {
                self.sqli_fingerprint(FLAG_QUOTE_SINGLE | FLAG_SQL_MYSQL);
                if self.check_fingerprint() {
                    return true;
                }
            }
        }

        // Pass 5: double-quote context (MySQL only)
        if memchr::memchr(BYTE_DOUBLE, self.input).is_some() {
            self.sqli_fingerprint(FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL);
            if self.check_fingerprint() {
                return true;
            }
        }

        false
    }
}

/// Go `IsSQLi`: top-level detection API.
///
/// Returns `(detected, fingerprint_bytes)` where fingerprint is valid only if detected.
pub(crate) fn is_sqli(input: &[u8]) -> (bool, [u8; 5], u8) {
    if input.is_empty() {
        return (false, [0; 5], 0);
    }
    let mut state = SqliState::new(input, 0);
    let detected = state.check();
    if detected {
        (true, state.fingerprint, state.fingerprint_len)
    } else {
        (false, [0; 5], 0)
    }
}

/// Check if input contains `sp_password` (case-sensitive, matching Go).
fn contains_sp_password(input: &[u8]) -> bool {
    memchr::memmem::find(input, b"sp_password").is_some()
}

/// True when `value` is a numeric literal with an exponent marker but no digits after it.
fn is_incomplete_exponent(value: &[u8]) -> bool {
    let Some(exp) = value.iter().position(|byte| matches!(byte, b'E' | b'e')) else {
        return false;
    };
    let prefix = value.get(..exp).unwrap_or(&[]);
    if prefix.is_empty() || !prefix.iter().all(|byte| byte.is_ascii_digit() || *byte == b'.') {
        return false;
    }
    let mut suffix = value.get(exp + 1..).unwrap_or(&[]);
    if suffix.first().is_some_and(|byte| matches!(byte, b'+' | b'-')) {
        suffix = suffix.get(1..).unwrap_or(&[]);
    }
    !suffix.iter().any(u8::is_ascii_digit)
}
