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

//! Folding engine — ported from `sqli.go:fold()` and `merge()`.

use super::{
    consts::{
        BYTE_NULL, MAX_TOKENS, TOKEN_SIZE, TT_BACKSLASH, TT_BAREWORD, TT_COLLATE, TT_COMMA, TT_COMMENT, TT_DOT,
        TT_EVIL, TT_EXPRESSION, TT_FUNCTION, TT_GROUP, TT_KEYWORD, TT_LBRACE, TT_LOGIC_OPERATOR, TT_LPAREN, TT_NUMBER,
        TT_OPERATOR, TT_RBRACE, TT_RPAREN, TT_SEMICOLON, TT_SQLTYPE, TT_STRING, TT_TSQL, TT_UNION, TT_VARIABLE,
    },
    helpers::to_upper_cmp,
    state::SqliState,
    token::SqliToken,
};

#[expect(
    clippy::multiple_inherent_impl,
    reason = "fold logic is a separate concern from tokenizer"
)]
impl SqliState<'_> {
    /// Go `merge`: try to merge two adjacent tokens into a compound phrase.
    ///
    /// On success, `token_vec[a_idx]` is updated with the merged result.
    pub(crate) fn try_merge(&mut self, a_idx: usize, b_idx: usize) -> bool {
        let a_cat = self.tc(a_idx);
        let b_cat = self.tc(b_idx);

        if !matches!(
            a_cat,
            TT_KEYWORD | TT_BAREWORD | TT_OPERATOR | TT_UNION | TT_FUNCTION | TT_EXPRESSION | TT_TSQL | TT_SQLTYPE
        ) {
            return false;
        }

        if !matches!(
            b_cat,
            TT_KEYWORD
                | TT_BAREWORD
                | TT_OPERATOR
                | TT_UNION
                | TT_FUNCTION
                | TT_EXPRESSION
                | TT_TSQL
                | TT_SQLTYPE
                | TT_LOGIC_OPERATOR
        ) {
            return false;
        }

        let a_len = self.token_len(a_idx);
        let b_len = self.token_len(b_idx);

        if a_len + b_len + 1 > TOKEN_SIZE {
            return false;
        }

        let a_val = self.token_val_slice(a_idx);
        let b_val = self.token_val_slice(b_idx);

        let a_copy = a_len.min(a_val.len());
        let b_copy = b_len.min(b_val.len());
        let total = a_copy + 1 + b_copy;

        let mut merged = [0_u8; TOKEN_SIZE];
        if let (Some(dst), Some(src)) = (merged.get_mut(..a_copy), a_val.get(..a_copy)) {
            dst.copy_from_slice(src);
        }
        if let Some(slot) = merged.get_mut(a_copy) {
            *slot = b' ';
        }
        if let (Some(dst), Some(src)) = (merged.get_mut(a_copy + 1..a_copy + 1 + b_copy), b_val.get(..b_copy)) {
            dst.copy_from_slice(src);
        }

        let ch = super::data::search_keyword(merged.get(..total).unwrap_or(&merged));
        if ch != BYTE_NULL {
            let a_pos = self.token_pos(a_idx);
            if let Some(tok) = self.token_vec.get_mut(a_idx) {
                tok.assign(ch, a_pos, total, merged.get(..total).unwrap_or(&merged));
            }
            return true;
        }
        false
    }

    /// Go `fold`: reduce token stream to ≤5 tokens for fingerprinting.
    pub(crate) fn fold(&mut self) -> usize {
        let mut pos: usize = 0;
        let mut left: usize = 0;
        let mut more: bool;
        let mut last_comment = SqliToken::default();

        // Phase 1: skip leading noise (comments, '(', SQL types, unary ops)
        self.current_idx = 0;
        loop {
            more = self.tokenize();
            if !more {
                break;
            }
            let cat = self.tc(self.current_idx);
            if !(cat == TT_COMMENT || cat == TT_LPAREN || cat == TT_SQLTYPE || self.token_is_unary_op(self.current_idx))
            {
                break;
            }
        }

        if !more {
            return 0;
        }
        pos += 1;

        // Main fold loop
        loop {
            // 5-token overflow special cases
            if pos >= MAX_TOKENS && self.check_5token_collapse(pos) {
                if pos > MAX_TOKENS {
                    self.copy_token(1, 5);
                    pos = 2;
                    left = 0;
                } else {
                    pos = 1;
                    left = 0;
                }
            }

            if !more || left >= MAX_TOKENS {
                left = pos;
                break;
            }

            // Read up to 2 tokens
            while more && pos <= MAX_TOKENS && pos - left < 2 {
                self.current_idx = pos;
                more = self.tokenize();
                if more {
                    if self.tc(self.current_idx) == TT_COMMENT {
                        if let Some(tok) = self.token_vec.get(self.current_idx).copied() {
                            last_comment = tok;
                        }
                    } else {
                        last_comment.category = BYTE_NULL;
                        pos += 1;
                    }
                }
            }

            // Did we get 2 tokens?
            if pos - left < 2 {
                left = pos;
                continue;
            }

            // Two-token fold rules (Go switch)
            let two_result = self.fold_two_tokens(&mut left, &mut pos);
            match two_result {
                FoldAction::Continue => continue,
                FoldAction::EarlyReturn(n) => return n,
                FoldAction::FallThrough => {},
            }

            // --- Read 3rd token ---
            while more && pos <= MAX_TOKENS && pos - left < 3 {
                self.current_idx = pos;
                more = self.tokenize();
                if more {
                    if self.tc(self.current_idx) == TT_COMMENT {
                        if let Some(tok) = self.token_vec.get(self.current_idx).copied() {
                            last_comment = tok;
                        }
                    } else {
                        last_comment.category = BYTE_NULL;
                        pos += 1;
                    }
                }
            }

            if pos - left < 3 {
                left = pos;
                continue;
            }

            // Three-token fold rules
            if self.fold_three_tokens(&mut left, &mut pos) {
                continue;
            }

            // No match: commit leftmost token
            left += 1;
        }

        // Trailing comment reattach
        if left < MAX_TOKENS && last_comment.category == TT_COMMENT {
            self.set_token(left, last_comment);
            left += 1;
        }

        if left > MAX_TOKENS {
            left = MAX_TOKENS;
        }

        left
    }

    /// Check the 5-token overflow collapse patterns.
    fn check_5token_collapse(&self, _pos: usize) -> bool {
        let t0 = self.tc(0);
        let t1 = self.tc(1);
        let t2 = self.tc(2);
        let t3 = self.tc(3);
        let t4 = self.tc(4);

        (t0 == TT_NUMBER
            && (t1 == TT_OPERATOR || t1 == TT_COMMA)
            && t2 == TT_LPAREN
            && t3 == TT_NUMBER
            && t4 == TT_RPAREN)
            || (t0 == TT_BAREWORD
                && t1 == TT_OPERATOR
                && t2 == TT_LPAREN
                && (t3 == TT_BAREWORD || t3 == TT_NUMBER)
                && t4 == TT_RPAREN)
            || (t0 == TT_NUMBER && t1 == TT_RPAREN && t2 == TT_COMMA && t3 == TT_LPAREN && t4 == TT_NUMBER)
            || (t0 == TT_BAREWORD && t1 == TT_RPAREN && t2 == TT_OPERATOR && t3 == TT_LPAREN && t4 == TT_BAREWORD)
    }

    /// Two-token fold rules. Returns the action to take.
    #[expect(
        clippy::too_many_lines,
        reason = "direct port of Go switch statement; splitting obscures logic"
    )]
    fn fold_two_tokens(&mut self, left: &mut usize, pos: &mut usize) -> FoldAction {
        let l = *left;
        let l0 = self.tc(l);
        let l1 = self.tc(l + 1);

        // "ss" → "s"
        if l0 == TT_STRING && l1 == TT_STRING {
            *pos -= 1;
            self.stats_folds += 1;
            return FoldAction::Continue;
        }

        // ";;" → ";"
        if l0 == TT_SEMICOLON && l1 == TT_SEMICOLON {
            *pos -= 1;
            self.stats_folds += 1;
            return FoldAction::Continue;
        }

        // (operator|&)(unary|t) → drop second, left=0
        if (l0 == TT_OPERATOR || l0 == TT_LOGIC_OPERATOR) && (self.token_is_unary_op(l + 1) || l1 == TT_SQLTYPE) {
            *pos -= 1;
            self.stats_folds += 1;
            *left = 0;
            return FoldAction::Continue;
        }

        // ( + unary → drop unary, left--
        if l0 == TT_LPAREN && self.token_is_unary_op(l + 1) {
            *pos -= 1;
            self.stats_folds += 1;
            if *left > 0 {
                *left -= 1;
            }
            return FoldAction::Continue;
        }

        // merge → left--
        if self.try_merge(l, l + 1) {
            *pos -= 1;
            self.stats_folds += 1;
            if *left > 0 {
                *left -= 1;
            }
            return FoldAction::Continue;
        }

        // ; + IF(function) → TSQL
        if l0 == TT_SEMICOLON && l1 == TT_FUNCTION && self.token_len(l + 1) >= 2 {
            let v = self.token_val_slice(l + 1);
            if v.len() >= 2
                && v.first().is_some_and(|&b| b == b'I' || b == b'i')
                && v.get(1).is_some_and(|&b| b == b'F' || b == b'f')
            {
                self.set_tc(l + 1, TT_TSQL);
                return FoldAction::Continue;
            }
        }

        // (n|v)( + known function name → reclassify as function
        if (l0 == TT_BAREWORD || l0 == TT_VARIABLE) && l1 == TT_LPAREN && self.is_disambiguated_function(l) {
            self.set_tc(l, TT_FUNCTION);
            return FoldAction::Continue;
        }

        // IN / NOT IN
        if l0 == TT_KEYWORD {
            let val_slice = self.token_val_slice(l);
            if to_upper_cmp(b"IN", val_slice) || to_upper_cmp(b"NOT IN", val_slice) {
                if l1 == TT_LPAREN {
                    self.set_tc(l, TT_OPERATOR);
                } else {
                    self.set_tc(l, TT_BAREWORD);
                }
                return FoldAction::Continue;
            }
        }

        // LIKE / NOT LIKE (no continue — falls through to 3-token)
        if l0 == TT_OPERATOR {
            let val_slice = self.token_val_slice(l);
            if to_upper_cmp(b"LIKE", val_slice) || to_upper_cmp(b"NOT LIKE", val_slice) {
                if l1 == TT_LPAREN {
                    self.set_tc(l, TT_FUNCTION);
                }
                return FoldAction::FallThrough;
            }
        }

        // SQL type swallow: t + (n|1|t|(|f|v|s) → left=0
        if l0 == TT_SQLTYPE
            && matches!(
                l1,
                TT_BAREWORD | TT_NUMBER | TT_SQLTYPE | TT_LPAREN | TT_FUNCTION | TT_VARIABLE | TT_STRING
            )
        {
            self.copy_token(l, l + 1);
            *pos -= 1;
            self.stats_folds += 1;
            *left = 0;
            return FoldAction::Continue;
        }

        // COLLATE + bareword (no continue — falls through; sets left=0 if _ found)
        if l0 == TT_COLLATE && l1 == TT_BAREWORD {
            let val = self.token_val_slice(l + 1);
            if val.contains(&b'_') {
                self.set_tc(l + 1, TT_SQLTYPE);
                *left = 0;
            }
            return FoldAction::FallThrough;
        }

        // Backslash → left=0
        if l0 == TT_BACKSLASH {
            if self.token_is_arithmetic_op(l + 1) {
                self.set_tc(l, TT_NUMBER);
            } else {
                self.copy_token(l, l + 1);
                *pos -= 1;
                self.stats_folds += 1;
            }
            *left = 0;
            return FoldAction::Continue;
        }

        // (( → drop one, left=0
        if l0 == TT_LPAREN && l1 == TT_LPAREN {
            *pos -= 1;
            *left = 0;
            self.stats_folds += 1;
            return FoldAction::Continue;
        }

        // )) → drop one, left=0
        if l0 == TT_RPAREN && l1 == TT_RPAREN {
            *pos -= 1;
            *left = 0;
            self.stats_folds += 1;
            return FoldAction::Continue;
        }

        // { + bareword → left=0
        if l0 == TT_LBRACE && l1 == TT_BAREWORD {
            if self.token_len(l + 1) == 0 {
                self.set_tc(l + 1, TT_EVIL);
                return FoldAction::EarlyReturn(l + 2);
            }
            *left = 0;
            *pos -= 2;
            self.stats_folds += 2;
            return FoldAction::Continue;
        }

        // ?} → drop }, left=0
        if l1 == TT_RBRACE {
            *pos -= 1;
            *left = 0;
            self.stats_folds += 1;
            return FoldAction::Continue;
        }

        FoldAction::FallThrough
    }

    /// Three-token fold rules. Returns `true` if matched (= continue loop).
    fn fold_three_tokens(&mut self, left: &mut usize, pos: &mut usize) -> bool {
        let l = *left;
        let t0 = self.tc(l);
        let t1 = self.tc(l + 1);
        let t2 = self.tc(l + 2);

        // 1 o 1
        if t0 == TT_NUMBER && t1 == TT_OPERATOR && t2 == TT_NUMBER {
            *pos -= 2;
            *left = 0;
            return true;
        }

        // o ? o (middle not '(')
        if t0 == TT_OPERATOR && t1 != TT_LPAREN && t2 == TT_OPERATOR {
            *pos -= 2;
            *left = 0;
            return true;
        }

        // & ? &
        if t0 == TT_LOGIC_OPERATOR && t2 == TT_LOGIC_OPERATOR {
            *pos -= 2;
            *left = 0;
            return true;
        }

        // v o (v|1|n)
        if t0 == TT_VARIABLE && t1 == TT_OPERATOR && matches!(t2, TT_VARIABLE | TT_NUMBER | TT_BAREWORD) {
            *pos -= 2;
            *left = 0;
            return true;
        }

        // (n|1) o (1|n)
        if (t0 == TT_BAREWORD || t0 == TT_NUMBER) && t1 == TT_OPERATOR && (t2 == TT_NUMBER || t2 == TT_BAREWORD) {
            *pos -= 2;
            *left = 0;
            return true;
        }

        // PG cast: ? :: t
        if matches!(t0, TT_BAREWORD | TT_NUMBER | TT_VARIABLE | TT_STRING) && t1 == TT_OPERATOR && t2 == TT_SQLTYPE {
            let op_val = self.token_val_slice(l + 1);
            let op_len = self.token_len(l + 1);
            if op_len == 2 && op_val.get(..2) == Some(b"::") {
                *pos -= 2;
                *left = 0;
                self.stats_folds += 2;
                return true;
            }
        }

        // Comma lists: (n|1|s|v) , (1|n|s|v)
        if matches!(t0, TT_BAREWORD | TT_NUMBER | TT_STRING | TT_VARIABLE)
            && t1 == TT_COMMA
            && matches!(t2, TT_NUMBER | TT_BAREWORD | TT_STRING | TT_VARIABLE)
        {
            *pos -= 2;
            *left = 0;
            return true;
        }

        // (E|B|,) + unary + (
        if matches!(t0, TT_EXPRESSION | TT_GROUP | TT_COMMA) && self.token_is_unary_op(l + 1) && t2 == TT_LPAREN {
            self.copy_token(l + 1, l + 2);
            *pos -= 1;
            *left = 0;
            return true;
        }

        // (k|E|B) + unary + (1|n|v|s|f)
        if matches!(t0, TT_KEYWORD | TT_EXPRESSION | TT_GROUP)
            && self.token_is_unary_op(l + 1)
            && matches!(t2, TT_NUMBER | TT_BAREWORD | TT_VARIABLE | TT_STRING | TT_FUNCTION)
        {
            self.copy_token(l + 1, l + 2);
            *pos -= 1;
            *left = 0;
            return true;
        }

        // , unary (1|n|v|s) → backtrack
        if t0 == TT_COMMA
            && self.token_is_unary_op(l + 1)
            && matches!(t2, TT_NUMBER | TT_BAREWORD | TT_VARIABLE | TT_STRING)
        {
            self.copy_token(l + 1, l + 2);
            *left = 0;
            *pos -= 3;
            return true;
        }

        // , unary function
        if t0 == TT_COMMA && self.token_is_unary_op(l + 1) && t2 == TT_FUNCTION {
            self.copy_token(l + 1, l + 2);
            *pos -= 1;
            *left = 0;
            return true;
        }

        // n . n
        if t0 == TT_BAREWORD && t1 == TT_DOT && t2 == TT_BAREWORD {
            *pos -= 2;
            *left = 0;
            return true;
        }

        // E . n → replace .n with n
        if t0 == TT_EXPRESSION && t1 == TT_DOT && t2 == TT_BAREWORD {
            self.copy_token(l + 1, l + 2);
            *pos -= 1;
            *left = 0;
            return true;
        }

        // f ( ? (not ')') → USER disambiguation (no continue in Go)
        if t0 == TT_FUNCTION && t1 == TT_LPAREN && t2 != TT_RPAREN {
            let val = self.token_val_slice(l);
            if to_upper_cmp(b"USER", val) {
                self.set_tc(l, TT_BAREWORD);
            }
        }

        false
    }

    /// Check if token at `left` matches a known function name for disambiguation.
    fn is_disambiguated_function(&self, left: usize) -> bool {
        let val = self.token_val_slice(left);
        to_upper_cmp(b"USER_ID", val)
            || to_upper_cmp(b"USER_NAME", val)
            || to_upper_cmp(b"DATABASE", val)
            || to_upper_cmp(b"PASSWORD", val)
            || to_upper_cmp(b"USER", val)
            || to_upper_cmp(b"CURRENT_USER", val)
            || to_upper_cmp(b"CURRENT_DATE", val)
            || to_upper_cmp(b"CURRENT_TIME", val)
            || to_upper_cmp(b"CURRENT_TIMESTAMP", val)
            || to_upper_cmp(b"LOCALTIME", val)
            || to_upper_cmp(b"LOCALTIMESTAMP", val)
    }
}

/// Control flow result from two-token fold attempt.
enum FoldAction {
    /// Matched and should `continue` the outer loop.
    Continue,
    /// Early return with token count.
    EarlyReturn(usize),
    /// No match (or non-continuing match); proceed to 3-token rules.
    FallThrough,
}
