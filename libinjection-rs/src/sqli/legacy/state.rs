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

//! `SqliState` and `tokenize()` — ported from `sqli.go`.

use super::{
    access::EMPTY_TOKEN,
    consts::{BYTE_NULL, FLAG_QUOTE_DOUBLE, FLAG_QUOTE_NONE, FLAG_QUOTE_SINGLE, FLAG_SQL_ANSI},
    helpers::flag2_delimiter,
    parse::dispatch,
    token::SqliToken,
};

/// Go `sqliState` — parser state for one input.
pub(crate) struct SqliState<'a> {
    /// Raw input bytes (never mutated).
    pub(crate) input: &'a [u8],
    /// Cached input length.
    pub(crate) length: usize,
    /// Flags (quote context + SQL dialect).
    pub(crate) flags: u32,
    /// Current byte offset.
    pub(crate) pos: usize,
    /// Token ring buffer (Go uses `[8]sqliToken`).
    pub(crate) token_vec: [SqliToken; 8],
    /// Index into `token_vec` for the current token being built.
    pub(crate) current_idx: usize,
    /// Fingerprint bytes (built during fold/detection).
    pub(crate) fingerprint: [u8; 5],
    /// Length of valid fingerprint bytes.
    pub(crate) fingerprint_len: u8,

    // -- Stats (accumulated across tokenize/fold calls) --
    /// `--[not-white]` comments (ANSI).
    pub(crate) stats_comment_ddx: u16,
    /// `#` operator/comment occurrences.
    pub(crate) stats_comment_hash: u16,
    /// Tokens folded away.
    pub(crate) stats_folds: u16,
    /// Total tokens emitted.
    pub(crate) stats_tokens: u16,

    /// Write-sink for out-of-bounds mutable token access (defensive fallback).
    overflow_token: SqliToken,
}

impl<'a> SqliState<'a> {
    /// Go `sqliInit`: create a new state for `input` with `flags`.
    ///
    /// If `flags == 0` the default `QUOTE_NONE | SQL_ANSI` is used.
    pub(crate) fn new(input: &'a [u8], flags: u32) -> Self {
        let flags = if flags == 0 {
            FLAG_QUOTE_NONE | FLAG_SQL_ANSI
        } else {
            flags
        };
        Self {
            input,
            length: input.len(),
            flags,
            pos: 0,
            token_vec: Default::default(),
            current_idx: 0,
            fingerprint: [0; 5],
            fingerprint_len: 0,
            stats_comment_ddx: 0,
            stats_comment_hash: 0,
            stats_folds: 0,
            stats_tokens: 0,
            overflow_token: SqliToken::default(),
        }
    }

    /// Go `reset`: re-initialize with the same input but new flags.
    pub(crate) fn reset(&mut self, flags: u32) {
        let input = self.input;
        *self = Self::new(input, flags);
    }

    /// Go `tokenize`: emit the next token, or `false` at EOF.
    pub(crate) fn tokenize(&mut self) -> bool {
        if self.length == 0 {
            return false;
        }
        if let Some(tok) = self.token_vec.get_mut(self.current_idx) {
            *tok = SqliToken::default();
        }

        // Simulated quote at pos == 0
        if self.pos == 0 && (self.flags & (FLAG_QUOTE_SINGLE | FLAG_QUOTE_DOUBLE)) != 0 {
            let delim = flag2_delimiter(self.flags);
            let input = self.input;
            let length = self.length;
            self.pos = self.current_mut().parse_string_core(input, length, 0, 0, delim);
            self.stats_tokens += 1;
            return true;
        }

        while self.pos < self.length {
            self.pos = dispatch(self);

            if self.current().category != BYTE_NULL {
                self.stats_tokens += 1;
                return true;
            }
        }

        false
    }

    // -- Accessors --

    /// Reference to the current token.
    pub(crate) fn current(&self) -> &SqliToken {
        self.token_vec.get(self.current_idx).unwrap_or(&EMPTY_TOKEN)
    }

    /// Mutable reference to the current token.
    pub(crate) fn current_mut(&mut self) -> &mut SqliToken {
        let idx = self.current_idx;
        if idx < self.token_vec.len() {
            // idx < 8 is guaranteed; get_mut always returns Some
            match self.token_vec.get_mut(idx) {
                Some(t) => t,
                None => &mut self.overflow_token,
            }
        } else {
            &mut self.overflow_token
        }
    }

    /// Go `reparseAsMySQL`: true if `MySQL` reparse is needed.
    pub(crate) fn reparse_as_mysql(&self) -> bool {
        self.stats_comment_ddx != 0 || self.stats_comment_hash != 0
    }
}
