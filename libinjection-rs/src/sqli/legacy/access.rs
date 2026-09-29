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

//! Safe accessor helpers for `SqliState` `token_vec`, fingerprint, and input.
//!
//! All methods use `.get()` / `.get_mut()` to avoid direct indexing, satisfying
//! `clippy::indexing_slicing` without module-level suppression.

use super::{
    consts::{BYTE_NULL, TOKEN_SIZE},
    state::SqliState,
    token::SqliToken,
};

/// Default zero-initialized token for out-of-bounds immutable fallback.
pub(crate) const EMPTY_TOKEN: SqliToken = SqliToken {
    pos: 0,
    len: 0,
    count: 0,
    category: BYTE_NULL,
    str_open: 0,
    str_close: 0,
    val: [0; TOKEN_SIZE],
};

#[expect(
    clippy::multiple_inherent_impl,
    reason = "safe accessors are a separate concern from tokenizer/fold/detect"
)]
impl SqliState<'_> {
    /// Token category at `idx`, or `BYTE_NULL` if out of bounds.
    pub(crate) fn tc(&self, idx: usize) -> u8 {
        self.token_vec.get(idx).map_or(BYTE_NULL, |t| t.category)
    }

    /// Set token category at `idx`.
    pub(crate) fn set_tc(&mut self, idx: usize, cat: u8) {
        if let Some(tok) = self.token_vec.get_mut(idx) {
            tok.category = cat;
        }
    }

    /// Token `len` at `idx`, or `0` if out of bounds.
    pub(crate) fn token_len(&self, idx: usize) -> usize {
        self.token_vec.get(idx).map_or(0, |t| t.len)
    }

    /// Token `pos` at `idx`, or `0` if out of bounds.
    pub(crate) fn token_pos(&self, idx: usize) -> usize {
        self.token_vec.get(idx).map_or(0, |t| t.pos)
    }

    /// Token `str_open` at `idx`, or `0` if out of bounds.
    pub(crate) fn token_str_open(&self, idx: usize) -> u8 {
        self.token_vec.get(idx).map_or(0, |t| t.str_open)
    }

    /// Token `str_close` at `idx`, or `0` if out of bounds.
    pub(crate) fn token_str_close(&self, idx: usize) -> u8 {
        self.token_vec.get(idx).map_or(0, |t| t.str_close)
    }

    /// Token `val_slice()` at `idx`, or `&[]` if out of bounds.
    pub(crate) fn token_val_slice(&self, idx: usize) -> &[u8] {
        match self.token_vec.get(idx) {
            Some(t) => t.val_slice(),
            None => &[],
        }
    }

    /// Byte `byte_idx` of token `idx` value, if in range.
    pub(crate) fn token_val_byte(&self, idx: usize, byte_idx: usize) -> Option<u8> {
        self.token_vec
            .get(idx)
            .and_then(|t| t.val_slice().get(byte_idx).copied())
    }

    /// Check `is_unary_op()` on token at `idx`.
    pub(crate) fn token_is_unary_op(&self, idx: usize) -> bool {
        self.token_vec.get(idx).is_some_and(SqliToken::is_unary_op)
    }

    /// Check `is_arithmetic_op()` on token at `idx`.
    pub(crate) fn token_is_arithmetic_op(&self, idx: usize) -> bool {
        self.token_vec.get(idx).is_some_and(SqliToken::is_arithmetic_op)
    }

    /// Copy token from `src` index to `dst` index in `token_vec`.
    pub(crate) fn copy_token(&mut self, dst: usize, src: usize) {
        if let Some(tok) = self.token_vec.get(src).copied() {
            self.set_token(dst, tok);
        }
    }

    /// Set a token at `idx` to a given `SqliToken`.
    pub(crate) fn set_token(&mut self, idx: usize, tok: SqliToken) {
        if let Some(d) = self.token_vec.get_mut(idx) {
            *d = tok;
        }
    }

    /// Fingerprint byte at `idx`, or `0` if out of bounds.
    pub(crate) fn fp(&self, idx: usize) -> u8 {
        self.fingerprint.get(idx).copied().unwrap_or(0)
    }

    /// Set fingerprint byte at `idx`.
    pub(crate) fn set_fp(&mut self, idx: usize, val: u8) {
        if let Some(slot) = self.fingerprint.get_mut(idx) {
            *slot = val;
        }
    }
}
