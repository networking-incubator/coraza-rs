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

//! Legacy `SQLi` path: tokenize, fold, fingerprint, blacklist, whitelist.
//!
//! Enabled only with the `legacy` feature. Used for corpus parity and
//! audit field 0 (`LegacyFingerprint`), not as the primary internal model.

/// Safe accessor helpers for `SqliState` (bounds-checked token/fingerprint/input access).
mod access;
/// Constants (flags, token types, limits).
pub(crate) mod consts;
/// Generated keyword / fingerprint table (`build.rs` + `include!`).
pub(crate) mod data;
/// SQLi detection: fingerprint, blacklist, whitelist, multi-pass check.
mod detect;
/// Folding engine: reduce token stream to ≤5 tokens for fingerprinting.
mod fold;
/// Byte-level helpers (escaping, whitespace, accept tables).
pub(crate) mod helpers;
/// Per-byte token parsers and dispatch table.
pub(crate) mod parse;
/// `SqliState` struct and `tokenize()`.
pub(crate) mod state;
/// `SqliToken` and token-level helpers.
pub(crate) mod token;

/// One SQL token exposed to the corpus test driver.
pub struct SqliTokenInfo {
    /// Token type byte (`b'E'`, `b's'`, `b'v'`, ...).
    pub category: u8,
    /// Byte offset in the original input.
    pub pos: usize,
    /// Significant value length.
    pub len: usize,
    /// `@` count for variables (1 or 2).
    pub count: u8,
    /// Opening string delimiter, or zero.
    pub str_open: u8,
    /// Closing string delimiter, or zero for an unclosed string.
    pub str_close: u8,
    /// Token value bytes.
    pub val: [u8; 31],
}

/// Exact SQL tokenizer and folder counters for one visitor pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SqliStatistics {
    /// Tokens emitted by the tokenizer, including comments and operators.
    pub tokens: usize,
    /// Tokens removed by folding rules.
    pub folds: usize,
    /// ANSI double-dash comments seen by the parser.
    pub comment_ddx: usize,
    /// Hash markers seen by the parser.
    pub comment_hash: usize,
}

/// Copy an internal token into the fixed-size public driver representation.
fn token_info(tok: &token::SqliToken) -> SqliTokenInfo {
    let mut val = [0_u8; 31];
    let copy_len = tok.len.min(val.len());
    if let Some(dst) = val.get_mut(..copy_len) {
        dst.copy_from_slice(tok.val_slice().get(..copy_len).unwrap_or(&[]));
    }
    SqliTokenInfo {
        category: tok.category,
        pos: tok.pos,
        len: tok.len,
        count: tok.count,
        str_open: tok.str_open,
        str_close: tok.str_close,
        val,
    }
}

/// Visit each token emitted by the legacy SQL tokenizer.
pub fn sqli_tokenize_visit(input: &[u8], flags: u32, mut visit: impl FnMut(SqliTokenInfo)) -> SqliStatistics {
    let mut state = state::SqliState::new(input, flags);
    while state.tokenize() {
        visit(token_info(state.current()));
    }
    sqli_statistics(&state)
}

/// Visit each token emitted by the legacy SQL folding pass.
pub fn sqli_fold_visit(input: &[u8], flags: u32, mut visit: impl FnMut(SqliTokenInfo)) -> SqliStatistics {
    let mut state = state::SqliState::new(input, flags);
    let num_tokens = state.fold();
    for tok in state.token_vec.iter().take(num_tokens) {
        visit(token_info(tok));
    }
    sqli_statistics(&state)
}

/// Copy the state counters into the visitor's stable, test-facing result.
fn sqli_statistics(state: &state::SqliState<'_>) -> SqliStatistics {
    SqliStatistics {
        tokens: state.stats_tokens,
        folds: state.stats_folds,
        comment_ddx: state.stats_comment_ddx,
        comment_hash: state.stats_comment_hash,
    }
}

/// Top-level legacy `SQLi` detection returning fingerprint bytes.
///
/// Returns `(detected, fingerprint_bytes, fingerprint_len)`.
pub(crate) fn detect_with_fingerprint(input: &[u8]) -> (bool, [u8; 5], u8) {
    detect::is_sqli(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn assert_fingerprint(input: &[u8], expected: &[u8]) {
        let (detected, fp, len) = detect_with_fingerprint(input);
        assert!(detected, "expected SQLi for input={input:?}");
        let end = usize::from(len);
        assert_eq!(fp.get(..end), Some(expected), "input={input:?}");
    }

    #[test]
    fn is_sqli_benign_inputs() {
        let (detected, _, len) = detect_with_fingerprint(b"");
        assert!(!detected);
        assert_eq!(len, 0);

        for input in [b"hello".as_slice(), b"foo 'bar'", b"foo 'bar' \"zap\""] {
            let (detected, _, len) = detect_with_fingerprint(input);
            assert!(!detected, "benign input should not detect: {input:?}");
            assert_eq!(len, 0);
        }
    }

    #[test]
    fn is_sqli_detects_classic_patterns() {
        assert_fingerprint(b"1 = 1 OR 1", b"1&1");
        assert_fingerprint(b"1\" UNION ALL SELECT * FROM FOO", b"sUEok");
        assert_fingerprint(b"1' or 1.e(1)", b"s&(1)");
        assert_fingerprint(b"1' OR '1'='1", b"s&sos");
    }

    #[test]
    fn detect_union_select_fingerprint() {
        assert_fingerprint(b"1 UNION SELECT 1", b"1UE1");
    }
}
