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
