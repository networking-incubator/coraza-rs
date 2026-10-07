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

//! Generated keyword / fingerprint table (`build.rs` + `include!`).

use core::cmp::Ordering;

use super::consts::{BYTE_NULL, LOOKUP_FINGERPRINT, LOOKUP_OPERATOR, LOOKUP_WORD};

include!(concat!(env!("OUT_DIR"), "/sqli_keywords.rs"));

/// Apply Go `strings.ToUpper` behavior relevant to the ASCII-only table, then
/// look up the result. Go's simple rune mapping has two non-ASCII inputs that
/// uppercase to ASCII: dotless i (`U+0131`) and long s (`U+017F`). Other
/// non-ASCII runes cannot match this table. Invalid UTF-8 also cannot match.
/// Returns the type byte or [`BYTE_NULL`] on miss without allocating.
pub(crate) fn search_keyword(key: &[u8]) -> u8 {
    let mut buf = [0_u8; 64];
    let mut written = 0_usize;
    let mut pos = 0_usize;

    while let Some(&byte) = key.get(pos) {
        let (upper, consumed) = match byte {
            b'a'..=b'z' => (byte - 0x20, 1),
            0xC4 if key.get(pos + 1).copied() == Some(0xB1) => (b'I', 2), // U+0131
            0xC5 if key.get(pos + 1).copied() == Some(0xBF) => (b'S', 2), // U+017F
            0x00..=0x7F => (byte, 1),
            // Go uppercases arbitrary invalid bytes as RuneError; that remains
            // non-ASCII and therefore cannot match any table key.
            _ => return BYTE_NULL,
        };
        let Some(slot) = buf.get_mut(written) else {
            return BYTE_NULL;
        };
        *slot = upper;
        written += 1;
        pos += consumed;
    }

    if pos != key.len() {
        return BYTE_NULL;
    }
    let Some(slice) = buf.get(..written) else {
        return BYTE_NULL;
    };
    lookup_keyword_bytes(slice).unwrap_or(BYTE_NULL)
}

/// Go `lookupWord` for tokenize-time keyword / operator resolution.
pub(crate) fn lookup_word(lookup_type: u8, word: &[u8]) -> u8 {
    if lookup_type == LOOKUP_FINGERPRINT {
        // Fingerprint lookup runs after fold via `blacklist()`, not during tokenize.
        return BYTE_NULL;
    }
    let ch = search_keyword(word);
    if ch != BYTE_NULL {
        return ch;
    }
    if lookup_type == LOOKUP_OPERATOR || lookup_type == LOOKUP_WORD {
        return BYTE_NULL;
    }
    BYTE_NULL
}

/// Binary search the build-time sorted keyword table.
fn lookup_keyword_bytes(key: &[u8]) -> Option<u8> {
    let mut lo = 0_usize;
    let mut hi = SQL_KEYWORD_ENTRIES.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let (entry_key, val) = SQL_KEYWORD_ENTRIES.get(mid)?;
        match entry_key.cmp(&key) {
            Ordering::Less => lo = mid + 1,
            Ordering::Greater => hi = mid,
            Ordering::Equal => return Some(*val),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::search_keyword;
    use crate::sqli::legacy::consts::{TT_EXPRESSION, TT_UNION};

    #[test]
    fn keyword_lookup_uses_go_simple_uppercase_mappings() {
        assert_eq!(search_keyword("ſelect".as_bytes()), TT_EXPRESSION);
        assert_eq!(search_keyword("unıon".as_bytes()), TT_UNION);
        // Go's simple rune uppercase does not expand sharp s into "SS".
        assert_eq!(search_keyword("ßelect".as_bytes()), 0);
        assert_eq!(search_keyword(&[0xFF, b'S', b'E', b'L', b'E', b'C', b'T']), 0);
        assert_eq!(search_keyword(b"select"), TT_EXPRESSION);
        assert_eq!(search_keyword(b"not_a_keyword"), 0);
    }
}
