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

/// Uppercase `key`, look it up in the static sorted table.
/// Returns the type byte or [`BYTE_NULL`] on miss.
pub(crate) fn search_keyword(key: &[u8]) -> u8 {
    let mut buf = [0_u8; 64];
    let len = key.len().min(buf.len());
    if let (Some(dst), Some(src)) = (buf.get_mut(..len), key.get(..len)) {
        for (d, s) in dst.iter_mut().zip(src) {
            *d = s.to_ascii_uppercase();
        }
    }
    let slice = buf.get(..len).unwrap_or(&[]);
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
