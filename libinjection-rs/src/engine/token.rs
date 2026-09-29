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

//! Lightweight token metadata (offset into original input, zero copy).

#![allow(clippy::missing_docs_in_private_items, reason = "internal tokenizer helpers")]

use super::ascii::{is_alnum, is_alpha, is_digit, is_space};
use crate::limits::MAX_TOKEN_SLOTS;

/// Token kind for stage-1 construct classification.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum TokenKind {
    /// Unclassified byte run.
    #[default]
    Other = 0,
    /// SQL/XSS keyword (letters).
    Keyword = 1,
    /// Numeric literal.
    Number = 2,
    /// Single-quoted string region.
    StringSingle = 3,
    /// Double-quoted string region.
    StringDouble = 4,
    /// Line or block comment.
    Comment = 5,
    /// Operator / punctuation cluster (`=`, `||`, `&&`, ...).
    Operator = 6,
    /// Statement separator `;`.
    Semicolon = 7,
}

/// One token: indices into the **original** input slice.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct TokenMeta {
    /// Byte offset into original input.
    pub offset: u16,
    /// Length in bytes.
    pub len: u16,
    /// Token classification.
    pub kind: TokenKind,
}

/// Fixed token buffer for one analysis pass.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TokenBuf {
    /// Stored tokens.
    pub slots: [TokenMeta; MAX_TOKEN_SLOTS],
    /// Number of valid entries in `slots`.
    pub count: u8,
    /// More tokens were present but dropped.
    pub limit_hit: bool,
}

impl TokenBuf {
    /// Push a token if capacity remains.
    pub(crate) fn push(&mut self, offset: u16, len: u16, kind: TokenKind) {
        let idx = usize::from(self.count);
        if idx >= MAX_TOKEN_SLOTS {
            self.limit_hit = true;
            return;
        }
        if let Some(slot) = self.slots.get_mut(idx) {
            *slot = TokenMeta { offset, len, kind };
            self.count = self.count.saturating_add(1);
        }
    }
}

/// Tokenize `original` for construct heuristics (offsets index `original`).
#[must_use]
pub(crate) fn tokenize(original: &[u8]) -> TokenBuf {
    let mut buf = TokenBuf::default();
    let mut i = 0_usize;
    while i < original.len() {
        let b = original.get(i).copied().unwrap_or(0);
        if is_space(b) {
            i += 1;
            continue;
        }
        let start = i;
        let kind = if b == b'\'' {
            scan_string(original, &mut i, b'\'');
            TokenKind::StringSingle
        } else if b == b'"' {
            scan_string(original, &mut i, b'"');
            TokenKind::StringDouble
        } else if b == b';' {
            i += 1;
            TokenKind::Semicolon
        } else if b == b'#'
            || (b == b'-'
                && original.get(i + 1) == Some(&b'-')
                && original.get(i + 2).is_none_or(|next| is_space(*next)))
        {
            i = original.len();
            TokenKind::Comment
        } else if b == b'/' && original.get(i + 1) == Some(&b'*') {
            scan_block_comment(original, &mut i);
            TokenKind::Comment
        } else if original.get(i).is_some_and(|b| is_digit(*b)) {
            while i < original.len() && original.get(i).is_some_and(|b| is_digit(*b)) {
                i += 1;
            }
            TokenKind::Number
        } else if original.get(i).is_some_and(|b| is_alpha(*b)) {
            while i < original.len() && original.get(i).is_some_and(|b| is_alnum(*b)) {
                i += 1;
            }
            TokenKind::Keyword
        } else {
            i += 1;
            TokenKind::Operator
        };
        let len = i.saturating_sub(start);
        if len > 0 {
            let offset = u16::try_from(start).unwrap_or(u16::MAX);
            let Ok(len_u16) = u16::try_from(len) else {
                continue;
            };
            buf.push(offset, len_u16, kind);
        }
    }
    buf
}

fn scan_string(input: &[u8], i: &mut usize, quote: u8) {
    *i += 1;
    while *i < input.len() {
        let b = input.get(*i).copied().unwrap_or(0);
        if b == b'\\' {
            *i = (*i).saturating_add(2).min(input.len());
            continue;
        }
        if b == quote {
            *i += 1;
            return;
        }
        *i += 1;
    }
}

fn scan_block_comment(input: &[u8], i: &mut usize) {
    *i = i.saturating_add(2);
    while *i + 1 < input.len() {
        if input.get(*i) == Some(&b'*') && input.get(*i + 1) == Some(&b'/') {
            *i = i.saturating_add(2);
            return;
        }
        *i += 1;
    }
    *i = input.len();
}

#[cfg(test)]
mod tests {
    use super::tokenize;

    #[test]
    fn terminal_escape_does_not_extend_string_span() {
        let tokens = tokenize(b"'\\");
        assert_eq!(tokens.count, 1);
        assert_eq!(tokens.slots.first().map(|token| token.len), Some(2));
    }
}
