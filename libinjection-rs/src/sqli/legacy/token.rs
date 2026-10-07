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

//! `SqliToken` — ported from `sqli_token.go`.

use super::{
    consts::{BYTE_NULL, TOKEN_SIZE, TT_OPERATOR, TT_STRING},
    helpers::to_upper_cmp,
};

/// One SQL token: category + position/length + optional string delimiters.
///
/// Token values are copied into `val` (Go `sqliToken.val` fixed buffer) so fold
/// merge does not need lifetime extension.
#[derive(Clone, Copy)]
pub(crate) struct SqliToken {
    /// Byte offset in original input.
    pub(crate) pos: usize,
    /// Significant length of `val` (≤ `TOKEN_SIZE - 1`).
    pub(crate) len: usize,
    /// `@` count for type `v` (1 = `@`, 2 = `@@`).
    pub(crate) count: u8,
    /// Token type byte (see `consts::TT_*`).
    pub(crate) category: u8,
    /// Opening delimiter for strings (`0` = none / simulated).
    pub(crate) str_open: u8,
    /// Closing delimiter for strings (`0` = unclosed).
    pub(crate) str_close: u8,
    /// Value bytes (len ≤ `TOKEN_SIZE - 1`).
    pub(crate) val: [u8; TOKEN_SIZE],
}

impl Default for SqliToken {
    fn default() -> Self {
        Self {
            pos: 0,
            len: 0,
            count: 0,
            category: 0,
            str_open: 0,
            str_close: 0,
            val: [0; TOKEN_SIZE],
        }
    }
}

impl SqliToken {
    /// Significant value slice (`val[..len]`).
    pub(crate) fn val_slice(&self) -> &[u8] {
        self.val.get(..self.len).unwrap_or(&[])
    }

    /// Go `assign`: set category, pos, truncate value to `TOKEN_SIZE - 1`.
    pub(crate) fn assign(&mut self, token_type: u8, pos: usize, length: usize, value: &[u8]) {
        let last = length.min(TOKEN_SIZE - 1).min(value.len());
        self.category = token_type;
        self.pos = pos;
        self.len = last;
        self.val = [0; TOKEN_SIZE];
        if last > 0
            && let Some(dst) = self.val.get_mut(..last)
        {
            dst.copy_from_slice(value.get(..last).unwrap_or(&[]));
        }
    }

    /// Scan a quoted string starting at `input[pos+offset]`.
    ///
    /// Returns the new position (past the closing delimiter, or at EOF).
    #[expect(
        clippy::too_many_arguments,
        reason = "shared scanner accepts explicit parser context"
    )]
    pub(crate) fn parse_string_core(
        &mut self,
        input: &[u8],
        length: usize,
        pos: usize,
        offset: usize,
        delimiter: u8,
    ) -> usize {
        if offset > 0 {
            self.str_open = delimiter;
        } else {
            self.str_open = BYTE_NULL;
        }

        let start = pos + offset;
        let haystack = input.get(start..).unwrap_or(b"");
        let mut cursor = 0_usize;

        while let Some(remaining) = haystack.get(cursor..) {
            let Some(relative) = memchr::memchr2(delimiter, b'\\', remaining) else {
                break;
            };
            cursor += relative;

            if haystack.get(cursor).copied() == Some(b'\\') {
                let slash_start = cursor;
                while haystack.get(cursor).copied() == Some(b'\\') {
                    cursor += 1;
                }
                let escaped = cursor.saturating_sub(slash_start) % 2 == 1;
                if haystack.get(cursor).copied() != Some(delimiter) {
                    continue;
                }
                if escaped {
                    // The first delimiter after an odd backslash run is
                    // escaped; a following delimiter is evaluated anew.
                    cursor += 1;
                    continue;
                }
            }

            if haystack.get(cursor).copied() == Some(delimiter) {
                if haystack.get(cursor + 1).copied() == Some(delimiter) {
                    // SQL doubled delimiters represent one literal delimiter.
                    cursor += 2;
                    continue;
                }

                self.assign(TT_STRING, start, cursor, haystack);
                self.str_close = delimiter;
                return start + cursor + 1;
            }
        }

        self.assign(TT_STRING, start, length.saturating_sub(start), haystack);
        self.str_close = BYTE_NULL;
        length
    }

    /// Go `isUnaryOp`.
    pub(crate) fn is_unary_op(&self) -> bool {
        if self.category != TT_OPERATOR {
            return false;
        }
        match self.len {
            1 => {
                let ch = self.val_slice().first().copied().unwrap_or(0);
                ch == b'+' || ch == b'-' || ch == b'!' || ch == b'~'
            },
            2 => self.val_slice().first().copied() == Some(b'!') && self.val_slice().get(1).copied() == Some(b'!'),
            3 => to_upper_cmp(b"NOT", self.val_slice().get(..3).unwrap_or(b"")),
            _ => false,
        }
    }

    /// Check `is_arithmetic_op`.
    pub(crate) fn is_arithmetic_op(&self) -> bool {
        if self.category != TT_OPERATOR || self.len != 1 {
            return false;
        }
        let ch = self.val_slice().first().copied().unwrap_or(0);
        ch == b'*' || ch == b'/' || ch == b'+' || ch == b'-' || ch == b'%'
    }
}
