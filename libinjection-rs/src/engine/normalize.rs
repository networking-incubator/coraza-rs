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

//! Bounded normalization into a stack buffer (best-effort, detection-only).

#![allow(clippy::missing_docs_in_private_items, reason = "internal normalize helpers")]

use crate::limits::NORM_BUF_LEN;

/// View over normalized bytes: either the original slice or a stack copy.
#[derive(Clone, Copy)]
pub(crate) struct NormView<'a> {
    /// Original input slice (evidence offsets reference this).
    pub original: &'a [u8],
    /// Bytes used for pattern matching.
    pub bytes: &'a [u8],
    /// Normalization exceeded [`NORM_BUF_LEN`].
    pub norm_truncated: bool,
}

/// Decode one `%HH` sequence; returns decoded byte and consumed width (1 or 3).
fn decode_percent(input: &[u8], i: usize) -> Option<(u8, usize)> {
    if input.get(i) != Some(&b'%') {
        return None;
    }
    let hi = hex_nibble(*input.get(i + 1)?)?;
    let lo = hex_nibble(*input.get(i + 2)?)?;
    Some(((hi << 4) | lo, 3))
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Bounded normalize: strip NULs, one layer of `%` decoding, lowercase ASCII letters.
#[must_use]
pub(crate) fn normalize<'a>(input: &'a [u8], buf: &'a mut [u8; NORM_BUF_LEN]) -> NormView<'a> {
    let mut out = 0_usize;
    let mut norm_truncated = false;
    let mut i = 0_usize;
    while i < input.len() {
        if out >= buf.len() {
            norm_truncated = true;
            break;
        }
        let b = input.get(i).copied().unwrap_or(0);
        if b == 0 {
            i += 1;
            continue;
        }
        if let Some((decoded, width)) = decode_percent(input, i) {
            if let Some(slot) = buf.get_mut(out) {
                *slot = decoded.to_ascii_lowercase();
                out += 1;
            }
            i += width;
            continue;
        }
        if let Some(slot) = buf.get_mut(out) {
            *slot = b.to_ascii_lowercase();
            out += 1;
        }
        i += 1;
    }
    if i < input.len() {
        norm_truncated = true;
    }
    let bytes = buf.get(..out).unwrap_or(&[]);
    NormView {
        original: input,
        bytes,
        norm_truncated,
    }
}

/// Map a normalized byte span back to the original input span.
pub(crate) fn original_span_for_normalized(input: &[u8], start: usize, len: usize) -> Option<(usize, usize)> {
    let end = start.checked_add(len)?;
    let mut normalized = 0_usize;
    let mut original_start = None;
    let mut original_end = None;
    let mut i = 0_usize;

    while i < input.len() && normalized < end {
        if input.get(i) == Some(&0) {
            i += 1;
            continue;
        }
        if normalized == start {
            original_start = Some(i);
        }
        let width = decode_percent(input, i).map_or(1, |(_, width)| width);
        normalized += 1;
        i += width;
        if normalized == end {
            original_end = Some(i);
        }
    }

    Some((original_start?, original_end?))
}
