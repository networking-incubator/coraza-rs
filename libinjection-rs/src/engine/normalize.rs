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

//! Normalize the selected input prefix, borrowing it when no changes are needed.

#![allow(clippy::missing_docs_in_private_items, reason = "internal normalize helpers")]

use std::borrow::Cow;

/// View over normalized bytes. Evidence offsets always refer to `original`.
#[derive(Clone, Debug)]
pub(crate) struct NormView<'a> {
    /// Original input slice (evidence offsets reference this).
    pub original: &'a [u8],
    /// Normalized bytes, borrowed when the input already has the target form.
    pub bytes: Cow<'a, [u8]>,
    /// Per-byte original spans, populated only by analyzer normalization when needed.
    pub original_spans: Option<Vec<(u32, u8)>>,
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

/// Strip NULs, decode one `%HH` layer, and lowercase ASCII without a size cap.
#[must_use]
#[cfg(test)]
pub(crate) fn normalize(input: &[u8]) -> NormView<'_> {
    normalize_inner(input, false)
}

/// Normalize input while recording a direct map for analyzer evidence spans.
/// The canonical detector keeps using `normalize` and does not allocate this map.
pub(crate) fn normalize_for_analysis(input: &[u8]) -> NormView<'_> {
    normalize_inner(input, true)
}

fn normalize_inner(input: &[u8], map_original_spans: bool) -> NormView<'_> {
    let mut owned = None::<Vec<u8>>;
    let mut original_spans = None::<Vec<(u32, u8)>>;
    let map_original_spans = map_original_spans && u32::try_from(input.len()).is_ok();
    let mut i = 0_usize;
    let mut normalized_len = 0_usize;

    while i < input.len() {
        let byte = input.get(i).copied().unwrap_or(0);
        let (normalized, width, keep) = if byte == 0 {
            (0, 1, false)
        } else if let Some((decoded, width)) = decode_percent(input, i) {
            (decoded.to_ascii_lowercase(), width, decoded != 0)
        } else {
            (byte.to_ascii_lowercase(), 1, true)
        };

        let changed = !keep || width != 1 || normalized != byte;
        if changed && owned.is_none() {
            let mut buffer = Vec::with_capacity(input.len());
            buffer.extend_from_slice(input.get(..i).unwrap_or_default());
            owned = Some(buffer);
        }

        if changed && map_original_spans && original_spans.is_none() {
            let mut spans = Vec::with_capacity(input.len());
            spans.extend((0..normalized_len).filter_map(|offset| u32::try_from(offset).ok().map(|offset| (offset, 1))));
            original_spans = Some(spans);
        }

        if let Some(buffer) = owned.as_mut()
            && keep
        {
            buffer.push(normalized);
        }
        if let Some(spans) = original_spans.as_mut()
            && keep
            && let Some((original_offset, original_width)) = u32::try_from(i).ok().zip(u8::try_from(width).ok())
        {
            spans.push((original_offset, original_width));
        }
        normalized_len += usize::from(keep);
        i += width;
    }

    let bytes = owned.map_or(Cow::Borrowed(input), Cow::Owned);
    NormView {
        original: input,
        bytes,
        original_spans,
    }
}

/// Map a normalized byte span to its original-input offset and byte length.
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
        let (byte, width) = decode_percent(input, i).unwrap_or_else(|| (input.get(i).copied().unwrap_or(0), 1));
        if byte == 0 {
            i += width;
            continue;
        }
        if normalized == start {
            original_start = Some(i);
        }
        normalized += 1;
        i += width;
        if normalized == end {
            original_end = Some(i);
        }
    }

    let original_start = original_start?;
    let original_end = original_end?;
    Some((original_start, original_end.checked_sub(original_start)?))
}

/// Map a normalized span through the offsets recorded by [`normalize_for_analysis`].
pub(crate) fn original_span_from_map(spans: &[(u32, u8)], start: usize, len: usize) -> Option<(usize, usize)> {
    let end = start.checked_add(len)?;
    if len == 0 {
        return None;
    }
    let (original_start, _) = *spans.get(start)?;
    let (last_start, last_width) = *spans.get(end.checked_sub(1)?)?;
    let original_start = usize::try_from(original_start).ok()?;
    let original_end = usize::try_from(last_start).ok()?.checked_add(usize::from(last_width))?;
    Some((original_start, original_end.checked_sub(original_start)?))
}

#[cfg(test)]
mod tests {
    use super::{normalize, normalize_for_analysis, original_span_for_normalized, original_span_from_map};

    #[test]
    fn raw_and_percent_encoded_nuls_are_removed_consistently() {
        let input = b"u%00n\0ion";
        let view = normalize(input);
        assert_eq!(view.bytes.as_ref(), b"union");
        assert_eq!(original_span_for_normalized(input, 0, 5), Some((0, input.len())));
    }

    #[test]
    fn analyzer_normalization_maps_bytes_to_original_spans_in_one_pass() {
        let input = b"a%3C\0b%00c";
        let view = normalize_for_analysis(input);
        assert!(view.original_spans.is_some(), "normalization changed input");
        let spans = view.original_spans.as_deref().unwrap_or_default();

        assert_eq!(view.bytes.as_ref(), b"a<bc");
        assert_eq!(spans.first(), Some(&(0, 1)));
        assert_eq!(spans.get(1), Some(&(1, 3)));
        assert_eq!(spans.get(2), Some(&(5, 1)));
        assert_eq!(spans.get(3), Some(&(9, 1)));

        for start in 0..view.bytes.len() {
            for len in 1..=view.bytes.len() - start {
                assert_eq!(
                    original_span_from_map(spans, start, len),
                    original_span_for_normalized(input, start, len),
                );
            }
        }
    }

    #[test]
    fn analyzer_normalization_does_not_build_a_map_for_unchanged_input() {
        let view = normalize_for_analysis(b"select 1");

        assert!(view.original_spans.is_none());
        assert!(std::ptr::eq(view.original, view.bytes.as_ref()));
    }
}
