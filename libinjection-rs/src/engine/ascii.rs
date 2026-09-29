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

//! ASCII helpers for stage-1 pattern scans (zero heap).

/// True if `b` is an ASCII word/identifier character.
#[must_use]
pub(crate) const fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// True if `b` is an ASCII letter.
#[must_use]
pub(crate) const fn is_alpha(b: u8) -> bool {
    b.is_ascii_alphabetic()
}

/// True if `b` is an ASCII digit.
#[must_use]
pub(crate) const fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

/// True if `b` is whitespace or other non-token glue.
#[must_use]
pub(crate) const fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c')
}

/// Word-boundary before `hay[i]`: start of slice or non-alnum before position.
#[must_use]
pub(crate) fn word_boundary_before(hay: &[u8], i: usize) -> bool {
    if i == 0 {
        return true;
    }
    hay.get(i.wrapping_sub(1)).is_none_or(|b| !is_alnum(*b))
}

/// Word-boundary after `hay[i + len - 1]`.
#[must_use]
pub(crate) fn word_boundary_after(hay: &[u8], start: usize, len: usize) -> bool {
    hay.get(start.saturating_add(len)).is_none_or(|b| !is_alnum(*b))
}

/// Case-insensitive compare of equal-length slices.
#[must_use]
pub(crate) fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Find `needle` in `hay` with ASCII case folding (first match).
#[must_use]
pub(crate) fn find_ignore_ascii_case(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let last = hay.len() - needle.len();
    let mut i = 0;
    while i <= last {
        let slice = hay.get(i..i + needle.len())?;
        if eq_ignore_ascii_case(slice, needle) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Find all occurrences of `needle` (case-insensitive), invoking `f` with start offset.
pub(crate) fn for_each_ignore_ascii_case<F>(hay: &[u8], needle: &[u8], mut f: F)
where
    F: FnMut(usize),
{
    if needle.is_empty() {
        return;
    }
    let mut pos = 0;
    while let Some(found) = find_ignore_ascii_case(hay.get(pos..).unwrap_or(&[]), needle) {
        let abs = pos + found;
        f(abs);
        pos = abs + 1;
    }
}
