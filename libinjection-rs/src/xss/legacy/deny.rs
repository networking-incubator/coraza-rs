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

use super::deny_list::{DENY_ATTRS, DENY_EVENTS, DENY_TAGS, DENY_URL_PREFIXES};

/// Maximum normalized bytes retained for one tag or attribute name.
const MAX_NORMALIZED_TOKEN_LEN: usize = 64;

/// Go `attributeType*` (libinjection-go).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum DenyAttrKind {
    /// Not on the deny list.
    None = 0,
    /// Go `attributeTypeBlack` - XSS on the attribute name.
    Deny = 1,
    /// Go `attributeTypeAttrURL` - check value later (`is_deny_url`).
    Url = 2,
    /// Go `attributeTypeStyle` - XSS on the name (`style` / `filter`).
    Style = 3,
    /// Go `attributeTypeAttrIndirect` - value is another attr name.
    Indirect = 4,
}

/// verifies if the name from a html tag is inside a deny list
pub(crate) fn is_deny_tag(name: &[u8]) -> bool {
    if name.len() < 3 {
        return false;
    }
    let Some((normalized, len)) = normalize_name(name) else {
        return false;
    };
    let Some(normalized) = normalized.get(..len) else {
        return false;
    };
    DENY_TAGS.contains(&normalized) || normalized.starts_with(b"SVG") || normalized.starts_with(b"XSL")
}

/// verifies if the name from a html tag is inside a deny list
pub(crate) fn is_deny_attr(name: &[u8]) -> DenyAttrKind {
    let Some((normalized, len)) = normalize_name(name) else {
        return DenyAttrKind::None;
    };
    let Some(normalized) = normalized.get(..len) else {
        return DenyAttrKind::None;
    };
    if normalized.len() < 2 {
        return DenyAttrKind::None;
    }

    if normalized == b"XMLNS" {
        return DenyAttrKind::Deny;
    }

    if normalized.starts_with(b"ON") {
        if normalized.len() >= 5 {
            let suffix = normalized.get(2..).unwrap_or(&[]);
            if DENY_EVENTS.binary_search(&suffix).is_ok() {
                return DenyAttrKind::Deny;
            }
        }
        // No named deny-list attribute begins with ON; an event miss cannot
        // match DENY_ATTRS, so avoid a second lookup on the common miss path.
        return DenyAttrKind::None;
    }

    DENY_ATTRS
        .binary_search_by(|(expected, _)| expected.cmp(&normalized))
        .ok()
        .and_then(|index| DENY_ATTRS.get(index))
        .map_or(DenyAttrKind::None, |(_, kind)| *kind)
}

/// verifies if the name from a html tag is inside a deny list
pub(crate) fn is_deny_url(value: &[u8]) -> bool {
    let mut i = 0;
    // Skip leading whitespace / controls / high-bit (Go c <= 32 || c >= 127)
    while let Some(&b) = value.get(i) {
        if b > 32 && b < 127 {
            break;
        }
        i += 1;
    }
    let Some(s) = value.get(i..) else {
        return false;
    };

    DENY_URL_PREFIXES.iter().any(|p| html_entity_starts_with(s, p))
}

/// Go XSS checks on `html5TypeTagComment` body.
pub(crate) fn is_deny_comment(body: &[u8]) -> bool {
    // 1) backtick anywhere
    if body.contains(&b'`') {
        return true;
    }

    // Go checks raw positions and raw token length for these two prefixes.
    if body.len() > 3
        && body.first() == Some(&b'[')
        && body.get(1).is_some_and(|b| b.eq_ignore_ascii_case(&b'I'))
        && body.get(2).is_some_and(|b| b.eq_ignore_ascii_case(&b'F'))
    {
        return true;
    }

    if body.len() > 3
        && body.first().is_some_and(|b| b.eq_ignore_ascii_case(&b'X'))
        && body.get(1).is_some_and(|b| b.eq_ignore_ascii_case(&b'M'))
        && body.get(2).is_some_and(|b| b.eq_ignore_ascii_case(&b'L'))
    {
        return true;
    }

    // Check the full comment body after removing NUL bytes so
    // embedded NULs cannot shift IMPORT / ENTITY past a fixed-width window.
    let mut buf = [0_u8; 6];
    let mut n = 0;
    for &b in body {
        if b == 0 {
            continue;
        }
        let Some(slot) = buf.get_mut(n) else {
            break;
        };
        *slot = b.to_ascii_uppercase();
        n += 1;
    }
    let prefix = buf.get(..n).unwrap_or(&[]);
    prefix.starts_with(b"IMPORT") || prefix.starts_with(b"ENTITY")
}

/// Uppercase ASCII and remove NUL bytes into Go's fixed-size name buffer.
fn normalize_name(input: &[u8]) -> Option<([u8; MAX_NORMALIZED_TOKEN_LEN], usize)> {
    let mut normalized = [0_u8; MAX_NORMALIZED_TOKEN_LEN];
    let mut len = 0;
    for &byte in input {
        if byte == 0 {
            continue;
        }
        let slot = normalized.get_mut(len)?;
        *slot = byte.to_ascii_uppercase();
        len += 1;
    }
    Some((normalized, len))
}

/// Match an HTML entity-decoded, case-insensitive prefix.
fn html_entity_starts_with(input: &[u8], expected: &[u8]) -> bool {
    let mut pos = 0;
    while input.get(pos).is_some_and(|byte| *byte <= 32 || *byte >= 127) {
        pos += 1;
    }
    let mut first = true;
    let mut matched = 0;
    while pos < input.len() {
        let Some(input_suffix) = input.get(pos..) else {
            return false;
        };
        let Some((mut value, consumed)) = decode_html_byte(input_suffix) else {
            break;
        };
        pos += consumed;
        if first && value <= 32 {
            continue;
        }
        first = false;
        if value == 0 || value == 10 {
            continue;
        }
        if (u32::from(b'a')..=u32::from(b'z')).contains(&value) {
            value -= 0x20;
        }
        if matched >= expected.len() {
            return true;
        }
        let [value_low_byte, ..] = value.to_le_bytes();
        let Some(expected_byte) = expected.get(matched).copied() else {
            return true;
        };
        if value_low_byte != expected_byte {
            return false;
        }
        matched += 1;
    }
    matched >= expected.len()
}

/// Decode one HTML numeric character reference like Go's `htmlDecodeByteAt`.
/// Return the full numeric value and number of bytes consumed.
fn decode_html_byte(input: &[u8]) -> Option<(u32, usize)> {
    let &first = input.first()?;
    if first != b'&' || input.len() < 2 {
        return Some((u32::from(first), 1));
    }
    if input.get(1) != Some(&b'#') || input.len() < 3 {
        return Some((u32::from(b'&'), 1));
    }

    let mut cursor = 2;
    let hex = input.get(cursor) == Some(&b'x') || input.get(cursor) == Some(&b'X');
    if hex {
        cursor += 1;
        if cursor >= input.len() {
            return Some((u32::from(b'&'), 1));
        }
    }
    let Some(first_digit) = input.get(cursor).and_then(|&byte| entity_digit(byte, hex)) else {
        return Some((u32::from(b'&'), 1));
    };
    let mut value = u32::from(first_digit);
    cursor += 1;
    while let Some(&byte) = input.get(cursor) {
        if byte == b';' {
            return Some((value, cursor + 1));
        }
        let Some(digit) = entity_digit(byte, hex) else {
            return Some((value, cursor));
        };
        value = value * if hex { 16 } else { 10 } + u32::from(digit);
        if value > 0x0010_00FF {
            return Some((u32::from(b'&'), 1));
        }
        cursor += 1;
    }
    Some((value, cursor))
}

/// Decode one ASCII decimal or hexadecimal digit.
fn entity_digit(byte: u8, hex: bool) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' if hex => Some(byte - b'a' + 10),
        b'A'..=b'F' if hex => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{DenyAttrKind, decode_html_byte, is_deny_attr, is_deny_tag, is_deny_url};

    #[test]
    fn semicolonless_numeric_entities_decode_and_leave_terminator() {
        assert_eq!(decode_html_byte(b"&#106avascript"), Some((106, 5)));
        assert_eq!(decode_html_byte(b"&#x6Avascript"), Some((106, 5)));
        assert!(is_deny_url(b"&#106avascript:"));
    }

    #[test]
    fn entity_consumption_matches_go_for_malformed_and_overflow_values() {
        for (input, expected) in [
            (b"&".as_slice(), (u32::from(b'&'), 1)),
            (b"&#".as_slice(), (u32::from(b'&'), 1)),
            (b"&#X".as_slice(), (u32::from(b'&'), 1)),
            (b"&#x;".as_slice(), (u32::from(b'&'), 1)),
            (b"&#12z".as_slice(), (12, 4)),
            (b"&#x14a;".as_slice(), (330, 7)),
            (b"&#16713216;".as_slice(), (u32::from(b'&'), 1)),
        ] {
            assert_eq!(decode_html_byte(input), Some(expected), "{input:?}");
        }
    }

    #[test]
    fn deny_names_use_go_exactness_and_normalization_limit() {
        assert_eq!(is_deny_attr(b"onclick"), DenyAttrKind::Deny);
        assert_eq!(is_deny_attr(b"onanimationstart"), DenyAttrKind::Deny);
        assert_eq!(is_deny_attr(b"xmlns"), DenyAttrKind::Deny);
        assert_eq!(is_deny_attr(b"xmlnsfoo"), DenyAttrKind::None);
        assert_eq!(is_deny_attr(b"xmlns:xss"), DenyAttrKind::None);
        assert_eq!(is_deny_attr(b"xlink"), DenyAttrKind::None);
        assert_eq!(is_deny_attr(b"xlinkfoo"), DenyAttrKind::None);
        assert_eq!(is_deny_attr(b"xlink:href"), DenyAttrKind::Url);
        assert_eq!(is_deny_attr(b"xlink:hrefx"), DenyAttrKind::None);
        assert_eq!(is_deny_attr(b"o\0nerror"), DenyAttrKind::Deny);

        let long_event = [b"onclick".as_slice(), &[b'x'; 64]].concat();
        assert_eq!(is_deny_attr(&long_event), DenyAttrKind::None);
        assert!(is_deny_tag(b"svganimate"));
        let long_svg = [b"svg".as_slice(), &[b'x'; 64]].concat();
        assert!(!is_deny_tag(&long_svg));
        assert!(!is_deny_tag(b"\0\0"));
    }

    #[test]
    fn url_entity_matching_keeps_numeric_value_until_go_masks_it() {
        assert!(is_deny_url(b"&#32;java:"));
        assert!(is_deny_url(b"&#x14a;ava:"));
        assert!(!is_deny_url(b"&#x100;avascript:"));
        assert!(is_deny_url(b"j&#0;avascript:"));
        assert!(!is_deny_url(b"https://example.com/javascript"));
    }

    #[test]
    fn deny_urls_ignore_embedded_nulls() {
        assert!(is_deny_url(b"j\0avascript:"));
        assert!(is_deny_url(b"j&#0;avascript:"));
    }
}
