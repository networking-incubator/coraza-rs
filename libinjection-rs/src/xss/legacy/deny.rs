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
    if DENY_TAGS.iter().any(|t| normalized_eq_ignore_ascii_case(name, t)) {
        return true;
    }
    // Go: SVG* / XSL* prefix (length >= 3)
    normalized_prefix_ignore_ascii_case(name, b"SVG") || normalized_prefix_ignore_ascii_case(name, b"XSL")
}

/// verifies if the name from a html tag is inside a deny list
pub(crate) fn is_deny_attr(name: &[u8]) -> DenyAttrKind {
    // Go: XMLNS* / XLINK* -> deny
    if normalized_prefix_ignore_ascii_case(name, b"XMLNS") || normalized_prefix_ignore_ascii_case(name, b"XLINK") {
        return DenyAttrKind::Deny;
    }

    // Go: ON* -> match suffix against deny events
    if normalized_prefix_ignore_ascii_case(name, b"ON") && normalized_suffix_ignore_ascii_case(name, b"ON", DENY_EVENTS)
    {
        return DenyAttrKind::Deny;
    }

    DENY_ATTRS
        .iter()
        .find(|(n, _)| normalized_eq_ignore_ascii_case(name, n))
        .map_or(DenyAttrKind::None, |(_, k)| *k)
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

    // 2) IE conditional: len > 3 and "[IF" (ASCII case-insensitive on IF)
    if normalized_prefix_ignore_ascii_case(body, b"[IF") && normalized_len(body) > 3 {
        return true;
    }

    // 3) XML prefix: len > 3 (Go v0.3.1 off-by-one fix)
    if normalized_prefix_ignore_ascii_case(body, b"XML") && normalized_len(body) > 3 {
        return true;
    }

    // 4) IMPORT / ENTITY after uppercase + strip nulls (first 6 meaningful bytes in Go)
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

/// Compare two byte strings after removing embedded NUL bytes.
fn normalized_eq_ignore_ascii_case(input: &[u8], expected: &[u8]) -> bool {
    normalized_len(input) == expected.len() && normalized_prefix_ignore_ascii_case(input, expected)
}

/// Compare an expected prefix while ignoring embedded NUL bytes.
fn normalized_prefix_ignore_ascii_case(input: &[u8], expected: &[u8]) -> bool {
    let mut input_pos = 0;
    for &want in expected {
        while input.get(input_pos) == Some(&0) {
            input_pos += 1;
        }
        let Some(&got) = input.get(input_pos) else { return false };
        if !got.eq_ignore_ascii_case(&want) {
            return false;
        }
        input_pos += 1;
    }
    true
}

/// Match a deny-list suffix after a normalized attribute prefix.
fn normalized_suffix_ignore_ascii_case(input: &[u8], prefix: &[u8], expected: &[&[u8]]) -> bool {
    let mut prefix_len = 0;
    for &byte in prefix {
        if byte != 0 {
            prefix_len += 1;
        }
    }
    let mut compact = [0_u8; 64];
    let mut len = 0;
    for &byte in input {
        if byte == 0 {
            continue;
        }
        let Some(slot) = compact.get_mut(len) else { return false };
        *slot = byte;
        len += 1;
    }
    compact
        .get(..len)
        .and_then(|name| name.get(prefix_len..))
        .is_some_and(|suffix| expected.iter().any(|event| suffix.eq_ignore_ascii_case(event)))
}

/// Count bytes after removing embedded NUL bytes.
fn normalized_len(input: &[u8]) -> usize {
    input.iter().filter(|&&byte| byte != 0).count()
}

/// Match an HTML entity-decoded, case-insensitive prefix.
fn html_entity_starts_with(input: &[u8], expected: &[u8]) -> bool {
    let mut pos = 0;
    while input.get(pos).is_some_and(|byte| *byte <= 32 || *byte >= 127) {
        pos += 1;
    }
    for &want in expected {
        loop {
            let Some(got) = next_html_byte(input, &mut pos) else {
                return false;
            };
            if got == 0 || got == b'\n' {
                continue;
            }
            if !got.eq_ignore_ascii_case(&want) {
                return false;
            }
            break;
        }
    }
    true
}

/// Decode one raw or numeric HTML entity byte and advance the cursor.
fn next_html_byte(input: &[u8], pos: &mut usize) -> Option<u8> {
    if input.get(*pos..)?.starts_with(b"&#") {
        let mut cursor = pos.saturating_add(2);
        let hex = input.get(cursor) == Some(&b'x') || input.get(cursor) == Some(&b'X');
        if hex {
            cursor += 1;
        }
        let start = cursor;
        let mut value = 0_u32;
        while let Some(&byte) = input.get(cursor) {
            if byte == b';' {
                if cursor == start {
                    return None;
                }
                *pos = cursor + 1;
                return value_to_byte(value);
            }
            let digit = if hex {
                match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => break,
                }
            } else {
                match byte {
                    b'0'..=b'9' => byte - b'0',
                    _ => break,
                }
            };
            value = value
                .saturating_mul(if hex { 16 } else { 10 })
                .saturating_add(u32::from(digit));
            cursor += 1;
        }
        if cursor == start {
            return None;
        }
        *pos = cursor;
        return value_to_byte(value);
    }
    let byte = *input.get(*pos)?;
    *pos += 1;
    Some(byte)
}

/// Convert an entity value without truncating values outside one byte.
///
/// This intentionally differs from current libinjection-go, which masks
/// decoded values to eight bits to preserve C behavior. Rejecting them avoids
/// treating an oversized entity as an unrelated byte in the Rust port.
fn value_to_byte(value: u32) -> Option<u8> {
    if value > 0x0010_00FF {
        return None;
    }
    u8::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::{is_deny_url, next_html_byte};

    #[test]
    fn semicolonless_numeric_entities_decode_and_leave_terminator() {
        let mut pos = 0;
        assert_eq!(next_html_byte(b"&#106avascript", &mut pos), Some(b'j'));
        assert_eq!(pos, 5);
        assert_eq!(next_html_byte(b"&#106avascript", &mut pos), Some(b'a'));

        assert!(is_deny_url(b"&#106avascript:"));
        let mut pos = 0;
        assert_eq!(next_html_byte(b"&#x6Avascript", &mut pos), Some(b'j'));
        assert_eq!(pos, 5);
    }

    #[test]
    fn oversized_numeric_entities_are_rejected() {
        let mut pos = 0;
        assert_eq!(next_html_byte(b"&#256;", &mut pos), None);

        let mut pos = 0;
        assert_eq!(next_html_byte(b"&#x100100;", &mut pos), None);
    }

    #[test]
    fn deny_urls_ignore_embedded_nulls() {
        assert!(is_deny_url(b"j\0avascript:"));
        assert!(is_deny_url(b"j&#0;avascript:"));
    }
}
