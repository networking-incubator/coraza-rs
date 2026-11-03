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

//! Pure HTTP metadata, header and response helpers shared by Envoy adapters.

use std::str;

/// Maximum number of headers or trailers accepted in one direction.
pub const MAX_HEADER_COUNT: usize = 1024;

/// Maximum bytes accepted in one HTTP header value.
pub const MAX_HEADER_VALUE_BYTES: usize = 64 * 1024;

/// Maximum bytes accepted across one direction's headers and trailers.
pub const MAX_HEADERS_BYTES: usize = 1024 * 1024;

/// Finds a header value using case-insensitive name matching.
pub fn find_header<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_slice())
}

/// Returns `:authority`, falling back to the host value when it is absent.
pub fn request_authority(headers: &[(String, Vec<u8>)], fallback: Option<&[u8]>) -> Vec<u8> {
    find_header(headers, ":authority")
        .or(fallback)
        .unwrap_or_default()
        .to_vec()
}

/// Checks header count, reported count, per-value size and aggregate size.
pub fn headers_within_limits(headers: &[(String, Vec<u8>)], reported_count: usize) -> bool {
    if headers.len() > MAX_HEADER_COUNT || headers.len() > reported_count {
        return false;
    }
    headers
        .iter()
        .try_fold(0_usize, |total, (name, value)| {
            if value.len() > MAX_HEADER_VALUE_BYTES {
                return None;
            }
            total.checked_add(name.len())?.checked_add(value.len())
        })
        .is_some_and(|total| total <= MAX_HEADERS_BYTES)
}

/// Normalizes an authority to the lowercase selection key used by policies.
///
/// The scheme's default port is removed. Invalid UTF-8, host syntax, IPv6
/// literals and ports are rejected.
pub fn normalize_authority(authority: &[u8], scheme: &[u8]) -> Option<String> {
    let authority = str::from_utf8(authority).ok()?;
    if authority.is_empty() {
        return Some(String::new());
    }
    let lower = authority.to_ascii_lowercase();
    let (host, port) = authority_parts(&lower)?;
    let default_port = if scheme.eq_ignore_ascii_case(b"http") {
        Some("80")
    } else if scheme.eq_ignore_ascii_case(b"https") {
        Some("443")
    } else {
        None
    };
    if port == default_port {
        Some(host.to_owned())
    } else {
        Some(lower)
    }
}

/// Returns the host component used for Coraza's server-name metadata.
pub fn authority_host(authority: &str) -> &str {
    if authority.starts_with('[') {
        authority
            .find(']')
            .and_then(|close| authority.get(1..close))
            .unwrap_or_default()
    } else {
        authority.split_once(':').map_or(authority, |(host, _)| host)
    }
}

/// Whether any content-encoding token is other than `identity`.
pub fn has_unsupported_content_encoding(headers: &[(String, Vec<u8>)]) -> bool {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .flat_map(|(_, value)| value.split(|byte| *byte == b','))
        .map(trim_ascii)
        .any(|encoding| !encoding.eq_ignore_ascii_case(b"identity"))
}

/// Whether headers indicate an HTTP upgrade.
pub fn has_upgrade(headers: &[(String, Vec<u8>)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("upgrade")
            || (name.eq_ignore_ascii_case("connection")
                && value
                    .split(|byte| *byte == b',')
                    .map(trim_ascii)
                    .any(|token| token.eq_ignore_ascii_case(b"upgrade")))
    })
}

/// Whether `value` can be written as a safe HTTP `Location` header value.
///
/// Only visible ASCII is accepted, rejecting control bytes and non-ASCII
/// encodings before the value reaches a host response encoder.
pub fn safe_location(value: &str) -> bool {
    value.bytes().all(|byte| (0x20..=0x7E).contains(&byte))
}

/// Returns the configured response status when valid, otherwise the default denial status.
pub fn valid_status(status: u16) -> u16 {
    if (200..=599).contains(&status) { status } else { 403 }
}

/// Splits a validated normalized authority into host and optional port.
fn authority_parts(authority: &str) -> Option<(&str, Option<&str>)> {
    if authority.starts_with('[') {
        let close = authority.find(']')?;
        let host = authority.get(..=close)?;
        let address = authority.get(1..close)?.parse::<std::net::Ipv6Addr>().ok()?;
        let _ = address;
        let suffix = authority.get(close.saturating_add(1)..)?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(valid_authority_port(suffix.strip_prefix(':')?)?)
        };
        Some((host, port))
    } else {
        let mut colons = authority.match_indices(':');
        let Some((index, _)) = colons.next() else {
            return valid_reg_name(authority).then_some((authority, None));
        };
        if colons.next().is_some() {
            return None;
        }
        let host = authority.get(..index)?;
        let port = valid_authority_port(authority.get(index.saturating_add(1)..)?)?;
        valid_reg_name(host).then_some((host, Some(port)))
    }
}

/// Returns a numeric port when it fits the authority port range.
fn valid_authority_port(port: &str) -> Option<&str> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    port.parse::<u16>().ok().map(|_| port)
}

/// Checks the URI registered-name syntax used for non-IPv6 hosts.
fn valid_reg_name(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    let bytes = host.as_bytes();
    let mut index = 0;
    while let Some(byte) = bytes.get(index).copied() {
        if byte == b'%' {
            if !bytes
                .get(index.saturating_add(1)..index.saturating_add(3))
                .is_some_and(|escape| escape.len() == 2 && escape.iter().all(u8::is_ascii_hexdigit))
            {
                return false;
            }
            index += 3;
            continue;
        }
        if !(byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&byte)) {
            return false;
        }
        index += 1;
    }
    true
}

/// Trims ASCII whitespace from both ends of a byte value.
fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = value.get(1..).unwrap_or_default();
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = value.get(..value.len().saturating_sub(1)).unwrap_or_default();
    }
    value
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_HEADER_COUNT, MAX_HEADER_VALUE_BYTES, find_header, has_unsupported_content_encoding, has_upgrade,
        headers_within_limits, normalize_authority, request_authority, safe_location, valid_status,
    };

    #[test]
    fn authority_normalization_covers_case_default_ports_and_ipv6() {
        assert_eq!(
            normalize_authority(b"a.example:80", b"https").as_deref(),
            Some("a.example:80")
        );
        assert_eq!(
            normalize_authority(b"a.example:443", b"http").as_deref(),
            Some("a.example:443")
        );
        assert_eq!(
            normalize_authority(b"WAF.EXAMPLE:80", b"http").as_deref(),
            Some("waf.example")
        );
        assert_eq!(
            normalize_authority(b"WAF.EXAMPLE:8443", b"https").as_deref(),
            Some("waf.example:8443")
        );
        assert_eq!(
            normalize_authority(b"[2001:DB8::1]:443", b"https").as_deref(),
            Some("[2001:db8::1]")
        );
        assert_eq!(
            normalize_authority(b"[2001:DB8::1]", b"http").as_deref(),
            Some("[2001:db8::1]")
        );
    }

    #[test]
    fn malformed_and_missing_authority_paths_are_explicit() {
        assert_eq!(normalize_authority(b"\xff", b"http"), None);
        assert_eq!(normalize_authority(b"a.example/path", b"http"), None);
        assert_eq!(normalize_authority(b"a.example:65536", b"http"), None);
        assert_eq!(normalize_authority(b"", b"http").as_deref(), Some(""));

        let headers = vec![(":method".to_owned(), b"GET".to_vec())];
        assert_eq!(
            request_authority(&headers, Some(b"fallback.example")),
            b"fallback.example"
        );
        assert_eq!(request_authority(&headers, None), b"");
    }

    #[test]
    fn header_helpers_preserve_case_insensitive_matching_and_limits() {
        let headers = vec![("X-Test".to_owned(), b"value".to_vec())];
        assert_eq!(find_header(&headers, "x-test"), Some(b"value".as_slice()));
        assert!(headers_within_limits(&headers, 1));
        assert!(!headers_within_limits(&headers, 0));
        assert!(!headers_within_limits(
            &[("x".to_owned(), vec![b'x'; MAX_HEADER_VALUE_BYTES + 1])],
            1
        ));
        assert!(!headers_within_limits(
            &(0..=MAX_HEADER_COUNT)
                .map(|_| ("x".to_owned(), vec![]))
                .collect::<Vec<_>>(),
            MAX_HEADER_COUNT + 1
        ));
    }

    #[test]
    fn encoding_and_upgrade_helpers_are_token_aware() {
        assert!(!has_unsupported_content_encoding(&[(
            "content-encoding".to_owned(),
            b" identity ".to_vec()
        )]));
        assert!(has_unsupported_content_encoding(&[(
            "content-encoding".to_owned(),
            b"gzip, identity".to_vec()
        )]));
        assert!(has_upgrade(&[(
            "connection".to_owned(),
            b"keep-alive, Upgrade".to_vec()
        )]));
        assert!(!has_upgrade(&[("connection".to_owned(), b"keep-alive".to_vec())]));
    }

    #[test]
    fn location_validator_accepts_only_visible_ascii() {
        assert!(safe_location("https://example.test/blocked"));
        assert!(!safe_location("https://example.test/blocked\r\nSet-Cookie: injected=1"));
        assert!(!safe_location("https://example.test/blocked\u{0080}"));
        for byte in 0..=u8::MAX {
            let value = char::from(byte).to_string();
            assert_eq!(
                safe_location(&value),
                (0x20..=0x7E).contains(&byte),
                "unexpected Location validation for byte {byte:#04x}"
            );
        }
    }

    #[test]
    fn invalid_response_statuses_fall_back_to_forbidden() {
        assert_eq!(valid_status(199), 403);
        assert_eq!(valid_status(200), 200);
        assert_eq!(valid_status(599), 599);
        assert_eq!(valid_status(600), 403);
    }
}
