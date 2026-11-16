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

#![expect(
    clippy::unwrap_used,
    clippy::tests_outside_test_module,
    reason = "recommended configuration tests use fixed rules and bounded fixtures"
)]

//! The shipped `coraza.conf-recommended` fails closed on the engine's error flags.

use std::collections::BTreeSet;

use coraza::{
    Waf,
    seclang::{Parser, RECOMMENDED_CONF},
};

/// The rules the recommended configuration ships, in file order.
const RECOMMENDED_RULE_IDS: [i32; 8] = [200_000, 200_001, 200_006, 200_009, 200_002, 200_003, 200_004, 200_005];

/// A complete multipart body with one benign field.
const BENIGN_MULTIPART: &[u8] = b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nvalue\r\n--b--\r\n";

/// A part with an empty header block, then a SQL injection in the next field.
const EMPTY_HEADER_PART_THEN_SQLI: &[u8] = b"--b\r\n\r\nx\r\n--b\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n1' UNION SELECT password FROM users--\r\n--b--\r\n";

/// An XML body Go's decoder refuses to read.
const BAD_XML: &[u8] = b"<?xml version=\"1.1\"?><a/>";

/// The recommended configuration, with `extra` directives after it.
fn waf(extra: &str) -> Waf {
    let mut parser = Parser::new();
    parser.from_string(RECOMMENDED_CONF).unwrap();
    parser.from_string(extra).unwrap();
    assert!(parser.skipped().is_empty(), "skipped: {:?}", parser.skipped());
    parser.into_waf().unwrap()
}

/// The recommended configuration with blocking enabled, as a deployment loads it.
fn enforcing() -> Waf {
    waf("SecRuleEngine On")
}

/// The rule and status that interrupt one request, if any.
fn interruption(waf: &Waf, uri: &str, content_type: Option<&str>, body: &[u8]) -> Option<(i32, u16)> {
    let mut tx = waf.new_transaction();
    tx.process_uri(uri, "POST", "HTTP/1.1");
    tx.add_request_header("Host", "example.com");
    if let Some(content_type) = content_type {
        tx.add_request_header("Content-Type", content_type);
    }
    if let Some(interruption) = tx.process_request_headers() {
        return Some((interruption.rule_id, interruption.status));
    }
    tx.process_request_body(body)
        .map(|interruption| (interruption.rule_id, interruption.status))
}

/// `count` `name=value` pairs joined by `&`.
fn arguments(count: usize) -> String {
    (0..count)
        .map(|index| format!("a{index}=1"))
        .collect::<Vec<_>>()
        .join("&")
}

#[test]
fn the_recommended_configuration_ships_the_upstream_rules() {
    let ids: BTreeSet<i32> = RECOMMENDED_CONF
        .match_indices("\"id:'")
        .filter_map(|(start, marker)| {
            let digits = RECOMMENDED_CONF.get(start + marker.len()..)?;
            digits.get(..6)?.parse().ok()
        })
        .collect();
    assert_eq!(ids, RECOMMENDED_RULE_IDS.into_iter().collect::<BTreeSet<_>>());
    assert_eq!(enforcing().rule_count(), RECOMMENDED_RULE_IDS.len());
}

#[test]
fn body_processor_rules_select_json_and_xml() {
    let waf = enforcing();
    // Each malformed body only fails when 200000, 200001 or 200006 selected a
    // structured processor for its content type; 200002 then blocks it.
    for (content_type, body, expected) in [
        ("application/json", &b"{\"a\":"[..], Some((200_002, 400))),
        ("Application/JSON; charset=utf-8", b"{\"a\":", Some((200_002, 400))),
        ("application/problem+json", b"[1,", Some((200_002, 400))),
        // Go's decoder is lenient about unclosed elements, but rejects XML 1.1.
        ("application/xml", BAD_XML, Some((200_002, 400))),
        ("text/xml", BAD_XML, Some((200_002, 400))),
        ("application/soap+xml", BAD_XML, Some((200_002, 400))),
        ("application/json", b"{\"a\":1}", None),
        ("application/vnd.api+json", b"{\"a\":[1,2]}", None),
        ("text/xml", b"<a>1</a>", None),
        // RAW bodies are not parsed, so they cannot fail to parse.
        ("text/plain", b"{\"a\":", None),
    ] {
        assert_eq!(
            interruption(&waf, "/", Some(content_type), body),
            expected,
            "{content_type} {}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn multipart_parse_and_strict_errors_fail_closed() {
    let waf = enforcing();
    let multipart = Some("multipart/form-data; boundary=b");
    // No final delimiter: the body processor fails and 200002 blocks before 200003.
    assert_eq!(
        interruption(
            &waf,
            "/",
            multipart,
            b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nvalue"
        ),
        Some((200_002, 400))
    );
    // A repeated part header parses, but fails strict validation: only 200003 sees it.
    assert_eq!(
        interruption(
            &waf,
            "/",
            multipart,
            b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nvalue\r\n--b--\r\n"
        ),
        Some((200_003, 400))
    );
    assert_eq!(interruption(&waf, "/", multipart, BENIGN_MULTIPART), None);
    assert_eq!(
        interruption(&waf, "/", Some("application/x-www-form-urlencoded"), b"a=1&b=2"),
        None
    );
}

#[test]
fn an_empty_header_part_is_inspected_rather_than_failing() {
    // A part without headers is valid multipart: the baseline must not block it,
    // and the field after it must reach the rules that follow the baseline.
    let multipart = Some("multipart/form-data; boundary=b");
    assert_eq!(
        interruption(&enforcing(), "/", multipart, EMPTY_HEADER_PART_THEN_SQLI),
        None
    );
    let waf = waf("SecRuleEngine On\n\
         SecRule ARGS_POST \"@detectSQLi\" \"id:1,phase:2,deny,status:403\"");
    assert_eq!(
        interruption(&waf, "/", multipart, EMPTY_HEADER_PART_THEN_SQLI),
        Some((1, 403))
    );
}

#[test]
fn uri_parse_errors_and_argument_limits_fail_closed() {
    let waf = enforcing();
    assert_eq!(
        interruption(&waf, "http://example.com:bad/path?q=attack", None, b""),
        Some((200_009, 400))
    );
    assert_eq!(
        interruption(&waf, &format!("/?{}", arguments(1001)), None, b""),
        Some((200_004, 400))
    );
    assert_eq!(interruption(&waf, &format!("/?{}", arguments(1000)), None, b""), None);
    let form = Some("application/x-www-form-urlencoded");
    assert_eq!(
        interruption(&waf, "/", form, arguments(1001).as_bytes()),
        Some((200_005, 400))
    );
    assert_eq!(interruption(&waf, "/", form, arguments(1000).as_bytes()), None);
}

#[test]
fn the_recommended_configuration_starts_in_detection_only() {
    // Upstream ships `SecRuleEngine DetectionOnly`: the rules match and log, but a
    // deployment must turn blocking on after loading the file.
    let waf = waf("");
    let mut tx = waf.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1");
    tx.add_request_header("Content-Type", "application/json");
    assert!(tx.process_request_headers().is_none());
    assert!(tx.process_request_body(b"{\"a\":").is_none());
    assert!(
        tx.matched_rules().iter().any(|matched| matched.rule_id() == 200_002),
        "200002 still matches in DetectionOnly"
    );
}
