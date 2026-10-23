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

use std::sync::Arc;

use super::{Transaction, VariableCollection};
use crate::{
    config::WafConfig,
    operators::Outputs,
    rules::VariableSpec,
    types::{BodyLimitAction, RuleEngineStatus, RulePhase, RuleVariable},
};

#[test]
fn stores_and_matches_byte_arguments() {
    let mut tx = Transaction::new("tx-1");
    tx.add_get_argument("id", b"\xff");
    tx.add_path_argument("route", "admin");
    let spec = VariableSpec::new_string(RuleVariable::Args, "id".to_owned());
    tx.set_request_uri(b"/\xff");
    let uri_spec = VariableSpec::new(RuleVariable::RequestURI);

    assert_eq!(tx.id(), "tx-1");
    assert_eq!(
        tx.find_matches(&spec).first().map(|matched| matched.value.as_slice()),
        Some(&b"\xff"[..])
    );
    assert_eq!(
        tx.get_variable(RuleVariable::Args, Some("id")).as_deref(),
        Some("\u{fffd}")
    );
    assert_eq!(
        tx.find_matches(&uri_spec)
            .first()
            .map(|matched| matched.value.as_slice()),
        Some(&b"/\xff"[..])
    );
    assert_eq!(
        tx.get_variable(RuleVariable::RequestURI, None).as_deref(),
        Some("/\u{fffd}")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsCombinedSize, None).as_deref(),
        Some("3")
    );
}

#[test]
fn enforces_argument_limit_and_tracks_dropped_arguments() {
    let config = WafConfig {
        argument_limit: 1,
        ..WafConfig::default()
    };
    let mut tx = Transaction::with_config("tx-2", Arc::new(config));
    tx.add_get_argument("id", "1");
    tx.add_get_argument("dropped", "2");
    tx.add_post_argument("name", "a");

    assert!(tx.arguments_limit_reached());
    assert_eq!(tx.get_variable(RuleVariable::ArgsGet, Some("dropped")), None);
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("name")).as_deref(),
        Some("a")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsCombinedSize, None).as_deref(),
        Some("8")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgumentsLimitReached, None).as_deref(),
        Some("1")
    );
}

#[test]
fn operator_outputs_clear_stale_tx_capture_variables() {
    let mut tx = Transaction::new("tx-captures");
    for index in 0..10 {
        tx.set_tx_variable(&index.to_string(), b"stale");
    }
    let mut outputs = Outputs::new(true);
    outputs.capture(0, b"current");

    tx.store_operator_outputs(&mut outputs);

    assert_eq!(tx.get_variable(RuleVariable::TX, Some("0")).as_deref(), Some("current"));
    for index in 1..10 {
        assert_eq!(tx.get_variable(RuleVariable::TX, Some(&index.to_string())), None);
    }
}

#[test]
fn headers_are_case_insensitive_and_name_variables_select_keys() {
    let mut tx = Transaction::new("tx-3");
    tx.add_request_header("X-Trace", b"\xff");
    let spec = VariableSpec::new_string(RuleVariable::RequestHeaders, "x-trace".to_owned());
    let names_spec = VariableSpec::new_string(RuleVariable::RequestHeadersNames, "x-trace".to_owned());

    assert_eq!(
        tx.find_matches(&spec).first().map(|matched| matched.value.as_slice()),
        Some(&b"\xff"[..])
    );
    assert_eq!(
        tx.get_variable(RuleVariable::RequestHeadersNames, Some("x-trace"))
            .as_deref(),
        Some("X-Trace")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::RequestHeadersNames, Some("missing")),
        None
    );
    assert_eq!(
        tx.find_matches(&names_spec)
            .first()
            .map(|matched| matched.value.as_slice()),
        Some(&b"X-Trace"[..])
    );
    assert!(matches!(
        tx.collection(RuleVariable::RequestHeaders),
        Some(VariableCollection::Map(_))
    ));
    assert!(matches!(
        tx.collection(RuleVariable::RequestBody),
        Some(VariableCollection::Single(_))
    ));
    assert_eq!(
        tx.get_variable(RuleVariable::RequestBodyLength, None).as_deref(),
        Some("0")
    );
}

#[test]
fn urlencoded_body_populates_arguments_and_runs_phase_two_rules() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRequestBodyAccess On\n\
             SecRule ARGS_POST \"@contains attack\" \"id:30,phase:2,deny,status:403\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("urlencoded-body");
    tx.add_request_header("Content-Type", b"application/x-www-form-urlencoded; charset=UTF-8");
    tx.process_request_headers();

    let body = b"name=attack&bin=%FF&bad=%G0&empty";
    let interruption = tx.process_request_body(body).unwrap();

    assert_eq!(interruption.rule_id, 30);
    assert_eq!(interruption.status, 403);
    assert_eq!(tx.last_phase(), Some(RulePhase::RequestBody));
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
        Some("URLENCODED")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::RequestBody, None).as_deref(),
        Some("name=attack&bin=%FF&bad=%G0&empty")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::RequestBodyLength, None),
        Some(body.len().to_string())
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("name")).as_deref(),
        Some("attack")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("empty")).as_deref(),
        Some("")
    );

    let binary = VariableSpec::new_string(RuleVariable::ArgsPost, "bin".to_owned());
    assert_eq!(
        tx.find_matches(&binary).first().map(|matched| matched.value.as_slice()),
        Some(&b"\xff"[..])
    );
    let invalid_escape = VariableSpec::new_string(RuleVariable::ArgsPost, "bad".to_owned());
    assert_eq!(
        tx.find_matches(&invalid_escape)
            .first()
            .map(|matched| matched.value.as_slice()),
        Some(&b"%G0"[..])
    );
}

#[test]
fn multipart_body_populates_fields_metadata_and_temporary_uploads() {
    let upload_dir = tempfile::tempdir().unwrap();
    let mut parser = crate::seclang::Parser::new();
    let rules = format!(
        "SecRequestBodyAccess On\nSecUploadDir {}\nSecRule ARGS_POST \"@contains hello\" \"id:77,phase:2,deny,status:403\"",
        upload_dir.path().display()
    );
    parser.from_string(&rules).unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("multipart-body");
    tx.add_request_header("Content-Type", b"multipart/form-data; boundary=boundary");
    tx.process_request_headers();

    let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"message\"\r\n\
\r\n\
hello\r\n\
--boundary\r\n\
Content-Disposition: form-data; name=\"upload\"; filename=\"legacy.txt\"; filename*=UTF-8'en'payload.txt\r\n\
Content-Type: application/octet-stream\r\n\
\r\n\
payload\r\n\
--boundary--";
    assert_eq!(tx.process_request_body(body).unwrap().rule_id, 77);

    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
        Some("MULTIPART")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("message")).as_deref(),
        Some("hello")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::Files, Some("")).as_deref(),
        Some("payload.txt")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::FilesNames, Some("")).as_deref(),
        Some("upload")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::FilesSizes, Some("payload.txt"))
            .as_deref(),
        Some("7")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::FilesSizes, Some("legacy.txt")).as_deref(),
        Some("7")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartFilenameCharset, Some("upload"))
            .as_deref(),
        Some("UTF-8")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartFilenameLanguage, Some("upload"))
            .as_deref(),
        Some("en")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartName, Some("message")).as_deref(),
        Some("message")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartPartHeaders, Some("upload"))
            .as_deref(),
        Some(
            "Content-Disposition: form-data; name=\"upload\"; filename=\"legacy.txt\"; filename*=UTF-8'en'payload.txt"
        )
    );
    assert_eq!(
        tx.get_variable(RuleVariable::FilesCombinedSize, None).as_deref(),
        Some("12")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartStrictError, None).as_deref(),
        Some("0")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartDuplicatePartHeader, None)
            .as_deref(),
        Some("0")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartInvalidQuoting, None).as_deref(),
        Some("0")
    );

    let path = tx.get_variable(RuleVariable::FilesTmpNames, Some("")).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"payload");
    assert!(std::path::Path::new(&path).exists());
    drop(tx);
    assert!(!std::path::Path::new(&path).exists());
}

#[test]
fn multipart_upload_limit_skips_extra_files_and_continues_fields() {
    let upload_dir = tempfile::tempdir().unwrap();
    let config = WafConfig {
        request_body_access: true,
        upload_dir: upload_dir.path().to_string_lossy().into_owned(),
        upload_file_limit: 1,
        ..WafConfig::default()
    };
    let mut tx = Transaction::with_config("multipart-upload-limit", Arc::new(config));
    tx.add_request_header("Content-Type", b"multipart/form-data; boundary=boundary");
    tx.process_request_headers();

    let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"first\"; filename=\"first.txt\"\r\n\
\r\n\
first\r\n\
--boundary\r\n\
Content-Disposition: form-data; name=\"second\"; filename=\"second.txt\"\r\n\
\r\n\
second\r\n\
--boundary\r\n\
Content-Disposition: form-data; name=\"after\"\r\n\
\r\n\
field value\r\n\
--boundary--";
    assert_eq!(tx.process_request_body(body), None);

    let files = tx.find_matches(&VariableSpec::new_string(RuleVariable::Files, String::new()));
    assert_eq!(files.len(), 1);
    assert_eq!(
        files.first().map(|matched| matched.value.as_slice()),
        Some(&b"first.txt"[..])
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("after")).as_deref(),
        Some("field value")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartStrictError, None).as_deref(),
        Some("1")
    );
}

#[test]
fn malformed_multipart_sets_processor_and_strict_errors() {
    let config = WafConfig {
        request_body_access: true,
        ..WafConfig::default()
    };
    let mut tx = Transaction::with_config("malformed-multipart", Arc::new(config));
    tx.add_request_header("Content-Type", b"multipart/form-data; boundary=boundary");
    tx.process_request_headers();

    let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"field\"\r\n\
\r\n\
value";
    assert_eq!(tx.process_request_body(body), None);
    assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("1"));
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessorError, None).as_deref(),
        Some("1")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartStrictError, None).as_deref(),
        Some("1")
    );
}

#[test]
fn multipart_upload_keep_files_preserves_files_after_transaction_drop() {
    let upload_dir = tempfile::tempdir().unwrap();
    let config = WafConfig {
        request_body_access: true,
        upload_dir: upload_dir.path().to_string_lossy().into_owned(),
        upload_keep_files: true,
        ..WafConfig::default()
    };
    let mut tx = Transaction::with_config("kept-multipart-upload", Arc::new(config));
    tx.add_request_header("Content-Type", b"multipart/form-data; boundary=boundary");
    tx.process_request_headers();
    let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"upload\"; filename=\"file.txt\"\r\n\
\r\n\
payload\r\n\
--boundary--";
    assert_eq!(tx.process_request_body(body), None);

    let path = tx.get_variable(RuleVariable::FilesTmpNames, Some("")).unwrap();
    drop(tx);
    assert!(std::path::Path::new(&path).exists());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn raw_body_is_selected_by_ctl_and_matches_original_bytes() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRequestBodyAccess On\n\
             SecAction \"id:31,phase:1,ctl:requestBodyProcessor=RAW,pass\"\n\
             SecRule REQUEST_BODY \"@contains attack\" \"id:32,phase:2,deny,status:403\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("raw-body");
    tx.add_request_header("Content-Type", b"text/plain");
    tx.process_request_headers();

    let body = b"xx\xffattack";
    assert_eq!(tx.process_request_body(body).unwrap().rule_id, 32);

    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
        Some("RAW")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::RequestBodyLength, None).as_deref(),
        Some("9")
    );
    assert_eq!(
        tx.find_matches(&VariableSpec::new(RuleVariable::RequestBody))
            .first()
            .map(|matched| matched.value.as_slice()),
        Some(&body[..])
    );
}

#[test]
fn request_body_limit_rejects_at_the_limit_and_processes_partial_bodies() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRequestBodyAccess On\n\
             SecAction \"id:33,phase:1,ctl:requestBodyLimit=4,ctl:requestBodyProcessor=RAW,pass\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("body-limit-reject");
    tx.process_request_headers();
    assert_eq!(tx.request_body_limit(), 4);

    let interruption = tx.process_request_body(b"body").unwrap();

    assert_eq!(interruption.rule_id, 0);
    assert_eq!(interruption.action, "deny");
    assert_eq!(interruption.status, 413);
    assert_eq!(
        tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
        Some("1")
    );
    assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some(""));

    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRequestBodyAccess On\n\
             SecRequestBodyLimit 4\n\
             SecRequestBodyLimitAction ProcessPartial\n\
             SecAction \"id:34,phase:1,ctl:requestBodyProcessor=RAW,pass\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("body-limit-partial");
    tx.process_request_headers();

    assert_eq!(tx.process_request_body(b"attack"), None);
    assert_eq!(
        tx.get_variable(RuleVariable::RequestBody, None).as_deref(),
        Some("atta")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::RequestBodyLength, None).as_deref(),
        Some("4")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
        Some("1")
    );
}

#[test]
fn detection_only_records_body_limit_rejection_and_processes_partial_body() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRuleEngine DetectionOnly\n\
             SecRequestBodyAccess On\n\
             SecRequestBodyLimit 4\n\
             SecAction \"id:39,phase:1,ctl:requestBodyProcessor=RAW,pass\"\n\
             SecRule REQUEST_BODY \"@contains atta\" \"id:40,phase:2,setvar:TX.body=+1,pass\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("detect-only-body-limit");
    tx.process_request_headers();

    assert_eq!(tx.process_request_body(b"attack"), None);
    assert!(tx.interruption().is_none());
    let would_be = tx.would_be_interruption().unwrap();
    assert_eq!(would_be.rule_id, 0);
    assert_eq!(would_be.action, "deny");
    assert_eq!(would_be.status, 413);
    assert_eq!(
        tx.get_variable(RuleVariable::RequestBody, None).as_deref(),
        Some("atta")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::RequestBodyLength, None).as_deref(),
        Some("4")
    );
    assert_eq!(tx.get_variable(RuleVariable::TX, Some("body")).as_deref(), Some("1"));
}

#[test]
fn request_body_phase_runs_without_body_access_and_only_once_after_headers() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRequestBodyAccess Off\n\
             SecAction \"id:35,phase:2,setvar:TX.body=+1,pass\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("body-phase-order");
    tx.add_get_argument("q", "attack");

    assert_eq!(tx.process_request_body(b"ignored=value"), None);
    assert_eq!(tx.last_phase(), None);
    tx.process_request_headers();
    assert_eq!(tx.process_request_body(b""), None);
    assert_eq!(tx.last_phase(), Some(RulePhase::RequestBody));
    assert_eq!(tx.process_request_body(b"again=value"), None);

    assert_eq!(tx.get_variable(RuleVariable::TX, Some("body")).as_deref(), Some("1"));
    assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("ignored")), None);
    assert_eq!(
        tx.get_variable(RuleVariable::RequestBodyLength, None).as_deref(),
        Some("0")
    );
}

#[test]
fn ctl_can_enable_body_access_and_force_urlencoded_processing() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRequestBodyAccess Off\n\
             SecAction \"id:36,phase:1,ctl:requestBodyAccess=On,ctl:forceRequestBodyVariable=On,pass\"\n\
             SecRule ARGS_POST \"@contains attack\" \"id:37,phase:2,deny\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("body-access-ctl");
    tx.process_request_headers();

    assert_eq!(tx.process_request_body(b"q=attack").unwrap().rule_id, 37);
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
        Some("URLENCODED")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("q")).as_deref(),
        Some("attack")
    );
}

#[test]
fn force_body_variable_does_not_override_an_explicit_json_processor() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRequestBodyAccess On\n\
             SecAction \"id:38,phase:1,ctl:forceRequestBodyVariable=On,ctl:requestBodyProcessor=JSON,pass\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("explicit-json-processor");
    tx.process_request_headers();

    assert_eq!(tx.process_request_body(br#"{"q":"attack"}"#), None);
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
        Some("JSON")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("json.q")).as_deref(),
        Some("attack")
    );
    assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some(""));
}

#[test]
fn json_body_populates_flattened_post_arguments_and_runs_phase_two_rules() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRequestBodyAccess On\n\
             SecAction \"id:41,phase:1,ctl:requestBodyProcessor=JSON,pass\"\n\
             SecRule ARGS_POST \"@contains admin\" \"id:42,phase:2,deny,status:403\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("json-body");
    tx.process_request_headers();

    let body = br#"{"user":{"name":"admin","enabled":true},"ids":[10,20],"nothing":null}"#;
    let interruption = tx.process_request_body(body).unwrap();

    assert_eq!(interruption.rule_id, 42);
    assert_eq!(interruption.status, 403);
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
        Some("JSON")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("json.user.name"))
            .as_deref(),
        Some("admin")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("json.user.enabled"))
            .as_deref(),
        Some("true")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("json.ids")).as_deref(),
        Some("2")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("json.ids.0")).as_deref(),
        Some("10")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("json.nothing")).as_deref(),
        Some("")
    );
    assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some(""));
    assert_eq!(
        tx.get_variable(RuleVariable::RequestBodyLength, None).as_deref(),
        Some("0")
    );
}

#[test]
fn json_body_errors_are_exposed_and_phase_two_still_runs() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRequestBodyAccess On\n\
             SecRequestBodyJsonDepthLimit 1\n\
             SecAction \"id:43,phase:1,ctl:requestBodyProcessor=JSON,pass\"\n\
             SecRule REQBODY_ERROR \"@eq 1\" \"id:44,phase:2,setvar:TX.error_seen=+1,pass\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();

    for (id, body, expected_error) in [
        ("invalid-json", b"{invalid}".as_slice(), "JSON:"),
        (
            "deep-json",
            br#"{"a":{"b":1}}"#.as_slice(),
            "JSON: nesting deeper than the limit of 1",
        ),
    ] {
        let mut tx = waf.new_transaction_with_id(id);
        tx.process_request_headers();

        assert_eq!(tx.process_request_body(body), None);
        assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("1"));
        assert!(
            tx.get_variable(RuleVariable::ReqbodyErrorMsg, None)
                .is_some_and(|message| message.starts_with(expected_error))
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessorError, None).as_deref(),
            Some("1")
        );
        assert!(
            tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None)
                .is_some_and(|message| !message.is_empty())
        );
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("error_seen")).as_deref(),
            Some("1")
        );
        assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("json.a")), None);
    }
}

#[test]
fn xml_body_populates_request_xml_and_runs_phase_two_rules() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRequestBodyAccess On\n\
             SecAction \"id:45,phase:1,ctl:requestBodyProcessor=XML,pass\"\n\
             SecRule XML:/* \"@contains superuser\" \"id:46,phase:2,deny,status:403\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("xml-body");
    tx.process_request_headers();

    let body = br#"<user name="admin"><role>superuser &amp; guest</role></user>"#;
    let interruption = tx.process_request_body(body).unwrap();

    assert_eq!(interruption.rule_id, 46);
    assert_eq!(interruption.status, 403);
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
        Some("XML")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::RequestXML, Some("//@*")).as_deref(),
        Some("admin")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::XML, Some("/*")).as_deref(),
        Some("superuser & guest")
    );
    assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some(""));
}

#[test]
fn xml_truncated_body_keeps_values_parsed_before_eof() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRequestBodyAccess On\n\
             SecAction \"id:49,phase:1,ctl:requestBodyProcessor=XML,pass\"\n\
             SecRule XML:/* \"@contains partial\" \"id:50,phase:2,deny\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("truncated-xml");
    tx.process_request_headers();

    assert_eq!(tx.process_request_body(b"<root><item>partial").unwrap().rule_id, 50);
    assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("0"));
    assert_eq!(
        tx.get_variable(RuleVariable::XML, Some("/*")).as_deref(),
        Some("partial")
    );
}

#[test]
fn xml_body_errors_are_exposed_and_phase_two_still_runs() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRequestBodyAccess On\n\
             SecAction \"id:47,phase:1,ctl:requestBodyProcessor=XML,pass\"\n\
             SecRule REQBODY_ERROR \"@eq 1\" \"id:48,phase:2,setvar:TX.xml_error=+1,pass\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("invalid-xml");
    tx.process_request_headers();

    assert_eq!(tx.process_request_body(b"<root><1bad>secret</1bad></root>"), None);
    assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("1"));
    assert!(
        tx.get_variable(RuleVariable::ReqbodyErrorMsg, None)
            .is_some_and(|message| message.starts_with("XML: malformed xml:"))
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessorError, None).as_deref(),
        Some("1")
    );
    assert!(
        tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None)
            .is_some_and(|message| message.starts_with("malformed xml:"))
    );
    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("xml_error")).as_deref(),
        Some("1")
    );
    assert_eq!(tx.get_variable(RuleVariable::RequestXML, Some("/*")), None);
}

#[test]
fn xml_content_type_does_not_select_the_processor_automatically() {
    let mut parser = crate::seclang::Parser::new();
    parser.from_string("SecRequestBodyAccess On").unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("xml-content-type");
    tx.add_request_header("Content-Type", b"application/xml");
    tx.process_request_headers();

    assert_eq!(tx.process_request_body(b"<root>text</root>"), None);
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
        Some("")
    );
    assert_eq!(tx.get_variable(RuleVariable::RequestXML, Some("/*")), None);
}

#[test]
fn only_the_first_content_type_selects_a_body_processor() {
    let mut parser = crate::seclang::Parser::new();
    parser.from_string("SecRequestBodyAccess On").unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("first-content-type");
    tx.add_request_header("Content-Type", b"application/json");
    tx.add_request_header("content-type", b"application/x-www-form-urlencoded");
    tx.process_request_headers();

    assert_eq!(tx.process_request_body(b"key=value"), None);
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
        Some("")
    );
    assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("key")), None);
    assert_eq!(tx.get_variable(RuleVariable::RequestBody, None).as_deref(), Some(""));
}

#[test]
fn evaluates_request_header_rules_from_a_compiled_waf() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string("SecRule ARGS \"@contains attack\" \"id:10,phase:1,deny,status:403\"")
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("blocked");
    tx.add_get_argument("q", b"an attack");

    let interruption = tx.process_request_headers().unwrap();

    assert_eq!(interruption.rule_id, 10);
    assert_eq!(interruption.action, "deny");
    assert_eq!(interruption.status, 403);
    assert_eq!(tx.last_phase(), Some(RulePhase::RequestHeaders));
    assert_eq!(tx.process_request_headers(), Some(interruption));
}

#[test]
fn detection_only_records_a_would_be_interruption() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string("SecRuleEngine DetectionOnly\nSecRule ARGS \"@contains attack\" \"id:11,phase:1,deny\"")
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("detect-only");
    tx.add_get_argument("q", b"attack");

    assert_eq!(tx.process_request_headers(), None);
    assert!(tx.interruption().is_none());
    let would_be = tx.would_be_interruption().unwrap();
    assert_eq!(would_be.rule_id, 11);
    assert_eq!(would_be.status, 403);
}

#[test]
fn response_phases_parse_json_and_evaluate_response_rules() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecResponseBodyAccess On\n\
             SecResponseBodyMimeType application/json\n\
             SecAction \"id:70,phase:3,ctl:responseBodyProcessor=JSON,pass\"\n\
             SecRule RESPONSE_STATUS \"@streq 200\" \"id:71,phase:3,pass,setvar:TX.response_status=seen\"\n\
             SecRule RESPONSE_ARGS:json.admin \"@streq true\" \"id:72,phase:4,deny,status:403\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("response-json");
    tx.process_request_headers();
    tx.process_request_body(b"");
    tx.add_response_header("Content-Type", "application/json; charset=utf-8");

    assert_eq!(tx.process_response_headers(200, "HTTP/1.1"), None);
    assert_eq!(tx.last_phase(), Some(RulePhase::ResponseHeaders));
    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("response_status")).as_deref(),
        Some("seen")
    );
    assert!(tx.is_response_body_processable());
    assert!(tx.response_body_access());

    let interruption = tx.process_response_body(br#"{"admin":true}"#).unwrap();
    assert_eq!(interruption.rule_id, 72);
    assert_eq!(interruption.status, 403);
    assert_eq!(tx.last_phase(), Some(RulePhase::ResponseBody));
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseArgs, Some("json.admin"))
            .as_deref(),
        Some("true")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseBody, None).as_deref(),
        Some(r#"{"admin":true}"#)
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseContentLength, None).as_deref(),
        Some("14")
    );
}

#[test]
fn response_raw_processor_populates_response_body() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecResponseBodyAccess On\n\
             SecResponseBodyMimeType text/plain\n\
             SecAction \"id:73,phase:3,ctl:responseBodyProcessor=RAW,pass\"\n\
             SecRule RESPONSE_BODY \"@contains attack\" \"id:74,phase:4,deny\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("response-raw");
    tx.process_request_headers();
    tx.process_request_body(b"");
    tx.add_response_header("Content-Type", "text/plain");
    tx.process_response_headers(200, "HTTP/1.1");

    assert_eq!(tx.process_response_body(b"attack").unwrap().rule_id, 74);
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseBody, None).as_deref(),
        Some("attack")
    );
}

#[test]
fn response_body_mime_uses_the_first_content_type_header() {
    let config = WafConfig {
        response_body_access: true,
        response_body_mime_types: vec!["text/plain".to_owned()],
        ..WafConfig::default()
    };
    let mut tx = Transaction::with_config("response-content-type", Arc::new(config));
    tx.process_request_headers();
    tx.process_request_body(b"");
    tx.add_response_header("Content-Type", "application/json");
    tx.add_response_header("content-type", "text/plain");
    tx.process_response_headers(200, "HTTP/1.1");

    assert!(!tx.is_response_body_processable());
    tx.process_response_body(b"body");
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseContentLength, None).as_deref(),
        Some("")
    );
}

#[test]
fn response_body_limit_reject_records_detection_only_and_processes_partial_body() {
    let config = WafConfig {
        rule_engine: RuleEngineStatus::DetectionOnly,
        response_body_access: true,
        response_body_limit: 3,
        response_body_limit_action: BodyLimitAction::Reject,
        response_body_mime_types: vec!["text/plain".to_owned()],
        ..WafConfig::default()
    };
    let mut tx = Transaction::with_config("response-limit-detection-only", Arc::new(config));
    tx.process_request_headers();
    tx.process_request_body(b"");
    tx.add_response_header("Content-Type", "text/plain");
    tx.process_response_headers(200, "HTTP/1.1");

    assert_eq!(tx.process_response_body(b"attack"), None);
    assert_eq!(
        tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
        Some("1")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseBody, None).as_deref(),
        Some("att")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseContentLength, None).as_deref(),
        Some("6")
    );
    assert_eq!(tx.would_be_interruption().map(|item| item.status), Some(500));

    let config = WafConfig {
        rule_engine: RuleEngineStatus::On,
        response_body_access: true,
        response_body_limit: 3,
        response_body_limit_action: BodyLimitAction::Reject,
        response_body_mime_types: vec!["text/plain".to_owned()],
        ..WafConfig::default()
    };
    let mut tx = Transaction::with_config("response-limit-reject", Arc::new(config));
    tx.process_request_headers();
    tx.process_request_body(b"");
    tx.add_response_header("Content-Type", "text/plain");
    tx.process_response_headers(200, "HTTP/1.1");

    assert_eq!(tx.process_response_body(b"attack").map(|item| item.status), Some(500));
    assert_eq!(tx.get_variable(RuleVariable::ResponseBody, None).as_deref(), Some(""));
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseContentLength, None).as_deref(),
        Some("6")
    );
}

#[test]
fn response_body_equal_to_limit_is_not_rejected() {
    let config = WafConfig {
        response_body_access: true,
        response_body_limit: 3,
        response_body_limit_action: BodyLimitAction::Reject,
        response_body_mime_types: vec!["text/plain".to_owned()],
        ..WafConfig::default()
    };
    let mut tx = Transaction::with_config("response-limit-equal", Arc::new(config));
    tx.process_request_headers();
    tx.process_request_body(b"");
    tx.add_response_header("Content-Type", "text/plain");
    tx.process_response_headers(200, "HTTP/1.1");

    assert_eq!(tx.process_response_body(b"abc"), None);
    assert_eq!(
        tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
        Some("0")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseBody, None).as_deref(),
        Some("abc")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseContentLength, None).as_deref(),
        Some("3")
    );
}

#[test]
fn empty_response_body_bypasses_zero_body_limit() {
    let config = WafConfig {
        response_body_access: true,
        response_body_limit: 0,
        response_body_limit_action: BodyLimitAction::Reject,
        response_body_mime_types: vec!["text/plain".to_owned()],
        ..WafConfig::default()
    };
    let mut tx = Transaction::with_config("empty-response-limit", Arc::new(config));
    tx.process_request_headers();
    tx.process_request_body(b"");
    tx.add_response_header("Content-Type", "text/plain");
    tx.process_response_headers(200, "HTTP/1.1");

    assert_eq!(tx.process_response_body(b""), None);
    assert_eq!(
        tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
        Some("0")
    );
    assert_eq!(tx.would_be_interruption(), None);
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseContentLength, None).as_deref(),
        Some("0")
    );
}

#[test]
fn ctl_rule_target_removal_only_changes_the_selected_transaction() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecAction \"id:80,phase:1,ctl:ruleRemoveTargetById=81;ARGS:/^USER$/,pass\"\n\
             SecRule ARGS \"@contains bad\" \"id:81,phase:1,deny\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();

    let mut excluded = waf.new_transaction_with_id("target-excluded");
    excluded.add_get_argument("user", "bad");
    excluded.process_request_headers();
    assert_eq!(excluded.interruption(), None);

    let mut other_key = waf.new_transaction_with_id("target-other-key");
    other_key.add_get_argument("user", "good");
    other_key.add_get_argument("query", "bad");
    let interruption = other_key.process_request_headers().unwrap();
    assert_eq!(interruption.rule_id, 81);
}

#[test]
fn ctl_rule_target_removal_by_tag_and_message_skips_matching_keys() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecAction \"id:86,phase:1,ctl:ruleRemoveTargetByTag=removed-tag;ARGS:tagged,ctl:ruleRemoveTargetByMsg=removed message;ARGS:message,pass\"\n\
             SecRule ARGS:tagged \"@contains bad\" \"id:87,phase:1,tag:removed-tag,deny\"\n\
             SecRule ARGS:message \"@contains bad\" \"id:88,phase:1,msg:removed message,deny\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("target-tag-message");
    tx.add_get_argument("tagged", "bad");
    tx.add_get_argument("message", "bad");

    assert_eq!(tx.process_request_headers(), None);
}

#[test]
fn response_body_controls_enable_forcing_and_limit_processing() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecResponseBodyAccess Off\n\
             SecAction \"id:84,phase:3,ctl:responseBodyAccess=On,ctl:forceResponseBodyVariable=On,ctl:responseBodyLimit=3,pass\"\n\
             SecRule RESPONSE_BODY \"@contains sec\" \"id:85,phase:4,deny\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("response-controls");
    tx.process_request_headers();
    tx.process_request_body(b"");
    tx.add_response_header("Content-Type", "text/plain");
    tx.process_response_headers(200, "HTTP/1.1");

    assert!(tx.response_body_access());
    assert!(tx.is_response_body_processable());
    assert_eq!(tx.process_response_body(b"secret").unwrap().rule_id, 85);
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseBody, None).as_deref(),
        Some("sec")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::OutboundDataError, None).as_deref(),
        Some("1")
    );
}

#[test]
fn response_body_requires_response_headers_and_runs_only_once() {
    let config = WafConfig {
        response_body_access: true,
        response_body_mime_types: vec!["text/plain".to_owned()],
        ..WafConfig::default()
    };
    let mut tx = Transaction::with_config("response-order", Arc::new(config));
    tx.process_request_headers();
    tx.process_request_body(b"");
    tx.add_response_header("Content-Type", "text/plain");

    assert_eq!(tx.process_response_body(b"too early"), None);
    assert_eq!(tx.last_phase(), Some(RulePhase::RequestBody));
    tx.process_response_headers(200, "HTTP/1.1");
    assert_eq!(tx.process_response_body(b"first"), None);
    assert_eq!(tx.process_response_body(b"second"), None);
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseBody, None).as_deref(),
        Some("first")
    );
}

#[test]
fn malformed_response_json_sets_processor_error_variables() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecResponseBodyAccess On\n\
             SecResponseBodyMimeType application/json\n\
             SecAction \"id:89,phase:3,ctl:responseBodyProcessor=JSON,pass\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("response-json-error");
    tx.process_request_headers();
    tx.process_request_body(b"");
    tx.add_response_header("Content-Type", "application/json");
    tx.process_response_headers(200, "HTTP/1.1");

    assert_eq!(tx.process_response_body(b"not json"), None);
    assert_eq!(tx.get_variable(RuleVariable::ResBodyError, None).as_deref(), Some("1"));
    assert!(
        tx.get_variable(RuleVariable::ResBodyErrorMsg, None)
            .is_some_and(|message| message.starts_with("JSON: malformed json:"))
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ResBodyProcessorError, None).as_deref(),
        Some("1")
    );
    assert!(
        tx.get_variable(RuleVariable::ResBodyProcessorErrorMsg, None)
            .is_some_and(|message| !message.is_empty())
    );
}

#[test]
fn ctl_rule_removal_by_id_tag_and_message_skips_matching_rules() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecAction \"id:90,phase:1,ctl:ruleRemoveById=91,ctl:ruleRemoveByTag=disabled,ctl:ruleRemoveByMsg=disabled message,pass\"\n\
             SecAction \"id:91,phase:1,deny\"\n\
             SecAction \"id:92,phase:1,tag:disabled,deny\"\n\
             SecAction \"id:93,phase:1,msg:disabled message,deny\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("rule-removals");

    assert_eq!(tx.process_request_headers(), None);
}

#[test]
fn setenv_writes_macro_expanded_values_to_env_collection() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string("SecAction \"id:100,phase:1,setvar:TX.user=alice,setenv:request.user=%{TX.user},pass\"")
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("setenv");

    assert_eq!(tx.process_request_headers(), None);
    assert_eq!(
        tx.get_variable(RuleVariable::Env, Some("request.user")).as_deref(),
        Some("alice")
    );
}

#[test]
fn chained_rules_only_apply_disruptive_actions_when_every_link_matches() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRule ARGS \"@contains first\" \"id:12,phase:1,deny,chain\"\n\
             SecRule ARGS \"@contains second\" \"\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("chain");
    tx.add_get_argument("q", b"first only");

    assert_eq!(tx.process_request_headers(), None);

    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRule ARGS \"@contains first\" \"id:13,phase:1,deny,chain\"\n\
             SecRule ARGS \"@contains second\" \"\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("chain-match");
    tx.add_get_argument("q", b"first and second");

    assert_eq!(tx.process_request_headers().unwrap().rule_id, 13);
}

#[test]
fn setvar_updates_tx_during_rule_evaluation() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string("SecAction \"id:14,phase:1,setvar:TX.score=+5,pass\"")
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("setvar");
    tx.set_tx_variable("score", b"2");

    tx.process_request_headers();

    assert_eq!(tx.get_variable(RuleVariable::TX, Some("score")).as_deref(), Some("7"));
}

#[test]
fn match_variables_are_available_to_action_macros() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRule ARGS \"@contains attack\" \"id:19,phase:1,setvar:TX.value=%{MATCHED_VAR},setvar:TX.name=%{MATCHED_VAR_NAME},deny\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("matched-vars");
    tx.add_get_argument("q", b"an attack");

    tx.process_request_headers();

    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("value")).as_deref(),
        Some("an attack")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("name")).as_deref(),
        Some("ARGS:q")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MatchedVar, None).as_deref(),
        Some("an attack")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MatchedVars, Some("ARGS:q")).as_deref(),
        Some("an attack")
    );
}

#[test]
fn rule_variables_describe_the_rule_being_evaluated() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecAction \"id:21,phase:1,rev:3,severity:WARNING,msg:'blocked',logdata:'data',setvar:TX.rule=%{RULE.id}/%{RULE.msg}/%{RULE.rev}/%{RULE.severity}/%{RULE.logdata},pass\"\n\\
             SecAction \"id:22,phase:1,setvar:TX.previous=%{RULE.msg}/%{RULE.logdata},pass\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("rule-vars");

    tx.process_request_headers();

    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("rule")).as_deref(),
        Some("21/blocked/3/warning/data")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("previous")).as_deref(),
        Some("blocked/data")
    );
}

#[test]
fn captures_are_stored_even_when_negation_makes_the_rule_miss() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string("SecRule ARGS \"!@rx (attack)\" \"id:20,phase:1,capture,pass\"")
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("negated-capture");
    tx.add_get_argument("q", b"attack");

    assert_eq!(tx.process_request_headers(), None);
    assert_eq!(tx.get_variable(RuleVariable::TX, Some("1")).as_deref(), Some("attack"));
}

#[test]
fn captures_survive_chain_links_without_captures() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRule ARGS \"@rx (attack)\" \"id:24,phase:1,capture,chain,pass\"\n\\
             SecRule ARGS \"@streq attack\" \"setvar:TX.saved=%{TX.1},pass\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("chain-captures");
    tx.add_get_argument("q", b"attack");

    tx.process_request_headers();

    assert_eq!(tx.get_variable(RuleVariable::TX, Some("1")).as_deref(), Some("attack"));
    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("saved")).as_deref(),
        Some("attack")
    );
}

#[test]
fn transformations_run_before_operator_matching() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string("SecRule ARGS \"@streq admin\" \"id:15,phase:1,t:lowercase,deny\"")
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("transformed");
    tx.add_get_argument("user", b"ADMIN");

    assert_eq!(tx.process_request_headers().unwrap().rule_id, 15);
}

#[test]
fn block_uses_phase_defaults_and_is_inert_without_them() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string("SecRule ARGS \"@contains attack\" \"id:16,phase:1,block\"")
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("block-without-default");
    tx.add_get_argument("q", b"attack");

    assert_eq!(tx.process_request_headers(), None);

    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecDefaultAction \"phase:1,deny\"\n\
             SecRule ARGS \"@contains attack\" \"id:17,phase:1,block\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("block-with-default");
    tx.add_get_argument("q", b"attack");

    assert_eq!(tx.process_request_headers().unwrap().rule_id, 17);
}

#[test]
fn skip_after_skips_through_and_including_its_marker() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecAction \"id:16,phase:1,skipAfter:END,pass\"\n\
             SecAction \"id:17,phase:1,deny\"\n\
             SecMarker END\n\
             SecAction \"id:18,phase:1,deny\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("skip-after");

    assert_eq!(tx.process_request_headers().unwrap().rule_id, 18);
}

#[test]
fn audit_logging_records_matches_and_request_response_data_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.json");
    let callback_lines = Arc::new(std::sync::Mutex::new(Vec::new()));
    let callback_output = Arc::clone(&callback_lines);
    let mut parser = crate::seclang::Parser::new();
    *parser.config_mut() = WafConfig {
        audit_engine: crate::types::AuditEngineStatus::On,
        audit_log: path.to_string_lossy().into_owned(),
        audit_log_format: crate::types::AuditLogFormat::Json,
        audit_log_parts: crate::types::parse_audit_log_parts("ABCFGHKZ").unwrap(),
        request_body_access: true,
        ..WafConfig::default()
    };
    parser.on_error_log(move |matched| {
        callback_output.lock().unwrap().push(matched.error_log());
    });
    parser
        .from_string(
            "SecRule ARGS \"@contains attack\" \"id:71,phase:1,log,msg:'found %{MATCHED_VAR}',logdata:'value %{MATCHED_VAR}',severity:WARNING\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("audit-1");
    tx.process_uri("/?q=attack#fragment", "GET", "HTTP/1.1");
    tx.set_remote_addr("192.0.2.1");
    tx.set_remote_port(1234);
    assert_eq!(tx.process_request_headers(), None);
    tx.add_request_header("Content-Type", "text/plain");
    tx.process_request_body(b"request-body");
    tx.add_response_header("Content-Type", "text/plain");
    tx.process_response_headers(200, "HTTP/1.1");
    tx.process_response_body(b"response-body");
    tx.process_logging().unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    let entry: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
    assert_eq!(
        entry.pointer("/transaction/id").and_then(serde_json::Value::as_str),
        Some("audit-1")
    );
    assert_eq!(
        entry
            .pointer("/transaction/request/uri")
            .and_then(serde_json::Value::as_str),
        Some("/?q=attack")
    );
    assert_eq!(
        entry
            .pointer("/transaction/request/body")
            .and_then(serde_json::Value::as_str),
        Some("request-body")
    );
    assert_eq!(
        entry
            .pointer("/transaction/response/body")
            .and_then(serde_json::Value::as_str),
        Some("response-body")
    );
    assert_eq!(
        entry.pointer("/messages/0/data/id").and_then(serde_json::Value::as_i64),
        Some(71)
    );
    assert_eq!(
        entry.pointer("/messages/0/message").and_then(serde_json::Value::as_str),
        Some("found attack")
    );
    assert_eq!(callback_lines.lock().unwrap().len(), 1);

    drop(tx);
    assert_eq!(std::fs::read_to_string(path).unwrap().lines().count(), 1);
}

#[test]
fn relevant_only_audits_matches_when_the_transaction_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut parser = crate::seclang::Parser::new();
    *parser.config_mut() = WafConfig {
        audit_engine: crate::types::AuditEngineStatus::RelevantOnly,
        audit_log: path.to_string_lossy().into_owned(),
        audit_log_parts: crate::types::parse_audit_log_parts("ABFHKZ").unwrap(),
        ..WafConfig::default()
    };
    parser
        .from_string("SecRule ARGS:q \"@streq evil\" \"id:81,phase:1,deny,status:403,log,auditlog,msg:'Evil'\"")
        .unwrap();
    let waf = parser.into_waf().unwrap();

    let mut benign = waf.new_transaction_with_id("tx-benign");
    benign.process_uri("/?q=fine", "GET", "HTTP/1.1");
    drop(benign.process_request_headers());
    drop(benign);

    let mut matched = waf.new_transaction_with_id("tx-evil");
    matched.process_uri("/?q=evil", "GET", "HTTP/1.1");
    assert_eq!(matched.process_request_headers().map(|item| item.rule_id), Some(81));
    drop(matched);

    let log = std::fs::read_to_string(path).unwrap();
    assert!(!log.contains("tx-benign"), "{log}");
    assert!(log.contains("tx-evil"), "{log}");
    assert!(log.contains("[id \"81\"]"), "{log}");
}

#[test]
fn logging_phase_runs_after_a_disruptive_request_match() {
    let mut parser = crate::seclang::Parser::new();
    parser
        .from_string(
            "SecRule ARGS \"@contains attack\" \"id:72,phase:1,deny\"\n\
             SecRule ARGS \"@contains attack\" \"id:73,phase:5,setvar:TX.logged=yes,pass\"",
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("logging-after-deny");
    tx.add_get_argument("q", "attack");

    assert_eq!(tx.process_request_headers().unwrap().rule_id, 72);
    tx.process_logging().unwrap();

    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("logged")).as_deref(),
        Some("yes")
    );
}

#[test]
fn process_uri_populates_decoded_query_arguments_without_the_fragment() {
    let mut tx = Transaction::new("process-uri");
    tx.process_uri("/search?q=hello+world&encoded=%ff#section", "GET", "HTTP/1.1");

    assert_eq!(
        tx.get_variable(RuleVariable::RequestURI, None).as_deref(),
        Some("/search?q=hello+world&encoded=%ff")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsGet, Some("q")).as_deref(),
        Some("hello world")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsGet, Some("encoded")).as_deref(),
        Some("\u{fffd}")
    );
    assert_eq!(tx.get_variable(RuleVariable::RemotePort, None), Some(String::new()));
}
