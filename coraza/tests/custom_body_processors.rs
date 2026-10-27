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
    reason = "custom body processor tests use fixed rules and bounded fixtures"
)]

//! End-to-end tests for parser-registered body processors.

use std::{fs, sync::Arc};

use coraza::{
    BodyDirection, BodyProcessor, BodyProcessorOptions, BodyProcessorOutput, RuleVariable, seclang::Parser,
    transaction::Transaction,
};

struct JsonLines;

impl BodyProcessor for JsonLines {
    fn process(
        &self,
        body: &[u8],
        _direction: BodyDirection,
        options: &BodyProcessorOptions<'_>,
        out: &mut BodyProcessorOutput,
    ) -> Result<(), String> {
        if options.argument_limit == 0 {
            return Err("argument limit was not resolved".to_owned());
        }
        for line in body.split(|&byte| byte == b'\n').filter(|line| !line.is_empty()) {
            let value: serde_json::Value =
                serde_json::from_slice(line).map_err(|_error| "invalid JSON line".to_owned())?;
            let Some(name) = value.get("name").and_then(serde_json::Value::as_str) else {
                return Err("missing name".to_owned());
            };
            let Some(value) = value.get("value").and_then(serde_json::Value::as_str) else {
                return Err("missing value".to_owned());
            };
            out.add_argument(name.as_bytes(), value.as_bytes());
        }
        Ok(())
    }
}

struct Literal(&'static str);

impl BodyProcessor for Literal {
    fn process(
        &self,
        _body: &[u8],
        _direction: BodyDirection,
        _options: &BodyProcessorOptions<'_>,
        out: &mut BodyProcessorOutput,
    ) -> Result<(), String> {
        out.add_argument(b"source", self.0.as_bytes());
        Ok(())
    }
}

struct FileAndXml;

impl BodyProcessor for FileAndXml {
    fn process(
        &self,
        _body: &[u8],
        _direction: BodyDirection,
        _options: &BodyProcessorOptions<'_>,
        out: &mut BodyProcessorOutput,
    ) -> Result<(), String> {
        out.add_file(b"upload", b"payload.txt", b"text/plain", b"file bytes");
        out.add_xml(b"/root/item", b"xml value");
        Ok(())
    }
}

struct TwoFiles;

impl BodyProcessor for TwoFiles {
    fn process(
        &self,
        _body: &[u8],
        _direction: BodyDirection,
        _options: &BodyProcessorOptions<'_>,
        out: &mut BodyProcessorOutput,
    ) -> Result<(), String> {
        out.add_file(b"first", b"first.txt", b"text/plain", b"first");
        out.add_file(b"second", b"second.txt", b"text/plain", b"second");
        Ok(())
    }
}

struct TwoArguments;

impl BodyProcessor for TwoArguments {
    fn process(
        &self,
        _body: &[u8],
        _direction: BodyDirection,
        _options: &BodyProcessorOptions<'_>,
        out: &mut BodyProcessorOutput,
    ) -> Result<(), String> {
        out.add_argument(b"first", b"kept");
        out.add_argument(b"second", b"dropped");
        Ok(())
    }
}

struct ErrorProcessor;

impl BodyProcessor for ErrorProcessor {
    fn process(
        &self,
        body: &[u8],
        _direction: BodyDirection,
        _options: &BodyProcessorOptions<'_>,
        out: &mut BodyProcessorOutput,
    ) -> Result<(), String> {
        out.add_argument(b"partial", b"retained");
        out.set_processor("reported-name");
        if body == b"set-error" {
            out.set_error("reported parse failure");
            Ok(())
        } else {
            Err("returned parse failure".to_owned())
        }
    }
}

fn request_transaction(waf: &coraza::Waf, body: &[u8], content_type: &[u8]) -> Transaction {
    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", content_type);
    tx.process_request_headers();
    tx.process_request_body(body);
    tx
}

#[test]
fn json_lines_processor_selected_by_ctl_survives_waf_compile_and_runs_rules() {
    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.config_mut().multiphase_evaluation = true;
    parser.register_body_processor("JsonLines", Arc::new(|| Box::new(JsonLines)));
    parser
        .from_string(
            "SecRequestBodyAccess On\n\
             SecAction \"id:1,phase:1,ctl:requestBodyProcessor=JSONLINES,pass\"\n\
             SecRule ARGS:user \"@streq alice\" \"id:2,phase:2,setvar:TX.custom=matched,pass\"",
        )
        .unwrap();

    let waf = parser.compile().unwrap();
    let tx = request_transaction(
        &waf,
        br#"{"name":"user","value":"alice"}
{"name":"second","value":"row"}"#,
        b"application/x-custom",
    );

    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
        Some("JSONLINES")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("user")).as_deref(),
        Some("alice")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::Args, Some("user")).as_deref(),
        Some("alice")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("second")).as_deref(),
        Some("row")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("custom")).as_deref(),
        Some("matched")
    );
}

#[test]
fn custom_processors_override_builtins_only_when_selected_by_ctl() {
    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.register_body_processor("JSON", Arc::new(|| Box::new(Literal("custom-json"))));
    parser
        .from_string("SecAction \"id:1,phase:1,ctl:requestBodyProcessor=JSON,pass\"")
        .unwrap();
    let tx = request_transaction(&parser.compile().unwrap(), b"{}", b"application/json");
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("source")).as_deref(),
        Some("custom-json")
    );

    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.register_body_processor("URLENCODED", Arc::new(|| Box::new(Literal("must-not-run"))));
    parser.from_string("SecRequestBodyAccess On").unwrap();
    let tx = request_transaction(
        &parser.compile().unwrap(),
        b"name=decoded",
        b"application/x-www-form-urlencoded",
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
        Some("URLENCODED")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("name")).as_deref(),
        Some("decoded")
    );
    assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("source")), None);
}

#[test]
fn custom_files_use_engine_temp_paths_and_xml_keeps_its_path() {
    let directory = tempfile::tempdir().unwrap();
    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.config_mut().upload_dir = directory.path().to_string_lossy().into_owned();
    parser.register_body_processor("filexml", Arc::new(|| Box::new(FileAndXml)));
    parser
        .from_string("SecAction \"id:1,phase:1,ctl:requestBodyProcessor=filexml,pass\"")
        .unwrap();
    let waf = parser.compile().unwrap();
    let mut tx = request_transaction(&waf, b"custom body", b"application/x-custom");

    assert_eq!(
        tx.get_variable(RuleVariable::Files, Some("")).as_deref(),
        Some("payload.txt")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::FilesNames, Some("")).as_deref(),
        Some("upload")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartName, Some("upload")).as_deref(),
        Some("upload")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartFilename, Some("upload"))
            .as_deref(),
        Some("payload.txt")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::FilesSizes, Some("payload.txt"))
            .as_deref(),
        Some("10")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::FilesCombinedSize, None).as_deref(),
        Some("10")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartPartHeaders, Some("upload"))
            .as_deref(),
        Some("Content-Type: text/plain")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::RequestXML, Some("/root/item")).as_deref(),
        Some("xml value")
    );

    let path = tx.get_variable(RuleVariable::FilesTmpNames, Some("")).unwrap();
    assert_eq!(fs::read(&*path).unwrap(), b"file bytes");
    tx.finish().unwrap();
    assert!(!std::path::Path::new(&*path).exists());
}

#[test]
fn custom_files_obey_the_transaction_upload_file_limit() {
    let directory = tempfile::tempdir().unwrap();
    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.config_mut().upload_dir = directory.path().to_string_lossy().into_owned();
    parser.config_mut().upload_file_limit = 1;
    parser.register_body_processor("twofiles", Arc::new(|| Box::new(TwoFiles)));
    parser
        .from_string("SecAction \"id:1,phase:1,ctl:requestBodyProcessor=twofiles,pass\"")
        .unwrap();
    let mut tx = request_transaction(&parser.compile().unwrap(), b"body", b"application/x-custom");

    assert_eq!(
        tx.get_variable(RuleVariable::Files, Some("")).as_deref(),
        Some("first.txt")
    );
    let path = tx.get_variable(RuleVariable::FilesTmpNames, Some("")).unwrap();
    assert_eq!(fs::read(&*path).unwrap(), b"first");
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartStrictError, None).as_deref(),
        Some("1")
    );
    tx.finish().unwrap();
    assert!(!std::path::Path::new(&*path).exists());
}

#[test]
fn custom_argument_limits_and_errors_keep_existing_body_error_semantics() {
    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.config_mut().argument_limit = 1;
    parser.register_body_processor("two", Arc::new(|| Box::new(TwoArguments)));
    parser
        .from_string("SecAction \"id:1,phase:1,ctl:requestBodyProcessor=two,pass\"")
        .unwrap();
    let waf = parser.compile().unwrap();

    let tx = request_transaction(&waf, b"body", b"application/x-custom");
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("first")).as_deref(),
        Some("kept")
    );
    assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("second")), None);
    assert_eq!(
        tx.get_variable(RuleVariable::ArgumentsLimitReached, None).as_deref(),
        Some("1")
    );
    assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("0"));
    assert!(!tx.inspection_incomplete());

    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.register_body_processor("error", Arc::new(|| Box::new(ErrorProcessor)));
    parser
        .from_string("SecAction \"id:3,phase:1,ctl:requestBodyProcessor=error,pass\"")
        .unwrap();
    let waf = parser.compile().unwrap();
    let tx = request_transaction(&waf, b"set-error", b"application/x-custom");
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("partial")).as_deref(),
        Some("retained")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
        Some("REPORTED-NAME")
    );
    assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("1"));
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyErrorMsg, None).as_deref(),
        Some("REPORTED-NAME: reported parse failure")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessorError, None).as_deref(),
        Some("1")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None).as_deref(),
        Some("reported parse failure")
    );
    assert!(!tx.inspection_incomplete());

    let tx = request_transaction(&waf, b"returned-error", b"application/x-custom");
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("partial")).as_deref(),
        Some("retained")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyErrorMsg, None).as_deref(),
        Some("REPORTED-NAME: returned parse failure")
    );
}

#[test]
fn custom_response_processor_populates_response_args() {
    let mut parser = Parser::new();
    parser.config_mut().response_body_access = true;
    parser
        .config_mut()
        .response_body_mime_types
        .push("text/plain".to_owned());
    parser.register_body_processor("reply", Arc::new(|| Box::new(JsonLines)));
    parser
        .from_string("SecAction \"id:1,phase:3,ctl:responseBodyProcessor=reply,pass\"")
        .unwrap();
    let waf = parser.compile().unwrap();
    let mut tx = waf.new_transaction();
    tx.add_response_header("Content-Type", "text/plain");
    tx.process_request_headers();
    tx.process_request_body(b"");
    tx.process_response_headers(200, "HTTP/1.1");
    tx.process_response_body(br#"{"name":"result","value":"ok"}"#);

    assert_eq!(
        tx.get_variable(RuleVariable::ResBodyProcessor, None).as_deref(),
        Some("REPLY")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseArgs, Some("result")).as_deref(),
        Some("ok")
    );
}

#[test]
fn body_processor_registries_are_parser_scoped_and_late_registration_is_not_retroactive() {
    fn parser_with_literal(value: &'static str) -> Parser {
        let mut parser = Parser::new();
        parser.config_mut().request_body_access = true;
        parser.register_body_processor("same", Arc::new(move || Box::new(Literal(value))));
        parser
            .from_string("SecAction \"id:1,phase:1,ctl:requestBodyProcessor=same,pass\"")
            .unwrap();
        parser
    }

    let tx_a = request_transaction(
        &parser_with_literal("a").compile().unwrap(),
        b"body",
        b"application/x-custom",
    );
    let tx_b = request_transaction(
        &parser_with_literal("b").compile().unwrap(),
        b"body",
        b"application/x-custom",
    );
    assert_eq!(
        tx_a.get_variable(RuleVariable::ArgsPost, Some("source")).as_deref(),
        Some("a")
    );
    assert_eq!(
        tx_b.get_variable(RuleVariable::ArgsPost, Some("source")).as_deref(),
        Some("b")
    );

    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser
        .from_string("SecRequestBodyAccess On\nSecAction \"id:2,phase:1,ctl:requestBodyProcessor=JSON,pass\"")
        .unwrap();
    parser.register_body_processor("JSON", Arc::new(|| Box::new(Literal("late"))));
    let tx = request_transaction(
        &parser.compile().unwrap(),
        br#"{"name":"builtin","value":"json"}"#,
        b"application/x-custom",
    );
    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("json_request_body")).as_deref(),
        Some(r#"{"name":"builtin","value":"json"}"#)
    );
    assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("source")), None);
}

#[test]
fn built_in_only_policy_is_unchanged_and_unknown_custom_names_are_rejected() {
    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.from_string("SecRequestBodyAccess On").unwrap();
    let tx = request_transaction(
        &parser.compile().unwrap(),
        b"name=built-in",
        b"application/x-www-form-urlencoded",
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
        Some("URLENCODED")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("name")).as_deref(),
        Some("built-in")
    );

    let mut parser = Parser::new();
    let error = parser
        .from_string("SecAction \"id:1,phase:1,ctl:requestBodyProcessor=notRegistered,pass\"")
        .unwrap_err();
    assert!(error.message.contains("invalid ctl command: requestBodyProcessor"));
}

#[cfg(target_os = "wasi")]
#[test]
fn file_output_is_rejected_without_a_wasi_storage_sink() {
    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.register_body_processor("filexml", Arc::new(|| Box::new(FileAndXml)));
    parser
        .from_string("SecAction \"id:1,phase:1,ctl:requestBodyProcessor=filexml,pass\"")
        .unwrap();
    let tx = request_transaction(&parser.compile().unwrap(), b"body", b"application/x-custom");

    assert_eq!(tx.get_variable(RuleVariable::Files, Some("")), None);
    assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("1"));
    assert!(
        tx.get_variable(RuleVariable::ReqbodyErrorMsg, None)
            .is_some_and(|message| message.contains("WASI"))
    );
}

#[test]
fn custom_body_processor_contract_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<JsonLines>();
    assert_send_sync::<Arc<dyn BodyProcessor>>();
}
