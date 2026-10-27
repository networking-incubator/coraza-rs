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

use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use coraza::{
    BodyDirection, BodyLimitAction, BodyProcessor, BodyProcessorOptions, BodyProcessorOutput, RuleVariable,
    config::UploadKeepFiles, seclang::Parser, transaction::Transaction,
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
        out.set_processor("JSON");
        if body == b"set-error" {
            out.set_error("reported parse failure");
            Ok(())
        } else {
            Err("returned parse failure".to_owned())
        }
    }
}

struct LargeErrors;

impl BodyProcessor for LargeErrors {
    fn process(
        &self,
        body: &[u8],
        _direction: BodyDirection,
        _options: &BodyProcessorOptions<'_>,
        out: &mut BodyProcessorOutput,
    ) -> Result<(), String> {
        let message = format!("{}é{}", "x".repeat(255), "x".repeat(1_000_000));
        let name = format!("{}é{}", "N".repeat(255), "N".repeat(1_000_000));
        out.set_processor(&name);
        if body == b"set-error" {
            out.set_error(&message);
            Ok(())
        } else {
            Err(message)
        }
    }
}

#[derive(Clone, Copy)]
enum OversizedOutputKind {
    Argument,
    File,
    Xml,
}

struct OversizedOutput(OversizedOutputKind);

impl BodyProcessor for OversizedOutput {
    fn process(
        &self,
        _body: &[u8],
        _direction: BodyDirection,
        _options: &BodyProcessorOptions<'_>,
        out: &mut BodyProcessorOutput,
    ) -> Result<(), String> {
        const TOO_LARGE: [u8; 128] = [b'x'; 128];
        out.add_argument(b"kept", b"yes");
        match self.0 {
            OversizedOutputKind::Argument => out.add_argument(b"large", &TOO_LARGE),
            OversizedOutputKind::File => out.add_file(b"upload", b"large.txt", b"text/plain", &TOO_LARGE),
            OversizedOutputKind::Xml => out.add_xml(b"/large", &TOO_LARGE),
        }
        out.add_argument(b"after-limit", b"dropped");
        Ok(())
    }
}

type RecordedOptions = Arc<Mutex<Vec<(&'static str, BodyDirection, bool, bool)>>>;

struct OptionsRecorder(&'static str, RecordedOptions);

impl BodyProcessor for OptionsRecorder {
    fn process(
        &self,
        _body: &[u8],
        direction: BodyDirection,
        options: &BodyProcessorOptions<'_>,
        _out: &mut BodyProcessorOutput,
    ) -> Result<(), String> {
        self.1
            .lock()
            .unwrap()
            .push((self.0, direction, options.truncated, options.data_error));
        Ok(())
    }
}

struct ResponseFile;

impl BodyProcessor for ResponseFile {
    fn process(
        &self,
        _body: &[u8],
        _direction: BodyDirection,
        _options: &BodyProcessorOptions<'_>,
        out: &mut BodyProcessorOutput,
    ) -> Result<(), String> {
        out.add_file(b"response", b"response.txt", b"text/plain", b"response file");
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RecordedBodyOptions {
    direction: BodyDirection,
    mime: Vec<u8>,
    argument_limit: usize,
    upload_dir: PathBuf,
    upload_file_limit: usize,
    upload_file_mode: u32,
    upload_keep_files: UploadKeepFiles,
    truncated: bool,
    data_error: bool,
}

struct FullOptionsRecorder(Arc<Mutex<Option<RecordedBodyOptions>>>);

impl BodyProcessor for FullOptionsRecorder {
    fn process(
        &self,
        _body: &[u8],
        direction: BodyDirection,
        options: &BodyProcessorOptions<'_>,
        _out: &mut BodyProcessorOutput,
    ) -> Result<(), String> {
        *self.0.lock().unwrap() = Some(RecordedBodyOptions {
            direction,
            mime: options.mime.to_vec(),
            argument_limit: options.argument_limit,
            upload_dir: options.upload_dir.to_path_buf(),
            upload_file_limit: options.upload_file_limit,
            upload_file_mode: options.upload_file_mode,
            upload_keep_files: options.upload_keep_files,
            truncated: options.truncated,
            data_error: options.data_error,
        });
        Ok(())
    }
}

struct ResponseOutputs;

impl BodyProcessor for ResponseOutputs {
    fn process(
        &self,
        body: &[u8],
        _direction: BodyDirection,
        _options: &BodyProcessorOptions<'_>,
        out: &mut BodyProcessorOutput,
    ) -> Result<(), String> {
        out.add_argument(b"result", b"ok");
        out.add_xml(b"/root/item", b"xml value");
        match body {
            b"file" => out.add_file(b"response", b"response.txt", b"text/plain", b"response file"),
            b"set-error" => out.set_error("response failure"),
            b"returned-error" => return Err("response failure".to_owned()),
            _ => {},
        }
        Ok(())
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
fn custom_processors_receive_resolved_non_default_body_options() {
    let directory = tempfile::tempdir().unwrap();
    let observed = Arc::new(Mutex::new(None));
    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.config_mut().request_body_limit = 4;
    parser.config_mut().request_body_limit_action = BodyLimitAction::ProcessPartial;
    parser.config_mut().argument_limit = 17;
    parser.config_mut().upload_dir = directory.path().to_string_lossy().into_owned();
    parser.config_mut().upload_file_limit = 3;
    parser.config_mut().upload_file_mode = 0o640;
    parser.config_mut().upload_keep_files = UploadKeepFiles::On;
    parser.register_body_processor(
        "options",
        Arc::new({
            let observed = Arc::clone(&observed);
            move || Box::new(FullOptionsRecorder(Arc::clone(&observed)))
        }),
    );
    parser
        .from_string("SecAction \"id:1,phase:1,ctl:requestBodyProcessor=options,pass\"")
        .unwrap();

    let _tx = request_transaction(
        &parser.compile().unwrap(),
        b"longer than limit",
        b"application/x-options",
    );
    assert_eq!(
        *observed.lock().unwrap(),
        Some(RecordedBodyOptions {
            direction: BodyDirection::Request,
            mime: b"application/x-options".to_vec(),
            argument_limit: 17,
            upload_dir: directory.path().to_path_buf(),
            upload_file_limit: 3,
            upload_file_mode: 0o640,
            upload_keep_files: UploadKeepFiles::On,
            truncated: true,
            data_error: true,
        })
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
fn processor_factories_are_lazy_and_multiple_selectors_construct_once() {
    let constructions = Arc::new(AtomicUsize::new(0));
    let mut parser = Parser::new();
    let factory_count = Arc::clone(&constructions);
    parser.register_body_processor(
        "counted",
        Arc::new(move || {
            factory_count.fetch_add(1, Ordering::SeqCst);
            Box::new(Literal("counted"))
        }),
    );
    parser
        .from_string("SecAction \"id:1,phase:1,ctl:requestBodyProcessor=counted,pass\"")
        .unwrap();
    let tx = request_transaction(&parser.compile().unwrap(), b"ignored", b"text/plain");
    assert_eq!(constructions.load(Ordering::SeqCst), 0);
    drop(tx);

    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    let factory_count = Arc::clone(&constructions);
    parser.register_body_processor(
        "counted",
        Arc::new(move || {
            factory_count.fetch_add(1, Ordering::SeqCst);
            Box::new(Literal("counted"))
        }),
    );
    parser
        .from_string(
            "SecAction \"id:2,phase:1,ctl:requestBodyProcessor=counted,pass\"\n\
             SecAction \"id:3,phase:1,ctl:requestBodyProcessor=counted,pass\"",
        )
        .unwrap();
    let tx = request_transaction(&parser.compile().unwrap(), b"processed", b"text/plain");
    assert_eq!(constructions.load(Ordering::SeqCst), 1);
    assert_eq!(
        tx.get_variable(RuleVariable::ArgsPost, Some("source")).as_deref(),
        Some("counted")
    );
}

#[test]
fn output_byte_budget_covers_arguments_files_and_xml_and_keeps_the_prefix() {
    for (name, kind) in [
        ("oversized-argument", OversizedOutputKind::Argument),
        ("oversized-file", OversizedOutputKind::File),
        ("oversized-xml", OversizedOutputKind::Xml),
    ] {
        let mut parser = Parser::new();
        parser.config_mut().request_body_access = true;
        parser.config_mut().request_body_limit = 128;
        parser.register_body_processor(name, Arc::new(move || Box::new(OversizedOutput(kind))));
        parser
            .from_string(&format!(
                "SecAction \"id:1,phase:1,ctl:requestBodyProcessor={name},pass\""
            ))
            .unwrap();
        let tx = request_transaction(&parser.compile().unwrap(), b"small", b"text/plain");

        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPost, Some("kept")).as_deref(),
            Some("yes")
        );
        assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("after-limit")), None);
        assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("1"));
        assert_eq!(
            tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
            Some("1")
        );
        let expected_error = match name {
            "oversized-argument" => "OVERSIZED-ARGUMENT: custom body processor output exceeded byte limit",
            "oversized-file" => "OVERSIZED-FILE: custom body processor output exceeded byte limit",
            _ => "OVERSIZED-XML: custom body processor output exceeded byte limit",
        };
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyErrorMsg, None).as_deref(),
            Some(expected_error)
        );
        match kind {
            OversizedOutputKind::Argument => {
                assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("large")), None);
            },
            OversizedOutputKind::File => {
                assert_eq!(tx.get_variable(RuleVariable::FilesSizes, Some("large.txt")), None);
            },
            OversizedOutputKind::Xml => {
                assert_eq!(tx.get_variable(RuleVariable::RequestXML, Some("/large")), None);
            },
        }
    }
}

#[test]
fn custom_request_and_response_processors_receive_their_direction_and_truncation_state() {
    let states = Arc::new(Mutex::new(Vec::new()));
    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.config_mut().response_body_access = true;
    parser
        .config_mut()
        .response_body_mime_types
        .push("text/plain".to_owned());
    parser.register_body_processor(
        "request-state",
        Arc::new({
            let states = Arc::clone(&states);
            move || Box::new(OptionsRecorder("request", Arc::clone(&states)))
        }),
    );
    parser.register_body_processor(
        "response-state",
        Arc::new({
            let states = Arc::clone(&states);
            move || Box::new(OptionsRecorder("response", Arc::clone(&states)))
        }),
    );
    parser
        .from_string(
            "SecRequestBodyLimit 4\n\
             SecRequestBodyLimitAction ProcessPartial\n\
             SecResponseBodyLimit 4\n\
             SecResponseBodyLimitAction ProcessPartial\n\
             SecAction \"id:1,phase:1,ctl:requestBodyProcessor=request-state,pass\"\n\
             SecAction \"id:2,phase:3,ctl:responseBodyProcessor=response-state,pass\"",
        )
        .unwrap();
    let waf = parser.compile().unwrap();
    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "text/plain");
    tx.process_request_headers();
    tx.process_request_body(b"request-body");
    assert_eq!(
        *states.lock().unwrap(),
        [("request", BodyDirection::Request, true, true)]
    );
    tx.add_response_header("Content-Type", "text/plain");
    tx.process_response_headers(200, "HTTP/1.1");
    tx.process_response_body(b"response-body");

    assert_eq!(
        *states.lock().unwrap(),
        [
            ("request", BodyDirection::Request, true, true),
            ("response", BodyDirection::Response, true, true)
        ]
    );
}

#[test]
fn custom_request_truncation_option_tracks_discarded_bytes_at_the_limit_boundary() {
    let states = Arc::new(Mutex::new(Vec::new()));
    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.config_mut().request_body_limit = 4;
    parser.config_mut().request_body_limit_action = BodyLimitAction::ProcessPartial;
    parser.register_body_processor(
        "request-state",
        Arc::new({
            let states = Arc::clone(&states);
            move || Box::new(OptionsRecorder("request", Arc::clone(&states)))
        }),
    );
    parser
        .from_string("SecAction \"id:1,phase:1,ctl:requestBodyProcessor=request-state,pass\"")
        .unwrap();
    let waf = parser.compile().unwrap();

    for (body, truncated) in [(&b"1234"[..], false), (&b"12345"[..], true)] {
        let tx = request_transaction(&waf, body, b"text/plain");
        assert_eq!(tx.request_body_stats().truncated, truncated);
        // Go's >= boundary still reports a data error for an exact-limit body.
        assert_eq!(
            tx.get_variable(RuleVariable::InboundDataError, None).as_deref(),
            Some("1")
        );
    }

    assert_eq!(
        *states.lock().unwrap(),
        [
            ("request", BodyDirection::Request, false, true),
            ("request", BodyDirection::Request, true, true)
        ]
    );
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

    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.from_string("SecRequestBodyAccess On").unwrap();
    let tx = request_transaction(
        &parser.compile().unwrap(),
        b"--boundary\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"payload.txt\"\r\nContent-Type: text/plain\r\n\r\nfile bytes\r\n--boundary--",
        b"multipart/form-data; boundary=boundary",
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartPartHeaders, Some("upload"))
            .as_deref(),
        Some("Content-Disposition: form-data; name=\"upload\"; filename=\"payload.txt\"")
    );
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
fn response_file_capacity_counts_stored_uploads_not_alternate_filenames() {
    let directory = tempfile::tempdir().unwrap();
    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.config_mut().response_body_access = true;
    parser
        .config_mut()
        .response_body_mime_types
        .push("text/plain".to_owned());
    parser.config_mut().upload_file_limit = 2;
    parser.config_mut().upload_dir = directory.path().to_string_lossy().into_owned();
    parser.register_body_processor("response-file", Arc::new(|| Box::new(ResponseFile)));
    parser
        .from_string("SecAction \"id:1,phase:3,ctl:responseBodyProcessor=response-file,pass\"")
        .unwrap();
    let waf = parser.compile().unwrap();
    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "multipart/form-data; boundary=boundary");
    tx.process_request_headers();
    tx.process_request_body(
        b"--boundary\r\n\
Content-Disposition: form-data; name=\"upload\"; filename=\"legacy.txt\"; filename*=UTF-8'en'payload.txt\r\n\
Content-Type: application/octet-stream\r\n\
\r\n\
payload\r\n\
--boundary--",
    );

    assert_eq!(
        tx.get_variable(RuleVariable::Files, Some("")).as_deref(),
        Some("payload.txt")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::FilesSizes, Some("legacy.txt")).as_deref(),
        Some("7")
    );
    tx.add_response_header("Content-Type", "text/plain");
    tx.process_response_headers(200, "HTTP/1.1");
    tx.process_response_body(b"response");

    assert_eq!(
        tx.get_variable(RuleVariable::FilesSizes, Some("response.txt"))
            .as_deref(),
        Some("13")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartStrictError, None).as_deref(),
        Some("0")
    );
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
        Some("JSON")
    );
    assert_eq!(tx.get_variable(RuleVariable::ReqbodyError, None).as_deref(), Some("1"));
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyErrorMsg, None).as_deref(),
        Some("JSON: reported parse failure")
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
        Some("JSON: returned parse failure")
    );
}

#[test]
fn custom_processor_errors_and_names_are_bounded_before_storage_and_formatting() {
    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.register_body_processor("large-errors", Arc::new(|| Box::new(LargeErrors)));
    parser
        .from_string("SecAction \"id:1,phase:1,ctl:requestBodyProcessor=large-errors,pass\"")
        .unwrap();
    let waf = parser.compile().unwrap();
    let expected_message = "x".repeat(255);
    let expected_name = "N".repeat(255);

    for body in [b"set-error".as_slice(), b"returned-error".as_slice()] {
        let tx = request_transaction(&waf, body, b"application/x-custom");
        let processor_error = tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None).unwrap();
        let error_message = tx.get_variable(RuleVariable::ReqbodyErrorMsg, None).unwrap();
        let processor_name = tx.get_variable(RuleVariable::ReqbodyProcessor, None).unwrap();

        assert_eq!(&*processor_error, expected_message);
        assert_eq!(&*error_message, format!("{expected_name}: {expected_message}"));
        assert_eq!(&*processor_name, expected_name);
        assert!(processor_error.len() <= 256);
        assert!(processor_name.len() <= 256);
        assert!(error_message.len() <= 2 * 256 + 2);
    }
}

#[test]
fn custom_response_processor_populates_outputs_and_matches_request_error_semantics() {
    let directory = tempfile::tempdir().unwrap();
    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.config_mut().response_body_access = true;
    parser
        .config_mut()
        .response_body_mime_types
        .push("text/plain".to_owned());
    parser.config_mut().upload_file_limit = 1;
    parser.config_mut().upload_dir = directory.path().to_string_lossy().into_owned();
    parser.register_body_processor("reply", Arc::new(|| Box::new(ResponseOutputs)));
    parser
        .from_string("SecAction \"id:1,phase:3,ctl:responseBodyProcessor=reply,pass\"")
        .unwrap();
    let waf = parser.compile().unwrap();
    let process_response = |request_content_type: &[u8], request_body: &[u8], response_body: &[u8]| {
        let mut tx = waf.new_transaction();
        tx.add_request_header("Content-Type", request_content_type);
        tx.process_request_headers();
        tx.process_request_body(request_body);
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");
        tx.process_response_body(response_body);
        tx
    };

    let mut tx = process_response(
        b"multipart/form-data; boundary=boundary",
        b"--boundary\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"request.txt\"\r\nContent-Type: text/plain\r\n\r\nrequest file\r\n--boundary--",
        b"file",
    );

    assert_eq!(
        tx.get_variable(RuleVariable::ResBodyProcessor, None).as_deref(),
        Some("REPLY")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseArgs, Some("result")).as_deref(),
        Some("ok")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ResponseXML, Some("/root/item"))
            .as_deref(),
        Some("xml value")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::Files, Some("")).as_deref(),
        Some("request.txt")
    );
    assert_eq!(tx.get_variable(RuleVariable::FilesSizes, Some("response.txt")), None);
    assert_eq!(
        tx.get_variable(RuleVariable::MultipartStrictError, None).as_deref(),
        Some("1")
    );
    tx.finish().unwrap();

    for body in [b"returned-error".as_slice(), b"set-error".as_slice()] {
        let tx = process_response(b"text/plain", b"", body);
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseArgs, Some("result")).as_deref(),
            Some("ok")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ResponseXML, Some("/root/item"))
                .as_deref(),
            Some("xml value")
        );
        assert_eq!(tx.get_variable(RuleVariable::ResBodyError, None).as_deref(), Some("1"));
        assert_eq!(
            tx.get_variable(RuleVariable::ResBodyErrorMsg, None).as_deref(),
            Some("REPLY: response failure")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ResBodyProcessorError, None).as_deref(),
            Some("1")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ResBodyProcessorErrorMsg, None).as_deref(),
            Some("response failure")
        );
        assert!(!tx.inspection_incomplete());
    }
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

#[test]
fn oversized_selected_processor_names_stay_bounded_in_the_reported_variable() {
    let long_name = "n".repeat(4096);
    let mut parser = Parser::new();
    parser.config_mut().request_body_access = true;
    parser.register_body_processor(&long_name, Arc::new(|| Box::new(Literal("value"))));
    parser
        .from_string(&format!(
            "SecRequestBodyAccess On\n\
             SecAction \"id:1,phase:1,ctl:requestBodyProcessor={long_name},pass\""
        ))
        .unwrap();

    let waf = parser.compile().unwrap();
    let tx = request_transaction(&waf, b"{}", b"application/x-custom");
    let reported = tx.get_variable(RuleVariable::ReqbodyProcessor, None);
    let reported = reported.as_deref().unwrap_or_default();

    assert!(
        !reported.is_empty() && reported.len() <= 256,
        "reported processor name must be bounded, got {} bytes",
        reported.len()
    );
}

#[test]
fn oversized_selected_response_processor_names_stay_bounded() {
    let long_name = "r".repeat(4096);
    let mut parser = Parser::new();
    parser.config_mut().response_body_access = true;
    parser.register_body_processor(&long_name, Arc::new(|| Box::new(Literal("value"))));
    parser
        .from_string(&format!(
            "SecResponseBodyAccess On\n\
             SecAction \"id:1,phase:3,ctl:responseBodyProcessor={long_name},pass\""
        ))
        .unwrap();

    let waf = parser.compile().unwrap();
    let mut tx = waf.new_transaction_with_id("oversized-response-name");
    tx.process_uri("/", "GET", "HTTP/1.1");
    tx.process_request_headers();
    tx.process_request_body(b"");
    tx.process_response_headers(200, "HTTP/1.1");
    tx.process_response_body(b"{}");

    let reported = tx.get_variable(RuleVariable::ResBodyProcessor, None);
    let reported = reported.as_deref().unwrap_or_default();

    assert!(
        !reported.is_empty() && reported.len() <= 256,
        "reported response processor name must be bounded, got {} bytes",
        reported.len()
    );
}
