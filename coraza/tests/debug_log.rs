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

//! Integration coverage for the public debug logging API.
#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]
#![expect(
    clippy::unwrap_used,
    reason = "debug logger tests use fixed local policies and temporary files"
)]
#![expect(
    clippy::indexing_slicing,
    reason = "the one-element warning fixture is checked before indexing"
)]

use std::sync::{Arc, Mutex};

use coraza::{DebugEvent, DebugField, DebugLevel, DebugLogger, Waf, config::WafConfig, seclang::Parser};

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedEvent {
    level: DebugLevel,
    message: &'static str,
    fields: Vec<String>,
}

#[derive(Default)]
struct CaptureLogger(Mutex<Vec<RecordedEvent>>);

impl CaptureLogger {
    fn events(&self) -> Vec<RecordedEvent> {
        self.0.lock().unwrap().clone()
    }
}

/// Clone a captured logger while erasing its concrete type for the public API.
fn share_logger(logger: &Arc<CaptureLogger>) -> Arc<dyn DebugLogger> {
    let logger: Arc<CaptureLogger> = Arc::clone(logger);
    logger
}

impl DebugLogger for CaptureLogger {
    fn enabled(&self, _level: DebugLevel) -> bool {
        true
    }

    fn log(&self, level: DebugLevel, event: &DebugEvent<'_>) {
        let fields = event
            .fields
            .iter()
            .map(|field| match field {
                DebugField::RuleId(id) => format!("rule_id={id}"),
                DebugField::Phase(phase) => format!("phase={phase}"),
                DebugField::Variable(variable) => format!("variable={variable}"),
                DebugField::Text(text) => format!("text={text}"),
            })
            .collect();
        self.0.lock().unwrap().push(RecordedEvent {
            level,
            message: event.message,
            fields,
        });
    }
}

#[test]
fn transaction_ctl_level_override_does_not_leak() {
    let logger = Arc::new(CaptureLogger::default());
    let mut parser = Parser::new().with_debug_logger(share_logger(&logger));
    parser.config_mut().debug_log_level = 2;
    parser
        .from_string(
            "SecRule ARGS:enable \"@streq yes\" \"id:1,phase:1,pass,ctl:debugLogLevel=9\"\n\
             SecRule ARGS:q \"@streq anything\" \"id:2,phase:1,pass\"",
        )
        .unwrap();
    let waf = parser.compile().unwrap();

    let mut first = waf.new_transaction_with_id("override");
    first.add_get_argument("enable", "yes");
    first.add_get_argument("q", "first-secret");
    first.process_request_headers();
    let traces_after_first = logger
        .events()
        .into_iter()
        .filter(|event| event.level == DebugLevel::Trace)
        .count();
    assert!(traces_after_first > 0, "ctl did not enable this transaction's trace");
    assert!(
        logger.events().iter().any(|event| {
            event.level == DebugLevel::Trace && event.fields.contains(&"text=first-secret".to_owned())
        })
    );
    assert!(logger.events().iter().all(|event| {
        event.level == DebugLevel::Trace || !event.fields.iter().any(|field| field.contains("first-secret"))
    }));

    let mut second = waf.new_transaction_with_id("default-level");
    second.add_get_argument("q", "second-secret");
    second.process_request_headers();
    let traces_after_second = logger
        .events()
        .into_iter()
        .filter(|event| event.level == DebugLevel::Trace)
        .count();
    assert_eq!(
        traces_after_second, traces_after_first,
        "ctl leaked to the next transaction"
    );
}

#[test]
fn invalid_ctl_level_compiles_and_warns_at_runtime() {
    let logger = Arc::new(CaptureLogger::default());
    let mut parser = Parser::new().with_debug_logger(share_logger(&logger));
    parser.config_mut().debug_log_level = 2;
    parser
        .from_string("SecAction \"id:1,phase:1,pass,ctl:debugLogLevel=invalid\"")
        .unwrap();
    let waf = parser.compile().unwrap();
    waf.new_transaction_with_id("invalid-ctl").process_request_headers();

    assert!(
        logger
            .events()
            .iter()
            .any(|event| { event.level == DebugLevel::Warn && event.message == "Invalid ctl debug log level" })
    );
}

#[test]
fn transformation_errors_are_warned_once_with_the_error() {
    let logger = Arc::new(CaptureLogger::default());
    let mut parser = Parser::new().with_debug_logger(share_logger(&logger));
    parser.config_mut().debug_log_level = 2;
    parser
        .from_string("SecRule ARGS:q \"@streq foo\" \"id:3,phase:1,pass,t:hexDecode\"")
        .unwrap();
    let waf = parser.compile().unwrap();
    let mut transaction = waf.new_transaction_with_id("transform-error");
    transaction.add_get_argument("q", "foo");
    transaction.process_request_headers();

    let warnings: Vec<_> = logger
        .events()
        .into_iter()
        .filter(|event| event.message == "Error transforming argument for rule")
        .collect();
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].fields.contains(&"rule_id=3".to_owned()));
    assert!(warnings[0].fields.contains(&"text=odd length hex string".to_owned()));
}

#[test]
fn debug_sink_failure_is_reported_without_panicking() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing/debug.log");
    let waf = Waf::new(WafConfig {
        debug_log: path.to_string_lossy().into_owned(),
        debug_log_level: 4,
        ..WafConfig::default()
    })
    .unwrap();

    let _transaction = waf.new_transaction_with_id("lazy-open-failure");
    assert_eq!(
        waf.debug_log_error().map(|(kind, _)| kind),
        Some(std::io::ErrorKind::NotFound)
    );
    assert_eq!(waf.activate().unwrap_err().kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn body_processor_errors_are_logged_without_body_bytes_below_trace() {
    let logger = Arc::new(CaptureLogger::default());
    let mut parser = Parser::new().with_debug_logger(share_logger(&logger));
    parser.config_mut().debug_log_level = 1;
    parser.config_mut().request_body_access = true;
    parser
        .from_string("SecAction \"id:1,phase:1,pass,ctl:requestBodyProcessor=JSON\"")
        .unwrap();
    let waf = parser.compile().unwrap();
    let mut transaction = waf.new_transaction_with_id("body-error");
    transaction.add_request_header("content-type", "application/json");
    transaction.process_request_headers();
    transaction.process_request_body(b"not-json-secret");

    let events = logger.events();
    assert!(events.iter().any(|event| {
        event.level == DebugLevel::Error
            && event.message == "Request body processor failed"
            && event.fields.contains(&"text=JSON".to_owned())
    }));
    assert!(events.iter().all(|event| {
        event.level == DebugLevel::Trace || !event.fields.iter().any(|field| field.contains("not-json-secret"))
    }));
}

#[test]
fn audit_activation_failure_is_logged() {
    let directory = tempfile::tempdir().unwrap();
    let logger = Arc::new(CaptureLogger::default());
    let waf = Waf::new(WafConfig {
        audit_engine: coraza::types::AuditEngineStatus::On,
        audit_log: directory
            .path()
            .join("missing/audit.log")
            .to_string_lossy()
            .into_owned(),
        debug_log_level: 1,
        ..WafConfig::default()
    })
    .unwrap()
    .with_debug_logger(share_logger(&logger));

    assert!(waf.activate().is_err());
    assert!(
        logger
            .events()
            .iter()
            .any(|event| { event.level == DebugLevel::Error && event.message == "Audit log activation failed" })
    );
}

#[test]
fn default_noop_and_waf_logger_override() {
    let waf = Waf::new(WafConfig::default()).unwrap();
    let mut transaction = waf.new_transaction_with_id("noop");
    transaction.process_request_headers();
    assert!(waf.debug_log_error().is_none());

    let logger = Arc::new(CaptureLogger::default());
    let waf = Waf::new(WafConfig {
        debug_log_level: 4,
        ..WafConfig::default()
    })
    .unwrap()
    .with_debug_logger(share_logger(&logger));
    let _transaction = waf.new_transaction_with_id("host-logger");
    assert!(
        logger
            .events()
            .iter()
            .any(|event| event.message == "A new WAF instance was created")
    );
}
