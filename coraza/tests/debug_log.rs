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
    reason = "asserted event fixtures are checked before indexing"
)]

#[cfg(unix)]
use std::process::Command;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use coraza::{
    DebugEvent, DebugField, DebugLevel, DebugLogger, LevelFilter, Waf, Writer, config::WafConfig, seclang::Parser,
};

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
fn share_logger<T: DebugLogger + 'static>(logger: &Arc<T>) -> Arc<dyn DebugLogger> {
    let logger: Arc<T> = Arc::clone(logger);
    logger
}

#[derive(Default)]
struct CountingLogger {
    enabled: AtomicUsize,
    logged: AtomicUsize,
}

impl CountingLogger {
    fn reset(&self) {
        self.enabled.store(0, Ordering::Relaxed);
        self.logged.store(0, Ordering::Relaxed);
    }
}

impl DebugLogger for CountingLogger {
    fn enabled(&self, _level: DebugLevel) -> bool {
        self.enabled.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn log(&self, _level: DebugLevel, _event: &DebugEvent<'_>) {
        self.logged.fetch_add(1, Ordering::Relaxed);
    }
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
fn transformation_errors_are_aggregated_once_per_argument() {
    let logger = Arc::new(CaptureLogger::default());
    let mut parser = Parser::new().with_debug_logger(share_logger(&logger));
    parser.config_mut().debug_log_level = 2;
    parser
        .from_string("SecRule ARGS:q \"@streq foo\" \"id:3,phase:1,pass,t:hexDecode,t:hexDecode\"")
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
    assert_eq!(
        warnings[0]
            .fields
            .iter()
            .filter(|field| *field == "text=odd length hex string")
            .count(),
        2,
        "both failing transforms should be aggregated into the argument's one warning"
    );
}

#[test]
fn scanned_detector_inputs_log_a_no_match_verdict() {
    let logger = Arc::new(CaptureLogger::default());
    let mut parser = Parser::new().with_debug_logger(share_logger(&logger));
    parser.config_mut().debug_log_level = 4;
    parser
        .from_string(
            "SecRule ARGS:oversized \"@detectSQLi\" \"id:970,phase:1,pass\"\n\
             SecRule ARGS:miss \"@streq expected\" \"id:971,phase:1,pass\"",
        )
        .unwrap();
    let waf = parser.compile().unwrap();
    let mut transaction = waf.new_transaction_with_id("debug-not-inspected");
    transaction.add_get_argument("oversized", vec![b'x'; libperfusion::MAX_INPUT_LEN + 1]);
    transaction.add_get_argument("miss", "actual");
    transaction.process_request_headers();

    let events = logger.events();
    assert!(!events.iter().any(|event| {
        event.message == "Evaluating operator: NOT INSPECTED" && event.fields.contains(&"rule_id=970".to_owned())
    }));
    assert!(events.iter().any(|event| {
        event.message == "Evaluating operator: NO MATCH" && event.fields.contains(&"rule_id=970".to_owned())
    }));
    assert!(events.iter().any(|event| {
        event.message == "Evaluating operator: NO MATCH" && event.fields.contains(&"rule_id=971".to_owned())
    }));
}

#[test]
fn chain_member_lifecycle_events_are_nested_inside_parent_events() {
    let logger = Arc::new(CaptureLogger::default());
    let mut parser = Parser::new().with_debug_logger(share_logger(&logger));
    parser.config_mut().debug_log_level = 4;
    parser
        .from_string(
            "SecRule ARGS:first \"@streq yes\" \"id:980,phase:1,chain,pass\"\n\
             SecRule ARGS:second \"@streq yes\" \"\"",
        )
        .unwrap();
    let waf = parser.compile().unwrap();
    let mut transaction = waf.new_transaction_with_id("debug-chain");
    transaction.add_get_argument("first", "yes");
    transaction.add_get_argument("second", "yes");
    transaction.process_request_headers();

    let lifecycle: Vec<_> = logger
        .events()
        .into_iter()
        .filter(|event| {
            matches!(
                event.message,
                "Evaluating rule"
                    | "Evaluating chain link"
                    | "Finished chain link evaluation"
                    | "Finished rule evaluation"
            )
        })
        .collect();
    assert_eq!(
        lifecycle.iter().map(|event| event.message).collect::<Vec<_>>(),
        [
            "Evaluating rule",
            "Evaluating chain link",
            "Finished chain link evaluation",
            "Finished rule evaluation"
        ]
    );
    assert!(
        lifecycle[1]
            .fields
            .iter()
            .any(|field| { field.contains("parent_rule_id=980") && field.contains("chain_level=1") })
    );
    assert!(lifecycle[1].fields.iter().any(|field| field.starts_with("rule_id=")));
}

#[test]
fn host_logger_is_checked_and_called_once_per_enabled_event() {
    let host = Arc::new(CountingLogger::default());
    let wrapped: Arc<dyn DebugLogger> = Arc::new(LevelFilter::new(share_logger(&host), 9));
    let mut parser = Parser::new().with_debug_logger(wrapped);
    parser.config_mut().debug_log_level = 2;
    parser
        .from_string("SecAction \"id:981,phase:1,pass,ctl:debugLogLevel=invalid\"")
        .unwrap();
    let waf = parser.compile().unwrap();
    let mut transaction = waf.new_transaction_with_id("debug-counting");
    host.reset();
    transaction.process_request_headers();

    assert_eq!(host.enabled.load(Ordering::Relaxed), 1);
    assert_eq!(host.logged.load(Ordering::Relaxed), 1);
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
    assert_eq!(waf.config().debug_log_level, 0);
    assert!(waf.config().debug_log.is_empty());
    assert!(waf.debug_log_error().is_none());

    let disabled_host = Arc::new(CountingLogger::default());
    let parser = Parser::new().with_debug_logger(share_logger(&disabled_host));
    let disabled_waf = parser.compile().unwrap();
    disabled_waf
        .new_transaction_with_id("disabled-host-logger")
        .process_request_headers();
    assert_eq!(disabled_host.enabled.load(Ordering::Relaxed), 0);
    assert_eq!(disabled_host.logged.load(Ordering::Relaxed), 0);

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

#[cfg(unix)]
#[test]
fn writer_routes_events_to_the_selected_standard_stream() {
    const CHILD: &str = "CORAZA_DEBUG_STREAM_CAPTURE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let stdout = Writer::stdout();
        let stderr = Writer::stderr();
        let event = |message| DebugEvent { message, fields: &[] };
        stdout.log(DebugLevel::Info, &event("stdout debug marker"));
        stderr.log(DebugLevel::Warn, &event("stderr debug marker"));
        return;
    }

    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "writer_routes_events_to_the_selected_standard_stream",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("[INFO] stdout debug marker"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("[WARN] stderr debug marker"));
}
