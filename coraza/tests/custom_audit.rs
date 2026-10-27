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
    clippy::indexing_slicing,
    reason = "custom audit tests use fixed directives and temporary fixtures"
)]

//! End-to-end tests for parser-registered audit writers and formatters.

/// Exercise custom audit extensions through the public parser and WAF API.
#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use coraza::{
        audit_log::{AuditLog, AuditLogFormatter, AuditLogWriter, AuditLogWriterFactory},
        seclang::Parser,
    };

    type CapturedEntries = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    #[derive(Clone)]
    struct CapturingAuditWriter(CapturedEntries);

    impl AuditLogWriter for CapturingAuditWriter {
        fn write(&self, entry: &AuditLog, formatted: &[u8]) -> std::io::Result<()> {
            self.0
                .lock()
                .unwrap()
                .push((entry.transaction.id.clone(), formatted.to_vec()));
            Ok(())
        }
    }

    struct JsonAuditFormatter;

    impl AuditLogFormatter for JsonAuditFormatter {
        fn format(&self, entry: &AuditLog) -> Vec<u8> {
            serde_json::json!({ "transaction_id": entry.transaction.id })
                .to_string()
                .into_bytes()
        }

        fn mime(&self) -> &'static str {
            "application/json"
        }
    }

    struct TextAuditFormatter;

    impl AuditLogFormatter for TextAuditFormatter {
        fn format(&self, entry: &AuditLog) -> Vec<u8> {
            format!("audit:{}", entry.transaction.id).into_bytes()
        }

        fn mime(&self) -> &'static str {
            "text/plain"
        }
    }

    struct ArgsAuditFormatter;

    impl AuditLogFormatter for ArgsAuditFormatter {
        fn format(&self, entry: &AuditLog) -> Vec<u8> {
            entry
                .transaction
                .request
                .args
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("&")
                .into_bytes()
        }

        fn mime(&self) -> &'static str {
            "text/plain"
        }
    }

    struct FailedAuditWriter;

    impl AuditLogWriter for FailedAuditWriter {
        fn write(&self, _entry: &AuditLog, _formatted: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "custom sink write failed",
            ))
        }
    }

    fn capture_factory(entries: CapturedEntries) -> AuditLogWriterFactory {
        Arc::new(move |_config| {
            let writer: Box<dyn AuditLogWriter> = Box::new(CapturingAuditWriter(Arc::clone(&entries)));
            Ok(writer)
        })
    }

    fn capture_parser(format_name: &str, formatter: Arc<dyn AuditLogFormatter>) -> (Parser, CapturedEntries) {
        let entries = CapturedEntries::default();
        let mut parser = Parser::new();
        parser.register_audit_log_writer("capture", capture_factory(Arc::clone(&entries)));
        parser.register_audit_log_formatter(format_name, formatter);
        parser
            .from_string(&format!(
                "SecAuditEngine On\nSecAuditLogType CAPTURE\nSecAuditLogFormat {format_name}\nSecAuditLog custom-target"
            ))
            .unwrap();
        (parser, entries)
    }

    #[test]
    fn custom_json_and_text_formatters_reach_the_registered_sink() {
        type FormatterCase = (&'static str, Arc<dyn AuditLogFormatter>, Vec<u8>);
        let cases: [FormatterCase; 2] = [
            (
                "custom-json",
                Arc::new(JsonAuditFormatter),
                br#"{"transaction_id":"audit-json"}"#.to_vec(),
            ),
            (
                "custom-text",
                Arc::new(TextAuditFormatter),
                b"audit:audit-text".to_vec(),
            ),
        ];
        for (name, formatter, expected) in cases {
            let (parser, entries) = capture_parser(name, formatter);
            let waf = parser.compile().unwrap();
            let id = if name == "custom-json" {
                "audit-json"
            } else {
                "audit-text"
            };
            let mut transaction = waf.new_transaction_with_id(id);
            transaction.finish().unwrap();

            let captured = entries.lock().unwrap();
            assert_eq!(captured.len(), 1);
            assert_eq!(captured[0], (id.to_owned(), expected));
        }
    }

    #[test]
    fn custom_formatter_can_read_args_outside_selected_audit_parts() {
        let entries = CapturedEntries::default();
        let mut parser = Parser::new();
        parser.register_audit_log_writer("capture", capture_factory(Arc::clone(&entries)));
        parser.register_audit_log_formatter("args", Arc::new(ArgsAuditFormatter));
        parser
            .from_string(
                "SecAuditEngine On\nSecAuditLogType capture\nSecAuditLogFormat args\nSecAuditLogParts AZ\nSecAuditLog target",
            )
            .unwrap();

        let waf = parser.compile().unwrap();
        let mut transaction = waf.new_transaction_with_id("parts-are-not-a-boundary");
        transaction.process_uri("/?secret=visible", "GET", "HTTP/1.1");
        transaction.finish().unwrap();

        assert_eq!(entries.lock().unwrap()[0].1, b"secret=visible");
    }

    #[test]
    fn audit_registrations_are_parser_scoped() {
        let (parser_a, entries_a) = capture_parser("same-name", Arc::new(TextAuditFormatter));
        let (parser_b, entries_b) = capture_parser("same-name", Arc::new(JsonAuditFormatter));
        let waf_a = parser_a.compile().unwrap();
        let waf_b = parser_b.compile().unwrap();

        let mut transaction_a = waf_a.new_transaction_with_id("parser-a");
        transaction_a.finish().unwrap();
        let mut transaction_b = waf_b.new_transaction_with_id("parser-b");
        transaction_b.finish().unwrap();

        assert_eq!(entries_a.lock().unwrap()[0].1, b"audit:parser-a");
        assert_eq!(entries_b.lock().unwrap()[0].1, br#"{"transaction_id":"parser-b"}"#);
    }

    #[test]
    fn custom_writer_factory_is_not_called_until_activation() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let factory_calls = Arc::clone(&calls);
        let mut parser = Parser::new();
        parser.register_audit_log_writer(
            "lazy",
            Arc::new(move |_config| {
                factory_calls.fetch_add(1, Ordering::Relaxed);
                let writer: Box<dyn AuditLogWriter> = Box::new(CapturingAuditWriter(CapturedEntries::default()));
                Ok(writer)
            }),
        );
        parser
            .from_string("SecAuditEngine On\nSecAuditLogType lazy\nSecAuditLog target")
            .unwrap();

        let waf = parser.compile().unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        waf.activate().unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn custom_type_and_format_names_override_builtins() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("must-not-be-created.log");
        let entries = CapturedEntries::default();
        let mut parser = Parser::new();
        parser.register_audit_log_writer("serial", capture_factory(Arc::clone(&entries)));
        parser.register_audit_log_formatter("native", Arc::new(TextAuditFormatter));
        parser
            .from_string(&format!(
                "SecAuditEngine On\nSecAuditLogType Serial\nSecAuditLogFormat Native\nSecAuditLog {}",
                target.display()
            ))
            .unwrap();

        let waf = parser.compile().unwrap();
        let mut transaction = waf.new_transaction_with_id("collision");
        transaction.finish().unwrap();

        assert!(
            !target.exists(),
            "the built-in serial writer overrode the custom writer"
        );
        assert_eq!(entries.lock().unwrap()[0].1, b"audit:collision");
    }

    #[test]
    fn custom_sink_failures_use_activation_and_finish_errors() {
        let mut parser = Parser::new();
        parser.register_audit_log_writer(
            "broken-open",
            Arc::new(|_config| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "custom sink open failed",
                ))
            }),
        );
        parser
            .from_string("SecAuditEngine On\nSecAuditLogType broken-open\nSecAuditLog target")
            .unwrap();
        let waf = parser.compile().unwrap();

        let activation = waf.activate().unwrap_err();
        assert_eq!(activation.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(waf.activation_error().map(|(kind, _)| kind), Some(activation.kind()));
        let mut transaction = waf.new_transaction_with_id("open-failure");
        assert_eq!(transaction.finish().unwrap_err().kind(), activation.kind());

        let mut parser = Parser::new();
        parser.register_audit_log_writer(
            "broken-write",
            Arc::new(|_config| {
                let writer: Box<dyn AuditLogWriter> = Box::new(FailedAuditWriter);
                Ok(writer)
            }),
        );
        parser
            .from_string("SecAuditEngine On\nSecAuditLogType broken-write\nSecAuditLog target")
            .unwrap();
        let waf = parser.compile().unwrap();
        let mut transaction = waf.new_transaction_with_id("write-failure");
        assert_eq!(
            transaction.finish().unwrap_err().kind(),
            std::io::ErrorKind::StorageFull
        );
        assert!(waf.activation_error().is_none());
    }

    #[test]
    fn audit_directive_resolution_is_not_rewritten_by_later_registration() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("builtin.log");
        let entries = CapturedEntries::default();
        let mut parser = Parser::new();
        parser
        .from_string(&format!(
            "SecAuditEngine On\nSecAuditLogType Serial\nSecAuditLogFormat Native\nSecAuditLog {}\nSecRule ARGS:q \"@contains x\" \"id:1,phase:1,pass\"",
            target.display()
        ))
        .unwrap();
        parser.register_audit_log_writer("serial", capture_factory(Arc::clone(&entries)));
        parser.register_audit_log_formatter("native", Arc::new(TextAuditFormatter));
        let waf = parser.compile().unwrap();
        let mut transaction = waf.new_transaction_with_id("resolved-before-register");
        transaction.finish().unwrap();

        assert!(entries.lock().unwrap().is_empty());
        let output = std::fs::read_to_string(target).unwrap();
        assert!(
            output.contains("-A--\n"),
            "the built-in formatter was not retained: {output}"
        );
    }

    #[test]
    fn unknown_audit_type_and_format_keep_parser_errors() {
        let mut parser = Parser::new();
        assert!(
            parser
                .from_string("SecAuditLogType missing-writer")
                .unwrap_err()
                .message
                .contains("invalid audit log type")
        );

        let mut parser = Parser::new();
        assert!(
            parser
                .from_string("SecAuditLogFormat missing-format")
                .unwrap_err()
                .message
                .contains("invalid audit log format")
        );
    }
}
