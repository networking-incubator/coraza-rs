# Coraza Rust crate

`coraza` is a separate Rust implementation based on the original Coraza. It
provides SecLang parsing, request and response phase processing, and audit
logging. It is not the upstream Go implementation. The `exec`, `initcol`, and
`expirevar` action effects are not implemented.

## Audit logging

Configure audit logging through SecLang:

```text
SecAuditEngine RelevantOnly
SecAuditLog /var/log/coraza/audit.log
SecAuditLogFormat JSON
SecAuditLogParts ABFHKZ
```

For `SecAuditLogType HTTPS`, `SecAuditLog` is the endpoint URL instead of a
path, for example `SecAuditLog https://collector.example/audit`.

The supported formats are `Native`, `JSON`, `JSONLegacy`, and `OCSF`. The
supported writers are serial files or standard output/error, concurrent files,
syslog, and HTTP(S) endpoints. Audit timestamps are UTC, while Go Coraza uses
the process local time zone.

`SecAuditLogType HTTPS` requires the `https-audit` crate feature; without it the
WAF is built with that writer rejected, never silently replaced by another one.
With the feature, each entry is POSTed to `SecAuditLog` with a one-second
timeout, as in Go Coraza. The target may be `http://` or `https://`, as Go
Coraza accepts both, so entries sent to a plaintext target are not encrypted.

Call `Transaction::process_logging` after response processing when the caller
needs to observe audit writer errors. Dropping a transaction runs the logging
phase automatically and ignores writer errors. `Parser::on_error_log` provides
a synchronous callback for matched rules with the `log` action; use
`MatchedRule::error_log` to format the Coraza-compatible line.

The audit parts control which headers, bodies, files, and rule details are
retained and written. Body capture is bounded by the configured request and
response body limits. Review the selected parts and storage permissions before
enabling audit logging for sensitive traffic.

## FTW integration

The [FTW runner guide](../ftw-runner/README.md) covers the optional go-ftw
server and a checked-in smoke test. The harness exercises the Coraza crate
through a test HTTP adapter; its results do not establish complete Go Coraza
compatibility.
