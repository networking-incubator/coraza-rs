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
supported writers are serial files or standard output/error, concurrent
files, syslog, and HTTP(S) endpoints. The formatted audit timestamps, the
concurrent audit file names and the `TIME`, `TIME_DAY`, `TIME_HOUR`,
`TIME_MIN`, `TIME_MON`, `TIME_SEC`, `TIME_WDAY` and `TIME_YEAR` variables use
the process local time zone, as in Go Coraza: the zone named by `TZ` at
startup, or the one `/etc/localtime` records. The JSON `unix_timestamp`, the
OCSF `time`, `start_time` and `metadata.logged_time`, and `TIME_EPOCH` remain
absolute epoch values.

`SecAuditLogType HTTPS` requires the `https-audit` crate feature; without it the
WAF is built with that writer rejected, never silently replaced by another one.
With the feature, each entry is POSTed to `SecAuditLog` with a one-second
timeout, as in Go Coraza. The target must be an absolute `http://` or
`https://` URL with a host; anything else is rejected when the WAF is built.
This is stricter than Go Coraza, which accepts such a target at init and only
fails when the first entry is written. Entries sent to a plaintext `http://`
target are not encrypted.

The feature uses `rustls` with the compiled-in Mozilla root bundle
(`webpki-roots`), not the host trust store. Certificates issued by a private CA
that is installed only in the host trust store are therefore not trusted; use
an endpoint with a public-CA certificate or terminate TLS at a local proxy.
Redirects are followed as in Go Coraza, except that a 307 or 308 response fails
the write instead of re-POSTing the entry.

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
