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

Parsing and compiling a policy does not activate its audit resources:
`Parser::compile` validates the configuration and returns a `Waf` without
creating or connecting audit files or sockets, so a candidate policy can be
discarded safely. Parsing does still create and immediately remove one probe
file in `SecUploadDir` to check that the directory is writable, as Go Coraza
does. `Waf::activate` opens the writer explicitly, retries a failed activation,
and is idempotent; the first `Waf::new_transaction` also activates it, so
existing embedders keep the same behavior. A transaction's activation failure
is memoised and surfaces from `Transaction::finish`, not retried per
transaction. `Parser::into_waf` is an alias for `Parser::compile`.

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

Call `Transaction::finish` after response processing when the caller needs to
observe the terminal outcome. It writes the audit entry at most once: a
successful write makes later calls return `Ok(())` without writing again, and a
failed write is stored and returned by this and every later call; it is never
retried. `Transaction::process_logging` remains as an alias, so it also removes
temporary upload files and returns their cleanup errors. Dropping a transaction
calls `finish` and ignores its error. `Parser::on_error_log` provides a
synchronous callback for matched rules with the `log` action; use
`MatchedRule::error_log` to format the Coraza-compatible line.

`finish` also removes temporary upload files unless `SecUploadKeepFiles` keeps
them: `On` keeps all files and `RelevantOnly` keeps them only when a matched
rule has the `log` action enabled, excluding `nolog`. A removal failure is
returned from `finish`, as Go Coraza's `Close` does, and cleanup is not retried
on a later call. The default, `Off`, deletes every temporary file.

`WafConfig::audit_log_connect_timeout` and `audit_log_write_timeout` are opt-in
deadlines for the syslog writer, with no SecLang directive, so the default
remains Go's unbounded behavior. The connect deadline covers TCP targets and
their reconnect; the write deadline covers TCP, UDP, and Unix sockets where the
platform supports a write deadline. DNS resolution is bounded by neither
deadline: a resolver that never answers keeps the writer call blocked. File
writes have no deadline, because a regular file write cannot time out, and
neither Go nor this crate adds one. HTTPS keeps its one-second whole-request
timeout regardless of these settings.

The audit parts control which headers, bodies, files, and rule details are
retained and written. Body capture is bounded by the configured request and
response body limits. Review the selected parts and storage permissions before
enabling audit logging for sensitive traffic.

## Operators

The default build compiles the built-in operators. Three upstream operators
live behind the `inspect-file`, `rbl` and `validate-schema` crate features,
with `host-operators` as the umbrella for the first two. Without its feature
the name is rejected when the `SecRule` is compiled, never silently mapped to
another operator:

- `inspect-file` adds `@inspectFile`, which runs a local program with the
  inspected value as its only argument. A first output byte other than `1`
  matches, a non-zero exit status does not. On Unix both streams share one
  socket, so the combined output keeps the program's write order like Go's
  `CombinedOutput`; other platforms use separate pipes and read stdout before
  stderr. The 10-second deadline also bounds the exit wait, killing and reaping
  a program that overruns it, and the retained output is capped at 1 MiB. An
  over-cap run, a spawn failure, or a missed deadline reports
  `OperatorOutcome::NotInspected`, which a rule treats as a miss;
  `Operator::evaluate` still returns `false`. The value is raw bytes on Unix
  and converted lossily elsewhere.
- `rbl` adds `@rbl`, which resolves a DNS blocklist. It queries A/AAAA records
  only: it does not read the TXT record, set `TX.httpbl_msg`, or copy the
  message into capture 0, so an address with a record but no TXT entry matches
  here where Go reports no match. A resolver failure, a lookup past the 500 ms
  budget, and the 64-lookups-in-flight cap report `NotInspected` instead of a
  plain miss. An empty or whitespace-only service is rejected at load time,
  where Go accepts it.
- `host-operators` is the umbrella feature that enables `inspect-file` and
  `rbl`.
- `validate-schema` adds `@validateSchema`, which validates JSON documents. The
  schema path must be relative, contain no `..` component, and canonicalise
  under the configured base directory; files over 1 MiB and non-regular files
  are rejected, and a compile error never quotes the schema. The dialect is
  pinned to 2020-12 while a document `$schema` still selects its own draft, the
  engine is this crate's `jsonschema` rather than Go's, external `$ref` targets
  are disabled, and `format` is an annotation only. A `pattern` that cannot
  complete counts as a violation. Each operator compiles its own schema
  instead of sharing Go's content-keyed memoizer.

`Parser::register_operator` registers an embedder factory under a name, matched
case-insensitively and consulted before the built-in names, so an embedder can
add or override an operator. Registering the same name again replaces the
earlier factory. A registered operator must be `Send` and `Sync`.

## Migrating from the previous API

- `WafConfig::upload_keep_files` is an `UploadKeepFiles` (`Off`, `On`,
  `RelevantOnly`) instead of a `bool`.
- `WafConfig` has new `audit_log_connect_timeout` and `audit_log_write_timeout`
  fields; both default to `None`.
- `Transaction::process_logging` now removes temporary uploads and returns
  their cleanup errors, like `finish`, and the audit write is attempted at most
  once instead of being retried.
- `Operator` now requires `Send + Sync`.
- `OperatorContext` has a new `custom` field for registered operators, and
  `OperatorEnum` has a new `Custom(Registered)` variant.
- `CustomOperators` is now a struct with `insert`, `get`, `keys`, and
  `is_empty`, not a bare map.

## FTW integration

The [FTW runner guide](../ftw-runner/README.md) covers the optional go-ftw
server and a checked-in smoke test. The harness exercises the Coraza crate
through a test HTTP adapter; its results do not establish complete Go Coraza
compatibility.
