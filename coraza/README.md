# Coraza Rust crate

`coraza` is a separate Rust implementation based on the original Coraza. It
provides SecLang parsing, request and response phase processing, and audit
logging. It is not the upstream Go implementation. The `exec`, `initcol`, and
`expirevar` action effects are not implemented.

## FIPS build profile

The `hash-transformations` feature (enabled by default) preserves the existing
`t:md5` and `t:sha1` behavior. The `fips` Cargo feature makes both return their
input unchanged, with `changed == false` and an error (`md5 transformation is
unavailable in FIPS 140-3 mode` or `sha1 transformation is unavailable in FIPS
140-3 mode`). It is a build profile, not runtime `GODEBUG=fips140` detection.
In FIPS mode, the hash transformations return the input unchanged and their
transformation error is currently not surfaced during rule evaluation.
Use `--no-default-features --features fips` for a digest-free FIPS build (for
example, `cargo test -p coraza --no-default-features --features fips`). Cargo
features are additive, so plain `--features fips` keeps the default hash
dependencies but still selects FIPS behavior. Disabling default features
without `fips` also omits the hashes, which then return a build-feature error.

## Multiphase evaluation profile

Set `WafConfig::multiphase_evaluation` before compiling rules to let a rule run
in an earlier processing phase when its variables are already available. This
runtime, per-WAF setting is the equivalent of Go Coraza's
`coraza.rule.multiphase_evaluation` build tag; it is not a Cargo feature or a
per-transaction switch. The default is `false`, preserving the ordinary
phase-matched evaluation behavior. A compiled rule set cannot be paired with a
WAF config that changes this setting.

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
does. `Waf::activate` opens the writer explicitly, retries a failed activation
immediately, and is idempotent. The first `Transaction::finish` that writes an
entry also activates it. A failed activation is memoised: `finish` reports it,
later transactions keep reporting it while the retry window is open, and the
next attempt after the window retries. The window starts at 30 seconds and
doubles after every failure up to five minutes, so a sink that stays down costs
at most one attempt per window. `Waf::new_transaction` never opens a sink, so a
connector's request path does not pay for a dial. `Waf::activation_error()`
returns the last failure with its `io::ErrorKind`, and `Waf::activate` returns
the dial error itself with its kind: a writer that cannot be opened is not a
configuration error. `Parser::into_waf` is an alias for `Parser::compile`.

The supported formats are `Native`, `JSON`, `JSONLegacy`, and `OCSF`. The
supported writers are serial files or standard output/error, concurrent
files, syslog, and HTTP(S) endpoints. The formatted audit timestamps, the
concurrent audit file names and the `TIME`, `TIME_DAY`, `TIME_HOUR`,
`TIME_MIN`, `TIME_MON`, `TIME_SEC`, `TIME_WDAY` and `TIME_YEAR` variables use
the process local time zone, as in Go Coraza: the zone named by `TZ` at
startup, or the one `/etc/localtime` records. The JSON `unix_timestamp`, the
OCSF `time`, `start_time` and `metadata.logged_time`, and `TIME_EPOCH` remain
absolute epoch values.

Embedders can register parser-scoped `AuditLogFormatter` and `AuditLogWriter`
implementations with `Parser::register_audit_log_formatter` and
`Parser::register_audit_log_writer`. Names are case-insensitive, and a custom
registration wins over a built-in name. The writer factory receives the
resolved `WafConfig` and is called only on `Waf::activate` or the first audit
write; it must not open a file or socket before then. Writers receive both the
`AuditLog` and its already-formatted bytes. This crate supplies no custom writer
for WASI; an embedder must provide one that avoids filesystem and socket calls.

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
failed write is stored and returned by this and every later call; the
transaction layer never retries it. The syslog writer below that layer still
reconnects and re-sends one frame after a write failure, so such a sink may
receive an entry twice. `Transaction::process_logging` remains as an alias, so
it also removes temporary upload files and returns their cleanup errors.
Dropping a transaction calls `finish` and ignores its error.
`Parser::on_error_log` provides a synchronous callback for matched rules with
the `log` action; use `MatchedRule::error_log` to format the
Coraza-compatible line.

`finish` also removes temporary upload files unless `SecUploadKeepFiles` keeps
them: `On` keeps all files and `RelevantOnly` keeps them only when a matched
rule has the `log` action enabled, excluding `nolog`. A removal failure is
returned from `finish`, as Go Coraza's `Close` does, and cleanup is not retried
on a later call. The default, `Off`, deletes every temporary file.

`WafConfig::audit_log_connect_timeout` and `audit_log_write_timeout` are opt-in
deadlines for the syslog writer, with no SecLang directive. The connect
deadline covers TCP targets and their reconnect; the write deadline covers TCP,
UDP, and Unix sockets where the platform supports a write deadline. DNS
resolution is bounded by neither deadline: a resolver that never answers keeps
the writer call blocked. File writes have no deadline, because a regular file
write cannot time out, and neither Go nor this crate adds one. HTTPS keeps its
one-second whole-request timeout regardless of these settings.

An unset connect deadline means two different things. `Waf::activate` is the
explicit path and keeps Go's unbounded dial. Activation triggered by
`Transaction::finish` is on a request thread, so it applies five seconds when
no deadline is configured: a blackholed syslog peer would otherwise park that
thread for the kernel's SYN timeout, about two minutes. This is a deliberate
safety deviation from Go Coraza, whose dial is unbounded.

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
  matches; for a run that stays within the 1 MiB output cap, a non-zero exit
  status does not. On Unix both streams share one socket, so the combined output
  keeps the program's write order like Go's `CombinedOutput`; other platforms
  use separate pipes and read stdout before stderr, so an over-cap verdict can
  be decided from stderr there. The 10-second deadline bounds the program and
  its exit wait: a killed program is reaped within a short grace, and one stuck
  in uninterruptible sleep is left to be reaped when the process exits rather
  than parking the caller. On Unix an abandoned reader is stopped and joined
  before the call returns; on other platforms a reader a surviving descendant
  keeps blocked is detached instead and holds one descriptor and at most the cap
  until the last write end closes. The retained output is capped at 1 MiB: an
  over-cap run keeps the collected prefix, and since Go's verdict is only the
  first output byte, that byte still decides it before the run is abandoned. The
  exit status is not consulted for an over-cap run, so a program that writes
  more than the cap and then exits non-zero matches here, where Go reads the
  whole output and returns false. A spawn failure, a read error, or a missed
  deadline reports `OperatorOutcome::NotMatched`, because Go returns `false` for
  every error, so a negated `!@inspectFile` matches on failure exactly as it does
  in Go. At most 64 runs execute at once in a process; a run above that cap is a
  plain miss. The value is raw bytes on Unix and converted lossily elsewhere. An
  empty or whitespace-only program is rejected when the rule loads, where Go
  accepts it and fails on every value.
- `rbl` adds `@rbl`, which resolves a DNS blocklist. It queries A/AAAA records
  only: it does not read the TXT record, set `TX.httpbl_msg`, or copy the
  message into capture 0, so an address with a record but no TXT entry matches
  here where Go reports no match. The configured service is trimmed and must be
  non-empty at load, where Go appends it verbatim; the value is decoded lossily
  before it is appended, so invalid UTF-8 reaches the resolver as U+FFFD. A
  resolver failure is a plain miss, as in Go. A lookup past the 500 ms budget,
  above the 64-lookups-in-flight cap, or a failed lookup-thread spawn reports
  `NotMatched` too, because Go returns `false` on its timeout; a negated
  `!@rbl` therefore matches on failure exactly as it does in Go. No
  host-operator outcome sets `TX.inspection_incomplete` or triggers
  `FailClosed`.
- `host-operators` is the umbrella feature that enables `inspect-file` and
  `rbl`.
- `validate-schema` adds `@validateSchema`, which validates JSON documents.
  Go's pinned `kaptinlin/jsonschema` compiler parses `$schema` but never
  consults it and compiles every schema as 2020-12; this port does the same, so
  an unknown `$schema` still loads and a draft-07-only keyword shape such as
  tuple `items` or a boolean `exclusiveMinimum` is a compile error. `format` is
  not asserted in either engine: Go leaves the compiler's `AssertFormat` off
  (`compiler.go:65`) and 2020-12 makes `format` an annotation, so
  `"format": "email"` accepts `not-an-email` whatever `$schema` declares. A
  schema that declares draft-04/6/7 used to assert its formats, because the old
  code let `$schema` select the draft, so a rule that relied on `format` as a
  validator now accepts those values. The schema path must be relative, contain
  no `..` component, name a `.json` file, and canonicalise under the configured
  base directory. The type and size are read from the opened descriptor, and on
  Linux the descriptor's own path is confined again, which catches a symlink
  swapped in before the open. On other platforms the check and the open are two
  steps, so a writer inside the configured root can win that window: the schema
  directory must be writable only by the process' own configuration source.
  Files over 1 MiB and non-regular files are rejected, a compile error never
  quotes the schema, external `$ref` targets are disabled, and each operator
  compiles its own schema instead of sharing Go's content-keyed memoizer. A
  `pattern` that cannot complete counts as a violation.

`Parser::register_operator` registers an embedder factory under a name, matched
case-insensitively and consulted before the built-in names, so an embedder can
add or override an operator. Registering the same name again replaces the
earlier factory. A registered operator must be `Send` and `Sync`.

## Migrating from the previous release

- `WafConfig::upload_keep_files` is an `UploadKeepFiles` (`Off`, `On`,
  `RelevantOnly`) instead of a `bool`.
- `WafConfig` has new `audit_log_connect_timeout` and `audit_log_write_timeout`
  fields; both default to `None`, and an unset connect deadline is bounded for
  internal activation and unbounded for `Waf::activate`.
- `Operator` now requires `Send + Sync`.
- `OperatorContext` has a new `custom` field for registered operators, and
  `OperatorEnum` has a new `Custom(Registered)` variant.
- `OperatorEnum` also has three feature-gated variants: `InspectFile`
  (`inspect-file`), `Rbl` (`rbl`) and `ValidateSchema` (`validate-schema`). A
  match over `OperatorEnum` was already exhaustive over the built-in variants,
  so it needs the new arms, guarded by the same features.
- `CustomOperators` is now a struct with `insert`, `get`, `keys`, and
  `is_empty`, not a bare map.
- `Transaction::finish` is new: it runs the logging phase, writes the audit
  entry when one is due, removes temporary uploads and returns the stored
  terminal failure. `Transaction::process_logging` is now an alias for it.
- `Waf::activate` returns `std::io::Result<()>` and `Waf::activation_error`
  returns `Option<(std::io::ErrorKind, String)>`, so a sink failure keeps its
  error kind. It is not a `ConfigError`: only `Waf::new` and `Parser::compile`
  report configuration errors.
- `Waf::new` and `Parser::compile` no longer fail when the audit sink cannot be
  opened: they validate it and defer activation to `Waf::activate` or the first
  `Transaction::finish` that writes an entry. A failed activation is reported by
  `finish`, retried after a retry window that starts at 30 seconds and doubles
  up to five minutes, and also visible through `Waf::activation_error()`.

### Behavior changes

- Argument regex selectors and exceptions no longer fold case.
  `ARGS:/^userId$/` matched both `UserId` and `USERID` before and matches
  neither now, because the pattern runs as written against the folded lookup
  key. `case_sensitive_args_keys` now only selects the argument map mode; it no
  longer changes how selectors are compiled.
- `*_NAMES` literal selectors are exact lookups. `ARGS_GET_NAMES:Id` no longer
  finds a stored `id` in the default folded map. `ARGS_PATH` literals are
  lowered like Go, so `ARGS_PATH:UserId` becomes `userid` and, under
  `case_sensitive_args_keys`, no longer selects a stored `UserId`.
- Count-mode `MATCHED_VAR_NAME` reports Go's compile-time key instead of an
  empty string, qualified by the variable as Go's `matchVariable` does:
  `&ARGS:/re/` reports `ARGS:/re/` and `&REQUEST_HEADERS:X-Foo` reports
  `REQUEST_HEADERS:x-foo`, because the key is lowered for variables outside the
  case-sensitive selector set.
- `RESPONSE_CONTENT_TYPE` keeps the last `Content-Type` header, as Go does, and
  stores the raw bytes before the first `;` without trimming. Response-body MIME
  selection is an exact comparison, not a case-insensitive one.
- `TX:0` through `TX:10` are always present and empty on a fresh transaction.
  `TX:0` through `TX:9` are cleared before every rule, so `TX:10` persists.
  This mirrors Go's seed of `TX:0` through `TX:10` and its reset of `TX:0`
  through `TX:9`, which leaves `TX:10` alone. The clear itself is a deliberate
  deviation: Go's `resetCaptures` exists but only its tests call it, so a Go
  rule can see the previous rule's captures.
- `percent_decode_lenient` no longer decodes `%+1`: only ASCII hexadecimal
  digits are accepted, as Go's `fromHex` does.
- `@validateSchema` no longer asserts `format` for a schema that declares
  draft-04/6/7. Every schema is compiled as 2020-12, where `format` is an
  annotation, as Go's pinned compiler already treats it (`AssertFormat` off), so
  `"format": "email"` now accepts `not-an-email` even under a draft-07
  `$schema`. A rule that used `format` as a validator must check the value with
  another operator.
- `Transaction::process_logging` now removes temporary uploads and returns their
  cleanup errors, like `finish`, and the transaction attempts the audit write at
  most once instead of retrying it. The syslog writer still reconnects and
  re-sends one frame after a write failure.

## FTW integration

The [FTW runner guide](../ftw-runner/README.md) covers the optional go-ftw
server and a checked-in smoke test. The harness exercises the Coraza crate
through a test HTTP adapter; its results do not establish complete Go Coraza
compatibility.
