# Coraza Rust crate

`coraza` is a separate Rust implementation based on the original Coraza. It
provides SecLang parsing, request and response phase processing, and audit
logging. It is not the upstream Go implementation. The `exec`, `initcol`, and
`expirevar` action effects are not implemented.

## Recommended configuration

[`coraza.conf-recommended`](coraza.conf-recommended) is a verbatim copy of the
recommended engine configuration that the pinned Go Coraza release ships
(Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors,
Apache-2.0). `cargo xtask go-fixtures-check` compares it with that release byte
for byte, and `cargo xtask go-fixtures-refresh` updates it with the other Go
fixtures. The text is also available as `coraza::seclang::RECOMMENDED_CONF`:

```rust
use coraza::{
    Waf,
    seclang::{Parser, RECOMMENDED_CONF},
};

fn waf() -> Result<Waf, Box<dyn std::error::Error>> {
    let mut parser = Parser::new();
    parser.from_string(RECOMMENDED_CONF)?;
    parser.from_string("SecRuleEngine On")?;
    Ok(parser.into_waf()?)
}
```

Load it before any rule set, the OWASP CRS included, then turn blocking on: like
upstream, it starts in `DetectionOnly`. Its rules are the fail-closed baseline for
the engine's error flags. The CRS reads none of these flags, so without the
baseline a body the engine could not parse is neither inspected nor blocked:

- 200002 denies a request whose body processor failed (`REQBODY_ERROR`).
- 200003 denies a multipart body that failed strict validation
  (`MULTIPART_STRICT_ERROR`).
- 200004 and 200005 deny a request whose arguments or cookies were dropped at
  `SecArgumentsLimit` (`ARGUMENTS_LIMIT_REACHED`).
- 200009 denies a request target that does not parse (`URI_PARSE_ERROR`).
- 200000, 200001 and 200006 select the XML and JSON body processors, which the
  engine does not pick from the content type on its own.

The file sets `SecRequestBodyInMemoryLimit` and `SecDataDir`, which need a
filesystem. The envoy-coraza filter embeds a copy without those two directives,
and without its `SecRuleEngine DetectionOnly`, as `@recommended-conf`.

### CRS rules 905100 and 905110

CRS rules 905100 and 905110 are Apache exceptions that remove every CRS rule,
and the audit record, for a loopback `REMOTE_ADDR` and the request line `GET /`
(905100) or, with a `User-Agent` ending in `(internal dummy connection)`,
`GET /` or `OPTIONS *` (905110). Behind a proxy the client may choose that
address, and no proxy sends such requests itself. An embedder that loads the
CRS removes them after the rules:

```text
Include /path/to/crs/crs-setup.conf
Include /path/to/crs/rules/*.conf
SecRuleRemoveById 905100 905110
```

The removal must come **after** `Include .../rules/*.conf`: placed before it,
for example in `crs-setup.conf`, it removes nothing, because the rules do not
exist yet. The envoy-coraza build with the embedded CRS already replaces the
file that holds them with a comment-only stub; a deployment that supplies the
CRS through `rule_data` adds the removal itself.

## Extension seams

| Seam | Registration/API | Contract |
| --- | --- | --- |
| Operators | `Parser::register_operator` | [Operators](#operators) |
| Transformations | `CustomTransformation`, `Parser::register_transformation` | [Custom transformations](#custom-transformations) |
| Actions | `CustomAction`, `Parser::register_action` | [Custom actions](#custom-actions) |
| Audit writers and formatters | `Parser::register_audit_log_writer` / `register_audit_log_formatter` | [Audit logging](#audit-logging) |
| Body processors | `BodyProcessor`, `Parser::register_body_processor` | [Custom body processors](#custom-body-processors) |
| Rule observer | `Parser::on_rule` | [Rule observer](#rule-observer) |

These host implementations run synchronously in the engine. Review each
section's execution, lifetime, and trust-boundary constraints before registering
custom code.

## FIPS build profile

The `hash-transformations` feature (enabled by default) preserves the existing
`t:md5` and `t:sha1` behavior. The `fips` Cargo feature makes both return their
input unchanged, with `changed == false` and an error (`md5 transformation is
unavailable in FIPS 140-3 mode` or `sha1 transformation is unavailable in FIPS
140-3 mode`). It is a build profile, not runtime `GODEBUG=fips140` detection.
In FIPS mode, the hash transformations return the input unchanged and their
transformation error is reported at the debug logger's warning level for each
argument evaluation.
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

## Debug logging

`SecDebugLog` selects an append-only path; `/dev/stdout` and `/dev/stderr` select
the standard streams. `SecDebugLogLevel` accepts levels 0 through 9: 0 disables
logging, 1-3 enable error/warn/info, 4-8 enable debug, and 9 enables trace.
The default is 0. Parsing and compiling a policy do not open the debug sink;
`Waf::activate` opens it explicitly, or the first enabled event opens it lazily.
An open failure is returned by `Waf::activate` and is also available through
`Waf::debug_log_error`.

`ctl:debugLogLevel=N` changes the threshold only for the current transaction.
Hosts can supply a `DebugLogger` with `Parser::with_debug_logger` or
`Waf::with_debug_logger`; the configured level still filters its events. Debug
events do not include request values by default. Trace logging can include
matched/argument values, body processor error details, and interruption details,
so enable it only when that data may be written to the selected sink.

Debug logger calls are synchronous on the request thread. The built-in `Writer`
holds its shared sink lock while opening and writing, so a slow or blocked sink
(including a full stdout/stderr pipe) blocks that transaction and serializes
other transactions sharing the writer. `Writer` is intended for development and
diagnostics, not high-throughput production logging. Hosts that cannot tolerate
this must provide their own buffered or asynchronous `DebugLogger`.

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
registration wins over a built-in name. Register each name **before** calling
`Parser::from_string` on directives that select it: `SecAuditLogType` and
`SecAuditLogFormat` are resolved during parsing. If parsing fails because a name
is unknown, register it and re-parse the selecting directives; later registration
does not revise a failed or already-parsed selection. These registrations are
parser state, not `WafConfig` fields: `WafConfig` equality compares configuration
only, so two WAFs with equal configs can use different custom implementations.

**Security:** `SecAuditLogParts` controls what built-in formatters serialize; it
is **not a confidentiality boundary** for custom formatters or writers. Custom
code receives the full `AuditLog` entry, including `ARGS` even when those parts
are not selected. The host is trusted code and must redact sensitive data itself.
The writer factory receives the resolved `WafConfig` and is called only on
`Waf::activate` or the first audit write; it must not open a file or socket
before then. Writers receive the `AuditLog`, its already-formatted bytes, and the
MIME type declared by the formatter that produced those bytes.
That MIME type must remain stable for the formatter's lifetime: built-in sinks
capture it at activation and pair it with later bytes. A formatter that varies
its MIME type violates the contract; debug builds check this for custom writers.
The engine drops a writer with its audit logger and does not call fallible
teardown; a host that needs fallible teardown must own the sink outside the
`AuditLogWriter` trait. This crate supplies no custom writer for WASI; an embedder
must provide one that avoids filesystem and socket calls.

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

The audit parts control which sections built-in formatters serialize. They do
not filter fields visible to custom formatters or writers (see the security note
above). Body capture is bounded by the configured request and response body
limits. Review the selected parts and storage permissions before enabling audit
logging for sensitive traffic.

The error line of a rule (`MatchedRule::error_log`, and part `H`'s per-message
error line) cuts the first match's `msg` and `data` at 280 bytes, as Go does,
and the request `[uri]` at 1 KiB, followed by `[+N uri bytes]` when it was cut
(the whole request line stays in part `B`). For the other matches that have a
message or data it lists the first eight `[msg_match_N ...] [data_match_N ...]`
pairs and, when more remain, ends with `[+N more matches]`. Go lists every pair
and the whole URI. Part `K` still lists every match. Every message of a rule
carries this line, so without these limits `H` and `K` together made the entry
quadratic in the matches of one rule and, with a long URI, the URI length times
the matches. With them each line has a bounded size and the entry grows
linearly with the rule's matches Q (about 0.8 KB per match in the test shape,
1.9 MB for 1000 matches of one rule with a 60 KB path).

## Custom transformations

Implement `coraza::transformations::CustomTransformation` and register it with
`Parser::register_transformation`. Names are case-insensitive; a custom
registration overrides a built-in and a later registration replaces an earlier
one. Each `t:` action resolves when its rule is compiled, so later registrations
do not change existing rules or compiled WAFs. Implementations receive
untrusted input bytes. If a transformation returns an error, its output is
discarded, the previous value is kept, and the chain continues. Custom
transformations run synchronously on the request path. The engine enforces
neither a timeout nor an output-size bound, and a transformation can panic or
block its caller. Registrations must be trusted host code; the host must bound
its own work and output and avoid panics.

## Custom actions

Implement `coraza::actions::CustomAction` and register a factory with
`Parser::register_action`. Names are case-insensitive; a custom action overrides
a built-in name except for the reserved metadata-only names listed in the
[root README](../README.md#custom-actions). The factory resolves while each
action is compiled, so later registrations do not rewrite compiled rules.

`ActionType` chooses when the action runs (`Nondisruptive`, `Flow`, or
`Disruptive`); it does not restrict what the implementation can do. A custom
action receives read-only `RuleMetadata` and a mutable `Transaction`, and can
use `interrupt`, `allow`, `set_skip`, and `set_skip_after` for rule-flow effects.
Keep effects consistent with the declared type. Actions execute synchronously
on the request thread; the engine provides neither panic catching nor a
timeout, so register only trusted implementations that do not panic or block.

## Custom body processors

Implement `coraza::BodyProcessor` and register a factory with
`Parser::register_body_processor`. Names are case-insensitive, custom names
override built-ins when selected by `ctl:requestBodyProcessor` or
`ctl:responseBodyProcessor`, and each selecting rule captures the factory when
compiled. A later registration does not rewrite an existing rule or WAF.
Content-Type selection remains built-in (URLENCODED and MULTIPART); it never
selects a custom processor. `BodyProcessorOptions` supplies the transaction's
resolved MIME, argument and upload limits, upload directory/mode/retention policy,
and request/response truncation and data-error state. Recursion limits are
advisory for custom processors and enforced only by built-ins; a truncated body
passed to a processor is the prefix retained by the engine.
`truncated` means bytes were actually discarded; reaching a body limit at the
`>=` boundary can still set the direction's data-error flag. Processor errors
and reported names are capped at 256 UTF-8 bytes to retain useful diagnostic
context while bounding transaction and log storage.

Processors can publish arguments, files, XML paths, a processor name, and an
error through `BodyProcessorOutput`; they do not receive `Transaction` access.
Request arguments enter `ARGS_POST` and `ARGS`, response arguments enter
`RESPONSE_ARGS`, and XML values enter `REQUEST_XML` or `RESPONSE_XML` by
direction. File bytes are written by the engine to its private temporary-file
path and populate `FILES`, `FILES_NAMES`, `FILES_SIZES`, `FILES_TMPNAMES`,
`FILES_COMBINED_SIZE`, `MULTIPART_NAME`, `MULTIPART_FILENAME`, and
`MULTIPART_PART_HEADERS`; the processor cannot supply a path. Argument/file
limit drops follow the transaction's existing flags. A
processor error (returned or set with `set_error`) sets the corresponding
`REQBODY_*` or response body error variables while retaining output already
published. The engine caps cumulative output bytes at the applicable request or response
body limit; exceeding it stops further output, keeps output already accepted,
and sets the direction's data-error and body-processor error variables.
`set_processor` is host-reported and not authoritative: it may differ
from the name selected by `ctl`, and the reported name is also used in body-error
message prefixes.

Custom files cannot reproduce a built-in multipart file's wire part headers:
the deliberately narrow `add_file(name, filename, content_type, bytes)` API has
no raw-part-header input, so `MULTIPART_PART_HEADERS` contains only
`Content-Type: <content_type>`. Rules that depend on wire part headers, including
`Content-Disposition`, must use the built-in multipart processor.

**Security and host hazard:** factories and processors run synchronously on the
transaction path, with no timeout and no panic catching. The zero-argument
factory receives no body; the processor receives attacker-controlled body bytes.
Both must not panic or block indefinitely, and processors must bound their own
work and honor the supplied limits. File output is rejected on WASI until a
connector supplies a memory-backed sink.

## Rule observer

`Parser::on_rule` registers a parser-scoped host callback for rule metadata. It is
called synchronously after each top-level rule is inserted during parsing. A
chain starter is observed once; its member links are not. This reports insertion
events, not the final surviving set: with `skip_failed_directives`, a starter may
already have been reported before a later failed link discards the whole chain.
Rejected rules are not observed. Calling `on_rule` again replaces the previous
callback. The compiled `Waf` retains only its compiled rules; the observer does
not run after compilation.

The callback must not panic or attempt to mutate the rule set. The engine does
not catch a panic; partial parser state may remain, and unwinding from
`Parser::from_string` skips file/line restoration. Do not reuse a parser after an
observer panic.

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
  `!@rbl` therefore matches on failure exactly as it does in Go.
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

`@rx` is dot-all: `.` matches a newline. A positive `@rx` is also multi-line,
as in Go, so an anchored pattern matches when one line of the value does. A
negated `!@rx` is not: `^` and `$` anchor the whole value, so
`!@rx ^[0-9]+$` fires on `123` followed by a newline and `' OR 1=1--`, where Go
stays silent. A negated rule that needs per-line anchors writes `(?m)`. A
pattern with a `\xHH` escape that is not valid UTF-8 runs on raw bytes with the
same flags; Go compiles that one without any flag.

`Parser::register_operator` registers an embedder factory under a name, matched
case-insensitively and consulted before the built-in names, so an embedder can
add or override an operator. Registering the same name again replaces the
earlier factory. A registered operator must be `Send` and `Sync`.

## Migrating from the previous release

- `Transaction::with_config` now applies the same configuration checks as
  `Waf::new` for a rule-less WAF and panics on an invalid body limit instead of
  building a transaction that inspects nothing. It still does not validate
  audit-log sinks. `Transaction::try_with_config` is the fallible form.
- `WafConfig::multiphase_evaluation` is a new runtime setting, defaulting to
  `false`. Set it before compiling rules; a compiled rule set cannot be paired
  with a WAF whose setting differs. It replaces the equivalent Go build-tag
  choice for this Rust crate.
- `AllowScope::{All, Phase, Request}` and `Transaction::allow` are new public
  APIs for custom actions. `Transaction::interrupt`, `set_skip`, and
  `set_skip_after` are also public so host actions can express disruptive and
  flow effects.
- `ActionType` and `RuleMetadata` are public custom-action APIs. Metadata is
  read through `id`, `phase`, `status`, `log`, and `audit_log` getters;
  `ActionType` is a scheduling declaration, not an enforced capability limit.
- `DebugLogger` and its event types are public. Supply a shared implementation
  with `Parser::with_debug_logger` or `Waf::with_debug_logger`; the configured
  debug level still filters calls. Debug events are synchronous, and a slow
  logger can block request processing.
- `SecDebugLog` and `SecDebugLogLevel` now emit engine events. The default level
  remains 0 (off), and configured sinks open only on `Waf::activate` or the first
  enabled event.
- `WafConfig::upload_keep_files` is an `UploadKeepFiles` (`Off`, `On`,
  `RelevantOnly`) instead of a `bool`.
- `WafConfig` has new `audit_log_connect_timeout` and `audit_log_write_timeout`
  fields; both default to `None`, and an unset connect deadline is bounded for
  internal activation and unbounded for `Waf::activate`.
- `WafConfig` has new public `audit_log_custom_type` and
  `audit_log_custom_format` fields (hidden from generated docs). This pre-1.0 API
  addition breaks exhaustive struct literals and patterns; literals now need
  `..Default::default()` and patterns need `..` to remain forward compatible.
- `AuditMessage` has two new public fields (hidden from generated docs):
  `rule_id: i32`, which bounded audit formatting uses to keep the interrupting
  rule's message, and `rule_message: String`, which a reduced bounded record
  uses to name the rule of a message that has part `H` but no part `K`. Neither
  is serialised in a record that fits. This pre-1.0 addition breaks code that
  builds an `AuditMessage` with every field named. Set the new fields, or end
  the literal with `..AuditMessage::default()` (the type implements `Default`)
  when a fixture needs no distinct `rule_id`.
- `AuditTransaction` has a new public field, `interruption_rule_id:
  Option<i32>`: the id of the rule whose disruptive action interrupted the
  transaction, which bounded formatters use to keep that rule's message when
  they drop messages. This pre-1.0 addition breaks exhaustive struct literals
  and patterns. A literal must initialise it or end with
  `..AuditTransaction::default()` (the type implements `Default`); a pattern
  that does not need it should end with `..`.
- `Operator` now requires `Send + Sync`.
- `MatchData::chain_level` is a new public `usize` field (parent level is zero),
  replacing the pre-release `u16`. Exhaustive `MatchData` literals must now
  initialize it; chain depth increments like Go's `int` instead of wrapping or
  panicking at extreme depths.
- `OperatorContext` has a new `custom` field for registered operators, and
  `OperatorEnum` has a new `Custom(Registered)` variant.
- `OperatorEnum` also has three feature-gated variants: `InspectFile`
  (`inspect-file`), `Rbl` (`rbl`) and `ValidateSchema` (`validate-schema`). A
  match over `OperatorEnum` was already exhaustive over the built-in variants,
  so it needs the new arms, guarded by the same features.
- `RuleVariable::multiphase_split` is a new public `const fn` that returns the
  variables `ARGS` and `ARGS_NAMES` compile to under multiphase evaluation.
  `OperatorEnum::for_negated_rule` is also new and public but hidden from
  generated docs: it is for the rule parser and compiles the `argument` it is
  given, not the operator's own pattern.
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
- The first interruption is kept in every engine mode. A later disruptive
  rule, such as a phase 5 `deny` after a phase 1 `deny`, no longer replaces it
  under `SecRuleEngine On`, matching `DetectionOnly`. This is a deliberate
  deviation: Go's `Transaction.Interrupt` overwrites the interruption in `On`
  mode. A later rule cannot replace an earlier interruption, so
  `Transaction::interruption()` and the audit log's interruption report the
  first one recorded.
- Disruptive actions in the logging phase (phase 5) are not reported as
  enforced. The logging phase runs after the response is released, so a phase 5
  `deny` can never take effect. As in Go, it is still stored by
  `Transaction::interruption()` when it is the first interruption. However, the
  audit log's `is_interrupted` and interruption rule do not report it. Its
  error log text and `MatchedRule::disruptive` do not claim it was enforced,
  just like a disruptive rule that matches after an earlier interruption. This
  is a deliberate deviation in what is logged: Go's audit entry reports it as an
  interruption.
- `REQUEST_COOKIES` counts against `SecArgumentsLimit` (1000 by default) across
  every `Cookie` header and `Transaction::add_request_cookie`. The first cookie
  past the limit is dropped with the rest of its header and sets
  `ARGUMENTS_LIMIT_REACHED`. This is a deliberate deviation: Go stores every
  cookie, so a `Cookie: a;a;a;...` header multiplies the work of every rule that
  reads `REQUEST_COOKIES`. The recommended baseline's rule 200004 denies such a
  request in phase 1. A policy without rules 200004 and 200005 must deny on
  `ARGUMENTS_LIMIT_REACHED` itself; otherwise the dropped cookies are never
  inspected.
- A `redirect` target has every ASCII control byte, below 0x20 and 0x7f,
  percent-encoded in upper case in `Interruption::data`, so a target that a
  macro expanded from request data, such as `redirect:/login?next=%{ARGS_GET.next}`
  with `next=a%0d%0aSet-Cookie:%20x=1`, reads `/login?next=a%0D%0ASet-Cookie: x=1`
  and cannot split the `Location` header an embedder puts it in. A target
  without such bytes is unchanged. This is a deliberate deviation: Go Coraza
  stores the raw bytes, and its HTTP middleware never sends a `Location` header.
- The XML request body processor refuses what a backend's parser would read as
  text this engine never inspects. These are a syntax error: a complete
  reference to an entity that is neither one of XML's five nor an HTML 4 entity
  (`&p;`, or a name past ASCII such as `&Ͱ;`); a DOCTYPE with an internal
  subset (`[`), an external identifier (`SYSTEM` or `PUBLIC`, in any case), a
  quoted literal or a markup declaration, whether or not its root name is glued
  to the keyword, or with a word or any other character before or after its
  root name but blanks, comments and the closing `>` (`<!DOCTYPE r extra>`,
  `<!DOCTYPE @r>`), or a root name that is not an XML name, by the same check
  as an element's (`<!DOCTYPE 1abc>`, `<!DOCTYPE -r>`, invalid UTF-8, or a
  character outside Go's name tables that XML 1.0's fifth edition allows, which
  an element name is refused for too; a bare `<!DOCTYPE name>` with a name such
  as `a:b-c.1` or `é` is accepted); any other
  directive, such as `<!ENTITY ...>` outside a DOCTYPE, and any directive
  after the first element; a control character other than tab and line ends,
  U+FFFE or U+FFFF in a comment or processing instruction, and a `--` inside a
  comment in a DOCTYPE (Go refuses one between tags too); and a body that ends
  inside a tag, a reference, a comment, an instruction or a directive
  (`unexpected EOF`) when no body limit cut it there. libxml2 in recover mode reads
  the subset of `<!DOCTYPEa [...]>`; before 2.15 it skips just the quote of
  `<!DOCTYPE a "...` and reads what follows as a subset or the root element; it
  ends a comment or instruction at such a character, and within an element
  skips just the `<!` of a directive, and reads on from there as markup; and it
  keeps the attributes of a tag, or the text before a reference, that the input
  ends in. `REQBODY_ERROR` and `REQBODY_PROCESSOR_ERROR` are set, no value of
  the document is kept, and the baseline's rule 200002 denies with 400. Under
  a body memory budget (`Transaction::set_body_memory_budget`) an error that
  quotes the document, an undeclared entity, an invalid name or the version or
  encoding of a declaration, needs room in the budget for its message: where
  the budget has none, the parse stops for the budget instead, keeping the
  values it read and setting `REQBODY_ERROR` with the budget's message, and a
  host that refuses a stop for the budget, as the Envoy connector does with
  503, refuses it where no rule denies first: with the enforcing
  `@recommended-conf`, rule 200002 can answer 400 first. Go
  Coraza publishes `&p;` as written, skips directives, comments and
  instructions whole, and drops a token the input ends in, so an entity's
  payload, or markup or values they held, reached such a backend unseen. A bare
  `<!DOCTYPE name>` before the first element, a body that ends between tags
  with elements open, references without `;`, numeric references and HTML
  entities such as `&nbsp;` are unchanged. A body that
  `SecRequestBodyLimitAction ProcessPartial` cut inside a token is not
  refused, and publishes what the token had read, where Go drops it with the
  token: the complete attributes of a start tag, the part of an attribute value
  up to the cut, quoted or not, and the text before a reference, which ends at
  the cut, the reference as written (`&am`). Only what the cut left unread goes
  uninspected, as past any `ProcessPartial` cut. A comment, instruction or
  directive publishes nothing, cut or whole, and neither does a bare attribute
  name or an element name that the cut ended in. Three cuts are refused, with
  `REQBODY_ERROR` set and a 400 from rule 200002: inside a CDATA section, and
  inside a UTF-8 character of text or of a quoted value, which are Go's syntax
  errors, and inside a reference when the text it ends, the reference as
  written included, holds a forbidden character or broken UTF-8 (`&\xc3`,
  `\0 &am`, `&\xef\xbf\xbe`, a name holding U+FFFE). Go accepts the body at
  such a reference and drops the text, so this is stricter than Go on purpose,
  to fail closed. A cut inside a comment, instruction, DOCTYPE,
  element name or attribute name is accepted like any other cut, when the
  unexpected EOF is the only error in the bytes before it: a forbidden
  character, a `--` inside a comment, a word after a DOCTYPE's root name
  (`<!DOCTYPE r extra`, with no delimiter after it yet; the root name itself, or a
  blank after it, is accepted), a root name that is no XML name once a blank,
  `>` or comment ends it (`<!DOCTYPE 1abc `; cut inside it, `<!DOCTYPE 1ab`, it
  is accepted), a character before it that is no blank, comment
  or name (`<!DOCTYPE @`), a directive whose first word, cut at its end, is
  not the start of `DOCTYPE` in any case (`<!ELE`, `<!ENTI`; `<!DOC` and
  `<!doct` are accepted, and so is `DOCTYPE` with a root name glued to it),
  an invalid name that ends before the cut (a name is checked once it is
  complete, so a cut inside one is accepted) or any other syntax error there
  refuses the body, as it refuses the whole document. The cost is a false
  positive on XML that declares its own
  entities and on documents whose DOCTYPE names an external DTD (`PUBLIC` or
  `SYSTEM`), such as XHTML 1.0, SVG 1.1, property lists and
  `<!DOCTYPE html SYSTEM "about:legacy-compat">`; the other refusals concern
  only documents that are not well-formed XML. To accept such documents on a
  path, select another body processor for it with a later phase 1
  `ctl:requestBodyProcessor`.
- XML values count against `SecArgumentsLimit`. `REQUEST_XML` keeps at most as
  many attribute and text values together as the limit (1000 by default); a
  document with more stops there, keeps the values before it, and sets
  `ARGUMENTS_LIMIT_REACHED` and `REQBODY_ERROR`, so the baseline's rules 200002
  and 200005 deny it. The values committed before the stop stay, but the
  attributes of a start tag the limit stops in are not kept, as when the memory
  budget stops in one, the ones that fit the limit included, so the collection
  can end below the limit (at a limit of two, a text value and then a start tag
  with two attributes leave just the text value). A custom body processor's XML
  output is cut at the same limit, in both directions, with the same flag and
  the direction's body error. Go Coraza has no limit on XML values, and each is
  one more evaluation of every rule that reads XML. Deployments with large SOAP
  or feed uploads raise `SecArgumentsLimit`.
- The error line of a rule that matched many values lists the first eight
  `[msg_match_N ...] [data_match_N ...]` pairs after its first match and ends
  with `[+N more matches]` for the rest, and cuts the request `[uri]` at 1 KiB
  with a `[+N uri bytes]` marker (the whole request line is in part `B`). This
  applies to `MatchedRule::error_log` and to the error line of each message
  under audit part `H`; part `K` still lists every match with its own `msg` and
  `logdata`. A rule with at most nine matches and a URI of at most 1 KiB reads
  as before. This is a deliberate deviation: Go Coraza lists every match and
  the whole URI in the line, and with parts `H` and `K` together that made the
  audit entry quadratic in the matches of one rule (245,930,171 bytes for 2000
  matches in the test shape) and proportional to the URI length times the
  matches. A parser that needs every match's expanded `msg` and `logdata` must
  read the JSON format. Native part `K` writes only the rule text, and
  JSONLegacy omits `logdata`.
- The `message` and `data` of a `MatchData` are cut to 4096 bytes each, at a
  character boundary: the expanded `msg` and `logdata` of a match, as the audit
  log's part `K` and `matched_rules()` report them. CRS's `logdata` expands
  `%{MATCHED_VAR}`, so every match of a large value kept a second copy of it, and
  one more where `msg` expanded it too (a 400 KB value, 800 KB of text per match).
  Go keeps both whole. `RULE:msg` and `RULE:logdata`, which hold the expansion
  that is made before the rule's variables are selected, are cut alike. The
  value of a match, `MatchData::value`, is kept whole, because the multiphase
  duplicate check compares it by equality, and so is what `setvar` and `capture`
  store, which rules read. The cut applies with or without a memory budget, and
  it can change a verdict: a rule that compares with or copies `%{RULE.msg}` or
  `%{RULE.logdata}` (an operator argument, a `setvar` value) reads the cut text,
  so a rule such as `@streq %{RULE.logdata}` matches a 4,096-byte value and
  misses a 4,097-byte one, where Go matches both. CRS has no rule that reads
  `RULE:msg` or `RULE:logdata`, so its verdicts are unchanged.
- A body memory budget (`Transaction::set_body_memory_budget`) now also bounds
  what the rules of the body phase keep, which it did not: the processors were
  charged and rule evaluation was not, so a body the budget admitted made the
  rules allocate many times its size (a match keeps the value it matched, and a
  rule that matches every value of a list keeps them all). With a budget set,
  the rules of that call of `process_request_body` or `process_response_body`
  draw on what the parse left of it, and charge, before they allocate it, each
  match (value, key, message, data and its slot), the entry it adds to
  `MATCHED_VARS`, the buffers `MATCHED_VAR` and `MATCHED_VAR_NAME` grow to, the
  `TX` entries `setvar` and `capture` write and the `ENV` entries `setenv`
  writes (each net of the value it replaces, or of the entry `setvar:!tx.key`
  removes; a removed capture key `TX:0` to `TX:9` is charged if a later capture
  or the next rule has to make it again), the path arguments an operator writes
  into `ARGS_PATH` and `ARGS` (a spelling of the name that replaces another is
  charged beside it, and the other is given back),
  the matched rule's record (the rule's metadata the record copies, meaning its
  text, `msg` and `logdata` templates, tags, version and file, and the
  addresses, URI and id), and, until the rule is done, the list of the values it
  selects, the list that holds them pending, the copy `multiMatch` makes of each
  of them, and the copies the multiphase duplicate check keeps (a duplicate it
  drops gives its copy back). The list of selected values is charged before each
  growth of the list, so that a collection of any number of values
  (`MULTIPART_PART_HEADERS`, which no argument limit bounds, is one) cannot make
  a list larger than the budget has left; the list holds references to the
  collection's own values and names, so a name that is not UTF-8 costs it no
  more than any other. A charge that does not fit ends rule evaluation for the
  transaction, including the phase 5 logging rules: the transaction is
  interrupted with status 503 (`rule evaluation memory budget exhausted`; in
  `DetectionOnly`, the would-be interruption, unless an earlier rule recorded
  one), no rule of any later phase runs (the request is already refused, and a
  rule that ran would allocate with the budget spent), nothing is charged or
  evaluated after it (the actions of the rule that was running that come after
  the charge, a `ctl` among them, do not run), and the rule that was running
  records nothing and denies nothing: a stop at the rule's own record is the
  503, never the rule's status, so the interruption never names a rule that
  `matched_rules()` does not show. The audit entry is written when the
  transaction finishes if the audit configuration selects it (`SecAuditEngine`,
  and for `RelevantOnly` the relevance of the status of the interruption or
  would-be interruption the transaction holds: the 503, unless an earlier rule
  recorded one, as a would-be 403 in `DetectionOnly` stays 403, or the response
  status when none was recorded, because the engine was switched `Off`),
  judged without the phase 5 rules, which did not run; it carries the rules
  recorded before the stop and, in the default mode, the interruption with rule
  id 0. A parse that the budget stopped leaves the rules 64 KiB at least, so
  that the rule that denies on the body error, the baseline's 200002, can still
  record its match and answer.
  `Transaction::rule_evaluation_stopped_by_memory_budget` reports it, in every
  engine mode, for a host that lets a `DetectionOnly` transaction through. The
  flag is the signal; the returned interruption follows the engine mode, so
  under `DetectionOnly`, or when a rule switched the engine `Off` before the
  refused charge, none is returned (and no further rule runs either). The Envoy
  connector refuses from the flag in every mode. Below the budget the matches,
  the scores and the verdict are those of a transaction with none; without a
  budget, the crate's default, nothing is charged and nothing changes. What a
  rule needs for one value while it evaluates it is not charged: it is gone when
  the value is, and bounded by the policy and the largest value, never by the
  number of values or of rules. A `capture` rule takes up to `G + min(G, 10)`
  copies of the value (one per group of its pattern, `G` counting the whole
  match, and the first ten again in the operator's outputs; nine nested groups
  that each hold the whole value measure 19, and CRS 4.30.0's own `capture`
  rules have at most three groups), a `multiMatch` rule one per transformation
  that changes the value (4.3 for six). `setvar` expands its key and value and
  `setenv` expands its value before the write is checked against the budget,
  even if the write is refused. Each field's temporary size depends on its
  expanded length: repeated references append the same value once per
  reference. `msg` and `logdata` are cut before they are copied (a value that
  is not UTF-8 is converted only as far as the cut, three source bytes past it
  at most; the temporary text can be up to three times that prefix before it
  is cut and freed). Custom body processors are not limited by the budget,
  and have no parse stop or 64 KiB reserve, but what they publish (`ARGS_POST`,
  `ARGS`, `FILES`) is taken from the budget before the rules draw on it, as
  what a built-in processor publishes is: output near or above the budget
  leaves the rules nothing, and the first charge of a rule stops rule
  evaluation with the 503.
- A multipart part with `Content-Transfer-Encoding: quoted-printable` is
  decoded as Go's `mime/multipart` does, and published twice when decoding
  changes it: the decoded body first, as Go publishes it, then the body as it
  was sent. A field's two values are both values of its name in `ARGS_POST` and
  `ARGS`; a file is two temporary uploads in `FILES_TMPNAMES` and two values of
  its name in `FILES_SIZES`. A backend that decodes the part, as Go's does, and
  one that takes it as sent (busboy, Starlette's `MultipartParser`, PHP) act on
  different text, so a rule reads both. The second value does not count against
  `SecArgumentsLimit`, is charged to the body memory budget, and counts in
  `ARGS_COMBINED_SIZE`; `FILES_COMBINED_SIZE` counts the part as it was sent. A
  part that decoding does not change is published once. Before, the part
  reached the rules still encoded, and a payload such as
  `cmd=3Bcat=20/etc/passwd` matched nothing that read the decoded text. The
  encoding header stays in `MULTIPART_PART_HEADERS`, where Go removes it, so CRS
  rule 922120 still matches every part that names an encoding, at paranoia
  level 1, as it did before the body was decoded. A part Go's quoted-printable
  reader rejects (a control byte, a `=` before a bare CR, a line over 4096
  bytes) is a body error with Go's message, published up to the failure and then
  as sent, and the parts after it are read, where Go stops. What follows the
  failing byte in that part is visible only as sent, encoded: a backend that
  decodes the whole part (python-multipart's `FormParser`) acts on text that no
  rule sees decoded. The recommended configuration's rules 200002 and 200003 and
  CRS rule 922120 refuse such a body; a policy with none of them does not. The
  [ledger](conformance/difference-ledger.md) lists where this deviates from Go.
- `FILES_COMBINED_SIZE` is the size of every multipart part's data, form fields
  included, as in Go Coraza. It counted file parts only, so a size rule such as
  CRS 920410 (limit set by 900350) saw too little of a body made mostly of
  fields.

## FTW integration

The [FTW runner guide](../ftw-runner/README.md) covers the optional go-ftw
server and a checked-in smoke test. The harness exercises the Coraza crate
through a test HTTP adapter; its results do not establish complete Go Coraza
compatibility.
