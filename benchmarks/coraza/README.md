# Coraza Go-versus-Rust workload

Shared workload layer, Rust and Go drivers, and a correctness-first parity
runner for the local Go-versus-Rust Coraza comparison. This wave provides
fixtures, case validation, both lifecycles and cross-engine outcome comparison.
It has no timing code, statistics, baseline report or speed claim; those remain
a later wave and start only after correctness parity passes.

The existing conformance case schema at
[`coraza/conformance/corpus-schema.json`](../../coraza/conformance/corpus-schema.json)
is used unchanged at `schema_version` 1. The workload only declares which
subset of that schema the drivers support.

## Layout

| Path | Role |
| --- | --- |
| `go/` | Isolated Go module with engine resolution checks and the Go lifecycle. See [`go/README.md`](go/README.md). |
| `go/workload.go` | Go loader and validator mirroring the Rust invariants. |
| `go/outcome.go` | Shared outcome types, Go observation, comparison and NDJSON I/O. |
| `go/cmd/workload` | Go workload driver: validates, runs and emits outcomes. |
| `go/cmd/parity` | Correctness parity runner over both drivers. |
| `workloads/manifest.json` | Frozen list of case paths and SHA-256 hashes. |
| `workloads/cases/*.json` | One conformance case per file, schema version 1. |
| `coraza/benches/coraza_workload.rs` | Rust driver entry point. |
| `coraza/benches/coraza_workload/driver.rs` | Loader, validator, Rust lifecycle, outcome comparison and document emission. |
| `coraza/tests/coraza_workload.rs` | Focused tests for the loader, hashes, ranges and the full subset. |

## Workload contract

The workload is language-neutral JSON. Neither driver may regenerate the
policy, rewrite the case or normalize the input bytes.

### Manifest

`workloads/manifest.json` fields:

- `schema_version`: always `1`, the case schema version.
- `workload_id`: stable name of the workload.
- `description`: human-readable purpose.
- `case_schema`: repository-root-relative path of the case schema. It is
  informational; drivers validate the subset they implement.
- `cases`: non-empty array of `{"path", "sha256"}`. `path` is relative to the
  manifest directory, must not be absolute and must not contain `.` or `..`
  components. `sha256` is the lower-case SHA-256 of the exact case file bytes.

Drivers must fail on a missing manifest, an unknown field, a duplicate case
path, a malformed hash, a hash mismatch, zero cases or an unknown schema
version. They load and verify every case once, before running any transaction.

### Cases

Each case is one object from `coraza/conformance/corpus-schema.json`:

- `connection`: remote and local addresses and ports, TLS metadata. The Rust
  driver applies the addresses and ports; TLS metadata is recorded for future
  profiles and is not exposed by the current public API.
- `request` and `response`: method or status, protocol, original URI bytes,
  ordered repeated headers, complete body bytes and chunk boundaries.
- `processor.sec_lang`: the exact policy text, compiled once.
- `processor.request_body_processor` and `response_body_processor`: `auto` in
  this workload. Selection follows `Content-Type` and `SecLang` controls, as in
  the engines; the JSON cases set `ctl:requestBodyProcessor=JSON` in phase 1.
- `processor.config`: typed host settings. Empty in this workload.
- `phase_calls`: the ordered lifecycle, including one `append_*` call per chunk.
- `expected`: matches, interruptions, captures, scores, flags, collections and
  audit expectations.
- `fixture_sha256`: SHA-256 of the primary referenced fixture, or, when the
  case references no fixture, SHA-256 of `request.body` followed by
  `response.body`. The primary fixture is the first reference in the order
  request URI, request headers, request body, response headers, response body,
policy text.
- `normalize`: declared nondeterminism. The drivers do not sort or discard any
  observable order.

Arbitrary bytes are inline canonical base64 or a fixture reference with the
fixture file's SHA-256 and an optional `offset`/`length` range. A fixture range
must stay inside the file. Chunk boundaries must be contiguous and cover the
body exactly.

### Lifecycle subset

Both drivers must execute `phase_calls` in order. This workload accepts only
the canonical sequence:

1. `process_connection`, `process_uri`, `process_request_headers`.
2. One `append_request_body` per request chunk, then `process_request_body`.
3. `process_response_headers`.
4. One `append_response_body` per response chunk, then `process_response_body`.
5. `process_logging`.

`process_logging` always runs, including after an interruption. An interruption
stops later calls. Calling `process_connection` sets client and server
addresses and ports; the first `Host` header becomes `SERVER_NAME` before phase
1. Drivers must pass the exact body and header bytes. The Rust public API takes
the whole body, so its chunk boundaries are validated metadata and the exact
body is supplied once.

## Rust driver

The driver is a harness-less bench target in the `coraza` crate rather than an
isolated crate. This follows the repository convention for native benchmark
drivers (`libperfusion/benches/*`, `harness = false`), keeps the workspace
lockfile and lints in effect, and gives the next wave one executable that can
gain a timing loop around `run_case` without moving the code.

Run it:

```sh
cargo bench -p coraza --bench coraza_workload
cargo bench -p coraza --bench coraza_workload -- --workloads /path/to/workloads
cargo bench -p coraza --bench coraza_workload -- --workloads /path/to/workloads --outcome /tmp/rust.ndjson
```

The `--outcome` flag keeps every existing validation step and additionally
writes the language-neutral NDJSON outcome document described below.

Run the focused tests:

```sh
cargo test -p coraza --test coraza_workload
```

The driver loads the manifest and every case once, verifies hashes, fixture
ranges, base64, chunk coverage and the canonical calls, compiles each policy
once with `coraza::seclang::Parser`, then creates one transaction per case with
that case's ID. It drives the phases through the public transaction API,
records the phase in which each rule first matched, calls `process_logging`,
and compares the observed outcome with `expected`.

Validated per case: matched rule IDs, phases, variables, keys and exact value
bytes; the effective interruption's rule, action, status and data; TX captures
0 through 9; named TX scores; named engine flags; and named collection values.
A mismatch or any malformed case fails the driver with a non-zero exit code;
the outcome document is written only after every case validates.

Not compared by this driver, and therefore rejected or documented:

- Audit entries: the common subset declares `required=false, entries=0`. Audit
  sink behavior is a later work package.
- `processor.config`: non-empty settings are rejected; use `SecLang`.
- Non-`auto` body processors: rejected, because forcing one outside the policy
  would diverge from the `SecLang` directives in the case.
- Request targets that are not UTF-8: the Rust public URI API takes text.
- DetectionOnly would-be interruptions: the subset uses `SecRuleEngine On`.
- Per-match phase in the shared document: the Rust driver derives it from the
  lifecycle call after which the match first appeared for expected validation,
  but the Go public API cannot expose it, so the field is absent from the
  cross-engine outcome document.

## Go driver

The Go driver reuses the existing lifecycle in `go/lifecycle.go`: `New`
compiles the policy once, `drive` supplies the same bytes, headers and
connection metadata, an interruption stops later calls and `ProcessLogging`
always runs. Like the Rust driver, it supplies the validated body once through
`ReadRequestBodyFrom`; the chunk boundaries are validated metadata so both
engines see the same call boundaries. The workload loader validates the same
invariants as the Rust loader.

Run it from the Go module directory:

```sh
cd benchmarks/coraza/go
GOWORK=off GOTOOLCHAIN=local go run ./cmd/workload
GOWORK=off GOTOOLCHAIN=local go run ./cmd/workload --workloads /path/to/workloads --outcome /tmp/go.ndjson
```

Without `--workloads` the driver resolves `../workloads` from the Go module
directory, which is the same directory as the Rust driver's default. Without
`--outcome` it writes the NDJSON document to standard output; pass and error
messages always go to standard error.

The loader mirrors the Rust checks: manifest presence and shape, schema
version, unknown fields, duplicate case paths, absolute and parent-traversal
paths, exact case-file SHA-256, zero cases, base64 validity, fixture hashes and
ranges, contiguous chunks that cover the body exactly, the case-level
`fixture_sha256`, the canonical lifecycle and the expected block. File reads
are bounded at 64 MiB. The case policy text, body bytes, header bytes and
protocol text are passed through unchanged.

Observables read from the Go engine:

- Effective interruption: rule ID, action, status and data.
- Matched rules in evaluation order: rule ID, variable name, collection key and
  matched value, from `MatchedRules`.
- TX captures 0 through 9, named TX scores, and the named collection values
  declared by the case.
- The engine flags declared by the case that v3.8.1 exposes:
  `REQBODY_ERROR`, `REQBODY_PROCESSOR_ERROR`, `INBOUND_DATA_ERROR`,
  `OUTBOUND_DATA_ERROR`, `MULTIPART_STRICT_ERROR` and
  `ARGUMENTS_LIMIT_REACHED`.

The Go side reads variables through the exported `Variables()` and
`Collection()` methods implemented by the transaction returned from
`WAF.NewTransaction()`. Those methods back the plugin API in
`experimental/plugins/plugintypes`; they are exported but are not part of the
`types.Transaction` interface, so a future engine upgrade must recheck them.

Observables the Go public API does not expose, and which are therefore not
fabricated or compared:

- Per-match phase. `MatchedRule` and `MatchData` carry no phase; the Rust
  document omits the field as well.
- `RES_BODY_ERROR` and `RES_BODY_PROCESSOR_ERROR`. v3.8.1 has neither a
  plugin-interface accessor nor a `Collection` mapping for them.
- Audit entries, for the same subset reason as the Rust driver.
- Non-`auto` body processors and non-empty `processor.config`, which the common
  subset rejects.

Go pre-seeds TX keys 0 through 10 with empty strings and leaves several
untouched flags as empty strings rather than `"0"`. Captures and scores treat
an empty seeded TX value as unset, matching the Rust driver's absent-key
behavior, and the document carries only the flags a case declares, so
initialization differences outside the declared contract are not masked into
comparisons.

## Outcome document

Both drivers emit one JSON object per line (NDJSON), one line per case in
workload order. Byte values are standard base64; strings and numbers are
otherwise plain JSON. `null` means the value is absent.

```json
{
  "case_id": "get-attack",
  "interruption": {"rule_id": 1001, "action": "deny", "status": 403, "data": ""},
  "matches": [{"rule_id": 1001, "variable": "ARGS_GET", "key": "q", "value": "YXR0YWNr"}],
  "captures": [{"index": 0, "value": "YXR0YWNr"}],
  "scores": {"inbound_anomaly_score": 5},
  "flags": {"REQBODY_ERROR": "0"},
  "collections": [{"variable": "REQBODY_PROCESSOR", "key": null, "value": "VVJMRU5DT0RFRA=="}]
}
```

Field rules:

- `case_id`: the manifest case ID.
- `interruption`: `null` or an object with `rule_id`, `action`, `status` and
  base64 `data`.
- `matches`: one entry per matched value, in evaluation order. `variable` is
  the engine variable name, `key` is `null` for keyless variables and `value`
  is base64. The per-match phase is omitted.
- `captures`: TX indices 0 through 9 with base64 values, in index order. An
  empty capture slot is unset and omitted. A case that expects an empty
  capture value is outside the common subset because Go cannot tell it from an
  unset slot.
- `scores`: the named TX scores declared by the case. A missing score is `0`,
  matching both drivers.
- `flags`: the engine flags declared by the case, using the exact string the
  engine exposes. A flag neither driver can observe is absent, and the Go
  expected comparison reports it instead of inventing a value.
- `collections`: the collection values declared by the case, in declaration
  order. `value` is base64 or `null` when the collection or key is absent.

Maps (`scores`, `flags`) have no observable order and are compared by key.
Every array has a defined order: matches are in evaluation order, captures in
index order and collections in case declaration order. No field is compared as
a multiset because no public API in this subset exposes an unordered array.

## Correctness parity runner

`go/cmd/parity` builds the Go driver, runs it and the Rust driver over the same
workload, parses both NDJSON documents and fails on any divergence:

```sh
cd benchmarks/coraza/go
GOWORK=off GOTOOLCHAIN=local go run ./cmd/parity
GOWORK=off GOTOOLCHAIN=local go run ./cmd/parity --workloads /path/to/workloads
```

The runner compiles each driver once per invocation, writes both documents to a
temporary directory and removes it afterwards. It fails closed on a non-zero
driver exit, a missing or unreadable document, invalid JSON or base64, an
incomplete case object, duplicate case IDs, a missing or extra case, or any
differing field. Divergences are printed one per line and name the case and
field, for example:

```text
case get-attack: matches[0].value: rust "YXR0YWNr", go "c2FmZQ=="
```

A run succeeds only when both drivers load and validate the complete workload
and every emitted field agrees. Pass or fail messages from the drivers go to
standard error and do not affect the outcome comparison.

## Running correctness parity locally

```sh
cargo test -p coraza --test coraza_workload
cd benchmarks/coraza/go
gofmt -l .
GOWORK=off GOTOOLCHAIN=local go vet ./...
GOWORK=off GOTOOLCHAIN=local go test ./...
GOWORK=off GOTOOLCHAIN=local go run ./cmd/parity
```

The Go tests cover the loader negatives (tampered hashes, traversal, invalid
base64, chunk gaps, wrong schema version, fixture ranges), the six shipped
cases through the Go lifecycle, the NDJSON round trip and a negative comparator
test built from synthetic outcome documents.

The six shipped cases are `get-benign`, `get-attack`, `form-benign`,
`form-attack`, `json-benign` and `json-attack`. Each pair shares one policy and
differs only in exact input bytes. Both drivers validate the expected block and
the parity runner compares the two engines. Only cases that pass correctness
parity are eligible for a later speed ratio; this wave makes no speed claim.
