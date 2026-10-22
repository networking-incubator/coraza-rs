# Coraza Go-versus-Rust workload

Shared workload layer and Rust driver for the local Go-versus-Rust Coraza
comparison. This wave provides fixtures, case validation and the Rust
lifecycle. It has no timing code, statistics, coordinator, baseline report or
CI job; the coordinator in the next wave compares the two engines.

The existing conformance case schema at
[`coraza/conformance/corpus-schema.json`](../../coraza/conformance/corpus-schema.json)
is used unchanged at `schema_version` 1. The workload only declares which
subset of that schema the drivers support.

## Layout

| Path | Role |
| --- | --- |
| `go/` | Isolated Go module with engine resolution checks and the Go lifecycle. See [`go/README.md`](go/README.md). |
| `workloads/manifest.json` | Frozen list of case paths and SHA-256 hashes. |
| `workloads/cases/*.json` | One conformance case per file, schema version 1. |
| `coraza/benches/coraza_workload.rs` | Rust driver entry point. |
| `coraza/benches/coraza_workload/driver.rs` | Loader, validator, Rust lifecycle and outcome comparison. |
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
```

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
A mismatch or any malformed case fails the driver with a non-zero exit code
before any future timing section starts.

Not compared by this driver, and therefore rejected or documented:

- Audit entries: the common subset declares `required=false, entries=0`. Audit
  sink behavior is a later work package.
- `processor.config`: non-empty settings are rejected; use `SecLang`.
- Non-`auto` body processors: rejected, because forcing one outside the policy
  would diverge from the `SecLang` directives in the case.
- Request targets that are not UTF-8: the Rust public URI API takes text.
- DetectionOnly would-be interruptions: the subset uses `SecRuleEngine On`.
- Per-match phase: the Rust public API does not expose it, so the driver
  derives it from the lifecycle call after which the match first appeared.

The six cases are `get-benign`, `get-attack`, `form-benign`, `form-attack`,
`json-benign` and `json-attack`. Each pair shares one policy and differs only
in exact input bytes. The expected blocks were validated against the Rust
driver only. This is not a parity claim; the coordinator compares both engines.

## What the Go driver must implement

The existing Go lifecycle in `go/lifecycle.go` already compiles a policy once
and drives phases 1 to 5. The next wave must add a loader that:

1. Reads `manifest.json` with the same validation rules and verifies each case
   file hash, fixture hash and fixture range.
2. Parses the schema version 1 case shape, including base64 bytes and ordered
   repeated headers.
3. Replays `phase_calls` in order, applies connection metadata, promotes the
   first `Host` header to `SERVER_NAME`, supplies identical bytes, uses the
   case's policy text unchanged, stops later calls on interruption and calls
   `ProcessLogging` once.
4. Compares the same observable outcomes: interruption rule/action/status/data,
   matched rule IDs and match details, TX captures 0 through 9, named scores,
   named flags and named collection values.
5. Loads, validates and compiles everything outside any timed unit. No `go
   run`, JSON IPC, file discovery or fixture generation may occur per timed
   transaction.

The coordinator must reject a run when either driver cannot load the complete
workload, when any case hash differs, or when an observed outcome differs from
the case. Only cases both engines reproduce are eligible for a speed ratio.
