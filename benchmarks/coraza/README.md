# Coraza Go-versus-Rust workload

Shared workload layer, Rust and Go drivers, a correctness-first parity runner
and a local coordinator for the local Go-versus-Rust Coraza comparison. The
workload, both drivers, cross-engine outcome comparison, the coordinator and
the Go timing driver are in place. The Rust driver still runs only its
correctness mode, so this branch produces no benchmark numbers and makes no
performance claim; speed ratios start only after correctness parity passes.

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
| `go/cmd/bench` | Go timing driver: loads once, times every case and writes the timing document. |
| `coordinator/` | Isolated Go module with the identity gate, parity orchestration and timing coordinator. Standard library only. |
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

The six shipped cases are `get-benign`, `get-attack`, `form-benign`,
`form-attack`, `json-benign` and `json-attack`. Each pair shares one policy and
differs only in exact input bytes. Both drivers validate the expected block and
the parity runner compares the two engines. Only cases that pass correctness
parity are eligible for a later speed ratio; this wave makes no speed claim.

## Coordinator

`benchmarks/coraza/coordinator` is an isolated Go module that uses only the
standard library. It is not part of the `go/` module. It has two subcommands:

- `parity`: validate the workload and engine identities, run the correctness
  gate and stop. No builds or timing runs.
- `bench`: validate identities, run the correctness gate, build each driver
  once, run at least three paired repetitions in alternating order and write a
  versioned result document.

The Makefile entry points are:

```sh
make coraza-parity
make coraza-bench BENCH_OUT=/path/to/results
make coraza-coordinator-check
```

Direct invocation from the repository root:

```sh
cd benchmarks/coraza/coordinator
GOWORK=off GOTOOLCHAIN=local go run . parity --workloads "$PWD/../workloads"
GOWORK=off GOTOOLCHAIN=local go run . bench --workloads "$PWD/../workloads" --output "$PWD/../../../target/coraza-bench"
```

`make coraza-parity` and `make coraza-bench` accept these overridable
variables: `CORAZA_WORKLOADS`, `BENCH_OUT`, `CORAZA_REPETITIONS`,
`CORAZA_ITERATIONS`, `CORAZA_GO_PROFILE`, `CORAZA_PARITY_CMD`,
`CORAZA_RUST_DRIVER_CMD`, `CORAZA_GO_DRIVER_CMD`, `CORAZA_RUST_BUILD_CMD` and
`CORAZA_GO_BUILD_CMD`. The coordinator also reads the matching environment
variables listed by `go run . help`.

### Identity gate

Before the parity command or any driver starts, the coordinator:

- Reads `manifest.json` with the driver validation rules. A missing manifest,
  zero cases, an unknown field, a duplicate case path or case ID, an unsafe
  path, a malformed hash or a hash mismatch fails the run.
- Runs the checkresolve command (default `go run ./cmd/checkresolve` in
  `benchmarks/coraza/go`) with `GOWORK=off` and `GOTOOLCHAIN=local`, requires a
  zero exit status and parses the JSON report. It refuses an unknown profile, a
  profile that differs from `CORAZA_GO_PROFILE`, a different engine module, an
  empty engine version, and a dirty engine checkout.
- Records the repository revision and tracked-file dirtiness, the `go`,
  `rustc` and `cargo` versions, the workload ID and exact manifest SHA-256, the
  Go resolution report and every exact command with its working directory.

The local Go profile still needs the generated `local.mod` and the build-time
identity stamps described in [`go/README.md`](go/README.md). Export the exact
stamped checkresolve command through `CORAZA_CHECKRESOLVE_CMD` (or pass
`--checkresolve-command`). The coordinator preserves inherited `GOFLAGS`, so
`GOFLAGS=-modfile=local.mod` selects the local profile for every Go command.

### Correctness gate

The coordinator appends `--workloads <dir>` to `CORAZA_PARITY_CMD` and runs it
in the Go module. The default is `go run ./cmd/parity`, the correctness parity
runner described above. Outcome comparison stays in that runner; the
coordinator does not reimplement it. A non-zero exit status stops the run
immediately, before builds or timing, and the parity stdout and stderr are kept
as raw artifacts.

An optional `CORAZA_PARITY_REPORT` (or `--parity-report`) JSON classifies the
cases:

```json
{
  "schema_version": 1,
  "cases": [
    {"case_id": "get-benign", "status": "passed"},
    {"case_id": "get-attack", "status": "divergent", "reason": "matched rules differ"}
  ]
}
```

`status` is `passed`, `divergent` or `ineligible`. Non-passed entries need a
reason. Unknown, duplicate or extra case IDs are rejected. A workload case
missing from the report is published as `ineligible`; it is never dropped.
Without a report, a successful gate marks every case eligible.

### Timing contract

The Go timing driver (`go/cmd/bench`) implements this contract. The Rust
driver does not have a timing mode yet, so a coordinator `bench` run stops at
the Rust driver until that mode lands. The coordinator invokes each driver
with:

```text
<driver> --workloads <dir> --timing <path> --iterations <n>
```

One invocation handles the whole workload: the driver loads and compiles once,
runs every case, exits zero and writes one JSON document to `<path>`:

```json
{
  "schema_version": 1,
  "engine": "rust",
  "workload_id": "coraza-common-subset-v1",
  "manifest_sha256": "<64 lower-case hex characters>",
  "iterations": 1000,
  "cases": [
    {"case_id": "get-benign", "samples_ns": [12345, 12380]}
  ]
}
```

Each manifest case must appear exactly once with at least one non-negative
per-transaction duration in nanoseconds. Unknown fields, trailing JSON, a
different engine, workload ID, manifest hash or iteration count, missing or
extra cases, empty samples and negative durations are rejected before any
statistic is computed.

The Go timing driver times one fresh transaction per iteration. A sample starts
immediately before `WAF.NewTransaction` and stops immediately after
`Transaction.Close`, so it includes transaction initialization, connection,
URI, request headers, request body read and processing, response headers,
response body read and processing, logging and close. Workload loading,
manifest and case validation, fixture decoding, policy compilation and outcome
observation are outside the timed section. The driver rejects an iteration
count below 1 or above 1,000,000, and writes the document through a temporary
file renamed into place.

The coordinator builds each driver once per run and reuses the executable for
every repetition. No transaction starts a process, invokes `go run`, uses JSON
IPC, discovers fixtures or compiles a policy. Configured build, driver and
parity commands run through `sh -c`; workload-controlled values are always
passed as shell-quoted arguments.

- Rust default build: `cargo build --locked --release -p coraza --bench
  coraza_workload --message-format=json`. The coordinator reads the executable
  from the cargo JSON messages and runs it from the repository root.
- Go default build: `go build -o <run>/bin/coraza-go-driver ./cmd/bench` in
  `benchmarks/coraza/go`, run from that module directory. `go/cmd/bench` is
  the Go timing driver described above. `make coraza-bench` still stops at the
  Rust driver until the Rust timing mode lands; `make coraza-parity` is
  unaffected.
- `CORAZA_RUST_DRIVER_CMD` and `CORAZA_GO_DRIVER_CMD` use a prebuilt driver
  command and skip the default build. Optionally pair them with
  `CORAZA_RUST_BUILD_CMD` and `CORAZA_GO_BUILD_CMD`, which run once before the
  first timed repetition. A build command without a driver command is
  rejected because the built executable would be unknown.

### Alternation, ratios and artifacts

Repetition 1 runs Rust then Go, repetition 2 runs Go then Rust, and the order
alternates from there. At least three repetitions are required; more can be
requested with `CORAZA_REPETITIONS`. The engines never run simultaneously.

`run.json` is the versioned result document. It records the identity, every
exact command, the gate record, the protocol parameters, every run's raw
samples and, per case, the pooled sample count, median, minimum and maximum
for each engine. `ratio_rust_over_go` is the Rust median divided by the Go
median (a value below 1 means Rust was faster). A ratio is published only when
the correctness gate passed the case. Divergent and ineligible cases keep their
statistics and a reason but no ratio.

Artifact layout, with one fresh directory per invocation:

```text
<BENCH_OUT>/bench-<UTC>/
  run.json
  identity.json
  raw/
    checkresolve.stdout.json
    checkresolve.stderr.log
    parity.stdout.log
    parity.stderr.log
    build-rust.stdout.log
    build-rust.stderr.log
    build-go.stdout.log
    build-go.stderr.log
    round-01-rust.timing.json
    round-01-rust.stdout.log
    round-01-rust.stderr.log
    ...
<BENCH_OUT>/parity-<UTC>/
  parity.json
  identity.json
  raw/
    checkresolve.stdout.json
    checkresolve.stderr.log
    parity.stdout.log
    parity.stderr.log
```

Every raw timing file and log is preserved and referenced from `run.json`. A
failed run still writes `run.json` with `status: failed`, the error and every
artifact produced so far.

No benchmark numbers are produced by this wave. The coordinator, identity gate,
collector and protocol are exercised with mock drivers and synthetic documents
by `make coraza-coordinator-check`; the Go timing driver is covered by the Go
tests, and the Rust timing mode is still outstanding.

## Running correctness parity locally

```sh
cargo test -p coraza --test coraza_workload
cd benchmarks/coraza/go
gofmt -l .
GOWORK=off GOTOOLCHAIN=local go vet ./...
GOWORK=off GOTOOLCHAIN=local go test ./...
GOWORK=off GOTOOLCHAIN=local go run ./cmd/parity
```

From the repository root, the Makefile wraps the same parity runner with the
identity gate:

```sh
make coraza-parity
make coraza-coordinator-check
```

The Go tests cover the loader negatives (tampered hashes, traversal, invalid
base64, chunk gaps, wrong schema version, fixture ranges), the six shipped
cases through the Go lifecycle, the NDJSON round trip and a negative comparator
test built from synthetic outcome documents. The coordinator tests cover the
identity gate, the parity gate record, workload validation, the timing protocol
and the result document with mock commands.
