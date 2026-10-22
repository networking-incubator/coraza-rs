# FTW test runner

This optional Go harness runs go-ftw tests against the Rust Coraza test server.
It supports end-to-end checks with CRS test cases. It is not part of the
published Rust library API.

## Requirements

- The Rust toolchain required by this repository.
- The Go version declared in `go.mod`.
- An explicit FTW test directory and a Coraza-compatible rules configuration.

## Build and run

From the repository root, build the server:

```sh
cargo build --release -p coraza --example ftw_server_async --features async-server
```

Then run the harness from this directory:

```sh
go run . --rules /path/to/crs-test.conf --test-dir /path/to/crs/tests/regression/tests
```

Run the checked-in smoke test without a CRS checkout:

```sh
go run . --rules testdata/smoke/rules.conf --test-dir testdata/smoke
```

The server listens on `127.0.0.1:8080`. The runner creates a temporary log
file, passes it to the server, and removes it after the server stops.

## Modes

`--mode conformance` is the default. It requires `--rules`, `--test-dir` and a
result manifest, and it fails the run when any of these hold:

- The test directory is missing, is not a directory, or contains no FTW YAML.
- A test file cannot be read or parsed, even if other files are valid.
- The server skips or rejects an unsupported rule, stops early, or did not
  write a strict startup inventory.
- The configured `--expected-*` counts do not match.
- go-ftw reports fewer test cases than the inventory selected.
- Any test or forced-fail result remains.

The server is started with `--strict`, which disables skip-on-failure loading
and requires `--rules`. The existing readiness token still proves that the
process answering on the port is the server this runner started.

`--mode health-only` is the explicit replacement for the old silent fallback.
It only checks that the server answers a few basic requests and asserts no FTW
coverage. It does not accept `--expected-*` counts and does not write a
manifest.

## Flags

- `--mode`: `conformance` (default) or `health-only`.
- `--rules`: SecLang configuration file to load. Required in conformance mode.
- `--test-dir`: Directory searched recursively for FTW `.yaml` and `.yml`
  tests. Required in conformance mode.
- `--max-tests`: Maximum number of test files to run; zero means all files.
  This limits files only. The runner reports inventory and selected counts
  separately for files, test cases and stages.
- `--expected-rules`: Expected number of loaded WAF rules; `-1` disables the
  check.
- `--expected-files`: Expected number of FTW files in the whole test directory.
- `--expected-tests`: Expected number of test cases in the whole test directory.
- `--expected-stages`: Expected number of stages in the whole test directory.
- `--failed-out`: Write failed test IDs to this file.
- `--manifest`: Machine-readable conformance result path; default
  `ftw-result.json`. The manifest records mode, strictness, expected counts,
  inventory and selected counts, loaded rule count, run results and every
  failure.

## Self-tests

Go runner tests (mode, inventory, manifest and process lifecycle checks):

```sh
cd ftw-runner
go test ./...
```

Rust example tests (strict loading, unsupported directives and expected rule
counts), without a live backend:

```sh
cargo test -p coraza --example ftw_server_async --features async-server
```

The server implements the `/reflect` endpoint used by CRS tests and records
matched rule messages in the format expected by go-ftw. Hyper rejects some raw
request-target forms before they reach the WAF, so FTW results do not represent
complete Coraza compatibility.

Audit log HTTPS output is not implemented. Audit and FTW behavior should be
verified against the target Coraza and CRS revisions before relying on it for
production policy decisions. Audit timestamps use UTC; Go Coraza uses the
process local time zone. The FTW server is a test adapter, not a production
HTTP connector.
