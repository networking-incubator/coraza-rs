# FTW test runner

This optional Go harness runs go-ftw tests against the Rust Coraza test server.
It supports end-to-end checks with CRS test cases. It is not part of the
published Rust library API.

## Requirements

- The Rust toolchain required by this repository.
- The Go version declared in `go.mod`.
- A CRS checkout containing go-ftw YAML tests and a Coraza-compatible rules
  configuration when running the full suite.

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
file, passes it to the server, and removes it after the server stops. If the
default CRS test directory (`../../coraza-coreruleset/tests`) is absent, the
runner performs only basic HTTP health checks.

Available flags:

- `--rules`: SecLang configuration file to load.
- `--test-dir`: Directory searched recursively for FTW `.yaml` and `.yml`
  tests.
- `--max-tests`: Maximum number of test files to run; zero means all files.
- `--failed-out`: Write failed test IDs to this file.

The server implements the `/reflect` endpoint used by CRS tests and records
matched rule messages in the format expected by go-ftw. Hyper rejects some raw
request-target forms before they reach the WAF, so FTW results do not represent
complete Coraza compatibility.

Audit log HTTPS output is not implemented. Audit and FTW behavior should be
verified against the target Coraza and CRS revisions before relying on it for
production policy decisions. Audit timestamps use UTC; Go Coraza uses the
process local time zone. The FTW server is a test adapter, not a production
HTTP connector.
