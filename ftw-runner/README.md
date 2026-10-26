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

## CRS suite

`testdata/crs/run-crs.sh` generates the Go-compatible CRS configuration and
runs the suite in conformance mode:

```sh
CORAZA_REF=~/go/pkg/mod/github.com/corazawaf/coraza/v3@v3.8.1 \
CRS_DIR=/path/to/coreruleset \
  ./testdata/crs/run-crs.sh
```

The expected inventory is 327 files, 5231 test cases, 5237 stages and 669
loaded rules. The raw suite is Apache-oriented and this runner does not apply
Go's CRS overrides, so the run reports the known failures instead of passing
completely; see [`testdata/crs/README.md`](testdata/crs/README.md).

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
matched rule messages in the format expected by go-ftw. It splits the raw
request line itself and parses the header block with `httparse`, then applies
the checks Go's `net/http` server applies before its handler: duplicate or
malformed `Host` headers and a missing HTTP/1.1 `Host` are 400, a protocol that
is not `HTTP/<digit>.<digit>` is 400, and a well-formed major other than 1 is
505. Bare-LF heads are accepted and re-emitted with CRLF.

The missing-Host check is skipped only for `CONNECT` and for the exact `PRI *
HTTP/2.0` preface, which Go's `isH2Upgrade` defines as method `PRI`, path `*`,
protocol `HTTP/2.0` and no headers at all. A `PRI * HTTP/2.0` request without a
`Host` but with any other header is therefore a 400.

`Transfer-Encoding` follows Go's `parseTransferEncoding`: an HTTP/1.0 request
ignores the header, and any other request is answered 501 before the handler,
with no rule run and no audit entry, unless it carries exactly one header whose
only coding is `chunked` (compared without case). Multiple `Transfer-Encoding`
headers, a comma-separated list such as `chunked, gzip`, and any other coding,
including `identity`, are unsupported. An accepted coding reaches the WAF as one
lowercased `Transfer-Encoding: chunked` header, as Go's middleware re-adds it.

The adapter's head limits differ from Go's defaults and are fail-closed: it
buffers at most 64 KiB of request head and parses at most 128 header lines,
while Go accepts 1 MB (`DefaultMaxHeaderBytes`) and 500 header values
(`DefaultMaxHeaderValueCount`). A head over either limit is rejected with a 4xx
before the WAF, so no rule runs and no audit entry is written. Obsolete folded
header lines (a continuation line starting with a space or tab) are also a 400
here, although Go's `textproto` folds them into the previous value: the pinned
`httparse` release only exposes folding for response heads.

Those behaviours are deliberate Go-parity choices, not Apache parity. Go's
`net/http` answers 505 to a well-formed protocol with a major other than 1, and
it accepts an empty `Host:` header (only a missing HTTP/1.1 `Host` is 400);
Go's middleware re-adds a non-empty `Host` to the WAF header map only, so an
empty Host is never visible to CRS. Apache instead answers 400 and never
reaches CRS. The raw CRS expectations therefore describe Apache: `920280-3`,
`920430-3`, `920430-8` and `920430-9` expect a 400 or a rule match where this
server returns 505, `920290-1` expects Apache's empty-Host 400, and `920290-4`
expects rule 920290 to see the empty Host. Those tests fail against this
runner. Go's own CRS harness rewrites part of that difference in
`tests/regression/coraza-overrides.yaml`; this runner does not apply overrides.

Go Coraza's middleware hands the WAF `req.URL.String()`, not the bytes on the
wire, so the server renders the target the same way before `ProcessURI`: `<`,
`>`, `"`, `#` and non-ASCII bytes in the path are percent-escaped, a valid
`RawPath` is preserved, the query stays as sent, and an absolute-form or
`CONNECT` authority becomes the request's `Host`/`SERVER_NAME`. Absolute-form and
opaque targets such as `http:///x`, `http:/x`, `h:1/x` and `a:b?c=d` reach the
WAF the same way: only an origin-form target is forwarded to hyper, so hyper's
URI parser cannot answer 400 before the WAF runs. It sets
`REMOTE_ADDR`, `REMOTE_PORT`, `SERVER_ADDR` and `SERVER_PORT` from the connection
before the URI. Each connection serves one request, so the capture of the raw
request head is per connection.

Audit log HTTPS output requires the crate's `https-audit` feature, which the
FTW server example does not enable. Audit and FTW behavior should be
verified against the target Coraza and CRS revisions before relying on it for
production policy decisions. Formatted audit timestamps use the process local
time zone, as in Go Coraza. The FTW server is a test adapter, not a production
HTTP connector.
