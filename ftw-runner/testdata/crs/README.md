# CRS run

This directory reproduces the OWASP Core Rule Set regression suite against the
Rust FTW server. It is a manual reference run, not part of the smoke gate:
`run-crs.sh` needs a CRS checkout and the pinned Go Coraza module.

## Prerequisites

- CRS v4.30.0 at commit `e03a4f6dabc7a30ebd8c52c97d28a154f590a48f`.
- Go Coraza v3.8.1 (`github.com/corazawaf/coraza/v3@v3.8.1`), normally in the Go
  module cache at `$(go env GOMODCACHE)/github.com/corazawaf/coraza/v3@v3.8.1`.
- The repository's Rust and Go toolchains.

```sh
CORAZA_REF=~/go/pkg/mod/github.com/corazawaf/coraza/v3@v3.8.1 \
CRS_DIR=/path/to/coreruleset \
  ./run-crs.sh
```

`FTW_CRS_OUT` overrides the artifact directory (default `target/ftw-crs`). The
script writes `crs-test.conf`, `result.json` and `failed.txt` there, builds the
release FTW server, and runs the runner in conformance mode.

## Configuration

The generated configuration has the same composition order as Go Coraza's CRS
harness:

1. `<CORAZA_REF>/coraza.conf-recommended` — the pinned engine's recommended
   configuration.
2. `SecResponseBodyMimeType text/plain` — as the Go harness sets it.
3. Rule `900005` from the CRS `tests/regression/README.md` test settings
   (detection-only engine, paranoia level 4, argument limits), verbatim.
4. Rule `999999` — writes the `X-CRS-Test` marker and excludes the marker
   request from every rule.
5. `<CRS_DIR>/crs-setup.conf.example`.
6. `<CRS_DIR>/rules/*.conf`.

The runner is invoked with the inventory of this CRS revision:
`--expected-files 327 --expected-tests 5231 --expected-stages 5237
--expected-rules 669`.

## Result

The suite loads 669 rules from 327 files and runs 5231 test cases in 5237
stages. It is not expected to pass completely: the raw CRS expectations are
written for Apache.

| Revision | Passed | Failed |
| --- | --- | --- |
| Base `9fadc0e` | 5189 | 42 |
| Branch, final | 5215 | 16 |

Relative to the base, the branch fixes 30 of those 42 failures and introduces
four: `920280-3`, `920290-4`, `920430-3` and `920430-9`, all from the Go 505
and Host-handoff parity described below. Its failure set is:

```
920100-5 920100-8 920270-4 920274-1 920280-3 920290-1 920290-4 920430-3
920430-5 920430-8 920430-9 920610-2 920620-1 922130-1 922130-2 922130-7
```

Run `run-crs.sh` and compare `failed.txt` to reproduce that set; the script
exits non-zero on these known failures.

## Why these failures are expected

The raw suite asserts Apache's behavior. Go's CRS harness rewrites part of it
with `tests/regression/coraza-overrides.yaml`; `ftw-runner` does not apply
overrides, so it sees the Apache expectations unchanged. In particular:

- `920280-3`, `920430-3`, `920430-8` and `920430-9` send `HTTP/0.8`, `HTTP/0.9`
  or `HTTP/4.0`. Go's `net/http` answers 505 before Coraza runs; Apache answers
  400 and still runs the rules. This server follows Go. `920430-5` omits the
  version and expects go-ftw to see a premature EOF; this server answers 400.
- `920290-1` sends an empty `Host:`. Go's `net/http` accepts the empty value,
  but its middleware does not re-add an empty `Host` to the WAF header map;
  Apache answers 400 instead. This server follows Go, so `920290-1` returns
  200.
- `920290-4` sends its own raw request, `GET / HTTP/1.0` with an empty `Host:`
  line. Go's middleware adds `Host` only when it is non-empty, so the WAF sees
  no `Host` header at all and rule 920290 never matches.
- `920100-5`, `920100-8` (CONNECT without a port, colon in the path), `920270-4`,
  `920274-1` (invalid Host bytes), `920610-2` (fragment in the request target),
  `920620-1` (multiple `Content-Type` headers) and `922130-1`, `-2`, `-7`
  (multipart header bytes) are the remaining Apache-vs-Go differences. Apache
  rejects or normalizes these before or during CRS; the Go-parity server does
  not, so the raw status or log expectations do not hold. Go's override file
  records the same tests for its own harness.

A green run requires either applying Go's override file or changing the server
away from Go parity; neither is part of this harness.
