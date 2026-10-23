# Coraza Go benchmark harness

Isolated Go side of the local Go-versus-Rust Coraza comparison. This is a
self-contained Go module with its own `go.mod` and `go.sum`, separate from
`ftw-runner` and from the Cargo workspace.

This wave provides resolution checks, the lifecycle, the shared workload
consumer, the correctness parity runner and the timing driver. It makes no
speed claim.

## Inputs

| Input | Value |
| --- | --- |
| Engine module | `github.com/corazawaf/coraza/v3` |
| Required version | `v3.8.1` |
| Module go directive | `1.26.0` |

`go.mod` has no replace directive, so the default build uses the published
engine. Resolution commands force `GOWORK=off` so an ambient workspace cannot
substitute another engine, and `GOTOOLCHAIN=local` so nothing is downloaded
implicitly. An inherited `GOFLAGS` is preserved.

## Profiles

`bench.CheckResolution` derives exactly one profile from `go list -m -json`:

- `upstream`: the module has no replace directive and resolves to
  `v3.8.1`. No git commands run.
- `local`: the module is replaced by a directory. Its resolved directory is
  checked with `git rev-parse HEAD` against the pinned revision in `resolve.go`,
  and tracked files must be unmodified.

The resolution report is the source of identity for a run. `cmd/checkresolve`
prints it as JSON, including the profile, module version, engine directory and,
for the local profile, the revision and cleanliness, then exits non-zero on
mismatch. Run it before any measurement. The check also compares the engine
recorded in the running binary's build info with the resolved profile, so a
different `GOFLAGS` cannot make the report describe an engine the binary did not
link. Run the command from the module directory; the working directory is the
module root.

Go 1.26 test binaries omit dependency build info: `go version -m` records only
`path` and `mod`, with no `dep` lines, so `debug.ReadBuildInfo` in a `go test`
binary cannot see the linked engine. Tests therefore check module resolution
only. `cmd/checkresolve` is a command binary, whose build info does record
dependencies, and it checks the linked engine. `make go-harness-check` runs both
checks.

To assess a local checkout, a coordinator generates an alternate module file
with the directory replace and runs with `GOFLAGS=-modfile=local.mod`. The
generated `local.mod` and `local.sum` are ignored by git and must never be
committed. The local profile also requires a build-time identity stamp, because
Go build info records a directory replace's path but not the replaced checkout's
revision or build-time cleanliness:

```sh
dir=/path/to/coraza
rev=$(git -C "$dir" rev-parse HEAD)
if [ -n "$(git -C "$dir" status --porcelain --untracked-files=no)" ]; then
  echo "engine checkout is dirty" >&2
  exit 1
fi
GOFLAGS=-modfile=local.mod GOWORK=off GOTOOLCHAIN=local go run -ldflags \
  "-X github.com/corazawaf/coraza-rs/benchmarks/coraza/go.linkedEngineDir=$dir \
   -X github.com/corazawaf/coraza-rs/benchmarks/coraza/go.linkedEngineRevision=$rev \
   -X github.com/corazawaf/coraza-rs/benchmarks/coraza/go.linkedEngineClean=1" \
  ./cmd/checkresolve
```

A binary without the stamps, one built from a different directory or revision,
or one built from a dirty checkout fails the local profile. The run-time check
also rejects a checkout with modified tracked files.

`TestBuildInfoMatchesResolution` also inspects `debug.ReadBuildInfo`, so it
checks the engine actually linked into the test binary rather than only what
the module file declares. When build info has no dependencies, as with Go 1.26
test binaries, the test skips with a message: module resolution is still
covered by the other tests, and `cmd/checkresolve` covers the linked-engine
check for that toolchain.

## Layout

- `lifecycle.go`: `Engine` and `Run`, the single lifecycle used by validation
  and timing modes.
- `workload.go`: shared workload loader and validator.
- `outcome.go`: outcome document types, observation, comparison and NDJSON I/O.
- `resolve.go`: profile detection, pinned revision for the local profile,
  resolution check and JSON report.
- `cmd/checkresolve`: prints the resolution report and exits non-zero on
  mismatch. Run it before any measurement.
- `cmd/workload`: validates the shared workload and emits NDJSON outcomes.
- `cmd/parity`: runs both drivers and compares outcomes field by field.
- `cmd/bench`: times every case for a fixed iteration count and writes the
  coordinator timing document.
- `timing.go`: `RunTimed`, the timed transaction lifecycle.
- `lifecycle_test.go`: smoke test that compiles one simple policy and runs
  allowed and denied transactions through phases 1 to 5.
- `workload_test.go`: loader negatives, the shipped cases and the canonical
  lifecycle.
- `outcome_test.go`: NDJSON round trip and comparator divergence tests.
- `resolve_test.go`: profile classification, resolved identity and linked-build
  checks.

## Lifecycle contract

`bench.New(directives)` compiles the policy once, outside any timed section.
`(*Engine).Run` then creates one transaction, drives phases 1 to 5 in the same
order as Coraza's HTTP middleware, calls `ProcessLogging`, and closes the
transaction. An interruption ends that unit of work, matching server behavior.
`(*Engine).Close` releases cached compiled patterns.

A timing driver must not invoke `go run`, JSON IPC, file discovery or fixture
generation per transaction. `RunTimed` times one fresh transaction from
`WAF.NewTransaction` through `Close`, including transaction initialization,
every lifecycle call, logging and cleanup. Workload loading, validation, policy
compilation and outcome observation stay outside the timed section.

`cmd/checkresolve` is a pre-run gate, not part of a timed unit. The workload
and outcome document format, including the exact command lines, are documented
in [`../README.md`](../README.md#outcome-document).

## Commands

```sh
cd benchmarks/coraza/go
GOWORK=off GOTOOLCHAIN=local go test ./...
GOWORK=off GOTOOLCHAIN=local go run ./cmd/checkresolve
GOWORK=off GOTOOLCHAIN=local go run ./cmd/workload --outcome /tmp/go.ndjson
GOWORK=off GOTOOLCHAIN=local go run ./cmd/parity
GOWORK=off GOTOOLCHAIN=local go run ./cmd/bench --timing /tmp/timing.json --iterations 2
```
