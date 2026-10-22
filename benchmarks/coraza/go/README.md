# Coraza Go benchmark harness

Isolated Go side of the local Go-versus-Rust Coraza comparison. This is a
self-contained Go module with its own `go.mod` and `go.sum`, separate from
`ftw-runner` and from the Cargo workspace.

This wave provides resolution checks and the lifecycle scaffold only. It has no
timing code, workload matrix, fixture format or result collection.

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

To assess a local checkout, a coordinator generates an alternate module file
with the directory replace and runs with `GOFLAGS=-modfile=local.mod`. The
generated `local.mod` and `local.sum` are ignored by git and must never be
committed. The local profile also requires a build-time identity stamp, because
Go build info records a directory replace's path but not the replaced checkout's
revision:

```sh
rev=$(git -C /path/to/coraza rev-parse HEAD)
GOFLAGS=-modfile=local.mod GOWORK=off GOTOOLCHAIN=local go run -ldflags \
  "-X github.com/corazawaf/coraza-rs/benchmarks/coraza/go.linkedEngineDir=/path/to/coraza \
   -X github.com/corazawaf/coraza-rs/benchmarks/coraza/go.linkedEngineRevision=$rev" \
  ./cmd/checkresolve
```

A binary without the stamp, or one built from a different directory or
revision, fails the local profile. Build the stamped binary only from a clean
checkout; the run-time check also rejects a checkout with modified tracked
files.

`TestBuildInfoMatchesResolution` also inspects `debug.ReadBuildInfo`, so it
checks the engine actually linked into the test binary rather than only what
the module file declares.

## Layout

- `lifecycle.go`: `Engine` and `Run`, the single lifecycle used by future
  validation and measurement modes.
- `resolve.go`: profile detection, pinned revision for the local profile,
  resolution check and JSON report.
- `cmd/checkresolve`: prints the resolution report and exits non-zero on
  mismatch. Run it before any measurement.
- `lifecycle_test.go`: smoke test that compiles one simple policy and runs
  allowed and denied transactions through phases 1 to 5.
- `resolve_test.go`: profile classification, resolved identity and linked-build
  checks.

## Lifecycle contract

`bench.New(directives)` compiles the policy once, outside any timed section.
`(*Engine).Run` then creates one transaction, drives phases 1 to 5 in the same
order as Coraza's HTTP middleware, calls `ProcessLogging`, and closes the
transaction. An interruption ends that unit of work, matching server behavior.
`(*Engine).Close` releases cached compiled patterns.

The future driver must not invoke `go run`, JSON IPC, file discovery or fixture
generation per transaction. `cmd/checkresolve` is a pre-run gate, not part of a
timed unit.

## Commands

```sh
cd benchmarks/coraza/go
GOWORK=off GOTOOLCHAIN=local go test ./...
GOWORK=off GOTOOLCHAIN=local go run ./cmd/checkresolve
```
