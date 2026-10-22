# Coraza Go benchmark harness

Isolated Go side of the local Go-versus-Rust Coraza comparison. This is a
self-contained Go module with its own `go.mod` and `go.sum`, separate from
`ftw-runner` and from the Cargo workspace.

This wave provides resolution checks and the lifecycle scaffold only. It has no
timing code, workload matrix, fixture format or result collection.

## Pinned inputs

| Input | Value |
| --- | --- |
| Engine module | `github.com/corazawaf/coraza/v3` |
| Required version | `v3.0.0` |
| Declared replace | `../../../../coraza` (relative to this directory) |
| Resolved source | `/home/rpchevuz/codes/work/waf/coraza` |
| Engine revision | `d9cc9befc2721fd217ce1660a0e91aca1157221d` |
| Engine checkout | clean at the time of writing |
| Module go directive | `1.26.0` |
| Go binary | `/usr/lib/golang/bin/go` (`/usr/bin/go` symlink) |
| Go version | `go version go1.27.2-X:nodwarf5 linux/amd64` |
| Workspace mode | `GOWORK=off` |
| Toolchain mode | `GOTOOLCHAIN=local` |

The `require` version is a placeholder for the local replace; the actual source
is the replaced directory. The revision is enforced at run time, not by
convention. `bench.CheckResolution`:

- runs `go list -m -json` with `GOWORK=off` and `GOTOOLCHAIN=local`, so an
  ambient `go.work` or an implicit toolchain download cannot change the run;
- rejects a module that is not resolved through the declared directory replace;
- checks the replace path equals `bench.DeclaredEngineReplace`;
- runs `git rev-parse HEAD` in the resolved directory and requires the pinned
  revision;
- fails when tracked files in the checkout are modified.

`TestBuildInfoUsesLocalReplacement` additionally inspects
`debug.ReadBuildInfo`, so it checks the engine actually linked into the test
binary and cannot pass after a workspace replace selected a different source.

## Layout

- `lifecycle.go`: `Engine` and `Run`, the single lifecycle used by future
  validation and measurement modes.
- `resolve.go`: pinned revision, resolution check and JSON report.
- `cmd/checkresolve`: prints the resolution report and exits non-zero on
  mismatch. Run it before any measurement.
- `lifecycle_test.go`: smoke test that compiles one simple policy and runs
  allowed and denied transactions through phases 1 to 5.
- `resolve_test.go`: revision and linked-build checks.

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

## Resolved module graph

Captured with `GOWORK=off go list -m all`:

```text
github.com/corazawaf/coraza-rs/benchmarks/coraza/go
github.com/corazawaf/coraza-coreruleset/crs/tests/v4 v4.30.0
github.com/corazawaf/coraza-coreruleset/crs/v4 v4.30.0
github.com/corazawaf/coraza/v3 v3.0.0 => ../../../../coraza
github.com/corazawaf/libinjection-go v0.3.4
github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
github.com/foxcpp/go-mockdns v1.2.0
github.com/goccy/go-json v0.10.5
github.com/goccy/go-yaml v1.19.2
github.com/golang/protobuf v1.5.0
github.com/google/go-cmp v0.7.0
github.com/gotnospirit/makeplural v0.0.0-20180622080156-a5f48d94d976
github.com/gotnospirit/messageformat v0.0.0-20221001023931-dfe49f1eb092
github.com/jcchavezs/mergefs v0.1.1
github.com/kaptinlin/go-i18n v0.1.4
github.com/kaptinlin/jsonschema v0.4.6
github.com/klauspost/compress v1.17.8
github.com/magefile/mage v1.17.0
github.com/mccutchen/go-httpbin/v2 v2.25.0
github.com/miekg/dns v1.1.57
github.com/pelletier/go-toml/v2 v2.2.4
github.com/petar-dambovaliev/aho-corasick v0.0.0-20250424160509-463d218d4745
github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2
github.com/santhosh-tekuri/jsonschema/v5 v5.3.1
github.com/stretchr/testify v1.11.1
github.com/tidwall/gjson v1.18.0
github.com/tidwall/match v1.1.1
github.com/tidwall/pretty v1.2.1
github.com/valllabh/ocsf-schema-golang v1.0.3
golang.org/x/crypto v0.57.0
golang.org/x/mod v0.41.0
golang.org/x/net v0.60.0
golang.org/x/sync v0.23.0
golang.org/x/sys v0.48.0
golang.org/x/term v0.46.0
golang.org/x/text v0.42.0
golang.org/x/tools v0.49.0
google.golang.org/protobuf v1.36.11
gopkg.in/ini.v1 v1.67.0
gopkg.in/yaml.v3 v3.0.1
rsc.io/binaryregexp v0.2.0
```

The directory replace is intentionally relative. A checkout that does not have
the pinned Coraza tree at `../../../../coraza` fails the resolution check rather
than silently downloading another engine.
