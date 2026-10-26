# CI Guide

This repository uses GitHub Actions to block risky changes early.

## What CI checks

### `tests`

- Lint: `make lint`
- Tests: `make test` runs the corpus, table, conformance and parity-manifest
  checks, the workspace tests with default features, and then a second
  `cargo test -p coraza` pass with the `host-operators,validate-schema` umbrella
  feature set, so the feature-gated operators keep their tests.
- `envoy-wasm`: builds the `wasm32-wasip1` filter and runs its shell-based
  integration checks against the pinned Envoy 1.40.0 image.
- Meta-lint: `make lint-extra` (typos, taplo over `**/*.toml`, actionlint,
  shellcheck); the downloaded tools are version- and checksum-pinned, see
  [Lint tool trust](#lint-tool-trust).
- Feature matrix: test and lint each feature combo with `cargo-hack`

### `differential parity`

- Checks the committed fixture manifest against the Go module pinned in
  `xtask/tools/go.mod`.
- Checks public SQLi fingerprints and XSS verdicts against the pinned C
  reference revision in `tests/parity/manifest.json`.
- Compares detector verdicts and fingerprints, SQL token and fold streams, and
  HTML token streams with the Go oracle.
- Runs on pull requests, pushes to `main` and release branches, and weekly.

The oracle module version, checksum, and comparison format are documented in
the [parity protocol](../libperfusion/tools/parity/PROTOCOL.md).

### `focused-fuzz`

- Runs 60-second libFuzzer campaigns with `-seed=20261007`, `-timeout=5` and
  per-target `-max_len`: `raw_bytes` (262144), `sql_grammar` (4096) and
  `html_grammar` (4096) in `libperfusion`; `coraza_variable_list` (4096),
  `seclang_operator` (4096), `seclang_rule_compilation` (4096),
  `coraza_uri_parser` (65536), `coraza_json_body` (65536) and
  `coraza_multipart_body` (65536) in `coraza`.
- Campaign corpora and crash artifacts are per target under
  `$RUNNER_TEMP/fuzz/corpus/<target>` and `$RUNNER_TEMP/fuzz/artifacts/<target>`.
- Each campaign requests 60 seconds of fuzzing for nine targets. Expect roughly
  10-15 minutes of wall time including the fuzz build, corpus setup and log
  upload on the CI runner; the 20-minute job timeout is sized for that range.
- Uploads campaign logs and crash artifacts, including on failure.
- Runs on pull requests, pushes to `main` and release branches, and weekly.

See the [fuzzing guide](../libperfusion/docs/FUZZING.md) for local runs and
regression promotion.

### Lint tool trust

`make lint-extra` runs `typos`, `taplo`, `actionlint` and `shellcheck`.

- `typos`, `taplo` and `actionlint` are GitHub release binaries in the
  `meta-lint` job. `.github/workflows/tests.yaml` pins each version and the
  SHA-256 of the exact release archive; the job downloads the archive, verifies
  it with `sha256sum --check --strict`, and only then extracts and executes it.
  A version bump must update both the version and the checksum.
- `shellcheck` comes from the pinned `ubuntu-24.04` runner image, not from a
  download in this repository.
- Rust tools (for example `cargo-audit`, `cargo-deny`, `cargo-llvm-cov`,
  `cargo-nextest`, `cargo-hack`, `cargo-machete`, `cargo-fuzz`) are installed
  with `cargo install --version <pinned> --locked`, so their dependency graphs
  come from the locked crate manifests rather than from floating updates.

Local `make lint-extra` runs use the binaries already on `PATH`; the CI job is
where downloaded tool integrity is enforced.

### `Coraza harness`

- `go-harness`: checks the isolated Go benchmark module in
  `benchmarks/coraza/go` with `gofmt -l`, `go vet`, `go test` and
  `go run ./cmd/checkresolve`. The Go toolchain comes from that module's
  `go.mod`, and commands run with `GOWORK=off GOTOOLCHAIN=local` so an ambient
  workspace or implicit toolchain download cannot change the resolved engine.
- `coraza-examples`: runs the async FTW example server tests.
- `tests` also replays Go Coraza's acceptance corpus against this crate:
  `coraza/tests/go_operators.rs` runs the 29-file operator corpus in
  `coraza/tests/go_operators`, and `coraza/tests/go_profiles_replay.rs` replays
  the 49 default-build engine profiles exported into
  `coraza/tests/go_profiles/profiles.json`. The replay asserts the fixture's
  Go version, build tags and profile/stage inventory before running.
- The vendored Go Coraza fixtures are refreshed from the version pinned in
  `coraza/tests/go_profiles/exporter/go.mod`: bump that `require` version, run
  `cargo xtask go-fixtures-refresh`, and review the diff, including the
  `FIXTURE_*` count constants in `coraza/tests/go_operators.rs` and
  `coraza/tests/go_profiles_replay.rs`. The command needs the pinned module in
  the Go module cache (`go mod download`). `cargo xtask go-fixtures-check`
  compares the checked-in operator and profile data bytes with that module and
  validates the operator and profile inventories against the `OPERATOR_*` and
  `PROFILE_*` constants: `make test` runs it in lenient mode (it skips without
  Go), and `make go-harness-check` runs it after its Go tests with
  `--require-go` so a missing toolchain or a drifted fixture fails there.
- `cargo xtask go-fixtures-check --provenance` also regenerates
  `coraza/tests/go_profiles/profiles.json` with the exporter and byte-compares
  it, so a same-inventory edit to rules or expected results fails. It needs the
  exporter's pinned Go 1.27.3 toolchain, which the `go-harness` setup does not
  install (that job runs `GOTOOLCHAIN=local` with an older Go), so it is a
  manual/pre-release step and not part of `make test` or `make go-harness-check`.
- `ftw-smoke`: runs the FTW runner in strict conformance mode against the
  checked-in smoke rules and test directory. Exact rule, file, test case and
  stage counts are required, and the manifest must contain no failed, skipped,
  ignored or forced-fail results. The result manifest is uploaded. It needs no
  CRS checkout.

Five modules have their own `go.mod` — `ftw-runner`, `benchmarks/coraza/go`,
`benchmarks/coraza/coordinator`, `coraza/tests/go_profiles/exporter` and
`xtask/tools` — and none is part of the Cargo workspace. Only
`benchmarks/coraza/go` is pinned by the `go-harness` job's setup step; the
exporter requires a newer Go than that job installs, so it is built on demand
by the fixture regeneration command.

### `supply-chain`

- `cargo audit`
- `cargo deny check`
- `cargo deny --all-features check`, which also resolves the feature-gated
  dependencies (`MIT-0` among them)

### `coverage`

- Enforces, on two separate reports:
  - line coverage >= 90%
  - region coverage >= 80%
- The first report is the workspace run with default features. The second is
  `cargo llvm-cov nextest -p coraza --all-features`, which measures the
  feature-gated operators and the optional host and HTTPS paths under the same
  floors; a high default-feature number does not cover them.

### `msrv`

- Builds the workspace with the Rust version from `rust-toolchain.toml`

### `zizmor`

- Audits GitHub Actions workflow and action security.

## Run checks locally

```console
make lint
make lint-extra
make test
make go-harness-check
make ftw-runner-check
make coraza-example-test
make ftw-smoke
make audit
make coverage-check
```

To run the full gate set:

```console
make all
```

The differential gates use the Go module pinned in `xtask/tools/go.mod` and a
C checkout at the revision pinned in `libperfusion/tests/parity/manifest.json`.
Set `LIBINJECTION_DIR` to that checkout before running:

```console
make parity-differential
```

## Signing requirements

Each commit must be:

- signed (`git commit -S`)
- signed off (`git commit -s`)

The approved exception for imported Coraza commits without source signoffs is
listed in the [Coraza import history](coraza-import-history.md).

You can do both in one command:

```console
git commit -S -s -m "type(scope): summary"
```

## If CI fails

- Read the failing job first, not all logs.
- Reproduce locally with the matching `make` target.
- Fix one class of failure at a time:
  - format/lint
  - tests
  - supply-chain
  - coverage

## Action pinning policy

- Third-party GitHub Actions must be pinned to commit SHAs.
- Do not use floating refs (`@main`, `@master`, `@vX`).
- Bump pinned SHAs regularly to current stable releases.
