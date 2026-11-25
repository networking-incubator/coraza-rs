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
  integration checks against the pinned Envoy 1.40.0 image. The harness fails
  when the example configuration lacks a setting that the connector README's
  "Required Envoy configuration" table marks as set, and checks that a
  client-supplied `X-Forwarded-For` does not reach `REMOTE_ADDR`, that
  respelled hosts keep their policy, that invalid authorities are refused with
  400, that dot segments and doubled slashes are resolved before the rules see
  the path, and that a header name with an underscore is refused.
- `envoy-wasm-crs`: fetches the CRS release pinned in `envoy-coraza/crs.pin`
  (verifying its SHA-256), builds the filter with the non-default `embed-crs`
  feature, and runs `make test-envoy-wasm-crs`. It also runs the Envoy lifecycle
  harness against the feature-on artifact via
  `ENVOY_CORAZA_MAKE_TARGET=build-envoy-wasm-crs`; that run adds a `crs.local`
  policy that includes the built-in `@recommended-conf` baseline and the
  embedded tree, and asserts that SQL injection requests, including one in the
  field after a multipart part with an empty header block, are denied by CRS
  rule 949110 and that an unterminated multipart body is denied by baseline rule
  200002. It also checks that the embedded tree's stub for CRS rules 905100
  and 905110 holds: an "internal dummy connection" `GET /` carrying a SQL
  injection, sent from inside the Envoy container so that `REMOTE_ADDR` is
  127.0.0.1, is denied before the backend and rule 107 logs the loopback
  address, and the same request claiming 127.0.0.1 in `X-Forwarded-For` from
  outside is denied too. The default `envoy-wasm` run and this one both check
  the same multipart cases against a `recommended.local` policy that loads the
  baseline without the CRS, and the same Envoy settings and request
  normalization cases.
- Meta-lint: `make lint-extra` (typos, taplo over `**/*.toml`, actionlint,
  shellcheck); the downloaded tools are version- and checksum-pinned, see
  [Lint tool trust](#lint-tool-trust).
- Feature matrix: test and lint each feature combo with `cargo-hack`; the job
  fetches the pinned CRS release first so `envoy-coraza`'s `embed-crs` feature
  can build. Also test the digest-free FIPS profile with
  `cargo test -p coraza --no-default-features --features fips`, then assert its
  graph omits both digest crates with
  `tree=$(cargo tree -p coraza --no-default-features --features fips) && ! printf '%s\n' "$tree" | grep -Eq '(^|[[:space:]])(md-5|sha1) v'`.
  Cargo features are additive: plain `--features fips` keeps the crates but
  selects FIPS behavior.

### `differential parity`

- Checks the committed fixture manifest against the Go module pinned in
  `xtask/tools/go.mod`.
- Checks public SQLi fingerprints and XSS verdicts against the pinned C
  reference revision in `tests/parity/differential.json`.
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
  `coraza_uri_parser` (65536), `coraza_json_body` (65536),
  `coraza_multipart_body` (65536) and `coraza_xml_body` (65536) in `coraza`.
- Campaign corpora and crash artifacts are per target under
  `$RUNNER_TEMP/fuzz/corpus/<target>` and `$RUNNER_TEMP/fuzz/artifacts/<target>`.
- Each campaign requests 60 seconds of fuzzing for ten targets. Expect roughly
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
  the 49-profile default fixture and the 52-profile
  `coraza.rule.multiphase_evaluation` fixture. The replay asserts each fixture's
  Go version, build tags, profile/test/stage inventory before running.
  `coraza/tests/go_multipart.rs` replays what Go's multipart body processor
  publishes for the bodies in `coraza/tests/go_multipart/cases.json`.
- The vendored Go Coraza fixtures are refreshed from the version pinned in
  `coraza/tests/go_profiles/exporter/go.mod`: bump that `require` version, run
  `cargo xtask go-fixtures-refresh`, and review the diff, including the
  `FIXTURE_*` count constants in `coraza/tests/go_operators.rs` and
  `coraza/tests/go_profiles_replay.rs`. This writes both `profiles.json` and
  `profiles-multiphase.json`, and copies the module's `coraza.conf-recommended`
  to `coraza/coraza.conf-recommended`. That is the only copy: envoy-coraza's
  `build.rs` derives the built-in `@recommended-conf` from it on every build, and
  fails if a directive it comments out (the Wasm-specific ones and `SecRuleEngine`) is no longer set. The
  command needs the pinned module in the Go module cache (`go mod download`).
  `cargo xtask go-fixtures-check` compares the checked-in operator and profile
  data bytes and the recommended configuration with that module and validates
  the operator and profile inventories against the `OPERATOR_*` and `PROFILE_*`
  constants: `make test` runs it in lenient mode (it skips without Go), and
  `make go-harness-check` runs it after its Go tests with `--require-go` so a
  missing toolchain or a drifted fixture fails there.
- `coraza/tests/go_multipart/cases.json` is regenerated by hand with the program in
  `coraza/tests/go_multipart/regenerate` (steps in `coraza/tests/go_multipart/README.md`),
  which requires the same Go Coraza as the exporter. After bumping the exporter's
  `require`, set the same version in `coraza/tests/go_multipart/regenerate/go.mod` (the
  `go-coraza` Dependabot group bumps both) and rerun it: `cargo xtask go-fixtures-check`
  fails when the two versions differ, with or without Go, in `make test` as well.
- `cargo xtask go-fixtures-check --provenance` also regenerates
  both profile JSON documents with the matching default and multiphase tags and
  byte-compares them, so a same-inventory edit to rules or expected results
  fails. It needs the exporter's pinned Go 1.27.3 toolchain, which the `go-harness` setup does not
  install (that job runs `GOTOOLCHAIN=local` with an older Go), so it is a
  manual/pre-release step and not part of `make test` or `make go-harness-check`.
- `ftw-smoke`: runs the FTW runner in strict conformance mode against the
  checked-in smoke rules and test directory. Exact rule, file, test case and
  stage counts are required, and the manifest must contain no failed, skipped,
  ignored or forced-fail results. The result manifest is uploaded. It needs no
  CRS checkout.

Six modules have their own `go.mod` — `ftw-runner`, `benchmarks/coraza/go`,
`benchmarks/coraza/coordinator`, `coraza/tests/go_profiles/exporter`,
`coraza/tests/go_multipart/regenerate` and `xtask/tools` — and none is part of the
Cargo workspace. Only `benchmarks/coraza/go` is pinned by the `go-harness` job's
setup step; the exporter and the multipart regenerator require a newer Go than that
job installs, so the exporter is built on demand by the fixture regeneration command
and the regenerator is run by hand.

### `supply-chain`

- `cargo audit`
- `cargo deny check`
- `cargo deny --all-features check`, which also resolves the feature-gated
  dependencies (`MIT-0` among them)
- Any `envoy-coraza/crs.pin` bump must be reconciled by a reviewer against the
  upstream release notes and the published asset digest before merging.

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
make crs-fetch
make test-envoy-wasm-crs
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
C checkout at the revision pinned in `libperfusion/tests/parity/differential.json`.
Set `LIBINJECTION_DIR` to that checkout before running:

```console
make parity-differential
```

Each libperfusion pin file has one writer and one checker:

| File | Records | Written by | Checked by (`make test`) |
| --- | --- | --- | --- |
| `libperfusion/tests/parity/manifest.json` | Go module version and checksum, fixture inventory | `cargo xtask corpus-refresh` | `cargo xtask corpus-check` |
| `libperfusion/tests/parity/sqli_oracle.tsv` | Go oracle SQLi verdict and fingerprint per SQL fixture | `cargo xtask corpus-refresh` | `cargo xtask corpus-check` |
| `libperfusion/data/tables.json` | C revision, upstream and local SQL/XSS table hashes and counts | `cargo xtask tables-refresh --upstream <checkout>` | `cargo xtask tables-check` |
| `libperfusion/tests/parity/differential.json` | C reference revision (equal to `data/tables.json`), Go module version and checksum the source hashes describe (equal to `manifest.json`), Go oracle toolchain, SQL byte dispatch hash, Go source hashes (offline only the `LICENSE` hash; CI's `--go-source` run compares the rest with the module source) | `python3 libperfusion/tools/parity/check_manifest.py --update --go-source <dir>` | `make parity-manifest-check` |

After bumping the module in `xtask/tools/go.mod`, run `cargo xtask
corpus-refresh`, then `check_manifest.py --update --go-source <dir>` with the
module directory (`cd xtask/tools && go list -m -f '{{.Dir}}'
github.com/corazawaf/libinjection-go`); `make parity-manifest-check` fails until
then. A table refresh at the same C revision needs only `cargo xtask
tables-refresh --upstream <checkout>`. A C revision bump runs that refresh on a
checkout of the new commit, sets `C_REFERENCE` in `check_manifest.py` to the
same commit (`make parity-manifest-check` fails while the two differ), reruns
`check_manifest.py --update --go-source <dir>`, and reruns `make
parity-differential` against the new checkout. The CI parity job runs
`check_manifest.py --go-source`, which compares the tables, the SQL dispatch,
the fixtures and the Go source hashes with the module source. Offline, `make
test` checks only the `LICENSE` hash among the Go source hashes.

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

## Releases

`.github/workflows/release.yml` publishes releases on a nightly schedule
(03:00 UTC, also via `workflow_dispatch`) and on manual `vX.Y.Z` tag pushes. It
builds the `envoy-coraza` filter for `wasm32-wasip1` (without and with the
`embed-crs` feature, using the same `--locked --release` flags as
`make build-envoy-wasm`/`build-envoy-wasm-crs`), links the WASI ENOSYS stubs
(`envoy-coraza/wasi-stub.wat`, via a pinned binaryen `wasm-as`/`wasm-merge`)
into both binaries so they also load on Envoy below 1.40 (e.g. Istio 1.30),
stages the results as
`release-artifacts/{coraza-rs,coraza-rs-crs}.wasm`, and runs GoReleaser
(`.goreleaser.yaml`). GoReleaser uploads the raw `.wasm` files as release
assets and packages each into a scratch Docker image
(`ghcr.io/networking-incubator/coraza-rs` and `...-crs`, usable directly as
Envoy `WASMPlugin` images) tagged `nightly` and `nightly-YYYYMMDD` for
nightlies, or `vX.Y.Z` for manual releases (`latest` only when the released
tag is the newest final one, so an older backported tag or a prerelease tag
cannot move it backwards). GitHub releases are marked as prereleases for any
semver prerelease tag (`vX.Y.Z-rc.N`, and the nightlies) and as regular
releases for final `vX.Y.Z` tags.

OSS GoReleaser has no nightly mode (Pro-only), so the nightly workflow passes
the dated tag (`v0.0.0-nightly.YYYYMMDD`) to GoReleaser via the
`GORELEASER_CURRENT_TAG` environment variable and GoReleaser creates the tag
and prerelease when publishing; a same-day rerun fails instead of moving the
existing tag. For a manual release, push a normal `vX.Y.Z` tag. To test
packaging locally without publishing, first install binaryen
[version 123](https://github.com/WebAssembly/binaryen/releases/tag/version_123)
— the version the workflow pins — and put its `bin/` on `PATH` (it provides
`wasm-as` and `wasm-merge`). Then stage the WASM files exactly as the
workflow does and run the snapshot (the config expects them to exist):

```console
./envoy-coraza/crs-fetch.sh
wasm-as envoy-coraza/wasi-stub.wat -o /tmp/wasi-stub.wasm
link_stubs() {
  wasm-merge /tmp/wasi-stub.wasm wasi_snapshot_preview1 \
    "$1" envoy-coraza -o "$2" --rename-export-conflicts --all-features
}
cargo build --locked --release --target wasm32-wasip1 -p envoy-coraza
link_stubs target/wasm32-wasip1/release/envoy_coraza.wasm release-artifacts/coraza-rs.wasm
cargo build --locked --release --target wasm32-wasip1 -p envoy-coraza --features envoy-coraza/embed-crs
link_stubs target/wasm32-wasip1/release/envoy_coraza.wasm release-artifacts/coraza-rs-crs.wasm
goreleaser release --snapshot --clean
```
