# CI Guide

This repository uses GitHub Actions to block risky changes early.

## What CI checks

### `tests`

- Lint: `make lint`
- Tests: `make test`
- `envoy-wasm`: builds the `wasm32-wasip1` filter and runs its shell-based
  integration checks against the pinned Envoy 1.40.0 image.
- Meta-lint: `make lint-extra`
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

- Runs short campaigns for raw bytes and SQL/HTML grammar inputs.
- Uploads campaign logs and crash artifacts, including on failure.
- Runs on pull requests, pushes to `main` and release branches, and weekly.

See the [fuzzing guide](../libperfusion/docs/FUZZING.md) for local runs and
regression promotion.

### `supply-chain`

- `cargo audit`
- `cargo deny check`

### `coverage`

- Enforces:
  - line coverage >= 90%
  - region coverage >= 80%

### `msrv`

- Builds the workspace with the Rust version from `rust-toolchain.toml`

### `zizmor`

- Audits GitHub Actions workflow and action security.

## Run checks locally

```console
make lint
make lint-extra
make test
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
