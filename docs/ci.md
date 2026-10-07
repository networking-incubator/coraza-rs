# CI Guide

This repository uses GitHub Actions to block risky changes early.

## What CI checks

### `tests`

- Lint: `make lint`
- Tests: `make test`
- Meta-lint: `make lint-extra`
- Feature matrix: test and lint each feature combo with `cargo-hack`

### Performance assurance

CI checks hostile-input and analyzer scaling, along with stack and fuzz
assurance. The paired Go/Rust latency matrix is a local check (`make
perf-check`); CI does not gate on nanosecond-scale timings because shared
runners can make them noisy.

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
make package-check
make miri-check
make perf-check
make perf-scaling-check
```

`make all` runs the common build, format, lint, test, audit, and coverage gates.
The commands above include the package, Miri, and performance checks separately.

To run the common gate set:

```console
make all
```

## Signing requirements

Each commit must be:

- signed (`git commit -S`)
- signed off (`git commit -s`)

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
