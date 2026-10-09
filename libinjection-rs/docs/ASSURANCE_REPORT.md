# Assurance checks

This guide lists the checks available in the repository. It records no pass
result for a particular checkout; run the commands against the source you
intend to ship.

## Routine checks

From the workspace root:

```sh
make lint
make lint-extra
make test
make audit
make coverage-check
```

`make test` verifies the corpus and parity manifest before running workspace
tests. `make all` also builds the workspace and runs formatting and all of the
checks above. CI runs these checks in separate jobs; see the repository's
[CI guide](../../docs/ci.md).

## Differential parity

The parity workflow checks the fixture manifest against the Go module pinned in
`xtask/tools/go.mod`, then compares Rust with that module across detector
results, SQL token and fold streams, and HTML token streams. The module version,
checksum, and comparison format are recorded in the
[parity protocol](../tools/parity/PROTOCOL.md).

To run the full differential suites locally, install Go 1.27.1 and run:

```sh
make parity-differential
```

The regular `make test` target does not require Go; it checks the committed
fixture inventory and hashes locally.

## Fuzzing

Fuzz targets and crash promotion are documented in the
[fuzzing guide](FUZZING.md). The scheduled and pull request fuzz workflow runs
short campaigns and uploads logs and crash artifacts for review.
