# Assurance checks

This guide lists the checks used for the crate. It records no pass result for a
particular checkout; run the commands against the source you intend to ship.

## Routine checks

From the workspace root:

```sh
make lint
make lint-extra
make test
make coverage-check
make package-check
make audit
```

`make all` runs the common local gates. Package, Miri, and performance checks
are separate targets. CI runs the configured GitHub Actions workflows; see the
repository's [CI guide](../../docs/ci.md).

## Differential checks

The oracle test needs a local checkout of the pinned Go implementation:

```sh
LIBINJECTION_GO_SOURCE=/path/to/libinjection-go \
  cargo test -p libinjection --test oracle_differential -- --ignored --nocapture

cargo test -p libinjection --test generated_differential -- --ignored --nocapture
```

The expected oracle version and comparison protocol are documented in
[`tools/parity/PROTOCOL.md`](../tools/parity/PROTOCOL.md). Fuzz campaign
instructions are in [`FUZZING.md`](FUZZING.md).

## Optional analysis

Performance and stack tools generate reports on demand. Their JSON outputs are
not committed; see [`PERFORMANCE_AND_STACK.md`](PERFORMANCE_AND_STACK.md) for
commands and interpretation. Stack figures cover analyzed library paths only
and do not promise a bound on the caller, runtime, or WASM engine stack.
