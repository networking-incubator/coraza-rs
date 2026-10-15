# Repository guidance

## Navigation

- Use the root [README](README.md) for the workspace map and public API overview. Read crate and task-specific docs before changing their area.

## Implementation

- Before editing, locate the affected APIs, callers, tests, fixtures, and CI checks. Make the smallest complete change and follow an existing project pattern; avoid speculative abstractions and dependencies.
- Treat detector inputs as hostile bytes. Preserve bounds, validation, error handling, and no-panic behavior. Keep detection allocation-free. `unsafe_code` and unchecked indexing are denied by workspace lints; do not weaken those guards.
- Review every changed path for security, correctness, and runtime or memory regressions. Add focused regression coverage for changed behavior and edge cases.

## Required checks

- For every change, including docs, configuration, and tooling, run `make lint` from the repository root before finishing. Fix failures caused by the change and rerun it. Report unrelated failures; do not claim lint passed.
- Some `typos` findings in detector code are intentional: SQL keyword names, libinjection fingerprints, and XSS/HTML inspection literals may need exact upstream spellings or malformed fixture bytes. Check `_typos.toml` and the pinned parity/corpus sources before editing them. Preserve confirmed literals and use only narrow, commented exceptions for false positives; fix genuine prose typos and do not suppress whole source trees.
- For every production Rust implementation change, run `make test`.
- For detector, parser, or input-path changes, run `make parity-differential` with `LIBINJECTION_DIR` set to the C revision pinned in `libperfusion/tests/parity/manifest.json`. This also requires the pinned Go oracle; see [docs/ci.md](docs/ci.md).
- For parser or input-validation security changes, run a focused fuzz campaign using [the fuzzing guide](libperfusion/docs/FUZZING.md) and promote any discovered crash to a regression fixture.
- For Envoy adapter or WASM runtime changes, also run `make build-envoy-wasm` and `bash examples/envoy-libperfusion/test-envoy.sh`.
- For dependency changes, run `make audit`. For workflow or shell changes, run `make lint-extra`.
- Use [docs/ci.md](docs/ci.md) to select the feature-matrix, coverage, MSRV, and other CI checks relevant to the changed area.
- Preserve libinjection attribution and license terms when changing upstream-derived source or tables; see `libperfusion/THIRD_PARTY_NOTICES.md`.
- Refresh pinned corpus and generated tables with `cargo xtask corpus-refresh` and `cargo xtask tables-refresh --upstream <checkout>` as applicable, then review the fixture, manifest, oracle, and table diffs.

## Performance gate

For every production runtime implementation change, benchmark both the pre-change revision and the candidate. Run the same release commands in each clean worktree, with the same toolchain, C revision, compiler flags, host, and workloads:

```sh
LIBINJECTION_DIR=/path/to/pinned-libinjection cargo bench -p libperfusion --bench speed
cargo bench -p libperfusion --bench compare
cargo bench -p libperfusion --bench scaling
```

`speed` compares libperfusion with libinjection C; `compare` covers the repository corpus; `scaling` covers 130 generated workloads. The latter two measure one revision at a time, so run them on both trees for a real before/after comparison. Run at least three paired repetitions, alternating which tree runs first; pin to one CPU when practical. Verify correctness before timing. Record both revisions, the C revision, toolchain/compiler and host, commands, and per-workload medians and ranges. Judge changes against repeated-run spread, not one timing. If a required benchmark cannot run, report the missing prerequisite and leave the performance gate incomplete.

Read [docs/performance.md](docs/performance.md) before performance-sensitive changes. Follow the [Rust Performance Book's benchmarking guidance](https://nnethercote.github.io/perf-book/benchmarking.html): use representative workloads and consistent conditions, and account for measurement variance.

## GitHub Actions

Reference repository actions with `uses: $/.github/...`, not `uses: ./.github/...`.

## Commits

Every commit must have a `Signed-off-by` trailer generated from the correct Git identity (use `git commit -s`). Do not include a `Co-authored-by` trailer.
