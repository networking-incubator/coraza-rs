# Coraza engine parity batch: evidence

Measured on 2026-10-27 against base `2bf7fd50f861bbb17e9866448eae86fa5ab69d9a`.
The detector benchmark candidate was clean revision
`31ffac3d72c6a2808355d47e83926a8a8c79ccbd` (the batch runtime changes are at
`1d04033`). The final branch later received `3788252`, a test/lint-only HTTPS
helper gate; it does not change production runtime behavior. The base and
candidate have no `libperfusion/` source differences.

## Delivered lanes

| Lane | Result |
| --- | --- |
| L0 | Chain-member disruptive-action rejection and `requires_features` manifest classification. |
| L1 | Runtime multiphase evaluation, tagged replay fixtures, chain-level `usize` metadata, and bounded duplicate suppression. |
| L2a/L2b | Structured debug events and `SecDebugLog` controls; digest-free `fips` build profile. |
| L3a/L3b | Parser-scoped custom transformations and actions, including scheduling, allow scope, and reserved metadata action names. |
| L3c/L3d | Custom audit writers/formatters and body processors, with deferred activation, bounded reported text, output budget, and truncation reporting. |
| L3e | Parser rule observer for top-level rules only, matching the Go profile. |
| L4 | Extension-seam index, migration notes, gate results, and benchmark evidence below. |

## Gate matrix

Cargo and Make checks used `RUSTUP_TOOLCHAIN=1.99.1 CARGO_BUILD_JOBS=6`.

| Command | Exit | Evidence |
| --- | ---: | --- |
| `make lint` | 0 | Clippy, format, and Rust license checks passed. |
| `make test` | 0 | Workspace: 996 passed, 0 failed, 15 ignored; second `host-operators,validate-schema` Coraza pass: 855 passed, 0 failed. Conformance, fixture, and manifest checks also passed. |
| `make audit` | 0 | 186 locked dependencies scanned; audit and deny checks passed. Cargo-deny emitted existing unmatched-license and duplicate-version warnings. |
| `make lint-extra` | 0 | Typos, TOML, actionlint, and shellcheck passed. Two narrow regex exceptions preserve a historical abbreviated commit ID and a byte-identical upstream fixture sentence. |
| `cargo doc -p coraza --no-deps` | 0 | API docs generated. |
| `cargo xtask conformance-check` | 0 | Manifest, difference ledger, and example are consistent. |
| `cargo xtask go-fixtures-check --provenance` | 0 | Go Coraza v3.8.1 provenance verified: 29 operator files, 49 default profiles, 52 multiphase profiles. |
| `python3 libperfusion/tools/parity/check_manifest.py` | 0 | 498 fixtures and source/table hashes verified. |
| `python3 libperfusion/tools/parity/test_manifest_semantics.py` | 0 | Changed XSS tag value rejected; fixture counts unchanged. |
| `cargo test -p coraza --test go_profiles_replay replays_go_engine_profiles -- --exact --nocapture` | 0 | 49/49 profiles, 120/120 stages, zero mismatches. |
| `cargo test -p coraza --test go_profiles_replay replays_go_engine_profiles_with_multiphase -- --exact --nocapture` | 0 | 52/52 profiles, 123/123 stages, zero mismatches. |
| `cargo test -p coraza --test go_operators` | 0 | Operator corpus passed. |
| `make ftw-smoke` | 0 | 1 rule, 1 case, 1 stage; passed. |
| `make coraza-parity` | 0 | Six common-subset Go/Rust cases passed; Go profile was upstream Coraza v3.8.1. |
| `LIBINJECTION_DIR=/tmp/opencode/parity/libinjection-533a165 make parity-differential` | 0 | Pinned C: 864 SQL/XSS results and 20 reviewed XSS differences. Go: 864 cases, 17,280 comparisons, 0 oracle errors, 6 reviewed exceptions, 16 diagnostic token differences. Generated differential: 770 cases passed. |
| `make build-envoy-wasm` | 0 | `wasm32-wasip1` release build passed. |
| `bash examples/envoy-libperfusion/test-envoy.sh` | 0 | Envoy 1.40 request/response inspection checks passed. |
| `cargo hack check -p coraza --each-feature` | 0 | All 11 feature sets passed. |
| `cargo hack clippy -p coraza --each-feature` | 0 | All 11 feature sets passed. |
| `cargo hack test -p coraza --each-feature` | 0 | All 11 feature sets passed. |
| `cargo test -p coraza --no-default-features --features fips` | 0 | Digest-free FIPS tests passed (682 unit tests plus integration tests). |
| FIPS digest tree assertion | 0 | `md-5` and `sha1` absent from the no-default-features FIPS graph. |
| `cargo test -p coraza --features host-operators,validate-schema,https-audit` | 0 | 761 unit tests and all integration/doc tests passed. |
| `CRS_DIR=/tmp/opencode/parity/crs-4.30 CORAZA_REF=/home/rpchevuz/go/pkg/mod/github.com/corazawaf/coraza/v3@v3.8.1 FTW_CRS_OUT=/tmp/opencode/parity/l4-crs-off bash ftw-runner/testdata/crs/run-crs.sh` | 1 | Pinned CRS v4.30.0 loaded 669 rules and ran 5,231 tests: 5,215 passed, 16 failed, none skipped. This is the documented Apache-vs-Go raw-suite failure set in `ftw-runner/testdata/crs/README.md`. |
| `taskset -c 3 env RUSTUP_TOOLCHAIN=1.99.1 CARGO_BUILD_JOBS=6 GOFLAGS=-tags=coraza.rule.multiphase_evaluation CRS_DIR=/tmp/opencode/parity/crs-4.30 CORAZA_REF=/home/rpchevuz/go/pkg/mod/github.com/corazawaf/coraza/v3@v3.8.1 FTW_CRS_OUT=/tmp/opencode/parity/l4-crs-on bash ftw-runner/testdata/crs/run-crs.sh` (throwaway test-server config enabled multiphase) | 1 | Same inventory: 5,207 passed, 24 failed, none skipped. Eight additional failures were `920540-4`, `920540-5`, `931130-24`, `932200-13`, `932300-10`, `933120-2`, `950020-1`, `950020-2`; this raw Apache suite does not establish whether those are Go multiphase divergences. |

The FIPS graph assertion was:

```sh
tree=$(cargo tree -p coraza --no-default-features --features fips) &&
  ! printf '%s\n' "$tree" | grep -Eq '(^|[[:space:]])(md-5|sha1) v'
```

The HTTPS all-feature matrix initially failed because a test-only `format_mime`
helper was compiled into non-test builds. The failure reproduced on retry. The
subsequent branch commit `3788252` gated the helper and fixed the associated
all-features test lint; the feature matrix and HTTPS combination above were
rerun successfully on that tip.

Before `3788252`, `cargo hack check -p coraza --each-feature`,
`cargo hack clippy -p coraza --each-feature`,
`cargo hack test -p coraza --each-feature`, and
`cargo test -p coraza --features host-operators,validate-schema,https-audit`
each failed twice (check/clippy/test exit 1; explicit feature test exit 101) on
the same dead-code diagnostic at `coraza/src/audit_log.rs::format_mime`.

Before the final `make lint-extra` pass, `make lint-extra` exited 2 twice on two
intentional literals: a historical abbreviated revision and a byte-identical
upstream fixture sentence. Their narrow, commented exceptions are in
`_typos.toml`; neither the source reference nor fixture bytes were edited.

No requested gate was skipped for a missing external prerequisite: the pinned C
checkout, Go Coraza v3.8.1 module, CRS v4.30.0 checkout, and Envoy 1.40 image
were available. The two CRS invocations returned nonzero for the test outcomes
listed above, not for missing prerequisites.

## Performance evidence

Base and candidate were clean worktrees; each process was pinned to logical CPU
3. Detector `speed`, `compare`, and `scaling` used three sequential alternating
base/candidate runs. The initial concurrent attempt at the second `speed` pair
was discarded and rerun sequentially. `make coraza-bench` used three campaigns
per revision, each with three internal paired repetitions and 1,000 transactions
per case; debug logging and multiphase were off. The full paired per-workload
medians and ranges are in
[`performance/coraza-engine-parity-batch.tsv`](performance/coraza-engine-parity-batch.tsv);
raw detector logs and all six `run.json` files are in
[`performance/coraza-engine-parity-batch/raw/`](performance/coraza-engine-parity-batch/raw/).

Detector commands were `taskset -c 3 env RUSTUP_TOOLCHAIN=1.99.1
CARGO_BUILD_JOBS=6 CARGO_TARGET_DIR=<revision-target> LIBINJECTION_DIR=<pinned-C>
cargo bench -p libperfusion --bench speed` and the same command with `--bench
compare` or `--bench scaling` (the C variable was used for `speed`). The engine
command was `taskset -c 3 env RUSTUP_TOOLCHAIN=1.99.1 CARGO_BUILD_JOBS=6
CARGO_TARGET_DIR=<revision-target> make coraza-bench BENCH_OUT=<run-output>`.

Environment: AMD Ryzen 7 PRO 7840HS, Linux 7.2.12, Rust/Cargo 1.99.1, Go
1.27.3, GCC 16.2.1; CPU frequency was not locked. The host is shared and has
background load. As noted in [`performance.md`](performance.md), it cannot
resolve effects around 1%; no sub-1% effect is claimed.

| Benchmark | Workloads | Base vs candidate, median and observed range | Verdict against repeated-run spread |
| --- | ---: | --- | --- |
| `speed` vs pinned libinjection C | 7 groups | Every full row is in the paired TSV. Two groups had non-overlapping run-median ranges: SQLi attack samples 450.1 [430.8–453.6] vs 488.9 [466.3–493.8] ns/input; XSS upstream sample 59.2 [57.1–59.3] vs 61.0 [60.9–62.6]. | Candidate was slower in those two observed ranges; no libperfusion source changed, so this is not attributable to the Coraza batch. |
| `compare` | 8 API/workload pairs (4 workloads × capped/caller-bounded) | All workload medians/ranges are in the paired TSV. Seven ranges overlap; capped XSS hit was 33.3 [32.8–41.2] vs 32.6 [30.9–32.6] ns/input. | One small non-overlap; 2.1% faster nominally, below the host's resolution. |
| `scaling` | 130 generated workloads | All 130 pairs, including medians and repeated-run/sample ranges, are in the TSV. Eleven run-median ranges did not overlap (8 candidate-faster, 3 slower). Two large SQLi cases showed nominal candidate medians +44.7% and +34.0%, but the candidate run spread was wide and the per-sample ranges overlap the baseline. | Inconclusive on this shared host; no `libperfusion/` source changed. Do not attribute those isolated shifts to this batch. |
| `make coraza-bench` | 6 end-to-end cases | Candidate medians were lower in all six. Two non-overlapping run-median ranges were form-benign 6,382 [6,322–6,622] vs 5,851 [5,520–6,232] ns/transaction and get-attack 6,422 [6,322–6,632] vs 5,961 [5,681–6,272]. Raw per-sample extrema are retained in each `run.json`. | No candidate slowdown observed; apparent speedups are not claimed because the raw sample ranges are broad and the host is shared. |

`MatchData::chain_level` widening and the multiphase duplicate-check change are
included in this batch. The default, multiphase-off profile showed no systematic
Coraza slowdown; the per-workload results above do not resolve effects near 1%.

### Multiphase-on profile probe

For a separate profile measurement, a throwaway worktree enabled
`WafConfig::multiphase_evaluation` in the Rust workload driver and FTW server;
the upstream Go tag `coraza.rule.multiphase_evaluation` was set for parity.
The command `taskset -c 3 env RUSTUP_TOOLCHAIN=1.99.1 CARGO_BUILD_JOBS=6
CARGO_TARGET_DIR=/tmp/opencode/parity/l4-target-multiphase
GOFLAGS=-tags=coraza.rule.multiphase_evaluation make coraza-bench
BENCH_OUT=/tmp/opencode/parity/l4-coraza-multiphase` exited 2 on both attempts,
failing its correctness gate before timing because
`get-attack` expected its match in phase 2 while the multiphase profile produced
the same match in phase 1. The raw failure is archived. A direct Rust timing run
then measured 1,000 transactions per case (medians [min–max], ns/transaction):

| Case | Median [min–max] |
| --- | ---: |
| get-benign | 5,070 [4,759–52,288] |
| get-attack | 5,190 [4,889–21,891] |
| form-benign | 5,140 [4,860–10,169] |
| form-attack | 5,691 [5,460–10,630] |
| json-benign | 6,261 [5,981–13,385] |
| json-attack | 6,778 [6,502–17,473] |

This is a single profile sample, not a regression comparison or parity result;
the direct timer intentionally did not apply the default-profile expected-phase
assertions. The Go/Rust default parity gate remains the six-case pass above.

## Outstanding follow-up

- The multiphase-on raw CRS run adds eight failures to the known default raw
  suite set. The raw CRS cases are Apache-oriented; compare these IDs with the
  Go multiphase CRS override run before classifying them as a compatibility
  defect.
- `make coraza-bench` cannot currently use the multiphase-on profile with its
  checked-in default expected outcomes: the phase number is part of the
  expected match. The direct profile timing is recorded but does not replace a
  profile-aware correctness fixture.
- No gate remains incomplete for an unavailable tool, image, or external
  checkout. The only expected nonzero gate result is the documented raw CRS
  Apache-vs-Go case set; the extra multiphase-on cases remain unclassified.
