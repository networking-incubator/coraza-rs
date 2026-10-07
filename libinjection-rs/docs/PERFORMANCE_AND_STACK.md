# Performance and stack analysis

The tools under `tools/perf/` and `tools/stack/` produce reports when run.
Generated reports are not checked into the repository. CI retains its run
artifacts; local runs can write to a temporary directory. Run these commands
from the workspace root.

## Latency

The paired Go/Rust latency runner needs a local checkout of the pinned Go
source:

```sh
python3 libinjection-rs/tools/perf/run.py \
  --go-source /path/to/libinjection-go \
  --artifact-dir /tmp/libinjection-perf \
  --output /tmp/libinjection-perf/report.json
```

Timing results are sensitive to host load. Use them for controlled comparisons;
CI does not gate on nanosecond-level latency.

## Hostile-input scaling

```sh
python3 libinjection-rs/tools/perf/scaling.py \
  --samples 3 --warmup 0 --rounds 3 \
  --artifact-dir /tmp/libinjection-scaling \
  --output /tmp/libinjection-scaling/report.json
```

The scaling gate checks growth across increasing input sizes and verifies
public verdict and fingerprint parity for shared cases.

## Stack analysis

```sh
python3 libinjection-rs/tools/stack/measure.py \
  --artifact-dir /tmp/libinjection-stack \
  --output /tmp/libinjection-stack/report.json
```

Stack results are informational. The analyzer uses the checked-in
`STACK_NATIVE_XSS_PROOFS.json` and `STACK_WASM_PANIC_PROOFS.json` inputs, but
its report covers only analyzed library paths. It does not establish a bound
for callers, runtimes, or the WASM engine stack. `--strict-budget` requests a
nonzero exit for an open or over-limit requested bound.
