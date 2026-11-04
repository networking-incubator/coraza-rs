# Envoy dynamic-module benchmark

`run.py` compares the pinned Envoy 1.40.0 image with no filter, the Wasm
Coraza filter, and the native dynamic module. It runs three paired repetitions
per ruleset, cycling which variant runs first. Each Envoy has two workers; the
load generator is CPU-affined and each container is pinned to the selected
available CPUs. Compose refuses to start when ports 9901 or 10001 are occupied.

Build the four release-mode artifacts into separate target directories, then
run the harness:

```sh
make crs-fetch
CARGO_TARGET_DIR=target/dynamic-default make build-envoy-dynamic
CARGO_TARGET_DIR=target/dynamic-crs make build-envoy-dynamic-crs
CARGO_TARGET_DIR=target/wasm-default make build-envoy-wasm
CARGO_TARGET_DIR=target/wasm-crs make build-envoy-wasm-crs
python3 benchmarks/envoy-dynamic/run.py \
  --native-default target/dynamic-default/release/libenvoy_coraza_dynamic.so \
  --native-crs target/dynamic-crs/release/libenvoy_coraza_dynamic.so \
  --wasm-default target/wasm-default/wasm32-wasip1/release/envoy_coraza.wasm \
  --wasm-crs target/wasm-crs/wasm32-wasip1/release/envoy_coraza.wasm
```

The script verifies allow/early-deny/late-deny outcomes before timing. It
records startup/configure time, throughput, p50/p95/p99, process CPU and RSS
samples, HTTP/2 stream multiplexing, and repeated downstream response-cancel
and upstream-reset outcomes. Minimal and pinned CRS policies use the same JSON
bytes for Wasm and native; audit logging is disabled for both, access logging is
disabled in the benchmark bootstrap, and request/response compression is not
used. Raw runs and per-workload medians/ranges are written to the Stage F
performance directory.
