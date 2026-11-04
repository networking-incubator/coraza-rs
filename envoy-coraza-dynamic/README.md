# Envoy Coraza native dynamic module

This crate builds an experimental native HTTP filter for standalone Envoy
1.40.0. It is a separate artifact from `envoy-coraza`'s Proxy-Wasm filter;
both use the same Coraza policy configuration, but the native module is not
sandboxed by Wasm.

## Build and test

The pinned Envoy SDK runs bindgen during compilation. Install `clang` and
`libclang-dev`, then use the workspace targets:

```sh
make build-envoy-dynamic
make build-envoy-dynamic-crs
make test-envoy-dynamic
```

The build produces `target/release/libenvoy_coraza_dynamic.so`. The CRS target
fetches the version pinned in `envoy-coraza/crs.pin` before enabling the
`embed-crs` feature. The integration harness needs Docker Compose, curl with
HTTP/2 support, Python 3, and an unused local port 9901; it runs the module only
from a local file in the pinned Envoy image, never from a remote module source.

## Deployment limits

- Tested host: digest-pinned standalone Envoy 1.40.0 on Linux/amd64 with glibc.
  This is not an Istio compatibility claim.
- Request and response retained-body ceilings are 16 MiB and 1 MiB per stream;
  a checked module-wide admission budget limits retained bodies to 64 MiB.
  Admission exhaustion fails closed. These limits do not bound Envoy's total
  process RSS.
- Request/response trailers are bounded and passed through when allowed, but
  trailer values are not SecLang rule variables. Residual compressed bodies,
  WebSocket/CONNECT inspection, HTTP/3, and indefinite SSE/gRPC bodies are not
  supported as fully inspected content.
- The first release intentionally writes the compatibility filter-state names
  `wasm.io.coraza.waf.*` and `wasm.io.coraza.waf.v1.*`; the `wasm.` prefix is
  retained explicitly and is not added by the native SDK.
- The native module executes in Envoy's address space. Panic containment does
  not isolate allocation aborts, memory corruption, fatal signals, or blocked
  worker threads. Load only trusted local artifacts and roll binaries by
  restarting Envoy; safe module unloading is not established.

The [integration harness guide](../examples/envoy-coraza-dynamic/README.md)
covers local execution; [CI checks](../docs/ci.md) lists the reproducible test
jobs.
