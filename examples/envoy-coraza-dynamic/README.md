# Envoy Coraza native dynamic-module harness

Run the native integration suite with:

```sh
python3 examples/envoy-coraza-dynamic/test.py native
```

The runner uses Python 3's standard library plus Docker Compose, curl with HTTP/2,
Rust, clang, and libclang. It reuses `examples/envoy-coraza/backend.go` and tests
startup rejection, request/response enforcement, body limits and framing,
trailers, HTTP/2, multiple workers and filter instances, and the feature-gated
panic path. Cancellation, admission exhaustion, and panic recovery each must be
followed by a byte-exact 8 MiB upload while other requests hold 39 MiB.
Trailer values are budget-checked but are not SecLang variables.
The checked-in `envoy.yaml` uses `{}` as an explicit uninspected baseline; it is
not a protective policy configuration to deploy unchanged. Filter-state output
uses the explicit legacy `wasm.io.coraza.waf.*` compatibility keys.

Response body inspection accepts identity encoding only. An upstream response
with another `Content-Encoding` returns 502 when response body access is enabled
and the response MIME type is inspectable.
Put Envoy's decompressor after Coraza in the filter list so reverse response
filter order decompresses first, or disable response body access on routes that
serve compressed responses.

Run the CRS FTW suite through the native module with `make test-envoy-dynamic-ftw`.
By default this checks out the pinned CRS test source and records a new run
directory under `target/envoy-coraza-dynamic-ftw/`. It invokes the pinned
upstream go-ftw CLI directly against Envoy; Go, Git and network access are
required for the pinned test checkout. A full run may return nonzero for known
CRS/Envoy differences. Set
`FTW_INCLUDE_TESTS` to a Go regular expression to bound the run and
`FTW_ALLOW_FAILURES_FILE` to permit only an explicit baseline failure set. The
CI gate runs five previously failing cases and five passing controls; it allows
four residual baseline failures but requires `944110-18` to pass. It is a
regression sample, not a full conformance or native/Wasm parity claim. The
runner waits 25 ms between up to 100 marker retries to let Envoy's asynchronous
log writes land. It records the upstream JSON summary, access log and run
metadata. Full historical native/Wasm/engine attribution is kept separately in
the [evidence branch](https://github.com/rikatz/coraza-rs/tree/envoy-coraza-dynamic-evidence/docs/performance/envoy-coraza-dynamic-stage-f/ftw).

Run the derived-image and native/Wasm rollback checks with:

```sh
ENVOY_IMAGE=my-derived-image ENVOY_PLATFORM=linux/arm64 python3 examples/envoy-coraza-dynamic/test.py derived-image
python3 examples/envoy-coraza-dynamic/test.py rollback
```

The derived-image command needs `readelf`; when `ARCHITECTURE`, `PLATFORM`, and
`PROFILE` are set, it builds the image with Docker Buildx before testing it.

The bootstrap is static and does not use xDS/ECDS. A live rejected filter
configuration update with in-flight requests is therefore not tested. The
native-host lifecycle and Stage E acceptance evidence is kept on the
[evidence branch](https://github.com/rikatz/coraza-rs/tree/envoy-coraza-dynamic-evidence).

## Switch between Wasm and native

The two filters are alternatives. Replace the Wasm entry in the HTTP filter
chain with the native entry; **never configure both on one chain**. Both entries
must carry the exact same policy JSON bytes in their `google.protobuf.StringValue`
`value`. Do not translate, reformat, or otherwise change the policy during a
rollback.

The Wasm form wraps the JSON in `configuration`:

```yaml
- name: envoy.filters.http.wasm
  typed_config:
    "@type": type.googleapis.com/udpa.type.v1.TypedStruct
    type_url: type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
    value:
      config:
        name: envoy-coraza
        root_id: envoy-coraza
        failure_policy: FAIL_CLOSED
        allow_on_headers_stop_iteration: true
        vm_config:
          runtime: envoy.wasm.runtime.v8
          code:
            local:
              filename: /etc/envoy/envoy_coraza.wasm
        configuration:
          "@type": type.googleapis.com/google.protobuf.StringValue
          value: |
            {"directives_map":{"default":["SecRuleEngine On"]},"default_directives":"default"}
```

Replace that single list item with the native form, copying the JSON value
verbatim:

```yaml
- name: envoy.filters.http.dynamic_modules
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter
    dynamic_module_config:
      name: envoy_coraza_dynamic
      do_not_close: true
      load_globally: false
    filter_name: coraza
    filter_config:
      "@type": type.googleapis.com/google.protobuf.StringValue
      value: |
        {"directives_map":{"default":["SecRuleEngine On"]},"default_directives":"default"}
```

The example JSON above is only a transport example; deploy the policy that has
been validated for your service, not this minimal policy.

Artifact installation differs. The Wasm filter uses the Wasm asset/WASMPlugin
or its OCI distribution. The native filter uses the matching, digest-pinned
Envoy 1.40.0 derived image (`ghcr.io/networking-incubator/coraza-rs-dynamic-envoy`
or `...-dynamic-crs-envoy`), or a locally installed `.so` at
`/opt/envoy/modules/libenvoy_coraza_dynamic.so` with
`ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/opt/envoy/modules`. Keep the module
root-owned and non-writable by Envoy's runtime UID, and roll the Envoy process
when replacing it; do not overwrite a loaded library.

Filter-state compatibility keys remain `wasm.io.coraza.waf.*` and
`wasm.io.coraza.waf.v1.*` with either adapter. Switching is not a filter-state
key migration. For rollback, switch the one filter-chain item back to the Wasm
entry and the Wasm artifact/image while keeping the policy JSON value unchanged.
The `rollback` subcommand swaps the native filter for Wasm with identical policy
bytes, then checks a denial and allowed upload on each. Stage F evidence records
the results.
