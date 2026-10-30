# Demo: run the Coraza WASM filter on an existing Istio cluster

A self-contained, manual step-by-step: download the released filter, serve it
from an HTTP endpoint, and deploy a Gateway + EnvoyFilter that inserts it in
front of a service you already have. No test harness, no Rust toolchain, and
no files beyond this page. The automated harness and its 52 gating assertions
live in PR #95 (`examples/envoy-coraza/istio/`); it automates exactly these
steps.

Verified against Istio 1.30.5 and 1.30.7 (Envoy 1.38.x) in Kind. On Envoy
1.40 or newer the WASI-stub merge in step 2 is unnecessary (the host provides
the stubs); step 2 includes a direct-serve shortcut for that case.

## 0. Prerequisites

- An Istio cluster reachable with `kubectl`, and an HTTP service in it that
  you can route traffic to (any deployment + service works).
- Gateway API CRDs: check with
  `kubectl get crd gateways.gateway.networking.io`; if absent, install the
  standard channel:
  `kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.0/standard-install.yaml`.
- `curl`, `sha256sum`, `sed`, and `python3`. Binaryen's `wasm-as`/`wasm-merge`
  is only needed on Envoy below 1.40 (step 2; version 123 was used for
  validation:
  <https://github.com/WebAssembly/binaryen/releases/tag/version_123>).
- An HTTP endpoint the Istio gateway pods can reach, to serve the wasm
  artifact. On Kind that is a plain `python3 -m http.server` bound to the
  docker bridge gateway (step 3); in any other cluster, use any plain-HTTP
  file server reachable from the gateway pods.

## 1. Download the filter

The filter is published as release assets: `coraza-rs.wasm` (core rules only)
and `coraza-rs-crs.wasm` (with the Core Rule Set embedded; same shape, bigger
file). Releases are cut nightly (`v0.0.0-nightly.YYYYMMDD` prereleases) and
on manual `vX.Y.Z` tags. Pick the newest one — nightly prereleases never
become the `latest` release, so query the list rather than the `latest`
endpoint:

```sh
RELEASE_TAG=$(curl -fsSL https://api.github.com/repos/networking-incubator/coraza-rs/releases \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)[0]["tag_name"])')
mkdir -p /tmp/coraza-demo
curl -fsSL -o /tmp/coraza-demo/coraza-rs.wasm \
  "https://github.com/networking-incubator/coraza-rs/releases/download/$RELEASE_TAG/coraza-rs.wasm"
```

To build the filter from source instead, run `make build-envoy-wasm` from the
repository root and use `target/wasm32-wasip1/release/envoy_coraza.wasm` as
the input of step 2; the release assets are built with the same locked
release flags.

## 2. Link the WASI stubs (Envoy below 1.40, e.g. Istio 1.30)

The module imports five WASI functions that Envoy's Proxy-Wasm host did not
implement before Envoy 1.40; on Istio 1.30 (Envoy 1.38.x) the VM refuses to
load the module unless ENOSYS stubs are linked in. The stubs only satisfy
the loader: the connector's validated configuration never reaches
filesystem-backed features.

On Envoy 1.40 or newer, skip this section and serve the downloaded
`coraza-rs.wasm` directly:

```sh
cp /tmp/coraza-demo/coraza-rs.wasm /tmp/coraza-demo/envoy_coraza_istio.wasm
WASM_SHA256=$(sha256sum /tmp/coraza-demo/envoy_coraza_istio.wasm | cut -d' ' -f1)
```

Otherwise, save this as `/tmp/wasi-stub.wat`:

```wat
(module
  (func (export "fd_filestat_get") (param i32 i32) (result i32) (i32.const 52))
  (func (export "fd_readdir") (param i32 i32 i32 i64 i32) (result i32) (i32.const 52))
  (func (export "path_create_directory") (param i32 i32 i32) (result i32) (i32.const 52))
  (func (export "path_filestat_get") (param i32 i32 i32 i32 i32) (result i32) (i32.const 52))
  (func (export "path_unlink_file") (param i32 i32 i32) (result i32) (i32.const 52))
)
```

Then link it into the artifact (`--all-features` is required: the artifact
uses post-MVP wasm features that wasm-merge's conservative default
validation rejects):

```sh
mkdir -p /tmp/coraza-demo
wasm-as /tmp/wasi-stub.wat -o /tmp/wasi-stub.wasm
wasm-merge /tmp/wasi-stub.wasm wasi_snapshot_preview1 \
    /tmp/coraza-demo/coraza-rs.wasm envoy-coraza \
    -o /tmp/coraza-demo/envoy_coraza_istio.wasm \
    --rename-export-conflicts --all-features
WASM_SHA256=$(sha256sum /tmp/coraza-demo/envoy_coraza_istio.wasm | cut -d' ' -f1)
echo "artifact sha256: $WASM_SHA256"
```

## 3. Serve the artifact over HTTP

On Kind, bind a file server to the docker bridge gateway address, which the
cluster nodes can reach. It serves the dedicated directory holding only the
artifact:

```sh
FETCH_ADDRESS=$(docker network inspect kind --format '{{json .IPAM.Config}}' | python3 -c '
import json, sys
for config in json.load(sys.stdin):
    if ":" not in config["Gateway"]:
        print(config["Gateway"]); break
else:
    raise SystemExit("no IPv4 gateway on the kind network")
')
FETCH_PORT=8123
python3 -m http.server --bind "$FETCH_ADDRESS" "$FETCH_PORT" --directory /tmp/coraza-demo &
```

On another cluster, serve `/tmp/coraza-demo/envoy_coraza_istio.wasm` from
any plain-HTTP endpoint reachable from the gateway pods, then set the same
variables to that endpoint:

```sh
FETCH_ADDRESS=artifact.example.com  # your endpoint host
FETCH_PORT=8080                      # your endpoint port
```

## 4. Create the Gateway and route

The Gateway, route and grant live in a dedicated namespace; create it first:

```sh
kubectl create namespace coraza-demo
```

Replace `your-service` and `your-namespace` with the service the WAF should
protect, then apply:

```sh
kubectl apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: coraza-gateway
  namespace: coraza-demo
spec:
  gatewayClassName: istio
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: Selector
          selector:
            matchLabels:
              kubernetes.io/metadata.name: coraza-demo
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: coraza-route
  namespace: coraza-demo
spec:
  parentRefs:
    - name: coraza-gateway
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: your-service
          namespace: your-namespace
          port: 80 # replace with your Service's port (its port, not targetPort)
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-coraza-demo-routes
  namespace: your-namespace
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: coraza-demo
  to:
    - group: ""
      kind: Service
EOF
```

The Istio gateway-class controller creates a Deployment named
`coraza-gateway-istio` whose pods carry the label
`gateway.networking.k8s.io/gateway-name=coraza-gateway` — that is what the
EnvoyFilter selects on. The ReferenceGrant is required because the route
references a Service in another namespace; if you instead put the HTTPRoute
in the Service's own namespace, drop the grant, the `namespace:` field on
the backendRef, and keep the Gateway's namespace selector in mind (only
routes from `coraza-demo` may attach).

## 5. Deploy the EnvoyFilter

Save this as `/tmp/envoyfilter.yaml` — it is the template validated on both
pinned Istio versions, with the fetch cluster, the buffer-limit patch, an
access log that prints the Coraza filter state, and the wasm filter
inserted immediately before `envoy.filters.http.router`:

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: coraza-demo
  namespace: coraza-demo
spec:
  workloadSelector:
    labels:
      gateway.networking.k8s.io/gateway-name: coraza-gateway
  configPatches:
    # Listener: raise the per-connection buffer limit to 16 MiB. This matters
    # only while the filter holds response headers stopped (phase-4 header
    # rules): Envoy buffers the body against the default ~1 MiB limit. Harness
    # convenience, not a production recommendation.
    - applyTo: LISTENER
      match:
        context: GATEWAY
        listener:
          portNumber: 80
      patch:
        operation: MERGE
        value:
          per_connection_buffer_limit_bytes: 16777216
    # Cluster used by Envoy's remote-data fetcher for the wasm artifact.
    # Envoy 1.38's HttpUri only accepts an explicit cluster, hence STATIC.
    - applyTo: CLUSTER
      match:
        context: GATEWAY
      patch:
        operation: ADD
        value:
          name: coraza-wasm-fetch
          type: STATIC
          connect_timeout: 5s
          load_assignment:
            cluster_name: coraza-wasm-fetch
            endpoints:
              - lb_endpoints:
                  - endpoint:
                      address:
                        socket_address:
                          address: __WASM_FETCH_ADDRESS__
                          port_value: __WASM_FETCH_PORT__
    # HCM: enable HTTP/1.1 request trailers and log the coraza filter-state.
    - applyTo: NETWORK_FILTER
      match:
        context: GATEWAY
        listener:
          portNumber: 80
          filterChain:
            filter:
              name: envoy.filters.network.http_connection_manager
      patch:
        operation: MERGE
        value:
          name: envoy.filters.network.http_connection_manager
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
            http_protocol_options:
              enable_trailers: true
            access_log:
              - name: envoy.access_loggers.file
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                  path: /dev/stdout
                  log_format:
                    text_format_source:
                      inline_string: "path=%REQ(:PATH)% coraza_observability event=%FILTER_STATE(wasm.io.coraza.waf.event:PLAIN)% rule_id=%FILTER_STATE(wasm.io.coraza.waf.rule_id:PLAIN)% phase=%FILTER_STATE(wasm.io.coraza.waf.phase:PLAIN)% action=%FILTER_STATE(wasm.io.coraza.waf.action:PLAIN)% status=%FILTER_STATE(wasm.io.coraza.waf.status:PLAIN)% reason=%FILTER_STATE(wasm.io.coraza.waf.v1.inspection_reason:PLAIN)% outcome=%FILTER_STATE(wasm.io.coraza.waf.v1.terminal_outcome:PLAIN)% details=%RESPONSE_CODE_DETAILS%\n"
    # The wasm HTTP filter, immediately before the router.
    - applyTo: HTTP_FILTER
      match:
        context: GATEWAY
        listener:
          portNumber: 80
          filterChain:
            filter:
              name: envoy.filters.network.http_connection_manager
              subFilter:
                name: envoy.filters.http.router
      patch:
        operation: INSERT_BEFORE
        value:
          name: envoy.filters.http.wasm
          typed_config:
            "@type": type.googleapis.com/udpa.type.v1.TypedStruct
            type_url: type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
            value:
              config:
                name: coraza-demo
                root_id: coraza-demo
                failure_policy: FAIL_CLOSED
                allow_on_headers_stop_iteration: true
                vm_config:
                  runtime: envoy.wasm.runtime.v8
                  code:
                    remote:
                      http_uri:
                        uri: __WASM_URI__
                        timeout: 120s
                        cluster: coraza-wasm-fetch
                      sha256: __WASM_SHA256__
                      retry_policy:
                        retry_back_off:
                          base_interval: 1s
                          max_interval: 10s
                        num_retries: 5
                configuration:
                  "@type": type.googleapis.com/google.protobuf.StringValue
                  value: |
                    {
                      "directives_map": {
                        "main": [
                          "SecRuleEngine On",
                          "SecRequestBodyAccess On",
                          "SecRule REQUEST_URI \"@streq /phase1-deny\" \"id:101,phase:1,deny,status:403,msg:'demo blocked'\"",
                          "SecRule ARGS \"@contains attack\" \"id:102,phase:1,deny,status:403\""
                        ]
                      },
                      "default_directives": "main",
                      "enable_filter_state_logs": true
                    }
```

Substitute your endpoint and the digest, then apply:

```sh
sed -e "s|__WASM_URI__|http://$FETCH_ADDRESS:$FETCH_PORT/envoy_coraza_istio.wasm|" \
    -e "s/__WASM_SHA256__/$WASM_SHA256/" \
    -e "s/__WASM_FETCH_ADDRESS__/$FETCH_ADDRESS/" \
    -e "s/__WASM_FETCH_PORT__/$FETCH_PORT/" \
    /tmp/envoyfilter.yaml | kubectl apply -f -
```

The `sha256` in `code.remote` makes the fetch verifiable: if the served
bytes do not match, Envoy keeps the VM failed and, with
`failure_policy: FAIL_CLOSED`, the gateway rejects traffic with 503 until
the artifact is fixed.

Wait for the gateway deployment to be ready:

```sh
kubectl -n coraza-demo rollout status deploy/coraza-gateway-istio
```

## 6. Send traffic

Port-forward to the gateway pod and try a benign request and a blocked one:

```sh
GATEWAY_POD=$(kubectl -n coraza-demo get pods -l gateway.networking.k8s.io/gateway-name=coraza-gateway -o name | head -1)
kubectl -n coraza-demo port-forward "$GATEWAY_POD" 18080:80 &
# Wait until the forward accepts connections (kubectl prints
# "Forwarding from 127.0.0.1:18080" when it is ready).
until curl -s -o /dev/null http://127.0.0.1:18080/; do sleep 1; done
```

```sh
curl -i http://127.0.0.1:18080/             # your service's response (status depends on the service)
curl -i http://127.0.0.1:18080/phase1-deny  # 403 from rule 101 (phase 1)
curl -i 'http://127.0.0.1:18080/?q=attack'  # 403 from rule 102 (phase 1)
```

Change the rules by editing the `configuration` JSON block of the
EnvoyFilter and re-applying: it accepts the `directives_map` /
`default_directives` / `per_authority_directives` schema of the connector.

The gateway's access log carries the Coraza filter-state per request:

```sh
kubectl -n coraza-demo logs deploy/coraza-gateway-istio -c istio-proxy | grep coraza_observability
```

## 7. Clean up

```sh
kubectl delete envoyfilter coraza-demo -n coraza-demo
kubectl delete gateway coraza-gateway -n coraza-demo
kubectl delete httproute coraza-route -n coraza-demo
kill %1 %2 2>/dev/null || true   # port-forward and http.server
```

## Notes and footguns

- The same artifacts also ship as scratch OCI images
  (`ghcr.io/networking-incubator/coraza-rs`, tags `nightly` and
  `nightly-YYYYMMDD`, plus a `-crs` variant) that can be pulled directly by
  Istio's `WASMPlugin` `image` field; this demo sticks to EnvoyFilter remote
  fetch.

- The EnvoyFilter patches are scoped to listener port 80 and inserted
  immediately before `envoy.filters.http.router`. A second listener on the
  Gateway would not be covered.
- Envoy keeps serving an already-loaded wasm VM across EnvoyFilter
  replacements; to prove a new artifact is actually serving, restart the
  gateway deployment after re-applying.
- Update `WASM_SHA256` on every rebuild — the digest pin is what makes the
  fetch verifiable, and a stale digest fails the VM closed.
