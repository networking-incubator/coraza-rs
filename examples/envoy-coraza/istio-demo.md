# Demo: run the Coraza WASM filter on an existing Istio cluster

A self-contained, manual step-by-step: download the released filter, serve it
from an HTTP endpoint, and deploy a Gateway + EnvoyFilter that inserts it in
front of a service you already have. No test harness, no Rust toolchain, and
no files beyond this page. The automated harness and its 52 gating assertions
live in PR #95 (`examples/envoy-coraza/istio/`); it automates exactly these
steps.

Verified against Istio 1.30.5 and 1.30.7 (Envoy 1.38.x) in Kind. The release
assets have the WASI ENOSYS stubs linked in, so they load unchanged on
Envoy 1.38 and newer; on Envoy 1.40+ the host provides the stubs itself and
the extra imports are simply unused.

## 0. Prerequisites

- An Istio cluster reachable with `kubectl`, and an HTTP service in it that
  you can route traffic to (any deployment + service works).
- Gateway API CRDs: check with
  `kubectl get crd gateways.gateway.networking.io`; if absent, install the
  standard channel:
  `kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.0/standard-install.yaml`.
- `curl`, `sha256sum`, `sed`, and `python3`.
- An HTTP endpoint the Istio gateway pods can reach, to serve the wasm
  artifact. On Kind that is a plain `python3 -m http.server` bound to the
  docker bridge gateway (step 2); in any other cluster, use any plain-HTTP
  file server reachable from the gateway pods.

## 1. Download the filter

The filter is published as release assets: `coraza-rs-crs.wasm` (with the
OWASP Core Rule Set embedded — this demo uses it) and `coraza-rs.wasm`
(core engine only, bring your own rules). Releases are cut nightly
(`v0.0.0-nightly.YYYYMMDD` prereleases) and on manual `vX.Y.Z` tags. Pick the
newest one — nightly prereleases never become the `latest` release, so query
the list rather than the `latest` endpoint:

```sh
RELEASE_TAG=$(curl -fsSL https://api.github.com/repos/networking-incubator/coraza-rs/releases \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)[0]["tag_name"])')
mkdir -p /tmp/coraza-demo
curl -fsSL -o /tmp/coraza-demo/coraza-rs-crs.wasm \
  "https://github.com/networking-incubator/coraza-rs/releases/download/$RELEASE_TAG/coraza-rs-crs.wasm"
WASM_SHA256=$(sha256sum /tmp/coraza-demo/coraza-rs-crs.wasm | cut -d' ' -f1)
echo "artifact sha256: $WASM_SHA256"
```

To build the filter from source instead, run `make build-envoy-wasm-crs`
from the repository root and link the WASI stubs into
`target/wasm32-wasip1/release/envoy_coraza.wasm` as described in the notes
at the end; the release assets are built with the same locked release flags.

## 2. Serve the artifact over HTTP

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

On another cluster, serve `/tmp/coraza-demo/coraza-rs-crs.wasm` from
any plain-HTTP endpoint reachable from the gateway pods, then set the same
variables to that endpoint:

```sh
FETCH_ADDRESS=artifact.example.com  # your endpoint host
FETCH_PORT=8080                      # your endpoint port
```

## 3. Create the Gateway and route

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

## 4. Deploy the EnvoyFilter

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
                        "crs": [
                          "SecRuleEngine On",
                          "SecRequestBodyAccess On",
                          "SecRequestBodyLimit 13107200",
                          "Include crs/crs-setup.conf",
                          "Include crs/rules/*.conf"
                        ]
                      },
                      "default_directives": "crs",
                      "enable_filter_state_logs": true
                    }
```

Substitute your endpoint and the digest, then apply:

```sh
sed -e "s|__WASM_URI__|http://$FETCH_ADDRESS:$FETCH_PORT/coraza-rs-crs.wasm|" \
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

## 5. Send traffic

Port-forward to the gateway pod and try a benign request and a blocked one:

```sh
GATEWAY_POD=$(kubectl -n coraza-demo get pods -l gateway.networking.k8s.io/gateway-name=coraza-gateway -o name | head -1)
kubectl -n coraza-demo port-forward "$GATEWAY_POD" 18080:80 &
# Wait until the forward accepts connections (kubectl prints
# "Forwarding from 127.0.0.1:18080" when it is ready).
until curl -s -o /dev/null http://127.0.0.1:18080/; do sleep 1; done
```

```sh
curl -i http://127.0.0.1:18080/                          # your service's response (status depends on the service)
curl -i 'http://127.0.0.1:18080/?file=../../../../etc/passwd'   # 403, CRS path traversal
curl -i 'http://127.0.0.1:18080/?id=1%20union%20select%20null'  # 403, CRS SQL injection
```

The matching CRS rule id is in the gateway's access log (next paragraph), in
the `rule_id` field.

Change the rules by editing the `configuration` JSON block of the
EnvoyFilter and re-applying: it accepts the `directives_map` /
`default_directives` / `per_authority_directives` schema of the connector.

The gateway's access log carries the Coraza filter-state per request:

```sh
kubectl -n coraza-demo logs deploy/coraza-gateway-istio -c istio-proxy | grep coraza_observability
```

## 6. Clean up

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
- Building from source on Envoy below 1.40: `make build-envoy-wasm-crs` does
  not link the WASI stubs (the release workflow does that with
  `envoy-coraza/wasi-stub.wat`), so link them into
  `target/wasm32-wasip1/release/envoy_coraza.wasm` yourself, with binaryen
  (`--all-features` is required: the artifact uses post-MVP wasm features
  that wasm-merge's conservative default validation rejects):

  ```sh
  wasm-as envoy-coraza/wasi-stub.wat -o /tmp/wasi-stub.wasm
  wasm-merge /tmp/wasi-stub.wasm wasi_snapshot_preview1 \
      target/wasm32-wasip1/release/envoy_coraza.wasm envoy-coraza \
      -o /tmp/coraza-demo/coraza-rs-crs.wasm \
      --rename-export-conflicts --all-features
  ```

  The stubs only satisfy the loader: the connector's validated configuration
  never reaches filesystem-backed features.

- The EnvoyFilter patches are scoped to listener port 80 and inserted
  immediately before `envoy.filters.http.router`. A second listener on the
  Gateway would not be covered.
- Envoy keeps serving an already-loaded wasm VM across EnvoyFilter
  replacements; to prove a new artifact is actually serving, restart the
  gateway deployment after re-applying.
- Update `WASM_SHA256` whenever the served artifact changes — the digest pin
  is what makes the fetch verifiable, and a stale digest fails the VM closed.
