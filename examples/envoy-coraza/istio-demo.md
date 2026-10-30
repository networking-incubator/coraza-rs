# Deploy the Coraza WAF filter on Istio

This guide deploys the Coraza WASM filter, with the OWASP Core Rule Set (CRS)
embedded, in front of a service on an Istio ingress Gateway. The filter is
served to Envoy over HTTP and digest-pinned; traffic is blocked with 403 when
it matches a CRS rule.

## 1. Install Gateway API and Istio

On an existing cluster, skip the first two commands.

```sh
kind create cluster --name coraza-demo
istioctl install -y --set profile=minimal
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml
```

## 2. Download the filter

```sh
RELEASE_TAG=$(curl -fsSL https://api.github.com/repos/networking-incubator/coraza-rs/releases \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)[0]["tag_name"])')
mkdir -p /tmp/coraza-demo
curl -fsSL -o /tmp/coraza-demo/coraza-rs-crs.wasm \
  "https://github.com/networking-incubator/coraza-rs/releases/download/$RELEASE_TAG/coraza-rs-crs.wasm"
WASM_SHA256=$(sha256sum /tmp/coraza-demo/coraza-rs-crs.wasm | cut -d' ' -f1)
```

Releases are cut nightly (`v0.0.0-nightly.YYYYMMDD`) and on `vX.Y.Z` tags;
the command above picks the newest. `coraza-rs.wasm` (without the CRS) is
published alongside it.

## 3. Serve the filter over HTTP

Envoy fetches the wasm module from an HTTP endpoint the gateway pods can
reach. On Kind, serve it from the docker bridge gateway:

```sh
FETCH_ADDRESS=$(docker network inspect coraza-demo --format '{{json .IPAM.Config}}' | python3 -c '
import json, sys
for config in json.load(sys.stdin):
    if ":" not in config["Gateway"]:
        print(config["Gateway"]); break
')
FETCH_PORT=8123
python3 -m http.server --bind "$FETCH_ADDRESS" "$FETCH_PORT" --directory /tmp/coraza-demo &
```

On another cluster, host `coraza-rs-crs.wasm` on any file server reachable
from the gateway pods and export its address and port as `FETCH_ADDRESS` /
`FETCH_PORT`.

## 4. Create the Gateway and route

The Gateway and HTTPRoute live in the same namespace as the Service they
route to (this avoids needing a ReferenceGrant). Replace `your-service`,
`your-namespace` and the port with the Service the WAF should protect:

```sh
kubectl apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: coraza-gateway
  namespace: your-namespace
spec:
  gatewayClassName: istio
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: Same
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: coraza-route
  namespace: your-namespace
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
          port: 80
EOF
```

## 5. Deploy the EnvoyFilter

Save as `/tmp/envoyfilter.yaml`:

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: coraza-demo
  namespace: your-namespace
spec:
  workloadSelector:
    labels:
      gateway.networking.k8s.io/gateway-name: coraza-gateway
  configPatches:
    # Cluster used by Envoy to fetch the wasm artifact.
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
    # Access log with the Coraza filter state.
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
            access_log:
              - name: envoy.access_loggers.file
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                  path: /dev/stdout
                  log_format:
                    text_format_source:
                      inline_string: "path=%REQ(:PATH)% event=%FILTER_STATE(wasm.io.coraza.waf.event:PLAIN)% rule_id=%FILTER_STATE(wasm.io.coraza.waf.rule_id:PLAIN)% phase=%FILTER_STATE(wasm.io.coraza.waf.phase:PLAIN)% action=%FILTER_STATE(wasm.io.coraza.waf.action:PLAIN)% status=%FILTER_STATE(wasm.io.coraza.waf.status:PLAIN)%\n"
    # The Coraza filter, immediately before the router.
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

Apply it with your endpoint and digest substituted:

```sh
sed -e "s|__WASM_URI__|http://$FETCH_ADDRESS:$FETCH_PORT/coraza-rs-crs.wasm|" \
    -e "s/__WASM_SHA256__/$WASM_SHA256/" \
    -e "s/__WASM_FETCH_ADDRESS__/$FETCH_ADDRESS/" \
    -e "s/__WASM_FETCH_PORT__/$FETCH_PORT/" \
    /tmp/envoyfilter.yaml | kubectl apply -f -
kubectl -n your-namespace rollout status deploy/coraza-gateway-istio
```

The `sha256` pin makes the fetch verifiable: if the served bytes do not
match, Envoy keeps the VM failed and, with `FAIL_CLOSED`, the gateway
returns 503 until the artifact is fixed.

## 6. Send traffic

```sh
GATEWAY_POD=$(kubectl -n your-namespace get pods -l gateway.networking.k8s.io/gateway-name=coraza-gateway -o name | head -1)
kubectl -n your-namespace port-forward "$GATEWAY_POD" 18080:80 &
until curl -s -o /dev/null http://127.0.0.1:18080/; do sleep 1; done

curl -i http://127.0.0.1:18080/                                # your service's response
curl -i 'http://127.0.0.1:18080/?file=../../../../etc/passwd'   # 403, CRS path traversal
curl -i 'http://127.0.0.1:18080/?id=1%20union%20select%20null'  # 403, CRS SQL injection
```

The matching CRS rule id is in the gateway access log:

```sh
kubectl -n your-namespace logs deploy/coraza-gateway-istio -c istio-proxy | grep rule_id
```

## 7. Clean up

```sh
kubectl -n your-namespace delete envoyfilter/coraza-demo gateway/coraza-gateway httproute/coraza-route
kill %1 %2 2>/dev/null || true   # port-forward and http.server
```

## Notes

- Change the rules by editing the `configuration` JSON in the EnvoyFilter;
  it accepts the connector's `directives_map` / `default_directives` /
  `per_authority_directives` schema.
- Envoy keeps an already-loaded wasm VM across EnvoyFilter replacements:
  restart the gateway deployment after applying a new artifact or digest.
- The same artifacts also ship as OCI images
  (`ghcr.io/networking-incubator/coraza-rs`, `nightly` tags) usable with
  Istio's `WASMPlugin` `image` field.
