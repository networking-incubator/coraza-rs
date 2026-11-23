# Deploy the Coraza WAF filter on Istio

This guide deploys the Coraza WASM filter, with the OWASP Core Rule Set (CRS)
embedded, in front of a service on an Istio ingress Gateway. The filter is
served to Envoy over HTTP and digest-pinned; traffic is blocked with 403 when
it matches a CRS rule.

## 1. Install Gateway API and Istio

On an existing cluster, skip the first two commands.

```sh
kind create cluster
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
FETCH_ADDRESS=$(docker network inspect kind --format '{{json .IPAM.Config}}' | python3 -c '
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
    # The connection manager settings the filter depends on (envoy-coraza/README.md, "Required Envoy
    # configuration"), and an access log with the Coraza filter state.
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
            use_remote_address: true
            # The number of trusted proxies in front of the gateway, such as a cloud load balancer: 0 when clients
            # connect to it directly. See step 6 for a value this patch cannot set.
            xff_num_trusted_hops: 0
            strip_trailing_host_dot: true
            strip_any_host_port: true
            normalize_path: true
            merge_slashes: true
            path_with_escaped_slashes_action: REJECT_REQUEST
            common_http_protocol_options:
              headers_with_underscores_action: REJECT_REQUEST
            # Finite, and long enough for the largest upload to arrive.
            request_timeout: 60s
            stream_idle_timeout: 60s
            access_log:
              - name: envoy.access_loggers.file
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                  path: /dev/stdout
                  log_format:
                    text_format_source:
                      inline_string: "path=%REQ(:PATH)% event=%FILTER_STATE(wasm.io.coraza.waf.event:PLAIN)% rule_id=%FILTER_STATE(wasm.io.coraza.waf.rule_id:PLAIN)% phase=%FILTER_STATE(wasm.io.coraza.waf.phase:PLAIN)% action=%FILTER_STATE(wasm.io.coraza.waf.action:PLAIN)% status=%FILTER_STATE(wasm.io.coraza.waf.status:PLAIN)%\n"
    # Legacy rewrite headers that would select a path no path rule saw.
    - applyTo: ROUTE_CONFIGURATION
      match:
        context: GATEWAY
      patch:
        operation: MERGE
        value:
          request_headers_to_remove:
            - x-original-url
            - x-rewrite-url
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
                          "Include @recommended-conf",
                          "SecRuleEngine On",
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

## 6. Check the gateway's connection manager

The filter depends on Envoy settings that istiod generates or that the patch
above merges in; see
[Required Envoy configuration](../../envoy-coraza/README.md#required-envoy-configuration).
Do not assume Istio's defaults: dump the gateway's listener, routes and
clusters and check each row. The dumps go to a new directory, not to
`/tmp/coraza-demo`, which step 3 serves over HTTP.

```sh
GATEWAY_POD=$(kubectl -n your-namespace get pods -l gateway.networking.k8s.io/gateway-name=coraza-gateway -o jsonpath='{.items[0].metadata.name}')
CHECK_DIR=$(mktemp -d)
istioctl proxy-config listener "$GATEWAY_POD" -n your-namespace --port 80 -o json >"$CHECK_DIR/listener.json"
istioctl proxy-config route "$GATEWAY_POD" -n your-namespace -o json >"$CHECK_DIR/routes.json"
istioctl proxy-config cluster "$GATEWAY_POD" -n your-namespace -o json >"$CHECK_DIR/clusters.json"
python3 - "$CHECK_DIR" <<'PY'
import json
import re
import sys

dumps = {}
for name in ("listener", "routes", "clusters"):
    with open(f"{sys.argv[1]}/{name}.json") as dump_file:
        dumps[name] = json.load(dump_file)


def values(node, key):
    """Every value of `key`, in snake_case or camelCase, anywhere under `node`."""
    camel = re.sub(r"_(.)", lambda match: match.group(1).upper(), key)
    if isinstance(node, dict):
        for name, value in node.items():
            if name in (key, camel):
                yield value
            yield from values(value, key)
    elif isinstance(node, list):
        for item in node:
            yield from values(item, key)


required = {
    "failure_policy": "FAIL_CLOSED",
    "allow_on_headers_stop_iteration": True,
    "use_remote_address": True,
    "strip_trailing_host_dot": True,
    "strip_any_host_port": True,
    "normalize_path": True,
    "merge_slashes": True,
    "path_with_escaped_slashes_action": "REJECT_REQUEST",
    "headers_with_underscores_action": "REJECT_REQUEST",
}
for key, want in required.items():
    found = list(values(dumps["listener"], key))
    verdict = "ok   " if found and all(value == want for value in found) else "FIX  "
    print(f"{verdict}{key}: {found or 'absent'} (want {want!r})")
removed = {name for names in values(dumps["routes"], "request_headers_to_remove") for name in names}
verdict = "ok   " if {"x-original-url", "x-rewrite-url"} <= removed else "FIX  "
print(f"{verdict}request_headers_to_remove: {sorted(removed) or 'absent'} (want x-original-url and x-rewrite-url)")
# JSON output leaves out a field at its default (0, false or unset), so absent means that default.
checks = [
    ("listener", "xff_num_trusted_hops", "the number of trusted proxies in front of the gateway"),
    ("listener", "proxy_100_continue", "absent or false"),
    ("listener", "stream_idle_timeout", "finite, sized to the largest upload"),
    ("listener", "request_timeout", "finite, sized to the largest upload"),
    ("listener", "max_request_headers_kb", "absent, the default 60"),
    ("listener", "accept_http_10", "absent or false"),
    ("listener", "per_connection_buffer_limit_bytes", "13107200 to 16777216; absent is 1 MiB"),
    ("clusters", "per_connection_buffer_limit_bytes", "13107200 to 16777216; absent is 1 MiB"),
    ("routes", "request_body_buffer_limit", "13107200 to 16777216, or absent"),
    ("routes", "domains", "the protected hosts, not *, when per-authority policies differ"),
]
for dump, key, want in checks:
    found = sorted({json.dumps(value) for value in values(dumps[dump], key)})
    print(f"check {dump} {key}: {', '.join(found) or 'absent'} (want {want})")
PY
```

Every `FIX` row needs the patch of step 5 or a change to it. Of the `check`
rows, `xff_num_trusted_hops` must equal the number of trusted proxies in front
of the gateway, `proxy_100_continue` must be absent or `false`, and both
timeouts must be finite and sized to the largest upload. The buffer limits must
be at least the largest `SecRequestBodyLimit` in use, 13107200 for this guide's
policy (from `@recommended-conf`), and at most 16 MiB, or Envoy answers 413 or
500 itself for larger bodies; the virtual host `domains` must name the protected
hosts rather than `*` whenever per-authority policies differ. A `MERGE` leaves a
field it sets to `0` or `false` as it was, so when the dump shows another
`xff_num_trusted_hops` or `proxy_100_continue: true`, change the value istiod
generates instead, for example through the gateway's `numTrustedProxies` proxy
setting. The dumps cannot show two rows of the table: keep Envoy's
`envoy.reloadable_features.http_reject_path_with_fragment` runtime flag at its
default, and Envoy's `wasm` log level at `warn` or more verbose, or the rule
lines and the filter's configure-time warnings and notices are dropped (audit
lines, logged at `critical`, are dropped only at `off`). Remove `$CHECK_DIR`
when done.

## 7. Send traffic

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

## 8. Clean up

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
  (`ghcr.io/networking-incubator/coraza-rs`, `nightly` tags), but deploy them
  with the `EnvoyFilter` form of this guide, not Istio's `WasmPlugin`. The
  `WasmPlugin` API has no field for `allow_on_headers_stop_iteration` (read in
  `istio.io/api` v1.30.5 and v1.32.0-alpha); without it every inspected body
  hangs until the idle timeout, and whether istiod sets it internally is not
  verified.
