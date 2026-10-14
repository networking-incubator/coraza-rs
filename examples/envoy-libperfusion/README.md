# Envoy libperfusion filter

This example runs the Rust Proxy-Wasm filter in standalone Envoy 1.40.0 with
the Gateway API conformance echo-basic v0.2.0 image. It exercises request
and response inspection, request decompression, body limits and WAF outcomes.

## Build and run

From the repository root:

```sh
make build-envoy-wasm
cd examples/envoy-libperfusion
docker compose up --detach
```

Envoy listens on http://localhost:10000. The default envoy.yaml uses detect
for both directions with report for incomplete inspection so the example can
pass content types without a parser. The plugin's built-in defaults remain
detect plus reject; detect always passes incomplete messages and logs the
coverage gap. The reject policy applies in block mode.

Try ordinary traffic and an encoded SQLi query:

```sh
curl -i http://localhost:10000/
curl -i 'http://localhost:10000/?q=1%27%20OR%20%271%27=%271'
```

The default detect profile inspects and logs the SQLi query, then forwards it.
To see requests blocked, switch to the blocking profile and try an SQLi query
and an XSS body:

```sh
docker compose down
ENVOY_CONFIG=envoy-blocking.yaml docker compose up --detach
curl -i 'http://localhost:10000/?q=1%27%20OR%20%271%27=%271'
curl -i --header 'content-type: application/json' \
  --data-binary '{"comment":"\u003cscript\u003ealert(1)\u003c/script\u003e"}' \
  http://localhost:10000/
```

Both requests should return HTTP 403 with the generic body
`Request blocked by security policy`. This profile also rejects incomplete
inspection. A body above its 8 MiB plugin cap receives 413. The route and
listener limits must be increased together when changing this profile; the
plugin cannot cap memory Envoy allocates before a callback.

To let a test request reach the upstream while blocking an unsafe response:

```sh
docker compose down
ENVOY_CONFIG=envoy-response-blocking.yaml docker compose up --detach
curl -i 'http://localhost:10000/?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E'
```

This request reaches the echo upstream, but the reflected XSS response should
be replaced with HTTP 502.

The echo image reflects request metadata as JSON and supports response headers
through x-echo-set-header. For example, this causes the upstream to emit an
unsafe Set-Cookie value:

```sh
curl -i -H 'x-echo-set-header: set-cookie:preview=%253Cscript%253Ealert(1)%253C%252Fscript%253E' \
  http://localhost:10000/
```

This unsafe response header should also produce HTTP 502. Stop the example when
finished with `docker compose down`.

With a direction set to block, request detections return a generic 403 and
blocked upstream responses become a generic 502. The 502 replaces the upstream
body and headers. SQLi/XSS signals and incomplete-coverage reasons are logged
without logging request or response contents.

## Verify the running filter

With Docker available, run this from the example directory after building the
Wasm artifact:

```sh
./test-envoy.sh
```

The Bash harness uses the pinned Envoy image and Gateway API echo-basic image.
It checks SQLi/XSS request blocking, percent-encoded headers, cookies and
bodies, request gzip decompression, reflected response-body and response-header
blocking, multipart SQLi, HTTP/2 gRPC trailers, plus 8 MiB accepted versus 9
MiB rejected uploads.

## Coverage and limits

The filter checks all exposed request/response header names and byte values,
up to four successive percent-decoded views of headers and bodies, request
paths and decoded query pairs, cookie pairs, raw bodies, form fields,
JSON keys/string values (including duplicate keys), multipart names, text-field
values and file names. Nested JSON and URL-encoded parts are parsed; other
structured part types are marked incomplete. File payloads receive raw-body
scanning only. SQLi and XSS are the only libperfusion detectors.

Configured body limits can be at most 64 MiB; a field can be at most 1 MiB and
cannot exceed the request body limit. Field count and JSON depth are capped at
65,536 and 128. Envoy's own buffering limits should be set to match the plugin
limits because the plugin cannot cap memory allocated before its callbacks.

Raw and percent-decoded values are both inspected, up to four decoding layers.
Malformed path/form encodings and values still encoded beyond that bound are
marked incomplete; the strict profile rejects them. Checking decoded
alternatives can flag opaque values that an application treats literally, so
use detect/report to tune before enabling block/reject.

The request gzip decompressor runs before the Wasm filter. Response gzip stays
encoded and is marked as incomplete coverage: in this Envoy 1.40 setup, its
response decompressor did not deliver end-of-stream to a paused Proxy-Wasm body
callback, so the strict profile replaces such a response with 502. The
echo-basic image does not emit compressed or oversized responses, so those
response cases are not exercised by this integration harness.

URL-encoded forms and JSON are decoded with their format parsers. XML and
other unsupported structured application/* bodies are marked incomplete;
unknown and application/octet-stream bodies get raw-byte inspection only.
The echo image reflects request metadata, not request bodies, so the harness
checks large request acceptance and WAF outcomes but does not assert a
byte-exact body round trip. The 8 MiB upload example does not unpack archives
or inspect files according to their application-specific formats.

Detection is heuristic. Response HTML containing legitimate script can be
flagged by XSS detection. Start in detect, review logs and incomplete
coverage, then choose blocking modes and exceptions for actual application
traffic.

## Istio example

The Docker build compiles the plugin in the official Rust 1.97.1 image, then
packages only `/plugin.wasm` in a `scratch` image. The result is an artifact
image for Istio to fetch, not a runnable service.

Build and push a versioned image to a registry reachable by the Istio agents:

```sh
make build-envoy-wasm-image ENVOY_WASM_IMAGE=docker.io/rpkatz/libperfusion-wasm:0.2.0
docker push docker.io/rpkatz/libperfusion-wasm:0.2.0
```

Use the manifest digest printed by `docker push` in the Istio resource so
proxies load an immutable artifact. This example uses the `TrafficExtension`
API; see the
[Istio Wasm module guide](https://istio.io/latest/docs/tasks/extensibility/wasm-modules/)
and [TrafficExtension reference](https://istio.io/latest/docs/reference/config/proxy_extensions/traffic_extension/).

The checked-in [TrafficExtension manifest](istio/traffic-extension.yaml) pins
the image digest above and attaches to the existing `istio-ingress/gateway`
Gateway. It is configured for the test cluster's HTTPRoute host
`some.example.tld` and echo service. It enables the interim request-body flow
for Istio, rejects incomplete inspection and leaves response inspection off.
Change its namespace, target Gateway, image URL, and request host for a
different cluster.

Apply it from the repository root. After Istio loads the artifact, try a
normal GET and POST, then SQLi and XSS probes in the query, header and body:

```sh
kubectl apply -f examples/envoy-libperfusion/istio/traffic-extension.yaml
GATEWAY_IP="$(kubectl get gateway -n istio-ingress gateway -o jsonpath='{.status.addresses[0].value}')"
curl -i -H 'Host: some.example.tld' "http://${GATEWAY_IP}/"
curl -i -H 'Host: some.example.tld' --data-urlencode 'query=hello' "http://${GATEWAY_IP}/"
curl -i -H 'Host: some.example.tld' "http://${GATEWAY_IP}/?q=1%27%20OR%20%271%27=%271"
curl -i -H 'Host: some.example.tld' "http://${GATEWAY_IP}/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
curl -i -H 'Host: some.example.tld' \
  -H 'x-untrusted: <script>alert(1)</script>' "http://${GATEWAY_IP}/"
curl -i -H 'Host: some.example.tld' \
  -H "x-untrusted: 1' OR '1'='1" "http://${GATEWAY_IP}/"
curl -i -H 'Host: some.example.tld' \
  --data-urlencode 'query=1 UNION SELECT password FROM users' "http://${GATEWAY_IP}/"
curl -i -H 'Host: some.example.tld' -H 'content-type: application/json' \
  --data-binary '{"comment":"<script>alert(1)</script>"}' "http://${GATEWAY_IP}/"
head -c 1048577 /dev/zero | curl -i -H 'Host: some.example.tld' \
  --data-binary @- "http://${GATEWAY_IP}/"
kubectl delete -f examples/envoy-libperfusion/istio/traffic-extension.yaml
```

The normal requests should return HTTP 200; the SQLi and XSS probes should
return HTTP 403, and the 1 MiB-plus request should return HTTP 413. The filter
checks headers before continuing them, then holds the body until it has
inspected the complete request. In this interim mode, clean request headers can
reach the upstream before a body-based rejection. Use it only where upstreams
do not perform sensitive actions based on headers alone. Increase the body
limit only to a bound that fits the gateway's memory budget. Unsupported,
streaming or oversized requests are rejected because incomplete inspection is
set to `reject`.

Response inspection remains disabled because response blocking still needs
header-stop support to replace the status and body safely. The local Envoy
integration harness also exercises the request-compatible mode with header-stop
support disabled. Live-test this manifest against the Envoy version bundled
with your Istio release before deploying it beyond an isolated test Gateway.

For a private registry, configure image pull credentials as required by the
Istio proxy. Verify compatibility with the Envoy runtime bundled with any
other Istio release before deployment.
