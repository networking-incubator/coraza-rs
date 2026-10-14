# Envoy libperfusion filter

This example runs the Rust Proxy-Wasm filter in standalone Envoy 1.40.0 with
the Gateway API conformance echo-basic v0.2.0 image. It exercises request
and response inspection, request decompression, body limits and WAF outcomes.

## Build and run

From the repository root:

```sh
cargo build --locked --release --target wasm32-wasip1 -p envoy-libperfusion
cd examples/envoy-libperfusion
docker compose up
```

Envoy listens on http://localhost:10000. The default envoy.yaml uses detect
for both directions with report for incomplete inspection so the example can
pass content types without a parser. The plugin's built-in defaults remain
detect plus reject; production rollout should choose the incomplete policy
deliberately.

Try ordinary traffic and an encoded SQLi query:

```sh
curl -i http://localhost:10000/
curl -i 'http://localhost:10000/?q=1%27%20OR%20%271%27=%271'
```

For request blocking and the 8 MiB upload profile, run:

```sh
ENVOY_CONFIG=envoy-blocking.yaml docker compose up
```

That profile blocks request and response detections and rejects incomplete
inspection. A body above the 8 MiB plugin cap receives 413. The route and
listener limits must be increased together when changing this profile; the
plugin cannot cap memory Envoy allocates before a callback.

To let a test request reach the upstream while blocking an unsafe response:

```sh
ENVOY_CONFIG=envoy-response-blocking.yaml docker compose up
curl -i 'http://localhost:10000/?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E'
```

The echo image reflects request metadata as JSON and supports response headers
through x-echo-set-header. For example, this causes the upstream to emit an
unsafe Set-Cookie value:

```sh
curl -i -H 'x-echo-set-header: set-cookie:preview=%253Cscript%253Ealert(1)%253C%252Fscript%253E' \
  http://localhost:10000/
```

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
blocking, plus 8 MiB accepted versus 9 MiB rejected uploads.

## Coverage and limits

The filter checks all exposed request/response header names and byte values,
up to four successive percent-decoded views of headers and bodies, request
paths and decoded query pairs, cookie pairs, raw bodies, form fields,
JSON keys/string values (including duplicate keys), multipart part names and
file names. It scans multipart part/file payloads in the raw body. SQLi and
XSS are the only libperfusion detectors.

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
