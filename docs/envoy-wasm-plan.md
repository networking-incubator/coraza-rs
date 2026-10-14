# Envoy Wasm plugin using libperfusion: context and implementation status

Research date: 2026-10-14. Status: initial implementation complete. The Wasm
artifact builds and the Envoy 1.40 blocking-profile integration checks pass.

The selected outcome is an Envoy HTTP Wasm filter that checks request and
response headers and bodies using libperfusion. Request and response modes are
independently configurable as `off`, `detect` or `block`; incomplete coverage
is configurable as `reject` or `report`. The example uses `detect` plus
`report`, while the integration profile uses blocking plus `reject`.

The user selected standalone Envoy 1.40, regular HTTP traffic and an 8 MiB
upload example. Istio is a later integration and is outside this implementation.
The example pins Envoy 1.40.0 by digest. The demonstration settings are not
production limits.

## What the repository already supplies

The workspace contains `libperfusion` and the host-side maintenance tool
`xtask`. There is no existing Envoy adapter, HTTP extraction layer, Wasm crate
or deployment configuration in the inspected tree. The natural integration
boundary is libperfusion's public byte API; no detector refactor is required.
See [workspace manifest](../Cargo.toml), [public API](../libperfusion/src/lib.rs)
and [library guide](../libperfusion/README.md).

| Existing API | Meaning for the plugin |
| --- | --- |
| `sqli(&[u8]) -> Option<Fingerprint>` | SQLi verdict with a compact matching fingerprint. |
| `sqli_with_dialect` | Optional additional SQL dialect information. |
| `xss(&[u8]) -> bool` | XSS candidate detection across HTML and attribute contexts. |
| `xss_with_context` | Optional matching HTML context for diagnostics. |
| `xss_in_context` | A selected HTML context, when the consumer has that knowledge. |
| `sqli_with_limit`, `xss_with_limit` | Prefix inspection only; a negative result does not cover the omitted suffix. |
| SQL/HTML tokenizers and `SqlState` | Lower-level analysis; unnecessary for the initial adapter. |

There are **two detection families: SQLi and XSS**. The lower-level APIs are
not additional vulnerability detectors. The crate does not provide a Coraza
rule engine, CRS, application schema validation, URL/form/JSON extraction,
decompression, command injection detection, path traversal detection or
malware scanning. Transport and parsing validation in this plan belongs to
the adapter or Envoy, not to an expanded claim about libperfusion.

Inputs are bytes, and the library instructs callers to decode them as the
application does. Detection uses `std` and does not allocate on its detection
paths; the adapter's host reads and parsing will allocate. Its runtime
dependency is `memchr`; native build-time table generation stays on the
build host. Keeping `std` is compatible with the proposed Wasm target.
See [crate manifest](../libperfusion/Cargo.toml) and
[build script](../libperfusion/build.rs).

Compatibility is intentionally selected against pinned C and Go references,
with reviewed differences. Preserve those verdicts and the
[mismatch ledger](../libperfusion/tests/parity/mismatch-ledger.md). Existing
[performance measurements](performance.md) are native measurements and do
not establish Envoy/Wasm latency or throughput.

Repository requirements include Rust 1.97/MSRV, a pinned 1.97.1 toolchain,
strict workspace lints and license checks. The new CI job builds the Wasm
target and runs the shell integration harness. See
[toolchain](../rust-toolchain.toml), [Makefile](../Makefile) and
[CI guide](ci.md).

## Verified integration context

**Proxy-Wasm is the integration interface.** The Rust `proxy-wasm` SDK supplies
callbacks and hostcalls; libperfusion supplies the detector. The released SDK
is currently **0.2.5** and exports ABI **0.2.1**. Pin the released SDK rather
than its development branch. Envoy **1.40.0**, released October 13, was the
current stable release observed during research. The example selects the V8
runtime and pins the Envoy image by digest.
[SDK API](https://docs.rs/proxy-wasm/0.2.5/proxy_wasm/),
[Envoy release](https://github.com/envoyproxy/envoy/releases/tag/v1.40.0).

The artifact is a Rust `cdylib` targeting **`wasm32-wasip1`**. This
is core Wasm with WASI Preview 1 imports, the successor to `wasm32-wasi`.
Use the SDK entry macro and validate the actual artifact's imports/exports.
Browser tooling is unnecessary. The official SDK provides body-filter
examples and Envoy deployment examples.
[SDK body example](https://github.com/proxy-wasm/proxy-wasm-rust-sdk/tree/main/examples/http_body),
[Rust target](https://doc.rust-lang.org/rustc/platform-support/wasm32-wasip1.html).

`wasm32-unknown-unknown` is an alternative, but its standard library has
limited host facilities. Do not add a second artifact until there is a
deployment need. LLVM's default Wasm features change with Rust versions, so
successful compilation alone does not prove compatibility with the selected
Envoy engine.
[Rust target constraints](https://doc.rust-lang.org/rustc/platform-support/wasm32-unknown-unknown.html).

SDK 0.2.5's `main!` macro emits `no_mangle` and WASI constructor machinery
including unsafe code. The adapter uses edition 2021 and narrowly allows the
generated ABI entry point while retaining `forbid(unsafe_code)` for its own
code. The locked Wasm build and Envoy runtime have both been exercised.
[Released macro source](https://raw.githubusercontent.com/proxy-wasm/proxy-wasm-rust-sdk/v0.2.5/src/lib.rs),
[Rust 2024 unsafe attributes](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-attributes.html).

Envoy executes filter callbacks synchronously on worker threads, with
separate Wasm instances/memory per worker. Use a root context for validated
configuration and metric IDs and an HTTP context for each request/response
pair. Heavy detection and parsing consume worker time. The example selects
`envoy.wasm.runtime.v8`; it is present in the pinned distribution. Other
engines require their own compatibility checks.
[Envoy execution model](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/wasm).

### Header/body flow control is a design constraint

The Rust SDK exposes header, body and trailer callbacks in both directions.
Body callback sizes become cumulative when the host buffers. A body can
terminate through trailers instead of a body callback with
`end_of_stream = true`.
[Released callback surface](https://raw.githubusercontent.com/proxy-wasm/proxy-wasm-rust-sdk/v0.2.5/src/traits.rs).

Header `Action::Pause` does **not** automatically mean "hold headers and keep
receiving the body." The inspected host maps it by default to
`StopAllIterationAndWatermark`. Set
**`allow_on_headers_stop_iteration: true`** in Envoy's plugin configuration
to allow the `StopIteration` behavior needed for a body inspection gate.
Body pause then buffers; final continuation releases the held message.
This applies to both directions.
[Host status conversion](https://raw.githubusercontent.com/proxy-wasm/proxy-wasm-cpp-host/master/src/context.cc),
[Envoy host implementation](https://raw.githubusercontent.com/envoyproxy/envoy/main/source/extensions/common/wasm/context.cc).

Istio's interim request-only mode opts in with
`allow_request_headers_before_body_verdict: true`. Header inspection still runs
before clean headers continue, and body delivery pauses until complete
inspection. The upstream may receive clean headers before the body verdict.
Keep `response_mode: off` in this mode; response blocking requires held
response headers to replace the status and body safely.

The ABI permits a local response before downstream response headers are
sent. Thus **response headers must remain held until body and trailers pass**
if a body verdict is to replace the response without leaking content.
Scanning chunks after forwarding headers cannot make this guarantee.
[Proxy-Wasm ABI](https://github.com/proxy-wasm/spec/blob/main/abi-versions/v0.2.1/README.md).

These host details were checked in the pinned Envoy runtime. The integration
harness covers held request denial, generic response replacement, and a blocked
HTTP/2 gRPC response followed by trailers and a healthy request. Concurrent
HTTP/2 stream behavior remains untested.

## Architecture and inspection contract

```text
Envoy HTTP callbacks
    -> read bounded byte fields and hold message as needed
    -> extract representations the application consumes
    -> libperfusion SQLi/XSS verdicts
    -> apply direction-specific policy
    -> continue, report, or send a local denial
```

The `envoy-libperfusion` workspace crate keeps configuration, inspection and
HTTP lifecycle handling inside the adapter.
The two new boundaries are Envoy/SDK -> adapter and adapter -> libperfusion.
Both need tests; detector internals should remain untouched. The codebase
map found no reusable HTTP integration seam. Its name-based graph includes
ambiguous matches and cannot establish callback coverage.

Use the existing high-level detector calls. An inspection result needs only
detector, direction, surface, optional fingerprint/context and coverage
status. There is no need for a new public analysis API, rule language or
generic detector registry.

### Coverage by HTTP surface

| Surface | Planned inspection |
| --- | --- |
| Request URI | Scan raw `:path` and up to four successive percent-decoded views; also decode query name/value pairs with form URL rules. Envoy path normalization affects what the filter sees; malformed or residual encodings are incomplete. |
| Request headers | Scan names and byte values plus up to four successive percent-decoded views, preserving repeated entries as exposed by Envoy; parse cookie pairs as well. |
| Response headers | Scan names and byte values plus up to four successive percent-decoded views, including repeated Set-Cookie values. |
| Request/response trailers | Scan names and byte values and finalize held bodies. Streaming responses continue before trailers and cannot be replaced if a trailer finding arrives. |
| Plain/raw bodies | Scan raw bytes and up to four successive percent-decoded views with both detectors; keep non-UTF-8 bytes intact. |
| URL-encoded bodies | Scan raw bytes plus each decoded name/value, retaining duplicates and empty values. |
| JSON bodies | Scan raw bytes plus decoded keys/string values and relevant scalar representations; visit all duplicate-key entries before any map can overwrite them. |
| Multipart bodies | Scan raw body, field names, bounded text-field values and file names; parse nested JSON and URL-encoded fields. Other structured part types are incomplete. File payloads receive raw-body scanning only; do not infer archive inspection. |
| XML, protobuf, archives or other encoded payloads | Raw byte scanning alone gives no decoded-content guarantee. Add an application-matching parser when required, otherwise report incomplete coverage or reject under strict policy. |

The plugin scans exposed header/body surfaces and marks unsupported or
unbounded representations incomplete. Raw scanning is useful for unfamiliar
types, but it is not semantic inspection when the application decodes another
format. In report mode, incomplete bodies can pass without full inspection.

Full-body inspection avoids arbitrary chunk-boundary misses. Libperfusion
has no incremental detector state contract suitable for arbitrary HTTP
chunking; a fixed overlap does not establish equivalent results. Scan the
assembled body once, rather than repeatedly rescanning a growing prefix.

### Bounded percent-decoded views

The adapter scans raw values and up to four successive percent-decoded views
for every exposed header value and body. This catches encoded payloads in
cookies and custom headers without assuming that the application decodes only
one layer. If a valid percent escape remains after four layers, inspection is
incomplete and the strict profile rejects the message. Form/query parsing also
applies the format-specific `+` to space rule; other headers and bodies do not.
JSON escapes are decoded through a JSON parser, which retains its recursion
limit and application-level nesting/field budget. Avoid `serde_json::Value` as
the sole inspection representation when duplicate object members could hide a
value.

Scanning decoded alternatives can flag a value that the application treats as
literal text. Use detect/report to observe such findings before enabling
block/reject on production traffic with opaque encoded headers or cookies.
[Form decoding specification](https://url.spec.whatwg.org/#application/x-www-form-urlencoded),
[JSON deserializer](https://docs.rs/serde_json/latest/serde_json/struct.Deserializer.html).

Malformed path/form encodings, unsupported character sets, percent escapes
remaining beyond the four-layer bound, unexpected residual Content-Encoding
and exceeded parsing budgets produce **incomplete inspection**, not a clean
verdict. Base64 and non-UTF-8 text conversion require explicit application
semantics and bounded expansion. No request mutation is needed for inspection.

SQLi/XSS verdicts are heuristic signals, not proof of exploitation. A normal
HTML response containing legitimate scripts can match XSS detection; SQL
examples in documentation can match SQLi. The plugin cannot determine
whether data actually enters a database query or an unsafe browser sink.
Define narrowly scoped, explicit policy exceptions only from observed
application requirements, and make their reduced coverage observable.

## Configurable enforcement and resource policy

Implemented configuration:

| Setting | Proposed contract |
| --- | --- |
| `request_mode`, `response_mode` | Independently `off`, `detect`, or `block`; built-in default is `detect`. |
| `allow_request_headers_before_body_verdict` | Defaults to `false`; set `true` only on hosts without header-stop support, accepting that clean headers reach the upstream before body inspection completes. |
| Detectors | SQLi and XSS both run in each enabled direction. |
| `max_request_body_bytes`, `max_response_body_bytes` | Hard body bounds; built-in default is 1 MiB each, maximum 64 MiB each. |
| Extraction budgets | Default 1,024 fields, 64 KiB per field and JSON depth 32; maximum 65,536 fields, 1 MiB per field and depth 128. Field bytes cannot exceed the request body limit. |
| `incomplete_inspection_policy` | `reject` or `report`; built-in default is `reject`, applied only when that direction uses `block`. |

The example uses a 1 MiB request/response bound in detect/report mode and an
8 MiB request bound in the blocking upload profile. Limits apply to bytes
Envoy exposes after configured request decompression. Configuration rejects
unknown fields, invalid enum values, zero limits and limits above these caps.
The root parses configuration once and each stream keeps a consistent snapshot.

`detect` reports a match and releases the inspected message. `block` returns
a generic 403 for request attacks and a 502 for rejected upstream
responses. Malformed/unsupported request representations use 400/415 and
oversized requests 413; corresponding rejected upstream content uses a
generic 502. Preserve a single terminal outcome per stream and prevent
inspection of the plugin's own denial from causing a rejection loop.

`off` is an explicit loss of coverage. `detect` always passes incomplete
messages and reports the coverage gap. In `block`, `report` passes incomplete
messages with an event, while `reject` refuses them. A prefix-limited miss is
never a whole-message clean result. These controls are separate from Envoy's
**VM failure policy**.

Use explicit `failure_policy: FAIL_CLOSED` initially. `FAIL_OPEN` bypasses
inspection when the VM fails; selecting it is a deployment availability
tradeoff. Invalid configuration should fail startup or reject an update.
[Envoy Wasm configuration](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/wasm/v3/wasm.proto.html).

Configure host buffering limits and timeouts in addition to plugin bounds.
The inspected SDK/ABI does not expose a buffer-limit setter. Envoy buffering
overflow can cause request 413, response 500 before headers, or a disconnect
after headers. Listener/route limit semantics must be verified against the
chosen release and protocol.
[Envoy flow control](https://www.envoyproxy.io/docs/envoy/latest/faq/configuration/flow_control).

The plugin cap cannot prevent all allocation in Envoy before its callback.
Budget Envoy buffers, host-to-Wasm copies, parsing allocations and all
simultaneously active streams per worker. Scan counters provide a
deterministic CPU-work bound; a wall-clock check cannot interrupt a detector
call already running. Release body scratch promptly after inspection, and
include slow-client and cancellation behavior in acceptance tests.

Complete buffering introduces latency and prevents unbounded streaming.
SSE, bidirectional gRPC, WebSockets and CONNECT need an explicit reject or
incomplete-coverage policy unless a later protocol-aware implementation is
requested. HTTP gRPC bytes alone do not expose decoded protobuf values.
HTTP/1.1 and HTTP/2 finite messages are the proposed first acceptance targets;
HTTP/3 requires a separate verified deployment matrix.

## Compression, ordering and host safety

Use Envoy's request decompressor before the plugin. Request filters execute in
configured order and response filters in reverse. The checked response-body
decompressor path stalled: Envoy 1.40 passed decoded response bytes to a held
Proxy-Wasm callback without completing the stream. The example therefore uses:

```text
request-only decompressor -> Wasm inspection -> router
```

Request gzip is decompressed before inspection. A response retaining a
Content-Encoding header is marked incomplete; strict mode replaces it with a
generic 502, while report mode forwards it and logs the coverage gap. The
response decompressor behavior needs an Envoy-level resolution before
compressed response bodies can be inspected semantically. Cache-Control
no-transform, decompression expansion and recompression still need deployment
tests. Bound decompression resource use as well as decoded body size; an
expansion ratio alone is not a global memory cap.
[Filter ordering](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/http_filters.html),
[Decompression behavior](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/decompressor_filter).

Authentication, rate limiting, header mutation, transcoding and caching also
affect the bytes visible at this position. Inspect after relevant request
transformations and before upstream forwarding; place response inspection
before downstream forwarding and test cache hits/local replies. Any later
mutation that introduces uninspected application input invalidates coverage.
Do not trust a client header as an inspection-bypass signal.

Use byte header maps to preserve input and avoid SDK string conversion
panics. Many SDK convenience methods unwrap hostcall results, and some
low-level functions panic on unexpected host statuses despite returning
`Result`. Handle returned errors where possible, use hostcalls only in valid
callback contexts and treat traps as VM failures; direct hostcalls do not
make every SDK error recoverable.
[SDK hostcall implementation](https://github.com/proxy-wasm/proxy-wasm-rust-sdk/blob/main/src/hostcalls.rs).

Keep allowed host capabilities minimal and validate capability restrictions
against the actual module imports. The plugin needs local HTTP inspection,
logging and metrics, without external service calls or shared queues.
Envoy describes the HTTP Wasm filter as experimental and the extension as
having an unknown security posture. That is a material deployment caveat for
an internet-facing security filter, beyond the sandbox's isolation benefits.
[Filter status](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/wasm_filter.html),
[Extension security notice](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/wasm/v3/wasm.proto).

## Observability and artifact delivery

The adapter currently logs direction, detector/mode and incomplete reason,
without request-controlled values or message contents. Custom metrics,
per-outcome counters and a SQL fingerprint/context log policy remain follow-up
work.
[SDK metric and logging API](https://docs.rs/proxy-wasm/0.2.5/proxy_wasm/hostcalls/index.html).

Ship a locked release `.wasm`, SHA-256 checksum, build/version manifest and
example Envoy configuration. Start with local-file loading. Remote Wasm
loading supports a required SHA-256 checksum; never use a mutable artifact
reference as the deployment identity. Leave precompiled artifact loading
disabled until separately justified; the Wasm configuration warns that
precompiled code is not verified.
[RemoteDataSource](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/base.proto),
[Wasm VM options](https://github.com/envoyproxy/envoy/blob/main/api/envoy/extensions/wasm/v3/wasm.proto).

## Additional context from Kuadrant Limitador and wasm-shim

Limitador is a native Rust rate-limit library/service exposing Envoy's gRPC
rate-limit protocol. Kuadrant's Rust Proxy-Wasm plugin is the separate
`wasm-shim` repository. The useful reference for our adapter is the shim;
libperfusion can execute locally without the shim's external authorization,
rate-limit services or CEL action pipeline.
[Limitador architecture](https://github.com/Kuadrant/limitador/blob/main/README.md),
[Shim purpose](https://github.com/Kuadrant/wasm-shim).

Inspected shim source revision:
`6e73539e9f3e74176fbb86128e3a54cc27b36566`. Pin source citations because its
development branch and released documentation can describe different code.

### SDK selection needs an enforcement review

The shim uses edition 2021, a `cdylib`, `wasm32-wasip1`, a pinned Kuadrant SDK
fork and a pinned compiled-Wasm test framework. This provides a concrete
reference for our first compatibility milestone, but does not establish
that their SDK choice is appropriate for our enforcement contract.
[Pinned adapter manifest](https://github.com/Kuadrant/wasm-shim/blob/6e73539e9f3e74176fbb86128e3a54cc27b36566/crates/wasm-shim/Cargo.toml).

Their SDK revision `6ceedbbdd07a048a65d197c9bbb1f950884561fb` adds three commits
to upstream 0.2.5 removing explicit panic/unwrap/expect paths. Unexpected host
statuses become returned errors, UTF-8 conversion can return
`SerializationFailure`, and convenience methods expose `Result`.
[Fork hostcalls](https://github.com/Kuadrant/proxy-wasm-rust-sdk/blob/6ceedbbdd07a048a65d197c9bbb1f950884561fb/src/hostcalls.rs),
[Fork traits](https://github.com/Kuadrant/proxy-wasm-rust-sdk/blob/6ceedbbdd07a048a65d197c9bbb1f950884561fb/src/traits.rs).

However, that fork's callback dispatcher logs certain dispatch errors and
returns `Action::Continue` for HTTP headers, bodies and trailers. Those
errors would not trap the VM, so Envoy's `FAIL_CLOSED` would not prevent the
resulting bypass. Removing panics changes failure semantics and does not
alone establish safe enforcement. Keep upstream 0.2.5 as the initial choice;
review every relevant error path during milestone 1. Adopt a fork or patch
only for a demonstrated requirement after reviewing its complete behavior.
[Pinned fork dispatcher](https://github.com/Kuadrant/proxy-wasm-rust-sdk/blob/6ceedbbdd07a048a65d197c9bbb1f950884561fb/src/dispatcher.rs#L810).

### Prove that inspection also preserves allowed traffic

Kuadrant reported lost 16 KiB request frames when Wasm header pause with
`allow_on_headers_stop_iteration: true` was combined with an `ext_proc`
FULL_DUPLEX filter. Reports covered Envoy 1.35 through 1.38 and bodies as
small as roughly 222 KiB, depending on pacing. Kuadrant reverted the header
setting as a workaround. This is evidence of a specific historical defect,
not evidence that all Wasm buffering corrupts bodies.
[Body-loss report](https://github.com/Kuadrant/wasm-shim/issues/388),
[Operator workaround](https://github.com/Kuadrant/kuadrant-operator/pull/2101).

Envoy fixed a core filter-manager path that forwarded an emptied frame
instead of the buffered data when continuing. Envoy 1.40.0 includes the
default-enabled guard
`envoy.reloadable_features.filter_manager_forward_added_data_on_continue`.
Keep it enabled in the reference deployment. Retain the header setting
needed for our body gate, and add byte-exact passthrough checks rather than
copying Kuadrant's workaround. Validate both request and response bodies
across multiple frames, 16 KiB boundaries, delayed uploads, trailers and
continuation. Compare bytes/digests, not only HTTP status or valid JSON.
Test ext_proc composition before adding it to the supported deployment
matrix; ext_proc is not needed for the standalone example.
[Envoy fix](https://github.com/envoyproxy/envoy/pull/46842),
[Pinned 1.40 runtime guards](https://github.com/envoyproxy/envoy/blob/v1.40.0/source/common/runtime/runtime_features.cc).

### Borrow lifecycle and test patterns selectively

The shim validates configuration in its root context, builds a replacement
factory and shares the configured factory with stream contexts. It handles
request and response body phases separately. Keep our configuration
snapshots immutable and distinguish unavailable phase data from malformed
content; a response header/body cannot be read during the request phase.
[Root lifecycle](https://github.com/Kuadrant/wasm-shim/blob/6e73539e9f3e74176fbb86128e3a54cc27b36566/crates/wasm-shim/src/filter/root_context.rs),
[HTTP callbacks](https://github.com/Kuadrant/wasm-shim/blob/6e73539e9f3e74176fbb86128e3a54cc27b36566/crates/wasm-shim/src/filter/kuadrant_filter.rs).

Its tests execute the compiled Wasm artifact against mocked hostcalls, with
separate real-service end-to-end jobs. Consider its test framework for SDK
callback/error checks only if it reduces our harness code. It complements
native extraction tests and real Envoy tests; it cannot establish actual
Envoy buffering or downstream response replacement. The shim's selected
JSON/SSE field extraction can stop once the desired fields are found; that
optimization does not satisfy a whole-body SQLi/XSS inspection contract.
[Compiled-Wasm response tests](https://github.com/Kuadrant/wasm-shim/blob/6e73539e9f3e74176fbb86128e3a54cc27b36566/crates/wasm-shim/tests/response_body.rs),
[Streaming tests](https://github.com/Kuadrant/wasm-shim/blob/6e73539e9f3e74176fbb86128e3a54cc27b36566/crates/wasm-shim/tests/streaming.rs),
[End-to-end CI](https://github.com/Kuadrant/wasm-shim/blob/6e73539e9f3e74176fbb86128e3a54cc27b36566/.github/workflows/e2e.yaml).

Its Dockerfile packages `/plugin.wasm` in a scratch image, a useful later
OCI distribution reference for Istio. Local-file loading remains the first
deployment. Test cold start with the artifact present/missing, concurrent
first requests on multiple workers, invalid configuration updates and
restart readiness; warm cached loading alone does not prove the artifact
will be available after restart.
[Artifact layout](https://github.com/Kuadrant/wasm-shim/blob/6e73539e9f3e74176fbb86128e3a54cc27b36566/Dockerfile).

A reported shim regression shows how an optional missing CEL field could
abort a rate-limit call and allow traffic under its configured allow-on-error
policy. For our plugin, missing optional HTTP fields, parser failures and
inspection failures must produce distinct outcomes and observable coverage.
Do not convert an error into a benign verdict.
[Failure-mode report](https://github.com/Kuadrant/wasm-shim/issues/391).

## Implementation status and verification

Implemented in this branch:

- `envoy-libperfusion` is a workspace `cdylib` with validated configuration,
  bounded header/body extraction, SQLi/XSS inspection and request/response
  policies.
- Native unit tests cover configuration, query/form/header/body decoding, JSON
  escapes and duplicate members, multipart text values and framing, malformed
  URL encoding, unsupported types and stream detection.
- Envoy 1.40.0 is pinned by image digest. The example includes a detect/report
  profile, request-blocking and response-blocking profiles, a request gzip
  decompressor and an 8 MiB upload route limit.
- CI builds `wasm32-wasip1` and runs the Bash integration harness. The harness
  checks 160 KiB and 8 MiB request acceptance, 9 MiB rejection, request
  SQLi/XSS blocking, percent-encoded header/cookie/body detection, gzip request
  detection, multipart SQLi blocking, reflected response-body/header blocking,
  and blocked gRPC trailers followed by a healthy request.

The tested profile replaces blocked responses with a generic 502 and removes
all upstream headers before adding the response headers for the local error.
Request attacks receive a generic 403; rejected incomplete requests receive
400, 413 or 415 according to the reason.

## Known coverage limits and follow-up

- A response retaining `Content-Encoding` is incomplete. `reject` safely
  replaces it with 502; `report` logs the gap and forwards the response.
  Request gzip is decompressed and inspected. Response decompression needs a
  separate Envoy 1.40 solution because the tested response decompressor path
  did not complete a paused Proxy-Wasm body callback.
- Report mode permits content that could not be fully inspected. This includes
  oversized bodies and streaming formats; body bytes are not inspected after
  the cap. In reject mode, these messages stop before being forwarded.
- Streaming response trailers can be scanned and reported after response
  headers/body have continued, but cannot be replaced at that point. Use
  `incomplete_inspection_policy: reject` where that behavior is unacceptable.
- Multipart file payloads receive raw-body scanning, without per-file semantic
  parsing. Add an application-specific bounded parser if file formats need
  structured inspection.
- XML, gRPC/protobuf, archives and other application-specific encodings do not
  have semantic parsers here. The plugin uses raw-byte inspection and marks
  unsupported structured content incomplete.
- The echo-basic image cannot echo request bodies or emit compressed or oversized
  responses. The Envoy harness checks body acceptance and policy outcomes, but
  not byte-exact body round trips or response compression/size enforcement;
  those end-to-end checks need a different fixture.
- Custom metrics, config hot-reload/concurrency checks, a release artifact and
  checksum manifest, target-specific size/performance measurements, Istio and
  production traffic tuning remain out of this iteration.

The integration runner is Bash and uses the Gateway API conformance
echo-basic v0.2.0 image. It reflects request metadata and supports response
headers, but not request-body echoing, compression or oversized responses; the
harness checks acceptance and WAF outcomes rather than byte-exact body round trips.
