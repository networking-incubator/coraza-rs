# Implementation plan: native Coraza dynamic module for Envoy

Status: proposed; no native adapter has been implemented or runtime-validated.
Prepared 2026-11-02 against repository revision
`81f0a2b73f53337462368eff590946356e1193bf`.

## 1. Outcome and scope

Add `envoy-coraza-dynamic`, a Rust native HTTP filter loaded through Envoy's
dynamic-modules extension. It is an **alternative artifact**, not a replacement
for `envoy-coraza.wasm`. Both adapters use the existing `coraza` engine and the
same policy configuration and enforcement contract.

Initial supported deployment: standalone Envoy 1.40.0, Linux x86-64 with glibc,
finite HTTP/1.1 and HTTP/2 request/response streams. Ship a locally installed
`libenvoy_coraza_dynamic.so` in an image containing the tested Envoy binary.
HTTP/2 multiplexing and multiple workers are release gates, not assumptions.

There is no new libperfusion filter, detector API, or detector implementation
work. `coraza` already depends on `libperfusion` for its SecLang detection
operators; that transitive dependency remains intact.

### Included

- Existing SecLang policies, authority selection, request/response phases,
  multiphase evaluation, body processors, and transaction finalization.
- Bounded body gating, request denial, response replacement, cancellation,
  partial-inspection reporting, and immutable configuration generations.
- Existing JSON configuration, including in-memory `rule_data` and the bounded
  `config_gzip_b64` envelope.
- Optional embedded CRS using the repository's existing CRS pin and fetch path.
- Bounded error/audit logging and interruption/health filter state.
- Native build, real-Envoy tests, measured comparison with the Wasm adapter,
  and an explicitly versioned release artifact.

### Not included

Istio integration, an operator/control-plane API, remote module downloads,
per-route policy overrides, binary hot-swapping, other native extension types,
HTTP/3, unbounded streaming inspection, WebSocket/CONNECT inspection, native
filesystem rule loading, upload-file storage, blocking external operators,
custom metrics, or new Coraza features. Do not remove the Wasm adapter or change
its published configuration while adding the native option.

## 2. Verified starting point and corrections

Use checked-in source as the baseline, rather than treating historical handoff
documents as current implementation evidence.

| Existing code | Reuse or implication |
| --- | --- |
| `envoy-coraza/src/config.rs`: `Config::parse` | Existing configuration schema, compressed envelope, validation and resource bounds. |
| `envoy-coraza/src/policy.rs`: `Generation::compile`, `PolicyCompiler::compile`, `Generation::select_named` | Strict all-policy compilation, multiphase mode, rule-data budgets and authority selection. Logging callbacks currently depend on Proxy-Wasm. |
| `envoy-coraza/src/stream.rs`: `CorazaHttp`, `Lifecycle`, `normalize_authority` | Reference behavior and regression cases. Hostcalls, cumulative Wasm body lengths and `Rc<Cell<usize>>` accounting cannot be copied into a multithreaded native factory. |
| `envoy-coraza/src/observability.rs` | Bounded formatting, interruption/health fields and diagnostic throttling; publication is host-specific. No custom counters or gauges currently exist. |
| `coraza/src/{waf,transaction,rule_data}.rs` | Existing compiled WAF, per-stream transaction, body-memory reporting, finalization and in-memory rule data. |
| `envoy-coraza/{build.rs,crs.pin,crs-fetch.sh}` | Existing optional CRS generation and source pin; do not create another CRS release pin. |
| `examples/envoy-coraza/{backend.go,test-envoy.sh,envoy.yaml,envoy-crs.yaml}` | Instrumented backend and behavioral test cases to reuse. |
| `Cargo.toml`, `rust-toolchain.toml` | Current manifest requires Rust 1.99; current toolchain is 1.99.1. Older README references to 1.97 are not the build authority. |

Important distinctions from Proxy-Wasm:

1. A native module has **no Wasm sandbox**. Rust panic containment is not
   protection against allocation aborts, memory corruption, fatal signals or a
   blocked worker. Those can affect the entire Envoy process.
2. Header holds and full-body inspection still require Envoy buffering,
   admission limits, timeouts and correct continuation. Native execution does
   not automatically remove the existing buffer-limit problems.
3. The SDK can borrow Envoy header/body bytes, but body views may be fragmented
   and their descriptor vectors allocate. Coraza's body API accepts one
   contiguous `&[u8]` and retains its own data. This is not an end-to-end
   zero-copy or allocation-free WAF.
4. Native compilation removes WASI imports and Wasm VM setup, not SecLang
   compilation cost. Compile once per native filter configuration where the
   host permits it, share immutable rules, and measure configure cost.
5. Native availability in an Envoy release does not establish availability in
   a particular Istio binary. No Istio support claim is part of this plan.

### Pinned SDK facts

Use Envoy `v1.40.0`, resolved during planning to commit
`9e5580933739775e8bce696a57a2e1bc99368f23`, as the initial source baseline.
Stage A must bind that source to the actual image/binary selected for testing.
The source links in section 10 all use this immutable revision.

- The official `envoy-proxy-dynamic-modules-rust-sdk` is a git dependency in
  the Envoy repository. Its build uses `bindgen` and requires Clang/libclang.
- `HttpFilterConfig<EHF>: Sync`; configuration is accessed by worker threads.
  Each stream's `HttpFilter` is thread-local.
- At this revision, HTTP hooks take **`&self`**, not `&mut self`, because Envoy
  can synchronously re-enter a filter. Response/completion hooks can also run
  when that filter's request hooks never ran.
- There are separate received-body and buffered-body APIs, plus
  `get_buffer_limit`/`set_buffer_limit`, local replies, stream reset, filter
  state and continuation methods. Do not assume Wasm's cumulative body model.
- `CatchUnwind` poisons a panicking filter and fails request callbacks closed
  with 500; response callbacks reset the stream. Poisoned cleanup callbacks may
  be skipped, so releasing memory cannot depend on `on_stream_complete` alone.
- The pinned ABI header documents additive compatibility and a diagnostic-only
  ABI version string. The common configuration proto still describes older
  exact-match/hash behavior. Do not use a matching version string as proof of
  compatibility: pin the SDK, record host identity and test the exact pair.
- The pinned common configuration proto explicitly warns that a failed remote
  module fetch can leave the HTTP filter uninstalled and traffic unfiltered.
  **Use local-file/by-name loading only**, and prove startup/update rejection
  for missing or invalid local artifacts.

## 3. Architecture and reuse boundary

```text
envoy-coraza (Proxy-Wasm) --+
                          +--> envoy-coraza-common --> coraza
envoy-coraza-dynamic ------+    config + policy compiler
  native SDK + stream          authority/format helpers
```

`envoy-coraza-common` is a small, unpublished workspace library. Extract only
code that both adapters actually need: configuration parsing, bounded policy
compilation/selection, authority normalization and pure log/state formatting.
Move the relevant tests with it. It must not depend on either Envoy SDK.

The compiler receives explicit error/audit callbacks using the engine's
existing callback pattern, rather than calling Proxy-Wasm directly. Preserve
the existing body ceilings, in-memory-only host restrictions, strict rejection
of skipped directives, and audit lock in both adapters. Rename WASM-specific
internal wording where the restriction now describes both proxy hosts; do not
add a general host-capability framework.

Keep ABI callbacks, stream state, buffer handling, log publication and filter
state in their adapter crates. **Do not generalize the entire Wasm stream
implementation into a new generic host interface.** Its tests and outcomes are
the behavioral reference, not a native host implementation.

Leave `coraza` public APIs and detector internals unchanged unless Stage A
demonstrates a missing capability that the current APIs cannot provide. Record
any such prerequisite as a separate engine change with its own tests.

### Ownership, threading and re-entrancy

- Compile every policy before returning a native configuration object. Return
  `None` on unknown filter name, invalid configuration, policy errors or
  exhausted compilation budgets. Never publish a partially compiled set.
- Own one immutable `Arc<Generation>` in the native configuration; clone it
  into each native stream. Add compile-time `Send + Sync` assertions for the
  shared generation/WAF types; never add an unsafe trait implementation.
- Let Envoy own configuration replacement and draining. Streams retain their
  old generation; new streams use the accepted replacement. Do not add a
  global active WAF, `ArcSwap`, background compiler or per-request compilation.
  Generation identifiers are diagnostic identities, not durable versions.
- Keep mutable transaction/lifecycle state stream-local using `Cell`/`RefCell`
  as required by the pinned `&self` hooks. **Release all state borrows and Envoy
  buffer views before host calls that can re-enter**, including local replies,
  continuation and reset. Mark terminal decisions before invoking those calls.
- Use checked borrowing, short state transitions and explicit pending actions;
  do not hold a `RefMut` across a callback-producing host operation or interpret
  an unavailable borrow as a clean verdict. Test synchronous re-entry directly.
- Keep request state optional until decode starts. Envoy-generated local replies
  that bypassed decode must not manufacture a transaction, rerun request phases
  or expose another stream's state.
- No module-owned worker threads, timers, async runtime or raw Envoy pointers
  are needed. Destructors must not panic or call back through an expired host.

### Resource policy

Start with the current connector's bounds, not larger native defaults:

| Resource | Initial bound |
| --- | --- |
| Plain/decompressed configuration | 8 MiB, including the existing structural-value budget |
| Policies / rules | 64 policies, 30,000 rules per policy, 60,000 per generation |
| In-memory rule data | 1,024 files, 1 MiB per file, 8 MiB total, 32 MiB read budget per generation |
| Authority mappings | 4,096 |
| Headers/trailers per direction | 1,024 entries, 64 KiB per value, 1 MiB aggregate |
| Retained request / response body | 16 MiB / 1 MiB host ceilings; effective SecLang limits may be lower |
| Native aggregate retained-body admission | 64 MiB across workers/configurations/generations of this loaded module |
| Error / audit log output | 4 KiB / 16 KiB |

Replace the Wasm root's single-threaded body counter with a native module-wide
atomic admission counter and stream-owned reservations released on every exit,
including `Drop`. Reserve with checked arithmetic before copying/retaining;
a load-then-add race is not sufficient. Shared admission across old and new
configurations prevents reload from resetting the budget. It applies to one
loaded module binary, not every library or allocation in Envoy.

Account for held Envoy body data, coalescing scratch and engine retention,
including audit copies. Use `Transaction::body_memory_bytes` where applicable.
This is a retained-body admission budget, **not a hard process RSS bound**:
Envoy allocates data before calling the filter, and parsed arguments, headers,
compiled rules and allocator capacity also cost memory. Bound concurrent
streams/configuration generations operationally, set host timeouts/buffer
limits, and validate RSS under load. Exhaustion must deny/reset rather than
bypass inspection. Preserve the engine's `ctl` ceilings and no-spill settings.

## 4. Configuration and artifact contract

Proposed native manifest shape (not a manifest change in this planning PR):

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
coraza = { path = "../coraza" }
envoy-coraza-common = { path = "../envoy-coraza-common" }
envoy-proxy-dynamic-modules-rust-sdk = { git = "https://github.com/envoyproxy/envoy", rev = "9e5580933739775e8bce696a57a2e1bc99368f23" }
```

Use edition 2021 if required by the pinned SDK's generated entry attributes,
as the current adapter does. Keep workspace safety lints; isolate only
SDK-generated entry/logging macro lint exceptions in the smallest ABI boundary
module, with a reason. Adapter logic must contain no handwritten unsafe code,
raw FFI hooks or unchecked indexing. Keep release overflow checks and unwinding
enabled so `CatchUnwind` can work; do not set `panic = "abort"`.

Example HTTP filter entry, before the router (not a full deployment config):

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
        {
          "directives_map": {
            "default": [
              "SecRuleEngine On",
              "SecRequestBodyAccess On",
              "SecRequestBodyLimit 8388608",
              "SecRule REQUEST_URI \"@contains attack\" \"id:1,phase:1,deny,status:403\""
            ]
          },
          "default_directives": "default"
        }
```

`StringValue` supplies the same JSON bytes the existing parser consumes. Test
`Struct` serialization as an additional configuration transport, but do not
invent a new policy schema. Preserve the current explicit uninspected outcomes
for empty configuration, unmatched authority and `SecRuleEngine Off`; warn as
today. DetectionOnly must remain non-disruptive for rule matches. Keep invalid
configuration distinct from an intentional bypass.

Set `ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/opt/envoy/modules` and install only the
trusted library there. `do_not_close: true` deliberately keeps code resident
for the initial release, avoiding an unproven Rust runtime/TLS unload contract.
It does not retain obsolete policy generations once streams release them.
Replace binaries by rolling the Envoy process, not overwriting a loaded `.so`.

Use the SDK's `declare_init_functions!`, `HttpFilterConfig`, `HttpFilter` and
`CatchUnwind`. There is no Wasm VM configuration, WASI stub merge,
`allow_on_headers_stop_iteration`, or Proxy-Wasm `failure_policy` in this entry.
This omission does not establish equivalent failure isolation.

### Delivery

Build with the repository toolchain and `--locked --release` for
`x86_64-unknown-linux-gnu` in a pinned builder compatible with the runtime
image's glibc. Include Clang/libclang prerequisites in developer and CI setup.
Do not use `target-cpu=native` for a distributable artifact.

Check architecture, dynamic dependencies, glibc symbol requirements, exported
module hooks and imported Envoy callbacks using ELF tooling. Unresolved Envoy
callbacks in the shared library are intentional; prove they resolve in the
real host. Do not mask unresolved symbols in unit-test executables. First try
the SDK's `mock` feature; if exported SDK hooks still require a test host shim,
keep it test-only, explicit and limited to the actual symbols.

Initially package the library into a derived, digest-pinned Envoy image, owned
by the build and not writable by the runtime UID. Record repository revision,
SDK commit, actual Envoy version/build SHA and image digest, target triple,
Rust/Clang versions, enabled features, CRS identity, library SHA-256, native
dependencies and licenses. The native artifact needs separate names/assets
from the current Wasm releases; a scratch Wasm OCI image is not a native module
installation mechanism. Additional architectures need independent builds/tests.

## 5. HTTP lifecycle and enforcement

Before writing the full adapter, Stage A must prove these mappings against the
selected host. The table is a required contract, not a claim that it has run.

| Native event | Required Coraza/transport behavior |
| --- | --- |
| Request headers | Read byte-preserving headers, validate budgets, normalize/select authority, create transaction, populate connection/URI/protocol/header data, run phase 1. Deny before upstream contact. Hold headers with native `StopIteration` only when body inspection needs them held. |
| Request body, non-final | Distinguish current received fragments from previously buffered data; enforce bounds/admission before retention. Use the native buffering status proven by the spike, normally `StopIterationAndBuffer`. Never forward bytes awaiting a blocking verdict. |
| Request body EOS or request trailers | Assemble the complete inspection input exactly once, run phase 2, then allow or deny. At trailer EOS include all buffered body bytes and preserve the trailers. Header-only/body-access-off requests still need the appropriate empty phase-2 processing. |
| Response headers | Run phase 3 and preserve the phase-4 header-rule behavior of the current adapter, including MIME-excluded/body-access-off cases. Hold headers whenever a later verdict can replace the response. |
| Response body EOS or response trailers | Run phase 4 once on eligible body data, then release allowed data or replace the response before any protected upstream content reaches the client. Preserve allowed trailers. |
| Stream complete | Run phase 5/`Transaction::finish` once, publish terminal state before access-log flush, and release retained resources. Handle normal completion, denial and cancellation separately. |
| Drop | Host-independent fallback cleanup, including when completion was skipped by panic containment/reset. Never double-finalize or call an expired host. |

### Body assembly and continuation

The native body API returns borrowed fragment views. Determine in the spike
whether the current frame is already in the host's buffered view at each event;
do not concatenate both blindly, miss the final frame or inspect it twice.
Use one borrowed slice when the complete input is contiguous, otherwise one
bounded coalescing buffer at inspection time. Release the views before changing
host buffers or continuing the chain. Do not rescan/coalesce a growing prefix
on every frame, or add a new incremental Coraza parser for this adapter.

Test terminal body events both with and without trailers. Use callback return
statuses for synchronous flow where sufficient; call continuation explicitly
only where the pinned host requires it. A trailer-terminated stream must not
remain paused. Keep clean payloads byte-exact across all framing choices.

### Denials, errors and partial coverage

- Preserve current request and response interruption actions/status handling,
  including redirects. Do not turn every request interruption into 403 or every
  response interruption into 502. The current `replace_interruption` honors the
  validated rule status and redirect location; replacement content is generic
  and all upstream headers/body/trailers are suppressed. Preserve empty-body
  behavior for HEAD, 204, 304 and redirects. Connector response-inspection
  failures use generic 502; engine body-limit interruptions retain their own
  statuses. Historical descriptions of an always-502 response are not the
  current contract.
- Prove the native local-reply path is legal in the relevant encode callbacks.
  If it cannot safely replace a held response, use checked header/body
  replacement through the native SDK. Commit to the method proven by Stage A,
  not two competing implementations. Any failed replacement resets the stream;
  never continue with the upstream response after a mutation failure.
- Preserve existing engine limit semantics, including the tested `>=` boundary,
  `Reject`, `ProcessPartial` and DetectionOnly behavior. A processed prefix is
  incomplete, not a whole-message clean result. A native hard ceiling or
  admission failure cannot be disabled by SecLang `ctl` actions.
- Keep malformed input, body-processor errors, detector inspection gaps,
  intentional bypasses and host failures distinct. Reuse existing outcome
  classification; do not introduce a second engine error policy.
- Invalid request authority/header budgets, request size errors, unsupported
  encoding and host failures retain their existing request status mappings.
  Late failures after downstream headers have been sent require reset, not a
  fictitious replacement status. Local replies must not be inspected again.
- Wrap streams in `CatchUnwind`, test poisoned behavior and ensure reservations
  are released even when its completion hook is skipped. Panic containment
  supplements no-panic code; OOM/abort is still process-wide failure.

### Inspection boundaries

Use the engine's URI/header/body byte APIs and existing processors, not an
adapter-specific URL/JSON/XML parser. Feed the actual host protocol and
connection attributes; never hardcode HTTP/1.1 for HTTP/2. Define which trusted
Envoy address supplies client identity; do not trust arbitrary forwarded
headers. Record normalization performed by Envoy before Coraza sees the URI.

Trailers terminate body phases and are budget-checked/passed through; they are
not new SecLang trailer collections. The current engine/adapter does not expose
them as Coraza rule variables. Document that coverage limitation explicitly.

Keep unsupported residual Content-Encoding rejected when the body is selected
for inspection. Request decompression may precede the filter, with bounded
decoded size and expansion. Response filter ordering is reversed: decompression
must execute before response inspection if enabled. The Wasm response
decompressor stall is not evidence that native decompression works. Test it
separately; compressed response inspection stays unsupported until it passes.

Preserve the existing restrictions on inspected upgrades/CONNECT and document
SSE/gRPC and other indefinite/binary bodies as outside semantic/full-body
coverage. Do not claim protobuf inspection from raw bytes. If policy turns
body inspection off or excludes a MIME type, preserve that explicit coverage
choice rather than silently describing it as protected streaming.

## 6. Observability and host capabilities

Preserve the existing metrics-free scope. Implement native publication of the
same interruption fields, closed health outcomes, bounded diagnostic logs and
opt-in audit records. Use SDK filter-state APIs with explicit lifecycle tests;
do not emulate Proxy-Wasm property paths through a raw FFI escape.

For the first release, publish the existing access-log key strings
`wasm.io.coraza.waf.*` and `wasm.io.coraza.waf.v1.*` explicitly through native
filter state. The `wasm.` prefix is retained only for compatibility, not added
automatically by this SDK. Prove formatter visibility, lifespan and deny/allow
stream isolation on the actual host. If the host cannot reproduce the keys,
stop and document an explicit migration rather than silently losing telemetry.

Keep `enable_filter_state_logs` behavior and the existing log size caps,
relevance selection and parts selection. Logs can contain sensitive audit
data; default access/health state must not include request bodies or matched
values. Preserve the documented limitation that a truncated structured audit
record may not be valid JSON; fixing all audit formats is separate work.
Telemetry failures must be observable but must not turn a denial into an allow.

Although native Rust can open files and sockets, initially retain the existing
no-spill, no-upload-storage and no-native-audit-sink profile. Keep optional
`inspect-file`, `rbl`, `https-audit` and `validate-schema` features disabled in
the shipped module, and test the resolved feature graph. Cargo features are
additive; a default setting alone is not a capability boundary. Validate
effective policy, including debug logging, so no filesystem/network sink or
upload-directory probe becomes enabled accidentally on Envoy worker threads.

Route debug output through an Envoy-backed `DebugLogger` or reject a requested
file debug sink; do not let the native engine lazily open a blocking writer.
Do not install a process-global Rust logger, panic hook, allocator or signal
handler from the module. Native module code is trusted with the entire Envoy
address space; local loading is not itself a sandbox or signature check.

## 7. Ordered implementation slices

Each slice must leave the Wasm artifact working. Do not start a broad engine
refactor or the full native lifecycle before the feasibility gate is green.

### A. Pin and prove the native host boundary

**Paths:** new `envoy-coraza-dynamic/{Cargo.toml,src/lib.rs,src/abi.rs,README.md}`,
new `examples/envoy-coraza-dynamic/{Dockerfile,compose.yaml,envoy.yaml,test-envoy.sh}`,
root workspace/lockfile and `deny.toml`.

1. Pin the SDK revision above, runtime image digest and compatible builder.
   Add only the Envoy git source to the supply-chain allowlist. Confirm the
   exact host binary registers `envoy.filters.http.dynamic_modules` and exports
   the required callbacks; record `envoy --version` and binary identity.
2. Build/load a minimal native filter using the official SDK, strict lints and
   a valid `coraza` filter name. Verify native test linking/mocking, unknown-name
   rejection, malformed config rejection, and missing/corrupt/wrong-architecture
   local library rejection. These negative controls must not serve unfiltered
   traffic. Test both initial startup and rejected configuration replacement.
3. Prove held headers, multiple received/buffered frames, trailer EOS,
   continuation, safe request denial, response replacement and inline re-entry.
   Exercise `set_buffer_limit` and overflow; retain host connection limits until
   evidence establishes what the native stream setting covers.
4. Inject a panic in a test-only filter and verify 500/reset, subsequent healthy
   traffic, no hang, and cleanup. Never put a panic-triggering request path in
   the production artifact.

**Exit gate:** real-host results and recorded exact callback/status/body-view
semantics. A build-only success is not sufficient. If release compatibility,
SDK safety or re-entry cannot satisfy the contract, stop and record the blocker.

### B. Extract the shared policy layer without behavior changes

**Paths:** new `envoy-coraza-common/{Cargo.toml,src/lib.rs,src/config.rs,src/policy.rs}`
and only the actually shared helpers; existing `envoy-coraza/src/{lib,config,policy,stream,observability}.rs`,
CRS build wiring, root workspace/lockfile.

Move `Config::parse`, policy compilation/selection, authority normalization and
their tests. Separate compiler callbacks/publication from shared logic. Forward
the existing `embed-crs` feature through the shared crate; reuse the fetched
tree and `crs.pin`, keeping `make crs-fetch`, custom-tree overrides and the Wasm
feature-on/off build behavior working. Relocate the build generator only as
needed; do not duplicate the pin, generated table or fetched tree.

**Exit gate:** shared config/compiler tests, unchanged default and embedded-CRS
Wasm lifecycle results, no SDK dependency in the common crate, and compile-time
thread-safety assertions. Do not cite old handoff assertions as new test runs.

### C. Wire native policy generations and request enforcement

**Paths:** `envoy-coraza-dynamic/src/{lib,stream,abi}.rs` and focused native tests;
reuse `examples/envoy-coraza/backend.go` without forking its behavior.

Implement configuration rejection/publication, `Arc` generation pinning,
transaction metadata, phases 1/2, body gating, native admission reservations,
authority/default selection and request-side interruptions. Add the tests
before each nontrivial lifecycle transition. Reuse bounded configuration,
including compressed config and `rule_data`, rather than adding new options.

**Exit gate:** deny-before-backend proof, byte-exact allowed uploads, malformed
and boundary fixtures, trailer termination, two-instance isolation, DetectionOnly,
body access off, and configuration replacement with in-flight old streams.

### D. Complete response handling, finalization and telemetry

**Paths:** native `src/{stream,observability,abi}.rs`, native test fixtures and
example access-log configuration; shared formatting helpers only where reused.

Implement phases 3/4/5, response header holds/replacement, MIME exclusions,
local-reply/no-decode paths, re-entry-safe terminal actions, one-time finish,
reset cleanup, native filter state, bounded audit/error/debug publication and
panic cleanup. Enable the shared optional embedded CRS in the native crate.

**Exit gate:** no upstream content/header/trailer leakage on denial; phase-4
header rules still enforce with excluded bodies; healthy follow-up streams;
exactly-once finish/audit; reservations released on completion/reset/panic/drop;
access-log field visibility/isolation; benign CRS traffic allowed and malicious
CRS traffic denied by expected rules. Smoke tests alone are not full CRS parity.

### E. Harden and make both variants reproducible in CI

**Paths:** `examples/envoy-coraza-dynamic/`, `.github/workflows/tests.yaml`,
relevant `.github/actions/` setup, `Makefile`, `docs/ci.md`, root `README.md`,
native crate README and focused fuzz/regression fixtures.

Add `make build-envoy-dynamic`, `make build-envoy-dynamic-crs` and
`make test-envoy-dynamic` targets, keeping Wasm targets unchanged. Add native
default/CRS host jobs and the native dependency prerequisites to every
workspace lint/test/feature/MSRV/coverage job that now needs them. Use the
repository's `$/.github/...` action references and pinned third-party actions.
Do not cross-compile the native SDK as part of Wasm package builds.

**Exit gate:** the acceptance matrix below on the pinned image; focused fuzz
results; dependency audit; workspace feature/MSRV/coverage gates; existing Wasm
integration jobs remain green. Bound all retries/timeouts; upload failure logs,
artifact hashes and host/config identities rather than passing skipped cases.

### F. Measure, package and document switching

**Paths:** native examples/benchmark runner and results under `docs/performance/`,
`.github/workflows/release.yml` and `.goreleaser.yaml` only for distinct native
assets, native deployment documentation.

Benchmark correctness-equivalent native/Wasm configurations, then package the
tested `.so` and derived Envoy image with checksums, source/build provenance and
licenses. Document exchanging the HTTP filter entry and artifact while keeping
policy JSON unchanged. Prove rolling back to the Wasm configuration/artifact.
Do not stack both filters accidentally and count the result as one WAF.

**Exit gate:** measured resource/performance report, clean-checkout reproducible
build procedure, release-image smoke/negative-control tests, and documented
rollback. Publish support only for the tested host/architecture pair.

## 8. Required acceptance and regression matrix

Mock SDK tests cover local decisions; only real Envoy tests prove forwarding,
buffering, re-entry, local replies and access-log behavior. Use the existing
instrumented backend to count upstream contact and compare payload digests.

| Area | Required cases |
| --- | --- |
| Configuration | Plain/compressed JSON; size/structure/decompression bounds; missing rule data; skipped directive rejection; unknown filter name; exact/default/no authority selection; normalized ports/IPv6; empty/off/detect policies; independent filter instances. |
| Update | Valid update with old streams pinned; invalid update keeps old serving config; rapid successive updates; old/new-generation simultaneous memory admission; no partial policy publication. |
| Input preservation | Repeated/empty headers; invalid UTF-8 where transport permits it; encoded URI/body values; URLENCODED/JSON/XML/multipart text through existing Coraza processors; file upload rejection; unmodified allowed trailers. |
| Blocking | Phase-1 and phase-2 denial never reaches backend; phase-3/4 interruption; response header rules with MIME-excluded/body-access-off bodies; generic response replacement strips upstream headers/body/trailers; supported redirects. |
| Framing | Empty/header-only, zero-length final body, one frame, many frames, 16 KiB boundaries, delayed chunks, trailer EOS and `Expect: 100-continue`. No dropped, duplicated or reordered bytes. |
| Limits | Request/response `N-1`, `N`, `N+1`; Reject/ProcessPartial/DetectionOnly; `ctl` cannot raise host bounds or enable spill; admission exhaustion; header/trailer budgets; host overflow while headers are held. |
| Failures | Missing/corrupt native library, configuration failure, failed response mutation, upstream reset, client cancellation/slow upload, inline local reply/completion, never-decoded response, injected panic and poisoned cleanup. Follow with healthy traffic. |
| Concurrency | At least two Envoy workers; concurrent HTTP/2 streams on one connection; deny/allow isolation; request/response cancellation; atomic budget contention; bounded RSS and no stuck streams after stress. |
| Audit/state | Phase 5 and audit once; configured parts/relevance; bounded/sanitized output; truncation disclosure; filter state visible before access logging; no secrets in default health state; no telemetry-based enforcement bypass. |
| CRS | Native feature off/on; current pinned complete CRS; configured overrides; expected attack-rule IDs plus benign controls; identical policy bytes and outcome comparison with Wasm; explicit ledger for differences. |
| Capabilities | No disk spill, upload file, unexpected debug/audit sink or blocking external operator; residual compression and unsupported protocol behavior documented/tested. |

Record selected and executed case inventories. Do not claim complete Go Coraza
or full FTW compatibility from the current Rust/Wasm smoke harness. Reuse
existing engine Go fixtures/FTW checks; expand connector cases where transport
changes could alter what the engine receives.

### Repository checks during implementation

- Every change, including this plan: `make lint`.
- Production Rust: `make test`; dependency changes: `make audit`; workflows or
  scripts: `make lint-extra`.
- Adapter/shared runtime changes: `make build-envoy-wasm`,
  `bash examples/envoy-libperfusion/test-envoy.sh` and
  `bash examples/envoy-coraza/test-envoy.sh`, plus native host tests and both
  CRS builds when their wiring changes.
- Input-path changes: `make parity-differential` with `LIBINJECTION_DIR` at the
  revision in `libperfusion/tests/parity/manifest.json` and the pinned Go oracle,
  as required by repository guidance. This is an existing workspace gate, not
  a separate libperfusion feature in this project.
- Parser/validation security changes: focused fuzz campaigns following
  `libperfusion/docs/FUZZING.md`, using relevant Coraza/configuration targets;
  promote crashes to fixed regression fixtures. Add a narrow adapter target
  only for new logic that existing targets do not reach.
- Feature matrix, MSRV and coverage requirements remain those in `docs/ci.md`;
  do not weaken safety lints or exclude new native code to make them pass.

## 9. Performance and completion criteria

Correctness first. Compare a no-WAF Envoy control, the existing Wasm Coraza
filter and the native filter with identical engine revision, rule bytes,
multiphase setting, body limits, audit settings, backend and traffic. Measure
minimal rules and the pinned CRS, benign passes and early/late denials, small
and large bodies, fragmented uploads, multiple workers and HTTP/2 concurrency.

Record startup/configure/update time, throughput, p50/p95/p99 latency, CPU,
RSS/peak memory and retained-body accounting. Use release builds, a fixed host
and toolchains, fixed Envoy image, repeatable offered load and no hidden
decompression/logging differences. Run at least three paired repetitions,
alternating native/Wasm order; preserve raw results and medians/ranges per
workload. No speedup target is asserted before measurement. Flag unexplained
regressions beyond run spread; document workload-specific tradeoffs explicitly.

Also satisfy the existing `AGENTS.md` production-runtime performance gate:
run the prescribed `speed`, `compare` and `scaling` benchmarks in clean
pre-change and candidate trees, at least three alternating paired repetitions
with the pinned C revision. These unchanged-detector checks do not measure the
native WAF. Use existing Coraza workload benchmarks when shared compiler/engine
behavior changes. Missing prerequisites leave a gate incomplete, not passed.

The native alternative is ready only when:

1. The pinned packaged library loads and malformed/missing local artifacts do
   not silently remove enforcement.
2. Shared configuration/policy behavior and the acceptance matrix pass with
   no unexplained native/Wasm differences.
3. Request and response gating prevent forbidden data from crossing the proxy;
   allowed data remains byte-exact, including under multiplexing/cancellation.
4. Transactions and admission reservations finalize/release on every tested
   path, and the native capability restrictions are enforced.
5. Existing Wasm functionality, CI and release assets remain intact.
6. Performance/resource evidence, security limitations, version/architecture
   support, native packaging and rollback instructions accompany the artifact.

## 10. Sources and remaining decisions

Primary Envoy sources inspected during planning:

- [Pinned ABI and compatibility/lifetime contracts](https://github.com/envoyproxy/envoy/blob/9e5580933739775e8bce696a57a2e1bc99368f23/source/extensions/dynamic_modules/abi/abi.h).
- [Pinned Rust SDK entry macros](https://github.com/envoyproxy/envoy/blob/9e5580933739775e8bce696a57a2e1bc99368f23/source/extensions/dynamic_modules/sdk/rust/src/lib.rs).
- [Pinned HTTP traits, buffering, filter state and threading](https://github.com/envoyproxy/envoy/blob/9e5580933739775e8bce696a57a2e1bc99368f23/source/extensions/dynamic_modules/sdk/rust/src/http.rs).
- [Pinned panic wrapper and poisoned cleanup behavior](https://github.com/envoyproxy/envoy/blob/9e5580933739775e8bce696a57a2e1bc99368f23/source/extensions/dynamic_modules/sdk/rust/src/catch_unwind.rs).
- [Pinned SDK build dependencies](https://github.com/envoyproxy/envoy/blob/9e5580933739775e8bce696a57a2e1bc99368f23/source/extensions/dynamic_modules/sdk/rust/Cargo.toml)
  and [bindings generation](https://github.com/envoyproxy/envoy/blob/9e5580933739775e8bce696a57a2e1bc99368f23/source/extensions/dynamic_modules/sdk/rust/build.rs).
- [Pinned HTTP filter configuration/serialization](https://github.com/envoyproxy/envoy/blob/9e5580933739775e8bce696a57a2e1bc99368f23/api/envoy/extensions/filters/http/dynamic_modules/v3/dynamic_modules.proto).
- [Pinned common module configuration and remote-fetch warning](https://github.com/envoyproxy/envoy/blob/9e5580933739775e8bce696a57a2e1bc99368f23/api/envoy/extensions/dynamic_modules/v3/dynamic_modules.proto).
- [Pinned native HTTP callback implementation](https://github.com/envoyproxy/envoy/blob/9e5580933739775e8bce696a57a2e1bc99368f23/source/extensions/filters/http/dynamic_modules/filter.cc).

Stage A must still establish the actual runtime image digest/build provenance,
native unit-test linking recipe, received/buffered-frame ownership,
response-denial mechanism, re-entry behavior and buffer-limit effects. No module
was built or run to validate those contracts while writing this plan. Broader
Envoy-version support, Istio installation and safe `dlclose` are later work,
not implied by the initial source review.
