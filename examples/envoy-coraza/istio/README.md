# envoy-coraza on Istio (MVP harness)

Proves the Rust `envoy-coraza` Proxy-Wasm filter loads, configures and enforces
on the pinned Istio versions through a Gateway API gateway, with the artifact
fetched from a digest-pinned local HTTP server, and records real host
outcomes. The assertions mirror the standalone Envoy harness
(`examples/envoy-coraza/test-envoy.sh`); results and evidence are written to
`/tmp/coraza-istio-results-<version>/`.

## Prerequisites

- The isolated Kind cluster `coraza-envoy-istio` (context
  `kind-coraza-envoy-istio`) must already exist, with
  `KUBECONFIG=/tmp/coraza-envoy-istio-kubeconfig`. The harness refuses to run
  against any other kube context.
- `kubectl`, `kind`, `docker` (backend image build, `kind load`, Kind network
  discovery), `curl`, `python3`, `git`, and `make` (wasm build).
- Pinned istioctl binaries: `/tmp/istio-1.30.5/bin/istioctl`,
  `/tmp/istio-1.30.7/bin/istioctl`.
- Network access on first run for: the Gateway API v1.5.0 CRDs
  (`standard-install.yaml`, sha256
  `510338cf6709f84410efcce5269268f4c7c5067efdc5d04c75aa2fd2f8380c96`,
  cached at `/tmp/gateway-api-standard-install-v1.5.0.yaml`), binaryen
  `version_123` (sha256
  `e959f2170af4c20c552e9de3a0253704d6a9d2766e8fdb88e4d6ac4bae9388fe`,
  cached at `/tmp/binaryen-version_123`), and the pinned Istio images.

## Commands

```sh
# Istio 1.30.5 (Envoy 1.38.5-dev)
bash examples/envoy-coraza/istio/test-istio.sh

# Istio 1.30.7 (Envoy 1.38.8-dev)
ISTIO_VERSION=1.30.7 bash examples/envoy-coraza/istio/test-istio.sh

# Keep the cluster deployed for debugging (skips teardown)
KEEP=1 ISTIO_VERSION=1.30.5 bash examples/envoy-coraza/istio/test-istio.sh

# Skip the upstream Go oracle smoke
ORACLE_WASM=none bash examples/envoy-coraza/istio/test-istio.sh

# Smoke a custom Go artifact instead of the pinned one
ORACLE_WASM=/path/to/main.wasm ISTIO_VERSION=1.30.7 bash examples/envoy-coraza/istio/test-istio.sh
```

`ORACLE_WASM` semantics: unset smokes the pinned upstream Go artifact;
`none` skips the oracle smoke (the summary then reports the gating assertions
only); any other value must be an existing file, checked before the cluster is
touched, and an explicitly empty value is rejected rather than silently
re-defaulting.

The harness is idempotent: it uninstalls any previously installed Istio first
and tears everything down on exit unless `KEEP=1`. With `KEEP=1` the Rust
filter is restored and the gateway restarted after the oracle smoke, so the
kept cluster serves the candidate for debugging (the oracle EnvoyFilter is
deleted). Run **one harness invocation per cluster at a time**: concurrent
runs delete each other's `coraza-istio`/`istio-system` namespaces and share
the per-version results directory.

## Deployment layout

- `backend.yaml` reuses the standalone harness backend
  (`examples/envoy-coraza/backend.go` + `Dockerfile`), built as
  `coraza-envoy-backend:istio-test` and loaded into the Kind node.
- `gateway.yaml` creates the Gateway API `Gateway` (class `istio`, port 80) and
  an `HTTPRoute` to the backend. Istio's gateway-class controller creates the
  Deployment `coraza-gateway-istio`; its pods carry the workload label
  `gateway.networking.k8s.io/gateway-name=coraza-gateway` (what the EnvoyFilter
  selects on) and an Envoy listener `0.0.0.0_80` that binds port 80 directly.
- `istio-operator.yaml` overlays the minimal profile: `hub: docker.io/istio`
  so the running proxy digest can be checked against the pinned digests, and
  `proxyStatsMatcher.inclusionPrefixes` so the `waf_filter` stats are recorded
  (Envoy on Istio drops stats outside the inclusion list).
- `envoyfilter.yaml` inserts the wasm HTTP filter immediately BEFORE
  `envoy.filters.http.router` (last filter before routing, after Istio's own
  filters), with the plugin configuration semantically identical to
  `examples/envoy-coraza/envoy.yaml` (`directives_map` {main,reject,response-off},
  `default_directives: main`, 32-byte body limits, `failure_policy:
  FAIL_CLOSED`, `allow_on_headers_stop_iteration: true`, filter-state logs,
  `metric_labels {suite: envoy-harness}`, `per_authority_directives`). It also:
  - raises the listener `per_connection_buffer_limit_bytes` to 16 MiB, matching
    the standalone `envoy.yaml`. This matters only while the filter holds
    response headers stopped (phase-4 header rules): Envoy buffers the body
    against the listener's default ~1 MiB limit and aborts the harness's
    1 MiB+1 response with a 500 (`response_payload_too_large`); freely
    streamed responses are unaffected (verified both ways on Istio 1.30.5).
    This is a harness convenience, not a production recommendation — see
    Known limitations,
  - enables HTTP/1.1 request trailers on the connection manager,
  - appends the file access log that dumps the coraza filter-state keys,
  - adds the `coraza-wasm-fetch` STATIC cluster used by Envoy's remote-data
    fetcher (Envoy 1.38's `HttpUri` has no local-DNS option, only an explicit
    cluster),
  - adds a bounded `retry_policy` to the artifact fetch
    (`retry_back_off` 1s..10s, 5 retries; `http_uri.timeout` bounds each
    attempt at 120s).

All patches are scoped to listener port 80: Istio's health (15021) and merged
metrics (15090) listeners must not run the WAF. **Footgun:** a listener added
to the Gateway later would serve traffic *without* the filter; the harness
fails if the Gateway has more than one listener, but a production deployment
must either extend the match or accept the scoping.

## Artifact distribution

`code.remote` + `sha256`: the harness builds the filter with
`make build-envoy-wasm`, links the WASI stubs (below), computes the sha256, and
serves the artifact from the host with `python3 -m http.server` bound to the
Kind bridge gateway address. Pods reach the host on that address; the harness
verifies the bytes the gateway pod fetches hash to the pinned value before
applying the EnvoyFilter. Fallbacks (copying the file into the proxy container,
an in-cluster server) were not needed.

The artifact is provenance-pinned, not just transit-pinned: `test-istio.sh`
carries `EXPECTED_UNPATCHED_SHA256` (the `make build-envoy-wasm` output) and
`EXPECTED_ISTIO_SHA256` (the stub-merged artifact) next to the binaryen/CRD
pins and fails on mismatch, and records `git rev-parse HEAD` plus both hashes
in the results directory. Because this worktree carries uncommitted work, the
harness also records `git status --porcelain` (`git-status.txt`), marks the
run `git_dirty=true` and prints a loud warning when the tree is dirty, so the
artifact is attributable to the recorded revision plus exactly those listed
changes.

### Updating the artifact pins

When the filter changes, the run fails with "artifact changed; update the
constant and re-record". To re-pin:

1. `make build-envoy-wasm` and `sha256sum
   target/wasm32-wasip1/release/envoy_coraza.wasm` → new
   `EXPECTED_UNPATCHED_SHA256`.
2. Link the stubs as the harness does (`wasm-as` + `wasm-merge`, see
   `test-istio.sh`) and hash the output → new `EXPECTED_ISTIO_SHA256`.
3. Re-run the harness on **both** Istio versions to completion, update
   `EXPECTED_GATING_ASSERTIONS` if the assertion set changed, and re-record the
   results table and artifact digests in your run notes.

### Fetch failure modes

`code.remote` failures (404 from the server, digest mismatch, fetch exceeding
`http_uri.timeout` after the bounded retries) leave the VM in a failed state:
with `failure_policy: FAIL_CLOSED` every request on the listener is rejected
with 503 until the config is re-pushed or the pod restarts. A successful but
slow fetch blocks the listener update (warming) rather than serving traffic
uninspected.

### WASI stub link (required for Envoy <= 1.39 hosts)

Envoy's v8 Proxy-Wasm host only implements a small WASI subset; before
proxy-wasm-cpp-host gained ENOSYS stubs for the rest (PR #433, first shipped in
Envoy 1.40), a module importing e.g. `wasi_snapshot_preview1.fd_filestat_get`
is refused at load time (`missing import`). The coraza engine's
filesystem-backed features (audit-log file sinks, file-backed operators)
reference those syscalls, so the `wasm32-wasip1` build imports five functions
the Istio 1.30 Envoy (1.38.x) host lacks: `fd_filestat_get`, `fd_readdir`,
`path_create_directory`, `path_filestat_get`, `path_unlink_file`.

`test-istio.sh` therefore links `wasi-stub.wat` (five ENOSYS stubs, errno 52)
into the built artifact with binaryen's `wasm-merge`, and asserts the merged
module imports **exactly** the 13 WASI functions observed on the pinned
artifacts (`clock_time_get, environ_get, environ_sizes_get, fd_close,
fd_fdstat_get, fd_prestat_dir_name, fd_prestat_get, fd_read, fd_seek,
fd_write, path_open, proc_exit, random_get`) — the Envoy 1.38 v8 host
implements 18 WASI functions (those 13 plus `args_get`, `args_sizes_get`,
`fd_fdstat_set_flags`, `poll_oneoff` and `sched_yield`;
proxy-wasm-cpp-host `beb8a4e`: `include/proxy-wasm/exports.h`
`FOR_ALL_WASI_FUNCTIONS`, registered in `src/wasm.cc`, implemented in
`src/exports.cc`), and this module does not import the other five.
`--all-features` is required for the merge because the artifact uses
post-MVP wasm features (bulk memory, sign extension) that wasm-merge's
conservative default validation rejects. The unpatched
`make build-envoy-wasm` artifact stays canonical for the standalone Envoy 1.40
harness.

The stubs exist only to satisfy the loader. The connector's validated
configuration does not reach filesystem-backed features (the Envoy host has no
filesystem to reach), so nothing in this harness exercises them; this is not a
verified claim that they fail identically to Envoy 1.40's host stubs at
runtime. If a future feature needs *working* WASI, it will fail with ENOSYS —
on Envoy 1.40 as well as here — and that would surface as a runtime failure of
that feature, not a load failure of the plugin.

## What is asserted

Per version (recorded run notes stay with the release evidence, not this change):

- The Gateway has exactly one listener on port 80 (the EnvoyFilter matches
  port 80 only; a second listener or a different port would bypass the WAF —
  the harness fails instead).
- Rendered config: wasm filter immediately before the router;
  `failure_policy: FAIL_CLOSED`; `allow_on_headers_stop_iteration: true`;
  `code.remote` sha256 pins the served artifact plus a bounded retry policy;
  HCM trailers; the file access log carries the coraza filter-state format.
- Proxy image digest equals the pinned digest (amd64 manifest or manifest
  list); Envoy version and istioctl version recorded; the runtime guard
  `envoy.reloadable_features.filter_manager_forward_added_data_on_continue`
  is asserted present in the running Envoy binary and recorded from
  `/runtime` (not overridden there, i.e. the compiled default applies).
- Lifecycle: phase-1/phase-2 request denials (403, backend not hit — with a
  positive control that the `/__stats` counter endpoint is reachable), benign
  byte-exact pass-through (16 KiB), an aborted held request (client reset
  mid-body must not reach the backend; the follow-up request is received
  exactly once; the stream finalizes and releases the gauges), request/response
  body limit boundaries at N=31/32/33 for ProcessPartial (200) and Reject
  (413/500) policies, phase-4 response body and response header denials (502,
  upstream body and sensitive headers withheld), large MIME-excluded response
  byte-exact, response body access off, header-only empty EOS,
  unknown-authority default-policy fallback, allowed stream after a denial.
  Before the first denial is measured, the harness drives denials until the
  new filter chain is observably enforcing (EnvoyFilter updates have a reload
  window).
- The 16 MiB listener buffer rationale is asserted as a recorded experiment:
  with the LISTENER patch removed from the applied EnvoyFilter, the
  headers-stopped response aborts with a 500 (`details=response_payload_too_large`
  in the access log) while the freely streamed 1 MiB+1 MIME-excluded body
  still passes 200 byte-exact; with the patch restored, the phase-4 header
  denial returns 502 (`buffer-limit-experiment.txt` in the results
  directory).
- Observability: the access log line carries the coraza filter-state fields
  for a denial (plus `%RESPONSE_CODE_DETAILS%`); the RelevantOnly audit record
  reaches the proxy log; admin stats expose `waf_filter.tx.total`, the
  interruption counter with `rule_id`/`phase`/`suite` in the raw stat name,
  and the same counter expectations as the standalone harness —
  `errors_total` > 0 (the aborted-held-request error terminal),
  `incomplete_inspections_total` > 0, and both gauges released to zero.
- The oracle smoke (reference-only, does not gate): the upstream Go artifact
  (`/tmp/coraza-proxy-wasm-upstream-pinned/build/main.wasm`) through the same
  EnvoyFilter path. The switch **restarts the gateway** and selects the
  post-restart pod by identity (new UID, no deletionTimestamp, Ready — the
  old pod stays Running during a rollout and can sort first by name), so the
  fresh proxy loads the oracle artifact from scratch (Envoy otherwise keeps
  serving the previously loaded Rust VM). It then verifies, before any
  request is asserted: the config dump's `node.id` names the selected pod and
  its **active** chain holds exactly one `envoy.filters.http.wasm` filter
  whose `code.remote.sha256` equals the oracle artifact's digest; the
  Rust-only counters (`waf_filter_errors_total`,
  `waf_filter_incomplete_inspections_total`) and the Rust filter-state denial
  log lines do not move across the oracle requests; and the Go plugin left
  positive evidence — both plugins emit `waf_filter.tx.total`, so
  attribution rests on the interruption stat's phase string
  (`_phase=http_request_headers` for the Go artifact vs
  `_phase=http_request_headers_identifier` for the Rust filter), whose
  appearance also proves configure succeeded (a plugin whose `on_configure`
  fails never serves). Only if every check passes are oracle PASS lines
  printed (all-or-nothing); failures — including a failed gateway restart —
  are recorded as `ORACLE-FAIL` lines and counted in the summary without
  aborting the run. Skippable with `ORACLE_WASM=none`; a corrupt artifact
  yields zero oracle PASS lines and non-zero failures (verified with a
  text-file artifact).
- The gating assertion count is pinned (`EXPECTED_GATING_ASSERTIONS`); the
  run fails if an assertion was added or lost.

## What is skipped and why

- Request-trailer delivery to the backend: Istio's generated
  gateway-to-backend cluster does not enable HTTP/1.1 upstream trailers, so
  `x-client-trailer` never reaches the backend (verified). The filter-relevant
  trailer cases (trailer-terminated benign request and phase-2 denial) are
  asserted. The standalone harness covers full trailer pass-through.
- Response trailers: same upstream limitation.
- `Expect: 100-continue` pass-through: covered by the standalone harness, not
  ported (Istio's HCM has no `proxy_100_continue` setting to mirror, and the
  case adds no gateway-specific coverage).
- Prometheus tag extraction for `rule_id`/`phase`/`suite`: the istio-agent
  bootstrap generates the regex `(tag=\.=(.*?);\.;)` for `extraStatTags`,
  which only matches the mixer/telemetry wasm naming convention and cannot
  extract this filter's `waf_filter.tx.interruptions_ruleid=N_phase=X_suite=Y`
  naming. The values are asserted in the raw admin stats instead; fixing the
  prometheus labels would need a custom proxy bootstrap template.
- Gateway `Programmed` condition: stays False on Kind because no
  LoadBalancer controller assigns the generated Service an address. Both
  observed messages ("address pending for hostname …" and "Failed to assign
  to any requested addresses: no instances found for hostname …") have been
  recorded on **both** 1.30.5 and 1.30.7 across runs — the message varies by
  istiod reconcile timing, not by version. Readiness is asserted on the
  generated deployment and pod instead; the condition is recorded, not gated.
- HTTP/2 multiplexing, multi-worker behavior, full CRS coverage and the full
  56-case contract capture: out of MVP scope.
- Per-case attribution of the `waf_filter_incomplete_inspections_total`
  counter (the harness asserts the aggregate; which of the cases make up the
  eight is not individually labeled).

## Known limitations

- One Kind node, one gateway replica, requests driven through
  `kubectl port-forward` to the gateway pod; nodeports/LoadBalancer ingress are
  not exercised.
- The EnvoyFilter targets Istio 1.30's generated gateway layout (pod label
  `gateway.networking.k8s.io/gateway-name`, listener `0.0.0.0_80`, filter chain
  ending in `envoy.filters.http.router`); other Istio versions may need the
  match adjusted.
- The EnvoyFilter matches listener port 80 only: any listener added to the
  Gateway later serves traffic without the WAF. The harness fails on a
  multi-listener Gateway; production deployments must extend the match or
  accept the scoping.
- EnvoyFilter updates have a reload window in which requests can traverse the
  previous filter chain; the harness drives denials until the new chain is
  observably enforcing before measuring, but a production rollout has the same
  window (Envoy/EnvoyFilter behaviour, not specific to this filter).
- The 16 MiB per-connection buffer ceiling is a memory cost paid by **every**
  connection on the listener, not a production recommendation; it exists so
  the phase-4 header-deny case can hold a 1 MiB+1 body while response headers
  are stopped.
- `wasm-merge` output is deterministic but re-encodes the module (the merged
  artifact is ~530 KiB smaller, mostly the stripped `name` section) and its
  sha256 differs from the unpatched build.
- `istioctl uninstall --purge` leaves the `istio-system` namespace behind,
  still holding CA material and controller state (`istio-ca-secret`,
  `istio-ca-root-cert`, `istio-ca-crl`, `istio-ip-autoallocate`,
  `istio-leader`, `istio-namespace-controller-election`, `kube-root-ca.crt`
  and the `default` service account — verified on the cluster). The harness
  therefore deletes the namespace as part of teardown and waits for it at the
  start of the next run; a manual cleanup needs the same
  `kubectl delete namespace istio-system` step to reach a clean slate.

## Teardown

The harness tears down on exit (EnvoyFilter, namespace, `istioctl uninstall
--purge`, the leftover `istio-system` namespace, Gateway API CRDs) unless
`KEEP=1`. Manual teardown:

```sh
export KUBECONFIG=/tmp/coraza-envoy-istio-kubeconfig
kubectl delete envoyfilter --all -n coraza-istio
kubectl delete namespace coraza-istio
/tmp/istio-1.30.5/bin/istioctl uninstall --purge --force -y
kubectl delete namespace istio-system --wait=false
kubectl delete -f /tmp/gateway-api-standard-install-v1.5.0.yaml
```
