# Envoy Coraza connector harness

Run the actual `envoy-coraza.wasm` filter in the repository's pinned standalone
Envoy 1.40 image with a small instrumented Go backend:

```sh
bash examples/envoy-coraza/test-envoy.sh
```

The host needs Docker Compose, curl, and Python 3. The runner uses Python's
standard library to send request trailers, so curl does not need optional
`--trailer` support.

The runner builds both Envoy Wasm artifacts, validates the HCM configuration,
starts Envoy and the backend, then removes its containers, image, and temporary
files. Set `ENVOY_CORAZA_MAKE_TARGET=build-envoy-wasm-crs` to build the
embedded-CRS artifact; that run uses `envoy-crs.yaml` — the same fixture
configuration plus a `crs.local` policy that includes `crs/crs-setup.conf`
and `crs/rules/*.conf`, usable as a CRS demo config — then checks that a SQL
injection request is denied by CRS rule 949110. The filter config sets
`allow_on_headers_stop_iteration: true`; this HCM profile also requires
`proxy_100_continue: false` because request headers stay paused while phase 1
runs.

The backend counts requests by path and supports deterministic body, header,
limit, empty-response, and trailer cases. The runner checks byte-exact request
and large MIME-excluded response forwarding; phase-1 and phase-2 denial before
backend receipt; response replacement without upstream body/header leaks;
request and response body-limit behavior at `N-1`, `N`, and `N+1`; an actual
`Expect: 100-continue` upload; empty and trailer-terminated messages; and
phase-4 response-header denials for both MIME-excluded and body-access-off
responses.

Trailer callbacks complete body phases and leave Envoy's trailer maps untouched.
The locally pinned Go Coraza v3.8.1 public transaction API has no request or
response trailer ingestion method and exports no `REQUEST_TRAILERS` or
`RESPONSE_TRAILERS` variables, so trailer values are not Coraza rule inputs.

## Observability

The harness explicitly enables `enable_filter_state_logs`. Its access logger
reads the legacy interruption properties through the exact one-element paths
`wasm.io.coraza.waf.<field>` and the additive health properties through
`wasm.io.coraza.waf.v1.<field>`. The switch defaults to `false`; when disabled,
neither property namespace is published.

Legacy interruption state is published before a local reply or response rewrite:
`event`, `rule_id`, `phase`, `action`, `status`, and, when the matched rule is
available, `severity`, `category`, and `client_ip`. The category is the first
case-sensitive `attack-` tag with a valid lowercase suffix, or `other`. Values
come from the Coraza interruption and matched rule; no request body or matched
variable is exported. The two namespaces stay separate so health does not alter
the PR #20 fields.

Health values are bounded strings: `inspection_complete`, `inspection_reason`,
decimal `policy_generation`, `request_body_truncated`,
`response_body_truncated`, `terminal_outcome`, and
`telemetry_publish_failed`. `inspection_reason` uses the closed set
`complete`, `denied`, `unmatched_authority`, `engine_off`, `unsupported`,
`incomplete`, `body_too_large`, `body_partially_inspected`,
`retained_body_budget_exhausted`, `invalid_lifecycle`, `invalid_authority`,
`upstream_failure_or_cancellation`, and `finalization_error`. The closed
`terminal_outcome` set is `completed`, `denied`, `uninspected`, `unsupported`,
`incomplete`, `upstream_failure_or_cancellation`, and `error`. The pinned
Proxy-Wasm SDK does not distinguish an upstream reset from other early
failure/cancellation endings, so they share the stable value
`upstream_failure_or_cancellation`.

This build does not publish Envoy/Prometheus counters or gauges. It publishes
only the optional PR #20 interruption filter-state properties, additive bounded
health filter-state properties, and bounded error/audit log lines. The standalone
harness checks the formatted health state and audit/error logs; there is no
`stats_tags` configuration or Prometheus metric assertion.

Telemetry hostcall failures do not change enforcement. Diagnostics use fixed
operation names and emit at failure counts 1, 2, 4, 8, and so on. Selected
Coraza audit records are opt-in through `SecAuditEngine`; the connector writes
the configured audit format through Proxy-Wasm logging with existing parts and
relevance selection, control-character escaping, a 16 KiB output cap, and an
explicit truncation marker. The harness opts into `RelevantOnly` and checks its
audit log callback. Native audit sinks remain unavailable in the WASM filter.
When JSON, JSONLegacy, or OCSF output exceeds the cap, it keeps a bounded
serialized prefix and appends the plain-text marker, so the result may not parse
as JSON. Parser-compatible truncation remains an open follow-up.

The standalone harness observed a formatted v1 health record on an allowed
stream. Its HCM log capture did not
produce per-request lines for local replies, so formatter visibility of the
PR #20 interruption properties and per-stream isolation across deny/allow
streams remain unproven. A no-Wasm Envoy control showed the same access-log
capture limitation, so the cause is unresolved in the harness. Keep that part
of the Stage E host gate open.

The standalone harness also does not prove the Istio 1.30.5 or 1.30.7 proxy
configuration; those host runs remain separate evidence requirements.

This harness proves the listed standalone Envoy cases only. Istio 1.30.5 and
1.30.7 filter-state formatter evidence must come from matching proxy hosts.
