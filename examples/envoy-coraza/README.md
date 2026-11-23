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
files. Both configurations have a `recommended.local` policy that loads the
built-in `@recommended-conf` baseline before a `@detectSQLi` rule; the runner
checks that a SQL injection in the field after a multipart part with an empty
header block is denied by that rule, and that a multipart body without its
final delimiter is denied by baseline rule 200002 before it reaches the backend.
Set `ENVOY_CORAZA_MAKE_TARGET=build-envoy-wasm-crs` to build the
embedded-CRS artifact; that run uses `envoy-crs.yaml` — the same fixture
configuration plus a `crs.local` policy that includes `@recommended-conf`,
`crs/crs-setup.conf` and `crs/rules/*.conf`, usable as a CRS demo config — then
checks that SQL injection requests, including the empty-header multipart case,
are denied by CRS rule 949110 and that the unterminated multipart body is denied
by rule 200002. The filter config sets
`allow_on_headers_stop_iteration: true`; this HCM profile also requires
`proxy_100_continue: false` because request headers stay paused while phase 1
runs. Both configurations set every Envoy setting marked "set" in the
[Required Envoy configuration](../../envoy-coraza/README.md#required-envoy-configuration)
table, such as `use_remote_address`, `strip_any_host_port` and `normalize_path`;
that table lists every setting the filter depends on and what each one
prevents. The runner fails when one of the
settings that table says the example sets is missing, and checks that a
client-supplied `X-Forwarded-For` does not reach
`REMOTE_ADDR`, that respelled hosts (`reject.local.`, `reject.local:1`) keep
their policy, that an invalid authority (`reject%2elocal`, two `Host` headers)
is refused with 400, that dot segments and doubled slashes are resolved before
the rules see the path, and that a header name with an underscore is refused.

The built-in `@recommended-conf` no longer starts in `DetectionOnly`: a policy
that includes it enforces unless it sets `SecRuleEngine DetectionOnly` itself.
The example policies keep their explicit `SecRuleEngine On`. The `crs` policy's
embedded CRS tree carries no rules 905100 and 905110. The CRS run checks that
with the request rule 905110 exempts, an "internal dummy connection" `GET /`
carrying a SQL injection, sent from inside the Envoy container so that its TCP
peer, and `REMOTE_ADDR`, is 127.0.0.1: it is denied, and the `crs` policy's
rule 107 logs that the rules saw the loopback address. With upstream's file the
request would reach the backend. A second request claims 127.0.0.1 in
`X-Forwarded-For` from outside and is denied too.

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

## Upgrade notes: behaviour changes

Read the connector's
[upgrade notes](../../envoy-coraza/README.md#upgrade-notes-behaviour-changes)
before reusing these files with other policies. For the request body:

* A policy without a `SecRequestBodyAccess` line, such as `response-off` here,
  now buffers and inspects request bodies. It holds a streaming request body
  (gRPC streaming, a long chunked upload) until it ends, and refuses what
  earlier builds streamed through uninspected; the reason is the
  `inspection_reason` health property (see [Observability](#observability)),
  and the filter logs no line for any of these:
  * 413 for a body of `SecRequestBodyLimit` bytes or more under the default
    `SecRequestBodyLimitAction Reject` in `SecRuleEngine On` (`denied`), and for
    one over 16 MiB (`body_too_large`). A 20 MB upload to `off.local` that
    earlier builds streamed through now gets 413;
  * 413 for a multipart request with a file part in `SecRuleEngine On`
    (`denied`, interruption `rule_id` 0): the filter has no filesystem, so the
    engine refuses uploads. A multipart body its parser stopped in is refused
    the same way;
  * 413 for a URL-encoded body, or a JSON body that a rule parses as JSON (CRS
    does for `application/*+json` and AWS JSON types), with more than
    `SecArgumentsLimit` (1000) fields (`incomplete`);
  * 415 for any request whose `Content-Encoding` is not `identity`
    (`unsupported`).
* `SecRequestBodyAccess Off` in a policy, or a phase-1
  `ctl:requestBodyAccess=Off` rule scoped to the paths that need it, lets those
  bodies through unread, reported as `request_body_not_inspected`, and is
  logged at configure time. Do not key such a rule only on a request header
  such as `Content-Type` or `Content-Encoding`: the client sends those, so any
  client could switch inspection off; the connector's upgrade notes show
  path-scoped rules. `SecArgumentsLimit` reads larger forms.
  `SecRequestBodyLimit` goes up to 16777216, with the listener's
  `per_connection_buffer_limit_bytes` and the route's
  `request_body_buffer_limit` at least as large, as both files set them.
* A policy that sets `SecRequestBodyLimit` above 16777216 without a
  `SecRequestBodyAccess` line no longer loads: the filter logs
  `rejected plugin configuration: policy "<name>" cannot run on this host:
  SecRequestBodyLimit is <N> bytes, over the 16777216-byte WASM ceiling`. Lower
  the limit, or add `SecRequestBodyAccess Off`.

## Compressed configuration

The plugin configuration may be carried gzip-compressed and base64-encoded.
Compress the same JSON document and wrap the output in a one-key document:

```sh
gzip -c config.json | base64 -w0
```

```json
{"config_gzip_b64": "H4sIA..."}
```

`-w0` is required: the value must be standard padded base64 on one line, so
GNU base64's default 76-column wrapping is rejected. Plain JSON stays the
default. `config_gzip_b64` must be the only key in the wrapper, the
decompressed document is capped at 8 MiB, and it must not itself contain
`config_gzip_b64`. Exactly one gzip member is accepted, with nothing after it
(a concatenated second member is rejected). The decompressed document follows
the same schema as the plain form.

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
`body_memory_budget_stopped`, `request_body_not_inspected`,
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
