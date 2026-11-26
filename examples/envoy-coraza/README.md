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
status, compressed, chunked, limit, empty-response, and trailer cases. The
runner checks byte-exact request and large MIME-excluded response forwarding;
phase-1 and phase-2 denial before backend receipt; response refusal without
upstream body/header leaks;
request and response body-limit behavior at `N-1`, `N`, and `N+1`; an actual
`Expect: 100-continue` upload; empty and trailer-terminated messages; and
phase-4 response-header denials for both MIME-excluded and body-access-off
responses.

The filter answers every response it refuses with a local reply when it
decides (see
[Refused responses](../../envoy-coraza/README.md#refused-responses)). The
runner checks that each kind of refusal reaches the client within two seconds
with its documented status and without a byte of the upstream response: a
`HEAD` response, a 204, a 304 and an empty 200 that rule 104 denies at their
headers; a gzip-encoded `text/plain` response (502); a phase-4 rule of the
`p4.local` policy that denies on a `TX` variable a phase-3 rule set, for a body
that policy does not inspect (502); an
inspected body of 1 MiB + 1 byte sent in 64 KiB writes (502), beside one of
exactly 1 MiB that passes; a response that rule 104 denies at its headers,
which is 502 over plain HTTP and, for an HTTP/2 request with
`content-type: application/grpc`, HTTP 200 with `grpc-status: 14` and
`grpc-message: Upstream response blocked`; and, in the CRS run, a `HEAD`
request for a 500 page on `crs2.local`, a CRS policy at paranoia level 2 where
rule 959100 denies in phase 4 (403). The `redir.local` policy redirects with a
target built from a query argument on the request side (rule 120) and on the
response side (rule 121); the runner sends CR LF in that argument and checks
that the 302 carries one `location` header, percent-encoded, and no injected
`Set-Cookie`. Last, it holds a request body that rule 102 would deny until
Envoy's 60-second timeout answers 408, checks that the client gets that 408,
then sends the rest of the body and checks that the backend never receives the
request; this case takes about a minute.

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
  `inspection_reason` health property (see [Observability](#observability)).
  Logging depends on the source of the refusal. Connector-originated guards,
  including the 16 MiB and retained-body budgets, argument limits and
  content-encoding checks, use bounded `Warn` decision logs sampled at counts
  1, 2, 4, 8, and so on per compiled generation, so an individual occurrence
  may have no connector log line. Policy-rule denials do not add
  connector-decision lines; Coraza's `log`/`nolog` action controls their rule
  logging. Engine-generated interruptions are not connector decisions either.
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
* A request with more than `SecArgumentsLimit` cookies (1000), across all its
  `Cookie` headers, gets 413 (`incomplete`) in any engine mode but `Off`, or
  400 from rule 200004 at `recommended.local`. This holds even under
  `SecRequestBodyAccess Off` and when the request has no body; raise
  `SecArgumentsLimit` instead.

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
`wasm.io.coraza.waf.v1.<field>`. The switch defaults to `false` and gates only
the legacy interruption properties; all seven bounded v1 health fields are
published for every stream pinned to a configured generation. A context
without one cannot publish terminal health or emit generation-scoped
connector-decision warnings.

Legacy interruption state is published before the local reply:
`event`, `rule_id`, `phase`, `action`, `status`, and, when the matched rule is
available, `severity`, `category`, and `client_ip`. The category is the first
case-sensitive `attack-` tag with a valid lowercase suffix, or `other`. Values
come from the Coraza interruption and matched rule; no request body or matched
variable is exported. The two namespaces stay separate so health does not alter
the PR #20 fields. `status` is the validated status actually sent in the local
reply; the current validator accepts 200–599, including 204. A policy rule
using `deny,status:200` still prevents the request from reaching the upstream,
but returns a 2xx local reply that can look successful to clients or
success-based monitoring.

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
health filter-state properties, and bounded error/audit/decision log lines. The
standalone harness checks the formatted health state and audit/error logs;
there is no `stats_tags` configuration or Prometheus metric assertion.

Telemetry hostcall failures do not change enforcement. Failure diagnostics use
fixed operation names and emit at failure counts 1, 2, 4, 8, and so on.
Connector-originated decisions also emit bounded `Warn` lines at counts 1, 2,
4, 8, and so on. Their counter is shared by streams pinned to one compiled
generation in its root context; separate root contexts count independently, so
this is not a cluster-wide limit. The first missing-client-address rejection
and first unmatched-authority decision in each generation are logged even if
their counts fall between those samples; later decisions use the shared
rate-limit counter. Lines contain only the passed/refused result, a closed
outcome, a fixed phase, a numeric status and count, plus an optional fixed
configuration hint; they never contain request data. A status of `0` means a
pass had no local reply. Passed decisions include unmatched-authority,
engine-off, partially inspected and request-body-not-inspected traffic. A
`passed` warning records the connector's local decision to allow traffic past
this filter, with the shown inspection outcome; it does not confirm end-to-end
delivery or successful transaction finalization. A stream can still end with
`terminal_outcome=upstream_failure_or_cancellation` after a reset/cancellation,
or report `inspection_reason=finalization_error` and `terminal_outcome=error` if
finalization fails. The hints are mnemonics, not JSON syntax:
`set_missing_client_address_allow` means the top-level setting
`"missing_client_address": "allow"`, and `set_unmatched_authority_allow` means
`"unmatched_authority": "allow"`. Policy-rule denials do not produce
connector-decision lines or consume that counter: Coraza's rule-level
`log`/`nolog` actions continue to govern their logs.

Engine-off and allowed unmatched-authority streams publish health before their
request-header callback returns, so an access log can read those states.
A stream that ends before request headers reach this filter publishes
`inspection_complete=false`, `inspection_reason=incomplete`, and
`terminal_outcome=incomplete`; this records the uninspected stream without
sending a local reply or inferring a status. Streams that finish through
`on_done`, including resets before completion, still publish terminal state
there, after Envoy has written the access-log line; that late state cannot
appear in that line. No `on_log` hook is used.

Selected Coraza audit records are opt-in through `SecAuditEngine`; the connector
writes the configured audit format through Proxy-Wasm logging with existing
parts and relevance selection, control-character escaping, a 16 KiB output
cap, and format-specific truncation. All serialized formats pass through the
control-character sanitizer before Proxy-Wasm logging; literal line feeds are
escaped as the two characters `\n`, keeping each entry to one proxy-log line.
Native-format output appends the text suffix ` [truncated]` when cut. The
harness opts into `RelevantOnly` and checks its audit log callback. Native
audit sinks remain unavailable in the WASM filter.

JSON, JSONLegacy, and OCSF use bounded formatters that keep reduced output valid
JSON within the cap. They mark reductions with `"truncated": true` for JSON and
JSONLegacy, or `"unmapped": {"truncated": true}` for OCSF; request details are
reduced before matched-rule messages. If a record needs truncation but the limit
cannot fit the marker (18 bytes for JSON/JSONLegacy, 31 for OCSF), the formatter
returns an empty result. The connector's 16 KiB cap is above both limits.

The standalone harness observed a formatted v1 health record on an allowed
stream; `test-envoy.sh` also checks that an engine-off pass has
`reason=engine_off outcome=uninspected complete=false generation=1
request_truncated=false response_truncated=false telemetry_failed=false` in its
access-log line. Its HCM log capture did not produce per-request lines for local
replies, so formatter visibility of the PR #20 interruption properties and
per-stream isolation across deny/allow streams remain unproven. A no-Wasm Envoy
control showed the same access-log capture limitation, so the cause is
unresolved in the harness. Keep that part of the Stage E host gate open.

The standalone harness also does not prove the Istio 1.30.5 or 1.30.7 proxy
configuration; those host runs remain separate evidence requirements.

This harness proves the listed standalone Envoy cases only. Istio 1.30.5 and
1.30.7 filter-state formatter evidence must come from matching proxy hosts.
