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
* **A configuration without a policy key is rejected**, so Envoy refuses it
  instead of loading a filter that inspects nothing. A document with only
  settings (`missing_client_address`, `unmatched_authority`,
  `enable_filter_state_logs`, `rule_data`, `metric_labels`), for example one
  whose policy key is misspelled, loaded before and passed every request
  uninspected. For a filter that is meant to inspect nothing, add
  `"directives_map": {}`; see
  [Empty or missing configuration](#empty-or-missing-configuration).
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
an uninspected filter is an explicit `{"directives_map": {}}`, which the filter
accepts and logs as a warning. A document whose recognised keys are all settings
(`unmatched_authority`, `missing_client_address`, `enable_filter_state_logs`,
`rule_data`, `metric_labels`) is rejected too: it needs one of `directives_map`,
`default_directives` or `per_authority_directives`, so a misspelled policy key
beside a setting cannot load as a filter that inspects nothing.

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
`source.address` itself comes from `X-Forwarded-For` when Envoy's
`use_remote_address` is `false`; the filter never falls back to that header, or
to any other, when the address is missing. A Unix-domain or
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
slots and about 12 KiB of the 8 MiB total budget.

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
      "Include crs/rules/*.conf"
    ]
  },
  "default_directives": "crs"
}
```

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
