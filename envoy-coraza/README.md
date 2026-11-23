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
  * refuses with 413 a URL-encoded body, or a JSON body that a rule parses as
    JSON (CRS does for `application/*+json` and AWS JSON types, with rules
    901360 and 901370), with more than `SecArgumentsLimit` fields (1000 by
    default), in any engine mode but `Off`
    (`inspection_reason=incomplete`, `inspection_complete=false`). With
    `@recommended-conf`, its rules 200004 and 200005 answer 400 first;
  * refuses with 415 every request whose `Content-Encoding` names anything but
    `identity`, such as `gzip` or `br`, with or without a body, in any engine
    mode but `Off` (`inspection_reason=unsupported`): the engine cannot read a
    compressed body;
  * charges each buffered body against the root context's 64 MiB body budget
    (see [Body memory budget](#body-memory-budget)).

  The filter writes no log line for these refusals. Envoy's access log shows
  the status, and with `enable_filter_state_logs` the health properties show
  the reason (see the harness's
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
* **`@recommended-conf` enforces**: a policy that includes it without
  `SecRuleEngine On` now blocks; see
  [Recommended baseline](#recommended-baseline-recommended-conf).
* **A request body the memory budget stopped is refused with 503** in every
  engine mode, `DetectionOnly` included; see
  [Body memory budget](#body-memory-budget) for which bodies reach it.
* **The embedded CRS no longer honours rules 905100 and 905110**; see
  [Embedding the OWASP Core Rule Set](#embedding-the-owasp-core-rule-set).

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
| Wasm log level | Envoy `--component-log-level` | `wasm` at `warn` or more verbose | rule lines, the configure-time warnings and each policy's `enforces` line with its count of rules that switch the rule engine or request body access off, all logged at `warn`, are dropped; the lines naming those rules are logged at `info`; audit lines are logged at `critical`, so only `off` drops them |

`REMOTE_ADDR` is only as trustworthy as `use_remote_address` and
`xff_num_trusted_hops`: without them, every rule keyed on the client address,
an allowlist or a blocklist alike, and the client address in every log line are
whatever the client writes in `X-Forwarded-For`. The rules see the request after
Envoy's normalization, so a path or host rule matches the normalized form, which
is the one the backend routes on. `REJECT_REQUEST` for header names with an
underscore refuses clients that send them on purpose; `DROP_HEADER` keeps them
working but drops the header without a trace.

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
| 200004, 200005 | Deny with 400 when arguments were dropped at `SecArgumentsLimit` (`ARGUMENTS_LIMIT_REACHED`). |
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
bytes went to the backend unread is reported as `inspection_complete=false`,
`inspection_reason=request_body_not_inspected`, whatever ended the stream: when
a response-phase rule then denies, `terminal_outcome=denied` shows the denial,
as it does beside the `body_partially_inspected` of a truncated body. So is a
request whose body had not ended when its response completed or a response-phase
rule denied, since the rest may still follow: without response body inspection,
phase 4 runs at the response headers, and a denial there does not stop the
request body. A request that ends without body bytes, with an empty last DATA
frame or with trailers alone, is not, and neither is one the filter refuses in
the request phase before any of its body arrived.

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
  replaces a response whose parser stopped at it with 502, unless a rule denied it first. A response body that merely
  does not parse (`RES_BODY_ERROR` for another reason) is left to the policy's rules, as before.

The budget covers the body processors only. What rules allocate after the parse (macro expansion, matched values,
`TX` updates) is not charged in advance, so the check after the phase is what bounds it.

The check after the parse stays the authority on what was retained and answers 503. Without a budget, which is the
engine's default, the processors refuse only what Go Coraza refuses.

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
