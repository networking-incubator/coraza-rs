# Envoy Coraza contract fixtures

`manifest.json` inventories the upstream connector, PR #20 state contract,
hosts, engine features and the cases in `cases.json`. Every inventory claim
maps to one or more topics, and every topic must appear on at least one case.
The manifest also pins the reference Go dependencies, Go/TinyGo declarations,
build flags, and embedded CRS versions/tree hashes. Per-file hashes attributed
to the recorded source commits and any license statements found in embedded rules are listed
in [`source-provenance.json`](source-provenance.json), whose exact-byte SHA-256
is verified by the manifest checker. Files without a per-file license
declaration remain deferred. The PR #20 extraction-to-commit binding also
remains deferred because no retained archive or export record independently
ties the inspected extraction to its declared commit.
The checker accepts every valid JSON value for `plugin_configuration`, rejects
duplicate keys recursively, and treats non-object roots as configurations with
no recognized keys. The dedicated duplicate-key case permits exactly one
duplicate top-level `default_directives` key for fixture-input validation.
Every other duplicate is rejected. Its capture requires the observed response
status, backend receipt and rule matches; no selected-policy outcome is
prescribed in advance, and the comparator reports the observed values.
Configuration shape probes record `configure.accepted/error` for a scalar
root, missing
authority policy, object policy value, and object/array directive entries.
Raw `plugin_configuration` text is retained beside its parsed value:
`config-empty`, `config-whitespace`, and `config-empty-object` require `""`,
non-empty ASCII whitespace, and exactly `{}`. The root-scalar probe requires
nonblank valid scalar JSON. Malformed directive collections are never filtered
into valid rule evidence: lifecycle probes validate every present
`directives_map` policy collection (a scalar string or an array of strings),
the `rules` value, authority keys and values, and every policy reference before
examining the selected policy. Dedicated configuration-shape cases still
accept intentionally malformed inputs as shape probes.
The checker ties each topic to its directive, request field, backend response,
reload input, host scenario or injected fault. Lifecycle input checks reject
unmodeled variables, operators, transforms, control actions and body encodings;
the chain and multiphase probes validate their complete directive sequences.
Byte-exact and duplicate-header probes require their method, path, body and
ordered header inputs, and every case declaring backend request observations
requires forwarded method and path fields. If `backend.received` is true, those
fields cannot be null; if false, optional observations may be null.
Response-header and trailer probes require status and body as well as the
relevant ordered pairs. The phase-3 probe sends a nonempty response body and
pauses after response headers but before body completion; its outcome schema
requires status, ordered headers, body, rule matches, and a header-before-body
timing observation. Additional topics cover request body limits at N-1/N/N+1,
phase-4 response rewriting, reset while headers are held and a PR #20
filter-state `set_property` hostcall failure. The two `rule_data` cases are
candidate-only diagnostic probes of fixture inputs; their captures validate
observation shapes but do not assert runtime file resolution or matching.
`@validateSchema` remains deferred because the Envoy artifact does not enable
that operator. Both supported scalar directive forms,
`directives_map.default` and deprecated `rules`, require matching deny-rule,
response, and backend observations. `backend_response` supplies the
deterministic upstream response used by response-inspection cases. The
manifest's `deferred_inventory` records plan requirements that do not yet have
a faithful fixture and why. It explicitly defers rule-data bounds and runtime
resolution/matching, `@validateSchema`, WebSocket and CONNECT tunnels,
indefinite streaming, gRPC message decoding, HTTP/3, arbitrary filesystem access, external-process and
DNS operators, custom remote audit transports, CRS exclusions, fragmented
bodies, real access-log consumption, response-body limit boundaries, HTTP/2
multiplexing (one request per case), multiple workers, the broader hostcall
fault matrix and resource exhaustion. Expected outputs are intentionally absent
until a contract host runner has executed the pinned reference artifacts. Do not
fill expected values from source inspection or from a different connector
revision.

Check fixture identity and pins with:

```sh
cargo xtask envoy-contract-check
```

A future host runner records normalized outcomes as a JSON object keyed by
every case ID assigned to that host. Every case value must be a non-empty JSON
object; the recorder rejects scalar, array and `null` values and duplicate keys
at every object depth. Each manifest case lists `required_outcome_fields` as
`{path, type}` entries. The recorder checks path presence and value shape:
HTTP statuses must be valid status integers, flags must be booleans, strings
may be empty, counters and event sequences must be non-negative integers, and
objects and arrays must have the declared shape. `optional_string` accepts a
string or `null`; `header_pairs` validates an ordered array of two-string pairs,
and `optional_header_pairs` also permits `null` for an absent backend request
observation. Response headers and trailers always use `header_pairs`, so their
arrays cannot be replaced with `null`. `rule_matches` validates an ordered
array of `{id, phase, action}` observations and permits an empty array. The
recorder does not require a particular boolean value, array length, counter
value, label value, rule match, or event order. The fixture `assert` describes the input probe and the
observations to compare; it does not prescribe a baseline result. Captures
contain what the host observed, including false, empty, or late observations,
and comparison reports differences.

The caller attests to the supplied source revision, artifact SHA-256 and
normalized outcomes. The recorder validates their shape and pinned revision
fields and refuses hosts without an immutable image digest. Record and compare
both enforce the host pin. The Istio 1.30.5 amd64 proxy image is pinned to
`sha256:324ec9f74e9194c43b16e859497d67567c93d3d1e5f0804a88ed48002e668f62`
(Envoy 1.38.5-dev); Istio 1.30.7 is pinned to
`sha256:340794767464f3d13c9e3df38cc663ecbc8264f00c7022dca53ad5c80336681f`
(Envoy 1.38.8-dev). The harness does not inspect the artifact, execute Envoy,
or independently prove which artifact produced the observations. These pins
make both hosts recordable; no Istio host outcomes exist yet.

The normalized schema uses these fields when a case exercises them:

- `configure`: `accepted` and `error` for configuration success or rejection;
  type-probe cases record `error` as a string, empty when there is no error.
- `response`: `status`, ordered header/trailer pairs and `body_base64`.
- `timing.response_headers_before_body_complete`: whether the phase-3 host
  schedule delivered response headers before the response body was complete.
- `response.upstream_sensitive_pairs_withheld`: boolean observation of
  whether neither sensitive upstream header/trailer pair appears in the
  normalized response arrays.
- `backend`: `received` and forwarded request fields, including method, path,
  ordered headers/trailers and `body_base64` where relevant.
- `rule_matches`: an ordered array of `{id, phase, action}` engine observations.
- `rule_matches_complete` and `rule_matches_later_deny_1006_absent`: boolean
  observations whose actual values are compared.
- `early_block`: `rule_id`, `phase` and boolean
  `response_before_request_body_complete`, collected while the host withholds
  body completion and waits for a local response.
- `filter_state`, `metrics`, `logs`, `reload`, `finalization` and `captures`:
  normalized state properties, metric deltas/labels, ordered rule log events,
  reload generations, finalization results and numbered captures.
- `filter_state.event`, `rule_id`, `phase`, `action`, `status`, `severity`,
  `category` and `client_ip`: PR #20 interruption fields, required as strings
  for its matching-rule probe.
- `filter_state.publication_sequence` and `local_reply.sequence`: required
  event order numbers compared to report when state publication preceded a
  deny reply. The recorder requires both numeric observations but leaves their
  order to comparison.
- `metrics.waf_filter_tx_interruptions`: a counter delta and observed labels,
  with string-shaped `phase` and `rule_id`; the configured-label probe also
  requires string-shaped `suite` and `env` on both legacy counters. Counter
  deltas are non-negative integers. Label values and deltas remain unrestricted
  so the comparator can report mismatches.
  Both phase-one and phase-two interruption probes require the legacy counter
  shapes; the phase-two case uses Coraza's `phase:request` alias with a form
  body.

Keep repeated headers, request trailers and cookies as ordered arrays. Encode
body bytes as standard Base64. The checker recursively validates every
non-null string whose key ends in `_base64` in `request`, `backend_response`
and captured outcomes; errors include the case ID and field path. Empty strings
are valid empty bodies. Use
`null` only for optional observations that are absent. This sample shows a
possible outcome shape; its values are illustrative
and are not seeded baseline results:

```json
{
  "rule-phase-one-deny": {
    "configure": {"accepted": true, "error": ""},
    "response": {"status": 403, "headers": [], "body_base64": ""},
    "backend": {"received": false},
    "rule_matches": [{"id": "1003", "phase": 1, "action": "deny"}],
    "filter_state": {"event": "coraza_waf_blocked_request", "rule_id": "1003"},
    "metrics": {"waf_filter_tx_total": {"delta": 1}},
    "logs": [],
    "finalization": {"result": "success"}
  }
}
```

The recorder validates case coverage, object shape, and each required field's
declared type and shape. It does not reject a capture because an observed value
differs from a fixture description. The comparator reports differences in the
recorded outcomes; equality does not certify complete behavior or parity. Do
not suppress differences while normalizing.

Inputs are bounded: `manifest.json` is limited to 64 KiB, `cases.json` to 1 MiB,
and outcomes/captures to 4 MiB each. Record and compare reject an output path
that resolves to one of their input files, including symlink and hard-link
aliases where the host filesystem exposes file identity. The recorder checks
the pretty-printed capture against the same 4 MiB cap before writing; outputs
are replaced through a sibling temporary file created with owner-only mode on
Unix, so a final-path symlink is not followed and the capture is not widened by
a permissive umask.

Record a pinned upstream capture after checking the artifact and host against
the manifest:

```sh
cargo xtask envoy-contract-record \
  --host standalone-envoy-1.40.0 \
  --role upstream \
  --revision b1770f5b0be397bd4ddc2c976ab6548a7a1eeb7f \
  --artifact-sha256 <wasm-sha256> \
  --outcomes upstream-outcomes.json \
  --output upstream-standalone.json
```

Use `--role pr20` and the pinned PR head for the PR #20 filter-state and
`set_property` failure cases. Record the candidate with `--role candidate` and
its full source commit. The comparator selects cases whose `reference` matches
the baseline role, so an upstream comparison omits PR #20 cases. Compare each
PR #20 baseline separately against the candidate capture for that host. The
standalone host is currently pinned:

```sh
cargo xtask envoy-contract-compare \
  --baseline upstream-standalone.json \
  --candidate candidate-standalone.json \
  --output upstream-mismatch-ledger-standalone.json

cargo xtask envoy-contract-record \
  --host standalone-envoy-1.40.0 \
  --role pr20 \
  --revision 266b6ed6a471e26e5c6862a46beb974eb1a0fa52 \
  --artifact-sha256 <pr20-wasm-sha256> \
  --outcomes pr20-standalone-outcomes.json \
  --output pr20-standalone.json

cargo xtask envoy-contract-compare \
  --baseline pr20-standalone.json \
  --candidate candidate-standalone.json \
  --output pr20-mismatch-ledger-standalone.json
```

For either `istio-1.30.5` or `istio-1.30.7`, use separate per-host outcome,
capture, and mismatch files. For example, with `istio-1.30.5`:

```sh
cargo xtask envoy-contract-compare \
  --baseline pr20-istio.json \
  --candidate candidate-istio.json \
  --output pr20-mismatch-ledger-istio.json
```

Use the same commands with `--host istio-1.30.7` and distinct paths to capture
the second proxy version. Neither Istio host has recorded outcomes yet.

The recorder rejects incomplete, extra or duplicate case coverage, duplicate
JSON case IDs, non-object outcomes, oversized inputs and wrong reference
revisions. Each capture stores `contract_sha256`: SHA-256 of compact canonical
JSON for contract semantics, including schema version and pins; observed
checkouts; host definitions and image digests; case roles, host assignments and
required observation paths and types; inventory and coverage; deferred item
IDs; and fixture inputs. Host status prose, top-level lifecycle status, deferred
explanations and fixture diagnostic/unknown fields are excluded. Fixture object
formatting is canonicalized, but the raw `plugin_configuration` string is
hashed exactly.
Besides the self-describing manifest digest, `envoy-contract-check` pins the
contract with code-side anchors in `xtask/src/envoy_contract.rs`:
`CONTRACT_SHA256` anchors the full contract semantics; `APPROVED_HOSTS`
anchors the required hosts and their image digests; `REQUIRED_CASE_COUNT`,
`CASE_SET_SHA256`, `CASES_FILE_SHA256` and `MANIFEST_CASES_SHA256` anchor the
case inventory, fixture content, and case references, host assignments and
required outcome fields; `REQUIRED_INVENTORY_CATEGORIES` and
`INVENTORY_CLAIM_SET_SHA256` anchor the inventory categories and claims;
`REQUIRED_DEFERRED_INVENTORY` and `DEFERRED_INVENTORY_SET_SHA256` anchor the
deferred items. Editing a case, a fixture body, an inventory claim, the
deferred set, or any contract semantics therefore also requires updating the
matching constant in the same reviewed change. Refreshing them is error-driven:
run `cargo xtask envoy-contract-check`; the first error reports the recomputed
`contract_sha256` (the "got" value) — write it into
`envoy-coraza/tests/contracts/manifest.json`; each further error names the
anchor constant to update, finishing with `CONTRACT_SHA256`.
Each mismatch row contains a `fixture_sha256`, the `contract_sha256`, both
artifact SHA-256 values, both revisions, and both outcomes. `fixture_sha256` is
SHA-256 of the compact canonical JSON for parsed fixture inputs (`id`,
configuration, request, reload configuration, host scenarios/faults, backend
response, and topics), so a mismatch row remains attributable without the
captures.
Artifact hashes are caller-attested values; the harness does not inspect the
WASM artifacts.
Comparison requires both captures to match the current contract digest, so
changing an observation requirement invalidates old captures. The comparator
writes a machine-readable mismatch ledger and exits nonzero on any difference.
Preserve that output with the capture files; add cause, security impact, intended
behavior and resolution when reviewing each mismatch.

These commands validate and compare host-driver output; they do not build or
start Envoy. `envoy-contract-check` validates the local fixture harness; it
does not execute cases and is not currently wired into CI. Stage A remains
partial and open until the pinned artifacts produce host captures and the
remaining provenance and license gaps are resolved. The blocker and current environment
observations are kept in the connector handoff, which is not part of this change.
