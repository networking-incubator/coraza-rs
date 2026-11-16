# envoy-coraza

Envoy Proxy-Wasm HTTP filter backed by the `coraza` engine. The filter compiles
policy generations and enforces them on request and response phases; the
standalone Envoy harness in [`examples/envoy-coraza`](../examples/envoy-coraza)
exercises the lifecycle checks.

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

The file is [`recommended.conf`](recommended.conf). It is the engine copy,
[`coraza/coraza.conf-recommended`](../coraza/coraza.conf-recommended), which
`cargo xtask go-fixtures-check` keeps byte-identical to the pinned Go Coraza
release, without its `SecRequestBodyInMemoryLimit` and `SecDataDir`: this filter
has no filesystem and keeps the whole request body in memory. A test fails if the
two copies differ in anything else. Like upstream, the file also starts the
engine in `DetectionOnly`, so put `SecRuleEngine On` after the `Include`; the
filter logs a configure-time warning for a policy left in `DetectionOnly`. It
also enables request and response body access with upstream's limits and
`RelevantOnly` audit logging. Override any of those with directives after the
`Include`.

The `Include` must name the file exactly: no wildcard pattern selects it, not
even a bare `Include *`, so a wildcard after `SecRuleEngine On` cannot load its
`SecRuleEngine DetectionOnly`. A configured `rule_data` entry named
`@recommended-conf` replaces the built-in file, and wildcards match that entry
like any other configured file. The file uses one of the 1024 `rule_data` file
slots and about 12 KiB of the 8 MiB total budget.

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
`SecRequestBodyLimit 13107200`. Without it, a request body the engine cannot
parse reaches the backend uninspected.

A configured `rule_data` entry whose normalized name matches an embedded file
overrides that file. Without the `embed-crs` feature the same directives work,
but the deployment must supply `crs/crs-setup.conf` (the release's
`crs-setup.conf.example`, which the feature-on build maps automatically) and
the complete `crs/rules/*.conf` **and** `crs/rules/*.data` set through the
`rule_data` config key; a partial set either fails to compile (missing `.data`
files) or cannot block (missing the blocking evaluation rules).

The fetched tree carries the upstream CRS Apache-2.0 `LICENSE`, and a
feature-on build embeds it with the rules as `crs/LICENSE`.

The embedded tree uses about 50 of the 1024 `rule_data` file slots and about
0.9 MiB of the 8 MiB total budget in a feature-on build. The configured
generation logs the embedded CRS version once at configure time.
