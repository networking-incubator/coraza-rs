# coraza-rs

`coraza-rs` is a Rust workspace containing a pure-Rust, libinjection-compatible
detector for SQL injection (SQLi) and cross-site scripting (XSS), plus an
optional Envoy Proxy-Wasm adapter. The detector tokenizes input bytes and
matches known patterns; it does not use regular expressions or allocate while
detecting.

## Workspace

| Path | Purpose |
| --- | --- |
| `coraza/` | Separate Rust Coraza implementation with SecLang rule compilation, request and response phases, transaction storage, operators, transformations, custom host extension seams, and audit logging. Optional features gate host operators, schema validation, HTTPS audit, and FIPS hash behavior; multiphase evaluation is selected per WAF at runtime. Request bodies support RAW, URLENCODED, JSON, XML, and multipart processing; response bodies support raw storage and JSON arguments. The `exec`, `initcol`, and `expirevar` effects remain unimplemented. |
| `ftw-runner/` | Optional Go FTW integration harness for the Coraza crate. |
| `libperfusion/` | Reusable SQLi/XSS library, parser APIs, tests, reference corpora, and benchmarks. |
| `envoy-libperfusion/` | Envoy Proxy-Wasm HTTP filter backed by `libperfusion`; this adapter is not published as a crate. |
| `examples/envoy-libperfusion/` | Local Envoy and Istio examples for the filter. |
| `xtask/` | Internal commands for checking and refreshing pinned corpora and generated tables. |
| `docs/` | CI, performance, and design documentation. |
| `.github/workflows/` | Build, test, parity, fuzz, coverage, and supply-chain workflows. |

The Rust crate is a separate implementation based on Coraza, created by Juan
Pablo Tosso and the OWASP Coraza contributors. It is not the upstream Go
project. See the
[Coraza import history](docs/coraza-import-history.md) for provenance.

## Use the library

Add `libperfusion` from this repository to an application. For example, a
consumer can use a Git dependency:

```toml
[dependencies]
libperfusion = { git = "https://github.com/networking-incubator/coraza-rs", package = "libperfusion" }
```

When developing in a workspace that has this checkout, use a path dependency
instead:

```toml
[dependencies]
libperfusion = { path = "../coraza-rs/libperfusion" }
```

The workspace requires Rust 1.97 or newer. Commit the application lockfile so
it retains the resolved Git revision for reproducible builds.

Basic detection uses byte slices:

```rust
if let Some(fingerprint) = libperfusion::sqli(b"1' OR '1'='1") {
    println!("SQLi fingerprint: {fingerprint}");
}

assert!(libperfusion::xss(b"<script>alert(1)</script>"));
```

The consuming application should decode input the same way its own parser
does before passing bytes to the detector. Detection is heuristic: use the
result as a security signal, not as a replacement for parameterized SQL,
contextual output encoding, or application-specific policy.

## Detection API

The top-level functions provide the common detection paths:

| Function | Result |
| --- | --- |
| `sqli(input: &[u8])` | `Option<Fingerprint>`; the fingerprint identifies a known SQLi pattern. |
| `sqli_with_dialect(input: &[u8])` | `Option<(Fingerprint, Dialect)>`, including the matching SQL dialect. |
| `sqli_with_limit(input: &[u8], max_bytes: usize)` | SQLi detection over at most the first `max_bytes` bytes. |
| `xss(input: &[u8])` | `bool`, checking the supported HTML and attribute-value contexts. |
| `xss_with_context(input: &[u8])` | `Option<HtmlContext>`, identifying a context with an XSS match. |
| `xss_in_context(input: &[u8], context: HtmlContext)` | `bool`, checking one caller-selected HTML context. |
| `xss_with_limit(input: &[u8], max_bytes: usize)` | XSS detection over at most the first `max_bytes` bytes. |

The public constant `MAX_INPUT_LEN` is 65,536. The default-cap functions
(`sqli`, `sqli_with_dialect`, `xss`, `xss_with_context`, and `xss_in_context`)
reject inputs longer than
`MAX_INPUT_LEN` without scanning them, returning the same `None` or `false`
used for a miss. Check the input length separately if your policy requires
full inspection. The `_with_limit` functions instead scan a prefix of the
requested length; a miss says nothing about bytes beyond that prefix.

### Parser and tokenizer APIs

For callers that need tokens, statistics, or lower-level control, the crate
also exports:

- `Fingerprint`: `as_str()` and `as_bytes()` expose the SQLi fingerprint.
- `SqlTokenizer`: `new(input, quote, dialect)` or `with_lookup(...)` creates a
  SQL token iterator; `stats()` returns its counters. `SqlToken` exposes
  `kind`, `pos`, `len`, `is_empty`, `variable_count`, `string_open`,
  `string_close`, `value`, and `c_value`.
- `SqlState`: `new(input)` or `with_lookup(...)` creates reusable SQL parser
  state. Its methods are `reset`, `fold`, `fingerprint`, `detect`,
  `check_fingerprint`, `tokens`, and `stats`. `SqlStatistics` exposes
  `tokens`, `folds`, `comment_ddx`, and `comment_hash` counters.
- `SqlLookup` requires `lookup_word` and `is_fingerprint`; its default
  `lookup_operator` delegates to `lookup_word`. Use `BuiltinSqlLookup` for the
  bundled keyword, operator, and fingerprint tables.
- `HtmlTokenizer::new(input, context)` creates an HTML token iterator.
  `HtmlToken` provides `kind` and the original input `text`; `HtmlContext`
  selects `Data`, unquoted attribute value, or single-, double-, or
  backtick-quoted attribute value parsing.
- `Dialect`, `Quote`, `SqlTokenType`, `SqlStatistics`, and `HtmlTokenKind`
  provide the corresponding parser options, categories, and counters.

Generate complete local API documentation with:

```sh
cargo doc -p libperfusion --no-deps --open
```

## Development

From the repository root, run the standard checks:

```sh
make lint
make test
```

`make parity-differential` additionally compares against the pinned C and Go
references. It needs the C checkout selected by
`libperfusion/tests/parity/manifest.json` and the pinned Go toolchain. See the
[CI guide](docs/ci.md) for all checks and prerequisites, the
[performance report](docs/performance.md) for benchmark methods and results,
and the [fuzzing guide](libperfusion/docs/FUZZING.md) for local fuzzing.
The [Envoy Wasm coverage contract](docs/envoy-wasm-plan.md) records adapter
limitations and supported inspection paths.

The [library README](libperfusion/README.md) has crate-specific compatibility,
corpus, and development details. The
[Envoy example guide](examples/envoy-libperfusion/README.md) explains how to
build and run the optional filter.

The [Coraza crate guide](coraza/README.md) describes SecLang processing and
audit logging.

### Custom actions

`coraza::seclang::Parser::register_action` registers a parser-scoped action
factory. `ActionType` selects when an action runs; it is not a capability
boundary. The engine does not prevent a custom action from interrupting,
allowing, or skipping rules regardless of its declared type, so hosts must keep
the implementation's effects consistent with that type. Metadata-only action
names are reserved and registration returns an error for: `accuracy`,
`auditlog`, `capture`, `chain`, `id`, `log`, `logdata`, `maturity`, `msg`,
`multimatch`, `noauditlog`, `nolog`, `phase`, `rev`, `severity`, `status`, `t`,
`tag`, and `ver`.

See the [Coraza extension-seam index](coraza/README.md#extension-seams) for the
other host hooks and their contracts.

The [FTW runner guide](ftw-runner/README.md) explains how to build the Coraza
test server and run go-ftw tests against a CRS checkout.
