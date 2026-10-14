# libperfusion

A Rust port of [libinjection] for SQL injection and cross-site scripting
detection. It uses `std` for accelerated byte searches and does not allocate
while detecting.
Inputs are bytes: decode them the way the consuming application does before
checking them.

```rust
let fingerprint = libperfusion::sqli(b"1' OR '1'='1").unwrap();
assert_eq!(fingerprint.as_str(), "s&sos");
assert!(libperfusion::xss(b"<script>alert(1)</script>"));
```

## API

The detection helpers cover the common path. SQLi returns an optional
fingerprint and can report the matching dialect. XSS can report its matching
HTML context or check one caller-selected context. The `_with_limit` helpers
scan only the first `max_bytes` bytes; a miss says nothing about the omitted
suffix.

`SqlTokenizer` exposes bounded, read-only token values. `SqlState` can fold
tokens, return fingerprints for a selected quote and dialect (including for
benign input), classify fingerprints, and accept a custom `SqlLookup`.
`HtmlTokenizer` exposes HTML tokens for a caller-selected starting context.

The library uses `std`; its detection paths do not allocate. Development tools,
tests, and benchmarks also use `std`.

## Compatibility and development

The default CI gate checks the corpus and generated inputs against the pinned
`libinjection-go` main commit. The exact reviewed differences are recorded in the
[mismatch ledger](tests/parity/mismatch-ledger.md). The vendored C-derived
tables retain their source revision in their headers and are checked with
`cargo xtask tables-check`.

Run the usual checks from the repository root. The parity target needs Go
1.27.1 and `LIBINJECTION_DIR` set to the C revision in the parity manifest.

```sh
make lint
make test
make parity-differential
```

The Go oracle version is pinned in `xtask/tools/go.mod`; update it there, then
review the refreshed corpus, manifest, tables, and parity results. Refresh Go
fixtures with `cargo xtask corpus-refresh`, and tables from a libinjection C
checkout with `cargo xtask tables-refresh --upstream /path/to/libinjection`.
The optional upstream C corpus and table checks use `LIBINJECTION_DIR`:

```sh
LIBINJECTION_DIR=/path/to/libinjection cargo test -p libperfusion --test upstream -- --ignored
LIBINJECTION_DIR=/path/to/libinjection cargo test -p libperfusion --test tables -- --ignored
```

The `compare` and `scaling` benchmarks run on the retained implementation
without an upstream checkout. The `speed` benchmark also times the C library
and needs an upstream checkout and C compiler. The
[performance report](../docs/performance.md) preserves the historical
pairwise comparison and adds measurements for the current implementation.

See the [CI guide](../docs/ci.md) and [fuzzing guide](docs/FUZZING.md) for
workflow and local campaign details.

## Deferred API ideas

The retired analysis API is not part of this compatibility implementation.
Revisit these only with a concrete consumer and explicit contracts:

| Follow-up | Design constraint |
| --- | --- |
| Snapshots, construct flags, or verdict hints | Keep descriptive analysis separate from the compatibility verdict; define what each flag or confidence level means. |
| Evidence spans and run metadata | Preserve original-input ranges, report actual quote/context passes, and make prefix truncation explicit. |
| Optional normalization | Keep it outside raw compatibility detection and define how decoded bytes map back to the original input. |
| Policy integration | Start from a real Coraza consumer and its enforcement rules. |
| C ABI and headers | Define symbols, ownership, errors, and C integration tests when a C caller requires them. |

Allocation avoidance is a development goal, not a public allocation-budget
promise. A prefix-limited miss must not be treated as a whole-input verdict.

## License

BSD 3-Clause; see [LICENSE](LICENSE) and
[third-party notices](THIRD_PARTY_NOTICES.md).

[libinjection]: https://github.com/libinjection/libinjection
