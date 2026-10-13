# libperfusion

A pure Rust port of [libinjection](https://github.com/libinjection/libinjection),
which detects SQL injection and cross-site scripting by tokenizing the input
rather than matching regular expressions against it.

```rust
let fingerprint = libperfusion::sqli(b"1' OR '1'='1").unwrap();
assert_eq!(fingerprint, "s&sos");

assert!(libperfusion::xss(b"<script>alert('xss')</script>"));
```

## Status

The port is complete, and not published yet. It follows libinjection 4.0.0
(`d88a8f8`): the SQL tokenizer, folding, fingerprints and false-positive
checks, the HTML5 tokenizer, and the XSS checks. Its one dependency is
[memchr](https://crates.io/crates/memchr), for byte searches. It has no
`unsafe` code of its own, and needs neither `std` nor an allocator.

The name is a play on the original's: `libinjection` and `libinjection-rs` are
taken on crates.io, by bindings to the C library.

The required tests check feature-level parity against the in-repository
`libinjection` crate and its pinned corpus. They compare SQLi fingerprints,
token records, counters, and XSS verdicts. Exact C comparisons remain
available as optional tests.

## Testing

`cargo test -p libperfusion` runs the local corpus, API, and regression tests;
`cargo test --workspace` also runs the sibling crate's tests. The exact-C
differential, upstream corpus, sample, and table comparisons are ignored by
default. Run them with an upstream checkout and a C compiler:

```sh
LIBINJECTION_DIR=/path/to/libinjection \
  cargo test -p libperfusion --test differential -- --ignored
LIBINJECTION_DIR=/path/to/libinjection \
  cargo test -p libperfusion --test upstream -- --ignored
LIBINJECTION_DIR=/path/to/libinjection \
  cargo test -p libperfusion --test tables -- --ignored
```

`CC` and `CFLAGS` configure the C compiler. The longer fuzz run and sanitizer
example are documented at the top of `tests/differential.rs`. `cargo xtask
tables-check` verifies the local SQL and XSS table data against recorded
semantic hashes. To refresh it from a libinjection checkout, run:

```sh
cargo xtask tables-refresh --upstream /path/to/libinjection
```

`tools/vendor_upstream.sh /path/to/libinjection` can populate
`tests/upstream` and refresh the local tables.

## Parser API

The detector helpers cover common use. `SqlTokenizer` iterates raw SQL tokens;
`SqlState` can fold those tokens, return a fingerprint in any typed quote and
dialect context (including benign inputs), and classify that fingerprint.
`SqlToken` exposes bounded values through read-only accessors. Implement
`SqlLookup` to customize word, operator, phrase, and fingerprint decisions;
`BuiltinSqlLookup` supplies the shipped tables. The lookup remains active
across reset and reparse.

`HtmlTokenizer` iterates tokens in any `HtmlContext`, and `xss_in_context`
checks the verdict for one explicitly chosen context. `xss_with_context`
continues to report the first matching context selected by the detector.

```rust
use libperfusion::{Dialect, Quote, SqlState};

let mut state = SqlState::new(b"1' OR '1'='1");
let fingerprint = state.fingerprint(Quote::None, Dialect::Ansi);
assert!(state.check_fingerprint());
assert!(!fingerprint.as_bytes().is_empty());
```

## Performance

`cargo bench` also needs the upstream checkout and a C compiler. It times the
port next to the C library on the same inputs: those of upstream's two speed
tests and sample corpora. The SQL corpora go
through the XSS detection as well, as inputs that are not XSS: those cost the
most, since nothing ends the search early. Below is the time per input, in
nanoseconds, on an AMD Ryzen 9 7900, with libinjection built by GCC 16.2 at
`-O3` and the port by Rust 1.99.

| Workload                    | Inputs | Average bytes | libinjection |   Port | Port / C |
| --------------------------- | -----: | ------------: | -----------: | -----: | -------: |
| sqli: upstream's speed test |      8 |            28 |        422.5 |  212.3 |    0.50x |
| sqli: attack samples        | 85,802 |           141 |       1059.4 |  583.5 |    0.55x |
| sqli: benign samples        |    423 |            34 |        604.7 |  331.7 |    0.55x |
| xss: upstream's speed test  |     26 |            30 |        222.1 |  102.0 |    0.46x |
| xss: attack samples         | 81,417 |            74 |        157.2 |   65.4 |    0.42x |
| xss: sqli attack samples    | 85,802 |           141 |       1495.6 |  734.2 |    0.49x |
| xss: benign samples         |    423 |            34 |        371.3 |  208.4 |    0.56x |

The table below preserves the earlier single C-first measurements. Current
`cargo bench` runs two measurements per workload, alternating which side runs
first and printing the order for each ratio. Nothing is pinned to a core, so
small differences remain noise: rebuilding alone can move a time by a tenth.

To compare this crate with the in-repository `libinjection-rs` implementation,
run `cargo bench -p libperfusion --bench compare` for the shared corpus and
`cargo bench -p libperfusion --bench scaling` for generated size and shape
workloads. These targets do not need the upstream C checkout. See the
[benchmark report](BENCHMARK_REPORT.md) for the measured results and limits.

## Missing quality of life APIs

The public API covers detection and, for each detector, the dialect or HTML
context that matched. Richer analysis found in comparable libraries is not yet
exposed:

- **Construct flags.** A bitset saying *which* constructs appeared in the
  match: for SQLi, things like union, tautology, stacked queries, comments,
  and functions; for XSS, script tags, event handlers, inline SVG, and URL
  schemes. The data is available from `SqlState::tokens()` after folding —
  this is a post-fold pass with no change to the hot path.

- **Verdict confidence.** A coarser classification than `Option<Fingerprint>`:
  something like `Decisive / Suspicious / Inconclusive` to let callers tune
  their response. Requires defining which fingerprints or false-positive paths
  map to each tier — new logic with no existing analogue in libinjection itself.

- **Evidence spans.** Byte offsets into the original input marking the tokens
  that made the call. Requires storing a start offset in `Token`, which the
  lexer does not currently track. Adding it is one write per token in the hot
  path and would need a fixed-size representation (no allocator) for the result.

- **SQLi quote context.** Which quote mode — raw input, single-quoted, or
  double-quoted — the matching parse was in. `sqli_with_dialect` returns the
  SQL dialect but drops this. It is already determined by the control flow in
  `detect_with_dialect` and costs nothing to surface.

- **Run metadata flags.** Bits describing the detection run itself: whether the
  input was truncated by a limit, whether multiple quote contexts were tried,
  whether the result came from a re-parse as MySQL. These fall out naturally
  from the existing control flow and pair well with the `_with_limit` variants.

- **`scan_prefix`.** A helper that truncates an input to a byte budget while
  respecting a token or character boundary, avoiding a cut mid-token. Useful
  for callers that want to bound scan cost without the `_with_limit` variants'
  hard slice.

## Open issues and decisions

- **A 0xFF byte ends HTML tokenization.** `<img \xff onerror=alert(1)>` is not
  flagged: not by libinjection on x86, and so not by the port. Keep the parity,
  or fix it here and report it upstream?
- **`char` signedness.** The port behaves like the C library built with a
  signed `char`. Where `char` is unsigned, as on ARM Linux, the C library
  itself answers differently on some inputs with bytes above 127.
- **Manifest.** It declares no repository.
- **Detection run metadata.** The detector helpers do not report which SQL
  quote context won or which contexts were tried. `SqlState` lets callers
  select a quote and dialect directly and inspect each resulting fingerprint.
- **Copyright.** `LICENSE` carries libinjection's notice, as its license
  requires. No line was added for this port.
- **Minimum Rust version.** None is declared or tested.
- **Mutation testing** was done once, by hand: of 14 deliberately broken
  variants of the port, the tests caught 11, and the other 3 appear to be
  equivalent. None of that is in the repository.
- **Following upstream.** The tables can be refreshed from C, but this does not
  port algorithm changes; review and port those separately.

## License

BSD 3-Clause, the same as libinjection: see `LICENSE`.
