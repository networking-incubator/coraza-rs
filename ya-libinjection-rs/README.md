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
checks, the HTML5 tokenizer, and the XSS checks. It has no dependencies and no
`unsafe` code, and needs neither `std` nor an allocator.

The name is a play on the original's: `libinjection` and `libinjection-rs` are
taken on crates.io, by bindings to the C library.

It is meant to give the same answer as the C library, as built on x86-64, on
every input. Two things check that:

- libinjection's own tests: its 584 expected-output files and its sample
  corpora.
- A differential test, which builds the C library and compares it with the
  port on upstream's corpus and on fuzzed inputs: tokens, folded tokens,
  fingerprints and verdicts, in every context. A default run compares some
  940,000 inputs. The longest so far compared 20 million and found no
  difference.

## Testing

`cargo test` runs everything. The differential tests need a C compiler (`CC`,
`CFLAGS`); the top of `tests/differential.rs` describes the longer run, and
the one with the C side under sanitizers.

`tests/upstream` holds libinjection's sources, tests and samples.
`tools/vendor_upstream.sh` refreshes it from a checkout and regenerates the
tables in `src` that are derived from it.

## Performance

`cargo bench` times the port next to the C library on the same inputs: those
of upstream's two speed tests, and its sample corpora. The SQL corpora go
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

The two sides run one after the other and nothing is pinned to a core, so
small differences are noise: rebuilding alone can move a time by a tenth.

## Missing quality of life APIs

The public API covers detection and, for each detector, the dialect or HTML
context that matched. Richer analysis found in comparable libraries is not yet
exposed:

- **Construct flags.** A bitset saying *which* constructs appeared in the
  match: for SQLi, things like union, tautology, stacked queries, comments,
  and functions; for XSS, script tags, event handlers, inline SVG, and URL
  schemes. All the data is in `State.tokens` after folding — it is a post-fold
  pass with no change to the hot path.

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
- **Public API.** Only `sqli` and `xss` are public. The tokenizers are behind
  `internals`, a hidden feature with no stability promise that the tests use.
  Upstream exposes them, along with a hook to replace the keyword lookup,
  which was not ported.
- **Copyright.** `LICENSE` carries libinjection's notice, as its license
  requires. No line was added for this port.
- **Minimum Rust version.** None is declared or tested.
- **Mutation testing** was done once, by hand: of 14 deliberately broken
  variants of the port, the tests caught 11, and the other 3 appear to be
  equivalent. None of that is in the repository.
- **Following upstream.** Only the tables are generated. Changes to the C code
  have to be ported by hand.

## License

BSD 3-Clause, the same as libinjection: see `LICENSE`.
