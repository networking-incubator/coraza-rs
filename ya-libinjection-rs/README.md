# libinjection-rs

A pure Rust port of [libinjection](https://github.com/libinjection/libinjection),
which detects SQL injection and cross-site scripting by tokenizing the input
rather than matching regular expressions against it.

```rust
let fingerprint = libinjection_rs::sqli(b"1' OR '1'='1").unwrap();
assert_eq!(fingerprint, "s&sos");

assert!(libinjection_rs::xss(b"<script>alert('xss')</script>"));
```

## Status

The port is complete, and not published yet. It follows libinjection 4.0.0
(`d88a8f8`): the SQL tokenizer, folding, fingerprints and false-positive
checks, the HTML5 tokenizer, and the XSS checks. It has no dependencies and no
`unsafe` code, and needs neither `std` nor an allocator.

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
of upstream's two speed tests, and its sample corpora. Below is the time per
input, in nanoseconds, on an AMD Ryzen 9 7900, with libinjection built by GCC
16.2 at `-O3` and the port by Rust 1.99.

| Workload                    | Inputs | Average bytes | libinjection |   Port | Port / C |
| --------------------------- | -----: | ------------: | -----------: | -----: | -------: |
| sqli: upstream's speed test |      8 |            28 |        414.8 |  633.0 |    1.53x |
| sqli: attack samples        | 85,802 |           141 |       1068.1 | 1572.8 |    1.47x |
| sqli: benign samples        |    423 |            34 |        601.9 |  865.2 |    1.44x |
| xss: upstream's speed test  |     26 |            30 |        223.9 |  162.2 |    0.72x |
| xss: attack samples         | 81,417 |            74 |        164.2 |  108.9 |    0.66x |

The two sides run one after the other and nothing is pinned to a core, so
small differences are noise.

## Open issues and decisions

- **A 0xFF byte ends HTML tokenization.** `<img \xff onerror=alert(1)>` is not
  flagged: not by libinjection on x86, and so not by the port. Keep the parity,
  or fix it here and report it upstream?
- **`char` signedness.** The port behaves like the C library built with a
  signed `char`. Where `char` is unsigned, as on ARM Linux, the C library
  itself answers differently on some inputs with bytes above 127.
- **Crate name.** `libinjection-rs` is taken on crates.io, by bindings to the C
  library. The manifest also lacks a description and a repository.
- **Public API.** Only `sqli` and `xss` are public. The tokenizers are behind
  `internals`, a hidden feature with no stability promise that the tests use.
  Upstream exposes them, along with a hook to replace the keyword lookup,
  which was not ported.
- **Copyright.** `LICENSE` carries libinjection's notice, as its license
  requires. No line was added for this port.
- **Performance.** The port takes about 1.5 times as long as the C library on
  SQL injection inputs (see above). Nothing has been optimized yet.
- **Minimum Rust version.** None is declared or tested.
- **Mutation testing** was done once, by hand: of 14 deliberately broken
  variants of the port, the tests caught 11, and the other 3 appear to be
  equivalent. None of that is in the repository.
- **Following upstream.** Only the tables are generated. Changes to the C code
  have to be ported by hand.

## License

BSD 3-Clause, the same as libinjection: see `LICENSE`.
