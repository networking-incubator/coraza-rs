# Development oracle protocol

`go-oracle` builds a test binary from the pinned Go commit in a temporary
directory. It does not patch the checkout. It accepts only these exact Go
version/experiment pairs: standard `go1.27.1` with an empty `GOEXPERIMENT`, or
the local `go1.27.1-X:nodwarf5` build with `GOEXPERIMENT=nodwarf5`. Both use
`linux/amd64`. The source commit, accepted toolchain flavors, and target are in
the machine-readable manifest. Each invocation prints its actual
`go_version`, `GOEXPERIMENT`, and target to stderr; the Rust harness relays that
per-run record. The only Go-specific test source is
[`oracle_driver_test.go`](oracle_driver_test.go), which observes existing APIs
and parser state. Go is never a Rust runtime dependency.

Send one line per case on stdin:

```text
case-id<TAB>lowercase-hex-input<LF>
```

The oracle emits one tab-separated response line per request, in request order.
All arbitrary bytes are represented as hex; no payload passes through UTF-8 or
newline decoding. Each response has 22 fields:

- **Field 0:** Case id copied from the request

- **Field 1:** Empty on success; otherwise semicolon-separated
  `field-index=hex(stage:panic-value)` records

- **Field 2–3:** `IsSQLi` boolean
  (`0`/`1`) and `fingerprint_hex:length_hex`; a miss is
  `:0`

- **Field 4–9:** Raw SQL token streams for flags 9, 17, 10, 18, 12, 20

- **Field 10–15:** Folded SQL streams for the same flags

- **Field 16–20:** HTML5 token streams for Data, unquoted, single, double, and
  backtick contexts

- **Field 21:** `IsXSS` boolean (`0`/`1`)

Each SQL stream has `tokens,folds,comment_ddx,comment_hash;records`. A raw token
record is
`category_hex:position:length:variable_count:open_hex:close_hex:value_hex`.
The category, delimiters, and value are bytes; the two zero delimiters are
`00`. HTML5 records are `kind:length:value_hex`; Go kinds are the numeric enum
values in `html5_decls.go`, including `TAG_DATA=4`. Empty token streams keep
their stats prefix and have an empty record suffix.

The fingerprint field encodes the exact Go bytes followed by their length in
hexadecimal, without a UTF-8 conversion. Each SQL result, SQL token mode, HTML5
context, and public XSS result has its own panic boundary. An errored field is
left empty and gets one `field-index=hex(stage:panic-value)` record in field 1;
later fields are still evaluated independently. The Rust differential test
compares every result whose oracle call completed, even when a different field
crashed. It treats every unlisted oracle error as a mismatch. The v0.3.3
baseline currently has no oracle errors; malformed CDATA cases and NUL
IMPORT/ENTITY comments are compared exactly like all other inputs. Field 1 and
the independent panic boundaries remain so a future oracle crash is reported
without losing results from fields that completed. Any exception requires
review and an exact manifest entry; oracle errors are never silently ignored.

The mode order is quote-none ANSI/MySQL, quote-single ANSI/MySQL, and
quote-double ANSI/MySQL. These are the explicit flags used to inspect the
tokenizer/folder, independent of `IsSQLi`, which reports its own multi-pass
boolean and fingerprint.
