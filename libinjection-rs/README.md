# libinjection-rs

Pure-Rust **WAF hot-path library** for SQL injection and XSS compatibility
detection plus construct analysis.

Designed as the analysis engine behind Coraza operators `@detectSQLi` and
`@detectXSS`. The library classifies untrusted input and returns an owned
[`AnalysisSnapshot`](src/snapshot.rs); **Coraza owns policy** (block, log,
audit, CRS rules).

**Status:** The bounded analysis API, full-input compatibility API, and legacy
corpus harness are implemented. Coraza wiring is not yet in this repo.

---

## What this library does

The analysis API:

1. **Prefilters** obvious non-candidates (fast reject).
2. **Normalizes** the selected input prefix, borrowing unchanged input and
   allocating an owned buffer only when normalization changes bytes (NUL
   removal, one layer of `%HH` decode, ASCII lowercasing).
3. **Tokenizes** and **classifies constructs** (UNION, tautology, `<script>`,
   event handlers, …).
4. Returns an [`AnalysisSnapshot`](src/snapshot.rs): construct bitset, owned
   evidence spans, status flags, and a [`VerdictHint`](src/snapshot.rs).

The crate exposes two separate APIs:

- **Construct analysis:** Construct flags, evidence, and partial-analysis
  status in a snapshot. Storage grows with the selected input prefix and the
  evidence found; it is not capped by internal token or evidence buffers.
- **Compatibility detection** (`legacy` feature): Full-input byte-compatible
  verdicts from [libinjection-go](https://github.com/corazawaf/libinjection-go),
  including the SQL fingerprint.

[`detect_sqli`](src/lib.rs) and [`detect_xss`](src/lib.rs) call the legacy
compatibility algorithms once on the complete raw byte slice. SQL detection
returns its boolean and exact fingerprint; XSS detection returns a boolean.
They do not return construct-analysis metadata. [`analyze_sqli`](src/lib.rs) and
[`analyze_xss`](src/lib.rs) are separate bounded, descriptive APIs.

**Not in scope for this crate:** SecRule actions, CRS rule packs, block/allow
decisions, or full SQL parsing on the hot path.

---

## Quick start

### Add the dependency

From the workspace (path dependency until published):

```toml
[dependencies]
libinjection = { path = "../libinjection-rs", features = ["legacy"] }
```

The crate always uses Rust's standard library. Default features include the
legacy compatibility API. To use only bounded analysis:

```toml
libinjection = { path = "../libinjection-rs", default-features = false }
```

### Detect with compatibility semantics

Use when you want the same semantics as `@detectSQLi` / `@detectXSS`:

```rust
use libinjection::{detect_sqli, detect_xss};

let sqli = detect_sqli(b"1' OR '1'='1");
assert!(sqli.detected);
assert_eq!(sqli.fingerprint.as_str(), Some("s&sos"));

let xss = detect_xss(b"<script>alert(1)</script>");
assert!(xss);

let benign = detect_sqli(b"ordinary text");
assert!(!benign.detected);
assert!(benign.fingerprint.as_str().is_none());
```

### Analyze within a configured input budget

Use when the caller needs bounded construct metadata, evidence, and status:

```rust
use libinjection::{analyze_sqli, analyze_xss};
use libinjection::snapshot::{ConstructFlags, VerdictHint};

let snap = analyze_sqli(b"1' UNION SELECT null--");
assert!(snap.constructs.intersects(ConstructFlags::SQL_UNION));
assert_eq!(snap.verdict_hint, VerdictHint::Decisive);

let xss = analyze_xss(b"<img src=x onerror=alert(1)>");
assert!(xss.constructs.any_xss());
```

`AnalysisFlags` reports when the caller's input budget omitted a suffix
(`TRUNCATED`) or a fast prefilter skipped detailed classification
(`PREFILTER_MISS`). Analysis storage grows to retain the normalized input,
relevant token metadata, and all distinct evidence spans found in the selected
prefix. Every evidence span indexes the original input. `Benign` means the pass
completed without recognizing one of its configured constructs; it does not
show that the input is safe. `Inconclusive` means a prefilter skipped detailed
classification or the configured scan budget left input unexamined. Handle
either hint through the surrounding policy. Use `detect_sqli` / `detect_xss`
when a libinjection compatibility verdict is required.

### Analysis scan budget

Analysis scans a prefix of the input (default **8192 bytes**). The configured
budget is not internally capped: storage and work can grow with the selected
prefix. Set it at WAF initialization from trusted configuration, never from
untrusted request metadata:

```rust
use libinjection::{
    limits::DEFAULT_MAX_INPUT_LEN, AnalyzeOptions, analyze_sqli_with,
};

let opts = AnalyzeOptions::with_max_input_len(16_384);
let snapshot = analyze_sqli_with(large_payload, opts);

if snapshot.flags.contains(libinjection::AnalysisFlags::TRUNCATED) {
    // The snapshot describes only the configured prefix.
}
```

Constants: [`DEFAULT_MAX_INPUT_LEN`](src/limits.rs) and its compatibility alias
[`MAX_INPUT_LEN`](src/limits.rs).

---

## API overview

- `analyze_sqli` / `analyze_xss` return `AnalysisSnapshot` for analysis
  details.
- `analyze_*_with` returns `AnalysisSnapshot` with a caller-configured scan
  budget.
- `detect_sqli` returns `SqliDetection` with the full-input compatibility
  boolean and fingerprint.
- `detect_xss` returns a full-input compatibility boolean.

Key types (re-exported from the crate root):

- [`AnalysisSnapshot`](src/snapshot.rs) — constructs, bounded-analysis status,
  `verdict_hint`, context, and original-input evidence.
- [`SqliDetection`](src/snapshot.rs) — compatibility `detected: bool` and exact
  fingerprint, available with `legacy`.
- [`ConstructFlags`](src/snapshot.rs) — SQL bits 0–15, XSS bits 16–27.
- [`VerdictHint`](src/snapshot.rs) — `Benign` / `Suspicious` / `Decisive` /
  `Inconclusive`; descriptive bounded-analysis output that must not serve as
  an allow decision.
- [`AnalyzeOptions`](src/options.rs) — bounded analysis scan budget.

---

## Features

- `legacy` (default): Canonical full-input `detect_*` APIs and public legacy
  visitors. It is independent of the analysis storage policy.

The crate always uses Rust's standard library. Without `legacy`, the canonical
compatibility detection functions and legacy visitor exports are unavailable.
XSS construct analysis still includes a private HTML denylist scanner used by
its classifier.

---

## Hot-path contract

The `analyze_*` path is designed for per-field WAF scanning:

- **Heap-backed analysis output.** Normalization, relevant token metadata, and
  evidence storage grow with the configured input prefix and matches.
- **Standard library required.** The parser uses no operating-system APIs.
- **Configurable input budget.** The default is 8 KiB; callers may select a
  larger trusted limit. The snapshot reports prefix truncation.
- Avoid heap allocations on hot paths where practical. Call out new allocations
  in code review; this is a best-effort goal, not an API guarantee.
- **Bounds-checked parser paths** with panic regression tests over arbitrary
  bytes; this is a tested property, not a formal proof for every input.
- **Runtime dependency:** `memchr` only on the hot path.

The full-input `detect_*` compatibility APIs do not use the `analyze_*` scan
budget. Callers should enforce their own input-size limit.

### Legacy XSS context dispatch

`detect_xss` checks data and unquoted-value contexts first. It then enters a
single-quote, double-quote, or backtick context only when that raw delimiter is
present. In the Go module pinned by `xtask/tools/go.mod`, a quoted context
without its delimiter emits one unclassified attribute value and reaches EOF,
so it cannot produce a hit. The check is byte-oriented and preserves behavior
with NUL and invalid UTF-8. The HTML tokenizer and `html5_visit` output are
unchanged.

Regression tests cover absent and late delimiters, NUL, invalid UTF-8, and
malformed values in
[`regression_tests.rs`](src/xss/legacy/regression_tests.rs).

WASM embedders: the crate requires `std` and uses no operating-system APIs.
See the [assurance guide](docs/ASSURANCE_REPORT.md) for build checks.

---

## Development

```bash
# Unit tests + integration tests
cargo test -p libinjection

# Legacy corpus parity
cargo test -p libinjection --test corpus_parse

# Workspace lint (from repo root)
make lint

# Optional WASI builds with the legacy API disabled and enabled
cargo check -p libinjection --target wasm32-wasip1 \
  --no-default-features
cargo check -p libinjection --target wasm32-wasip1

# Validate parity fixture inventory and hashes
make parity-manifest-check
```

The full Go differential suites use the module pinned in `xtask/tools/go.mod`;
see the [assurance checks](docs/ASSURANCE_REPORT.md).

---

## Architecture

```text
analyze_*  = bounded prefix → normalize → tokenize/classify
             → AnalysisSnapshot + VerdictHint
detect_sqli = full raw input → legacy-compatible boolean + fingerprint
detect_xss  = full raw input → legacy-compatible boolean
```

**Library** emits analysis. **Coraza** applies SecRules/CRS, audit, and
block/allow policy.

---

## Documentation

- [Assurance checks](docs/ASSURANCE_REPORT.md) — local validation and Go
  differential commands.
- [Fuzzing](docs/FUZZING.md) — fuzz targets and regression workflow.
- [Parity protocol](tools/parity/PROTOCOL.md) — pinned Go oracle and byte-safe
  comparison format.
- [CI guide](../docs/ci.md) — workspace CI jobs and local commands.

---

## Roadmap

| Phase | Status |
| --- | --- |
| 0 – scaffold | Done |
| 1 – corpus harness | Done |
| 2a – legacy compatibility | Done |
| 2b – modern engine + `analyze_*` | Done |
| 3 – Coraza integration | Separate follow-up in `coraza-rs` |
| 4 – construct rule-matching interface | Future consumer design |
| 5 – construct hardening | Future consumer design |

---

## Goal

Replace `libinjectionrs = "0.1.1"` in coraza-rs with this crate for
`@detectSQLi` and `@detectXSS`, while moving long-term policy to
construct-based matching instead of embedded fingerprint blacklists.
