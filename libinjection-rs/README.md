# libinjection-rs

Pure-Rust **WAF hot-path analysis library** for SQL injection and XSS construct
detection.

Designed as the analysis engine behind Coraza operators `@detectSQLi` and
`@detectXSS`. The library classifies untrusted input and returns a fixed-size
[`AnalysisSnapshot`](src/snapshot.rs); **Coraza owns policy** (block, log,
audit, CRS rules).

**Status:** PR1 implements the bounded stage-1 engine and public `analyze_*` /
`detect_*` API. Corpus fixtures and their harness are preserved for PR2.
Coraza wiring is not yet in this repo.

---

## What this library does

On every call the library:

1. **Prefilters** obvious non-candidates (fast reject).
2. **Normalizes** input in a bounded stack buffer (NUL strip, one layer of
   `%HH` decode, ASCII lowercasing).
3. **Tokenizes** and **classifies constructs** (UNION, tautology, `<script>`,
   event handlers, …).
4. Returns an [`AnalysisSnapshot`](src/snapshot.rs): construct bitset, evidence
   spans, status flags, and a [`VerdictHint`](src/snapshot.rs).

Two detection paths coexist:

| Path | Role |
| --- | --- |
| **Modern (stage 1)** | Construct flags + evidence — primary long-term API. |
| **Legacy** (`legacy` feature) | Fingerprint-blacklist engine from [libinjection-go](https://github.com/corazawaf/libinjection-go) for corpus parity and audit field 0. |

[`detect_sqli`](src/lib.rs) / [`detect_xss`](src/lib.rs) apply a **built-in
minimal policy** on construct flags and OR in a legacy hit when `legacy` is
enabled. [`analyze_sqli`](src/lib.rs) / [`analyze_xss`](src/lib.rs) return the
full snapshot without applying that policy — use this when Coraza will match
on specific constructs.

**Not in scope for this crate:** SecRule actions, CRS rule packs, block/allow
decisions, or full SQL parsing on the hot path.

---

## Quick start

### Add the dependency

From the workspace (path dependency until published):

```toml
[dependencies]
libinjection = { path = "../libinjection-rs", features = ["legacy", "std"] }
```

Default features include `legacy`. For a minimal `no_std` build:

```toml
libinjection = { path = "../libinjection-rs", default-features = false }
```

### Detect (boolean verdict)

Use when you want the same semantics as `@detectSQLi` / `@detectXSS`:

```rust
use libinjection::{detect_sqli, detect_xss};

let sqli = detect_sqli(b"1' OR '1'='1");
assert!(sqli.detected);

let xss = detect_xss(b"<script>alert(1)</script>");
assert!(xss.detected);

// Inspect the underlying analysis:
if sqli.snapshot.constructs.any_sqli() {
    // construct bits, evidence spans, verdict hint, ...
}
```

### Analyze (full snapshot)

Use when policy lives in the caller (future CRS construct rules, custom masks, logging):

```rust
use libinjection::{analyze_sqli, analyze_xss};
use libinjection::snapshot::{ConstructFlags, VerdictHint};

let snap = analyze_sqli(b"1' UNION SELECT null--");
assert!(snap.constructs.intersects(ConstructFlags::SQL_UNION));
assert_eq!(snap.verdict_hint, VerdictHint::Decisive);

let xss = analyze_xss(b"<img src=x onerror=alert(1)>");
assert!(xss.constructs.any_xss());
```

### Scan budget

Stage-1 scans a prefix of the input (default **8192 bytes**, hard cap **64 KiB**).
Set at WAF init — **never from untrusted request metadata**:

```rust
use libinjection::{AnalyzeOptions, detect_sqli_with, limits::DEFAULT_MAX_INPUT_LEN};

let opts = AnalyzeOptions::with_max_input_len(16_384);
let verdict = detect_sqli_with(large_payload, opts);

if verdict.snapshot.flags.contains(libinjection::AnalysisFlags::TRUNCATED) {
    // default policy: incomplete analysis is treated as a detection
}

let opts = AnalyzeOptions::with_max_input_len(16_384).allow_truncation();
let verdict = detect_sqli_with(large_payload, opts);
if verdict.snapshot.verdict_hint == libinjection::VerdictHint::Inconclusive {
    // caller owns the continuation or deeper inspection policy
}
```

Constants: [`DEFAULT_MAX_INPUT_LEN`](src/limits.rs),
[`ABSOLUTE_MAX_INPUT_LEN`](src/limits.rs), [`NORM_BUF_LEN`](src/limits.rs).

---

## API overview

| Function | Returns | Use when |
| --- | --- | --- |
| `analyze_sqli` / `analyze_xss` | `AnalysisSnapshot` | Analysis details. |
| `analyze_*_with` | `AnalysisSnapshot` | A custom scan budget. |
| `detect_sqli` / `detect_xss` | `DetectionVerdict` | Built-in policy. |
| `detect_*_with` | `DetectionVerdict` | Policy with a custom budget. |

Key types (re-exported from the crate root):

- [`AnalysisSnapshot`](src/snapshot.rs) — constructs, flags, `verdict_hint`,
  context, evidence, optional legacy fingerprint.
- [`DetectionVerdict`](src/snapshot.rs) — `detected: bool` + embedded snapshot.
- [`ConstructFlags`](src/snapshot.rs) — SQL bits 0–15, XSS bits 16–27.
- [`VerdictHint`](src/snapshot.rs) — `Benign` / `Suspicious` / `Decisive` /
  `Inconclusive` (hint only, with fail-closed truncation configurable).
- [`AnalyzeOptions`](src/options.rs) — scan budget and truncation policy.

---

## Features

| Feature | Default | Description |
| --- | --- | --- |
| `legacy` | yes | Static fingerprints/tables; corpus in PR2. |
| `std` | no | Enables `memchr`'s `std` support. |

---

## Hot-path contract

The default `analyze_*` / `detect_*` path is designed for per-field WAF scanning:

- **Zero heap** on the default path (enforced by `tests/no_alloc.rs`).
- **`no_std`** core (`std` is optional for embedders that want it).
- **Stack-only**, bounded buffers (512 B normalize, 8 token slots, 4 evidence spans).
- **O(n)** over scanned bytes with early exit.
- **No panic** on untrusted input (bounds-checked access throughout).
- **Runtime dependency:** `memchr` only on the hot path.

WASM embedders: see [WASM portability](docs/WASM_PORTABILITY.md).

---

## Development

```bash
# Unit tests + integration tests
cargo test -p libinjection

# Zero-alloc gate
cargo test -p libinjection --test no_alloc

# Workspace lint (from repo root)
make lint

# no_std / WASM smoke check
cargo check -p libinjection --target wasm32-wasip1 --no-default-features
```

---

## Architecture

```text
input
  → scan_prefix (caller budget)
  → prefilter
  → normalize (bounded)
  → tokenize
  → classify constructs
  → AnalysisSnapshot + VerdictHint

detect_*  =  modern construct policy  OR  legacy fingerprint hit (if legacy)
```

**Library** emits analysis. **Coraza** applies SecRules/CRS, audit, and
block/allow policy.

---

## Documentation

| Document | Description |
| ---------- | ------------- |
| [Implementation plan](docs/IMPLEMENTATION_PLAN.md) | Current implementation scope and gates |
| [Modernization plan](docs/MODERNIZATION_PLAN.md) | `AnalysisSnapshot` spec, hot-path contract, Coraza boundary |
| [Research index](docs/README.md) | Go/C analyses, Rust guidelines |
| [WASM portability](docs/WASM_PORTABILITY.md) | Embedder constraints |

---

## Roadmap

| Phase | Status |
| --- | --- |
| 0 – scaffold | Done |
| 1 – corpus harness | Preserved for PR2 |
| 2a – legacy compatibility | In PR1 |
| 2b – modern engine + `analyze_*` | Done |
| **3 – Coraza integration** | **Next** — `detection.rs`; CRS 941/942 |
| 4 – construct rule-matching interface | Planned |
| 5 – construct hardening | Planned |
| PR2 – corpus fixtures and harness | Preserved for follow-up |

---

## Goal

Replace `libinjectionrs = "0.1.1"` in coraza-rs with this crate for
`@detectSQLi` and `@detectXSS`, while moving long-term policy to
construct-based matching instead of embedded fingerprint blacklists.
