# Libinjection assessment and consolidation plan

<!-- markdownlint-configure-file {"MD013":{"tables":false}} -->

Date: 2026-10-13. Assessed branch: `alex-implementation`.
Repository baseline: `af42a1590af7da5e374fe8e1d12abbfa4787c371`.
This document records findings and work for later implementation. It does
not change either detector, its fixtures, or CI configuration.

## Decision

**Use libperfusion as the future single Rust implementation. It is not ready
to replace the existing implementation without the work below.** Keep
`libinjection-rs` temporarily to migrate its tests and check the transition.
Remove its engine and modern analysis layer once the replacement gates pass.
There is no demonstrated requirement to keep two Rust detector engines.

Libperfusion already has the core SQL lexer, folder, fingerprints, whitelist
rules, HTML tokenizer, and XSS classifier. Its typed tokens and states are
clearer and its implementation is smaller. Existing measurements often favor
it, although some inputs favor the other engine. This recommendation rests
on maintainability and the ability to preserve upstream capabilities; speed
alone does not establish replacement readiness.

The current `libinjection-rs` is a useful source of regression tests, Go
compatibility behavior, oracle tooling, and future analysis requirements.
It is not an infallible oracle: it misses Go's bare `XLINK` case and, like
libperfusion and Go v0.3.5, lacks the newest C LIKE folding fix.

### What replacement means

The intended first release is a Rust library for the libinjection feature
set. It includes byte-oriented SQLi/XSS detection, hit fingerprints,
tokenization, folding, explicit parse contexts, and the C library's
customizable lookup capability. API names and Rust result types can differ.
Snapshot analysis, construct flags, evidence collection, and inferred
confidence are a later product layer.

This does **not** promise C ABI compatibility. Neither current crate exports
C symbols or ships an ABI-compatible `.h` interface. Copyright/license
headers must be fixed now. C include headers, `staticlib`/`cdylib` output,
bindings, and installation metadata need a separate decision if C callers
must link to the Rust library.

## Upstream baselines and compatibility policy

The sources were checked independently of the sibling Rust implementation:

| Reference | Revision | Role |
| --- | --- | --- |
| Go release | v0.3.5, `de4ec9bfed163a9499c426e8c53af0805973cb35` | Current release selected by `xtask/tools/go.mod` |
| Earlier C baseline | `d88a8f86d617ac8dcb9169c9f34637aaac71ac76` | Libperfusion's declared port baseline, after v4.0.0 |
| Current C main | `533a165ebc1f7c36ecbe3e5583990ea0db81f554` | Includes the October 12 LIKE folding correction |

Go v0.3.5 was verified as the latest GitHub release during this assessment.
Its module checksum matches the checked-in manifest:
`h1:Zj2AAAKnaRtoLCXYqmc/wzCVAVXxe81UpF5JblL4WQA=`.
C main was exactly one commit ahead of the declared C baseline.

Primary references:

- [Go v0.3.5 source](https://github.com/corazawaf/libinjection-go/tree/de4ec9bfed163a9499c426e8c53af0805973cb35)
- [C LIKE correction](https://github.com/libinjection/libinjection/commit/533a165ebc1f7c36ecbe3e5583990ea0db81f554)
- [C SQL feature interface](https://github.com/libinjection/libinjection/blob/533a165ebc1f7c36ecbe3e5583990ea0db81f554/src/libinjection_sqli.h)
- [C XSS context interface](https://github.com/libinjection/libinjection/blob/533a165ebc1f7c36ecbe3e5583990ea0db81f554/src/libinjection_xss.h)

### Both upstreams cannot be identical on every byte sequence

C and Go disagree on NUL separators, normalized names, event-name suffixes,
Unicode SQL keywords, indirect attribute classification, and some limits.
For example, C flags `<a onerrorfoo=1>` while Go does not; Go flags
`<a on\x00error=1>` while C does not. These are runtime results, not inferred
differences in implementation style.

Recommended policy for Coraza:

1. Use Go v0.3.5 public detection behavior and hit fingerprints as the default
   compatibility target, including its negative controls. Preserve the same
   raw-byte input boundary; do not introduce analyzer normalization.
2. Keep the already reviewed C-aligned SQL NUL-prefix exceptions and the
   existing FF/offset corrections. Add the newest C LIKE correction as a
   narrowly recorded difference from the older Go release.
3. Use the selected Go streams for supported parser operations, with exact
   exceptions for intentionally retained C differences. Keep C's streams and
   verdicts as a second independent oracle and explain each disagreement.
4. Provide C-equivalent capabilities through supported Rust APIs without
   copying its mutable struct layout, source-line debug reasons, or unsafe
   pointer preconditions.

Do not describe this as universally identical behavior with both upstreams.
Release documentation must name the versions and reviewed exceptions. If
literal, selectable C and Go behavior is required, a compatibility profile
would be a separate product decision. It should share one engine; it should
not recreate two implementations. Such profiles are not part of this plan.

## Evidence from this assessment

### Validation performed

| Check | Result |
| --- | --- |
| `make test` | Corpus checks and detector test binaries passed; xtask's workspace header test exited with failure |
| `cargo xtask corpus-check` | 496 fixture hashes/inventory and 54 SQL oracle inputs verified |
| Parity manifest checks | Passed, including direct verification against downloaded Go v0.3.5 source |
| `make parity-differential` | Passed against Go 1.27.1 on linux/amd64, under its existing limited comparison contract |
| `make lint` | Failed at Clippy: `fold::fill` has 6 arguments, above the configured limit of 5 |
| `cargo xtask lint-license` | Failed: 19 libperfusion Rust files lack the required project header |
| `cargo package -p libperfusion --offline` | Package creation succeeded; isolated verification failed on the sibling keyword-data path |
| Libperfusion optional C table tests | All 5 passed against the declared C baseline |
| Libperfusion optional C upstream tests | All 7 enabled corpus/sample tests passed against that baseline |
| Libperfusion optional exact-C differential | All 5 failed because `tests/oracle/oracle.c` is missing; comparison was blocked |
| Independent YA full corpus check | All 496 fixture expectations passed across all five families |
| Independent public detector comparisons | 843 existing direct cases, 770 existing generated cases, 26 focused probes compared against Go and both C revisions |

The five corpus families are 118 folding, 68 HTML5, 54 SQLi, 249 raw SQL
token, and 7 XSS fixtures. The independent check evaluated their intended
outputs; it did not merely run each input through the high-level detectors.

The existing Go runner requires an exact toolchain. The installed Go 1.27.2
did not meet its guard, so Go 1.27.1 was used without changing that guard.
This local version mismatch is not a CI failure: CI already installs 1.27.1.
Go is a development oracle, not a Rust runtime dependency.

The C public drivers used `-O2 -fsigned-char`. The current C SQL file was
reconstructed from the sole upstream patch and checked against its Git blob
hash, `05ef180dce576bd77d6656a1999957f1ac4830f6`. Large external C source/sample
assets remained outside this repository. All independent oracle calls
completed; no oracle errors were flattened into benign results.

### What the existing Go suite actually establishes

The direct suite completed 843 cases and 16,860 defined field comparisons,
with two accepted Rust-only SQL verdict exceptions and eight parser
diagnostic differences. The generated suite completed 770 cases with one
accepted SQL verdict exception and one fingerprint diagnostic.

These counts do **not** mean every field was identical. The existing harness
fails unexpected public verdict differences, but generally logs fingerprint,
SQL token/fold, and HTML stream differences without failing. Its one-way
verdict contract is weaker than the requested replacement contract.

### Independent public-result comparison

The table counts differences against Go v0.3.5. Fingerprints are compared
here when both implementations report a SQLi hit. These are selected test
inventories, not measured false-positive or false-negative rates.

| Candidate / cases | SQL verdict differences | XSS verdict differences | Go XSS hits lost | Hit fingerprint differences |
| --- | ---: | ---: | ---: | ---: |
| YA / existing 843 | 2 | 9 | 5 | 0 |
| Reference Rust / existing 843 | 2 | 0 | 0 | 0 |
| YA / generated 770 | 1 | 0 | 0 | 0 |
| Reference Rust / generated 770 | 1 | 0 | 0 | 0 |
| YA / focused 26 | 3 | 9 | 4 | 0 |
| Reference Rust / focused 26 | 1 | 2 | 2 | 0 |

The focused YA SQL differences include two lost Go hits involving Unicode
keyword folding. The remaining SQL differences include already reviewed
C-aligned NUL-prefix behavior. Against the declared C baseline, YA agrees on
all public results and hit fingerprints in the existing 843 cases. Its one
generated XSS difference is an additional hit. The current C LIKE fixture
adds a real missing hit and a fingerprint difference on a separate input.

### Reproduced differences

In this table, `\x00` and `\xff` describe raw bytes, not literal backslash
characters. C results are identical between the two C revisions for these
XSS inputs. `hit` means the detector flags the input; it is not a claim that
the input executes in every browser or database.

| Input | C XSS | Go XSS | YA XSS | Reference Rust XSS |
| --- | --- | --- | --- | --- |
| `xlink=1` | hit | hit | hit | miss |
| `<a onerrorfoo=1>` | hit | miss | hit | miss |
| `<a on\x00error=1>` | miss | hit | miss | hit |
| `<sv\x00gload>` | miss | hit | miss | hit |
| `<a xm\x00lns=1>` | miss | hit | miss | hit |
| `href=ja\x00va:` | miss | hit | miss | hit |
| `<?im\x00port namespace="t">` | miss | hit | miss | hit |
| `<!EN\x00TITY x SYSTEM "file:///etc/passwd">` | miss | hit | miss | hit |
| `<a xmlnsfoo=1>` | hit | miss | hit | miss |
| `<a attributename=href>` | hit | miss | hit | miss |
| `<img \xff onerror=alert(1)>` | miss | hit | hit | hit |

All four embedded-NUL IMPORT/ENTITY cases in the existing direct inventory
are missed by YA. Go and the reference detect them. The existing overlong
SVG/XSL controls and namespace-prefix controls contribute the four YA-only
XSS hits in that inventory.

| SQL input | Current C | Go v0.3.5 | YA / reference Rust |
| --- | --- | --- | --- |
| `1 LIKE (SELECT 1)` | hit, `1o(E1` | hit, `1f(E1` | hit, `1f(E1` |
| `' OR (8459 LIKE (SELECT 8459)) * 4906 --\x20` | hit, `s&(1o` | miss | miss |
| `1 UNıON SELECT 1` | miss | hit, `1UE1` | YA misses; reference matches Go |
| `1 UNION ſELECT 1` | miss | hit, `1UE1` | YA misses; reference matches Go |
| `1 or 0x\x001=1--\x20` | hit, `1&1c` | miss | hit, `1&1c` |

The LIKE attack's last `\x20` is a raw trailing space. The Unicode examples
use U+0131 and U+017F. They demonstrate Go compatibility differences; this
assessment does not assert that every SQL engine accepts those keywords.

## Capability comparison

| Capability | Libperfusion | Current libinjection-rs | Migration requirement |
| --- | --- | --- | --- |
| Byte-oriented SQLi / XSS detection | Present | Present under `legacy` | Keep full-input APIs and raw-byte semantics |
| Exact SQLi hit fingerprint | `Option<Fingerprint>` | Boolean plus fixed fingerprint | Keep bytes and make differential fingerprint checks fail when wrong |
| SQL dialect reporting | Present | No equivalent compatibility result field | Keep; API shape can differ |
| Winning HTML context reporting | Present | Not exposed by compatibility detector | Keep; distinguish reporting from selecting a context |
| Caller-selected SQL quote/dialect | Hidden `internals` | Numeric visitor flags | Provide a small supported typed interface |
| Raw SQL tokenization and folding | Hidden `internals` | Public visitors | Support and test both operations |
| Fingerprint arbitrary selected context, including benign input | Hidden `State` | Private engine function | Expose a supported operation |
| Explicit-context XSS evaluation | Hidden `is_xss` | Private `is_xss` | Expose context selection; winning-context API is insufficient |
| HTML tokenization in five contexts | Hidden iterator | Public visitor | Retain supported byte spans and token kinds |
| Custom keyword/operator/fingerprint lookup | Absent | Absent | Implement C-equivalent customization within the one engine |
| State reset retaining lookup configuration | Current reset rebuilds fixed state | Internal state, fixed lookup | Specify and implement for the customizable parser |
| Parser counters | Raw token and two comment counters; no fold count | Four public visitor counters, more internal state | Preserve promised counters used by the parity protocol |
| Version/provenance information | Documentation and table comments | Manifest and notices | Publish clear tested upstream versions and exceptions |
| Optional byte-prefix limits | Present | Analysis budgets; compatibility takes supplied slice | Keep explicit prefix semantics without claiming suffix safety |
| Snapshots, constructs, confidence hints, owned evidence | Absent | Present in separate modern pipelines | Document as follow-up; remove active implementation now |
| C binary interface and generated include headers | Absent | Absent | Separate future integration, not required for the Rust replacement |

The complete C parser state also exposes dash-whitespace and block-comment
counters. Existing Rust public statistics and the current Go protocol are
not a complete mirror of that struct. Decide the supported statistics
contract explicitly. If these C counters are part of full capability
parity, add them while instrumenting the existing scanner, without retaining
a second parser or reproducing a C struct ABI.

## Findings requiring implementation

### Must fix before replacement

**F1. The newest C LIKE correction is missing in both Rust engines.**
YA `src/sqli/fold.rs:254` and reference
`src/sqli/legacy/fold.rs:321` turn LIKE followed by `(` into a function
without checking the preceding operand. This loses the new upstream attack
hit and produces the old fingerprint on `1 LIKE (SELECT 1)`.
Port the upstream operand guard into YA. Cover LIKE and NOT LIKE following
number, string, bareword, variable, and right parenthesis; retain controls
where LIKE really is function-like. Record the Go v0.3.5 disagreement by
exact input/result and source revision.

**F2. YA misses Go's NUL-normalized XSS names, values, and comment prefixes.**
`src/bytes.rs:34` automatically includes NUL in every C-style byte set.
`src/html5.rs:276,342` uses those sets for attribute names/unquoted values.
`src/xss.rs:184,196,287` checks raw SVG/XSL prefixes and takes a fixed-width
raw IMPORT/ENTITY prefix before removing NULs. The inputs above establish
actual lost Go hits.
For the chosen Go default, make HTML separator decisions explicit per state;
do not change the SQL byte-set helper globally. Normalize names and comment
prefixes before checking the relevant characters, while preserving the
raw-byte tests for IE conditional/XML prefixes. Retain the original input
and borrowed token spans. Add all missed direct cases as mandatory tests.

**F3. YA's C prefix rules differ from the selected Go negative controls.**
`src/xss.rs:208` permits event suffix prefixes and checks the first five raw
bytes of XMLNS/XLINK. Its indirect attribute branch accepts any recognized
attribute class. Go uses normalized exact event/namespace matching, a
64-byte normalized name limit, and only the Black class for indirect values.
Implement those selected rules using the existing tables. Include exact
XLINK, namespaced lookalikes, trailing event text, overlong names, and
indirect URL/style/Black controls. Preserve the C outcomes in the ledger.

**F4. YA's ASCII SQL keyword lookup loses current Go hits.**
`src/sqli/keywords.rs` hashes and compares ASCII uppercased bytes. Go
`searchKeyword` uses Unicode uppercasing. The U+0131/U+017F probes produce
real public verdict differences. Add Go-compatible normalization only where
the lookup and phrase-merge contract requires it, preserving original token
positions/bytes, invalid UTF-8 behavior, and the ASCII fast path. Reuse the
reference's tested mapping behavior; do not copy its whole SQL implementation.

**F5. Libperfusion cannot build as an isolated package.**
`build.rs:7` requires `../libinjection-rs/data/sqli_keywords.txt`.
`cargo package` reproduced a missing-file failure in its isolated verifier.
Its tests and two comparison benchmarks also depend on the sibling engine.
Make the survivor own its table input and all mandatory test assets before
removing either directory. An isolated package build is an acceptance gate.

**F6. Full C capabilities are not supported public APIs yet.**
The root API exposes six detection/metadata/limit functions. Tokenizers,
selected contexts, and state are hidden behind expressly unstable
`internals`; custom lookup is absent. Define the supported small API from
the capability table. Thread custom lookup through keyword/operator parsing,
phrase merging, and fingerprint checks, and retain it across reset/reparse.
Expose read-only token records: `internals::Token.len` is currently mutable
and `value()` slices a private buffer using that length. A caller can create
a panic by changing it. This is an API encapsulation issue, not a demonstrated
attacker-input panic through the current stable detectors.

**F7. The required gates are attached to the engine slated for removal.**
The Go parity workflow and fuzz workflow currently target `libinjection-rs`.
YA's `tests/repository_parity.rs` depends on that Rust engine and checks
fixture expectations only for the SQLi/XSS families. The Go differential
harness treats most fingerprint/parser mismatches as diagnostics.
Retain and retarget the existing infrastructure. Gate every field promised
by supported APIs and preserve exact reviewed exceptions. Restore the tiny
C oracle helper or replace it with one maintained development driver. Do
not replace independent upstream evidence with a sibling Rust comparison.

**F8. Workspace quality checks and provenance integration fail today.**
Clippy rejects `src/sqli/fold.rs::fill`; 19 Rust files fail the current
Apache-header-only checker. YA also lacks declared MSRV and repository
metadata. Resolve the small Clippy issue and establish file-appropriate
headers, notices, package metadata, and lint policy. Preserve BSD-derived
copyrights; adding an Apache-only header to everything is not a provenance
plan. The current Apache-labeled YA tests/benchmarks are excluded from its
package, so their presence alone does not prove its BSD package metadata is
wrong. Inspect the final distributed files before choosing its SPDX expression.

### Should fix during consolidation

**F9. Table updates have conflicting and incomplete paths.**
YA `tools/gen_tables.py` overwrites `src/sqli/keyword_table.rs` with static
literals while `build.rs` generates an OUT_DIR table from the sibling's data.
`tools/vendor_upstream.sh` can reintroduce large C/testdata directories.
The existing `xtask corpus-refresh` refreshes Go fixtures/SQL expected outputs
but preserves the older `differential` section and does not port algorithms
or update every table. Consolidate on one canonical table input and the
existing xtask/Go module process. A dependency bump must trigger source/table
review; metadata refresh cannot establish algorithm parity on its own.

**F10. Both sets of documentation contain outdated statements.**
YA README still says FF ends its tokenizer despite its regression fix,
says only two functions are public despite six exports, and says token
offsets need adding despite `Token.pos` already existing. The old comparison
document describes older revisions and is explicitly static-only.
The reference README includes a modern `intersects` example using a raw flag
where a wrapped `ConstructFlags` is needed. Rewrite the survivor's README
around actual compatibility behavior and archive useful future requirements
here; remove obsolete comparison/plan material after its useful content is
preserved. Keep the current benchmark report and regression explanations.

## Security, performance, and maintenance assessment

Both compatibility engines scan caller-provided bytes. Neither implements
universal application, browser, or database decoding. The reference modern
analyzers are separate pipelines; their richer construct hints do not change
its compatibility SQL detector. Reusing those hints as a replacement verdict
would change the product contract.

Every handwritten Rust parser/detector source file was reviewed for cursor
progress, state transitions, buffer bounds, quote handling, folding, and
entity arithmetic. No additional stable-public attacker-input panic,
unsafe memory operation, or superlinear path was established. That is an
inspection and test result, not a proof for all byte sequences. Keep fuzz
deadlines: callback-count progress assertions cannot interrupt a loop that
never emits a callback.

YA uses fixed token/fingerprint buffers, borrowed HTML spans, `no_std`, and
no allocator in its detector paths. Its table lookup uses a static hash
index with a compile-time probe-run bound. The reference uses more defensive
accessor/overflow-sink machinery and also carries an owned modern analysis
system. Source inventory is 8,105 Rust lines in the reference's `src` versus
3,551 in YA's `src`; these are different scopes, not a quality score.
Deleting the old engine saves its source burden while preserving test assets.
The surviving engine will still need small adapters and parity corrections.

The existing benchmark report covers actual detection calls, corpus inputs,
multiple input shapes, early/late hits, and sizes up to 10 MiB. CPU frequency
was not locked and the comparisons are a single-process measurement. Preserve
its history and workloads; do not infer deployment throughput or choose an
engine from one winning row. No new timed benchmark sweep was run for this
assessment.

The previously deferred binary-noise optimization stays deferred. Its
2.39 ms YA versus 0.249 ms reference measurement at 1 MiB is associated with
many NUL-delimited attribute tokens. The selected Go NUL handling is required
for compatibility independently of that timing; changing it may incidentally
affect the benchmark. Do not add a separate binary-specific shortcut now.

Known shared limitations remain outside this compatibility migration:

- `j&#9;avascript:`, `j&#13;avascript:`, and `j&Tab;avascript:` URL probes
  were missed by both upstreams and both Rust implementations.
- Executable MariaDB comments are not parsed as executable SQL by the
  compatibility lexers. The tested `1 /*M!50000 UNION SELECT 1*/` input was
  nevertheless flagged as `1c`; do not misreport that probe as a public miss.
- Optional prefix-limit calls intentionally omit the suffix. Their miss
  result is not a verdict on the complete original input.

Browser/database hardening can be a later explicit mode with its own
false-positive review. Allocation avoidance remains a development/review
goal, consistent with repository guidance; do not introduce a `no_alloc`
promise or allocation-counter test as part of this migration.

## Implementation plan for subsequent agents

### Final repository layout

Use `libinjection-rs/` as the surviving directory and name its package
`libperfusion`. Replace its `src` with the selected YA engine after preparing
the gates. This retains the existing corpus/tools/fuzz paths and minimizes
changes to CI and xtask. Remove `ya-libinjection-rs/` once its engine,
benchmarks, useful tests, notices, and report have moved.

The resulting workspace contains one detector crate and xtask:

```text
Cargo.toml                      # libinjection-rs + xtask
libinjection-rs/
  Cargo.toml                    # package = libperfusion
  src/                          # one lexer/folder/HTML detector implementation
  data/                         # one canonical SQL lookup source
  tests/corpus/                 # existing immutable Go fixture corpus
  tests/parity/                 # manifest, expected outputs, mismatch ledger
  tests/common/                 # one parser/formatter/subprocess toolkit
  tests/                        # compatibility, progress, oracle regressions
  fuzz/                         # existing three targets and grammar tests
  tools/parity/                 # independent Go and C development drivers
  tools/fuzz/                   # existing artifact promotion tool
  benches/                      # retained compare/scaling/speed workloads
  docs/                         # retained operating guides and benchmark report
  LICENSES/                     # preserved license texts and provenance
xtask/
  src/                          # one integrity/refresh/header toolchain
  tools/go.mod                  # Go version controlled by Dependabot
```

Changing the package name is deliberate; user-facing APIs may also change.
Do not add an old-name facade crate or duplicate detector API solely for
name compatibility. Add an adapter only if a real caller requires it.

### Ordered work and acceptance criteria

Each step can be a focused commit. Later steps depend on the earlier gates.
Implementation agents should reference finding IDs rather than rediscovering
the decision. Each step includes the tests required for its actual changes.

**M1. Fix the compatibility contract and expected cases first.**

- Record the two C SHAs, Go version/checksum, default policy, and exact
  exceptions in the existing parity manifest/ledger and protocol.
- Add the reproduced F1-F4 and bare-XLINK cases to independent oracle inputs.
  Store arbitrary bytes as hex. Keep the original Go corpus bytes unchanged.
  New C fixtures may collide by filename with Go fixtures; add separate
  revision-labeled C regressions instead of overwriting the Go inventory.
- Gate exact public fingerprints, token fields, supported statistics,
  folded output, and five-context HTML output. An exception must identify
  input bytes, field/mode, upstream result, selected result, version, and why.
  Do not replace exact comparisons with an unrestricted superset-hit rule.

Acceptance: the new tests visibly expose the current failures; all known
differences have explicit expected outcomes. The 843/770 inventories remain
present, with new cases added deliberately rather than silently skipped.

**M2. Correct the selected engine using the existing module boundaries.**

- Port the small current-C LIKE/NOT LIKE operand guard to YA's folder.
- Implement selected Go HTML NUL/name/value/comment behavior in
  `html5.rs` and `xss.rs`; avoid global edits to C-style SQL byte sets.
- Implement exact normalized attribute/event policy and bounded normalized
  tag behavior. Preserve exact XLINK, unlike the reference's stale test.
- Implement Go-compatible SQL keyword/phrase casing with an ASCII fast path.
- Preserve FF handling, numeric-comment offset corrections, quote escape
  parity, and existing HTML short-match fast paths unless a test disproves
  their compatibility. Port algorithm behavior, not defensive boilerplate.

Acceptance: selected-oracle gates pass for the complete retained inventories
and new cases. The LIKE attack is detected with `s&(1o`; Go misses introduced
by choosing older C quirks are not accepted. Any fingerprint/token changes
are reviewed explicitly. Repeat the existing benchmark workloads after the
functional changes and update only the simple historical comparison columns.

**M3. Provide the missing supported C-equivalent Rust capabilities.**

- Define typed quote/dialect/context selection and safe read-only token
  records. Reuse the current lexer/folder/HTML tokenizer.
- Support raw SQL iteration, folding, per-context fingerprints even on
  misses, fingerprint classification, HTML iteration, and explicit-context
  XSS checks. Winning-context reporting alone does not meet this requirement.
- Add custom lookup with separate word/operator and fingerprint decisions.
  Ensure lexer, phrase folding, every detector reparse, and reset use it.
- Expose required counters, including fold counts, without fabricated
  values. Document any C-only debug metadata intentionally omitted.
- Stabilize only that surface; remove or narrow the blanket `internals`
  exposure when its test consumers can use the supported APIs.

Acceptance: all six SQL configurations and five HTML contexts have meaningful
behavior tests. Custom lookup demonstrably changes keyword and fingerprint
decisions and survives reset/reparse. Users cannot create invalid token
buffer lengths through the new API. Default detector behavior remains gated.

**M4. Make the package self-contained and unify updates.**

- Make the canonical SQL input local to the survivor. Generate its one
  runtime table deterministically; retain table count/order/type assertions.
- Bring event/tag/attribute generation and semantic hash checking into the
  existing xtask process or one shared generator it invokes. Do not retain
  two scripts that write different forms of the same module.
- Keep `xtask/tools/go.mod` and Go checksums as the Go source of truth.
  Dependabot bumps that module; refresh then reviews changed algorithms,
  tables, corpus, source hashes, and exceptions. A fixture refresh is not
  an automatic port of upstream code.
- Keep a reproducible C revision for the external test oracle in the same
  provenance system. Fetch it into ignored build/temporary storage; do not
  vendor the large C tree/sample datasets into the production repository.
- Remove YA's conflicting `gen_tables.py`/`vendor_upstream.sh` only after
  their necessary table/source checks have a maintained home.

Acceptance: an isolated package builds without sibling files, C compiler,
Go toolchain, network access, or fixture downloads once Rust dependencies
are available. Corpus and table refresh/check are deterministic and version
disagreements fail. A Go dependency bump cannot bless changed behavior by
merely updating expected outputs.

**M5. Migrate the evidence and CI onto the single package.**

- Keep all 496 Go fixtures, integrity hashes, `sqli_oracle.tsv`, corpus
  parser/formatters, and all five fixture-family assertions.
- Port the reference's compatibility unit regressions before deleting their
  source modules, especially escaped/doubled quotes, Unicode phrase merging,
  NUL cases, statistics boundaries, late hits, and all deny-list classes.
- Retain `detection_api`, `oracle_differential`, `generated_differential`,
  `property_progress`, and `fuzz_regressions` test purposes and input sets.
  Adapt result types instead of retaining the old engine as an oracle.
- Keep the three fuzz targets, raw/SQL/HTML grammars, separator-reachability
  test, regression manifest, artifact promotion, process timeouts, and uploads.
  Drop snapshot calls/assertions from those shared paths only when they test
  the deferred API, while preserving parser span/progress and verdict checks.
- Keep every existing CI job: lint/meta-lint, tests, feature matrix, parity,
  fuzz, coverage, MSRV, supply-chain, and zizmor. Update package selectors
  and features. Existing directory-based paths can largely stay unchanged.
- Keep coverage thresholds. Revisit the obsolete legacy-path exclusions for
  the new module layout; do not add a blanket exclusion of the survivor.
- Restore the small C oracle helper and make targeted C checks a maintained
  part of parity CI. Keep large optional C sample/fuzz runs reproducible.
- Preserve the useful manifest JSON: it enforces provenance and integrity.
  Delete only obsolete generated reports/duplicates, not required fixtures.

Acceptance: the survivor runs the retained corpus, regression, progress,
and external parity checks; the old engine is not required for expected
answers. Snapshot-only tests can be retired with their purpose recorded in
the follow-up section. No compatibility case or CI job is dropped silently.

**M6. Preserve benchmarks while removing their sibling dependency.**

- Keep all existing corpus/shape/size workloads in `compare`, `scaling`,
  and `speed`, including escaped quotes, NUL/high bytes, slash/angle noise,
  late URL hits, benign streams, and prose/JSON/base64 misses.
- Keep the benchmark report's original YA, original libinjection-rs, and
  final optimized YA columns. Those original results are historical assets;
  they do not require shipping a second Rust engine.
- Retarget the executable comparison to an external C development driver
  or another independent upstream oracle. Time loops inside each detector
  process; do not compare in-process Rust calls to one subprocess per call.
- Keep the ordinary survivor benchmark usable without upstream downloads;
  make the external comparison's requirements explicit. Fix the misleading
  blanket README statement that every benchmark needs a C checkout.

Acceptance: all workload names and expected outcomes remain represented,
the shared workloads run against the survivor, and optional upstream
comparison reports honest timing boundaries. The removed Rust crate is
absent from dev-dependencies.

**M7. Resolve packaging, headers, lints, and current documentation.**

- Declare tested MSRV/repository metadata and the selected lint policy.
  Fix `fold::fill` with the smallest local change. Do not use global lint
  suppression as the migration's acceptance criterion.
- Preserve C, Go fixture, and port author notices. Classify imported BSD
  material and project Apache material accurately; adapt the header checker
  to accepted file-specific provenance. Generated files need a generated
  marker and origin, not manual edits lost on regeneration.
- Select the package license expression from the actual packaged contents.
  Keep upstream BSD texts and relevant Apache text/notices wherever required.
- Rewrite README/version/refresh/API documentation for the final package.
  Explain raw bytes, Go/C differences, prefix limits, external oracle tools,
  and no_std support that is actually maintained.

Acceptance: lint, doc, tests, audit, coverage, feature/MSRV checks, and isolated
package verification pass. The documented examples use the actual API.
The license checker passes without falsely relabeling third-party code.

**M8. Delete the old product only after the migration gates pass.**

- Replace `libinjection-rs/src` with the selected engine and remove the old
  legacy SQL/XSS implementation, modern analyzers, engine normalization,
  snapshot/options/policy machinery, and the old generator build script.
- Bring YA's retained tests, benchmarks, report, license notices, and engine
  into the survivor; remove the second workspace member and dev-dependency.
- Remove the obsolete `legacy` feature when there is no optional second
  product to gate. Update Makefile `-p libinjection` selectors to libperfusion.
- Merge duplicate corpus/test helpers and remove obsolete comparison/plan
  docs after checking that the useful findings are covered here or by tests.
- Recheck `.coderabbit.yaml`, `_typos.toml`, coverage paths, fixture tools,
  README links, workflow working directories, and xtask help messages.

Acceptance: the workspace has exactly one detector implementation, all tests
and CI use it, package verification passes, and repository searches reveal
no live dependency on `ya-libinjection-rs` or the retired modern/legacy split.
Historical benchmark labels and assessment references may retain old names.

## Useful follow-ups from libinjection-rs

Preserve these requirements and lessons in documentation rather than leaving
the retired implementation dormant. None should block the compatibility
release except features already required by the capability table.

| Future capability | Useful existing work | Requirements before reintroducing it |
| --- | --- | --- |
| Evidence spans | Original-input ranges, deduplication, complete evidence sets | Preserve source extent separately from truncated token value; test encoded/NUL mappings and offsets beyond 64 KiB |
| Bounded result with status | `TRUNCATED`, `PREFILTER_MISS`, multiple-context metadata | Make incomplete scanning explicit; a prefix miss cannot authorize the omitted suffix |
| Construct descriptions | SQL/XSS flag vocabulary | Build descriptions over the one scanner where possible; specify which flags are observations versus detections |
| Verdict hints | Benign/Suspicious/Decisive/Inconclusive vocabulary | Evaluate consumer meaning and false positives; do not substitute hints for compatibility booleans |
| Optional normalization for analysis | Borrow unchanged input, normalize once, map back to original bytes | Keep this outside raw compatibility detection; define URL/entity decoding layers for the actual sink |
| Policy integration | Construct masks and descriptive contexts | Establish a real Coraza consumer and its enforcement rules before adding generalized policy machinery |
| Rich run metadata | Quote mode, dialect, contexts tried, scan budget | Report facts from actual detection passes; inferred analyzer contexts are not interchangeable |
| Additional performance work | Merged quote search, cached password-marker lookup, sorted deny lookup | Reuse only missing improvements justified by measurements; keep best-effort allocation review |
| Browser/database hardening | Shared URL/control/entity and executable-comment limitations | Separate intended upstream deviations from bugs; use meaningful positive and benign controls |
| C ABI packaging | Neither current crate provides it | Add symbols, headers, error/ownership contracts and C integration tests only when required |

The snapshot layer currently owns vectors and the modern analyzer is not
the same detector as the compatibility engine. Do not promise a fixed-size
snapshot, fixed allocation budget, or caller safety decision based on the
old API name alone. The existing descriptive analysis examples need review
before becoming a next-version design.

The deferred binary-noise optimization belongs to this backlog. Any NUL
behavior changes in M2 are correctness/compatibility work, with separate
performance measurements afterward.

## Review coverage and limits

The assessment used parallel Rust source reviews and an independent
verification pass. Every handwritten Rust file in both implementation
directories was read, including embedded tests, integration tests, build
scripts, fuzz targets, and benchmark code. Root review covered their shared
CI/configuration, corpus/refresh/provenance tooling, and independent sources.

| Area | Read scope |
| --- | --- |
| YA core | `lib.rs`, `bytes.rs`, `html5.rs`, `sqli.rs`, `xss.rs` |
| YA SQL internals | `sqli/fold.rs`, `keywords.rs`, `lexer.rs`, `token.rs` |
| YA integration/build | `build.rs`, all seven integration/common test files, all three Rust benchmarks and C speed helper, table/vendor scripts |
| Reference compatibility SQL | Every file under `src/sqli/legacy` |
| Reference compatibility XSS | Every file under `src/xss/legacy`, including deny tables and embedded regressions |
| Reference optional analysis | Every file under `src/engine`, `src/sqli/modern`, `src/xss/modern`, plus root API, limits/options/policy/snapshot/modules |
| Reference tests/fuzz | Every Rust file under `tests` and `fuzz`, including common subprocess helpers |
| Shared integration | Workspace/crate manifests, Makefile, workflow/action files, Dependabot, review/typo configuration, license checker, corpus refresh/check, parity/fuzz tools and operating docs |

YA has 20 handwritten Rust files plus two generated table/wrapper files.
The reference review covered 47 Rust files, including build and fuzz code.
Generated SQL/event tables were checked through their construction invariants
and all five exact upstream table tests; no manual semantic review of each
of the 9,352 SQL entries is claimed. The 496 corpus payloads were exercised
and integrity-checked, not interpreted manually one by one.

No implementation changes, production test additions, CI edits, dependency
bumps, commits, or new timed benchmarks were made for this assessment.
Scratch oracle drivers and logs were kept outside the repository. The
normal exact-C differential harness remains broken until its helper is
restored; the independent C public-driver checks do not substitute for its
full six-mode SQL and five-context randomized parser comparisons.

Coverage/audit/sanitizer/Miri campaigns, browser/database execution of
payloads, ARM/unsigned-char behavior, concurrency, and deployment load were
not newly run. Existing historical results are supporting material only.
Passing the listed cases is evidence for the recommendation and migration
plan, not a guarantee of safety on all future inputs.
