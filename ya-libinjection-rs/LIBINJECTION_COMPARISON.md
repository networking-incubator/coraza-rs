# libperfusion and Coraza libinjection: comparative source audit

Date: 2026-10-09. Scope: feature parity, security, detection gaps, static performance, complexity, and opportunities to exchange improvements.

## 1. Snapshot and method

This audit was restarted from scratch after the requested rebase. It describes these checkouts:

| Label used below | Checkout | Revision |
|---|---|---|
| Current | `ya-libinjection-rs`, crate `libperfusion` | `544914a9d114cdf68c64c9321a9406e4d6acdbdd` |
| Coraza | `../coraza-rs/libinjection-rs`, crate `libinjection` in its parent workspace | `c96d18052b49aedfeb4cc48a1470f8532a4c3bf4` |

Production paths were mapped and read: public APIs; SQL lexers, folders, lookups, and whitelist decisions; HTML tokenizers and XSS classifiers; Coraza's prefilters, normalization, construct classifiers, evidence mapping, budgets, and verdict hints. Manifests, table generation, and documentation were compared. A 48-file source hash inventory was captured at the beginning and checked again before completion. The current tracked checkout was clean; unrelated untracked files in the Coraza parent workspace were excluded.

**No tests, detector executions, browser probes, fuzzing, benchmarks, or implementation changes were performed.** Table comparisons, source metrics, and hashing are static analysis. Every concrete verdict below is a prediction from source control flow, not a runtime reproduction. Browser and database validity is supported by primary specifications. No detection-rate, false-positive-rate, or throughput percentage is claimed.

Priority means:

- **Must fix:** concrete detection gap or integration contract likely to produce unsafe enforcement assumptions.
- **Should fix:** coverage, precision, resource, or maintenance issue with a stated condition.
- **Optional:** useful optimization or API improvement whose value depends on consumers or measurements.

## 2. Main conclusions

1. **The compatibility algorithms have substantial parity, but are not behaviorally identical.** Their SQL tables contain the same 9,352 key/type pairs, including 8,367 fingerprints. Their XSS event tables contain the same 432 distinct event suffixes. Differences come from parser, comparison, whitelist, and context behavior.
2. **Coraza contains two different products.** `detect_sqli` and `detect_xss` directly use compatibility backends. `analyze_sqli` and `analyze_xss` produce descriptive constructs and hints through separate pipelines. Modern SQL findings do not automatically improve `detect_sqli`.
3. **Both have concrete shared false negatives.** Browser-valid JavaScript URLs containing certain internal character references are missed. Numeric MySQL injection can be suppressed by compatibility whitelist rules. MariaDB executable comments are not recognized as executable by either compatibility SQL lexer.
4. **Current preserves two inherited behaviors that Coraza improves:** the leading-whitespace numeric-comment offset error, and HTML byte `0xFF` behaving as EOF. These can produce valid injection misses under the conditions documented below.
5. **Current has the smaller operational footprint:** dependency-free, `no_std`, no heap allocation in its detector pipelines, and fixed working state. Coraza offers richer analysis, public token visitors, status flags, and evidence, with input-proportional heap storage in its analyzer.
6. **The rebased Coraza source removes the earlier stacked-query rescan concern.** It searches from the first semicolon and uses binary search for token containment. The inspected modern SQL pipeline has an approximately `O(b log(b + 1))` upper bound under ordinary evidence mapping, rather than the previously suspected quadratic path.
7. **Neither API establishes that arbitrary input is safe to execute.** These are fragment heuristics with finite fingerprints, selected contexts, and application-dependent decoding. Several Coraza `Decisive` hints also arise from harmless syntax.

## 3. Feature and contract parity

Sources: current [public API](src/lib.rs), [SQL detector](src/sqli.rs), [XSS detector](src/xss.rs); Coraza [public API](../coraza-rs/libinjection-rs/src/lib.rs), [options](../coraza-rs/libinjection-rs/src/options.rs), [snapshot](../coraza-rs/libinjection-rs/src/snapshot.rs).

| Capability | Current | Coraza | Consequence |
|---|---|---|---|
| SQL compatibility detection | `sqli -> Option<Fingerprint>` | `detect_sqli -> SqliDetection` | Both report a fingerprint on a match; Coraza's miss returns an empty fingerprint. |
| XSS compatibility detection | `xss -> bool` | `detect_xss -> bool` | Similar purpose; differences below prevent exact substitution. |
| Winning SQL dialect | `sqli_with_dialect` | No equivalent in compatibility result | Coraza's analysis dialect describes its own inference. |
| Winning HTML context | `xss_with_context` | No equivalent in compatibility result | Analyzer context is not a record of the compatibility winning pass. |
| Caller-selected prefix | `sqli_with_limit`, `xss_with_limit` | `analyze_*_with`; compatibility calls consume the supplied slice | Current limit calls silently omit the suffix in their return types. |
| Partial-analysis status | No result flag | `TRUNCATED`, `PREFILTER_MISS`, `MULTI_CONTEXT` | Coraza makes incomplete analysis visible. |
| Construct classification | No modern construct layer | SQL/XSS construct bitsets | More descriptive information, with different detection semantics. |
| Evidence | No stable public evidence result | Original-input `EvidenceSpan` vector | Useful for logging and rule integration, with allocation cost. |
| Token and fold inspection | Unstable `internals` feature | Public `sqli_tokenize_visit`, `sqli_fold_visit`, `html5_visit` under `legacy` | Coraza has a supported inspection surface; SQL visitor flags are numeric and would benefit from public typed constants. |
| SQL contexts | Raw ANSI, conditional MySQL; single-quoted ANSI/conditional MySQL; double-quoted MySQL | Comparable compatibility strategy | At most five compatibility passes; neither represents every database grammar/configuration. |
| HTML contexts | Data, unquoted, single quote, double quote, backtick | Same compatibility context family, with candidate gating | Context coverage is fragment-oriented. |
| Decoding | Caller supplies decoded bytes | Compatibility also uses original supplied bytes; analyzer lowercases ASCII, strips NUL, decodes one `%HH` layer | Analyzer normalization is not a universal request/browser decoder. |
| Default scan budget | Full supplied slice; optional limits | Analyzer defaults to 8,192 bytes | Limits are raw byte cuts, not token boundaries. |
| Maximum configured budget | Caller chooses a `usize` | Caller chooses a `usize`; no internal hard clamp | Coraza's documented 64 KiB hard cap does not exist in this revision. |
| Runtime environment | `no_std`, forbids unsafe code, no runtime dependencies | Uses `std`, `Vec`, `Cow`, `HashSet`, and `memchr` | Different embedding and resource requirements. |
| Feature controls | `internals` exposes unstable details | Default `legacy`; disabling it removes compatibility APIs and SQL visitor surface | Modern XSS still compiles its compatibility fallback. |
| Distribution | Standalone edition-2024 crate | Workspace-inherited version, edition, Rust version, repository/lints; build-time generated tables | Packaging and minimum-version assumptions differ. |
| License metadata | BSD-3-Clause | Apache-2.0 AND BSD-3-Clause | Preserve relevant notices when exchanging code. |

### Actual Coraza call paths

```text
detect_sqli -> legacy SQL detection -> bool + fingerprint
detect_xss  -> legacy XSS detection -> bool

analyze_sqli -> selected prefix -> prefilter -> normalization
             -> token ranges -> modern SQL constructs/evidence -> hint

analyze_xss  -> selected prefix -> prefilter -> normalization
             -> inferred context + Data classification -> merge
             -> legacy XSS fallback on original bytes if no XSS construct
             -> constructs/evidence -> hint
```

These paths are visible at Coraza `src/lib.rs:46`, `63`, `80`, `100`, and `src/xss/modern/classify.rs:59`. There is no modern SQL fallback to the compatibility detector. The XSS fallback executes once after context results merge in this revision.

### Table parity does not imply parser parity

The static comparison matched every current [SQL table](src/sqli/keyword_table.rs) entry with Coraza [SQL data](../coraza-rs/libinjection-rs/data/sqli_keywords.txt), including type values. The other 985 entries are keywords/operators rather than fingerprints. Current's generated header references C libinjection `v4.0.0-8-gd88a8f8`; Coraza's data header references its Go-port provenance. Those origins do not prove identical runtime behavior.

The [current events](src/xss/events.rs) and [Coraza deny lists](../coraza-rs/libinjection-rs/src/xss/legacy/deny_list.rs) have identical 432-event sets. Current matches a recognized event suffix as a prefix; Coraza uses exact matching. Coraza SQL lookup also maps UTF-8 dotless i and long s to ASCII I/S, whereas current follows ASCII/C-oriented lookup semantics. That difference alone is not a demonstrated SQL bypass: the downstream database or application must perform the corresponding normalization.

## 4. Concrete misses and security findings

### F1. Shared dangerous-URL normalization gap — must fix for browser-oriented detection

Examples:

```html
<a href="j&#9;avascript:alert(1)">open</a>
<a href="j&#13;avascript:alert(1)">open</a>
<a href="j&Tab;avascript:alert(1)">open</a>
<a href="j&NewLine;avascript:alert(1)">open</a>
```

A literal TAB after the initial `j` inside the quoted attribute is another variant.

**Predicted result:** current `xss == false`; Coraza `detect_xss == false`; Coraza `analyze_xss` has no XSS construct and a `Benign` hint for these short examples.

**Trace:** current `src/xss.rs:90` decodes numeric references only; its prefix loop at `129` skips internal NUL/LF at `142`, but not TAB/CR. After matching J, the next decoded byte fails against A. Named references remain literal ampersand text. Coraza `src/xss/legacy/deny.rs:160`, `179`, `202` has the same decisions. Modern normalization does not resolve HTML references or remove internal TAB/CR; modern URL classification needs contiguous `javascript:`. Its original-byte fallback inherits the same miss.

**Valid sink:** HTML resolves the references; the URL parser removes ASCII TAB/LF/CR, yielding a JavaScript scheme. Activating the link can evaluate code when the surrounding document permits it. This does not claim automatic execution on insertion or a CSP bypass. See [HTML character references](https://html.spec.whatwg.org/multipage/parsing.html#named-character-reference-state), [named reference values](https://html.spec.whatwg.org/multipage/named-characters.html#named-character-references), [URL preprocessing](https://url.spec.whatwg.org/#concept-basic-url-parser), [ASCII tab or newline](https://infra.spec.whatwg.org/#ascii-tab-or-newline), and [JavaScript navigation](https://html.spec.whatwg.org/multipage/browsing-the-web.html#javascript-protocol).

**Improvement for both:** normalize URL attribute values according to browser rules, including relevant named references and internal TAB/LF/CR. Preserve source offsets and explicitly record divergence from a pinned compatibility oracle. Arbitrarily deleting internal spaces would introduce incorrect semantics. `javascript&colon;...` is already caught by the broad `JAVA` prefix and is not a bypass example.

### F2. Current numeric-comment check uses length as an absolute offset — must fix

```rust
b"\t1--"
```

**Predicted result:** current SQL misses; Coraza compatibility SQL detects.

**Trace:** both obtain number/comment fingerprint `1c` with two tokens. The number starts at offset 1 and has length 1. Current `src/sqli.rs:230` reads `input[token.len]`, which is the digit at offset 1, and rejects the match. Coraza `src/sqli/legacy/detect.rs:144–156` reads `token.pos + token.len`, sees `--`, and confirms it. No quote or differing-comment reparse rescues current's input.

**Valid sink:** concatenate into `SELECT ... WHERE id = <input> AND enabled = 1`. The trusted suffix begins with a space, so the assembled `-- AND ...` also meets MySQL's whitespace requirement and removes the restriction. See [MySQL comments](https://dev.mysql.com/doc/refman/8.4/en/comments.html).

**Improvement current can take from Coraza:** include the token's start position. Token lengths can represent capped token text or folded values, so any broader evidence API should distinguish original source extent from stored token-value length. The position already exists in current `src/sqli/token.rs:60`; adding a new offset field is unnecessary.

### F3. Current HTML treats byte FF as EOF — must fix where such bytes reach scanning

```rust
b"<img \xff onerror=alert(1)>"
```

**Predicted result:** current XSS misses; Coraza compatibility XSS detects; Coraza modern analysis recognizes the event.

**Trace:** current `src/html5.rs:105–113` returns `None` for `0xFF` while advancing before an attribute name. Parsing ends before the separated `onerror`; quote contexts do not rescue this quote-free fragment. Coraza `src/xss/legacy/mod.rs:842`, `854` keeps bytes unsigned and proceeds past the irrelevant attribute to the event handler. Its modern `onerror=` classifier also matches.

**Valid sink condition:** ordinary UTF-8 replacement decoding converts FF to U+FFFD, rather than EOF. The subsequent ASCII space still separates the event handler. A suitable single-byte document encoding also avoids this EOF interpretation. An application that rejects invalid UTF-8 or transcodes before scanning removes this exact raw-byte path. See [UTF-8 decoding](https://encoding.spec.whatwg.org/#utf-8-decoder) and [HTML attribute-name parsing](https://html.spec.whatwg.org/multipage/parsing.html#before-attribute-name-state).

Current's README already acknowledges this compatibility limitation. **Improvement:** distinguish EOF from every valid `u8`, borrowing Coraza's unsigned-byte approach. Make any change to upstream-parity policy explicit.

### F4. Shared three-token suppression misses numeric Boolean SQLi — should fix with explicit policy

```sql
1 OR 1
```

**Predicted result:** both compatibility SQL detectors miss; Coraza modern SQL returns no SQL construct and `Benign`.

**Trace:** compatibility tokenization produces `1&1`. Current `src/sqli.rs:253–256` and Coraza `src/sqli/legacy/detect.rs:186–194` suppress this fingerprint when exactly three tokens were read. Modern tautology patterns at `src/sqli/modern/classify.rs:85` do not include OR followed by a truthy number. Boolean detection at `203` requires nearby `=` or `like`; numeric comparison classification also has no comparison to recognize.

**Valid sink:** `SELECT ... WHERE id = <input>` becomes `(id = 1) OR 1`, true in MySQL. Nonzero numeric operands are truthy and comparisons bind before OR. See [MySQL logical operators](https://dev.mysql.com/doc/refman/8.4/en/logical-operators.html) and [operator precedence](https://dev.mysql.com/doc/refman/8.4/en/operator-precedence.html).

This is an intentional precision tradeoff in the compatibility whitelist, but remains a valid false negative at a numeric SQL sink. **Improvement:** add numeric-sink-aware Boolean classification or an explicit stricter policy. Simply removing the suppression globally can flag ordinary text/numbers; describe that tradeoff to callers.

### F5. Shared hash-comment suppression misses MySQL suffix removal — should fix with explicit dialect policy

```sql
1#
```

**Predicted result:** both compatibility detectors miss. Coraza modern analysis flags `SQL_COMMENT_INJECTION` and gives a `Decisive` hint.

**Trace:** hash syntax requests a MySQL reparse. The MySQL number/comment fingerprint is then unconditionally suppressed when comment text starts with `#`: current `src/sqli.rs:197–199`, Coraza `src/sqli/legacy/detect.rs:123–125`. Modern comment classification at `src/sqli/modern/classify.rs:153` has no corresponding suppression.

**Valid sink:** `SELECT ... WHERE id = 1# AND enabled = 1` comments out the remaining line under [MySQL's hash-comment syntax](https://dev.mysql.com/doc/refman/8.4/en/comments.html).

**Improvement:** permit a dialect/sink-specific strict policy. Coraza can reuse its modern finding as an additional signal only through an explicitly composed enforcement path; its current `detect_sqli` does not consume that finding.

### F6. Shared MariaDB executable-comment omission — must fix when protecting MariaDB

```sql
/*M! 1 OR 1 */
```

**Predicted result:** both compatibility SQL detectors miss; Coraza modern analysis flags a SQL comment and returns `Decisive`.

**Trace:** current `src/sqli/lexer.rs:239–264` treats a comment as executable/evil only when its body starts with `!`, or when a nested opener is found. Coraza `src/sqli/legacy/parse.rs:138–163` delegates to `helpers.rs:71`, also checking only the byte immediately after `/*` for `!`. The M-prefixed body is an ordinary comment. Both folders discard initial comments; a comment-only input has no fingerprint. The recognized `/*!...*/` form is already handled and is not the missing case.

**Valid sink:** on MariaDB, `SELECT ... WHERE id = /*M! 1 OR 1 */` executes the comment body and produces a truthy OR expression. MariaDB documents this executable syntax without a mandatory version number. No statement delimiter is placed inside the example. See [MariaDB executable comments](https://mariadb.com/docs/server/reference/sql-statements/comment-syntax).

**Improvement for both:** recognize `/*M!` as executable syntax in compatibility lexing or expose a deliberate hardened dialect mode. Coraza should additionally distinguish executable comments from ordinary comments in its construct/dialect reporting. Its generic modern comment flag catches this fragment but does not repair its compatibility API.

### F7. Modern SQL Boolean classification can downgrade an attack caught by compatibility — should fix

```sql
1 OR 2>1
```

**Predicted result:** both compatibility detectors detect; Coraza modern analysis reports `SQL_NUMERIC_INJECTION` with a `Suspicious` hint rather than `Decisive`.

**Trace:** compatibility folding reduces the numeric comparison to a number, yielding `1&1`, but five source tokens bypass the three-token suppression. Modern `has_comparison_near` at `src/sqli/modern/classify.rs:273` only recognizes `=` or `like`, so `>` does not establish Boolean injection. Its numeric scanner recognizes `2>1`, but `src/policy.rs:20` omits `SQL_NUMERIC_INJECTION` from the decisive mask.

**Condition:** this becomes a miss if an integrator treats only `Decisive` analysis as blocking and replaces compatibility detection. The documented analysis contract makes hints descriptive; this is not a claim that `detect_sqli` misses this payload.

**Improvement Coraza can take from compatibility:** recognize the full comparison family in Boolean context and compose semantic evidence. Promoting every numeric comparison to decisive would reject benign mathematical text. The same numeric sink and operator semantics as F4 apply.

### F8. Modern XSS fallback ignores its normalized view — should fix when decoding coverage is intended

```text
%3Cdetails%20open%20ontoggle%3Dalert(1)%3E
```

Normalized form:

```html
<details open ontoggle=alert(1)>
```

**Predicted result:** Coraza modern analysis misses the encoded form and gives `Benign`, but recognizes the decoded form via the compatibility fallback. Both compatibility APIs expect their caller to decode percent encoding; missing the raw encoded text is consistent with that contract.

**Trace:** modern normalization creates the decoded fragment. The eight names in `src/xss/modern/classify.rs:159` exclude `ontoggle`, and its narrow tag set does not independently reject `details`. The fallback at line 59 scans only original bytes, which contain no literal tag or handler. The 432-event compatibility list recognizes the decoded version.

**Valid sink condition:** the application percent-decodes the input and inserts the decoded HTML, allowing the details toggle handler to run. A browser receiving the original percent text as HTML does not execute it. See [details toggle behavior](https://html.spec.whatwg.org/multipage/interactive-elements.html#the-details-element).

**Improvement:** evaluate the normalized view through the fallback as well, retaining original evidence coordinates and recording which view produced the match. Decide explicitly whether application decoding semantics justify NUL stripping and each decoding layer. Do not silently expand decoding indefinitely.

### F9. Prefix cuts can conceal valid suffixes — must address in enforcement integration

Current limit APIs scan exactly `input[..min(max_bytes, input.len())]`. For example, a limit ending before a trailing `<script>` gives the same Boolean result as the harmless prefix, with no indication that bytes were omitted. This is the advertised prefix contract, not an implementation error; treating the result as approval of the whole field creates the security gap.

Coraza's analyzer exposes `TRUNCATED`. `src/engine/verdict.rs:35–43` returns `Inconclusive` for a partial scan without a decisive construct, and preserves `Decisive` when one is present. Its compatibility detectors do not apply the analyzer budget. Both cut mechanisms can split an escape, token, comment, or HTML reference.

**Improvement current can take from Coraza:** offer a status-bearing limited result, or require callers to retain `input.len() > limit` alongside the verdict. Coraza should make the distinction between bounded analysis and full-slice compatibility calls unmistakable in documentation. Configure body/field limits separately from scan budgets; a partial negative requires an integration policy.

### Cross-check: latest `libinjection-go` main

Follow-up checked on 2026-10-09 against [`corazawaf/libinjection-go`](https://github.com/corazawaf/libinjection-go), freshly cloned from `main`. The live remote `refs/heads/main` was independently checked and matched **[`de4ec9bfed163a9499c426e8c53af0805973cb35`](https://github.com/corazawaf/libinjection-go/commit/de4ec9bfed163a9499c426e8c53af0805973cb35)**, committed 2026-10-08 with subject `chore(main): release 0.3.5 (#136)`. This checks main at that snapshot, rather than assuming the Rust port's v0.3.3 provenance represents current Go behavior. The links below pin the exact commit.

**Method:** trace the public `IsSQLi`/`IsXSS` calls through lexing, folding, whitelist decisions, HTML tokenization, and attribute/URL checks. Outcomes remain source-derived predictions; no Go tests, detector runs, or benchmarks were performed. Browser/database conditions from F1–F9 still apply.

| Finding | Go-main outcome for the listed input | Does the same issue affect Go? |
|---|---|---|
| F1: `j&#9;avascript:`, `j&#13;avascript:`, `j&Tab;avascript:`, `j&NewLine;avascript:` in href | `IsXSS == false`; literal internal TAB also misses | **Yes.** Same numeric-only reference decoding and internal NUL/LF-only skipping. |
| F2: `"\t1--"` | `IsSQLi == false` | **Yes.** Still indexes by token length without adding its position. Coraza Rust's corrected offset is an improvement over this Go main. |
| F3: raw FF before a separated `onerror` attribute | `IsXSS == true` | **No.** FF is 255; EOF is separately represented as -1. |
| F4: `1 OR 1` | `IsSQLi == false` | **Yes.** Same three-source-token suppression of `1&1`. |
| F5: `1#` | `IsSQLi == false` | **Yes.** MySQL reparse still suppresses the hash comment. |
| F6: `/*M! 1 OR 1 */` | `IsSQLi == false` | **Yes.** Only `/*!` is recognized as executable; the M-prefixed comment is discarded. |
| F7: `1 OR 2>1` | `IsSQLi == true` | **No.** Go has no modern-analysis hint downgrade; compatibility catches this input. |
| F8: fully percent-encoded details/ontoggle fragment | Encoded text: `IsXSS == false`; decoded HTML: `IsXSS == true` | **Same encoded-input miss, different contract.** Go has no internal percent decoder or modern analyzer, so caller decoding is required; it does not have Coraza's normalized-fallback inconsistency. |
| F9: a byte budget excludes a dangerous suffix | No Go budget API or truncation status | **No direct counterpart.** A caller that manually slices a string can create the same partial-input enforcement risk. |

Supporting source traces:

- **F1:** [`htmlDecodeByteAt`](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/xss_helpers.go#L130) leaves named references literal. [`htmlEncodeStartsWith`](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/xss_helpers.go#L208) skips only internal NUL/LF at line 227; TAB/CR mismatch before `JAVA` finishes. [`handleAttrValue`](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/xss.go#L64) delegates href values to that URL classifier. Other HTML contexts provide no rescuing match.
- **F2:** [`notWhitelist`, line 777](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/sqli.go#L775) reads `s.input[s.tokenVec[0].len]`. For the tab-prefixed number, it reads the digit instead of the first dash and returns false.
- **F3:** [`skipWhite`](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/html5.go#L7) returns `int(ch)` for FF; [`byteEOF`](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/html5_decls.go#L4) is -1. Tokenization continues to the handler.
- **F4/F5:** [`three-token suppression`](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/sqli.go#L819) and [`hash-comment suppression`](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/sqli.go#L738) retain the Rust compatibility decisions. [`check`](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/sqli.go#L863) performs the conditional MySQL pass; it does not override the suppression.
- **F6:** [`parseSlash`](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/sqli_parse.go#L140) uses [`isMysqlComment`](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/sqli_helpers.go#L92), which checks only `s[pos+2] == '!'`. [`fold`](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/sqli.go#L191) discards initial ordinary comments and returns zero for a comment-only input.
- **F7:** [`numeric comparison folding`](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/sqli.go#L483) produces `1&1` with five source tokens. The suppression applies only at three, so this match survives.
- **F8/F9:** [`IsXSS`](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/xss.go#L128) and [`IsSQLi`](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/sqli.go#L911) accept the supplied string without percent normalization, budget options, or analysis hints. The decoded details handler matches [`TOGGLE` in the event map](https://github.com/corazawaf/libinjection-go/blob/de4ec9bfed163a9499c426e8c53af0805973cb35/xss_decls.go#L392). Go's fixed name-normalization buffer is separate from an input scan budget.

**Result:** five of the concrete gaps are shared with latest Go main: **F1, F2, F4, F5, F6**. F3 is absent in Go. F7 is a Coraza-modern difference. F8 requires distinguishing caller decoding from analyzer normalization, and F9 has no built-in Go budget counterpart. The Go review therefore supports fixing shared inherited behavior deliberately rather than treating Go-main parity as a complete security criterion.

## 5. Precision, context, and documentation risks

### Memory safety and availability

The inspected first-party detector pipelines use safe Rust. Current forbids unsafe code at the crate root; Coraza inherits a workspace `unsafe_code = "deny"` lint. Bounds-checked slices, fixed compatibility token buffers, and checked or saturating arithmetic in Coraza's range handling limit conventional memory-corruption exposure. No concrete attacker-triggered memory corruption or panic was established by this review; this is not a proof of panic freedom. Coraza's `memchr` dependency has a separate implementation surface that was not audited internally.

The principal availability difference is resource growth: compatibility scanning has fixed auxiliary memory but can spend CPU proportional to a large supplied field; modern analysis additionally allocates proportional to its selected prefix. An allocator failure can still affect the process despite safe Rust. Trusted scan-budget configuration and request-size/concurrency controls are therefore part of the integration contract. Coraza's workspace declares Rust 1.97 and edition 2024; current declares edition 2024 without an explicit `rust-version`, which leaves its minimum supported compiler less explicit.

### Descriptive constructs can overstate danger

Coraza modern SQL flags a whole-word `union` without establishing a SQL statement (`src/sqli/modern/classify.rs:71`). Text such as `labor union` therefore produces a decisive analysis signal. Modern XSS flags an ordinary `<!-- ordinary comment -->` as `XSS_COMMENT_BYPASS` (`classify.rs:264`); that bit is in the decisive mask. Neither fragment by itself establishes injection. Compatibility detection does not reject that ordinary comment alone.

This is a **should-fix precision/calibration issue**, especially where hints are used directly as policy. Associate decisive status with dangerous combinations or context rather than an isolated keyword/comment opener. Preserve a distinction between an observed construct and evidence that it enables code execution.

### Compatibility false-positive choices

Both XSS backends reject every style attribute regardless of its value, and accept dangerous URL prefixes without requiring a scheme colon. Examples include `<p style="color:red">` and `<a href="java-guide.html">`. Both numeric-reference comparators take a decoded value's low byte: `&#x14a;ava:example` is compared like `JAVA`, although the HTML value begins with U+014A. Browser numeric references resolve Unicode; see [numeric reference replacement rules](https://html.spec.whatwg.org/multipage/parsing.html#numeric-character-reference-end-state).

Current's event-prefix matching rejects an invented `onclickx` attribute; Coraza's exact event lookup avoids that particular false positive. Current also uses broader namespace-related prefix checks where Coraza uses exact names. These are precision differences, not demonstrated exploits. Actual content event handlers have specific names; see [HTML event handlers](https://html.spec.whatwg.org/multipage/webappapis.html#event-handlers).

Coraza rejects a name lookup when its normalized name exceeds 64 bytes (`src/xss/legacy/deny.rs:17`, `145`); current compares full slices. Appending padding to a handler name creates a different attribute, so this ceiling alone is not evidence of a valid browser bypass. Compatibility hardening must follow sink semantics rather than maximize substring matches.

### Context limitations common to both

- HTML fragment scanning is not full browser tree construction, sanitization, JavaScript parsing, CSS parsing, or mutation-XSS analysis.
- SQL fingerprints are bounded to five folded type bytes. Full supplied input does not guarantee that every suffix token is inspected after the fingerprint window commits. Dialect labels are not full MySQL/PostgreSQL/MariaDB/SQL Server configurations.
- A value such as `alert(1)` inside an already existing handler or script body lacks the containing HTML syntax needed by these detectors. An omitted sink is a coverage limitation, not proof that the HTML tokenizer is wrong.
- Application URL decoding, character encoding, NUL handling, SQL modes, and output escaping can change exploitability. Compatibility API callers must supply the representation actually used downstream.

### Documentation mismatches — must correct before relying on README contracts

Coraza's [README](../coraza-rs/libinjection-rs/README.md) still describes a fixed-size snapshot and bounded stack normalization, a modern-policy-plus-legacy detection path, `DetectionVerdict`, `detect_*_with`, `allow_truncation`, and a 64 KiB hard cap. Those descriptions/examples do not match this revision. Actual snapshots own vectors; normalization can allocate; compatibility detection directly calls legacy; configured budgets are not clamped. Examples accessing `xss.detected` or `sqli.snapshot` also mismatch the result types. Its general `O(n)` claim is too broad for modern SQL token-containment work.

Current's [README](README.md) says only `sqli` and `xss` are public despite the added context/dialect/limit APIs. Its evidence roadmap says token start offsets need to be stored, but `Token.pos` already exists. Update that roadmap to describe missing source extent/result plumbing instead.

Neither README's historical corpus or benchmark claims were treated as evidence of current correctness or speed in this audit.

## 6. Static performance and complexity

Let `n` be supplied input length, `b = min(n, configured budget)` for bounded analysis, `K = 9,352` SQL table entries, `T` stored analyzer token ranges, `M` candidate positions requiring token containment, and `E` evidence spans. Fixed pattern/event lists are constants. Bounds describe the inspected source, not measured latency or hardware behavior.

| Path | Static time characterization | Auxiliary working memory | Main cost drivers |
|---|---|---|---|
| Current SQL compatibility | Amortized linear scans/folding with a fixed context factor; generic variable-needle search caveat below | `O(1)`, excluding static tables | Byte scanning, token copies, fixed-window folding, lookup probes. |
| Coraza SQL compatibility | Comparable scanning/folding; table lookup `O(log K)` per bounded key | `O(1)`, excluding static tables | Uppercase key buffer, binary search, memchr/memmem scans. |
| Current XSS | `O(n)` with at most five contexts and fixed lists | `O(1)` | Repeated HTML passes, entity decoding, prefix/event matching. |
| Coraza XSS compatibility | `O(n)` with at most five candidate contexts | `O(1)` | Context gating, memchr scans, exact deny-list lookup. |
| Coraza modern SQL | Approximately `O(b + M log(T + 1) + E)` expected; `T,M,E = O(b)`, hence `O(b log(b + 1))` | `O(b)` | Normalization/map, token vector, repeated fixed-pattern scans, containment searches, evidence/dedup. |
| Coraza modern XSS | `O(b + E)` expected with fixed pattern/context factors and one legacy fallback | `O(b)` | Normalization/map, construct scans, evidence, fallback HTML parsing. |

HashSet deduplication contributes expected rather than deterministic linear cost. For enormous configured budgets beyond `u32` mapping capacity, normalization can omit its direct source map and evidence recovery rescans original bytes; the ordinary analyzer bound above should not be extrapolated blindly to such budgets.

### SQL lookup tradeoffs

Current [keywords.rs:33–103](src/sqli/keywords.rs) adds 32,768 `u16` slots: **64 KiB of static index storage**, beyond the shared keyword data. FNV-based lookup uppercases ASCII while hashing; a compile-time assertion proves occupied runs are at most 14 entries, including wraparound. An attacker cannot create a growing hash-collision chain in this immutable table. A miss can inspect those candidates plus an empty slot. The tradeoff is static footprint/cache pressure versus typically fewer comparisons.

Coraza [legacy/data.rs](../coraza-rs/libinjection-rs/src/sqli/legacy/data.rs) uses a fixed 64-byte normalized key buffer and binary search over the sorted generated table. Approximately 14 comparison steps suffice for this table size. The Go-style Unicode-to-ASCII cases introduce extra normalization work and different semantics. Binary search uses less indexing storage but has its own locality costs. Source inspection cannot establish which wins on actual workloads.

Coraza's [build.rs](../coraza-rs/libinjection-rs/build.rs) validates uppercase ASCII keys, duplicate keys, one-byte values, sorting, and expected table/fingerprint counts. Current checks in generated data and builds its lookup index at compile time. Current can borrow generation validation; Coraza can consider a bounded static index if speed measurements justify its size.

### Scanning and pass reduction

Both SQL compatibility paths make at most five context/dialect attempts. Token windows and token-value buffers are fixed-size, so folding work does not grow with parser nesting. Long skipped comments, strings, whitespace, or reducible expressions can still require scanning most of the input.

Coraza uses memchr/memmem for several byte/subsequence scans and handles escape runs while advancing. Current uses simple scalar helpers and reverse escape checks around quote candidates. The traversals inspected are monotonic or amortized over disjoint runs; the latter alone does not prove quadratic quote handling. Current's generic `find_slice` performs window comparisons with the textbook `O(n*m)` bound for needle length `m`. Production fixed needles yield linear bounds. The variable dollar-quote delimiter has structural constraints; no concrete adversarial quadratic input was established here. Consider a linear substring primitive if a real profile identifies that path.

Coraza caches the full-input `sp_password` search across SQL passes; current may repeat it with a fixed pass factor. For XSS, current attempts all five contexts on a miss. Coraza gates Data on a relevant tag opener and quote contexts on the delimiter's presence, using memchr searches; a quoted context cannot exit without its delimiter. Current can adopt such gating while preserving the documented ordering of its first matching context.

### Modern SQL after the rebase

Coraza `src/sqli/modern/classify.rs:118` locates the first real semicolon token and scans its suffix for a fixed list of statement verbs. It does not independently rescan a suffix for every semicolon. At `379`, `token_contains` uses `partition_point` on ordered, disjoint token ranges, giving logarithmic containment checks. These changes materially improve the static bound and are included in this fresh audit.

Repeated patterns can still produce input-proportional candidates and evidence. Multiple fixed-pattern passes have meaningful constants even though they are linear in aggregate input size. Replacing binary containment checks with a monotonic token cursor within an ordered candidate scan is a possible optimization; it is not necessary to fix the old rescan problem in this revision.

### Analyzer allocation and memory estimates

Coraza normalization borrows unchanged bytes. The first ASCII uppercase byte, percent decoding change, or NUL removal causes an owned byte vector and an original-span vector, each initially reserving capacity proportional to `b` (`src/engine/normalize.rs:64`). Evidence stays in original coordinates, which is useful, but lowercase-only scans and transformed scans have different allocation profiles.

Illustrative 64-bit layout estimates, not measured peak allocations:

- Normalized byte capacity plus `(u32, u8)` map entries at typically 8 bytes each: about `9*b`, or **72 KiB** for an 8,192-byte selected prefix.
- `TokenMeta` is `repr(C)` with two `usize`s and a kind byte: typically 24 bytes. A prefix of repeated semicolons can store `b` ranges: **192 KiB** of element storage at the default budget, before capacity/allocator overhead.
- `EvidenceSpan` is two `usize`s: 16 bytes each on 64-bit. Candidate/result vectors and HashSet deduplication add storage; temporary and final evidence can overlap in lifetime.

These examples describe different inputs and are not a single asserted worst-case peak. They nevertheless disprove fixed stack-storage assumptions. Concurrent scans multiply per-field working memory; very large trusted budgets increase both CPU and heap exposure. The parent repository guidance asks for allocation avoidance where practical, not a zero-allocation API guarantee.

Useful opportunities include avoiding blanket lowercase allocation where comparisons already ignore ASCII case, lazy/compact offset maps, caller-provided reusable scratch storage where justified, and an evidence budget that explicitly reports omitted evidence. Any such change must preserve source coordinates and completeness status. Do not introduce a large buffer-management abstraction without a consumer need or profile.

### Maintenance complexity

Fresh ripwire static metrics identify these parser decision concentrations. Cyclomatic/cognitive counts are tool-derived review signals, not runtime heat or proof of bugs.

| Production symbol | Cyclomatic | Cognitive | Interpretation |
|---|---:|---:|---|
| Current `State::fold`, `src/sqli/fold.rs:120` | 98 | 106 | Much of the rule ordering is concentrated in one method. |
| Current `State::not_whitelist`, `src/sqli.rs:174` | 30 | 37 | Compact expression matching reduces repeated checks. |
| Coraza `SqliState::fold`, `legacy/fold.rs:99` | 35 | 61 | Top-level folding is split into helpers. |
| Coraza `fold_two_tokens`, `legacy/fold.rs:243` | 49 | 59 | A large portion of complexity moved here. |
| Coraza `fold_three_tokens`, `legacy/fold.rs:409` | 47 | 35 | Another substantial rule group. |
| Coraza `not_whitelist`, `legacy/detect.rs:99` | 55 | 68 | Manual byte checks add branches; it contains the corrected source offset. |
| Coraza `detect_stacked`, `modern/classify.rs:118` | 8 | 7 | The rebased scan has a comparatively small decision surface. |

Indicative handwritten production line counts, excluding generated/static deny tables and test sections, were approximately **2,734 current versus 5,603 Coraza**. They include comments and use a simple source-section boundary convention, so they are maintenance-size estimates. Coraza also implements analysis and evidence features absent from current; the difference is not evidence of removable bloat.

Current can borrow Coraza's named two-/three-token rule seams where they make ordering easier to inspect. Coraza can borrow current's enums, slice patterns, and direct token access to reduce repeated numeric-byte plumbing. Neither should merge distinct analysis and compatibility semantics merely to reduce file count.

## 7. Reciprocal improvement plan

| Priority | Current can take from Coraza | Coraza can take from current | Shared action |
|---|---|---|---|
| Must | Correct numeric token-end indexing; unsigned HTML byte/EOF distinction | Keep compatibility APIs explicit and lightweight; expose a winning context/dialect if consumers need it | Repair browser URL normalization and MariaDB executable-comment coverage for the supported sinks. |
| Must | Status-bearing limited results | Clear docs for actual API types, heap use, and uncapped configured budgets | Define enforcement behavior for partial input and descriptive hints. |
| Should | Exact event matching; public visitors if required | Typed tokens and compact whitelist/fold expression matching | Separate pinned compatibility from documented hardening; record intentional divergences. |
| Should | Table-generation validation | Retain first-semicolon scan and binary containment improvements | Add numeric Boolean/dialect policy coverage without blindly increasing false positives. |
| Should | Candidate-context gating | Run XSS fallback on appropriate normalized views; calibrate comment/keyword hints | Carry representation/sink assumptions into caller contracts and evidence. |
| Optional | Cached constant searches; selected memchr-style primitives | Bounded static keyword index if measurements justify 64 KiB | Profile real integration workloads before ranking throughput. |
| Optional | Small evidence/context result extension built on existing token positions | Reduce avoidable lowercase/map/evidence allocation | Add functionality only where a consuming WAF rule/operator needs it. |

Suggested implementation order:

1. Correct README/API contracts and make partial-scan decisions visible to integrators.
2. Fix F2/F3 in current, and executable-comment/URL gaps in both with explicitly documented compatibility changes.
3. Repair Coraza normalized fallback and Boolean-context classification; calibrate decisive hints.
4. Reduce redundant context scans and allocations where source already demonstrates avoidable work.
5. When separately authorized, reproduce the listed cases in matching SQL/browser sinks and add focused regression cases before releasing detector changes. No such execution was part of this audit.

## 8. Selection guidance and remaining uncertainty

Choose current when a dependency-free `no_std` compatibility detector, fixed working memory, and explicit match context are the primary requirements. Its current inherited misses require attention; small footprint is not evidence of stronger detection.

Choose Coraza's compatibility surface when public token visitors, workspace integration, and its existing offset/unsigned-byte fixes matter. Choose its analyzer when constructs, evidence, and partial-scan status are needed, with explicit policy for its precision and coverage differences. Its richer API does not establish stronger enforcement across all payload families.

The most useful combination is a clear compatibility contract plus deliberate hardening and optional descriptive analysis. Importing the entire modern pipeline into current would add heap, dependency, policy, and maintenance costs; exchanging small parser fixes and normalization rules provides immediate value.

This review did not exhaustively prove panic freedom, termination for every byte sequence, all SQL modes, every browser encoding/tree-construction case, mutation XSS, or downstream Coraza rule integration. It did not measure compiler output, cache behavior, stack size, allocator peaks, binary size, or speed. The concrete misses are source-predicted and sink-conditioned; the analysis establishes neither an accuracy percentage nor a claim that unlisted inputs are safe.
