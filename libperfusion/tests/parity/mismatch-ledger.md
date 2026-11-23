# Differential behavior and mismatch ledger

The machine-readable rows of every reviewed difference below -- oracle,
suite, exact input bytes and both verdicts -- are in
[`reviewed-differences.tsv`](reviewed-differences.tsv), keyed by the same
ids. The direct and generated differential tests, the SQL corpus baselines
and the `speed` benchmark read them from there; a test checks that every id
there appears here.

The selected oracle is `libinjection-go` v0.3.6 (release commit
`355a9b39be7f692a976372cb34b675f45ec07188`), pinned as `v0.3.6` in
`xtask/tools/go.mod` with checksum
`h1:cXqACFY1anDzC9W127WguanVYvzvvcdQJI0BmErixdk=`. The direct suite covers
869 corpus and binary cases across SQL/XSS public results, SQL token and fold
streams, and five HTML contexts. The generated suite covers 770 deterministic
byte and grammar inputs.

The direct suite compares 17,380 defined fields. All 869 cases complete
without oracle errors; 862 match all three public fields. Seven exact cases
carry reviewed public-result differences. Parser stream differences are
reported as diagnostics and do not relax the public-result gate.

The pinned Go module carries upstream libinjection-go #140 (C-strchr NUL
semantics in the SQLi span helpers), which closed the two former
`sql-nul-*` public-result deviations and the fifteen former SQL token-stream
diagnostics. It also carries #141 (MySQL charset introducers), matching the
pinned C revision's keyword table.

## Reviewed direct differences

| Case | Input | Pinned Go main | libperfusion | Reason |
| --- | --- | --- | --- | --- |
| `xss-soaj1664ashar-pastebin-u6FY1xDA.txt:78` | `74) <math><a xlink:href="//jsfiddle.net/t846h/">click` | XSS miss | XSS hit | Local `MATH` tag row; the pinned C reference also flags it. |
| `xss-soaj1664ashar-pastebin-u6FY1xDA.txt:102` | `97) <math><a xlink:href="//jsfiddle.net/t846h/">click` | XSS miss | XSS hit | As above. |
| `xss-xenotix.txt:693` | `<math><a xlink:href="//XXXxenotixXXX:3555/xss_serve_payloads/bmpz.bmp">KCF` | XSS miss | XSS hit | As above. |
| `xss-xenotix.txt:694` | `<math><a xlink:href="//XXXxenotixXXX:3555/xss_serve_payloads/kcf.js">KCF` | XSS miss | XSS hit | As above. |
| `test-sqli-038` | `1 and @version` | SQLi miss | SQLi hit, `1&v` | Short numeric boolean, no longer spared at three tokens; the pinned C reference also misses it. |
| `test-sqli-041` | `1 and "a"` | SQLi miss | SQLi hit, `1&s` | As above. |
| `test-tokens-words-021` | `` 1 AND`BAR` `` | SQLi miss | SQLi hit, `1&n` | Local `01&N` row; the pinned C reference also misses it. |

Each exception is keyed by both case ID and exact bytes. The test requires
every reviewed `go`/`direct` row to be observed and no other difference, so
unrelated differences fail.

The generated suite has seven reviewed SQLi verdict differences:
`raw-0043`, `raw-0060`, `raw-0075`, `raw-0227`, `raw-0292`, `raw-0365` and
`raw-0373` -- the narrowed `#` comment whitelist described below: each
minimizes to `"#` or `'#` and yields the `sc` fingerprint Go suppresses. All
seven are pinned by case ID and exact bytes as the `go`/`generated` rows;
other verdict differences fail.

## Parser diagnostics

- For `<%a%b%><script>alert(1)</script>`, public XSS results match while the
  HTML token streams differ.

This accounts for one diagnostic stream field. The former fifteen SQL
token/fold diagnostics around NUL-containing numeric spans were closed by the
pinned Go module's #140 fix. The direct inventory also covers SQL
fold-collapse cases, namespace lookalikes, SVG/XSL name boundaries, and
`xlink=1`; none are additional exceptions.

## Pinned C reference

The C check uses commit `1b9f5f077fc10754e7e4b6498cdaa8fbee53d707`, pinned in
`tests/parity/differential.json`. Across 869 inputs, SQLi verdicts and fingerprints
match exactly except `test-sqli-038`, `test-sqli-041` and
`test-tokens-words-021`, the three short numeric booleans in the Go table
above, which C misses too. Twenty XSS verdict differences are reviewed:

- **C misses; libperfusion detects:** `xss-event-name-nul`,
  `xss-tag-name-nul`, `xss-xmlns-name-nul`, `xss-url-nul`,
  `xss-nul-import-1`, `xss-nul-import-2`, `xss-nul-entity-1`, and
  `xss-nul-entity-2`. These follow the selected Go main behavior for NULs
  inside names and comments.
- **C detects; libperfusion allows:** `xss-event-suffix-control`,
  `xss-namespace-xmlns-prefix`, `xss-namespace-xlink-prefix`,
  `xss-indirect-url-control`, `xss-indirect-style-control`,
  `xss-svg-prefix-overlong-control`, and `xss-xsl-prefix-overlong-control`.
  These cases avoid C's suffix/prefix overmatches and agree with Go main.
- **C detects; libperfusion and Go main allow:** `xss-html5secorg.txt:232`,
  `xss-html5secorg.txt:234`, `xss-html5secorg.txt:236`, and
  `xss-html5secorg.txt:468`; and `xss-xenotix.txt:1196`. The cases contain
  prefixed XML/SVG elements. Their exact bytes are reviewed rows and are
  checked against both references.
- **C and libperfusion detect; Go main allows:**
  `xss-soaj1664ashar-pastebin-u6FY1xDA.txt:78` and `:102`, and
  `xss-xenotix.txt:693` and `:694`. All four are
  `<math><a xlink:href="//host/path">`. They were C-only detections until
  the local `MATH` tag row was added; the row closed them, so these four
  moved from the C difference list to the Go one. They are still pinned by
  case ID and exact bytes as `go`/`direct` rows, and the C gate allows no
  difference on them, so losing the detection again fails both gates.

On all 81,420 XSS samples in the pinned C data (the revision carries the
0xFF `h5_skip_white` fix and its three `data/xss-github-92.txt` samples),
libperfusion flags 81,395 and allows 25; Go main flags 81,391 and allows 29;
C flags 81,400 and allows 20. The four samples above are the whole difference
between libperfusion and Go main, and five C-only detections remain.

The optional C gate compares exact case IDs and bytes and requires exactly
these twenty XSS and three SQLi differences; new SQL or XSS differences fail.
The Go gate also checks all nine added sample inputs, including their XSS
verdicts, and requires exactly seven reviewed public-result exceptions.

## Corpus formatter regression

The mismatch in `test-tokens-words-020.txt` was in corpus output formatting,
not token bytes:

- Input: `43555252454e545f555345526060424152`
- Expected output: `v CURRENT_USER\nn \nn BAR`
- The formatter preserves the empty bareword's trailing space and trims only
  the complete output.

Oracle errors and panics fail the comparison. The pinned Go main oracle
completes every result field in the checked-in baseline.

## Deliberate detection deviations from upstream

The following changes make this port detect inputs upstream misses. They are
deviations from the pinned upstream revision `1b9f5f0` by design, so the
pinned oracle will disagree on
these shapes; each is covered by a test in `tests/regressions.rs`.

| Change | Upstream | libperfusion | Reason |
| --- | --- | --- | --- |
| `#` comment whitelist narrowed | suppresses every `sc` whose comment starts with `#` | suppressed unless the comment closes a string the input did not open and ends the input | `admin'#` is a complete MySQL authentication bypass; the blanket suppression dates from a corpus in which a bare `#` in prose was common |
| `--` comment whitelist narrowed | suppresses any comment token longer than two bytes | allowed through when the comment body is entirely whitespace and ends the input | ANSI SQL and MySQL both require whitespace after `--`, so `admin'-- ` is the more canonical terminator and the whitelist was inverted relative to exploitability |
| 8 stacked-statement fingerprints added | `01;ES`, `01;T`, `0S;ES`, `0S;T`, `01;TN`, `0S;TN`, `01;TC`, `0S;TC` absent | present | Length-4 coverage is thin upstream, so `1;WAITFOR DELAY '0:0:5'` passed while `1;WAITFOR DELAY '0:0:5',` was caught |
| 20 opt-in dialect identifiers (`strict-sql-lookup`) | absent | present when enabled | These improve some function-call detections but can reclassify UNION columns; the default lookup omits them. `sqli_with_strict_fallback()` adds 16 of them on a retry and `ATTACH`, `COPY`, `DETACH` and `VACUUM` only directly after a `;`. See `data/sqli_keywords_strict.txt` |
| 12 URL-bearing attributes and the `MATH` tag added | absent | present | Local attributes inspect colon-terminated schemes to avoid prose false positives; upstream does not inspect these URL-bearing attributes. See `data/xss_tables_local.txt` |
| `1&n` fingerprint added; three-token suppression kept only for `s&n` and `n&1` | `1&n` absent; `s&n`, `n&1`, `1&1`, `1&v` and `1&s` suppressed at exactly three raw tokens | `01&N` in `data/sqli_keywords_local.txt`; `1&1`, `1&v` and `1&s` flagged at three tokens | `1 or id=id`, `-1 or pass`, `1 or 1`, `0 or 1` and `1 or 'a'` broaden `WHERE id = <input>` and passed CRS at PL1. A number on the left is not prose; `s&n` and `n&1` ("sexy and 17") stay suppressed, and `n&n` is never listed. False-positive classes: every short `N and\|or word` phrase and every numeric pair |

### Measured effect on the pinned upstream sample data

Each row was measured by running every sample of the pinned C checkout
through both this revision and the pre-change revision; the counts are
asserted in `tests/upstream.rs`.

| Sample set | Upstream C | libperfusion | Difference |
| --- | --- | --- | --- |
| `sqli-*.txt` (85,802) | 85,785 flagged | 85,785 flagged | none |
| `false_positives.txt` (423) | 21 flagged | 32 flagged | eleven more: four from the `#` whitelist, seven from short numeric booleans |
| `xss*.txt` (81,420) | 81,400 flagged | 81,395 flagged | four more than Go main, all from the `MATH` tag |

The four added false positives are the cost of the `#` change and are
recorded here rather than argued away: `7" #2 CIRCULAR NEEDLE`
(`false_positives.txt:222`), `"#2 MOM"` (`false_positives.txt:226`),
`BAMBOO CHARCOAL SOAP 1 '#` (`false_positives.txt:232`) and `FOO BAR'# BLAH`
(`false_positives.txt:302`). Each has the
same token shape as `admin'#` -- a string the input did not open, closed by
a `#` comment that ends the input -- so no rule separates them from the
authentication bypass. Four product-catalog strings in 423 is the price of
catching the bypass, and a deployment that cannot pay it should revert the
`#` whitelist to the upstream form rather than add ad-hoc exemptions. The
same shape accounts for the seven reviewed `raw-*` deviations in the
generated suite.

The seven short numeric boolean false positives are the cost of the `1&n`
row and of no longer sparing `1&1` at three tokens. The row flags
`40 AND FAB` (`false_positives.txt:40`), `7 AND HALF`
(`false_positives.txt:171`), `10.00 AND UNDER` (`false_positives.txt:175`),
`10 OR LESS` (`false_positives.txt:177`) and `9/PLUGS AND TUNNELS`
(`false_positives.txt:223`); the arm flags `00 AND 3`
(`false_positives.txt:174`) and `1950 or 1960` (`false_positives.txt:375`).
`1 or 2` cannot be told from the injection `0 or 2` by tokens, so no narrower
rule exists. Measured on the review's sets, the row alone adds 5 of 423
decoded `false_positives.txt` lines, 5 of 60 short form values and 4 of 20,995
licence-prose windows; the arm alone adds 2 of 423, 10 of 60 and 9 of 20,995
(0 of 2,000 random `<word> and|or <word>` pairs for either). Rule 942100 is
critical, so each is a 403 at PL1; numeric fields that legitimately carry such
values need a rule exclusion. Adding `0N&N` instead would flag 76.7 % of short
`X and Y` values and catch nothing more.

The `MATH` tag can also fire on benign MathML; `data/xss_tables_local.txt`
documents the trade-off and how to drop the row.

The `speed` benchmark checks the port against libinjection C input by input
before it reports any timing, against the `speed:*` rows: these eleven false
positives and the five C-only XSS samples above.

`XP_CMDSHELL` was in the dialect list and has been removed: classifying it
as a `Function` *lost* detections, because
`'AND 1.-1LIKE.1 EXEC xp_cmdshell 'dir<SP>` (sqli-phpids.txt:264, where
`<SP>` stands for the trailing space the payload ends with) and
`'; EXEC xp_cmdshell 'dir'--` moved from the listed `s&1Tn`/`s;Tns`
fingerprints to the unlisted `s&1Tf`/`s;Tfs`.
`EXEC` already carries the Tsql classification that makes the shape
recognisable. This is the same hazard as the bare Oracle package names
below, and `tests/regressions.rs` now pins all three payloads.

Identifiers were chosen to have no plausible reading as ordinary prose; the
exceptions are `ATTACH`, `COPY`, `DETACH` and `VACUUM`, which
`sqli_with_strict_fallback()` accepts only as a statement directly after a `;`.
Other common English words that appear in the dialect references -- `WINDOW`,
`FILTER`, `GROUPS`, `WITHIN`, `LATERAL`, `RETURNING`, `PIVOT`, `UPSERT`,
`PROGRAM` -- were deliberately **not** added: adding them produced a false
positive on the sentence "please copy the program to the new window"
(`nTnkn`). `tests/regressions.rs` asserts the retained set leaves prose alone.

Bare Oracle package names (`UTL_HTTP`, `UTL_INADDR`, `DBMS_PIPE`,
`DBMS_LOCK`) were likewise **not** added. The table already carries them as
fully qualified names such as `UTL_INADDR.GET_HOST_ADDRESS`, and classifying
the bare package stops the lexer merging the dotted form, which *loses* a
detection the table already had.

The added rows live in `data/sqli_keywords_local.txt` and
`data/xss_tables_local.txt`, not in the upstream-generated
`data/sqli_keywords.txt` and `data/xss_tables.txt`. `build.rs` merges each
supplement into the matching upstream table at compile time, so
`cargo xtask tables-refresh --upstream <checkout>` can rewrite the upstream
files from a newer C revision without dropping the local rows. The
upstream-generated files therefore stay byte-identical to what the pinned
revision produces, and `source_sha256` in
`tests/parity/differential.json` and `sql`/`xss` in `data/tables.json` continue to
describe upstream alone; the supplements are pinned by `local` in
`data/tables.json` and verified by `cargo xtask tables-check`. The pinned Go
and C oracles still describe upstream, so the optional
`make parity-differential` gate reports these shapes as differences.

## Provenance

Compatibility is selected against the pinned Go main commit using
go1.27.4-X:nodwarf5/linux/amd64. The shipped tables were extracted from C
revision `1b9f5f077fc10754e7e4b6498cdaa8fbee53d707`, recorded in
`data/tables.json`. The checked-in differential workflow runs both the pinned
Go module and the C checkout at `1b9f5f077fc10754e7e4b6498cdaa8fbee53d707`,
recorded in `tests/parity/differential.json`, as CI oracles.
