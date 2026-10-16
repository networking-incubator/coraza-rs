# Differential behavior and mismatch ledger

The selected oracle is `libinjection-go` main at commit
`24322d8dcaccb6ce078151937741fb4f7e462a55`, pinned as
`v0.3.6-0.20261012170915-24322d8dcacc` in `xtask/tools/go.mod` with checksum
`h1:IYJ0i4VxE2/ypgknP6JXxob1mNB83n2JXWpxnAzP/Co=`. The direct suite covers
864 corpus and binary cases across SQL/XSS public results, SQL token and fold
streams, and five HTML contexts. The generated suite covers 770 deterministic
byte and grammar inputs.

The direct suite compares 17,280 defined fields. All 864 cases complete
without oracle errors; 858 match all three public fields. Six exact cases
carry reviewed public-result differences. Parser stream differences are
reported as diagnostics and do not relax the public-result gate.

## Reviewed direct differences

| Case | Input | Pinned Go main | libperfusion | Reason |
| --- | --- | --- | --- | --- |
| `sql-nul-after-hex-prefix` | `31206f7220307800313d312d2d20` (`1 or 0x<NUL>1=1-- `) | SQLi miss | SQLi hit, `1&1c` | Retains the C parser's bounded numeric-span behavior. |
| `sql-nul-after-hex-prefix-hash` | `273d30580023` (`'=0X<NUL>#`) | SQLi miss | SQLi hit, `so1c` | Retains the C parser's NUL-containing hexadecimal-number behavior. |
| `xss-soaj1664ashar-pastebin-u6FY1xDA.txt:78` | `74) <math><a xlink:href="//jsfiddle.net/t846h/">click` | XSS miss | XSS hit | Local `MATH` tag row; the pinned C reference also flags it. |
| `xss-soaj1664ashar-pastebin-u6FY1xDA.txt:102` | `97) <math><a xlink:href="//jsfiddle.net/t846h/">click` | XSS miss | XSS hit | As above. |
| `xss-xenotix.txt:693` | `<math><a xlink:href="//XXXxenotixXXX:3555/xss_serve_payloads/bmpz.bmp">KCF` | XSS miss | XSS hit | As above. |
| `xss-xenotix.txt:694` | `<math><a xlink:href="//XXXxenotixXXX:3555/xss_serve_payloads/kcf.js">KCF` | XSS miss | XSS hit | As above. |

Each exception is keyed by both case ID and exact bytes in
`tests/oracle_differential.rs`. The test requires exactly six reviewed
exception cases, so unrelated differences fail.

The generated suite has eight reviewed SQLi verdict differences. The first is
`raw-0265`, input
`3d2f5932200a273d63300a3058002358592d62255c603e592060202025612a`: Go reports
a miss; libperfusion reports a hit with fingerprint `son1o`. The other seven
-- `raw-0043`, `raw-0060`, `raw-0075`, `raw-0227`, `raw-0292`, `raw-0365` and
`raw-0373` -- are the narrowed `#` comment whitelist described below: each
minimizes to `"#` or `'#` and yields the `sc` fingerprint Go suppresses. All
eight are pinned by case ID and exact bytes in
`tests/generated_differential.rs`; other verdict differences fail.

## Parser diagnostics

- For benign `0x<NUL>1` (`30780031`), Go emits a word and number while
  libperfusion emits one number token. Both public verdicts are benign.
- For benign `@<NUL>name` (`40006e616d65`), Go emits one variable token while
  libperfusion separates an empty variable token from `name`. Both public
  verdicts are benign.
- For `1 or 0x<NUL>1=1-- ` and `'=0X<NUL>#`, Go and libperfusion differ in
  numeric token boundaries. Their public verdict differences are listed above.
- For `<%a%b%><script>alert(1)</script>`, public XSS results match while the
  HTML token streams differ.

These account for 16 diagnostic stream fields: 15 SQL token/fold fields and
one HTML field. The direct inventory also covers SQL fold-collapse cases,
namespace lookalikes, SVG/XSL name boundaries, and `xlink=1`; none are
additional exceptions.

## Pinned C reference

The C check uses commit `533a165ebc1f7c36ecbe3e5583990ea0db81f554`, pinned in
`tests/parity/manifest.json`. Across 864 inputs, SQLi verdicts and fingerprints
match exactly. Twenty XSS verdict differences are reviewed:

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
  `:234`, `:236`, and `:468`; and `xss-xenotix.txt:1196`. The cases contain
  prefixed XML/SVG elements. Their exact bytes are in the differential test
  and are checked against both references.
- **C and libperfusion detect; Go main allows:**
  `xss-soaj1664ashar-pastebin-u6FY1xDA.txt:78` and `:102`, and
  `xss-xenotix.txt:693` and `:694`. All four are
  `<math><a xlink:href="//host/path">`. They were C-only detections until
  the local `MATH` tag row was added; the row closed them, so these four
  moved from the C difference list to the Go one. They are still pinned by
  case ID and exact bytes, as `(C, libperfusion) = (true, true)` rows of
  `C_XSS_SAMPLE_VERDICTS`, so losing the detection again fails the gate.

On all 81,417 XSS samples in the pinned C data, libperfusion flags 81,392
and allows 25; Go main flags 81,388 and allows 29; C flags 81,397 and allows
20. The four samples above are the whole difference between libperfusion and
Go main, and five C-only detections remain.

The optional C gate compares exact case IDs and bytes and requires exactly
these twenty XSS differences; new SQL or XSS differences fail. The Go gate
also checks all nine added sample inputs, including their XSS verdicts, and
requires exactly six reviewed public-result exceptions.

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
deviations from `d88a8f8` by design, so the pinned oracle will disagree on
these shapes; each is covered by a test in `tests/regressions.rs`.

| Change | Upstream | libperfusion | Reason |
| --- | --- | --- | --- |
| `#` comment whitelist narrowed | suppresses every `sc` whose comment starts with `#` | suppressed unless the comment closes a string the input did not open and ends the input | `admin'#` is a complete MySQL authentication bypass; the blanket suppression dates from a corpus in which a bare `#` in prose was common |
| `--` comment whitelist narrowed | suppresses any comment token longer than two bytes | allowed through when the comment body is entirely whitespace and ends the input | ANSI SQL and MySQL both require whitespace after `--`, so `admin'-- ` is the more canonical terminator and the whitelist was inverted relative to exploitability |
| 8 stacked-statement fingerprints added | `01;ES`, `01;T`, `0S;ES`, `0S;T`, `01;TN`, `0S;TN`, `01;TC`, `0S;TC` absent | present | Length-4 coverage is thin upstream, so `1;WAITFOR DELAY '0:0:5'` passed while `1;WAITFOR DELAY '0:0:5',` was caught |
| 20 dialect identifiers added | absent | present | A callable missing from the table is classified `Bareword`, which moves the fingerprint off the denylist; see `data/sqli_keywords_local.txt` |
| 12 URL-bearing attributes and the `MATH` tag added | absent | present | `SRCSET`, `PING`, `CITE`, and the rest carry a URL that upstream never inspects, and no black tag backstops them; see `data/xss_tables_local.txt` |

### Measured effect on the pinned upstream sample data

Each row was measured by running every sample of the pinned C checkout
through both this revision and the pre-change revision; the counts are
asserted in `tests/upstream.rs`.

| Sample set | Upstream C | libperfusion | Difference |
| --- | --- | --- | --- |
| `sqli-*.txt` (85,802) | 85,785 flagged | 85,785 flagged | none |
| `false_positives.txt` (423) | 21 flagged | 25 flagged | four more, all from the `#` whitelist |
| `xss*.txt` (81,417) | 81,397 flagged | 81,392 flagged | four more than Go main, all from the `MATH` tag |

The four added false positives are the cost of the `#` change and are
recorded here rather than argued away: `7" #2 CIRCULAR NEEDLE`,
`"#2 MOM"`, `BAMBOO CHARCOAL SOAP 1 '#` and `FOO BAR'# BLAH`. Each has the
same token shape as `admin'#` -- a string the input did not open, closed by
a `#` comment that ends the input -- so no rule separates them from the
authentication bypass. Four product-catalog strings in 423 is the price of
catching the bypass, and a deployment that cannot pay it should revert the
`#` whitelist to the upstream form rather than add ad-hoc exemptions. The
same shape accounts for the seven reviewed `raw-*` deviations in the
generated suite.

The `MATH` tag can also fire on benign MathML; `data/xss_tables_local.txt`
documents the trade-off and how to drop the row.

`XP_CMDSHELL` was in the dialect list and has been removed: classifying it
as a `Function` *lost* detections, because
`'AND 1.-1LIKE.1 EXEC xp_cmdshell 'dir<SP>` (sqli-phpids.txt:264, where
`<SP>` stands for the trailing space the payload ends with) and
`'; EXEC xp_cmdshell 'dir'--` moved from the listed `s&1Tn`/`s;Tns`
fingerprints to the unlisted `s&1Tf`/`s;Tfs`.
`EXEC` already carries the Tsql classification that makes the shape
recognisable. This is the same hazard as the bare Oracle package names
below, and `tests/regressions.rs` now pins all three payloads.

Identifiers were chosen to have no plausible reading as ordinary prose.
Common English words that appear in the dialect references -- `WINDOW`,
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
revision produces, and `tables` and `source_sha256` in
`tests/parity/manifest.json` and `sql`/`xss` in `data/tables.json` continue to
describe upstream alone; the supplements are pinned by `local` in
`data/tables.json` and verified by `cargo xtask tables-check`. The pinned Go
and C oracles still describe upstream, so the optional
`make parity-differential` gate reports these shapes as differences.

## Provenance

Compatibility is selected against the pinned Go main commit using Go
1.27.1/linux/amd64. The shipped tables were extracted from C revision
`d88a8f86d617ac8dcb9169c9f34637aaac71ac76`, recorded in `data/tables.json`.
The checked-in differential workflow runs both the pinned Go module and the C
checkout at `533a165ebc1f7c36ecbe3e5583990ea0db81f554`, recorded in
`tests/parity/manifest.json`, as CI oracles.
