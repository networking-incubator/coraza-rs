# Differential behavior and mismatch ledger

The selected oracle is `libinjection-go` main at commit
`24322d8dcaccb6ce078151937741fb4f7e462a55`, pinned as
`v0.3.6-0.20261012170915-24322d8dcacc` in `xtask/tools/go.mod` with checksum
`h1:IYJ0i4VxE2/ypgknP6JXxob1mNB83n2JXWpxnAzP/Co=`. The direct suite covers
864 corpus and binary cases across SQL/XSS public results, SQL token and fold
streams, and five HTML contexts. The generated suite covers 770 deterministic
byte and grammar inputs.

The direct suite compares 17,280 defined fields. All 864 cases complete
without oracle errors; 862 match all three public fields. Two exact cases
contain four reviewed public-result differences. Parser stream differences
are reported as diagnostics and do not relax the public-result gate.

## Reviewed direct differences

| Case | Input | Pinned Go main | libperfusion | Reason |
| --- | --- | --- | --- | --- |
| `sql-nul-after-hex-prefix` | `31206f7220307800313d312d2d20` (`1 or 0x<NUL>1=1-- `) | SQLi miss | SQLi hit, `1&1c` | Retains the C parser's bounded numeric-span behavior. |
| `sql-nul-after-hex-prefix-hash` | `273d30580023` (`'=0X<NUL>#`) | SQLi miss | SQLi hit, `so1c` | Retains the C parser's NUL-containing hexadecimal-number behavior. |

Each exception is keyed by both case ID and exact bytes in
`tests/oracle_differential.rs`. The test requires exactly two reviewed
exception cases, so unrelated differences fail.

The generated suite has one additional reviewed SQLi verdict difference on
`raw-0265`, input
`3d2f5932200a273d63300a3058002358592d62255c603e592060202025612a`. Go reports
a miss; libperfusion reports a hit with fingerprint `son1o`. The exact case is
checked in `tests/generated_differential.rs`; other verdict differences fail.

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
match exactly. Twenty-four XSS verdict differences are reviewed:

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
  `:234`, `:236`, and `:468`; `xss-soaj1664ashar-pastebin-u6FY1xDA.txt:78` and
  `:102`; and `xss-xenotix.txt:693`, `:694`, and `:1196`. The cases contain
  prefixed XML/SVG elements or `xlink:href` values. Their exact bytes are in
  the differential test and are checked against both references.

On all 81,417 XSS samples in the pinned C data, libperfusion and Go main
both flag 81,388 and allow 29; C flags 81,397 and allows 20. These nine
additional C-only detections account for the count difference.

The optional C gate compares exact case IDs and bytes and requires exactly
these twenty-four XSS differences; new SQL or XSS differences fail. The Go
gate also checks all nine added sample inputs, including their XSS verdicts.

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
| 21 dialect identifiers added | absent | present | A callable missing from the table is classified `Bareword`, which moves the fingerprint off the denylist; see `data/sqli_keywords.txt` |

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

`differential.tables` and `differential.source_sha256` in
`tests/parity/manifest.json`, and `sql` in `data/tables.json`, are updated to
match. The pinned Go and C oracles still describe upstream, so the optional
`make parity-differential` gate reports these shapes as differences.

## Provenance

Compatibility is selected against the pinned Go main commit using Go
1.27.1/linux/amd64. The shipped tables were extracted from C revision
`d88a8f86d617ac8dcb9169c9f34637aaac71ac76`, recorded in `data/tables.json`.
The checked-in differential workflow runs both the pinned Go module and the C
checkout at `533a165ebc1f7c36ecbe3e5583990ea0db81f554`, recorded in
`tests/parity/manifest.json`, as CI oracles.
