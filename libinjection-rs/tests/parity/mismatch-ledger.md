# Differential behavior and mismatch ledger

Current oracle: `libinjection-go` v0.3.5, selected by
`xtask/tools/go.mod`. Its module checksum is
`h1:Zj2AAAKnaRtoLCXYqmc/wzCVAVXxe81UpF5JblL4WQA=`. The direct suite compares
853 corpus and binary cases across public SQL/XSS verdicts, fingerprints, SQL
raw/fold streams, and five HTML5 contexts. The generated suite checks 770
deterministic byte and grammar cases.

The selected compatibility target is Go v0.3.5 public detection behavior and
hit fingerprints, with only the exact deviations below. The Go oracle uses
toolchain 1.27.1 on linux/amd64. The C implementation is a secondary reference:
the earlier port baseline is `d88a8f86d617ac8dcb9169c9f34637aaac71ac76`, and
the current-C comparison is `533a165ebc1f7c36ecbe3e5583990ea0db81f554`.
Those C revisions were used for the recorded analysis, not as an additional CI
oracle; the checked-in differential workflow runs against the pinned Go module.

The legacy engine and YA/libperfusion are compared independently against Go.
Each candidate's SQL/XSS verdicts and SQL fingerprints must match except for
the exact reviewed cases below. Legacy token and HTML parser differences are
diagnostics; they do not affect YA's public-result gate.

## Current differential result

The direct comparison passes **853 cases** and **17,060 defined results** with
**zero oracle errors**, **two reviewed legacy-Rust SQL verdict exceptions**, and
**zero unreviewed public verdict mismatches**. The legacy Rust engine reports
nine diagnostic differences: eight parser differences on two benign
NUL-containing controls and the bare-XLINK XSS case. YA/libperfusion matches
all three public Go fields on 849 direct cases; the other four cases have
seven exact field differences documented below. The generated comparison
passes **770 cases** with one reviewed SQL verdict difference for each Rust
engine and one YA fingerprint diagnostic.

The earlier v0.3.3 differences for malformed quotes, whitespace before `1c`
patterns, high-byte Oracle q-strings, NUL-containing `@` attacks, and the
percent-comment XSS verdict now match v0.3.5. They remain covered by the
corpus and binary cases, but are no longer allowlisted verdict exceptions.

## Legacy Rust SQL verdict exceptions

### NUL inside a hexadecimal prefix

- **Input:** `31206f7220307800313d312d2d20`
  (`1 or 0x<NUL>1=1--\x20`)
- **Go v0.3.5:** benign
- **Legacy Rust / YA:** detected, fingerprint `1&1c`
- **Reason:** Rust preserves the reviewed C parser's bounded numeric-span
  behavior. The public verdict and exact token differences are allowlisted for
  this case only.

### NUL in a hexadecimal prefix before a hash operator

- **Input:** `273d30580023` (`'=0X<NUL>#`)
- **Go v0.3.5:** benign
- **Legacy Rust / YA:** detected, fingerprint `so1c`
- **Reason:** The reviewed C parser and Rust treat `0X<NUL>` as a number. The
  public verdict and exact token differences are allowlisted for this case
  only.

## Parser diagnostics

- **Benign NUL-containing hex value** — `30780031` (`0x<NUL>1`). Go emits a
  word and number token; Rust emits one number token. Both public verdicts are
  benign. This accounts for four diagnostic differences across raw/folded
  ANSI/MySQL token modes.
- **Benign NUL-containing variable** — `40006e616d65` (`@<NUL>name`). Go
  emits one variable token containing the NUL; Rust separates an empty
  variable token from `name`. Both public verdicts are benign. This accounts
  for the other four diagnostic differences.
- **Percent-comment followed by script** —
  `<%a%b%><script>alert(1)</script>`. Go and Rust agree on the public XSS
  verdict, but their HTML token streams differ. Only this exact diagnostic
  field is allowlisted.

Eight SQL fold-collapse cases compare number/word, operator/comma/parenthesis,
UNION, and tautology patterns. They match and are not exceptions. The corpus
also retains benign namespace lookalikes and SVG/XSL length-boundary controls.

## YA/libperfusion direct differences

The selected implementation is checked independently on the same 853 direct
cases. SQL and XSS verdicts and SQL fingerprints must match Go except for
these exact cases and fields:

### NUL inside a hexadecimal prefix

- **Input:** `1 or 0x<NUL>1=1--\x20`
- **Go v0.3.5:** benign; no fingerprint.
- **YA/libperfusion:** hit, fingerprint `1&1c`.
- **Reason:** Preserves current-C bounded numeric-span behavior.

### NUL before a hash operator

- **Input:** `'=0X<NUL>#`
- **Go v0.3.5:** benign; no fingerprint.
- **YA/libperfusion:** hit, fingerprint `so1c`.
- **Reason:** Preserves current-C NUL-containing hexadecimal number behavior.

### LIKE operator fingerprint

- **Input:** `1 LIKE (SELECT 1)`
- **Go v0.3.5:** hit, fingerprint `1f(E1`.
- **YA/libperfusion:** hit, fingerprint `1o(E1`.
- **Reason:** Current C folds this form as an operator; Go classifies it as a
  function.

### LIKE attack missed by Go

- **Input:** `' OR (8459 LIKE (SELECT 8459)) * 4906 --\x20`
- **Go v0.3.5:** benign; no fingerprint.
- **YA/libperfusion:** hit, fingerprint `s&(1o`.
- **Reason:** Current C detects this attack; Go v0.3.5 misses it.

Each case is matched by both its case ID and exact input bytes in
`tests/oracle_differential.rs`. The test hard-codes the direct inventory and
requires exactly four reviewed exception cases, so unrelated Go mismatches
cannot be accepted by these allowances.

The direct inventory also includes `xlink=1`: YA and Go both detect it. The
legacy Rust engine misses it; that result is printed as a diagnostic and does
not weaken YA's comparison.

## Generated differential exception

The generated suite accepts one exact SQL verdict difference for each Rust
engine on case
`raw-0265`:

- **Input:** `3d2f5932200a273d63300a3058002358592d62255c603e592060202025612a`
- **Go v0.3.5:** benign
- **Legacy Rust / YA:** detected
- **YA fingerprint:** `son1o`

The bytes, expected results, and reviewed exception are pinned in
`tests/generated_differential.rs`. The suite also reports fingerprint
differences as diagnostics.

## Fixed corpus formatter mismatch

The original mismatch in `test-tokens-words-020.txt` was in the test formatter,
not token bytes:

- **Input (hex):** `43555252454e545f555345526060424152`
- **Oracle output:** `v CURRENT_USER\nn \nn BAR`
- **Fix:** Preserve the empty bareword's trailing space in
  `tests/common/drivers.rs`; trim only the complete output.

The direct binary oracle compares token category, position, length, variable
count, delimiter bytes, values, and counters without text formatting adapters.
Oracle panics remain a failure unless reviewed and recorded. In the current
v0.3.5 baseline every oracle result completes successfully.
