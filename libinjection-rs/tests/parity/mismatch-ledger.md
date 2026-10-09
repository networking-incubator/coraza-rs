# Differential behavior and mismatch ledger

Current oracle: `libinjection-go` v0.3.5, selected by
`xtask/tools/go.mod`. Its module checksum is
`h1:Zj2AAAKnaRtoLCXYqmc/wzCVAVXxe81UpF5JblL4WQA=`. The direct suite compares
843 corpus and binary cases across public SQL/XSS verdicts, fingerprints, SQL
raw/fold streams, and five HTML5 contexts. The generated suite checks 770
deterministic byte and grammar cases.

Public verdicts enforce a one-way release contract: every Go hit must remain a
Rust hit, and any Rust-only hit must match an exact reviewed exception.
Fingerprints and parser outputs are diagnostics, not release gates.

## Current differential result

The direct comparison passes **843 cases** and **16,860 defined results** with
**zero oracle errors**, **two reviewed Rust-only SQL verdict exceptions**, and
**zero unreviewed public verdict mismatches**. It reports eight parser
diagnostic differences on two benign NUL-containing controls. The generated
comparison passes **770 cases** with one reviewed Rust-only SQL verdict and
one fingerprint diagnostic.

The earlier v0.3.3 differences for malformed quotes, whitespace before `1c`
patterns, high-byte Oracle q-strings, NUL-containing `@` attacks, and the
percent-comment XSS verdict now match v0.3.5. They remain covered by the
corpus and binary cases, but are no longer allowlisted verdict exceptions.

## Active SQL verdict exceptions

### NUL inside a hexadecimal prefix

- **Input:** `31206f7220307800313d312d2d20`
  (`1 or 0x<NUL>1=1--\x20`)
- **Go v0.3.5:** benign
- **Rust:** detected, fingerprint `1&1c`
- **Reason:** Rust preserves the reviewed C parser's bounded numeric-span
  behavior. The public verdict and exact token differences are allowlisted for
  this case only.

### NUL in a hexadecimal prefix before a hash operator

- **Input:** `273d30580023` (`'=0X<NUL>#`)
- **Go v0.3.5:** benign
- **Rust:** detected, fingerprint `so1c`
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

## Generated differential exception

The generated suite accepts one exact Rust-only SQL verdict for case
`raw-0265`:

- **Input:** `3d2f5932200a273d63300a3058002358592d62255c603e592060202025612a`
- **Go v0.3.5:** benign
- **Rust:** detected

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
