# Differential behavior and mismatch ledger

Current oracle: `libinjection-go` v0.3.3, release commit
`f6c336efc0ddac2597fd27d3b1b7db9c87613e8d`. The direct suite records the
public SQL verdict, six SQL raw token streams, six folded streams and their
counters, five HTML5 contexts, and the public XSS verdict. Public verdicts
enforce the one-way release contract: every Go hit must remain a Rust hit,
and any Rust-only hit must match an exact reviewed exception. Fingerprints and
parser outputs are diagnostics, not delivery gates. The expanded suite
compares **843 cases** and **16,860 defined results** with **ten exact,
reviewed exception groups**: the SQL quote-stream difference and
malformed-quote improvement, three `1c` whitelist cases, two high-byte Oracle
q-string cases plus the following-`UNION` case, and two exact NUL-after-`0x`
cases. Each exception is pinned by case ID, exact bytes, Go value, Rust value,
and result layer. Benign controls cover the SQL changes, namespace lookalikes,
and SVG/XSL length boundaries. The previously recorded v0.3.2
CDATA and NUL-containing IMPORT/ENTITY cases now compare exactly against
v0.3.3 and are not exceptions.

Inline payload examples use `\x20` to show a boundary ASCII space; the hex is
the exact byte sequence.

## Fixed — ``test-tokens-words-020.txt``

- **Layer:** SQL raw-token fixture formatting
- **Raw input (hex):** `43555252454e545f555345526060424152`
- **Oracle expected:** `v CURRENT_USER\nn \nn BAR`
- **Initial Rust actual:** `v CURRENT_USER\nn\nn BAR`
- **Assigned fix:** Removed per-token whitespace trimming from
  `tests/common/drivers.rs`; preserve the empty bareword's trailing space and
  trim only the complete output, matching Go's section reader.

## Accepted SQL parser behavior change — ``sql-escape-suffix``

- **Layer:** SQL raw and folded token streams in the no-quote ANSI and MySQL
  passes
- **Raw input (hex):** `275c2727` (`'\''`)
- **Go stream:** `1,0,0,0;73:1:3:0:27:00:5c2727`; Go's repeated-suffix lookup
  leaves the string open and includes the final delimiter in the value.
- **Rust stream:** `1,0,0,0;73:1:2:0:27:27:5c27`; Rust treats the first quote as
  backslash-escaped and closes at the following unescaped quote.
- **Scope:** Only the exact no-quote ANSI/MySQL raw/fold stream fields for this
  input are allowlisted. SQL verdicts and fingerprints match for this input.
  The separate malformed-quote case below shows that the scanner also changes
  public detection on a different malformed input.
- **Security check:** The corresponding attack-shaped input
  `275c2727204f5220313d31202d2d20` (`'\\'' OR 1=1 --\x20`) is included in the
  differential suite. Both Go and Rust detect it with fingerprint
  `73263163:4`; a unit regression also asserts Rust detects it.
- **Reason:** Rust scans each quote run once, tracks backslash parity, consumes
  unescaped doubled delimiters, and closes at the next unescaped delimiter.
  This removes repeated full-suffix searches. The malformed-input difference
  is narrow; corpus behavior and the attack verdict remain covered.

- **Public verdict and token stream on a malformed quote run** — Input
  `2d28746f703c3e7468656e64726f70312e355c272d2d6e756c6c272d2d`
  (`-(top<>thendrop1.5\'--null'--`) is missed by Go v0.3.3 and detected by
  Rust with fingerprint `sc`. The reviewed C reference also detects it. The
  exact public and token-stream differences are allowlisted in the expanded
  direct differential suite and remain covered through `detect_sqli`; this is
  a deliberate safety improvement, not an attempt to imitate Go's parser quirk.

## Reviewed SQL behavior changes over Go v0.3.3

- **`1c` slash comment after whitespace** — Input `09312f2a` (`\t1/*`) is
  missed by Go because its short-fingerprint check excludes `/`, then its
  fallback indexes the original input without including the number token's
  position. Rust now recognizes the slash-comment case directly and includes
  the token position in the fallback offset. The upstream C check also treats
  a `1c` fingerprint ending in `/` as SQLi. The expanded differential test
  also pins `\x20 1/*x*/`, `\x20 0x1/*`, and `\n1e5/*`; Rust returns detected
  with fingerprint `1c`, while Go returns false.
- **High-byte Oracle q-string delimiter** — Input
  `7127e92720756e696f6e202f2a21353030303073656c6563742a2f2031`
  (`q'\xe9' union /*!50000select*/ 1`) previously let Go and Rust consume the
  remaining SQL as an unterminated q-string. Rust now treats bytes above
  `0x7f` as invalid q-string delimiters and resumes ordinary tokenization, so
  the following SQL remains visible to detection. The direct differential
  suite also pins the exact raw and folded stream changes for an unclosed
  high-byte delimiter and a UTF-8 delimiter sequence.
- **NUL after an `@` variable prefix** — Input
  `4000756e696f6e2073656c6563742031` (`@\0union select 1`) previously let Go
  and Rust absorb the NUL and following SQL into one variable token. Rust now
  ends the variable at NUL, which its tokenizer treats as a separator, and
  detects the following `UNION SELECT` sequence.
- **NUL inside a `0x` numeric prefix** — Input
  `31206f7220307800313d312d2d20` (`1 or 0x<NUL>1=1--\x20`) is missed by Go
  v0.3.3 but detected by the reviewed C reference. Rust now preserves C's
  bounded `strchr` behavior for this numeric span and detects the tautology
  with fingerprint `1&1c`.
  The exact public, raw-stream, and folded-stream differences are included in
  the differential allowlist.

- **NUL in a hexadecimal prefix before a hash operator** — Input
  `273d30580023` (`'=0X<NUL>#`) is a minimized generated differential case.
  The reviewed C parser and Rust treat `0X<NUL>` as a number and detect it with
  fingerprint `so1c`; Go treats the NUL differently and returns benign. The
  exact public, raw-token, and folded-token differences are allowlisted. This
  case ensures the NUL span behavior remains limited to the exact parser
  contract under review.

The SQL improvements above are covered at the public detection API; every
Rust-only verdict has an exact one-way exception entry, while Go hits remain
ordinary required hits. Neighboring benign
controls (`1`, `q'` plus a high byte, a standalone NUL-containing hex literal,
and a NUL-terminated variable) remain undetected by Rust.

## XSS prefix and namespace controls

- **SVG/XSL tag prefixes** — Go v0.3.3 uppercases and strips NULs into a
  64-byte normalized buffer, then treats any non-truncated `SVG` or `XSL`
  prefix as a hit. Rust follows that bound: a 64-byte normalized name with an
  SVG prefix remains a hit, while a 65-byte normalized name is ignored.
  `svganimate` and `xsl:template` are Go-positive controls and remain detected;
  the exact-length overlong controls are benign in both. This preserves
  compatibility while exposing the conservative false-positive surface of
  the upstream prefix rule.
- **XMLNS and XLINK attribute lookalikes** — `<div xmlnsfoo="safe">`,
  `<div xmlns:xss="safe">`, and `<div xlinkfoo="safe">` are benign under Go
  v0.3.3 and Rust. `<div xlink:href="javascript:alert(1)">` remains detected
  through the exact URL attribute and URL value checks. These are ordinary
  verdict comparisons, not exception entries.

- **Bogus percent comment cursor** — Input
  `<%a%b%><script>alert(1)</script>` previously let the Go tokenizer search
  from the original cursor after recognizing `%`, swallowing the later script
  into one comment token. Rust now advances from the actual candidate cursor,
  closes the bogus comment at `%>`, and keeps the script visible. The corrected
  HTML5 token stream has a pinned diagnostic fixture; public XSS detection
  remains compared independently.

## Current v0.3.3 differential result

The direct comparison passed **843 cases** and **16,860 defined results** with
**zero oracle errors**, **ten exact accepted exception groups**, and **zero
Go-positive/Rust-negative or unreviewed Rust-only verdicts**. It records SQL
fingerprints, all six raw/fold SQL modes and counters, all five HTML token
streams, and XSS verdicts. Parser and fingerprint differences are diagnostic.
The CDATA cursor-bound and NUL-containing IMPORT/ENTITY fixes from v0.3.3 are
ordinary verdict comparisons now.

Eight SQL fold-collapse inputs were added to compare the folded streams and
public verdicts around number/word, operator/comma/parenthesis, UNION, and
tautology patterns. They all match. These cases establish observable behavior
for those patterns; they are not evidence that Go's `pos > maxTokens` frontier
branch is reached. Rust retains its current folding logic unless a public
behavior difference is demonstrated.

The generated public differential separately passed its 770 deterministic
cases. This is a verdict/fingerprint check and does not replace the direct
token-stream comparison.

The original corpus mismatch was in the test formatter, not the token bytes.
The direct binary oracle compares category, original position, length, variable
count, delimiter bytes, values, and all reported counters without text
formatting adapters. Field 1 remains available for oracle panics; v0.3.3
produces an empty field for every current case, and any non-empty oracle error
fails the differential unless separately reviewed and recorded.

The mode order is quote-none ANSI/MySQL, quote-single ANSI/MySQL, and
quote-double ANSI/MySQL. These explicit flags inspect the tokenizer/folder
independently of `IsSQLi`, which reports its own multi-pass boolean and
fingerprint.
