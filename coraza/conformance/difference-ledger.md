# Coraza engine difference ledger

This ledger records reviewed differences between the pinned native Go Coraza
reference and this Rust engine for the same exact byte fixture. It is the
companion to `capability-manifest.json`; the manifest says whether a capability
exists, and this file records cases where two existing or reviewed behaviors
diverge.

Reference profiles:

- Go Coraza: `d9cc9befc2721fd217ce1660a0e91aca1157221d`
  (`https://github.com/corazawaf/coraza`), native default build.
- Rust: `45f8785f8b17fb1f4df56f87bf87155cc986b916`
  (`https://github.com/networking-incubator/coraza-rs`).

Keys are `case_id` plus `fixture_sha256`. The hash is SHA-256 over the exact
input bytes, lower-case hexadecimal. A case may appear only once per key.
Detector rows below are carried over from the reviewed detector differences in
`libperfusion/tests/parity/mismatch-ledger.md`; they are documented outcomes,
not results executed by the Coraza engine. Engine rows come from a direct
Go Coraza/Rust comparison of the fixture bytes named in the reason. New rows
must state which side was observed.

## Reviewed engine and detector differences

| Case ID | Fixture SHA-256 | Expected Go | Expected Rust | Reason |
| --- | --- | --- | --- | --- |
| `sql-nul-after-hex-prefix` | `ada05d3c4ccbcb21de99ab1609081812dbe7a37e76a516595d44af97cb6ed02e` | SQLi miss | SQLi hit, fingerprint `1&1c` | Retains the C parser's bounded numeric-span behavior. |
| `sql-nul-after-hex-prefix-hash` | `74c8cdb374f247b42999a58680292f04fab7bd6e0da6c2d2bf88de41fc2b8f4b` | SQLi miss | SQLi hit, fingerprint `so1c` | Retains the C parser's NUL-containing hexadecimal-number behavior. |
| `xss-soaj1664ashar-pastebin-u6FY1xDA.txt:78` | `86ec68034c98e8a26e01f68db4c2051938b1b38131344c4876d0ad805cd92227` | XSS miss | XSS hit | Local `MATH` tag row; the pinned C reference also flags it. |
| `xss-soaj1664ashar-pastebin-u6FY1xDA.txt:102` | `9624e59812bd58fedf68d5e0639fc2a966224641bd3b54bed91700ecaeb7dce5` | XSS miss | XSS hit | As above. |
| `xss-xenotix.txt:693` | `779a6aca1d223eb0a63f0362a44841e48b43bbf505679119dcd3cb07b5c2c8f3` | XSS miss | XSS hit | As above. |
| `xss-xenotix.txt:694` | `55841cd4d4f4ad2d2a678fcc29a7a78534eb3ae4a0a9916a8fa22a30673b5194` | XSS miss | XSS hit | As above. |
| `raw-0265` | `8ceda65b55dbd3d4557ea3eef1d140660fb28d983b86b9ce8aa3111aecb3205a` | SQLi miss | SQLi hit, fingerprint `son1o` | Narrowed `#` comment whitelist; `#` is followed by additional bytes and the input ends with `a*`, not a trailing comment. |
| `raw-0043` | `1cdd835eb77c2bd1acb9003388a4c91e9b294fd01a2fed1b7701b1381f84701a` | SQLi miss | SQLi hit, fingerprint `sc` | Narrowed `#` comment whitelist; minimizes to a `#` shape. |
| `raw-0060` | `f39efb68b9bee584cd30dcf85698b40f92cd709d48dec013d0ab919ca7f412c6` | SQLi miss | SQLi hit, fingerprint `sc` | As above. |
| `raw-0075` | `35d086a03bd3f4508cb19796b772c6faadd39d3aa1e1969ddf130f9ab7a2e06d` | SQLi miss | SQLi hit, fingerprint `sc` | As above. |
| `raw-0227` | `dc7bb8a43bc5b39a14663709e677b83f978ba3c54c1425552de5e83e207cbf81` | SQLi miss | SQLi hit, fingerprint `sc` | As above. |
| `raw-0292` | `245ac590dddc9898908c6d974085e33488a08219c48957278145049618d69b38` | SQLi miss | SQLi hit, fingerprint `sc` | As above. |
| `raw-0365` | `58c14b7bcbc569d32c0a70b54939c2c97aa53d4cfd68e17f7e933d515bf87527` | SQLi miss | SQLi hit, fingerprint `sc` | As above. |
| `raw-0373` | `e27f2dcab16bfa5874e2ef0fc3d7702d363446029fdcab9a6d2c64bc8526d373` | SQLi miss | SQLi hit, fingerprint `sc` | As above. |
| `args-get-invalid-utf8-names` | `3c9133937f99186e0ef69373aef20e1a5382ce02ece6b94936da02a4c07cb95f` | `/?%ff=a&%fe=b` yields two `ARGS_GET` keys, the single bytes `0xff` and `0xfe` | The same target yields one `ARGS_GET` key, `U+FFFD`, with values `a` and `b` | Decoded parameter names are Rust `String`s, so invalid UTF-8 becomes `U+FFFD` and distinct byte names collide. Values stay byte-exact. The byte-key collection refactor is deferred; do not emulate byte identity with lossy lookups. |

## Deliberate deviation classes without engine case IDs yet

The detector ledger also records five deliberate classes. They have no Coraza
engine case ID or fixture hash yet, so they are not rows in the table above;
adding them requires a shared-corpus fixture first.

- `#` comment whitelist narrowed. Cases: `raw-0043`, `raw-0060`, `raw-0075`,
  `raw-0227`, `raw-0292`, `raw-0365`, `raw-0373`.
- `--` comment whitelist narrowed. Cases are pinned in
  `libperfusion/tests/regressions.rs`.
- Eight stacked-statement fingerprints added. Cases are pinned in
  `libperfusion/tests/regressions.rs`.
- Twenty dialect identifiers added. Cases are pinned in
  `libperfusion/tests/regressions.rs`.
- Twelve URL-bearing attributes and the `MATH` tag added. Cases are pinned in
  `libperfusion/tests/regressions.rs` and the two XSS corpus rows above.

## Row format

Every row has exactly five columns:

1. `Case ID`: stable corpus case identifier.
2. `Fixture SHA-256`: 64 lower-case hexadecimal characters over the exact input
   bytes.
3. `Expected Go`: observed or documented Go outcome.
4. `Expected Rust`: observed or documented Rust outcome.
5. `Reason`: why the difference is retained or what it records.

Allowed outcome vocabulary is deliberately loose because a case may compare
whole-transaction results rather than only a detector verdict. Use `hit` or
`miss` for detector outcomes; for engine cases include the interruption,
capture, score, flag or audit effect that differs. Do not leave an outcome
blank and do not write "unknown": an unreviewed case belongs in a test output,
not in this ledger.
