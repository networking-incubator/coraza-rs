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
| `json-invalid-utf8-keys` | `5475fd660355bbc435ec9208d8cb01b6cb2206e28a7ad500af8ff4b4782d9a05` | `{"k\xff":1,"k\xfe":2}` yields two `ARGS_POST` keys with the byte sequences `json.k\xff` and `json.k\xfe` | The same body yields one `ARGS_POST` key, `json.k` followed by `U+FFFD`, with values `1` and `2` | Flattened JSON keys are Rust `String`s, so invalid UTF-8 key bytes become `U+FFFD` and distinct byte keys collide; both values are still published. Values and `TX.json_request_body`/`TX.json_response_body` stay byte-exact on both sides. |

## Resolved differences

These rows were reviewed differences and have been removed from this engine. The
case ID and fixture hash are kept so the case stays traceable.

| Case ID | Fixture SHA-256 | Resolution |
| --- | --- | --- |
| `args-get-invalid-utf8-names` | `3c9133937f99186e0ef69373aef20e1a5382ce02ece6b94936da02a4c07cb95f` | Resolved end to end. URL-decoded query and form argument names are decoded to bytes in the transaction and stored byte-exactly, so `/?%ff=a&%fe=b` yields two `ARGS_GET` keys, the single bytes `0xff` and `0xfe`, with values `a` and `b`, and the same names in a URL-encoded body yield two `ARGS_POST` keys. Go Coraza v3.8.1 reports the same keys. Text interfaces use a lossy view but do not decide which entries exist. |

## Remaining byte-identity restrictions

- Multipart part names still pass through lossy text decoding in the multipart
  body processor (`String::from_utf8_lossy` in
  `coraza/src/body_processors/multipart/parser.rs`), so names that are not
  valid UTF-8 can still collide in `ARGS_POST`. URL-decoded query, form and
  connector-supplied path names preserve their bytes.

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
- Body-limit `Reject` under `SecRuleEngine DetectionOnly`. Go Coraza sets a blocking
  interruption even in detection-only mode; this port records
  `would_be_interruption` and inspects the bytes retained up to the limit.
- Zero body limits. Go Coraza refuses `SecRequestBodyLimit 0`,
  `SecRequestBodyInMemoryLimit 0` and `SecResponseBodyLimit 0` during configuration
  validation; this port accepts zero, treats any non-empty body as over the limit while
  an empty body bypasses the check, and uses `SecRequestBodyInMemoryLimit 0` as the
  sentinel for "unset", where the effective memory limit follows `SecRequestBodyLimit`.
  Go instead rejects an explicit zero and distinguishes unset only through its nullable
  configuration value.
- `SecRequestBodyNoFilesLimit` is accepted, validated and documented as not enforced,
  matching Go Coraza v3.8.1 (`internal/corazawaf/waf.go:120`, corazawaf/coraza#896).
  No admission decision depends on it on either side.

## Rust-only multipart parser hardening budgets

The multipart parser fails closed with `ParseError::Limit` when a body exceeds
a budget the pinned Go reference does not enforce. Go Coraza v3.8.1's
`internal/bodyprocessors/multipart.go` reads parts with Go's
`mime/multipart.Reader.NextPart` loop. The caller reports a limit as
`malformed multipart: limit exceeded: ...` and sets `MULTIPART_STRICT_ERROR`,
so rule 200003 interrupts a body Go would process. These are hardening limits,
not parity claims; no shared-corpus case IDs exist yet.

- Boundary length: 1024 bytes. Go has no boundary-length check in
  `mime.ParseMediaType` or `mime/multipart`; its 4096-byte read buffer makes a
  delimiter line longer than about 4090 bytes fail instead. Rust rejects a
  longer boundary before parsing. RFC 2046 limits boundaries to 70 characters.
- Part count: 1000. Go Coraza calls `mime/multipart.Reader.NextPart`
  (`internal/bodyprocessors/multipart.go`), which has no part limit; the Go
  standard library's `Reader.ReadForm` caps a form at 1000 parts
  (`mime/multipart/formdata.go`), and Rust adopts that constant.
- Per-part header block: 10 MiB of raw header bytes and 10000 header lines.
  The constants come from Go's `maxMIMEHeaderSize` and the default
  `multipartmaxheaders` value (`mime/multipart/multipart.go`, Go 1.27.3). Go
  charges the 10 MiB as key bytes plus value bytes plus 200 bytes per distinct
  header; Rust caps raw header bytes with the same constant.
- Total header metadata: 10 MiB of raw header bytes summed across every part.
  Rust-only: Go Coraza accumulates all parts' headers in
  `MULTIPART_PART_HEADERS` without a whole-body budget.

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
