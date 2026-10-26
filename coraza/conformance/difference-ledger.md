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
| `request-xml-root-selector` | `f707b8592127823f559f353e1bed7900ec284294e55b9a1e56d47d6eececcad5` | matches every XML entry, attributes included (empty regex) | matches the document's root children, exactly as XML:/* | Observed on both sides for the fixture `<a id="1">x</a>`: Go parses `REQUEST_XML:/*` as an empty regex and selects both XML entries (`//@*` and `/*`); this engine parses it as the XPath `/*` and selects the root children only. |
| `xml-lowercase-selector` | `f707b8592127823f559f353e1bed7900ec284294e55b9a1e56d47d6eececcad5` | matches every XML entry, attributes included (empty regex) | matches the document's root children, exactly as XML:/* | Observed on both sides for the fixture `<a id="1">x</a>` with `xml:/*` and `request_xml:/*`: Go matched `REQUEST_XML://@*` (`1`) and `REQUEST_XML:/*` (`x`), because its rule parser enters the path branch only for the exact spellings `XML` and `JSON` (`internal/seclang/rule_parser.go:124`) and sends every other spelling down its regex path; this engine folds the name case before the same guard (`coraza/src/seclang/variable_parser.rs:184-189`), so only `/*` matches. The folded guard also admits lower-case `json:` selectors, which Go's exact check does not. |

## Resolved differences

These rows were reviewed differences and have been removed from this engine. The
case ID and fixture hash are kept so the case stays traceable.

| Case ID | Fixture SHA-256 | Resolution |
| --- | --- | --- |
| `args-get-invalid-utf8-names` | `3c9133937f99186e0ef69373aef20e1a5382ce02ece6b94936da02a4c07cb95f` | Resolved end to end. URL-decoded query and form argument names are decoded to bytes in the transaction and stored byte-exactly, so `/?%ff=a&%fe=b` yields two `ARGS_GET` keys, the single bytes `0xff` and `0xfe`, with values `a` and `b`, and the same names in a URL-encoded body yield two `ARGS_POST` keys. Go Coraza v3.8.1 reports the same keys. Argument collections match Go's default key case behavior: keyed lookups fold case, while stored keys keep their original bytes and spelling, so case folding never merges two distinct byte keys. `WafConfig::case_sensitive_args_keys` defaults to `false` and is the equivalent of Go's `coraza.rule.case_sensitive_args_keys` build tag: when enabled, only `ARGS`, `ARGS_GET`, `ARGS_POST`, `ARGS_PATH` and their `*_NAMES` views become case-sensitive, while files, multipart, XML, `RESPONSE_ARGS`, `TX`, `RULE` and `ENV` stay case-insensitive as in Go. Text interfaces use a lossy view but do not decide which entries exist. |
| `json-invalid-utf8-keys` | `5475fd660355bbc435ec9208d8cb01b6cb2206e28a7ad500af8ff4b4782d9a05` | Resolved end to end. Flattened JSON argument keys are published to `ARGS_POST`, `ARGS` and `RESPONSE_ARGS` as the exact key bytes instead of a lossy `String`, so `{"k\xff":1,"k\xfe":2}` yields two distinct keys, `json.k\xff` and `json.k\xfe`, with values `1` and `2`. Go Coraza v3.8.1 reports the same keys. JSON parsing, flattening order, budgets and error semantics are unchanged, and values and `TX.json_request_body`/`TX.json_response_body` stay byte-exact. |
| `transform-base64decodeext-forgiving` | `d0db3a9154efe2f64b3fdad2f2cb8be26f6561e1679b0be302ab805adfe1109f` | Resolved. `t:base64DecodeExt` now skips bytes outside the Base64 alphabet instead of stopping at the first one, and maps the base64url `-` and `_` characters to `+` and `/`, matching Go Coraza v3.8.1. `\xc2\xa9dzBzV==` decodes to `w0s` on both sides; URL-safe tokens and invalid bytes between valid groups decode identically. The strict `t:base64Decode` behavior is unchanged: it still returns partial output up to the first invalid byte. Padding, decoded NUL bytes and the always-true changed flag are unchanged. |
| `transform-jsdecode-braced-escape` | `00ba0dfd13fd6810393903d8cf8459be76bab3b0adaf13e7331c38e4bfaec3f8` | Resolved. `t:jsDecode` now decodes ES2015 `\u{H...H}` escapes of one to six hex digits in addition to the four-digit `\uHHHH` form, so `\u{41}` becomes `A` on both sides. Go's lower-byte truncation and full-width ASCII fold, checked against the resolved value, are preserved: supplementary values such as `\u{1F600}` and out-of-range scalars such as `\u{110000}` both collapse to `0x00`, and empty, over-long or unterminated bodies fall back to the simple escape. |
| `transform-compresswhitespace-latin1` | `a2ad3a1ec45ebe0d391a75c57add9aec844e37d912f04c64dc6f5950f90bc458` | Resolved. `t:compressWhitespace` now collapses only ASCII whitespace, U+0085, U+00A0 and a stray `0xA0` byte, matching Go Coraza v3.8.1, instead of using full Unicode whitespace. U+3000 and the other Unicode spaces are preserved, malformed bytes are copied unchanged, and `SELECT\xa01` becomes `SELECT 1` on both sides. `t:removeWhitespace` still uses full Unicode whitespace, as in Go. |
| `multipart-invalid-utf8-names` | `198682754b8b93bd8c634406ae9ecab9b3648501a8124adac6729219e88170a8` | Resolved end to end. Multipart part names are stored as bytes through parsing and published with `Map::add_bytes`, so two names that differ only in invalid UTF-8 bytes (`\xff` and `\xfe`) stay two distinct `ARGS_POST` keys and two distinct `MULTIPART_NAME` keys, and the lossy U+FFFD text is not a key. Go Coraza v3.8.1's `p.FormName()` returns the same raw bytes. Lossy text remains only as a view (text getters, MIME type, audit filename) and does not decide which entries exist. Pinned by `field_names_that_are_not_utf8_are_distinct_keys` in `coraza/src/transaction/request_body.rs`, whose body bytes are the fixture. |
| `multipart-invalid-utf8-file-names` | `fae6fadf266f0431b5c290e9223eb9793389b2ad5001ea1f04fd8ca778a51966` | Resolved end to end. File part names that differ only in invalid UTF-8 bytes are kept as bytes too: `FILES_NAMES` stores both names as two values under the empty key, matching Go Coraza v3.8.1's `filesNamesCol.Add("", p.FormName())`, while `MULTIPART_NAME` and `MULTIPART_FILENAME` keep the two names as distinct byte keys. This fixture's filenames are ASCII (`a.txt`, `b.txt`), so invalid-UTF-8 `filename*` decoding is not covered here. Pinned by `file_part_names_that_are_not_utf8_are_distinct_keys` in `coraza/src/transaction/request_body.rs`, whose body bytes are the fixture. |

## Remaining byte-identity restrictions

No known byte-identity restrictions remain in the reviewed fixtures as of this revision.

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
- Capture reset before each rule. `TX:0` through `TX:10` are seeded empty on every
  transaction, as Go Coraza does (`internal/corazawaf/waf.go:264-268`), but this
  engine clears `TX:0` through `TX:9` before every rule. Go's `resetCaptures`
  (`internal/corazawaf/transaction.go:477`) is only called by its tests, so a Go
  rule can read the previous rule's captures while a Rust rule cannot. This is a
  deliberate deviation with no engine case ID or fixture hash yet.
- Detector input bound. The `detectSQLi` and `detectXSS` operators use
  libperfusion's public wrappers, which do not scan inputs longer than 65536 bytes;
  Go Coraza passes any length to libinjection-go. The operators report
  `OperatorOutcome::NotInspected` for these inputs, the transaction sets
  `TX.inspection_incomplete` to `"1"` and `Transaction::inspection_incomplete()`
  returns true, and `WafConfig::detector_inspection_action` defaults to
  `RecordOnly`, which keeps the miss verdict and the signal. `FailClosed`
  interrupts the transaction instead. No partial scan, splitting or chunking is
  performed.

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
