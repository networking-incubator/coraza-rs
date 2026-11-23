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
| `xss-nul-unquoted-value-boundary` | `705b7a0091fb18e44c6683300e022e8b9c5da00e7617875046b4d7d7da04a771` | XSS miss | XSS hit | Rust adds a NUL-as-space second pass, so `<a href=x\0onerror=alert(1)>` exposes the event attribute. The pinned C reference also flags it; Go misses it. |
| `raw-0265` | `8ceda65b55dbd3d4557ea3eef1d140660fb28d983b86b9ce8aa3111aecb3205a` | SQLi miss | SQLi hit, fingerprint `son1o` | Narrowed `#` comment whitelist; `#` is followed by additional bytes and the input ends with `a*`, not a trailing comment. |
| `raw-0043` | `1cdd835eb77c2bd1acb9003388a4c91e9b294fd01a2fed1b7701b1381f84701a` | SQLi miss | SQLi hit, fingerprint `sc` | Narrowed `#` comment whitelist; minimizes to a `#` shape. |
| `raw-0060` | `f39efb68b9bee584cd30dcf85698b40f92cd709d48dec013d0ab919ca7f412c6` | SQLi miss | SQLi hit, fingerprint `sc` | As above. |
| `raw-0075` | `35d086a03bd3f4508cb19796b772c6faadd39d3aa1e1969ddf130f9ab7a2e06d` | SQLi miss | SQLi hit, fingerprint `sc` | As above. |
| `raw-0227` | `dc7bb8a43bc5b39a14663709e677b83f978ba3c54c1425552de5e83e207cbf81` | SQLi miss | SQLi hit, fingerprint `sc` | As above. |
| `raw-0292` | `245ac590dddc9898908c6d974085e33488a08219c48957278145049618d69b38` | SQLi miss | SQLi hit, fingerprint `sc` | As above. |
| `raw-0365` | `58c14b7bcbc569d32c0a70b54939c2c97aa53d4cfd68e17f7e933d515bf87527` | SQLi miss | SQLi hit, fingerprint `sc` | As above. |
| `raw-0373` | `e27f2dcab16bfa5874e2ef0fc3d7702d363446029fdcab9a6d2c64bc8526d373` | SQLi miss | SQLi hit, fingerprint `sc` | As above. |
| `request-xml-root-selector` | `f707b8592127823f559f353e1bed7900ec284294e55b9a1e56d47d6eececcad5` | matches every XML entry, attributes included (empty regex) | matches all text segments stored under `/*`, exactly as XML:/* | Observed on both sides for the fixture `<a id="1">x</a>`: Go's regex path drops the trailing byte of a selector with no closing slash, so `REQUEST_XML:/*` parses as the empty regex and selects both XML entries (`//@*` and `/*`); this engine parses it as the XPath `/*` and selects only the text segments stored under that literal key. Every XML/JSON selector Go's regex path leaves empty collapses the same way, such as `/*`, `/x` and `//`. |
| `xml-lowercase-selector` | `f707b8592127823f559f353e1bed7900ec284294e55b9a1e56d47d6eececcad5` | matches every XML entry, attributes included (empty regex) | matches all text segments stored under `/*`, exactly as XML:/* | Observed on both sides for the fixture `<a id="1">x</a>` with `xml:/*` and `request_xml:/*`: Go matched `REQUEST_XML://@*` (`1`) and `REQUEST_XML:/*` (`x`), because its rule parser enters the path branch only for the exact spellings `XML` and `JSON` (`internal/seclang/rule_parser.go:124`) and sends every other spelling down its regex path, where a selector with no closing slash loses its last byte and `/*` becomes the empty regex; this engine folds the name case before the same guard (`coraza/src/seclang/variable_parser.rs:184-189`), so only the text segments stored under `/*` match. The folded guard also admits lower-case `json:` selectors, which Go's exact check does not. |

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
| `multipart-empty-header-part` | `2533e650bf3459e0419a0749ce9882e2bc4b99c4c36c9b6c094b3866a9a6cbc1` | Resolved end to end. A part with an empty header block, its delimiter line followed directly by a blank line as RFC 2046 allows, is published as the nameless field `ARGS_POST[""]` and the parts after it are parsed. Go Coraza v3.8.1 does the same: `textproto.ReadMIMEHeader` returns an empty header and `NextPart` reads on. The parser required a header line before the blank line, so it reported `malformed MIME header: no blank line after headers` and stopped. The SQL injection in the later `q` field was never inspected, and a policy without a rule on `REQBODY_ERROR` or `MULTIPART_STRICT_ERROR`, such as the CRS alone, allowed the request while Go blocked it. Observed on both sides with Go Coraza's unchanged v3.8.1 multipart processor. Pinned by `an_empty_header_part_does_not_hide_the_fields_after_it` in `coraza/src/transaction/request_body.rs`, whose body bytes are the fixture. |
| `multipart-empty-header-part-lf` | `b4e4de505591552e9cefb83977eb47a54e63f48531d64a8af0aedf151e3417a2` | Resolved end to end. The same shape with bare LF line endings. In LF mode the parser could instead end the header block at a later blank line, silently dropping the part content. Go reads the leading blank line as the empty header block, and the parser now does too, so `MARK1 headerless` is the nameless field's value and `q` is inspected. Pinned by `an_empty_header_part_in_lf_mode_does_not_hide_the_fields_after_it` in `coraza/src/transaction/request_body.rs`, whose body bytes are the fixture. |

## Remaining byte-identity restrictions

No known byte-identity restrictions remain in the reviewed fixtures as of this revision.

## Deliberate deviation classes without engine case IDs yet

The detector ledger also records six deliberate classes. They have no Coraza
engine case ID or fixture hash yet, so they are not rows in the table above;
adding them requires a shared-corpus fixture first.

- `#` comment whitelist narrowed. Cases: `raw-0043`, `raw-0060`, `raw-0075`,
  `raw-0227`, `raw-0292`, `raw-0365`, `raw-0373`.
- `--` comment whitelist narrowed. Cases are pinned in
  `libperfusion/tests/regressions.rs`.
- Eight stacked-statement fingerprints added. Cases are pinned in
  `libperfusion/tests/regressions.rs`.
- Dialect identifiers added to the `@detectSQLi` fallback: sixteen on a retry after a
  default-table miss, and `ATTACH`, `COPY`, `DETACH` and `VACUUM` only as a statement
  directly after `;`. Default `sqli()` is unchanged. Cases are pinned in
  `libperfusion/tests/regressions.rs`.
- Twelve URL-bearing attributes and the `MATH` tag added. Cases are pinned in
  `libperfusion/tests/regressions.rs` and the two XSS corpus rows above.
- `1&n` fingerprint added; three-token suppression kept only for `s&n` and `n&1`.
  `@detectSQLi` flags short numeric booleans such as `1 or id`, `1 or 1` and
  `1 or 2`, including the false positives `5 or more` and `2019 or 2020`. Cases are
  pinned in `libperfusion/tests/regressions.rs`.
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
  engine clears `TX:0` through `TX:9` before every rule, so `TX:10` persists just
  as it does under Go's reset of `TX:0` through `TX:9`. Go's `resetCaptures`
  (`internal/corazawaf/transaction.go:477`) is only called by its tests, so a Go
  rule can read the previous rule's captures while a Rust rule cannot. This is a
  deliberate deviation with no engine case ID or fixture hash yet.
- Empty-regex `KeyStr` collapse. Go's rule parser drops the last byte of a
  regex selector that has no closing slash, so `ARGS://` compiles to the empty
  regex `//` and selects every argument through `FindRegex`, while `ARGS:/`
  becomes an empty `KeyStr` and selects every argument through Go's `FindAll`
  arm; `!ARGS://` excludes every argument. This engine treats `//` and `/` as
  literal keys, so they select nothing. This is a pre-existing selector-parser
  deviation (`coraza/src/seclang/variable_parser.rs::parse_key`) with no engine
  case ID or fixture hash yet.
- Multiphase negation is scoped by family: `!ARGS_NAMES:x` no longer removes
  `ARGS_GET:x`/`ARGS_POST:x`, and `!ARGS:x` no longer removes the `*_NAMES`
  views. Go's `AddVariableNegation` applies the cross product
  (`internal/corazawaf/rule.go:615-619,645-650` in v3.8.1); Go's own
  `RemoveRuleTargetByID` maps by family (`transaction.go:721-745`), as this
  engine's `ctl:ruleRemoveTarget*` path does. Both paths now share
  `RuleVariable::multiphase_split`, and for a rule that lists `ARGS` or
  `ARGS_NAMES` the result equals multiphase off. On a rule that lists a split
  variable itself (`ARGS_GET`), `!ARGS:x` still removes `ARGS_GET:x` under
  multiphase only, as in Go. CRS's
  `SecRuleUpdateTargetById 930120 "!ARGS_NAMES:/^json\.profile[.\w\-]*$/"` keeps
  the value of `json.profile` inspected.
- `!@rx` compiles without the multi-line flag, so `^` and `$` anchor the whole
  value and one matching line does not satisfy a negated allow-list. Go prepends
  `(?sm)` to every text pattern unless built with `coraza.rule.no_regex_multiline`
  (`internal/operators/rx.go:65-78`). A positive `@rx` keeps `(?sm)`. Dropping the
  flag only makes a pattern match less, so a negated rule only fires more: CRS
  920120 fires on a file name with a literal `%0a`, 942200 and 942440 on
  multi-line text.
- Byte-path `@rx` (a pattern with a `\xHH` escape that is not valid UTF-8) is
  dot-all and takes the same multi-line choice. Go's `newBinaryRX` compiles the
  raw pattern without flags (`internal/operators/rx.go:186-194`). This reverses
  the S-17 alignment of commit `e66a6a0`; CRS 933180 sees `$f(` and `)` split by
  a newline.
- `t:cmdLine` removes the backtick as it removes `"`, `'`, `\` and `^`; Go's
  `cmdLine` keeps it (`internal/transformations/cmd_line.go:45`). One backtick
  of a run stays, as in Go, in three cases only: when the next byte after it
  that `t:cmdLine` neither removes nor treats as a backtick is `~`
  (``a ` ~+`` becomes `a ~+`); when the run is all that is between a `(` already
  written and the next written `)`, or between a `[` already written and the
  next written `]`; and when the last byte written before the run is `%`.
  Second case:
  ```$(``)``` becomes ``$(`)`` and ```/e[^``^]c``` becomes ``/e[`]c``, so 932130
  (PL1), and 932131 (PL2) in `User-Agent` and `Referer`, still match
  ```;c$(``)at /e$(``)tc/pa$(``)sswd```, ```who$(``)ami``` and
  ```cat /e[^``^]c/passwd``` as in Go, because their `[^\)]+` needs a byte inside
  `$(...)` and their glob branch, `[^\]]+`, a byte inside `/e[...]`. Bash runs
  the empty substitution as nothing, so ```/e[^``^]c``` is the glob `/e[^^]c`,
  which matches `/etc`. A byte written between them, a space too, ends that case
  (```$( `` )``` becomes `$( )`, which `[^\)]+` matches). ```${``}``` keeps no
  backtick: bash rejects it (`bad substitution`). Third case, whatever follows
  the run: ``for %` in (x) do calc``
  becomes ``for %` in(x) do calc`` and the batch form ``for %%` in (x) do calc``
  keeps its backtick too, so 932140 (PL1) still matches `%+[^ ]+ in\(` as it
  does with the previous `t:cmdLine`. Windows takes any character that is not a
  digit as a FOR loop variable, a backtick included, so the shape is a real
  command. A removed byte between the `%` and the run does not end the case
  (``%^` in`` keeps it); a written byte, a space too, does.
  PowerShell's in-word escape (``Invoke`-`Expression``) and bash's empty pair
  (```c``at```) normalize like the plain command, and so does a backtick before
  a Windows keyword: CRS 932140 (PL1) needs the space or `)` directly before
  `in(`, `do`, `defined` and `exist`, and catches
  ``cmd /c "if `defined x calc"`` and
  ``cmd /c "for /f %i `in ('whoami') `do calc"`` (Go misses both). Only rules
  with `t:cmdLine` benefit: ```who``ami``` and `who$()ami` still pass CRS at
  PL1. CRS 932270 reads the backtick before `~` as a command start, so
  `` `~+` ``, ``a`~+` ``, ``a`"~+`` and ``cd`~-`` match it at PL1 (keeping every
  backtick, as Go does, misses the first two). Known miss: 932238 (critical, 5
  points at PL3 and PL4) no longer sees a backtick command start, which Go
  matches: ``echo `whoami` ``, ``x;`whoami` ``, ``foo`whoami` ``,
  ``a:`whoami` ``. A backtick at a word start cannot be kept for it: it would
  sit between the space and the keyword of 932140, a PL1 bypass, and in a word
  it has the bytes of ``Proc`ess``. These requests still block: the `whoami`
  examples at PL1 through 932235, 932260 and 932380, and ``a:`ps aux` `` from
  PL2 (it passes PL1 as in Go). A backtick right after a `%` is kept, so 932238
  still sees ``echo %`whoami` ``. Still open: only the empty pair ``` `` ```
  is normalized. A substitution that prints nothing (`` `~` ``, `` `:` ``,
  `` `true` ``, `$()`) still hides the word from the `t:cmdLine` rules:
  ``;c`~`at /e`~`tc/pa`~`sswd``, ``;c`:`at /e`:`tc/pa`:`sswd`` and
  `;c$()at /e$()tc/pa$()sswd` pass CRS at PL1 here and in Go, and block from
  PL2. Closing that needs a rule change.
- XML entities, DOCTYPEs, directives, comments and instructions. Go Coraza's
  XML processor reads with `Strict` off: it publishes a reference to an
  undeclared entity such as `&p;` as written and skips directives, comments and
  processing instructions whole, so `<!DOCTYPE a [<!ENTITY p "...">]><a>&p;</a>`
  is accepted with `&p;` in `XML:/*` (observed with the Go oracle) while an
  entity-expanding backend reads the payload. This engine refuses the document
  with `REQBODY_ERROR`: a complete reference to an entity that is not
  predefined or HTML's (`invalid character entity &p;`, Go's `Strict` wording),
  a name past ASCII included; a DOCTYPE with an internal subset, an external
  identifier, a literal or a markup declaration, its root name glued to the
  keyword or not, a word or another character before or after its root name but
  blanks, comments and the closing `>`, or a root name that is not an XML name,
  by the check an element's name gets (`<!DOCTYPE 1abc>`, `<!DOCTYPE -r>`, invalid UTF-8, a character Go's name tables lack); any other directive, and any directive
  after the first element; and a control character, U+FFFE or U+FFFF in a
  comment or instruction, and a `--` inside a comment in a DOCTYPE (Go skips a
  comment in a directive without that check, and refuses one between tags
  too).
  libxml2 in recover mode reads the subset of
  `<!DOCTYPEa [...]>`, before 2.15 skips just the quote of a DOCTYPE literal
  and reads what follows as a subset or the root element, and reads what such a
  directive or comment holds as markup
  (`coraza/src/body_processors/xml/decoder.rs`). Under a body memory budget an
  error that quotes the document (an undeclared entity, an invalid name, the
  version or encoding of a declaration) is a stop for the budget, not this
  error, where the budget has no room for its message: the values read stay,
  and a host that refuses a budget stop refuses it, whatever its rules.
- XML bodies that end inside a token. Go Coraza accepts `unexpected EOF`
  anywhere (for `ProcessPartial`) and drops the token the input ends in: the
  attributes of a start tag, the text before a reference, or a comment,
  instruction or directive, so `<r a="..." b="...` or `<r>... &amp` publishes
  nothing while libxml2 in recover mode keeps the attribute or the text. This
  engine refuses such a body with `REQBODY_ERROR` (`unexpected EOF`, Go's
  wording) unless a body limit discarded the rest of it, and accepts, as Go
  does, one that ends between tags with elements open. Where a body limit cut
  the body, it publishes what the token had read and Go drops: the complete
  attributes of a start tag, the part of an attribute value up to the cut,
  quoted or not, and the text before a reference, the reference as written.
  Where the cut is in a CDATA section (`unexpected EOF in CDATA section`) or in
  a UTF-8 character of text or of a quoted value (`invalid UTF-8`), it is Go's
  syntax error. Where it is in a reference and the text it ends, the reference as
  written included, holds a forbidden character or broken UTF-8 (`&\xc3`,
  `\0 &am`, `&\xef\xbf\xbe`, a name holding U+FFFE), it is refused for that,
  a deliberate deviation: Go accepts the body there (`unexpected EOF`) and
  drops the text, and this engine fails closed. A cut inside a comment, instruction, DOCTYPE, element name or
  attribute name is accepted, as in Go, when the unexpected EOF is the only error in the bytes before it: a
  forbidden character, a `--` inside a comment, a word after a DOCTYPE's root name (`<!DOCTYPE r extra`, with no
  delimiter after it yet; the root name itself, or a blank after it, is accepted), a root name that is no XML name once a blank, `>` or
  comment ends it (`<!DOCTYPE 1abc `; cut inside it, `<!DOCTYPE 1ab`, it is accepted), a character before it that is no blank, comment or
  name (`<!DOCTYPE @`), a directive whose first word, cut at its end, is not the start of `DOCTYPE` in any case
  (`<!ELE`, `<!ENTI`; `<!DOC` and `<!doct` are accepted, as is `DOCTYPE` with a root name glued to it), an invalid name
  that ends before the cut (a name is checked once it is complete, so a cut inside one is accepted) or any other syntax error there refuses the body, as it refuses the
  whole document. A comment, instruction or directive
  publishes nothing, cut or whole, and neither does a bare attribute name or an
  element name the cut ended in (`coraza/src/body_processors/xml/mod.rs`).
- XML value count. Go Coraza publishes every XML attribute and text value; this
  engine stops at `SecArgumentsLimit` values, keeps those, and sets
  `ARGUMENTS_LIMIT_REACHED` and `REQBODY_ERROR`. The values committed before the
  stop stay, but the attributes of a start tag the limit interrupts are not
  kept, the ones that fit the limit included, so the collection can end below
  the limit: at a limit of two, a text value and then a start tag with two
  attributes leave just the text value (`coraza/src/body_processors/xml/mod.rs`).

## Rust-only multipart parser hardening budgets

The multipart parser fails closed with `ParseError::Limit` when a body exceeds
a budget the pinned Go reference does not enforce. Go Coraza v3.8.1's
`internal/bodyprocessors/multipart.go` reads parts with Go's
`mime/multipart.Reader.NextPart` loop. The caller reports a limit as
`malformed multipart: limit exceeded: ...` and sets `MULTIPART_STRICT_ERROR`,
so rule 200003 interrupts a body Go would process. As in Go's loop, the parts
read before the limit are still published to `ARGS_POST`, `FILES` and the
multipart metadata before the error is reported. These are hardening limits,
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
