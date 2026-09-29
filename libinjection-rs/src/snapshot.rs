// Copyright Coraza Kubernetes Operator contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Fixed-size analysis output: no heap fields.
//! Spec: `docs/MODERNIZATION_PLAN.md` section [`AnalysisSnapshot`] API spec.

use crate::limits::MAX_EVIDENCE;

/// Stage-1 confidence hint for Coraza. Not a block/allow decision.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum VerdictHint {
    /// No interesting constructs (or prefilter miss).
    #[default]
    Benign = 0,
    /// Some constructs present; below built-in detect policy.
    Suspicious = 1,
    /// Constructs match policy, or fail-closed truncation requires blocking.
    Decisive = 2,
    /// Ambiguous, for example because the scan was truncated.
    Inconclusive = 3,
}

/// Quote context used for a `SQLi` pass (matches legacy multi-pass ideas).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SqliQuoteMode {
    /// Not inside a simulated string.
    #[default]
    None = 0,
    /// Treat input as starting inside single quotes.
    Single = 1,
    /// Treat input as starting inside double quotes.
    Double = 2,
    /// Treat input as starting inside backticks (MySQL-style).
    Backtick = 3,
}

/// HTML entry context for an XSS pass (libinjection five contexts).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum XssHtmlContext {
    /// Normal HTML data / text.
    #[default]
    Data = 0,
    /// Inside an unquoted attribute value.
    AttrUnquoted = 1,
    /// Inside a single-quoted attribute value.
    AttrSingle = 2,
    /// Inside a double-quoted attribute value.
    AttrDouble = 3,
    /// Inside a backtick-quoted attribute value.
    AttrBacktick = 4,
}

/// Dialect hint derived from stage-1 tokens and constructs.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SqlDialect {
    /// ANSI / generic SQL.
    #[default]
    Ansi = 0,
    /// MySQL-oriented (backticks, `#`, `/*!`).
    Mysql = 1,
    /// MSSQL-oriented (brackets, EXEC, etc.).
    Mssql = 2,
    /// Oracle-oriented (q-quote, dual, etc.).
    Oracle = 3,
}

/// Parse context recorded on one `AnalysisSnapshot`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AnalysisContext {
    /// `SQLi` quote mode for this analysis pass.
    pub sqli_quote_mode: SqliQuoteMode,
    /// XSS HTML entry context for this analysis pass.
    pub xss_html_context: XssHtmlContext,
    /// Best-effort SQL dialect hint from stage 1.
    pub dialect: SqlDialect,
}

/// Bitset of SQL/XSS constructs found in one analysis pass.
/// Primary signal for Coraza policy (not the legacy fingerprint).
///
/// `SQLi` uses bits 0 through 15. XSS uses bits 16 through 27.
/// Combine with `|`, test with [`ConstructFlags::intersects`] or masks.
///
/// # Examples
///
/// `SQL_UNION` is bit 0 (`0x0000_0001`). `XSS_TAG_SCRIPT` is bit 16 (`0x0001_0000`).
/// Together they are `0x0001_0001`:
///
/// ```
/// use libinjection::snapshot::ConstructFlags;
///
/// let bits = ConstructFlags::SQL_UNION | ConstructFlags::XSS_TAG_SCRIPT;
/// let flags = ConstructFlags(bits);
/// assert_eq!(flags.0, 0x0001_0001);
/// assert!(flags.any_sqli());
/// assert!(flags.any_xss());
/// ```
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ConstructFlags(pub u32);

impl ConstructFlags {
    /// Boolean logic with comparisons (blind `SQLi` style).
    pub const SQL_BOOLEAN_BLIND: u32 = 1 << 6;
    /// Comment markers used as injection glue (`--`, `#`, `/* */`).
    pub const SQL_COMMENT_INJECTION: u32 = 1 << 4;
    /// MSSQL-specific syntax hints.
    pub const SQL_DIALECT_MSSQL: u32 = 1 << 9;
    /// MySQL-specific syntax hints.
    pub const SQL_DIALECT_MYSQL: u32 = 1 << 8;
    /// Oracle-specific syntax hints.
    pub const SQL_DIALECT_ORACLE: u32 = 1 << 10;
    /// Dangerous or probing function calls (`SLEEP`, `LOAD_FILE`, ...).
    pub const SQL_FUNCTION_CALL: u32 = 1 << 5;
    /// Keyword chains such as `SELECT ... FROM` / `UNION ALL`.
    pub const SQL_KEYWORD_CHAIN: u32 = 1 << 11;
    /// Arithmetic / numeric injection patterns.
    pub const SQL_NUMERIC_INJECTION: u32 = 1 << 7;
    /// Semicolon-chained / stacked queries.
    pub const SQL_STACKED_QUERY: u32 = 1 << 3;
    /// Quote or comment used to break out of a string/context.
    pub const SQL_STRING_BREAK: u32 = 1 << 2;
    /// Tautology such as `OR 1=1` / `AND 'a'='a'`.
    pub const SQL_TAUTOLOGY: u32 = 1 << 1;
    // SQLi constructs (bits 0 through 15)

    /// `UNION` / `UNION ALL` style injection.
    pub const SQL_UNION: u32 = 1 << 0;
    /// Comment / IE / backtick style bypass tricks.
    pub const XSS_COMMENT_BYPASS: u32 = 1 << 24;
    /// `<!DOCTYPE>` related vector.
    pub const XSS_DOCTYPE: u32 = 1 << 25;
    /// Event handler attribute (`onclick`, `onerror`, ...).
    pub const XSS_EVENT_HANDLER: u32 = 1 << 20;
    /// Go/C-compatible HTML deny-list hit not covered by a narrower XSS bit.
    pub const XSS_HTML_DENYLIST: u32 = 1 << 26;
    /// CSS `expression(...)` style vectors.
    pub const XSS_STYLE_EXPRESSION: u32 = 1 << 23;
    /// `<iframe>` tag.
    pub const XSS_TAG_IFRAME: u32 = 1 << 17;
    /// `<object>` tag.
    pub const XSS_TAG_OBJECT: u32 = 1 << 18;
    // XSS constructs (bits 16 through 27)

    /// `<script>` (or equivalent) tag.
    pub const XSS_TAG_SCRIPT: u32 = 1 << 16;
    /// SVG-related tag family.
    pub const XSS_TAG_SVG: u32 = 1 << 19;
    /// `data:` URL scheme.
    pub const XSS_URL_DATA: u32 = 1 << 22;
    /// `javascript:` URL scheme.
    pub const XSS_URL_JAVASCRIPT: u32 = 1 << 21;

    /// No constructs set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// True if any `SQLi` bit (low 16) is set.
    #[must_use]
    pub const fn any_sqli(self) -> bool {
        (self.0 & 0x0000_FFFF) != 0
    }

    /// True if any XSS bit (bits 16 through 27) is set.
    #[must_use]
    pub const fn any_xss(self) -> bool {
        (self.0 & 0x0FFF_0000) != 0
    }

    /// True if any bit in `mask` overlaps this set.
    #[must_use]
    pub const fn intersects(self, mask: Self) -> bool {
        (self.0 & mask.0) != 0
    }
}

/// Status flags for normalize/parse (truncation, prefilter, legacy FP, ...).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AnalysisFlags(pub u16);

impl AnalysisFlags {
    /// `legacy_fingerprint` is valid (`legacy` feature path).
    pub const LEGACY_FP_AVAILABLE: u16 = 1 << 1;
    /// More than one quote/HTML context was tried.
    pub const MULTI_CONTEXT: u16 = 1 << 2;
    /// Fast prefilter found nothing interesting.
    pub const PREFILTER_MISS: u16 = 1 << 3;
    /// Token buffer filled (`MAX_TOKEN_SLOTS`).
    pub const TOKEN_LIMIT: u16 = 1 << 4;
    /// Input or norm buffer exceeded a cap; only a prefix was used.
    pub const TRUNCATED: u16 = 1 << 0;

    /// No status bits set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// True if `bit` is set in this flags word.
    #[must_use]
    pub const fn contains(self, bit: u16) -> bool {
        (self.0 & bit) != 0
    }
}

/// One evidence region in the original input slice.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct EvidenceSpan {
    /// Byte offset into the original input.
    pub offset: u16,
    /// Length in bytes from `offset`.
    pub len: u16,
}

/// Fixed set of evidence spans (at most [`MAX_EVIDENCE`]).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceSet {
    /// Span slots (only the first `count` are meaningful).
    pub spans: [EvidenceSpan; MAX_EVIDENCE],
    /// Number of valid spans in `spans`.
    pub count: u8,
}

impl Default for EvidenceSet {
    fn default() -> Self {
        Self {
            spans: [EvidenceSpan { offset: 0, len: 0 }; MAX_EVIDENCE],
            count: 0,
        }
    }
}

/// Legacy libinjection type-byte fingerprint (compat view for audit / corpus).
///
/// Not the primary signal; [`ConstructFlags`] is. Populated when `legacy` is enabled.
///
/// # Examples
///
/// ```
/// use libinjection::snapshot::LegacyFingerprint;
///
/// let empty = LegacyFingerprint::default();
/// assert!(empty.as_str().is_none());
///
/// let mut fp = LegacyFingerprint::default();
/// fp.bytes[0] = b'1';
/// fp.bytes[1] = b'&';
/// fp.bytes[2] = b'1';
/// fp.len = 3;
/// assert_eq!(fp.as_str(), Some("1&1"));
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct LegacyFingerprint {
    /// Fingerprint bytes (only `len` leading bytes are significant).
    pub bytes: [u8; 8],
    /// Significant length of `bytes` (0 means none).
    pub len: u8,
}

impl LegacyFingerprint {
    /// UTF-8 view of the significant fingerprint bytes, if any.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        if self.len == 0 {
            return None;
        }
        let end = usize::from(self.len);
        let bytes = self.bytes.get(..end)?;
        core::str::from_utf8(bytes).ok()
    }
}

/// Result of one stage-1 analysis pass over a single field value.
///
/// All evidence spans index into the original input passed to `analyze_*`.
/// Fixed-size and [`Copy`]: safe for the zero-heap hot path.
///
/// # Examples
///
/// ```
/// use libinjection::snapshot::{AnalysisSnapshot, VerdictHint};
///
/// let snap = AnalysisSnapshot::benign();
/// assert_eq!(snap.verdict_hint, VerdictHint::Benign);
/// assert!(!snap.constructs.any_sqli());
/// assert!(snap.legacy_fingerprint.as_str().is_none());
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnalysisSnapshot {
    /// SQL/XSS constructs found (primary signal).
    pub constructs: ConstructFlags,
    /// Normalize/parse status (truncation, prefilter, legacy FP, ...).
    pub flags: AnalysisFlags,
    /// Non-binding stage-1 hint for Coraza.
    pub verdict_hint: VerdictHint,
    /// Quote / HTML / dialect context for this pass.
    pub context: AnalysisContext,
    /// Up to [`MAX_EVIDENCE`] regions in the original input.
    pub evidence: EvidenceSet,
    /// Derived legacy fingerprint when `legacy` produced one.
    pub legacy_fingerprint: LegacyFingerprint,
}

impl AnalysisSnapshot {
    /// Empty/clean snapshot: no constructs, [`VerdictHint::Benign`].
    #[must_use]
    pub const fn benign() -> Self {
        Self {
            constructs: ConstructFlags::empty(),
            flags: AnalysisFlags::empty(),
            verdict_hint: VerdictHint::Benign,
            context: AnalysisContext {
                sqli_quote_mode: SqliQuoteMode::None,
                xss_html_context: XssHtmlContext::Data,
                dialect: SqlDialect::Ansi,
            },
            evidence: EvidenceSet {
                spans: [EvidenceSpan { offset: 0, len: 0 }; MAX_EVIDENCE],
                count: 0,
            },
            legacy_fingerprint: LegacyFingerprint { bytes: [0; 8], len: 0 },
        }
    }
}

impl Default for AnalysisSnapshot {
    fn default() -> Self {
        Self::benign()
    }
}

/// Built-in minimal policy result for `@detectSQLi` / `@detectXSS`.
///
/// `detected` is Coraza-facing convenience. Policy details live in `snapshot`.
///
/// # Examples
///
/// ```
/// use libinjection::snapshot::DetectionVerdict;
///
/// let v = DetectionVerdict::benign();
/// assert!(!v.detected);
/// assert_eq!(
///     v.snapshot,
///     libinjection::snapshot::AnalysisSnapshot::benign()
/// );
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DetectionVerdict {
    /// Whether the built-in detect policy matched.
    pub detected: bool,
    /// Full stage-1 analysis output.
    pub snapshot: AnalysisSnapshot,
}

impl DetectionVerdict {
    /// No detection; snapshot is [`AnalysisSnapshot::benign`].
    #[must_use]
    pub const fn benign() -> Self {
        Self {
            detected: false,
            snapshot: AnalysisSnapshot::benign(),
        }
    }
}
