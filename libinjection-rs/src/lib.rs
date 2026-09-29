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

#![cfg_attr(not(feature = "std"), no_std)]

//! SQL injection and XSS analysis for WAF hot paths (Coraza).
//!
//! Stage 1 returns a fixed-size [`AnalysisSnapshot`] (zero heap).
//! [`detect_sqli`] / [`detect_xss`] apply a built-in minimal policy for
//! Coraza operators `@detectSQLi` / `@detectXSS`. Scan budget defaults are in
//! [`limits`]; override via [`AnalyzeOptions`] (Coraza policy, not request input).

pub mod error;
pub mod flags;
pub mod limits;
pub mod options;
pub mod snapshot;

mod engine;
mod policy;
mod sqli;
mod xss;

pub use flags::SqliFlags;
pub use limits::{
    ABSOLUTE_MAX_INPUT_LEN, DEFAULT_MAX_INPUT_LEN, MAX_EVIDENCE, MAX_INPUT_LEN, MAX_STACK_BUDGET, MAX_TOKEN_SLOTS,
    NORM_BUF_LEN, clamp_max_input_len, scan_prefix,
};
pub use options::{AnalyzeOptions, TruncationPolicy};
pub use snapshot::{
    AnalysisContext, AnalysisFlags, AnalysisSnapshot, ConstructFlags, DetectionVerdict, EvidenceSet, EvidenceSpan,
    LegacyFingerprint, SqlDialect, SqliQuoteMode, VerdictHint, XssHtmlContext,
};

/// Primary hot-path `SQLi` analysis.
///
/// Uses [`AnalyzeOptions::default`] (`DEFAULT_MAX_INPUT_LEN`).
#[must_use]
pub fn analyze_sqli(input: &[u8]) -> AnalysisSnapshot {
    analyze_sqli_with(input, AnalyzeOptions::default())
}

/// `SQLi` analysis with a caller scan budget.
#[must_use]
pub fn analyze_sqli_with(input: &[u8], opts: AnalyzeOptions) -> AnalysisSnapshot {
    let (slice, truncated) = scan_prefix(input, opts.effective_max_input_len());
    finish_sqli_snapshot(sqli::modern::analyze(slice, opts), truncated, opts.truncation_policy)
}

/// XSS analysis with a caller scan budget.
#[must_use]
pub fn analyze_xss_with(input: &[u8], opts: AnalyzeOptions) -> AnalysisSnapshot {
    let (slice, truncated) = scan_prefix(input, opts.effective_max_input_len());
    finish_xss_snapshot(xss::modern::analyze(slice, opts), truncated, opts.truncation_policy)
}

/// Primary hot-path XSS analysis.
#[must_use]
pub fn analyze_xss(input: &[u8]) -> AnalysisSnapshot {
    analyze_xss_with(input, AnalyzeOptions::default())
}

/// Built-in minimal policy for Coraza `@detectSQLi`.
#[must_use]
pub fn detect_sqli(input: &[u8]) -> DetectionVerdict {
    detect_sqli_with(input, AnalyzeOptions::default())
}

/// Coraza `@detectSQLi` with caller scan budget.
#[must_use]
pub fn detect_sqli_with(input: &[u8], opts: AnalyzeOptions) -> DetectionVerdict {
    let (slice, truncated) = scan_prefix(input, opts.effective_max_input_len());
    #[cfg(feature = "legacy")]
    let mut snapshot = finish_sqli_snapshot(sqli::modern::analyze(slice, opts), truncated, opts.truncation_policy);
    #[cfg(not(feature = "legacy"))]
    let snapshot = finish_sqli_snapshot(sqli::modern::analyze(slice, opts), truncated, opts.truncation_policy);

    let construct_hit = snapshot.constructs.intersects(policy::BUILTIN_SQLI_DETECT);

    #[cfg(feature = "legacy")]
    let legacy_hit = {
        let mut hit = merge_legacy_sqli(&mut snapshot, slice);
        if truncated && !hit {
            hit = merge_legacy_sqli(&mut snapshot, input);
            if !hit && !construct_hit && opts.truncation_policy == TruncationPolicy::AllowInconclusive {
                snapshot.verdict_hint = VerdictHint::Inconclusive;
            }
        }
        hit
    };

    #[cfg(not(feature = "legacy"))]
    let legacy_hit = false;

    let truncation_hit = truncated && opts.truncation_policy == TruncationPolicy::FailClosed && !legacy_hit;
    let detected = construct_hit || legacy_hit || truncation_hit;
    DetectionVerdict { detected, snapshot }
}

/// Built-in minimal policy for Coraza `@detectXSS`
#[must_use]
pub fn detect_xss(input: &[u8]) -> DetectionVerdict {
    detect_xss_with(input, AnalyzeOptions::default())
}

/// Coraza `@detectXSS` with caller scan budget.
#[must_use]
pub fn detect_xss_with(input: &[u8], opts: AnalyzeOptions) -> DetectionVerdict {
    let (slice, truncated) = scan_prefix(input, opts.effective_max_input_len());
    let mut snapshot = finish_xss_snapshot(xss::modern::analyze(slice, opts), truncated, opts.truncation_policy);

    let construct_hit = snapshot.constructs.intersects(policy::BUILTIN_XSS_DETECT);
    let legacy_hit = if truncated && !construct_hit {
        let hit = xss::legacy::detect(input);
        if hit {
            snapshot.constructs.0 |= ConstructFlags::XSS_HTML_DENYLIST;
            snapshot.verdict_hint = VerdictHint::Decisive;
        } else if opts.truncation_policy == TruncationPolicy::AllowInconclusive {
            snapshot.verdict_hint = VerdictHint::Inconclusive;
        }
        hit
    } else {
        false
    };

    let truncation_hit = truncated && opts.truncation_policy == TruncationPolicy::FailClosed && !legacy_hit;
    let detected = construct_hit || legacy_hit || truncation_hit;
    DetectionVerdict { detected, snapshot }
}

/// Apply scan truncation flags and refresh verdict hint for `SQLi`.
fn finish_sqli_snapshot(
    mut snap: AnalysisSnapshot,
    truncated: bool,
    truncation_policy: TruncationPolicy,
) -> AnalysisSnapshot {
    if truncated {
        snap.flags = AnalysisFlags(snap.flags.0 | AnalysisFlags::TRUNCATED);
        snap.verdict_hint = engine::verdict::verdict_hint(snap.constructs, snap.flags, policy::BUILTIN_SQLI_DETECT);
        if truncation_policy == TruncationPolicy::FailClosed {
            snap.verdict_hint = VerdictHint::Decisive;
        } else if !snap.constructs.any_sqli() {
            snap.verdict_hint = VerdictHint::Inconclusive;
        }
    }
    snap
}

/// Apply scan truncation flags and refresh verdict hint for XSS.
fn finish_xss_snapshot(
    mut snap: AnalysisSnapshot,
    truncated: bool,
    truncation_policy: TruncationPolicy,
) -> AnalysisSnapshot {
    if truncated {
        snap.flags = AnalysisFlags(snap.flags.0 | AnalysisFlags::TRUNCATED);
        snap.verdict_hint = engine::verdict::verdict_hint(snap.constructs, snap.flags, policy::BUILTIN_XSS_DETECT);
        if truncation_policy == TruncationPolicy::FailClosed {
            snap.verdict_hint = VerdictHint::Decisive;
        } else if !snap.constructs.any_xss() {
            snap.verdict_hint = VerdictHint::Inconclusive;
        }
    }
    snap
}

/// Run legacy fingerprint detection and copy into `snapshot` when hit.
#[cfg(feature = "legacy")]
fn merge_legacy_sqli(snapshot: &mut AnalysisSnapshot, slice: &[u8]) -> bool {
    let (hit, fp_bytes, fp_len) = sqli::legacy::detect_with_fingerprint(slice);
    if hit {
        let end = usize::from(fp_len).min(8);
        if let (Some(dst), Some(src)) = (snapshot.legacy_fingerprint.bytes.get_mut(..end), fp_bytes.get(..end)) {
            dst.copy_from_slice(src);
            snapshot.legacy_fingerprint.len = fp_len.min(8);
            snapshot.flags = AnalysisFlags(snapshot.flags.0 | AnalysisFlags::LEGACY_FP_AVAILABLE);
        }
    }
    hit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_benign() {
        let sqli = detect_sqli(b"");
        assert!(!sqli.detected);
        assert_eq!(sqli.snapshot.verdict_hint, VerdictHint::Benign);

        let xss = detect_xss(b"");
        assert!(!xss.detected);
        assert_eq!(xss.snapshot.verdict_hint, VerdictHint::Benign);
    }

    #[test]
    fn detect_sqli_detects_classic_injection() {
        assert!(detect_sqli(b"1' OR '1'='1").detected);
    }

    #[test]
    fn detect_xss_flags_deny_script() {
        assert!(detect_xss(b"<script>alert(1)</script>").detected);
    }

    #[test]
    fn analyze_sqli_populates_constructs() {
        let snap = analyze_sqli(b"1' UNION SELECT null--");
        assert!(snap.constructs.any_sqli());
        assert!(!snap.flags.contains(AnalysisFlags::PREFILTER_MISS));
    }

    #[test]
    fn analyze_xss_populates_constructs() {
        let snap = analyze_xss(b"<script>alert(1)</script>");
        assert!(snap.constructs.any_xss());
    }

    #[test]
    fn analyze_returns_copy_snapshot() {
        let a = analyze_sqli(b"hello");
        let b = a;
        assert_eq!(a, b);
        assert!(!a.constructs.any_sqli());
    }

    #[test]
    fn analyze_options_default_matches_limit() {
        let opts = AnalyzeOptions::default();
        assert_eq!(opts.max_input_len, DEFAULT_MAX_INPUT_LEN);
        assert_eq!(opts.effective_max_input_len(), DEFAULT_MAX_INPUT_LEN);
        assert_eq!(opts.truncation_policy, TruncationPolicy::FailClosed);
    }

    #[test]
    fn analyze_sqli_requires_explicit_truncation_opt_in() {
        let input = [b'a'; DEFAULT_MAX_INPUT_LEN + 1];
        let fail_closed = analyze_sqli_with(&input, AnalyzeOptions::default());
        assert_eq!(fail_closed.verdict_hint, VerdictHint::Decisive);
        assert!(fail_closed.flags.contains(AnalysisFlags::TRUNCATED));

        let allow_truncation = analyze_sqli_with(&input, AnalyzeOptions::default().allow_truncation());
        assert_eq!(allow_truncation.verdict_hint, VerdictHint::Inconclusive);
        assert!(allow_truncation.flags.contains(AnalysisFlags::TRUNCATED));
    }

    #[test]
    fn analyze_xss_requires_explicit_truncation_opt_in() {
        let input = [b'a'; DEFAULT_MAX_INPUT_LEN + 1];
        let fail_closed = analyze_xss_with(&input, AnalyzeOptions::default());
        assert_eq!(fail_closed.verdict_hint, VerdictHint::Decisive);
        assert!(fail_closed.flags.contains(AnalysisFlags::TRUNCATED));

        let allow_truncation = analyze_xss_with(&input, AnalyzeOptions::default().allow_truncation());
        assert_eq!(allow_truncation.verdict_hint, VerdictHint::Inconclusive);
        assert!(allow_truncation.flags.contains(AnalysisFlags::TRUNCATED));
    }

    #[test]
    fn detect_sqli_fails_closed_without_truncation_opt_in() {
        let long = [b'a'; DEFAULT_MAX_INPUT_LEN + 100];
        let opts = AnalyzeOptions::default();
        let verdict = detect_sqli_with(&long, opts);
        assert!(verdict.detected);
        assert!(verdict.snapshot.flags.contains(AnalysisFlags::TRUNCATED));
        assert_eq!(verdict.snapshot.verdict_hint, VerdictHint::Decisive);
    }

    #[test]
    fn detect_sqli_allows_explicit_truncation_opt_in() {
        let long = [b'a'; DEFAULT_MAX_INPUT_LEN + 100];
        let verdict = detect_sqli_with(&long, AnalyzeOptions::default().allow_truncation());
        assert!(!verdict.detected);
        assert!(verdict.snapshot.flags.contains(AnalysisFlags::TRUNCATED));
        assert_eq!(verdict.snapshot.verdict_hint, VerdictHint::Inconclusive);
    }

    #[cfg(feature = "legacy")]
    #[test]
    fn detect_sqli_finds_attack_after_scan_budget_with_legacy_fallback() {
        const ATTACK: &[u8] = b"' OR '1'='1";
        let mut input = [b'a'; DEFAULT_MAX_INPUT_LEN + ATTACK.len()];
        input[DEFAULT_MAX_INPUT_LEN..].copy_from_slice(ATTACK);
        let verdict = detect_sqli_with(&input, AnalyzeOptions::default());
        assert!(verdict.detected);
        assert!(verdict.snapshot.flags.contains(AnalysisFlags::TRUNCATED));
    }

    #[cfg(not(feature = "legacy"))]
    #[test]
    fn detect_sqli_fails_closed_without_legacy_fallback() {
        const ATTACK: &[u8] = b"' OR '1'='1";
        let mut input = [b'a'; DEFAULT_MAX_INPUT_LEN + ATTACK.len()];
        input[DEFAULT_MAX_INPUT_LEN..].copy_from_slice(ATTACK);
        let verdict = detect_sqli_with(&input, AnalyzeOptions::default());
        assert!(verdict.detected);
        assert!(verdict.snapshot.flags.contains(AnalysisFlags::TRUNCATED));
        assert_eq!(verdict.snapshot.verdict_hint, VerdictHint::Decisive);
    }

    #[cfg(not(feature = "legacy"))]
    #[test]
    fn detect_sqli_allows_truncation_without_legacy_fallback() {
        const ATTACK: &[u8] = b"' OR '1'='1";
        let mut input = [b'a'; DEFAULT_MAX_INPUT_LEN + ATTACK.len()];
        input[DEFAULT_MAX_INPUT_LEN..].copy_from_slice(ATTACK);
        let verdict = detect_sqli_with(&input, AnalyzeOptions::default().allow_truncation());
        assert!(!verdict.detected);
        assert!(verdict.snapshot.flags.contains(AnalysisFlags::TRUNCATED));
        assert_eq!(verdict.snapshot.verdict_hint, VerdictHint::Inconclusive);
    }

    #[test]
    fn detect_xss_fails_closed_without_truncation_opt_in() {
        let long = [b'a'; DEFAULT_MAX_INPUT_LEN + 100];
        let opts = AnalyzeOptions::default();
        let verdict = detect_xss_with(&long, opts);
        assert!(verdict.detected);
        assert!(verdict.snapshot.flags.contains(AnalysisFlags::TRUNCATED));
        assert_eq!(verdict.snapshot.verdict_hint, VerdictHint::Decisive);
    }

    #[test]
    fn detect_xss_allows_explicit_truncation_opt_in() {
        let long = [b'a'; DEFAULT_MAX_INPUT_LEN + 100];
        let verdict = detect_xss_with(&long, AnalyzeOptions::default().allow_truncation());
        assert!(!verdict.detected);
        assert!(verdict.snapshot.flags.contains(AnalysisFlags::TRUNCATED));
        assert_eq!(verdict.snapshot.verdict_hint, VerdictHint::Inconclusive);
    }

    #[test]
    fn detect_xss_finds_attack_after_scan_budget_with_legacy_fallback() {
        const ATTACK: &[u8] = b"<script>alert(1)";
        let mut input = [b'a'; DEFAULT_MAX_INPUT_LEN + ATTACK.len()];
        input[DEFAULT_MAX_INPUT_LEN..].copy_from_slice(ATTACK);
        let verdict = detect_xss_with(&input, AnalyzeOptions::default());
        assert!(verdict.detected);
        assert!(verdict.snapshot.flags.contains(AnalysisFlags::TRUNCATED));
    }
}
