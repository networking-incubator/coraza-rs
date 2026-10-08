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

//! Bounded SQLi/XSS construct analysis and optional libinjection compatibility detection.
//!
//! [`analyze_sqli`] and [`analyze_xss`] return descriptive snapshots with owned
//! evidence. Their configured input budget is reported in [`AnalysisFlags`].
//! With the default `legacy` feature, [`detect_sqli`] and [`detect_xss`] expose
//! the full-input byte-compatible detection APIs.

pub mod limits;
pub mod options;
pub mod snapshot;

mod engine;
mod policy;
mod sqli;
mod xss;

pub use limits::{DEFAULT_MAX_INPUT_LEN, MAX_INPUT_LEN, scan_prefix};
pub use options::AnalyzeOptions;
#[cfg(feature = "legacy")]
pub use snapshot::SqliDetection;
pub use snapshot::{
    AnalysisContext, AnalysisFlags, AnalysisSnapshot, ConstructFlags, EvidenceSet, EvidenceSpan, LegacyFingerprint,
    SqlDialect, SqliQuoteMode, VerdictHint, XssHtmlContext,
};
#[cfg(feature = "legacy")]
pub use sqli::legacy::{SqliStatistics, SqliTokenInfo, sqli_fold_visit, sqli_tokenize_visit};
#[cfg(feature = "legacy")]
pub use xss::legacy::{Html5TokenKind, html5_visit};

/// Analyze one SQL input within the default byte budget.
#[must_use]
pub fn analyze_sqli(input: &[u8]) -> AnalysisSnapshot {
    analyze_sqli_with(input, AnalyzeOptions::default())
}

/// Analyze SQL constructs within the caller's bounded byte budget.
#[must_use]
pub fn analyze_sqli_with(input: &[u8], opts: AnalyzeOptions) -> AnalysisSnapshot {
    let (slice, truncated) = scan_prefix(input, opts.effective_max_input_len());
    finish_bounded_snapshot(
        sqli::modern::analyze(slice, opts),
        truncated,
        policy::BUILTIN_SQLI_DETECT,
    )
}

/// Analyze XSS constructs within the default byte budget.
#[must_use]
pub fn analyze_xss(input: &[u8]) -> AnalysisSnapshot {
    analyze_xss_with(input, AnalyzeOptions::default())
}

/// Analyze XSS constructs within the caller's bounded byte budget.
#[must_use]
pub fn analyze_xss_with(input: &[u8], opts: AnalyzeOptions) -> AnalysisSnapshot {
    let (slice, truncated) = scan_prefix(input, opts.effective_max_input_len());
    finish_bounded_snapshot(xss::modern::analyze(slice, opts), truncated, policy::BUILTIN_XSS_DETECT)
}

/// Detect SQL injection using the pinned libinjection-compatible algorithm.
///
/// Scans the complete supplied byte slice. The fingerprint is populated only
/// when `detected` is true; a miss returns an empty fingerprint.
#[cfg(feature = "legacy")]
#[must_use]
pub fn detect_sqli(input: &[u8]) -> SqliDetection {
    let (detected, bytes, len) = sqli::legacy::detect_with_fingerprint(input);
    if !detected {
        return SqliDetection::default();
    }

    let mut fingerprint = LegacyFingerprint::default();
    let len = usize::from(len).min(bytes.len()).min(fingerprint.bytes.len());
    if let (Some(dst), Some(src)) = (fingerprint.bytes.get_mut(..len), bytes.get(..len)) {
        dst.copy_from_slice(src);
    }
    fingerprint.len = u8::try_from(len).unwrap_or(0);
    SqliDetection { detected, fingerprint }
}

/// Detect XSS using the pinned libinjection-compatible algorithm.
///
/// Scans the complete supplied byte slice in all five legacy HTML contexts.
#[cfg(feature = "legacy")]
#[must_use]
pub fn detect_xss(input: &[u8]) -> bool {
    xss::legacy::detect(input)
}

/// Add input-budget status and refresh the hint when analysis was partial.
fn finish_bounded_snapshot(
    mut snapshot: AnalysisSnapshot,
    truncated: bool,
    detect_mask: ConstructFlags,
) -> AnalysisSnapshot {
    if truncated {
        snapshot.flags.0 |= AnalysisFlags::TRUNCATED;
        snapshot.verdict_hint = engine::verdict::verdict_hint(snapshot.constructs, snapshot.flags, detect_mask);
    }
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_analysis_is_benign() {
        assert_eq!(analyze_sqli(b"").verdict_hint, VerdictHint::Benign);
        assert_eq!(analyze_xss(b"").verdict_hint, VerdictHint::Benign);
    }

    #[cfg(feature = "legacy")]
    #[test]
    fn canonical_detection_matches_compatibility_examples() {
        let sqli = detect_sqli(b"1' OR '1'='1");
        assert!(sqli.detected);
        assert_eq!(sqli.fingerprint.as_str(), Some("s&sos"));

        assert!(detect_xss(b"<script>alert(1)</script>"));
    }

    #[test]
    fn bounded_options_default_and_explicit_budgets_are_preserved() {
        let opts = AnalyzeOptions::default();
        assert_eq!(opts.max_input_len, DEFAULT_MAX_INPUT_LEN);
        assert_eq!(opts.effective_max_input_len(), DEFAULT_MAX_INPUT_LEN);

        let opts = AnalyzeOptions::with_max_input_len(usize::MAX);
        assert_eq!(opts.effective_max_input_len(), usize::MAX);
    }

    #[test]
    fn truncated_prefilter_miss_is_inconclusive() {
        let snapshot = analyze_sqli_with(b"benign prefix with SQL after", AnalyzeOptions::with_max_input_len(6));
        assert!(snapshot.flags.contains(AnalysisFlags::TRUNCATED));
        assert!(snapshot.flags.contains(AnalysisFlags::PREFILTER_MISS));
        assert_eq!(snapshot.verdict_hint, VerdictHint::Inconclusive);
    }

    #[test]
    fn complete_prefilter_skips_are_inconclusive_for_both_analyzers() {
        let sqli = analyze_sqli(b"ordinary request text");
        assert!(sqli.flags.contains(AnalysisFlags::PREFILTER_MISS));
        assert_eq!(sqli.verdict_hint, VerdictHint::Inconclusive);

        let xss = analyze_xss(b"ordinary request text");
        assert!(xss.flags.contains(AnalysisFlags::PREFILTER_MISS));
        assert_eq!(xss.verdict_hint, VerdictHint::Inconclusive);
    }

    #[test]
    fn observed_decisive_construct_survives_partial_analysis_hint() {
        let input = b"<script>omitted suffix";
        let snapshot = analyze_xss_with(input, AnalyzeOptions::with_max_input_len(8));
        assert!(snapshot.flags.contains(AnalysisFlags::TRUNCATED));
        assert!(
            snapshot
                .constructs
                .intersects(ConstructFlags(ConstructFlags::XSS_TAG_SCRIPT))
        );
        assert_eq!(snapshot.verdict_hint, VerdictHint::Decisive);
    }

    #[test]
    fn evidence_reports_distinct_original_ranges() {
        let snapshot = analyze_sqli(b"union union union union union");
        assert_eq!(snapshot.evidence.spans.len(), 5);
        assert!(
            snapshot
                .evidence
                .spans
                .iter()
                .all(|span| span.offset + span.len <= b"union union union union union".len())
        );
    }

    #[test]
    fn encoded_sql_evidence_keeps_all_original_spans_and_decisive_hint() {
        let input = b"= %75nion %75nion %75nion %75nion %75nion";
        assert_eq!(
            engine::normalize::original_span_for_normalized(input, 2, 5),
            Some((2, 7))
        );
        let snapshot = analyze_sqli(input);

        assert!(
            snapshot
                .constructs
                .intersects(ConstructFlags(ConstructFlags::SQL_UNION))
        );
        assert_eq!(snapshot.evidence.spans.len(), 5);
        assert_eq!(snapshot.verdict_hint, VerdictHint::Decisive);

        let expected_offsets = [2, 10, 18, 26, 34];
        for (span, expected_offset) in snapshot.evidence.spans.iter().zip(expected_offsets) {
            assert_eq!(span.offset, expected_offset);
            assert_eq!(span.len, b"%75nion".len(), "span={span:?}, input={input:?}");
            assert_eq!(
                input.get(expected_offset..expected_offset + span.len),
                Some(&b"%75nion"[..]),
            );
        }
    }

    #[test]
    fn encoded_xss_evidence_keeps_all_original_spans_and_decisive_hint() {
        let input = b"%3Cscript %3Cscript %3Cscript %3Cscript %3Cscript";
        assert_eq!(
            engine::normalize::original_span_for_normalized(input, 8, 7),
            Some((10, 9))
        );
        let snapshot = analyze_xss(input);

        assert!(
            snapshot
                .constructs
                .intersects(ConstructFlags(ConstructFlags::XSS_TAG_SCRIPT))
        );
        assert_eq!(snapshot.evidence.spans.len(), 5);
        assert_eq!(snapshot.verdict_hint, VerdictHint::Decisive);

        let expected_offsets = [0, 10, 20, 30, 40];
        for (span, expected_offset) in snapshot.evidence.spans.iter().zip(expected_offsets) {
            assert_eq!(span.offset, expected_offset);
            assert_eq!(span.len, b"%3Cscript".len(), "span={span:?}, input={input:?}");
            assert_eq!(
                input.get(expected_offset..expected_offset + span.len),
                Some(&b"%3Cscript"[..]),
            );
        }
    }

    #[test]
    fn long_token_stream_does_not_truncate_analysis_storage() {
        let snapshot = analyze_sqli(b"1=1 1=1 1=1 1=1 1=1");
        assert!(!snapshot.flags.contains(AnalysisFlags::TRUNCATED));
    }

    #[test]
    fn evidence_beyond_u16_boundary_indexes_the_original_input() {
        let mut input = [b'x'; 65_535];
        let marker = b"<script>";
        let start = input.len() - marker.len();
        assert!(input.get_mut(start..).is_some_and(|dst| {
            dst.copy_from_slice(marker);
            true
        }));

        let snapshot = analyze_xss_with(&input, AnalyzeOptions::with_max_input_len(usize::MAX));
        assert!(!snapshot.flags.contains(AnalysisFlags::TRUNCATED));
        let span = snapshot.evidence.spans.first().copied().unwrap_or_default();
        assert_eq!(span.offset, start);
        assert_eq!(span.len, marker.len() - 1);
        assert!(span.offset + span.len <= input.len());
    }

    #[test]
    fn scan_budget_boundaries_report_only_real_prefix_truncation() {
        for len in [
            DEFAULT_MAX_INPUT_LEN - 1,
            DEFAULT_MAX_INPUT_LEN,
            DEFAULT_MAX_INPUT_LEN + 1,
        ] {
            let input = [b'x'; DEFAULT_MAX_INPUT_LEN + 1];
            let snapshot = analyze_sqli_with(input.get(..len).unwrap_or_default(), AnalyzeOptions::default());
            assert_eq!(
                snapshot.flags.contains(AnalysisFlags::TRUNCATED),
                len > DEFAULT_MAX_INPUT_LEN
            );
        }
    }
}
