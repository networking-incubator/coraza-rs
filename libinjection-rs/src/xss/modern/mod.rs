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

//! Stage-1 XSS construct analysis.

mod classify;

use classify::{classify, infer_html_context};

use crate::{
    engine::{normalize::normalize_for_analysis, prefilter::xss_may_be_interesting, verdict::verdict_hint},
    options::AnalyzeOptions,
    policy,
    snapshot::{
        AnalysisContext, AnalysisFlags, AnalysisSnapshot, ConstructFlags, SqlDialect, SqliQuoteMode, XssHtmlContext,
    },
};

/// Analyze one input slice (caller applies scan budget).
#[must_use]
pub(crate) fn analyze(input: &[u8], _opts: AnalyzeOptions) -> AnalysisSnapshot {
    if input.is_empty() {
        return AnalysisSnapshot::benign();
    }
    if !xss_may_be_interesting(input) {
        let flags = AnalysisFlags(AnalysisFlags::PREFILTER_MISS);
        return AnalysisSnapshot {
            flags,
            verdict_hint: verdict_hint(ConstructFlags::empty(), flags, policy::BUILTIN_XSS_DETECT),
            ..AnalysisSnapshot::benign()
        };
    }

    let norm = normalize_for_analysis(input);
    let html_context = infer_html_context(norm.bytes.as_ref());
    let classified = classify(&norm, html_context);

    let mut flags = AnalysisFlags::empty();
    if html_context != XssHtmlContext::Data {
        flags.0 |= AnalysisFlags::MULTI_CONTEXT;
    }
    let verdict_hint = verdict_hint(classified.constructs, flags, policy::BUILTIN_XSS_DETECT);

    AnalysisSnapshot {
        constructs: classified.constructs,
        flags,
        verdict_hint,
        context: AnalysisContext {
            sqli_quote_mode: SqliQuoteMode::None,
            xss_html_context: classified.html_context,
            dialect: SqlDialect::Ansi,
        },
        evidence: classified.evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{ConstructFlags, VerdictHint};

    #[test]
    fn script_tag_sets_construct() {
        let snap = analyze(b"<script>alert(1)</script>", AnalyzeOptions::default());
        assert!(
            snap.constructs
                .intersects(ConstructFlags(ConstructFlags::XSS_TAG_SCRIPT))
        );
        assert_eq!(snap.verdict_hint, VerdictHint::Decisive);
    }

    #[test]
    fn javascript_url_detected() {
        let snap = analyze(b"javascript:alert(1)", AnalyzeOptions::default());
        assert!(
            snap.constructs
                .intersects(ConstructFlags(ConstructFlags::XSS_URL_JAVASCRIPT))
        );
    }

    #[test]
    fn fully_percent_encoded_xss_reaches_normalization() {
        let input = b"%68%72%65%66%3d%6a%61%76%61%73%63%72%69%70%74%3a%61%6c%65%72%74%28%31%29";
        let snap = analyze(input, AnalyzeOptions::default());
        assert!(!snap.flags.contains(AnalysisFlags::PREFILTER_MISS));
        assert!(
            snap.constructs
                .intersects(ConstructFlags(ConstructFlags::XSS_URL_JAVASCRIPT)),
            "snapshot={snap:?}"
        );
    }

    #[test]
    fn encoded_script_tags_are_classified_in_the_normalized_context() {
        for input in [
            b"%3Cscript%20src=//x%3E".as_slice(),
            b"%3Cscript%20src=//x%3E%3C/script%3E",
            b"x=%3Cscript%3E",
        ] {
            let snap = analyze(input, AnalyzeOptions::default());
            assert!(
                snap.constructs
                    .intersects(ConstructFlags(ConstructFlags::XSS_TAG_SCRIPT)),
                "input={input:?}, snapshot={snap:?}"
            );
        }
    }

    #[test]
    fn quoted_attribute_escape_also_checks_data_context() {
        let input = b"\"><script>alert(1)</script>";
        let snap = analyze(input, AnalyzeOptions::default());
        assert!(
            snap.constructs
                .intersects(ConstructFlags(ConstructFlags::XSS_TAG_SCRIPT)),
            "snapshot={snap:?}"
        );
        assert!(snap.flags.contains(AnalysisFlags::MULTI_CONTEXT));
        assert!(
            snap.evidence.spans.iter().any(|span| {
                let start = span.offset;
                let end = start.saturating_add(span.len);
                input
                    .get(start..end)
                    .is_some_and(|text| text.windows(b"<script".len()).any(|window| window == b"<script"))
            }),
            "evidence should identify the script tag in the original input: {snap:?}"
        );
    }

    #[test]
    fn percent_decoded_nuls_are_removed_before_tag_classification() {
        let input = b"%3Csc%00ript%3E";
        let snap = analyze(input, AnalyzeOptions::default());
        assert!(
            snap.constructs
                .intersects(ConstructFlags(ConstructFlags::XSS_TAG_SCRIPT)),
            "snapshot={snap:?}"
        );
        let span = snap.evidence.spans.first().copied().unwrap_or_default();
        let start = span.offset;
        let end = start + span.len;
        assert_eq!(input.get(start..end), Some(&b"%3Csc%00ript"[..]));
    }

    #[test]
    fn hardening_cases_respect_html_context_and_boundaries() {
        struct Case {
            input: &'static [u8],
            flag: u32,
            detected: bool,
        }

        let cases = [
            Case {
                input: b"<script>alert(1)</script>",
                flag: ConstructFlags::XSS_TAG_SCRIPT,
                detected: true,
            },
            Case {
                input: b"<scripted>text</scripted>",
                flag: 0,
                detected: false,
            },
            Case {
                input: b"<img onerror=alert(1)>",
                flag: ConstructFlags::XSS_EVENT_HANDLER,
                detected: true,
            },
            Case {
                input: b"href=javascript:alert(1)",
                flag: ConstructFlags::XSS_URL_JAVASCRIPT,
                detected: true,
            },
            Case {
                input: b"xjavascript:alert(1)",
                flag: 0,
                detected: false,
            },
            Case {
                input: b"<div style=expression(alert(1))>",
                flag: ConstructFlags::XSS_STYLE_EXPRESSION,
                detected: true,
            },
            Case {
                input: b"<!DOCTYPE html>",
                flag: ConstructFlags::XSS_DOCTYPE,
                detected: true,
            },
            Case {
                input: b"<!-- comment -->",
                flag: ConstructFlags::XSS_COMMENT_BYPASS,
                detected: true,
            },
            Case {
                input: b"doctype is ordinary text",
                flag: 0,
                detected: false,
            },
            Case {
                input: b"<embed src=x>",
                flag: ConstructFlags::XSS_HTML_DENYLIST,
                detected: true,
            },
            Case {
                input: b"<img onanimationstart=alert(1)>",
                flag: ConstructFlags::XSS_HTML_DENYLIST,
                detected: true,
            },
            Case {
                input: b"<div style=color:red>",
                flag: ConstructFlags::XSS_HTML_DENYLIST,
                detected: true,
            },
            Case {
                input: b"<a href=vbscript:alert(1)>",
                flag: ConstructFlags::XSS_HTML_DENYLIST,
                detected: true,
            },
        ];

        for case in cases {
            let snap = analyze(case.input, AnalyzeOptions::default());
            assert_eq!(snap.constructs.0 & case.flag, case.flag, "input={:?}", case.input);
            assert_eq!(detect_xss_for_test(case.input), case.detected, "input={:?}", case.input);
        }
    }

    #[test]
    fn normalized_tag_evidence_maps_to_original_bytes() {
        let input = b"%3Cscript%3E";
        let snap = analyze(input, AnalyzeOptions::default());
        assert!(
            snap.constructs
                .intersects(ConstructFlags(ConstructFlags::XSS_TAG_SCRIPT))
        );
        let span = snap.evidence.spans.first().copied().unwrap_or_default();
        let start = span.offset;
        let end = start + span.len;
        assert!(end <= input.len());
        assert_eq!(input.get(start..end), Some(&b"%3Cscript"[..]));
    }

    fn detect_xss_for_test(input: &[u8]) -> bool {
        let snapshot = analyze(input, AnalyzeOptions::default());
        snapshot.constructs.intersects(policy::BUILTIN_XSS_DETECT)
    }
}
