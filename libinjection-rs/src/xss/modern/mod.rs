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

//! Stage-1 XSS analysis (construct flags, zero heap).

mod classify;

use classify::{classify, infer_html_context};

use crate::{
    engine::{normalize::normalize, prefilter::xss_may_be_interesting, verdict::verdict_hint},
    limits::NORM_BUF_LEN,
    options::AnalyzeOptions,
    policy,
    snapshot::{AnalysisContext, AnalysisFlags, AnalysisSnapshot, LegacyFingerprint, SqlDialect, SqliQuoteMode},
};

/// Analyze one input slice (caller applies scan budget).
#[must_use]
pub(crate) fn analyze(input: &[u8], _opts: AnalyzeOptions) -> AnalysisSnapshot {
    if input.is_empty() {
        return AnalysisSnapshot::benign();
    }
    if !xss_may_be_interesting(input) {
        return AnalysisSnapshot {
            flags: AnalysisFlags(AnalysisFlags::PREFILTER_MISS),
            ..AnalysisSnapshot::benign()
        };
    }

    let html_context = infer_html_context(input);
    let mut norm_buf = [0_u8; NORM_BUF_LEN];
    let norm = normalize(input, &mut norm_buf);
    let classified = classify(norm, html_context);

    let mut flags = AnalysisFlags::empty();
    if norm.norm_truncated {
        flags.0 |= AnalysisFlags::TRUNCATED;
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
        legacy_fingerprint: LegacyFingerprint::default(),
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
        let span = snap.evidence.spans[0];
        let start = usize::from(span.offset);
        let end = start + usize::from(span.len);
        assert!(end <= input.len());
        assert_eq!(input.get(start..end), Some(&b"%3Cscript"[..]));
    }

    fn detect_xss_for_test(input: &[u8]) -> bool {
        super::super::super::detect_xss(input).detected
    }
}
