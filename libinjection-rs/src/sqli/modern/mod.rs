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

//! Stage-1 `SQLi` analysis (construct flags, zero heap).

mod classify;

use classify::classify;

use crate::{
    engine::{normalize::normalize, prefilter::sqli_may_be_interesting, token::tokenize, verdict::verdict_hint},
    limits::NORM_BUF_LEN,
    options::AnalyzeOptions,
    policy,
    snapshot::{AnalysisContext, AnalysisFlags, AnalysisSnapshot, LegacyFingerprint, XssHtmlContext},
};

/// Analyze one input slice (caller applies scan budget).
#[must_use]
pub(crate) fn analyze(input: &[u8], _opts: AnalyzeOptions) -> AnalysisSnapshot {
    if input.is_empty() {
        return AnalysisSnapshot::benign();
    }
    if !sqli_may_be_interesting(input) {
        return AnalysisSnapshot {
            flags: AnalysisFlags(AnalysisFlags::PREFILTER_MISS),
            ..AnalysisSnapshot::benign()
        };
    }

    let mut norm_buf = [0_u8; NORM_BUF_LEN];
    let norm = normalize(input, &mut norm_buf);
    let tokens = tokenize(norm.original);

    let classified = classify(norm, &tokens);

    let mut flags = AnalysisFlags::empty();
    if norm.norm_truncated {
        flags.0 |= AnalysisFlags::TRUNCATED;
    }
    if tokens.limit_hit {
        flags.0 |= AnalysisFlags::TOKEN_LIMIT;
    }

    let verdict_hint = verdict_hint(classified.constructs, flags, policy::BUILTIN_SQLI_DETECT);

    AnalysisSnapshot {
        constructs: classified.constructs,
        flags,
        verdict_hint,
        context: AnalysisContext {
            sqli_quote_mode: classified.quote_mode,
            xss_html_context: XssHtmlContext::Data,
            dialect: classified.dialect,
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
    fn prefilter_miss_is_benign() {
        let snap = analyze(b"hello", AnalyzeOptions::default());
        assert!(snap.flags.contains(AnalysisFlags::PREFILTER_MISS));
        assert_eq!(snap.verdict_hint, VerdictHint::Benign);
    }

    #[test]
    fn union_injection_sets_construct() {
        let snap = analyze(b"1' UNION SELECT null--", AnalyzeOptions::default());
        assert!(snap.constructs.intersects(ConstructFlags(ConstructFlags::SQL_UNION)));
        assert!(snap.constructs.any_sqli());
    }

    #[test]
    fn classic_tautology_detected() {
        let snap = analyze(b"1' OR '1'='1", AnalyzeOptions::default());
        assert!(snap.constructs.intersects(ConstructFlags(
            ConstructFlags::SQL_TAUTOLOGY | ConstructFlags::SQL_STRING_BREAK
        )));
    }

    #[test]
    fn function_triggers_are_not_filtered_out() {
        for input in [b"xp_cmdshell".as_slice(), b"WAITFOR DELAY".as_slice()] {
            let snap = analyze(input, AnalyzeOptions::default());
            assert!(!snap.flags.contains(AnalysisFlags::PREFILTER_MISS), "input={input:?}");
            assert!(
                snap.constructs
                    .intersects(ConstructFlags(ConstructFlags::SQL_FUNCTION_CALL))
            );
        }
    }

    #[test]
    fn hardening_cases_keep_lexical_and_dialect_boundaries() {
        struct Case {
            input: &'static [u8],
            flag: u32,
            detected: bool,
        }

        let cases = [
            Case {
                input: b"1/*!50000UNION*/SELECT",
                flag: ConstructFlags::SQL_COMMENT_INJECTION | ConstructFlags::SQL_DIALECT_MYSQL,
                detected: true,
            },
            Case {
                input: b"foo--bar",
                flag: 0,
                detected: false,
            },
            Case {
                input: b"1; DROP TABLE users",
                flag: ConstructFlags::SQL_STACKED_QUERY,
                detected: true,
            },
            Case {
                input: b"1; hello",
                flag: 0,
                detected: false,
            },
            Case {
                input: b"[user]",
                flag: ConstructFlags::SQL_DIALECT_MSSQL,
                detected: false,
            },
            Case {
                input: b"EXEC foo",
                flag: ConstructFlags::SQL_DIALECT_MSSQL,
                detected: false,
            },
            Case {
                input: b"DUAL",
                flag: ConstructFlags::SQL_DIALECT_ORACLE,
                detected: false,
            },
            Case {
                input: b"q'[value]'",
                flag: ConstructFlags::SQL_DIALECT_ORACLE,
                detected: false,
            },
            Case {
                input: b"duality",
                flag: 0,
                detected: false,
            },
            Case {
                input: b"account_union_status",
                flag: 0,
                detected: false,
            },
        ];

        for case in cases {
            let snap = analyze(case.input, AnalyzeOptions::default());
            assert_eq!(snap.constructs.0 & case.flag, case.flag, "input={:?}", case.input);
            assert_eq!(
                detect_sqli_for_test(case.input),
                case.detected,
                "input={:?}",
                case.input
            );
        }
    }

    #[test]
    fn versioned_comment_evidence_stays_in_original_input() {
        let input = b"1/*!50000UNION*/SELECT";
        let snap = analyze(input, AnalyzeOptions::default());
        let span = snap.evidence.spans[0];
        let start = usize::from(span.offset);
        let end = start + usize::from(span.len);
        assert!(end <= input.len());
        assert_eq!(input.get(start..end), Some(&b"/*"[..]));
    }

    fn detect_sqli_for_test(input: &[u8]) -> bool {
        super::super::super::detect_sqli(input).detected
    }
}
