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

//! Stage-1 `SQLi` construct analysis.

mod classify;

use classify::classify;

use crate::{
    engine::{
        normalize::normalize_for_analysis, prefilter::sqli_may_be_interesting, token::tokenize, verdict::verdict_hint,
    },
    options::AnalyzeOptions,
    policy,
    snapshot::{AnalysisContext, AnalysisFlags, AnalysisSnapshot, ConstructFlags, XssHtmlContext},
};

/// Analyze one input slice (caller applies scan budget).
#[must_use]
pub(crate) fn analyze(input: &[u8], _opts: AnalyzeOptions) -> AnalysisSnapshot {
    if input.is_empty() {
        return AnalysisSnapshot::benign();
    }
    if !sqli_may_be_interesting(input) {
        let flags = AnalysisFlags(AnalysisFlags::PREFILTER_MISS);
        return AnalysisSnapshot {
            flags,
            verdict_hint: verdict_hint(ConstructFlags::empty(), flags, policy::BUILTIN_SQLI_DETECT),
            ..AnalysisSnapshot::benign()
        };
    }

    let norm = normalize_for_analysis(input);
    let tokens = tokenize(norm.bytes.as_ref());

    let classified = classify(norm, &tokens);

    let flags = AnalysisFlags::empty();
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
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;
    use crate::snapshot::{ConstructFlags, VerdictHint};

    #[test]
    fn prefilter_miss_is_inconclusive() {
        let snap = analyze(b"hello", AnalyzeOptions::default());
        assert!(snap.flags.contains(AnalysisFlags::PREFILTER_MISS));
        assert_eq!(snap.verdict_hint, VerdictHint::Inconclusive);
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
    fn numeric_comparison_sets_numeric_injection_construct() {
        let snap = analyze(b"1=1", AnalyzeOptions::default());
        assert!(
            snap.constructs
                .intersects(ConstructFlags(ConstructFlags::SQL_NUMERIC_INJECTION)),
            "snapshot={snap:?}"
        );
    }

    #[test]
    fn duplicate_raw_and_normalized_evidence_spans_are_deduplicated() {
        let snap = analyze(b"exec", AnalyzeOptions::default());
        assert_eq!(snap.evidence.spans.len(), 1);
    }

    #[test]
    fn tautology_patterns_accept_sql_whitespace_and_plus_separators() {
        for input in [b"1\tor\t1=1".as_slice(), b"1+or+1=1", b"1%09or%091=1"] {
            let snap = analyze(input, AnalyzeOptions::default());
            assert!(
                snap.constructs
                    .intersects(ConstructFlags(ConstructFlags::SQL_TAUTOLOGY)),
                "input={input:?}, snapshot={snap:?}"
            );
        }
    }

    #[test]
    fn stacked_query_and_comment_detection_use_normalized_tokens_and_all_verbs() {
        for (input, evidence) in [
            (b"1%3b drop table x".as_slice(), b"drop".as_slice()),
            (b"1; d\0rop table x", b"d\0rop"),
            (b"1;'drop' drop table x", b"drop"),
        ] {
            let snap = analyze(input, AnalyzeOptions::default());
            assert!(
                snap.constructs
                    .intersects(ConstructFlags(ConstructFlags::SQL_STACKED_QUERY)),
                "input={input:?}, snapshot={snap:?}"
            );
            assert!(
                evidence_is_present(&snap, input, evidence),
                "input={input:?}, snapshot={snap:?}"
            );
        }

        let input = b"1%23";
        let comment = analyze(input, AnalyzeOptions::default());
        assert!(
            comment
                .constructs
                .intersects(ConstructFlags(ConstructFlags::SQL_COMMENT_INJECTION)),
            "snapshot={comment:?}"
        );
        assert!(evidence_is_present(&comment, input, b"%23"), "snapshot={comment:?}");
    }

    fn evidence_is_present(snapshot: &AnalysisSnapshot, input: &[u8], expected: &[u8]) -> bool {
        snapshot.evidence.spans.iter().any(|span| {
            let start = span.offset;
            let end = start.saturating_add(span.len);
            input
                .get(start..end)
                .is_some_and(|text| text.windows(expected.len()).any(|window| window == expected))
        })
    }

    #[test]
    fn sqli_prefilter_admits_known_operator_and_keyword_shapes() {
        for input in [
            b"@@||x".as_slice(),
            b"admin||@@",
            b"1e1<@@",
            b"1<2",
            b"1<>2",
            b"or true",
            b"1or true",
            b"and true",
        ] {
            let snap = analyze(input, AnalyzeOptions::default());
            assert!(
                !snap.flags.contains(AnalysisFlags::PREFILTER_MISS),
                "input={input:?}, snapshot={snap:?}"
            );
        }
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
    fn percent_encoded_and_nul_obfuscated_keywords_reach_normalization() {
        for input in [b"%75%6e%69%6f%6e".as_slice(), b"un\0ion".as_slice()] {
            let snap = analyze(input, AnalyzeOptions::default());
            assert!(!snap.flags.contains(AnalysisFlags::PREFILTER_MISS), "input={input:?}");
            assert!(
                snap.constructs.intersects(ConstructFlags(ConstructFlags::SQL_UNION)),
                "input={input:?}, snapshot={snap:?}"
            );
        }

        let tautology = b"%31%27%20or%20%271%27%3d%271";
        let snap = analyze(tautology, AnalyzeOptions::default());
        assert!(!snap.flags.contains(AnalysisFlags::PREFILTER_MISS));
        assert!(
            snap.constructs
                .intersects(ConstructFlags(ConstructFlags::SQL_TAUTOLOGY)),
            "snapshot={snap:?}"
        );
    }

    #[test]
    fn backtick_only_input_reaches_mysql_dialect_classification() {
        let snap = analyze(b"`identifier`", AnalyzeOptions::default());
        assert!(!snap.flags.contains(AnalysisFlags::PREFILTER_MISS));
        assert!(
            snap.constructs
                .intersects(ConstructFlags(ConstructFlags::SQL_DIALECT_MYSQL))
        );
        assert_eq!(snap.context.dialect, crate::snapshot::SqlDialect::Mysql);
    }

    #[test]
    fn keyword_chains_require_whole_words() {
        for input in [b"selectivity fromage".as_slice(), b"unionized select"] {
            let snap = analyze(input, AnalyzeOptions::default());
            assert!(
                !snap
                    .constructs
                    .intersects(ConstructFlags(ConstructFlags::SQL_KEYWORD_CHAIN)),
                "input={input:?}, snapshot={snap:?}"
            );
        }

        for input in [
            b"SELECT value FROM users".as_slice(),
            b"SELECT alone; SELECT value FROM users",
        ] {
            let snap = analyze(input, AnalyzeOptions::default());
            assert!(
                snap.constructs
                    .intersects(ConstructFlags(ConstructFlags::SQL_KEYWORD_CHAIN)),
                "input={input:?}, snapshot={snap:?}"
            );
        }
    }

    #[test]
    fn long_select_runs_still_find_the_following_from_clause() {
        let mut input = Vec::with_capacity(4_000);
        for _ in 0..500 {
            input.extend_from_slice(b"select ");
        }
        input.extend_from_slice(b"from users");
        let snap = analyze(&input, AnalyzeOptions::default());
        assert!(
            snap.constructs
                .intersects(ConstructFlags(ConstructFlags::SQL_KEYWORD_CHAIN)),
            "snapshot={snap:?}"
        );
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
        let span = snap.evidence.spans.first().copied().unwrap_or_default();
        let start = span.offset;
        let end = start + span.len;
        assert!(end <= input.len());
        assert_eq!(input.get(start..end), Some(&b"/*"[..]));
    }

    fn detect_sqli_for_test(input: &[u8]) -> bool {
        let snapshot = analyze(input, AnalyzeOptions::default());
        snapshot.constructs.intersects(policy::BUILTIN_SQLI_DETECT)
    }
}
