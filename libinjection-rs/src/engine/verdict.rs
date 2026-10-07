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

//! Map constructs + flags to [`VerdictHint`].

use crate::snapshot::{AnalysisFlags, ConstructFlags, VerdictHint};

/// True when the configured input budget omitted a suffix from analysis.
fn scan_limited(flags: AnalysisFlags) -> bool {
    flags.contains(AnalysisFlags::TRUNCATED)
}

/// Derive stage-1 verdict hint from constructs and status flags.
///
/// An observed construct in `detect_mask` stays [`VerdictHint::Decisive`] even
/// when the configured input budget truncated the scan. Every other partial snapshot
/// is [`VerdictHint::Inconclusive`], including one whose prefilter missed.
#[must_use]
pub(crate) fn verdict_hint(
    constructs: ConstructFlags,
    flags: AnalysisFlags,
    detect_mask: ConstructFlags,
) -> VerdictHint {
    if scan_limited(flags) {
        return if constructs.intersects(detect_mask) {
            VerdictHint::Decisive
        } else {
            VerdictHint::Inconclusive
        };
    }
    if flags.contains(AnalysisFlags::PREFILTER_MISS) {
        return VerdictHint::Inconclusive;
    }
    if constructs.intersects(detect_mask) {
        return VerdictHint::Decisive;
    }
    if constructs.any_sqli() || constructs.any_xss() {
        return VerdictHint::Suspicious;
    }
    VerdictHint::Benign
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{BUILTIN_SQLI_DETECT, BUILTIN_XSS_DETECT};

    #[test]
    fn prefilter_miss_is_inconclusive() {
        let flags = AnalysisFlags(AnalysisFlags::PREFILTER_MISS);
        let constructs = ConstructFlags::empty();
        assert_eq!(
            verdict_hint(constructs, flags, BUILTIN_SQLI_DETECT),
            VerdictHint::Inconclusive
        );
    }

    #[test]
    fn policy_match_is_decisive_without_truncation() {
        let constructs = ConstructFlags(ConstructFlags::SQL_UNION);
        assert_eq!(
            verdict_hint(constructs, AnalysisFlags::empty(), BUILTIN_SQLI_DETECT),
            VerdictHint::Decisive
        );
    }

    #[test]
    fn policy_match_stays_decisive_when_truncated() {
        let constructs = ConstructFlags(ConstructFlags::SQL_UNION);
        let flags = AnalysisFlags(AnalysisFlags::TRUNCATED);
        assert_eq!(
            verdict_hint(constructs, flags, BUILTIN_SQLI_DETECT),
            VerdictHint::Decisive
        );
    }

    #[test]
    fn policy_match_stays_decisive_when_input_is_truncated() {
        let constructs = ConstructFlags(ConstructFlags::XSS_TAG_SCRIPT);
        let flags = AnalysisFlags(AnalysisFlags::TRUNCATED);
        assert_eq!(
            verdict_hint(constructs, flags, BUILTIN_XSS_DETECT),
            VerdictHint::Decisive
        );
    }

    #[test]
    fn partial_weak_dialect_is_inconclusive() {
        let constructs = ConstructFlags(ConstructFlags::SQL_DIALECT_MYSQL);
        let flags = AnalysisFlags(AnalysisFlags::TRUNCATED);
        assert_eq!(
            verdict_hint(constructs, flags, BUILTIN_SQLI_DETECT),
            VerdictHint::Inconclusive
        );
    }

    #[test]
    fn weak_dialect_only_is_suspicious_when_not_truncated() {
        let constructs = ConstructFlags(ConstructFlags::SQL_DIALECT_MYSQL);
        assert_eq!(
            verdict_hint(constructs, AnalysisFlags::empty(), BUILTIN_SQLI_DETECT),
            VerdictHint::Suspicious
        );
    }

    #[test]
    fn truncated_without_constructs_is_inconclusive() {
        let flags = AnalysisFlags(AnalysisFlags::TRUNCATED);
        assert_eq!(
            verdict_hint(ConstructFlags::empty(), flags, BUILTIN_SQLI_DETECT),
            VerdictHint::Inconclusive
        );
    }

    #[test]
    fn non_policy_construct_is_inconclusive_when_truncated() {
        let constructs = ConstructFlags(ConstructFlags::SQL_NUMERIC_INJECTION);
        let flags = AnalysisFlags(AnalysisFlags::TRUNCATED);
        assert_eq!(
            verdict_hint(constructs, flags, BUILTIN_SQLI_DETECT),
            VerdictHint::Inconclusive
        );
    }

    #[test]
    fn truncated_weak_dialect_is_inconclusive() {
        let constructs = ConstructFlags(ConstructFlags::SQL_DIALECT_ORACLE);
        let flags = AnalysisFlags(AnalysisFlags::TRUNCATED);
        assert_eq!(
            verdict_hint(constructs, flags, BUILTIN_SQLI_DETECT),
            VerdictHint::Inconclusive
        );
    }
}
