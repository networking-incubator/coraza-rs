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

//! Stage-1 SQL construct classifiers (stack-only heuristics).

#![allow(clippy::missing_docs_in_private_items, reason = "internal detector helpers")]

use crate::{
    engine::{
        ascii::{
            find_ignore_ascii_case, for_each_ignore_ascii_case, is_space, word_boundary_after, word_boundary_before,
        },
        normalize::{NormView, original_span_for_normalized},
        token::{TokenBuf, TokenKind},
    },
    limits::MAX_EVIDENCE,
    snapshot::{ConstructFlags, EvidenceSet, EvidenceSpan, SqlDialect, SqliQuoteMode},
};

/// Classification output for one `SQLi` pass.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SqliClassifyResult {
    /// Matched construct bits.
    pub constructs: ConstructFlags,
    /// Evidence spans (offsets into original input).
    pub evidence: EvidenceSet,
    /// Best-effort quote mode.
    pub quote_mode: SqliQuoteMode,
    /// Best-effort dialect hint.
    pub dialect: SqlDialect,
}

/// Run all `SQLi` construct detectors.
#[must_use]
pub(crate) fn classify(norm: NormView<'_>, tokens: &TokenBuf) -> SqliClassifyResult {
    let mut out = SqliClassifyResult::default();
    let hay_orig = norm.original;
    let hay_norm = norm.bytes;

    detect_union(hay_orig, hay_norm, &mut out);
    detect_tautology(hay_orig, hay_norm, &mut out);
    detect_string_break(hay_orig, &mut out);
    detect_stacked(hay_orig, tokens, &mut out);
    detect_comments(hay_orig, tokens, &mut out);
    detect_functions(hay_orig, hay_norm, &mut out);
    detect_boolean_blind(hay_orig, hay_norm, &mut out);
    detect_keyword_chain(hay_orig, hay_norm, &mut out);
    detect_dialect(hay_orig, tokens, &mut out);
    out.quote_mode = infer_quote_mode(hay_orig);
    out
}

fn detect_union(orig: &[u8], norm: &[u8], out: &mut SqliClassifyResult) {
    for hay in [orig, norm] {
        for_each_ignore_ascii_case(hay, b"union", |pos| {
            if word_boundary_before(hay, pos) && word_boundary_after(hay, pos, 5) {
                out.constructs.0 |= ConstructFlags::SQL_UNION;
                push_match_evidence(&mut out.evidence, orig, hay, pos, 5);
            }
        });
        if out.constructs.0 & ConstructFlags::SQL_UNION != 0 {
            return;
        }
    }
}

fn detect_tautology(orig: &[u8], norm: &[u8], out: &mut SqliClassifyResult) {
    const PATTERNS: &[&[u8]] = &[
        b"or 1=1",
        b"or '1'='1",
        b"or \"1\"=\"1",
        b"and 1=1",
        b"or true",
        b"and true",
        b"'='",
        b"\"=\"",
    ];
    for hay in [orig, norm] {
        for pat in PATTERNS {
            if let Some(pos) = find_ignore_ascii_case(hay, pat) {
                out.constructs.0 |= ConstructFlags::SQL_TAUTOLOGY;
                push_match_evidence(&mut out.evidence, orig, hay, pos, pat.len());
                return;
            }
        }
    }
}

fn detect_string_break(orig: &[u8], out: &mut SqliClassifyResult) {
    const PATTERNS: &[&[u8]] = &[b"' or", b"\" or", b"';", b"\";--", b"'--", b"\"--"];
    for pat in PATTERNS {
        if let Some(pos) = find_ignore_ascii_case(orig, pat) {
            out.constructs.0 |= ConstructFlags::SQL_STRING_BREAK;
            push_evidence(&mut out.evidence, orig, pos, pat.len());
            return;
        }
    }
}

fn detect_stacked(orig: &[u8], tokens: &TokenBuf, out: &mut SqliClassifyResult) {
    const VERBS: &[&[u8]] = &[
        b"select", b"insert", b"update", b"delete", b"drop", b"create", b"alter", b"exec",
    ];
    for token in tokens.slots.iter().take(usize::from(tokens.count)) {
        if token.kind != TokenKind::Semicolon {
            continue;
        }
        let start = usize::from(token.offset.saturating_add(token.len));
        let Some(tail) = orig.get(start..) else { continue };
        for verb in VERBS {
            if let Some(relative) = find_ignore_ascii_case(tail, verb) {
                let pos = start + relative;
                if word_boundary_before(orig, pos)
                    && word_boundary_after(orig, pos, verb.len())
                    && !token_contains(tokens, pos, TokenKind::Comment)
                    && !token_contains(tokens, pos, TokenKind::StringSingle)
                    && !token_contains(tokens, pos, TokenKind::StringDouble)
                {
                    out.constructs.0 |= ConstructFlags::SQL_STACKED_QUERY;
                    push_evidence(&mut out.evidence, orig, pos, verb.len());
                    return;
                }
            }
        }
    }
}

fn detect_comments(orig: &[u8], tokens: &TokenBuf, out: &mut SqliClassifyResult) {
    for token in tokens.slots.iter().take(usize::from(tokens.count)) {
        if token.kind != TokenKind::Comment {
            continue;
        }
        let pos = usize::from(token.offset);
        let Some(bytes) = orig.get(pos..) else { continue };
        let marker_len = if bytes.starts_with(b"#") {
            1
        } else if bytes.starts_with(b"--") {
            if bytes.get(2).is_some_and(|next| !is_space(*next)) {
                continue;
            }
            2
        } else if bytes.starts_with(b"/*") {
            2
        } else {
            continue;
        };
        out.constructs.0 |= ConstructFlags::SQL_COMMENT_INJECTION;
        push_evidence(&mut out.evidence, orig, pos, marker_len);
        if bytes.starts_with(b"/*") && bytes.get(2) == Some(&b'!') {
            out.constructs.0 |= ConstructFlags::SQL_DIALECT_MYSQL;
        }
        return;
    }
}

fn detect_functions(orig: &[u8], norm: &[u8], out: &mut SqliClassifyResult) {
    const FUNCS: &[&[u8]] = &[
        b"sleep(",
        b"benchmark(",
        b"load_file(",
        b"xp_cmdshell",
        b"waitfor delay",
        b"extractvalue(",
        b"updatexml(",
        b"pg_sleep(",
    ];
    for hay in [orig, norm] {
        for func in FUNCS {
            if let Some(pos) = find_ignore_ascii_case(hay, func) {
                out.constructs.0 |= ConstructFlags::SQL_FUNCTION_CALL;
                push_match_evidence(&mut out.evidence, orig, hay, pos, func.len());
                return;
            }
        }
    }
}

fn detect_boolean_blind(orig: &[u8], norm: &[u8], out: &mut SqliClassifyResult) {
    for hay in [orig, norm] {
        for_each_ignore_ascii_case(hay, b" and ", |pos| {
            if has_comparison_near(hay, pos + 5) {
                out.constructs.0 |= ConstructFlags::SQL_BOOLEAN_BLIND;
                push_match_evidence(&mut out.evidence, orig, hay, pos, 5);
            }
        });
        for_each_ignore_ascii_case(hay, b" or ", |pos| {
            if has_comparison_near(hay, pos + 4) {
                out.constructs.0 |= ConstructFlags::SQL_BOOLEAN_BLIND;
                push_match_evidence(&mut out.evidence, orig, hay, pos, 4);
            }
        });
        if out.constructs.0 & ConstructFlags::SQL_BOOLEAN_BLIND != 0 {
            return;
        }
    }
}

fn has_comparison_near(hay: &[u8], start: usize) -> bool {
    let end = start.saturating_add(12).min(hay.len());
    let slice = hay.get(start..end).unwrap_or(&[]);
    slice.contains(&b'=') || find_ignore_ascii_case(slice, b"like").is_some()
}

fn detect_keyword_chain(orig: &[u8], norm: &[u8], out: &mut SqliClassifyResult) {
    for hay in [orig, norm] {
        if let Some(sel) = find_ignore_ascii_case(hay, b"select") {
            let after = sel.saturating_add(6);
            let tail = hay.get(after..).unwrap_or(&[]);
            if find_ignore_ascii_case(tail, b"from").is_some() {
                out.constructs.0 |= ConstructFlags::SQL_KEYWORD_CHAIN;
                push_match_evidence(&mut out.evidence, orig, hay, sel, 6);
                return;
            }
        }
        if find_ignore_ascii_case(hay, b"union").is_some() && find_ignore_ascii_case(hay, b"select").is_some() {
            out.constructs.0 |= ConstructFlags::SQL_KEYWORD_CHAIN;
            return;
        }
    }
}

fn detect_dialect(orig: &[u8], tokens: &TokenBuf, out: &mut SqliClassifyResult) {
    if contains_outside_quoted(orig, tokens, b"`") {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_MYSQL;
        out.dialect = SqlDialect::Mysql;
    }
    if contains_outside_quoted(orig, tokens, b"#") {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_MYSQL;
        out.dialect = SqlDialect::Mysql;
    }
    if let Some(pos) = find_bracket_identifier(orig, tokens) {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_MSSQL;
        out.dialect = SqlDialect::Mssql;
        push_evidence(&mut out.evidence, orig, pos, bracket_len(orig, pos));
    }
    if let Some(pos) = find_word_outside(orig, tokens, b"exec") {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_MSSQL;
        out.dialect = SqlDialect::Mssql;
        push_evidence(&mut out.evidence, orig, pos, 4);
    }
    if let Some(pos) = find_word_outside(orig, tokens, b"dual") {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_ORACLE;
        out.dialect = SqlDialect::Oracle;
        push_evidence(&mut out.evidence, orig, pos, 4);
    } else if let Some(pos) = find_q_quote(orig, tokens) {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_ORACLE;
        out.dialect = SqlDialect::Oracle;
        push_evidence(&mut out.evidence, orig, pos, 2);
    }
}

fn token_contains(tokens: &TokenBuf, pos: usize, kind: TokenKind) -> bool {
    tokens.slots.iter().take(usize::from(tokens.count)).any(|token| {
        token.kind == kind
            && pos >= usize::from(token.offset)
            && pos < usize::from(token.offset.saturating_add(token.len))
    })
}

fn contains_outside_quoted(hay: &[u8], tokens: &TokenBuf, needle: &[u8]) -> bool {
    let mut offset = 0;
    while let Some(relative) = find_ignore_ascii_case(hay.get(offset..).unwrap_or_default(), needle) {
        let pos = offset + relative;
        if !token_contains(tokens, pos, TokenKind::StringSingle)
            && !token_contains(tokens, pos, TokenKind::StringDouble)
        {
            return true;
        }
        offset = pos.saturating_add(1);
    }
    false
}

fn find_word_outside(hay: &[u8], tokens: &TokenBuf, word: &[u8]) -> Option<usize> {
    let mut offset = 0;
    while let Some(relative) = find_ignore_ascii_case(hay.get(offset..).unwrap_or_default(), word) {
        let pos = offset + relative;
        if word_boundary_before(hay, pos)
            && word_boundary_after(hay, pos, word.len())
            && !token_contains(tokens, pos, TokenKind::StringSingle)
            && !token_contains(tokens, pos, TokenKind::StringDouble)
        {
            return Some(pos);
        }
        offset = pos.saturating_add(1);
    }
    None
}

fn find_q_quote(hay: &[u8], tokens: &TokenBuf) -> Option<usize> {
    let mut offset = 0;
    while let Some(relative) = find_ignore_ascii_case(hay.get(offset..).unwrap_or_default(), b"q'") {
        let pos = offset + relative;
        if word_boundary_before(hay, pos)
            && !token_contains(tokens, pos, TokenKind::StringSingle)
            && !token_contains(tokens, pos, TokenKind::StringDouble)
        {
            return Some(pos);
        }
        offset = pos.saturating_add(1);
    }
    None
}

fn find_bracket_identifier(hay: &[u8], tokens: &TokenBuf) -> Option<usize> {
    for (pos, byte) in hay.iter().enumerate() {
        if *byte == b'['
            && !token_contains(tokens, pos, TokenKind::StringSingle)
            && !token_contains(tokens, pos, TokenKind::StringDouble)
            && hay.get(pos + 1..).is_some_and(|tail| tail.contains(&b']'))
        {
            return Some(pos);
        }
    }
    None
}

fn bracket_len(hay: &[u8], start: usize) -> usize {
    hay.get(start..)
        .and_then(|tail| tail.iter().position(|byte| *byte == b']'))
        .map_or(1, |end| end + 1)
}

fn infer_quote_mode(orig: &[u8]) -> SqliQuoteMode {
    if orig.contains(&b'\'') {
        SqliQuoteMode::Single
    } else if orig.contains(&b'"') {
        SqliQuoteMode::Double
    } else if orig.contains(&b'`') {
        SqliQuoteMode::Backtick
    } else {
        SqliQuoteMode::None
    }
}

fn push_evidence(evidence: &mut EvidenceSet, hay: &[u8], pos: usize, len: usize) {
    if usize::from(evidence.count) >= MAX_EVIDENCE {
        return;
    }
    let offset = u16::try_from(pos).unwrap_or(u16::MAX);
    let Ok(span_len) = u16::try_from(len.min(hay.len().saturating_sub(pos))) else {
        return;
    };
    let idx = usize::from(evidence.count);
    if let Some(slot) = evidence.spans.get_mut(idx) {
        *slot = EvidenceSpan { offset, len: span_len };
        evidence.count = evidence.count.saturating_add(1);
    }
}

fn push_match_evidence(evidence: &mut EvidenceSet, original: &[u8], hay: &[u8], pos: usize, len: usize) {
    if hay.as_ptr() == original.as_ptr() {
        push_evidence(evidence, original, pos, len);
    } else if let Some((offset, span_len)) = original_span_for_normalized(original, pos, len) {
        push_evidence(evidence, original, offset, span_len);
    }
}
