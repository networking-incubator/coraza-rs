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

//! Stage-1 SQL construct classifiers.

#![allow(clippy::missing_docs_in_private_items, reason = "internal detector helpers")]

use crate::{
    engine::{
        ascii::{
            find_ignore_ascii_case, for_each_ignore_ascii_case, is_space, word_boundary_after, word_boundary_before,
        },
        normalize::{NormView, original_span_for_normalized, original_span_from_map},
        token::{TokenBuf, TokenKind},
    },
    snapshot::{ConstructFlags, EvidenceSet, EvidenceSpan, SqlDialect, SqliQuoteMode},
};

/// Classification output for one `SQLi` pass.
#[derive(Clone, Debug, Default)]
pub(crate) struct SqliClassifyResult {
    /// Matched construct bits.
    pub constructs: ConstructFlags,
    /// Evidence spans (offsets into original input).
    pub evidence: EvidenceSet,
    /// Best-effort quote mode.
    pub quote_mode: SqliQuoteMode,
    /// Best-effort dialect hint.
    pub dialect: SqlDialect,
    /// Original byte ranges corresponding to normalized bytes, for analyzer evidence.
    original_spans: Option<Vec<(u32, u8)>>,
}

/// Run all `SQLi` construct detectors.
#[must_use]
pub(crate) fn classify(norm: NormView<'_>, tokens: &TokenBuf) -> SqliClassifyResult {
    let mut out = SqliClassifyResult {
        original_spans: norm.original_spans,
        ..SqliClassifyResult::default()
    };
    let hay_orig = norm.original;
    let hay_norm = norm.bytes.as_ref();

    detect_union(hay_orig, hay_norm, &mut out);
    detect_tautology(hay_orig, hay_norm, &mut out);
    detect_string_break(hay_orig, &mut out);
    detect_stacked(hay_norm, hay_orig, tokens, &mut out);
    detect_comments(hay_norm, hay_orig, tokens, &mut out);
    detect_functions(hay_orig, hay_norm, &mut out);
    detect_boolean_blind(hay_orig, hay_norm, &mut out);
    detect_numeric_injection(hay_orig, hay_norm, &mut out);
    detect_keyword_chain(hay_orig, hay_norm, &mut out);
    detect_dialect(hay_norm, hay_orig, tokens, &mut out);
    out.quote_mode = infer_quote_mode(hay_orig);
    out.evidence.deduplicate();
    out.original_spans = None;
    out
}

fn detect_union(orig: &[u8], norm: &[u8], out: &mut SqliClassifyResult) {
    for hay in [orig, norm] {
        for_each_ignore_ascii_case(hay, b"union", |pos| {
            if word_boundary_before(hay, pos) && word_boundary_after(hay, pos, 5) {
                out.constructs.0 |= ConstructFlags::SQL_UNION;
                push_match_evidence(out, orig, hay, pos, 5);
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
            if let Some((pos, end)) = find_sql_phrase(hay, pat) {
                out.constructs.0 |= ConstructFlags::SQL_TAUTOLOGY;
                push_match_evidence(out, orig, hay, pos, end - pos);
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

fn detect_stacked(hay: &[u8], original: &[u8], tokens: &TokenBuf, out: &mut SqliClassifyResult) {
    const VERBS: &[&[u8]] = &[
        b"select", b"insert", b"update", b"delete", b"drop", b"create", b"alter", b"exec",
    ];
    let Some(start) = tokens
        .entries
        .iter()
        .find(|token| token.kind == TokenKind::Semicolon)
        .map(|token| token.offset.saturating_add(token.len))
    else {
        return;
    };
    let Some(tail) = hay.get(start..) else { return };
    for verb in VERBS {
        let mut search = 0;
        while let Some(search_tail) = tail.get(search..) {
            let Some(relative) = find_ignore_ascii_case(search_tail, verb) else {
                break;
            };
            let pos = start + search + relative;
            if word_boundary_before(hay, pos)
                && word_boundary_after(hay, pos, verb.len())
                && !token_contains(tokens, pos, TokenKind::Comment)
                && !token_contains(tokens, pos, TokenKind::StringSingle)
                && !token_contains(tokens, pos, TokenKind::StringDouble)
            {
                out.constructs.0 |= ConstructFlags::SQL_STACKED_QUERY;
                push_match_evidence(out, original, hay, pos, verb.len());
                return;
            }
            search = relative.saturating_add(search).saturating_add(1);
        }
    }
}

fn detect_comments(hay: &[u8], original: &[u8], tokens: &TokenBuf, out: &mut SqliClassifyResult) {
    for token in &tokens.entries {
        if token.kind != TokenKind::Comment {
            continue;
        }
        let pos = token.offset;
        let Some(bytes) = hay.get(pos..) else { continue };
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
        push_match_evidence(out, original, hay, pos, marker_len);
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
                push_match_evidence(out, orig, hay, pos, func.len());
                return;
            }
        }
    }
}

fn detect_boolean_blind(orig: &[u8], norm: &[u8], out: &mut SqliClassifyResult) {
    for hay in [orig, norm] {
        for word in [b"and".as_slice(), b"or"] {
            let mut offset = 0;
            while let Some((pos, end)) = find_sql_phrase_from(hay, word, offset) {
                if word_boundary_before(hay, pos)
                    && word_boundary_after(hay, pos, word.len())
                    && has_comparison_near(hay, end)
                {
                    out.constructs.0 |= ConstructFlags::SQL_BOOLEAN_BLIND;
                    push_match_evidence(out, orig, hay, pos, end - pos);
                }
                offset = pos.saturating_add(1);
            }
        }
        if out.constructs.0 & ConstructFlags::SQL_BOOLEAN_BLIND != 0 {
            return;
        }
    }
}

/// Match a SQL phrase where each space in `pattern` accepts one or more SQL
/// whitespace bytes or plus signs. Plus is included because request parsers
/// commonly present form-encoded spaces to this descriptive analyzer.
fn find_sql_phrase(hay: &[u8], pattern: &[u8]) -> Option<(usize, usize)> {
    find_sql_phrase_from(hay, pattern, 0)
}

fn find_sql_phrase_from(hay: &[u8], pattern: &[u8], start: usize) -> Option<(usize, usize)> {
    let first = *pattern.first()?;
    for pos in start..hay.len() {
        if !hay.get(pos).is_some_and(|byte| byte.eq_ignore_ascii_case(&first)) {
            continue;
        }
        let (mut input_pos, mut pattern_pos) = (pos, 0);
        while pattern_pos < pattern.len() {
            if pattern.get(pattern_pos) == Some(&b' ') {
                if !hay.get(input_pos).is_some_and(|byte| is_sql_separator(*byte)) {
                    break;
                }
                while pattern.get(pattern_pos) == Some(&b' ') {
                    pattern_pos += 1;
                }
                while hay.get(input_pos).is_some_and(|byte| is_sql_separator(*byte)) {
                    input_pos += 1;
                }
            } else {
                let expected = pattern.get(pattern_pos)?;
                if !hay
                    .get(input_pos)
                    .is_some_and(|byte| byte.eq_ignore_ascii_case(expected))
                {
                    break;
                }
                input_pos += 1;
                pattern_pos += 1;
            }
        }
        if pattern_pos == pattern.len() {
            return Some((pos, input_pos));
        }
    }
    None
}

fn is_sql_separator(byte: u8) -> bool {
    is_space(byte) || byte == b'+'
}

fn has_comparison_near(hay: &[u8], start: usize) -> bool {
    let end = start.saturating_add(12).min(hay.len());
    let slice = hay.get(start..end).unwrap_or(&[]);
    slice.contains(&b'=') || find_ignore_ascii_case(slice, b"like").is_some()
}

fn detect_numeric_injection(orig: &[u8], norm: &[u8], out: &mut SqliClassifyResult) {
    for hay in [orig, norm] {
        let mut operator_start = 0;
        while operator_start < hay.len() {
            let Some(&byte) = hay.get(operator_start) else { break };
            let operator_len = match (byte, hay.get(operator_start + 1)) {
                (b'<' | b'>', Some(b'=' | b'>')) | (b'!', Some(b'=')) => 2,
                (b'=' | b'<' | b'>', _) => 1,
                _ => {
                    operator_start += 1;
                    continue;
                },
            };

            let mut left_end = operator_start;
            while left_end > 0 && hay.get(left_end - 1).is_some_and(|b| is_sql_separator(*b)) {
                left_end -= 1;
            }
            let mut left_start = left_end;
            while left_start > 0 && hay.get(left_start - 1).is_some_and(u8::is_ascii_digit) {
                left_start -= 1;
            }

            let mut right_start = operator_start.saturating_add(operator_len);
            while hay.get(right_start).is_some_and(|b| is_sql_separator(*b)) {
                right_start += 1;
            }
            let mut right_end = right_start;
            while hay.get(right_end).is_some_and(u8::is_ascii_digit) {
                right_end += 1;
            }

            if left_start < left_end && right_start < right_end {
                out.constructs.0 |= ConstructFlags::SQL_NUMERIC_INJECTION;
                push_match_evidence(out, orig, hay, left_start, right_end - left_start);
                return;
            }
            operator_start = operator_start.saturating_add(operator_len);
        }
    }
}

fn detect_keyword_chain(orig: &[u8], norm: &[u8], out: &mut SqliClassifyResult) {
    for hay in [orig, norm] {
        if let Some(sel) = find_word_from(hay, b"select", 0)
            && find_word_from(hay, b"from", sel.saturating_add(6)).is_some()
        {
            out.constructs.0 |= ConstructFlags::SQL_KEYWORD_CHAIN;
            push_match_evidence(out, orig, hay, sel, 6);
            return;
        }
        if find_word_from(hay, b"union", 0).is_some() && find_word_from(hay, b"select", 0).is_some() {
            out.constructs.0 |= ConstructFlags::SQL_KEYWORD_CHAIN;
            return;
        }
    }
}

/// Find a whole ASCII word at or after `start` without changing byte offsets.
fn find_word_from(hay: &[u8], word: &[u8], start: usize) -> Option<usize> {
    let mut offset = start;
    while let Some(relative) = find_ignore_ascii_case(hay.get(offset..)?, word) {
        let pos = offset.checked_add(relative)?;
        if word_boundary_before(hay, pos) && word_boundary_after(hay, pos, word.len()) {
            return Some(pos);
        }
        offset = pos.saturating_add(1);
    }
    None
}

fn detect_dialect(hay: &[u8], original: &[u8], tokens: &TokenBuf, out: &mut SqliClassifyResult) {
    if contains_outside_quoted(hay, tokens, b"`") {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_MYSQL;
        out.dialect = SqlDialect::Mysql;
    }
    if contains_outside_quoted(hay, tokens, b"#") {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_MYSQL;
        out.dialect = SqlDialect::Mysql;
    }
    if let Some(pos) = find_bracket_identifier(hay, tokens) {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_MSSQL;
        out.dialect = SqlDialect::Mssql;
        push_match_evidence(out, original, hay, pos, bracket_len(hay, pos));
    }
    if let Some(pos) = find_word_outside(hay, tokens, b"exec") {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_MSSQL;
        out.dialect = SqlDialect::Mssql;
        push_match_evidence(out, original, hay, pos, 4);
    }
    if let Some(pos) = find_word_outside(hay, tokens, b"dual") {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_ORACLE;
        out.dialect = SqlDialect::Oracle;
        push_match_evidence(out, original, hay, pos, 4);
    } else if let Some(pos) = find_q_quote(hay, tokens) {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_ORACLE;
        out.dialect = SqlDialect::Oracle;
        push_match_evidence(out, original, hay, pos, 2);
    }
}

fn token_contains(tokens: &TokenBuf, pos: usize, kind: TokenKind) -> bool {
    tokens
        .entries
        .get(..tokens.entries.partition_point(|token| token.offset <= pos))
        .and_then(|tokens| tokens.last())
        .is_some_and(|token| token.kind == kind && pos < token.offset.saturating_add(token.len))
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
    let last_close = hay.iter().rposition(|byte| *byte == b']')?;
    for (pos, byte) in hay.iter().enumerate().take(last_close) {
        if *byte == b'['
            && !token_contains(tokens, pos, TokenKind::StringSingle)
            && !token_contains(tokens, pos, TokenKind::StringDouble)
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
    let Some(_) = hay.get(pos..) else { return };
    let span = EvidenceSpan {
        offset: pos,
        len: len.min(hay.len().saturating_sub(pos)),
    };
    evidence.spans.push(span);
}

fn push_match_evidence(out: &mut SqliClassifyResult, original: &[u8], hay: &[u8], pos: usize, len: usize) {
    if hay.as_ptr() == original.as_ptr() {
        push_evidence(&mut out.evidence, original, pos, len);
    } else {
        let mapped = match out.original_spans.as_deref() {
            Some(spans) => original_span_from_map(spans, pos, len),
            None => original_span_for_normalized(original, pos, len),
        };
        if let Some((offset, span_len)) = mapped {
            push_evidence(&mut out.evidence, original, offset, span_len);
        }
    }
}
