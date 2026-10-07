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

//! Stage-1 XSS construct classifiers.

#![allow(clippy::missing_docs_in_private_items, reason = "internal detector helpers")]

use crate::{
    engine::{
        ascii::{
            find_ignore_ascii_case, for_each_ignore_ascii_case, is_space, word_boundary_after, word_boundary_before,
        },
        normalize::{NormView, original_span_for_normalized, original_span_from_map},
    },
    snapshot::{ConstructFlags, EvidenceSet, EvidenceSpan, XssHtmlContext},
    xss::legacy,
};

/// Classification output for one XSS pass.
#[derive(Clone, Debug, Default)]
pub(crate) struct XssClassifyResult {
    /// Matched construct bits.
    pub constructs: ConstructFlags,
    /// Evidence spans.
    pub evidence: EvidenceSet,
    /// HTML context hint.
    pub html_context: XssHtmlContext,
}

#[derive(Clone, Copy)]
struct EvidenceSource<'a> {
    original: &'a [u8],
    original_spans: Option<&'a [(u32, u8)]>,
}

/// Run XSS construct detectors.
#[must_use]
pub(crate) fn classify(norm: &NormView<'_>, html_context: XssHtmlContext) -> XssClassifyResult {
    let original_spans = norm.original_spans.as_deref();
    let mut result = classify_in_context(norm, html_context, original_spans);
    if html_context != XssHtmlContext::Data {
        let data_result = classify_in_context(norm, XssHtmlContext::Data, original_spans);
        result.constructs.0 |= data_result.constructs.0;
        for span in &data_result.evidence.spans {
            push_evidence(&mut result.evidence, norm.original, span.offset, span.len);
        }
    }
    result.evidence.deduplicate();
    result
}

fn classify_in_context(
    norm: &NormView<'_>,
    html_context: XssHtmlContext,
    original_spans: Option<&[(u32, u8)]>,
) -> XssClassifyResult {
    let mut out = XssClassifyResult {
        html_context,
        ..XssClassifyResult::default()
    };
    let orig = norm.original;
    let norm_bytes = norm.bytes.as_ref();

    detect_script(orig, norm_bytes, html_context, original_spans, &mut out);
    detect_iframe(orig, norm_bytes, html_context, &mut out);
    detect_object(orig, norm_bytes, html_context, &mut out);
    detect_svg(orig, norm_bytes, html_context, &mut out);
    detect_event_handlers(orig, norm_bytes, original_spans, &mut out);
    detect_javascript_url(orig, norm_bytes, original_spans, &mut out);
    detect_data_url(orig, norm_bytes, original_spans, &mut out);
    detect_expression(orig, norm_bytes, &mut out);
    detect_comment_bypass(orig, html_context, &mut out);
    detect_doctype(orig, norm_bytes, html_context, original_spans, &mut out);
    if !out.constructs.any_xss() && legacy::detect(orig) {
        out.constructs.0 |= ConstructFlags::XSS_HTML_DENYLIST;
    }
    out
}

fn detect_script(
    orig: &[u8],
    norm: &[u8],
    context: XssHtmlContext,
    original_spans: Option<&[(u32, u8)]>,
    out: &mut XssClassifyResult,
) {
    if context != XssHtmlContext::Data {
        return;
    }
    for hay in [orig, norm] {
        for_each_ignore_ascii_case(hay, b"<script", |pos| {
            if word_boundary_after(hay, pos + 1, 6) {
                out.constructs.0 |= ConstructFlags::XSS_TAG_SCRIPT;
                push_match_evidence(
                    &mut out.evidence,
                    EvidenceSource {
                        original: orig,
                        original_spans,
                    },
                    hay,
                    pos,
                    7,
                );
            }
        });
        if out.constructs.0 & ConstructFlags::XSS_TAG_SCRIPT != 0 {
            return;
        }
    }
}

fn detect_iframe(orig: &[u8], norm: &[u8], context: XssHtmlContext, out: &mut XssClassifyResult) {
    if context != XssHtmlContext::Data {
        return;
    }
    for hay in [orig, norm] {
        if find_tag(hay, b"<iframe") {
            out.constructs.0 |= ConstructFlags::XSS_TAG_IFRAME;
            return;
        }
    }
}

fn detect_object(orig: &[u8], norm: &[u8], context: XssHtmlContext, out: &mut XssClassifyResult) {
    if context != XssHtmlContext::Data {
        return;
    }
    for hay in [orig, norm] {
        if find_tag(hay, b"<object") {
            out.constructs.0 |= ConstructFlags::XSS_TAG_OBJECT;
            return;
        }
    }
}

fn detect_svg(orig: &[u8], norm: &[u8], context: XssHtmlContext, out: &mut XssClassifyResult) {
    if context != XssHtmlContext::Data {
        return;
    }
    for hay in [orig, norm] {
        if find_tag(hay, b"<svg") {
            out.constructs.0 |= ConstructFlags::XSS_TAG_SVG;
            return;
        }
    }
}

fn detect_event_handlers(orig: &[u8], norm: &[u8], original_spans: Option<&[(u32, u8)]>, out: &mut XssClassifyResult) {
    const EVENTS: &[&[u8]] = &[
        b"onerror",
        b"onload",
        b"onclick",
        b"onmouseover",
        b"onfocus",
        b"onblur",
        b"onchange",
        b"onsubmit",
    ];
    if out.html_context != XssHtmlContext::Data {
        return;
    }
    for hay in [orig, norm] {
        for ev in EVENTS {
            for_each_ignore_ascii_case(hay, ev, |pos| {
                if word_boundary_before(hay, pos) && attr_assignment_after(hay, pos, ev.len()) {
                    out.constructs.0 |= ConstructFlags::XSS_EVENT_HANDLER;
                    push_match_evidence(
                        &mut out.evidence,
                        EvidenceSource {
                            original: orig,
                            original_spans,
                        },
                        hay,
                        pos,
                        ev.len(),
                    );
                }
            });
        }
        if out.constructs.0 & ConstructFlags::XSS_EVENT_HANDLER != 0 {
            return;
        }
    }
}

fn detect_javascript_url(orig: &[u8], norm: &[u8], original_spans: Option<&[(u32, u8)]>, out: &mut XssClassifyResult) {
    for hay in [orig, norm] {
        if let Some(pos) = find_ignore_ascii_case(hay, b"javascript:")
            && word_boundary_before(hay, pos)
        {
            out.constructs.0 |= ConstructFlags::XSS_URL_JAVASCRIPT;
            push_match_evidence(
                &mut out.evidence,
                EvidenceSource {
                    original: orig,
                    original_spans,
                },
                hay,
                pos,
                11,
            );
            return;
        }
    }
}

fn detect_data_url(orig: &[u8], norm: &[u8], original_spans: Option<&[(u32, u8)]>, out: &mut XssClassifyResult) {
    for hay in [orig, norm] {
        if let Some(pos) = find_ignore_ascii_case(hay, b"data:text/html")
            && word_boundary_before(hay, pos)
        {
            out.constructs.0 |= ConstructFlags::XSS_URL_DATA;
            push_match_evidence(
                &mut out.evidence,
                EvidenceSource {
                    original: orig,
                    original_spans,
                },
                hay,
                pos,
                14,
            );
            return;
        }
        if let Some(pos) = find_ignore_ascii_case(hay, b"data:")
            && word_boundary_before(hay, pos)
        {
            out.constructs.0 |= ConstructFlags::XSS_URL_DATA;
            push_match_evidence(
                &mut out.evidence,
                EvidenceSource {
                    original: orig,
                    original_spans,
                },
                hay,
                pos,
                5,
            );
            return;
        }
    }
}

fn detect_expression(orig: &[u8], norm: &[u8], out: &mut XssClassifyResult) {
    for hay in [orig, norm] {
        if find_ignore_ascii_case(hay, b"expression(").is_some() {
            out.constructs.0 |= ConstructFlags::XSS_STYLE_EXPRESSION;
            return;
        }
    }
}

fn detect_comment_bypass(orig: &[u8], context: XssHtmlContext, out: &mut XssClassifyResult) {
    if context != XssHtmlContext::Data {
        return;
    }
    if find_ignore_ascii_case(orig, b"<!--").is_some() || find_ignore_ascii_case(orig, b"<![cdata[").is_some() {
        out.constructs.0 |= ConstructFlags::XSS_COMMENT_BYPASS;
    }
}

fn detect_doctype(
    orig: &[u8],
    norm: &[u8],
    context: XssHtmlContext,
    original_spans: Option<&[(u32, u8)]>,
    out: &mut XssClassifyResult,
) {
    if context != XssHtmlContext::Data {
        return;
    }
    for hay in [orig, norm] {
        if let Some(pos) = find_ignore_ascii_case(hay, b"<!doctype") {
            out.constructs.0 |= ConstructFlags::XSS_DOCTYPE;
            push_match_evidence(
                &mut out.evidence,
                EvidenceSource {
                    original: orig,
                    original_spans,
                },
                hay,
                pos,
                9,
            );
            return;
        }
    }
}

fn find_tag(hay: &[u8], tag: &[u8]) -> bool {
    let mut offset = 0;
    while let Some(relative) = find_ignore_ascii_case(hay.get(offset..).unwrap_or_default(), tag) {
        let pos = offset + relative;
        if word_boundary_after(hay, pos + 1, tag.len().saturating_sub(1)) {
            return true;
        }
        offset = pos.saturating_add(1);
    }
    false
}

fn attr_assignment_after(hay: &[u8], start: usize, len: usize) -> bool {
    let mut pos = start.saturating_add(len);
    while hay.get(pos).is_some_and(|byte| is_space(*byte)) {
        pos += 1;
    }
    hay.get(pos) == Some(&b'=')
}

fn push_evidence(evidence: &mut EvidenceSet, hay: &[u8], pos: usize, len: usize) {
    if hay.get(pos..).is_some() {
        let span = EvidenceSpan {
            offset: pos,
            len: len.min(hay.len().saturating_sub(pos)),
        };
        evidence.spans.push(span);
    }
}

fn push_match_evidence(evidence: &mut EvidenceSet, source: EvidenceSource<'_>, hay: &[u8], pos: usize, len: usize) {
    if hay.as_ptr() == source.original.as_ptr() {
        push_evidence(evidence, source.original, pos, len);
    } else {
        let mapped = match source.original_spans {
            Some(spans) => original_span_from_map(spans, pos, len),
            None => original_span_for_normalized(source.original, pos, len),
        };
        if let Some((offset, span_len)) = mapped {
            push_evidence(evidence, source.original, offset, span_len);
        }
    }
}

/// Infer HTML context from entry hint and input shape.
#[must_use]
pub(crate) fn infer_html_context(input: &[u8]) -> XssHtmlContext {
    if input.starts_with(b"\"") {
        XssHtmlContext::AttrDouble
    } else if input.starts_with(b"'") {
        XssHtmlContext::AttrSingle
    } else if input.starts_with(b"`") {
        XssHtmlContext::AttrBacktick
    } else if input.contains(&b'=') && !input.contains(&b'<') {
        XssHtmlContext::AttrUnquoted
    } else {
        XssHtmlContext::Data
    }
}
