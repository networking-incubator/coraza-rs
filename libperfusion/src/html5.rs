// Copyright (c) 2012-2016, Nick Galbreath
// Copyright (c) 2017-2024, libinjection Contributors
// Copyright 2026 Coraza Kubernetes Operator contributors.
//
// SPDX-License-Identifier: BSD-3-Clause
// See the crate's LICENSE for the complete terms.
//! A small HTML5 tokenizer, after the tokenization chapter of the HTML5 spec

//! with the browser quirks upstream cares about (NULs in tag names,
//! backtick-quoted attribute values, `<% %>` comments).
//!
//! Kept state-for-state with upstream's `libinjection_html5.c`.

#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "Private tokenizer state and transition helpers implement the documented HTML API."
    )
)]
use crate::bytes::{byte_set, cspan, find_byte};

/// The kind of HTML token returned by [`Tokenizer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    /// Text outside a tag.
    DataText,
    /// The name after an opening `<`.
    TagNameOpen,
    /// The name after a closing `</`.
    TagNameClose,
    /// The `/>` ending a self-closing tag.
    TagNameSelfClose,
    /// The `>` ending a tag.
    TagClose,
    /// An attribute name.
    AttrName,
    /// An attribute value.
    AttrValue,
    /// A comment-like token, including malformed tag starts.
    TagComment,
    /// A doctype declaration.
    Doctype,
}

/// A borrowed HTML token. `text` is the exact input slice consumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token<'a> {
    /// Classification of this token.
    pub kind: TokenKind,
    /// Original bytes for this token.
    pub text: &'a [u8],
}

/// Where in a document the input is assumed to start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    /// Between tags.
    Data,
    /// Inside a tag, in an unquoted attribute value.
    ValueNoQuote,
    /// Inside an attribute value quoted with `'`.
    ValueSingleQuote,
    /// Inside an attribute value quoted with `"`.
    ValueDoubleQuote,
    /// Inside an attribute value quoted with `` ` `` (old IE).
    ValueBackQuote,
}

/// The states the tokenizer can rest in between tokens. The remaining
/// states of the spec are always passed through within a single step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Eof,
    Data,
    TagOpen,
    TagNameClose,
    SelfClosingStartTag,
    BeforeAttributeName,
    AfterAttributeName,
    BeforeAttributeValue,
    /// Only ever the initial state, for the quoted-value contexts.
    AttributeValueQuoted(u8),
    AfterAttributeValueQuoted,
}

/// What ends an attribute name: whitespace (see [`is_white`]), '/', '=' or '>'.
///
/// NUL stays inside the name: `black_attr` folds it away, so `<a on\0error=1>` is
/// still an event handler. The second NUL-as-space detection pass in `xss` covers
/// the separate `<a href=x\0onerror=...>` boundary.
const fn html_byte_set(bytes: &[u8]) -> [bool; 256] {
    let mut set = byte_set(bytes);
    set[0] = false;
    set
}

static ATTRIBUTE_NAME_END: [bool; 256] = html_byte_set(b" \t\n\x0b\x0c\r/=>");
/// What ends an unquoted attribute value: whitespace or '>'.
static UNQUOTED_VALUE_END: [bool; 256] = html_byte_set(b" \t\n\x0b\x0c\r>");
/// Attribute-name delimiters for the NUL-as-space XSS pass.
static ATTRIBUTE_NAME_END_NUL: [bool; 256] = byte_set(b" \t\n\x0b\x0c\r/=>");
/// Unquoted-value delimiters for the NUL-as-space XSS pass.
static UNQUOTED_VALUE_END_NUL: [bool; 256] = byte_set(b" \t\n\x0b\x0c\r>");

/// Short spans are cheaper to check directly before searching multiple delimiter groups.
const HTML_SCALAR_PREFIX: usize = 128;

/// Returns the earliest match from a small group of accelerated byte searches.
fn first_match(s: &[u8], matches: [Option<usize>; 3]) -> usize {
    matches.into_iter().flatten().min().unwrap_or(s.len())
}

/// Finds HTML whitespace for an attribute-name span; NUL stays inside the name.
fn html_space_cspan(s: &[u8]) -> usize {
    first_match(
        s,
        [
            memchr::memchr3(b' ', b'\t', b'\n', s),
            memchr::memchr3(0x0B, 0x0C, b'\r', s),
            None,
        ],
    )
}

/// Finds the end of an attribute name using the HTML delimiter bytes.
fn attribute_name_cspan(s: &[u8]) -> usize {
    if s.len() <= HTML_SCALAR_PREFIX {
        return cspan(s, &ATTRIBUTE_NAME_END);
    }

    let prefix = cspan(&s[..HTML_SCALAR_PREFIX], &ATTRIBUTE_NAME_END);
    if prefix < HTML_SCALAR_PREFIX {
        return prefix;
    }

    HTML_SCALAR_PREFIX + attribute_name_rest_cspan(&s[HTML_SCALAR_PREFIX..])
}

/// Attribute-name span with NUL treated as a delimiter for the XSS NUL pass.
fn attribute_name_cspan_nul(s: &[u8]) -> usize {
    cspan(s, &ATTRIBUTE_NAME_END_NUL)
}

/// Searches the long attribute-name tail after the scalar prefix has no match.
#[inline(never)]
fn attribute_name_rest_cspan(s: &[u8]) -> usize {
    first_match(
        s,
        [Some(html_space_cspan(s)), memchr::memchr3(b'/', b'=', b'>', s), None],
    )
}

/// Upstream's `h5_is_white`, a `strchr` that also matches NUL.
fn is_white(ch: u8) -> bool {
    matches!(ch, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r' | 0)
}

/// Iterates over HTML tokens in one caller-selected starting context.
pub struct Tokenizer<'a> {
    s: &'a [u8],
    pos: usize,
    /// Set by `</`, so the tag name that follows is a closing one.
    is_close: bool,
    /// Treat NUL as whitespace in attribute names and unquoted values.
    nul_as_space: bool,
    state: State,
}

impl<'a> Tokenizer<'a> {
    /// Starts tokenization at the beginning of `s` in `context`.
    pub fn new(s: &'a [u8], context: Context) -> Self {
        let state = match context {
            Context::Data => State::Data,
            Context::ValueNoQuote => State::BeforeAttributeName,
            Context::ValueSingleQuote => State::AttributeValueQuoted(b'\''),
            Context::ValueDoubleQuote => State::AttributeValueQuoted(b'"'),
            Context::ValueBackQuote => State::AttributeValueQuoted(b'`'),
        };
        Self {
            s,
            pos: 0,
            is_close: false,
            nul_as_space: false,
            state,
        }
    }

    /// Starts tokenization with NUL treated as whitespace, without copying the input.
    pub(crate) fn new_nul_as_space(s: &'a [u8], context: Context) -> Self {
        let mut tokenizer = Self::new(s, context);
        tokenizer.nul_as_space = true;
        tokenizer
    }

    pub(crate) fn new_data_at(s: &'a [u8], pos: usize) -> Self {
        Self {
            s,
            pos,
            is_close: false,
            nul_as_space: false,
            state: State::Data,
        }
    }

    /// Starts data tokenization at `pos` with NUL treated as whitespace.
    pub(crate) fn new_data_at_nul_as_space(s: &'a [u8], pos: usize) -> Self {
        let mut tokenizer = Self::new_data_at(s, pos);
        tokenizer.nul_as_space = true;
        tokenizer
    }

    fn token(&self, kind: TokenKind, start: usize, len: usize) -> Token<'a> {
        let s = self.s;
        Token {
            kind,
            text: &s[start..start + len],
        }
    }

    /// Skips whitespace and returns the byte that follows, without
    /// consuming it, or `None` at the end of input.
    fn skip_white(&mut self) -> Option<u8> {
        while let Some(&ch) = self.s.get(self.pos) {
            match ch {
                // NUL, VT and CR are skipped by IE only.
                0x00 | b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r' => self.pos += 1,
                // Upstream returns the byte as an `int` through a `char`
                // that is signed on its reference platform, where 0xFF
                // comes out as -1, its end-of-input marker, and ends the
                // scan: "<img \xff onerror=...>" gets through. 0xFF is an
                // ordinary byte here.
                _ => return Some(ch),
            }
        }
        None
    }

    fn state_data(&mut self) -> Option<Token<'a>> {
        let start = self.pos;
        // A run of invalid '<' bytes reaches this state one byte at a time.
        // Avoid calling memchr for each immediate match in that case.
        let next_tag = if self.s.get(start) == Some(&b'<') {
            Some(start)
        } else {
            find_byte(self.s, start, b'<')
        };
        match next_tag {
            None => {
                self.state = State::Eof;
                let len = self.s.len() - start;
                if len == 0 {
                    None
                } else {
                    Some(self.token(TokenKind::DataText, start, len))
                }
            },
            Some(idx) => {
                self.pos = idx + 1;
                self.state = State::TagOpen;
                if idx == start {
                    self.state_tag_open()
                } else {
                    Some(self.token(TokenKind::DataText, start, idx - start))
                }
            },
        }
    }

    /// 12.2.4.8
    fn state_tag_open(&mut self) -> Option<Token<'a>> {
        let &ch = self.s.get(self.pos)?;
        match ch {
            b'!' => {
                self.pos += 1;
                self.state_markup_declaration_open()
            },
            b'/' => {
                self.pos += 1;
                self.is_close = true;
                self.state_end_tag_open()
            },
            b'?' => {
                self.pos += 1;
                self.state_bogus_comment()
            },
            // Not in the spec: the alternative comment format of IE <= 9
            // and Safari < 4.0.3.
            b'%' => {
                self.pos += 1;
                self.state_bogus_comment2()
            },
            // An IE-ism: NUL characters are ignored.
            b'a'..=b'z' | b'A'..=b'Z' | 0 => self.state_tag_name(),
            _ => {
                if self.pos == 0 {
                    return self.state_data();
                }
                // Not a tag after all: the '<' is text.
                self.state = State::Data;
                Some(self.token(TokenKind::DataText, self.pos - 1, 1))
            },
        }
    }

    /// 12.2.4.9
    fn state_end_tag_open(&mut self) -> Option<Token<'a>> {
        let &ch = self.s.get(self.pos)?;
        if ch == b'>' {
            return self.state_data();
        } else if ch.is_ascii_alphabetic() {
            return self.state_tag_name();
        }
        self.is_close = false;
        self.state_bogus_comment()
    }

    fn state_tag_name_close(&mut self) -> Option<Token<'a>> {
        self.is_close = false;
        let start = self.pos;
        self.pos += 1;
        self.state = if self.pos < self.s.len() {
            State::Data
        } else {
            State::Eof
        };
        Some(self.token(TokenKind::TagNameClose, start, 1))
    }

    /// 12.2.4.10
    fn state_tag_name(&mut self) -> Option<Token<'a>> {
        let s = self.s;
        let start = self.pos;
        let mut pos = start;
        while pos < s.len() {
            let ch = s[pos];
            if ch == 0 {
                // Non-standard: some old browsers allow and ignore NULs
                // in tag names.
                pos += 1;
            } else if is_white(ch) {
                self.pos = pos + 1;
                self.state = State::BeforeAttributeName;
                return Some(self.token(TokenKind::TagNameOpen, start, pos - start));
            } else if ch == b'/' {
                self.pos = pos + 1;
                self.state = State::SelfClosingStartTag;
                return Some(self.token(TokenKind::TagNameOpen, start, pos - start));
            } else if ch == b'>' {
                return if self.is_close {
                    self.pos = pos + 1;
                    self.is_close = false;
                    self.state = State::Data;
                    Some(self.token(TokenKind::TagClose, start, pos - start))
                } else {
                    self.pos = pos;
                    self.state = State::TagNameClose;
                    Some(self.token(TokenKind::TagNameOpen, start, pos - start))
                };
            } else {
                pos += 1;
            }
        }

        self.state = State::Eof;
        Some(self.token(TokenKind::TagNameOpen, start, s.len() - start))
    }

    /// 12.2.4.34
    fn state_before_attribute_name(&mut self) -> Option<Token<'a>> {
        loop {
            match self.skip_white()? {
                b'/' => {
                    let remaining = &self.s[self.pos..];
                    self.pos += remaining.iter().position(|&ch| ch != b'/').unwrap_or(remaining.len());
                    // Anything but "/>" starts this state over. Upstream
                    // loops here rather than going through the self-closing
                    // state, which would recurse once per '/'.
                    if self.s.get(self.pos).is_some_and(|&ch| ch != b'>') {
                        continue;
                    }
                    return self.state_self_closing_start_tag();
                },
                b'>' => {
                    let start = self.pos;
                    self.pos += 1;
                    self.state = State::Data;
                    return Some(self.token(TokenKind::TagNameClose, start, 1));
                },
                _ => return self.state_attribute_name(),
            }
        }
    }

    fn state_attribute_name(&mut self) -> Option<Token<'a>> {
        let s = self.s;
        let start = self.pos;
        // The first byte is part of the name, whatever it is.
        let end = start
            + 1
            + if self.nul_as_space {
                attribute_name_cspan_nul(&s[start + 1..])
            } else {
                attribute_name_cspan(&s[start + 1..])
            };
        (self.state, self.pos) = match s.get(end) {
            None => (State::Eof, end),
            Some(b'/') => (State::SelfClosingStartTag, end + 1),
            Some(b'=') => (State::BeforeAttributeValue, end + 1),
            Some(b'>') => (State::TagNameClose, end),
            Some(_) => (State::AfterAttributeName, end + 1),
        };
        Some(self.token(TokenKind::AttrName, start, end - start))
    }

    /// 12.2.4.36
    fn state_after_attribute_name(&mut self) -> Option<Token<'a>> {
        match self.skip_white()? {
            b'/' => {
                self.pos += 1;
                self.state_self_closing_start_tag()
            },
            b'=' => {
                self.pos += 1;
                self.state_before_attribute_value()
            },
            b'>' => self.state_tag_name_close(),
            _ => self.state_attribute_name(),
        }
    }

    /// 12.2.4.37
    fn state_before_attribute_value(&mut self) -> Option<Token<'a>> {
        let Some(ch) = self.skip_white() else {
            self.state = State::Eof;
            return None;
        };
        match ch {
            // The backtick is non-standard, IE only.
            b'"' | b'\'' | b'`' => self.state_attribute_value_quote(ch),
            _ => self.state_attribute_value_no_quote(),
        }
    }

    fn state_attribute_value_quote(&mut self, quote: u8) -> Option<Token<'a>> {
        // Skip the opening quote, except at the very start of the input:
        // there the tokenizer was started inside a quoted value, and
        // an input of "'><foo" has an empty value.
        if self.pos > 0 {
            self.pos += 1;
        }

        let start = self.pos;
        match find_byte(self.s, start, quote) {
            None => {
                self.state = State::Eof;
                Some(self.token(TokenKind::AttrValue, start, self.s.len() - start))
            },
            Some(idx) => {
                self.state = State::AfterAttributeValueQuoted;
                self.pos = idx + 1;
                Some(self.token(TokenKind::AttrValue, start, idx - start))
            },
        }
    }

    fn state_attribute_value_no_quote(&mut self) -> Option<Token<'a>> {
        let s = self.s;
        let start = self.pos;
        let end = start
            + cspan(
                &s[start..],
                if self.nul_as_space {
                    &UNQUOTED_VALUE_END_NUL
                } else {
                    &UNQUOTED_VALUE_END
                },
            );
        (self.state, self.pos) = match s.get(end) {
            // Unlike elsewhere, upstream leaves the position where it was.
            None => (State::Eof, start),
            Some(b'>') => (State::TagNameClose, end),
            Some(_) => (State::BeforeAttributeName, end + 1),
        };
        Some(self.token(TokenKind::AttrValue, start, end - start))
    }

    /// 12.2.4.41
    fn state_after_attribute_value_quoted(&mut self) -> Option<Token<'a>> {
        let &ch = self.s.get(self.pos)?;
        if is_white(ch) {
            self.pos += 1;
            self.state_before_attribute_name()
        } else if ch == b'/' {
            self.pos += 1;
            self.state_self_closing_start_tag()
        } else if ch == b'>' {
            let start = self.pos;
            self.pos += 1;
            self.state = State::Data;
            Some(self.token(TokenKind::TagNameClose, start, 1))
        } else {
            self.state_before_attribute_name()
        }
    }

    /// 12.2.4.43
    fn state_self_closing_start_tag(&mut self) -> Option<Token<'a>> {
        let &ch = self.s.get(self.pos)?;
        if ch == b'>' {
            let start = self.pos - 1;
            self.pos += 1;
            self.state = State::Data;
            Some(self.token(TokenKind::TagNameSelfClose, start, 2))
        } else {
            self.state_before_attribute_name()
        }
    }

    /// 12.2.4.44
    fn state_bogus_comment(&mut self) -> Option<Token<'a>> {
        let s = self.s;
        let start = self.pos;
        match find_byte(s, start, b'>') {
            None => {
                self.pos = s.len();
                self.state = State::Eof;
                Some(self.token(TokenKind::TagComment, start, s.len() - start))
            },
            Some(idx) => {
                self.pos = idx + 1;
                self.state = State::Data;
                Some(self.token(TokenKind::TagComment, start, idx - start))
            },
        }
    }

    /// 12.2.4.44, for `<% ... %>`.
    fn state_bogus_comment2(&mut self) -> Option<Token<'a>> {
        let s = self.s;
        let start = self.pos;
        let mut pos = start;
        loop {
            match find_byte(s, pos, b'%') {
                Some(idx) if idx + 1 < s.len() => {
                    if s[idx + 1] != b'>' {
                        pos = idx + 1;
                        continue;
                    }
                    self.pos = idx + 2;
                    self.state = State::Data;
                    return Some(self.token(TokenKind::TagComment, start, idx - start));
                },
                _ => {
                    self.pos = s.len();
                    self.state = State::Eof;
                    return Some(self.token(TokenKind::TagComment, start, s.len() - start));
                },
            }
        }
    }

    /// 8.2.4.45
    fn state_markup_declaration_open(&mut self) -> Option<Token<'a>> {
        let rest = &self.s[self.pos..];
        if rest
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"DOCTYPE"))
        {
            self.state_doctype()
        } else if rest.starts_with(b"[CDATA[") {
            // Upper case required.
            self.pos += 7;
            self.state_cdata()
        } else if rest.starts_with(b"--") {
            self.pos += 2;
            self.state_comment()
        } else {
            self.state_bogus_comment()
        }
    }

    /// 12.2.4.48 to 12.2.4.51: a comment ends at the end of input, at `-->`
    /// or at `-!>`, with any NULs after the first '-' ignored.
    fn state_comment(&mut self) -> Option<Token<'a>> {
        let s = self.s;
        let len = s.len();
        let start = self.pos;
        let mut pos = start;
        // The comment runs to the end of input if there is no '-' left, or
        // fewer than three bytes from it.
        while let Some(idx) = find_byte(s, pos, b'-').filter(|&idx| idx + 3 <= len) {
            // Skip all NULs.
            let mut offset = 1;
            while idx + offset < len && s[idx + offset] == 0 {
                offset += 1;
            }
            if idx + offset == len {
                break;
            }

            let ch = s[idx + offset];
            if ch != b'-' && ch != b'!' {
                pos = idx + 1;
                continue;
            }

            offset += 1;
            if idx + offset == len {
                break;
            }

            if s[idx + offset] != b'>' {
                pos = idx + 1;
                continue;
            }
            offset += 1;

            self.pos = idx + offset;
            self.state = State::Data;
            return Some(self.token(TokenKind::TagComment, start, idx - start));
        }

        self.state = State::Eof;
        Some(self.token(TokenKind::TagComment, start, len - start))
    }

    fn state_cdata(&mut self) -> Option<Token<'a>> {
        let s = self.s;
        let len = s.len();
        let start = self.pos;
        let mut pos = start;
        loop {
            // As for comments: nothing found, or fewer than three bytes left.
            match find_byte(s, pos, b']').filter(|&idx| idx + 3 <= len) {
                None => {
                    self.state = State::Eof;
                    return Some(self.token(TokenKind::DataText, start, len - start));
                },
                Some(idx) if s[idx + 1] == b']' && s[idx + 2] == b'>' => {
                    self.state = State::Data;
                    self.pos = idx + 3;
                    return Some(self.token(TokenKind::DataText, start, idx - start));
                },
                Some(idx) => pos = idx + 1,
            }
        }
    }

    /// 8.2.4.52
    fn state_doctype(&mut self) -> Option<Token<'a>> {
        let s = self.s;
        let start = self.pos;
        match find_byte(s, start, b'>') {
            None => {
                self.state = State::Eof;
                Some(self.token(TokenKind::Doctype, start, s.len() - start))
            },
            Some(idx) => {
                self.state = State::Data;
                self.pos = idx + 1;
                Some(self.token(TokenKind::Doctype, start, idx - start))
            },
        }
    }
}

impl<'a> Iterator for Tokenizer<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Token<'a>> {
        match self.state {
            State::Eof => None,
            State::Data => self.state_data(),
            State::TagOpen => self.state_tag_open(),
            State::TagNameClose => self.state_tag_name_close(),
            State::SelfClosingStartTag => self.state_self_closing_start_tag(),
            State::BeforeAttributeName => self.state_before_attribute_name(),
            State::AfterAttributeName => self.state_after_attribute_name(),
            State::BeforeAttributeValue => self.state_before_attribute_value(),
            State::AttributeValueQuoted(quote) => self.state_attribute_value_quote(quote),
            State::AfterAttributeValueQuoted => self.state_after_attribute_value_quoted(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collects token kinds and owned token bytes for direct context assertions.
    fn token_pairs(context: Context, input: &[u8]) -> Vec<(TokenKind, Vec<u8>)> {
        Tokenizer::new(input, context)
            .map(|token| (token.kind, token.text.to_vec()))
            .collect()
    }

    #[test]
    fn attribute_tokens_preserve_embedded_nul_bytes_and_spans() {
        let input = b"<a on\0error=ja\0va:>";
        let tokens: Vec<_> = Tokenizer::new(input, Context::Data).collect();
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::AttrName && token.text == b"on\0error")
        );
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::AttrValue && token.text == b"ja\0va:")
        );
    }

    #[test]
    fn accelerated_attribute_name_span_matches_the_byte_table_for_every_byte() {
        let lengths = [
            0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, 128, 129, 255, 256, 257,
        ];
        for byte in u8::MIN..=u8::MAX {
            for length in lengths {
                if length == 0 {
                    assert_eq!(attribute_name_cspan(&[]), cspan(&[], &ATTRIBUTE_NAME_END));
                    continue;
                }
                for position in 0..length {
                    let mut input = vec![b'a'; length];
                    input[position] = byte;
                    assert_eq!(
                        attribute_name_cspan(&input),
                        cspan(&input, &ATTRIBUTE_NAME_END),
                        "attribute-name delimiter {byte:#04x} at {position}/{length}"
                    );
                }
            }
        }
    }

    #[test]
    fn accelerated_html_spans_return_the_earliest_of_multiple_delimiters() {
        let delimiters = [b' ', b'\t', b'\n', 0x0B, 0x0C, b'\r', b'/', b'=', b'>'];
        for length in [2, 3, 7, 16, 31, 64, 65, 127] {
            for first in delimiters {
                for second in delimiters {
                    let mut input = vec![b'a'; length];
                    let early = length / 3;
                    let late = length * 2 / 3;
                    input[early] = first;
                    input[late] = second;
                    assert_eq!(
                        attribute_name_cspan(&input),
                        cspan(&input, &ATTRIBUTE_NAME_END),
                        "attribute-name delimiters {first:#04x}, {second:#04x} in {length} bytes"
                    );
                }
            }
        }
    }

    #[test]
    fn optimized_delimiters_preserve_tokens_in_all_starting_contexts() {
        assert_eq!(
            token_pairs(Context::Data, b"<a href=value>"),
            vec![
                (TokenKind::TagNameOpen, b"a".to_vec()),
                (TokenKind::AttrName, b"href".to_vec()),
                (TokenKind::AttrValue, b"value".to_vec()),
                (TokenKind::TagNameClose, b">".to_vec()),
            ]
        );
        assert_eq!(
            token_pairs(Context::ValueNoQuote, b"href=value>"),
            vec![
                (TokenKind::AttrName, b"href".to_vec()),
                (TokenKind::AttrValue, b"value".to_vec()),
                (TokenKind::TagNameClose, b">".to_vec()),
            ]
        );
        assert_eq!(
            token_pairs(Context::ValueSingleQuote, b"value'"),
            vec![(TokenKind::AttrValue, b"value".to_vec())]
        );
        assert_eq!(
            token_pairs(Context::ValueDoubleQuote, b"value\""),
            vec![(TokenKind::AttrValue, b"value".to_vec())]
        );
        assert_eq!(
            token_pairs(Context::ValueBackQuote, b"value`"),
            vec![(TokenKind::AttrValue, b"value".to_vec())]
        );
    }
}
