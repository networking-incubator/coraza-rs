//! A small HTML5 tokenizer, after the tokenization chapter of the HTML5 spec
//! with the browser quirks upstream cares about (NULs in tag names,
//! backtick-quoted attribute values, `<% %>` comments).
//!
//! Kept state-for-state with upstream's `libinjection_html5.c`.

use crate::bytes::find_byte;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    DataText,
    TagNameOpen,
    TagNameClose,
    TagNameSelfClose,
    TagClose,
    AttrName,
    AttrValue,
    TagComment,
    Doctype,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token<'a> {
    pub kind: TokenKind,
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

/// Upstream's `h5_is_white`, a `strchr` that also matches NUL.
fn is_white(ch: u8) -> bool {
    matches!(ch, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r' | 0)
}

pub struct Tokenizer<'a> {
    s: &'a [u8],
    pos: usize,
    /// Set by `</`, so the tag name that follows is a closing one.
    is_close: bool,
    state: State,
}

impl<'a> Tokenizer<'a> {
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
            state,
        }
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
                // comes out as -1: its end-of-input marker.
                0xFF => return None,
                _ => return Some(ch),
            }
        }
        None
    }

    fn state_data(&mut self) -> Option<Token<'a>> {
        let start = self.pos;
        match find_byte(self.s, start, b'<') {
            None => {
                self.state = State::Eof;
                let len = self.s.len() - start;
                if len == 0 {
                    None
                } else {
                    Some(self.token(TokenKind::DataText, start, len))
                }
            }
            Some(idx) => {
                self.pos = idx + 1;
                self.state = State::TagOpen;
                if idx == start {
                    self.state_tag_open()
                } else {
                    Some(self.token(TokenKind::DataText, start, idx - start))
                }
            }
        }
    }

    /// 12.2.4.8
    fn state_tag_open(&mut self) -> Option<Token<'a>> {
        let &ch = self.s.get(self.pos)?;
        match ch {
            b'!' => {
                self.pos += 1;
                self.state_markup_declaration_open()
            }
            b'/' => {
                self.pos += 1;
                self.is_close = true;
                self.state_end_tag_open()
            }
            b'?' => {
                self.pos += 1;
                self.state_bogus_comment()
            }
            // Not in the spec: the alternative comment format of IE <= 9
            // and Safari < 4.0.3.
            b'%' => {
                self.pos += 1;
                self.state_bogus_comment2()
            }
            // An IE-ism: NUL characters are ignored.
            b'a'..=b'z' | b'A'..=b'Z' | 0 => self.state_tag_name(),
            _ => {
                if self.pos == 0 {
                    return self.state_data();
                }
                // Not a tag after all: the '<' is text.
                self.state = State::Data;
                Some(self.token(TokenKind::DataText, self.pos - 1, 1))
            }
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
                    self.pos += 1;
                    // Anything but "/>" starts this state over. Upstream
                    // loops here rather than going through the self-closing
                    // state, which would recurse once per '/'.
                    if self.s.get(self.pos).is_some_and(|&ch| ch != b'>') {
                        continue;
                    }
                    return self.state_self_closing_start_tag();
                }
                b'>' => {
                    let start = self.pos;
                    self.pos += 1;
                    self.state = State::Data;
                    return Some(self.token(TokenKind::TagNameClose, start, 1));
                }
                _ => return self.state_attribute_name(),
            }
        }
    }

    fn state_attribute_name(&mut self) -> Option<Token<'a>> {
        let s = self.s;
        let start = self.pos;
        let mut pos = start + 1;
        while pos < s.len() {
            let ch = s[pos];
            let (state, next_pos) = if is_white(ch) {
                (State::AfterAttributeName, pos + 1)
            } else if ch == b'/' {
                (State::SelfClosingStartTag, pos + 1)
            } else if ch == b'=' {
                (State::BeforeAttributeValue, pos + 1)
            } else if ch == b'>' {
                (State::TagNameClose, pos)
            } else {
                pos += 1;
                continue;
            };
            self.state = state;
            self.pos = next_pos;
            return Some(self.token(TokenKind::AttrName, start, pos - start));
        }

        self.state = State::Eof;
        self.pos = s.len();
        Some(self.token(TokenKind::AttrName, start, s.len() - start))
    }

    /// 12.2.4.36
    fn state_after_attribute_name(&mut self) -> Option<Token<'a>> {
        match self.skip_white()? {
            b'/' => {
                self.pos += 1;
                self.state_self_closing_start_tag()
            }
            b'=' => {
                self.pos += 1;
                self.state_before_attribute_value()
            }
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
            }
            Some(idx) => {
                self.state = State::AfterAttributeValueQuoted;
                self.pos = idx + 1;
                Some(self.token(TokenKind::AttrValue, start, idx - start))
            }
        }
    }

    fn state_attribute_value_no_quote(&mut self) -> Option<Token<'a>> {
        let s = self.s;
        let start = self.pos;
        let mut pos = start;
        while pos < s.len() {
            let ch = s[pos];
            if is_white(ch) {
                self.pos = pos + 1;
                self.state = State::BeforeAttributeName;
                return Some(self.token(TokenKind::AttrValue, start, pos - start));
            } else if ch == b'>' {
                self.pos = pos;
                self.state = State::TagNameClose;
                return Some(self.token(TokenKind::AttrValue, start, pos - start));
            }
            pos += 1;
        }

        self.state = State::Eof;
        Some(self.token(TokenKind::AttrValue, start, s.len() - start))
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
            }
            Some(idx) => {
                self.pos = idx + 1;
                self.state = State::Data;
                Some(self.token(TokenKind::TagComment, start, idx - start))
            }
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
                }
                _ => {
                    self.pos = s.len();
                    self.state = State::Eof;
                    return Some(self.token(TokenKind::TagComment, start, s.len() - start));
                }
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
                }
                Some(idx) if s[idx + 1] == b']' && s[idx + 2] == b'>' => {
                    self.state = State::Data;
                    self.pos = idx + 3;
                    return Some(self.token(TokenKind::DataText, start, idx - start));
                }
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
            }
            Some(idx) => {
                self.state = State::Data;
                self.pos = idx + 1;
                Some(self.token(TokenKind::Doctype, start, idx - start))
            }
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
