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

//! Legacy XSS path: HTML5 tokenizer helpers and deny-lists.
//!
//! Shared byte-oriented HTML5/XSS compatibility parser.

use deny::{DenyAttrKind, is_deny_attr, is_deny_comment, is_deny_tag, is_deny_url};
use memchr::{memchr, memchr2, memchr3};

/// Bit marking that the single-quote delimiter was seen.
const SINGLE_QUOTE: u8 = 1;
/// Bit marking that the double-quote delimiter was seen.
const DOUBLE_QUOTE: u8 = 2;
/// Bit marking that the backtick delimiter was seen.
const BACK_QUOTE: u8 = 4;
/// Mask for contexts already delimited by a single and double quote.
const SINGLE_AND_DOUBLE_QUOTES: u8 = SINGLE_QUOTE | DOUBLE_QUOTE;
/// Mask for contexts already delimited by a single quote and backtick.
const SINGLE_AND_BACK_QUOTES: u8 = SINGLE_QUOTE | BACK_QUOTE;
/// Mask for contexts already delimited by a double quote and backtick.
const DOUBLE_AND_BACK_QUOTES: u8 = DOUBLE_QUOTE | BACK_QUOTE;

/// Deny-list helpers for legacy XSS (Go `isBlackTag` / related).
mod deny;
mod deny_list;

/// HTML5 tokenizer start context (libinjection-go `html5Flags*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Html5Flags {
    DataState = 0,
    ValueNoQuote = 1,
    ValueSingleQuote = 2,
    ValueDoubleQuote = 3,
    ValueBackQuote = 4,
}

/// Go `isXSS`: run detection in one HTML context.
#[must_use]
pub(crate) fn is_xss(input: &[u8], flags: Html5Flags) -> bool {
    let mut h5 = Html5State::new(input, flags);
    let mut attr_kind = DenyAttrKind::None;
    while let Some(tok) = h5.next_token() {
        // Go clears the prior attribute classification before every token
        // except its value. A deny/style attribute is only decisive once an
        // AttrValue token is emitted.
        if tok.kind != Html5Type::AttrValue {
            attr_kind = DenyAttrKind::None;
        }
        match tok.kind {
            Html5Type::DocType => return true,
            Html5Type::TagComment if is_deny_comment(tok.value) => return true,
            Html5Type::TagNameOpen if is_deny_tag(tok.value) => return true,
            Html5Type::AttrName => {
                attr_kind = is_deny_attr(tok.value);
            },
            Html5Type::AttrValue => {
                let hit = match attr_kind {
                    DenyAttrKind::Deny | DenyAttrKind::Style => true,
                    DenyAttrKind::Url => is_deny_url(tok.value),
                    DenyAttrKind::Indirect => is_deny_attr(tok.value) == DenyAttrKind::Deny,
                    DenyAttrKind::None => false,
                };
                attr_kind = DenyAttrKind::None;
                if hit {
                    return true;
                }
            },
            _ => {
                attr_kind = DenyAttrKind::None;
            },
        };
    }
    false
}

/// Go `IsXSS`: true if any of the five contexts matches.
#[must_use]
pub(crate) fn detect(input: &[u8]) -> bool {
    // DataState can only emit an HTML token after an opening '<'. Avoid
    // constructing and scanning that parser when the byte is absent.
    if (memchr(b'<', input).is_some() && is_xss(input, Html5Flags::DataState))
        || is_xss(input, Html5Flags::ValueNoQuote)
    {
        return true;
    }

    // A quoted context with no raw delimiter emits one unclassified value,
    // reaches EOF, and cannot detect. Visit only contexts with a delimiter.
    let mut cursor = 0;
    let mut seen_quotes = 0;
    while let Some((next_cursor, quote)) = next_unseen_quote(input, cursor, seen_quotes) {
        cursor = next_cursor;
        seen_quotes |= quote;
        let context = match quote {
            SINGLE_QUOTE => Html5Flags::ValueSingleQuote,
            DOUBLE_QUOTE => Html5Flags::ValueDoubleQuote,
            _ => Html5Flags::ValueBackQuote,
        };
        if is_xss(input, context) {
            return true;
        }
    }
    false
}

/// Find the next quoted-value context delimiter not already encountered.
fn next_unseen_quote(input: &[u8], cursor: usize, seen: u8) -> Option<(usize, u8)> {
    let rest = input.get(cursor..)?;
    let relative = match seen {
        0 => memchr3(b'\'', b'"', b'`', rest),
        SINGLE_QUOTE => memchr2(b'"', b'`', rest),
        DOUBLE_QUOTE => memchr2(b'\'', b'`', rest),
        SINGLE_AND_DOUBLE_QUOTES => memchr(b'`', rest),
        BACK_QUOTE => memchr2(b'\'', b'"', rest),
        SINGLE_AND_BACK_QUOTES => memchr(b'"', rest),
        DOUBLE_AND_BACK_QUOTES => memchr(b'\'', rest),
        _ => None,
    }?;
    let quote = match rest.get(relative).copied()? {
        b'\'' => SINGLE_QUOTE,
        b'"' => DOUBLE_QUOTE,
        b'`' => BACK_QUOTE,
        _ => return None,
    };
    Some((cursor + relative + 1, quote))
}

/// HTML5 token kind exposed to the corpus test driver.
#[cfg(feature = "legacy")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Html5TokenKind {
    /// Raw text / CDATA body.
    DataText,
    /// Opening tag name.
    TagNameOpen,
    /// `>` closing an open tag.
    TagNameClose,
    /// `/>` self-closing end.
    TagNameSelfClose,
    /// Close tag name.
    TagClose,
    /// Attribute name.
    AttrName,
    /// Attribute value.
    AttrValue,
    /// Comment or bogus comment body.
    TagComment,
    /// DOCTYPE declaration body.
    DocType,
}

#[cfg(feature = "legacy")]
impl From<Html5Type> for Html5TokenKind {
    fn from(kind: Html5Type) -> Self {
        match kind {
            Html5Type::DataText => Self::DataText,
            Html5Type::TagNameOpen | Html5Type::TagData => Self::TagNameOpen,
            Html5Type::TagNameClose => Self::TagNameClose,
            Html5Type::TagNameSelfClose => Self::TagNameSelfClose,
            Html5Type::TagClose => Self::TagClose,
            Html5Type::AttrName => Self::AttrName,
            Html5Type::AttrValue => Self::AttrValue,
            Html5Type::TagComment => Self::TagComment,
            Html5Type::DocType => Self::DocType,
        }
    }
}

/// Visit HTML5 tokens as zero-copy slices into `input`.
#[cfg(feature = "legacy")]
pub fn html5_visit(
    input: &[u8],
    context: crate::snapshot::XssHtmlContext,
    mut visit: impl FnMut(Html5TokenKind, &[u8]),
) {
    let flags = match context {
        crate::snapshot::XssHtmlContext::Data => Html5Flags::DataState,
        crate::snapshot::XssHtmlContext::AttrUnquoted => Html5Flags::ValueNoQuote,
        crate::snapshot::XssHtmlContext::AttrSingle => Html5Flags::ValueSingleQuote,
        crate::snapshot::XssHtmlContext::AttrDouble => Html5Flags::ValueDoubleQuote,
        crate::snapshot::XssHtmlContext::AttrBacktick => Html5Flags::ValueBackQuote,
    };
    let mut state = Html5State::new(input, flags);
    while let Some(token) = state.next_token() {
        visit(token.kind.into(), token.value);
    }
}

/// Go `html5Type*` token kinds.
#[expect(
    dead_code,
    reason = "TagData is part of the Go enum surface; not all variants emit yet"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Html5Type {
    DataText = 0,
    TagNameOpen = 1,
    TagNameClose = 2,
    TagNameSelfClose = 3,
    TagData = 4,
    TagClose = 5,
    AttrName = 6,
    AttrValue = 7,
    TagComment = 8,
    DocType = 9,
}

/// Iterative HTML states corresponding to libinjection-go's `h5State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Html5ParseState {
    /// Parse ordinary HTML text until the next `<` or EOF.
    Data,
    /// Inspect the byte following `<`.
    TagOpen,
    /// Inspect a possible close tag after `</`.
    EndTagOpen,
    /// Choose a doctype, comment, CDATA, or bogus-comment state after `<!`.
    MarkupDeclarationOpen,
    /// Parse a standard HTML comment body.
    Comment,
    /// Parse a CDATA body.
    CData,
    /// Parse a doctype body.
    Doctype,
    /// Skip separators and begin another attribute or close the tag.
    BeforeAttributeName,
    /// Resolve a slash after a tag name or attribute value.
    SelfClosingStartTag,
    /// Parse an opening or closing tag name.
    TagName,
    /// Emit the `>` ending an opening tag.
    TagNameClose,
    /// Parse one attribute name.
    AttributeName,
    /// Decide whether another attribute follows a name.
    AfterAttributeName,
    /// Select a quoted or unquoted attribute-value state.
    BeforeAttributeValue,
    /// Parse an unquoted attribute value.
    AttributeValueNoQuote,
    /// Parse a single-quoted attribute value.
    AttributeValueSingleQuote,
    /// Parse a double-quoted attribute value.
    AttributeValueDoubleQuote,
    /// Parse a backtick-quoted attribute value.
    AttributeValueBackQuote,
    /// Continue after a quoted attribute value.
    AfterAttributeValueQuoted,
    /// Parse a bogus comment through `>` or EOF.
    BogusComment,
    /// Parse the special `%` bogus-comment form.
    BogusCommentPercent,
    /// Parsing is complete.
    Eof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// One HTML5 token: type + slice into the original input (no copy).
pub(crate) struct Html5Token<'a> {
    /// Token kind (`html5Type*` in Go).
    pub(crate) kind: Html5Type,
    /// Bytes for this token (slice into the original input).
    pub(crate) value: &'a [u8],
}

/// Go `h5State`: tokenizer cursor over `input`.
pub(crate) struct Html5State<'a> {
    /// Full input being tokenized.
    pub(crate) input: &'a [u8],
    /// Byte offset of the next character to read.
    pub(crate) pos: usize,
    /// Defines if the current HTML5 state is parsing an open tag
    pub(crate) state: Html5ParseState,
    /// Go `isClose`: parsing a close tag name (`</...>`).
    is_close: bool,
}

impl<'a> Html5State<'a> {
    /// Start a tokenizer in the given HTML context.
    #[must_use]
    pub(crate) fn new(input: &'a [u8], flags: Html5Flags) -> Self {
        let state = match flags {
            Html5Flags::DataState => Html5ParseState::Data,
            Html5Flags::ValueNoQuote => Html5ParseState::BeforeAttributeName,
            Html5Flags::ValueSingleQuote => Html5ParseState::AttributeValueSingleQuote,
            Html5Flags::ValueDoubleQuote => Html5ParseState::AttributeValueDoubleQuote,
            Html5Flags::ValueBackQuote => Html5ParseState::AttributeValueBackQuote,
        };
        Self {
            input,
            pos: 0,
            state,
            is_close: false,
        }
    }

    /// Go `h5.next()`: emit the next token, or `None` at EOF.
    pub(crate) fn next_token(&mut self) -> Option<Html5Token<'a>> {
        loop {
            let token = match self.state {
                Html5ParseState::Data => self.state_data(),
                Html5ParseState::TagOpen => self.state_tag_open(),
                Html5ParseState::EndTagOpen => self.state_end_tag_open(),
                Html5ParseState::MarkupDeclarationOpen => self.state_markup_declaration_open(),
                Html5ParseState::Comment => self.state_comment(),
                Html5ParseState::CData => self.state_cdata(),
                Html5ParseState::Doctype => self.state_doctype(),
                Html5ParseState::BeforeAttributeName => self.state_before_attribute_name(),
                Html5ParseState::SelfClosingStartTag => self.state_self_closing_start_tag(),
                Html5ParseState::TagName => self.state_tag_name(),
                Html5ParseState::TagNameClose => self.state_tag_name_close(),
                Html5ParseState::AttributeName => self.state_attribute_name(),
                Html5ParseState::AfterAttributeName => self.state_after_attribute_name(),
                Html5ParseState::BeforeAttributeValue => self.state_before_attribute_value(),
                Html5ParseState::AttributeValueNoQuote => self.state_attribute_value_no_quote(),
                Html5ParseState::AttributeValueSingleQuote => self.state_attribute_value_quote(b'\''),
                Html5ParseState::AttributeValueDoubleQuote => self.state_attribute_value_quote(b'"'),
                Html5ParseState::AttributeValueBackQuote => self.state_attribute_value_quote(b'`'),
                Html5ParseState::AfterAttributeValueQuoted => self.state_after_attribute_value_quoted(),
                Html5ParseState::BogusComment => self.state_bogus_comment(),
                Html5ParseState::BogusCommentPercent => self.state_bogus_comment_percent(),
                Html5ParseState::Eof => return None,
            };
            if token.is_some() {
                return token;
            }
            if self.state == Html5ParseState::Eof {
                return None;
            }
        }
    }

    /// Emit data text or transition into a tag after `<`.
    fn state_data(&mut self) -> Option<Html5Token<'a>> {
        if self.pos >= self.input.len() {
            self.state = Html5ParseState::Eof;
            return None;
        }
        if let Some(relative) = self.input.get(self.pos..)?.iter().position(|&b| b == b'<') {
            let start = self.pos;
            if relative == 0 {
                self.pos += 1;
                self.state = Html5ParseState::TagOpen;
                return None;
            }
            self.pos += relative + 1;
            self.state = Html5ParseState::TagOpen;
            return self.token(Html5Type::DataText, start, start + relative);
        }
        let start = self.pos;
        self.pos = self.input.len();
        self.state = Html5ParseState::Eof;
        if start == self.pos {
            None
        } else {
            self.token(Html5Type::DataText, start, self.pos)
        }
    }

    /// Select the state following an opening `<`.
    fn state_tag_open(&mut self) -> Option<Html5Token<'a>> {
        let Some(ch) = self.current() else {
            self.state = Html5ParseState::Eof;
            return None;
        };
        match ch {
            b'!' => {
                self.pos += 1;
                self.state = Html5ParseState::MarkupDeclarationOpen;
                None
            },
            b'/' => {
                self.pos += 1;
                self.is_close = true;
                self.state = Html5ParseState::EndTagOpen;
                None
            },
            b'?' => {
                self.pos += 1;
                self.state = Html5ParseState::BogusComment;
                None
            },
            b'%' => {
                self.pos += 1;
                self.state = Html5ParseState::BogusCommentPercent;
                None
            },
            b if b.is_ascii_alphabetic() || b == 0 => {
                self.state = Html5ParseState::TagName;
                None
            },
            _ if self.pos > 0 => {
                let start = self.pos - 1;
                self.state = Html5ParseState::Data;
                self.token(Html5Type::DataText, start, start + 1)
            },
            _ => {
                self.state = Html5ParseState::Data;
                None
            },
        }
    }

    /// Select a closing-tag name or bogus-comment state after `</`.
    fn state_end_tag_open(&mut self) -> Option<Html5Token<'a>> {
        let Some(ch) = self.current() else {
            self.state = Html5ParseState::Eof;
            return None;
        };
        if ch == b'>' {
            self.state = Html5ParseState::Data;
        } else if ch.is_ascii_alphabetic() {
            self.state = Html5ParseState::TagName;
        } else {
            self.is_close = false;
            self.state = Html5ParseState::BogusComment;
        }
        None
    }

    /// Recognize doctype, comment, and CDATA declarations.
    fn state_markup_declaration_open(&mut self) -> Option<Html5Token<'a>> {
        let rest = self.input.get(self.pos..)?;
        if rest
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"DOCTYPE"))
        {
            self.state = Html5ParseState::Doctype;
        } else if rest.starts_with(b"[CDATA[") {
            self.pos += 7;
            self.state = Html5ParseState::CData;
        } else if rest.starts_with(b"--") {
            self.pos += 2;
            self.state = Html5ParseState::Comment;
        } else {
            self.state = Html5ParseState::BogusComment;
        }
        None
    }

    /// Emit a doctype token ending at `>` or EOF.
    fn state_doctype(&mut self) -> Option<Html5Token<'a>> {
        let start = self.pos;
        if let Some(relative) = self.input.get(self.pos..)?.iter().position(|&b| b == b'>') {
            self.pos += relative + 1;
            self.state = Html5ParseState::Data;
            self.token(Html5Type::DocType, start, start + relative)
        } else {
            self.pos = self.input.len();
            self.state = Html5ParseState::Eof;
            self.token(Html5Type::DocType, start, self.pos)
        }
    }

    /// Finish a self-closing tag or resume attribute parsing.
    fn state_self_closing_start_tag(&mut self) -> Option<Html5Token<'a>> {
        if self.pos >= self.input.len() {
            self.state = Html5ParseState::Eof;
            return None;
        }
        if self.current() == Some(b'>') {
            let start = self.pos.saturating_sub(1);
            self.pos += 1;
            self.state = Html5ParseState::Data;
            return self.token(Html5Type::TagNameSelfClose, start, self.pos);
        }
        self.state = Html5ParseState::BeforeAttributeName;
        None
    }

    /// Emit the closing `>` token for an opening tag.
    fn state_tag_name_close(&mut self) -> Option<Html5Token<'a>> {
        let start = self.pos;
        if self.current() != Some(b'>') {
            self.state = Html5ParseState::Eof;
            return None;
        }
        self.pos += 1;
        self.state = if self.pos < self.input.len() {
            Html5ParseState::Data
        } else {
            Html5ParseState::Eof
        };
        self.is_close = false;
        self.token(Html5Type::TagNameClose, start, self.pos)
    }

    /// Parse and emit an opening-tag or closing-tag name.
    fn state_tag_name(&mut self) -> Option<Html5Token<'a>> {
        let start = self.pos;
        let mut pos = self.pos;
        while pos < self.input.len() {
            let Some(&byte) = self.input.get(pos) else {
                break;
            };
            match byte {
                0 => pos += 1,
                b if is_h5_whitespace(b) => {
                    self.pos = pos + 1;
                    self.state = Html5ParseState::BeforeAttributeName;
                    return self.token(Html5Type::TagNameOpen, start, pos);
                },
                b'/' => {
                    self.pos = pos + 1;
                    self.state = Html5ParseState::SelfClosingStartTag;
                    return self.token(Html5Type::TagNameOpen, start, pos);
                },
                b'>' if self.is_close => {
                    self.pos = pos + 1;
                    self.state = Html5ParseState::Data;
                    self.is_close = false;
                    return self.token(Html5Type::TagClose, start, pos);
                },
                b'>' => {
                    self.pos = pos;
                    self.state = Html5ParseState::TagNameClose;
                    return self.token(Html5Type::TagNameOpen, start, pos);
                },
                _ => pos += 1,
            }
        }
        self.pos = self.input.len();
        self.state = Html5ParseState::Eof;
        self.is_close = false;
        self.token(Html5Type::TagNameOpen, start, self.pos)
    }

    /// Skip separators before the next attribute or the tag close.
    fn state_before_attribute_name(&mut self) -> Option<Html5Token<'a>> {
        loop {
            let Some(ch) = self.skip_white() else {
                self.state = Html5ParseState::Eof;
                return None;
            };
            match ch {
                b'/' => {
                    self.pos += 1;
                    if self.current().is_some_and(|next| next != b'>') {
                        continue;
                    }
                    self.state = Html5ParseState::SelfClosingStartTag;
                    return None;
                },
                b'>' => {
                    let start = self.pos;
                    self.pos += 1;
                    self.state = Html5ParseState::Data;
                    return self.token(Html5Type::TagNameClose, start, self.pos);
                },
                _ => {
                    self.state = Html5ParseState::AttributeName;
                    return None;
                },
            }
        }
    }

    /// Parse one attribute name through whitespace, `=`, `/`, `>`, or EOF.
    fn state_attribute_name(&mut self) -> Option<Html5Token<'a>> {
        let start = self.pos;
        let mut pos = self.pos.saturating_add(1);
        while pos < self.input.len() {
            let Some(&byte) = self.input.get(pos) else {
                break;
            };
            match byte {
                b if is_h5_whitespace(b) => {
                    self.pos = pos + 1;
                    self.state = Html5ParseState::AfterAttributeName;
                    return self.token(Html5Type::AttrName, start, pos);
                },
                b'/' => {
                    self.pos = pos + 1;
                    self.state = Html5ParseState::SelfClosingStartTag;
                    return self.token(Html5Type::AttrName, start, pos);
                },
                b'=' => {
                    self.pos = pos + 1;
                    self.state = Html5ParseState::BeforeAttributeValue;
                    return self.token(Html5Type::AttrName, start, pos);
                },
                b'>' => {
                    self.pos = pos;
                    self.state = Html5ParseState::TagNameClose;
                    return self.token(Html5Type::AttrName, start, pos);
                },
                _ => pos += 1,
            }
        }
        self.pos = self.input.len();
        self.state = Html5ParseState::Eof;
        self.token(Html5Type::AttrName, start, self.pos)
    }

    /// Continue an attribute name, begin its value, or close the tag.
    fn state_after_attribute_name(&mut self) -> Option<Html5Token<'a>> {
        let Some(ch) = self.skip_white() else {
            self.state = Html5ParseState::Eof;
            return None;
        };
        match ch {
            b'/' => {
                self.pos += 1;
                self.state = Html5ParseState::SelfClosingStartTag;
                None
            },
            b'=' => {
                self.pos += 1;
                self.state = Html5ParseState::BeforeAttributeValue;
                None
            },
            b'>' => self.state_tag_name_close(),
            _ => {
                self.state = Html5ParseState::AttributeName;
                None
            },
        }
    }

    /// Select the value parser from its opening quote or first byte.
    fn state_before_attribute_value(&mut self) -> Option<Html5Token<'a>> {
        let Some(ch) = self.skip_white() else {
            self.state = Html5ParseState::Eof;
            return None;
        };
        self.state = match ch {
            b'"' => Html5ParseState::AttributeValueDoubleQuote,
            b'\'' => Html5ParseState::AttributeValueSingleQuote,
            b'`' => Html5ParseState::AttributeValueBackQuote,
            _ => Html5ParseState::AttributeValueNoQuote,
        };
        None
    }

    /// Emit an unquoted attribute value through whitespace, `>`, or EOF.
    fn state_attribute_value_no_quote(&mut self) -> Option<Html5Token<'a>> {
        let start = self.pos;
        let mut pos = self.pos;
        while pos < self.input.len() {
            let Some(&ch) = self.input.get(pos) else {
                break;
            };
            if is_h5_whitespace(ch) {
                self.pos = pos + 1;
                self.state = Html5ParseState::BeforeAttributeName;
                return self.token(Html5Type::AttrValue, start, pos);
            }
            if ch == b'>' {
                self.pos = pos;
                self.state = Html5ParseState::TagNameClose;
                return self.token(Html5Type::AttrValue, start, pos);
            }
            pos += 1;
        }
        self.pos = self.input.len();
        self.state = Html5ParseState::Eof;
        self.token(Html5Type::AttrValue, start, self.pos)
    }

    /// Emit a quoted attribute value through its matching delimiter or EOF.
    fn state_attribute_value_quote(&mut self, quote: u8) -> Option<Html5Token<'a>> {
        if self.pos > 0 {
            self.pos += 1;
        }
        let start = self.pos;
        let relative = self.input.get(self.pos..)?.iter().position(|&b| b == quote);
        if let Some(relative) = relative {
            self.pos += relative + 1;
            self.state = Html5ParseState::AfterAttributeValueQuoted;
            self.token(Html5Type::AttrValue, start, start + relative)
        } else {
            self.pos = self.input.len();
            self.state = Html5ParseState::Eof;
            self.token(Html5Type::AttrValue, start, self.pos)
        }
    }

    /// Continue after a quoted value or close the containing tag.
    fn state_after_attribute_value_quoted(&mut self) -> Option<Html5Token<'a>> {
        let Some(ch) = self.current() else {
            self.state = Html5ParseState::Eof;
            return None;
        };
        match ch {
            b if is_h5_whitespace(b) => {
                self.pos += 1;
                self.state = Html5ParseState::BeforeAttributeName;
                None
            },
            b'/' => {
                self.pos += 1;
                self.state = Html5ParseState::SelfClosingStartTag;
                None
            },
            b'>' => self.state_tag_name_close(),
            _ => {
                self.state = Html5ParseState::BeforeAttributeName;
                None
            },
        }
    }

    /// Emit a standard comment body through its ending marker or EOF.
    fn state_comment(&mut self) -> Option<Html5Token<'a>> {
        let start = self.pos;
        let mut scan = self.pos;
        loop {
            let rest = self.input.get(scan..)?;
            let Some(relative) = rest.iter().position(|&b| b == b'-') else {
                self.pos = self.input.len();
                self.state = Html5ParseState::Eof;
                return self.token(Html5Type::TagComment, start, self.pos);
            };
            let dash = scan + relative;
            // Preserve Go's state machine bounds check while remaining safe.
            if dash.checked_add(3).is_none_or(|end| end > self.input.len()) {
                self.pos = self.input.len();
                self.state = Html5ParseState::Eof;
                return self.token(Html5Type::TagComment, start, self.pos);
            }
            let mut offset = 1;
            while self.input.get(dash + offset) == Some(&0) {
                offset += 1;
            }
            let Some(&next) = self.input.get(dash + offset) else {
                self.pos = self.input.len();
                self.state = Html5ParseState::Eof;
                return self.token(Html5Type::TagComment, start, self.pos);
            };
            if next != b'-' && next != b'!' {
                scan = dash + 1;
                continue;
            }
            offset += 1;
            if self.input.get(dash + offset) != Some(&b'>') {
                scan = dash + 1;
                continue;
            }
            self.pos = dash + offset + 1;
            self.state = Html5ParseState::Data;
            return self.token(Html5Type::TagComment, start, dash);
        }
    }

    /// Emit a CDATA body through `]]>` or EOF.
    fn state_cdata(&mut self) -> Option<Html5Token<'a>> {
        let start = self.pos;
        let mut scan = self.pos;
        loop {
            let rest = self.input.get(scan..)?;
            let Some(relative) = rest.iter().position(|&b| b == b']') else {
                self.pos = self.input.len();
                self.state = Html5ParseState::Eof;
                return self.token(Html5Type::DataText, start, self.pos);
            };
            let bracket = scan + relative;
            // Match Go's moving search cursor and bounded `]]>` check. Keep
            // the check on a slice so malformed input remains panic-free.
            if self.input.get(bracket..bracket.saturating_add(3)) == Some(b"]]>") {
                self.pos = bracket + 3;
                self.state = Html5ParseState::Data;
                return self.token(Html5Type::DataText, start, bracket);
            }
            scan = bracket + 1;
        }
    }

    /// Emit a bogus comment through `>` or EOF.
    fn state_bogus_comment(&mut self) -> Option<Html5Token<'a>> {
        let start = self.pos;
        if let Some(relative) = self.input.get(self.pos..)?.iter().position(|&b| b == b'>') {
            self.pos += relative + 1;
            self.state = Html5ParseState::Data;
            self.token(Html5Type::TagComment, start, start + relative)
        } else {
            self.pos = self.input.len();
            self.state = Html5ParseState::Eof;
            self.token(Html5Type::TagComment, start, self.pos)
        }
    }

    /// Emit the C-compatible `%` bogus-comment form through its terminator or EOF.
    fn state_bogus_comment_percent(&mut self) -> Option<Html5Token<'a>> {
        let start = self.pos;
        let mut scan = self.pos;
        loop {
            let Some(rest) = self.input.get(scan..) else {
                self.pos = self.input.len();
                self.state = Html5ParseState::Eof;
                return self.token(Html5Type::TagComment, start, self.pos);
            };
            let Some(relative) = rest.iter().position(|&b| b == b'%') else {
                self.pos = self.input.len();
                self.state = Html5ParseState::Eof;
                return self.token(Html5Type::TagComment, start, self.pos);
            };
            let Some(percent) = scan.checked_add(relative) else {
                self.pos = self.input.len();
                self.state = Html5ParseState::Eof;
                return self.token(Html5Type::TagComment, start, self.pos);
            };
            let Some(next) = percent.checked_add(1) else {
                self.pos = self.input.len();
                self.state = Html5ParseState::Eof;
                return self.token(Html5Type::TagComment, start, self.pos);
            };
            if next >= self.input.len() {
                self.pos = self.input.len();
                self.state = Html5ParseState::Eof;
                return self.token(Html5Type::TagComment, start, self.pos);
            }
            if self.input.get(next) != Some(&b'>') {
                scan = next;
                continue;
            }
            let Some(end) = next.checked_add(1) else {
                self.pos = self.input.len();
                self.state = Html5ParseState::Eof;
                return self.token(Html5Type::TagComment, start, self.pos);
            };
            self.pos = end;
            self.state = Html5ParseState::Data;
            return self.token(Html5Type::TagComment, start, percent);
        }
    }

    /// Skip HTML whitespace and NUL bytes, returning the next byte.
    fn skip_white(&mut self) -> Option<u8> {
        while let Some(ch) = self.current() {
            if ch == 0 || is_h5_whitespace(ch) {
                self.pos += 1;
            } else {
                return Some(ch);
            }
        }
        None
    }

    /// Return the byte at the current cursor.
    fn current(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    /// Construct a token over a checked range in the original input.
    fn token(&self, kind: Html5Type, start: usize, end: usize) -> Option<Html5Token<'a>> {
        Some(Html5Token {
            kind,
            value: self.input.get(start..end)?,
        })
    }
}

/// Return whether a byte is HTML5 ASCII whitespace.
fn is_h5_whitespace(b: u8) -> bool {
    matches!(b, b'\n' | b'\t' | b'\x0b' | b'\x0c' | b'\r' | b' ')
}

#[cfg(test)]
mod regression_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html5_smoke_ascii_word() {
        let mut h5 = Html5State::new(b"foo", Html5Flags::DataState);
        assert_eq!(
            h5.next_token(),
            Some(Html5Token {
                kind: Html5Type::DataText,
                value: b"foo"
            })
        );
        assert!(h5.next_token().is_none());
    }

    #[test]
    fn is_xss_assertions() {
        assert!(is_xss(b"<!DOCTYPE html>", Html5Flags::DataState));
        assert!(is_xss(b"<IFrAME>", Html5Flags::DataState));
        assert!(!is_xss(b"<xxxx>", Html5Flags::DataState));
        assert!(!is_xss(b"hello", Html5Flags::DataState));
        assert!(is_xss(b"<img onclick=1>", Html5Flags::DataState));
        assert!(is_xss(b"<a href=javascript:alert(1)>", Html5Flags::DataState));
        assert!(is_xss(b"<a href=data:text/html,x>", Html5Flags::DataState));
        assert!(is_xss(b"<a href=&#106;avascript:alert(1)>", Html5Flags::DataState));
        assert!(is_xss(b"<a href=&#x76;bscript:alert(1)>", Html5Flags::DataState));
        assert!(is_xss(b"<scr\0ipt>", Html5Flags::DataState));
        assert!(!is_xss(b"<a href=https://example.com>", Html5Flags::DataState));
        assert!(is_xss(b"<!--`-->", Html5Flags::DataState));
        assert!(is_xss(b"<!--[if IE]>", Html5Flags::DataState));
        assert!(is_xss(b"<!--xml?>", Html5Flags::DataState)); // body starts with xml...
        // tokenizer: <!--xml--> -> body b"xml" - len 3, XML check needs len > 3,
        // so use longer: b"<!--xmlx-->" or b"<!--XML-->" with len>3 body
        assert!(!is_xss(b"<!--XML-->", Html5Flags::DataState)); // body "XML", len == 3
        assert!(is_xss(b"<!--XMLx-->", Html5Flags::DataState)); // len == 4 -> true
    }

    #[test]
    fn bare_closing_tag_resumes_data_tokenization() {
        let mut h5 = Html5State::new(b"</><script>", Html5Flags::DataState);
        assert_eq!(
            h5.next_token(),
            Some(Html5Token {
                kind: Html5Type::DataText,
                value: b">",
            })
        );
        assert_eq!(
            h5.next_token(),
            Some(Html5Token {
                kind: Html5Type::TagClose,
                value: b"script",
            })
        );
        assert!(!is_xss(b"</><script>", Html5Flags::DataState));
        assert!(detect(b"</><script>"));
    }

    #[test]
    fn cdata_bounds_are_safe_at_eof() {
        for input in [
            b"<![CDATA[]]]".as_slice(),
            b"<![CDATA[]]]]".as_slice(),
            b"<![CDATA[a]]b]]]".as_slice(),
            b"<![CDATA[]]".as_slice(),
            b"<![CDATA[]]>".as_slice(),
            b"<![CDATA[x]]>y".as_slice(),
            b"<![CDATA[]]]>".as_slice(),
        ] {
            let _detected = detect(input);
        }
    }

    #[test]
    fn embedded_nulls_in_comment_keywords_are_detected() {
        for input in [
            b"<?im\0port namespace=\"t\">".as_slice(),
            b"<?\0import namespace=\"t\">".as_slice(),
            b"<!\0ENTITY x SYSTEM \"file:///etc/passwd\">".as_slice(),
            b"<!EN\0TITY x SYSTEM \"file:///etc/passwd\">".as_slice(),
        ] {
            assert!(detect(input), "input={input:?}");
        }
    }

    #[test]
    fn attribute_payloads_without_angle_bracket_still_detect() {
        assert!(detect(b"onerror=alert(1)"));
        assert!(!detect(b"myvar=onfoobar=="));
    }

    #[test]
    fn data_text_then_tag_name_open_and_close() {
        let mut h5 = Html5State::new(b"hello<script>", Html5Flags::DataState);
        assert_eq!(
            h5.next_token(),
            Some(Html5Token {
                kind: Html5Type::DataText,
                value: b"hello",
            })
        );
        assert_eq!(h5.pos, 6);
        assert_eq!(h5.state, Html5ParseState::TagOpen);
        assert_eq!(
            h5.next_token(),
            Some(Html5Token {
                kind: Html5Type::TagNameOpen,
                value: b"script",
            })
        );
        assert_eq!(h5.pos, 12);
        assert_eq!(h5.state, Html5ParseState::TagNameClose);
        assert_eq!(
            h5.next_token(),
            Some(Html5Token {
                kind: Html5Type::TagNameClose,
                value: b">",
            })
        );
        assert_eq!(h5.pos, 13);
        assert_eq!(h5.state, Html5ParseState::Eof);
    }

    #[test]
    fn value_no_quote_entry() {
        let mut h5 = Html5State::new(b"foo>", Html5Flags::ValueNoQuote);
        assert_eq!(
            h5.next_token(),
            Some(Html5Token {
                kind: Html5Type::AttrName,
                value: b"foo",
            })
        );
        // then TagNameClose ">" via the before-attribute-name state
        assert_eq!(
            h5.next_token(),
            Some(Html5Token {
                kind: Html5Type::TagNameClose,
                value: b">",
            })
        );
    }

    #[test]
    fn value_single_quote_entry() {
        let mut h5 = Html5State::new(b"bar'", Html5Flags::ValueSingleQuote);
        assert_eq!(
            h5.next_token(),
            Some(Html5Token {
                kind: Html5Type::AttrValue,
                value: b"bar",
            })
        );
    }

    struct Case {
        input: &'static [u8],
        expect: &'static [(Html5Type, &'static [u8])],
    }
    const TOKENIZE_CASES: &[Case] = &[
        Case {
            input: b"<script>",
            expect: &[(Html5Type::TagNameOpen, b"script"), (Html5Type::TagNameClose, b">")],
        },
        Case {
            input: b"<script/>",
            expect: &[
                (Html5Type::TagNameOpen, b"script"),
                (Html5Type::TagNameSelfClose, b"/>"),
            ],
        },
        Case {
            input: b"</script>",
            expect: &[(Html5Type::TagClose, b"script")],
        },
        Case {
            input: b"<script  />",
            expect: &[
                (Html5Type::TagNameOpen, b"script"),
                (Html5Type::TagNameSelfClose, b"/>"),
            ],
        },
        Case {
            input: b"<script   >",
            expect: &[(Html5Type::TagNameOpen, b"script"), (Html5Type::TagNameClose, b">")],
        },
        Case {
            input: b"<script   \x0b >",
            expect: &[(Html5Type::TagNameOpen, b"script"), (Html5Type::TagNameClose, b">")],
        },
        Case {
            input: b"<!--xss-->",
            expect: &[(Html5Type::TagComment, b"xss")],
        },
        Case {
            input: b"<script foo>",
            expect: &[
                (Html5Type::TagNameOpen, b"script"),
                (Html5Type::AttrName, b"foo"),
                (Html5Type::TagNameClose, b">"),
            ],
        },
        Case {
            input: b"<script foo=xpto>",
            expect: &[
                (Html5Type::TagNameOpen, b"script"),
                (Html5Type::AttrName, b"foo"),
                (Html5Type::AttrValue, b"xpto"),
                (Html5Type::TagNameClose, b">"),
            ],
        },
        Case {
            input: b"<script foo='xpto'>",
            expect: &[
                (Html5Type::TagNameOpen, b"script"),
                (Html5Type::AttrName, b"foo"),
                (Html5Type::AttrValue, b"xpto"),
                (Html5Type::TagNameClose, b">"),
            ],
        },
        Case {
            input: b"<!DOCTYPE html>",
            expect: &[(Html5Type::DocType, b"DOCTYPE html")],
        },
        Case {
            input: b"<!doctype html>",
            expect: &[(Html5Type::DocType, b"doctype html")],
        },
        Case {
            input: b"<?foo>",
            expect: &[(Html5Type::TagComment, b"foo")],
        },
        Case {
            input: b"<%foo%>",
            expect: &[(Html5Type::TagComment, b"foo")],
        },
        Case {
            input: b"<!foo>",
            expect: &[(Html5Type::TagComment, b"foo")],
        },
        Case {
            input: b"<!--xss-->",
            expect: &[(Html5Type::TagComment, b"xss")],
        },
        Case {
            input: b"<script2>",
            expect: &[(Html5Type::TagNameOpen, b"script2"), (Html5Type::TagNameClose, b">")],
        },
        Case {
            input: b"<scr\0ipt>",
            expect: &[(Html5Type::TagNameOpen, b"scr\0ipt"), (Html5Type::TagNameClose, b">")],
        },
    ];
    #[test]
    fn tokenizes_in_tag_cases() {
        for case in TOKENIZE_CASES {
            let mut h5 = Html5State::new(case.input, Html5Flags::DataState);
            for &(kind, value) in case.expect {
                assert_eq!(
                    h5.next_token(),
                    Some(Html5Token { kind, value }),
                    "input={:?}",
                    case.input
                );
            }
            assert!(h5.next_token().is_none(), "input={:?}", case.input);
        }
    }
}
