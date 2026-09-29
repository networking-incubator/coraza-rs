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
//! Enabled only with the `legacy` feature.

use deny::{DenyAttrKind, is_deny_attr, is_deny_comment, is_deny_tag, is_deny_url};

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
    // Go: remember attr type from AttrName until AttrValue (or reset).
    let mut attr_kind = DenyAttrKind::None;
    while let Some(tok) = h5.next_token() {
        match tok.kind {
            Html5Type::DocType => return true,
            Html5Type::TagComment if is_deny_comment(tok.value) => return true,
            Html5Type::TagNameOpen if is_deny_tag(tok.value) => return true,
            Html5Type::AttrName => {
                attr_kind = is_deny_attr(tok.value);
                match attr_kind {
                    DenyAttrKind::Deny | DenyAttrKind::Style => return true,
                    // Url / Indirect: wait for AttrValue
                    _ => {},
                }
            },
            Html5Type::AttrValue => {
                let hit = match attr_kind {
                    DenyAttrKind::Url => is_deny_url(tok.value),
                    DenyAttrKind::Indirect => {
                        matches!(is_deny_attr(tok.value), DenyAttrKind::Deny | DenyAttrKind::Style)
                    },
                    _ => false,
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
    // DataState can only emit tag-related tokens after '<'. The four
    // attribute-value contexts still detect payloads without it.
    (input.contains(&b'<') && is_xss(input, Html5Flags::DataState))
        || is_xss(input, Html5Flags::ValueNoQuote)
        || is_xss(input, Html5Flags::ValueSingleQuote)
        || is_xss(input, Html5Flags::ValueDoubleQuote)
        || is_xss(input, Html5Flags::ValueBackQuote)
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

/// Internal representation of the current Html state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Html5ParseState {
    /// Represents a state where just data is being parsed
    Data,
    /// Represents a state where a tag open was found (<)
    InTag,
    /// Entry / mid-tag attribute value.
    /// `quote` is `None` for unquoted; `Some(q)` for delimiter `q` (`'`, `"`, or backtick).
    InAttrValue {
        /// Quote byte, or `None` if the value is unquoted.
        quote: Option<u8>,
    },
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
    /// After `AttrName`, the next `=` begins a value; otherwise `=` can start a name.
    expect_attr_equals: bool,
}

impl<'a> Html5State<'a> {
    /// Start a tokenizer in the given HTML context.
    #[must_use]
    pub(crate) fn new(input: &'a [u8], flags: Html5Flags) -> Self {
        let state = match flags {
            Html5Flags::DataState => Html5ParseState::Data,
            // Go's unquoted value context starts at before-attribute-name,
            // allowing inputs such as `onerror=alert(1)` without '<'.
            Html5Flags::ValueNoQuote => Html5ParseState::InTag,
            Html5Flags::ValueSingleQuote => Html5ParseState::InAttrValue { quote: Some(b'\'') },
            Html5Flags::ValueDoubleQuote => Html5ParseState::InAttrValue { quote: Some(b'"') },
            Html5Flags::ValueBackQuote => Html5ParseState::InAttrValue { quote: Some(b'`') },
        };
        Self {
            input,
            pos: 0,
            state,
            is_close: false,
            expect_attr_equals: false,
        }
    }

    /// Go `h5.next()`: emit the next token, or `None` at EOF.
    pub(crate) fn next_token(&mut self) -> Option<Html5Token<'a>> {
        loop {
            if self.pos >= self.input.len() {
                return None;
            }
            let token = match self.state {
                Html5ParseState::InTag => self.next_in_tag(),
                Html5ParseState::Data => self.next_in_data(),
                Html5ParseState::InAttrValue { quote } => self.next_in_attr_value(quote),
            };
            if token.is_some() {
                return token;
            }
        }
    }

    /// Deal with `InTag` state
    fn next_in_tag(&mut self) -> Option<Html5Token<'a>> {
        self.skip_html_whitespace();

        match self.current()? {
            b'/' => self.handle_slash_in_tag(),
            b'>' => self.tag_close(),
            b'=' if self.expect_attr_equals => self.attr_value(),
            _ => self.attr_name(),
        }
    }

    /// Deal with `Data` state
    fn next_in_data(&mut self) -> Option<Html5Token<'a>> {
        if self.current()? == b'<' {
            self.advance();
            return self.after_lt();
        }
        let start = self.pos;
        while self.current().is_some_and(|b| b != b'<') {
            self.advance();
        }
        self.emit(Html5Type::DataText, start)
    }

    /// Deal with `InAttrValue` state
    fn next_in_attr_value(&mut self, quote: Option<u8>) -> Option<Html5Token<'a>> {
        let start = self.pos;
        if let Some(q) = quote {
            while self.current().is_some_and(|b| b != q) {
                self.advance();
            }
            let value = self.slice_from(start)?;
            if self.current() == Some(q) {
                self.advance();
            }
            self.state = Html5ParseState::InTag;
            Some(Html5Token {
                kind: Html5Type::AttrValue,
                value,
            })
        } else {
            while self
                .current()
                .is_some_and(|b| !is_html_whitespace(b) && b != b'>' && b != b'/')
            {
                self.advance();
            }
            let value = self.slice_from(start)?;
            self.state = Html5ParseState::InTag;
            Some(Html5Token {
                kind: Html5Type::AttrValue,
                value,
            })
        }
    }

    /// Deal with the whole case after '<' character
    fn after_lt(&mut self) -> Option<Html5Token<'a>> {
        let first = self.current()?;

        // <!-- ... -->  |  <!DOCTYPE ...>  |  <![CDATA[...]]>  |  <!...> bogus
        if first == b'!' {
            self.advance(); // consume '!'

            // <!-- comment -->
            if self.current() == Some(b'-') {
                self.advance();
                if self.current() == Some(b'-') {
                    self.advance(); // past "<!--"
                    return self.read_comment();
                }
                // single '-' after '!': fall through to bogus
            }

            // <![CDATA[...]]>
            if self.input.get(self.pos..).is_some_and(|s| s.starts_with(b"[CDATA[")) {
                self.pos += 7;
                return self.read_cdata();
            }

            // <!DOCTYPE ...>
            if self.starts_with_doctype() {
                let value = self.take_until_gt()?;
                return Some(Html5Token {
                    kind: Html5Type::DocType,
                    value,
                });
            }

            // <!bogus ...>
            return self.bogus_comment();
        }

        // </name> or bogus close
        if first == b'/' {
            self.advance();
            if self.current() == Some(b'>') {
                self.advance();
                self.state = Html5ParseState::Data;
                return None;
            }
            if self.current().is_some_and(|c| c.is_ascii_alphabetic()) {
                self.is_close = true;
                return self.read_tag_name();
            }
            self.is_close = false;
            return self.bogus_comment();
        }

        // <?..>
        if first == b'?' {
            self.advance();
            return self.bogus_comment();
        }

        // <%...%>
        if first == b'%' {
            self.advance();
            let value = self.take_until_pct_gt()?;
            self.state = Html5ParseState::Data;
            return Some(Html5Token {
                kind: Html5Type::TagComment,
                value,
            });
        }

        // <name ...  or  <\0name ... (IE)
        if first.is_ascii_alphabetic() || first == 0 {
            return self.read_tag_name();
        }

        // non-html tag opener (Go `stateTagOpen` default)
        self.state = Html5ParseState::Data;
        Some(Html5Token {
            kind: Html5Type::DataText,
            value: self.input.get(self.pos - 1..self.pos)?,
        })
    }

    /// Go `stateTagName`.
    fn read_tag_name(&mut self) -> Option<Html5Token<'a>> {
        let start = self.pos;
        while let Some(b) = self.current() {
            match b {
                0 => self.advance(),
                b if is_html_whitespace(b) && b != 0 => {
                    let name = self.slice_from(start)?;
                    self.skip_html_whitespace();
                    self.state = Html5ParseState::InTag;
                    self.is_close = false;
                    return Some(Html5Token {
                        kind: Html5Type::TagNameOpen,
                        value: name,
                    });
                },
                b'/' if !self.is_close => {
                    let name = self.slice_from(start)?;
                    self.state = Html5ParseState::InTag;
                    return Some(Html5Token {
                        kind: Html5Type::TagNameOpen,
                        value: name,
                    });
                },
                b'>' => {
                    let name = self.slice_from(start)?;
                    if self.is_close {
                        self.advance();
                        self.state = Html5ParseState::Data;
                        self.is_close = false;
                        return Some(Html5Token {
                            kind: Html5Type::TagClose,
                            value: name,
                        });
                    }
                    self.state = Html5ParseState::InTag;
                    return Some(Html5Token {
                        kind: Html5Type::TagNameOpen,
                        value: name,
                    });
                },
                _ => self.advance(),
            }
        }

        let name = self.slice_from(start)?;
        self.state = Html5ParseState::InTag;
        self.is_close = false;
        Some(Html5Token {
            kind: Html5Type::TagNameOpen,
            value: name,
        })
    }

    /// Go `stateComment` (`-->` and `-!>` terminators).
    fn read_comment(&mut self) -> Option<Html5Token<'a>> {
        let start = self.pos;
        let mut scan = self.pos;
        while let Some(rest) = self.input.get(scan..) {
            let Some(dash_idx) = rest.iter().position(|&b| b == b'-') else {
                break;
            };
            let abs = scan + dash_idx;
            if abs + 3 > self.input.len() {
                break;
            }
            let mut offset = 1_usize;
            while self.input.get(abs + offset) == Some(&0) {
                offset += 1;
            }
            let Some(&ch) = self.input.get(abs + offset) else {
                break;
            };
            if ch != b'-' && ch != b'!' {
                scan = abs + 1;
                continue;
            }
            offset += 1;
            if self.input.get(abs + offset) != Some(&b'>') {
                scan = abs + 1;
                continue;
            }
            offset += 1;
            let body = self.input.get(start..abs)?;
            self.pos = abs + offset;
            self.state = Html5ParseState::Data;
            return Some(Html5Token {
                kind: Html5Type::TagComment,
                value: body,
            });
        }

        let body = self.input.get(start..)?;
        self.pos = self.input.len();
        Some(Html5Token {
            kind: Html5Type::TagComment,
            value: body,
        })
    }

    /// Go `stateCData`.
    fn read_cdata(&mut self) -> Option<Html5Token<'a>> {
        let start = self.pos;
        let mut scan = self.pos;
        while let Some(rest) = self.input.get(scan..) {
            let Some(rb_idx) = rest.iter().position(|&b| b == b']') else {
                break;
            };
            let abs = scan + rb_idx;
            if self.input.get(abs..abs + 3) == Some(b"]]>") {
                let value = self.input.get(start..abs)?;
                self.pos = abs + 3;
                self.state = Html5ParseState::Data;
                return Some(Html5Token {
                    kind: Html5Type::DataText,
                    value,
                });
            }
            scan = abs + 1;
        }

        let value = self.input.get(start..)?;
        self.pos = self.input.len();
        Some(Html5Token {
            kind: Html5Type::DataText,
            value,
        })
    }

    /// Go `stateBogusComment`.
    fn bogus_comment(&mut self) -> Option<Html5Token<'a>> {
        let start = self.pos;
        if let Some(rest) = self.input.get(self.pos..)
            && let Some(idx) = rest.iter().position(|&b| b == b'>')
        {
            let body = self.input.get(start..self.pos + idx)?;
            self.pos += idx + 1;
            self.state = Html5ParseState::Data;
            return Some(Html5Token {
                kind: Html5Type::TagComment,
                value: body,
            });
        }
        let body = self.input.get(start..)?;
        self.pos = self.input.len();
        Some(Html5Token {
            kind: Html5Type::TagComment,
            value: body,
        })
    }

    /// Go `stateBeforeAttributeName` / `stateSelfClosingStartTag` for `/`.
    fn handle_slash_in_tag(&mut self) -> Option<Html5Token<'a>> {
        let slash = self.pos;
        self.advance();
        self.skip_html_whitespace();
        if self.current() == Some(b'>') {
            self.advance();
            let value = self.input.get(slash..self.pos)?;
            self.state = Html5ParseState::Data;
            return Some(Html5Token {
                kind: Html5Type::TagNameSelfClose,
                value,
            });
        }
        // `<foo /junk>`: `/` not followed by `>` → attribute name
        self.attr_name()
    }

    /// Deal with final tag close
    fn tag_close(&mut self) -> Option<Html5Token<'a>> {
        let start = self.pos;
        self.advance();
        self.state = Html5ParseState::Data;
        self.expect_attr_equals = false;
        self.emit(Html5Type::TagNameClose, start)
    }

    /// Deal with attribute names (after tag name)
    fn attr_name(&mut self) -> Option<Html5Token<'a>> {
        let start = self.pos;
        self.advance();
        while self.current().is_some_and(|b| !is_delimiter(b)) {
            self.advance();
        }
        self.expect_attr_equals = true;
        self.emit(Html5Type::AttrName, start)
    }

    /// Deal with attributes after '=' sign
    fn attr_value(&mut self) -> Option<Html5Token<'a>> {
        self.expect_attr_equals = false;
        // We were called because current byte is '=' (from next_in_tag).
        self.advance(); // consume '='
        self.skip_html_whitespace();

        let quote = match self.current()? {
            q if matches!(q, b'\'' | b'"' | b'`') => {
                self.advance(); // consume opener (same as flag entry: value starts after quote)
                Some(q)
            },
            _ => None, // unquoted; pos stays on first value byte
        };

        self.state = Html5ParseState::InAttrValue { quote };
        self.next_in_attr_value(quote)
    }

    /// Body until `>` (exclusive); consume `>` if present.
    fn take_until_gt(&mut self) -> Option<&'a [u8]> {
        let start = self.pos;
        while self.current().is_some_and(|b| b != b'>') {
            self.advance();
        }
        let body = self.slice_from(start)?;
        if self.current() == Some(b'>') {
            self.advance();
        }
        Some(body)
    }

    /// Body until `%>` (exclusive); consume `%>` if present (IE).
    fn take_until_pct_gt(&mut self) -> Option<&'a [u8]> {
        let start = self.pos;
        loop {
            match self.current() {
                None => break,
                Some(b'%') if self.input.get(self.pos..).is_some_and(|s| s.starts_with(b"%>")) => {
                    break;
                },
                _ => self.advance(),
            }
        }
        let body = self.slice_from(start)?;
        if self.input.get(self.pos..).is_some_and(|s| s.starts_with(b"%>")) {
            self.pos += 2;
        }
        Some(body)
    }

    /// check if input contains a doctype comment
    fn starts_with_doctype(&self) -> bool {
        let Some(s) = self.input.get(self.pos..) else {
            return false;
        };
        s.get(..7).is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"DOCTYPE"))
    }

    /// Helper functions
    /// skip all of the whitespaces
    fn skip_html_whitespace(&mut self) {
        while self.current().is_some_and(is_html_whitespace) {
            self.advance();
        }
    }

    /// advance to the next position of the state
    fn advance(&mut self) {
        self.pos += 1;
    }

    /// Slice from `start` to current `pos` (via `.get`).
    fn slice_from(&self, start: usize) -> Option<&'a [u8]> {
        self.input.get(start..self.pos)
    }

    /// get the current byte
    fn current(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    /// emit a `Html5Token`
    fn emit(&self, kind: Html5Type, start: usize) -> Option<Html5Token<'a>> {
        Some(Html5Token {
            kind,
            value: self.slice_from(start)?,
        })
    }
}

/// HTML/libinjection whitespace: ASCII whitespace plus vertical tab.
fn is_html_whitespace(b: u8) -> bool {
    b == 0 || b.is_ascii_whitespace() || b == b'\x0b'
}

/// Bytes that end an attribute name inside a tag.
fn is_delimiter(b: u8) -> bool {
    is_html_whitespace(b) || matches!(b, b'=' | b'/' | b'>')
}

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
                kind: Html5Type::TagNameOpen,
                value: b"script",
            })
        );
        assert!(is_xss(b"</><script>", Html5Flags::DataState));
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
        assert_eq!(h5.pos, 5);
        assert_eq!(h5.state, Html5ParseState::Data);
        assert_eq!(
            h5.next_token(),
            Some(Html5Token {
                kind: Html5Type::TagNameOpen,
                value: b"script",
            })
        );
        assert_eq!(h5.pos, 12);
        assert_eq!(h5.state, Html5ParseState::InTag);
        assert_eq!(
            h5.next_token(),
            Some(Html5Token {
                kind: Html5Type::TagNameClose,
                value: b">",
            })
        );
        assert_eq!(h5.pos, 13);
        assert_eq!(h5.state, Html5ParseState::Data);
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
