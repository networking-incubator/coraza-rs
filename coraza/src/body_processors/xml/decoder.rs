// Copyright 2009 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The part of Go's `encoding/xml` `Decoder` (`src/encoding/xml/xml.go`) that Go
//! Coraza's XML body processor uses, set up as it sets it up: `Strict` off, `AutoClose`
//! with the HTML elements, and `Entity` with HTML's. Name spaces aren't translated, since
//! the body processor reads no names.

use std::fmt;

use super::tables::{AUTO_CLOSE, FIRST, HTML_ENTITIES, SECOND};

/// An element's name as written: `prefix:local`, or `local` alone
#[derive(Debug, Clone)]
pub(super) struct Name {
    /// Namespace prefix before the colon, if present.
    space: String,
    /// Element name after the colon, or the full name without a prefix.
    local: String,
}

/// An open element
#[derive(Debug)]
struct Open {
    /// Parsed element name.
    name: Name,
    /// The name of [`AUTO_CLOSE`] it has, if any: the element is then closed before the
    /// next token, unless that token is its end tag
    auto_close: Option<&'static str>,
}

/// What [`Decoder::token`] reads, as far as the body processor needs it
#[derive(Debug)]
pub(super) enum Token {
    /// A start tag, and the values of its attributes in order
    Start {
        /// Parsed element name.
        name: Name,
        /// Attribute values in document order.
        attribute_values: Vec<String>,
    },

    /// An end tag, or the end of an element the decoder closed itself
    End(Name),

    /// Text, from character data or a CDATA section, its references replaced
    CharData(String),

    /// A comment, processing instruction or directive
    Other,
}

/// Why [`Decoder::token`] can't read on
#[derive(Debug)]
pub(super) enum DecodeError {
    /// The input ended within a token or an element: Go's `SyntaxError` "unexpected EOF"
    UnexpectedEof {
        /// Current one-based line number.
        line: usize,
    },

    /// Go's `SyntaxError`: what's wrong, on which line (from 1)
    Syntax {
        /// Current one-based line number.
        line: usize,
        /// Description of the malformed input.
        message: String,
    },

    /// The `<?xml ...?>` declaration is of a version or an encoding Go doesn't read
    Declaration(String),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::UnexpectedEof { line } => {
                write!(f, "XML syntax error on line {line}: unexpected EOF")
            },
            DecodeError::Syntax { line, message } => {
                write!(f, "XML syntax error on line {line}: {message}")
            },
            DecodeError::Declaration(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Where [`Decoder::text`] stops
#[derive(Clone, Copy, PartialEq)]
enum TextEnd {
    /// Character data: at the next `<`
    Markup,
    /// An attribute value: at its closing quote
    Quote(u8),
    /// A CDATA section: at `]]>`
    Cdata,
}

/// Reads an XML document's tokens, as Go's `Decoder.Token` does.
pub(super) struct Decoder<'a> {
    /// Input document bytes.
    input: &'a [u8],
    /// Byte offset of the next input byte.
    offset: usize,
    /// One-based line number at the current offset.
    line: usize,
    /// The elements open, innermost last
    open: Vec<Open>,
    /// The end tag to give before reading on: the end of `<a/>`, or one that closed an
    /// element of another name first (Go's `needClose` and `toClose`)
    pending_end: Option<Name>,
    /// The token read before the end of an element closed automatically
    next_token: Option<Token>,
}

impl<'a> Decoder<'a> {
    /// Create a decoder over an XML document.
    pub(super) fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            line: 1,
            open: Vec::new(),
            pending_end: None,
            next_token: None,
        }
    }

    /// The next token, or `None` at the end of the input when no element is open.
    ///
    /// An end tag closes the elements open until one of its local name, and the open
    /// HTML elements that are always empty, such as `<br>`, are closed before the next
    /// token unless it is their end tag.
    ///
    /// # Errors
    ///
    /// If the input is malformed as Go's decoder reads it, with `Strict` off, or ends
    /// within a token or an element.
    pub(super) fn token(&mut self) -> Result<Option<Token>, DecodeError> {
        let token = match self.next_token.take() {
            Some(token) => token,
            None => match self.raw_token()? {
                Some(token) => token,
                None if self.open.is_empty() => return Ok(None),
                None => return Err(DecodeError::UnexpectedEof { line: self.line }),
            },
        };
        let token = match self.auto_close(&token) {
            Some(end) => {
                self.next_token = Some(token);
                end
            },
            None => token,
        };
        Ok(Some(match token {
            Token::Start { name, attribute_values } => {
                let auto_close = AUTO_CLOSE.iter().copied().find(|html| equal_fold(html, &name.local));
                self.open.push(Open {
                    name: name.clone(),
                    auto_close,
                });
                Token::Start { name, attribute_values }
            },
            Token::End(name) => Token::End(self.pop_element(name)?),
            token => token,
        }))
    }

    /// Closes the innermost element for the end tag `name`, and gives the name of the
    /// element it closed. An end tag of another local name closes it all the same, and is
    /// read again for the next element out (Go's `popElement`, not `Strict`).
    fn pop_element(&mut self, name: Name) -> Result<Name, DecodeError> {
        let Some(Open { name: open, .. }) = self.open.pop() else {
            return Err(self.syntax_error(format!("unexpected end element </{}>", name.local)));
        };
        if open.local != name.local {
            self.pending_end = Some(name);
            return Ok(open);
        }
        if open.space != name.space {
            let space = if name.space.is_empty() { r#""""# } else { &name.space };
            return Err(self.syntax_error(format!(
                "element <{}> in space {} closed by </{}> in space {}",
                open.local, open.space, name.local, space
            )));
        }
        Ok(name)
    }

    /// The end of the innermost element, if it is one of [`AUTO_CLOSE`] and `token` isn't
    /// its end tag (Go's `autoClose`).
    fn auto_close(&self, token: &Token) -> Option<Token> {
        let open = self.open.last()?;
        let html = open.auto_close?;
        match token {
            Token::End(name) if equal_fold(html, &name.local) => None,
            _ => Some(Token::End(open.name.clone())),
        }
    }

    /// The next token as written (Go's `rawToken`), or `None` at the end of the input.
    fn raw_token(&mut self) -> Result<Option<Token>, DecodeError> {
        if let Some(name) = self.pending_end.take() {
            return Ok(Some(Token::End(name)));
        }
        let Some(b) = self.getc() else {
            return Ok(None);
        };
        if b != b'<' {
            self.ungetc();
            return Ok(Some(Token::CharData(self.text(TextEnd::Markup)?)));
        }
        let token = match self.mustgetc()? {
            b'/' => {
                let name = self
                    .nsname()?
                    .ok_or_else(|| self.syntax_error("expected element name after </"))?;
                self.space();
                if self.mustgetc()? != b'>' {
                    return Err(self.syntax_error(format!("invalid characters between </{} and >", name.local)));
                }
                Token::End(name)
            },
            b'?' => {
                self.processing_instruction()?;
                Token::Other
            },
            b'!' => match self.mustgetc()? {
                b'-' => {
                    self.comment()?;
                    Token::Other
                },
                b'[' => {
                    for &expected in b"CDATA[" {
                        if self.mustgetc()? != expected {
                            return Err(self.syntax_error("invalid <![ sequence"));
                        }
                    }
                    Token::CharData(self.text(TextEnd::Cdata)?)
                },
                _ => {
                    self.directive()?;
                    Token::Other
                },
            },
            _ => {
                self.ungetc();
                self.start_tag()?
            },
        };
        Ok(Some(token))
    }

    /// Reads a processing instruction, after its `<?`, rejecting an `xml` declaration of a
    /// version other than 1.0 or an encoding other than UTF-8.
    fn processing_instruction(&mut self) -> Result<(), DecodeError> {
        let target = self
            .name()?
            .ok_or_else(|| self.syntax_error("expected target name after <?"))?;
        self.space();
        let mut content = Vec::new();
        let mut previous = 0;
        loop {
            let b = self.mustgetc()?;
            if previous == b'?' && b == b'>' {
                break;
            }
            content.push(b);
            previous = b;
        }
        content.pop();
        if target != "xml" {
            return Ok(());
        }
        // Quoted as Go's %q quotes, but for unprintable characters, escaped as Rust escapes
        // them, and bytes that aren't UTF-8, replaced
        let version = proc_inst("version", &content);
        if !version.is_empty() && version != b"1.0" {
            return Err(DecodeError::Declaration(format!(
                "xml: unsupported version {:?}; only version 1.0 is supported",
                String::from_utf8_lossy(version)
            )));
        }
        let encoding = proc_inst("encoding", &content);
        if !encoding.is_empty() && !encoding.eq_ignore_ascii_case(b"utf-8") {
            return Err(DecodeError::Declaration(format!(
                "xml: encoding {:?} declared but Decoder.CharsetReader is nil",
                String::from_utf8_lossy(encoding)
            )));
        }
        Ok(())
    }

    /// Reads a comment, after its `<!-`.
    fn comment(&mut self) -> Result<(), DecodeError> {
        if self.mustgetc()? != b'-' {
            return Err(self.syntax_error("invalid sequence <!- not part of <!--"));
        }
        let (mut b0, mut b1) = (0, 0);
        loop {
            let b = self.mustgetc()?;
            if b0 == b'-' && b1 == b'-' {
                if b != b'>' {
                    return Err(self.syntax_error(r#"invalid sequence "--" not allowed in comments"#));
                }
                return Ok(());
            }
            (b0, b1) = (b1, b);
        }
    }

    /// Reads a directive such as `<!DOCTYPE ...>`, after its `<!` and first byte: up to
    /// the `>` that isn't quoted and closes every `<` it holds, its comments skipped.
    fn directive(&mut self) -> Result<(), DecodeError> {
        let mut quote = 0;
        let mut depth = 0_usize;
        // A byte read while looking for a comment, handled as if just read, but for
        // ending the directive
        let mut reread = None;
        loop {
            let b = if let Some(b) = reread.take() {
                b
            } else {
                let b = self.mustgetc()?;
                if quote == 0 && b == b'>' && depth == 0 {
                    return Ok(());
                }
                b
            };
            if b == quote {
                quote = 0;
            } else if quote != 0 {
                // Quoted
            } else if b == b'\'' || b == b'"' {
                quote = b;
            } else if b == b'>' {
                depth -= 1;
            } else if b == b'<' {
                let mut mismatch = None;
                for &expected in b"!--" {
                    let b = self.mustgetc()?;
                    if b != expected {
                        mismatch = Some(b);
                        break;
                    }
                }
                if mismatch.is_some() {
                    depth += 1;
                    reread = mismatch;
                    continue;
                }
                let (mut b0, mut b1) = (0, 0);
                loop {
                    let b = self.mustgetc()?;
                    if b0 == b'-' && b1 == b'-' && b == b'>' {
                        break;
                    }
                    (b0, b1) = (b1, b);
                }
            }
        }
    }

    /// Reads a start tag, from its name. An attribute without a value has its local name
    /// for one, and an unquoted value is the run of letters, digits, `_`, `:` and `-`
    /// (not `Strict`).
    fn start_tag(&mut self) -> Result<Token, DecodeError> {
        let name = self
            .nsname()?
            .ok_or_else(|| self.syntax_error("expected element name after <"))?;
        let mut attribute_values = Vec::new();
        loop {
            self.space();
            match self.mustgetc()? {
                b'/' => {
                    if self.mustgetc()? != b'>' {
                        return Err(self.syntax_error("expected /> in element"));
                    }
                    self.pending_end = Some(name.clone());
                    break;
                },
                b'>' => break,
                _ => self.ungetc(),
            }
            let attribute = self
                .nsname()?
                .ok_or_else(|| self.syntax_error("expected attribute name in element"))?;
            self.space();
            let value = if self.mustgetc()? == b'=' {
                self.space();
                self.attribute_value()?
            } else {
                self.ungetc();
                attribute.local
            };
            attribute_values.push(value);
        }
        Ok(Token::Start { name, attribute_values })
    }

    /// Reads an attribute's value, after its `=` (Go's `attrval`).
    fn attribute_value(&mut self) -> Result<String, DecodeError> {
        let b = self.mustgetc()?;
        if b == b'"' || b == b'\'' {
            return self.text(TextEnd::Quote(b));
        }
        self.ungetc();
        let mut value = String::new();
        loop {
            let b = self.mustgetc()?;
            if b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-') {
                value.push(char::from(b));
            } else {
                self.ungetc();
                return Ok(value);
            }
        }
    }

    /// Reads text up to `end`, past it for a quote or `]]>`. Outside CDATA sections, the
    /// entities XML predefines and HTML 4's, and numeric character references, are
    /// replaced, and others kept as written (not `Strict`); `\r\n` and `\r` read as `\n`.
    /// Text that reaches the end of the input ends there, but for a CDATA section's.
    fn text(&mut self, end: TextEnd) -> Result<String, DecodeError> {
        let (mut b0, mut b1) = (0, 0);
        let mut text = Vec::new();
        loop {
            let Some(b) = self.getc() else {
                if end == TextEnd::Cdata {
                    return Err(self.syntax_error("unexpected EOF in CDATA section"));
                }
                break;
            };
            if !matches!(end, TextEnd::Quote(_)) && b0 == b']' && b1 == b']' && b == b'>' {
                if end == TextEnd::Cdata {
                    text.truncate(text.len().saturating_sub(2));
                    break;
                }
                return Err(self.syntax_error("unescaped ]]> not in CDATA section"));
            }
            if b == b'<' && end != TextEnd::Cdata {
                if end != TextEnd::Markup {
                    return Err(self.syntax_error("unescaped < inside quoted string"));
                }
                self.ungetc();
                break;
            }
            if end == TextEnd::Quote(b) {
                break;
            }
            if b == b'&' && end != TextEnd::Cdata {
                self.reference(&mut text)?;
                (b0, b1) = (0, 0);
                continue;
            }
            if b == b'\r' {
                text.push(b'\n');
            } else if b1 != b'\r' || b != b'\n' {
                text.push(b);
            }
            (b0, b1) = (b1, b);
        }
        self.characters(text)
    }

    /// Reads an entity or character reference, after its `&`, onto `text`: what it stands
    /// for, or as written.
    fn reference(&mut self, text: &mut Vec<u8>) -> Result<(), DecodeError> {
        let start = text.len();
        text.push(b'&');
        let mut replacement = None;
        let mut b = self.mustgetc()?;
        if b == b'#' {
            text.push(b);
            b = self.mustgetc()?;
            let radix = if b == b'x' {
                text.push(b);
                b = self.mustgetc()?;
                16
            } else {
                10
            };
            let digits = text.len();
            while char::from(b).is_digit(radix) {
                text.push(b);
                b = self.mustgetc()?;
            }
            if b == b';' {
                let digits = text.get(digits..).unwrap_or_default();
                replacement = std::str::from_utf8(digits)
                    .ok()
                    .and_then(|digits| u32::from_str_radix(digits, radix).ok())
                    .filter(|&code| code <= 0x0010_FFFF)
                    // Go's string(rune) of a surrogate
                    .map(|code| char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER));
                text.push(b);
            } else {
                self.ungetc();
            }
        } else {
            self.ungetc();
            self.read_name(text)?;
            if self.mustgetc()? == b';' {
                let name = text.get(start.saturating_add(1)..).unwrap_or_default();
                if is_name(name) {
                    replacement = entity(name);
                }
                text.push(b';');
            } else {
                self.ungetc();
            }
        }
        if let Some(replacement) = replacement {
            text.truncate(start);
            text.extend_from_slice(replacement.encode_utf8(&mut [0; 4]).as_bytes());
        }
        Ok(())
    }

    /// `text` as a string, if it's UTF-8 of the characters XML allows.
    fn characters(&self, text: Vec<u8>) -> Result<String, DecodeError> {
        // The first offending character decides, as Go reads them in order
        for chunk in text.utf8_chunks() {
            if let Some(c) = chunk.valid().chars().find(|&c| !is_in_character_range(c)) {
                return Err(self.syntax_error(format!("illegal character code U+{:04X}", u32::from(c))));
            }
            if !chunk.invalid().is_empty() {
                break;
            }
        }
        String::from_utf8(text).map_err(|_error| self.syntax_error("invalid UTF-8"))
    }

    /// Reads a name, split at its colon if it has one between other characters (Go's
    /// `nsname`); `None` if there is no name, or one with more colons.
    fn nsname(&mut self) -> Result<Option<Name>, DecodeError> {
        let Some(name) = self.name()? else {
            return Ok(None);
        };
        if name.matches(':').count() > 1 {
            return Ok(None);
        }
        Ok(Some(match name.split_once(':') {
            Some((space, local)) if !space.is_empty() && !local.is_empty() => Name {
                space: space.to_owned(),
                local: local.to_owned(),
            },
            _ => Name {
                space: String::new(),
                local: name,
            },
        }))
    }

    /// Reads a name, `None` if there is none.
    ///
    /// # Errors
    ///
    /// If the bytes it reads as one aren't a valid XML name.
    fn name(&mut self) -> Result<Option<String>, DecodeError> {
        let mut name = Vec::new();
        if !self.read_name(&mut name)? {
            return Ok(None);
        }
        if !is_name(&name) {
            return Err(self.syntax_error(format!("invalid XML name: {}", String::from_utf8_lossy(&name))));
        }
        let name = String::from_utf8(name).map_err(|_error| self.syntax_error("invalid UTF-8"))?;
        Ok(Some(name))
    }

    /// Reads what may be a name onto `name`: up to an ASCII character no name has, any
    /// byte past ASCII included. `false` if there is none.
    fn read_name(&mut self, name: &mut Vec<u8>) -> Result<bool, DecodeError> {
        let mut read = false;
        loop {
            let b = self.mustgetc()?;
            if b.is_ascii() && !is_name_byte(b) {
                self.ungetc();
                return Ok(read);
            }
            name.push(b);
            read = true;
        }
    }

    /// Skips spaces, tabs and line ends.
    fn space(&mut self) {
        while let Some(b) = self.getc() {
            if !matches!(b, b' ' | b'\r' | b'\n' | b'\t') {
                self.ungetc();
                return;
            }
        }
    }

    /// Read one byte, advancing the input offset and line count.
    fn getc(&mut self) -> Option<u8> {
        let b = *self.input.get(self.offset)?;
        self.offset += 1;
        if b == b'\n' {
            self.line += 1;
        }
        Some(b)
    }

    /// Read one byte or report that the input ended.
    fn mustgetc(&mut self) -> Result<u8, DecodeError> {
        self.getc().ok_or(DecodeError::UnexpectedEof { line: self.line })
    }

    /// Steps back over the byte [`Self::getc`] just read.
    fn ungetc(&mut self) {
        self.offset = self.offset.saturating_sub(1);
        if self.input.get(self.offset) == Some(&b'\n') {
            self.line = self.line.saturating_sub(1);
        }
    }

    /// Create a syntax error at the current line.
    fn syntax_error(&self, message: impl Into<String>) -> DecodeError {
        DecodeError::Syntax {
            line: self.line,
            message: message.into(),
        }
    }
}

/// What the entity `name` stands for, of the ones XML predefines, or else of HTML 4's.
fn entity(name: &[u8]) -> Option<char> {
    match name {
        b"lt" => Some('<'),
        b"gt" => Some('>'),
        b"amp" => Some('&'),
        b"apos" => Some('\''),
        b"quot" => Some('"'),
        _ => HTML_ENTITIES
            .binary_search_by(|(html, _)| html.as_bytes().cmp(name))
            .ok()
            .and_then(|i| HTML_ENTITIES.get(i).map(|(_, value)| *value)),
    }
}

/// Go's `procInst`: the value of `param="..."` or `param='...'` in a processing
/// instruction's `content`, empty if there's none.
fn proc_inst<'c>(param: &str, content: &'c [u8]) -> &'c [u8] {
    let param = format!("{param}=");
    let param = param.as_bytes();
    let mut i = 0;
    let mut quote = None;
    while i < content.len() {
        let Some(rest) = content.get(i..) else {
            return b"";
        };
        let Some(k) = rest.windows(param.len()).position(|w| w == param) else {
            return b"";
        };
        let Some(value_offset) = param.len().checked_add(k) else {
            return b"";
        };
        if value_offset >= rest.len() {
            return b"";
        }
        let Some(c) = rest.get(value_offset).copied() else {
            return b"";
        };
        i = i.saturating_add(value_offset).saturating_add(1);
        if c == b'\'' || c == b'"' {
            quote = Some(c);
            break;
        }
    }
    let Some(quote) = quote else {
        return b"";
    };
    let Some(rest) = content.get(i..) else {
        return b"";
    };
    match rest.iter().position(|&b| b == quote) {
        Some(j) => rest.get(..j).unwrap_or_default(),
        None => b"",
    }
}

/// Go's `strings.EqualFold(ascii, name)` for an ASCII `ascii`: besides ASCII letters
/// themselves, only the Kelvin sign and long s fold to ASCII letters.
fn equal_fold(ascii: &str, name: &str) -> bool {
    if name.is_ascii() {
        return name.eq_ignore_ascii_case(ascii);
    }
    let fold = |c: char| match c {
        '\u{212A}' => 'k',
        '\u{017F}' => 's',
        c => c.to_ascii_lowercase(),
    };
    name.chars().map(fold).eq(ascii.chars().map(fold))
}

/// Whether XML allows `c` in a document (its `Char`).
fn is_in_character_range(c: char) -> bool {
    matches!(c, '\u{09}' | '\u{0A}' | '\u{0D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

/// Whether an ASCII byte cannot continue an XML name.
fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'.' | b'-')
}

/// Whether `name` is UTF-8 of an XML name: a character of [`FIRST`], then of [`FIRST`]
/// or [`SECOND`].
fn is_name(name: &[u8]) -> bool {
    let Ok(name) = std::str::from_utf8(name) else {
        return false;
    };
    let mut chars = name.chars();
    chars.next().is_some_and(|c| in_table(FIRST, c)) && chars.all(|c| in_table(FIRST, c) || in_table(SECOND, c))
}

/// Whether `c` is in `table`, as Go's `unicode.Is` decides for a table of 16-bit ranges.
/// It searches a long table by bisection, which, since ranges of a stride other than 1
/// overlap others, can give another answer than looking at every range.
fn in_table(table: &[(u16, u16, u16)], c: char) -> bool {
    let Some(&(_, last, _)) = table.last() else {
        return false;
    };
    let c = match u16::try_from(u32::from(c)) {
        Ok(c) if c <= last => c,
        _ => return false,
    };
    let holds = |&(low, _, stride): &(u16, u16, u16)| stride == 1 || (c - low) % stride == 0;
    if table.len() <= 18 || c <= 0xFF {
        return table
            .iter()
            .find(|&&(low, high, _)| c < low || c <= high)
            .is_some_and(|range| c >= range.0 && holds(range));
    }
    let (mut lo, mut hi) = (0, table.len());
    while lo < hi {
        let m = (lo + hi) / 2;
        let Some(&(low, high, _)) = table.get(m) else {
            return false;
        };
        if low <= c && c <= high {
            return table.get(m).is_some_and(holds);
        }
        if c < low {
            hi = m;
        } else {
            lo = m + 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_entities_are_sorted_for_their_binary_search() {
        assert!(HTML_ENTITIES.windows(2).all(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_some_and(|(first, second)| first.0 < second.0)
        }));
    }
}
