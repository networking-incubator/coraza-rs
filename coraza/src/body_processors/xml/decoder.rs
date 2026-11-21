// Copyright 2009 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The part of Go's `encoding/xml` `Decoder` (`src/encoding/xml/xml.go`) that Go
//! Coraza's XML body processor uses, set up as it sets it up: `Strict` off, `AutoClose`
//! with the HTML elements, and `Entity` with HTML's. Name spaces aren't translated, since
//! the body processor reads no names.

use std::fmt;

use super::tables::{AUTO_CLOSE, FIRST, HTML_ENTITIES, SECOND};
use crate::{
    body_processors::budget::{self, MemoryBudget},
    collection::{ALLOCATION_OVERHEAD_BYTES, Growth},
};

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
    /// A start tag; the values of its attributes went to the sink as they were read
    Start {
        /// Parsed element name.
        name: Name,
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
    /// Reading on would take the decoder past the memory budget its host set; there is no Go counterpart.
    MemoryBudget {
        /// The budget the host set, in bytes.
        budget: usize,
    },

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
            DecodeError::MemoryBudget { budget } => {
                write!(f, "parsed XML exceeds the {budget} byte body memory budget")
            },
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
    /// What `pending_end` was charged while it waits, which a limited budget keeps reserved until the name is read
    /// again: a long mismatched end tag name is held across tokens, after the scratch it was read in was given back
    pending_charged: usize,
    /// The token read before the end of an element closed automatically
    next_token: Option<Token>,
    /// The memory its host allows it, which charges everything the decoder holds, values and scratch alike
    memory: MemoryBudget,
    /// Stack entries already charged against `memory`: the stack's high-water mark, as it never shrinks
    open_charged: usize,
    /// Scratch bytes charged against `memory` since the token began, given back when it ends
    scratch: usize,
    /// Attribute values the start tag being read has handed over, which it takes back if it does not complete
    tag_attributes: usize,
    /// Bytes of the names of the elements open now
    open_name_bytes: usize,
    /// The most `open_name_bytes` has reached, which is what has been charged for names
    name_bytes_charged: usize,
}

/// Bytes the names of an open element hold: those in the stack and the ones of the token that opened it, which the
/// caller still holds.
fn name_bytes(name: &Name) -> usize {
    name.local
        .len()
        .saturating_add(name.space.len())
        .saturating_mul(2)
        .saturating_add(4 * ALLOCATION_OVERHEAD_BYTES)
}

/// How much of a value an error message quotes when the decoder has a budget to keep.
const EXCERPT_BYTES: usize = 64;

impl<'a> Decoder<'a> {
    /// Create a decoder over an XML document that holds what it reads within the host's `memory` budget: it reads
    /// ahead to size what it is about to allocate, and charges that first. An unlimited budget changes nothing.
    pub(super) fn new(input: &'a [u8], memory: MemoryBudget) -> Self {
        Self {
            input,
            offset: 0,
            line: 1,
            open: Vec::new(),
            pending_end: None,
            pending_charged: 0,
            next_token: None,
            memory,
            open_charged: 0,
            scratch: 0,
            tag_attributes: 0,
            open_name_bytes: 0,
            name_bytes_charged: 0,
        }
    }

    /// Gives back `bytes` that [`Decoder::reserve`] reserved beyond what a stored value keeps.
    pub(super) fn release(&mut self, bytes: usize) {
        self.memory.refund(bytes);
    }

    /// Reserves `bytes` of the host's memory budget, which is a no-op without one.
    ///
    /// # Errors
    ///
    /// [`DecodeError::MemoryBudget`] when the budget cannot cover it. The budget is not reduced then.
    pub(super) fn reserve(&mut self, bytes: usize) -> Result<(), DecodeError> {
        if self.memory.charge(bytes) {
            Ok(())
        } else {
            Err(DecodeError::MemoryBudget {
                budget: self.memory.limit(),
            })
        }
    }

    /// Whether the host set a memory budget, which is when the decoder looks ahead to size its scratch.
    fn is_limited(&self) -> bool {
        self.memory.is_limited()
    }

    /// What `cost` says a value takes, asked only when there is a budget to charge it to.
    pub(super) fn cost(&self, cost: impl FnOnce() -> Growth) -> Growth {
        if self.is_limited() { cost() } else { Growth::default() }
    }

    /// Reserves `bytes` for a buffer the decoder is about to fill. It stays reserved until
    /// [`Decoder::release_scratch_to`], which every token does at its end.
    fn scratch(&mut self, bytes: usize) -> Result<(), DecodeError> {
        self.reserve(bytes)?;
        self.scratch = self.scratch.saturating_add(bytes);
        Ok(())
    }

    /// Gives back what [`Decoder::scratch`] reserved since the scratch was `mark`, all of it for `0`: the buffers it
    /// covered are gone, or are now values, which the caller charges for itself.
    fn release_scratch_to(&mut self, mark: usize) {
        let release = self.scratch.saturating_sub(mark);
        self.memory.refund(release);
        self.scratch = mark;
    }

    /// What to reserve for a buffer about to be read: nothing without a budget, as it then grows while it is filled,
    /// and with one `bound`, the most it can take, charged as scratch first.
    fn scratch_for(&mut self, bound: impl FnOnce(&Self) -> usize) -> Result<usize, DecodeError> {
        if !self.is_limited() {
            return Ok(0);
        }
        let bound = bound(self);
        self.scratch(bound.saturating_add(ALLOCATION_OVERHEAD_BYTES))?;
        Ok(bound)
    }

    /// The length of the input from the offset to the first byte `stop` accepts, or to its end.
    fn run_len(&self, stop: impl Fn(u8) -> bool) -> usize {
        let rest = self.input.get(self.offset..).unwrap_or_default();
        rest.iter().position(|&b| stop(b)).unwrap_or(rest.len())
    }

    /// The length of the input from the offset through the first `end`, or to its end.
    fn through(&self, end: &[u8]) -> usize {
        let rest = self.input.get(self.offset..).unwrap_or_default();
        memchr::memmem::find(rest, end).map_or(rest.len(), |at| at.saturating_add(end.len()))
    }

    /// The most bytes the text read up to `end` can take: the input up to its end, which references and line
    /// ends only shorten.
    fn text_bound(&self, end: TextEnd) -> usize {
        let rest = self.input.get(self.offset..).unwrap_or_default();
        match end {
            TextEnd::Markup => memchr::memchr(b'<', rest).unwrap_or(rest.len()),
            TextEnd::Quote(quote) => memchr::memchr2(quote, b'<', rest).unwrap_or(rest.len()),
            TextEnd::Cdata => self.through(b"]]>"),
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
    pub(super) fn token(&mut self, sink: &mut dyn super::Sink) -> Result<Option<Token>, DecodeError> {
        let token = self.next_checked_token(sink);
        self.release_scratch_to(0);
        token
    }

    /// [`Decoder::token`], before the scratch it reserved is given back.
    fn next_checked_token(&mut self, sink: &mut dyn super::Sink) -> Result<Option<Token>, DecodeError> {
        let token = match self.next_token.take() {
            Some(token) => token,
            None => match self.raw_token(sink)? {
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
            Token::Start { name } => {
                // Nothing else bounds how deep a document nests, and each level is held until it closes: its entry
                // in the stack, which keeps its capacity, and its names.
                if self.open.len() >= self.open_charged {
                    self.reserve(2 * size_of::<Open>())?;
                    self.open_charged = self.open.len().saturating_add(1);
                }
                self.open_name_bytes = self.open_name_bytes.saturating_add(name_bytes(&name));
                if self.open_name_bytes > self.name_bytes_charged {
                    self.reserve(self.open_name_bytes - self.name_bytes_charged)?;
                    self.name_bytes_charged = self.open_name_bytes;
                }
                let auto_close = AUTO_CLOSE.iter().copied().find(|html| equal_fold(html, &name.local));
                self.open.push(Open {
                    name: name.clone(),
                    auto_close,
                });
                Token::Start { name }
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
            let shown = self.shown(&name.local);
            return Err(self.syntax_error(format!("unexpected end element </{shown}>")));
        };
        self.open_name_bytes = self.open_name_bytes.saturating_sub(name_bytes(&open));
        if open.local != name.local {
            self.hold_end(name, true)?;
            return Ok(open);
        }
        if open.space != name.space {
            let space = if name.space.is_empty() { r#""""# } else { &name.space };
            let (open_local, open_space) = (self.shown(&open.local), self.shown(&open.space));
            let (local, space) = (self.shown(&name.local), self.shown(space));
            return Err(self.syntax_error(format!(
                "element <{open_local}> in space {open_space} closed by </{local}> in space {space}"
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
    fn raw_token(&mut self, sink: &mut dyn super::Sink) -> Result<Option<Token>, DecodeError> {
        if let Some(name) = self.pending_end.take() {
            // The name is a token now, which holds it until the token ends and gives its scratch back.
            self.scratch = self.scratch.saturating_add(std::mem::take(&mut self.pending_charged));
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
                    let shown = self.shown(&name.local);
                    return Err(self.syntax_error(format!("invalid characters between </{shown} and >")));
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
                self.start_tag(sink)?
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
        // Only the declaration's content is read, so any other instruction is skipped without buffering it.
        let keep = target == "xml";
        let mut content = Vec::new();
        if keep {
            content.reserve_exact(self.scratch_for(|decoder| decoder.through(b"?>"))?);
        }
        let mut previous = 0;
        loop {
            let b = self.mustgetc()?;
            if previous == b'?' && b == b'>' {
                break;
            }
            if keep {
                content.push(b);
            }
            previous = b;
        }
        content.pop();
        if !keep {
            return Ok(());
        }
        // Quoted as Go's %q quotes, but for unprintable characters, escaped as Rust escapes
        // them, and bytes that aren't UTF-8, replaced
        let version = proc_inst("version", &content);
        if !version.is_empty() && version != b"1.0" {
            let shown = self.excerpt(version)?;
            return Err(DecodeError::Declaration(format!(
                "xml: unsupported version {shown:?}; only version 1.0 is supported",
            )));
        }
        let encoding = proc_inst("encoding", &content);
        if !encoding.is_empty() && !encoding.eq_ignore_ascii_case(b"utf-8") {
            let shown = self.excerpt(encoding)?;
            return Err(DecodeError::Declaration(format!(
                "xml: encoding {shown:?} declared but Decoder.CharsetReader is nil",
            )));
        }
        Ok(())
    }

    /// Keeps `name` as the end tag to give before reading on, charging what it holds while it waits when there is a
    /// budget. A name that is the token being read, and so no longer held as one, takes over the scratch it was read
    /// in (`moved`), which would be given back at the token's end while the name is still alive; one that is a copy
    /// of a name the token keeps is charged on its own.
    fn hold_end(&mut self, name: Name, moved: bool) -> Result<(), DecodeError> {
        if self.is_limited() {
            let bytes = name
                .local
                .len()
                .saturating_add(name.space.len())
                .saturating_add(2 * ALLOCATION_OVERHEAD_BYTES);
            let taken = if moved { bytes.min(self.scratch) } else { 0 };
            self.reserve(bytes.saturating_sub(taken))?;
            self.scratch = self.scratch.saturating_sub(taken);
            self.pending_charged = self.pending_charged.saturating_add(bytes);
        }
        self.pending_end = Some(name);
        Ok(())
    }

    /// `text` as an error message quotes it: all of it, as Go does, unless there is a budget, which bounds what the
    /// message keeps to the first [`EXCERPT_BYTES`] bytes (ended at a character boundary) and a marker for the rest.
    /// The message outlives the scratch the name was read in, and is stored more than once, so it cannot be the
    /// size of the input.
    fn shown<'t>(&self, text: &'t str) -> std::borrow::Cow<'t, str> {
        if self.is_limited() {
            budget::excerpt(text, EXCERPT_BYTES)
        } else {
            std::borrow::Cow::Borrowed(text)
        }
    }

    /// `bytes` as text for an error message. Without a budget that is all of them, as Go quotes them. With one it is
    /// the first [`EXCERPT_BYTES`], the message's own storage reserved first, so that a value the declaration or a
    /// name is made of, which is held beside it, is not copied whole into a second buffer past the budget.
    fn excerpt(&mut self, bytes: &[u8]) -> Result<String, DecodeError> {
        if !self.is_limited() {
            return Ok(String::from_utf8_lossy(bytes).into_owned());
        }
        let shown = bytes.get(..EXCERPT_BYTES).unwrap_or(bytes);
        // The text of the bytes, which a lossy view can triple, and the message quoting it, which escapes can multiply
        // again.
        self.scratch(
            EXCERPT_BYTES
                .saturating_mul(16)
                .saturating_add(4 * ALLOCATION_OVERHEAD_BYTES),
        )?;
        let mut text = String::from_utf8_lossy(shown).into_owned();
        if shown.len() < bytes.len() {
            text.push_str("...");
        }
        Ok(text)
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
    ///
    /// A single start tag can hold as many attributes as the body has bytes, so each value is charged as it is
    /// read and handed to the sink at once, instead of waiting in a list beside the collection it joins. A tag that
    /// does not complete leaves them with the caller, who is told how many by [`Decoder::unfinished_attributes`]
    /// and drops them, as a token that was never returned never had them.
    fn start_tag(&mut self, sink: &mut dyn super::Sink) -> Result<Token, DecodeError> {
        let name = self
            .nsname()?
            .ok_or_else(|| self.syntax_error("expected element name after <"))?;
        self.tag_attributes = 0;
        loop {
            self.space();
            match self.mustgetc()? {
                b'/' => {
                    if self.mustgetc()? != b'>' {
                        return Err(self.syntax_error("expected /> in element"));
                    }
                    self.hold_end(name.clone(), false)?;
                    break;
                },
                b'>' => break,
                _ => self.ungetc(),
            }
            // The attribute's own buffers are given back when it is read; the element's name, which the tag holds
            // to its end, keeps what it reserved.
            let mark = self.scratch;
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
            self.release_scratch_to(mark);
            let cost = self.cost(|| sink.attribute_cost(value.len()));
            self.reserve(cost.grown)?;
            self.tag_attributes = self.tag_attributes.saturating_add(1);
            sink.attribute(value);
            self.release(cost.freed);
        }
        self.tag_attributes = 0;
        Ok(Token::Start { name })
    }

    /// How many attribute values the start tag the input ended in had handed over before it ended.
    pub(super) const fn unfinished_attributes(&self) -> usize {
        self.tag_attributes
    }

    /// Reads an attribute's value, after its `=` (Go's `attrval`).
    fn attribute_value(&mut self) -> Result<String, DecodeError> {
        let b = self.mustgetc()?;
        if b == b'"' || b == b'\'' {
            return self.text(TextEnd::Quote(b));
        }
        self.ungetc();
        let mut value = String::new();
        value.reserve_exact(self.scratch_for(|decoder| {
            decoder.run_len(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-')))
        })?);
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
        // The text cannot outgrow the input it is read from, so under a budget the buffer is sized once, and charged,
        // instead of doubling past the budget on the way to a value the budget would then refuse.
        text.reserve_exact(self.scratch_for(|decoder| decoder.text_bound(end))?);
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
        let mut value = self.characters(text)?;
        if self.is_limited() {
            // The value is kept: drop what its references and line ends saved.
            value.shrink_to_fit();
        }
        Ok(value)
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
        // The name itself is reserved as it is read; what is left to reserve is the two halves it may be split
        // into beside it.
        let Some(name) = self.name()? else {
            return Ok(None);
        };
        if name.matches(':').count() > 1 {
            return Ok(None);
        }
        if self.is_limited() && name.contains(':') {
            self.scratch(name.len().saturating_add(2 * ALLOCATION_OVERHEAD_BYTES))?;
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
        // Whatever the name is for, it is read whole before anything is known about it, so it is reserved first.
        name.reserve_exact(self.scratch_for(|decoder| decoder.run_len(|b| b.is_ascii() && !is_name_byte(b)))?);
        if !self.read_name(&mut name)? {
            return Ok(None);
        }
        if !is_name(&name) {
            let shown = self.excerpt(&name)?;
            return Err(self.syntax_error(format!("invalid XML name: {shown}")));
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
