//! SQL injection detection: tokenize, fold, and match the resulting
//! fingerprint against the known-bad list.

mod fold;
pub(crate) mod keyword_table;
mod keywords;
pub(crate) mod lexer;
pub(crate) mod token;

use core::cmp::Ordering;
use core::fmt;

use self::keywords::{cstrcasecmp, lookup_word};
pub use self::lexer::Dialect;
use self::lexer::{Lexer, Quote};
use self::token::{Token, TokenType};
use crate::bytes::find_slice;

/// The most tokens a folded input, and so a fingerprint, can have.
pub(crate) const MAX_TOKENS: usize = 5;

/// The pattern an input was recognised by: one byte for each of its (up to
/// five) folded tokens, e.g. `s&1c` for string, logic operator, number,
/// comment.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    bytes: [u8; MAX_TOKENS],
    len: u8,
}

impl Fingerprint {
    /// Collects the token types up to the first cleared slot, where
    /// upstream's NUL-terminated fingerprint would end.
    fn from_tokens(tokens: &[Token]) -> Self {
        let mut fingerprint = Self::default();
        for token in tokens.iter().take(MAX_TOKENS) {
            if token.ty == TokenType::Null {
                break;
            }
            fingerprint.bytes[usize::from(fingerprint.len)] = token.ty.as_byte();
            fingerprint.len += 1;
        }
        fingerprint
    }

    /// The fingerprint of an input that cannot be tokenized reliably.
    fn evil() -> Self {
        let mut fingerprint = Self::default();
        fingerprint.bytes[0] = TokenType::Evil.as_byte();
        fingerprint.len = 1;
        fingerprint
    }

    /// The fingerprint as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// The fingerprint as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Every byte is a `TokenType` discriminant, all of them ASCII.
        core::str::from_utf8(self.as_bytes()).unwrap_or_default()
    }
}

impl AsRef<[u8]> for Fingerprint {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<str> for Fingerprint {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Fingerprint").field(&self.as_str()).finish()
    }
}

impl PartialEq<str> for Fingerprint {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for Fingerprint {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

pub struct State<'a> {
    input: &'a [u8],
    lexer: Lexer<'a>,
    /// One more slot than a fingerprint needs, since a sixth token is
    /// sometimes read to decide the type of the fifth.
    pub tokens: [Token; 8],
    fingerprint: Fingerprint,
}

impl<'a> State<'a> {
    pub fn new(input: &'a [u8], quote: Quote, dialect: Dialect) -> Self {
        Self {
            input,
            lexer: Lexer::new(input, quote, dialect),
            tokens: [Token::default(); 8],
            fingerprint: Fingerprint::default(),
        }
    }

    /// Fingerprints the input in the given context.
    pub fn fingerprint(&mut self, quote: Quote, dialect: Dialect) -> Fingerprint {
        *self = Self::new(self.input, quote, dialect);
        let tlen = self.fold();

        // PHP's backquote "comment": a trailing, empty, unclosed backtick
        // bareword is turned into a comment.
        if tlen > 2 {
            let last = &mut self.tokens[tlen - 1];
            if last.ty == TokenType::Bareword
                && last.str_open == Some(b'`')
                && last.len == 0
                && last.str_close.is_none()
            {
                last.ty = TokenType::Comment;
            }
        }

        // An 'X' anywhere means the input could not be tokenized reliably
        // (nested comments and the like): the whole pattern becomes "X".
        // Folding can hand back a sixth token in that case, so this looks at
        // the tokens rather than at the five a fingerprint holds.
        let tokens = &self.tokens[..tlen];
        self.fingerprint = if tokens.iter().any(|token| token.ty == TokenType::Evil) {
            self.tokens[0].mark_evil();
            self.tokens[1].ty = TokenType::Null;
            Fingerprint::evil()
        } else {
            Fingerprint::from_tokens(tokens)
        };

        self.fingerprint
    }

    /// Whether the fingerprint is on the list of known SQLi patterns.
    fn blacklist(&self) -> bool {
        let fingerprint = self.fingerprint.as_bytes();
        if fingerprint.is_empty() {
            return false;
        }

        // The table stores fingerprints upper-cased behind a '0' prefix.
        let mut key = [b'0'; MAX_TOKENS + 1];
        for (dst, src) in key[1..].iter_mut().zip(fingerprint) {
            *dst = src.to_ascii_uppercase();
        }
        lookup_word(&key[..=fingerprint.len()]) == Some(TokenType::Fingerprint)
    }

    /// Second-guesses a blacklisted fingerprint to cut false positives.
    /// Returns `true` if the input is still considered SQLi.
    fn not_whitelist(&self) -> bool {
        let fingerprint = self.fingerprint.as_bytes();
        let tokens = &self.tokens;
        let stats = &self.lexer.stats;

        // SQL Server's audit log skips anything mentioning 'sp_password',
        // which makes it a known companion of SQLi in a trailing comment.
        if fingerprint.len() > 1
            && fingerprint.last() == Some(&TokenType::Comment.as_byte())
            && find_slice(self.input, b"sp_password").is_some()
        {
            return true;
        }

        match fingerprint.len() {
            // Very small patterns are hard to tell from normal input.
            2 => {
                if fingerprint[1] == TokenType::Union.as_byte() {
                    // "1 union" alone has plenty of innocent readings; with
                    // folding or comments involved it does not.
                    return stats.tokens != 2;
                }

                // A '#' comment: too many false positives.
                if tokens[1].byte(0) == b'#' {
                    return false;
                }

                // For "nc", only a "/*" comment counts: trailing "--" and
                // "#" comments are not SQLi.
                if tokens[0].ty == TokenType::Bareword
                    && tokens[1].ty == TokenType::Comment
                    && tokens[1].byte(0) != b'/'
                {
                    return false;
                }

                if tokens[0].ty == TokenType::Number && tokens[1].ty == TokenType::Comment {
                    // "1c" ending in a "/*" comment is SQLi.
                    if tokens[1].byte(0) == b'/' {
                        return true;
                    }

                    // Base64-looking values such as "1234-ABCDEFEhfhihwuefi--"
                    // also come out as "1c", so make sure the "1" really is
                    // a plain number followed by the comment. This has to
                    // look at the input: folding may have merged tokens.
                    if stats.tokens > 2 {
                        // Folding went on: highly likely SQLi.
                        return true;
                    }

                    // The byte after the number. Upstream indexes with the
                    // token's length, not its end, and compares a `char`
                    // that is signed on its reference platform, so bytes
                    // above 127 count as whitespace.
                    let after = tokens[0].len;
                    return match self.input.get(after) {
                        Some(&ch) if ch.cast_signed() <= 32 => true,
                        Some(b'/') => self.input.get(after + 1) == Some(&b'*'),
                        Some(b'-') => self.input.get(after + 1) == Some(&b'-'),
                        _ => false,
                    };
                }

                // Many people put "--" in plain text, so only an input that
                // ends with it is flagged: "1--" but not "1-- foo".
                if tokens[1].len > 2 && tokens[1].byte(0) == b'-' {
                    return false;
                }
            }
            3 => {
                if matches!(fingerprint, b"sos" | b"s&s") {
                    // "...foo' + 'bar...": no opening quote, no closing
                    // quote, and the same quote in between. Anything else
                    // of this shape is not SQLi.
                    return tokens[0].str_open.is_none()
                        && tokens[2].str_close.is_none()
                        && tokens[0].str_close == tokens[2].str_open;
                } else if matches!(fingerprint, b"s&n" | b"n&1" | b"1&1" | b"1&v" | b"1&s") {
                    // "sexy and 17" is not SQLi, "sexy and 17<18" is.
                    if stats.tokens == 3 {
                        return false;
                    }
                } else if tokens[1].ty == TokenType::Keyword {
                    // Unless it is "INTO OUTFILE" or "INTO DUMPFILE" (MySQL),
                    // treat it as safe.
                    let keyword = tokens[1].value();
                    if keyword.len() < 5 || cstrcasecmp(b"INTO", &keyword[..4]) != Ordering::Equal {
                        return false;
                    }
                }
            }
            _ => {}
        }

        true
    }

    /// Fingerprints the input in the given context, returning the
    /// fingerprint if it is SQLi there.
    fn check(&mut self, quote: Quote, dialect: Dialect) -> Option<Fingerprint> {
        let fingerprint = self.fingerprint(quote, dialect);
        self.check_fingerprint().then_some(fingerprint)
    }

    /// Whether the fingerprint last taken is SQLi: a known pattern that the
    /// false-positive checks let through.
    pub fn check_fingerprint(&self) -> bool {
        self.blacklist() && self.not_whitelist()
    }

    /// Whether the last pass met syntax that MySQL reads differently.
    fn reparse_as_mysql(&self) -> bool {
        let stats = &self.lexer.stats;
        stats.comment_ddx != 0 || stats.comment_hash != 0
    }

    /// [`check`](Self::check), then once more as MySQL if that could differ.
    /// Returns the fingerprint and the dialect it was found in.
    fn check_ansi_then_mysql_dialect(&mut self, quote: Quote) -> Option<(Fingerprint, Dialect)> {
        if let Some(fingerprint) = self.check(quote, Dialect::Ansi) {
            return Some((fingerprint, Dialect::Ansi));
        }
        if self.reparse_as_mysql() {
            return self.check(quote, Dialect::Mysql).map(|fp| (fp, Dialect::Mysql));
        }
        None
    }
}

pub(crate) fn detect(input: &[u8]) -> Option<Fingerprint> {
    detect_with_dialect(input).map(|(fp, _)| fp)
}

pub(crate) fn detect_with_dialect(input: &[u8]) -> Option<(Fingerprint, Dialect)> {
    if input.is_empty() {
        return None;
    }
    let mut state = State::new(input, Quote::None, Dialect::Ansi);

    // The input as-is.
    if let Some(result) = state.check_ansi_then_mysql_dialect(Quote::None) {
        return Some(result);
    }

    // If the input has a single quote, test it as if it sat inside a
    // single-quoted string: "1' = 1" is read as "'1' = 1".
    if input.contains(&b'\'')
        && let Some(result) = state.check_ansi_then_mysql_dialect(Quote::Single)
    {
        return Some(result);
    }

    // The same with a double quote, which only MySQL uses for strings.
    if input.contains(&b'"') {
        return state
            .check(Quote::Double, Dialect::Mysql)
            .map(|fp| (fp, Dialect::Mysql));
    }

    None
}
