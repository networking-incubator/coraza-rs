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
//
// This port is based on the original Coraza, created by Juan Pablo Tosso and
// the OWASP Coraza contributors.
//
// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Regular expression matching.

use std::path::Path;

use aho_corasick::AhoCorasick;

use super::{Datasets, Macro, MacroError, Operator, Outputs, simple::contains_bytes};
use crate::{
    rule_data::{FileSystem, RuleData},
    transaction::Transaction,
    transformations::{RegexText, lowercase},
    utils::strings::x2c,
};

/// Regular expression operator with Coraza's multiline and dotall defaults.
#[derive(Debug, Clone)]
pub struct Rx {
    /// Compiled pattern.
    regex: CompiledRx,
}

/// A compiled pattern that matches either Unicode text or raw bytes.
#[derive(Debug, Clone)]
enum CompiledRx {
    /// A Unicode regular expression over Go-decoded text.
    Text(regex::Regex),
    /// A byte regular expression for patterns that spell invalid UTF-8 bytes.
    Bytes(regex::bytes::Regex),
}

impl CompiledRx {
    /// Compile a pattern, enabling multiline and dotall behavior.
    fn new(pattern: &str) -> Result<Self, regex::Error> {
        if spells_non_utf8_bytes(pattern) {
            let pattern = unbrace_byte_escapes(pattern);
            regex::bytes::RegexBuilder::new(&format!("(?sm){pattern}"))
                .unicode(false)
                .build()
                .map(Self::Bytes)
        } else {
            let pattern = ascii_perl_classes(pattern);
            regex::Regex::new(&format!("(?sm){pattern}")).map(Self::Text)
        }
    }

    /// Check whether the pattern matches the supplied bytes.
    fn is_match(&self, input: &[u8]) -> bool {
        match self {
            Self::Text(regex) => regex.is_match(RegexText::for_match(input).as_str()),
            Self::Bytes(regex) => regex.is_match(input),
        }
    }

    /// Return the match and all capture groups as bytes.
    fn captures(&self, input: &[u8]) -> Option<Vec<Option<Vec<u8>>>> {
        match self {
            Self::Text(regex) => {
                let text = RegexText::new(input);
                regex.captures(text.as_str()).map(|captures| {
                    captures
                        .iter()
                        .map(|group| {
                            group.map(|group| {
                                let range = text.original_range(group.start(), group.end());
                                input.get(range).unwrap_or_default().to_vec()
                            })
                        })
                        .collect()
                })
            },
            Self::Bytes(regex) => regex.captures(input).map(|captures| {
                captures
                    .iter()
                    .map(|group| group.map(|group| group.as_bytes().to_vec()))
                    .collect()
            }),
        }
    }
}

/// Rewrite Go's ASCII-only Perl classes as Unicode-disabled inline groups.
///
/// Go defines `\b`, `\B`, `\w`, `\W`, `\d`, `\D`, `\s` and `\S` in terms of
/// ASCII. Escaped literals such as `\\w` and `\b` inside a character class
/// (a backspace there) are left alone.
fn ascii_perl_classes(pattern: &str) -> std::borrow::Cow<'_, str> {
    let mut result = String::with_capacity(pattern.len());
    let mut changed = false;
    let mut offset = 0;

    while let Some(rest) = pattern.get(offset..) {
        let Some(character) = rest.chars().next() else {
            break;
        };
        let length = character.len_utf8();

        if character == '['
            && let Some(end) = class_end(pattern, offset)
        {
            let class = pattern.get(offset..end).unwrap_or_default();
            if let Some(rewritten) = rewrite_class(class) {
                result.push_str(&rewritten);
                changed = true;
            } else {
                result.push_str(class);
            }
            offset = end;
            continue;
        }

        if character == '\\' {
            if let Some(escaped) = rest.get(length..).and_then(|tail| tail.chars().next()) {
                let escaped_length = escaped.len_utf8();
                match escaped {
                    'b' | 'B' => {
                        result.push_str("(?-u:\\");
                        result.push(escaped);
                        result.push(')');
                    },
                    // A class, not `(?-u:\w)`: under `(?i)` Go folds the ASCII
                    // word class to `ſ` and Kelvin sign, as the class does.
                    'w' => result.push_str("[0-9A-Za-z_]"),
                    'W' => result.push_str("[^0-9A-Za-z_]"),
                    'd' => result.push_str("[0-9]"),
                    'D' => result.push_str("[^0-9]"),
                    // Rust's ASCII `\s` includes vertical tab; Go's does not.
                    's' => result.push_str(r"[\t\n\x0c\r ]"),
                    'S' => result.push_str(r"[^\t\n\x0c\r ]"),
                    _ => {
                        result.push('\\');
                        result.push(escaped);
                    },
                }
                changed |= matches!(escaped, 'b' | 'B' | 'w' | 'W' | 'd' | 'D' | 's' | 'S');
                offset += length + escaped_length;
                continue;
            }
            result.push('\\');
            offset += length;
            continue;
        }

        result.push(character);
        offset += length;
    }

    if changed {
        std::borrow::Cow::Owned(result)
    } else {
        std::borrow::Cow::Borrowed(pattern)
    }
}

/// The byte offset just past a `[:name:]` POSIX class, or `None` if it is not one.
fn posix_class_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'[') || bytes.get(start + 1) != Some(&b':') {
        return None;
    }
    let mut offset = start + 2;
    while offset + 1 < bytes.len() {
        if bytes.get(offset) == Some(&b':') && bytes.get(offset + 1) == Some(&b']') {
            return Some(offset + 2);
        }
        offset += 1;
    }
    None
}

/// The byte offset just past the character class starting at `start`.
fn class_end(pattern: &str, start: usize) -> Option<usize> {
    let bytes = pattern.as_bytes();
    let mut offset = start.checked_add(1)?;
    if bytes.get(offset) == Some(&b'^') {
        offset += 1;
    }
    let mut first = true;
    while let Some(&byte) = bytes.get(offset) {
        match byte {
            b'\\' => {
                offset = offset.saturating_add(2);
                first = false;
            },
            b'[' if bytes.get(offset + 1) == Some(&b':') => {
                // Only `[:name:]` is a POSIX class; `[.` and `[=` are literal
                // brackets in Go. An unterminated `[:` stays a literal `[` so a
                // later `]` still closes the class.
                if let Some(end) = posix_class_end(bytes, offset) {
                    offset = end;
                } else {
                    offset += 1;
                }
                first = false;
            },
            b']' if first => {
                offset += 1;
                first = false;
            },
            b']' => return Some(offset + 1),
            _ => {
                offset += 1;
                first = false;
            },
        }
    }
    None
}

/// Rewrite one character class containing a Perl class or Rust-only class syntax.
///
/// Rust's regex supports class nesting, so `[\s\S]` becomes
/// `[[\t\n\x0c\r ][^\t\n\x0c\r ]]`, which is exhaustive, and `[^\W]` becomes
/// `[^[^0-9A-Za-z_]]`, the ASCII word class. Rust's class-set operators and nested
/// `[` syntax are escaped so Go's literal reading survives. This preserves Go's
/// positive and negative semantics without lookaround (which the regex crate does
/// not support).
fn rewrite_class(class: &str) -> Option<String> {
    let inner = class.strip_prefix('[')?.strip_suffix(']')?;
    // Go treats `--` as a range/literal run while Rust reads it as class
    // difference. Leave those classes alone rather than guess; ordinary ranges
    // and the exhaustive `[\s\S]`/`[\w\W]` forms are handled below.
    //
    // shortcut: a class containing `--` keeps its pre-existing Rust parsing;
    // a full Go class parser is needed before rewriting hyphen runs.
    if inner.contains("--") {
        return None;
    }
    let mut rewritten = String::with_capacity(class.len());
    rewritten.push('[');
    let mut offset = 0;
    if inner.as_bytes().first() == Some(&b'^') {
        rewritten.push('^');
        offset = 1;
    }
    let mut changed = false;

    while let Some(&byte) = inner.as_bytes().get(offset) {
        if byte == b'\\' {
            let Some(escaped) = inner.get(offset + 1..).and_then(|tail| tail.chars().next()) else {
                rewritten.push('\\');
                offset += 1;
                continue;
            };
            let replacement = match escaped {
                'w' => Some("[0-9A-Za-z_]"),
                'W' => Some("[^0-9A-Za-z_]"),
                'd' => Some("[0-9]"),
                'D' => Some("[^0-9]"),
                's' => Some(r"[\t\n\x0c\r ]"),
                'S' => Some(r"[^\t\n\x0c\r ]"),
                _ => None,
            };
            if let Some(replacement) = replacement {
                rewritten.push_str(replacement);
                changed = true;
            } else {
                rewritten.push('\\');
                rewritten.push(escaped);
            }
            offset += 1 + escaped.len_utf8();
            continue;
        }

        // Rust treats `&&`, `--` and `~~` as class-set operators; Go treats
        // those bytes literally. A raw `[` starts a nested class in Rust, and
        // `]`/`^` are only literal in specific class positions. Escape them so
        // the nested-class wrapper does not change the original set.
        if byte == b'['
            && let Some(end) = posix_class_end(inner.as_bytes(), offset)
        {
            rewritten.push_str(inner.get(offset..end).unwrap_or_default());
            offset = end;
            continue;
        }
        match byte {
            b'&' => {
                rewritten.push_str(r"\x26");
                changed = true;
            },
            b'~' => {
                rewritten.push_str(r"\x7e");
                changed = true;
            },
            b'[' => {
                rewritten.push_str(r"\x5b");
                changed = true;
            },
            b']' => {
                rewritten.push_str(r"\x5d");
                changed = true;
            },
            b'^' => {
                rewritten.push_str(r"\x5e");
                changed = true;
            },
            _ => {
                let length = inner
                    .get(offset..)
                    .and_then(|tail| tail.chars().next())
                    .map_or(1, char::len_utf8);
                rewritten.push_str(inner.get(offset..offset.saturating_add(length)).unwrap_or_default());
                offset += length;
                continue;
            },
        }
        offset += 1;
    }

    rewritten.push(']');
    changed.then_some(rewritten)
}

/// Whether escaped bytes in `pattern` form invalid UTF-8.
fn spells_non_utf8_bytes(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut spelled = Vec::with_capacity(bytes.len());
    let mut offset = 0;
    while let Some(rest) = bytes.get(offset..) {
        if rest.is_empty() {
            break;
        }
        if let Some((byte, length)) = byte_escape(rest) {
            spelled.push(byte);
            offset += length;
        } else {
            let Some(byte) = rest.first().copied() else {
                break;
            };
            spelled.push(byte);
            offset += 1;
            if byte == b'\\'
                && let Some(escaped) = rest.get(1).copied()
            {
                spelled.push(escaped);
                offset += 1;
            }
        }
    }
    std::str::from_utf8(&spelled).is_err()
}

/// Convert braced byte escapes to the syntax accepted by the byte regex engine.
fn unbrace_byte_escapes(pattern: &str) -> String {
    let mut result = String::with_capacity(pattern.len());
    let mut rest = pattern;
    while !rest.is_empty() {
        if let Some((byte, length)) = byte_escape(rest.as_bytes()) {
            result.push_str("\\x");
            result.push(hex_digit(byte >> 4));
            result.push(hex_digit(byte & 0x0F));
            let Some(tail) = rest.get(length..) else {
                result.push_str(rest);
                break;
            };
            rest = tail;
            continue;
        }

        let Some(character) = rest.chars().next() else {
            break;
        };
        let escaped_length = if character == '\\' {
            rest.get(1..)
                .and_then(|tail| tail.chars().next())
                .map_or(0, char::len_utf8)
        } else {
            0
        };
        let length = character.len_utf8() + escaped_length;
        let Some(segment) = rest.get(..length) else {
            result.push_str(rest);
            break;
        };
        result.push_str(segment);
        let Some(tail) = rest.get(length..) else {
            break;
        };
        rest = tail;
    }
    result
}

/// Convert one hexadecimal nibble to a lowercase ASCII digit.
fn hex_digit(nibble: u8) -> char {
    if nibble < 10 {
        char::from(b'0' + nibble)
    } else {
        char::from(b'a' + nibble - 10)
    }
}

/// Decode an ASCII `\\xHH` or `\\x{HH}` escape at the start of `pattern`.
fn byte_escape(pattern: &[u8]) -> Option<(u8, usize)> {
    let decode = |digits: &[u8]| digits.iter().all(u8::is_ascii_hexdigit).then(|| x2c(digits))?;
    match pattern {
        [b'\\', b'x', b'{', high, low, b'}', ..] => Some((decode(&[*high, *low])?, 6)),
        [b'\\', b'x', b'{', digit, b'}', ..] => Some((decode(&[b'0', *digit])?, 5)),
        [b'\\', b'x', high, low, ..] => Some((decode(&[*high, *low])?, 4)),
        _ => None,
    }
}

impl Operator for Rx {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        if !out.wants_captures() {
            return self.regex.is_match(input);
        }
        let Some(groups) = self.regex.captures(input) else {
            return false;
        };
        for (index, group) in groups.iter().take(10).enumerate() {
            out.capture(index, group.as_deref().unwrap_or(&[]));
        }
        true
    }
}

/// Create a regular expression operator.
///
/// The pattern is compiled verbatim when the rule loads, as Go's `newRX` does;
/// `%{...}` is not expanded.
///
/// # Errors
///
/// Returns an error for an invalid regular expression.
pub fn rx(pattern: &str) -> Result<Rx, Box<dyn std::error::Error>> {
    Ok(Rx {
        regex: CompiledRx::new(pattern)?,
    })
}

/// Case-insensitive matching for any of the space-separated phrases.
#[derive(Debug, Clone)]
pub struct Pm {
    /// Phrases with transaction variable references parsed.
    macro_param: Macro,
    /// Matcher cached when the parameter has no variable references.
    cached_matcher: Option<AhoCorasick>,
}

impl Operator for Pm {
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        let expanded;
        let matcher = if let Some(matcher) = &self.cached_matcher {
            matcher
        } else {
            let patterns = self.macro_param.expand(tx).to_lowercase();
            // Go keeps empty phrases from `strings.Split`: an empty phrase
            // matches every input.
            let dict: Vec<&str> = patterns.split(' ').collect();
            match AhoCorasick::builder().ascii_case_insensitive(true).build(&dict) {
                Ok(matcher) => {
                    expanded = matcher;
                    &expanded
                },
                Err(_) => return false,
            }
        };

        if !out.wants_captures() {
            return matcher.is_match(input);
        }
        let mut matched = false;
        for (index, found) in matcher.find_iter(input).take(10).enumerate() {
            out.capture(index, input.get(found.range()).unwrap_or_default());
            matched = true;
        }
        matched
    }
}

/// Create a case-insensitive phrase matcher from space-separated patterns.
///
/// # Errors
///
/// Returns an error for malformed macro syntax.
pub fn pm(patterns: &str) -> Result<Pm, MacroError> {
    let macro_param = Macro::new(patterns)?;
    let cached_matcher = if patterns.contains("%{") {
        None
    } else {
        let patterns = patterns.to_lowercase();
        let dict: Vec<&str> = patterns.split(' ').collect();
        AhoCorasick::builder().ascii_case_insensitive(true).build(&dict).ok()
    };
    Ok(Pm {
        macro_param,
        cached_matcher,
    })
}

/// Case-insensitive phrase matching from a file, with one phrase per line.
#[derive(Debug, Clone)]
pub struct PmFromFile {
    /// Phrase matcher built from the file contents.
    phrases: Phrases,
}

/// A fixed phrase matcher shared by file and dataset operators.
#[derive(Debug, Clone)]
struct Phrases {
    /// Case-insensitive multi-pattern matcher.
    matcher: AhoCorasick,
}

impl Phrases {
    /// Build a matcher from phrases.
    ///
    /// # Errors
    ///
    /// Returns an error if the phrase set cannot be compiled.
    fn new(patterns: Vec<Vec<u8>>) -> Result<Self, String> {
        let matcher = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(patterns)
            .map_err(|error| format!("failed to build matcher: {error}"))?;
        Ok(Self { matcher })
    }

    /// Test the input and record up to ten matches when captures are enabled.
    fn evaluate(&self, input: &[u8], out: &mut Outputs) -> bool {
        if !out.wants_captures() {
            return self.matcher.is_match(input);
        }
        let mut matched = false;
        for (index, found) in self.matcher.find_iter(input).take(10).enumerate() {
            out.capture(index, input.get(found.range()).unwrap_or_default());
            matched = true;
        }
        matched
    }
}

impl PmFromFile {
    /// Read phrases from `file_path`, ignoring blank lines and comments.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn new(file_path: impl AsRef<Path>) -> Result<Self, String> {
        Self::with_rule_data(file_path, &FileSystem)
    }

    /// Read phrases from `file_path` through `rule_data`, ignoring blank lines and comments.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub(crate) fn with_rule_data(file_path: impl AsRef<Path>, rule_data: &dyn RuleData) -> Result<Self, String> {
        let file_path = file_path.as_ref();
        let content = rule_data
            .read(file_path)
            .map_err(|error| format!("failed to read {}: {error}", file_path.display()))?;
        let patterns = content
            .split(|byte| *byte == b'\n')
            .map(<[u8]>::trim_ascii)
            .filter(|line| !line.is_empty() && !line.starts_with(b"#"))
            .map(|line| lowercase(line).0)
            .collect();
        Ok(Self {
            phrases: Phrases::new(patterns)?,
        })
    }
}

impl Operator for PmFromFile {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        self.phrases.evaluate(input, out)
    }
}

/// Case-insensitive phrase matching from a named dataset.
#[derive(Debug, Clone)]
pub struct PmFromDataset {
    /// Phrase matcher built from the dataset contents.
    phrases: Phrases,
}

impl Operator for PmFromDataset {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        self.phrases.evaluate(input, out)
    }
}

/// Create a phrase matcher from dataset `name`.
///
/// # Errors
///
/// Returns an error if the dataset is missing or cannot be compiled.
pub fn pm_from_dataset(name: &str, datasets: &Datasets) -> Result<PmFromDataset, String> {
    let items = datasets
        .get(name)
        .ok_or_else(|| format!("dataset \"{name}\" not found"))?;
    let patterns = items.iter().map(|item| item.as_bytes().to_vec()).collect();
    Ok(PmFromDataset {
        phrases: Phrases::new(patterns)?,
    })
}

/// Create a phrase matcher from a file.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
pub fn pm_from_file(file_path: impl AsRef<Path>) -> Result<PmFromFile, String> {
    PmFromFile::new(file_path)
}

/// Match when the input occurs within the macro-expanded parameter.
#[derive(Debug, Clone)]
pub struct Within {
    /// Haystack with transaction variable references parsed.
    macro_param: Macro,
}

impl Operator for Within {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        contains_bytes(self.macro_param.expand(tx).as_bytes(), input)
    }
}

/// Create a `within` operator.
///
/// # Errors
///
/// Returns an error for malformed macro syntax.
pub fn within(haystack: &str) -> Result<Within, MacroError> {
    Ok(Within {
        macro_param: Macro::new(haystack)?,
    })
}

/// Case-sensitive substring matching, compatible with `strmatch`.
#[derive(Debug, Clone)]
pub struct StrMatch {
    /// Needle with transaction variable references parsed.
    macro_param: Macro,
}

impl Operator for StrMatch {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        contains_bytes(input, self.macro_param.expand(tx).as_bytes())
    }
}

/// Create a `strmatch` operator.
///
/// # Errors
///
/// Returns an error for malformed macro syntax.
pub fn strmatch(pattern: &str) -> Result<StrMatch, MacroError> {
    Ok(StrMatch {
        macro_param: Macro::new(pattern)?,
    })
}

/// Match a path template and return the values captured by its named segments.
///
/// A segment such as `{id}` matches up to the next slash or query delimiter. The
/// rest of the template is a regular expression, matched anywhere in the value.
#[derive(Debug, Clone)]
pub struct RestPath {
    /// Compiled template matcher.
    regex: regex::Regex,
}

impl Operator for RestPath {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        let text = RegexText::new(input);
        let Some(captures) = self.regex.captures(text.as_str()) else {
            return false;
        };
        for name in self.regex.capture_names().flatten() {
            if let Some(segment) = captures.name(name) {
                let range = text.original_range(segment.start(), segment.end());
                let value = String::from_utf8_lossy(input.get(range).unwrap_or_default());
                out.add_path_argument(name, &value);
            }
        }
        true
    }
}

/// Create a `restpath` operator from a template.
///
/// # Errors
///
/// Returns an error if a segment name or the resulting regular expression is invalid.
pub fn rest_path(template: &str) -> Result<RestPath, String> {
    let segment =
        regex::Regex::new(r"\{([^}]+)\}").map_err(|error| format!("invalid path segment matcher: {error}"))?;
    let pattern = segment.replace_all(template, "(?P<$1>[^?/]+)");
    regex::Regex::new(&pattern)
        .map(|regex| RestPath { regex })
        .map_err(|error| format!("invalid @restpath template {template:?}: {error}"))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "operator tests use fixed valid patterns")]
mod tests {
    use super::{Operator as _, Outputs, pm, rest_path, rx, strmatch, within};
    use crate::transaction::Transaction;

    #[test]
    fn regex_uses_multiline_and_dotall_defaults() {
        let tx = Transaction::new("operator-test");
        let mut out = Outputs::default();
        assert!(rx("^b$").unwrap().evaluate(&tx, b"a\nb\nc", &mut out));
        assert!(rx("hello.*world").unwrap().evaluate(&tx, b"hello\nworld", &mut out));
    }

    #[test]
    fn regex_matches_non_utf8_byte_escapes() {
        let tx = Transaction::new("operator-test");
        let mut out = Outputs::default();
        assert!(rx(r"\xff").unwrap().evaluate(&tx, b"\xff", &mut out));
        assert!(rx(r"\xff.*end").unwrap().evaluate(&tx, b"\xff\nend", &mut out));
        assert!(!rx(r"\xff").unwrap().evaluate(&tx, "\u{00ff}".as_bytes(), &mut out));
        assert!(rx(r"\\xff").unwrap().evaluate(&tx, br"\xff", &mut out));
    }

    #[test]
    fn regex_captures_at_most_ten_groups() {
        let tx = Transaction::new("operator-test");
        let operator = rx("(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)").unwrap();
        let mut out = Outputs::new(true);
        assert!(operator.evaluate(&tx, b"abcdefghij", &mut out));
        let captures: Vec<_> = out.take_captures().collect();
        assert_eq!(captures.len(), 10);
        assert_eq!(captures.first(), Some(&(0, b"abcdefghij".to_vec())));
        assert_eq!(captures.last(), Some(&(9, b"i".to_vec())));
    }

    #[test]
    fn regex_does_not_expand_macros() {
        let mut tx = Transaction::new("operator-test");
        tx.set_tx_variable("pattern", b"abc");

        // `%{2,}` is the regex quantifier over `%`, not a transaction variable.
        let operator = rx("%{2,}").unwrap();
        assert!(operator.evaluate(&tx, b"%%", &mut Outputs::default()));
        assert!(!operator.evaluate(&tx, b"abc", &mut Outputs::default()));
    }

    #[test]
    fn invalid_patterns_are_errors() {
        assert!(rx("(").is_err());
    }

    #[test]
    fn perl_classes_are_ascii_only_like_go() {
        let tx = Transaction::new("operator-test");
        let matches = |pattern: &str, input: &[u8]| rx(pattern).unwrap().evaluate(&tx, input, &mut Outputs::default());

        assert!(matches(r"\bfoo\b", "éfooé".as_bytes()));
        assert!(matches(r"\bselect\b", "éselecté".as_bytes()));
        assert!(!matches(r"^[\w.-]+$", "naïve".as_bytes()));
        assert!(!matches(r"\d", "٣".as_bytes()));
        assert!(!matches(r"\s", "\u{a0}".as_bytes()));
        assert!(!matches(r"\s", b"\x0b"), "Go's \\s excludes vertical tab");
        assert!(matches(r"\S", b"\x0b"), "Go's \\S includes vertical tab");
        assert!(matches(r"\W", "é".as_bytes()));
        // Go's `(?i)\w` folds the ASCII class to ſ and Kelvin sign; `(?-u:\w)` would not.
        assert!(matches(r"(?i)\w", "ſ".as_bytes()));
        assert!(!matches(r"(?i)\W", "ſ".as_bytes()));
        assert!(matches(r"\Bfoo", b"xfoo"));
        // `.` stays Unicode-aware.
        assert!(matches("^.$", "é".as_bytes()));
        // Nested classes keep the negation ASCII-only.
        assert!(!matches(r"[^\W]", "é".as_bytes()));
        assert!(matches(r"[\W]", "é".as_bytes()));
        assert!(matches(r"[^\d]", "١".as_bytes()));
        // A '-' after a class escape is literal, not a range beside the expansion.
        assert!(matches(r"[\w-a]", b"-"));
        assert!(matches(r"[\w-.]", b"."));
        // A positive class and its negation stay exhaustive after the rewrite.
        assert!(matches(r"[\s\S]", b"\x0b"));
        assert!(matches(r"[\s\S]", "\u{a0}".as_bytes()));
        assert!(matches(r"[\w\W]", "é".as_bytes()));
        assert!(matches(r"[\d\D]", "١".as_bytes()));
        assert!(matches(r"[^\W_]", b"a"));
        assert!(!matches(r"[^\W_]", b"_"));
        assert!(!matches(r"[^\W_]", "é".as_bytes()));
    }

    #[test]
    fn class_rewrite_escapes_rust_only_syntax() {
        let tx = Transaction::new("operator-test");
        let matches = |pattern: &str, input: &[u8]| rx(pattern).unwrap().evaluate(&tx, input, &mut Outputs::default());

        // Rust's class-set operators must not swallow Go's literal bytes.
        assert!(matches(r"[\w&&]", b"&"));
        assert!(matches(r"[\w~~]", b"~"));
        assert!(matches(r"[\w[]", b"["));
        assert!(matches(r"[\w^]", b"^"));
        // The rewrite also covers Rust-only class syntax when no Perl class is present.
        assert!(matches("[&&]", b"&"));
        assert!(matches("[a&&b]", b"&"));
        assert!(matches("[~~]", b"~"));
        assert!(matches("[[]", b"["));
    }

    #[test]
    fn posix_class_scanning_treats_dot_and_equals_as_literal_brackets() {
        let tx = Transaction::new("operator-test");
        let matches = |pattern: &str, input: &[u8]| rx(pattern).unwrap().evaluate(&tx, input, &mut Outputs::default());

        assert!(matches("[[.]", b"["));
        assert!(matches("[[.]", b"."));
        assert!(!matches("[[.]", b"]"));
        assert!(matches("[[=]", b"["));
        assert!(matches("[[=]", b"="));
        assert!(!matches("[[=]", b"]"));
        assert!(matches(r"[\w[.]", b"["));
        assert!(matches(r"[\w[.]", b"."));
        assert!(matches(r"[\w[.]", b"a"));
    }

    #[test]
    fn perl_class_scanner_leaves_literals_and_class_backspace_alone() {
        use super::ascii_perl_classes;

        assert_eq!(
            ascii_perl_classes(r"\bfoo\b [\b] \\w \d \S"),
            r"(?-u:\b)foo(?-u:\b) [\b] \\w [0-9] [^\t\n\x0c\r ]"
        );
        assert_eq!(ascii_perl_classes(r"[\w.-]+"), "[[0-9A-Za-z_].-]+");
        assert_eq!(ascii_perl_classes(r"[[:alpha:]\w]"), "[[:alpha:][0-9A-Za-z_]]");
        assert_eq!(ascii_perl_classes(r"[\W-a]"), "[[^0-9A-Za-z_]-a]");
    }

    #[test]
    fn invalid_utf8_is_one_replacement_character_per_byte() {
        let tx = Transaction::new("operator-test");
        let mut out = Outputs::default();

        assert!(rx("^..$").unwrap().evaluate(&tx, b"\xff\xfe", &mut out));
        assert!(!rx("^.$").unwrap().evaluate(&tx, b"\xff\xfe", &mut out));
        assert!(rx("^.$").unwrap().evaluate(&tx, "é".as_bytes(), &mut out));
    }

    #[test]
    fn captures_return_the_original_invalid_bytes() {
        let tx = Transaction::new("operator-test");
        let mut out = Outputs::new(true);

        assert!(rx("a(.*)b").unwrap().evaluate(&tx, b"a\xffb", &mut out));
        assert_eq!(
            out.take_captures().collect::<Vec<_>>(),
            [(0, b"a\xffb".to_vec()), (1, b"\xff".to_vec())]
        );

        // A valid multibyte character before the invalid byte keeps its bytes too.
        let mut out = Outputs::new(true);
        assert!(rx("(é)(.)").unwrap().evaluate(&tx, b"\xc3\xa9\xff", &mut out));
        assert_eq!(
            out.take_captures().collect::<Vec<_>>(),
            [
                (0, b"\xc3\xa9\xff".to_vec()),
                (1, b"\xc3\xa9".to_vec()),
                (2, b"\xff".to_vec()),
            ]
        );
    }

    #[test]
    fn phrase_operators_match_case_insensitively_and_capture_matches() {
        let tx = Transaction::new("operator-test");
        let operator = pm("admin guest").unwrap();
        let mut out = Outputs::new(true);
        assert!(operator.evaluate(&tx, b"ADMIN and guest", &mut out));
        assert_eq!(
            out.take_captures().collect::<Vec<_>>(),
            [(0, b"ADMIN".to_vec()), (1, b"guest".to_vec())]
        );
    }

    #[test]
    fn phrase_operators_keep_empty_phrases_like_go() {
        let mut tx = Transaction::new("operator-test");
        tx.set_tx_variable("empty", b"");

        for patterns in ["", "   ", " \t\n ", "%{TX.empty}"] {
            let operator = pm(patterns).unwrap();
            assert!(operator.evaluate(&tx, b"", &mut Outputs::default()));
            assert!(operator.evaluate(&tx, b"anything", &mut Outputs::default()));
        }
        // `@pm foo  bar` splits into `foo`, ``, `bar`; the empty phrase matches.
        assert!(
            pm("foo  bar")
                .unwrap()
                .evaluate(&tx, b"nothing", &mut Outputs::default())
        );
        assert!(
            !pm("foo bar")
                .unwrap()
                .evaluate(&tx, b"nothing", &mut Outputs::default())
        );
    }

    #[test]
    fn pm_from_file_reads_bytes_and_accepts_an_empty_file() {
        let tx = Transaction::new("operator-test");
        let directory = tempfile::tempdir().unwrap();
        let phrases = directory.path().join("phrases.data");
        std::fs::write(&phrases, b"# comment\nBAD\xffWORD\nNeedle\n").unwrap();
        let operator = super::pm_from_file(&phrases).unwrap();
        assert!(operator.evaluate(&tx, b"a NEEDLE here", &mut Outputs::default()));

        let empty = directory.path().join("empty.data");
        std::fs::write(&empty, b"# only comments\n\n").unwrap();
        let operator = super::pm_from_file(&empty).unwrap();
        assert!(!operator.evaluate(&tx, b"anything", &mut Outputs::default()));
    }

    #[test]
    fn phrase_and_substring_operators_expand_macros() {
        let mut tx = Transaction::new("operator-test");
        tx.set_tx_variable("terms", b"bad request");
        tx.set_tx_variable("needle", b"needle");

        assert!(
            pm("%{TX.terms}")
                .unwrap()
                .evaluate(&tx, b"BAD request", &mut Outputs::default())
        );
        assert!(
            within("a long parameter")
                .unwrap()
                .evaluate(&tx, b"long", &mut Outputs::default())
        );
        assert!(
            strmatch("%{TX.needle}")
                .unwrap()
                .evaluate(&tx, b"a needle here", &mut Outputs::default())
        );
        assert!(
            !strmatch("Needle")
                .unwrap()
                .evaluate(&tx, b"needle", &mut Outputs::default())
        );
    }

    #[test]
    fn restpath_extracts_segments_before_slashes_and_queries() {
        let tx = Transaction::new("operator-test");
        let operator = rest_path("/users/{id}/{name}").unwrap();
        let mut out = Outputs::default();

        assert!(operator.evaluate(&tx, b"/users/42/Alice?active=1", &mut out));
        assert_eq!(
            out.take_path_arguments().collect::<Vec<_>>(),
            [
                ("id".to_owned(), "42".to_owned()),
                ("name".to_owned(), "Alice".to_owned())
            ]
        );
        assert!(!operator.evaluate(&tx, b"/groups/42/Alice", &mut Outputs::default()));
    }

    #[test]
    fn restpath_rejects_invalid_segment_names() {
        assert!(rest_path("/users/{user-id}").is_err());
    }
}
