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

//! Regular expression matching with transaction macro expansion.

use std::path::Path;

use aho_corasick::AhoCorasick;

use super::{Datasets, Macro, MacroError, Operator, Outputs, simple::contains_bytes};
use crate::{
    rule_data::{FileSystem, RuleData, read_to_string},
    transaction::Transaction,
    transformations::text_of,
    utils::strings::x2c,
};

/// Regular expression operator with Coraza's multiline and dotall defaults.
#[derive(Debug, Clone)]
pub struct Rx {
    /// Pattern text with parsed transaction-variable references.
    macro_param: Macro,
    /// Compiled pattern when the parameter has no transaction variables.
    cached_regex: Option<CompiledRx>,
}

/// A compiled pattern that matches either Unicode text or raw bytes.
#[derive(Debug, Clone)]
enum CompiledRx {
    /// A Unicode regular expression using lossy input text when needed.
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
            regex::Regex::new(&format!("(?sm){pattern}")).map(Self::Text)
        }
    }

    /// Check whether the pattern matches the supplied bytes.
    fn is_match(&self, input: &[u8]) -> bool {
        match self {
            Self::Text(regex) => regex.is_match(&text_of(input)),
            Self::Bytes(regex) => regex.is_match(input),
        }
    }

    /// Return the match and all capture groups as bytes.
    fn captures(&self, input: &[u8]) -> Option<Vec<Option<Vec<u8>>>> {
        match self {
            Self::Text(regex) => regex.captures(&text_of(input)).map(|captures| {
                captures
                    .iter()
                    .map(|group| group.map(|group| group.as_str().as_bytes().to_vec()))
                    .collect()
            }),
            Self::Bytes(regex) => regex.captures(input).map(|captures| {
                captures
                    .iter()
                    .map(|group| group.map(|group| group.as_bytes().to_vec()))
                    .collect()
            }),
        }
    }
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
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        let expanded;
        let regex = if let Some(regex) = &self.cached_regex {
            regex
        } else {
            let pattern = self.macro_param.expand(tx);
            let Ok(compiled) = CompiledRx::new(&pattern) else {
                return false;
            };
            expanded = compiled;
            &expanded
        };

        if !out.wants_captures() {
            return regex.is_match(input);
        }
        let Some(groups) = regex.captures(input) else {
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
/// Patterns without transaction variables are compiled immediately. Patterns
/// containing variables are compiled when evaluated.
///
/// # Errors
///
/// Returns an error for malformed macros or an invalid static regular expression.
pub fn rx(pattern: &str) -> Result<Rx, Box<dyn std::error::Error>> {
    let macro_param = Macro::new(pattern)?;
    let cached_regex = if pattern.contains("%{") {
        None
    } else {
        Some(CompiledRx::new(pattern)?)
    };
    Ok(Rx {
        macro_param,
        cached_regex,
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
            let dict: Vec<&str> = patterns.split(' ').filter(|phrase| !phrase.trim().is_empty()).collect();
            if dict.is_empty() {
                return false;
            }
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
        let dict: Vec<&str> = patterns.split(' ').filter(|phrase| !phrase.trim().is_empty()).collect();
        if dict.is_empty() {
            None
        } else {
            AhoCorasick::builder().ascii_case_insensitive(true).build(&dict).ok()
        }
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
    fn new(patterns: &[String]) -> Result<Self, String> {
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
    /// Returns an error if the file cannot be read or no phrases are found.
    pub fn new(file_path: impl AsRef<Path>) -> Result<Self, String> {
        Self::with_rule_data(file_path, &FileSystem)
    }

    /// Read phrases from `file_path` through `rule_data`, ignoring blank lines and comments.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or no phrases are found.
    pub(crate) fn with_rule_data(file_path: impl AsRef<Path>, rule_data: &dyn RuleData) -> Result<Self, String> {
        let file_path = file_path.as_ref();
        let content = read_to_string(rule_data, file_path)
            .map_err(|error| format!("failed to read {}: {error}", file_path.display()))?;
        let patterns: Vec<_> = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_owned)
            .collect();
        if patterns.is_empty() {
            return Err(format!("no valid patterns found in {}", file_path.display()));
        }
        Ok(Self {
            phrases: Phrases::new(&patterns)?,
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
    Ok(PmFromDataset {
        phrases: Phrases::new(items)?,
    })
}

/// Create a phrase matcher from a file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or no phrases are found.
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
        let input = text_of(input);
        let Some(captures) = self.regex.captures(&input) else {
            return false;
        };
        for name in self.regex.capture_names().flatten() {
            if let Some(segment) = captures.name(name) {
                out.add_path_argument(name, segment.as_str());
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
    fn regex_expands_macros_and_captures_at_most_ten_groups() {
        let mut tx = Transaction::new("operator-test");
        tx.set_tx_variable("pattern", b"(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)");
        let operator = rx("%{TX.pattern}").unwrap();
        let mut out = Outputs::new(true);
        assert!(operator.evaluate(&tx, b"abcdefghij", &mut out));
        let captures: Vec<_> = out.take_captures().collect();
        assert_eq!(captures.len(), 10);
        assert_eq!(captures.first(), Some(&(0, b"abcdefghij".to_vec())));
        assert_eq!(captures.last(), Some(&(9, b"i".to_vec())));
    }

    #[test]
    fn invalid_patterns_are_errors_or_non_matches() {
        assert!(rx("(").is_err());
        assert!(rx("%{TX.pattern}").is_ok());
        let mut tx = Transaction::new("operator-test");
        tx.set_tx_variable("pattern", b"(");
        assert!(
            !rx("%{TX.pattern}")
                .unwrap()
                .evaluate(&tx, b"input", &mut Outputs::default())
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
    fn phrase_operators_ignore_empty_patterns() {
        let mut tx = Transaction::new("operator-test");
        tx.set_tx_variable("empty", b"");

        for patterns in ["", "   ", " \t\n ", "%{TX.empty}"] {
            let operator = pm(patterns).unwrap();
            assert!(!operator.evaluate(&tx, b"", &mut Outputs::default()));
            assert!(!operator.evaluate(&tx, b"anything", &mut Outputs::default()));
        }
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
