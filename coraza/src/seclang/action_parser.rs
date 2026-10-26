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

//! Action parser for `SecRule` directives.
//!
//! Parses action syntax like:
//! - `id:1,deny,log` - Multiple actions
//! - `id:123` - Action with value
//! - `deny` - Bare action (no value)
//! - `msg:'Attack detected'` - Quoted value
//! - `msg:'O\'Reilly'` - Escaped quotes

use winnow::{
    combinator::{alt, opt, preceded, repeat},
    error::EmptyError,
    prelude::*,
    token::{any, take_till, take_while},
};

use crate::seclang::CompileError;

/// Fallible result returned by the action parser.
type ParseResult<T> = Result<T, CompileError>;

/// One action of a rule's action list, as written; see [`crate::actions::Action::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedAction {
    /// Action key/name (lowercase, trimmed)
    pub key: String,

    /// Action value (trimmed, quotes removed); empty if the action has none
    pub value: String,
}

impl ParsedAction {
    /// The action written `key:value`, with its key trimmed and lowercased and its value
    /// trimmed and unquoted.
    fn new(key: &str, value: &str) -> Self {
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|rest| rest.strip_suffix('\'')))
            .unwrap_or(value);
        Self {
            key: key.trim().to_lowercase(),
            value: value.to_owned(),
        }
    }
}

/// Parse actions from `SecRule` syntax.
///
/// Parses action specifications like:
/// - `id:1,deny,log` - Multiple actions
/// - `id:123` - Single action with value
/// - `deny` - Bare action (no value)
/// - `msg:'Attack detected'` - Quoted value with spaces
/// - `msg:'O\'Reilly'` - Escaped quotes in value
///
/// # Arguments
///
/// * `input` - Action specification string (comma-separated)
///
/// # Returns
///
/// The actions in order, as name/value pairs; whether each name is a known action is
/// checked when the rule is compiled.
///
/// # Special handling
///
/// - Keys are lowercased and trimmed
/// - Values are trimmed and quotes removed
/// - As in Go Coraza, which only warns about it, a quote left open runs to the end of the line; the value then keeps
///   its opening quote, so a comma inside it doesn't separate
pub(crate) fn parse_actions(input: &str) -> ParseResult<Vec<ParsedAction>> {
    if input.trim().is_empty() {
        return Ok(Vec::new());
    }
    // The grammar accepts every non-empty line; report a failure instead of panicking on
    // hostile input if one ever slips through.
    action_list
        .parse(input)
        .map_err(|_error| CompileError::new(format!("invalid action line: {input}")))
}

/// `KEY[:VALUE]` actions separated by commas.
///
/// A comma, or a colon, doesn't separate between quotes (`'`) or after a backslash. As in
/// Go Coraza, the list's first character never separates nor opens a quote.
fn action_list(input: &mut &str) -> winnow::Result<Vec<ParsedAction>, EmptyError> {
    let first_key = (alt((escaped, any.take())), segment([',', ':'])).take();
    let mut actions = vec![action(first_key).parse_next(input)?];
    repeat(0.., preceded(',', action(segment([',', ':']))))
        .fold(|| (), |(), action| actions.push(action))
        .parse_next(input)?;
    Ok(actions)
}

/// An action, its key read by `key`: `KEY`, or `KEY:VALUE` where VALUE runs to the next
/// separating comma.
fn action<'i>(key: impl Parser<&'i str, &'i str, EmptyError>) -> impl Parser<&'i str, ParsedAction, EmptyError> {
    (key, opt(preceded(':', segment([','])))).map(|(key, value)| ParsedAction::new(key, value.unwrap_or_default()))
}

/// Text up to the first of `separators` that is neither quoted nor escaped.
fn segment<'i, const N: usize>(separators: [char; N]) -> impl Parser<&'i str, &'i str, EmptyError> {
    let unquoted = take_till(1.., move |c| matches!(c, '\\' | '\'') || separators.contains(&c));
    repeat::<_, _, (), _, _>(0.., alt((unquoted, quoted, escaped))).take()
}

/// `'...'`, in which a backslash escapes the closing quote. A quote left open takes the
/// rest of the line, as in Go Coraza: the value keeps its opening quote, which
/// [`ParsedAction::new`] then leaves alone.
fn quoted<'i>(input: &mut &'i str) -> winnow::Result<&'i str, EmptyError> {
    alt((('\'', quote_body, '\'').take(), ('\'', quote_body).take())).parse_next(input)
}

/// Text up to the closing quote, escapes kept.
fn quote_body<'i>(input: &mut &'i str) -> winnow::Result<&'i str, EmptyError> {
    let unescaped = take_till(1.., |c| matches!(c, '\\' | '\''));
    repeat::<_, _, (), _, _>(0.., alt((unescaped, escaped)))
        .take()
        .parse_next(input)
}

/// Backslashes and the character after them, which they escape: as in Go Coraza, a
/// character after a backslash is escaped even when that backslash is.
fn escaped<'i>(input: &mut &'i str) -> winnow::Result<&'i str, EmptyError> {
    (take_while(1.., '\\'), opt(any)).take().parse_next(input)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "action parser tests use fixed inputs"
)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_bare_action() {
        let actions = parse_actions("deny").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "deny");
        assert_eq!(actions[0].value, "");
    }

    #[test]
    fn test_parse_single_action_with_value() {
        let actions = parse_actions("id:123").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "id");
        assert_eq!(actions[0].value, "123");
    }

    #[test]
    fn test_parse_multiple_actions() {
        let actions = parse_actions("id:1,deny,log").unwrap();
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0].key, "id");
        assert_eq!(actions[0].value, "1");
        assert_eq!(actions[1].key, "deny");
        assert_eq!(actions[1].value, "");
        assert_eq!(actions[2].key, "log");
        assert_eq!(actions[2].value, "");
    }

    #[test]
    fn test_parse_action_with_quoted_value() {
        let actions = parse_actions("msg:'Attack detected'").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "msg");
        assert_eq!(actions[0].value, "Attack detected");
    }

    #[test]
    fn test_parse_action_with_escaped_quote() {
        let actions = parse_actions("msg:'O\\'Reilly'").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "msg");
        // Note: Escaped quote remains in value (backslash preserved)
        assert_eq!(actions[0].value, "O\\'Reilly");
    }

    #[test]
    fn test_parse_action_with_comma_in_quotes() {
        let actions = parse_actions("msg:'Hello, World'").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "msg");
        assert_eq!(actions[0].value, "Hello, World");
    }

    #[test]
    fn test_parse_action_with_colon_in_quotes() {
        let actions = parse_actions("msg:'Error: Bad request'").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "msg");
        assert_eq!(actions[0].value, "Error: Bad request");
    }

    #[test]
    fn test_parse_unterminated_quote_runs_to_end_of_line() {
        // As in Go Coraza, which warns about the quote left open instead of rejecting it:
        // the value keeps that quote, as its closing one is missing.
        let actions = parse_actions("msg:'Multipart request body failed strict validation.").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "msg");
        assert_eq!(actions[0].value, "'Multipart request body failed strict validation.");
    }

    #[test]
    fn test_parse_unterminated_quote_keeps_commas() {
        let actions = parse_actions("id:1,msg:'a,b,deny").unwrap();
        let pairs: Vec<_> = actions.iter().map(|a| (a.key.as_str(), a.value.as_str())).collect();
        assert_eq!(pairs, [("id", "1"), ("msg", "'a,b,deny")]);
    }

    #[test]
    fn test_parse_action_case_insensitive() {
        let actions = parse_actions("DENY,Log,ID:1").unwrap();
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0].key, "deny");
        assert_eq!(actions[1].key, "log");
        assert_eq!(actions[2].key, "id");
    }

    #[test]
    fn test_parse_action_with_whitespace() {
        let actions = parse_actions("id : 123 , deny , log").unwrap();
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0].key, "id");
        assert_eq!(actions[0].value, "123");
        assert_eq!(actions[1].key, "deny");
        assert_eq!(actions[2].key, "log");
    }

    #[test]
    fn test_parse_empty_action_string() {
        assert!(parse_actions("").unwrap().is_empty());
        assert!(parse_actions("  ").unwrap().is_empty());
    }

    #[test]
    fn test_parse_action_with_double_quotes() {
        let actions = parse_actions("msg:\"Double quoted\"").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "msg");
        assert_eq!(actions[0].value, "Double quoted");
    }

    #[test]
    fn test_parse_separators_escaped_or_quoted() {
        let actions = parse_actions("msg:a\\,b,tag:'x:y,z',setvar:tx.a=b:c").unwrap();
        let pairs: Vec<_> = actions.iter().map(|a| (a.key.as_str(), a.value.as_str())).collect();
        assert_eq!(pairs, [("msg", "a\\,b"), ("tag", "x:y,z"), ("setvar", "tx.a=b:c")]);
    }

    #[test]
    fn test_parse_escaped_backslash_still_escapes() {
        // As in Go Coraza, the quote after `\\` is escaped, so its value is left open and
        // runs to the end of the line, commas included
        let actions = parse_actions("msg:'a\\\\',deny").unwrap();
        let pairs: Vec<_> = actions.iter().map(|a| (a.key.as_str(), a.value.as_str())).collect();
        assert_eq!(pairs, [("msg", "'a\\\\',deny")]);
    }

    #[test]
    fn test_parse_first_character_never_separates() {
        // As in Go Coraza
        let actions = parse_actions(",deny").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, ",deny");
    }
}
