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

//! Parses variable lists used by `SecRule` directives.

use std::{borrow::Cow, str::FromStr as _};

use regex::RegexBuilder;
use winnow::{
    combinator::{alt, eof, not, opt, repeat, terminated},
    error::EmptyError,
    prelude::*,
    token::{any, take_till},
};

use crate::{
    rules::{VariableKey, VariableSpec},
    seclang::CompileError,
    types::RuleVariable,
};

/// The result of parsing a variable expression.
type ParseResult<T> = Result<T, CompileError>;

/// Parse variable expressions such as `ARGS|ARGS:id|&TX:score` in the default key mode.
#[cfg(test)]
pub(crate) fn parse_variables(input: &str) -> ParseResult<Vec<VariableSpec>> {
    parse_variables_in(input, false)
}

/// Parse variable expressions, compiling key regexes for the given argument key mode.
///
/// `case_sensitive_args_keys` mirrors [`crate::config::WafConfig::case_sensitive_args_keys`],
/// so regex selectors and maps agree on whether argument keys fold case.
pub(crate) fn parse_variables_in(input: &str, case_sensitive_args_keys: bool) -> ParseResult<Vec<VariableSpec>> {
    let mut variables = Vec::new();
    VariableList::parse(input, case_sensitive_args_keys)?.apply_to(&mut variables);
    Ok(variables)
}

/// A variable list, retained so negations can exclude earlier entries.
pub(crate) struct VariableList(Vec<Element>);

impl VariableList {
    /// Parse all expressions in a variable list.
    pub(crate) fn parse(input: &str, case_sensitive_args_keys: bool) -> ParseResult<Self> {
        if input.is_empty() {
            return Err(CompileError::new("empty variable specification".to_owned()));
        }

        let written: Vec<WrittenVariable<'_>> = repeat(0.., written_variable)
            .parse(input.as_bytes())
            .map_err(|_error| CompileError::new("invalid variable syntax".to_owned()))?;
        let parsed = written
            .into_iter()
            .map(WrittenVariable::resolve)
            .collect::<ParseResult<Vec<_>>>()?;
        parsed
            .into_iter()
            .map(|variable| build_element(&variable, case_sensitive_args_keys))
            .collect::<ParseResult<Vec<_>>>()
            .map(Self)
    }

    /// Apply entries in order. A negation modifies matching earlier variables.
    pub(crate) fn apply_to(&self, variables: &mut Vec<VariableSpec>) {
        for element in &self.0 {
            match element {
                Element::Inspect(spec) => variables.push(spec.clone()),
                Element::Exclude(variable, key) => {
                    for spec in variables.iter_mut().filter(|spec| spec.variable() == *variable) {
                        match key {
                            VariableKey::String(key) => spec.add_exception_string(key),
                            VariableKey::Regex(key) => spec.add_exception_regex(key.clone()),
                        }
                    }
                },
            }
        }
    }
}

/// A variable expression before its name is resolved.
struct WrittenVariable<'a> {
    /// The variable name, including any final delimiter character.
    name: Cow<'a, [u8]>,
    /// Count and negation markers found in the name.
    markers: Markers,
    /// Optional key, path, or regex as written.
    key: WrittenKey<'a>,
}

/// Count and negation flags from one variable expression.
struct Markers {
    /// Whether the variable is negated.
    is_negation: bool,
    /// Whether the variable requests a count.
    is_count: bool,
}

/// A parsed variable name and its marker flags.
type ParsedName<'a> = (Cow<'a, [u8]>, Markers);

/// The selector text following a variable name.
enum WrittenKey<'a> {
    /// No selector was written.
    None,
    /// Literal key text.
    Text(Vec<u8>),
    /// `XPath` or JSON path bytes.
    Path(&'a [u8]),
    /// Regex bytes without the surrounding slashes.
    Regex(Vec<u8>),
}

impl WrittenVariable<'_> {
    /// Resolve the variable name and validate its key selector.
    fn resolve(self) -> ParseResult<ParsedVariable> {
        let name = String::from_utf8_lossy(&self.name);
        let variable = RuleVariable::from_str(&name)
            .map_err(|error| CompileError::new(format!("invalid variable name '{name}': {error}")))?;

        let has_selector = !matches!(&self.key, WrittenKey::None);
        if has_selector && !variable.can_be_selected() {
            return Err(CompileError::new(format!(
                "attempting to select a value inside a non-selectable collection: {name}"
            )));
        }

        let (text, key) = match &self.key {
            WrittenKey::None => (&[][..], String::new()),
            WrittenKey::Text(text) => (text.as_slice(), String::from_utf8_lossy(text).into_owned()),
            WrittenKey::Path(path) => (*path, String::from_utf8_lossy(path).into_owned()),
            WrittenKey::Regex(pattern) => (pattern.as_slice(), format!("/{}/", String::from_utf8_lossy(pattern))),
        };

        Ok(ParsedVariable {
            variable,
            key: (!text.is_empty()).then_some(key),
            markers: self.markers,
        })
    }
}

/// A variable expression after its name has been resolved.
struct ParsedVariable {
    /// Resolved variable identifier.
    variable: RuleVariable,
    /// Optional literal, path, or regex selector text.
    key: Option<String>,
    /// Count and negation markers from the written name.
    markers: Markers,
}

/// Parse one variable expression and its terminating `|`.
fn written_variable<'i>(input: &mut &'i [u8]) -> winnow::Result<WrittenVariable<'i>, EmptyError> {
    not(eof).parse_next(input)?;
    let (name, markers) = name(input)?;
    let key = match opt(b':').parse_next(input)? {
        None => {
            opt(b'|').parse_next(input)?;
            WrittenKey::None
        },
        // Variable names are case-insensitive (`impl FromStr for RuleVariable`), so this
        // guard must fold case too: `request_xml:/*` resolves to `RequestXML` and needs the
        // same path parsing as `REQUEST_XML:/*`.
        Some(_)
            if name.eq_ignore_ascii_case(b"XML")
                || name.eq_ignore_ascii_case(b"JSON")
                || name.eq_ignore_ascii_case(b"REQUEST_XML") =>
        {
            // `REQUEST_XML` is the alias of `XML`, so an XPath selector such as `/*` must
            // parse as a path. Go exposes the alias as selectable
            // (`internal/variables/variables.go:594`, `RequestXML // CanBeSelected`) but
            // sends `REQUEST_XML:/*` down its regex parser, where the trailing `*` is
            // dropped and an empty pattern selects every XML entry. Parsing it as a path
            // selects the document root children, exactly as `XML:/*` does.
            let path = terminated(take_till(0.., b'|'), opt(b'|')).parse_next(input)?;
            WrittenKey::Path(path)
        },
        Some(_) => key(input)?,
    };
    Ok(WrittenVariable { name, markers, key })
}

/// Parse a variable name, removing `!` and `&` markers before resolving it.
fn name<'i>(input: &mut &'i [u8]) -> winnow::Result<ParsedName<'i>, EmptyError> {
    let written = (take_till(0.., (b'|', b':')), opt((b':', eof)))
        .take()
        .parse_next(input)?;
    let (marked, last) = if input.is_empty() {
        written.split_at(written.len().saturating_sub(1))
    } else {
        (written, &b""[..])
    };
    let is_marker = |byte: &u8| matches!(byte, b'!' | b'&');
    let parsed_name = if marked.iter().any(is_marker) {
        Cow::Owned(
            marked
                .iter()
                .filter(|byte| !is_marker(byte))
                .chain(last)
                .copied()
                .collect(),
        )
    } else {
        Cow::Borrowed(written)
    };
    Ok((
        parsed_name,
        Markers {
            is_negation: marked.contains(&b'!'),
            is_count: marked.contains(&b'&'),
        },
    ))
}

/// Parse a collection key, regex, or quoted key.
fn key<'i>(input: &mut &'i [u8]) -> winnow::Result<WrittenKey<'i>, EmptyError> {
    if opt(b'\'').parse_next(input)?.is_some() {
        let text = take_till(0.., b'\'').parse_next(input)?;
        b'\''.parse_next(input)?;
        finish_key(input)?;
        return Ok(WrittenKey::Text(text.to_vec()));
    }

    let mut text = take_till(0.., (b'|', b'/', b'\'')).parse_next(input)?.to_vec();
    if input.first() == Some(&b'/') {
        b'/'.parse_next(input)?;
        text.extend_from_slice(pattern(input)?);
        finish_key(input)?;
        Ok(WrittenKey::Regex(text))
    } else {
        finish_key(input)?;
        Ok(WrittenKey::Text(text))
    }
}

/// Consume the variable separator, or require the selector to end at EOF.
fn finish_key(input: &mut &[u8]) -> winnow::Result<(), EmptyError> {
    if opt(b'|').parse_next(input)?.is_none() {
        eof.parse_next(input)?;
    }
    Ok(())
}

/// Parse the contents of a slash-delimited regex key and require its closing slash.
fn pattern<'i>(input: &mut &'i [u8]) -> winnow::Result<&'i [u8], EmptyError> {
    let parsed = repeat::<_, _, (), _, _>(
        0..,
        alt((
            (b'\\', any).void(),
            take_till(1.., (b'\\', b'/')).void(),
            (b'\\', eof).void(),
        )),
    )
    .take()
    .parse_next(input)?;
    b'/'.parse_next(input)?;
    Ok(parsed)
}

/// One operation in an ordered variable list.
enum Element {
    /// Inspect the selected variable.
    Inspect(VariableSpec),
    /// Exclude keys from matching earlier variables of the same kind.
    Exclude(RuleVariable, VariableKey),
}

/// Build a selector or exclusion from one parsed expression.
fn build_element(variable: &ParsedVariable, case_sensitive_args_keys: bool) -> ParseResult<Element> {
    let key = variable
        .key
        .as_deref()
        .map(|key| parse_key(variable.variable, key, case_sensitive_args_keys))
        .transpose()?;

    if variable.markers.is_negation {
        let key =
            key.ok_or_else(|| CompileError::new(format!("a negated variable needs a key: !{}", variable.variable)))?;
        return Ok(Element::Exclude(variable.variable, key));
    }

    let mut spec = match key {
        Some(VariableKey::Regex(regex)) => VariableSpec::new_regex(variable.variable, regex),
        Some(VariableKey::String(key)) => VariableSpec::new_string(variable.variable, key),
        None => VariableSpec::new(variable.variable),
    };
    spec.set_count(variable.markers.is_count);
    Ok(Element::Inspect(spec))
}

/// Parse a slash-delimited key as a regex, using the variable's key sensitivity.
///
/// Go compiles selector regexes without the case-insensitive flag. For every variable
/// except the argument collections it first lower-cases the pattern source, which changes
/// what escapes and classes match: `REQUEST_HEADERS:/^\S+$/` becomes `^\s+$` and selects
/// nothing (`internal/corazawaf/rule.go:586`). Argument selectors keep the written source
/// and fold case only while their map folds it, because the regex runs against the
/// lower-cased lookup keys.
fn parse_key(variable: RuleVariable, key: &str, case_sensitive_args_keys: bool) -> ParseResult<VariableKey> {
    let Some(pattern) = key
        .strip_prefix('/')
        .and_then(|key| key.strip_suffix('/'))
        .filter(|pattern| !pattern.is_empty())
    else {
        return Ok(VariableKey::String(key.to_owned()));
    };

    let (source, case_insensitive) = if variable.has_case_sensitive_regex_keys() {
        // The argument collections keep the written source; the regex folds case exactly
        // while the argument map folds it too.
        (Cow::Borrowed(pattern), !case_sensitive_args_keys)
    } else {
        (Cow::Owned(pattern.to_lowercase()), false)
    };
    RegexBuilder::new(&source)
        .case_insensitive(case_insensitive)
        .build()
        .map(VariableKey::Regex)
        .map_err(|error| CompileError::new(format!("invalid regex pattern '{source}': {error}")))
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test variable expressions and regexes are fixed")]
mod tests {
    use super::*;
    use crate::{collection::Map, rules::CollectionView};

    fn parsed(input: &str) -> Vec<VariableSpec> {
        parse_variables(input).expect("test variable expression is valid")
    }

    fn matches(input: &str, variable: RuleVariable, map: &Map) -> Vec<String> {
        matches_in(input, variable, map, false)
    }

    fn matches_in(input: &str, variable: RuleVariable, map: &Map, case_sensitive_args_keys: bool) -> Vec<String> {
        parse_variables_in(input, case_sensitive_args_keys)
            .expect("test variable expression is valid")
            .iter()
            .filter(|spec| spec.variable() == variable)
            .flat_map(|spec| spec.get_matches(Some(CollectionView::Map(map))))
            .map(|matched| String::from_utf8_lossy(&matched.value).into_owned())
            .collect()
    }

    #[test]
    fn parses_all_values_and_literal_keys() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add("id", b"123");
        map.add("user", b"alice");

        let mut all_values = matches("ARGS", RuleVariable::Args, &map);
        all_values.sort_unstable();
        assert_eq!(all_values, ["123", "alice"]);
        assert_eq!(matches("ARGS:id", RuleVariable::Args, &map), ["123"]);
    }

    #[test]
    fn parses_regex_keys_and_applies_collection_case_rules() {
        let mut headers = Map::new(RuleVariable::RequestHeaders);
        headers.add("X-Forwarded-For", b"1.2.3.4");
        headers.add("Host", b"localhost");
        let mut args = Map::new(RuleVariable::Args);
        args.add("Foo", b"1");
        args.add("foo", b"2");

        assert_eq!(
            matches("REQUEST_HEADERS:/^x-forwarded/", RuleVariable::RequestHeaders, &headers),
            ["1.2.3.4"]
        );
        // The default mode folds argument key regexes like the argument maps fold lookups.
        assert_eq!(matches("ARGS:/^Foo$/", RuleVariable::Args, &args), ["1", "2"]);
        assert_eq!(matches_in("ARGS:/^foo$/", RuleVariable::Args, &args, false), ["1", "2"]);

        let mut strict = Map::new_case_sensitive(RuleVariable::Args);
        strict.add("Foo", b"1");
        strict.add("foo", b"2");
        assert_eq!(matches_in("ARGS:/^Foo$/", RuleVariable::Args, &strict, true), ["1"]);
        assert_eq!(matches_in("ARGS:/^foo$/", RuleVariable::Args, &strict, true), ["2"]);
        assert!(matches_in("ARGS:/^FOO$/", RuleVariable::Args, &strict, true).is_empty());
    }

    #[test]
    fn regex_key_escapes_are_not_lowercased() {
        let mut args = Map::new(RuleVariable::Args);
        args.add("USERID", b"value");

        // Lowercasing the pattern source would turn `\S` into `\s`, which cannot match.
        assert_eq!(
            matches_in("ARGS:/^user\\Sd$/", RuleVariable::Args, &args, false),
            ["value"]
        );
    }

    #[test]
    fn non_argument_regex_keys_are_lowered_in_both_modes() {
        let mut headers = Map::new(RuleVariable::RequestHeaders);
        headers.add("X-Trace", b"value");

        // Go lower-cases the pattern source instead of enabling case-insensitive matching,
        // so a lower-cased literal still selects the header in either key mode.
        assert_eq!(
            matches_in(
                "REQUEST_HEADERS:/^X-TRACE$/",
                RuleVariable::RequestHeaders,
                &headers,
                false
            ),
            ["value"]
        );
        assert_eq!(
            matches_in(
                "REQUEST_HEADERS:/^X-TRACE$/",
                RuleVariable::RequestHeaders,
                &headers,
                true
            ),
            ["value"]
        );
    }

    #[test]
    fn insensitive_regex_keys_are_lowered_like_go() {
        let mut headers = Map::new(RuleVariable::RequestHeaders);
        headers.add("Host", b"example");
        headers.add("Xa", b"2");
        headers.add("X-A", b"1");

        // Go turns `^\S+$` into `^\s+$`, which no header name can match
        // (`internal/corazawaf/rule.go:586`).
        assert!(matches("REQUEST_HEADERS:/^\\S+$/", RuleVariable::RequestHeaders, &headers).is_empty());
        // `\D` becomes `\d`, and no header name is all digits.
        assert!(matches("REQUEST_HEADERS:/^\\D+$/", RuleVariable::RequestHeaders, &headers).is_empty());
        // `[A-Z]` becomes `[a-z]`, which only the all-letter header names match.
        let mut letters = matches("REQUEST_HEADERS:/^[A-Z]+$/", RuleVariable::RequestHeaders, &headers);
        letters.sort_unstable();
        assert_eq!(letters, ["2", "example"]);
        // Literal letters are unaffected once both the pattern and the stored keys are
        // lower-cased.
        assert_eq!(
            matches("REQUEST_HEADERS:/^Host$/", RuleVariable::RequestHeaders, &headers),
            ["example"]
        );
        // Literal selectors never consult the regex path.
        assert_eq!(
            matches("REQUEST_HEADERS:Host", RuleVariable::RequestHeaders, &headers),
            ["example"]
        );
        assert_eq!(
            matches("REQUEST_HEADERS:'Host'", RuleVariable::RequestHeaders, &headers),
            ["example"]
        );
    }

    #[test]
    fn argument_regex_keys_keep_their_case_in_strict_mode() {
        let mut strict = Map::new_case_sensitive(RuleVariable::Args);
        strict.add("userXd", b"1");
        strict.add("userxd", b"2");

        // Go leaves the argument pattern as written (`internal/corazawaf/rule.go:548`), so
        // `\S` keeps its meaning and both spellings of the non-space character match.
        let mut non_space = matches_in("ARGS:/^user\\Sd$/", RuleVariable::Args, &strict, true);
        non_space.sort_unstable();
        assert_eq!(non_space, ["1", "2"]);
        // `\W` still means non-word, so it cannot match the upper-case `X`.
        assert!(matches_in("ARGS:/^user\\Wd$/", RuleVariable::Args, &strict, true).is_empty());
        // An upper-case class stays upper-case.
        assert!(matches_in("ARGS:/^[A-Z]+$/", RuleVariable::Args, &strict, true).is_empty());
        assert_eq!(matches_in("ARGS:/^userXd$/", RuleVariable::Args, &strict, true), ["1"]);
    }

    #[test]
    fn regex_exclusions_follow_regex_case_rules() {
        let mut args = Map::new(RuleVariable::Args);
        args.add("Foo", b"1");
        args.add("foo", b"2");

        // Default mode folds the exception regex, so it excludes every spelling.
        assert!(matches("ARGS|!ARGS:/^Foo$/", RuleVariable::Args, &args).is_empty());

        let mut strict = Map::new_case_sensitive(RuleVariable::Args);
        strict.add("Foo", b"1");
        strict.add("foo", b"2");
        assert_eq!(
            matches_in("ARGS|!ARGS:/^Foo$/", RuleVariable::Args, &strict, true),
            ["2"]
        );
        assert_eq!(
            matches_in("ARGS|!ARGS:/^foo$/", RuleVariable::Args, &strict, true),
            ["1"]
        );
    }

    #[test]
    fn count_and_negation_apply_to_prior_specs() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add("id", b"123");
        map.add("name", b"alice");

        let counted = parsed("&ARGS");
        let counted = counted
            .first()
            .expect("count expression creates one selector")
            .get_matches(Some(CollectionView::Map(&map)));
        assert_eq!(counted.len(), 1);
        assert_eq!(counted.first().expect("count creates one match").value, b"2");
        assert_eq!(matches("ARGS|!ARGS:id", RuleVariable::Args, &map), ["alice"]);
        assert!(parsed("!ARGS:id").is_empty());
    }

    #[test]
    fn regex_negation_and_pipe_inside_regex_are_parsed() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add("id_1", b"1");
        map.add("name", b"2");

        assert_eq!(matches("ARGS:/a|e/", RuleVariable::Args, &map), ["2"]);
        assert_eq!(matches("ARGS|!ARGS:/^id_/", RuleVariable::Args, &map), ["2"]);
    }

    #[test]
    fn accepts_xml_and_json_paths() {
        assert_eq!(parsed("XML:/*|JSON:a.b").len(), 2);
        assert_eq!(parsed("REQUEST_XML:/*").len(), 1);

        // Names parse case-insensitively, so every spelling must take the path branch.
        // `/*` only survives it: the generic key parser reads it as an unterminated regex.
        assert_eq!(parsed("xml:/*|json:a.b").len(), 2);
        assert_eq!(parsed("Request_Xml:/*").len(), 1);

        // The guard covers only those three names: another variable, however cased, still
        // reaches the generic key parser, including pipes inside its regex.
        let mut args = Map::new(RuleVariable::Args);
        args.add("id_1", b"1");
        args.add("name", b"2");
        assert_eq!(matches("args:/a|e/", RuleVariable::Args, &args), ["2"]);
    }

    #[test]
    fn request_xml_selector_selects_the_root_children_in_both_key_modes() {
        let mut xml = Map::new(RuleVariable::RequestXML);
        xml.add("/*", b"superuser & guest");
        xml.add("//@*", b"admin");

        // Go marks REQUEST_XML selectable (`internal/variables/variables.go:594`), so the
        // selector compiles in either key mode, and the name is case-insensitive.
        for selector in ["REQUEST_XML:/*", "request_xml:/*", "Request_Xml:/*"] {
            assert_eq!(
                parse_variables_in(selector, true).map(|variables| variables.len()),
                Ok(1)
            );
            assert_eq!(matches(selector, RuleVariable::RequestXML, &xml), ["superuser & guest"]);
            assert_eq!(
                matches_in(selector, RuleVariable::RequestXML, &xml, true),
                ["superuser & guest"]
            );
        }

        // Selectability does not depend on the key mode, but single-value collections stay
        // unselectable in both.
        assert!(parse_variables("REQUEST_XML:foo").is_ok());
        assert!(parse_variables_in("REQUEST_URI:foo", true).is_err());
    }

    #[test]
    fn chained_rules_see_the_lowered_selector_patterns() {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRule REQUEST_HEADERS:/^\\S+$/ \"@unconditionalMatch\" \"id:90,phase:1,deny,chain\"\n\
                 SecRule REQUEST_HEADERS:/^host$/ \"@unconditionalMatch\" \"\"",
            )
            .expect("chained rules compile");
        let waf = parser.into_waf().expect("chained rules build a WAF");
        let mut tx = waf.new_transaction_with_id("chain-lowered");
        tx.add_request_header("Host", b"example");
        assert_eq!(tx.process_request_headers(), None);

        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRule REQUEST_HEADERS:/.*/ \"@unconditionalMatch\" \"id:91,phase:1,deny,chain\"\n\
                 SecRule REQUEST_HEADERS:/^host$/ \"@unconditionalMatch\" \"\"",
            )
            .expect("chained rules compile");
        let waf = parser.into_waf().expect("chained rules build a WAF");
        let mut tx = waf.new_transaction_with_id("chain-match");
        tx.add_request_header("Host", b"example");
        assert_eq!(tx.process_request_headers().map(|item| item.rule_id), Some(91));
    }

    #[test]
    fn rejects_invalid_and_non_selectable_variables() {
        assert!(parse_variables("").is_err());
        assert!(parse_variables("INVALID_VAR").is_err());
        assert!(parse_variables("REQUEST_URI:foo").is_err());
        assert!(parse_variables("REQUEST_URI://").is_err());
        assert!(parse_variables("URI_PARSE_ERROR:foo").is_err());
        assert_eq!(
            parse_variables("URI_PARSE_ERROR").map(|variables| variables.len()),
            Ok(1)
        );
        assert_eq!(
            parse_variables("REQUEST_URI:/foo/").err(),
            parse_variables("REQUEST_URI:foo").err()
        );
        assert!(parse_variables("ARGS|!ARGS").is_err());
        assert!(parse_variables("ARGS:/[/").is_err());
        assert!(parse_variables("ARGS:/^id$").is_err());
        assert!(parse_variables("ARGS:/^id$/!ARGS:secret").is_err());
    }

    #[test]
    fn preserves_upstream_quoting_and_terminal_delimiter_behavior() {
        let mut args = Map::new_case_sensitive(RuleVariable::Args);
        args.add("id", b"123");

        assert_eq!(matches("ARGS:'id'", RuleVariable::Args, &args), ["123"]);
        assert_eq!(parsed("ARGS:'id'|TX").len(), 2);
        assert_eq!(matches("ARGS:'id'|TX", RuleVariable::Args, &args), ["123"]);
        assert!(parse_variables("ARGS:'id").is_err());
        assert_eq!(parsed("ARGS:'/a/'|TX").len(), 2);
        assert!(parse_variables("ARGS:'/a/|TX").is_err());
        assert!(parse_variables("ARGS|ARGS:").is_err());
    }
}
