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

use regex::Regex;
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
    utils::lowercase_like_go,
};

/// The result of parsing a variable expression.
type ParseResult<T> = Result<T, CompileError>;

/// Parse variable expressions such as `ARGS|ARGS:id|&TX:score`.
#[cfg(test)]
pub(crate) fn parse_variables(input: &str) -> ParseResult<Vec<VariableSpec>> {
    parse_variables_in(input)
}

/// Parse variable expressions.
///
/// The configured argument key mode does not affect compilation: a selector is lowered
/// from its variable alone, as Go's `caseSensitiveVariable` decides it, and only the
/// transaction's argument maps decide whether the keys it is matched against fold case.
pub(crate) fn parse_variables_in(input: &str) -> ParseResult<Vec<VariableSpec>> {
    let mut variables = Vec::new();
    VariableList::parse(input)?.apply_to(&mut variables, false);
    Ok(variables)
}

/// A variable list, retained so negations can exclude earlier entries.
pub(crate) struct VariableList(Vec<Element>);

impl VariableList {
    /// Parse all expressions in a variable list.
    pub(crate) fn parse(input: &str) -> ParseResult<Self> {
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
            .map(|variable| build_element(&variable))
            .collect::<ParseResult<Vec<_>>>()
            .map(Self)
    }

    /// Apply entries in order. A negation modifies matching earlier variables.
    pub(crate) fn apply_to(&self, variables: &mut Vec<VariableSpec>, multiphase: bool) {
        for element in &self.0 {
            match element {
                Element::Inspect(spec) => {
                    if multiphase {
                        match spec.clone().split_args() {
                            Ok(split) => variables.extend(split),
                            Err(spec) => variables.push(spec),
                        }
                    } else {
                        variables.push(spec.clone());
                    }
                },
                Element::Exclude(variable, key) => {
                    for spec in variables.iter_mut().filter(|spec| {
                        spec.variable() == *variable
                            || (multiphase
                                && matches!(
                                    (*variable, spec.variable()),
                                    (
                                        RuleVariable::Args | RuleVariable::ArgsNames,
                                        RuleVariable::ArgsGet
                                            | RuleVariable::ArgsPost
                                            | RuleVariable::ArgsGetNames
                                            | RuleVariable::ArgsPostNames
                                    )
                                ))
                    }) {
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
            //
            // `RESPONSE_XML` stays out: it is never populated, so the path branch would
            // only turn valid selectors such as `RESPONSE_XML:/a\|b/` into compile errors.
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
fn build_element(variable: &ParsedVariable) -> ParseResult<Element> {
    let key = variable
        .key
        .as_deref()
        .map(|key| parse_key(variable.variable, key))
        .transpose()?;

    if variable.markers.is_negation {
        let key =
            key.ok_or_else(|| CompileError::new(format!("a negated variable needs a key: !{}", variable.variable)))?;
        return Ok(Element::Exclude(variable.variable, key));
    }

    let mut spec = match key {
        Some(VariableKey::Regex(regex)) => {
            let count_key = variable
                .key
                .as_deref()
                .map_or_else(String::new, |key| count_key(variable.variable, key));
            VariableSpec::new_regex(variable.variable, regex, count_key)
        },
        Some(VariableKey::String(key)) => VariableSpec::new_string(variable.variable, key),
        None => VariableSpec::new(variable.variable),
    };
    spec.set_count(variable.markers.is_count);
    Ok(Element::Inspect(spec))
}

/// The selector text Go reports for a count-mode match.
///
/// Go's `KeyStr` is the whole written selector, slashes included, lowered for every
/// variable outside `caseSensitiveVariable` (`internal/corazawaf/rule.go:562-570`); a
/// literal selector is stored already lowered by [`parse_key`].
fn count_key(variable: RuleVariable, key: &str) -> String {
    if variable.has_case_sensitive_selectors() {
        key.to_owned()
    } else {
        lowercase_like_go(key)
    }
}

/// Parse a slash-delimited key as a regex, using the variable's key sensitivity.
///
/// Go compiles every selector and exception regex as written, without the
/// case-insensitive flag. For every variable outside `caseSensitiveVariable` it first
/// lower-cases the pattern source with its simple mapping, which changes what escapes and
/// classes match: `REQUEST_HEADERS:/^\S+$/` becomes `^\s+$` and selects nothing
/// (`internal/corazawaf/rule.go:575-589`). Argument patterns keep the written source and
/// run against the folded lookup key, so `ARGS:/^userId$/` never matches even when the
/// argument is spelled `userId`; selectors and exceptions share that rule
/// (`internal/corazawaf/rule.go:562`, `internal/corazawaf/transaction.go:684-698`).
///
/// A literal key is lowered the same way. Go lowers `KeyStr` before it looks a literal up
/// (`rule.go:562-570`), which only changes a case-sensitive map such as `ARGS_PATH` under
/// `coraza.rule.case_sensitive_args_keys`: `ARGS_PATH:UserId` becomes `userid` and no
/// longer selects the stored `UserId`.
fn parse_key(variable: RuleVariable, key: &str) -> ParseResult<VariableKey> {
    let Some(pattern) = key
        .strip_prefix('/')
        .and_then(|key| key.strip_suffix('/'))
        .filter(|pattern| !pattern.is_empty())
    else {
        return Ok(VariableKey::String(count_key(variable, key)));
    };

    let source = if variable.has_case_sensitive_selectors() {
        Cow::Borrowed(pattern)
    } else {
        Cow::Owned(lowercase_like_go(pattern))
    };
    Regex::new(&source)
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
        parse_variables_in(input)
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
        // Go compiles the argument pattern as written and runs it against the folded key,
        // so `^Foo$` never matches the folded `foo`; a lower-cased pattern matches both
        // spellings.
        assert!(matches("ARGS:/^Foo$/", RuleVariable::Args, &args).is_empty());
        assert_eq!(matches("ARGS:/^foo$/", RuleVariable::Args, &args), ["1", "2"]);

        let mut strict = Map::new_case_sensitive(RuleVariable::Args);
        strict.add("Foo", b"1");
        strict.add("foo", b"2");
        assert_eq!(matches("ARGS:/^Foo$/", RuleVariable::Args, &strict), ["1"]);
        assert_eq!(matches("ARGS:/^foo$/", RuleVariable::Args, &strict), ["2"]);
        assert!(matches("ARGS:/^FOO$/", RuleVariable::Args, &strict).is_empty());
    }

    #[test]
    fn regex_key_escapes_are_not_lowercased() {
        let mut args = Map::new(RuleVariable::Args);
        args.add("USERID", b"value");

        // Lowercasing the pattern source would turn `\S` into `\s`, which cannot match.
        assert_eq!(matches("ARGS:/^user\\Sd$/", RuleVariable::Args, &args), ["value"]);
    }

    #[test]
    fn non_argument_regex_keys_are_lowered() {
        let mut headers = Map::new(RuleVariable::RequestHeaders);
        headers.add("X-Trace", b"value");

        // Go lower-cases the pattern source instead of enabling case-insensitive matching,
        // so a lower-cased literal still selects the header.
        assert_eq!(
            matches("REQUEST_HEADERS:/^X-TRACE$/", RuleVariable::RequestHeaders, &headers),
            ["value"]
        );
    }

    #[test]
    fn non_argument_regex_keys_lower_u_0130_like_go() {
        let mut headers = Map::new(RuleVariable::RequestHeaders);
        headers.add("\u{130}", b"value");

        // Go lowers the pattern source with its simple mapping, so `^İ$` becomes `^i$` and
        // matches the folded key. Rust's full mapping would keep `i` + U+0307 and match
        // nothing.
        assert_eq!(
            matches("REQUEST_HEADERS:/^\u{130}$/", RuleVariable::RequestHeaders, &headers),
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
    fn argument_regex_keys_keep_their_written_case() {
        let mut strict = Map::new_case_sensitive(RuleVariable::Args);
        strict.add("userXd", b"1");
        strict.add("userxd", b"2");

        // Go leaves the argument pattern as written (`internal/corazawaf/rule.go:562`), so
        // `\S` keeps its meaning and both spellings of the non-space character match.
        let mut non_space = matches("ARGS:/^user\\Sd$/", RuleVariable::Args, &strict);
        non_space.sort_unstable();
        assert_eq!(non_space, ["1", "2"]);
        // `\W` still means non-word, so it cannot match the upper-case `X`.
        assert!(matches("ARGS:/^user\\Wd$/", RuleVariable::Args, &strict).is_empty());
        // An upper-case class stays upper-case.
        assert!(matches("ARGS:/^[A-Z]+$/", RuleVariable::Args, &strict).is_empty());
        assert_eq!(matches("ARGS:/^userXd$/", RuleVariable::Args, &strict), ["1"]);
    }

    #[test]
    fn regex_exclusions_follow_regex_case_rules() {
        let mut args = Map::new(RuleVariable::Args);
        args.add("Foo", b"1");
        args.add("foo", b"2");

        // Go compiles the exception as written and runs it against the folded key, so
        // `^Foo$` excludes nothing even though the map folds `Foo` to `foo`.
        let mut none = matches("ARGS|!ARGS:/^Foo$/", RuleVariable::Args, &args);
        none.sort_unstable();
        assert_eq!(none, ["1", "2"]);
        assert!(matches("ARGS|!ARGS:/^foo$/", RuleVariable::Args, &args).is_empty());

        let mut strict = Map::new_case_sensitive(RuleVariable::Args);
        strict.add("Foo", b"1");
        strict.add("foo", b"2");
        // Go runs the exception regex against the lowered key, so a written `^Foo$` never
        // excludes the stored `Foo`, while `^foo$` excludes both spellings
        // (`internal/corazawaf/transaction.go:689`).
        let mut both = matches("ARGS|!ARGS:/^Foo$/", RuleVariable::Args, &strict);
        both.sort_unstable();
        assert_eq!(both, ["1", "2"]);
        assert!(matches("ARGS|!ARGS:/^foo$/", RuleVariable::Args, &strict).is_empty());
    }

    #[test]
    fn names_selectors_are_exact_lookups() {
        let names = |input: &str, variable: RuleVariable, map: &Map| -> Vec<String> {
            parse_variables_in(input)
                .expect("test variable expression is valid")
                .iter()
                .filter(|spec| spec.variable() == variable)
                .flat_map(|spec| spec.get_matches(Some(CollectionView::Names(variable, map))))
                .map(|matched| String::from_utf8_lossy(&matched.value).into_owned())
                .collect()
        };

        // `?Id=secret`: the folded map stores the lookup key `id`, and Go's names view is
        // an exact `data[key]` lookup that never folds the selector
        // (`internal/collections/named.go:129-131`).
        let mut folded = Map::new(RuleVariable::ArgsGet);
        folded.add("Id", b"secret");
        assert!(names("ARGS_GET_NAMES:Id", RuleVariable::ArgsGetNames, &folded).is_empty());
        // The names view exposes the stored spelling, as Go's `d.key` does.
        assert_eq!(names("ARGS_GET_NAMES:id", RuleVariable::ArgsGetNames, &folded), ["Id"]);

        // Under `case_sensitive_args_keys` the stored key keeps its spelling.
        let mut exact = Map::new_case_sensitive(RuleVariable::ArgsGet);
        exact.add("Id", b"secret");
        assert_eq!(names("ARGS_GET_NAMES:Id", RuleVariable::ArgsGetNames, &exact), ["Id"]);
        assert!(names("ARGS_GET_NAMES:id", RuleVariable::ArgsGetNames, &exact).is_empty());

        // Non-argument selectors are lowered before the exact lookup, so both writings
        // reach the folded header key, as Go's `KeyStr` does.
        let mut headers = Map::new(RuleVariable::RequestHeaders);
        headers.add("X-Foo", b"bar");
        assert_eq!(
            names(
                "REQUEST_HEADERS_NAMES:X-Foo",
                RuleVariable::RequestHeadersNames,
                &headers
            ),
            ["X-Foo"]
        );
        assert_eq!(
            names(
                "REQUEST_HEADERS_NAMES:x-foo",
                RuleVariable::RequestHeadersNames,
                &headers
            ),
            ["X-Foo"]
        );
    }

    #[test]
    fn args_path_literals_are_lowered_like_go() {
        // Go's `caseSensitiveVariable` leaves ARGS_PATH out (`internal/corazawaf/rule.go:548`),
        // so its literal is lowered even when the map keeps stored keys as written.
        let mut folded = Map::new(RuleVariable::ArgsPath);
        folded.add("UserId", b"1");
        assert_eq!(matches("ARGS_PATH:UserId", RuleVariable::ArgsPath, &folded), ["1"]);
        assert_eq!(matches("ARGS_PATH:userid", RuleVariable::ArgsPath, &folded), ["1"]);

        let mut exact = Map::new_case_sensitive(RuleVariable::ArgsPath);
        exact.add("UserId", b"1");
        assert!(matches("ARGS_PATH:UserId", RuleVariable::ArgsPath, &exact).is_empty());
        assert!(matches("ARGS_PATH:userid", RuleVariable::ArgsPath, &exact).is_empty());

        // Only an already-lowered stored key is reachable through the lowered selector.
        let mut lower = Map::new_case_sensitive(RuleVariable::ArgsPath);
        lower.add("userid", b"2");
        assert_eq!(matches("ARGS_PATH:userid", RuleVariable::ArgsPath, &lower), ["2"]);
    }

    #[test]
    fn count_matches_report_go_key_str() {
        let mut headers = Map::new(RuleVariable::RequestHeaders);
        headers.add("X-Foo", b"bar");
        let counted = |input: &str| -> Vec<String> {
            parse_variables_in(input)
                .expect("test variable expression is valid")
                .iter()
                .flat_map(|spec| spec.get_matches(Some(CollectionView::Map(&headers))))
                .map(|matched| matched.key)
                .collect()
        };
        // Go reports the compile-time `KeyStr` (`internal/corazawaf/transaction.go:698-704`):
        // the lowered literal, or the lowered selector with its slashes.
        assert_eq!(counted("&REQUEST_HEADERS:X-Foo"), ["x-foo"]);
        assert_eq!(counted("&REQUEST_HEADERS:/^X-FOO$/"), ["/^x-foo$/"]);

        let mut args = Map::new(RuleVariable::Args);
        args.add("re1", b"one");
        let counted = parse_variables_in("&ARGS:/re/")
            .expect("test variable expression is valid")
            .iter()
            .flat_map(|spec| spec.get_matches(Some(CollectionView::Map(&args))))
            .map(|matched| matched.key)
            .collect::<Vec<_>>();
        // Argument selectors keep their written case, so `KeyStr` is `/re/`.
        assert_eq!(counted, ["/re/"]);
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
    fn multiphase_variable_list_splits_count_regex_and_negation() {
        let list = VariableList::parse("&ARGS:/^user/|!ARGS:blocked").expect("test variable list is valid");
        let mut variables = Vec::new();
        list.apply_to(&mut variables, true);

        assert_eq!(variables.len(), 2);
        for (spec, variable) in variables.iter().zip([RuleVariable::ArgsGet, RuleVariable::ArgsPost]) {
            assert_eq!(spec.variable(), variable);
            let mut map = Map::new_case_sensitive(variable);
            map.add("user1", b"one");
            map.add("blocked", b"two");
            let matches = spec.get_matches(Some(CollectionView::Map(&map)));
            assert_eq!(matches.first().map(|matched| matched.value.as_slice()), Some(&b"1"[..]));
            assert_eq!(matches.first().map(|matched| matched.key.as_str()), Some("/^user/"));
        }
    }

    #[test]
    fn args_negation_excludes_cross_family_names_variants() {
        let list = VariableList::parse("ARGS_GET_NAMES|!ARGS:foo").expect("test variable list is valid");
        let mut variables = Vec::new();
        list.apply_to(&mut variables, true);

        let spec = variables.first().expect("name variable is present");
        assert_eq!(spec.variable(), RuleVariable::ArgsGetNames);
        let mut get_args = Map::new(RuleVariable::ArgsGet);
        get_args.add("foo", b"bar");
        assert!(
            spec.get_matches(Some(CollectionView::Names(RuleVariable::ArgsGetNames, &get_args)))
                .is_empty()
        );
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
    fn response_xml_selectors_keep_the_generic_key_parser() {
        let mut xml = Map::new(RuleVariable::ResponseXML);
        xml.add("a|b", b"regex");
        xml.add("aa", b"literal");

        // `RESPONSE_XML` is never populated (`internal/variables/variables.go:592`, "Not
        // Implemented yet"), so it keeps the generic parser. A regex with an escaped pipe
        // stays intact instead of being cut into a path plus a stray variable name.
        assert_eq!(
            matches("RESPONSE_XML:/a\\|b/", RuleVariable::ResponseXML, &xml),
            ["regex"]
        );
        // A quoted key keeps its literal text, quotes stripped.
        assert_eq!(
            matches("RESPONSE_XML:'aa'", RuleVariable::ResponseXML, &xml),
            ["literal"]
        );
        // `/*` is therefore not a path for this variable; the generic parser rejects it.
        assert!(parse_variables("RESPONSE_XML:/*").is_err());
    }

    #[test]
    fn request_xml_selector_selects_the_root_children() {
        let mut xml = Map::new(RuleVariable::RequestXML);
        xml.add("/*", b"superuser & guest");
        xml.add("//@*", b"admin");

        // Go marks REQUEST_XML selectable (`internal/variables/variables.go:594`), so the
        // selector compiles, and the name is case-insensitive.
        for selector in ["REQUEST_XML:/*", "request_xml:/*", "Request_Xml:/*"] {
            assert_eq!(parse_variables_in(selector).map(|variables| variables.len()), Ok(1));
            assert_eq!(matches(selector, RuleVariable::RequestXML, &xml), ["superuser & guest"]);
        }

        // Selectability does not depend on the key mode, but single-value collections stay
        // unselectable.
        assert!(parse_variables("REQUEST_XML:foo").is_ok());
        assert!(parse_variables_in("REQUEST_URI:foo").is_err());
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
