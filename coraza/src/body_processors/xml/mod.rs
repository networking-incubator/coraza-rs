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

//! XML body parsing with the behavior of Go Coraza's XML body processor, but for what it refuses that Go reads: a
//! reference to an entity the document declares, a DOCTYPE with more than its name and comments, any other
//! directive, a character XML does not allow in a comment or instruction, a body that ends in a token unless a body
//! limit cut it there, and values past the argument limit.

mod decoder;
mod tables;

use decoder::{Decoder, Token};

use crate::{
    body_processors::budget::{MemoryBudget, insert_growth},
    collection::{Growth, Map},
};

/// Bytes charged to a host's memory budget for each value beyond its text when the values go to a plain list, as in
/// the tests below: the entry, with the growth slack of the vector that holds it, and the allocation overhead of
/// the text. The collection charges from the shape of its own lists instead, see [`CollectionSink`].
///
/// Without a host budget only the argument limit bounds the output. Go Coraza has no bound: each value is one more
/// evaluation of every rule that reads XML, so a body of bare attributes would cost each such rule one evaluation per
/// two bytes.
#[cfg(test)]
const VALUE_OVERHEAD_BYTES: usize = 128;

/// The budget charge for one value of `len` bytes that goes to a plain list.
#[cfg(test)]
pub(super) fn value_cost(len: usize) -> usize {
    VALUE_OVERHEAD_BYTES.saturating_add(len)
}

/// The `REQUEST_XML` key of attribute values.
const ATTRIBUTE_KEY: &[u8] = b"//@*";

/// The `REQUEST_XML` key of text.
const TEXT_KEY: &[u8] = b"/*";

/// Where the parser puts the values it reads, in document order.
trait Sink {
    /// What an attribute value of `len` bytes costs once it is stored, and while it is.
    fn attribute_cost(&mut self, len: usize) -> Growth;

    /// What a text segment of `len` bytes costs, as for [`Sink::attribute_cost`].
    fn text_cost(&mut self, len: usize) -> Growth;

    /// An attribute value.
    fn attribute(&mut self, value: String);

    /// A non-empty text segment, trimmed.
    fn text(&mut self, value: String);

    /// Takes back the last `count` attribute values, which belonged to a start tag the input, the budget or the limit
    /// ended in.
    fn discard_attributes(&mut self, count: usize);

    /// The values it holds, those it held before the parse included, which the argument limit bounds.
    fn value_count(&self) -> usize;
}

/// Publishes values straight into `REQUEST_XML`, so the document is never held beside its collection.
struct CollectionSink<'a> {
    /// The collection.
    map: &'a mut Map,
    /// Values `//@*` held before the parse, which a failed parse restores.
    attributes_before: usize,
    /// Values `/*` held before the parse.
    text_before: usize,
    /// Attribute values this parse added.
    attributes_added: usize,
}

impl<'a> CollectionSink<'a> {
    /// Publish into `map`.
    fn new(map: &'a mut Map) -> Self {
        Self {
            attributes_before: map.values(ATTRIBUTE_KEY).count(),
            text_before: map.values(TEXT_KEY).count(),
            attributes_added: 0,
            map,
        }
    }

    /// The parse ended and its values stay. Attribute values have always come before the text in the
    /// collection's key order, whichever the document reached first.
    fn finish(self) {
        self.map.order_before(ATTRIBUTE_KEY, TEXT_KEY);
    }

    /// The parse failed, and Go keeps nothing of a document it cannot read: take its values back.
    fn rollback(self) {
        self.map.truncate_values(ATTRIBUTE_KEY, self.attributes_before);
        self.map.truncate_values(TEXT_KEY, self.text_before);
    }
}

impl Sink for CollectionSink<'_> {
    fn attribute_cost(&mut self, len: usize) -> Growth {
        insert_growth(&[&*self.map], ATTRIBUTE_KEY, len)
    }

    fn text_cost(&mut self, len: usize) -> Growth {
        insert_growth(&[&*self.map], TEXT_KEY, len)
    }

    fn attribute(&mut self, value: String) {
        self.map.add_owned(ATTRIBUTE_KEY, value.into_bytes());
        self.attributes_added = self.attributes_added.saturating_add(1);
    }

    fn text(&mut self, value: String) {
        self.map.add_owned(TEXT_KEY, value.into_bytes());
    }

    fn discard_attributes(&mut self, count: usize) {
        self.attributes_added = self.attributes_added.saturating_sub(count);
        self.map.truncate_values(
            ATTRIBUTE_KEY,
            self.attributes_before.saturating_add(self.attributes_added),
        );
    }

    fn value_count(&self) -> usize {
        self.map.value_count()
    }
}

/// `text` without the whitespace around it, in the buffer it came in.
fn trimmed(mut text: String) -> String {
    text.truncate(text.trim_end().len());
    let leading = text.len().saturating_sub(text.trim_start().len());
    if leading > 0 {
        text.drain(..leading);
    }
    text
}

/// Why a parse ended before the document did. The values read before that point stay in the collection.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// The host's memory budget ran out; the message names its size.
    MemoryBudget(String),
    /// The collection held as many values as the argument limit allows and the document had more; the message
    /// names the limit.
    ArgumentLimit(String),
}

/// Parse a request body into `REQUEST_XML`, accepting a document that ends in an element as partial input, as Go
/// does, and one that ends in a token only when `truncated`, a body limit having cut the rest of it.
///
/// Values go into `collection` as they are read, charged to the host's `memory` budget before each is allocated,
/// until the collection holds `limit` values. A document that outgrows the budget or has more values keeps the
/// values before that point, and the [`Stop`] returned says which ended it. A document the decoder rejects leaves
/// the collection as it found it, and returns the decoder's message.
///
/// # Errors
///
/// The syntax error that made Go reject the document, or what this parser refuses beyond it (see the module docs).
pub(crate) fn parse_into(
    body: &[u8],
    memory: MemoryBudget,
    limit: usize,
    truncated: bool,
    collection: &mut Map,
) -> Result<Option<Stop>, String> {
    let mut sink = CollectionSink::new(collection);
    match read(body, memory, limit, truncated, &mut sink) {
        Ok(stop) => {
            sink.finish();
            Ok(stop)
        },
        Err(error) => {
            sink.rollback();
            Err(error.to_string())
        },
    }
}

/// Read as far as the decoder permits, to an input that ends in an element or, when `truncated`, in a token, where
/// Go Coraza accepts unexpected EOF anywhere. Returns why it stopped early, if the budget ran out or the sink holds
/// `limit` values.
fn read(
    xml: &[u8],
    memory: MemoryBudget,
    limit: usize,
    truncated: bool,
    sink: &mut impl Sink,
) -> Result<Option<Stop>, decoder::DecodeError> {
    let mut decoder = Decoder::new(xml, memory, limit, truncated);
    loop {
        match decoder.token(sink) {
            Ok(Some(Token::CharData(text))) => {
                let text = trimmed(text);
                if !text.is_empty() {
                    if let Err(error) = decoder.admit(sink.value_count()) {
                        return Ok(Some(Stop::ArgumentLimit(error.to_string())));
                    }
                    let cost = decoder.cost(&text, |len| sink.text_cost(len));
                    if let Err(error) = decoder.reserve(cost.grown) {
                        return Ok(Some(Stop::MemoryBudget(error.to_string())));
                    }
                    sink.text(text);
                    decoder.release(cost.freed);
                }
            },
            Ok(Some(Token::Start { .. } | Token::End(_) | Token::Other)) => {},
            Ok(None) => return Ok(None),
            // Between tokens, with elements open, the input ends as Go reads it. Within a token it is a syntax
            // error, as a backend's parser in recover mode keeps what the token had read, or reads on past what
            // this one skips. A body limit's cut (Go's `ProcessPartial`) ends a token the same way, and what the
            // token had read is published: the complete attributes of a start tag, the part of a quoted or an
            // unquoted value the cut reached, the text before a reference. A comment, an instruction and a
            // directive publish nothing, cut or whole, and neither does an attribute or element name the cut
            // ended in. Only what the cut left unread goes uninspected, as past any cut. Three cuts are errors
            // below, never reaching this arm: in a CDATA section and in a UTF-8 character of text or of a quoted
            // value, as in Go, and in a reference when the text it ends, the reference as written included, holds a
            // forbidden character or broken UTF-8, where Go accepts and drops the text and this engine fails closed.
            Err(decoder::DecodeError::UnexpectedEof { in_token, .. }) if truncated || !in_token => return Ok(None),
            Err(error @ decoder::DecodeError::MemoryBudget { .. }) => {
                // A start tag the budget ended in was never returned, so the attributes it had read are taken back.
                sink.discard_attributes(decoder.unfinished_attributes());
                return Ok(Some(Stop::MemoryBudget(error.to_string())));
            },
            Err(error @ decoder::DecodeError::ArgumentLimit { .. }) => {
                // And those of one the limit ended in.
                sink.discard_attributes(decoder.unfinished_attributes());
                return Ok(Some(Stop::ArgumentLimit(error.to_string())));
            },
            Err(error) => return Err(error),
        }
    }
}

/// XML attributes and text as the tests below compare them.
#[cfg(test)]
#[derive(Debug, Default)]
struct Document {
    /// Attribute values in document order.
    attribute_values: Vec<String>,
    /// Non-empty text segments, trimmed and in document order.
    text: Vec<String>,
    /// Set when parsing stopped because the budget ran out; the values before that point are kept.
    budget_error: Option<Stop>,
}

#[cfg(test)]
impl Sink for Document {
    fn attribute_cost(&mut self, len: usize) -> Growth {
        Growth {
            grown: value_cost(len),
            freed: 0,
        }
    }

    fn text_cost(&mut self, len: usize) -> Growth {
        self.attribute_cost(len)
    }

    fn attribute(&mut self, value: String) {
        self.attribute_values.push(value);
    }

    fn text(&mut self, value: String) {
        self.text.push(value);
    }

    fn discard_attributes(&mut self, count: usize) {
        let keep = self.attribute_values.len().saturating_sub(count);
        self.attribute_values.truncate(keep);
    }

    fn value_count(&self) -> usize {
        self.attribute_values.len().saturating_add(self.text.len())
    }
}

#[cfg(test)]
impl Document {
    /// Parse under `memory`, the host's budget, and no argument limit: the collection's own tests cover that.
    fn read(xml: &[u8], memory: MemoryBudget) -> Result<Self, decoder::DecodeError> {
        let mut document = Self::default();
        document.budget_error = read(xml, memory, usize::MAX, false, &mut document)?;
        Ok(document)
    }
}

/// Parse a body as the transaction does by default, without a host budget.
#[cfg(test)]
fn parse(body: &[u8]) -> Result<Document, String> {
    Document::read(body, MemoryBudget::default()).map_err(|error| error.to_string())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "XML budget tests use fixed documents")]
mod tests {
    use super::{Document, MemoryBudget, Stop, parse, parse_into, read, value_cost};
    use crate::{collection::Map, config::DEFAULT_ARGUMENT_LIMIT as LIMIT, types::RuleVariable};

    /// A document with one attribute value and two text values, `a`, `b` and `c`.
    const THREE_VALUES: &[u8] = b"<r x=\"a\"><i>b</i><i>c</i></r>";

    /// Parses `body` into a fresh collection under the default argument limit: what that returns, and the values
    /// the collection then holds.
    fn parse_counted(body: &[u8]) -> (Result<Option<Stop>, String>, usize) {
        let mut map = collection();
        let stop = parse_into(body, MemoryBudget::default(), LIMIT, false, &mut map);
        (stop, map.value_count())
    }

    /// The stop at the default argument limit.
    fn limit_stop() -> Stop {
        Stop::ArgumentLimit(format!("parsed XML exceeds the {LIMIT} value argument limit"))
    }

    #[test]
    fn valid_documents_are_refused_at_the_argument_limit_and_not_before() {
        // Sixteen copies of `<a b="c">d</a>` is 224 bytes and 32 values: a limit proportional to the body, with a
        // floor of a few kilobytes, once stopped it after 31. Only the number of values stops one now.
        for copies in [1, 15, 16, 17, 31, 32, 33, 100, 500, 501, 1000, 50_000] {
            let body = format!("<r>{}</r>", "<a b=\"c\">d</a>".repeat(copies));
            let expected = if 2 * copies <= LIMIT { None } else { Some(limit_stop()) };
            assert_eq!(
                parse_counted(body.as_bytes()),
                (Ok(expected), (2 * copies).min(LIMIT)),
                "{copies} copies"
            );
        }
        // The same shapes the other way round, and the densest list, at every size around the old floor. A tag
        // the limit stops in keeps none of its attributes.
        for count in (1..200).chain([4096, 100_000]) {
            for (unit, values) in [
                ("<i>1</i>", 1),
                ("<a b c d e f g h/>", 7),
                ("<a b=\"c\"/>", 1),
                ("<a b=\"c\">d</a>", 2),
            ] {
                let body = format!("<r>{}</r>", unit.repeat(count));
                let (stop, published) = parse_counted(body.as_bytes());
                if count * values <= LIMIT {
                    assert_eq!((stop, published), (Ok(None), count * values), "{count} of {unit}");
                } else {
                    assert_eq!(stop, Ok(Some(limit_stop())), "{count} of {unit}");
                    assert_eq!(published, LIMIT / values * values, "{count} of {unit}");
                }
            }
        }
        // And the bare-attribute flood in one tag, the densest of all, which keeps nothing.
        let mut body = b"<r".to_vec();
        body.extend(std::iter::repeat_n(*b" b", 100_000).flatten());
        body.extend_from_slice(b"></r>");
        assert_eq!(parse_counted(&body), (Ok(Some(limit_stop())), 0));
    }

    #[test]
    fn the_argument_limit_counts_attributes_text_and_what_was_there_before() {
        // A thousand values pass, and the next stops the parse with the thousand before it kept.
        let exactly = "<i>1</i>".repeat(LIMIT);
        assert_eq!(parse_counted(format!("<r>{exactly}</r>").as_bytes()), (Ok(None), LIMIT));
        assert_eq!(
            parse_counted(format!("<r>{exactly}<i>2</i></r>").as_bytes()),
            (Ok(Some(limit_stop())), LIMIT)
        );
        // Attributes and text count together.
        let mixed = "<i a=\"1\">2</i>".repeat(LIMIT / 2);
        assert_eq!(parse_counted(format!("<r>{mixed}</r>").as_bytes()), (Ok(None), LIMIT));
        for extra in ["<i>3</i>", "<i a=\"3\"/>"] {
            let mut map = collection();
            let body = format!("<r>{mixed}{extra}</r>");
            let stop = parse_into(body.as_bytes(), MemoryBudget::default(), LIMIT, false, &mut map);
            assert_eq!(stop, Ok(Some(limit_stop())), "{extra}");
            assert!(map.iter().all(|(_, value)| value != b"3"), "{extra}");
            assert_eq!(map.value_count(), LIMIT, "{extra}");
        }
        // The attributes of the start tag the limit ended in are taken back, as a budget stop takes them back.
        let tag = format!("<r>{}<b x=\"x\" y=\"y\" z=\"z\"/></r>", "<i>1</i>".repeat(LIMIT - 2));
        let mut map = collection();
        assert_eq!(
            parse_into(tag.as_bytes(), MemoryBudget::default(), LIMIT, false, &mut map),
            Ok(Some(limit_stop()))
        );
        assert_eq!(map.value_count(), LIMIT - 2);
        assert!(map.iter().all(|(key, _)| key == "/*"));
        // Values the collection held before the parse count, and stay.
        let mut map = collection();
        map.add("/*", "earlier");
        assert_eq!(
            parse_into(
                format!("<r>{exactly}</r>").as_bytes(),
                MemoryBudget::default(),
                LIMIT,
                false,
                &mut map
            ),
            Ok(Some(limit_stop()))
        );
        assert_eq!(map.value_count(), LIMIT);
        assert_eq!(map.iter().next().map(|(_, value)| value), Some(&b"earlier"[..]));
        // A limit of one admits one value.
        let mut map = collection();
        let stop = parse_into(b"<r a=\"1\">2</r>", MemoryBudget::default(), 1, false, &mut map);
        assert_eq!(
            stop,
            Ok(Some(Stop::ArgumentLimit(
                "parsed XML exceeds the 1 value argument limit".to_owned()
            )))
        );
        assert_eq!(entries(&map), [("//@*".to_owned(), "1".to_owned())]);
    }

    #[test]
    fn a_limit_stop_inside_a_start_tag_can_leave_the_collection_below_the_limit() {
        // The values committed before the tag stay, and the tag the limit interrupts hands none of its attributes on,
        // the ones that fit the limit included: at a limit of two, a text value and a tag of two attributes leave one
        // value, not two.
        for (body, kept, stop) in [
            ("<r>x<b a=\"1\" b=\"2\"/></r>", &["x"][..], true),
            ("<r>x<b a=\"1\" b=\"2\"></b></r>", &["x"], true),
            ("<r a=\"1\" b=\"2\" c=\"3\"/>", &[], true),
            ("<r><i>x</i><i>y</i><b a=\"1\"/></r>", &["x", "y"], true),
            // A tag that fits is kept whole, and text after one that filled the limit is what stops.
            ("<r>x<b a=\"1\"/></r>", &["1", "x"], false),
            ("<r>x<b a=\"1\"/>y</r>", &["1", "x"], true),
        ] {
            let mut map = collection();
            let result = parse_into(body.as_bytes(), MemoryBudget::default(), 2, false, &mut map);
            let expected =
                stop.then(|| Stop::ArgumentLimit("parsed XML exceeds the 2 value argument limit".to_owned()));
            assert_eq!(result, Ok(expected), "{body}");
            let mut values: Vec<_> = entries(&map).into_iter().map(|(_, value)| value).collect();
            values.sort();
            assert_eq!(values, kept, "{body}");
        }
    }

    #[test]
    fn the_host_budget_is_charged_per_value_and_accepts_exactly_what_it_needs() {
        let needed = (1..4096_usize)
            .find(|&budget| {
                Document::read(THREE_VALUES, MemoryBudget::new(Some(budget)))
                    .unwrap()
                    .budget_error
                    .is_none()
            })
            .unwrap();
        assert!(needed >= 3 * value_cost(1), "three values at least: {needed}");
        let document = Document::read(THREE_VALUES, MemoryBudget::new(Some(needed))).unwrap();
        assert_eq!(document.attribute_values, ["a"]);
        assert_eq!(document.text, ["b", "c"]);
        let one_less = Document::read(THREE_VALUES, MemoryBudget::new(Some(needed - 1))).unwrap();
        assert_eq!(
            one_less.budget_error,
            Some(Stop::MemoryBudget(format!(
                "parsed XML exceeds the {} byte body memory budget",
                needed - 1
            )))
        );
    }

    /// A fresh `REQUEST_XML`.
    fn collection() -> Map {
        Map::new_case_sensitive(RuleVariable::RequestXML)
    }

    /// The keys and values of `map` as text, in order.
    fn entries(map: &Map) -> Vec<(String, String)> {
        map.iter()
            .map(|(key, value)| (key.to_owned(), String::from_utf8_lossy(value).into_owned()))
            .collect()
    }

    #[test]
    fn values_go_straight_into_the_collection_with_the_attributes_listed_first() {
        let mut map = collection();
        // Text comes before the first attribute, yet the attribute key has always been first.
        let message = parse_into(
            b"<r>head<i x=\"a\">b</i><i y=\"c\"/>tail</r>",
            MemoryBudget::default(),
            LIMIT,
            false,
            &mut map,
        );
        assert_eq!(message, Ok(None));
        assert_eq!(
            entries(&map),
            [
                ("//@*".to_owned(), "a".to_owned()),
                ("//@*".to_owned(), "c".to_owned()),
                ("/*".to_owned(), "head".to_owned()),
                ("/*".to_owned(), "b".to_owned()),
                ("/*".to_owned(), "tail".to_owned()),
            ]
        );
        assert_eq!(map.value_count(), 5);
    }

    #[test]
    fn the_collection_holds_what_the_document_gives_for_every_budget_that_covers_it() {
        let body = b"<r a=\"1\"><i b=\"2\">x</i> y </r>";
        let mut expected = collection();
        assert_eq!(
            parse_into(body, MemoryBudget::default(), LIMIT, false, &mut expected),
            Ok(None)
        );
        let document = parse(body).unwrap();
        assert_eq!(document.attribute_values, ["1", "2"]);
        assert_eq!(document.text, ["x", "y"]);
        for budget in [1_000_000_usize, usize::MAX] {
            let mut map = collection();
            assert_eq!(
                parse_into(body, MemoryBudget::new(Some(budget)), LIMIT, false, &mut map),
                Ok(None)
            );
            assert_eq!(entries(&map), entries(&expected), "budget {budget}");
        }
    }

    #[test]
    fn a_syntax_error_takes_back_the_values_it_published_and_keeps_what_was_there() {
        let mut map = collection();
        map.add("/*", "earlier");
        map.add("other", "kept");
        let before = entries(&map);
        let message = parse_into(
            b"<r a=\"1\"><i b=\"2\">x</i></y></x>",
            MemoryBudget::default(),
            LIMIT,
            false,
            &mut map,
        );
        assert!(message.unwrap_err().starts_with("XML syntax error on line 1"));
        assert_eq!(entries(&map), before, "the collection is as it was found");
        assert_eq!(map.value_count(), 2);

        let mut fresh = collection();
        assert!(parse_into(b"<r a=\"1\">x</y>", MemoryBudget::default(), LIMIT, false, &mut fresh).is_err());
        assert!(fresh.is_empty(), "keys it created are gone too");
        assert_eq!(fresh.value_count(), 0);
    }

    #[test]
    fn a_truncated_document_keeps_its_values() {
        let mut map = collection();
        assert_eq!(
            parse_into(b"<r a=\"1\"><i>x", MemoryBudget::default(), LIMIT, false, &mut map),
            Ok(None)
        );
        assert_eq!(entries(&map).len(), 2);
    }

    #[test]
    fn the_host_budget_stops_the_parse_with_the_values_before_it_and_names_its_size() {
        let body = format!("<r>{}</r>", "<i>12345678</i>".repeat(1000));
        let mut map = collection();
        let message = parse_into(body.as_bytes(), MemoryBudget::new(Some(20_000)), LIMIT, false, &mut map).unwrap();
        assert_eq!(
            message,
            Some(Stop::MemoryBudget(
                "parsed XML exceeds the 20000 byte body memory budget".to_owned()
            ))
        );
        let kept = map.value_count();
        assert!(0 < kept && kept < 1000, "a prefix: {kept}");
        assert!(map.iter().all(|(key, value)| key == "/*" && value == b"12345678"));

        // A budget that covers the document admits it, and one too small for its first value refuses it.
        let mut map = collection();
        let message = parse_into(
            b"<r a=\"1\" b=\"2\" c=\"3\">x</r>",
            MemoryBudget::new(Some(1_000_000)),
            LIMIT,
            false,
            &mut map,
        );
        assert_eq!(message, Ok(None));
        let tiny = MemoryBudget::new(Some(100));
        let mut map = collection();
        assert!(
            parse_into(b"<r a=\"1\" b=\"2\" c=\"3\">x</r>", tiny, LIMIT, false, &mut map)
                .unwrap()
                .is_some()
        );
        assert_eq!(map.value_count(), 0, "not even the first value fits a hundred bytes");
    }

    #[test]
    fn scratch_is_given_back_when_its_token_ends() {
        // Whitespace, comments and instructions between the values hold nothing once read, so a budget for the
        // values and a little scratch must be enough however many of them there are.
        let filler = "  <!-- comment --> <?pi data?> \n".repeat(2000);
        let body = format!("<r>{filler}<i>x</i>{filler}</r>");
        let budget = MemoryBudget::new(Some(value_cost(1) + 4096));
        let document = Document::read(body.as_bytes(), budget).unwrap();
        assert_eq!(document.budget_error, None);
        assert_eq!(document.text, ["x"]);
    }

    #[test]
    fn one_huge_token_is_refused_before_it_is_read_and_siblings_reuse_the_nesting_they_charged() {
        let budget = MemoryBudget::new(Some(100_000));
        for body in [
            format!("<r>{}</r>", "x".repeat(1_000_000)),
            format!("<r a=\"{}\"/>", "x".repeat(1_000_000)),
            format!("<{}/>", "x".repeat(1_000_000)),
            format!("<?xml version=\"1.0\" {}?><r/>", "x".repeat(1_000_000)),
            format!("<r a={}/>", "x".repeat(1_000_000)),
            format!("<r>{}</r>", "&amp;".repeat(200_000)),
        ] {
            let document = Document::read(body.as_bytes(), budget).unwrap();
            assert!(document.budget_error.is_some(), "{:?}", body.get(..30));
            assert!(document.text.is_empty() && document.attribute_values.is_empty());
        }

        // Siblings at the same depth hold the stack once.
        let siblings = format!("<r>{}</r>", "<a/>".repeat(50_000));
        assert_eq!(Document::read(siblings.as_bytes(), budget).unwrap().budget_error, None);
        // Nesting holds it per level.
        let nested = format!("<r>{}</r>", "<a>".repeat(50_000));
        assert!(
            Document::read(nested.as_bytes(), budget)
                .unwrap()
                .budget_error
                .is_some()
        );
    }

    #[test]
    fn a_body_limit_cut_in_a_start_tag_keeps_the_attributes_it_had_read() {
        // Where a body limit cut the body inside a start tag, what the tag had read is published, the complete
        // attributes and the part of a value the cut ended in, quoted or not: the backend gets the whole body, and
        // a lenient parser keeps them too. Nothing past the cut is inspected. A bare attribute name is not kept,
        // since no libxml2 version tried hands one to its application, in a root tag or a nested one.
        for (body, attributes, text) in [
            (&b"<r a=\"x\""[..], &["x"][..], &[][..]),
            (b"<r a=\"x\" ", &["x"], &[]),
            (b"<r a=\"x\" b=", &["x"], &[]),
            (b"<r a=\"x\" b=\"", &["x", ""], &[]),
            (b"<r a=\"x\" b=\"y", &["x", "y"], &[]),
            (b"<r a=\"x\" b=\"y\"", &["x", "y"], &[]),
            (b"<r a=\"x\" b", &["x"], &[]),
            (b"<r a=x", &["x"], &[]),
            (b"<r a=PWNED/", &["PWNED"], &[]),
            // An unquoted value is kept wherever its tag is: libxml2 in recover mode reads it, and what follows up
            // to the next `<`, as the parent's text, though only for a tag that has a parent.
            (b"<p><r a=PWNED", &["PWNED"], &[]),
            (b"<p><r a=PW", &["PW"], &[]),
            (b"<p><r x=\"1\" a=PWNED", &["1", "PWNED"], &[]),
            (b"<a><b><c><r a=PWNED", &["PWNED"], &[]),
            (b"<p>t<r a=PWNED", &["PWNED"], &["t"]),
            (b"<p><r a=PWNED/", &["PWNED"], &[]),
            // A bare attribute name is not kept, whatever its tag: no libxml2 version hands it on.
            (b"<r a", &[], &[]),
            (b"<p><r PWNED", &[], &[]),
            (b"<p><r x=\"1\" PWNED", &["1"], &[]),
            (b"<r a=\"x\"/", &["x"], &[]),
            (b"<r a=\"x", &["x"], &[]),
            (b"<r a=\"x &am", &["x &am"], &[]),
            (b"<r a='x &#x4", &["x &#x4"], &[]),
            (b"<r a=\"x &amp; y &", &["x & y &"], &[]),
            (b"<r a=\"x\">", &["x"], &[]),
            (b"<r a=\"x\">tex", &["x"], &["tex"]),
            (b"<a b=\"1\"><c d=\"2\"", &["1", "2"], &[]),
            (b"<a b=\"1\"><c d=\"2\" e=\"3\"/><f g=\"4\"", &["1", "2", "3", "4"], &[]),
            (b"<a b=\"1\"><c d=\"2\" e=\"3\"/><f g=\"4", &["1", "2", "3", "4"], &[]),
        ] {
            let mut document = Document::default();
            assert_eq!(
                read(body, MemoryBudget::default(), usize::MAX, true, &mut document).unwrap(),
                None
            );
            assert_eq!(
                document.attribute_values,
                attributes,
                "{}",
                String::from_utf8_lossy(body)
            );
            assert_eq!(document.text, text, "{}", String::from_utf8_lossy(body));
            // The same through the collection.
            let mut map = collection();
            assert_eq!(
                parse_into(body, MemoryBudget::default(), LIMIT, true, &mut map),
                Ok(None)
            );
            let published: Vec<_> = entries(&map)
                .into_iter()
                .filter(|(key, _)| key == "//@*")
                .map(|(_, value)| value)
                .collect();
            assert_eq!(published, attributes, "{}", String::from_utf8_lossy(body));
            assert_eq!(map.value_count(), attributes.len() + text.len());
        }
        // The same bodies with nothing cut are errors, and the collection is as it was found.
        for body in [
            &b"<r a=\"x\""[..],
            b"<r a=\"x",
            b"<r a=\"x &am",
            b"<a b=\"1\"><c d=\"2\"",
            b"<r a=x",
            b"<p><r a=PWNED",
        ] {
            let mut map = collection();
            assert_eq!(
                parse_into(body, MemoryBudget::default(), LIMIT, false, &mut map),
                Err("XML syntax error on line 1: unexpected EOF".to_owned()),
                "{}",
                String::from_utf8_lossy(body)
            );
            assert_eq!(map.value_count(), 0);
        }
        // Values the collection held before stay, and the tag's follow them.
        let mut map = collection();
        map.add_owned(b"//@*", b"before".to_vec());
        assert_eq!(
            parse_into(b"<r a=\"x\"", MemoryBudget::default(), LIMIT, true, &mut map),
            Ok(None)
        );
        assert_eq!(
            entries(&map),
            [
                ("//@*".to_owned(), "before".to_owned()),
                ("//@*".to_owned(), "x".to_owned())
            ]
        );
    }

    #[test]
    fn a_body_limit_cut_in_a_reference_keeps_the_text_before_it() {
        // The text a reference the cut ended in belongs to is published up to the cut, the reference as written.
        for (body, text) in [
            (&b"<r>x &am"[..], "x &am"),
            (b"<r>x &", "x &"),
            (b"<r>x &#", "x &#"),
            (b"<r>x &#x", "x &#x"),
            (b"<r>x &#x4", "x &#x4"),
            (b"<r>x &#12", "x &#12"),
            (b"<r>x &zz", "x &zz"),
            (b"<r>x &amp; y &am", "x & y &am"),
            (b"<r>x<i/>y &lt", "y &lt"),
            (b"<r><![CDATA[c]]>x &am", "x &am"),
        ] {
            let mut document = Document::default();
            assert_eq!(
                read(body, MemoryBudget::default(), usize::MAX, true, &mut document).unwrap(),
                None
            );
            assert_eq!(
                document.text.last().map(String::as_str),
                Some(text),
                "{}",
                String::from_utf8_lossy(body)
            );
            // Without a cut the document ends in the reference, which is an error.
            assert_eq!(
                parse(body).unwrap_err(),
                "XML syntax error on line 1: unexpected EOF",
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn a_body_limit_cut_in_cdata_or_in_a_utf8_character_of_text_or_a_value_is_an_error_as_in_go() {
        // Go's decoder fails on all of them, and its Coraza accepts only a plain `unexpected EOF`, so a cut there is
        // a 400. A cut anywhere in a CDATA section is one, and so is a cut in a character of any width.
        for (body, message) in [
            (&b"<r><![CDATA["[..], "unexpected EOF in CDATA section"),
            (b"<r><![CDATA[x", "unexpected EOF in CDATA section"),
            (b"<r><![CDATA[x]]", "unexpected EOF in CDATA section"),
            (b"<r>x \xc3", "invalid UTF-8"),
            (b"<r>x \xe2", "invalid UTF-8"),
            (b"<r>x \xe2\x82", "invalid UTF-8"),
            (b"<r>x \xf0\x9f\x98", "invalid UTF-8"),
            (b"<r a=\"x \xc3", "invalid UTF-8"),
            (b"<r a='x \xe2\x82", "invalid UTF-8"),
        ] {
            let mut map = collection();
            assert_eq!(
                parse_into(body, MemoryBudget::default(), LIMIT, true, &mut map),
                Err(format!("XML syntax error on line 1: {message}")),
                "{}",
                String::from_utf8_lossy(body)
            );
            assert_eq!(map.value_count(), 0, "{}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn a_body_limit_cut_in_a_utf8_character_of_a_reference_name_is_refused_where_go_accepts_it() {
        // A deliberate deviation. Go's decoder reads the name of a reference with `readName`, which fails with
        // `unexpected EOF` at the end of the input, and Go's Coraza accepts that message and drops the text. Here the
        // incomplete character is `invalid UTF-8`, a 400, whatever the text before it held: stricter than Go, and
        // it fails closed.
        for body in [
            &b"<r>x &\xc3"[..],
            b"<r>PWNED &a\xc3",
            b"<r>PWNED &amp; &\xe2\x82",
            b"<r>x &\xf0\x9f\x98",
            b"<r>x &\xff\xff",
            b"<r a=\"x &\xc3",
            b"<r a=\"PWNED &a\xe2\x82",
        ] {
            let mut map = collection();
            assert_eq!(
                parse_into(body, MemoryBudget::default(), LIMIT, true, &mut map),
                Err("XML syntax error on line 1: invalid UTF-8".to_owned()),
                "{}",
                String::from_utf8_lossy(body)
            );
            assert_eq!(map.value_count(), 0, "{}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn a_body_limit_cut_in_a_reference_after_text_xml_does_not_allow_is_refused_for_the_text() {
        // A cut inside a reference is refused when the text it ends, the reference as written included, holds a
        // forbidden character or broken UTF-8, which Go's `unexpected EOF` for the reference hides: the text before
        // the reference, or a name holding U+FFFE or U+FFFF, the only name characters XML forbids.
        for (body, message) in [
            (&b"<r>x\0 &am"[..], "illegal character code U+0000"),
            (b"<r>x\x01 &", "illegal character code U+0001"),
            (b"<r>x &#3; &am", "illegal character code U+0003"),
            (b"<r a=\"x\x01 &am", "illegal character code U+0001"),
            (b"<r>x \xff &am", "invalid UTF-8"),
            (b"<r>PWNEDxxxx&\xef\xbf\xbe", "illegal character code U+FFFE"),
            (b"<r a=\"PWNEDxx&\xef\xbf\xbf", "illegal character code U+FFFF"),
        ] {
            let mut map = collection();
            assert_eq!(
                parse_into(body, MemoryBudget::default(), LIMIT, true, &mut map),
                Err(format!("XML syntax error on line 1: {message}")),
                "{}",
                String::from_utf8_lossy(body)
            );
            assert_eq!(map.value_count(), 0, "{}", String::from_utf8_lossy(body));
            // Without the cut it is the reference that fails first, or a character of the text that does.
            assert!(parse(body).is_err(), "{}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn a_body_limit_cut_in_a_utf8_character_of_other_markup_is_accepted_and_publishes_nothing_of_it() {
        // Unlike the cuts above, one in a comment, an instruction, a DOCTYPE, an element name or an attribute name is
        // accepted like any other cut, as in Go, and the token publishes nothing: what was published before it stays.
        for body in [
            &b"<r a=\"x\"><!-- x \xc3"[..],
            b"<r a=\"x\"><?p x \xe2\x82",
            b"<!DOCTYPE \xc3",
            b"<!DOCTYPE r <!-- \xf0\x9f\x98",
            b"<r a=\"x\"><\xc3",
            b"<r a=\"x\"><i\xe2\x82",
            b"<r a=\"x\" \xc3",
            b"<r a=\"x\" b\xe2\x82",
            b"<r a=\"x\"></\xc3",
        ] {
            let mut map = collection();
            assert_eq!(
                parse_into(body, MemoryBudget::default(), LIMIT, true, &mut map),
                Ok(None),
                "{}",
                String::from_utf8_lossy(body)
            );
            let published: Vec<_> = entries(&map).into_iter().map(|(_, value)| value).collect();
            let expected: &[&str] = if body.starts_with(b"<r a=") { &["x"] } else { &[] };
            assert_eq!(published, expected, "{}", String::from_utf8_lossy(body));
        }
    }

    /// Documents the input ends in a token of: a start tag, a reference, a comment, an instruction, a directive, an
    /// end tag, markup that never says what it is, and a CDATA section.
    const ENDS_IN_A_TOKEN: [&[u8]; 20] = [
        b"<r a=\"x\"",
        b"<r a=\"x\" b",
        b"<r a=\"x",
        b"<r a='x &amp",
        b"<r>x</r><y",
        b"<r>x &amp",
        b"<r>x &",
        b"<r>x &#x4",
        b"<r>x &zz",
        b"<r>x<!-- <b>y</b>",
        b"<!-- <r>x</r>",
        b"<r>x<?p <b>y</b>",
        b"<?xml version=\"1.0\"",
        b"<!DOCTYPE r",
        b"<!DOCTYPE r <!-- <r>x</r>",
        b"<r>x</r",
        b"<r>x<",
        b"<r>x<!",
        b"<r>x<![CDA",
        b"<r>x<![CDATA[y",
    ];

    #[test]
    fn a_body_limit_cut_accepts_unexpected_eof_and_no_other_error_in_the_bytes_before_it() {
        // The cuts accepted above, in a comment, an instruction, a DOCTYPE, an element name or an attribute name,
        // are those where the unexpected EOF is the only error: a forbidden character, an invalid name or any other
        // syntax error before the cut refuses the body as it does the whole document.
        for (body, message) in [
            (&b"<r><!-- \0 x"[..], "illegal character code U+0000"),
            (b"<r><!-- \x01", "illegal character code U+0001"),
            (b"<r><!-- \xef\xbf\xbe x", "illegal character code U+FFFE"),
            (b"<r><!-- a -- b", "invalid sequence \"--\" not allowed in comments"),
            (b"<r><?p \0 x", "illegal character code U+0000"),
            (b"<!DOCTYPE a <!-- \0 x", "illegal character code U+0000"),
            (
                b"<!DOCTYPE a <!-- a -- b",
                "invalid sequence \"--\" not allowed in comments",
            ),
            (
                b"<!DOCTYPE a extra <!-- x",
                "DOCTYPE with more than its root name is not accepted",
            ),
            (
                b"<!DOCTYPE a SYSTEM \"x",
                "DOCTYPE with an external identifier is not accepted",
            ),
            // A word after the root name is refused where the cut ends it, with no delimiter after it: it is
            // already more than a root name, whatever it would have grown into.
            (
                b"<!DOCTYPE a extra",
                "DOCTYPE with more than its root name is not accepted",
            ),
            (b"<!DOCTYPE a e", "DOCTYPE with more than its root name is not accepted"),
            (b"<r>&p; <!-- x", "invalid character entity &p;"),
            (b"<r>\0<!-- x", "illegal character code U+0000"),
            (b"<r $ a", "expected attribute name in element"),
            (b"<r a=\"1\" $ b", "expected attribute name in element"),
            (b"<r><1abc/><!-- x", "invalid XML name: 1abc"),
        ] {
            let mut map = collection();
            assert_eq!(
                parse_into(body, MemoryBudget::default(), LIMIT, true, &mut map),
                Err(format!("XML syntax error on line 1: {message}")),
                "{}",
                String::from_utf8_lossy(body)
            );
            assert_eq!(map.value_count(), 0, "{}", String::from_utf8_lossy(body));
        }
        // The same cuts without such an error are accepted.
        for body in [
            &b"<r><!-- x"[..],
            b"<r><!-- x -",
            b"<r><!-- x --",
            b"<r><?p x",
            b"<!DOCTYPE a <!-- x",
            b"<!DOCTYPE a",
            b"<!DOCTYPE a ",
            // A cut inside the keyword or inside the root name, right after the root name and its blanks, and a
            // complete bare DOCTYPE, which is as well formed as the whole one.
            b"<!DOCTYPE",
            b"<!DOCTYPEa",
            b"<!DOCTYPE ro",
            b"<!DOCTYPE root \t",
            b"<!DOCTYPE \xc3\xa9",
            b"<!DOCTYPE a>",
            b"<!DOCTYPE a >",
            b"<!DOCTYPE a <!-- c -->",
            b"<r",
            b"<r a",
            // A name is checked once it is complete, so a cut inside an invalid one is accepted.
            b"<r><1a",
            b"<r a=\"1\" 1a",
        ] {
            let mut map = collection();
            assert_eq!(
                parse_into(body, MemoryBudget::default(), LIMIT, true, &mut map),
                Ok(None),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn a_body_limit_cut_in_a_directive_is_accepted_only_where_it_could_still_be_a_doctype() {
        for (body, message) in [
            // A stray character between the keyword and the root name is refused at once, as past the root name.
            (
                &b"<!DOCTYPE @"[..],
                "DOCTYPE with more than its root name is not accepted",
            ),
            (
                b"<!DOCTYPE <!-- c --> @r",
                "DOCTYPE with more than its root name is not accepted",
            ),
            (b"<!DOCTYPE /", "DOCTYPE with more than its root name is not accepted"),
            // A first word that no body limit could have made `DOCTYPE` of is refused where the cut ends it.
            (b"<!ELE", "directive other than a DOCTYPE is not accepted"),
            (b"<!ENTI", "directive other than a DOCTYPE is not accepted"),
            (b"<!A", "directive other than a DOCTYPE is not accepted"),
            (b"<!DOCTYPF", "directive other than a DOCTYPE is not accepted"),
            (b"<!doctypf", "directive other than a DOCTYPE is not accepted"),
            (b"<!DOCX", "directive other than a DOCTYPE is not accepted"),
            (b"<!\xc3\xa9", "directive other than a DOCTYPE is not accepted"),
            (b"<r>x<!ELE", "directive after the first element is not accepted"),
            (
                b"<!DOCTYPEa extra",
                "DOCTYPE with more than its root name is not accepted",
            ),
            (
                b"<!DOCTYPE a <!-- c -->extra",
                "DOCTYPE with more than its root name is not accepted",
            ),
            (
                b"<!DOCTYPE a \xc3\xa9",
                "DOCTYPE with more than its root name is not accepted",
            ),
            (
                b"<!DOCTYPE a SYSTEM",
                "DOCTYPE with an external identifier is not accepted",
            ),
        ] {
            let mut map = collection();
            assert_eq!(
                parse_into(body, MemoryBudget::default(), LIMIT, true, &mut map),
                Err(format!("XML syntax error on line 1: {message}")),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        for body in [
            &b"<!DOCTYPE:a"[..],
            b"<!DOCTYPEelement",
            b"<!DOCTYPE\xc3\xa9",
            // A cut inside the first word, which may still become `DOCTYPE`, in any case.
            b"<!D",
            b"<!DOC",
            b"<!doct",
            b"<!DoCtYp",
            b"<!DOCTYPE <!-- c --> ",
        ] {
            let mut map = collection();
            assert_eq!(
                parse_into(body, MemoryBudget::default(), LIMIT, true, &mut map),
                Ok(None),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn a_doctype_root_name_that_is_no_xml_name_is_an_error() {
        let message = "XML syntax error on line 1: DOCTYPE root name is not an XML name";
        for body in [
            // A digit, `-` or `.` starts no name, whatever delimiter ends the word, glued to the keyword or not.
            &b"<!DOCTYPE 1abc><r>x</r>"[..],
            b"<!DOCTYPE 1><r>x</r>",
            b"<!DOCTYPE -r><r>x</r>",
            b"<!DOCTYPE .r><r>x</r>",
            b"<!DOCTYPE 1abc ><r>x</r>",
            b"<!DOCTYPE 1abc<!-- c -->><r>x</r>",
            b"<!DOCTYPE <!-- c --> 1abc><r>x</r>",
            b"<!doctype 1abc><r>x</r>",
            b"<!DOCTYPE1abc><r>x</r>",
            b"<!DOCTYPE-r><r>x</r>",
            b"<!DOCTYPE.r><r>x</r>",
            // Invalid UTF-8, and a character that is no name character, past ASCII.
            b"<!DOCTYPE r\xff><r>x</r>",
            b"<!DOCTYPE \xff><r>x</r>",
            b"<!DOCTYPE \xc3><r>x</r>",
            b"<!DOCTYPE r\xc3 ><r>x</r>",
            b"<!DOCTYPE\xff><r>x</r>",
            b"<!DOCTYPE \xc3\x97><r>x</r>",
            b"<!DOCTYPE r\xc3\x97><r>x</r>",
            // The name is refused before whatever else the delimiter starts is read.
            b"<!DOCTYPE 1abc [<r>x</r>",
            b"<!DOCTYPE 1abc\"<r>x</r>",
        ] {
            assert_eq!(parse(body).unwrap_err(), message, "{}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn a_doctype_root_name_that_is_an_xml_name_is_accepted() {
        for body in [
            &b"<!DOCTYPE r1><r>x</r>"[..],
            b"<!DOCTYPE _r><r>x</r>",
            b"<!DOCTYPE :r><r>x</r>",
            b"<!DOCTYPE a:b><r>x</r>",
            b"<!DOCTYPE a-b.c1:d_e ><r>x</r>",
            b"<!DOCTYPE r-><r>x</r>",
            b"<!DOCTYPE r.><r>x</r>",
            b"<!DOCTYPE SYSTEM><r>x</r>",
            b"<!DOCTYPEr1><r>x</r>",
            b"<!DOCTYPE_r><r>x</r>",
            b"<!DOCTYPE:r><r>x</r>",
            b"<!DOCTYPE \xc3\xa9><r>x</r>",
            b"<!DOCTYPE \xc3\xa9\xce\xb1-1><r>x</r>",
            b"<!DOCTYPE \xe3\x81\x82\xe4\xb8\x80><r>x</r>",
            b"<!DOCTYPE r\xc2\xb7><r>x</r>",
            b"<!DOCTYPE\xc3\xa9><r>x</r>",
            b"<!DOCTYPE <!-- c --> \xce\xb1 <!-- c -->><r>x</r>",
        ] {
            let text = parse(body).map(|document| document.text);
            assert_eq!(text, Ok(vec!["x".to_owned()]), "{}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn a_body_limit_cut_in_a_doctype_root_name_is_accepted_until_a_delimiter_ends_it() {
        // The name is checked when it ends: a cut inside it may be one inside a character, or before the rest of a
        // name that would be one.
        for body in [
            &b"<!DOCTYPE 1ab"[..],
            b"<!DOCTYPE 1",
            b"<!DOCTYPE -",
            b"<!DOCTYPE r\xff",
            b"<!DOCTYPE \xc3",
            b"<!DOCTYPE r\xc3",
            b"<!DOCTYPE1ab",
            b"<!DOCTYPE\xff",
            b"<!DOCTYPE <!-- c --> 1ab",
        ] {
            let mut map = collection();
            assert_eq!(
                parse_into(body, MemoryBudget::default(), LIMIT, true, &mut map),
                Ok(None),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        for body in [
            &b"<!DOCTYPE 1ab "[..],
            b"<!DOCTYPE 1ab>",
            b"<!DOCTYPE 1ab<",
            b"<!DOCTYPE -r\t",
            b"<!DOCTYPE r\xff ",
            b"<!DOCTYPE \xc3\t",
            b"<!DOCTYPE1ab>",
            b"<!DOCTYPE\xff ",
            b"<!DOCTYPE <!-- c --> 1ab ",
        ] {
            let mut map = collection();
            assert_eq!(
                parse_into(body, MemoryBudget::default(), LIMIT, true, &mut map),
                Err("XML syntax error on line 1: DOCTYPE root name is not an XML name".to_owned()),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn a_document_the_input_ends_in_a_token_of_is_an_error() {
        // The token is lost with what it read, where a backend's parser in recover mode keeps the attributes of
        // the tag and the text before the reference, or reads past what this one skips.
        for body in ENDS_IN_A_TOKEN {
            let expected = if body.ends_with(b"[y") {
                "XML syntax error on line 1: unexpected EOF in CDATA section"
            } else {
                "XML syntax error on line 1: unexpected EOF"
            };
            assert_eq!(parse(body).unwrap_err(), expected, "{}", String::from_utf8_lossy(body));
        }
        // One it ends in an element of, between tokens, keeps what it read, as in Go. One a body limit cut in a token
        // is accepted too, with what the token had read (the tests above), but for a CDATA section, a UTF-8
        // character of text or of a value, and one of a reference name, which are errors.
        assert_eq!(parse(b"<r a=\"x\"><i>y").unwrap().text, ["y"]);
        for body in ENDS_IN_A_TOKEN {
            let mut map = collection();
            let cut = parse_into(body, MemoryBudget::default(), LIMIT, true, &mut map);
            assert_eq!(cut.is_ok(), !body.ends_with(b"[y"), "{}", String::from_utf8_lossy(body));
        }
        let payload = "1' UNION SELECT password FROM users-- -";
        for body in [
            format!("<r>{payload} &amp"),
            format!("<r a=\"{payload}\""),
            format!("<r><!-- --><i>{payload}</i><!-- "),
        ] {
            assert_eq!(verdict(&body), Some((200_002, 400)), "{body}");
        }
    }

    #[test]
    fn a_declaration_error_quotes_a_bounded_excerpt_under_a_budget_and_the_whole_value_without_one() {
        let long = "9".repeat(1_000_000);
        let declaration = |attribute: &str| format!("<?xml {attribute}=\"{long}\"?><r/>");
        for (attribute, wording) in [("version", "unsupported version"), ("encoding", "encoding")] {
            let body = declaration(attribute);
            let unbudgeted = parse(body.as_bytes()).unwrap_err();
            assert!(
                unbudgeted.len() > 1_000_000,
                "{attribute}: the full message without a budget"
            );
            assert!(unbudgeted.contains(wording));

            let budgeted = Document::read(body.as_bytes(), MemoryBudget::new(Some(2_000_000))).unwrap_err();
            let message = budgeted.to_string();
            assert!(message.contains(wording), "{message}");
            assert!(
                message.len() < 1_000,
                "{attribute}: a bounded excerpt, not {} bytes",
                message.len()
            );
        }
        // The message is reserved before it is built: the declaration takes what it needs (the target, then its
        // content up to the `?>`) and a hundred bytes more is not room for the message.
        let body = declaration("version");
        let content = body.len() - "<?xml ".len() - "<r/>".len();
        let tight = MemoryBudget::new(Some(35 + content + 32 + 100));
        assert!(Document::read(body.as_bytes(), tight).unwrap().budget_error.is_some());
        let roomy = MemoryBudget::new(Some(35 + content + 32 + 4_000));
        assert!(
            Document::read(body.as_bytes(), roomy).is_err(),
            "with room, the declaration is the error"
        );
    }

    #[test]
    fn an_element_name_stays_reserved_while_the_attributes_of_its_tag_are_read() {
        // A 1 MiB name, a short attribute, then a 2.5 MiB one: the name is held to the end of the tag, so the three
        // do not fit 3 MiB however the first attribute gave its own buffers back.
        let body = format!("<{} a=\"x\" b=\"{}\"/>", "n".repeat(1 << 20), "v".repeat(5 << 19));
        let document = Document::read(body.as_bytes(), MemoryBudget::new(Some(3 << 20))).unwrap();
        assert!(document.budget_error.is_some());
        // A budget for all three admits it.
        let document = Document::read(body.as_bytes(), MemoryBudget::new(Some(9 << 20))).unwrap();
        assert_eq!(document.budget_error, None);
        assert_eq!(document.attribute_values.len(), 2);
    }

    #[test]
    fn a_processing_instruction_target_is_reserved_before_it_is_read() {
        let budget = MemoryBudget::new(Some(100_000));
        for body in [
            format!("<?{} data?><r/>", "t".repeat(1_000_000)),
            format!("<?{}?><r/>", "t".repeat(1_000_000)),
            // A split name holds both halves beside it.
            format!("<{}:{}/>", "p".repeat(60_000), "q".repeat(60_000)),
        ] {
            let document = Document::read(body.as_bytes(), budget).unwrap();
            assert!(document.budget_error.is_some(), "{:?}", body.get(..20));
        }
        // An instruction that fits is skipped as before, and a name is charged once for its read and once more
        // for the two halves it splits into, not twice for the read.
        let fits = Document::read(b"<?pi data?><p:q a=\"1\">x</p:q>", MemoryBudget::new(Some(4096))).unwrap();
        assert_eq!(fits.budget_error, None);
        assert_eq!(fits.text, ["x"]);
    }

    /// The status and rule of the interruption a request with the XML `body` gets from the baseline's error rule
    /// and a rule that sees `UNION` in the text, if any.
    fn verdict(body: &str) -> Option<(i32, u16)> {
        let mut parser = crate::seclang::Parser::new();
        parser
            .from_string(
                "SecRuleEngine On\nSecRequestBodyAccess On\n\
                 SecAction \"id:100,phase:1,pass,nolog,ctl:requestBodyProcessor=XML\"\n\
                 SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,deny,status:400\"\n\
                 SecRule XML:/* \"@contains UNION\" \"id:1,phase:2,deny,status:403\"",
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction();
        tx.add_request_header("Content-Type", "application/xml");
        assert!(tx.process_request_headers().is_none());
        tx.process_request_body(body.as_bytes())
            .map(|interruption| (interruption.rule_id, interruption.status))
    }

    #[test]
    fn control_written_out_payload_blocks() {
        assert_eq!(
            verdict("<a>1' UNION SELECT password FROM users-- -</a>"),
            Some((1, 403))
        );
    }

    #[test]
    fn entity_nested_in_text_blocks() {
        let body =
            "<!DOCTYPE a [<!ENTITY q \"UNION SELECT\"><!ENTITY p \"1' &q; password FROM users-- -\">]><a>&p;</a>";
        assert_eq!(verdict(body), Some((200_002, 400)), "entity-delivered SQLi is not seen");
    }

    #[test]
    fn entity_split_across_two_in_attribute_blocks() {
        let body =
            "<!DOCTYPE r [<!ENTITY a \"1' UNI\"><!ENTITY b \"ON SELECT password FROM users-- -\">]><r v=\"&a;&b;\"/>";
        assert_eq!(verdict(body), Some((200_002, 400)), "entity-delivered SQLi is not seen");
    }

    #[test]
    fn predefined_html_numeric_and_unterminated_references_decode_as_before() {
        let document = parse(b"<r a=\"&amp;&nbsp;&#x41;&unterminated x\">&amp;&nbsp;&#x41;&unterminated</r>").unwrap();
        assert_eq!(document.attribute_values, ["&\u{a0}A&unterminated x"]);
        assert_eq!(document.text, ["&\u{a0}A&unterminated"]);
        // Not a name, so not a reference either.
        assert_eq!(parse(b"<r>&; & &1;</r>").unwrap().text, ["&; & &1;"]);
    }

    #[test]
    fn a_reference_to_an_entity_nobody_declared_is_an_error_in_text_and_in_an_attribute() {
        for body in [
            &b"<r>&p;</r>"[..],
            b"<r a=\"&p;\"/>",
            b"<r>x &p; y</r>",
            b"<r a=\"1&p;2\"/>",
        ] {
            assert_eq!(
                parse(body).unwrap_err(),
                "XML syntax error on line 1: invalid character entity &p;",
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        // Names Go's tables do not hold, which a backend's tables may: XML 1.0's fifth edition takes U+0370 and
        // U+10000 for name characters.
        for (body, name) in [
            ("<r>&\u{370};</r>", "\u{370}"),
            ("<r a=\"&\u{10000};\"/>", "\u{10000}"),
            ("<r>&\u{a0};</r>", "\u{a0}"),
        ] {
            assert_eq!(
                parse(body.as_bytes()).unwrap_err(),
                format!("XML syntax error on line 1: invalid character entity &{name};"),
                "{body}"
            );
        }
        // A long name is quoted whole without a budget, and as an excerpt under one.
        let long = format!("<r>&{};</r>", "n".repeat(100_000));
        assert!(parse(long.as_bytes()).unwrap_err().len() > 100_000);
        let budgeted = Document::read(long.as_bytes(), MemoryBudget::new(Some(1 << 20))).unwrap_err();
        assert!(budgeted.to_string().len() < 1_000, "{budgeted}");
    }

    /// Parses `body` at every budget below 16,384 bytes and checks that it is a memory stop up to some budget and the
    /// error, quoting what is wrong (`detailed`), from there on: with no room for the message there is no unquoted
    /// message in its place, which would be a verdict that a connector lets through where it refuses a stop.
    fn assert_a_stop_until_the_message_fits(body: &str, detailed: &str) {
        let mut first_error = None;
        let mut last_stop = None;
        for budget in 0..16_384 {
            let mut map = collection();
            match parse_into(body.as_bytes(), MemoryBudget::new(Some(budget)), LIMIT, false, &mut map) {
                Ok(stop) => {
                    assert!(
                        matches!(stop, Some(Stop::MemoryBudget(_))),
                        "{body}: {budget}: {stop:?}"
                    );
                    assert_eq!(
                        first_error, None,
                        "{body}: a memory stop at {budget}, past the first error"
                    );
                    last_stop = Some(budget);
                },
                Err(message) => {
                    assert_eq!(message, detailed, "{body}: {budget}");
                    assert_eq!(map.value_count(), 0, "{body}: {budget}: the values are taken back");
                    first_error.get_or_insert(budget);
                },
            }
        }
        assert!(last_stop.is_some(), "{body}: no memory stop");
        assert_eq!(
            first_error,
            last_stop.map(|stop| stop + 1),
            "{body}: no gap between the stops and the errors"
        );
        // And the same message without a budget.
        assert_eq!(parse(body.as_bytes()).unwrap_err(), detailed, "{body}");
    }

    #[test]
    fn an_error_that_quotes_the_document_is_a_memory_stop_until_the_budget_has_room_to_quote_it() {
        // `&unknown;` fits the scratch its text was read in at budgets with no room to quote it. The parse stops for
        // the budget then, as it does anywhere else it cannot go on, and a connector refuses that whatever its
        // rules: the error is only ever the quoted one, never an unquoted message in place of the stop. So are the
        // others that quote a name or a value of the document.
        assert_a_stop_until_the_message_fits(
            "<r a=\"1\"><i>x</i>&unknown;</r>",
            "XML syntax error on line 1: invalid character entity &unknown;",
        );
        assert_a_stop_until_the_message_fits(
            "<r a=\"1\"><i>x</i><1abc/></r>",
            "XML syntax error on line 1: invalid XML name: 1abc",
        );
        assert_a_stop_until_the_message_fits(
            "<?xml version=\"2.0\"?><r a=\"1\">x</r>",
            "xml: unsupported version \"2.0\"; only version 1.0 is supported",
        );
        assert_a_stop_until_the_message_fits(
            "<?xml encoding=\"latin1\"?><r a=\"1\">x</r>",
            "xml: encoding \"latin1\" declared but Decoder.CharsetReader is nil",
        );
    }

    #[test]
    fn a_bare_doctype_is_accepted() {
        for body in [
            &b"<!DOCTYPE a><a>x</a>"[..],
            b"<!DOCTYPE a ><a>x</a>",
            b"<!doctype a><a>x</a>",
            b"<!DOCTYPE><a>x</a>",
            b"<!DOCTYPEa><a>x</a>",
            b"<!DOCTYPE SYSTEM><a>x</a>",
            b"<!-- c --><?p x?><!DOCTYPE a><!-- c --><a>x</a>",
            // The keywords in a comment are not the keywords.
            b"<!DOCTYPE a <!-- SYSTEM [ <!ENTITY \" ' --> ><a>x</a>",
        ] {
            let text = parse(body).map(|document| document.text);
            assert_eq!(text, Ok(vec!["x".to_owned()]), "{}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn a_comment_in_a_doctype_is_read_as_any_other_comment() {
        // The same text is a comment, or an error, in a DOCTYPE and between tags, as `--` inside a comment is not
        // XML.
        for comment in [
            "<!---->",
            "<!-- -->",
            "<!-- - -->",
            "<!-- a-b -->",
            "<!--->-->",
            "<!--- -->",
            "<!-- a - -->",
            "<!-- <b>x</b> -->",
            "<!-- a -- b -->",
            "<!-- a --- b -->",
            "<!----->",
            "<!---- -->",
            "<!-- a --b-->",
            "<!-- a --\"-->",
            "<!-- a --\n-->",
            "<!-- \0 -->",
            "<!-x -->",
            "<!-->",
        ] {
            let between = parse(format!("<a>{comment}</a>").as_bytes()).map(|document| document.text);
            let inside = parse(format!("<!DOCTYPE a {comment}><a>x</a>").as_bytes()).map(|document| document.text);
            assert_eq!(between.is_ok(), inside.is_ok(), "{comment}");
            if let (Err(between), Err(inside)) = (&between, &inside) {
                assert_eq!(between, inside, "{comment}");
            }
        }
        let malformed = "XML syntax error on line 1: invalid sequence \"--\" not allowed in comments";
        for comment in ["<!-- a -- b -->", "<!-- a --- b -->", "<!---- -->", "<!-- a --b-->"] {
            assert_eq!(
                parse(format!("<!DOCTYPE a {comment}><a>x</a>").as_bytes()).unwrap_err(),
                malformed,
                "{comment}"
            );
        }
        for comment in [
            "<!---->",
            "<!-- - -->",
            "<!--->-->",
            "<!-- a-b -->",
            "<!-- <b>x</b> -->",
        ] {
            let document = parse(format!("<!DOCTYPE a {comment}><a>x</a>").as_bytes()).unwrap();
            assert_eq!(document.text, ["x"], "{comment}");
        }
    }

    #[test]
    fn a_doctype_with_more_than_its_root_name_and_comments_is_an_error() {
        let more = "XML syntax error on line 1: DOCTYPE with more than its root name is not accepted";
        for body in [
            &b"<!DOCTYPE r extra><r/>"[..],
            b"<!DOCTYPE r a b><r/>",
            b"<!DOCTYPE r\textra\t><r/>",
            b"<!DOCTYPEr extra><r/>",
            b"<!DOCTYPE r <!-- c --> extra><r/>",
            b"<!DOCTYPE r extra <!-- c -->><r/>",
            b"<!DOCTYPE r<!-- c -->extra><r/>",
            b"<!DOCTYPE r \xc3\xa9><r/>",
            b"<!DOCTYPE r !><r/>",
            b"<!DOCTYPE r /><r/>",
            b"<!DOCTYPE r/><r/>",
            b"<!DOCTYPEr/><r/>",
            b"<!DOCTYPE r %p;><r/>",
            b"<!DOCTYPE r \0><r/>",
            b"<!DOCTYPE r = ><r/>",
            b"<!DOCTYPE r public><r/>",
            b"<!DOCTYPE r\nSyStEm><r/>",
            // A character that is no blank, comment or name between the keyword and the root name is as much more
            // than the root name as one after it.
            b"<!DOCTYPE @r><r>x</r>",
            b"<!DOCTYPE @><r>x</r>",
            b"<!DOCTYPE !r><r>x</r>",
            b"<!DOCTYPE /r><r>x</r>",
            b"<!DOCTYPE =r><r>x</r>",
            b"<!DOCTYPE %p;r><r>x</r>",
            b"<!DOCTYPE\t@ r><r>x</r>",
            b"<!DOCTYPE <!-- c --> @r><r>x</r>",
            b"<!DOCTYPE@r><r>x</r>",
            b"<!DOCTYPE /><r>x</r>",
        ] {
            let expected = if body
                .windows(6)
                .any(|word| word.eq_ignore_ascii_case(b"system") || word.eq_ignore_ascii_case(b"public"))
            {
                "XML syntax error on line 1: DOCTYPE with an external identifier is not accepted"
            } else {
                more
            };
            let expected = expected.replace(
                "line 1",
                &format!("line {}", 1 + body.iter().filter(|&&b| b == b'\n').count()),
            );
            assert_eq!(parse(body).unwrap_err(), expected, "{}", String::from_utf8_lossy(body));
        }
        // What a bare DOCTYPE holds is its root name, blanks around it and comments: nothing else is well formed.
        for body in [
            &b"<!DOCTYPE r><r>x</r>"[..],
            b"<!DOCTYPE r ><r>x</r>",
            b"<!DOCTYPE r\t\r\n ><r>x</r>",
            b"<!DOCTYPE   r   ><r>x</r>",
            b"<!DOCTYPE r <!-- extra words --> ><r>x</r>",
            b"<!DOCTYPE r<!-- c -->><r>x</r>",
            b"<!DOCTYPE <!-- c --> r><r>x</r>",
            b"<!DOCTYPE\n\t<!-- c -->\r r><r>x</r>",
            b"<!DOCTYPE:a><r>x</r>",
            b"<!DOCTYPE a.b-c_d:e><r>x</r>",
            b"<!DOCTYPE \xc3\xa9\xce\xb1><r>x</r>",
            b"<!DOCTYPE><r>x</r>",
            b"<!DOCTYPEr><r>x</r>",
        ] {
            let text = parse(body).map(|document| document.text);
            assert_eq!(text, Ok(vec!["x".to_owned()]), "{}", String::from_utf8_lossy(body));
        }
        // And the verdict is the error's, not the body's: a word there is no way to hide markup from a rule.
        assert_eq!(
            verdict("<!DOCTYPE r UNION><r>1' UNION SELECT password FROM users-- -</r>"),
            Some((200_002, 400))
        );
    }

    #[test]
    fn a_doctype_with_a_literal_is_an_error() {
        // A literal belongs to an external identifier or a subset, both refused; libxml2 2.13 and older in recover
        // mode skip just its quote and read what it holds as a subset or the root element.
        let literal = "XML syntax error on line 1: DOCTYPE with a literal is not accepted";
        for body in [
            &b"<!DOCTYPE a \"SYSTEM\"><a>x</a>"[..],
            b"<!DOCTYPE a 'PUBLIC [x]'><a>x</a>",
            b"<!DOCTYPE r\"[<!ENTITY nbsp \"v\">]><r>&nbsp;</r>",
            b"<!DOCTYPE r'[<!ENTITY nbsp \"v\">]><r>&nbsp;</r>",
            b"<!DOCTYPE \"[<!ENTITY nbsp \"v\">]><r>&nbsp;</r>",
            b"<!DOCTYPEr'[<!ENTITY nbsp \"v\">]><r>&nbsp;</r>",
            b"<!DOCTYPE r \"<r>x</r>\"><r>y</r>",
            b"<!DOCTYPE r\"<r>x</r>",
            b"<!DOCTYPE r <!-- c --> '<r>x</r>'><r>y</r>",
        ] {
            assert_eq!(parse(body).unwrap_err(), literal, "{}", String::from_utf8_lossy(body));
        }
        let payload = "1' UNION SELECT password FROM users-- -";
        for body in [
            format!("<!DOCTYPE r\"[<!ENTITY nbsp \"{payload}\">]><r v=\"&nbsp;\">&nbsp;</r>"),
            format!("<!DOCTYPE r \"<r>{payload}</r>\"><r>x</r>"),
        ] {
            assert_eq!(verdict(&body), Some((200_002, 400)), "{body}");
        }
    }

    #[test]
    fn a_directive_other_than_a_doctype_or_after_the_first_element_is_an_error() {
        let other = "XML syntax error on line 1: directive other than a DOCTYPE is not accepted";
        let late = "XML syntax error on line 1: directive after the first element is not accepted";
        for (body, expected) in [
            (&b"<!ELEMENT a ANY><a>x</a>"[..], other),
            (b"<!ATTLIST a SYSTEM [x]><a>x</a>", other),
            (b"<!ENTITY nbsp \"v\"><a>&nbsp;</a>", other),
            (b"<!FOO [<!ENTITY nbsp \"v\">]><a>&nbsp;</a>", other),
            (b"<!DOCTYP a><a/>", other),
            (b"<!DOCTYP<!-- -->E a [<!ENTITY nbsp \"v\">]><a/>", other),
            (b"<!>", other),
            (b"<! DOCTYPE a><a/>", other),
            (b"<!\"x\"><a/>", other),
            ("<!\u{feff}DOCTYPE a [<!ENTITY nbsp \"v\">]><a/>".as_bytes(), other),
            // Inside an element a lenient parser skips the `<!` and reads on: what a directive quotes or nests
            // would be markup to it.
            (b"<a><!FOO \"<b>x</b>\"></a>", late),
            (b"<a><!FOO <b>x</b>></a>", late),
            (b"<a><!DOCTYPE a \"<b>x</b>\"></a>", late),
            (b"<a><!DOCTYPE a [<!ENTITY p \"v\">]></a>", late),
            (b"<a><!ENTITY x '<b>x</b>'></a>", late),
            (b"<a><br><!FOO \"<b>x</b>\"></a>", late),
            // After it too: an end tag that closes more elements than its own can leave it open elsewhere.
            (b"<a/><!DOCTYPE a>", late),
            (b"<a><c></a><!FOO \"<b>x</b>\">", late),
        ] {
            assert_eq!(parse(body).unwrap_err(), expected, "{}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn a_doctype_with_a_subset_an_external_identifier_or_a_declaration_is_an_error() {
        let subset = "XML syntax error on line 1: DOCTYPE with an internal subset is not accepted";
        let external = "XML syntax error on line 1: DOCTYPE with an external identifier is not accepted";
        let declaration = "XML syntax error on line 1: DOCTYPE with a markup declaration is not accepted";
        for (body, expected) in [
            (&b"<!DOCTYPE a SYSTEM \"x\"><a/>"[..], external),
            (b"<!DOCTYPE a PUBLIC \"x\" \"y\"><a/>", external),
            (b"<!DOCTYPE a SYSTEM>", external),
            (b"<!DOCTYPE a SYSTEM\"x\"><a/>", external),
            (b"<!doctype a system \"x\"><a/>", external),
            (b"<!DOCTYPE\ta\nPUBLIC 'x' 'y'><a/>", external),
            (b"<!DOCTYPE a [<!ENTITY p \"v\">]><a>&p;</a>", subset),
            (b"<!DOCTYPE a[]><a/>", subset),
            (b"<!DOCTYPE a SYSTEM \"x\" [<!ENTITY p \"v\">]><a/>", external),
            (b"<!DOCTYPE a [<!ENTITY % p SYSTEM \"http://x/\"> %p;]><a/>", subset),
            (b"<!DOCTYPE a <!ENTITY p \"v\">><a/>", declaration),
            // The root name glued to the keyword, which libxml2 takes in recover mode, or another word glued to it.
            (b"<!DOCTYPEa [<!ENTITY p \"v\">]><a/>", subset),
            (b"<!doctypea [<!ENTITY p \"v\">]><a/>", subset),
            (b"<!DOCTYPES[<!ENTITY p \"v\">]><a/>", subset),
            (b"<!DOCTYPE[<!ENTITY p \"v\">]><a/>", subset),
            (b"<!DOCTYPEa SYSTEM \"x\"><a/>", external),
            (b"<!DOCTYPE:a PUBLIC 'x' 'y'><a/>", external),
        ] {
            assert_eq!(
                parse(body).unwrap_err(),
                expected.replace(
                    "line 1",
                    &format!("line {}", 1 + body.iter().filter(|&&b| b == b'\n').count())
                ),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        // Whatever separates the root name from the keyword, or does not.
        for separator in [
            "", "\t", "\n", "\r", "\0", ":", "_", "-", ".", "#", "%", "/", "\u{a0}", "\u{feff}", "\u{e9}", "\u{370}",
        ] {
            let lines = 1 + separator.matches('\n').count();
            // A separator that is an ASCII character but no blank or name byte is refused before the root name, and
            // one that starts no name, glued to the keyword, makes the root name one that is none.
            let stray = matches!(separator, "\0" | "#" | "%" | "/");
            let no_name = matches!(separator, "-" | "." | "\u{a0}" | "\u{feff}" | "\u{370}");
            let more = "XML syntax error on line 1: DOCTYPE with more than its root name is not accepted";
            let invalid = "XML syntax error on line 1: DOCTYPE root name is not an XML name";
            for (body, expected) in [
                (
                    format!("<!DOCTYPE{separator}a [<!ENTITY p \"v\">]><a/>"),
                    if stray {
                        more
                    } else if no_name {
                        invalid
                    } else {
                        subset
                    },
                ),
                (
                    format!("<!DOCTYPE{separator}a SYSTEM \"x\"><a/>"),
                    if stray {
                        more
                    } else if no_name {
                        invalid
                    } else {
                        external
                    },
                ),
            ] {
                assert_eq!(
                    parse(body.as_bytes()).unwrap_err(),
                    expected.replace("line 1", &format!("line {lines}")),
                    "{body:?}"
                );
            }
        }
    }

    #[test]
    fn a_glued_doctype_or_a_directive_in_an_element_blocks() {
        let payload = "1' UNION SELECT password FROM users-- -";
        for body in [
            // libxml2 in recover mode expands `&nbsp;` to the payload, which this parser read as U+00A0.
            format!("<!DOCTYPEa [<!ENTITY nbsp \"{payload}\">]><r v=\"&nbsp;\"/>"),
            format!("<!DOCTYPE:a [<!ENTITY \u{370} \"{payload}\">]><r v=\"&\u{370};\"/>"),
            // And reads the element this parser skipped as part of the directive.
            format!("<a><!FOO \"<b>{payload}</b>\"></a>"),
        ] {
            assert_eq!(verdict(&body), Some((200_002, 400)), "{body}");
        }
    }

    #[test]
    fn a_comment_or_instruction_with_a_character_xml_does_not_allow_is_an_error() {
        for (c, code) in [
            ("\0", "0000"),
            ("\u{1}", "0001"),
            ("\u{8}", "0008"),
            ("\u{b}", "000B"),
            ("\u{c}", "000C"),
            ("\u{1f}", "001F"),
            ("\u{fffe}", "FFFE"),
            ("\u{ffff}", "FFFF"),
        ] {
            for body in [
                format!("<a><!--{c} <b>x</b> --></a>"),
                format!("<a><!--{c}<b>x</b></a>"),
                format!("<a><?p {c} <b>x</b> ?></a>"),
                format!("<!DOCTYPE a <!--{c}-->><a/>"),
                format!("<?xml version=\"1.0\"{c}?><a/>"),
            ] {
                assert_eq!(
                    parse(body.as_bytes()).unwrap_err(),
                    format!("XML syntax error on line 1: illegal character code U+{code}"),
                    "{body:?}"
                );
            }
            // Glued to the target, the character is refused, whether as one or in the name.
            assert!(parse(format!("<a><?p{c}<b>x</b></a>").as_bytes()).is_err(), "{c:?}");
        }
        // What XML allows is skipped as before.
        let body = "<a><!-- \t\r\n\u{7f}\u{85}\u{e9}\u{fffd}\u{10000} --><?p \t\u{7f}\u{fffd} ?>x</a>";
        assert_eq!(parse(body.as_bytes()).unwrap().text, ["x"]);
        assert_eq!(
            verdict("<a><!--\0<b>1' UNION SELECT password FROM users-- -</b>--></a>"),
            Some((200_002, 400))
        );
    }

    #[test]
    fn a_document_refused_for_an_entity_leaves_the_collection_as_it_was() {
        for body in [
            &b"<r a=\"1\"><i b=\"2\">x</i>&p;</r>"[..],
            b"<r a=\"1\"><i b=\"&p;\"/></r>",
            b"<r a=\"1\">x<!DOCTYPE r SYSTEM \"http://x/\"></r>",
        ] {
            let mut map = collection();
            map.add("/*", "earlier");
            let before = entries(&map);
            assert!(parse_into(body, MemoryBudget::default(), LIMIT, false, &mut map).is_err());
            assert_eq!(entries(&map), before, "{}", String::from_utf8_lossy(body));
        }
    }
}
