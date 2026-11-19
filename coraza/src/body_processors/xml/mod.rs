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

//! XML body parsing with the behavior of Go Coraza's XML body processor.

mod decoder;
mod tables;

use decoder::{Decoder, Token};

use crate::{body_processors::budget::MemoryBudget, collection::Map};

/// Bytes charged to a host's memory budget for each value beyond its text: the entry in the collection, with the
/// growth slack of the vector that holds it (a vector being grown holds its old and new buffers at once), the
/// allocation overhead of the text.
///
/// Without a host budget nothing bounds the output, as in Go Coraza: a document is never refused for having many
/// values.
const VALUE_OVERHEAD_BYTES: usize = 128;

/// The budget charge for one value of `len` bytes, which is read into one string and moved into the collection.
pub(super) fn value_cost(len: usize) -> usize {
    VALUE_OVERHEAD_BYTES.saturating_add(len)
}

/// The `REQUEST_XML` key of attribute values.
const ATTRIBUTE_KEY: &[u8] = b"//@*";

/// The `REQUEST_XML` key of text.
const TEXT_KEY: &[u8] = b"/*";

/// Where the parser puts the values it reads, in document order.
trait Sink {
    /// An attribute value.
    fn attribute(&mut self, value: String);

    /// A non-empty text segment, trimmed.
    fn text(&mut self, value: String);

    /// Takes back the last `count` attribute values, which belonged to a start tag the input ended in.
    fn discard_attributes(&mut self, count: usize);
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

/// Parse a request body into `REQUEST_XML`, accepting truncated documents as partial input.
///
/// Values go into `collection` as they are read, charged to the host's `memory` budget before each is allocated;
/// without one, as by default, nothing limits them. A document that outgrows the budget keeps the values before
/// that point, and the message returned names it. A document the decoder rejects leaves the
/// collection as it found it, and returns the decoder's message.
///
/// # Errors
///
/// The syntax error that made Go reject the document.
pub(crate) fn parse_into(body: &[u8], memory: MemoryBudget, collection: &mut Map) -> Result<Option<String>, String> {
    let mut sink = CollectionSink::new(collection);
    match read(body, memory, &mut sink) {
        Ok(budget_error) => {
            sink.finish();
            Ok(budget_error)
        },
        Err(error) => {
            sink.rollback();
            Err(error.to_string())
        },
    }
}

/// Read as far as the decoder permits; Go Coraza accepts unexpected EOF. Returns why it stopped early, if a
/// budget ran out.
fn read(xml: &[u8], memory: MemoryBudget, sink: &mut impl Sink) -> Result<Option<String>, decoder::DecodeError> {
    let mut decoder = Decoder::new(xml).with_memory_budget(memory);
    loop {
        match decoder.token(&mut |value| sink.attribute(value)) {
            Ok(Some(Token::CharData(text))) => {
                let text = trimmed(text);
                if !text.is_empty() {
                    if let Err(error) = decoder.charge(value_cost(text.len())) {
                        return Ok(Some(error.to_string()));
                    }
                    sink.text(text);
                }
            },
            Ok(Some(Token::Start { .. } | Token::End(_) | Token::Other)) => {},
            Ok(None) => return Ok(None),
            Err(decoder::DecodeError::UnexpectedEof { .. }) => {
                // A start tag the input ended in was never returned, so the attributes it had read are not there.
                sink.discard_attributes(decoder.unfinished_attributes());
                return Ok(None);
            },
            Err(error @ decoder::DecodeError::MemoryBudget { .. }) => {
                return Ok(Some(error.to_string()));
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
    /// Set when parsing stopped because a budget ran out; the values before that point are kept.
    budget_error: Option<String>,
}

#[cfg(test)]
impl Sink for Document {
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
}

#[cfg(test)]
impl Document {
    /// Parse under `memory`, the host's budget.
    fn read(xml: &[u8], memory: MemoryBudget) -> Result<Self, decoder::DecodeError> {
        let mut document = Self::default();
        document.budget_error = read(xml, memory, &mut document)?;
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
    use super::{Document, MemoryBudget, parse, parse_into, value_cost};
    use crate::{collection::Map, types::RuleVariable};

    /// A document with one attribute value and two text values, `a`, `b` and `c`.
    const THREE_VALUES: &[u8] = b"<r x=\"a\"><i>b</i><i>c</i></r>";

    #[test]
    fn valid_documents_are_never_refused_for_having_many_values_without_a_host_budget() {
        // Go Coraza has no limit on what a document produces. Sixteen copies of `<a b="c">d</a>` is 224 bytes
        // and 32 values: a limit proportional to the body, with a floor of a few kilobytes, stopped it after 31.
        for copies in [1, 15, 16, 17, 31, 32, 33, 100, 1000, 50_000] {
            let body = format!("<r>{}</r>", "<a b=\"c\">d</a>".repeat(copies));
            let document = parse(body.as_bytes()).unwrap();
            assert_eq!(document.budget_error, None, "{copies} copies");
            assert_eq!(document.attribute_values.len(), copies, "{copies} copies");
            assert_eq!(document.text.len(), copies, "{copies} copies");
        }
        // The same shapes the other way round, and the densest list, at every size around the old floor.
        for count in (1..200).chain([4096, 100_000]) {
            for unit in ["<i>1</i>", "<a b c d e f g h/>", "<a b=\"c\"/>", "<a b=\"c\">d</a>"] {
                let body = format!("<r>{}</r>", unit.repeat(count));
                assert_eq!(parse(body.as_bytes()).unwrap().budget_error, None, "{count} of {unit}");
            }
        }
        // And the bare-attribute flood in one tag, the densest of all.
        let mut body = b"<r".to_vec();
        body.extend(std::iter::repeat_n(*b" b", 100_000).flatten());
        body.extend_from_slice(b"></r>");
        let document = parse(&body).unwrap();
        assert_eq!(document.budget_error, None);
        assert_eq!(document.attribute_values.len(), 100_000);
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
            one_less.budget_error.as_deref(),
            Some(format!("parsed XML exceeds the {} byte body memory budget", needed - 1).as_str())
        );
    }

    #[test]
    fn an_attribute_flood_in_one_tag_keeps_the_values_the_budget_admitted() {
        let mut body = b"<r".to_vec();
        body.extend(std::iter::repeat_n(*b" b", 10_000).flatten());
        body.extend_from_slice(b"></r>");
        let document = Document::read(&body, MemoryBudget::new(Some(10 * value_cost(1)))).unwrap();
        let kept = document.attribute_values.len();
        assert!((1..10).contains(&kept), "the values read before it ran out: {kept}");
        assert!(document.attribute_values.iter().all(|value| value == "b"));
        assert!(document.budget_error.is_some());
    }

    #[test]
    fn a_syntax_error_still_discards_the_document_as_before() {
        assert!(parse(b"<a b=\"c\"></x></y>").is_err());
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
        assert_eq!(parse_into(body, MemoryBudget::default(), &mut expected), Ok(None));
        let document = parse(body).unwrap();
        assert_eq!(document.attribute_values, ["1", "2"]);
        assert_eq!(document.text, ["x", "y"]);
        for budget in [1_000_000_usize, usize::MAX] {
            let mut map = collection();
            assert_eq!(parse_into(body, MemoryBudget::new(Some(budget)), &mut map), Ok(None));
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
            &mut map,
        );
        assert!(message.unwrap_err().starts_with("XML syntax error on line 1"));
        assert_eq!(entries(&map), before, "the collection is as it was found");
        assert_eq!(map.value_count(), 2);

        let mut fresh = collection();
        assert!(parse_into(b"<r a=\"1\">x</y>", MemoryBudget::default(), &mut fresh).is_err());
        assert!(fresh.is_empty(), "keys it created are gone too");
        assert_eq!(fresh.value_count(), 0);
    }

    #[test]
    fn a_truncated_document_keeps_its_values() {
        let mut map = collection();
        assert_eq!(
            parse_into(b"<r a=\"1\"><i>x", MemoryBudget::default(), &mut map),
            Ok(None)
        );
        assert_eq!(entries(&map).len(), 2);
    }

    #[test]
    fn the_host_budget_stops_the_parse_with_the_values_before_it_and_names_its_size() {
        let body = format!("<r>{}</r>", "<i>12345678</i>".repeat(1000));
        let mut map = collection();
        let message = parse_into(body.as_bytes(), MemoryBudget::new(Some(20_000)), &mut map).unwrap();
        assert_eq!(
            message.as_deref(),
            Some("parsed XML exceeds the 20000 byte body memory budget")
        );
        let kept = map.value_count();
        assert!(0 < kept && kept < 1000, "a prefix: {kept}");
        assert!(map.iter().all(|(key, value)| key == "/*" && value == b"12345678"));

        // The smaller of the two budgets is the one that reports: the document's own 18x one here.
        let mut map = collection();
        let message = parse_into(
            b"<r a=\"1\" b=\"2\" c=\"3\">x</r>",
            MemoryBudget::new(Some(1_000_000)),
            &mut map,
        );
        assert_eq!(message, Ok(None));
        let tiny = MemoryBudget::new(Some(100));
        let mut map = collection();
        assert!(
            parse_into(b"<r a=\"1\" b=\"2\" c=\"3\">x</r>", tiny, &mut map)
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
    fn a_start_tag_the_input_ends_in_has_no_attributes_as_before() {
        // Go's decoder returns a start token only when its tag is complete, so the attributes read before the
        // input ended inside one were never seen. The document is accepted as far as it goes.
        for (body, attributes, text) in [
            (&b"<r a=\"x\""[..], &[][..], &[][..]),
            (b"<r a=\"x\" b=", &[], &[]),
            (b"<r a=\"x\" b=\"y\"", &[], &[]),
            (b"<r a=\"x\" b", &[], &[]),
            (b"<r a=x", &[], &[]),
            (b"<r a=\"x\"/", &[], &[]),
            (b"<r a=\"x\">", &["x"], &[]),
            (b"<r a=\"x\">tex", &["x"], &["tex"]),
            (b"<a b=\"1\"><c d=\"2\"", &["1"], &[]),
            (b"<a b=\"1\"><c d=\"2\" e=\"3\"/><f g=\"4\"", &["1", "2", "3"], &[]),
        ] {
            let document = parse(body).unwrap();
            assert_eq!(
                document.attribute_values,
                attributes,
                "{}",
                String::from_utf8_lossy(body)
            );
            assert_eq!(document.text, text, "{}", String::from_utf8_lossy(body));
            // The same through the collection, where the key is not created for values that never were.
            let mut map = collection();
            assert_eq!(parse_into(body, MemoryBudget::default(), &mut map), Ok(None));
            let published: Vec<_> = entries(&map)
                .into_iter()
                .filter(|(key, _)| key == "//@*")
                .map(|(_, value)| value)
                .collect();
            assert_eq!(published, attributes, "{}", String::from_utf8_lossy(body));
            assert_eq!(map.value_count(), attributes.len() + text.len());
        }
        // Values the collection held before are not taken back with them.
        let mut map = collection();
        map.add_owned(b"//@*", b"before".to_vec());
        assert_eq!(parse_into(b"<r a=\"x\"", MemoryBudget::default(), &mut map), Ok(None));
        assert_eq!(entries(&map), [("//@*".to_owned(), "before".to_owned())]);
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
}
