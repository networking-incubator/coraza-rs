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

#![no_main]

use std::sync::OnceLock;

use coraza::{
    config::DEFAULT_ARGUMENT_LIMIT, seclang::Parser, transaction::VariableCollection, types::RuleVariable, waf::Waf,
};
use libfuzzer_sys::fuzz_target;

/// Select the XML processor with a phase 1 `ctl`, as the baseline's rule 200000 does for an XML
/// content type, so every input reaches the parser whatever its headers.
const XML_RULES: &str = "SecRequestBodyAccess On\n\
                         SecAction \"id:1,phase:1,ctl:requestBodyProcessor=XML,pass\"";

/// Body limits under `ProcessPartial` that cut most inputs, in or near a token, so the parser takes the exception for
/// an input a body limit ended in a token.
const PARTIAL_LIMITS: [usize; 3] = [16, 64, 256];

/// The compiled WAF is immutable, so build it once instead of compiling rules per input.
fn xml_waf() -> &'static Waf {
    static WAF: OnceLock<Waf> = OnceLock::new();
    WAF.get_or_init(|| build(XML_RULES))
}

/// The WAFs that cut a body at each of [`PARTIAL_LIMITS`] and inspect what they keep.
fn partial_wafs() -> &'static [Waf] {
    static WAFS: OnceLock<Vec<Waf>> = OnceLock::new();
    WAFS.get_or_init(|| {
        PARTIAL_LIMITS
            .iter()
            .map(|limit| {
                build(&format!(
                    "SecRequestBodyAccess On\nSecRequestBodyLimit {limit}\nSecRequestBodyLimitAction ProcessPartial\n\
                     SecAction \"id:1,phase:1,ctl:requestBodyProcessor=XML,pass\""
                ))
            })
            .collect()
    })
}

/// Compile `rules` into a WAF.
fn build(rules: &str) -> Waf {
    let mut parser = Parser::new();
    parser.from_string(rules).expect("fuzz XML rules compile");
    parser.into_waf().expect("fuzz XML WAF is valid")
}

/// What a transaction made of a body: the values `REQUEST_XML` holds in order, and the body error.
#[derive(Debug, PartialEq)]
struct Outcome {
    values: Vec<(String, Vec<u8>)>,
    /// `REQBODY_ERROR`.
    error: bool,
    /// `REQBODY_ERROR_MSG`.
    message: String,
}

impl Outcome {
    /// Whether the body ended in a token with nothing else wrong: Go's `unexpected EOF`, which a CDATA section's
    /// and an invalid UTF-8 character's messages are not.
    fn is_unexpected_eof(&self) -> bool {
        self.message
            .strip_prefix("XML: XML syntax error on line ")
            .and_then(|rest| rest.split_once(": "))
            .is_some_and(|(line, text)| line.bytes().all(|b| b.is_ascii_digit()) && text == "unexpected EOF")
    }
}

/// Whether a cut that refused the body, where the same bytes without a limit end in `unexpected EOF`, is right to: the
/// text it ends, the reference as written included, holds a forbidden character or broken UTF-8. A space ends a
/// reference the cut ended in as written, so the unlimited WAF on `kept` plus one space checks that text as the cut
/// does and must give the cut's message, which is never `unexpected EOF`.
fn is_refused_for_what_it_kept(cut: &Outcome, kept: &[u8]) -> bool {
    !cut.is_unexpected_eof() && feed(xml_waf(), None, &[kept, b" "].concat()).message == cut.message
}

/// Feed `data` as a request body to `waf` under `budget`, check the values it publishes, and return them.
fn feed(waf: &Waf, budget: Option<usize>, data: &[u8]) -> Outcome {
    let mut tx = waf.new_transaction();
    tx.set_body_memory_budget(budget);
    tx.process_request_headers();
    let _ = tx.process_request_body(data);
    let mut values = Vec::new();
    if let Some(VariableCollection::Map(xml)) = tx.collection(RuleVariable::RequestXML) {
        // The rules leave the argument limit at its default, which bounds the values a document publishes.
        assert!(
            xml.value_count() <= DEFAULT_ARGUMENT_LIMIT,
            "{} XML values",
            xml.value_count()
        );
        values = xml
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_vec()))
            .collect();
    }
    Outcome {
        values,
        error: tx.get_variable(RuleVariable::ReqbodyError, None).as_deref() == Some("1"),
        message: tx.get_variable(RuleVariable::ReqbodyErrorMsg, None).unwrap_or_default(),
    }
}

fuzz_target!(|data: &[u8]| {
    // Without a budget, as by default, and under one the first byte sizes small enough to run out anywhere.
    let budget = data.first().map(|&byte| usize::from(byte) * 64);
    let whole = feed(xml_waf(), None, data);
    feed(xml_waf(), budget, data);
    for (waf, limit) in partial_wafs().iter().zip(PARTIAL_LIMITS) {
        let cut = feed(waf, None, data);
        if data.len() <= limit {
            // Nothing was cut, so the limit changes nothing.
            assert_eq!(cut, whole, "a body of {} bytes under a limit of {limit}", data.len());
            continue;
        }
        // The cut leaves the first `limit` bytes. Where the document without a limit reads that prefix, the cut reads
        // it the same way. Where that ends in a token, the cut keeps what the token had read, so it must not refuse
        // the body, but for the cuts that are errors: in a CDATA section or a UTF-8 character of text or a value,
        // which have other messages without a limit, and in a reference, whose text the cut checks and the
        // reference's `unexpected EOF` came before.
        let kept = &data[..limit];
        let prefix = feed(xml_waf(), None, kept);
        if !prefix.error {
            assert_eq!(cut, prefix, "a body of {} bytes cut at {limit} bytes", data.len());
        } else if prefix.is_unexpected_eof() {
            assert!(
                !cut.error || is_refused_for_what_it_kept(&cut, kept),
                "{prefix:?} refused when cut at {limit} bytes: {cut:?}"
            );
        }
    }
});
