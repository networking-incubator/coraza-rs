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

#![expect(
    clippy::unwrap_used,
    clippy::tests_outside_test_module,
    reason = "budget tests use fixed rules and bounded fixtures"
)]

//! The absolute memory budget a connector can give the built-in body processors, as seen through the public API:
//! what stops, what is kept, what is reported, and that nothing changes without one.

mod common;

use std::{
    fmt::Write as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use common::smallest_budget;
use coraza::{
    actions::{ActionType, CustomAction, RuleMetadata},
    operators::{Operator, Outputs},
    seclang::Parser,
    transaction::{Transaction, VariableCollection},
    types::RuleVariable,
    waf::Waf,
};

/// The engine with `rules` beside a body policy that parses by `Content-Type`, XML and JSON as CRS selects them.
fn waf(rules: &str) -> Waf {
    waf_in(Parser::new(), rules)
}

/// [`waf`] built by `parser`, which a test may have given a callback.
fn waf_in(mut parser: Parser, rules: &str) -> Waf {
    parser
        .from_string(&format!(
            "SecRequestBodyAccess On\n\
             SecRequestBodyLimit 134217728\n\
             SecRequestBodyInMemoryLimit 134217728\n\
             SecResponseBodyAccess On\n\
             SecResponseBodyMimeType application/json\n\
             SecArgumentsLimit 100000\n\
             SecRule REQUEST_HEADERS:Content-Type \"^text/xml\" \
                 \"id:900000,phase:1,t:none,pass,nolog,ctl:requestBodyProcessor=XML\"\n\
             SecRule REQUEST_HEADERS:Content-Type \"^application/json\" \
                 \"id:900001,phase:1,t:none,pass,nolog,ctl:requestBodyProcessor=JSON\"\n\
             SecRule RESPONSE_CONTENT_TYPE \"^application/json\" \
                 \"id:900002,phase:3,t:none,pass,nolog,ctl:responseBodyProcessor=JSON\"\n\
             {rules}"
        ))
        .unwrap();
    parser.into_waf().unwrap()
}

/// A transaction that has read the headers of a request with `content_type`.
fn request(waf: &Waf, content_type: &str, budget: Option<usize>) -> Transaction {
    let mut tx = waf.new_transaction();
    tx.set_body_memory_budget(budget);
    tx.add_request_header("Content-Type", content_type);
    tx.process_request_headers();
    tx
}

/// A transaction that has read the headers of a JSON response to a request without a body, under `budget`.
fn json_response(waf: &Waf, budget: Option<usize>) -> Transaction {
    let mut tx = waf.new_transaction();
    tx.process_request_headers();
    tx.process_request_body(b"");
    tx.add_response_header("Content-Type", "application/json");
    tx.process_response_headers(200, "HTTP/1.1");
    tx.set_body_memory_budget(budget);
    tx
}

/// Whether `REQBODY_ERROR` and `REQBODY_PROCESSOR_ERROR` are both raised.
fn request_body_errored(tx: &Transaction) -> bool {
    tx.get_variable(RuleVariable::ReqbodyError, None).as_deref() == Some("1")
        && tx.get_variable(RuleVariable::ReqbodyProcessorError, None).as_deref() == Some("1")
}

/// The values of a map variable, in order, as text.
fn values_of(tx: &Transaction, variable: RuleVariable) -> Vec<(String, String)> {
    match tx.collection(variable) {
        Some(VariableCollection::Map(map)) => map
            .iter()
            .map(|(key, value)| (key.to_owned(), String::from_utf8_lossy(value).into_owned()))
            .collect(),
        _ => Vec::new(),
    }
}

/// `count` pairs `k0=v0&k1=v1...`.
fn pairs(count: usize) -> Vec<u8> {
    (0..count)
        .map(|index| format!("k{index}=v{index}"))
        .collect::<Vec<_>>()
        .join("&")
        .into_bytes()
}

#[test]
fn there_is_no_budget_unless_a_connector_sets_one() {
    let waf = waf("");
    let mut tx = waf.new_transaction();
    assert_eq!(tx.body_memory_budget(), None);
    tx.set_body_memory_budget(Some(4096));
    assert_eq!(tx.body_memory_budget(), Some(4096));
    tx.set_body_memory_budget(None);
    assert_eq!(tx.body_memory_budget(), None);

    // A finished transaction goes back to the pool, and the next one must not inherit the limit.
    tx.set_body_memory_budget(Some(1));
    drop(tx);
    assert_eq!(waf.new_transaction().body_memory_budget(), None);
}

#[test]
fn urlencoded_arguments_stop_at_the_budget_and_keep_the_pairs_before_it() {
    let waf = waf("");
    let body = pairs(5_000);
    let form = "application/x-www-form-urlencoded";

    let mut unlimited = request(&waf, form, None);
    unlimited.process_request_body(&body);
    assert!(!request_body_errored(&unlimited), "no budget, no error");
    assert_eq!(values_of(&unlimited, RuleVariable::ArgsPost).len(), 5_000);

    let mut tx = request(&waf, form, Some(100_000));
    let interruption = tx.process_request_body(&body);

    assert!(interruption.is_none(), "a body error does not interrupt by itself");
    assert!(request_body_errored(&tx));
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None).as_deref(),
        Some("parsed arguments exceed the body memory budget")
    );
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyErrorMsg, None).as_deref(),
        Some("URLENCODED: parsed arguments exceed the body memory budget")
    );
    let post = values_of(&tx, RuleVariable::ArgsPost);
    assert!(
        !post.is_empty() && post.len() < 5_000,
        "a prefix was published: {}",
        post.len()
    );
    let expected: Vec<(String, String)> = (0..post.len()).map(|i| (format!("k{i}"), format!("v{i}"))).collect();
    assert_eq!(post, expected, "the prefix is the first pairs, in order");
    assert_eq!(
        values_of(&tx, RuleVariable::Args),
        expected,
        "ARGS holds the same prefix"
    );
    assert!(tx.body_memory_bytes() < 2 * unlimited.body_memory_bytes());
}

#[test]
fn a_bigger_budget_admits_more_and_a_budget_that_covers_the_body_changes_nothing() {
    let waf = waf("");
    let body = pairs(2_000);
    let form = "application/x-www-form-urlencoded";
    let admitted = |budget: Option<usize>| {
        let mut tx = request(&waf, form, budget);
        tx.process_request_body(&body);
        (values_of(&tx, RuleVariable::ArgsPost).len(), request_body_errored(&tx))
    };
    let (small, small_errored) = admitted(Some(50_000));
    let (large, large_errored) = admitted(Some(200_000));
    assert!(small_errored && large_errored);
    assert!(0 < small && small < large && large < 2_000, "{small} < {large}");

    assert_eq!(admitted(None), (2_000, false));
    assert_eq!(admitted(Some(usize::MAX)), (2_000, false));
    assert_eq!(admitted(Some(100_000_000)), (2_000, false));
}

#[test]
fn an_xml_document_stops_at_the_budget_with_its_values_before_it_and_the_same_key_order() {
    let waf = waf("");
    // Text comes first, then attributes: the collection has always listed attribute values first.
    let mut document = String::from("<r>head");
    for index in 0..4_000 {
        write!(document, "<i a=\"{index}\">t{index}</i>").unwrap();
    }
    document.push_str("</r>");

    let mut unlimited = request(&waf, "text/xml", None);
    unlimited.process_request_body(document.as_bytes());
    assert!(!request_body_errored(&unlimited));
    let all = values_of(&unlimited, RuleVariable::RequestXML);
    assert_eq!(all.len(), 8_001);
    assert_eq!(all.first().map(|(key, _)| key.as_str()), Some("//@*"));
    assert_eq!(all.last().map(|(key, _)| key.as_str()), Some("/*"));

    let mut tx = request(&waf, "text/xml", Some(100_000));
    assert!(tx.process_request_body(document.as_bytes()).is_none());
    assert!(request_body_errored(&tx));
    let message = tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None).unwrap();
    assert_eq!(message, "parsed XML exceeds the 100000 byte body memory budget");
    let kept = values_of(&tx, RuleVariable::RequestXML);
    assert!(!kept.is_empty() && kept.len() < all.len(), "a prefix: {}", kept.len());
    assert_eq!(
        kept.first().map(|(key, _)| key.as_str()),
        Some("//@*"),
        "attributes still come first"
    );
    let attributes: Vec<&String> = kept
        .iter()
        .filter(|(key, _)| key == "//@*")
        .map(|(_, value)| value)
        .collect();
    let expected: Vec<String> = (0..attributes.len()).map(|index| index.to_string()).collect();
    assert_eq!(attributes, expected.iter().collect::<Vec<_>>(), "in document order");
}

#[test]
fn an_xml_syntax_error_still_discards_every_value_under_a_budget() {
    let waf = waf("");
    for budget in [None, Some(1_000_000)] {
        let mut tx = request(&waf, "text/xml", budget);
        tx.process_request_body(b"<r a=\"1\"><i a=\"2\">text</i></x></y>");
        assert!(request_body_errored(&tx), "{budget:?}");
        assert!(values_of(&tx, RuleVariable::RequestXML).is_empty(), "{budget:?}");
        assert!(
            tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None)
                .unwrap()
                .starts_with("XML syntax error on line 1"),
            "{budget:?}"
        );
    }
}

#[test]
fn json_arguments_stop_at_the_budget_and_keep_the_leaves_before_it() {
    let waf = waf("");
    let leaves: Vec<String> = (0..2_000).map(|index| format!("\"k{index}\":\"v{index}\"")).collect();
    let body = format!("{{{}}}", leaves.join(",")).into_bytes();

    let mut unlimited = request(&waf, "application/json", None);
    unlimited.process_request_body(&body);
    assert!(!request_body_errored(&unlimited));
    assert_eq!(values_of(&unlimited, RuleVariable::ArgsPost).len(), 2_000);

    let mut tx = request(&waf, "application/json", Some(200_000));
    assert!(tx.process_request_body(&body).is_none());
    assert!(request_body_errored(&tx));
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None).unwrap(),
        "flattened form exceeds the 200000 byte body memory budget"
    );
    let post = values_of(&tx, RuleVariable::ArgsPost);
    assert!(!post.is_empty() && post.len() < 2_000, "a prefix: {}", post.len());
    assert_eq!(post.first(), Some(&("json.k0".to_owned(), "v0".to_owned())));
    assert_eq!(values_of(&tx, RuleVariable::Args), post, "ARGS holds the same prefix");
    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("json_request_body"))
            .unwrap_or_default(),
        "",
        "a body that failed to parse is not kept as the JSON text"
    );
}

#[test]
fn a_json_container_index_over_the_budget_refuses_the_body_whole() {
    let waf = waf("");
    let mut body = b"[".to_vec();
    body.extend(b"[[]],".repeat(20_000));
    body.extend_from_slice(b"[]]");

    let mut tx = request(&waf, "application/json", Some(100_000));
    tx.process_request_body(&body);
    assert!(request_body_errored(&tx));
    assert!(
        values_of(&tx, RuleVariable::ArgsPost).is_empty(),
        "there is no index to flatten with"
    );

    let mut roomy = request(&waf, "application/json", Some(100_000_000));
    roomy.process_request_body(&body);
    assert!(!request_body_errored(&roomy));
}

#[test]
fn a_budget_never_loosens_gos_own_json_limit() {
    let waf = waf("");
    // One 100 KB key over 999 leaves outgrows Go's raw budget (eight times the body) with room to spare.
    let mut body = b"{\"".to_vec();
    body.extend(std::iter::repeat_n(b'k', 100_000));
    body.extend_from_slice(b"\":[");
    body.extend(std::iter::repeat_n(b"1,".as_slice(), 998).flatten());
    body.extend_from_slice(b"1]}");
    for budget in [None, Some(usize::MAX)] {
        let mut tx = request(&waf, "application/json", budget);
        tx.process_request_body(&body);
        assert!(request_body_errored(&tx), "{budget:?}");
        let message = tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None).unwrap();
        assert!(
            message.starts_with("flattened form exceeds the") && message.ends_with("byte body"),
            "Go's message, and no other limit's: {message}"
        );
    }
}

#[test]
fn without_a_budget_a_valid_body_is_an_error_go_would_not_report_only_past_the_xml_argument_limit() {
    // 200002 is what turns an error into a 400, so a body that parses must raise none.
    let waf = waf("SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,t:none,deny,status:400\"");
    let denied = |content_type: &str, body: &[u8]| request(&waf, content_type, None).process_request_body(body);

    // Repeated attribute and text shapes at every size around the old 4096 byte floor of the XML output limit, up to
    // the argument limit of 100,000 values. Past it the body is an error, which Go, with no limit, does not report.
    for (unit, values) in [
        ("<a b=\"c\">d</a>", 2),
        ("<i>1</i>", 1),
        ("<a b c d e f g h/>", 7),
        ("<a b=\"c\"/>", 1),
    ] {
        for copies in (1..400).step_by(7).chain([4096, 100_000 / values]) {
            let body = format!("<r>{}</r>", unit.repeat(copies));
            assert!(denied("text/xml", body.as_bytes()).is_none(), "{copies} of {unit}");
        }
        let past = format!("<r>{}</r>", unit.repeat(100_000 / values + 1));
        assert_eq!(
            denied("text/xml", past.as_bytes()).map(|interruption| interruption.status),
            Some(400),
            "one more {unit}"
        );
    }
    let sixteen = format!("<r>{}</r>", "<a b=\"c\">d</a>".repeat(16));
    assert!(sixteen.len() < 300, "a document of {} bytes", sixteen.len());
    let mut tx = request(&waf, "text/xml", None);
    assert!(tx.process_request_body(sixteen.as_bytes()).is_none());
    assert_eq!(values_of(&tx, RuleVariable::RequestXML).len(), 32);

    // A long key over a few leaves: 660 bytes that fit Go's raw budget.
    let mut body = b"{\"".to_vec();
    body.extend(std::iter::repeat_n(b'k', 300));
    body.extend_from_slice(b"\":[");
    body.extend(std::iter::repeat_n(b"1,".as_slice(), 11).flatten());
    body.extend_from_slice(b"1]}");
    assert!(denied("application/json", &body).is_none());

    // A dense array under a raised argument limit has no limit but Go's.
    let waf = self::waf(
        "SecArgumentsLimit 100000000\n\
         SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,t:none,deny,status:400\"",
    );
    let dense = format!("[{}1]", "1,".repeat(200_000));
    assert!(
        request(&waf, "application/json", None)
            .process_request_body(dense.as_bytes())
            .is_none()
    );
}

#[test]
fn multipart_parts_stop_at_the_budget_and_keep_the_parts_before_it() {
    let waf = waf("");
    let body = fields_then(300, "--b--\r\n");
    let content_type = "multipart/form-data; boundary=b";

    let mut unlimited = request(&waf, content_type, None);
    unlimited.process_request_body(body.as_bytes());
    assert!(!request_body_errored(&unlimited));
    assert_eq!(values_of(&unlimited, RuleVariable::ArgsPost).len(), 300);

    // Reading the parts stops at the budget, and the parts that did not fit are never read.
    let mut tx = request(&waf, content_type, Some(60_000));
    assert!(tx.process_request_body(body.as_bytes()).is_none());
    assert!(request_body_errored(&tx));
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None).unwrap(),
        "malformed multipart: limit exceeded: body memory budget exceeded"
    );
    let post = values_of(&tx, RuleVariable::ArgsPost);
    assert!(!post.is_empty() && post.len() < 300, "a prefix: {}", post.len());
    assert_eq!(post.first(), Some(&("f0".to_owned(), "value0".to_owned())));
    assert_ne!(
        tx.get_variable(RuleVariable::MultipartStrictError, None).as_deref(),
        Some("1"),
        "running out of budget is not a violation of the format"
    );
}

#[test]
fn a_bigger_budget_never_publishes_fewer_multipart_parts() {
    let waf = waf("");
    let body = fields_then(300, "--b--\r\n");
    // Parts read hold memory while they wait, so a budget that reads more of them must not leave less for publishing.
    let mut published = 0;
    for budget in (0..=400_000).step_by(4_000) {
        let mut tx = request(&waf, "multipart/form-data; boundary=b", Some(budget));
        tx.process_request_body(body.as_bytes());
        let fields = values_of(&tx, RuleVariable::ArgsPost).len();
        assert!(
            fields >= published,
            "{budget} bytes publish {fields} fields, a smaller budget {published}"
        );
        published = fields;
    }
    assert_eq!(published, 300);
}

#[test]
fn multipart_values_are_charged_before_they_are_published() {
    let waf = waf("");
    // Twenty parts of 5000 bytes are cheap to read, but publishing each costs it twice over, once for `ARGS_POST`
    // and once for `ARGS`.
    let mut body = String::new();
    for index in 0..20 {
        write!(
            body,
            "--b\r\nContent-Disposition: form-data; name=\"f{index}\"\r\n\r\n{}\r\n",
            "x".repeat(5000)
        )
        .unwrap();
    }
    body.push_str("--b--\r\n");

    // 98_000 is between the 89_872 bytes eight parts need and the 98_320 nine do.
    let mut tx = request(&waf, "multipart/form-data; boundary=b", Some(98_000));
    assert!(tx.process_request_body(body.as_bytes()).is_none());
    assert_eq!(
        tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None).unwrap(),
        "published parts exceed the body memory budget"
    );
    let post = values_of(&tx, RuleVariable::ArgsPost);
    assert_eq!(post.len(), 8);
    assert_eq!(values_of(&tx, RuleVariable::Args), post);
    assert_eq!(
        values_of(&tx, RuleVariable::MultipartName).len(),
        post.len(),
        "the part that did not fit left no trace in the metadata of the others"
    );
}

#[test]
fn multipart_headers_are_charged_while_the_parts_are_read() {
    let waf = waf("");
    // One part with thousands of tiny headers: what reading them holds is bounded before anything is published.
    let mut body = String::from("--b\r\nContent-Disposition: form-data; name=\"f\"\r\n");
    for index in 0..9_000 {
        write!(body, "X-{index}: v\r\n").unwrap();
    }
    body.push_str("\r\ndata\r\n--b--\r\n");
    let content_type = "multipart/form-data; boundary=b";

    let mut tx = request(&waf, content_type, Some(100_000));
    tx.process_request_body(body.as_bytes());
    assert!(request_body_errored(&tx));
    assert!(
        tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None)
            .unwrap()
            .contains("body memory budget"),
        "{:?}",
        tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None)
    );
    assert!(values_of(&tx, RuleVariable::MultipartPartHeaders).is_empty());

    let mut roomy = request(&waf, content_type, None);
    roomy.process_request_body(body.as_bytes());
    assert!(!request_body_errored(&roomy));
}

#[test]
fn a_quoted_printable_part_is_charged_for_the_copy_it_decodes() {
    let waf = waf("");
    let content_type = "multipart/form-data; boundary=b";
    // A part Go's `NextPart` decodes as it reads, so the engine holds the decoded copy until the part is published,
    // where a part it does not decode is read from the body in place. Lines of 70 bytes, as an encoder writes them:
    // Go's reader takes no line over 4096 bytes. Each decodes to 68 (`=3D` is one byte), so the copy is a new text.
    let sent = format!("{}=3D\r\n", "x".repeat(67)).repeat(70);
    let decoded = format!("{}=\r\n", "x".repeat(67)).repeat(70);
    let body =
        |header: &str| format!("--b\r\nContent-Disposition: form-data; name=\"f\"\r\n{header}\r\n{sent}\r\n--b--\r\n");
    let smallest = |body: String| {
        smallest_budget(1 << 20, |budget| {
            let mut tx = request(&waf, content_type, Some(budget));
            tx.process_request_body(body.as_bytes());
            !request_body_errored(&tx) && !values_of(&tx, RuleVariable::ArgsPost).is_empty()
        })
    };
    let plain = smallest(body(""));
    let quoted_printable = smallest(body("Content-Transfer-Encoding: quoted-printable\r\n"));
    assert!(
        quoted_printable >= plain + 4_000,
        "decoding takes {quoted_printable} bytes, reading in place {plain}"
    );

    // Without a budget nothing is stopped, and what is published is the decoded body, then the body as sent.
    let mut tx = request(&waf, content_type, None);
    tx.process_request_body(body("Content-Transfer-Encoding: quoted-printable\r\n").as_bytes());
    assert!(!request_body_errored(&tx));
    assert_eq!(
        values_of(&tx, RuleVariable::ArgsPost),
        [("f".to_owned(), decoded), ("f".to_owned(), sent)]
    );
}

#[test]
fn a_quoted_printable_part_is_charged_for_both_values_it_publishes() {
    let waf = waf("");
    let content_type = "multipart/form-data; boundary=b";
    let qp = "Content-Transfer-Encoding: quoted-printable\r\n";
    let body = |data: &str| format!("--b\r\nContent-Disposition: form-data; name=\"f\"\r\n{qp}\r\n{data}\r\n--b--\r\n");
    // 3,000 bytes as sent that decode to 1,000 (`=3D` is `=`), and 3,000 that decoding does not change. The first
    // publishes the 1,000 and the 3,000 in `ARGS_POST` and in `ARGS`, the second its 3,000 in each.
    let (changed, unchanged) = (body(&"=3D".repeat(1_000)), body(&"x".repeat(3_000)));
    let smallest = |body: &str| {
        smallest_budget(1 << 20, |budget| {
            let mut tx = request(&waf, content_type, Some(budget));
            tx.process_request_body(body.as_bytes());
            !request_body_errored(&tx) && !values_of(&tx, RuleVariable::ArgsPost).is_empty()
        })
    };
    let (needs_both, needs_one) = (smallest(&changed), smallest(&unchanged));
    assert!(
        needs_both >= needs_one + 2 * 1_000,
        "two values need {needs_both} bytes, one {needs_one}"
    );

    // A part that does not fit adds neither value, and a budget that covers it adds both.
    let mut tx = request(&waf, content_type, Some(needs_both - 1));
    tx.process_request_body(changed.as_bytes());
    assert!(values_of(&tx, RuleVariable::ArgsPost).is_empty());
    let mut tx = request(&waf, content_type, Some(needs_both));
    tx.process_request_body(changed.as_bytes());
    let post = values_of(&tx, RuleVariable::ArgsPost);
    assert_eq!(post.len(), 2);
    assert_eq!(post.first().map(|(_, value)| value.len()), Some(1_000));
    assert_eq!(post.get(1).map(|(_, value)| value.len()), Some(3_000));
    assert_eq!(values_of(&tx, RuleVariable::Args), post);
}

#[test]
fn a_response_body_stops_at_the_budget_and_reports_through_the_response_variables() {
    let waf = waf("");
    let leaves: Vec<String> = (0..2_000).map(|index| format!("\"k{index}\":\"v{index}\"")).collect();
    let body = format!("{{{}}}", leaves.join(",")).into_bytes();
    let respond = |budget: Option<usize>| {
        let mut tx = json_response(&waf, budget);
        let interruption = tx.process_response_body(&body);
        (tx, interruption)
    };

    let (tx, interruption) = respond(None);
    assert!(interruption.is_none());
    assert_ne!(tx.get_variable(RuleVariable::ResBodyError, None).as_deref(), Some("1"));
    assert_eq!(values_of(&tx, RuleVariable::ResponseArgs).len(), 2_000);

    let (tx, interruption) = respond(Some(200_000));
    assert!(interruption.is_none());
    assert_eq!(tx.get_variable(RuleVariable::ResBodyError, None).as_deref(), Some("1"));
    assert_eq!(
        tx.get_variable(RuleVariable::ResBodyProcessorError, None).as_deref(),
        Some("1")
    );
    let kept = values_of(&tx, RuleVariable::ResponseArgs).len();
    assert!(0 < kept && kept < 2_000, "a prefix: {kept}");
}

#[test]
fn a_repeated_value_is_charged_for_growing_a_value_list_that_is_already_full() {
    let waf = waf("");
    let form = "application/x-www-form-urlencoded";
    let admitted = |existing: usize, budget: usize| {
        let mut tx = request(&waf, form, Some(budget));
        for _ in 0..existing {
            tx.add_post_argument("k", "v");
        }
        tx.process_request_body(b"k=w");
        (values_of(&tx, RuleVariable::ArgsPost).len(), request_body_errored(&tx))
    };
    // 1,024 values fill the list exactly, so one more grows it by a quarter in both maps: far over 1 KiB.
    assert_eq!(
        admitted(1024, 1024),
        (1024, true),
        "the growth is refused before it happens"
    );
    // With a spare slot only the new entry is charged, which a 1 KiB budget covers.
    assert_eq!(admitted(1000, 1024), (1001, false));
    // A budget that covers the growth admits the value.
    assert_eq!(admitted(1024, 1_000_000), (1025, false));
}

/// The engine with `rules`, as [`waf`] makes it, and the connector's policy of not accepting file uploads.
fn waf_rejecting_uploads(rules: &str) -> Waf {
    let mut parser = Parser::new();
    parser
        .from_string(&format!(
            "SecRequestBodyAccess On\nSecArgumentsLimit 100000\n\
             SecRule REQUEST_HEADERS:Content-Type \"^text/plain\" \
                 \"id:900003,phase:1,t:none,pass,nolog,ctl:requestBodyProcessor=MULTIPART\"\n{rules}"
        ))
        .unwrap();
    parser.config_mut().reject_multipart_file_uploads = true;
    parser.into_waf().unwrap()
}

/// A multipart body of `fields` small fields, then `last`.
fn fields_then(fields: usize, last: &str) -> String {
    let mut body = String::new();
    for index in 0..fields {
        write!(
            body,
            "--b\r\nContent-Disposition: form-data; name=\"f{index}\"\r\n\r\nvalue{index}\r\n"
        )
        .unwrap();
    }
    body.push_str(last);
    body
}

#[test]
fn a_multipart_body_the_parser_stopped_in_cannot_carry_an_unchecked_upload_past_the_ban() {
    let waf = waf_rejecting_uploads("");
    let content_type = "multipart/form-data; boundary=b";
    let upload = "--b\r\nContent-Disposition: form-data; name=\"up\"; filename=\"x.txt\"\r\n\r\nPAYLOAD\r\n--b--\r\n";
    let status = |body: &str, budget: Option<usize>| {
        let mut tx = waf.new_transaction();
        tx.set_body_memory_budget(budget);
        tx.add_request_header("Content-Type", content_type);
        tx.process_request_headers();
        let interruption = tx.process_request_body(body.as_bytes());
        (
            interruption.map(|interruption| interruption.status),
            request_body_errored(&tx),
            tx.request_body_stopped_by_memory_budget(),
        )
    };

    // The published prefix holds the upload: refused, as before.
    assert_eq!(status(&fields_then(2, upload), None), (Some(413), false, false));
    // No upload anywhere and nothing stopped the parser: passes.
    assert_eq!(status(&fields_then(2, "--b--\r\n"), None), (None, false, false));

    // The reading budget runs out before the last part, which is the upload: no rule reads REQBODY_ERROR here, and
    // the body still must not pass with a part nobody looked at.
    let body = fields_then(300, upload);
    assert_eq!(status(&body, Some(60_000)), (Some(413), true, true));
    assert_eq!(status(&body, None), (Some(413), false, false));
    // An upload read before the budget ran out is refused at once, and the stop is still reported.
    let first = format!("{}{}", upload.replace("--b--\r\n", ""), fields_then(300, "--b--\r\n"));
    assert_eq!(status(&first, Some(60_000)), (Some(413), false, true));

    // A malformed part stops the parser the same way, in front of an upload it never reads.
    let malformed = fields_then(1, &format!("--b\r\nBad Header\r\n\r\nx\r\n{upload}"));
    assert_eq!(status(&malformed, None), (Some(413), true, false));

    // A body that is not multipart at all has no part for an upload to hide in.
    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "text/plain");
    tx.process_request_headers();
    assert!(tx.process_request_body(upload.as_bytes()).is_none());
    assert!(request_body_errored(&tx), "the forced processor still reports it");
}

/// What `body` does to a request under `waf`, as its status and whether the body was reported as in error.
fn status_of(waf: &Waf, content_type: &str, body: &[u8]) -> (Option<u16>, bool, bool) {
    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", content_type);
    tx.process_request_headers();
    let interruption = tx.process_request_body(body);
    (
        interruption.map(|interruption| interruption.status),
        request_body_errored(&tx),
        tx.request_body_stats().truncated,
    )
}

#[test]
fn a_multipart_body_cut_by_the_limit_is_refused_where_uploads_are_banned_whatever_it_shows() {
    let content_type = "multipart/form-data; boundary=b";
    let cut = "SecRequestBodyLimit 120\nSecRequestBodyLimitAction ProcessPartial";
    let banned = waf_rejecting_uploads(cut);
    let upload = "--b\r\nContent-Disposition: form-data; name=\"x\"; filename=\"evil.php\"\r\n\r\nPAYLOAD\r\n--b--\r\n";

    // The file starts after the cut: the parser sees a field and no error, and the file was never looked at.
    let hidden = fields_then(2, upload);
    assert!(hidden.len() > 120);
    assert_eq!(
        status_of(&banned, content_type, hidden.as_bytes()),
        (Some(413), false, true)
    );

    // The same body, whatever the part the cut leaves: a body cut before its closing delimiter can always hide
    // a file in the bytes that were discarded, so with no file in the prefix it is refused too.
    let fields_only = fields_then(8, "--b--\r\n");
    assert!(fields_only.len() > 120);
    assert_eq!(
        status_of(&banned, content_type, fields_only.as_bytes()),
        (Some(413), false, true)
    );

    // A body that is not cut passes, and one that ends exactly at the limit with its closing delimiter in place has
    // nothing hidden: the limit was reached and nothing was discarded.
    let closed = fields_then(1, "--b--\r\n");
    assert_eq!(
        status_of(&banned, content_type, closed.as_bytes()),
        (None, false, false)
    );
    let exact = waf_rejecting_uploads(&format!(
        "SecRequestBodyLimit {}\nSecRequestBodyLimitAction ProcessPartial",
        closed.len()
    ));
    assert_eq!(status_of(&exact, content_type, closed.as_bytes()), (None, false, false));

    // Where uploads are not banned nothing changes: the cut body is inspected up to its last part and passes.
    let mut parser = Parser::new();
    parser
        .from_string(&format!("SecRequestBodyAccess On\nSecArgumentsLimit 100000\n{cut}"))
        .unwrap();
    let open = parser.into_waf().unwrap();
    assert_eq!(status_of(&open, content_type, hidden.as_bytes()), (None, false, true));
}

#[test]
fn error_messages_quote_an_excerpt_under_a_budget_and_all_of_it_without_one() {
    let waf = waf("");
    let name = "b".repeat(5000);
    let body = format!("<a></{name}>");
    let message_of = |budget: Option<usize>| {
        let mut tx = request(&waf, "text/xml", budget);
        tx.process_request_body(body.as_bytes());
        assert!(request_body_errored(&tx));
        let message = String::clone(&tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None).unwrap());
        (message, tx.body_memory_bytes())
    };
    // Go quotes the name whole, which is what the engine does by default.
    let (full, retained) = message_of(None);
    assert!(full.contains(&name), "{} bytes", full.len());
    assert!(
        retained >= 2 * full.len(),
        "the messages are retained and counted: {retained}"
    );
    // With a budget the message keeps a short excerpt of the name and says so, and the messages are accounted for.
    let (short, retained) = message_of(Some(1 << 20));
    assert!(short.len() < 300, "{} bytes", short.len());
    assert!(short.contains("</bbbb") && short.contains("..."), "{short}");
    assert!(retained >= 2 * short.len());
}

#[test]
fn a_temporary_upload_is_charged_for_its_path_only_when_it_is_written() {
    let mut body = String::new();
    for index in 0..30 {
        write!(
            body,
            "--b\r\nContent-Disposition: form-data; name=\"up{index}\"; filename=\"x{index}.txt\"\r\n\r\nPAYLOAD\r\n"
        )
        .unwrap();
    }
    body.push_str("--b--\r\n");
    // The smallest budget that admits the thirty uploads with up to `limit` of them written under `directory`.
    let needed = |directory: &str, limit: usize| {
        let mut parser = Parser::new();
        parser.from_string("SecRequestBodyAccess On").unwrap();
        parser.config_mut().upload_dir = directory.to_owned();
        parser.config_mut().upload_file_limit = limit;
        let waf = parser.into_waf().unwrap();
        smallest_budget(1_000_000, |budget| {
            let mut tx = request(&waf, "multipart/form-data; boundary=b", Some(budget));
            tx.process_request_body(body.as_bytes());
            !tx.request_body_stopped_by_memory_budget()
        })
    };
    // Past the limit every upload is still published, but none is written, so its directory costs nothing.
    let long_directory = format!("/nonexistent/{}", "d".repeat(300));
    assert_eq!(needed("/nonexistent-a", 0), needed(&long_directory, 0));
    // A file written keeps its path in `FILES_TMPNAMES` and for cleanup, each with the file name the engine adds.
    let directory = tempfile::tempdir().unwrap();
    let (short, long) = (directory.path(), directory.path().join("d".repeat(200)));
    std::fs::create_dir(&long).unwrap();
    let longer = long.as_os_str().len() - short.as_os_str().len();
    let (short_need, long_need) = (needed(short.to_str().unwrap(), 30), needed(long.to_str().unwrap(), 30));
    assert!(
        long_need >= short_need + 29 * 2 * longer,
        "a directory {longer} bytes longer raised the smallest budget from {short_need} to {long_need}"
    );
}

#[test]
fn a_dense_json_array_is_refused_only_by_a_budget_near_what_it_holds_and_a_response_pays_for_one_collection_less() {
    let waf = waf("");
    let leaves = 50_000;
    let body = format!("[{}1]", "1,".repeat(leaves));
    let request_json = |budget: Option<usize>, body: &str| {
        let mut tx = request(&waf, "application/json", budget);
        tx.process_request_body(body.as_bytes());
        tx
    };
    let respond = |budget: usize, body: &str| {
        let mut tx = json_response(&waf, Some(budget));
        tx.process_response_body(body.as_bytes());
        tx.get_variable(RuleVariable::ResBodyError, None).as_deref() == Some("1")
    };

    let unlimited = request_json(None, &body);
    assert_eq!(values_of(&unlimited, RuleVariable::ArgsPost).len(), leaves + 2);
    let retained = unlimited.body_memory_bytes();

    // Half as much as the transaction measures itself holding is refused, and twice as much is plenty: a body is
    // not refused for the worst case of its entries when a budget comfortably covers what they take.
    assert!(request_body_errored(&request_json(Some(retained / 2), &body)));
    let roomy = request_json(Some(2 * retained), &body);
    assert!(
        !request_body_errored(&roomy),
        "{retained} bytes held, {} budgeted",
        2 * retained
    );
    assert_eq!(values_of(&roomy, RuleVariable::ArgsPost).len(), leaves + 2);

    // A response is published into `RESPONSE_ARGS` alone, so the same body fits a smaller budget than as a request.
    let small = format!("[{}1]", "1,".repeat(2_000));
    let as_request = smallest_budget(1 << 28, |budget| {
        !request_body_errored(&request_json(Some(budget), &small))
    });
    let as_response = smallest_budget(1 << 28, |budget| !respond(budget, &small));
    assert!(
        as_response * 4 < as_request * 3,
        "a response needs {as_response} and a request {as_request}: it holds one collection fewer"
    );
}

#[test]
fn a_member_past_the_argument_limit_ends_the_json_walk_as_one_even_when_the_budget_could_not_unescape_it() {
    let waf = waf("SecArgumentsLimit 2");
    let big = "x".repeat(100_000);
    let outcome = |body: &str, budget: Option<usize>| {
        let mut tx = request(&waf, "application/json", budget);
        tx.process_request_body(body.as_bytes());
        (
            tx.get_variable(RuleVariable::ArgumentsLimitReached, None).as_deref() == Some("1"),
            request_body_errored(&tx),
            values_of(&tx, RuleVariable::ArgsPost).len(),
        )
    };
    // An escaped key or an escaped value after the second member: the limit is reached, as it is without a budget,
    // and nothing in the body was refused for memory.
    for body in [
        format!("{{\"a\":1,\"b\":2,\"c\\n{big}\":3}}"),
        format!("{{\"a\":1,\"b\":2,\"c\":\"\\n{big}\"}}"),
        format!("[1,2,\"\\n{big}\"]"),
    ] {
        assert_eq!(outcome(&body, None), (true, false, 2), "{body:.30}");
        assert_eq!(outcome(&body, Some(20_000)), (true, false, 2), "{body:.30}");
    }
    // A document that ends at the limit has nothing past it, whatever its budget.
    // (An array also publishes its length.)
    for (body, values) in [("{\"a\":1,\"b\":2}", 2), ("[1,2]", 3)] {
        assert_eq!(outcome(body, None), (false, false, values));
        assert_eq!(outcome(body, Some(20_000)), (false, false, values), "{body}");
    }
    // A member that is not past the limit and does not fit is still the budget's to refuse.
    let (limit_reached, errored, _) = outcome(&format!("{{\"a\":1,\"c\\n{big}\":3}}"), Some(20_000));
    assert!(!limit_reached && errored);
}

#[test]
fn the_xml_floods_a_connector_budget_admits_publish_no_more_than_the_argument_limit() {
    // The densest shapes, sized as the connector's parse budget on an idle 64 MiB root admitted them: each value
    // costs every rule that reads XML a full evaluation, and nothing but the argument limit bounds their number.
    const ROOT: usize = 64 << 20;
    let waf = waf("SecArgumentsLimit 1000");
    let flood = |head: &[u8], unit: &[u8], count: usize, tail: &[u8]| [head, &unit.repeat(count), tail].concat();
    for (label, body) in [
        ("bare attributes in one tag", flood(b"<r", b" b", 528_211, b"></r>")),
        ("text values", flood(b"<r>", b"1<i/>", 200_000, b"</r>")),
        (
            "attack values",
            flood(
                b"<r>",
                b"<i>../../etc/passwd;cat /etc/shadow' or 1=1-- </i>",
                20_000,
                b"</r>",
            ),
        ),
    ] {
        for budget in [None, Some(ROOT - 3 * body.len())] {
            let mut tx = request(&waf, "text/xml", budget);
            tx.process_request_body(&body);
            let published = values_of(&tx, RuleVariable::RequestXML).len();
            assert!(published <= 1000, "{label}, {budget:?}: {published} values");
            assert!(request_body_errored(&tx), "{label}, {budget:?}");
            assert_eq!(
                tx.get_variable(RuleVariable::ArgumentsLimitReached, None).as_deref(),
                Some("1"),
                "{label}, {budget:?}"
            );
            assert!(!tx.request_body_stopped_by_memory_budget(), "{label}, {budget:?}");
        }
    }
}

#[test]
fn a_multipart_field_past_the_argument_limit_costs_the_budget_nothing() {
    let waf = waf("SecArgumentsLimit 1");
    let needed = |second: &str| {
        let body = format!(
            "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n\
             --b\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n{second}\r\n--b--\r\n"
        );
        smallest_budget(1 << 22, |budget| {
            let mut tx = request(&waf, "multipart/form-data; boundary=b", Some(budget));
            tx.process_request_body(body.as_bytes());
            !tx.request_body_stopped_by_memory_budget()
        })
    };
    // The limit drops `b`, so how large its value is cannot change what the body needs.
    assert_eq!(needed(&"x".repeat(400 * 1024)), needed("1"));
}

#[test]
fn a_body_that_ends_at_the_limit_after_a_delimiter_is_not_cut_and_one_byte_more_is() {
    let content_type = "multipart/form-data; boundary=b";
    // A field, then a delimiter line that is not the closing one: the body ends where the limit does.
    let body = "--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n--b\r\n";
    assert_eq!(body.len(), 57);
    let partial = |limit: usize| {
        waf_rejecting_uploads(&format!(
            "SecRequestBodyLimit {limit}\nSecRequestBodyLimitAction ProcessPartial"
        ))
    };
    // Nothing was discarded, so no part can be hiding past the end: the ban has nothing to refuse.
    assert_eq!(
        status_of(&partial(body.len()), content_type, body.as_bytes()),
        (None, false, false)
    );
    // One byte over the limit is cut, and what was cut could be a file.
    assert_eq!(
        status_of(&partial(body.len() - 1), content_type, body.as_bytes()),
        (Some(413), false, true)
    );
}

#[test]
fn only_a_processor_that_stopped_for_the_budget_says_so_whatever_the_body_quotes() {
    let waf = waf("");
    // A declaration that quotes the words of the budget's own message, with no budget set.
    let spoof = b"<?xml version=\"x body memory budget x\"?><r/>";
    let mut tx = request(&waf, "text/xml", None);
    tx.process_request_body(spoof);
    assert!(request_body_errored(&tx), "the declaration is a syntax error");
    assert!(
        tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None)
            .is_some_and(|message| message.contains("body memory budget")),
        "and the message quotes it"
    );
    assert!(!tx.request_body_stopped_by_memory_budget());

    // The same under a budget that is not what stopped it.
    let mut tx = request(&waf, "text/xml", Some(1 << 20));
    tx.process_request_body(spoof);
    assert!(request_body_errored(&tx));
    assert!(!tx.request_body_stopped_by_memory_budget());

    // And a stop for the budget is still reported, by each processor.
    let xml: String = format!("<r>{}</r>", "<i>1</i>".repeat(2000));
    let json = format!("[{}1]", "1,".repeat(2000));
    let form = pairs(2000);
    let multipart = "multipart/form-data; boundary=b";
    let fields = fields_then(2000, "--b--\r\n");
    // A content type whose parameters alone are more than the budget, for a body of one field.
    let field = fields_then(1, "--b--\r\n");
    let parameters = format!(
        "{multipart}{}",
        (0..3_000).map(|index| format!("; p{index}=v")).collect::<String>()
    );
    // Parts that are cheap to read and dear to publish, then a malformed one: the budget runs out while the parts
    // are published, and the parser's error is the one reported.
    let then_malformed = (0..100)
        .map(|index| {
            format!(
                "--b\r\nContent-Disposition: form-data; name=\"f{index}\"\r\n\r\n{}\r\n",
                "v".repeat(2000)
            )
        })
        .chain([String::from("--b\r\nBad Header\r\n\r\nx\r\n--b--\r\n")])
        .collect::<String>();
    let cases: [(&str, &[u8], usize, &str); 6] = [
        ("text/xml", xml.as_bytes(), 20_000, "budget"),
        ("application/json", json.as_bytes(), 20_000, "budget"),
        ("application/x-www-form-urlencoded", &form, 20_000, "budget"),
        (multipart, fields.as_bytes(), 20_000, "budget"),
        (&parameters, field.as_bytes(), 20_000, "budget"),
        (multipart, then_malformed.as_bytes(), 200_000, "missing colon"),
    ];
    for (content_type, body, budget, reported) in cases {
        let mut tx = request(&waf, content_type, Some(budget));
        tx.process_request_body(body);
        let message = tx.get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None).unwrap();
        assert!(message.contains(reported), "{content_type:.40}: {message}");
        assert!(tx.request_body_stopped_by_memory_budget(), "{content_type:.40}");
    }
}

/// `count` rules that each match the one large field of a form, keep the value in their match and copy it to a `TX`
/// key of their own, and a last rule that says whether the phase got to it.
fn copying_rules(count: usize, mode: &str) -> String {
    let rules: String = (0..count)
        .map(|index| {
            format!(
                "SecRule ARGS_POST \"@rx .\" \"id:{},phase:2,pass,nolog,msg:'copy',setvar:tx.copy{index}=%{{MATCHED_VAR}}\"\n",
                100 + index
            )
        })
        .collect();
    format!("SecRuleEngine {mode}\n{rules}SecAction \"id:999,phase:2,pass,nolog,setvar:tx.reached=1\"\n")
}

/// A transaction of `waf` that has read a form of one field of `size` bytes, under `budget`, and its body processed.
fn form_after_rules(
    waf: &Waf,
    size: usize,
    budget: Option<usize>,
) -> (Transaction, Option<coraza::transaction::Interruption>) {
    let mut tx = request(waf, "application/x-www-form-urlencoded", budget);
    let interruption = tx.process_request_body(format!("k={}", "v".repeat(size)).as_bytes());
    (tx, interruption)
}

#[test]
fn rules_that_would_keep_more_than_the_budget_has_left_stop_the_phase_and_nothing_runs_after_the_stop() {
    const SIZE: usize = 20_000;
    let parse_only = waf("");
    let (reference, _) = form_after_rules(&parse_only, SIZE, None);
    let parse = smallest_budget(1 << 30, |budget| {
        !request_body_errored(&form_after_rules(&parse_only, SIZE, Some(budget)).0)
    });

    // What forty such rules retain, without a budget: all of them match, and each leaves a copy in TX.
    let with_rules = waf(&copying_rules(40, "On"));
    let (unlimited, interruption) = form_after_rules(&with_rules, SIZE, None);
    assert!(interruption.is_none() && !unlimited.rule_evaluation_stopped_by_memory_budget());
    assert_eq!(unlimited.matched_rules().len(), 41);
    let retained = unlimited.body_memory_bytes() - reference.body_memory_bytes();
    assert!(
        retained > 40 * SIZE,
        "{retained}: forty copies of the value and forty matches of it"
    );

    // A budget with room for what they retain lets them finish, as having none does.
    let (fits, interruption) = form_after_rules(&with_rules, SIZE, Some(parse + 2 * retained));
    assert!(interruption.is_none() && !fits.rule_evaluation_stopped_by_memory_budget());
    assert_eq!(fits.matched_rules().len(), 41);
    assert_eq!(
        fits.get_variable(RuleVariable::TX, Some("copy39")),
        unlimited.get_variable(RuleVariable::TX, Some("copy39")),
        "the values the rules set are the same"
    );
    assert_eq!(
        fits.get_variable(RuleVariable::TX, Some("reached")).as_deref(),
        Some("1")
    );

    // With room for about half of them the phase stops: 503, nothing records or runs after it, and what is held
    // stays within what the budget allowed.
    let (stopped, interruption) = form_after_rules(&with_rules, SIZE, Some(parse + retained / 2));
    let interruption = interruption.unwrap();
    assert_eq!(
        (interruption.status, interruption.rule_id, interruption.action.as_str()),
        (503, 0, "deny")
    );
    assert_eq!(interruption.data, "rule evaluation memory budget exhausted");
    assert!(stopped.rule_evaluation_stopped_by_memory_budget());
    let recorded = stopped.matched_rules().len();
    assert!((5..35).contains(&recorded), "{recorded} of the 41 rules were recorded");
    assert_eq!(
        stopped.get_variable(RuleVariable::TX, Some("reached")),
        None,
        "no rule ran after the stop"
    );
    assert!(
        stopped.body_memory_bytes() <= reference.body_memory_bytes() + parse + retained / 2,
        "the transaction holds {} against the {} the budget allowed",
        stopped.body_memory_bytes(),
        reference.body_memory_bytes() + parse + retained / 2
    );
    assert_eq!(
        stopped
            .get_variable(RuleVariable::TX, Some(&format!("copy{}", recorded - 1)))
            .map(|value| value.len()),
        Some(SIZE),
        "what the rules before the stop did is kept"
    );

    // A budget that cannot hold even the first match stops at it.
    let (first, interruption) = form_after_rules(&with_rules, SIZE, Some(parse));
    assert!(interruption.is_some() && first.rule_evaluation_stopped_by_memory_budget());
    assert_eq!(first.matched_rules().len(), 0);
}

#[test]
fn in_detection_only_the_stop_is_a_recorded_would_be_interruption_and_the_phase_still_stops() {
    const SIZE: usize = 20_000;
    let parse_only = waf("");
    let parse = smallest_budget(1 << 30, |budget| {
        !request_body_errored(&form_after_rules(&parse_only, SIZE, Some(budget)).0)
    });
    let with_rules = waf(&copying_rules(40, "DetectionOnly"));
    let (stopped, interruption) = form_after_rules(&with_rules, SIZE, Some(parse + 100_000));
    assert!(interruption.is_none(), "DetectionOnly interrupts nothing");
    let would_be = stopped.would_be_interruption().unwrap();
    assert_eq!(
        (would_be.status, would_be.data.as_str()),
        (503, "rule evaluation memory budget exhausted")
    );
    assert!(stopped.rule_evaluation_stopped_by_memory_budget(), "the host can tell");
    assert!(stopped.matched_rules().len() < 40);
    assert_eq!(
        stopped.get_variable(RuleVariable::TX, Some("reached")),
        None,
        "no rule ran after the stop"
    );
}

/// Rules shaped as CRS's are: a capture, a `logdata` that expands what matched, scores added with `setvar`, a chain
/// that holds back until its second link matches, and a blocking rule that reads the score.
const SCORING_RULES: &str = "\
SecAction \"id:901,phase:1,pass,nolog,setvar:tx.anomaly_score=0,setvar:tx.hits=0\"\n\
SecRule ARGS|XML:/*|ARGS_NAMES \"@rx (?i)select\\s+(\\w+)\" \"id:942100,phase:2,pass,capture,t:none,t:urlDecodeUni,\
msg:'SQL Injection',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
setvar:tx.anomaly_score=+5,setvar:tx.hits=+1,setvar:'tx.sqli_%{MATCHED_VAR_NAME}=%{TX.1}'\"\n\
SecRule ARGS \"@rx ^\\w+$\" \"id:920100,phase:2,pass,chain,msg:'Short word',logdata:'%{MATCHED_VAR}'\"\n\
  SecRule ARGS \"@rx secret\" \"t:none,setvar:tx.anomaly_score=+2\"\n\
SecRule TX:ANOMALY_SCORE \"@ge 5\" \"id:949110,phase:2,deny,status:403,msg:'Blocked',logdata:'%{TX.ANOMALY_SCORE}'\"\n";

#[test]
fn a_budget_that_fits_changes_neither_what_matches_nor_the_scores_nor_the_verdict() {
    let with_rules = waf(SCORING_RULES);
    let long_attack = format!("a=select {}&b=ok&c=secret", "x".repeat(30_000));
    let json = r#"{"user":"select name","note":"hello","items":["select 1","fine","secret"]}"#;
    let xml = "<r><a>select q</a><b secret=\"1\">fine</b><c>select z</c></r>";
    let requests: [(&str, &str); 7] = [
        ("application/x-www-form-urlencoded", "a=hello&b=world"),
        ("application/x-www-form-urlencoded", "a=select+name&b=word&c=secret"),
        (
            "application/x-www-form-urlencoded",
            "q=select%20a&r=select%20b&s=fine&t=secret",
        ),
        ("application/x-www-form-urlencoded", &long_attack),
        ("application/json", json),
        ("text/xml", xml),
        ("application/x-www-form-urlencoded", ""),
    ];
    let (mut matches, mut blocked) = (0, 0);
    for (content_type, body) in requests {
        let run = |budget: Option<usize>| {
            let mut tx = request(&with_rules, content_type, budget);
            let interruption = tx.process_request_body(body.as_bytes());
            (tx, interruption)
        };
        let (plain, plain_interruption) = run(None);
        matches += plain
            .matched_rules()
            .iter()
            .map(|rule| rule.matches.len())
            .sum::<usize>();
        blocked += usize::from(plain_interruption.is_some());
        for budget in [1 << 20, 64 << 20] {
            let (budgeted, interruption) = run(Some(budget));
            let label = format!("{content_type} {body:.30} at {budget}");
            assert!(!budgeted.rule_evaluation_stopped_by_memory_budget(), "{label}");
            assert_eq!(interruption, plain_interruption, "{label}");
            assert_eq!(budgeted.matched_rules().len(), plain.matched_rules().len(), "{label}");
            for (left, right) in budgeted.matched_rules().iter().zip(plain.matched_rules()) {
                assert_eq!(left.rule.id(), right.rule.id(), "{label}");
                assert_eq!(left.matches, right.matches, "{label}: rule {}", left.rule.id());
            }
            for key in ["anomaly_score", "hits", "0", "1"] {
                assert_eq!(
                    budgeted.get_variable(RuleVariable::TX, Some(key)),
                    plain.get_variable(RuleVariable::TX, Some(key)),
                    "{label}: TX:{key}"
                );
            }
            assert_eq!(
                budgeted.body_memory_bytes(),
                plain.body_memory_bytes(),
                "{label}: the same is held"
            );
        }
    }
    assert!(
        matches >= 10 && (3..7).contains(&blocked),
        "{matches} matches, {blocked} blocked: the rules do their work"
    );
}

#[test]
fn what_a_rule_held_and_did_not_record_is_given_back_when_it_is_done() {
    const SIZE: usize = 20_000;
    let parse_only = waf("");
    let parse = smallest_budget(1 << 30, |budget| {
        !request_body_errored(&form_after_rules(&parse_only, SIZE, Some(budget)).0)
    });
    // Room for the copies one match makes of the value (its record, its entry in `MATCHED_VARS`, `MATCHED_VAR`) and
    // not for a hundred of them.
    let budget = parse + 5 * SIZE;

    // Two hundred chains whose first link matches the value and whose second link never does: each holds the
    // value's match while it is evaluated, and records nothing.
    let chained: String = (0..200)
        .map(|index| {
            format!(
                "SecRule ARGS_POST \"@rx .\" \"id:{},phase:2,pass,nolog,chain\"\n  SecRule ARGS_POST \"@rx NEVER\" \"t:none\"\n",
                100 + index
            )
        })
        .collect();
    let (tx, interruption) = form_after_rules(&waf(&chained), SIZE, Some(budget));
    assert!(
        interruption.is_none() && !tx.rule_evaluation_stopped_by_memory_budget(),
        "dropped matches are given back"
    );
    assert!(tx.matched_rules().is_empty());

    // The same rules without the second link keep their matches, and the budget does not hold them.
    let kept: String = (0..200)
        .map(|index| {
            format!(
                "SecRule ARGS_POST \"@rx .\" \"id:{},phase:2,pass,nolog\"\n",
                100 + index
            )
        })
        .collect();
    let (tx, interruption) = form_after_rules(&waf(&kept), SIZE, Some(budget));
    assert!(interruption.is_some() && tx.rule_evaluation_stopped_by_memory_budget());
    assert!(tx.matched_rules().len() < 20, "{} recorded", tx.matched_rules().len());

    // A rule that matches twenty thousand values records each, and copies each to `MATCHED_VARS`: four megabytes do
    // not hold them.
    let many = "SecArgumentsLimit 100000\nSecRule ARGS_POST \"@rx .\" \"id:5,phase:2,pass,nolog\"\n";
    let mut tx = request(&waf(many), "application/x-www-form-urlencoded", Some(parse + 4_000_000));
    tx.process_request_body(&pairs(20_000));
    assert!(
        tx.rule_evaluation_stopped_by_memory_budget(),
        "twenty thousand matches of one rule are over four megabytes"
    );
}

#[test]
fn the_rules_of_a_response_body_phase_are_bounded_alike() {
    const SIZE: usize = 20_000;
    let rules = copying_rules(40, "On")
        .replace("phase:2", "phase:4")
        .replace("ARGS_POST", "RESPONSE_BODY");
    let with_rules = waf(&format!("SecResponseBodyMimeType text/plain\n{rules}"));
    let respond = |budget: Option<usize>| {
        let mut tx = with_rules.new_transaction();
        tx.process_request_headers();
        tx.process_request_body(b"");
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");
        tx.set_body_memory_budget(budget);
        let interruption = tx.process_response_body("v".repeat(SIZE).as_bytes());
        (tx, interruption)
    };

    let (unlimited, interruption) = respond(None);
    assert!(interruption.is_none() && !unlimited.rule_evaluation_stopped_by_memory_budget());
    assert_eq!(unlimited.matched_rules().len(), 41);
    let (fits, interruption) = respond(Some(100 << 20));
    assert!(interruption.is_none() && !fits.rule_evaluation_stopped_by_memory_budget());
    assert_eq!(fits.matched_rules().len(), 41);

    let (stopped, interruption) = respond(Some(400_000));
    let interruption = interruption.unwrap();
    assert_eq!(
        (interruption.status, interruption.data.as_str()),
        (503, "rule evaluation memory budget exhausted")
    );
    assert!(stopped.rule_evaluation_stopped_by_memory_budget());
    assert!(
        (1..20).contains(&stopped.matched_rules().len()),
        "{} recorded",
        stopped.matched_rules().len()
    );
    assert_eq!(stopped.get_variable(RuleVariable::TX, Some("reached")), None);
}

#[test]
fn a_parse_the_budget_stopped_leaves_the_rules_room_to_deny_on_the_body_error() {
    const SIZE: usize = 20_000;
    // The baseline's rule 200002, which answers a body error before the connector does.
    let rules = "SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,t:none,deny,status:400,msg:'Failed to parse request body',\
                 logdata:'%{reqbody_error_msg}',setvar:tx.anomaly_score=+5\"\n";
    let parse_only = waf("");
    let with_rules = waf(rules);
    let parse = smallest_budget(1 << 30, |budget| {
        !request_body_errored(&form_after_rules(&parse_only, SIZE, Some(budget)).0)
    });
    // A budget the parse cannot finish in leaves the rules nothing of their own: the denial still gets through.
    let (tx, interruption) = form_after_rules(&with_rules, SIZE, Some(parse - 1));
    assert!(request_body_errored(&tx) && tx.request_body_stopped_by_memory_budget());
    let interruption = interruption.unwrap();
    assert_eq!((interruption.status, interruption.rule_id), (400, 200_002));
    assert!(
        !tx.rule_evaluation_stopped_by_memory_budget(),
        "the rule that answers is not the stop"
    );
    assert_eq!(
        tx.get_variable(RuleVariable::TX, Some("anomaly_score")).as_deref(),
        Some("5")
    );
}

/// Every way a rule holds the values it selects, each as a policy: the copies `multiMatch` makes at each stage, the
/// snapshot of `TX` that its own `setvar`s must not change, a chain evaluated in more than one phase, and values that
/// match nothing.
fn selection_policies() -> Vec<(&'static str, String)> {
    let copies = copying_rules(3, "On");
    vec![
        (
            "multiMatch",
            "SecRule ARGS_POST \"@rx v\" \"id:300,phase:2,pass,nolog,multiMatch,t:lowercase,t:urlDecodeUni,msg:'mm',\
             setvar:tx.mm=+1\"\n"
                .to_owned(),
        ),
        (
            "a rule that selects TX, whose own setvar must not change what it selects",
            format!("{copies}SecRule TX:/^copy/ \"@rx v\" \"id:301,phase:2,pass,nolog,setvar:tx.seen=+1\"\n"),
        ),
        (
            "a chain",
            "SecRule ARGS_POST \"@rx v\" \"id:302,phase:2,pass,nolog,chain,msg:'%{MATCHED_VAR_NAME}'\"\n  \
             SecRule ARGS_POST \"@rx vv\" \"t:none,setvar:tx.chained=+1\"\n"
                .to_owned(),
        ),
        (
            "no match",
            "SecRule ARGS_POST \"@rx NEVER\" \"id:303,phase:2,pass,nolog\"\n".to_owned(),
        ),
    ]
}

#[test]
fn every_way_a_rule_holds_the_values_it_selects_is_charged_and_changes_nothing_below_the_budget() {
    const SIZE: usize = 5_000;
    let parse_only = waf("");
    let parse = smallest_budget(1 << 30, |budget| {
        !request_body_errored(&form_after_rules(&parse_only, SIZE, Some(budget)).0)
    });
    // `multiphase_evaluation` is what the connector compiles with: the duplicate check copies each match.
    for multiphase in [false, true] {
        for (label, rules) in selection_policies() {
            let mut parser = Parser::new();
            parser.config_mut().multiphase_evaluation = multiphase;
            parser
                .from_string(&format!(
                    "SecRequestBodyAccess On\nSecRequestBodyLimit 134217728\nSecArgumentsLimit 100000\nSecRuleEngine On\n{rules}"
                ))
                .unwrap();
            let with_rules = parser.into_waf().unwrap();
            let (plain, _) = form_after_rules(&with_rules, SIZE, None);
            let (fits, interruption) = form_after_rules(&with_rules, SIZE, Some(parse + (50 << 20)));
            assert!(
                interruption.is_none() && !fits.rule_evaluation_stopped_by_memory_budget(),
                "{label} (multiphase {multiphase})"
            );
            assert_eq!(fits.matched_rules().len(), plain.matched_rules().len(), "{label}");
            for key in ["mm", "seen", "chained", "copy2"] {
                assert_eq!(
                    fits.get_variable(RuleVariable::TX, Some(key)),
                    plain.get_variable(RuleVariable::TX, Some(key)),
                    "{label}: TX:{key}"
                );
            }
            // What the rules hold is charged: a budget with no room for the value's copies stops them, unless the
            // policy matches nothing, which holds nothing.
            let (tight, _) = form_after_rules(&with_rules, SIZE, Some(parse + SIZE));
            assert_eq!(
                tight.rule_evaluation_stopped_by_memory_budget(),
                !plain.matched_rules().is_empty(),
                "{label} (multiphase {multiphase})"
            );
        }
    }
}

#[test]
fn a_rule_whose_own_record_does_not_fit_stops_the_phase_and_never_denies() {
    // The record of a match copies the URI, so a long one makes the record the large charge of the rule.
    let uri = format!("/x?{}", "u".repeat(30_000));
    for mode in ["On", "DetectionOnly"] {
        let with_rules = waf(&format!(
            "SecRuleEngine {mode}\n\
             SecRule ARGS_POST \"@rx .\" \"id:10,phase:2,deny,status:403,msg:'x',setvar:tx.marker=1\"\n\
             SecAction \"id:11,phase:2,pass,nolog,setvar:tx.after=1\"\n"
        ));
        let mut stopped_at_the_record = 0;
        for budget in (0..120_000).step_by(512) {
            let mut tx = with_rules.new_transaction();
            tx.process_uri(&uri, "POST", "HTTP/1.1");
            tx.set_body_memory_budget(Some(budget));
            tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
            tx.process_request_headers();
            let interruption = tx.process_request_body(b"a=1");
            let label = format!("{mode} at {budget}");
            if tx.request_body_stopped_by_memory_budget() {
                // The parse did not fit: no rule saw an argument.
                continue;
            }
            let reported = interruption.as_ref().or_else(|| tx.would_be_interruption());
            let recorded = tx.matched_rules().iter().any(|rule| rule.rule.id() == 10);
            if tx.rule_evaluation_stopped_by_memory_budget() {
                let reported = reported.unwrap();
                // A rule recorded before the stop keeps the denial it made (DetectionOnly goes on to the next rule,
                // and the first would-be interruption stands); a rule stopped at its own record denies nothing.
                let expected = if recorded { (403, 10) } else { (503, 0) };
                assert_eq!((reported.status, reported.rule_id), expected, "{label}");
                if !recorded {
                    assert_eq!(
                        tx.get_variable(RuleVariable::TX, Some("after")),
                        None,
                        "{label}: no rule ran after"
                    );
                }
                // The marker is the rule's own action, which runs once its match is found and before its record is
                // made: a stop with the marker set and no record is a stop at the record or at its text, and one
                // without it came earlier, at the selection or at the match.
                stopped_at_the_record +=
                    usize::from(!recorded && tx.get_variable(RuleVariable::TX, Some("marker")).is_some());
            } else {
                assert!(recorded, "{label}: nothing stopped, so the rule ran");
                assert_eq!(
                    reported.map(|item| (item.status, item.rule_id)),
                    Some((403, 10)),
                    "{label}"
                );
            }
            // Whatever the engine reports names a rule it has recorded, or the stop.
            if let Some(reported) = reported.filter(|item| item.rule_id == 10) {
                assert!(recorded, "{label}: {} is not in matched_rules()", reported.rule_id);
            }
        }
        assert!(
            stopped_at_the_record > 0,
            "{mode}: no budget stopped the rule at its record, the case does not test it"
        );
    }
}

#[test]
fn a_selection_the_budget_cannot_hold_stops_the_phase_before_the_list_is_made_plain_or_multimatch() {
    // Twenty thousand arguments: a list of references to them is megabytes, and no rule here ever matches.
    let body = pairs(20_000);
    let parse_only = waf("");
    let parse = smallest_budget(1 << 30, |budget| {
        let mut tx = request(&parse_only, "application/x-www-form-urlencoded", Some(budget));
        tx.process_request_body(&body);
        !request_body_errored(&tx)
    });
    for (label, transformations) in [("plain", "t:lowercase"), ("multiMatch", "multiMatch,t:lowercase")] {
        let with_rules = waf(&format!(
            "SecRule ARGS_POST \"@rx zzz\" \"id:5,phase:2,pass,nolog,{transformations}\"\n\
             SecAction \"id:6,phase:2,pass,nolog,setvar:tx.reached=1\"\n"
        ));
        let run = |budget: usize| {
            let mut tx = request(&with_rules, "application/x-www-form-urlencoded", Some(budget));
            let interruption = tx.process_request_body(&body);
            (tx, interruption)
        };
        // Room for the parse and a little more: the list does not fit, and nothing after the rule runs.
        let (stopped, interruption) = run(parse + 100_000);
        let interruption = interruption.unwrap();
        assert_eq!(
            (interruption.status, interruption.rule_id),
            (503, 0),
            "{label}: the selection stops the phase"
        );
        assert!(stopped.rule_evaluation_stopped_by_memory_budget(), "{label}");
        assert_eq!(stopped.get_variable(RuleVariable::TX, Some("reached")), None, "{label}");
        // Room for it: the rule runs as it does without a budget.
        let (fits, interruption) = run(parse + 100_000_000);
        assert!(
            interruption.is_none() && !fits.rule_evaluation_stopped_by_memory_budget(),
            "{label}"
        );
        assert_eq!(
            fits.get_variable(RuleVariable::TX, Some("reached")).as_deref(),
            Some("1"),
            "{label}"
        );
    }
}

#[test]
fn a_stopped_transaction_runs_no_rule_of_a_later_phase_and_still_writes_its_audit_entry() {
    const SIZE: usize = 20_000;
    let parse_only = waf("");
    let parse = smallest_budget(1 << 30, |budget| {
        !request_body_errored(&form_after_rules(&parse_only, SIZE, Some(budget)).0)
    });
    for mode in ["On", "DetectionOnly"] {
        let entries = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&entries);
        let mut parser = Parser::new();
        parser.on_audit_log(move |entry| sink.lock().unwrap().push(entry.clone()));
        // Rule 20 is recorded before the stop and is audited; the actions of the later phases would each set a variable
        // and be audited too, if they ran.
        let with_rules = waf_in(
            parser,
            &format!(
                "SecAuditEngine RelevantOnly\nSecAuditLogParts ABHKZ\n\
                 SecAction \"id:20,phase:2,pass,log,auditlog,msg:'before the stop'\"\n{}\
                 SecAction \"id:30,phase:3,pass,log,auditlog,msg:'response headers',setvar:tx.phase3=1\"\n\
                 SecAction \"id:40,phase:4,pass,log,auditlog,msg:'response body',setvar:tx.phase4=1\"\n\
                 SecAction \"id:50,phase:5,pass,log,auditlog,msg:'logging',setvar:tx.phase5=1\"\n",
                copying_rules(40, mode)
            ),
        );
        let mut tx = request(&with_rules, "application/x-www-form-urlencoded", Some(parse + 100_000));
        tx.process_request_body(format!("k={}", "v".repeat(SIZE)).as_bytes());
        assert!(tx.rule_evaluation_stopped_by_memory_budget(), "{mode}");

        // The stop ends rule evaluation for the transaction, the response phases and the logging phase with it.
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");
        tx.set_body_memory_budget(Some(parse + 100_000));
        tx.process_response_body(b"hello");
        tx.finish().unwrap();
        for phase in ["phase3", "phase4", "phase5"] {
            assert_eq!(tx.get_variable(RuleVariable::TX, Some(phase)), None, "{mode}: {phase}");
        }
        let recorded: Vec<i32> = tx.matched_rules().iter().map(|rule| rule.rule.id()).collect();
        assert!(recorded.contains(&20), "{mode}: {recorded:?}");
        assert!(
            !recorded.iter().any(|id| matches!(id, 30 | 40 | 50 | 999)),
            "{mode}: {recorded:?}"
        );

        // The engine still writes the entry, with the rules recorded before the stop and the stop itself: the
        // interruption of the rule evaluation, which has no rule id.
        let entries = entries.lock().unwrap();
        assert_eq!(entries.len(), 1, "{mode}: one audit entry");
        let entry = entries.first().unwrap();
        assert!(entry.messages.iter().any(|message| message.rule_id == 20), "{mode}");
        assert!(
            !entry
                .messages
                .iter()
                .any(|message| matches!(message.rule_id, 30 | 40 | 50)),
            "{mode}"
        );
        assert_eq!(entry.transaction.is_interrupted, mode == "On", "{mode}");
        assert_eq!(
            entry.transaction.interruption_rule_id,
            (mode == "On").then_some(0),
            "{mode}: the stop has no rule"
        );
        let stop = tx.interruption().or_else(|| tx.would_be_interruption()).unwrap();
        assert_eq!((stop.status, stop.rule_id), (503, 0), "{mode}");
        drop(entries);

        // The stop is the transaction's own: the ones that take its pooled state evaluate every phase, with a budget
        // that fits and without one.
        drop(tx);
        for budget in [None, Some(parse + 100_000_000), None] {
            let mut tx = request(&with_rules, "application/x-www-form-urlencoded", budget);
            tx.process_request_body(format!("k={}", "v".repeat(SIZE)).as_bytes());
            assert!(!tx.rule_evaluation_stopped_by_memory_budget(), "{mode}: {budget:?}");
            tx.finish().unwrap();
            assert_eq!(
                tx.get_variable(RuleVariable::TX, Some("phase5")).as_deref(),
                Some("1"),
                "{mode}: {budget:?}: the logging rules run"
            );
        }
    }
}

/// An action that says it ran, without a charge of its own: `tx.set_tx_variable` is not a rule's write.
struct Witness;

impl CustomAction for Witness {
    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }

    fn evaluate(&self, _rule: &RuleMetadata, tx: &mut Transaction) {
        tx.set_tx_variable("witness", "1");
    }
}

/// An action that says it was reached, as [`Witness`] says it ran, to tell a rule the budget stopped before an action
/// from one it stopped at that action.
struct Marker;

impl CustomAction for Marker {
    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }

    fn evaluate(&self, _rule: &RuleMetadata, tx: &mut Transaction) {
        tx.set_tx_variable("marker", "1");
    }
}

/// [`waf`] with the `witness` and `marker` actions.
fn waf_with_witness(rules: &str) -> Waf {
    let mut parser = Parser::new();
    parser
        .register_action("witness", Arc::new(|_| Ok(Box::new(Witness))))
        .unwrap();
    parser
        .register_action("marker", Arc::new(|_| Ok(Box::new(Marker))))
        .unwrap();
    waf_in(parser, rules)
}

/// Whether the rules of the phase stopped, as the parse of its body did not.
fn rules_stopped(tx: &Transaction) -> bool {
    !tx.request_body_stopped_by_memory_budget() && tx.rule_evaluation_stopped_by_memory_budget()
}

/// Whether the budget held both the parse of the body and the rules of its phase. A budget the parser stopped at leaves
/// the rules a reserve and nothing to see, so they do not stop either: a search for the smallest budget that the
/// rules do not stop at lands on one that is too small for the parse unless it asks for both.
fn within_budget(tx: &Transaction) -> bool {
    !tx.request_body_stopped_by_memory_budget() && !tx.rule_evaluation_stopped_by_memory_budget()
}

/// Whether the rule `id` was recorded, which is to say that it ran and matched.
fn rule_recorded(tx: &Transaction, id: i32) -> bool {
    tx.matched_rules().iter().any(|rule| rule.rule.id() == id)
}

#[test]
fn a_rule_the_budget_stopped_runs_none_of_its_remaining_actions() {
    const SIZE: usize = 50_000;
    // The action after the `setvar` is the witness, which no charge refuses, so only a check can keep it from running.
    // The marker before it is what tells a stop at the `setvar` from one at the selection or the match, which never
    // reach it and keep the witness from running without any check.
    let witnessed = waf_with_witness(
        "SecRule ARGS_POST \"@rx .\" \"id:30,phase:2,pass,nolog,marker,setvar:tx.big=%{MATCHED_VAR},witness\"",
    );
    let (mut refused, mut ran) = (0, 0);
    for budget in (0..400_000).step_by(1_024) {
        let (tx, _) = form_after_rules(&witnessed, SIZE, Some(budget));
        let witness = tx.get_variable(RuleVariable::TX, Some("witness")).is_some();
        let reached_setvar = tx.get_variable(RuleVariable::TX, Some("marker")).is_some();
        if tx.get_variable(RuleVariable::TX, Some("big")).is_some() {
            // The `setvar` fit, so the rule went on to the witness.
            assert!(witness, "{budget}: the action after a write that fit runs");
            ran += 1;
        } else if reached_setvar && rules_stopped(&tx) {
            assert!(!witness, "{budget}: the write did not fit, and the action after it ran");
            refused += 1;
        }
    }
    assert!(
        refused > 0 && ran > 0,
        "{refused} budgets refused the write and {ran} let it through: the sweep does not test the stop"
    );
}

#[test]
fn a_stop_after_a_ctl_that_switched_the_engine_off_sets_the_flag_and_returns_no_interruption() {
    const SIZE: usize = 50_000;
    // The `ctl` runs before the write that is refused: the engine ignores every interruption once off, as for any rule.
    let engine_off = waf_with_witness(
        "SecRuleEngine On\n\
         SecRule ARGS_POST \"@rx .\" \"id:32,phase:2,pass,nolog,ctl:ruleEngine=Off,setvar:tx.big=%{MATCHED_VAR}\"",
    );
    let mut refused = 0;
    for budget in (0..400_000).step_by(1_024) {
        let (tx, interruption) = form_after_rules(&engine_off, SIZE, Some(budget));
        if !rules_stopped(&tx)
            || tx.rule_engine() != coraza::types::RuleEngineStatus::Off
            || tx.get_variable(RuleVariable::TX, Some("big")).is_some()
        {
            continue;
        }
        assert!(
            interruption.is_none(),
            "{budget}: the engine is off, so nothing is returned"
        );
        refused += 1;
    }
    assert!(
        refused > 0,
        "no budget stopped the rule after its ctl: the sweep does not test the case"
    );
}

#[test]
fn a_ctl_after_the_charge_that_stopped_the_rule_cannot_hide_the_503() {
    const SIZE: usize = 50_000;
    // In `On` mode `ctl:ruleEngine=Off` is the way a rule would lose the interruption: the engine ignores it once off.
    let engine_off = waf_with_witness(
        "SecRuleEngine On\n\
         SecRule ARGS_POST \"@rx .\" \"id:31,phase:2,pass,nolog,setvar:tx.big=%{MATCHED_VAR},ctl:ruleEngine=Off\"",
    );
    let mut refused = 0;
    for budget in (0..400_000).step_by(1_024) {
        let (tx, interruption) = form_after_rules(&engine_off, SIZE, Some(budget));
        if !rules_stopped(&tx) || tx.get_variable(RuleVariable::TX, Some("big")).is_some() {
            continue;
        }
        // The write was refused, and the stop is what the engine returns: the `ctl` never ran.
        assert_eq!(
            interruption.map(|item| (item.status, item.rule_id)),
            Some((503, 0)),
            "{budget}: the stop was dropped from the return value"
        );
        assert_eq!(
            tx.rule_engine(),
            coraza::types::RuleEngineStatus::On,
            "{budget}: the ctl after the refused write ran"
        );
        refused += 1;
    }
    assert!(
        refused > 0,
        "no budget refused the write: the sweep does not test the stop"
    );
}

#[test]
fn an_operatorless_rule_whose_record_is_refused_runs_none_of_its_actions() {
    let witnessed = waf_with_witness("SecAction \"id:20,phase:2,pass,nolog,witness\"");
    let (mut stopped, mut ran) = (0, 0);
    for budget in 0..20_000 {
        let (tx, _) = form_after_rules(&witnessed, 1, Some(budget));
        let witness = tx.get_variable(RuleVariable::TX, Some("witness")).is_some();
        // The entry of `MATCHED_VARS` is the record that rule makes before its actions.
        let recorded = values_of(&tx, RuleVariable::MatchedVars).len();
        if rules_stopped(&tx) && recorded == 0 {
            assert!(!witness, "{budget}: the record was refused, and the actions ran");
            stopped += 1;
        } else if !rules_stopped(&tx) {
            assert!(witness, "{budget}: nothing stopped, so the rule ran");
            ran += 1;
        }
    }
    assert!(
        stopped > 0 && ran > 0,
        "{stopped} stopped and {ran} ran: the sweep does not test the stop"
    );
}

#[test]
fn a_chain_the_budget_stopped_in_a_link_records_nothing_and_nothing_runs_after_it() {
    const SIZE: usize = 20_000;
    let chained = waf_with_witness(
        "SecRule ARGS_POST \"@rx .\" \"id:10,phase:2,pass,nolog,chain\"\n\
         SecRule ARGS_POST \"@rx .\" \"setvar:tx.copy=%{MATCHED_VAR},witness\"\n\
         SecAction \"id:11,phase:2,pass,nolog,setvar:tx.after=1\"",
    );
    let (mut stopped, mut finished) = (0, 0);
    for budget in (0..200_000).step_by(512) {
        let (tx, interruption) = form_after_rules(&chained, SIZE, Some(budget));
        if tx.request_body_stopped_by_memory_budget() {
            continue;
        }
        let recorded: Vec<i32> = tx.matched_rules().iter().map(|rule| rule.rule.id()).collect();
        if tx.rule_evaluation_stopped_by_memory_budget() {
            assert_eq!(
                interruption.map(|item| (item.status, item.rule_id)),
                Some((503, 0)),
                "{budget}"
            );
            assert_eq!(tx.get_variable(RuleVariable::TX, Some("after")), None, "{budget}");
            assert!(
                !recorded.contains(&10),
                "{budget}: a chain that was cut records nothing"
            );
            stopped += 1;
        } else {
            assert_eq!(recorded, [10, 11], "{budget}");
            finished += 1;
        }
    }
    assert!(stopped > 0 && finished > 0, "{stopped} stopped and {finished} finished");
}

/// An operator that matches, takes two captures of its input, and writes one path argument.
struct CaptureAndPath;

impl Operator for CaptureAndPath {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        out.capture(0, input);
        out.capture(1, input);
        out.add_path_argument("pathkey", "pathvalue");
        true
    }
}

/// An operator that matches and writes `per_run` path arguments of `size` bytes: the same key each time, or a key
/// of its own.
struct PathWriter {
    size: usize,
    distinct: bool,
    per_run: usize,
    count: AtomicUsize,
}

impl Operator for PathWriter {
    fn evaluate(&self, _tx: &Transaction, _input: &[u8], out: &mut Outputs) -> bool {
        for _ in 0..self.per_run {
            let key = if self.distinct {
                format!("path{}", self.count.fetch_add(1, Ordering::Relaxed))
            } else {
                "path".to_owned()
            };
            out.add_path_argument(&key, &"p".repeat(self.size));
        }
        true
    }
}

#[test]
fn the_path_arguments_of_an_operator_whose_captures_were_refused_are_not_written() {
    const SIZE: usize = 50_000;
    let mut parser = Parser::new();
    parser.register_operator("captureandpath", Arc::new(|_| Ok(Box::new(CaptureAndPath))));
    let with_operator = waf_in(
        parser,
        "SecRule ARGS_POST:k \"@captureandpath x\" \"id:50,phase:2,pass,nolog,capture\"",
    );
    let (mut cut, mut whole) = (0, 0);
    for budget in (0..600_000).step_by(512) {
        let (tx, _) = form_after_rules(&with_operator, SIZE, Some(budget));
        if tx.request_body_stopped_by_memory_budget() {
            continue;
        }
        // The captures a rule has not written are kept as empty values, so a capture is written when it holds the
        // value.
        let capture = |index: &str| {
            tx.get_variable(RuleVariable::TX, Some(index))
                .is_some_and(|value| value.len() == SIZE)
        };
        let path = tx.get_variable(RuleVariable::ArgsPath, Some("pathkey")).is_some();
        if capture("0") && !capture("1") {
            assert!(
                !path,
                "{budget}: the second capture did not fit, and the path argument was written"
            );
            cut += 1;
        }
        if path {
            assert!(
                capture("0") && capture("1"),
                "{budget}: a path argument without its captures"
            );
            whole += 1;
        }
    }
    assert!(
        cut > 0 && whole > 0,
        "{cut} cut after one capture and {whole} whole: the sweep does not test the stop"
    );
}

#[test]
fn the_path_arguments_a_rule_writes_are_charged_and_a_rewritten_one_is_charged_once() {
    const SIZE: usize = 50_000;
    // The operator writes `per_run` arguments each time it runs, and `limit` is what `SecArgumentsLimit` allows.
    let needed = |operator: Option<(bool, usize, usize)>, limit: usize| {
        let mut parser = Parser::new();
        if let Some((distinct, size, per_run)) = operator {
            parser.register_operator(
                "pathwriter",
                Arc::new(move |_| {
                    Ok(Box::new(PathWriter {
                        size,
                        distinct,
                        per_run,
                        count: AtomicUsize::new(0),
                    }))
                }),
            );
        }
        let rules = if operator.is_some() {
            "SecRule ARGS_POST \"@pathwriter x\" \"id:60,phase:2,pass,nolog\""
        } else {
            "SecRule ARGS_POST \"@rx zzz\" \"id:60,phase:2,pass,nolog\""
        };
        let with_rules = waf_in(parser, &format!("SecArgumentsLimit {limit}\n{rules}"));
        // Three arguments, so the operator runs three times.
        let body = b"a=1&b=2&c=3";
        let run = |budget| {
            let mut tx = request(&with_rules, "application/x-www-form-urlencoded", Some(budget));
            tx.process_request_body(body);
            tx
        };
        let budget = smallest_budget(1 << 30, |budget| within_budget(&run(budget)));
        // The operator that writes the arguments always matches, so its rule is recorded where the search ends.
        assert!(
            operator.is_none() || rule_recorded(&run(budget), 60),
            "the rule ran at {budget}"
        );
        (budget, run(1 << 30))
    };
    let (none, _) = needed(None, 100_000);
    let (distinct, tx) = needed(Some((true, SIZE, 1)), 100_000);
    // `ARGS_PATH` and `ARGS` each keep their own copy of every value.
    assert_eq!(values_of(&tx, RuleVariable::ArgsPath).len(), 3);
    assert!(
        distinct >= none + 3 * SIZE,
        "three path arguments of {SIZE} bytes need {} more than none, which is less than their values",
        distinct - none
    );
    // The same key written three times holds one value, whose buffer the next rewrites.
    let (same, tx) = needed(Some((false, SIZE, 1)), 100_000);
    assert_eq!(values_of(&tx, RuleVariable::ArgsPath).len(), 1);
    assert!(
        same >= none + SIZE,
        "{} more than none for one value of {SIZE}",
        same - none
    );
    assert!(
        same + SIZE <= distinct,
        "a rewritten path argument is charged once: {same} against {distinct} for three"
    );
    // An argument past `SecArgumentsLimit` is dropped, and takes nothing: one run writes four, and two are kept.
    let (limited, tx) = needed(Some((true, SIZE, 4)), 2);
    assert_eq!(values_of(&tx, RuleVariable::ArgsPath).len(), 2);
    let (unlimited, _) = needed(Some((true, SIZE, 4)), 100_000);
    assert!(
        limited >= none + 2 * SIZE && limited + 2 * SIZE <= unlimited,
        "the dropped arguments are charged: {limited} against {unlimited} without the limit"
    );
}

#[test]
fn setenv_is_charged_like_setvar_and_a_rewritten_variable_is_charged_once() {
    const SIZE: usize = 50_000;
    let body = format!("a={}", "v".repeat(SIZE));
    let needed = |actions: &str| {
        let with_rules = waf(&format!(
            "SecRule ARGS_POST \"@rx .\" \"id:60,phase:2,pass,nolog{actions}\""
        ));
        let run = |budget| {
            let mut tx = request(&with_rules, "application/x-www-form-urlencoded", Some(budget));
            tx.process_request_body(body.as_bytes());
            tx
        };
        let budget = smallest_budget(1 << 30, |budget| within_budget(&run(budget)));
        assert!(rule_recorded(&run(budget), 60), "the rule ran at {budget}");
        (budget, run(1 << 30))
    };
    let (none, _) = needed("");
    let (three, tx) = needed(",setenv:e1=%{MATCHED_VAR},setenv:e2=%{MATCHED_VAR},setenv:e3=%{MATCHED_VAR}");
    assert_eq!(
        tx.get_variable(RuleVariable::Env, Some("e3")).map(|value| value.len()),
        Some(SIZE)
    );
    assert!(
        three >= none + 3 * SIZE,
        "three variables of {SIZE} bytes need {} more than none, which is less than their values",
        three - none
    );
    // One variable written three times holds one value: the budget needs the peak of a rewrite, which is two.
    let (same, _) = needed(",setenv:e=%{MATCHED_VAR},setenv:e=%{MATCHED_VAR},setenv:e=%{MATCHED_VAR}");
    // The rule's record, a few kilobytes, is charged after its actions, when the variable holds one value, so it is
    // not part of the peak of a rewrite as it is of the baseline's.
    assert!(
        same + 4 * 1024 >= none + 2 * SIZE,
        "{} more than none for the peak of a rewrite",
        same.saturating_sub(none)
    );
    assert!(
        same + SIZE / 2 <= three,
        "a rewritten variable is given back what it replaced: {same} against {three} for three"
    );
    // What was refused is not written.
    let refused = (0..three)
        .step_by(4_096)
        .map(|budget| {
            let mut tx = request(&waf(
                "SecRule ARGS_POST \"@rx .\" \"id:60,phase:2,pass,nolog,setenv:e1=%{MATCHED_VAR},setenv:e2=%{MATCHED_VAR},setenv:e3=%{MATCHED_VAR}\"",
            ), "application/x-www-form-urlencoded", Some(budget));
            tx.process_request_body(body.as_bytes());
            tx
        })
        .filter(rules_stopped)
        // The stop is at the write that was refused: the first variable holds its value and the second is not there,
        // and not a stop before any `setenv` ran, which leaves `e2` absent as well.
        .filter(|tx| tx.get_variable(RuleVariable::Env, Some("e1")).map(|value| value.len()) == Some(SIZE))
        .filter(|tx| tx.get_variable(RuleVariable::Env, Some("e2")).is_none())
        .inspect(|tx| assert!(tx.get_variable(RuleVariable::Env, Some("e3")).is_none()))
        .count();
    assert!(refused > 0, "no budget stopped between the variables");
}

#[test]
fn a_removed_tx_entry_gives_its_bytes_back_to_the_rules() {
    const SIZE: usize = 50_000;
    let body = format!("a={}", "v".repeat(SIZE));
    let needed = |pairs: usize| {
        let rules: String = (0..pairs)
            .map(|index| {
                format!(
                    "SecRule ARGS_POST \"@rx .\" \"id:{},phase:2,pass,nolog,setvar:tx.big=%{{MATCHED_VAR}}\"\n\
                     SecAction \"id:{},phase:2,pass,nolog,setvar:!tx.big\"\n",
                    100 + 2 * index,
                    101 + 2 * index
                )
            })
            .collect();
        let with_rules = waf(&rules);
        let run = |budget| {
            let mut tx = request(&with_rules, "application/x-www-form-urlencoded", Some(budget));
            tx.process_request_body(body.as_bytes());
            tx
        };
        let budget = smallest_budget(1 << 30, |budget| within_budget(&run(budget)));
        let tx = run(budget);
        assert!(rule_recorded(&tx, 100), "the rule that sets the entry ran at {budget}");
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("big")), None);
        budget
    };
    // Each pair keeps the value in the record of its first rule, and nothing in `TX`: a removal that gives nothing
    // back kept a second copy charged for every pair, which is the whole of the value.
    let (one, eight) = (needed(1), needed(8));
    let per_pair = (eight - one) / 7;
    assert!(
        per_pair < SIZE + SIZE / 2,
        "a pair of rules costs {per_pair} bytes, and the value it sets and removes is {SIZE}"
    );
}

#[test]
fn a_multiphase_duplicate_gives_back_the_copy_it_was_checked_by() {
    const SIZE: usize = 10_000;
    let rules = "SecRule REQUEST_HEADERS:x \"@rx .\" \"id:40,phase:2,pass,nolog,chain\"\n\
                 SecRule ARGS \"@rx .\" \"\"";
    let mut parser = Parser::new();
    parser.config_mut().multiphase_evaluation = true;
    let multiphase = waf_in(parser, rules);
    // Phase 1 records the chain on `x` and an argument, and phase 2 sees the same arguments again: each is a
    // duplicate of a match already recorded, whose copy the check made and dropped.
    let needed = |duplicates: usize| {
        let query: Vec<String> = (0..duplicates)
            .map(|index| format!("q{index}={}", "g".repeat(SIZE)))
            .collect();
        let run = |budget| {
            let mut tx = multiphase.new_transaction();
            tx.process_uri(format!("/?{}", query.join("&")), "POST", "HTTP/1.1");
            tx.set_body_memory_budget(Some(budget));
            tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
            tx.add_request_header("x", "1");
            tx.process_request_headers();
            tx.process_request_body(b"p=1");
            tx
        };
        let budget = smallest_budget(1 << 30, |budget| {
            let tx = run(budget);
            !tx.rule_evaluation_stopped_by_memory_budget() && !tx.request_body_stopped_by_memory_budget()
        });
        // The chain is recorded in both phases, the second time with the arguments that are not duplicates.
        let tx = run(budget);
        assert_eq!(tx.matched_rules().iter().filter(|rule| rule.rule.id() == 40).count(), 2);
        budget
    };
    let (one, forty) = (needed(1), needed(40));
    let per_duplicate = (forty - one) / 39;
    // The match of a duplicate is given back, and the record keeps the URI that holds the argument once more: one
    // value's worth each. A copy kept charged until the rule ends is a second.
    assert!(
        per_duplicate < SIZE + SIZE / 2,
        "each duplicate costs {per_duplicate} bytes, and its value is {SIZE}"
    );
}
