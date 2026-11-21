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

use std::fmt::Write as _;

use common::smallest_budget;
use coraza::{
    seclang::Parser,
    transaction::{Transaction, VariableCollection},
    types::RuleVariable,
    waf::Waf,
};

/// The engine with `rules` beside a body policy that parses by `Content-Type`, XML and JSON as CRS selects them.
fn waf(rules: &str) -> Waf {
    let mut parser = Parser::new();
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
fn without_a_budget_no_valid_body_is_an_error_that_go_would_not_report() {
    // 200002 is what turns an error into a 400, so a body that parses must raise none.
    let waf = waf("SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,t:none,deny,status:400\"");
    let denied = |content_type: &str, body: &[u8]| request(&waf, content_type, None).process_request_body(body);

    // Repeated attribute and text shapes at every size around the old 4096 byte floor of the XML output limit.
    for unit in ["<a b=\"c\">d</a>", "<i>1</i>", "<a b c d e f g h/>", "<a b=\"c\"/>"] {
        for copies in (1..400).step_by(7).chain([4096, 60_000]) {
            let body = format!("<r>{}</r>", unit.repeat(copies));
            assert!(denied("text/xml", body.as_bytes()).is_none(), "{copies} of {unit}");
        }
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
