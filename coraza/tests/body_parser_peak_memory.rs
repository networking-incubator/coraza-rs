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

//! Peak heap growth of the request body processors, measured with a counting allocator.
//!
//! Without a memory budget the processors refuse nothing Go Coraza would not (the first test measures what that
//! costs, and that the transaction's own accounting covers it). A connector with a fixed ceiling sets an absolute
//! budget instead, and the second test gives it bodies that amplified to 20 to 300 times their size: the processors
//! must stop before they make the heap go past it, whatever the shape of the body.

#![expect(
    unsafe_code,
    clippy::unwrap_used,
    clippy::tests_outside_test_module,
    reason = "a counting global allocator and fixed fixtures; the allocator only forwards to System"
)]

mod common;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    fmt::Write as _,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
};

use common::smallest_budget;
use coraza::{
    seclang::Parser,
    transaction::{Transaction, VariableCollection},
    types::RuleVariable,
};

/// Forwards to the system allocator while tracking live and peak bytes, in two ways.
///
/// `CURRENT` and `PEAK` count the bytes the program asked for. `CHUNKS` and `PEAK_CHUNKS` model what a request
/// holds in the worst allocator it can run on: every allocation is charged the chunk a malloc rounds it up to (a
/// header and 16-byte units, 32 at least), and resizing one counts the old chunk and the new together at the
/// moment of the copy, as the WASI allocator that the connector runs on may have to.
struct Counting;

/// Bytes currently allocated.
static CURRENT: AtomicUsize = AtomicUsize::new(0);
/// The highest value `CURRENT` has reached since the last reset.
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// Bytes currently allocated, with the allocator's chunks.
static CHUNKS: AtomicUsize = AtomicUsize::new(0);
/// The highest value `CHUNKS` has reached since the last reset.
static PEAK_CHUNKS: AtomicUsize = AtomicUsize::new(0);

/// The bytes a malloc keeps for a request of `size`.
fn chunk(size: usize) -> usize {
    if size == 0 {
        0
    } else {
        (size + 8).next_multiple_of(16).max(32)
    }
}

// SAFETY: every method forwards its arguments unchanged to `System`, which upholds the `GlobalAlloc` contract;
// the counters are only bookkeeping.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's layout contract is passed on to `System`.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let current = CURRENT.fetch_add(layout.size(), SeqCst) + layout.size();
            PEAK.fetch_max(current, SeqCst);
            let chunks = CHUNKS.fetch_add(chunk(layout.size()), SeqCst) + chunk(layout.size());
            PEAK_CHUNKS.fetch_max(chunks, SeqCst);
        }
        pointer
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` and `layout` come from a matching `alloc`, as the caller guarantees.
        unsafe { System.dealloc(ptr, layout) }
        CURRENT.fetch_sub(layout.size(), SeqCst);
        CHUNKS.fetch_sub(chunk(layout.size()), SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: `ptr`, `layout` and `new_size` satisfy the `realloc` contract the caller promised.
        let grown = unsafe { System.realloc(ptr, layout, new_size) };
        if !grown.is_null() {
            if new_size > layout.size() {
                let current = CURRENT.fetch_add(new_size - layout.size(), SeqCst) + new_size - layout.size();
                PEAK.fetch_max(current, SeqCst);
            } else {
                CURRENT.fetch_sub(layout.size() - new_size, SeqCst);
            }
            let (old, new) = (chunk(layout.size()), chunk(new_size));
            // Both chunks are live while the contents are copied, which an allocator may do to shrink one too.
            if new != old {
                PEAK_CHUNKS.fetch_max(CHUNKS.load(SeqCst) + new, SeqCst);
            }
            if new > old {
                CHUNKS.fetch_add(new - old, SeqCst);
            } else {
                CHUNKS.fetch_sub(old - new, SeqCst);
            }
        }
        grown
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Held by every test: the counters are global, so measurements must not overlap.
static SERIAL: Mutex<()> = Mutex::new(());

/// What one processed body left behind.
struct Measured {
    /// Peak heap growth while `process_request_body` ran, in bytes asked for.
    peak: usize,
    /// The same peak in the worst allocator's terms, see [`Counting`].
    peak_chunks: usize,
    /// The transaction's own estimate of what it retained.
    retained: usize,
    /// What the transaction actually holds afterwards, in the worst allocator's terms.
    live_chunks: usize,
    /// Whether `REQBODY_ERROR` and `REQBODY_PROCESSOR_ERROR` were raised.
    errored: bool,
    /// The error message.
    message: String,
    /// Whether `MULTIPART_STRICT_ERROR` was raised.
    strict: bool,
    /// Number of values that reached `ARGS_POST` or `REQUEST_XML`.
    values: usize,
}

/// A request body and the processor that reads it.
struct Case {
    /// Name for failure messages.
    label: &'static str,
    /// The body processor, as `ctl:requestBodyProcessor` names it.
    processor: &'static str,
    /// The request `Content-Type`.
    content_type: String,
    /// Extra configuration, such as a larger argument limit.
    configuration: &'static str,
    /// Whether `ARGS` and its kin keep the case of their keys.
    case_sensitive: bool,
    /// The body.
    body: Vec<u8>,
}

/// A body for `processor` under `configuration`, with a content type it accepts.
fn case(label: &'static str, processor: &'static str, configuration: &'static str, body: Vec<u8>) -> Case {
    let content_type = match processor {
        "xml" => "text/xml",
        "json" => "application/json",
        "urlencoded" => "application/x-www-form-urlencoded",
        _ => "multipart/form-data; boundary=b",
    };
    Case {
        label,
        processor,
        content_type: content_type.to_owned(),
        configuration,
        case_sensitive: false,
        body,
    }
}

impl Case {
    /// Copies of the body the engine holds beside what the processor builds, which no budget is for: its buffer, the
    /// raw `REQUEST_BODY` of a URL-encoded body and the text a JSON body that parsed is kept as.
    fn copies(&self, measured: &Measured) -> usize {
        1 + usize::from(self.processor == "urlencoded") + usize::from(self.processor == "json" && !measured.errored)
    }
}

/// A transaction that has read the headers of `case`'s request, under `budget`.
fn prepared(case: &Case, budget: Option<usize>) -> Transaction {
    let mut parser = Parser::new();
    parser.config_mut().case_sensitive_args_keys = case.case_sensitive;
    parser
        .from_string(&format!(
            "SecRequestBodyAccess On\nSecRequestBodyLimit 134217728\n{}\n\
             SecAction \"id:1,phase:1,ctl:requestBodyProcessor={},pass,nolog\"",
            case.configuration, case.processor
        ))
        .unwrap();
    let waf = parser.into_waf().unwrap();
    // A fixed id: the generated one grows a digit as other tests make transactions, and the matched rules keep a
    // copy of it, so two measurements to compare could otherwise differ by that byte.
    let mut tx = waf.new_transaction_with_id("measured");
    tx.set_body_memory_budget(budget);
    tx.add_request_header("Content-Type", &case.content_type);
    tx.process_request_headers();
    tx
}

/// Processes `case`'s body under `budget` and measures it.
fn measure(case: &Case, budget: Option<usize>) -> Measured {
    measure_body(&mut prepared(case, budget), &case.body, case.processor == "xml")
}

/// Processes `body` as the request body of `tx` and measures the peak heap growth.
fn measure_body(tx: &mut Transaction, body: &[u8], request_xml: bool) -> Measured {
    let baseline = CURRENT.load(SeqCst);
    PEAK.store(baseline, SeqCst);
    let baseline_chunks = CHUNKS.load(SeqCst);
    PEAK_CHUNKS.store(baseline_chunks, SeqCst);
    tx.process_request_body(body);
    let peak = PEAK.load(SeqCst).saturating_sub(baseline);
    let peak_chunks = PEAK_CHUNKS.load(SeqCst).saturating_sub(baseline_chunks);
    let live_chunks = CHUNKS.load(SeqCst).saturating_sub(baseline_chunks);
    let errored = tx.get_variable(RuleVariable::ReqbodyError, None).as_deref() == Some("1")
        && tx.get_variable(RuleVariable::ReqbodyProcessorError, None).as_deref() == Some("1");
    let message = tx
        .get_variable(RuleVariable::ReqbodyProcessorErrorMsg, None)
        .map(|message| String::clone(&message))
        .unwrap_or_default();
    let strict = tx.get_variable(RuleVariable::MultipartStrictError, None).as_deref() == Some("1");
    let variable = if request_xml {
        RuleVariable::RequestXML
    } else {
        RuleVariable::ArgsPost
    };
    let values = if let Some(VariableCollection::Map(map)) = tx.collection(variable) {
        map.value_count()
    } else {
        0
    };
    Measured {
        peak,
        peak_chunks,
        live_chunks,
        retained: tx.body_memory_bytes(),
        errored,
        message,
        strict,
        values,
    }
}

/// What the transaction's own accounting may be short of what it holds: its variables and error messages.
const ACCOUNTING_SLACK: usize = 4 * 1024;

/// The estimate the connector's retained-body check is built on must cover what the transaction holds, the
/// allocator's chunks included, or that check admits more than it means to.
#[track_caller]
fn assert_accounting_is_conservative(label: &str, measured: &Measured) {
    assert!(
        measured.live_chunks <= measured.retained + ACCOUNTING_SLACK,
        "{label}: the transaction holds {} bytes but estimates {}",
        measured.live_chunks,
        measured.retained
    );
}

/// `prefix`, then `unit` repeated to about `size` bytes, then `suffix`.
fn repeated(prefix: &[u8], unit: &[u8], size: usize, suffix: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(size + 16);
    body.extend_from_slice(prefix);
    while body.len() < size {
        body.extend_from_slice(unit);
    }
    body.extend_from_slice(suffix);
    body
}

/// An object with one very long key of `byte`s over 999 array leaves, the path-amplification body. The key is not
/// valid UTF-8 when `byte` is above 0x7F.
fn json_long_key(byte: u8, size: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(b"{\"");
    body.extend(std::iter::repeat_n(byte, size / 3));
    body.extend_from_slice(b"\":[");
    for index in 0..999 {
        if index > 0 {
            body.push(b',');
        }
        body.push(b'1');
    }
    body.extend_from_slice(b"]}");
    body
}

/// An object holding `count` modest keys over a few leaves each, the ordinary shape.
fn json_ordinary(count: usize) -> Vec<u8> {
    let mut body = b"{".to_vec();
    for index in 0..count {
        if index > 0 {
            body.push(b',');
        }
        body.extend_from_slice(
            format!("\"user{index}\":{{\"name\":\"Alice {index}\",\"roles\":[\"admin\",\"dev\"],\"active\":true}}")
                .as_bytes(),
        );
    }
    body.push(b'}');
    body
}

/// The configuration of every XML case: an argument limit no case reaches, as the form cases have, so that only the
/// budget, or nothing, stops a document.
const XML_LIMIT: &str = "SecArgumentsLimit 100000000";

/// Peak growth the XML processor may reach without a budget, as a multiple of the body, in bytes asked for. Values
/// are read straight into `REQUEST_XML`, so a value costs its text and one entry of the collection's list, which
/// grows by a quarter at a time: the worst body, a dense one, peaks at about eight times its size, where it was
/// twenty-three before.
const XML_PEAK_FACTOR: usize = 10;

/// The same, counting the allocator's chunks: a one-byte value is a 32-byte chunk, and a list being grown is held
/// twice for a moment.
const XML_CHUNK_PEAK_FACTOR: usize = 20;

/// A value costs its entry in the collection's list, forty bytes and a quarter spare, whatever its text, so a body
/// of one value per two or three bytes, which no real document is, holds up to twenty-five times its size.
/// Under a raised argument limit only an absolute budget bounds that; Go Coraza, which has no limit, admits it too.
const XML_ONE_PER_TWO_BYTES_PEAK_FACTOR: usize = 30;

/// And counting the allocator's chunks, where each of the million values is one of thirty-two bytes.
const XML_ONE_PER_TWO_BYTES_CHUNK_FACTOR: usize = 70;

/// Peak growth the JSON flattener may reach before Go's raw budget stops it: that budget is eight times the body of
/// keys and values, and the transaction holds three copies of each.
const JSON_PEAK_FACTOR: usize = 26;

const MIB: usize = 1024 * 1024;

/// Bodies that amplify, with the most their peak may be as a multiple of the body, without and with the allocator's
/// chunks. The JSON one is over Go's raw budget and refused; an XML document under the raised limit never is.
fn amplifying_cases() -> [(Case, usize, usize); 4] {
    [
        (
            case(
                "xml, one value per two bytes in one tag",
                "xml",
                XML_LIMIT,
                repeated(b"<r", b" b", 2 * MIB, b"></r>"),
            ),
            XML_ONE_PER_TWO_BYTES_PEAK_FACTOR,
            XML_ONE_PER_TWO_BYTES_CHUNK_FACTOR,
        ),
        (
            case(
                "xml, 14-byte element with an attribute and text",
                "xml",
                XML_LIMIT,
                repeated(b"<r>", b"<a b=\"c\">d</a>", 2 * MIB, b"</r>"),
            ),
            XML_PEAK_FACTOR,
            XML_CHUNK_PEAK_FACTOR,
        ),
        (
            case(
                "xml, valueless attributes in many tags",
                "xml",
                XML_LIMIT,
                repeated(b"<r>", b"<a b c d e f g h/>", 2 * MIB, b"</r>"),
            ),
            XML_ONE_PER_TWO_BYTES_PEAK_FACTOR,
            XML_ONE_PER_TWO_BYTES_CHUNK_FACTOR,
        ),
        (
            case(
                "json, long key over 999 leaves",
                "json",
                "",
                json_long_key(b'k', 3 * MIB),
            ),
            JSON_PEAK_FACTOR,
            JSON_PEAK_FACTOR,
        ),
    ]
}

#[test]
fn without_a_budget_nothing_but_gos_own_limit_is_refused_and_accounting_covers_what_is_held() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for (case, factor, chunk_factor) in amplifying_cases() {
        let length = case.body.len();
        let measured = measure(&case, None);
        assert_eq!(
            measured.errored,
            case.processor == "json",
            "{}: {}",
            case.label,
            measured.message
        );
        assert_accounting_is_conservative(case.label, &measured);
        assert!(
            measured.peak <= factor * length,
            "{}: peak {} bytes is over {factor}x the {length} byte body",
            case.label,
            measured.peak
        );
        assert!(
            measured.peak_chunks <= chunk_factor * length,
            "{}: peak {} bytes with allocator chunks is over {chunk_factor}x the {length} byte body",
            case.label,
            measured.peak_chunks
        );
        assert!(
            measured.retained <= chunk_factor * length,
            "{}: retained {} bytes is over {chunk_factor}x the {length} byte body",
            case.label,
            measured.retained
        );
    }

    // The same machinery must leave ordinary bodies alone.
    let ordinary = [
        case(
            "ordinary xml",
            "xml",
            XML_LIMIT,
            repeated(
                b"<r>",
                b"<item id=\"7\"><name>Alice</name><note>hello world</note></item>",
                MIB,
                b"</r>",
            ),
        ),
        case(
            "dense xml list",
            "xml",
            XML_LIMIT,
            repeated(b"<r>", b"<i>12345</i>", MIB, b"</r>"),
        ),
        case(
            "densest ordinary xml list",
            "xml",
            XML_LIMIT,
            repeated(b"<r>", b"<i>1</i>", MIB, b"</r>"),
        ),
        case("ordinary json", "json", "", json_ordinary(8_000)),
        case(
            "dense json array",
            "json",
            "",
            format!("[{}1]", "1,".repeat(MIB / 4)).into_bytes(),
        ),
        // A rule that matches every value keeps a copy of each in the transaction's matched rules.
        case(
            "urlencoded, every value matched",
            "urlencoded",
            "SecRule ARGS_POST \"@unconditionalMatch\" \"id:2,phase:2,pass,nolog\"",
            vec!["a=1"; 1000].join("&").into_bytes(),
        ),
    ];
    for case in &ordinary {
        let measured = measure(case, None);
        assert!(
            !measured.errored,
            "{}: no error for an ordinary body ({})",
            case.label, measured.message
        );
        assert!(measured.values > 0, "{}: the values were published", case.label);
        assert_accounting_is_conservative(case.label, &measured);
    }
}

/// The absolute budget a connector gives the processors in the cases below.
const BUDGET: usize = 8 * MIB;

/// The size of the bodies that must not make a processor go past [`BUDGET`]: twice the budget.
const BIG: usize = 16 * MIB;

/// What the heap may grow by beyond the budget and the engine's own copies of the body: the lists a processor
/// grows, the transaction's own variables and the allocator's rounding.
const SLACK: usize = MIB;

/// The bodies that must stop at the budget.
fn budgeted_cases() -> Vec<Case> {
    let xml = |label, body| case(label, "xml", XML_LIMIT, body);
    let json = |label, body| case(label, "json", "", body);
    let form = |label, body| case(label, "urlencoded", "SecArgumentsLimit 100000000", body);
    vec![
        xml(
            "xml, attribute and text per element",
            repeated(b"<r>", b"<a b=\"c\">d</a>", BIG, b"</r>"),
        ),
        xml(
            "xml, one value per two bytes in one tag",
            repeated(b"<r", b" b", BIG, b"></r>"),
        ),
        xml(
            "xml, valueless attributes in many tags",
            repeated(b"<r>", b"<a b c d e f g h/>", BIG, b"</r>"),
        ),
        xml("xml, densest text list", repeated(b"<r>", b"<i>1</i>", BIG, b"</r>")),
        xml("xml, nested elements", repeated(b"<r>", b"<a>", BIG, b"</r>")),
        xml("xml, one text node", repeated(b"<r>", b"x", BIG, b"</r>")),
        xml("xml, one escaped text node", repeated(b"<r>", b"&amp;", BIG, b"</r>")),
        xml("xml, one element name", repeated(b"<", b"x", BIG, b">")),
        xml("xml, one attribute value", repeated(b"<r a=\"", b"x", BIG, b"\"/>")),
        xml(
            "xml, one processing instruction",
            repeated(b"<?xml ", b"x", BIG, b"?><r/>"),
        ),
        json("json, long key over 999 leaves", json_long_key(b'k', BIG)),
        json("json, long invalid UTF-8 key over 999 leaves", json_long_key(0xFF, BIG)),
        // One key that fits the budget as bytes (about 5 times its length is charged for a valid one) but not
        // with its text views, in a body padded to the size of the others.
        json(
            "json, one invalid UTF-8 key beside a big body",
            [&b"{\""[..], &vec![0xFF; 3 * MIB / 2], b"\":1}", &vec![b' '; BIG]].concat(),
        ),
        json("json, container index", repeated(b"[", b"[[]],", BIG, b"[]]")),
        json(
            "json, deeply nested objects with leaves",
            repeated(b"[", b"{\"a\":[1]},", BIG, b"1]"),
        ),
        // A single escape makes the string unescape into a buffer as long as the string itself.
        json("json, one escaped string", repeated(b"{\"a\":\"\\n", b"x", BIG, b"\"}")),
        json("json, one escaped key", repeated(b"{\"\\n", b"x", BIG, b"\":1}")),
        json(
            "json, many escapes in one string",
            repeated(b"{\"a\":\"", b"\\n", BIG, b"\"}"),
        ),
        case(
            "json, many leaves",
            "json",
            "SecArgumentsLimit 100000000",
            repeated(b"[", b"1,", BIG, b"1]"),
        ),
        form("urlencoded, many tiny pairs", repeated(b"", b"a=b&", BIG, b"")),
        form(
            "urlencoded, many pairs with percent escapes",
            repeated(b"", b"%ff=%fe&", BIG, b""),
        ),
        form("urlencoded, one long value", repeated(b"k=", b"v", BIG, b"")),
    ]
}

#[test]
fn an_absolute_budget_bounds_the_peak_of_every_body_shape_and_reports_the_error() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for case in budgeted_cases() {
        let measured = measure(&case, Some(BUDGET));
        let allowed = case.copies(&measured) * case.body.len() + BUDGET + SLACK;
        assert!(measured.errored, "{}: the budget error is reported", case.label);
        assert_accounting_is_conservative(case.label, &measured);
        assert!(
            measured.peak_chunks <= allowed,
            "{}: peak {} bytes is over the {allowed} that the engine's copies of the body, the {BUDGET} byte budget \
             and {SLACK} of slack allow",
            case.label,
            measured.peak_chunks
        );
    }
}

#[test]
fn a_budget_that_is_not_reached_changes_nothing() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let cases = [
        case(
            "xml",
            "xml",
            XML_LIMIT,
            repeated(
                b"<r>",
                b"<item id=\"7\"><name>Alice</name><note>hello world</note></item>",
                MIB / 4,
                b"</r>",
            ),
        ),
        case("json", "json", "", json_ordinary(500)),
        case(
            "urlencoded",
            "urlencoded",
            "",
            repeated(b"", b"name=Alice&", 10_000, b""),
        ),
    ];
    for case in &cases {
        let plain = measure(case, None);
        let budgeted = measure(case, Some(BUDGET));
        assert!(!budgeted.errored, "{}: {}", case.label, budgeted.message);
        assert_eq!(
            budgeted.values, plain.values,
            "{}: the same values are published",
            case.label
        );
        assert_eq!(budgeted.retained, plain.retained, "{}: and retained alike", case.label);
    }
}

/// Bodies of every processor and of the shapes that once hid a copy or a growth from the budget.
#[expect(clippy::too_many_lines, reason = "one entry per body shape")]
fn admitted_cases() -> Vec<Case> {
    let field = b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--b--\r\n".to_vec();
    let long_boundary = "b".repeat(4090);
    vec![
        case(
            "xml, densest list",
            "xml",
            XML_LIMIT,
            repeated(b"<r>", b"<i>1</i>", 60_000, b"</r>"),
        ),
        case(
            "xml, attribute and text",
            "xml",
            XML_LIMIT,
            repeated(b"<r>", b"<a b=\"c\">d</a>", 60_000, b"</r>"),
        ),
        case(
            "xml, valueless attributes",
            "xml",
            XML_LIMIT,
            repeated(b"<r>", b"<a b c d e f g h/>", 60_000, b"</r>"),
        ),
        // References shorten the text below the buffer it was read into, which is trimmed to it when it is stored.
        case(
            "xml, one escaped text node",
            "xml",
            XML_LIMIT,
            repeated(b"<r>", b"&amp;", 250_000, b"</r>"),
        ),
        // 513 values take the list of `/*` past 512 slots, which grows to 1,024 beside the old one.
        case(
            "xml, one past a full list",
            "xml",
            XML_LIMIT,
            format!("<r>{}</r>", "<i>1</i>".repeat(513)).into_bytes(),
        ),
        // The shape that reached 95 MB of peak and 72 MB retained at 400 KB with a raised argument limit and no
        // budget.
        case(
            "json, dense array under a raised argument limit",
            "json",
            "SecArgumentsLimit 100000000",
            repeated(b"[", b"1,", 60_000, b"1]"),
        ),
        case(
            "json, long key over a few leaves",
            "json",
            "",
            repeated(&[b"{\"".as_slice(), &[b'k'; 300], b"\":["].concat(), b"1,", 24, b"1]}"),
        ),
        // Members that a case-insensitive collection files under one name share its list.
        case(
            "json, a name in two spellings",
            "json",
            "",
            format!("{{\"A\":1{}}}", ",\"a\":1,\"A\":1".repeat(256)).into_bytes(),
        ),
        case(
            "urlencoded, many pairs",
            "urlencoded",
            "SecArgumentsLimit 100000000",
            repeated(b"", b"name=value&", 60_000, b""),
        ),
        // The decoded pair is alive while it is inserted, and a name with a capital is looked up through a lowercase
        // copy of it, which outgrows the vector sized for the name when, as `Ⱥ`'s, its lowercase form is longer.
        case(
            "urlencoded, a name whose lowercase form is longer",
            "urlencoded",
            "",
            repeated(b"", "Ⱥ".as_bytes(), 128 * 1024, b"=1"),
        ),
        case(
            "urlencoded, a long name with capitals",
            "urlencoded",
            "",
            repeated(b"", b"A", 256 * 1024, b"=1"),
        ),
        case(
            "json, a long name with capitals",
            "json",
            "",
            repeated(b"{\"", b"A", 64 * 1024, b"\":1}"),
        ),
        case(
            "multipart, a long name with capitals",
            "multipart",
            "",
            repeated(
                b"--b\r\nContent-Disposition: form-data; name=\"",
                b"A",
                64 * 1024,
                b"\"\r\n\r\n1\r\n--b--\r\n",
            ),
        ),
        // A disposition parameter's name is lower-cased as Go's `strings.ToLower` does, which writes each byte that is
        // not UTF-8 as the three bytes of U+FFFD.
        case(
            "multipart, a long parameter name that is not UTF-8",
            "multipart",
            "",
            repeated(
                b"--b\r\nContent-Disposition: form-data; ",
                b"\xff",
                64 * 1024,
                b"=1\r\n\r\n1\r\n--b--\r\n",
            ),
        ),
        // The media type and the parser's markers are held while the parts are read.
        Case {
            content_type: format!(
                "multipart/form-data; boundary=b{}",
                (0..3_000).map(|index| format!("; p{index}=v")).collect::<String>()
            ),
            ..case("multipart, three thousand parameters", "multipart", "", field.clone())
        },
        Case {
            content_type: format!("multipart/form-data; boundary={long_boundary}"),
            ..case(
                "multipart, the longest boundary",
                "multipart",
                "",
                String::from_utf8(field)
                    .unwrap()
                    .replace("--b", &format!("--{long_boundary}"))
                    .into_bytes(),
            )
        },
    ]
}

/// The smallest budget up to `high` that admits `case`, which must cover its peak with no slack: what the processor
/// allocates beyond the engine's copies of the body is what it was charged. Also what the heap grew by beyond those
/// copies, and the measurement at that budget.
fn smallest_admitting(case: &Case, high: usize) -> (usize, usize, Measured) {
    let budget = smallest_budget(high, |budget| !measure(case, Some(budget)).errored);
    let admitted = measure(case, Some(budget));
    let copies = case.copies(&admitted) * chunk(case.body.len());
    assert!(
        admitted.peak_chunks <= copies + budget,
        "{}: the peak {} passes the {budget} the budget allowed beside {copies} bytes of copies of the body",
        case.label,
        admitted.peak_chunks
    );
    (budget, admitted.peak_chunks.saturating_sub(copies), admitted)
}

#[test]
fn the_smallest_budget_that_admits_a_body_covers_its_peak() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for case in &admitted_cases() {
        let (budget, grown, admitted) = smallest_admitting(case, 1 << 30);
        assert!(admitted.values > 0, "{}: {}", case.label, admitted.message);
        assert!(
            budget <= 4 * grown.max(1),
            "{}: a budget of {budget} for {grown} bytes of growth is wasteful",
            case.label
        );
    }
}

/// A multipart body whose one part has a Content-Disposition of `disposition_len` bytes.
fn multipart_with_header(disposition_len: usize) -> Vec<u8> {
    let mut body = b"--b\r\nContent-Disposition: form-data; name=\"a\"; filename=\"".to_vec();
    body.resize(body.len() + disposition_len, b'f');
    body.extend_from_slice(b"\"\r\n\r\ndata\r\n--b--\r\n");
    body
}

#[test]
fn a_multipart_header_block_is_reserved_before_it_is_parsed_and_a_budget_stop_is_not_a_strict_error() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    // Within the 10 MiB header limit, so only the budget can stop it.
    let case = case("multipart", "multipart", "", multipart_with_header(9 * MIB));
    for budget in [0, 64 * 1024] {
        let measured = measure(&case, Some(budget));
        assert!(measured.errored, "budget {budget}: the budget error is reported");
        assert!(
            measured.message.contains("body memory budget"),
            "budget {budget}: {}",
            measured.message
        );
        assert!(
            !measured.strict,
            "budget {budget}: running out of budget is not a strictness violation"
        );
        // The engine's own copies of the body, the budget and slack; nothing parsed from the header.
        assert!(
            measured.peak_chunks <= 2 * case.body.len() + budget + SLACK,
            "budget {budget}: the peak {} grows with the header block the budget refused",
            measured.peak_chunks
        );
    }
}

#[test]
fn the_parts_of_a_multipart_body_are_charged_what_they_hold_while_they_wait() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    // A thousand uploads, each part with a list of headers, its names and a filename.
    let case = case("multipart", "multipart", "SecUploadFileLimit 0", uploads(1000));
    // The smallest budget that reads them all holds them all, then runs out while they are published.
    let budget = smallest_budget(1 << 30, |budget| {
        !measure(&case, Some(budget)).message.starts_with("malformed multipart")
    });
    let measured = measure(&case, Some(budget));
    assert_eq!(measured.message, "published parts exceed the body memory budget");
    assert!(
        measured.peak_chunks <= case.body.len() + budget,
        "the peak {} passes the {budget} byte budget",
        measured.peak_chunks
    );
}

#[test]
fn xml_names_are_reserved_before_they_are_read_and_a_tags_name_stays_reserved_to_its_end() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let name_in_tag = format!("<{} a=\"x\" b=\"{}\"/>", "n".repeat(MIB), "v".repeat(5 * MIB / 2));
    let cases = [
        // A processing-instruction target that is not `xml` is read whole before anything else is known of it.
        (
            case(
                "a long processing instruction target",
                "xml",
                XML_LIMIT,
                repeated(b"<?", b"x", BIG, b" data?><r/>"),
            ),
            0,
        ),
        (
            case(
                "a long prefixed name",
                "xml",
                XML_LIMIT,
                repeated(b"<", b"x", BIG, b":y/>"),
            ),
            0,
        ),
        // A 1 MiB element name stays live while the attributes after a short first one are read: a 3 MiB budget
        // does not cover them together, whichever of them is read second.
        (
            case(
                "a name, a short attribute and a long one",
                "xml",
                XML_LIMIT,
                name_in_tag.into_bytes(),
            ),
            3 * MIB,
        ),
    ];
    for (case, budget) in cases {
        let measured = measure(&case, Some(budget));
        assert!(measured.errored, "{}: the budget error is reported", case.label);
        assert!(
            measured.peak_chunks <= case.body.len() + budget + 64 * 1024,
            "{}: the peak {} is over the engine's copy of the body and the {budget} byte budget",
            case.label,
            measured.peak_chunks
        );
    }
}

#[test]
fn a_start_tag_the_budget_stops_in_keeps_none_of_its_attributes_and_takes_them_back_in_place() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    // A thousand values leave `//@*` spare slots, then a tag's first attribute fits and its second does not.
    let body = |value: usize| {
        let tags = "<a x=\"1\"/>".repeat(1000);
        case(
            "xml",
            "xml",
            XML_LIMIT,
            format!("<r>{tags}<b y=\"1\" z=\"{}\"/></r>", "x".repeat(value)).into_bytes(),
        )
    };
    let budget = smallest_budget(1 << 30, |budget| !measure(&body(1), Some(budget)).errored);
    let stopped = body(100_000);
    let measured = measure(&stopped, Some(budget));
    assert!(measured.errored, "{}", measured.message);
    assert_eq!(measured.values, 1000, "the tag that was never read whole keeps none");
    // Trimming the list it took them back from would copy the thousand values beside it.
    assert!(
        measured.peak_chunks <= stopped.body.len() + budget,
        "the peak {} passes the {budget} byte budget",
        measured.peak_chunks
    );
}

#[test]
fn json_scratch_and_the_traversal_stack_are_reserved_before_they_grow() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let deep = 100_000;
    let cases = [
        // A document that is one string with an escape unescapes into a buffer as long as the string.
        (
            case(
                "a root string with an escape",
                "json",
                "",
                repeated(b"\"\\n", b"x", 3 * MIB, b"\""),
            ),
            MIB,
        ),
        // A chain of nested arrays under a raised depth limit: the index of its containers fits, and the stack of
        // open containers, which holds a frame per level, does not.
        (
            case(
                "a hundred thousand nested arrays",
                "json",
                "SecRequestBodyJsonDepthLimit 1000000",
                [vec![b'['; deep], vec![b']'; deep]].concat(),
            ),
            10 * MIB,
        ),
    ];
    for (case, budget) in cases {
        let measured = measure(&case, Some(budget));
        assert!(
            measured.errored && measured.message.contains("body memory budget"),
            "{}: the budget error is reported: {}",
            case.label,
            measured.message
        );
        // The engine's copy of the body, the budget and slack.
        assert!(
            measured.peak_chunks <= case.body.len() + budget + SLACK,
            "{}: the peak {} is over the engine's copy of the {} byte body and the {budget} byte budget",
            case.label,
            measured.peak_chunks,
            case.body.len()
        );
    }
}

/// The longest an error message may be when the processor has a budget, which quotes only an excerpt of what is
/// malformed.
const EXCERPT_MESSAGE_LIMIT: usize = 1024;

#[test]
fn the_diagnostics_of_malformed_input_stay_within_the_budget_and_are_accounted_for() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let size = 3 * MIB;
    let cases = [
        case(
            "xml: a long mismatched end tag name",
            "xml",
            XML_LIMIT,
            repeated(b"<a></", b"b", size, b">"),
        ),
        case(
            "xml: a long end tag name with nothing open",
            "xml",
            XML_LIMIT,
            repeated(b"</", b"b", size, b">"),
        ),
        case(
            "xml: characters after a long end tag name",
            "xml",
            XML_LIMIT,
            repeated(b"<a></", b"b", size, b" x>"),
        ),
        case(
            "xml: an end tag name in the wrong space",
            "xml",
            XML_LIMIT,
            repeated(b"<p:a></q:", b"b", size, b">"),
        ),
        case(
            "xml: a bad version in the declaration",
            "xml",
            XML_LIMIT,
            repeated(b"<?xml version=\"", b"9", size, b"\"?><a/>"),
        ),
        case(
            "xml: an unsupported encoding in the declaration",
            "xml",
            XML_LIMIT,
            repeated(b"<?xml encoding=\"", b"e", size, b"\"?><a/>"),
        ),
        case(
            "multipart: a header line without a colon",
            "multipart",
            "",
            repeated(
                b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n",
                b"h",
                256 * 1024,
                b"\r\n\r\nv\r\n--b--\r\n",
            ),
        ),
        case(
            "multipart: a header name with a bad byte",
            "multipart",
            "",
            repeated(
                b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n(",
                b"h",
                256 * 1024,
                b": v\r\n\r\nv\r\n--b--\r\n",
            ),
        ),
        case(
            "multipart: a delimiter line that goes on",
            "multipart",
            "",
            repeated(
                b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--b ",
                b"x",
                size,
                b"\r\nmore\r\n--b--\r\n",
            ),
        ),
    ];
    for case in &cases {
        let measured = measure(case, Some(BUDGET));
        assert!(measured.errored, "{}: the malformed input is reported", case.label);
        assert!(
            measured.message.len() <= EXCERPT_MESSAGE_LIMIT,
            "{}: the message quotes {} bytes of the input",
            case.label,
            measured.message.len()
        );
        assert!(
            measured.peak_chunks <= 2 * case.body.len() + BUDGET + SLACK,
            "{}: the peak {} is over two copies of the body and the budget",
            case.label,
            measured.peak_chunks
        );
        assert_accounting_is_conservative(case.label, &measured);
    }
}

#[test]
fn duplicate_json_members_are_charged_for_what_they_allocate_and_a_fitting_budget_keeps_them_all() {
    const COUNT: usize = 100_000;
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let case = case(
        "duplicate json members",
        "json",
        "SecArgumentsLimit 1000000",
        format!("{{{}}}", vec!["\"a\":1"; COUNT].join(",")).into_bytes(),
    );
    let unbudgeted = measure(&case, None);
    assert_eq!(unbudgeted.values, COUNT);
    // The walk's own list and the entries of both collections are held together while the collections are filled,
    // so what the body needs is the peak and not what is left afterwards. A budget a sixth above it must admit it
    // whole: the key is one spelling, shared by every value, and charging it again for each would not.
    let budget = unbudgeted.peak_chunks + unbudgeted.peak_chunks / 6;
    let measured = measure(&case, Some(budget));
    assert!(
        !measured.errored,
        "the budget error is raised: {} of {COUNT} values were kept",
        measured.values
    );
    assert_eq!(measured.values, COUNT);
    assert_accounting_is_conservative(case.label, &measured);
    assert!(
        measured.peak_chunks <= 2 * case.body.len() + budget + SLACK,
        "peak {} is over the budget {budget}",
        measured.peak_chunks
    );
}

#[test]
fn json_and_multipart_values_are_charged_for_growing_a_list_the_query_or_body_filled_before() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let processors = [
        (
            case("json", "json", "SecArgumentsLimit 100000", b"{\"a\":1}".to_vec()),
            "json.a",
        ),
        (
            case(
                "multipart",
                "multipart",
                "SecArgumentsLimit 100000",
                b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--b--\r\n".to_vec(),
            ),
            "a",
        ),
    ];
    let budget = 16 * 1024;
    // `ARGS` holds `existing` values of `key`, from the query string alone or as body arguments as well.
    let filled = |case: &Case, key: &str, existing: usize, query: bool| {
        let mut tx = prepared(case, Some(budget));
        for _ in 0..existing {
            if query {
                tx.add_get_argument(key, "v");
            } else {
                tx.add_post_argument(key, "v");
            }
        }
        tx
    };
    let args = |tx: &Transaction| match tx.collection(RuleVariable::Args) {
        Some(VariableCollection::Map(map)) => map.value_count(),
        _ => 0,
    };
    for (case, key) in &processors {
        for query in [true, false] {
            // 1,024 values fill the list exactly, so one more grows it by a quarter: tens of kilobytes the budget
            // does not have. 1,000 leave room, and the value costs only what it allocates.
            for (existing, grows) in [(4, true), (16, true), (1024, true), (1000, false)] {
                let label = format!("{} into {existing} values, from the query: {query}", case.label);
                let mut tx = filled(case, key, existing, query);
                let measured = measure_body(&mut tx, &case.body, false);
                // What the budget allows beyond the engine's copies of the body is the 16 KiB and a little slack.
                assert!(
                    measured.peak_chunks <= 2 * case.body.len() + budget + 4096,
                    "{label}: the peak {} is over the {budget} byte budget",
                    measured.peak_chunks
                );
                if existing == 1024 {
                    assert!(measured.errored, "{label}: the growth is refused, not made");
                    assert_eq!(args(&tx), existing, "{label}: nothing was added");
                }
                if !grows {
                    assert!(!measured.errored, "{label}: a spare slot costs only the value");
                    assert_eq!(args(&tx), existing + 1, "{label}");
                }
            }
        }
    }

    // Members under two spellings of the name join the one list a case-insensitive collection files them in: the
    // 25 of them take the 1,000 values the query left to past 1,024, which is refused.
    let spellings = format!("{{\"A\":1{}}}", ",\"a\":1,\"A\":1".repeat(12));
    let spelled = case("json", "json", "SecArgumentsLimit 100000", spellings.into_bytes());
    let mut tx = filled(&spelled, "json.a", 1000, true);
    let measured = measure_body(&mut tx, &spelled.body, false);
    assert!(measured.errored, "the growth of the shared list is refused");
    assert_eq!(args(&tx), 1024, "the values that fit the list were kept");
    assert!(
        measured.peak_chunks <= 2 * spelled.body.len() + budget + 4096,
        "the peak {} is over the {budget} byte budget",
        measured.peak_chunks
    );
}

#[test]
fn a_new_key_in_a_full_table_of_arguments_is_charged_for_the_table_that_replaces_it() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let cases = [
        case("json", "json", "SecArgumentsLimit 100000", b"{\"new\":1}".to_vec()),
        case(
            "urlencoded",
            "urlencoded",
            "SecArgumentsLimit 100000",
            b"new=1".to_vec(),
        ),
        case(
            "multipart",
            "multipart",
            "SecArgumentsLimit 100000",
            b"--b\r\nContent-Disposition: form-data; name=\"new\"\r\n\r\n1\r\n--b--\r\n".to_vec(),
        ),
    ];
    // 896 keys fill the table of a map exactly: one more makes a table twice as big, beside the old one.
    let with_query = |case: &Case, budget: usize| {
        let mut tx = prepared(case, Some(budget));
        for index in 0..896 {
            tx.add_get_argument(format!("q{index}"), "v");
        }
        tx
    };
    for case in &cases {
        let small = 16 * 1024;
        let mut tx = with_query(case, small);
        let before = tx.body_memory_bytes();
        let refused = measure_body(&mut tx, &case.body, false);
        assert!(refused.errored, "{}: a table that does not fit is not made", case.label);
        assert_eq!(refused.values, 0, "{}: and nothing is added", case.label);
        assert!(
            tx.body_memory_bytes().saturating_sub(before) <= small,
            "{}: the retained growth stays within the budget",
            case.label
        );

        // The budget that admits it covers the growth of the table, and the peak stays within it.
        let budget = smallest_budget(MIB, |budget| {
            !measure_body(&mut with_query(case, budget), &case.body, false).errored
        });
        let mut tx = with_query(case, budget);
        let before = tx.body_memory_bytes();
        let admitted = measure_body(&mut tx, &case.body, false);
        assert!(admitted.values == 1, "{}", case.label);
        assert!(
            admitted.peak_chunks <= case.body.len() + budget,
            "{}: the peak {} passes the {budget} byte budget",
            case.label,
            admitted.peak_chunks
        );
        assert!(
            tx.body_memory_bytes().saturating_sub(before) <= budget,
            "{}: the retained growth passes the budget",
            case.label
        );
    }
}

#[test]
fn a_name_is_charged_what_its_collections_allocate_for_it() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let long = "k".repeat(4096);
    let lowercase = format!("{}=1", "\u{e9}".repeat(16));
    let form = |label, case_sensitive, body: String| Case {
        case_sensitive,
        ..case(label, "urlencoded", "SecArgumentsLimit 100000", body.into_bytes())
    };
    let cases = [
        // The second value shares the key the first made in each collection.
        form("a 4 KiB name twice", false, format!("{long}=1&{long}=2")),
        // A case-sensitive collection keeps one copy of a name, its map key, which every value shares.
        form(
            "a 600 KiB name in case-sensitive collections",
            true,
            format!("{}=1", "k".repeat(600 * 1024)),
        ),
        // A name that is not UTF-8 keeps a lossy text, whose buffer doubles beside the old one while it is built.
        form(
            "a name that is not UTF-8 in case-sensitive collections",
            true,
            format!("{}=1", "%FF".repeat(16 * 1024)),
        ),
        // A name that is its own lowercase form is filed under itself, whatever its bytes.
        form(
            "a lowercase name that is not ASCII, repeated",
            false,
            vec![lowercase.as_str(); 2000].join("&"),
        ),
        // A list that grows gives back the one it replaced.
        form("a thousand values of one name", false, vec!["a=1"; 1000].join("&")),
        // Distinct names grow the tables of keys, which are charged as large as they are allocated.
        form(
            "two thousand names",
            false,
            (0..2000).map(|i| format!("a{i}=1")).collect::<Vec<_>>().join("&"),
        ),
        case(
            "two thousand JSON names",
            "json",
            "SecArgumentsLimit 100000",
            format!(
                "{{{}}}",
                (0..2000).map(|i| format!("\"a{i}\":1")).collect::<Vec<_>>().join(",")
            )
            .into_bytes(),
        ),
        case(
            "a thousand fields of distinct names",
            "multipart",
            "SecArgumentsLimit 100000",
            format!(
                "{}--b--\r\n",
                (0..1000)
                    .map(|i| format!("--b\r\nContent-Disposition: form-data; name=\"a{i}\"\r\n\r\n1\r\n"))
                    .collect::<String>()
            )
            .into_bytes(),
        ),
        // A field is filed under its name in the collections of its part's metadata as well.
        case(
            "a thousand fields of one name",
            "multipart",
            "SecArgumentsLimit 100000",
            format!(
                "{}--b--\r\n",
                "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n".repeat(1000)
            )
            .into_bytes(),
        ),
    ];
    for case in &cases {
        let (budget, grown, _) = smallest_admitting(case, 1_000 * case.body.len());
        // The growths of the collections are charged before any is made, which is all a budget adds.
        assert!(
            budget <= grown + grown / 4,
            "{}: a budget of {budget} for {grown} bytes of growth charges what is not allocated",
            case.label
        );
    }
}

#[test]
fn a_camel_case_json_name_is_charged_the_spelling_its_collections_keep_and_no_more() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    // The smallest budget that admits 500 names, and the peak of parsing them.
    let measured = |name: &str| {
        let members: Vec<String> = (0..500).map(|index| format!("\"{name}{index}\":1")).collect();
        let body = format!("{{{}}}", members.join(",")).into_bytes();
        let case = case("json names", "json", "", body);
        let budget = smallest_budget(1 << 30, |budget| !measure(&case, Some(budget)).errored);
        (budget, measure(&case, None).peak_chunks)
    };
    let (lower, camel) = (measured("username"), measured("userName"));
    // The walk's count of the names that fold alike is dropped before the collections are filled, so their copies of
    // the spelling are all the budget adds.
    assert!(
        camel.0 - lower.0 <= 2 * (camel.1 - lower.1),
        "camelCase adds {} to the budget for {} of peak",
        camel.0 - lower.0,
        camel.1 - lower.1
    );
}

/// A multipart body of `count` uploads, each under its own name.
fn uploads(count: usize) -> Vec<u8> {
    let mut body = String::new();
    for index in 0..count {
        write!(
            body,
            "--b\r\nContent-Disposition: form-data; name=\"f{index}\"; filename=\"x{index}.txt\"\r\n\r\nx\r\n"
        )
        .unwrap();
    }
    body.push_str("--b--\r\n");
    body.into_bytes()
}

#[test]
fn the_paths_of_the_temporary_uploads_a_transaction_keeps_are_part_of_its_estimate() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    // Long paths, so that the copy kept for cleanup, beside the one in `FILES_TMPNAMES`, is most of what is held.
    let directory = tempfile::tempdir().unwrap();
    let mut path = directory.path().to_path_buf();
    for _ in 0..3 {
        path.push("d".repeat(250));
    }
    std::fs::create_dir_all(&path).unwrap();
    let mut parser = Parser::new();
    parser
        .from_string(
            "SecRequestBodyAccess On\nSecRequestBodyLimit 134217728\nSecUploadFileLimit 1000\n\
             SecAction \"id:1,phase:1,ctl:requestBodyProcessor=MULTIPART,pass,nolog\"",
        )
        .unwrap();
    parser.config_mut().upload_dir = path.to_string_lossy().into_owned();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction_with_id("measured");
    tx.add_request_header("Content-Type", "multipart/form-data; boundary=b");
    tx.process_request_headers();
    let measured = measure_body(&mut tx, &uploads(1000), false);
    assert!(!measured.errored, "{}", measured.message);
    assert_accounting_is_conservative("1,000 uploads", &measured);
}

#[test]
fn a_full_tx_table_is_estimated_as_held_when_a_key_is_rewritten_or_most_are_removed() {
    // 1,792 keys fill a table of 2,048 buckets, the eleven capture keys a transaction starts with among them.
    const FULL: usize = 1_792;
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let removals: Vec<_> = (5..FULL).map(|index| format!("setvar:!tx.k{index}")).collect();
    let mut parser = Parser::new();
    parser
        .from_string(&format!("SecAction \"id:1,phase:1,pass,nolog,{}\"", removals.join(",")))
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let keys = |tx: &Transaction| match tx.collection(RuleVariable::TX) {
        Some(VariableCollection::Map(map)) => map.len(),
        _ => 0,
    };
    let rewrite: fn(&mut Transaction) = |tx| tx.set_tx_variable("k0", "2");
    let remove: fn(&mut Transaction) = |tx| {
        tx.process_request_headers();
    };
    for (label, step) in [("rewritten", rewrite), ("removed", remove)] {
        let mut tx = waf.new_transaction_with_id("measured");
        let (chunks, estimate) = (CHUNKS.load(SeqCst), tx.body_memory_bytes());
        let mut index = 0;
        while keys(&tx) < FULL {
            tx.set_tx_variable(&format!("k{index}"), "1");
            index += 1;
        }
        step(&mut tx);
        let (held, estimated) = (CHUNKS.load(SeqCst), tx.body_memory_bytes());
        assert!(
            held + estimate <= chunks + estimated + ACCOUNTING_SLACK,
            "{label}: the transaction went from {chunks} to {held} bytes but estimates {estimate} to {estimated}"
        );
    }
}
