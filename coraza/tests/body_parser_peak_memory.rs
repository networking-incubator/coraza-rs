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
    clippy::print_stderr,
    reason = "a counting global allocator and fixed fixtures; the allocator only forwards to System"
)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    fmt::Write as _,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
};

use coraza::{
    seclang::Parser,
    transaction::{Transaction, VariableCollection},
    types::RuleVariable,
};

/// Forwards to the system allocator while tracking live and peak bytes, in two ways.
///
/// `CURRENT` and `PEAK` count the bytes the program asked for. `CHUNKS` and `PEAK_CHUNKS` model what a request
/// holds in the worst allocator it can run on: every allocation is charged the chunk a malloc rounds it up to (a
/// header and 16-byte units, 32 at least), and growing one counts the old chunk and the new together at the
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
            if new > old {
                // Both chunks are live while the contents are copied.
                PEAK_CHUNKS.fetch_max(CHUNKS.load(SeqCst) + new, SeqCst);
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

/// Processes `body` as the request body under `processor` and measures the peak heap growth.
fn measure(processor: &str, content_type: &str, body: &[u8], request_xml: bool) -> Measured {
    measure_with(processor, content_type, body, request_xml, &Setup::default())
}

/// What a measurement may add to the engine's default setup.
#[derive(Default)]
struct Setup<'a> {
    /// The absolute memory budget a connector would set.
    budget: Option<usize>,
    /// Extra configuration, such as a larger argument limit.
    configuration: &'a str,
}

/// A transaction that has read the headers of a request that selects `processor`, under an absolute memory budget
/// and extra configuration.
fn prepared(processor: &str, content_type: &str, budget: Option<usize>, configuration: &str) -> Transaction {
    let mut parser = Parser::new();
    parser
        .from_string(&format!(
            "SecRequestBodyAccess On\nSecRequestBodyLimit 134217728\n{configuration}\n\
             SecAction \"id:1,phase:1,ctl:requestBodyProcessor={processor},pass,nolog\""
        ))
        .unwrap();
    let waf = parser.into_waf().unwrap();
    // A fixed id: the generated one grows a digit as other tests make transactions, and the matched rules keep a
    // copy of it, so two measurements to compare could otherwise differ by that byte.
    let mut tx = waf.new_transaction_with_id("measured");
    tx.set_body_memory_budget(budget);
    tx.add_request_header("Content-Type", content_type);
    tx.process_request_headers();
    tx
}

/// [`measure`] under an absolute memory budget and extra configuration.
fn measure_with(processor: &str, content_type: &str, body: &[u8], request_xml: bool, setup: &Setup<'_>) -> Measured {
    let Setup { budget, configuration } = *setup;
    let mut tx = prepared(processor, content_type, budget, configuration);
    measure_body(&mut tx, body, request_xml)
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
const ACCOUNTING_SLACK: usize = 64 * 1024;

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

/// A multiple of `body_len` in tenths, for readable output without float casts.
fn tenths(bytes: usize, body_len: usize) -> String {
    let tenths = bytes.saturating_mul(10) / body_len.max(1);
    format!("{}.{}x", tenths / 10, tenths % 10)
}

/// `<r>` then `unit` repeated to about `size` bytes, then `</r>`.
fn xml_of(unit: &[u8], size: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(size + 16);
    body.extend_from_slice(b"<r>");
    while body.len() < size {
        body.extend_from_slice(unit);
    }
    body.extend_from_slice(b"</r>");
    body
}

/// One start tag with as many valueless attributes as fit in `size` bytes.
fn xml_one_tag(size: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(size + 16);
    body.extend_from_slice(b"<r");
    while body.len() < size {
        body.extend_from_slice(b" b");
    }
    body.extend_from_slice(b"></r>");
    body
}

/// An object with one very long key over 999 array leaves, the path-amplification body.
fn json_long_key(size: usize) -> Vec<u8> {
    json_long_key_of(b'k', size)
}

/// [`json_long_key`] with a key of `byte`s, which is not valid UTF-8 when it is above 0x7F.
fn json_long_key_of(byte: u8, size: usize) -> Vec<u8> {
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
/// Only an absolute budget bounds that; without one Go Coraza admits it too.
const XML_ONE_PER_TWO_BYTES_PEAK_FACTOR: usize = 30;

/// And counting the allocator's chunks, where each of the million values is one of thirty-two bytes.
const XML_ONE_PER_TWO_BYTES_CHUNK_FACTOR: usize = 70;

/// Peak growth the JSON flattener may reach before Go's raw budget stops it: that budget is eight times the body of
/// keys and values, and the transaction holds three copies of each.
const JSON_PEAK_FACTOR: usize = 26;

const MIB: usize = 1024 * 1024;

/// A body that amplifies, with the processor that reads it and the peak multiple it may reach.
struct Amplifying {
    /// Name for failure messages.
    label: &'static str,
    /// The body processor, as `ctl:requestBodyProcessor` names it.
    processor: &'static str,
    /// The request `Content-Type`.
    content_type: &'static str,
    /// The body.
    body: Vec<u8>,
    /// Whether the values land in `REQUEST_XML` rather than `ARGS_POST`.
    request_xml: bool,
    /// The most the peak may be, as a multiple of the body.
    factor: usize,
    /// The most the peak may be, as a multiple of the body, counting the allocator's chunks.
    chunk_factor: usize,
    /// Whether Go's own limit refuses the body: an XML document is never refused, a JSON one over its 8x budget is.
    refused: bool,
}

/// The bodies that amplify.
fn amplifying_cases() -> Vec<Amplifying> {
    let xml = |label, body, factor, chunk_factor| Amplifying {
        label,
        processor: "xml",
        content_type: "text/xml",
        body,
        request_xml: true,
        factor,
        chunk_factor,
        refused: false,
    };
    vec![
        xml(
            "xml, one value per two bytes in one tag",
            xml_one_tag(2 * MIB),
            XML_ONE_PER_TWO_BYTES_PEAK_FACTOR,
            XML_ONE_PER_TWO_BYTES_CHUNK_FACTOR,
        ),
        xml(
            "xml, 14-byte element with an attribute and text",
            xml_of(b"<a b=\"c\">d</a>", 2 * MIB),
            XML_PEAK_FACTOR,
            XML_CHUNK_PEAK_FACTOR,
        ),
        xml(
            "xml, valueless attributes in many tags",
            xml_of(b"<a b c d e f g h/>", 2 * MIB),
            XML_ONE_PER_TWO_BYTES_PEAK_FACTOR,
            XML_ONE_PER_TWO_BYTES_CHUNK_FACTOR,
        ),
        Amplifying {
            label: "json, long key over 999 leaves",
            processor: "json",
            content_type: "application/json",
            body: json_long_key(3 * MIB),
            request_xml: false,
            factor: JSON_PEAK_FACTOR,
            chunk_factor: JSON_PEAK_FACTOR,
            refused: true,
        },
    ]
}

#[test]
fn without_a_budget_nothing_but_gos_own_limit_is_refused_and_accounting_covers_what_is_held() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for case in amplifying_cases() {
        let length = case.body.len();
        let measured = measure(case.processor, case.content_type, &case.body, case.request_xml);
        eprintln!(
            "{}: body {length}, peak {} ({} with allocator chunks), retained {}, values {}, error {:?}",
            case.label,
            tenths(measured.peak, length),
            tenths(measured.peak_chunks, length),
            tenths(measured.retained, length),
            measured.values,
            measured.message
        );
        assert_eq!(measured.errored, case.refused, "{}: {}", case.label, measured.message);
        assert_accounting_is_conservative(case.label, &measured);
        assert!(
            measured.peak <= case.factor * length,
            "{}: peak {} bytes is over {}x the {length} byte body",
            case.label,
            measured.peak,
            case.factor
        );
        assert!(
            measured.peak_chunks <= case.chunk_factor * length,
            "{}: peak {} bytes with allocator chunks is over {}x the {length} byte body",
            case.label,
            measured.peak_chunks,
            case.chunk_factor
        );
        assert!(
            measured.retained <= case.chunk_factor * length,
            "{}: retained {} bytes is over {}x the {length} byte body",
            case.label,
            measured.retained,
            case.chunk_factor
        );
    }

    // The same machinery must leave ordinary bodies alone.
    let ordinary = [
        (
            "ordinary xml",
            "xml",
            "text/xml",
            xml_of(b"<item id=\"7\"><name>Alice</name><note>hello world</note></item>", MIB),
            true,
        ),
        ("dense xml list", "xml", "text/xml", xml_of(b"<i>12345</i>", MIB), true),
        (
            "densest ordinary xml list",
            "xml",
            "text/xml",
            xml_of(b"<i>1</i>", MIB),
            true,
        ),
        ("ordinary json", "json", "application/json", json_ordinary(8_000), false),
        (
            "dense json array",
            "json",
            "application/json",
            format!("[{}1]", "1,".repeat(MIB / 4)).into_bytes(),
            false,
        ),
    ];
    for (label, processor, content_type, body, request_xml) in ordinary {
        let length = body.len();
        let measured = measure(processor, content_type, &body, request_xml);
        eprintln!(
            "{label}: body {length}, peak {} ({} with allocator chunks), retained {}, values {}",
            tenths(measured.peak, length),
            tenths(measured.peak_chunks, length),
            tenths(measured.retained, length),
            measured.values
        );
        assert!(
            !measured.errored,
            "{label}: no error for an ordinary body ({})",
            measured.message
        );
        assert!(measured.values > 0, "{label}: the values were published");
        assert_accounting_is_conservative(label, &measured);
    }
}

/// The absolute budget a connector gives the processors in the cases below.
const BUDGET: usize = 8 * MIB;

/// The size of the bodies that must not make a processor go past [`BUDGET`]: twice the budget.
const BIG: usize = 16 * MIB;

/// What the heap may grow by beyond the budget and the engine's own copies of the body: the lists a processor
/// grows, the transaction's own variables and the allocator's rounding.
const SLACK: usize = MIB;

/// A body shaped to make a processor hold as much as it can.
struct Budgeted {
    /// Name for failure messages.
    label: &'static str,
    /// The body processor, as `ctl:requestBodyProcessor` names it.
    processor: &'static str,
    /// The request `Content-Type`.
    content_type: &'static str,
    /// Extra configuration the body needs, such as a larger argument limit.
    configuration: &'static str,
    /// The body.
    body: Vec<u8>,
    /// Whether the values land in `REQUEST_XML` rather than `ARGS_POST`.
    request_xml: bool,
    /// Copies of the body the engine itself holds while the processor runs: the buffer, and for URL-encoded
    /// bodies the raw `REQUEST_BODY` beside it. They are not the processor's, and no budget is for them.
    copies: usize,
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

/// The bodies that must stop at the budget.
fn budgeted_cases() -> Vec<Budgeted> {
    let xml = |label, body| Budgeted {
        label,
        processor: "xml",
        content_type: "text/xml",
        configuration: "",
        body,
        request_xml: true,
        copies: 1,
    };
    let json = |label, configuration, body| Budgeted {
        label,
        processor: "json",
        content_type: "application/json",
        configuration,
        body,
        request_xml: false,
        copies: 1,
    };
    let form = |label, body| Budgeted {
        label,
        processor: "urlencoded",
        content_type: "application/x-www-form-urlencoded",
        configuration: "SecArgumentsLimit 100000000",
        body,
        request_xml: false,
        copies: 2,
    };
    vec![
        xml("xml, attribute and text per element", xml_of(b"<a b=\"c\">d</a>", BIG)),
        xml("xml, one value per two bytes in one tag", xml_one_tag(BIG)),
        xml(
            "xml, valueless attributes in many tags",
            xml_of(b"<a b c d e f g h/>", BIG),
        ),
        xml("xml, densest text list", xml_of(b"<i>1</i>", BIG)),
        xml("xml, nested elements", xml_of(b"<a>", BIG)),
        xml("xml, one text node", repeated(b"<r>", b"x", BIG, b"</r>")),
        xml("xml, one escaped text node", repeated(b"<r>", b"&amp;", BIG, b"</r>")),
        xml("xml, one element name", repeated(b"<", b"x", BIG, b">")),
        xml("xml, one attribute value", repeated(b"<r a=\"", b"x", BIG, b"\"/>")),
        xml(
            "xml, one processing instruction",
            repeated(b"<?xml ", b"x", BIG, b"?><r/>"),
        ),
        json("json, long key over 999 leaves", "", json_long_key(BIG)),
        json(
            "json, long invalid UTF-8 key over 999 leaves",
            "",
            json_long_key_of(0xFF, BIG),
        ),
        // One key that fits the budget as bytes (about 5 times its length is charged for a valid one) but not
        // with its text views, in a body padded to the size of the others.
        json(
            "json, one invalid UTF-8 key beside a big body",
            "",
            [&b"{\""[..], &vec![0xFF; 3 * MIB / 2], b"\":1}", &vec![b' '; BIG]].concat(),
        ),
        json("json, container index", "", repeated(b"[", b"[[]],", BIG, b"[]]")),
        json(
            "json, deeply nested objects with leaves",
            "",
            repeated(b"[", b"{\"a\":[1]},", BIG, b"1]"),
        ),
        // A single escape makes the string unescape into a buffer as long as the string itself.
        json(
            "json, one escaped string",
            "",
            repeated(b"{\"a\":\"\\n", b"x", BIG, b"\"}"),
        ),
        json("json, one escaped key", "", repeated(b"{\"\\n", b"x", BIG, b"\":1}")),
        json(
            "json, many escapes in one string",
            "",
            repeated(b"{\"a\":\"", b"\\n", BIG, b"\"}"),
        ),
        json(
            "json, many leaves",
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
        let setup = Setup {
            budget: Some(BUDGET),
            configuration: case.configuration,
        };
        let measured = measure_with(case.processor, case.content_type, &case.body, case.request_xml, &setup);
        let length = case.body.len();
        let allowed = case.copies * length + BUDGET + SLACK;
        eprintln!(
            "{}: body {length}, peak {} (the engine's {} copies and the budget allow {}), retained {}, values {}, error {:?}",
            case.label,
            tenths(measured.peak_chunks, length),
            case.copies,
            tenths(allowed, length),
            tenths(measured.retained, length),
            measured.values,
            measured.message
        );
        assert!(measured.errored, "{}: the budget error is reported", case.label);
        assert_accounting_is_conservative(case.label, &measured);
        assert!(
            measured.peak_chunks <= allowed,
            "{}: peak {} bytes is over the {allowed} that {} copies of the body, the {BUDGET} byte budget and {SLACK} of slack allow",
            case.label,
            measured.peak_chunks,
            case.copies
        );
    }
}

#[test]
fn a_budget_that_is_not_reached_changes_nothing() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let cases = [
        (
            "xml",
            "text/xml",
            xml_of(
                b"<item id=\"7\"><name>Alice</name><note>hello world</note></item>",
                MIB / 4,
            ),
            true,
        ),
        ("json", "application/json", json_ordinary(500), false),
        (
            "urlencoded",
            "application/x-www-form-urlencoded",
            repeated(b"", b"name=Alice&", 10_000, b""),
            false,
        ),
    ];
    for (processor, content_type, body, request_xml) in cases {
        let plain = measure(processor, content_type, &body, request_xml);
        let setup = Setup {
            budget: Some(BUDGET),
            configuration: "",
        };
        let budgeted = measure_with(processor, content_type, &body, request_xml, &setup);
        assert!(!budgeted.errored, "{processor}: {}", budgeted.message);
        assert_eq!(
            budgeted.values, plain.values,
            "{processor}: the same values are published"
        );
        assert_eq!(budgeted.retained, plain.retained, "{processor}: and retained alike");
    }
}

/// A body that parses in full under a big enough budget, whose smallest such budget is found.
struct Boundary {
    /// Name for failure messages.
    label: &'static str,
    /// The body processor, as `ctl:requestBodyProcessor` names it.
    processor: &'static str,
    /// The request `Content-Type`.
    content_type: &'static str,
    /// Extra configuration, such as a larger argument limit.
    configuration: &'static str,
    /// The body.
    body: Vec<u8>,
    /// Whether the values land in `REQUEST_XML` rather than `ARGS_POST`.
    request_xml: bool,
    /// Copies of the body the engine holds beside what the processor builds: the buffer, the raw body of a
    /// URL-encoded one and the JSON text a parsed JSON body is kept as.
    copies: usize,
}

/// What `budget` makes of the body.
fn run_boundary(case: &Boundary, budget: usize) -> Measured {
    let setup = Setup {
        budget: Some(budget),
        configuration: case.configuration,
    };
    measure_with(case.processor, case.content_type, &case.body, case.request_xml, &setup)
}

#[test]
fn the_smallest_budget_that_admits_a_body_covers_its_peak_and_one_byte_less_refuses_it() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let json = |label, configuration, body| Boundary {
        label,
        processor: "json",
        content_type: "application/json",
        configuration,
        body,
        request_xml: false,
        copies: 2,
    };
    let xml = |label, body| Boundary {
        label,
        processor: "xml",
        content_type: "text/xml",
        configuration: "",
        body,
        request_xml: true,
        copies: 1,
    };
    let cases = [
        xml("xml, densest list", xml_of(b"<i>1</i>", 60_000)),
        xml("xml, attribute and text", xml_of(b"<a b=\"c\">d</a>", 60_000)),
        xml("xml, valueless attributes", xml_of(b"<a b c d e f g h/>", 60_000)),
        // The body that reached 95 MB of peak and 72 MB retained with a raised argument limit and no budget.
        json(
            "json, dense array under a raised argument limit",
            "SecArgumentsLimit 100000000",
            repeated(b"[", b"1,", 400_000, b"1]"),
        ),
        json(
            "json, long key over a few leaves",
            "",
            repeated(&[b"{\"".as_slice(), &[b'k'; 300], b"\":["].concat(), b"1,", 24, b"1]}"),
        ),
        Boundary {
            label: "urlencoded, many pairs",
            processor: "urlencoded",
            content_type: "application/x-www-form-urlencoded",
            configuration: "SecArgumentsLimit 100000000",
            body: repeated(b"", b"name=value&", 60_000, b""),
            request_xml: false,
            copies: 2,
        },
    ];
    for case in &cases {
        let length = case.body.len();
        // The largest budget the case could need is a few hundred bytes per byte of body.
        let (mut low, mut high) = (0_usize, 1_000 * length);
        assert!(
            !run_boundary(case, high).errored,
            "{}: a huge budget admits it",
            case.label
        );
        while low + 1 < high {
            let middle = low + (high - low) / 2;
            if run_boundary(case, middle).errored {
                low = middle;
            } else {
                high = middle;
            }
        }
        let admitted = run_boundary(case, high);
        let grown = admitted.peak_chunks.saturating_sub(case.copies * length);
        eprintln!(
            "{}: body {length}, smallest budget {high}, peak above the engine's copies {grown}, retained {}",
            case.label, admitted.retained
        );
        assert!(
            run_boundary(case, high - 1).errored,
            "{}: one byte less refuses it",
            case.label
        );
        assert!(
            !admitted.errored && admitted.values > 0,
            "{}: {}",
            case.label,
            admitted.message
        );
        assert!(
            admitted.peak_chunks <= case.copies * length + high + 64 * 1024,
            "{}: the peak {} passes the {high} the budget allowed beside {} copies of the body",
            case.label,
            admitted.peak_chunks,
            case.copies
        );
        assert!(
            high <= 4 * grown.max(1),
            "{}: a budget of {high} for {grown} bytes of growth is wasteful",
            case.label
        );
    }
}

/// A multipart body whose one part has a Content-Disposition of `disposition_len` bytes.
fn multipart_with_header(disposition_len: usize) -> Vec<u8> {
    let mut body = b"--X\r\nContent-Disposition: form-data; name=\"a\"; filename=\"".to_vec();
    body.resize(body.len() + disposition_len, b'f');
    body.extend_from_slice(b"\"\r\n\r\ndata\r\n--X--\r\n");
    body
}

#[test]
fn a_multipart_header_block_is_reserved_before_it_is_parsed_and_a_budget_stop_is_not_a_strict_error() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    // Within the 10 MiB header limit, so only the budget can stop it.
    let body = multipart_with_header(9 * MIB);
    for budget in [0, 64 * 1024] {
        let setup = Setup {
            budget: Some(budget),
            configuration: "",
        };
        let measured = measure_with("multipart", "multipart/form-data; boundary=X", &body, false, &setup);
        eprintln!(
            "multipart header {} with budget {budget}: peak {}, error {:?}",
            body.len(),
            tenths(measured.peak_chunks, body.len()),
            measured.message
        );
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
            measured.peak_chunks <= 2 * body.len() + budget + SLACK,
            "budget {budget}: the peak {} grows with the header block the budget refused",
            measured.peak_chunks
        );
    }
}

#[test]
fn xml_names_are_reserved_before_they_are_read_and_a_tags_name_stays_reserved_to_its_end() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let name_in_tag = format!("<{} a=\"x\" b=\"{}\"/>", "n".repeat(MIB), "v".repeat(5 * MIB / 2));
    let cases = [
        // A processing-instruction target that is not `xml` is read whole before anything else is known of it.
        (
            "a long processing instruction target",
            repeated(b"<?", b"x", BIG, b" data?><r/>"),
            0,
        ),
        ("a long prefixed name", repeated(b"<", b"x", BIG, b":y/>"), 0),
        // A 1 MiB element name stays live while the attributes after a short first one are read: a 3 MiB budget
        // does not cover them together, whichever of them is read second.
        (
            "a name, a short attribute and a long one",
            name_in_tag.into_bytes(),
            3 * MIB,
        ),
    ];
    for (label, body, budget) in cases {
        let setup = Setup {
            budget: Some(budget),
            configuration: "",
        };
        let measured = measure_with("xml", "text/xml", &body, true, &setup);
        eprintln!(
            "{label}: body {}, peak {}, error {:?}",
            body.len(),
            tenths(measured.peak_chunks, body.len()),
            measured.message
        );
        assert!(measured.errored, "{label}: the budget error is reported");
        assert!(
            measured.peak_chunks <= body.len() + budget + 64 * 1024,
            "{label}: the peak {} is over the engine's copy of the body and the {budget} byte budget",
            measured.peak_chunks
        );
    }
}

#[test]
fn json_scratch_and_the_traversal_stack_are_reserved_before_they_grow() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let deep = 100_000;
    let chain = [vec![b'['; deep], vec![b']'; deep]].concat();
    let cases = [
        // A document that is one string with an escape unescapes into a buffer as long as the string.
        (
            "a root string with an escape",
            repeated(b"\"\\n", b"x", 3 * MIB, b"\""),
            "",
            MIB,
        ),
        // A chain of nested arrays under a raised depth limit: the index of its containers fits, and the stack of
        // open containers, which holds a frame per level, does not.
        (
            "a hundred thousand nested arrays",
            chain,
            "SecRequestBodyJsonDepthLimit 1000000",
            10 * MIB,
        ),
    ];
    for (label, body, configuration, budget) in cases {
        let setup = Setup {
            budget: Some(budget),
            configuration,
        };
        let measured = measure_with("json", "application/json", &body, false, &setup);
        eprintln!(
            "{label}: body {}, peak {}, error {:?}",
            body.len(),
            tenths(measured.peak_chunks, body.len()),
            measured.message
        );
        assert!(
            measured.errored,
            "{label}: the budget error is reported: {}",
            measured.message
        );
        assert!(
            measured.message.contains("body memory budget"),
            "{label}: {}",
            measured.message
        );
        // The engine's copy of the body, the budget and slack.
        assert!(
            measured.peak_chunks <= body.len() + budget + SLACK,
            "{label}: the peak {} is over the engine's copy of the {} byte body and the {budget} byte budget",
            measured.peak_chunks,
            body.len()
        );
    }
}

/// The longest an error message may be when the processor has a budget, which quotes only an excerpt of what is
/// malformed.
const EXCERPT_MESSAGE_LIMIT: usize = 1024;

/// What the budget lets a body whose malformed part is `copies` times as long as the body cost: the engine's copies
/// of the body, the budget and slack.
#[track_caller]
fn assert_malformed_input_stays_within_the_budget(label: &str, measured: &Measured, body_len: usize, budget: usize) {
    eprintln!(
        "{label}: body {body_len}, peak {}, retained {}, message {} bytes",
        tenths(measured.peak_chunks, body_len),
        tenths(measured.retained, body_len),
        measured.message.len()
    );
    assert!(measured.errored, "{label}: the malformed input is reported");
    assert!(
        measured.message.len() <= EXCERPT_MESSAGE_LIMIT,
        "{label}: the message quotes {} bytes of the input",
        measured.message.len()
    );
    assert!(
        measured.peak_chunks <= 2 * body_len + budget + SLACK,
        "{label}: the peak {} is over two copies of the {body_len} byte body and the {budget} byte budget",
        measured.peak_chunks
    );
    assert_accounting_is_conservative(label, measured);
}

/// A malformed body: its label, the processor, the content type, the body and whether its values go to `REQUEST_XML`.
type MalformedCase = (&'static str, &'static str, &'static str, Vec<u8>, bool);

#[test]
fn the_diagnostics_of_malformed_input_stay_within_the_budget_and_are_accounted_for() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let size = 3 * MIB;
    let cases: Vec<MalformedCase> = vec![
        (
            "xml: a long mismatched end tag name",
            "xml",
            "text/xml",
            repeated(b"<a></", b"b", size, b">"),
            true,
        ),
        (
            "xml: a long end tag name with nothing open",
            "xml",
            "text/xml",
            repeated(b"</", b"b", size, b">"),
            true,
        ),
        (
            "xml: characters after a long end tag name",
            "xml",
            "text/xml",
            repeated(b"<a></", b"b", size, b" x>"),
            true,
        ),
        (
            "xml: an end tag name in the wrong space",
            "xml",
            "text/xml",
            repeated(b"<p:a></q:", b"b", size, b">"),
            true,
        ),
        (
            "xml: a bad version in the declaration",
            "xml",
            "text/xml",
            repeated(b"<?xml version=\"", b"9", size, b"\"?><a/>"),
            true,
        ),
        (
            "xml: an unsupported encoding in the declaration",
            "xml",
            "text/xml",
            repeated(b"<?xml encoding=\"", b"e", size, b"\"?><a/>"),
            true,
        ),
        (
            "multipart: a header line without a colon",
            "multipart",
            "multipart/form-data; boundary=b",
            repeated(
                b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n",
                b"h",
                256 * 1024,
                b"\r\n\r\nv\r\n--b--\r\n",
            ),
            false,
        ),
        (
            "multipart: a header name with a bad byte",
            "multipart",
            "multipart/form-data; boundary=b",
            repeated(
                b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n(",
                b"h",
                256 * 1024,
                b": v\r\n\r\nv\r\n--b--\r\n",
            ),
            false,
        ),
        (
            "multipart: a delimiter line that goes on",
            "multipart",
            "multipart/form-data; boundary=b",
            repeated(
                b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--b ",
                b"x",
                size,
                b"\r\nmore\r\n--b--\r\n",
            ),
            false,
        ),
    ];
    for (label, processor, content_type, body, request_xml) in cases {
        let setup = Setup {
            budget: Some(BUDGET),
            configuration: "",
        };
        let measured = measure_with(processor, content_type, &body, request_xml, &setup);
        assert_malformed_input_stays_within_the_budget(label, &measured, body.len(), BUDGET);
    }
}

/// The body that adds `count` values to the one key `a`: JSON members, which all land in one path.
fn duplicate_json_members(count: usize) -> Vec<u8> {
    let mut body = b"{".to_vec();
    for index in 0..count {
        if index > 0 {
            body.push(b',');
        }
        body.extend_from_slice(b"\"a\":1");
    }
    body.push(b'}');
    body
}

/// The number of members of the body of the test below.
const COUNT: usize = 100_000;

#[test]
fn duplicate_json_members_are_charged_for_what_they_allocate_and_a_fitting_budget_keeps_them_all() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let body = duplicate_json_members(COUNT);
    let configuration = "SecArgumentsLimit 1000000";
    let unbudgeted = measure_with(
        "json",
        "application/json",
        &body,
        false,
        &Setup {
            budget: None,
            configuration,
        },
    );
    assert_eq!(unbudgeted.values, COUNT);
    // The walk's own list and the entries of both collections are held together while the collections are filled,
    // so what the body needs is the peak and not what is left afterwards. A budget a sixth above it must admit it
    // whole: the key is one spelling, shared by every value, and charging it again for each would not.
    let budget = unbudgeted.peak_chunks + unbudgeted.peak_chunks / 6;
    let measured = measure_with(
        "json",
        "application/json",
        &body,
        false,
        &Setup {
            budget: Some(budget),
            configuration,
        },
    );
    eprintln!(
        "{COUNT} duplicate members: unbudgeted peak {}, retained {}; budget {budget}: values {}, error {:?}",
        unbudgeted.peak_chunks, unbudgeted.retained, measured.values, measured.message
    );
    assert!(
        !measured.errored,
        "the budget error is raised: {} of {COUNT} values were kept",
        measured.values
    );
    assert_eq!(measured.values, COUNT);
    assert_accounting_is_conservative("duplicate json members", &measured);
    assert!(
        measured.peak_chunks <= 2 * body.len() + budget + SLACK,
        "peak {} is over the budget {budget}",
        measured.peak_chunks
    );
}

/// How a collection came to hold the values of a key before the body is processed.
#[derive(Clone, Copy, Debug)]
enum Existing {
    /// Through the query string: `ARGS` alone.
    Query,
    /// As body arguments: `ARGS_POST` and `ARGS`.
    Post,
}

/// Processes `body` under `budget` into a transaction whose collections already hold `existing` values of `key`.
fn measure_into_existing(
    (processor, content_type): (&str, &str),
    body: &[u8],
    key: &str,
    (how, existing): (Existing, usize),
    budget: usize,
) -> (Measured, Transaction) {
    let mut tx = prepared(processor, content_type, Some(budget), "SecArgumentsLimit 100000");
    for _ in 0..existing {
        match how {
            Existing::Query => tx.add_get_argument(key, "v"),
            Existing::Post => tx.add_post_argument(key, "v"),
        }
    }
    let measured = measure_body(&mut tx, body, false);
    (measured, tx)
}

#[test]
fn json_and_multipart_values_are_charged_for_growing_a_list_the_query_or_body_filled_before() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let json = b"{\"a\":1}".to_vec();
    let multipart = b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--b--\r\n".to_vec();
    let processors = [
        (("json", "application/json"), "json.a", json),
        (("multipart", "multipart/form-data; boundary=b"), "a", multipart),
    ];
    let budget = 16 * 1024;
    for (kind, key, body) in &processors {
        for how in [Existing::Query, Existing::Post] {
            // 1,024 values fill the list exactly, so one more grows it by a quarter: tens of kilobytes the budget
            // does not have. 1,000 leave room, and the value costs only what it allocates.
            for (existing, grows) in [(4, true), (16, true), (1024, true), (1000, false)] {
                let label = format!("{} into {existing} values from {how:?}", kind.0);
                let (measured, tx) = measure_into_existing(*kind, body, key, (how, existing), budget);
                let args = match tx.collection(RuleVariable::Args) {
                    Some(VariableCollection::Map(map)) => map.value_count(),
                    _ => 0,
                };
                eprintln!(
                    "{label}: peak {}, error {}, ARGS {args}",
                    measured.peak_chunks, measured.errored
                );
                // What the budget allows beyond the engine's copies of the body is the 16 KiB and a little slack.
                assert!(
                    measured.peak_chunks <= 2 * body.len() + budget + 4096,
                    "{label}: the peak {} is over the {budget} byte budget",
                    measured.peak_chunks
                );
                if existing == 1024 {
                    assert!(measured.errored, "{label}: the growth is refused, not made");
                    assert_eq!(args, existing, "{label}: nothing was added");
                }
                if !grows {
                    assert!(!measured.errored, "{label}: a spare slot costs only the value");
                    assert_eq!(args, existing + 1, "{label}");
                }
            }
        }
    }
}

/// The smallest budget that `body` is admitted under, by bisection, with what it measures at that budget.
fn smallest_admitting_budget(case: &Boundary) -> (usize, Measured) {
    let length = case.body.len();
    let (mut low, mut high) = (0_usize, 1_000 * length.max(1_000));
    assert!(
        !run_boundary(case, high).errored,
        "{}: a huge budget admits it",
        case.label
    );
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if run_boundary(case, middle).errored {
            low = middle;
        } else {
            high = middle;
        }
    }
    (high, run_boundary(case, high))
}

#[test]
fn the_budget_that_admits_a_body_covers_its_peak_exactly_for_the_shapes_that_hid_a_copy_or_a_growth() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let upper_key = |processor, content_type, body: Vec<u8>, copies| Boundary {
        label: processor,
        processor,
        content_type,
        configuration: "",
        body,
        request_xml: false,
        copies,
    };
    let mut form = vec![b'A'; 256 * 1024];
    form.extend_from_slice(b"=1");
    let mut json = b"{\"".to_vec();
    json.extend(std::iter::repeat_n(b'A', 64 * 1024));
    json.extend_from_slice(b"\":1}");
    let mut multipart = b"--b\r\nContent-Disposition: form-data; name=\"".to_vec();
    multipart.extend(std::iter::repeat_n(b'A', 64 * 1024));
    multipart.extend_from_slice(b"\"\r\n\r\n1\r\n--b--\r\n");
    // `Ⱥ` takes two bytes and its lowercase form three, so the lowercase copy outgrows the vector sized for the
    // name, which doubles beside the old one.
    let mut expanding = "Ⱥ".repeat(64 * 1024).into_bytes();
    expanding.extend_from_slice(b"=1");
    let cases = [
        Boundary {
            label: "urlencoded, a name whose lowercase form is longer",
            ..upper_key("urlencoded", "application/x-www-form-urlencoded", expanding, 2)
        },
        // The decoded pair is alive while it is inserted, and a name with a capital is looked up through a lowercase
        // copy of it: neither was charged.
        upper_key("urlencoded", "application/x-www-form-urlencoded", form, 2),
        upper_key("json", "application/json", json, 2),
        upper_key("multipart", "multipart/form-data; boundary=b", multipart, 1),
        // 513 values take the list of `/*` past 512 slots, which grows to 1,024 beside the old one.
        Boundary {
            label: "xml, one past a full list",
            processor: "xml",
            content_type: "text/xml",
            configuration: "",
            body: format!("<r>{}</r>", "<i>1</i>".repeat(513)).into_bytes(),
            request_xml: true,
            copies: 1,
        },
    ];
    for case in &cases {
        let (budget, admitted) = smallest_admitting_budget(case);
        let length = case.body.len();
        eprintln!(
            "{}: body {length}, smallest budget {budget}, peak {}",
            case.label, admitted.peak_chunks
        );
        assert!(!admitted.errored && admitted.values > 0, "{}", case.label);
        // No slack: what the processor allocates beyond the engine's copies of the body is what it was charged.
        assert!(
            admitted.peak_chunks <= case.copies * length + budget,
            "{}: the peak {} passes the {budget} the budget allowed beside {} copies of {length} bytes",
            case.label,
            admitted.peak_chunks,
            case.copies
        );
    }
}

/// A transaction whose `ARGS` already holds `keys` distinct query arguments, which fills the table of keys when
/// `keys` is what a table of that size holds.
fn prepared_with_query(processor: &str, content_type: &str, budget: usize, keys: usize) -> Transaction {
    let mut tx = prepared(processor, content_type, Some(budget), "SecArgumentsLimit 100000");
    for index in 0..keys {
        tx.add_get_argument(format!("q{index}"), "v");
    }
    tx
}

#[test]
fn a_new_key_in_a_full_table_of_arguments_is_charged_for_the_table_that_replaces_it() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    // 896 keys fill the table of a map exactly: one more makes a table twice as big, beside the old one.
    let keys = 896;
    let cases = [
        ("json", "application/json", b"{\"new\":1}".to_vec()),
        ("urlencoded", "application/x-www-form-urlencoded", b"new=1".to_vec()),
        (
            "multipart",
            "multipart/form-data; boundary=b",
            b"--b\r\nContent-Disposition: form-data; name=\"new\"\r\n\r\n1\r\n--b--\r\n".to_vec(),
        ),
    ];
    for (processor, content_type, body) in &cases {
        let small = 16 * 1024;
        let mut tx = prepared_with_query(processor, content_type, small, keys);
        let before = tx.body_memory_bytes();
        let refused = measure_body(&mut tx, body, false);
        assert!(refused.errored, "{processor}: a table that does not fit is not made");
        assert_eq!(refused.values, 0, "{processor}: and nothing is added");
        assert!(
            tx.body_memory_bytes().saturating_sub(before) <= small,
            "{processor}: the retained growth stays within the budget"
        );

        // The budget that admits it covers the growth of the table, and the peak stays within it.
        let (mut low, mut high) = (small, 1024 * 1024);
        while low + 1 < high {
            let middle = low + (high - low) / 2;
            let mut tx = prepared_with_query(processor, content_type, middle, keys);
            if measure_body(&mut tx, body, false).errored {
                low = middle;
            } else {
                high = middle;
            }
        }
        let mut tx = prepared_with_query(processor, content_type, high, keys);
        let before = tx.body_memory_bytes();
        let admitted = measure_body(&mut tx, body, false);
        eprintln!(
            "{processor}: smallest budget {high}, peak {}, retained growth {}",
            admitted.peak_chunks,
            tx.body_memory_bytes().saturating_sub(before)
        );
        assert!(!admitted.errored && admitted.values == 1, "{processor}");
        assert!(
            admitted.peak_chunks <= body.len() + high,
            "{processor}: the peak {} passes the {high} byte budget",
            admitted.peak_chunks
        );
        assert!(
            tx.body_memory_bytes().saturating_sub(before) <= high,
            "{processor}: the retained growth passes the budget"
        );
    }
}

#[test]
fn a_repeated_lowercase_name_is_not_charged_a_spelling_the_map_shares() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let key = "k".repeat(4096);
    let case = Boundary {
        label: "urlencoded, a 4 KiB name twice",
        processor: "urlencoded",
        content_type: "application/x-www-form-urlencoded",
        configuration: "",
        body: format!("{key}=1&{key}=2").into_bytes(),
        request_xml: false,
        copies: 2,
    };
    let (budget, admitted) = smallest_admitting_budget(&case);
    let grown = admitted.peak_chunks.saturating_sub(case.copies * case.body.len());
    eprintln!(
        "{}: smallest budget {budget}, peak above the copies {grown}",
        case.label
    );
    assert_eq!(admitted.values, 2, "both values reach ARGS_POST");
    // The second value shares the key the first made in each map. Charging it a spelling of its own, 4 KiB in each
    // of the two maps, put the budget above twice what the heap grows by.
    assert!(
        budget < 2 * grown,
        "a budget of {budget} for {grown} bytes of growth charges a copy that is not made"
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
    // `assert_accounting_is_conservative` with the slack of a few variables only: the copies of 1,000 paths of
    // 800 bytes are far more than that.
    assert!(
        measured.live_chunks <= measured.retained + 16 * 1024,
        "the transaction holds {} bytes but estimates {}",
        measured.live_chunks,
        measured.retained
    );
}
