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
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
};

use coraza::{seclang::Parser, transaction::VariableCollection, types::RuleVariable};

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

/// [`measure`] under an absolute memory budget and extra configuration.
fn measure_with(processor: &str, content_type: &str, body: &[u8], request_xml: bool, setup: &Setup<'_>) -> Measured {
    let Setup { budget, configuration } = *setup;
    let mut parser = Parser::new();
    parser
        .from_string(&format!(
            "SecRequestBodyAccess On\nSecRequestBodyLimit 134217728\n{configuration}\n\
             SecAction \"id:1,phase:1,ctl:requestBodyProcessor={processor},pass,nolog\""
        ))
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction();
    tx.set_body_memory_budget(budget);
    tx.add_request_header("Content-Type", content_type);
    tx.process_request_headers();

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
