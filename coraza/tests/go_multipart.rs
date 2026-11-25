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

//! Replays what Go Coraza's multipart body processor publishes for a set of bodies against this crate.
//!
//! `tests/go_multipart/cases.json` holds each body and what Go's processor left in the transaction for it (`go`), and
//! for the same body with its `Content-Transfer-Encoding` headers renamed, so that no part is decoded (`raw`);
//! `tests/go_multipart/README.md` says how it was made. A part Go decodes from quoted-printable is published here
//! twice, decoded as Go publishes it and as it was sent, which is the part `raw` holds, so a rule sees what a backend
//! that decodes it acts on and what one that does not decode it acts on. A case passes when:
//!
//! - the collections decoding cannot change (`FILES`, `FILES_NAMES`, `MULTIPART_NAME`, `MULTIPART_FILENAME`) are Go's;
//! - `MULTIPART_PART_HEADERS` are the part headers as sent, which is `raw`'s: Go removes the encoding header of a part
//!   it decodes, this engine keeps it;
//! - `ARGS_POST`, `FILES_SIZES` and the temporary uploads hold every row of `go` and every row of `raw`, and nothing
//!   else, in no more rows than the two have together;
//! - `FILES_COMBINED_SIZE` is `raw`'s (the part sizes as sent: the larger of the two);
//! - the strict error is Go's, or the one `raw` has (a repeated encoding header is flagged here and not in Go), and the
//!   error is Go's;
//!
//! with one allowance: where Go's processor stops at a part (it returns a quoted-printable error, or reads no further
//! part after a part that ended inside its body), this engine publishes that part as far as it was decoded and reads
//! the parts after it, so its collections hold Go's and more.

#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "the fixture is trusted and a failed case is the test output"
)]

use std::{fmt::Write as _, path::Path};

use coraza::{
    seclang::Parser,
    transaction::{Transaction, VariableCollection},
    types::RuleVariable,
};
use serde_json::Value;

const FIXTURE: &str = include_str!("go_multipart/cases.json");

/// What the request body limit leaves out of a body it cut, which the engine is given beyond the limit.
const DISCARDED: &[u8] = b"ZZZZZZZZ";

/// The collections Go's processor fills that decoding a part cannot change, as the fixture names them.
const PLAIN_COLLECTIONS: [(&str, RuleVariable); 4] = [
    ("files", RuleVariable::Files),
    ("files_names", RuleVariable::FilesNames),
    ("mp_name", RuleVariable::MultipartName),
    ("mp_filename", RuleVariable::MultipartFilename),
];

/// The collections that hold a part's data, or its size, so that a part decoded from quoted-printable publishes
/// twice in them.
const VALUE_COLLECTIONS: [(&str, RuleVariable); 2] = [
    ("args_post", RuleVariable::ArgsPost),
    ("files_sizes", RuleVariable::FilesSizes),
];

/// A key and a value, as hex.
type Row = (String, String);

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(text.get(2 * index..2 * index + 2).unwrap(), 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").unwrap();
        text
    })
}

/// The rows of a map variable as hex pairs, sorted as the fixture sorts them.
fn rows(tx: &Transaction, variable: RuleVariable) -> Vec<Row> {
    let mut rows: Vec<Row> = match tx.collection(variable) {
        Some(VariableCollection::Map(map)) => map
            .iter()
            .map(|(key, value)| (hex(key.as_bytes()), hex(value)))
            .collect(),
        _ => Vec::new(),
    };
    rows.sort();
    rows
}

fn single(tx: &Transaction, variable: RuleVariable) -> String {
    tx.get_variable(variable, None).unwrap_or_default()
}

/// Whether every row of `wanted` is among `rows`, each used once.
fn holds_all(rows: &[Row], wanted: &[Row]) -> bool {
    let mut remaining = rows.to_vec();
    wanted.iter().all(|row| {
        remaining
            .iter()
            .position(|candidate| candidate == row)
            .map(|at| remaining.remove(at))
            .is_some()
    })
}

/// `field` of `value`, a string.
fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value.get(field).and_then(Value::as_str).unwrap()
}

/// The rows of `value`, a JSON array of key and value pairs.
fn pairs(value: &Value) -> Vec<Row> {
    let at = |row: &Value, index: usize| row.get(index).and_then(Value::as_str).unwrap().to_owned();
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|row| (at(row, 0), at(row, 1)))
        .collect()
}

/// A transaction that read `body` as a multipart body, cut by the request body limit when `cut`.
fn process(upload_dir: &Path, body: &[u8], cut: bool) -> Transaction {
    let limit = if cut { body.len() } else { 134_217_728 };
    let mut parser = Parser::new();
    parser
        .from_string(&format!(
            "SecRequestBodyAccess On\nSecRequestBodyLimit {limit}\nSecRequestBodyInMemoryLimit {limit}\n\
             SecRequestBodyLimitAction ProcessPartial\nSecUploadDir {}\nSecUploadFileLimit 1000\n\
             SecRule REQUEST_HEADERS:Content-Type \"^multipart/\" \
             \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=MULTIPART\"\n",
            upload_dir.display()
        ))
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "multipart/form-data; boundary=b");
    tx.process_request_headers();
    let mut fed = body.to_vec();
    if cut {
        fed.extend_from_slice(DISCARDED);
    }
    tx.process_request_body(&fed);
    tx
}

/// How many times `row` is among `rows`.
fn count_of(rows: &[Row], row: &Row) -> usize {
    rows.iter().filter(|candidate| *candidate == row).count()
}

/// Compares the errors, the strict error and `FILES_COMBINED_SIZE`.
fn check_flags(name: &str, tx: &Transaction, case: &Value, go_stopped: bool) {
    let (go, raw) = (case.get("go").unwrap(), case.get("raw").unwrap());
    let go_error = text(go, "error");
    let flag = |value: &Value, field: &str| value.get(field).and_then(Value::as_bool).unwrap();
    let errored = single(tx, RuleVariable::ReqbodyError) == "1";
    let strict = single(tx, RuleVariable::MultipartStrictError) == "1";
    let message_is_go_s = || single(tx, RuleVariable::ReqbodyProcessorErrorMsg).contains(go_error);
    if go_stopped {
        // Where Go returns an error it is this engine's too, from the same part. Where Go only stopped, a part
        // after it, which Go never read, may fail here.
        if !go_error.is_empty() {
            assert!(errored && message_is_go_s(), "{name}: error");
        }
        assert!(strict || !flag(go, "strict"), "{name}: strict error");
    } else {
        assert_eq!(errored, !go_error.is_empty(), "{name}: error");
        assert!(!errored || message_is_go_s(), "{name}: error message");
        // The strict error is Go's, and a repeated encoding header too: Go removes the header of a part it decodes
        // before it looks for repeated headers, which this engine does not.
        assert_eq!(
            strict,
            flag(go, "strict") || flag(raw, "strict"),
            "{name}: strict error"
        );
    }

    // The size of a part is the larger of the two it publishes, as it was sent: the size Go's processor adds up when
    // it does not decode. Decoding never makes a part longer.
    let size = |value: &Value| match text(value, "combined_size") {
        "" => 0,
        size => size.parse::<u64>().unwrap(),
    };
    let combined = single(tx, RuleVariable::FilesCombinedSize).parse::<u64>().unwrap();
    assert_eq!(combined, size(raw), "{name}: combined size");
    assert!(
        combined >= size(go),
        "{name}: combined size {combined}, Go {}",
        size(go)
    );
}

/// The rows of `collection` in `value`, a case's `go` or `raw`.
fn expected(value: &Value, collection: &str) -> Vec<Row> {
    pairs(value.get("collections").and_then(|all| all.get(collection)).unwrap())
}

/// A part header row of the case as it was sent: the encoding header, renamed so that Go would not decode by it, named
/// again.
fn unrename(row: &Row) -> Row {
    let value = unhex(&row.1);
    let renamed = b"Content-Transfer-Encodinx";
    let value = match value
        .windows(renamed.len())
        .position(|window| window.eq_ignore_ascii_case(renamed))
    {
        Some(at) => [
            value.get(..at).unwrap(),
            b"Content-Transfer-Encoding",
            value.get(at + renamed.len()..).unwrap(),
        ]
        .concat(),
        None => value,
    };
    (row.0.clone(), hex(&value))
}

/// Checks that `got` holds every row of `go` and of `raw`, and when `bounded` nothing else and no more rows than the
/// two have together: the rows of the part as Go publishes it, and of the part as it was sent, each only where decoding
/// changed it.
fn check_both_values(label: &str, got: &[Row], go: &[Row], raw: &[Row], bounded: bool) {
    assert!(holds_all(got, go), "{label} lacks a row Go publishes");
    assert!(holds_all(got, raw), "{label} lacks a row of the part as it was sent");
    if bounded {
        assert!(got.len() <= go.len() + raw.len(), "{label} has rows to spare");
        for row in got {
            assert!(
                count_of(got, row) <= count_of(go, row) + count_of(raw, row),
                "{label} repeats a row beyond what the two publish"
            );
            assert!(
                go.contains(row) || raw.contains(row),
                "{label} holds a row that neither publishes"
            );
        }
    }
}

/// Compares the collections and the contents of the temporary uploads.
fn check_collections(name: &str, tx: &Transaction, case: &Value, go_stopped: bool) {
    let (go, raw) = (case.get("go").unwrap(), case.get("raw").unwrap());
    let same = |got: &[Row], want: &[Row]| if go_stopped { holds_all(got, want) } else { got == want };
    for (collection, variable) in PLAIN_COLLECTIONS {
        assert!(
            same(&rows(tx, variable), &expected(go, collection)),
            "{name}: {collection}"
        );
    }

    // The headers as sent, which is what the processor publishes for the body with no part decoded.
    let headers = rows(tx, RuleVariable::MultipartPartHeaders);
    let mut sent: Vec<Row> = expected(raw, "part_headers").iter().map(unrename).collect();
    sent.sort();
    assert_eq!(headers, sent, "{name}: part_headers");
    assert!(
        holds_all(&headers, &expected(go, "part_headers")),
        "{name}: part_headers lack a header Go publishes"
    );

    for (collection, variable) in VALUE_COLLECTIONS {
        // A part Go stopped at publishes more here than either does, as far as it was decoded.
        check_both_values(
            &format!("{name}: {collection}"),
            &rows(tx, variable),
            &expected(go, collection),
            &expected(raw, collection),
            !go_stopped,
        );
    }

    let uploads = |tx: &Transaction| -> Vec<Row> {
        let mut uploads: Vec<Row> = rows(tx, RuleVariable::FilesTmpNames)
            .into_iter()
            .map(|(_, path)| {
                let content = std::fs::read(String::from_utf8(unhex(&path)).unwrap()).unwrap();
                (String::new(), hex(&content))
            })
            .collect();
        uploads.sort();
        uploads
    };
    let files = |value: &Value| -> Vec<Row> {
        value
            .get("tmp_files")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .map(|content| (String::new(), content.as_str().unwrap().to_owned()))
            .collect()
    };
    check_both_values(
        &format!("{name}: uploads"),
        &uploads(tx),
        &files(go),
        &files(raw),
        !go_stopped,
    );
}

#[test]
fn bodies_publish_what_go_s_multipart_processor_publishes() {
    let cases: Vec<Value> = serde_json::from_str(FIXTURE).expect("the fixture is JSON");
    assert!(cases.len() > 100, "{} cases", cases.len());
    let upload_dir = tempfile::tempdir().unwrap();
    let (mut stopped_early, mut published_twice) = (0, 0);

    for case in &cases {
        let name = text(case, "name");
        let cut = case.get("cut").and_then(Value::as_bool).unwrap();
        let tx = process(upload_dir.path(), &unhex(text(case, "body")), cut);

        // Go's processor returned before it published the part whose body it could not read, or read no further part
        // after one that ended inside its body.
        let go_stopped = case
            .get("go")
            .and_then(|go| go.get("stopped"))
            .and_then(Value::as_bool)
            .unwrap();
        stopped_early += usize::from(go_stopped);
        published_twice +=
            usize::from(rows(&tx, RuleVariable::ArgsPost).len() > expected(case.get("go").unwrap(), "args_post").len());

        check_flags(name, &tx, case, go_stopped);
        check_collections(name, &tx, case, go_stopped);
    }
    assert!(stopped_early > 0, "the fixture holds cases where Go stops at a part");
    assert!(published_twice > 0, "the fixture holds fields that decoding changes");
}
