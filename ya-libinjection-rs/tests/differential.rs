//! The port against libinjection itself: `tests/oracle/oracle.c` runs the C
//! library, built from the sources vendored in `tests/upstream/src`, and
//! every input has to come out of both identically. Compared are the SQL
//! tokens, folded tokens, fingerprints and verdicts in each of the six
//! quote/dialect contexts, and the HTML5 tokens and XSS verdicts in each of
//! the five HTML contexts.
//!
//! The inputs are upstream's whole corpus and, seeded from it, fuzzed
//! ones. The fuzzing is deterministic: a run compares the same inputs
//! every time.
//!
//! These tests need a C compiler: `CC` (default `cc`) with `CFLAGS`
//! (default `-O2`). To have the C side checked for memory errors as well:
//!
//! ```text
//! CC=clang CFLAGS="-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined" \
//!     cargo test --test differential
//! ```
//!
//! `DIFFERENTIAL_FUZZ_INPUTS` sets how many fuzzed inputs to compare, in
//! all. For a long run, with the number of inputs each test compared:
//!
//! ```text
//! DIFFERENTIAL_FUZZ_INPUTS=20000000 cargo test --release --test differential -- --nocapture
//! ```

mod common;

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

use libinjection_rs::internals::html5::{Context, TokenKind, Tokenizer};
use libinjection_rs::internals::sqli::{Dialect, Lexer, Quote, State, Token};
use libinjection_rs::internals::xss::is_xss;

/// How many fuzzed inputs to compare by default, over all the fuzz tests.
const DEFAULT_FUZZ_INPUTS: usize = 500_000;

/// Inputs are generated and compared this many at a time.
const CHUNK: usize = 20_000;

/// The contexts of the dump, in the order `oracle.c` goes through them.
const SQL_CONTEXTS: [(Quote, Dialect); 6] = [
    (Quote::None, Dialect::Ansi),
    (Quote::None, Dialect::Mysql),
    (Quote::Single, Dialect::Ansi),
    (Quote::Single, Dialect::Mysql),
    (Quote::Double, Dialect::Ansi),
    (Quote::Double, Dialect::Mysql),
];
const HTML_CONTEXTS: [Context; 5] = [
    Context::Data,
    Context::ValueNoQuote,
    Context::ValueSingleQuote,
    Context::ValueDoubleQuote,
    Context::ValueBackQuote,
];

/// The oracle binary, built on first use.
fn oracle() -> &'static Path {
    static ORACLE: OnceLock<PathBuf> = OnceLock::new();
    ORACLE.get_or_init(|| {
        let sources = common::upstream().join("src");
        let tmp = Path::new(env!("CARGO_TARGET_TMPDIR"));
        let binary = tmp.join("libinjection-oracle");
        // Built aside and moved into place, so that another test run still
        // executing the previous binary is left alone.
        let building = tmp.join(format!("libinjection-oracle.{}", std::process::id()));

        let cc = env::var("CC").unwrap_or_else(|_| "cc".to_owned());
        let cflags = env::var("CFLAGS").unwrap_or_else(|_| "-O2".to_owned());
        let status = Command::new(&cc)
            .args(cflags.split_whitespace())
            // Upstream's headers declare static functions they do not define.
            .arg("-w")
            .arg("-I")
            .arg(&sources)
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracle/oracle.c"))
            .args(
                [
                    "libinjection_sqli.c",
                    "libinjection_html5.c",
                    "libinjection_xss.c",
                ]
                .map(|source| sources.join(source)),
            )
            .arg("-o")
            .arg(&building)
            .status()
            .unwrap_or_else(|e| panic!("cannot run the C compiler `{cc}` (set CC): {e}"));
        assert!(status.success(), "`{cc}` failed to build the oracle");
        fs::rename(&building, &binary).unwrap();
        binary
    })
}

fn dump_token(out: &mut String, token: &Token) {
    write!(
        out,
        "[{:02x} {} {} {} {:02x} {:02x} ",
        token.ty.as_byte(),
        token.pos,
        token.len,
        token.count,
        token.str_open.unwrap_or(0),
        token.str_close.unwrap_or(0)
    )
    .unwrap();
    for byte in token.value() {
        write!(out, "{byte:02x}").unwrap();
    }
    out.push(']');
}

/// What the port makes of `input`, in the format of `oracle.c`.
fn dump(input: &[u8]) -> String {
    let mut out = String::new();
    match libinjection_rs::sqli(input) {
        Some(fingerprint) => write!(out, "S1:{fingerprint}").unwrap(),
        None => out.push_str("S0:"),
    }
    for (k, (quote, dialect)) in SQL_CONTEXTS.into_iter().enumerate() {
        write!(out, " T{k}:").unwrap();
        let mut lexer = Lexer::new(input, quote, dialect);
        for token in lexer.by_ref() {
            dump_token(&mut out, &token);
        }
        let stats = lexer.stats;
        write!(
            out,
            "/{},{},{}",
            stats.tokens, stats.comment_ddx, stats.comment_hash
        )
        .unwrap();

        write!(out, " F{k}:").unwrap();
        let mut state = State::new(input, quote, dialect);
        let count = state.fold();
        for token in &state.tokens[..count] {
            dump_token(&mut out, token);
        }

        let fingerprint = state.fingerprint(quote, dialect);
        let is_sqli = u8::from(state.check_fingerprint());
        write!(out, " P{k}:{fingerprint},{is_sqli}").unwrap();
    }

    write!(out, " X{}", u8::from(libinjection_rs::xss(input))).unwrap();
    for (k, context) in HTML_CONTEXTS.into_iter().enumerate() {
        write!(out, " x{k}:{}:", u8::from(is_xss(input, context))).unwrap();
        for token in Tokenizer::new(input, context) {
            // The values of upstream's `enum html5_type`.
            let kind = match token.kind {
                TokenKind::DataText => 0,
                TokenKind::TagNameOpen => 1,
                TokenKind::TagNameClose => 2,
                TokenKind::TagNameSelfClose => 3,
                TokenKind::TagClose => 5,
                TokenKind::AttrName => 6,
                TokenKind::AttrValue => 7,
                TokenKind::TagComment => 8,
                TokenKind::Doctype => 9,
            };
            let start = token.text.as_ptr() as usize - input.as_ptr() as usize;
            write!(out, "({kind} {start} {})", token.text.len()).unwrap();
        }
    }
    out
}

/// Names the first field two dumps of `input` disagree on.
fn describe_mismatch(input: &[u8], theirs: &str, ours: &str) -> String {
    let (theirs, ours) = theirs
        .split(' ')
        .zip(ours.split(' '))
        .find(|(theirs, ours)| theirs != ours)
        .unwrap_or((theirs, ours));
    format!(
        "input \"{}\"\n  libinjection: {theirs}\n  port:         {ours}",
        input.escape_ascii()
    )
}

/// Runs `inputs` through the oracle and through the port.
fn compare(inputs: &[Vec<u8>]) -> Result<(), String> {
    let mut child = Command::new(oracle())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run the oracle: {e}"))?;
    let stdin = child.stdin.take().expect("stdin is piped");
    let stdout = BufReader::new(child.stdout.take().expect("stdout is piped"));

    let mut answered = 0;
    let mut mismatch = None;
    thread::scope(|scope| {
        scope.spawn(move || {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut stdin = BufWriter::new(stdin);
            let mut line = Vec::new();
            for input in inputs {
                line.clear();
                for &byte in input {
                    line.extend([HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]]);
                }
                line.push(b'\n');
                // If the oracle is gone, the reading side reports it.
                if stdin.write_all(&line).is_err() {
                    return;
                }
            }
        });

        // Keep reading after a mismatch, or the oracle would block on its
        // output and the writer above on the oracle.
        for (input, theirs) in inputs.iter().zip(stdout.lines()) {
            let Ok(theirs) = theirs else { break };
            answered += 1;
            if mismatch.is_none() {
                let ours = dump(input);
                if ours != theirs {
                    mismatch = Some(describe_mismatch(input, &theirs, &ours));
                }
            }
        }
    });

    let status = child
        .wait()
        .map_err(|e| format!("cannot wait for the oracle: {e}"))?;
    if let Some(mismatch) = mismatch {
        return Err(mismatch);
    }
    if answered != inputs.len() || !status.success() {
        return Err(format!(
            "the oracle stopped at input {answered} of {} ({status}): \"{}\"",
            inputs.len(),
            inputs
                .get(answered)
                .map_or(&[][..], Vec::as_slice)
                .escape_ascii()
        ));
    }
    Ok(())
}

/// Compares `chunks` chunks of inputs, `inputs(index)` each, on all cores.
fn compare_chunks(what: &str, chunks: usize, inputs: impl Fn(usize) -> Vec<Vec<u8>> + Sync) {
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let workers = thread::available_parallelism().map_or(1, usize::from);

    let results: Vec<Result<usize, String>> = thread::scope(|scope| {
        let workers: Vec<_> = (0..workers.min(chunks))
            .map(|_| {
                scope.spawn(|| {
                    let mut compared = 0;
                    while !failed.load(Ordering::Relaxed) {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        if index >= chunks {
                            break;
                        }
                        let inputs = inputs(index);
                        if let Err(e) = compare(&inputs) {
                            failed.store(true, Ordering::Relaxed);
                            return Err(format!("chunk {index}: {e}"));
                        }
                        compared += inputs.len();
                    }
                    Ok(compared)
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("worker panicked"))
            .collect()
    });

    let mut compared = 0;
    for result in results {
        match result {
            Ok(count) => compared += count,
            Err(e) => panic!("{what}: {e}"),
        }
    }
    println!("{what}: {compared} inputs, identical to libinjection");
}

/// Upstream's corpus: the seeds of the fuzz tests.
fn corpus() -> &'static [Vec<u8>] {
    static CORPUS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    CORPUS.get_or_init(common::corpus)
}

/// The number of chunks that `share` percent of the fuzz budget comes to.
fn fuzz_chunks(share: usize) -> usize {
    let total = env::var("DIFFERENTIAL_FUZZ_INPUTS").map_or(DEFAULT_FUZZ_INPUTS, |inputs| {
        inputs
            .parse()
            .expect("DIFFERENTIAL_FUZZ_INPUTS is not a number")
    });
    (total * share / 100).div_ceil(CHUNK)
}

/// SplitMix64: small, fast, and the same sequence everywhere.
struct Rng(u64);

impl Rng {
    /// A generator for chunk `index` of the fuzz family `family`.
    fn new(family: u64, index: usize) -> Self {
        Self(family << 48 | index as u64)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number in `0..n`.
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }

    /// A number in `low..=high`.
    fn between(&mut self, low: usize, high: usize) -> usize {
        low + self.below(high - low + 1)
    }

    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    fn pick<'a>(&mut self, items: &[&'a [u8]]) -> &'a [u8] {
        items[self.below(items.len())]
    }
}

/// Pieces of SQL that the tokenizer treats specially.
const SQL: &[&[u8]] = &[
    b"'",
    b"\"",
    b"`",
    b"\\",
    b"\\N",
    b"--",
    b"-- ",
    b"#",
    b"/*",
    b"*/",
    b"/*!",
    b"$",
    b"$$",
    b"$a$",
    b"$1,0.",
    b"$.",
    b"@",
    b"@@",
    b".",
    b"1",
    b"0",
    b"0x",
    b"0b",
    b"0xAf",
    b"0b01",
    b"1e",
    b"1.e",
    b"1e5",
    b"1.5e-3",
    b"e",
    b"1f",
    b"1d",
    b"1fU",
    b"E'",
    b"e'",
    b"N'",
    b"n'",
    b"q'[",
    b"Q'(",
    b"nq'{",
    b"nQ'<",
    b"U&'",
    b"u&'",
    b"x'",
    b"X'ff'",
    b"b'",
    b"B'01'",
    b"[",
    b"]",
    b"{",
    b"}",
    b"(",
    b")",
    b",",
    b";",
    b":",
    b"::",
    b"<=>",
    b"!",
    b"!!",
    b"!=",
    b"~",
    b"+",
    b"-",
    b"*",
    b"/",
    b"%",
    b"&",
    b"&&",
    b"|",
    b"||",
    b"=",
    b"<",
    b">",
    b"<>",
    b"?",
    b"^",
    b" ",
    b" ",
    b" ",
    b"\t",
    b"\n",
    b"\x0b",
    b"\x0c",
    b"\r",
    b"\x00",
    b"\xa0",
    b"\xff",
    b"\x7f",
    b"\x80",
    b"\x01",
    b"SELECT",
    b"select",
    b"UNION",
    b"ALL",
    b"AND",
    b"OR",
    b"NOT",
    b"IN",
    b"LIKE",
    b"IF",
    b"if",
    b"USER",
    b"user_id",
    b"DATABASE",
    b"PASSWORD",
    b"CURRENT_USER",
    b"LOCALTIME",
    b"COLLATE",
    b"utf8_bin",
    b"INTO",
    b"OUTFILE",
    b"NULL",
    b"sp_password",
    b"CASE",
    b"WHEN",
    b"FROM",
    b"WHERE",
    b"GROUP",
    b"BY",
    b"ORDER",
    b"HAVING",
    b"LIMIT",
    b"IS",
    b"BETWEEN",
    b"EXEC",
    b"WAITFOR",
    b"DELAY",
    b"sleep",
    b"char",
    b"concat",
    b"INT",
    b"VARCHAR",
    b"BINARY",
    b"_utf8",
    b"foo",
    b"a",
    b"x",
    b"BOOLEAN",
    b"MODE",
    b"DIV",
    b"XOR",
    b"SOUNDS",
    b"NATURAL",
    b"JOIN",
    b"CROSS",
    b"DECLARE",
    b"SET",
    b"TOP",
    b"DISTINCT",
    b"version",
    // Longer than a token's value can be.
    b"1234567890123456789012345678901234567890",
    b"abcdefghijklmnopqrstuvwxyzabcdefghijklmnop",
];

/// Pieces of HTML that the tokenizer or the XSS checks treat specially.
const HTML: &[&[u8]] = &[
    b"<",
    b">",
    b"/",
    b"</",
    b"/>",
    b"<!",
    b"<!--",
    b"-->",
    b"-!>",
    b"--",
    b"-",
    b"<?",
    b"<%",
    b"%>",
    b"%",
    b"<![CDATA[",
    b"]]>",
    b"]",
    b"<!DOCTYPE",
    b"<!doctype",
    b"=",
    b"'",
    b"\"",
    b"`",
    b" ",
    b" ",
    b"\t",
    b"\n",
    b"\x00",
    b"\xff",
    b"\x0b",
    b"\x0c",
    b"\r",
    b"\x80",
    b"\x7f",
    b"script",
    b"SCRIPT",
    b"svg",
    b"xsl",
    b"a",
    b"img",
    b"iframe",
    b"style",
    b"href",
    b"src",
    b"onerror",
    b"onclick",
    b"ON",
    b"on",
    b"onx",
    b"onload",
    b"xmlns",
    b"XLINK",
    b"xlink:href",
    b"attributename",
    b"formaction",
    b"to",
    b"by",
    b"javascript:",
    b"JaVa",
    b"data:",
    b"vbscript:",
    b"view-source:",
    b"&#106;",
    b"&#x6a;",
    b"&#x6A",
    b"&#X144;",
    b"&#",
    b"&#x",
    b"&",
    b";",
    b"&#0;",
    b"&#10;",
    b"&#9;",
    b"&#99999999;",
    b"&#xfffffff;",
    b"[if",
    b"xml",
    b"import",
    b"entity",
    b"IMPORT",
    b"ENTITY",
    b"x",
    b"1",
    b"?",
    b"!",
    b"[",
    b"p",
    b"div",
    b"b",
];

/// Whole SQL tokens of every type, to drive the folding rules rather than
/// the tokenizer.
const SOUP: &[&[u8]] = &[
    b"1",
    b"2",
    b"1.5",
    b"foo",
    b"bar",
    b"x_y",
    b"'s'",
    b"'t",
    b"\"d\"",
    b"@v",
    b"@@g",
    b"(",
    b")",
    b"(",
    b")",
    b",",
    b";",
    b"{",
    b"}",
    b"{",
    b"``",
    b"`",
    b"`a`",
    b"`sleep`",
    b".",
    b"\\",
    b"::",
    b":",
    b"+",
    b"-",
    b"*",
    b"/",
    b"%",
    b"!",
    b"~",
    b"!!",
    b"=",
    b"<",
    b"select",
    b"union",
    b"all",
    b"and",
    b"or",
    b"not",
    b"&&",
    b"||",
    b"in",
    b"like",
    b"if",
    b"user",
    b"database",
    b"current_user",
    b"collate",
    b"int",
    b"varchar",
    b"_utf8",
    b"from",
    b"where",
    b"group by",
    b"order",
    b"by",
    b"having",
    b"limit",
    b"into",
    b"outfile",
    b"case",
    b"when",
    b"null",
    b"is",
    b"between",
    b"exec",
    b"sleep",
    b"char",
    b"concat",
    b"boolean",
    b"mode",
    b"-- c",
    b"--",
    b"#",
    b"/*c*/",
    b"/*!c*/",
    b"/* /* */",
    b"sp_password",
    b"?",
    b"[w]",
    b"1e",
    b"$1",
    b"$$s$$",
    b"x'ff'",
    b"N'n'",
];

/// A piece of [`SQL`] or of [`HTML`].
fn any_piece(rng: &mut Rng) -> &'static [u8] {
    let index = rng.below(SQL.len() + HTML.len());
    SQL.get(index).unwrap_or_else(|| &HTML[index - SQL.len()])
}

fn concat(
    rng: &mut Rng,
    count: usize,
    mut piece: impl FnMut(&mut Rng) -> &'static [u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..count {
        out.extend_from_slice(piece(rng));
    }
    out
}

/// A seed, with a few random edits.
fn mutate(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut s = seeds[rng.below(seeds.len())].clone();
    for _ in 0..rng.between(1, 4) {
        let at = rng.between(0, s.len());
        match rng.below(8) {
            0 => drop(s.splice(at..at, any_piece(rng).iter().copied())),
            1 if !s.is_empty() => {
                let end = s.len().min(at + rng.between(1, 6));
                s.drain(at..end);
            }
            2 if !s.is_empty() => {
                let at = rng.below(s.len());
                s[at] = rng.byte();
            }
            3 if !s.is_empty() => {
                let end = s.len().min(at + rng.between(1, 12));
                let repeated = s[at..end].to_vec();
                s.splice(at..at, repeated);
            }
            4 => s.truncate(at),
            5 => drop(s.drain(..at)),
            6 if !s.is_empty() => {
                let at = rng.below(s.len());
                s[at] ^= 0x20;
            }
            // Continue with the tail of another seed.
            _ => {
                let other = &seeds[rng.below(seeds.len())];
                s.truncate(at);
                s.extend_from_slice(&other[rng.between(0, other.len())..]);
            }
        }
    }
    s.truncate(400);
    s
}

#[test]
fn corpus_matches() {
    let corpus = corpus();
    compare_chunks("upstream corpus", corpus.len().div_ceil(CHUNK), |index| {
        corpus.chunks(CHUNK).nth(index).unwrap().to_vec()
    });
}

/// Mutated seeds, strings of special pieces, and plain random bytes.
#[test]
fn fuzz_mutations() {
    let seeds = corpus();
    compare_chunks("mutations", fuzz_chunks(60), |index| {
        let mut rng = Rng::new(1, index);
        (0..CHUNK)
            .map(|_| match rng.below(10) {
                0..4 => mutate(&mut rng, seeds),
                4..6 => {
                    let count = rng.between(0, 12);
                    concat(&mut rng, count, |rng| rng.pick(SQL))
                }
                6..8 => {
                    let count = rng.between(0, 14);
                    concat(&mut rng, count, |rng| rng.pick(HTML))
                }
                8 => {
                    let count = rng.between(0, 10);
                    concat(&mut rng, count, any_piece)
                }
                _ => (0..rng.between(0, 24)).map(|_| rng.byte()).collect(),
            })
            .collect()
    });
}

/// Sequences of whole SQL tokens, for the folding rules.
#[test]
fn fuzz_sql_token_soup() {
    compare_chunks("SQL token soup", fuzz_chunks(30), |index| {
        let mut rng = Rng::new(2, index);
        (0..CHUNK)
            .map(|_| {
                let mut input = Vec::new();
                // Sometimes as if inside, or closing, a quoted string.
                if rng.chance(15) {
                    input.extend_from_slice(rng.pick(&[b"'", b"\"", b"1' ", b"x\" "]));
                }
                let separator: &[u8] = rng.pick(&[b" ", b" ", b" ", b"", b"\n"]);
                for i in 0..rng.between(1, 9) {
                    if i > 0 {
                        input.extend_from_slice(separator);
                    }
                    input.extend_from_slice(rng.pick(SOUP));
                }
                input
            })
            .collect()
    });
}

/// URL attributes whose scheme is spelled with numeric character
/// references, in and out of a tag.
#[test]
fn fuzz_entity_urls() {
    compare_chunks("entity-encoded URLs", fuzz_chunks(10), |index| {
        let mut rng = Rng::new(3, index);
        (0..CHUNK)
            .map(|_| {
                let mut url = rng
                    .pick(&[b"", b" ", b"\x01\t", b"\xa0\xff", b"&#9;", b"&#x20;&#0;"])
                    .to_vec();
                let scheme: &[u8] = rng.pick(&[
                    b"data",
                    b"view-source",
                    b"java",
                    b"javascript",
                    b"vbscript",
                    b"http",
                    b"jav",
                    b"dat",
                ]);
                for &ch in scheme {
                    let ch = if rng.chance(30) { ch ^ 0x20 } else { ch };
                    // Sometimes out of a byte's range: upstream narrows the
                    // decoded value.
                    let value = u32::from(ch)
                        + [0, 0, 0, 0x100, 0x200, 0x1_0000, 0x10_0000, 0x100_0000][rng.below(8)];
                    let end = if rng.chance(66) { ";" } else { "" };
                    match rng.below(7) {
                        0 => url.extend_from_slice(format!("&#{value}{end}").as_bytes()),
                        1 => url.extend_from_slice(format!("&#x{value:x}{end}").as_bytes()),
                        2 => url.extend_from_slice(format!("&#X{value:X}{end}").as_bytes()),
                        _ => url.push(ch),
                    }
                    // Things the scheme match skips, or trips on.
                    url.extend_from_slice(rng.pick(&[
                        b"", b"", b"", b"\x00", b"\n", b"&#0;", b"&#10;", b"&#x0a;", b"\t", b" ",
                        b"&", b"&#", b"&#x",
                    ]));
                }
                url.extend_from_slice(rng.pick(&[b":alert(1)", b":", b"", b"&colon;x"]));

                let attr: &[u8] = rng.pick(&[
                    b"href",
                    b"src",
                    b"action",
                    b"formaction",
                    b"xlink:href",
                    b"to",
                    b"background",
                    b"title",
                    b"attributename",
                ]);
                let quote: &[u8] = rng.pick(&[b"\"", b"'", b"`", b""]);
                match rng.below(4) {
                    0 => [b"<a ", attr, b"=", quote, &url, quote, b">"].concat(),
                    1 => url,
                    2 => [quote, b" ", attr, b"=", &url].concat(),
                    _ => [b"<x ", attr, b" = ", quote, &url].concat(),
                }
            })
            .collect()
    });
}

/// A number, then a comment, with every possible byte between or after
/// them: the false-positive check for the `1c` fingerprint looks at the
/// byte that follows the number.
#[test]
fn number_then_comment() {
    let prefixes: [&[u8]; 4] = [b"", b" ", b"\xa0", b"  "];
    let numbers: [&[u8]; 7] = [b"1", b"12", b"1.5", b"0x1f", b"\\N", b"$1", &[b'1'; 40]];
    let comments: [&[u8]; 8] = [b"--", b"-- x", b"/*x*/", b"/*", b"#", b"--\n", b"-", b"/"];

    let mut inputs = Vec::new();
    for prefix in prefixes {
        for number in numbers {
            for byte in 0..=u8::MAX {
                for comment in comments {
                    inputs.push([prefix, number, &[byte], comment].concat());
                    inputs.push([prefix, number, comment, &[byte]].concat());
                }
            }
        }
    }
    compare_chunks(
        "number then comment",
        inputs.len().div_ceil(CHUNK),
        |index| inputs.chunks(CHUNK).nth(index).unwrap().to_vec(),
    );
}
