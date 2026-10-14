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
//! Helpers shared by the integration tests and the benchmark: access to

//! the files vendored from libinjection, read the way its own test programs
//! read them, and a way to build the C library to run alongside the port.

// Each test binary uses its own subset of these.
#![expect(
    dead_code,
    reason = "Each test and benchmark target uses a different subset of this shared harness."
)]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "The shared harness fails fast when required pinned fixtures or tools are unavailable."
)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

/// The libinjection files the tests run against: the copy vendored in
/// `tests/upstream`, or the checkout `LIBINJECTION_DIR` points at.
pub(crate) fn upstream() -> PathBuf {
    let dir = env::var_os("LIBINJECTION_DIR").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/upstream"),
        PathBuf::from,
    );
    assert!(dir.join("tests").is_dir(), "no libinjection files at {}", dir.display());
    dir
}

/// Reads one of upstream's source files.
pub(crate) fn upstream_source(path: &str) -> String {
    let path = upstream().join(path);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The files of `upstream()/<dir>` whose name starts with `prefix`, sorted.
fn files(dir: &str, prefix: &str) -> Vec<(String, Vec<u8>)> {
    let dir = upstream().join(dir);
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with(prefix) && name.ends_with(".txt"))
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no {prefix}*.txt in {}", dir.display());
    names
        .into_iter()
        .map(|name| {
            let content = fs::read(dir.join(&name)).unwrap();
            (name, content)
        })
        .collect()
}

/// The C compiler: `CC`, or `cc`.
pub(crate) fn c_compiler() -> String {
    env::var("CC").unwrap_or_else(|_| "cc".to_owned())
}

/// The C compiler's flags: `CFLAGS`, or `default`.
pub(crate) fn c_flags(default: &str) -> String {
    env::var("CFLAGS").unwrap_or_else(|_| default.to_owned())
}

/// Compiles `program`, a C file of this repository, together with
/// libinjection's sources, and returns the path of the binary.
pub(crate) fn build_with_libinjection(program: &str, default_flags: &str) -> PathBuf {
    let sources = upstream().join("src");
    let program = Path::new(env!("CARGO_MANIFEST_DIR")).join(program);
    let name = program.file_stem().unwrap().to_str().unwrap();
    let tmp = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let binary = tmp.join(format!("libinjection-{name}"));
    // Built aside and moved into place, so that another run still executing
    // the previous binary is left alone.
    let building = tmp.join(format!("libinjection-{name}.{}", std::process::id()));

    let cc = c_compiler();
    let status = Command::new(&cc)
        // The port follows libinjection as built with a signed `char`: the
        // default on x86, but not, for one, on ARM Linux.
        .arg("-fsigned-char")
        .args(c_flags(default_flags).split_whitespace())
        // Upstream's headers declare static functions they do not define.
        .arg("-w")
        .arg("-I")
        .arg(&sources)
        .arg(&program)
        .args(["libinjection_sqli.c", "libinjection_html5.c", "libinjection_xss.c"].map(|source| sources.join(source)))
        .arg("-o")
        .arg(&building)
        .status()
        .unwrap_or_else(|e| panic!("cannot run the C compiler `{cc}` (set CC): {e}"));
    assert!(status.success(), "`{cc}` failed to build {name}");
    fs::rename(&building, &binary).unwrap();
    binary
}

/// Upstream's `modp_rtrim`.
pub(crate) fn rtrim(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\n' | b'\t' | b'\r'))
        .map_or(0, |last| last + 1);
    &bytes[..end]
}

/// One of the expected-output files of upstream's `tests/`.
pub(crate) struct Case {
    /// Filename of the upstream test case.
    pub(crate) name: String,
    /// Input bytes from its `--INPUT--` section.
    pub(crate) input: Vec<u8>,
    /// Expected output bytes from its `--EXPECTED--` section.
    pub(crate) expected: Vec<u8>,
}

/// Splits a test file into its `--TEST--`, `--INPUT--` and `--EXPECTED--`
/// sections, as `read_file` in `testdriver.c` does.
fn parse_case(name: String, content: &[u8]) -> Case {
    let mut sections: [Vec<u8>; 3] = Default::default();
    let mut seen: usize = 0;
    for line in content.split_inclusive(|&b| b == b'\n') {
        match (seen, line) {
            (0, b"--TEST--\n") | (1, b"--INPUT--\n") | (2, b"--EXPECTED--\n") => seen += 1,
            (0, _) => panic!("{name}: text before --TEST--"),
            _ => sections[seen - 1].extend_from_slice(line),
        }
    }
    assert_eq!(seen, 3, "{name}: missing section");
    Case {
        name,
        input: rtrim(&sections[1]).to_vec(),
        expected: rtrim(&sections[2]).to_vec(),
    }
}

/// The cases in `tests/<prefix>*.txt`.
pub(crate) fn cases(prefix: &str) -> Vec<Case> {
    files("tests", prefix)
        .into_iter()
        .map(|(name, content)| parse_case(name, &content))
        .collect()
}

/// `modp_url_decode` in `reader.c`.
pub(crate) fn url_decode(s: &[u8]) -> Vec<u8> {
    let hex = |b: u8| char::from(b).to_digit(16);
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < s.len() => {
                if let (Some(high), Some(low)) = (hex(s[i + 1]), hex(s[i + 2])) {
                    out.push(u8::try_from(high << 4 | low).unwrap());
                    i += 2;
                } else {
                    out.push(b'%');
                }
            },
            other => out.push(other),
        }
        i += 1;
    }
    out
}

/// The sample lines of `data/<prefix>*.txt`, still URL-encoded. As in
/// `reader.c`, blank lines and `#` comments are skipped.
pub(crate) fn sample_lines(prefix: &str) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    for (_, content) in files("data", prefix) {
        lines.extend(
            content
                .split(|&b| b == b'\n')
                .map(rtrim)
                .filter(|line| !line.is_empty() && line[0] != b'#')
                .map(<[u8]>::to_vec),
        );
    }
    lines
}

/// Every input upstream ships, once each: the samples of `data/`, both
/// URL-encoded and decoded, and the inputs of the cases in `tests/`.
pub(crate) fn corpus() -> Vec<Vec<u8>> {
    let mut corpus = Vec::new();
    for line in sample_lines("") {
        corpus.push(url_decode(&line));
        corpus.push(line);
    }
    corpus.extend(cases("test-").into_iter().map(|case| case.input));
    corpus.sort_unstable();
    corpus.dedup();
    corpus
}
