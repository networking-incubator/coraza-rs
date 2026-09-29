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

//! Build script: static keyword table + accept LUTs for legacy `SQLi` (`include!`).

#![expect(clippy::expect_used, reason = "build scripts must abort on error")]
#![expect(clippy::missing_docs_in_private_items, reason = "build script")]
#![expect(clippy::panic, reason = "build scripts must abort on error")]

use std::{env, fs, io::Write as _, path::Path};

/// Must match `data/sqli_keywords.txt` (libinjection-go v0.3.2).
const EXPECTED_KEYWORD_COUNT: usize = 9_352;

fn rust_byte_str_literal(s: &str) -> String {
    let mut out = String::from("b\"");
    for &b in s.as_bytes() {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7E => out.push(b as char),
            _ => {
                use std::fmt::Write as _;
                write!(out, "\\x{b:02x}").expect("format hex escape");
            },
        }
    }
    out.push('"');
    out
}

fn main() {
    if env::var("CARGO_FEATURE_LEGACY").is_err() {
        return;
    }

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");
    generate_sql_keywords(&out_dir);
    generate_accept_tables(&out_dir);
}

fn generate_sql_keywords(out_dir: &str) {
    let go_data_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("data/sqli_keywords.txt");

    println!("cargo:rerun-if-changed={}", go_data_path.display());

    let contents = fs::read_to_string(&go_data_path).unwrap_or_else(|e| {
        panic!(
            "failed to read {}: {e}. Run the extraction script first.",
            go_data_path.display()
        )
    });

    let mut entries: Vec<(&str, u8)> = Vec::new();

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, val)) = line.split_once('\t') else {
            continue;
        };
        assert!(
            key.is_ascii()
                && key
                    .bytes()
                    .all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_uppercase()),
            "sqli_keywords.txt key is not uppercase ASCII: {key:?}"
        );
        let Some(&val_byte) = val.as_bytes().first() else {
            continue;
        };
        if val.len() != 1 {
            continue;
        }
        entries.push((key, val_byte));
    }

    entries.sort_by_key(|(k, _)| *k);

    assert_eq!(
        entries.len(),
        EXPECTED_KEYWORD_COUNT,
        "sqli_keywords.txt entry count drifted (expected {EXPECTED_KEYWORD_COUNT})"
    );

    let dest = Path::new(out_dir).join("sqli_keywords.rs");
    let mut file = fs::File::create(&dest).expect("create sqli_keywords.rs");

    writeln!(
        file,
        "/// Auto-generated from `data/sqli_keywords.txt` ({EXPECTED_KEYWORD_COUNT} entries, sorted).\n\
         /// Binary search lookup — no runtime `phf` dependency.\n\
         static SQL_KEYWORD_ENTRIES: [(&[u8], u8); {EXPECTED_KEYWORD_COUNT}] = ["
    )
    .expect("write sqli_keywords.rs header");

    for (key, val) in &entries {
        let key_lit = rust_byte_str_literal(key);
        writeln!(file, "    ({key_lit}, {val}),").expect("write entry");
    }

    writeln!(file, "];").expect("write sqli_keywords.rs footer");
}

fn generate_accept_tables(out_dir: &str) {
    let word_bytes: &[u8] = b" []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r\"\xa0\x00";
    let var_bytes: &[u8] = b" <>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r'`\"";

    let dest = Path::new(out_dir).join("accept_tables.rs");
    let mut file = fs::File::create(&dest).expect("create accept_tables.rs");

    write_accept_table(&mut file, "WORD_ACCEPT_TABLE", word_bytes, "wordAcceptTable");
    write_accept_table(&mut file, "VAR_ACCEPT_TABLE", var_bytes, "varAcceptTable");
}

fn build_table(accept_str: &[u8]) -> [u8; 256] {
    let mut table = [0_u8; 256];
    for &b in accept_str {
        if let Some(slot) = table.get_mut(b as usize) {
            *slot = 1;
        }
    }
    table
}

fn write_accept_table(file: &mut fs::File, name: &str, accept_str: &[u8], go_name: &str) {
    let table = build_table(accept_str);
    writeln!(file, "/// Go `{go_name}`.").expect("write doc comment");
    write!(file, "pub(crate) static {name}: [u8; 256] = [\n    ").expect("write header");
    for (i, &b) in table.iter().enumerate() {
        write!(file, "{b}").expect("write byte");
        if i < 255 {
            write!(file, ", ").expect("write comma");
            if (i + 1) % 16 == 0 {
                write!(file, "\n    ").expect("write newline");
            }
        }
    }
    writeln!(file, "\n];\n").expect("write footer");
}
