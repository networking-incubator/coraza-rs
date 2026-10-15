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
//! Refresh and verify libperfusion's local tables from a selected C revision.

#![allow(clippy::missing_docs_in_private_items, reason = "internal xtask implementation")]

use std::{
    collections::HashSet,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use clap::Args;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const REPOSITORY: &str = "https://github.com/libinjection/libinjection";

/// Upstream-generated SQL table, rewritten by `tables-refresh`.
const SQL_FILE: &str = "sqli_keywords.txt";
/// Upstream-generated XSS table, rewritten by `tables-refresh`.
const XSS_FILE: &str = "xss_tables.txt";
/// Locally authored SQL additions, never rewritten by `tables-refresh`.
const LOCAL_SQL_FILE: &str = "sqli_keywords_local.txt";
/// Locally authored XSS additions, never rewritten by `tables-refresh`.
const LOCAL_XSS_FILE: &str = "xss_tables_local.txt";

#[derive(Args)]
pub(crate) struct RefreshArgs {
    /// libinjection C checkout (or a directory containing its `src/` files).
    #[arg(long)]
    upstream: PathBuf,
}

pub(crate) fn check_or_exit() {
    if let Err(error) = check(&workspace_root()) {
        eprintln!("table check failed: {error}");
        std::process::exit(1);
    }
    println!("upstream and local SQL and XSS tables match their recorded semantic hashes");
}

pub(crate) fn refresh_or_exit(args: &RefreshArgs) {
    if let Err(error) = refresh(&workspace_root(), &args.upstream) {
        eprintln!("table refresh failed: {error}");
        std::process::exit(1);
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn refresh(root: &Path, upstream: &Path) -> Result<(), String> {
    let source_root = if upstream.join("src").is_dir() {
        upstream.to_path_buf()
    } else {
        upstream
            .parent()
            .filter(|parent| parent.join("src").is_dir())
            .ok_or_else(|| format!("{} has no src/ directory", upstream.display()))?
            .to_path_buf()
    };
    let revision = source_revision(&source_root)?;
    let sql_source =
        fs::read_to_string(source_root.join("src/libinjection_sqli_data.h")).map_err(|error| error.to_string())?;
    let xss_source =
        fs::read_to_string(source_root.join("src/libinjection_xss.c")).map_err(|error| error.to_string())?;
    let sql_rows = parse_c_sql(&sql_source)?;
    let xss_rows = parse_c_xss(&xss_source)?;

    let data = root.join("libperfusion/data");
    fs::create_dir_all(&data).map_err(|error| error.to_string())?;
    // Only the upstream-generated files are rewritten: the local supplements
    // stay as they are, and build.rs merges both at compile time.
    fs::write(data.join(SQL_FILE), render_sql(&revision, &sql_rows)).map_err(|error| error.to_string())?;
    fs::write(data.join(XSS_FILE), render_xss_data(&revision, &xss_rows)).map_err(|error| error.to_string())?;
    let (local_sql, local_xss) = read_local(&data)?;
    merged_sql(&sql_rows, &local_sql)?;
    merged_xss(&xss_rows, &local_xss)?;
    fs::write(
        data.join("tables.json"),
        render_manifest(&revision, &sql_rows, &xss_rows, &local_sql, &local_xss),
    )
    .map_err(|error| error.to_string())?;

    check(root)?;
    println!(
        "Refreshed {} SQL and {} XSS rows from {}, keeping {} local SQL and {} local XSS rows",
        sql_rows.len(),
        xss_rows.len(),
        revision.commit,
        local_sql.len(),
        local_xss.len()
    );
    Ok(())
}

/// Parsed `KEY<TAB>BYTE` SQL rows.
type SqlRows = Vec<(String, u8)>;
/// Parsed XSS rows, each a `kind`, `name`, and optional attribute type.
type XssRows = Vec<Vec<String>>;

/// Reads and validates the locally authored supplement tables.
fn read_local(data: &Path) -> Result<(SqlRows, XssRows), String> {
    let sql = fs::read_to_string(data.join(LOCAL_SQL_FILE)).map_err(|error| format!("{LOCAL_SQL_FILE}: {error}"))?;
    let xss = fs::read_to_string(data.join(LOCAL_XSS_FILE)).map_err(|error| format!("{LOCAL_XSS_FILE}: {error}"))?;
    Ok((parse_sql_data(&sql)?, parse_xss_rows(&xss)?))
}

/// The table build.rs generates: upstream rows and local rows, sorted.
fn merged_sql(upstream: &[(String, u8)], local: &[(String, u8)]) -> Result<SqlRows, String> {
    let mut rows = upstream.to_vec();
    rows.extend_from_slice(local);
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    validate_sql_rows(&rows).map_err(|error| format!("{LOCAL_SQL_FILE} does not merge with {SQL_FILE}: {error}"))?;
    Ok(rows)
}

/// The rows build.rs generates: upstream rows first, local rows after them.
fn merged_xss(upstream: &[Vec<String>], local: &[Vec<String>]) -> Result<XssRows, String> {
    let mut rows = upstream.to_vec();
    rows.extend_from_slice(local);
    validate_xss_rows(&rows).map_err(|error| format!("{LOCAL_XSS_FILE} does not merge with {XSS_FILE}: {error}"))?;
    Ok(rows)
}

fn check(root: &Path) -> Result<(), String> {
    let data = root.join("libperfusion/data");
    let sql = fs::read_to_string(data.join(SQL_FILE)).map_err(|error| error.to_string())?;
    let xss = fs::read_to_string(data.join(XSS_FILE)).map_err(|error| error.to_string())?;
    let manifest: Value =
        serde_json::from_slice(&fs::read(data.join("tables.json")).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let sql_rows = parse_sql_data(&sql)?;
    let xss_rows = parse_xss_data(&xss)?;
    let (local_sql, local_xss) = read_local(&data)?;
    // The supplements must stay disjoint from the upstream rows: build.rs
    // rejects the merged table otherwise.
    merged_sql(&sql_rows, &local_sql)?;
    merged_xss(&xss_rows, &local_xss)?;
    if manifest.get("local") != Some(&local_section(&local_sql, &local_xss)) {
        return Err("local supplement tables differ from the \"local\" section of data/tables.json".into());
    }
    let (events, attributes, tags) = xss_counts(&xss_rows);
    let expected_sql_hash = sql_hash(&sql_rows);
    let expected_xss_hash = xss_hash(&xss_rows);

    if manifest.get("schema").and_then(Value::as_u64) != Some(1)
        || manifest
            .get("source")
            .and_then(|source| source.get("repository"))
            .and_then(Value::as_str)
            != Some(REPOSITORY)
        || manifest
            .get("source")
            .and_then(|source| source.get("version"))
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || manifest
            .get("source")
            .and_then(|source| source.get("commit"))
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || manifest
            .get("sql")
            .and_then(|sql| sql.get("entries"))
            .and_then(Value::as_u64)
            != Some(sql_rows.len() as u64)
        || manifest
            .get("sql")
            .and_then(|sql| sql.get("sha256"))
            .and_then(Value::as_str)
            != Some(expected_sql_hash.as_str())
        || manifest
            .get("xss")
            .and_then(|xss| xss.get("entries"))
            .and_then(Value::as_u64)
            != Some(xss_rows.len() as u64)
        || manifest
            .get("xss")
            .and_then(|xss| xss.get("events"))
            .and_then(Value::as_u64)
            != Some(events as u64)
        || manifest
            .get("xss")
            .and_then(|xss| xss.get("attributes"))
            .and_then(Value::as_u64)
            != Some(attributes as u64)
        || manifest
            .get("xss")
            .and_then(|xss| xss.get("tags"))
            .and_then(Value::as_u64)
            != Some(tags as u64)
        || manifest
            .get("xss")
            .and_then(|xss| xss.get("sha256"))
            .and_then(Value::as_str)
            != Some(expected_xss_hash.as_str())
    {
        return Err("local table data differs from data/tables.json; review and refresh it".into());
    }
    Ok(())
}

/// Counts the `event`, `attr`, and `tag` rows of an XSS table.
fn xss_counts(rows: &[Vec<String>]) -> (usize, usize, usize) {
    let count = |kind: &str| {
        rows.iter()
            .filter(|row| row.first().is_some_and(|row_kind| row_kind == kind))
            .count()
    };
    (count("event"), count("attr"), count("tag"))
}

/// The `"local"` section of `data/tables.json` for the supplement tables.
fn local_section(sql: &[(String, u8)], xss: &[Vec<String>]) -> Value {
    let (events, attributes, tags) = xss_counts(xss);
    json!({
        "sql": { "file": LOCAL_SQL_FILE, "entries": sql.len(), "sha256": sql_hash(sql) },
        "xss": {
            "file": LOCAL_XSS_FILE,
            "entries": xss.len(),
            "events": events,
            "attributes": attributes,
            "tags": tags,
            "sha256": xss_hash(xss)
        }
    })
}

struct Revision {
    version: String,
    commit: String,
}

fn source_revision(root: &Path) -> Result<Revision, String> {
    if root.join(".git").exists() {
        let version = git_output(root, ["describe", "--tags", "--always"])?;
        let commit = git_output(root, ["rev-parse", "HEAD"])?;
        return Ok(Revision { version, commit });
    }

    let recorded = root.join("REVISION");
    if let Ok(text) = fs::read_to_string(&recorded) {
        let mut lines = text.lines();
        let version = lines.next().unwrap_or_default().trim();
        let commit = lines.next().unwrap_or(version).trim();
        if !version.is_empty() && !commit.is_empty() {
            return Ok(Revision {
                version: version.to_owned(),
                commit: commit.to_owned(),
            });
        }
    }

    Err(format!("no .git entry or usable REVISION file at {}", root.display()))
}

fn git_output<const N: usize>(root: &Path, args: [&str; N]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!("could not read libinjection revision at {}", root.display()));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| error.to_string())
}

fn parse_c_sql(source: &str) -> Result<Vec<(String, u8)>, String> {
    let body = array_body(source, "sql_keywords[] = {")?;
    let mut rows = Vec::new();
    for line in body.lines().map(str::trim).filter(|line| line.starts_with("{")) {
        let bytes = line.as_bytes();
        let (key, mut pos) = read_c_string(bytes, 1)?;
        skip_space(bytes, &mut pos);
        expect(bytes, &mut pos, b',')?;
        skip_space(bytes, &mut pos);
        expect(bytes, &mut pos, b'\'')?;
        let value = *bytes.get(pos).ok_or("missing SQL table type")?;
        pos += 1;
        expect(bytes, &mut pos, b'\'')?;
        if !key.is_ascii() {
            return Err(format!("non-ASCII SQL table key {key:?}"));
        }
        rows.push((key, value));
    }
    validate_sql_rows(&rows)?;
    Ok(rows)
}

fn parse_c_xss(source: &str) -> Result<Vec<Vec<String>>, String> {
    let events = array_body(source, "BLACKATTREVENT[] = {")?;
    let attributes = array_body(source, "static stringtype_t BLACKATTR[] = {")?;
    let tags = array_body(source, "static const char *BLACKTAG[] = {")?;
    let events = quoted_entries(&strip_c_comments(events))?
        .into_iter()
        .map(|(name, rest)| {
            if !rest.contains("TYPE_BLACK") {
                return Err(format!("unexpected event type for {name}"));
            }
            Ok(vec!["event".to_owned(), name])
        })
        .collect::<Result<Vec<_>, String>>()?;
    let attributes = quoted_entries(&strip_c_comments(attributes))?
        .into_iter()
        .map(|(name, rest)| {
            let kind = ["TYPE_BLACK", "TYPE_ATTR_URL", "TYPE_STYLE", "TYPE_ATTR_INDIRECT"]
                .into_iter()
                .find(|kind| rest.contains(kind))
                .ok_or_else(|| format!("unknown attribute type for {name}: {rest}"))?;
            let kind = match kind {
                "TYPE_BLACK" => "Black",
                "TYPE_ATTR_URL" => "Url",
                "TYPE_STYLE" => "Style",
                _ => "Indirect",
            };
            Ok(vec!["attr".to_owned(), name, kind.to_owned()])
        })
        .collect::<Result<Vec<_>, String>>()?;
    let tags = quoted_entries(&strip_c_comments(tags))?
        .into_iter()
        .map(|(name, _)| vec!["tag".to_owned(), name])
        .collect::<Vec<_>>();

    let mut rows = events;
    rows.extend(attributes);
    rows.extend(tags);
    validate_xss_rows(&rows)?;
    Ok(rows)
}

fn array_body<'a>(source: &'a str, declaration: &str) -> Result<&'a str, String> {
    let start = source
        .find(declaration)
        .ok_or_else(|| format!("missing C table {declaration:?}"))?
        + declaration.len();
    let remainder = source
        .get(start..)
        .ok_or("C table declaration is not on a UTF-8 boundary")?;
    let end = remainder
        .find("};")
        .ok_or_else(|| format!("unterminated C table {declaration:?}"))?;
    remainder
        .get(..end)
        .ok_or_else(|| format!("C table {declaration:?} is not on a UTF-8 boundary"))
}

fn strip_c_comments(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(start) = rest.find("/*") {
        let Some(prefix) = rest.get(..start) else {
            return result;
        };
        result.push_str(prefix);
        let Some(after_open) = rest.get(start + 2..) else {
            return result;
        };
        let Some(end) = after_open.find("*/") else {
            return result;
        };
        let Some(after_comment) = after_open.get(end + 2..) else {
            return result;
        };
        rest = after_comment;
    }
    result.push_str(rest);
    result
}

fn quoted_entries(source: &str) -> Result<Vec<(String, String)>, String> {
    let bytes = source.as_bytes();
    let mut entries = Vec::new();
    let mut pos = 0;
    while let Some(offset) = bytes.get(pos..).and_then(|tail| tail.iter().position(|&ch| ch == b'"')) {
        let start = pos + offset;
        let (value, end) = read_c_string(bytes, start)?;
        let rest = bytes.get(end..).ok_or("invalid C string end position")?;
        let next = rest
            .iter()
            .position(|&ch| ch == b'"')
            .map_or(bytes.len(), |offset| end + offset);
        let suffix = bytes.get(end..next).ok_or("invalid C table entry boundary")?;
        entries.push((value, String::from_utf8_lossy(suffix).into_owned()));
        pos = next;
    }
    Ok(entries)
}

fn read_c_string(bytes: &[u8], quote_at: usize) -> Result<(String, usize), String> {
    if bytes.get(quote_at) != Some(&b'"') {
        return Err("expected quoted C table value".into());
    }
    let mut pos = quote_at + 1;
    let mut value = Vec::new();
    loop {
        let byte = *bytes.get(pos).ok_or("unterminated C string")?;
        pos += 1;
        match byte {
            b'"' => break,
            b'\\' => {
                let escaped = *bytes.get(pos).ok_or("unterminated C escape")?;
                pos += 1;
                value.push(match escaped {
                    b'\\' => b'\\',
                    b'"' => b'"',
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    other => return Err(format!("unsupported C escape \\{other}")),
                });
            },
            other => value.push(other),
        }
    }
    String::from_utf8(value)
        .map(|value| (value, pos))
        .map_err(|error| error.to_string())
}

fn skip_space(bytes: &[u8], pos: &mut usize) {
    while bytes.get(*pos).is_some_and(u8::is_ascii_whitespace) {
        *pos += 1;
    }
}

fn expect(bytes: &[u8], pos: &mut usize, expected: u8) -> Result<(), String> {
    if bytes.get(*pos) != Some(&expected) {
        return Err(format!("expected {:?} in C table row", char::from(expected)));
    }
    *pos += 1;
    Ok(())
}

fn parse_sql_data(source: &str) -> Result<Vec<(String, u8)>, String> {
    let mut rows = Vec::new();
    for line in source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (key, value) = line
            .split_once('\t')
            .ok_or_else(|| format!("missing tab in {line:?}"))?;
        if value.len() != 1 || !key.is_ascii() {
            return Err(format!("invalid SQL table row {line:?}"));
        }
        let value_byte = value
            .as_bytes()
            .first()
            .copied()
            .ok_or_else(|| format!("missing SQL table value in {line:?}"))?;
        rows.push((key.to_owned(), value_byte));
    }
    validate_sql_rows(&rows)?;
    Ok(rows)
}

fn validate_sql_rows(rows: &[(String, u8)]) -> Result<(), String> {
    if rows.is_empty()
        || rows.windows(2).any(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_some_and(|(left, right)| left.0 >= right.0)
        })
    {
        return Err("SQL table must be non-empty, sorted, and unique".into());
    }
    if rows.iter().any(|(_, value)| {
        !matches!(
            *value,
            b'k' | b'U'
                | b'B'
                | b'E'
                | b't'
                | b'f'
                | b'n'
                | b'1'
                | b'v'
                | b's'
                | b'o'
                | b'&'
                | b'c'
                | b'A'
                | b'T'
                | b'F'
        )
    }) {
        return Err("SQL table contains an unknown token type".into());
    }
    Ok(())
}

/// Parses XSS rows without requiring every kind: a supplement table may
/// carry only some of them.
fn parse_xss_rows(source: &str) -> Result<Vec<Vec<String>>, String> {
    let mut rows = Vec::new();
    for line in source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields = line.split('\t').map(str::to_owned).collect::<Vec<_>>();
        match fields.as_slice() {
            [kind, name] if (kind == "event" || kind == "tag") && !name.is_empty() => {},
            [kind, name, attr]
                if kind == "attr"
                    && !name.is_empty()
                    && ["Black", "Url", "Style", "Indirect"].contains(&attr.as_str()) => {},
            _ => return Err(format!("invalid XSS table row {line:?}")),
        }
        rows.push(fields);
    }
    check_unique_xss_rows(&rows)?;
    Ok(rows)
}

fn parse_xss_data(source: &str) -> Result<Vec<Vec<String>>, String> {
    let rows = parse_xss_rows(source)?;
    validate_xss_rows(&rows)?;
    Ok(rows)
}

fn check_unique_xss_rows(rows: &[Vec<String>]) -> Result<(), String> {
    let mut seen = HashSet::new();
    for row in rows {
        let (Some(kind), Some(name)) = (row.first(), row.get(1)) else {
            return Err(format!("invalid XSS table entry: {row:?}"));
        };
        if !name.is_ascii() || !seen.insert((kind.as_str(), name.as_str())) {
            return Err(format!("invalid or duplicate XSS table entry: {row:?}"));
        }
    }
    Ok(())
}

fn validate_xss_rows(rows: &[Vec<String>]) -> Result<(), String> {
    check_unique_xss_rows(rows)?;
    for kind in ["event", "attr", "tag"] {
        if !rows
            .iter()
            .any(|row| row.first().is_some_and(|row_kind| row_kind == kind))
        {
            return Err(format!("XSS table has no {kind} rows"));
        }
    }
    Ok(())
}

fn render_sql(revision: &Revision, rows: &[(String, u8)]) -> String {
    let mut out = format!(
        "# Extracted from libinjection C {} ({})\n# Total entries: {}\n# Format: KEY<TAB>VALUE_BYTE\n",
        revision.version,
        revision.commit,
        rows.len()
    );
    for (key, value) in rows {
        writeln!(&mut out, "{key}\t{}", char::from(*value)).unwrap();
    }
    out
}

fn render_xss_data(revision: &Revision, rows: &[Vec<String>]) -> String {
    let mut out = format!(
        "# Extracted from libinjection C {} ({})\n# Format: event<TAB>NAME, attr<TAB>NAME<TAB>TYPE, tag<TAB>NAME\n",
        revision.version, revision.commit
    );
    for row in rows {
        out.push_str(&row.join("\t"));
        out.push('\n');
    }
    out
}

fn render_manifest(
    revision: &Revision,
    sql: &[(String, u8)],
    xss: &[Vec<String>],
    local_sql: &[(String, u8)],
    local_xss: &[Vec<String>],
) -> Vec<u8> {
    let (events, attributes, tags) = xss_counts(xss);
    serde_json::to_vec_pretty(&json!({
        "schema": 1,
        "source": { "repository": REPOSITORY, "version": revision.version, "commit": revision.commit },
        "sql": { "entries": sql.len(), "sha256": sql_hash(sql) },
        "xss": { "entries": xss.len(), "events": events, "attributes": attributes, "tags": tags, "sha256": xss_hash(xss) },
        "local": local_section(local_sql, local_xss)
    }))
    .unwrap()
}

fn sql_hash(rows: &[(String, u8)]) -> String {
    let mut hash = Sha256::new();
    for (key, value) in rows {
        hash.update(key.as_bytes());
        hash.update([0, *value, b'\n']);
    }
    hex(&hash.finalize())
}

fn xss_hash(rows: &[Vec<String>]) -> String {
    let mut hash = Sha256::new();
    for row in rows {
        for field in row {
            hash.update(field.as_bytes());
            hash.update([0]);
        }
        hash.update(b"\n");
    }
    hex(&hash.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").unwrap();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_c_tables_and_preserves_source_order() {
        let sql = "static const keyword_t sql_keywords[] = {\n {\"A\", 'k'},\n {\"B\", 'F'},\n};";
        assert_eq!(parse_c_sql(sql).unwrap(), [("A".into(), b'k'), ("B".into(), b'F')]);

        let xss = "static stringtype_t BLACKATTREVENT[] = {{\"LOAD\", TYPE_BLACK}, {NULL, TYPE_NONE}};\nstatic stringtype_t BLACKATTR[] = {{\"HREF\", TYPE_ATTR_URL}, {NULL, TYPE_NONE}};\nstatic const char *BLACKTAG[] = {\"SCRIPT\", NULL};";
        let rows = parse_c_xss(xss).unwrap();
        assert_eq!(
            rows,
            [
                vec!["event", "LOAD"],
                vec!["attr", "HREF", "Url"],
                vec!["tag", "SCRIPT"],
            ]
        );
    }

    #[test]
    fn merges_local_rows_and_rejects_collisions() {
        let upstream = vec![("A".to_owned(), b'k'), ("C".to_owned(), b'k')];
        let local = vec![("B".to_owned(), b'f')];
        assert_eq!(
            merged_sql(&upstream, &local).unwrap(),
            [("A".to_owned(), b'k'), ("B".to_owned(), b'f'), ("C".to_owned(), b'k')]
        );
        assert!(merged_sql(&upstream, &[("C".to_owned(), b'f')]).is_err());

        let upstream = vec![
            vec!["event".to_owned(), "LOAD".to_owned()],
            vec!["attr".to_owned(), "HREF".to_owned(), "Url".to_owned()],
            vec!["tag".to_owned(), "SCRIPT".to_owned()],
        ];
        let local = vec![vec!["tag".to_owned(), "MATH".to_owned()]];
        assert_eq!(merged_xss(&upstream, &local).unwrap().len(), 4);
        let collision = vec![vec!["attr".to_owned(), "HREF".to_owned(), "Black".to_owned()]];
        assert!(merged_xss(&upstream, &collision).is_err());
    }

    #[test]
    fn local_supplements_may_hold_only_some_row_kinds() {
        let rows = parse_xss_rows("# comment\nattr\tSRCDOC\tBlack\ntag\tMATH\n").unwrap();
        assert_eq!(xss_counts(&rows), (0, 1, 1));
        // The upstream table must still carry every kind.
        assert!(parse_xss_data("attr\tSRCDOC\tBlack\n").is_err());
        let section = local_section(&[("VACUUM".to_owned(), b'T')], &rows);
        assert_eq!(
            section.get("xss").and_then(|xss| xss.get("file")),
            Some(&json!(LOCAL_XSS_FILE))
        );
        assert_eq!(section.get("sql").and_then(|sql| sql.get("entries")), Some(&json!(1)));
    }
}
