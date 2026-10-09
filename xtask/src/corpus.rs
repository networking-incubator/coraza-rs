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

//! Verify and refresh the pinned upstream corpus.

#![allow(clippy::missing_docs_in_private_items, reason = "internal xtask implementation")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const REPOSITORY: &str = "https://github.com/corazawaf/libinjection-go";
const MODULE: &str = "github.com/corazawaf/libinjection-go";

struct Fixture {
    name: String,
    input: Vec<u8>,
    expected: Vec<u8>,
}

struct TemporaryDirectory(PathBuf);

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.0));
    }
}

pub(crate) fn check_or_exit() {
    if let Err(error) = check(&workspace_root()) {
        eprintln!("corpus check failed: {error}");
        std::process::exit(1);
    }
}

pub(crate) fn refresh_or_exit() {
    if let Err(error) = refresh() {
        eprintln!("corpus refresh failed: {error}");
        std::process::exit(1);
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is a workspace member")
        .to_owned()
}

fn check(root: &Path) -> Result<(), String> {
    let (version, module_sum) = pinned_module(root)?;
    let crate_root = root.join("libinjection-rs");
    check_snapshot(
        &crate_root.join("tests/corpus"),
        &crate_root.join("tests/parity/manifest.json"),
        &crate_root.join("tests/parity/sqli_oracle.tsv"),
        &version,
        &module_sum,
    )
}

fn check_snapshot(
    corpus_dir: &Path,
    manifest_path: &Path,
    oracle_path: &Path,
    version: &str,
    module_sum: &str,
) -> Result<(), String> {
    let manifest: Value = serde_json::from_slice(
        &fs::read(manifest_path).map_err(|error| format!("{}: {error}", manifest_path.display()))?,
    )
    .map_err(|error| format!("{}: {error}", manifest_path.display()))?;
    let expected_names = check_fixture_manifest(corpus_dir, &manifest, version, module_sum)?;
    check_sql_oracle(corpus_dir, oracle_path, version, &expected_names)?;
    println!(
        "Verified {} fixtures and {} SQL oracle inputs",
        expected_names.len(),
        expected_names
            .iter()
            .filter(|name| name.starts_with("test-sqli-"))
            .count()
    );
    Ok(())
}

fn check_fixture_manifest(
    corpus_dir: &Path,
    manifest: &Value,
    version: &str,
    module_sum: &str,
) -> Result<BTreeSet<String>, String> {
    if manifest.get("schema").and_then(Value::as_u64) != Some(2) {
        return Err("unsupported corpus manifest schema".into());
    }
    if manifest.pointer("/source/repository").and_then(Value::as_str) != Some(REPOSITORY) {
        return Err("manifest source repository is incorrect".into());
    }
    if manifest.pointer("/source/version").and_then(Value::as_str) != Some(version) {
        return Err("manifest source version differs from xtask/tools/go.mod".into());
    }
    if manifest.pointer("/source/module_sum").and_then(Value::as_str) != Some(module_sum) {
        return Err("manifest source checksum differs from xtask/tools/go.sum".into());
    }
    if manifest.pointer("/oracle/version").and_then(Value::as_str) != Some(version) {
        return Err("oracle and fixture source versions differ".into());
    }
    if manifest.pointer("/oracle/module_sum").and_then(Value::as_str) != Some(module_sum) {
        return Err("oracle and fixture source checksums differ".into());
    }

    let records = manifest
        .pointer("/fixtures/files")
        .and_then(Value::as_array)
        .ok_or("manifest has no fixture records")?;
    let mut expected_names = BTreeSet::new();
    let mut family_counts = BTreeMap::new();
    for record in records {
        let name = record
            .get("name")
            .and_then(Value::as_str)
            .ok_or("manifest fixture has no name")?;
        if !valid_fixture_name(name) || !expected_names.insert(name.to_owned()) {
            return Err(format!("invalid or duplicate fixture name: {name}"));
        }
        *family_counts.entry(fixture_family(name)?.to_owned()).or_insert(0_u64) += 1;

        let path = corpus_dir.join(name);
        let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let actual_hash = sha256(&bytes);
        if record.get("size").and_then(Value::as_u64) != Some(bytes.len() as u64)
            || record.get("sha256").and_then(Value::as_str) != Some(&actual_hash)
        {
            return Err(format!("fixture bytes differ from manifest: {name}"));
        }
    }

    let actual_names = fixture_names(corpus_dir)?;
    if actual_names != expected_names {
        return Err("corpus filenames differ from manifest".into());
    }
    if manifest.pointer("/fixtures/total").and_then(Value::as_u64) != Some(records.len() as u64) {
        return Err("manifest fixture total is incorrect".into());
    }
    let recorded_families = manifest
        .pointer("/fixtures/families")
        .and_then(Value::as_object)
        .ok_or("manifest has no fixture families")?;
    if recorded_families.len() != family_counts.len()
        || family_counts
            .iter()
            .any(|(family, count)| recorded_families.get(family).and_then(Value::as_u64) != Some(*count))
    {
        return Err("manifest fixture family counts are incorrect".into());
    }
    Ok(expected_names)
}

fn check_sql_oracle(
    corpus_dir: &Path,
    oracle_path: &Path,
    version: &str,
    expected_names: &BTreeSet<String>,
) -> Result<(), String> {
    let mut oracle_names = BTreeSet::new();
    let oracle = fs::read_to_string(oracle_path).map_err(|error| format!("{}: {error}", oracle_path.display()))?;
    let expected_header = format!("# Oracle: libinjection-go {version}; generated by cargo xtask corpus-refresh");
    if oracle.lines().next() != Some(expected_header.as_str()) {
        return Err("SQL oracle header version differs from manifest".into());
    }
    for (line_number, line) in oracle.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 4 {
            return Err(format!(
                "{}:{}: malformed SQL oracle row",
                oracle_path.display(),
                line_number + 1
            ));
        }
        let [name, input_hash, detected, fingerprint] = fields.as_slice() else {
            unreachable!();
        };
        if !oracle_names.insert((*name).to_owned())
            || !expected_names.contains(*name)
            || !name.starts_with("test-sqli-")
        {
            return Err(format!(
                "{}:{}: invalid SQL oracle fixture {name}",
                oracle_path.display(),
                line_number + 1
            ));
        }
        let path = corpus_dir.join(name);
        let fixture = parse_fixture(
            name,
            &fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?,
        )?;
        if *input_hash != sha256(&fixture.input) {
            return Err(format!("SQL oracle input hash differs from fixture: {name}"));
        }
        if !matches!(*detected, "0" | "1")
            || *fingerprint != hex(&fixture.expected)
            || (*detected == "1") != !fingerprint.is_empty()
        {
            return Err(format!("SQL oracle result differs from fixture: {name}"));
        }
    }
    let sql_names: BTreeSet<_> = expected_names
        .iter()
        .filter(|name| name.starts_with("test-sqli-"))
        .cloned()
        .collect();
    if oracle_names != sql_names {
        return Err("SQL oracle inventory differs from SQL fixtures".into());
    }
    Ok(())
}

fn pinned_module(root: &Path) -> Result<(String, String), String> {
    let tools = root.join("xtask/tools");
    let version = pinned_module_version(&tools)?;
    let go_sum = fs::read_to_string(tools.join("go.sum")).map_err(|error| error.to_string())?;
    let module_sum = go_sum
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            match fields.as_slice() {
                [module, sum_version, sum] if *module == MODULE && *sum_version == version => Some((*sum).to_owned()),
                _ => None,
            }
        })
        .next()
        .ok_or("go.sum has no checksum for the pinned libinjection-go version")?;
    Ok((version, module_sum))
}

fn refresh() -> Result<(), String> {
    let root = workspace_root();
    let crate_root = root.join("libinjection-rs");
    let previous_manifest: Value = serde_json::from_slice(
        &fs::read(crate_root.join("tests/parity/manifest.json")).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let previous_differential = previous_manifest.get("differential").cloned();
    let tools_dir = root.join("xtask/tools");
    let version = pinned_module_version(&tools_dir)?;
    let (source_root, downloaded_version, downloaded_sum) = download_module(&tools_dir, &version)?;
    if downloaded_version != version {
        return Err(format!(
            "downloaded libinjection-go {downloaded_version}, expected {version}"
        ));
    }
    let (pinned_version, module_sum) = pinned_module(&root)?;
    if pinned_version != version || module_sum != downloaded_sum {
        return Err("downloaded Go module does not match go.mod and go.sum".into());
    }
    let temporary = temporary_directory()?;
    let temporary_corpus = temporary.0.join("corpus");
    let temporary_parity = temporary.0.join("parity");
    fs::create_dir(&temporary_corpus).map_err(|error| error.to_string())?;
    fs::create_dir(&temporary_parity).map_err(|error| error.to_string())?;
    let fixtures = read_upstream_fixtures(&source_root.join("tests"), &temporary_corpus)?;
    let go_version = run_output(Command::new("go").arg("version"), "read Go version")?;
    let oracle_rows = generate_oracle(&tools_dir, &temporary, &version, &fixtures)?;

    let mut manifest = build_manifest(&version, &module_sum, &go_version, &temporary_corpus, &fixtures)?;
    if let Some(differential) = previous_differential {
        manifest
            .as_object_mut()
            .ok_or_else(|| "generated manifest root is not an object".to_owned())?
            .insert("differential".to_owned(), differential);
    }
    let manifest_path = temporary_parity.join("manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let oracle_path = temporary_parity.join("sqli_oracle.tsv");
    fs::write(&oracle_path, oracle_rows).map_err(|error| error.to_string())?;
    check_snapshot(&temporary_corpus, &manifest_path, &oracle_path, &version, &module_sum)?;

    replace_fixture_files(&crate_root.join("tests/corpus"), &temporary_corpus, &fixtures)?;
    fs::copy(&manifest_path, crate_root.join("tests/parity/manifest.json")).map_err(|error| error.to_string())?;
    fs::copy(&oracle_path, crate_root.join("tests/parity/sqli_oracle.tsv")).map_err(|error| error.to_string())?;
    println!(
        "Refreshed {} fixtures from libinjection-go {version}; run `cargo test -p libinjection` to review parity.",
        fixtures.len()
    );
    Ok(())
}

fn pinned_module_version(tools_dir: &Path) -> Result<String, String> {
    let go_mod = fs::read_to_string(tools_dir.join("go.mod")).map_err(|error| error.to_string())?;
    let mut in_require_block = false;
    go_mod
        .lines()
        .filter_map(|line| {
            let line = line.split("//").next()?.trim();
            if line == "require (" {
                in_require_block = true;
                return None;
            }
            if line == ")" {
                in_require_block = false;
                return None;
            }
            let fields: Vec<_> = line.split_whitespace().collect();
            match fields.as_slice() {
                ["require", module, version] if *module == MODULE => Some((*version).to_owned()),
                [module, version, ..] if in_require_block && *module == MODULE => Some((*version).to_owned()),
                _ => None,
            }
        })
        .next()
        .ok_or_else(|| "go.mod does not pin libinjection-go".into())
}

fn download_module(tools_dir: &Path, version: &str) -> Result<(PathBuf, String, String), String> {
    let output = run_output(
        Command::new("go")
            .args(["mod", "download", "-json"])
            .arg(format!("{MODULE}@{version}"))
            .current_dir(tools_dir),
        "download pinned libinjection-go module",
    )?;
    let module: Value = serde_json::from_str(&output).map_err(|error| error.to_string())?;
    let dir = module
        .get("Dir")
        .and_then(Value::as_str)
        .ok_or("go mod download returned no source directory")?;
    let version = module
        .get("Version")
        .and_then(Value::as_str)
        .ok_or("go mod download returned no module version")?;
    let module_sum = module
        .get("Sum")
        .and_then(Value::as_str)
        .ok_or("go mod download returned no module checksum")?;
    Ok((PathBuf::from(dir), version.to_owned(), module_sum.to_owned()))
}

fn read_upstream_fixtures(source_dir: &Path, destination: &Path) -> Result<Vec<Fixture>, String> {
    let mut paths = fs::read_dir(source_dir)
        .map_err(|error| format!("{}: {error}", source_dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("{}: {error}", source_dir.display()))?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("test-") && name.ends_with(".txt"))
        })
        .collect::<Vec<_>>();
    paths.sort();
    if paths.is_empty() {
        return Err("pinned Go module contains no test fixtures".into());
    }

    paths
        .into_iter()
        .map(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("fixture name is not UTF-8")?;
            if !valid_fixture_name(name) {
                return Err(format!("invalid fixture name: {name}"));
            }
            let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            let fixture = parse_fixture(name, &bytes)?;
            fs::write(destination.join(name), &bytes).map_err(|error| error.to_string())?;
            Ok(fixture)
        })
        .collect()
}

fn generate_oracle(
    tools_dir: &Path,
    temporary: &TemporaryDirectory,
    version: &str,
    fixtures: &[Fixture],
) -> Result<String, String> {
    let request_path = temporary.0.join("oracle-inputs.tsv");
    let mut request = String::new();
    for fixture in fixtures.iter().filter(|fixture| fixture.name.starts_with("test-sqli-")) {
        request.push_str(&fixture.name);
        request.push('\t');
        request.push_str(&hex(&fixture.input));
        request.push('\n');
    }
    fs::write(&request_path, request).map_err(|error| error.to_string())?;
    let output = run_output(
        Command::new("go")
            .args(["run", "."])
            .arg(&request_path)
            .current_dir(tools_dir),
        "run pinned libinjection-go SQL oracle",
    )?;
    let result_rows: BTreeMap<_, _> = output
        .lines()
        .map(|line| {
            let mut fields = line.split('\t');
            let (Some(name), Some(detected), Some(fingerprint)) = (fields.next(), fields.next(), fields.next()) else {
                return Err(format!("malformed Go oracle output: {line:?}"));
            };
            if fields.next().is_some() {
                return Err(format!("malformed Go oracle output: {line:?}"));
            }
            Ok((name.to_owned(), (detected.to_owned(), fingerprint.to_owned())))
        })
        .collect::<Result<_, String>>()?;

    let mut oracle = format!("# Oracle: libinjection-go {version}; generated by cargo xtask corpus-refresh\n");
    oracle.push_str("# fixture\tinput_sha256\tdetected\tfingerprint_hex\n");

    let expected_names: BTreeSet<_> = fixtures
        .iter()
        .filter(|fixture| fixture.name.starts_with("test-sqli-"))
        .map(|fixture| fixture.name.as_str())
        .collect();
    if result_rows.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_names {
        return Err("Go oracle output inventory differs from SQL fixtures".into());
    }
    for fixture in fixtures.iter().filter(|fixture| fixture.name.starts_with("test-sqli-")) {
        let Some((detected, fingerprint)) = result_rows.get(&fixture.name) else {
            return Err(format!("Go oracle omitted {}", fixture.name));
        };
        if fingerprint != &hex(&fixture.expected) {
            return Err(format!("upstream SQL fixture disagrees with IsSQLi: {}", fixture.name));
        }
        oracle.push_str(&fixture.name);
        oracle.push('\t');
        oracle.push_str(&sha256(&fixture.input));
        oracle.push('\t');
        oracle.push_str(detected);
        oracle.push('\t');
        oracle.push_str(fingerprint);
        oracle.push('\n');
    }
    Ok(oracle)
}

fn build_manifest(
    version: &str,
    module_sum: &str,
    go_version: &str,
    corpus_dir: &Path,
    fixtures: &[Fixture],
) -> Result<Value, String> {
    let mut families = BTreeMap::<String, usize>::new();
    let mut files = Vec::with_capacity(fixtures.len());
    for fixture in fixtures {
        *families.entry(fixture_family(&fixture.name)?.to_owned()).or_default() += 1;
        let bytes = fs::read(corpus_dir.join(&fixture.name)).map_err(|error| error.to_string())?;
        files.push(json!({
            "name": fixture.name,
            "size": bytes.len(),
            "sha256": sha256(&bytes),
        }));
    }
    Ok(json!({
        "schema": 2,
        "source": { "repository": REPOSITORY, "version": version, "module_sum": module_sum },
        "oracle": { "version": version, "module_sum": module_sum, "go_version": go_version.trim() },
        "fixtures": { "total": fixtures.len(), "families": families, "files": files },
    }))
}

fn replace_fixture_files(current: &Path, staged: &Path, fixtures: &[Fixture]) -> Result<(), String> {
    let names: BTreeSet<_> = fixtures.iter().map(|fixture| fixture.name.as_str()).collect();
    let current_paths = fs::read_dir(current)
        .map_err(|error| format!("{}: {error}", current.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("{}: {error}", current.display()))?
        .into_iter()
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    for name in &names {
        fs::copy(staged.join(name), current.join(name)).map_err(|error| error.to_string())?;
    }
    for path in current_paths {
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("test-") && name.ends_with(".txt") && !names.contains(name))
        {
            fs::remove_file(path).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn fixture_names(directory: &Path) -> Result<BTreeSet<String>, String> {
    let names = fs::read_dir(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("{}: {error}", directory.display()))?
        .into_iter()
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
            (path.is_file() && name.starts_with("test-") && name.ends_with(".txt")).then(|| name.to_owned())
        })
        .collect::<BTreeSet<_>>();
    Ok(names)
}

fn fixture_family(name: &str) -> Result<&'static str, String> {
    [
        ("test-sqli-", "sqli"),
        ("test-folding-", "folding"),
        ("test-tokens-", "tokens"),
        ("test-html5-", "html5"),
        ("test-xss-", "xss"),
    ]
    .into_iter()
    .find_map(|(prefix, family)| name.starts_with(prefix).then_some(family))
    .ok_or_else(|| format!("unsupported fixture family: {name}"))
}

fn valid_fixture_name(name: &str) -> bool {
    name.starts_with("test-")
        && name.ends_with(".txt")
        && Path::new(name).file_name().and_then(|file| file.to_str()) == Some(name)
        && !name.chars().any(|character| matches!(character, '\t' | '\n' | '\r'))
}

fn parse_fixture(name: &str, data: &[u8]) -> Result<Fixture, String> {
    let markers = [b"--TEST--".as_slice(), b"--INPUT--", b"--EXPECTED--"];
    let mut sections: [Vec<u8>; 3] = std::array::from_fn(|_| Vec::new());
    let mut marker_index = 0;
    for raw_line in data.split_inclusive(|byte| *byte == b'\n') {
        let has_newline = raw_line.ends_with(b"\n");
        let mut line = raw_line.strip_suffix(b"\n").unwrap_or(raw_line);
        if has_newline {
            line = line.strip_suffix(b"\r").unwrap_or(line);
        }
        if markers
            .get(marker_index)
            .is_some_and(|marker| line.trim_ascii() == *marker)
        {
            marker_index += 1;
        } else if marker_index == 0 {
            return Err(format!("{name}: content before --TEST--"));
        } else if let Some(section) = sections.get_mut(marker_index - 1) {
            section.extend_from_slice(line);
            section.push(b'\n');
        }
    }
    if marker_index != markers.len() {
        return Err(format!("{name}: missing section marker"));
    }
    let input = trim_section(std::mem::take(sections.get_mut(1).ok_or("missing input section")?));
    let expected = trim_section(std::mem::take(sections.get_mut(2).ok_or("missing expected section")?));
    Ok(Fixture {
        name: name.to_owned(),
        input,
        expected,
    })
}

fn trim_section(mut bytes: Vec<u8>) -> Vec<u8> {
    while bytes
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        bytes.pop();
    }
    bytes
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0F));
    }
    output
}

fn hex_digit(value: u8) -> char {
    char::from(match value {
        0..=9 => b'0' + value,
        _ => b'a' + value - 10,
    })
}

fn temporary_directory() -> Result<TemporaryDirectory, String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let path = std::env::temp_dir().join(format!("coraza-corpus-{}-{timestamp}", std::process::id()));
    fs::create_dir(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(TemporaryDirectory(path))
}

fn run_output(command: &mut Command, description: &str) -> Result<String, String> {
    let output = command.output().map_err(|error| format!("{description}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{description}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| format!("{description}: {error}"))
}
