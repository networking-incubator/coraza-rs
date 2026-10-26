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

//! Refresh and verify the vendored Go Coraza acceptance fixtures.

#![allow(clippy::missing_docs_in_private_items, reason = "internal xtask implementation")]

use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use clap::Args;
use serde_json::Value;

const MODULE: &str = "github.com/corazawaf/coraza/v3";
const EXPORTER_DIR: &str = "coraza/tests/go_profiles/exporter";
const OPERATORS_DIR: &str = "coraza/tests/go_operators";
const PROFILES_DATA_DIR: &str = "coraza/tests/go_profiles/data";
const PROFILES_FILE: &str = "coraza/tests/go_profiles/profiles.json";
const OPERATOR_JSON_FILES: usize = 29;
const OPERATOR_CASES: usize = 3934;
const PROFILE_COUNT: usize = 49;
const PROFILE_STAGE_COUNT: usize = 120;

#[derive(Args)]
pub(crate) struct CheckArgs {
    /// Fail when the Go toolchain or the pinned module is unavailable.
    #[arg(long)]
    require_go: bool,
    /// Re-run the profile exporter and byte-compare its output with the vendored document.
    ///
    /// Needs the exporter's pinned Go toolchain, so it is not part of the default check; see docs/ci.md.
    #[arg(long)]
    provenance: bool,
}

struct Source {
    version: String,
    module: PathBuf,
}

pub(crate) fn check_or_exit(args: &CheckArgs) {
    let root = workspace_root();
    match resolve(&root) {
        Ok(source) => {
            if let Err(error) = check(&root, &source, args.provenance) {
                eprintln!("go fixture check failed: {error}");
                std::process::exit(1);
            }
        },
        Err(error) if args.require_go || args.provenance => {
            eprintln!("go fixture check failed: {error}");
            std::process::exit(1);
        },
        Err(error) => println!("go-fixtures check skipped: {error}"),
    }
}

pub(crate) fn refresh_or_exit() {
    let root = workspace_root();
    let result = resolve(&root).and_then(|source| refresh(&root, &source));
    if let Err(error) = result {
        eprintln!("go fixture refresh failed: {error}");
        std::process::exit(1);
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is a workspace member")
        .to_owned()
}

fn resolve(root: &Path) -> Result<Source, String> {
    let version = pinned_version(root)?;
    let module = go_mod_cache()?.join(format!("{MODULE}@{version}"));
    if !module.is_dir() {
        return Err(format!(
            "pinned module directory {} is missing; run `go mod download {MODULE}@{version}` in {EXPORTER_DIR}",
            module.display()
        ));
    }
    Ok(Source { version, module })
}

fn pinned_version(root: &Path) -> Result<String, String> {
    let path = root.join(EXPORTER_DIR).join("go.mod");
    let go_mod = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    for line in go_mod.lines() {
        let line = line.split("//").next().unwrap_or_default().trim();
        let fields: Vec<_> = line
            .strip_prefix("require ")
            .unwrap_or(line)
            .split_whitespace()
            .collect();
        if let [module, version, ..] = fields.as_slice()
            && *module == MODULE
        {
            return Ok((*version).to_owned());
        }
    }
    Err(format!("{} does not pin {MODULE}", path.display()))
}

fn go_mod_cache() -> Result<PathBuf, String> {
    let output = Command::new("go")
        .args(["env", "GOMODCACHE"])
        .output()
        .map_err(|error| format!("Go toolchain not found: {error}; install Go and retry"))?;
    if !output.status.success() {
        return Err(format!(
            "Go toolchain not found: `go env GOMODCACHE` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let path = String::from_utf8(output.stdout)
        .map_err(|error| format!("Go toolchain not found: `go env GOMODCACHE` returned invalid UTF-8: {error}"))?;
    let path = path.trim();
    if path.is_empty() {
        return Err("Go toolchain not found: `go env GOMODCACHE` returned an empty path".into());
    }
    Ok(PathBuf::from(path))
}

fn refresh(root: &Path, source: &Source) -> Result<(), String> {
    let testdata = source.module.join("internal/operators/testdata");
    let operator_files = files_with_extension(&testdata, "json")?;
    if operator_files.is_empty() {
        return Err(format!("{} contains no operator JSON files", testdata.display()));
    }
    let operator_data_files = files_with_extension(&testdata.join("op"), "dat")?;
    let profile_data_files = files_with_extension(&source.module.join("testing/testdata"), "dat")?;

    let operators_dir = root.join(OPERATORS_DIR);
    let operator_data_dir = operators_dir.join("op");
    let profiles_data_dir = root.join(PROFILES_DATA_DIR);
    fs::create_dir_all(&operator_data_dir).map_err(|error| format!("{}: {error}", operator_data_dir.display()))?;
    fs::create_dir_all(&profiles_data_dir).map_err(|error| format!("{}: {error}", profiles_data_dir.display()))?;

    copy_files(&operator_files, &operators_dir)?;
    copy_files(&operator_data_files, &operator_data_dir)?;
    copy_files(&profile_data_files, &profiles_data_dir)?;
    remove_stale(&operators_dir, &operator_files, "json")?;
    remove_stale(&operator_data_dir, &operator_data_files, "dat")?;
    remove_stale(&profiles_data_dir, &profile_data_files, "dat")?;

    run_exporter(root, &root.join(PROFILES_FILE))?;
    verify_inventory(root, &operator_files, &source.version)?;

    println!(
        "Refreshed Go Coraza {} fixtures: {} operator files, {} profiles; run the harnesses to review parity.",
        source.version,
        operator_files.len(),
        PROFILE_COUNT
    );
    Ok(())
}

fn check(root: &Path, source: &Source, provenance: bool) -> Result<(), String> {
    let mut drifted = Vec::new();
    compare_trees(
        root,
        &source.module.join("internal/operators/testdata"),
        &root.join(OPERATORS_DIR),
        "json",
        &mut drifted,
    )?;
    compare_trees(
        root,
        &source.module.join("internal/operators/testdata/op"),
        &root.join(OPERATORS_DIR).join("op"),
        "dat",
        &mut drifted,
    )?;
    compare_trees(
        root,
        &source.module.join("testing/testdata"),
        &root.join(PROFILES_DATA_DIR),
        "dat",
        &mut drifted,
    )?;

    let operator_files = files_with_extension(&root.join(OPERATORS_DIR), "json")?;
    if let Err(error) = verify_inventory(root, &operator_files, &source.version) {
        drifted.push(error);
    }

    if !drifted.is_empty() {
        return Err(format!(
            "drifted Go Coraza fixtures:\n  {}\nrun `cargo xtask go-fixtures-refresh` to update them",
            drifted.join("\n  ")
        ));
    }
    if provenance {
        check_provenance(root, &root.join(PROFILES_FILE))?;
    }
    println!(
        "Verified Go Coraza {} fixtures: {} operator files, {} profiles.",
        source.version, OPERATOR_JSON_FILES, PROFILE_COUNT
    );
    Ok(())
}

fn compare_trees(
    root: &Path,
    source: &Path,
    destination: &Path,
    extension: &str,
    drifted: &mut Vec<String>,
) -> Result<(), String> {
    let expected = file_names(&files_with_extension(source, extension)?)?;
    let actual = file_names(&files_with_extension(destination, extension)?)?;
    for name in expected.difference(&actual) {
        drifted.push(format!("{}: missing", relative(root, &destination.join(name))));
    }
    for name in actual.difference(&expected) {
        drifted.push(format!("{}: unexpected", relative(root, &destination.join(name))));
    }
    for name in expected.intersection(&actual) {
        let source_path = source.join(name);
        let destination_path = destination.join(name);
        let source_bytes = fs::read(&source_path).map_err(|error| format!("{}: {error}", source_path.display()))?;
        let destination_bytes =
            fs::read(&destination_path).map_err(|error| format!("{}: {error}", destination_path.display()))?;
        if source_bytes != destination_bytes {
            drifted.push(format!("{}: modified", relative(root, &destination_path)));
        }
    }
    Ok(())
}

fn check_provenance(root: &Path, pinned: &Path) -> Result<(), String> {
    let exported = std::env::temp_dir().join(format!("coraza-go-profiles-{}.json", std::process::id()));
    run_exporter(root, &exported)?;
    let expected = fs::read(pinned).map_err(|error| format!("{}: {error}", pinned.display()))?;
    let actual = fs::read(&exported).map_err(|error| format!("{}: {error}", exported.display()))?;
    if expected == actual {
        drop(fs::remove_file(&exported));
        return Ok(());
    }
    Err(format!(
        "{} does not match a fresh export from the pinned Go module; diff it against {} or rerun `cargo xtask go-fixtures-refresh`",
        relative(root, pinned),
        exported.display()
    ))
}

fn verify_inventory(root: &Path, operator_files: &[PathBuf], version: &str) -> Result<(), String> {
    let mut cases = 0;
    for path in operator_files {
        let entries = read_json(path)?;
        let entries = entries
            .as_array()
            .ok_or_else(|| format!("{}: expected a JSON array of cases", path.display()))?;
        cases += entries.len();
    }
    if operator_files.len() != OPERATOR_JSON_FILES || cases != OPERATOR_CASES {
        return Err(format!(
            "operator inventory changed: found {} JSON files and {cases} cases, expected {OPERATOR_JSON_FILES} files and {OPERATOR_CASES} cases; update OPERATOR_JSON_FILES and OPERATOR_CASES in xtask/src/go_fixtures.rs and FIXTURE_FILES and FIXTURE_CASES in coraza/tests/go_operators.rs, then rerun `cargo xtask go-fixtures-refresh`",
            operator_files.len()
        ));
    }

    let profiles_path = root.join(PROFILES_FILE);
    let label = relative(root, &profiles_path);
    let document = read_json(&profiles_path)?;
    if document.pointer("/source/version").and_then(Value::as_str) != Some(version) {
        return Err(format!(
            "{label} was exported from a different Go Coraza version; rerun `cargo xtask go-fixtures-refresh`"
        ));
    }
    let profiles = document
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{label}: missing profiles array"))?;
    let stages = profile_stages(profiles);
    if profiles.len() != PROFILE_COUNT || stages != PROFILE_STAGE_COUNT {
        return Err(format!(
            "profile inventory changed: found {} profiles and {stages} stages, expected {PROFILE_COUNT} profiles and {PROFILE_STAGE_COUNT} stages; update PROFILE_COUNT and PROFILE_STAGE_COUNT in xtask/src/go_fixtures.rs and FIXTURE_PROFILES and FIXTURE_STAGES in coraza/tests/go_profiles_replay.rs, then rerun `cargo xtask go-fixtures-refresh`",
            profiles.len()
        ));
    }
    Ok(())
}

fn profile_stages(profiles: &[Value]) -> usize {
    let mut stages = 0;
    for profile in profiles {
        for test in profile.get("tests").and_then(Value::as_array).into_iter().flatten() {
            stages += test.get("stages").and_then(Value::as_array).map_or(0, Vec::len);
        }
    }
    stages
}

fn run_exporter(root: &Path, output: &Path) -> Result<(), String> {
    let exporter = root.join(EXPORTER_DIR);
    let result = Command::new("go")
        .args(["run", ".", "-o"])
        .arg(output)
        .env("GOWORK", "off")
        .env("GOPROXY", "off")
        .env("GOTOOLCHAIN", "local")
        .current_dir(&exporter)
        .output()
        .map_err(|error| format!("run the Go profile exporter in {}: {error}", exporter.display()))?;
    if !result.status.success() {
        return Err(format!(
            "run the Go profile exporter in {}: {}\nrun `go mod download` in that directory and retry",
            exporter.display(),
            String::from_utf8_lossy(&result.stderr).trim()
        ));
    }
    Ok(())
}

fn files_with_extension(directory: &Path, extension: &str) -> Result<Vec<PathBuf>, String> {
    let mut paths = fs::read_dir(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("{}: {error}", directory.display()))?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().and_then(OsStr::to_str) == Some(extension))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn file_names(paths: &[PathBuf]) -> Result<BTreeSet<String>, String> {
    paths
        .iter()
        .map(|path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("{}: file name is not UTF-8", path.display()))
        })
        .collect()
}

fn copy_files(paths: &[PathBuf], destination: &Path) -> Result<(), String> {
    for path in paths {
        let name = path
            .file_name()
            .ok_or_else(|| format!("{}: has no file name", path.display()))?;
        let target = destination.join(name);
        if target.exists() {
            make_writable(&target)?;
        }
        fs::copy(path, &target).map_err(|error| format!("{}: {error}", target.display()))?;
        make_writable(&target)?;
    }
    Ok(())
}

fn remove_stale(directory: &Path, expected: &[PathBuf], extension: &str) -> Result<(), String> {
    let expected = file_names(expected)?;
    for path in files_with_extension(directory, extension)? {
        if let Some(name) = path.file_name().and_then(OsStr::to_str)
            && !expected.contains(name)
        {
            make_writable(&path)?;
            fs::remove_file(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        }
    }
    Ok(())
}

fn make_writable(path: &Path) -> Result<(), String> {
    let mut permissions = fs::metadata(path)
        .map_err(|error| format!("{}: {error}", path.display()))?
        .permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        if permissions.mode() & 0o200 == 0 {
            permissions.set_mode(0o644);
            fs::set_permissions(path, permissions).map_err(|error| format!("{}: {error}", path.display()))?;
        }
    }
    #[cfg(not(unix))]
    if permissions.readonly() {
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).map_err(|error| format!("{}: {error}", path.display()))?;
    }
    Ok(())
}

fn read_json(path: &Path) -> Result<Value, String> {
    serde_json::from_slice(&fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?)
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).display().to_string()
}
