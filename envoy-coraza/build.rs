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

//! Generates the files `src/policy.rs` embeds.
//!
//! Every build derives the built-in `@recommended-conf` from
//! `coraza/coraza.conf-recommended`, the repository's only copy of Go Coraza's
//! recommended configuration: the derived file is that one with the directives
//! the Wasm filter cannot honour commented out.
//!
//! The `embed-crs` feature also generates the rule-data table. The table maps
//! `crs/`-prefixed names to the bytes of the fetched CRS tree, so an existing
//! policy's `Include rules/*.conf` cannot pick up CRS files. It is only
//! generated from a tree whose version marker and file count match the tracked
//! pin and the tree itself.

use std::{
    collections::BTreeSet,
    env,
    fmt::Write as _,
    fs, io,
    io::Read as _,
    path::{Path, PathBuf},
};

/// The fetched tree, relative to this crate, that `make crs-fetch` populates.
const CRS_DIR: &str = "crs";
/// The tracked release pin, relative to this crate; the single source of truth.
const PIN: &str = "crs.pin";
/// Prefix every embedded name gets, so the CRS occupies its own namespace.
const EMBEDDED_PREFIX: &str = "crs";
/// The upstream name of the CRS setup file.
const CRS_SETUP_SOURCE: &str = "crs-setup.conf.example";
/// The embedded name `Include crs/crs-setup.conf` resolves to.
const CRS_SETUP_KEY: &str = "crs/crs-setup.conf";
/// The marker `make crs-fetch` writes after extracting a verified release.
const MARKER: &str = ".version";
/// Most marker bytes read; the marker is three short fields.
const MAX_MARKER_BYTES: u64 = 256;
/// Most pin bytes read; the pin is two short fields.
const MAX_PIN_BYTES: u64 = 256;
/// The engine's recommended configuration, relative to this crate: the single
/// source of the built-in `@recommended-conf`.
const RECOMMENDED_SOURCE: &str = "../coraza/coraza.conf-recommended";
/// The derived file, under `OUT_DIR`, that `src/policy.rs` embeds.
const RECOMMENDED_OUTPUT: &str = "recommended.conf";
/// The directives of [`RECOMMENDED_SOURCE`] the Wasm filter cannot honour, each
/// with the reason the derived file gives, one note line per reason line.
const WASM_DISABLED_DIRECTIVES: [(&str, &str); 2] = [
    (
        "SecRequestBodyInMemoryLimit",
        "the filter has no filesystem, keeps the whole request\n\
         body in memory, and refuses an in-memory limit below SecRequestBodyLimit.",
    ),
    ("SecDataDir", "the filter has no filesystem."),
];
/// The start of the note above each directive the derivation comments out.
const DISABLED_NOTE: &str = "# Disabled for WASM: ";
/// The derived file's header, up to its list of disabled directives.
const RECOMMENDED_HEADER: &str = "\
# envoy-coraza built-in baseline, loaded with `Include @recommended-conf`.
#
# Derived at build time by envoy-coraza/build.rs from
# coraza/coraza.conf-recommended, the verbatim copy of Go Coraza's
# coraza.conf-recommended (Copyright 2022 Juan Pablo Tosso and the OWASP Coraza
# contributors, Apache-2.0). Every line below is upstream's, except that these
# directives, which the Wasm filter cannot honour, are commented out under a
# \"Disabled for WASM\" note:
#
";
/// The rest of the derived file's header, after its list of disabled directives.
const RECOMMENDED_HEADER_END: &str = "\
#
# The file starts in DetectionOnly, like upstream. Set SecRuleEngine On after
# the Include for the rules below to block.

";

/// The setup error for a tree that is missing, partial, or from another release.
fn stale_tree(root: &Path) -> Box<dyn std::error::Error> {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "embedded CRS tree is stale or partial; run `make crs-fetch` (expected {})",
            root.display()
        ),
    )
    .into()
}

/// The setup error for a pin that is missing, unreadable, or malformed.
fn pin_error(path: &Path, reason: &str) -> Box<dyn std::error::Error> {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "CRS pin {}: {reason}; check out envoy-coraza/crs.pin and run `make crs-fetch`",
            path.display()
        ),
    )
    .into()
}

/// Rejects a path that would inject a `cargo:` directive through a control character.
fn reject_control(value: &str, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if value.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("CRS entry {} contains a control character", path.display()),
        )
        .into());
    }
    Ok(())
}

/// Whether a release tag can be embedded in a log line and a rustc env value.
fn valid_version(version: &str) -> bool {
    !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Whether a value is a 64-digit hexadecimal SHA-256.
fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Reads the tracked pin as `(version, sha256)`, bounded and strict.
fn pinned_release(manifest: &Path) -> Result<(String, String), Box<dyn std::error::Error>> {
    let path = manifest.join(PIN);
    let metadata = fs::symlink_metadata(&path).map_err(|_error| pin_error(&path, "missing or unreadable"))?;
    if !metadata.is_file() || metadata.len() > MAX_PIN_BYTES {
        return Err(pin_error(&path, "missing or unreadable"));
    }
    let file = fs::File::open(&path).map_err(|_error| pin_error(&path, "missing or unreadable"))?;
    let mut pin = String::new();
    file.take(MAX_PIN_BYTES)
        .read_to_string(&mut pin)
        .map_err(|_error| pin_error(&path, "missing or unreadable"))?;
    let mut fields = pin.split_whitespace();
    let (Some(version), Some(sha256)) = (fields.next(), fields.next()) else {
        return Err(pin_error(&path, "must contain `<version> <sha256>`"));
    };
    if fields.next().is_some() || !valid_version(version) || !valid_sha256(sha256) {
        return Err(pin_error(&path, "must contain `<version> <sha256>`"));
    }
    Ok((version.to_owned(), sha256.to_owned()))
}

/// Reads the marker as `(version, sha256, file count)`, bounded and strict.
fn marker_release(root: &Path) -> Result<(String, String, usize), Box<dyn std::error::Error>> {
    let path = root.join(MARKER);
    let metadata = fs::symlink_metadata(&path).map_err(|_error| stale_tree(root))?;
    if !metadata.is_file() || metadata.len() > MAX_MARKER_BYTES {
        return Err(stale_tree(root));
    }
    let file = fs::File::open(&path).map_err(|_error| stale_tree(root))?;
    let mut marker = String::new();
    file.take(MAX_MARKER_BYTES)
        .read_to_string(&mut marker)
        .map_err(|_error| stale_tree(root))?;
    let mut fields = marker.split_whitespace();
    let (Some(version), Some(sha256), Some(files)) = (fields.next(), fields.next(), fields.next()) else {
        return Err(stale_tree(root));
    };
    let files = files.parse::<usize>().map_err(|_error| stale_tree(root))?;
    if fields.next().is_some() || !valid_version(version) || !valid_sha256(sha256) {
        return Err(stale_tree(root));
    }
    Ok((version.to_owned(), sha256.to_owned(), files))
}

/// Collects every regular file under `dir` as `(key, path)`.
///
/// Directory entries are inspected without following symlinks; symlinks and
/// special files are rejected. Hard links cannot be told apart from regular
/// files and are therefore accepted.
fn collect(
    root: &Path,
    dir: &Path,
    files: &mut Vec<(String, PathBuf)>,
    keys: &mut BTreeSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if entry.file_name() == MARKER {
            // A directory or special file named `.version` is a partial tree, not a marker.
            if !file_type.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("CRS marker {} is not a regular file", path.display()),
                )
                .into());
            }
            continue;
        }
        if file_type.is_dir() {
            collect(root, &path, files, keys)?;
            continue;
        }
        if !file_type.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("CRS entry {} is not a regular file", path.display()),
            )
            .into());
        }
        let path_text = path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("CRS path {} is not UTF-8", path.display()),
            )
        })?;
        reject_control(path_text, &path)?;
        let relative = path.strip_prefix(root)?;
        let relative = relative.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("CRS path {} is not UTF-8", path.display()),
            )
        })?;
        let key = if relative == CRS_SETUP_SOURCE {
            CRS_SETUP_KEY.to_owned()
        } else {
            format!("{EMBEDDED_PREFIX}/{relative}")
        };
        if !keys.insert(key.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("duplicate embedded CRS key {key:?}"),
            )
            .into());
        }
        files.push((key, path));
    }
    Ok(())
}

/// Derives the built-in `@recommended-conf` from the engine's recommended
/// configuration: a comment header, then `source` line for line, with each
/// directive in [`WASM_DISABLED_DIRECTIVES`] commented out under a note.
///
/// Fails when a disabled directive is missing, so the header never lists one
/// the file does not set. Also fails when one continues onto the next line: the
/// parser drops a comment before joining lines, so that next line would load
/// as a directive of its own.
fn derive_recommended_conf(source: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut out = String::from(RECOMMENDED_HEADER);
    for (name, _) in WASM_DISABLED_DIRECTIVES {
        writeln!(&mut out, "# - {name}")?;
    }
    out.push_str(RECOMMENDED_HEADER_END);
    let mut disabled = BTreeSet::new();
    for line in source.split_inclusive('\n') {
        // Directive names are case-insensitive, and the parser trims every line.
        let first = line.split_whitespace().next().unwrap_or_default();
        let Some(&(name, reason)) = WASM_DISABLED_DIRECTIVES
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(first))
        else {
            out.push_str(line);
            continue;
        };
        if line.trim_end().ends_with('\\') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{RECOMMENDED_SOURCE}: {name} continues onto the next line, which a leading `#` does not disable"
                ),
            )
            .into());
        }
        for (index, text) in reason.lines().enumerate() {
            let prefix = if index == 0 { DISABLED_NOTE } else { "# " };
            writeln!(&mut out, "{prefix}{text}")?;
        }
        out.push('#');
        out.push_str(line);
        disabled.insert(name);
    }
    if let Some((name, _)) = WASM_DISABLED_DIRECTIVES
        .iter()
        .find(|(name, _)| !disabled.contains(name))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{RECOMMENDED_SOURCE} no longer sets {name}; update WASM_DISABLED_DIRECTIVES in envoy-coraza/build.rs"
            ),
        )
        .into());
    }
    Ok(out)
}

/// Writes the built-in `@recommended-conf`, derived from [`RECOMMENDED_SOURCE`],
/// to `output_dir`.
fn write_recommended_conf(manifest: &Path, output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed={RECOMMENDED_SOURCE}");
    let path = manifest.join(RECOMMENDED_SOURCE);
    let source = fs::read_to_string(&path)
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))?;
    fs::write(output_dir.join(RECOMMENDED_OUTPUT), derive_recommended_conf(&source)?)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output_dir = PathBuf::from(
        env::var_os("OUT_DIR").ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "OUT_DIR is not set"))?,
    );
    write_recommended_conf(manifest, &output_dir)?;
    if env::var_os("CARGO_FEATURE_EMBED_CRS").is_none() {
        return Ok(());
    }
    let (pinned_version, pinned_sha256) = pinned_release(manifest)?;
    let root = manifest.join(CRS_DIR);
    println!("cargo:rerun-if-changed={}", root.display());
    println!("cargo:rerun-if-changed={}", manifest.join(PIN).display());
    match fs::symlink_metadata(&root) {
        Ok(metadata) if metadata.is_dir() => {},
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "CRS tree is not a directory; run `make crs-fetch` (expected {})",
                    root.display()
                ),
            )
            .into());
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("CRS tree missing; run `make crs-fetch` (expected {})", root.display()),
            )
            .into());
        },
        Err(error) => return Err(error.into()),
    }
    let (version, sha256, pinned_count) = marker_release(&root)?;
    if version != pinned_version || sha256 != pinned_sha256 {
        return Err(stale_tree(&root));
    }
    let mut files = Vec::new();
    let mut keys = BTreeSet::new();
    collect(&root, &root, &mut files, &mut keys)?;
    let has_setup = keys.contains(CRS_SETUP_KEY);
    let has_rule = keys
        .iter()
        .any(|key| key.starts_with("crs/rules/") && key.ends_with(".conf"));
    if files.len() != pinned_count || !has_setup || !has_rule {
        return Err(stale_tree(&root));
    }
    files.sort();

    let mut out = String::from(
        "// @generated by build.rs from the fetched CRS tree.\n\
         /// The CRS files `Include` resolves, keyed by their `crs/`-prefixed names.\n\
         pub(crate) static EMBEDDED_CRS: &[(&str, &[u8])] = &[\n",
    );
    for (key, path) in &files {
        println!("cargo:rerun-if-changed={}", path.display());
        let path = path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("CRS path {} is not UTF-8", path.display()),
            )
        })?;
        writeln!(&mut out, "    ({key:?}, include_bytes!({path:?})),")?;
    }
    out.push_str("];\n");
    writeln!(&mut out, "/// The CRS release whose files this build embedded.\npub(crate) static EMBEDDED_CRS_VERSION: &str = {version:?};")?;

    fs::write(output_dir.join("embedded_crs.rs"), out)?;
    Ok(())
}
