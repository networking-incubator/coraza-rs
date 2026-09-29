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

//! `cargo xtask lint-license` - enforce the Apache-2.0 copyright header on
//! every tracked `.rs` file.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use clap::Parser;
use glob::glob;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The copyright header every `.rs` file must start with.
const LICENSE_HEADER: &str = r#"// Copyright Coraza Kubernetes Operator contributors.
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
"#;

/// Directory names skipped while walking the workspace for `.rs` files.
const SKIPPED_DIRS: [&str; 3] = ["target", ".git", "coraza-rs"];

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask lint-license`.
#[derive(Parser)]
pub(crate) struct Args;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors surfaced while checking license headers.
#[derive(Debug, PartialEq, Eq)]
enum LintLicenseError {
    /// One or more `.rs` files are missing the required header.
    Violations(Vec<PathBuf>),
    /// A workspace `.rs` file could not be read.
    ReadFile {
        /// File that could not be read.
        path: PathBuf,
        /// Human-readable failure message for stderr.
        message: String,
    },
    /// The workspace manifest could not be read or parsed.
    Workspace {
        /// Human-readable failure message for stderr.
        message: String,
    },
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Check every `.rs` file under workspace members for the required
/// copyright header, exiting with an error if any are missing it.
pub(crate) fn run(_args: Args) {
    if execute_lint(&workspace_root()).is_err() {
        std::process::exit(1);
    }
}

/// Run the license-header check and emit human-readable status to stdout/stderr.
fn execute_lint(root: &Path) -> Result<(), LintLicenseError> {
    match lint_license_headers(root) {
        Ok(()) => {
            println!("all .rs files carry the required copyright header");
            Ok(())
        },
        Err(LintLicenseError::Violations(violations)) => {
            eprintln!("missing or malformed copyright header:");
            for path in &violations {
                eprintln!("  {}", path.display());
            }
            Err(LintLicenseError::Violations(violations))
        },
        Err(LintLicenseError::ReadFile { path, message }) => {
            eprintln!("failed to read {}: {message}", path.display());
            Err(LintLicenseError::ReadFile { path, message })
        },
        Err(LintLicenseError::Workspace { message }) => {
            eprintln!("{message}");
            Err(LintLicenseError::Workspace { message })
        },
    }
}

/// Validate every workspace member `.rs` file carries the required header.
fn lint_license_headers(root: &Path) -> Result<(), LintLicenseError> {
    let violations = collect_violations(root)?;
    if violations.is_empty() {
        Ok(())
    } else {
        Err(LintLicenseError::Violations(violations))
    }
}

/// Collect `.rs` files under workspace members that lack the required header.
fn collect_violations(root: &Path) -> Result<Vec<PathBuf>, LintLicenseError> {
    let member_dirs = workspace_member_dirs(root)?;
    let files = member_dirs
        .iter()
        .map(|dir| find_rs_files(dir))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    let mut violations = Vec::new();
    for path in files {
        let content = fs::read_to_string(&path).map_err(|err| LintLicenseError::ReadFile {
            path: path.clone(),
            message: err.to_string(),
        })?;
        if !content.starts_with(LICENSE_HEADER) {
            violations.push(path);
        }
    }

    Ok(violations)
}

// -----------------------------------------------------------------------------
// Filesystem Walking
// -----------------------------------------------------------------------------

/// Recursively collect every `.rs` file under `root`, skipping
/// [`SKIPPED_DIRS`] and other hidden directories.
fn find_rs_files(root: &Path) -> Result<Vec<PathBuf>, LintLicenseError> {
    let canonical_root = fs::canonicalize(root).map_err(|err| LintLicenseError::Workspace {
        message: format!("failed to canonicalize directory {}: {err}", root.display()),
    })?;
    let mut files = Vec::new();
    let mut visited = HashSet::from([canonical_root.clone()]);
    walk(root, &canonical_root, &mut visited, &mut files)?;
    Ok(files)
}

/// Walk `dir` recursively, appending `.rs` files found to `files`.
fn walk(
    dir: &Path,
    canonical_root: &Path,
    visited: &mut HashSet<PathBuf>,
    files: &mut Vec<PathBuf>,
) -> Result<(), LintLicenseError> {
    let entries = fs::read_dir(dir).map_err(|err| LintLicenseError::Workspace {
        message: format!("failed to read directory {}: {err}", dir.display()),
    })?;

    for entry in entries {
        let entry = entry.map_err(|err| LintLicenseError::Workspace {
            message: format!("failed to read directory entry in {}: {err}", dir.display()),
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|err| LintLicenseError::Workspace {
            message: format!("failed to inspect workspace entry {}: {err}", path.display()),
        })?;

        if file_type.is_dir()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| SKIPPED_DIRS.contains(&name) || name.starts_with('.'))
        {
            continue;
        }

        let canonical_path = fs::canonicalize(&path).map_err(|err| LintLicenseError::Workspace {
            message: format!("failed to canonicalize workspace entry {}: {err}", path.display()),
        })?;
        if !canonical_path.starts_with(canonical_root) {
            return Err(LintLicenseError::Workspace {
                message: format!(
                    "workspace entry {} resolves outside workspace root {}",
                    path.display(),
                    canonical_root.display()
                ),
            });
        }

        if canonical_path.is_dir() {
            if visited.insert(canonical_path.clone()) {
                walk(&canonical_path, canonical_root, visited, files)?;
            }
        } else if canonical_path.extension().is_some_and(|ext| ext == "rs") {
            files.push(canonical_path);
        }
    }

    Ok(())
}

/// Locate the workspace root directory.
///
/// Uses `CARGO_MANIFEST_DIR` (set by cargo for the xtask crate) and
/// navigates one level up to reach the workspace root.
fn workspace_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    Path::new(&manifest_dir)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_owned()
}

/// Resolve workspace member directories from the root `Cargo.toml`.
fn workspace_member_dirs(root: &Path) -> Result<Vec<PathBuf>, LintLicenseError> {
    let cargo_toml_path = root.join("Cargo.toml");
    let cargo_toml = fs::read_to_string(&cargo_toml_path).map_err(|err| LintLicenseError::Workspace {
        message: format!("failed to read {}: {err}", cargo_toml_path.display()),
    })?;

    let members = extract_workspace_members(&cargo_toml).ok_or_else(|| LintLicenseError::Workspace {
        message: format!("failed to parse workspace members from {}", cargo_toml_path.display()),
    })?;

    let canonical_root = fs::canonicalize(root).map_err(|err| LintLicenseError::Workspace {
        message: format!("failed to canonicalize workspace root {}: {err}", root.display()),
    })?;

    let mut member_dirs = Vec::with_capacity(members.len());
    for member in members {
        if !is_safe_workspace_member(&member) {
            return Err(LintLicenseError::Workspace {
                message: format!(
                    "invalid workspace member {member:?}: path must be relative and must not contain '..'"
                ),
            });
        }

        let member_pattern = canonical_root.join(&member);
        let member_pattern = member_pattern.to_string_lossy();
        let matches = glob(&member_pattern).map_err(|err| LintLicenseError::Workspace {
            message: format!("failed to expand workspace member {member:?}: {err}"),
        })?;

        let mut matched_member = false;
        for matched in matches {
            matched_member = true;
            let member_path = matched.map_err(|err| LintLicenseError::Workspace {
                message: format!("failed to expand workspace member {member:?}: {err}"),
            })?;
            let canonical_member = fs::canonicalize(&member_path).map_err(|err| LintLicenseError::Workspace {
                message: format!(
                    "failed to canonicalize workspace member {}: {err}",
                    member_path.display()
                ),
            })?;

            if !canonical_member.starts_with(&canonical_root) {
                return Err(LintLicenseError::Workspace {
                    message: format!(
                        "workspace member {member:?} resolves outside workspace root {}",
                        canonical_root.display()
                    ),
                });
            }

            member_dirs.push(canonical_member);
        }

        if !matched_member {
            return Err(LintLicenseError::Workspace {
                message: format!("failed to canonicalize workspace member {member_pattern}: path does not exist"),
            });
        }
    }

    Ok(member_dirs)
}

/// Returns `true` when `member` is a relative path without parent-directory components.
fn is_safe_workspace_member(member: &str) -> bool {
    let path = Path::new(member);
    !path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
}

/// Extract `[workspace].members` paths from a `Cargo.toml` string.
fn extract_workspace_members(content: &str) -> Option<Vec<String>> {
    let document = content.parse::<toml::Value>().ok()?;
    let members = document.get("workspace")?.get("members")?.as_array()?;
    let members = members.iter().map(toml::Value::as_str).collect::<Option<Vec<_>>>()?;

    (!members.is_empty()).then_some(members.into_iter().map(str::to_owned).collect())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn run_succeeds_on_current_workspace() {
        run(Args);
    }

    #[test]
    fn workspace_root_points_at_workspace_directory() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(workspace_root(), manifest_dir.parent().unwrap());
    }

    #[test]
    fn workspace_member_dirs_reads_current_workspace() {
        let members = workspace_member_dirs(&workspace_root()).unwrap();
        assert!(members.iter().any(|path| path.ends_with("xtask")));
        assert!(members.iter().any(|path| path.ends_with("libinjection-rs")));
    }

    #[test]
    fn workspace_member_dirs_errors_when_cargo_toml_is_missing() {
        let root = tempfile_dir();
        let err = workspace_member_dirs(&root).unwrap_err();
        assert!(matches!(
            err,
            LintLicenseError::Workspace { message } if message.starts_with("failed to read")
        ));
    }

    #[test]
    fn workspace_member_dirs_errors_when_members_are_missing() {
        let root = tempfile_dir();
        fs::write(root.join("Cargo.toml"), "[workspace]\nresolver = \"3\"\n").unwrap();
        let err = workspace_member_dirs(&root).unwrap_err();
        assert_eq!(
            err,
            LintLicenseError::Workspace {
                message: format!(
                    "failed to parse workspace members from {}",
                    root.join("Cargo.toml").display()
                ),
            }
        );
    }

    #[test]
    fn workspace_member_dirs_rejects_parent_dir_components() {
        let root = tempfile_dir();
        fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"../outside\"]\n").unwrap();
        let err = workspace_member_dirs(&root).unwrap_err();
        assert!(matches!(
            err,
            LintLicenseError::Workspace { message } if message.contains("invalid workspace member")
        ));
    }

    #[test]
    fn workspace_member_dirs_rejects_absolute_members() {
        let root = tempfile_dir();
        fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"/tmp/crate-a\"]\n").unwrap();
        let err = workspace_member_dirs(&root).unwrap_err();
        assert!(matches!(
            err,
            LintLicenseError::Workspace { message } if message.contains("invalid workspace member")
        ));
    }

    #[test]
    fn workspace_member_dirs_errors_when_member_directory_is_missing() {
        let root = tempfile_dir();
        fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"missing-crate\"]\n").unwrap();
        let err = workspace_member_dirs(&root).unwrap_err();
        assert!(matches!(
            err,
            LintLicenseError::Workspace { message } if message.starts_with("failed to canonicalize workspace member")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_member_dirs_rejects_members_outside_workspace_root() {
        use std::os::unix::fs::symlink;

        let root = tempfile_dir();
        let outside = tempfile_dir();
        symlink(&outside, root.join("escape")).unwrap();
        fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"escape\"]\n").unwrap();

        let err = workspace_member_dirs(&root).unwrap_err();
        assert!(matches!(
            err,
            LintLicenseError::Workspace { message } if message.contains("resolves outside workspace root")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn collect_violations_rejects_nested_symlinks_outside_workspace() {
        use std::os::unix::fs::symlink;

        let root = write_temp_workspace(&["crate-a"], &[("crate-a/src/lib.rs", LICENSE_HEADER)]);
        let outside = tempfile_dir();
        fs::write(outside.join("escape.rs"), LICENSE_HEADER).unwrap();
        symlink(&outside, root.join("crate-a/escape")).unwrap();

        let err = collect_violations(&root).unwrap_err();
        assert!(matches!(
            err,
            LintLicenseError::Workspace { message }
                if message.contains("workspace entry") && message.contains("outside workspace root")
        ));
    }

    #[test]
    fn collect_violations_errors_on_invalid_utf8_file() {
        let root = write_temp_workspace(&["crate-a"], &[("crate-a/src/lib.rs", LICENSE_HEADER)]);
        let path = root.join("crate-a/src/lib.rs");
        fs::write(&path, [0xFF]).unwrap();

        let err = collect_violations(&root).unwrap_err();
        assert!(matches!(err, LintLicenseError::ReadFile { .. }));
    }

    #[test]
    fn execute_lint_reports_violations_without_exiting() {
        let root = write_temp_workspace(&["crate-a"], &[("crate-a/src/lib.rs", "fn main() {}\n")]);
        let err = execute_lint(&root).unwrap_err();
        assert!(matches!(err, LintLicenseError::Violations(_)));
    }

    #[test]
    fn execute_lint_reports_workspace_errors_without_exiting() {
        let root = tempfile_dir();
        let err = execute_lint(&root).unwrap_err();
        assert!(matches!(err, LintLicenseError::Workspace { .. }));
    }

    #[test]
    fn walk_returns_empty_for_missing_directory() {
        let dir = tempfile_dir().join("missing");
        assert!(matches!(find_rs_files(&dir), Err(LintLicenseError::Workspace { .. })));
    }

    #[test]
    fn is_safe_workspace_member_accepts_relative_paths() {
        assert!(is_safe_workspace_member("crate-a"));
        assert!(is_safe_workspace_member("crates/nested"));
    }

    #[test]
    fn is_safe_workspace_member_rejects_unsafe_paths() {
        assert!(!is_safe_workspace_member("/tmp/crate-a"));
        assert!(!is_safe_workspace_member("../outside"));
        assert!(!is_safe_workspace_member("crate-a/../../outside"));
    }

    #[test]
    fn lint_license_headers_ok_on_valid_temp_workspace() {
        let root = write_temp_workspace(&["crate-a"], &[("crate-a/src/lib.rs", LICENSE_HEADER)]);
        assert_eq!(lint_license_headers(&root), Ok(()));
    }

    #[test]
    fn collect_violations_reports_missing_headers() {
        let root = write_temp_workspace(
            &["crate-a"],
            &[
                ("crate-a/src/lib.rs", "fn main() {}\n"),
                ("crate-a/src/good.rs", LICENSE_HEADER),
            ],
        );
        let violations = collect_violations(&root).unwrap();
        assert_eq!(violations, vec![root.join("crate-a/src/lib.rs")]);
    }

    #[test]
    fn lint_license_headers_errors_on_violations() {
        let root = write_temp_workspace(&["crate-a"], &[("crate-a/src/lib.rs", "fn main() {}\n")]);
        assert_eq!(
            lint_license_headers(&root),
            Err(LintLicenseError::Violations(vec![root.join("crate-a/src/lib.rs")]))
        );
    }

    #[test]
    fn file_with_header_passes() {
        let dir = tempfile_dir();
        fs::write(dir.join("good.rs"), format!("{LICENSE_HEADER}\nfn main() {{}}\n")).unwrap();
        assert!(
            find_rs_files(&dir)
                .unwrap()
                .iter()
                .all(|f| fs::read_to_string(f).unwrap().starts_with(LICENSE_HEADER))
        );
    }

    #[test]
    fn file_missing_header_fails() {
        let dir = tempfile_dir();
        fs::write(dir.join("bad.rs"), "fn main() {}\n").unwrap();
        let content = fs::read_to_string(dir.join("bad.rs")).unwrap();
        assert!(!content.starts_with(LICENSE_HEADER));
    }

    #[test]
    fn skipped_dirs_are_not_walked() {
        let dir = tempfile_dir();
        let target_dir = dir.join("target");
        fs::create_dir(&target_dir).unwrap();
        fs::write(target_dir.join("generated.rs"), "fn main() {}\n").unwrap();
        assert!(find_rs_files(&dir).unwrap().is_empty());
    }

    #[test]
    fn walk_finds_nested_rs_files() {
        let dir = tempfile_dir();
        let nested = dir.join("src/nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("mod.rs"), "fn nested() {}\n").unwrap();
        assert_eq!(find_rs_files(&dir).unwrap(), vec![nested.join("mod.rs")]);
    }

    #[cfg(unix)]
    #[test]
    fn walk_skips_directory_symlinks_to_ancestors() {
        use std::os::unix::fs::symlink;

        let dir = tempfile_dir();
        let nested = dir.join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("mod.rs"), "fn nested() {}\n").unwrap();
        symlink(&nested, nested.join("ancestor")).unwrap();

        assert_eq!(find_rs_files(&dir).unwrap(), vec![nested.join("mod.rs")]);
    }

    #[test]
    fn walk_skips_hidden_directories() {
        let dir = tempfile_dir();
        let hidden = dir.join(".hidden");
        fs::create_dir(&hidden).unwrap();
        fs::write(hidden.join("secret.rs"), "fn secret() {}\n").unwrap();
        assert!(find_rs_files(&dir).unwrap().is_empty());
    }

    #[test]
    fn walk_ignores_non_rs_files() {
        let dir = tempfile_dir();
        fs::write(dir.join("notes.txt"), "not rust\n").unwrap();
        assert!(find_rs_files(&dir).unwrap().is_empty());
    }

    #[test]
    fn extract_workspace_members_parses_multiline_array() {
        let cargo_toml = r#"
[workspace]
members = [
    "libinjection-rs",
    "xtask",
]
"#;
        assert_eq!(
            extract_workspace_members(cargo_toml),
            Some(vec!["libinjection-rs".to_owned(), "xtask".to_owned(),])
        );
    }

    #[test]
    fn extract_workspace_members_parses_inline_array() {
        let cargo_toml = "[workspace]\nmembers = [\"crate-a\", \"crate-b\"] # comment\n";
        assert_eq!(
            extract_workspace_members(cargo_toml),
            Some(vec!["crate-a".to_owned(), "crate-b".to_owned()])
        );
    }

    #[test]
    fn workspace_member_dirs_expands_member_globs() {
        let root = tempfile_dir();
        fs::create_dir_all(root.join("crates/crate-a")).unwrap();
        fs::create_dir_all(root.join("crates/crate-b")).unwrap();
        fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"crates/*\"]\n").unwrap();

        let members = workspace_member_dirs(&root).unwrap();
        assert_eq!(members.len(), 2);
        assert!(members.iter().any(|path| path.ends_with("crate-a")));
        assert!(members.iter().any(|path| path.ends_with("crate-b")));
    }

    fn write_temp_workspace(members: &[&str], files: &[(&str, &str)]) -> PathBuf {
        let root = tempfile_dir();
        let member_list = members
            .iter()
            .map(|member| format!("\"{member}\""))
            .collect::<Vec<_>>()
            .join(", ");
        fs::write(
            root.join("Cargo.toml"),
            format!("[workspace]\nmembers = [{member_list}]\n"),
        )
        .unwrap();

        for (relative_path, contents) in files {
            let path = root.join(relative_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, contents).unwrap();
        }

        root
    }

    fn tempfile_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("xtask-lint-license-test-{}-{id}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
