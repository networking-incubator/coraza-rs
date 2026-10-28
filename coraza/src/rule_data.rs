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

//! Read-only sources for the files a rule compilation needs.
//!
//! Compiling `SecLang` can read files: `Include` follows a configuration file,
//! `@pmFromFile`/`@pmf` and `@ipMatchFromFile`/`@ipMatchF` load data lists, and
//! `@validateSchema` loads a JSON Schema. [`FileSystem`] reads those files from
//! the process filesystem and is the default, so a parser built with
//! [`Parser::new`](crate::seclang::Parser::new) behaves as it always has.
//!
//! An embedder without a usable filesystem, such as an Envoy Proxy-Wasm filter
//! on WASI where `path_open` and `fd_read` return `ENOTSUP`, can implement
//! [`RuleData`] over its own storage instead and install it with
//! [`Parser::with_rule_data`](crate::seclang::Parser::with_rule_data). [`Memory`]
//! is such a source: it serves a map supplied by the embedder, so includes and
//! file-based operators compile without any filesystem access.

use std::{
    collections::BTreeMap,
    io,
    path::{Component, Path, PathBuf},
};

/// Longest glob pattern or stored name this module will process.
const MAX_PATH_BYTES: usize = 4096;

/// Most `/`-separated components a glob pattern or stored name may have.
const MAX_PATH_COMPONENTS: usize = 64;

/// Component matching for [`Memory::glob`]: case-sensitive, and `*`/`?` stay
/// inside one path component, like the filesystem glob's per-component walk.
const MATCH_OPTIONS: glob::MatchOptions = glob::MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

/// Read-only access to the files a rule compilation needs.
///
/// Paths passed to [`read`](RuleData::read) and
/// [`glob`](RuleData::glob) are already resolved against the configuration
/// directory, exactly as the filesystem source would open them. Callers do not
/// otherwise confine them: a file-operator argument is joined onto the base
/// directory with any `..` or absolute component intact, so an implementation
/// that serves storage other than the process filesystem MUST reject `..`
/// components and absolute paths itself. [`FileSystem`] performs no confinement
/// of its own and leaves it to callers that need it; [`Memory`] reports such a
/// name as [`io::ErrorKind::PermissionDenied`].
pub trait RuleData: Send + Sync {
    /// Read the file at `path`.
    ///
    /// # Errors
    ///
    /// Returns the error that prevented reading; [`io::ErrorKind::NotFound`]
    /// means the source has no such file, [`io::ErrorKind::InvalidInput`] a
    /// malformed name, and [`io::ErrorKind::PermissionDenied`] a name that
    /// leaves the source's root.
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;

    /// Expand the glob `pattern`, in deterministic sorted order.
    ///
    /// A pattern that matches nothing returns an empty list; the caller reports
    /// that as an error.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] when the pattern is malformed,
    /// and another error when it cannot be expanded.
    fn glob(&self, pattern: &str) -> io::Result<Vec<PathBuf>>;

    /// The underlying [`FileSystem`], when this source is exactly it.
    ///
    /// A caller that needs the process filesystem's own confinement uses this
    /// to select its filesystem path. `@validateSchema` branches on `Some` to
    /// keep its descriptor-based, canonical-path-confined read, which never
    /// calls [`read`](RuleData::read); every other source is read through
    /// [`read`](RuleData::read), and a source that performs real filesystem
    /// access must apply its own containment. It returns the source itself
    /// rather than a boolean so that only the real [`FileSystem`] can be
    /// returned: a wrapper cannot claim the disk confinement it does not
    /// implement.
    fn as_file_system(&self) -> Option<&FileSystem> {
        None
    }
}

/// The process filesystem, the default [`RuleData`] source.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileSystem;

impl RuleData for FileSystem {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn glob(&self, pattern: &str) -> io::Result<Vec<PathBuf>> {
        let paths =
            glob::glob(pattern).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        // Keep the glob error's own text, which names the directory it failed on.
        paths
            .map(|entry| entry.map_err(|error| io::Error::other(error.to_string())))
            .collect()
    }

    fn as_file_system(&self) -> Option<&FileSystem> {
        Some(self)
    }
}

/// Rule data held in memory, for embedders without a filesystem.
///
/// Names are normalized relative paths, separated by `/` and without a leading
/// `./` or a repeated separator. [`Memory::new`] normalizes each supplied name,
/// and when two names normalize to the same value the later pair wins. A name
/// with no components (`""` or `.`) is rejected by both
/// [`read`](RuleData::read) and [`glob`](RuleData::glob) with
/// [`io::ErrorKind::InvalidInput`].
///
/// [`Memory::glob`] follows filesystem glob semantics: `*` and `?` do not
/// cross `/`, `**` matches zero or more directories, and results follow the
/// same directory walk order as [`glob::glob`]. Patterns are normalized like
/// names, so `./rules/*.conf`, `rules//*.conf` and `rules/./*.conf` all mean
/// `rules/*.conf`. A pattern longer than 4096 bytes or with more than 64
/// components is rejected with [`io::ErrorKind::InvalidInput`], and stored
/// names longer than 4096 bytes are not matched.
///
/// A pattern only produces names [`read`](RuleData::read) accepts, so one
/// unusable stored name cannot break a recursive include: an absolute name, one
/// containing `..`, one with no components and one with more than 64 components
/// are rejected by `read` and never matched, and an oversized name is readable
/// by its exact name but never matched.
#[derive(Debug, Clone, Default)]
pub struct Memory {
    /// File name to contents.
    files: BTreeMap<String, Vec<u8>>,
}

impl Memory {
    /// Build a source from `name`/`contents` pairs.
    ///
    /// Names are normalized by dropping `.` components and repeated separators.
    /// When two names normalize to the same value, the later pair wins. A name
    /// that is absolute, contains `..`, or has more than 64 components is kept
    /// as given and rejected when it is read.
    pub fn new(files: impl IntoIterator<Item = (String, Vec<u8>)>) -> Self {
        Self {
            files: files
                .into_iter()
                .map(|(name, contents)| (normalize_name(Path::new(&name)).unwrap_or(name), contents))
                .collect(),
        }
    }

    /// Build the tree the glob walk searches.
    ///
    /// A stored name that [`read`](RuleData::read) rejects, or that is longer
    /// than [`MAX_PATH_BYTES`], is left out, so no pattern can produce a name
    /// the same source cannot read; the name stays readable by its exact name
    /// when `read` accepts it.
    fn tree(&self) -> Dir<'_> {
        let mut root = Dir::default();
        for name in self.files.keys() {
            if name.len() > MAX_PATH_BYTES || checked_name(Path::new(name)).is_err() {
                continue;
            }
            let mut dir = &mut root;
            for part in name.split('/') {
                dir = dir.entries.entry(part).or_default();
            }
        }
        root
    }
}

impl RuleData for Memory {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let name = checked_name(path)?;
        self.files
            .get(&name)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("rule data has no file '{name}'")))
    }

    /// Expand `pattern` over the stored names.
    ///
    /// The order reproduces [`glob::glob`]'s directory walk, because include
    /// order is semantic (default actions, duplicate ids, evaluation order):
    /// entries of each directory are sorted by name and a matched directory is
    /// entered before the next sibling. For `rules/Z/z.conf`,
    /// `rules/a/b.conf`, `rules/a.conf` and `rules/b.conf`, `rules/**/*.conf`
    /// yields `Z/z.conf`, `a/b.conf`, `a.conf`, `b.conf`.
    ///
    /// A directory that matches is returned like any other entry, as the
    /// filesystem glob does; a later [`read`](RuleData::read) of it then fails,
    /// so an `Include` of a directory is an error for both sources. A pattern
    /// with a trailing separator, such as `rules/*/`, matches directories only
    /// on both sources. An empty directory cannot be stored, so it is the one
    /// directory the memory result omits. Unlike the disk source, `.` and `..`
    /// entries are never returned: a pattern like `rules/.*` matches a stored
    /// `rules/.hidden` but not the special directory entries `glob` emits,
    /// because `Memory` never exposes traversable special entries.
    fn glob(&self, pattern: &str) -> io::Result<Vec<PathBuf>> {
        if pattern.len() > MAX_PATH_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("glob pattern is longer than {MAX_PATH_BYTES} bytes"),
            ));
        }
        // A trailing separator makes the filesystem glob require a directory;
        // the normalized pattern below has lost it.
        let require_dir = pattern.ends_with('/') || pattern.ends_with(std::path::MAIN_SEPARATOR);
        let pattern = checked_name(Path::new(pattern))?;
        let segments = pattern
            .split('/')
            .map(Segment::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let mut matches = Vec::new();
        walk(&self.tree(), &segments, require_dir, &mut matches);
        Ok(matches)
    }
}

/// One `/`-separated pattern component; `None` is the recursive `**`.
struct Segment {
    /// The component to match against one entry name, or `None` for `**`.
    pattern: Option<glob::Pattern>,
}

impl Segment {
    /// Compile one pattern component; `**` is kept as the recursive wildcard.
    fn new(component: &str) -> Result<Self, glob::PatternError> {
        if component == "**" {
            return Ok(Self { pattern: None });
        }
        glob::Pattern::new(component).map(|pattern| Self { pattern: Some(pattern) })
    }

    /// Whether this component is `**`, which also matches directories.
    fn is_recursive(&self) -> bool {
        self.pattern.is_none()
    }

    /// Match one entry name; `**` is handled by the walk, not here.
    fn matches(&self, name: &str) -> bool {
        self.pattern
            .as_ref()
            .is_some_and(|pattern| pattern.matches_with(name, MATCH_OPTIONS))
    }
}

/// The stored names as a directory tree, for the [`Memory::glob`] walk.
#[derive(Debug, Default)]
struct Dir<'a> {
    /// Entries by name; the map keeps each directory sorted like `glob`'s walk.
    entries: BTreeMap<&'a str, Dir<'a>>,
}

/// Walk `root` following `segments`, appending matched names in glob order.
///
/// `require_dir` rejects a matched leaf, as a trailing separator does on the
/// filesystem; a node with children is the memory tree's directory.
fn walk(root: &Dir<'_>, segments: &[Segment], require_dir: bool, matches: &mut Vec<PathBuf>) {
    let mut todo: Vec<(PathBuf, &Dir<'_>, usize)> = Vec::new();
    push_children(&mut todo, root, Path::new(""), 0);
    while let Some((path, dir, mut idx)) = todo.pop() {
        if segments.get(idx).is_some_and(Segment::is_recursive) {
            let mut recursive = idx;
            while segments.get(recursive + 1).is_some_and(Segment::is_recursive) {
                recursive += 1;
            }
            if dir.entries.is_empty() {
                // `**` cannot consume a file as a directory.
                if recursive + 1 == segments.len() {
                    continue;
                }
            } else {
                // Enter the directory's children, then let `**` also consume
                // zero directories here, exactly as `glob` does.
                push_children(&mut todo, dir, &path, recursive);
                if recursive + 1 == segments.len() {
                    matches.push(path);
                    continue;
                }
            }
            idx = recursive + 1;
        }
        // The tree stores `/`-separated names, so the last component is the name.
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(segment) = segments.get(idx) else {
            continue;
        };
        if !segment.matches(name) {
            continue;
        }
        if idx + 1 == segments.len() {
            if !require_dir || !dir.entries.is_empty() {
                matches.push(path);
            }
        } else {
            push_children(&mut todo, dir, &path, idx + 1);
        }
    }
}

/// Push `dir`'s entries deepest name first, so the stack pops them in order.
fn push_children<'a>(todo: &mut Vec<(PathBuf, &'a Dir<'a>, usize)>, dir: &'a Dir<'a>, path: &Path, idx: usize) {
    for (name, child) in dir.entries.iter().rev() {
        todo.push((path.join(name), child, idx));
    }
}

/// Read `path` through `data` as UTF-8 text.
///
/// Invalid bytes fail with the error [`std::fs::read_to_string`] reports, so the
/// message a caller adds stays the same whichever source served the file.
pub(crate) fn read_to_string(data: &dyn RuleData, path: &Path) -> io::Result<String> {
    let bytes = data.read(path)?;
    match String::from_utf8(bytes) {
        Ok(text) => Ok(text),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        )),
    }
}

/// `path` as a stored name: `/`-separated relative components.
///
/// Returns `PermissionDenied` for an absolute path or one with a `..`
/// component, which would leave the source's root, and `InvalidInput` for a
/// component that is not UTF-8 or for a path with more than
/// [`MAX_PATH_COMPONENTS`] components.
fn normalize_name(path: &Path) -> io::Result<String> {
    let mut name = String::new();
    let mut components = 0;
    for component in path.components() {
        match component {
            Component::CurDir => {},
            Component::Normal(part) => {
                components += 1;
                if components > MAX_PATH_COMPONENTS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "rule data path has more than {MAX_PATH_COMPONENTS} components: {}",
                            path.display()
                        ),
                    ));
                }
                let part = part.to_str().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("rule data path is not valid UTF-8: {}", path.display()),
                    )
                })?;
                if !name.is_empty() {
                    name.push('/');
                }
                name.push_str(part);
            },
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("rule data path escapes the rule-data namespace: {}", path.display()),
                ));
            },
            Component::Prefix(_) | Component::RootDir => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("rule data path is absolute: {}", path.display()),
                ));
            },
        }
    }
    Ok(name)
}

/// [`normalize_name`], rejecting a name with no components (`""` or `.`).
fn checked_name(path: &Path) -> io::Result<String> {
    let name = normalize_name(path)?;
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("rule data path is empty: {}", path.display()),
        ));
    }
    Ok(name)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "rule data tests use fixed names")]
mod tests {
    use std::{
        io,
        path::{Path, PathBuf},
    };

    use super::{FileSystem, MAX_PATH_BYTES, MAX_PATH_COMPONENTS, Memory, RuleData as _};

    /// Names from a glob result, for readable assertions.
    fn names(paths: Vec<PathBuf>) -> Vec<String> {
        paths
            .into_iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn reads_named_files_and_normalizes_dot_components() {
        let data = Memory::new([
            ("rules/main.conf".to_owned(), b"main".to_vec()),
            ("./rules/extra.conf".to_owned(), b"extra".to_vec()),
            ("rules/main.conf".to_owned(), b"main again".to_vec()),
        ]);

        assert_eq!(data.read(Path::new("rules/main.conf")).unwrap(), b"main again");
        assert_eq!(data.read(Path::new("./rules/extra.conf")).unwrap(), b"extra");
        assert_eq!(data.read(Path::new("./rules//./extra.conf")).unwrap(), b"extra");
    }

    #[test]
    fn unknown_files_are_not_found() {
        let data = Memory::default();

        assert_eq!(
            data.read(Path::new("missing.conf")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn traversal_and_absolute_paths_are_permission_denied() {
        let data = Memory::new([("secret.conf".to_owned(), b"secret".to_vec())]);

        let error = data.read(Path::new("../secret.conf")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("escapes the rule-data namespace"), "{error}");

        let error = data.read(Path::new("rules/../../secret.conf")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("escapes the rule-data namespace"), "{error}");

        for name in ["/secret.conf", "//secret.conf"] {
            let error = data.read(Path::new(name)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{name}");
            assert!(error.to_string().contains("is absolute"), "{error}");
        }
    }

    #[test]
    fn empty_names_are_invalid_input() {
        let data = Memory::new([(String::new(), b"empty".to_vec()), (".".to_owned(), b"dot".to_vec())]);

        for name in ["", "."] {
            assert_eq!(
                data.read(Path::new(name)).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "read({name:?})"
            );
        }
        for pattern in ["", "."] {
            assert_eq!(
                data.glob(pattern).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "glob({pattern:?})"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_components_are_invalid_input() {
        use std::os::unix::ffi::OsStrExt as _;

        let data = Memory::new([("rules/ok.conf".to_owned(), Vec::new())]);
        let path = std::ffi::OsStr::from_bytes(b"rules/\xff.conf");
        let error = data.read(Path::new(path)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("not valid UTF-8"), "{error}");
    }

    #[test]
    fn glob_normalizes_patterns_like_read() {
        let data = Memory::new([
            ("rules/10-a.conf".to_owned(), Vec::new()),
            ("rules/nested/20-b.conf".to_owned(), Vec::new()),
        ]);

        let expected = data.glob("rules/*.conf").unwrap();
        assert_eq!(expected, [PathBuf::from("rules/10-a.conf")]);
        for pattern in ["./rules/*.conf", "rules//*.conf", "rules/./*.conf"] {
            assert_eq!(data.glob(pattern).unwrap(), expected, "{pattern}");
        }
    }

    #[test]
    fn glob_and_read_reject_escaping_patterns() {
        let data = Memory::default();

        for pattern in ["/rules/*.conf", "../rules/*.conf", "rules/../*.conf"] {
            assert_eq!(
                data.glob(pattern).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied,
                "{pattern}"
            );
        }
    }

    #[test]
    fn glob_is_sorted_and_star_stays_in_a_directory() {
        let data = Memory::new([
            ("rules/20-b.conf".to_owned(), Vec::new()),
            ("rules/10-a.conf".to_owned(), Vec::new()),
            ("rules/nested/c.conf".to_owned(), Vec::new()),
            ("rules/notes.txt".to_owned(), Vec::new()),
        ]);

        assert_eq!(
            names(data.glob("rules/*.conf").unwrap()),
            ["rules/10-a.conf", "rules/20-b.conf"],
            "matches must be sorted and `*` must not cross `/`"
        );
        assert_eq!(
            names(data.glob("rules/**/*.conf").unwrap()),
            ["rules/10-a.conf", "rules/20-b.conf", "rules/nested/c.conf"]
        );
        assert!(data.glob("rules/*.xml").unwrap().is_empty());
    }

    #[test]
    fn glob_order_is_deterministic() {
        let data = Memory::new([
            ("rules/c.conf".to_owned(), Vec::new()),
            ("rules/a.conf".to_owned(), Vec::new()),
            ("rules/b.conf".to_owned(), Vec::new()),
        ]);

        let first = names(data.glob("rules/*.conf").unwrap());
        let second = names(data.glob("rules/*.conf").unwrap());
        assert_eq!(first, ["rules/a.conf", "rules/b.conf", "rules/c.conf"]);
        assert_eq!(first, second, "repeated globs must keep the same order");
    }

    /// A tree where `rules/a` (directory) shares a prefix with `rules/a.conf`.
    const PREFIX_TREE: [&str; 4] = ["rules/Z/z.conf", "rules/a/b.conf", "rules/a.conf", "rules/b.conf"];

    /// Write [`PREFIX_TREE`] to a fresh temporary directory.
    fn disk_tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for name in PREFIX_TREE {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"").unwrap();
        }
        dir
    }

    /// The disk source's sequence for `pattern`, relative to `dir`.
    fn disk_glob(dir: &Path, pattern: &str) -> Vec<String> {
        let pattern = dir.join(pattern).to_string_lossy().into_owned();
        FileSystem
            .glob(&pattern)
            .unwrap()
            .iter()
            .map(|path| path.strip_prefix(dir).unwrap().to_string_lossy().into_owned())
            .collect()
    }

    fn memory_tree() -> Memory {
        Memory::new(PREFIX_TREE.map(|name| (name.to_owned(), Vec::new())))
    }

    #[test]
    fn glob_walk_order_matches_the_filesystem() {
        let dir = disk_tree();
        let data = memory_tree();

        for pattern in ["rules/**/*.conf", "rules/*.conf", "rules/*", "rules/**"] {
            assert_eq!(
                names(data.glob(pattern).unwrap()),
                disk_glob(dir.path(), pattern),
                "{pattern}"
            );
        }
        assert_eq!(
            names(data.glob("rules/**/*.conf").unwrap()),
            ["rules/Z/z.conf", "rules/a/b.conf", "rules/a.conf", "rules/b.conf"],
            "entries sort per directory, and a directory is entered before the next sibling"
        );
    }

    #[test]
    fn glob_returns_matching_directories_that_read_rejects() {
        let dir = disk_tree();
        let data = memory_tree();

        let disk = disk_glob(dir.path(), "rules/*");
        assert_eq!(names(data.glob("rules/*").unwrap()), disk);
        assert_eq!(disk, ["rules/Z", "rules/a", "rules/a.conf", "rules/b.conf"]);

        for name in ["rules/Z", "rules/a"] {
            assert!(
                FileSystem.read(&dir.path().join(name)).is_err(),
                "a directory must not read as a file on disk: {name}"
            );
            assert!(
                data.read(Path::new(name)).is_err(),
                "a directory must not read as a file in memory: {name}"
            );
        }
    }

    #[test]
    fn trailing_recursive_glob_matches_directories_in_walk_order() {
        let dir = disk_tree();
        let data = memory_tree();

        let disk = disk_glob(dir.path(), "rules/**");
        assert_eq!(disk, ["rules/Z", "rules/a"]);
        assert_eq!(names(data.glob("rules/**").unwrap()), disk);

        for name in &disk {
            assert!(FileSystem.read(&dir.path().join(name)).is_err(), "{name}");
            assert!(data.read(Path::new(name)).is_err(), "{name}");
        }
    }

    #[test]
    fn trailing_separator_matches_only_directories() {
        let dir = disk_tree();
        let data = memory_tree();

        let disk = disk_glob(dir.path(), "rules/*/");
        assert_eq!(disk, ["rules/Z", "rules/a"], "disk matches directories only");
        assert_eq!(names(data.glob("rules/*/").unwrap()), disk);

        for name in &disk {
            assert!(
                FileSystem.read(&dir.path().join(name)).is_err(),
                "a directory must not read as a file on disk: {name}"
            );
            assert!(
                data.read(Path::new(name)).is_err(),
                "a directory must not read as a file in memory: {name}"
            );
        }
    }

    #[test]
    fn glob_rejects_an_oversized_pattern_and_skips_oversized_names() {
        let long_name = "a".repeat(MAX_PATH_BYTES + 1);
        let data = Memory::new([(long_name, Vec::new())]);

        assert!(
            data.glob("*").unwrap().is_empty(),
            "an oversized stored name must not match"
        );

        let pattern = "*".repeat(60_000);
        assert_eq!(
            data.glob(&pattern).unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
            "an oversized pattern must be rejected before matching"
        );
    }

    #[test]
    fn glob_never_returns_a_name_read_rejects() {
        let data = Memory::new([
            ("../secret.conf".to_owned(), b"secret".to_vec()),
            ("/etc/passwd".to_owned(), b"passwd".to_vec()),
            ("rules/a.conf".to_owned(), b"rules".to_vec()),
        ]);

        for pattern in ["**/*", "**"] {
            let got = names(data.glob(pattern).unwrap());
            assert!(
                got.iter().all(|name| name == "rules" || name == "rules/a.conf"),
                "{pattern} must not return a name read rejects: {got:?}"
            );
        }
        assert_eq!(names(data.glob("**/*").unwrap()), ["rules", "rules/a.conf"]);
        assert_eq!(names(data.glob("**").unwrap()), ["rules"]);
        assert_eq!(
            data.read(Path::new("../secret.conf")).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn too_many_path_components_are_invalid_input() {
        let accepted = vec!["a"; MAX_PATH_COMPONENTS].join("/");
        let rejected = vec!["a"; MAX_PATH_COMPONENTS + 1].join("/");
        let data = Memory::new([(accepted.clone(), b"ok".to_vec()), (rejected.clone(), b"no".to_vec())]);

        assert_eq!(data.read(Path::new(&accepted)).unwrap(), b"ok");
        assert_eq!(names(data.glob(&accepted).unwrap()), [accepted]);
        assert!(
            !names(data.glob("**/*").unwrap()).contains(&rejected),
            "a stored name over the component budget must not be matched"
        );

        for error in [
            data.read(Path::new(&rejected)).unwrap_err(),
            data.glob(&rejected).unwrap_err(),
        ] {
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(
                error.to_string().contains("more than 64 components"),
                "the error must name the budget: {error}"
            );
        }
    }

    #[test]
    fn filesystem_reads_and_globs_the_disk() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b.conf"), b"b").unwrap();
        std::fs::write(dir.path().join("a.conf"), b"a").unwrap();
        let pattern = dir.path().join("*.conf").to_string_lossy().into_owned();

        let files = FileSystem.glob(&pattern).unwrap();
        assert_eq!(files.len(), 2);
        assert!(
            files.first().unwrap().ends_with("a.conf"),
            "glob must be sorted: {files:?}"
        );
        assert_eq!(FileSystem.read(&dir.path().join("a.conf")).unwrap(), b"a");
        assert_eq!(
            FileSystem.read(&dir.path().join("missing.conf")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(FileSystem.as_file_system().is_some());
    }
}
