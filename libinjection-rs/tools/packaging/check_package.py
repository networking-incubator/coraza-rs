#!/usr/bin/env python3
"""Check the published crate archive, offline build, and runtime dependencies."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[3]
CRATE = ROOT / "libinjection-rs"
MANIFEST = CRATE / "Cargo.toml"
PACKAGE_NAME = "libinjection"
WORKSPACE = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
PACKAGE_VERSION = WORKSPACE["workspace"]["package"]["version"]
TARGET_DIR = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
if not TARGET_DIR.is_absolute():
    TARGET_DIR = ROOT / TARGET_DIR
ARCHIVE = TARGET_DIR / "package" / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.crate"
PREFIX = f"{PACKAGE_NAME}-{PACKAGE_VERSION}/"
REQUIRED = {
    "Cargo.toml",
    "docs/ASSURANCE_REPORT.md",
    "docs/PERFORMANCE_AND_STACK.md",
    "build.rs",
    "data/sqli_keywords.txt",
    "LICENSES/Apache-2.0.txt",
    "LICENSES/libinjection-C-BSD-3-Clause.txt",
    "LICENSES/libinjection-go-BSD-3-Clause.txt",
    "THIRD_PARTY_NOTICES.md",
    "src/lib.rs",
    "tests/generated_differential.rs",
    "tests/no_alloc.rs",
    "tests/property_progress.rs",
    "tools/parity/check_manifest.py",
    "tools/parity/go-oracle",
    "tools/parity/PROTOCOL.md",
    "tools/parity/test_manifest_semantics.py",
}


def run(command: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=True, text=True, capture_output=True)


def main() -> None:
    manifest = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    dependencies = manifest.get("dependencies", {})
    if set(dependencies) != {"memchr"}:
        raise SystemExit(f"expected memchr as the only runtime dependency, got: {sorted(dependencies)}")
    if dependencies["memchr"].get("default-features", True) or "std" not in dependencies["memchr"].get("features", []):
        raise SystemExit("memchr must keep default features disabled and enable its std feature explicitly")
    crate_license = CRATE / "LICENSES/Apache-2.0.txt"
    workspace_license = ROOT / "LICENSE"
    if crate_license.read_bytes() != workspace_license.read_bytes():
        raise SystemExit("crate-local Apache-2.0 license differs from the workspace license")
    bsd_license = CRATE / "LICENSES/libinjection-go-BSD-3-Clause.txt"
    parity_manifest = json.loads((CRATE / "tests/parity/manifest.json").read_text(encoding="utf-8"))
    if hashlib.sha256(bsd_license.read_bytes()).hexdigest() != parity_manifest["source_sha256"].get("LICENSE"):
        raise SystemExit("crate-local BSD license differs from the pinned Go source LICENSE hash")

    listed = run(["cargo", "package", "--list", "-p", PACKAGE_NAME, "--offline", "--allow-dirty"]).stdout.splitlines()
    missing_from_list = REQUIRED - set(listed)
    if missing_from_list:
        raise SystemExit(f"crate package omits required provenance/test files: {sorted(missing_from_list)}")

    run(["cargo", "package", "-p", PACKAGE_NAME, "--offline", "--allow-dirty", "--no-verify"])
    if not ARCHIVE.is_file():
        raise SystemExit(f"cargo package did not produce {ARCHIVE}")

    with tempfile.TemporaryDirectory(prefix="libinjection-package-") as temporary:
        extracted = Path(temporary)
        with tarfile.open(ARCHIVE, "r:gz") as package:
            members = package.getmembers()
            for member in members:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts:
                    raise SystemExit(f"unsafe path in generated crate archive: {member.name!r}")
                if not member.name.startswith(PREFIX):
                    raise SystemExit(f"unexpected top-level crate path: {member.name!r}")
            packaged_files = {member.name.removeprefix(PREFIX) for member in members if member.isfile()}
            missing_from_archive = REQUIRED - packaged_files
            if missing_from_archive:
                raise SystemExit(f"crate archive omits required files: {sorted(missing_from_archive)}")
            oracle_script = next(member for member in members if member.name == f"{PREFIX}tools/parity/go-oracle")
            if oracle_script.mode & 0o111 == 0:
                raise SystemExit("packaged Go oracle helper lost its executable bit")
            package.extractall(extracted)

        packaged_root = extracted / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
        packaged_manifest = packaged_root / "Cargo.toml"
        if (packaged_root / "LICENSES/Apache-2.0.txt").read_bytes() != workspace_license.read_bytes():
            raise SystemExit("published crate archive does not contain the full Apache-2.0 license text")
        if (packaged_root / "LICENSES/libinjection-go-BSD-3-Clause.txt").read_bytes() != bsd_license.read_bytes():
            raise SystemExit("published crate archive does not contain the full pinned Go BSD license text")
        c_license = CRATE / "LICENSES/libinjection-C-BSD-3-Clause.txt"
        if (packaged_root / "LICENSES/libinjection-C-BSD-3-Clause.txt").read_bytes() != c_license.read_bytes():
            raise SystemExit("published crate archive does not contain the original libinjection BSD license text")
        package_metadata = manifest.get("package", {})
        if "Apache-2.0 AND BSD-3-Clause" not in package_metadata.get("license", ""):
            raise SystemExit("crate SPDX expression must include both Apache-2.0 and BSD-3-Clause")
        for features in ([], ["legacy"]):
            command = [
                "cargo",
                "check",
                "--offline",
                "--manifest-path",
                str(packaged_manifest),
                "--no-default-features",
            ]
            if features:
                command.extend(["--features", ",".join(features)])
            run(command, cwd=packaged_root)

    print(f"package check passed: {ARCHIVE.name}; memchr is the only runtime dependency")


if __name__ == "__main__":
    main()
