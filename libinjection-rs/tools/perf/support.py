"""Shared helpers for reproducible libinjection performance runs."""

from __future__ import annotations

import gzip
import json
from pathlib import Path
import shutil
import subprocess


def cargo_target_directory(manifest: Path, *, cwd: Path) -> Path:
    """Return Cargo's effective target directory, including CARGO_TARGET_DIR."""
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--no-deps",
            "--format-version=1",
            "--manifest-path",
            str(manifest),
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(result.stdout)
    target_directory = Path(metadata["target_directory"])
    if not target_directory.is_absolute():
        target_directory = cwd / target_directory
    return target_directory.resolve()


def gzip_deterministic(source_path: Path, compressed_path: Path) -> None:
    """Write a gzip stream whose container metadata is stable across runs."""
    with source_path.open("rb") as source, compressed_path.open("wb") as destination:
        with gzip.GzipFile(filename="", fileobj=destination, mode="wb", compresslevel=6, mtime=0) as compressed:
            shutil.copyfileobj(source, compressed)
