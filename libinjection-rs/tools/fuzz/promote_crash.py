#!/usr/bin/env python3
"""Append a libFuzzer artifact to the deterministic byte regression manifest."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


CRATE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = CRATE_ROOT / "tests/fuzz_regressions/inputs.hex"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="libFuzzer crash artifact file")
    parser.add_argument("--id", help="stable regression name (defaults to a SHA-256 prefix)")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--sqli", choices=("0", "1"), help="expected legacy SQLi verdict")
    parser.add_argument("--xss", choices=("0", "1"), help="expected legacy XSS verdict")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    artifact = args.artifact.read_bytes()
    name = args.id or f"fuzz-{hashlib.sha256(artifact).hexdigest()[:12]}"
    if not name or any(char in name for char in "\t\r\n"):
        raise SystemExit("regression ID must be non-empty and contain no tabs or newlines")

    lines = args.manifest.read_text(encoding="ascii").splitlines()
    existing = {line.split("\t", 1)[0] for line in lines if line and not line.startswith("#")}
    if name in existing:
        raise SystemExit(f"regression ID already exists: {name}")

    fields = [name, artifact.hex()]
    if args.sqli is not None:
        fields.append(f"sqli={args.sqli}")
    if args.xss is not None:
        fields.append(f"xss={args.xss}")
    with args.manifest.open("a", encoding="ascii", newline="\n") as manifest:
        manifest.write("\n".join(lines).rstrip() + "\n" + "\t".join(fields) + "\n")
    print(f"promoted {args.artifact} as {name} ({len(artifact)} bytes) in {args.manifest}")


if __name__ == "__main__":
    main()
