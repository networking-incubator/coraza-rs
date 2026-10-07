#!/usr/bin/env python3
"""Create shared binary inputs for hostile release-scaling measurements."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def records():
    for size in (1024, 2048, 4096, 8192, 16384, 32768, 65536):
        yield "sqli", "detect_sqli", "unary", size, b"+" * size
        comment = b"/*" + b"x" * max(0, size - 3) + b"/"
        yield "sqli", "detect_sqli", "comment", len(comment), comment
    # Include the large-range suffix points where the pinned Go implementation
    # exposes its inherited superlinear scan cost above timer quantization.
    for count in (1600, 3200, 6400, 12800, 25600, 51200):
        mixed = b"'\\" + b"'" * count
        yield "sqli", "detect_sqli", "mixed_escaped_quote_suffix", len(mixed), mixed

    # Keep escape-only and doubled-delimiter inputs as quote-path controls.
    for count in (128, 256, 512, 1024, 2048):
        escaped = b"'" + b"\\'" * count
        yield "sqli", "detect_sqli", "escaped_quotes", len(escaped), escaped
        doubled = b"'" + b"''" * count
        yield "sqli", "detect_sqli", "doubled_quotes", len(doubled), doubled
    for count in (1024, 2048, 4096, 8192, 16384, 32767):
        brackets = b"[" * count + b"]"
        yield "rust", "analyze_sqli", "brackets", len(brackets), brackets
    for size in (1_000_000, 5_000_000, 10_000_000):
        yield "xss", "detect_xss", "slashes", size, b"/" * size


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for detector, api, name, size, data in records():
        path = args.output_dir / f"{detector}-{name}-{size}.bin"
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        rows.append(f"{detector}\t{api}\t{name}\t{size}\t{path.name}\t{digest}")
    manifest = args.output_dir / "scaling-inputs.tsv"
    manifest.write_text("\n".join(rows) + "\n")
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
