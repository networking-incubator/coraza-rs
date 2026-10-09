#!/usr/bin/env python3
"""Check order-independent table hashing and same-count value drift detection."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


CRATE = Path(__file__).resolve().parents[2]
PINNED = CRATE / "src/xss/legacy/deny_list.rs"
MUTATION_FROM = 'b"APPLET"'
MUTATION_TO = 'b"APPLEZ"'
ORDER_FROM = '    (b"BACKGROUND", DenyAttrKind::Url),\n    (b"BY", DenyAttrKind::Url),'
ORDER_TO = '    (b"BY", DenyAttrKind::Url),\n    (b"BACKGROUND", DenyAttrKind::Url),'


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="libinjection-manifest-test-") as temporary:
        copy = Path(temporary) / "libinjection-rs"
        shutil.copytree(CRATE, copy)
        table = copy / PINNED.relative_to(CRATE)
        contents = table.read_text(encoding="utf-8")
        if contents.count(ORDER_FROM) != 1:
            raise SystemExit(f"expected one test table-order point in {table}")
        table.write_text(contents.replace(ORDER_FROM, ORDER_TO, 1), encoding="utf-8")

        checker = copy / "tools/parity/check_manifest.py"
        result = subprocess.run(["python3", str(checker)], cwd=copy.parent, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise SystemExit(f"offline manifest rejected reordered equivalent table rows:\n{result.stdout}{result.stderr}")

        contents = table.read_text(encoding="utf-8")
        if contents.count(MUTATION_FROM) != 1:
            raise SystemExit(f"expected one test mutation point in {table}")
        table.write_text(contents.replace(MUTATION_FROM, MUTATION_TO, 1), encoding="utf-8")

        result = subprocess.run(["python3", str(checker)], cwd=copy.parent, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            raise SystemExit("offline parity manifest accepted a changed XSS tag with unchanged table counts")
        output = result.stdout + result.stderr
        if "parity manifest mismatch" not in output:
            raise SystemExit(f"checker failed for an unrelated reason:\n{output}")

    print("offline manifest regression passed: changed XSS tag value rejected with counts unchanged")


if __name__ == "__main__":
    main()
