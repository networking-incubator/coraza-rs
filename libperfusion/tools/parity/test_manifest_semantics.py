#!/usr/bin/env python3
"""Check that the offline parity check fails when a pin it copies goes stale.

``tests/parity/differential.json`` records the Go module the source hashes
describe (owned by ``tests/parity/manifest.json``) and the C revision CI fetches
(``data/tables.json`` records the revision the tables came from). A bump that
refreshes only the owning file must fail ``make parity-manifest-check`` until
``check_manifest.py --update --go-source <dir>`` runs. The table hashes
themselves are checked by ``cargo xtask tables-check``.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_manifest


def run_offline() -> tuple[int, str]:
    output = io.StringIO()
    sys.argv = ["check_manifest.py"]
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        try:
            check_manifest.main()
        except SystemExit as error:
            if isinstance(error.code, str):
                return 1, output.getvalue() + error.code
            return error.code or 0, output.getvalue()
    return 0, output.getvalue()


def run_with_edited(name: str, edit: Callable[[dict], None]) -> tuple[int, str]:
    """Run the offline check with a temporary, edited copy of the JSON file ``check_manifest.<name>``."""
    original = getattr(check_manifest, name)
    data = json.loads(original.read_text(encoding="utf-8"))
    edit(data)
    with tempfile.TemporaryDirectory(prefix="parity-pin-test-") as temporary:
        copy = Path(temporary) / original.name
        copy.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        setattr(check_manifest, name, copy)
        try:
            return run_offline()
        finally:
            setattr(check_manifest, name, original)


def expect(name: str, edit: Callable[[dict], None], code: int, message: str, case: str) -> None:
    actual, output = run_with_edited(name, edit)
    if actual != code or message not in output:
        raise SystemExit(f"{case}: expected exit {code} with {message!r}, got exit {actual}:\n{output}")


def set_fields(sections: tuple[str, ...], field: str, value: str) -> Callable[[dict], None]:
    def edit(data: dict) -> None:
        for section in sections:
            data[section][field] = value

    return edit


def main() -> None:
    # Each control (an unchanged copy) passes, so the failures come from the edits.
    expect("MANIFEST", lambda _: None, 0, "parity differential verified", "unchanged manifest.json")
    # A Go module bump that ran only `cargo xtask corpus-refresh`, which rewrites
    # both module pins in manifest.json.
    for field, value in (("version", "v0.3.7"), ("module_sum", "h1:FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK=")):
        edit = set_fields(("source", "oracle"), field, value)
        expect("MANIFEST", edit, 1, "parity differential mismatch", f"Go module {field} bump without --update")
    expect("TABLES", lambda _: None, 0, "parity differential verified", "unchanged tables.json")
    # A C revision bump that ran only `cargo xtask tables-refresh`.
    edit = set_fields(("source",), "commit", "0" * 40)
    expect("TABLES", edit, 1, "C_REFERENCE", "C revision bump without a C_REFERENCE edit")
    print("parity pin regression passed: stale Go module and C revision pins rejected")


if __name__ == "__main__":
    main()
