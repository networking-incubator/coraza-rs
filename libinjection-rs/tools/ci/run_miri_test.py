#!/usr/bin/env python3
"""Run one exact Miri test and reject filters that select zero tests."""

from __future__ import annotations

import re
import os
import subprocess
import sys


TOOLCHAIN = os.environ.get("LIBINJECTION_MIRI_TOOLCHAIN", "nightly-2026-10-06")


def main() -> int:
    arguments = sys.argv[1:]
    if len(arguments) < 2 or arguments[-1].startswith("-"):
        print("usage: run_miri_test.py [--lib|--test TEST_TARGET] EXACT_TEST_NAME", file=sys.stderr)
        return 2

    test_name = arguments[-1]
    cargo_arguments = arguments[:-1]
    command = [
        "cargo",
        f"+{TOOLCHAIN}",
        "miri",
        "test",
        "-p",
        "libinjection",
        *cargo_arguments,
        test_name,
        "--",
        "--exact",
    ]
    result = subprocess.run(command, check=False, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, text=True)
    print(result.stdout, end="")
    if result.returncode != 0:
        return result.returncode

    selected = [int(count) for count in re.findall(r"^running (\d+) tests?$", result.stdout, re.MULTILINE)]
    if not selected or not any(count > 0 for count in selected):
        print(f"Miri filter selected zero tests: {test_name}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
