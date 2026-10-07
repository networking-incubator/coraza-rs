#!/usr/bin/env python3
"""Generate shared exact-length detector workloads for Go and Rust."""

from __future__ import annotations

import argparse
from pathlib import Path


BASE_SIZES = (256, 1024)
BASE_CASES = {
    "sqli": ("benign", "attack", "binary", "multiple_context"),
    "xss": ("benign", "attack", "binary", "multiple_context", "event_hit", "event_miss"),
}
SQL_LARGE = {
    65536: ("realistic_text", "json_body", "attack_head", "attack_tail"),
    131072: ("dollar_quote_unterminated", "quote_unterminated", "comment_unterminated"),
}
XSS_LARGE = {
    1024: ("event_hit_tail",),
    65536: ("realistic_html", "script_attack_tail", "event_hit_tail"),
    131072: ("realistic_html", "event_hit_tail"),
}


def pad(payload: bytes, size: int) -> bytes:
    if len(payload) > size:
        raise ValueError(f"workload template is {len(payload)} bytes, larger than {size}")
    return payload + b" " * (size - len(payload))


def repeat_exact(pattern: bytes, size: int) -> bytes:
    if not pattern:
        raise ValueError("workload filler must not be empty")
    return (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]


def place(size: int, marker: bytes, filler: bytes, *, at_tail: bool) -> bytes:
    if len(marker) > size:
        raise ValueError(f"marker is {len(marker)} bytes, larger than {size}")
    body = repeat_exact(filler, size - len(marker))
    return body + marker if at_tail else marker + body


def templates(detector: str) -> dict[str, bytes]:
    if detector == "sqli":
        return {
            "benign": b"customer_reference=" + b"x" * 36,
            "attack": b"1' OR '1'='1 -- attacker",
            "binary": b"\xff\x00" + b"1' OR '1'='1 -- binary",
            "multiple_context": b'"a"=\'a\' OR `b`=`b` # [c] /* d */',
        }
    if detector == "xss":
        return {
            "benign": b"customer note=" + b"x" * 32,
            "attack": b"<script>alert(1)</script>",
            "binary": b"\x00\xff<img src=x onerror=alert(1)>",
            "multiple_context": b'" onload=alert(1)><svg/onload=alert(1)>`<img src=x onerror=alert(1)>',
            "event_hit": b"<a onzoom=1>",
            "event_miss": b"<a onnotanactualevent=1>",
        }
    raise ValueError(f"unknown detector: {detector}")


def workload_rows() -> list[tuple[str, int, str, bytes]]:
    rows = []
    for detector in ("sqli", "xss"):
        samples = templates(detector)
        for size in BASE_SIZES:
            for case in BASE_CASES[detector]:
                rows.append((detector, size, case, pad(samples[case], size)))

    sql_text = b"The customer updated a shipping address and requested the latest delivery estimate. "
    sql_json_item = b'{"account":"customer-184","note":"please update my contact details","active":true}'
    for size, cases in SQL_LARGE.items():
        for case in cases:
            if case == "realistic_text":
                value = repeat_exact(sql_text, size)
            elif case == "json_body":
                item_count = max(1, (size - 2) // (len(sql_json_item) + 1))
                json_items = b",".join([sql_json_item] * item_count)
                padding = b" " * (size - len(json_items) - 2)
                value = b"[" + json_items + padding + b"]"
            elif case == "attack_head":
                value = place(size, b"' OR 1=1-- ", sql_text, at_tail=False)
            elif case == "attack_tail":
                value = place(size, b"' OR 1=1-- ", sql_text, at_tail=True)
            elif case == "dollar_quote_unterminated":
                value = b"$a$" + repeat_exact(b"x", size - 3)
            elif case == "quote_unterminated":
                value = b"'" + repeat_exact(b"x", size - 1)
            else:
                value = b"/*" + repeat_exact(b"x", size - 2)
            rows.append(("sqli", size, case, value))

    html_text = b"<article><p>The customer requested a delivery estimate for the current order.</p></article>"
    for size, cases in XSS_LARGE.items():
        for case in cases:
            if case == "event_hit_tail":
                value = place(size, b"<a onzoom=alert(1)>", html_text, at_tail=True)
            elif case == "script_attack_tail":
                value = place(size, b"<script>alert(1)</script>", html_text, at_tail=True)
            else:
                value = repeat_exact(html_text, size)
            rows.append(("xss", size, case, value))

    keys = [(detector, size, case) for detector, size, case, _ in rows]
    if len(keys) != len(set(keys)):
        raise ValueError("workload detector/size/case keys must be unique")
    for detector, size, case, value in rows:
        if len(value) != size:
            raise ValueError(f"{detector}/{size}/{case} has {len(value)} bytes")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = workload_rows()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        "\n".join(f"{detector}\t{size}\t{case}\t{value.hex()}" for detector, size, case, value in rows) + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
