#!/usr/bin/env python3
"""Measure and gate repeated-construct analysis time and allocation growth."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

from run import tree_sha256
from support import cargo_target_directory


ROOT = Path(__file__).resolve().parents[3]
PERF = Path(__file__).resolve().parent
MANIFEST = PERF / "Cargo.toml"
SOURCE = ROOT / "libinjection-rs" / "src"
DEFAULT_OUTPUT = Path("/tmp/libinjection-analysis-scaling/report.json")
GROWTH_LIMIT = 3.0
FIELDS = (
    "detector",
    "encoding",
    "input_bytes",
    "scan_limit",
    "median_ns",
    "alloc_calls",
    "alloc_bytes",
    "peak_live_bytes",
    "distinct_spans",
)


def run_driver(*, mode: str, rounds: int, cpu: int, count_allocations: bool) -> list[dict[str, object]]:
    command = [
        "taskset",
        "-c",
        str(cpu),
        "cargo",
        "run",
        "--offline",
        "--locked",
        "--quiet",
        "--release",
        "--manifest-path",
        str(MANIFEST),
        "--bin",
        "analyze_scaling",
    ]
    if count_allocations:
        command.extend(("--features", "count-allocations"))
    command.extend(("--", "--rounds", str(rounds), "--mode", mode))
    result = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    reader = csv.DictReader(io.StringIO(result.stdout), delimiter="\t")
    rows = []
    for raw in reader:
        row: dict[str, object] = {}
        for field in FIELDS:
            value = raw[field]
            row[field] = value if field in ("detector", "encoding") else None if value == "-" else int(value)
        rows.append(row)
    return rows


def growth_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str], list[dict[str, object]]] = {}
    for row in rows:
        grouped.setdefault((str(row["detector"]), str(row["encoding"])), []).append(row)

    comparisons = []
    for (detector, encoding), values in sorted(grouped.items()):
        values.sort(key=lambda row: int(row["input_bytes"]))
        for previous, current in zip(values, values[1:]):
            previous_size = int(previous["input_bytes"])
            current_size = int(current["input_bytes"])
            metrics = {}
            for name in ("median_ns", "alloc_calls", "alloc_bytes", "peak_live_bytes"):
                before = int(previous[name])
                after = int(current[name])
                metrics[f"{name}_growth_ratio"] = after / before if before else None
            passed = all(
                metrics[f"{name}_growth_ratio"] is not None
                and metrics[f"{name}_growth_ratio"] <= GROWTH_LIMIT
                for name in ("median_ns", "alloc_calls", "alloc_bytes", "peak_live_bytes")
            )
            comparisons.append(
                {
                    "detector": detector,
                    "encoding": encoding,
                    "from_bytes": previous_size,
                    "to_bytes": current_size,
                    **metrics,
                    "direct_growth_limit": GROWTH_LIMIT,
                    "passed": passed,
                }
            )
    return comparisons


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=11)
    parser.add_argument("--cpu", type=int, help="allowed CPU used for both analyzer runs")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if args.rounds < 5 or args.rounds > 101 or args.rounds % 2 == 0:
        parser.error("--rounds must be an odd number between 5 and 101")

    allowed_cpus = sorted(os.sched_getaffinity(0))
    cpu = args.cpu if args.cpu is not None else allowed_cpus[0]
    if cpu not in allowed_cpus:
        parser.error(f"CPU {cpu} is outside current affinity {allowed_cpus}")

    latency_rows = run_driver(mode="latency", rounds=args.rounds, cpu=cpu, count_allocations=False)
    allocation_rows = run_driver(mode="allocations", rounds=args.rounds, cpu=cpu, count_allocations=True)
    allocations = {
        (row["detector"], row["encoding"], row["input_bytes"]): row
        for row in allocation_rows
    }
    rows = []
    for latency in latency_rows:
        key = (latency["detector"], latency["encoding"], latency["input_bytes"])
        allocation = allocations[key]
        rows.append(
            {
                **latency,
                "alloc_calls": allocation["alloc_calls"],
                "alloc_bytes": allocation["alloc_bytes"],
                "peak_live_bytes": allocation["peak_live_bytes"],
            }
        )

    comparisons = growth_rows(rows)
    report = {
        "schema_version": 1,
        "date_utc": datetime.now(timezone.utc).isoformat(),
        "source_tree_sha256": tree_sha256(SOURCE),
        "host": {"system": platform.platform(), "machine": platform.machine(), "cpu": cpu},
        "method": {
            "rounds_per_row": args.rounds,
            "summary": "median single-call time, allocation calls, allocated bytes, and peak live bytes",
            "scan_limit": "8 KiB default through 8 KiB input; trusted limit equals input size above 8 KiB",
            "growth_gate": f"each adjacent doubled input size must grow by at most {GROWTH_LIMIT}x in every metric",
            "input_sizes": "1, 2, 4, and 8 KiB default-path cases plus 16 KiB raw and 12/24 KiB encoded trusted-limit cases",
            "allocation_measurement": "separate release build with a counting System allocator; latency runs use the unwrapped System allocator",
            "target_directory": str(cargo_target_directory(MANIFEST, cwd=ROOT)),
        },
        "growth_limit": GROWTH_LIMIT,
        "rows": rows,
        "adjacent_growth": comparisons,
        "overall_passed": all(row["passed"] for row in comparisons),
    }
    output_path = args.output.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"report: {output_path}")
    print(f"source tree: {report['source_tree_sha256']}")
    for row in comparisons:
        status = "PASS" if row["passed"] else "FAIL"
        print(
            f"{status} {row['detector']} {row['encoding']} {row['from_bytes']}->{row['to_bytes']} bytes: "
            f"time={row['median_ns_growth_ratio']:.3f}x allocs={row['alloc_calls_growth_ratio']:.3f}x "
            f"allocated={row['alloc_bytes_growth_ratio']:.3f}x peak={row['peak_live_bytes_growth_ratio']:.3f}x"
        )
    print(f"analysis growth gate: {'PASS' if report['overall_passed'] else 'FAIL'}")
    return 0 if report["overall_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
