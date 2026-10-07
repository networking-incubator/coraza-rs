#!/usr/bin/env python3
"""Build a compact, hash-linked record from completed perf reports."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text())


def compact_attempt(name: str, report_path: Path) -> dict[str, object]:
    report = load(report_path)
    raw_artifacts = []
    missing = []
    for pair in report["run_pairs"]:
        for run in pair["runs"]:
            raw_path = Path(run["raw_samples"])
            if not raw_path.is_absolute():
                raw_path = report_path.parent / raw_path
            expected = run["raw_samples_sha256"]
            actual = sha256(raw_path) if raw_path.exists() else None
            item = {
                "path": str(raw_path),
                "sha256": expected,
                "exists": actual is not None,
                "hash_verified": actual == expected,
            }
            raw_artifacts.append(item)
            if actual != expected:
                missing.append(str(raw_path))

    rows = [
        {
            key: row[key]
            for key in (
                "profile",
                "detector",
                "input_bytes",
                "case",
                "go_p99_ns_by_round",
                "rust_p99_ns_by_round",
                "go_p99_ns_median",
                "rust_p99_ns_median",
                "rust_to_go_p99_ratio",
                "p99_gate_passed",
                "go_verdict",
                "go_fingerprint_hex",
            )
        }
        for row in report["summary"]["rows"]
    ]
    return {
        "name": name,
        "report_path": str(report_path),
        "report_sha256": sha256(report_path),
        "date_utc": report["date_utc"],
        "source_tree_sha256": report["rust"]["source_tree_sha256"],
        "pinned_go": report["pinned_go"],
        "rust": report["rust"],
        "host": report["host"],
        "method": report["method"],
        "workloads": report["workloads"],
        "paired_rounds": max((len(row["go_p99_ns_by_round"]) for row in rows), default=0),
        "confirmation_was_run": report["confirmation_was_run"],
        "initial_profile_failures": report.get("initial_profile_failures", report.get("initial_default_failures", [])),
        "supported_profile_performance_open_issues": report.get("supported_profile_performance_open_issues", []),
        "verdict_mismatches": report["verdict_mismatches"],
        "overall_passed": report["overall_passed"],
        "rows": rows,
        "raw_artifacts": raw_artifacts,
        "raw_artifact_hashes_verified": not missing,
        "raw_artifacts_missing_or_changed": missing,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--initial", type=Path, required=True, help="first successful 7-round matrix")
    parser.add_argument("--confirmation", type=Path, required=True, help="14-round confirmation matrix")
    parser.add_argument("--post-change", type=Path, required=True, help="post-optimization matrix")
    parser.add_argument("--failed-attempt", type=Path, required=True, help="initial report-assembly failure metadata")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    failed_attempt = load(args.failed_attempt)
    result = {
        "schema_version": 1,
        "purpose": "Durable compact Phase 5 latency evidence; raw timed samples remain in /tmp and are hash-linked below.",
        "reproduction_command": (
            "python3 libinjection-rs/tools/perf/run.py --artifact-dir /tmp/libinjection-perf-phase5/<attempt> "
            "--output /tmp/libinjection-perf-phase5/<attempt>/report.json"
        ),
        "archive_policy": (
            "Keep compact metadata, per-row rounds, report hashes, and raw sample hashes in the repository. "
            "Raw .tsv.gz samples remain under /tmp; regenerate with the recorded command if they are unavailable."
        ),
        "attempts": [
            compact_attempt("pre-fix-initial-7-round", args.initial.resolve()),
            compact_attempt("pre-fix-confirmed-14-round", args.confirmation.resolve()),
            compact_attempt("post-xss-fix-7-round", args.post_change.resolve()),
        ],
        "first_report_assembly_failure": {
            "metadata_path": str(args.failed_attempt.resolve()),
            "metadata_sha256": sha256(args.failed_attempt.resolve()),
            "status": failed_attempt.get("status"),
            "failure": failed_attempt.get("failure"),
            "sampling": failed_attempt.get("sampling"),
            "raw_artifacts": failed_attempt.get("raw_artifacts"),
            "result_status": failed_attempt.get("result_status"),
            "p99_claimed": False,
        },
    }
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    attempts = result["attempts"]
    print(f"wrote {output}")
    for attempt in attempts:
        print(
            f"{attempt['name']}: rounds={attempt['paired_rounds']} rows={len(attempt['rows'])} "
            f"raw_hashes_verified={attempt['raw_artifact_hashes_verified']}"
        )
    return 0 if all(attempt["raw_artifact_hashes_verified"] for attempt in attempts) else 1


if __name__ == "__main__":
    raise SystemExit(main())
