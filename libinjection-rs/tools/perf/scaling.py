#!/usr/bin/env python3
"""Run paired hostile-input release scaling checks against pinned Go."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time

from support import cargo_target_directory, gzip_deterministic


ROOT = Path(__file__).resolve().parents[2]
PERF = Path(__file__).resolve().parent
PINNED_GO_COMMIT = "f6c336efc0ddac2597fd27d3b1b7db9c87613e8d"
LINEAR_COST_GROWTH_LIMIT = 2.5


def command(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(argv, cwd=cwd, env=env, check=True, text=True, capture_output=True)
    return result.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cpu_usage(cpu: int) -> tuple[int, int]:
    with Path("/proc/stat").open() as source:
        for line in source:
            if line.startswith(f"cpu{cpu} "):
                fields = [int(value) for value in line.split()[1:]]
                return sum(fields), fields[3] + (fields[4] if len(fields) > 4 else 0)
    raise RuntimeError(f"CPU {cpu} has no /proc/stat counters")


def wait_for_idle_cpu(cpu: int, timeout_seconds: int) -> list[float]:
    deadline = time.monotonic() + timeout_seconds
    quiet = 0
    seen = []
    before_total, before_idle = cpu_usage(cpu)
    while time.monotonic() < deadline:
        time.sleep(0.5)
        total, idle = cpu_usage(cpu)
        delta_total = total - before_total
        delta_idle = idle - before_idle
        percent = 100.0 * (delta_total - delta_idle) / delta_total if delta_total else 0.0
        seen.append(round(percent, 2))
        quiet = quiet + 1 if percent <= 15.0 else 0
        before_total, before_idle = total, idle
        if quiet >= 3:
            return seen[-3:]
    raise RuntimeError(f"CPU {cpu} did not meet the idle policy within {timeout_seconds}s; latest usage={seen[-3:]}")


def pin_process(cpu: int):
    def pin() -> None:
        os.sched_setaffinity(0, {cpu})

    return pin


def run_driver(language: str, argv: list[str], cpu: int, raw_path: Path) -> dict[str, object]:
    if language == "go":
        argv = [*argv, "-raw", str(raw_path)]
    else:
        argv = [*argv, str(raw_path)]
    output = subprocess.run(argv, check=True, text=True, capture_output=True, preexec_fn=pin_process(cpu))
    parsed = json.loads(output.stdout)
    zipped = raw_path.with_suffix(raw_path.suffix + ".gz")
    gzip_deterministic(raw_path, zipped)
    raw_path.unlink()
    return {
        "command": argv,
        "result": parsed,
        "raw_samples": zipped.relative_to(raw_path.parent).as_posix(),
        "sha256": sha256(zipped),
    }


def normalized_growth(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str, str], list[dict[str, object]]] = {}
    for row in rows:
        grouped.setdefault((row["language"], row["detector"], row["case"]), []).append(row)
    comparisons = []
    for (language, detector, case), values in sorted(grouped.items()):
        values.sort(key=lambda row: row["input_bytes"])
        for previous, current in zip(values, values[1:]):
            if previous["input_bytes"] == current["input_bytes"]:
                continue
            old_cost = previous["median_ns"] / previous["input_bytes"]
            new_cost = current["median_ns"] / current["input_bytes"]
            ratio = new_cost / old_cost if old_cost else None
            comparisons.append(
                {
                    "language": language,
                    "detector": detector,
                    "case": case,
                    "from_bytes": previous["input_bytes"],
                    "to_bytes": current["input_bytes"],
                    "median_ns_from": previous["median_ns"],
                    "median_ns_to": current["median_ns"],
                    "normalized_ns_per_byte_growth": ratio,
                    "limit": LINEAR_COST_GROWTH_LIMIT,
                    "gate_applied": language == "rust",
                    "policy": "Rust linear normalized-cost growth gate"
                    if language == "rust"
                    else "pinned Go comparison baseline (reported, not gated)",
                    "passed": ratio is not None and ratio <= LINEAR_COST_GROWTH_LIMIT if language == "rust" else None,
                }
            )
    return comparisons


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-source", type=Path, default=Path("/tmp/libinjection-go-v033"))
    parser.add_argument("--rust", default="1.97.1")
    parser.add_argument("--samples", type=int, default=9)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--idle-timeout", type=int, default=60)
    parser.add_argument("--cpu", type=int, help="allowed CPU for timed processes (default: first allowed CPU)")
    parser.add_argument("--artifact-dir", type=Path, default=Path("/tmp/libinjection-perf-scaling"))
    parser.add_argument("--output", type=Path, help="JSON report path (default: artifact-dir/scaling.json)")
    args = parser.parse_args()
    if args.samples < 3 or args.warmup < 0 or args.rounds < 1:
        raise RuntimeError("scaling requires at least three samples, nonnegative warmup, and one paired round")

    go_source = args.go_source.resolve()
    go_head = command(["git", "-C", str(go_source), "rev-parse", "HEAD"]).strip()
    if go_head != PINNED_GO_COMMIT:
        raise RuntimeError(f"Go source must be pinned at {PINNED_GO_COMMIT}; found {go_head}")
    go_version = command(["go", "version"]).strip()
    go_env = command(["go", "env", "GOEXPERIMENT", "GOARCH", "GOOS", "GOTOOLCHAIN"]).splitlines()
    go_experiment, go_arch, go_os, go_toolchain = go_env
    allowed = (go_version == "go version go1.27.1 linux/amd64" and not go_experiment) or (
        go_version == "go version go1.27.1-X:nodwarf5 linux/amd64" and go_experiment == "nodwarf5"
    )
    if not allowed or go_arch != "amd64" or go_os != "linux":
        raise RuntimeError(f"unsupported Go measurement tuple: {go_version}; GOEXPERIMENT={go_experiment}; {go_os}/{go_arch}")

    allowed_cpus = sorted(os.sched_getaffinity(0))
    cpu = args.cpu if args.cpu is not None else allowed_cpus[0]
    if cpu not in allowed_cpus:
        raise RuntimeError(f"CPU {cpu} is outside current affinity {allowed_cpus}")

    output_dir = args.artifact_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    go_cache = output_dir / "go-cache"
    go_tmp = output_dir / "go-tmp"
    go_cache.mkdir(parents=True, exist_ok=True)
    go_tmp.mkdir(parents=True, exist_ok=True)
    inputs_dir = output_dir / "inputs"
    subprocess.run([sys.executable, str(PERF / "scaling_inputs.py"), "--output-dir", str(inputs_dir)], check=True)
    manifest = inputs_dir / "scaling-inputs.tsv"
    for line in manifest.read_text().splitlines():
        columns = line.split("\t")
        if len(columns) != 6:
            raise RuntimeError(f"malformed hostile input manifest row: {line}")
        input_path = Path(columns[4])
        if not input_path.is_absolute():
            input_path = manifest.parent / input_path
        if sha256(input_path) != columns[5]:
            raise RuntimeError(f"hostile input SHA-256 check failed: {line}")

    go_binary = output_dir / "go-scaling-driver"
    go_build = ["go", "build", "-trimpath", "-o", str(go_binary), str(PERF / "go" / "scaling.go")]
    go_env_map = os.environ.copy()
    go_env_map["GOEXPERIMENT"] = go_experiment
    go_env_map["GOCACHE"] = str(go_cache)
    go_env_map["GOTMPDIR"] = str(go_tmp)
    subprocess.run(go_build, cwd=go_source, env=go_env_map, check=True)
    target_directory = cargo_target_directory(PERF / "Cargo.toml", cwd=ROOT)
    rust_build = [
        "cargo",
        f"+{args.rust}",
        "build",
        "--offline",
        "--locked",
        "--manifest-path",
        str(PERF / "Cargo.toml"),
        "--release",
        "--bin",
        "scaling",
        "--no-default-features",
        "--features",
        "legacy",
    ]
    subprocess.run(rust_build, cwd=ROOT, check=True)
    rust_binary = output_dir / "rust-scaling-driver"
    shutil.copy2(target_directory / "release" / "scaling", rust_binary)

    idle = wait_for_idle_cpu(cpu, args.idle_timeout)
    all_runs = []
    for round_number in range(1, args.rounds + 1):
        languages = ("rust", "go") if round_number % 2 else ("go", "rust")
        pair = {"round": round_number, "runs": []}
        for language in languages:
            raw = output_dir / f"round{round_number}-{language}.tsv"
            argv = (
                [str(go_binary), "-manifest", str(manifest), "-samples", str(args.samples), "-warmup", str(args.warmup)]
                if language == "go"
                else [str(rust_binary), str(manifest), str(args.samples), str(args.warmup)]
            )
            pair["runs"].append({"language": language, **run_driver(language, argv, cpu, raw)})
        all_runs.append(pair)

    medians = {}
    verdict_mismatches = []
    for pair in all_runs:
        language_rows = {}
        for run in pair["runs"]:
            language = run["language"]
            language_rows[language] = run["result"]["cases"]
            for row in run["result"]["cases"]:
                key = (language, row["detector"], row["case"], row["input_bytes"])
                medians.setdefault(key, []).append(row["median_ns"])
        if set(language_rows) == {"go", "rust"}:
            go_rows = {(row["detector"], row["case"], row["input_bytes"]): row for row in language_rows["go"]}
            rust_rows = {(row["detector"], row["case"], row["input_bytes"]): row for row in language_rows["rust"]}
            for key in go_rows.keys() | rust_rows.keys():
                go_row = go_rows.get(key)
                rust_row = rust_rows.get(key)
                if key[0] == "rust" and go_row is None:
                    # Bracket analysis is a Rust-only bounded-analysis stress
                    # case; the Go driver intentionally does not implement it.
                    continue
                if go_row is None or rust_row is None or (go_row["detected"], go_row["fingerprint"]) != (
                    rust_row["detected"],
                    rust_row["fingerprint"],
                ):
                    verdict_mismatches.append({"round": pair["round"], "input": key, "go": go_row, "rust": rust_row})

    summary_rows = []
    for key, values in sorted(medians.items()):
        language, detector, case, size = key
        summary_rows.append(
            {
                "language": language,
                "detector": detector,
                "case": case,
                "input_bytes": size,
                "median_ns_by_round": values,
                "median_ns": statistics.median(values),
            }
        )
    growth = normalized_growth(summary_rows)
    rust_growth = [row for row in growth if row["language"] == "rust"]
    if not rust_growth:
        raise RuntimeError("scaling run produced no Rust growth measurements")
    linearity_passed = all(bool(row["passed"]) for row in rust_growth)
    report = {
        "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_sha256": hashlib.sha256(
            b"".join(
                path.relative_to(ROOT / "src").as_posix().encode()
                + b"\0"
                + bytes.fromhex(sha256(path))
                for path in sorted((ROOT / "src").rglob("*"))
                if path.is_file()
            )
        ).hexdigest(),
        "pinned_go": {
            "commit": go_head,
            "version": go_version,
            "goexperiment": go_experiment,
            "goarch": go_arch,
            "goos": go_os,
            "gotoolchain": go_toolchain,
            "gocache": str(go_cache),
            "gotmpdir": str(go_tmp),
            "build_command": go_build,
            "binary_sha256": sha256(go_binary),
        },
        "rust": {
            "rustc": command(["rustc", f"+{args.rust}", "--version", "--verbose"]).strip(),
            "cargo": command(["cargo", f"+{args.rust}", "--version"]).strip(),
            "cargo_target_directory": str(target_directory),
            "build_command": rust_build,
            "binary_sha256": sha256(rust_binary),
            "performance_manifest_sha256": sha256(PERF / "Cargo.toml"),
            "performance_lock_sha256": sha256(PERF / "Cargo.lock"),
            "performance_driver_sources_sha256": hashlib.sha256(
                b"".join(
                    path.relative_to(PERF / "src").as_posix().encode()
                    + b"\0"
                    + bytes.fromhex(sha256(path))
                    for path in sorted((PERF / "src").rglob("*"))
                    if path.is_file()
                )
            ).hexdigest(),
        },
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_pinned": cpu,
            "allowed_cpus": allowed_cpus,
            "load_average_before_timing": os.getloadavg(),
            "idle_window_policy": "three consecutive 500ms windows on the pinned CPU at <=15% usage",
            "idle_window_observation": idle,
        },
        "method": {
            "timed_operation": "one detector/analysis call per sample; input-file IO, warmup, formatting, raw output, process startup, and Go/Rust IPC excluded",
            "samples_per_input_per_round": args.samples,
            "warmup_calls_per_input": args.warmup,
            "paired_rounds": args.rounds,
            "summary": "median of per-call medians across paired rounds",
            "linearity_metric": "median nanoseconds per input byte; adjacent-size normalized cost may grow by at most 2.5x",
            "noise_policy": "Pin child processes to one allowed CPU; wait for three quiet 500ms windows; alternate language order by round; keep every result.",
            "growth_policy": "Apply the 2.5x adjacent-size normalized-cost threshold to every Rust workload family, including mixed_escaped_quote_suffix. Record pinned Go timings and growth as a comparison baseline, without using Go growth as a pass/fail contract. Exact public detector verdict and fingerprint parity remains required.",
        },
        "inputs_manifest": manifest.relative_to(output_dir).as_posix(),
        "inputs_manifest_sha256": sha256(manifest),
        "runs": all_runs,
        "summary": summary_rows,
        "normalized_growth": growth,
        "verdict_mismatches": verdict_mismatches,
        "linearity_passed": linearity_passed,
        "verdicts_passed": not verdict_mismatches,
        "overall_passed": linearity_passed and not verdict_mismatches,
    }
    output_path = args.output.resolve() if args.output else output_dir / "scaling.json"
    output_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"report: {output_path}")
    print(f"pinned Go: {go_version} ({go_head})")
    print(f"Rust: {report['rust']['rustc'].splitlines()[0]}")
    print(f"CPU: {cpu}; paired rounds: {args.rounds}; verdict mismatches: {len(verdict_mismatches)}")
    for row in growth:
        status = ("PASS" if row["passed"] else "FAIL") if row["gate_applied"] else "BASE"
        print(
            f"{status} {row['language']} {row['detector']} {row['case']} {row['from_bytes']}→{row['to_bytes']}B: "
            f"normalized-cost ratio={row['normalized_ns_per_byte_growth']} "
            f"(limit {LINEAR_COST_GROWTH_LIMIT}; policy={row['policy']})"
        )
    print(f"overall hostile scaling gate: {'PASS' if report['overall_passed'] else 'FAIL'}")
    return 0 if report["overall_passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"hostile scaling run failed: {error}", file=sys.stderr)
        sys.exit(2)
