#!/usr/bin/env python3
"""Run paired in-process Go/Rust per-call latency distributions."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time

from support import cargo_target_directory, gzip_deterministic
from workloads import workload_rows


ROOT = Path(__file__).resolve().parents[2]
PERF = Path(__file__).resolve().parent
PINNED_GO_COMMIT = "f6c336efc0ddac2597fd27d3b1b7db9c87613e8d"
PROFILES = {
    "legacy": ("--no-default-features", "--features", "legacy"),
}
DETECTORS = ("sqli", "xss")


def command(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(argv, cwd=cwd, env=env, check=True, text=True, capture_output=True)
    return result.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    for source in sorted(file for file in path.rglob("*") if file.is_file()):
        digest.update(source.relative_to(path).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256(source)))
    return digest.hexdigest()


def workload_file(path: Path) -> list[tuple[str, int, str]]:
    subprocess.run([sys.executable, str(PERF / "workloads.py"), "--output", str(path)], check=True)
    cases = []
    for line_number, line in enumerate(path.read_text().splitlines(), start=1):
        columns = line.split("\t")
        if len(columns) != 4:
            raise RuntimeError(f"workload row {line_number} must have four tab-separated columns")
        detector, size, case, encoded = columns
        if detector not in DETECTORS:
            raise RuntimeError(f"workload row {line_number} has unknown detector {detector!r}")
        size_bytes = int(size)
        if len(encoded) != size_bytes * 2:
            raise RuntimeError(f"workload row {line_number} has encoded length inconsistent with {size} bytes")
        cases.append((detector, size_bytes, case))
    if not cases or len(cases) != len(set(cases)):
        raise RuntimeError("workload file must contain unique detector/size/case rows")
    expected = {(detector, size, case) for detector, size, case, _ in workload_rows()}
    if set(cases) != expected:
        raise RuntimeError("workload file differs from the shared workload definition")
    return cases


def pin_process(cpu: int):
    def pin() -> None:
        os.sched_setaffinity(0, {cpu})

    return pin


def cpu_usage(cpu: int) -> tuple[int, int]:
    with Path("/proc/stat").open() as source:
        for line in source:
            if line.startswith(f"cpu{cpu} "):
                fields = [int(value) for value in line.split()[1:]]
                idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
                total = sum(fields)
                return total, idle
    raise RuntimeError(f"CPU {cpu} has no /proc/stat counters")


def wait_for_idle_cpu(cpu: int, timeout_seconds: int) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    quiet_windows = 0
    observations = []
    previous_total, previous_idle = cpu_usage(cpu)
    while time.monotonic() < deadline:
        time.sleep(0.5)
        total, idle = cpu_usage(cpu)
        delta_total = total - previous_total
        delta_idle = idle - previous_idle
        usage_percent = 100.0 * (delta_total - delta_idle) / delta_total if delta_total else 0.0
        observations.append(round(usage_percent, 2))
        quiet_windows = quiet_windows + 1 if usage_percent <= 15.0 else 0
        previous_total, previous_idle = total, idle
        if quiet_windows >= 3:
            return {"cpu": cpu, "quiet_windows_percent": observations[-3:], "threshold_percent": 15.0, "window_ms": 500}
    raise RuntimeError(f"CPU {cpu} did not meet the idle policy within {timeout_seconds}s; latest usage={observations[-3:]}")


def parse_output(raw: str) -> dict[str, object]:
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"benchmark driver returned invalid JSON: {error}\n{raw[-2000:]}") from error
    return result


def result_rows(result: dict[str, object]) -> dict[tuple[str, int, str], dict[str, object]]:
    return {(result["detector"], row["size"], row["case"]): row for row in result["cases"]}


def verify_driver_cases(run: dict[str, object], expected: set[tuple[str, int, str]]) -> None:
    actual = set(result_rows(run["result"]))
    if actual != expected:
        raise RuntimeError(
            f"{run['language']} {run['result']['detector']} driver cases differ from workload manifest; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )


def run_driver(
    name: str,
    argv: list[str],
    *,
    cpu: int,
    output_dir: Path,
    round_number: int,
    profile: str,
    detector: str,
) -> dict[str, object]:
    raw_path = output_dir / f"{profile}-round{round_number}-{detector}-{name}.tsv"
    if name == "rust":
        argv = [*argv, str(raw_path)]
    else:
        argv = [*argv, "-raw", str(raw_path)]
    completed = subprocess.run(
        argv,
        check=True,
        text=True,
        capture_output=True,
        preexec_fn=pin_process(cpu),
    )
    result = parse_output(completed.stdout)
    compressed_path = raw_path.with_suffix(raw_path.suffix + ".gz")
    gzip_deterministic(raw_path, compressed_path)
    raw_path.unlink()
    return {
        "language": name,
        "command": argv,
        "result": result,
        "raw_samples": compressed_path.relative_to(output_dir).as_posix(),
        "raw_samples_sha256": sha256(compressed_path),
    }


def collect_rounds(
    *,
    rounds: int,
    first_round: int,
    binaries: dict[str, Path],
    go_binary: Path,
    case_file: Path,
    cpu: int,
    output_dir: Path,
    samples: int,
    warmup: int,
    workload_manifest: list[tuple[str, int, str]],
) -> list[dict[str, object]]:
    rows = []
    for round_offset in range(rounds):
        round_number = first_round + round_offset
        for detector_index, detector in enumerate(DETECTORS):
            for profile, rust_binary in binaries.items():
                order = ("rust", "go") if (round_number + detector_index) % 2 == 0 else ("go", "rust")
                pair = {"round": round_number, "profile": profile, "detector": detector, "runs": []}
                for language in order:
                    if language == "rust":
                        argv = [
                            str(rust_binary),
                            detector,
                            str(case_file),
                            str(samples),
                            str(warmup),
                        ]
                    else:
                        argv = [
                            str(go_binary),
                            "-detector",
                            detector,
                            "-cases",
                            str(case_file),
                            "-samples",
                            str(samples),
                            "-warmup",
                            str(warmup),
                        ]
                    run = run_driver(
                        language,
                        argv,
                        cpu=cpu,
                        output_dir=output_dir,
                        round_number=round_number,
                        profile=profile,
                        detector=detector,
                    )
                    verify_driver_cases(run, {row for row in workload_manifest if row[0] == detector})
                    pair["runs"].append(run)
                rows.append(pair)
    return rows


def summarize(
    rows: list[dict[str, object]], max_ratio: float, max_absolute_slack_ns: float
) -> dict[str, object]:
    grouped: dict[tuple[str, str, int, str], dict[str, list[int]]] = {}
    verdicts: dict[tuple[str, int, str], tuple[bool, str]] = {}
    for pair in rows:
        profile = pair["profile"]
        detector = pair["detector"]
        for run in pair["runs"]:
            language = run["language"]
            for key, row in result_rows(run["result"]).items():
                _, size, case = key
                grouped.setdefault((profile, detector, size, case), {}).setdefault(language, []).append(row["p99_ns"])
                verdict_key = (detector, size, case)
                verdict = (row["detected"], row["fingerprint"])
                if language == "go":
                    verdicts[verdict_key] = verdict
                elif verdicts.get(verdict_key) != verdict:
                    # Preserve a Rust-first pair's result until the Go row arrives.
                    verdicts.setdefault(verdict_key, verdict)

    reports = []
    for (profile, detector, size, case), values in sorted(grouped.items()):
        go_values = values.get("go", [])
        rust_values = values.get("rust", [])
        if not go_values or not rust_values:
            raise RuntimeError(f"incomplete paired samples for {profile}/{detector}/{size}/{case}")
        go_median = statistics.median(go_values)
        rust_median = statistics.median(rust_values)
        ratio = rust_median / go_median if go_median else None
        absolute_delta = rust_median - go_median
        ratio_passed = ratio is not None and ratio <= max_ratio
        absolute_slack_passed = absolute_delta <= max_absolute_slack_ns
        verdict = verdicts.get((detector, size, case))
        reports.append(
            {
                "profile": profile,
                "detector": detector,
                "input_bytes": size,
                "case": case,
                "go_p99_ns_by_round": go_values,
                "rust_p99_ns_by_round": rust_values,
                "go_p99_ns_median": go_median,
                "rust_p99_ns_median": rust_median,
                "rust_to_go_p99_ratio": ratio,
                "p99_gate_threshold_ratio": max_ratio,
                "rust_minus_go_p99_ns": absolute_delta,
                "p99_gate_absolute_slack_ns": max_absolute_slack_ns,
                "p99_gate_ratio_passed": ratio_passed,
                "p99_gate_absolute_slack_passed": absolute_slack_passed,
                "p99_gate_passed": ratio_passed or absolute_slack_passed,
                "go_verdict": verdict[0] if verdict else None,
                "go_fingerprint_hex": verdict[1] if verdict else None,
            }
        )
    return {"rows": reports}


def compare_verdicts(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    mismatches = []
    for pair in rows:
        runs = {run["language"]: result_rows(run["result"]) for run in pair["runs"]}
        if "go" not in runs or "rust" not in runs:
            mismatches.append({"pair": [pair["profile"], pair["round"], pair["detector"]], "reason": "missing language run"})
            continue
        for key, go_row in runs["go"].items():
            rust_row = runs["rust"].get(key)
            if rust_row is None or (go_row["detected"], go_row["fingerprint"]) != (
                rust_row["detected"],
                rust_row["fingerprint"],
            ):
                mismatches.append(
                    {
                        "pair": [pair["profile"], pair["round"], pair["detector"]],
                        "input": list(key),
                        "go": {"detected": go_row["detected"], "fingerprint": go_row["fingerprint"]},
                        "rust": None
                        if rust_row is None
                        else {"detected": rust_row["detected"], "fingerprint": rust_row["fingerprint"]},
                    }
                )
    return mismatches


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-source", type=Path, default=Path("/tmp/libinjection-go-v033"))
    parser.add_argument("--rust", default="1.97.1")
    parser.add_argument("--samples", type=int, default=20000)
    parser.add_argument("--warmup", type=int, default=2000)
    parser.add_argument("--rounds", type=int, default=7)
    parser.add_argument("--confirm-rounds", type=int, default=7)
    parser.add_argument(
        "--max-ratio",
        type=float,
        default=1.0,
        help="maximum Rust/Go median-p99 ratio (default: 1.0)",
    )
    parser.add_argument(
        "--max-absolute-slack-ns",
        type=float,
        default=25.0,
        help="allow this many absolute nanoseconds above Go p99 to absorb timer noise (default: 25)",
    )
    parser.add_argument("--idle-timeout", type=int, default=60)
    parser.add_argument("--cpu", type=int, help="allowed CPU to pin timed child processes (default: first allowed CPU)")
    parser.add_argument("--artifact-dir", type=Path, default=Path("/tmp/libinjection-perf-phase5"))
    parser.add_argument("--output", type=Path, help="JSON report path (default: artifact-dir/report.json)")
    args = parser.parse_args()
    if (
        args.samples < 100
        or args.warmup < 0
        or args.rounds < 1
        or args.confirm_rounds < 1
        or not math.isfinite(args.max_ratio)
        or args.max_ratio < 1.0
        or not math.isfinite(args.max_absolute_slack_ns)
        or args.max_absolute_slack_ns < 0.0
    ):
        raise RuntimeError(
            "samples must be >=100, warmup >=0, rounds and confirmation rounds >=1, max-ratio must be finite and >=1, and max-absolute-slack-ns must be finite and >=0"
        )

    go_source = args.go_source.resolve()
    go_head = command(["git", "-C", str(go_source), "rev-parse", "HEAD"]).strip()
    if go_head != PINNED_GO_COMMIT:
        raise RuntimeError(f"Go source must be pinned at {PINNED_GO_COMMIT}; found {go_head}")
    go_version = command(["go", "version"]).strip()
    go_env = command(["go", "env", "GOEXPERIMENT", "GOARCH", "GOOS", "GOTOOLCHAIN"]).splitlines()
    go_experiment, go_arch, go_os, go_toolchain = go_env
    allowed_go = (go_version == "go version go1.27.1 linux/amd64" and not go_experiment) or (
        go_version == "go version go1.27.1-X:nodwarf5 linux/amd64" and go_experiment == "nodwarf5"
    )
    if not allowed_go or go_arch != "amd64" or go_os != "linux":
        raise RuntimeError(
            f"unsupported Go measurement tuple: {go_version}; GOEXPERIMENT={go_experiment}; {go_os}/{go_arch}"
        )

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
    cases_path = output_dir / "workloads.tsv"
    workload_manifest = workload_file(cases_path)
    go_binary = output_dir / "go-perf-driver"
    go_build = ["go", "build", "-trimpath", "-o", str(go_binary), str(PERF / "go" / "main.go")]
    go_env_map = os.environ.copy()
    go_env_map["GOEXPERIMENT"] = go_experiment
    go_env_map["GOCACHE"] = str(go_cache)
    go_env_map["GOTMPDIR"] = str(go_tmp)
    subprocess.run(go_build, cwd=go_source, env=go_env_map, check=True)

    target_directory = cargo_target_directory(PERF / "Cargo.toml", cwd=ROOT)
    rust_binaries = {}
    for profile, features in PROFILES.items():
        build = [
            "cargo",
            f"+{args.rust}",
            "build",
            "--offline",
            "--locked",
            "--manifest-path",
            str(PERF / "Cargo.toml"),
            "--release",
            *features,
        ]
        subprocess.run(build, cwd=ROOT, check=True)
        source_binary = target_directory / "release" / "libinjection-perf-driver"
        destination = output_dir / f"rust-perf-driver-{profile}"
        shutil.copy2(source_binary, destination)
        rust_binaries[profile] = destination

    idle = wait_for_idle_cpu(cpu, args.idle_timeout)
    first_rows = collect_rounds(
        rounds=args.rounds,
        first_round=1,
        binaries=rust_binaries,
        go_binary=go_binary,
        case_file=cases_path,
        cpu=cpu,
        output_dir=output_dir,
        samples=args.samples,
        warmup=args.warmup,
        workload_manifest=workload_manifest,
    )
    first_summary = summarize(first_rows, args.max_ratio, args.max_absolute_slack_ns)
    initial_profile_failures = [
        row
        for row in first_summary["rows"]
        if not row["p99_gate_passed"]
    ]
    second_rows = []
    if initial_profile_failures:
        wait_for_idle_cpu(cpu, args.idle_timeout)
        second_rows = collect_rounds(
            rounds=args.confirm_rounds,
            first_round=args.rounds + 1,
            binaries=rust_binaries,
            go_binary=go_binary,
            case_file=cases_path,
            cpu=cpu,
            output_dir=output_dir,
            samples=args.samples,
            warmup=args.warmup,
            workload_manifest=workload_manifest,
        )
    all_rows = first_rows + second_rows
    summary = summarize(all_rows, args.max_ratio, args.max_absolute_slack_ns)
    verdict_mismatches = compare_verdicts(all_rows)
    report = {
        "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
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
            "source_tree_sha256": tree_sha256(ROOT / "src"),
            "cargo_manifest_sha256": sha256(ROOT / "Cargo.toml"),
            "performance_manifest_sha256": sha256(PERF / "Cargo.toml"),
            "performance_lock_sha256": sha256(PERF / "Cargo.lock"),
            "performance_driver_sources_sha256": tree_sha256(PERF / "src"),
            "profiles": {
                profile: {"features": list(PROFILES[profile]), "binary_sha256": sha256(path)}
                for profile, path in rust_binaries.items()
            },
        },
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_pinned": cpu,
            "allowed_cpus": allowed_cpus,
            "load_average_before_timing": os.getloadavg(),
            "idle_window_policy": "three consecutive 500ms windows on pinned CPU at <=15% usage",
            "idle_window_observation": idle,
        },
        "method": {
            "timed_operation": "one canonical detector call per sample; input decoding, result formatting, raw output, fixture IO, compilation, process startup, and oracle communication excluded",
            "clock": "Go time.Now/time.Since; Rust std::time::Instant; both monotonic clocks",
            "black_box": "Rust black_box surrounds input and result; Go results are retained for parity output",
            "samples_per_case_per_run": args.samples,
            "untimed_warmup_calls_per_case": args.warmup,
            "initial_paired_rounds": args.rounds,
            "confirmation_rounds_on_any_supported_profile_failure": args.confirm_rounds,
            "p99": "nearest-rank p99 of individually timed calls; no batched mean or Criterion estimate",
            "noise_policy": "Pin child processes to one allowed CPU; alternate language order per paired round; summarize median p99 across rounds; on any initial profile failure, collect a second full paired set. A bounded absolute nanosecond allowance handles timer noise on tiny workloads.",
            "gate": f"For every detector, size, and workload category in the std-enabled legacy profile, median Rust p99 must be <= {args.max_ratio} * median pinned Go p99 or at most {args.max_absolute_slack_ns} ns above it; exact detection booleans and SQL fingerprints must match.",
        },
        "p99_gate_max_ratio": args.max_ratio,
        "p99_gate_max_absolute_slack_ns": args.max_absolute_slack_ns,
        "workloads": {
            "path": cases_path.relative_to(output_dir).as_posix(),
            "sha256": sha256(cases_path),
            "rows": sum(1 for _ in cases_path.open()),
            "sizes": sorted({size for _, size, _ in workload_manifest}),
            "cases_each_detector": {
                detector: sorted({case for found_detector, _, case in workload_manifest if found_detector == detector})
                for detector in DETECTORS
            },
            "cases": [
                {"detector": detector, "size": size, "case": case}
                for detector, size, case in workload_manifest
            ],
            "bytes": "fixed-length exact byte slices; binary rows include invalid UTF-8 and NUL bytes",
        },
        "run_pairs": all_rows,
        "summary": summary,
        "verdict_mismatches": verdict_mismatches,
        "confirmation_was_run": bool(second_rows),
        "initial_profile_failures": initial_profile_failures,
        "supported_profile_performance_open_issues": [
            row for row in summary["rows"] if not row["p99_gate_passed"]
        ],
        "overall_passed": not verdict_mismatches
        and all(row["p99_gate_passed"] for row in summary["rows"]),
    }
    output_path = args.output.resolve() if args.output else output_dir / "report.json"
    output_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"report: {output_path}")
    print(f"pinned Go: {go_version} ({go_head})")
    print(f"Rust: {report['rust']['rustc'].splitlines()[0]}")
    print(f"CPU: {cpu}; rounds: {len(all_rows) // (len(DETECTORS) * len(PROFILES))} paired sets")
    print(f"verdict mismatches: {len(verdict_mismatches)}")
    for row in summary["rows"]:
        status = "PASS" if row["p99_gate_passed"] else "FAIL"
        print(
            f"{status} {row['profile']} {row['detector']} {row['input_bytes']}B {row['case']}: "
            f"Rust p99={row['rust_p99_ns_median']}ns, Go p99={row['go_p99_ns_median']}ns, "
            f"ratio={row['rust_to_go_p99_ratio']}"
        )
    print(f"p99 gate: ratio <= {args.max_ratio}x or absolute excess <= {args.max_absolute_slack_ns}ns")
    print(f"overall gate: {'PASS' if report['overall_passed'] else 'FAIL'}")
    if report["supported_profile_performance_open_issues"]:
        print(
            "supported-profile p99 issues: "
            + str(len(report["supported_profile_performance_open_issues"]))
            + " (see JSON report; ratio and absolute thresholds were not changed)"
        )
    return 0 if report["overall_passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"performance run failed: {error}", file=sys.stderr)
        sys.exit(2)
