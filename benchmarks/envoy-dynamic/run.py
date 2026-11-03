#!/usr/bin/env python3
# Copyright Coraza Kubernetes Operator contributors.
# SPDX-License-Identifier: Apache-2.0

"""Run the paired Envoy no-WAF/Wasm/native comparison on the pinned host."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.client
import json
import math
import os
import pathlib
import platform
import re
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
ENVOY_IMAGE = os.environ.get("ENVOY_IMAGE", "")
MODULE_PATH = "/opt/envoy/modules/libenvoy_coraza_dynamic.so"
SIMPLE_REQUESTS = 120
LARGE_REQUESTS = 12
FRAGMENTED_REQUESTS = 32
HTTP2_REQUESTS = 60
CANCEL_REQUESTS = 24
CANCEL_BATCHES = 3
MULTIWORKER_REQUESTS = 60
CONCURRENCY = 16
BODY_BYTES = 512 * 1024
FRAGMENTED_BYTES = 64 * 1024


def run(
    command: list[str],
    *,
    cwd: pathlib.Path = ROOT,
    capture: bool = False,
    check: bool = True,
    timeout: float = 300,
) -> str:
    try:
        result = subprocess.run(command, cwd=cwd, check=check, text=True, capture_output=capture, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"command timed out after {timeout:g}s: {command!r}") from error
    return result.stdout if capture else ""


def require_file(path: pathlib.Path) -> None:
    if not path.is_file():
        raise SystemExit(f"required release artifact is missing: {path}")


def assert_ports_free() -> None:
    for port in (9901, 10001):
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise RuntimeError(f"port {port} is occupied; benchmark refused to start")


def policy_for(ruleset: str) -> str:
    common = [
        "SecRuleEngine On",
        "SecAuditEngine Off",
        "SecRequestBodyAccess On",
        "SecRequestBodyLimit 13107200",
        "SecRequestBodyInMemoryLimit 13107200",
        "SecRequestBodyLimitAction ProcessPartial",
        "SecResponseBodyAccess On",
        "SecResponseBodyLimit 1048576",
        "SecResponseBodyMimeType text/plain text/html application/json",
    ]
    if ruleset == "minimal":
        directives = common + [
            'SecAction "id:1,phase:1,ctl:requestBodyProcessor=RAW,pass"',
            'SecRule REQUEST_URI "@streq /phase1-deny" "id:2,phase:1,deny,status:403"',
            'SecRule REQUEST_BODY "@contains body-attack" "id:3,phase:2,deny,status:403"',
        ]
    else:
        directives = common + [
            'SecAction "id:900005,phase:1,nolog,pass,setvar:tx.arg_name_length=100,setvar:tx.arg_length=1048576,setvar:tx.total_arg_length=1048576,setvar:tx.max_num_args=255,setvar:tx.max_file_size=1048576,setvar:tx.combined_file_sizes=1048576"',
            'SecRule REQUEST_HEADERS:Content-Type "@rx ^application/json(?:\\s*;.*)?$" "id:200001,phase:1,pass,nolog,t:none,t:lowercase,ctl:requestBodyProcessor=JSON"',
        ]
        directives.extend([
            "Include crs/crs-setup.conf",
            "Include crs/rules/*.conf",
        ])
    return json.dumps(
        {
            "directives_map": {"benchmark": directives},
            "default_directives": "benchmark",
            "enable_filter_state_logs": False,
        },
        separators=(",", ":"),
    )


def wasm_filter(policy: str) -> str:
    lines = [
        '                  - name: envoy.filters.http.wasm',
        '                    typed_config:',
        '                      "@type": type.googleapis.com/udpa.type.v1.TypedStruct',
        '                      type_url: type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm',
        '                      value:',
        '                        config:',
        '                          name: coraza-dynamic-benchmark',
        '                          root_id: coraza-dynamic-benchmark',
        '                          failure_policy: FAIL_CLOSED',
        '                          allow_on_headers_stop_iteration: true',
        '                          vm_config:',
        '                            runtime: envoy.wasm.runtime.v8',
        '                            code:',
        '                              local:',
        '                                filename: /etc/envoy/filter.wasm',
        '                          configuration:',
        '                            "@type": type.googleapis.com/google.protobuf.StringValue',
        '                            value: |',
    ]
    lines.extend("                              " + line for line in policy.splitlines())
    return "\n".join(lines) + "\n"


def envoy_config(variant: str, policy: str, destination: pathlib.Path) -> None:
    source = (ROOT / "examples/envoy-coraza-dynamic/envoy.yaml").read_text()
    access_log = source.index("                access_log:\n")
    next_setting = source.index("                upgrade_configs:\n", access_log)
    source = source[:access_log] + source[next_setting:]
    filter_start = source.index("                  - name: envoy.filters.http.dynamic_modules\n")
    filter_end = source.index("                  - name: envoy.filters.http.router\n", filter_start)
    if variant == "native":
        block = source[filter_start:filter_end]
        placeholder = "                        value: '{}'\n"
        assert block.count(placeholder) == 1
        replacement = "                        value: |\n" + "".join(
            "                          " + line + "\n" for line in policy.splitlines()
        )
        block = block.replace(placeholder, replacement, 1)
    elif variant == "wasm":
        block = wasm_filter(policy)
    else:
        block = ""
    source = source[:filter_start] + block + source[filter_end:]
    destination.write_text(source)


def compose_file(
    path: pathlib.Path,
    config: pathlib.Path,
    variant: str,
    module: pathlib.Path,
    wasm: pathlib.Path,
    cpus: list[int],
) -> None:
    cpuset = f"{cpus[0]}" if len(cpus) == 1 else f"{cpus[0]},{cpus[-1]}"
    volumes = [f'      - "{config}:/etc/envoy/envoy.yaml:ro"']
    env = []
    if variant == "native":
        volumes.append(f'      - "{module}:{MODULE_PATH}:ro"')
        env = ["    environment:", "      ENVOY_DYNAMIC_MODULES_SEARCH_PATH: /opt/envoy/modules"]
    elif variant == "wasm":
        volumes.append(f'      - "{wasm}:/etc/envoy/filter.wasm:ro"')
    path.write_text(
        "\n".join(
            [
                "services:",
                "  backend:",
                "    image: coraza-rs-stage-f-bench-backend:local",
                f'    cpuset: "{cpuset}"',
                "  envoy:",
                f"    image: {ENVOY_IMAGE}",
                '    command: ["-c", "/etc/envoy/envoy.yaml", "--log-level", "critical", "--concurrency", "2"]',
                f'    cpuset: "{cpuset}"',
                *env,
                "    depends_on:",
                "      - backend",
                "    ports:",
                '      - "127.0.0.1:10001:10001"',
                '      - "127.0.0.1:9901:9901"',
                "    volumes:",
                *volumes,
            ]
        )
        + "\n"
    )


def wait_ready(timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen("http://127.0.0.1:9901/ready", timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(0.1)
    raise TimeoutError("Envoy did not become ready before the startup timeout")


def request(method: str, path: str, body: bytes = b"", content_type: str = "text/plain") -> tuple[int, float, int]:
    connection = http.client.HTTPConnection("127.0.0.1", 10001, timeout=30)
    started = time.perf_counter()
    try:
        headers = {"Host": "example.test"}
        if method == "POST":
            headers["Content-Type"] = content_type
        connection.request(method, path, body=body if method == "POST" else None, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        return response.status, (time.perf_counter() - started) * 1000, len(payload)
    finally:
        connection.close()


def fragmented_request() -> tuple[int, float, int]:
    payload = json_body(FRAGMENTED_BYTES)
    started = time.perf_counter()
    connection = socket.create_connection(("127.0.0.1", 10001), timeout=30)
    connection.settimeout(30)
    try:
        connection.sendall(
            b"POST /echo HTTP/1.1\r\nHost: example.test\r\n"
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        )
        for offset in range(0, len(payload), 16 * 1024):
            part = payload[offset : offset + 16 * 1024]
            connection.sendall(f"{len(part):X}\r\n".encode() + part + b"\r\n")
        connection.sendall(b"0\r\n\r\n")
        response = http.client.HTTPResponse(connection)
        response.begin()
        body = response.read()
        return response.status, (time.perf_counter() - started) * 1000, len(body)
    finally:
        connection.close()


def fragmented_requests(count: int) -> list[tuple[int, float, int]]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        return list(executor.map(lambda _: fragmented_request(), range(count)))


def json_body(size: int) -> bytes:
    prefix, suffix = b'{"body":"', b'"}'
    if size < len(prefix) + len(suffix):
        raise ValueError("JSON workload body is too small")
    return prefix + b"x" * (size - len(prefix) - len(suffix)) + suffix


def cancel_response() -> tuple[int, float, int]:
    connection = http.client.HTTPConnection("127.0.0.1", 10001, timeout=0.1)
    started = time.perf_counter()
    try:
        connection.request("GET", "/slow-response", headers={"Host": "example.test"})
        response = connection.getresponse()
        response.read(1)
        return response.status, (time.perf_counter() - started) * 1000, 1
    except (TimeoutError, OSError):
        return 0, (time.perf_counter() - started) * 1000, 0
    finally:
        connection.close()


def cancellation_count() -> int:
    connection = http.client.HTTPConnection("127.0.0.1", 10001, timeout=5)
    try:
        connection.request("GET", "/__stats?cancelled=%2Fslow-response")
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError(f"backend cancellation counter returned HTTP {response.status}")
        return int(response.read())
    finally:
        connection.close()


def http2_requests(count: int, trace_path: pathlib.Path) -> tuple[list[int], list[float], int]:
    command = [
        "curl",
        "--parallel",
        "--parallel-immediate",
        "--parallel-max",
        str(CONCURRENCY),
    ]
    if "--parallel-max-host" in run(["curl", "--help", "all"], capture=True):
        command.extend(["--parallel-max-host", "1"])
    command.extend(
        [
            "--max-time",
            "30",
            "--http2-prior-knowledge",
            "--resolve",
            "example.test:10001:127.0.0.1",
            "--silent",
            "--show-error",
            "--trace-ascii",
            str(trace_path),
        ]
    )
    url = "http://example.test:10001/healthy"
    for _ in range(count):
        command.extend(
            ["--url", url, "--output", os.devnull, "--write-out", "%{http_code} %{time_total}\n"]
        )
    started = time.perf_counter()
    output = run(command, capture=True)
    elapsed = time.perf_counter() - started
    statuses: list[int] = []
    latencies: list[float] = []
    for line in output.splitlines():
        status, duration = line.split()
        statuses.append(int(status))
        latencies.append(float(duration) * 1000)
    if len(statuses) != count:
        raise RuntimeError(f"HTTP/2 driver returned {len(statuses)} outcomes for {count} requests")
    streams = len(re.findall(r"\[\d+\] OPENED stream", trace_path.read_text(errors="replace")))
    if streams < 2:
        raise RuntimeError(f"HTTP/2 driver did not show multiplexed streams: {streams}")
    return statuses, latencies, streams


class ResourceSampler:
    def __init__(self, compose_file: pathlib.Path, project: str):
        ids = run(["docker", "compose", "-f", str(compose_file), "-p", project, "ps", "-q", "envoy"],
                  capture=True).split()
        if not ids:
            raise RuntimeError("cannot sample resources: Compose has no running Envoy container")
        self.pids = [
            int(run(["docker", "inspect", "--format", "{{.State.Pid}}", container], capture=True).strip())
            for container in ids
        ]
        self.clock_ticks = os.sysconf("SC_CLK_TCK")
        self.cgroups = []
        for pid in self.pids:
            memberships = pathlib.Path(f"/proc/{pid}/cgroup").read_text().splitlines()
            unified = next((line.partition("::")[2] for line in memberships if line.startswith("0::")), None)
            if unified is not None:
                path = pathlib.Path("/sys/fs/cgroup") / unified.lstrip("/")
                if (path / "cpu.stat").is_file():
                    self.cgroups.append(path)

    def cpu_seconds(self) -> float:
        if len(self.cgroups) == len(self.pids):
            microseconds = 0
            for cgroup in self.cgroups:
                stats = dict(line.split() for line in (cgroup / "cpu.stat").read_text().splitlines())
                microseconds += int(stats["usage_usec"])
            return microseconds / 1_000_000
        ticks = 0
        for pid in self.pids:
            fields = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            ticks += int(fields[11]) + int(fields[12])
        return ticks / self.clock_ticks

    def rss_bytes(self) -> int:
        total = 0
        for pid in self.pids:
            for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    total += int(line.split()[1]) * 1024
                    break
        return total

    def latest(self) -> dict:
        return {"memory_bytes": self.rss_bytes()}


def percentiles(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {
        f"p{percentile}": ordered[max(0, math.ceil(percentile / 100 * len(ordered)) - 1)]
        for percentile in (50, 95, 99)
    }


def sample_workload(sampler: ResourceSampler, action) -> dict:
    started = time.perf_counter()
    cpu_before = sampler.cpu_seconds()
    resource_samples = [{"elapsed_s": 0.0, "rss_bytes": sampler.rss_bytes()}]
    monitor_stop = threading.Event()

    def monitor() -> None:
        while not monitor_stop.wait(0.02):
            resource_samples.append(
                {"elapsed_s": time.perf_counter() - started, "rss_bytes": sampler.rss_bytes()}
            )

    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    try:
        result = action()
        if isinstance(result, tuple) and len(result) == 3 and isinstance(result[0], list):
            statuses, latencies, streams = result
        else:
            rows = list(result)
            statuses = [row[0] for row in rows]
            latencies = [row[1] for row in rows]
            streams = 0
    finally:
        monitor_stop.set()
        monitor_thread.join()
    elapsed = time.perf_counter() - started
    resource_samples.append({"elapsed_s": elapsed, "rss_bytes": sampler.rss_bytes()})
    cpu_seconds = max(0.0, sampler.cpu_seconds() - cpu_before)
    return {
        "requests": len(statuses),
        "status_counts": {str(status): statuses.count(status) for status in sorted(set(statuses))},
        "duration_s": elapsed,
        "throughput_rps": len(statuses) / elapsed,
        "latency_ms": percentiles(latencies),
        "latencies_ms": latencies,
        "cpu_seconds": cpu_seconds,
        "cpu_avg_percent": cpu_seconds / elapsed * 100,
        "rss_peak_bytes": max(point["rss_bytes"] for point in resource_samples),
        "resource_sample_count": len(resource_samples),
        "resource_samples": resource_samples,
        "http2_streams": streams,
    }


def check_status(result: dict, expected: int, label: str) -> None:
    counts = result["status_counts"]
    if counts != {str(expected): result["requests"]}:
        raise RuntimeError(f"{label}: got status counts {counts}, expected only HTTP {expected}")


def check_status_counts(result: dict, expected: dict[str, int], label: str) -> None:
    if result["status_counts"] != expected:
        raise RuntimeError(f"{label}: got status counts {result['status_counts']}, expected {expected}")


def preflight(ruleset: str, variant: str) -> dict:
    if ruleset == "minimal":
        early = "/phase1-deny"
        late_body = b"body-attack"
        late_type = "text/plain"
    else:
        early = "/crs-sqli?q=1%27%20OR%201%3D1"
        late_body = b"id=1%27+OR+1%3D1"
        late_type = "application/x-www-form-urlencoded"
    expect = 200 if variant == "control" else 403
    checks = {
        "allow": request("GET", "/healthy")[0],
        "early_deny": request("GET", early)[0],
        "late_deny": request("POST", "/echo", late_body, late_type)[0],
    }
    expected = {"allow": 200, "early_deny": expect, "late_deny": expect}
    if checks != expected:
        raise RuntimeError(f"{ruleset}/{variant} correctness preflight mismatch: {checks}, expected {expected}")
    return {"observed": checks, "expected": expected}


def run_load(ruleset: str, variant: str, sampler: ResourceSampler, temp: pathlib.Path) -> list[dict]:
    if ruleset == "minimal":
        early_path = "/phase1-deny"
        late_body = b"body-attack"
        late_type = "text/plain"
    else:
        early_path = "/crs-sqli?q=1%27%20OR%201%3D1"
        late_body = b"id=1%27+OR+1%3D1"
        late_type = "application/x-www-form-urlencoded"
    deny_expected = 200 if variant == "control" else 403
    allow_expected = 200
    payload_small = json_body(1024)
    payload_large = json_body(BODY_BYTES)

    def concurrent_requests(count: int, method: str, path: str, body: bytes = b"", content_type: str = "text/plain"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            return list(executor.map(lambda _: request(method, path, body, content_type), range(count)))

    workloads = [
        (
            "benign-pass",
            lambda: concurrent_requests(SIMPLE_REQUESTS, "GET", "/healthy"),
            allow_expected,
        ),
        (
            "early-denial",
            lambda: concurrent_requests(SIMPLE_REQUESTS, "GET", early_path),
            deny_expected,
        ),
        (
            "late-denial",
            lambda: concurrent_requests(SIMPLE_REQUESTS, "POST", "/echo", late_body, late_type),
            deny_expected,
        ),
        (
            "small-body",
            lambda: concurrent_requests(SIMPLE_REQUESTS, "POST", "/reflect", payload_small, "application/json"),
            allow_expected,
        ),
        (
            "large-body",
            lambda: concurrent_requests(LARGE_REQUESTS, "POST", "/reflect", payload_large, "application/json"),
            allow_expected,
        ),
        (
            "fragmented-upload",
            lambda: fragmented_requests(FRAGMENTED_REQUESTS),
            allow_expected,
        ),
    ]

    results = []
    for name, action, expected in workloads:
        stats = sample_workload(sampler, action)
        check_status(stats, expected, name)
        stats["name"] = name
        results.append(stats)

    def multiworker_isolation():
        requests = [("GET", early_path)] * MULTIWORKER_REQUESTS + [("GET", "/healthy")] * MULTIWORKER_REQUESTS
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            return list(executor.map(lambda item: request(item[0], item[1]), requests))

    multiworker = sample_workload(sampler, multiworker_isolation)
    expected_multiworker = (
        {"200": 2 * MULTIWORKER_REQUESTS}
        if variant == "control"
        else {"200": MULTIWORKER_REQUESTS, "403": MULTIWORKER_REQUESTS}
    )
    check_status_counts(multiworker, expected_multiworker, "multi-worker deny/allow isolation")
    multiworker["name"] = "multi-worker-isolation"
    results.append(multiworker)

    def cancel_batch():
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            return list(executor.map(lambda _: cancel_response(), range(CANCEL_REQUESTS)))

    cancellation_expected = 200 if variant == "control" else 0
    for batch_index in range(CANCEL_BATCHES):
        before_cancellations = cancellation_count()
        cancelled = sample_workload(sampler, cancel_batch)
        check_status(cancelled, cancellation_expected, "response-cancellation")
        deadline = time.monotonic() + 5
        after_cancellations = before_cancellations
        while time.monotonic() < deadline:
            after_cancellations = cancellation_count()
            if after_cancellations >= before_cancellations + CANCEL_REQUESTS:
                break
            time.sleep(0.05)
        if after_cancellations < before_cancellations + CANCEL_REQUESTS:
            raise RuntimeError(
                f"only {after_cancellations - before_cancellations}/{CANCEL_REQUESTS} upstream response resets were observed"
            )
        cancelled["name"] = f"response-cancellation-batch-{batch_index + 1}"
        cancelled["backend_upstream_resets"] = after_cancellations - before_cancellations
        time.sleep(0.5)
        cancelled["rss_recovery_bytes"] = sampler.latest()["memory_bytes"]
        results.append(cancelled)

    trace = temp / "http2.trace"
    stats = sample_workload(
        sampler,
        lambda: http2_requests(HTTP2_REQUESTS, trace),
    )
    check_status(stats, allow_expected, "http2-concurrency")
    stats["name"] = "http2-concurrency"
    results.append(stats)
    return results


def benchmark_variant(
    ruleset: str,
    variant: str,
    repetition: int,
    order_index: int,
    module: pathlib.Path,
    wasm: pathlib.Path,
    cpus: list[int],
) -> dict:
    assert_ports_free()
    policy = policy_for(ruleset)
    project = f"coraza-stagef-bench-{uuid.uuid4().hex[:10]}"
    with tempfile.TemporaryDirectory(prefix="coraza-stagef-bench-") as directory:
        temp = pathlib.Path(directory)
        config = temp / "envoy.yaml"
        compose = temp / "compose.yaml"
        envoy_config(variant, policy, config)
        compose_file(compose, config, variant, module, wasm, cpus)
        compose_command = ["docker", "compose", "-f", str(compose), "-p", project]
        started = time.perf_counter()
        try:
            run([*compose_command, "up", "--detach"])
            wait_ready()
            startup = time.perf_counter() - started
            checks = preflight(ruleset, variant)
            sampler = ResourceSampler(compose, project)
            workloads = run_load(ruleset, variant, sampler, temp)
            return {
                "ruleset": ruleset,
                "variant": variant,
                "repetition": repetition,
                "order_index": order_index,
                "workers": 2,
                "startup_configure_s": startup,
                "preflight": checks,
                "policy_sha256": hashlib.sha256(policy.encode()).hexdigest(),
                "workloads": workloads,
            }
        finally:
            try:
                run([*compose_command, "down", "--volumes"], check=False, capture=True, timeout=30)
            except RuntimeError as error:
                print(f"warning: benchmark cleanup failed: {error}", file=sys.stderr)


def summarize(records: list[dict]) -> list[dict]:
    summary = []
    groups = sorted({(record["ruleset"], record["variant"]) for record in records})
    for ruleset, variant in groups:
        group = [r for r in records if r["ruleset"] == ruleset and r["variant"] == variant]
        metrics = {
            "startup_configure_s": [r["startup_configure_s"] for r in group],
        }
        for record in group:
            for workload in record["workloads"]:
                prefix = f"workload:{workload['name']}:"
                metrics.setdefault(prefix + "throughput_rps", []).append(workload["throughput_rps"])
                metrics.setdefault(prefix + "p50_ms", []).append(workload["latency_ms"]["p50"])
                metrics.setdefault(prefix + "p95_ms", []).append(workload["latency_ms"]["p95"])
                metrics.setdefault(prefix + "p99_ms", []).append(workload["latency_ms"]["p99"])
                metrics.setdefault(prefix + "cpu_avg_percent", []).append(workload["cpu_avg_percent"])
                metrics.setdefault(prefix + "rss_peak_bytes", []).append(workload["rss_peak_bytes"])
                if "backend_upstream_resets" in workload:
                    metrics.setdefault(prefix + "backend_upstream_resets", []).append(
                        workload["backend_upstream_resets"]
                    )
                    metrics.setdefault(prefix + "rss_recovery_bytes", []).append(
                        workload["rss_recovery_bytes"]
                    )
        summary.append(
            {
                "ruleset": ruleset,
                "variant": variant,
                "repetitions": len(group),
                "metrics": {
                    key: {
                        "median": statistics.median(numeric),
                        "min": min(numeric),
                        "max": max(numeric),
                    }
                    for key, values in sorted(metrics.items())
                    if (numeric := [value for value in values if value is not None])
                },
            }
        )
    return summary


def write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def artifact_identity(path: pathlib.Path) -> dict:
    manifest_path = path.with_suffix(".provenance.json")
    identity = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text())
        identity["provenance"] = {
            key: manifest[key]
            for key in ("target", "rust_version", "clang_version", "enabled_features", "sdk_commit")
        }
    return identity


def main() -> None:
    global ENVOY_IMAGE
    if not ENVOY_IMAGE:
        ENVOY_IMAGE = run(["make", "--no-print-directory", "print-envoy-image"], capture=True).strip()
    if not ENVOY_IMAGE:
        raise SystemExit("make print-envoy-image returned an empty pin")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-default", type=pathlib.Path, required=True)
    parser.add_argument("--native-crs", type=pathlib.Path, required=True)
    parser.add_argument("--wasm-default", type=pathlib.Path, required=True)
    parser.add_argument("--wasm-crs", type=pathlib.Path, required=True)
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=ROOT / "docs/performance/envoy-coraza-dynamic-stage-f/benchmark-raw.json",
    )
    args = parser.parse_args()
    args.native_default = args.native_default.resolve()
    args.native_crs = args.native_crs.resolve()
    args.wasm_default = args.wasm_default.resolve()
    args.wasm_crs = args.wasm_crs.resolve()
    modules = {
        "minimal": {"native": args.native_default, "wasm": args.wasm_default},
        "crs": {"native": args.native_crs, "wasm": args.wasm_crs},
    }
    for ruleset, variants in modules.items():
        for variant, path in variants.items():
            require_file(path)
    curl_version = run(["curl", "--version"], capture=True)
    if "HTTP2" not in curl_version:
        raise SystemExit("curl with HTTP/2 support is required")
    docker_version = run(["docker", "buildx", "version"], capture=True).strip()
    run(["docker", "pull", ENVOY_IMAGE], timeout=900)
    available = sorted(os.sched_getaffinity(0))
    cpus = available[:2]
    if not cpus:
        raise SystemExit("no available CPU affinity set")
    os.sched_setaffinity(0, {cpus[0]})

    backend_image = "coraza-rs-stage-f-bench-backend:local"
    run(
        [
            "docker",
            "build",
            "--tag",
            backend_image,
            "--file",
            str(ROOT / "examples/envoy-coraza/Dockerfile"),
            str(ROOT / "examples/envoy-coraza"),
        ]
    )
    diff = run(["git", "diff", "--binary", "HEAD"], capture=True)
    meta = {
        "repository_revision": run(["git", "rev-parse", "HEAD"], capture=True).strip(),
        "working_tree_dirty": bool(run(["git", "status", "--porcelain"], capture=True).strip()),
        "tracked_diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
        "benchmark_runner_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
        "envoy_image": ENVOY_IMAGE,
        "sdk_commit": "9e5580933739775e8bce696a57a2e1bc99368f23",
        "crs_pin": (ROOT / "envoy-coraza/crs.pin").read_text().strip(),
        "crs_test_checkout_commit": "e03a4f6dabc7a30ebd8c52c97d28a154f590a48f",
        "artifacts": {
            "native_default": artifact_identity(args.native_default),
            "native_crs": artifact_identity(args.native_crs),
            "wasm_default": artifact_identity(args.wasm_default),
            "wasm_crs": artifact_identity(args.wasm_crs),
        },
        "host_toolchain": {
            "rustc": run(["rustc", "--version"], capture=True).strip(),
            "clang": run(["clang", "--version"], capture=True).splitlines()[0],
            "cargo": run(["cargo", "--version"], capture=True).strip(),
        },
        "docker_buildx": docker_version,
        "host": {"system": platform.platform(), "machine": platform.machine(), "cpus": cpus},
        "offered_load": {
            "concurrency": CONCURRENCY,
            "workers": 2,
            "simple_requests_per_workload": SIMPLE_REQUESTS,
            "large_body_requests": LARGE_REQUESTS,
            "large_body_bytes": BODY_BYTES,
            "fragmented_upload_requests": FRAGMENTED_REQUESTS,
            "fragmented_upload_bytes": FRAGMENTED_BYTES,
            "http2_requests": HTTP2_REQUESTS,
            "response_cancellations": CANCEL_REQUESTS,
            "response_cancellation_batches": CANCEL_BATCHES,
            "multiworker_isolation_pairs": MULTIWORKER_REQUESTS,
        },
        "backend_image": backend_image,
        "backend_image_id": run(["docker", "image", "inspect", "--format", "{{.Id}}", backend_image], capture=True).strip(),
        "repetition_order": [
            ["control", "wasm", "native"],
            ["native", "control", "wasm"],
            ["wasm", "native", "control"],
        ],
    }
    records: list[dict] = []
    order = meta["repetition_order"]
    variant_paths = {
        "minimal": {"native": args.native_default, "wasm": args.wasm_default},
        "crs": {"native": args.native_crs, "wasm": args.wasm_crs},
    }
    for ruleset in ("minimal", "crs"):
        for repetition, variants in enumerate(order, start=1):
            for order_index, variant in enumerate(variants):
                module = variant_paths[ruleset]["native"]
                wasm = variant_paths[ruleset]["wasm"]
                record = benchmark_variant(
                    ruleset,
                    variant,
                    repetition,
                    order_index,
                    module,
                    wasm,
                    cpus,
                )
                records.append(record)
                write_json(args.output, {"metadata": meta, "records": records})
                print(f"completed {ruleset} repetition {repetition} variant {variant}", flush=True)
                time.sleep(0.5)
    summary_path = args.output.with_name("benchmark-summary.json")
    write_json(summary_path, {"metadata": meta, "summary": summarize(records)})
    print(f"wrote raw results to {args.output} and medians/ranges to {summary_path}")


if __name__ == "__main__":
    main()
