#!/usr/bin/env python3
# Copyright Coraza Kubernetes Operator contributors.
# SPDX-License-Identifier: Apache-2.0

"""Run native Envoy, packaged-image, FTW and rollback checks."""

from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import hashlib
import http.client
import http.server
import json
import os
import pathlib
import re
import select
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples/envoy-coraza-dynamic"
COMPOSE_FILE = EXAMPLE / "compose.yaml"
COMMAND_TIMEOUT = 900


class CommandTimeout(RuntimeError):
    pass


def command(args: list[str], *, cwd: pathlib.Path = ROOT, env: dict[str, str] | None = None,
            capture: bool = False, check: bool = True,
            timeout: float = COMMAND_TIMEOUT) -> subprocess.CompletedProcess:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    try:
        result = subprocess.run(
            args, cwd=cwd, env=merged, text=True, capture_output=capture, check=False, timeout=timeout
        )
    except subprocess.TimeoutExpired as error:
        raise CommandTimeout(f"command timed out after {timeout:g}s: {args!r}") from error
    if check and result.returncode:
        detail = "\n".join(part for part in (result.stdout, result.stderr) if part)
        raise RuntimeError(f"command failed ({result.returncode}): {args!r}\n{detail[-6000:]}")
    return result


class Compose:
    def __init__(self, compose_file: pathlib.Path, project: str, env: dict[str, str] | None = None):
        self.prefix = ["docker", "compose", "-f", str(compose_file), "-p", project]
        self.env = env or {}

    def run(self, *args: str, env: dict[str, str] | None = None,
            capture: bool = False, check: bool = True,
            timeout: float = COMMAND_TIMEOUT) -> subprocess.CompletedProcess:
        return command([*self.prefix, *args], env={**self.env, **(env or {})},
                       capture=capture, check=check, timeout=timeout)

    def logs(self, service: str) -> str:
        return self.run("logs", "--no-color", "--no-log-prefix", service,
                        capture=True, check=False, timeout=10).stdout

    def down(self) -> None:
        self.run("down", "--volumes", capture=True, check=False, timeout=60)


def assert_ports_free(ports: tuple[int, ...] = (9901, 10001), timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while True:
        occupied = []
        for port in ports:
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    occupied.append(port)
        if not occupied:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"ports {occupied} are occupied; refusing to start Envoy tests")
        time.sleep(1)


def wait_ready(timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen("http://127.0.0.1:9901/ready", timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("Envoy did not become ready with the native filter installed")


def request(path: str, *, method: str = "GET", headers: dict[str, str] | None = None,
            body: bytes | None = None, timeout: float = 20,
            port: int = 10001) -> tuple[int, list[tuple[str, str]], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.getheaders(), response.read()
    finally:
        connection.close()


def backend_count(path: str, port: int = 10001) -> int:
    query = urllib.parse.urlencode({"path": path})
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", f"/__stats?{query}", headers={"Host": "stats.local"})
        response = connection.getresponse()
        return int(response.read())
    finally:
        connection.close()


def assert_status(actual: int, expected: int, label: str) -> None:
    if actual != expected:
        raise RuntimeError(f"{label}: HTTP {actual}, expected {expected}")


def assert_body(actual: bytes, expected: bytes, label: str) -> None:
    if actual != expected:
        actual_hash = hashlib.sha256(actual).hexdigest()
        expected_hash = hashlib.sha256(expected).hexdigest()
        raise RuntimeError(
            f"{label}: byte mismatch (actual {len(actual)} bytes sha256={actual_hash}; "
            f"expected {len(expected)} bytes sha256={expected_hash})"
        )


def assert_no_upstream_leak(headers: list[tuple[str, str]], body: bytes, label: str) -> None:
    combined = "\n".join(f"{key}: {value}" for key, value in headers).encode() + body
    forbidden = (b"x-upstream-secret", b"upstream-secret=", b"secret upstream", b"upstream-trailer-marker",
                 b"x-backend-trailer", b"secret trailer response", b"leak-marker", b"x-large-probe")
    if any(token.lower() in combined.lower() for token in forbidden):
        raise RuntimeError(f"{label}: upstream data leaked")


def write_body(path: pathlib.Path, size: int, byte: bytes) -> bytes:
    body = byte * size
    path.write_bytes(body)
    return body


def wait_backend(compose: Compose) -> None:
    for _ in range(30):
        if "backend listening on" in compose.logs("backend"):
            return
        time.sleep(0.1)
    raise RuntimeError("backend did not start")


def require_access_log(compose: Compose, path: str, expected: str) -> None:
    for _ in range(100):
        lines = [line for line in compose.logs("envoy").splitlines()
                 if f"path={path} " in line]
        if lines and expected in lines[-1]:
            return
        time.sleep(0.1)
    raise RuntimeError(f"Envoy access log for {path} did not contain {expected!r}")


def module_policy() -> dict:
    return {
        "directives_map": {
            "main": [
                "SecRuleEngine On", "SecAuditEngine RelevantOnly", "SecAuditLogFormat JSON",
                "SecRequestBodyAccess On", "SecRequestBodyLimit 16777216",
                "SecResponseBodyAccess On", "SecResponseBodyLimit 1048576",
                "SecResponseBodyMimeType text/plain",
                'SecAction "id:1,phase:1,ctl:requestBodyProcessor=RAW,pass"',
                'SecRule REQUEST_URI "@contains phase1-deny" "id:2,phase:1,deny,status:451"',
                'SecRule REQUEST_BODY "@contains body-attack" "id:3,phase:2,deny,status:429"',
                'SecRule REQUEST_BODY "@contains request-crlf-redirect" "id:14,phase:2,redirect:https://example.test/blocked?value=%{REQUEST_BODY},status:307"',
                'SecRule REQUEST_URI "@contains redirect-deny" "id:4,phase:1,redirect:https://example.test/blocked,status:307"',
                'SecRule REQUEST_URI "@contains no-content" "id:5,phase:1,deny,status:204"',
                'SecRule REQUEST_URI "@contains not-modified" "id:6,phase:1,deny,status:304"',
                'SecRule RESPONSE_BODY "@contains secret" "id:8,phase:4,deny,status:451,auditlog,msg:\'stage-d-response-audit\'"',
                'SecRule RESPONSE_HEADERS:x-deny-response "@streq yes" "id:9,phase:4,deny,status:452"',
                'SecRule RESPONSE_BODY "@contains response-redirect" "id:10,phase:4,redirect:https://example.test/response-blocked,status:307"',
                'SecRule RESPONSE_BODY "@contains response-crlf-redirect" "id:15,phase:4,redirect:https://example.test/blocked?value=%{RESPONSE_BODY},status:307"',
            ],
            "off": [
                "SecRuleEngine On", "SecResponseBodyAccess Off",
                'SecRule RESPONSE_HEADERS:x-deny-response "@streq yes" "id:11,phase:4,deny,status:452"',
            ],
            "head": [
                "SecRuleEngine On",
                'SecRule RESPONSE_HEADERS:x-upstream-secret "@streq upstream-header-marker" "id:12,phase:3,deny,status:204"',
            ],
            "not-modified": [
                "SecRuleEngine On",
                'SecRule RESPONSE_HEADERS:x-upstream-secret "@streq upstream-header-marker" "id:13,phase:3,deny,status:304"',
            ],
            "limit": [
                "SecRuleEngine On", "SecResponseBodyAccess On", "SecResponseBodyLimit 5",
                "SecResponseBodyLimitAction Reject", "SecResponseBodyMimeType text/plain",
            ],
            "stats": ["SecRuleEngine Off"],
            "boundary": [
                "SecRuleEngine On", "SecRequestBodyAccess On", "SecRequestBodyLimit 32",
                "SecRequestBodyLimitAction Reject", "SecResponseBodyAccess On",
                "SecResponseBodyLimit 32", "SecResponseBodyLimitAction Reject",
                "SecResponseBodyMimeType text/plain",
                'SecAction "id:31,phase:1,ctl:requestBodyProcessor=RAW,pass"',
            ],
            "partial": [
                "SecRuleEngine On", "SecRequestBodyAccess On", "SecRequestBodyLimit 32",
                "SecRequestBodyLimitAction ProcessPartial", "SecResponseBodyAccess On",
                "SecResponseBodyLimit 32", "SecResponseBodyLimitAction ProcessPartial",
                "SecResponseBodyMimeType text/plain",
                'SecAction "id:32,phase:1,ctl:requestBodyProcessor=RAW,pass"',
                'SecRule REQUEST_BODY "@contains partial-marker" "id:33,phase:2,deny,status:429"',
                'SecRule RESPONSE_BODY "@contains partial-marker" "id:34,phase:4,deny,status:451"',
            ],
        },
        "default_directives": "main",
        "per_authority_directives": {
            "off.local": "off", "head.local": "head", "not-modified.local": "not-modified",
            "limit.local": "limit", "stats.local": "stats", "boundary.local": "boundary",
            "partial.local": "partial",
        },
        "enable_filter_state_logs": True,
    }


def write_bootstrap(path: pathlib.Path, policy: dict | str, *, second_policy: dict | str | None = None,
                    invalid_utf8: bool = False) -> None:
    text = (EXAMPLE / "envoy.yaml").read_text()
    placeholder = "                        value: '{}'"
    if text.count(placeholder) != 1:
        raise RuntimeError("expected one native filter configuration placeholder")
    if invalid_utf8:
        text = text.replace("google.protobuf.StringValue", "google.protobuf.BytesValue", 1)
        text = text.replace(placeholder, '                        value: "/w=="', 1)
    else:
        encoded = policy if isinstance(policy, str) else json.dumps(policy, indent=2)
        value = "                        value: |\n" + "".join(
            "                          " + line + "\n" for line in encoded.splitlines()
        )
        text = text.replace(placeholder, value.rstrip("\n"), 1)
    if second_policy is not None:
        router = "                  - name: envoy.filters.http.router"
        second = second_policy if isinstance(second_policy, str) else json.dumps(second_policy, indent=2)
        block = (
            "                  - name: envoy.filters.http.dynamic_modules\n"
            "                    typed_config:\n"
            '                      "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter\n'
            "                      dynamic_module_config:\n"
            "                        name: envoy_coraza_dynamic\n"
            "                        do_not_close: true\n"
            "                        load_globally: false\n"
            "                      filter_name: coraza\n"
            "                      filter_config:\n"
            '                        "@type": type.googleapis.com/google.protobuf.StringValue\n'
            "                        value: |\n"
            + "".join("                          " + line + "\n" for line in second.splitlines())
        )
        if text.count(router) != 1:
            raise RuntimeError("expected one router filter in Envoy config")
        text = text.replace(router, block + router, 1)
    path.write_text(text)


def run_curl_h2(work: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    trace, status = work / "http2.trace", work / "http2.status"
    max_host = ["--parallel-max-host", "1"] if "--parallel-max-host" in command(
        ["curl", "--help", "all"], capture=True
    ).stdout else []
    result = command([
        "curl", "--parallel", *max_host, "--http2-prior-knowledge",
        "--trace-ascii", str(trace), "--silent", "--show-error",
        "--output", str(work / "http2-deny"), "--write-out", "deny %{http_version} %{http_code}\\n",
        "http://127.0.0.1:10001/phase1-deny", "--next", *max_host,
        "--http2-prior-knowledge", "--silent", "--show-error", "--output", str(work / "http2-allow"),
        "--write-out", "allow %{http_version} %{http_code}\\n", "--request", "POST",
        "--header", "content-type: application/octet-stream", "--data-binary", f"@{work / 'http2-expected'}",
        "http://127.0.0.1:10001/echo",
    ], cwd=work, capture=True)
    status.write_text(result.stdout)
    return trace, status


def abort_held_upload() -> None:
    connection = socket.create_connection(("127.0.0.1", 10001), timeout=10)
    try:
        connection.sendall(
            b"POST /cancel-upload HTTP/1.1\r\nHost: example.test\r\n"
            b"Content-Type: application/octet-stream\r\nContent-Length: 8388608\r\n"
            b"Connection: close\r\n\r\n"
        )
        for _ in range(32):
            connection.sendall(b"x" * (64 * 1024))
            time.sleep(0.01)
        readable, _, _ = select.select([connection], [], [], 0.5)
        if readable and connection.recv(4096):
            raise RuntimeError("Envoy responded before the upload reached EOS")
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    finally:
        connection.close()


def exhaust_admission() -> None:
    held: list[socket.socket] = []
    try:
        for index in range(5):
            connection = socket.create_connection(("127.0.0.1", 10001), timeout=30)
            connection.settimeout(30)
            held.append(connection)
            connection.sendall(
                f"POST /admission-{index} HTTP/1.1\r\n".encode()
                + b"Host: example.test\r\nContent-Type: application/octet-stream\r\n"
                + b"Content-Length: 15728640\r\nConnection: close\r\n\r\n"
            )
            chunk = b"a" * (64 * 1024)
            for _ in range(13 * 16):
                try:
                    connection.sendall(chunk)
                except OSError:
                    break
            if index == 4:
                response = bytearray()
                while b"\r\n" not in response:
                    data = connection.recv(1024)
                    if not data:
                        break
                    response.extend(data)
                if b" 503 " not in response:
                    raise RuntimeError(f"admission exhaustion was not denied with 503: {response!r}")
    finally:
        for connection in held:
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            connection.close()


class EnvoyTest:
    def __init__(self, work: pathlib.Path):
        self.work = work
        self.project = f"envoy-coraza-dynamic-test-{os.getpid()}"
        self.compose = Compose(COMPOSE_FILE, self.project)
        self.target_dir = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", "target"))
        if not self.target_dir.is_absolute():
            self.target_dir = ROOT / self.target_dir
        self.temp_modules: list[pathlib.Path] = []
        self.extra_target_dirs: list[pathlib.Path] = []

    def build_module(self, *, features: str = "", label: str) -> str:
        if features:
            target = self.target_dir / f"dynamic-test-{label}-{uuid.uuid4().hex}"
            self.extra_target_dirs.append(target)
            command(["cargo", "build", "--locked", "--release", "-p", "envoy-coraza-dynamic",
                     "--features", features, "--target-dir", str(target)], capture=True)
            source = target / "release/libenvoy_coraza_dynamic.so"
        else:
            command(["make", "--no-print-directory", "-C", str(ROOT), "build-envoy-dynamic"],
                    env={"CARGO_TARGET_DIR": str(self.target_dir)}, capture=True)
            source = self.target_dir / "release/libenvoy_coraza_dynamic.so"
        (ROOT / "target").mkdir(exist_ok=True)
        target = ROOT / "target" / f"envoy-coraza-dynamic-{label}-{os.getpid()}-{uuid.uuid4().hex[:6]}.so"
        shutil.copyfile(source, target)
        self.temp_modules.append(target)
        return "target/" + target.name

    def module_env(self, relative: str) -> dict[str, str]:
        return {"ENVOY_CORAZA_DYNAMIC_MODULE": relative}

    def build_stack(self, module: str) -> None:
        self.compose.run("build", "backend", "envoy", env=self.module_env(module), capture=True)
        self.compose.run("up", "--detach", "backend", capture=True)
        wait_backend(self.compose)

    def build_envoy(self, module: str) -> None:
        self.compose.run("build", "envoy", env=self.module_env(module), capture=True)

    def start(self, config: pathlib.Path, *, concurrency: int = 0, module: str | None = None) -> None:
        self.compose.down()
        env = {"ENVOY_CORAZA_DYNAMIC_CONFIG": str(config),
               "ENVOY_CORAZA_DYNAMIC_CONCURRENCY": str(concurrency)}
        if module:
            env.update(self.module_env(module))
        self.compose.run("up", "--detach", env=env, capture=True)
        wait_backend(self.compose)
        wait_ready()

    def cleanup(self) -> None:
        self.compose.down()
        for module in self.temp_modules:
            module.unlink(missing_ok=True)
        for target in self.extra_target_dirs:
            shutil.rmtree(target, ignore_errors=True)


def raw_response_status(request_bytes: bytes, *, port: int = 10001) -> bytes:
    connection = socket.create_connection(("127.0.0.1", port), timeout=15)
    try:
        connection.sendall(request_bytes)
        response = bytearray()
        while b"\r\n" not in response:
            data = connection.recv(4096)
            if not data:
                break
            response.extend(data)
        return bytes(response)
    finally:
        connection.close()


def check_startup_rejected(compose: Compose, label: str, config: pathlib.Path,
                           module_dir: pathlib.Path | None = None) -> None:
    args = ["run", "--rm", "--no-deps", "--service-ports"]
    if module_dir is not None:
        args.extend(["--volume", f"{module_dir}:/opt/envoy/modules:ro"])
    args.append("envoy")
    try:
        result = compose.run(*args, env={"ENVOY_CORAZA_DYNAMIC_CONFIG": str(config)},
                             capture=True, check=False, timeout=30)
    except CommandTimeout as error:
        raise RuntimeError(f"{label}: Envoy timed out instead of rejecting invalid configuration") from error
    if result.returncode == 0:
        raise RuntimeError(f"{label}: Envoy unexpectedly accepted invalid module/config")
    try:
        status, _, _ = request("/should-not-be-unfiltered", timeout=1)
    except (OSError, http.client.HTTPException, TimeoutError):
        status = 0
    if status == 200:
        raise RuntimeError(f"{label}: rejected config served unfiltered traffic")
    print(f"negative-control {label}: startup rejected, probe HTTP {status}")


def assert_admission_released(label: str, expected: bytes) -> None:
    held: list[socket.socket] = []
    chunk = b"a" * (64 * 1024)
    try:
        for index in range(3):
            connection = socket.create_connection(("127.0.0.1", 10001), timeout=30)
            connection.settimeout(30)
            held.append(connection)
            size = 13 * 1024 * 1024 + 1
            connection.sendall(
                f"POST /admission-pressure-{label}-{index} HTTP/1.1\r\n".encode()
                + b"Host: example.test\r\nContent-Type: application/octet-stream\r\n"
                + f"Content-Length: {size}\r\nConnection: close\r\n\r\n".encode()
            )
            for _ in range(13 * 16):
                connection.sendall(chunk)
        time.sleep(0.2)
        status, _, _ = request("/echo", method="POST", body=b"p" * (8 * 1024 * 1024 + 512 * 1024 + 1),
                               headers={"Host": "example.test", "Content-Type": "application/octet-stream"})
        if status != 503:
            raise RuntimeError(f"{label}: admission pressure not established; got {status}, expected 503")
        time.sleep(0.5)
        status, _, body = request("/echo", method="POST", body=expected,
                                  headers={"Host": "example.test", "Content-Type": "application/octet-stream"})
        if status != 200:
            raise RuntimeError(f"{label}: reservation recovery got HTTP {status}")
        assert_body(body, expected, f"{label} admission recovery")
    finally:
        for connection in held:
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            connection.close()


def test_envoy() -> None:
    assert_ports_free()
    if "HTTP2" not in command(["curl", "--version"], capture=True).stdout:
        raise RuntimeError("curl with HTTP/2 support is required")
    print("Running native Envoy integration checks")
    with tempfile.TemporaryDirectory(prefix="coraza-dynamic-") as directory:
        work = pathlib.Path(directory)
        harness = EnvoyTest(work)
        try:
            command(["make", "--no-print-directory", "-C", str(ROOT), "crs-fetch"], capture=True)
            default_module = harness.build_module(label="default")
            phase = module_policy()
            bootstrap = work / "phase.yaml"
            write_bootstrap(bootstrap, phase)
            harness.build_stack(default_module)

            for label, content in (("missing-library", None), ("corrupt-library", b"not an ELF shared object\n")):
                modules = work / label
                modules.mkdir()
                if content is not None:
                    (modules / "libenvoy_coraza_dynamic.so").write_bytes(content)
                check_startup_rejected(harness.compose, label, EXAMPLE / "envoy.yaml", modules)

            wrong_arch = work / "wrong-architecture"
            wrong_arch.mkdir()
            shutil.copyfile(harness.target_dir / "release/libenvoy_coraza_dynamic.so",
                            wrong_arch / "libenvoy_coraza_dynamic.so")
            with (wrong_arch / "libenvoy_coraza_dynamic.so").open("r+b") as library:
                ident = library.read(20)
                if ident[:4] != b"\x7fELF" or ident[5] not in (1, 2):
                    raise RuntimeError("built module is not a supported ELF file")
                endian = "little" if ident[5] == 1 else "big"
                library.seek(18)
                library.write((183 if int.from_bytes(ident[18:20], endian) == 62 else 62).to_bytes(2, endian))
            check_startup_rejected(harness.compose, "wrong-architecture", EXAMPLE / "envoy.yaml", wrong_arch)

            unknown = work / "unknown-filter.yaml"
            write_bootstrap(unknown, {})
            unknown.write_text(unknown.read_text().replace("filter_name: coraza", "filter_name: unknown", 1))
            check_startup_rejected(harness.compose, "unknown-filter", unknown)
            malformed = work / "malformed-json.yaml"
            write_bootstrap(malformed, "not-json")
            check_startup_rejected(harness.compose, "malformed-json", malformed)
            invalid_utf8 = work / "invalid-utf8.yaml"
            write_bootstrap(invalid_utf8, {}, invalid_utf8=True)
            check_startup_rejected(harness.compose, "invalid-utf8", invalid_utf8)

            harness.start(bootstrap)
            status, _, _ = request("/healthy", headers={"x-coraza-probe": "panic"})
            assert_status(status, 200, "default build panic-probe header")
            if "caught panic" in harness.compose.logs("envoy"):
                raise RuntimeError("default build executed feature-gated panic probe")
            assert_status(request("/telemetry-allow")[0], 200, "healthy telemetry request")
            require_access_log(harness.compose, "/telemetry-allow",
                               "event=- rule_id=- phase=- action=- status=- reason=complete outcome=completed complete=true")

            panic_module = harness.build_module(features="panic-probe", label="panic")
            harness.build_envoy(panic_module)
            harness.start(bootstrap, concurrency=2)
            if b"server.concurrency: 2" not in request("/stats", port=9901)[2]:
                raise RuntimeError("Envoy does not report two workers")

            payload = b"x" * 65536
            before = backend_count("/phase1-deny")
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                denied_future = pool.submit(request, "/phase1-deny")
                allowed_future = pool.submit(request, "/echo", method="POST", body=payload,
                                             headers={"Content-Type": "application/octet-stream"})
                denied = denied_future.result()
                allowed = allowed_future.result()
            assert_status(denied[0], 451, "two-worker deny")
            assert_status(allowed[0], 200, "two-worker allow")
            assert_body(allowed[2], payload, "two-worker upload")
            if backend_count("/phase1-deny") != before:
                raise RuntimeError("two-worker denied request reached the backend")

            def worker_request(deny: bool) -> tuple[int, bytes]:
                status, _, body = request(
                    "/phase1-deny" if deny else "/echo", method="GET" if deny else "POST",
                    body=None if deny else payload,
                    headers={"x-coraza-probe": "worker", "Content-Type": "application/octet-stream"},
                )
                return status, body

            before_deny, before_allow = backend_count("/phase1-deny"), backend_count("/echo")
            sequence = [deny for _ in range(16) for deny in (True, False)]
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
                results = list(pool.map(worker_request, sequence))
            if any(status != (451 if deny else 200) or body != (b"Request denied\n" if deny else payload)
                   for (status, body), deny in zip(results, sequence)):
                raise RuntimeError("multi-worker concurrent deny/allow assertions failed")
            if backend_count("/phase1-deny") != before_deny or backend_count("/echo") != before_allow + 16:
                raise RuntimeError("multi-worker backend request counts did not match")
            worker_ids = set(re.findall(r"worker probe thread_id=([^\s]+)", harness.compose.logs("envoy")))
            if len(worker_ids) != 2:
                raise RuntimeError(f"traffic reached {len(worker_ids)} worker threads, expected two")

            h2_expected = bytes(range(256)) * 8
            (work / "http2-expected").write_bytes(h2_expected)
            denied_before = backend_count("/phase1-deny")
            trace, status_file = run_curl_h2(work)
            statuses = status_file.read_text()
            if "deny 2 451" not in statuses or "allow 2 200" not in statuses:
                raise RuntimeError(f"HTTP/2 deny/allow statuses were incorrect: {statuses!r}")
            trace_text = trace.read_text(errors="replace")
            if "[1] OPENED stream" not in trace_text or "[3] OPENED stream" not in trace_text:
                raise RuntimeError("HTTP/2 requests did not multiplex on one connection")
            if backend_count("/phase1-deny") != denied_before:
                raise RuntimeError("HTTP/2 denied stream reached the backend")
            assert_body((work / "http2-allow").read_bytes(), h2_expected, "HTTP/2 allowed body")

            followup = write_body(work / "reservation-followup", 8 * 1024 * 1024, b"x")
            assert_admission_released("baseline", followup)
            before = backend_count("/cancel-upload")
            abort_held_upload()
            if backend_count("/cancel-upload") != before:
                raise RuntimeError("cancelled upload reached the backend before EOS")
            assert_admission_released("cancellation", followup)
            exhaust_admission()
            assert_admission_released("exhaustion", followup)

            before = backend_count("/response-deny")
            status, headers, body = request("/response-deny")
            assert_status(status, 451, "phase-4 response-body rule denial")
            assert_body(body, b"Upstream response blocked\n", "response denial replacement")
            if backend_count("/response-deny") != before + 1:
                raise RuntimeError("response-denied transaction did not reach the backend exactly once")
            assert_no_upstream_leak(headers, body, "response body denial")
            require_access_log(harness.compose, "/response-deny",
                               "event=coraza_waf_blocked_request rule_id=8 phase=http_response_body action=deny status=451 reason=denied outcome=denied complete=true")
            logs = harness.compose.logs("envoy")
            audit_lines = [line for line in logs.splitlines() if "stage-d-response-audit" in line]
            if len(audit_lines) != 1:
                raise RuntimeError("response transaction did not emit exactly one audit record")
            if "event=coraza_waf_blocked_request rule_id=8 phase=http_response_body action=deny status=451" not in logs:
                raise RuntimeError("response interruption fields were not published before access logging")

            status, _, body = request("/healthy-after-response-deny")
            assert_status(status, 200, "healthy response after denial")
            require_access_log(harness.compose, "/healthy-after-response-deny",
                               "event=- rule_id=- phase=- action=- status=- reason=complete outcome=completed complete=true")
            status, headers, body = request("/response-deny", headers={"Host": "limit.local"})
            assert_status(status, 500, "engine response-body Reject status")
            assert_no_upstream_leak(headers, body, "engine response-body limit")
            status, _, body = request("/empty")
            assert_status(status, 200, "header-only empty response")
            assert_body(body, b"", "empty response")

            status, headers, body = request("/multi-frame-response")
            assert_status(status, 200, "allowed inspectable multi-frame response")
            assert_body(body, b"a" * 262144, "inspectable multi-frame response")
            if not any(k.lower() == "x-large-probe" and v == "inspectable" for k, v in headers):
                raise RuntimeError("multi-frame response header was not preserved")
            status, headers, body = request("/large-uninspectable")
            assert_status(status, 200, "large MIME-excluded response")
            assert_body(body, b"z" * 1048577, "MIME-excluded response")
            if not any(k.lower() == "x-large-probe" and v == "preserved" for k, v in headers):
                raise RuntimeError("MIME-excluded response header was not preserved")

            for size in (31, 32, 33):
                data = b"a" * size
                before = backend_count("/echo")
                status, _, response = request("/echo", method="POST", body=data,
                                               headers={"Host": "boundary.local", "Content-Type": "text/plain"})
                assert_status(status, 200 if size < 32 else 413, f"request body limit N={size}")
                if size < 32:
                    assert_body(response, data, f"request body N={size}")
                elif backend_count("/echo") != before:
                    raise RuntimeError("over-limit request body reached the backend")
                status, _, response = request(f"/bytes/{size}", headers={"Host": "boundary.local"})
                assert_status(status, 200 if size < 32 else 500, f"response body limit N={size}")
                assert_body(response, b"a" * size if size < 32 else b"Upstream response blocked\n",
                            f"response body N={size}")

            partial = b"x" * 32 + b"partial-marker"
            status, _, response = request("/echo", method="POST", body=partial,
                                          headers={"Host": "partial.local", "Content-Type": "text/plain"})
            assert_status(status, 200, "ProcessPartial request")
            assert_body(response, partial, "ProcessPartial request forwarding")
            require_access_log(harness.compose, "/echo", "request_truncated=true")
            require_access_log(harness.compose, "/echo", "complete=false")
            status, _, response = request("/response-partial", headers={"Host": "partial.local"})
            assert_status(status, 200, "ProcessPartial response")
            assert_body(response, partial, "ProcessPartial response forwarding")
            require_access_log(harness.compose, "/response-partial", "response_truncated=true")
            require_access_log(harness.compose, "/response-partial", "complete=false")

            before = backend_count("/header-budget")
            raw = raw_response_status(b"GET /header-budget HTTP/1.1\r\nHost: example.test\r\nX-Budget: "
                                     + b"a" * (65536 + 1) + b"\r\nConnection: close\r\n\r\n")
            if b" 431 " not in raw or backend_count("/header-budget") != before:
                raise RuntimeError("over-budget request header did not fail closed with 431")
            before = backend_count("/trailer-budget")
            raw = raw_response_status(b"POST /trailer-budget HTTP/1.1\r\nHost: example.test\r\n"
                                     b"Transfer-Encoding: chunked\r\nTrailer: X-Budget\r\nConnection: close\r\n\r\n"
                                     b"0\r\nX-Budget: " + b"a" * (65536 + 1) + b"\r\n\r\n")
            if b" 431 " not in raw or backend_count("/trailer-budget") != before:
                raise RuntimeError("over-budget request trailer did not fail closed with 431")
            status, headers, body = request("/response-trailer-budget")
            assert_status(status, 502, "over-budget upstream response trailer")
            assert_body(body, b"Response inspection unavailable\n", "response trailer budget")
            if any(k.lower() == "x-large-trailer" for k, _ in headers):
                raise RuntimeError("over-budget response trailer was forwarded downstream")

            before = backend_count("/phase1-deny")
            assert_status(request("/phase1-deny")[0], 451, "phase-1 rule denial")
            if backend_count("/phase1-deny") != before:
                raise RuntimeError("phase-1 denied request reached the backend")

            for host, path, expected in (("off.local", "/large-header-deny", 452),
                                         ("example.test", "/large-header-deny", 452)):
                status, headers, body = request(path, headers={"Host": host})
                assert_status(status, expected, f"phase-4 response header denial for {host}")
                assert_no_upstream_leak(headers, body, f"response header denial for {host}")

            status, headers, body = request("/response-redirect")
            assert_status(status, 307, "phase-4 response redirect")
            if not any(k.lower() == "location" and v == "https://example.test/response-blocked" for k, v in headers):
                raise RuntimeError("response redirect Location was missing")
            assert_body(body, b"", "response redirect")
            for host, method, expected in (("head.local", "HEAD", 204),
                                           ("not-modified.local", "GET", 304)):
                status, headers, body = request("/response-deny", method=method, headers={"Host": host})
                assert_status(status, expected, f"response replacement status for {host}")
                assert_body(body, b"", f"response replacement for {host}")
                assert_no_upstream_leak(headers, body, f"response replacement for {host}")

            connection = socket.create_connection(("127.0.0.1", 10001), timeout=10)
            try:
                connection.sendall(b"GET /response-trailers HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
                chunks = []
                while data := connection.recv(4096):
                    chunks.append(data)
            finally:
                connection.close()
            raw = b"".join(chunks)
            if b"HTTP/1.1 200" not in raw or b"trailer response" not in raw or b"x-backend-trailer: passed" not in raw.lower():
                raise RuntimeError(f"allowed response body/trailer changed: {raw!r}")

            status, headers, body = request("/response-trailers-deny")
            assert_status(status, 451, "response-trailer denial")
            assert_body(body, b"Upstream response blocked\n", "response-trailer denial")
            assert_no_upstream_leak(headers, body, "response-trailer denial")
            status, headers, body = request("/large-response")
            assert_status(status, 502, "native response host ceiling")
            if any(k.lower() == "x-upstream-secret" for k, _ in headers) or b"z" in body:
                raise RuntimeError("response-size failure leaked upstream headers or body")

            before = backend_count("/phase1-deny")
            status, _, body = request("/phase1-deny", method="HEAD")
            assert_status(status, 451, "HEAD denial")
            assert_body(body, b"", "HEAD denial")
            if backend_count("/phase1-deny") != before:
                raise RuntimeError("HEAD denial reached the backend")
            for path, expected in (("/redirect-deny", "https://example.test/blocked"),
                                   ("/no-content", None), ("/not-modified", None)):
                status, headers, body = request(path)
                code = 307 if expected else (204 if path == "/no-content" else 304)
                assert_status(status, code, f"configured denial {path}")
                if expected and not any(k.lower() == "location" and v == expected for k, v in headers):
                    raise RuntimeError("configured redirect Location was missing")
                assert_body(body, b"", f"configured denial {path}")

            before = backend_count("/echo")
            assert_status(request("/echo", method="POST", body=b"body-attack",
                                 headers={"Content-Type": "text/plain"})[0], 429, "phase-2 request-body denial")
            if backend_count("/echo") != before:
                raise RuntimeError("phase-2 denied request reached the backend")

            crlf_request = b"request-crlf-redirect\r\nSet-Cookie: injected=1"
            before = backend_count("/echo")
            status, headers, body = request("/echo", method="POST", body=crlf_request,
                                            headers={"Content-Type": "text/plain"})
            assert_status(status, 307, "request redirect with macro-expanded CRLF")
            assert_no_upstream_leak(headers, body, "request CRLF redirect")
            if any(k.lower() == "location" for k, _ in headers):
                raise RuntimeError("unsafe request redirect target reached Location")
            assert_body(body, b"Request denied\n", "unsafe request redirect fallback")
            if backend_count("/echo") != before:
                raise RuntimeError("unsafe request redirect reached the backend")

            status, headers, body = request("/response-redirect-crlf")
            assert_status(status, 307, "response redirect with macro-expanded CRLF")
            assert_no_upstream_leak(headers, body, "response CRLF redirect")
            if any(k.lower() == "location" for k, _ in headers):
                raise RuntimeError("unsafe response redirect target reached Location")
            assert_body(body, b"Upstream response blocked\n", "unsafe response redirect fallback")

            before = backend_count("/echo")
            status, _, _ = request("/echo", method="POST", body=b"encoded",
                                   headers={"Content-Type": "text/plain", "Content-Encoding": "gzip"})
            assert_status(status, 415, "unsupported request content encoding")
            if backend_count("/echo") != before:
                raise RuntimeError("unsupported-encoding request reached the backend")
            status, _, _ = request("/upgrade", headers={"Connection": "Upgrade", "Upgrade": "websocket"})
            assert_status(status, 501, "unsupported request upgrade")

            payload = bytes(range(256)) * 256
            connection = http.client.HTTPConnection("127.0.0.1", 10001, timeout=15)
            try:
                connection.putrequest("POST", "/echo", skip_accept_encoding=True)
                connection.putheader("Content-Type", "application/octet-stream")
                connection.putheader("Transfer-Encoding", "chunked")
                connection.putheader("Connection", "close")
                connection.endheaders()
                for part in (payload[:16383], payload[16383:16384], payload[16384:32768], payload[32768:]):
                    connection.send(f"{len(part):X}\r\n".encode() + part + b"\r\n")
                connection.send(b"0\r\n\r\n")
                response = connection.getresponse()
                status, body = response.status, response.read()
            finally:
                connection.close()
            assert_status(status, 200, "multi-frame chunked upload")
            assert_body(body, payload, "multi-frame upload across 16 KiB boundaries")

            connection = http.client.HTTPConnection("127.0.0.1", 10001, timeout=15)
            try:
                connection.putrequest("POST", "/echo", skip_accept_encoding=True)
                connection.putheader("Content-Type", "text/plain")
                connection.putheader("Transfer-Encoding", "chunked")
                connection.putheader("Trailer", "x-client-trailer")
                connection.putheader("Connection", "close")
                connection.endheaders()
                for part in (b"trailer-", b"terminated"):
                    connection.send(f"{len(part):X}\r\n".encode() + part + b"\r\n")
                connection.send(b"0\r\nx-client-trailer: preserved\r\n\r\n")
                response = connection.getresponse()
                headers, body = response.getheaders(), response.read()
                status = response.status
            finally:
                connection.close()
            assert_status(status, 200, "trailer-terminated upload")
            assert_body(body, b"trailer-terminated", "trailer-terminated upload")
            if not any(k.lower() == "x-client-trailer-seen" and v == "preserved" for k, v in headers):
                raise RuntimeError(f"backend did not receive the request trailer: {headers!r}")

            harness.compose.down()
            detection = {"directives_map": {"main": [
                "SecRuleEngine DetectionOnly", "SecRequestBodyAccess On", "SecRequestBodyLimit 16777216",
                'SecAction "id:1,phase:1,ctl:requestBodyProcessor=RAW,pass"',
                'SecRule REQUEST_URI "@contains phase1-deny" "id:2,phase:1,deny,status:451"',
                'SecRule REQUEST_BODY "@contains body-attack" "id:3,phase:2,deny,status:429"',
            ]}, "default_directives": "main"}
            detection_file = work / "detection-only.yaml"
            write_bootstrap(detection_file, detection)
            harness.start(detection_file)
            assert_status(request("/phase1-deny")[0], 200, "DetectionOnly phase-1 rule")
            status, _, body = request("/echo", method="POST", body=b"body-attack",
                                      headers={"Content-Type": "text/plain"})
            assert_status(status, 200, "DetectionOnly phase-2 rule")
            assert_body(body, b"body-attack", "DetectionOnly request body")

            body_off = {"directives_map": {"off": [
                "SecRuleEngine On", "SecRequestBodyAccess Off",
                'SecRule REQUEST_BODY "@contains body-attack" "id:4,phase:2,deny,status:429"',
            ]}, "default_directives": "off"}
            body_off_file = work / "body-off.yaml"
            write_bootstrap(body_off_file, body_off)
            harness.start(body_off_file)
            status, _, body = request("/echo", method="POST", body=b"body-attack",
                                      headers={"Content-Type": "text/plain"})
            assert_status(status, 200, "SecRequestBodyAccess Off")
            assert_body(body, b"body-attack", "body-access-off upload")

            engine_off_file = work / "engine-off.yaml"
            write_bootstrap(engine_off_file, {"directives_map": {"off": [
                "SecRuleEngine Off",
                'SecRule REQUEST_URI "@contains phase1-deny" "id:7,phase:1,deny,status:451"',
            ]}, "default_directives": "off"})
            harness.start(engine_off_file)
            assert_status(request("/phase1-deny")[0], 200, "SecRuleEngine Off")
            require_access_log(harness.compose, "/phase1-deny",
                               "event=- rule_id=- phase=- action=- status=- reason=- outcome=- complete=-")

            unmatched_file = work / "unmatched.yaml"
            write_bootstrap(unmatched_file, {"directives_map": {"protected": [
                "SecRuleEngine On",
                'SecRule REQUEST_URI "@contains phase1-deny" "id:5,phase:1,deny,status:451"',
            ]}, "per_authority_directives": {"protected.test": "protected"}})
            harness.start(unmatched_file)
            assert_status(request("/phase1-deny", headers={"Host": "unmatched.test"})[0], 200,
                          "unmatched authority bypass")
            assert_status(request("/phase1-deny", headers={"Host": "protected.test"})[0], 451,
                          "normalized authority policy selection")

            empty_file = work / "empty.yaml"
            write_bootstrap(empty_file, {})
            harness.start(empty_file)
            assert_status(request("/phase1-deny")[0], 200, "empty policy bypass")

            first = {"directives_map": {"first": [
                "SecRuleEngine On",
                'SecRule REQUEST_URI "@contains first-instance" "id:10,phase:1,deny,status:451"',
            ]}, "default_directives": "first"}
            second = {"directives_map": {"second": [
                "SecRuleEngine On",
                'SecRule REQUEST_URI "@contains second-instance" "id:11,phase:1,deny,status:452"',
            ]}, "default_directives": "second"}
            instances_file = work / "two-instances.yaml"
            write_bootstrap(instances_file, first, second_policy=second)
            harness.start(instances_file)
            assert_status(request("/first-instance")[0], 451, "first independent filter policy")
            assert_status(request("/second-instance")[0], 452, "second independent filter policy")
            assert_status(request("/allowed")[0], 200, "independent filter pass")

            harness.compose.down()
            crs_policy = {"directives_map": {"crs": [
                "SecRuleEngine On", "SecAuditEngine RelevantOnly", "SecAuditLogFormat JSON",
                "SecRequestBodyAccess On", "SecRequestBodyLimit 13107200", "SecResponseBodyAccess On",
                "SecResponseBodyLimit 1048576", "SecResponseBodyMimeType text/plain text/html application/json",
                "Include crs/crs-setup.conf", "Include crs/rules/*.conf",
                'SecRule REQUEST_HEADERS:Content-Type "@rx ^application/json(?:\\s*;.*)?$" "id:999100,phase:1,pass,nolog,t:none,t:lowercase,ctl:requestBodyProcessor=JSON"',
            ]}, "per_authority_directives": {"crs.local": "crs"}, "enable_filter_state_logs": True}
            crs_file = work / "crs.yaml"
            write_bootstrap(crs_file, crs_policy)
            crs_module = harness.build_module(features="embed-crs", label="crs")
            harness.build_envoy(crs_module)
            harness.start(crs_file)
            before = backend_count("/crs-sqli")
            status, _, _ = request("/crs-sqli?q=1%27%20OR%201%3D1", headers={"Host": "crs.local"})
            assert_status(status, 403, "embedded CRS SQL injection")
            if backend_count("/crs-sqli") != before or "949110" not in harness.compose.logs("envoy"):
                raise RuntimeError("CRS SQL injection reached the backend or lacked rule 949110")
            assert_status(request("/healthy", headers={"Host": "crs.local"})[0], 200,
                          "embedded CRS benign request")

            harness.build_envoy(panic_module)
            panic_policy = {"directives_map": {"p": [
                "SecRuleEngine On", "SecRequestBodyAccess On", "SecRequestBodyLimit 16777216",
                'SecAction "id:1,phase:1,ctl:requestBodyProcessor=RAW,pass"', "SecResponseBodyAccess On",
                "SecResponseBodyLimit 1048576", "SecResponseBodyMimeType text/plain",
            ]}, "default_directives": "p"}
            panic_file = work / "panic.yaml"
            write_bootstrap(panic_file, panic_policy)
            harness.start(panic_file)
            before = backend_count("/panic")
            status, _, _ = request("/panic", headers={"x-coraza-probe": "panic"})
            assert_status(status, 500, "feature-gated request panic")
            if backend_count("/panic") != before:
                raise RuntimeError("panicking request reached the backend")

            before = backend_count("/response-deny")
            try:
                request("/response-deny", method="POST", body=b"x" * (8 * 1024 * 1024), timeout=10,
                        headers={"x-coraza-probe": "panic-response", "Content-Type": "application/octet-stream"})
            except (OSError, http.client.HTTPException, TimeoutError):
                pass
            else:
                raise RuntimeError("response callback panic did not reset the stream")
            if backend_count("/response-deny") != before + 1:
                raise RuntimeError("body-bearing response-panic probe did not reach the backend")
            if "caught panic: feature-gated response panic probe" not in harness.compose.logs("envoy"):
                raise RuntimeError("response callback panic was not caught and reset")
            assert_admission_released("panic", followup)
            print("Envoy 1.40 native request-enforcement checks passed")
        except Exception:
            logs = harness.compose.logs("envoy")
            if logs:
                print("--- Envoy logs ---", file=sys.stderr)
                print("\n".join(logs.splitlines()[-80:]), file=sys.stderr)
            raise
        finally:
            harness.cleanup()


def stop_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def compress_log(path: pathlib.Path) -> None:
    if not path.exists():
        return
    with path.open("rb") as source, gzip.open(f"{path}.gz", "wb", compresslevel=9) as output:
        shutil.copyfileobj(source, output)
    path.unlink()


def test_ftw() -> None:
    assert_ports_free()
    pinned_commit = "e03a4f6dabc7a30ebd8c52c97d28a154f590a48f"
    default_artifact = ROOT / "target/envoy-coraza-dynamic-ftw" / (
        "native-rerun-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    )
    artifact = pathlib.Path(os.environ.get("FTW_OUTPUT_DIR", default_artifact))
    if not artifact.is_absolute():
        artifact = ROOT / artifact
    artifact.mkdir(parents=True, exist_ok=False)
    project = f"envoy-coraza-dynamic-ftw-{os.getpid()}-{uuid.uuid4().hex[:6]}"
    compose = Compose(COMPOSE_FILE, project)
    temp = tempfile.TemporaryDirectory(prefix="coraza-ftw-")
    work = pathlib.Path(temp.name)
    log_process = None
    runner_status = None
    try:
        checkout_value = os.environ.get("CRS_TEST_CHECKOUT")
        if checkout_value:
            checkout = pathlib.Path(checkout_value)
            if not checkout.is_absolute():
                checkout = ROOT / checkout
        else:
            checkout = work / "coreruleset"
            command(["git", "init", "--quiet", str(checkout)])
            command(["git", "-C", str(checkout), "remote", "add", "origin",
                     "https://github.com/coreruleset/coreruleset.git"])
            command(["git", "-C", str(checkout), "fetch", "--quiet", "--depth=1", "origin", pinned_commit])
            command(["git", "-C", str(checkout), "checkout", "--quiet", "--detach", "FETCH_HEAD"])
        revision = command(["git", "-C", str(checkout), "rev-parse", "HEAD"], capture=True).stdout.strip()
        if revision != pinned_commit:
            raise RuntimeError(f"CRS test checkout must be pinned to {pinned_commit}, got {revision}")
        test_dir = checkout / "tests/regression/tests"
        if not test_dir.is_dir():
            raise RuntimeError(f"CRS FTW tests are missing: {test_dir}")

        command(["make", "--no-print-directory", "-C", str(ROOT), "build-envoy-dynamic-crs"], capture=True)
        target_dir = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", "target"))
        if not target_dir.is_absolute():
            target_dir = ROOT / target_dir
        module_source = target_dir / "release/libenvoy_coraza_dynamic.so"
        module_copy = ROOT / "target" / f"envoy-coraza-dynamic-ftw-{uuid.uuid4().hex[:8]}.so"
        module_copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(module_source, module_copy)
        module = f"target/{module_copy.name}"
        go_env = {"GOWORK": "off", "GOTOOLCHAIN": "local"}
        go_dir = ROOT / "ftw-runner"
        command(["go", "mod", "download", "github.com/corazawaf/coraza/v3@v3.8.1"], cwd=go_dir, env=go_env)
        coraza = pathlib.Path(command(["go", "env", "GOMODCACHE"], cwd=go_dir, capture=True).stdout.strip()) \
            / "github.com/corazawaf/coraza/v3@v3.8.1"
        recommended = coraza / "coraza.conf-recommended"
        if not recommended.is_file():
            raise RuntimeError(f"Go Coraza v3.8.1 was not found at {coraza}")
        go_ftw_version = None
        for line in (ROOT / "ftw-runner/go.mod").read_text().splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[0] == "github.com/coreruleset/go-ftw/v2":
                go_ftw_version = fields[1]
                break
        if not go_ftw_version:
            raise RuntimeError("go-ftw version is missing from ftw-runner/go.mod")

        policy = {
            "directives_map": {"ftw": [
                "Include coraza.conf-recommended", "SecResponseBodyMimeType text/plain",
                "SecRequestBodyLimit 13107200", "SecRequestBodyInMemoryLimit 13107200",
                'SecAction "id:900005,phase:1,nolog,pass,ctl:ruleEngine=DetectionOnly,ctl:ruleRemoveById=910000,setvar:tx.blocking_paranoia_level=4,setvar:tx.crs_validate_utf8_encoding=1,setvar:tx.arg_name_length=100,setvar:tx.arg_length=400,setvar:tx.total_arg_length=64000,setvar:tx.max_num_args=255,setvar:tx.max_file_size=64100,setvar:tx.combined_file_sizes=65535"',
                'SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" "id:999999,phase:1,pass,t:none,log,msg:\'X-CRS-Test %{MATCHED_VAR}\',ctl:ruleRemoveById=1-999999"',
                "Include crs/crs-setup.conf", "Include crs/rules/*.conf",
            ]},
            "default_directives": "ftw",
        }
        policy["rule_data"] = {"coraza.conf-recommended": recommended.read_text()}
        policy_file = work / "policy.json"
        policy_file.write_text(json.dumps(policy, indent=2) + "\n")
        bootstrap = work / "envoy.yaml"
        write_bootstrap(bootstrap, policy_file.read_text().strip())
        text = bootstrap.read_text()
        log_marker = "telemetry_failed=%FILTER_STATE(wasm.io.coraza.waf.v1.telemetry_publish_failed:PLAIN)%\\n\""
        if text.count(log_marker) != 1:
            raise RuntimeError("could not locate the native access-log format")
        bootstrap.write_text(text.replace(log_marker,
            "telemetry_failed=%FILTER_STATE(wasm.io.coraza.waf.v1.telemetry_publish_failed:PLAIN)% status=%RESPONSE_CODE% marker=%REQ(X-CRS-Test)%\\n\"", 1))
        ftw_config = work / "ftw.yaml"
        ftw_config.write_text("""logmarkerheadername: X-CRS-Test
testoverride:
  input:
    dest_addr: 127.0.0.1
    port: 10001
mode: default
""")

        env = {"ENVOY_CORAZA_DYNAMIC_MODULE": module,
               "ENVOY_CORAZA_DYNAMIC_CONFIG": str(bootstrap),
               "ENVOY_CORAZA_DYNAMIC_CONCURRENCY": "2"}
        compose.run("build", "backend", "envoy", env={"ENVOY_CORAZA_DYNAMIC_MODULE": module}, capture=True)
        compose.run("up", "--detach", env=env, capture=True)
        wait_backend(compose)
        wait_ready()
        access_log = artifact / "envoy-access.log"
        with access_log.open("ab") as output:
            log_process = subprocess.Popen(
                [*compose.prefix, "logs", "--follow", "--no-color", "--no-log-prefix", "envoy"],
                cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
            )

        marker_wait = os.environ.get("FTW_MARKER_WAIT", "25ms")
        args = ["go", "run", f"github.com/coreruleset/go-ftw/v2@{go_ftw_version}",
                "--config", str(ftw_config), "run", "--dir", str(test_dir),
                "--log-file", str(access_log), "--output", "json",
                "--file", str(artifact / "native.json"), "--connect-timeout", "30s",
                "--read-timeout", "30s", "--rate-limit", marker_wait,
                "--max-marker-retries", "100"]
        if os.environ.get("FTW_INCLUDE_TESTS"):
            args.extend(["--include", os.environ["FTW_INCLUDE_TESTS"]])
        with (artifact / "runner.log").open("wb") as output:
            try:
                runner = subprocess.run(args, cwd=ROOT, env={**os.environ, **go_env},
                                        stdout=output, stderr=subprocess.STDOUT, check=False, timeout=35 * 60)
            except subprocess.TimeoutExpired as error:
                raise CommandTimeout(f"go-ftw timed out after 35 minutes; see {artifact / 'runner.log'}") from error
        runner_status = runner.returncode
        stop_process(log_process)
        log_process = None
        if not (artifact / "native.json").is_file():
            raise RuntimeError(f"go-ftw did not write its JSON summary; see {artifact / 'runner.log'}")
        manifest = json.loads((artifact / "native.json").read_text())
        selected = manifest.get("run", 0) - len(manifest.get("skipped", []))
        expected = int(os.environ.get("FTW_EXPECTED_SELECTED_TESTS", "0"))
        if not expected and not os.environ.get("FTW_INCLUDE_TESTS"):
            expected = 5231
        if expected and selected != expected:
            raise RuntimeError(f"FTW selected {selected} tests, expected {expected}")
        allow_file_value = os.environ.get("FTW_ALLOW_FAILURES_FILE")
        allow_file = pathlib.Path(allow_file_value) if allow_file_value else None
        if allow_file and not allow_file.is_absolute():
            allow_file = ROOT / allow_file
        allowed = ({line.strip() for line in allow_file.read_text().splitlines()
                    if line.strip() and not line.lstrip().startswith("#")} if allow_file else set())
        failed = set(manifest.get("failed", [])) | set(manifest.get("forced-fail", []))
        unexpected = sorted(failed - allowed)
        if unexpected:
            raise RuntimeError(f"unexpected FTW failures: {unexpected}")
        if runner_status and not failed:
            raise RuntimeError("go-ftw failed without reporting a failed test")
        if runner_status and not allow_file:
            raise RuntimeError(f"FTW exited {runner_status}; see {artifact / 'runner.log'}")

        metadata = {
            "repository_revision": command(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture=True).stdout.strip(),
            "crs_test_revision": revision,
            "crs_rules_pin": (ROOT / "envoy-coraza/crs.pin").read_text().strip(),
            "envoy_image": command(["make", "--no-print-directory", "-C", str(ROOT), "print-envoy-image"], capture=True).stdout.strip(),
            "test_directory": str(test_dir), "runner_exit_status": runner_status,
            "selected_tests": selected, "include_tests": os.environ.get("FTW_INCLUDE_TESTS"),
            "marker_wait": marker_wait, "marker_max_retries": 100,
            "go_ftw": f"github.com/coreruleset/go-ftw/v2 {go_ftw_version}",
            "go_coraza": "github.com/corazawaf/coraza/v3 v3.8.1",
            "policy_sha256": hashlib.sha256(policy_file.read_bytes()).hexdigest(),
            "module_sha256": hashlib.sha256(module_copy.read_bytes()).hexdigest(),
            "rustc": command(["rustc", "--version"], capture=True).stdout.strip(),
            "go": command(["go", "version"], capture=True).stdout.strip(),
            "commands": ["make build-envoy-dynamic-crs", "go run " + " ".join(args)],
        }
        (artifact / "run-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
        compress_log(access_log)
        compress_log(artifact / "runner.log")
        print(f"FTW completed: {selected} selected; {len(failed)} allow-listed failure(s). Artifacts: {artifact}")
    except Exception:
        if log_process:
            stop_process(log_process)
        logs = compose.logs("envoy")
        if logs:
            print("--- Envoy logs ---", file=sys.stderr)
            print("\n".join(logs.splitlines()[-80:]), file=sys.stderr)
        runner_log = artifact / "runner.log"
        if runner_log.exists():
            print("--- go-ftw log ---", file=sys.stderr)
            print("\n".join(runner_log.read_text(errors="replace").splitlines()[-80:]), file=sys.stderr)
        raise
    finally:
        stop_process(log_process)
        compose.down()
        if "module_copy" in locals():
            module_copy.unlink(missing_ok=True)
        temp.cleanup()


def readelf_symbols(output: str, *, imports: bool) -> set[str]:
    result = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 8:
            continue
        bind, index, name = fields[4], fields[6], fields[7]
        if imports and index == "UND" and name.startswith("envoy_dynamic_module_callback_"):
            result.add(name)
        if not imports and bind in {"GLOBAL", "WEAK"} and index != "UND":
            result.add(name)
    return result


def test_derived_image() -> None:
    base_image = os.environ.get("ENVOY_IMAGE")
    platform = os.environ.get("PLATFORM", os.environ.get("ENVOY_PLATFORM", "linux/amd64"))
    expected_arch = platform.rsplit("/", 1)[-1]
    assert_ports_free((9901, 10001, 3000))
    if os.environ.get("PROFILE"):
        architecture = os.environ.get("ARCHITECTURE", expected_arch)
        if architecture != expected_arch:
            raise RuntimeError(f"architecture {architecture} does not match platform {platform}")
        if not base_image:
            raise RuntimeError("ENVOY_IMAGE must contain the pinned base image when PROFILE is set")
        image = f"coraza-rs-dynamic-{architecture}-{os.environ['PROFILE']}:ci"
        command(["docker", "buildx", "build", "--platform", platform, "--load",
                 "--file", "Dockerfile.goreleaser-dynamic", "--build-arg", f"ENVOY_IMAGE={base_image}",
                 "--build-arg", f"CARGO_FEATURES={os.environ.get('CARGO_FEATURES', '')}",
                 "--tag", image, "."], capture=True)
    else:
        image = base_image
        if not image:
            raise RuntimeError("set ENVOY_IMAGE to the derived image to smoke-test")
    arch = command(["docker", "image", "inspect", "--format", "{{.Architecture}}", image], capture=True).stdout.strip()
    if arch != expected_arch:
        raise RuntimeError(f"image {image} has architecture {arch}, expected {expected_arch}")

    with tempfile.TemporaryDirectory(prefix="coraza-derived-") as directory:
        work = pathlib.Path(directory)
        log_path = work / "envoy.log"
        probe = None
        envoy = None
        server = None
        try:
            probe = command(["docker", "create", "--platform", platform, image], capture=True).stdout.strip()
            command(["docker", "cp", f"{probe}:/usr/local/bin/envoy", str(work / "envoy")])
            command(["docker", "cp", f"{probe}:/opt/envoy/modules/libenvoy_coraza_dynamic.so", str(work / "module.so")])
            command(["docker", "rm", probe], capture=True)
            probe = None
            imports = readelf_symbols(command(["readelf", "--wide", "--dyn-syms", str(work / "module.so")], capture=True).stdout,
                                      imports=True)
            exports = readelf_symbols(command(["readelf", "--wide", "--dyn-syms", str(work / "envoy")], capture=True).stdout,
                                      imports=False)
            unresolved = sorted(imports - exports)
            if unresolved:
                raise RuntimeError("Envoy does not export dynamic-module callbacks: " + ", ".join(unresolved))

            config = work / "envoy.yaml"
            write_bootstrap(config, {"directives_map": {"smoke": [
                "SecRuleEngine On",
                'SecRule REQUEST_URI "@streq /deny" "id:1,phase:1,deny,status:403"',
            ]}, "default_directives": "smoke"})
            config.write_text(config.read_text().replace("address: backend\n", "address: 127.0.0.1\n", 1))
            invalid = work / "invalid.yaml"
            invalid.write_text(config.read_text().replace("filter_name: coraza", "filter_name: invalid", 1))
            result = command(["docker", "run", "--rm", "--platform", platform, "--network", "none",
                              "--volume", f"{invalid}:/etc/envoy/invalid.yaml:ro", image,
                              "-c", "/etc/envoy/invalid.yaml", "--log-level", "critical"],
                             capture=True, check=False)
            if result.returncode == 0:
                raise RuntimeError("derived image accepted an unknown native filter name")

            counts = work / "backend-count"

            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    with counts.open("a") as output:
                        output.write(self.path + "\n")
                    body = b"derived-image-smoke-allow"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *_args):
                    pass

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 3000), Handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            container = f"coraza-derived-{os.getpid()}-{uuid.uuid4().hex[:8]}"
            with log_path.open("wb") as output:
                envoy = subprocess.Popen(
                    ["docker", "run", "--rm", "--name", container, "--platform", platform, "--network", "host",
                     "--volume", f"{config}:/etc/envoy/envoy.yaml:ro", image,
                     "-c", "/etc/envoy/envoy.yaml", "--log-level", "warning"],
                    cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
                )
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                if envoy.poll() is not None:
                    raise RuntimeError(f"derived Envoy exited with {envoy.returncode}")
                try:
                    with urllib.request.urlopen("http://127.0.0.1:9901/ready", timeout=2) as response:
                        if response.status == 200:
                            break
                except Exception:
                    time.sleep(1)
            else:
                raise RuntimeError("derived Envoy did not become ready")

            status, _, body = request("/deny", port=10001)
            assert_status(status, 403, "derived image deny")
            assert_body(body, b"Request denied\n", "derived image denial")
            if counts.exists() and counts.read_text():
                raise RuntimeError("denied request reached the backend")
            status, _, body = request("/allow", port=10001)
            assert_status(status, 200, "derived image allow")
            assert_body(body, b"derived-image-smoke-allow", "derived image backend response")
            if counts.read_text() != "/allow\n":
                raise RuntimeError("expected only the allowed request to reach the backend")

            ldd = command(["docker", "run", "--rm", "--platform", platform, "--entrypoint", "sh", image,
                           "-c", "ldd /opt/envoy/modules/libenvoy_coraza_dynamic.so"], capture=True)
            if "not found" in ldd.stdout:
                raise RuntimeError("derived module has unresolved shared-library dependencies:\n" + ldd.stdout)
            print(f"{expected_arch} derived Envoy smoke passed")
        except Exception:
            if log_path.exists():
                print("--- derived Envoy log ---", file=sys.stderr)
                print("\n".join(log_path.read_text(errors="replace").splitlines()[-80:]), file=sys.stderr)
            raise
        finally:
            if envoy:
                stop_process(envoy)
            if 'container' in locals():
                command(["docker", "rm", "-f", container], capture=True, check=False)
            if probe:
                command(["docker", "rm", probe], capture=True, check=False)
            if server:
                server.shutdown()
                server.server_close()


def test_rollback() -> None:
    assert_ports_free()
    image = command(["make", "--no-print-directory", "-C", str(ROOT), "print-envoy-image"], capture=True).stdout.strip()
    native = Compose(COMPOSE_FILE, f"coraza-rollback-native-{os.getpid()}-{uuid.uuid4().hex[:6]}")
    wasm = Compose(ROOT / "examples/envoy-coraza/compose.yaml",
                   f"coraza-rollback-wasm-{os.getpid()}-{uuid.uuid4().hex[:6]}", env={"ENVOY_IMAGE": image})
    module = ROOT / "target" / f"coraza-rollback-{os.getpid()}-{uuid.uuid4().hex[:6]}.so"
    try:
        command(["make", "--no-print-directory", "-C", str(ROOT), "build-envoy-dynamic", "build-envoy-wasm"], capture=True)
        target_dir = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", "target"))
        if not target_dir.is_absolute():
            target_dir = ROOT / target_dir
        module.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(target_dir / "release/libenvoy_coraza_dynamic.so", module)
        policy_json = json.dumps({"directives_map": {"smoke": [
            "SecRuleEngine On", "SecRequestBodyAccess On", "SecRequestBodyLimit 16777216",
            'SecAction "id:1,phase:1,ctl:requestBodyProcessor=RAW,pass"',
            'SecRule REQUEST_URI "@streq /phase1-deny" "id:2,phase:1,deny,status:451"',
            'SecRule REQUEST_BODY "@contains body-attack" "id:3,phase:2,deny,status:429"',
        ]}, "default_directives": "smoke"}, separators=(",", ":"))
        with tempfile.TemporaryDirectory(prefix="coraza-rollback-") as directory:
            work = pathlib.Path(directory)
            native_config = work / "native.yaml"
            write_bootstrap(native_config, policy_json)
            base = (EXAMPLE / "envoy.yaml").read_text()
            start = base.index("                  - name: envoy.filters.http.dynamic_modules\n")
            end = base.index("                  - name: envoy.filters.http.router\n", start)
            wasm_filter = (
                "                  - name: envoy.filters.http.wasm\n"
                "                    typed_config:\n"
                '                      "@type": type.googleapis.com/udpa.type.v1.TypedStruct\n'
                "                      type_url: type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm\n"
                "                      value:\n"
                "                        config:\n"
                "                          name: coraza-stage-f-rollback\n"
                "                          root_id: coraza-stage-f-rollback\n"
                "                          failure_policy: FAIL_CLOSED\n"
                "                          allow_on_headers_stop_iteration: true\n"
                "                          vm_config:\n"
                "                            runtime: envoy.wasm.runtime.v8\n"
                "                            code:\n"
                "                              local:\n"
                "                                filename: /etc/envoy/envoy_coraza.wasm\n"
                "                          configuration:\n"
                '                            "@type": type.googleapis.com/google.protobuf.StringValue\n'
                "                            value: |\n"
                + "".join("                              " + line + "\n" for line in policy_json.splitlines())
            )
            wasm_config = work / "wasm.yaml"
            wasm_config.write_text(base[:start] + wasm_filter + base[end:])

            def smoke(label: str) -> None:
                before = backend_count("/phase1-deny")
                status, _, _ = request("/phase1-deny", headers={"Host": "example.test"})
                assert_status(status, 451, f"{label} phase-1 deny")
                if backend_count("/phase1-deny") != before:
                    raise RuntimeError(f"{label} phase-1 denial reached the backend")
                before = backend_count("/echo")
                status, _, _ = request("/echo", method="POST", body=b"body-attack",
                                       headers={"Host": "example.test", "Content-Type": "text/plain"})
                assert_status(status, 429, f"{label} phase-2 deny")
                if backend_count("/echo") != before:
                    raise RuntimeError(f"{label} phase-2 denial reached the backend")
                status, _, body = request("/echo", method="POST", body=b"rollback-allow",
                                          headers={"Host": "example.test", "Content-Type": "text/plain"})
                assert_status(status, 200, f"{label} allow")
                assert_body(body, b"rollback-allow", f"{label} allow body")
                print(f"{label}: deny and allow passed")

            module_rel = f"target/{module.name}"
            native_env = {"ENVOY_CORAZA_DYNAMIC_CONFIG": str(native_config),
                          "ENVOY_CORAZA_DYNAMIC_MODULE": module_rel}
            native.run("up", "--detach", "--build", env=native_env, capture=True)
            wait_ready()
            wait_backend(native)
            smoke("native")
            native.down()

            wasm_asset = target_dir / "wasm32-wasip1/release/envoy_coraza.wasm"
            wasm.run("up", "--detach", "--build", env={
                "ENVOY_CORAZA_CONFIG": str(wasm_config),
                "ENVOY_CORAZA_WASM": str(wasm_asset),
            }, capture=True)
            wait_ready()
            wait_backend(wasm)
            smoke("wasm")
            digest = hashlib.sha256(policy_json.encode()).hexdigest()
            print(f"rollback proof passed: policy SHA-256 {digest}; native and Wasm checks passed")
    except Exception:
        for label, compose in (("native", native), ("wasm", wasm)):
            logs = compose.logs("envoy")
            if logs:
                print(f"--- {label} Envoy logs ---", file=sys.stderr)
                print("\n".join(logs.splitlines()[-60:]), file=sys.stderr)
        raise
    finally:
        native.down()
        wasm.down()
        module.unlink(missing_ok=True)


def run_crs_demo() -> None:
    assert_ports_free()
    command(["make", "--no-print-directory", "-C", str(ROOT), "build-envoy-dynamic-crs"], capture=True)

    policy = {
        "directives_map": {
            "crs": [
                "SecRuleEngine On",
                "SecRequestBodyAccess On",
                "SecRequestBodyLimit 13107200",
                "SecRequestBodyInMemoryLimit 13107200",
                "Include crs/crs-setup.conf",
                "Include crs/rules/*.conf",
            ]
        },
        "default_directives": "crs",
    }
    config = ROOT / "target/envoy-coraza-dynamic-crs-demo/envoy.yaml"
    config.parent.mkdir(parents=True, exist_ok=True)
    write_bootstrap(config, policy)

    target_dir = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", "target"))
    if not target_dir.is_absolute():
        target_dir = ROOT / target_dir
    module = ROOT / "target" / f"envoy-coraza-dynamic-crs-demo-{os.getpid()}.so"
    module.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(target_dir / "release/libenvoy_coraza_dynamic.so", module)

    project = "envoy-coraza-dynamic-crs-demo"
    env = {
        "ENVOY_CORAZA_DYNAMIC_CONFIG": str(config),
        "ENVOY_CORAZA_DYNAMIC_MODULE": f"target/{module.name}",
    }
    compose = Compose(COMPOSE_FILE, project, env=env)
    path = "/crs-sqli?q=1%27%20OR%201%3D1"
    try:
        compose.run("up", "--detach", "--build", capture=True)
        wait_backend(compose)
        wait_ready()
        before = backend_count("/crs-sqli")
        status, _, _ = request(path, headers={"Host": "crs.local"})
        assert_status(status, 403, "embedded CRS SQLi demo")
        if backend_count("/crs-sqli") != before:
            raise RuntimeError("CRS-blocked request reached the backend")
    except Exception:
        logs = compose.logs("envoy")
        if logs:
            print("--- Envoy logs ---", file=sys.stderr)
            print("\n".join(logs.splitlines()[-60:]), file=sys.stderr)
        compose.down()
        raise
    finally:
        module.unlink(missing_ok=True)

    compose_prefix = ["docker", "compose", "-f", str(COMPOSE_FILE), "-p", project]
    image_env = f"ENVOY_CORAZA_DYNAMIC_CONFIG={config}"
    print("Envoy is running with the embedded CRS; the SQLi demo request returned 403.")
    print(f"try:    curl -i -H 'Host: crs.local' 'http://127.0.0.1:10001{path}'")
    print(f"logs:   {shlex.join([image_env, *compose_prefix, 'logs', 'envoy'])}")
    print(f"stop:   {shlex.join([image_env, *compose_prefix, 'down', '--volumes'])}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="test", required=True)
    for name, description, run in (
        ("native", "Run native Envoy integration checks", test_envoy),
        ("ftw", "Run the native CRS FTW suite", test_ftw),
        ("derived-image", "Smoke-test a derived Envoy image", test_derived_image),
        ("rollback", "Compare native and Wasm using identical policy bytes", test_rollback),
        ("demo-crs", "Run an interactive embedded-CRS Envoy demo", run_crs_demo),
    ):
        subparser = subparsers.add_parser(name, help=description)
        subparser.set_defaults(run=run)
    args = parser.parse_args()
    try:
        args.run()
        return 0
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
