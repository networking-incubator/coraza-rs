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

grep --quiet --fixed-strings 'proxy_100_continue: false' "$ENVOY_CORAZA_CONFIG" \
    || fail 'the HCM deployment invariant proxy_100_continue: false is missing'

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

if [[ $envoy_target == build-envoy-wasm-crs ]]; then
    before=$(backend_count /crs-sqli)
    status=$(request "$temp_dir/response" --header 'Host: crs.local' \
        'http://127.0.0.1:10001/crs-sqli?q=1%27%20OR%20%271%27%3D%271')
    check_status 403 "$status" 'embedded CRS SQLi denial'
    [[ $(backend_count /crs-sqli) == "$before" ]] \
        || fail 'embedded CRS sent a denied request to the backend'
    require_log '[id "949110"]'

    printf '{"name":"1%s OR %s1%s=%s1"}' "'" "'" "'" "'" >"$temp_dir/crs-json-sqli"
    before=$(backend_count /crs-json-sqli)
    status=$(request "$temp_dir/response" --header 'Host: crs.local' \
        --header 'Content-Type: application/json' \
        --data-binary "@$temp_dir/crs-json-sqli" http://127.0.0.1:10001/crs-json-sqli)
    check_status 403 "$status" 'embedded CRS JSON SQLi denial'
    [[ $(backend_count /crs-json-sqli) == "$before" ]] \
        || fail 'embedded CRS sent a denied JSON request to the backend'
fi

# A field-only multipart body must not need a temporary upload directory. This used
# to abort the WASI plugin in std::env::temp_dir() before the part was published.
printf '%b' '--X\r\nContent-Disposition: form-data; name="name"\r\n\r\nAlice\r\n--X--\r\n' \
    >"$temp_dir/multipart-field"
status=$(request "$temp_dir/response" --header 'Host: crs.local' \
    --header 'content-type: multipart/form-data; boundary=X' \
    --data-binary "@$temp_dir/multipart-field" 'http://127.0.0.1:10001/greet?name=test')
check_status 200 "$status" 'field-only multipart'
if envoy_logs | grep --quiet --fixed-strings 'not supported by WASI yet'; then
    fail 'field-only multipart aborted in the WASI temporary-directory path'
fi

envoy_logs >"$temp_dir/envoy.log"
grep --quiet --fixed-strings 'test blocked' "$temp_dir/envoy.log" \
    || fail 'RelevantOnly audit output did not reach the bounded Proxy-Wasm log sink'

printf 'Envoy 1.40 Coraza connector lifecycle checks passed\n'
