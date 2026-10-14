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

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
compose=(docker compose -f "$script_dir/compose.yaml" -p libperfusion-envoy-test)
temp_dir=$(mktemp -d)
compat_config="$script_dir/.envoy-istio-compatible.$$.yaml"

cleanup() {
    local exit_code=$?
    trap - EXIT
    if (( exit_code != 0 )); then
        "${compose[@]}" logs --no-color envoy 2>&1 \
            | grep --extended-regexp --ignore-case 'critical|error|warning|libperfusion|wasm' \
            | tail --lines=40 >&2 || true
    fi
    "${compose[@]}" down --volumes >/dev/null 2>&1 || true
    rm -f "$compat_config"
    rm -rf "$temp_dir"
    exit "$exit_code"
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

check_status() {
    local expected=$1
    local actual=$2
    local description=$3
    [[ $actual == "$expected" ]] || fail "$description returned HTTP $actual, expected $expected"
}

request() {
    local output=$1
    shift
    curl --silent --show-error --output "$output" --write-out '%{http_code}' "$@"
}

wait_for_envoy() {
    local status
    for _attempt in {1..60}; do
        status=$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:10000/health || true)
        if [[ $status == 200 ]]; then
            return
        fi
        sleep 1
    done
    fail 'Envoy did not become ready; inspect docker compose logs envoy'
}

for config in envoy.yaml envoy-blocking.yaml envoy-response-blocking.yaml; do
    "${compose[@]}" run --rm --no-deps envoy --mode validate \
        -c "/etc/envoy/config/$config"
done

sed \
    -e 's/allow_on_headers_stop_iteration: true/allow_on_headers_stop_iteration: false/' \
    -e 's/"request_mode":"detect"/"request_mode":"block","allow_request_headers_before_body_verdict":true/' \
    -e 's/"response_mode":"detect"/"response_mode":"off"/' \
    -e 's/"incomplete_inspection_policy":"report"/"incomplete_inspection_policy":"reject"/' \
    "$script_dir/envoy.yaml" >"$compat_config"
compat_config_name=$(basename -- "$compat_config")
"${compose[@]}" run --rm --no-deps envoy --mode validate \
    -c "/etc/envoy/config/$compat_config_name"

ENVOY_CONFIG="$compat_config_name" "${compose[@]}" up --detach
wait_for_envoy
status=$(request "$temp_dir/response" --request POST --data-urlencode 'query=hello' http://127.0.0.1:10000/echo)
check_status 200 "$status" 'Istio-compatible clean request body'
status=$(request "$temp_dir/response" --header 'x-untrusted: <script>alert(1)</script>' http://127.0.0.1:10000/)
check_status 403 "$status" 'Istio-compatible blocked request header'
status=$(request "$temp_dir/response" --data-urlencode 'query=1 UNION SELECT password FROM users' http://127.0.0.1:10000/echo)
check_status 403 "$status" 'Istio-compatible blocked request body'
status=$(request "$temp_dir/response" http://127.0.0.1:10000/health)
check_status 200 "$status" 'request after Istio-compatible body rejection'
"${compose[@]}" down >/dev/null

ENVOY_CONFIG=envoy-blocking.yaml "${compose[@]}" up --detach
wait_for_envoy

dd if=/dev/zero of="$temp_dir/body" bs=1024 count=160 status=none
status=$(request "$temp_dir/response" --request POST --header 'content-type: application/octet-stream' \
    --data-binary "@$temp_dir/body" http://127.0.0.1:10000/echo)
check_status 200 "$status" 'allowed 160 KiB request body'

status=$(request "$temp_dir/response" 'http://127.0.0.1:10000/?q=1%27%20OR%20%271%27=%271')
check_status 403 "$status" 'SQLi query'

status=$(request "$temp_dir/response" 'http://127.0.0.1:10000/%3Cscript%3Ealert(1)%3C/script%3E')
check_status 403 "$status" 'percent-encoded path XSS'

printf '%s' '{"comment":"\u003cscript\u003ealert(1)\u003c/script\u003e"}' >"$temp_dir/xss.json"
status=$(request "$temp_dir/response" --request POST --header 'content-type: application/json' \
    --data-binary "@$temp_dir/xss.json" http://127.0.0.1:10000/)
check_status 403 "$status" 'escaped JSON XSS'

status=$(request "$temp_dir/response" --header 'x-untrusted: <script>alert(1)</script>' \
    http://127.0.0.1:10000/)
check_status 403 "$status" 'request header XSS'

status=$(request "$temp_dir/response" --header 'cookie: payload=%253Cscript%253Ealert(1)%253C%252Fscript%253E' \
    http://127.0.0.1:10000/)
check_status 403 "$status" 'percent-encoded cookie XSS'

status=$(request "$temp_dir/response" --form-string 'query=1 UNION SELECT password FROM users' \
    http://127.0.0.1:10000/echo)
check_status 403 "$status" 'multipart SQLi field'

status=$(request "$temp_dir/response" --header 'x-untrusted: query=1%2527%2520OR%2520%25271%2527=%25271' \
    http://127.0.0.1:10000/)
check_status 403 "$status" 'percent-encoded custom-header SQLi'

status=$(request "$temp_dir/response" --header 'x-untrusted: %252525253Cscript%252525253E' \
    http://127.0.0.1:10000/)
check_status 400 "$status" 'header encoding beyond inspection depth'

printf '%s' '%253Cscript%253Ealert(1)%253C%252Fscript%253E' >"$temp_dir/xss.txt"
status=$(request "$temp_dir/response" --request POST --header 'content-type: text/plain' \
    --data-binary "@$temp_dir/xss.txt" http://127.0.0.1:10000/echo)
check_status 403 "$status" 'percent-encoded raw-body XSS'

printf '%s' '{"comment":"<script>alert(1)</script>"}' | gzip --stdout >"$temp_dir/xss.json.gz"
status=$(request "$temp_dir/response" --request POST --header 'content-type: application/json' \
    --header 'content-encoding: gzip' --data-binary "@$temp_dir/xss.json.gz" http://127.0.0.1:10000/)
check_status 403 "$status" 'decompressed request XSS'

dd if=/dev/zero of="$temp_dir/upload" bs=1048576 count=8 status=none
status=$(request "$temp_dir/response" --request POST --header 'content-type: application/octet-stream' \
    --data-binary "@$temp_dir/upload" http://127.0.0.1:10000/upload)
check_status 200 "$status" '8 MiB upload'

dd if=/dev/zero of="$temp_dir/upload-too-large" bs=1048576 count=9 status=none
status=$(request "$temp_dir/response" --request POST --header 'content-type: application/octet-stream' \
    --data-binary "@$temp_dir/upload-too-large" http://127.0.0.1:10000/upload)
check_status 413 "$status" '9 MiB upload'

"${compose[@]}" down >/dev/null
ENVOY_CONFIG=envoy.yaml "${compose[@]}" up --detach
wait_for_envoy

printf '\000\000\000\000\000' >"$temp_dir/grpc-request"
status=$(request "$temp_dir/response" --dump-header "$temp_dir/grpc-headers" --http2-prior-knowledge \
    --header 'content-type: application/grpc' --header 'te: trailers' \
    --data-binary "@$temp_dir/grpc-request" \
    http://127.0.0.1:10000/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/Echo)
check_status 200 "$status" 'gRPC response with trailers in detect mode'
if ! grep --ignore-case --quiet '^grpc-status: 0' "$temp_dir/grpc-headers"; then
    fail 'gRPC echo response did not return its success trailer'
fi

"${compose[@]}" down >/dev/null
ENVOY_CONFIG=envoy-response-blocking.yaml "${compose[@]}" up --detach
wait_for_envoy

status=$(request "$temp_dir/response" --dump-header "$temp_dir/headers" --http2-prior-knowledge \
    --header 'content-type: application/grpc' --header 'te: trailers' \
    --data-binary "@$temp_dir/grpc-request" \
    http://127.0.0.1:10000/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/Echo)
check_status 200 "$status" 'blocked gRPC response'
if ! grep --ignore-case --quiet '^grpc-status: 14' "$temp_dir/headers"; then
    fail 'blocked gRPC response did not return the local UNAVAILABLE status'
fi

status=$(request "$temp_dir/response" http://127.0.0.1:10000/health)
check_status 200 "$status" 'request after blocked gRPC response'

status=$(request "$temp_dir/response" --dump-header "$temp_dir/headers" \
    'http://127.0.0.1:10000/?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E')
check_status 502 "$status" 'reflected response-body XSS'
if grep --quiet --fixed-strings 'alert(1)' "$temp_dir/response"; then
    fail 'blocked response body leaked the XSS payload'
fi

status=$(request "$temp_dir/response" --dump-header "$temp_dir/headers" \
    --header 'x-echo-set-header: set-cookie:preview=%253Cscript%253Ealert(1)%253C%252Fscript%253E' \
    http://127.0.0.1:10000/)
check_status 502 "$status" 'reflected response-header XSS'
if grep --ignore-case --quiet '^set-cookie:' "$temp_dir/headers"; then
    fail 'blocked response retained an upstream Set-Cookie header'
fi

printf 'Envoy 1.40 request/response inspection checks passed\n'
