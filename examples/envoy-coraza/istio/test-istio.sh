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

# Istio MVP harness for the envoy-coraza Rust Proxy-Wasm filter.
#
# Installs Gateway API CRDs and one pinned Istio version into the isolated
# Kind cluster, inserts the filter into a Gateway API gateway through an
# EnvoyFilter (artifact fetched from a digest-pinned local HTTP server), and
# runs lifecycle, rendered-config and observability assertions equivalent to
# examples/envoy-coraza/test-envoy.sh. See README.md in this directory.
#
# Usage:
#   bash test-istio.sh                    # Istio 1.30.5 (default)
#   ISTIO_VERSION=1.30.7 bash test-istio.sh
#   KEEP=1 ...                            # keep the deployment for debugging
#   ORACLE_WASM=/path/to/main.wasm ...    # smoke a custom upstream Go artifact
#   ORACLE_WASM=none ...                  # skip the oracle smoke entirely
#
# ORACLE_WASM semantics: unset runs the pinned upstream Go artifact; `none`
# skips the oracle smoke (the summary then reports gating assertions only);
# any other value must be an existing file, checked before the cluster is
# touched. An empty value is rejected rather than silently re-defaulting.
#
# The script is idempotent: it uninstalls any previous Istio first and tears
# everything down on exit unless KEEP=1.

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
script_dir="$repo_root/examples/envoy-coraza/istio"

ISTIO_VERSION=${ISTIO_VERSION:-1.30.5}
KEEP=${KEEP:-0}
# Unset-only default: an explicitly empty ORACLE_WASM is rejected below
# instead of silently re-enabling the pinned artifact.
ORACLE_WASM=${ORACLE_WASM-/tmp/coraza-proxy-wasm-upstream-pinned/build/main.wasm}
KIND_CLUSTER=coraza-envoy-istio
NAMESPACE=coraza-istio
GATEWAY_NAME=coraza-gateway
HTTP_PORT=8123
FORWARD_PORT=18080
RESULTS_DIR="/tmp/coraza-istio-results-$ISTIO_VERSION"
ARTIFACT_DIR=/tmp/coraza-istio-artifacts

# Gateway API v1.5.0 CRDs (not shipped in the istioctl archives).
GATEWAY_API_URL=https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.0/standard-install.yaml
GATEWAY_API_SHA256=510338cf6709f84410efcce5269268f4c7c5067efdc5d04c75aa2fd2f8380c96
GATEWAY_API_CACHE=/tmp/gateway-api-standard-install-v1.5.0.yaml

# Binaryen supplies wasm-merge, used to link ENOSYS stubs (wasi-stub.wat) for
# the WASI functions Envoy <= 1.39 hosts do not implement. See README.md.
BINARYEN_URL=https://github.com/WebAssembly/binaryen/releases/download/version_123/binaryen-version_123-x86_64-linux.tar.gz
BINARYEN_SHA256=e959f2170af4c20c552e9de3a0253704d6a9d2766e8fdb88e4d6ac4bae9388fe
BINARYEN_DIR=/tmp/binaryen-version_123

# Artifact provenance pins: the sha256 of the unpatched make build-envoy-wasm
# output and of the Istio-served (stub-merged) artifact this harness was last
# validated against. A mismatch means the filter changed: re-validate on both
# Istio versions, update these constants, and re-record the results
# (see README.md, "Updating the artifact pins").
EXPECTED_UNPATCHED_SHA256=dbe01dd7d581fcc70c9226079f5a3d49394091bb8d43eede37f0e267108a9d36
EXPECTED_ISTIO_SHA256=TO_BE_RECORDED

# Total gating PASS lines the harness must emit (the oracle smoke records up
# to five more PASS lines through `oracle_pass`, and never gates). A mismatch means an assertion
# was added or lost; update the constant together with the documented results.
EXPECTED_GATING_ASSERTIONS=52

# Pinned proxy images: the amd64 manifest digest is the deployment pin; the
# manifest-list digest is what containerd reports in pod status.imageID when
# the image is pulled by tag (both verified against the tag, see README.md).
case "$ISTIO_VERSION" in
    1.30.5)
        ISTIOCTL=/tmp/istio-1.30.5/bin/istioctl
        PROXY_AMD64_SHA256=324ec9f74e9194c43b16e859497d67567c93d3d1e5f0804a88ed48002e668f62
        PROXY_LIST_SHA256=a30fb25b1e4cfc0fbc50a8a6795f5984a49022dd0ec09bcd8683b3db35af5ed3
        ;;
    1.30.7)
        ISTIOCTL=/tmp/istio-1.30.7/bin/istioctl
        PROXY_AMD64_SHA256=340794767464f3d13c9e3df38cc663ecbc8264f00c7022dca53ad5c80336681f
        PROXY_LIST_SHA256=f8f963340f92550b7b67228b0319fba7963a98137bdaace3f593da186427e717
        ;;
    *)
        printf 'FAIL: unsupported ISTIO_VERSION %s (supported: 1.30.5, 1.30.7)\n' "$ISTIO_VERSION" >&2
        exit 1
        ;;
esac

export KUBECONFIG=/tmp/coraza-envoy-istio-kubeconfig

http_server_pid=""
forward_pid=""

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

pass() {
    printf 'PASS: %s\n' "$1" | tee -a "$RESULTS_DIR/assertions.txt"
}

# Prerequisite binaries first: the kube-context guard below needs kubectl, and
# its message is misleading when kubectl itself is missing.
command -v python3 >/dev/null 2>&1 || fail 'python3 is required'
command -v docker >/dev/null 2>&1 || fail 'docker is required'
command -v curl >/dev/null 2>&1 || fail 'curl is required'
command -v kubectl >/dev/null 2>&1 || fail 'kubectl is required'
command -v kind >/dev/null 2>&1 || fail 'kind is required'
command -v git >/dev/null 2>&1 || fail 'git is required'
command -v make >/dev/null 2>&1 || fail 'make is required'
[[ -x $ISTIOCTL ]] || fail "pinned istioctl is missing: $ISTIOCTL"
[[ $ORACLE_WASM == none || -f $ORACLE_WASM ]] \
    || fail "ORACLE_WASM must be 'none' or an existing file (got: '$ORACLE_WASM')"

# Only ever touch the isolated Kind cluster created for this harness.
[[ $(kubectl config current-context) == "kind-$KIND_CLUSTER" ]] \
    || fail "kube context is $(kubectl config current-context), expected kind-$KIND_CLUSTER"

cleanup() {
    local exit_code=$?
    trap - EXIT
    if (( exit_code != 0 )); then
        kubectl -n "$NAMESPACE" logs -l "gateway.networking.k8s.io/gateway-name=$GATEWAY_NAME" \
            --tail=100 --prefix 2>/dev/null >"$RESULTS_DIR/gateway-failure.log" || true
    fi
    if [[ -n $forward_pid ]]; then
        kill "$forward_pid" 2>/dev/null || true
    fi
    if [[ -n $http_server_pid ]]; then
        kill "$http_server_pid" 2>/dev/null || true
    fi
    if (( KEEP == 0 )); then
        kubectl delete envoyfilter --all -n "$NAMESPACE" >/dev/null 2>&1 || true
        kubectl delete namespace "$NAMESPACE" --wait=false >/dev/null 2>&1 || true
        "$ISTIOCTL" uninstall --purge --force -y >/dev/null 2>&1 || true
        # uninstall --purge leaves istio-system behind, still holding the CA
        # material and election configmaps; delete the namespace too.
        kubectl delete namespace istio-system --wait=false >/dev/null 2>&1 || true
        kubectl delete -f "$GATEWAY_API_CACHE" >/dev/null 2>&1 || true
    fi
    exit "$exit_code"
}

mkdir -p "$ARTIFACT_DIR"
rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"
: >"$RESULTS_DIR/assertions.txt"

printf '== envoy-coraza Istio MVP harness\n'
printf 'istio_version=%s\n' "$ISTIO_VERSION"
printf 'istioctl_client=%s\n' "$("$ISTIOCTL" version --remote=false)"

# ---------------------------------------------------------------------------
# Artifact preparation (before mutating the cluster).
# ---------------------------------------------------------------------------

make -C "$repo_root" build-envoy-wasm
BUILT_WASM="$repo_root/target/wasm32-wasip1/release/envoy_coraza.wasm"
[[ -f $BUILT_WASM ]] || fail "Wasm artifact is missing: $BUILT_WASM"
BUILT_SHA256=$(sha256sum "$BUILT_WASM" | cut -d' ' -f1)

# Provenance: record the revision and, because this worktree carries
# uncommitted work, the full dirty-state listing; a dirty tree is marked
# loudly rather than failed so in-development runs stay possible.
GIT_HEAD=$(git -C "$repo_root" rev-parse HEAD)
git -C "$repo_root" status --porcelain >"$RESULTS_DIR/git-status.txt"
GIT_DIRTY=false
if [[ -s $RESULTS_DIR/git-status.txt ]]; then
    GIT_DIRTY=true
    printf 'WARNING: worktree is dirty (see git-status.txt in the results dir); the artifact is attributable to those uncommitted changes plus %s\n' "$GIT_HEAD" >&2
fi

if [[ ! -d $BINARYEN_DIR ]]; then
    curl -fsSL -o "$ARTIFACT_DIR/binaryen.tar.gz" "$BINARYEN_URL" \
        || fail 'binaryen download failed'
    echo "$BINARYEN_SHA256  $ARTIFACT_DIR/binaryen.tar.gz" | sha256sum --check --status \
        || fail 'binaryen download digest mismatch'
    tar -xzf "$ARTIFACT_DIR/binaryen.tar.gz" -C /tmp
fi
WASM_AS="$BINARYEN_DIR/bin/wasm-as"
WASM_MERGE="$BINARYEN_DIR/bin/wasm-merge"
[[ -x $WASM_MERGE ]] || fail "wasm-merge is missing: $WASM_MERGE"

# Link the ENOSYS stubs for the WASI functions Envoy <= 1.39 hosts lack; the
# resulting artifact is what Istio serves (the unpatched build stays canonical
# for the standalone Envoy 1.40 harness). --all-features is required because
# the artifact uses post-MVP wasm features (bulk memory, sign extension);
# wasm-merge validates the merged module with conservative defaults and
# rejects it otherwise ("memory.copy operations require bulk memory
# operations").
"$WASM_AS" "$script_dir/wasi-stub.wat" -o "$ARTIFACT_DIR/wasi-stub.wasm"
"$WASM_MERGE" "$ARTIFACT_DIR/wasi-stub.wasm" wasi_snapshot_preview1 \
    "$BUILT_WASM" envoy-coraza -o "$ARTIFACT_DIR/envoy_coraza.wasm" \
    --rename-export-conflicts --all-features >/dev/null \
    || fail 'wasm-merge failed to link the WASI stubs'
WASM_PATH="$ARTIFACT_DIR/envoy_coraza.wasm"
WASM_SHA256=$(sha256sum "$WASM_PATH" | cut -d' ' -f1)
{
    printf 'git_head=%s\ngit_dirty=%s\n' "$GIT_HEAD" "$GIT_DIRTY"
    printf 'unpatched_wasm=%s\nunpatched_sha256=%s\n' "$BUILT_WASM" "$BUILT_SHA256"
    printf 'wasm_artifact=%s\nwasm_sha256=%s\n' "$WASM_PATH" "$WASM_SHA256"
} | tee "$RESULTS_DIR/artifact.txt"
# Both pins are checked after both hashes are known so a mismatch reports the
# full picture in one run (no update loop over two runs).
if [[ $BUILT_SHA256 != "$EXPECTED_UNPATCHED_SHA256" || $WASM_SHA256 != "$EXPECTED_ISTIO_SHA256" ]]; then
    fail "artifact changed; observed unpatched $BUILT_SHA256 (expected $EXPECTED_UNPATCHED_SHA256), observed stub-merged $WASM_SHA256 (expected $EXPECTED_ISTIO_SHA256); update the constants and re-record the Istio results"
fi

# The merged module must import exactly the WASI functions observed on the
# pinned artifacts. The Envoy 1.38 v8 host implements 18 WASI functions (the
# 13 below plus args_get, args_sizes_get, fd_fdstat_set_flags, poll_oneoff and
# sched_yield; proxy-wasm-cpp-host beb8a4e, include/proxy-wasm/exports.h
# FOR_ALL_WASI_FUNCTIONS, registered in src/wasm.cc, implemented in
# src/exports.cc); this module simply does not import the other five. An exact
# set (not a superset check) so a new import fails loudly with the diff.
python3 - "$WASM_PATH" <<'PY'
import sys

def read_leb(buf, i):
    result = 0
    shift = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, i

data = open(sys.argv[1], "rb").read()
i = 8
wasi = []
while i < len(data):
    section = data[i]
    i += 1
    size, i = read_leb(data, i)
    end = i + size
    if section == 2:
        count, j = read_leb(data, i)
        for _ in range(count):
            mod_len, j = read_leb(data, j)
            module = data[j : j + mod_len].decode()
            j += mod_len
            name_len, j = read_leb(data, j)
            name = data[j : j + name_len].decode()
            j += name_len
            kind = data[j]
            j += 1
            if kind == 0:
                _, j = read_leb(data, j)
            elif kind == 1:
                j += 1
                _, j = read_leb(data, j)
            elif kind == 2:
                flags = data[j]
                j += 1
                _, j = read_leb(data, j)
                if flags & 1:
                    _, j = read_leb(data, j)
            elif kind == 3:
                j += 2
            if module == "wasi_snapshot_preview1":
                wasi.append(name)
    i = end

expected = {
    "clock_time_get",
    "environ_get",
    "environ_sizes_get",
    "fd_close",
    "fd_fdstat_get",
    "fd_prestat_dir_name",
    "fd_prestat_get",
    "fd_read",
    "fd_seek",
    "fd_write",
    "path_open",
    "proc_exit",
    "random_get",
}
observed = set(wasi)
if observed != expected:
    added = ", ".join(sorted(observed - expected)) or "(none)"
    removed = ", ".join(sorted(expected - observed)) or "(none)"
    raise AssertionError(
        f"merged module WASI imports changed; added: {added}; removed: {removed}. "
        "Envoy <= 1.39 hosts reject unknown WASI imports at load time; "
        "extend wasi-stub.wat and update this set plus the docs."
    )
print(f"wasi imports after merge ({len(wasi)}): {', '.join(wasi)}")
PY

# Gateway API CRDs, cached under /tmp for offline reruns.
if ! sha256sum --check --status <(printf '%s  %s\n' "$GATEWAY_API_SHA256" "$GATEWAY_API_CACHE") 2>/dev/null; then
    curl -fsSL -o "$GATEWAY_API_CACHE" "$GATEWAY_API_URL" || fail 'Gateway API CRD download failed'
fi
sha256sum --check --status <(printf '%s  %s\n' "$GATEWAY_API_SHA256" "$GATEWAY_API_CACHE") \
    || fail 'Gateway API CRD cache digest mismatch'
printf 'gateway_api_crds=%s (sha256 %s)\n' "$GATEWAY_API_URL" "$GATEWAY_API_SHA256"

# ---------------------------------------------------------------------------
# Cluster bring-up. The exit trap is installed only here: everything above
# only validated inputs and built artifacts, so a failed precondition must not
# trigger the destructive teardown of a cluster this run never touched.
# ---------------------------------------------------------------------------

trap cleanup EXIT

# Idempotency: remove any previous harness installation first.
kubectl delete envoyfilter --all -n "$NAMESPACE" >/dev/null 2>&1 || true
kubectl delete namespace "$NAMESPACE" --wait=false >/dev/null 2>&1 || true
"$ISTIOCTL" uninstall --purge --force -y >/dev/null 2>&1 || true
# uninstall --purge leaves istio-system behind with CA material; the previous
# run's cleanup deletes the namespace, wait for that here so istioctl install
# starts from a clean slate.
kubectl delete namespace istio-system --wait=false >/dev/null 2>&1 || true
kubectl delete -f "$GATEWAY_API_CACHE" >/dev/null 2>&1 || true
for _attempt in {1..60}; do
    if ! kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 \
        && ! kubectl get namespace istio-system >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
if kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
    fail "namespace $NAMESPACE is stuck Terminating; inspect its finalizers with 'kubectl get namespace $NAMESPACE -o jsonpath='{.spec.finalizers}'', clear them, then retry"
fi
if kubectl get namespace istio-system >/dev/null 2>&1; then
    fail "namespace istio-system is stuck Terminating; inspect its finalizers with 'kubectl get namespace istio-system -o jsonpath='{.spec.finalizers}'', clear them, then retry"
fi

kubectl apply -f "$GATEWAY_API_CACHE" >/dev/null || fail 'Gateway API CRD install failed'
kubectl wait --for=condition=Established crd/gateways.gateway.networking.k8s.io --timeout=120s >/dev/null \
    || fail 'Gateway CRD did not become established'

"$ISTIOCTL" install -y -f "$script_dir/istio-operator.yaml" \
    || fail "istioctl install failed for $ISTIO_VERSION"
# istioctl's banner does not end with a newline; emit one so subsequent PASS
# lines are not glued to it in the captured stdout.
printf '\n'
kubectl wait -n istio-system --for=condition=available deploy/istiod --timeout=300s >/dev/null \
    || fail 'istiod did not become available'
kubectl get gatewayclass istio -o jsonpath='{.status.conditions[?(@.type=="Accepted")].status}' \
    | grep -q True || fail 'istio GatewayClass was not accepted'

# Note: istioctl uninstall --purge leaves the empty istio-system namespace
# behind; the apply below tolerates whatever state it is in.
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null \
    || fail "could not (re)create namespace $NAMESPACE"
kubectl apply -f "$script_dir/backend.yaml" >/dev/null || fail 'backend install failed'
kubectl apply -f "$script_dir/gateway.yaml" >/dev/null || fail 'gateway install failed'

# The EnvoyFilter matches listener port 80 only: a second listener on this
# Gateway would serve traffic without the WAF, and a different single port
# would not be covered either. Fail loudly instead of letting that happen
# silently (see README.md, "Known limitations").
LISTENERS=$(kubectl -n "$NAMESPACE" get "gateway/$GATEWAY_NAME" -o json \
    | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["spec"]["listeners"]))')
python3 - "$LISTENERS" <<'PY' | tee -a "$RESULTS_DIR/assertions.txt"
import json
import sys

listeners = json.loads(sys.argv[1])
assert len(listeners) == 1, f"expected exactly one listener, found {len(listeners)}: {listeners}"
listener = listeners[0]
assert listener.get("port") == 80 and listener.get("protocol") == "HTTP", listener
print("PASS: Gateway has exactly one listener on port 80, so all served traffic is covered")
PY

docker build --quiet --tag coraza-envoy-backend:istio-test "$repo_root/examples/envoy-coraza" >/dev/null \
    || fail 'backend image build failed'
kind load docker-image coraza-envoy-backend:istio-test --name "$KIND_CLUSTER" >/dev/null 2>&1 \
    || fail 'kind load of the backend image failed'

kubectl -n "$NAMESPACE" wait --for=condition=available deploy/coraza-backend --timeout=300s >/dev/null \
    || fail 'backend did not become available'
# The Gateway Programmed condition stays False on Kind: there is no
# LoadBalancer controller to assign the generated Service an address
# ("address pending for hostname ..."). Readiness is the generated gateway
# deployment and pod; the condition value is recorded below for the record.
GATEWAY_PROGRAMMED=$(kubectl -n "$NAMESPACE" get "gateway/$GATEWAY_NAME" \
    -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.message}{"; "}{end}')
printf 'gateway_conditions=%s\n' "$GATEWAY_PROGRAMMED" | tee -a "$RESULTS_DIR/artifact.txt"
kubectl -n "$NAMESPACE" rollout status deploy/coraza-gateway-istio --timeout=300s >/dev/null \
    || fail 'gateway deployment did not become available'

GATEWAY_POD=""
for _attempt in {1..60}; do
    # Pick a Ready pod that is not terminating: never rely on list order, which can
    # return a draining pod during a rollout.
    GATEWAY_POD=$(kubectl -n "$NAMESPACE" get pod -l "gateway.networking.k8s.io/gateway-name=$GATEWAY_NAME" \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.deletionTimestamp}{"\t"}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' 2>/dev/null \
        | awk -F'\t' '$2 == "" && $3 == "True" {print $1; exit}' || true)
    [[ -n $GATEWAY_POD ]] && break
    sleep 2
done
[[ -n $GATEWAY_POD ]] || fail 'gateway pod not found'
kubectl -n "$NAMESPACE" wait --for=condition=Ready "pod/$GATEWAY_POD" --timeout=300s >/dev/null \
    || fail 'gateway pod did not become ready'
printf 'gateway_pod=%s\n' "$GATEWAY_POD"

# Verify the proxy image resolves to the pinned digest.
IMAGE_ID=$(kubectl -n "$NAMESPACE" get pod "$GATEWAY_POD" \
    -o jsonpath='{.status.containerStatuses[?(@.name=="istio-proxy")].imageID}')
printf 'proxy_image_id=%s\n' "$IMAGE_ID" | tee -a "$RESULTS_DIR/artifact.txt"
case "$IMAGE_ID" in
    *"@sha256:$PROXY_AMD64_SHA256") pass "proxy image digest equals the pinned amd64 manifest ($ISTIO_VERSION)" ;;
    *"@sha256:$PROXY_LIST_SHA256") pass "proxy image digest equals the pinned manifest list ($ISTIO_VERSION)" ;;
    *) fail "running istio-proxy image is not the pinned one for $ISTIO_VERSION: $IMAGE_ID" ;;
esac

ENVOY_VERSION=$(kubectl -n "$NAMESPACE" exec -c istio-proxy "$GATEWAY_POD" -- \
    curl -s localhost:15000/server_info | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')
printf 'envoy_version=%s\n' "$ENVOY_VERSION" | tee -a "$RESULTS_DIR/artifact.txt"

# ---------------------------------------------------------------------------
# Artifact server: host HTTP on the Kind bridge gateway, fetched by Envoy's
# remote data source through the coraza-wasm-fetch cluster added by the
# EnvoyFilter.
# ---------------------------------------------------------------------------

FETCH_ADDRESS=$(docker network inspect kind --format '{{json .IPAM.Config}}' | python3 -c '
import json
import sys

for config in json.load(sys.stdin):
    if ":" not in config["Gateway"]:
        print(config["Gateway"])
        break
else:
    raise SystemExit("no IPv4 gateway on the kind network")
')
printf 'artifact_server=http://%s:%s\n' "$FETCH_ADDRESS" "$HTTP_PORT"

python3 -m http.server --bind "$FETCH_ADDRESS" "$HTTP_PORT" \
    --directory "$ARTIFACT_DIR" >"$RESULTS_DIR/http-server.log" 2>&1 &
http_server_pid=$!

# Verify the gateway pod fetches the exact artifact bytes.
FETCHED_SHA=""
for _attempt in {1..20}; do
    FETCHED_SHA=$(kubectl -n "$NAMESPACE" exec -c istio-proxy "$GATEWAY_POD" -- \
        sh -c "curl -s http://$FETCH_ADDRESS:$HTTP_PORT/envoy_coraza.wasm | sha256sum" 2>/dev/null \
        | cut -d' ' -f1 || true)
    [[ $FETCHED_SHA == "$WASM_SHA256" ]] && break
    sleep 1
done
[[ ${FETCHED_SHA:-} == "$WASM_SHA256" ]] \
    || fail "gateway pod fetched ${FETCHED_SHA:-nothing}, expected $WASM_SHA256"
pass 'gateway pod fetches the served artifact bytes (sha256 match)'

# ---------------------------------------------------------------------------
# EnvoyFilter.
# ---------------------------------------------------------------------------

render_envoyfilter() {
    local filter_name=$1
    local uri=$2
    local sha256=$3
    local output=$4
    sed -e "s|__FILTER_NAME__|$filter_name|g" \
        -e "s|__WASM_URI__|$uri|" \
        -e "s|__WASM_SHA256__|$sha256|" \
        -e "s|__WASM_FETCH_ADDRESS__|$FETCH_ADDRESS|" \
        -e "s|__WASM_FETCH_PORT__|$HTTP_PORT|" \
        "$script_dir/envoyfilter.yaml" >"$output"
}

apply_envoyfilter() {
    local filter_name=$1
    local uri=$2
    local sha256=$3
    render_envoyfilter "$filter_name" "$uri" "$sha256" "$RESULTS_DIR/envoyfilter.yaml"
    kubectl apply -f "$RESULTS_DIR/envoyfilter.yaml" >/dev/null 2>&1 \
        || fail "EnvoyFilter apply failed for $filter_name"
}

wait_for_filter() {
    local filter_name=$1
    for _attempt in {1..60}; do
        if kubectl -n "$NAMESPACE" exec -c istio-proxy "$GATEWAY_POD" -- \
            curl -s localhost:15000/config_dump 2>/dev/null \
            | grep -q "\"name\": \"$filter_name\""; then
            return 0
        fi
        sleep 2
    done
    return 1
}

wait_for_filter_absent() {
    local filter_name=$1
    for _attempt in {1..60}; do
        if ! kubectl -n "$NAMESPACE" exec -c istio-proxy "$GATEWAY_POD" -- \
            curl -s localhost:15000/config_dump 2>/dev/null \
            | grep -q "\"name\": \"$filter_name\""; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# Restart the gateway deployment and re-establish the port-forward. Used when
# switching the wasm artifact: Envoy otherwise keeps serving the already
# loaded VM (from a warming or draining listener) even after the EnvoyFilter
# is replaced, so a fresh proxy is the only way to prove which artifact
# actually answers.
#
# The post-restart pod is selected by identity, not name ordering: during a
# rollout the old pod stays Running with no deletionTimestamp and can sort
# first, which left the oracle stage talking to the pod that just served the
# previous artifact. Returns non-zero on failure so the oracle path can
# record ORACLE-FAIL instead of aborting; the KEEP=1 restore path fails fast.
restart_gateway() {
    local old_uids
    old_uids=$(kubectl -n "$NAMESPACE" get pods -l "gateway.networking.k8s.io/gateway-name=$GATEWAY_NAME" \
        -o json | python3 -c '
import json
import sys

for pod in json.load(sys.stdin)["items"]:
    print(pod["metadata"]["uid"])
')
    kubectl -n "$NAMESPACE" rollout restart deploy/coraza-gateway-istio || return 1
    kubectl -n "$NAMESPACE" rollout status deploy/coraza-gateway-istio --timeout=300s >/dev/null || return 1
    GATEWAY_POD=""
    for _attempt in {1..90}; do
        GATEWAY_POD=$(kubectl -n "$NAMESPACE" get pods -l "gateway.networking.k8s.io/gateway-name=$GATEWAY_NAME" \
            -o json | python3 -c '
import json
import sys

excluded = set(filter(None, sys.argv[1].split()))
for pod in json.load(sys.stdin)["items"]:
    metadata = pod["metadata"]
    if metadata["uid"] in excluded or metadata.get("deletionTimestamp"):
        continue
    conditions = {c["type"]: c["status"] for c in pod["status"].get("conditions", [])}
    if pod["status"].get("phase") == "Running" and conditions.get("Ready") == "True":
        print(metadata["name"])
        break
' "$old_uids")
        [[ -n $GATEWAY_POD ]] && break
        sleep 2
    done
    [[ -n $GATEWAY_POD ]] || return 1
    if [[ -n $forward_pid ]]; then
        kill "$forward_pid" 2>/dev/null || true
    fi
    kubectl -n "$NAMESPACE" port-forward "pod/$GATEWAY_POD" "$FORWARD_PORT:80" \
        >"$RESULTS_DIR/port-forward.log" 2>&1 &
    forward_pid=$!
    for _attempt in {1..20}; do
        curl -s -o /dev/null "http://127.0.0.1:$FORWARD_PORT/" && return 0
        sleep 1
    done
    return 1
}

# Verify the ACTIVE filter chain serves exactly one wasm filter with the
# expected name and artifact digest, and that the config dump itself comes
# from the expected pod (node.id): the check is only meaningful if the admin
# endpoint answered for the pod the port-forward targets. Presence anywhere
# in the config dump (warming or draining listeners included) proves nothing.
verify_wasm_identity() {
    local expected_name=$1
    local expected_sha256=$2
    local dump_file=$3
    kubectl -n "$NAMESPACE" exec -c istio-proxy "$GATEWAY_POD" -- \
        curl -s localhost:15000/config_dump >"$dump_file" 2>/dev/null
    python3 - "$dump_file" "$expected_name" "$expected_sha256" "$GATEWAY_POD" <<'PY'
import json
import sys

dump = json.load(open(sys.argv[1]))
expected_name, expected_sha256, pod_name = sys.argv[2], sys.argv[3], sys.argv[4]
node_id = ""
for config in dump["configs"]:
    if "BootstrapConfigDump" in config.get("@type", ""):
        node_id = config.get("bootstrap", {}).get("node", {}).get("id", "")
assert pod_name in node_id, f"config dump is from node {node_id!r}, expected pod {pod_name}"
hcm = None
for config in dump["configs"]:
    if "ListenersConfigDump" not in config.get("@type", ""):
        continue
    for listener in config.get("dynamic_listeners", []):
        active = listener.get("active_state")
        if not active or listener.get("name") != "0.0.0.0_80":
            continue
        for chain in active["listener"]["filter_chains"]:
            for network_filter in chain["filters"]:
                if network_filter["name"] == "envoy.filters.network.http_connection_manager":
                    hcm = network_filter["typed_config"]
assert hcm is not None, "no active HCM on listener 0.0.0.0_80"
wasm_filters = [f for f in hcm["http_filters"] if f["name"] == "envoy.filters.http.wasm"]
assert len(wasm_filters) == 1, f"expected exactly one wasm filter, found {len(wasm_filters)}"
config = wasm_filters[0]["typed_config"]["value"]["config"]
assert config["name"] == expected_name, f"active wasm filter is {config['name']}, expected {expected_name}"
sha256 = config["vm_config"]["code"]["remote"]["sha256"]
assert sha256 == expected_sha256, f"active chain serves sha256 {sha256}, expected {expected_sha256}"
PY
}

# Count of Rust denial-signature access-log lines (the Rust plugin's
# filter-state values; the Go oracle leaves these fields empty).
rust_deny_log_count() {
    kubectl -n "$NAMESPACE" logs "$GATEWAY_POD" -c istio-proxy 2>/dev/null \
        | grep -c 'event=coraza_waf_blocked_request' || true
}

apply_envoyfilter envoy-coraza-test "http://coraza-wasm-fetch/envoy_coraza.wasm" "$WASM_SHA256"
wait_for_filter envoy-coraza-test || fail 'wasm filter did not render into the gateway config'

# ---------------------------------------------------------------------------
# Rendered-config assertions.
# ---------------------------------------------------------------------------

kubectl -n "$NAMESPACE" exec -c istio-proxy "$GATEWAY_POD" -- curl -s localhost:15000/config_dump \
    >"$RESULTS_DIR/config_dump.json"
python3 - "$RESULTS_DIR/config_dump.json" "$WASM_SHA256" <<'PY' | tee -a "$RESULTS_DIR/assertions.txt"
import json
import sys

dump = json.load(open(sys.argv[1]))
sha256 = sys.argv[2]
hcm = None
for config in dump["configs"]:
    if "ListenersConfigDump" not in config.get("@type", ""):
        continue
    for listener in config.get("dynamic_listeners", []):
        if listener.get("name") != "0.0.0.0_80":
            continue
        active = listener["active_state"]["listener"]
        for chain in active["filter_chains"]:
            for network_filter in chain["filters"]:
                if network_filter["name"] == "envoy.filters.network.http_connection_manager":
                    hcm = network_filter["typed_config"]

assert hcm is not None, "HTTP connection manager not found on listener 0.0.0.0_80"
names = [http_filter["name"] for http_filter in hcm["http_filters"]]
wasm = next(f for f in hcm["http_filters"] if f["name"] == "envoy.filters.http.wasm")
router_index = names.index("envoy.filters.http.router")
wasm_index = names.index("envoy.filters.http.wasm")
assert wasm_index == router_index - 1, f"wasm filter at {wasm_index}, router at {router_index}"
print(f"PASS: wasm filter inserted immediately before envoy.filters.http.router (chain: {', '.join(names)})")

config = wasm["typed_config"]["value"]["config"]
assert config["failure_policy"] == "FAIL_CLOSED", config["failure_policy"]
print("PASS: wasm failure_policy is FAIL_CLOSED")
assert config["allow_on_headers_stop_iteration"] is True
print("PASS: wasm allow_on_headers_stop_iteration is true")
remote = config["vm_config"]["code"]["remote"]
assert remote["sha256"] == sha256, remote["sha256"]
print(f"PASS: wasm code.remote sha256 pins the served artifact ({sha256})")
expected_retry = {"retry_back_off": {"base_interval": "1s", "max_interval": "10s"}, "num_retries": 5}
assert remote.get("retry_policy") == expected_retry, remote.get("retry_policy")
assert remote["http_uri"]["timeout"] == "120s", remote["http_uri"]
print(f"PASS: wasm code.remote retry policy and fetch timeout match the documented values ({expected_retry}, timeout 120s)")
assert hcm.get("http_protocol_options", {}).get("enable_trailers") is True
print("PASS: HCM enables HTTP/1.1 request trailers")
file_logs = [log.get("typed_config", {}) for log in hcm.get("access_log", [])
             if log.get("name") == "envoy.access_loggers.file"]
assert file_logs, "no file access log on the HCM"
formats = [log.get("log_format", {}).get("text_format_source", {}).get("inline_string", "")
           for log in file_logs]
assert any("coraza_observability" in fmt
           and "%FILTER_STATE(wasm.io.coraza.waf.event:PLAIN)%" in fmt
           and "%FILTER_STATE(wasm.io.coraza.waf.rule_id:PLAIN)%" in fmt
           for fmt in formats), f"no coraza filter-state access-log format: {formats}"
print("PASS: HCM file access log carries the coraza filter-state format")
PY

# Record the effective runtime guard. Envoy only lists explicitly-set runtime
# keys in /runtime; absence means the compiled default applies (the guard
# defaults to enabled since the 1.38-branch backport of envoy#46842). The flag
# itself is asserted present in the running Envoy binary.
RUNTIME_GUARD=envoy.reloadable_features.filter_manager_forward_added_data_on_continue
kubectl -n "$NAMESPACE" exec -c istio-proxy "$GATEWAY_POD" -- \
    curl -s 'localhost:15000/runtime?format=json' >"$RESULTS_DIR/runtime.json"
GUARD_OUTPUT=$(python3 - "$RESULTS_DIR/runtime.json" "$RUNTIME_GUARD" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1]))["entries"].get(sys.argv[2])
print(value["final_value"] if value else "compiled-default (no runtime override)")
print("true" if value else "false")
PY
)
GUARD_VALUE=$(printf '%s\n' "$GUARD_OUTPUT" | sed -n 1p)
GUARD_OVERRIDDEN=$(printf '%s\n' "$GUARD_OUTPUT" | sed -n 2p)
printf 'runtime_guard=%s value=%s\n' "$RUNTIME_GUARD" "$GUARD_VALUE" \
    | tee -a "$RESULTS_DIR/artifact.txt"
if kubectl -n "$NAMESPACE" exec -c istio-proxy "$GATEWAY_POD" -- \
    sh -c "grep -aq '$RUNTIME_GUARD' /usr/local/bin/envoy"; then
    pass "runtime guard $RUNTIME_GUARD present in the running Envoy binary"
else
    fail "runtime guard $RUNTIME_GUARD not found in the running Envoy binary"
fi
if [[ $GUARD_OVERRIDDEN == true ]]; then
    pass "runtime guard recorded with an explicit override: $GUARD_VALUE"
else
    pass "runtime guard recorded: $GUARD_VALUE"
fi

# ---------------------------------------------------------------------------
# Request-path assertions (port-forward to the gateway listener on port 80).
# ---------------------------------------------------------------------------

kubectl -n "$NAMESPACE" port-forward "pod/$GATEWAY_POD" "$FORWARD_PORT:80" \
    >"$RESULTS_DIR/port-forward.log" 2>&1 &
forward_pid=$!
PORT_FORWARD_READY=false
for _attempt in {1..20}; do
    if curl -s -o /dev/null "http://127.0.0.1:$FORWARD_PORT/"; then
        PORT_FORWARD_READY=true
        break
    fi
    sleep 1
done
if [[ $PORT_FORWARD_READY != true ]]; then
    tail -5 "$RESULTS_DIR/port-forward.log" >&2 || true
    fail "port-forward to the gateway pod did not become usable within 20s (see $RESULTS_DIR/port-forward.log)"
fi

request() {
    local output=$1
    shift
    curl --silent --show-error --output "$output" --write-out '%{http_code}' "$@"
}

backend_count() {
    local path=$1
    curl --silent --show-error --get --data-urlencode "path=$path" \
        "http://127.0.0.1:$FORWARD_PORT/__stats"
}

# Positive control for the counter endpoint itself: every "backend not hit"
# assertion below compares two /__stats bodies. Retried to ride out a cold
# backend connection.
STATS_PROBE_OK=false
for _attempt in {1..10}; do
    status=$(request "$RESULTS_DIR/stats-probe" --get --data-urlencode "path=/echo" \
        "http://127.0.0.1:$FORWARD_PORT/__stats")
    if [[ $status == 200 && $(cat "$RESULTS_DIR/stats-probe") =~ ^[0-9]+$ ]]; then
        STATS_PROBE_OK=true
        break
    fi
    sleep 1
done
if [[ $STATS_PROBE_OK != true ]]; then
    fail "/__stats endpoint unreachable or non-numeric through the gateway (HTTP $status, body $(cat "$RESULTS_DIR/stats-probe" 2>/dev/null))"
fi
pass '/__stats backend counter endpoint reachable and numeric'

check_status() {
    local expected=$1
    local actual=$2
    local label=$3
    [[ $actual == "$expected" ]] || fail "$label returned HTTP $actual, expected $expected"
    pass "$label returned HTTP $actual"
}

# EnvoyFilter updates have a reload window in which requests can traverse the
# previous filter chain (config_dump already showing the filter is not proof
# it is enforced yet). Drive denials until the new chain is observably active
# before taking the backend counts the not-hit assertions compare against.
for _attempt in {1..60}; do
    status=$(request "$RESULTS_DIR/body" "http://127.0.0.1:$FORWARD_PORT/phase1-deny" || true)
    [[ $status == 403 ]] && break
    sleep 1
done
[[ $status == 403 ]] \
    || fail "wasm filter did not start denying within the reload window (last status $status)"

# Request-header deny.
before=$(backend_count /phase1-deny)
status=$(request "$RESULTS_DIR/body" "http://127.0.0.1:$FORWARD_PORT/phase1-deny")
check_status 403 "$status" 'phase-1 request denial'
[[ $(backend_count /phase1-deny) == "$before" ]] || fail 'phase-1 denied request reached the backend'
pass 'phase-1 denied request did not reach the backend'

# Allowed stream after a denial.
status=$(request "$RESULTS_DIR/body" "http://127.0.0.1:$FORWARD_PORT/echo")
check_status 200 "$status" 'allowed stream after request denial'

# Unknown authority falls back to the default policy.
status=$(request "$RESULTS_DIR/body" --header 'Host: unknown.local' \
    "http://127.0.0.1:$FORWARD_PORT/phase1-deny")
check_status 403 "$status" 'unknown-authority default-policy denial'

# Request-body deny.
printf 'q=block' >"$RESULTS_DIR/deny-body"
before=$(backend_count /phase2-deny)
status=$(request "$RESULTS_DIR/body" --header 'content-type: application/x-www-form-urlencoded' \
    --data-binary "@$RESULTS_DIR/deny-body" "http://127.0.0.1:$FORWARD_PORT/phase2-deny")
check_status 403 "$status" 'phase-2 request denial'
[[ $(backend_count /phase2-deny) == "$before" ]] || fail 'phase-2 denied request reached the backend'
pass 'phase-2 denied request did not reach the backend'

# Benign byte-exact pass-through (larger than the 32-byte body limits, so the
# ProcessPartial truncation path is exercised).
head -c 16384 /dev/zero | tr '\000' x >"$RESULTS_DIR/expected-pass"
status=$(request "$RESULTS_DIR/pass" --request POST --header 'content-type: application/octet-stream' \
    --data-binary "@$RESULTS_DIR/expected-pass" "http://127.0.0.1:$FORWARD_PORT/echo")
check_status 200 "$status" 'byte-exact benign pass-through'
cmp --silent "$RESULTS_DIR/expected-pass" "$RESULTS_DIR/pass" \
    || fail 'benign request body changed in transit'
pass 'benign request body was byte-exact'

# Aborted held request: the filter holds the request body until EOS, so a
# client reset mid-body must not reach the backend, and the stream ends as an
# error terminal, exactly as in the standalone harness.
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
        raise RuntimeError("gateway responded before the request body reached EOS")
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
finally:
    connection.close()
time.sleep(0.25)
PY
}

before=$(backend_count /abort-held)
abort_held_http1_request "http://127.0.0.1:$FORWARD_PORT/abort-held"
[[ $(backend_count /abort-held) == "$before" ]] \
    || fail 'aborted held request reached the backend before EOS'
pass 'aborted held request did not reach the backend before EOS'
status=$(request "$RESULTS_DIR/body" "http://127.0.0.1:$FORWARD_PORT/abort-held")
check_status 200 "$status" 'normal request after aborted held request'
[[ $(backend_count /abort-held) == "$((before + 1))" ]] \
    || fail 'normal request after abort was not received exactly once'
pass 'normal request after abort was received exactly once'

# Body limit boundaries at N-1/N/N+1 of the configured 32-byte limits.
for size in 31 32 33; do
    head -c "$size" /dev/zero | tr '\000' a >"$RESULTS_DIR/request-$size"
    status=$(request "$RESULTS_DIR/body" --header 'content-type: application/x-www-form-urlencoded' \
        --data-binary "@$RESULTS_DIR/request-$size" "http://127.0.0.1:$FORWARD_PORT/echo")
    check_status 200 "$status" "ProcessPartial request body at N=$size"

    status=$(request "$RESULTS_DIR/body" --header 'Host: reject.local' \
        --header 'content-type: application/x-www-form-urlencoded' \
        --data-binary "@$RESULTS_DIR/request-$size" "http://127.0.0.1:$FORWARD_PORT/echo")
    expected=200
    (( size >= 32 )) && expected=413
    check_status "$expected" "$status" "Reject request body at N=$size"

    status=$(request "$RESULTS_DIR/body" "http://127.0.0.1:$FORWARD_PORT/bytes/$size")
    check_status 200 "$status" "ProcessPartial response body at N=$size"

    status=$(request "$RESULTS_DIR/body" --header 'Host: reject.local' \
        "http://127.0.0.1:$FORWARD_PORT/bytes/$size")
    expected=200
    (( size >= 32 )) && expected=500
    check_status "$expected" "$status" "Reject response body at N=$size"
done

# Response-body deny: upstream body and sensitive headers must be withheld.
status=$(request "$RESULTS_DIR/response" --dump-header "$RESULTS_DIR/headers" \
    "http://127.0.0.1:$FORWARD_PORT/response-deny")
check_status 502 "$status" 'phase-4 response body denial'
if grep --ignore-case --quiet -E '^(x-upstream-secret|set-cookie):' "$RESULTS_DIR/headers"; then
    fail 'response denial leaked an upstream sensitive header'
fi
if grep --quiet --fixed-strings 'secret' "$RESULTS_DIR/response"; then
    fail 'response denial leaked upstream body bytes'
fi
pass 'phase-4 response denial withheld upstream headers and body'

# Response-header deny on a MIME-excluded body.
status=$(request "$RESULTS_DIR/response" --dump-header "$RESULTS_DIR/headers" \
    "http://127.0.0.1:$FORWARD_PORT/large-header-deny")
check_status 502 "$status" 'phase-4 response header denial for excluded body'
if grep --ignore-case --quiet -E '^(x-deny-response|x-large-probe):' "$RESULTS_DIR/headers"; then
    fail 'phase-4 header denial leaked upstream response headers'
fi
if grep --quiet --fixed-strings 'LEAK-MARKER' "$RESULTS_DIR/response"; then
    fail 'phase-4 header denial leaked upstream response body bytes'
fi
pass 'phase-4 header denial withheld upstream headers and body'

# Large MIME-excluded response passes through byte-exact.
head -c 1048577 /dev/zero | tr '\000' z >"$RESULTS_DIR/expected-large"
status=$(request "$RESULTS_DIR/response" --dump-header "$RESULTS_DIR/headers" \
    "http://127.0.0.1:$FORWARD_PORT/large-uninspectable")
check_status 200 "$status" 'large MIME-excluded response'
cmp --silent "$RESULTS_DIR/expected-large" "$RESULTS_DIR/response" \
    || fail 'large MIME-excluded response was not byte-exact'
grep --ignore-case --quiet '^x-large-probe: preserved' "$RESULTS_DIR/headers" \
    || fail 'large MIME-excluded response header was not preserved'
pass 'large MIME-excluded response was byte-exact with headers preserved'

# Response body access off (per-authority policy response-off).
status=$(request "$RESULTS_DIR/response" --header 'Host: off.local' \
    "http://127.0.0.1:$FORWARD_PORT/large-uninspectable")
check_status 200 "$status" 'response body access off'
cmp --silent "$RESULTS_DIR/expected-large" "$RESULTS_DIR/response" \
    || fail 'response with body access off was not byte-exact'

# Header-only empty response.
status=$(request "$RESULTS_DIR/response" --dump-header "$RESULTS_DIR/headers" \
    "http://127.0.0.1:$FORWARD_PORT/empty")
check_status 200 "$status" 'header-only empty EOS'
[[ ! -s $RESULTS_DIR/response ]] || fail 'empty response acquired a body'

# Chunked request with trailer EOS. The trailer itself is not asserted to
# reach the backend: Istio's generated gateway-to-backend cluster does not
# enable HTTP/1.1 upstream trailers (see README.md).
request_with_trailer() {
    local output=$1
    local headers=$2
    local body=$3
    local url=$4
    python3 - "$output" "$headers" "$body" "$url" <<'PY'
import http.client
import sys
from urllib.parse import urlsplit

output_path, headers_path, body_path, raw_url = sys.argv[1:]
url = urlsplit(raw_url)
target = url.path or "/"
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
    connection.send(b"0\r\nx-client-trailer: passed\r\n\r\n")
    response = connection.getresponse()
    with open(headers_path, "wb") as headers_file:
        headers_file.write(f"HTTP/1.1 {response.status} {response.reason}\r\n".encode("iso-8859-1"))
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

: >"$RESULTS_DIR/empty-request"
status=$(request_with_trailer "$RESULTS_DIR/response" "$RESULTS_DIR/headers" \
    "$RESULTS_DIR/empty-request" "http://127.0.0.1:$FORWARD_PORT/echo")
check_status 200 "$status" 'empty request with trailer EOS'

status=$(request_with_trailer "$RESULTS_DIR/response" "$RESULTS_DIR/headers" \
    "$RESULTS_DIR/deny-body" "http://127.0.0.1:$FORWARD_PORT/phase2-deny")
check_status 403 "$status" 'phase-2 denial on trailer-terminated request'

# ---------------------------------------------------------------------------
# Observability assertions.
# ---------------------------------------------------------------------------

# Envoy buffers file access-log writes; poll until the line is flushed.
require_gateway_log() {
    local expected=$1
    for _attempt in {1..50}; do
        kubectl -n "$NAMESPACE" logs "$GATEWAY_POD" -c istio-proxy >"$RESULTS_DIR/gateway.log" 2>/dev/null || true
        if grep --quiet --fixed-strings "$expected" "$RESULTS_DIR/gateway.log"; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

require_gateway_log \
    'path=/phase1-deny coraza_observability event=coraza_waf_blocked_request rule_id=101 phase=http_request_headers action=deny status=403 reason=denied outcome=denied complete=true' \
    || fail 'access log did not carry the filter-state fields for the denial'
pass 'access log carried the coraza filter-state fields for a denial'

require_gateway_log 'test blocked' \
    || fail 'RelevantOnly audit output did not reach the proxy log'
pass 'RelevantOnly audit output reached the proxy log'

# ---------------------------------------------------------------------------
# QTE: the 16 MiB listener buffer limit exists so the phase-4 header-deny case
# can hold the 1 MiB+1 body while response headers are stopped. Record the
# failure mode it prevents (and its restoration) instead of just claiming it;
# written to buffer-limit-experiment.txt in the results directory. Streams
# aborted by this experiment may produce additional state/log records; those
# do not affect the earlier lifecycle assertions.
# ---------------------------------------------------------------------------

render_envoyfilter envoy-coraza-test "http://coraza-wasm-fetch/envoy_coraza.wasm" \
    "$WASM_SHA256" "$RESULTS_DIR/envoyfilter-full.yaml"
python3 - "$RESULTS_DIR/envoyfilter-full.yaml" "$RESULTS_DIR/envoyfilter-no-listener.yaml" <<'PY'
import sys

text = open(sys.argv[1]).read()
start = text.index("    # Listener: raise the per-connection buffer limit")
end = text.index("    # Cluster used by Envoy")
open(sys.argv[2], "w").write(text[:start] + text[end:])
PY
kubectl apply -f "$RESULTS_DIR/envoyfilter-no-listener.yaml" >/dev/null 2>&1 \
    || fail 'could not apply the no-listener EnvoyFilter variant'
UNPATCHED_STATUS=""
for _attempt in {1..30}; do
    UNPATCHED_STATUS=$(request "$RESULTS_DIR/body" "http://127.0.0.1:$FORWARD_PORT/large-header-deny" || true)
    [[ $UNPATCHED_STATUS == 500 ]] && break
    sleep 2
done
[[ $UNPATCHED_STATUS == 500 ]] \
    || fail "removing the listener buffer patch did not reproduce the expected 500 (got '$UNPATCHED_STATUS')"
require_gateway_log 'details=response_payload_too_large' \
    || fail 'access log did not record response_payload_too_large for the unpatched run'
pass 'without the 16 MiB listener buffer, the headers-stopped response aborts with 500 response_payload_too_large'

# Freely streamed responses are unaffected by the buffer limit: assert the
# 1 MiB+1 MIME-excluded body still passes byte-exact in the unpatched window.
status=$(request "$RESULTS_DIR/unpatched-stream" "http://127.0.0.1:$FORWARD_PORT/large-uninspectable")
check_status 200 "$status" 'freely streamed response during the unpatched window'
cmp --silent "$RESULTS_DIR/expected-large" "$RESULTS_DIR/unpatched-stream" \
    || fail 'freely streamed response was not byte-exact during the unpatched window'
pass 'freely streamed response was byte-exact during the unpatched window'

kubectl apply -f "$RESULTS_DIR/envoyfilter-full.yaml" >/dev/null 2>&1 \
    || fail 'could not restore the full EnvoyFilter'
RESTORED_STATUS=""
for _attempt in {1..30}; do
    RESTORED_STATUS=$(request "$RESULTS_DIR/body" "http://127.0.0.1:$FORWARD_PORT/large-header-deny" || true)
    [[ $RESTORED_STATUS == 502 ]] && break
    sleep 2
done
[[ $RESTORED_STATUS == 502 ]] \
    || fail "restoring the listener buffer patch did not bring back 502 (got $RESTORED_STATUS)"
pass 'with the 16 MiB listener buffer restored, the phase-4 header denial returns 502'
printf 'large-header-deny without listener patch: HTTP %s (details=response_payload_too_large)\nlarge-header-deny with listener patch: HTTP %s\nfreely streamed large-uninspectable without listener patch: HTTP 200, byte-exact\n' \
    "$UNPATCHED_STATUS" "$RESTORED_STATUS" | tee "$RESULTS_DIR/buffer-limit-experiment.txt"

# ---------------------------------------------------------------------------
# Oracle smoke: the upstream Go artifact through the same EnvoyFilter path.
# Reference-only: configure (proven by the identity-verified active chain
# serving traffic), one deny, one pass. The switch restarts the gateway so
# the fresh proxy loads the oracle artifact from scratch — Envoy otherwise
# keeps answering from the previously loaded Rust VM, which made the old
# presence-only check meaningless. Failures are recorded (ORACLE-FAIL lines,
# tee'd into the assertions file) but never abort the harness.
# ---------------------------------------------------------------------------

# Oracle assertions must use this helper, not pass/check_status: the summary
# counts gating assertions as the PASS lines that are NOT prefixed
# "PASS: oracle".
oracle_pass() {
    printf 'PASS: oracle %s\n' "$1" | tee -a "$RESULTS_DIR/assertions.txt"
}

oracle_fail() {
    printf 'ORACLE-FAIL: %s\n' "$1" | tee -a "$RESULTS_DIR/assertions.txt"
}

ORACLE_MODE=skipped
if [[ $ORACLE_WASM != none ]]; then
    ORACLE_MODE=ran
    if cp "$ORACLE_WASM" "$ARTIFACT_DIR/oracle_main.wasm" 2>/dev/null; then
        ORACLE_SHA256=$(sha256sum "$ARTIFACT_DIR/oracle_main.wasm" | cut -d' ' -f1)
        printf 'oracle_artifact=%s\noracle_sha256=%s\n' "$ORACLE_WASM" "$ORACLE_SHA256" \
            | tee -a "$RESULTS_DIR/artifact.txt"
        kubectl -n "$NAMESPACE" delete envoyfilter envoy-coraza-test >/dev/null 2>&1 || true
        wait_for_filter_absent envoy-coraza-test \
            || oracle_fail 'previous Rust filter still rendered in the gateway config'
        render_envoyfilter envoy-coraza-oracle "http://coraza-wasm-fetch/oracle_main.wasm" \
            "$ORACLE_SHA256" "$RESULTS_DIR/envoyfilter-oracle.yaml"
        if kubectl apply -f "$RESULTS_DIR/envoyfilter-oracle.yaml" >/dev/null 2>&1; then
            # All checks must pass before any oracle PASS line is printed: a
            # corrupt artifact can render into the active chain (its digest is
            # pinned faithfully) and still fail at runtime, and that must not
            # be reported as a partial success. ORACLE_CHECKS_OK is set before
            # the first check so every failure folds into the all-or-nothing
            # emission.
            ORACLE_CHECKS_OK=true
            # Fresh proxy: the restarted gateway must load and serve the
            # oracle artifact, not the previously loaded Rust VM. A failed
            # restart records ORACLE-FAIL and skips the remaining checks; the
            # oracle never aborts the run.
            if restart_gateway; then
                ORACLE_IDENTITY_OK=false
                for _attempt in {1..60}; do
                    if verify_wasm_identity envoy-coraza-oracle "$ORACLE_SHA256" \
                        "$RESULTS_DIR/config_dump_oracle.json"; then
                        ORACLE_IDENTITY_OK=true
                        break
                    fi
                    sleep 2
                done
                if [[ $ORACLE_IDENTITY_OK != true ]]; then
                    oracle_fail 'active filter chain does not serve the oracle artifact (identity check failed)'
                    ORACLE_CHECKS_OK=false
                fi
                # The Rust plugin's interruption state signature must not appear
                # in the fresh proxy's access log while the oracle handles traffic.
                RUST_DENYLOG_BEFORE=$(rust_deny_log_count)
                # Bounded retries: the freshly loaded plugin can still be
                # warming when the chain is already active (fail-closed 503s).
                ORACLE_DENY_STATUS=""
                for _attempt in {1..15}; do
                    ORACLE_DENY_STATUS=$(request "$RESULTS_DIR/body" "http://127.0.0.1:$FORWARD_PORT/phase1-deny" || true)
                    [[ $ORACLE_DENY_STATUS == 403 ]] && break
                    sleep 2
                done
                [[ $ORACLE_DENY_STATUS == 403 ]] || {
                    oracle_fail "phase-1 denial returned '${ORACLE_DENY_STATUS:-no response}', expected 403"
                    ORACLE_CHECKS_OK=false
                }
                ORACLE_PASS_STATUS=""
                for _attempt in {1..15}; do
                    ORACLE_PASS_STATUS=$(request "$RESULTS_DIR/body" "http://127.0.0.1:$FORWARD_PORT/echo" || true)
                    [[ $ORACLE_PASS_STATUS == 200 ]] && break
                    sleep 2
                done
                [[ $ORACLE_PASS_STATUS == 200 ]] || {
                    oracle_fail "benign request returned '${ORACLE_PASS_STATUS:-no response}', expected 200"
                    ORACLE_CHECKS_OK=false
                }
                # Let Envoy flush the access log before re-reading evidence.
                sleep 3
                RUST_DENYLOG_AFTER=$(rust_deny_log_count)
                if [[ $RUST_DENYLOG_BEFORE != "$RUST_DENYLOG_AFTER" ]]; then
                    oracle_fail "Rust filter-state denial signature appeared during oracle requests ($RUST_DENYLOG_BEFORE->$RUST_DENYLOG_AFTER)"
                    ORACLE_CHECKS_OK=false
                fi
            else
                oracle_fail 'gateway restart for the oracle switch failed; the remaining oracle checks were skipped'
                ORACLE_CHECKS_OK=false
            fi
            if [[ $ORACLE_CHECKS_OK == true ]]; then
                oracle_pass 'artifact identity verified: exactly one wasm filter in the active chain of the restarted pod, sha256 matches'
                oracle_pass 'phase-1 request denial returned 403'
                oracle_pass 'benign request returned 200'
                oracle_pass 'Rust interruption filter-state was absent from the fresh proxy logs'
            fi
        else
            oracle_fail 'oracle EnvoyFilter apply failed'
        fi
    else
        oracle_fail "could not copy the oracle artifact from $ORACLE_WASM"
    fi
else
    printf 'oracle smoke skipped (ORACLE_WASM=none)\n'
fi

# KEEP=1 debugging must inspect the candidate, not the oracle: restore the
# Rust filter and restart the gateway so the kept pod serves it alone.
if (( KEEP == 1 )) && [[ $ORACLE_MODE == ran ]]; then
    kubectl -n "$NAMESPACE" delete envoyfilter envoy-coraza-oracle >/dev/null 2>&1 || true
    kubectl apply -f "$RESULTS_DIR/envoyfilter.yaml" >/dev/null 2>&1 \
        || fail 'could not restore the Rust EnvoyFilter for KEEP=1'
    # Fail-fast here is correct: a KEEP=1 cluster left serving the oracle
    # (or nothing) would defeat the debug hold.
    restart_gateway \
        || fail 'gateway restart for the KEEP=1 restore failed'
    for _attempt in {1..60}; do
        verify_wasm_identity envoy-coraza-test "$WASM_SHA256" "$RESULTS_DIR/config_dump.json" && break
        sleep 2
    done
    verify_wasm_identity envoy-coraza-test "$WASM_SHA256" "$RESULTS_DIR/config_dump.json" \
        || fail 'restored Rust filter did not become the active chain for KEEP=1'
    printf 'KEEP=1: Rust filter restored and active on gateway pod %s\n' "$GATEWAY_POD"
fi

kill "$forward_pid" 2>/dev/null || true
kill "$http_server_pid" 2>/dev/null || true

# The oracle smoke records but does not gate: only the gating count is pinned.
GATING_ASSERTIONS=$(grep -c '^PASS' "$RESULTS_DIR/assertions.txt" || true)
ORACLE_ASSERTIONS=$(grep -c '^PASS: oracle' "$RESULTS_DIR/assertions.txt" || true)
ORACLE_FAILURES=$(grep -c '^ORACLE-FAIL' "$RESULTS_DIR/assertions.txt" || true)
GATING_ASSERTIONS=$((GATING_ASSERTIONS - ORACLE_ASSERTIONS))
if (( GATING_ASSERTIONS != EXPECTED_GATING_ASSERTIONS )); then
    fail "expected $EXPECTED_GATING_ASSERTIONS gating assertions, recorded $GATING_ASSERTIONS; an assertion was added or lost, update EXPECTED_GATING_ASSERTIONS and the documented results"
fi
if (( ORACLE_ASSERTIONS > 4 )); then
    fail "oracle smoke emitted $ORACLE_ASSERTIONS PASS lines, expected at most 4"
fi

printf '\n== summary (istio %s, envoy %s, wasm sha256 %s)\n' \
    "$ISTIO_VERSION" "$ENVOY_VERSION" "$WASM_SHA256"
if [[ $ORACLE_MODE == ran ]]; then
    printf '%d gating assertions passed; oracle smoke: %d passed, %d failed; details in %s\n' \
        "$GATING_ASSERTIONS" "$ORACLE_ASSERTIONS" "$ORACLE_FAILURES" "$RESULTS_DIR"
else
    printf '%d gating assertions passed; oracle smoke skipped (ORACLE_WASM=none); details in %s\n' \
        "$GATING_ASSERTIONS" "$RESULTS_DIR"
fi
