#!/bin/sh
# Reproduce the CRS raw-suite run against the Rust FTW server.
#
# Required:
#   CRS_DIR      CRS checkout at v4.30.0 (e03a4f6)
#   CORAZA_REF   Go Coraza v3.8.1 module directory (the pinned engine)
#
# The runner exits non-zero when the known Apache-oriented expectations fail;
# see README.md in this directory.
set -eu

: "${CRS_DIR:?set CRS_DIR to the CRS checkout at v4.30.0}"
: "${CORAZA_REF:?set CORAZA_REF to the Go Coraza v3.8.1 module directory}"

if [ ! -d "$CORAZA_REF" ] || [ ! -f "$CORAZA_REF/coraza.conf-recommended" ]; then
    printf 'CORAZA_REF is not a Go Coraza v3.8.1 module directory: %s\n' "$CORAZA_REF" >&2
    exit 1
fi
if [ ! -d "$CRS_DIR/rules" ] || [ ! -f "$CRS_DIR/crs-setup.conf.example" ] ||
    [ ! -d "$CRS_DIR/tests/regression/tests" ]; then
    printf 'CRS_DIR is not a CRS v4.30.0 checkout: %s\n' "$CRS_DIR" >&2
    exit 1
fi

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
out=${FTW_CRS_OUT:-"$root/target/ftw-crs"}
conf="$out/crs-test.conf"
manifest="$out/result.json"
failed="$out/failed.txt"

mkdir -p "$out"

# Same composition as Go Coraza's CRS harness: engine defaults, the response
# MIME type it sets, the CRS test settings, then the CRS configuration and
# rules. The test settings (rule 900005) are the block from
# tests/regression/README.md; rule 999999 makes the X-CRS-Test marker request
# run no rules.
{
    printf 'Include %s/coraza.conf-recommended\n\n' "$CORAZA_REF"
    printf 'SecResponseBodyMimeType text/plain\n\n'
    cat <<'SETTINGS'
# Rule 900005 from CRS tests/regression/README.md (test settings)
SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  setvar:tx.blocking_paranoia_level=4,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400,\
  setvar:tx.total_arg_length=64000,\
  setvar:tx.max_num_args=255,\
  setvar:tx.max_file_size=64100,\
  setvar:tx.combined_file_sizes=65535"

# Write the X-CRS-Test header value as a marker and exclude the request from all rules.
SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \
  "id:999999,\
  phase:1,\
  pass,\
  t:none,\
  log,\
  msg:'X-CRS-Test %{MATCHED_VAR}',\
  ctl:ruleRemoveById=1-999999"
SETTINGS
    printf '\nInclude %s/crs-setup.conf.example\n' "$CRS_DIR"
    printf 'Include %s/rules/*.conf\n' "$CRS_DIR"
} >"$conf"

cargo build --release -p coraza --example ftw_server_async --features async-server

cd "$root/ftw-runner"
GOWORK=off GOTOOLCHAIN=local go run . \
    --rules "$conf" \
    --test-dir "$CRS_DIR/tests/regression/tests" \
    --expected-files 327 \
    --expected-tests 5231 \
    --expected-stages 5237 \
    --expected-rules 669 \
    --manifest "$manifest" \
    --failed-out "$failed"
