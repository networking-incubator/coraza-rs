# Fuzzing

The workspace has nine libFuzzer targets across two isolated `fuzz/` packages:
three detector targets in `libperfusion/fuzz` and six Coraza parser and SecLang
targets in `coraza/fuzz`.

`libperfusion/fuzz`:

- `raw_bytes` exercises full-input detection, SQL visitors, and HTML
  token contexts with arbitrary bytes.
- `sql_grammar` generates SQL keywords, quoting, comments, operators, and
  encoded fragments.
- `html_grammar` generates tags, attributes, URLs, comments, CDATA, and
  entities.

`coraza/fuzz`:

- `coraza_variable_list` exercises SecLang variable-list parsing.
- `seclang_operator` exercises operator parsing and evaluation.
- `seclang_rule_compilation` exercises rule and action compilation.
- `coraza_uri_parser` exercises the request-URI parser.
- `coraza_json_body` exercises the JSON request body processor.
- `coraza_multipart_body` exercises the multipart request body processor.

The libperfusion detector targets check parser progress and token/span bounds.
Fuzz dependencies stay separate from the published library dependencies.

## Run a campaign

Install nightly Rust, `cargo-fuzz`, and the libFuzzer build prerequisites. The
CI workflow pins `nightly-2026-10-06`; use the same toolchain so a finding is
reproducible. From `libperfusion/`, run:

```sh
export RUSTUP_TOOLCHAIN=nightly-2026-10-06
cargo fuzz run raw_bytes -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=262144
cargo fuzz run sql_grammar -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=4096
cargo fuzz run html_grammar -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=4096
```

From `coraza/`, run the six Coraza targets with the same flags:

```sh
export RUSTUP_TOOLCHAIN=nightly-2026-10-06
cargo fuzz run coraza_variable_list -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=4096
cargo fuzz run seclang_operator -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=4096
cargo fuzz run seclang_rule_compilation -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=4096
cargo fuzz run coraza_uri_parser -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=65536
cargo fuzz run coraza_json_body -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=65536
cargo fuzz run coraza_multipart_body -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=65536
```

Each target writes its evolving corpus under `fuzz/corpus/<target>/` and crash
artifacts under `fuzz/artifacts/<target>/`.

## Keep a finding as a regression

Promote a crash artifact into the byte fixture manifest. The ID defaults to a
stable digest; expected compatibility verdicts are optional:

```sh
python3 tools/fuzz/promote_crash.py \
  fuzz/artifacts/raw_bytes/CRASH --sqli 1 --xss 0
cargo test -p libperfusion --test fuzz_regressions
```

For a minimized Go/Rust token-stream mismatch, add the bytes to
`tests/oracle_differential.rs` with a stable case ID.
