# Fuzzing

The isolated `fuzz/` package has three libFuzzer targets:

- `raw_bytes` exercises full-input detection, SQL visitors, and HTML
  token contexts with arbitrary bytes.
- `sql_grammar` generates SQL keywords, quoting, comments, operators, and
  encoded fragments.
- `html_grammar` generates tags, attributes, URLs, comments, CDATA, and
  entities.
- `coraza_variable_list` exercises the SecLang variable-list parser with
  UTF-8 text derived from arbitrary bytes; invalid sequences are replaced by
  U+FFFD before parsing.

The libperfusion detector targets check parser progress and token/span bounds.
The Coraza target exercises SecLang variable-list parsing with arbitrary text.
Fuzz dependencies stay separate from the published library dependencies.

## Run a campaign

Install nightly Rust, `cargo-fuzz`, and the libFuzzer build prerequisites.
From `libperfusion/`, run:

```sh
cargo +nightly fuzz run raw_bytes -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=262144
cargo +nightly fuzz run sql_grammar -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=4096
cargo +nightly fuzz run html_grammar -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=4096
cargo +nightly fuzz run coraza_variable_list -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=4096
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
