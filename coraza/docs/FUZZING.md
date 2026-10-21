# Coraza fuzzing

The isolated `fuzz/` package contains three targets:

- `coraza_variable_list` exercises SecLang variable-list parsing with UTF-8
  text derived from arbitrary bytes; invalid sequences are replaced by U+FFFD.
- `seclang_operator` exercises explicit, implicit, and negated operator
  expressions. It only constructs `@rx` operators, so fuzz input cannot access
  files or datasets.
- `seclang_rule_compilation` exercises rule and configuration parsing with
  bounded input inside fixed, known directives, without file-loading handlers.

Install nightly Rust, `cargo-fuzz`, and the libFuzzer build prerequisites.
From `coraza/`, run:

```sh
export RUSTUP_TOOLCHAIN=nightly
cargo fuzz run coraza_variable_list -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=4096
```

Run the operator parser target with:

```sh
cargo fuzz run seclang_operator -- -seed=20261007 -max_total_time=60 -timeout=5 -max_len=4096
cargo fuzz run seclang_rule_compilation -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=4096
```

Each target writes its evolving corpus under `fuzz/corpus/<target>/` and crash
artifacts under `fuzz/artifacts/<target>/`.
