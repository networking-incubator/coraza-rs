# Coraza fuzzing

The isolated `fuzz/` package contains the `coraza_variable_list` target. It
exercises SecLang variable-list parsing with UTF-8 text derived from arbitrary
bytes; invalid sequences are replaced by U+FFFD before parsing.

Install nightly Rust, `cargo-fuzz`, and the libFuzzer build prerequisites.
From `coraza/`, run:

```sh
export RUSTUP_TOOLCHAIN=nightly
cargo fuzz run coraza_variable_list -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=4096
```

The target writes its evolving corpus under `fuzz/corpus/coraza_variable_list/`
and crash artifacts under `fuzz/artifacts/coraza_variable_list/`.
