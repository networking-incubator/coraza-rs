# Coraza fuzzing

The isolated `fuzz/` package contains seven targets:

- `coraza_variable_list` exercises SecLang variable-list parsing with UTF-8
  text derived from arbitrary bytes; invalid sequences are replaced by U+FFFD.
- `seclang_operator` exercises explicit, implicit, and negated operator
  expressions. It only constructs `@rx` operators, so fuzz input cannot access
  files or datasets.
- `seclang_rule_compilation` exercises rule and configuration parsing with
  bounded input inside fixed, known directives, without file-loading handlers.
- `coraza_uri_parser` feeds each input as a raw request target to the URI
  parser, its first byte choosing the method and protocol.
- `coraza_json_body` feeds each input as a JSON request body.
- `coraza_multipart_body` feeds each input as a multipart request body.
- `coraza_xml_body` feeds each input as an XML request body, without a memory
  budget and under a small one, and again under `SecRequestBodyLimitAction
  ProcessPartial` with body limits of 16, 64 and 256 bytes, which cut the
  input inside a token. It checks that `REQUEST_XML` holds no more values than
  the default argument limit; that a body no longer than a limit parses exactly
  as with no limit; and that a cut body is not refused where the same bytes
  without a limit fail only with `unexpected EOF`, but for the documented
  refusals (a CDATA section, UTF-8 of text or a value, and a cut reference
  when the text it ends, the reference as written included, holds a forbidden
  character or broken UTF-8). Such a refusal must repeat the message the
  unlimited WAF gives the kept bytes plus one space.

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
cargo fuzz run coraza_xml_body -- \
  -seed=20261007 -max_total_time=60 -timeout=5 -max_len=65536
```

Each target writes its evolving corpus under `fuzz/corpus/<target>/` and crash
artifacts under `fuzz/artifacts/<target>/`.
