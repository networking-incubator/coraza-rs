# Go engine profile fixture

`profiles.json` is a generated, read-only snapshot of the test profiles registered by
Go Coraza's `testing/engine` package. It exists so the Rust replay harness in
`coraza/tests/go_profiles_replay.rs` can run the same scenarios against this crate
without a Go toolchain at test time.

Do not edit `profiles.json` by hand. `data/` is a byte-for-byte copy of the upstream
fixtures that some profiles load through file-backed operators.

## Origin and attribution

- Source: `github.com/corazawaf/coraza/v3`, module version `v3.8.1`,
  commit `9f8521398d1ff023b958fad0b944cac265763866`, package `testing/engine`
  (profiles are registered through `profile.RegisterProfile` from `init` functions;
  upstream has no JSON/YAML loader or exporter).
- The profiles and `testdata/*.dat` fixtures are Copyright 2022 Juan Pablo Tosso and
  the OWASP Coraza contributors, licensed under the Apache License 2.0
  (`SPDX-License-Identifier: Apache-2.0`). See the upstream `LICENSE`.
- The exporter and this fixture keep that attribution and license; the JSON is a
  derived work of those test fixtures, not of this repository's engine.

## Regenerating

`cargo xtask go-fixtures-refresh` re-vendors `data/` and regenerates
`profiles.json` from the module version pinned in `exporter/go.mod`. To bump the
fixture, update that `require` version, run the command, and review the diff,
including `FIXTURE_PROFILES` and `FIXTURE_STAGES` in
`../go_profiles_replay.rs`. `cargo xtask go-fixtures-check` compares the
checked-in data files with the pinned module and verifies the exported profile
inventory; add `--provenance` to re-export the profiles and byte-compare the
document (it needs the exporter's Go 1.27.3 toolchain), and `--require-go` to
fail instead of skipping when the Go toolchain is unavailable.

The exporter is a standalone Go module pinned to the source version (no `replace`
directive), so the JSON can also be regenerated on its own:

```sh
cd coraza/tests/go_profiles/exporter
GOWORK=off GOTOOLCHAIN=local go run . -o ../profiles.json
```

Upstream gates a second set of profiles behind the
`coraza.rule.multiphase_evaluation` build tag. They are not part of this fixture, but
the same exporter emits them:

```sh
cd coraza/tests/go_profiles/exporter
GOWORK=off GOTOOLCHAIN=local go run -tags coraza.rule.multiphase_evaluation . -o /tmp/tagged-profiles.json
```

`source.build_tags` records which set a given file holds (`default` here).

The exporter refuses to emit a stage that uses `input.version`, `input.port`,
`input.stop_magic`, `input.raw_request` or `input.encoded_request`: the Rust
replay would ignore them, so the export panics instead of silently dropping a
Go expectation. `output.no_log_contains` is exported and asserted as the
inverse of `log_contains`.

## What the default build contains

The default build registers 49 profiles (78 tests, 120 stages). With
`coraza.rule.multiphase_evaluation` the Go package registers 52 profiles (81 tests,
123 stages); 8 profiles are `!coraza.rule.multiphase_evaluation` only and 11 are
tag-only, so the union of both builds is 60 profiles (89 tests, 138 stages).

Tag-only profiles, absent from this fixture: `chains_multiphase.yaml`,
`chains_multiphase_2.yaml`, `chains_multiphase_counter.yaml`,
`chains_multiphase_crs.yaml`, `chains_multiphase_crs_920250.yaml`,
`chains_multiphase_crs_931130.yaml`, `chains_multiphase_crs_933120.yaml`,
`multiphase.yaml`, `multiphase_ruleRemoveTargetById.yaml`,
`multiphase_ruleRemoveTargetById_args.yaml`, `multiphase_skipafter.yaml`.

## Shape

```jsonc
{
  "source": { "module", "version", "commit", "build_tags", "exporter" },
  "profiles": [
    {
      "name", "author", "description",
      "rules": "<SecLang text>",
      "tests": [
        {
          "title", "description",
          "stages": [
            {
              "input":  { "uri", "method", "headers", "data", "dest_addr" },
              "output": {
                "headers", "data",
                "triggered_rules", "non_triggered_rules", "log_contains",
                "no_log_contains",
                "interruption": { "rule_id", "action", "status", "data" }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

Empty or absent fields are omitted. `data` is the request body under `input` and the
response body under `output`, flattened the same way the Go runner's `bodyToString`
does. `output.headers` replaces the runner's default `Content-Type: text/html` rather
than adding to it.

## Running the replay

```sh
cargo test -p coraza --test go_profiles_replay -- --nocapture
```

The replay runs by default. It discovers 49 profiles, all compile, and all 120
stages pass; a parser rejection or a stage mismatch fails the test with the
profile, stage and expected/actual values.

## Parser tolerance (resolved)

Two Go profiles needed this parser to match Go's leniency; both have unit tests and now
replay clean.

- `SecRuleUpdateTarget.yaml` — `SecRuleUpdateTargetById 13-15 16 18 "!ARGS:t2"` names
  rule `18`, which the profile never defines. Go's
  `directiveSecRuleUpdateTargetByID` (`internal/seclang/directives.go`) applies a range
  to every rule it finds and returns from the loop at the first single ID, so `18` is
  never resolved; a range that matches nothing is always a no-op. This parser now
  applies the update to the rules that exist and ignores IDs and ranges that name none.
- `multipart_error.yaml` — the last rule's action line opens `msg:'` and never closes
  it (`msg:'Multipart request body failed strict validation.`). Go's `parseActions`
  logs `unclosed quotes in action line` as a warning and lets the value run to the end
  of the line, keeping the opening quote; `seclang/action_parser.rs` now does the same.
  A rule whose action list itself is not double-quoted is still rejected, as in Go's
  `parseActionOperator`.

## Resolved differences

The three default-build profiles that previously differed now pass every stage:

- `disruptive_actions.yaml` stage 7: `redirect` uses Go's status allowlist
  (301/302/303/307), so `status:401` still interrupts with 302.
- `multipart_filename_star.yaml`: a rejected `Content-Disposition` (duplicate
  parameter) yields no filename fields, as Go's `originFileName` does, so 933110
  no longer matches.
- `multipart_process_partial.yaml`: a truncated body follows Go's `ErrUnexpectedEOF`
  path (`INBOUND_DATA_ERROR` suppresses `MULTIPART_STRICT_ERROR`), so the truncated
  arguments are inspected and no interruption is raised.

## Not replayed

The fixture covers the default build: 49 profiles, 78 tests, 120 stages. The 11
profiles registered only with `coraza.rule.multiphase_evaluation` are listed above
and are not replayed.
