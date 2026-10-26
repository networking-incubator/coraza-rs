# Go Coraza operator corpus

These 29 JSON files are the operator test corpus of Go Coraza v3.8.1, copied
verbatim from
`internal/operators/testdata` in
`github.com/corazawaf/coraza/v3@v3.8.1`.

They are unmodified: every file is byte-identical to the upstream copy. They are
hand-written test data, not generated output. To refresh them for a new Go
Coraza release, bump `github.com/corazawaf/coraza/v3` in
`../go_profiles/exporter/go.mod`, run `cargo xtask go-fixtures-refresh`, and
review the diff, including the `FIXTURE_FILES` and `FIXTURE_CASES` constants in
`../go_operators.rs`. `cargo xtask go-fixtures-check` reports drift and
validates the vendored file and case counts against the `OPERATOR_*`
constants; add `--require-go` to fail instead of skipping when Go or the pinned
module is unavailable.

`op/` holds the two data files the corpus references (`pmFromFile-01.dat` and
`netranges.dat`), also copied verbatim from `internal/operators/testdata/op`.
Go's harness serves them from `os.DirFS("testdata")` with `Path: ["op"]`; the
replay sets `OperatorContext::base_dir` to this `op/` directory for the same
reason.

Each file holds an array of cases with the shape Go's `operators.Test` decodes:

```json
{ "name": "eq", "param": "0", "input": "", "type": "op", "ret": 1 }
```

`ret` is `1` when the case expects a match and `0` when it expects no match.
`coraza/tests/go_operators.rs` replays every `type == "op"` case through
`OperatorEnum` as an acceptance test. Of the 3934 cases it executes 3836 and
skips 98, counted by reason with the total pinned:

- 93 name operators this crate does not implement: `containsWord` (15),
  `verifyCC` (69), `verifycpf` (2), `verifyssn` (4), `verifysvnr` (3).
- 5 are `@validateSchema` cases whose argument is `testdata/schema.json`;
  Go's testdata ships no such file, so upstream cannot run them either.

`@ipMatch 10.0.0.0/100` runs: like Go's `newIPMatch`, the factory drops an
entry `net.ParseCIDR` rejects and an argument with no valid entry matches
nothing. `ipMatch` and `ipMatchFromFile` do not fail on unparsable entries.

## Engine profiles

Go's other acceptance corpus, the engine test profiles registered through
`profile.RegisterProfile`, is replayed separately by
`coraza/tests/go_profiles_replay.rs`; see
[`../go_profiles/README.md`](../go_profiles/README.md) for the fixture, its
exporter and the current profile inventory.

## Attribution

Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors.

Licensed under the Apache License, Version 2.0. See the repository `LICENSE` for
the complete terms. The corpus originates from the SpiderLabs
`secrules-language-tests` set, as noted in Go Coraza's `operators_test.go`.
