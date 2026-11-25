# Go Coraza multipart processor results

`cases.json` holds multipart bodies and what Go Coraza's multipart body processor
left in the transaction for each, twice. `go` is the processor on the body: the
collections it fills (`ARGS_POST`, `FILES`, `FILES_NAMES`, `FILES_SIZES`,
`MULTIPART_PART_HEADERS`, `MULTIPART_NAME`, `MULTIPART_FILENAME`), the contents of the
temporary uploads, `FILES_COMBINED_SIZE`, `MULTIPART_STRICT_ERROR` and the error the
processor returned, and `stopped`: whether it stopped at a part, that is returned the
error of reading its body, or read no further part after one that ended inside its
body while a part follows. `raw` is the processor on the same body with every
`Content-Transfer-Encoding` header renamed, so that no part is decoded: the parts as
they were sent. Every body uses the boundary `b`. A case with `"cut": true` is a body
the request body limit cut, which carries `INBOUND_DATA_ERROR`; it has no closing
delimiter.

`coraza/tests/go_multipart.rs` replays each body through this crate and compares.
Keys and values are hex, and rows are sorted, because Go's maps have no order.

This engine publishes a part Go decodes from quoted-printable twice, decoded as Go
publishes it and as it was sent, and keeps the encoding header Go removes, so the
replay does not ask for Go's collections to be this engine's. It asks for what
`../../conformance/difference-ledger.md` ("Multipart quoted-printable parts") says
differs, and nothing more: `ARGS_POST`, `FILES_SIZES` and the uploads hold every row of
`go` and every row of `raw` and no other row, in no more rows than the two have
together; `MULTIPART_PART_HEADERS` are `raw`'s with the header named again;
`FILES_COMBINED_SIZE` is `raw`'s; the other collections, the error and the strict
error are Go's, the strict error also where `raw` has it (a repeated encoding header).
Where `go.stopped`, this engine publishes more than Go (a part as far as it was decoded,
and the parts after it), and the replay asks for Go's rows and `raw`'s only.

## Origin

The results are Go's, from `github.com/corazawaf/coraza/v3`
`v3.8.2-0.20261114225743-1cfa4f955a19`, the version `../go_profiles/exporter/go.mod`
pins, run on Go 1.27.4. The bodies are:

- hand-written cases for quoted-printable parts (field and file parts, soft line
  breaks, lowercase hex, invalid escapes, control bytes, lines around 4096 bytes,
  header spellings, repeated headers, `filename*`, bodies cut by the limit, one name
  or file name twice, a payload after a failing part) and for `FILES_COMBINED_SIZE`
  (fields, files, empty parts, partial bodies), and
- a sample of generated bodies: random quoted-printable text, escapes and line
  ends, one to four parts each, some with a file name.

See "Multipart quoted-printable parts" in `../../conformance/difference-ledger.md`.

## Regenerating

`regenerate/main.go` runs Go's processor on the `body` of every case and rewrites
the `go` and `raw` parts of `cases.json`; the bodies are the input and stay as they
are. To add a case, append `{"name": ..., "cut": false, "body": "<hex>"}` and run it. It
needs the pinned module in the Go module cache and Go 1.27.3 or newer:

```sh
cd coraza/tests/go_multipart/regenerate
GOWORK=off GOTOOLCHAIN=local go run . ../cases.json "$SCRATCH"
```

`$SCRATCH` is a directory the processor writes the temporary uploads under. The
program's module path is below Go Coraza's `internal/` directory because that is the
only place from which Go allows importing the processor and the transaction
variables it fills.

`regenerate/go.mod` requires the Go Coraza version `../go_profiles/exporter/go.mod`
pins, and `cargo xtask go-fixtures-check` (part of `make test`) fails when the two
differ: bump both, with the exporter's refresh steps in `docs/ci.md`, and run the
command above.

## Attribution

Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors, licensed under the
Apache License 2.0. The expected values are what that project's processor produces.
