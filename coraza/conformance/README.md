# Conformance artifacts

This directory holds the capability manifest, the reviewed difference ledger,
the byte-event case schema and one example case.

## Generated and hand-maintained files

`capability-manifest.json` is generated. Do not edit it by hand. Its
source-derived fields are recomputed from the Rust source on every run:

- group membership and capability names (case-insensitive membership from the
  factories, the directive handler, the body processor list and the
  `VARIABLES` table);
- `reference_revision` from the pinned Go reference;
- `producer` and `evaluator`, the group registry and dispatch symbols for
  implemented capabilities, or the entry's override when one is present.
- `requires_features` from the override's optional `features` list, sorted and
  deduplicated.

`capability-overrides.json` is hand-maintained. It holds the human decisions
keyed by group and primary name: `state`, `go_reference`, `fixtures`,
`differences`, optional `producer` and `evaluator`, and optional `notes`
(review context that is not emitted into the manifest), and optional `features`
(Cargo features required by the capability). Optional `aliases` groups
spellings that share one entry. The top-level `reference` block pins the
profiles and commits; it is copied into the manifest.

`state` describes the capability's semantics; it does not describe whether the
default build includes it. `requires_features` lists the Cargo features a build
must enable, and an empty list means the capability is available in the default
build. The generator checks feature names against `coraza/Cargo.toml` and checks
feature-gated names against the explicit source-gate map in
`xtask/src/conformance.rs`.

For an entry whose state is not `unavailable`, an optional `producer` or
`evaluator` overrides the group default for that field. Each override is
verified against the source the same way the group defaults are; generation
fails if the symbol does not resolve. Unavailable entries must not have
`producer` or `evaluator` overrides, and an explicit `unavailable` override for
a name in a group registry fails generation. The `variables` group is a name
table rather than a runtime registry, so an unavailable variable there is not a
contradiction; the drift test validates that state.

`difference-ledger.md` is hand-maintained. It records reviewed differences
against `libperfusion/tests/parity/mismatch-ledger.md` and any shared-corpus
case with two observed outcomes.

`corpus-schema.json` and `example-case.json` are hand-maintained contracts,
not generated. The schema's `schema_version` and the example's
`schema_version` are both 1; change them together. The check task validates
the example's shape and resolved fixture ranges, but it does not run a JSON
Schema validator.

`fixtures/` contains the binary fixtures referenced by the example and future
cases. A fixture reference may omit `length`; the omitted length resolves to
`file_len - offset`. The referenced range must satisfy `offset <= file_len`
and `offset + length <= file_len`.

## Commands

Regenerate the manifest after a source or override change:

```sh
cargo xtask conformance-refresh
```

Verify that the committed manifest matches a fresh generation and that the
ledger and example are well formed:

```sh
cargo xtask conformance-check
```

Both commands are also available as `make conformance-refresh` and
`make conformance-check`. `make test` runs the check.

Refresh output is deterministic: groups keep a fixed order, entries are
sorted by primary name, keys keep a fixed order, and JSON uses two-space
indentation. Running the refresh twice must produce no diff.

## Adding a capability

1. Add the capability to the Rust source.
2. Run `cargo xtask conformance-refresh`. It writes the manifest.
3. If the name is not covered by an override, the manifest gains an
   `unavailable` entry with `go_reference` set to `review required` and a
   `differences` note, and the refresh exits after writing because the
   subsequent check fails. This keeps the capability visible; it is never
   dropped silently.
4. Add an override for the name with the reviewed `state`, `go_reference`,
   `fixtures`, and `differences`, then refresh again. `cargo xtask
   conformance-check` fails while any entry still has `go_reference` set to
   `review required`, listing the affected group and names, until the override
   classifies the name.

## Adding a difference review

1. Record the reviewed case in the ledger table with a stable case ID and the
   SHA-256 of the exact input bytes.
2. Add the same case ID to the entry's `fixtures` or explain the outcome in
   `differences` in `capability-overrides.json`.
3. Run `cargo xtask conformance-refresh` and `cargo xtask conformance-check`.

The ledger format is five columns: case ID, fixture SHA-256, expected Go
outcome, expected Rust outcome, and reason. The check task enforces the
column shape, a lower-case 64-character hash, and non-empty outcomes and
reason.
