# Vendored libinjection-go corpus

This directory contains the pinned `libinjection-go` test fixtures. The exact
module version, checksum, inventory, and file hashes are recorded in
[`../parity/manifest.json`](../parity/manifest.json). `make test` verifies those
records before running the Rust tests.

To refresh after updating the pinned Go module version in
[`../../../xtask/tools/go.mod`](../../../xtask/tools/go.mod), run:

```sh
cargo xtask corpus-refresh
cargo test -p libinjection
```

The refresh imports fixtures from that module version, regenerates the SQL
oracle and manifest, and updates the Go module checksum. It requires Go 1.24.6
or later. Dependabot monitors this Go module; after it updates the version,
refresh the corpus before merging its pull request. The Rust tests report
parity failures.

Fixture section parsing follows the upstream driver's right-trim behavior. The
complete attribution and license are in
[`../../THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md).
