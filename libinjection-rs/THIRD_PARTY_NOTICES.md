# Third-party notices

The detector source is derived from libinjection and distributed under
BSD-3-Clause; the complete notice is in [`LICENSE`](LICENSE). Repository
tests and maintenance tools also contain project-authored Apache-2.0 material,
whose text is included in [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt).

The SQL injection and XSS implementation and its static lookup data are
translations or derivatives of Coraza's
[`libinjection-go`](https://github.com/corazawaf/libinjection-go). The corpus
source module version and checksum are recorded in
[`tests/parity/manifest.json`](tests/parity/manifest.json).
The upstream license is reproduced in
[the Go license file](LICENSES/libinjection-go-BSD-3-Clause.txt).

The translated engine descends from Nick Galbreath's original libinjection C
implementation. Its BSD-3-Clause notice is preserved in the
[C license file](LICENSES/libinjection-C-BSD-3-Clause.txt), from the upstream
[`COPYING`](https://github.com/client9/libinjection/blob/master/COPYING).

Fixture hashes and SQL oracle input hashes are checked by
`cargo xtask corpus-check`. Refresh them from the version pinned in
`xtask/tools/go.mod` with `cargo xtask corpus-refresh`.

The pinned Go module supplies the development oracle and corpus provenance; it
adds no runtime or Rust crate dependency.
