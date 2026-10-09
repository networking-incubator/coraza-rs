# Third-party notices

The crate contains project-authored material under Apache-2.0 and migrated
libinjection material under BSD-3-Clause. The package SPDX expression is
`Apache-2.0 AND BSD-3-Clause`. The Apache-2.0 text is included in
[`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt).

The legacy SQL injection and XSS engines and their static lookup data in this
crate are translations or derivatives of Coraza's
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

The Go oracle is used only by the development corpus refresh tool; it adds no
runtime or Rust crate dependency.
