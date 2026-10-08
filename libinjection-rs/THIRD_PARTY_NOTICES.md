# Third-party notices

The crate contains project-authored material under Apache-2.0 and migrated
libinjection material under BSD-3-Clause. The package SPDX expression is
`Apache-2.0 AND BSD-3-Clause`. The Apache-2.0 text is included in
[`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt).

The legacy SQL injection and XSS engines and their static lookup data in this
crate are translations or derivatives of Coraza's `libinjection-go` v0.3.3 at
commit [`f6c336efc0ddac2597fd27d3b1b7db9c87613e8d`](https://github.com/corazawaf/libinjection-go/tree/f6c336efc0ddac2597fd27d3b1b7db9c87613e8d).
The upstream license is reproduced in
[`LICENSES/libinjection-go-BSD-3-Clause.txt`](LICENSES/libinjection-go-BSD-3-Clause.txt).

The translated engine descends from Nick Galbreath's original libinjection C
implementation. Its BSD-3-Clause notice is preserved in
[`LICENSES/libinjection-C-BSD-3-Clause.txt`](LICENSES/libinjection-C-BSD-3-Clause.txt),
from the upstream [`COPYING`](https://github.com/client9/libinjection/blob/master/COPYING).

The migrated corpus fixtures came from that same revision's `tests/` directory.
Their names and SHA-256 hashes are recorded in
[`tests/parity/manifest.json`](tests/parity/manifest.json). The pinned SQL lookup
table and XSS classifications are checked against the Go source by
[`tools/parity/check_manifest.py`](tools/parity/check_manifest.py).

The Go oracle is development-only. It is built from the pinned source into a
temporary directory by [`tools/parity/go-oracle`](tools/parity/go-oracle); Go is
not a Rust runtime or crate dependency.
