# Third-party notices

The HTML entity table and decoder in `src/transformations/html_entities.rs` are
derived from Go's standard library `html` package. The XML decoder and tables
in `src/body_processors/xml/` are derived from Go's `encoding/xml` package. The
source files retain their Go Authors copyright and BSD-3-Clause SPDX identifier.
The license terms are in
[`LICENSES/Go-Authors-BSD-3-Clause.txt`](LICENSES/Go-Authors-BSD-3-Clause.txt).
Copyright 2009 The Go Authors. All rights reserved.

`coraza.conf-recommended` is a verbatim copy of the file of the same name from
Go Coraza v3.8.1 (`github.com/corazawaf/coraza/v3`), Copyright 2022 Juan Pablo
Tosso and the OWASP Coraza contributors, licensed under the Apache License,
Version 2.0, the license of this crate. `envoy-coraza/recommended.conf` is the
same file without its `SecRequestBodyInMemoryLimit` and `SecDataDir` directives.
