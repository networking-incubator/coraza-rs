# coraza-rs

Rust workspace for Coraza's libinjection-compatible SQLi and XSS detector.
The workspace contains one detector implementation, the `libperfusion` crate,
plus `xtask` for corpus, provenance, and table maintenance.

- [Library API and development guide](libperfusion/README.md)
- [CI checks](docs/ci.md)
- [Fuzzing guide](libperfusion/docs/FUZZING.md)
- [Historical performance comparison](docs/performance.md)

Run `make lint` and `make test` from the repository root before submitting
changes.
