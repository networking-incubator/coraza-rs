# Vendored libinjection-go corpus

This directory contains the **496** fixtures from the `tests/` directory of
Coraza `libinjection-go` v0.3.3 at commit
[`f6c336efc0ddac2597fd27d3b1b7db9c87613e8d`](https://github.com/corazawaf/libinjection-go/tree/f6c336efc0ddac2597fd27d3b1b7db9c87613e8d):

| Fixture family | Files |
| --- | ---: |
| SQLi | 54 |
| SQL folding | 118 |
| SQL tokens | 249 |
| HTML5 tokens | 68 |
| XSS verdicts | 7 |
| **Total** | **496** |

The counts sum to 496; 499 in the original migration notes was a counting
mistake. Every filename and file hash is frozen in
[`../parity/manifest.json`](../parity/manifest.json). Run
`python3 libinjection-rs/tools/parity/check_manifest.py` from the workspace
root to verify the inventory and bytes. With a checkout of the pinned Go source,
pass
`--go-source /path/to/libinjection-go` to also compare table contents and all
256 SQL dispatch selections.

Fixture section parsing follows the upstream driver's right-trim behavior.
Internal payload lines, including trailing spaces and carriage returns, are
preserved. The complete attribution and license are in
[`../../THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md).
