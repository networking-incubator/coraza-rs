# Coraza source import history

This repository contains a separate Rust implementation based on Coraza source
attributed to Juan Pablo Tosso and the OWASP Coraza contributors. The Rust port
was authored by Alex Snaps in `coraza-rs-alex` and integrated here by Coraza
Kubernetes Operator contributors. It is not the upstream Go implementation or
a complete Coraza engine. The source files retain the original Coraza
attribution and Apache-2.0 license notice.

The port preserves source authorship, author dates, commit messages, and
existing signoff trailers. Importing files under `coraza/` rewrites commit
hashes, so signatures on source commits cannot be retained; imported commits
are signed by the committer in this repository.

The repository normally requires every commit to carry a `Signed-off-by`
trailer. The repository owner approved a narrow exception for the following
14 commits from `coraza-rs-alex` snapshot
`77c11c26201ab77b205f4ae861396fa088640269`, which have no source signoff. Keep
their original messages unchanged when importing them; do not add a signoff
that suggests an upstream attestation. None of these commits were included in
the PR 1 core-types slice.

| Source commit | Date | Subject |
| --- | --- | --- |
| `7ad6b75953fb8d7a593c04ec404b722296fb9c0d` | 2026-10-16 | Merge pull request #14 from alexsnaps/body-parsing |
| `cfd472b5f111616ea37c52ae89a46a416d03e1aa` | 2026-10-16 | Merge pull request #13 from alexsnaps/transaction |
| `ad4b4292b5d4c65fdf9e284b0f555d2da78bd454` | 2026-10-16 | Merge pull request #12 from alexsnaps/connector |
| `94b1f5010d4d8983b5c86ba75d1642aa12daf423` | 2026-10-16 | Merge pull request #11 from alexsnaps/rules |
| `6e011a7533f84da3d99875863d53737471ea01d5` | 2026-10-16 | Merge pull request #10 from alexsnaps/body |
| `76df24fd03e24b3a34fca5cd687b25400b2c0275` | 2026-10-16 | Merge pull request #9 from alexsnaps/transaction |
| `0cf74a475941895c85694f7bee40a4abb323b5b1` | 2026-10-16 | Merge pull request #8 from alexsnaps/more-bugs |
| `564da71f0df9a90b297a21bdd16b6ec01b80de3d` | 2026-10-16 | Merge pull request #7 from alexsnaps/phase-evaluation |
| `9503698e7745e87851f0812fd8f4bb5774c75f8f` | 2026-10-15 | Merge pull request #6 from alexsnaps/parser |
| `6625333e9b9ed6e9ffc445a2039430dbb40d3624` | 2026-10-15 | Merge pull request #5 from alexsnaps/bench |
| `93291fdb20095fe8e92d38453a2a80b6aadf6c4f` | 2026-10-15 | Merge pull request #4 from alexsnaps/gaps |
| `bff199f4fe4eb9ca101fd8cd392d7004b90e3ad2` | 2026-10-15 | Merge pull request #2 from alexsnaps/rust-authoring |
| `df918342d38093d1468e139e80f20856b4114c4f` | 2026-03-27 | Merge pull request #1 from alexsnaps/ftw |
| `421266b37039ed4c4f20c2e9571b638706a4370e` | 2026-03-10 | Add formatting and Clippy checks to CI workflow |
