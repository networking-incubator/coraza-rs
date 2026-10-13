# Repository guidance

Before finishing any code change, run `make lint` from the repository root. Do
this for every change, including documentation, configuration, and tooling. Fix
lint failures caused by the change and rerun the command. If an unrelated
failure remains, report it clearly and do not claim that lint passed.

The pull request CI also runs `make lint`; local lint is still required during
development so failures are caught before the final review.
