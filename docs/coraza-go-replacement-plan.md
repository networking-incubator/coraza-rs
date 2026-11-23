# Coraza Go replacement readiness plan

This document is the current source of truth for what remains before the
`coraza` crate can replace a Go Coraza deployment. It is a plan, not a claim.

It supersedes the remaining items of the earlier internal assessment (findings
F01-F13, work packages WP1-WP9). That assessment was written before the
acceptance suites existed; it is still useful for the reasoning behind
individual differences, but its status list is stale.

Evidence in this document is as of `main` at `2bf7fd5` (2026-10-26), after the
acceptance batch. Every number below can be reproduced with the commands in
[Verification](#verification) unless the row says otherwise.

## Answer this plan is driving to

"Is a `coraza-rs` build a drop-in replacement for a Go Coraza installation?"

Today: **no**. The engine semantics are at Go's default-build acceptance level,
but the deployment surface, one detector default, and the operational and
stability contracts are not. This document lists what "yes" requires.

## Definition of done

The answer becomes yes when all of the following hold. Each is a requirement,
not a suggestion; the work packages below map to them.

- **R1 - Engine semantics.** No known behavior difference that changes a rule
  outcome in the default Go build, or every remaining difference is deliberate,
  documented, and covered by a reviewed `coraza/conformance/difference-ledger.md`
  row with a fixture.
- **R2 - Detector completeness.** No input silently bypasses `@detectSQLi` or
  `@detectXSS` because of an internal size bound. Over-bound input has an
  explicit, documented result, and the default policy is a conscious decision.
- **R3 - Deployment surface.** At least one production-shaped integration with
  a documented contract: connection metadata, request and response ordering,
  chunked bodies, interruptions before forwarding, reload and shutdown.
- **R4 - Audit operations.** A documented delivery contract and an injectable
  sink; bounded behavior for a stalled sink; retention and permissions;
  configurable trust roots; failure observability.
- **R5 - Security posture.** Feature-gated host capabilities are documented and
  default off; FIPS 140-3 behavior is either implemented or explicitly
  unsupported with a deployment note; the dependency and audit policy is
  stated.
- **R6 - API stability.** A semver policy, a migration guide, and no breaking
  change without a deprecation cycle. Today the crate is `0.1.0` and the last
  batch changed public types.
- **R7 - Verification.** Go's operator corpus, engine profiles (default and
  multiphase), the CRS suite scored the way Go scores it, the differential
  oracle, fuzzing, fault injection, and performance at CRS scale, all wired
  into CI.
- **R8 - Documentation.** A deployment guide, a parity matrix, and the known
  deviations with their rationale.

## Current evidence

| Area | Evidence | State |
| --- | --- | --- |
| Go operator corpus | 3,836 of 3,836 executed cases pass; 98 skipped (93 operator names Go itself does not implement, 5 whose schema Go does not ship) | Verified in `cargo test` |
| Go engine profiles | 49 of 49 default-build profiles, 120 of 120 stages, 0 mismatches | Verified in `cargo test` |
| OWASP CRS v4.30.0 (raw) | 5,215 of 5,231 passed; 16 failures, each explained in `ftw-runner/testdata/crs/README.md`; none is an engine regression, and 4 are deliberate 505/empty-Host parity trade-offs | `ftw-runner/testdata/crs/run-crs.sh` |
| Detector differential | Pinned libinjection C and Go oracles pass (`make parity-differential`) | CI and local |
| Engineering gates | lint, 8/8 feature clippy, coverage 94.6% lines, fuzz targets for 9 campaigns, audit, MSRV | CI |
| Performance | 6-case Go-vs-Rust workload and detector benches; no CRS-scale end-to-end run | Partial |

## Gap register

Each gap states why it blocks a replacement, not only that it exists.

- **G1 - Detector inputs over 65,536 bytes are a silent miss.**
  `@detectSQLi` and `@detectXSS` return `OperatorOutcome::NotInspected` above
  `libperfusion::MAX_INPUT_LEN`, rules treat that as not matched, and the
  default `DetectorInspectionAction` is `RecordOnly`. Go scans the full value.
  A miss looks exactly like a clean value. **Blocks R2.**
- **G2 - No production connector.** The repository ships an FTW example server.
  The Envoy Proxy-Wasm adapter uses `libperfusion` directly, not the `coraza`
  engine. Go Coraza deployments normally live in Caddy, Traefik, Envoy or nginx
  connectors. **Blocks R3.**
- **G3 - Audit operational gaps.** No injectable sink; connect and write
  deadlines are opt-in and unbounded by default (Go parity); HTTPS trusts the
  compiled-in webpki roots only, so a private CA fails; retention and rotation
  are left to the operator; a stalled file or syslog sink blocks the caller.
  **Blocks R4.**
- **G4 - No FIPS profile.** `md5`/`sha1` cannot report a FIPS-mode error and
  retain the value as Go does under its FIPS mode. **Blocks R5 where required.**
- **G5 - No multiphase evaluation.** Go's opt-in
  `coraza.rule.multiphase_evaluation` build tag evaluates a rule as each of its
  variables becomes ready; the 11 tag-only profiles are not replayed, and Go's
  CI runs CRS in that mode as well. Off in the default Go build. **Blocks R7,
  and CRS hardening parity.**
- **G6 - CRS is scored raw, not as Go scores it.** `ftw-runner` has no override
  support, so the 16 raw failures cannot be compared directly against Go's CI
  result. **Blocks R7.**
- **G7 - Documented fail-closed deviations.** HTTP header obs-fold is rejected
  before the WAF; the example connector accepts 128 headers / 64 KiB where Go
  accepts 500 / 1 MiB; a multipart body ending exactly after a delimiter reports
  a body error; multi-colon URI hosts follow the Go 1.25 semantics recorded at
  the base commit; `@rbl` has no TXT message, `TX.httpbl_msg` or capture;
  `@validateSchema` compiles per operator instead of Go's content-keyed
  memoizer. Each must be fixed or explicitly accepted. **Blocks R1/R8 for the
  ones that change outcomes; the rest are documentation.**
- **G8 - Pre-1.0 API.** `coraza` is `0.1.0`; the last batch changed
  `UploadKeepFiles`, `process_logging`/`finish`, `Waf::activate` and the
  operator enum. **Blocks R6.**
- **G9 - No lifecycle or observability contract.** No reload pinning, no
  metrics, no supported shutdown story. **Blocks R3/R6.**
- **G10 - Performance at CRS scale is unmeasured.** Six cases and detector
  benches do not predict a CRS deployment. **Blocks R7.**
- **G11 - The libperfusion security plan is untouched (42 tasks).** It includes
  the explicit `InputTooLarge` API that closes G1, the verified URL-scheme
  bypasses, the HTML URL-value context, and the opt-in SQL policy. **Blocks
  R2/R5.**
- **G12 - Verification infrastructure gaps.** The pinned libinjection checkout
  is not documented as a local prerequisite; long fuzz campaigns and
  audit/filesystem fault injection are not run; profile provenance is a manual
  check because the exporter needs a newer Go than the harness job.
  **Blocks R7.**

## Work packages

Sizes are relative: S is under a day, M is a few days, L is one to two weeks.
The order inside each phase is the recommended merge order.

### Phase A - required before calling it a replacement

- **RP1 - Detector completeness (closes G1, G11 in part).** Size M.
  Add `libperfusion` checked entry points that return an explicit
  `InputTooLarge { actual, limit }` instead of a miss, keep the bounded default
  wrappers for compatibility, expose a checked full-value path, and make the
  operator outcome and the connector policy explicit. Decide and document the
  default `DetectorInspectionAction`.
  Exit: an over-bound value never reports a clean miss; a rule can fail closed;
  fixtures cover limit-1/exact/limit+1; the policy default is documented.
- **RP2 - Deployment surface (closes G2, G9).** Size L.
  Pick one production connector (a standalone HTTP proxy or an Envoy/ext_proc
  integration are the natural candidates), implement the documented lifecycle:
  connection metadata, URI and header ingestion, chunked body ingestion,
  interruption before forwarding, response phases, reload with pinned rules,
  graceful shutdown, and basic metrics.
  Exit: a live integration test suite drives requests through the connector and
  asserts rule outcomes; a deployment guide exists; reload and shutdown are
  tested.
- **RP3 - Audit operations (closes G3).** Size M.
  Add an injectable sink interface, a bounded-stall policy for file and syslog
  writes (deadline or documented synchronous contract), a host-trust-store
  option for HTTPS, and retention/rotation guidance. Add fault-injection tests
  for a stalled sink and an unwritable target.
  Exit: no audit failure is silent; a stalled sink cannot block indefinitely
  without a documented choice; trust roots are configurable; the contract is
  documented.
- **RP4 - CRS scoring and overrides (closes G6).** Size S.
  Teach `ftw-runner` to load the engine's override file, and wire the CRS run
  into CI with expected counts.
  Exit: CI reports the CRS result as Go scores it, with a documented baseline.
- **RP5 - Deviation review (closes G7).** Size M.
  Walk every row of the deviation list: fix the outcome-changing ones (obs-fold,
  multipart trailing delimiter, and the multi-colon host choice), and record the
  rest as accepted with a rationale and a ledger row.
  Exit: every documented difference is either gone or explicitly accepted; no
  difference changes a rule outcome without a ledger row.

### Phase B - production-grade requirements

- **RP6 - API stabilization (closes G8).** Size M.
  Define the semver and deprecation policy, publish the migration guide,
  document MSRV, and prepare a 1.0 checklist (feature flags, error types,
  configuration surface).
  Exit: no breaking change without a deprecation cycle; the migration guide
  covers every release.
- **RP7 - Performance at CRS scale (closes G10).** Size M.
  Run the paired Go-vs-Rust protocol on a representative CRS workload
  (latency, allocations, memory, reload cost), and record medians and ranges.
  Exit: results are published and reproducible; regressions are caught in CI.
- **RP8 - Multiphase evaluation (closes G5), decision-gated.** Size L.
  Add a default-off `multiphase-evaluation` feature mirroring the Go tag:
  per-phase variable readiness, `ARGS`/`ARGS_NAMES` splitting, chain minimum
  phase, deferred non-disruptive actions, and tagged `skip`/`allow` semantics.
  Export and replay the 52-profile tagged set, and run CRS in both modes.
  Exit: tagged profiles pass under the feature; the default build is unchanged.
- **RP9 - FIPS profile (closes G4), decision-gated.** Size S/M.
  Add a feature that makes `md5`/`sha1` report the FIPS-mode error and retain
  the untransformed value, matching Go; document the deployment requirement.
  Exit: the FIPS behavior is testable and documented.

### Phase C - hardening and assurance

- **RP10 - Verification hardening (closes G12).** Size M.
  Document the pinned libinjection checkout and provide a setup command; add
  long fuzz campaigns for the parsers and audit/filesystem fault injection;
  wire the profile provenance check into a CI job with the exporter's Go
  version.
  Exit: every declared target and campaign runs in CI or is documented as a
  release gate; drift is detected automatically.
- **RP11 - Migration and deployment docs (closes R8).** Size S.
  Publish the parity matrix, the migration guide from Go, and the supported
  profiles (feature flags, audit modes, connector).

## Decisions required

These block the corresponding packages; they are not code questions.

1. **Detector policy default** - fail closed on over-bound input, record only,
   or require the connector to choose (RP1).
2. **First connector** - standalone proxy, Envoy ext_proc, or another host
   (RP2).
3. **Audit default** - keep Go's unbounded writes or bound them by default
   (RP3).
4. **FIPS** - required for the target deployments or explicitly unsupported
   (RP9).
5. **Multiphase** - in scope for the replacement claim, or documented as a
   Go-only option (RP8).
6. **`@rbl` TXT** - take a DNS dependency for message and capture parity, or
   keep the documented A/AAAA limitation (RP5).
7. **Trust roots** - webpki only, or an optional host store (RP3).
8. **CRS scoring** - apply Go's overrides in CI, or publish the raw result with
   the per-case explanation (RP4).

## Known deviations that may remain

These do not block a replacement if they are documented and reviewed, because
Go itself does not promise them or they are fail-closed:

- `exec`, `initcol` and `expirevar` remain no-ops; Go's implementations are also
  empty or inactive.
- The 16 CRS raw failures, explained per case in the CRS README; none of them
  is an engine regression.
- The multi-colon URI host semantics recorded against the pinned Go 1.25
  behavior.
- `@rbl`'s missing TXT message and capture, if the DNS decision is "no".
- `@validateSchema` compiling per operator, if the memoizer is not needed.
- The example connector's header limits, which are not part of the library.

Anything that changes a rule outcome must be fixed or added to the ledger;
prose alone is not enough.

## Verification

The commands that produce the evidence above:

```sh
make lint
cargo hack clippy -p coraza --each-feature --all-targets -- -D warnings
make test
make coverage-check
cargo xtask conformance-check
cargo test -p coraza --all-features
make go-harness-check
make parity-differential          # needs the pinned libinjection checkout
make audit
make coraza-example-test
make ftw-smoke
ftw-runner/testdata/crs/run-crs.sh  # needs CRS_DIR and CORAZA_REF
cargo xtask go-fixtures-check --require-go
cargo xtask go-fixtures-check --provenance
```

`make parity-differential` requires a libinjection checkout at the revision
pinned in `libperfusion/tests/parity/manifest.json`; the command and the
revision are documented in `docs/ci.md`.

## Tracking

Update this document when a work package lands: record the commit, the
verification command, and the remaining gap. Do not mark a requirement done
without evidence that runs in CI. When every requirement is green, replace the
answer at the top with "yes" and state the supported deployment profiles.
