# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

V ?=
NIGHTLY ?= nightly
CARGO_TARGET_DIR ?= target
ENVOY_WASM_IMAGE ?= coraza-rs/envoy-libperfusion:dev
FTW_MANIFEST ?= target/ftw-smoke-result.json
CORAZA_WORKLOADS ?= benchmarks/coraza/workloads
BENCH_OUT ?= target/coraza-bench
CORAZA_REPETITIONS ?= 3
CORAZA_ITERATIONS ?= 1000
CORAZA_GO_PROFILE ?= auto
CORAZA_CHECKRESOLVE_CMD ?=
CORAZA_PARITY_CMD ?=
CORAZA_RUST_BUILD_CMD ?=
CORAZA_RUST_DRIVER_CMD ?=
CORAZA_GO_BUILD_CMD ?=
CORAZA_GO_DRIVER_CMD ?=

ifneq ($(V),)
  _NOCAPTURE := -- --nocapture
endif

.PHONY: all build build-envoy-wasm build-envoy-wasm-image check clean test conformance-check conformance-refresh parity-manifest-check parity-differential go-harness-check coraza-coordinator-check coraza-parity coraza-bench ftw-runner-check coraza-example-test ftw-smoke lint lint-extra audit coverage-check fmt doc setup-hooks help

all: build fmt lint lint-extra test audit coverage-check

# -------------------------------------------------------------------
# Build
# -------------------------------------------------------------------

build:
	cargo build --workspace

check:
	cargo check --workspace

build-envoy-wasm:
	rustup target add wasm32-wasip1
	CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" cargo build --locked --release --target wasm32-wasip1 -p envoy-libperfusion

build-envoy-wasm-image:
	docker build --file envoy-libperfusion/Dockerfile --tag "$(ENVOY_WASM_IMAGE)" .

clean:
	cargo clean

# -------------------------------------------------------------------
# Test
# -------------------------------------------------------------------

test:
	cargo xtask corpus-check
	cargo xtask tables-check
	cargo xtask conformance-check
	cargo xtask go-fixtures-check
	$(MAKE) parity-manifest-check
	cargo test --workspace $(_NOCAPTURE)
	cargo test -p coraza --features host-operators,validate-schema $(_NOCAPTURE)

conformance-check:
	cargo xtask conformance-check

conformance-refresh:
	cargo xtask conformance-refresh

parity-manifest-check:
	python3 libperfusion/tools/parity/check_manifest.py
	python3 libperfusion/tools/parity/test_manifest_semantics.py

parity-differential:
	cargo test -p libperfusion --test upstream xss_samples -- --ignored
	cargo test -p libperfusion --test oracle_differential pinned_c_oracle_matches_corpus_and_binary_cases -- --ignored --nocapture
	cargo test -p libperfusion --test oracle_differential -- --ignored --nocapture
	cargo test -p libperfusion --test generated_differential -- --ignored --nocapture

go-harness-check:
	@files="$$(cd benchmarks/coraza/go && gofmt -l .)"; \
	if [ -n "$$files" ]; then printf '%s\n' "$$files"; exit 1; fi
	cd benchmarks/coraza/go && GOWORK=off GOTOOLCHAIN=local go vet ./...
	cd benchmarks/coraza/go && GOWORK=off GOTOOLCHAIN=local go test ./...
	cargo xtask go-fixtures-check --require-go
	cd benchmarks/coraza/go && GOWORK=off GOTOOLCHAIN=local go run ./cmd/checkresolve

coraza-coordinator-check:
	@files="$$(cd benchmarks/coraza/coordinator && gofmt -l .)"; \
	if [ -n "$$files" ]; then printf '%s\n' "$$files"; exit 1; fi
	cd benchmarks/coraza/coordinator && GOWORK=off GOTOOLCHAIN=local go vet ./...
	cd benchmarks/coraza/coordinator && GOWORK=off GOTOOLCHAIN=local go test ./...

coraza-parity:
	cd benchmarks/coraza/coordinator && \
		CORAZA_REPO="$(abspath .)" \
		CORAZA_WORKLOADS="$(abspath $(CORAZA_WORKLOADS))" \
		BENCH_OUT="$(abspath $(BENCH_OUT))" \
		CORAZA_GO_PROFILE="$(CORAZA_GO_PROFILE)" \
		CORAZA_CHECKRESOLVE_CMD="$(CORAZA_CHECKRESOLVE_CMD)" \
		CORAZA_PARITY_CMD="$(CORAZA_PARITY_CMD)" \
		GOWORK=off GOTOOLCHAIN=local go run . parity

coraza-bench:
	cd benchmarks/coraza/coordinator && \
		CORAZA_REPO="$(abspath .)" \
		CORAZA_WORKLOADS="$(abspath $(CORAZA_WORKLOADS))" \
		BENCH_OUT="$(abspath $(BENCH_OUT))" \
		CORAZA_GO_PROFILE="$(CORAZA_GO_PROFILE)" \
		CORAZA_CHECKRESOLVE_CMD="$(CORAZA_CHECKRESOLVE_CMD)" \
		CORAZA_PARITY_CMD="$(CORAZA_PARITY_CMD)" \
		CORAZA_REPETITIONS="$(CORAZA_REPETITIONS)" \
		CORAZA_ITERATIONS="$(CORAZA_ITERATIONS)" \
		CORAZA_RUST_BUILD_CMD="$(CORAZA_RUST_BUILD_CMD)" \
		CORAZA_RUST_DRIVER_CMD="$(CORAZA_RUST_DRIVER_CMD)" \
		CORAZA_GO_BUILD_CMD="$(CORAZA_GO_BUILD_CMD)" \
		CORAZA_GO_DRIVER_CMD="$(CORAZA_GO_DRIVER_CMD)" \
		GOWORK=off GOTOOLCHAIN=local go run . bench

ftw-runner-check:
	@files="$$(cd ftw-runner && gofmt -l .)"; \
	if [ -n "$$files" ]; then printf '%s\n' "$$files"; exit 1; fi
	cd ftw-runner && GOWORK=off GOTOOLCHAIN=local go vet ./...
	cd ftw-runner && GOWORK=off GOTOOLCHAIN=local go test ./...

coraza-example-test:
	cargo test -p coraza --example ftw_server_async --features async-server $(_NOCAPTURE)

ftw-smoke:
	cargo build --release -p coraza --example ftw_server_async --features async-server
	cd ftw-runner && GOWORK=off GOTOOLCHAIN=local go run . \
		--rules testdata/smoke/rules.conf \
		--test-dir testdata/smoke \
		--expected-rules 1 \
		--expected-files 1 \
		--expected-tests 1 \
		--expected-stages 1 \
		--manifest "$(abspath $(FTW_MANIFEST))"
	@python3 -c 'import json, sys; m = json.load(open(sys.argv[1])); bad = [k for k in ("failed", "skipped", "ignored", "forced_failed") if m["results"][k]]; (sys.exit("FTW smoke failed: %s %s" % (m["failures"], bad)) if (not m["ok"] or bad) else None)' "$(abspath $(FTW_MANIFEST))"
	@python3 -c 'import json, sys; m = json.load(open(sys.argv[1])); incomplete = [k for k in ("files", "tests", "stages") if m["counts"][k]["selected"] != m["counts"][k]["inventory"]]; (sys.exit("FTW smoke incomplete counts: %s" % incomplete) if incomplete else None)' "$(abspath $(FTW_MANIFEST))"

# -------------------------------------------------------------------
# Quality
# -------------------------------------------------------------------

lint:
	cargo clippy --workspace --all-targets -- -D warnings
	cargo +$(NIGHTLY) fmt --all -- --check
	cargo xtask lint-license

lint-extra:
	typos .
	taplo format --check '**/*.toml'
	actionlint -ignore 'specifying action "\$$/.+" in invalid format because ref is missing'
	shellcheck $$(git ls-files '*.sh') .hooks/pre-commit

audit:
	cargo audit
	cargo deny check
	cargo deny --all-features check

# Offline corpus, table, conformance and Go fixture tools are not runtime coverage targets.
# llvm-cov sees native test profiles; Envoy WASM callbacks are exercised in the integration job.
# The default workspace run does not enable the gated operators or the optional host/HTTPS
# code, so the second run measures coraza with every feature and enforces the same floors.
coverage-check:
	mkdir -p target/llvm-cov
	cargo llvm-cov nextest --workspace --lcov --output-path target/llvm-cov/lcov.info \
		--ignore-filename-regex 'envoy-libperfusion/src/lib\.rs|src/main\.rs|xtask/src/corpus\.rs|xtask/src/tables\.rs|xtask/src/conformance\.rs|xtask/src/go_fixtures\.rs'
	cargo llvm-cov report --summary-only --fail-under-lines 90 --fail-under-regions 80 \
		--ignore-filename-regex 'envoy-libperfusion/src/lib\.rs|src/main\.rs|xtask/src/corpus\.rs|xtask/src/tables\.rs|xtask/src/conformance\.rs|xtask/src/go_fixtures\.rs'
	cargo llvm-cov nextest -p coraza --all-features --summary-only \
		--fail-under-lines 90 --fail-under-regions 80

fmt:
	cargo +$(NIGHTLY) fmt --all

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items

# -------------------------------------------------------------------
# Dev Setup
# -------------------------------------------------------------------

setup-hooks:
	@set -eu; \
	project_root="$$(git rev-parse --show-toplevel)"; \
	project_hooks="$$(cd "$$project_root/.hooks" && pwd -P)"; \
	current_hooks="$$(git config --get core.hooksPath 2>/dev/null || git rev-parse --git-path hooks)"; \
	case "$$current_hooks" in /*) ;; *) current_hooks="$$project_root/$$current_hooks" ;; esac; \
	if [ -d "$$current_hooks" ]; then current_hooks="$$(cd "$$current_hooks" && pwd -P)"; fi; \
	if [ "$$current_hooks" = "$$project_hooks" ]; then \
		echo "Git hooks already point to .hooks."; \
	else \
		git config --local coraza.previousHooksPath "$$current_hooks"; \
		git config --local core.hooksPath .hooks; \
		echo "Git hooks installed; an existing pre-commit hook will be chained when present."; \
	fi; \
	chmod +x "$$project_hooks/pre-commit"

# -------------------------------------------------------------------
# Help
# -------------------------------------------------------------------

help:
	@echo "Variables:"
	@echo "  V=1        show test output (--nocapture)"
	@echo "  NIGHTLY    rustup toolchain used for rustfmt (default: nightly)"
	@echo ""
	@echo "Top-level:"
	@echo "  all        build + fmt + lint + lint-extra + test + audit + coverage-check"
	@echo ""
	@echo "Build:"
	@echo "  build      cargo build --workspace"
	@echo "  build-envoy-wasm       build the release Envoy filter for wasm32-wasip1"
	@echo "  build-envoy-wasm-image build/tag a scratch OCI image using Docker's Rust build stage"
	@echo "    ENVOY_WASM_IMAGE=...  image tag (default: $(ENVOY_WASM_IMAGE))"
	@echo "  check      cargo check --workspace"
	@echo "  clean      cargo clean"
	@echo ""
	@echo "Test:"
	@echo "  test       verify corpus and run all tests"
	@echo "  parity-manifest-check  verify parity fixture inventory and hashes"
	@echo "  parity-differential   run pinned C/Go corpus and generated-byte parity gates"
	@echo "  go-harness-check      verify Go fixtures, then gofmt, vet, test and resolution-check the Go benchmark module"
	@echo "  coraza-coordinator-check  gofmt, vet and test the Coraza benchmark coordinator"
	@echo "  coraza-parity         validate identities and run the correctness parity gate"
	@echo "  coraza-bench          run the correctness gate and the paired timing protocol"
	@echo "    CORAZA_WORKLOADS=...  workload directory (default: $(CORAZA_WORKLOADS))"
	@echo "    BENCH_OUT=...         artifact root (default: $(BENCH_OUT))"
	@echo "    CORAZA_REPETITIONS=...  paired repetitions, at least 3 (default: $(CORAZA_REPETITIONS))"
	@echo "    CORAZA_ITERATIONS=...   driver iterations (default: $(CORAZA_ITERATIONS))"
	@echo "    CORAZA_GO_PROFILE=...   auto, upstream or local (default: $(CORAZA_GO_PROFILE))"
	@echo "    CORAZA_CHECKRESOLVE_CMD=...  stamped checkresolve command for the local profile"
	@echo "    CORAZA_PARITY_CMD=...   parity runner command (default: go run ./cmd/parity)"
	@echo "    CORAZA_RUST_DRIVER_CMD=... / CORAZA_GO_DRIVER_CMD=...  prebuilt driver commands"
	@echo "    CORAZA_RUST_BUILD_CMD=... / CORAZA_GO_BUILD_CMD=...    build commands with driver commands"
	@echo "  ftw-runner-check      gofmt, vet and test the FTW runner module"
	@echo "  coraza-example-test   run the async FTW example server tests"
	@echo "  ftw-smoke             run strict FTW conformance against the smoke fixtures"
	@echo "    FTW_MANIFEST=...      result manifest path (default: $(FTW_MANIFEST))"
	@echo ""
	@echo "Quality:"
	@echo "  lint       clippy + rustfmt check + license header check"
	@echo "  lint-extra typos + taplo + actionlint + shellcheck"
	@echo "  audit      cargo audit + cargo deny"
	@echo "  coverage-check  enforce 90% line / 80% region coverage"
	@echo "  fmt        format with rustfmt"
	@echo "  doc        build docs with warnings denied"
	@echo ""
	@echo "Dev Setup:"
	@echo "  setup-hooks  enable project pre-commit checks and chain existing hooks"
