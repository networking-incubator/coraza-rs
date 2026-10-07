# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

V ?=
NIGHTLY ?= nightly-2026-10-06
export LIBINJECTION_MIRI_TOOLCHAIN ?= $(NIGHTLY)
GO_SOURCE ?= $(if $(LIBINJECTION_GO_SOURCE),$(LIBINJECTION_GO_SOURCE),/tmp/libinjection-go-v033)

ifneq ($(V),)
  _NOCAPTURE := -- --nocapture
endif

.PHONY: all build check clean test parity-manifest-check parity-differential feature-check wasm-check miri-check package-check perf-check perf-scaling-check lint lint-extra audit coverage-check fmt doc setup-hooks help

all: build fmt lint lint-extra test audit coverage-check

# -------------------------------------------------------------------
# Build
# -------------------------------------------------------------------

build:
	cargo build --workspace

check:
	cargo check --workspace

clean:
	cargo clean

# -------------------------------------------------------------------
# Test
# -------------------------------------------------------------------

test:
	$(MAKE) parity-manifest-check
	cargo test --workspace $(_NOCAPTURE)

parity-manifest-check:
	python3 libinjection-rs/tools/parity/check_manifest.py
	python3 libinjection-rs/tools/parity/test_manifest_semantics.py

parity-differential:
	cargo test -p libinjection --test oracle_differential -- --ignored --nocapture
	cargo test -p libinjection --test generated_differential -- --ignored --nocapture

# Keep both legacy API configurations explicit; the library always uses std.
feature-check:
	cargo check -p libinjection --no-default-features
	cargo check -p libinjection --no-default-features --features legacy
	cargo test --release -p libinjection --test no_alloc --no-default-features --features legacy

wasm-check:
	rustup target add wasm32-wasip1 --toolchain "$$(awk -F '"' '/channel = / { print $$2 }' rust-toolchain.toml)"
	cargo check -p libinjection --target wasm32-wasip1 --no-default-features
	cargo check -p libinjection --target wasm32-wasip1 --no-default-features --features legacy

perf-check:
	python3 libinjection-rs/tools/perf/run.py --go-source "$(GO_SOURCE)"

perf-scaling-check:
	python3 libinjection-rs/tools/perf/scaling.py --go-source "$(GO_SOURCE)"

# Requires nightly Miri to be installed by the caller/CI image.
# Keep interpreted parser inputs finite; 65 KiB counter stress is covered by
# native tests and coverage, while these targeted cases cover byte semantics.
# The corpus test reads vendored files, so it disables Miri isolation only for
# that filesystem-dependent command.
miri-check:
	cargo +$(NIGHTLY) miri setup
	python3 libinjection-rs/tools/ci/run_miri_test.py --lib sqli::legacy::parse::tests::high_byte_q_delimiter_falls_back_to_ordinary_string_tokenization
	python3 libinjection-rs/tools/ci/run_miri_test.py --lib sqli::legacy::parse::tests::escaped_quote_followed_by_quote_closes_at_the_following_quote
	python3 libinjection-rs/tools/ci/run_miri_test.py --lib sqli::legacy::parse::tests::mixed_escaped_and_doubled_quote_run_closes_at_final_unpaired_quote
	python3 libinjection-rs/tools/ci/run_miri_test.py --lib sqli::legacy::parse::tests::unicode_keyword_uppercase_and_invalid_utf8_match_go
	MIRIFLAGS=-Zmiri-disable-isolation python3 libinjection-rs/tools/ci/run_miri_test.py --test corpus_parse folding_corpus_baseline
	python3 libinjection-rs/tools/ci/run_miri_test.py --lib xss::legacy::regression_tests::html5_transition_regressions_match_go_tokens
	python3 libinjection-rs/tools/ci/run_miri_test.py --lib xss::legacy::deny::tests::entity_consumption_matches_go_for_malformed_and_overflow_values
	python3 libinjection-rs/tools/ci/run_miri_test.py --lib xss::legacy::deny::tests::url_entity_matching_keeps_numeric_value_until_go_masks_it
	python3 libinjection-rs/tools/ci/run_miri_test.py --lib tests::evidence_reports_distinct_original_ranges
	python3 libinjection-rs/tools/ci/run_miri_test.py --lib tests::encoded_sql_evidence_keeps_all_original_spans_and_decisive_hint
	python3 libinjection-rs/tools/ci/run_miri_test.py --lib tests::encoded_xss_evidence_keeps_all_original_spans_and_decisive_hint

package-check:
	python3 libinjection-rs/tools/packaging/check_package.py

# -------------------------------------------------------------------
# Quality
# -------------------------------------------------------------------

lint:
	cargo clippy --workspace --all-targets -- -D warnings
	cargo +$(NIGHTLY) fmt --all -- --check
	cargo xtask lint-license

lint-extra:
	typos .
	taplo format --check .
	actionlint
	shellcheck .hooks/*

audit:
	cargo audit
	cargo deny check

coverage-check:
	mkdir -p target/llvm-cov
	cargo +$(NIGHTLY) llvm-cov --branch nextest --workspace --lcov --output-path target/llvm-cov/lcov.info \
		--ignore-filename-regex 'src/main\.rs'
	cargo +$(NIGHTLY) llvm-cov --branch report --summary-only --fail-under-lines 90 --fail-under-regions 80 \
		--ignore-filename-regex 'src/main\.rs'
	cargo +$(NIGHTLY) llvm-cov --branch report --text --show-missing-lines \
		--ignore-filename-regex 'src/main\.rs'

fmt:
	cargo +$(NIGHTLY) fmt --all

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items

# -------------------------------------------------------------------
# Dev Setup
# -------------------------------------------------------------------

setup-hooks:
	ln -sf ../../.hooks/pre-commit .git/hooks/pre-commit
	@echo "Git hooks installed."

# -------------------------------------------------------------------
# Help
# -------------------------------------------------------------------

help:
	@echo "Variables:"
	@echo "  V=1        show test output (--nocapture)"
	@echo "  NIGHTLY    pinned nightly toolchain for formatting, coverage, and Miri (default: nightly-2026-10-06)"
	@echo "  GO_SOURCE  pinned libinjection-go checkout (default: /tmp/libinjection-go-v033)"
	@echo ""
	@echo "Top-level:"
	@echo "  all        build + fmt + lint + lint-extra + test + audit + coverage-check"
	@echo ""
	@echo "Build:"
	@echo "  build      cargo build --workspace"
	@echo "  check      cargo check --workspace"
	@echo "  clean      cargo clean"
	@echo ""
	@echo "Test:"
	@echo "  test       run all tests"
	@echo "  parity-manifest-check  verify libinjection fixture inventory and hashes"
	@echo "  parity-differential   run ignored Go corpus and generated-byte parity gates"
	@echo "  feature-check         check legacy API on/off and legacy no-allocation behavior"
	@echo "  wasm-check            compile minimal and legacy WASM profiles"
	@echo "  perf-check            run paired Rust/Go latency assurance"
	@echo "  perf-scaling-check    run paired hostile-input scaling assurance"
	@echo "  miri-check            run parser, fold, HTML, entity, and span tests under Miri"
	@echo "  package-check         verify packaged provenance and offline std builds"
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
	@echo "  setup-hooks  install git pre-commit hook (commit signing + lint)"
