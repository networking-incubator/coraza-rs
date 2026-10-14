# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

V ?=
NIGHTLY ?= nightly

ifneq ($(V),)
  _NOCAPTURE := -- --nocapture
endif

.PHONY: all build check clean test parity-manifest-check parity-differential lint lint-extra audit coverage-check fmt doc setup-hooks help

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
	cargo xtask corpus-check
	cargo xtask tables-check
	$(MAKE) parity-manifest-check
	cargo test --workspace $(_NOCAPTURE)

parity-manifest-check:
	python3 libinjection-rs/tools/parity/check_manifest.py
	python3 libinjection-rs/tools/parity/test_manifest_semantics.py

parity-differential:
	cargo test -p libperfusion --test upstream xss_samples -- --ignored
	cargo test -p libperfusion --test oracle_differential pinned_c_oracle_matches_corpus_and_binary_cases -- --ignored --nocapture
	cargo test -p libperfusion --test oracle_differential -- --ignored --nocapture
	cargo test -p libperfusion --test generated_differential -- --ignored --nocapture

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
	actionlint -ignore 'specifying action "\$$/.+" in invalid format because ref is missing'
	shellcheck .hooks/*

audit:
	cargo audit
	cargo deny check

# Legacy SQL parser coverage is supplied by the corpus tests in PR2.
coverage-check:
	mkdir -p target/llvm-cov
	cargo llvm-cov nextest --workspace --lcov --output-path target/llvm-cov/lcov.info \
		--ignore-filename-regex 'src/main\.rs|xtask/src/corpus\.rs'
	cargo llvm-cov report --summary-only --fail-under-lines 90 --fail-under-regions 80 \
		--ignore-filename-regex 'src/main\.rs|xtask/src/corpus\.rs'

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
	@echo "  check      cargo check --workspace"
	@echo "  clean      cargo clean"
	@echo ""
	@echo "Test:"
	@echo "  test       verify corpus and run all tests"
	@echo "  parity-manifest-check  verify parity fixture inventory and hashes"
	@echo "  parity-differential   run pinned C/Go corpus and generated-byte parity gates"
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
