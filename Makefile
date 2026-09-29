# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

V ?=
NIGHTLY ?= nightly

ifneq ($(V),)
  _NOCAPTURE := -- --nocapture
endif

.PHONY: all build check clean test lint lint-extra audit coverage-check fmt doc setup-hooks help

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
	cargo test --workspace $(_NOCAPTURE)

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
	npx --yes markdownlint-cli2@0.23.2 "**/*.md" "#target"

audit:
	cargo audit
	cargo deny check

# Legacy SQL parser coverage is supplied by the corpus tests in PR2.
coverage-check:
	mkdir -p target/llvm-cov
	cargo llvm-cov nextest --workspace --lcov --output-path target/llvm-cov/lcov.info \
		--ignore-filename-regex 'src/main\.rs|libinjection-rs/src/sqli/legacy/.*'
	cargo llvm-cov report --summary-only --fail-under-lines 90 --fail-under-regions 80 \
		--ignore-filename-regex 'src/main\.rs|libinjection-rs/src/sqli/legacy/.*'

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
	@echo "  test       run all tests"
	@echo ""
	@echo "Quality:"
	@echo "  lint       clippy + rustfmt check + license header check"
	@echo "  lint-extra typos + taplo + actionlint + shellcheck + markdownlint"
	@echo "  audit      cargo audit + cargo deny"
	@echo "  coverage-check  enforce 90% line / 80% region coverage"
	@echo "  fmt        format with rustfmt"
	@echo "  doc        build docs with warnings denied"
	@echo ""
	@echo "Dev Setup:"
	@echo "  setup-hooks  install git pre-commit hook (commit signing + lint)"
