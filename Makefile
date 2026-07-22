# Makefile — convenience wrapper for common Security-Agent developer commands.
#
# All targets are thin wrappers around `cargo`; they do not hide errors.
# Run `make help` to list available targets.

.PHONY: all help fmt clippy test build check status clean android deploy

CARGO ?= cargo
RELEASE_BIN := target/release/security-agent
ANDROID_TARGET := aarch64-linux-android

# Default target: run the full check suite.
all: check

## help: Print this help message.
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'

## fmt: Check code formatting (cargo fmt --all --check).
fmt:
	$(CARGO) fmt --all --check

## fmt-fix: Auto-fix code formatting (cargo fmt --all).
fmt-fix:
	$(CARGO) fmt --all

## clippy: Lint all targets, treating warnings as errors.
clippy:
	$(CARGO) clippy --all-targets -- -D warnings

## test: Run the library unit tests.
test:
	$(CARGO) test --lib

## build: Build an optimized release binary.
build:
	$(CARGO) build --release

## check: Run fmt + clippy + test + build in sequence.
check: fmt clippy test build
	@echo ""
	@echo "All checks passed."

## status: Report the agent's local runtime status.
status: build
	$(RELEASE_BIN) --offline-status

## list-tools: List all cataloged tools and whether they are locally installed.
list-tools: build
	$(RELEASE_BIN) --list-tools

## list-skills: List skills compiled into the binary.
list-skills: build
	$(RELEASE_BIN) --list-skills

## android: Cross-compile for arm64-v8a Android.
#  Requires: rustup target add aarch64-linux-android
#            NDK clang wrappers in PATH (see .cargo/config.toml)
android:
	$(CARGO) build --release --target $(ANDROID_TARGET)
	@echo ""
	@echo "Android binary: target/$(ANDROID_TARGET)/release/security-agent"

## deploy: Run the full gate, build a release binary, and package it into
#  a checksummed dist/ archive (scripts/deploy.sh). Pass extra flags via
#  DEPLOY_FLAGS, e.g. `make deploy DEPLOY_FLAGS="--skip-checks"`.
deploy:
	./scripts/deploy.sh $(DEPLOY_FLAGS)

## clean: Remove build artifacts.
clean:
	$(CARGO) clean
	rm -rf dist
