# Makefile — convenience wrapper for common Security-Agent developer commands.
#
# All targets are thin wrappers around `cargo`; they do not hide errors.
# Run `make help` to list available targets.

.PHONY: all help fmt clippy test build check status clean install uninstall android android-install deploy electron electron-install electron-pack electron-icons electron-installer electron-installer-win electron-installer-mac electron-installer-linux

CARGO ?= cargo
RELEASE_BIN := target/release/security-agent

# Install location. Override with `make install PREFIX=/usr/local` for a
# system-wide install, or set DESTDIR for staged/packaging installs.
PREFIX ?= $(HOME)/.local
DESTDIR ?=
BINDIR := $(DESTDIR)$(PREFIX)/bin

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

## android-install: Guided one-command install onto an Android device.
#  Auto-detects Termux vs. ADB, the device ABI, the Rust target, and the NDK,
#  then cross-compiles, pushes, and smoke-tests on the device. Pass flags via
#  ANDROID_INSTALL_FLAGS, e.g. `make android-install ANDROID_INSTALL_FLAGS=--check`.
android-install:
	./scripts/android-install.sh $(ANDROID_INSTALL_FLAGS)

## deploy: Run the full gate, build a release binary, and package it into
#  a checksummed dist/ archive (scripts/deploy.sh). Pass extra flags via
#  DEPLOY_FLAGS, e.g. `make deploy DEPLOY_FLAGS="--skip-checks"`.
deploy:
	./scripts/deploy.sh $(DEPLOY_FLAGS)

## electron-install: Install Electron app dependencies.
electron-install:
	cd electron && npm install

## electron: Launch the Electron GUI (builds Rust binary first if needed).
electron: build
	cd electron && npm start

## electron-pack: Package the Electron app for distribution.
electron-pack: build
	cd electron && npm run dist

## electron-icons: Generate app icon PNGs from the shield SVG.
electron-icons:
	cd electron && node scripts/generate-icons.js

## electron-installer: Build platform installer for the current OS.
#   On Windows: NSIS .exe installer + portable .exe
#   On macOS:   .dmg disk image
#   On Linux:   .deb + .rpm + .AppImage + .tar.gz
electron-installer: build electron-icons
	cd electron && npm run dist

## electron-installer-win: Cross-compile Windows NSIS installer from Linux.
#   Requires: Wine + NSIS (apt install wine64 nsis) or native Windows build.
electron-installer-win: build electron-icons
	cd electron && npm run dist:win

## electron-installer-mac: Build macOS DMG (requires macOS host).
electron-installer-mac: build electron-icons
	cd electron && npm run dist:mac

## electron-installer-linux: Build Linux deb/rpm/AppImage packages.
electron-installer-linux: build electron-icons
	cd electron && npm run dist:linux

## install: Build the release binary and install it to $(PREFIX)/bin
#  (default ~/.local/bin). Override PREFIX for a different prefix, or set
#  DESTDIR for a staged install: `make install PREFIX=/usr/local`.
install: build
	@mkdir -p "$(BINDIR)"
	install -m 0755 "$(RELEASE_BIN)" "$(BINDIR)/security-agent"
	@echo ""
	@echo "Installed: $(BINDIR)/security-agent"
	@echo "Ensure $(PREFIX)/bin is on your PATH, then run: security-agent --build-info"

## uninstall: Remove a binary installed by `make install`.
uninstall:
	rm -f "$(BINDIR)/security-agent"
	@echo "Removed: $(BINDIR)/security-agent"

## clean: Remove build artifacts.
clean:
	$(CARGO) clean
	rm -rf dist
	cd electron && rm -rf node_modules dist out
