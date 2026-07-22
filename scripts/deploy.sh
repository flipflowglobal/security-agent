#!/usr/bin/env bash
# scripts/deploy.sh — build, verify, and package the Security-Agent CLI
# binary for distribution.
#
# This is a release/packaging script for the offline Rust CLI: it runs the
# same quality gate CI enforces, builds an optimized binary (optionally
# cross-compiled), and packages it into a checksummed archive under
# dist/. There is no web service or network call involved — the agent is a
# terminal tool, so "deploying" it means producing a trustworthy, versioned
# release artifact a user can download and run locally.
#
# Usage:
#   scripts/deploy.sh [--target <triple>] [--skip-checks] [--out <dir>] [--no-color]
#
#   --target <triple>   Cross-compile for <triple> (e.g. aarch64-linux-android)
#                        instead of the host. Requires the target's toolchain
#                        to already be installed (rustup target add ...).
#   --skip-checks        Skip fmt/clippy/test and only build + package
#                        (a fast repackage of already-verified code).
#   --out <dir>          Directory to write the packaged archive into.
#                        Defaults to "dist".
#   --no-color            Disable ANSI styling (auto-disabled when stdout is
#                        not a terminal, or NO_COLOR is set).
#   -h, --help           Show this help and exit.
set -euo pipefail

# ── argument parsing ────────────────────────────────────────────────────────

TARGET=""
SKIP_CHECKS=0
OUT_DIR="dist"
FORCE_NO_COLOR=0

while [ $# -gt 0 ]; do
    case "$1" in
        --target)
            TARGET="${2:?missing value for --target}"
            shift 2
            ;;
        --skip-checks)
            SKIP_CHECKS=1
            shift
            ;;
        --out)
            OUT_DIR="${2:?missing value for --out}"
            shift 2
            ;;
        --no-color)
            FORCE_NO_COLOR=1
            shift
            ;;
        -h | --help)
            sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

# ── styling ──────────────────────────────────────────────────────────────────
# Colors are enabled only on an interactive terminal, and only when the
# operator hasn't asked for plain output (--no-color or NO_COLOR set) — CI
# logs and piped output stay clean of escape codes either way.

if [ "$FORCE_NO_COLOR" -eq 0 ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    CYAN=$'\033[36m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    RED=$'\033[31m'
    RESET=$'\033[0m'
else
    BOLD="" DIM="" CYAN="" GREEN="" YELLOW="" RED="" RESET=""
fi

TOTAL_STEPS=5
STEP_INDEX=0
DEPLOY_START=$(date +%s)

banner() {
    printf '%s\n' "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    printf '%s\n' "${BOLD}${CYAN}║           Security-Agent — Release Deploy Pipeline              ║${RESET}"
    printf '%s\n' "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
}

step_start() {
    STEP_INDEX=$((STEP_INDEX + 1))
    printf '\n%s\n' "${BOLD}${YELLOW}▶ [${STEP_INDEX}/${TOTAL_STEPS}] $1${RESET}"
}

step_skip() {
    printf '  %s\n' "${DIM}– skipped${RESET}"
}

step_ok() {
    printf '  %s\n' "${GREEN}✔ done${RESET}"
}

fail() {
    printf '\n%s\n' "${RED}✘ deploy failed: $1${RESET}" >&2
    exit 1
}

kv() {
    printf '  %s%-16s%s %s\n' "${DIM}" "$1" "${RESET}" "$2"
}

# ── preflight ────────────────────────────────────────────────────────────────

banner

command -v cargo >/dev/null 2>&1 || fail "cargo not found on PATH"

PKG_VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
HOST_TRIPLE=$(rustc -vV | sed -n 's/^host: //p')
BUILD_TRIPLE="${TARGET:-$HOST_TRIPLE}"

echo ""
kv "Package" "security-agent $PKG_VERSION"
kv "Target" "$BUILD_TRIPLE"
kv "Cargo" "$(cargo --version)"

# ── quality gate (mirrors CI exactly) ───────────────────────────────────────

if [ "$SKIP_CHECKS" -eq 1 ]; then
    step_start "Formatting (cargo fmt --all --check)"
    step_skip
    step_start "Lint (cargo clippy, pedantic + nursery)"
    step_skip
    step_start "Tests (cargo test)"
    step_skip
else
    step_start "Formatting (cargo fmt --all --check)"
    cargo fmt --all --check || fail "formatting check failed — run 'cargo fmt --all'"
    step_ok

    step_start "Lint (cargo clippy, pedantic + nursery)"
    cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::nursery \
        || fail "clippy found issues"
    step_ok

    step_start "Tests (cargo test)"
    cargo test || fail "test suite failed"
    step_ok
fi

# ── build ────────────────────────────────────────────────────────────────────

step_start "Release build ($BUILD_TRIPLE)"
if [ -n "$TARGET" ]; then
    cargo build --release --target "$TARGET" || fail "release build failed"
    BIN_PATH="target/$TARGET/release/security-agent"
else
    cargo build --release || fail "release build failed"
    BIN_PATH="target/release/security-agent"
fi
[ -f "$BIN_PATH" ] || fail "expected binary not found at $BIN_PATH"
step_ok

# ── package ──────────────────────────────────────────────────────────────────

step_start "Package (dist archive + checksum)"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

mkdir -p "$OUT_DIR"
ARCHIVE_NAME="security-agent-${PKG_VERSION}-${BUILD_TRIPLE}.tar.gz"
ARCHIVE_PATH="$OUT_DIR/$ARCHIVE_NAME"

STAGE_DIR=$(mktemp -d)
trap 'rm -rf "$STAGE_DIR"' EXIT

cp "$BIN_PATH" "$STAGE_DIR/security-agent"
[ -f LICENSE ] && cp LICENSE "$STAGE_DIR/"
[ -f README.md ] && cp README.md "$STAGE_DIR/"

tar -czf "$ARCHIVE_PATH" -C "$STAGE_DIR" .
CHECKSUM=$(sha256_of "$ARCHIVE_PATH")
printf '%s  %s\n' "$CHECKSUM" "$ARCHIVE_NAME" >"$ARCHIVE_PATH.sha256"
BIN_SIZE=$(wc -c <"$BIN_PATH" | tr -d ' ')

step_ok

# ── summary ──────────────────────────────────────────────────────────────────

DEPLOY_END=$(date +%s)
ELAPSED=$((DEPLOY_END - DEPLOY_START))

echo ""
printf '%s\n' "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${RESET}"
printf '%s\n' "${BOLD}${GREEN}║                      Deploy Summary                              ║${RESET}"
printf '%s\n' "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${RESET}"
kv "Version" "$PKG_VERSION"
kv "Target" "$BUILD_TRIPLE"
kv "Binary" "$BIN_PATH ($BIN_SIZE bytes)"
kv "Archive" "$ARCHIVE_PATH"
kv "SHA-256" "$CHECKSUM"
kv "Elapsed" "${ELAPSED}s"
echo ""
