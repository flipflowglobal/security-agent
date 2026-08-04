#!/usr/bin/env bash
# scripts/android-install.sh — guided, one-command Android installer for the
# Security-Agent CLI.
#
# It removes the manual multi-step Android dance (add a Rust target, find the
# NDK, set linker PATHs, cross-compile, adb push, chmod, run) and does it for
# you, choosing the right method and settings automatically:
#
#   * On a phone (Termux): builds/installs natively and links it onto PATH.
#   * On a desktop with a device attached: detects the device's CPU ABI,
#     adds the matching Rust target, locates the NDK (or uses cargo-ndk if
#     present), cross-compiles, pushes over ADB, and runs an on-device smoke
#     test — all from one command.
#
# Usage:
#   scripts/android-install.sh [options]
#
#   --method auto|termux|adb   Install method. "auto" (default) picks Termux
#                              when run on-device, otherwise ADB.
#   --device <serial>          Target a specific ADB device (see `adb devices`).
#   --abi <abi>                Force the device ABI (arm64-v8a, armeabi-v7a,
#                              x86_64, x86) instead of auto-detecting it.
#   --dest <path>              On-device install path for the ADB method.
#                              Default: /data/local/tmp/security-agent
#   --release-dir <dir>        Where the Termux method installs the launcher.
#                              Default: $PREFIX/bin (Termux) or $HOME/.local/bin.
#   --yes                      Assume "yes" to prompts (non-interactive).
#   --check                    Dry run: print the plan and exit, change nothing.
#   --no-color                 Disable ANSI styling.
#   -h, --help                 Show this help and exit.
set -euo pipefail

# ── argument parsing ────────────────────────────────────────────────────────

METHOD="auto"
DEVICE=""
FORCE_ABI=""
DEST="/data/local/tmp/security-agent"
RELEASE_DIR=""
ASSUME_YES=0
DRY_RUN=0
FORCE_NO_COLOR=0

while [ $# -gt 0 ]; do
    case "$1" in
        --method) METHOD="${2:?missing value for --method}"; shift 2 ;;
        --device) DEVICE="${2:?missing value for --device}"; shift 2 ;;
        --abi) FORCE_ABI="${2:?missing value for --abi}"; shift 2 ;;
        --dest) DEST="${2:?missing value for --dest}"; shift 2 ;;
        --release-dir) RELEASE_DIR="${2:?missing value for --release-dir}"; shift 2 ;;
        --yes | -y) ASSUME_YES=1; shift ;;
        --check | --dry-run) DRY_RUN=1; shift ;;
        --no-color) FORCE_NO_COLOR=1; shift ;;
        -h | --help)
            sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

case "$METHOD" in
    auto | termux | adb) ;;
    *) echo "invalid --method '$METHOD' (want: auto, termux, adb)" >&2; exit 2 ;;
esac

# ── styling (mirrors scripts/deploy.sh) ─────────────────────────────────────

if [ "$FORCE_NO_COLOR" -eq 0 ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; CYAN=$'\033[0;36m'
    GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; RED=$'\033[0;31m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; CYAN=""; GREEN=""; YELLOW=""; RED=""; RESET=""
fi

STEP_INDEX=0
banner() {
    printf '%s%s\n' "$CYAN" "$BOLD"
    printf '  Security-Agent — Android Installer\n'
    printf '%s%s  a guided, one-command install%s\n' "$RESET" "$DIM" "$RESET"
}
step() { STEP_INDEX=$((STEP_INDEX + 1)); printf '\n%s\n' "${CYAN}${BOLD}━━ [${STEP_INDEX}] $1 ━━${RESET}"; }
ok() { printf '  %s\n' "${GREEN}✓ $1${RESET}"; }
skip() { printf '  %s\n' "${YELLOW}○ $1${RESET}"; }
info() { printf '  %s%s%s\n' "$DIM" "$1" "$RESET"; }
kv() { printf '  %s%-12s%s %s\n' "$DIM" "$1" "$RESET" "$2"; }
fail() { printf '\n%s\n' "${RED}${BOLD}✗ install failed: $1${RESET}" >&2; exit 1; }

# Anchor to the repo root regardless of caller's working directory.
REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_DIR"

# Prompt helper: returns 0 for yes. Honors --yes and non-interactive stdin.
confirm() {
    local prompt="$1"
    if [ "$ASSUME_YES" -eq 1 ]; then return 0; fi
    if [ ! -t 0 ]; then return 0; fi
    printf '  %s%s [Y/n] %s' "$BOLD" "$prompt" "$RESET"
    local reply; read -r reply
    case "$reply" in n | N | no | NO) return 1 ;; *) return 0 ;; esac
}

# Runs a command, or just prints it under --check.
run() {
    if [ "$DRY_RUN" -eq 1 ]; then printf '  %s$ %s%s\n' "$DIM" "$*" "$RESET"; return 0; fi
    "$@"
}

# ── method auto-detection ───────────────────────────────────────────────────

detect_method() {
    if [ "$METHOD" != "auto" ]; then echo "$METHOD"; return; fi
    # Termux sets PREFIX to .../com.termux/files/usr.
    if [ -n "${PREFIX:-}" ] && printf '%s' "$PREFIX" | grep -q "com.termux"; then
        echo "termux"; return
    fi
    if command -v adb >/dev/null 2>&1; then echo "adb"; return; fi
    # Under --check we still want a preview even with no tooling present:
    # assume the common desktop → ADB path.
    [ "$DRY_RUN" -eq 1 ] && { echo "adb"; return; }
    echo "none"
}

# Maps an Android CPU ABI to the Rust target triple.
abi_to_target() {
    case "$1" in
        arm64-v8a) echo "aarch64-linux-android" ;;
        armeabi-v7a | armeabi) echo "armv7-linux-androideabi" ;;
        x86_64) echo "x86_64-linux-android" ;;
        x86) echo "i686-linux-android" ;;
        *) echo "" ;;
    esac
}

# ── Termux (on-device) install ──────────────────────────────────────────────

install_termux() {
    step "Termux install (native, on-device)"
    kv "Method" "Termux (build and run on this phone)"

    if [ "$DRY_RUN" -eq 0 ] && ! command -v cargo >/dev/null 2>&1; then
        info "Rust toolchain not found."
        if confirm "Install Rust now (pkg install rust)?"; then
            run pkg install -y rust
        else
            fail "Rust is required in Termux — run: pkg install rust"
        fi
    fi
    ok "Rust toolchain present"

    step "Build (cargo build --release)"
    run cargo build --release || fail "build failed"
    ok "built target/release/security-agent"

    local dest_dir="${RELEASE_DIR:-${PREFIX:-$HOME/.local}/bin}"
    step "Install launcher into $dest_dir"
    run mkdir -p "$dest_dir"
    run install -m 0755 "target/release/security-agent" "$dest_dir/security-agent" \
        || run cp "target/release/security-agent" "$dest_dir/security-agent"
    ok "installed $dest_dir/security-agent"

    step "Verify (--offline-status)"
    run "$dest_dir/security-agent" --offline-status >/dev/null || fail "on-device smoke test failed"
    ok "security-agent runs on this device"
    printf '\n%s\n' "${GREEN}${BOLD}Done — type 'security-agent --guide' to get started.${RESET}"
}

# ── ADB (desktop → device) install ──────────────────────────────────────────

adb_() { if [ -n "$DEVICE" ]; then adb -s "$DEVICE" "$@"; else adb "$@"; fi; }

# Like adb_, but under --check prints the real `adb` command instead of running.
adb_run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        local pfx="adb"; [ -n "$DEVICE" ] && pfx="adb -s $DEVICE"
        printf '  %s$ %s %s%s\n' "$DIM" "$pfx" "$*" "$RESET"; return 0
    fi
    adb_ "$@"
}

pick_device() {
    [ -n "$DEVICE" ] && { echo "$DEVICE"; return; }
    [ "$DRY_RUN" -eq 1 ] && { echo "<device>"; return; }
    local list; list=$(adb devices | awk 'NR>1 && $2=="device" {print $1}')
    local count; count=$(printf '%s\n' "$list" | grep -c . || true)
    if [ "$count" -eq 0 ]; then
        fail "no device detected. Enable USB debugging and run 'adb devices' (or pass --device)."
    elif [ "$count" -eq 1 ]; then
        echo "$list"
    else
        printf '  %sMultiple devices found:%s\n' "$BOLD" "$RESET" >&2
        printf '%s\n' "$list" | sed 's/^/    /' >&2
        fail "more than one device — choose one with --device <serial>"
    fi
}

locate_ndk() {
    for candidate in \
        "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}" \
        "${ANDROID_SDK_ROOT:-}/ndk" "${ANDROID_HOME:-}/ndk" \
        "$HOME/Android/Sdk/ndk" "/opt/android-ndk" "/usr/lib/android-ndk"; do
        [ -z "$candidate" ] && continue
        if [ -d "$candidate/toolchains" ]; then echo "$candidate"; return; fi
        # A parent "ndk/" dir holds versioned subdirs; take the newest.
        if [ -d "$candidate" ]; then
            local newest; newest=$(ls -1 "$candidate" 2>/dev/null | sort -V | tail -1)
            if [ -n "$newest" ] && [ -d "$candidate/$newest/toolchains" ]; then
                echo "$candidate/$newest"; return
            fi
        fi
    done
    echo ""
}

install_adb() {
    step "ADB install (cross-compile → push to device)"
    if [ "$DRY_RUN" -eq 0 ]; then
        command -v adb >/dev/null 2>&1 || fail "adb not found. Install Android platform-tools."
        command -v cargo >/dev/null 2>&1 || fail "cargo not found. Install Rust: https://rustup.rs"
    fi

    local dev; dev=$(pick_device); DEVICE="$dev"
    kv "Device" "$dev"

    # Detect ABI → Rust target.
    local abi="$FORCE_ABI"
    if [ -z "$abi" ]; then
        if [ "$DRY_RUN" -eq 1 ]; then abi="arm64-v8a"; else
            abi=$(adb_ shell getprop ro.product.cpu.abi | tr -d '\r')
        fi
    fi
    local target; target=$(abi_to_target "$abi")
    [ -n "$target" ] || fail "unsupported ABI '$abi' (want arm64-v8a, armeabi-v7a, x86_64, x86)"
    kv "Device ABI" "$abi"
    kv "Rust target" "$target"

    step "Ensure Rust target '$target'"
    if [ "$DRY_RUN" -eq 0 ] && rustup target list --installed 2>/dev/null | grep -qx "$target"; then
        ok "target already installed"
    else
        run rustup target add "$target" || fail "could not add target — is rustup installed?"
        ok "added $target"
    fi

    step "Cross-compile (release, $target)"
    if command -v cargo-ndk >/dev/null 2>&1; then
        info "using cargo-ndk (handles NDK linker paths automatically)"
        run cargo ndk -t "$abi" -o /dev/null build --release --target "$target" \
            || run cargo ndk -t "$abi" build --release --target "$target" \
            || fail "cargo-ndk build failed"
    else
        local ndk; ndk=$(locate_ndk)
        if [ -n "$ndk" ]; then
            info "found NDK: $ndk"
            export ANDROID_NDK_HOME="$ndk"
            local llvm_bin
            llvm_bin=$(ls -d "$ndk"/toolchains/llvm/prebuilt/*/bin 2>/dev/null | head -1)
            [ -n "$llvm_bin" ] && export PATH="$llvm_bin:$PATH"
        else
            info "no NDK auto-detected; relying on .cargo/config.toml linker wrappers on PATH"
            info "tip: install cargo-ndk (cargo install cargo-ndk) for the easiest path"
        fi
        run cargo build --release --target "$target" \
            || fail "cross-compile failed — install the Android NDK or cargo-ndk (see .cargo/config.toml)"
    fi
    local bin="target/$target/release/security-agent"
    ok "built $bin"

    step "Push to device ($DEST) and mark executable"
    adb_run push "$bin" "$DEST" || fail "adb push failed"
    adb_run shell chmod 755 "$DEST" || fail "could not chmod on device"
    ok "pushed to $DEST"

    step "Verify (on-device --offline-status)"
    if [ "$DRY_RUN" -eq 1 ]; then
        info "would run: adb shell $DEST --offline-status"
    else
        adb_ shell "$DEST" --offline-status >/dev/null || fail "on-device smoke test failed"
    fi
    ok "security-agent runs on the device"
    printf '\n%s\n' "${GREEN}${BOLD}Done.${RESET} Run it with:  ${RESET}adb shell $DEST --guide"
}

# ── main ─────────────────────────────────────────────────────────────────────

banner
[ "$DRY_RUN" -eq 1 ] && info "(--check: dry run, nothing will be changed)"

RESOLVED=$(detect_method)
case "$RESOLVED" in
    termux) install_termux ;;
    adb) install_adb ;;
    none)
        fail "could not pick a method automatically. On a phone, run this in Termux; \
on a desktop, install ADB (platform-tools) and attach a device, or pass --method."
        ;;
esac
