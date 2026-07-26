# Contributing to Security-Agent

Thank you for contributing! This guide covers everything you need to start
working on Security-Agent, pass the CI gates, and get a pull request merged.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Local development workflow](#local-development-workflow)
3. [Running the checks locally](#running-the-checks-locally)
4. [CI gates — what must pass before merge](#ci-gates)
5. [Commit and PR conventions](#commit-and-pr-conventions)
6. [Branch strategy](#branch-strategy)
7. [Security and authorization rules](#security-and-authorization-rules)
8. [Android cross-compilation](#android-cross-compilation)

---

## Prerequisites

| Tool | Minimum version | Install |
|---|---|---|
| Rust | 1.85 | `rustup` |
| `cargo` | ships with Rust | – |
| `rustfmt` | stable | `rustup component add rustfmt` |
| `clippy` | stable | `rustup component add clippy` |
| Git | any recent | OS package manager |

### Optional (for Android cross-compilation)

| Tool | Notes |
|---|---|
| Android NDK | r25c or later, from [developer.android.com/ndk](https://developer.android.com/ndk/downloads) |
| aarch64 Rust target | `rustup target add aarch64-linux-android` |

---

## Local development workflow

```bash
# 1. Fork and clone
git clone https://github.com/<your-fork>/security-agent.git
cd security-agent

# 2. Create a feature branch (never commit directly to main)
git checkout -b feat/my-improvement

# 3. Make your changes

# 4. Run all local checks (see next section)
make check

# 5. Commit with a descriptive message
git commit -m "feat: describe what changed"

# 6. Push and open a pull request
git push origin feat/my-improvement
```

---

## Running the checks locally

Use the `Makefile` targets for convenience:

```bash
make fmt      # cargo fmt --all --check
make clippy   # cargo clippy --all-targets -- -D warnings
make test     # cargo test --lib
make build    # cargo build --release
make check    # runs all four above in sequence
make status   # ./target/release/security-agent --offline-status
```

Or run `cargo` commands directly:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --lib
cargo build --release
./target/release/security-agent --offline-status
```

All five steps must succeed before opening a pull request.

---

## CI gates

The CI pipeline (`.github/workflows/ci.yml`) runs these jobs on every push and
pull request:

| Job | Description | Blocks merge |
|---|---|---|
| `fmt` | `cargo fmt --all --check` | Yes |
| `clippy` | `cargo clippy --all-targets -- -D warnings` | Yes |
| `test` | `cargo test --lib` on Linux and macOS | Yes |
| `build` | `cargo build --release` + binary smoke test | Yes |
| `android-cross` | Cross-compile for `aarch64-linux-android` | Yes |

> **Note on `cargo test --lib`:** The project includes `candle` / `candle-transformers` 
> as optional future inference back-ends. On aarch64 hosts without the `+fullfp16` 
> CPU feature, the `gemm-f16` crate fails to compile integration tests.  
> Running `--lib` limits compilation to the library crate and its unit tests, 
> which avoids that toolchain incompatibility while still covering all business 
> logic.

---

## Commit and PR conventions

- **Prefix commits** with a [Conventional Commits](https://www.conventionalcommits.org/) type:
  `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `ci:`
- **Keep commits focused** — one logical change per commit.
- **Write descriptive PR descriptions** — include what changed and why.
- **Do not force-push** shared branches.
- **Reference issues** in the PR body when applicable (`Closes #42`).

---

## Branch strategy

| Branch | Purpose |
|---|---|
| `main` | Protected, always-green. Only merged via PR. |
| `feat/*` | New features |
| `fix/*` | Bug fixes |
| `docs/*` | Documentation-only changes |
| `ci/*` | CI and tooling changes |

---

## Security and authorization rules

This project implements an authorization-gated security orchestration model.
Any change that touches `src/policy.rs`, `src/coordinator.rs`, or
`src/governance.rs` must:

1. Maintain or strengthen existing authorization checks — never weaken them.
2. Add or update a test that covers the changed behaviour.
3. Document the policy intent in a code comment.
4. Be reviewed by a security-aware maintainer.

Changes that add new `Technique` variants **must** also update:
- `src/registry.rs` (assign the technique to at least one specialist)
- `src/coordinator.rs` (`default_techniques_for_target` if relevant)
- The `Supported Target Types` table in `README.md`

---

## Android cross-compilation

Full instructions are in [`README.md`](./README.md) and
[`.cargo/config.toml`](./.cargo/config.toml).

Quick summary:

```bash
# Add the target
rustup target add aarch64-linux-android

# Export NDK clang to PATH (adjust path to your NDK install)
export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"

# Build
cargo build --release --target aarch64-linux-android

# Deploy via ADB
adb push target/aarch64-linux-android/release/security-agent /data/local/tmp/
adb shell chmod +x /data/local/tmp/security-agent
adb shell /data/local/tmp/security-agent --offline-status
```

The Termux path (no desktop required):

```bash
# On the Android device, inside Termux:
pkg install rust git
git clone <repo-url> && cd security-agent
cargo run --release
```
