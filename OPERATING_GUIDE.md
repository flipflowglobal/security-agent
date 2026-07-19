# Security-Agent Operating Guide (Beginner Friendly)

This guide explains how to run and use Security-Agent step by step, with simple language and clear checks at each stage.

---

## 1) What this project is

Security-Agent is a Rust application for **authorized defensive security testing**.

It helps you:
- organize security checks,
- run tests in a controlled way,
- and keep an audit record of what was done.

It is designed for legal, approved security work only.

---

## 2) Before you start (important)

Only test systems that you are explicitly allowed to test.

You should have:
- a computer with terminal access (Linux, macOS, or Windows),
- Git installed,
- Rust installed (`cargo` command available),
- internet access for first-time dependency download.

### Check your tools

Run these commands:

```bash
git --version
cargo --version
rustc --version
```

If one command fails, install that tool first before continuing.

---

## 3) Get the project

```bash
git clone <repo-url>
cd security-agent
```

You are now in the project root folder.

---

## 4) Understand the main commands

You will mainly use these commands:

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo build --release
cargo run --release
```

What each one does:
- `cargo fmt --check` → verifies code formatting.
- `cargo clippy -- -D warnings` → lint check, fails on warnings.
- `cargo test` → runs automated tests.
- `cargo build --release` → creates optimized binary.
- `cargo run --release` → builds and starts the demo program.

---

## 5) First-time setup workflow (recommended)

Run the commands in this order:

1. `cargo fmt --check`
2. `cargo clippy -- -D warnings`
3. `cargo test`
4. `cargo build --release`
5. `cargo run --release`

If all commands pass, your environment is working correctly.

---

## 6) Daily operating workflow

Use this routine whenever you work in the repository:

1. Pull latest changes.
2. Make your edits.
3. Run checks:
   - `cargo fmt --check`
   - `cargo clippy -- -D warnings`
   - `cargo test`
4. Build release:
   - `cargo build --release`
5. Run locally if needed:
   - `cargo run --release`

This keeps your changes safe and consistent.

---

## 7) Running on Android (quick path summary)

You have two common options:

### Option A: Run natively in Termux

```bash
pkg install rust
git clone <repo-url>
cd security-agent
cargo run --release
```

### Option B: Cross-compile from desktop

1. Install Android NDK.
2. Add Rust Android targets.
3. Add NDK LLVM tools to `PATH`.
4. Build with:

```bash
cargo build --release --target aarch64-linux-android
```

5. Push with ADB and execute on device.

For full command details, see `/home/runner/work/security-agent/security-agent/README.md`.

---

## 8) Basic usage expectations

Security-Agent follows a controlled model:
- A coordinator plans work.
- Specialists run specific analysis areas.
- Policies control what is allowed.
- Audit records track actions.

As an operator, your responsibility is to:
- define authorized scope,
- avoid out-of-scope targets,
- run with least privilege,
- review findings responsibly.

---

## 9) Safety and authorization checklist

Before any scan or test run, confirm:

- [ ] You have written authorization.
- [ ] Targets are in the approved scope.
- [ ] Testing window/time is approved.
- [ ] High-impact techniques are approved when needed.
- [ ] Credentials are short-lived and minimal.
- [ ] You are not using shared long-lived secrets.

If any item is missing, stop and resolve it first.

---

## 10) Troubleshooting

### `cargo` command not found
- Rust is not installed or not in your shell path.
- Install Rust and restart your terminal.

### Build fails on first run
- Dependencies may still be downloading.
- Re-run the command and check network access.

### `cargo clippy -- -D warnings` fails
- There is at least one lint warning.
- Fix warnings before continuing.

### Tests fail
- Run `cargo test` again and read the first failing test.
- Confirm your environment matches project requirements.

### Release build fails
- Run `cargo build --release` alone and review full error output.

---

## 11) File map for beginners

Key files in this repository:
- `/home/runner/work/security-agent/security-agent/README.md` → high-level project overview.
- `/home/runner/work/security-agent/security-agent/src/main.rs` → runnable demo binary entry point.
- `/home/runner/work/security-agent/security-agent/src/lib.rs` → core library logic and tests.
- `/home/runner/work/security-agent/security-agent/Cargo.toml` → Rust package metadata and dependencies.

---

## 12) Good operating habits

- Work in small changes.
- Run validation after every meaningful edit.
- Keep scope and authorization explicit.
- Treat findings as sensitive internal data.
- Document what you ran and why.

---

## 13) Quick command copy block

```bash
git clone <repo-url>
cd security-agent
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo build --release
cargo run --release
```

If this block succeeds, you are fully operational.
