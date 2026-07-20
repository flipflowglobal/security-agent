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
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
./target/release/security-agent --offline-status
```

What each one does:
- `cargo fmt --check` → verifies code formatting.
- `cargo clippy --all-targets -- -D warnings` → lint check, fails on warnings.
- `cargo test` → runs automated tests.
- `cargo build --release` → creates optimized binary.
- `./target/release/security-agent --offline-status` → reports actual local status.

---

## 5) First-time setup workflow (recommended)

Run the commands in this order:

1. `cargo fmt --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test`
4. `cargo build --release`
5. `./target/release/security-agent --offline-status`

If all commands pass, your environment is working correctly.

---

## 6) Daily operating workflow

Use this routine whenever you work in the repository:

1. Pull latest changes.
2. Make your edits.
3. Run checks:
   - `cargo fmt --check`
   - `cargo clippy --all-targets -- -D warnings`
   - `cargo test`
4. Build release:
   - `cargo build --release`
5. Inspect local status:
   - `./target/release/security-agent --offline-status`

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

## 8) Local runtime commands

Run these from the repository root after `cargo build --release`:

```bash
./target/release/security-agent
./target/release/security-agent --offline-status
./target/release/security-agent --list-skills
./target/release/security-agent --show-skill security-agent
./target/release/security-agent --list-tools
./target/release/security-agent --run-tool autopsy <local-path>
./target/release/security-agent --run-tool autopsy <local-path> --output <report-path>.txt
./target/release/security-agent --run-tool volatility <local-memory-image>
./target/release/security-agent --run-tool volatility <local-memory-image> --output <report-path>.txt
./target/release/security-agent --run-tool wireshark <local-capture.pcap>
./target/release/security-agent --run-tool wireshark <local-capture.pcap> --output <report-path>.txt
```

- No argument and `--offline-status` report the same local runtime state.
- `--list-skills` lists skills compiled into the binary.
- `--show-skill` prints the named embedded skill.
- `--list-tools` distinguishes built-in substitutes, installed executables, and
  catalog entries that are not installed.
- `--run-tool autopsy` inventories regular files and computes SHA-256 digests.
- `--run-tool volatility` analyzes a local memory image or binary for entropy,
  embedded executable/archive signatures, and printable strings.
- `--run-tool wireshark` parses a local classic PCAP and reports capture,
  link-layer, network-layer, and transport-layer statistics.
- `--output` writes the same human-readable report to a `.txt` file.

To install the binary into Cargo's local binary directory:

```bash
cargo install --path . --locked
```

After installation, replace `./target/release/security-agent` with
`security-agent`.

---

## 9) Basic usage expectations

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

## 10) Safety and authorization checklist

Before any scan or test run, confirm:

- [ ] You have written authorization.
- [ ] Targets are in the approved scope.
- [ ] Testing window/time is approved.
- [ ] High-impact techniques are approved when needed.
- [ ] Credentials are short-lived and minimal.
- [ ] You are not using shared long-lived secrets.

If any item is missing, stop and resolve it first.

---

## 11) Troubleshooting

### `cargo` command not found
- Rust is not installed or not in your shell path.
- Install Rust and restart your terminal.

### Build fails on first run
- Dependencies may still be downloading.
- Re-run the command and check network access.

### `cargo clippy --all-targets -- -D warnings` fails
- There is at least one lint warning.
- Fix warnings before continuing.

### Tests fail
- Run `cargo test` again and read the first failing test.
- Confirm your environment matches project requirements.

### Release build fails
- Run `cargo build --release` alone and review full error output.

---

## 12) File map for beginners

Key files in this repository:
- `/home/runner/work/security-agent/security-agent/README.md` → high-level project overview.
- `/home/runner/work/security-agent/security-agent/src/main.rs` → offline local runtime entry point.
- `/home/runner/work/security-agent/security-agent/src/lib.rs` → core library logic and tests.
- `/home/runner/work/security-agent/security-agent/Cargo.toml` → Rust package metadata and dependencies.

---

## 13) Good operating habits

- Work in small changes.
- Run validation after every meaningful edit.
- Keep scope and authorization explicit.
- Treat findings as sensitive internal data.
- Document what you ran and why.

---

## 14) Quick command copy block

```bash
git clone <repo-url>
cd security-agent
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
./target/release/security-agent --offline-status
```

If this block succeeds, you are fully operational.
