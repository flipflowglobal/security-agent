# Security-Agent Operating Guide (Beginner Friendly)

This guide explains how to run and use Security-Agent step by step, with simple language and clear checks at each stage.

---

## 1) What this project is

Security-Agent is a Rust application for **authorized defensive and offensive
security testing** — both hardening/detection work and hands-on penetration
testing against systems you (or your client) own or have explicit permission
to test.

It helps you:
- organize security checks, both defensive and offensive,
- run tests in a controlled way — live/active (offensive) tools require an
  explicit online opt-in on top of authorization (see `--allow-network`),
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
cargo test --lib
cargo build --release
./target/release/security-agent --offline-status
```

Tip: run `make check` to execute all four validation steps in one command.

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
3. `cargo test --lib`
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
   - `cargo test --lib`
4. Build release:
   - `cargo build --release`
5. Inspect local status:
   - `./target/release/security-agent --offline-status`

This keeps your changes safe and consistent.

---

## 7) Running on Android

### Easiest: the guided one-command installer ⭐

From the repo root, run:

```bash
make android-install
# or, directly:  ./scripts/android-install.sh
```

It figures out the rest for you:

- **On a phone (Termux):** installs Rust if needed, builds, and puts
  `security-agent` on your `PATH`.
- **On a desktop with a device attached (USB debugging on):** detects the
  device's CPU ABI, adds the matching Rust target, locates the Android NDK
  (or uses `cargo-ndk` if installed), cross-compiles, pushes over ADB, and
  runs an on-device smoke test.

Preview exactly what it will do without changing anything:

```bash
./scripts/android-install.sh --check
```

Useful flags: `--method termux|adb`, `--device <serial>`, `--dest <path>`,
`--abi <arm64-v8a|armeabi-v7a|x86_64|x86>`, `--yes` (non-interactive),
`--check` (dry run). Run `./scripts/android-install.sh --help` for all of them.

### Manual paths (if you prefer)

**Run natively in Termux:**

```bash
pkg install rust
git clone <repo-url>
cd security-agent
cargo run --release
```

**Cross-compile from a desktop:** install the Android NDK, add the Rust
target(s), put the NDK LLVM tools on `PATH`, then
`cargo build --release --target aarch64-linux-android` and push with ADB.
See [`.cargo/config.toml`](./.cargo/config.toml) for the exact prerequisites
and linker settings, or [`README.md`](./README.md) for full details.

---

## 8) Local runtime commands

Run these from the repository root after `cargo build --release`:

```bash
./target/release/security-agent
./target/release/security-agent --offline-status
./target/release/security-agent --about
./target/release/security-agent --list-skills
./target/release/security-agent --show-skill security-agent
./target/release/security-agent --show-skill nmap
./target/release/security-agent --list-tools
./target/release/security-agent --run-tool autopsy <local-path>
./target/release/security-agent --run-tool autopsy <local-path> --output <report-path>.txt
./target/release/security-agent --run-tool volatility <local-memory-image>
./target/release/security-agent --run-tool volatility <local-memory-image> --output <report-path>.txt
./target/release/security-agent --run-tool wireshark <local-capture.pcap>
./target/release/security-agent --run-tool wireshark <local-capture.pcap> --output <report-path>.txt
./target/release/security-agent --run-tool binwalk <local-blob>
./target/release/security-agent --run-tool foremost <local-blob>
./target/release/security-agent --run-tool bulk_extractor <local-blob>
./target/release/security-agent --run-tool hashdeep <local-path>
./target/release/security-agent --run-external-tool semgrep --version
./target/release/security-agent --run-external-tool --allow-network nmap -sV <in-scope-host>
./target/release/security-agent --run-external-tool --allow-network masscan -p80 <in-scope-range>
./target/release/security-agent --plan-scan <engagement-config-path>
./target/release/security-agent --plan-scan <engagement-config-path> --audit-log <log-path>.jsonl
./target/release/security-agent --plan-scan <engagement-config-path> --findings-log <findings-log-path>.jsonl --execute <args-passed-to-each-tool>
./target/release/security-agent --plan-scan <engagement-config-path> --execute <args-passed-to-each-tool>
./target/release/security-agent --plan-scan <engagement-config-path> --cognitive-review
./target/release/security-agent --plan-scan <engagement-config-path> --cognitive-review --memory <findings-log-path>.jsonl
./target/release/security-agent --record-findings <destination-log>.jsonl <source-log>.jsonl
./target/release/security-agent --view-audit <log-path>.jsonl
./target/release/security-agent --schedule-retest <findings-log-path>.jsonl
./target/release/security-agent --llm-generate <prompt words...>
./target/release/security-agent --llm-perplexity <text words...>
./target/release/security-agent --ask <plain-English instruction...>
./target/release/security-agent --allow-network --ollama-status
./target/release/security-agent --allow-network --ollama-generate <model> <prompt words...>
./target/release/security-agent --allow-network --ollama-chat <model> <message words...>
./target/release/security-agent --tui
```

- No argument and `--offline-status` report the same local runtime state,
  including a `capability_coverage=ok` (or `error: <reason>`) health check.
- `--about` (alias `--version`) prints the package version, mission
  statement, and the four roadmap phases.
- `--list-skills` lists skills compiled into the binary: one general skill
  plus one per cataloged tool (90 total).
- `--show-skill` prints the named embedded skill (e.g. `security-agent`, or
  any cataloged tool name such as `nmap`).
- `--list-tools` distinguishes built-in substitutes, installed executables, and
  catalog entries that are not installed, and shows each installed tool's
  integrity state (`verified`/`mismatch`/`unpinned`) against the bundled
  integrity manifest.
- `--run-tool autopsy` inventories regular files and computes SHA-256 digests.
- `--run-tool volatility` analyzes a local memory image or binary for entropy,
  embedded executable/archive signatures, and printable strings.
- `--run-tool wireshark` parses a local classic PCAP and reports capture,
  link-layer, network-layer, and transport-layer statistics.
- `--run-tool binwalk` maps embedded magic signatures and high-entropy
  (likely compressed/encrypted) regions in a local firmware image or blob.
- `--run-tool foremost` carves recoverable embedded files by header, bounding
  their length with a footer where the format defines one.
- `--run-tool bulk_extractor` extracts indicators of compromise (emails,
  URLs, IPv4 addresses) from a local blob's printable content.
- `--run-tool hashdeep` recursively hashes a local directory tree with
  SHA-256 and CRC-32 and reports files that share a digest. These four
  (`src/local_analyzers.rs`) are offline, defensive, local-file analyzers;
  offensive and live-network catalog tools are not reimplemented in-house.
- `--output` writes the same human-readable report to a `.txt` file.
- **Offline by default; online is opt-in.** The runtime does no live-target
  or network activity unless you pass the explicit `--allow-network` flag for
  that invocation (`--offline-status` shows `default_network_mode=offline`).
  This keeps going online a deliberate, per-invocation, auditable choice.
- `--run-external-tool [--allow-network] <name> <args>` runs a real, locally
  installed cataloged tool directly. Static-local-analysis tools run in the
  default offline mode; live `ActiveNetwork`/`ActiveExploitation` tools (nmap,
  masscan, sqlmap, hydra, …) require `--allow-network` placed immediately
  after `--run-external-tool`, otherwise they are refused with a message
  pointing to the opt-in. Only the real installed binary is ever spawned —
  the agent never reimplements a tool's offensive behavior. Aggressive
  network-scan flags exceeding the declared intensity print a non-blocking
  advisory to stderr. See `README.md`'s "Offline by default, online by
  explicit opt-in" section for the full trust model.
- `--plan-scan <config>` loads an engagement configuration file (see
  section 8a below), authorizes it, and prints the resulting scan plan.
- `--plan-scan <config> --audit-log <path>` additionally appends the
  planning call's audit records to `<path>` as an append-only JSON Lines
  file.
- `--plan-scan <config> --execute <args>` additionally runs every approved,
  locally installed tool in the plan (passing `<args>` to each), prints
  each outcome, and prints a findings summary (severity counts, top
  findings by risk score, and attack-path graph node/edge counts) ingested
  from each tool's output. In the default offline mode only local-analysis
  tools run; add `--allow-network` (before `--execute`) to also run the live
  `ActiveNetwork`/`ActiveExploitation` tools the engagement authorizes —
  target scope, technique allow-list, deny-lists, approval gates, and the
  time window are still enforced.
- `--plan-scan <config> --findings-log <path> --execute <args>` additionally
  appends every finding ingested from `--execute`'s tool output to `<path>`
  as an append-only JSON Lines file; a no-op without `--execute`.
- `--plan-scan <config> --cognitive-review` prints the advisory cognitive
  assessment and the deep cognitive deliberation (train of thought,
  Bayesian beliefs, adversary model, attention, metacognition). Add
  `--memory <findings-log>` to make it history-informed: it folds a prior
  findings log (the same format `--findings-log` writes) into cognitive
  memory so hypotheses, beliefs, and adversary payoffs sharpen across
  engagements. A missing log is treated as empty history.
- `--record-findings <destination-log> <source-log>` appends findings from
  one findings log onto another (merging/curating logs). It never plans,
  authorizes, or executes.
- `--llm-generate <prompt>` continues the prompt with the built-in small
  neural language model (`src/language_model.rs`), a from-scratch model
  trained deterministically on a bundled security corpus — no network, no
  weights on disk. `--llm-perplexity <text>` scores how in-domain the text
  reads (lower is more expected). Advisory/inspection only.
- `--allow-network --ollama-status` probes the locally-running Ollama service
  (`127.0.0.1:11434`) and lists its version and installed models.
  `--allow-network --ollama-generate <model> <prompt>` continues a prompt
  with a named Ollama model, and `--allow-network --ollama-chat <model>
  [--system <text>] <message>` runs a single-turn chat. These open a local
  socket, so they require the explicit `--allow-network` opt-in. Ollama is
  *not* wired into `--model`: its API exposes no per-token probabilities, so
  there is no honest perplexity, and any failure is a hard error rather than
  silent empty output.
- `--ask <plain-English instruction>` interprets a natural-language
  instruction against the agent's own capabilities (`src/nlu.rs`), prints the
  understood intent, a confidence, and a reply, then carries out the
  read-only action (report status, list/explain tools or skills, generate
  text, or score text for anomaly). Off-topic requests decline as
  `out-of-scope`. Intents that require an engagement, a persisted log, or
  authorization (planning a scan, scheduling a retest, viewing an audit log)
  are explained — it tells you the exact command — but never executed through
  `--ask`, so plain English cannot widen the agent's authority.
- `--tui` opens an interactive menu- and chat-bar-driven REPL over every
  command above (see `README.md`'s "Interactive terminal UI" section). Every
  menu choice calls the identical command function the plain CLI dispatches
  to, so behavior is identical either way; typing anything else at the
  prompt routes through the same `--ask` router. Menu option `0`/`help`
  prints the full capability summary. Exits cleanly at end-of-input.
- `--view-audit <path>` is a read-only view: it loads a persisted audit
  log and prints its records (operating under the least-privilege `Viewer`
  role). It never plans, authorizes, executes, or writes.
- `--schedule-retest <findings-log-path>` reads a findings log written by
  `--findings-log` and prints a retest schedule (soonest first) derived
  from each finding's risk score.

To install the binary onto your `PATH`:

```bash
make install                 # -> ~/.local/bin/security-agent
make install PREFIX=/usr/local   # -> /usr/local/bin (may need sudo)
make uninstall               # remove it again
```

`make install` builds the release binary and copies it to `$PREFIX/bin`
(default `~/.local/bin`); set `DESTDIR` for a staged/packaging install. Or use
Cargo's own directory:

```bash
cargo install --path . --locked
```

After installation, replace `./target/release/security-agent` with
`security-agent`. Confirm what you installed with `security-agent --build-info`,
which prints the exact commit, build date, target, and compiler the binary was
built from (add `--json` for a machine-readable line).

To build a distributable, checksummed release package instead (for handing
the binary to someone else, or archiving a release), run:

```bash
./scripts/deploy.sh
# or: make deploy
```

This runs the full quality gate, builds the release binary, and packages it
with `README.md`/`LICENSE` into `dist/security-agent-<version>-<target-triple>.tar.gz`
plus a `.sha256` checksum file. Add `--target <triple>` to cross-compile (e.g.
`--target aarch64-linux-android`), or `--skip-checks` to skip straight to
build + package when the code has already been verified. See `README.md`'s
"Release deployment" section for the full flag list.

Pushing a version tag (`git tag v0.1.0 && git push origin v0.1.0`) runs the
**Release** CI workflow, which builds these same checksummed archives for
Linux, macOS, and Android and attaches them to the GitHub Release
automatically. Builds honor `SOURCE_DATE_EPOCH` (pinned to the tagged commit),
so the packaged binary is reproducible.

---

## 8a) Writing an engagement configuration file

`--plan-scan` reads a simple, hand-written `key=value` text file — no JSON
or YAML needed. Comments start with `#`; one or more `[target]` sections
list the targets in scope:

```text
engagement_id=eng-2026-001
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=1750000000
time_window_end=1760000000
in_scope_targets=api-staging,web-staging
allowed_techniques=PassiveRecon,ConfigurationAudit,ApiSecurity
deny_list_targets=prod-ledger
max_intensity=Standard
high_impact_approved=false
penetrative_testing_approved=true

[target]
id=api-staging
target_type=Api
criticality=5
network_address=192.168.1.10

[target]
id=web-staging
target_type=WebApp
criticality=3
```

- `network_address` is optional (`web-staging` above omits it): a
  resolvable IP or hostname for the target. When set, real execution of a
  network tool (nmap, masscan) through `--plan-scan ... --execute` binds
  to this address automatically — it is prepended as the tool's first
  argument, ahead of whatever `--execute` arguments were given. Static
  local-analysis tools (semgrep, jadx, ...) are never affected. Omitting
  `network_address` leaves the target label-only, exactly as before this
  field existed.
- `time_window_start`/`time_window_end` are Unix epoch seconds; the plan is
  only authorized while the current time falls inside that window.
- `authorized_by_role` and `target_type` must match one of the values Rust
  prints for `Role`/`TargetType` (e.g. `SecurityAdmin`, `Auditor`, `Api`,
  `WebApp`, `MobileApp` — see `src/model.rs`/`src/governance.rs` for the
  full lists).
- `in_scope_targets`, `allowed_techniques`, and `deny_list_targets` are
  comma-separated; leave the value empty for an empty list.
- `--plan-scan` refuses to produce a plan if authorization fails (expired
  window, out-of-scope or denied target, disallowed technique, intensity
  above the cap, or a high-impact/penetrative technique missing explicit
  approval) — it prints the specific reason and exits non-zero rather than
  silently narrowing scope.

---

## 9) Basic usage expectations

Security-Agent follows a controlled model:
- A coordinator plans work (`--plan-scan <config>`).
- Specialists run specific analysis areas (see the "Tasks" section of the
  printed plan).
- Policies control what is allowed (authorization failures are printed and
  exit non-zero, never silently narrowed).
- Audit records track actions (`--plan-scan <config> --audit-log <path>`
  persists them to an append-only JSON Lines file).

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
- [`README.md`](./README.md) → high-level project overview.
- [`src/main.rs`](./src/main.rs) → offline local runtime entry point.
- [`src/lib.rs`](./src/lib.rs) → core library logic and tests.
- [`Cargo.toml`](./Cargo.toml) → Rust package metadata and dependencies.

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
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --lib
cargo build --release
./target/release/security-agent --offline-status
```

If this block succeeds, you are fully operational.
