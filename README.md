# Security-Agent

[![CI](https://github.com/flipflowglobal/security-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/flipflowglobal/security-agent/actions/workflows/ci.yml)

Rust-first hybrid defensive and offensive security orchestration agent for authorized vulnerability and penetration testing across web, API, mobile (Android), blockchain, cloud, and infrastructure targets.

## Mission

Defensive and offensive security orchestration agent for authorized vulnerability and penetration testing across platform applications, tools, APIs, and infrastructure.

## Operating Guide

For a beginner-friendly, step-by-step operations manual, read:

- [`OPERATING_GUIDE.md`](./OPERATING_GUIDE.md)
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — developer workflow and CI gates
- [`CHANGELOG.md`](./CHANGELOG.md) — version history

---

## Quick Start

### Host (Linux / macOS / Windows)

```bash
# Clone and build
git clone <repo-url>
cd security-agent

# Validate and build (or just `make check` for all four steps)
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --lib
cargo build --release

# Inspect actual local status
./target/release/security-agent --offline-status
```

### Android Device / Termux (native, no cross-compilation needed)

```bash
# Install Rust inside Termux
pkg install rust

# Clone and run directly on-device
git clone <repo-url> && cd security-agent
cargo run --release
```

### Android — Cross-compile from a desktop machine

**Prerequisites**

1. Install the [Android NDK](https://developer.android.com/ndk/downloads) (r25c or later).
2. Add Rust Android targets:

```bash
rustup target add aarch64-linux-android   # arm64-v8a  (modern phones, recommended)
rustup target add armv7-linux-androideabi # armeabi-v7a (older 32-bit devices)
rustup target add x86_64-linux-android    # x86_64 emulator
```

3. Add NDK clang wrappers to `PATH` (or update `.cargo/config.toml` with absolute paths):

```bash
export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
```

**Build**

```bash
cargo build --release --target aarch64-linux-android
```

**Deploy via ADB**

```bash
adb push target/aarch64-linux-android/release/security-agent /data/local/tmp/
adb shell chmod +x /data/local/tmp/security-agent
adb shell /data/local/tmp/security-agent
```

The resulting binary is fully self-contained — no JVM, no framework, no internet access required at runtime.

---

## Architecture

For a full file-system → architecture map (layer diagram, per-module
directory, data-flow, and the neural-LM integration map), see
[`ARCHITECTURE.md`](./ARCHITECTURE.md).

Federated model (not an unrestricted super-agent):

- **Coordinator** — plans scoped runs, maps targets to specialists, writes immutable audit records, emits execution plans.
- **Specialists** — SAST, DAST, API security, dependency risk, cloud/IaC, container/K8s, secrets, malware, compliance, **Android/mobile**, **blockchain/smart-contract**.
- **Capability Registry** — maps specialists to approved tools, supported target types, and allowed techniques.
- **Policy Engine** — time-bounded engagement profiles, technique allow-lists, deny-list targets, intensity caps, high-impact approval gate.
- **Audit Ledger** — append-only record of every authorized action; filterable by role and action type.
- **Attack-Path Graph** — builds threat model (nodes + edges) from a set of findings.
- **Retest Scheduler** — drift-and-risk-based retest intervals derived from finding risk scores.
- **Cognitive Layer** (`src/cognition.rs`) — advisory reasoning over an already-authorized plan: ranks tasks by expected risk yield, proposes ranked hypotheses about which technique is likely to find what per target type, and reflects on the plan to flag coverage gaps.
- **Advanced Cognitive Architecture** (`src/cognitive_engine.rs`) — models the reasoning *process* itself as cooperating faculties: an explicit, provenance-linked **train of thought** (observe → hypothesize → imagine → decide → reflect), **Bayesian belief revision** with Shannon-entropy uncertainty, **adversary theory-of-mind** predicting an attacker's ranked next moves, salience-weighted **attention allocation**, **metacognition** that self-assesses confidence, names knowledge gaps, and decides when to escalate to a human, **confidence calibration** scoring the agent's priors against realized findings (Brier score / expected calibration error / over- vs under-confidence) and feeding that correction back into live hypothesis confidence via leave-one-out recalibration, and **compromise propagation** that spreads lateral-movement risk across the attack graph. Exposed via `--plan-scan <config> --cognitive-review`.
- **Cognitive Memory** (`src/memory_store.rs`) — folds the single append-only findings log (`src/findings_log.rs`) into cognitive memory, so cognition **learns across engagements** instead of starting blank each run. A scan's findings log (written by `--findings-log`) loads directly as `--cognitive-review --memory <log>` input — one format across the whole loop — so hypothesis confidence and attention rise, beliefs get Bayesian-updated by real evidence, and metacognition stops flagging a well-evidenced target as a knowledge gap.

Both cognitive layers are **purely advisory** — they reason over plans the `PolicyEngine`/`Coordinator` have already authorized, and never grant, restrict, execute, or bypass any authorization decision.

---

## Supported Target Types

| Target Type | Use Case Pack | Default Techniques |
|---|---|---|
| `WebApp` | webapp-core-pack | PassiveRecon, ConfigurationAudit, DAST |
| `Api` | api-core-pack | PassiveRecon, ConfigurationAudit, ApiSecurity |
| `MobileBackend` | mobile-backend-pack *(deprecated → api-core-pack)* | ConfigurationAudit, ApiSecurity, AndroidStaticAnalysis |
| `MobileApp` | **android-mobile-pack** | AndroidStaticAnalysis, MobileRuntime, SecretScan, DependencyAudit |
| `Cloud` | cloud-posture-pack | ConfigurationAudit, CloudPosture |
| `Blockchain` | smart-contract-pack | SAST, ThreatModeling, AttackPathAnalysis |
| `Container` | cloud-posture-pack | ConfigurationAudit, ContainerPosture |
| `Infrastructure` | cloud-posture-pack | ConfigurationAudit, CloudPosture |
| `SourceCode` | webapp-core-pack | SAST, SecretScan |
| `DependencyManifest` | webapp-core-pack | DependencyAudit |

---

## Android Mobile Tool Pack

The `MobileAndroid` specialist uses a dedicated tool set for APK/DEX analysis and runtime instrumentation:

`apktool`, `jadx`, `mobsf`, `androguard`, `frida`, `objection`, `apkleaks`, `apksigner`, `dex2jar`, `drozer`, `qark`, `mariana-trench`, `trueseeing`, `nuclei`, `semgrep`

---

## Key Controls

**Authorization and scope:**
- Time-bounded engagement profiles
- Explicit in-scope target allow-list (target IDs must be pre-authorized)
- Technique allow-list per engagement
- Explicit deny-list targets
- High-impact approval gate (criticality ≥ 8 + Standard intensity)
- Explicit penetrative-technique approval gate (DAST/API/mobile runtime/exploit validation)

**Least-privilege defaults (enforced in `AuthorizationOutcome`):**
- Ephemeral runner required
- Short-lived credentials required
- Shared long-lived credentials forbidden
- Per-tool network egress policy metadata

---

## Workflow Stages

1. Discovery and inventory
2. Passive recon and configuration checks
3. Source / dependency / static analysis
4. Runtime app / API scanning
5. Cloud / container / infrastructure posture checks
6. Correlation and risk scoring

---

## Modules

| Module | Responsibility |
|---|---|
| `src/mission.rs` | Mission statement constant |
| `src/model.rs` | Core enums and structs (targets, techniques, engagement profile) |
| `src/registry.rs` | Capability registry and toolchain pack registry |
| `src/policy.rs` | Authorization and least-privilege policy engine |
| `src/workflow.rs` | Ordered workflow stage model |
| `src/coordinator.rs` | Orchestration, scoped task planning, audit integration |
| `src/engagement_config.rs` | Zero-dependency parser for `--plan-scan` engagement config files |
| `src/execution.rs` | Bounded real execution of `StaticLocalAnalysis` cataloged tools, plus `execute_plan` |
| `src/audit_log.rs` | Append-only on-disk persistence for the audit ledger |
| `src/findings.rs` | Unified finding model and normalized risk scorer |
| `src/ingest.rs` | Turns real tool output (semgrep, SARIF, JSONL) into scored `Finding`s |
| `src/findings_log.rs` | Append-only on-disk findings log — the single findings format, reused by cognition |
| `src/json.rs` | In-house JSON parser/writer (keeps the crate free of external runtime crates) |
| `src/governance.rs` | Append-only audit ledger with role/action filtering |
| `src/intensity_guard.rs` | Non-blocking intensity advisories for network-tool execution |
| `src/integrity.rs` | Offline tool-integrity verification against a bundled manifest |
| `src/advanced.rs` | Attack-path graph builder and retest scheduler |
| `src/cognition.rs` | Advisory reasoning layer: risk-yield task prioritization, per-target-type hypothesis generation, and reflective plan critique |
| `src/cognitive_engine.rs` | Advanced cognitive architecture: chained reasoning, Bayesian belief revision, adversary theory-of-mind, attention allocation, metacognition, calibration, and compromise propagation |
| `src/calibration.rs` | Confidence-calibration tracking: Brier score, reliability bins, expected calibration error, over/under-confidence tendency, and histogram recalibration |
| `src/belief_propagation.rs` | Noisy-OR compromise-risk propagation across the attack graph (lateral movement) |
| `src/language_model.rs` | Small from-scratch **self-attentive, vector-quantized temporal-frequency** neural language model (embed → self-attention → DCT → residual VQ codebooks → softmax), self-trained on a bundled security corpus; text generation and perplexity scoring |
| `src/builtin_tools.rs` | Offline built-in substitutes (autopsy, volatility) plus the in-house SHA-256; real local-file analysis, no network |
| `src/local_analyzers.rs` | Offline forensic substitutes — binwalk (signature/entropy), foremost (carving), bulk_extractor (IOC features), hashdeep (recursive multi-hash + dedup) |
| `src/network_policy.rs` | `NetworkMode` egress governance: offline by default, live network/active tools only under the explicit per-invocation `--allow-network` opt-in |
| `src/anomaly.rs` | Language-model perplexity as an anomaly lens: flags out-of-domain finding text in the cognitive review |
| `src/nlu.rs` | Grounded plain-English intent router behind `--ask`: lexical + semantic mapping of instructions to real capabilities |
| `src/memory_store.rs` | Folds the append-only findings log into cognitive memory, so cognition learns across engagements from one shared format |
| `src/compat.rs` | Integration adapter contracts and wire-format envelope (audit + finding records) |
| `src/roadmap.rs` | Phased rollout model (surfaced by `--about`) |
| `src/main.rs` | Offline local runtime entry point (also cross-compiles for Android); includes the `--tui` interactive terminal UI, built entirely on the same command functions the plain CLI dispatches to |

---

## Roadmap

- **Phase 1** — Coordinator, core scanners, and reporting *(complete)*
- **Phase 2** — Cloud, container, and supply-chain specialists *(complete)*
- **Phase 3** — Attack-path analytics and autonomous retesting *(complete)*
- **Phase 4** — Organization-wide policy automation and continuous validation

---

## Development

For a full contributor guide see [`CONTRIBUTING.md`](./CONTRIBUTING.md).

### Quick reference

```bash
make fmt      # cargo fmt --all --check
make clippy   # cargo clippy --all-targets -- -D warnings
make test     # cargo test --lib
make build    # cargo build --release
make check    # runs all four above in sequence
```

Or run `cargo` directly:

```bash
cargo fmt --all --check                    # verify formatting
cargo clippy --all-targets -- -D warnings  # lint all targets
cargo test --lib                           # run library unit tests
cargo build --release                      # optimized host binary
```

### Release deployment

`scripts/deploy.sh` (also `make deploy`) builds, verifies, and packages the
CLI binary for distribution. There is no web service or network call
involved — "deploying" this agent means producing a trustworthy, versioned
release artifact, since it is a local terminal tool:

```bash
./scripts/deploy.sh                       # full gate + build + package
./scripts/deploy.sh --target aarch64-linux-android   # cross-compiled package
./scripts/deploy.sh --skip-checks         # fast repackage (build + package only)
make deploy                               # same, via the Makefile
make deploy DEPLOY_FLAGS="--skip-checks"  # pass flags through
```

It runs CI's required formatting and lint gate exactly (`cargo fmt --all
--check`, `cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W
clippy::nursery`), plus the full `cargo test` — a deliberate superset of
CI's `cargo test --lib`, since a release artifact should be verified by at
least as much as CI requires, and the CLI integration suite in
`tests/cli.rs` exercises the actual compiled binary the way the packaged
archive will be used. It then builds an optimized `--release` binary
(optionally cross-compiled via `--target`), and packages it — plus
`README.md` and `LICENSE` — into a checksummed
`dist/security-agent-<version>-<target-triple>.tar.gz` with a matching
`.sha256` file (recording the archive's repo-root-relative path, so
`sha256sum -c dist/<name>.sha256` verifies correctly from the repo root).
Colors are automatically disabled when not attached to a terminal (or with
`--no-color` / `NO_COLOR`), so CI logs stay clean. The script always
operates from the repo root regardless of the caller's working directory.
Pure POSIX-ish bash — no new dependency, consistent with the rest of the
crate.

The console styling deliberately follows the same conventions used across
this org's other launch/verify scripts: a plain colored title (no boxed
banner), light `━━ … ━━` section rules per step, a three-state ✓ (green,
pass) / ✗ (red, fail) / ○ (yellow, skipped) glyph system, and a flat
`====...`-divided completion block at the end — the same shape those
scripts' own deploy/verify output ends on.

### Optional inference feature

The `candle` / `candle-transformers` / `tokenizers` crates are optional
dependencies grouped under the `inference` feature flag.  They are not used
by the core orchestration logic and are disabled by default:

```bash
# Build with the inference back-end enabled
cargo build --release --features inference
```

### Offline local assets

All skills are compiled into the Rust binary and the tool catalog is generated
from the built-in registry. These commands do not use the network or read an
external skill source:

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
./target/release/security-agent --run-tool binwalk <local-blob>
./target/release/security-agent --run-tool foremost <local-blob>
./target/release/security-agent --run-tool bulk_extractor <local-blob>
./target/release/security-agent --run-tool hashdeep <local-path>
./target/release/security-agent --llm-generate <prompt words...>
./target/release/security-agent --llm-perplexity <text words...>
./target/release/security-agent --ask <plain-English instruction...>
./target/release/security-agent --tui
```

`--about` (alias `--version`) prints the package version, mission statement,
and the four roadmap phases.

`--ask` takes a plain-English instruction and routes it to the matching
capability (see [Plain-English instructions](#plain-english-instructions--ask)).

`--tui` launches an interactive terminal UI over every command above (see
[Interactive terminal UI](#interactive-terminal-ui---tui)).

### Built-in small language model

`src/language_model.rs` is a small, from-scratch **neural** language model
with a vector-quantized, temporal-frequency architecture, trained
deterministically on a security-domain corpus compiled into the binary. The
prediction path is:

1. **Embed** the recent window of tokens into learned vectors — a short
   multi-channel time signal.
2. **Self-attend**: a single-head scaled dot-product attention layer lets
   every position in the window mix in every other position's value vector,
   weighted by a learned, content-dependent query/key match (no causal
   mask — every position is already-known context for the token being
   predicted *after* the window). The attended output is added residually
   to the raw embeddings, so *what* each position ends up representing can
   depend on what's actually in the window, not just where it sits.
3. **Temporal → frequency**: a Discrete Cosine Transform (DCT-II) along the
   time axis of the attended representation, so the model reasons about
   *how* the context changes across the window (its spectral content).
4. **Residually vector-quantize** the spectral features against a *stack* of
   learned codebooks (VQ-VAE style: nearest-code lookup, straight-through
   estimator, commitment penalty). Each stage quantizes what the previous
   stage could not represent — the final code is the sum of the per-stage
   codes (`q = q1 + q2`), a **residual path around the quantizer** that
   halves the reconstruction error a single codebook leaves behind while
   keeping the discrete bottleneck.
5. **Predict** the next token from the quantized code through a tanh hidden
   layer and a softmax over the vocabulary.
6. **Sample**: decoding draws from that distribution with temperature and
   top-`k` filtering (rather than always taking the most probable token),
   seeded deterministically from the prompt so the same prompt still always
   produces the same continuation.

The self-attention layer, DCT, residual codebook search, and forward/backward
passes are all hand-rolled: **no external crates, no network, no weights on
disk**. The
model trains itself at startup (well under a second) and ships inside the
offline binary. Being tiny — and quantized through a discrete bottleneck —
its text is modest; it learns the domain vocabulary and local phrasing
rather than long-range coherence.

```bash
# Continuation of a prompt (temperature/top-k sampling, deterministic per prompt).
./target/release/security-agent --llm-generate the coordinator plans an

# Perplexity: how surprising text is to the model (lower = more in-domain).
./target/release/security-agent --llm-perplexity the policy engine denies scope
```

The `LanguageModel` trait is the seam where a larger model could plug in
later; this is distinct from the still-optional `inference` feature flag
(below), which is reserved for a heavier candle-based back-end and is not
used by the core.

The same perplexity signal is looped back into the cognitive layer as an
**anomaly lens**: during a `--plan-scan ... --cognitive-review --memory
<log>` run, every prior finding's text is scored against the model, and text
that does not read like ordinary security-domain English (high perplexity,
or unscorable) is flagged as out-of-domain — a cheap, fully-local check for
encoded payloads, injected markup, or noise stuffed into third-party tool
output. See `src/anomaly.rs`.

### Plain-English instructions (`--ask`)

`--ask` lets the agent understand a plain-English instruction and *carry it
out*, entirely offline. A grounded intent router (`src/nlu.rs`) maps the
instruction to one of the agent's real capabilities — report status, list or
explain tools/skills, plan a scan, generate text, or score a string for
anomaly — using two fully-local signals: lexical anchoring against each
capability's trigger vocabulary (and recognition of the agent's own
tool/skill names), plus semantic similarity in the built-in model's learned
embedding space to rank paraphrases. It prints what it understood (intent and
confidence) and a plain-English reply, then runs the action:

```bash
./target/release/security-agent --ask "what tools do you have"
./target/release/security-agent --ask "are you healthy and ready"
./target/release/security-agent --ask "explain the nmap skill"
./target/release/security-agent --ask "generate text about scanning targets"
./target/release/security-agent --ask 'is this suspicious: "zzq xqv vfrb qwx"'
```

Routing is **scoped to authorized defensive and offensive security work**: an
off-topic request with no capability match declines cleanly (`out-of-scope`)
rather than guessing. And
`--ask` only *executes* the read-only, no-authorization intents; anything
that touches an engagement, a persisted log, or authorization (planning a
scan, scheduling a retest, viewing an audit log) is explained — the agent
tells you the exact command to run — but never run through `--ask`, so plain
English can never widen the agent's authority.

### Interactive terminal UI (`--tui`)

`--tui` opens a menu- and chat-bar-driven REPL over every command above, all
offline, with no new dependencies (pure `std::io`):

```bash
./target/release/security-agent --tui
```

```
[1]  Offline status              [2]  About
[3]  List tools                  [4]  Show a skill or tool
[5]  List skills                 [6]  Run a built-in local tool
[7]  Run a real external tool    [8]  Plan a scan (engagement config)
[9]  Record findings (merge)     [10] View audit log
[11] Schedule retest             [12] Generate text (LLM)
[13] Score text for anomaly (LLM)
[0]  Help / full capability summary          [q] Quit
```

Type a menu number to run that function (each prompts for the arguments it
needs, the same ones its CLI flag takes), or just type a plain-English
instruction at the `>` prompt and press Enter — that's the **chat bar**,
routed through the exact same grounded router as `--ask`, including
prompting the built-in language model directly (`generate text about ...`,
`is this suspicious: "..."`). Menu option `0` (or typing `help`) prints the
**capability summary page**: every function the agent exposes, its CLI
command, and — where the chat bar can run it — a plain-English example.

`--tui` is a thin wrapper: every menu choice calls the identical command
function the plain CLI dispatches to (`src/main.rs`), so behavior — including
the offline/online gating from `--allow-network` — is exactly the same either
way. It reads lines from stdin and exits cleanly at end-of-input, so it is
fully scriptable and tested the same way as the rest of the CLI (see
`tests/cli.rs`).

Running without arguments is equivalent to `--offline-status`. To install the
binary into Cargo's local binary directory, run `cargo install --path . --locked`;
the same commands can then use `security-agent` instead of the path above.

All 89 tool definitions are stored in and loaded from the binary.
`--list-tools` also reports whether a corresponding third-party executable is
already present on the local `PATH`. Catalog presence does not imply that the
third-party executable is installed or functional. Execution plans only
approve tools found locally. Security-Agent does not download, contact, or
silently execute external sources.

### Per-tool skills

Alongside the general `security-agent` skill, every one of the 89 cataloged
tools has its own skill file under `.github/skills/<tool-name>/SKILL.md`,
compiled into the binary the same way (`--list-skills` lists all 90;
`--show-skill <tool-name>` prints one). Each tool's skill documents:

- its `ExecutionClass` (`static-local-analysis`, `active-network`, or
  `active-exploitation` — see `src/registry.rs`),
- which specialist(s), if any, currently include it in their
  `approved_tools` scope,
- the authorization gate it falls under (`src/policy.rs`), and
- whether Security-Agent can run it for real today (`--run-external-tool`,
  currently wired for `semgrep`, `jadx`, `androguard`, `apktool`, `dex2jar`,
  and `apksigner`) or catalog/detection only (`--list-tools`).

`tool_skills_cover_every_cataloged_tool` in `src/local_assets.rs` asserts
every cataloged tool has a matching skill, so the two stay in sync.

The built-in Autopsy substitute inventories and hashes a local evidence path.
It prints a human-readable report to the terminal, or writes the same report
to a local `.txt` file when the optional `--output` argument is supplied.

The built-in Volatility substitute analyzes a local memory image or binary,
computes its SHA-256 digest and byte entropy, detects embedded ELF, PE/COFF, and
ZIP signatures, and extracts bounded printable strings:

```bash
./target/release/security-agent --run-tool volatility <local-memory-image>
./target/release/security-agent --run-tool volatility <local-memory-image> --output <report-path>.txt
```

The built-in Wireshark substitute strictly parses classic PCAP files, reports
capture timestamps and byte totals, and classifies Ethernet, VLAN, IPv4, IPv6,
ARP, TCP, UDP, ICMP, and ICMPv6 traffic without live capture:

```bash
./target/release/security-agent --run-tool wireshark <local-capture.pcap>
./target/release/security-agent --run-tool wireshark <local-capture.pcap> --output <report-path>.txt
```

Four further forensic substitutes (`src/local_analyzers.rs`) extend the same
offline, local-file, no-dependency pattern to the file-carving and
feature-extraction family of the catalog:

```bash
# Binwalk: map embedded magic signatures and high-entropy (likely
# compressed/encrypted) regions in a firmware image or binary blob.
./target/release/security-agent --run-tool binwalk <local-blob>

# Foremost: carve recoverable embedded files by header, bounding their
# length with a footer where the format defines one.
./target/release/security-agent --run-tool foremost <local-blob>

# Bulk Extractor: pull indicators of compromise — emails, URLs, IPv4
# addresses — out of a blob's printable content.
./target/release/security-agent --run-tool bulk_extractor <local-blob>

# Hashdeep: recursively hash a directory tree (SHA-256 + CRC-32) and report
# sets of files that share a digest.
./target/release/security-agent --run-tool hashdeep <local-path>
```

Each accepts the same optional `--output <report-path>.txt`. These are
**defensive** analyzers over evidence you already hold — none contacts a live
target. The offensive (`ActiveExploitation`) and live-network
(`ActiveNetwork`) catalog tools are deliberately **not** reimplemented as
in-house attack code; instead the agent *orchestrates the real, installed
binaries* under the online opt-in and authorization controls described next.

### Offline by default, online by explicit opt-in

The runtime is **fully offline by default**: no command performs live-target
or network activity unless you opt in *for that invocation* with the explicit
`--allow-network` flag (`src/network_policy.rs`, `NetworkMode`). This makes
going online a deliberate, per-invocation, auditable choice — `--offline-status`
reports `default_network_mode=offline` and the `online_opt_in_flag`.

- **Offline** (default): only the built-in substitutes and
  `StaticLocalAnalysis` tools (local files only) may run.
- **Online** (`--allow-network`): the real, installed `ActiveNetwork` and
  `ActiveExploitation` tools additionally become eligible, so an **authorized**
  engagement has full tool scope. Going online never bypasses the
  authorization policy — when run through a planned scan, target scope, the
  technique allow-list, deny-lists, approval gates, and the time window are
  all still enforced.

The agent only ever spawns the real third-party binaries you have installed;
it never reimplements a tool's offensive behavior itself. Full-scope active
testing is therefore available for authorized work, with the authorization
and audit controls kept firmly in place.

### Running real cataloged tools

Every cataloged tool is classified by `ExecutionClass` (`src/registry.rs`):
`StaticLocalAnalysis` (operates only on local files — semgrep, jadx,
androguard, apktool, dex2jar, apksigner, and others), `ActiveNetwork`
(scans or contacts a live target), or `ActiveExploitation` (attempts to
compromise a live target or running process). `--run-external-tool`
directly invokes a real, locally installed tool. `StaticLocalAnalysis`
tools run in the default offline mode; live `ActiveNetwork` /
`ActiveExploitation` tools require the explicit `--allow-network` opt-in
placed immediately after `--run-external-tool`:

```bash
# Offline (local files only) — no opt-in needed:
./target/release/security-agent --run-external-tool semgrep --version
./target/release/security-agent --run-external-tool jadx -d <out-dir> <apk-path>

# Online (live target) — requires the explicit opt-in:
./target/release/security-agent --run-external-tool --allow-network nmap -sV <in-scope-host>
./target/release/security-agent --run-external-tool --allow-network sqlmap -u <in-scope-url>
```

The process is spawned with a bounded execution timeout and its stdout,
stderr, exit code, and duration are captured into a report. Arguments given
to `--execute`/`--run-external-tool` are trusted as-is. As a non-blocking
aid, arguments to network tools are passed through an intensity advisory
(`src/intensity_guard.rs`): aggressive flags (`-T5`, `--min-rate`,
full-range sweeps) that exceed the engagement's declared `max_intensity`
print a warning to stderr, but execution still proceeds. Without
`--allow-network`, a live `ActiveNetwork`/`ActiveExploitation` tool is
refused with a message pointing to the opt-in — it never runs active work
in offline mode.

### Tool integrity

Before spawning any eligible tool, Security-Agent checks the resolved
binary against a bundled integrity manifest (`assets/tool_integrity.txt`,
compiled into the binary). Each line pins a tool to the expected
lowercase-hex SHA-256 of its executable:

```text
semgrep=<64-hex-sha256-of-the-vetted-semgrep-binary>
```

Per tool, the check yields one of three states, shown in `--list-tools`
(the `integrity=` column) and counted in `--offline-status`
(`integrity_verified_tools=`):

- **verified** — a manifest entry exists and the local binary's SHA-256
  matches it. Executes.
- **mismatch** — a manifest entry exists but the local binary differs.
  Execution is **refused** with an error.
- **unpinned** — no manifest entry. Executes. This is the default for
  every tool: the shipped manifest is intentionally empty, so integrity
  pinning never blocks day-to-day use until an operator deliberately vets
  a binary and adds its hash. Only pinned tools are ever hashed, so an
  empty manifest adds no runtime cost. The SHA-256 is the crate's own
  implementation (`src/builtin_tools.rs`) — no external dependency. Add an
  entry only with documented provenance for the exact binary you intend to
  pin.

### Planning and running an authorized scan

`--plan-scan` reads a hand-written engagement configuration file (a plain
`key=value` text file — see `OPERATING_GUIDE.md` section 8a for the exact
format), authorizes it through the same `PolicyEngine`/`Coordinator` used
by the library's tests, and prints the resulting scan plan:

```bash
./target/release/security-agent --plan-scan engagement.txt
./target/release/security-agent --plan-scan engagement.txt --audit-log audit.jsonl
./target/release/security-agent --plan-scan engagement.txt --cognitive-review
./target/release/security-agent --plan-scan engagement.txt --execute <args-passed-to-each-tool>
./target/release/security-agent --plan-scan engagement.txt --findings-log findings.jsonl --execute <args>
./target/release/security-agent --schedule-retest findings.jsonl
```

- With no extra flags, `--plan-scan` only plans: it prints the
  `ExecutionPlan` (workflow stages, selected toolchain packs, and each
  task's specialist/techniques/approved tools) or, if authorization
  failed, the specific reason and a non-zero exit code.
- `--audit-log <path>` appends that call's audit records to `<path>` as
  an append-only JSON Lines file (`src/audit_log.rs`), so the audit trail
  survives past a single run instead of living only in memory.
- `--cognitive-review` runs both advisory reasoning layers over the
  resulting plan. First (`src/cognition.rs`) it prints a risk-yield task
  ranking, ranked per-target hypotheses about which technique is likely to
  find what, and a reflective critique flagging coverage gaps (e.g. a task
  with no locally installed tool). Then (`src/cognitive_engine.rs`) it
  prints a full **Cognitive Deliberation**: an explicit train of thought
  with provenance links, a Bayesian belief distribution with its
  uncertainty, the modeled adversary's predicted next moves, attention
  allocation across targets, and a metacognitive self-assessment that
  decides whether to escalate to a human. Add `--memory <ledger>` to make
  this history-informed (see below); without it the run is stateless and
  priors are type-based only.
- `--memory <log>` loads the append-only findings log at `<log>`
  (`src/findings_log.rs`, via `src/memory_store.rs`) before running
  `--cognitive-review`, so cognition reasons from history accumulated across
  prior engagements: the folded memory boosts hypothesis confidence and
  attention, and the raw findings drive Bayesian belief revision. A missing
  log is treated as empty history (no error). Because there is one findings
  format, a log written by `--findings-log` is valid `--memory` input
  directly; `--record-findings` merges logs when needed.
- `--execute <args>` additionally runs every approved, locally installed,
  `StaticLocalAnalysis`-classified tool in the plan via
  `execute_plan`, passing `<args>` to each invocation, and prints each
  outcome (success with exit code/duration, or the specific failure).
- Flags may be combined, in this order: `--audit-log <path>`, then
  `--cognitive-review`, then `--memory <log>`, then `--findings-log <path>`,
  then `--execute <args>...`.

### Persisting cognitive memory across engagements

The cognitive layers learn from the single append-only findings log. A scan
writes its scored findings with `--findings-log`; a later engagement reasons
from that accumulated history by pointing `--memory` at the same file — no
format conversion:

```bash
# Engagement 1: run tools and persist scored findings to the log.
./target/release/security-agent --plan-scan engagement.txt \
  --findings-log findings.jsonl --execute <args>

# Engagement 2: reason from the accumulated history — sharper hypotheses,
# Bayesian-updated beliefs, higher adversary payoffs, and metacognition that
# no longer flags well-evidenced targets as gaps.
./target/release/security-agent --plan-scan engagement.txt \
  --cognitive-review --memory findings.jsonl

# Optional: merge/curate logs (append one log's findings onto another).
./target/release/security-agent --record-findings combined.jsonl findings.jsonl
```

The log is human-readable (one `finding_record` per line) and only ever
grows — each engagement's findings accumulate on top of earlier ones, and
cognition is always re-derived by folding the full log.
