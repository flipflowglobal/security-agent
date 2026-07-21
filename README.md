# Security-Agent

[![CI](https://github.com/flipflowglobal/security-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/flipflowglobal/security-agent/actions/workflows/ci.yml)

Rust-first hybrid defensive security orchestration agent for authorized vulnerability testing across web, API, mobile (Android), blockchain, cloud, and infrastructure targets.

## Mission

Defensive security orchestration agent for authorized vulnerability testing across platform applications, tools, APIs, and infrastructure.

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

Federated model (not an unrestricted super-agent):

- **Coordinator** — plans scoped runs, maps targets to specialists, writes immutable audit records, emits execution plans.
- **Specialists** — SAST, DAST, API security, dependency risk, cloud/IaC, container/K8s, secrets, malware, compliance, **Android/mobile**, **blockchain/smart-contract**.
- **Capability Registry** — maps specialists to approved tools, supported target types, and allowed techniques.
- **Policy Engine** — time-bounded engagement profiles, technique allow-lists, deny-list targets, intensity caps, high-impact approval gate.
- **Audit Ledger** — append-only record of every authorized action; filterable by role and action type.
- **Attack-Path Graph** — builds threat model (nodes + edges) from a set of findings.
- **Retest Scheduler** — drift-and-risk-based retest intervals derived from finding risk scores.
- **Cognitive Layer** (`src/cognition.rs`) — advisory reasoning over an already-authorized plan: ranks tasks by expected risk yield, proposes ranked hypotheses about which technique is likely to find what per target type, and reflects on the plan to flag coverage gaps.
- **Advanced Cognitive Architecture** (`src/cognitive_engine.rs`) — models the reasoning *process* itself as cooperating faculties: an explicit, provenance-linked **train of thought** (observe → hypothesize → imagine → decide → reflect), **Bayesian belief revision** with Shannon-entropy uncertainty, **adversary theory-of-mind** predicting an attacker's ranked next moves, salience-weighted **attention allocation**, and **metacognition** that self-assesses confidence, names knowledge gaps, and decides when to escalate to a human. Exposed via `--plan-scan <config> --cognitive-review`.
- **Cognitive Memory** (`src/memory_store.rs`) — persists the finding history the cognitive layers learn from as an append-only JSON Lines ledger, so cognition **learns across engagements** instead of starting blank each run. Findings are folded into memory (`--record-findings`), and a later `--cognitive-review --memory <ledger>` reasons from the full accumulated history: hypothesis confidence and attention rise, beliefs get Bayesian-updated by real evidence, and metacognition stops flagging a well-evidenced target as a knowledge gap.

Both cognitive layers are **purely advisory** — they reason over plans the `PolicyEngine`/`Coordinator` have already authorized, and never grant, restrict, execute, or bypass any authorization decision.

---

## Supported Target Types

| Target Type | Use Case Pack | Default Techniques |
|---|---|---|
| `WebApp` | webapp-core-pack | PassiveRecon, ConfigurationAudit, DAST |
| `Api` | api-core-pack | PassiveRecon, ConfigurationAudit, ApiSecurity |
| `MobileBackend` | mobile-backend-pack | ConfigurationAudit, ApiSecurity, AndroidStaticAnalysis |
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
| `src/governance.rs` | Append-only audit ledger with role/action filtering |
| `src/advanced.rs` | Attack-path graph builder and retest scheduler |
| `src/cognition.rs` | Advisory reasoning layer: risk-yield task prioritization, per-target-type hypothesis generation, and reflective plan critique |
| `src/cognitive_engine.rs` | Advanced cognitive architecture: explicit chained reasoning (train of thought), Bayesian belief revision, adversary theory-of-mind, attention allocation, and metacognitive self-reflection |
| `src/memory_store.rs` | Append-only, on-disk persistence of the cognitive layer's finding history, so cognition learns across engagements |
| `src/compat.rs` | Integration adapter contracts and wire-format envelope |
| `src/roadmap.rs` | Phased rollout model |
| `src/main.rs` | Offline local runtime entry point (also cross-compiles for Android) |

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
./target/release/security-agent --list-skills
./target/release/security-agent --show-skill security-agent
./target/release/security-agent --show-skill nmap
./target/release/security-agent --list-tools
./target/release/security-agent --run-tool autopsy <local-path>
./target/release/security-agent --run-tool autopsy <local-path> --output <report-path>.txt
```

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

### Running real cataloged tools

Every cataloged tool is classified by `ExecutionClass` (`src/registry.rs`):
`StaticLocalAnalysis` (operates only on local files — semgrep, jadx,
androguard, apktool, dex2jar, apksigner, and others), `ActiveNetwork`
(scans or contacts a live target), or `ActiveExploitation` (attempts to
compromise a live target or running process). `--run-external-tool`
directly invokes a real, locally installed tool when it is classified
`StaticLocalAnalysis`, or is `nmap` or `masscan` — explicit, reviewed
exceptions (see `WIRED_DESPITE_EXECUTION_CLASS` in `src/execution.rs`):

```bash
./target/release/security-agent --run-external-tool semgrep --version
./target/release/security-agent --run-external-tool jadx -d <out-dir> <apk-path>
./target/release/security-agent --run-external-tool nmap -sV <in-scope-host>
./target/release/security-agent --run-external-tool masscan -p80 <in-scope-range>
```

The process is spawned with a bounded execution timeout and its stdout,
stderr, exit code, and duration are captured into a report. `nmap` and
`masscan` run under the same gate as the `StaticLocalAnalysis` tools
above — the coordinator's existing planning approval (scope + technique
allow-list) plus local installation — with no additional
target-confirmation, approval, or rate-limiting: arguments given to
`--execute`/`--run-external-tool` are trusted as-is. As a non-blocking
aid, arguments to these network tools are passed through an intensity
advisory (`src/intensity_guard.rs`): aggressive flags (`-T5`,
`--min-rate`, full-range sweeps) that exceed the engagement's declared
`max_intensity` print a warning to stderr, but execution still proceeds.
Every other tool classified `ActiveNetwork` or `ActiveExploitation`
(sqlmap, hydra, msfconsole, and similar) is still rejected by this
command — real execution of those needs a live-target
confirmation/rate-limit design layered on the policy engine's
`AuthorizationOutcome`, which does not exist yet.

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
- `--memory <ledger>` loads the append-only findings ledger at `<ledger>`
  (`src/memory_store.rs`) before running `--cognitive-review`, so cognition
  reasons from history accumulated across prior engagements: the folded
  memory boosts hypothesis confidence and attention, and the raw findings
  drive Bayesian belief revision. A missing ledger is treated as empty
  history (no error). Populate the ledger with `--record-findings`.
- `--execute <args>` additionally runs every approved, locally installed,
  `StaticLocalAnalysis`-classified tool in the plan via
  `execute_plan`, passing `<args>` to each invocation, and prints each
  outcome (success with exit code/duration, or the specific failure).
- Flags may be combined, in this order: `--audit-log <path>`, then
  `--cognitive-review`, then `--memory <ledger>`, then `--execute <args>...`.

### Persisting cognitive memory across engagements

The cognitive layers learn from an append-only findings ledger. Record an
engagement's findings into it, then let a later engagement reason from the
accumulated history:

```bash
# Fold a scan's findings (JSON Lines of Finding) into the memory ledger.
./target/release/security-agent --record-findings memory.jsonl findings.jsonl

# A later engagement reasons from the accumulated history: sharper
# hypotheses, Bayesian-updated beliefs, higher adversary payoffs, and
# metacognition that no longer flags well-evidenced targets as gaps.
./target/release/security-agent --plan-scan engagement.txt \
  --cognitive-review --memory memory.jsonl
```

The ledger is human-readable (one finding per line) and only ever grows —
each engagement's findings accumulate on top of earlier ones, and cognition
is always re-derived by folding the full ledger.
