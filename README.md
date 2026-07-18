# Security-Agent

Rust-first hybrid defensive security orchestration agent for authorized vulnerability testing across web, API, mobile (Android), blockchain, cloud, and infrastructure targets.

## Mission

Defensive security orchestration agent for authorized vulnerability testing across platform applications, tools, APIs, and infrastructure.

---

## Quick Start

### Host (Linux / macOS / Windows)

```bash
# Clone and build
git clone <repo-url>
cd security-agent

# Run all tests
cargo test

# Build and run the demo agent binary
cargo run --release
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
| `src/findings.rs` | Unified finding model and normalized risk scorer |
| `src/governance.rs` | Append-only audit ledger with role/action filtering |
| `src/advanced.rs` | Attack-path graph builder and retest scheduler |
| `src/compat.rs` | Integration adapter contracts and wire-format envelope |
| `src/roadmap.rs` | Phased rollout model |
| `src/main.rs` | Runnable demo binary (also cross-compiles for Android) |

---

## Roadmap

- **Phase 1** — Coordinator, core scanners, and reporting *(complete)*
- **Phase 2** — Cloud, container, and supply-chain specialists *(complete)*
- **Phase 3** — Attack-path analytics and autonomous retesting *(complete)*
- **Phase 4** — Organization-wide policy automation and continuous validation

---

## Development

```bash
cargo test            # run all 29 tests
cargo fmt --check     # verify formatting
cargo clippy          # lint (zero warnings enforced)
cargo build --release # optimized host binary
```
