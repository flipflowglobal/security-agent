# Changelog

All notable changes to Security-Agent are documented here.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
conventions. Releases use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **`src/cognitive_engine.rs`** — advanced cognitive architecture that
  models the agent's reasoning *process* as cooperating faculties:
  `ReasoningChain` (an explicit, provenance-linked train of thought:
  observe → hypothesize → imagine → decide → reflect), `BeliefState`
  (a normalized probability distribution revised with Bayes' rule as
  finding evidence accumulates, with Shannon-entropy uncertainty),
  `AdversaryModel` (theory-of-mind prediction of a rational attacker's
  ranked next moves given an objective), `AttentionAllocator`
  (salience-weighted focus across targets), and `Metacognition` (the
  agent self-assessing confidence, naming knowledge gaps, and deciding
  when to escalate to a human). `CognitiveEngine::deliberate` runs all
  faculties and returns a `CognitiveDeliberation`. Like `src/cognition.rs`
  it is purely advisory and never affects authorization. Surfaced through
  the existing `--plan-scan <config> --cognitive-review` flag, printed
  after the flat cognitive assessment.
- **`src/cognition.rs`** — advisory reasoning layer above the coordinator.
  Given an already-authorized `ExecutionPlan`, it ranks tasks by expected
  risk yield (`prioritize_tasks`), proposes ranked hypotheses about which
  technique is most likely to surface a finding per target type
  (`generate_hypotheses`), and reflects on the plan to flag coverage gaps
  such as a task with no locally installed tool or a target with a history
  of severe findings still being tested at `Passive` intensity
  (`critique_plan`). `CognitiveMemory` carries finding history across calls
  so confidence and prioritization improve as more findings are recorded.
  This layer is purely advisory: it does not grant, restrict, or bypass any
  `PolicyEngine`/`Coordinator` authorization decision. Wired into the CLI
  as `--plan-scan <config> --cognitive-review`.
- **GitHub Actions CI pipeline** (`.github/workflows/ci.yml`) — covers `fmt`,
  `clippy`, `test --lib`, release `build`, and `android-cross` jobs on every
  push and pull request targeting `main`.
- **`CONTRIBUTING.md`** — developer onboarding guide covering prerequisites,
  local workflow, CI gates, commit conventions, branch strategy, and Android
  cross-compilation instructions.
- **`Makefile`** — convenience wrapper around cargo commands (`fmt`, `clippy`,
  `test`, `build`, `check`, `status`, `list-tools`, `list-skills`, `android`,
  `clean`).
- **`rustfmt.toml`** — explicit formatting configuration (`edition = "2024"`,
  `max_width = 100`) so all contributors produce identical output.
- **`CHANGELOG.md`** — this file; documents project history going forward.

### Changed
- **`Cargo.toml`** — `candle`, `candle-transformers`, and `tokenizers` are now
  optional dependencies grouped under the `inference` feature flag.  These
  crates were listed as direct dependencies but had zero references in the
  codebase.  Making them optional eliminates build failures on aarch64 hosts
  without the `+fullfp16` CPU feature (required by `gemm-f16`, a transitive
  dependency), and reduces default compile times significantly.
- **`OPERATING_GUIDE.md`** — replaced hardcoded `/home/runner/work/...`
  absolute paths with relative Markdown links, fixed `cargo test` → `cargo
  test --lib` throughout, and added a `make check` tip.
- **`README.md`** — added CI badge, updated Quick Start and Development
  sections to match the new `cargo test --lib` invocation, linked
  `CONTRIBUTING.md`, and documented the `inference` feature flag.
- **`.gitignore`** — expanded from a single `/target` entry to cover secrets,
  environment files, OS artefacts, editor files, coverage reports, and Python
  virtualenvs.

---

## [0.1.0] — 2026-07

### Added
- Coordinator, capability registry, toolchain pack registry, policy engine,
  and audit ledger (append-only, filterable by role, action, and test-run ID).
- Specialist kinds: SAST, DAST, API security, dependency risk, cloud/IaC,
  container/K8s, secrets, malware, compliance, **Android/mobile**, and
  **blockchain/smart-contract**.
- Authorization model: time-bounded engagement profiles, in-scope allow-list,
  deny-list, technique allow-list, high-impact approval gate, and penetrative
  technique approval gate.
- Attack-path graph builder and retest scheduler (drift-and-risk-based).
- Tagged test-run support with full audit trail (`TaggedTestRun`, `TestRunReport`).
- Built-in offline tool substitutes: Autopsy, Volatility, Wireshark (PCAP parser).
- Embedded skill (`security-agent/SKILL.md`) and tool catalog (89 entries).
- Android cross-compilation configuration (`.cargo/config.toml`).
- Offline local runtime binary with `--offline-status`, `--list-skills`,
  `--show-skill`, `--list-tools`, and `--run-tool` sub-commands.
- 45 unit tests covering all policy gates, coordinator logic, audit ledger
  filtering, attack-path graph construction, retest scheduling, compatibility
  adapters, and capability coverage.
- `OPERATING_GUIDE.md` — beginner-friendly step-by-step operations manual.
