# Security-Agent Architecture

This document maps the repository's file system onto the agent's architecture,
so the "building" (directory layout) matches the design and every module's role
and wiring is explicit. It is a companion to the module table in
[`README.md`](./README.md).

The crate is a single Rust library (`src/lib.rs`) plus a thin CLI binary
(`src/main.rs`). Modules live in a flat `src/` — idiomatic for Rust, where the
module path (`security_agent::<module>`) is the namespace, not the folder. The
layers below are the *logical* architecture; each module is annotated with the
layer it belongs to.

## Layered view

```
┌─────────────────────────────────────────────────────────────────────┐
│  CLI / entry point         main.rs (incl. --tui terminal UI) · lib.rs │
├─────────────────────────────────────────────────────────────────────┤
│  Neural language layer     language_model.rs · anomaly.rs · nlu.rs    │
├─────────────────────────────────────────────────────────────────────┤
│  Cognitive layer           cognition.rs · cognitive_engine.rs ·       │
│                            calibration.rs · belief_propagation.rs ·   │
│                            advanced.rs                                 │
├─────────────────────────────────────────────────────────────────────┤
│  Findings pipeline         ingest.rs · findings.rs · findings_log.rs ·│
│                            memory_store.rs · compat.rs                 │
├─────────────────────────────────────────────────────────────────────┤
│  Orchestration & execution coordinator.rs · execution.rs ·            │
│                            engagement_config.rs · tagged_run.rs        │
├─────────────────────────────────────────────────────────────────────┤
│  Local tools (offline)     builtin_tools.rs · local_analyzers.rs ·    │
│                            pcap.rs · local_assets.rs                   │
├─────────────────────────────────────────────────────────────────────┤
│  Authorization & governance policy.rs · governance.rs · audit_log.rs ·│
│                            integrity.rs · intensity_guard.rs ·        │
│                            network_policy.rs                          │
├─────────────────────────────────────────────────────────────────────┤
│  Domain model              model.rs · registry.rs · capability_graph.rs│
│                            findings.rs · workflow.rs                   │
├─────────────────────────────────────────────────────────────────────┤
│  Identity                  mission.rs · roadmap.rs                    │
├─────────────────────────────────────────────────────────────────────┤
│  Infrastructure            json.rs   (in-house, zero external crates) │
└─────────────────────────────────────────────────────────────────────┘

Assets (compiled into the binary):  .github/skills/**  ·  assets/**
Tests:                              tests/cli.rs  +  per-module #[cfg(test)]
Release packaging:                  scripts/deploy.sh (make deploy)
```

## Module directory

| Layer | File | Responsibility | Key public API |
|---|---|---|---|
| Entry | `src/main.rs` | CLI arg parsing and command dispatch, plus the `--tui` interactive terminal UI (menu + chat bar over the same command functions) | `main`, `run_tui_command` |
| Entry | `src/lib.rs` | Crate root; module registry and re-exports | — |
| Identity | `src/mission.rs` | Mission statement constant | `MISSION_STATEMENT` |
| Identity | `src/roadmap.rs` | Phased rollout model (surfaced by `--about`) | `ROADMAP_PHASES` |
| Domain | `src/model.rs` | Core enums/structs: targets, techniques, engagement profile | `EngagementProfile`, `Target`, `Technique` |
| Domain | `src/registry.rs` | Capability + toolchain-pack registries, `ExecutionClass` | `CapabilityRegistry`, `ToolchainPackRegistry` |
| Domain | `src/capability_graph.rs` | Coverage validation across registries | `CapabilityGraph` |
| Domain | `src/findings.rs` | Unified finding model + normalized risk scorer | `Finding`, `RiskScoreCalculator` |
| Domain | `src/workflow.rs` | Ordered workflow-stage model | `WorkflowStage` |
| Authz | `src/policy.rs` | Least-privilege authorization engine | `PolicyEngine`, `AuthorizationOutcome` |
| Authz | `src/governance.rs` | Append-only audit ledger + role/action filtering | `AuditLedger`, `Role` |
| Authz | `src/audit_log.rs` | On-disk persistence for the audit ledger | `append_audit_records`, `load_audit_records` |
| Authz | `src/audit_db.rs` | Same role as `audit_log.rs`, backed by `.sadb` (see Infra) instead of JSON Lines | `append_audit_records`, `load_audit_records` |
| Authz | `src/integrity.rs` | Offline tool-integrity verification vs. manifest | `verify`, `IntegrityStatus` |
| Authz | `src/intensity_guard.rs` | Non-blocking intensity advisories | `advise` |
| Authz | `src/network_policy.rs` | Offline-by-default / online-opt-in egress governance | `NetworkMode` |
| Tools | `src/builtin_tools.rs` | Offline substitutes (autopsy, volatility) + SHA-256 | `run_builtin_tool`, `is_builtin_tool` |
| Tools | `src/local_analyzers.rs` | Forensic substitutes (binwalk, foremost, bulk_extractor, hashdeep) | `run_binwalk`, `run_foremost`, `run_bulk_extractor`, `run_hashdeep` |
| Tools | `src/pcap.rs` | Offline Wireshark substitute (classic PCAP parser) | `run_wireshark` |
| Tools | `src/local_assets.rs` | Compiled-in skill/tool catalog + PATH resolution | `LocalAgentAssets` |
| Exec | `src/coordinator.rs` | Scoped task planning, audit integration | `Coordinator`, `ExecutionPlan` |
| Exec | `src/execution.rs` | Real external-tool execution, gated by `NetworkMode` | `run_external_tool`, `execute_plan` |
| Exec | `src/engagement_config.rs` | Zero-dependency engagement-config parser | `load_engagement_config` |
| Exec | `src/tagged_run.rs` | Tagged test-run metadata for audit correlation | `TaggedTestRun` |
| Findings | `src/ingest.rs` | Real tool output → scored `Finding`s | `ingest` |
| Findings | `src/findings_log.rs` | Append-only on-disk findings log (single format) | `append_findings`, `load_findings` |
| Findings | `src/findings_db.rs` | Same role as `findings_log.rs`, backed by `.sadb` (see Infra) instead of JSON Lines | `append_findings`, `load_findings` |
| Findings | `src/memory_store.rs` | Folds the findings log into cognitive memory | `load_memory` |
| Findings | `src/compat.rs` | Integration-adapter contracts + wire envelope | `JsonLineAdapter` |
| Cognition | `src/cognition.rs` | Task prioritization, hypotheses, plan critique | `assess`, `generate_hypotheses` |
| Cognition | `src/cognitive_engine.rs` | Chained reasoning, Bayesian beliefs, adversary model, metacognition | `CognitiveEngine`, `CognitiveDeliberation` |
| Cognition | `src/calibration.rs` | Confidence-calibration tracking (Brier, ECE, reliability bins) | `CalibrationTracker` |
| Cognition | `src/calibration_db.rs` | Persists calibration records across runs so `CognitiveEngine::with_calibration` has real cross-engagement evidence, not an empty tracker | `append_calibration_records`, `load_calibration` |
| Cognition | `src/reasoning_log_db.rs` | Write-only archive of each `--cognitive-review` run's full reasoning chain + metacognitive verdict | `append_run`, `load_runs` |
| Cognition | `src/belief_propagation.rs` | Noisy-OR compromise-risk propagation | `PropagationGraph` |
| Cognition | `src/advanced.rs` | Attack-path graph builder + retest scheduler | `AttackPathGraph`, `propose_retest_schedule` |
| Neural LM | `src/language_model.rs` | **In-house vector-quantized temporal-frequency neural LM** | `NeuralLanguageModel`, `LanguageModel` |
| Neural LM | `src/anomaly.rs` | LM perplexity as an out-of-domain anomaly lens | `scan_findings` |
| Neural LM | `src/nlu.rs` | Grounded plain-English intent router (`--ask`) | `interpret`, `Intent` |
| Infra | `src/json.rs` | In-house JSON parser/writer (keeps the crate crate-free) | — |
| Infra | `src/sadb.rs` (+ `src/sadb/`) | Zero-dependency embedded append-only store: pager, slot-directory heap pages, an immutable-image catalog, and a checksummed-footer transaction boundary. Not `SQLite`-compatible by design — see the module docs for why. | `Database`, `Transaction` |

## Data flow (a planned scan)

```
engagement config (engagement_config.rs)
        │
        ▼
Coordinator.plan_authorized_scan  ── PolicyEngine.authorize (policy.rs)
   (coordinator.rs)                    scope · technique · approval · window
        │                              │
        │                              └──▶ AuditLedger (governance.rs) ─▶ audit_log.rs
        ▼
ExecutionPlan ──▶ execute_plan (execution.rs)
                    │   gate: NetworkMode (network_policy.rs)
                    │   offline → StaticLocalAnalysis only
                    │   online  → + ActiveNetwork / ActiveExploitation (real binaries)
                    ▼
             tool output ──▶ ingest.rs ──▶ Finding (findings.rs) ──▶ findings_log.rs
                                                              │
      ┌───────────────────────────────────────────────────────┘
      ▼
Cognitive review (--cognitive-review)
   cognition.rs + cognitive_engine.rs + calibration.rs + belief_propagation.rs
      │
      └── anomaly lens: anomaly.rs ── perplexity ── language_model.rs
```

Plain-English entry (`--ask`) routes through `nlu.rs`, which uses
`language_model.rs` embeddings for semantic ranking, then dispatches to the
same read-only commands above.

## Neural language model — integration map

The neural LM is fully wired; it is reachable from three surfaces and shares
one bundled, memoized instance:

- **Definition:** `src/language_model.rs` — `NeuralLanguageModel` (embed → DCT
  → residual vector quantization → tanh hidden → softmax), the `LanguageModel`
  trait (`generate`, `perplexity`, `embed_text`), trained deterministically at
  startup on a bundled corpus. Memoized via `bundled()`.
- **CLI:** `--llm-generate` and `--llm-perplexity` (`src/main.rs`).
- **Cognitive layer:** `src/anomaly.rs` scores finding text with the model's
  perplexity during `--cognitive-review --memory`.
- **Plain-English routing:** `src/nlu.rs` uses `embed_text` for semantic
  intent ranking behind `--ask`.
- **Exports:** `pub use language_model::{LanguageModel, NeuralLanguageModel}`
  in `src/lib.rs`.

## Compiled-in assets

- `.github/skills/**` — one general skill plus one per cataloged tool (90
  total), `include_str!`-compiled into the binary via `src/local_assets.rs`.
- `assets/**` — the tool-integrity manifest and related offline data.

Nothing is fetched at runtime: all skills, the tool catalog, and the LM corpus
are embedded, so the binary runs with no network and no on-disk model weights.

## Release packaging

- `scripts/deploy.sh` (aliased as `make deploy`) — outside the `security_agent`
  library/binary entirely; a POSIX-ish bash script that runs the CI quality
  gate, builds the `--release` binary (optionally cross-compiled via
  `--target`), and packages it into a checksummed archive under `dist/`
  (gitignored — a build output, not source). It never contacts the network
  and adds no build-time dependency; "deploying" this CLI means producing a
  trustworthy, versioned local artifact, not standing up a service.

## Physical vs. logical layout

The layers above are logical. If a physically nested tree is later preferred
(e.g. `src/cognition/`, `src/tools/`, `src/authz/`), the modules can be moved
into subdirectories with `mod.rs` re-exports without changing the public
`security_agent::*` API — the layer boundaries in this document are the seams
along which that regrouping would happen.
