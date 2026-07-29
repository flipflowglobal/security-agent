# Changelog

All notable changes to Security-Agent are documented here.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
conventions. Releases use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Full catalog adapter coverage: every cataloged tool now has an
  invocation adapter and is coverage-tested.** The 14 tools with rich
  behavior keep their hand-written adapters; the remaining ~75 are driven by
  a declarative `ToolSpec` table (`CATALOG_SPECS`) through a single
  `SpecAdapter`, each with a realistic non-interactive invocation and a
  target-placement shape (network host / web URL / local path / no target).
  `registry::cataloged_tool_names()` exposes the authoritative,
  deduplicated 89-tool catalog, and two data-driven tests enforce the
  contract: `every_cataloged_tool_has_a_registered_adapter` (a real adapter,
  never the fallback, builds a well-formed invocation for each) and
  `every_cataloged_tool_has_a_bundled_skill` (each has its compiled-in
  `SKILL.md`). Names outside the catalog still resolve to the conservative
  fallback.
- **End-to-end reporting integration tests (Stage 8).** A new
  `tests/report_e2e.rs` seeds a real findings log through the library, then
  drives the compiled binary's `--report` command and asserts on the
  rendered deliverables — SARIF validity and severity levels, Markdown
  risk-ranking and the attack-path section, JSON summary counts, and clean
  tolerance of a findings log full of garbage. This covers the full load →
  correlate → render → print path with real data, complementing the
  black-box `cli.rs` (which relies only on built-in assets).
- **`src/observability.rs` — structured engagement observability (Stage 7),
  emitted live by the runtime.** A typed `EngagementEvent` stream
  (stage/step started, completed, failed, refused) serializes to
  deterministic JSON lines and flows to pluggable `EventSink`s — a
  `WriterSink` for JSON-Lines log aggregation, a `CollectingSink` for tests,
  or `NullSink`. Sinks are `Sync`, so `ExecutionRuntime` emits from its
  concurrent workers (wired via `RunInputs::with_events`), giving a live
  signal of a long run. `ProgressSummary::of` folds a set of outcomes into a
  one-line status (succeeded / failed / refused), counting a pre-spawn
  refusal separately from an execution failure.
- **`src/secrets.rs` + `src/scope.rs` — secrets handling and egress scope
  enforcement (Stage 6), wired into the runtime.** Authenticated tooling can
  now be driven safely: `Secret` wraps a credential so it never renders in
  `Debug`/`Display`, and `SecretStore` resolves named secrets from the
  environment (`SECAGENT_SECRET_*`) or an on-disk file, substitutes
  `${secret:NAME}` references in a tool's arguments at spawn time, and
  redacts any secret value echoed in a tool's output before it is recorded.
  `ScopePolicy` enforces the authorized egress scope: before a tool spawns,
  the runtime checks the concrete argv for IPv4 literals, `host:port` pairs,
  and URL hosts and refuses (`ToolExecutionError::Refused`) any target
  outside the configured exact hosts / IPv4 CIDR ranges — defense in depth
  atop `NetworkMode`, with in-house CIDR matching and no DNS. Both are wired
  into `ExecutionRuntime` via `RunInputs::with_scope` / `with_secrets`, so a
  run resolves secrets, enforces scope, and scrubs output on every step.
- **`src/report.rs` — engagement reporting and deliverables (Stage 5).**
  Renders scored, correlated findings and their evidence into the documents
  an engagement is judged by: a **SARIF 2.1.0** file for scanners/CI/
  dashboards, a machine-readable **JSON summary**, and a human **Markdown
  report** (executive summary, severity rollup, ranked findings with
  remediation, the attack-path narrative from `advanced.rs`, and the
  evidence chain-of-custody table). Every renderer is deterministic for a
  given input — findings ordered by descending risk then id, timestamp
  supplied by the caller — so a report is byte-identical across runs.
  Serialization is in-house (an escaping JSON value writer plus an epoch→UTC
  formatter; no date/JSON dependency). Surfaced end to end via the new
  `--report <findings-log> [--format sarif|json|markdown] [--evidence
  <path>] [--engagement <id>]` CLI command, which loads a findings log,
  correlates it, and writes the chosen deliverable.
- **Execution/data plane: a real per-tool invocation layer, a concurrent
  runtime, a result-driven pipeline, and findings hardening.** Four stages
  built on the merged foundation (`tool_adapter.rs`, `runtime.rs`,
  `engagement_context.rs`) turn the orchestrated schedule into an actual
  engagement:
  - **`src/tool_adapter.rs` (Stage 1)** — a bespoke `ToolAdapter` per
    cataloged tool (nmap, masscan, nuclei, gobuster, feroxbuster, ffuf,
    nikto, whatweb, wpscan, subfinder, sqlmap, hydra, semgrep, jadx) that
    builds a correct, tool-specific `argv` + `OutputFormat` from the
    authorized step, maps `TestIntensity` onto each tool's aggressiveness
    knobs, targets discovered endpoints/services from the engagement
    context, and appends operator overrides last. Un-adapted tools keep the
    conservative fallback.
  - **`src/runtime.rs` (Stage 3)** — `ExecutionRuntime` executes a schedule
    one execution class at a time (a class fully completes before the next
    starts) with bounded concurrency *within* a class via
    `std::thread::scope`, returns outcomes in deterministic execution order,
    and adds rate limiting, an `AtomicBool` cancellation kill-switch, a
    mid-run authorization guard, and checkpoint/resume.
  - **`src/pipeline.rs` (Stage 2)** — `run_engagement_pipeline` runs the
    schedule class-by-class and folds each stage's tool output
    (nmap/masscan XML → hosts/services, URL/subdomain JSON-lines →
    endpoints/hosts) into the shared `EngagementContext`, so later stages
    scan what discovery actually found.
  - **`src/correlation.rs` + `src/evidence.rs` (Stage 4)** — `correlate`
    deduplicates findings by normalized identity and boosts confidence on
    independent cross-tool corroboration; `capture` records a SHA-256 +
    provenance `EvidenceRecord` per tool run for chain-of-custody. An nmap
    XML parser was also added to `ingest.rs`.

  All modules are zero-dependency, total/bounded over untrusted tool output,
  and pass the full `clippy::pedantic` + `clippy::nursery` gate with unit
  tests.
- **`src/orchestrator.rs` — a tool orchestrator that turns an
  `ExecutionPlan` into an ordered, deduplicated `OrchestrationSchedule`.**
  The coordinator's plan says *what is authorized* but not *what order to
  run in*, and its per-target tasks can name the same tool for the same
  target more than once (a target matched by two specialists, overlapping
  toolchain packs). `ToolOrchestrator::schedule` closes that gap with two
  guarantees: it orders steps **least-invasive first** — static local
  analysis before active network before active exploitation, via
  `registry::classify_execution` (now `pub`, the same name-based classifier
  the catalog stamps every `ToolDefinition` with) — so read-only work can
  surface a blocker before any traffic reaches a live target and
  exploitation is always last; and it schedules each `(target, tool)` pair
  **exactly once**, keeping its first appearance. Ordering is a stable sort,
  so ties within a class keep plan order and a schedule is fully
  deterministic. This is an ordering/dedup layer, not a permission one — the
  `NetworkMode` egress gate in `src/execution.rs` still decides whether an
  active step may run at all. `execute_plan` now runs the schedule instead
  of iterating raw tasks, so real execution follows the safe order and never
  double-runs a tool against a target; `--plan-scan` prints the resulting
  `Execution Schedule` alongside the plan. Static-local steps never carry a
  network address (they operate on files, not targets), mirroring the
  argument-injection rule execution already applied.
- **`src/language_model.rs` — a hand-rolled Levenberg-Marquardt refinement
  pass (`lm_refine_attention`) for the self-attention projections.**
  Full-network LM isn't feasible here — it needs a dense `JᵀJ` over every
  trainable parameter (~18k of them), an 18k×18k matrix no hand-rolled code
  is inverting every step — and LM also needs a genuine sum-of-squares
  residual to operate on, which the softmax cross-entropy loss SGD trains
  against isn't. The model already has one, though: the residual VQ
  reconstruction error `‖spectral − quant‖²` from the DCT/VQ stage. After
  SGD trains the whole model as before, `bundled()` now runs a second,
  small phase that refines just the three `EMBED × EMBED` attention
  projections (300 parameters — small enough for a real, hand-rolled dense
  `JᵀJ` solve) against that objective, treating each window's VQ
  reconstruction as a fixed local target (the same straight-through
  treatment training already gives the discrete bottleneck elsewhere).
  Each iteration forms the Gauss-Newton normal equations (row `f`'s
  Jacobian comes from backpropagating a one-hot seed at `spectral[f]`
  through the DCT and then through the existing `attend_backward`, reused
  here as a vector-Jacobian-product primitive instead of a scalar-loss
  gradient), solves the damped system `h = -(JᵀJ + μI)⁻¹Jᵀr` via a
  hand-rolled Gauss-Jordan elimination, and only keeps the step if the
  *actual* error reduction tracks the *quadratic model's predicted*
  reduction closely enough (the gain ratio `q`) — shrinking the damping `μ`
  on a good step, growing it on a bad one, the classic trust-region
  heuristic. Because a step is only ever kept when it strictly reduced the
  reconstruction error, the pass can only leave it the same or lower than
  where it started, never higher — verified directly in
  `lm_refine_attention_never_increases_reconstruction_error`. The Jacobian
  construction itself is checked against central finite differences in
  `lm_normal_equations_jtr_matches_finite_differences`, and the dense
  solver against a known 3×3 system in `solve_damped_matches_a_known_system`.
  `trained_on`/`trained_staged` deliberately skip this pass, so the
  existing epoch-count comparison tests stay pure-SGD baselines; only
  `bundled()` (real CLI/`--ask`/anomaly-lens usage) gets the refined model.
  Startup cost rises from well under a second to about a second in a
  release build.
- **`src/language_model.rs` — a hand-rolled single-head self-attention layer
  over the `CONTEXT` window**, inserted between the embedding step and the
  DCT. Each position's query is matched (scaled dot-product) against every
  position's key — no causal mask, since all `CONTEXT` positions are
  already-known context for the token being predicted *after* the window —
  and the softmax-weighted mix of value vectors is added residually to the
  raw token embeddings before the DCT sees them. Unlike the DCT (a fixed
  linear transform applied the same way regardless of content), attention's
  query/key match is *learned and input-dependent*: which earlier positions
  matter most can change with what's actually in the window. Forward
  (`self_attend`) and backward (`attend_backward`, a free function so it can
  borrow the model's `attn_wq`/`attn_wk`/`attn_wv` immutably while the
  caller holds `&mut self`) are both fully hand-derived — no autodiff, no
  external crates — adding three new learned `EMBED × EMBED` projection
  matrices. `attend_backward`'s gradients are checked against central finite
  differences in a new test (`attend_backward_matches_finite_differences`) —
  the strongest available correctness signal for hand-rolled backprop math
  like this; two more tests confirm each attention row is a valid softmax
  and that training actually moves the projection weights away from their
  random initialization (rather than asserting non-uniformity against the
  initial state, which the random — not uniform — init could already
  satisfy on its own). All existing invariant tests (loss reduction,
  residual-VQ error, perplexity ordering) continued to hold with attention
  added, with no hyperparameter retuning needed.

### Changed
- **`src/language_model.rs` — temperature/top-`k` sampling in `generate()`,
  replacing pure greedy argmax decoding.** Each decoding step now
  temperature-sharpens the predicted distribution (`TEMPERATURE = 0.7`),
  keeps only its `TOP_K = 8` most probable tokens (ranked by weight with
  token id as an explicit tie-breaker, via `f32::total_cmp` rather than
  `partial_cmp`, so ties or a stray `NaN` can't make the ordering — and so
  the sampled token — depend on sort stability), and draws one proportional
  to those weights from a per-call `Rng` — so generation no longer always
  takes the single most probable next token, which was prone to short
  repetition loops. Determinism is preserved without needing
  caller-supplied entropy: the sampling `Rng` is seeded by hashing the
  prompt (a hand-rolled FNV-1a, `hash_prompt`), so the same prompt always
  draws the same sequence of samples and yields the same continuation,
  while different prompts land on different (still reproducible) draws.
  `LanguageModel::generate`'s trait doc no longer promises "greedy
  decoding"; `--llm-generate`'s doc comment and the README's
  built-in-language-model section are updated to match (`ask_generate`'s
  doc comment never mentioned greedy decoding, so it is unchanged).
- **`src/language_model.rs` — a bigger, richer bundled corpus and more model
  capacity.** `SECURITY_CORPUS` grows from 20 to 52 sentences, adding
  vocabulary and phrasing for topics the original corpus didn't cover
  (recon, web/cloud/mobile findings, social engineering, anomaly language,
  reporting and generation verbs, governance and compliance terms) — partly
  chosen to overlap with `src/nlu.rs`'s intent-router trigger words and
  example phrasings, so `embed_text`'s semantic-similarity signal has more
  of the agent's own vocabulary to draw on. Embedding width, hidden width,
  and the VQ codebook size (`EMBED` 8→10, `HIDDEN` 24→28, `CODES` 48→56) grow
  to match the larger vocabulary (roughly 130 → 300 tokens); `EPOCHS` drops
  150→55; because the bigger corpus yields far more training windows per
  epoch, total gradient exposure is comparable to before. Training remains
  fully deterministic, in-process, and under a second in a release build.
  The `residual_quantization_lowers_error_and_loss` test's reconstruction-
  error check now compares *relative* error (unexplained energy over total
  spectral energy) rather than raw squared error: the one- and two-stage
  models are trained independently, and a bigger vocabulary gives the
  embeddings more incentive to spread out for softmax separability, so their
  raw spectral magnitudes differ enough that an unnormalized comparison
  stopped being meaningful — the normalized version is what "reconstructs
  more accurately" was always meant to test.
- **Identity updated from purely defensive to defensive/offensive.** The
  agent's mission statement, package description, and every user-facing
  description of its scope (README, `OPERATING_GUIDE.md`, the embedded
  `security-agent` skill, the `--tui` banner, and the `--ask` router's
  out-of-scope decline message) now describe it as a **defensive and
  offensive** security orchestration agent for authorized vulnerability and
  **penetration** testing, reflecting the online-opt-in execution path
  (`--allow-network`, added earlier) that already lets it orchestrate real,
  installed offensive (`ActiveNetwork`/`ActiveExploitation`) tools under
  authorization and audit. This is a naming/documentation update, not a new
  capability or a loosened control — authorization, scope, and the online
  opt-in are unchanged.

### Added
- **`scripts/deploy.sh` (`make deploy`)** — a release/packaging script for
  the CLI binary. Runs the exact CI quality gate (fmt, clippy pedantic +
  nursery, tests), builds an optimized `--release` binary (optionally
  cross-compiled via `--target`), and packages it with `README.md` and
  `LICENSE` into a checksummed `dist/security-agent-<version>-<triple>.tar.gz`
  (`.sha256` alongside it). Console styling follows this org's other
  launch/verify scripts: a plain colored title, light `━━ … ━━` section
  rules, a ✓/✗/○ (pass/fail/skip) glyph system, and a flat `====`-divided
  completion block ending in version/target/binary/archive/checksum/elapsed
  facts; colors auto-disable off a terminal or via `--no-color`/`NO_COLOR`.
  `--skip-checks` allows a fast repackage of already-verified code. Pure
  POSIX-ish bash, no new dependency.
- **`--tui` interactive terminal UI** — a menu- and chat-bar-driven REPL
  over every existing command, added entirely with `std::io` (no new
  dependencies). A numbered menu covers every agent function (status, about,
  tools/skills, running built-in and real external tools, planning a scan,
  recording findings, viewing the audit log, scheduling a retest, and
  prompting the built-in language model for generation or anomaly scoring);
  typing anything else at the prompt is a **chat bar** routed through the
  same grounded `--ask` router, including direct language-model prompting.
  Menu option `0`/`help` prints a **capability summary page**: every
  function, its CLI command, and — where the chat bar can run it — a
  plain-English example. Every menu choice calls the identical private
  command function the plain CLI dispatches to (`src/main.rs`), so behavior,
  including the `--allow-network` offline/online gating, is identical either
  way; no business logic is duplicated. Exits cleanly at end-of-input, so it
  is fully scriptable and covered by both unit tests (the pure banner/menu/
  capability-page text) and CLI integration tests (`tests/cli.rs`) that pipe
  scripted stdin into the real binary.
- **`src/network_policy.rs` — offline-by-default / online opt-in egress
  governance.** A new `NetworkMode` is threaded into the execution path so the
  runtime performs no live-target or network activity unless the operator
  explicitly opts in *for that invocation* with `--allow-network`. Offline
  (the default) runs only the built-in substitutes and `StaticLocalAnalysis`
  tools; the opt-in additionally unlocks the real, installed `ActiveNetwork`
  and `ActiveExploitation` tools, giving authorized engagements full tool
  scope. `--run-external-tool [--allow-network] <tool> <args>` and
  `--plan-scan … [--allow-network] --execute …` both honor it, an online-mode
  banner is emitted to stderr when engaged, and `--offline-status` now reports
  `default_network_mode=offline` and `online_opt_in_flag=--allow-network`.

### Changed
- **Live tool execution is now gated by the online opt-in rather than a
  hardcoded allowlist.** `src/execution.rs` replaces the `nmap`/`masscan`
  `WIRED_DESPITE_EXECUTION_CLASS` exception with the general `NetworkMode`
  gate: `StaticLocalAnalysis` tools still run offline, while any live
  `ActiveNetwork`/`ActiveExploitation` tool runs only under `--allow-network`.
  Going online never bypasses the coordinator's authorization policy (scope,
  technique allow-list, deny-lists, approval gates, time window). The agent
  still only spawns real installed binaries — it does not reimplement any
  tool's offensive behavior in-house. The `ToolExecutionError::NotEligibleForExecution`
  variant is renamed `RequiresOnlineMode` with a message that points to the
  opt-in.
- **`src/local_analyzers.rs`** — four new offline, in-house forensic
  substitutes that make more of the cataloged tools executable locally with
  no network and no external crates, extending the built-in-substitute
  pattern (`--run-tool <name> <path>`): **binwalk** (embedded magic-signature
  map plus high-entropy region sweep of a firmware image or blob),
  **foremost** (file carving by header, bounded by a footer where the format
  defines one), **bulk_extractor** (indicator-of-compromise extraction —
  emails, URLs, IPv4 addresses — from printable content), and **hashdeep**
  (recursive SHA-256 + hand-rolled CRC-32 audit of a directory tree with
  duplicate-digest detection). All four are defensive analyzers over local
  evidence; the offensive (`ActiveExploitation`) and live-network
  (`ActiveNetwork`) catalog tools are deliberately not reimplemented as
  in-house executables. `built_in_substitute_tools` rises from 3 to 7.
- **`src/language_model.rs`** — a small, from-scratch **neural** language
  model with a *vector-quantized temporal-frequency* architecture: it embeds
  the recent token window into a multi-channel time signal, applies a DCT-II
  along the time axis (temporal → frequency), vector-quantizes the spectral
  features against a learned codebook (VQ-VAE style: nearest-code lookup,
  straight-through estimator, commitment penalty), and predicts the next
  token through a tanh hidden layer and softmax. Trained deterministically by
  SGD on a compact security corpus compiled into the binary — no external
  crates, no network, no weights on disk; the DCT, codebook search, and
  forward/backward passes are all hand-rolled. Exposes generation and
  perplexity through a `LanguageModel` trait (the seam for a heavier back-end
  later), surfaced via `--llm-generate` and `--llm-perplexity`.
- **Residual vector quantization** in the language model — a *residual path
  around the quantizer*: the spectral features are quantized against a stack
  of codebooks where each stage encodes the residual the previous stage left
  behind, and the final code is the sum of the per-stage codes (`q = q1 +
  q2`). This roughly halves the reconstruction error a single codebook
  leaves while keeping the discrete bottleneck; a regression test asserts the
  two-stage error is lower than one stage.
- **`src/anomaly.rs`** — the language model's perplexity signal looped back
  into the cognitive layer as an anomaly lens. During a `--cognitive-review`
  with `--memory`, each prior finding's text is scored, and out-of-domain
  text (high perplexity, or unscorable — e.g. encoded payloads, injected
  markup, non-English noise stuffed into third-party tool output) is flagged
  most-surprising-first in the plan's review output. Advisory only: it never
  changes authorization or execution.
- **`--ask` command and `src/nlu.rs`** — a grounded, fully-local
  plain-English intent router. It maps an instruction to one of the agent's
  real capabilities using lexical anchoring against each capability's trigger
  vocabulary (and recognition of the agent's own tool/skill names) plus
  semantic similarity in the model's learned embedding space to rank
  paraphrases, then prints the understood intent, a confidence, and a
  plain-English reply before carrying out the action. Routing is scoped to
  defensive security (off-topic requests decline as `out-of-scope`), and
  `--ask` executes only the read-only, no-authorization intents — anything
  requiring an engagement, a log, or authorization is explained, not run, so
  plain English cannot widen the agent's authority.
- **`src/calibration.rs`** — confidence-calibration tracking for the
  cognitive layer. `CalibrationTracker` accumulates predicted-vs-realized
  outcomes and computes the Brier score, reliability bins, expected
  calibration error, an over/under-confidence tendency, and a histogram
  recalibration. `CognitiveEngine` scores its *prior* (type-based)
  predictions non-circularly against the findings recorded in memory and
  reports the result in the deliberation.
- **`src/belief_propagation.rs`** — noisy-OR compromise-risk propagation
  across a directed attack graph, so a node's risk reflects the weaknesses
  of everything that can reach it (lateral movement). The deliberation now
  shows per-asset `P(compromise)`, and a finding-free asset adjacent to a
  compromised one surfaces as at-risk.
- **`--about` command** (alias `--version`) — surfaces the package version,
  `MISSION_STATEMENT`, and the four `ROADMAP_PHASES`, which were exported
  but shown by no command.
- **Toolchain-pack deprecation lifecycle** — `ToolchainPackRegistry::deprecated_packs()`
  enumerates deprecated packs, `ExecutionPlan`'s display renders
  `- <name> (DEPRECATED -> <replacement>)`, and `mobile-backend-pack` is
  now marked deprecated in favor of `api-core-pack` (a mobile backend is an
  API surface). The previously inert `deprecated`/`replacement_pack` fields
  now drive real behavior.
- **`tests/cli.rs`** — black-box integration suite exercising the compiled
  binary across `--offline-status`, `--about`, `--list-skills`,
  `--show-skill`, `--list-tools`, an unknown command, and `--plan-scan`
  (success and authorization-denied), using only built-in assets and temp
  files.
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
- **Closed the calibration self-correction loop.** Confidence calibration
  now feeds back into live reasoning: each target's reported hypothesis
  confidence is corrected through `CalibrationTracker::calibrated_percent`,
  using calibration supplied to the engine
  (`CognitiveEngine::with_calibration`) plus **leave-one-out** evidence from
  the other targets in the run — never the target's own outcome, so the
  correction stays non-circular. Calibration adjusts how sure the agent is,
  not which technique is likeliest, and the reasoning chain annotates a
  corrected value (`[calibration-adjusted from N%]`). New helper
  `cognition::recalibrate_hypotheses`.
- **Unified the findings-persistence format.** `--memory`,
  `--findings-log`, `--record-findings`, and `--schedule-retest` now all
  use the single `finding_record` JSON Lines format (`src/findings_log.rs`).
  Previously `--memory` read a separate `serde`-JSON format written by
  `--record-findings`, so a `--findings-log` output silently failed to load
  as `--memory` input. `src/memory_store.rs` is now a thin bridge that
  folds the findings log into `CognitiveMemory`, and a scan's
  `--findings-log` output is valid `--memory` input directly — closing the
  intelligence loop end to end.
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

### Removed
- **`serde`, `serde_json`, and `anyhow` dependencies.** They were used only
  by the now-removed second findings format (`anyhow` was entirely unused),
  so `[dependencies]` is empty again and the crate uses no external runtime
  crates — matching its in-house JSON/SHA-256/PCAP design. Removed the
  `serde` derives on `Finding`/`Severity` and the stale `changelog`
  `Cargo.toml` manifest key.

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
