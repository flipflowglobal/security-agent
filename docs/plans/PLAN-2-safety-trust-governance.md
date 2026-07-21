# Plan 2 — Safety, Trust & Governance Hardening

| | |
|---|---|
| **Priority** | P1 — raises the trust floor of real tool execution; complements Plan 1 |
| **Primary owner** | Security/Rust engineer |
| **Depends on** | Independent of Plan 1 and Plan 3. Sub-feature C (read-only view) reads Plan 1's findings log **if present**, but degrades gracefully to the audit log if Plan 1 has not shipped. |
| **Est. effort** | 3–5 engineering days |
| **Quality bar** | `cargo fmt --check` clean · `cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::nursery` clean · `cargo test` green · zero external crates |

---

## 1. Why this plan exists (problem statement)

Real execution exists (`src/execution.rs`) and is honestly documented as "arguments trusted as-is" (`src/execution.rs:16-21`), but four trust/governance affordances that the data model already anticipates are still inert:

- **No intensity ceiling on network tools.** `nmap` is wired via `WIRED_DESPITE_EXECUTION_CLASS` (`src/execution.rs:122`) with "no additional rate-limiting" — `-T5 --min-rate 100000` against a `max_intensity=Passive` engagement is accepted silently.
- **`signed` / `vulnerability_reviewed` are dead.** `ToolDefinition` (`src/registry.rs:421-429`) carries both booleans; every construction site hardcodes `false` (`src/registry.rs:461-462`, `src/registry.rs:476-477`). Nothing verifies the local binary.
- **`Role::Viewer` is unreachable.** Defined and parseable (`src/governance.rs:9`, `src/governance.rs:32`) but no CLI path ever assigns it — there is no read-only command.
- **The execution allowlist is single-entry.** `WIRED_DESPITE_EXECUTION_CLASS = &["nmap"]` — `masscan`, architecturally identical (fast port scanner, discrete targets, local binary), is not wired even though its skill and catalog entry exist.

### Exact report items addressed by this plan

6. **Soft nmap/network intensity ceiling.**
7. **Tool signature verification** (`signed` / `vulnerability_reviewed`).
8. **`Role::Viewer` usage** via a read-only view command.
12. **Expand `WIRED_DESPITE_EXECUTION_CLASS` to `masscan`.**

---

## 2. Sub-feature A — Soft intensity ceiling for network tools

### A.1 Design decision: warn, do not reject
Per the operating model ("Trust the operator's arguments as-is"), this is a **non-blocking advisory**, not a new hard gate. It surfaces a mismatch between the engagement's declared `max_intensity` (`src/model.rs:193`, `EngagementProfile.max_intensity`) and aggressive flags in the operator's args, without changing exit codes. This keeps the existing 7-gate authorization model (in `src/policy.rs`) untouched — the ceiling is an observation, not an eighth gate.

### A.2 New module `src/intensity_guard.rs`
```rust
use crate::model::TestIntensity;

/// An advisory about operator arguments that appear more aggressive than
/// the engagement's declared ceiling. Never blocks execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntensityAdvisory {
    pub flag: String,             // the offending token, e.g. "-T5"
    pub declared_ceiling: TestIntensity,
    pub message: String,
}

/// Scans `arguments` for tokens whose aggressiveness exceeds `ceiling`.
/// Returns one advisory per offending token (empty when clean). Pure and
/// side-effect free so it is trivially testable.
#[must_use]
pub fn advise(arguments: &[String], ceiling: TestIntensity) -> Vec<IntensityAdvisory>;
```

### A.3 Rules (first tranche, nmap/masscan vocabulary)
Encode a small table mapping tokens → the minimum intensity at which they are "expected":

| Token pattern | Expected minimum ceiling |
|---|---|
| `-T4`, `-T5`, `--min-rate`, `--min-parallelism`, `--max-rate` (nmap) | `Aggressive` |
| `--rate` above a threshold, `-p-` full-range (masscan/nmap) | `Standard` |
| everything else | `Passive` (no advisory) |

`advise` emits an advisory when the token's expected minimum `>` `ceiling` (uses the existing `TestIntensity: Ord` derive at `src/model.rs:142`). For `--min-rate N`/`--rate N`, parse the numeric operand (next token) and threshold it; if unparseable, do not warn (fail quiet, never panic).

### A.4 Integration points (advisory only)
- `src/main.rs` `run_external_tool_command` (`src/main.rs:169-193`): after resolving the tool, if `tool.definition.execution_class != StaticLocalAnalysis`, print each advisory to **stderr** before running. There is no engagement profile here, so default the ceiling to `Standard` (the CLI-direct path has no declared engagement).
- `src/main.rs` `plan_scan` `--execute` path (`src/main.rs:281-284`): here the `EngagementProfile.max_intensity` **is** known — thread it into `execute_plan` (or compute advisories in `plan_scan` before calling `execute_plan`) and print advisories with the real declared ceiling.

### A.5 Tests (`src/intensity_guard.rs`)
- `flags_t5_against_passive_ceiling` → one advisory.
- `no_advisory_for_t5_against_aggressive_ceiling` → empty.
- `parses_min_rate_operand_and_thresholds` → advisory for `--min-rate 100000` at `Standard`.
- `unparseable_operand_does_not_warn` → `--min-rate abc` → empty, no panic.
- `clean_args_yield_no_advisories`.

---

## 3. Sub-feature B — Offline tool signature/integrity verification

### B.1 Current state
`ToolDefinition.signed` and `ToolDefinition.vulnerability_reviewed` (`src/registry.rs:425-426`) are always `false`. `LocalTool` (`src/local_assets.rs`) resolves an `executable: Option<PathBuf>` on `PATH` but never hashes it. The crate already has a tested, in-house SHA-256 (`src/builtin_tools.rs`, KATs at `src/lib.rs` and used by autopsy) — **reuse it**; do not add a crate.

### B.2 Design — a bundled integrity manifest
- Add a bundled, compiled-in manifest file `assets/tool_integrity.txt`, loaded via `include_str!` exactly like the 90 skill files (pattern in `src/local_assets.rs`). Format: line-oriented `name=sha256hex` (zero-dependency, same spirit as the engagement config parser). Ship it empty-but-documented initially; entries are added as tools are vetted.
- New module `src/integrity.rs`:
```rust
pub struct IntegrityManifest { entries: std::collections::BTreeMap<String, String> }

impl IntegrityManifest {
    #[must_use] pub fn bundled() -> Self;                       // parses include_str! manifest
    #[must_use] pub fn expected_sha256(&self, tool: &str) -> Option<&str>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityStatus {
    Verified,        // manifest entry present AND local binary hash matches
    Mismatch,        // entry present, hash differs  ← execution should refuse
    Unpinned,        // no manifest entry (current default for all tools)
}

/// Hashes the tool's resolved executable with the crate's SHA-256 and
/// compares against the manifest.
#[must_use]
pub fn verify(tool: &LocalTool, manifest: &IntegrityManifest) -> IntegrityStatus;
```

### B.3 Wire into execution and the model
- In `run_external_tool` (`src/execution.rs:141`), after the `NotInstalled`/`NotEligibleForExecution` checks (`src/execution.rs:147-152`) and before spawn (`src/execution.rs:155`), compute `verify(...)`. On `IntegrityStatus::Mismatch`, return a **new error variant** `ToolExecutionError::IntegrityMismatch { tool, expected, actual }` (add to the enum at `src/execution.rs:38-50` and its `Display` at `:52-68`). `Unpinned` and `Verified` both proceed (do not break the current default where nothing is pinned).
- Populate `ToolDefinition.signed` / `vulnerability_reviewed` meaningfully: set `signed = IntegrityStatus::Verified` at asset-resolution time in `src/local_assets.rs` where `LocalTool` is built, or expose the status on `LocalTool` and keep `ToolDefinition` describing catalog intent. **Recommended:** add `pub integrity: IntegrityStatus` to `LocalTool` (runtime fact) and leave `ToolDefinition.signed` as catalog metadata that the manifest can flip to `true` for vetted tools. Document the distinction in the module doc.
- Reflect verified/mismatch/unpinned counts in `--list-tools` (`src/main.rs:86-104`) and `--offline-status` (`src/main.rs:36-51`, add a `signature_verified_tools=N` line).

### B.4 Tests
- `integrity.rs`: `verifies_matching_hash`, `flags_mismatch`, `reports_unpinned_for_absent_entry`, `manifest_parses_name_equals_hash_lines`, `manifest_ignores_comments_and_blanks`.
- `execution.rs`: `rejects_execution_on_integrity_mismatch` — construct a `LocalTool` pointing at `/bin/true` with a manifest entry of a wrong hash → `Err(IntegrityMismatch)`. `unpinned_tool_still_executes` — regression guard that the default (empty manifest) path is unchanged, so all existing execution tests keep passing.

### B.5 Docs
- `README.md`: new "Tool integrity" section — how to add a vetted tool's hash to `assets/tool_integrity.txt`, what `Verified`/`Unpinned`/`Mismatch` mean, and that unpinned is the safe default.

---

## 4. Sub-feature C — `Role::Viewer` and read-only view commands

### C.1 Design
Introduce genuinely read-only commands whose natural actor role is `Viewer` (`src/governance.rs:9`). These never plan, execute, authorize, or write — they only load and render existing artifacts, closing the "Viewer is defined but unreachable" gap.

### C.2 New commands (`src/main.rs` dispatch, `src/main.rs:18-33`)
- `--view-audit <audit-log>.jsonl` — `load_audit_records` (`src/audit_log.rs:62`), render a table (timestamp, actor, role, action, target). Read-only.
- `--view-findings <findings-log>.jsonl` — if Plan 1 shipped, `load_findings` and render by severity; **if Plan 1 has not shipped**, gate this behind the file existing and print a clear "findings log format not yet supported" — OR defer this arm entirely to Plan 1's Sub-feature D.2 (`--schedule-retest` already reads findings). **Coordination note:** to avoid overlap, this plan owns `--view-audit` (always buildable now); `--view-findings` is deferred to whichever plan ships the findings log first.

### C.3 Where `Viewer` gets assigned
- Any audit record these read commands themselves might emit (if you choose to log "someone viewed the audit trail") must use `Role::Viewer`. Recommended: **do not** write audit records from read paths (keep them pure reads); instead, assert the role's reachability with a dedicated unit test and use `Viewer` as the documented role for read-only API consumers in `README.md`'s RBAC section. If a read path is later made to emit a record, `Role::Viewer` is the correct actor — document this explicitly next to the enum (`src/governance.rs:9`).

### C.4 Tests (`src/main.rs`)
- `view_audit_reads_a_written_log` — write via `append_audit_records`, invoke `view_audit_command` helper (returns `ExitCode`, testable like `plan_scan`), assert `ExitCode::SUCCESS`.
- `view_audit_reports_failure_for_missing_file`.
- `governance.rs` already tests `Role::Viewer` round-trips (`src/governance.rs:91-101`); add a comment there pointing at the read-only consumer as its assigned use.

---

## 5. Sub-feature D — Add `masscan` to the execution allowlist

### D.1 Change
- `src/execution.rs:122`: `const WIRED_DESPITE_EXECUTION_CLASS: &[&str] = &["nmap", "masscan"];`
- `classify_execution` (`src/registry.rs:437-452`) keeps `masscan` in the default `ActiveNetwork` arm — **do not** move it to `StaticLocalAnalysis`. The allowlist is deliberately the only mechanism that grants execution to a non-static tool, so the class counts (34 static / 11 exploitation / 44 network) in the test at `src/registry.rs:583-616` **stay unchanged**. Confirm that test still passes untouched.
- Because masscan is far more aggressive than nmap by default (it can saturate a link), **couple this to Sub-feature A**: masscan execution must run the intensity advisory. Note this dependency in the commit message.

### D.2 Tests (`src/execution.rs`, mirror the nmap test at `:432-445`)
- `masscan_is_eligible_for_real_execution_despite_being_active_network` — `tool_named("masscan", "/bin/true", ActiveNetwork)` → `Ok`, `report.tool == "masscan"`.
- Keep `rejects_other_active_network_tools_not_on_the_explicit_allowlist` (`src/execution.rs:417-430`) green — pick a still-excluded tool (e.g. `hydra`) so the test remains a valid negative.

### D.3 Skill doc updates
- `.github/skills/masscan/SKILL.md`: update "Execution status" to describe real execution (mirror the nmap skill at `.github/skills/nmap/SKILL.md:28-30`), and add `execution_exception: "true"` to its front-matter metadata (mirror `.github/skills/nmap/SKILL.md:9`).
- `.github/skills/nmap/SKILL.md`: update the sentence "`nmap` is the only entry today" implications if referenced elsewhere; verify the `WIRED_DESPITE_EXECUTION_CLASS` doc-comment (`src/execution.rs:116-121`) is updated to say "nmap and masscan."

---

## 6. Execution order (strict)

1. **A** — `src/intensity_guard.rs` (pure, no integration risk). Ship + test.
2. **D** — masscan allowlist + skill docs, **wired to A's advisory**. Ship + test.
3. **B** — `src/integrity.rs` + manifest + execution gate + `--list-tools`/`--offline-status` counts. Ship + test.
4. **C** — `--view-audit` read-only command + `Viewer` documentation. Ship + test.
5. Full gate (Section 8). One logical commit per sub-feature.

---

## 7. Definition of Done

- [ ] Aggressive network flags against a low declared ceiling print a non-blocking advisory on stderr; exit codes are unchanged.
- [ ] `masscan` executes through the reviewed allowlist path; the 34/11/44 execution-class partition test is untouched and green.
- [ ] A bundled integrity manifest exists; a hash mismatch **refuses** execution with a typed error; unpinned tools (the default) still execute exactly as before.
- [ ] `signed`/`vulnerability_reviewed` (or a new `LocalTool.integrity`) reflect real verification state, surfaced in `--list-tools` and `--offline-status`.
- [ ] `Role::Viewer` is assigned by a real read-only path (`--view-audit`) and/or documented as its consumer with a reachability test.
- [ ] No existing test deleted or weakened; every current execution test still passes.

---

## 8. Quality gate (run after every sub-feature)

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::nursery
cargo test
```

---

## 9. Risks, edge cases, rollback

- **Advisory scope creep** — resist turning the intensity guard into a hard gate; the operating model explicitly trusts operator args. Keep it stderr-only. If a hard ceiling is later wanted, it belongs in `src/policy.rs` as a real eighth gate with its own `AuthorizationError` variant, decided separately.
- **Integrity manifest false-positives** — a legitimately updated binary will hash-mismatch. That is the intended signal, but the default must stay `Unpinned` so an empty/partial manifest never blocks day-to-day use. Never ship non-empty entries without a documented provenance.
- **Hashing cost** — hashing a large binary on every run adds latency. Acceptable for the current synchronous model; note it and cap/skip for binaries above a size threshold if it becomes an issue.
- **masscan aggressiveness** — the whole reason D is coupled to A. Do not ship D without A in the same PR.
- **Rollback** — each sub-feature is an additive module + additive enum variant/field; revert one commit to remove it. The masscan allowlist change is a one-line revert.

## 10. Explicitly out of scope for Plan 2
- Cryptographic signature verification (GPG/sigstore) — this plan does offline SHA-256 pinning only; real signing infrastructure is a separate design.
- A full RBAC enforcement layer — `Viewer` is surfaced and documented here, not turned into an access-control system.
- Rate-limiting network tools at the packet level — advisory only; no traffic shaping.
