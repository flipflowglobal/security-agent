# Plan 1 — Close the Intelligence Loop (Findings → Risk → Persistence → Retest)

| | |
|---|---|
| **Priority** | P0 — highest business value; completes the core purpose of the agent |
| **Primary owner** | Backend/Rust engineer (feature) |
| **Depends on** | Nothing. Can start immediately. Plan 2 and Plan 3 are independent. |
| **Est. effort** | 4–6 engineering days (4 sub-features, each independently shippable) |
| **Quality bar** | `cargo fmt --check` clean · `cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::nursery` clean · `cargo test` green · zero external crates |

---

## 1. Why this plan exists (problem statement)

Today the agent can **authorize**, **plan**, and **execute** real tools, but the output of that execution goes nowhere. In `src/main.rs:281-286` and `src/execution.rs:246-265`, `execute_plan` returns a `Vec<TaskExecutionOutcome>` whose `stdout`/`stderr` are printed to the terminal (`src/main.rs:304`) and then discarded. Meanwhile the crate already contains a fully-built, fully-tested intelligence layer that **nothing calls from any runtime path**:

- `src/findings.rs` — `Finding` struct + `RiskScoreCalculator::normalized_score(...)`.
- `src/advanced.rs:28` — `AttackPathGraph::build_from_findings(&[Finding])`.
- `src/advanced.rs:68` — `propose_retest_schedule(&Finding, now_epoch_seconds)`.
- `src/compat.rs:279` — `JsonLineAdapter::import_finding_hint(...)` already parses a `finding_hint` envelope into a `Finding`, but hardcodes `Severity::Medium` and `normalized_risk_score: 0.0` (`src/compat.rs:301-306`), and is only exercised by a unit test (`src/lib.rs:883-887`).

**The gap:** there is no path from "a tool produced output" to "a scored, persisted `Finding` that can drive a retest schedule." This plan builds that path end-to-end.

### Exact report items addressed by this plan

1. **Finding ingestion from tool output** — parse `ToolExecutionReport.stdout` into `Finding` structs.
2. **Finding persistence** — a `src/findings_log.rs` analogous to `src/audit_log.rs`.
3. **`Target.network_address` field** — let the engagement config bind a resolvable address per target and auto-inject it into network tool invocations.
4. **Retest scheduler surfaced** — a `--schedule-retest` command that reads persisted findings and calls the existing `propose_retest_schedule`.

---

## 2. Sub-feature A — Finding ingestion from tool output

### A.1 Current state
- `run_external_tool` (`src/execution.rs:141`) returns `ToolExecutionReport { tool, arguments, exit_code, stdout, stderr, duration }` (`src/execution.rs:72-80`).
- `Finding` (`src/findings.rs:10-20`) needs: `finding_id`, `source_tool`, `title`, `target_id`, `severity`, `confidence_percent: u8`, `remediation_playbook`, `normalized_risk_score: f32`.
- `RiskScoreCalculator::normalized_score(severity, confidence_percent, exploitability_validated) -> f32` (`src/findings.rs:26`) already exists and is tested (`src/lib.rs:832-841`). **Reuse it — do not reimplement scoring.**

### A.2 Target design — new module `src/ingest.rs`
Create a dependency-free ingestion layer with one **parser trait** and one **parser per supported tool**, plus a dispatcher keyed on tool name.

```rust
//! Parses raw external-tool output (ToolExecutionReport) into scored Findings.

use crate::execution::ToolExecutionReport;
use crate::findings::{Finding, RiskScoreCalculator, Severity};

/// A parser that knows how to turn one tool's stdout into Findings.
pub trait FindingParser {
    /// The cataloged tool name this parser handles (e.g. "semgrep").
    fn tool_name(&self) -> &'static str;
    /// Parse `report.stdout` for `target_id`. Returns `Vec::new()` when the
    /// output contains no findings (a clean run is not an error).
    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding>;
}

/// Selects the right parser for `report.tool` and runs it. Tools with no
/// registered parser return an empty Vec (their output is still available
/// in the ToolExecutionReport for the operator, just not auto-ingested).
#[must_use]
pub fn ingest(target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> { /* ... */ }
```

### A.3 First tranche of parsers (ship these; defer the rest)
Choose tools whose output is **deterministic, local, and machine-readable**, so tests do not need the binary installed (they parse fixed sample strings):

| Parser | Input format | Notes |
|---|---|---|
| `SemgrepJsonParser` | `semgrep --json` results array | Map `extra.severity` (`ERROR`/`WARNING`/`INFO`) → `Severity`; `check_id` → `title`; `path:line` into `remediation_playbook`. |
| `SarifParser` | Generic SARIF `runs[].results[]` | Covers any SARIF-emitting tool (nuclei `-sarif`, others). `level` (`error`/`warning`/`note`) → `Severity`. |
| `GenericJsonLinesParser` | One JSON object per line | Fallback for tools emitting JSONL; requires `severity` + `title` keys. |

- **JSON parsing:** reuse the hand-rolled parser primitives already in `src/compat.rs` (`parse_json_string`, `parse_json_string_object`, `skip_whitespace`, `expect_char`, `parse_hex4`). **Before writing a new JSON reader, refactor these primitives out of `compat.rs` into a new `src/json.rs` submodule** and have both `compat.rs` and `ingest.rs` depend on it. This keeps the zero-dependency stance and avoids a second, divergent JSON parser. Expand it minimally to handle arrays, numbers, booleans, and `null` (currently it only reads objects of string→string).
- **Scoring:** every parser fills `normalized_risk_score` by calling `RiskScoreCalculator::normalized_score(severity, confidence_percent, exploitability_validated)`. Static-analysis findings pass `exploitability_validated = false`. Never set the score by hand.
- **`finding_id`:** deterministic and stable — `format!("{tool}-{target_id}-{n}")` where `n` is the 0-based index within that report, so re-ingesting the same output is idempotent (important for the dedup logic in Sub-feature B).

### A.4 Severity mapping helper
Add one shared `fn severity_from_label(label: &str) -> Severity` in `src/findings.rs` (near the `Severity` enum), covering the union of vocabularies (`critical/high/medium/low/info`, `error/warning/note`, semgrep's `ERROR/WARNING/INFO`). Unknown labels map to `Severity::Informational` (fail safe toward low noise, never panic). Add a `#[derive(Default)]`? No — keep explicit. Unit-test every mapping.

### A.5 Tests (in `src/ingest.rs`, `#[cfg(test)]`)
- `semgrep_json_parses_two_findings_with_correct_severities` — feed a fixed 2-result semgrep JSON string; assert 2 findings, correct `Severity`, `source_tool == "semgrep"`, non-zero `normalized_risk_score`.
- `sarif_parser_maps_levels` — one SARIF blob with error+warning+note; assert 3 findings and correct severities.
- `clean_run_yields_no_findings` — empty results array → `Vec::new()`.
- `unknown_tool_returns_empty_vec` — a report from `"nmap"` (no parser) → empty.
- `finding_ids_are_stable_and_indexed` — same input twice → identical `finding_id`s.
- `malformed_json_is_ignored_not_panicked` — truncated JSON → empty vec, no panic.

---

## 3. Sub-feature B — Finding persistence (`src/findings_log.rs`)

### B.1 Template to copy
`src/audit_log.rs` is the exact pattern. It exposes `append_audit_records(path, &[AuditRecord])` (`src/audit_log.rs:38`) and `load_audit_records(path)` (`src/audit_log.rs:62`), using the `CompatibilityEnvelope` wire format and skipping non-matching lines on load. Mirror it precisely.

### B.2 Wire-format bridge (extend `src/compat.rs`)
Add, alongside `audit_record_to_envelope`/`envelope_to_audit_record` (`src/compat.rs:196-239`), a new pair using a **new `payload_kind = "finding_record"`** (distinct from the existing lossy `"finding_hint"`, which stays for the integration-adapter use case):

```rust
#[must_use]
pub fn finding_to_envelope(finding: &Finding) -> CompatibilityEnvelope;   // serializes ALL 8 fields
#[must_use]
pub fn envelope_to_finding(envelope: &CompatibilityEnvelope) -> Option<Finding>; // inverse; None on wrong kind/missing field
```

- Serialize `severity` via a new `Severity: Display + FromStr` impl (add to `src/findings.rs`, following the `Role`/`TargetType` pattern in `src/governance.rs:12` and `src/model.rs:35`). This is required for the round-trip and reused by the view command in Plan 2.
- Serialize `normalized_risk_score` with `{:.4}` and parse back with `f32::from_str`; add a round-trip test tolerant to that precision.

### B.3 New module `src/findings_log.rs`
```rust
pub enum FindingsLogError { Io(std::io::Error) }        // mirror AuditLogError
pub fn append_findings(path: &Path, findings: &[Finding]) -> Result<(), FindingsLogError>;
pub fn load_findings(path: &Path) -> Result<Vec<Finding>, FindingsLogError>;
```
- Append-only, `OpenOptions::new().create(true).append(true)` — identical guarantees to the audit log.
- `load_findings` skips lines whose envelope `payload_kind != "finding_record"` (reuses `CompatibilityEnvelope::from_wire_format` + `envelope_to_finding`), so a mixed log never blocks loading.

### B.4 Re-exports & tests
- Add to `src/lib.rs` (near line 24): `pub use findings_log::{FindingsLogError, append_findings, load_findings};` and register `pub mod findings_log;` (near line 9).
- Tests mirroring `src/audit_log.rs:106-164`: `appends_and_loads_round_trip`, `appending_twice_preserves_earlier_findings`, `load_skips_non_finding_lines`, `load_reports_io_error_for_missing_file`, `append_creates_file_if_absent`.

---

## 4. Sub-feature C — `Target.network_address` and auto-injection

### C.1 Current state & blast radius
`Target` (`src/model.rs:199-204`) is `{ id, target_type, criticality }`. Adding a field is a **breaking change to every struct literal**. Enumerate them before editing:

```bash
rg -n 'Target\s*\{' src/     # engagement_config.rs, coordinator tests, and ~12 lib.rs tests
```

### C.2 Design
- Add `pub network_address: Option<String>` as the **last** field of `Target`. `None` = no resolvable address (label-only target, current behavior).
- Parser change (`src/engagement_config.rs:171-177`, `build_target`): read an **optional** `network_address` key. Use `fields.get("network_address").cloned()` — do **not** route it through `required_string`, so existing configs without the key keep parsing. Document the new key in the module doc-comment example (`src/engagement_config.rs:6-29`) and in `OPERATING_GUIDE.md` section 8a.
- Update every other `Target { ... }` literal to add `network_address: None` (tests) or a real value where relevant.

### C.3 Auto-injection into execution
This is the safety-relevant part: it keeps the authorization boundary (the target **id**) connected to what the tool actually connects to (the **address**).

- Thread the address into the plan. Options, pick the lower-churn one:
  - **Recommended:** give `ScanTask` (`src/coordinator.rs:13-20`) a new `pub network_address: Option<String>` field, populated in `build_authorized_plan` (`src/coordinator.rs:253-259`) from `target.network_address.clone()`. This survives into `execute_plan` without changing `execute_plan`'s public signature's meaning.
- In `execute_plan` (`src/execution.rs:246`), when a task has a `network_address` **and** the tool's `execution_class != StaticLocalAnalysis` (i.e. it's a network tool like nmap/masscan), prepend the address as the first argument: effective args = `[address] ++ caller_args`. Static-local tools (semgrep, jadx) operate on files, not addresses — never inject for them.
- Add a doc note: injection is prepend-only and never overrides operator args; it guarantees a network tool run through a plan targets the authorized address, not whatever the operator typed.

### C.4 Tests
- `engagement_config.rs`: `parses_optional_network_address`, `network_address_absent_is_none` (regression: existing configs still parse).
- `execution.rs`: `execute_plan_injects_network_address_for_network_tools` (task with address + an `ActiveNetwork` tool → outcome's report `arguments[0]` == address) and `execute_plan_does_not_inject_for_static_tools`.
- `model.rs`: extend the existing construction in tests; no new behavior test needed for the plain field.

---

## 5. Sub-feature D — Wire the loop into the CLI

### D.1 Extend `--plan-scan ... --execute` to ingest, score, and persist
In `src/main.rs`, `plan_scan` (`src/main.rs:238-287`) currently maps `--execute` to `execute_plan` and returns raw outcomes. Extend it:
1. After `execute_plan` returns `Vec<TaskExecutionOutcome>`, for each `Ok(report)` call `ingest::ingest(&outcome.target_id, report)` → `Vec<Finding>`.
2. Accept an optional `--findings-log <path>.jsonl` flag (parse it in the same block as `--audit-log`, `src/main.rs:249-261`). When present, `append_findings(path, &all_findings)`.
3. Print a findings summary block after "Execution Outcomes" (count by severity, top N by `normalized_risk_score`).
4. Optionally build the `AttackPathGraph::build_from_findings(&all_findings)` and print node/edge counts — this finally exercises `src/advanced.rs:28` from a runtime path.

Add a new `PlanScanError::FindingsLogWrite(String)` variant (mirror `AuditLogWrite`, `src/main.rs:203`).

### D.2 New command `--schedule-retest <findings-log>.jsonl`
Add a dispatch arm in `main` (`src/main.rs:18-33`) and a `schedule_retest_command`:
1. `load_findings(path)`.
2. For each finding, call `propose_retest_schedule(&finding, current_epoch_seconds())` (`src/advanced.rs:68`, `src/main.rs:322`).
3. Print a table: `target_id`, `next_retest_epoch_seconds`, `reason`, sorted by soonest retest. This surfaces `propose_retest_schedule`, closing report item #4.

### D.3 Docs
- `OPERATING_GUIDE.md` section 8: add `--plan-scan ... --findings-log <path>.jsonl` and `--schedule-retest <path>.jsonl` to the command list (`OPERATING_GUIDE.md:143-161`) with one-line summaries (`OPERATING_GUIDE.md:163-189`).
- `README.md`: add a "Findings pipeline" subsection describing execute → ingest → score → persist → retest.

### D.4 Tests (`src/main.rs` `#[cfg(test)]`)
- `plan_scan_writes_findings_log_when_flag_is_given` (mirror `plan_scan_writes_audit_log_when_flag_is_given`, `src/main.rs:574-624`).
- `schedule_retest_reads_findings_and_emits_schedule` — write a findings log via `append_findings`, invoke the command helper, assert `ExitCode::SUCCESS`.
- `plan_scan_findings_log_missing_path` — `--findings-log` with no path → error variant.

---

## 6. Execution order (strict)

1. **Refactor JSON primitives** out of `compat.rs` into `src/json.rs`; keep all `compat.rs` tests green. *(enables A and B)*
2. **A** — `src/ingest.rs` + parsers + `severity_from_label`. Ship + test.
3. **B** — `Severity: Display+FromStr`, `finding_to_envelope`/`envelope_to_finding`, `src/findings_log.rs`. Ship + test.
4. **C** — `Target.network_address`, config parser, `ScanTask` field, `execute_plan` injection. Ship + test.
5. **D** — CLI wiring (`--findings-log`, findings summary, `--schedule-retest`) + docs. Ship + test.
6. Full gate (Section 8). Commit each of steps 2–5 as its own logical commit.

---

## 7. Definition of Done

- [ ] `execute_plan` output is parsed into scored `Finding`s for at least semgrep + SARIF-emitting tools.
- [ ] Findings persist to an append-only JSONL log and reload byte-faithfully (round-trip test green).
- [ ] `RiskScoreCalculator`, `AttackPathGraph::build_from_findings`, and `propose_retest_schedule` are each reached from a real CLI path (grep for their call sites shows non-test callers).
- [ ] Engagement configs can bind `network_address` per target; network-tool runs through a plan use that address as arg 0; static tools are unaffected.
- [ ] `--schedule-retest` emits a schedule from a persisted findings log.
- [ ] No existing test deleted or weakened; existing configs without `network_address` still parse (regression test present).

---

## 8. Quality gate (run after every sub-feature)

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::nursery
cargo test
```

---

## 9. Risks, edge cases, rollback

- **Divergent JSON parsers** — mitigated by the Section 6 step 1 refactor; do not hand-roll a second reader.
- **Struct-literal breakage from the `Target` field** — mitigated by the `rg` enumeration in C.1; the compiler will flag every missed site, so this is safe but touches ~14 files/tests.
- **`f32` round-trip precision** — fixed `{:.4}` format + tolerance test; never assert exact float equality (clippy `float_cmp` will also catch this).
- **Untrusted tool output** — parser input is third-party stdout. Parsers must be total (no `unwrap` on external data), bounded (cap findings per report, e.g. 10_000, like the autopsy 100_000-file cap), and must never execute or interpret content — only read strings. Add a `malformed_json_is_ignored_not_panicked` test as the guard.
- **Rollback** — each sub-feature is an isolated module + additive field; reverting one commit removes it without touching the others.

## 10. Explicitly out of scope for Plan 1
- Parsers for `ActiveNetwork`/`ActiveExploitation` tool output beyond SARIF (nikto native, hydra, etc.) — add incrementally later.
- A findings UI or HTML report — text output only in this plan.
- Deduplication across engagements/time — `finding_id` is stable within a report; cross-run dedup is a future enhancement.
