# Plan 3 — Developer Experience, CI & Housekeeping

| | |
|---|---|
| **Priority** | P2 — lowest risk, high leverage; protects the quality bar Plans 1 & 2 must not regress |
| **Primary owner** | Any Rust engineer / can be split across the team |
| **Depends on** | Fully independent. **Recommended to land first** so CI guards Plans 1 & 2 as they merge. |
| **Est. effort** | 2–3 engineering days |
| **Quality bar** | `cargo fmt --check` clean · `cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::nursery` clean · `cargo test` green · zero external crates |

---

## 1. Why this plan exists (problem statement)

The codebase holds a strict quality bar — pedantic + nursery clippy at zero warnings across 20 source files and 90 skill files — but that bar is enforced **only by local convention**. There is no CI. Separately, several exported items and struct fields are inert scaffolding that either misleads readers or should be surfaced:

- **No CI** — a single missed `cargo clippy` locally lets a regression merge.
- **`ToolchainPack.deprecated` / `replacement_pack`** (`src/registry.rs:487-488`) are always `false`/`None` across all six pack constructions (`src/registry.rs:501-565`). Dead fields that imply a lifecycle that doesn't exist.
- **`ROADMAP_PHASES`** (`src/roadmap.rs:7`) and **`MISSION_STATEMENT`** (`src/mission.rs:1`) are exported (`src/lib.rs:45`, `src/lib.rs:55`) but surfaced by no command.
- **No integration tests** — only in-module `#[cfg(test)]` units exist; there is no `tests/` directory exercising the compiled binary end-to-end.
- **`.github/skills/zenmap/SKILL.md`** (`:29`) still says execution "would require ... follow-up," stale now that nmap executes.

### Exact report items addressed by this plan

5. **CI workflow.**
9. **Implement (not remove) `ToolchainPack.deprecated` / `replacement_pack` lifecycle.**
10. **Surface `ROADMAP_PHASES` + `MISSION_STATEMENT`** via `--about`.
11. **Integration test directory (`tests/`).**
13. **Update `zenmap` SKILL.md.**

---

## 2. Sub-feature A — GitHub Actions CI

### A.1 File: `.github/workflows/ci.yml`
Mirror the exact commands the project already runs locally (`OPERATING_GUIDE.md:59-65`). Pin to stable, cache the cargo registry/target for speed.

```yaml
name: CI
on:
  push:
    branches: [ main ]
  pull_request:
jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --check
      - run: cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::nursery
      - run: cargo test --all-targets
      - run: cargo build --release
```

### A.2 Notes
- The clippy invocation must match the **exact** flags in the quality bar, or CI will diverge from local expectations. Copy them verbatim.
- `cargo test --all-targets` will pick up the new `tests/` integration tests from Sub-feature D.
- Actions are external services (`actions/checkout`, `dtolnay/rust-toolchain`, `Swatinem/rust-cache`) — this is standard and acceptable for CI, and does **not** violate the crate's zero-**dependency** stance (no new `Cargo.toml` deps). Call this out in the PR so it isn't mistaken for a supply-chain regression.
- Add a CI status badge to `README.md` top.

### A.3 Verification
- Open the PR and confirm the workflow runs and passes on the branch before merge. A red CI on the introducing PR is the acceptance test.

---

## 3. Sub-feature B — Implement toolchain-pack lifecycle

### B.1 Decision: implement, do not delete
The report offered "remove or implement." Implement — a pack-deprecation signal is genuinely useful for an evolving tool catalog, and the fields already exist. This turns dead scaffolding into a working (if small) feature without removing any public field.

### B.2 Changes
- Introduce at least one deprecated pack **or** a deterministic way to mark one, so the lifecycle is exercised. Recommended, low-churn approach:
  - Add a method on `ToolchainPackRegistry` (`src/registry.rs:571-576`):
    ```rust
    impl ToolchainPackRegistry {
        /// Packs marked deprecated, each paired with its replacement (if any).
        #[must_use]
        pub fn deprecated_packs(&self) -> Vec<&ToolchainPack>;
    }
    ```
  - In `build_authorized_plan` (`src/coordinator.rs:262-267`), when a selected pack has `deprecated == true`, record it: append a note to the plan or emit an `AuditRecord` with `action = "deprecated_pack_selected"` and `details` naming the `replacement_pack`. This makes selecting a deprecated pack **visible** in the audit trail (ties into the append-only ledger, `src/governance.rs:49`).
- Surface deprecation in `ExecutionPlan`'s `Display` (`src/coordinator.rs:47-55`, the "Selected Toolchain Packs" block): print `- <name> (DEPRECATED → <replacement>)` when applicable.
- To actually exercise it, either (a) mark one existing pack deprecated with a documented replacement, or (b) add a small doc-only "legacy" pack. Prefer (a): pick a pack that is genuinely a candidate for consolidation and set `deprecated: true, replacement_pack: Some("...")` — document the rationale in a code comment so it isn't mistaken for a mistake.

### B.3 Tests (`src/registry.rs`, `src/coordinator.rs`)
- `deprecated_packs_returns_only_deprecated` — construct a registry with one deprecated pack; assert the accessor returns exactly it.
- `plan_display_marks_deprecated_packs` — a plan selecting the deprecated pack renders the `(DEPRECATED → ...)` marker.
- `selecting_a_deprecated_pack_is_audited` (if you take the audit-record route) — assert an `AuditRecord` with `action == "deprecated_pack_selected"` is appended.

---

## 4. Sub-feature C — `--about` / `--version` command

### C.1 Command
Add a dispatch arm in `main` (`src/main.rs:18-33`) for `--about` (and alias `--version`) → `print_about()`:
- `MISSION_STATEMENT` (`src/mission.rs:1`, re-exported `src/lib.rs:45`).
- `env!("CARGO_PKG_VERSION")` and `env!("CARGO_PKG_NAME")`.
- The roadmap: iterate `ROADMAP_PHASES` (`src/roadmap.rs:7`, re-exported `src/lib.rs:55`), printing `phase` + `focus` for each of the 4 entries.

```rust
fn print_about() -> ExitCode {
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    println!();
    println!("{}", security_agent::MISSION_STATEMENT);
    println!();
    println!("Roadmap");
    println!("-------");
    for phase in security_agent::ROADMAP_PHASES {
        println!("{:<9} {}", phase.phase, phase.focus);
    }
    ExitCode::SUCCESS
}
```

### C.2 Tests (`src/main.rs`)
- `about_reports_success` — `assert_eq!(print_about(), ExitCode::SUCCESS)`.
- Optionally capture stdout is overkill here; the compile-time `env!` + iteration is the coverage. A `roadmap.rs` test already implicitly guarantees the array length; add `roadmap_has_four_phases` if not present.

### C.3 Docs
- `OPERATING_GUIDE.md` section 8 (`:143-161` list and `:163-189` summaries): add `--about`.
- `README.md`: mention `--about` in the command overview.

---

## 5. Sub-feature D — Integration test directory (`tests/`)

### D.1 Rationale
Unit tests call functions directly; they never prove the **compiled binary** parses argv, dispatches, and prints correctly. Add black-box tests that run the release/debug binary via `std::process::Command` and assert on exit code + stdout. Cargo compiles files under `tests/` as separate integration crates automatically — no `Cargo.toml` change.

### D.2 File: `tests/cli.rs`
Use `env!("CARGO_BIN_EXE_security-agent")` (Cargo sets this for integration tests) to locate the built binary — no path guessing.

```rust
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_security-agent"))
        .args(args)
        .output()
        .expect("binary should run")
}
```

### D.3 Cases (each asserts exit code + a stdout substring)
- `offline_status_reports_core_fields` — `--offline-status` stdout contains `network_required=false` and `capability_coverage=ok` (`src/main.rs:44-50`).
- `list_skills_lists_the_general_skill` — `--list-skills` contains `security-agent`.
- `show_skill_prints_nmap` — `--show-skill nmap` contains `Network discovery`.
- `list_tools_marks_builtin_substitutes` — `--list-tools` contains `autopsy\tbuilt-in-substitute`.
- `unknown_command_exits_2` — `--bogus` → exit code `2` (`src/main.rs:29-32`).
- `about_prints_mission_and_roadmap` — `--about` contains `Defensive security orchestration` and `Phase 1` *(depends on Sub-feature C)*.
- `plan_scan_end_to_end_from_a_temp_config` — write a temp engagement config to `std::env::temp_dir()`, run `--plan-scan <path>`, assert exit `0` and stdout contains `Execution Plan` and the engagement id. Mirrors the in-module test at `src/main.rs:496-532` but through the real binary.
- `plan_scan_denied_config_exits_1` — a deny-listed target config → exit `1` and stderr contains `authorization denied` (`src/main.rs:311-313`).

### D.4 Notes
- Integration tests must be deterministic: only use built-in tools and temp files; never assume `semgrep`/`nmap` are installed (same discipline as `src/execution.rs:355-357`, which skips when `/bin/true` is absent).
- Clean up temp files in each test.

---

## 6. Sub-feature E — Update `zenmap` skill doc

### E.1 Change
`.github/skills/zenmap/SKILL.md:28-30` currently reads: execution "would require the live-target confirmation/rate-limit design noted as follow-up." Now that nmap (its CLI backend) executes and, per Plan 2, masscan too, update the "Execution status" section to:
- Clarify zenmap is a **GUI front-end**, not itself wired for execution.
- Point to nmap's now-active execution path (`--run-external-tool nmap`) as the underlying capability.
- Keep the honest statement that zenmap itself remains catalog/detection-only.

### E.2 No code change
This is a docs-only edit. Verify no test asserts on the old wording (`rg -n "follow-up" .github/skills/` and `rg -n zenmap src/`).

---

## 7. Execution order (recommended: land this plan first)

1. **A** — CI workflow. Merges first so it guards everything after.
2. **E** — zenmap doc (trivial, no risk).
3. **C** — `--about` command + docs.
4. **B** — toolchain-pack lifecycle.
5. **D** — `tests/cli.rs` integration suite (add `about_*` case after C lands).
6. Full gate (Section 8). One logical commit per sub-feature.

---

## 8. Definition of Done

- [ ] CI runs `fmt --check`, the exact pedantic+nursery clippy line, `cargo test --all-targets`, and `cargo build --release` on every PR, and is green on the introducing PR.
- [ ] `ToolchainPack.deprecated`/`replacement_pack` drive real behavior: a deprecated pack is enumerable, rendered in the plan, and/or audited when selected — no longer inert.
- [ ] `--about` prints the mission statement, package version, and all 4 roadmap phases.
- [ ] A `tests/` integration suite exercises the compiled binary across ≥6 commands, deterministically, with no reliance on optional external tools.
- [ ] `zenmap` SKILL.md reflects the current nmap execution reality.
- [ ] No existing test deleted or weakened; the quality bar is unchanged and now CI-enforced.

---

## 9. Quality gate (run after every sub-feature)

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::nursery
cargo test --all-targets
```

---

## 10. Risks, edge cases, rollback

- **CI clippy drift** — if CI's clippy flags differ from local, contributors get surprised failures. Copy the flags verbatim from the quality bar; treat the workflow file as the single source of truth and reference it in `OPERATING_GUIDE.md`.
- **Integration-test flakiness** — the binary path is resolved via `CARGO_BIN_EXE_*` (stable), and only built-in tools/temp files are used, so there is no environmental dependency. Do not add cases that need network or installed scanners.
- **Deprecated-pack semantics** — marking a real pack deprecated changes plan output. Ensure any test asserting on the affected `Display` output is updated in the same commit, and document why the pack is deprecated so reviewers don't read it as a bug.
- **Rollback** — every item is additive (a new file, a new command arm, a new accessor, doc edits). Revert the relevant commit to remove it; nothing here changes existing public behavior except the intentional deprecated-pack marker.

## 11. Explicitly out of scope for Plan 3
- Release automation / publishing to crates.io — CI here is quality-gating only.
- Removing any public field or export — the directive is to keep functionality; `deprecated`/`replacement_pack` are implemented, not deleted.
- Coverage tooling or benchmarks — plain `cargo test` only.
