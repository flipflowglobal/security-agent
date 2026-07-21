# Development Plans — Security-Agent Improvement Program

Three self-contained, independently shippable plans that together implement every
improvement, refinement, and gap identified in the functionality & architecture
review. Each plan is written to be executed by a developer or an AI assistant with
no additional context: exact file/line references, new type signatures, step
ordering, test names, and a definition of done.

## The three plans

| Plan | Theme | Priority | Report items covered |
|---|---|---|---|
| [Plan 1](./PLAN-1-close-the-intelligence-loop.md) | **Close the intelligence loop** — findings ingestion → risk scoring → persistence → retest scheduling | P0 (highest value) | 1, 2, 3, 4 |
| [Plan 2](./PLAN-2-safety-trust-governance.md) | **Safety, trust & governance hardening** — intensity advisories, integrity verification, `Viewer` role, masscan | P1 | 6, 7, 8, 12 |
| [Plan 3](./PLAN-3-devex-ci-housekeeping.md) | **Developer experience, CI & housekeeping** — CI, pack lifecycle, `--about`, integration tests, doc fixes | P2 (lowest risk) | 5, 9, 10, 11, 13 |

## Full coverage matrix (all 13 review items)

| # | Improvement item | Plan | Sub-feature |
|---|---|---|---|
| 1 | Finding ingestion from tool output | 1 | A |
| 2 | Finding persistence (`findings_log.rs`) | 1 | B |
| 3 | `Target.network_address` + auto-injection | 1 | C |
| 4 | Surface `propose_retest_schedule` (`--schedule-retest`) | 1 | D |
| 5 | CI workflow | 3 | A |
| 6 | Soft network-tool intensity ceiling | 2 | A |
| 7 | Tool signature/integrity verification | 2 | B |
| 8 | `Role::Viewer` read-only command | 2 | C |
| 9 | Implement `ToolchainPack` deprecation lifecycle | 3 | B |
| 10 | Surface `ROADMAP_PHASES` + `MISSION_STATEMENT` (`--about`) | 3 | C |
| 11 | Integration test directory (`tests/`) | 3 | D |
| 12 | Expand execution allowlist to `masscan` | 2 | D |
| 13 | Update `zenmap` SKILL.md | 3 | E |

## Recommended sequencing across plans

1. **Plan 3 first (partial): land CI (Plan 3 / A).** It then guards Plans 1 & 2 as they merge.
2. **Plan 1** — the core value; unblocks the findings-log read paths that Plan 2 / C and Plan 1 / D both want.
3. **Plan 2** — hardening on top of the now-complete execution+findings pipeline. Ship masscan (2/D) only together with the intensity advisory (2/A).
4. **Plan 3 remainder** — pack lifecycle, `--about`, integration tests, zenmap doc.

Plans are otherwise independent and can be parallelized across engineers. The only
cross-plan coupling is the **findings log format**, defined in Plan 1 / B and
consumed by the read/retest commands; whichever plan ships it first owns
`--view-findings` (see Plan 2 / C.2).

## Non-negotiable constraints (apply to every plan)

- **Never remove existing functionality or logic** — extend and add only.
- **Zero external crates** — `Cargo.toml` `[dependencies]` stays empty. Reuse the
  in-house SHA-256, PCAP, and JSON primitives already in the crate.
- **Quality bar on every change:**
  ```bash
  cargo fmt --check
  cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::nursery
  cargo test --all-targets
  ```
- **No existing test deleted or weakened** — only added to or strengthened.
- Every new module gets its own `#[cfg(test)]` coverage for success **and** error paths.
