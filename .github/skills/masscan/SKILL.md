---
name: masscan
description: Extremely fast asynchronous port scanner capable of scanning very large address ranges.
category: active-network
metadata:
  execution_class: ActiveNetwork
  cataloged: "true"
  bundled_binary: "false"
  execution_exception: "true"
---

# masscan

Extremely fast asynchronous port scanner capable of scanning very large address ranges.

## Execution class

`ActiveNetwork` (see `ExecutionClass` in `src/registry.rs`).

## Specialist approval

Approved for the `CloudIaC` specialist(s) in `src/registry.rs`.

## Authorization requirements

Requires the target to be in-scope and the relevant technique present in the engagement's `allowed_techniques`. Techniques classified penetrative (`Dast`, `ApiSecurity`, `MobileRuntime`, `ExploitValidationSandboxed` — see `src/policy.rs`) additionally require `penetrative_testing_approved`.

## Execution status in Security-Agent

Real execution is available: `--run-external-tool masscan <args>` and `--plan-scan <config> --execute <args>` both run the locally installed binary directly (see `src/execution.rs`), bounded by an execution timeout with stdout/stderr/exit-code capture. `masscan` is an explicit, reviewed exception to the general rule that only `StaticLocalAnalysis` tools get real execution (tracked as `WIRED_DESPITE_EXECUTION_CLASS` in `src/execution.rs`, alongside `nmap`) — it is gated only by the coordinator's existing planning approval (scope + technique allow-list) and local installation. Because masscan can saturate a link at its default rate, its arguments are additionally run through the non-blocking intensity advisory (`src/intensity_guard.rs`), which warns on stderr when the requested rate/aggressiveness exceeds the engagement's declared ceiling but never blocks execution. Arguments are otherwise trusted as-is. Every other `ActiveNetwork`/`ActiveExploitation` tool remains catalog/detection-only.

## Availability

Security-Agent never downloads, contacts, or silently invokes this tool. `masscan` must
already be installed and present on `PATH`; `--list-tools` reports whether that is the
case on the current host. Security-Agent does not bundle, distribute, or vouch for the
security of any third-party tool binary.
