---
name: nmap
description: Network discovery and port-scanning tool with service/version detection and a scripting engine (NSE).
category: active-network
metadata:
  execution_class: ActiveNetwork
  cataloged: "true"
  bundled_binary: "false"
  execution_exception: "true"
---

# nmap

Network discovery and port-scanning tool with service/version detection and a scripting engine (NSE).

## Execution class

`ActiveNetwork` (see `ExecutionClass` in `src/registry.rs`).

## Specialist approval

Approved for the `CloudIaC` specialist(s) in `src/registry.rs`.

## Authorization requirements

Requires the target to be in-scope and the relevant technique present in the engagement's `allowed_techniques`. Techniques classified penetrative (`Dast`, `ApiSecurity`, `MobileRuntime`, `ExploitValidationSandboxed` — see `src/policy.rs`) additionally require `penetrative_testing_approved`.

## Execution status in Security-Agent

Real execution is available for authorized work: `--run-external-tool --allow-network nmap <args>` and `--plan-scan <config> --allow-network --execute <args>` run the locally installed binary directly (see `src/execution.rs`), bounded by an execution timeout with stdout/stderr/exit-code capture. As an `ActiveNetwork` tool, nmap performs live-target activity, so it runs only under the explicit per-invocation `--allow-network` opt-in (the runtime is offline by default; see `src/network_policy.rs`); without it the run is refused. Under a planned scan the coordinator's authorization policy (scope + technique allow-list + deny-lists + approval gates + time window) still governs, and arguments are trusted as-is. Only the real installed binary is spawned.

## Availability

Security-Agent never downloads, contacts, or silently invokes this tool. `nmap` must
already be installed and present on `PATH`; `--list-tools` reports whether that is the
case on the current host. Security-Agent does not bundle, distribute, or vouch for the
security of any third-party tool binary.
