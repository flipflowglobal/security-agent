---
name: subfinder
description: Fast passive subdomain enumeration tool that queries multiple public sources and APIs.
category: active-network
metadata:
  execution_class: ActiveNetwork
  cataloged: "true"
  bundled_binary: "false"
---

# subfinder

Fast passive subdomain enumeration tool that queries multiple public sources and APIs.

## Execution class

`ActiveNetwork` (see `ExecutionClass` in `src/registry.rs`).

## Specialist approval

Not currently listed in any specialist's `approved_tools` scope in `src/registry.rs`. It is cataloged (present in the toolchain packs and `--list-tools` output) but no specialist is presently approved to select it for a task.

## Authorization requirements

Requires the target to be in-scope and the relevant technique present in the engagement's `allowed_techniques`. Techniques classified penetrative (`Dast`, `ApiSecurity`, `MobileRuntime`, `ExploitValidationSandboxed` — see `src/policy.rs`) additionally require `penetrative_testing_approved`.

## Execution status in Security-Agent

Catalog and local-installation detection only, via `--list-tools`. Security-Agent does not invoke this tool directly. Real execution would require the live-target confirmation/rate-limit design noted as follow-up in `src/execution.rs`.

## Availability

Security-Agent never downloads, contacts, or silently invokes this tool. `subfinder` must
already be installed and present on `PATH`; `--list-tools` reports whether that is the
case on the current host. Security-Agent does not bundle, distribute, or vouch for the
security of any third-party tool binary.
