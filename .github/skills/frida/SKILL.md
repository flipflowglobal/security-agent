---
name: frida
description: Dynamic instrumentation toolkit that injects JavaScript into running processes to hook and modify behavior at runtime.
category: active-exploitation
metadata:
  execution_class: ActiveExploitation
  cataloged: "true"
  bundled_binary: "false"
---

# frida

Dynamic instrumentation toolkit that injects JavaScript into running processes to hook and modify behavior at runtime.

## Execution class

`ActiveExploitation` (see `ExecutionClass` in `src/registry.rs`).

## Specialist approval

Approved for the `MobileAndroid` specialist(s) in `src/registry.rs`.

## Authorization requirements

Requires explicit `penetrative_testing_approved` and, for high-criticality targets, `high_impact_approved` (see `src/policy.rs`). Security-Agent does not implement real execution for this class; cataloging and detection only.

## Execution status in Security-Agent

Catalog and local-installation detection only, via `--list-tools`. Security-Agent does not invoke this tool directly. Real execution would require the live-target confirmation/rate-limit design noted as follow-up in `src/execution.rs`.

## Availability

Security-Agent never downloads, contacts, or silently invokes this tool. `frida` must
already be installed and present on `PATH`; `--list-tools` reports whether that is the
case on the current host. Security-Agent does not bundle, distribute, or vouch for the
security of any third-party tool binary.
