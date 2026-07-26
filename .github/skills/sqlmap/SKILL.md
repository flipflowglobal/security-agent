---
name: sqlmap
description: Automated SQL-injection detection and exploitation tool for web application database backends.
category: active-exploitation
metadata:
  execution_class: ActiveExploitation
  cataloged: "true"
  bundled_binary: "false"
---

# sqlmap

Automated SQL-injection detection and exploitation tool for web application database backends.

## Execution class

`ActiveExploitation` (see `ExecutionClass` in `src/registry.rs`).

## Specialist approval

Not currently listed in any specialist's `approved_tools` scope in `src/registry.rs`. It is cataloged (present in the toolchain packs and `--list-tools` output) but no specialist is presently approved to select it for a task.

## Authorization requirements

Requires explicit `penetrative_testing_approved` and, for high-criticality targets, `high_impact_approved` (see `src/policy.rs`). Security-Agent does not implement real execution for this class; cataloging and detection only.

## Execution status in Security-Agent

Catalog and local-installation detection only, via `--list-tools`. Security-Agent does not invoke this tool directly. Real execution would require the live-target confirmation/rate-limit design noted as follow-up in `src/execution.rs`.

## Availability

Security-Agent never downloads, contacts, or silently invokes this tool. `sqlmap` must
already be installed and present on `PATH`; `--list-tools` reports whether that is the
case on the current host. Security-Agent does not bundle, distribute, or vouch for the
security of any third-party tool binary.
