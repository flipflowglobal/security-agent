---
name: volatility
description: Memory forensics framework for analyzing RAM captures to find processes, injected code, and other artifacts of compromise.
category: static-local-analysis
metadata:
  execution_class: StaticLocalAnalysis
  cataloged: "true"
  bundled_binary: "false"
---

# volatility

Memory forensics framework for analyzing RAM captures to find processes, injected code, and other artifacts of compromise.

## Execution class

`StaticLocalAnalysis` (see `ExecutionClass` in `src/registry.rs`).

## Specialist approval

Approved for the `Malware` specialist(s) in `src/registry.rs`.

## Authorization requirements

Operates only on local files already gathered as evidence; no network or live-target interaction. Beyond the engagement's standard technique allow-list, no additional authorization gate applies.

## Execution status in Security-Agent

Classified for direct-execution eligibility (`ExecutionClass::StaticLocalAnalysis`) but not yet in the `--run-external-tool` first tranche (`semgrep`, `jadx`, `androguard`, `apktool`, `dex2jar`, `apksigner`). Today this tool is catalog/detection only via `--list-tools`.

## Availability

Security-Agent never downloads, contacts, or silently invokes this tool. `volatility` must
already be installed and present on `PATH`; `--list-tools` reports whether that is the
case on the current host. Security-Agent does not bundle, distribute, or vouch for the
security of any third-party tool binary.
