---
name: chkrootkit
description: Local rootkit and trojan detector for Unix systems; checks system binaries for signs of common rootkits.
category: static-local-analysis
metadata:
  execution_class: StaticLocalAnalysis
  cataloged: "true"
  bundled_binary: "false"
---

# chkrootkit

Local rootkit and trojan detector for Unix systems; checks system binaries for signs of common rootkits.

## Execution class

`StaticLocalAnalysis` (see `ExecutionClass` in `src/registry.rs`).

## Specialist approval

Approved for the `CloudIaC`, `ContainerK8s`, `Malware`, `Compliance` specialist(s) in `src/registry.rs`.

## Authorization requirements

Operates only on local files already gathered as evidence; no network or live-target interaction. Beyond the engagement's standard technique allow-list, no additional authorization gate applies.

## Execution status in Security-Agent

Classified for direct-execution eligibility (`ExecutionClass::StaticLocalAnalysis`) but not yet in the `--run-external-tool` first tranche (`semgrep`, `jadx`, `androguard`, `apktool`, `dex2jar`, `apksigner`). Today this tool is catalog/detection only via `--list-tools`.

## Availability

Security-Agent never downloads, contacts, or silently invokes this tool. `chkrootkit` must
already be installed and present on `PATH`; `--list-tools` reports whether that is the
case on the current host. Security-Agent does not bundle, distribute, or vouch for the
security of any third-party tool binary.
