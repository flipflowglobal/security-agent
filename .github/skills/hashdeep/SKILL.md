---
name: hashdeep
description: Computes and audits cryptographic hashes (MD5/SHA family) recursively across directory trees for integrity verification.
category: static-local-analysis
metadata:
  execution_class: StaticLocalAnalysis
  cataloged: "true"
  bundled_binary: "false"
---

# hashdeep

Computes and audits cryptographic hashes (MD5/SHA family) recursively across directory trees for integrity verification.

## Execution class

`StaticLocalAnalysis` (see `ExecutionClass` in `src/registry.rs`).

## Specialist approval

Approved for the `ContainerK8s`, `DependencyRisk` specialist(s) in `src/registry.rs`.

## Authorization requirements

Operates only on local files already gathered as evidence; no network or live-target interaction. Beyond the engagement's standard technique allow-list, no additional authorization gate applies.

## Execution status in Security-Agent

Classified for direct-execution eligibility (`ExecutionClass::StaticLocalAnalysis`) but not yet in the `--run-external-tool` first tranche (`semgrep`, `jadx`, `androguard`, `apktool`, `dex2jar`, `apksigner`). Today this tool is catalog/detection only via `--list-tools`.

## Availability

Security-Agent never downloads, contacts, or silently invokes this tool. `hashdeep` must
already be installed and present on `PATH`; `--list-tools` reports whether that is the
case on the current host. Security-Agent does not bundle, distribute, or vouch for the
security of any third-party tool binary.
