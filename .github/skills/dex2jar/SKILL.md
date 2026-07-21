---
name: dex2jar
description: Converts Android DEX bytecode into standard Java JAR files for analysis with Java decompilers.
category: static-local-analysis
metadata:
  execution_class: StaticLocalAnalysis
  cataloged: "true"
  bundled_binary: "false"
---

# dex2jar

Converts Android DEX bytecode into standard Java JAR files for analysis with Java decompilers.

## Execution class

`StaticLocalAnalysis` (see `ExecutionClass` in `src/registry.rs`).

## Specialist approval

Approved for the `MobileAndroid` specialist(s) in `src/registry.rs`.

## Authorization requirements

Operates only on local files already gathered as evidence; no network or live-target interaction. Beyond the engagement's standard technique allow-list, no additional authorization gate applies.

## Execution status in Security-Agent

Real execution is available: `--run-external-tool dex2jar <args>` runs the locally installed binary directly (see `src/execution.rs`), bounded by an execution timeout with stdout/stderr/exit-code capture.

## Availability

Security-Agent never downloads, contacts, or silently invokes this tool. `dex2jar` must
already be installed and present on `PATH`; `--list-tools` reports whether that is the
case on the current host. Security-Agent does not bundle, distribute, or vouch for the
security of any third-party tool binary.
