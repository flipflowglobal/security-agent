# aureon-mev-system

Rust-first hybrid defensive security orchestration foundation for authorized vulnerability testing.

## Mission

This project implements a defensive security orchestration agent for authorized testing across:
- Platform applications
- Internal/external APIs
- Tools and services
- Infrastructure and cloud assets

## Architecture

Federated model (not an unrestricted super-agent):
- **Coordinator**: plans scoped runs, maps targets to specialists, emits execution plans.
- **Specialists**: SAST, DAST, API security, dependency risk, cloud/IaC, container/K8s, secrets, malware, compliance.
- **Capability Registry**: maps specialists to approved tools, supported target types, and allowed techniques.

## Key Controls

Authorization and scope controls:
- Time-bounded engagement profiles
- Technique allow-list per engagement
- Explicit deny-list targets
- High-impact approval gate

Least privilege defaults:
- Ephemeral runner requirement
- Short-lived credential requirement
- Shared long-lived credential prohibition
- Tool-level network egress policy metadata

Toolchain pack model:
- Curated packs by use case (web app, API, mobile backend, cloud, blockchain/smart contract)
- Version-pinned tool metadata
- Signed and vulnerability-reviewed markers
- Deprecation/replacement fields

## Workflow Coverage

Implemented stage model:
1. Discovery and inventory
2. Passive recon and configuration checks
3. Source/dependency/static analysis
4. Runtime app/API scanning
5. Cloud/container/infrastructure posture checks
6. Correlation and risk scoring

Advanced controls:
- Threat model node/edge graph structures
- Attack-path graph structures
- Drift/risk-based retest scheduling helper

## Hybrid Compatibility

Rust core exposes adapter contracts via `IntegrationAdapter` and `CompatibilityEnvelope`:
- Stable envelope fields for cross-agent integration
- Exportable execution plans
- Import hooks for external finding hints

This enables compatibility with CLI, service, or polyglot wrappers while retaining a Rust security core.

## Modules

- `src/mission.rs`: mission definition
- `src/model.rs`: core target/engagement/specialist models
- `src/registry.rs`: capability and toolchain pack registries
- `src/policy.rs`: authorization and least-privilege policy engine
- `src/workflow.rs`: multi-layer workflow stage model
- `src/coordinator.rs`: orchestration and scoped task planning
- `src/findings.rs`: unified finding model and risk scoring
- `src/governance.rs`: audit record ledger model
- `src/advanced.rs`: attack-path/retest primitives
- `src/compat.rs`: hybrid compatibility adapter contracts
- `src/roadmap.rs`: phased rollout model

## Roadmap Phases

- Phase 1: coordinator + core scanners + reporting
- Phase 2: cloud/container/supply-chain specialists
- Phase 3: attack-path analytics + autonomous retesting
- Phase 4: org-wide policy automation + continuous validation