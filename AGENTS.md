# AGENTS.md

Rust CLI crate with a companion Electron GUI (`electron/`). `opencode.json`
already loads `ARCHITECTURE.md`, `CONTRIBUTING.md`, and `OPERATING_GUIDE.md`
into every session — this file only adds facts those docs miss or understate.

## Verify with the CI command, not `make check`

`make check` runs fmt → clippy → `cargo test --lib` → release build, but its
clippy target is WEAKER than CI:

- `make clippy`: `cargo clippy --all-targets -- -D warnings`
- CI and `scripts/deploy.sh`: `cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::nursery`

Code can pass `make check` and still fail CI. The codebase is written to the
pedantic + nursery bar. Before finishing, run the exact CI gate:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::nursery
cargo test --lib
cargo build --release
```

If a new pedantic/nursery lint fires, fix it or add a scoped `#[allow]` with
justification — never weaken the gate.

## Zero external runtime dependencies (design invariant)

The core crate has **no runtime crates by design**: JSON (`src/json.rs`),
SHA-256, and PCAP parsing (`src/pcap.rs`) are all in-house. Do not add a
runtime dependency unless the task explicitly requires it. `candle` /
`tokenizers` exist only behind the `inference` feature (off by default, not
exercised by CI) — leave it alone unless the task is inference-specific.

Rust specifics: edition 2024, MSRV 1.85, `rustfmt.toml` `max_width = 100`.
Keep `rustfmt.toml` to stable options only — nightly-only keys are silently
ignored on stable but emit warnings in CI logs.

## Compiled-in assets require regeneration

Skills, the tool catalog, the LM corpus, and trained weights are embedded in
the binary at compile time. Changing a generator without regenerating the
committed artifact fails a consistency test:

- **Skills** `.github/skills/<name>/SKILL.md` are `include_str!`-compiled via
  the macro list in `src/local_assets.rs`. Every tool in `src/registry.rs`
  must have a matching skill (test `tool_skills_cover_every_cataloged_tool`
  in that module enforces it). Adding a cataloged tool means touching the
  registry, the skills macro list, and the integrity manifest.
- **LM weights** `src/model_weights.bin` — regenerate after changing
  `src/language_model.rs` with:
  `cargo run --release --example train_weights > src/model_weights.bin`.
  Linux-gated test `committed_weights_match_a_freshly_trained_model` fails on
  drift.
- **Corpus** `src/corpus_catalog.txt` — regenerate after editing the tool
  catalog with `cargo run --example corpus_build`; a test asserts the
  committed file matches the generator.
- **Integrity manifest** `assets/tool_integrity.txt` — used by
  `src/integrity.rs` to verify installed tools; new cataloged tools need
  manifest entries (`--list-tools` shows the per-tool status).

## Authorization is load-bearing — never weaken it

This is an authorization-gated security tool. Changes to `src/policy.rs`,
`src/coordinator.rs`, or `src/governance.rs` must maintain or strengthen
checks, add tests, and document policy intent (CONTRIBUTING.md rules). Adding
a `Technique` variant requires coordinated edits to `src/registry.rs`,
`src/coordinator.rs`, and the README's Supported Target Types table —
half-done changes fail the registry/skill consistency tests. Offline by
default is an invariant: live tools require the explicit, per-invocation
`--allow-network` opt-in; `--ask` must never widen authority.

## Testing quirks

- CI's test gate is `cargo test --lib` only. The stated reason is that the
  optional candle feature can break full-suite compilation on some aarch64
  hosts (CONTRIBUTING.md); on x86-64 the full suite is fine.
- `tests/cli.rs` and `tests/report_e2e.rs` are black-box tests of the compiled
  binary via `CARGO_BIN_EXE_security-agent`. They are deterministic and must
  NOT depend on external tools (semgrep, nmap, …) being installed — keep new
  tests that way. `scripts/deploy.sh` runs the full `cargo test` (a superset
  of CI).
- Unit tests live inline per module plus a large `#[cfg(test)] mod` in
  `src/lib.rs` with shared `authorized_profile()` / `android_profile()`
  fixtures — reuse those instead of inventing new profiles.

## Repo layout beyond the docs

- `src/main.rs` dispatches ~40 CLI commands; many arsenal/offensive helpers
  (`--gen-shell`, `--analyze-payload`, `--obfuscate-ps`, `--listen`, …) are
  documented in `src/help.rs` (`--guide`, `--tool-help`, `--shell-guide`),
  not in README/OPERATING_GUIDE. `src/offensive/` is a real module directory
  (payload gen, listeners, recon, wireless, cloud, …).
- `electron/` is a separate npm project with its own `package-lock.json`; the
  GUI spawns the built Rust binary (`target/release/security-agent` or
  `target/debug/security-agent`). Changing Rust CLI output changes GUI
  behavior. Electron is not exercised by CI; `make electron*` targets drive
  it (`make electron` builds the release binary first).
- `sa` (repo root) is a wrapper that auto-builds the release binary and
  forwards args; `setup.sh` symlinks it into `~/.local/bin`.
- `Cargo.lock` is committed (binary crate). `target/`, `dist/`,
  `electron/node_modules/` are gitignored build output.

## Workflow

Conventional Commits, feature branches, PRs into protected `main`
(CONTRIBUTING.md). Run `cargo fmt --all` after edits, then the full CI gate
above before considering work done.
