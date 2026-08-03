# reaver — built-in offline substitute

**Real tool:** WPS PIN brute-force attack tool.
**Function class:** WPS PIN attack
**Substitute fidelity:** Tier A. Faithful substitute — the offline analysis is essentially the real tool's job on a local input.

## What the built-in substitute does
Analyzes an 8-digit WPS PIN for structural weakness (checksum, known-default patterns).

## Usage
```
security-agent --run-tool reaver <input-file>
```
Runs entirely offline — no network access, and no external `reaver` binary is
ever spawned.

## Expected input
First line: an 8-digit WPS PIN.

## Offline limitations
Offline: structural analysis only; it does not transmit WPS attempts.

## Notes
- **Network used:** No.
- Implemented in `src/arsenal.rs` under the `WpsAttack` category; dispatched
  from `crate::builtin_tools::run_builtin_tool`.
- See `SKILL.md` in this folder for the full engagement playbook and the
  tool's execution class / approval requirements.
