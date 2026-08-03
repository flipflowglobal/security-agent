# macchanger — built-in offline substitute

**Real tool:** MAC address manipulation utility.
**Function class:** Evasion / traffic manipulation
**Substitute fidelity:** Tier B. Partial substitute — real, useful offline analysis, but it does not perform the tool's live/active function (see limitations).

## What the built-in substitute does
Generates evasion transforms for a command/payload: PowerShell obfuscation variants and a decoy-traffic plan.

## Usage
```
security-agent --run-tool macchanger <input-file>
```
Runs entirely offline — no network access, and no external `macchanger` binary is
ever spawned.

## Expected input
A file whose contents are the command/payload to transform.

## Offline limitations
Offline: it generates transforms and a plan; it does not manipulate live traffic or interfaces.

## Notes
- **Network used:** No.
- Implemented in `src/arsenal.rs` under the `Evasion` category; dispatched
  from `crate::builtin_tools::run_builtin_tool`.
- See `SKILL.md` in this folder for the full engagement playbook and the
  tool's execution class / approval requirements.
