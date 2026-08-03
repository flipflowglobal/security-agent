# setoolkit — built-in offline substitute

**Real tool:** Social-Engineer Toolkit.
**Function class:** Payload / exploit generation
**Substitute fidelity:** Tier B. Partial substitute — real, useful offline analysis, but it does not perform the tool's live/active function (see limitations).

## What the built-in substitute does
Analyzes a payload/command string and suggests evasion transforms.

## Usage
```
security-agent --run-tool setoolkit <input-file>
```
Runs entirely offline — no network access, and no external `setoolkit` binary is
ever spawned.

## Expected input
A file whose contents are the payload or command string to analyze.

## Offline limitations
Offline: it characterizes and advises on a payload; it does not build or deliver a live exploit.

## Notes
- **Network used:** No.
- Implemented in `src/arsenal.rs` under the `Payload` category; dispatched
  from `crate::builtin_tools::run_builtin_tool`.
- See `SKILL.md` in this folder for the full engagement playbook and the
  tool's execution class / approval requirements.
