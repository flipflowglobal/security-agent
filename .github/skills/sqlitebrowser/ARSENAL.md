# sqlitebrowser — built-in offline substitute

**Real tool:** SQLite database browser.
**Function class:** Local forensic artifact parsing
**Substitute fidelity:** Tier B. Partial substitute — real, useful offline analysis, but it does not perform the tool's live/active function (see limitations).

## What the built-in substitute does
Detects the artifact's file type and extracts printable strings.

## Usage
```
security-agent --run-tool sqlitebrowser <input-file>
```
Runs entirely offline — no network access, and no external `sqlitebrowser` binary is
ever spawned.

## Expected input
Any local artifact file (index.dat, database, notebook, recording, ...).

## Offline limitations
Offline: generic artifact triage. It does not fully parse proprietary formats the real tool understands.

## Notes
- **Network used:** No.
- Implemented in `src/arsenal.rs` under the `Forensic` category; dispatched
  from `crate::builtin_tools::run_builtin_tool`.
- See `SKILL.md` in this folder for the full engagement playbook and the
  tool's execution class / approval requirements.
