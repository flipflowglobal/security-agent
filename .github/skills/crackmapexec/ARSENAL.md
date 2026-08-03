# crackmapexec — built-in offline substitute

**Real tool:** Active Directory / SMB post-exploitation and credential sweeper.
**Function class:** Credential / brute-force attack
**Substitute fidelity:** Tier B. Partial substitute — real, useful offline analysis, but it does not perform the tool's live/active function (see limitations).

## What the built-in substitute does
Ranks each supplied credential by its resistance to guessing, accepting `user:pass` pairs or bare passwords.

## Usage
```
security-agent --run-tool crackmapexec <input-file>
```
Runs entirely offline — no network access, and no external `crackmapexec` binary is
ever spawned.

## Expected input
A text file with one credential per line.

## Offline limitations
Offline: live authentication and brute force are disabled. It scores candidate strength only — it never contacts a target.

## Notes
- **Network used:** No.
- Implemented in `src/arsenal.rs` under the `Credential` category; dispatched
  from `crate::builtin_tools::run_builtin_tool`.
- See `SKILL.md` in this folder for the full engagement playbook and the
  tool's execution class / approval requirements.
