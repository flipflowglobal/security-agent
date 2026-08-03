# rcrack — built-in offline substitute

**Real tool:** RainbowCrack rainbow-table hash cracker.
**Function class:** Password / hash cracking
**Substitute fidelity:** Tier A. Faithful substitute — the offline analysis is essentially the real tool's job on a local input.

## What the built-in substitute does
Reads candidate hashes (one per line) and identifies each hash's likely algorithm and format.

## Usage
```
security-agent --run-tool rcrack <input-file>
```
Runs entirely offline — no network access, and no external `rcrack` binary is
ever spawned.

## Expected input
A text file with one hash per line (`#` comments ignored).

## Offline limitations
Offline: it *fingerprints and classifies* hashes; it does not brute-force or recover plaintext (that needs the live tool).

## Notes
- **Network used:** No.
- Implemented in `src/arsenal.rs` under the `HashCracker` category; dispatched
  from `crate::builtin_tools::run_builtin_tool`.
- See `SKILL.md` in this folder for the full engagement playbook and the
  tool's execution class / approval requirements.
