# cewl — built-in offline substitute

**Real tool:** Custom wordlist builder that scrapes words from content.
**Function class:** Wordlist generation
**Substitute fidelity:** Tier A. Faithful substitute — the offline analysis is essentially the real tool's job on a local input.

## What the built-in substitute does
Generates a targeted wordlist from a seed term plus optional extra seed words.

## Usage
```
security-agent --run-tool cewl <input-file>
```
Runs entirely offline — no network access, and no external `cewl` binary is
ever spawned.

## Expected input
First line: the seed/target word. Following lines: optional extra seeds.

## Offline limitations
Faithful offline generator; produces up to 1000 candidate words.

## Notes
- **Network used:** No.
- Implemented in `src/arsenal.rs` under the `Wordlist` category; dispatched
  from `crate::builtin_tools::run_builtin_tool`.
- See `SKILL.md` in this folder for the full engagement playbook and the
  tool's execution class / approval requirements.
