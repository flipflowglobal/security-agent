# androguard — built-in offline substitute

**Real tool:** Android APK/DEX static analysis toolkit.
**Function class:** Mobile / binary reverse engineering
**Substitute fidelity:** Tier B. Partial substitute — real, useful offline analysis, but it does not perform the tool's live/active function (see limitations).

## What the built-in substitute does
Performs offline binary triage — entropy, embedded signatures, and printable strings — on the supplied file.

## Usage
```
security-agent --run-tool androguard <input-file>
```
Runs entirely offline — no network access, and no external `androguard` binary is
ever spawned.

## Expected input
Any binary/APK/DEX/native file.

## Offline limitations
Offline: triage only. It is *not* a full decompiler; use the real tool for complete disassembly/decompilation.

## Notes
- **Network used:** No.
- Implemented in `src/arsenal.rs` under the `Binary` category; dispatched
  from `crate::builtin_tools::run_builtin_tool`.
- See `SKILL.md` in this folder for the full engagement playbook and the
  tool's execution class / approval requirements.
