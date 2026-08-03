# aircrack-ng — built-in offline substitute

**Real tool:** WPA/WEP handshake capture and key cracking suite.
**Function class:** WPA handshake capture / cracking
**Substitute fidelity:** Tier A. Faithful substitute — the offline analysis is essentially the real tool's job on a local input.

## What the built-in substitute does
Parses captured EAPOL / WPA-handshake frames and reports handshake completeness.

## Usage
```
security-agent --run-tool aircrack-ng <input-file>
```
Runs entirely offline — no network access, and no external `aircrack-ng` binary is
ever spawned.

## Expected input
Hex-encoded EAPOL frames, one per line; falls back to the raw file bytes.

## Offline limitations
Offline: it validates and analyzes a captured handshake; it does not perform the dictionary crack.

## Notes
- **Network used:** No.
- Implemented in `src/arsenal.rs` under the `WirelessHandshake` category; dispatched
  from `crate::builtin_tools::run_builtin_tool`.
- See `SKILL.md` in this folder for the full engagement playbook and the
  tool's execution class / approval requirements.
