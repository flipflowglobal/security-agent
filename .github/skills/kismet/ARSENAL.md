# kismet — built-in offline substitute

**Real tool:** Wireless network detector and sniffer.
**Function class:** Wireless network audit
**Substitute fidelity:** Tier A. Faithful substitute — the offline analysis is essentially the real tool's job on a local input.

## What the built-in substitute does
Audits a wireless survey export, flagging weak security/encryption per network.

## Usage
```
security-agent --run-tool kismet <input-file>
```
Runs entirely offline — no network access, and no external `kismet` binary is
ever spawned.

## Expected input
One network per line as `ESSID,security(WPA2/WPA3/WEP/Open),encryption(CCMP/TKIP/None)`.

## Offline limitations
Offline: analyzes a survey you exported; it does not scan the air.

## Notes
- **Network used:** No.
- Implemented in `src/arsenal.rs` under the `WirelessAudit` category; dispatched
  from `crate::builtin_tools::run_builtin_tool`.
- See `SKILL.md` in this folder for the full engagement playbook and the
  tool's execution class / approval requirements.
