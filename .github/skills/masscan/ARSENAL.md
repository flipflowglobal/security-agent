# masscan — built-in offline substitute

**Real tool:** Internet-scale asynchronous port scanner.
**Function class:** Network scanning / discovery
**Substitute fidelity:** Tier B. Partial substitute — real, useful offline analysis, but it does not perform the tool's live/active function (see limitations).

## What the built-in substitute does
Parses a saved host/service inventory and flags risky exposed services (telnet, SMB, RDP, exposed databases, SNMP, ...).

## Usage
```
security-agent --run-tool masscan <input-file>
```
Runs entirely offline — no network access, and no external `masscan` binary is
ever spawned.

## Expected input
A saved scan or asset list — e.g. `host port service` lines or a prior scan export.

## Offline limitations
Offline: active probing is disabled. It analyzes an inventory you provide; it does not scan the network itself.

## Notes
- **Network used:** No.
- Implemented in `src/arsenal.rs` under the `ScanInventory` category; dispatched
  from `crate::builtin_tools::run_builtin_tool`.
- See `SKILL.md` in this folder for the full engagement playbook and the
  tool's execution class / approval requirements.
