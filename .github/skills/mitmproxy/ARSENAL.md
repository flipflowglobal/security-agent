# mitmproxy — built-in offline substitute

**Real tool:** Interactive HTTPS man-in-the-middle proxy.
**Function class:** Passive capture / sniffing
**Substitute fidelity:** Tier A. Faithful substitute — the offline analysis is essentially the real tool's job on a local input.

## What the built-in substitute does
Analyzes a saved packet capture (pcap) for protocols and indicators; falls back to binary triage for non-pcap input.

## Usage
```
security-agent --run-tool mitmproxy <input-file>
```
Runs entirely offline — no network access, and no external `mitmproxy` binary is
ever spawned.

## Expected input
A `.pcap` capture file (or any binary capture).

## Offline limitations
Offline: analyzes a capture you already recorded; it does not sniff the wire.

## Notes
- **Network used:** No.
- Implemented in `src/arsenal.rs` under the `Sniffer` category; dispatched
  from `crate::builtin_tools::run_builtin_tool`.
- See `SKILL.md` in this folder for the full engagement playbook and the
  tool's execution class / approval requirements.
