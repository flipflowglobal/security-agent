# semgrep — built-in offline substitute

**Real tool:** Static analysis pattern scanner for source code.
**Function class:** Static source analysis
**Substitute fidelity:** Tier A. Faithful substitute — the offline analysis is essentially the real tool's job on a local input.

## What the built-in substitute does
Pattern-scans source code for insecure calls (eval/exec/deserialization), weak crypto, and embedded secrets/keys.

## Usage
```
security-agent --run-tool semgrep <input-file>
```
Runs entirely offline — no network access, and no external `semgrep` binary is
ever spawned.

## Expected input
A source file (any language) to scan.

## Offline limitations
Faithful offline pattern scan; heuristic, not a full dataflow analysis.

## Notes
- **Network used:** No.
- Implemented in `src/arsenal.rs` under the `SourceScan` category; dispatched
  from `crate::builtin_tools::run_builtin_tool`.
- See `SKILL.md` in this folder for the full engagement playbook and the
  tool's execution class / approval requirements.
