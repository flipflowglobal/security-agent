# httrack — built-in offline substitute

**Real tool:** Website mirroring / offline copier.
**Function class:** Web application scanning
**Substitute fidelity:** Tier A. Faithful substitute — the offline analysis is essentially the real tool's job on a local input.

## What the built-in substitute does
Analyzes a *saved* HTTP response for missing/weak security headers, SQL-error signatures, and reflected-XSS sinks.

## Usage
```
security-agent --run-tool httrack <input-file>
```
Runs entirely offline — no network access, and no external `httrack` binary is
ever spawned.

## Expected input
A file containing a captured HTTP response (headers as `Header: value` lines, plus the body).

## Offline limitations
Offline: it inspects a response you already captured; it does not crawl or send requests to a live site.

## Notes
- **Network used:** No.
- Implemented in `src/arsenal.rs` under the `Web` category; dispatched
  from `crate::builtin_tools::run_builtin_tool`.
- See `SKILL.md` in this folder for the full engagement playbook and the
  tool's execution class / approval requirements.
