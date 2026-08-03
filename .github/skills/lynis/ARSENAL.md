# lynis — built-in offline substitute

**Real tool:** Host security auditing and hardening tool.
**Function class:** Host hardening / rootkit audit
**Substitute fidelity:** Tier A. Faithful substitute — the offline analysis is essentially the real tool's job on a local input.

## What the built-in substitute does
Reviews local host-hardening artifacts for privilege-escalation and misconfiguration risks.

## Usage
```
security-agent --run-tool lynis <input-file>
```
Runs entirely offline — no network access, and no external `lynis` binary is
ever spawned.

## Expected input
A copy of a system file — `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `authorized_keys`, or a hosts/trust file.

## Offline limitations
Faithful offline audit of the supplied artifact.

## Notes
- **Network used:** No.
- Implemented in `src/arsenal.rs` under the `Privesc` category; dispatched
  from `crate::builtin_tools::run_builtin_tool`.
- See `SKILL.md` in this folder for the full engagement playbook and the
  tool's execution class / approval requirements.
