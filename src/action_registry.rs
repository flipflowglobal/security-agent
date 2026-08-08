//! The catalog of actions the agent loop can invoke.
//!
//! Stage 16 (agent mode) lets the built-in model *drive* the binary: turn a
//! plain-English goal into a sequence of real command invocations and run
//! them. For that to be safe and grounded, the model must plan against a
//! fixed, machine-readable description of what the binary can actually do —
//! not free-form command strings it might hallucinate. This module is that
//! description.
//!
//! Every [`ActionSpec`] names one command, classifies it
//! ([`ActionClass`]) so the agent's policy can gate effectful and
//! network-touching actions, declares the one argument it resolves from the
//! goal ([`ArgKind`]), and carries the trigger words and example phrasings the
//! grounded router scores against (mirroring [`crate::nlu`]'s approach). The
//! registry is static and deterministic: the same goal always plans to the
//! same actions.

/// How dangerous an action is, so the agent policy can gate it. `ReadOnly`
/// actions run autonomously; anything else needs an explicit opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionClass {
    /// Reads and prints only — never writes, authorizes, or touches the
    /// network. Safe to run without confirmation.
    ReadOnly,
    /// Persists data to disk (a log, a database, a report file).
    Writes,
    /// Plans or authorizes an engagement, or performs live network activity.
    /// The most privileged class.
    Privileged,
}

impl ActionClass {
    /// Whether this action does anything beyond reading — i.e. requires the
    /// agent's execute opt-in before it may run.
    #[must_use]
    pub const fn is_effectful(self) -> bool {
        !matches!(self, Self::ReadOnly)
    }

    /// A short label for transcripts and audit records.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::Writes => "writes",
            Self::Privileged => "privileged",
        }
    }
}

/// The single argument an action resolves from the goal text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    /// Takes no argument.
    None,
    /// The name of one of the agent's tools or skills (e.g. `nmap`).
    AssetName,
    /// A filesystem path (recognized by a `/` or `.` in a token).
    Path,
    /// Free text (the remainder of the goal after command words).
    Text,
}

/// One invocable action: a command, its safety class, the argument it takes,
/// and the routing signals that match a goal to it.
#[derive(Debug, Clone, Copy)]
pub struct ActionSpec {
    /// Stable short identifier, e.g. `"list-tools"`.
    pub name: &'static str,
    /// The CLI command the executor runs, e.g. `"--list-tools"`.
    pub command: &'static str,
    /// One-line description of what the action does.
    pub summary: &'static str,
    /// Safety class, used by the agent policy to gate execution.
    pub class: ActionClass,
    /// Whether the action performs live network I/O (needs `--allow-network`).
    pub network: bool,
    /// The argument the action resolves from the goal.
    pub arg: ArgKind,
    /// Trigger words/phrases (a phrase with a space must appear verbatim).
    pub triggers: &'static [&'static str],
    /// Example phrasings, embedded to form the action's semantic centroid.
    pub examples: &'static [&'static str],
}

/// The complete set of actions the agent may plan and invoke. Ordered
/// roughly least- to most-privileged; the planner preserves goal order, not
/// this order, so registry order only affects tie-breaking.
pub static REGISTRY: &[ActionSpec] = &[
    ActionSpec {
        name: "offline-status",
        command: "--offline-status",
        summary: "Report local runtime health: tools, skills, coverage.",
        class: ActionClass::ReadOnly,
        network: false,
        arg: ArgKind::None,
        triggers: &["status", "health", "ready", "healthy"],
        examples: &[
            "report your status",
            "are you healthy",
            "run a health check",
        ],
    },
    ActionSpec {
        name: "list-tools",
        command: "--list-tools",
        summary: "List cataloged tools and whether each is installed.",
        class: ActionClass::ReadOnly,
        network: false,
        arg: ArgKind::None,
        triggers: &["list tools", "tools", "tool catalog"],
        examples: &[
            "list your tools",
            "what tools do you have",
            "show the tool catalog",
        ],
    },
    ActionSpec {
        name: "list-skills",
        command: "--list-skills",
        summary: "List the step-by-step skill playbooks compiled in.",
        class: ActionClass::ReadOnly,
        network: false,
        arg: ArgKind::None,
        triggers: &["list skills", "skills", "playbooks"],
        examples: &[
            "list your skills",
            "what skills do you have",
            "show the playbooks",
        ],
    },
    ActionSpec {
        name: "show-skill",
        command: "--show-skill",
        summary: "Print one skill's full playbook.",
        class: ActionClass::ReadOnly,
        network: false,
        arg: ArgKind::AssetName,
        triggers: &["explain", "describe", "skill for", "how do i use"],
        examples: &[
            "explain the nmap skill",
            "show me the nikto playbook",
            "describe hydra",
        ],
    },
    ActionSpec {
        name: "build-info",
        command: "--build-info",
        summary: "Print the binary's build provenance.",
        class: ActionClass::ReadOnly,
        network: false,
        arg: ArgKind::None,
        triggers: &[
            "build info",
            "provenance",
            "what commit",
            "which version built",
        ],
        examples: &[
            "show build info",
            "what commit are you",
            "print build provenance",
        ],
    },
    ActionSpec {
        name: "view-audit",
        command: "--view-audit",
        summary: "Read a JSON Lines audit log.",
        class: ActionClass::ReadOnly,
        network: false,
        arg: ArgKind::Path,
        triggers: &["audit log", "audit", "ledger"],
        examples: &[
            "view the audit log",
            "show audit records",
            "read the audit ledger",
        ],
    },
    ActionSpec {
        name: "report",
        command: "--report",
        summary: "Render a deliverable report from a findings log.",
        class: ActionClass::ReadOnly,
        network: false,
        arg: ArgKind::Path,
        triggers: &["report", "deliverable", "render findings"],
        examples: &[
            "write a report from the findings",
            "render the findings report",
            "produce a deliverable",
        ],
    },
    ActionSpec {
        name: "schedule-retest",
        command: "--schedule-retest",
        summary: "Order findings by risk for a verification pass.",
        class: ActionClass::ReadOnly,
        network: false,
        arg: ArgKind::Path,
        triggers: &["retest", "reschedule", "verification pass"],
        examples: &[
            "schedule a retest",
            "order findings for retest",
            "plan a verification pass",
        ],
    },
    ActionSpec {
        name: "generate",
        command: "--llm-generate",
        summary: "Continue a prompt with the built-in language model.",
        class: ActionClass::ReadOnly,
        network: false,
        arg: ArgKind::Text,
        triggers: &["generate", "write", "compose", "draft", "continue"],
        examples: &[
            "generate text about scanning",
            "write a note",
            "continue this prompt",
        ],
    },
    ActionSpec {
        name: "anomaly-check",
        command: "--llm-perplexity",
        summary: "Score how out-of-domain a string reads.",
        class: ActionClass::ReadOnly,
        network: false,
        arg: ArgKind::Text,
        triggers: &["anomaly", "suspicious", "perplexity", "surprising", "weird"],
        examples: &[
            "is this suspicious",
            "score this for anomaly",
            "how surprising is this",
        ],
    },
    ActionSpec {
        name: "record-findings",
        command: "--record-findings",
        summary: "Merge one findings log into another (writes).",
        class: ActionClass::Writes,
        network: false,
        arg: ArgKind::Path,
        triggers: &["record findings", "merge findings", "accumulate findings"],
        examples: &[
            "merge these findings",
            "record the findings log",
            "accumulate findings",
        ],
    },
    ActionSpec {
        name: "plan-scan",
        command: "--plan-scan",
        summary: "Validate scope/approvals and print the scan plan (offline).",
        class: ActionClass::Privileged,
        network: false,
        arg: ArgKind::Path,
        triggers: &["plan scan", "plan a scan", "validate scope", "scan plan"],
        examples: &[
            "plan a scan from this config",
            "validate the engagement scope",
            "build a scan plan",
        ],
    },
    ActionSpec {
        name: "run-engagement",
        command: "--run-engagement",
        summary: "Run the staged engagement engine (live when --allow-network).",
        class: ActionClass::Privileged,
        network: true,
        arg: ArgKind::Path,
        triggers: &[
            "run engagement",
            "run the engagement",
            "execute the engagement",
            "run scan",
        ],
        examples: &[
            "run the engagement from this config",
            "execute the staged scan",
            "run the assessment",
        ],
    },
];

/// Looks up an action by its stable `name`.
#[must_use]
pub fn by_name(name: &str) -> Option<&'static ActionSpec> {
    REGISTRY.iter().find(|spec| spec.name == name)
}

/// Looks up an action by the CLI `command` it runs.
#[must_use]
pub fn by_command(command: &str) -> Option<&'static ActionSpec> {
    REGISTRY.iter().find(|spec| spec.command == command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_entries_are_internally_consistent() {
        for spec in REGISTRY {
            assert!(!spec.name.is_empty());
            assert!(spec.command.starts_with("--"), "{}", spec.command);
            assert!(!spec.triggers.is_empty(), "{} has no triggers", spec.name);
            assert!(!spec.examples.is_empty(), "{} has no examples", spec.name);
            // Only privileged actions may touch the network.
            if spec.network {
                assert_eq!(spec.class, ActionClass::Privileged, "{}", spec.name);
            }
        }
    }

    #[test]
    fn names_and_commands_are_unique() {
        for (index, spec) in REGISTRY.iter().enumerate() {
            for other in &REGISTRY[index + 1..] {
                assert_ne!(spec.name, other.name, "duplicate name {}", spec.name);
                assert_ne!(
                    spec.command, other.command,
                    "duplicate cmd {}",
                    spec.command
                );
            }
        }
    }

    #[test]
    fn lookup_by_name_and_command_round_trips() {
        for spec in REGISTRY {
            assert_eq!(by_name(spec.name).unwrap().command, spec.command);
            assert_eq!(by_command(spec.command).unwrap().name, spec.name);
        }
        assert!(by_name("does-not-exist").is_none());
        assert!(by_command("--nope").is_none());
    }

    #[test]
    fn class_effectfulness_is_correct() {
        assert!(!ActionClass::ReadOnly.is_effectful());
        assert!(ActionClass::Writes.is_effectful());
        assert!(ActionClass::Privileged.is_effectful());
    }
}
