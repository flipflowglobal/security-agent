//! Active-tool gating — the execution-time authorization check for *which
//! tools* an engagement may run.
//!
//! The runtime already gates two axes of a live engagement: [`crate::scope`]
//! restricts the network *targets* a step may reach, and the network mode
//! ([`crate::network_policy`]) gates *live traffic*. This is the third axis,
//! and the one a rules-of-engagement document cares about most — only the
//! tools explicitly authorized for the engagement may execute; everything
//! else is refused before it spawns.
//!
//! The gate is defense-in-depth: the planner already restricts a schedule to
//! approved tools, but the runtime should not *trust* that — a bug, a tampered
//! schedule, or a future result-driven expansion could introduce a tool the
//! engagement never authorized. The runtime consults this gate per step and
//! **fails closed**: an empty allow-list authorizes nothing.

use std::collections::BTreeSet;

/// A tool-authorization policy: an optional allow-list plus a deny-list.
///
/// * `allow == None` — no allow-list; every tool passes the allow check (the
///   deny-list still applies). This is the unrestricted default.
/// * `allow == Some(set)` — only tools in `set` may run. `Some(empty)`
///   authorizes nothing (fail-closed).
///
/// The deny-list always wins over the allow-list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolGate {
    allow: Option<BTreeSet<String>>,
    deny: BTreeSet<String>,
}

/// The gate's verdict for one tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// The tool is authorized to run.
    Allowed,
    /// The tool is refused; the string explains why, for the refusal record.
    Denied(String),
}

impl GateDecision {
    /// `true` when the tool may run.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

impl ToolGate {
    /// An unrestricted gate: every tool is allowed and nothing is denied.
    #[must_use]
    pub fn unrestricted() -> Self {
        Self::default()
    }

    /// A gate whose allow-list is exactly `tools`. Only those tools may run;
    /// an empty iterator authorizes nothing (fail-closed).
    #[must_use]
    pub fn allow_only<I, S>(tools: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allow: Some(tools.into_iter().map(Into::into).collect()),
            deny: BTreeSet::new(),
        }
    }

    /// Adds `tools` to the deny-list (which always wins over the allow-list).
    #[must_use]
    pub fn deny<I, S>(mut self, tools: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.deny.extend(tools.into_iter().map(Into::into));
        self
    }

    /// Narrows the allow-list to its intersection with `tools` — an operator
    /// can only *further restrict* what the engagement already authorized,
    /// never widen it. With no existing allow-list, this establishes one.
    #[must_use]
    pub fn restrict_to<I, S>(mut self, tools: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let requested: BTreeSet<String> = tools.into_iter().map(Into::into).collect();
        self.allow = Some(match self.allow.take() {
            Some(existing) => existing.intersection(&requested).cloned().collect(),
            None => requested,
        });
        self
    }

    /// `true` when this gate restricts anything (it has an allow-list or a
    /// non-empty deny-list). An unrestricted gate is a no-op.
    #[must_use]
    pub fn is_restricting(&self) -> bool {
        self.allow.is_some() || !self.deny.is_empty()
    }

    /// The number of tools on the allow-list, or `None` when unrestricted.
    #[must_use]
    pub fn allowed_count(&self) -> Option<usize> {
        self.allow.as_ref().map(BTreeSet::len)
    }

    /// The gate's decision for `tool`: the deny-list is checked first, then
    /// the allow-list. Fails closed when an allow-list is present.
    #[must_use]
    pub fn decision(&self, tool: &str) -> GateDecision {
        if self.deny.contains(tool) {
            return GateDecision::Denied(format!("tool '{tool}' is on the engagement deny-list"));
        }
        if let Some(allow) = &self.allow {
            if !allow.contains(tool) {
                return GateDecision::Denied(format!(
                    "tool '{tool}' is not in the engagement tool allow-list"
                ));
            }
        }
        GateDecision::Allowed
    }

    /// Convenience: `true` when `tool` is authorized to run.
    #[must_use]
    pub fn allows(&self, tool: &str) -> bool {
        self.decision(tool).is_allowed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_allows_everything() {
        let gate = ToolGate::unrestricted();
        assert!(gate.allows("nmap"));
        assert!(gate.allows("anything"));
        assert!(!gate.is_restricting());
        assert_eq!(gate.allowed_count(), None);
    }

    #[test]
    fn allow_list_admits_only_listed_tools() {
        let gate = ToolGate::allow_only(["nmap", "gobuster"]);
        assert!(gate.allows("nmap"));
        assert!(!gate.allows("sqlmap"));
        assert!(gate.is_restricting());
        assert_eq!(gate.allowed_count(), Some(2));
    }

    #[test]
    fn empty_allow_list_fails_closed() {
        let gate = ToolGate::allow_only(Vec::<String>::new());
        assert!(!gate.allows("nmap"));
        match gate.decision("nmap") {
            GateDecision::Denied(reason) => assert!(reason.contains("allow-list")),
            GateDecision::Allowed => panic!("empty allow-list must deny"),
        }
    }

    #[test]
    fn deny_list_wins_over_allow_list() {
        let gate = ToolGate::allow_only(["nmap", "sqlmap"]).deny(["sqlmap"]);
        assert!(gate.allows("nmap"));
        assert!(!gate.allows("sqlmap"));
        match gate.decision("sqlmap") {
            GateDecision::Denied(reason) => assert!(reason.contains("deny-list")),
            GateDecision::Allowed => panic!("denied tool must not run"),
        }
    }

    #[test]
    fn restrict_to_only_narrows() {
        // From a 3-tool authorization, an operator narrows to a 2-tool subset.
        let gate = ToolGate::allow_only(["nmap", "gobuster", "sqlmap"])
            .restrict_to(["nmap", "sqlmap", "hydra"]);
        // Intersection only: hydra was never authorized, so it stays denied.
        assert!(gate.allows("nmap"));
        assert!(gate.allows("sqlmap"));
        assert!(!gate.allows("gobuster"));
        assert!(!gate.allows("hydra"));
        assert_eq!(gate.allowed_count(), Some(2));
    }

    #[test]
    fn restrict_to_on_unrestricted_establishes_the_list() {
        let gate = ToolGate::unrestricted().restrict_to(["nmap"]);
        assert!(gate.allows("nmap"));
        assert!(!gate.allows("gobuster"));
    }
}
