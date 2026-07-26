//! Network-egress governance for the runtime.
//!
//! The agent is **offline by default**: no command performs live-target or
//! network-tool activity unless the operator explicitly opts in *for that
//! invocation*. This module carries that opt-in as an explicit
//! [`NetworkMode`] value threaded into the execution path
//! ([`crate::execution`]), so going online is always a deliberate,
//! per-invocation, auditable decision rather than an ambient default.
//!
//! Offline mode still permits the fully-local analyzers (built-in
//! substitutes and `StaticLocalAnalysis` tools, which touch only local
//! files). Online mode additionally unlocks the real, installed
//! `ActiveNetwork` and `ActiveExploitation` tools — for **authorized**
//! security work, still gated by the engagement authorization policy
//! ([`crate::policy`]) when run through a planned scan. This module governs
//! *whether the operator has opted into egress at all*; it does not replace
//! the scope/technique/approval checks that authorize a specific engagement.

/// Whether live network / live-target activity is permitted for the current
/// invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkMode {
    /// Fully local: only offline analyzers and `StaticLocalAnalysis` tools
    /// may run. No live-target or network activity. This is the default.
    #[default]
    Offline,
    /// The operator explicitly opted in (for this invocation) to live
    /// network / active testing, unlocking the real `ActiveNetwork` and
    /// `ActiveExploitation` tools.
    Online,
}

impl NetworkMode {
    /// Selects the mode from an explicit operator opt-in flag: `true` yields
    /// [`NetworkMode::Online`], `false` the offline default.
    #[must_use]
    pub const fn from_opt_in(online: bool) -> Self {
        if online { Self::Online } else { Self::Offline }
    }

    /// Whether real `ActiveNetwork` / `ActiveExploitation` tools may run.
    #[must_use]
    pub const fn allows_active(self) -> bool {
        matches!(self, Self::Online)
    }

    /// A short label for status output and audit records.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Online => "online",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_is_the_default() {
        assert_eq!(NetworkMode::default(), NetworkMode::Offline);
        assert!(!NetworkMode::default().allows_active());
    }

    #[test]
    fn opt_in_selects_online() {
        assert_eq!(NetworkMode::from_opt_in(true), NetworkMode::Online);
        assert_eq!(NetworkMode::from_opt_in(false), NetworkMode::Offline);
        assert!(NetworkMode::from_opt_in(true).allows_active());
    }

    #[test]
    fn labels_are_stable() {
        assert_eq!(NetworkMode::Offline.label(), "offline");
        assert_eq!(NetworkMode::Online.label(), "online");
    }
}
