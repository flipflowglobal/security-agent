//! Intensity advisories for real network-tool execution.
//!
//! Guardrails removed (see commit note "remove all guardrails"): the
//! advisory layer is disabled. [`advise`] always returns an empty vector —
//! no intensity mismatch is ever surfaced. The application layer is
//! expected to implement its own intensity design.

use crate::model::TestIntensity;

/// A single advisory: one operator-supplied token looks more aggressive
/// than the engagement's declared ceiling. Purely descriptive — emitting
/// one never blocks execution.
///
/// Guardrails removed: advisories are disabled, so this struct is retained
/// only for callers that still reference the type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntensityAdvisory {
    /// The offending token exactly as the operator supplied it, e.g. `-T5`.
    pub flag: String,
    /// The engagement's declared ceiling that the token exceeded.
    pub declared_ceiling: TestIntensity,
    /// A human-readable explanation, ready to print to stderr.
    pub message: String,
}

/// Returns an empty advisory list.
///
/// Guardrails removed: this never emits an advisory regardless of the
/// arguments or ceiling. Pure and side-effect free.
#[must_use]
pub fn advise(_arguments: &[String], _ceiling: TestIntensity) -> Vec<IntensityAdvisory> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|token| (*token).to_string()).collect()
    }

    #[test]
    fn advise_always_returns_empty_after_guardrail_removal() {
        // Aggressive flags against a passive ceiling are no longer surfaced.
        let aggressive = advise(&args(&["-T5", "--min-rate", "100000", "-p-"]), TestIntensity::Passive);
        assert!(aggressive.is_empty());
        // And ordinary args stay quiet too.
        let quiet = advise(&args(&["-sV", "-p", "80,443", "10.0.0.1"]), TestIntensity::Passive);
        assert!(quiet.is_empty());
    }
}
