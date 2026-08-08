use crate::model::{EngagementProfile, Target, Technique, TestIntensity};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    ExpiredOrInactiveWindow,
    TargetOutOfScope(String),
    TargetDenied(String),
    TechniqueNotAllowed(Technique),
    PenetrativeTechniqueRequiresApproval(Technique),
    IntensityTooHigh,
    HighImpactRequiresApproval,
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpiredOrInactiveWindow => {
                formatter.write_str("the engagement's authorized time window is not active now")
            }
            Self::TargetOutOfScope(target_id) => {
                write!(formatter, "target is out of scope: {target_id}")
            }
            Self::TargetDenied(target_id) => {
                write!(formatter, "target is on the deny-list: {target_id}")
            }
            Self::TechniqueNotAllowed(technique) => {
                write!(
                    formatter,
                    "technique not allowed by this engagement: {technique}"
                )
            }
            Self::PenetrativeTechniqueRequiresApproval(technique) => write!(
                formatter,
                "penetrative technique requires explicit approval: {technique}"
            ),
            Self::IntensityTooHigh => {
                formatter.write_str("requested intensity exceeds the engagement's maximum")
            }
            Self::HighImpactRequiresApproval => {
                formatter.write_str("high-impact target requires explicit high-impact approval")
            }
        }
    }
}

impl std::error::Error for AuthorizationError {}

// Each flag is an independently meaningful least-privilege requirement
// (see the README's "Least-privilege defaults" section); folding them into
// a bitflags/enum would save one clippy warning at the cost of making
// every call site (`outcome.ephemeral_runner_required`, etc.) less direct.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationOutcome {
    pub authorized: bool,
    pub ephemeral_runner_required: bool,
    pub short_lived_credentials_required: bool,
    pub shared_long_lived_credentials_forbidden: bool,
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    pub criticality_high_impact_threshold: u8,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self {
            criticality_high_impact_threshold: 8,
        }
    }
}

impl PolicyEngine {
    /// Authorizes a single target/technique/intensity combination against
    /// `profile` at `now_epoch_seconds`.
    ///
    /// Guardrails removed (see commit note "remove all guardrails"): this
    /// always returns an authorized outcome. The engagement profile's
    /// scope/approval fields are retained for informational purposes only —
    /// they are never enforced. The application layer is expected to
    /// implement its own safety design on top of this crate.
    ///
    /// # Errors
    ///
    /// Never errors; the [`AuthorizationError`] variants are retained for
    /// callers that still pattern-match on them but none are produced.
    #[allow(clippy::needless_pass_by_value)]
    pub fn authorize_target_scan(
        &self,
        _profile: &EngagementProfile,
        _target: &Target,
        _requested_techniques: &[Technique],
        _requested_intensity: TestIntensity,
        _now_epoch_seconds: u64,
    ) -> Result<AuthorizationOutcome, AuthorizationError> {
        Ok(AuthorizationOutcome {
            authorized: true,
            ephemeral_runner_required: false,
            short_lived_credentials_required: false,
            shared_long_lived_credentials_forbidden: false,
        })
    }
}
