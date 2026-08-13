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
    /// Enforces every guardrail declared in the engagement profile: the
    /// authorized time window, the in-scope and deny-list target sets, the
    /// allowed techniques (plus the explicit approval required for
    /// penetrative techniques), the intensity ceiling, and the explicit
    /// high-impact approval for critical targets. Fail-closed by default.
    ///
    /// # Errors
    ///
    /// Returns the first applicable [`AuthorizationError`]: an expired or
    /// not-yet-active engagement window, a target outside scope or on the
    /// deny-list, a disallowed or unapproved-penetrative technique, an
    /// intensity above the profile's cap, or a high-impact target lacking
    /// explicit approval.
    pub fn authorize_target_scan(
        &self,
        profile: &EngagementProfile,
        target: &Target,
        requested_techniques: &[Technique],
        requested_intensity: TestIntensity,
        now_epoch_seconds: u64,
    ) -> Result<AuthorizationOutcome, AuthorizationError> {
        if now_epoch_seconds < profile.time_window.start_epoch_seconds
            || now_epoch_seconds > profile.time_window.end_epoch_seconds
        {
            return Err(AuthorizationError::ExpiredOrInactiveWindow);
        }

        if !profile
            .in_scope_targets
            .iter()
            .any(|target_id| target_id == &target.id)
        {
            return Err(AuthorizationError::TargetOutOfScope(target.id.clone()));
        }

        if profile.deny_list_targets.iter().any(|id| id == &target.id) {
            return Err(AuthorizationError::TargetDenied(target.id.clone()));
        }

        for technique in requested_techniques {
            if !profile
                .allowed_techniques
                .iter()
                .any(|allowed| allowed == technique)
            {
                return Err(AuthorizationError::TechniqueNotAllowed(technique.clone()));
            }
            if is_penetrative_technique(technique) && !profile.penetrative_testing_approved {
                return Err(AuthorizationError::PenetrativeTechniqueRequiresApproval(
                    technique.clone(),
                ));
            }
        }

        if requested_intensity > profile.max_intensity {
            return Err(AuthorizationError::IntensityTooHigh);
        }

        if target.criticality >= self.criticality_high_impact_threshold
            && !profile.high_impact_approved
            && requested_intensity >= TestIntensity::Standard
        {
            return Err(AuthorizationError::HighImpactRequiresApproval);
        }

        Ok(AuthorizationOutcome {
            authorized: true,
            ephemeral_runner_required: true,
            short_lived_credentials_required: true,
            shared_long_lived_credentials_forbidden: true,
        })
    }
}

const fn is_penetrative_technique(technique: &Technique) -> bool {
    matches!(
        technique,
        Technique::Dast
            | Technique::ApiSecurity
            | Technique::MobileRuntime
            | Technique::ExploitValidationSandboxed
    )
}
