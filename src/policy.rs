use crate::model::{EngagementProfile, Target, Technique, TestIntensity};

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

fn is_penetrative_technique(technique: &Technique) -> bool {
    matches!(
        technique,
        Technique::Dast
            | Technique::ApiSecurity
            | Technique::MobileRuntime
            | Technique::ExploitValidationSandboxed
    )
}
