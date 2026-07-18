pub mod advanced;
pub mod compat;
pub mod coordinator;
pub mod findings;
pub mod governance;
pub mod mission;
pub mod model;
pub mod policy;
pub mod registry;
pub mod roadmap;
pub mod workflow;

pub use advanced::{
    AttackPathEdge, AttackPathGraph, RetestSchedule, ThreatModelNode, propose_retest_schedule,
};
pub use compat::{CompatibilityEnvelope, IntegrationAdapter, JsonLineAdapter};
pub use coordinator::{Coordinator, ExecutionPlan, ScanTask};
pub use findings::{Finding, RiskScoreCalculator, Severity};
pub use governance::{AuditLedger, AuditRecord, Role};
pub use mission::MISSION_STATEMENT;
pub use model::{
    EngagementProfile, SpecialistKind, Target, TargetType, Technique, TestIntensity, TimeWindow,
};
pub use policy::{AuthorizationError, AuthorizationOutcome, PolicyEngine};
pub use registry::{
    CapabilityRegistry, SpecialistCapability, ToolDefinition, ToolchainPack, ToolchainPackRegistry,
    UseCase,
};
pub use roadmap::{ROADMAP_PHASES, RoadmapPhase};
pub use workflow::WorkflowStage;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile() -> EngagementProfile {
        EngagementProfile {
            engagement_id: "eng-001".to_string(),
            authorized_by: "secops".to_string(),
            time_window: TimeWindow {
                start_epoch_seconds: 10,
                end_epoch_seconds: 1000,
            },
            allowed_techniques: vec![
                Technique::PassiveRecon,
                Technique::ConfigurationAudit,
                Technique::Sast,
                Technique::ApiSecurity,
                Technique::Dast,
            ],
            deny_list_targets: vec!["prod-ledger".to_string()],
            max_intensity: TestIntensity::Standard,
            high_impact_approved: false,
        }
    }

    #[test]
    fn policy_blocks_denied_target() {
        let engine = PolicyEngine::default();
        let profile = sample_profile();
        let target = Target {
            id: "prod-ledger".to_string(),
            target_type: TargetType::Api,
            criticality: 10,
        };

        let result = engine.authorize_target_scan(
            &profile,
            &target,
            &[Technique::PassiveRecon],
            TestIntensity::Passive,
            50,
        );

        assert!(matches!(
            result,
            Err(AuthorizationError::TargetDenied(target_id)) if target_id == "prod-ledger"
        ));
    }

    #[test]
    fn coordinator_creates_scoped_tasks() {
        let capability_registry = CapabilityRegistry::default();
        let pack_registry = ToolchainPackRegistry::default();
        let policy_engine = PolicyEngine::default();
        let mut coordinator = Coordinator::new(capability_registry, pack_registry, policy_engine);

        let profile = sample_profile();
        let targets = vec![
            Target {
                id: "api-staging".to_string(),
                target_type: TargetType::Api,
                criticality: 5,
            },
            Target {
                id: "web-staging".to_string(),
                target_type: TargetType::WebApp,
                criticality: 3,
            },
        ];

        let plan = coordinator
            .plan_authorized_scan(profile, targets, 80)
            .expect("expected valid authorized plan");

        assert!(!plan.tasks.is_empty());
        assert_eq!(plan.high_impact_tasks, 0);
    }

    #[test]
    fn risk_score_normalizes_severity_and_confidence() {
        let score = RiskScoreCalculator::normalized_score(Severity::High, 80, true);
        assert!(score > 0.0);
        assert!(score <= 10.0);
    }
}
