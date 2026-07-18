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

    fn android_profile() -> EngagementProfile {
        EngagementProfile {
            engagement_id: "eng-android-001".to_string(),
            authorized_by: "mobile-secops".to_string(),
            time_window: TimeWindow {
                start_epoch_seconds: 10,
                end_epoch_seconds: 1000,
            },
            allowed_techniques: vec![
                Technique::AndroidStaticAnalysis,
                Technique::MobileRuntime,
                Technique::SecretScan,
                Technique::DependencyAudit,
                Technique::ApiSecurity,
                Technique::ConfigurationAudit,
                Technique::Sast,
                Technique::ThreatModeling,
                Technique::AttackPathAnalysis,
            ],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Aggressive,
            high_impact_approved: true,
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

    #[test]
    fn android_scan_generates_mobile_tasks() {
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );

        let profile = android_profile();
        let targets = vec![Target {
            id: "com.example.app".to_string(),
            target_type: TargetType::MobileApp,
            criticality: 6,
        }];

        let plan = coordinator
            .plan_authorized_scan(profile, targets, 50)
            .expect("expected valid android scan plan");

        assert!(!plan.tasks.is_empty(), "android scan should produce tasks");
        let has_android_specialist = plan
            .tasks
            .iter()
            .any(|t| matches!(t.specialist.specialist, SpecialistKind::MobileAndroid));
        assert!(
            has_android_specialist,
            "MobileAndroid specialist should be assigned"
        );

        // Approved tools should include android-specific tools.
        let all_tools: Vec<_> = plan
            .tasks
            .iter()
            .flat_map(|t| t.approved_tools.iter())
            .collect();
        assert!(
            all_tools.iter().any(|t| t.as_str() == "mobsf"),
            "mobsf should be in approved tools"
        );
    }

    #[test]
    fn mobile_backend_scan_assigns_specialist() {
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );

        let profile = android_profile();
        let targets = vec![Target {
            id: "mobile-api".to_string(),
            target_type: TargetType::MobileBackend,
            criticality: 5,
        }];

        let plan = coordinator
            .plan_authorized_scan(profile, targets, 50)
            .expect("mobile backend scan should succeed");

        assert!(
            !plan.tasks.is_empty(),
            "mobile backend should produce tasks"
        );
    }

    #[test]
    fn blockchain_scan_assigns_specialist() {
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );

        let profile = android_profile();
        let targets = vec![Target {
            id: "defi-contract".to_string(),
            target_type: TargetType::Blockchain,
            criticality: 7,
        }];

        let plan = coordinator
            .plan_authorized_scan(profile, targets, 50)
            .expect("blockchain scan should succeed");

        let has_blockchain_specialist = plan.tasks.iter().any(|t| {
            matches!(
                t.specialist.specialist,
                SpecialistKind::BlockchainSmartContract
            )
        });
        assert!(
            has_blockchain_specialist,
            "BlockchainSmartContract specialist should be assigned"
        );
    }

    #[test]
    fn coordinator_writes_audit_record() {
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );

        let profile = android_profile();
        let targets = vec![Target {
            id: "com.example.app".to_string(),
            target_type: TargetType::MobileApp,
            criticality: 4,
        }];

        coordinator
            .plan_authorized_scan(profile, targets, 50)
            .expect("plan should succeed");

        assert_eq!(
            coordinator.audit_ledger.records().len(),
            1,
            "one audit record should be written"
        );
        assert_eq!(
            coordinator.audit_ledger.records()[0].action,
            "plan_authorized_scan"
        );
    }

    #[test]
    fn attack_path_graph_built_from_findings() {
        let findings = vec![
            Finding {
                finding_id: "f1".to_string(),
                source_tool: "mobsf".to_string(),
                title: "Insecure data storage".to_string(),
                target_id: "com.example.app".to_string(),
                severity: Severity::High,
                confidence_percent: 90,
                remediation_playbook: "encrypt-at-rest".to_string(),
                normalized_risk_score: 7.5,
            },
            Finding {
                finding_id: "f2".to_string(),
                source_tool: "frida".to_string(),
                title: "Cleartext traffic observed".to_string(),
                target_id: "com.example.app".to_string(),
                severity: Severity::Medium,
                confidence_percent: 75,
                remediation_playbook: "enforce-tls".to_string(),
                normalized_risk_score: 4.0,
            },
        ];

        let graph = AttackPathGraph::build_from_findings(&findings);

        // Attacker node + 1 unique target node.
        assert_eq!(graph.nodes.len(), 2);
        // Two edges (one per finding).
        assert_eq!(graph.edges.len(), 2);
        assert!(graph.nodes.iter().any(|n| n.node_id == "attacker"));
        assert!(graph.nodes.iter().any(|n| n.node_id == "com.example.app"));
    }

    // ── Error-path / edge-case tests ─────────────────────────────────────────

    #[test]
    fn policy_blocks_expired_time_window() {
        let engine = PolicyEngine::default();
        let profile = EngagementProfile {
            engagement_id: "eng-expired".to_string(),
            authorized_by: "secops".to_string(),
            time_window: TimeWindow {
                start_epoch_seconds: 100,
                end_epoch_seconds: 200,
            },
            allowed_techniques: vec![Technique::PassiveRecon],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Passive,
            high_impact_approved: false,
        };
        let target = Target {
            id: "t1".to_string(),
            target_type: TargetType::Api,
            criticality: 1,
        };
        // now=50 is before the window start
        let result = engine.authorize_target_scan(
            &profile,
            &target,
            &[Technique::PassiveRecon],
            TestIntensity::Passive,
            50,
        );
        assert!(matches!(
            result,
            Err(AuthorizationError::ExpiredOrInactiveWindow)
        ));

        // now=300 is after the window end
        let result2 = engine.authorize_target_scan(
            &profile,
            &target,
            &[Technique::PassiveRecon],
            TestIntensity::Passive,
            300,
        );
        assert!(matches!(
            result2,
            Err(AuthorizationError::ExpiredOrInactiveWindow)
        ));
    }

    #[test]
    fn policy_blocks_disallowed_technique() {
        let engine = PolicyEngine::default();
        let profile = EngagementProfile {
            engagement_id: "eng-limited".to_string(),
            authorized_by: "secops".to_string(),
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            allowed_techniques: vec![Technique::PassiveRecon],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Standard,
            high_impact_approved: false,
        };
        let target = Target {
            id: "t1".to_string(),
            target_type: TargetType::WebApp,
            criticality: 2,
        };
        let result = engine.authorize_target_scan(
            &profile,
            &target,
            &[Technique::Dast],
            TestIntensity::Passive,
            10,
        );
        assert!(matches!(
            result,
            Err(AuthorizationError::TechniqueNotAllowed(_))
        ));
    }

    #[test]
    fn policy_blocks_intensity_too_high() {
        let engine = PolicyEngine::default();
        let profile = EngagementProfile {
            engagement_id: "eng-passive".to_string(),
            authorized_by: "secops".to_string(),
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            allowed_techniques: vec![Technique::Dast],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Passive,
            high_impact_approved: false,
        };
        let target = Target {
            id: "t1".to_string(),
            target_type: TargetType::WebApp,
            criticality: 2,
        };
        let result = engine.authorize_target_scan(
            &profile,
            &target,
            &[Technique::Dast],
            TestIntensity::Aggressive,
            10,
        );
        assert!(matches!(result, Err(AuthorizationError::IntensityTooHigh)));
    }

    #[test]
    fn policy_blocks_high_impact_without_approval() {
        let engine = PolicyEngine::default();
        let profile = EngagementProfile {
            engagement_id: "eng-noapproval".to_string(),
            authorized_by: "secops".to_string(),
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            allowed_techniques: vec![Technique::Dast],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Standard,
            high_impact_approved: false, // <-- no approval
        };
        // criticality >= 8 triggers high-impact gate
        let target = Target {
            id: "critical-target".to_string(),
            target_type: TargetType::WebApp,
            criticality: 9,
        };
        let result = engine.authorize_target_scan(
            &profile,
            &target,
            &[Technique::Dast],
            TestIntensity::Standard,
            10,
        );
        assert!(matches!(
            result,
            Err(AuthorizationError::HighImpactRequiresApproval)
        ));
    }

    #[test]
    fn policy_allows_high_impact_with_approval() {
        let engine = PolicyEngine::default();
        let profile = EngagementProfile {
            engagement_id: "eng-approved".to_string(),
            authorized_by: "ciso".to_string(),
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            allowed_techniques: vec![Technique::Dast],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Aggressive,
            high_impact_approved: true,
        };
        let target = Target {
            id: "critical-target".to_string(),
            target_type: TargetType::WebApp,
            criticality: 9,
        };
        let result = engine.authorize_target_scan(
            &profile,
            &target,
            &[Technique::Dast],
            TestIntensity::Standard,
            10,
        );
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert!(outcome.authorized);
        assert!(outcome.ephemeral_runner_required);
        assert!(outcome.short_lived_credentials_required);
        assert!(outcome.shared_long_lived_credentials_forbidden);
    }

    #[test]
    fn coordinator_returns_empty_plan_for_empty_targets() {
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );
        let profile = android_profile();
        let plan = coordinator
            .plan_authorized_scan(profile, vec![], 50)
            .expect("empty target list should succeed");
        assert!(plan.tasks.is_empty());
        assert_eq!(plan.high_impact_tasks, 0);
        assert_eq!(plan.selected_packs.len(), 0);
    }

    #[test]
    fn coordinator_aborts_on_denied_target_in_batch() {
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );
        let profile = EngagementProfile {
            engagement_id: "eng-deny".to_string(),
            authorized_by: "secops".to_string(),
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            allowed_techniques: vec![
                Technique::PassiveRecon,
                Technique::ApiSecurity,
                Technique::ConfigurationAudit,
            ],
            deny_list_targets: vec!["forbidden".to_string()],
            max_intensity: TestIntensity::Standard,
            high_impact_approved: false,
        };
        let targets = vec![
            Target {
                id: "allowed".to_string(),
                target_type: TargetType::Api,
                criticality: 2,
            },
            Target {
                id: "forbidden".to_string(),
                target_type: TargetType::Api,
                criticality: 2,
            },
        ];
        let result = coordinator.plan_authorized_scan(profile, targets, 50);
        assert!(matches!(
            result,
            Err(AuthorizationError::TargetDenied(id)) if id == "forbidden"
        ));
        // No audit record should be written when authorization fails.
        assert_eq!(coordinator.audit_ledger.records().len(), 0);
    }

    #[test]
    fn audit_ledger_filter_by_role_and_action() {
        use governance::AuditRecord;

        let mut ledger = AuditLedger::default();
        ledger.append(AuditRecord {
            timestamp_epoch_seconds: 1,
            actor: "alice".to_string(),
            role: Role::SecurityAdmin,
            action: "plan_authorized_scan".to_string(),
            target: "eng-1".to_string(),
            details: "tasks=3".to_string(),
        });
        ledger.append(AuditRecord {
            timestamp_epoch_seconds: 2,
            actor: "bob".to_string(),
            role: Role::Auditor,
            action: "review_findings".to_string(),
            target: "eng-1".to_string(),
            details: "reviewed".to_string(),
        });

        let admin_records = ledger.filter_by_role(Role::SecurityAdmin);
        assert_eq!(admin_records.len(), 1);
        assert_eq!(admin_records[0].actor, "alice");

        let auditor_records = ledger.filter_by_role(Role::Auditor);
        assert_eq!(auditor_records.len(), 1);
        assert_eq!(auditor_records[0].actor, "bob");

        let scan_records = ledger.filter_by_action("plan_authorized_scan");
        assert_eq!(scan_records.len(), 1);

        let empty = ledger.filter_by_action("nonexistent");
        assert!(empty.is_empty());
    }

    #[test]
    fn retest_schedule_thresholds_are_correct() {
        let make_finding = |score: f32| Finding {
            finding_id: "f".to_string(),
            source_tool: "tool".to_string(),
            title: "t".to_string(),
            target_id: "target".to_string(),
            severity: Severity::High,
            confidence_percent: 80,
            remediation_playbook: "fix".to_string(),
            normalized_risk_score: score,
        };

        let day = 60u64 * 60 * 24;
        let now = 0u64;

        // score >= 8.0 → 1 day
        let s1 = propose_retest_schedule(&make_finding(8.0), now);
        assert_eq!(s1.next_retest_epoch_seconds, day);

        // score >= 5.0 but < 8.0 → 3 days
        let s2 = propose_retest_schedule(&make_finding(5.0), now);
        assert_eq!(s2.next_retest_epoch_seconds, 3 * day);

        // score < 5.0 → 7 days
        let s3 = propose_retest_schedule(&make_finding(4.9), now);
        assert_eq!(s3.next_retest_epoch_seconds, 7 * day);
    }

    #[test]
    fn risk_score_caps_at_ten() {
        // 10.0 * 1.0 * 1.15 > 10.0, should be capped.
        let score = RiskScoreCalculator::normalized_score(Severity::Critical, 100, true);
        assert_eq!(score, 10.0);
    }

    #[test]
    fn risk_score_informational_low_value() {
        let score = RiskScoreCalculator::normalized_score(Severity::Informational, 10, false);
        assert!(score > 0.0);
        assert!(score < 1.0);
    }

    #[test]
    fn compat_adapter_round_trip() {
        use compat::{IntegrationAdapter, JsonLineAdapter};
        use std::collections::BTreeMap;

        let adapter = JsonLineAdapter;

        // Build a minimal plan to export.
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );
        let profile = android_profile();
        let targets = vec![Target {
            id: "com.example.app".to_string(),
            target_type: TargetType::MobileApp,
            criticality: 4,
        }];
        let plan = coordinator
            .plan_authorized_scan(profile, targets, 50)
            .expect("plan should succeed");

        let envelope = adapter.export_execution_plan(&plan);
        assert_eq!(envelope.payload_kind, "execution_plan");
        assert_eq!(
            envelope.fields.get("engagement_id").map(String::as_str),
            Some("eng-android-001")
        );

        // Import a finding hint.
        let mut fields = BTreeMap::new();
        fields.insert("finding_id".to_string(), "hint-1".to_string());
        fields.insert("title".to_string(), "Suspicious intent".to_string());
        fields.insert("target_id".to_string(), "com.example.app".to_string());
        fields.insert("confidence_percent".to_string(), "70".to_string());

        let hint_envelope = CompatibilityEnvelope {
            protocol_version: "1".to_string(),
            producer: "external-scanner".to_string(),
            payload_kind: "finding_hint".to_string(),
            fields,
        };

        let finding = adapter.import_finding_hint(&hint_envelope);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.finding_id, "hint-1");
        assert_eq!(f.confidence_percent, 70);
        assert_eq!(f.target_id, "com.example.app");
    }

    #[test]
    fn compat_adapter_rejects_wrong_payload_kind() {
        use compat::{CompatibilityEnvelope, IntegrationAdapter, JsonLineAdapter};
        use std::collections::BTreeMap;

        let adapter = JsonLineAdapter;
        let envelope = CompatibilityEnvelope {
            protocol_version: "1".to_string(),
            producer: "test".to_string(),
            payload_kind: "execution_plan".to_string(), // wrong kind for finding import
            fields: BTreeMap::new(),
        };
        assert!(adapter.import_finding_hint(&envelope).is_none());
    }

    #[test]
    fn attack_path_graph_empty_findings() {
        let graph = AttackPathGraph::build_from_findings(&[]);
        // Only attacker node, no target nodes, no edges.
        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(graph.edges.len(), 0);
        assert_eq!(graph.nodes[0].node_id, "attacker");
    }

    #[test]
    fn toolchain_pack_registry_covers_all_use_cases() {
        let registry = ToolchainPackRegistry::default();
        for use_case in [
            UseCase::WebApp,
            UseCase::Api,
            UseCase::MobileBackend,
            UseCase::MobileApp,
            UseCase::Cloud,
            UseCase::BlockchainSmartContract,
        ] {
            assert!(
                registry.by_use_case(&use_case).is_some(),
                "Missing pack for use case: {use_case:?}"
            );
        }
    }

    #[test]
    fn capability_registry_covers_all_target_types() {
        let registry = CapabilityRegistry::default();
        for target_type in [
            TargetType::WebApp,
            TargetType::Api,
            TargetType::MobileBackend,
            TargetType::MobileApp,
            TargetType::Cloud,
            TargetType::Blockchain,
            TargetType::Container,
            TargetType::Infrastructure,
            TargetType::SourceCode,
            TargetType::DependencyManifest,
        ] {
            let caps = registry.capabilities_for_target(&target_type);
            assert!(
                !caps.is_empty(),
                "No specialist registered for target type: {target_type:?}"
            );
        }
    }
}
