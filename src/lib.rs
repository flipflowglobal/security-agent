pub mod advanced;
pub mod anomaly;
pub mod arsenal;
pub mod audit_db;
pub mod audit_log;
pub mod belief_propagation;
pub mod build_info;
pub mod builtin_tools;
pub mod calibration;
pub mod calibration_db;
pub mod capability_graph;
pub mod cognition;
pub mod cognitive_engine;
pub mod compat;
pub mod coordinator;
pub mod corpus_gen;
pub mod correlation;
pub mod engagement_audit;
pub mod engagement_config;
pub mod engagement_context;
pub mod evidence;
pub mod execution;
pub mod expansion;
pub mod findings;
pub mod findings_db;
pub mod findings_log;
pub mod governance;
pub mod help;
pub mod ingest;
pub mod integrity;
pub mod intensity_guard;
mod json;
pub mod language_model;
pub mod lm_eval;
pub mod local_analyzers;
pub mod local_assets;
pub mod memory_store;
pub mod mission;
pub mod model;
pub mod network_policy;
pub mod nlu;
pub mod observability;
pub mod offensive;
pub mod orchestrator;
pub mod pcap;
pub mod pipeline;
pub mod policy;
pub mod reasoning_log_db;
pub mod registry;
pub mod report;
pub mod roadmap;
pub mod run_control;
pub mod runtime;
pub mod sadb;
pub mod scope;
pub mod secrets;
pub mod tagged_run;
pub mod tool_adapter;
pub mod tool_gate;
pub mod workflow;

pub use advanced::{
    AttackPathEdge, AttackPathGraph, RetestSchedule, ThreatModelNode, propose_retest_schedule,
};
pub use anomaly::{AnomalyFlag, DEFAULT_ANOMALY_THRESHOLD, scan_findings};
pub use audit_log::{AuditLogError, append_audit_records, load_audit_records};
pub use belief_propagation::{
    NodeBelief, PropagationEdge, PropagationGraph, PropagationNode,
    from_targets_and_findings as propagate_from_targets_and_findings,
};
pub use build_info::BuildInfo;
pub use builtin_tools::{
    AutopsyReport, BuiltInToolError, EmbeddedSignature, EvidenceFile, MemoryString,
    VolatilityReport, is_builtin_tool, run_autopsy, run_builtin_tool, run_volatility,
};
pub use calibration::{CalibrationRecord, CalibrationTendency, CalibrationTracker, ReliabilityBin};
pub use capability_graph::{CapabilityGraph, CapabilityNode, CapabilityStage, FunctionFamily};
pub use cognition::{
    CognitiveAssessment, CognitiveInsight, CognitiveMemory, Hypothesis, InsightSeverity,
    PrioritizedTask, assess as assess_plan_cognitively, critique_plan, generate_hypotheses,
    prioritize_tasks, recalibrate_hypotheses,
};
pub use cognitive_engine::{
    AdversaryModel, AdversaryMove, AdversaryObjective, AttentionAllocator, AttentionFocus, Belief,
    BeliefState, CognitiveDeliberation, CognitiveEngine, Metacognition, ReasoningChain, Thought,
    ThoughtKind,
};
pub use compat::{
    CompatibilityEnvelope, IntegrationAdapter, JsonLineAdapter, audit_record_to_envelope,
    envelope_to_audit_record, envelope_to_finding, finding_to_envelope,
};
pub use coordinator::{Coordinator, ExecutionPlan, ScanTask};
pub use correlation::correlate;
pub use engagement_audit::{EngagementAuditContext, audit_records_for_engagement};
pub use engagement_config::{
    EngagementConfigError, load_engagement_config, parse_engagement_config,
};
pub use engagement_context::{Endpoint, EngagementContext, Host, Service};
pub use evidence::{EvidenceError, EvidenceRecord, append_evidence, capture, load_evidence};
pub use execution::{
    DEFAULT_TIMEOUT, TaskExecutionOutcome, ToolExecutionError, ToolExecutionReport, execute_plan,
    run_external_tool, run_external_tool_with_default_timeout,
};
pub use expansion::FollowUpPlanner;
pub use findings::{Finding, RiskScoreCalculator, Severity};
pub use findings_log::{FindingsLogError, append_findings, load_findings};
pub use governance::{AuditLedger, AuditRecord, Role};
pub use help::{
    ALL_COMMANDS, CommandHelp, GUIDE_SECTIONS, render_all_help, render_help_for,
    render_reverse_shell_guide, render_section,
};
pub use integrity::{IntegrityManifest, IntegrityStatus, verify};
pub use intensity_guard::{IntensityAdvisory, advise};
pub use language_model::{LanguageModel, NeuralLanguageModel};
pub use lm_eval::{
    CoverageEval, GenerationEval, LmEvalReport, PerplexityEval, RoutingEval, evaluate,
};
pub use local_analyzers::{
    BinwalkReport, CarvedFile, EntropyRegion, FeatureGroup, FeatureReport, ForemostReport,
    HashdeepReport, HashedFile, SignatureHit, run_binwalk, run_bulk_extractor, run_foremost,
    run_hashdeep,
};
pub use local_assets::{LocalAgentAssets, LocalSkill, LocalTool};
pub use memory_store::load_memory;
pub use mission::MISSION_STATEMENT;
pub use model::{
    EngagementProfile, SpecialistKind, Target, TargetType, Technique, TestIntensity, TimeWindow,
};
pub use network_policy::NetworkMode;
pub use nlu::{Intent, Interpretation, interpret};
pub use observability::{
    CollectingSink, EngagementEvent, EventSink, NullSink, ProgressSummary, WriterSink,
};
pub use offensive::*;
pub use orchestrator::{OrchestrationSchedule, OrchestrationStep, ToolOrchestrator};
pub use pcap::{CaptureTimestamp, ProtocolCounts, WiresharkReport, run_wireshark};
pub use pipeline::{
    EngagementGuards, EngagementReport, StageOutcome, record_report_artifacts,
    run_engagement_pipeline,
};
pub use policy::{AuthorizationError, AuthorizationOutcome, PolicyEngine};
pub use registry::{
    CapabilityRegistry, ExecutionClass, SpecialistCapability, ToolDefinition, ToolchainPack,
    ToolchainPackRegistry, UseCase, cataloged_tool_names, classify_execution,
};
pub use report::{
    EngagementDeliverable, ReportInputs, SeverityRollup, render_engagement_json,
    render_engagement_markdown, render_json as render_report_json, render_markdown, render_sarif,
};
pub use roadmap::{ROADMAP_PHASES, RoadmapPhase};
pub use run_control::{
    ControlCommand, RunController, RunPhase, parse_command as parse_control_command,
};
pub use runtime::{ExecutionRuntime, RunInputs, RuntimeConfig};
pub use scope::{ScopePolicy, ScopeViolation};
pub use secrets::{Secret, SecretError, SecretStore};
pub use tagged_run::{TaggedTestRun, TestEnvironment, TestRunReport};
pub use tool_adapter::{
    AdapterRegistry, InvocationContext, OutputChannel, OutputFormat, ToolAdapter, ToolInvocation,
};
pub use tool_gate::{GateDecision, ToolGate};
pub use workflow::WorkflowStage;

#[cfg(test)]
mod tests {
    use super::*;

    fn authorized_profile() -> EngagementProfile {
        EngagementProfile {
            engagement_id: "eng-001".to_string(),
            authorized_by: "secops".to_string(),
            authorized_by_role: Role::SecurityAdmin,
            time_window: TimeWindow {
                start_epoch_seconds: 10,
                end_epoch_seconds: 1000,
            },
            in_scope_targets: vec![
                "api-staging".to_string(),
                "web-staging".to_string(),
                "prod-ledger".to_string(),
            ],
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
            penetrative_testing_approved: true,
        }
    }

    fn android_profile() -> EngagementProfile {
        EngagementProfile {
            engagement_id: "eng-android-001".to_string(),
            authorized_by: "mobile-secops".to_string(),
            authorized_by_role: Role::SecurityAdmin,
            time_window: TimeWindow {
                start_epoch_seconds: 10,
                end_epoch_seconds: 1000,
            },
            in_scope_targets: vec![
                "authorized-mobile-app".to_string(),
                "mobile-api".to_string(),
                "defi-contract".to_string(),
            ],
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
            penetrative_testing_approved: true,
        }
    }

    #[test]
    fn policy_blocks_denied_target() {
        let engine = PolicyEngine::default();
        let profile = authorized_profile();
        let target = Target {
            id: "prod-ledger".to_string(),
            target_type: TargetType::Api,
            criticality: 10,
            network_address: None,
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

        let profile = authorized_profile();
        let targets = vec![
            Target {
                id: "api-staging".to_string(),
                target_type: TargetType::Api,
                criticality: 5,
                network_address: None,
            },
            Target {
                id: "web-staging".to_string(),
                target_type: TargetType::WebApp,
                criticality: 3,
                network_address: None,
            },
        ];

        let plan = coordinator
            .plan_authorized_scan(profile, targets, 80)
            .expect("expected valid authorized plan");

        assert!(!plan.tasks.is_empty());
        assert_eq!(plan.high_impact_tasks, 0);
    }

    #[test]
    fn coordinator_requests_aggressive_intensity_when_authorized() {
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );

        let profile = EngagementProfile {
            engagement_id: "eng-aggressive".to_string(),
            authorized_by: "ciso".to_string(),
            authorized_by_role: Role::SecurityAdmin,
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            in_scope_targets: vec!["api-critical".to_string()],
            allowed_techniques: vec![
                Technique::PassiveRecon,
                Technique::ConfigurationAudit,
                Technique::ApiSecurity,
            ],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Aggressive,
            high_impact_approved: true,
            penetrative_testing_approved: true,
        };
        let targets = vec![Target {
            id: "api-critical".to_string(),
            target_type: TargetType::Api,
            criticality: 9,
            network_address: None,
        }];

        let plan = coordinator
            .plan_authorized_scan(profile, targets, 10)
            .expect("aggressive-authorized plan should succeed");

        assert_eq!(plan.high_impact_tasks, 1);
        assert!(
            plan.tasks
                .iter()
                .all(|task| task.intensity == TestIntensity::Aggressive),
            "tasks for a high-criticality target under an Aggressive-capped, \
             high-impact-approved profile should run at Aggressive intensity"
        );
    }

    #[test]
    fn coordinator_caps_at_standard_when_profile_not_aggressive() {
        // Same high-criticality target and approvals, but the profile caps at
        // Standard: intensity must not silently escalate to Aggressive.
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );

        let profile = EngagementProfile {
            engagement_id: "eng-standard-cap".to_string(),
            authorized_by: "ciso".to_string(),
            authorized_by_role: Role::SecurityAdmin,
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            in_scope_targets: vec!["api-critical".to_string()],
            allowed_techniques: vec![
                Technique::PassiveRecon,
                Technique::ConfigurationAudit,
                Technique::ApiSecurity,
            ],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Standard,
            high_impact_approved: true,
            penetrative_testing_approved: true,
        };
        let targets = vec![Target {
            id: "api-critical".to_string(),
            target_type: TargetType::Api,
            criticality: 9,
            network_address: None,
        }];

        let plan = coordinator
            .plan_authorized_scan(profile, targets, 10)
            .expect("standard-capped plan should succeed");

        assert!(
            plan.tasks
                .iter()
                .all(|task| task.intensity == TestIntensity::Standard),
            "a profile capped at Standard must never produce Aggressive tasks"
        );
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
            id: "authorized-mobile-app".to_string(),
            target_type: TargetType::MobileApp,
            criticality: 6,
            network_address: None,
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

        let local_assets = LocalAgentAssets::bundled();
        let all_tools: Vec<_> = plan
            .tasks
            .iter()
            .flat_map(|t| t.approved_tools.iter())
            .collect();
        assert!(
            all_tools
                .iter()
                .all(|name| local_assets.tool(name).is_some_and(LocalTool::is_available)),
            "execution plans must not approve unavailable tools"
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
            network_address: None,
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
            network_address: None,
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
            id: "authorized-mobile-app".to_string(),
            target_type: TargetType::MobileApp,
            criticality: 4,
            network_address: None,
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
    fn plan_authorized_scan_records_the_profile_authorizer_role() {
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );

        let mut profile = android_profile();
        profile.authorized_by_role = Role::Auditor;
        let targets = vec![Target {
            id: "authorized-mobile-app".to_string(),
            target_type: TargetType::MobileApp,
            criticality: 4,
            network_address: None,
        }];

        coordinator
            .plan_authorized_scan(profile, targets, 50)
            .expect("plan should succeed");

        assert_eq!(
            coordinator.audit_ledger.records()[0].role,
            Role::Auditor,
            "the audit record's role must come from the profile, not be hardcoded"
        );
    }

    #[test]
    fn plan_tagged_scan_records_the_test_run_operator_role() {
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );

        let profile = authorized_profile();
        let targets = vec![Target {
            id: "api-staging".to_string(),
            target_type: TargetType::Api,
            criticality: 4,
            network_address: None,
        }];
        let run = tagged_run();
        assert_eq!(run.operator_role, Role::SecurityEngineer);

        let (_, report) = coordinator
            .plan_tagged_scan(profile, targets, 80, &run)
            .expect("tagged scan should succeed");

        assert_eq!(
            coordinator.audit_ledger.records()[0].role,
            Role::SecurityEngineer,
            "the audit record's role must come from the test run's operator_role"
        );
        assert_eq!(report.operator_role, Role::SecurityEngineer);
    }

    #[test]
    fn attack_path_graph_built_from_findings() {
        let findings = vec![
            Finding {
                finding_id: "f1".to_string(),
                source_tool: "mobsf".to_string(),
                title: "Insecure data storage".to_string(),
                target_id: "authorized-mobile-app".to_string(),
                severity: Severity::High,
                confidence_percent: 90,
                remediation_playbook: "encrypt-at-rest".to_string(),
                normalized_risk_score: 7.5,
            },
            Finding {
                finding_id: "f2".to_string(),
                source_tool: "frida".to_string(),
                title: "Cleartext traffic observed".to_string(),
                target_id: "authorized-mobile-app".to_string(),
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
        assert!(
            graph
                .nodes
                .iter()
                .any(|n| n.node_id == "authorized-mobile-app")
        );
    }

    // ── Error-path / edge-case tests ─────────────────────────────────────────

    #[test]
    fn policy_blocks_expired_time_window() {
        let engine = PolicyEngine::default();
        let profile = EngagementProfile {
            engagement_id: "eng-expired".to_string(),
            authorized_by: "secops".to_string(),
            authorized_by_role: Role::SecurityAdmin,
            time_window: TimeWindow {
                start_epoch_seconds: 100,
                end_epoch_seconds: 200,
            },
            in_scope_targets: vec!["t1".to_string()],
            allowed_techniques: vec![Technique::PassiveRecon],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Passive,
            high_impact_approved: false,
            penetrative_testing_approved: false,
        };
        let target = Target {
            id: "t1".to_string(),
            target_type: TargetType::Api,
            criticality: 1,
            network_address: None,
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
            authorized_by_role: Role::SecurityAdmin,
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            in_scope_targets: vec!["t1".to_string()],
            allowed_techniques: vec![Technique::PassiveRecon],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Standard,
            high_impact_approved: false,
            penetrative_testing_approved: false,
        };
        let target = Target {
            id: "t1".to_string(),
            target_type: TargetType::WebApp,
            criticality: 2,
            network_address: None,
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
            authorized_by_role: Role::SecurityAdmin,
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            in_scope_targets: vec!["t1".to_string()],
            allowed_techniques: vec![Technique::Dast],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Passive,
            high_impact_approved: false,
            penetrative_testing_approved: true,
        };
        let target = Target {
            id: "t1".to_string(),
            target_type: TargetType::WebApp,
            criticality: 2,
            network_address: None,
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
            authorized_by_role: Role::SecurityAdmin,
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            in_scope_targets: vec!["critical-target".to_string()],
            allowed_techniques: vec![Technique::Dast],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Standard,
            high_impact_approved: false, // <-- no approval
            penetrative_testing_approved: true,
        };
        // criticality >= 8 triggers high-impact gate
        let target = Target {
            id: "critical-target".to_string(),
            target_type: TargetType::WebApp,
            criticality: 9,
            network_address: None,
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
            authorized_by_role: Role::SecurityAdmin,
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            in_scope_targets: vec!["critical-target".to_string()],
            allowed_techniques: vec![Technique::Dast],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Aggressive,
            high_impact_approved: true,
            penetrative_testing_approved: true,
        };
        let target = Target {
            id: "critical-target".to_string(),
            target_type: TargetType::WebApp,
            criticality: 9,
            network_address: None,
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
            authorized_by_role: Role::SecurityAdmin,
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            in_scope_targets: vec!["allowed".to_string(), "forbidden".to_string()],
            allowed_techniques: vec![
                Technique::PassiveRecon,
                Technique::ApiSecurity,
                Technique::ConfigurationAudit,
            ],
            deny_list_targets: vec!["forbidden".to_string()],
            max_intensity: TestIntensity::Standard,
            high_impact_approved: false,
            penetrative_testing_approved: true,
        };
        let targets = vec![
            Target {
                id: "allowed".to_string(),
                target_type: TargetType::Api,
                criticality: 2,
                network_address: None,
            },
            Target {
                id: "forbidden".to_string(),
                target_type: TargetType::Api,
                criticality: 2,
                network_address: None,
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
            test_run_id: None,
        });
        ledger.append(AuditRecord {
            timestamp_epoch_seconds: 2,
            actor: "bob".to_string(),
            role: Role::Auditor,
            action: "review_findings".to_string(),
            target: "eng-1".to_string(),
            details: "reviewed".to_string(),
            test_run_id: None,
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
        assert!((score - 10.0).abs() < f32::EPSILON);
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
            id: "authorized-mobile-app".to_string(),
            target_type: TargetType::MobileApp,
            criticality: 4,
            network_address: None,
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
        fields.insert("target_id".to_string(), "authorized-mobile-app".to_string());
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
        assert_eq!(f.target_id, "authorized-mobile-app");
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

    #[test]
    fn policy_blocks_target_outside_scope() {
        let engine = PolicyEngine::default();
        let profile = EngagementProfile {
            engagement_id: "eng-scope".to_string(),
            authorized_by: "secops".to_string(),
            authorized_by_role: Role::SecurityAdmin,
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            in_scope_targets: vec!["in-scope".to_string()],
            allowed_techniques: vec![Technique::PassiveRecon],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Passive,
            high_impact_approved: false,
            penetrative_testing_approved: false,
        };
        let target = Target {
            id: "out-of-scope".to_string(),
            target_type: TargetType::Api,
            criticality: 1,
            network_address: None,
        };
        let result = engine.authorize_target_scan(
            &profile,
            &target,
            &[Technique::PassiveRecon],
            TestIntensity::Passive,
            10,
        );
        assert!(matches!(
            result,
            Err(AuthorizationError::TargetOutOfScope(id)) if id == "out-of-scope"
        ));
    }

    #[test]
    fn policy_blocks_penetrative_technique_without_explicit_approval() {
        let engine = PolicyEngine::default();
        let profile = EngagementProfile {
            engagement_id: "eng-pen-no".to_string(),
            authorized_by: "secops".to_string(),
            authorized_by_role: Role::SecurityAdmin,
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            in_scope_targets: vec!["api-staging".to_string()],
            allowed_techniques: vec![Technique::ApiSecurity],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Standard,
            high_impact_approved: true,
            penetrative_testing_approved: false,
        };
        let target = Target {
            id: "api-staging".to_string(),
            target_type: TargetType::Api,
            criticality: 5,
            network_address: None,
        };
        let result = engine.authorize_target_scan(
            &profile,
            &target,
            &[Technique::ApiSecurity],
            TestIntensity::Standard,
            10,
        );
        assert!(matches!(
            result,
            Err(AuthorizationError::PenetrativeTechniqueRequiresApproval(
                Technique::ApiSecurity
            ))
        ));
    }

    #[test]
    fn coordinator_deduplicates_selected_toolchain_packs() {
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );
        let profile = EngagementProfile {
            engagement_id: "eng-dedupe".to_string(),
            authorized_by: "secops".to_string(),
            authorized_by_role: Role::SecurityAdmin,
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            in_scope_targets: vec!["api-1".to_string(), "api-2".to_string()],
            allowed_techniques: vec![
                Technique::PassiveRecon,
                Technique::ConfigurationAudit,
                Technique::ApiSecurity,
            ],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Standard,
            high_impact_approved: true,
            penetrative_testing_approved: true,
        };
        let targets = vec![
            Target {
                id: "api-1".to_string(),
                target_type: TargetType::Api,
                criticality: 4,
                network_address: None,
            },
            Target {
                id: "api-2".to_string(),
                target_type: TargetType::Api,
                criticality: 4,
                network_address: None,
            },
        ];

        let plan = coordinator
            .plan_authorized_scan(profile, targets, 10)
            .expect("plan should succeed");
        assert_eq!(plan.selected_packs.len(), 1);
        assert_eq!(plan.selected_packs[0].name, "api-core-pack");
    }

    #[test]
    fn capability_graph_validates_registry_and_pack_coverage() {
        let result = CapabilityGraph::validate_coverage(
            &CapabilityRegistry::default(),
            &ToolchainPackRegistry::default(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn function_first_order_is_prioritized_and_stable() {
        let order = CapabilityGraph::function_first_order();
        assert_eq!(
            order,
            [
                FunctionFamily::DiscoveryInventory,
                FunctionFamily::StaticSourceDependencyAnalysis,
                FunctionFamily::RuntimeAppApiMobileCloudContainerChecks,
                FunctionFamily::FindingNormalizationRiskScoring,
                FunctionFamily::AttackPathCorrelationRetestScheduling,
                FunctionFamily::RemediationVerificationLoop,
            ]
        );
    }

    fn tagged_run() -> TaggedTestRun {
        TaggedTestRun::new(
            "run-abc-123".to_string(),
            TestEnvironment::Staging,
            "secops-engineer".to_string(),
            Role::SecurityEngineer,
            "Quarterly API surface regression".to_string(),
            10,
        )
    }

    #[test]
    fn tagged_test_run_source_tag_contains_run_id() {
        let run = tagged_run();
        assert!(run.source_tag().contains("run-abc-123"));
        assert!(run.source_tag().starts_with("security-agent/test-run/"));
    }

    #[test]
    fn plan_tagged_scan_tags_audit_records() {
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );

        let profile = authorized_profile();
        let targets = vec![Target {
            id: "api-staging".to_string(),
            target_type: TargetType::Api,
            criticality: 4,
            network_address: None,
        }];
        let run = tagged_run();

        coordinator
            .plan_tagged_scan(profile, targets, 80, &run)
            .expect("tagged scan should succeed");

        for record in coordinator.audit_ledger.records() {
            assert_eq!(record.test_run_id.as_deref(), Some("run-abc-123"));
        }
    }

    #[test]
    fn plan_tagged_scan_returns_accurate_report() {
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );

        let profile = authorized_profile();
        let targets = vec![Target {
            id: "api-staging".to_string(),
            target_type: TargetType::Api,
            criticality: 4,
            network_address: None,
        }];
        let run = tagged_run();

        let (plan, report) = coordinator
            .plan_tagged_scan(profile, targets, 80, &run)
            .expect("tagged scan should succeed");

        assert_eq!(report.test_run_id, "run-abc-123");
        assert_eq!(report.environment, TestEnvironment::Staging);
        assert_eq!(report.operator, "secops-engineer");
        assert_eq!(report.started_at_epoch_seconds, 10);
        assert_eq!(report.completed_at_epoch_seconds, 80);
        assert_eq!(report.task_count, plan.tasks.len());
        assert!(report.audit_record_count > 0);
        assert!(report.source_tag.contains("run-abc-123"));
    }

    #[test]
    fn filter_by_test_run_id_returns_tagged_records_only() {
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );

        let profile_a = authorized_profile();
        let untagged_targets = vec![Target {
            id: "web-staging".to_string(),
            target_type: TargetType::WebApp,
            criticality: 3,
            network_address: None,
        }];
        coordinator
            .plan_authorized_scan(profile_a, untagged_targets, 50)
            .expect("untagged scan should succeed");

        let profile_b = EngagementProfile {
            engagement_id: "eng-tagged".to_string(),
            authorized_by: "secops".to_string(),
            authorized_by_role: Role::SecurityAdmin,
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: u64::MAX,
            },
            in_scope_targets: vec!["api-staging".to_string()],
            allowed_techniques: vec![
                Technique::PassiveRecon,
                Technique::ConfigurationAudit,
                Technique::ApiSecurity,
            ],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Standard,
            high_impact_approved: false,
            penetrative_testing_approved: true,
        };
        let tagged_targets = vec![Target {
            id: "api-staging".to_string(),
            target_type: TargetType::Api,
            criticality: 3,
            network_address: None,
        }];
        let run = tagged_run();
        coordinator
            .plan_tagged_scan(profile_b, tagged_targets, 80, &run)
            .expect("tagged scan should succeed");

        let tagged = coordinator
            .audit_ledger
            .filter_by_test_run_id("run-abc-123");
        assert_eq!(tagged.len(), 1);
        assert_eq!(tagged[0].action, "plan_tagged_scan");

        let untagged_record = coordinator
            .audit_ledger
            .records()
            .iter()
            .find(|r| r.action == "plan_authorized_scan")
            .expect("untagged record must exist");
        assert!(untagged_record.test_run_id.is_none());
    }

    #[test]
    fn plan_tagged_scan_rejects_denied_target() {
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );
        let profile = authorized_profile();
        let targets = vec![Target {
            id: "prod-ledger".to_string(),
            target_type: TargetType::Api,
            criticality: 10,
            network_address: None,
        }];
        let run = tagged_run();
        let result = coordinator.plan_tagged_scan(profile, targets, 80, &run);
        assert!(matches!(
            result,
            Err(AuthorizationError::TargetDenied(id)) if id == "prod-ledger"
        ));
        assert_eq!(coordinator.audit_ledger.records().len(), 0);
    }
}
