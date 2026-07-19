use crate::governance::{AuditLedger, AuditRecord, Role};
use crate::model::{EngagementProfile, Target, TargetType, Technique, TestIntensity};
use crate::policy::{AuthorizationError, PolicyEngine};
use crate::registry::{
    CapabilityRegistry, SpecialistCapability, ToolchainPack, ToolchainPackRegistry, UseCase,
};
use crate::tagged_run::{TaggedTestRun, TestRunReport};
use crate::workflow::WorkflowStage;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct ScanTask {
    pub target_id: String,
    pub specialist: SpecialistCapability,
    pub techniques: Vec<Technique>,
    pub approved_tools: Vec<String>,
    pub intensity: TestIntensity,
}

#[derive(Debug, Clone)]
pub struct ExecutionPlan {
    pub engagement_id: String,
    pub workflow_stages: Vec<WorkflowStage>,
    pub tasks: Vec<ScanTask>,
    pub selected_packs: Vec<ToolchainPack>,
    pub high_impact_tasks: usize,
}

#[derive(Debug, Clone)]
pub struct Coordinator {
    capability_registry: CapabilityRegistry,
    pack_registry: ToolchainPackRegistry,
    policy_engine: PolicyEngine,
    pub audit_ledger: AuditLedger,
}

impl Coordinator {
    pub fn new(
        capability_registry: CapabilityRegistry,
        pack_registry: ToolchainPackRegistry,
        policy_engine: PolicyEngine,
    ) -> Self {
        Self {
            capability_registry,
            pack_registry,
            policy_engine,
            audit_ledger: AuditLedger::default(),
        }
    }

    pub fn plan_authorized_scan(
        &mut self,
        profile: EngagementProfile,
        targets: Vec<Target>,
        now_epoch_seconds: u64,
    ) -> Result<ExecutionPlan, AuthorizationError> {
        let mut tasks = Vec::new();
        let mut selected_packs = Vec::new();
        let mut selected_use_cases = HashSet::new();
        let mut high_impact_count = 0;

        for target in targets {
            let intensity = if target.criticality >= 8 {
                TestIntensity::Standard
            } else {
                TestIntensity::Passive
            };

            let default_techniques = default_techniques_for_target(&target.target_type);
            self.policy_engine.authorize_target_scan(
                &profile,
                &target,
                &default_techniques,
                intensity,
                now_epoch_seconds,
            )?;

            if target.criticality >= 8 && intensity >= TestIntensity::Standard {
                high_impact_count += 1;
            }

            for specialist in self
                .capability_registry
                .capabilities_for_target(&target.target_type)
            {
                let techniques = specialist
                    .supported_techniques
                    .iter()
                    .filter(|technique| default_techniques.iter().any(|t| t == *technique))
                    .cloned()
                    .collect::<Vec<_>>();

                if techniques.is_empty() {
                    continue;
                }

                tasks.push(ScanTask {
                    target_id: target.id.clone(),
                    specialist,
                    techniques,
                    approved_tools: vec![],
                    intensity,
                });
            }

            let use_case = use_case_for_target(&target.target_type);
            if selected_use_cases.insert(use_case) {
                if let Some(pack) = self.pack_registry.by_use_case(&use_case) {
                    selected_packs.push(pack.clone());
                }
            }
        }

        for task in &mut tasks {
            task.approved_tools = task.specialist.approved_tools.clone();
        }

        let plan = ExecutionPlan {
            engagement_id: profile.engagement_id.clone(),
            workflow_stages: WorkflowStage::ordered().to_vec(),
            tasks,
            selected_packs,
            high_impact_tasks: high_impact_count,
        };

        self.audit_ledger.append(AuditRecord {
            timestamp_epoch_seconds: now_epoch_seconds,
            actor: profile.authorized_by.clone(),
            role: Role::SecurityAdmin,
            action: "plan_authorized_scan".to_string(),
            target: profile.engagement_id.clone(),
            details: format!(
                "tasks={} high_impact={}",
                plan.tasks.len(),
                plan.high_impact_tasks
            ),
            test_run_id: None,
        });

        Ok(plan)
    }

    pub fn plan_tagged_scan(
        &mut self,
        profile: EngagementProfile,
        targets: Vec<Target>,
        now_epoch_seconds: u64,
        test_run: &TaggedTestRun,
    ) -> Result<(ExecutionPlan, TestRunReport), AuthorizationError> {
        let ledger_len_before = self.audit_ledger.records().len();

        let mut tasks = Vec::new();
        let mut selected_packs = Vec::new();
        let mut selected_use_cases = HashSet::new();
        let mut high_impact_count = 0;

        for target in targets {
            let intensity = if target.criticality >= 8 {
                TestIntensity::Standard
            } else {
                TestIntensity::Passive
            };

            let default_techniques = default_techniques_for_target(&target.target_type);
            self.policy_engine.authorize_target_scan(
                &profile,
                &target,
                &default_techniques,
                intensity,
                now_epoch_seconds,
            )?;

            if target.criticality >= 8 && intensity >= TestIntensity::Standard {
                high_impact_count += 1;
            }

            for specialist in self
                .capability_registry
                .capabilities_for_target(&target.target_type)
            {
                let techniques = specialist
                    .supported_techniques
                    .iter()
                    .filter(|technique| default_techniques.iter().any(|t| t == *technique))
                    .cloned()
                    .collect::<Vec<_>>();

                if techniques.is_empty() {
                    continue;
                }

                tasks.push(ScanTask {
                    target_id: target.id.clone(),
                    specialist,
                    techniques,
                    approved_tools: vec![],
                    intensity,
                });
            }

            let use_case = use_case_for_target(&target.target_type);
            if selected_use_cases.insert(use_case) {
                if let Some(pack) = self.pack_registry.by_use_case(&use_case) {
                    selected_packs.push(pack.clone());
                }
            }
        }

        for task in &mut tasks {
            task.approved_tools = task.specialist.approved_tools.clone();
        }

        let plan = ExecutionPlan {
            engagement_id: profile.engagement_id.clone(),
            workflow_stages: WorkflowStage::ordered().to_vec(),
            tasks,
            selected_packs,
            high_impact_tasks: high_impact_count,
        };

        self.audit_ledger.append(AuditRecord {
            timestamp_epoch_seconds: now_epoch_seconds,
            actor: test_run.operator.clone(),
            role: Role::SecurityAdmin,
            action: "plan_tagged_scan".to_string(),
            target: profile.engagement_id.clone(),
            details: format!(
                "tasks={} high_impact={} source={}",
                plan.tasks.len(),
                plan.high_impact_tasks,
                test_run.source_tag(),
            ),
            test_run_id: Some(test_run.test_run_id.clone()),
        });

        let audit_records_written = self.audit_ledger.records().len() - ledger_len_before;

        let report = TestRunReport {
            test_run_id: test_run.test_run_id.clone(),
            environment: test_run.environment,
            operator: test_run.operator.clone(),
            purpose: test_run.purpose.clone(),
            source_tag: test_run.source_tag(),
            started_at_epoch_seconds: test_run.started_at_epoch_seconds,
            completed_at_epoch_seconds: now_epoch_seconds,
            task_count: plan.tasks.len(),
            audit_record_count: audit_records_written,
        };

        Ok((plan, report))
    }
}

fn use_case_for_target(target_type: &TargetType) -> UseCase {
    match target_type {
        TargetType::WebApp => UseCase::WebApp,
        TargetType::Api => UseCase::Api,
        TargetType::MobileBackend => UseCase::MobileBackend,
        TargetType::MobileApp => UseCase::MobileApp,
        TargetType::Cloud | TargetType::Container | TargetType::Infrastructure => UseCase::Cloud,
        TargetType::Blockchain => UseCase::BlockchainSmartContract,
        TargetType::SourceCode | TargetType::DependencyManifest => UseCase::WebApp,
    }
}

fn default_techniques_for_target(target_type: &TargetType) -> Vec<Technique> {
    match target_type {
        TargetType::WebApp => vec![
            Technique::PassiveRecon,
            Technique::ConfigurationAudit,
            Technique::Dast,
        ],
        TargetType::Api => vec![
            Technique::PassiveRecon,
            Technique::ConfigurationAudit,
            Technique::ApiSecurity,
        ],
        TargetType::MobileBackend => vec![
            Technique::ConfigurationAudit,
            Technique::ApiSecurity,
            Technique::AndroidStaticAnalysis,
        ],
        TargetType::MobileApp => vec![
            Technique::AndroidStaticAnalysis,
            Technique::MobileRuntime,
            Technique::SecretScan,
            Technique::DependencyAudit,
        ],
        TargetType::Cloud => vec![Technique::ConfigurationAudit, Technique::CloudPosture],
        TargetType::Blockchain => vec![
            Technique::Sast,
            Technique::ThreatModeling,
            Technique::AttackPathAnalysis,
        ],
        TargetType::Container => vec![Technique::ConfigurationAudit, Technique::ContainerPosture],
        TargetType::Infrastructure => vec![Technique::ConfigurationAudit, Technique::CloudPosture],
        TargetType::SourceCode => vec![Technique::Sast, Technique::SecretScan],
        TargetType::DependencyManifest => vec![Technique::DependencyAudit],
    }
}
