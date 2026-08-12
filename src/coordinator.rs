use crate::governance::{AuditLedger, AuditRecord};
use crate::local_assets::LocalAgentAssets;
use crate::model::{EngagementProfile, Target, TargetType, Technique, TestIntensity};
use crate::policy::{AuthorizationError, PolicyEngine};
use crate::registry::{
    CapabilityRegistry, SpecialistCapability, ToolchainPack, ToolchainPackRegistry, UseCase,
};
use crate::tagged_run::{TaggedTestRun, TestRunReport};
use crate::workflow::WorkflowStage;
use std::collections::HashSet;
use std::fmt;

#[derive(Debug, Clone)]
pub struct ScanTask {
    pub target_id: String,
    pub specialist: SpecialistCapability,
    pub techniques: Vec<Technique>,
    pub approved_tools: Vec<String>,
    pub intensity: TestIntensity,
    /// Carried through from `Target.network_address`, if any. Used by
    /// `crate::execution::execute_plan` to bind network-tool execution to
    /// the authorized address (see `Target::network_address`).
    pub network_address: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExecutionPlan {
    pub engagement_id: String,
    pub workflow_stages: Vec<WorkflowStage>,
    pub tasks: Vec<ScanTask>,
    pub selected_packs: Vec<ToolchainPack>,
    pub high_impact_tasks: usize,
}

impl fmt::Display for ExecutionPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Execution Plan")?;
        writeln!(formatter, "===============")?;
        writeln!(formatter, "Engagement       : {}", self.engagement_id)?;
        writeln!(
            formatter,
            "Workflow stages  : {}",
            self.workflow_stages
                .iter()
                .map(|stage| format!("{stage:?}"))
                .collect::<Vec<_>>()
                .join(" -> ")
        )?;
        writeln!(formatter, "High-impact tasks: {}", self.high_impact_tasks)?;
        writeln!(formatter)?;
        writeln!(formatter, "Selected Toolchain Packs")?;
        writeln!(formatter, "------------------------")?;
        if self.selected_packs.is_empty() {
            writeln!(formatter, "None")?;
        } else {
            for pack in &self.selected_packs {
                if pack.deprecated {
                    let replacement = pack.replacement_pack.as_deref().unwrap_or("no replacement");
                    writeln!(formatter, "- {} (DEPRECATED -> {replacement})", pack.name)?;
                } else {
                    writeln!(formatter, "- {}", pack.name)?;
                }
            }
        }
        writeln!(formatter)?;
        writeln!(formatter, "Tasks")?;
        writeln!(formatter, "-----")?;
        if self.tasks.is_empty() {
            writeln!(formatter, "None")?;
        } else {
            for (index, task) in self.tasks.iter().enumerate() {
                writeln!(
                    formatter,
                    "{}. target={} specialist={:?} intensity={}",
                    index + 1,
                    task.target_id,
                    task.specialist.specialist,
                    task.intensity
                )?;
                writeln!(
                    formatter,
                    "   techniques     : {}",
                    task.techniques
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )?;
                let approved_tools = if task.approved_tools.is_empty() {
                    "none locally installed".to_string()
                } else {
                    task.approved_tools.join(", ")
                };
                writeln!(formatter, "   approved_tools : {approved_tools}")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Coordinator {
    capability_registry: CapabilityRegistry,
    pack_registry: ToolchainPackRegistry,
    policy_engine: PolicyEngine,
    pub audit_ledger: AuditLedger,
}

impl Coordinator {
    #[must_use]
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

    /// Authorizes and plans a scan across `targets` under `profile`, writing
    /// one audit record for the attempt.
    ///
    /// # Errors
    ///
    /// Returns the first [`AuthorizationError`] encountered while
    /// authorizing any target (expired window, out-of-scope/denied target,
    /// disallowed technique, excessive intensity, or missing high-impact
    /// approval). No audit record is written when authorization fails.
    // `profile` is taken by value so a caller cannot accidentally reuse the
    // same engagement snapshot across multiple planning calls after it was
    // meant to be consumed by this one.
    #[allow(clippy::needless_pass_by_value)]
    pub fn plan_authorized_scan(
        &mut self,
        profile: EngagementProfile,
        targets: Vec<Target>,
        now_epoch_seconds: u64,
    ) -> Result<ExecutionPlan, AuthorizationError> {
        let plan = self.build_authorized_plan(&profile, targets, now_epoch_seconds)?;

        self.audit_ledger.append(AuditRecord {
            timestamp_epoch_seconds: now_epoch_seconds,
            actor: profile.authorized_by.clone(),
            role: profile.authorized_by_role,
            action: "plan_authorized_scan".to_string(),
            target: profile.engagement_id,
            details: format!(
                "tasks={} high_impact={}",
                plan.tasks.len(),
                plan.high_impact_tasks
            ),
            test_run_id: None,
        });

        Ok(plan)
    }

    /// Same as [`Self::plan_authorized_scan`], but tags the resulting audit
    /// records with `test_run` and returns a [`TestRunReport`] alongside the
    /// plan.
    ///
    /// # Errors
    ///
    /// Returns the same [`AuthorizationError`] variants as
    /// [`Self::plan_authorized_scan`]. No audit record is written when
    /// authorization fails.
    #[allow(clippy::needless_pass_by_value)]
    pub fn plan_tagged_scan(
        &mut self,
        profile: EngagementProfile,
        targets: Vec<Target>,
        now_epoch_seconds: u64,
        test_run: &TaggedTestRun,
    ) -> Result<(ExecutionPlan, TestRunReport), AuthorizationError> {
        let ledger_len_before = self.audit_ledger.records().len();

        let plan = self.build_authorized_plan(&profile, targets, now_epoch_seconds)?;

        self.audit_ledger.append(AuditRecord {
            timestamp_epoch_seconds: now_epoch_seconds,
            actor: test_run.operator.clone(),
            role: test_run.operator_role,
            action: "plan_tagged_scan".to_string(),
            target: profile.engagement_id,
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
            operator_role: test_run.operator_role,
            purpose: test_run.purpose.clone(),
            source_tag: test_run.source_tag(),
            started_at_epoch_seconds: test_run.started_at_epoch_seconds,
            completed_at_epoch_seconds: now_epoch_seconds,
            task_count: plan.tasks.len(),
            audit_record_count: audit_records_written,
        };

        Ok((plan, report))
    }

    /// Shared task-building logic used by both `plan_authorized_scan` and
    /// `plan_tagged_scan`: authorizes every target, assigns specialists and
    /// techniques, resolves locally installed tools, and selects toolchain
    /// packs. Callers are responsible for appending their own audit record.
    fn build_authorized_plan(
        &self,
        profile: &EngagementProfile,
        targets: Vec<Target>,
        now_epoch_seconds: u64,
    ) -> Result<ExecutionPlan, AuthorizationError> {
        let mut tasks = Vec::new();
        let mut selected_packs = Vec::new();
        let mut selected_use_cases = HashSet::new();
        let mut high_impact_count = 0;

        for target in targets {
            let intensity = requested_intensity_for_target(profile, &target);

            let default_techniques = default_techniques_for_target(&target.target_type);
            self.policy_engine.authorize_target_scan(
                profile,
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
                    network_address: target.network_address.clone(),
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
            task.approved_tools = locally_installed_tools(&task.specialist.approved_tools);
        }

        Ok(ExecutionPlan {
            engagement_id: profile.engagement_id.clone(),
            workflow_stages: WorkflowStage::ordered().to_vec(),
            tasks,
            selected_packs,
            high_impact_tasks: high_impact_count,
        })
    }
}

/// Derives the intensity to request for a target: `Aggressive` when the
/// target is high-criticality (>= 8) and the engagement profile both caps
/// at `Aggressive` and has explicit high-impact approval; `Standard` for
/// other high-criticality targets; `Passive` otherwise.
fn requested_intensity_for_target(profile: &EngagementProfile, target: &Target) -> TestIntensity {
    if target.criticality >= 8 {
        if profile.max_intensity == TestIntensity::Aggressive && profile.high_impact_approved {
            TestIntensity::Aggressive
        } else {
            TestIntensity::Standard
        }
    } else {
        TestIntensity::Passive
    }
}

fn locally_installed_tools(tool_names: &[String]) -> Vec<String> {
    let assets = LocalAgentAssets::bundled();
    tool_names
        .iter()
        .filter(|name| {
            assets
                .tool(name)
                .is_some_and(super::local_assets::LocalTool::is_available)
        })
        .cloned()
        .collect()
}

const fn use_case_for_target(target_type: &TargetType) -> UseCase {
    match target_type {
        TargetType::WebApp | TargetType::SourceCode | TargetType::DependencyManifest => {
            UseCase::WebApp
        }
        TargetType::Api => UseCase::Api,
        TargetType::MobileBackend => UseCase::MobileBackend,
        TargetType::MobileApp => UseCase::MobileApp,
        TargetType::Cloud | TargetType::Container | TargetType::Infrastructure => UseCase::Cloud,
        TargetType::Blockchain => UseCase::BlockchainSmartContract,
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
        TargetType::Cloud | TargetType::Infrastructure => {
            vec![Technique::ConfigurationAudit, Technique::CloudPosture]
        }
        TargetType::Blockchain => vec![
            Technique::Sast,
            Technique::ThreatModeling,
            Technique::AttackPathAnalysis,
        ],
        TargetType::Container => vec![Technique::ConfigurationAudit, Technique::ContainerPosture],
        TargetType::SourceCode => vec![Technique::Sast, Technique::SecretScan],
        TargetType::DependencyManifest => vec![Technique::DependencyAudit],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ToolchainPack;

    #[test]
    fn plan_display_marks_deprecated_packs_with_their_replacement() {
        let plan = ExecutionPlan {
            engagement_id: "eng-deprecation".to_string(),
            workflow_stages: WorkflowStage::ordered().to_vec(),
            tasks: vec![],
            selected_packs: vec![ToolchainPack {
                name: "mobile-backend-pack".to_string(),
                use_case: UseCase::MobileBackend,
                tools: vec![],
                deprecated: true,
                replacement_pack: Some("api-core-pack".to_string()),
            }],
            high_impact_tasks: 0,
        };

        let rendered = plan.to_string();
        assert!(
            rendered.contains("mobile-backend-pack (DEPRECATED -> api-core-pack)"),
            "deprecated packs should render with their replacement:\n{rendered}"
        );
    }

    #[test]
    fn plan_display_leaves_active_packs_unmarked() {
        let plan = ExecutionPlan {
            engagement_id: "eng-active".to_string(),
            workflow_stages: WorkflowStage::ordered().to_vec(),
            tasks: vec![],
            selected_packs: vec![ToolchainPack {
                name: "api-core-pack".to_string(),
                use_case: UseCase::Api,
                tools: vec![],
                deprecated: false,
                replacement_pack: None,
            }],
            high_impact_tasks: 0,
        };

        let rendered = plan.to_string();
        assert!(rendered.contains("- api-core-pack\n"));
        assert!(!rendered.contains("DEPRECATED"));
    }
}
