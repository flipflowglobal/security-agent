//! Advisory reasoning layer above `Coordinator`/`ExecutionPlan`.
//!
//! This module changes nothing about authorization. `PolicyEngine` still
//! decides what is in scope, allowed, and approved; `Coordinator` still
//! builds the `ExecutionPlan`. `cognition` only reasons *over* an
//! already-authorized plan (and, optionally, findings carried forward from
//! past engagements) to do three things a human reviewer would otherwise
//! have to do by hand:
//!
//! - rank tasks by expected risk yield instead of engagement-file order
//!   ([`prioritize_tasks`]),
//! - propose ranked, falsifiable hypotheses about which technique is most
//!   likely to surface a finding for a given target type
//!   ([`generate_hypotheses`]), and
//! - flag coverage gaps -- a task with no locally installed tool, or a
//!   target with a history of severe findings still being tested at
//!   `Passive` intensity ([`critique_plan`]).
//!
//! Every output here is advisory text attached to the plan for a reviewer
//! to read; nothing in this module grants, restricts, or executes anything.

use crate::coordinator::ExecutionPlan;
use crate::findings::{Finding, Severity};
use crate::model::{SpecialistKind, Target, TargetType, Technique, TestIntensity};
use std::collections::HashMap;

fn severity_weight(severity: Severity) -> f32 {
    match severity {
        Severity::Critical => 10.0,
        Severity::High => 8.0,
        Severity::Medium => 5.0,
        Severity::Low => 2.5,
        Severity::Informational => 1.0,
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct TargetHistory {
    finding_count: u32,
    severity_sum: f32,
}

impl TargetHistory {
    fn average_severity(self) -> f32 {
        if self.finding_count == 0 {
            0.0
        } else {
            self.severity_sum / self.finding_count as f32
        }
    }
}

/// Cross-engagement memory of prior findings, keyed by target.
///
/// Feeding findings from past test runs back into `CognitiveMemory` lets
/// [`generate_hypotheses`], [`critique_plan`], and [`prioritize_tasks`]
/// weight future attention toward targets that have historically produced
/// more, and more severe, findings -- instead of treating every in-scope
/// target as an equally blank unknown. An empty, default memory is a valid
/// starting state: every function in this module degrades gracefully to
/// its type-based defaults when no history exists yet.
#[derive(Debug, Clone, Default)]
pub struct CognitiveMemory {
    history: HashMap<String, TargetHistory>,
}

impl CognitiveMemory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds `findings` into memory, accumulating per-target finding count
    /// and severity. Safe to call repeatedly across engagements/retests --
    /// history only ever accumulates.
    pub fn record_findings(&mut self, findings: &[Finding]) {
        for finding in findings {
            let entry = self.history.entry(finding.target_id.clone()).or_default();
            entry.finding_count += 1;
            entry.severity_sum += severity_weight(finding.severity);
        }
    }

    /// Returns `(finding_count, average_severity)` recorded for
    /// `target_id`, or `(0, 0.0)` if nothing has been recorded for it yet.
    #[must_use]
    pub fn history_for(&self, target_id: &str) -> (u32, f32) {
        self.history.get(target_id).map_or((0, 0.0), |history| {
            (history.finding_count, history.average_severity())
        })
    }
}

/// A ranked, falsifiable hypothesis about a likely vulnerability class for
/// a target: which technique is expected to surface it, why, and how
/// confident that expectation is.
#[derive(Debug, Clone)]
pub struct Hypothesis {
    pub technique: Technique,
    pub rationale: String,
    pub confidence_percent: u8,
}

/// Built-in, target-type-specific hypotheses -- this layer's domain
/// knowledge about which technique tends to surface which class of issue.
/// Confidence is a starting point; [`generate_hypotheses`] boosts it using
/// [`CognitiveMemory`] history, if any exists for the target.
fn base_hypotheses(target_type: &TargetType) -> Vec<(Technique, &'static str, u8)> {
    match target_type {
        TargetType::WebApp => vec![
            (
                Technique::Dast,
                "web apps most often leak issues through runtime request/response behavior (injection, auth, session handling)",
                55,
            ),
            (
                Technique::ConfigurationAudit,
                "misconfigured headers, TLS, and exposed admin surfaces are the most common low-effort finding class",
                45,
            ),
        ],
        TargetType::Api => vec![
            (
                Technique::ApiSecurity,
                "broken object/function level authorization is the dominant API vulnerability class",
                60,
            ),
            (
                Technique::ConfigurationAudit,
                "missing rate limiting and permissive CORS are common API misconfigurations",
                40,
            ),
        ],
        TargetType::MobileBackend => vec![
            (
                Technique::ApiSecurity,
                "mobile backends inherit API-style authorization and input-validation gaps",
                50,
            ),
            (
                Technique::AndroidStaticAnalysis,
                "backend contracts are frequently discoverable from the paired client binary",
                35,
            ),
        ],
        TargetType::MobileApp => vec![
            (
                Technique::SecretScan,
                "hardcoded keys and tokens in APKs are one of the most frequent mobile findings",
                55,
            ),
            (
                Technique::MobileRuntime,
                "runtime instrumentation reveals insecure storage and weak certificate pinning that static analysis alone misses",
                50,
            ),
            (
                Technique::AndroidStaticAnalysis,
                "decompiled bytecode commonly exposes insecure crypto and exported-component issues",
                45,
            ),
        ],
        TargetType::Cloud | TargetType::Infrastructure => vec![
            (
                Technique::CloudPosture,
                "overly permissive IAM and public storage are the most common cloud posture findings",
                55,
            ),
            (
                Technique::ConfigurationAudit,
                "default credentials and open management ports remain common on infrastructure",
                40,
            ),
        ],
        TargetType::Container => vec![(
            Technique::ContainerPosture,
            "privileged containers and unpinned base images are the leading container misconfiguration class",
            50,
        )],
        TargetType::Blockchain => vec![
            (
                Technique::Sast,
                "reentrancy and integer-overflow patterns are commonly caught by static analysis of contract source",
                55,
            ),
            (
                Technique::ThreatModeling,
                "economic/logic attack paths (oracle manipulation, flash-loan abuse) require explicit threat modeling to surface",
                45,
            ),
            (
                Technique::AttackPathAnalysis,
                "composability with other on-chain contracts often creates attack paths invisible to single-contract review",
                40,
            ),
        ],
        TargetType::SourceCode => vec![
            (
                Technique::Sast,
                "source-level static analysis is the primary detector for injection and unsafe deserialization bugs",
                55,
            ),
            (
                Technique::SecretScan,
                "committed secrets are one of the most common source-repository findings",
                40,
            ),
        ],
        TargetType::DependencyManifest => vec![(
            Technique::DependencyAudit,
            "known-vulnerable transitive dependencies are the dominant risk in manifest-only review",
            60,
        )],
    }
}

/// Generates ranked hypotheses (highest confidence first) about which
/// technique is most likely to surface a finding on `target_id`, given its
/// `target_type`. Confidence is boosted, capped at 95%, when `memory`
/// shows `target_id` already has a history of findings -- a target that
/// has produced severe findings before is judged more likely to produce
/// more.
#[must_use]
pub fn generate_hypotheses(
    target_id: &str,
    target_type: &TargetType,
    memory: &CognitiveMemory,
) -> Vec<Hypothesis> {
    let (finding_count, average_severity) = memory.history_for(target_id);
    let history_boost = if finding_count > 0 {
        (average_severity * 2.0) as u8
    } else {
        0
    };

    let mut hypotheses: Vec<Hypothesis> = base_hypotheses(target_type)
        .into_iter()
        .map(|(technique, rationale, base_confidence)| Hypothesis {
            technique,
            rationale: rationale.to_string(),
            confidence_percent: base_confidence.saturating_add(history_boost).min(95),
        })
        .collect();

    hypotheses.sort_by(|a, b| b.confidence_percent.cmp(&a.confidence_percent));
    hypotheses
}

/// Severity of an advisory insight raised by [`critique_plan`]. Purely
/// informational -- unlike `PolicyEngine` authorization outcomes, nothing
/// here gates execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InsightSeverity {
    Info,
    Advisory,
    Concern,
}

/// One advisory observation a reflective review of a plan surfaced.
#[derive(Debug, Clone)]
pub struct CognitiveInsight {
    pub target_id: String,
    pub severity: InsightSeverity,
    pub message: String,
}

/// Reflects on an already-authorized `plan` in light of `memory`,
/// surfacing coverage gaps and history mismatches a reviewer might
/// otherwise miss: tasks with no locally installed approved tool, and
/// targets with a history of severe findings that are still only being
/// tested at `Passive` intensity. Returns a single informational entry
/// when nothing is worth flagging.
#[must_use]
pub fn critique_plan(plan: &ExecutionPlan, memory: &CognitiveMemory) -> Vec<CognitiveInsight> {
    let mut insights = Vec::new();

    for task in &plan.tasks {
        if task.approved_tools.is_empty() {
            insights.push(CognitiveInsight {
                target_id: task.target_id.clone(),
                severity: InsightSeverity::Concern,
                message: format!(
                    "{:?} task for {} has no locally installed approved tool -- the plan authorizes the technique but cannot execute it on this host",
                    task.specialist.specialist, task.target_id
                ),
            });
        }

        let (finding_count, average_severity) = memory.history_for(&task.target_id);
        if finding_count > 0 && average_severity >= 7.0 && task.intensity == TestIntensity::Passive
        {
            insights.push(CognitiveInsight {
                target_id: task.target_id.clone(),
                severity: InsightSeverity::Advisory,
                message: format!(
                    "{} has a history of {finding_count} finding(s) averaging {average_severity:.1} risk score but is only authorized at Passive intensity this run -- consider requesting Standard/Aggressive approval",
                    task.target_id
                ),
            });
        }
    }

    if insights.is_empty() {
        insights.push(CognitiveInsight {
            target_id: String::new(),
            severity: InsightSeverity::Info,
            message: "no coverage gaps or history mismatches found".to_string(),
        });
    }

    insights
}

/// One task, ranked by expected risk yield.
#[derive(Debug, Clone)]
pub struct PrioritizedTask {
    pub target_id: String,
    pub specialist: SpecialistKind,
    pub expected_score: f32,
}

const fn intensity_weight(intensity: TestIntensity) -> f32 {
    match intensity {
        TestIntensity::Aggressive => 3.0,
        TestIntensity::Standard => 2.0,
        TestIntensity::Passive => 1.0,
    }
}

/// Ranks `plan`'s tasks by expected risk yield (highest first): each
/// task's intensity -- already criticality-gated by the coordinator --
/// combined with how severe `memory` shows the target's past findings to
/// be. Tasks that share an intensity are broken apart by history, so a
/// target known to produce serious findings surfaces before an
/// equal-intensity target with no history.
#[must_use]
pub fn prioritize_tasks(plan: &ExecutionPlan, memory: &CognitiveMemory) -> Vec<PrioritizedTask> {
    let mut ranked: Vec<PrioritizedTask> = plan
        .tasks
        .iter()
        .map(|task| {
            let (finding_count, average_severity) = memory.history_for(&task.target_id);
            let history_factor =
                1.0 + (average_severity / 10.0) + (finding_count.min(5) as f32 * 0.05);
            PrioritizedTask {
                target_id: task.target_id.clone(),
                specialist: task.specialist.specialist.clone(),
                expected_score: intensity_weight(task.intensity) * history_factor,
            }
        })
        .collect();

    ranked.sort_by(|a, b| {
        b.expected_score
            .partial_cmp(&a.expected_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    ranked
}

/// A full reflective assessment of an authorized plan: ranked hypotheses
/// per target, coverage/history insights, and a risk-yield-ordered task
/// ranking. Build one with [`assess`].
#[derive(Debug, Clone)]
pub struct CognitiveAssessment {
    pub hypotheses_by_target: Vec<(String, Vec<Hypothesis>)>,
    pub insights: Vec<CognitiveInsight>,
    pub prioritized_tasks: Vec<PrioritizedTask>,
}

/// Builds a full [`CognitiveAssessment`] for `plan`: hypotheses for each
/// unique target in `targets` (used to recover each target's
/// [`TargetType`], since `ExecutionPlan` itself only carries target IDs),
/// a reflective critique of `plan` against `memory`, and a risk-yield task
/// ranking.
#[must_use]
pub fn assess(
    plan: &ExecutionPlan,
    targets: &[Target],
    memory: &CognitiveMemory,
) -> CognitiveAssessment {
    let hypotheses_by_target = targets
        .iter()
        .map(|target| {
            (
                target.id.clone(),
                generate_hypotheses(&target.id, &target.target_type, memory),
            )
        })
        .collect();

    CognitiveAssessment {
        hypotheses_by_target,
        insights: critique_plan(plan, memory),
        prioritized_tasks: prioritize_tasks(plan, memory),
    }
}

impl std::fmt::Display for CognitiveAssessment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(formatter, "Cognitive Assessment")?;
        writeln!(formatter, "=====================")?;
        writeln!(formatter)?;
        writeln!(
            formatter,
            "Prioritized Tasks (highest expected yield first)"
        )?;
        writeln!(
            formatter,
            "-------------------------------------------------"
        )?;
        if self.prioritized_tasks.is_empty() {
            writeln!(formatter, "None")?;
        } else {
            for (index, task) in self.prioritized_tasks.iter().enumerate() {
                writeln!(
                    formatter,
                    "{}. target={} specialist={:?} expected_score={:.2}",
                    index + 1,
                    task.target_id,
                    task.specialist,
                    task.expected_score
                )?;
            }
        }
        writeln!(formatter)?;
        writeln!(formatter, "Hypotheses")?;
        writeln!(formatter, "----------")?;
        for (target_id, hypotheses) in &self.hypotheses_by_target {
            writeln!(formatter, "{target_id}:")?;
            for hypothesis in hypotheses {
                writeln!(
                    formatter,
                    "  [{:>2}%] {} -- {}",
                    hypothesis.confidence_percent, hypothesis.technique, hypothesis.rationale
                )?;
            }
        }
        writeln!(formatter)?;
        writeln!(formatter, "Insights")?;
        writeln!(formatter, "--------")?;
        for insight in &self.insights {
            writeln!(
                formatter,
                "[{:?}] {}{}",
                insight.severity,
                if insight.target_id.is_empty() {
                    String::new()
                } else {
                    format!("{}: ", insight.target_id)
                },
                insight.message
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::{Coordinator, ExecutionPlan, ScanTask};
    use crate::findings::{Finding, Severity};
    use crate::policy::PolicyEngine;
    use crate::registry::{CapabilityRegistry, SpecialistCapability, ToolchainPackRegistry};

    fn sample_finding(target_id: &str, severity: Severity) -> Finding {
        Finding {
            finding_id: "F-1".to_string(),
            source_tool: "semgrep".to_string(),
            title: "sample".to_string(),
            target_id: target_id.to_string(),
            severity,
            confidence_percent: 90,
            remediation_playbook: "fix it".to_string(),
            normalized_risk_score: 9.0,
        }
    }

    #[test]
    fn memory_starts_empty_and_accumulates() {
        let mut memory = CognitiveMemory::new();
        assert_eq!(memory.history_for("t1"), (0, 0.0));

        memory.record_findings(&[
            sample_finding("t1", Severity::Critical),
            sample_finding("t1", Severity::Medium),
        ]);

        let (count, average) = memory.history_for("t1");
        assert_eq!(count, 2);
        assert!((average - 7.5).abs() < f32::EPSILON);
        assert_eq!(memory.history_for("t2"), (0, 0.0));
    }

    #[test]
    fn generate_hypotheses_are_ranked_and_capped() {
        let mut memory = CognitiveMemory::new();
        for _ in 0..3 {
            memory.record_findings(&[sample_finding("t1", Severity::Critical)]);
        }

        let hypotheses = generate_hypotheses("t1", &TargetType::Api, &memory);
        assert!(!hypotheses.is_empty());
        assert!(
            hypotheses
                .windows(2)
                .all(|pair| pair[0].confidence_percent >= pair[1].confidence_percent)
        );
        assert!(hypotheses.iter().all(|h| h.confidence_percent <= 95));

        let no_history = generate_hypotheses("t2", &TargetType::Api, &CognitiveMemory::new());
        assert!(no_history[0].confidence_percent < hypotheses[0].confidence_percent);
    }

    fn build_plan() -> (ExecutionPlan, Vec<Target>) {
        let targets = vec![Target {
            id: "web-1".to_string(),
            target_type: TargetType::WebApp,
            criticality: 9,
        }];

        let profile = crate::model::EngagementProfile {
            engagement_id: "eng-1".to_string(),
            authorized_by: "tester".to_string(),
            authorized_by_role: crate::governance::Role::SecurityAdmin,
            time_window: crate::model::TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: 1_000_000,
            },
            in_scope_targets: vec!["web-1".to_string()],
            allowed_techniques: vec![
                Technique::PassiveRecon,
                Technique::ConfigurationAudit,
                Technique::Dast,
            ],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Standard,
            high_impact_approved: true,
            penetrative_testing_approved: true,
        };

        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );
        let plan = coordinator
            .plan_authorized_scan(profile, targets.clone(), 0)
            .expect("plan should authorize");
        (plan, targets)
    }

    #[test]
    fn critique_plan_flags_missing_local_tools() {
        let (plan, _targets) = build_plan();
        let memory = CognitiveMemory::new();
        let insights = critique_plan(&plan, &memory);
        assert!(!insights.is_empty());
    }

    #[test]
    fn critique_plan_flags_passive_intensity_with_severe_history() {
        let mut plan = build_plan().0;
        for task in &mut plan.tasks {
            task.intensity = TestIntensity::Passive;
        }
        let mut memory = CognitiveMemory::new();
        memory.record_findings(&[sample_finding("web-1", Severity::Critical)]);

        let insights = critique_plan(&plan, &memory);
        assert!(
            insights
                .iter()
                .any(|insight| insight.severity == InsightSeverity::Advisory
                    && insight.message.contains("Passive intensity"))
        );
    }

    #[test]
    fn prioritize_tasks_ranks_worse_history_first_at_equal_intensity() {
        let task_low = ScanTask {
            target_id: "low".to_string(),
            specialist: SpecialistCapability {
                specialist: SpecialistKind::Sast,
                target_types: vec![],
                approved_tools: vec![],
                supported_techniques: vec![],
                max_intensity: TestIntensity::Standard,
            },
            techniques: vec![],
            approved_tools: vec![],
            intensity: TestIntensity::Standard,
        };
        let mut task_high = task_low.clone();
        task_high.target_id = "high".to_string();

        let plan = ExecutionPlan {
            engagement_id: "eng".to_string(),
            workflow_stages: vec![],
            tasks: vec![task_low, task_high],
            selected_packs: vec![],
            high_impact_tasks: 0,
        };

        let mut memory = CognitiveMemory::new();
        memory.record_findings(&[sample_finding("high", Severity::Critical)]);

        let ranked = prioritize_tasks(&plan, &memory);
        assert_eq!(ranked[0].target_id, "high");
    }

    #[test]
    fn assess_builds_full_assessment_and_displays() {
        let (plan, targets) = build_plan();
        let memory = CognitiveMemory::new();
        let assessment = assess(&plan, &targets, &memory);

        assert_eq!(assessment.hypotheses_by_target.len(), targets.len());
        assert!(!assessment.prioritized_tasks.is_empty());
        assert!(!assessment.insights.is_empty());

        let rendered = assessment.to_string();
        assert!(rendered.contains("Cognitive Assessment"));
        assert!(rendered.contains("web-1"));
    }
}
