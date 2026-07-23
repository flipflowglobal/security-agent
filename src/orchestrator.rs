//! Turns a planned scan into an ordered, deduplicated execution schedule.
//!
//! [`crate::coordinator`] produces an [`ExecutionPlan`]: a set of
//! per-target [`ScanTask`]s, each carrying the tools a specialist approved
//! for it. That structure answers *what is authorized*, but it says nothing
//! about *what order to run in* — and its tasks can name the same tool for
//! the same target more than once (a target matched by two specialists, an
//! overlapping toolchain pack, ...). Feeding that directly to
//! [`crate::execution::execute_plan`] would run tools in arbitrary,
//! task-declaration order and repeat redundant invocations.
//!
//! The orchestrator sits between planning and execution and imposes a
//! deterministic schedule with two guarantees:
//!
//! 1. **Least-invasive first.** Steps are ordered by execution class —
//!    [`ExecutionClass::StaticLocalAnalysis`] before
//!    [`ExecutionClass::ActiveNetwork`] before
//!    [`ExecutionClass::ActiveExploitation`]. Local, read-only analysis
//!    runs (and can surface a blocker) before any traffic reaches a live
//!    target, and exploitation is always last. This mirrors the crate's
//!    offline-by-default safety posture at the level of *ordering* rather
//!    than *permission*: the network gate in [`crate::execution`] still
//!    decides whether an active step may run at all.
//! 2. **No redundant work.** A `(target, tool)` pair is scheduled once,
//!    keeping the earliest occurrence so a tool never runs twice against
//!    the same target within one plan.
//!
//! Ordering is *stable* within an execution class: steps that tie on class
//! keep the order in which the plan declared them, so a schedule is fully
//! deterministic for a given plan.
//!
//! A tool's class is derived by name via [`crate::registry::classify_execution`]
//! — the same function the catalog uses to stamp every
//! [`crate::registry::ToolDefinition`] — so the schedule can be built from a
//! plan alone, without resolving binaries on `PATH`. Whether a scheduled
//! tool is actually installed (and thus produces an outcome) remains an
//! execution-time concern; the orchestrator plans intent, not availability.

use crate::coordinator::ExecutionPlan;
use crate::model::TestIntensity;
use crate::registry::{ExecutionClass, classify_execution};
use std::collections::HashSet;
use std::fmt;

/// One scheduled tool invocation: a single tool run against a single
/// target, positioned in the overall order by [`OrchestrationStep::sequence`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrchestrationStep {
    /// 1-based position of this step in the schedule.
    pub sequence: usize,
    /// The authorized target this tool runs against.
    pub target_id: String,
    /// The tool to invoke (a cataloged tool name).
    pub tool: String,
    /// The tool's execution surface, which determined its ordering.
    pub execution_class: ExecutionClass,
    /// The intensity of the task this step was drawn from.
    pub intensity: TestIntensity,
    /// The live address to bind an active tool to, carried through from the
    /// task (see [`crate::coordinator::ScanTask::network_address`]). `None`
    /// for static-local work.
    pub network_address: Option<String>,
}

/// An ordered, deduplicated sequence of [`OrchestrationStep`]s derived from
/// an [`ExecutionPlan`]. This is what execution consumes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OrchestrationSchedule {
    pub steps: Vec<OrchestrationStep>,
}

impl OrchestrationSchedule {
    /// Number of scheduled steps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Whether the schedule has no steps (e.g. a plan whose tasks approved
    /// no locally relevant tools).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Iterates the steps in scheduled order.
    pub fn iter(&self) -> std::slice::Iter<'_, OrchestrationStep> {
        self.steps.iter()
    }

    /// Counts scheduled steps in a given execution class — handy for a
    /// pre-execution summary ("N active steps require online mode").
    #[must_use]
    pub fn count_in_class(&self, class: ExecutionClass) -> usize {
        self.steps
            .iter()
            .filter(|step| step.execution_class == class)
            .count()
    }
}

impl<'a> IntoIterator for &'a OrchestrationSchedule {
    type Item = &'a OrchestrationStep;
    type IntoIter = std::slice::Iter<'a, OrchestrationStep>;

    fn into_iter(self) -> Self::IntoIter {
        self.steps.iter()
    }
}

impl fmt::Display for OrchestrationSchedule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Execution Schedule")?;
        writeln!(formatter, "------------------")?;
        if self.steps.is_empty() {
            writeln!(formatter, "None")?;
            return Ok(());
        }
        for step in &self.steps {
            let address = step
                .network_address
                .as_deref()
                .map(|address| format!(" -> {address}"))
                .unwrap_or_default();
            writeln!(
                formatter,
                "{}. [{:?}] target={} tool={}{} intensity={}",
                step.sequence,
                step.execution_class,
                step.target_id,
                step.tool,
                address,
                step.intensity
            )?;
        }
        Ok(())
    }
}

/// Builds an [`OrchestrationSchedule`] from an [`ExecutionPlan`].
///
/// The default orchestrator orders least-invasive first and deduplicates
/// `(target, tool)` pairs; see the [module docs](crate::orchestrator).
#[derive(Debug, Clone, Copy, Default)]
pub struct ToolOrchestrator;

impl ToolOrchestrator {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Computes the ordered, deduplicated schedule for `plan`.
    ///
    /// Every `(target, tool)` pair named by the plan's tasks is scheduled
    /// exactly once. Steps are sorted by execution class (static → active
    /// network → active exploitation), preserving each pair's first
    /// appearance in the plan as the tie-breaker so the result is
    /// deterministic.
    #[must_use]
    pub fn schedule(&self, plan: &ExecutionPlan) -> OrchestrationSchedule {
        // Collect one step per unique (target, tool), in plan order. The
        // `sequence` is a placeholder until the stable sort below fixes the
        // final order.
        let mut seen: HashSet<(&str, &str)> = HashSet::new();
        let mut steps: Vec<OrchestrationStep> = Vec::new();

        for task in &plan.tasks {
            for tool in &task.approved_tools {
                if !seen.insert((task.target_id.as_str(), tool.as_str())) {
                    continue;
                }
                let class = classify_execution(tool);
                // A static-local tool operates on files on disk, never an
                // address, so it never binds to one — matching the argument
                // injection in `crate::execution::execute_plan`. Recording
                // `None` here keeps the schedule's address field meaning
                // "what this step actually connects to".
                let network_address = match class {
                    ExecutionClass::StaticLocalAnalysis => None,
                    _ => task.network_address.clone(),
                };
                steps.push(OrchestrationStep {
                    sequence: 0,
                    target_id: task.target_id.clone(),
                    tool: tool.clone(),
                    execution_class: class,
                    intensity: task.intensity,
                    network_address,
                });
            }
        }

        // Stable sort by invasiveness: equal classes keep their plan order,
        // so the schedule is deterministic without an explicit tie-breaker.
        steps.sort_by_key(|step| invasiveness_rank(step.execution_class));
        for (index, step) in steps.iter_mut().enumerate() {
            step.sequence = index + 1;
        }

        OrchestrationSchedule { steps }
    }
}

/// Orders execution classes least-invasive first. Kept explicit rather than
/// relying on the enum's declaration order so the safety-relevant ordering
/// is a deliberate, self-documenting contract of this module.
const fn invasiveness_rank(class: ExecutionClass) -> u8 {
    match class {
        ExecutionClass::StaticLocalAnalysis => 0,
        ExecutionClass::ActiveNetwork => 1,
        ExecutionClass::ActiveExploitation => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::ScanTask;
    use crate::model::SpecialistKind;
    use crate::registry::SpecialistCapability;

    fn task(
        target: &str,
        tools: &[&str],
        intensity: TestIntensity,
        address: Option<&str>,
    ) -> ScanTask {
        ScanTask {
            target_id: target.to_string(),
            specialist: SpecialistCapability {
                specialist: SpecialistKind::Sast,
                target_types: Vec::new(),
                approved_tools: Vec::new(),
                supported_techniques: Vec::new(),
                max_intensity: TestIntensity::Passive,
            },
            techniques: Vec::new(),
            approved_tools: tools.iter().map(ToString::to_string).collect(),
            intensity,
            network_address: address.map(str::to_string),
        }
    }

    fn plan(tasks: Vec<ScanTask>) -> ExecutionPlan {
        ExecutionPlan {
            engagement_id: "eng-test".to_string(),
            workflow_stages: Vec::new(),
            tasks,
            selected_packs: Vec::new(),
            high_impact_tasks: 0,
        }
    }

    #[test]
    fn orders_least_invasive_first_across_tasks() {
        // Declared exploitation-first, network-second, static-last; the
        // schedule must invert that into static -> network -> exploitation.
        let schedule = ToolOrchestrator::new().schedule(&plan(vec![
            task(
                "t1",
                &["msfconsole"],
                TestIntensity::Aggressive,
                Some("10.0.0.1"),
            ),
            task("t1", &["nmap"], TestIntensity::Standard, Some("10.0.0.1")),
            task("t1", &["semgrep"], TestIntensity::Passive, None),
        ]));

        let order: Vec<&str> = schedule.iter().map(|step| step.tool.as_str()).collect();
        assert_eq!(order, vec!["semgrep", "nmap", "msfconsole"]);
        assert_eq!(
            schedule.steps[0].execution_class,
            ExecutionClass::StaticLocalAnalysis
        );
        assert_eq!(
            schedule.steps[1].execution_class,
            ExecutionClass::ActiveNetwork
        );
        assert_eq!(
            schedule.steps[2].execution_class,
            ExecutionClass::ActiveExploitation
        );
        // Sequence numbers are 1-based and dense.
        assert_eq!(
            schedule.iter().map(|s| s.sequence).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn deduplicates_same_target_tool_pair_keeping_first() {
        // Same (target, tool) named by two tasks at different intensities;
        // only the first survives, carrying that task's intensity/address.
        let schedule = ToolOrchestrator::new().schedule(&plan(vec![
            task("t1", &["nmap"], TestIntensity::Standard, Some("10.0.0.1")),
            task("t1", &["nmap"], TestIntensity::Aggressive, Some("10.0.0.9")),
        ]));

        assert_eq!(schedule.len(), 1);
        assert_eq!(schedule.steps[0].intensity, TestIntensity::Standard);
        assert_eq!(
            schedule.steps[0].network_address.as_deref(),
            Some("10.0.0.1")
        );
    }

    #[test]
    fn same_tool_on_distinct_targets_is_not_deduplicated() {
        let schedule = ToolOrchestrator::new().schedule(&plan(vec![
            task("t1", &["nmap"], TestIntensity::Standard, None),
            task("t2", &["nmap"], TestIntensity::Standard, None),
        ]));

        assert_eq!(schedule.len(), 2);
        let targets: Vec<&str> = schedule.iter().map(|s| s.target_id.as_str()).collect();
        assert_eq!(targets, vec!["t1", "t2"]);
    }

    #[test]
    fn stable_within_class_preserves_plan_order() {
        // Three static tools already in declaration order stay put.
        let schedule = ToolOrchestrator::new().schedule(&plan(vec![task(
            "t1",
            &["semgrep", "jadx", "apktool"],
            TestIntensity::Passive,
            None,
        )]));

        let order: Vec<&str> = schedule.iter().map(|s| s.tool.as_str()).collect();
        assert_eq!(order, vec!["semgrep", "jadx", "apktool"]);
    }

    #[test]
    fn empty_plan_yields_empty_schedule() {
        let schedule = ToolOrchestrator::new().schedule(&plan(Vec::new()));
        assert!(schedule.is_empty());
        assert_eq!(schedule.count_in_class(ExecutionClass::ActiveNetwork), 0);
        assert_eq!(schedule.to_string().trim_end().lines().last(), Some("None"));
    }

    #[test]
    fn count_in_class_tallies_per_surface() {
        let schedule = ToolOrchestrator::new().schedule(&plan(vec![task(
            "t1",
            &["semgrep", "jadx", "nmap", "msfconsole"],
            TestIntensity::Standard,
            Some("10.0.0.1"),
        )]));

        assert_eq!(
            schedule.count_in_class(ExecutionClass::StaticLocalAnalysis),
            2
        );
        assert_eq!(schedule.count_in_class(ExecutionClass::ActiveNetwork), 1);
        assert_eq!(
            schedule.count_in_class(ExecutionClass::ActiveExploitation),
            1
        );
    }

    #[test]
    fn display_renders_ordered_steps_with_addresses() {
        let schedule = ToolOrchestrator::new().schedule(&plan(vec![task(
            "t1",
            &["semgrep", "nmap"],
            TestIntensity::Standard,
            Some("10.0.0.1"),
        )]));

        let rendered = schedule.to_string();
        assert!(rendered.contains("Execution Schedule"));
        assert!(rendered.contains("1. [StaticLocalAnalysis] target=t1 tool=semgrep"));
        // The static step carries no address; the active one does.
        assert!(rendered.contains("2. [ActiveNetwork] target=t1 tool=nmap -> 10.0.0.1"));
    }
}
