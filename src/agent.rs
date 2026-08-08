//! Agent mode: turning a plain-English goal into a gated, audited sequence of
//! real command invocations (Stage 16).
//!
//! [`crate::nlu`] maps one instruction to one intent; this module generalizes
//! that into an *agent loop*. An [`AgentPlanner`] routes a goal to an ordered
//! plan of concrete [`ActionCall`]s against the grounded
//! [`crate::action_registry`], and [`run_agent`] executes that plan one step at
//! a time — gating each call through an [`AgentPolicy`], observing each step's
//! output to enqueue grounded follow-ups (bounded, like Stage 12 expansion),
//! and recording the whole run as an [`AgentTranscript`] that converts to an
//! audit trail.
//!
//! The safety model is deliberate: the model may *propose* any action, but the
//! policy decides what actually runs. Read-only actions run autonomously;
//! effectful and network actions require explicit opt-ins. The planner is
//! **grounded** — it only ever plans actions the registry defines, so the
//! model can never invent a command — and **deterministic**: the same goal
//! and outputs always produce the same transcript.

use crate::action_registry::{ActionClass, ActionSpec, ArgKind, REGISTRY};
use crate::governance::{AuditRecord, Role};
use crate::language_model::NeuralLanguageModel;
use crate::local_assets::LocalAgentAssets;
use std::collections::{BTreeSet, VecDeque};

/// A concrete, resolved decision to run one registry action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionCall {
    /// The action's stable name (matches [`ActionSpec::name`]).
    pub action: &'static str,
    /// The CLI command the executor should run.
    pub command: &'static str,
    /// The action's safety class.
    pub class: ActionClass,
    /// Whether the action performs live network I/O.
    pub network: bool,
    /// The resolved argument, if the action takes one and it was found.
    pub arg: Option<String>,
    /// Grounded routing confidence, 0–100 (semantic similarity to the
    /// action's examples).
    pub confidence: u8,
}

/// What happened when the loop handled one [`ActionCall`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionStatus {
    /// The executor ran the command and it exited with this code.
    Ran { exit_code: i32 },
    /// The policy refused the call before running it (with the reason).
    Refused(String),
    /// The executor attempted the call but it failed (with the reason).
    Failed(String),
    /// The call was skipped without running (e.g. a required argument was
    /// missing).
    Skipped(String),
}

impl ActionStatus {
    /// A short label for transcripts and audit records.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Ran { .. } => "ran",
            Self::Refused(_) => "refused",
            Self::Failed(_) => "failed",
            Self::Skipped(_) => "skipped",
        }
    }
}

/// The result of executing one action: its terminal status and any captured
/// output text (used to observe and plan grounded follow-ups).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionOutcome {
    /// The terminal status.
    pub status: ActionStatus,
    /// Captured output text, if the executor collected any.
    pub output: String,
}

impl ActionOutcome {
    /// A ran outcome carrying `output`.
    #[must_use]
    pub fn ran(exit_code: i32, output: impl Into<String>) -> Self {
        Self {
            status: ActionStatus::Ran { exit_code },
            output: output.into(),
        }
    }

    /// A failed outcome with a reason and no output.
    #[must_use]
    pub fn failed(reason: impl Into<String>) -> Self {
        Self {
            status: ActionStatus::Failed(reason.into()),
            output: String::new(),
        }
    }
}

/// Executes a resolved [`ActionCall`], returning its outcome.
///
/// Implemented by the binary (dispatching to the real command functions) and
/// by tests (a recording fake). Must never panic — a failing command returns
/// [`ActionStatus::Failed`], not a panic.
pub trait ActionExecutor {
    /// Runs `call` and returns its outcome.
    fn execute(&mut self, call: &ActionCall) -> ActionOutcome;
}

/// How the agent runs a plan.
///
/// The agent does **not** re-gate what the tools already guard. Each planned
/// command is invoked as the real command, whose own guardrails — engagement
/// scope, the active-tool gate, the offline-by-default network policy, config
/// approvals — decide what is actually permitted. This policy only carries the
/// operator's run-level choices: preview vs. run, whether to forward the
/// network opt-in, the loop bound, and the (default-off) output-feedback mode.
#[derive(Debug, Clone, Copy)]
pub struct AgentPolicy {
    /// Preview only: plan and print, but execute nothing. Off by default — the
    /// agent runs the planned commands as instructed.
    pub dry_run: bool,
    /// Forward the `--allow-network` opt-in to planned commands that perform
    /// live network I/O. Off by default, matching the binary's offline
    /// default. This is not an agent-level gate: the invoked tool still owns
    /// the guardrail (it runs offline, or refuses, without the flag); this only
    /// passes the operator's opt-in through to it.
    pub allow_network: bool,
    /// Maximum number of actions to execute in one run — a loop-termination
    /// bound, not a guardrail.
    pub max_steps: usize,
    /// Re-plan grounded follow-ups from each ran step's *output* (an
    /// observe→continue loop). Off by default: with a keyword-grounded
    /// planner, ordinary command output (which is data, not instructions)
    /// contains vocabulary that spuriously anchors unrelated actions, so this
    /// is only useful for executors whose output is itself directive. The
    /// multi-step behavior that matters — "do X then Y" — comes from planning
    /// the *goal*, which is always on.
    pub follow_up_from_output: bool,
}

impl Default for AgentPolicy {
    /// The default: execute the plan, network opt-in off (the tool stays
    /// offline unless told otherwise), no output-driven follow-ups, up to 8
    /// steps.
    fn default() -> Self {
        Self {
            dry_run: false,
            allow_network: false,
            max_steps: 8,
            follow_up_from_output: false,
        }
    }
}

impl AgentPolicy {
    /// Whether the agent will actually execute planned actions (i.e. this is
    /// not a preview-only dry run).
    #[must_use]
    pub const fn will_execute(&self) -> bool {
        !self.dry_run
    }
}

/// One handled step of a run: the call and what happened to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStep {
    /// The action call the loop handled.
    pub call: ActionCall,
    /// Its outcome.
    pub outcome: ActionOutcome,
}

/// The full record of an agent run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTranscript {
    /// The original goal.
    pub goal: String,
    /// The handled steps, in execution order.
    pub steps: Vec<AgentStep>,
    /// Whether the run hit the step budget with actions still queued.
    pub budget_exhausted: bool,
}

impl AgentTranscript {
    /// Whether the planner found no grounded action for the goal.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// The number of steps that actually ran (not refused/failed/skipped).
    #[must_use]
    pub fn ran_count(&self) -> usize {
        self.steps
            .iter()
            .filter(|step| matches!(step.outcome.status, ActionStatus::Ran { .. }))
            .count()
    }
}

/// Routes a plain-English goal to an ordered plan of grounded action calls.
pub struct AgentPlanner<'a> {
    assets: &'a LocalAgentAssets,
    model: &'a NeuralLanguageModel,
}

impl<'a> AgentPlanner<'a> {
    /// A planner over the agent's own assets and language model.
    #[must_use]
    pub const fn new(assets: &'a LocalAgentAssets, model: &'a NeuralLanguageModel) -> Self {
        Self { assets, model }
    }

    /// Plans an ordered, de-duplicated list of action calls for `goal`.
    ///
    /// An action is included only when the goal lexically anchors to its
    /// triggers (or names one of the agent's assets, for `show-skill`), so
    /// off-topic text plans nothing. Included actions are ordered by where
    /// their trigger first appears in the goal, so "run the engagement then
    /// report" plans `run-engagement` before `report`.
    #[must_use]
    pub fn plan(&self, goal: &str) -> Vec<ActionCall> {
        let lowered = goal.to_ascii_lowercase();
        let goal_vec = self.model.embed_text(goal);
        let asset = first_asset(&lowered, self.assets);

        let mut hits: Vec<(usize, usize, ActionCall)> = Vec::new();
        for (order, spec) in REGISTRY.iter().enumerate() {
            let Some(position) = anchor_position(&lowered, spec, asset.as_ref()) else {
                continue;
            };
            let confidence = semantic_confidence(&goal_vec, spec.examples, self.model);
            let arg = resolve_arg(spec, goal, &lowered, asset.as_ref());
            hits.push((
                position,
                order,
                ActionCall {
                    action: spec.name,
                    command: spec.command,
                    class: spec.class,
                    network: spec.network,
                    arg,
                    confidence,
                },
            ));
        }
        // Order by first appearance in the goal, then registry order for ties.
        hits.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        let mut seen = BTreeSet::new();
        hits.into_iter()
            .filter(|(_, _, call)| seen.insert(call.action))
            .map(|(_, _, call)| call)
            .collect()
    }
}

/// Runs the agent loop: plan the goal, then execute steps in order under
/// `policy`, observing each ran step's output to enqueue grounded follow-ups.
///
/// Each action runs at most once and the loop stops at `policy.max_steps`, so
/// it always terminates. Refused/failed steps are recorded but never produce
/// follow-ups. Returns the full transcript.
#[must_use]
pub fn run_agent(
    goal: &str,
    planner: &AgentPlanner,
    executor: &mut dyn ActionExecutor,
    policy: AgentPolicy,
) -> AgentTranscript {
    let mut queue: VecDeque<ActionCall> = planner.plan(goal).into();
    let mut queued: BTreeSet<&'static str> = queue.iter().map(|call| call.action).collect();
    let mut handled: BTreeSet<&'static str> = BTreeSet::new();
    let mut steps: Vec<AgentStep> = Vec::new();
    let mut budget_exhausted = false;

    while let Some(call) = queue.pop_front() {
        if handled.contains(call.action) {
            continue;
        }
        if steps.len() >= policy.max_steps {
            budget_exhausted = true;
            break;
        }
        handled.insert(call.action);

        let outcome = handle_call(&call, executor, policy);

        // Observe: when enabled, a step that actually ran can surface grounded
        // follow-ups from its output — bounded by the run-once invariant and
        // the budget.
        if policy.follow_up_from_output && matches!(outcome.status, ActionStatus::Ran { .. }) {
            for follow_up in planner.plan(&outcome.output) {
                if !handled.contains(follow_up.action) && queued.insert(follow_up.action) {
                    queue.push_back(follow_up);
                }
            }
        }
        steps.push(AgentStep { call, outcome });
    }

    AgentTranscript {
        goal: goal.to_string(),
        steps,
        budget_exhausted,
    }
}

/// Runs `call` through `executor`, unless this is a dry run (previewed, not
/// executed) or a required path/text argument is missing (skipped). The tools'
/// own guardrails — not this function — decide whether an executed command is
/// actually permitted.
fn handle_call(
    call: &ActionCall,
    executor: &mut dyn ActionExecutor,
    policy: AgentPolicy,
) -> ActionOutcome {
    if policy.dry_run {
        return ActionOutcome {
            status: ActionStatus::Refused("dry-run: previewed, not executed".to_string()),
            output: String::new(),
        };
    }
    if requires_arg(call.command) && call.arg.is_none() {
        return ActionOutcome {
            status: ActionStatus::Skipped(
                "required argument was not found in the goal".to_string(),
            ),
            output: String::new(),
        };
    }
    executor.execute(call)
}

/// Whether a command cannot run without its argument (the path/config-driven
/// ones). Argument-optional actions (e.g. `--llm-generate`) are not listed.
fn requires_arg(command: &str) -> bool {
    matches!(
        command,
        "--show-skill"
            | "--view-audit"
            | "--report"
            | "--schedule-retest"
            | "--record-findings"
            | "--plan-scan"
            | "--run-engagement"
    )
}

/// Identity/timing for the audit records derived from a run.
#[derive(Debug, Clone, Copy)]
pub struct AgentAuditContext<'a> {
    /// A stable identifier for this agent run (its `test_run_id`).
    pub run_id: &'a str,
    /// Who initiated the run.
    pub actor: &'a str,
    /// The actor's role.
    pub role: Role,
    /// Unix epoch seconds stamped on every record.
    pub timestamp_epoch_seconds: u64,
}

/// Derives an audit record per step (plus a completion summary), keyed to the
/// run id — the same accountability the engagement audit trail gives a scan.
#[must_use]
pub fn agent_audit_records(
    context: &AgentAuditContext,
    transcript: &AgentTranscript,
) -> Vec<AuditRecord> {
    let mut records: Vec<AuditRecord> = transcript
        .steps
        .iter()
        .map(|step| {
            let arg = step.call.arg.as_deref().unwrap_or("-");
            AuditRecord {
                timestamp_epoch_seconds: context.timestamp_epoch_seconds,
                actor: context.actor.to_string(),
                role: context.role,
                action: format!("agent_action_{}", step.outcome.status.label()),
                target: step.call.action.to_string(),
                details: format!(
                    "command={} class={} arg={arg} confidence={}",
                    step.call.command,
                    step.call.class.label(),
                    step.call.confidence,
                ),
                test_run_id: Some(context.run_id.to_string()),
            }
        })
        .collect();
    records.push(AuditRecord {
        timestamp_epoch_seconds: context.timestamp_epoch_seconds,
        actor: context.actor.to_string(),
        role: context.role,
        action: "agent_run_completed".to_string(),
        target: context.run_id.to_string(),
        details: format!(
            "goal_steps={} ran={}",
            transcript.steps.len(),
            transcript.ran_count(),
        ),
        test_run_id: Some(context.run_id.to_string()),
    });
    records
}

// ── grounded routing helpers ────────────────────────────────────────────────

/// The earliest byte position in `lowered` at which `spec` anchors — the first
/// matching trigger, or the named asset for a `show-skill`-style spec — or
/// `None` when nothing anchors it.
fn anchor_position(
    lowered: &str,
    spec: &ActionSpec,
    asset: Option<&(usize, String)>,
) -> Option<usize> {
    let mut best: Option<usize> = None;
    for trigger in spec.triggers {
        if let Some(position) = trigger_position(lowered, trigger) {
            best = Some(best.map_or(position, |b| b.min(position)));
        }
    }
    if spec.arg == ArgKind::AssetName {
        if let Some((position, _)) = asset {
            best = Some(best.map_or(*position, |b| b.min(*position)));
        }
    }
    best
}

/// The byte position where `trigger` matches in `lowered` — `contains` for a
/// phrase (has a space), whole-token stem match for a single word — or `None`.
fn trigger_position(lowered: &str, trigger: &str) -> Option<usize> {
    if trigger.contains(' ') {
        return lowered.find(trigger);
    }
    let trigger_stem = stem(trigger);
    let mut index = 0usize;
    for token in lowered.split(|c: char| !c.is_ascii_alphanumeric()) {
        if !token.is_empty() && stem(token) == trigger_stem {
            return Some(index);
        }
        // Advance past this token and the single delimiter that followed it.
        index += token.len() + 1;
    }
    None
}

/// The first token in `lowered` that names one of the agent's tools/skills,
/// with its byte position.
fn first_asset(lowered: &str, assets: &LocalAgentAssets) -> Option<(usize, String)> {
    let mut index = 0usize;
    for token in lowered.split(|c: char| !c.is_ascii_alphanumeric()) {
        if !token.is_empty() && (assets.tool(token).is_some() || assets.skill(token).is_some()) {
            return Some((index, token.to_string()));
        }
        index += token.len() + 1;
    }
    None
}

/// Resolves the argument `spec` takes from the goal.
fn resolve_arg(
    spec: &ActionSpec,
    goal: &str,
    lowered: &str,
    asset: Option<&(usize, String)>,
) -> Option<String> {
    match spec.arg {
        ArgKind::None => None,
        ArgKind::AssetName => asset.map(|(_, name)| name.clone()),
        ArgKind::Path => goal
            .split_whitespace()
            .find(|token| token.contains('/') || token.contains('.'))
            .map(ToString::to_string),
        ArgKind::Text => {
            let remainder = strip_leading_triggers(goal, lowered, spec.triggers);
            if remainder.is_empty() {
                None
            } else {
                Some(remainder)
            }
        }
    }
}

/// Drops the leading command words a `Text` action's triggers match, keeping
/// the substantive remainder as the argument.
fn strip_leading_triggers(goal: &str, lowered: &str, triggers: &[&str]) -> String {
    let single: BTreeSet<&str> = triggers
        .iter()
        .filter(|t| !t.contains(' '))
        .copied()
        .collect();
    let noise = ["a", "the", "some", "me", "about", "text", "this", "for"];
    let words: Vec<&str> = goal.split_whitespace().collect();
    let lowered_words: Vec<&str> = lowered.split_whitespace().collect();
    let mut start = 0usize;
    while start < words.len() {
        let clean = lowered_words[start].trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if single.iter().any(|t| stem(t) == stem(clean)) || noise.contains(&clean) {
            start += 1;
        } else {
            break;
        }
    }
    words[start..].join(" ")
}

/// Semantic confidence (0–100): cosine similarity between the goal and the
/// action's example centroid, mapped from `[-1, 1]` to a percentage.
fn semantic_confidence(goal_vec: &[f32], examples: &[&str], model: &NeuralLanguageModel) -> u8 {
    let mut centroid = vec![0.0_f32; goal_vec.len()];
    for example in examples {
        for (acc, value) in centroid.iter_mut().zip(model.embed_text(example)) {
            *acc += value;
        }
    }
    let similarity = (cosine(goal_vec, &centroid) + 1.0) * 0.5;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let percent = (similarity.clamp(0.0, 1.0) * 100.0).round() as u8;
    percent.min(100)
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let norm_a = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm_a > 0.0 && norm_b > 0.0 {
        dot / (norm_a * norm_b)
    } else {
        0.0
    }
}

/// A conservative suffix stemmer matching [`crate::nlu`]'s, so a trigger word
/// still anchors the inflected form a user naturally types.
fn stem(word: &str) -> &str {
    for (suffix, min_stem) in [("ous", 4), ("es", 3), ("y", 6), ("s", 3)] {
        if let Some(root) = word.strip_suffix(suffix) {
            if root.len() >= min_stem {
                return root;
            }
        }
    }
    word
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> NeuralLanguageModel {
        NeuralLanguageModel::bundled()
    }

    fn planner_over<'a>(
        assets: &'a LocalAgentAssets,
        model: &'a NeuralLanguageModel,
    ) -> AgentPlanner<'a> {
        AgentPlanner::new(assets, model)
    }

    /// A fake executor that records calls and returns scripted output, so the
    /// loop is exercised deterministically without running real commands.
    struct FakeExecutor {
        calls: Vec<ActionCall>,
        output_for: fn(&str) -> String,
    }

    impl FakeExecutor {
        fn new(output_for: fn(&str) -> String) -> Self {
            Self {
                calls: Vec::new(),
                output_for,
            }
        }
    }

    impl ActionExecutor for FakeExecutor {
        fn execute(&mut self, call: &ActionCall) -> ActionOutcome {
            self.calls.push(call.clone());
            ActionOutcome::ran(0, (self.output_for)(call.action))
        }
    }

    /// Executes, forwards network, and follows up from output — for exercising
    /// the full loop.
    fn permissive() -> AgentPolicy {
        AgentPolicy {
            dry_run: false,
            allow_network: true,
            max_steps: 8,
            follow_up_from_output: true,
        }
    }

    #[test]
    fn plans_a_single_grounded_action() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model).plan("list your tools");
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].action, "list-tools");
    }

    #[test]
    fn plans_multiple_actions_in_goal_order() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        // "engagement" then "report" must plan run-engagement before report.
        let plan = planner_over(&assets, &model)
            .plan("run the engagement config.conf then write a report");
        let names: Vec<&str> = plan.iter().map(|c| c.action).collect();
        let run_pos = names.iter().position(|n| *n == "run-engagement");
        let report_pos = names.iter().position(|n| *n == "report");
        assert!(
            run_pos.is_some() && report_pos.is_some(),
            "planned: {names:?}"
        );
        assert!(run_pos < report_pos, "order wrong: {names:?}");
    }

    #[test]
    fn out_of_scope_goal_plans_nothing() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        assert!(
            planner_over(&assets, &model)
                .plan("book me a flight to paris")
                .is_empty()
        );
    }

    #[test]
    fn resolves_a_path_argument() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model).plan("view the audit log at audit.jsonl");
        let call = plan
            .iter()
            .find(|c| c.action == "view-audit")
            .expect("view-audit");
        assert_eq!(call.arg.as_deref(), Some("audit.jsonl"));
    }

    #[test]
    fn resolves_an_asset_name_argument() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model).plan("explain the nmap skill");
        let call = plan
            .iter()
            .find(|c| c.action == "show-skill")
            .expect("show-skill");
        assert_eq!(call.arg.as_deref(), Some("nmap"));
    }

    #[test]
    fn executes_effectful_actions_by_default() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let planner = planner_over(&assets, &model);
        let mut executor = FakeExecutor::new(|_| String::new());
        // Default policy executes the plan as instructed — the tool's own
        // guardrails, not the agent, decide what a run may actually do.
        let transcript = run_agent(
            "run the engagement engagement.conf",
            &planner,
            &mut executor,
            AgentPolicy::default(),
        );
        let step = transcript
            .steps
            .iter()
            .find(|s| s.call.action == "run-engagement")
            .expect("run-engagement planned");
        assert!(matches!(step.outcome.status, ActionStatus::Ran { .. }));
        // The effectful action was actually handed to the executor.
        assert!(executor.calls.iter().any(|c| c.action == "run-engagement"));
    }

    #[test]
    fn dry_run_previews_without_executing_anything() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let planner = planner_over(&assets, &model);
        let mut executor = FakeExecutor::new(|_| String::new());
        let policy = AgentPolicy {
            dry_run: true,
            ..AgentPolicy::default()
        };
        let transcript = run_agent(
            "run the engagement engagement.conf",
            &planner,
            &mut executor,
            policy,
        );
        // Everything is previewed as refused, and the executor is never called.
        assert!(
            transcript
                .steps
                .iter()
                .all(|s| matches!(s.outcome.status, ActionStatus::Refused(_)))
        );
        assert!(executor.calls.is_empty());
        assert!(!policy.will_execute());
    }

    #[test]
    fn skips_an_action_whose_required_argument_is_missing() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let planner = planner_over(&assets, &model);
        let mut executor = FakeExecutor::new(|_| String::new());
        // "view the audit log" with no path -> planned but skipped.
        let transcript = run_agent("view the audit log", &planner, &mut executor, permissive());
        let step = transcript
            .steps
            .iter()
            .find(|s| s.call.action == "view-audit")
            .expect("view-audit planned");
        assert!(matches!(step.outcome.status, ActionStatus::Skipped(_)));
    }

    #[test]
    fn observes_output_to_enqueue_a_grounded_follow_up() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let planner = planner_over(&assets, &model);
        // list-tools "produces" output that grounds a follow-up (list skills).
        let mut executor = FakeExecutor::new(|action| {
            if action == "list-tools" {
                "now list your skills".to_string()
            } else {
                String::new()
            }
        });
        let transcript = run_agent("list your tools", &planner, &mut executor, permissive());
        let names: Vec<&str> = transcript.steps.iter().map(|s| s.call.action).collect();
        assert!(names.contains(&"list-tools"));
        assert!(
            names.contains(&"list-skills"),
            "follow-up not run: {names:?}"
        );
    }

    #[test]
    fn each_action_runs_at_most_once_and_the_loop_terminates() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let planner = planner_over(&assets, &model);
        // Output that would re-ground the same action must not loop forever.
        let mut executor = FakeExecutor::new(|_| "list your tools".to_string());
        let transcript = run_agent("list your tools", &planner, &mut executor, permissive());
        let tools_runs = transcript
            .steps
            .iter()
            .filter(|s| s.call.action == "list-tools")
            .count();
        assert_eq!(tools_runs, 1);
    }

    #[test]
    fn respects_the_step_budget() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let planner = planner_over(&assets, &model);
        let mut executor = FakeExecutor::new(|_| String::new());
        let policy = AgentPolicy {
            dry_run: false,
            allow_network: true,
            max_steps: 1,
            follow_up_from_output: false,
        };
        let transcript = run_agent(
            "list your tools and list your skills",
            &planner,
            &mut executor,
            policy,
        );
        assert_eq!(transcript.steps.len(), 1);
        assert!(transcript.budget_exhausted);
    }

    #[test]
    fn default_policy_does_not_follow_up_from_output() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let planner = planner_over(&assets, &model);
        // Even output that grounds another action must not enqueue a follow-up
        // when follow_up_from_output is off (the default), so ordinary command
        // output never spawns spurious steps.
        let mut executor = FakeExecutor::new(|_| "now list your skills".to_string());
        let policy = AgentPolicy::default();
        let transcript = run_agent("list your tools", &planner, &mut executor, policy);
        let names: Vec<&str> = transcript.steps.iter().map(|s| s.call.action).collect();
        assert_eq!(
            names,
            vec!["list-tools"],
            "no follow-up expected: {names:?}"
        );
    }

    #[test]
    fn derives_audit_records_keyed_to_the_run() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let planner = planner_over(&assets, &model);
        let mut executor = FakeExecutor::new(|_| String::new());
        let transcript = run_agent("list your tools", &planner, &mut executor, permissive());
        let ctx = AgentAuditContext {
            run_id: "agent-1",
            actor: "operator",
            role: Role::SecurityEngineer,
            timestamp_epoch_seconds: 100,
        };
        let records = agent_audit_records(&ctx, &transcript);
        // One per step plus a completion record.
        assert_eq!(records.len(), transcript.steps.len() + 1);
        assert!(
            records
                .iter()
                .all(|r| r.test_run_id.as_deref() == Some("agent-1"))
        );
        assert!(records.iter().any(|r| r.action == "agent_run_completed"));
    }

    #[test]
    fn planning_is_deterministic() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let planner = planner_over(&assets, &model);
        let goal = "run the engagement e.conf then write a report from findings.jsonl";
        assert_eq!(planner.plan(goal), planner.plan(goal));
    }
}
