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

/// A typed artifact one action can produce and another can consume.
///
/// This lets the loop wire steps together (e.g. an engagement's findings
/// feeding a report). Extensible; today the one chained artifact is a findings
/// log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Artifact {
    /// A findings log (`--findings-log` output), consumed by `--report` /
    /// `--schedule-retest`.
    FindingsLog,
}

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
    /// The full resolved argument vector passed after `command` — the
    /// positional argument (a path, asset name, or free text) followed by any
    /// flags the planner derived from the goal (e.g. `--format json`) and any
    /// artifact wiring the loop added (e.g. `--findings-log <path>`).
    pub args: Vec<String>,
    /// Grounded routing confidence, 0–100 (semantic similarity to the
    /// action's examples).
    pub confidence: u8,
}

impl ActionCall {
    /// The primary (positional) argument, if any — the first entry of
    /// [`Self::args`] that isn't a flag.
    #[must_use]
    pub fn primary_arg(&self) -> Option<&str> {
        self.args
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .map(String::as_str)
    }
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

    /// Allocates a fresh path for a chained `artifact` (e.g. a temp findings
    /// log), or `None` if this executor can't — in which case the loop skips
    /// artifact chaining and each step uses only what the goal named. The
    /// default is `None`; the real (binary) executor overrides it.
    fn allocate_artifact(&mut self, _artifact: Artifact) -> Option<String> {
        None
    }
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
    /// report" plans `run-engagement` before `report`. When two actions anchor
    /// at the same position, the more specific trigger (a phrase over a single
    /// word) wins — "generate a wordlist for acme" plans `--gen-wordlist`, not
    /// `--llm-generate`.
    #[must_use]
    pub fn plan(&self, goal: &str) -> Vec<ActionCall> {
        let lowered = goal.to_ascii_lowercase();
        let goal_vec = self.model.embed_text(goal);
        let asset = first_asset(&lowered, self.assets);

        let mut hits: Vec<(usize, usize, usize, ActionCall)> = Vec::new();
        for (order, spec) in REGISTRY.iter().enumerate() {
            let Some((position, specificity)) = anchor_position(&lowered, spec, asset.as_ref())
            else {
                continue;
            };
            let confidence = semantic_confidence(&goal_vec, spec.examples, self.model);
            let args = resolve_args(spec, goal, &lowered, asset.as_ref());
            hits.push((
                position,
                specificity,
                order,
                ActionCall {
                    action: spec.name,
                    command: spec.command,
                    class: spec.class,
                    network: spec.network,
                    args,
                    confidence,
                },
            ));
        }
        // Order by first appearance in the goal; at the same position the more
        // specific trigger wins, then registry order breaks any remaining tie.
        hits.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)).then(a.2.cmp(&b.2)));

        let mut last_position: Option<usize> = None;
        let mut seen = BTreeSet::new();
        hits.into_iter()
            .filter(|(position, _, _, _)| {
                if last_position == Some(*position) {
                    return false;
                }
                last_position = Some(*position);
                true
            })
            .filter(|(_, _, _, call)| seen.insert(call.action))
            .map(|(_, _, _, call)| call)
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
    let mut plan = planner.plan(goal);
    chain_artifacts(&mut plan, executor);
    let mut queue: VecDeque<ActionCall> = plan.into();
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
    if requires_arg(call.command) && call.primary_arg().is_none() {
        return ActionOutcome {
            status: ActionStatus::Skipped(
                "required argument was not found in the goal".to_string(),
            ),
            output: String::new(),
        };
    }
    executor.execute(call)
}

/// Whether a command cannot run without its positional argument (the
/// path/config-driven ones). Argument-optional actions (e.g. `--llm-generate`)
/// are not listed.
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

/// The artifact an action can produce, if any.
fn produces_artifact(action: &str) -> Option<Artifact> {
    match action {
        "run-engagement" => Some(Artifact::FindingsLog),
        _ => None,
    }
}

/// The artifact an action consumes as its positional input, if any.
fn consumes_artifact(action: &str) -> Option<Artifact> {
    match action {
        "report" | "schedule-retest" => Some(Artifact::FindingsLog),
        _ => None,
    }
}

/// Wires produced artifacts to later consumers.
///
/// When the plan runs a producer (e.g. `run-engagement`, which can write a
/// findings log) before a consumer (`report` / `schedule-retest`), the loop
/// allocates one artifact path, makes the producer emit it
/// (`--findings-log <path>`), and points every following consumer at it — so
/// "run the engagement then report" reports on what the run just found, with no
/// path named in the goal. A consumer with no preceding producer keeps whatever
/// path the goal named. A no-op when the executor can't allocate a path (see
/// [`ActionExecutor::allocate_artifact`]).
pub fn chain_artifacts(plan: &mut [ActionCall], executor: &mut dyn ActionExecutor) {
    chain_one(plan, executor, Artifact::FindingsLog, "--findings-log");
}

/// Chains a single artifact kind through the plan (see [`chain_artifacts`]).
fn chain_one(
    plan: &mut [ActionCall],
    executor: &mut dyn ActionExecutor,
    artifact: Artifact,
    produce_flag: &str,
) {
    let Some(producer_idx) = plan
        .iter()
        .position(|call| produces_artifact(call.action) == Some(artifact))
    else {
        return;
    };
    let has_following_consumer = plan
        .iter()
        .skip(producer_idx + 1)
        .any(|call| consumes_artifact(call.action) == Some(artifact));
    if !has_following_consumer {
        return;
    }
    let Some(path) = executor.allocate_artifact(artifact) else {
        return;
    };

    // The producer emits the artifact (unless the goal already set that flag).
    let producer = &mut plan[producer_idx];
    if !producer.args.iter().any(|arg| arg == produce_flag) {
        producer.args.push(produce_flag.to_string());
        producer.args.push(path.clone());
    }
    // Point each following consumer's positional argument at it, overriding any
    // goal-resolved path (which for these commands would otherwise grab the
    // producer's config) while keeping the consumer's own flags (e.g.
    // `--format json`).
    for call in plan.iter_mut().skip(producer_idx + 1) {
        if consumes_artifact(call.action) == Some(artifact) {
            set_positional(&mut call.args, path.clone());
        }
    }
}

/// Sets the positional (first non-flag) argument of `args` to `path`, keeping
/// any flags. Replaces an existing positional, or prepends when there is none.
fn set_positional(args: &mut Vec<String>, path: String) {
    if args.first().is_some_and(|first| !first.starts_with('-')) {
        args[0] = path;
    } else {
        args.insert(0, path);
    }
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
            let args = if step.call.args.is_empty() {
                "-".to_string()
            } else {
                step.call.args.join(" ")
            };
            AuditRecord {
                timestamp_epoch_seconds: context.timestamp_epoch_seconds,
                actor: context.actor.to_string(),
                role: context.role,
                action: format!("agent_action_{}", step.outcome.status.label()),
                target: step.call.action.to_string(),
                details: format!(
                    "command={} class={} args=[{args}] confidence={}",
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
/// matching trigger, or the named asset for a `show-skill`-style spec — paired
/// with the anchoring trigger's specificity (its length, so a phrase outranks
/// a single word at the same position), or `None` when nothing anchors it.
fn anchor_position(
    lowered: &str,
    spec: &ActionSpec,
    asset: Option<&(usize, String)>,
) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    {
        let mut consider = |position: usize, specificity: usize| {
            let wins = match best {
                Some((best_position, best_specificity)) => {
                    position < best_position
                        || (position == best_position && specificity > best_specificity)
                }
                None => true,
            };
            if wins {
                best = Some((position, specificity));
            }
        };
        for trigger in spec.triggers {
            if let Some(position) = trigger_position(lowered, trigger) {
                consider(position, trigger.len());
            }
        }
        if spec.arg == ArgKind::AssetName {
            if let Some((position, name)) = asset {
                // A named asset is highly specific: it outranks any word
                // trigger anchored at the same position.
                consider(*position, 100 + name.len());
            }
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

/// Resolves the full argument vector `spec` takes from the goal: its
/// positional argument (a path, asset name, or free text), followed by any
/// flags the goal implies for that command (see [`flag_modifiers`]).
fn resolve_args(
    spec: &ActionSpec,
    goal: &str,
    lowered: &str,
    asset: Option<&(usize, String)>,
) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    let positional = match spec.arg {
        ArgKind::None => None,
        ArgKind::AssetName => asset.map(|(_, name)| name.clone()),
        ArgKind::Path => goal
            .split_whitespace()
            .find(|token| token.contains('/') || token.contains('.'))
            .map(ToString::to_string),
        ArgKind::Text => {
            let remainder = strip_leading_triggers(goal, lowered, spec.triggers);
            (!remainder.is_empty()).then_some(remainder)
        }
    };
    if let Some(positional) = positional {
        args.push(positional);
    }
    args.extend(flag_modifiers(spec.name, lowered));
    args
}

/// Extra command flags a goal implies for a given action — grounded, precise,
/// and additive (an unrecognized phrasing adds nothing). Examples: "report as
/// json" → `--format json`; "run the engagement without expansion" →
/// `--no-expand`.
fn flag_modifiers(action: &str, lowered: &str) -> Vec<String> {
    let mut flags = Vec::new();
    match action {
        "report" => {
            if lowered.contains("sarif") {
                flags.push("--format".to_string());
                flags.push("sarif".to_string());
            } else if lowered.contains("json") {
                flags.push("--format".to_string());
                flags.push("json".to_string());
            } else if lowered.contains("markdown") || lowered.contains(" md") {
                flags.push("--format".to_string());
                flags.push("markdown".to_string());
            }
        }
        "run-engagement" if wants_no_expand(lowered) => {
            flags.push("--no-expand".to_string());
        }
        _ => {}
    }
    flags
}

/// Whether the goal asks to disable result-driven expansion.
fn wants_no_expand(lowered: &str) -> bool {
    lowered.contains("no expand")
        || lowered.contains("no expansion")
        || lowered.contains("without expansion")
        || lowered.contains("don't expand")
        || lowered.contains("dont expand")
}

/// Drops the leading command words a `Text` action's triggers match, keeping
/// the substantive remainder as the argument. Both single-word triggers (stem
/// matched) and leading phrase triggers (matched verbatim, longest first) are
/// stripped, along with filler words, so "create a wordlist for the target
/// acme" yields "acme".
fn strip_leading_triggers(goal: &str, lowered: &str, triggers: &[&str]) -> String {
    let single: BTreeSet<&str> = triggers
        .iter()
        .filter(|t| !t.contains(' '))
        .copied()
        .collect();
    let mut phrases: Vec<Vec<&str>> = triggers
        .iter()
        .filter(|t| t.contains(' '))
        .map(|t| t.split_whitespace().collect())
        .collect();
    phrases.sort_by_key(|phrase| std::cmp::Reverse(phrase.len()));
    let noise = ["a", "the", "some", "me", "about", "text", "this", "for"];
    let words: Vec<&str> = goal.split_whitespace().collect();
    let lowered_words: Vec<&str> = lowered.split_whitespace().collect();
    let mut start = 0usize;
    while start < words.len() {
        if let Some(phrase) = phrases
            .iter()
            .find(|phrase| phrase_matches_at(&lowered_words, start, phrase))
        {
            start += phrase.len();
            continue;
        }
        let clean = lowered_words[start].trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if single.iter().any(|t| stem(t) == stem(clean)) || noise.contains(&clean) {
            start += 1;
        } else {
            break;
        }
    }
    words[start..].join(" ")
}

/// Whether every word of `phrase` matches `lowered_words` starting at `start`
/// (verbatim, ignoring surrounding punctuation).
fn phrase_matches_at(lowered_words: &[&str], start: usize, phrase: &[&str]) -> bool {
    start + phrase.len() <= lowered_words.len()
        && phrase.iter().enumerate().all(|(offset, word)| {
            let phrase_word = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
            let goal_word =
                lowered_words[start + offset].trim_matches(|c: char| !c.is_ascii_alphanumeric());
            phrase_word == goal_word
        })
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

    /// A fake executor that records calls, returns scripted output, and hands
    /// out deterministic artifact paths, so the loop (and chaining) is
    /// exercised without running real commands or touching the filesystem.
    struct FakeExecutor {
        calls: Vec<ActionCall>,
        output_for: fn(&str) -> String,
        allocations: usize,
    }

    impl FakeExecutor {
        fn new(output_for: fn(&str) -> String) -> Self {
            Self {
                calls: Vec::new(),
                output_for,
                allocations: 0,
            }
        }
    }

    impl ActionExecutor for FakeExecutor {
        fn execute(&mut self, call: &ActionCall) -> ActionOutcome {
            self.calls.push(call.clone());
            ActionOutcome::ran(0, (self.output_for)(call.action))
        }

        fn allocate_artifact(&mut self, artifact: Artifact) -> Option<String> {
            self.allocations += 1;
            let Artifact::FindingsLog = artifact;
            Some(format!("/tmp/fake-findings-{}.jsonl", self.allocations))
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
        assert_eq!(call.primary_arg(), Some("audit.jsonl"));
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
        assert_eq!(call.primary_arg(), Some("nmap"));
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

    #[test]
    fn resolves_report_format_flag_from_the_goal() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model).plan("write a report from findings.jsonl as json");
        let call = plan.iter().find(|c| c.action == "report").expect("report");
        assert!(
            call.args.windows(2).any(|w| w == ["--format", "json"]),
            "args: {:?}",
            call.args
        );
    }

    #[test]
    fn resolves_no_expand_flag_for_the_engagement() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan =
            planner_over(&assets, &model).plan("run the engagement e.conf without expansion");
        let call = plan
            .iter()
            .find(|c| c.action == "run-engagement")
            .expect("run-engagement");
        assert!(
            call.args.iter().any(|a| a == "--no-expand"),
            "args: {:?}",
            call.args
        );
    }

    #[test]
    fn plans_hash_identification_with_the_hash_as_the_argument() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model)
            .plan("identify the hash 5f4dcc3b5aa765d61d8327deb882cf99");
        let call = plan
            .iter()
            .find(|c| c.action == "hash-id")
            .expect("hash-id planned");
        assert_eq!(call.primary_arg(), Some("5f4dcc3b5aa765d61d8327deb882cf99"));
    }

    #[test]
    fn plans_wordlist_generation_with_the_target_as_the_argument() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model).plan("create a wordlist for the target acme");
        let call = plan
            .iter()
            .find(|c| c.action == "gen-wordlist")
            .expect("gen-wordlist planned");
        assert_eq!(call.primary_arg(), Some("acme"));
    }

    #[test]
    fn plans_payload_analysis_with_the_payload_as_the_argument() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model).plan("analyze this payload bash -i");
        let call = plan
            .iter()
            .find(|c| c.action == "analyze-payload")
            .expect("analyze-payload planned");
        assert_eq!(call.primary_arg(), Some("bash -i"));
    }

    #[test]
    fn plans_password_strength_with_the_password_as_the_argument() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan =
            planner_over(&assets, &model).plan("check the strength of this password Tr0ub4dor&3");
        let call = plan
            .iter()
            .find(|c| c.action == "password-strength")
            .expect("password-strength planned");
        assert_eq!(call.primary_arg(), Some("Tr0ub4dor&3"));
    }

    #[test]
    fn prefers_a_phrase_trigger_over_a_single_word_at_the_same_position() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        // "generate" alone would anchor --llm-generate, but "generate a
        // wordlist" is the more specific intent at the same position.
        let plan = planner_over(&assets, &model).plan("generate a wordlist for acme");
        let names: Vec<&str> = plan.iter().map(|c| c.action).collect();
        assert!(names.contains(&"gen-wordlist"), "planned: {names:?}");
        assert!(!names.contains(&"generate"), "planned: {names:?}");
    }

    #[test]
    fn plans_a_wps_pin_check() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model).plan("check the wps pin 12345670");
        let call = plan
            .iter()
            .find(|c| c.action == "wps-pin")
            .expect("wps-pin planned");
        assert_eq!(call.primary_arg(), Some("12345670"));
    }

    #[test]
    fn chains_engagement_findings_into_the_report() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let mut plan = planner_over(&assets, &model)
            .plan("run the engagement e.conf then write a report as json");
        let mut executor = FakeExecutor::new(|_| String::new());
        chain_artifacts(&mut plan, &mut executor);

        let producer = plan
            .iter()
            .find(|c| c.action == "run-engagement")
            .expect("run-engagement");
        let consumer = plan.iter().find(|c| c.action == "report").expect("report");

        // The producer was made to emit a findings log...
        let log = producer
            .args
            .windows(2)
            .find(|w| w[0] == "--findings-log")
            .map(|w| w[1].clone())
            .expect("producer emits --findings-log");
        // ...the report's positional now points at exactly that path...
        assert_eq!(consumer.primary_arg(), Some(log.as_str()));
        // ...and its own flag (--format json) survived the chaining.
        assert!(
            consumer.args.windows(2).any(|w| w == ["--format", "json"]),
            "flags lost: {:?}",
            consumer.args
        );
    }

    #[test]
    fn report_without_a_producer_keeps_its_named_path() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let mut plan = planner_over(&assets, &model).plan("write a report from findings.jsonl");
        let mut executor = FakeExecutor::new(|_| String::new());
        chain_artifacts(&mut plan, &mut executor);
        let consumer = plan.iter().find(|c| c.action == "report").expect("report");
        assert_eq!(consumer.primary_arg(), Some("findings.jsonl"));
        // No producer -> no artifact was allocated.
        assert_eq!(executor.allocations, 0);
    }

    #[test]
    fn chaining_reports_on_what_the_run_found_end_to_end() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let planner = planner_over(&assets, &model);
        let mut executor = FakeExecutor::new(|_| String::new());
        let transcript = run_agent(
            "run the engagement e.conf then write a report",
            &planner,
            &mut executor,
            permissive(),
        );
        // The report step actually executed with the chained findings path.
        let report_call = executor
            .calls
            .iter()
            .find(|c| c.action == "report")
            .expect("report ran");
        assert!(
            report_call
                .primary_arg()
                .is_some_and(|p| p.contains("fake-findings")),
            "report arg: {:?}",
            report_call.args
        );
        assert!(!transcript.is_empty());
    }
}
