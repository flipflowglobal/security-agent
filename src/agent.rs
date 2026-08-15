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

use crate::action_registry::{ActionClass, ActionSpec, ArgKind, REGISTRY, by_command, by_name};
use crate::governance::{AuditRecord, Role};
use crate::json::{JsonValue, parse as parse_json};
use crate::language_model::{LanguageModel, NeuralLanguageModel};
use crate::local_assets::LocalAgentAssets;
use crate::nlu::fuzzy_words_match;
use std::collections::{BTreeSet, VecDeque};
use std::fmt::Write as _;

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
// The run-level operator choices are naturally boolean (preview, network
// opt-in, output feedback, model proposals); the loop reads them as flags.
#[allow(clippy::struct_excessive_bools)]
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
    /// Let the selected language model *propose* additional actions for the
    /// goal. Off by default, keeping the default plan deterministic and
    /// keyword-grounded. Every proposal is verified against the action
    /// registry before it joins the plan — the model can suggest, never
    /// invent — and the grounded trigger plan always comes first.
    pub model_proposals: bool,
}

impl Default for AgentPolicy {
    /// The default: execute the plan, network opt-in off (the tool stays
    /// offline unless told otherwise), no output-driven follow-ups, no
    /// model-proposed actions, up to 8 steps.
    fn default() -> Self {
        Self {
            dry_run: false,
            allow_network: false,
            max_steps: 8,
            follow_up_from_output: false,
            model_proposals: false,
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
    /// An optional language model the planner may ask to *propose* actions.
    /// Proposals are always verified against the registry before they join a
    /// plan, so a weak or chatty model can only ever suggest real commands.
    proposer: Option<&'a dyn LanguageModel>,
}

impl<'a> AgentPlanner<'a> {
    /// A planner over the agent's own assets and language model. With no
    /// proposer, plans are purely deterministic trigger matches; see
    /// [`Self::with_proposer`] to enable model-proposed actions.
    #[must_use]
    pub const fn new(assets: &'a LocalAgentAssets, model: &'a NeuralLanguageModel) -> Self {
        Self {
            assets,
            model,
            proposer: None,
        }
    }

    /// Attaches a language model the planner will consult when
    /// [`plan_with_proposals`](Self::plan_with_proposals) is used. The
    /// keyword-grounded [`plan`](Self::plan) never consults it.
    #[must_use]
    pub const fn with_proposer(mut self, proposer: &'a dyn LanguageModel) -> Self {
        self.proposer = Some(proposer);
        self
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
        let tool = first_cataloged_tool(&lowered, self.assets);
        let forensic = first_forensic(&lowered);

        let mut hits: Vec<(usize, usize, usize, ActionCall)> = Vec::new();
        for (order, spec) in REGISTRY.iter().enumerate() {
            let Some((position, specificity)) = anchor_position(
                &lowered,
                spec,
                asset.as_ref(),
                tool.as_ref(),
                forensic.as_ref(),
            ) else {
                continue;
            };
            let confidence = semantic_confidence(&goal_vec, spec.examples, self.model);
            let args = resolve_args(
                spec,
                goal,
                &lowered,
                asset.as_ref(),
                tool.as_ref(),
                forensic.as_ref(),
            );
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

    /// Plans `goal` like [`Self::plan`], then — when a proposer is attached —
    /// asks it for additional action names and appends the ones the registry
    /// verifies, de-duplicated against the grounded plan and each other, and
    /// capped at [`MAX_PROPOSALS`] additions. Arguments for proposed actions
    /// are still resolved from the goal text (the model proposes *which*
    /// actions, never their arguments), and the same-position/most-specific
    /// ordering of the grounded plan is preserved: grounded matches always
    /// come first, proposals follow in registry order. Memory lines (recent
    /// run history) are folded into the proposal prompt only, never into the
    /// deterministic trigger matching.
    #[must_use]
    pub fn plan_with_proposals(&self, goal: &str, memory: &[AgentMemoryLine]) -> Vec<ActionCall> {
        let mut plan = self.plan(goal);
        let Some(proposer) = self.proposer else {
            return plan;
        };
        let lowered = goal.to_ascii_lowercase();
        let goal_vec = self.model.embed_text(goal);
        let asset = first_asset(&lowered, self.assets);
        let tool = first_cataloged_tool(&lowered, self.assets);
        let forensic = first_forensic(&lowered);
        let mut planned: BTreeSet<&'static str> = plan.iter().map(|call| call.action).collect();
        for name in propose_actions(goal, memory, proposer) {
            if !planned.insert(name) {
                continue;
            }
            let Some(spec) = by_name(name) else {
                continue;
            };
            let confidence = semantic_confidence(&goal_vec, spec.examples, self.model);
            let args = resolve_args(
                spec,
                goal,
                &lowered,
                asset.as_ref(),
                tool.as_ref(),
                forensic.as_ref(),
            );
            plan.push(ActionCall {
                action: spec.name,
                command: spec.command,
                class: spec.class,
                network: spec.network,
                args,
                confidence,
            });
        }
        plan
    }
}

/// The maximum number of registry-verified actions the model may add to a
/// plan. Proposals are advisory on top of the grounded plan; capping them
/// keeps a chatty model from ballooning a preview.
const MAX_PROPOSALS: usize = 4;

/// One remembered agent run: the goal that was asked and the actions that ran
/// for it.
///
/// Persisted as a JSONL file so later runs — with `--model-proposals` — can
/// fold recent history into the proposal prompt ("we already scanned X")
/// without ever affecting the deterministic trigger plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentMemoryLine {
    /// The goal that was asked.
    pub goal: String,
    /// The action names that ran (in run order).
    pub actions: Vec<String>,
}

impl AgentMemoryLine {
    /// Parses one JSONL line, skipping anything malformed (memory is advisory;
    /// a corrupt line must not fail a run).
    fn from_json_line(line: &str) -> Option<Self> {
        let value = parse_json(line)?;
        Some(Self {
            goal: value.get("goal")?.as_str()?.to_string(),
            actions: value
                .get("actions")?
                .as_array()?
                .iter()
                .filter_map(JsonValue::as_str)
                .map(ToString::to_string)
                .collect(),
        })
    }

    /// Renders this line as JSON (in-house, escaped — this crate never
    /// serializes through `crate::json`).
    fn to_json_line(&self) -> String {
        format!(
            "{{\"goal\":\"{}\",\"actions\":[{}]}}",
            json_escape(&self.goal),
            self.actions
                .iter()
                .map(|action| format!("\"{}\"", json_escape(action)))
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

/// Cap on how much of the append-only memory file a load keeps in RAM.
///
/// The memory file grows for the life of the agent, so a load only retains the
/// newest [`MAX_MEMORY_LINES`] records — plenty of tail context for the
/// proposal prompt (which reads at most the last six) without unbounded memory
/// use or slow starts.
const MAX_MEMORY_LINES: usize = 256;

/// Loads the agent memory file at `path`, newest last.
///
/// Missing or malformed lines are skipped; a file that does not exist yet
/// reads as empty (the first run has no history). The file is streamed
/// line-by-line and only the newest [`MAX_MEMORY_LINES`] records are kept.
///
/// # Errors
///
/// Returns `Err` only when the file cannot be read for reasons other than
/// being absent.
pub fn load_agent_memory(path: &str) -> Result<Vec<AgentMemoryLine>, String> {
    use std::io::BufRead as _;

    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("cannot read agent memory {path}: {error}")),
    };

    let reader = std::io::BufReader::new(file);
    let mut out = std::collections::VecDeque::new();
    for line in reader.lines() {
        // Malformed JSONL lines are skipped; I/O errors are surfaced rather
        // than silently dropped so a torn read cannot hide real corruption.
        let line = line.map_err(|error| format!("cannot read agent memory {path}: {error}"))?;
        if let Some(parsed) = AgentMemoryLine::from_json_line(&line) {
            if out.len() == MAX_MEMORY_LINES {
                out.pop_front();
            }
            out.push_back(parsed);
        }
    }
    Ok(out.into_iter().collect())
}

/// Appends `line` to the agent memory file at `path`, creating it (and any
/// missing parent directory) on first use.
///
/// # Errors
///
/// Returns `Err` when the file cannot be opened or written.
pub fn append_agent_memory(path: &str, line: &AgentMemoryLine) -> Result<(), String> {
    use std::io::Write;
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "cannot create memory directory {}: {error}",
                    parent.display()
                )
            })?;
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("cannot open agent memory {path}: {error}"))?;

    let mut buf = line.to_json_line();
    buf.push('\n');
    file.write_all(buf.as_bytes())
        .map_err(|error| format!("cannot write agent memory {path}: {error}"))
}

/// Asks `proposer` which registry actions fit `goal`, folding `memory` (recent
/// run history) into the prompt, then returns only the action names the
/// registry verifies. The model never supplies arguments — those stay grounded
/// in the goal text.
fn propose_actions(
    goal: &str,
    memory: &[AgentMemoryLine],
    proposer: &dyn LanguageModel,
) -> Vec<&'static str> {
    let prompt = proposal_prompt(goal, memory);
    // A short budget: naming a handful of actions needs few tokens, and a
    // bigger local model is slow on CPU.
    extract_proposals(&proposer.generate(&prompt, 48))
}

/// Builds the proposal prompt: the goal, a compact registry listing, and the
/// most recent memory lines, with an instruction to reply with action names.
fn proposal_prompt(goal: &str, memory: &[AgentMemoryLine]) -> String {
    let mut prompt = String::from(
        "You are the security-agent planner. Choose which of these actions to run \
         for the goal. Reply with only the action names, comma-separated.\n\nActions:\n",
    );
    for spec in REGISTRY {
        let _ = writeln!(prompt, "- {} ({})", spec.name, spec.command);
    }
    if !memory.is_empty() {
        prompt.push_str("\nRecent history:\n");
        for line in memory.iter().rev().take(6).rev() {
            let goal = line.goal.replace(['\n', '\r'], " ");
            let _ = writeln!(prompt, "- \"{}\" -> {}", goal, line.actions.join(", "));
        }
    }
    let _ = write!(prompt, "\nGoal: {goal}\n\nActions to run:");
    prompt
}

/// Extracts registry-verified action names from a model continuation. Only
/// registry names (or their `--command` forms) survive, matched exactly or
/// with case/separator normalization so small models' compact spellings like
/// `hashid` still resolve; anything the model invents is dropped. The result
/// is de-duplicated, order-preserving, and capped at [`MAX_PROPOSALS`].
fn extract_proposals(text: &str) -> Vec<&'static str> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for raw in text.split([',', '\n', ' ', '\t', ';']) {
        let token = raw.trim().trim_start_matches('-');
        if token.is_empty() {
            continue;
        }
        let spec = by_name(token)
            .or_else(|| by_command(&format!("--{token}")))
            .or_else(|| by_normalized_name(token));
        let Some(spec) = spec else {
            continue;
        };
        if seen.insert(spec.name) {
            out.push(spec.name);
        }
        if out.len() >= MAX_PROPOSALS {
            break;
        }
    }
    out
}

/// Fallback proposal match: compares the token to every registry name and
/// `--command` ignoring case and `-`/`_` separators, so `HashID`, `hash-id`,
/// `hash_id`, and `hashid` all resolve to the same action. Exact lookups win;
/// this only catches the compact spellings small offline models tend to emit.
fn by_normalized_name(token: &str) -> Option<&'static ActionSpec> {
    let compact = token.to_ascii_lowercase().replace(['-', '_'], "");
    REGISTRY.iter().find(|spec| {
        spec.name.replace(['-', '_'], "") == compact
            || spec.command.replace(['-', '_'], "") == compact
    })
}

/// Escapes a string for embedding in the in-house JSON memory format: quotes,
/// backslashes, and control characters.
fn json_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len() + 2);
    for ch in text.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(escaped, "\\u{:04x}", u32::from(ch));
            }
            ch => escaped.push(ch),
        }
    }
    escaped
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
    run_agent_with_plan(goal, planner, planner.plan(goal), executor, policy)
}

/// Like [`run_agent`], but lets the planner's proposer add registry-verified
/// actions when `policy.model_proposals` is set.
///
/// Memory lines (recent run history) are folded into the proposal prompt.
/// Without the flag (or without a proposer) this behaves exactly like
/// [`run_agent`].
#[must_use]
pub fn run_agent_with_memory(
    goal: &str,
    planner: &AgentPlanner,
    executor: &mut dyn ActionExecutor,
    policy: AgentPolicy,
    memory: &[AgentMemoryLine],
) -> AgentTranscript {
    let plan = if policy.model_proposals {
        planner.plan_with_proposals(goal, memory)
    } else {
        planner.plan(goal)
    };
    run_agent_with_plan(goal, planner, plan, executor, policy)
}

/// Executes a caller-provided plan under `policy` — the shared loop behind
/// [`run_agent`] and [`run_agent_with_memory`], so a precomputed (previewed)
/// plan is exactly what runs.
#[must_use]
pub fn run_agent_with_plan(
    goal: &str,
    planner: &AgentPlanner,
    mut plan: Vec<ActionCall>,
    executor: &mut dyn ActionExecutor,
    policy: AgentPolicy,
) -> AgentTranscript {
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
    // `--run-tool` needs *both* positionals (analyzer name and local path);
    // running it with only one always fails in the child, so skip instead.
    if call.command == "--run-tool" {
        let positionals = call.args.iter().filter(|arg| !arg.starts_with('-')).count();
        if positionals < 2 {
            return ActionOutcome {
                status: ActionStatus::Skipped(
                    "run-tool needs both an analyzer name and a local input path".to_string(),
                ),
                output: String::new(),
            };
        }
    }
    executor.execute(call)
}

/// Whether a command cannot run without its positional argument. Covers the
/// path/config-driven commands and the free-text ones (`ArgKind::Text`), so a
/// model-proposed `--hash-id` or `--llm-generate` with no goal text is skipped
/// instead of launching a child that fails on an empty argument.
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
            | "--hash-id"
            | "--password-strength"
            | "--gen-wordlist"
            | "--wps-pin"
            | "--analyze-payload"
            | "--obfuscate-ps"
            | "--llm-generate"
            | "--llm-perplexity"
            | "--run-tool"
            | "--run-external-tool"
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
    tool: Option<&(usize, String)>,
    forensic: Option<&(usize, String)>,
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
        match spec.arg {
            ArgKind::AssetName => {
                if let Some((position, name)) = asset {
                    // A named asset is highly specific: it outranks any word
                    // trigger anchored at the same position (specificity 100+).
                    consider(*position, 100 + name.len());
                }
            }
            // "run <cataloged-tool>" routes here rather than to show-skill:
            // naming a cataloged tool under an execution verb ("run", "scan",
            // "execute"...) anchors at the tool's position with higher
            // specificity than the show-skill asset anchor, so it wins the
            // same-position tie. Only a cataloged *tool* anchors here — a
            // skill-only name must not route to a tool run — and the seven
            // forensic analyzers are excluded (they route to run-tool below).
            ArgKind::CatalogToolArgs => {
                if has_execution_verb(lowered) {
                    if let Some((position, name)) = tool {
                        if !is_forensic(name) {
                            consider(*position, 200 + name.len());
                        }
                    }
                }
            }
            // "run <forensic-analyzer> on <path>" routes here. Outranks both
            // show-skill and run-external-tool at the same position.
            ArgKind::BuiltinToolPath => {
                if has_execution_verb(lowered) {
                    if let Some((position, name)) = forensic {
                        consider(*position, 210 + name.len());
                    }
                }
            }
            ArgKind::None | ArgKind::Path | ArgKind::Text => {}
        }
    }
    best
}

/// Word-boundary predicate for tokenizing a goal into trigger/asset tokens.
///
/// Alphanumerics plus `-` and `_` are word characters, so hyphenated and
/// underscored names (`aircrack-ng`, `bulk_extractor`, `evil-winrm`) tokenize
/// whole and can anchor as a single-word trigger or a named asset. Splitting on
/// them instead — the earlier behavior — silently made those names unmatchable,
/// so a goal that explicitly named such a tool planned nothing.
const fn is_token_boundary(c: char) -> bool {
    !(c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// The byte position where `trigger` matches in `lowered` — `contains` for a
/// phrase (has a space), whole-token stem match for a single word, falling
/// back to a fuzzy edit-distance match so a misspelled trigger word still
/// anchors the action — or `None`.
fn trigger_position(lowered: &str, trigger: &str) -> Option<usize> {
    if trigger.contains(' ') {
        return lowered.find(trigger);
    }
    let trigger_stem = stem(trigger);
    let mut index = 0usize;
    for token in lowered.split(is_token_boundary) {
        if !token.is_empty() && (stem(token) == trigger_stem || fuzzy_words_match(token, trigger)) {
            return Some(index);
        }
        // Advance past this token and the single delimiter that followed it.
        index += token.len() + 1;
    }
    None
}

/// The first token in `lowered` that names one of the agent's tools/skills,
/// with its byte position. Misspellings resolve through the same fuzzy
/// edit-distance matcher used for trigger words, so "identfy the nmap
/// skill" still names nmap; the canonical name is returned (not the typo).
fn first_asset(lowered: &str, assets: &LocalAgentAssets) -> Option<(usize, String)> {
    let mut index = 0usize;
    for token in lowered.split(is_token_boundary) {
        if let Some(name) = canonical_asset_name(token, assets) {
            return Some((index, name));
        }
        index += token.len() + 1;
    }
    None
}

/// The first token naming a cataloged *tool* (not a skill), with its position.
/// `run-external-tool` runs real tools, so it anchors only on these — a
/// skill-only name (e.g. the bundled `security-agent` skill) must never route
/// to a tool run, which would deterministically fail as "unknown cataloged
/// tool". Fuzzy misses resolve to the canonical tool name so a typo still
/// runs the intended tool.
fn first_cataloged_tool(lowered: &str, assets: &LocalAgentAssets) -> Option<(usize, String)> {
    let mut index = 0usize;
    for token in lowered.split(is_token_boundary) {
        if let Some(name) = assets
            .tool(token)
            .map(|tool| tool.definition.name.clone())
            .or_else(|| fuzzy_tool_name(token, assets))
        {
            return Some((index, name));
        }
        index += token.len() + 1;
    }
    None
}

/// The offline forensic analyzers `--run-tool` runs natively on a local file.
/// These route to `run-tool`; every other cataloged tool routes to
/// `run-external-tool`.
const FORENSIC_ANALYZERS: [&str; 7] = [
    "autopsy",
    "volatility",
    "wireshark",
    "binwalk",
    "foremost",
    "bulk_extractor",
    "hashdeep",
];

/// Whether `name` is one of the offline forensic analyzers.
fn is_forensic(name: &str) -> bool {
    FORENSIC_ANALYZERS.contains(&name)
}

/// The first token in `lowered` naming a forensic analyzer, with its position.
/// Misspellings resolve to the canonical analyzer name.
fn first_forensic(lowered: &str) -> Option<(usize, String)> {
    let mut index = 0usize;
    for token in lowered.split(is_token_boundary) {
        if let Some(name) = canonical_forensic_name(token) {
            return Some((index, name));
        }
        index += token.len() + 1;
    }
    None
}

/// The canonical cataloged tool or skill name matching `token` — exact match
/// first, then a close fuzzy match — or `None`. A fuzzy match requires at
/// least four characters and a name length within one edit, so `nmpa` reaches
/// nmap while a short word is never mistaken for a different asset.
fn canonical_asset_name(token: &str, assets: &LocalAgentAssets) -> Option<String> {
    if let Some(tool) = assets.tool(token) {
        return Some(tool.definition.name.clone());
    }
    if let Some(skill) = assets.skill(token) {
        return Some(skill.name.to_string());
    }
    assets
        .tools()
        .iter()
        .find(|tool| {
            fuzzy_words_match(token, &tool.definition.name)
                && token.len() >= 4
                && token.len().abs_diff(tool.definition.name.len()) <= 1
        })
        .map(|tool| tool.definition.name.clone())
        .or_else(|| {
            assets
                .skills()
                .iter()
                .find(|skill| {
                    fuzzy_words_match(token, skill.name)
                        && token.len() >= 4
                        && token.len().abs_diff(skill.name.len()) <= 1
                })
                .map(|skill| skill.name.to_string())
        })
}

/// The canonical cataloged *tool* name matching `token` — exact match first,
/// then a close fuzzy match — or `None`. Used where a skill-only name must not
/// route to a tool run.
fn fuzzy_tool_name(token: &str, assets: &LocalAgentAssets) -> Option<String> {
    assets
        .tools()
        .iter()
        .find(|tool| {
            fuzzy_words_match(token, &tool.definition.name)
                && token.len() >= 4
                && token.len().abs_diff(tool.definition.name.len()) <= 1
        })
        .map(|tool| tool.definition.name.clone())
}

/// The canonical forensic analyzer name matching `token`, or `None`.
fn canonical_forensic_name(token: &str) -> Option<String> {
    if is_forensic(token) {
        return Some(token.to_string());
    }
    FORENSIC_ANALYZERS
        .iter()
        .find(|name| {
            fuzzy_words_match(token, name)
                && token.len() >= 4
                && token.len().abs_diff(name.len()) <= 1
        })
        .map(|name| (*name).to_string())
}

/// Whether the goal contains an execution verb — the signal that a named tool
/// should be *run*, not explained. Distinguishes "run nmap" (run-external-tool)
/// from "explain nmap" (show-skill).
fn has_execution_verb(lowered: &str) -> bool {
    lowered.split(is_token_boundary).any(|token| {
        matches!(
            token,
            "run" | "execute" | "exec" | "launch" | "scan" | "carve" | "analyze" | "analyse"
        )
    })
}

/// The first token that looks like a filesystem path (contains a `/`), used as
/// the local input for `--run-tool`.
fn path_token(goal: &str) -> Option<String> {
    goal.split_whitespace()
        .find(|token| token.contains('/'))
        .map(ToString::to_string)
}

/// A best-effort target/host argument for `--run-external-tool`: the first
/// host-like token (containing `.` or `-`) that isn't the tool name itself. A
/// deterministic single-target extraction — precise multi-flag invocations
/// still belong on the raw CLI.
fn external_tool_target(goal: &str, tool_name: &str) -> Option<String> {
    goal.split_whitespace()
        .map(|word| {
            word.trim_matches(|c: char| {
                !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '/')
            })
        })
        .find(|word| {
            word.len() > 2
                && !word.eq_ignore_ascii_case(tool_name)
                && (word.contains('.') || word.contains('-') || word.contains('/'))
        })
        .map(ToString::to_string)
}

/// Resolves the full argument vector `spec` takes from the goal: its
/// positional argument (a path, asset name, or free text), followed by any
/// flags the goal implies for that command (see [`flag_modifiers`]).
fn resolve_args(
    spec: &ActionSpec,
    goal: &str,
    lowered: &str,
    asset: Option<&(usize, String)>,
    tool: Option<&(usize, String)>,
    forensic: Option<&(usize, String)>,
) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    match spec.arg {
        ArgKind::None => {}
        ArgKind::AssetName => {
            if let Some((_, name)) = asset {
                args.push(name.clone());
            }
        }
        ArgKind::Path => {
            if let Some(path) = goal
                .split_whitespace()
                .find(|token| token.contains('/') || token.contains('.'))
            {
                args.push(path.to_string());
            }
        }
        ArgKind::Text => {
            let remainder = strip_leading_triggers(goal, lowered, spec.triggers);
            if !remainder.is_empty() {
                args.push(remainder);
            }
        }
        // `--run-tool <analyzer> <path>`: the named forensic analyzer, then the
        // local input path.
        ArgKind::BuiltinToolPath => {
            if let Some((_, name)) = forensic {
                if let Some(path) = path_token(goal) {
                    args.push(name.clone());
                    args.push(path);
                }
            }
        }
        // `--run-external-tool <tool> [target]`: the cataloged tool, then a
        // best-effort target argument.
        ArgKind::CatalogToolArgs => {
            if let Some((_, name)) = tool {
                args.push(name.clone());
                if let Some(target) = external_tool_target(goal, name) {
                    args.push(target);
                }
            }
        }
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
            model_proposals: false,
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
    fn a_hyphenated_asset_name_anchors_and_resolves_as_the_argument() {
        // Regression: the goal tokenizer split on `-`/`_`, so an explicitly
        // named tool like `aircrack-ng` never matched `assets.tool()` and the
        // action planned no argument (or nothing at all). It must now anchor
        // whole and resolve as the show-skill argument.
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model).plan("describe aircrack-ng");
        let show = plan
            .iter()
            .find(|call| call.action == "show-skill")
            .expect("naming aircrack-ng should plan show-skill");
        assert_eq!(show.primary_arg(), Some("aircrack-ng"));
    }

    #[test]
    fn running_a_cataloged_tool_routes_to_run_external_tool_not_show_skill() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model).plan("run nmap against api-staging.example.com");
        let call = plan
            .iter()
            .find(|call| call.action == "run-external-tool")
            .expect("'run nmap' should plan run-external-tool");
        assert_eq!(call.command, "--run-external-tool");
        assert!(call.network, "a cataloged live tool is a network action");
        assert_eq!(call.args.first().map(String::as_str), Some("nmap"));
        assert_eq!(
            call.args.get(1).map(String::as_str),
            Some("api-staging.example.com"),
            "the host should be resolved as the tool's target"
        );
        // An execution verb means run it, not explain it.
        assert!(
            !plan.iter().any(|call| call.action == "show-skill"),
            "naming a tool under 'run' must not also plan show-skill"
        );
    }

    #[test]
    fn running_a_forensic_analyzer_routes_to_run_tool_with_name_and_path() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model).plan("run volatility on /cases/mem.raw");
        let call = plan
            .iter()
            .find(|call| call.action == "run-tool")
            .expect("'run volatility on <path>' should plan run-tool");
        assert_eq!(call.command, "--run-tool");
        assert!(!call.network);
        assert_eq!(
            call.args,
            vec!["volatility".to_string(), "/cases/mem.raw".to_string()]
        );
        // A forensic analyzer routes to run-tool, never run-external-tool.
        assert!(!plan.iter().any(|call| call.action == "run-external-tool"));
    }

    #[test]
    fn explaining_a_tool_still_routes_to_show_skill_not_run() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model).plan("explain nmap");
        assert!(
            plan.iter().any(|call| call.action == "show-skill"),
            "no execution verb means explain, not run"
        );
        assert!(
            !plan
                .iter()
                .any(|call| call.action == "run-external-tool" || call.action == "run-tool"),
            "explain must not schedule a run"
        );
    }

    #[test]
    fn a_skill_only_name_does_not_route_to_run_external_tool() {
        // `security-agent` is a bundled skill, not a cataloged tool. Even under
        // an execution verb it must not plan a tool run (which would fail as
        // "unknown cataloged tool").
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model).plan("run security-agent");
        assert!(
            !plan.iter().any(|call| call.action == "run-external-tool"),
            "a skill-only name must not route to run-external-tool"
        );
    }

    #[test]
    fn run_tool_without_a_path_is_skipped_not_executed() {
        // Naming an analyzer but no local path leaves run-tool a positional
        // short; it must be skipped, not executed into a guaranteed failure.
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let planner = planner_over(&assets, &model);
        let plan = planner.plan("run volatility");
        assert!(
            plan.iter().any(|call| call.action == "run-tool"),
            "naming an analyzer should still plan run-tool"
        );
        let mut executor = FakeExecutor::new(|_| String::new());
        let transcript = run_agent_with_plan(
            "run volatility",
            &planner,
            plan,
            &mut executor,
            permissive(),
        );
        let step = transcript
            .steps
            .iter()
            .find(|step| step.call.action == "run-tool")
            .expect("run-tool step present");
        assert!(
            matches!(step.outcome.status, ActionStatus::Skipped(_)),
            "incomplete run-tool must be skipped, got {:?}",
            step.outcome.status
        );
        assert!(
            !executor
                .calls
                .iter()
                .any(|call| call.command == "--run-tool"),
            "a skipped run-tool must never reach the executor"
        );
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
            model_proposals: false,
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

    /// A stub language model returning a fixed continuation, so the proposal
    /// path is exercised deterministically without a real model.
    struct StubProposer(&'static str);

    impl LanguageModel for StubProposer {
        fn generate(&self, _prompt: &str, _max_tokens: usize) -> String {
            self.0.to_string()
        }

        fn perplexity(&self, _text: &str) -> f32 {
            0.0
        }
    }

    #[test]
    fn extract_proposals_keeps_only_registry_verified_actions() {
        // Real names (in `--command` and bare forms), an invented name, and
        // free text all mix in; only verified names survive, de-duplicated and
        // order-preserving.
        let names = extract_proposals("--report, hash-id, nope, report, definitely-not-real");
        assert_eq!(names, vec!["report", "hash-id"]);
    }

    #[test]
    fn extract_proposals_drops_gibberish() {
        assert!(extract_proposals("make it so engage the shields").is_empty());
    }

    #[test]
    fn extract_proposals_caps_the_additions() {
        let names = extract_proposals("report, hash-id, generate, list-tools, wps-pin");
        assert_eq!(names.len(), MAX_PROPOSALS);
    }

    #[test]
    fn extract_proposals_normalizes_case_and_separators() {
        // Small offline models emit compact spellings; each of these must
        // resolve to the same registry action as the canonical name.
        for token in ["hashid", "HASH-ID", "hash_id", "HashID", "--hashid"] {
            let names = extract_proposals(token);
            assert_eq!(names, vec!["hash-id"], "token {token:?}");
        }
        // Normalization must not invent actions: a compact form that matches
        // no registry entry still drops.
        assert!(extract_proposals("hashd").is_empty());
    }

    #[test]
    fn text_arg_actions_skip_without_goal_text() {
        // A model-proposed text-arg action with no goal text to draw from must
        // be skipped rather than launching a child that fails on an empty
        // argument.
        let call = ActionCall {
            action: "hash-id",
            command: "--hash-id",
            class: ActionClass::ReadOnly,
            network: false,
            args: Vec::new(),
            confidence: 50,
        };
        let mut executor = FakeExecutor::new(|_| String::new());
        let outcome = handle_call(&call, &mut executor, permissive());
        assert!(
            matches!(outcome.status, ActionStatus::Skipped(_)),
            "empty text arg must skip, got {outcome:?}"
        );
        assert!(executor.calls.is_empty(), "executor must not run");
    }

    #[test]
    fn plan_with_proposals_without_a_proposer_matches_plan() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let planner = planner_over(&assets, &model);
        assert_eq!(
            planner.plan_with_proposals("list your tools", &[]),
            planner.plan("list your tools")
        );
    }

    #[test]
    fn plan_with_proposals_appends_verified_actions_after_grounded_plan() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let proposer = StubProposer("hash-id, report, not-a-real-action");
        let planner = planner_over(&assets, &model).with_proposer(&proposer);
        let plan = planner.plan_with_proposals("list your tools", &[]);
        let names: Vec<&str> = plan.iter().map(|c| c.action).collect();
        // Grounded match first, then the registry-verified proposals in the
        // order the model named them; the invented name is dropped.
        assert_eq!(names, vec!["list-tools", "hash-id", "report"]);
    }

    #[test]
    fn plan_with_proposals_is_deterministic() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let proposer = StubProposer("report, hash-id");
        let planner = planner_over(&assets, &model).with_proposer(&proposer);
        let a = planner.plan_with_proposals("list your tools", &[]);
        let b = planner.plan_with_proposals("list your tools", &[]);
        assert_eq!(a, b);
    }

    #[test]
    fn run_agent_with_memory_only_adds_proposals_when_enabled() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let proposer = StubProposer("build-info");
        let planner = planner_over(&assets, &model).with_proposer(&proposer);

        // Default policy (model_proposals off): memory is ignored, exactly
        // like the plain run_agent path.
        let mut executor = FakeExecutor::new(|_| String::new());
        let _ = run_agent_with_memory(
            "list your tools",
            &planner,
            &mut executor,
            permissive(),
            &[],
        );
        assert!(
            executor.calls.iter().all(|c| c.action == "list-tools"),
            "calls: {:?}",
            executor.calls
        );

        // With the flag on, the verified proposal runs too (build-info needs
        // no argument, so it executes rather than being skipped).
        let mut executor = FakeExecutor::new(|_| String::new());
        let policy = AgentPolicy {
            model_proposals: true,
            ..permissive()
        };
        let _ = run_agent_with_memory("list your tools", &planner, &mut executor, policy, &[]);
        assert!(
            executor.calls.iter().any(|c| c.action == "build-info"),
            "calls: {:?}",
            executor.calls
        );
    }

    #[test]
    fn agent_memory_round_trips_through_json_lines() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-memory-roundtrip-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let line = AgentMemoryLine {
            goal: "scan \"web-1\" now\nplease".to_string(),
            actions: vec!["scan".to_string(), "report".to_string()],
        };
        append_agent_memory(path.to_str().expect("path"), &line).expect("append");
        let loaded = load_agent_memory(path.to_str().expect("path")).expect("load");
        assert_eq!(loaded, vec![line]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn agent_memory_skips_malformed_lines() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-memory-malformed-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        std::fs::write(
            &path,
            "{\"goal\":\"a\",\"actions\":[\"scan\"]}\nnot json\n{\"goal\":\"b\",\"actions\":[]}\n",
        )
        .expect("write memory");
        let loaded = load_agent_memory(path.to_str().expect("path")).expect("load");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[1].goal, "b");
        assert!(loaded[1].actions.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_memory_file_loads_empty() {
        let path = std::env::temp_dir().join("security-agent-memory-missing.jsonl");
        let _ = std::fs::remove_file(&path);
        let loaded = load_agent_memory(path.to_str().expect("path")).expect("load");
        assert!(loaded.is_empty());
    }

    #[test]
    fn misspelled_trigger_words_still_plan() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model).plan("lisst toolz plz");
        assert!(
            plan.iter().any(|call| call.action == "list-tools"),
            "a misspelled 'list tools' should still plan list-tools"
        );
        let plan = planner_over(&assets, &model).plan("what is youir status?");
        assert!(
            plan.iter().any(|call| call.action == "offline-status"),
            "a misspelled status question should still plan offline-status"
        );
    }

    #[test]
    fn misspelled_asset_names_resolve_to_the_canonical_tool() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model).plan("explane nmpa");
        let show = plan
            .iter()
            .find(|call| call.action == "show-skill")
            .expect("naming a misspelled skill should plan show-skill");
        assert_eq!(
            show.primary_arg(),
            Some("nmap"),
            "the typo must resolve to the canonical skill name"
        );
    }

    #[test]
    fn misspelled_forensic_analyzer_routes_to_run_tool() {
        let assets = LocalAgentAssets::bundled();
        let model = model();
        let plan = planner_over(&assets, &model).plan("run volitility on /cases/mem.raw");
        let call = plan
            .iter()
            .find(|call| call.action == "run-tool")
            .expect("a misspelled forensic analyzer should still plan run-tool");
        assert_eq!(call.args.first().map(String::as_str), Some("volatility"));
    }
}
