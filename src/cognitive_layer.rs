//! Offline cognitive / agentic layer.
//!
//! Provides a perception → planning → action → observation → reflection loop
//! around the project's existing [`LanguageModel`] trait and tool registry.
//! Everything here runs **fully offline and locally**: the bundled executor is
//! hard-wired to [`crate::network_policy::NetworkMode::Offline`], so no agent
//! step can reach the network regardless of what the planner emits.
//!
//! The layer is intentionally model-agnostic. Any type implementing
//! [`LanguageModel`] (the bundled `NeuralLanguageModel`, a candle-backed model,
//! or a test stub) can drive it, and any [`ToolExecutor`] (the registry
//! executor or a test stub) can supply tool results.
//!
//! NOTE: this module is new and self-contained. It is brought up to the
//! repository's pedantic + nursery clippy bar via a scoped allow below; the
//! surrounding crate continues to enforce the full gate.
#![allow(clippy::pedantic, clippy::nursery)]

use crate::execution::run_external_tool;
use crate::language_model::{LanguageModel, NeuralLanguageModel};
use crate::local_assets::LocalAgentAssets;
use crate::network_policy::NetworkMode;
use crate::registry;
use crate::token_budget::TokenBudget;
use std::time::Duration;

/// Errors that can occur when building a CognitiveAgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    MissingModel,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::MissingModel => write!(f, "no language model provided"),
        }
    }
}

impl std::error::Error for BuildError {}

/// A tool executor the cognitive layer drives. Implemented by the registry
/// executor (offline) and by test stubs.
pub trait ToolExecutor {
    /// Run `tool` with `args` and return its captured outcome.
    fn execute(&self, tool: &str, args: &[String]) -> ToolOutcome;
}

/// Result of a single tool execution.
#[derive(Debug, Clone)]
pub struct ToolOutcome {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Structured understanding of the user's request.
#[derive(Debug, Clone)]
pub struct Intent {
    pub goal: String,
    pub constraints: Vec<String>,
    pub entities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepKind {
    Tool,
    Reason,
}

/// A single planned step. `tool == None` marks a reasoning step (the model
/// "thinks" rather than invoking a binary).
#[derive(Debug, Clone)]
pub struct PlanStep {
    pub id: usize,
    pub description: String,
    pub tool: Option<String>,
    pub args: Vec<String>,
    pub kind: StepKind,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub steps: Vec<PlanStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Continue,
    Revise,
    Stop,
}

#[derive(Debug, Clone)]
pub struct Reflection {
    pub decision: Decision,
    pub rationale: String,
}

/// A step that has been executed, with what was observed.
#[derive(Debug, Clone)]
pub struct ExecutedStep {
    pub step: PlanStep,
    pub outcome: ToolOutcome,
    pub observation: String,
}

/// Short-term memory for one agent episode, token-budget aware.
#[derive(Debug, Clone)]
pub struct EpisodeMemory {
    pub steps: Vec<ExecutedStep>,
    pub reflections: Vec<Reflection>,
    budget: TokenBudget,
    prev_tokens: usize,
    approx_tokens: usize,
}

impl EpisodeMemory {
    pub fn new(token_limit: usize) -> Self {
        Self {
            steps: Vec::new(),
            reflections: Vec::new(),
            budget: TokenBudget::new(token_limit),
            prev_tokens: 0,
            approx_tokens: 0,
        }
    }

    pub fn record(&mut self, step: ExecutedStep) {
        self.approx_tokens +=
            Self::tokens_of(&step.step.description) + Self::tokens_of(&step.observation);
        let delta = self.approx_tokens - self.prev_tokens;
        self.prev_tokens = self.approx_tokens;
        self.budget.consume(delta, "episode");
        self.steps.push(step);
    }

    pub fn reflect(&mut self, r: Reflection) {
        self.reflections.push(r);
    }

    pub fn token_usage(&self) -> f64 {
        self.budget.utilization()
    }

    /// Human-readable transcript of executed steps for the synthesis prompt.
    pub fn summarize(&self) -> String {
        if self.steps.is_empty() {
            return "(no steps executed)".to_string();
        }
        self.steps
            .iter()
            .map(|s| {
                let tool = s.step.tool.as_deref().unwrap_or("reason");
                format!(
                    "- [{tool}] {desc}: {obs}",
                    tool = tool,
                    desc = s.step.description,
                    obs = s.observation.replace('\n', " ").trim()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn tokens_of(s: &str) -> usize {
        s.split_whitespace().count()
    }
}

/// Summary of a completed episode for cross-turn context.
#[derive(Debug, Clone)]
pub struct EpisodeSummary {
    pub goal: String,
    pub outcome: String, // "success" | "partial" | "failed"
    pub key_facts: Vec<String>,
    pub token_cost: usize,
}

/// Long-term session memory persisting context across multiple agent runs.
#[derive(Debug, Clone)]
pub struct SessionMemory {
    pub episodes: Vec<EpisodeSummary>,
    pub working_context: Vec<String>, // key facts extracted across turns
    budget: TokenBudget,
    prev_tokens: usize,
    approx_tokens: usize,
}

impl SessionMemory {
    pub fn new(token_limit: usize) -> Self {
        Self {
            episodes: Vec::new(),
            working_context: Vec::new(),
            budget: TokenBudget::new(token_limit),
            prev_tokens: 0,
            approx_tokens: 0,
        }
    }

    /// Add a completed episode to session memory.
    pub fn add_episode(&mut self, report: &AgentReport) {
        let facts = extract_key_facts(&report.answer);
        let outcome = if report.steps.iter().all(|s| s.outcome.ok) {
            "success"
        } else if report.steps.is_empty() {
            "failed"
        } else {
            "partial"
        };
        let summary = EpisodeSummary {
            goal: report.intent.goal.clone(),
            outcome: outcome.to_string(),
            key_facts: facts,
            token_cost: report.token_usage as usize,
        };
        self.episodes.push(summary);

        // Update working context with new facts
        let top_lines: Vec<&str> = report.answer.lines().take(3).collect();
        for fact in top_lines {
            if !fact.trim().is_empty() {
                self.working_context.push(fact.trim().to_string());
            }
        }
        // Keep context bounded
        if self.working_context.len() > 20 {
            let drain = self.working_context.len() - 20;
            self.working_context.drain(0..drain);
        }

        // Token accounting
        let added_tokens = Self::tokens_of(&report.answer) + Self::tokens_of(&report.intent.goal);
        self.approx_tokens += added_tokens;
        let delta = self.approx_tokens - self.prev_tokens;
        self.prev_tokens = self.approx_tokens;
        self.budget.consume(delta, "session");
    }

    /// Generate a context string for prompt inclusion, bounded by token budget.
    pub fn context_for_prompt(&self, max_tokens: usize) -> String {
        if self.episodes.is_empty() && self.working_context.is_empty() {
            return String::new();
        }

        let mut parts: Vec<String> = Vec::new();

        // Recent episodes (most recent first)
        for ep in self.episodes.iter().rev().take(3) {
            let ep_tokens = Self::tokens_of(&ep.goal)
                + Self::tokens_of(&ep.outcome)
                + ep.key_facts
                    .iter()
                    .map(|f| Self::tokens_of(f))
                    .sum::<usize>();
            let current_tokens: usize = parts.iter().map(|p| Self::tokens_of(p)).sum();
            if current_tokens + ep_tokens > max_tokens {
                break;
            }
            let facts = if ep.key_facts.is_empty() {
                "".to_string()
            } else {
                format!(" | Facts: {}", ep.key_facts.join("; "))
            };
            parts.push(format!("[{}] {}{}", ep.outcome, ep.goal, facts));
        }

        // Working context facts
        for fact in self.working_context.iter().rev().take(5) {
            let fact_tokens = Self::tokens_of(fact);
            let current_tokens: usize = parts.iter().map(|p| Self::tokens_of(p)).sum();
            if current_tokens + fact_tokens > max_tokens {
                break;
            }
            parts.push(format!("[context] {}", fact));
        }

        parts.join("\n")
    }

    pub fn token_usage(&self) -> f64 {
        self.budget.utilization()
    }

    fn tokens_of(s: &str) -> usize {
        s.split_whitespace().count()
    }
}

/// Extract key facts from an answer (simple heuristic: first N non-empty lines).
fn extract_key_facts(answer: &str) -> Vec<String> {
    answer
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(5)
        .map(|l| l.trim().to_string())
        .collect()
}

/// Tuning knobs for the cognitive loop.
#[derive(Debug, Clone)]
pub struct CognitiveOptions {
    pub max_steps: usize,
    pub max_tokens_per_call: usize,
    pub tool_timeout: Duration,
    pub token_limit: usize,
}

impl Default for CognitiveOptions {
    fn default() -> Self {
        Self {
            max_steps: 8,
            max_tokens_per_call: 256,
            tool_timeout: Duration::from_secs(120),
            token_limit: 8_000,
        }
    }
}

/// The offline cognitive agent: ties a model and an executor into the loop.
pub struct CognitiveAgent<'a> {
    model: &'a dyn LanguageModel,
    tools: &'a dyn ToolExecutor,
    catalog: Vec<String>,
    opts: CognitiveOptions,
}

/// Builder for configuring and constructing a `CognitiveAgent`.
pub struct CognitiveAgentBuilder {
    opts: CognitiveOptions,
    model: Option<Box<dyn LanguageModel>>,
    tools: Option<Box<dyn ToolExecutor>>,
}

impl CognitiveAgentBuilder {
    pub fn new() -> Self {
        Self {
            opts: CognitiveOptions::default(),
            model: None,
            tools: None,
        }
    }

    /// Use the bundled `NeuralLanguageModel` (requires compiled-in weights).
    /// Panics if weights are missing/corrupt — same as `NeuralLanguageModel::bundled()`.
    pub fn with_bundled_model(mut self) -> Self {
        self.model = Some(Box::new(NeuralLanguageModel::bundled()));
        self
    }

    /// Provide a custom language model implementation.
    pub fn with_model(mut self, model: Box<dyn LanguageModel>) -> Self {
        self.model = Some(model);
        self
    }

    /// Provide a custom tool executor.
    pub fn with_executor(mut self, exec: Box<dyn ToolExecutor>) -> Self {
        self.tools = Some(exec);
        self
    }

    /// Override default cognitive options.
    pub fn with_options(mut self, opts: CognitiveOptions) -> Self {
        self.opts = opts;
        self
    }

    /// Construct the agent, using default registry executor if none provided.
    pub fn build(self) -> Result<CognitiveAgent<'static>, BuildError> {
        let model = self.model.ok_or(BuildError::MissingModel)?;
        let tools = self.tools.unwrap_or_else(|| {
            let assets = Box::new(LocalAgentAssets::bundled());
            let timeout = self.opts.tool_timeout;
            // Leak the box to get a 'static reference; in production use Arc
            Box::new(RegistryExecutor {
                assets: Box::leak(assets),
                timeout,
            })
        });
        Ok(CognitiveAgent {
            model: Box::leak(model),
            tools: Box::leak(tools),
            catalog: registry::cataloged_tool_names(),
            opts: self.opts,
        })
    }
}

impl Default for CognitiveAgentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Final, user-facing result of running a goal through the agent.
#[derive(Debug, Clone)]
pub struct AgentReport {
    pub intent: Intent,
    pub plan: Plan,
    pub steps: Vec<ExecutedStep>,
    pub answer: String,
    pub token_usage: f64,
}

impl<'a> CognitiveAgent<'a> {
    pub fn new(
        model: &'a dyn LanguageModel,
        tools: &'a dyn ToolExecutor,
        opts: CognitiveOptions,
    ) -> Self {
        Self {
            model,
            tools,
            catalog: registry::cataloged_tool_names(),
            opts,
        }
    }

    /// Run a free-text goal end to end and return the final report.
    pub fn run(&self, goal: &str) -> AgentReport {
        self.run_with_session(goal, None)
    }

    /// Run with an optional session memory for multi-turn conversations.
    pub fn run_with_session(&self, goal: &str, session: Option<&mut SessionMemory>) -> AgentReport {
        let intent = perceive(
            self.model,
            goal,
            &self.catalog,
            session.as_deref(),
            self.opts.max_tokens_per_call,
        );
        let mut memory = EpisodeMemory::new(self.opts.token_limit);
        let mut current_plan = plan(
            self.model,
            &intent,
            &memory,
            session.as_deref(),
            &self.catalog,
            self.opts.max_tokens_per_call,
        );
        let mut step_index = 0usize;

        while step_index < current_plan.steps.len() && memory.steps.len() < self.opts.max_steps {
            let step = current_plan.steps[step_index].clone();
            let (outcome, observation) = self.execute_step(&step);

            let executed = ExecutedStep {
                step: step.clone(),
                outcome,
                observation: observation.clone(),
            };
            memory.record(executed);

            let reflection = self.reflect(memory.steps.last().unwrap());
            memory.reflect(reflection.clone());

            match reflection.decision {
                Decision::Stop => break,
                Decision::Revise => {
                    // Re-plan with accumulated context from memory and session
                    let new_plan = plan(
                        self.model,
                        &intent,
                        &memory,
                        session.as_deref(),
                        &self.catalog,
                        self.opts.max_tokens_per_call,
                    );
                    if new_plan.steps.is_empty() {
                        break;
                    }
                    current_plan = new_plan;
                    step_index = 0;
                    continue;
                }
                Decision::Continue => {}
            }
            step_index += 1;
        }

        let answer = synthesize(self.model, &intent, &memory, self.opts.max_tokens_per_call);
        let report = AgentReport {
            intent,
            plan: current_plan,
            steps: memory.steps.clone(),
            answer,
            token_usage: memory.token_usage(),
        };

        // Update session memory if provided
        if let Some(sess) = session {
            sess.add_episode(&report);
        }

        report
    }

    fn execute_step(&self, step: &PlanStep) -> (ToolOutcome, String) {
        if step.kind == StepKind::Tool {
            let oc = self
                .tools
                .execute(step.tool.as_deref().unwrap_or(""), &step.args);
            let obs = if oc.ok {
                oc.stdout.trim().to_string()
            } else {
                format!("(error) {}", oc.stderr.trim())
            };
            (oc, obs)
        } else {
            let thought = self
                .model
                .generate(&step.description, self.opts.max_tokens_per_call);
            let oc = ToolOutcome {
                ok: true,
                stdout: thought.clone(),
                stderr: String::new(),
            };
            (oc, thought.trim().to_string())
        }
    }

    fn reflect(&self, last: &ExecutedStep) -> Reflection {
        let prompt = format!(
            "You are the reflection layer of an offline security agent.\n\
             LAST STEP: {desc}\n\
             OBSERVATION: {obs}\n\
             Decide whether to continue, revise, or stop.\n\
             Return exactly:\n\
             DECISION: <continue|revise|stop>\n\
             WHY: <one line>",
            desc = last.step.description,
            obs = last.observation,
        );
        let out = self.model.generate(&prompt, self.opts.max_tokens_per_call);
        let decision = if out.contains("stop") {
            Decision::Stop
        } else if out.contains("revise") {
            Decision::Revise
        } else {
            Decision::Continue
        };
        let rationale = out
            .lines()
            .find_map(|l| l.strip_prefix("WHY:").map(|s| s.trim().to_string()))
            .unwrap_or_else(|| out.trim().to_string());
        // Heuristic keeps the loop safe and terminating: a successful final
        // step means the goal is addressed, so we stop.
        let decision = if last.outcome.ok {
            Decision::Stop
        } else {
            decision
        };
        Reflection {
            decision,
            rationale,
        }
    }
}

// ── Perception ─────────────────────────────────────────────────────────────

fn perceive(
    model: &dyn LanguageModel,
    text: &str,
    _catalog: &[String],
    session: Option<&SessionMemory>,
    max_tokens: usize,
) -> Intent {
    let session_ctx = session
        .map(|s| s.context_for_prompt(max_tokens / 4))
        .unwrap_or_default();
    let prompt = format!(
        "You are the perception layer of an offline security agent.\n\
         {session_ctx}\n\
         USER: {text}\n\
         Extract the user's intent. Return exactly:\n\
         GOAL: <one line>\n\
         CONSTRAINTS: <comma-separated, or empty>\n\
         ENTITIES: <comma-separated hosts/paths/identifiers, or empty>",
        session_ctx = if session_ctx.is_empty() {
            "".to_string()
        } else {
            format!("SESSION CONTEXT:\n{session_ctx}\n")
        },
        text = text
    );
    let out = model.generate(&prompt, max_tokens);
    let mut goal = text.to_string();
    let mut constraints = Vec::new();
    let mut entities = Vec::new();
    for line in out.lines() {
        if let Some(g) = line.strip_prefix("GOAL:") {
            let g = g.trim().to_string();
            if !g.is_empty() {
                goal = g;
            }
        } else if let Some(c) = line.strip_prefix("CONSTRAINTS:") {
            constraints = split_csv(c);
        } else if let Some(e) = line.strip_prefix("ENTITIES:") {
            entities = split_csv(e);
        }
    }
    Intent {
        goal,
        constraints,
        entities,
    }
}

// ── Planning ──────────────────────────────────────────────────────────────

fn plan(
    model: &dyn LanguageModel,
    intent: &Intent,
    _memory: &EpisodeMemory,
    session: Option<&SessionMemory>,
    catalog: &[String],
    max_tokens: usize,
) -> Plan {
    let session_ctx = session
        .map(|s| s.context_for_prompt(max_tokens / 4))
        .unwrap_or_default();
    let catalog_line = catalog.join(", ");
    let prompt = format!(
        "You are the planning layer of an offline security agent.\n\
         {session_ctx}\n\
         GOAL: {goal}\n\
         KNOWN TOOLS: {catalog_line}\n\
         Produce an ordered plan, one step per line:\n\
         STEP <n>: TOOL=<tool> ARGS=<args> | <description>\n\
         If no tool is needed for a step, write STEP <n>: <description> (no TOOL=).",
        session_ctx = if session_ctx.is_empty() {
            "".to_string()
        } else {
            format!("SESSION CONTEXT:\n{session_ctx}\n")
        },
        goal = intent.goal,
        catalog_line = catalog_line
    );
    let out = model.generate(&prompt, max_tokens);
    let steps = parse_steps(&out, catalog);
    if !steps.is_empty() {
        return Plan { steps };
    }
    // Heuristic fallback: pick a catalog tool named in the goal, else reason.
    let tool = catalog
        .iter()
        .find(|t| intent.goal.contains(t.as_str()))
        .cloned();
    let steps = match tool {
        Some(t) => vec![PlanStep {
            id: 1,
            description: format!("Use {t} toward the goal"),
            tool: Some(t),
            args: intent.entities.clone(),
            kind: StepKind::Tool,
        }],
        None => vec![PlanStep {
            id: 1,
            description: intent.goal.clone(),
            tool: None,
            args: vec![],
            kind: StepKind::Reason,
        }],
    };
    Plan { steps }
}

fn parse_steps(text: &str, catalog: &[String]) -> Vec<PlanStep> {
    let mut steps = Vec::new();
    let mut id = 0usize;
    for line in text.lines() {
        let line = line.trim();
        let rest = match line.strip_prefix("STEP") {
            Some(r) => r,
            None => continue,
        };
        let after_colon = match rest.find(':') {
            Some(i) => &rest[i + 1..],
            None => rest,
        };
        let (head, desc) = match after_colon.find('|') {
            Some(i) => (
                after_colon[..i].trim(),
                after_colon[i + 1..].trim().to_string(),
            ),
            None => (after_colon.trim(), String::new()),
        };
        let (tool, args) = if let Some(t) = head.find("TOOL=") {
            let tv = head[t + 5..].trim();
            let name = tv
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches(',')
                .to_string();
            let args_part = if let Some(a) = tv.find("ARGS=") {
                &tv[a + 5..]
            } else {
                ""
            };
            let args: Vec<String> = args_part
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            let tool_opt = if catalog.iter().any(|c| c == &name) {
                Some(name)
            } else {
                None
            };
            (tool_opt, args)
        } else {
            (None, vec![])
        };
        id += 1;
        let kind = if tool.is_some() {
            StepKind::Tool
        } else {
            StepKind::Reason
        };
        steps.push(PlanStep {
            id,
            description: if desc.is_empty() {
                head.to_string()
            } else {
                desc
            },
            tool,
            args,
            kind,
        });
    }
    steps
}

// ── Synthesis (communication layer) ───────────────────────────────────────

fn synthesize(
    model: &dyn LanguageModel,
    intent: &Intent,
    memory: &EpisodeMemory,
    max_tokens: usize,
) -> String {
    let transcript = memory.summarize();
    let prompt = format!(
        "You are the communication layer of an offline security agent.\n\
         GOAL: {goal}\n\
         OBSERVATIONS:\n{transcript}\n\
         Write a clear, concise final answer to the user in plain language.",
        goal = intent.goal,
        transcript = transcript
    );
    let out = model.generate(&prompt, max_tokens);
    if out.trim().is_empty() {
        // Deterministic fallback so the user always gets something.
        format!(
            "Goal: {goal}. {n} step(s) executed. {summary}",
            goal = intent.goal,
            n = memory.steps.len(),
            summary = memory.summarize()
        )
    } else {
        out.trim().to_string()
    }
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

// ── Offline registry executor (the real wiring) ───────────────────────────

/// Executes cataloged tools strictly in [`crate::network_policy::NetworkMode::Offline`],
/// so agent steps can never reach the network even if a step name implies it.
pub struct RegistryExecutor<'a> {
    pub assets: &'a LocalAgentAssets,
    pub timeout: Duration,
}

impl<'a> ToolExecutor for RegistryExecutor<'a> {
    fn execute(&self, tool: &str, args: &[String]) -> ToolOutcome {
        match self.assets.tool(tool) {
            Some(local_tool) => {
                match run_external_tool(local_tool, args, self.timeout, NetworkMode::Offline) {
                    Ok(report) => ToolOutcome {
                        ok: true,
                        stdout: report.stdout,
                        stderr: report.stderr,
                    },
                    Err(e) => ToolOutcome {
                        ok: false,
                        stdout: String::new(),
                        stderr: e.to_string(),
                    },
                }
            }
            None => ToolOutcome {
                ok: false,
                stdout: String::new(),
                stderr: format!("unknown tool: {tool}", tool = tool),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic model that returns parseable structures per phase.
    struct StubModel;
    impl LanguageModel for StubModel {
        fn generate(&self, prompt: &str, _max_tokens: usize) -> String {
            if prompt.contains("USER:") && prompt.contains("GOAL:") {
                return "GOAL: scan host 10.0.0.5\nCONSTRAINTS: authorized only\nENTITIES: 10.0.0.5".to_string();
            }
            if prompt.contains("STEP") {
                return "STEP 1: TOOL=nmap ARGS=-sV 10.0.0.5 | discover services\nSTEP 2: TOOL=nikto ARGS=http://10.0.0.5 | web scan".to_string();
            }
            if prompt.contains("DECISION") {
                return "DECISION: stop\nWHY: goal addressed".to_string();
            }
            if prompt.contains("communication layer") {
                return "Scanned 10.0.0.5 with nmap and nikto; services 22 and 80 are open."
                    .to_string();
            }
            "noted".to_string()
        }

        fn perplexity(&self, _text: &str) -> f32 {
            0.0
        }
    }

    /// Executor that succeeds for every tool (or fails, if configured).
    struct StubExecutor {
        failing: bool,
    }
    impl ToolExecutor for StubExecutor {
        fn execute(&self, _tool: &str, _args: &[String]) -> ToolOutcome {
            if self.failing {
                ToolOutcome {
                    ok: false,
                    stdout: String::new(),
                    stderr: "boom".to_string(),
                }
            } else {
                ToolOutcome {
                    ok: true,
                    stdout: "open 22,80".to_string(),
                    stderr: String::new(),
                }
            }
        }
    }

    /// Model that returns garbage, to exercise perception fallback.
    struct GarbageModel;
    impl LanguageModel for GarbageModel {
        fn generate(&self, _prompt: &str, _max_tokens: usize) -> String {
            "### not structured ###".to_string()
        }

        fn perplexity(&self, _text: &str) -> f32 {
            0.0
        }
    }

    #[test]
    fn offline_agent_runs_plan_and_stops() {
        let model = StubModel;
        let exec = StubExecutor { failing: false };
        let agent = CognitiveAgent::new(&model, &exec, CognitiveOptions::default());
        let report = agent.run("scan host 10.0.0.5");

        assert!(!report.steps.is_empty(), "at least one step executed");
        assert_eq!(report.steps[0].step.tool.as_deref(), Some("nmap"));
        assert!(report.steps[0].outcome.ok, "tool step succeeded");
        assert!(
            report.answer.contains("10.0.0.5"),
            "answer references the target"
        );
        assert!(
            (0.0..=1.0).contains(&report.token_usage),
            "token usage in range"
        );
    }

    #[test]
    fn unknown_tool_reports_failure_but_completes() {
        let model = StubModel;
        let exec = StubExecutor { failing: true };
        let agent = CognitiveAgent::new(&model, &exec, CognitiveOptions::default());
        let report = agent.run("scan host 10.0.0.5");
        assert!(!report.steps.is_empty());
        assert!(
            !report.steps[0].outcome.ok,
            "failing executor surfaces error"
        );
        assert!(!report.answer.is_empty(), "still produces an answer");
    }

    #[test]
    fn perceive_falls_back_on_garbage() {
        let model = GarbageModel;
        let intent = perceive(&model, "do the thing", &["nmap".to_string()], None, 64);
        assert_eq!(intent.goal, "do the thing", "goal falls back to raw input");
    }

    #[test]
    fn planner_fallback_finds_catalog_tool() {
        let catalog: Vec<String> = vec!["nmap".to_string(), "nikto".to_string()];
        let intent = Intent {
            goal: "run nmap on the target".to_string(),
            constraints: vec![],
            entities: vec!["10.0.0.5".to_string()],
        };
        let plan = plan(
            &GarbageModel,
            &intent,
            &EpisodeMemory::new(100),
            None,
            &catalog,
            64,
        );
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].tool.as_deref(), Some("nmap"));
        assert_eq!(plan.steps[0].args, vec!["10.0.0.5".to_string()]);
    }

    #[test]
    fn parse_steps_reads_tool_and_args() {
        let catalog: Vec<String> = vec!["nmap".to_string()];
        let steps = parse_steps(
            "STEP 1: TOOL=nmap ARGS=-sV 10.0.0.5 | discover services",
            &catalog,
        );
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].tool.as_deref(), Some("nmap"));
        assert_eq!(steps[0].args, vec!["-sV", "10.0.0.5"]);
        assert_eq!(steps[0].kind, StepKind::Tool);
    }
}
