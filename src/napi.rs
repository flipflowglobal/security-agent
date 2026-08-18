//! NAPI-RS bindings for Electron embedding.
//!
//! Exposes the cognitive layer and core orchestration as native Node.js modules.
//! This allows the Electron app to call Rust functions directly without spawning
//! a separate process.

#![cfg(feature = "napi-bindings")]

use crate::cognitive_layer::{
    AgentReport, CognitiveAgentBuilder, CognitiveOptions, EpisodeMemory, EpisodeSummary, Intent,
    Plan, PlanStep, RegistryExecutor, SessionMemory, ToolExecutor, ToolOutcome,
};
use crate::language_model::{LanguageModel, NeuralLanguageModel};
use crate::local_assets::LocalAgentAssets;
use crate::network_policy::NetworkMode;
use crate::token_budget::TokenBudget;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::time::Duration;

// Model constants (from language_model.rs)
const MODEL_CONTEXT: usize = 6;
const MODEL_EMBED: usize = 16;

/// JavaScript-friendly AgentReport
#[napi(object)]
pub struct JsAgentReport {
    pub intent: JsIntent,
    pub plan: JsPlan,
    pub steps: Vec<JsExecutedStep>,
    pub answer: String,
    pub token_usage: f64,
}

impl From<AgentReport> for JsAgentReport {
    fn from(report: AgentReport) -> Self {
        Self {
            intent: report.intent.into(),
            plan: report.plan.into(),
            steps: report.steps.into_iter().map(Into::into).collect(),
            answer: report.answer,
            token_usage: report.token_usage,
        }
    }
}

#[napi(object)]
pub struct JsIntent {
    pub goal: String,
    pub constraints: Vec<String>,
    pub entities: Vec<String>,
}

impl From<Intent> for JsIntent {
    fn from(i: Intent) -> Self {
        Self {
            goal: i.goal,
            constraints: i.constraints,
            entities: i.entities,
        }
    }
}

#[napi(object)]
pub struct JsPlan {
    pub steps: Vec<JsPlanStep>,
}

impl From<Plan> for JsPlan {
    fn from(p: Plan) -> Self {
        Self {
            steps: p.steps.into_iter().map(Into::into).collect(),
        }
    }
}

#[napi(object)]
pub struct JsPlanStep {
    pub id: u32,
    pub description: String,
    pub tool: Option<String>,
    pub args: Vec<String>,
    pub kind: String, // "Tool" or "Reason"
}

impl From<PlanStep> for JsPlanStep {
    fn from(s: PlanStep) -> Self {
        Self {
            id: s.id as u32,
            description: s.description,
            tool: s.tool,
            args: s.args,
            kind: match s.kind {
                crate::cognitive_layer::StepKind::Tool => "Tool".to_string(),
                crate::cognitive_layer::StepKind::Reason => "Reason".to_string(),
            },
        }
    }
}

#[napi(object)]
pub struct JsExecutedStep {
    pub step: JsPlanStep,
    pub outcome: JsToolOutcome,
    pub observation: String,
}

impl From<crate::cognitive_layer::ExecutedStep> for JsExecutedStep {
    fn from(s: crate::cognitive_layer::ExecutedStep) -> Self {
        Self {
            step: s.step.into(),
            outcome: s.outcome.into(),
            observation: s.observation,
        }
    }
}

#[napi(object)]
pub struct JsToolOutcome {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

impl From<ToolOutcome> for JsToolOutcome {
    fn from(o: ToolOutcome) -> Self {
        Self {
            ok: o.ok,
            stdout: o.stdout,
            stderr: o.stderr,
        }
    }
}

/// JavaScript-friendly SessionMemory
#[napi]
pub struct JsSessionMemory {
    episodes: Vec<JsEpisodeSummary>,
    working_context: Vec<String>,
    token_usage: f64,
}

#[napi]
impl JsSessionMemory {
    #[napi(constructor)]
    pub fn new(_token_limit: Option<u32>) -> Self {
        Self {
            episodes: Vec::new(),
            working_context: Vec::new(),
            token_usage: 0.0,
        }
    }

    #[napi]
    pub fn add_episode(&mut self, report: JsAgentReport) {
        let outcome = if report.steps.iter().all(|s| s.outcome.ok) {
            "success"
        } else if report.steps.is_empty() {
            "failed"
        } else {
            "partial"
        };
        let facts: Vec<String> = report
            .answer
            .lines()
            .filter(|l| !l.trim().is_empty())
            .take(5)
            .map(|l| l.trim().to_string())
            .collect();

        self.episodes.push(JsEpisodeSummary {
            goal: report.intent.goal,
            outcome: outcome.to_string(),
            key_facts: facts,
            token_cost: report.token_usage as u32,
        });

        for fact in report.answer.lines().take(3) {
            if !fact.trim().is_empty() {
                self.working_context.push(fact.trim().to_string());
            }
        }
        if self.working_context.len() > 20 {
            let drain = self.working_context.len() - 20;
            self.working_context.drain(0..drain);
        }
        self.token_usage = report.token_usage;
    }

    #[napi]
    pub fn context_for_prompt(&self, max_tokens: u32) -> String {
        if self.episodes.is_empty() && self.working_context.is_empty() {
            return String::new();
        }

        let mut parts: Vec<String> = Vec::new();
        let tokens_of = |s: &str| s.split_whitespace().count();

        for ep in self.episodes.iter().rev().take(3) {
            let ep_tokens = tokens_of(&ep.goal)
                + tokens_of(&ep.outcome)
                + ep.key_facts.iter().map(|f| tokens_of(f)).sum::<usize>();
            let current: usize = parts.iter().map(|p| tokens_of(p)).sum();
            if current + ep_tokens > max_tokens as usize {
                break;
            }
            let facts = if ep.key_facts.is_empty() {
                String::new()
            } else {
                format!(" | Facts: {}", ep.key_facts.join("; "))
            };
            parts.push(format!("[{}] {}{}", ep.outcome, ep.goal, facts));
        }

        for fact in self.working_context.iter().rev().take(5) {
            let fact_tokens = tokens_of(fact);
            let current: usize = parts.iter().map(|p| tokens_of(p)).sum();
            if current + fact_tokens > max_tokens as usize {
                break;
            }
            parts.push(format!("[context] {}", fact));
        }

        parts.join("\n")
    }

    #[napi(getter)]
    pub fn episodes(&self) -> Vec<JsEpisodeSummary> {
        self.episodes.clone()
    }

    #[napi(getter)]
    pub fn working_context(&self) -> Vec<String> {
        self.working_context.clone()
    }

    #[napi(getter)]
    pub fn token_usage(&self) -> f64 {
        self.token_usage
    }
}

#[napi(object)]
#[derive(Clone)]
pub struct JsEpisodeSummary {
    pub goal: String,
    pub outcome: String,
    pub key_facts: Vec<String>,
    pub token_cost: u32,
}

/// CognitiveAgent handle for running goals
#[napi]
pub struct CognitiveAgentHandle {
    opts: CognitiveOptions,
}

#[napi]
impl CognitiveAgentHandle {
    #[napi(constructor)]
    pub fn new(
        max_steps: Option<u32>,
        max_tokens_per_call: Option<u32>,
        tool_timeout_secs: Option<u32>,
        token_limit: Option<u32>,
    ) -> Self {
        Self {
            opts: CognitiveOptions {
                max_steps: max_steps.unwrap_or(8) as usize,
                max_tokens_per_call: max_tokens_per_call.unwrap_or(256) as usize,
                tool_timeout: Duration::from_secs(tool_timeout_secs.unwrap_or(120) as u64),
                token_limit: token_limit.unwrap_or(8000) as usize,
            },
        }
    }

    /// Run a goal through the cognitive agent with bundled model
    #[napi]
    pub fn run(&self, goal: String) -> napi::Result<JsAgentReport> {
        let model = Box::new(NeuralLanguageModel::bundled()) as Box<dyn LanguageModel>;
        let assets = Box::new(LocalAgentAssets::bundled());
        let executor = Box::new(RegistryExecutor {
            assets: Box::leak(assets),
            timeout: self.opts.tool_timeout,
        });

        let agent = CognitiveAgentBuilder::new()
            .with_model(model)
            .with_executor(executor)
            .with_options(self.opts.clone())
            .build()
            .map_err(|e| napi::Error::new(napi::Status::GenericFailure, format!("{:?}", e)))?;

        let report = agent.run(&goal);
        Ok(report.into())
    }

    /// Run with session memory for multi-turn conversations
    #[napi]
    pub fn run_with_session(
        &self,
        goal: String,
        session: &mut JsSessionMemory,
    ) -> napi::Result<JsAgentReport> {
        let model = Box::new(NeuralLanguageModel::bundled()) as Box<dyn LanguageModel>;
        let assets = Box::new(LocalAgentAssets::bundled());
        let executor = Box::new(RegistryExecutor {
            assets: Box::leak(assets),
            timeout: self.opts.tool_timeout,
        });

        let agent = CognitiveAgentBuilder::new()
            .with_model(model)
            .with_executor(executor)
            .with_options(self.opts.clone())
            .build()
            .map_err(|e| napi::Error::new(napi::Status::GenericFailure, format!("{:?}", e)))?;

        let mut session_mem = session.to_rust();
        let report = agent.run_with_session(&goal, Some(&mut session_mem));
        session.from_rust(&session_mem);
        Ok(report.into())
    }
}

impl JsSessionMemory {
    fn to_rust(&self) -> SessionMemory {
        let mut mem = SessionMemory::new(8000);
        mem.episodes = self
            .episodes
            .iter()
            .map(|e| EpisodeSummary {
                goal: e.goal.clone(),
                outcome: e.outcome.clone(),
                key_facts: e.key_facts.clone(),
                token_cost: e.token_cost as usize,
            })
            .collect();
        mem.working_context = self.working_context.clone();
        mem
    }

    fn from_rust(&mut self, rust: &SessionMemory) {
        self.episodes = rust
            .episodes
            .iter()
            .map(|e| JsEpisodeSummary {
                goal: e.goal.clone(),
                outcome: e.outcome.clone(),
                key_facts: e.key_facts.clone(),
                token_cost: e.token_cost as u32,
            })
            .collect();
        self.working_context = rust.working_context.clone();
        self.token_usage = rust.token_usage();
    }
}

/// Initialize the bundled model and return capabilities
#[napi]
pub fn init_bundled_model() -> napi::Result<JsModelInfo> {
    let model = NeuralLanguageModel::bundled();
    Ok(JsModelInfo {
        vocab_size: model.vocab_size() as u32,
        embedding_dim: model.embedding_dim() as u32,
        max_seq_len: model.max_seq_len() as u32,
        supports_inference: true,
    })
}

#[napi(object)]
pub struct JsModelInfo {
    pub vocab_size: u32,
    pub embedding_dim: u32,
    pub max_seq_len: u32,
    pub supports_inference: bool,
}

/// List all available tools from the registry
#[napi]
pub fn list_tools() -> napi::Result<Vec<JsToolInfo>> {
    let tools = crate::registry::cataloged_tool_names();
    let assets = LocalAgentAssets::bundled();
    let mut result = Vec::new();
    for name in tools {
        if let Some(tool) = assets.tool(&name) {
            // Build description from ToolDefinition fields
            let desc = format!(
                "{} v{} (built-in: {}, class: {:?})",
                tool.definition.name,
                tool.definition.version,
                tool.built_in,
                tool.definition.execution_class
            );
            result.push(JsToolInfo {
                name: name.clone(),
                description: desc,
                built_in: tool.built_in,
                available: tool.is_available(),
            });
        }
    }
    Ok(result)
}

#[napi(object)]
pub struct JsToolInfo {
    pub name: String,
    pub description: String,
    pub built_in: bool,
    pub available: bool,
}

/// Execute a single tool directly
#[napi]
pub fn execute_tool(
    name: String,
    args: Vec<String>,
    timeout_secs: Option<u32>,
) -> napi::Result<JsToolOutcome> {
    let assets = LocalAgentAssets::bundled();
    let tool = assets.tool(&name).ok_or_else(|| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("Tool not found: {}", name),
        )
    })?;

    let timeout = Duration::from_secs(timeout_secs.unwrap_or(120) as u64);
    let report = crate::execution::run_external_tool(tool, &args, timeout, NetworkMode::Offline)
        .map_err(|e| napi::Error::new(napi::Status::GenericFailure, e.to_string()))?;

    Ok(JsToolOutcome {
        ok: true,
        stdout: report.stdout,
        stderr: report.stderr,
    })
}

/// Get model info
#[napi]
pub fn get_model_info() -> napi::Result<JsModelInfo> {
    init_bundled_model()
}

/// Run a quick inference test
#[napi]
pub fn test_inference(prompt: String, max_tokens: Option<u32>) -> napi::Result<String> {
    let model = NeuralLanguageModel::bundled();
    Ok(model.generate(&prompt, max_tokens.unwrap_or(64) as usize))
}
