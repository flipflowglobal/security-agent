//! The execution runtime: turns an orchestrated schedule into outcomes by
//! actually spawning tools, building each one's command through the
//! [`AdapterRegistry`].
//!
//! `execute_plan` is a synchronous, one-tool-at-a-time loop with a single
//! fixed timeout and no way to bound load, cancel in flight, re-check the
//! authorization window mid-run, or resume after a crash. Those are the
//! properties a real engagement needs, and they belong to a dedicated
//! runtime rather than the planning path. This module is that seam.
//!
//! This is **Stage-3 territory** (robust execution runtime). The stub here
//! runs the schedule sequentially — a faithful upgrade of `execute_plan`
//! that routes every step through its [`ToolAdapter`] — so the rest of the
//! system can build against a stable `ExecutionRuntime::run` signature while
//! Stage-3 work fills in bounded concurrency, rate limiting, cancellation,
//! mid-run policy re-checks, and checkpoint/resume beneath it. The
//! [`RuntimeConfig`] knobs are already surfaced so callers wire them now and
//! get the behavior when it lands.

use crate::engagement_context::EngagementContext;
use crate::execution::{DEFAULT_TIMEOUT, TaskExecutionOutcome, run_external_tool};
use crate::local_assets::LocalAgentAssets;
use crate::network_policy::NetworkMode;
use crate::orchestrator::OrchestrationSchedule;
use crate::tool_adapter::{AdapterRegistry, InvocationContext};
use std::time::Duration;

/// Tunable limits for one runtime execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// Maximum tools to run at once (Stage-3 concurrency; the stub honors
    /// only sequential execution but stores the intended bound).
    pub max_concurrency: usize,
    /// Per-tool execution timeout.
    pub per_tool_timeout: Duration,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 4,
            per_tool_timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// Executes an [`OrchestrationSchedule`] against locally-installed tools.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExecutionRuntime {
    config: RuntimeConfig,
}

impl ExecutionRuntime {
    /// A runtime with the given configuration.
    #[must_use]
    pub const fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }

    /// This runtime's configuration.
    #[must_use]
    pub const fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Runs every step in `schedule`, building each tool's command via
    /// `adapters` and the engagement's discovered context.
    ///
    /// A step whose tool is not resolvable in `assets` is skipped (no
    /// spurious outcome), matching `execute_plan`. The `NetworkMode` gate in
    /// [`crate::execution`] still governs whether an active step may run.
    #[must_use]
    pub fn run(
        &self,
        schedule: &OrchestrationSchedule,
        adapters: &AdapterRegistry,
        assets: &LocalAgentAssets,
        engagement: &EngagementContext,
        operator_args: &[String],
        mode: NetworkMode,
    ) -> Vec<TaskExecutionOutcome> {
        let mut outcomes = Vec::new();
        for step in schedule {
            let Some(tool) = assets.tool(&step.tool) else {
                continue;
            };
            let ctx = InvocationContext {
                target_id: &step.target_id,
                network_address: step.network_address.as_deref(),
                intensity: step.intensity,
                operator_args,
                engagement,
            };
            let invocation = adapters.invocation_for(step, &ctx);
            outcomes.push(TaskExecutionOutcome {
                target_id: step.target_id.clone(),
                tool: step.tool.clone(),
                result: run_external_tool(
                    tool,
                    &invocation.argv,
                    self.config.per_tool_timeout,
                    mode,
                ),
            });
        }
        outcomes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_are_sane() {
        let runtime = ExecutionRuntime::default();
        assert_eq!(runtime.config().max_concurrency, 4);
        assert_eq!(runtime.config().per_tool_timeout, DEFAULT_TIMEOUT);
    }

    #[test]
    fn empty_schedule_yields_no_outcomes() {
        let runtime = ExecutionRuntime::default();
        let outcomes = runtime.run(
            &OrchestrationSchedule::default(),
            &AdapterRegistry::with_defaults(),
            &LocalAgentAssets {
                skills: Vec::new(),
                tools: Vec::new(),
            },
            &EngagementContext::new(),
            &[],
            NetworkMode::Offline,
        );
        assert!(outcomes.is_empty());
    }
}
