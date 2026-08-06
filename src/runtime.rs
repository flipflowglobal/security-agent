//! The execution runtime: turns an orchestrated schedule into outcomes by
//! actually spawning tools, building each one's command through the
//! [`AdapterRegistry`].
//!
//! `execute_plan` is a synchronous, one-tool-at-a-time loop with a single
//! fixed timeout and no way to bound load, cancel in flight, re-check the
//! authorization window mid-run, or resume after a crash. Those are the
//! properties a real engagement needs, and they belong to a dedicated
//! runtime rather than the planning path. This module is that runtime.
//!
//! Two invariants make it safe to run tools concurrently:
//!
//! 1. **Least-invasive class barrier.** Steps are executed one execution
//!    class at a time — every [`ExecutionClass::StaticLocalAnalysis`] step
//!    finishes before any [`ExecutionClass::ActiveNetwork`] step starts, and
//!    all of those finish before any [`ExecutionClass::ActiveExploitation`]
//!    step. Parallelism happens only *within* a class, never across, so a
//!    blocker found by cheap local analysis can still halt the run before
//!    traffic reaches a live target.
//! 2. **Deterministic output.** Outcomes are returned in the schedule's own
//!    order regardless of which worker thread finished first.
//!
//! On top of that the runtime offers bounded concurrency, an optional
//! minimum interval between tool spawns (rate limiting), a cancellation
//! kill-switch, a mid-run authorization guard, and checkpoint/resume so an
//! interrupted engagement skips the steps it already completed.

use crate::engagement_context::EngagementContext;
use crate::execution::ToolExecutionError;
use crate::execution::{
    DEFAULT_TIMEOUT, TaskExecutionOutcome, ToolExecutionReport, run_external_tool,
};
use crate::local_assets::LocalAgentAssets;
use crate::network_policy::NetworkMode;
use crate::observability::{EngagementEvent, EventSink};
use crate::orchestrator::OrchestrationSchedule;
use crate::registry::ExecutionClass;
use crate::run_control::RunController;
use crate::scope::ScopePolicy;
use crate::secrets::SecretStore;
use crate::tool_adapter::{AdapterRegistry, InvocationContext};
use crate::tool_gate::{GateDecision, ToolGate};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The order execution classes run in — least invasive first. A class fully
/// completes before the next begins.
const CLASS_ORDER: [ExecutionClass; 3] = [
    ExecutionClass::StaticLocalAnalysis,
    ExecutionClass::ActiveNetwork,
    ExecutionClass::ActiveExploitation,
];

/// Tunable limits for one runtime execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// Maximum tools to run at once within a single execution class.
    pub max_concurrency: usize,
    /// Per-tool execution timeout.
    pub per_tool_timeout: Duration,
    /// Minimum wall-clock interval between two tool spawns, enforced across
    /// the concurrent workers. `None` disables rate limiting.
    pub min_spawn_interval: Option<Duration>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 4,
            per_tool_timeout: DEFAULT_TIMEOUT,
            min_spawn_interval: None,
        }
    }
}

/// The invariant inputs of one run: what to execute and how each command is
/// built. Bundled into one value so the runtime's entry points stay readable.
pub struct RunInputs<'a> {
    /// The ordered, deduplicated schedule to execute.
    pub schedule: &'a OrchestrationSchedule,
    /// Adapters that turn each step into a concrete command.
    pub adapters: &'a AdapterRegistry,
    /// The locally-installed tools; a step whose tool is absent is skipped.
    pub assets: &'a LocalAgentAssets,
    /// The engagement's discovered context, passed to each adapter.
    pub engagement: &'a EngagementContext,
    /// Operator-supplied extra arguments applied to every invocation.
    pub operator_args: &'a [String],
    /// The egress gate for this run.
    pub mode: NetworkMode,
    /// Optional egress scope enforcement: when set, a step whose resolved
    /// arguments carry an out-of-scope network target is refused before it
    /// spawns (see [`crate::scope`]).
    pub scope: Option<&'a ScopePolicy>,
    /// Optional secret store: when set, `${secret:NAME}` references in a
    /// step's arguments are resolved to plaintext just before spawning, and
    /// any secret value echoed in the tool's output is redacted before the
    /// outcome is recorded (see [`crate::secrets`]).
    pub secrets: Option<&'a SecretStore>,
    /// Optional structured-event sink: when set, the runtime emits
    /// stage/step lifecycle events as the run progresses (see
    /// [`crate::observability`]).
    pub events: Option<&'a dyn EventSink>,
    /// Optional active-tool gate: when set, a step whose tool is not
    /// authorized for the engagement is refused before it spawns, failing
    /// closed (see [`crate::tool_gate`]).
    pub gate: Option<&'a ToolGate>,
}

impl<'a> RunInputs<'a> {
    /// Convenience constructor for a run with no scope or secret guards.
    #[must_use]
    pub const fn new(
        schedule: &'a OrchestrationSchedule,
        adapters: &'a AdapterRegistry,
        assets: &'a LocalAgentAssets,
        engagement: &'a EngagementContext,
        operator_args: &'a [String],
        mode: NetworkMode,
    ) -> Self {
        Self {
            schedule,
            adapters,
            assets,
            engagement,
            operator_args,
            mode,
            scope: None,
            secrets: None,
            events: None,
            gate: None,
        }
    }

    /// Adds egress scope enforcement.
    #[must_use]
    pub const fn with_scope(mut self, scope: &'a ScopePolicy) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Adds secret resolution and output redaction.
    #[must_use]
    pub const fn with_secrets(mut self, secrets: &'a SecretStore) -> Self {
        self.secrets = Some(secrets);
        self
    }

    /// Adds a structured-event sink for live progress reporting.
    #[must_use]
    pub const fn with_events(mut self, events: &'a dyn EventSink) -> Self {
        self.events = Some(events);
        self
    }

    /// Adds an active-tool gate: unauthorized tools are refused before spawn.
    #[must_use]
    pub const fn with_gate(mut self, gate: &'a ToolGate) -> Self {
        self.gate = Some(gate);
        self
    }
}

/// Runtime controls layered on top of a plain run: cancellation, a mid-run
/// authorization guard, an optional checkpoint file, and an optional live
/// [`RunController`] (pause/resume/cancel/rate).
struct RunControl<'c> {
    cancel: &'c AtomicBool,
    still_authorized: &'c (dyn Fn() -> bool + Sync),
    checkpoint: Option<&'c Path>,
    controller: Option<&'c RunController>,
}

/// How long a paused worker sleeps between checks for resume/cancel.
const PAUSE_POLL_INTERVAL: Duration = Duration::from_millis(50);

impl RunControl<'_> {
    /// `true` when the run must stop launching new steps: an explicit cancel,
    /// a failed authorization re-check, or a live controller cancellation.
    fn should_stop(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
            || !(self.still_authorized)()
            || self.controller.is_some_and(RunController::is_cancelled)
    }

    /// Blocks while the live controller is paused, returning as soon as it is
    /// resumed or the run must stop. A no-op without a controller.
    fn wait_while_paused(&self) {
        if let Some(controller) = self.controller {
            while controller.is_paused() && !self.should_stop() {
                std::thread::sleep(PAUSE_POLL_INTERVAL);
            }
        }
    }

    /// The effective minimum spawn interval: a live controller override when
    /// set, otherwise the runtime's configured `default`.
    fn effective_min_spawn_interval(&self, default: Option<Duration>) -> Option<Duration> {
        self.controller
            .map_or(default, |controller| controller.min_spawn_interval(default))
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
    /// `adapters` and the engagement's discovered context. This is the flat
    /// convenience entry point; see [`RunInputs`] for the bundled form used
    /// by the cancellable / resumable variants.
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
        let inputs = RunInputs::new(schedule, adapters, assets, engagement, operator_args, mode);
        let never_cancel = AtomicBool::new(false);
        let always = || true;
        self.execute(
            &inputs,
            &RunControl {
                cancel: &never_cancel,
                still_authorized: &always,
                checkpoint: None,
                controller: None,
            },
        )
    }

    /// Like [`run`](Self::run) but stops launching new steps once `cancel`
    /// is set (already-running tools are allowed to finish).
    #[must_use]
    pub fn run_with_cancel(
        &self,
        inputs: &RunInputs,
        cancel: &AtomicBool,
    ) -> Vec<TaskExecutionOutcome> {
        let always = || true;
        self.execute(
            inputs,
            &RunControl {
                cancel,
                still_authorized: &always,
                checkpoint: None,
                controller: None,
            },
        )
    }

    /// Like [`run`](Self::run) but driven by a live [`RunController`]: the run
    /// can be paused (in-flight tools finish, no new steps launch), resumed,
    /// cancelled, or have its spawn rate adjusted while it runs.
    #[must_use]
    pub fn run_controlled(
        &self,
        inputs: &RunInputs,
        controller: &RunController,
    ) -> Vec<TaskExecutionOutcome> {
        let never_cancel = AtomicBool::new(false);
        let always = || true;
        self.execute(
            inputs,
            &RunControl {
                cancel: &never_cancel,
                still_authorized: &always,
                checkpoint: None,
                controller: Some(controller),
            },
        )
    }

    /// Like [`run`](Self::run) but stops launching new steps once
    /// `still_authorized` returns `false` — the hook for a mid-run
    /// time-window / authorization re-check.
    #[must_use]
    pub fn run_guarded(
        &self,
        inputs: &RunInputs,
        still_authorized: &(dyn Fn() -> bool + Sync),
    ) -> Vec<TaskExecutionOutcome> {
        let never_cancel = AtomicBool::new(false);
        self.execute(
            inputs,
            &RunControl {
                cancel: &never_cancel,
                still_authorized,
                checkpoint: None,
                controller: None,
            },
        )
    }

    /// Like [`run`](Self::run) but durable: `(target, tool)` pairs recorded
    /// in `checkpoint_path` from a previous run are skipped, and each newly
    /// completed step is appended, so an interrupted engagement resumes
    /// without re-running finished work. A missing or malformed checkpoint is
    /// treated as empty.
    #[must_use]
    pub fn run_resumable(
        &self,
        inputs: &RunInputs,
        checkpoint_path: &Path,
    ) -> Vec<TaskExecutionOutcome> {
        let never_cancel = AtomicBool::new(false);
        let always = || true;
        self.execute(
            inputs,
            &RunControl {
                cancel: &never_cancel,
                still_authorized: &always,
                checkpoint: Some(checkpoint_path),
                controller: None,
            },
        )
    }

    fn execute(&self, inputs: &RunInputs, control: &RunControl) -> Vec<TaskExecutionOutcome> {
        let steps: Vec<_> = inputs.schedule.iter().collect();
        let already_done = control.checkpoint.map(load_checkpoint).unwrap_or_default();
        let results: Mutex<Vec<Option<TaskExecutionOutcome>>> =
            Mutex::new((0..steps.len()).map(|_| None).collect());
        let last_spawn: Mutex<Option<Instant>> = Mutex::new(None);
        let checkpoint = control
            .checkpoint
            .map(|path| Mutex::new(open_checkpoint(path)));
        let workers = self.config.max_concurrency.max(1);

        // Class barrier: one class at a time, parallel only within a class.
        for class in CLASS_ORDER {
            if control.should_stop() {
                break;
            }
            let indices: Vec<usize> = (0..steps.len())
                .filter(|&i| steps[i].execution_class == class)
                .collect();
            if indices.is_empty() {
                continue;
            }
            emit_stage_started(inputs.events, class, indices.len());
            let queue = Mutex::new(indices.into_iter());
            let worker_count = workers.min(steps.len().max(1));
            std::thread::scope(|scope| {
                for _ in 0..worker_count {
                    scope.spawn(|| {
                        loop {
                            // Live control: block while paused, then bail if the
                            // run was cancelled (or lost authorization).
                            control.wait_while_paused();
                            if control.should_stop() {
                                break;
                            }
                            let Some(index) = queue.lock().expect("queue poisoned").next() else {
                                break;
                            };
                            let step = steps[index];
                            if already_done.contains(&(step.target_id.clone(), step.tool.clone())) {
                                continue;
                            }
                            // Active-tool gate: refuse unauthorized tools before spawn.
                            if refuse_if_gated(inputs, step, index, &results, checkpoint.as_ref()) {
                                continue;
                            }
                            let Some(tool) = inputs.assets.tool(&step.tool) else {
                                continue;
                            };
                            self.rate_limit(&last_spawn, control);
                            let ctx = InvocationContext {
                                target_id: &step.target_id,
                                network_address: step.network_address.as_deref(),
                                intensity: step.intensity,
                                operator_args: inputs.operator_args,
                                engagement: inputs.engagement,
                            };
                            let invocation = inputs.adapters.invocation_for(step, &ctx);
                            emit(
                                inputs.events,
                                &EngagementEvent::StepStarted {
                                    target: step.target_id.clone(),
                                    tool: step.tool.clone(),
                                },
                            );
                            let result = match preflight(inputs, &invocation.argv) {
                                Ok(argv) => {
                                    let mut result = run_external_tool(
                                        tool,
                                        &argv,
                                        self.config.per_tool_timeout,
                                        inputs.mode,
                                    );
                                    redact_output(inputs.secrets, &mut result);
                                    result
                                }
                                Err(refusal) => Err(refusal),
                            };
                            emit_step_result(inputs.events, &step.target_id, &step.tool, &result);
                            let outcome = TaskExecutionOutcome {
                                target_id: step.target_id.clone(),
                                tool: step.tool.clone(),
                                result,
                            };
                            if let Some(writer) = &checkpoint {
                                record_completed(writer, &step.target_id, &step.tool);
                            }
                            results.lock().expect("results poisoned")[index] = Some(outcome);
                        }
                    });
                }
            });

            emit_stage_completed(inputs.events, &results, &steps, class);
        }

        collect_ordered(results, &steps)
    }

    /// Enforces the effective minimum interval between spawns by holding the
    /// spacing lock while it sleeps out any remaining interval, then stamping
    /// the spawn time. The interval is a live [`RunController`] override when
    /// set, otherwise the runtime's configured `min_spawn_interval`.
    fn rate_limit(&self, last_spawn: &Mutex<Option<Instant>>, control: &RunControl) {
        let Some(interval) = control.effective_min_spawn_interval(self.config.min_spawn_interval)
        else {
            return;
        };
        let mut guard = last_spawn.lock().expect("spawn clock poisoned");
        if let Some(previous) = *guard {
            let elapsed = previous.elapsed();
            if elapsed < interval {
                std::thread::sleep(interval.saturating_sub(elapsed));
            }
        }
        *guard = Some(Instant::now());
    }
}

/// Applies the pre-spawn guards to a step's argv: resolves `${secret:NAME}`
/// references, then enforces egress scope on the resolved argv. Returns the
/// argv to run, or a [`ToolExecutionError::Refused`] (failing closed) if a
/// reference is unresolved or a target is out of scope.
fn preflight(inputs: &RunInputs, argv: &[String]) -> Result<Vec<String>, ToolExecutionError> {
    let resolved = match inputs.secrets {
        Some(secrets) => secrets
            .resolve_args(argv)
            .map_err(|error| ToolExecutionError::Refused(error.to_string()))?,
        None => argv.to_vec(),
    };
    if let Some(scope) = inputs.scope {
        scope
            .enforce_args(&resolved)
            .map_err(|violation| ToolExecutionError::Refused(violation.to_string()))?;
    }
    Ok(resolved)
}

/// Applies the active-tool gate to `step`. When the gate denies the tool,
/// records the refusal — emits the start/refused lifecycle events,
/// checkpoints the step, stores the refused outcome — and returns `true` so
/// the worker skips it. Returns `false` (and does nothing) when there is no
/// gate or the tool is allowed. Factored out so the worker loop stays short.
fn refuse_if_gated(
    inputs: &RunInputs,
    step: &crate::orchestrator::OrchestrationStep,
    index: usize,
    results: &Mutex<Vec<Option<TaskExecutionOutcome>>>,
    checkpoint: Option<&Mutex<Option<std::fs::File>>>,
) -> bool {
    let Some(gate) = inputs.gate else {
        return false;
    };
    let GateDecision::Denied(reason) = gate.decision(&step.tool) else {
        return false;
    };
    emit(
        inputs.events,
        &EngagementEvent::StepStarted {
            target: step.target_id.clone(),
            tool: step.tool.clone(),
        },
    );
    let result = Err(ToolExecutionError::Refused(reason));
    emit_step_result(inputs.events, &step.target_id, &step.tool, &result);
    if let Some(writer) = checkpoint {
        record_completed(writer, &step.target_id, &step.tool);
    }
    results.lock().expect("results poisoned")[index] = Some(TaskExecutionOutcome {
        target_id: step.target_id.clone(),
        tool: step.tool.clone(),
        result,
    });
    true
}

/// Emits a `StageStarted` event for `class` with its step count.
fn emit_stage_started(sink: Option<&dyn EventSink>, class: ExecutionClass, steps: usize) {
    emit(
        sink,
        &EngagementEvent::StageStarted {
            class: format!("{class:?}"),
            steps,
        },
    );
}

/// Emits a `StageCompleted` event tallying the outcomes recorded for `class`.
fn emit_stage_completed(
    sink: Option<&dyn EventSink>,
    results: &Mutex<Vec<Option<TaskExecutionOutcome>>>,
    steps: &[&crate::orchestrator::OrchestrationStep],
    class: ExecutionClass,
) {
    if sink.is_none() {
        return;
    }
    let guard = results.lock().expect("results poisoned");
    let (mut completed, mut failed) = (0usize, 0usize);
    for (index, step) in steps.iter().enumerate() {
        if step.execution_class != class {
            continue;
        }
        match guard[index].as_ref().map(|outcome| outcome.result.is_ok()) {
            Some(true) => completed += 1,
            Some(false) => failed += 1,
            None => {}
        }
    }
    drop(guard);
    emit(
        sink,
        &EngagementEvent::StageCompleted {
            class: format!("{class:?}"),
            completed,
            failed,
        },
    );
}

/// Drains the per-index results into execution order: class-grouped
/// (least-invasive first), stable within a class — deterministic regardless
/// of input order or which worker finished first.
fn collect_ordered(
    results: Mutex<Vec<Option<TaskExecutionOutcome>>>,
    steps: &[&crate::orchestrator::OrchestrationStep],
) -> Vec<TaskExecutionOutcome> {
    let mut filled = results.into_inner().expect("results poisoned");
    let mut ordered = Vec::with_capacity(filled.len());
    for class in CLASS_ORDER {
        for (index, step) in steps.iter().enumerate() {
            if step.execution_class == class {
                if let Some(outcome) = filled[index].take() {
                    ordered.push(outcome);
                }
            }
        }
    }
    ordered
}

/// Emits an event to the sink, if one is configured.
fn emit(sink: Option<&dyn EventSink>, event: &EngagementEvent) {
    if let Some(sink) = sink {
        sink.emit(event);
    }
}

/// Emits the terminal event for a step from its result: completed, refused
/// (a pre-spawn guard), or failed (any other execution error).
fn emit_step_result(
    sink: Option<&dyn EventSink>,
    target: &str,
    tool: &str,
    result: &Result<ToolExecutionReport, ToolExecutionError>,
) {
    let Some(sink) = sink else {
        return;
    };
    let event = match result {
        Ok(report) => EngagementEvent::StepCompleted {
            target: target.to_string(),
            tool: tool.to_string(),
            exit_code: report.exit_code,
            duration_ms: u64::try_from(report.duration.as_millis()).unwrap_or(u64::MAX),
        },
        Err(ToolExecutionError::Refused(reason)) => EngagementEvent::StepRefused {
            target: target.to_string(),
            tool: tool.to_string(),
            reason: reason.clone(),
        },
        Err(other) => EngagementEvent::StepFailed {
            target: target.to_string(),
            tool: tool.to_string(),
            error: other.to_string(),
        },
    };
    sink.emit(&event);
}

/// Redacts any configured secret value that leaked into the tool's captured
/// output, before the outcome is recorded.
fn redact_output(
    secrets: Option<&SecretStore>,
    result: &mut Result<ToolExecutionReport, ToolExecutionError>,
) {
    if let (Some(secrets), Ok(report)) = (secrets, result.as_mut()) {
        report.stdout = secrets.redact(&report.stdout);
        report.stderr = secrets.redact(&report.stderr);
    }
}

/// Reads the `(target, tool)` pairs a prior run recorded. A missing or
/// malformed file yields an empty set — resume never fails a run.
fn load_checkpoint(path: &Path) -> HashSet<(String, String)> {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    contents
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, '\t');
            Some((parts.next()?.to_string(), parts.next()?.to_string()))
        })
        .collect()
}

/// Opens (creating if needed) the checkpoint file for appending.
fn open_checkpoint(path: &Path) -> Option<std::fs::File> {
    OpenOptions::new().create(true).append(true).open(path).ok()
}

/// Appends one completed `(target, tool)` pair to the checkpoint. Best
/// effort: a write failure never aborts the run.
fn record_completed(writer: &Mutex<Option<std::fs::File>>, target: &str, tool: &str) {
    if let Ok(mut guard) = writer.lock() {
        if let Some(file) = guard.as_mut() {
            let _ = writeln!(file, "{target}\t{tool}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrity::IntegrityStatus;
    use crate::local_assets::LocalTool;
    use crate::model::TestIntensity;
    use crate::orchestrator::OrchestrationStep;
    use crate::registry::ToolDefinition;
    use crate::secrets::Secret;
    use std::path::PathBuf;
    use std::time::Duration;

    fn tool(name: &str, path: &str, class: ExecutionClass) -> LocalTool {
        LocalTool {
            definition: ToolDefinition {
                name: name.to_string(),
                version: "not-detected".to_string(),
                signed: false,
                vulnerability_reviewed: false,
                egress_policy: vec!["offline-local-only".to_string()],
                execution_class: class,
            },
            built_in: false,
            executable: Some(PathBuf::from(path)),
            integrity: IntegrityStatus::Unpinned,
        }
    }

    fn assets(tools: Vec<LocalTool>) -> LocalAgentAssets {
        LocalAgentAssets {
            skills: Vec::new(),
            tools,
        }
    }

    fn step(seq: usize, target: &str, tool: &str, class: ExecutionClass) -> OrchestrationStep {
        OrchestrationStep {
            sequence: seq,
            target_id: target.to_string(),
            tool: tool.to_string(),
            execution_class: class,
            intensity: TestIntensity::Standard,
            network_address: None,
        }
    }

    fn schedule(steps: Vec<OrchestrationStep>) -> OrchestrationSchedule {
        OrchestrationSchedule { steps }
    }

    fn inputs<'a>(
        sched: &'a OrchestrationSchedule,
        adapters: &'a AdapterRegistry,
        asset: &'a LocalAgentAssets,
        eng: &'a EngagementContext,
        args: &'a [String],
    ) -> RunInputs<'a> {
        RunInputs::new(sched, adapters, asset, eng, args, NetworkMode::Online)
    }

    #[test]
    fn config_defaults_are_sane() {
        let runtime = ExecutionRuntime::default();
        assert_eq!(runtime.config().max_concurrency, 4);
        assert_eq!(runtime.config().per_tool_timeout, DEFAULT_TIMEOUT);
        assert!(runtime.config().min_spawn_interval.is_none());
    }

    #[test]
    fn empty_schedule_yields_no_outcomes() {
        let outcomes = ExecutionRuntime::default().run(
            &OrchestrationSchedule::default(),
            &AdapterRegistry::with_defaults(),
            &assets(Vec::new()),
            &EngagementContext::new(),
            &[],
            NetworkMode::Offline,
        );
        assert!(outcomes.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn deterministic_order_and_class_barrier_under_concurrency() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let asset = assets(vec![
            tool("s", "/bin/true", ExecutionClass::StaticLocalAnalysis),
            tool("n", "/bin/true", ExecutionClass::ActiveNetwork),
            tool("x", "/bin/true", ExecutionClass::ActiveExploitation),
        ]);
        // Declared out of class order; result must be static -> net -> exploit
        // and stable across the many worker threads.
        let sched = schedule(vec![
            step(1, "a", "x", ExecutionClass::ActiveExploitation),
            step(2, "b", "n", ExecutionClass::ActiveNetwork),
            step(3, "c", "s", ExecutionClass::StaticLocalAnalysis),
            step(4, "d", "n", ExecutionClass::ActiveNetwork),
            step(5, "e", "s", ExecutionClass::StaticLocalAnalysis),
        ]);
        let adapters = AdapterRegistry::with_defaults();
        let eng = EngagementContext::new();
        let runtime = ExecutionRuntime::new(RuntimeConfig {
            max_concurrency: 8,
            ..RuntimeConfig::default()
        });
        let outcomes = runtime.run(&sched, &adapters, &asset, &eng, &[], NetworkMode::Online);
        let tools: Vec<&str> = outcomes.iter().map(|o| o.tool.as_str()).collect();
        assert_eq!(tools, vec!["s", "s", "n", "n", "x"]);
    }

    #[test]
    fn cancelled_run_launches_nothing() {
        let asset = assets(vec![tool(
            "n",
            "/nonexistent/n",
            ExecutionClass::ActiveNetwork,
        )]);
        let sched = schedule(vec![step(1, "a", "n", ExecutionClass::ActiveNetwork)]);
        let adapters = AdapterRegistry::with_defaults();
        let eng = EngagementContext::new();
        let args: Vec<String> = Vec::new();
        let ins = inputs(&sched, &adapters, &asset, &eng, &args);
        let cancel = AtomicBool::new(true);
        let outcomes = ExecutionRuntime::default().run_with_cancel(&ins, &cancel);
        assert!(outcomes.is_empty());
    }

    #[test]
    fn controller_cancel_launches_nothing() {
        let asset = assets(vec![tool(
            "n",
            "/nonexistent/n",
            ExecutionClass::ActiveNetwork,
        )]);
        let sched = schedule(vec![step(1, "a", "n", ExecutionClass::ActiveNetwork)]);
        let adapters = AdapterRegistry::with_defaults();
        let eng = EngagementContext::new();
        let args: Vec<String> = Vec::new();
        let ins = inputs(&sched, &adapters, &asset, &eng, &args);
        let controller = RunController::new();
        controller.cancel();
        let outcomes = ExecutionRuntime::default().run_controlled(&ins, &controller);
        assert!(outcomes.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn paused_run_resumes_and_completes() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let asset = assets(vec![tool("n", "/bin/true", ExecutionClass::ActiveNetwork)]);
        let sched = schedule(vec![step(1, "a", "n", ExecutionClass::ActiveNetwork)]);
        let adapters = AdapterRegistry::with_defaults();
        let eng = EngagementContext::new();
        let args: Vec<String> = Vec::new();
        let ins = inputs(&sched, &adapters, &asset, &eng, &args);
        let controller = RunController::new();
        controller.pause();
        // A helper resumes shortly after the run starts (and blocks on pause);
        // the run must then complete its one step. Deterministic: the run
        // cannot finish until resume is observed, and resume always arrives.
        let outcomes = std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                controller.resume();
            });
            ExecutionRuntime::default().run_controlled(&ins, &controller)
        });
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].result.is_ok());
    }

    #[test]
    fn unauthorized_guard_launches_nothing() {
        let asset = assets(vec![tool(
            "n",
            "/nonexistent/n",
            ExecutionClass::ActiveNetwork,
        )]);
        let sched = schedule(vec![step(1, "a", "n", ExecutionClass::ActiveNetwork)]);
        let adapters = AdapterRegistry::with_defaults();
        let eng = EngagementContext::new();
        let args: Vec<String> = Vec::new();
        let ins = inputs(&sched, &adapters, &asset, &eng, &args);
        let deny = || false;
        let outcomes = ExecutionRuntime::default().run_guarded(&ins, &deny);
        assert!(outcomes.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn resume_skips_already_completed_steps() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let dir = std::env::temp_dir();
        let checkpoint = dir.join(format!("sa-runtime-ckpt-{}", std::process::id()));
        let _ = std::fs::remove_file(&checkpoint);

        let asset = assets(vec![tool("n", "/bin/true", ExecutionClass::ActiveNetwork)]);
        let sched = schedule(vec![step(1, "a", "n", ExecutionClass::ActiveNetwork)]);
        let adapters = AdapterRegistry::with_defaults();
        let eng = EngagementContext::new();
        let args: Vec<String> = Vec::new();
        let ins = inputs(&sched, &adapters, &asset, &eng, &args);
        let runtime = ExecutionRuntime::default();

        let first = runtime.run_resumable(&ins, &checkpoint);
        assert_eq!(first.len(), 1);
        // Second run sees the checkpoint and skips the completed step.
        let second = runtime.run_resumable(&ins, &checkpoint);
        assert!(second.is_empty());

        let _ = std::fs::remove_file(&checkpoint);
    }

    #[test]
    fn unknown_tool_is_skipped() {
        let asset = assets(vec![tool(
            "known",
            "/nonexistent/known",
            ExecutionClass::ActiveNetwork,
        )]);
        let sched = schedule(vec![
            step(1, "a", "known", ExecutionClass::ActiveNetwork),
            step(2, "b", "missing", ExecutionClass::ActiveNetwork),
        ]);
        let adapters = AdapterRegistry::with_defaults();
        let eng = EngagementContext::new();
        let outcomes = ExecutionRuntime::default().run(
            &sched,
            &adapters,
            &asset,
            &eng,
            &[],
            NetworkMode::Online,
        );
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].tool, "known");
    }

    fn secret_ref(name: &str) -> String {
        format!("${{secret:{name}}}")
    }

    #[test]
    #[cfg(unix)]
    fn out_of_scope_target_is_refused_before_spawn() {
        let asset = assets(vec![tool(
            "nmap",
            "/bin/true",
            ExecutionClass::ActiveNetwork,
        )]);
        let mut refused_step = step(1, "t", "nmap", ExecutionClass::ActiveNetwork);
        refused_step.network_address = Some("10.9.9.9".to_string());
        let sched = schedule(vec![refused_step]);
        let adapters = AdapterRegistry::with_defaults();
        let eng = EngagementContext::new();
        let args: Vec<String> = Vec::new();
        let policy = ScopePolicy::from_targets(&["10.0.0.0/24".to_string()]);
        let ins = inputs(&sched, &adapters, &asset, &eng, &args).with_scope(&policy);

        let outcomes = ExecutionRuntime::default().run_with_cancel(&ins, &AtomicBool::new(false));
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(
            outcomes[0].result,
            Err(ToolExecutionError::Refused(_)),
        ));
    }

    #[test]
    fn unauthorized_tool_is_refused_before_spawn() {
        // 'sqlmap' is scheduled and installed, but is not on the engagement
        // allow-list, so the gate refuses it before it can spawn.
        let asset = assets(vec![tool(
            "sqlmap",
            "/nonexistent/sqlmap",
            ExecutionClass::ActiveNetwork,
        )]);
        let sched = schedule(vec![step(1, "t", "sqlmap", ExecutionClass::ActiveNetwork)]);
        let adapters = AdapterRegistry::with_defaults();
        let eng = EngagementContext::new();
        let args: Vec<String> = Vec::new();
        let gate = ToolGate::allow_only(["nmap"]);
        let ins = inputs(&sched, &adapters, &asset, &eng, &args).with_gate(&gate);

        let outcomes = ExecutionRuntime::default().run_with_cancel(&ins, &AtomicBool::new(false));
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(
            outcomes[0].result,
            Err(ToolExecutionError::Refused(_)),
        ));
    }

    #[test]
    #[cfg(unix)]
    fn allow_listed_tool_is_permitted_to_run() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let asset = assets(vec![tool(
            "nmap",
            "/bin/true",
            ExecutionClass::ActiveNetwork,
        )]);
        let sched = schedule(vec![step(1, "t", "nmap", ExecutionClass::ActiveNetwork)]);
        let adapters = AdapterRegistry::with_defaults();
        let eng = EngagementContext::new();
        let args: Vec<String> = Vec::new();
        let gate = ToolGate::allow_only(["nmap", "gobuster"]);
        let ins = inputs(&sched, &adapters, &asset, &eng, &args).with_gate(&gate);

        let outcomes = ExecutionRuntime::default().run_with_cancel(&ins, &AtomicBool::new(false));
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].result.is_ok());
    }

    #[test]
    fn preflight_resolves_secrets_and_fails_closed_on_unknown() {
        let sched = schedule(Vec::new());
        let adapters = AdapterRegistry::with_defaults();
        let asset = assets(Vec::new());
        let eng = EngagementContext::new();
        let args: Vec<String> = Vec::new();
        let mut store = SecretStore::new();
        store.insert("pw", Secret::new("s3cret"));
        let ins = inputs(&sched, &adapters, &asset, &eng, &args).with_secrets(&store);

        let resolved = preflight(&ins, &[format!("--pw={}", secret_ref("pw"))]).expect("resolves");
        assert_eq!(resolved[0], "--pw=s3cret");

        let refused = preflight(&ins, &[secret_ref("missing")]);
        assert!(matches!(refused, Err(ToolExecutionError::Refused(_))));
    }

    #[test]
    #[cfg(unix)]
    fn runtime_emits_lifecycle_events() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let asset = assets(vec![tool("n", "/bin/true", ExecutionClass::ActiveNetwork)]);
        let sched = schedule(vec![step(1, "a", "n", ExecutionClass::ActiveNetwork)]);
        let adapters = AdapterRegistry::with_defaults();
        let eng = EngagementContext::new();
        let args: Vec<String> = Vec::new();
        let sink = crate::observability::CollectingSink::new();
        let ins = inputs(&sched, &adapters, &asset, &eng, &args).with_events(&sink);

        let _ = ExecutionRuntime::default().run_with_cancel(&ins, &AtomicBool::new(false));

        let events = sink.events();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, EngagementEvent::StageStarted { .. }))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, EngagementEvent::StepStarted { .. }))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, EngagementEvent::StepCompleted { .. }))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, EngagementEvent::StageCompleted { completed: 1, .. }))
        );
    }

    #[test]
    fn redact_output_masks_secrets_in_the_report() {
        let mut store = SecretStore::new();
        store.insert("pw", Secret::new("s3cret"));
        let mut result: Result<ToolExecutionReport, ToolExecutionError> = Ok(ToolExecutionReport {
            tool: "x".to_string(),
            arguments: Vec::new(),
            exit_code: Some(0),
            stdout: "auth ok using s3cret".to_string(),
            stderr: String::new(),
            duration: Duration::from_millis(1),
        });
        redact_output(Some(&store), &mut result);
        let report = result.expect("ok");
        assert!(!report.stdout.contains("s3cret"));
        assert!(report.stdout.contains("***"));
    }
}
