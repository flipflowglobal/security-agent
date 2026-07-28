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
use crate::execution::{DEFAULT_TIMEOUT, TaskExecutionOutcome, run_external_tool};
use crate::local_assets::LocalAgentAssets;
use crate::network_policy::NetworkMode;
use crate::orchestrator::OrchestrationSchedule;
use crate::registry::ExecutionClass;
use crate::tool_adapter::{AdapterRegistry, InvocationContext};
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
}

/// Runtime controls layered on top of a plain run: cancellation, a mid-run
/// authorization guard, and an optional checkpoint file.
struct RunControl<'c> {
    cancel: &'c AtomicBool,
    still_authorized: &'c (dyn Fn() -> bool + Sync),
    checkpoint: Option<&'c Path>,
}

impl RunControl<'_> {
    fn should_stop(&self) -> bool {
        self.cancel.load(Ordering::Relaxed) || !(self.still_authorized)()
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
        let inputs = RunInputs {
            schedule,
            adapters,
            assets,
            engagement,
            operator_args,
            mode,
        };
        let never_cancel = AtomicBool::new(false);
        let always = || true;
        self.execute(
            &inputs,
            &RunControl {
                cancel: &never_cancel,
                still_authorized: &always,
                checkpoint: None,
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
            let queue = Mutex::new(indices.into_iter());
            let worker_count = workers.min(steps.len().max(1));
            std::thread::scope(|scope| {
                for _ in 0..worker_count {
                    scope.spawn(|| {
                        loop {
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
                            let Some(tool) = inputs.assets.tool(&step.tool) else {
                                continue;
                            };
                            self.rate_limit(&last_spawn);
                            let ctx = InvocationContext {
                                target_id: &step.target_id,
                                network_address: step.network_address.as_deref(),
                                intensity: step.intensity,
                                operator_args: inputs.operator_args,
                                engagement: inputs.engagement,
                            };
                            let invocation = inputs.adapters.invocation_for(step, &ctx);
                            let outcome = TaskExecutionOutcome {
                                target_id: step.target_id.clone(),
                                tool: step.tool.clone(),
                                result: run_external_tool(
                                    tool,
                                    &invocation.argv,
                                    self.config.per_tool_timeout,
                                    inputs.mode,
                                ),
                            };
                            if let Some(writer) = &checkpoint {
                                record_completed(writer, &step.target_id, &step.tool);
                            }
                            results.lock().expect("results poisoned")[index] = Some(outcome);
                        }
                    });
                }
            });
        }

        // Report in execution order: class-grouped (least-invasive first),
        // stable within a class — deterministic regardless of input order or
        // which worker finished first.
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

    /// Enforces `min_spawn_interval` between spawns by holding the spacing
    /// lock while it sleeps out any remaining interval, then stamping the
    /// spawn time.
    fn rate_limit(&self, last_spawn: &Mutex<Option<Instant>>) {
        let Some(interval) = self.config.min_spawn_interval else {
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
    use std::path::PathBuf;

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
        RunInputs {
            schedule: sched,
            adapters,
            assets: asset,
            engagement: eng,
            operator_args: args,
            mode: NetworkMode::Online,
        }
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
}
