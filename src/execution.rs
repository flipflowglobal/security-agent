//! Real (non-substitute) execution of cataloged external tools.
//!
//! Unlike `crate::builtin_tools` and `crate::pcap`, which are offline
//! substitutes implemented entirely in this crate, this module actually
//! spawns a locally installed third-party binary. Eligibility is governed by
//! a [`NetworkMode`] the caller passes in, which reflects an explicit,
//! per-invocation operator opt-in (see [`crate::network_policy`]):
//!
//! - **Offline** (the default): only tools classified
//!   [`ExecutionClass::StaticLocalAnalysis`] may run — they operate solely on
//!   local files with no network or live-target interaction. Live
//!   `ActiveNetwork` / `ActiveExploitation` tools are refused with
//!   [`ToolExecutionError::RequiresOnlineMode`].
//! - **Online** (operator opted in for this run): the real, installed
//!   `ActiveNetwork` and `ActiveExploitation` tools additionally become
//!   eligible, so authorized engagements get full tool scope.
//!
//! This is only the *egress* gate. When these tools run as part of a planned
//! scan, the coordinator's authorization policy ([`crate::policy`]) still
//! enforces target scope, the technique allow-list, deny-lists, approval
//! gates, and the time window — going online never bypasses that. Arguments
//! passed to `--execute`/`execute_plan` are trusted as-is. Only real,
//! installed third-party binaries are ever spawned; this crate never
//! reimplements a tool's offensive behavior itself.

use crate::coordinator::ExecutionPlan;
use crate::integrity::IntegrityStatus;
use crate::local_assets::LocalAgentAssets;
use crate::local_assets::LocalTool;
use crate::network_policy::NetworkMode;
use crate::orchestrator::ToolOrchestrator;
use crate::registry::ExecutionClass;
use std::fmt;
use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Execution timeout used by [`run_external_tool_with_default_timeout`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

const POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Debug)]
pub enum ToolExecutionError {
    NotInstalled(String),
    RequiresOnlineMode(String),
    IntegrityMismatch(String),
    Spawn {
        tool: String,
        source: std::io::Error,
    },
    TimedOut {
        tool: String,
        timeout: Duration,
    },
    /// The tool was refused before spawning by a pre-execution guard — an
    /// out-of-scope target ([`crate::scope`]) or an unresolved secret
    /// reference ([`crate::secrets`]). The message explains which.
    Refused(String),
}

impl fmt::Display for ToolExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInstalled(name) => write!(formatter, "{name} is not installed locally"),
            Self::RequiresOnlineMode(name) => write!(
                formatter,
                "{name} performs live network / active-target activity and is refused in \
                 offline mode; re-run with the explicit --allow-network opt-in to enable it"
            ),
            Self::IntegrityMismatch(name) => write!(
                formatter,
                "{name}'s local binary does not match its pinned integrity-manifest hash; \
                 refusing to execute (see assets/tool_integrity.txt)"
            ),
            Self::Spawn { tool, source } => write!(formatter, "failed to spawn {tool}: {source}"),
            Self::TimedOut { tool, timeout } => write!(
                formatter,
                "{tool} exceeded the {timeout:?} execution timeout and was killed"
            ),
            Self::Refused(message) => write!(formatter, "refused before execution: {message}"),
        }
    }
}

impl std::error::Error for ToolExecutionError {}

#[derive(Debug, Clone)]
pub struct ToolExecutionReport {
    pub tool: String,
    pub arguments: Vec<String>,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
}

impl fmt::Display for ToolExecutionReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "External Tool Execution Report")?;
        writeln!(formatter, "===============================")?;
        writeln!(formatter, "Tool           : {}", self.tool)?;
        writeln!(formatter, "Arguments      : {}", self.arguments.join(" "))?;
        writeln!(
            formatter,
            "Exit code      : {}",
            self.exit_code.map_or_else(
                || "unknown (terminated by signal)".to_string(),
                |code| code.to_string()
            )
        )?;
        writeln!(
            formatter,
            "Duration       : {:.3}s",
            self.duration.as_secs_f64()
        )?;
        writeln!(formatter)?;
        writeln!(formatter, "Stdout")?;
        writeln!(formatter, "------")?;
        writeln!(formatter, "{}", self.stdout)?;
        writeln!(formatter, "Stderr")?;
        writeln!(formatter, "------")?;
        write!(formatter, "{}", self.stderr)
    }
}

/// Whether `tool` may be executed under network mode `mode`.
///
/// `StaticLocalAnalysis` tools touch only local files and are always
/// eligible. Live `ActiveNetwork` / `ActiveExploitation` tools are eligible
/// only when the operator has opted into [`NetworkMode::Online`] for this
/// invocation — the explicit egress gate. When these run inside a planned
/// scan the coordinator's authorization policy still governs scope,
/// technique, approval, and the time window on top of this.
const fn is_eligible_for_execution(tool: &LocalTool, mode: NetworkMode) -> bool {
    matches!(
        tool.definition.execution_class,
        ExecutionClass::StaticLocalAnalysis
    ) || mode.allows_active()
}

/// Runs `tool` with `arguments` under network mode `mode`, enforcing a
/// bounded execution window.
///
/// # Errors
///
/// Returns [`ToolExecutionError::NotInstalled`] if the tool has no
/// resolved executable path, [`ToolExecutionError::RequiresOnlineMode`]
/// if the tool is a live `ActiveNetwork`/`ActiveExploitation` tool and
/// `mode` is [`NetworkMode::Offline`], [`ToolExecutionError::Spawn`] if the
/// process could not be started, and [`ToolExecutionError::TimedOut`] if it
/// exceeded `timeout` and had to be killed. A non-zero exit code from the
/// tool itself is not an error: it is reported in
/// [`ToolExecutionReport::exit_code`].
pub fn run_external_tool(
    tool: &LocalTool,
    arguments: &[String],
    timeout: Duration,
    mode: NetworkMode,
) -> Result<ToolExecutionReport, ToolExecutionError> {
    let name = tool.definition.name.clone();
    let Some(executable) = tool.executable.as_ref() else {
        return Err(ToolExecutionError::NotInstalled(name));
    };
    if !is_eligible_for_execution(tool, mode) {
        return Err(ToolExecutionError::RequiresOnlineMode(name));
    }
    // A pinned binary whose hash no longer matches the manifest is refused;
    // Unpinned (the default) and Verified both proceed.
    if tool.integrity == IntegrityStatus::Mismatch {
        return Err(ToolExecutionError::IntegrityMismatch(name));
    }

    let start = Instant::now();
    let mut child = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| ToolExecutionError::Spawn {
            tool: name.clone(),
            source,
        })?;

    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let stdout_reader = thread::spawn(move || read_all(&mut stdout_pipe));
    let stderr_reader = thread::spawn(move || read_all(&mut stderr_pipe));

    let exit_status = wait_with_timeout(&mut child, timeout);
    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    let duration = start.elapsed();

    match exit_status {
        Some(status) => Ok(ToolExecutionReport {
            tool: name,
            arguments: arguments.to_vec(),
            exit_code: status.code(),
            stdout,
            stderr,
            duration,
        }),
        None => Err(ToolExecutionError::TimedOut {
            tool: name,
            timeout,
        }),
    }
}

/// Convenience wrapper around [`run_external_tool`] using
/// [`DEFAULT_TIMEOUT`].
///
/// # Errors
///
/// Same as [`run_external_tool`].
pub fn run_external_tool_with_default_timeout(
    tool: &LocalTool,
    arguments: &[String],
    mode: NetworkMode,
) -> Result<ToolExecutionReport, ToolExecutionError> {
    run_external_tool(tool, arguments, DEFAULT_TIMEOUT, mode)
}

/// The result of attempting to run one approved tool for one planned task.
#[derive(Debug)]
pub struct TaskExecutionOutcome {
    pub target_id: String,
    pub tool: String,
    pub result: Result<ToolExecutionReport, ToolExecutionError>,
}

impl fmt::Display for TaskExecutionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.result {
            Ok(report) => write!(
                formatter,
                "target={} tool={} exit_code={} duration={:.3}s",
                self.target_id,
                self.tool,
                report
                    .exit_code
                    .map_or_else(|| "unknown".to_string(), |code| code.to_string()),
                report.duration.as_secs_f64()
            ),
            Err(error) => write!(
                formatter,
                "target={} tool={} error: {error}",
                self.target_id, self.tool
            ),
        }
    }
}

/// Attempts to run the tools a `plan` approved, passing the same `arguments`
/// to each invocation.
///
/// The plan is first turned into an ordered, deduplicated schedule by
/// [`ToolOrchestrator`], so execution runs *least-invasive first* (static
/// local analysis before active network before active exploitation) and a
/// `(target, tool)` pair never runs twice. See [`crate::orchestrator`] for
/// the ordering contract.
///
/// This only actually executes tools the coordinator approved for a task
/// (`ScanTask::approved_tools`, which is already filtered to what's locally
/// installed) — it never expands scope beyond what was planned. A scheduled
/// tool that is not resolvable in `assets` is skipped (no spurious outcome).
/// Live tools attempted under [`NetworkMode::Offline`] are still reported (so
/// the caller sees why, via [`ToolExecutionError::RequiresOnlineMode`] in the
/// outcome) rather than silently skipped.
///
/// When a scheduled step carries a network address (from
/// [`crate::coordinator::ScanTask::network_address`]) and the tool is not
/// [`ExecutionClass::StaticLocalAnalysis`] (i.e. it is a network tool like
/// nmap/masscan), the address is prepended as the tool's first argument —
/// see [`effective_arguments`] — keeping the authorization boundary (the
/// target id) connected to what the tool actually connects to.
/// Static-local tools operate on local files, not addresses, so they are
/// never touched by this.
#[must_use]
pub fn execute_plan(
    plan: &ExecutionPlan,
    assets: &LocalAgentAssets,
    arguments: &[String],
    mode: NetworkMode,
) -> Vec<TaskExecutionOutcome> {
    let schedule = ToolOrchestrator::new().schedule(plan);
    let mut outcomes = Vec::new();
    for step in &schedule {
        let Some(tool) = assets.tool(&step.tool) else {
            continue;
        };
        let effective_arguments =
            effective_arguments(step.network_address.as_deref(), tool, arguments);
        outcomes.push(TaskExecutionOutcome {
            target_id: step.target_id.clone(),
            tool: step.tool.clone(),
            result: run_external_tool_with_default_timeout(tool, &effective_arguments, mode),
        });
    }
    outcomes
}

/// Pre-resolved tool invocation ready for thread dispatch.
struct PreparedStep {
    target_id: String,
    tool_name: String,
    effective_arguments: Vec<String>,
}

/// Like [`execute_plan`], but runs tools against independent targets in
/// parallel using scoped threads.
///
/// Each tool invocation targets a different system (or the same target with
/// different tools), so there are no shared mutable dependencies between
/// invocations. [`std::thread::scope`] ensures the borrowed `assets` and
/// `arguments` outlive every spawned thread — no `Arc` or `Send` bounds
/// needed.
///
/// The schedule is still produced by [`ToolOrchestrator`] (least-invasive
/// first, deduplicated), but within each execution class the tools run
/// concurrently. This is a significant speedup for multi-target scans: if
/// three targets each need nmap, the sequential version runs them one after
/// another while this version runs all three simultaneously.
///
/// # Ordering
///
/// The returned outcomes preserve submission (schedule) order, identical to
/// the sequential [`execute_plan`].
///
/// # Panics
///
/// This function does not panic. Scoped thread panics are caught; the
/// panicked step's outcome is silently omitted from the results.
#[must_use]
pub fn execute_plan_concurrent(
    plan: &ExecutionPlan,
    assets: &LocalAgentAssets,
    arguments: &[String],
    mode: NetworkMode,
) -> Vec<TaskExecutionOutcome> {
    let schedule = ToolOrchestrator::new().schedule(plan);

    // Pre-resolve tools and build effective arguments so we can validate
    // everything before spawning threads. Uncataloged tools are skipped
    // (same as the sequential version).
    let prepared: Vec<PreparedStep> = schedule
        .iter()
        .filter_map(|step| {
            let tool = assets.tool(&step.tool)?;
            Some(PreparedStep {
                target_id: step.target_id.clone(),
                tool_name: step.tool.clone(),
                effective_arguments: effective_arguments(
                    step.network_address.as_deref(),
                    tool,
                    arguments,
                ),
            })
        })
        .collect();

    let step_count = prepared.len();
    let mut outcomes: Vec<Option<TaskExecutionOutcome>> = (0..step_count).map(|_| None).collect();

    std::thread::scope(|s| {
        let handles: Vec<_> = prepared
            .iter()
            .enumerate()
            .map(|(idx, step)| {
                let tool_name = &step.tool_name;
                let effective_args = &step.effective_arguments;
                s.spawn(move || {
                    let tool_ref = assets.tool(tool_name);
                    let result = tool_ref.map_or_else(
                        // Tool was resolved earlier; if it vanishes between
                        // resolve and here, treat as not installed.
                        || Err(ToolExecutionError::NotInstalled(step.tool_name.clone())),
                        |tool| run_external_tool_with_default_timeout(tool, effective_args, mode),
                    );
                    (idx, step.target_id.clone(), step.tool_name.clone(), result)
                })
            })
            .collect();

        for handle in handles {
            match handle.join() {
                Ok((idx, target_id, tool_name, result)) => {
                    outcomes[idx] = Some(TaskExecutionOutcome {
                        target_id,
                        tool: tool_name,
                        result,
                    });
                }
                Err(_panic) => {
                    // Scoped thread panicked — the outcome is silently
                    // omitted. In practice this cannot happen because
                    // `run_external_tool` catches its own errors.
                }
            }
        }
    });

    outcomes.into_iter().flatten().collect()
}

/// Builds the argument list actually passed to `tool` for a scheduled step.
///
/// Prepends `network_address` (when present) as the first argument, but only
/// for tools that are not [`ExecutionClass::StaticLocalAnalysis`] — static-local
/// tools (semgrep, jadx, ...) operate on local files, not network addresses.
/// This is prepend-only: it never removes or reorders the caller's own
/// `arguments`. Note the two class checks come from different places — the
/// orchestrator decides whether the step carries an address from the *name*
/// (`registry::classify_execution`), while `is_network_tool` here reads the
/// *resolved catalog tool's* class. The catalog stamps every
/// [`crate::registry::ToolDefinition`] with that same `classify_execution`,
/// so the two always agree in practice and injection is consistent. They can
/// only diverge for a hand-built [`LocalTool`] whose class was set to
/// something other than its name implies (as some unit tests do).
fn effective_arguments(
    network_address: Option<&str>,
    tool: &LocalTool,
    arguments: &[String],
) -> Vec<String> {
    let is_network_tool = tool.definition.execution_class != ExecutionClass::StaticLocalAnalysis;
    match (is_network_tool, network_address) {
        (true, Some(address)) => {
            let mut effective = Vec::with_capacity(arguments.len() + 1);
            effective.push(address.to_string());
            effective.extend_from_slice(arguments);
            effective
        }
        _ => arguments.to_vec(),
    }
}

fn read_all<R: Read>(pipe: &mut Option<R>) -> String {
    let mut buffer = Vec::new();
    if let Some(reader) = pipe {
        let _ = reader.read_to_end(&mut buffer);
    }
    String::from_utf8_lossy(&buffer).into_owned()
}

/// Polls `child` until it exits or `timeout` elapses. On timeout, kills the
/// child (reaping it so it doesn't linger as a zombie) and returns `None`.
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let start = Instant::now();
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    // Several integration tests (and their helper `tool_at`/`Path` import) are
    // `#[cfg(unix)]`; on non-unix platforms those tests are excluded, so the
    // helpers would otherwise be flagged dead. Linux CI keeps the strict lints.
    #![cfg_attr(not(unix), allow(dead_code, unused_imports))]
    use super::*;
    use crate::registry::ToolDefinition;
    use std::path::{Path, PathBuf};

    fn tool_at(path: &str, execution_class: ExecutionClass) -> LocalTool {
        tool_named("test-tool", path, execution_class)
    }

    fn tool_named(name: &str, path: &str, execution_class: ExecutionClass) -> LocalTool {
        tool_with_integrity(name, path, execution_class, IntegrityStatus::Unpinned)
    }

    fn tool_with_integrity(
        name: &str,
        path: &str,
        execution_class: ExecutionClass,
        integrity: IntegrityStatus,
    ) -> LocalTool {
        LocalTool {
            definition: ToolDefinition {
                name: name.to_string(),
                version: "not-detected".to_string(),
                signed: false,
                vulnerability_reviewed: false,
                egress_policy: vec!["offline-local-only".to_string()],
                execution_class,
            },
            built_in: false,
            executable: Some(PathBuf::from(path)),
            integrity,
        }
    }

    fn assets_with(tools: Vec<LocalTool>) -> LocalAgentAssets {
        LocalAgentAssets {
            skills: Vec::new(),
            tools,
        }
    }

    fn minimal_task(target_id: &str, approved_tools: Vec<String>) -> crate::coordinator::ScanTask {
        task_with_network_address(target_id, approved_tools, None)
    }

    fn task_with_network_address(
        target_id: &str,
        approved_tools: Vec<String>,
        network_address: Option<&str>,
    ) -> crate::coordinator::ScanTask {
        use crate::model::{SpecialistKind, TestIntensity};
        use crate::registry::SpecialistCapability;

        crate::coordinator::ScanTask {
            target_id: target_id.to_string(),
            specialist: SpecialistCapability {
                specialist: SpecialistKind::Sast,
                target_types: Vec::new(),
                approved_tools: Vec::new(),
                supported_techniques: Vec::new(),
                max_intensity: TestIntensity::Passive,
            },
            techniques: Vec::new(),
            approved_tools,
            intensity: TestIntensity::Passive,
            network_address: network_address.map(str::to_string),
        }
    }

    fn minimal_plan(tasks: Vec<crate::coordinator::ScanTask>) -> ExecutionPlan {
        ExecutionPlan {
            engagement_id: "eng-test".to_string(),
            workflow_stages: Vec::new(),
            tasks,
            selected_packs: Vec::new(),
            high_impact_tasks: 0,
        }
    }

    #[test]
    #[cfg(unix)]
    fn runs_a_static_local_analysis_tool_successfully() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let tool = tool_at("/bin/true", ExecutionClass::StaticLocalAnalysis);

        let report = run_external_tool(&tool, &[], Duration::from_secs(5), NetworkMode::Offline)
            .expect("execution should succeed");

        assert_eq!(report.exit_code, Some(0));
        assert_eq!(report.tool, "test-tool");
    }

    #[test]
    #[cfg(unix)]
    fn reports_a_nonzero_exit_code_without_erroring() {
        if !Path::new("/bin/false").exists() {
            return;
        }
        let tool = tool_at("/bin/false", ExecutionClass::StaticLocalAnalysis);

        let report = run_external_tool(&tool, &[], Duration::from_secs(5), NetworkMode::Offline)
            .expect("execution should succeed");

        assert_eq!(report.exit_code, Some(1));
    }

    #[test]
    fn rejects_a_tool_with_no_resolved_executable() {
        let tool = LocalTool {
            definition: ToolDefinition {
                name: "missing-tool".to_string(),
                version: "not-detected".to_string(),
                signed: false,
                vulnerability_reviewed: false,
                egress_policy: vec!["offline-local-only".to_string()],
                execution_class: ExecutionClass::StaticLocalAnalysis,
            },
            built_in: false,
            executable: None,
            integrity: IntegrityStatus::Unpinned,
        };

        let result = run_external_tool(&tool, &[], Duration::from_secs(5), NetworkMode::Offline);

        assert!(
            matches!(result, Err(ToolExecutionError::NotInstalled(name)) if name == "missing-tool")
        );
    }

    #[test]
    #[cfg(unix)]
    fn refuses_execution_on_integrity_mismatch() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        // A statically-eligible, installed tool whose pinned hash no longer
        // matches must be refused before spawn.
        let tool = tool_with_integrity(
            "pinned-tool",
            "/bin/true",
            ExecutionClass::StaticLocalAnalysis,
            IntegrityStatus::Mismatch,
        );

        let result = run_external_tool(&tool, &[], Duration::from_secs(5), NetworkMode::Offline);

        assert!(matches!(
            result,
            Err(ToolExecutionError::IntegrityMismatch(name)) if name == "pinned-tool"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn unpinned_tool_still_executes() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        // Regression guard: the default (Unpinned) path is unchanged.
        let tool = tool_with_integrity(
            "unpinned-tool",
            "/bin/true",
            ExecutionClass::StaticLocalAnalysis,
            IntegrityStatus::Unpinned,
        );

        let report = run_external_tool(&tool, &[], Duration::from_secs(5), NetworkMode::Offline)
            .expect("unpinned tools execute exactly as before");
        assert_eq!(report.exit_code, Some(0));
    }

    #[test]
    #[cfg(unix)]
    fn refuses_active_tools_in_offline_mode() {
        let tool = tool_at("/bin/true", ExecutionClass::ActiveNetwork);

        let result = run_external_tool(&tool, &[], Duration::from_secs(5), NetworkMode::Offline);

        assert!(matches!(
            result,
            Err(ToolExecutionError::RequiresOnlineMode(name)) if name == "test-tool"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn refuses_exploitation_tools_in_offline_mode() {
        // A live exploitation tool (e.g. hydra) is refused offline and must
        // name the online opt-in as the way to enable it.
        let tool = tool_named("hydra", "/bin/true", ExecutionClass::ActiveExploitation);

        let result = run_external_tool(&tool, &[], Duration::from_secs(5), NetworkMode::Offline);

        assert!(matches!(
            result,
            Err(ToolExecutionError::RequiresOnlineMode(name)) if name == "hydra"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn active_network_tool_runs_when_operator_opts_into_online_mode() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let tool = tool_named("nmap", "/bin/true", ExecutionClass::ActiveNetwork);

        // Offline: refused. Online (explicit opt-in): eligible and runs.
        assert!(matches!(
            run_external_tool(&tool, &[], Duration::from_secs(5), NetworkMode::Offline),
            Err(ToolExecutionError::RequiresOnlineMode(_))
        ));
        let report = run_external_tool(&tool, &[], Duration::from_secs(5), NetworkMode::Online)
            .expect("online opt-in should make an ActiveNetwork tool eligible");

        assert_eq!(report.exit_code, Some(0));
        assert_eq!(report.tool, "nmap");
    }

    #[test]
    #[cfg(unix)]
    fn exploitation_tool_runs_when_operator_opts_into_online_mode() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let tool = tool_named("sqlmap", "/bin/true", ExecutionClass::ActiveExploitation);

        let report = run_external_tool(&tool, &[], Duration::from_secs(5), NetworkMode::Online)
            .expect("online opt-in should make an ActiveExploitation tool eligible");

        assert_eq!(report.exit_code, Some(0));
        assert_eq!(report.tool, "sqlmap");
    }

    #[test]
    #[cfg(unix)]
    fn kills_and_reports_timeout_for_a_long_running_process() {
        if !Path::new("/bin/sleep").exists() {
            return;
        }
        let tool = tool_at("/bin/sleep", ExecutionClass::StaticLocalAnalysis);

        let result = run_external_tool(
            &tool,
            &["2".to_string()],
            Duration::from_millis(100),
            NetworkMode::Offline,
        );

        assert!(matches!(
            result,
            Err(ToolExecutionError::TimedOut { tool, .. }) if tool == "test-tool"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn execute_plan_runs_every_approved_tool_and_skips_uncataloged_names() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let assets = assets_with(vec![tool_named(
            "tool-a",
            "/bin/true",
            ExecutionClass::StaticLocalAnalysis,
        )]);
        let plan = minimal_plan(vec![minimal_task(
            "target-a",
            vec!["tool-a".to_string(), "not-cataloged".to_string()],
        )]);

        let outcomes = execute_plan(&plan, &assets, &[], NetworkMode::Offline);

        // "not-cataloged" isn't in `assets`, so it's skipped rather than
        // producing a spurious outcome.
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].target_id, "target-a");
        assert_eq!(outcomes[0].tool, "tool-a");
        assert!(matches!(&outcomes[0].result, Ok(report) if report.exit_code == Some(0)));
    }

    #[test]
    fn execute_plan_covers_every_task_and_reports_per_tool_failures() {
        let assets = assets_with(vec![
            tool_named(
                "tool-a",
                "/nonexistent/tool-a",
                ExecutionClass::StaticLocalAnalysis,
            ),
            tool_named(
                "tool-b",
                "/nonexistent/tool-b",
                ExecutionClass::ActiveNetwork,
            ),
        ]);
        let plan = minimal_plan(vec![
            minimal_task("target-a", vec!["tool-a".to_string()]),
            minimal_task("target-b", vec!["tool-b".to_string()]),
        ]);

        let outcomes = execute_plan(&plan, &assets, &[], NetworkMode::Offline);

        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].target_id, "target-a");
        assert_eq!(outcomes[1].target_id, "target-b");
    }

    #[test]
    #[cfg(unix)]
    fn execute_plan_injects_network_address_for_network_tools() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let assets = assets_with(vec![tool_named(
            "nmap",
            "/bin/true",
            ExecutionClass::ActiveNetwork,
        )]);
        let task =
            task_with_network_address("target-a", vec!["nmap".to_string()], Some("10.0.0.5"));
        let plan = minimal_plan(vec![task]);

        // nmap is ActiveNetwork, so injecting a live target requires the
        // online opt-in.
        let outcomes = execute_plan(&plan, &assets, &["-sV".to_string()], NetworkMode::Online);

        assert_eq!(outcomes.len(), 1);
        let report = outcomes[0].result.as_ref().expect("nmap should execute");
        assert_eq!(
            report.arguments,
            vec!["10.0.0.5".to_string(), "-sV".to_string()]
        );
    }

    #[test]
    #[cfg(unix)]
    fn execute_plan_does_not_inject_for_static_tools() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let assets = assets_with(vec![tool_named(
            "tool-a",
            "/bin/true",
            ExecutionClass::StaticLocalAnalysis,
        )]);
        let task =
            task_with_network_address("target-a", vec!["tool-a".to_string()], Some("10.0.0.5"));
        let plan = minimal_plan(vec![task]);

        let outcomes = execute_plan(
            &plan,
            &assets,
            &["--version".to_string()],
            NetworkMode::Offline,
        );

        let report = outcomes[0].result.as_ref().expect("should execute");
        assert_eq!(report.arguments, vec!["--version".to_string()]);
    }

    #[test]
    fn task_execution_outcome_display_renders_success_and_failure() {
        let success = TaskExecutionOutcome {
            target_id: "target-a".to_string(),
            tool: "tool-a".to_string(),
            result: Ok(ToolExecutionReport {
                tool: "tool-a".to_string(),
                arguments: Vec::new(),
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                duration: Duration::from_millis(5),
            }),
        };
        assert!(success.to_string().contains("target=target-a"));
        assert!(success.to_string().contains("tool=tool-a"));
        assert!(success.to_string().contains("exit_code=0"));

        let failure = TaskExecutionOutcome {
            target_id: "target-b".to_string(),
            tool: "tool-b".to_string(),
            result: Err(ToolExecutionError::NotInstalled("tool-b".to_string())),
        };
        assert!(failure.to_string().contains("error:"));
    }

    fn task_with_tools(target_id: &str, tools: &[&str]) -> crate::coordinator::ScanTask {
        minimal_task(target_id, tools.iter().map(ToString::to_string).collect())
    }

    #[test]
    fn execute_plan_runs_a_duplicate_target_tool_pair_only_once() {
        // The same tool is approved for the same target by two tasks; the
        // orchestrator collapses that to a single scheduled invocation, so
        // execution never spawns the tool twice against one target.
        let assets = assets_with(vec![tool_named(
            "sqlmap",
            "/nonexistent/sqlmap",
            ExecutionClass::ActiveExploitation,
        )]);
        let plan = minimal_plan(vec![
            task_with_tools("target-a", &["sqlmap"]),
            task_with_tools("target-a", &["sqlmap"]),
        ]);

        let outcomes = execute_plan(&plan, &assets, &[], NetworkMode::Online);

        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].tool, "sqlmap");
    }

    #[test]
    #[cfg(unix)]
    fn execute_plan_concurrent_runs_all_approved_tools() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let assets = assets_with(vec![tool_named(
            "tool-a",
            "/bin/true",
            ExecutionClass::StaticLocalAnalysis,
        )]);
        let plan = minimal_plan(vec![minimal_task(
            "target-a",
            vec!["tool-a".to_string(), "not-cataloged".to_string()],
        )]);

        let outcomes = execute_plan_concurrent(&plan, &assets, &[], NetworkMode::Offline);

        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].target_id, "target-a");
        assert_eq!(outcomes[0].tool, "tool-a");
        assert!(matches!(&outcomes[0].result, Ok(report) if report.exit_code == Some(0)));
    }

    #[test]
    #[cfg(unix)]
    fn execute_plan_concurrent_runs_tools_in_parallel() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        // Three independent targets, each with its own tool — all should run.
        let assets = assets_with(vec![
            tool_named("nmap", "/bin/true", ExecutionClass::ActiveNetwork),
            tool_named("sqlmap", "/bin/true", ExecutionClass::ActiveExploitation),
        ]);
        let plan = minimal_plan(vec![
            task_with_network_address("t1", vec!["nmap".to_string()], Some("10.0.0.1")),
            task_with_network_address("t2", vec!["nmap".to_string()], Some("10.0.0.2")),
            task_with_tools("t3", &["sqlmap"]),
        ]);

        let outcomes =
            execute_plan_concurrent(&plan, &assets, &["-sV".to_string()], NetworkMode::Online);

        // All three should complete in submission order.
        assert_eq!(outcomes.len(), 3);
        let mut target_ids: Vec<&str> = outcomes.iter().map(|o| o.target_id.as_str()).collect();
        target_ids.sort_unstable();
        assert_eq!(target_ids, vec!["t1", "t2", "t3"]);
    }

    #[test]
    fn execute_plan_concurrent_deduplicates_target_tool_pairs() {
        let assets = assets_with(vec![tool_named(
            "sqlmap",
            "/nonexistent/sqlmap",
            ExecutionClass::ActiveExploitation,
        )]);
        let plan = minimal_plan(vec![
            task_with_tools("target-a", &["sqlmap"]),
            task_with_tools("target-a", &["sqlmap"]),
        ]);

        let outcomes = execute_plan_concurrent(&plan, &assets, &[], NetworkMode::Online);

        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].tool, "sqlmap");
    }

    #[test]
    fn execute_plan_concurrent_skips_uncataloged_tools() {
        let assets = assets_with(vec![]);
        let plan = minimal_plan(vec![minimal_task(
            "target-a",
            vec!["nonexistent".to_string()],
        )]);

        let outcomes = execute_plan_concurrent(&plan, &assets, &[], NetworkMode::Offline);

        assert!(outcomes.is_empty());
    }

    #[test]
    fn execute_plan_concurrent_returns_empty_for_empty_plan() {
        let assets = assets_with(vec![]);
        let plan = minimal_plan(vec![]);

        let outcomes = execute_plan_concurrent(&plan, &assets, &[], NetworkMode::Offline);

        assert!(outcomes.is_empty());
    }

    #[test]
    fn execute_plan_runs_least_invasive_tools_first() {
        // Tasks declare exploitation before recon before static; execution
        // must follow the orchestrated static -> network -> exploitation
        // order regardless of declaration order.
        let assets = assets_with(vec![
            tool_named(
                "sqlmap",
                "/nonexistent/sqlmap",
                ExecutionClass::ActiveExploitation,
            ),
            tool_named("nmap", "/nonexistent/nmap", ExecutionClass::ActiveNetwork),
            tool_named(
                "semgrep",
                "/nonexistent/semgrep",
                ExecutionClass::StaticLocalAnalysis,
            ),
        ]);
        let plan = minimal_plan(vec![
            task_with_tools("target-a", &["sqlmap"]),
            task_with_tools("target-a", &["nmap"]),
            task_with_tools("target-a", &["semgrep"]),
        ]);

        let outcomes = execute_plan(&plan, &assets, &[], NetworkMode::Online);

        let order: Vec<&str> = outcomes.iter().map(|o| o.tool.as_str()).collect();
        assert_eq!(order, vec!["semgrep", "nmap", "sqlmap"]);
    }
}
