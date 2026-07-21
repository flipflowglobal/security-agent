//! Real (non-substitute) execution of cataloged external tools.
//!
//! Unlike `crate::builtin_tools` and `crate::pcap`, which are offline
//! substitutes implemented entirely in this crate, this module actually
//! spawns a locally installed third-party binary. To keep that safe, only
//! tools classified [`ExecutionClass::StaticLocalAnalysis`] may be run
//! this way by default: tools that operate solely on local files, with no
//! network or live-target interaction. Most `ActiveNetwork` and
//! `ActiveExploitation` tools (sqlmap, hydra, msfconsole, and similar) are
//! rejected here — real execution of those needs a live-target
//! confirmation/rate-limit design layered on
//! [`crate::policy::AuthorizationOutcome`], which does not exist yet.
//!
//! `nmap` is a deliberate, explicit exception (see
//! `WIRED_DESPITE_EXECUTION_CLASS`): it has been reviewed and wired for
//! real execution the same way `StaticLocalAnalysis` tools are — gated
//! only by the coordinator's existing planning approval (scope + technique
//! allow-list) and the tool being locally installed, with no additional
//! target-confirmation, approval, or rate-limiting beyond that. Arguments
//! passed to `--execute`/`execute_plan` are trusted as-is, exactly like
//! the already-wired static tools.

use crate::coordinator::ExecutionPlan;
use crate::integrity::IntegrityStatus;
use crate::local_assets::LocalAgentAssets;
use crate::local_assets::LocalTool;
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
    NotEligibleForExecution(String),
    IntegrityMismatch(String),
    Spawn {
        tool: String,
        source: std::io::Error,
    },
    TimedOut {
        tool: String,
        timeout: Duration,
    },
}

impl fmt::Display for ToolExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInstalled(name) => write!(formatter, "{name} is not installed locally"),
            Self::NotEligibleForExecution(name) => write!(
                formatter,
                "{name} is not classified as static-local-analysis and has no explicit \
                 execution exception; real execution is not wired up for it yet"
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

/// Tools classified `ActiveNetwork`/`ActiveExploitation` that have been
/// explicitly reviewed and wired for real execution anyway. Kept to an
/// explicit, named list rather than loosening the execution-class check
/// itself, so enabling a new tool here is always a deliberate, visible
/// decision rather than an accidental side effect of some other change.
///
/// `nmap` and `masscan` are the entries today: both are approved the same
/// way the `StaticLocalAnalysis` tools are — via the coordinator's existing
/// planning gate (scope + technique allow-list) plus local installation,
/// with no additional target-confirmation, approval, or rate-limiting.
/// Arguments given to `--execute`/[`execute_plan`] are trusted as-is.
/// Because `masscan` can saturate a link at its default rate, its
/// arguments are additionally passed through the non-blocking intensity
/// advisory (see `crate::intensity_guard`) at the CLI layer, but that only
/// warns — it never gates execution here.
const WIRED_DESPITE_EXECUTION_CLASS: &[&str] = &["nmap", "masscan"];

fn is_eligible_for_execution(tool: &LocalTool) -> bool {
    tool.definition.execution_class == ExecutionClass::StaticLocalAnalysis
        || WIRED_DESPITE_EXECUTION_CLASS.contains(&tool.definition.name.as_str())
}

/// Runs `tool` with `arguments`, enforcing a bounded execution window.
///
/// # Errors
///
/// Returns [`ToolExecutionError::NotInstalled`] if the tool has no
/// resolved executable path, [`ToolExecutionError::NotEligibleForExecution`]
/// if the tool isn't classified for direct execution and has no explicit
/// exception (see `WIRED_DESPITE_EXECUTION_CLASS`),
/// [`ToolExecutionError::Spawn`] if the process could not be started, and
/// [`ToolExecutionError::TimedOut`] if it exceeded `timeout` and had to be
/// killed. A non-zero exit code from the tool itself is not an error: it
/// is reported in [`ToolExecutionReport::exit_code`].
pub fn run_external_tool(
    tool: &LocalTool,
    arguments: &[String],
    timeout: Duration,
) -> Result<ToolExecutionReport, ToolExecutionError> {
    let name = tool.definition.name.clone();
    let Some(executable) = tool.executable.as_ref() else {
        return Err(ToolExecutionError::NotInstalled(name));
    };
    if !is_eligible_for_execution(tool) {
        return Err(ToolExecutionError::NotEligibleForExecution(name));
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
) -> Result<ToolExecutionReport, ToolExecutionError> {
    run_external_tool(tool, arguments, DEFAULT_TIMEOUT)
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

/// Attempts to run every approved tool for every task in `plan`, passing
/// the same `arguments` to each invocation.
///
/// This only actually executes tools the coordinator approved for a task
/// (`ScanTask::approved_tools`, which is already filtered to what's locally
/// installed) — it never expands scope beyond what was planned. Tools not
/// eligible for direct execution (see `WIRED_DESPITE_EXECUTION_CLASS`)
/// are still attempted (so the caller sees why, via
/// [`ToolExecutionError::NotEligibleForExecution`] in the outcome) rather
/// than silently skipped.
#[must_use]
pub fn execute_plan(
    plan: &ExecutionPlan,
    assets: &LocalAgentAssets,
    arguments: &[String],
) -> Vec<TaskExecutionOutcome> {
    let mut outcomes = Vec::new();
    for task in &plan.tasks {
        for tool_name in &task.approved_tools {
            let Some(tool) = assets.tool(tool_name) else {
                continue;
            };
            outcomes.push(TaskExecutionOutcome {
                target_id: task.target_id.clone(),
                tool: tool_name.clone(),
                result: run_external_tool_with_default_timeout(tool, arguments),
            });
        }
    }
    outcomes
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

        let report = run_external_tool(&tool, &[], Duration::from_secs(5))
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

        let report = run_external_tool(&tool, &[], Duration::from_secs(5))
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

        let result = run_external_tool(&tool, &[], Duration::from_secs(5));

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

        let result = run_external_tool(&tool, &[], Duration::from_secs(5));

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

        let report = run_external_tool(&tool, &[], Duration::from_secs(5))
            .expect("unpinned tools execute exactly as before");
        assert_eq!(report.exit_code, Some(0));
    }

    #[test]
    #[cfg(unix)]
    fn rejects_a_tool_not_classified_static_local_analysis() {
        let tool = tool_at("/bin/true", ExecutionClass::ActiveNetwork);

        let result = run_external_tool(&tool, &[], Duration::from_secs(5));

        assert!(matches!(
            result,
            Err(ToolExecutionError::NotEligibleForExecution(name)) if name == "test-tool"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn rejects_other_active_network_tools_not_on_the_explicit_allowlist() {
        // Only "nmap" is on WIRED_DESPITE_EXECUTION_CLASS; a differently
        // named ActiveNetwork tool (e.g. hydra) must still be rejected.
        let tool = tool_named("hydra", "/bin/true", ExecutionClass::ActiveNetwork);

        let result = run_external_tool(&tool, &[], Duration::from_secs(5));

        assert!(matches!(
            result,
            Err(ToolExecutionError::NotEligibleForExecution(name)) if name == "hydra"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn nmap_is_eligible_for_real_execution_despite_being_active_network() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let tool = tool_named("nmap", "/bin/true", ExecutionClass::ActiveNetwork);

        let report = run_external_tool(&tool, &[], Duration::from_secs(5))
            .expect("nmap should be an explicit execution exception");

        assert_eq!(report.exit_code, Some(0));
        assert_eq!(report.tool, "nmap");
    }

    #[test]
    #[cfg(unix)]
    fn masscan_is_eligible_for_real_execution_despite_being_active_network() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let tool = tool_named("masscan", "/bin/true", ExecutionClass::ActiveNetwork);

        let report = run_external_tool(&tool, &[], Duration::from_secs(5))
            .expect("masscan should be an explicit execution exception");

        assert_eq!(report.exit_code, Some(0));
        assert_eq!(report.tool, "masscan");
    }

    #[test]
    #[cfg(unix)]
    fn kills_and_reports_timeout_for_a_long_running_process() {
        if !Path::new("/bin/sleep").exists() {
            return;
        }
        let tool = tool_at("/bin/sleep", ExecutionClass::StaticLocalAnalysis);

        let result = run_external_tool(&tool, &["2".to_string()], Duration::from_millis(100));

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

        let outcomes = execute_plan(&plan, &assets, &[]);

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

        let outcomes = execute_plan(&plan, &assets, &[]);

        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].target_id, "target-a");
        assert_eq!(outcomes[1].target_id, "target-b");
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
}
