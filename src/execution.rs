//! Real (non-substitute) execution of cataloged external tools.
//!
//! Unlike `crate::builtin_tools` and `crate::pcap`, which are offline
//! substitutes implemented entirely in this crate, this module actually
//! spawns a locally installed third-party binary. To keep that safe, only
//! tools classified [`ExecutionClass::StaticLocalAnalysis`] may be run
//! this way: tools that operate solely on local files, with no network or
//! live-target interaction. Tools classified `ActiveNetwork` or
//! `ActiveExploitation` (nmap, sqlmap, hydra, msfconsole, and similar) are
//! rejected here — real execution of those needs a live-target
//! confirmation/rate-limit design layered on
//! [`crate::policy::AuthorizationOutcome`], which does not exist yet.

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
    NotStaticLocalAnalysis(String),
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
            Self::NotStaticLocalAnalysis(name) => write!(
                formatter,
                "{name} is not classified as static-local-analysis; \
                 real execution is not wired up for it yet"
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

/// Runs `tool` with `arguments`, enforcing a bounded execution window.
///
/// # Errors
///
/// Returns [`ToolExecutionError::NotInstalled`] if the tool has no
/// resolved executable path, [`ToolExecutionError::NotStaticLocalAnalysis`]
/// if the tool isn't classified for direct execution,
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
    if tool.definition.execution_class != ExecutionClass::StaticLocalAnalysis {
        return Err(ToolExecutionError::NotStaticLocalAnalysis(name));
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
        LocalTool {
            definition: ToolDefinition {
                name: "test-tool".to_string(),
                version: "not-detected".to_string(),
                signed: false,
                vulnerability_reviewed: false,
                egress_policy: vec!["offline-local-only".to_string()],
                execution_class,
            },
            built_in: false,
            executable: Some(PathBuf::from(path)),
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
        };

        let result = run_external_tool(&tool, &[], Duration::from_secs(5));

        assert!(
            matches!(result, Err(ToolExecutionError::NotInstalled(name)) if name == "missing-tool")
        );
    }

    #[test]
    #[cfg(unix)]
    fn rejects_a_tool_not_classified_static_local_analysis() {
        let tool = tool_at("/bin/true", ExecutionClass::ActiveNetwork);

        let result = run_external_tool(&tool, &[], Duration::from_secs(5));

        assert!(matches!(
            result,
            Err(ToolExecutionError::NotStaticLocalAnalysis(name)) if name == "test-tool"
        ));
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
}
