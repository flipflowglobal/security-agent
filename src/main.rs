//! Security-Agent local runtime.

use security_agent::{
    CapabilityGraph, CapabilityRegistry, Coordinator, LocalAgentAssets, PolicyEngine,
    ToolchainPackRegistry, load_engagement_config, run_builtin_tool,
    run_external_tool_with_default_timeout,
};
use std::fmt;
use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> ExitCode {
    let assets = LocalAgentAssets::bundled();
    let mut arguments = std::env::args().skip(1);

    match arguments.next().as_deref() {
        None | Some("--offline-status") => {
            print_offline_status(&assets);
            ExitCode::SUCCESS
        }
        Some("--list-skills") => list_skills(&assets),
        Some("--show-skill") => show_skill(&assets, &mut arguments),
        Some("--list-tools") => list_tools(&assets),
        Some("--run-tool") => run_tool_command(&mut arguments),
        Some("--run-external-tool") => run_external_tool_command(&assets, &mut arguments),
        Some("--plan-scan") => plan_scan_command(&mut arguments),
        Some(command) => {
            eprintln!("unknown command: {command}");
            ExitCode::from(2)
        }
    }
}

fn print_offline_status(assets: &LocalAgentAssets) {
    let executable_tools = assets
        .tools()
        .iter()
        .filter(|tool| tool.is_installed())
        .count();
    let built_in_tools = assets.tools().iter().filter(|tool| tool.built_in).count();

    println!("network_required=false");
    println!("external_api_required=false");
    println!("embedded_skills={}", assets.skills().len());
    println!("cataloged_tool_definitions={}", assets.tools().len());
    println!("built_in_substitute_tools={built_in_tools}");
    println!("locally_executable_tools={executable_tools}");
    println!("capability_coverage={}", capability_coverage_status());
}

/// Runs `CapabilityGraph::validate_coverage` as a startup health check: does
/// every target type have at least one specialist and one toolchain pack
/// registered? Reported as `ok` or `error: <reason>` in `--offline-status`.
fn capability_coverage_status() -> String {
    match CapabilityGraph::validate_coverage(
        &CapabilityRegistry::default(),
        &ToolchainPackRegistry::default(),
    ) {
        Ok(()) => "ok".to_string(),
        Err(message) => format!("error: {message}"),
    }
}

fn list_skills(assets: &LocalAgentAssets) -> ExitCode {
    for skill in assets.skills() {
        println!("{}", skill.name);
    }
    ExitCode::SUCCESS
}

fn show_skill(assets: &LocalAgentAssets, arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(name) = arguments.next() else {
        eprintln!("missing skill name");
        return ExitCode::from(2);
    };
    let Some(skill) = assets.skill(&name) else {
        eprintln!("unknown local skill: {name}");
        return ExitCode::from(2);
    };
    print!("{}", skill.content);
    ExitCode::SUCCESS
}

fn list_tools(assets: &LocalAgentAssets) -> ExitCode {
    for tool in assets.tools() {
        if tool.built_in {
            println!("{}\tbuilt-in-substitute", tool.definition.name);
        } else if let Some(path) = &tool.executable {
            println!(
                "{}\tcataloged\texecutable={}",
                tool.definition.name,
                path.display()
            );
        } else {
            println!(
                "{}\tcataloged\texecutable=not-installed",
                tool.definition.name
            );
        }
    }
    ExitCode::SUCCESS
}

/// Parses an optional trailing `--output <path>.txt` argument pair.
/// Returns `Ok(None)` if no more arguments remain, `Ok(Some(path))` if a
/// valid `.txt` output path was given, or `Err(exit_code)` describing why
/// parsing failed.
fn parse_output_argument(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<Option<String>, ExitCode> {
    match arguments.next().as_deref() {
        None => Ok(None),
        Some("--output") => {
            let Some(path) = arguments.next() else {
                eprintln!("missing .txt output path");
                return Err(ExitCode::from(2));
            };
            if Path::new(&path)
                .extension()
                .and_then(|value| value.to_str())
                != Some("txt")
            {
                eprintln!("output path must use the .txt extension");
                return Err(ExitCode::from(2));
            }
            Ok(Some(path))
        }
        Some(argument) => {
            eprintln!("unknown tool argument: {argument}");
            Err(ExitCode::from(2))
        }
    }
}

fn run_tool_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(name) = arguments.next() else {
        eprintln!("missing tool name");
        return ExitCode::from(2);
    };
    let Some(input) = arguments.next() else {
        eprintln!("missing local input path");
        return ExitCode::from(2);
    };
    let output = match parse_output_argument(arguments) {
        Ok(output) => output,
        Err(code) => return code,
    };
    if let Some(argument) = arguments.next() {
        eprintln!("unexpected tool argument: {argument}");
        return ExitCode::from(2);
    }
    match run_builtin_tool(&name, Path::new(&input)) {
        Ok(report) => write_or_print_report(&name, report, output),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

/// Runs a real, cataloged (non-substitute) tool directly, e.g.
/// `--run-external-tool semgrep --version`. Only tools classified for
/// static local analysis (see `security_agent::registry::ExecutionClass`)
/// are wired up for direct execution; everything else is rejected with an
/// explanatory error.
fn run_external_tool_command(
    assets: &LocalAgentAssets,
    arguments: &mut impl Iterator<Item = String>,
) -> ExitCode {
    let Some(name) = arguments.next() else {
        eprintln!("missing tool name");
        return ExitCode::from(2);
    };
    let Some(tool) = assets.tool(&name) else {
        eprintln!("unknown cataloged tool: {name}");
        return ExitCode::from(2);
    };
    let tool_arguments: Vec<String> = arguments.collect();

    match run_external_tool_with_default_timeout(tool, &tool_arguments) {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

/// Reasons [`plan_scan`] can fail to produce an [`security_agent::ExecutionPlan`].
#[derive(Debug, PartialEq, Eq)]
enum PlanScanError {
    MissingConfigPath,
    UnexpectedArgument(String),
    ConfigLoad(String),
    AuthorizationDenied(String),
}

impl fmt::Display for PlanScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingConfigPath => formatter.write_str("missing engagement config file path"),
            Self::UnexpectedArgument(argument) => {
                write!(formatter, "unexpected argument: {argument}")
            }
            Self::ConfigLoad(message) => write!(formatter, "failed to load config: {message}"),
            Self::AuthorizationDenied(message) => {
                write!(formatter, "authorization denied: {message}")
            }
        }
    }
}

/// Loads an engagement configuration file and authorizes/plans a scan
/// against it. Separated from [`plan_scan_command`] so the outcome can be
/// asserted on directly in tests instead of through an `ExitCode`, which
/// does not implement `PartialEq`.
///
/// If the argument immediately after the config path is the literal
/// `--execute`, every remaining argument is passed through to
/// [`security_agent::execute_plan`], which runs each planned task's
/// approved `StaticLocalAnalysis` tools and returns their outcomes
/// alongside the plan.
fn plan_scan(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<
    (
        security_agent::ExecutionPlan,
        Option<Vec<security_agent::TaskExecutionOutcome>>,
    ),
    PlanScanError,
> {
    let config_path = arguments.next().ok_or(PlanScanError::MissingConfigPath)?;
    let tool_arguments = match arguments.next() {
        None => None,
        Some(flag) if flag == "--execute" => Some(arguments.collect::<Vec<String>>()),
        Some(other) => return Err(PlanScanError::UnexpectedArgument(other)),
    };

    let (profile, targets) = load_engagement_config(Path::new(&config_path))
        .map_err(|error| PlanScanError::ConfigLoad(error.to_string()))?;

    let mut coordinator = Coordinator::new(
        CapabilityRegistry::default(),
        ToolchainPackRegistry::default(),
        PolicyEngine::default(),
    );

    let plan = coordinator
        .plan_authorized_scan(profile, targets, current_epoch_seconds())
        .map_err(|error| PlanScanError::AuthorizationDenied(error.to_string()))?;

    let outcomes = tool_arguments.map(|tool_arguments| {
        let assets = LocalAgentAssets::bundled();
        security_agent::execute_plan(&plan, &assets, &tool_arguments)
    });

    Ok((plan, outcomes))
}

/// CLI entry point for `--plan-scan <config-file> [--execute <args>...]`;
/// prints the resulting [`security_agent::ExecutionPlan`], and — when
/// `--execute` was given — each task's tool execution outcomes.
fn plan_scan_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    match plan_scan(arguments) {
        Ok((plan, outcomes)) => {
            print!("{plan}");
            if let Some(outcomes) = outcomes {
                println!();
                println!("Execution Outcomes");
                println!("==================");
                if outcomes.is_empty() {
                    println!("None (no approved tools were locally installed)");
                } else {
                    for outcome in &outcomes {
                        println!("{outcome}");
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(PlanScanError::AuthorizationDenied(message)) => {
            eprintln!("authorization denied: {message}");
            ExitCode::from(1)
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn write_or_print_report(name: &str, report: String, output: Option<String>) -> ExitCode {
    if let Some(path) = output {
        match fs::write(&path, report) {
            Ok(()) => {
                println!("{name} report written to {path}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("failed to write {path}: {error}");
                ExitCode::from(1)
            }
        }
    } else {
        print!("{report}");
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_coverage_status_reports_ok_for_the_default_registries() {
        assert_eq!(capability_coverage_status(), "ok");
    }

    #[test]
    fn current_epoch_seconds_is_plausible() {
        // Any correctly functioning clock reports a time after this
        // project's initial commit (2026-07-18).
        assert!(current_epoch_seconds() > 1_784_000_000);
    }

    #[test]
    fn plan_scan_reports_missing_config_path() {
        let mut arguments = std::iter::empty::<String>();
        assert!(matches!(
            plan_scan(&mut arguments),
            Err(PlanScanError::MissingConfigPath)
        ));
    }

    #[test]
    fn plan_scan_reports_unexpected_trailing_argument() {
        let mut arguments = vec!["config.txt".to_string(), "extra".to_string()].into_iter();
        assert!(matches!(
            plan_scan(&mut arguments),
            Err(PlanScanError::UnexpectedArgument(argument)) if argument == "extra"
        ));
    }

    #[test]
    fn plan_scan_reports_config_load_failure_for_missing_file() {
        let mut arguments =
            vec!["/nonexistent/security-agent-engagement.txt".to_string()].into_iter();
        let result = plan_scan(&mut arguments);
        assert!(matches!(result, Err(PlanScanError::ConfigLoad(_))));
    }

    #[test]
    fn plan_scan_authorizes_and_plans_a_valid_config() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-{}.txt",
            std::process::id()
        ));
        fs::write(
            &path,
            "\
engagement_id=eng-cli-test
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=0
time_window_end=99999999999
in_scope_targets=api-staging
allowed_techniques=PassiveRecon,ConfigurationAudit,ApiSecurity
max_intensity=Standard
high_impact_approved=false
penetrative_testing_approved=true

[target]
id=api-staging
target_type=Api
criticality=3
",
        )
        .expect("write temp config");

        let mut arguments = vec![path.to_string_lossy().into_owned()].into_iter();
        let result = plan_scan(&mut arguments);
        fs::remove_file(&path).expect("remove temp config");

        let (plan, outcomes) = result.expect("valid config should authorize and plan");
        assert_eq!(plan.engagement_id, "eng-cli-test");
        assert!(!plan.tasks.is_empty());
        assert!(outcomes.is_none(), "no --execute flag was given");
    }

    #[test]
    fn plan_scan_executes_when_flag_is_given() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-execute-{}.txt",
            std::process::id()
        ));
        fs::write(
            &path,
            "\
engagement_id=eng-cli-execute
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=0
time_window_end=99999999999
in_scope_targets=api-staging
allowed_techniques=PassiveRecon,ConfigurationAudit,ApiSecurity
max_intensity=Standard
high_impact_approved=false
penetrative_testing_approved=true

[target]
id=api-staging
target_type=Api
criticality=3
",
        )
        .expect("write temp config");

        let mut arguments =
            vec![path.to_string_lossy().into_owned(), "--execute".to_string()].into_iter();
        let result = plan_scan(&mut arguments);
        fs::remove_file(&path).expect("remove temp config");

        let (_, outcomes) = result.expect("valid config should authorize and plan");
        assert!(
            outcomes.is_some(),
            "--execute should produce Some(outcomes), even if empty"
        );
    }

    #[test]
    fn plan_scan_reports_authorization_denial() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-denied-{}.txt",
            std::process::id()
        ));
        fs::write(
            &path,
            "\
engagement_id=eng-cli-denied
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=0
time_window_end=99999999999
in_scope_targets=prod-ledger
allowed_techniques=PassiveRecon
deny_list_targets=prod-ledger
max_intensity=Passive
high_impact_approved=false
penetrative_testing_approved=false

[target]
id=prod-ledger
target_type=Api
criticality=2
",
        )
        .expect("write temp config");

        let mut arguments = vec![path.to_string_lossy().into_owned()].into_iter();
        let result = plan_scan(&mut arguments);
        fs::remove_file(&path).expect("remove temp config");

        assert!(matches!(result, Err(PlanScanError::AuthorizationDenied(_))));
    }
}
