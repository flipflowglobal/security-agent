//! Security-Agent local runtime.

use security_agent::{
    CapabilityGraph, CapabilityRegistry, CognitiveAssessment, CognitiveDeliberation,
    CognitiveEngine, CognitiveMemory, Coordinator, LocalAgentAssets, PolicyEngine,
    ToolchainPackRegistry, assess_plan_cognitively, load_engagement_config, run_builtin_tool,
    run_external_tool_with_default_timeout,
};
use std::fmt;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() -> ExitCode {
    let assets = LocalAgentAssets::bundled();
    let mut arguments = std::env::args().skip(1).peekable();

    // Global online opt-in: a leading `--allow-network` enables the
    // live-network commands (currently `--listen`) for this invocation, as
    // documented (`security-agent --allow-network --listen 4444`). The flag
    // is consumed here so per-command handlers never see it; commands that
    // do not open sockets ignore it. `--run-external-tool` and `--plan-scan`
    // additionally accept the flag in their own documented positions.
    let allow_network = arguments.peek().map(String::as_str) == Some("--allow-network");
    if allow_network {
        arguments.next();
    }

    match arguments.next().as_deref() {
        None | Some("--offline-status") => {
            print_offline_status(&assets);
            ExitCode::SUCCESS
        }
        Some("--about" | "--version") => print_about(),
        Some("--list-skills") => list_skills(&assets),
        Some("--show-skill") => show_skill(&assets, &mut arguments),
        Some("--list-tools") => list_tools(&assets),
        Some("--run-tool") => run_tool_command(&mut arguments),
        Some("--run-external-tool") => run_external_tool_command(&assets, &mut arguments),
        Some("--plan-scan") => plan_scan_command(&mut arguments),
        Some("--run-engagement") => run_engagement_command(&mut arguments),
        Some("--engagement-control") => engagement_control_command(&mut arguments),
        Some("--record-findings") => record_findings_command(&mut arguments),
        Some("--view-audit") => view_audit_command(&mut arguments),
        Some("--view-audit-db") => view_audit_db_command(&mut arguments),
        Some("--view-findings-db") => view_findings_db_command(&mut arguments),
        Some("--view-calibration-db") => view_calibration_db_command(&mut arguments),
        Some("--view-reasoning-log-db") => view_reasoning_log_db_command(&mut arguments),
        Some("--schedule-retest") => schedule_retest_command(&mut arguments),
        Some("--report") => report_command(&mut arguments),
        Some("--lm-eval") => lm_eval_command(),
        Some("--llm-generate") => llm_generate_command(&mut arguments),
        Some("--llm-perplexity") => llm_perplexity_command(&mut arguments),
        Some("--ask") => ask_command(&assets, &mut arguments),
        Some("--tui") => run_tui_command(&assets),
        Some("--hash-id") => hash_id_command(&mut arguments),
        Some("--password-strength") => password_strength_command(&mut arguments),
        Some("--gen-wordlist") => gen_wordlist_command(&mut arguments),
        Some("--gen-shell") => gen_shell_command(&mut arguments),
        Some("--analyze-payload") => analyze_payload_command(&mut arguments),
        Some("--obfuscate-ps") => obfuscate_ps_command(&mut arguments),
        Some("--gen-decoys") => gen_decoys_command(&mut arguments),
        Some("--analyze-handshake") => analyze_handshake_command(&mut arguments),
        Some("--wps-pin") => wps_pin_command(&mut arguments),
        Some("--audit-wifi") => audit_wifi_command(&mut arguments),
        Some("--analyze-passwd") => analyze_passwd_command(&mut arguments),
        Some("--analyze-sudoers") => analyze_sudoers_command(&mut arguments),
        Some("--analyze-keys") => analyze_keys_command(&mut arguments),
        Some("--guide") => guide_command(&mut arguments),
        Some("--tool-help") => tool_help_command(&mut arguments),
        Some("--shell-guide") => shell_guide_command(),
        Some("--listen") => listen_command(&mut arguments, allow_network),
        Some(command) => {
            eprintln!("unknown command: {command}");
            ExitCode::from(2)
        }
    }
}

/// Prints the agent's identity: package name/version, mission statement,
/// and the phased roadmap (`--about`, alias `--version`). Surfaces
/// `security_agent::MISSION_STATEMENT` and `security_agent::ROADMAP_PHASES`,
/// which are otherwise exported but shown by no command.
fn print_about() -> ExitCode {
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    println!();
    println!("{}", security_agent::MISSION_STATEMENT);
    println!();
    println!("Roadmap");
    println!("-------");
    for phase in security_agent::ROADMAP_PHASES {
        println!("{:<9} {}", phase.phase, phase.focus);
    }
    ExitCode::SUCCESS
}

/// `--guide [section]` — print the complete plain-language guide, or one
/// named section (e.g. `reverse-shell`, `tools`).
fn guide_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(section) = arguments.next() else {
        print!("{}", security_agent::render_all_help());
        return ExitCode::SUCCESS;
    };
    if let Some(extra) = arguments.next() {
        eprintln!("unexpected argument: {extra}");
        return ExitCode::from(2);
    }
    security_agent::render_section(&section).map_or_else(
        || {
            eprintln!("unknown guide section: {section}");
            eprintln!("available sections:");
            for (name, blurb, _) in security_agent::GUIDE_SECTIONS {
                println!("  {name}: {blurb}");
            }
            ExitCode::from(2)
        },
        |rendered| {
            print!("{rendered}");
            ExitCode::SUCCESS
        },
    )
}

/// `--tool-help <command-or-tool>` — print the plain-language guide entry
/// for a single command or tool.
fn tool_help_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(name) = arguments.next() else {
        eprintln!("usage: --tool-help <command-or-tool>");
        eprintln!("example: --tool-help --listen");
        return ExitCode::from(2);
    };
    if let Some(extra) = arguments.next() {
        eprintln!("unexpected argument: {extra}");
        return ExitCode::from(2);
    }
    security_agent::render_help_for(&name).map_or_else(
        || {
            eprintln!("no guide entry for: {name}");
            eprintln!("use --guide to list every documented command.");
            ExitCode::from(2)
        },
        |rendered| {
            print!("{rendered}");
            ExitCode::SUCCESS
        },
    )
}

/// `--shell-guide` — print the end-to-end reverse shell tutorial.
fn shell_guide_command() -> ExitCode {
    print!("{}", security_agent::render_reverse_shell_guide());
    ExitCode::SUCCESS
}

fn print_offline_status(assets: &LocalAgentAssets) {
    let executable_tools = assets
        .tools()
        .iter()
        .filter(|tool| tool.is_installed())
        .count();
    let built_in_tools = assets.tools().iter().filter(|tool| tool.built_in).count();
    let integrity_verified_tools = assets
        .tools()
        .iter()
        .filter(|tool| tool.integrity == security_agent::IntegrityStatus::Verified)
        .count();

    println!("network_required=false");
    println!("external_api_required=false");
    println!("default_network_mode=offline");
    println!("online_opt_in_flag=--allow-network");
    println!("embedded_skills={}", assets.skills().len());
    println!("cataloged_tool_definitions={}", assets.tools().len());
    println!("built_in_substitute_tools={built_in_tools}");
    println!("locally_executable_tools={executable_tools}");
    println!("integrity_verified_tools={integrity_verified_tools}");
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
                "{}\tcataloged\texecutable={}\tintegrity={}",
                tool.definition.name,
                path.display(),
                tool.integrity.label()
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
/// `--run-external-tool semgrep --version`. Static-local-analysis tools run
/// in the default offline mode; live `ActiveNetwork` / `ActiveExploitation`
/// tools require the explicit `--allow-network` opt-in placed immediately
/// after `--run-external-tool` (e.g.
/// `--run-external-tool --allow-network nmap -sV <host>`), otherwise they are
/// refused. Only real, locally installed binaries are ever spawned.
fn run_external_tool_command(
    assets: &LocalAgentAssets,
    arguments: &mut impl Iterator<Item = String>,
) -> ExitCode {
    let Some(mut token) = arguments.next() else {
        eprintln!("missing tool name");
        return ExitCode::from(2);
    };
    // An explicit online opt-in may precede the tool name.
    let mut mode = security_agent::NetworkMode::Offline;
    if token == "--allow-network" {
        mode = security_agent::NetworkMode::Online;
        let Some(next) = arguments.next() else {
            eprintln!("missing tool name after --allow-network");
            return ExitCode::from(2);
        };
        token = next;
    }
    let name = token;
    let Some(tool) = assets.tool(&name) else {
        eprintln!("unknown cataloged tool: {name}");
        return ExitCode::from(2);
    };
    let tool_arguments: Vec<String> = arguments.collect();

    // The direct CLI path has no declared engagement, so advise against a
    // default Standard ceiling — but only for a live tool that will actually
    // run, i.e. a non-static tool under the online opt-in. In offline mode
    // such a tool is refused, so an intensity advisory would just be noise.
    let is_live_tool =
        tool.definition.execution_class != security_agent::ExecutionClass::StaticLocalAnalysis;
    if is_live_tool && mode.allows_active() {
        eprintln!(
            "online mode engaged (--allow-network): running live tool '{name}' against \
             operator-supplied targets"
        );
        print_intensity_advisories(&tool_arguments, security_agent::TestIntensity::Standard);
    }

    match run_external_tool_with_default_timeout(tool, &tool_arguments, mode) {
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
    MissingAuditLogPath,
    MissingAuditDbPath,
    MissingMemoryPath,
    MissingCalibrationDbPath,
    MissingFindingsLogPath,
    MissingFindingsDbPath,
    MissingReasoningLogDbPath,
    UnexpectedArgument(String),
    ConfigLoad(String),
    AuthorizationDenied(String),
    AuditLogWrite(String),
    AuditDbWrite(String),
    MemoryLoad(String),
    CalibrationDbLoad(String),
    CalibrationDbWrite(String),
    FindingsLogWrite(String),
    FindingsDbWrite(String),
    ReasoningLogDbWrite(String),
}

impl fmt::Display for PlanScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingConfigPath => formatter.write_str("missing engagement config file path"),
            Self::MissingAuditLogPath => formatter.write_str("missing --audit-log file path"),
            Self::MissingAuditDbPath => formatter.write_str("missing --audit-db file path"),
            Self::MissingMemoryPath => formatter.write_str("missing --memory file path"),
            Self::MissingCalibrationDbPath => {
                formatter.write_str("missing --calibration-db file path")
            }
            Self::MissingFindingsLogPath => formatter.write_str("missing --findings-log file path"),
            Self::MissingFindingsDbPath => formatter.write_str("missing --findings-db file path"),
            Self::MissingReasoningLogDbPath => {
                formatter.write_str("missing --reasoning-log-db file path")
            }
            Self::UnexpectedArgument(argument) => {
                write!(formatter, "unexpected argument: {argument}")
            }
            Self::ConfigLoad(message) => write!(formatter, "failed to load config: {message}"),
            Self::AuthorizationDenied(message) => {
                write!(formatter, "authorization denied: {message}")
            }
            Self::AuditLogWrite(message) => {
                write!(formatter, "failed to write audit log: {message}")
            }
            Self::AuditDbWrite(message) => {
                write!(formatter, "failed to write audit database: {message}")
            }
            Self::MemoryLoad(message) => {
                write!(formatter, "failed to load cognitive memory: {message}")
            }
            Self::CalibrationDbLoad(message) => {
                write!(formatter, "failed to load calibration database: {message}")
            }
            Self::CalibrationDbWrite(message) => {
                write!(formatter, "failed to write calibration database: {message}")
            }
            Self::FindingsLogWrite(message) => {
                write!(formatter, "failed to write findings log: {message}")
            }
            Self::FindingsDbWrite(message) => {
                write!(formatter, "failed to write findings database: {message}")
            }
            Self::ReasoningLogDbWrite(message) => {
                write!(
                    formatter,
                    "failed to write reasoning log database: {message}"
                )
            }
        }
    }
}

/// Loads an engagement configuration file and authorizes/plans a scan
/// against it. Separated from [`plan_scan_command`] so the outcome can be
/// asserted on directly in tests instead of through an `ExitCode`, which
/// does not implement `PartialEq`.
///
/// Recognizes five optional trailing arguments, in order: `--audit-log
/// <path>` appends the new audit ledger records this call produced to
/// `<path>` (see [`security_agent::append_audit_records`]); `--cognitive-review`
/// runs the advisory reasoning layers over the resulting plan and returns a
/// [`CognitiveReview`] alongside it — both the flat
/// [`CognitiveAssessment`] (see [`security_agent::cognition`]) and the deep
/// [`CognitiveDeliberation`] (see [`security_agent::cognitive_engine`]:
/// train of thought, Bayesian beliefs, adversary model, attention, and
/// metacognition); `--memory <path>` loads the append-only findings ledger
/// at `<path>` (see [`security_agent::memory_store`]) so that cognitive
/// review is informed by history accumulated across prior engagements —
/// the folded memory boosts hypothesis confidence and attention, and the
/// raw findings drive Bayesian belief revision — with the run staying
/// stateless and type-based when the flag is omitted; `--findings-log
/// <path>` appends every finding ingested from `--execute`'s tool output
/// to `<path>` (see [`security_agent::append_findings`]) — a no-op unless
/// `--execute` was also given; `--execute <args>...` passes every
/// remaining argument through to [`security_agent::execute_plan`], which
/// runs each planned task's approved, execution-eligible tools
/// (`StaticLocalAnalysis`, plus `nmap`/`masscan` as explicit exceptions)
/// and returns their outcomes alongside the plan.
/// The advisory cognitive output for a `--cognitive-review` run: the flat
/// [`CognitiveAssessment`] (prioritization, hypotheses, insights), the deep
/// [`CognitiveDeliberation`] (train of thought, beliefs, adversary model,
/// attention, and metacognition), and language-model anomaly flags over the
/// finding text loaded from `--memory`.
type CognitiveReview = (
    CognitiveAssessment,
    CognitiveDeliberation,
    Vec<security_agent::AnomalyFlag>,
);

type PlanScanOutcome = (
    security_agent::ExecutionPlan,
    Option<CognitiveReview>,
    Option<Vec<security_agent::TaskExecutionOutcome>>,
    Vec<security_agent::Finding>,
);

/// Loops the language model's perplexity signal into the cognitive review:
/// flags finding text that does not look like ordinary security-domain
/// English. Only builds the model (and pays its startup cost) when there
/// are prior findings to scan; otherwise returns no flags.
fn scan_prior_findings(
    prior_findings: &[security_agent::Finding],
) -> Vec<security_agent::AnomalyFlag> {
    if prior_findings.is_empty() {
        return Vec::new();
    }
    let model = security_agent::NeuralLanguageModel::bundled();
    let threshold = model.anomaly_threshold();
    security_agent::scan_findings(prior_findings, &model, threshold)
}

/// The parsed optional flags of a `--plan-scan` invocation, in the order they
/// must appear on the command line.
struct PlanScanArgs {
    config_path: String,
    audit_log_path: Option<String>,
    audit_db_path: Option<String>,
    cognitive_review: bool,
    memory_path: Option<String>,
    calibration_db_path: Option<String>,
    findings_log_path: Option<String>,
    findings_db_path: Option<String>,
    reasoning_log_db_path: Option<String>,
    network_mode: security_agent::NetworkMode,
    tool_arguments: Option<Vec<String>>,
}

/// Parses `--plan-scan <config> [--audit-log <p>] [--audit-db <p>]
/// [--cognitive-review] [--memory <p>] [--calibration-db <p>]
/// [--findings-log <p>] [--findings-db <p>] [--reasoning-log-db <p>]
/// [--allow-network] [--execute <args>]` in fixed order, consuming
/// `arguments`.
///
/// The `-db` flags are siblings of their `-log`/`-memory` counterparts,
/// backed by the zero-dependency `.sadb` embedded store
/// ([`security_agent::sadb`]) instead of JSON Lines text: `--audit-db`
/// alongside `--audit-log`, `--calibration-db` alongside `--memory`
/// (closing the loop documented on
/// [`security_agent::CognitiveEngine::with_calibration`] -- see
/// [`security_agent::calibration_db`]), and `--findings-db` alongside
/// `--findings-log`. `--reasoning-log-db` has no JSON Lines counterpart:
/// it archives each `--cognitive-review` run's full reasoning chain and
/// metacognitive verdict (see [`security_agent::reasoning_log_db`]), and
/// is a no-op unless `--cognitive-review` was also given, matching how
/// `--findings-log`/`--findings-db` are no-ops without `--execute`.
fn parse_plan_scan_args(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<PlanScanArgs, PlanScanError> {
    let config_path = arguments.next().ok_or(PlanScanError::MissingConfigPath)?;

    let mut next_argument = arguments.next();
    let audit_log_path = if next_argument.as_deref() == Some("--audit-log") {
        let path = arguments.next().ok_or(PlanScanError::MissingAuditLogPath)?;
        next_argument = arguments.next();
        Some(path)
    } else {
        None
    };
    let audit_db_path = if next_argument.as_deref() == Some("--audit-db") {
        let path = arguments.next().ok_or(PlanScanError::MissingAuditDbPath)?;
        next_argument = arguments.next();
        Some(path)
    } else {
        None
    };
    let cognitive_review = if next_argument.as_deref() == Some("--cognitive-review") {
        next_argument = arguments.next();
        true
    } else {
        false
    };
    let memory_path = if next_argument.as_deref() == Some("--memory") {
        let path = arguments.next().ok_or(PlanScanError::MissingMemoryPath)?;
        next_argument = arguments.next();
        Some(path)
    } else {
        None
    };
    let calibration_db_path = if next_argument.as_deref() == Some("--calibration-db") {
        let path = arguments
            .next()
            .ok_or(PlanScanError::MissingCalibrationDbPath)?;
        next_argument = arguments.next();
        Some(path)
    } else {
        None
    };
    let findings_log_path = if next_argument.as_deref() == Some("--findings-log") {
        let path = arguments
            .next()
            .ok_or(PlanScanError::MissingFindingsLogPath)?;
        next_argument = arguments.next();
        Some(path)
    } else {
        None
    };
    let findings_db_path = if next_argument.as_deref() == Some("--findings-db") {
        let path = arguments
            .next()
            .ok_or(PlanScanError::MissingFindingsDbPath)?;
        next_argument = arguments.next();
        Some(path)
    } else {
        None
    };
    let reasoning_log_db_path = if next_argument.as_deref() == Some("--reasoning-log-db") {
        let path = arguments
            .next()
            .ok_or(PlanScanError::MissingReasoningLogDbPath)?;
        next_argument = arguments.next();
        Some(path)
    } else {
        None
    };
    // Explicit, per-invocation online opt-in. Offline (the default) runs only
    // local-analysis tools during --execute; --allow-network additionally
    // authorizes the live ActiveNetwork/ActiveExploitation tools the
    // engagement already approves.
    let network_mode = if next_argument.as_deref() == Some("--allow-network") {
        next_argument = arguments.next();
        security_agent::NetworkMode::Online
    } else {
        security_agent::NetworkMode::Offline
    };
    let tool_arguments = match next_argument {
        None => None,
        Some(flag) if flag == "--execute" => Some(arguments.collect::<Vec<String>>()),
        Some(other) => return Err(PlanScanError::UnexpectedArgument(other)),
    };
    Ok(PlanScanArgs {
        config_path,
        audit_log_path,
        audit_db_path,
        cognitive_review,
        memory_path,
        calibration_db_path,
        findings_log_path,
        findings_db_path,
        reasoning_log_db_path,
        network_mode,
        tool_arguments,
    })
}

/// Loads the accumulated calibration history from `--calibration-db` so
/// this run's hypothesis-confidence correction
/// (`CognitiveEngine::with_calibration`) has real cross-engagement
/// evidence instead of starting empty each time. See
/// [`security_agent::calibration_db`] for why this closes a real gap:
/// `assess_calibration` computes fresh evidence every run, but nothing
/// previously carried it forward.
///
/// Returns an empty tracker without touching the database at all unless
/// `cognitive_review` is true -- calibration has no effect otherwise, so
/// `--calibration-db` must be a true no-op without `--cognitive-review`,
/// matching `--reasoning-log-db`'s no-op gating, rather than creating an
/// empty database as a side effect of a flag that does nothing here.
fn load_calibration_history(
    cognitive_review: bool,
    calibration_db_path: Option<&str>,
) -> Result<security_agent::CalibrationTracker, PlanScanError> {
    if !cognitive_review {
        return Ok(security_agent::CalibrationTracker::new());
    }
    calibration_db_path.map_or_else(
        || Ok(security_agent::CalibrationTracker::new()),
        |path| {
            security_agent::calibration_db::load_calibration(Path::new(path))
                .map_err(|error| PlanScanError::CalibrationDbLoad(error.to_string()))
        },
    )
}

/// Appends this run's fresh calibration evidence and reasoning-log
/// archive, when `cognitive_output` is `Some` and the corresponding `-db`
/// flag was given; a no-op otherwise.
///
/// `deliberation.calibration` is always this run's *fresh*
/// `assess_calibration` evidence only -- it starts from an empty tracker,
/// never from the accumulated history [`load_calibration_history`] loads
/// -- so appending it here grows the history without ever
/// double-counting it.
fn persist_cognitive_artifacts(
    cognitive_output: Option<&CognitiveReview>,
    calibration_db_path: Option<&str>,
    reasoning_log_db_path: Option<&str>,
) -> Result<(), PlanScanError> {
    let Some((_, deliberation, _)) = cognitive_output else {
        return Ok(());
    };
    if let Some(path) = calibration_db_path {
        security_agent::calibration_db::append_calibration_records(
            Path::new(path),
            deliberation.calibration.records(),
        )
        .map_err(|error| PlanScanError::CalibrationDbWrite(error.to_string()))?;
    }
    if let Some(path) = reasoning_log_db_path {
        security_agent::reasoning_log_db::append_run(
            Path::new(path),
            current_epoch_seconds(),
            &deliberation.reasoning_chain,
            &deliberation.metacognition,
        )
        .map_err(|error| PlanScanError::ReasoningLogDbWrite(error.to_string()))?;
    }
    Ok(())
}

fn plan_scan(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<PlanScanOutcome, PlanScanError> {
    let PlanScanArgs {
        config_path,
        audit_log_path,
        audit_db_path,
        cognitive_review,
        memory_path,
        calibration_db_path,
        findings_log_path,
        findings_db_path,
        reasoning_log_db_path,
        network_mode,
        tool_arguments,
    } = parse_plan_scan_args(arguments)?;

    let (profile, targets) = load_engagement_config(Path::new(&config_path))
        .map_err(|error| PlanScanError::ConfigLoad(error.to_string()))?;

    // Captured before `profile` is moved into planning; used to advise on
    // over-aggressive `--execute` arguments against the declared ceiling.
    let declared_ceiling = profile.max_intensity;

    let mut coordinator = Coordinator::new(
        CapabilityRegistry::default(),
        ToolchainPackRegistry::default(),
        PolicyEngine::default(),
    );

    let targets_for_review = targets.clone();
    let plan = coordinator
        .plan_authorized_scan(profile, targets, current_epoch_seconds())
        .map_err(|error| PlanScanError::AuthorizationDenied(error.to_string()))?;

    if let Some(path) = audit_log_path {
        security_agent::append_audit_records(Path::new(&path), coordinator.audit_ledger.records())
            .map_err(|error| PlanScanError::AuditLogWrite(error.to_string()))?;
    }
    if let Some(path) = audit_db_path {
        security_agent::audit_db::append_audit_records(
            Path::new(&path),
            coordinator.audit_ledger.records(),
        )
        .map_err(|error| PlanScanError::AuditDbWrite(error.to_string()))?;
    }

    // When `--memory <path>` is given, load the append-only findings ledger
    // (empty if it does not exist yet) so cognition is informed by history
    // accumulated across prior engagements: the folded `CognitiveMemory`
    // boosts hypothesis confidence and attention, and the raw findings drive
    // Bayesian belief revision in the deliberation. Without `--memory`, the
    // run stays stateless and priors are type-based only.
    let prior_findings = match &memory_path {
        Some(path) => {
            let ledger = Path::new(path);
            if ledger.exists() {
                security_agent::load_findings(ledger)
                    .map_err(|error| PlanScanError::MemoryLoad(error.to_string()))?
            } else {
                Vec::new()
            }
        }
        None => Vec::new(),
    };

    // See `load_calibration_history` for why this is gated on
    // `cognitive_review`.
    let calibration = load_calibration_history(cognitive_review, calibration_db_path.as_deref())?;

    let cognitive_output = cognitive_review.then(|| {
        let mut memory = CognitiveMemory::new();
        memory.record_findings(&prior_findings);
        let assessment = assess_plan_cognitively(&plan, &targets_for_review, &memory);
        let engine = CognitiveEngine::new(memory, security_agent::AdversaryModel::default())
            .with_calibration(calibration);
        let deliberation = engine.deliberate(&plan, &targets_for_review, &prior_findings);
        let anomalies = scan_prior_findings(&prior_findings);
        (assessment, deliberation, anomalies)
    });

    persist_cognitive_artifacts(
        cognitive_output.as_ref(),
        calibration_db_path.as_deref(),
        reasoning_log_db_path.as_deref(),
    )?;

    if let Some(tool_arguments) = &tool_arguments {
        print_intensity_advisories(tool_arguments, declared_ceiling);
        if network_mode.allows_active() {
            eprintln!(
                "online mode engaged (--allow-network): live tools approved by this engagement \
                 may run against in-scope targets"
            );
        }
    }

    let outcomes = tool_arguments.map(|tool_arguments| {
        let assets = LocalAgentAssets::bundled();
        security_agent::execute_plan(&plan, &assets, &tool_arguments, network_mode)
    });

    let findings: Vec<security_agent::Finding> = outcomes
        .as_ref()
        .map(|outcomes| {
            outcomes
                .iter()
                .filter_map(|outcome| outcome.result.as_ref().ok().map(|report| (outcome, report)))
                .flat_map(|(outcome, report)| {
                    security_agent::ingest::ingest(&outcome.target_id, report)
                })
                .collect()
        })
        .unwrap_or_default();

    // Only touch the findings log/database when --execute actually ran
    // (`outcomes` is `Some`); otherwise --findings-log/--findings-db are
    // true no-ops, matching their documented behavior, rather than
    // creating an empty log file or database.
    if outcomes.is_some() {
        if let Some(path) = findings_log_path {
            security_agent::append_findings(Path::new(&path), &findings)
                .map_err(|error| PlanScanError::FindingsLogWrite(error.to_string()))?;
        }
        if let Some(path) = findings_db_path {
            security_agent::findings_db::append_findings(Path::new(&path), &findings)
                .map_err(|error| PlanScanError::FindingsDbWrite(error.to_string()))?;
        }
    }

    Ok((plan, cognitive_output, outcomes, findings))
}

/// CLI entry point for `--plan-scan <config-file> [--audit-log <path>]
/// [--audit-db <path>] [--cognitive-review] [--memory <path>]
/// [--calibration-db <path>] [--findings-log <path>] [--findings-db <path>]
/// [--reasoning-log-db <path>] [--execute <args>...]`; prints the
/// resulting [`security_agent::ExecutionPlan`], the [`CognitiveAssessment`]
/// when `--cognitive-review` was given, and — when `--execute` was given —
/// each task's tool execution outcomes plus a findings summary ingested
/// from their output. See [`parse_plan_scan_args`] for what each `-db`
/// flag does differently from its JSON Lines counterpart.
fn plan_scan_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    match plan_scan(arguments) {
        Ok((plan, cognitive_output, outcomes, findings)) => {
            print!("{plan}");
            // The orchestrated schedule shows the deterministic,
            // least-invasive-first order execution will follow (and that
            // `--execute` actually runs), deduplicated per (target, tool).
            let schedule = security_agent::ToolOrchestrator::new().schedule(&plan);
            println!();
            print!("{schedule}");
            if let Some((assessment, deliberation, anomalies)) = cognitive_output {
                println!();
                print!("{assessment}");
                println!();
                print!("{deliberation}");
                if !anomalies.is_empty() {
                    println!();
                    println!("Anomaly Scan (language-model surprise over finding text)");
                    println!("--------------------------------------------------------");
                    for flag in &anomalies {
                        let marker = if flag.anomalous { "ANOMALOUS" } else { "ok" };
                        let perplexity = if flag.perplexity.is_finite() {
                            format!("{:.1}", flag.perplexity)
                        } else {
                            "inf".to_string()
                        };
                        println!(
                            "  [{marker:>9}] ppl={perplexity:>6}  {} : {}",
                            flag.finding_id, flag.text
                        );
                    }
                }
            }
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
                print_findings_summary(&findings);
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

/// The parsed flags of a `--run-engagement` invocation.
struct RunEngagementArgs {
    config_path: String,
    max_concurrency: Option<usize>,
    per_tool_timeout: Option<Duration>,
    min_spawn_interval: Option<Duration>,
    secrets_path: Option<String>,
    events_path: Option<String>,
    findings_log_path: Option<String>,
    findings_db_path: Option<String>,
    network_mode: security_agent::NetworkMode,
    allow_tools: Vec<String>,
    deny_tools: Vec<String>,
    control_file: Option<String>,
    operator_args: Vec<String>,
}

/// Parses `<config-file>` followed by the optional `--run-engagement` flags.
/// A bare `--` ends flag parsing; everything after it is passed through to
/// every tool invocation as operator arguments.
fn parse_run_engagement_args(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<RunEngagementArgs, String> {
    let config_path = arguments
        .next()
        .ok_or("missing config file path for --run-engagement")?;
    let mut args = RunEngagementArgs {
        config_path,
        max_concurrency: None,
        per_tool_timeout: None,
        min_spawn_interval: None,
        secrets_path: None,
        events_path: None,
        findings_log_path: None,
        findings_db_path: None,
        network_mode: security_agent::NetworkMode::Offline,
        allow_tools: Vec::new(),
        deny_tools: Vec::new(),
        control_file: None,
        operator_args: Vec::new(),
    };

    let value = |arguments: &mut dyn Iterator<Item = String>, flag: &str| {
        arguments
            .next()
            .ok_or_else(|| format!("missing value after {flag}"))
    };
    let seconds = |raw: &str, flag: &str| {
        raw.parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|_| format!("{flag} expects a whole number of seconds, got '{raw}'"))
    };

    while let Some(flag) = arguments.next() {
        match flag.as_str() {
            "--allow-network" => args.network_mode = security_agent::NetworkMode::Online,
            "--max-concurrency" => {
                let raw = value(arguments, "--max-concurrency")?;
                args.max_concurrency =
                    Some(raw.parse::<usize>().map_err(|_| {
                        format!("--max-concurrency expects an integer, got '{raw}'")
                    })?);
            }
            "--per-tool-timeout" => {
                args.per_tool_timeout = Some(seconds(
                    &value(arguments, "--per-tool-timeout")?,
                    "--per-tool-timeout",
                )?);
            }
            "--min-spawn-interval" => {
                args.min_spawn_interval = Some(seconds(
                    &value(arguments, "--min-spawn-interval")?,
                    "--min-spawn-interval",
                )?);
            }
            "--allow-tool" => args.allow_tools.push(value(arguments, "--allow-tool")?),
            "--deny-tool" => args.deny_tools.push(value(arguments, "--deny-tool")?),
            "--control-file" => args.control_file = Some(value(arguments, "--control-file")?),
            "--secrets" => args.secrets_path = Some(value(arguments, "--secrets")?),
            "--events" => args.events_path = Some(value(arguments, "--events")?),
            "--findings-log" => args.findings_log_path = Some(value(arguments, "--findings-log")?),
            "--findings-db" => args.findings_db_path = Some(value(arguments, "--findings-db")?),
            "--" => {
                args.operator_args.extend(arguments.by_ref());
                break;
            }
            other => return Err(format!("unexpected argument for --run-engagement: {other}")),
        }
    }
    Ok(args)
}

/// CLI entry point for
/// `--run-engagement <config-file> [--max-concurrency N] [--per-tool-timeout S]
/// [--min-spawn-interval S] [--allow-tool <name>]... [--deny-tool <name>]...
/// [--secrets <file>] [--events <file>] [--findings-log <path>]
/// [--findings-db <path>] [--control-file <path>] [--allow-network]
/// [-- <operator args>...]`.
///
/// `--control-file <path>` enables real-time control: while the engagement
/// runs, another terminal can `--engagement-control <path> pause|resume|cancel`
/// (or `rate <secs>` / `rate off`) to steer it live.
///
/// Drives the concurrent, staged engagement engine
/// ([`security_agent::run_engagement_pipeline`]) — the orchestrator, the
/// bounded-concurrency runtime with its least-invasive-first class barrier,
/// and the discovery feedback loop — rather than the sequential
/// `--plan-scan --execute` path. Egress scope is derived automatically from
/// the engagement's declared target addresses, so the engine can only touch
/// what the engagement authorized. The active-tool gate additionally refuses,
/// before spawn, any tool the engagement did not approve; `--allow-tool`
/// narrows that authorized set to a subset and `--deny-tool` blocks specific
/// tools (both repeatable, and both can only further restrict). `--secrets`
/// resolves `${secret:NAME}` references and redacts them from output;
/// `--events` streams the run's lifecycle as JSON lines.
fn run_engagement_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    match run_engagement(arguments) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

/// The inputs to one engagement execution, bundled so the optional live-control
/// wrapper stays readable (and under clippy's argument limit).
#[derive(Clone, Copy)]
struct RunEngagementCall<'a> {
    plan: &'a security_agent::ExecutionPlan,
    adapters: &'a security_agent::AdapterRegistry,
    runtime: &'a security_agent::ExecutionRuntime,
    assets: &'a LocalAgentAssets,
    operator_args: &'a [String],
    network_mode: security_agent::NetworkMode,
    guards: security_agent::EngagementGuards<'a>,
    control_file: Option<&'a str>,
    controller: &'a security_agent::RunController,
    event_sink: Option<&'a dyn security_agent::EventSink>,
}

/// Runs the engagement pipeline. With a control file configured, a poller
/// thread watches it and applies pause/resume/cancel/rate commands to the
/// shared [`security_agent::RunController`] while the pipeline runs.
fn run_engagement_with_optional_control(
    call: RunEngagementCall,
) -> security_agent::EngagementReport {
    let pipeline = || {
        security_agent::run_engagement_pipeline(
            call.plan,
            call.adapters,
            call.runtime,
            call.assets,
            call.operator_args,
            call.network_mode,
            call.guards,
        )
    };
    let Some(control_path) = call.control_file else {
        return pipeline();
    };
    eprintln!(
        "live control enabled — drive it from another terminal with \
         `--engagement-control {control_path} <command>`:"
    );
    eprintln!("  pause | resume | cancel | rate <seconds> | rate off");
    let run_done = AtomicBool::new(false);
    let path = Path::new(control_path);
    std::thread::scope(|scope| {
        scope.spawn(|| poll_control_file(path, call.controller, call.event_sink, &run_done));
        let report = pipeline();
        run_done.store(true, Ordering::Relaxed);
        report
    })
}

/// Polls the control file until the run finishes (or is cancelled), applying
/// each newly written command to the shared controller. Best effort: an
/// unreadable file or an unparseable line is reported and skipped, never fatal.
fn poll_control_file(
    path: &Path,
    controller: &security_agent::RunController,
    sink: Option<&dyn security_agent::EventSink>,
    run_done: &AtomicBool,
) {
    let mut last = String::new();
    while !run_done.load(Ordering::Relaxed) && !controller.is_cancelled() {
        if let Ok(text) = fs::read_to_string(path) {
            if text != last {
                last.clone_from(&text);
                if let Some(line) = text.lines().rev().find(|line| !line.trim().is_empty()) {
                    apply_control_line(line.trim(), controller, sink);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Applies one control line to the controller and mirrors the transition to
/// the event sink (so `--events` records pause/resume/cancel).
fn apply_control_line(
    line: &str,
    controller: &security_agent::RunController,
    sink: Option<&dyn security_agent::EventSink>,
) {
    match security_agent::parse_control_command(line) {
        Ok(command) => {
            controller.apply(command);
            eprintln!("control: applied '{line}'");
            let event = match command {
                security_agent::ControlCommand::Pause => {
                    Some(security_agent::EngagementEvent::RunPaused)
                }
                security_agent::ControlCommand::Resume => {
                    Some(security_agent::EngagementEvent::RunResumed)
                }
                security_agent::ControlCommand::Cancel => {
                    Some(security_agent::EngagementEvent::RunCancelled)
                }
                security_agent::ControlCommand::SetRate(_) => None,
            };
            if let (Some(event), Some(sink)) = (event, sink) {
                sink.emit(&event);
            }
        }
        Err(error) => eprintln!("control: ignoring '{line}': {error}"),
    }
}

/// `--engagement-control <control-file> <pause|resume|cancel|rate SECS|rate off>`
/// — write a command a running `--run-engagement --control-file` picks up.
fn engagement_control_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    match engagement_control(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

fn engagement_control(arguments: &mut impl Iterator<Item = String>) -> Result<(), String> {
    let path = arguments.next().ok_or(
        "usage: --engagement-control <control-file> <pause|resume|cancel|rate SECS|rate off>",
    )?;
    let words: Vec<String> = arguments.collect();
    if words.is_empty() {
        return Err(
            "missing control command (pause, resume, cancel, rate <secs>, rate off)".to_string(),
        );
    }
    let line = words.join(" ");
    security_agent::parse_control_command(&line)
        .map_err(|error| format!("invalid control command: {error}"))?;
    fs::write(&path, format!("{line}\n"))
        .map_err(|error| format!("failed to write control file '{path}': {error}"))?;
    println!("control command '{line}' written to {path}");
    Ok(())
}

/// Builds the engagement's active-tool gate: the allow-list is the union of
/// every task's approved tools, optionally narrowed by `--allow-tool` and
/// blocked by `--deny-tool`. Fails closed (see [`security_agent::tool_gate`]).
fn build_tool_gate(
    plan: &security_agent::ExecutionPlan,
    allow_tools: &[String],
    deny_tools: &[String],
) -> security_agent::ToolGate {
    let approved = plan
        .tasks
        .iter()
        .flat_map(|task| task.approved_tools.iter().cloned());
    let mut gate = security_agent::ToolGate::allow_only(approved);
    if !allow_tools.is_empty() {
        gate = gate.restrict_to(allow_tools.iter().cloned());
    }
    if !deny_tools.is_empty() {
        gate = gate.deny(deny_tools.iter().cloned());
    }
    gate
}

fn run_engagement(arguments: &mut impl Iterator<Item = String>) -> Result<ExitCode, String> {
    let args = parse_run_engagement_args(arguments)?;

    let (profile, targets) = load_engagement_config(Path::new(&args.config_path))
        .map_err(|error| format!("failed to load config: {error}"))?;

    // Scope defaults to the engagement's declared target addresses: the engine
    // may only reach what the engagement authorized.
    let scope_targets: Vec<String> = targets
        .iter()
        .filter_map(|target| target.network_address.clone())
        .collect();
    let scope = security_agent::ScopePolicy::from_targets(&scope_targets);

    let mut coordinator = Coordinator::new(
        CapabilityRegistry::default(),
        ToolchainPackRegistry::default(),
        PolicyEngine::default(),
    );
    let plan = coordinator
        .plan_authorized_scan(profile, targets, current_epoch_seconds())
        .map_err(|error| format!("authorization denied: {error}"))?;

    let secrets = match &args.secrets_path {
        Some(path) => {
            let mut store = security_agent::SecretStore::from_env();
            store
                .load_file(Path::new(path))
                .map_err(|error| format!("failed to load secrets: {error}"))?;
            Some(store)
        }
        None => None,
    };

    let event_sink = match &args.events_path {
        Some(path) => {
            let file = fs::File::create(path)
                .map_err(|error| format!("failed to open events file '{path}': {error}"))?;
            Some(security_agent::WriterSink::new(file))
        }
        None => None,
    };

    let mut config = security_agent::RuntimeConfig::default();
    if let Some(concurrency) = args.max_concurrency {
        config.max_concurrency = concurrency.max(1);
    }
    if let Some(timeout) = args.per_tool_timeout {
        config.per_tool_timeout = timeout;
    }
    config.min_spawn_interval = args.min_spawn_interval;
    let runtime = security_agent::ExecutionRuntime::new(config);

    let adapters = security_agent::AdapterRegistry::with_defaults();
    let assets = LocalAgentAssets::bundled();

    // Active-tool gate: the runtime may run only tools this engagement's
    // authorization approved (narrowed by --allow-tool / --deny-tool).
    let gate = build_tool_gate(&plan, &args.allow_tools, &args.deny_tools);
    if let Some(count) = gate.allowed_count() {
        eprintln!(
            "active-tool gate: {count} tool(s) authorized for this engagement; \
             any other tool is refused before spawn"
        );
    }

    // Live run control: when a control file is given, the run can be paused,
    // resumed, cancelled, or rate-adjusted while it runs (see `--engagement-control`).
    let controller = security_agent::RunController::new();

    let guards = security_agent::EngagementGuards {
        scope: Some(&scope),
        secrets: secrets.as_ref(),
        events: event_sink
            .as_ref()
            .map(|sink| sink as &dyn security_agent::EventSink),
        gate: Some(&gate),
        controller: args.control_file.as_ref().map(|_| &controller),
    };

    if args.network_mode.allows_active() {
        eprintln!(
            "online mode engaged (--allow-network): live tools approved by this engagement \
             may run against in-scope targets"
        );
    }

    let report = run_engagement_with_optional_control(RunEngagementCall {
        plan: &plan,
        adapters: &adapters,
        runtime: &runtime,
        assets: &assets,
        operator_args: &args.operator_args,
        network_mode: args.network_mode,
        guards,
        control_file: args.control_file.as_deref(),
        controller: &controller,
        event_sink: event_sink
            .as_ref()
            .map(|sink| sink as &dyn security_agent::EventSink),
    });

    let findings: Vec<security_agent::Finding> = report
        .all_outcomes()
        .iter()
        .filter_map(|outcome| outcome.result.as_ref().ok().map(|report| (outcome, report)))
        .flat_map(|(outcome, report)| security_agent::ingest::ingest(&outcome.target_id, report))
        .collect();

    if let Some(path) = &args.findings_log_path {
        security_agent::append_findings(Path::new(path), &findings)
            .map_err(|error| format!("failed to write findings log: {error}"))?;
    }
    if let Some(path) = &args.findings_db_path {
        security_agent::findings_db::append_findings(Path::new(path), &findings)
            .map_err(|error| format!("failed to write findings database: {error}"))?;
    }

    print_engagement_report(&report, &findings);
    Ok(ExitCode::SUCCESS)
}

/// Prints the staged engagement's outcomes: each stage's per-tool results,
/// the discovery blackboard totals, and the ingested-findings count.
fn print_engagement_report(
    report: &security_agent::EngagementReport,
    findings: &[security_agent::Finding],
) {
    println!("Engagement Execution (concurrent staged pipeline)");
    println!("=================================================");

    if report.stages.is_empty() {
        println!("\nNo tools scheduled — the plan produced no executable steps.");
    }
    for stage in &report.stages {
        let mut ok = 0usize;
        let mut refused = 0usize;
        let mut failed = 0usize;
        for outcome in &stage.outcomes {
            match &outcome.result {
                Ok(_) => ok += 1,
                Err(security_agent::ToolExecutionError::Refused(_)) => refused += 1,
                Err(_) => failed += 1,
            }
        }
        println!(
            "\nStage {:?}: {ok} ok, {failed} failed, {refused} refused",
            stage.class
        );
        for outcome in &stage.outcomes {
            let status = match &outcome.result {
                Ok(_) => "ok".to_string(),
                Err(error) => error.to_string(),
            };
            println!("  [{}] {} -> {status}", outcome.tool, outcome.target_id);
        }
    }

    let context = &report.context;
    println!(
        "\nDiscovery: {} host(s), {} service(s), {} endpoint(s)",
        context.hosts().len(),
        context.services().len(),
        context.endpoints().len()
    );
    println!("Findings ingested: {}", findings.len());
}

/// Prints a summary of findings ingested from `--execute`'s tool output:
/// counts by severity, the top few by [`security_agent::RiskScoreCalculator`]
/// score, and the node/edge counts of the
/// [`security_agent::AttackPathGraph`] built from them.
fn print_findings_summary(findings: &[security_agent::Finding]) {
    const TOP_FINDINGS_SHOWN: usize = 5;

    println!();
    println!("Findings Summary");
    println!("================");
    if findings.is_empty() {
        println!("None (no findings ingested from tool output)");
        return;
    }

    let mut by_severity: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for finding in findings {
        *by_severity.entry(finding.severity.to_string()).or_insert(0) += 1;
    }
    for (severity, count) in &by_severity {
        println!("{severity:<14}: {count}");
    }

    println!();
    println!("Top findings by risk score");
    println!("--------------------------");
    let mut by_risk_score: Vec<&security_agent::Finding> = findings.iter().collect();
    by_risk_score.sort_by(|a, b| b.normalized_risk_score.total_cmp(&a.normalized_risk_score));
    for finding in by_risk_score.iter().take(TOP_FINDINGS_SHOWN) {
        println!(
            "{:.2}\t{}\t{}\t{}",
            finding.normalized_risk_score, finding.severity, finding.target_id, finding.title
        );
    }

    let graph = security_agent::AttackPathGraph::build_from_findings(findings);
    println!();
    println!(
        "Attack path graph: {} nodes, {} edges",
        graph.nodes.len(),
        graph.edges.len()
    );
}

/// Prints one non-blocking intensity advisory per over-aggressive argument
/// to stderr (see `security_agent::intensity_guard`). Never changes control
/// flow or exit codes — it only makes a scope/aggressiveness mismatch
/// visible to the operator.
fn print_intensity_advisories(arguments: &[String], ceiling: security_agent::TestIntensity) {
    for advisory in security_agent::advise(arguments, ceiling) {
        eprintln!("intensity advisory: {}", advisory.message);
    }
}

/// Copies findings from one findings log into another
/// (`--record-findings <destination-log>.jsonl <source-log>.jsonl`).
///
/// Reads `Finding`s from `<source-log>` (an append-only `finding_record`
/// JSON Lines file — the single format produced by `--findings-log` and
/// [`security_agent::append_findings`]) and appends them to the
/// append-only log at `<destination-log>`. Because there is now one
/// findings format, a `--findings-log` output can also be used directly as
/// `--memory` input; this command is for merging or curating logs. Later
/// engagements accumulate on top of earlier ones, so a subsequent
/// `--plan-scan ... --cognitive-review --memory <destination-log>` reasons
/// from the full accumulated history. This command never plans,
/// authorizes, or executes — it only persists evidence for the advisory
/// cognitive layer.
fn record_findings_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(destination_path) = arguments.next() else {
        eprintln!("missing destination findings-log path");
        return ExitCode::from(2);
    };
    let Some(source_path) = arguments.next() else {
        eprintln!("missing source findings-log path");
        return ExitCode::from(2);
    };
    if let Some(extra) = arguments.next() {
        eprintln!("unexpected argument: {extra}");
        return ExitCode::from(2);
    }

    let findings = match security_agent::load_findings(Path::new(&source_path)) {
        Ok(findings) => findings,
        Err(error) => {
            eprintln!("failed to read source findings log: {error}");
            return ExitCode::from(1);
        }
    };
    if findings.is_empty() {
        eprintln!("no valid findings parsed from {source_path}");
        return ExitCode::from(1);
    }

    match security_agent::append_findings(Path::new(&destination_path), &findings) {
        Ok(()) => {
            println!(
                "recorded {} finding(s) into findings log {destination_path}",
                findings.len()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("failed to record findings: {error}");
            ExitCode::from(1)
        }
    }
}

/// Continues a prompt with the built-in small neural language model
/// (`--llm-generate <prompt words...>`).
///
/// The model (`security_agent::language_model`) is a tiny, from-scratch
/// neural language model trained deterministically on a bundled
/// security-domain corpus — no network, no weights on disk. Decoding
/// samples with temperature and top-k filtering, seeded from the prompt, so
/// the same prompt always yields the same continuation. Text is modest
/// given the model's size; this exists to make the offline language-model
/// capability usable and inspectable.
fn llm_generate_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    use security_agent::LanguageModel;
    let prompt = arguments.collect::<Vec<String>>().join(" ");
    if prompt.trim().is_empty() {
        eprintln!("missing prompt for --llm-generate");
        return ExitCode::from(2);
    }
    let model = security_agent::NeuralLanguageModel::bundled();
    let continuation = model.generate(&prompt, 24);
    // Avoid a trailing space when the model produces no continuation.
    if continuation.is_empty() {
        println!("{prompt}");
    } else {
        println!("{prompt} {continuation}");
    }
    ExitCode::SUCCESS
}

/// Runs the held-out evaluation of the built-in language model and prints
/// the report (`--lm-eval`). Measures the model's three production jobs —
/// perplexity-based anomaly discrimination, intent routing, and generation —
/// against fixed quality floors, plus a vocabulary-coverage diagnostic.
/// Exits non-zero when a gated floor is not met, so the command doubles as a
/// regression check outside the test suite.
fn lm_eval_command() -> ExitCode {
    let assets = security_agent::LocalAgentAssets::bundled();
    let model = security_agent::NeuralLanguageModel::bundled();
    let report = security_agent::evaluate(&assets, &model);
    print!("{}", report.summary());
    if report.passes() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Scores how surprising text is to the built-in language model
/// (`--llm-perplexity <text words...>`). Lower perplexity means the text
/// reads more like the security-domain corpus the model learned.
fn llm_perplexity_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    use security_agent::LanguageModel;
    let text = arguments.collect::<Vec<String>>().join(" ");
    if text.trim().is_empty() {
        eprintln!("missing text for --llm-perplexity");
        return ExitCode::from(2);
    }
    let model = security_agent::NeuralLanguageModel::bundled();
    println!("perplexity={:.3}", model.perplexity(&text));
    ExitCode::SUCCESS
}

/// Plain-English entry point (`--ask <instruction words...>`).
///
/// Interprets a natural-language instruction against the agent's own
/// capabilities using the fully-local grounded router
/// (`security_agent::nlu`), prints what it understood (intent, confidence,
/// and a plain-English reply), and then *carries out* the read-only,
/// no-authorization intents directly — reporting status, listing or
/// explaining tools/skills, generating text, or scoring a string for
/// anomaly. Intents that require an engagement, a persisted log, or
/// authorization are never executed here: the agent explains the exact
/// command to run instead, so `--ask` can plan nothing it is not allowed to.
fn ask_command(
    assets: &LocalAgentAssets,
    arguments: &mut impl Iterator<Item = String>,
) -> ExitCode {
    use security_agent::Intent;

    let instruction = arguments.collect::<Vec<String>>().join(" ");
    if instruction.trim().is_empty() {
        eprintln!("missing instruction for --ask");
        return ExitCode::from(2);
    }

    let model = security_agent::NeuralLanguageModel::bundled();
    let interpretation = security_agent::interpret(&instruction, assets, &model);

    println!(
        "Understood: {} (confidence {}%)",
        interpretation.intent.label(),
        interpretation.confidence
    );
    println!("{}", interpretation.reply);

    // Only the read-only, no-authorization intents actually run. Everything
    // that touches an engagement, a log, or authorization is described, not
    // executed, so plain English can never widen the agent's authority.
    let slot = interpretation.slot.as_deref();
    match interpretation.intent {
        Intent::OfflineStatus => {
            println!();
            print_offline_status(assets);
            ExitCode::SUCCESS
        }
        Intent::About => {
            println!();
            print_about()
        }
        Intent::ListTools => {
            println!();
            list_tools(assets)
        }
        Intent::ListSkills => {
            println!();
            list_skills(assets)
        }
        Intent::ShowSkill => ask_show_skill(assets, slot),
        Intent::Generate => ask_generate(&model, slot),
        Intent::AnomalyCheck => ask_anomaly(&model, slot),
        // Help prints the full plain-language guide (it's read-only, in scope,
        // and the natural answer to "help" / "what can you do").
        Intent::Help => {
            println!();
            guide_command(&mut std::iter::empty())
        }
        // PlanScan, ScheduleRetest, every ViewAudit/ViewAudit-Db-style
        // intent, OutOfScope: the reply already told the operator what to
        // do next; nothing to execute.
        Intent::PlanScan
        | Intent::ScheduleRetest
        | Intent::ViewAudit
        | Intent::ViewAuditDb
        | Intent::ViewFindingsDb
        | Intent::ViewCalibrationDb
        | Intent::ViewReasoningLogDb
        | Intent::OutOfScope => ExitCode::SUCCESS,
    }
}

/// Prints a resolved skill's body for `--ask` (the `ShowSkill` intent).
/// A missing or unrecognized skill name is a soft failure (exit 2) — the
/// interpretation's reply already told the operator what to try instead.
fn ask_show_skill(assets: &LocalAgentAssets, name: Option<&str>) -> ExitCode {
    let Some(name) = name else {
        return ExitCode::from(2);
    };
    let Some(skill) = assets.skill(name) else {
        return ExitCode::from(2);
    };
    println!();
    print!("{}", skill.content);
    ExitCode::SUCCESS
}

/// Continues an extracted prompt with the built-in language model for
/// `--ask` (the `Generate` intent). An empty prompt is a no-op success.
fn ask_generate(model: &security_agent::NeuralLanguageModel, prompt: Option<&str>) -> ExitCode {
    use security_agent::LanguageModel;
    let prompt = prompt.unwrap_or("").trim();
    if prompt.is_empty() {
        return ExitCode::SUCCESS;
    }
    let continuation = model.generate(prompt, 24);
    println!();
    if continuation.is_empty() {
        println!("{prompt}");
    } else {
        println!("{prompt} {continuation}");
    }
    ExitCode::SUCCESS
}

/// Scores extracted text for language-model surprise for `--ask` (the
/// `AnomalyCheck` intent), labelling it against
/// [`security_agent::DEFAULT_ANOMALY_THRESHOLD`]. Empty text is a no-op
/// success.
fn ask_anomaly(model: &security_agent::NeuralLanguageModel, text: Option<&str>) -> ExitCode {
    use security_agent::LanguageModel;
    let text = text.unwrap_or("").trim();
    if text.is_empty() {
        return ExitCode::SUCCESS;
    }
    let perplexity = model.perplexity(text);
    let verdict = if !perplexity.is_finite() || perplexity >= model.anomaly_threshold() {
        "ANOMALOUS (out-of-domain)"
    } else {
        "looks in-domain"
    };
    println!();
    if perplexity.is_finite() {
        println!("perplexity={perplexity:.3} — {verdict}");
    } else {
        println!("perplexity=inf — {verdict}");
    }
    ExitCode::SUCCESS
}

/// Interactive terminal UI (`--tui`): a menu- and chat-bar-driven REPL over
/// the exact same command functions the plain CLI dispatches to, so behavior
/// is identical either way — no duplicated business logic. Any input that
/// isn't a recognized menu token is routed through the plain-English `--ask`
/// router (the chat bar), so typing a natural-language instruction directly
/// at the prompt "talks to" the built-in language model and the rest of the
/// agent's capabilities. Reads lines from stdin; exits cleanly on
/// `q`/`quit`/`exit` or end-of-input (e.g. a piped, non-interactive stdin),
/// so it is scriptable and testable the same way the rest of the CLI is.
// The stdin lock is meant to be held for the whole interactive session, not
// tightened to a smaller scope.
#[allow(clippy::significant_drop_tightening)]
fn run_tui_command(assets: &LocalAgentAssets) -> ExitCode {
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    println!("{}", tui_banner());
    println!("{}", tui_menu());

    loop {
        print!("\n> ");
        let _ = io::stdout().flush();
        // Distinguish a real stdin I/O error from clean end-of-input: an
        // error is reported (to stderr, and distinctly on stdout) rather
        // than silently treated as a quiet, successful exit.
        let raw = match lines.next() {
            Some(Ok(line)) => line,
            Some(Err(error)) => {
                eprintln!("stdin read error: {error}");
                println!("\nstdin error — exiting.");
                break;
            }
            None => {
                println!("\n(end of input) goodbye.");
                break;
            }
        };
        let input = raw.trim();
        if input.is_empty() {
            continue;
        }
        if matches!(input.to_ascii_lowercase().as_str(), "q" | "quit" | "exit") {
            println!("goodbye.");
            break;
        }
        dispatch_tui_choice(input, assets, &mut lines);
    }
    ExitCode::SUCCESS
}

/// Runs one menu choice (or, for anything unrecognized, the plain-English
/// chat bar) against the shared command functions.
fn dispatch_tui_choice(
    input: &str,
    assets: &LocalAgentAssets,
    lines: &mut impl Iterator<Item = io::Result<String>>,
) {
    match input {
        "0" | "help" | "capabilities" => println!("{}", tui_capabilities_page(assets)),
        "1" => print_offline_status(assets),
        "2" => {
            let _ = print_about();
        }
        "3" => {
            let _ = list_tools(assets);
        }
        "4" => {
            let Some(name) = tui_prompt(lines, "skill or tool name: ") else {
                return;
            };
            if name.trim().is_empty() {
                println!("cancelled.");
                return;
            }
            let _ = show_skill(assets, &mut std::iter::once(name));
        }
        "5" => {
            let _ = list_skills(assets);
        }
        "6" => tui_run_builtin_tool(lines),
        "7" => tui_run_external_tool(lines, assets),
        "8" => {
            let _ = tui_plan_scan(lines);
        }
        "9" => tui_record_findings(lines),
        "10" => tui_run_with_prompted_path(lines, "audit log path: ", view_audit_command),
        "11" => tui_run_with_prompted_path(lines, "findings log path: ", schedule_retest_command),
        "12" => {
            let Some(prompt) = tui_prompt(lines, "prompt: ") else {
                return;
            };
            if prompt.trim().is_empty() {
                println!("cancelled.");
                return;
            }
            let _ = llm_generate_command(&mut std::iter::once(prompt));
        }
        "13" => {
            let Some(text) = tui_prompt(lines, "text to score: ") else {
                return;
            };
            if text.trim().is_empty() {
                println!("cancelled.");
                return;
            }
            let _ = llm_perplexity_command(&mut std::iter::once(text));
        }
        "14" => tui_listen(lines),
        "15" => tui_run_with_prompted_path(lines, "audit database path: ", view_audit_db_command),
        "16" => {
            tui_run_with_prompted_path(lines, "findings database path: ", view_findings_db_command);
        }
        "17" => tui_run_with_prompted_path(
            lines,
            "calibration database path: ",
            view_calibration_db_command,
        ),
        "18" => tui_run_with_prompted_path(
            lines,
            "reasoning log database path: ",
            view_reasoning_log_db_command,
        ),
        "19" => {
            let _ = guide_command(&mut std::iter::empty());
        }
        "20" => {
            let _ = shell_guide_command();
        }
        "21" => {
            let Some(name) = tui_prompt(lines, "command or tool name (e.g. --listen, nmap): ")
            else {
                return;
            };
            if name.trim().is_empty() {
                println!("cancelled.");
                return;
            }
            let _ = tool_help_command(&mut std::iter::once(name));
        }
        // The chat bar: anything else typed is a plain-English instruction,
        // routed through the same grounded router as `--ask`. Passed as one
        // already-trimmed line (not split into words) — `ask_command` joins
        // its arguments with spaces anyway, so a single element avoids
        // needless per-word allocations and preserves the line's internal
        // spacing exactly, matching how every other TUI prompt hands over
        // a full line rather than a word list.
        _ => {
            let _ = ask_command(assets, &mut std::iter::once(input.to_string()));
        }
    }
}

/// Prompts for a path and, if it's non-blank, runs `command` with it as
/// the sole argument -- the shared shape behind every TUI menu entry that
/// just needs "one path, then dispatch" (every `--view-*` command, plus
/// `schedule_retest_command`).
fn tui_run_with_prompted_path(
    lines: &mut impl Iterator<Item = io::Result<String>>,
    prompt: &str,
    command: fn(&mut std::iter::Once<String>) -> ExitCode,
) {
    let Some(path) = tui_prompt(lines, prompt) else {
        return;
    };
    if path.trim().is_empty() {
        println!("cancelled.");
        return;
    }
    let _ = command(&mut std::iter::once(path));
}

/// Reads one line from `lines`. Returns `None` at clean end-of-input (e.g. a
/// non-interactive/piped stdin that has been exhausted or closed) — and also
/// on a real stdin I/O error, but that case is reported to stderr first, so
/// it is never silently indistinguishable from a normal, quiet EOF.
fn tui_read_line(lines: &mut impl Iterator<Item = io::Result<String>>) -> Option<String> {
    match lines.next() {
        Some(Ok(line)) => Some(line),
        Some(Err(error)) => {
            eprintln!("stdin read error: {error}");
            None
        }
        None => None,
    }
}

/// Prints `prompt` (no trailing newline), flushes stdout, and reads the next
/// line of input.
fn tui_prompt(
    lines: &mut impl Iterator<Item = io::Result<String>>,
    prompt: &str,
) -> Option<String> {
    print!("{prompt}");
    let _ = io::stdout().flush();
    tui_read_line(lines)
}

/// Whether a prompted yes/no answer means "yes" (`y`/`yes`, case-insensitive;
/// anything else, including blank, means "no").
fn tui_answered_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Menu flow for `--run-tool <name> <path> [--output <path>.txt]`: one of
/// the offline, in-house local analyzers (autopsy, volatility, wireshark,
/// binwalk, foremost, `bulk_extractor`, hashdeep).
fn tui_run_builtin_tool(lines: &mut impl Iterator<Item = io::Result<String>>) {
    let Some(name) = tui_prompt(
        lines,
        "built-in tool (autopsy/volatility/wireshark/binwalk/foremost/bulk_extractor/hashdeep): ",
    ) else {
        return;
    };
    let name = name.trim().to_string();
    if name.is_empty() {
        println!("cancelled.");
        return;
    }
    let Some(path) = tui_prompt(lines, "local input path: ") else {
        return;
    };
    let path = path.trim().to_string();
    if path.is_empty() {
        println!("cancelled.");
        return;
    }
    let Some(output) = tui_prompt(lines, "output .txt path (blank to print to screen): ") else {
        return;
    };
    let mut args = vec![name, path];
    let output = output.trim();
    if !output.is_empty() {
        args.push("--output".to_string());
        args.push(output.to_string());
    }
    let _ = run_tool_command(&mut args.into_iter());
}

/// Menu flow for `--run-external-tool [--allow-network] <name> <args>`: a
/// real, locally installed cataloged tool. Live (`ActiveNetwork` /
/// `ActiveExploitation`) tools still require the explicit online opt-in,
/// which this flow asks for directly rather than assuming.
fn tui_run_external_tool(
    lines: &mut impl Iterator<Item = io::Result<String>>,
    assets: &LocalAgentAssets,
) {
    let Some(name) = tui_prompt(lines, "cataloged tool name: ") else {
        return;
    };
    let name = name.trim().to_string();
    if name.is_empty() {
        println!("cancelled.");
        return;
    }
    let Some(online) = tui_prompt(
        lines,
        "opt into live network / active testing for this run? (y/N): ",
    ) else {
        return;
    };
    let Some(extra) = tui_prompt(lines, "tool arguments (space-separated, blank for none): ")
    else {
        return;
    };
    let mut args = Vec::new();
    if tui_answered_yes(&online) {
        args.push("--allow-network".to_string());
    }
    args.push(name);
    args.extend(extra.split_whitespace().map(str::to_string));
    let _ = run_external_tool_command(assets, &mut args.into_iter());
}

/// Prompts for an optional `<flag> <path>` pair, pushing both onto `args`
/// only if a non-blank path is entered. Returns `None` at end-of-input
/// (propagated by the caller via `?`), `Some(())` otherwise -- including
/// when the prompt was left blank and skipped.
fn tui_optional_path_flag(
    lines: &mut impl Iterator<Item = io::Result<String>>,
    prompt: &str,
    flag: &str,
    args: &mut Vec<String>,
) -> Option<()> {
    let value = tui_prompt(lines, prompt)?;
    let value = value.trim();
    if !value.is_empty() {
        args.push(flag.to_string());
        args.push(value.to_string());
    }
    Some(())
}

/// Menu flow for `--plan-scan <config> [--audit-log <p>] [--audit-db <p>]
/// [--cognitive-review] [--memory <p>] [--calibration-db <p>]
/// [--findings-log <p>] [--findings-db <p>] [--reasoning-log-db <p>]
/// [--allow-network] [--execute <args>]`. Prompts follow the exact flag
/// order `parse_plan_scan_args` expects.
fn tui_plan_scan(lines: &mut impl Iterator<Item = io::Result<String>>) -> Option<()> {
    let config = tui_prompt(lines, "engagement config path: ")?;
    let config = config.trim().to_string();
    if config.is_empty() {
        println!("cancelled.");
        return Some(());
    }
    let mut args = vec![config];

    tui_optional_path_flag(
        lines,
        "audit log path (blank to skip): ",
        "--audit-log",
        &mut args,
    )?;
    tui_optional_path_flag(
        lines,
        "audit database path (blank to skip): ",
        "--audit-db",
        &mut args,
    )?;

    let review = tui_prompt(lines, "run cognitive review? (y/N): ")?;
    if tui_answered_yes(&review) {
        args.push("--cognitive-review".to_string());
    }

    tui_optional_path_flag(
        lines,
        "prior-findings memory log (blank to skip): ",
        "--memory",
        &mut args,
    )?;
    tui_optional_path_flag(
        lines,
        "calibration database path (blank to skip; only used with --cognitive-review): ",
        "--calibration-db",
        &mut args,
    )?;

    tui_optional_path_flag(
        lines,
        "findings log to append to (blank to skip; only used with --execute): ",
        "--findings-log",
        &mut args,
    )?;
    tui_optional_path_flag(
        lines,
        "findings database to append to (blank to skip; only used with --execute): ",
        "--findings-db",
        &mut args,
    )?;
    tui_optional_path_flag(
        lines,
        "reasoning log database (blank to skip; only used with --cognitive-review): ",
        "--reasoning-log-db",
        &mut args,
    )?;

    let execute = tui_prompt(lines, "execute approved tools now? (y/N): ")?;
    if tui_answered_yes(&execute) {
        let online = tui_prompt(
            lines,
            "opt into live network / active tools for execution? (y/N): ",
        )?;
        if tui_answered_yes(&online) {
            args.push("--allow-network".to_string());
        }
        args.push("--execute".to_string());
        let exec_args = tui_prompt(
            lines,
            "arguments passed to each executed tool (space-separated, blank for none): ",
        )?;
        args.extend(exec_args.split_whitespace().map(str::to_string));
    }

    let _ = plan_scan_command(&mut args.into_iter());
    Some(())
}

/// Menu flow for `--record-findings <destination-log> <source-log>`.
fn tui_record_findings(lines: &mut impl Iterator<Item = io::Result<String>>) {
    let Some(dest) = tui_prompt(lines, "destination findings log path: ") else {
        return;
    };
    let dest = dest.trim().to_string();
    if dest.is_empty() {
        println!("cancelled.");
        return;
    }
    let Some(src) = tui_prompt(lines, "source findings log path: ") else {
        return;
    };
    let src = src.trim().to_string();
    if src.is_empty() {
        println!("cancelled.");
        return;
    }
    let _ = record_findings_command(&mut vec![dest, src].into_iter());
}

fn tui_listen(lines: &mut impl Iterator<Item = io::Result<String>>) {
    let online = tui_prompt(
        lines,
        "opt into live network (opens a listening socket)? (y/N): ",
    );
    let Some(online) = online else {
        return;
    };
    if !tui_answered_yes(&online) {
        println!("cancelled — listener requires the --allow-network opt-in.");
        return;
    }
    let Some(port_str) = tui_prompt(lines, "port to listen on: ") else {
        return;
    };
    let port_str = port_str.trim().to_string();
    if port_str.is_empty() {
        println!("cancelled.");
        return;
    }
    let max_str = tui_prompt(lines, "max connections (empty for unlimited): ");
    let mut args = vec!["--listen".to_string(), port_str];
    if let Some(max) = max_str {
        let max = max.trim().to_string();
        if !max.is_empty() {
            args.push(max);
        }
    }
    let log_str = tui_prompt(lines, "session log path (empty to skip; JSON Lines): ");
    if let Some(log) = log_str {
        let log = log.trim().to_string();
        if !log.is_empty() {
            args.push("--log".to_string());
            args.push(log);
        }
    }
    let _ = listen_command(&mut args.into_iter(), true);
}

fn tui_banner() -> String {
    "Security-Agent — Interactive Terminal UI\n\
     =========================================\n\
     Defensive and offensive security orchestration agent (see --about).\n\
     Offline by default; live/active tools need the --allow-network opt-in.\n\
     Type a menu number below, or type a plain-English instruction and press\n\
     Enter — that's the chat bar, routed through the same grounded router as\n\
     --ask, including prompting the built-in language model. Type '0' for the\n\
     full capability summary, or 'q' / 'quit' / 'exit' to leave."
        .to_string()
}

fn tui_menu() -> String {
    "\n\
     [1]  Offline status              [2]  About\n\
     [3]  List tools                  [4]  Show a skill or tool\n\
     [5]  List skills                 [6]  Run a built-in local tool\n\
     [7]  Run a real external tool    [8]  Plan a scan (engagement config)\n\
     [9]  Record findings (merge)     [10] View audit log\n\
     [11] Schedule retest             [12] Generate text (LLM)\n\
     [13] Score text for anomaly (LLM) [14] Reverse shell listener\n\
     [15] View audit database          [16] View findings database\n\
     [17] View calibration database    [18] View reasoning log database\n\
     [19] Plain-language guide          [20] Reverse shell tutorial\n\
     [21] Guide for one tool/command   [0]  Help / full capability summary\n\
     [q] Quit"
        .to_string()
}

/// (function, CLI command, plain-English chat-bar example or note) for every
/// capability the agent exposes.
const CAPABILITY_ROWS: &[(&str, &str, &str)] = &[
    (
        "Offline status",
        "--offline-status",
        "\"are you healthy\" / \"what is your status\"",
    ),
    (
        "About / mission",
        "--about",
        "\"who are you\" / \"what is your mission\"",
    ),
    ("List tools", "--list-tools", "\"what tools do you have\""),
    (
        "List skills",
        "--list-skills",
        "\"what skills do you have\"",
    ),
    (
        "Show a skill/tool",
        "--show-skill <name>",
        "\"explain the nmap skill\"",
    ),
    (
        "Generate text (LLM)",
        "--llm-generate <words>",
        "\"generate text about scanning targets\"",
    ),
    (
        "Score text for anomaly (LLM)",
        "--llm-perplexity <words>",
        "\"is this suspicious: <quoted text>\"",
    ),
    (
        "Plan a scan",
        "--plan-scan <config> [...]",
        "\"plan a scan of the target\" (explains the command; not executed by chat)",
    ),
    (
        "Schedule a retest",
        "--schedule-retest <log>",
        "\"schedule a retest\" (explains the command)",
    ),
    (
        "View audit log",
        "--view-audit <log>",
        "\"show the audit log\" (explains the command)",
    ),
    (
        "View audit database",
        "--view-audit-db <db>",
        "\"show the audit database\" (explains the command)",
    ),
    (
        "View findings database",
        "--view-findings-db <db>",
        "\"show the findings database\" (explains the command)",
    ),
    (
        "View calibration database",
        "--view-calibration-db <db>",
        "\"show the calibration database\" (explains the command)",
    ),
    (
        "View reasoning log database",
        "--view-reasoning-log-db <db>",
        "\"show the reasoning log\" (explains the command)",
    ),
    (
        "Run a built-in local tool",
        "--run-tool <name> <path>",
        "not routed through the chat bar; use the menu or CLI",
    ),
    (
        "Run a real external tool",
        "--run-external-tool [--allow-network] <name> <args>",
        "not routed through the chat bar; use the menu or CLI",
    ),
    (
        "Record findings (merge logs)",
        "--record-findings <dst> <src>",
        "not routed through the chat bar; use the menu or CLI",
    ),
    (
        "Start reverse shell listener",
        "--listen <port> [max-connections] [bind-address]",
        "not routed through the chat bar; use the menu or CLI",
    ),
    (
        "Plain-English router",
        "--ask <instruction>",
        "any of the above, in your own words",
    ),
    (
        "Plain-language guide (all commands)",
        "--guide [section]",
        "\"show me the guide\"",
    ),
    (
        "Reverse shell tutorial",
        "--shell-guide",
        "\"how do i use a reverse shell\"",
    ),
    (
        "Guide for one tool/command",
        "--tool-help <command-or-tool>",
        "\"how do i use --listen\"",
    ),
];

/// The full capability summary: every function this agent exposes, its CLI
/// command, and (where routed through the plain-English chat bar) an example
/// natural-language prompt. Shown by menu option `0`/`help`/`capabilities`.
fn tui_capabilities_page(assets: &LocalAgentAssets) -> String {
    use std::fmt::Write as _;
    let mut page = String::new();
    let _ = writeln!(page, "Security-Agent — Capability Summary");
    let _ = writeln!(page, "====================================");
    let _ = writeln!(
        page,
        "{} cataloged tools ({} built-in offline substitutes), {} embedded skills.",
        assets.tools().len(),
        assets.tools().iter().filter(|tool| tool.built_in).count(),
        assets.skills().len()
    );
    let _ = writeln!(page);
    let _ = writeln!(
        page,
        "{:<30}{:<52}Plain-English example (--ask / chat bar)",
        "Function", "CLI command"
    );
    let _ = writeln!(page, "{}", "-".repeat(110));
    for (function, command, example) in CAPABILITY_ROWS {
        let _ = writeln!(page, "{function:<30}{command:<52}{example}");
    }
    let _ = writeln!(page);
    let _ = write!(
        page,
        "Offline by default; live/active tools require the explicit --allow-network \
         opt-in (see --offline-status). The chat bar only executes the read-only, \
         no-authorization functions above that have a plain-English example; \
         everything else needs the menu or the exact CLI command shown."
    );
    page
}

/// Read-only view of a persisted audit log (`--view-audit <path>.jsonl`).
///
/// This command never plans, authorizes, executes, or writes — it only
/// loads and renders existing records. That is exactly the surface the
/// `Viewer` role (`security_agent::Role::Viewer`) exists for, so the view
/// is rendered as operating under that role. Loading a missing or
/// unreadable file is an error (exit 1); a readable but empty/foreign log
/// simply shows no records.
fn view_audit_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(path) = arguments.next() else {
        eprintln!("missing audit log file path");
        return ExitCode::from(2);
    };
    match security_agent::load_audit_records(Path::new(&path)) {
        Ok(records) => {
            // Read-only consumers operate under the least-privilege Viewer role.
            let role = security_agent::Role::Viewer;
            println!("Audit Log View (role: {role})");
            println!("=============================");
            if records.is_empty() {
                println!("No audit records found.");
            } else {
                for record in &records {
                    println!(
                        "{}\tactor={}\trole={}\taction={}\ttarget={}",
                        record.timestamp_epoch_seconds,
                        record.actor,
                        record.role,
                        record.action,
                        record.target
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("failed to read audit log: {error}");
            ExitCode::from(1)
        }
    }
}

/// Reads a persisted findings log (`--schedule-retest <path>.jsonl`) and
/// emits a retest schedule for every finding via
/// [`security_agent::propose_retest_schedule`], sorted by soonest retest
/// first. Surfaces that scheduler from a real CLI path for the first time.
fn schedule_retest_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(path) = arguments.next() else {
        eprintln!("missing findings log file path");
        return ExitCode::from(2);
    };
    match security_agent::load_findings(Path::new(&path)) {
        Ok(findings) => {
            let now = current_epoch_seconds();
            let mut schedules: Vec<security_agent::RetestSchedule> = findings
                .iter()
                .map(|finding| security_agent::propose_retest_schedule(finding, now))
                .collect();
            schedules.sort_by_key(|schedule| schedule.next_retest_epoch_seconds);

            println!("Retest Schedule");
            println!("===============");
            if schedules.is_empty() {
                println!("No findings in log.");
            } else {
                for schedule in &schedules {
                    println!(
                        "{}\tnext_retest_epoch_seconds={}\treason={}",
                        schedule.target_id, schedule.next_retest_epoch_seconds, schedule.reason
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("failed to read findings log: {error}");
            ExitCode::from(1)
        }
    }
}

/// Renders an engagement report from a persisted findings log.
///
/// `--report <findings-log> [--format sarif|json|markdown] [--evidence
/// <path>] [--engagement <id>]`. Loads the findings, correlates them
/// (dedup + cross-tool corroboration), optionally attaches an evidence log,
/// and writes the chosen deliverable to stdout (Markdown by default). See
/// [`security_agent::report`].
fn report_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(findings_path) = arguments.next() else {
        eprintln!(
            "usage: --report <findings-log> [--format sarif|json|markdown] \
             [--evidence <path>] [--engagement <id>]"
        );
        return ExitCode::from(2);
    };

    let mut format = "markdown".to_string();
    let mut evidence_path: Option<String> = None;
    let mut engagement_id = "engagement".to_string();
    while let Some(flag) = arguments.next() {
        let Some(value) = arguments.next() else {
            eprintln!("{flag} requires a value");
            return ExitCode::from(2);
        };
        match flag.as_str() {
            "--format" => format = value,
            "--evidence" => evidence_path = Some(value),
            "--engagement" => engagement_id = value,
            other => {
                eprintln!("unknown --report option: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let findings = match security_agent::load_findings(Path::new(&findings_path)) {
        Ok(findings) => findings,
        Err(error) => {
            eprintln!("failed to read findings log: {error}");
            return ExitCode::from(1);
        }
    };
    let correlated = security_agent::correlate(&findings);

    let evidence = match &evidence_path {
        Some(path) => match security_agent::load_evidence(Path::new(path)) {
            Ok(records) => records,
            Err(error) => {
                eprintln!("failed to read evidence log: {error}");
                return ExitCode::from(1);
            }
        },
        None => Vec::new(),
    };

    let inputs = security_agent::ReportInputs {
        engagement_id: &engagement_id,
        findings: &correlated,
        evidence: &evidence,
        generated_at_epoch: current_epoch_seconds(),
    };

    let output = match format.as_str() {
        "sarif" => security_agent::render_sarif(&correlated),
        "json" => security_agent::render_report_json(&inputs),
        "markdown" | "md" => security_agent::render_markdown(&inputs),
        other => {
            eprintln!("unknown format: {other} (want sarif|json|markdown)");
            return ExitCode::from(2);
        }
    };
    print!("{output}");
    ExitCode::SUCCESS
}

/// Read-only view of a persisted `.sadb` audit database
/// (`--view-audit-db <path>.sadb`). Same role as [`view_audit_command`],
/// backed by [`security_agent::audit_db`] instead of JSON Lines.
fn view_audit_db_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(path) = arguments.next() else {
        eprintln!("missing audit database file path");
        return ExitCode::from(2);
    };
    match security_agent::audit_db::load_audit_records(Path::new(&path)) {
        Ok(records) => {
            let role = security_agent::Role::Viewer;
            println!("Audit Database View (role: {role})");
            println!("================================");
            if records.is_empty() {
                println!("No audit records found.");
            } else {
                for record in &records {
                    println!(
                        "{}\tactor={}\trole={}\taction={}\ttarget={}",
                        record.timestamp_epoch_seconds,
                        record.actor,
                        record.role,
                        record.action,
                        record.target
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("failed to read audit database: {error}");
            ExitCode::from(1)
        }
    }
}

/// Read-only view of a persisted `.sadb` findings database
/// (`--view-findings-db <path>.sadb`).
///
/// There is no JSON Lines equivalent command: a `.jsonl` findings log can
/// be read directly with any text tool, but `.sadb`'s binary page format
/// has no such fallback -- which is exactly why this command exists.
fn view_findings_db_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(path) = arguments.next() else {
        eprintln!("missing findings database file path");
        return ExitCode::from(2);
    };
    match security_agent::findings_db::load_findings(Path::new(&path)) {
        Ok(findings) => {
            let role = security_agent::Role::Viewer;
            println!("Findings Database View (role: {role})");
            println!("==================================");
            if findings.is_empty() {
                println!("No findings found.");
            } else {
                for finding in &findings {
                    println!(
                        "{}\tsource={}\tseverity={}\tconfidence={}%\trisk={:.1}\ttarget={}\t{}",
                        finding.finding_id,
                        finding.source_tool,
                        finding.severity,
                        finding.confidence_percent,
                        finding.normalized_risk_score,
                        finding.target_id,
                        finding.title
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("failed to read findings database: {error}");
            ExitCode::from(1)
        }
    }
}

/// Read-only view of a persisted `.sadb` calibration database
/// (`--view-calibration-db <path>.sadb`): the accumulated
/// `(predicted_percent, occurred)` history plus the metrics
/// [`security_agent::CalibrationTracker`] derives from it.
///
/// Surfaces those metrics through the CLI for the first time -- until now
/// they existed only in library code with no command reading them.
fn view_calibration_db_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(path) = arguments.next() else {
        eprintln!("missing calibration database file path");
        return ExitCode::from(2);
    };
    match security_agent::calibration_db::load_calibration(Path::new(&path)) {
        Ok(tracker) => {
            let role = security_agent::Role::Viewer;
            println!("Calibration Database View (role: {role})");
            println!("====================================");
            if tracker.is_empty() {
                println!("No calibration records found.");
                return ExitCode::SUCCESS;
            }
            println!("Records: {}", tracker.len());
            if let Some(mean_predicted) = tracker.mean_predicted() {
                println!("Mean predicted confidence: {:.1}%", mean_predicted * 100.0);
            }
            if let Some(empirical_rate) = tracker.empirical_rate() {
                println!("Empirical hit rate:        {:.1}%", empirical_rate * 100.0);
            }
            if let Some(brier_score) = tracker.brier_score() {
                println!("Brier score:                {brier_score:.4}");
            }
            if let Some(mean_error) = tracker.mean_calibration_error() {
                println!("Mean calibration error:     {:.1} pts", mean_error * 100.0);
            }
            if let Some(tendency) = tracker.tendency(0.1) {
                println!("Tendency:                   {tendency}");
            }
            println!();
            println!("Reliability bins:");
            for bin in tracker.reliability_bins(5) {
                if bin.count == 0 {
                    continue;
                }
                println!(
                    "  [{:>3}-{:<3}%)  n={:<4}  predicted={:.1}%  actual={:.1}%",
                    bin.lower_percent,
                    bin.upper_percent,
                    bin.count,
                    bin.mean_predicted * 100.0,
                    bin.empirical_rate * 100.0
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("failed to read calibration database: {error}");
            ExitCode::from(1)
        }
    }
}

/// Read-only view of a persisted `.sadb` reasoning-log database
/// (`--view-reasoning-log-db <path>.sadb`): every archived
/// `--cognitive-review` run's full train of thought and metacognitive
/// verdict, oldest first.
///
/// This is the whole reason [`security_agent::reasoning_log_db`] exists --
/// auditable, after-the-fact explainability -- so without this command
/// that archive had no way to actually be read by a person.
fn view_reasoning_log_db_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(path) = arguments.next() else {
        eprintln!("missing reasoning log database file path");
        return ExitCode::from(2);
    };
    match security_agent::reasoning_log_db::load_runs(Path::new(&path)) {
        Ok(runs) => {
            let role = security_agent::Role::Viewer;
            println!("Reasoning Log Database View (role: {role})");
            println!("=======================================");
            if runs.is_empty() {
                println!("No reasoning runs found.");
                return ExitCode::SUCCESS;
            }
            for (index, run) in runs.iter().enumerate() {
                println!();
                println!(
                    "Run {} @ {}  (overall confidence: {}%)",
                    index + 1,
                    run.timestamp_epoch_seconds,
                    run.reasoning_chain.overall_confidence()
                );
                for thought in run.reasoning_chain.thoughts() {
                    println!(
                        "  [{}] {} ({}%)",
                        thought.kind, thought.statement, thought.confidence_percent
                    );
                }
                println!(
                    "  Metacognition: self-assessed {}%, uncertainty {:.2}, escalate={}",
                    run.metacognition.self_assessed_confidence,
                    run.metacognition.uncertainty,
                    run.metacognition.should_escalate
                );
                println!("    {}", run.metacognition.reasoning);
                for gap in &run.metacognition.knowledge_gaps {
                    println!("    knowledge gap: {gap}");
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("failed to read reasoning log database: {error}");
            ExitCode::from(1)
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

// ─── Offensive Toolkit CLI Commands ──────────────────────────────────────────

/// `--hash-id <hash>` — identify hash type and suggest cracking tools.
fn hash_id_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(hash) = arguments.next() else {
        eprintln!("usage: --hash-id <hash>");
        return ExitCode::from(2);
    };
    if let Some(extra) = arguments.next() {
        eprintln!("unexpected argument: {extra}");
        return ExitCode::from(2);
    }
    let analysis = security_agent::offensive::credential_attack::identify_hash(&hash);
    println!("{analysis}");
    ExitCode::SUCCESS
}

/// `--password-strength <password>` — analyze password entropy and crack resistance.
fn password_strength_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(password) = arguments.next() else {
        eprintln!("usage: --password-strength <password>");
        return ExitCode::from(2);
    };
    if let Some(extra) = arguments.next() {
        eprintln!("unexpected argument: {extra}");
        return ExitCode::from(2);
    }
    let analysis =
        security_agent::offensive::credential_attack::analyze_password_strength(&password);
    println!("{analysis}");
    ExitCode::SUCCESS
}

/// `--gen-wordlist <target> [--company <name>] [--year <year>]` — generate targeted wordlist.
fn gen_wordlist_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(target) = arguments.next() else {
        eprintln!("usage: --gen-wordlist <target> [--company <name>] [--year <year>]");
        return ExitCode::from(2);
    };
    let mut company = None;
    let mut year = None;
    let mut next = arguments.next();
    while let Some(arg) = next.take() {
        match arg.as_str() {
            "--company" => {
                company = arguments.next();
                next = arguments.next();
            }
            "--year" => {
                year = arguments.next();
                next = arguments.next();
            }
            other => {
                eprintln!("unexpected argument: {other}");
                return ExitCode::from(2);
            }
        }
    }
    let words = security_agent::offensive::credential_attack::generate_targeted_wordlist(
        &target,
        company.as_deref(),
        year.as_deref(),
        &[],
    );
    println!("Generated {} words for target: {target}", words.len());
    for word in &words {
        println!("{word}");
    }
    ExitCode::SUCCESS
}

/// `--gen-shell <type> <lhost> <lport>` — generate a reverse/bind shell payload.
/// `--gen-shell --list` — print the full shell-type catalog.
fn gen_shell_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    use security_agent::offensive::payload_gen::ShellType;

    let Some(shell_type) = arguments.next() else {
        eprintln!("usage: --gen-shell <type> <lhost> <lport>");
        eprintln!("       --gen-shell --list");
        eprintln!();
        eprintln!("types: bash, netcat, python, perl, ruby, php, tcp, powershell, bind,");
        eprintln!("       meterpreter, http, https");
        eprintln!("run `--gen-shell --list` for the full catalog with descriptions.");
        return ExitCode::from(2);
    };

    // `--gen-shell --list` prints the catalog without needing lhost/lport.
    if shell_type == "--list" {
        println!("Shell Payload Catalog");
        println!("=====================");
        for entry in ShellType::catalog() {
            println!(
                "  {:<12} aliases: {}",
                entry.shell_type,
                entry.aliases.join(", ")
            );
            println!("  {:<12} platform: {}", "", entry.platform);
            println!("  {:<12} {}", "", entry.description);
            println!();
        }
        return ExitCode::SUCCESS;
    }

    let Some(lhost) = arguments.next() else {
        eprintln!("missing lhost");
        eprintln!("usage: --gen-shell <type> <lhost> <lport>");
        return ExitCode::from(2);
    };
    let Some(lport_str) = arguments.next() else {
        eprintln!("missing lport");
        eprintln!("usage: --gen-shell <type> <lhost> <lport>");
        return ExitCode::from(2);
    };
    if let Some(extra) = arguments.next() {
        eprintln!("unexpected argument: {extra}");
        return ExitCode::from(2);
    }
    let lport: u16 = if let Ok(p) = lport_str.parse() {
        p
    } else {
        eprintln!("invalid lport: {lport_str}");
        return ExitCode::from(2);
    };

    let Some(st) = ShellType::parse(&shell_type) else {
        eprintln!("unknown shell type: {shell_type}");
        eprintln!(
            "valid types: {}",
            ShellType::catalog()
                .iter()
                .flat_map(|entry| entry.aliases.iter().copied())
                .collect::<Vec<_>>()
                .join(", ")
        );
        return ExitCode::from(2);
    };

    let payload = security_agent::offensive::payload_gen::generate_reverse_shell(st, &lhost, lport);
    println!("{payload}");
    ExitCode::SUCCESS
}

/// `--analyze-payload <payload>` — analyze a payload for shellcode patterns and detection risk.
fn analyze_payload_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(payload) = arguments.next() else {
        eprintln!("usage: --analyze-payload <payload>");
        return ExitCode::from(2);
    };
    if let Some(extra) = arguments.next() {
        eprintln!("unexpected argument: {extra}");
        return ExitCode::from(2);
    }
    let analysis = security_agent::offensive::payload_gen::analyze_payload(&payload);
    println!("{analysis}");

    let suggestions = security_agent::offensive::payload_gen::suggest_evasion(&analysis);
    if !suggestions.is_empty() {
        println!("\nEvasion Suggestions");
        println!("===================");
        for s in &suggestions {
            println!("{s}");
        }
    }
    ExitCode::SUCCESS
}

/// `--obfuscate-ps <command>` — apply `PowerShell` obfuscation techniques.
fn obfuscate_ps_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(command) = arguments.next() else {
        eprintln!("usage: --obfuscate-ps <command>");
        return ExitCode::from(2);
    };
    if let Some(extra) = arguments.next() {
        eprintln!("unexpected argument: {extra}");
        return ExitCode::from(2);
    }
    let results = security_agent::offensive::evasion::obfuscate_powershell(&command);
    println!("Applied {} obfuscation techniques:\n", results.len());
    for r in &results {
        println!("{r}");
        println!();
    }
    ExitCode::SUCCESS
}

/// `--gen-decoys <real-ip> [count]` — generate decoy IPs for scan obfuscation.
fn gen_decoys_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(real_ip) = arguments.next() else {
        eprintln!("usage: --gen-decoys <real-ip> [count]");
        return ExitCode::from(2);
    };
    let count: usize = arguments.next().and_then(|s| s.parse().ok()).unwrap_or(5);
    let decoys = security_agent::offensive::evasion::generate_decoys(&real_ip, count);
    println!("{decoys}");
    ExitCode::SUCCESS
}

/// `--listen <port> [max-connections] [bind-address] [--log <path>]` —
/// start a reverse shell listener.
///
/// The listener opens a listening socket, so it runs only with the explicit
/// `--allow-network` opt-in for the invocation (fail-closed otherwise): the
/// caller's `main` consumed the leading flag and passes `allow_network`.
fn listen_command(arguments: &mut impl Iterator<Item = String>, allow_network: bool) -> ExitCode {
    use security_agent::offensive::listener::{ListenerConfig, start_listener};

    if !allow_network {
        eprintln!("--listen requires the explicit --allow-network opt-in.");
        eprintln!("re-run as: security-agent --allow-network --listen <port>");
        eprintln!("the runtime is offline by default; opening a listener is a deliberate,");
        eprintln!("per-invocation, auditable choice.");
        return ExitCode::from(2);
    }

    let Some(port_str) = arguments.next() else {
        eprintln!("usage: --listen <port> [max-connections] [bind-address] [--log <path>]");
        eprintln!();
        eprintln!("Starts a TCP reverse shell listener that catches inbound connections");
        eprintln!("from targets where a payload (generated by --gen-shell) has been executed.");
        eprintln!();
        eprintln!("examples:");
        eprintln!(
            "  --listen 4444                        # listen on port 4444, unlimited connections"
        );
        eprintln!("  --listen 4444 5                      # accept at most 5 connections");
        eprintln!("  --listen 4444 5 192.168.1.100         # bind to a specific interface");
        eprintln!("  --listen 4444 --log sessions.jsonl    # persist session records (JSON Lines)");
        eprintln!();
        eprintln!("requires --allow-network (opens a listening socket)");
        return ExitCode::from(2);
    };
    let port: u16 = if let Ok(p) = port_str.parse() {
        p
    } else {
        eprintln!("invalid port: {port_str}");
        return ExitCode::from(2);
    };

    // Parse optional positionals (max-connections, bind-address) and the
    // optional `--log <path>` flag in any order.
    let mut max_conn: Option<u32> = None;
    let mut bind_addr = "0.0.0.0".to_string();
    let mut session_log: Option<std::path::PathBuf> = None;
    let mut seen_bind = false;
    while let Some(arg) = arguments.next() {
        match arg.as_str() {
            "--log" => {
                let Some(path) = arguments.next() else {
                    eprintln!("--log requires a path");
                    return ExitCode::from(2);
                };
                session_log = Some(std::path::PathBuf::from(path));
            }
            other => {
                if let Ok(n) = other.parse::<u32>() {
                    if max_conn.is_none() {
                        max_conn = Some(n);
                        continue;
                    }
                    eprintln!("duplicate max-connections: {other}");
                    return ExitCode::from(2);
                }
                if seen_bind {
                    eprintln!("unexpected argument: {other}");
                    return ExitCode::from(2);
                }
                bind_addr = other.to_string();
                seen_bind = true;
            }
        }
    }

    let config = ListenerConfig {
        bind_address: bind_addr,
        port,
        max_connections: max_conn,
        io_timeout: Some(std::time::Duration::from_secs(300)),
        session_log,
    };

    match start_listener(&config) {
        Ok(_summary) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

/// `--analyze-handshake <eapol-hex...>` — analyze EAPOL frames for WPA handshake completeness.
fn analyze_handshake_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let frames: Vec<Vec<u8>> = arguments.map(|hex_str| hex_to_bytes(&hex_str)).collect();
    if frames.is_empty() {
        eprintln!("usage: --analyze-handshake <eapol-hex-frame1> [frame2] ...");
        eprintln!("pass raw EAPOL frames as hex strings");
        return ExitCode::from(2);
    }
    let info = security_agent::offensive::wireless::analyze_eapol_frames(&frames);
    println!("{info}");
    ExitCode::SUCCESS
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim().trim_start_matches("0x");
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| {
            hex.get(i..i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
        .collect()
}

/// `--wps-pin <pin>` — analyze a WPS PIN for default/vulnerable status.
fn wps_pin_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(pin) = arguments.next() else {
        eprintln!("usage: --wps-pin <pin>");
        return ExitCode::from(2);
    };
    if let Some(extra) = arguments.next() {
        eprintln!("unexpected argument: {extra}");
        return ExitCode::from(2);
    }
    let info = security_agent::offensive::wireless::analyze_wps_pin(&pin);
    println!("{info}");
    ExitCode::SUCCESS
}

/// `--audit-wifi <essid> <security> <encryption>` — audit wireless network security.
fn audit_wifi_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(essid) = arguments.next() else {
        eprintln!("usage: --audit-wifi <essid> <security-protocol> <encryption>");
        eprintln!("example: --audit-wifi MyNetwork wpa2 aes");
        return ExitCode::from(2);
    };
    let Some(security) = arguments.next() else {
        eprintln!("missing security protocol (open/wep/wpa/wpa2/wpa3)");
        return ExitCode::from(2);
    };
    let Some(encryption) = arguments.next() else {
        eprintln!("missing encryption type (none/wep/tkip/aes/ccmp)");
        return ExitCode::from(2);
    };
    if let Some(extra) = arguments.next() {
        eprintln!("unexpected argument: {extra}");
        return ExitCode::from(2);
    }
    let audit = security_agent::offensive::wireless::audit_wireless_security(
        &essid,
        &security,
        &encryption,
    );
    println!("{audit}");
    ExitCode::SUCCESS
}

/// `--analyze-passwd <content>` — analyze /etc/passwd for privilege escalation indicators.
fn analyze_passwd_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(path_or_content) = arguments.next() else {
        eprintln!("usage: --analyze-passwd <path-to-passwd-or-content>");
        return ExitCode::from(2);
    };
    if let Some(extra) = arguments.next() {
        eprintln!("unexpected argument: {extra}");
        return ExitCode::from(2);
    }
    let content = if std::path::Path::new(&path_or_content).exists() {
        fs::read_to_string(&path_or_content).unwrap_or_default()
    } else {
        path_or_content
    };
    let indicators = security_agent::offensive::post_exploit::analyze_passwd_file(&content);
    if indicators.is_empty() {
        println!("No privilege escalation indicators found.");
    } else {
        println!("Privilege Escalation Indicators ({})", indicators.len());
        println!("=================================");
        for ind in &indicators {
            println!("{ind}");
        }
    }
    ExitCode::SUCCESS
}

/// `--analyze-sudoers <content>` — analyze sudoers for risky configurations.
fn analyze_sudoers_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(path_or_content) = arguments.next() else {
        eprintln!("usage: --analyze-sudoers <path-to-sudoers-or-content>");
        return ExitCode::from(2);
    };
    if let Some(extra) = arguments.next() {
        eprintln!("unexpected argument: {extra}");
        return ExitCode::from(2);
    }
    let content = if std::path::Path::new(&path_or_content).exists() {
        fs::read_to_string(&path_or_content).unwrap_or_default()
    } else {
        path_or_content
    };
    let indicators = security_agent::offensive::post_exploit::analyze_sudoers(&content);
    if indicators.is_empty() {
        println!("No risky sudoers configurations found.");
    } else {
        println!("Sudoers Issues ({})", indicators.len());
        println!("===============");
        for ind in &indicators {
            println!("{ind}");
        }
    }
    ExitCode::SUCCESS
}

/// `--analyze-keys <content>` — analyze SSH `authorized_keys` for lateral movement indicators.
fn analyze_keys_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(path_or_content) = arguments.next() else {
        eprintln!("usage: --analyze-keys <path-to-authorized_keys-or-content>");
        return ExitCode::from(2);
    };
    if let Some(extra) = arguments.next() {
        eprintln!("unexpected argument: {extra}");
        return ExitCode::from(2);
    }
    let content = if std::path::Path::new(&path_or_content).exists() {
        fs::read_to_string(&path_or_content).unwrap_or_default()
    } else {
        path_or_content
    };
    let indicators = security_agent::offensive::post_exploit::analyze_authorized_keys(&content);
    if indicators.is_empty() {
        println!("No lateral movement indicators found.");
    } else {
        println!("Lateral Movement Indicators ({})", indicators.len());
        println!("=============================");
        for ind in &indicators {
            println!("{ind}");
        }
    }
    ExitCode::SUCCESS
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
    fn parse_output_argument_defaults_to_none_with_no_more_arguments() {
        let mut arguments = std::iter::empty::<String>();
        assert_eq!(parse_output_argument(&mut arguments), Ok(None));
    }

    #[test]
    fn parse_output_argument_accepts_a_txt_path() {
        let mut arguments = vec!["--output".to_string(), "report.txt".to_string()].into_iter();
        assert_eq!(
            parse_output_argument(&mut arguments),
            Ok(Some("report.txt".to_string()))
        );
    }

    #[test]
    fn parse_output_argument_rejects_a_non_txt_extension() {
        let mut arguments = vec!["--output".to_string(), "report.bin".to_string()].into_iter();
        assert!(parse_output_argument(&mut arguments).is_err());
    }

    #[test]
    fn parse_output_argument_rejects_a_missing_path_after_flag() {
        let mut arguments = vec!["--output".to_string()].into_iter();
        assert!(parse_output_argument(&mut arguments).is_err());
    }

    #[test]
    fn parse_output_argument_rejects_an_unknown_argument() {
        let mut arguments = vec!["--bogus".to_string()].into_iter();
        assert!(parse_output_argument(&mut arguments).is_err());
    }

    #[test]
    fn about_reports_success() {
        assert_eq!(print_about(), ExitCode::SUCCESS);
    }

    #[test]
    fn list_skills_reports_success() {
        let assets = LocalAgentAssets::bundled();
        assert_eq!(list_skills(&assets), ExitCode::SUCCESS);
    }

    #[test]
    fn list_tools_reports_success() {
        let assets = LocalAgentAssets::bundled();
        assert_eq!(list_tools(&assets), ExitCode::SUCCESS);
    }

    #[test]
    fn show_skill_reports_success_for_a_known_skill() {
        let assets = LocalAgentAssets::bundled();
        let mut arguments = vec!["security-agent".to_string()].into_iter();
        assert_eq!(show_skill(&assets, &mut arguments), ExitCode::SUCCESS);
    }

    #[test]
    fn show_skill_reports_failure_for_an_unknown_skill() {
        let assets = LocalAgentAssets::bundled();
        let mut arguments = vec!["no-such-skill".to_string()].into_iter();
        assert_ne!(show_skill(&assets, &mut arguments), ExitCode::SUCCESS);
    }

    #[test]
    fn show_skill_reports_failure_with_no_name_given() {
        let assets = LocalAgentAssets::bundled();
        let mut arguments = std::iter::empty::<String>();
        assert_ne!(show_skill(&assets, &mut arguments), ExitCode::SUCCESS);
    }

    #[test]
    fn run_tool_command_reports_success_for_autopsy_on_a_real_file() {
        let path = std::env::current_exe().expect("resolve current test executable");
        let mut arguments =
            vec!["autopsy".to_string(), path.to_string_lossy().into_owned()].into_iter();
        assert_eq!(run_tool_command(&mut arguments), ExitCode::SUCCESS);
    }

    #[test]
    fn run_tool_command_reports_failure_for_an_unsupported_tool() {
        let mut arguments = vec!["not-a-real-tool".to_string(), "/tmp".to_string()].into_iter();
        assert_ne!(run_tool_command(&mut arguments), ExitCode::SUCCESS);
    }

    #[test]
    fn write_or_print_report_writes_to_a_txt_file() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-main-write-report-{}.txt",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        let outcome = write_or_print_report(
            "example",
            "report body".to_string(),
            Some(path.to_string_lossy().into_owned()),
        );

        assert_eq!(outcome, ExitCode::SUCCESS);
        let written = fs::read_to_string(&path).expect("report file should exist");
        fs::remove_file(&path).expect("remove temp report");
        assert_eq!(written, "report body");
    }

    #[test]
    fn write_or_print_report_prints_when_no_output_path_given() {
        assert_eq!(
            write_or_print_report("example", "report body".to_string(), None),
            ExitCode::SUCCESS
        );
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

        let (plan, assessment, outcomes, findings) =
            result.expect("valid config should authorize and plan");
        assert_eq!(plan.engagement_id, "eng-cli-test");
        assert!(!plan.tasks.is_empty());
        assert!(outcomes.is_none(), "no --execute flag was given");
        assert!(assessment.is_none(), "no --cognitive-review flag was given");
        assert!(findings.is_empty(), "no --execute flag was given");
    }

    #[test]
    fn plan_scan_runs_cognitive_review_when_flag_is_given() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-cognitive-{}.txt",
            std::process::id()
        ));
        fs::write(
            &path,
            "\
engagement_id=eng-cli-cognitive
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

        let mut arguments = vec![
            path.to_string_lossy().into_owned(),
            "--cognitive-review".to_string(),
        ]
        .into_iter();
        let result = plan_scan(&mut arguments);
        fs::remove_file(&path).expect("remove temp config");

        let (_, review, outcomes, _) = result.expect("valid config should authorize and plan");
        let (assessment, deliberation, _anomalies) =
            review.expect("--cognitive-review should produce Some(review)");
        assert_eq!(assessment.hypotheses_by_target.len(), 1);
        assert!(!assessment.prioritized_tasks.is_empty());
        // The deep deliberation ran too: a train of thought reaching at
        // least one decision, and a metacognitive self-assessment.
        assert!(!deliberation.reasoning_chain.is_empty());
        assert!(deliberation.metacognition.self_assessed_confidence > 0);
        assert!(outcomes.is_none(), "no --execute flag was given");
    }

    #[test]
    fn plan_scan_reports_missing_memory_path() {
        let mut arguments = vec![
            "config.txt".to_string(),
            "--cognitive-review".to_string(),
            "--memory".to_string(),
        ]
        .into_iter();
        assert!(matches!(
            plan_scan(&mut arguments),
            Err(PlanScanError::MissingMemoryPath)
        ));
    }

    #[test]
    fn plan_scan_loads_persisted_memory_and_sharpens_cognition() {
        let config_path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-mem-config-{}.txt",
            std::process::id()
        ));
        let memory_path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-mem-ledger-{}.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&memory_path);
        fs::write(
            &config_path,
            "\
engagement_id=eng-cli-memory
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

        // Seed the persistent ledger with prior-engagement findings on the
        // same target, then confirm the current run's cognition reflects
        // that accumulated history rather than cold type-based priors.
        let priors = vec![
            security_agent::Finding {
                finding_id: "F-1".to_string(),
                source_tool: "semgrep".to_string(),
                title: "BOLA".to_string(),
                target_id: "api-staging".to_string(),
                severity: security_agent::Severity::Critical,
                confidence_percent: 95,
                remediation_playbook: "enforce object-level authz".to_string(),
                normalized_risk_score: 9.5,
            },
            security_agent::Finding {
                finding_id: "F-2".to_string(),
                source_tool: "nuclei".to_string(),
                title: "no rate limit".to_string(),
                target_id: "api-staging".to_string(),
                severity: security_agent::Severity::High,
                confidence_percent: 80,
                remediation_playbook: "add rate limiting".to_string(),
                normalized_risk_score: 8.0,
            },
        ];
        security_agent::append_findings(&memory_path, &priors).expect("seed memory ledger");

        let mut arguments = vec![
            config_path.to_string_lossy().into_owned(),
            "--cognitive-review".to_string(),
            "--memory".to_string(),
            memory_path.to_string_lossy().into_owned(),
        ]
        .into_iter();
        let result = plan_scan(&mut arguments);
        fs::remove_file(&config_path).expect("remove temp config");
        fs::remove_file(&memory_path).expect("remove temp ledger");

        let (_, cognitive_output, _, _) = result.expect("valid config should authorize and plan");
        let (assessment, deliberation, _anomalies) =
            cognitive_output.expect("--cognitive-review should produce Some(review)");

        // The top hypothesis confidence is boosted above its cold 60% base
        // by the recorded finding history.
        let (_, hypotheses) = &assessment.hypotheses_by_target[0];
        assert!(
            hypotheses[0].confidence_percent > 60,
            "history should boost hypothesis confidence above the cold base"
        );
        // The deliberation's train of thought records the prior findings.
        assert!(
            deliberation
                .reasoning_chain
                .thoughts()
                .iter()
                .any(|thought| thought.statement.contains("prior finding")),
            "reasoning should cite accumulated finding history"
        );
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

        let (_, _, outcomes, _) = result.expect("valid config should authorize and plan");
        assert!(
            outcomes.is_some(),
            "--execute should produce Some(outcomes), even if empty"
        );
    }

    #[test]
    fn plan_scan_writes_audit_log_when_flag_is_given() {
        let config_path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-audit-config-{}.txt",
            std::process::id()
        ));
        let log_path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-audit-log-{}.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&log_path);
        fs::write(
            &config_path,
            "\
engagement_id=eng-cli-audit
authorized_by=jane.doe
authorized_by_role=Auditor
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

        let mut arguments = vec![
            config_path.to_string_lossy().into_owned(),
            "--audit-log".to_string(),
            log_path.to_string_lossy().into_owned(),
        ]
        .into_iter();
        let result = plan_scan(&mut arguments);
        fs::remove_file(&config_path).expect("remove temp config");

        result.expect("valid config should authorize, plan, and log");

        let records = security_agent::load_audit_records(&log_path).expect("load audit log");
        fs::remove_file(&log_path).expect("remove temp audit log");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "plan_authorized_scan");
        assert_eq!(records[0].role, security_agent::Role::Auditor);
    }

    #[test]
    fn plan_scan_reports_missing_audit_log_path() {
        let mut arguments = vec!["config.txt".to_string(), "--audit-log".to_string()].into_iter();
        assert!(matches!(
            plan_scan(&mut arguments),
            Err(PlanScanError::MissingAuditLogPath)
        ));
    }

    #[test]
    fn plan_scan_findings_log_missing_path() {
        let mut arguments =
            vec!["config.txt".to_string(), "--findings-log".to_string()].into_iter();
        assert!(matches!(
            plan_scan(&mut arguments),
            Err(PlanScanError::MissingFindingsLogPath)
        ));
    }

    #[test]
    fn plan_scan_findings_log_is_a_noop_without_execute() {
        let config_path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-findings-noop-config-{}.txt",
            std::process::id()
        ));
        let log_path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-findings-noop-log-{}.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&log_path);
        fs::write(
            &config_path,
            "\
engagement_id=eng-cli-findings-noop
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

        // --findings-log given, but --execute is not: the flag must be a
        // true no-op and never touch the log path into existence.
        let mut arguments = vec![
            config_path.to_string_lossy().into_owned(),
            "--findings-log".to_string(),
            log_path.to_string_lossy().into_owned(),
        ]
        .into_iter();
        let result = plan_scan(&mut arguments);
        fs::remove_file(&config_path).expect("remove temp config");

        result.expect("valid config should authorize and plan");
        assert!(
            !log_path.exists(),
            "--findings-log without --execute must not create the log file"
        );
    }

    #[test]
    fn plan_scan_writes_findings_log_when_flag_is_given() {
        let config_path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-findings-config-{}.txt",
            std::process::id()
        ));
        let log_path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-findings-log-{}.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&log_path);
        fs::write(
            &config_path,
            "\
engagement_id=eng-cli-findings
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

        let mut arguments = vec![
            config_path.to_string_lossy().into_owned(),
            "--findings-log".to_string(),
            log_path.to_string_lossy().into_owned(),
            "--execute".to_string(),
        ]
        .into_iter();
        let result = plan_scan(&mut arguments);
        fs::remove_file(&config_path).expect("remove temp config");

        result.expect("valid config should authorize, plan, execute, and log findings");

        // No arguments were given to --execute, so no tool (installed or
        // not) has a real target to scan; ingestion is deterministically
        // empty regardless of what happens to be on PATH in this
        // environment. The log is still created and loadable.
        let findings = security_agent::load_findings(&log_path).expect("load findings log");
        fs::remove_file(&log_path).expect("remove temp findings log");
        assert!(findings.is_empty());
    }

    fn write_temp_config(name: &str, engagement_id: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-{name}-config-{}.txt",
            std::process::id()
        ));
        fs::write(
            &path,
            format!(
                "\
engagement_id={engagement_id}
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
"
            ),
        )
        .expect("write temp config");
        path
    }

    #[test]
    fn plan_scan_writes_audit_db_when_flag_is_given() {
        let config_path = write_temp_config("audit-db", "eng-cli-audit-db");
        let db_path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-audit-db-{}.sadb",
            std::process::id()
        ));
        let _ = fs::remove_file(&db_path);

        let mut arguments = vec![
            config_path.to_string_lossy().into_owned(),
            "--audit-db".to_string(),
            db_path.to_string_lossy().into_owned(),
        ]
        .into_iter();
        let result = plan_scan(&mut arguments);
        fs::remove_file(&config_path).expect("remove temp config");

        result.expect("valid config should authorize, plan, and log");

        let records =
            security_agent::audit_db::load_audit_records(&db_path).expect("load audit db");
        fs::remove_file(&db_path).expect("remove temp audit db");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "plan_authorized_scan");
    }

    #[test]
    fn plan_scan_reports_missing_audit_db_path() {
        let mut arguments = vec!["config.txt".to_string(), "--audit-db".to_string()].into_iter();
        assert!(matches!(
            plan_scan(&mut arguments),
            Err(PlanScanError::MissingAuditDbPath)
        ));
    }

    #[test]
    fn plan_scan_writes_findings_db_when_flag_is_given() {
        let config_path = write_temp_config("findings-db", "eng-cli-findings-db");
        let db_path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-findings-db-{}.sadb",
            std::process::id()
        ));
        let _ = fs::remove_file(&db_path);

        let mut arguments = vec![
            config_path.to_string_lossy().into_owned(),
            "--findings-db".to_string(),
            db_path.to_string_lossy().into_owned(),
            "--execute".to_string(),
        ]
        .into_iter();
        let result = plan_scan(&mut arguments);
        fs::remove_file(&config_path).expect("remove temp config");

        result.expect("valid config should authorize, plan, execute, and log findings");

        // Database is created and loadable even though --execute had no
        // arguments to ingest findings from.
        assert!(db_path.exists());
        let findings = security_agent::findings_db::load_findings(&db_path)
            .expect("load findings from database");
        fs::remove_file(&db_path).expect("remove temp findings db");
        assert!(findings.is_empty());
    }

    #[test]
    fn plan_scan_findings_db_is_a_noop_without_execute() {
        let config_path = write_temp_config("findings-db-noop", "eng-cli-findings-db-noop");
        let db_path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-findings-db-noop-{}.sadb",
            std::process::id()
        ));
        let _ = fs::remove_file(&db_path);

        let mut arguments = vec![
            config_path.to_string_lossy().into_owned(),
            "--findings-db".to_string(),
            db_path.to_string_lossy().into_owned(),
        ]
        .into_iter();
        let result = plan_scan(&mut arguments);
        fs::remove_file(&config_path).expect("remove temp config");

        result.expect("valid config should authorize and plan");
        assert!(
            !db_path.exists(),
            "--findings-db without --execute must not create the database"
        );
    }

    #[test]
    fn plan_scan_reports_missing_findings_db_path() {
        let mut arguments = vec!["config.txt".to_string(), "--findings-db".to_string()].into_iter();
        assert!(matches!(
            plan_scan(&mut arguments),
            Err(PlanScanError::MissingFindingsDbPath)
        ));
    }

    #[test]
    fn plan_scan_calibration_db_accumulates_across_separate_runs() {
        let db_path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-calibration-db-{}.sadb",
            std::process::id()
        ));
        let _ = fs::remove_file(&db_path);

        for engagement in ["eng-cli-calibration-1", "eng-cli-calibration-2"] {
            let config_path = write_temp_config("calibration-db", engagement);
            let mut arguments = vec![
                config_path.to_string_lossy().into_owned(),
                "--cognitive-review".to_string(),
                "--calibration-db".to_string(),
                db_path.to_string_lossy().into_owned(),
            ]
            .into_iter();
            let result = plan_scan(&mut arguments);
            fs::remove_file(&config_path).expect("remove temp config");
            result.expect("valid config should authorize, plan, and review");
        }

        // One target reviewed per run: two runs should leave two
        // accumulated calibration records, not two independent, disjoint
        // single-record histories.
        let tracker =
            security_agent::calibration_db::load_calibration(&db_path).expect("load calibration");
        fs::remove_file(&db_path).expect("remove temp calibration db");
        assert_eq!(tracker.len(), 2);
    }

    #[test]
    fn plan_scan_calibration_db_is_a_noop_without_cognitive_review() {
        let config_path = write_temp_config("calibration-db-noop", "eng-cli-calibration-db-noop");
        let db_path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-calibration-db-noop-{}.sadb",
            std::process::id()
        ));
        let _ = fs::remove_file(&db_path);

        let mut arguments = vec![
            config_path.to_string_lossy().into_owned(),
            "--calibration-db".to_string(),
            db_path.to_string_lossy().into_owned(),
        ]
        .into_iter();
        let result = plan_scan(&mut arguments);
        fs::remove_file(&config_path).expect("remove temp config");

        result.expect("valid config should authorize and plan");
        assert!(
            !db_path.exists(),
            "--calibration-db without --cognitive-review must not create the database"
        );
    }

    #[test]
    fn plan_scan_reports_missing_calibration_db_path() {
        let mut arguments =
            vec!["config.txt".to_string(), "--calibration-db".to_string()].into_iter();
        assert!(matches!(
            plan_scan(&mut arguments),
            Err(PlanScanError::MissingCalibrationDbPath)
        ));
    }

    #[test]
    fn plan_scan_writes_reasoning_log_db_when_cognitive_review_is_given() {
        let config_path = write_temp_config("reasoning-log-db", "eng-cli-reasoning-log-db");
        let db_path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-reasoning-log-db-{}.sadb",
            std::process::id()
        ));
        let _ = fs::remove_file(&db_path);

        let mut arguments = vec![
            config_path.to_string_lossy().into_owned(),
            "--cognitive-review".to_string(),
            "--reasoning-log-db".to_string(),
            db_path.to_string_lossy().into_owned(),
        ]
        .into_iter();
        let result = plan_scan(&mut arguments);
        fs::remove_file(&config_path).expect("remove temp config");

        result.expect("valid config should authorize, plan, and review");

        let runs =
            security_agent::reasoning_log_db::load_runs(&db_path).expect("load reasoning log");
        fs::remove_file(&db_path).expect("remove temp reasoning log db");

        assert_eq!(runs.len(), 1);
        assert!(!runs[0].reasoning_chain.thoughts().is_empty());
    }

    #[test]
    fn plan_scan_reasoning_log_db_is_a_noop_without_cognitive_review() {
        let config_path = write_temp_config("reasoning-log-noop", "eng-cli-reasoning-log-noop");
        let db_path = std::env::temp_dir().join(format!(
            "security-agent-main-plan-scan-reasoning-log-noop-{}.sadb",
            std::process::id()
        ));
        let _ = fs::remove_file(&db_path);

        let mut arguments = vec![
            config_path.to_string_lossy().into_owned(),
            "--reasoning-log-db".to_string(),
            db_path.to_string_lossy().into_owned(),
        ]
        .into_iter();
        let result = plan_scan(&mut arguments);
        fs::remove_file(&config_path).expect("remove temp config");

        result.expect("valid config should authorize and plan");
        assert!(
            !db_path.exists(),
            "--reasoning-log-db without --cognitive-review must not create the database"
        );
    }

    #[test]
    fn plan_scan_reports_missing_reasoning_log_db_path() {
        let mut arguments =
            vec!["config.txt".to_string(), "--reasoning-log-db".to_string()].into_iter();
        assert!(matches!(
            plan_scan(&mut arguments),
            Err(PlanScanError::MissingReasoningLogDbPath)
        ));
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

    #[test]
    fn view_audit_reads_a_written_log() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-main-view-audit-{}.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        security_agent::append_audit_records(
            &path,
            &[security_agent::AuditRecord {
                timestamp_epoch_seconds: 42,
                actor: "jane.doe".to_string(),
                role: security_agent::Role::SecurityAdmin,
                action: "plan_authorized_scan".to_string(),
                target: "eng-view".to_string(),
                details: "tasks=1 high_impact=0".to_string(),
                test_run_id: None,
            }],
        )
        .expect("write audit log");

        let mut arguments = vec![path.to_string_lossy().into_owned()].into_iter();
        let outcome = view_audit_command(&mut arguments);
        fs::remove_file(&path).expect("remove temp audit log");

        assert_eq!(outcome, ExitCode::SUCCESS);
    }

    #[test]
    fn view_audit_reports_failure_for_missing_file() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-main-view-audit-missing-{}.jsonl",
            std::process::id()
        ));
        let mut arguments = vec![path.to_string_lossy().into_owned()].into_iter();
        assert_ne!(view_audit_command(&mut arguments), ExitCode::SUCCESS);
    }

    #[test]
    fn view_audit_reports_missing_path() {
        let mut arguments = std::iter::empty::<String>();
        assert_ne!(view_audit_command(&mut arguments), ExitCode::SUCCESS);
    }

    #[test]
    fn view_audit_db_reads_a_written_database() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-main-view-audit-db-{}.sadb",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        security_agent::audit_db::append_audit_records(
            &path,
            &[security_agent::AuditRecord {
                timestamp_epoch_seconds: 42,
                actor: "jane.doe".to_string(),
                role: security_agent::Role::SecurityAdmin,
                action: "plan_authorized_scan".to_string(),
                target: "eng-view".to_string(),
                details: "tasks=1 high_impact=0".to_string(),
                test_run_id: None,
            }],
        )
        .expect("write audit db");

        let mut arguments = vec![path.to_string_lossy().into_owned()].into_iter();
        let outcome = view_audit_db_command(&mut arguments);
        fs::remove_file(&path).expect("remove temp audit db");

        assert_eq!(outcome, ExitCode::SUCCESS);
    }

    #[test]
    fn view_audit_db_reports_missing_path() {
        let mut arguments = std::iter::empty::<String>();
        assert_ne!(view_audit_db_command(&mut arguments), ExitCode::SUCCESS);
    }

    #[test]
    fn view_audit_db_creates_and_shows_an_empty_database_for_a_new_path() {
        // Unlike --view-audit's plain text log, opening a .sadb path that
        // doesn't exist yet creates an empty database rather than
        // erroring -- see crate::audit_db's module docs.
        let path = std::env::temp_dir().join(format!(
            "security-agent-main-view-audit-db-new-{}.sadb",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        let mut arguments = vec![path.to_string_lossy().into_owned()].into_iter();
        let outcome = view_audit_db_command(&mut arguments);
        fs::remove_file(&path).expect("remove created audit db");

        assert_eq!(outcome, ExitCode::SUCCESS);
    }

    #[test]
    fn view_findings_db_reads_a_written_database() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-main-view-findings-db-{}.sadb",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        security_agent::findings_db::append_findings(
            &path,
            &[security_agent::Finding {
                finding_id: "F-view-1".to_string(),
                source_tool: "semgrep".to_string(),
                title: "exec detected".to_string(),
                target_id: "api-staging".to_string(),
                severity: security_agent::Severity::High,
                confidence_percent: 75,
                remediation_playbook: "review call site".to_string(),
                normalized_risk_score: 6.0,
            }],
        )
        .expect("write findings db");

        let mut arguments = vec![path.to_string_lossy().into_owned()].into_iter();
        let outcome = view_findings_db_command(&mut arguments);
        fs::remove_file(&path).expect("remove temp findings db");

        assert_eq!(outcome, ExitCode::SUCCESS);
    }

    #[test]
    fn view_findings_db_reports_missing_path() {
        let mut arguments = std::iter::empty::<String>();
        assert_ne!(view_findings_db_command(&mut arguments), ExitCode::SUCCESS);
    }

    #[test]
    fn view_calibration_db_reads_a_written_database() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-main-view-calibration-db-{}.sadb",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        security_agent::calibration_db::append_calibration_records(
            &path,
            &[
                security_agent::CalibrationRecord {
                    predicted_percent: 70,
                    occurred: true,
                },
                security_agent::CalibrationRecord {
                    predicted_percent: 40,
                    occurred: false,
                },
            ],
        )
        .expect("write calibration db");

        let mut arguments = vec![path.to_string_lossy().into_owned()].into_iter();
        let outcome = view_calibration_db_command(&mut arguments);
        fs::remove_file(&path).expect("remove temp calibration db");

        assert_eq!(outcome, ExitCode::SUCCESS);
    }

    #[test]
    fn view_calibration_db_reports_missing_path() {
        let mut arguments = std::iter::empty::<String>();
        assert_ne!(
            view_calibration_db_command(&mut arguments),
            ExitCode::SUCCESS
        );
    }

    #[test]
    fn view_reasoning_log_db_reads_a_written_database() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-main-view-reasoning-log-db-{}.sadb",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let mut chain = security_agent::ReasoningChain::new();
        chain.push(
            security_agent::ThoughtKind::Observation,
            "target has no history",
            100,
            vec![],
        );
        let metacognition = security_agent::Metacognition {
            self_assessed_confidence: 55,
            uncertainty: 0.4,
            knowledge_gaps: vec!["no prior engagements".to_string()],
            should_escalate: false,
            reasoning: "adequate confidence for a routine review".to_string(),
        };
        security_agent::reasoning_log_db::append_run(&path, 1_700_000_000, &chain, &metacognition)
            .expect("write reasoning log db");

        let mut arguments = vec![path.to_string_lossy().into_owned()].into_iter();
        let outcome = view_reasoning_log_db_command(&mut arguments);
        fs::remove_file(&path).expect("remove temp reasoning log db");

        assert_eq!(outcome, ExitCode::SUCCESS);
    }

    #[test]
    fn view_reasoning_log_db_reports_missing_path() {
        let mut arguments = std::iter::empty::<String>();
        assert_ne!(
            view_reasoning_log_db_command(&mut arguments),
            ExitCode::SUCCESS
        );
    }

    #[test]
    fn schedule_retest_reads_findings_and_emits_schedule() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-main-schedule-retest-{}.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        security_agent::append_findings(
            &path,
            &[security_agent::Finding {
                finding_id: "semgrep-target-a-0".to_string(),
                source_tool: "semgrep".to_string(),
                title: "exec-detected".to_string(),
                target_id: "target-a".to_string(),
                severity: security_agent::Severity::High,
                confidence_percent: 75,
                remediation_playbook: "app.py:10".to_string(),
                normalized_risk_score: 8.5,
            }],
        )
        .expect("write findings log");

        let mut arguments = vec![path.to_string_lossy().into_owned()].into_iter();
        let outcome = schedule_retest_command(&mut arguments);
        fs::remove_file(&path).expect("remove temp findings log");

        assert_eq!(outcome, ExitCode::SUCCESS);
    }

    #[test]
    fn schedule_retest_reports_failure_for_missing_file() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-main-schedule-retest-missing-{}.jsonl",
            std::process::id()
        ));
        let mut arguments = vec![path.to_string_lossy().into_owned()].into_iter();
        assert_ne!(schedule_retest_command(&mut arguments), ExitCode::SUCCESS);
    }

    #[test]
    fn schedule_retest_reports_missing_path() {
        let mut arguments = std::iter::empty::<String>();
        assert_ne!(schedule_retest_command(&mut arguments), ExitCode::SUCCESS);
    }

    #[test]
    fn tui_banner_explains_the_menu_and_the_chat_bar() {
        let banner = tui_banner();
        assert!(banner.contains("Interactive Terminal UI"));
        assert!(banner.contains("--ask"));
        assert!(banner.contains("quit"));
    }

    #[test]
    fn tui_menu_lists_every_agent_function() {
        let menu = tui_menu();
        // One numbered entry per underlying command, plus quit.
        for token in ["[1]", "[5]", "[9]", "[13]", "[0]", "[q]"] {
            assert!(menu.contains(token), "menu should list {token}");
        }
    }

    #[test]
    fn tui_capabilities_page_reflects_the_bundled_catalog_and_every_command() {
        let assets = LocalAgentAssets::bundled();
        let page = tui_capabilities_page(&assets);

        assert!(page.contains("Capability Summary"));
        assert!(page.contains(&format!("{} cataloged tools", assets.tools().len())));
        // Every CLI command and its plain-English column header must appear.
        for (function, command, _) in CAPABILITY_ROWS {
            assert!(page.contains(function), "missing function: {function}");
            assert!(page.contains(command), "missing command: {command}");
        }
        assert!(page.contains("--allow-network"));
    }

    #[test]
    fn tui_answered_yes_accepts_only_y_and_yes_case_insensitively() {
        assert!(tui_answered_yes("y"));
        assert!(tui_answered_yes("Y"));
        assert!(tui_answered_yes("yes"));
        assert!(tui_answered_yes("YES"));
        assert!(tui_answered_yes("  yes  "));
        assert!(!tui_answered_yes("n"));
        assert!(!tui_answered_yes(""));
        assert!(!tui_answered_yes("sure"));
    }

    #[test]
    fn tui_prompt_reads_the_next_line_and_stops_cleanly_at_eof() {
        let mut lines = vec![Ok("first".to_string()), Ok("second".to_string())].into_iter();
        assert_eq!(tui_prompt(&mut lines, "> "), Some("first".to_string()));
        assert_eq!(tui_read_line(&mut lines), Some("second".to_string()));
        assert_eq!(tui_read_line(&mut lines), None);
    }

    #[test]
    fn dispatch_tui_choice_routes_free_text_through_ask() {
        // A free-text menu choice with no matching menu token must not panic
        // and must be handled entirely by the chat-bar (--ask) path; this
        // just asserts it runs to completion without needing further input.
        let assets = LocalAgentAssets::bundled();
        let mut lines = std::iter::empty::<io::Result<String>>();
        dispatch_tui_choice("what tools do you have", &assets, &mut lines);
    }
}
