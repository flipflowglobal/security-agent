//! Security-Agent local runtime.

use security_agent::{
    CapabilityGraph, CapabilityRegistry, CognitiveAssessment, CognitiveDeliberation,
    CognitiveEngine, CognitiveMemory, Coordinator, LocalAgentAssets, PolicyEngine,
    ToolchainPackRegistry, assess_plan_cognitively, load_engagement_config, run_builtin_tool,
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
        Some("--about" | "--version") => print_about(),
        Some("--list-skills") => list_skills(&assets),
        Some("--show-skill") => show_skill(&assets, &mut arguments),
        Some("--list-tools") => list_tools(&assets),
        Some("--run-tool") => run_tool_command(&mut arguments),
        Some("--run-external-tool") => run_external_tool_command(&assets, &mut arguments),
        Some("--plan-scan") => plan_scan_command(&mut arguments),
        Some("--record-findings") => record_findings_command(&mut arguments),
        Some("--view-audit") => view_audit_command(&mut arguments),
        Some("--schedule-retest") => schedule_retest_command(&mut arguments),
        Some("--llm-generate") => llm_generate_command(&mut arguments),
        Some("--llm-perplexity") => llm_perplexity_command(&mut arguments),
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
/// `--run-external-tool semgrep --version`. Only tools classified for
/// static local analysis (see `security_agent::registry::ExecutionClass`)
/// are wired up for direct execution, plus `nmap` as an explicit,
/// reviewed exception (see `security_agent::execution`); everything else
/// is rejected with an explanatory error.
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

    // The direct CLI path has no declared engagement, so advise against a
    // default Standard ceiling. Advisory only for tools that actually reach
    // a live target — static-local tools never touch the network.
    if tool.definition.execution_class != security_agent::ExecutionClass::StaticLocalAnalysis {
        print_intensity_advisories(&tool_arguments, security_agent::TestIntensity::Standard);
    }

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
    MissingAuditLogPath,
    MissingMemoryPath,
    MissingFindingsLogPath,
    UnexpectedArgument(String),
    ConfigLoad(String),
    AuthorizationDenied(String),
    AuditLogWrite(String),
    MemoryLoad(String),
    FindingsLogWrite(String),
}

impl fmt::Display for PlanScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingConfigPath => formatter.write_str("missing engagement config file path"),
            Self::MissingAuditLogPath => formatter.write_str("missing --audit-log file path"),
            Self::MissingMemoryPath => formatter.write_str("missing --memory file path"),
            Self::MissingFindingsLogPath => formatter.write_str("missing --findings-log file path"),
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
            Self::MemoryLoad(message) => {
                write!(formatter, "failed to load cognitive memory: {message}")
            }
            Self::FindingsLogWrite(message) => {
                write!(formatter, "failed to write findings log: {message}")
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

fn plan_scan(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<PlanScanOutcome, PlanScanError> {
    let config_path = arguments.next().ok_or(PlanScanError::MissingConfigPath)?;

    let mut next_argument = arguments.next();
    let audit_log_path = if next_argument.as_deref() == Some("--audit-log") {
        let path = arguments.next().ok_or(PlanScanError::MissingAuditLogPath)?;
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
    let findings_log_path = if next_argument.as_deref() == Some("--findings-log") {
        let path = arguments
            .next()
            .ok_or(PlanScanError::MissingFindingsLogPath)?;
        next_argument = arguments.next();
        Some(path)
    } else {
        None
    };
    let tool_arguments = match next_argument {
        None => None,
        Some(flag) if flag == "--execute" => Some(arguments.collect::<Vec<String>>()),
        Some(other) => return Err(PlanScanError::UnexpectedArgument(other)),
    };

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

    let cognitive_output = cognitive_review.then(|| {
        let mut memory = CognitiveMemory::new();
        memory.record_findings(&prior_findings);
        let assessment = assess_plan_cognitively(&plan, &targets_for_review, &memory);
        let engine = CognitiveEngine::new(memory, security_agent::AdversaryModel::default());
        let deliberation = engine.deliberate(&plan, &targets_for_review, &prior_findings);
        // Loop the language model's perplexity signal into the review: flag
        // finding text that does not look like ordinary security-domain
        // English. Only runs (and only pays the model's startup cost) when
        // there are prior findings to scan.
        let anomalies = if prior_findings.is_empty() {
            Vec::new()
        } else {
            let model = security_agent::NeuralLanguageModel::bundled();
            security_agent::scan_findings(
                &prior_findings,
                &model,
                security_agent::DEFAULT_ANOMALY_THRESHOLD,
            )
        };
        (assessment, deliberation, anomalies)
    });

    if let Some(tool_arguments) = &tool_arguments {
        print_intensity_advisories(tool_arguments, declared_ceiling);
    }

    let outcomes = tool_arguments.map(|tool_arguments| {
        let assets = LocalAgentAssets::bundled();
        security_agent::execute_plan(&plan, &assets, &tool_arguments)
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

    // Only touch the findings log when --execute actually ran (`outcomes`
    // is `Some`); otherwise --findings-log is a true no-op, matching its
    // documented behavior, rather than creating an empty log file.
    if outcomes.is_some() {
        if let Some(path) = findings_log_path {
            security_agent::append_findings(Path::new(&path), &findings)
                .map_err(|error| PlanScanError::FindingsLogWrite(error.to_string()))?;
        }
    }

    Ok((plan, cognitive_output, outcomes, findings))
}

/// CLI entry point for `--plan-scan <config-file> [--audit-log <path>]
/// [--cognitive-review] [--memory <path>] [--findings-log <path>]
/// [--execute <args>...]`;
/// prints the resulting [`security_agent::ExecutionPlan`], the
/// [`CognitiveAssessment`] when `--cognitive-review` was given, and —
/// when `--execute` was given — each task's tool execution outcomes plus
/// a findings summary ingested from their output.
fn plan_scan_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    match plan_scan(arguments) {
        Ok((plan, cognitive_output, outcomes, findings)) => {
            print!("{plan}");
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
/// security-domain corpus — no network, no weights on disk. Decoding is
/// greedy, so the same prompt always yields the same continuation. Text is
/// modest given the model's size; this exists to make the offline
/// language-model capability usable and inspectable.
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
}
