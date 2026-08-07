//! Engagement reporting: findings and evidence rendered into deliverables.
//!
//! An engagement is judged by its report, not its logs. This module renders
//! scored findings and their evidence into a SARIF 2.1.0 file for tooling, a
//! machine-readable JSON summary, and a human Markdown report.
//!
//! The findings pipeline ([`crate::ingest`], [`crate::correlation`]) produces
//! scored, correlated [`Finding`]s and [`crate::evidence`] captures their
//! chain of custody, but neither is a report. This module is the last mile:
//! it renders those into stable, self-contained documents. Every renderer is
//! deterministic for a given input (findings are ordered by descending risk,
//! then finding id, and the caller supplies the generation timestamp), so the
//! same engagement always produces byte-identical output — important for
//! diffing reports and for reproducible pipelines.
//!
//! Serialization is in-house (the crate has no external dependencies): a
//! small [`Json`] value tree renders exact, escaped JSON for the SARIF and
//! summary outputs, and an epoch→UTC formatter timestamps the Markdown
//! without pulling in a date library.

use crate::advanced::AttackPathGraph;
use crate::engagement_context::EngagementContext;
use crate::evidence::EvidenceRecord;
use crate::execution::{TaskExecutionOutcome, ToolExecutionError};
use crate::findings::{Finding, Severity};
use crate::pipeline::EngagementReport;
use std::collections::BTreeSet;
use std::fmt::Write as _;

/// Repository/tool identity embedded in generated reports.
const TOOL_NAME: &str = "security-agent";
const TOOL_URI: &str = "https://github.com/flipflowglobal/security-agent";
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// The inputs to a full engagement report.
pub struct ReportInputs<'a> {
    /// The engagement identifier the report is for.
    pub engagement_id: &'a str,
    /// The scored (ideally already correlated) findings.
    pub findings: &'a [Finding],
    /// The evidence records backing the findings.
    pub evidence: &'a [EvidenceRecord],
    /// Unix epoch seconds the report was generated at (caller-supplied so the
    /// output is deterministic and testable).
    pub generated_at_epoch: u64,
}

/// Per-severity finding counts, most-severe first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeverityRollup {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
}

impl SeverityRollup {
    /// Tallies findings by severity.
    #[must_use]
    pub fn of(findings: &[Finding]) -> Self {
        let mut rollup = Self::default();
        for finding in findings {
            match finding.severity {
                Severity::Critical => rollup.critical += 1,
                Severity::High => rollup.high += 1,
                Severity::Medium => rollup.medium += 1,
                Severity::Low => rollup.low += 1,
                Severity::Informational => rollup.informational += 1,
            }
        }
        rollup
    }

    /// Total number of findings tallied.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.informational
    }
}

/// Returns `findings` ordered by descending risk, then finding id — the
/// canonical, deterministic order every renderer uses.
fn ranked(findings: &[Finding]) -> Vec<&Finding> {
    let mut ordered: Vec<&Finding> = findings.iter().collect();
    ordered.sort_by(|a, b| {
        b.normalized_risk_score
            .partial_cmp(&a.normalized_risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.finding_id.cmp(&b.finding_id))
    });
    ordered
}

/// Maps a [`Severity`] onto a SARIF result level.
const fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Informational => "note",
    }
}

/// A stable SARIF `ruleId` for a finding, derived from its title so findings
/// of the same class share one rule.
fn rule_id(finding: &Finding) -> String {
    let slug: String = finding
        .title
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = slug.trim_matches('-');
    if trimmed.is_empty() {
        "finding".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Renders findings as a SARIF 2.1.0 document — the interchange format code
/// scanners, CI, and security dashboards consume.
#[must_use]
pub fn render_sarif(findings: &[Finding]) -> String {
    let ordered = ranked(findings);

    // One rule per distinct ruleId, in first-seen order.
    let mut seen_rules = BTreeSet::new();
    let mut rules = Vec::new();
    for finding in &ordered {
        let id = rule_id(finding);
        if seen_rules.insert(id.clone()) {
            rules.push(Json::Obj(vec![
                ("id", Json::str(&id)),
                ("name", Json::str(&finding.title)),
                (
                    "shortDescription",
                    Json::Obj(vec![("text", Json::str(&finding.title))]),
                ),
                (
                    "defaultConfiguration",
                    Json::Obj(vec![("level", Json::str(sarif_level(finding.severity)))]),
                ),
            ]));
        }
    }

    let results = ordered
        .iter()
        .map(|finding| {
            Json::Obj(vec![
                ("ruleId", Json::str(&rule_id(finding))),
                ("level", Json::str(sarif_level(finding.severity))),
                (
                    "message",
                    Json::Obj(vec![("text", Json::str(&finding.title))]),
                ),
                (
                    "properties",
                    Json::Obj(vec![
                        (
                            "security-severity",
                            Json::str(&format!("{:.1}", finding.normalized_risk_score)),
                        ),
                        (
                            "confidence",
                            Json::Int(i64::from(finding.confidence_percent)),
                        ),
                        ("source-tool", Json::str(&finding.source_tool)),
                        ("target", Json::str(&finding.target_id)),
                        ("remediation", Json::str(&finding.remediation_playbook)),
                    ]),
                ),
                (
                    "locations",
                    Json::Arr(vec![Json::Obj(vec![(
                        "physicalLocation",
                        Json::Obj(vec![(
                            "artifactLocation",
                            Json::Obj(vec![("uri", Json::str(&finding.target_id))]),
                        )]),
                    )])]),
                ),
            ])
        })
        .collect();

    let root = Json::Obj(vec![
        ("$schema", Json::str(SARIF_SCHEMA)),
        ("version", Json::str("2.1.0")),
        (
            "runs",
            Json::Arr(vec![Json::Obj(vec![
                (
                    "tool",
                    Json::Obj(vec![(
                        "driver",
                        Json::Obj(vec![
                            ("name", Json::str(TOOL_NAME)),
                            ("informationUri", Json::str(TOOL_URI)),
                            ("version", Json::str(env!("CARGO_PKG_VERSION"))),
                            ("rules", Json::Arr(rules)),
                        ]),
                    )]),
                ),
                ("results", Json::Arr(results)),
            ])]),
        ),
    ]);

    let mut out = root.render();
    out.push('\n');
    out
}

/// Renders a machine-readable JSON summary of the whole engagement:
/// metadata, the severity rollup, the ranked findings, and the evidence
/// chain of custody.
#[must_use]
pub fn render_json(inputs: &ReportInputs) -> String {
    let rollup = SeverityRollup::of(inputs.findings);
    let findings = ranked(inputs.findings)
        .iter()
        .map(|finding| {
            Json::Obj(vec![
                ("finding_id", Json::str(&finding.finding_id)),
                ("title", Json::str(&finding.title)),
                ("target", Json::str(&finding.target_id)),
                ("severity", Json::str(&finding.severity.to_string())),
                (
                    "confidence",
                    Json::Int(i64::from(finding.confidence_percent)),
                ),
                (
                    "risk_score",
                    Json::str(&format!("{:.1}", finding.normalized_risk_score)),
                ),
                ("source_tool", Json::str(&finding.source_tool)),
                ("remediation", Json::str(&finding.remediation_playbook)),
            ])
        })
        .collect();
    let evidence = inputs
        .evidence
        .iter()
        .map(|record| {
            Json::Obj(vec![
                ("target", Json::str(&record.target_id)),
                ("tool", Json::str(&record.tool)),
                ("output_sha256", Json::str(&record.output_sha256)),
                (
                    "byte_len",
                    Json::Int(i64::try_from(record.byte_len).unwrap_or(i64::MAX)),
                ),
                (
                    "exit_code",
                    record
                        .exit_code
                        .map_or(Json::Null, |code| Json::Int(i64::from(code))),
                ),
            ])
        })
        .collect();

    let root = Json::Obj(vec![
        ("engagement_id", Json::str(inputs.engagement_id)),
        (
            "generated_at",
            Json::str(&format_utc(inputs.generated_at_epoch)),
        ),
        ("tool", Json::str(TOOL_NAME)),
        (
            "summary",
            Json::Obj(vec![
                (
                    "total",
                    Json::Int(i64::try_from(rollup.total()).unwrap_or(i64::MAX)),
                ),
                (
                    "critical",
                    Json::Int(i64::try_from(rollup.critical).unwrap_or(i64::MAX)),
                ),
                (
                    "high",
                    Json::Int(i64::try_from(rollup.high).unwrap_or(i64::MAX)),
                ),
                (
                    "medium",
                    Json::Int(i64::try_from(rollup.medium).unwrap_or(i64::MAX)),
                ),
                (
                    "low",
                    Json::Int(i64::try_from(rollup.low).unwrap_or(i64::MAX)),
                ),
                (
                    "informational",
                    Json::Int(i64::try_from(rollup.informational).unwrap_or(i64::MAX)),
                ),
            ]),
        ),
        ("findings", Json::Arr(findings)),
        ("evidence", Json::Arr(evidence)),
    ]);

    let mut out = root.render();
    out.push('\n');
    out
}

/// Renders the human-facing Markdown engagement report: executive summary,
/// severity rollup, ranked findings with remediation, the attack-path
/// narrative, and the evidence chain of custody.
#[must_use]
pub fn render_markdown(inputs: &ReportInputs) -> String {
    let rollup = SeverityRollup::of(inputs.findings);
    let ordered = ranked(inputs.findings);
    let mut out = String::new();

    let _ = writeln!(out, "# Security Engagement Report");
    let _ = writeln!(out);
    let _ = writeln!(out, "- **Engagement:** {}", inputs.engagement_id);
    let _ = writeln!(
        out,
        "- **Generated:** {}",
        format_utc(inputs.generated_at_epoch)
    );
    let _ = writeln!(out, "- **Tool:** {TOOL_NAME} {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out);

    let _ = writeln!(out, "## Executive Summary");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "This engagement produced **{}** finding(s): {} critical, {} high, {} medium, {} low, {} informational.",
        rollup.total(),
        rollup.critical,
        rollup.high,
        rollup.medium,
        rollup.low,
        rollup.informational,
    );
    let _ = writeln!(out);
    if let Some(top) = ordered.first() {
        let _ = writeln!(
            out,
            "The highest-risk issue is **{}** ({}, risk {:.1}) on `{}`.",
            top.title, top.severity, top.normalized_risk_score, top.target_id,
        );
    } else {
        let _ = writeln!(out, "No findings were reported for this engagement.");
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Severity Rollup");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Severity | Count |");
    let _ = writeln!(out, "|---|---|");
    let _ = writeln!(out, "| Critical | {} |", rollup.critical);
    let _ = writeln!(out, "| High | {} |", rollup.high);
    let _ = writeln!(out, "| Medium | {} |", rollup.medium);
    let _ = writeln!(out, "| Low | {} |", rollup.low);
    let _ = writeln!(out, "| Informational | {} |", rollup.informational);
    let _ = writeln!(out, "| **Total** | **{}** |", rollup.total());
    let _ = writeln!(out);

    let _ = writeln!(out, "## Findings");
    let _ = writeln!(out);
    if ordered.is_empty() {
        let _ = writeln!(out, "_No findings._");
        let _ = writeln!(out);
    } else {
        for (index, finding) in ordered.iter().enumerate() {
            let _ = writeln!(
                out,
                "### {}. {} ({})",
                index + 1,
                finding.title,
                finding.severity,
            );
            let _ = writeln!(out);
            let _ = writeln!(out, "- **Target:** `{}`", finding.target_id);
            let _ = writeln!(out, "- **Source tool(s):** {}", finding.source_tool);
            let _ = writeln!(out, "- **Confidence:** {}%", finding.confidence_percent);
            let _ = writeln!(
                out,
                "- **Risk score:** {:.1} / 10",
                finding.normalized_risk_score
            );
            let _ = writeln!(out, "- **Finding id:** `{}`", finding.finding_id);
            let _ = writeln!(out);
            let _ = writeln!(out, "**Remediation:** {}", finding.remediation_playbook);
            let _ = writeln!(out);
        }
    }

    render_attack_path_section(&mut out, inputs.findings);
    render_evidence_section(&mut out, inputs.evidence);

    out
}

/// Appends the attack-path narrative built from the findings.
fn render_attack_path_section(out: &mut String, findings: &[Finding]) {
    let graph = AttackPathGraph::build_from_findings(findings);
    let _ = writeln!(out, "## Attack Path Analysis");
    let _ = writeln!(out);
    if graph.edges.is_empty() {
        let _ = writeln!(out, "_No attack paths derived (no findings)._");
        let _ = writeln!(out);
        return;
    }
    let _ = writeln!(
        out,
        "Derived {} node(s) and {} edge(s) from the findings. An external threat actor reaches each affected asset as follows:",
        graph.nodes.len(),
        graph.edges.len(),
    );
    let _ = writeln!(out);
    for edge in &graph.edges {
        let _ = writeln!(
            out,
            "- `{}` → `{}` (via {})",
            edge.from, edge.to, edge.technique
        );
    }
    let _ = writeln!(out);
}

/// Appends the evidence / chain-of-custody table.
fn render_evidence_section(out: &mut String, evidence: &[EvidenceRecord]) {
    let _ = writeln!(out, "## Evidence & Chain of Custody");
    let _ = writeln!(out);
    if evidence.is_empty() {
        let _ = writeln!(out, "_No evidence records were captured._");
        let _ = writeln!(out);
        return;
    }
    let _ = writeln!(out, "| Target | Tool | Output SHA-256 | Bytes | Exit |");
    let _ = writeln!(out, "|---|---|---|---|---|");
    for record in evidence {
        let exit = record
            .exit_code
            .map_or_else(|| "—".to_string(), |code| code.to_string());
        let _ = writeln!(
            out,
            "| `{}` | {} | `{}` | {} | {} |",
            record.target_id, record.tool, record.output_sha256, record.byte_len, exit,
        );
    }
    let _ = writeln!(out);
}

/// The inputs to a full engagement deliverable: the run-level report that
/// combines execution outcomes, discovery, result-driven expansion, and the
/// ingested findings into a single hand-off document.
///
/// Where [`ReportInputs`] renders *findings and evidence*, this renders the
/// whole engagement — what ran, in what stages, what discovery turned up, how
/// far expansion reached, and the findings that resulted — for an operator or
/// client to read as the record of the run.
pub struct EngagementDeliverable<'a> {
    /// The engagement identifier the deliverable is for.
    pub engagement_id: &'a str,
    /// Unix epoch seconds the deliverable was generated at (caller-supplied so
    /// output is deterministic and testable).
    pub generated_at_epoch: u64,
    /// The completed engagement run (stages, discovery, expansion count).
    pub report: &'a EngagementReport,
    /// The findings ingested from the run's tool output.
    pub findings: &'a [Finding],
}

/// A tool's terminal status within a stage, classified for rendering.
enum OutcomeStatus {
    Completed {
        exit_code: Option<i32>,
        duration_ms: u64,
    },
    Failed(String),
    Refused(String),
}

/// Classifies one outcome into a stable terminal status.
fn outcome_status(outcome: &TaskExecutionOutcome) -> OutcomeStatus {
    match &outcome.result {
        Ok(execution) => OutcomeStatus::Completed {
            exit_code: execution.exit_code,
            duration_ms: u64::try_from(execution.duration.as_millis()).unwrap_or(u64::MAX),
        },
        Err(ToolExecutionError::Refused(reason)) => OutcomeStatus::Refused(reason.clone()),
        Err(error) => OutcomeStatus::Failed(error.to_string()),
    }
}

/// Whole-run outcome tallies.
#[derive(Default, Clone, Copy)]
struct RunCounts {
    tools: usize,
    completed: usize,
    failed: usize,
    refused: usize,
}

/// Tallies every outcome across all stages by terminal status.
fn run_counts(report: &EngagementReport) -> RunCounts {
    let mut counts = RunCounts::default();
    for outcome in report.all_outcomes() {
        counts.tools += 1;
        match &outcome.result {
            Ok(_) => counts.completed += 1,
            Err(ToolExecutionError::Refused(_)) => counts.refused += 1,
            Err(_) => counts.failed += 1,
        }
    }
    counts
}

/// Sanitizes a value for a single Markdown table cell: no pipes, no newlines.
fn md_cell(value: &str) -> String {
    value.replace('|', "\\|").replace(['\n', '\r'], " ")
}

/// Renders the human-facing Markdown **engagement deliverable**: run summary,
/// discovery inventory, per-stage execution timeline, and a findings overview.
#[must_use]
pub fn render_engagement_markdown(deliverable: &EngagementDeliverable) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Security Engagement Deliverable");
    let _ = writeln!(out);
    let _ = writeln!(out, "- **Engagement:** {}", deliverable.engagement_id);
    let _ = writeln!(
        out,
        "- **Generated:** {}",
        format_utc(deliverable.generated_at_epoch)
    );
    let _ = writeln!(out, "- **Tool:** {TOOL_NAME} {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out);

    render_run_summary_section(&mut out, deliverable);
    render_discovery_section(&mut out, &deliverable.report.context);
    render_timeline_section(&mut out, deliverable.report);
    render_findings_overview_section(&mut out, deliverable.findings);
    out
}

/// Appends the run-summary bullet list.
fn render_run_summary_section(out: &mut String, deliverable: &EngagementDeliverable) {
    let counts = run_counts(deliverable.report);
    let discovery = &deliverable.report.context;
    let rollup = SeverityRollup::of(deliverable.findings);
    let _ = writeln!(out, "## Run Summary");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- **Stages executed:** {}",
        deliverable.report.stages.len()
    );
    let _ = writeln!(
        out,
        "- **Tools executed:** {} ({} succeeded, {} failed, {} refused)",
        counts.tools, counts.completed, counts.failed, counts.refused,
    );
    let _ = writeln!(
        out,
        "- **Follow-up steps added by expansion:** {}",
        deliverable.report.expansion_added
    );
    let _ = writeln!(
        out,
        "- **Assets discovered:** {} host(s), {} service(s), {} endpoint(s)",
        discovery.hosts().len(),
        discovery.services().len(),
        discovery.endpoints().len(),
    );
    let _ = writeln!(
        out,
        "- **Findings:** {} total ({} critical, {} high, {} medium, {} low, {} informational)",
        rollup.total(),
        rollup.critical,
        rollup.high,
        rollup.medium,
        rollup.low,
        rollup.informational,
    );
    let _ = writeln!(out);
}

/// Appends the discovery inventory: hosts, open services, and web endpoints.
fn render_discovery_section(out: &mut String, context: &EngagementContext) {
    let _ = writeln!(out, "## Discovery");
    let _ = writeln!(out);

    let _ = writeln!(out, "### Hosts ({})", context.hosts().len());
    let _ = writeln!(out);
    if context.hosts().is_empty() {
        let _ = writeln!(out, "_No hosts discovered._");
    } else {
        let _ = writeln!(out, "| Address | Hostname |");
        let _ = writeln!(out, "|---|---|");
        for host in context.hosts() {
            let hostname = host.hostname.as_deref().unwrap_or("—");
            let _ = writeln!(
                out,
                "| `{}` | {} |",
                md_cell(&host.address),
                md_cell(hostname)
            );
        }
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "### Open Services ({})", context.services().len());
    let _ = writeln!(out);
    if context.services().is_empty() {
        let _ = writeln!(out, "_No services discovered._");
    } else {
        let _ = writeln!(out, "| Host | Port | Protocol | Service |");
        let _ = writeln!(out, "|---|---|---|---|");
        for service in context.services() {
            let name = service.service.as_deref().unwrap_or("—");
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} |",
                md_cell(&service.host),
                service.port,
                md_cell(&service.protocol),
                md_cell(name),
            );
        }
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "### Web Endpoints ({})", context.endpoints().len());
    let _ = writeln!(out);
    if context.endpoints().is_empty() {
        let _ = writeln!(out, "_No endpoints discovered._");
    } else {
        for endpoint in context.endpoints() {
            let _ = writeln!(out, "- `{}`", md_cell(&endpoint.url));
        }
    }
    let _ = writeln!(out);
}

/// Renders one outcome's status as a Markdown table cell.
fn status_cell(status: &OutcomeStatus) -> String {
    match status {
        OutcomeStatus::Completed {
            exit_code,
            duration_ms,
        } => {
            let exit = exit_code.map_or_else(|| "signal".to_string(), |code| code.to_string());
            format!("ok (exit {exit}, {duration_ms} ms)")
        }
        OutcomeStatus::Failed(error) => format!("failed: {}", md_cell(error)),
        OutcomeStatus::Refused(reason) => format!("refused: {}", md_cell(reason)),
    }
}

/// Appends the per-stage execution timeline table.
fn render_timeline_section(out: &mut String, report: &EngagementReport) {
    let _ = writeln!(out, "## Execution Timeline");
    let _ = writeln!(out);
    if report.stages.iter().all(|stage| stage.outcomes.is_empty()) {
        let _ = writeln!(out, "_No tools were executed._");
        let _ = writeln!(out);
        return;
    }
    let _ = writeln!(out, "| Stage | Tool | Target | Result |");
    let _ = writeln!(out, "|---|---|---|---|");
    for stage in &report.stages {
        let class = format!("{:?}", stage.class);
        for outcome in &stage.outcomes {
            let _ = writeln!(
                out,
                "| {} | {} | `{}` | {} |",
                md_cell(&class),
                md_cell(&outcome.tool),
                md_cell(&outcome.target_id),
                status_cell(&outcome_status(outcome)),
            );
        }
    }
    let _ = writeln!(out);
}

/// Appends the findings overview: the severity rollup and the ranked findings.
fn render_findings_overview_section(out: &mut String, findings: &[Finding]) {
    let rollup = SeverityRollup::of(findings);
    let ordered = ranked(findings);
    let _ = writeln!(out, "## Findings");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Severity | Count |");
    let _ = writeln!(out, "|---|---|");
    let _ = writeln!(out, "| Critical | {} |", rollup.critical);
    let _ = writeln!(out, "| High | {} |", rollup.high);
    let _ = writeln!(out, "| Medium | {} |", rollup.medium);
    let _ = writeln!(out, "| Low | {} |", rollup.low);
    let _ = writeln!(out, "| Informational | {} |", rollup.informational);
    let _ = writeln!(out, "| **Total** | **{}** |", rollup.total());
    let _ = writeln!(out);

    if ordered.is_empty() {
        let _ = writeln!(out, "_No findings were reported for this engagement._");
        let _ = writeln!(out);
        return;
    }
    let _ = writeln!(out, "| # | Title | Severity | Target | Risk |");
    let _ = writeln!(out, "|---|---|---|---|---|");
    for (index, finding) in ordered.iter().enumerate() {
        let _ = writeln!(
            out,
            "| {} | {} | {} | `{}` | {:.1} |",
            index + 1,
            md_cell(&finding.title),
            finding.severity,
            md_cell(&finding.target_id),
            finding.normalized_risk_score,
        );
    }
    let _ = writeln!(out);
}

/// Renders the machine-readable JSON **engagement deliverable**: run summary,
/// discovery inventory, execution timeline, and a findings summary.
#[must_use]
pub fn render_engagement_json(deliverable: &EngagementDeliverable) -> String {
    let report = deliverable.report;
    let counts = run_counts(report);
    let discovery = &report.context;
    let rollup = SeverityRollup::of(deliverable.findings);

    let root = Json::Obj(vec![
        ("engagement_id", Json::str(deliverable.engagement_id)),
        (
            "generated_at",
            Json::str(&format_utc(deliverable.generated_at_epoch)),
        ),
        ("tool", Json::str(TOOL_NAME)),
        (
            "summary",
            Json::Obj(vec![
                ("stages", json_usize(report.stages.len())),
                ("tools_executed", json_usize(counts.tools)),
                ("completed", json_usize(counts.completed)),
                ("failed", json_usize(counts.failed)),
                ("refused", json_usize(counts.refused)),
                ("expansion_added", json_usize(report.expansion_added)),
                ("hosts", json_usize(discovery.hosts().len())),
                ("services", json_usize(discovery.services().len())),
                ("endpoints", json_usize(discovery.endpoints().len())),
                ("findings_total", json_usize(rollup.total())),
                ("findings_critical", json_usize(rollup.critical)),
                ("findings_high", json_usize(rollup.high)),
                ("findings_medium", json_usize(rollup.medium)),
                ("findings_low", json_usize(rollup.low)),
                ("findings_informational", json_usize(rollup.informational)),
            ]),
        ),
        ("discovery", discovery_json(discovery)),
        ("timeline", timeline_json(report)),
        ("findings", findings_json(deliverable.findings)),
    ]);

    let mut out = root.render();
    out.push('\n');
    out
}

/// Wraps a `usize` as a JSON integer, saturating on overflow.
fn json_usize(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

/// Builds the `discovery` object of the JSON deliverable.
fn discovery_json(context: &EngagementContext) -> Json {
    let hosts = context
        .hosts()
        .iter()
        .map(|host| {
            Json::Obj(vec![
                ("address", Json::str(&host.address)),
                (
                    "hostname",
                    host.hostname.as_deref().map_or(Json::Null, Json::str),
                ),
            ])
        })
        .collect();
    let services = context
        .services()
        .iter()
        .map(|service| {
            Json::Obj(vec![
                ("host", Json::str(&service.host)),
                ("port", Json::Int(i64::from(service.port))),
                ("protocol", Json::str(&service.protocol)),
                (
                    "service",
                    service.service.as_deref().map_or(Json::Null, Json::str),
                ),
            ])
        })
        .collect();
    let endpoints = context
        .endpoints()
        .iter()
        .map(|endpoint| Json::str(&endpoint.url))
        .collect();
    Json::Obj(vec![
        ("hosts", Json::Arr(hosts)),
        ("services", Json::Arr(services)),
        ("endpoints", Json::Arr(endpoints)),
    ])
}

/// Builds the `timeline` array of the JSON deliverable, one object per outcome.
fn timeline_json(report: &EngagementReport) -> Json {
    let mut entries = Vec::new();
    for stage in &report.stages {
        let class = format!("{:?}", stage.class);
        for outcome in &stage.outcomes {
            let mut fields = vec![
                ("stage", Json::str(&class)),
                ("tool", Json::str(&outcome.tool)),
                ("target", Json::str(&outcome.target_id)),
            ];
            match outcome_status(outcome) {
                OutcomeStatus::Completed {
                    exit_code,
                    duration_ms,
                } => {
                    fields.push(("status", Json::str("completed")));
                    fields.push((
                        "exit_code",
                        exit_code.map_or(Json::Null, |code| Json::Int(i64::from(code))),
                    ));
                    fields.push((
                        "duration_ms",
                        Json::Int(i64::try_from(duration_ms).unwrap_or(i64::MAX)),
                    ));
                }
                OutcomeStatus::Failed(error) => {
                    fields.push(("status", Json::str("failed")));
                    fields.push(("error", Json::Str(error)));
                }
                OutcomeStatus::Refused(reason) => {
                    fields.push(("status", Json::str("refused")));
                    fields.push(("reason", Json::Str(reason)));
                }
            }
            entries.push(Json::Obj(fields));
        }
    }
    Json::Arr(entries)
}

/// Builds the ranked `findings` array of the JSON deliverable.
fn findings_json(findings: &[Finding]) -> Json {
    let entries = ranked(findings)
        .iter()
        .map(|finding| {
            Json::Obj(vec![
                ("finding_id", Json::str(&finding.finding_id)),
                ("title", Json::str(&finding.title)),
                ("target", Json::str(&finding.target_id)),
                ("severity", Json::str(&finding.severity.to_string())),
                (
                    "confidence",
                    Json::Int(i64::from(finding.confidence_percent)),
                ),
                (
                    "risk_score",
                    Json::str(&format!("{:.1}", finding.normalized_risk_score)),
                ),
                ("source_tool", Json::str(&finding.source_tool)),
            ])
        })
        .collect();
    Json::Arr(entries)
}

/// Formats Unix epoch seconds as an ISO-8601 UTC timestamp, without a date
/// dependency. Uses the standard civil-from-days algorithm; valid for all
/// dates at or after the Unix epoch.
fn format_utc(epoch: u64) -> String {
    let days = epoch / 86_400;
    let secs = epoch % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = secs / 3_600;
    let minute = (secs % 3_600) / 60;
    let second = secs % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Converts a count of days since 1970-01-01 into a `(year, month, day)`
/// Gregorian date (Howard Hinnant's algorithm, unsigned variant).
const fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

/// A minimal JSON value tree with exact, escaped rendering — the crate has
/// no external JSON writer, and generated SARIF/JSON must be byte-correct.
enum Json {
    Str(String),
    Int(i64),
    Null,
    Arr(Vec<Self>),
    Obj(Vec<(&'static str, Self)>),
}

impl Json {
    fn str(value: &str) -> Self {
        Self::Str(value.to_string())
    }

    fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Self::Str(value) => write_json_string(value, out),
            Self::Int(value) => {
                let _ = write!(out, "{value}");
            }
            Self::Null => out.push_str("null"),
            Self::Arr(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Self::Obj(fields) => {
                out.push('{');
                for (index, (key, value)) in fields.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_json_string(key, out);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// Writes `value` as a quoted, escaped JSON string.
fn write_json_string(value: &str, out: &mut String) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::RiskScoreCalculator;

    fn finding(
        id: &str,
        tool: &str,
        target: &str,
        title: &str,
        sev: Severity,
        conf: u8,
    ) -> Finding {
        Finding {
            finding_id: id.to_string(),
            source_tool: tool.to_string(),
            title: title.to_string(),
            target_id: target.to_string(),
            severity: sev,
            confidence_percent: conf,
            normalized_risk_score: RiskScoreCalculator::normalized_score(sev, conf, false),
            remediation_playbook: "patch it".to_string(),
        }
    }

    fn sample() -> Vec<Finding> {
        vec![
            finding(
                "f-1",
                "nuclei",
                "web",
                "SQL injection",
                Severity::Critical,
                90,
            ),
            finding(
                "f-2",
                "semgrep",
                "api",
                "Hardcoded secret",
                Severity::Medium,
                70,
            ),
        ]
    }

    #[test]
    fn sarif_is_valid_json_with_expected_structure() {
        let sarif = render_sarif(&sample());
        let parsed = crate::json::parse(&sarif).expect("SARIF must be valid JSON");
        assert_eq!(
            parsed.get("version").and_then(|v| v.as_str()),
            Some("2.1.0")
        );
        let runs = parsed.get("runs").and_then(|v| v.as_array()).expect("runs");
        let results = runs[0]
            .get("results")
            .and_then(|v| v.as_array())
            .expect("results");
        assert_eq!(results.len(), 2);
        // Highest risk first: the critical SQLi.
        assert_eq!(
            results[0].get("level").and_then(|v| v.as_str()),
            Some("error"),
        );
    }

    #[test]
    fn json_summary_parses_and_counts_severities() {
        let findings = sample();
        let inputs = ReportInputs {
            engagement_id: "eng-1",
            findings: &findings,
            evidence: &[],
            generated_at_epoch: 1_700_000_000,
        };
        let json = render_json(&inputs);
        let parsed = crate::json::parse(&json).expect("valid JSON");
        let summary = parsed.get("summary").expect("summary");
        assert_eq!(
            summary
                .get("total")
                .and_then(crate::json::JsonValue::as_u64),
            Some(2)
        );
        assert_eq!(
            summary
                .get("critical")
                .and_then(crate::json::JsonValue::as_u64),
            Some(1)
        );
    }

    #[test]
    fn markdown_has_the_expected_sections_and_ranking() {
        let findings = sample();
        let inputs = ReportInputs {
            engagement_id: "eng-1",
            findings: &findings,
            evidence: &[capture_record()],
            generated_at_epoch: 1_700_000_000,
        };
        let md = render_markdown(&inputs);
        assert!(md.contains("# Security Engagement Report"));
        assert!(md.contains("## Executive Summary"));
        assert!(md.contains("## Severity Rollup"));
        assert!(md.contains("## Attack Path Analysis"));
        assert!(md.contains("## Evidence & Chain of Custody"));
        // Critical SQLi ranks above the medium finding.
        let sqli = md.find("SQL injection").expect("sqli present");
        let secret = md.find("Hardcoded secret").expect("secret present");
        assert!(sqli < secret);
    }

    fn capture_record() -> EvidenceRecord {
        EvidenceRecord {
            target_id: "web".to_string(),
            tool: "nuclei".to_string(),
            output_sha256: "abc123".to_string(),
            byte_len: 42,
            exit_code: Some(0),
        }
    }

    #[test]
    fn renderers_are_deterministic() {
        let findings = sample();
        let inputs = ReportInputs {
            engagement_id: "eng-1",
            findings: &findings,
            evidence: &[],
            generated_at_epoch: 1_700_000_000,
        };
        assert_eq!(render_sarif(&findings), render_sarif(&findings));
        assert_eq!(render_json(&inputs), render_json(&inputs));
        assert_eq!(render_markdown(&inputs), render_markdown(&inputs));
    }

    #[test]
    fn json_string_escaping_is_correct() {
        let findings = vec![finding(
            "f-1",
            "tool",
            "t",
            "quote \" and \\ backslash",
            Severity::Low,
            50,
        )];
        let sarif = render_sarif(&findings);
        // Must still parse despite the special characters.
        let parsed = crate::json::parse(&sarif).expect("escaped JSON must parse");
        assert!(parsed.get("runs").is_some());
    }

    #[test]
    fn format_utc_matches_known_epoch() {
        // 1700000000 == 2023-11-14T22:13:20Z.
        assert_eq!(format_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn empty_engagement_renders_cleanly() {
        let inputs = ReportInputs {
            engagement_id: "eng-empty",
            findings: &[],
            evidence: &[],
            generated_at_epoch: 0,
        };
        let md = render_markdown(&inputs);
        assert!(md.contains("No findings were reported"));
        let sarif = render_sarif(&[]);
        assert!(crate::json::parse(&sarif).is_some());
    }

    fn sample_engagement_report() -> EngagementReport {
        use crate::engagement_context::{Host, Service};
        use crate::execution::{TaskExecutionOutcome, ToolExecutionReport};
        use crate::pipeline::StageOutcome;
        use crate::registry::ExecutionClass;
        use std::time::Duration;

        let mut context = EngagementContext::new();
        context.record_host(Host {
            address: "10.0.0.5".to_string(),
            hostname: Some("web-01".to_string()),
        });
        context.record_service(Service {
            host: "10.0.0.5".to_string(),
            port: 80,
            protocol: "tcp".to_string(),
            service: Some("http".to_string()),
        });

        let completed = TaskExecutionOutcome {
            target_id: "10.0.0.5".to_string(),
            tool: "nmap".to_string(),
            result: Ok(ToolExecutionReport {
                tool: "nmap".to_string(),
                arguments: Vec::new(),
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                duration: Duration::from_millis(12),
            }),
        };
        let refused = TaskExecutionOutcome {
            target_id: "10.0.0.5".to_string(),
            tool: "sqlmap".to_string(),
            result: Err(ToolExecutionError::Refused(
                "tool not authorized".to_string(),
            )),
        };

        EngagementReport {
            context,
            stages: vec![StageOutcome {
                class: ExecutionClass::ActiveNetwork,
                outcomes: vec![completed, refused],
            }],
            expansion_added: 1,
        }
    }

    #[test]
    fn engagement_markdown_has_all_sections_and_run_facts() {
        let report = sample_engagement_report();
        let findings = sample();
        let deliverable = EngagementDeliverable {
            engagement_id: "eng-9",
            generated_at_epoch: 1_700_000_000,
            report: &report,
            findings: &findings,
        };
        let md = render_engagement_markdown(&deliverable);
        assert!(md.contains("# Security Engagement Deliverable"));
        assert!(md.contains("## Run Summary"));
        assert!(md.contains("## Discovery"));
        assert!(md.contains("## Execution Timeline"));
        assert!(md.contains("## Findings"));
        // Run facts: two tools, one ok, one refused; one expansion step.
        assert!(md.contains("**Tools executed:** 2 (1 succeeded, 0 failed, 1 refused)"));
        assert!(md.contains("**Follow-up steps added by expansion:** 1"));
        // Discovery inventory is rendered.
        assert!(md.contains("10.0.0.5"));
        assert!(md.contains("web-01"));
        assert!(md.contains("http"));
        // Timeline classifies the refusal.
        assert!(md.contains("refused: tool not authorized"));
    }

    #[test]
    fn engagement_json_parses_and_carries_the_summary() {
        let report = sample_engagement_report();
        let findings = sample();
        let deliverable = EngagementDeliverable {
            engagement_id: "eng-9",
            generated_at_epoch: 1_700_000_000,
            report: &report,
            findings: &findings,
        };
        let json = render_engagement_json(&deliverable);
        let parsed = crate::json::parse(&json).expect("valid JSON");
        assert_eq!(
            parsed.get("engagement_id").and_then(|v| v.as_str()),
            Some("eng-9")
        );
        let summary = parsed.get("summary").expect("summary");
        assert_eq!(
            summary
                .get("tools_executed")
                .and_then(crate::json::JsonValue::as_u64),
            Some(2)
        );
        assert_eq!(
            summary
                .get("refused")
                .and_then(crate::json::JsonValue::as_u64),
            Some(1)
        );
        assert_eq!(
            summary
                .get("expansion_added")
                .and_then(crate::json::JsonValue::as_u64),
            Some(1)
        );
        // Discovery and timeline are present and non-empty.
        let hosts = parsed
            .get("discovery")
            .and_then(|d| d.get("hosts"))
            .and_then(|v| v.as_array())
            .expect("hosts array");
        assert_eq!(hosts.len(), 1);
        let timeline = parsed
            .get("timeline")
            .and_then(|v| v.as_array())
            .expect("timeline array");
        assert_eq!(timeline.len(), 2);
    }

    #[test]
    fn engagement_renderers_are_deterministic() {
        let report = sample_engagement_report();
        let findings = sample();
        let deliverable = EngagementDeliverable {
            engagement_id: "eng-9",
            generated_at_epoch: 1_700_000_000,
            report: &report,
            findings: &findings,
        };
        assert_eq!(
            render_engagement_markdown(&deliverable),
            render_engagement_markdown(&deliverable),
        );
        assert_eq!(
            render_engagement_json(&deliverable),
            render_engagement_json(&deliverable),
        );
    }

    #[test]
    fn empty_engagement_deliverable_renders_cleanly() {
        let report = EngagementReport {
            context: EngagementContext::new(),
            stages: Vec::new(),
            expansion_added: 0,
        };
        let deliverable = EngagementDeliverable {
            engagement_id: "eng-empty",
            generated_at_epoch: 0,
            report: &report,
            findings: &[],
        };
        let md = render_engagement_markdown(&deliverable);
        assert!(md.contains("_No tools were executed._"));
        assert!(md.contains("_No hosts discovered._"));
        assert!(md.contains("_No findings were reported for this engagement._"));
        let json = render_engagement_json(&deliverable);
        assert!(crate::json::parse(&json).is_some());
    }
}
