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
use crate::evidence::EvidenceRecord;
use crate::findings::{Finding, Severity};
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
}
