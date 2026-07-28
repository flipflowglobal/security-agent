//! Parses raw external-tool output (a [`ToolExecutionReport`]) into scored
//! [`Finding`]s.
//!
//! Real execution (`crate::execution::run_external_tool`) captures a
//! tool's stdout but does nothing with its contents. This module closes
//! that gap for tools whose output is deterministic, local JSON: it reads
//! the report, extracts whatever findings the tool reported, and scores
//! each one via [`RiskScoreCalculator`] — never by hand.
//!
//! Tool output is untrusted third-party input. Every parser here is total
//! (no panics on malformed input — a parse failure simply yields no
//! findings for that report) and bounded (at most [`MAX_FINDINGS_PER_REPORT`]
//! findings per report), and only ever reads strings out of the parsed
//! JSON tree — it never executes or otherwise interprets tool output.

use crate::execution::ToolExecutionReport;
use crate::findings::{Finding, RiskScoreCalculator, Severity, severity_from_label};
use crate::json::{self, JsonValue};

/// Upper bound on findings extracted from a single tool report. Mirrors
/// the defensive caps elsewhere in this crate (e.g. autopsy's 100,000-file
/// walk limit): untrusted output should never be able to force unbounded
/// memory growth.
const MAX_FINDINGS_PER_REPORT: usize = 10_000;

/// A parser that knows how to turn one tool's stdout into [`Finding`]s.
trait FindingParser {
    /// The cataloged tool name this parser handles (e.g. `"semgrep"`).
    fn tool_name(&self) -> &'static str;
    /// Parses `report.stdout` for `target_id`. Returns an empty `Vec` when
    /// the output contains no findings or doesn't parse — a clean run or
    /// malformed output is not an ingestion error, it just yields nothing.
    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding>;
}

/// Selects the parser registered for `report.tool` and runs it.
///
/// Tools with no registered parser return an empty `Vec` — their raw
/// output remains available on the [`ToolExecutionReport`] for the
/// operator, it is simply not auto-ingested into scored findings yet.
#[must_use]
pub fn ingest(target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
    let parsers: [&dyn FindingParser; 4] = [
        &SemgrepJsonParser,
        &SarifParser,
        &GenericJsonLinesParser,
        &NmapXmlParser,
    ];
    let Some(parser) = parsers
        .into_iter()
        .find(|parser| parser.tool_name() == report.tool)
    else {
        return Vec::new();
    };
    let mut findings = parser.parse(target_id, report);
    findings.truncate(MAX_FINDINGS_PER_REPORT);
    findings
}

fn scored_finding(
    tool: &str,
    target_id: &str,
    index: usize,
    title: String,
    severity: Severity,
    confidence_percent: u8,
    remediation_playbook: String,
) -> Finding {
    Finding {
        finding_id: format!("{tool}-{target_id}-{index}"),
        source_tool: tool.to_string(),
        title,
        target_id: target_id.to_string(),
        severity,
        confidence_percent,
        normalized_risk_score: RiskScoreCalculator::normalized_score(
            severity,
            confidence_percent,
            false,
        ),
        remediation_playbook,
    }
}

/// Parses `semgrep --json` output: a top-level object with a `results`
/// array, each entry carrying `check_id`, `path`, `start.line`, and
/// `extra.severity`.
struct SemgrepJsonParser;

impl FindingParser for SemgrepJsonParser {
    fn tool_name(&self) -> &'static str {
        "semgrep"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };
        let Some(results) = root.get("results").and_then(JsonValue::as_array) else {
            return Vec::new();
        };

        results
            .iter()
            .enumerate()
            .map(|(index, result)| {
                let title = result
                    .get("check_id")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("semgrep-finding")
                    .to_string();
                let path = result.get("path").and_then(JsonValue::as_str);
                let line = result
                    .get("start")
                    .and_then(|start| start.get("line"))
                    .and_then(JsonValue::as_u64);
                let severity_label = result
                    .get("extra")
                    .and_then(|extra| extra.get("severity"))
                    .and_then(JsonValue::as_str)
                    .unwrap_or("");

                let remediation_playbook = match (path, line) {
                    (Some(path), Some(line)) => format!("{path}:{line}"),
                    (Some(path), None) => path.to_string(),
                    _ => "review-and-remediate".to_string(),
                };

                scored_finding(
                    self.tool_name(),
                    target_id,
                    index,
                    title,
                    severity_from_label(severity_label),
                    75,
                    remediation_playbook,
                )
            })
            .collect()
    }
}

/// Parses generic SARIF output (`runs[].results[]`), used by any
/// SARIF-emitting tool (e.g. `nuclei -sarif`).
struct SarifParser;

impl FindingParser for SarifParser {
    fn tool_name(&self) -> &'static str {
        "nuclei"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };
        let Some(runs) = root.get("runs").and_then(JsonValue::as_array) else {
            return Vec::new();
        };

        let mut findings = Vec::new();
        for run in runs {
            let Some(results) = run.get("results").and_then(JsonValue::as_array) else {
                continue;
            };
            for result in results {
                let title = result
                    .get("ruleId")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("sarif-finding")
                    .to_string();
                let level = result
                    .get("level")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("");
                let message = result
                    .get("message")
                    .and_then(|message| message.get("text"))
                    .and_then(JsonValue::as_str)
                    .unwrap_or("see tool output for details")
                    .to_string();

                let index = findings.len();
                findings.push(scored_finding(
                    self.tool_name(),
                    target_id,
                    index,
                    title,
                    severity_from_label(level),
                    70,
                    message,
                ));
            }
        }
        findings
    }
}

/// Fallback for tools emitting one JSON object per line (JSON Lines).
/// Requires each line to carry `severity` and `title`; lines missing
/// either, or that aren't valid JSON, are skipped rather than failing the
/// whole report.
struct GenericJsonLinesParser;

impl FindingParser for GenericJsonLinesParser {
    fn tool_name(&self) -> &'static str {
        "generic-jsonl"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        report
            .stdout
            .lines()
            .filter_map(json::parse)
            .enumerate()
            .filter_map(|(index, value)| {
                let title = value.get("title").and_then(JsonValue::as_str)?.to_string();
                let severity_label = value.get("severity").and_then(JsonValue::as_str)?;
                Some(scored_finding(
                    self.tool_name(),
                    target_id,
                    index,
                    title,
                    severity_from_label(severity_label),
                    60,
                    "review-and-remediate".to_string(),
                ))
            })
            .collect()
    }
}

/// Parses nmap XML (`-oX`) into one informational finding per open port:
/// an exposed service is attack surface worth recording, even when no
/// vulnerability is asserted. Tolerant of malformed XML (skips fragments it
/// cannot read) and bounded by [`MAX_FINDINGS_PER_REPORT`].
struct NmapXmlParser;

impl FindingParser for NmapXmlParser {
    fn tool_name(&self) -> &'static str {
        "nmap"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let mut findings = Vec::new();
        // "<host " avoids matching "<hosthint"/"<hostnames".
        for host_block in report.stdout.split("<host ").skip(1) {
            let address = xml_attr(host_block, "addr").unwrap_or(target_id);
            for port_block in host_block.split("<port ").skip(1) {
                if findings.len() >= MAX_FINDINGS_PER_REPORT {
                    return findings;
                }
                if !port_block.contains("state=\"open\"") {
                    continue;
                }
                let protocol = xml_attr(port_block, "protocol").unwrap_or("tcp");
                let Some(port) = xml_attr(port_block, "portid") else {
                    continue;
                };
                let service = port_block
                    .split_once("<service ")
                    .and_then(|(_, rest)| xml_attr(rest, "name"))
                    .unwrap_or("unknown");
                let index = findings.len();
                findings.push(scored_finding(
                    self.tool_name(),
                    target_id,
                    index,
                    format!("open-port-{port}-{protocol} ({service})"),
                    Severity::Informational,
                    80,
                    format!("{address}:{port}/{protocol}"),
                ));
            }
        }
        findings
    }
}

/// Reads an attribute value `key="value"` out of an XML fragment, or `None`.
fn xml_attr<'a>(fragment: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=\"");
    let start = fragment.find(&needle)? + needle.len();
    let rest = &fragment[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn report(tool: &str, stdout: &str) -> ToolExecutionReport {
        ToolExecutionReport {
            tool: tool.to_string(),
            arguments: Vec::new(),
            exit_code: Some(0),
            stdout: stdout.to_string(),
            stderr: String::new(),
            duration: Duration::from_millis(1),
        }
    }

    #[test]
    fn semgrep_json_parses_two_findings_with_correct_severities() {
        let stdout = r#"{"results":[
            {"check_id":"python.lang.security.audit.exec-detected","path":"app.py","start":{"line":10},"extra":{"severity":"ERROR"}},
            {"check_id":"python.lang.correctness.unused-var","path":"util.py","start":{"line":3},"extra":{"severity":"WARNING"}}
        ]}"#;
        let findings = ingest("target-a", &report("semgrep", stdout));

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].source_tool, "semgrep");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].remediation_playbook, "app.py:10");
        assert_eq!(findings[1].severity, Severity::Medium);
        assert!(findings[0].normalized_risk_score > 0.0);
        assert!(findings[1].normalized_risk_score > 0.0);
    }

    #[test]
    fn sarif_parser_maps_levels() {
        let stdout = r#"{"runs":[{"results":[
            {"ruleId":"rule-1","level":"error","message":{"text":"m1"}},
            {"ruleId":"rule-2","level":"warning","message":{"text":"m2"}},
            {"ruleId":"rule-3","level":"note","message":{"text":"m3"}}
        ]}]}"#;
        let findings = ingest("target-a", &report("nuclei", stdout));

        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Medium);
        assert_eq!(findings[2].severity, Severity::Informational);
    }

    #[test]
    fn clean_run_yields_no_findings() {
        let findings = ingest("target-a", &report("semgrep", r#"{"results":[]}"#));
        assert!(findings.is_empty());
    }

    #[test]
    fn unknown_tool_returns_empty_vec() {
        let findings = ingest("target-a", &report("wafw00f", "some scan output"));
        assert!(findings.is_empty());
    }

    #[test]
    fn nmap_xml_yields_informational_findings_for_open_ports() {
        let xml = r#"<nmaprun><host starttime="1"><address addr="10.0.0.5" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
              <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
            </ports></host></nmaprun>"#;
        let findings = ingest("target-a", &report("nmap", xml));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Informational);
        assert!(findings[0].title.contains("open-port-443-tcp"));
        assert_eq!(findings[0].remediation_playbook, "10.0.0.5:443/tcp");
    }

    #[test]
    fn nmap_non_xml_output_yields_nothing() {
        assert!(ingest("target-a", &report("nmap", "some scan output")).is_empty());
    }

    #[test]
    fn finding_ids_are_stable_and_indexed() {
        let stdout = r#"{"results":[{"check_id":"c1","path":"a.py","start":{"line":1},"extra":{"severity":"ERROR"}}]}"#;
        let first = ingest("target-a", &report("semgrep", stdout));
        let second = ingest("target-a", &report("semgrep", stdout));

        assert_eq!(first[0].finding_id, second[0].finding_id);
        assert_eq!(first[0].finding_id, "semgrep-target-a-0");
    }

    #[test]
    fn malformed_json_is_ignored_not_panicked() {
        let findings = ingest("target-a", &report("semgrep", "{not valid json"));
        assert!(findings.is_empty());

        let findings = ingest("target-a", &report("nuclei", "{\"runs\": not-json}"));
        assert!(findings.is_empty());
    }

    #[test]
    fn generic_jsonl_requires_severity_and_title() {
        let stdout = "{\"severity\":\"high\",\"title\":\"finding-a\"}\n{\"title\":\"missing-severity\"}\nnot json\n";
        let findings = ingest("target-a", &report("generic-jsonl", stdout));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "finding-a");
        assert_eq!(findings[0].severity, Severity::High);
    }
}
