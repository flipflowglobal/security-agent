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
    let parsers: &[&dyn FindingParser] = &[
        &SemgrepJsonParser,
        &NucleiSarifParser,
        &NmapParser,
        &NiktoJsonParser,
        &SqlmapJsonParser,
        &HydraJsonParser,
        &GobusterJsonParser,
        &FfufJsonParser,
        &WpscanJsonParser,
        &AmassJsonLinesParser,
        &MasscanJsonParser,
        &WhatwebJsonParser,
        &Wafw00fJsonParser,
        &LynisJsonParser,
        &SubfinderJsonLinesParser,
        &TrufflehogJsonLinesParser,
        &Enum4linuxNgJsonParser,
        &QarkJsonParser,
        &MarianaTrenchJsonParser,
        &ApkleaksJsonParser,
        &JadxJsonParser,
        &MobSfJsonParser,
        &GenericJsonLinesParser,
        &NmapParser,
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

fn extract_str<'a>(value: &'a JsonValue, key: &str) -> Option<&'a str> {
    value.get(key).and_then(JsonValue::as_str)
}

fn extract_u64(value: &JsonValue, key: &str) -> Option<u64> {
    value.get(key).and_then(JsonValue::as_u64)
}

fn json_array_or_empty<'a>(value: &'a JsonValue, key: &str) -> Vec<&'a JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .map_or_else(Vec::new, |arr| arr.iter().collect())
}

// ─── Semgrep ────────────────────────────────────────────────────────────────

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
                let title = extract_str(result, "check_id")
                    .unwrap_or("semgrep-finding")
                    .to_string();
                let path = extract_str(result, "path");
                let line = result
                    .get("start")
                    .and_then(|start| extract_u64(start, "line"));
                let severity_label = result
                    .get("extra")
                    .and_then(|extra| extract_str(extra, "severity"))
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

// ─── Nuclei (SARIF) ─────────────────────────────────────────────────────────

struct NucleiSarifParser;

impl FindingParser for NucleiSarifParser {
    fn tool_name(&self) -> &'static str {
        "nuclei"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        // Try SARIF format first: runs[].results[]
        if let Some(root) = json::parse(&report.stdout) {
            if let Some(runs) = root.get("runs").and_then(JsonValue::as_array) {
                let mut findings = Vec::new();
                for run in runs {
                    let Some(results) = run.get("results").and_then(JsonValue::as_array) else {
                        continue;
                    };
                    for result in results {
                        let title = extract_str(result, "ruleId")
                            .unwrap_or("nuclei-finding")
                            .to_string();
                        let level = extract_str(result, "level").unwrap_or("");
                        let message = result
                            .get("message")
                            .and_then(|m| extract_str(m, "text"))
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
                if !findings.is_empty() {
                    return findings;
                }
            }
        }

        // NDJSON format: one JSON object per line with template-id, severity, host
        let mut findings = Vec::new();
        for (index, line) in report.stdout.lines().enumerate() {
            let Some(obj) = json::parse(line) else {
                continue;
            };
            let title = extract_str(&obj, "template-id")
                .or_else(|| extract_str(&obj, "templateID"))
                .unwrap_or("nuclei-finding")
                .to_string();
            let severity_label = extract_str(&obj, "severity").unwrap_or("info");
            let host = extract_str(&obj, "host").unwrap_or("");
            let matched_at = extract_str(&obj, "matched-at").unwrap_or("");

            let remediation = if matched_at.is_empty() {
                host.to_string()
            } else {
                matched_at.to_string()
            };

            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                title,
                severity_from_label(severity_label),
                70,
                remediation,
            ));
        }
        findings
    }
}

// ─── Nmap (JSON -oJ + XML -oX) ─────────────────────────────────────────────

/// Unified nmap parser that auto-detects format: JSON (`-oJ`, top-level array)
/// or XML (`-oX`, `<nmaprun>`). Falls back to XML parsing for the test
/// path that supplies XML output — this avoids registering two parsers for
/// the same tool name (which makes the first-wins lookup order-dependent).
struct NmapParser;

impl FindingParser for NmapParser {
    fn tool_name(&self) -> &'static str {
        "nmap"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let stdout = report.stdout.trim();

        // Try JSON path first (nmap -oJ produces a top-level array)
        if stdout.starts_with('[') {
            return parse_nmap_json(target_id, stdout);
        }

        // Fall back to XML path (nmap -oX)
        parse_nmap_xml(target_id, stdout)
    }
}

fn parse_nmap_json(target_id: &str, json_str: &str) -> Vec<Finding> {
    let Some(root) = json::parse(json_str) else {
        return Vec::new();
    };
    let hosts = match &root {
        JsonValue::Array(arr) => arr.iter().filter_map(|v| {
            if v.is_null() { None } else { Some(v) }
        }),
        _ => return Vec::new(),
    };

    let mut findings = Vec::new();
    for host in hosts {
        let addr = extract_str(host, "address").unwrap_or("unknown");
        let ports = json_array_or_empty(host, "ports");
        for port_val in ports {
            let port_id = extract_u64(port_val, "portid").unwrap_or(0);
            let protocol = extract_str(port_val, "protocol").unwrap_or("tcp");
            let state = extract_str(port_val, "state").unwrap_or("unknown");
            let service_name = port_val
                .get("service")
                .and_then(|s| extract_str(s, "name"))
                .unwrap_or("unknown");

            let is_open = state == "open";
            let severity = if is_open && is_risky_port(port_id) {
                Severity::High
            } else {
                Severity::Informational
            };

            let title = format!("{port_id}/{protocol} {state} — {service_name} on {addr}");

            // NSE scripts that indicate vulnerabilities
            let scripts = json_array_or_empty(port_val, "scripts");
            for script in scripts {
                let script_id = extract_str(script, "id").unwrap_or("nse-script");
                let script_output = extract_str(script, "output").unwrap_or("");
                let script_severity = classify_nmap_script(script_id, script_output);
                let index = findings.len();
                findings.push(scored_finding(
                    "nmap", target_id, index,
                    format!("NSE: {script_id} on {addr}:{port_id}"),
                    script_severity, 65,
                    format!("{addr}:{port_id} — {script_output}"),
                ));
            }

            let index = findings.len();
            findings.push(scored_finding(
                "nmap", target_id, index, title, severity, 80,
                format!("{addr}:{port_id}/{protocol}"),
            ));
        }
    }
    findings
}

fn parse_nmap_xml(target_id: &str, xml: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for host_block in xml.split("<host ").skip(1) {
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
                "nmap", target_id, index,
                format!("open-port-{port}-{protocol} ({service})"),
                Severity::Informational, 80,
                format!("{address}:{port}/{protocol}"),
            ));
        }
    }
    findings
}

fn is_risky_port(port: u64) -> bool {
    matches!(
        port,
        21 | 22 | 23 | 25 | 53 | 80 | 110 | 111 | 135 | 139 | 143 | 443 | 445 | 993 | 995
            | 1433 | 1434 | 1521 | 3306 | 3389 | 5432 | 5900 | 5985 | 6379 | 8080 | 8443 | 9200
            | 27017
    )
}

fn classify_nmap_script(script_id: &str, output: &str) -> Severity {
    let lower = output.to_ascii_lowercase();
    if script_id.contains("vuln") || script_id.contains("exploit") {
        Severity::High
    } else if script_id.contains("auth") && lower.contains("anonymous") {
        Severity::Medium
    } else if script_id.contains("ssl") && lower.contains("weak") {
        Severity::Medium
    } else if lower.contains("vulnerable") || lower.contains("exploit") {
        Severity::High
    } else if lower.contains("weak") || lower.contains("insecure") {
        Severity::Medium
    } else {
        Severity::Informational
    }
}

// ─── Nikto (-Format json) ───────────────────────────────────────────────────

struct NiktoJsonParser;

impl FindingParser for NiktoJsonParser {
    fn tool_name(&self) -> &'static str {
        "nikto"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };

        // Nikto JSON: { "host": "...", "vulnerabilities": [{ "id": "...", "msg": "...", "method": "...", "url": "..." }] }
        let vulns = json_array_or_empty(&root, "vulnerabilities");
        if vulns.is_empty() {
            // Also try top-level array format
            if let JsonValue::Array(arr) = &root {
                let mut findings = Vec::new();
                for (index, item) in arr.iter().enumerate() {
                    let msg = extract_str(item, "msg")
                        .or_else(|| extract_str(item, "message"))
                        .unwrap_or("nikto-finding")
                        .to_string();
                    let method = extract_str(item, "method").unwrap_or("GET");
                    let url = extract_str(item, "url").unwrap_or("/");
                    let severity = classify_nikto_finding(&msg);
                    findings.push(scored_finding(
                        self.tool_name(),
                        target_id,
                        index,
                        format!("{method} {url} — {msg}"),
                        severity,
                        65,
                        format!("{method} {url}"),
                    ));
                }
                return findings;
            }
            return Vec::new();
        }

        vulns
            .iter()
            .enumerate()
            .map(|(index, vuln)| {
                let msg = extract_str(vuln, "msg")
                    .or_else(|| extract_str(vuln, "message"))
                    .unwrap_or("nikto-finding")
                    .to_string();
                let method = extract_str(vuln, "method").unwrap_or("GET");
                let url = extract_str(vuln, "url").unwrap_or("/");
                let id = extract_str(vuln, "id").unwrap_or("");
                let severity = classify_nikto_finding(&msg);

                let title = if id.is_empty() {
                    format!("{method} {url} — {msg}")
                } else {
                    format!("[{id}] {method} {url} — {msg}")
                };

                scored_finding(
                    self.tool_name(),
                    target_id,
                    index,
                    title,
                    severity,
                    65,
                    format!("{method} {url}"),
                )
            })
            .collect()
    }
}

fn classify_nikto_finding(msg: &str) -> Severity {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("remote code execution")
        || lower.contains("remote file inclusion")
        || lower.contains("sql injection")
        || lower.contains("xss")
    {
        Severity::High
    } else if lower.contains("directory listing")
        || lower.contains("outdated")
        || lower.contains("default password")
        || lower.contains("backup")
    {
        Severity::Medium
    } else if lower.contains("header") || lower.contains("cookie") {
        Severity::Low
    } else {
        Severity::Informational
    }
}

// ─── SQLMap (--forms --batch --output-dir JSON logs) ────────────────────────

struct SqlmapJsonParser;

impl FindingParser for SqlmapJsonParser {
    fn tool_name(&self) -> &'static str {
        "sqlmap"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        // SQLMap output in JSON format or parsed log lines
        let mut findings = Vec::new();

        // Try JSON array/object
        if let Some(root) = json::parse(&report.stdout) {
            if let Some(vulns) = root.get("vulnerabilities").and_then(JsonValue::as_array) {
                for (index, vuln) in vulns.iter().enumerate() {
                    let title = extract_str(vuln, "title")
                        .unwrap_or("sqlmap-finding")
                        .to_string();
                    let payload = extract_str(vuln, "payload").unwrap_or("");
                    let severity = extract_str(vuln, "severity").unwrap_or("High");
                    findings.push(scored_finding(
                        self.tool_name(),
                        target_id,
                        index,
                        title,
                        severity_from_label(severity),
                        80,
                        if payload.is_empty() {
                            "review-and-remediate".to_string()
                        } else {
                            format!("payload: {payload}")
                        },
                    ));
                }
                return findings;
            }

            // Alternative: top-level array of injection results
            if let JsonValue::Array(arr) = &root {
                for (index, item) in arr.iter().enumerate() {
                    let title = extract_str(item, "title")
                        .or_else(|| extract_str(item, "type"))
                        .unwrap_or("sqlmap-finding")
                        .to_string();
                    let payload = extract_str(item, "payload")
                        .or_else(|| extract_str(item, "vector"))
                        .unwrap_or("");
                    findings.push(scored_finding(
                        self.tool_name(),
                        target_id,
                        index,
                        title,
                        Severity::High,
                        80,
                        if payload.is_empty() {
                            "review-and-remediate".to_string()
                        } else {
                            format!("payload: {payload}")
                        },
                    ));
                }
                return findings;
            }
        }

        // Fallback: line-by-line parsing for text output
        for (index, line) in report.stdout.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if lower.contains("injectable")
                || lower.contains("blind")
                || lower.contains("time-based")
                || lower.contains("union")
                || lower.contains("error-based")
            {
                let severity = if lower.contains("time-based") || lower.contains("union") {
                    Severity::Critical
                } else {
                    Severity::High
                };
                findings.push(scored_finding(
                    self.tool_name(),
                    target_id,
                    index,
                    line.trim().to_string(),
                    severity,
                    75,
                    "review-and-remediate".to_string(),
                ));
            }
        }
        findings
    }
}

// ─── Hydra (JSON output: -o json) ──────────────────────────────────────────

struct HydraJsonParser;

impl FindingParser for HydraJsonParser {
    fn tool_name(&self) -> &'static str {
        "hydra"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        // Hydra JSON: { "success": [...], "error": [...] }
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };

        let mut findings = Vec::new();

        // Parse successful credential discoveries
        let successes = json_array_or_empty(&root, "success");
        for (index, entry) in successes.iter().enumerate() {
            let login = extract_str(entry, "login").unwrap_or("unknown");
            let pass = extract_str(entry, "pass").unwrap_or("unknown");
            let port = extract_u64(entry, "port").unwrap_or(0);
            let service = extract_str(entry, "service").unwrap_or("unknown");
            let host = extract_str(entry, "host").unwrap_or("unknown");

            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                format!("Valid credentials: {login}:{pass} on {service} ({host}:{port})"),
                Severity::Critical,
                90,
                format!("{host}:{port}/{service} — {login}:{pass}"),
            ));
        }

        // Parse errors for informational context
        let errors = json_array_or_empty(&root, "error");
        for (index, entry) in errors.iter().enumerate() {
            let msg = extract_str(entry, "msg")
                .or_else(|| extract_str(entry, "error"))
                .unwrap_or("hydra-error")
                .to_string();
            let index = findings.len() + index;
            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                format!("Hydra error: {msg}"),
                Severity::Informational,
                40,
                "review-tool-output".to_string(),
            ));
        }

        findings
    }
}

// ─── Gobuster (-format json) ───────────────────────────────────────────────

struct GobusterJsonParser;

impl FindingParser for GobusterJsonParser {
    fn tool_name(&self) -> &'static str {
        "gobuster"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        // Gobuster JSON: { "results": [{ "path": "...", "status": ..., "size": ... }] }
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };

        let results = json_array_or_empty(&root, "results");
        let mut findings = Vec::new();

        for (index, entry) in results.iter().enumerate() {
            let path = extract_str(entry, "path").unwrap_or("/");
            let status = extract_u64(entry, "status").unwrap_or(0);
            let size = extract_u64(entry, "size").unwrap_or(0);

            let severity = match status {
                200 => Severity::Informational,
                301 | 302 | 307 | 308 => Severity::Low,
                403 => Severity::Low,
                500 => Severity::Medium,
                _ => Severity::Informational,
            };

            let title = format!("Discovered: {path} (HTTP {status}, {size} bytes)");

            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                title,
                severity,
                60,
                path.to_string(),
            ));
        }
        findings
    }
}

// ─── ffuf (-of json) ───────────────────────────────────────────────────────

struct FfufJsonParser;

impl FindingParser for FfufJsonParser {
    fn tool_name(&self) -> &'static str {
        "ffuf"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        // ffuf JSON: { "results": [{ "input": ..., "position": ..., "status": ..., "length": ..., "words": ..., "url": ... }] }
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };

        let results = json_array_or_empty(&root, "results");
        let mut findings = Vec::new();

        for (index, entry) in results.iter().enumerate() {
            let status = extract_u64(entry, "status").unwrap_or(0);
            let length = extract_u64(entry, "length").unwrap_or(0);
            let words = extract_u64(entry, "words").unwrap_or(0);
            let input_val = extract_str(entry, "input").unwrap_or("");
            let url = extract_str(entry, "url").unwrap_or("");
            let input_key = entry
                .get("input")
                .and_then(|v| v.get("FUZZ"))
                .and_then(JsonValue::as_str)
                .unwrap_or("");

            let fuzz_term = if input_key.is_empty() {
                input_val
            } else {
                input_key
            };

            let severity = match status {
                200 => Severity::Low,
                301 | 302 | 307 | 308 => Severity::Low,
                403 => Severity::Medium,
                500 => Severity::Medium,
                _ => Severity::Informational,
            };

            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                format!("Fuzz match: \"{fuzz_term}\" → {url} (HTTP {status}, {words} words/{length} bytes)"),
                severity,
                60,
                url.to_string(),
            ));
        }
        findings
    }
}

// ─── WPScan (--format json) ────────────────────────────────────────────────

struct WpscanJsonParser;

impl FindingParser for WpscanJsonParser {
    fn tool_name(&self) -> &'static str {
        "wpscan"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };

        let mut findings = Vec::new();

        // Parse vulnerabilities
        let vulns = root.get("vulnerabilities");
        if let Some(vulns_obj) = vulns {
            for category in ["direct", "indirect"] {
                let entries = json_array_or_empty(vulns_obj, category);
                for entry in entries {
                    let title = extract_str(entry, "title")
                        .unwrap_or("wpscan-vuln")
                        .to_string();
                    let severity_label = extract_str(entry, "severity")
                        .or_else(|| extract_str(entry, "cvss"))
                        .unwrap_or("info");
                    let fixed_in = extract_str(entry, "fixed_in").unwrap_or("");
                    let _references = extract_str(entry, "references")
                        .unwrap_or("");

                    let remediation = if !fixed_in.is_empty() {
                        format!("Update to version {fixed_in}")
                    } else {
                        "update-plugin".to_string()
                    };

                    let index = findings.len();
                    findings.push(scored_finding(
                        self.tool_name(),
                        target_id,
                        index,
                        format!("[{category}] {title}"),
                        severity_from_label(severity_label),
                        70,
                        remediation,
                    ));
                }
            }
        }

        // Parse interesting findings
        let interesting = json_array_or_empty(&root, "interesting_findings");
        for entry in interesting {
            let url = extract_str(entry, "url").unwrap_or("/");
            let msg = extract_str(entry, "msg").unwrap_or("interesting finding");
            let confidence = extract_u64(entry, "confidence").unwrap_or(50);

            let index = findings.len();
            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                format!("{msg} at {url}"),
                Severity::Low,
                confidence as u8,
                url.to_string(),
            ));
        }

        // Parse version/maintainer info
        if let Some(version_info) = root.get("version") {
            let version = extract_str(version_info, "number").unwrap_or("unknown");
            let index = findings.len();
            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                format!("WordPress version: {version}"),
                Severity::Informational,
                90,
                "verify-and-update".to_string(),
            ));
        }

        // Parse plugins with vulnerabilities
        if let Some(plugins) = root.get("plugins") {
            if let JsonValue::Object(map) = plugins {
                for (slug, plugin_data) in map {
                    if let Some(vulns) = plugin_data.get("vulnerabilities") {
                        if let JsonValue::Array(arr) = vulns {
                            if !arr.is_empty() {
                                let index = findings.len();
                                findings.push(scored_finding(
                                    self.tool_name(),
                                    target_id,
                                    index,
                                    format!("Plugin \"{slug}\" has {} known vulnerabilities", arr.len()),
                                    Severity::Medium,
                                    75,
                                    "update-or-remove-plugin".to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        findings
    }
}

// ─── Amass (JSON Lines output) ─────────────────────────────────────────────

struct AmassJsonLinesParser;

impl FindingParser for AmassJsonLinesParser {
    fn tool_name(&self) -> &'static str {
        "amass"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (index, line) in report.stdout.lines().enumerate() {
            let Some(obj) = json::parse(line) else {
                continue;
            };
            let name = extract_str(&obj, "name")
                .or_else(|| extract_str(&obj, "hostname"))
                .unwrap_or("unknown")
                .to_string();
            let domain = extract_str(&obj, "domain").unwrap_or("");
            let addresses = json_array_or_empty(&obj, "addresses");
            let addr_str = addresses
                .iter()
                .filter_map(|a| extract_str(a, "ip"))
                .collect::<Vec<_>>()
                .join(", ");
            let tag = extract_str(&obj, "tag").unwrap_or("");
            let sources = json_array_or_empty(&obj, "sources");
            let source_names: Vec<&str> = sources
                .iter()
                .filter_map(|s| extract_str(s, "source"))
                .collect();

            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                format!("Discovered: {name} ({addr_str}) tag={tag}"),
                Severity::Informational,
                70,
                format!("{domain} — sources: {}", source_names.join(", ")),
            ));
        }
        findings
    }
}

// ─── Masscan (-oJ JSON output) ─────────────────────────────────────────────

struct MasscanJsonParser;

impl FindingParser for MasscanJsonParser {
    fn tool_name(&self) -> &'static str {
        "masscan"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        // Masscan -oJ: each line is a JSON object with "ip", "ports": [{ "port": ..., "proto": ..., "status": ..., "service": { "name": ..., "banner": ... } }]
        let mut findings = Vec::new();
        for line in report.stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed == "]" || trimmed == "[" {
                continue;
            }
            // Strip trailing comma if present
            let json_line = trimmed.trim_end_matches(',');
            let Some(obj) = json::parse(json_line) else {
                continue;
            };

            let ip = extract_str(&obj, "ip").unwrap_or("unknown");
            let ports = json_array_or_empty(&obj, "ports");
            for port_val in ports {
                let port = extract_u64(port_val, "port").unwrap_or(0);
                let proto = extract_str(port_val, "proto").unwrap_or("tcp");
                let _status = extract_str(port_val, "status").unwrap_or("open");
                let service_name = port_val
                    .get("service")
                    .and_then(|s| extract_str(s, "name"))
                    .unwrap_or("unknown");
                let banner = port_val
                    .get("service")
                    .and_then(|s| extract_str(s, "banner"))
                    .unwrap_or("");

                let index = findings.len();
                let title = if banner.is_empty() {
                    format!("{ip}:{port}/{proto} open — {service_name}")
                } else {
                    format!("{ip}:{port}/{proto} open — {service_name} ({banner})")
                };

                findings.push(scored_finding(
                    self.tool_name(),
                    target_id,
                    index,
                    title,
                    Severity::Informational,
                    75,
                    format!("{ip}:{port}/{proto}"),
                ));
            }
        }
        findings
    }
}

// ─── WhatWeb (JSON output) ─────────────────────────────────────────────────

struct WhatwebJsonParser;

impl FindingParser for WhatwebJsonParser {
    fn tool_name(&self) -> &'static str {
        "whatweb"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };

        let targets = match &root {
            JsonValue::Array(arr) => arr.iter().collect::<Vec<_>>(),
            JsonValue::Object(_) => vec![&root],
            _ => return Vec::new(),
        };

        let mut findings = Vec::new();
        for target in targets {
            let url = extract_str(target, "target")
                .or_else(|| extract_str(target, "url"))
                .unwrap_or("unknown");
            let _http_status = extract_u64(target, "http_status").unwrap_or(0);

            let plugins = target.get("plugins");
            if let Some(plugins_obj) = plugins {
                for (plugin_name, plugin_data) in plugins_obj.iter_object() {
                    let version = plugin_data
                        .get("version")
                        .and_then(|v| match v {
                            JsonValue::Array(arr) => arr.first().and_then(JsonValue::as_str),
                            JsonValue::String(s) => Some(s.as_str()),
                            _ => None,
                        })
                        .unwrap_or("");
                    let accounts = plugin_data.get("account");

                    let mut details = Vec::new();
                    if !version.is_empty() {
                        details.push(format!("v{version}"));
                    }
                    if let Some(JsonValue::Array(accs)) = accounts {
                        for acc in accs {
                            if let JsonValue::String(s) = acc {
                                details.push(s.clone());
                            }
                        }
                    }

                    let severity = classify_whatweb_plugin(plugin_name);
                    let index = findings.len();
                    findings.push(scored_finding(
                        self.tool_name(),
                        target_id,
                        index,
                        format!("{plugin_name}{} at {url}",
                            if details.is_empty() {
                                String::new()
                            } else {
                                format!(" ({})", details.join(", "))
                            }),
                        severity,
                        55,
                        url.to_string(),
                    ));
                }
            }
        }
        findings
    }
}

fn classify_whatweb_plugin(name: &str) -> Severity {
    let lower = name.to_ascii_lowercase();
    if lower.contains("joomla")
        || lower.contains("wordpress")
        || lower.contains("drupal")
        || lower.contains("phpbb")
        || lower.contains("vbulletin")
        || lower.contains("magento")
    {
        Severity::Low
    } else if lower.contains("jquery") || lower.contains("bootstrap") || lower.contains("d3") {
        Severity::Informational
    } else {
        Severity::Informational
    }
}

// ─── Wafw00f (JSON output) ─────────────────────────────────────────────────

struct Wafw00fJsonParser;

impl FindingParser for Wafw00fJsonParser {
    fn tool_name(&self) -> &'static str {
        "wafw00f"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };

        // wafw00f: { "target": "...", "firewall": "...", "manufacturer": "...", "detected": true }
        let detected = root.get("detected").and_then(JsonValue::as_bool).unwrap_or(false);
        let firewall = extract_str(&root, "firewall").unwrap_or("unknown");
        let manufacturer = extract_str(&root, "manufacturer").unwrap_or("unknown");

        if !detected {
            return Vec::new();
        }

        let target_url = extract_str(&root, "target")
            .or_else(|| extract_str(&root, "url"))
            .unwrap_or("unknown");

        let findings = vec![scored_finding(
            self.tool_name(),
            target_id,
            0,
            format!("WAF detected: {firewall} by {manufacturer}"),
            Severity::Informational,
            80,
            format!("{target_url} — WAF present"),
        )];

        // Also check for additional WAFs if array format
        let mut all_findings = findings;
        if let Some(wafs) = root.get("firewalls").and_then(JsonValue::as_array) {
            for waf in wafs {
                let name = extract_str(waf, "firewall")
                    .or_else(|| extract_str(waf, "name"))
                    .unwrap_or("unknown");
                let mfg = extract_str(waf, "manufacturer").unwrap_or("unknown");
                let index = all_findings.len();
                all_findings.push(scored_finding(
                    self.tool_name(),
                    target_id,
                    index,
                    format!("WAF detected: {name} by {mfg}"),
                    Severity::Informational,
                    80,
                    format!("{target_url} — WAF present"),
                ));
            }
        }

        all_findings
    }
}

// ─── Lynis (JSON report) ───────────────────────────────────────────────────

struct LynisJsonParser;

impl FindingParser for LynisJsonParser {
    fn tool_name(&self) -> &'static str {
        "lynis"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };

        let mut findings = Vec::new();

        // Lynis audit results: { "tests": [{ "id": "...", "description": "...", "result": "...", "severity": ... }] }
        let tests = json_array_or_empty(&root, "tests");
        for (index, test) in tests.iter().enumerate() {
            let id = extract_str(test, "id").unwrap_or("");
            let desc = extract_str(test, "description")
                .or_else(|| extract_str(test, "desc"))
                .unwrap_or("lynis-test");
            let result = extract_str(test, "result").unwrap_or("");
            let severity_label = extract_str(test, "severity").unwrap_or("");
            let warning = test.get("warning").and_then(JsonValue::as_bool).unwrap_or(false);
            let critical = test.get("critical").and_then(JsonValue::as_bool).unwrap_or(false);

            let severity = if critical {
                Severity::High
            } else if warning {
                Severity::Medium
            } else if !severity_label.is_empty() {
                severity_from_label(severity_label)
            } else {
                Severity::Informational
            };

            let title = if id.is_empty() {
                desc.to_string()
            } else {
                format!("[{id}] {desc}: {result}")
            };

            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                title,
                severity,
                60,
                "lynis-audit".to_string(),
            ));
        }

        // Also parse hardening index
        if let Some(hardening) = root.get("hardening_index") {
            let score = extract_u64(&hardening, "score")
                .or_else(|| {
                    // Sometimes it's just a number
                    if let JsonValue::Number(n) = hardening {
                        Some(*n as u64)
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let index = findings.len();
            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                format!("Lynis hardening index: {score}/100"),
                if score < 50 {
                    Severity::High
                } else if score < 75 {
                    Severity::Medium
                } else {
                    Severity::Low
                },
                85,
                "improve-system-hardening".to_string(),
            ));
        }

        findings
    }
}

// ─── Subfinder (JSON Lines) ────────────────────────────────────────────────

struct SubfinderJsonLinesParser;

impl FindingParser for SubfinderJsonLinesParser {
    fn tool_name(&self) -> &'static str {
        "subfinder"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (index, line) in report.stdout.lines().enumerate() {
            let Some(obj) = json::parse(line) else {
                continue;
            };
            let host = extract_str(&obj, "host")
                .or_else(|| extract_str(&obj, "domain"))
                .unwrap_or("unknown")
                .to_string();
            let source = extract_str(&obj, "source").unwrap_or("unknown");

            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                format!("Discovered subdomain: {host} (source: {source})"),
                Severity::Informational,
                65,
                host,
            ));
        }
        findings
    }
}

// ─── Trufflehog (JSON Lines) ───────────────────────────────────────────────

struct TrufflehogJsonLinesParser;

impl FindingParser for TrufflehogJsonLinesParser {
    fn tool_name(&self) -> &'static str {
        "trufflehog"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (index, line) in report.stdout.lines().enumerate() {
            let Some(obj) = json::parse(line) else {
                continue;
            };
            let detector_name = extract_str(&obj, "DetectorName")
                .or_else(|| extract_str(&obj, "detector_name"))
                .unwrap_or("unknown-secret")
                .to_string();
            let verified = obj
                .get("Verified")
                .or_else(|| obj.get("verified"))
                .and_then(JsonValue::as_bool)
                .unwrap_or(false);
            let source_name = extract_str(&obj, "SourceName")
                .or_else(|| extract_str(&obj, "source_name"))
                .unwrap_or("unknown");
            let source_metadata = obj.get("SourceMetadata");
            let repo_url = source_metadata
                .and_then(|m| m.get("Data"))
                .and_then(|d| d.get("Git"))
                .and_then(|g| extract_str(g, "remote"))
                .unwrap_or("");

            let severity = if verified {
                Severity::Critical
            } else {
                Severity::High
            };

            let title = format!("Secret detected: {detector_name} ({source_name})");
            let remediation = if verified {
                format!("Verified secret — rotate immediately: {repo_url}")
            } else {
                format!("Unverified secret — investigate: {repo_url}")
            };

            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                title,
                severity,
                if verified { 95 } else { 60 },
                remediation,
            ));
        }
        findings
    }
}

// ─── enum4linux-ng (JSON output) ───────────────────────────────────────────

struct Enum4linuxNgJsonParser;

impl FindingParser for Enum4linuxNgJsonParser {
    fn tool_name(&self) -> &'static str {
        "enum4linux"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };

        let mut findings = Vec::new();

        // Parse users
        let users = json_array_or_empty(&root, "users");
        for user_entry in &users {
            let username = extract_str(user_entry, "username")
                .or_else(|| extract_str(user_entry, "user"))
                .unwrap_or("unknown");
            let rid = extract_u64(user_entry, "rid").unwrap_or(0);

            let severity = if rid == 500 || rid == 501 {
                Severity::Low
            } else {
                Severity::Informational
            };

            let index = findings.len();
            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                format!("SMB user discovered: {username} (RID {rid})"),
                severity,
                70,
                "smb-user-enumeration".to_string(),
            ));
        }

        // Parse shares
        let shares = json_array_or_empty(&root, "shares");
        for share in &shares {
            let name = extract_str(share, "name").unwrap_or("unknown");
            let type_val = extract_str(share, "type").unwrap_or("");
            let comment = extract_str(share, "comment").unwrap_or("");

            let severity = if name.to_uppercase() == "IPC$" || name.to_uppercase() == "ADMIN$" {
                Severity::Informational
            } else if name.to_uppercase() == "C$" {
                Severity::Low
            } else {
                Severity::Low
            };

            let index = findings.len();
            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                format!("SMB share: {name} [{type_val}] — {comment}"),
                severity,
                70,
                format!("smb://target/{name}"),
            ));
        }

        // Parse policies
        if let Some(policy) = root.get("password_policy") {
            let min_len = extract_u64(policy, "minimum_password_length").unwrap_or(0);
            let _complexity = extract_str(policy, "complexity").unwrap_or("");

            if min_len > 0 && min_len < 8 {
                let index = findings.len();
                findings.push(scored_finding(
                    self.tool_name(),
                    target_id,
                    index,
                    format!("Weak password policy: minimum length {min_len}"),
                    Severity::Medium,
                    75,
                    "enforce-stronger-password-policy".to_string(),
                ));
            }
        }

        // Parse groups
        let groups = json_array_or_empty(&root, "groups");
        for group in &groups {
            let name = extract_str(group, "name").unwrap_or("unknown");
            let members = json_array_or_empty(group, "members");
            let member_names: Vec<&str> = members
                .iter()
                .filter_map(|m| extract_str(m, "name").or_else(|| m.as_str()))
                .collect();

            if !member_names.is_empty() {
                let index = findings.len();
                findings.push(scored_finding(
                    self.tool_name(),
                    target_id,
                    index,
                    format!("Group \"{name}\": {}", member_names.join(", ")),
                    Severity::Informational,
                    65,
                    "smb-group-enumeration".to_string(),
                ));
            }
        }

        findings
    }
}

// ─── QARK (JSON output) ───────────────────────────────────────────────────

struct QarkJsonParser;

impl FindingParser for QarkJsonParser {
    fn tool_name(&self) -> &'static str {
        "qark"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };

        let items = match &root {
            JsonValue::Array(arr) => arr.iter().collect::<Vec<_>>(),
            JsonValue::Object(_) => vec![&root],
            _ => return Vec::new(),
        };

        let mut findings = Vec::new();
        for (index, item) in items.iter().enumerate() {
            let title = extract_str(item, "title")
                .or_else(|| extract_str(item, "issue"))
                .unwrap_or("qark-finding")
                .to_string();
            let severity_label = extract_str(item, "severity").unwrap_or("Medium");
            let filepath = extract_str(item, "filepath")
                .or_else(|| extract_str(item, "file"))
                .unwrap_or("");
            let line = extract_u64(item, "line").unwrap_or(0);
            let description = extract_str(item, "description")
                .or_else(|| extract_str(item, "detail"))
                .unwrap_or("");

            let remediation = if !filepath.is_empty() && line > 0 {
                format!("{filepath}:{line}")
            } else if !filepath.is_empty() {
                filepath.to_string()
            } else {
                "review-and-remediate".to_string()
            };

            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                title,
                severity_from_label(severity_label),
                65,
                if description.is_empty() {
                    remediation
                } else {
                    format!("{remediation} — {description}")
                },
            ));
        }
        findings
    }
}

// ─── Mariana Trench (JSON output) ──────────────────────────────────────────

struct MarianaTrenchJsonParser;

impl FindingParser for MarianaTrenchJsonParser {
    fn tool_name(&self) -> &'static str {
        "mariana-trench"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };

        let results = match &root {
            JsonValue::Array(arr) => arr.iter().collect::<Vec<_>>(),
            JsonValue::Object(_) => {
                // May be wrapped in a "results" key
                if let Some(res) = root.get("results").and_then(JsonValue::as_array) {
                    res.iter().collect::<Vec<_>>()
                } else {
                    vec![&root]
                }
            }
            _ => return Vec::new(),
        };

        let mut findings = Vec::new();
        for (index, item) in results.iter().enumerate() {
            let title = extract_str(item, "rule")
                .or_else(|| extract_str(item, "title"))
                .unwrap_or("mt-finding")
                .to_string();
            let severity_label = extract_str(item, "severity").unwrap_or("High");
            let source_file = extract_str(item, "source_file")
                .or_else(|| extract_str(item, "file"))
                .unwrap_or("");
            let sink = extract_str(item, "sink").unwrap_or("");
            let source = extract_str(item, "source").unwrap_or("");

            let remediation = if !sink.is_empty() && !source.is_empty() {
                format!("taint flow: {source} → {sink}")
            } else if !source_file.is_empty() {
                source_file.to_string()
            } else {
                "review-taint-flow".to_string()
            };

            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                title,
                severity_from_label(severity_label),
                70,
                remediation,
            ));
        }
        findings
    }
}

// ─── APKLeaks (JSON output) ────────────────────────────────────────────────

struct ApkleaksJsonParser;

impl FindingParser for ApkleaksJsonParser {
    fn tool_name(&self) -> &'static str {
        "apkleaks"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };

        let mut findings = Vec::new();

        // APKLeaks: { "urls": [...], "emails": [...], "endpoints": [...], "aws_keys": [...] }
        for (category, severity) in [
            ("urls", Severity::Low),
            ("emails", Severity::Medium),
            ("endpoints", Severity::Medium),
            ("aws_keys", Severity::Critical),
            ("google_api_keys", Severity::High),
            ("firebase_urls", Severity::Medium),
            ("hardcoded_secrets", Severity::Critical),
        ] {
            let entries = json_array_or_empty(&root, category);
            for entry in entries {
                let value = match entry {
                    JsonValue::String(s) => s.clone(),
                    JsonValue::Object(_) => {
                        extract_str(&entry, "match")
                            .or_else(|| extract_str(&entry, "value"))
                            .or_else(|| extract_str(&entry, "url"))
                            .unwrap_or("unknown")
                            .to_string()
                    }
                    _ => continue,
                };

                let index = findings.len();
                findings.push(scored_finding(
                    self.tool_name(),
                    target_id,
                    index,
                    format!("{category}: {value}"),
                    severity,
                    if severity == Severity::Critical {
                        90
                    } else {
                        65
                    },
                    format!("review-{category}"),
                ));
            }
        }
        findings
    }
}

// ─── jadx (JSON output) ────────────────────────────────────────────────────

struct JadxJsonParser;

impl FindingParser for JadxJsonParser {
    fn tool_name(&self) -> &'static str {
        "jadx"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };

        let mut findings = Vec::new();

        // jadx may report: { "classes": [...], "warnings": [...], "errors": [...] }
        let warnings = json_array_or_empty(&root, "warnings");
        for (index, warn) in warnings.iter().enumerate() {
            let msg = extract_str(warn, "message")
                .or_else(|| extract_str(warn, "msg"))
                .unwrap_or("jadx-warning")
                .to_string();
            let file = extract_str(warn, "file").unwrap_or("");

            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                format!("jadx warning: {msg}"),
                Severity::Low,
                40,
                if file.is_empty() {
                    "review-jadx-output".to_string()
                } else {
                    file.to_string()
                },
            ));
        }

        // Errors
        let errors = json_array_or_empty(&root, "errors");
        for error in &errors {
            let msg = extract_str(error, "message")
                .or_else(|| extract_str(error, "msg"))
                .unwrap_or("jadx-error")
                .to_string();
            let index = findings.len();
            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                format!("jadx error: {msg}"),
                Severity::Informational,
                30,
                "review-jadx-output".to_string(),
            ));
        }

        // If jadx found classes with security annotations
        let classes = json_array_or_empty(&root, "classes");
        for class in &classes {
            let name = extract_str(class, "name").unwrap_or("");
            let annotations = json_array_or_empty(class, "annotations");
            for annotation in &annotations {
                let ann_name = extract_str(annotation, "name").unwrap_or("");
                if ann_name.contains("Permission")
                    || ann_name.contains("Unsafe")
                    || ann_name.contains("Deprecated")
                {
                    let index = findings.len();
                    findings.push(scored_finding(
                        self.tool_name(),
                        target_id,
                        index,
                        format!("{ann_name} annotation on {name}"),
                        Severity::Low,
                        50,
                        name.to_string(),
                    ));
                }
            }
        }

        findings
    }
}

// ─── MobSF (JSON output) ───────────────────────────────────────────────────

struct MobSfJsonParser;

impl FindingParser for MobSfJsonParser {
    fn tool_name(&self) -> &'static str {
        "mobsf"
    }

    fn parse(&self, target_id: &str, report: &ToolExecutionReport) -> Vec<Finding> {
        let Some(root) = json::parse(&report.stdout) else {
            return Vec::new();
        };

        let mut findings = Vec::new();

        // MobSF scan results: { "security_analysis": [...], "permissions": [...], "components": [...] }
        let security = json_array_or_empty(&root, "security_analysis");
        for (index, item) in security.iter().enumerate() {
            let title = extract_str(item, "title")
                .or_else(|| extract_str(item, "issue"))
                .unwrap_or("mobsf-finding")
                .to_string();
            let severity_label = extract_str(item, "severity").unwrap_or("Medium");
            let description = extract_str(item, "description").unwrap_or("");
            let file_path = extract_str(item, "file_path")
                .or_else(|| extract_str(item, "file"))
                .unwrap_or("");

            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                title,
                severity_from_label(severity_label),
                70,
                if !file_path.is_empty() {
                    format!("{file_path} — {description}")
                } else if !description.is_empty() {
                    description.to_string()
                } else {
                    "review-mobsf-output".to_string()
                },
            ));
        }

        // Permissions
        let permissions = json_array_or_empty(&root, "permissions");
        for perm in &permissions {
            let name = extract_str(perm, "name")
                .or_else(|| perm.as_str())
                .unwrap_or("unknown");
            let status = extract_str(perm, "status").unwrap_or("");

            let severity = if status == "dangerous" {
                Severity::Medium
            } else {
                Severity::Informational
            };

            let index = findings.len();
            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                format!("Permission: {name} [{status}]"),
                severity,
                60,
                "review-permissions".to_string(),
            ));
        }

        // Binary analysis / file analysis
        let binaries = json_array_or_empty(&root, "binary_analysis");
        for binary in &binaries {
            let title = extract_str(binary, "title")
                .unwrap_or("binary-analysis-finding")
                .to_string();
            let severity_label = extract_str(binary, "severity").unwrap_or("Informational");
            let description = extract_str(binary, "description").unwrap_or("");

            let index = findings.len();
            findings.push(scored_finding(
                self.tool_name(),
                target_id,
                index,
                title,
                severity_from_label(severity_label),
                60,
                if !description.is_empty() {
                    description.to_string()
                } else {
                    "review-binary-analysis".to_string()
                },
            ));
        }

        findings
    }
}

// ─── Generic JSON Lines Fallback ────────────────────────────────────────────

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
                let title = extract_str(&value, "title")?.to_string();
                let severity_label = extract_str(&value, "severity")?;
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
    fn nuclei_ndjson_parses_findings() {
        let stdout = r#"{"template-id":"CVE-2024-1234","severity":"critical","host":"example.com","matched-at":"https://example.com/api"}
{"template-id":"misconfig-xyz","severity":"medium","host":"example.com","matched-at":"https://example.com/admin"}"#;
        let findings = ingest("target-a", &report("nuclei", stdout));

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    #[test]
    fn nmap_json_parses_open_ports() {
        let stdout = r#"[{"address":"192.168.1.1","ports":[{"portid":80,"protocol":"tcp","state":"open","service":{"name":"http"}},{"portid":22,"protocol":"tcp","state":"open","service":{"name":"ssh"}}]}]"#;
        let findings = ingest("target-a", &report("nmap", stdout));

        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("80/tcp"));
        assert!(findings[1].title.contains("22/tcp"));
    }

    #[test]
    fn nmap_json_with_nse_scripts() {
        let stdout = r#"[{"address":"10.0.0.1","ports":[{"portid":445,"protocol":"tcp","state":"open","service":{"name":"smb"},"scripts":[{"id":"smb-vuln-ms17-010","output":"VULNERABLE: Remote Code Execution"}]}]}]"#;
        let findings = ingest("target-a", &report("nmap", stdout));

        // Should have the NSE vuln finding plus the port finding
        assert!(findings.len() >= 2);
        let has_nse = findings.iter().any(|f| f.title.contains("smb-vuln"));
        assert!(has_nse);
    }

    #[test]
    fn nikto_json_parses_vulnerabilities() {
        let stdout = r#"{"host":"192.168.1.100","vulnerabilities":[{"id":"001","msg":"Directory listing found","method":"GET","url":"/images/"},{"id":"002","msg":"XSS vulnerability","method":"POST","url":"/search"}]}"#;
        let findings = ingest("target-a", &report("nikto", stdout));

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[1].severity, Severity::High);
    }

    #[test]
    fn sqlmap_json_parses_injection_results() {
        let stdout = r#"{"vulnerabilities":[{"title":"Boolean-based blind SQL injection","payload":"1 AND 1=1","severity":"High"},{"title":"Time-based blind SQL injection","payload":"1 AND SLEEP(5)","severity":"Critical"}]}"#;
        let findings = ingest("target-a", &report("sqlmap", stdout));

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Critical);
    }

    #[test]
    fn hydra_json_parses_credential_findings() {
        let stdout = r#"{"success":[{"login":"admin","pass":"password123","port":22,"service":"ssh","host":"10.0.0.1"}]}"#;
        let findings = ingest("target-a", &report("hydra", stdout));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("admin:password123"));
    }

    #[test]
    fn gobuster_json_parses_directories() {
        let stdout = r#"{"results":[{"path":"/admin","status":200,"size":1234},{"path":"/backup","status":301,"size":0}]}"#;
        let findings = ingest("target-a", &report("gobuster", stdout));

        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn ffuf_json_parses_fuzz_results() {
        let stdout = r#"{"results":[{"input":{"FUZZ":"admin"},"status":200,"length":5678,"words":100,"url":"https://example.com/admin"}]}"#;
        let findings = ingest("target-a", &report("ffuf", stdout));

        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("admin"));
    }

    #[test]
    fn wpscan_json_parses_vulnerabilities() {
        let stdout = r#"{"vulnerabilities":{"direct":[{"title":"SQL Injection in plugin","severity":"high","fixed_in":"2.0"}]},"interesting_findings":[{"url":"http://example.com/wp-login.php","msg":"Login page found","confidence":80}]}"#;
        let findings = ingest("target-a", &report("wpscan", stdout));

        assert!(findings.len() >= 2);
    }

    #[test]
    fn trufflehog_json_lines_parses_secrets() {
        let stdout = r#"{"DetectorName":"AWS Access Key","Verified":true,"SourceName":"git","SourceMetadata":{"Data":{"Git":{"remote":"https://github.com/org/repo"}}}}
{"DetectorName":"GitHub Token","Verified":false,"SourceName":"git","SourceMetadata":{"Data":{"Git":{"remote":"https://github.com/org/repo"}}}}"#;
        let findings = ingest("target-a", &report("trufflehog", stdout));

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::High);
    }

    #[test]
    fn wafw00f_json_parses_waf_detection() {
        let stdout = r#"{"target":"https://example.com","detected":true,"firewall":"CloudFlare","manufacturer":"CloudFlare, Inc."}"#;
        let findings = ingest("target-a", &report("wafw00f", stdout));

        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("CloudFlare"));
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

    #[test]
    fn masscan_json_parses_ports() {
        let stdout = r#"{"ip":"10.0.0.1","ports":[{"port":80,"proto":"tcp","status":"open","service":{"name":"http","banner":"nginx/1.18"}}]}
{"ip":"10.0.0.1","ports":[{"port":443,"proto":"tcp","status":"open","service":{"name":"https"}}]}"#;
        let findings = ingest("target-a", &report("masscan", stdout));

        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("80/tcp"));
        assert!(findings[0].title.contains("nginx"));
    }

    #[test]
    fn amass_json_lines_parses_subdomains() {
        let stdout = r#"{"name":"api.example.com","domain":"example.com","addresses":[{"ip":"1.2.3.4"}],"tag":"brute","sources":[{"source":"dns"}]}"#;
        let findings = ingest("target-a", &report("amass", stdout));

        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("api.example.com"));
    }

    #[test]
    fn subfinder_json_lines_parses_results() {
        let stdout = r#"{"host":"test.example.com","source":"crtsh"}"#;
        let findings = ingest("target-a", &report("subfinder", stdout));

        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("test.example.com"));
    }

    #[test]
    fn apkleaks_json_parses_secrets() {
        let stdout = r#"{"hardcoded_secrets":[{"match":"api_key=sk_live_abc123"}],"urls":[{"match":"https://api.example.com/v1"}]}"#;
        let findings = ingest("target-a", &report("apkleaks", stdout));

        assert!(findings.len() >= 2);
        let has_secret = findings.iter().any(|f| f.severity == Severity::Critical);
        assert!(has_secret);
    }

    #[test]
    fn enum4linux_ng_json_parses_users() {
        let stdout = r#"{"users":[{"username":"admin","rid":500},{"username":"guest","rid":501}],"shares":[{"name":"SharedDocs","type":"Disk","comment":"Shared Documents"}]}"#;
        let findings = ingest("target-a", &report("enum4linux", stdout));

        assert!(findings.len() >= 3);
    }

    #[test]
    fn lynis_json_parses_tests() {
        let stdout = r#"{"tests":[{"id":"TEST-001","description":"Check SSH config","result":"Hardened","warning":false,"critical":false},{"id":"TEST-002","description":"Firewall check","result":"Not configured","warning":true,"critical":false}],"hardening_index":{"score":65}}"#;
        let findings = ingest("target-a", &report("lynis", stdout));

        assert!(findings.len() >= 3);
        let has_warning = findings.iter().any(|f| f.severity == Severity::Medium);
        assert!(has_warning);
    }

    #[test]
    fn mariana_trench_json_parses_taint_flows() {
        let stdout = r#"{"results":[{"rule":"taint-source-to-sink","severity":"High","source":"request.getParameter()","sink":"Statement.execute()","source_file":"com/app/DbHelper.java"}]}"#;
        let findings = ingest("target-a", &report("mariana-trench", stdout));

        assert_eq!(findings.len(), 1);
        assert!(findings[0].remediation_playbook.contains("request.getParameter"));
    }
}
