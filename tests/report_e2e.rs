//! End-to-end reporting integration tests.
//!
//! Unlike the black-box `cli.rs`, these seed a real findings log through the
//! library, then invoke the compiled binary's `--report` command and assert
//! on the rendered deliverables — exercising the full load → correlate →
//! render → print path a real engagement uses.

use security_agent::{Finding, RiskScoreCalculator, Severity, append_findings};
use std::path::PathBuf;
use std::process::Command;

const fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_security-agent")
}

fn temp_path(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "sa-e2e-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    ));
    path
}

fn finding(
    id: &str,
    tool: &str,
    target: &str,
    title: &str,
    severity: Severity,
    confidence: u8,
) -> Finding {
    Finding {
        finding_id: id.to_string(),
        source_tool: tool.to_string(),
        title: title.to_string(),
        target_id: target.to_string(),
        severity,
        confidence_percent: confidence,
        normalized_risk_score: RiskScoreCalculator::normalized_score(severity, confidence, false),
        remediation_playbook: "parameterize queries and add a WAF rule".to_string(),
    }
}

#[test]
fn report_sarif_end_to_end_contains_real_findings() {
    let log = temp_path("sarif");
    append_findings(
        &log,
        &[
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
        ],
    )
    .expect("write findings log");

    let output = Command::new(binary())
        .args(["--report", log.to_str().unwrap(), "--format", "sarif"])
        .output()
        .expect("run binary");
    let _ = std::fs::remove_file(&log);

    assert!(output.status.success());
    let sarif = String::from_utf8(output.stdout).expect("utf8");
    assert!(sarif.contains("\"version\":\"2.1.0\""));
    assert!(sarif.contains("SQL injection"));
    // The critical finding maps to SARIF "error".
    assert!(sarif.contains("\"level\":\"error\""));
}

#[test]
fn report_markdown_end_to_end_ranks_by_risk() {
    let log = temp_path("md");
    append_findings(
        &log,
        &[
            finding(
                "f-low",
                "whatweb",
                "web",
                "Server banner disclosure",
                Severity::Low,
                60,
            ),
            finding(
                "f-crit",
                "sqlmap",
                "web",
                "SQL injection",
                Severity::Critical,
                95,
            ),
        ],
    )
    .expect("write findings log");

    let output = Command::new(binary())
        .args(["--report", log.to_str().unwrap(), "--engagement", "e2e-md"])
        .output()
        .expect("run binary");
    let _ = std::fs::remove_file(&log);

    assert!(output.status.success());
    let md = String::from_utf8(output.stdout).expect("utf8");
    assert!(md.contains("# Security Engagement Report"));
    assert!(md.contains("e2e-md"));
    assert!(md.contains("## Attack Path Analysis"));
    // The critical SQLi must rank above the low-severity banner finding.
    let sqli = md.find("SQL injection").expect("sqli present");
    let banner = md.find("Server banner disclosure").expect("banner present");
    assert!(sqli < banner, "critical finding should rank first");
}

#[test]
fn report_json_end_to_end_is_valid_and_summarized() {
    let log = temp_path("json");
    append_findings(
        &log,
        &[finding("f-1", "nuclei", "web", "XSS", Severity::High, 80)],
    )
    .expect("write findings log");

    let output = Command::new(binary())
        .args(["--report", log.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("run binary");
    let _ = std::fs::remove_file(&log);

    assert!(output.status.success());
    let json = String::from_utf8(output.stdout).expect("utf8");
    // Must be machine-parseable and carry the summary.
    assert!(json.contains("\"summary\""));
    assert!(json.contains("\"high\":1"));
    assert!(json.contains("XSS"));
}

#[test]
fn report_tolerates_a_findings_log_full_of_garbage() {
    // A log with no valid finding envelopes must still produce a clean,
    // zero-finding report rather than crashing.
    let log = temp_path("garbage");
    std::fs::write(&log, "not json\n{\"unrelated\":true}\n\n{bad}\n").expect("write");

    let output = Command::new(binary())
        .args(["--report", log.to_str().unwrap()])
        .output()
        .expect("run binary");
    let _ = std::fs::remove_file(&log);

    assert!(output.status.success());
    let md = String::from_utf8(output.stdout).expect("utf8");
    assert!(md.contains("No findings were reported"));
}
