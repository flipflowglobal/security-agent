//! Append-only, on-disk persistence for scored findings.
//!
//! [`crate::execution::execute_plan`] runs tools and [`crate::ingest`]
//! turns their output into scored [`Finding`]s, but both are in-memory
//! only and vanish with the process. This module appends each `Finding`
//! to a local JSON Lines file (reusing [`CompatibilityEnvelope`]'s wire
//! format, mirroring `crate::audit_log`) so a real findings history
//! survives past a single run, and can be read back for review or retest
//! scheduling.

use crate::compat::{CompatibilityEnvelope, envelope_to_finding, finding_to_envelope};
use crate::findings::Finding;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[derive(Debug)]
pub enum FindingsLogError {
    Io(std::io::Error),
}

impl fmt::Display for FindingsLogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for FindingsLogError {}

/// Appends every finding in `findings` to the file at `path` as one JSON
/// line each, creating the file if it doesn't already exist.
///
/// Never truncates or rewrites existing lines — this is an append-only log.
///
/// # Errors
///
/// Returns [`FindingsLogError::Io`] if the file cannot be opened or written.
pub fn append_findings(path: &Path, findings: &[Finding]) -> Result<(), FindingsLogError> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(FindingsLogError::Io)?;
    for finding in findings {
        let line = finding_to_envelope(finding).to_wire_format();
        file.write_all(line.as_bytes())
            .map_err(FindingsLogError::Io)?;
    }
    Ok(())
}

/// Reads back every valid finding previously written by
/// [`append_findings`].
///
/// Lines that aren't valid `finding_record` envelopes are skipped rather
/// than failing the whole read, so a log file containing unrelated JSON
/// Lines content (e.g. audit records) doesn't block loading the findings
/// this crate understands.
///
/// # Errors
///
/// Returns [`FindingsLogError::Io`] if the file cannot be read.
pub fn load_findings(path: &Path) -> Result<Vec<Finding>, FindingsLogError> {
    let text = fs::read_to_string(path).map_err(FindingsLogError::Io)?;
    Ok(text
        .lines()
        .filter_map(CompatibilityEnvelope::from_wire_format)
        .filter_map(|envelope| envelope_to_finding(&envelope))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;

    fn sample_findings() -> Vec<Finding> {
        vec![
            Finding {
                finding_id: "semgrep-target-a-0".to_string(),
                source_tool: "semgrep".to_string(),
                title: "exec-detected".to_string(),
                target_id: "target-a".to_string(),
                severity: Severity::High,
                confidence_percent: 75,
                remediation_playbook: "app.py:10".to_string(),
                normalized_risk_score: 6.0,
            },
            Finding {
                finding_id: "nuclei-target-b-0".to_string(),
                source_tool: "nuclei".to_string(),
                title: "rule-1".to_string(),
                target_id: "target-b".to_string(),
                severity: Severity::Medium,
                confidence_percent: 70,
                remediation_playbook: "see tool output for details".to_string(),
                normalized_risk_score: 3.5,
            },
        ]
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "security-agent-findings-log-{name}-{}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn appends_and_loads_findings_round_trip() {
        let path = temp_path("round-trip");
        let _ = fs::remove_file(&path);

        append_findings(&path, &sample_findings()).expect("append should succeed");
        let loaded = load_findings(&path).expect("load should succeed");

        fs::remove_file(&path).expect("remove temp log");
        assert_eq!(loaded, sample_findings());
    }

    #[test]
    fn appending_twice_preserves_earlier_findings() {
        let path = temp_path("append-twice");
        let _ = fs::remove_file(&path);

        let findings = sample_findings();
        append_findings(&path, &findings[..1]).expect("first append should succeed");
        append_findings(&path, &findings[1..]).expect("second append should succeed");
        let loaded = load_findings(&path).expect("load should succeed");

        fs::remove_file(&path).expect("remove temp log");
        assert_eq!(loaded, findings);
    }

    #[test]
    fn load_skips_lines_that_are_not_finding_records() {
        let path = temp_path("skips-non-finding-lines");
        let _ = fs::remove_file(&path);

        fs::write(
            &path,
            "not json\n{\"version\":\"1\",\"producer\":\"x\",\"kind\":\"audit_record\",\"fields\":{}}\n",
        )
        .expect("write temp log");
        append_findings(&path, &sample_findings()[..1]).expect("append should succeed");

        let loaded = load_findings(&path).expect("load should succeed");
        fs::remove_file(&path).expect("remove temp log");

        assert_eq!(loaded, sample_findings()[..1]);
    }

    #[test]
    fn load_reports_io_error_for_missing_file() {
        let path = temp_path("missing");
        let result = load_findings(&path);
        assert!(matches!(result, Err(FindingsLogError::Io(_))));
    }

    #[test]
    fn append_creates_the_file_if_it_does_not_exist() {
        let path = temp_path("creates-file");
        let _ = fs::remove_file(&path);
        assert!(!path.exists());

        append_findings(&path, &sample_findings()).expect("append should succeed");
        assert!(path.exists());

        fs::remove_file(&path).expect("remove temp log");
    }
}
