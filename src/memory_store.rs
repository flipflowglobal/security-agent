//! Append-only, on-disk persistence for the cognitive layer's memory.
//!
//! [`crate::cognition::CognitiveMemory`] is in-memory only and is dropped
//! with the process that built it, so every engagement would otherwise
//! start cognitively blank — its hypotheses, beliefs, adversary payoffs,
//! and attention weights falling back to type-based priors with no benefit
//! from anything learned before.
//!
//! This module persists the *evidence* memory is built from — the
//! [`Finding`]s themselves — as an append-only JSON Lines ledger, exactly
//! like [`crate::audit_log`] does for audit records. `CognitiveMemory` is
//! always re-derived by folding the full ledger ([`load_memory`]), so:
//!
//! - persistence is **append-only and lossless** — recording a new
//!   engagement's findings never rewrites or double-counts earlier ones,
//! - the ledger is human-readable and inspectable, one finding per line,
//!   and
//! - the same file loads back into both `CognitiveMemory` (for
//!   history-informed hypotheses) and the raw `Finding` list (for Bayesian
//!   belief revision in [`crate::cognitive_engine`]).

use crate::cognition::CognitiveMemory;
use crate::findings::Finding;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[derive(Debug)]
pub enum MemoryStoreError {
    Io(std::io::Error),
    Serialize(serde_json::Error),
}

impl fmt::Display for MemoryStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(source) => write!(formatter, "{source}"),
            Self::Serialize(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for MemoryStoreError {}

/// Appends every finding in `findings` to the ledger at `path` as one JSON
/// line each, creating the file if it doesn't already exist. Never
/// truncates or rewrites existing lines — this is an append-only ledger,
/// so a later engagement's findings accumulate on top of earlier ones.
///
/// # Errors
///
/// Returns [`MemoryStoreError::Io`] if the file cannot be opened or
/// written, or [`MemoryStoreError::Serialize`] if a finding cannot be
/// serialized.
pub fn append_findings(path: &Path, findings: &[Finding]) -> Result<(), MemoryStoreError> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(MemoryStoreError::Io)?;
    for finding in findings {
        let mut line = serde_json::to_string(finding).map_err(MemoryStoreError::Serialize)?;
        line.push('\n');
        file.write_all(line.as_bytes())
            .map_err(MemoryStoreError::Io)?;
    }
    Ok(())
}

/// Reads back every valid finding previously written by
/// [`append_findings`].
///
/// Lines that aren't valid `Finding` JSON are skipped rather than failing
/// the whole read, so a ledger that also holds unrelated JSON Lines
/// content (or a future format version) doesn't block loading the findings
/// this crate understands.
///
/// # Errors
///
/// Returns [`MemoryStoreError::Io`] if the file cannot be read.
pub fn load_findings(path: &Path) -> Result<Vec<Finding>, MemoryStoreError> {
    let text = fs::read_to_string(path).map_err(MemoryStoreError::Io)?;
    Ok(text
        .lines()
        .filter_map(|line| serde_json::from_str::<Finding>(line).ok())
        .collect())
}

/// Loads the append-only findings ledger at `path` and folds it into a
/// [`CognitiveMemory`], so every engagement's recorded findings inform the
/// next run's cognition.
///
/// # Errors
///
/// Returns [`MemoryStoreError::Io`] if the file cannot be read.
pub fn load_memory(path: &Path) -> Result<CognitiveMemory, MemoryStoreError> {
    let findings = load_findings(path)?;
    let mut memory = CognitiveMemory::new();
    memory.record_findings(&findings);
    Ok(memory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;

    fn sample_findings() -> Vec<Finding> {
        vec![
            Finding {
                finding_id: "F-1".to_string(),
                source_tool: "semgrep".to_string(),
                title: "sql injection".to_string(),
                target_id: "api-1".to_string(),
                severity: Severity::Critical,
                confidence_percent: 90,
                remediation_playbook: "parameterize queries".to_string(),
                normalized_risk_score: 9.0,
            },
            Finding {
                finding_id: "F-2".to_string(),
                source_tool: "nuclei".to_string(),
                title: "weak tls".to_string(),
                target_id: "web-1".to_string(),
                severity: Severity::Medium,
                confidence_percent: 70,
                remediation_playbook: "disable TLS 1.0".to_string(),
                normalized_risk_score: 3.5,
            },
        ]
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "security-agent-memory-store-{name}-{}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn appends_and_loads_findings_round_trip() {
        let path = temp_path("round-trip");
        let _ = fs::remove_file(&path);

        append_findings(&path, &sample_findings()).expect("append should succeed");
        let loaded = load_findings(&path).expect("load should succeed");

        fs::remove_file(&path).expect("remove temp ledger");
        assert_eq!(loaded, sample_findings());
    }

    #[test]
    fn appending_twice_accumulates_across_engagements() {
        let path = temp_path("append-twice");
        let _ = fs::remove_file(&path);

        let findings = sample_findings();
        append_findings(&path, &findings[..1]).expect("first engagement append");
        append_findings(&path, &findings[1..]).expect("second engagement append");

        let memory = load_memory(&path).expect("load memory");
        fs::remove_file(&path).expect("remove temp ledger");

        // Both engagements' findings survive and fold into one memory.
        assert_eq!(memory.history_for("api-1").0, 1);
        assert_eq!(memory.history_for("web-1").0, 1);
    }

    #[test]
    fn load_memory_folds_repeated_findings_for_a_target() {
        let path = temp_path("folds-repeats");
        let _ = fs::remove_file(&path);

        let mut findings = sample_findings();
        // Two more Critical findings on api-1 across a later engagement.
        findings.push(findings[0].clone());
        append_findings(&path, &findings).expect("append should succeed");

        let memory = load_memory(&path).expect("load memory");
        fs::remove_file(&path).expect("remove temp ledger");

        let (count, average) = memory.history_for("api-1");
        assert_eq!(count, 2);
        assert!((average - 10.0).abs() < f32::EPSILON);
    }

    #[test]
    fn load_skips_lines_that_are_not_findings() {
        let path = temp_path("skips-non-findings");
        let _ = fs::remove_file(&path);

        fs::write(&path, "not json\n{\"unrelated\":true}\n").expect("seed ledger");
        append_findings(&path, &sample_findings()[..1]).expect("append should succeed");

        let loaded = load_findings(&path).expect("load should succeed");
        fs::remove_file(&path).expect("remove temp ledger");

        assert_eq!(loaded, sample_findings()[..1]);
    }

    #[test]
    fn load_reports_io_error_for_missing_file() {
        let path = temp_path("missing");
        assert!(matches!(load_findings(&path), Err(MemoryStoreError::Io(_))));
    }

    #[test]
    fn append_creates_the_file_if_it_does_not_exist() {
        let path = temp_path("creates-file");
        let _ = fs::remove_file(&path);
        assert!(!path.exists());

        append_findings(&path, &sample_findings()).expect("append should succeed");
        assert!(path.exists());

        fs::remove_file(&path).expect("remove temp ledger");
    }
}
