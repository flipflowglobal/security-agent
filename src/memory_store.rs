//! Bridges the persistent findings log into cognitive memory.
//!
//! [`crate::cognition::CognitiveMemory`] is in-memory only and is dropped
//! with the process that built it, so every engagement would otherwise
//! start cognitively blank — its hypotheses, beliefs, adversary payoffs,
//! and attention weights falling back to type-based priors with no benefit
//! from anything learned before.
//!
//! Rather than defining a second on-disk format, this module folds the
//! single, append-only findings log ([`crate::findings_log`] — the same
//! `finding_record` JSON Lines written by `--findings-log` and
//! `--record-findings`) straight into a `CognitiveMemory`. One format
//! feeds the whole intelligence loop: a scan's findings log loads directly
//! into the cognitive layer, so `CognitiveMemory` is always re-derived by
//! folding the full log — lossless, and never a separate serialization to
//! keep in sync.

use crate::cognition::CognitiveMemory;
use crate::findings_log::{FindingsLogError, load_findings};
use std::path::Path;

/// Loads the append-only findings log at `path` and folds it into a
/// [`CognitiveMemory`], so every engagement's recorded findings inform the
/// next run's cognition.
///
/// # Errors
///
/// Returns [`FindingsLogError::Io`] if the file cannot be read.
pub fn load_memory(path: &Path) -> Result<CognitiveMemory, FindingsLogError> {
    let findings = load_findings(path)?;
    let mut memory = CognitiveMemory::new();
    memory.record_findings(&findings);
    Ok(memory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Finding, Severity};
    use crate::findings_log::append_findings;
    use std::fs;

    fn finding(target_id: &str, severity: Severity) -> Finding {
        Finding {
            finding_id: format!("{target_id}-0"),
            source_tool: "semgrep".to_string(),
            title: "t".to_string(),
            target_id: target_id.to_string(),
            severity,
            confidence_percent: 90,
            remediation_playbook: "fix".to_string(),
            normalized_risk_score: 9.0,
        }
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "security-agent-memory-store-{name}-{}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn load_memory_folds_the_findings_log_across_engagements() {
        let path = temp_path("folds-across-engagements");
        let _ = fs::remove_file(&path);

        // Two separate engagements append to the same log.
        append_findings(&path, &[finding("api-1", Severity::Critical)]).expect("first engagement");
        append_findings(&path, &[finding("web-1", Severity::Medium)]).expect("second engagement");

        let memory = load_memory(&path).expect("load memory");
        fs::remove_file(&path).expect("remove temp log");

        assert_eq!(memory.history_for("api-1").0, 1);
        assert_eq!(memory.history_for("web-1").0, 1);
    }

    #[test]
    fn load_memory_averages_repeated_findings_for_a_target() {
        let path = temp_path("averages-repeats");
        let _ = fs::remove_file(&path);

        append_findings(
            &path,
            &[
                finding("api-1", Severity::Critical),
                finding("api-1", Severity::Critical),
            ],
        )
        .expect("append findings");

        let memory = load_memory(&path).expect("load memory");
        fs::remove_file(&path).expect("remove temp log");

        let (count, average) = memory.history_for("api-1");
        assert_eq!(count, 2);
        assert!((average - 10.0).abs() < f32::EPSILON);
    }

    #[test]
    fn load_memory_reports_io_error_for_missing_file() {
        let path = temp_path("missing");
        assert!(matches!(load_memory(&path), Err(FindingsLogError::Io(_))));
    }
}
