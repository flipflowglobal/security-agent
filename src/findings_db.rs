//! On-disk persistence for scored findings, backed by the `.sadb` engine.
//!
//! Same role as [`crate::findings_log`]'s append-only JSON Lines file,
//! just backed by [`crate::sadb`] instead: a real indexed page store for
//! callers that want [`crate::sadb::Database::scan`] rather than a
//! line-by-line read.
//!
//! Opening a `.sadb` path that doesn't exist yet creates an empty
//! database rather than erroring -- unlike [`crate::findings_log`]'s
//! plain files, a database is naturally something you open-or-create, not
//! something whose absence is exceptional.

use crate::findings::{Finding, Severity};
use crate::sadb::codec::{Reader, write_f32, write_string, write_u8};
use crate::sadb::{Database, DbError};
use std::path::Path;
use std::str::FromStr;

const TABLE: &str = "findings";

fn encode(finding: &Finding) -> Vec<u8> {
    let mut buffer = Vec::new();
    write_string(&mut buffer, &finding.finding_id);
    write_string(&mut buffer, &finding.source_tool);
    write_string(&mut buffer, &finding.title);
    write_string(&mut buffer, &finding.target_id);
    write_string(&mut buffer, &finding.severity.to_string());
    write_u8(&mut buffer, finding.confidence_percent);
    write_string(&mut buffer, &finding.remediation_playbook);
    write_f32(&mut buffer, finding.normalized_risk_score);
    buffer
}

fn decode(bytes: &[u8]) -> Option<Finding> {
    let mut reader = Reader::new(bytes);
    Some(Finding {
        finding_id: reader.read_string().ok()?,
        source_tool: reader.read_string().ok()?,
        title: reader.read_string().ok()?,
        target_id: reader.read_string().ok()?,
        severity: Severity::from_str(&reader.read_string().ok()?).ok()?,
        confidence_percent: reader.read_u8().ok()?,
        remediation_playbook: reader.read_string().ok()?,
        normalized_risk_score: reader.read_f32().ok()?,
    })
}

/// Appends every finding in `findings` to the `.sadb` database at `path`
/// in a single transaction, creating the database if it doesn't already
/// exist.
///
/// # Errors
///
/// Returns [`DbError`] if the database can't be opened, a finding can't
/// be inserted, or the transaction can't be committed.
pub fn append_findings(path: &Path, findings: &[Finding]) -> Result<(), DbError> {
    let mut db = Database::open(path)?;
    let mut txn = db.begin();
    for finding in findings {
        txn.insert(TABLE, &encode(finding))?;
    }
    txn.commit()
}

/// Reads back every valid finding previously written by
/// [`append_findings`], oldest first.
///
/// Rows that don't decode as a `Finding` are skipped rather than failing
/// the whole read, mirroring [`crate::findings_log::load_findings`]'s
/// tolerance for a shared store containing more than one record kind.
///
/// # Errors
///
/// Returns [`DbError`] if the database can't be opened or scanned.
pub fn load_findings(path: &Path) -> Result<Vec<Finding>, DbError> {
    let mut db = Database::open(path)?;
    let rows = db.scan(TABLE)?;
    Ok(rows.iter().filter_map(|row| decode(row)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;
    use std::fs;

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
            "security-agent-findings-db-{name}-{}.sadb",
            std::process::id()
        ))
    }

    #[test]
    fn appends_and_loads_findings_round_trip() {
        let path = temp_path("round-trip");
        let _ = fs::remove_file(&path);

        append_findings(&path, &sample_findings()).expect("append should succeed");
        let loaded = load_findings(&path).expect("load should succeed");

        fs::remove_file(&path).expect("remove temp file");
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

        fs::remove_file(&path).expect("remove temp file");
        assert_eq!(loaded, findings);
    }

    #[test]
    fn loading_a_path_that_does_not_exist_yet_returns_an_empty_database() {
        let path = temp_path("missing");
        let _ = fs::remove_file(&path);

        let loaded = load_findings(&path).expect("opening a missing path creates it empty");

        fs::remove_file(&path).expect("remove temp file");
        assert!(loaded.is_empty());
    }
}
