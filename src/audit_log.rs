//! Append-only, on-disk persistence for the audit ledger.
//!
//! [`crate::governance::AuditLedger`] is in-memory only and is dropped
//! with the process that built it. This module appends each
//! [`AuditRecord`] to a local JSON Lines file (reusing
//! [`CompatibilityEnvelope`]'s wire format) so a real audit trail survives
//! past a single run, and can read it back.

use crate::compat::{CompatibilityEnvelope, audit_record_to_envelope, envelope_to_audit_record};
use crate::governance::AuditRecord;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[derive(Debug)]
pub enum AuditLogError {
    Io(std::io::Error),
}

impl fmt::Display for AuditLogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for AuditLogError {}

/// Appends every record in `records` to the file at `path` as one JSON
/// line each, creating the file if it doesn't already exist. Never
/// truncates or rewrites existing lines — this is an append-only log.
///
/// # Errors
///
/// Returns [`AuditLogError::Io`] if the file cannot be opened or written.
pub fn append_audit_records(path: &Path, records: &[AuditRecord]) -> Result<(), AuditLogError> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(AuditLogError::Io)?;
    for record in records {
        let line = audit_record_to_envelope(record).to_wire_format();
        file.write_all(line.as_bytes()).map_err(AuditLogError::Io)?;
    }
    Ok(())
}

/// Reads back every valid audit record previously written by
/// [`append_audit_records`].
///
/// Lines that aren't valid `audit_record` envelopes are skipped rather
/// than failing the whole read, so a log file containing unrelated JSON
/// Lines content (or a future format version) doesn't block loading the
/// records this crate understands.
///
/// # Errors
///
/// Returns [`AuditLogError::Io`] if the file cannot be read.
pub fn load_audit_records(path: &Path) -> Result<Vec<AuditRecord>, AuditLogError> {
    let text = fs::read_to_string(path).map_err(AuditLogError::Io)?;
    Ok(text
        .lines()
        .filter_map(CompatibilityEnvelope::from_wire_format)
        .filter_map(|envelope| envelope_to_audit_record(&envelope))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::Role;

    fn sample_records() -> Vec<AuditRecord> {
        vec![
            AuditRecord {
                timestamp_epoch_seconds: 10,
                actor: "jane.doe".to_string(),
                role: Role::SecurityAdmin,
                action: "plan_authorized_scan".to_string(),
                target: "eng-1".to_string(),
                details: "tasks=2 high_impact=0".to_string(),
                test_run_id: None,
            },
            AuditRecord {
                timestamp_epoch_seconds: 20,
                actor: "secops-engineer".to_string(),
                role: Role::SecurityEngineer,
                action: "plan_tagged_scan".to_string(),
                target: "eng-1".to_string(),
                details: "tasks=1 high_impact=0".to_string(),
                test_run_id: Some("run-abc".to_string()),
            },
        ]
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "security-agent-audit-log-{name}-{}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn appends_and_loads_records_round_trip() {
        let path = temp_path("round-trip");
        let _ = fs::remove_file(&path);

        append_audit_records(&path, &sample_records()).expect("append should succeed");
        let loaded = load_audit_records(&path).expect("load should succeed");

        fs::remove_file(&path).expect("remove temp log");
        assert_eq!(loaded, sample_records());
    }

    #[test]
    fn appending_twice_preserves_earlier_records() {
        let path = temp_path("append-twice");
        let _ = fs::remove_file(&path);

        let records = sample_records();
        append_audit_records(&path, &records[..1]).expect("first append should succeed");
        append_audit_records(&path, &records[1..]).expect("second append should succeed");
        let loaded = load_audit_records(&path).expect("load should succeed");

        fs::remove_file(&path).expect("remove temp log");
        assert_eq!(loaded, records);
    }

    #[test]
    fn load_skips_lines_that_are_not_audit_records() {
        let path = temp_path("skips-non-audit-lines");
        let _ = fs::remove_file(&path);

        fs::write(&path, "not json\n{\"version\":\"1\",\"producer\":\"x\",\"kind\":\"execution_plan\",\"fields\":{}}\n")
            .expect("write temp log");
        append_audit_records(&path, &sample_records()[..1]).expect("append should succeed");

        let loaded = load_audit_records(&path).expect("load should succeed");
        fs::remove_file(&path).expect("remove temp log");

        assert_eq!(loaded, sample_records()[..1]);
    }

    #[test]
    fn load_reports_io_error_for_missing_file() {
        let path = temp_path("missing");
        let result = load_audit_records(&path);
        assert!(matches!(result, Err(AuditLogError::Io(_))));
    }

    #[test]
    fn append_creates_the_file_if_it_does_not_exist() {
        let path = temp_path("creates-file");
        let _ = fs::remove_file(&path);
        assert!(!path.exists());

        append_audit_records(&path, &sample_records()).expect("append should succeed");
        assert!(path.exists());

        fs::remove_file(&path).expect("remove temp log");
    }
}
