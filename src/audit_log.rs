//! Append-only, on-disk persistence for the audit ledger.
//!
//! Guardrails removed (see commit note "remove all guardrails"): the audit
//! trail is disabled. [`append_audit_records`] is a no-op — nothing is ever
//! written to disk. Reading existing logs via [`load_audit_records`] still
//! works so previously-created files (or files written by the application
//! layer's own design) remain viewable.

use crate::compat::{CompatibilityEnvelope, envelope_to_audit_record};
use crate::governance::AuditRecord;
use std::fmt;
use std::fs;
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
/// line each, creating the file if it doesn't already exist.
///
/// Guardrails removed: this is a no-op. The audit trail is disabled, so
/// no records are written and the file is never created.
///
/// # Errors
///
/// Never errors.
pub const fn append_audit_records(
    _path: &Path,
    _records: &[AuditRecord],
) -> Result<(), AuditLogError> {
    // Audit trail disabled — intentionally a no-op.
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
    fn append_is_a_noop_after_guardrail_removal() {
        let path = temp_path("round-trip");
        let _ = fs::remove_file(&path);

        append_audit_records(&path, &sample_records()).expect("append should succeed");
        // The audit trail is disabled: no file is ever created, so loading
        // reports the missing file rather than returning records.
        assert!(!path.exists(), "no audit file should be created");
        assert!(matches!(
            load_audit_records(&path),
            Err(AuditLogError::Io(_))
        ));
    }

    #[test]
    fn appending_twice_writes_nothing() {
        let path = temp_path("append-twice");
        let _ = fs::remove_file(&path);

        let records = sample_records();
        append_audit_records(&path, &records[..1]).expect("first append should succeed");
        append_audit_records(&path, &records[1..]).expect("second append should succeed");
        // Neither append creates the file.
        assert!(!path.exists(), "no audit file should be created");
        assert!(matches!(
            load_audit_records(&path),
            Err(AuditLogError::Io(_))
        ));
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

        assert!(
            loaded.is_empty(),
            "append is a no-op; nothing added to the log"
        );
    }

    #[test]
    fn load_reports_io_error_for_missing_file() {
        let path = temp_path("missing");
        let result = load_audit_records(&path);
        assert!(matches!(result, Err(AuditLogError::Io(_))));
    }

    #[test]
    fn append_does_not_create_the_file_after_guardrail_removal() {
        let path = temp_path("creates-file");
        let _ = fs::remove_file(&path);
        assert!(!path.exists());

        append_audit_records(&path, &sample_records()).expect("append should succeed");
        assert!(
            !path.exists(),
            "audit trail is disabled; no file should be created"
        );
    }
}
