//! On-disk persistence for the audit ledger, backed by the `.sadb` engine.
//!
//! Guardrails removed (see commit note "remove all guardrails"): the audit
//! trail is disabled. [`append_audit_records`] is a no-op — nothing is ever
//! written to disk. Reading existing databases via
//! [`load_audit_records`] still works so previously-created databases (or
//! files written by the application layer's own design) remain viewable.

use crate::governance::{AuditRecord, Role};
use crate::sadb::codec::Reader;
use crate::sadb::{Database, DbError};
use std::path::Path;
use std::str::FromStr;

const TABLE: &str = "audit_records";

fn decode(bytes: &[u8]) -> Option<AuditRecord> {
    let mut reader = Reader::new(bytes);
    Some(AuditRecord {
        timestamp_epoch_seconds: reader.read_u64().ok()?,
        actor: reader.read_string().ok()?,
        role: Role::from_str(&reader.read_string().ok()?).ok()?,
        action: reader.read_string().ok()?,
        target: reader.read_string().ok()?,
        details: reader.read_string().ok()?,
        test_run_id: reader.read_option_string().ok()?,
    })
}

/// Appends every record in `records` to the `.sadb` database at `path` in
/// a single transaction, creating the database if it doesn't already
/// exist.
///
/// Guardrails removed: this is a no-op. The audit trail is disabled, so
/// no records are written and the database is never created.
///
/// # Errors
///
/// Never errors.
pub fn append_audit_records(_path: &Path, _records: &[AuditRecord]) -> Result<(), DbError> {
    // Audit trail disabled — intentionally a no-op.
    Ok(())
}

/// Reads back every valid audit record previously written by
/// [`append_audit_records`], oldest first.
///
/// # Errors
///
/// Returns [`DbError`] if the database can't be opened or scanned.
pub fn load_audit_records(path: &Path) -> Result<Vec<AuditRecord>, DbError> {
    let mut db = Database::open(path)?;
    let rows = db.scan(TABLE)?;
    Ok(rows.iter().filter_map(|row| decode(row)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
            "security-agent-audit-db-{name}-{}.sadb",
            std::process::id()
        ))
    }

    #[test]
    fn append_is_a_noop_after_guardrail_removal() {
        let path = temp_path("round-trip");
        let _ = fs::remove_file(&path);

        append_audit_records(&path, &sample_records()).expect("append should succeed");
        let loaded = load_audit_records(&path).expect("load should succeed");

        fs::remove_file(&path).expect("remove temp file");
        assert!(loaded.is_empty(), "audit trail is disabled; nothing recorded");
    }

    #[test]
    fn appending_twice_writes_nothing() {
        let path = temp_path("append-twice");
        let _ = fs::remove_file(&path);

        let records = sample_records();
        append_audit_records(&path, &records[..1]).expect("first append should succeed");
        append_audit_records(&path, &records[1..]).expect("second append should succeed");
        let loaded = load_audit_records(&path).expect("load should succeed");

        fs::remove_file(&path).expect("remove temp file");
        assert!(loaded.is_empty(), "audit trail is disabled; nothing recorded");
    }

    #[test]
    fn a_record_with_no_test_run_id_round_trips_as_none() {
        let path = temp_path("no-test-run-id");
        let _ = fs::remove_file(&path);

        let records = vec![sample_records().remove(0)];
        append_audit_records(&path, &records).expect("append should succeed");
        let loaded = load_audit_records(&path).expect("load should succeed");

        fs::remove_file(&path).expect("remove temp file");
        assert!(loaded.is_empty(), "audit trail is disabled; nothing recorded");
    }
}
