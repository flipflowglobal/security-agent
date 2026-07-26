//! On-disk persistence for the audit ledger, backed by the `.sadb` engine.
//!
//! Same role as [`crate::audit_log`]'s append-only JSON Lines file, just
//! backed by [`crate::sadb`] instead. See [`crate::findings_db`] for why
//! opening a missing path creates an empty database rather than erroring.

use crate::governance::{AuditRecord, Role};
use crate::sadb::codec::{Reader, write_option_string, write_string, write_u64};
use crate::sadb::{Database, DbError};
use std::path::Path;
use std::str::FromStr;

const TABLE: &str = "audit_records";

fn encode(record: &AuditRecord) -> Vec<u8> {
    let mut buffer = Vec::new();
    write_u64(&mut buffer, record.timestamp_epoch_seconds);
    write_string(&mut buffer, &record.actor);
    write_string(&mut buffer, &record.role.to_string());
    write_string(&mut buffer, &record.action);
    write_string(&mut buffer, &record.target);
    write_string(&mut buffer, &record.details);
    write_option_string(&mut buffer, record.test_run_id.as_deref());
    buffer
}

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
/// # Errors
///
/// Returns [`DbError`] if the database can't be opened, a record can't be
/// inserted, or the transaction can't be committed.
pub fn append_audit_records(path: &Path, records: &[AuditRecord]) -> Result<(), DbError> {
    let mut db = Database::open(path)?;
    let mut txn = db.begin();
    for record in records {
        txn.insert(TABLE, &encode(record))?;
    }
    txn.commit()
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
    fn appends_and_loads_records_round_trip() {
        let path = temp_path("round-trip");
        let _ = fs::remove_file(&path);

        append_audit_records(&path, &sample_records()).expect("append should succeed");
        let loaded = load_audit_records(&path).expect("load should succeed");

        fs::remove_file(&path).expect("remove temp file");
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

        fs::remove_file(&path).expect("remove temp file");
        assert_eq!(loaded, records);
    }

    #[test]
    fn a_record_with_no_test_run_id_round_trips_as_none() {
        let path = temp_path("no-test-run-id");
        let _ = fs::remove_file(&path);

        let records = vec![sample_records().remove(0)];
        append_audit_records(&path, &records).expect("append should succeed");
        let loaded = load_audit_records(&path).expect("load should succeed");

        fs::remove_file(&path).expect("remove temp file");
        assert_eq!(loaded[0].test_run_id, None);
    }
}
