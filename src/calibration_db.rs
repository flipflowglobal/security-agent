//! On-disk persistence for confidence-calibration records.
//!
//! Closes the loop [`crate::cognitive_engine::CognitiveEngine::assess_calibration`]
//! computes but nothing previously carried across runs -- see the
//! `with_calibration` doc comment on [`crate::cognitive_engine::CognitiveEngine`].
//! Every run's `(predicted_percent, occurred)` pairs accumulate here, so
//! the next run's calibration correction has real cross-engagement
//! history instead of starting empty each time.

use crate::calibration::{CalibrationRecord, CalibrationTracker};
use crate::sadb::codec::{Reader, write_bool, write_u8};
use crate::sadb::{Database, DbError};
use std::path::Path;

const TABLE: &str = "calibration_records";

fn encode(record: CalibrationRecord) -> Vec<u8> {
    let mut buffer = Vec::new();
    write_u8(&mut buffer, record.predicted_percent);
    write_bool(&mut buffer, record.occurred);
    buffer
}

fn decode(bytes: &[u8]) -> Option<CalibrationRecord> {
    let mut reader = Reader::new(bytes);
    Some(CalibrationRecord {
        predicted_percent: reader.read_u8().ok()?,
        occurred: reader.read_bool().ok()?,
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
pub fn append_calibration_records(
    path: &Path,
    records: &[CalibrationRecord],
) -> Result<(), DbError> {
    let mut db = Database::open(path)?;
    let mut txn = db.begin();
    for record in records {
        txn.insert(TABLE, &encode(*record))?;
    }
    txn.commit()
}

/// Loads every calibration record previously written by
/// [`append_calibration_records`] into a fresh [`CalibrationTracker`].
///
/// The result is ready to pass to
/// [`crate::cognitive_engine::CognitiveEngine::with_calibration`].
///
/// # Errors
///
/// Returns [`DbError`] if the database can't be opened or scanned.
pub fn load_calibration(path: &Path) -> Result<CalibrationTracker, DbError> {
    let mut db = Database::open(path)?;
    let rows = db.scan(TABLE)?;
    let mut tracker = CalibrationTracker::new();
    for row in &rows {
        if let Some(record) = decode(row) {
            tracker.record(record.predicted_percent, record.occurred);
        }
    }
    Ok(tracker)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sample_records() -> Vec<CalibrationRecord> {
        vec![
            CalibrationRecord {
                predicted_percent: 70,
                occurred: true,
            },
            CalibrationRecord {
                predicted_percent: 40,
                occurred: false,
            },
        ]
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "security-agent-calibration-db-{name}-{}.sadb",
            std::process::id()
        ))
    }

    #[test]
    fn appends_and_loads_records_round_trip() {
        let path = temp_path("round-trip");
        let _ = fs::remove_file(&path);

        append_calibration_records(&path, &sample_records()).expect("append should succeed");
        let tracker = load_calibration(&path).expect("load should succeed");

        fs::remove_file(&path).expect("remove temp file");
        assert_eq!(tracker.records(), sample_records());
    }

    #[test]
    fn appending_across_multiple_runs_accumulates_history() {
        let path = temp_path("accumulates");
        let _ = fs::remove_file(&path);

        let records = sample_records();
        append_calibration_records(&path, &records[..1]).expect("first run's records");
        append_calibration_records(&path, &records[1..]).expect("second run's records");
        let tracker = load_calibration(&path).expect("load should succeed");

        fs::remove_file(&path).expect("remove temp file");
        assert_eq!(tracker.len(), 2);
        assert_eq!(tracker.records(), records);
    }

    #[test]
    fn loading_a_path_that_does_not_exist_yet_returns_an_empty_tracker() {
        let path = temp_path("missing");
        let _ = fs::remove_file(&path);

        let tracker = load_calibration(&path).expect("opening a missing path creates it empty");

        fs::remove_file(&path).expect("remove temp file");
        assert!(tracker.is_empty());
    }
}
