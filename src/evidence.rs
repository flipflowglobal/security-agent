//! Evidence capture and chain-of-custody (Stage-4 territory).
//!
//! A finding is only defensible if you can point back at the exact tool
//! output that produced it. This module captures, for each executed tool, a
//! content hash of its output (via the in-house SHA-256 in
//! [`crate::builtin_tools`]) plus provenance — the target, the tool, the
//! byte length, and the exit code — as an [`EvidenceRecord`]. Records append
//! to a local JSON-Lines log, mirroring [`crate::findings_log`], so the
//! chain of custody survives the process and can be reviewed later.
//!
//! The hash is over the tool's captured stdout: two runs that produced
//! identical output share a hash, and any change to the output changes it,
//! which is exactly the integrity property evidence needs.

use crate::builtin_tools::Sha256;
use crate::execution::ToolExecutionReport;
use crate::json::{self, JsonValue};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// A tamper-evident record of one tool's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    /// The authorized target the tool ran against.
    pub target_id: String,
    /// The tool that produced the output.
    pub tool: String,
    /// Lowercase hex SHA-256 of the captured stdout.
    pub output_sha256: String,
    /// Length in bytes of the captured stdout.
    pub byte_len: usize,
    /// The tool's exit code, if it exited normally.
    pub exit_code: Option<i32>,
}

/// Errors persisting or loading evidence.
#[derive(Debug)]
pub enum EvidenceError {
    /// The underlying file could not be read or written.
    Io(std::io::Error),
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for EvidenceError {}

/// Captures the evidence for one tool execution: hashes the report's stdout
/// and records its provenance.
#[must_use]
pub fn capture(target_id: &str, report: &ToolExecutionReport) -> EvidenceRecord {
    let bytes = report.stdout.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    EvidenceRecord {
        target_id: target_id.to_string(),
        tool: report.tool.clone(),
        output_sha256: hasher.finalize_hex(),
        byte_len: bytes.len(),
        exit_code: report.exit_code,
    }
}

/// Appends each record to `path` as one JSON line, creating the file if it
/// does not exist. Append-only: existing lines are never rewritten.
///
/// # Errors
///
/// Returns [`EvidenceError::Io`] if the file cannot be opened or written.
pub fn append_evidence(path: &Path, records: &[EvidenceRecord]) -> Result<(), EvidenceError> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(EvidenceError::Io)?;
    for record in records {
        file.write_all(to_line(record).as_bytes())
            .map_err(EvidenceError::Io)?;
    }
    Ok(())
}

/// Reads back every valid evidence record previously written to `path`.
/// Lines that aren't valid `evidence_record` objects are skipped rather than
/// failing the whole read.
///
/// # Errors
///
/// Returns [`EvidenceError::Io`] if the file cannot be read.
pub fn load_evidence(path: &Path) -> Result<Vec<EvidenceRecord>, EvidenceError> {
    let text = fs::read_to_string(path).map_err(EvidenceError::Io)?;
    Ok(text.lines().filter_map(from_line).collect())
}

/// Serializes a record to a single JSON line (trailing newline included).
fn to_line(record: &EvidenceRecord) -> String {
    let exit = record
        .exit_code
        .map_or_else(|| "null".to_string(), |code| code.to_string());
    format!(
        "{{\"kind\":\"evidence_record\",\"target_id\":\"{}\",\"tool\":\"{}\",\"output_sha256\":\"{}\",\"byte_len\":{},\"exit_code\":{}}}\n",
        escape(&record.target_id),
        escape(&record.tool),
        record.output_sha256,
        record.byte_len,
        exit,
    )
}

/// Parses one JSON line back into a record, or `None` if it isn't a
/// well-formed `evidence_record`.
fn from_line(line: &str) -> Option<EvidenceRecord> {
    let value = json::parse(line)?;
    if value.get("kind").and_then(JsonValue::as_str) != Some("evidence_record") {
        return None;
    }
    Some(EvidenceRecord {
        target_id: value.get("target_id")?.as_str()?.to_string(),
        tool: value.get("tool")?.as_str()?.to_string(),
        output_sha256: value.get("output_sha256")?.as_str()?.to_string(),
        byte_len: usize::try_from(value.get("byte_len")?.as_u64()?).ok()?,
        exit_code: value
            .get("exit_code")
            .and_then(JsonValue::as_u64)
            .and_then(|code| i32::try_from(code).ok()),
    })
}

/// Escapes the characters that would break a JSON string literal.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn report(tool: &str, stdout: &str, exit: Option<i32>) -> ToolExecutionReport {
        ToolExecutionReport {
            tool: tool.to_string(),
            arguments: Vec::new(),
            exit_code: exit,
            stdout: stdout.to_string(),
            stderr: String::new(),
            duration: Duration::from_millis(1),
        }
    }

    #[test]
    fn identical_output_hashes_identically() {
        let a = capture("t1", &report("nmap", "same bytes", Some(0)));
        let b = capture("t1", &report("nmap", "same bytes", Some(0)));
        assert_eq!(a.output_sha256, b.output_sha256);
        assert_eq!(a.byte_len, 10);
    }

    #[test]
    fn different_output_hashes_differently() {
        let a = capture("t1", &report("nmap", "output one", Some(0)));
        let b = capture("t1", &report("nmap", "output two", Some(0)));
        assert_ne!(a.output_sha256, b.output_sha256);
    }

    #[test]
    fn append_and_load_round_trips() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sa-evidence-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let records = vec![
            capture("t1", &report("nmap", "a", Some(0))),
            capture("t2", &report("sqlmap", "b\"c", None)),
        ];
        append_evidence(&path, &records).expect("append");
        let loaded = load_evidence(&path).expect("load");

        assert_eq!(loaded, records);
        assert_eq!(loaded[1].exit_code, None);
        assert_eq!(loaded[1].tool, "sqlmap");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sa-evidence-bad-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "not json\n{\"kind\":\"other\"}\n").expect("write");
        let loaded = load_evidence(&path).expect("load");
        assert!(loaded.is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
