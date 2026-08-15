use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    SecurityAdmin,
    SecurityEngineer,
    Auditor,
    /// Least-privilege, read-only role. Assigned by read-only surfaces that
    /// load and render existing artifacts without planning, authorizing,
    /// executing, or writing — e.g. the `--view-audit` command in the
    /// binary. If a read path is ever made to emit an audit record, this is
    /// the correct actor role for it.
    Viewer,
}

impl fmt::Display for Role {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::SecurityAdmin => "SecurityAdmin",
            Self::SecurityEngineer => "SecurityEngineer",
            Self::Auditor => "Auditor",
            Self::Viewer => "Viewer",
        };
        formatter.write_str(name)
    }
}

impl FromStr for Role {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "SecurityAdmin" => Ok(Self::SecurityAdmin),
            "SecurityEngineer" => Ok(Self::SecurityEngineer),
            "Auditor" => Ok(Self::Auditor),
            "Viewer" => Ok(Self::Viewer),
            other => Err(format!("unknown role: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub timestamp_epoch_seconds: u64,
    pub actor: String,
    pub role: Role,
    pub action: String,
    pub target: String,
    pub details: String,
    pub test_run_id: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct AuditLedger {
    records: Vec<AuditRecord>,
}

impl AuditLedger {
    /// Records `record` in the in-memory ledger.
    pub fn append(&mut self, record: AuditRecord) {
        self.records.push(record);
    }

    #[must_use]
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// Return all records where the actor's role matches `role`.
    #[must_use]
    pub fn filter_by_role(&self, role: Role) -> Vec<&AuditRecord> {
        self.records.iter().filter(|r| r.role == role).collect()
    }

    /// Return all records where the action string equals `action`.
    #[must_use]
    pub fn filter_by_action<'a>(&'a self, action: &str) -> Vec<&'a AuditRecord> {
        self.records.iter().filter(|r| r.action == action).collect()
    }

    /// Return all records that belong to the given test run.
    #[must_use]
    pub fn filter_by_test_run_id<'a>(&'a self, test_run_id: &str) -> Vec<&'a AuditRecord> {
        self.records
            .iter()
            .filter(|r| r.test_run_id.as_deref() == Some(test_run_id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_display_and_from_str_round_trip() {
        for role in [
            Role::SecurityAdmin,
            Role::SecurityEngineer,
            Role::Auditor,
            Role::Viewer,
        ] {
            let rendered = role.to_string();
            assert_eq!(rendered.parse::<Role>(), Ok(role));
        }
    }

    #[test]
    fn role_from_str_rejects_unknown_values() {
        assert!("root".parse::<Role>().is_err());
        assert!("".parse::<Role>().is_err());
    }
}
