#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    SecurityAdmin,
    SecurityEngineer,
    Auditor,
    Viewer,
}

#[derive(Debug, Clone)]
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
    pub fn append(&mut self, record: AuditRecord) {
        self.records.push(record);
    }

    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// Return all records where the actor's role matches `role`.
    pub fn filter_by_role(&self, role: Role) -> Vec<&AuditRecord> {
        self.records.iter().filter(|r| r.role == role).collect()
    }

    /// Return all records where the action string equals `action`.
    pub fn filter_by_action<'a>(&'a self, action: &str) -> Vec<&'a AuditRecord> {
        self.records.iter().filter(|r| r.action == action).collect()
    }

    /// Return all records that belong to the given test run.
    pub fn filter_by_test_run_id<'a>(&'a self, test_run_id: &str) -> Vec<&'a AuditRecord> {
        self.records
            .iter()
            .filter(|r| r.test_run_id.as_deref() == Some(test_run_id))
            .collect()
    }
}
