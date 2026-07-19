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
}
