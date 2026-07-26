use crate::governance::Role;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestEnvironment {
    Staging,
    Development,
    IsolatedSandbox,
}

#[derive(Debug, Clone)]
pub struct TaggedTestRun {
    pub test_run_id: String,
    pub environment: TestEnvironment,
    pub operator: String,
    /// The role `operator` was acting in for this test run. Carried through
    /// to every audit record the coordinator writes while planning under
    /// this tagged run.
    pub operator_role: Role,
    pub purpose: String,
    pub started_at_epoch_seconds: u64,
}

impl TaggedTestRun {
    #[must_use]
    pub const fn new(
        test_run_id: String,
        environment: TestEnvironment,
        operator: String,
        operator_role: Role,
        purpose: String,
        started_at_epoch_seconds: u64,
    ) -> Self {
        Self {
            test_run_id,
            environment,
            operator,
            operator_role,
            purpose,
            started_at_epoch_seconds,
        }
    }

    #[must_use]
    pub fn source_tag(&self) -> String {
        format!("security-agent/test-run/{}", self.test_run_id)
    }
}

#[derive(Debug, Clone)]
pub struct TestRunReport {
    pub test_run_id: String,
    pub environment: TestEnvironment,
    pub operator: String,
    pub operator_role: Role,
    pub purpose: String,
    pub source_tag: String,
    pub started_at_epoch_seconds: u64,
    pub completed_at_epoch_seconds: u64,
    pub task_count: usize,
    pub audit_record_count: usize,
}
