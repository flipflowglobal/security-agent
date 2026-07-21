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
    pub purpose: String,
    pub started_at_epoch_seconds: u64,
}

impl TaggedTestRun {
    #[must_use]
    pub const fn new(
        test_run_id: String,
        environment: TestEnvironment,
        operator: String,
        purpose: String,
        started_at_epoch_seconds: u64,
    ) -> Self {
        Self {
            test_run_id,
            environment,
            operator,
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
    pub purpose: String,
    pub source_tag: String,
    pub started_at_epoch_seconds: u64,
    pub completed_at_epoch_seconds: u64,
    pub task_count: usize,
    pub audit_record_count: usize,
}
