/// The environment in which a tagged security test run executes.
///
/// Production is deliberately absent from this enum.  Tagged test runs are
/// only permitted in isolated, non-production environments to prevent any
/// accidental impact on live systems or live data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestEnvironment {
    Staging,
    Development,
    IsolatedSandbox,
}

/// An authorised, fully-logged security test run with a stable identifier.
///
/// Every audit record emitted during this run is tagged with `test_run_id` so
/// that operations teams can:
///
/// * Filter test traffic in dashboards without deleting it.
/// * Correlate all artefacts produced by a single engagement.
/// * Distinguish automated security-agent events from user-initiated ones.
///
/// **Nothing is suppressed.**  All events are written to the normal
/// [`crate::governance::AuditLedger`]; the tag is purely additive.
#[derive(Debug, Clone)]
pub struct TaggedTestRun {
    /// Stable identifier for this test run (e.g. a UUID).
    pub test_run_id: String,
    /// The non-production environment being tested.
    pub environment: TestEnvironment,
    /// Identity of the operator who authorised this run.
    pub operator: String,
    /// Human-readable description of the run's purpose.
    pub purpose: String,
    /// When this run was created (epoch seconds).
    pub started_at_epoch_seconds: u64,
}

impl TaggedTestRun {
    /// Create a new tagged test run.
    pub fn new(
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

    /// The source tag attached to every audit record produced by this run.
    ///
    /// Format: `security-agent/test-run/<test_run_id>`
    pub fn source_tag(&self) -> String {
        format!("security-agent/test-run/{}", self.test_run_id)
    }
}

/// A post-run summary produced when a tagged security test run completes.
///
/// This struct is returned alongside the [`crate::coordinator::ExecutionPlan`]
/// by [`crate::coordinator::Coordinator::plan_tagged_scan`] and provides a
/// compact record suitable for compliance reporting.
#[derive(Debug, Clone)]
pub struct TestRunReport {
    /// Matches [`TaggedTestRun::test_run_id`].
    pub test_run_id: String,
    /// The non-production environment that was tested.
    pub environment: TestEnvironment,
    /// The operator who authorised the run.
    pub operator: String,
    /// Human-readable purpose of the run.
    pub purpose: String,
    /// Source tag embedded in every audit record for this run.
    pub source_tag: String,
    /// When the run started (epoch seconds).
    pub started_at_epoch_seconds: u64,
    /// When the run completed (epoch seconds, i.e. `now` at plan time).
    pub completed_at_epoch_seconds: u64,
    /// Number of scan tasks planned.
    pub task_count: usize,
    /// Number of audit records written during the run.
    pub audit_record_count: usize,
}
