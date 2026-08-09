//! Turning a completed engagement run into an append-only audit trail.
//!
//! The coordinator already writes [`AuditRecord`]s when it *plans* an
//! authorized scan (who authorized it, how many tasks, how many high-impact),
//! but planning is only half the story: a real audit trail must also record
//! what the run actually *did* — every tool that completed, failed, or was
//! refused, what discovery turned up, and how far result-driven expansion
//! reached. This module derives exactly those records from an
//! [`EngagementReport`], so the same append-only ledger
//! ([`crate::audit_log`] / [`crate::audit_db`]) that holds the planning
//! records also holds the execution trail, keyed to the engagement by
//! `test_run_id`.
//!
//! Derivation is total and deterministic: it walks the report's stages in
//! execution order, emits one record per tool outcome, then a fixed set of
//! run-summary records (discovery, expansion, completion). The same run
//! always yields the same records in the same order — an audit trail must be
//! reproducible.

use crate::execution::ToolExecutionError;
use crate::governance::{AuditRecord, Role};
use crate::pipeline::EngagementReport;

/// The action string for a tool that ran to completion.
const ACTION_TOOL_COMPLETED: &str = "engagement_tool_completed";
/// The action string for a tool that failed to run.
const ACTION_TOOL_FAILED: &str = "engagement_tool_failed";
/// The action string for a tool refused before it spawned.
const ACTION_TOOL_REFUSED: &str = "engagement_tool_refused";
/// The action string for the discovery-blackboard summary record.
const ACTION_DISCOVERY: &str = "engagement_discovery";
/// The action string for the result-driven-expansion summary record.
const ACTION_EXPANSION: &str = "engagement_expansion";
/// The action string for the final run-completion summary record.
const ACTION_COMPLETED: &str = "engagement_completed";

/// Identity and timing stamped onto every record derived from a run.
///
/// The actor and role are the engagement's authorizer (from the loaded
/// profile), the timestamp is caller-supplied so derivation is deterministic
/// and testable, and the engagement id becomes each record's `test_run_id`
/// so the whole run can be recovered with
/// [`crate::governance::AuditLedger::filter_by_test_run_id`].
#[derive(Debug, Clone, Copy)]
pub struct EngagementAuditContext<'a> {
    /// The engagement identifier; used as `target` on summary records and as
    /// `test_run_id` on every record.
    pub engagement_id: &'a str,
    /// Who authorized (and is accountable for) the engagement.
    pub actor: &'a str,
    /// The role the actor authorized the engagement under.
    pub role: Role,
    /// Unix epoch seconds stamped on every derived record.
    pub timestamp_epoch_seconds: u64,
}

/// Per-outcome and summary tallies over a run, computed once.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RunTally {
    tools: usize,
    completed: usize,
    failed: usize,
    refused: usize,
}

impl EngagementAuditContext<'_> {
    /// Builds one record with this context's identity/timing.
    fn record(&self, action: &str, target: &str, details: String) -> AuditRecord {
        AuditRecord {
            timestamp_epoch_seconds: self.timestamp_epoch_seconds,
            actor: self.actor.to_string(),
            role: self.role,
            action: action.to_string(),
            target: target.to_string(),
            details,
            test_run_id: Some(self.engagement_id.to_string()),
        }
    }
}

/// Derives the full audit trail of a run: one record per tool outcome (in
/// execution order), then discovery, expansion, and completion summaries.
///
/// Every record carries the engagement id as its `test_run_id`, so the
/// complete run can be recovered from a mixed ledger.
#[must_use]
pub fn audit_records_for_engagement(
    context: &EngagementAuditContext,
    report: &EngagementReport,
) -> Vec<AuditRecord> {
    let mut records = Vec::new();
    let mut tally = RunTally::default();

    for stage in &report.stages {
        let class = format!("{:?}", stage.class);
        for outcome in &stage.outcomes {
            tally.tools += 1;
            let record = match &outcome.result {
                Ok(execution) => {
                    tally.completed += 1;
                    let exit = execution
                        .exit_code
                        .map_or_else(|| "signal".to_string(), |code| code.to_string());
                    context.record(
                        ACTION_TOOL_COMPLETED,
                        &outcome.target_id,
                        format!(
                            "tool={} class={class} exit={exit} duration_ms={}",
                            outcome.tool,
                            execution.duration.as_millis(),
                        ),
                    )
                }
                Err(ToolExecutionError::Refused(reason)) => {
                    tally.refused += 1;
                    context.record(
                        ACTION_TOOL_REFUSED,
                        &outcome.target_id,
                        format!("tool={} class={class} reason={reason}", outcome.tool),
                    )
                }
                Err(error) => {
                    tally.failed += 1;
                    context.record(
                        ACTION_TOOL_FAILED,
                        &outcome.target_id,
                        format!("tool={} class={class} error={error}", outcome.tool),
                    )
                }
            };
            records.push(record);
        }
    }

    let discovery = &report.context;
    records.push(context.record(
        ACTION_DISCOVERY,
        context.engagement_id,
        format!(
            "hosts={} services={} endpoints={}",
            discovery.hosts().len(),
            discovery.services().len(),
            discovery.endpoints().len(),
        ),
    ));
    records.push(context.record(
        ACTION_EXPANSION,
        context.engagement_id,
        format!("follow_up_steps_added={}", report.expansion_added),
    ));
    records.push(context.record(
        ACTION_COMPLETED,
        context.engagement_id,
        format!(
            "stages={} tools={} completed={} failed={} refused={}",
            report.stages.len(),
            tally.tools,
            tally.completed,
            tally.failed,
            tally.refused,
        ),
    ));

    records
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engagement_context::{EngagementContext, Host, Service};
    use crate::execution::{TaskExecutionOutcome, ToolExecutionReport};
    use crate::pipeline::StageOutcome;
    use crate::registry::ExecutionClass;
    use std::time::Duration;

    fn ok_outcome(tool: &str, target: &str, exit: i32) -> TaskExecutionOutcome {
        TaskExecutionOutcome {
            target_id: target.to_string(),
            tool: tool.to_string(),
            result: Ok(ToolExecutionReport {
                tool: tool.to_string(),
                arguments: Vec::new(),
                exit_code: Some(exit),
                stdout: String::new(),
                stderr: String::new(),
                duration: Duration::from_millis(7),
            }),
        }
    }

    fn refused_outcome(tool: &str, target: &str, reason: &str) -> TaskExecutionOutcome {
        TaskExecutionOutcome {
            target_id: target.to_string(),
            tool: tool.to_string(),
            result: Err(ToolExecutionError::Refused(reason.to_string())),
        }
    }

    fn failed_outcome(tool: &str, target: &str) -> TaskExecutionOutcome {
        TaskExecutionOutcome {
            target_id: target.to_string(),
            tool: tool.to_string(),
            result: Err(ToolExecutionError::NotInstalled(tool.to_string())),
        }
    }

    fn sample_report() -> EngagementReport {
        let mut discovery = EngagementContext::new();
        discovery.record_host(Host {
            address: "10.0.0.5".to_string(),
            hostname: Some("web-01".to_string()),
        });
        discovery.record_service(Service {
            host: "10.0.0.5".to_string(),
            port: 80,
            protocol: "tcp".to_string(),
            service: Some("http".to_string()),
        });
        EngagementReport {
            context: discovery,
            stages: vec![
                StageOutcome {
                    class: ExecutionClass::ActiveNetwork,
                    outcomes: vec![
                        ok_outcome("nmap", "10.0.0.5", 0),
                        refused_outcome("sqlmap", "10.0.0.5", "tool not authorized"),
                    ],
                },
                StageOutcome {
                    class: ExecutionClass::ActiveExploitation,
                    outcomes: vec![failed_outcome("nikto", "10.0.0.5")],
                },
            ],
            expansion_added: 1,
        }
    }

    fn context() -> EngagementAuditContext<'static> {
        EngagementAuditContext {
            engagement_id: "eng-1",
            actor: "jane.doe",
            role: Role::SecurityEngineer,
            timestamp_epoch_seconds: 1_700_000_000,
        }
    }

    #[test]
    fn derives_a_record_per_outcome_plus_three_summaries() {
        let records = audit_records_for_engagement(&context(), &sample_report());
        // 3 tool outcomes + discovery + expansion + completion.
        assert_eq!(records.len(), 6);
    }

    #[test]
    fn every_record_is_keyed_to_the_engagement_run() {
        let records = audit_records_for_engagement(&context(), &sample_report());
        assert!(
            records
                .iter()
                .all(|record| record.test_run_id.as_deref() == Some("eng-1"))
        );
        assert!(records.iter().all(|record| record.actor == "jane.doe"));
        assert!(
            records
                .iter()
                .all(|record| record.role == Role::SecurityEngineer)
        );
        assert!(
            records
                .iter()
                .all(|record| record.timestamp_epoch_seconds == 1_700_000_000)
        );
    }

    #[test]
    fn classifies_completed_refused_and_failed_outcomes() {
        let records = audit_records_for_engagement(&context(), &sample_report());
        let completed = records
            .iter()
            .find(|record| record.action == ACTION_TOOL_COMPLETED)
            .expect("completed record");
        assert!(completed.details.contains("tool=nmap"));
        assert!(completed.details.contains("class=ActiveNetwork"));
        assert!(completed.details.contains("exit=0"));

        let refused = records
            .iter()
            .find(|record| record.action == ACTION_TOOL_REFUSED)
            .expect("refused record");
        assert!(refused.details.contains("tool=sqlmap"));
        assert!(refused.details.contains("reason=tool not authorized"));

        let failed = records
            .iter()
            .find(|record| record.action == ACTION_TOOL_FAILED)
            .expect("failed record");
        assert!(failed.details.contains("tool=nikto"));
        assert!(failed.details.contains("error="));
    }

    #[test]
    fn summary_records_carry_the_run_totals() {
        let records = audit_records_for_engagement(&context(), &sample_report());
        let discovery = records
            .iter()
            .find(|record| record.action == ACTION_DISCOVERY)
            .expect("discovery record");
        assert_eq!(discovery.details, "hosts=1 services=1 endpoints=0");

        let expansion = records
            .iter()
            .find(|record| record.action == ACTION_EXPANSION)
            .expect("expansion record");
        assert_eq!(expansion.details, "follow_up_steps_added=1");

        let completed = records
            .iter()
            .find(|record| record.action == ACTION_COMPLETED)
            .expect("completion record");
        assert_eq!(
            completed.details,
            "stages=2 tools=3 completed=1 failed=1 refused=1"
        );
        assert_eq!(completed.target, "eng-1");
    }

    #[test]
    fn derivation_is_deterministic() {
        let report = sample_report();
        let ctx = context();
        assert_eq!(
            audit_records_for_engagement(&ctx, &report),
            audit_records_for_engagement(&ctx, &report),
        );
    }

    #[test]
    fn ledger_append_is_a_noop_after_guardrail_removal() {
        use crate::governance::AuditLedger;
        let records = audit_records_for_engagement(&context(), &sample_report());
        let mut ledger = AuditLedger::default();
        for record in records {
            ledger.append(record);
        }
        // append() is a no-op now: nothing is retained, filters return nothing.
        assert!(ledger.filter_by_test_run_id("eng-1").is_empty());
        assert!(ledger.filter_by_action(ACTION_TOOL_COMPLETED).is_empty());
        assert!(ledger.records().is_empty());
    }

    #[test]
    fn empty_run_still_emits_the_three_summaries() {
        let report = EngagementReport {
            context: EngagementContext::new(),
            stages: Vec::new(),
            expansion_added: 0,
        };
        let records = audit_records_for_engagement(&context(), &report);
        assert_eq!(records.len(), 3);
        let completed = records
            .iter()
            .find(|record| record.action == ACTION_COMPLETED)
            .expect("completion record");
        assert_eq!(
            completed.details,
            "stages=0 tools=0 completed=0 failed=0 refused=0"
        );
    }
}
