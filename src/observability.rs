//! Structured observability for a running engagement.
//!
//! A long engagement is opaque without a live signal of what is running, what
//! finished, and what was refused. This module provides a structured
//! [`EngagementEvent`] stream and pluggable [`EventSink`]s so the runtime can
//! report progress as it happens — to a JSON-Lines log for aggregation, to an
//! in-memory collector for tests, or nowhere ([`NullSink`]) — plus a
//! [`ProgressSummary`] that folds a set of outcomes into a one-line status.
//!
//! Events are plain data with no embedded timestamp, so they serialize
//! deterministically; a sink that wants wall-clock time adds it. Sinks are
//! `Sync` and take `&self`, so the runtime can emit from its concurrent
//! workers without a per-event lock in the hot path of the caller.

use crate::execution::{TaskExecutionOutcome, ToolExecutionError};
use std::fmt;
use std::io::Write;
use std::sync::Mutex;

/// A structured event in the lifecycle of an engagement run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngagementEvent {
    /// An execution-class stage began with `steps` tools to run.
    StageStarted { class: String, steps: usize },
    /// A tool started against a target.
    StepStarted { target: String, tool: String },
    /// A tool finished (successfully spawned and awaited).
    StepCompleted {
        target: String,
        tool: String,
        exit_code: Option<i32>,
        duration_ms: u64,
    },
    /// A tool failed to run (spawn error, timeout, integrity, offline gate).
    StepFailed {
        target: String,
        tool: String,
        error: String,
    },
    /// A tool was refused before spawning (out-of-scope target or unresolved
    /// secret).
    StepRefused {
        target: String,
        tool: String,
        reason: String,
    },
    /// An execution-class stage finished.
    StageCompleted {
        class: String,
        completed: usize,
        failed: usize,
    },
}

impl EngagementEvent {
    /// The event's kind tag, used as the `event` field when serialized.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::StageStarted { .. } => "stage_started",
            Self::StepStarted { .. } => "step_started",
            Self::StepCompleted { .. } => "step_completed",
            Self::StepFailed { .. } => "step_failed",
            Self::StepRefused { .. } => "step_refused",
            Self::StageCompleted { .. } => "stage_completed",
        }
    }

    /// Serializes the event as a single JSON object line.
    #[must_use]
    pub fn to_json_line(&self) -> String {
        let body = match self {
            Self::StageStarted { class, steps } => {
                format!(",\"class\":\"{}\",\"steps\":{steps}", esc(class))
            }
            Self::StepStarted { target, tool } => {
                format!(",\"target\":\"{}\",\"tool\":\"{}\"", esc(target), esc(tool))
            }
            Self::StepCompleted {
                target,
                tool,
                exit_code,
                duration_ms,
            } => {
                let exit = exit_code.map_or_else(|| "null".to_string(), |code| code.to_string());
                format!(
                    ",\"target\":\"{}\",\"tool\":\"{}\",\"exit_code\":{exit},\"duration_ms\":{duration_ms}",
                    esc(target),
                    esc(tool),
                )
            }
            Self::StepFailed {
                target,
                tool,
                error,
            } => format!(
                ",\"target\":\"{}\",\"tool\":\"{}\",\"error\":\"{}\"",
                esc(target),
                esc(tool),
                esc(error),
            ),
            Self::StepRefused {
                target,
                tool,
                reason,
            } => format!(
                ",\"target\":\"{}\",\"tool\":\"{}\",\"reason\":\"{}\"",
                esc(target),
                esc(tool),
                esc(reason),
            ),
            Self::StageCompleted {
                class,
                completed,
                failed,
            } => format!(
                ",\"class\":\"{}\",\"completed\":{completed},\"failed\":{failed}",
                esc(class),
            ),
        };
        format!("{{\"event\":\"{}\"{body}}}", self.kind())
    }
}

/// Escapes the characters that would break a JSON string literal.
fn esc(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// A destination for engagement events. Implementations are `Sync` so the
/// runtime can emit from concurrent workers.
pub trait EventSink: Sync {
    /// Records one event. Must not panic; a sink that cannot write should
    /// drop the event rather than fail the run.
    fn emit(&self, event: &EngagementEvent);
}

/// An event sink that discards everything — the default when observability
/// is not configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSink;

impl EventSink for NullSink {
    fn emit(&self, _event: &EngagementEvent) {}
}

/// An in-memory sink that records events in order, for tests and summaries.
#[derive(Debug, Default)]
pub struct CollectingSink {
    events: Mutex<Vec<EngagementEvent>>,
}

impl CollectingSink {
    /// A new, empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot of the events recorded so far, in order.
    #[must_use]
    pub fn events(&self) -> Vec<EngagementEvent> {
        self.events
            .lock()
            .map_or_else(|_| Vec::new(), |e| e.clone())
    }
}

impl EventSink for CollectingSink {
    fn emit(&self, event: &EngagementEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event.clone());
        }
    }
}

/// An event sink that writes each event as a JSON line to any writer — a
/// file, a pipe, or stderr — for log aggregation.
pub struct WriterSink<W: Write + Send> {
    writer: Mutex<W>,
}

impl<W: Write + Send> WriterSink<W> {
    /// Wraps a writer as a sink.
    pub const fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }
}

impl<W: Write + Send> EventSink for WriterSink<W> {
    fn emit(&self, event: &EngagementEvent) {
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writeln!(writer, "{}", event.to_json_line());
        }
    }
}

/// A rollup of a set of outcomes: how many ran, succeeded, failed, or were
/// refused before spawning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProgressSummary {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub refused: usize,
}

impl ProgressSummary {
    /// Folds a set of outcomes into a summary. A non-zero tool exit code
    /// still counts as *succeeded* (the tool ran); only an execution error
    /// is a failure, and a [`ToolExecutionError::Refused`] is counted
    /// separately as a pre-spawn refusal.
    #[must_use]
    pub fn of(outcomes: &[TaskExecutionOutcome]) -> Self {
        let mut summary = Self {
            total: outcomes.len(),
            ..Self::default()
        };
        for outcome in outcomes {
            match &outcome.result {
                Ok(_) => summary.succeeded += 1,
                Err(ToolExecutionError::Refused(_)) => summary.refused += 1,
                Err(_) => summary.failed += 1,
            }
        }
        summary
    }
}

impl fmt::Display for ProgressSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} step(s): {} succeeded, {} failed, {} refused",
            self.total, self.succeeded, self.failed, self.refused
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::ToolExecutionReport;
    use std::time::Duration;

    #[test]
    fn events_serialize_to_valid_json_lines() {
        let event = EngagementEvent::StepCompleted {
            target: "t1".to_string(),
            tool: "nmap".to_string(),
            exit_code: Some(0),
            duration_ms: 1234,
        };
        let line = event.to_json_line();
        let parsed = crate::json::parse(&line).expect("valid JSON");
        assert_eq!(
            parsed.get("event").and_then(|v| v.as_str()),
            Some("step_completed"),
        );
        assert_eq!(
            parsed
                .get("duration_ms")
                .and_then(crate::json::JsonValue::as_u64),
            Some(1234)
        );
    }

    #[test]
    fn refused_event_serializes_with_reason() {
        let event = EngagementEvent::StepRefused {
            target: "t1".to_string(),
            tool: "nmap".to_string(),
            reason: "out-of-scope target '10.9.9.9'".to_string(),
        };
        let parsed = crate::json::parse(&event.to_json_line()).expect("valid JSON");
        assert_eq!(
            parsed.get("event").and_then(|v| v.as_str()),
            Some("step_refused")
        );
        assert!(parsed.get("reason").and_then(|v| v.as_str()).is_some());
    }

    #[test]
    fn collecting_sink_preserves_order() {
        let sink = CollectingSink::new();
        sink.emit(&EngagementEvent::StageStarted {
            class: "StaticLocalAnalysis".to_string(),
            steps: 2,
        });
        sink.emit(&EngagementEvent::StepStarted {
            target: "t1".to_string(),
            tool: "semgrep".to_string(),
        });
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0],
            EngagementEvent::StageStarted { steps: 2, .. }
        ));
    }

    #[test]
    fn writer_sink_emits_one_line_per_event() {
        let mut buffer = Vec::new();
        {
            let sink = WriterSink::new(&mut buffer);
            sink.emit(&EngagementEvent::StepStarted {
                target: "t1".to_string(),
                tool: "nmap".to_string(),
            });
            sink.emit(&EngagementEvent::StageCompleted {
                class: "ActiveNetwork".to_string(),
                completed: 1,
                failed: 0,
            });
        }
        let text = String::from_utf8(buffer).expect("utf8");
        assert_eq!(text.lines().count(), 2);
        assert!(crate::json::parse(text.lines().next().unwrap()).is_some());
    }

    fn outcome(
        tool: &str,
        result: Result<ToolExecutionReport, ToolExecutionError>,
    ) -> TaskExecutionOutcome {
        TaskExecutionOutcome {
            target_id: "t1".to_string(),
            tool: tool.to_string(),
            result,
        }
    }

    fn ok_report() -> ToolExecutionReport {
        ToolExecutionReport {
            tool: "x".to_string(),
            arguments: Vec::new(),
            exit_code: Some(1),
            stdout: String::new(),
            stderr: String::new(),
            duration: Duration::from_millis(1),
        }
    }

    #[test]
    fn progress_summary_classifies_outcomes() {
        let outcomes = vec![
            outcome("a", Ok(ok_report())),
            outcome("b", Err(ToolExecutionError::NotInstalled("b".to_string()))),
            outcome(
                "c",
                Err(ToolExecutionError::Refused("out of scope".to_string())),
            ),
        ];
        let summary = ProgressSummary::of(&outcomes);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.refused, 1);
        assert!(summary.to_string().contains("1 refused"));
    }
}
