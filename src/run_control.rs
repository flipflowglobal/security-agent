//! Real-time control of a running engagement: pause, resume, cancel, and live
//! rate adjustment, shared safely across the runtime's worker threads.
//!
//! A long engagement is otherwise fire-and-forget: once `--run-engagement`
//! starts, an operator can only let it finish or kill the process. This module
//! gives them a live handle instead. The runtime consults a [`RunController`]
//! between step launches (see [`crate::runtime`]); whatever drives it — a CLI
//! control-file poller, a signal handler, or a test — flips the same lock-free
//! state.
//!
//! The type is deliberately dependency-light (just atomics) and holds no I/O:
//! parsing an operator's command and reporting transitions live in the layers
//! that own the file and the event sink, so this core stays trivially testable.
//!
//! **Cancellation is terminal and monotonic.** Once cancelled, pause and resume
//! are ignored, so a cancelled run can never be silently un-cancelled.

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

/// The live phase of a controllable run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunPhase {
    /// Workers launch new steps normally.
    Running,
    /// In-flight tools finish, but no new steps launch until resumed.
    Paused,
    /// In-flight tools finish, then the run ends; no new steps launch.
    Cancelled,
}

const RUNNING: u8 = 0;
const PAUSED: u8 = 1;
const CANCELLED: u8 = 2;

/// Sentinel rate meaning "no override — use the runtime's configured interval".
const RATE_UNSET: u64 = u64::MAX;

/// One operator instruction to a running engagement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlCommand {
    /// Stop launching new steps; let in-flight tools finish.
    Pause,
    /// Resume launching steps after a pause.
    Resume,
    /// Stop the run (terminal): finish in-flight tools, launch no more.
    Cancel,
    /// Live-adjust the minimum interval between tool spawns. `None` removes any
    /// rate limit.
    SetRate(Option<Duration>),
}

/// A control handle shared between an engagement run and whatever drives it.
///
/// All operations are lock-free and safe to call from any thread; the runtime
/// reads the state between step launches.
#[derive(Debug)]
pub struct RunController {
    phase: AtomicU8,
    rate_ms: AtomicU64,
}

impl Default for RunController {
    fn default() -> Self {
        Self::new()
    }
}

impl RunController {
    /// A fresh controller: running, with no rate override.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: AtomicU8::new(RUNNING),
            rate_ms: AtomicU64::new(RATE_UNSET),
        }
    }

    /// Pauses the run. Ignored once cancelled (cancellation is terminal).
    pub fn pause(&self) {
        let _ = self
            .phase
            .compare_exchange(RUNNING, PAUSED, Ordering::SeqCst, Ordering::SeqCst);
    }

    /// Resumes a paused run. Ignored once cancelled.
    pub fn resume(&self) {
        let _ = self
            .phase
            .compare_exchange(PAUSED, RUNNING, Ordering::SeqCst, Ordering::SeqCst);
    }

    /// Cancels the run. Terminal: no later pause/resume can undo it.
    pub fn cancel(&self) {
        self.phase.store(CANCELLED, Ordering::SeqCst);
    }

    /// The current phase.
    #[must_use]
    pub fn phase(&self) -> RunPhase {
        match self.phase.load(Ordering::SeqCst) {
            PAUSED => RunPhase::Paused,
            CANCELLED => RunPhase::Cancelled,
            _ => RunPhase::Running,
        }
    }

    /// `true` while the run is paused.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.phase.load(Ordering::SeqCst) == PAUSED
    }

    /// `true` once the run has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.phase.load(Ordering::SeqCst) == CANCELLED
    }

    /// Overrides the minimum spawn interval live. `Some(Duration::ZERO)` or
    /// `None` both remove any rate limit.
    pub fn set_min_spawn_interval(&self, interval: Option<Duration>) {
        let encoded = interval.map_or(0, |duration| {
            u64::try_from(duration.as_millis().min(u128::from(RATE_UNSET - 1))).unwrap_or(0)
        });
        self.rate_ms.store(encoded, Ordering::SeqCst);
    }

    /// The effective minimum spawn interval: the live override when one has
    /// been set, otherwise `default`. An override of "no limit" returns `None`.
    #[must_use]
    pub fn min_spawn_interval(&self, default: Option<Duration>) -> Option<Duration> {
        match self.rate_ms.load(Ordering::SeqCst) {
            RATE_UNSET => default,
            0 => None,
            ms => Some(Duration::from_millis(ms)),
        }
    }

    /// Applies one operator command.
    pub fn apply(&self, command: ControlCommand) {
        match command {
            ControlCommand::Pause => self.pause(),
            ControlCommand::Resume => self.resume(),
            ControlCommand::Cancel => self.cancel(),
            ControlCommand::SetRate(interval) => self.set_min_spawn_interval(interval),
        }
    }
}

/// Parses one operator command line, e.g. `pause`, `resume`, `cancel`,
/// `rate 5`, or `rate off`. Case-insensitive; ignores surrounding whitespace.
///
/// # Errors
///
/// Returns a human-readable message when the verb is unknown, a `rate` value
/// is missing or not a whole number of seconds, or extra arguments trail the
/// command.
pub fn parse_command(line: &str) -> Result<ControlCommand, String> {
    let mut parts = line.split_whitespace();
    let Some(verb) = parts.next() else {
        return Err("empty control command".to_string());
    };
    let command = match verb.to_ascii_lowercase().as_str() {
        "pause" => ControlCommand::Pause,
        "resume" | "continue" => ControlCommand::Resume,
        "cancel" | "stop" | "abort" => ControlCommand::Cancel,
        "rate" => {
            let arg = parts
                .next()
                .ok_or_else(|| "`rate` needs a value: whole seconds or 'off'".to_string())?;
            if arg.eq_ignore_ascii_case("off") || arg == "0" {
                ControlCommand::SetRate(None)
            } else {
                let secs = arg
                    .parse::<u64>()
                    .map_err(|_| format!("invalid rate '{arg}' (want whole seconds or 'off')"))?;
                ControlCommand::SetRate(Some(Duration::from_secs(secs)))
            }
        }
        other => return Err(format!("unknown control command '{other}'")),
    };
    if parts.next().is_some() {
        return Err(format!("unexpected extra arguments after '{verb}'"));
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_running_with_no_rate_override() {
        let controller = RunController::new();
        assert_eq!(controller.phase(), RunPhase::Running);
        assert!(!controller.is_paused());
        assert!(!controller.is_cancelled());
        assert_eq!(
            controller.min_spawn_interval(Some(Duration::from_secs(2))),
            Some(Duration::from_secs(2)),
        );
    }

    #[test]
    fn pause_and_resume_round_trip() {
        let controller = RunController::new();
        controller.pause();
        assert!(controller.is_paused());
        assert_eq!(controller.phase(), RunPhase::Paused);
        controller.resume();
        assert_eq!(controller.phase(), RunPhase::Running);
    }

    #[test]
    fn cancel_is_terminal() {
        let controller = RunController::new();
        controller.cancel();
        assert!(controller.is_cancelled());
        // Pause/resume must not undo a cancellation.
        controller.pause();
        controller.resume();
        assert_eq!(controller.phase(), RunPhase::Cancelled);
    }

    #[test]
    fn rate_override_wins_over_default_and_off_disables() {
        let controller = RunController::new();
        controller.set_min_spawn_interval(Some(Duration::from_secs(5)));
        assert_eq!(
            controller.min_spawn_interval(None),
            Some(Duration::from_secs(5))
        );
        controller.set_min_spawn_interval(None);
        assert_eq!(
            controller.min_spawn_interval(Some(Duration::from_secs(9))),
            None
        );
    }

    #[test]
    fn apply_dispatches_each_command() {
        let controller = RunController::new();
        controller.apply(ControlCommand::Pause);
        assert!(controller.is_paused());
        controller.apply(ControlCommand::SetRate(Some(Duration::from_secs(3))));
        assert_eq!(
            controller.min_spawn_interval(None),
            Some(Duration::from_secs(3))
        );
        controller.apply(ControlCommand::Cancel);
        assert!(controller.is_cancelled());
    }

    #[test]
    fn parses_the_command_vocabulary() {
        assert_eq!(parse_command("pause"), Ok(ControlCommand::Pause));
        assert_eq!(parse_command("  RESUME "), Ok(ControlCommand::Resume));
        assert_eq!(parse_command("continue"), Ok(ControlCommand::Resume));
        assert_eq!(parse_command("cancel"), Ok(ControlCommand::Cancel));
        assert_eq!(parse_command("stop"), Ok(ControlCommand::Cancel));
        assert_eq!(
            parse_command("rate 7"),
            Ok(ControlCommand::SetRate(Some(Duration::from_secs(7))))
        );
        assert_eq!(parse_command("rate off"), Ok(ControlCommand::SetRate(None)));
        assert_eq!(parse_command("rate 0"), Ok(ControlCommand::SetRate(None)));
    }

    #[test]
    fn rejects_bad_commands() {
        assert!(parse_command("").is_err());
        assert!(parse_command("frobnicate").is_err());
        assert!(parse_command("rate").is_err());
        assert!(parse_command("rate soon").is_err());
        assert!(parse_command("pause now").is_err());
    }
}
