//! Conversation context compaction for multi-turn agent sessions.
//!
//! Manages a sliding window of conversation turns and compacts older turns
//! when the total token count exceeds a configurable threshold. This prevents
//! unbounded context growth in long-running agent sessions without losing
//! recent, relevant context.
//!
//! # Design
//!
//! Compaction uses a simple summarization strategy: when the total estimated
//! token count across all turns exceeds `threshold`, the oldest turns are
//! collapsed into a single synthetic summary turn. The summary preserves the
//! key facts (goal, actions taken, outcomes) while discarding verbatim text.
//! Recent turns (within `preserve_recent` of the end) are never compacted.
//!
//! ```text
//! Before compaction:
//!   [system] [user: "scan X"] [agent: "planned nmap"] [agent: "nmap ran"]
//!            [user: "now scan Y"] [agent: "planned masscan"] [agent: "done"]
//!
//! After compaction (preserve_recent=2):
//!   [summary: "Scanned X with nmap (ran)."] [user: "now scan Y"]
//!            [agent: "planned masscan"] [agent: "done"]
//! ```
//!
//! Token estimation is byte-based (`bytes / 4`) — fast, zero-dependency,
//! and close enough for budget enforcement. The summary is a structured
//! extraction, not an LLM call, so it stays deterministic and offline.
//!
//! # Security
//!
//! Compaction is purely a context-management optimization. It never modifies
//! authorization state, audit records, or the agent transcript. The summary
//! turn is clearly marked as synthetic and cannot be mistaken for user input
//! or agent output.

use std::fmt;

/// Estimated tokens per character. English text averages ~4 characters per
/// token; this constant is intentionally conservative (slightly underestimates)
/// so the budget is not exceeded by estimation error.
const CHARS_PER_TOKEN: usize = 4;

/// A single turn in a conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Turn {
    /// Who produced this turn.
    pub role: TurnRole,
    /// The verbatim text content.
    pub content: String,
    /// Estimated token count (cached at construction).
    estimated_tokens: usize,
}

impl Turn {
    /// Creates a new turn, pre-computing its token estimate.
    #[must_use]
    pub fn new(role: TurnRole, content: impl Into<String>) -> Self {
        let content = content.into();
        let estimated_tokens = estimate_tokens(&content);
        Self {
            role,
            content,
            estimated_tokens,
        }
    }

    /// The estimated token count for this turn.
    #[must_use]
    pub const fn estimated_tokens(&self) -> usize {
        self.estimated_tokens
    }
}

/// The role of a conversation participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TurnRole {
    /// System instructions / context.
    System,
    /// Human operator input.
    User,
    /// Agent / assistant response.
    Assistant,
    /// Synthetic summary of compacted turns (not a real participant).
    Summary,
}

impl fmt::Display for TurnRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => write!(f, "system"),
            Self::User => write!(f, "user"),
            Self::Assistant => write!(f, "assistant"),
            Self::Summary => write!(f, "summary"),
        }
    }
}

/// A conversation context window with automatic compaction.
///
/// Grows until the total estimated tokens exceed `threshold`, then collapses
/// the oldest non-preserved turns into a summary.
///
/// # Examples
///
/// ```
/// use security_agent::context_compaction::{ContextWindow, Turn, TurnRole};
///
/// let mut window = ContextWindow::new(50, 2);
/// // Push turns until compaction triggers.
/// for i in 0..10 {
///     window.push(Turn::new(TurnRole::User, format!("action {i} padding content here")));
/// }
/// // Compaction has run at least once.
/// assert!(window.compaction_count() >= 1);
/// // Recent turns are preserved (not summaries).
/// let last = window.turns().last().unwrap();
/// assert_eq!(last.role, TurnRole::User);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextWindow {
    /// Maximum estimated tokens before compaction triggers.
    threshold: usize,
    /// Number of recent turns to never compact (counted from the end).
    preserve_recent: usize,
    /// The turns, oldest first.
    turns: Vec<Turn>,
    /// Cumulative estimated tokens across all turns (kept in sync).
    total_tokens: usize,
    /// Number of compactions performed (for observability).
    compaction_count: usize,
}

impl ContextWindow {
    /// Creates a new window with the given `threshold` (total tokens before
    /// compaction) and `preserve_recent` (turns at the end that are never
    /// compacted).
    ///
    /// `preserve_recent` must be at least 1 — there must always be a
    /// non-synthetic turn to anchor the conversation.
    ///
    /// # Panics
    ///
    /// Panics if `preserve_recent` is 0.
    #[must_use]
    pub fn new(threshold: usize, preserve_recent: usize) -> Self {
        assert!(preserve_recent > 0, "preserve_recent must be at least 1");
        Self {
            threshold,
            preserve_recent,
            turns: Vec::new(),
            total_tokens: 0,
            compaction_count: 0,
        }
    }

    /// Appends a turn to the window and triggers compaction if needed.
    pub fn push(&mut self, turn: Turn) {
        self.total_tokens = self.total_tokens.saturating_add(turn.estimated_tokens());
        self.turns.push(turn);
        self.compact_if_needed();
    }

    /// The turns currently in the window.
    #[must_use]
    pub fn turns(&self) -> &[Turn] {
        &self.turns
    }

    /// Total estimated tokens across all turns.
    #[must_use]
    pub const fn total_estimated_tokens(&self) -> usize {
        self.total_tokens
    }

    /// Number of compactions performed since creation.
    #[must_use]
    pub const fn compaction_count(&self) -> usize {
        self.compaction_count
    }

    /// The compaction threshold.
    #[must_use]
    pub const fn threshold(&self) -> usize {
        self.threshold
    }

    /// Number of recent turns preserved during compaction.
    #[must_use]
    pub const fn preserve_recent(&self) -> usize {
        self.preserve_recent
    }

    /// Drains all turns, resetting the window to empty.
    pub fn clear(&mut self) {
        self.turns.clear();
        self.total_tokens = 0;
        self.compaction_count = 0;
    }

    /// Triggers compaction if total tokens exceed the threshold.
    ///
    /// Compaction collapses the oldest non-preserved turns into a single
    /// summary turn. The summary is structured (not LLM-generated) and
    /// clearly marked with [`TurnRole::Summary`].
    fn compact_if_needed(&mut self) {
        if self.total_tokens <= self.threshold || self.turns.len() <= self.preserve_recent {
            return;
        }
        // Split: compactable prefix | preserved suffix.
        let compactable_end = self.turns.len().saturating_sub(self.preserve_recent);
        if compactable_end == 0 {
            return;
        }
        let compactable: Vec<Turn> = self.turns.drain(..compactable_end).collect();
        let summary = summarize_turns(&compactable);
        let summary_tokens = summary.estimated_tokens();
        // Recalculate total from what remains + the new summary.
        self.total_tokens = self
            .turns
            .iter()
            .map(Turn::estimated_tokens)
            .sum::<usize>()
            .saturating_add(summary_tokens);
        self.turns.insert(0, summary);
        self.compaction_count += 1;
    }
}

/// Estimates the token count of text using a byte-based heuristic.
///
/// Uses `text.len() / 4` (bytes, not characters) as a conservative
/// approximation. For English text (ASCII, ~1 byte per character), bytes
/// and characters are equivalent. For non-ASCII content (CJK, emoji), the
/// byte count exceeds the character count, making this estimate
/// *over*-conservative — it triggers compaction earlier than strictly
/// necessary, which is the safe direction for budget enforcement.
#[must_use]
pub const fn estimate_tokens(text: &str) -> usize {
    // Integer division rounds down, giving a conservative estimate.
    text.len() / CHARS_PER_TOKEN
}

/// Builds a structured summary from a sequence of compacted turns.
///
/// The summary extracts goals, actions, and outcomes without requiring an LLM.
/// It is deterministic: the same input always produces the same summary.
fn summarize_turns(turns: &[Turn]) -> Turn {
    let mut goals = Vec::new();
    let mut actions = Vec::new();
    let mut prior_contexts: usize = 0;

    for turn in turns {
        match turn.role {
            TurnRole::User => {
                let trimmed = turn.content.trim();
                if !trimmed.is_empty() {
                    goals.push(truncated(trimmed, 80));
                }
            }
            TurnRole::Assistant => {
                let trimmed = turn.content.trim();
                if trimmed.len() > 4 {
                    // Skip very short acknowledgements ("ok", "done").
                    actions.push(truncated(trimmed, 80));
                }
            }
            TurnRole::System => {
                // System turns are context, not actionable — skip.
            }
            TurnRole::Summary => {
                // Already-compacted content — count it as prior context
                // without copying the full text (prevents summary-of-summary
                // bloat on repeated compaction).
                prior_contexts += 1;
            }
        }
    }

    let mut parts = Vec::new();
    if prior_contexts > 0 {
        parts.push(format!("({prior_contexts} prior compacted turns)"));
    }
    if !goals.is_empty() {
        parts.push(format!("Goals: {}.", goals.join("; ")));
    }
    if !actions.is_empty() {
        parts.push(format!("Actions: {}.", actions.join("; ")));
    }

    let content = if parts.is_empty() {
        "[compacted context]".to_string()
    } else {
        format!("[compacted] {}", parts.join(" "))
    };

    Turn::new(TurnRole::Summary, content)
}

/// Truncates `text` to at most `max_chars` characters, appending "..." if
/// truncated. Uses character boundaries (not byte indices) so multi-byte
/// UTF-8 content is never sliced mid-character.
#[must_use]
fn truncated(text: &str, max_chars: usize) -> String {
    let end = text
        .char_indices()
        .nth(max_chars)
        .map_or(text.len(), |(i, _)| i);
    if end >= text.len() {
        text.to_string()
    } else {
        format!("{}...", &text[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_tokens_basic() {
        // 16 chars / 4 = 4 tokens.
        assert_eq!(estimate_tokens("abcdabcdabcdabcd"), 4);
    }

    #[test]
    fn estimate_tokens_rounds_down() {
        // 7 chars / 4 = 1 (conservative).
        assert_eq!(estimate_tokens("abcdefg"), 1);
    }

    #[test]
    fn estimate_tokens_empty_string() {
        assert_eq!(estimate_tokens(""), 0);
    }

    #[test]
    fn turn_stores_content_and_estimate() {
        let turn = Turn::new(TurnRole::User, "hello world"); // 11 chars -> 2 tokens.
        assert_eq!(turn.content, "hello world");
        assert_eq!(turn.role, TurnRole::User);
        assert_eq!(turn.estimated_tokens(), 2);
    }

    #[test]
    fn new_window_is_empty() {
        let window = ContextWindow::new(1000, 2);
        assert!(window.turns().is_empty());
        assert_eq!(window.total_estimated_tokens(), 0);
        assert_eq!(window.compaction_count(), 0);
    }

    #[test]
    fn push_adds_turn_and_tracks_tokens() {
        let mut window = ContextWindow::new(1000, 2);
        window.push(Turn::new(TurnRole::User, "hello")); // 5/4 = 1
        assert_eq!(window.turns().len(), 1);
        assert_eq!(window.total_estimated_tokens(), 1);
    }

    #[test]
    fn compaction_triggers_when_threshold_exceeded() {
        // Threshold of 20 tokens, preserve 2 recent turns.
        let mut window = ContextWindow::new(20, 2);
        // Add 6 turns of 40 chars each (10 tokens each = 60 total).
        for i in 0..6 {
            window.push(Turn::new(
                TurnRole::User,
                format!("turn {i} with some content here to fill space"),
            ));
        }
        // After compaction, the old turns should be summarized and the
        // window should be significantly smaller than the uncompacted 60
        // tokens. Summary overhead adds some fixed cost, so we verify the
        // reduction is meaningful rather than exact.
        assert!(
            window.total_estimated_tokens() < 55,
            "total: {} (expected significant reduction from 60)",
            window.total_estimated_tokens()
        );
        assert!(
            window.compaction_count() >= 1,
            "compaction should have occurred"
        );
        // The preserved recent turns should still be present.
        let last_two: Vec<&str> = window
            .turns()
            .iter()
            .rev()
            .take(2)
            .map(|t| t.content.as_str())
            .collect();
        assert!(
            last_two.iter().any(|c| c.contains("turn 5")),
            "recent turn should be preserved: {last_two:?}"
        );
    }

    #[test]
    fn compaction_never_compacts_preserved_turns() {
        let mut window = ContextWindow::new(10, 2);
        // Fill with tiny turns to exceed threshold.
        for i in 0..10 {
            window.push(Turn::new(
                TurnRole::User,
                format!("{i}: abcdefghij"), // ~3-4 tokens each
            ));
        }
        // The last 2 turns must not be summaries.
        let last_roles: Vec<TurnRole> = window
            .turns()
            .iter()
            .rev()
            .take(2)
            .map(|t| t.role)
            .collect();
        assert!(
            last_roles.iter().all(|r| *r != TurnRole::Summary),
            "preserved turns must not be summaries: {last_roles:?}"
        );
    }

    #[test]
    fn clear_resets_everything() {
        let mut window = ContextWindow::new(10, 1);
        window.push(Turn::new(TurnRole::User, "hello"));
        window.push(Turn::new(TurnRole::User, "world"));
        window.clear();
        assert!(window.turns().is_empty());
        assert_eq!(window.total_estimated_tokens(), 0);
    }

    #[test]
    fn summary_turn_has_summary_role() {
        let mut window = ContextWindow::new(5, 1);
        // Force compaction with enough turns.
        for i in 0..10 {
            window.push(Turn::new(
                TurnRole::User,
                format!("turn {i} padding content here"),
            ));
        }
        assert!(
            window.turns().iter().any(|t| t.role == TurnRole::Summary),
            "should have at least one summary turn"
        );
    }

    #[test]
    fn no_compaction_when_under_threshold() {
        let mut window = ContextWindow::new(1000, 2);
        for i in 0..5 {
            window.push(Turn::new(TurnRole::User, format!("{i}: hi")));
        }
        assert_eq!(window.compaction_count(), 0);
        assert_eq!(window.turns().len(), 5);
    }

    #[test]
    fn turn_role_display() {
        assert_eq!(TurnRole::System.to_string(), "system");
        assert_eq!(TurnRole::User.to_string(), "user");
        assert_eq!(TurnRole::Assistant.to_string(), "assistant");
        assert_eq!(TurnRole::Summary.to_string(), "summary");
    }

    #[test]
    fn preserved_recent_of_one_preserves_last_turn() {
        let mut window = ContextWindow::new(5, 1);
        for i in 0..10 {
            window.push(Turn::new(TurnRole::User, format!("turn {i} padding here")));
        }
        let last = window.turns().last().expect("at least one turn");
        assert_eq!(last.role, TurnRole::User);
        assert!(
            last.content.contains("turn 9"),
            "last turn: {}",
            last.content
        );
    }

    #[test]
    fn window_is_cloneable() {
        let mut window = ContextWindow::new(100, 1);
        window.push(Turn::new(TurnRole::User, "test"));
        let cloned = window.clone();
        assert_eq!(cloned.turns().len(), 1);
        assert_eq!(
            cloned.total_estimated_tokens(),
            window.total_estimated_tokens()
        );
    }

    #[test]
    fn truncated_helper() {
        assert_eq!(truncated("hello", 10), "hello");
        assert_eq!(truncated("hello world", 5), "hello...");
    }

    #[test]
    fn system_turns_are_excluded_from_summary() {
        let mut window = ContextWindow::new(5, 1);
        // Add system turns + user turns to trigger compaction.
        window.push(Turn::new(TurnRole::System, "system instruction"));
        window.push(Turn::new(TurnRole::User, "action one padding content"));
        window.push(Turn::new(TurnRole::User, "action two padding content"));
        window.push(Turn::new(TurnRole::User, "action three padding content"));
        // Find the summary and verify it doesn't contain the system text.
        for turn in window.turns() {
            if turn.role == TurnRole::Summary {
                assert!(
                    !turn.content.contains("system instruction"),
                    "summary should not include system turns: {}",
                    turn.content
                );
            }
        }
    }

    #[test]
    fn truncated_handles_multibyte_utf8_safely() {
        // CJK characters are 3 bytes each. 78 ASCII + 3 CJK = 87 bytes.
        // Truncating at 80 bytes would slice mid-character in byte-based code.
        let prefix = "a".repeat(78);
        let text = format!("{prefix}你好世");
        let result = truncated(&text, 80);
        assert!(result.ends_with("..."), "should be truncated: {result}");
        // Must end on a valid char boundary.
        let trimmed = result.trim_end_matches('.');
        assert!(
            std::str::from_utf8(trimmed.as_bytes()).is_ok(),
            "truncation must not split UTF-8"
        );
    }

    #[test]
    fn truncated_preserves_multibyte_within_limit() {
        let text = "你好世界"; // 12 bytes, 4 chars.
        assert_eq!(truncated(text, 10), "你好世界");
    }

    #[test]
    fn threshold_zero_compacts_every_push() {
        let mut window = ContextWindow::new(0, 1);
        // First push: 1 turn ≤ preserve_recent (1), no compaction yet.
        window.push(Turn::new(TurnRole::User, "first"));
        assert_eq!(window.compaction_count(), 0);
        // Second push: 2 turns > preserve_recent (1), compaction triggers.
        window.push(Turn::new(TurnRole::User, "second"));
        assert_eq!(window.compaction_count(), 1);
        // Third push: triggers again.
        window.push(Turn::new(TurnRole::User, "third"));
        assert_eq!(window.compaction_count(), 2);
    }

    #[test]
    fn repeated_compaction_converges() {
        let mut window = ContextWindow::new(10, 1);
        for i in 0..100 {
            window.push(Turn::new(
                TurnRole::User,
                format!("turn {i} padding content here"),
            ));
        }
        assert!(window.turns().len() <= 3, "turns: {}", window.turns().len());
        assert!(window.total_estimated_tokens() < 100);
    }

    #[test]
    fn clear_after_compaction_resets_tokens() {
        let mut window = ContextWindow::new(5, 1);
        for i in 0..10 {
            window.push(Turn::new(TurnRole::User, format!("turn {i} padding")));
        }
        assert!(window.total_estimated_tokens() > 0);
        assert!(window.compaction_count() > 0);
        window.clear();
        assert_eq!(window.total_estimated_tokens(), 0);
        assert_eq!(window.compaction_count(), 0);
        assert!(window.turns().is_empty());
    }
}
