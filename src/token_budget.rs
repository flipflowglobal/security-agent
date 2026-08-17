//! Token budget tracking for LLM interactions.
//!
//! Tracks cumulative token consumption across a session and enforces
//! configurable limits. Every LLM call — proposal generation, ask-mode
//! continuations, perplexity scoring — draws from the same budget, preventing
//! runaway token usage from unbounded conversation loops or repeated retries.
//!
//! The budget is *advisory*: it lives alongside the authorization engine and
//! never gates security decisions. A budget exhaustion means "stop spending
//! tokens," not "deny the action."
//!
//! # Design
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │  TokenBudget                        │
//! │  ┌─────────┐  ┌──────────────────┐  │
//! │  │ limit   │  │ used: usize      │  │
//! │  │ (total) │  │ per_category:    │  │
//! │  │         │  │   HashMap<str,   │  │
//! │  │         │  │   usize>         │  │
//! │  └─────────┘  └──────────────────┘  │
//! │  try_reserve(n) -> Result<()>       │
//! │  consume(n)                         │
//! │  remaining() -> usize               │
//! │  utilization() -> f64               │
//! │  per_category_usage() -> Map        │
//! └─────────────────────────────────────┘
//! ```
//!
//! Two usage patterns:
//!
//! 1. **Pre-check**: call [`TokenBudget::try_reserve`] *before* the LLM call
//!    to fail fast when the budget is exhausted.
//! 2. **Post-tracking**: call [`TokenBudget::consume`] *after* the LLM call
//!    with the actual token count, for observability even when the pre-check
//!    passes.
//!
//! Both patterns are safe to combine — `try_reserve` is a hint, `consume` is
//! the ground truth.

use std::collections::HashMap;
use std::fmt;

/// Error returned when a token reservation exceeds the remaining budget.
///
/// The error carries the requested and available counts so callers can log a
/// precise message ("requested 512 tokens, only 200 remaining") without
/// re-querying the budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenBudgetExceeded {
    /// Tokens the caller requested.
    pub requested: usize,
    /// Tokens still available.
    pub available: usize,
}

impl fmt::Display for TokenBudgetExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "token budget exceeded: requested {} tokens, only {} remaining",
            self.requested, self.available
        )
    }
}

impl std::error::Error for TokenBudgetExceeded {}

/// Tracks cumulative token consumption across a session with optional
/// per-category breakdowns.
///
/// Categories let callers distinguish proposal tokens from ask-mode tokens
/// from perplexity scoring tokens, so the budget report shows *where* tokens
/// were spent, not just *that* they were spent.
///
/// # Examples
///
/// ```
/// use security_agent::token_budget::TokenBudget;
///
/// let mut budget = TokenBudget::new(1000);
/// assert!(budget.try_reserve(500, "proposal").is_ok());
/// budget.consume(480, "proposal");
/// assert_eq!(budget.remaining(), 520);
/// assert!(budget.try_reserve(600, "ask").is_err());
/// ```
#[derive(Debug, Clone)]
pub struct TokenBudget {
    /// Hard upper bound on total tokens. `None` means unlimited (budget is
    /// tracking-only, never rejecting).
    limit: Option<usize>,
    /// Cumulative tokens consumed across all categories.
    used: usize,
    /// Per-category token counts.
    per_category: HashMap<String, usize>,
}

impl TokenBudget {
    /// Creates a budget with a hard `limit`. The budget starts fully
    /// available.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            limit: Some(limit),
            used: 0,
            per_category: HashMap::new(),
        }
    }

    /// Creates a tracking-only budget with no enforcement limit. All
    /// `try_reserve` calls succeed; `consume` still records usage for
    /// observability.
    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            limit: None,
            used: 0,
            per_category: HashMap::new(),
        }
    }

    /// Attempts to reserve `n` tokens from the global budget. Returns
    /// `Ok(())` if the reservation fits the remaining budget (or the budget
    /// is unlimited), `Err(TokenBudgetExceeded)` otherwise.
    ///
    /// The `category` parameter is reserved for future per-category budget
    /// enforcement and currently has no effect — reservations are checked
    /// against the global limit only.
    ///
    /// Reservation is *advisory*: a failed reservation does not mutate the
    /// budget. The caller is expected to either proceed with a smaller
    /// allocation or abort the operation entirely.
    ///
    /// # Errors
    ///
    /// Returns [`TokenBudgetExceeded`] when `n` exceeds the remaining budget.
    pub const fn try_reserve(&self, n: usize, _category: &str) -> Result<(), TokenBudgetExceeded> {
        let available = self.remaining();
        if n <= available {
            Ok(())
        } else {
            Err(TokenBudgetExceeded {
                requested: n,
                available,
            })
        }
    }

    /// Records `n` tokens as consumed within `category`. Call this after an
    /// LLM call completes with the actual token count.
    ///
    /// `consume` does not check the budget limit — it unconditionally
    /// increments the counter so that `remaining()` and `utilization()` always
    /// reflect ground truth. A `try_reserve` that succeeded but a `consume`
    /// that overshoots is possible (the LLM generated more tokens than
    /// estimated); the next `try_reserve` will correctly reflect the new
    /// reality.
    pub fn consume(&mut self, n: usize, category: &str) {
        self.used = self.used.saturating_add(n);
        if let Some(entry) = self.per_category.get_mut(category) {
            *entry = entry.saturating_add(n);
        } else {
            self.per_category.insert(category.to_string(), n);
        }
    }

    /// Tokens remaining before the limit is reached. For unlimited budgets,
    /// returns [`usize::MAX`].
    #[must_use]
    pub const fn remaining(&self) -> usize {
        match self.limit {
            Some(limit) => limit.saturating_sub(self.used),
            None => usize::MAX,
        }
    }

    /// Total tokens consumed so far.
    #[must_use]
    pub const fn used(&self) -> usize {
        self.used
    }

    /// The hard limit, if any.
    #[must_use]
    pub const fn limit(&self) -> Option<usize> {
        self.limit
    }

    /// Fraction of the budget consumed, in `[0.0, 1.0]`. Returns `0.0` for a
    /// fresh budget and `1.0` when fully consumed. For unlimited budgets,
    /// returns `0.0` (there is no meaningful utilization fraction).
    #[must_use]
    pub fn utilization(&self) -> f64 {
        match self.limit {
            Some(limit) if limit > 0 => {
                #[allow(clippy::cast_precision_loss)]
                let used_f = self.used as f64;
                #[allow(clippy::cast_precision_loss)]
                let limit_f = limit as f64;
                (used_f / limit_f).clamp(0.0, 1.0)
            }
            _ => 0.0,
        }
    }

    /// A read-only view of per-category token usage.
    #[must_use]
    pub const fn per_category_usage(&self) -> &HashMap<String, usize> {
        &self.per_category
    }

    /// Tokens consumed within a specific category.
    #[must_use]
    pub fn category_used(&self, category: &str) -> usize {
        self.per_category.get(category).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_budget_is_fully_available() {
        let budget = TokenBudget::new(1000);
        assert_eq!(budget.remaining(), 1000);
        assert_eq!(budget.used(), 0);
        assert!((budget.utilization() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn consume_reduces_remaining() {
        let mut budget = TokenBudget::new(1000);
        budget.consume(300, "proposal");
        assert_eq!(budget.remaining(), 700);
        assert_eq!(budget.used(), 300);
        assert!((budget.utilization() - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn try_reserve_succeeds_within_budget() {
        let mut budget = TokenBudget::new(1000);
        budget.consume(500, "ask");
        assert!(budget.try_reserve(500, "ask").is_ok());
    }

    #[test]
    fn try_reserve_fails_when_exceeded() {
        let mut budget = TokenBudget::new(1000);
        budget.consume(800, "ask");
        let err = budget.try_reserve(300, "ask").unwrap_err();
        assert_eq!(err.requested, 300);
        assert_eq!(err.available, 200);
    }

    #[test]
    fn try_reserve_does_not_mutate_budget() {
        let mut budget = TokenBudget::new(1000);
        budget.consume(800, "ask");
        let _ = budget.try_reserve(300, "ask");
        assert_eq!(
            budget.used(),
            800,
            "failed reservation must not consume tokens"
        );
    }

    #[test]
    fn unlimited_budget_never_exceeds() {
        let mut budget = TokenBudget::unlimited();
        budget.consume(usize::MAX / 2, "a");
        assert!(budget.try_reserve(usize::MAX / 2, "b").is_ok());
        assert_eq!(budget.remaining(), usize::MAX);
    }

    #[test]
    fn per_category_tracking() {
        let mut budget = TokenBudget::new(10_000);
        budget.consume(100, "proposal");
        budget.consume(200, "ask");
        budget.consume(100, "proposal");
        assert_eq!(budget.category_used("proposal"), 200);
        assert_eq!(budget.category_used("ask"), 200);
        assert_eq!(budget.category_used("nonexistent"), 0);
        assert_eq!(budget.used(), 400);
    }

    #[test]
    fn utilization_is_one_when_fully_consumed() {
        let mut budget = TokenBudget::new(100);
        budget.consume(100, "all");
        assert!((budget.utilization() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn utilization_saturates_at_one() {
        let mut budget = TokenBudget::new(100);
        budget.consume(200, "overshoot");
        assert!((budget.utilization() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn unlimited_utilization_is_zero() {
        let mut budget = TokenBudget::unlimited();
        budget.consume(1000, "work");
        assert!((budget.utilization() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn remaining_saturates_at_zero() {
        let mut budget = TokenBudget::new(100);
        budget.consume(200, "overshoot");
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn zero_limit_budget_is_immediately_exhausted() {
        let budget = TokenBudget::new(0);
        assert!(budget.try_reserve(0, "noop").is_ok());
        assert!(budget.try_reserve(1, "anything").is_err());
    }

    #[test]
    fn budget_is_cloneable() {
        let mut budget = TokenBudget::new(500);
        budget.consume(100, "a");
        let cloned = budget.clone();
        assert_eq!(cloned.remaining(), 400);
        assert_eq!(cloned.category_used("a"), 100);
    }

    #[test]
    fn displayed_exceeded_error_shows_counts() {
        let err = TokenBudgetExceeded {
            requested: 512,
            available: 200,
        };
        let msg = err.to_string();
        assert!(msg.contains("512"), "should show requested: {msg}");
        assert!(msg.contains("200"), "should show available: {msg}");
    }

    #[test]
    fn display_implementation_for_budget_exceeded() {
        let err = TokenBudgetExceeded {
            requested: 100,
            available: 50,
        };
        assert_eq!(
            err.to_string(),
            "token budget exceeded: requested 100 tokens, only 50 remaining"
        );
    }

    #[test]
    fn budget_limit_is_queryable() {
        let budget = TokenBudget::new(2048);
        assert_eq!(budget.limit(), Some(2048));
        let unlimited = TokenBudget::unlimited();
        assert_eq!(unlimited.limit(), None);
    }

    #[test]
    fn multiple_reserves_draw_down_budget() {
        let mut budget = TokenBudget::new(1000);
        assert!(budget.try_reserve(400, "a").is_ok());
        budget.consume(400, "a");
        assert!(budget.try_reserve(400, "b").is_ok());
        budget.consume(400, "b");
        assert_eq!(budget.remaining(), 200);
        assert!(budget.try_reserve(300, "c").is_err());
        assert!(budget.try_reserve(200, "c").is_ok());
    }

    #[test]
    fn per_category_usage_returns_reference() {
        let mut budget = TokenBudget::new(10_000);
        budget.consume(100, "proposal");
        budget.consume(200, "ask");
        let usage = budget.per_category_usage();
        assert_eq!(usage.len(), 2);
        assert_eq!(usage["proposal"], 100);
        assert_eq!(usage["ask"], 200);
    }

    #[test]
    fn consume_extreme_values_does_not_panic() {
        let mut budget = TokenBudget::unlimited();
        budget.consume(usize::MAX, "x");
        assert_eq!(budget.category_used("x"), usize::MAX);
    }

    #[test]
    fn empty_string_category_is_valid() {
        let mut budget = TokenBudget::new(1000);
        budget.consume(50, "");
        assert_eq!(budget.category_used(""), 50);
    }

    #[test]
    fn exceeded_error_equality() {
        let a = TokenBudgetExceeded {
            requested: 10,
            available: 5,
        };
        let b = TokenBudgetExceeded {
            requested: 10,
            available: 5,
        };
        assert_eq!(a, b);
    }
}
