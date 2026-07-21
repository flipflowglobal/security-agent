//! Non-blocking intensity advisories for real network-tool execution.
//!
//! Real execution (see `crate::execution`) trusts operator arguments as-is:
//! there is no hard ceiling on how aggressive an `nmap`/`masscan` invocation
//! may be. That is a deliberate part of the operating model. This module
//! adds an *advisory* layer on top of it — it never rejects a command or
//! changes an exit code, it only surfaces a mismatch between the
//! aggressiveness implied by the operator's flags and the engagement's
//! declared [`TestIntensity`] ceiling, so the operator (and the audit
//! reader) can see when a scan is being run harder than the engagement
//! nominally authorized.
//!
//! A real, blocking ceiling would belong in `crate::policy` as an eighth
//! authorization gate with its own error variant; that is intentionally out
//! of scope here.

use crate::model::TestIntensity;

/// A single advisory: one operator-supplied token looks more aggressive
/// than the engagement's declared ceiling. Purely descriptive — emitting
/// one never blocks execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntensityAdvisory {
    /// The offending token exactly as the operator supplied it, e.g. `-T5`.
    pub flag: String,
    /// The engagement's declared ceiling that the token exceeded.
    pub declared_ceiling: TestIntensity,
    /// A human-readable explanation, ready to print to stderr.
    pub message: String,
}

/// The minimum intensity at which a given flag is "expected" — i.e. below
/// which it looks out of place and warrants an advisory.
fn expected_minimum_for_token(token: &str) -> Option<TestIntensity> {
    match token {
        // Timing templates T4/T5 and explicit rate/parallelism floors are
        // aggressive-tier: they deliberately push packets faster than a
        // measured scan.
        "-T4" | "-T5" | "--min-rate" | "--max-rate" | "--min-parallelism" => {
            Some(TestIntensity::Aggressive)
        }
        // Full-range port sweeps and masscan's `--rate` are standard-tier:
        // heavier than passive recon but not inherently aggressive.
        "-p-" | "--rate" => Some(TestIntensity::Standard),
        _ => None,
    }
}

/// Rate-style flags whose *operand* (the following token) decides whether
/// they are aggressive. A high packet rate is aggressive regardless of the
/// flag's baseline tier.
const RATE_FLAGS_WITH_OPERAND: &[&str] = &["--min-rate", "--max-rate", "--rate"];

/// Packets-per-second at or above which a rate operand is treated as
/// aggressive rather than merely standard.
const AGGRESSIVE_RATE_THRESHOLD: u64 = 20_000;

/// Scans `arguments` for tokens that look more aggressive than `ceiling`
/// and returns one [`IntensityAdvisory`] per offending token (empty when
/// the arguments are within the declared ceiling).
///
/// Pure and side-effect free: it reads only `arguments` and `ceiling`, and
/// never panics on malformed input (an unparseable rate operand simply
/// yields no advisory).
#[must_use]
pub fn advise(arguments: &[String], ceiling: TestIntensity) -> Vec<IntensityAdvisory> {
    let mut advisories = Vec::new();

    for (index, token) in arguments.iter().enumerate() {
        let expected = if RATE_FLAGS_WITH_OPERAND.contains(&token.as_str()) {
            // The tier depends on the numeric operand that follows. If it is
            // missing or unparseable, fail quiet (no advisory) rather than
            // guessing.
            match arguments
                .get(index + 1)
                .and_then(|operand| operand.parse::<u64>().ok())
            {
                Some(rate) if rate >= AGGRESSIVE_RATE_THRESHOLD => TestIntensity::Aggressive,
                Some(_) => TestIntensity::Standard,
                None => continue,
            }
        } else if let Some(expected) = expected_minimum_for_token(token) {
            expected
        } else {
            continue;
        };

        if expected > ceiling {
            advisories.push(IntensityAdvisory {
                flag: token.clone(),
                declared_ceiling: ceiling,
                message: format!(
                    "argument {token} implies {expected} intensity but the engagement's \
                     declared ceiling is {ceiling}; execution is not blocked, but the scan \
                     is running harder than authorized"
                ),
            });
        }
    }

    advisories
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|token| (*token).to_string()).collect()
    }

    #[test]
    fn flags_t5_against_passive_ceiling() {
        let advisories = advise(&args(&["-T5", "10.0.0.1"]), TestIntensity::Passive);
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].flag, "-T5");
        assert_eq!(advisories[0].declared_ceiling, TestIntensity::Passive);
    }

    #[test]
    fn no_advisory_for_t5_against_aggressive_ceiling() {
        let advisories = advise(&args(&["-T5", "10.0.0.1"]), TestIntensity::Aggressive);
        assert!(advisories.is_empty());
    }

    #[test]
    fn parses_min_rate_operand_and_thresholds() {
        // 100000 >= threshold -> aggressive -> exceeds Standard.
        let advisories = advise(&args(&["--min-rate", "100000"]), TestIntensity::Standard);
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].flag, "--min-rate");

        // A modest rate is standard-tier and does not exceed a Standard ceiling.
        let modest = advise(&args(&["--min-rate", "500"]), TestIntensity::Standard);
        assert!(modest.is_empty());
    }

    #[test]
    fn unparseable_operand_does_not_warn() {
        let advisories = advise(&args(&["--min-rate", "abc"]), TestIntensity::Passive);
        assert!(advisories.is_empty());
    }

    #[test]
    fn missing_operand_does_not_warn() {
        let advisories = advise(&args(&["--min-rate"]), TestIntensity::Passive);
        assert!(advisories.is_empty());
    }

    #[test]
    fn clean_args_yield_no_advisories() {
        let advisories = advise(
            &args(&["-sV", "-p", "80,443", "10.0.0.1"]),
            TestIntensity::Passive,
        );
        assert!(advisories.is_empty());
    }

    #[test]
    fn full_port_range_exceeds_passive_but_not_standard() {
        assert_eq!(advise(&args(&["-p-"]), TestIntensity::Passive).len(), 1);
        assert!(advise(&args(&["-p-"]), TestIntensity::Standard).is_empty());
    }

    #[test]
    fn reports_every_offending_token() {
        let advisories = advise(
            &args(&["-T5", "--min-parallelism", "255"]),
            TestIntensity::Passive,
        );
        // -T5 and --min-parallelism are both aggressive-tier flags.
        assert_eq!(advisories.len(), 2);
    }
}
