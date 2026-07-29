//! Held-out evaluation harness for the neural language model
//! (`crate::language_model`).
//!
//! The model does three jobs in production, and each one is measured here so
//! a change to the architecture, corpus, or training schedule can be proven
//! to help or caught regressing rather than judged by eye:
//!
//! 1. **Perplexity discrimination** — the anomaly detector
//!    (`crate::anomaly`) flags a finding when its text surprises the model.
//!    For that to mean anything the model must assign *lower* perplexity to
//!    coherent in-domain text than to word-salad built from the same
//!    vocabulary. We measure the mean-perplexity separation and a
//!    threshold-free ranking score (the Mann-Whitney statistic — the
//!    fraction of coherent/scrambled pairs the model orders correctly).
//! 2. **Semantic intent routing** — [`crate::nlu::interpret`] uses
//!    [`NeuralLanguageModel::embed_text`] to route plain-English
//!    instructions to a capability. We measure routing accuracy on a set of
//!    held-out paraphrases distinct from the router's own example phrasings,
//!    so the number reflects generalization, not memorization.
//! 3. **Text generation** — [`crate::language_model::LanguageModel::generate`]
//!    must be deterministic, terminate, and stay in-distribution (its own
//!    continuations should look less surprising than word-salad).
//!
//! A fourth metric, **vocabulary coverage**, records the fraction of tokens
//! in realistic finding text that the word-level vocabulary actually knows.
//! Unknown words are dropped before scoring (`encode_sentences` in
//! `crate::language_model`), so a low coverage number is a direct, honest
//! measure of the out-of-vocabulary hole the tokenizer leaves — the quantity
//! a future sub-word tokenizer is meant to move.
//!
//! Every dataset below is held out: none of these exact strings appears in
//! the training corpus or in the router's example table. The harness is
//! deterministic and dependency-free; [`evaluate`] on the bundled model
//! always yields the same report.

use crate::language_model::{LanguageModel, NeuralLanguageModel};
use crate::local_assets::LocalAgentAssets;
use crate::nlu::{self, Intent};
use std::fmt::Write as _;

/// Coherent, in-domain security sentences that are **not** in the training
/// corpus. Every content word is in-vocabulary, so perplexity reflects the
/// model's learned word order rather than vocabulary coverage.
const IN_DOMAIN_HELDOUT: &[&str] = &[
    "the scanner enumerates open ports on an authorized target",
    "a critical finding requires approval before active testing",
    "weak tls and misconfigured headers are common web findings",
    "the policy engine denies an out of scope target",
    "static analysis surfaces injection and unsafe deserialization",
    "hardcoded secrets in a mobile binary are a frequent finding",
    "lateral movement raises the risk of neighboring assets",
    "the audit ledger records every authorized action",
    "passive recon precedes active scanning on an authorized engagement",
    "belief propagation spreads compromise risk across the attack graph",
    "the specialist maps techniques to approved tools within scope",
    "rate limiting mitigates brute force against the api",
];

/// Realistic finding-title text of the kind the anomaly detector scores in
/// production: tool names, identifiers, versions, and hostnames the
/// word-level vocabulary largely does not contain. Used to measure
/// word-level vocabulary coverage, never for perplexity floors.
const REALISTIC_FINDINGS: &[&str] = &[
    "nmap detected openssh 8.2p1 on port 22",
    "sqlmap confirmed a boolean based blind injection in login.php",
    "nuclei matched cve-2021-44228 log4shell on the api host",
    "gobuster enumerated an exposed .git directory on staging",
    "jadx revealed a hardcoded firebase api key in the apk",
    "wpscan flagged an outdated woocommerce plugin version",
    "the s3 bucket acme-backups is publicly listable",
    "feroxbuster found /admin returning http 200 without auth",
];

/// Alphanumeric non-words: they survive `normalize` (so they are not blank)
/// but appear in no corpus, so every one is out-of-vocabulary. Before the
/// byte-fallback tokenizer these were silently dropped, leaving an empty
/// sentence the model could not score as surprising; with byte-fallback they
/// decompose into characters and are scored as the improbable text they are.
/// Used for the OOV-surprise metric — a direct check that anomalous,
/// unfamiliar finding text no longer slips past the detector.
const OOV_GIBBERISH: &[&str] = &[
    "xqzk vprmn blorptwig zznk qwphble",
    "jkxvmb ttghre plfwqz mbvxae nnrkdt",
    "zzqwx frbltn vmpkgh sdrlwe kxptbz",
    "wgblmr xtqvn pplzkd nnbvhc jjrwqe",
];

/// Held-out routing cases: a paraphrase and the intent it should reach. None
/// of these strings is a router example phrasing, and several deliberately use
/// inflected forms (`tool`, `anomalous`, `healthy`, `assess`) to check that
/// routing generalizes across morphology rather than memorizing exact words.
const ROUTING_CASES: &[(&str, Intent)] = &[
    ("are you online and ready to work", Intent::OfflineStatus),
    ("tell me about yourself", Intent::About),
    ("what can you help me with", Intent::Help),
    ("show me every tool you have", Intent::ListTools),
    ("which skills do you know", Intent::ListSkills),
    ("plan an authorized scan of the target", Intent::PlanScan),
    ("when should we retest this finding", Intent::ScheduleRetest),
    ("open the audit ledger", Intent::ViewAudit),
    ("continue this sentence for me", Intent::Generate),
    ("does this log line look anomalous", Intent::AnomalyCheck),
    ("what is the weather like tomorrow", Intent::OutOfScope),
    ("recommend a good pasta recipe", Intent::OutOfScope),
    // Second batch: broader paraphrases and inflected forms.
    ("check the health of the local agent", Intent::OfflineStatus),
    ("list every tool you can run", Intent::ListTools),
    ("enumerate your skills", Intent::ListSkills),
    ("describe the nmap skill", Intent::ShowSkill),
    ("assess this target for me", Intent::PlanScan),
    ("show me the audit ledger", Intent::ViewAudit),
    ("draft a note about the results", Intent::Generate),
    ("flag anything suspicious here", Intent::AnomalyCheck),
    ("open the findings database", Intent::ViewFindingsDb),
    ("view the reasoning log", Intent::ViewReasoningLogDb),
    ("book a table for two tonight", Intent::OutOfScope),
    ("how many planets are in the sky", Intent::OutOfScope),
];

/// Prompts fed to the generator when checking that its continuations stay
/// in-distribution and that decoding is deterministic. Each is a strict
/// mid-sentence prefix (never a sentence ending), so a healthy model is
/// expected to continue rather than immediately emit end-of-sentence.
const GENERATION_PROMPTS: &[&str] = &[
    "the coordinator plans an",
    "static analysis surfaces",
    "passive recon precedes active",
    "the attacker pivots from a",
];

/// Perplexity-discrimination results (anomaly-detection quality).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PerplexityEval {
    /// Mean perplexity over the coherent held-out sentences.
    pub mean_in_domain: f32,
    /// Mean perplexity over the scrambled (word-salad) counterparts.
    pub mean_scrambled: f32,
    /// `mean_scrambled / mean_in_domain`; above 1 means coherent text is
    /// scored as less surprising, which is the property the anomaly detector
    /// depends on.
    pub separation_ratio: f32,
    /// Fraction of (coherent, scrambled) pairs the model orders correctly
    /// (coherent perplexity below scrambled) — the Mann-Whitney statistic, a
    /// threshold-free stand-in for the ROC area. 1.0 is perfect separation,
    /// 0.5 is chance.
    pub ranking_auc: f32,
    /// Number of sentence pairs compared.
    pub pairs: usize,
    /// `mean_oov_gibberish_perplexity / mean_in_domain`. Out-of-vocabulary
    /// gibberish should be *more* surprising than coherent text; above 1
    /// confirms the byte-fallback tokenizer lets the detector see it at all
    /// (before byte-fallback such text was dropped and scored nothing).
    pub oov_surprise_ratio: f32,
}

/// Intent-routing results (NLU quality).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingEval {
    pub total: usize,
    pub correct: usize,
}

impl RoutingEval {
    /// Routing accuracy in `[0, 1]`.
    #[must_use]
    pub fn accuracy(self) -> f32 {
        if self.total == 0 {
            return 0.0;
        }
        count(self.correct) / count(self.total)
    }
}

/// Text-generation results.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GenerationEval {
    /// The same prompt decoded twice produced identical text for every
    /// prompt — the determinism guarantee decoding is documented to give.
    pub deterministic: bool,
    /// Every prompt produced a bounded, non-empty continuation.
    pub terminates: bool,
    /// Mean perplexity of the model's own continuations.
    pub mean_continuation_perplexity: f32,
    /// Mean perplexity of scrambled security text, as an out-of-distribution
    /// baseline for the continuations.
    pub mean_baseline_perplexity: f32,
    /// The model's continuations are less surprising than the scrambled
    /// baseline — evidence generation stays on the training distribution.
    pub in_distribution: bool,
}

/// Vocabulary-coverage results: the *word-level* hit rate, distinct from the
/// byte-level representability the fallback tokenizer now guarantees for all
/// input.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CoverageEval {
    /// Fraction of coherent held-out words known as whole-word tokens
    /// (expected high).
    pub in_domain_coverage: f32,
    /// Fraction of realistic finding words known as whole-word tokens
    /// (expected low — the residual gap a sub-word merge step, not just
    /// character fallback, would close). Byte-fallback already makes these
    /// words *representable*; this measures how many are first-class tokens.
    pub realistic_coverage: f32,
}

/// The full held-out evaluation of the neural language model.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LmEvalReport {
    pub perplexity: PerplexityEval,
    pub routing: RoutingEval,
    pub generation: GenerationEval,
    pub coverage: CoverageEval,
}

/// Minimum acceptable quality floors.
///
/// [`LmEvalReport::passes`] checks the report against these; the regression
/// tests assert them, so a change that makes the model worse on any
/// production job fails CI. Coverage is deliberately *not* gated — it is a
/// diagnostic that today reads low by design and is expected to rise only
/// when the tokenizer changes.
pub mod floors {
    /// Coherent text must be at least this much less perplexing than its
    /// scrambled counterpart, on average.
    pub const MIN_SEPARATION_RATIO: f32 = 1.05;
    /// Pairwise ranking must beat this. 0.5 is chance.
    pub const MIN_RANKING_AUC: f32 = 0.70;
    /// Held-out routing accuracy floor.
    ///
    /// The router clears all 24 held-out paraphrases after the L4
    /// morphology/scope fixes; the floor sits below that with headroom so the
    /// gate passes reliably yet still fails on a multi-case regression
    /// (21/24 = 0.875 < floor).
    pub const MIN_ROUTING_ACCURACY: f32 = 0.90;
    /// Out-of-vocabulary gibberish must be at least this many times as
    /// perplexing as coherent in-domain text.
    ///
    /// This is the byte-fallback tokenizer's guarantee that unfamiliar finding
    /// text is scored as surprising rather than silently dropped.
    pub const MIN_OOV_SURPRISE_RATIO: f32 = 1.50;
}

impl LmEvalReport {
    /// Whether the report clears every gated quality floor (see [`floors`]).
    /// Generation must be deterministic and in-distribution; the perplexity
    /// and routing metrics must clear their minimums.
    #[must_use]
    pub fn passes(&self) -> bool {
        self.generation.deterministic
            && self.generation.terminates
            && self.generation.in_distribution
            && self.perplexity.separation_ratio >= floors::MIN_SEPARATION_RATIO
            && self.perplexity.ranking_auc >= floors::MIN_RANKING_AUC
            && self.perplexity.oov_surprise_ratio >= floors::MIN_OOV_SURPRISE_RATIO
            && self.routing.accuracy() >= floors::MIN_ROUTING_ACCURACY
    }

    /// A multi-line, human-readable summary for the `--lm-eval` CLI command.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut out = String::new();
        out.push_str("Neural Language Model — Held-Out Evaluation\n");
        out.push_str("===========================================\n\n");

        out.push_str("Perplexity discrimination (anomaly detection)\n");
        push_metric(
            &mut out,
            "  mean perplexity, in-domain",
            self.perplexity.mean_in_domain,
            None,
        );
        push_metric(
            &mut out,
            "  mean perplexity, scrambled",
            self.perplexity.mean_scrambled,
            None,
        );
        push_metric(
            &mut out,
            "  separation ratio",
            self.perplexity.separation_ratio,
            Some(floors::MIN_SEPARATION_RATIO),
        );
        push_metric(
            &mut out,
            "  ranking AUC",
            self.perplexity.ranking_auc,
            Some(floors::MIN_RANKING_AUC),
        );
        push_metric(
            &mut out,
            "  OOV-surprise ratio",
            self.perplexity.oov_surprise_ratio,
            Some(floors::MIN_OOV_SURPRISE_RATIO),
        );

        out.push_str("\nIntent routing (NLU)\n");
        push_metric(
            &mut out,
            "  accuracy",
            self.routing.accuracy(),
            Some(floors::MIN_ROUTING_ACCURACY),
        );
        let _ = writeln!(
            out,
            "    {} of {} held-out paraphrases routed correctly",
            self.routing.correct, self.routing.total
        );

        out.push_str("\nGeneration\n");
        push_flag(&mut out, "  deterministic", self.generation.deterministic);
        push_flag(&mut out, "  terminates", self.generation.terminates);
        push_flag(
            &mut out,
            "  in-distribution",
            self.generation.in_distribution,
        );
        push_metric(
            &mut out,
            "  continuation perplexity",
            self.generation.mean_continuation_perplexity,
            None,
        );
        push_metric(
            &mut out,
            "  baseline perplexity",
            self.generation.mean_baseline_perplexity,
            None,
        );

        out.push_str("\nWord-level vocabulary coverage (diagnostic, not gated)\n");
        push_metric(
            &mut out,
            "  in-domain word coverage",
            self.coverage.in_domain_coverage,
            None,
        );
        push_metric(
            &mut out,
            "  realistic-finding word coverage",
            self.coverage.realistic_coverage,
            None,
        );

        let _ = writeln!(
            out,
            "\nOverall: {}",
            if self.passes() { "PASS" } else { "FAIL" }
        );
        out
    }
}

/// Runs the full held-out evaluation against `model`, using `assets` for the
/// intent router. Deterministic for a given model.
#[must_use]
pub fn evaluate(assets: &LocalAgentAssets, model: &NeuralLanguageModel) -> LmEvalReport {
    LmEvalReport {
        perplexity: evaluate_perplexity(model),
        routing: evaluate_routing(assets, model),
        generation: evaluate_generation(model),
        coverage: evaluate_coverage(model),
    }
}

fn evaluate_perplexity(model: &NeuralLanguageModel) -> PerplexityEval {
    let in_domain: Vec<f32> = IN_DOMAIN_HELDOUT
        .iter()
        .map(|s| model.perplexity(s))
        .filter(|p| p.is_finite())
        .collect();
    let scrambled: Vec<f32> = IN_DOMAIN_HELDOUT
        .iter()
        .map(|s| model.perplexity(&scramble(s)))
        .filter(|p| p.is_finite())
        .collect();

    let mean_in_domain = mean(&in_domain);
    let mean_scrambled = mean(&scrambled);
    let separation_ratio = if mean_in_domain > 0.0 {
        mean_scrambled / mean_in_domain
    } else {
        0.0
    };

    // Mann-Whitney: over every (coherent, scrambled) pair, the fraction where
    // the coherent sentence is the less surprising of the two. Ties count as
    // a half, matching the standard AUC convention.
    let mut correct = 0.0_f32;
    let mut pairs = 0usize;
    for &good in &in_domain {
        for &bad in &scrambled {
            pairs += 1;
            if good < bad {
                correct += 1.0;
            } else if (good - bad).abs() <= f32::EPSILON {
                correct += 0.5;
            }
        }
    }
    let ranking_auc = if pairs > 0 {
        correct / count(pairs)
    } else {
        0.0
    };

    let oov_gibberish: Vec<f32> = OOV_GIBBERISH
        .iter()
        .map(|s| model.perplexity(s))
        .filter(|p| p.is_finite())
        .collect();
    let mean_oov = mean(&oov_gibberish);
    let oov_surprise_ratio = if mean_in_domain > 0.0 {
        mean_oov / mean_in_domain
    } else {
        0.0
    };

    PerplexityEval {
        mean_in_domain,
        mean_scrambled,
        separation_ratio,
        ranking_auc,
        pairs,
        oov_surprise_ratio,
    }
}

fn evaluate_routing(assets: &LocalAgentAssets, model: &NeuralLanguageModel) -> RoutingEval {
    let mut correct = 0;
    for &(instruction, expected) in ROUTING_CASES {
        if nlu::interpret(instruction, assets, model).intent == expected {
            correct += 1;
        }
    }
    RoutingEval {
        total: ROUTING_CASES.len(),
        correct,
    }
}

fn evaluate_generation(model: &NeuralLanguageModel) -> GenerationEval {
    let mut deterministic = true;
    let mut terminates = true;
    let mut continuation_ppls = Vec::new();

    for &prompt in GENERATION_PROMPTS {
        let first = model.generate(prompt, 24);
        let second = model.generate(prompt, 24);
        if first != second {
            deterministic = false;
        }
        if first.is_empty() {
            terminates = false;
        }
        // Score the full prompt+continuation the way production text is
        // scored, so a continuation that derails is penalized.
        let ppl = model.perplexity(&format!("{prompt} {first}"));
        if ppl.is_finite() {
            continuation_ppls.push(ppl);
        }
    }

    let baseline_ppls: Vec<f32> = IN_DOMAIN_HELDOUT
        .iter()
        .map(|s| model.perplexity(&scramble(s)))
        .filter(|p| p.is_finite())
        .collect();

    let mean_continuation_perplexity = mean(&continuation_ppls);
    let mean_baseline_perplexity = mean(&baseline_ppls);
    let in_distribution = mean_continuation_perplexity > 0.0
        && mean_continuation_perplexity < mean_baseline_perplexity;

    GenerationEval {
        deterministic,
        terminates,
        mean_continuation_perplexity,
        mean_baseline_perplexity,
        in_distribution,
    }
}

fn evaluate_coverage(model: &NeuralLanguageModel) -> CoverageEval {
    CoverageEval {
        in_domain_coverage: mean_coverage(model, IN_DOMAIN_HELDOUT),
        realistic_coverage: mean_coverage(model, REALISTIC_FINDINGS),
    }
}

/// Mean word-level coverage over `texts`: the fraction of words the model
/// knows as first-class whole-word tokens (`knows_word`). This is distinct
/// from representability — byte-fallback makes every word representable — and
/// is the honest measure of how much realistic finding text still relies on
/// character fallback rather than dedicated tokens.
fn mean_coverage(model: &NeuralLanguageModel, texts: &[&str]) -> f32 {
    let mut covered = 0usize;
    let mut total = 0usize;
    for text in texts {
        for word in text.split_whitespace() {
            total += 1;
            if model.knows_word(word) {
                covered += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        count(covered) / count(total)
    }
}

/// Deterministically shuffles the words of `sentence` into an order the
/// language does not license, keeping the exact same multiset of tokens (so
/// any perplexity difference is due to order, not vocabulary). A fixed-seed
/// splitmix64 Fisher-Yates keeps the result reproducible and independent of
/// the model's internal RNG. Sentences of length two are reversed (the only
/// derangement available); length zero or one are returned unchanged.
fn scramble(sentence: &str) -> String {
    let mut words: Vec<&str> = sentence.split_whitespace().collect();
    let n = words.len();
    if n < 2 {
        return sentence.to_string();
    }

    let mut state = 0x9E37_79B9_7F4A_7C15_u64 ^ (n as u64);
    for i in (1..n).rev() {
        state = splitmix64(state);
        // `state % (i + 1)` is at most `i < n`, so it always fits a `usize`.
        let j = usize::try_from(state % (i as u64 + 1)).unwrap_or(0);
        words.swap(i, j);
    }
    // Guarantee a genuine reordering: if the shuffle happened to reproduce
    // the original (possible for short inputs), rotate by one so the salad is
    // never accidentally the coherent sentence.
    if words.iter().copied().eq(sentence.split_whitespace()) {
        words.rotate_left(1);
    }
    words.join(" ")
}

const fn splitmix64(state: u64) -> u64 {
    let mut z = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn mean(values: &[f32]) -> f32 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f32>() / count(values.len())
}

/// `usize`-to-`f32` count conversion, isolated so the precision-loss lint is
/// acknowledged in exactly one place; the magnitudes here (dataset sizes) are
/// far below `f32`'s integer-exact range.
#[allow(clippy::cast_precision_loss)]
const fn count(n: usize) -> f32 {
    n as f32
}

fn push_metric(out: &mut String, label: &str, value: f32, floor: Option<f32>) {
    match floor {
        Some(min) => {
            let mark = if value >= min { "ok" } else { "LOW" };
            let _ = writeln!(out, "{label}: {value:.3}  (floor {min:.3}) [{mark}]");
        }
        None => {
            let _ = writeln!(out, "{label}: {value:.3}");
        }
    }
}

fn push_flag(out: &mut String, label: &str, value: bool) {
    let _ = writeln!(out, "{label}: {}", if value { "yes" } else { "NO" });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> LmEvalReport {
        evaluate(
            &LocalAgentAssets::bundled(),
            &NeuralLanguageModel::bundled(),
        )
    }

    #[test]
    fn evaluation_is_deterministic() {
        assert_eq!(
            report(),
            report(),
            "held-out evaluation must be reproducible"
        );
    }

    #[test]
    fn perplexity_separates_coherent_from_scrambled_text() {
        let p = report().perplexity;
        assert!(
            p.separation_ratio >= floors::MIN_SEPARATION_RATIO,
            "coherent text should be less perplexing than word-salad: ratio {:.3} < floor {:.3} (in-domain {:.2}, scrambled {:.2})",
            p.separation_ratio,
            floors::MIN_SEPARATION_RATIO,
            p.mean_in_domain,
            p.mean_scrambled,
        );
        assert!(
            p.ranking_auc >= floors::MIN_RANKING_AUC,
            "pairwise ranking {:.3} below floor {:.3}",
            p.ranking_auc,
            floors::MIN_RANKING_AUC,
        );
    }

    #[test]
    fn oov_gibberish_is_scored_as_surprising() {
        // The byte-fallback tokenizer's headline guarantee: out-of-vocabulary
        // text is decomposed into characters and scored as surprising rather
        // than dropped. Before byte-fallback these strings reduced to empty
        // sentences and could not be flagged at all.
        let p = report().perplexity;
        assert!(
            p.oov_surprise_ratio >= floors::MIN_OOV_SURPRISE_RATIO,
            "OOV gibberish should be far more perplexing than in-domain text: ratio {:.3} < floor {:.3}",
            p.oov_surprise_ratio,
            floors::MIN_OOV_SURPRISE_RATIO,
        );
    }

    #[test]
    fn byte_fallback_leaves_no_word_unrepresented() {
        // Every realistic finding word — including tool names, versions, and
        // identifiers absent from the vocabulary — must produce a nonzero
        // embedding, proving nothing is silently dropped.
        let model = NeuralLanguageModel::bundled();
        for text in REALISTIC_FINDINGS {
            for word in text.split_whitespace() {
                let embedding = model.embed_text(word);
                assert!(
                    embedding.iter().any(|v| *v != 0.0),
                    "word '{word}' produced a zero embedding — byte-fallback dropped it",
                );
            }
        }
    }

    #[test]
    fn routing_meets_accuracy_floor_on_held_out_paraphrases() {
        let r = report().routing;
        assert!(
            r.accuracy() >= floors::MIN_ROUTING_ACCURACY,
            "held-out routing accuracy {:.3} below floor {:.3} ({}/{})",
            r.accuracy(),
            floors::MIN_ROUTING_ACCURACY,
            r.correct,
            r.total,
        );
    }

    #[test]
    fn generation_is_deterministic_and_in_distribution() {
        let g = report().generation;
        assert!(g.deterministic, "decoding must be reproducible");
        assert!(
            g.terminates,
            "every prompt must yield a bounded continuation"
        );
        assert!(
            g.in_distribution,
            "continuations ({:.2}) should be less perplexing than scrambled baseline ({:.2})",
            g.mean_continuation_perplexity, g.mean_baseline_perplexity,
        );
    }

    #[test]
    fn overall_report_passes_all_gated_floors() {
        assert!(report().passes(), "\n{}", report().summary());
    }

    #[test]
    fn word_level_coverage_gap_motivates_subword_merges() {
        // Not a quality gate — a recorded observation that in-domain text is
        // well covered at the whole-word level while realistic finding text
        // is not. Byte-fallback already makes every word representable (see
        // `byte_fallback_leaves_no_word_unrepresented`); the residual gap
        // here is what a sub-word merge step, not just character fallback,
        // would close. Revise upward if such a step lands.
        let c = report().coverage;
        assert!(
            c.in_domain_coverage > c.realistic_coverage,
            "in-domain word coverage ({:.3}) should exceed realistic word coverage ({:.3})",
            c.in_domain_coverage,
            c.realistic_coverage,
        );
    }

    #[test]
    fn scramble_preserves_the_token_multiset() {
        let sentence = "the scanner enumerates open ports on a target";
        let mut original: Vec<&str> = sentence.split_whitespace().collect();
        let salad = scramble(sentence);
        let mut shuffled: Vec<&str> = salad.split_whitespace().collect();
        original.sort_unstable();
        shuffled.sort_unstable();
        assert_eq!(
            original, shuffled,
            "scramble must only reorder, never add or drop"
        );
        assert_ne!(salad, sentence, "scramble must actually reorder");
    }

    #[test]
    fn scramble_is_stable_for_short_inputs() {
        assert_eq!(scramble(""), "");
        assert_eq!(scramble("token"), "token");
        assert_eq!(scramble("two words"), "words two");
    }
}
