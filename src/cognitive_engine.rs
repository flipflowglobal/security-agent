//! Advanced cognitive architecture layered over [`crate::cognition`].
//!
//! Where [`crate::cognition`] produces a flat advisory assessment, this
//! module models the agent's *reasoning process itself* as a set of
//! cooperating cognitive faculties, so a reviewer can see not just the
//! conclusions but the train of thought, the shifting beliefs, and the
//! agent's own judgement about the limits of what it knows:
//!
//! - **Deliberation** ([`ReasoningChain`]) — an explicit, provenance-linked
//!   chain of thoughts (observation → inference → hypothesis →
//!   counterfactual → decision → reflection), each carrying its own
//!   confidence, so the reasoning is auditable step by step rather than
//!   delivered as an opaque verdict.
//! - **Belief revision** ([`BeliefState`]) — a normalized probability
//!   distribution over propositions that is updated with Bayes' rule as
//!   evidence (past findings) accumulates, and whose Shannon entropy
//!   quantifies how uncertain the agent currently is.
//! - **Adversary theory-of-mind** ([`AdversaryModel`]) — a model of how a
//!   rational attacker with a given objective would reason about the same
//!   targets, producing ranked predicted next moves.
//! - **Attention** ([`AttentionAllocator`]) — salience-weighted focus that
//!   decides where finite cognitive/testing resources should be spent.
//! - **Metacognition** ([`Metacognition`]) — the agent reflecting on its
//!   own confidence, naming its knowledge gaps, and deciding when a human
//!   should be escalated to.
//!
//! [`CognitiveEngine::deliberate`] runs every faculty and returns a single
//! [`CognitiveDeliberation`]. As with [`crate::cognition`], **everything
//! here is advisory**: the engine reasons over plans that
//! [`crate::policy::PolicyEngine`] has already authorized and never grants,
//! restricts, or executes anything.

use crate::calibration::CalibrationTracker;
use crate::cognition::{CognitiveMemory, generate_hypotheses};
use crate::coordinator::ExecutionPlan;
use crate::findings::Finding;
use crate::model::{Target, TargetType, Technique};
use std::fmt;

/// The cognitive role a single [`Thought`] plays in a [`ReasoningChain`].
///
/// The ordering mirrors a deliberation's natural arc — from taking in a
/// fact to reflecting on the whole — which lets a reader follow the
/// agent's train of thought at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThoughtKind {
    /// A fact taken in from the plan, targets, or memory.
    Observation,
    /// A conclusion derived from earlier thoughts.
    Inference,
    /// A tentative, falsifiable claim about a likely vulnerability.
    Hypothesis,
    /// A "what if" exploration of an alternative or omission.
    Counterfactual,
    /// A committed judgement about what to do.
    Decision,
    /// The agent reasoning about its own reasoning.
    Reflection,
}

impl fmt::Display for ThoughtKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Observation => "OBSERVE",
            Self::Inference => "INFER",
            Self::Hypothesis => "HYPOTHESIZE",
            Self::Counterfactual => "IMAGINE",
            Self::Decision => "DECIDE",
            Self::Reflection => "REFLECT",
        };
        formatter.write_str(name)
    }
}

/// One step in a chain of reasoning: a statement, the confidence the agent
/// holds in it (0–100), and the indices of the earlier thoughts it was
/// derived from (its provenance).
#[derive(Debug, Clone)]
pub struct Thought {
    pub kind: ThoughtKind,
    pub statement: String,
    pub confidence_percent: u8,
    /// Indices, within the owning [`ReasoningChain`], of the thoughts this
    /// one was derived from. Empty for a grounding observation.
    pub derived_from: Vec<usize>,
}

/// An explicit, ordered train of thought. Each thought may cite the
/// earlier thoughts it followed from, so the whole chain forms an
/// auditable reasoning graph rather than a flat list of assertions.
#[derive(Debug, Clone, Default)]
pub struct ReasoningChain {
    thoughts: Vec<Thought>,
}

impl ReasoningChain {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a thought and returns its index, so later thoughts can cite
    /// it as provenance.
    pub fn push(
        &mut self,
        kind: ThoughtKind,
        statement: impl Into<String>,
        confidence_percent: u8,
        derived_from: Vec<usize>,
    ) -> usize {
        let index = self.thoughts.len();
        self.thoughts.push(Thought {
            kind,
            statement: statement.into(),
            confidence_percent,
            derived_from,
        });
        index
    }

    #[must_use]
    pub fn thoughts(&self) -> &[Thought] {
        &self.thoughts
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.thoughts.is_empty()
    }

    /// The agent's confidence in the chain as a whole: the mean confidence
    /// of its decision thoughts, or of every thought when no decision was
    /// reached. Returns 0 for an empty chain.
    #[must_use]
    pub fn overall_confidence(&self) -> u8 {
        let decisions: Vec<u16> = self
            .thoughts
            .iter()
            .filter(|thought| thought.kind == ThoughtKind::Decision)
            .map(|thought| u16::from(thought.confidence_percent))
            .collect();
        let sample = if decisions.is_empty() {
            self.thoughts
                .iter()
                .map(|thought| u16::from(thought.confidence_percent))
                .collect::<Vec<_>>()
        } else {
            decisions
        };
        if sample.is_empty() {
            return 0;
        }
        #[allow(clippy::cast_possible_truncation)]
        let mean = (sample.iter().sum::<u16>() / sample.len() as u16) as u8;
        mean
    }
}

/// A single proposition the agent holds a degree of belief in.
#[derive(Debug, Clone)]
pub struct Belief {
    pub proposition: String,
    /// Posterior probability in `[0.0, 1.0]`.
    pub probability: f32,
}

/// A normalized probability distribution over competing propositions,
/// revised with Bayes' rule as evidence arrives.
#[derive(Debug, Clone, Default)]
pub struct BeliefState {
    beliefs: Vec<Belief>,
}

impl BeliefState {
    /// Builds a uniform prior over `propositions` (each equally likely).
    #[must_use]
    pub fn uniform(propositions: &[String]) -> Self {
        if propositions.is_empty() {
            return Self::default();
        }
        #[allow(clippy::cast_precision_loss)]
        let prior = 1.0 / propositions.len() as f32;
        Self {
            beliefs: propositions
                .iter()
                .map(|proposition| Belief {
                    proposition: proposition.clone(),
                    probability: prior,
                })
                .collect(),
        }
    }

    /// Builds a distribution from raw, non-normalized weights (e.g.
    /// per-target risk scores), normalizing them into probabilities.
    #[must_use]
    pub fn from_weights(weighted: &[(String, f32)]) -> Self {
        let total: f32 = weighted.iter().map(|(_, weight)| weight.max(0.0)).sum();
        if total <= 0.0 {
            let propositions: Vec<String> = weighted.iter().map(|(name, _)| name.clone()).collect();
            return Self::uniform(&propositions);
        }
        Self {
            beliefs: weighted
                .iter()
                .map(|(proposition, weight)| Belief {
                    proposition: proposition.clone(),
                    probability: weight.max(0.0) / total,
                })
                .collect(),
        }
    }

    /// Revises every belief with Bayes' rule given a per-proposition
    /// likelihood `P(evidence | proposition)`, then renormalizes so the
    /// posteriors sum to 1. Propositions absent from `likelihoods` keep a
    /// neutral likelihood of 1.0 (the evidence is uninformative for them).
    pub fn update(&mut self, likelihoods: &[(String, f32)]) {
        let mut unnormalized = 0.0;
        for belief in &mut self.beliefs {
            let likelihood = likelihoods
                .iter()
                .find(|(name, _)| name == &belief.proposition)
                .map_or(1.0, |(_, value)| value.max(0.0));
            belief.probability = (belief.probability * likelihood).max(0.0);
            unnormalized += belief.probability;
        }
        if unnormalized > 0.0 {
            for belief in &mut self.beliefs {
                belief.probability /= unnormalized;
            }
        }
    }

    #[must_use]
    pub fn beliefs(&self) -> &[Belief] {
        &self.beliefs
    }

    /// The most probable proposition, if any.
    #[must_use]
    pub fn most_likely(&self) -> Option<&Belief> {
        self.beliefs.iter().max_by(|a, b| {
            a.probability
                .partial_cmp(&b.probability)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Shannon entropy of the distribution in bits — a scalar measure of
    /// how uncertain the agent is. 0 means all mass is on one proposition;
    /// the maximum, `log2(n)`, means maximal uncertainty across `n`
    /// propositions.
    #[must_use]
    pub fn entropy_bits(&self) -> f32 {
        self.beliefs
            .iter()
            .filter(|belief| belief.probability > 0.0)
            .map(|belief| -belief.probability * belief.probability.log2())
            .sum()
    }

    /// Normalized uncertainty in `[0.0, 1.0]`: entropy divided by the
    /// maximum possible entropy for this many propositions. 1.0 is a
    /// perfectly uniform (maximally uncertain) distribution.
    #[must_use]
    pub fn normalized_uncertainty(&self) -> f32 {
        let count = self.beliefs.len();
        if count <= 1 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let max_entropy = (count as f32).log2();
        if max_entropy <= 0.0 {
            0.0
        } else {
            (self.entropy_bits() / max_entropy).clamp(0.0, 1.0)
        }
    }
}

/// What a modeled adversary is ultimately trying to achieve. Shapes which
/// predicted next moves the [`AdversaryModel`] weights most heavily.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdversaryObjective {
    DataExfiltration,
    ServiceDisruption,
    FinancialGain,
    Persistence,
}

impl fmt::Display for AdversaryObjective {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::DataExfiltration => "data exfiltration",
            Self::ServiceDisruption => "service disruption",
            Self::FinancialGain => "financial gain",
            Self::Persistence => "persistence",
        };
        formatter.write_str(name)
    }
}

/// A modeled attacker: how capable they are and what they want. Used to
/// reason about the engagement from the adversary's point of view.
#[derive(Debug, Clone, Copy)]
pub struct AdversaryModel {
    /// Capability level, 1 (opportunistic) – 10 (nation-state).
    pub sophistication: u8,
    pub objective: AdversaryObjective,
}

impl Default for AdversaryModel {
    fn default() -> Self {
        Self {
            sophistication: 6,
            objective: AdversaryObjective::DataExfiltration,
        }
    }
}

/// A predicted attacker action against a specific target, ranked by the
/// payoff the modeled adversary would expect from it.
#[derive(Debug, Clone)]
pub struct AdversaryMove {
    pub target_id: String,
    pub technique: Technique,
    /// Expected payoff to the adversary, higher is more attractive.
    pub expected_payoff: f32,
    pub reasoning: String,
}

impl AdversaryModel {
    /// Reasons about how this adversary would prioritize `targets`,
    /// returning their most attractive predicted moves (highest expected
    /// payoff first). Payoff rises with target criticality, with how well
    /// the target's most-likely weakness serves the adversary's objective,
    /// and with adversary sophistication.
    #[must_use]
    pub fn predict_moves(
        &self,
        targets: &[Target],
        memory: &CognitiveMemory,
    ) -> Vec<AdversaryMove> {
        let mut moves: Vec<AdversaryMove> = targets
            .iter()
            .map(|target| {
                let technique = Self::preferred_technique(&target.target_type);
                let objective_fit = self.objective_fit(&target.target_type);
                let (finding_count, average_severity) = memory.history_for(&target.id);
                let history_factor = 1.0 + (average_severity / 10.0);
                #[allow(clippy::cast_precision_loss)]
                let sophistication_factor = 0.5 + f32::from(self.sophistication) / 20.0;
                let expected_payoff = f32::from(target.criticality)
                    * objective_fit
                    * history_factor
                    * sophistication_factor;
                let reasoning = format!(
                    "a level-{} actor seeking {} would target this {} (criticality {}) via {technique}; {} prior finding(s) on record",
                    self.sophistication,
                    self.objective,
                    target.target_type,
                    target.criticality,
                    finding_count,
                );
                AdversaryMove {
                    target_id: target.id.clone(),
                    technique,
                    expected_payoff,
                    reasoning,
                }
            })
            .collect();

        moves.sort_by(|a, b| {
            b.expected_payoff
                .partial_cmp(&a.expected_payoff)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        moves
    }

    /// The single technique this adversary would most likely reach for
    /// against a given target type.
    const fn preferred_technique(target_type: &TargetType) -> Technique {
        match target_type {
            TargetType::WebApp => Technique::Dast,
            TargetType::Api | TargetType::MobileBackend => Technique::ApiSecurity,
            TargetType::MobileApp => Technique::MobileRuntime,
            TargetType::Cloud | TargetType::Infrastructure => Technique::CloudPosture,
            TargetType::Container => Technique::ContainerPosture,
            TargetType::Blockchain => Technique::AttackPathAnalysis,
            TargetType::SourceCode => Technique::Sast,
            TargetType::DependencyManifest => Technique::DependencyAudit,
        }
    }

    /// How well compromising a given target type serves this adversary's
    /// objective, as a multiplier centered on 1.0.
    const fn objective_fit(self, target_type: &TargetType) -> f32 {
        match self.objective {
            AdversaryObjective::DataExfiltration => match target_type {
                TargetType::Api | TargetType::MobileBackend | TargetType::Cloud => 1.4,
                TargetType::SourceCode => 1.2,
                _ => 1.0,
            },
            AdversaryObjective::ServiceDisruption => match target_type {
                TargetType::Infrastructure | TargetType::Container => 1.4,
                TargetType::WebApp => 1.2,
                _ => 1.0,
            },
            AdversaryObjective::FinancialGain => match target_type {
                TargetType::Blockchain => 1.6,
                TargetType::Api => 1.2,
                _ => 1.0,
            },
            AdversaryObjective::Persistence => match target_type {
                TargetType::Cloud | TargetType::Infrastructure => 1.3,
                TargetType::MobileApp => 1.1,
                _ => 1.0,
            },
        }
    }
}

/// Where the agent has chosen to direct finite testing/reasoning effort,
/// and why.
#[derive(Debug, Clone)]
pub struct AttentionFocus {
    pub target_id: String,
    /// Salience in `[0.0, 1.0]`, normalized across all foci.
    pub salience: f32,
    pub justification: String,
}

/// Allocates attention across targets by salience (criticality × known
/// history), so the most consequential, most-evidenced targets draw the
/// most focus.
pub struct AttentionAllocator;

impl AttentionAllocator {
    #[must_use]
    pub fn allocate(targets: &[Target], memory: &CognitiveMemory) -> Vec<AttentionFocus> {
        let raw: Vec<(String, f32, String)> = targets
            .iter()
            .map(|target| {
                let (finding_count, average_severity) = memory.history_for(&target.id);
                let salience = f32::from(target.criticality) * (1.0 + average_severity / 5.0);
                let justification = format!(
                    "criticality {} with {finding_count} prior finding(s) (avg severity {average_severity:.1})",
                    target.criticality,
                );
                (target.id.clone(), salience, justification)
            })
            .collect();

        let total: f32 = raw.iter().map(|(_, salience, _)| salience).sum();
        let mut foci: Vec<AttentionFocus> = raw
            .into_iter()
            .map(|(target_id, salience, justification)| AttentionFocus {
                target_id,
                salience: if total > 0.0 { salience / total } else { 0.0 },
                justification,
            })
            .collect();

        foci.sort_by(|a, b| {
            b.salience
                .partial_cmp(&a.salience)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        foci
    }
}

/// The agent's reflection on its own epistemic state: how calibrated its
/// confidence is, what it does not know, and whether a human should be
/// brought in.
#[derive(Debug, Clone)]
pub struct Metacognition {
    /// Mean confidence across the reasoning the agent just performed (0–100).
    pub self_assessed_confidence: u8,
    /// Normalized belief-state uncertainty in `[0.0, 1.0]`.
    pub uncertainty: f32,
    /// Named gaps in the agent's knowledge that bound its conclusions.
    pub knowledge_gaps: Vec<String>,
    /// Whether the agent judges that a human should review before acting.
    pub should_escalate: bool,
    /// The agent's own explanation of that judgement.
    pub reasoning: String,
}

/// The complete output of a deliberation: the train of thought plus every
/// faculty's product.
#[derive(Debug, Clone)]
pub struct CognitiveDeliberation {
    pub reasoning_chain: ReasoningChain,
    pub beliefs: BeliefState,
    pub adversary_moves: Vec<AdversaryMove>,
    pub attention: Vec<AttentionFocus>,
    pub metacognition: Metacognition,
    /// How well the agent's *prior* (type-based) predictions match the
    /// findings actually recorded in memory. Empty when there is no history
    /// to score against.
    pub calibration: CalibrationTracker,
}

/// Orchestrates the cognitive faculties into a single deliberation over an
/// authorized plan.
#[derive(Debug, Clone, Default)]
pub struct CognitiveEngine {
    pub memory: CognitiveMemory,
    pub adversary: AdversaryModel,
}

impl CognitiveEngine {
    #[must_use]
    pub const fn new(memory: CognitiveMemory, adversary: AdversaryModel) -> Self {
        Self { memory, adversary }
    }

    /// Runs a full deliberation: generates an explicit train of thought
    /// over `plan`/`targets`, forms and revises beliefs from `findings`,
    /// predicts adversary moves, allocates attention, and reflects on the
    /// whole to produce a metacognitive report.
    #[must_use]
    pub fn deliberate(
        &self,
        plan: &ExecutionPlan,
        targets: &[Target],
        findings: &[Finding],
    ) -> CognitiveDeliberation {
        let reasoning_chain = self.reason_over(plan, targets);
        let beliefs = self.form_beliefs(targets, findings);
        let adversary_moves = self.adversary.predict_moves(targets, &self.memory);
        let attention = AttentionAllocator::allocate(targets, &self.memory);
        let metacognition = self.reflect(&reasoning_chain, &beliefs, targets);
        let calibration = self.assess_calibration(targets);

        CognitiveDeliberation {
            reasoning_chain,
            beliefs,
            adversary_moves,
            attention,
            metacognition,
            calibration,
        }
    }

    /// Scores the agent's *prior* predictions against realized outcomes,
    /// without circularity: the prediction for each target is the
    /// type-based prior confidence (generated from an **empty** memory, so
    /// it is not boosted by the very history it will be judged against), and
    /// the outcome is whether that target has any finding recorded in this
    /// engine's memory. Over many targets and engagements this reveals
    /// whether the priors are over- or under-confident.
    #[must_use]
    pub fn assess_calibration(&self, targets: &[Target]) -> CalibrationTracker {
        let prior = CognitiveMemory::new();
        let mut tracker = CalibrationTracker::new();
        for target in targets {
            let predicted = generate_hypotheses(&target.id, &target.target_type, &prior)
                .first()
                .map_or(0, |hypothesis| hypothesis.confidence_percent);
            let occurred = self.memory.history_for(&target.id).0 > 0;
            tracker.record(predicted, occurred);
        }
        tracker
    }

    /// Builds the explicit train of thought: for each target, ground an
    /// observation, infer its likeliest weakness, imagine the cost of
    /// omitting the test, and decide; then reflect globally.
    fn reason_over(&self, plan: &ExecutionPlan, targets: &[Target]) -> ReasoningChain {
        let mut chain = ReasoningChain::new();

        let root = chain.push(
            ThoughtKind::Observation,
            format!(
                "engagement {} plans {} task(s) across {} target(s)",
                plan.engagement_id,
                plan.tasks.len(),
                targets.len()
            ),
            100,
            vec![],
        );

        for target in targets {
            let observation = chain.push(
                ThoughtKind::Observation,
                format!(
                    "{} is a {} of criticality {}",
                    target.id, target.target_type, target.criticality
                ),
                100,
                vec![root],
            );

            let hypotheses = generate_hypotheses(&target.id, &target.target_type, &self.memory);
            let Some(top) = hypotheses.first() else {
                continue;
            };

            let hypothesis_idx = chain.push(
                ThoughtKind::Hypothesis,
                format!(
                    "{} is most likely exposed via {} — {}",
                    target.id, top.technique, top.rationale
                ),
                top.confidence_percent,
                vec![observation],
            );

            let (finding_count, average_severity) = self.memory.history_for(&target.id);
            let inference_confidence = if finding_count > 0 {
                let inference = chain.push(
                    ThoughtKind::Inference,
                    format!(
                        "{} has {finding_count} prior finding(s) averaging {average_severity:.1} risk — recurrence is likely",
                        target.id
                    ),
                    top.confidence_percent.saturating_add(10).min(95),
                    vec![observation, hypothesis_idx],
                );
                (inference, top.confidence_percent.saturating_add(10).min(95))
            } else {
                (hypothesis_idx, top.confidence_percent)
            };

            let residual = f32::from(target.criticality) * (f32::from(top.confidence_percent) / 100.0);
            chain.push(
                ThoughtKind::Counterfactual,
                format!(
                    "if {} were skipped, an estimated {residual:.1}/10 of residual risk would go unverified on {}",
                    top.technique, target.id
                ),
                top.confidence_percent,
                vec![hypothesis_idx],
            );

            chain.push(
                ThoughtKind::Decision,
                format!("prioritize {} on {}", top.technique, target.id),
                inference_confidence.1,
                vec![inference_confidence.0],
            );
        }

        chain
    }

    /// Forms a belief distribution over "target X is the weakest link",
    /// weighted by criticality and top-hypothesis confidence, then revises
    /// it with Bayesian evidence from recorded findings.
    fn form_beliefs(&self, targets: &[Target], findings: &[Finding]) -> BeliefState {
        let weighted: Vec<(String, f32)> = targets
            .iter()
            .map(|target| {
                let hypotheses = generate_hypotheses(&target.id, &target.target_type, &self.memory);
                let top_confidence = hypotheses.first().map_or(0.0, |hypothesis| {
                    f32::from(hypothesis.confidence_percent) / 100.0
                });
                let weight = f32::from(target.criticality) * (0.5 + top_confidence);
                (format!("{} is the weakest link", target.id), weight)
            })
            .collect();

        let mut beliefs = BeliefState::from_weights(&weighted);

        if !findings.is_empty() {
            // Each recorded finding is evidence raising the likelihood that
            // its target is the weakest link.
            let mut likelihoods: Vec<(String, f32)> = Vec::new();
            for target in targets {
                let hits = findings
                    .iter()
                    .filter(|finding| finding.target_id == target.id)
                    .count();
                #[allow(clippy::cast_precision_loss)]
                let likelihood = 1.0 + hits as f32;
                likelihoods.push((format!("{} is the weakest link", target.id), likelihood));
            }
            beliefs.update(&likelihoods);
        }

        beliefs
    }

    /// Reflects on the just-completed reasoning: mean confidence, residual
    /// uncertainty, explicit knowledge gaps, and an escalation judgement.
    fn reflect(
        &self,
        chain: &ReasoningChain,
        beliefs: &BeliefState,
        targets: &[Target],
    ) -> Metacognition {
        let self_assessed_confidence = chain.overall_confidence();
        let uncertainty = beliefs.normalized_uncertainty();

        let mut knowledge_gaps = Vec::new();
        for target in targets {
            let (finding_count, _) = self.memory.history_for(&target.id);
            if finding_count == 0 && target.criticality >= 7 {
                knowledge_gaps.push(format!(
                    "{} is high-criticality ({}) but has no prior finding history — priors are type-based only",
                    target.id, target.criticality
                ));
            }
        }
        if targets.is_empty() {
            knowledge_gaps.push("no targets in scope — nothing to reason about".to_string());
        }

        // Escalate when the agent is not confident, when its beliefs are
        // near-uniform (it cannot tell targets apart), or when a
        // high-criticality target sits in a knowledge gap.
        let should_escalate =
            self_assessed_confidence < 60 || uncertainty > 0.85 || !knowledge_gaps.is_empty();

        let reasoning = if should_escalate {
            format!(
                "confidence {self_assessed_confidence}% and normalized uncertainty {uncertainty:.2}; {} knowledge gap(s) — human review recommended before acting",
                knowledge_gaps.len()
            )
        } else {
            format!(
                "confidence {self_assessed_confidence}% with normalized uncertainty {uncertainty:.2} and no material knowledge gaps — conclusions are well-supported",
            )
        };

        Metacognition {
            self_assessed_confidence,
            uncertainty,
            knowledge_gaps,
            should_escalate,
            reasoning,
        }
    }
}

impl fmt::Display for CognitiveDeliberation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Cognitive Deliberation")?;
        writeln!(formatter, "=======================")?;
        writeln!(formatter)?;

        writeln!(formatter, "Train of Thought")?;
        writeln!(formatter, "----------------")?;
        for (index, thought) in self.reasoning_chain.thoughts().iter().enumerate() {
            let provenance = if thought.derived_from.is_empty() {
                String::new()
            } else {
                format!(
                    " (from {})",
                    thought
                        .derived_from
                        .iter()
                        .map(|index| format!("#{index}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            writeln!(
                formatter,
                "#{index} [{:>11}] ({:>3}%) {}{provenance}",
                thought.kind.to_string(),
                thought.confidence_percent,
                thought.statement
            )?;
        }
        writeln!(formatter)?;

        writeln!(
            formatter,
            "Beliefs (normalized uncertainty {:.2})",
            self.beliefs.normalized_uncertainty()
        )?;
        writeln!(formatter, "--------")?;
        for belief in self.beliefs.beliefs() {
            writeln!(
                formatter,
                "  P={:.2}  {}",
                belief.probability, belief.proposition
            )?;
        }
        writeln!(formatter)?;

        writeln!(formatter, "Predicted Adversary Moves (attacker's view)")?;
        writeln!(formatter, "-------------------------------------------")?;
        for (rank, adversary_move) in self.adversary_moves.iter().enumerate() {
            writeln!(
                formatter,
                "{}. payoff={:.1} target={} via {} — {}",
                rank + 1,
                adversary_move.expected_payoff,
                adversary_move.target_id,
                adversary_move.technique,
                adversary_move.reasoning
            )?;
        }
        writeln!(formatter)?;

        writeln!(formatter, "Attention Allocation")?;
        writeln!(formatter, "--------------------")?;
        for focus in &self.attention {
            writeln!(
                formatter,
                "  {:>5.1}%  {} — {}",
                focus.salience * 100.0,
                focus.target_id,
                focus.justification
            )?;
        }
        writeln!(formatter)?;

        writeln!(formatter, "Metacognition (self-reflection)")?;
        writeln!(formatter, "-------------------------------")?;
        writeln!(
            formatter,
            "  self-assessed confidence : {}%",
            self.metacognition.self_assessed_confidence
        )?;
        writeln!(
            formatter,
            "  uncertainty              : {:.2}",
            self.metacognition.uncertainty
        )?;
        writeln!(
            formatter,
            "  escalate to human        : {}",
            if self.metacognition.should_escalate {
                "yes"
            } else {
                "no"
            }
        )?;
        if !self.metacognition.knowledge_gaps.is_empty() {
            writeln!(formatter, "  knowledge gaps:")?;
            for gap in &self.metacognition.knowledge_gaps {
                writeln!(formatter, "    - {gap}")?;
            }
        }
        writeln!(formatter, "  judgement: {}", self.metacognition.reasoning)?;
        writeln!(formatter)?;

        self.write_calibration(formatter)
    }
}

impl CognitiveDeliberation {
    /// Renders the confidence-calibration section of the deliberation.
    /// Split out of the `Display` body to keep each rendering unit small.
    fn write_calibration(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Confidence Calibration (prior vs. realized)")?;
        writeln!(formatter, "-------------------------------------------")?;
        if self.calibration.is_empty() {
            return writeln!(formatter, "  no scored predictions yet");
        }
        writeln!(formatter, "  scored predictions : {}", self.calibration.len())?;
        if let (Some(predicted), Some(empirical)) = (
            self.calibration.mean_predicted(),
            self.calibration.empirical_rate(),
        ) {
            writeln!(formatter, "  mean predicted     : {:.0}%", predicted * 100.0)?;
            writeln!(formatter, "  realized rate      : {:.0}%", empirical * 100.0)?;
        }
        if let Some(brier) = self.calibration.brier_score() {
            writeln!(formatter, "  brier score        : {brier:.3} (0 = perfect)")?;
        }
        if let Some(ece) = self.calibration.expected_calibration_error(10) {
            writeln!(formatter, "  calibration error  : {ece:.3} (0 = perfect)")?;
        }
        if let Some(tendency) = self.calibration.tendency(0.05) {
            writeln!(formatter, "  tendency           : {tendency}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::{Coordinator, ExecutionPlan};
    use crate::findings::{Finding, Severity};
    use crate::governance::Role;
    use crate::model::{
        EngagementProfile, Target, TargetType, Technique, TestIntensity, TimeWindow,
    };
    use crate::policy::PolicyEngine;
    use crate::registry::{CapabilityRegistry, ToolchainPackRegistry};

    fn finding(target_id: &str, severity: Severity) -> Finding {
        Finding {
            finding_id: "F".to_string(),
            source_tool: "semgrep".to_string(),
            title: "t".to_string(),
            target_id: target_id.to_string(),
            severity,
            confidence_percent: 90,
            remediation_playbook: "fix".to_string(),
            normalized_risk_score: 9.0,
        }
    }

    fn build_plan_and_targets() -> (ExecutionPlan, Vec<Target>) {
        let targets = vec![
            Target {
                id: "api-1".to_string(),
                target_type: TargetType::Api,
                criticality: 9,
                network_address: None,
            },
            Target {
                id: "web-1".to_string(),
                target_type: TargetType::WebApp,
                criticality: 4,
                network_address: None,
            },
        ];
        let profile = EngagementProfile {
            engagement_id: "eng-cog".to_string(),
            authorized_by: "lead".to_string(),
            authorized_by_role: Role::SecurityAdmin,
            time_window: TimeWindow {
                start_epoch_seconds: 0,
                end_epoch_seconds: 1_000_000,
            },
            in_scope_targets: vec!["api-1".to_string(), "web-1".to_string()],
            allowed_techniques: vec![
                Technique::PassiveRecon,
                Technique::ConfigurationAudit,
                Technique::ApiSecurity,
                Technique::Dast,
            ],
            deny_list_targets: vec![],
            max_intensity: TestIntensity::Standard,
            high_impact_approved: true,
            penetrative_testing_approved: true,
        };
        let mut coordinator = Coordinator::new(
            CapabilityRegistry::default(),
            ToolchainPackRegistry::default(),
            PolicyEngine::default(),
        );
        let plan = coordinator
            .plan_authorized_scan(profile, targets.clone(), 0)
            .expect("authorize");
        (plan, targets)
    }

    #[test]
    fn reasoning_chain_links_provenance_and_reaches_decisions() {
        let (plan, targets) = build_plan_and_targets();
        let engine = CognitiveEngine::default();
        let deliberation = engine.deliberate(&plan, &targets, &[]);

        let chain = &deliberation.reasoning_chain;
        assert!(!chain.is_empty());
        assert!(
            chain
                .thoughts()
                .iter()
                .any(|thought| thought.kind == ThoughtKind::Decision)
        );
        // Every non-root thought cites provenance.
        assert!(
            chain
                .thoughts()
                .iter()
                .skip(1)
                .all(|thought| !thought.derived_from.is_empty())
        );
        assert!(chain.overall_confidence() > 0);
    }

    #[test]
    fn belief_state_normalizes_and_updates_bayesian() {
        let mut beliefs =
            BeliefState::from_weights(&[("a".to_string(), 1.0), ("b".to_string(), 3.0)]);
        let sum: f32 = beliefs.beliefs().iter().map(|b| b.probability).sum();
        assert!((sum - 1.0).abs() < 1e-5);
        assert_eq!(beliefs.most_likely().unwrap().proposition, "b");

        // Strong evidence for "a" should flip the most-likely belief.
        beliefs.update(&[("a".to_string(), 10.0), ("b".to_string(), 1.0)]);
        let sum_after: f32 = beliefs.beliefs().iter().map(|b| b.probability).sum();
        assert!((sum_after - 1.0).abs() < 1e-5);
        assert_eq!(beliefs.most_likely().unwrap().proposition, "a");
    }

    #[test]
    fn entropy_is_zero_for_certainty_and_maximal_for_uniform() {
        let certain = BeliefState::from_weights(&[("a".to_string(), 1.0), ("b".to_string(), 0.0)]);
        assert!(certain.entropy_bits() < 1e-4);

        let uniform = BeliefState::uniform(&[
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ]);
        // log2(4) = 2 bits for a uniform 4-way distribution.
        assert!((uniform.entropy_bits() - 2.0).abs() < 1e-4);
        assert!((uniform.normalized_uncertainty() - 1.0).abs() < 1e-4);
    }

    #[test]
    fn adversary_ranks_high_value_objective_fit_first() {
        let (_, targets) = build_plan_and_targets();
        let model = AdversaryModel {
            sophistication: 8,
            objective: AdversaryObjective::DataExfiltration,
        };
        let moves = model.predict_moves(&targets, &CognitiveMemory::new());
        assert_eq!(moves.len(), 2);
        // api-1 (criticality 9, exfil-relevant) should outrank web-1.
        assert_eq!(moves[0].target_id, "api-1");
        assert!(moves[0].expected_payoff >= moves[1].expected_payoff);
    }

    #[test]
    fn attention_is_normalized_and_history_weighted() {
        let (_, targets) = build_plan_and_targets();
        let mut memory = CognitiveMemory::new();
        memory.record_findings(&[finding("web-1", Severity::Critical)]);

        let foci = AttentionAllocator::allocate(&targets, &memory);
        let total: f32 = foci.iter().map(|focus| focus.salience).sum();
        assert!((total - 1.0).abs() < 1e-5);
    }

    #[test]
    fn metacognition_escalates_on_high_criticality_gap() {
        let (plan, targets) = build_plan_and_targets();
        // No findings recorded → api-1 (criticality 9) is a knowledge gap.
        let engine = CognitiveEngine::default();
        let deliberation = engine.deliberate(&plan, &targets, &[]);
        assert!(deliberation.metacognition.should_escalate);
        assert!(!deliberation.metacognition.knowledge_gaps.is_empty());
    }

    #[test]
    fn deliberation_renders_all_faculties() {
        let (plan, targets) = build_plan_and_targets();
        let mut memory = CognitiveMemory::new();
        memory.record_findings(&[finding("api-1", Severity::High)]);
        let engine = CognitiveEngine::new(memory, AdversaryModel::default());
        let deliberation = engine.deliberate(&plan, &targets, &[finding("api-1", Severity::High)]);

        let rendered = deliberation.to_string();
        assert!(rendered.contains("Train of Thought"));
        assert!(rendered.contains("Predicted Adversary Moves"));
        assert!(rendered.contains("Attention Allocation"));
        assert!(rendered.contains("Metacognition"));
        assert!(rendered.contains("Confidence Calibration"));
        assert!(rendered.contains("api-1"));
    }

    #[test]
    fn calibration_is_non_circular_and_scores_priors_against_history() {
        // api-1 (criticality 9) has findings; web-1 (criticality 4) does not.
        let (_, targets) = build_plan_and_targets();
        let mut memory = CognitiveMemory::new();
        memory.record_findings(&[finding("api-1", Severity::Critical)]);
        let engine = CognitiveEngine::new(memory, AdversaryModel::default());

        let calibration = engine.assess_calibration(&targets);
        // One record per target, and the predictions are the *type-based
        // priors* — unaffected by the history they are scored against.
        assert_eq!(calibration.len(), targets.len());
        let prior = CognitiveMemory::new();
        for target in &targets {
            let prior_confidence =
                generate_hypotheses(&target.id, &target.target_type, &prior)[0].confidence_percent;
            let recorded = calibration
                .records()
                .iter()
                .find(|record| record.predicted_percent == prior_confidence);
            assert!(
                recorded.is_some(),
                "prediction must be the un-boosted prior for {}",
                target.id
            );
        }
        // Exactly the target with findings counts as an occurrence.
        let occurred = calibration
            .records()
            .iter()
            .filter(|record| record.occurred)
            .count();
        assert_eq!(occurred, 1);
    }
}
