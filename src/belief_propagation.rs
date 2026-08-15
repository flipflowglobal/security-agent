//! Belief (compromise-risk) propagation over an attack graph.
//!
//! [`crate::cognitive_engine::BeliefState`] scores each target
//! independently. Real breaches don't stay put: once an attacker
//! compromises one asset they pivot to reachable ones (lateral movement).
//! This module propagates compromise probability across a directed graph so
//! a node's risk reflects not only its own weaknesses but the weaknesses of
//! everything that can reach it.
//!
//! The update is the standard **noisy-OR**: a node is compromised if its
//! own prior fires, or if compromise spreads to it along any incoming edge.
//! For a node `v` with prior `p_v` and incoming edges `u -> v` carrying
//! transmission probability `t_uv`:
//!
//! ```text
//! P(v) = 1 - (1 - p_v) * Π_{u -> v} (1 - P(u) * t_uv)
//! ```
//!
//! Iterating this map is monotone non-decreasing and bounded by 1, so it
//! converges even on cyclic graphs (bounded iteration count as a backstop).
//! Nothing here affects authorization — it is advisory risk analysis.

use crate::findings::Finding;
use crate::model::Target;
use std::collections::HashMap;

/// A node in the propagation graph and its prior compromise probability
/// (its standalone likelihood of being compromised, before considering
/// neighbors), clamped to `[0.0, 1.0]`.
#[derive(Debug, Clone, PartialEq)]
pub struct PropagationNode {
    pub id: String,
    pub prior: f32,
}

/// A directed edge `from -> to` and the probability that compromise of
/// `from` spreads to `to`, clamped to `[0.0, 1.0]`.
#[derive(Debug, Clone, PartialEq)]
pub struct PropagationEdge {
    pub from: String,
    pub to: String,
    pub transmission: f32,
}

/// A node's prior and its propagated posterior compromise probability.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeBelief {
    pub id: String,
    pub prior: f32,
    pub posterior: f32,
}

/// A directed graph of assets with edges representing possible lateral
/// movement, over which compromise probability is propagated.
#[derive(Debug, Clone, Default)]
pub struct PropagationGraph {
    nodes: Vec<PropagationNode>,
    edges: Vec<PropagationEdge>,
}

impl PropagationGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a node, or updates its prior if the id already exists. The
    /// prior is clamped to `[0.0, 1.0]`.
    pub fn add_node(&mut self, id: impl Into<String>, prior: f32) {
        let id = id.into();
        let prior = prior.clamp(0.0, 1.0);
        if let Some(node) = self.nodes.iter_mut().find(|node| node.id == id) {
            node.prior = prior;
        } else {
            self.nodes.push(PropagationNode { id, prior });
        }
    }

    /// Adds a directed edge. Transmission is clamped to `[0.0, 1.0]`. Edges
    /// referencing ids with no corresponding node are ignored during
    /// propagation.
    pub fn add_edge(&mut self, from: impl Into<String>, to: impl Into<String>, transmission: f32) {
        self.edges.push(PropagationEdge {
            from: from.into(),
            to: to.into(),
            transmission: transmission.clamp(0.0, 1.0),
        });
    }

    #[must_use]
    pub fn nodes(&self) -> &[PropagationNode] {
        &self.nodes
    }

    #[must_use]
    pub fn edges(&self) -> &[PropagationEdge] {
        &self.edges
    }

    /// Propagates compromise probability to a fixpoint via noisy-OR,
    /// stopping when the largest per-node change drops below `epsilon` or
    /// after `max_iterations`. Returns each node's prior and posterior,
    /// highest posterior first (ties broken by id).
    ///
    /// The iteration is monotone non-decreasing and bounded by 1, so it
    /// always converges; `max_iterations` only bounds work on large or
    /// cyclic graphs.
    #[must_use]
    pub fn propagate(&self, max_iterations: usize, epsilon: f32) -> Vec<NodeBelief> {
        let count = self.nodes.len();
        if count == 0 {
            return Vec::new();
        }

        let index: HashMap<&str, usize> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, node)| (node.id.as_str(), i))
            .collect();

        let priors: Vec<f32> = self.nodes.iter().map(|node| node.prior).collect();

        // Incoming edges per node: (source index, transmission). Edges to or
        // from unknown ids are dropped.
        let mut incoming: Vec<Vec<(usize, f32)>> = vec![Vec::new(); count];
        for edge in &self.edges {
            if let (Some(&from), Some(&to)) =
                (index.get(edge.from.as_str()), index.get(edge.to.as_str()))
            {
                incoming[to].push((from, edge.transmission));
            }
        }

        let mut probability = priors.clone();
        for _ in 0..max_iterations.max(1) {
            let mut next = probability.clone();
            let mut max_delta = 0.0_f32;
            for (node_idx, sources) in incoming.iter().enumerate() {
                // Noisy-OR: start from the "not compromised by prior" mass
                // and multiply in each incoming path's "did not transmit".
                let mut not_compromised = 1.0 - priors[node_idx];
                for &(source_idx, transmission) in sources {
                    // 1 - P(source) * transmission, via a fused multiply-add.
                    not_compromised *= probability[source_idx].mul_add(-transmission, 1.0);
                }
                let updated = (1.0 - not_compromised).clamp(0.0, 1.0);
                max_delta = max_delta.max((updated - probability[node_idx]).abs());
                next[node_idx] = updated;
            }
            probability = next;
            if max_delta < epsilon {
                break;
            }
        }

        let mut beliefs: Vec<NodeBelief> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, node)| NodeBelief {
                id: node.id.clone(),
                prior: node.prior,
                posterior: probability[i],
            })
            .collect();

        beliefs.sort_by(|a, b| {
            b.posterior
                .partial_cmp(&a.posterior)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.id.cmp(&b.id))
        });
        beliefs
    }
}

/// Builds a propagation graph from an engagement's `targets` and recorded
/// `findings`, modeling an attacker who enters through targets with
/// findings and then pivots laterally between assets.
///
/// - A single `attacker` node with prior `1.0` (the threat actor is, by
///   definition, in control of their own position).
/// - One node per target with prior `0.0` — a target's compromise risk
///   comes from evidence and propagation, not an unconditional prior.
/// - An `attacker -> target` entry edge for each target that has at least
///   one finding, with transmission `entry_transmission` scaled by that
///   target's strongest finding confidence (stronger evidence ⇒ likelier
///   foothold).
/// - Lateral `target <-> target` edges (both directions) between every
///   distinct pair of targets, with transmission `lateral_transmission`,
///   modeling pivotability among co-scoped assets. This full-mesh lateral
///   assumption is deliberately conservative; a finding-free asset adjacent
///   to a compromised one therefore still shows non-zero, attenuated risk.
#[must_use]
pub fn from_targets_and_findings(
    targets: &[Target],
    findings: &[Finding],
    entry_transmission: f32,
    lateral_transmission: f32,
) -> PropagationGraph {
    let mut graph = PropagationGraph::new();
    graph.add_node("attacker", 1.0);
    for target in targets {
        graph.add_node(target.id.clone(), 0.0);
    }

    for target in targets {
        if let Some(max_confidence) = findings
            .iter()
            .filter(|finding| finding.target_id == target.id)
            .map(|finding| finding.confidence_percent)
            .max()
        {
            let evidence = f32::from(max_confidence) / 100.0;
            graph.add_edge("attacker", target.id.clone(), entry_transmission * evidence);
        }
    }

    for (i, from) in targets.iter().enumerate() {
        for to in targets.iter().skip(i + 1) {
            graph.add_edge(from.id.clone(), to.id.clone(), lateral_transmission);
            graph.add_edge(to.id.clone(), from.id.clone(), lateral_transmission);
        }
    }

    graph
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;
    use crate::model::TargetType;

    const MAX_ITERS: usize = 100;
    const EPS: f32 = 1e-6;

    fn target(id: &str) -> Target {
        Target {
            id: id.to_string(),
            target_type: TargetType::Api,
            criticality: 5,
            network_address: None,
        }
    }

    fn finding_on(target_id: &str, confidence: u8) -> Finding {
        Finding {
            finding_id: format!("{target_id}-0"),
            source_tool: "semgrep".to_string(),
            title: "x".to_string(),
            target_id: target_id.to_string(),
            severity: Severity::High,
            confidence_percent: confidence,
            remediation_playbook: "y".to_string(),
            normalized_risk_score: 8.0,
        }
    }

    fn posterior_of(beliefs: &[NodeBelief], id: &str) -> f32 {
        beliefs
            .iter()
            .find(|belief| belief.id == id)
            .unwrap()
            .posterior
    }

    #[test]
    fn empty_graph_propagates_to_nothing() {
        let graph = PropagationGraph::new();
        assert!(graph.propagate(MAX_ITERS, EPS).is_empty());
    }

    #[test]
    fn isolated_nodes_keep_their_prior() {
        let mut graph = PropagationGraph::new();
        graph.add_node("a", 0.3);
        graph.add_node("b", 0.0);
        let beliefs = graph.propagate(MAX_ITERS, EPS);
        assert!((posterior_of(&beliefs, "a") - 0.3).abs() < 1e-6);
        assert!((posterior_of(&beliefs, "b") - 0.0).abs() < 1e-6);
    }

    #[test]
    fn compromise_attenuates_along_a_chain() {
        // attacker(1.0) -> a -> b, each edge transmits at 0.5.
        let mut graph = PropagationGraph::new();
        graph.add_node("attacker", 1.0);
        graph.add_node("a", 0.0);
        graph.add_node("b", 0.0);
        graph.add_edge("attacker", "a", 0.5);
        graph.add_edge("a", "b", 0.5);

        let beliefs = graph.propagate(MAX_ITERS, EPS);
        // a = 1.0 * 0.5 = 0.5 ; b = 0.5 * 0.5 = 0.25.
        assert!((posterior_of(&beliefs, "a") - 0.5).abs() < 1e-4);
        assert!((posterior_of(&beliefs, "b") - 0.25).abs() < 1e-4);
        // Strictly attenuating away from the source.
        assert!(posterior_of(&beliefs, "a") > posterior_of(&beliefs, "b"));
    }

    #[test]
    fn noisy_or_combines_two_parents() {
        // Two source nodes at 0.5 each feed v at full transmission.
        let mut graph = PropagationGraph::new();
        graph.add_node("p1", 0.5);
        graph.add_node("p2", 0.5);
        graph.add_node("v", 0.0);
        graph.add_edge("p1", "v", 1.0);
        graph.add_edge("p2", "v", 1.0);

        let beliefs = graph.propagate(MAX_ITERS, EPS);
        // 1 - (1-0.5)(1-0.5) = 0.75.
        assert!((posterior_of(&beliefs, "v") - 0.75).abs() < 1e-4);
    }

    #[test]
    fn higher_transmission_yields_higher_posterior() {
        let build = |t: f32| {
            let mut graph = PropagationGraph::new();
            graph.add_node("attacker", 1.0);
            graph.add_node("a", 0.0);
            graph.add_edge("attacker", "a", t);
            posterior_of(&graph.propagate(MAX_ITERS, EPS), "a")
        };
        assert!(build(0.8) > build(0.3));
    }

    #[test]
    fn propagation_is_stable_after_convergence() {
        // A cycle a <-> b with an attacker feeding a; extra iterations must
        // not change the converged result.
        let mut graph = PropagationGraph::new();
        graph.add_node("attacker", 1.0);
        graph.add_node("a", 0.0);
        graph.add_node("b", 0.0);
        graph.add_edge("attacker", "a", 0.6);
        graph.add_edge("a", "b", 0.4);
        graph.add_edge("b", "a", 0.4);

        let few = graph.propagate(3, 0.0);
        let many = graph.propagate(MAX_ITERS, EPS);
        for belief in &many {
            let other = posterior_of(&few, &belief.id);
            // Monotone increasing, so more iterations never decrease risk.
            assert!(belief.posterior >= other - 1e-6);
        }
        // And a converged run equals a longer one.
        let longer = graph.propagate(MAX_ITERS * 2, EPS);
        for belief in &many {
            assert!((belief.posterior - posterior_of(&longer, &belief.id)).abs() < 1e-5);
        }
    }

    #[test]
    fn priors_and_transmissions_are_clamped() {
        let mut graph = PropagationGraph::new();
        graph.add_node("a", 5.0); // clamps to 1.0
        graph.add_node("b", -1.0); // clamps to 0.0
        graph.add_edge("a", "b", 9.0); // clamps to 1.0
        let beliefs = graph.propagate(MAX_ITERS, EPS);
        assert!((posterior_of(&beliefs, "a") - 1.0).abs() < 1e-6);
        // b fully compromised via clamped-to-1 transmission from a=1.0.
        assert!((posterior_of(&beliefs, "b") - 1.0).abs() < 1e-6);
    }

    #[test]
    fn lateral_movement_lifts_a_finding_free_neighbor() {
        // api has a finding (entry); web has none. Lateral edges let the
        // attacker pivot api -> web, so web shows non-zero, attenuated risk.
        let targets = vec![target("api"), target("web")];
        let findings = vec![finding_on("api", 90)];
        let graph = from_targets_and_findings(&targets, &findings, 0.8, 0.3);

        let beliefs = graph.propagate(MAX_ITERS, EPS);
        let api = posterior_of(&beliefs, "api");
        let web = posterior_of(&beliefs, "web");

        assert!(api > 0.0, "api has a direct foothold");
        assert!(web > 0.0, "web inherits lateral risk despite no finding");
        assert!(
            web < api,
            "lateral risk is attenuated below the entry point"
        );
        assert!(
            (posterior_of(&beliefs, "attacker") - 1.0).abs() < 1e-6,
            "attacker stays fully in control"
        );
    }

    #[test]
    fn stronger_evidence_raises_the_entry_foothold() {
        let targets = vec![target("api")];
        let weak = from_targets_and_findings(&targets, &[finding_on("api", 20)], 0.8, 0.3)
            .propagate(MAX_ITERS, EPS);
        let strong = from_targets_and_findings(&targets, &[finding_on("api", 95)], 0.8, 0.3)
            .propagate(MAX_ITERS, EPS);
        assert!(posterior_of(&strong, "api") > posterior_of(&weak, "api"));
    }
}
