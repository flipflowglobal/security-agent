use crate::findings::Finding;

#[derive(Debug, Clone)]
pub struct ThreatModelNode {
    pub node_id: String,
    pub role: String,
    pub trust_zone: String,
}

#[derive(Debug, Clone)]
pub struct AttackPathEdge {
    pub from: String,
    pub to: String,
    pub technique: String,
}

#[derive(Debug, Clone, Default)]
pub struct AttackPathGraph {
    pub nodes: Vec<ThreatModelNode>,
    pub edges: Vec<AttackPathEdge>,
}

impl AttackPathGraph {
    /// Populate the graph by creating a node per unique target in `findings`
    /// and an edge for each finding connecting the attacker entry point to the
    /// affected target via the source tool that identified it.
    pub fn build_from_findings(findings: &[Finding]) -> Self {
        let mut graph = AttackPathGraph::default();

        // Single attacker entry-point node.
        graph.nodes.push(ThreatModelNode {
            node_id: "attacker".to_string(),
            role: "Threat Actor".to_string(),
            trust_zone: "untrusted".to_string(),
        });

        let mut seen_targets = std::collections::HashSet::new();

        for finding in findings {
            if seen_targets.insert(finding.target_id.clone()) {
                graph.nodes.push(ThreatModelNode {
                    node_id: finding.target_id.clone(),
                    role: "Target Asset".to_string(),
                    trust_zone: "internal".to_string(),
                });
            }

            graph.edges.push(AttackPathEdge {
                from: "attacker".to_string(),
                to: finding.target_id.clone(),
                technique: finding.source_tool.clone(),
            });
        }

        graph
    }
}

#[derive(Debug, Clone)]
pub struct RetestSchedule {
    pub target_id: String,
    pub next_retest_epoch_seconds: u64,
    pub reason: String,
}

pub fn propose_retest_schedule(finding: &Finding, now_epoch_seconds: u64) -> RetestSchedule {
    let offset = if finding.normalized_risk_score >= 8.0 {
        60 * 60 * 24
    } else if finding.normalized_risk_score >= 5.0 {
        60 * 60 * 24 * 3
    } else {
        60 * 60 * 24 * 7
    };
    RetestSchedule {
        target_id: finding.target_id.clone(),
        next_retest_epoch_seconds: now_epoch_seconds + offset,
        reason: "drift-and-risk-based-retest".to_string(),
    }
}
