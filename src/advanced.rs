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
