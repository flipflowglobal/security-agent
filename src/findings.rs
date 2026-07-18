#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub finding_id: String,
    pub source_tool: String,
    pub title: String,
    pub target_id: String,
    pub severity: Severity,
    pub confidence_percent: u8,
    pub remediation_playbook: String,
    pub normalized_risk_score: f32,
}

pub struct RiskScoreCalculator;

impl RiskScoreCalculator {
    pub fn normalized_score(
        severity: Severity,
        confidence_percent: u8,
        exploitability_validated: bool,
    ) -> f32 {
        let severity_weight = match severity {
            Severity::Critical => 10.0,
            Severity::High => 8.0,
            Severity::Medium => 5.0,
            Severity::Low => 2.5,
            Severity::Informational => 1.0,
        };
        let confidence_factor = (confidence_percent.min(100) as f32) / 100.0;
        let exploitability_factor = if exploitability_validated { 1.15 } else { 1.0 };
        (severity_weight * confidence_factor * exploitability_factor).min(10.0)
    }
}
