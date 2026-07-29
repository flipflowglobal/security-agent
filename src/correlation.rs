//! Findings deduplication and cross-tool correlation (Stage-4 territory).
//!
//! Running many tools against the same target surfaces the same issue more
//! than once — two scanners both flag a missing security header, or the same
//! CVE shows up from a version check and an active probe. Reported raw, that
//! is noise. [`correlate`] collapses findings that share a normalized
//! identity (the same target and the same title, case- and
//! whitespace-insensitive) into one, and treats independent corroboration as
//! signal: when two or more *distinct* tools report the same issue,
//! confidence is raised and the risk score recomputed. The result is
//! deterministic — ordered by descending risk, then finding id — so the same
//! inputs always produce the same correlated view.

use crate::findings::{Finding, RiskScoreCalculator, Severity};
use std::collections::BTreeSet;

/// Collapses duplicate and corroborating findings into a deduplicated,
/// correlated set.
///
/// Findings are grouped by `(target_id, normalized title)`. Each group keeps
/// the highest severity seen, the representative (lowest finding id) title
/// and remediation, and the union of source tools. Confidence starts at the
/// group's highest and gains a bounded boost for each additional distinct
/// corroborating tool; the normalized risk score is recomputed from the
/// merged severity and confidence.
#[must_use]
pub fn correlate(findings: &[Finding]) -> Vec<Finding> {
    let mut groups: Vec<Group> = Vec::new();

    for finding in findings {
        let key = (finding.target_id.clone(), normalize_title(&finding.title));
        if let Some(group) = groups.iter_mut().find(|group| group.key == key) {
            group.absorb(finding);
        } else {
            groups.push(Group::new(key, finding));
        }
    }

    let mut correlated: Vec<Finding> = groups.iter().map(Group::to_finding).collect();
    correlated.sort_by(|a, b| {
        b.normalized_risk_score
            .partial_cmp(&a.normalized_risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.finding_id.cmp(&b.finding_id))
    });
    correlated
}

/// One correlation group: findings sharing a target and normalized title.
struct Group {
    key: (String, String),
    severity: Severity,
    max_confidence: u8,
    tools: BTreeSet<String>,
    representative_id: String,
    title: String,
    remediation: String,
}

impl Group {
    fn new(key: (String, String), finding: &Finding) -> Self {
        let mut tools = BTreeSet::new();
        tools.insert(finding.source_tool.clone());
        Self {
            key,
            severity: finding.severity,
            max_confidence: finding.confidence_percent,
            tools,
            representative_id: finding.finding_id.clone(),
            title: finding.title.clone(),
            remediation: finding.remediation_playbook.clone(),
        }
    }

    fn absorb(&mut self, finding: &Finding) {
        if severity_rank(finding.severity) > severity_rank(self.severity) {
            self.severity = finding.severity;
        }
        self.max_confidence = self.max_confidence.max(finding.confidence_percent);
        self.tools.insert(finding.source_tool.clone());
        // The lowest finding id is the stable representative for title,
        // remediation, and the merged finding's own id.
        if finding.finding_id < self.representative_id {
            self.representative_id.clone_from(&finding.finding_id);
            self.title.clone_from(&finding.title);
            self.remediation.clone_from(&finding.remediation_playbook);
        }
    }

    fn to_finding(&self) -> Finding {
        let distinct = self.tools.len();
        let boost = 8 * distinct.saturating_sub(1);
        let confidence =
            u8::try_from((usize::from(self.max_confidence) + boost).min(100)).unwrap_or(100);
        let corroborated = distinct >= 2;
        Finding {
            finding_id: self.representative_id.clone(),
            source_tool: self.tools.iter().cloned().collect::<Vec<_>>().join("+"),
            title: self.title.clone(),
            target_id: self.key.0.clone(),
            severity: self.severity,
            confidence_percent: confidence,
            normalized_risk_score: RiskScoreCalculator::normalized_score(
                self.severity,
                confidence,
                corroborated,
            ),
            remediation_playbook: self.remediation.clone(),
        }
    }
}

/// Case- and whitespace-insensitive title key for grouping.
fn normalize_title(title: &str) -> String {
    title
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

/// Orders severities most-severe first for the merge.
const fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Informational => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(
        id: &str,
        tool: &str,
        target: &str,
        title: &str,
        sev: Severity,
        conf: u8,
    ) -> Finding {
        Finding {
            finding_id: id.to_string(),
            source_tool: tool.to_string(),
            title: title.to_string(),
            target_id: target.to_string(),
            severity: sev,
            confidence_percent: conf,
            normalized_risk_score: RiskScoreCalculator::normalized_score(sev, conf, false),
            remediation_playbook: "fix it".to_string(),
        }
    }

    #[test]
    fn duplicate_same_tool_collapses_without_extra_boost() {
        let input = vec![
            finding(
                "a-1",
                "nuclei",
                "t1",
                "Missing HSTS header",
                Severity::Medium,
                60,
            ),
            finding(
                "a-2",
                "nuclei",
                "t1",
                "missing   hsts   HEADER",
                Severity::Medium,
                70,
            ),
        ];
        let out = correlate(&input);
        assert_eq!(out.len(), 1);
        // Same single tool -> no corroboration boost; confidence is the max.
        assert_eq!(out[0].confidence_percent, 70);
        assert_eq!(out[0].source_tool, "nuclei");
    }

    #[test]
    fn cross_tool_corroboration_raises_confidence_and_keeps_max_severity() {
        let input = vec![
            finding("a-2", "nuclei", "t1", "SQL injection", Severity::High, 70),
            finding(
                "a-1",
                "sqlmap",
                "t1",
                "sql injection",
                Severity::Critical,
                60,
            ),
        ];
        let out = correlate(&input);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Critical);
        // Two distinct tools -> +8 over the max confidence (70).
        assert_eq!(out[0].confidence_percent, 78);
        assert_eq!(out[0].source_tool, "nuclei+sqlmap");
        // Representative id is the lexicographically smallest.
        assert_eq!(out[0].finding_id, "a-1");
    }

    #[test]
    fn distinct_issues_are_preserved_and_ordered_by_risk() {
        let input = vec![
            finding("a", "nuclei", "t1", "Info leak", Severity::Low, 50),
            finding("b", "nuclei", "t1", "RCE", Severity::Critical, 90),
        ];
        let out = correlate(&input);
        assert_eq!(out.len(), 2);
        // Highest risk first.
        assert_eq!(out[0].title, "RCE");
    }

    #[test]
    fn same_title_different_targets_not_merged() {
        let input = vec![
            finding("a", "nuclei", "t1", "Open redirect", Severity::Medium, 60),
            finding("b", "nuclei", "t2", "Open redirect", Severity::Medium, 60),
        ];
        assert_eq!(correlate(&input).len(), 2);
    }

    #[test]
    fn empty_input_yields_empty() {
        assert!(correlate(&[]).is_empty());
    }
}
