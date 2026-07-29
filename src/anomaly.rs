//! Language-model surprise as an anomaly signal for the cognitive layer.
//!
//! Findings ingested from third-party tool output carry free text (titles,
//! remediation notes) that an attacker or a broken tool could stuff with
//! out-of-domain content — encoded payloads, injected markup, non-English
//! noise. The built-in language model ([`crate::language_model`]) learned
//! what ordinary security-domain English looks like, so its **perplexity**
//! on a string is a cheap, fully-local measure of how *surprising* that
//! string is. High perplexity (or a string the model cannot score at all)
//! flags text worth a human glance.
//!
//! This is advisory only — it never changes authorization or execution; it
//! feeds the cognitive review an extra "does this look normal?" lens over
//! finding text.

use crate::findings::Finding;
use crate::language_model::LanguageModel;

/// Fallback perplexity threshold for callers that have no concrete model to
/// calibrate against.
///
/// Prefer [`crate::language_model::NeuralLanguageModel::anomaly_threshold`],
/// which derives the cutoff from the model's own in-domain perplexity
/// distribution and therefore tracks corpus/tokenizer/training changes
/// without re-tuning. This constant is only the scale-tied default used when
/// a self-calibrated value is unavailable.
pub const DEFAULT_ANOMALY_THRESHOLD: f32 = 1000.0;

/// One finding's text scored for language-model surprise.
#[derive(Debug, Clone, PartialEq)]
pub struct AnomalyFlag {
    pub finding_id: String,
    pub target_id: String,
    pub text: String,
    pub perplexity: f32,
    pub anomalous: bool,
}

/// Scores each finding's title with `model` and flags the out-of-domain ones.
///
/// A finding is flagged when its perplexity is at or above `threshold`, or
/// when the model cannot score its text at all. Returns one [`AnomalyFlag`]
/// per finding, most surprising first.
#[must_use]
pub fn scan_findings(
    findings: &[Finding],
    model: &impl LanguageModel,
    threshold: f32,
) -> Vec<AnomalyFlag> {
    let mut flags: Vec<AnomalyFlag> = findings
        .iter()
        .map(|finding| {
            let perplexity = model.perplexity(&finding.title);
            AnomalyFlag {
                finding_id: finding.finding_id.clone(),
                target_id: finding.target_id.clone(),
                text: finding.title.clone(),
                perplexity,
                anomalous: !perplexity.is_finite() || perplexity >= threshold,
            }
        })
        .collect();

    flags.sort_by(|a, b| {
        b.perplexity
            .partial_cmp(&a.perplexity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    flags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;
    use crate::language_model::NeuralLanguageModel;

    fn finding(id: &str, title: &str) -> Finding {
        Finding {
            finding_id: id.to_string(),
            source_tool: "tool".to_string(),
            title: title.to_string(),
            target_id: "t".to_string(),
            severity: Severity::Medium,
            confidence_percent: 50,
            remediation_playbook: "fix".to_string(),
            normalized_risk_score: 5.0,
        }
    }

    #[test]
    fn flags_out_of_domain_text_and_spares_in_domain_text() {
        let model = NeuralLanguageModel::bundled();
        let findings = vec![
            finding("F-normal", "the policy engine denies out of scope targets"),
            finding("F-weird", "zzq xqv vfrb qwx ncbz"),
        ];
        // Exercise the self-calibrated threshold, not the fallback constant.
        let flags = scan_findings(&findings, &model, model.anomaly_threshold());

        let weird = flags.iter().find(|f| f.finding_id == "F-weird").unwrap();
        let normal = flags.iter().find(|f| f.finding_id == "F-normal").unwrap();
        assert!(weird.anomalous, "gibberish should be flagged anomalous");
        assert!(
            !normal.anomalous,
            "in-domain text should not be flagged (perplexity {})",
            normal.perplexity
        );
        // Most surprising first.
        assert_eq!(flags[0].finding_id, "F-weird");
    }

    #[test]
    fn empty_findings_produce_no_flags() {
        let model = NeuralLanguageModel::bundled();
        assert!(scan_findings(&[], &model, DEFAULT_ANOMALY_THRESHOLD).is_empty());
    }
}
