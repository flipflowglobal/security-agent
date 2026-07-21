#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Informational => "Informational",
        };
        formatter.write_str(name)
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Critical" => Ok(Self::Critical),
            "High" => Ok(Self::High),
            "Medium" => Ok(Self::Medium),
            "Low" => Ok(Self::Low),
            "Informational" => Ok(Self::Informational),
            other => Err(format!("unknown severity: {other}")),
        }
    }
}

/// Maps a third-party tool's own severity/level vocabulary onto this
/// crate's [`Severity`] scale. Covers the common vocabularies seen in
/// tool-emitted JSON: `critical`/`high`/`medium`/`low`/`info`(`rmational`),
/// SARIF's `error`/`warning`/`note`, and semgrep's `ERROR`/`WARNING`/`INFO`
/// (case-insensitively). An unrecognized label maps to
/// [`Severity::Informational`] rather than failing — ingesting untrusted
/// tool output should fail safe toward low noise, never panic or reject
/// the whole report over one unfamiliar label.
#[must_use]
pub(crate) fn severity_from_label(label: &str) -> Severity {
    match label.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" | "error" => Severity::High,
        "medium" | "warning" | "moderate" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Informational,
    }
}

#[derive(Debug, Clone, PartialEq)]
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
    #[must_use]
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
        let confidence_factor = f32::from(confidence_percent.min(100)) / 100.0;
        let exploitability_factor = if exploitability_validated { 1.15 } else { 1.0 };
        (severity_weight * confidence_factor * exploitability_factor).min(10.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_display_and_from_str_round_trip() {
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Informational,
        ] {
            assert_eq!(severity.to_string().parse(), Ok(severity));
        }
        assert!("nonexistent".parse::<Severity>().is_err());
    }

    #[test]
    fn severity_from_label_maps_common_vocabularies() {
        assert_eq!(severity_from_label("critical"), Severity::Critical);
        assert_eq!(severity_from_label("CRITICAL"), Severity::Critical);
        assert_eq!(severity_from_label("high"), Severity::High);
        assert_eq!(severity_from_label("ERROR"), Severity::High);
        assert_eq!(severity_from_label("medium"), Severity::Medium);
        assert_eq!(severity_from_label("WARNING"), Severity::Medium);
        assert_eq!(severity_from_label("low"), Severity::Low);
        assert_eq!(severity_from_label("INFO"), Severity::Informational);
        assert_eq!(severity_from_label("note"), Severity::Informational);
    }

    #[test]
    fn severity_from_label_fails_safe_for_unknown_labels() {
        assert_eq!(
            severity_from_label("totally-unknown"),
            Severity::Informational
        );
        assert_eq!(severity_from_label(""), Severity::Informational);
    }
}
