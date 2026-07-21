use crate::coordinator::ExecutionPlan;
use crate::findings::{Finding, Severity};
use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone)]
pub struct CompatibilityEnvelope {
    pub protocol_version: String,
    pub producer: String,
    pub payload_kind: String,
    pub fields: BTreeMap<String, String>,
}

impl CompatibilityEnvelope {
    #[must_use]
    pub fn to_wire_format(&self) -> String {
        let mut out = format!(
            "version={}\nproducer={}\nkind={}\n",
            self.protocol_version, self.producer, self.payload_kind
        );
        for (k, v) in &self.fields {
            let _ = writeln!(out, "{k}={v}");
        }
        out
    }
}

pub trait IntegrationAdapter {
    fn name(&self) -> &'static str;
    fn export_execution_plan(&self, plan: &ExecutionPlan) -> CompatibilityEnvelope;
    fn import_finding_hint(&self, envelope: &CompatibilityEnvelope) -> Option<Finding>;
}

#[derive(Debug, Default, Clone)]
pub struct JsonLineAdapter;

impl IntegrationAdapter for JsonLineAdapter {
    fn name(&self) -> &'static str {
        "json-line-adapter"
    }

    fn export_execution_plan(&self, plan: &ExecutionPlan) -> CompatibilityEnvelope {
        let mut fields = BTreeMap::new();
        fields.insert("engagement_id".to_string(), plan.engagement_id.clone());
        fields.insert("task_count".to_string(), plan.tasks.len().to_string());
        fields.insert(
            "high_impact_tasks".to_string(),
            plan.high_impact_tasks.to_string(),
        );
        fields.insert(
            "workflow_stages".to_string(),
            plan.workflow_stages
                .iter()
                .map(|stage| format!("{stage:?}"))
                .collect::<Vec<_>>()
                .join(","),
        );
        CompatibilityEnvelope {
            protocol_version: "1".to_string(),
            producer: "security-agent".to_string(),
            payload_kind: "execution_plan".to_string(),
            fields,
        }
    }

    fn import_finding_hint(&self, envelope: &CompatibilityEnvelope) -> Option<Finding> {
        if envelope.payload_kind != "finding_hint" {
            return None;
        }
        let finding_id = envelope.fields.get("finding_id")?.clone();
        let title = envelope.fields.get("title")?.clone();
        let target_id = envelope.fields.get("target_id")?.clone();
        let source_tool = envelope
            .fields
            .get("source_tool")
            .cloned()
            .unwrap_or_else(|| "external".to_string());
        let confidence_percent = envelope
            .fields
            .get("confidence_percent")
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(50);

        Some(Finding {
            finding_id,
            source_tool,
            title,
            target_id,
            severity: Severity::Medium,
            confidence_percent,
            remediation_playbook: "triage-and-remediate".to_string(),
            normalized_risk_score: 0.0,
        })
    }
}
