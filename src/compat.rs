use crate::coordinator::ExecutionPlan;
use crate::findings::{Finding, Severity};
use crate::governance::AuditRecord;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::iter::Peekable;
use std::str::Chars;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityEnvelope {
    pub protocol_version: String,
    pub producer: String,
    pub payload_kind: String,
    pub fields: BTreeMap<String, String>,
}

impl CompatibilityEnvelope {
    /// Serializes this envelope as one line of JSON (JSON Lines format),
    /// matching what [`JsonLineAdapter`]'s name promises. Round-trips
    /// exactly through [`Self::from_wire_format`].
    #[must_use]
    pub fn to_wire_format(&self) -> String {
        let mut out = String::from("{");
        push_json_key_value(&mut out, "version", &self.protocol_version, true);
        push_json_key_value(&mut out, "producer", &self.producer, false);
        push_json_key_value(&mut out, "kind", &self.payload_kind, false);
        out.push_str(",\"fields\":{");
        for (index, (key, value)) in self.fields.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            push_json_string(&mut out, key);
            out.push(':');
            push_json_string(&mut out, value);
        }
        out.push_str("}}\n");
        out
    }

    /// Parses a single line produced by [`Self::to_wire_format`]. This is a
    /// minimal parser for this crate's fixed envelope shape (an object with
    /// string `version`/`producer`/`kind` fields and a `fields` object of
    /// string-to-string pairs) rather than a general-purpose JSON parser;
    /// it returns `None` for anything that doesn't match that shape.
    #[must_use]
    pub fn from_wire_format(line: &str) -> Option<Self> {
        let mut chars = line.trim().chars().peekable();
        expect_char(&mut chars, '{')?;

        let mut protocol_version = None;
        let mut producer = None;
        let mut payload_kind = None;
        let mut fields = None;

        loop {
            skip_whitespace(&mut chars);
            if peek_char(&mut chars, '}') {
                chars.next();
                break;
            }
            let key = parse_json_string(&mut chars)?;
            skip_whitespace(&mut chars);
            expect_char(&mut chars, ':')?;
            skip_whitespace(&mut chars);
            match key.as_str() {
                "version" => protocol_version = Some(parse_json_string(&mut chars)?),
                "producer" => producer = Some(parse_json_string(&mut chars)?),
                "kind" => payload_kind = Some(parse_json_string(&mut chars)?),
                "fields" => fields = Some(parse_json_string_object(&mut chars)?),
                _ => return None,
            }
            skip_whitespace(&mut chars);
            match chars.next()? {
                ',' => {}
                '}' => break,
                _ => return None,
            }
        }

        Some(Self {
            protocol_version: protocol_version?,
            producer: producer?,
            payload_kind: payload_kind?,
            fields: fields.unwrap_or_default(),
        })
    }
}

fn push_json_key_value(out: &mut String, key: &str, value: &str, is_first: bool) {
    if !is_first {
        out.push(',');
    }
    push_json_string(out, key);
    out.push(':');
    push_json_string(out, value);
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn skip_whitespace(chars: &mut Peekable<Chars<'_>>) {
    while chars.next_if(|ch| ch.is_whitespace()).is_some() {}
}

fn peek_char(chars: &mut Peekable<Chars<'_>>, expected: char) -> bool {
    chars.peek() == Some(&expected)
}

fn expect_char(chars: &mut Peekable<Chars<'_>>, expected: char) -> Option<()> {
    skip_whitespace(chars);
    if chars.next() == Some(expected) {
        Some(())
    } else {
        None
    }
}

fn parse_json_string(chars: &mut Peekable<Chars<'_>>) -> Option<String> {
    skip_whitespace(chars);
    expect_char(chars, '"')?;
    let mut value = String::new();
    loop {
        match chars.next()? {
            '"' => return Some(value),
            '\\' => match chars.next()? {
                '"' => value.push('"'),
                '\\' => value.push('\\'),
                '/' => value.push('/'),
                'n' => value.push('\n'),
                'r' => value.push('\r'),
                't' => value.push('\t'),
                'u' => {
                    let code_point = parse_hex4(chars)?;
                    value.push(char::from_u32(code_point)?);
                }
                _ => return None,
            },
            ch => value.push(ch),
        }
    }
}

fn parse_hex4(chars: &mut Peekable<Chars<'_>>) -> Option<u32> {
    let mut code_point = 0_u32;
    for _ in 0..4 {
        let digit = chars.next()?.to_digit(16)?;
        code_point = code_point * 16 + digit;
    }
    Some(code_point)
}

fn parse_json_string_object(chars: &mut Peekable<Chars<'_>>) -> Option<BTreeMap<String, String>> {
    expect_char(chars, '{')?;
    let mut map = BTreeMap::new();
    loop {
        skip_whitespace(chars);
        if peek_char(chars, '}') {
            chars.next();
            return Some(map);
        }
        let key = parse_json_string(chars)?;
        skip_whitespace(chars);
        expect_char(chars, ':')?;
        let value = parse_json_string(chars)?;
        map.insert(key, value);
        skip_whitespace(chars);
        match chars.next()? {
            ',' => {}
            '}' => return Some(map),
            _ => return None,
        }
    }
}

/// Converts an [`AuditRecord`] to a [`CompatibilityEnvelope`].
///
/// The result is suitable for [`CompatibilityEnvelope::to_wire_format`],
/// used to persist the audit ledger to an append-only JSON Lines file
/// (see `crate::audit_log`).
#[must_use]
pub fn audit_record_to_envelope(record: &AuditRecord) -> CompatibilityEnvelope {
    let mut fields = BTreeMap::new();
    fields.insert(
        "timestamp_epoch_seconds".to_string(),
        record.timestamp_epoch_seconds.to_string(),
    );
    fields.insert("actor".to_string(), record.actor.clone());
    fields.insert("role".to_string(), record.role.to_string());
    fields.insert("action".to_string(), record.action.clone());
    fields.insert("target".to_string(), record.target.clone());
    fields.insert("details".to_string(), record.details.clone());
    if let Some(test_run_id) = &record.test_run_id {
        fields.insert("test_run_id".to_string(), test_run_id.clone());
    }
    CompatibilityEnvelope {
        protocol_version: "1".to_string(),
        producer: "security-agent".to_string(),
        payload_kind: "audit_record".to_string(),
        fields,
    }
}

/// The inverse of [`audit_record_to_envelope`]. Returns `None` if
/// `envelope` isn't an `audit_record` payload or is missing a required
/// field.
#[must_use]
pub fn envelope_to_audit_record(envelope: &CompatibilityEnvelope) -> Option<AuditRecord> {
    if envelope.payload_kind != "audit_record" {
        return None;
    }
    Some(AuditRecord {
        timestamp_epoch_seconds: envelope
            .fields
            .get("timestamp_epoch_seconds")?
            .parse()
            .ok()?,
        actor: envelope.fields.get("actor")?.clone(),
        role: envelope.fields.get("role")?.parse().ok()?,
        action: envelope.fields.get("action")?.clone(),
        target: envelope.fields.get("target")?.clone(),
        details: envelope.fields.get("details")?.clone(),
        test_run_id: envelope.fields.get("test_run_id").cloned(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> CompatibilityEnvelope {
        let mut fields = BTreeMap::new();
        fields.insert("engagement_id".to_string(), "eng-1".to_string());
        fields.insert("task_count".to_string(), "3".to_string());
        CompatibilityEnvelope {
            protocol_version: "1".to_string(),
            producer: "security-agent".to_string(),
            payload_kind: "execution_plan".to_string(),
            fields,
        }
    }

    #[test]
    fn to_wire_format_produces_valid_json_lines() {
        let envelope = sample_envelope();
        let line = envelope.to_wire_format();

        assert!(line.ends_with('\n'));
        let trimmed = line.trim_end();
        assert!(trimmed.starts_with('{') && trimmed.ends_with('}'));
        assert!(trimmed.contains("\"version\":\"1\""));
        assert!(trimmed.contains("\"fields\":{"));
        assert_eq!(trimmed.matches('\n').count(), 0, "must be a single line");
    }

    #[test]
    fn wire_format_round_trips_exactly() {
        let envelope = sample_envelope();
        let line = envelope.to_wire_format();

        let parsed =
            CompatibilityEnvelope::from_wire_format(&line).expect("valid wire format should parse");

        assert_eq!(parsed, envelope);
    }

    #[test]
    fn wire_format_round_trips_special_characters() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "note".to_string(),
            "quote \" backslash \\ newline \n tab \t".to_string(),
        );
        let envelope = CompatibilityEnvelope {
            protocol_version: "1".to_string(),
            producer: "unit\u{2003}test".to_string(),
            payload_kind: "finding_hint".to_string(),
            fields,
        };

        let line = envelope.to_wire_format();
        let parsed = CompatibilityEnvelope::from_wire_format(&line)
            .expect("escaped wire format should parse");

        assert_eq!(parsed, envelope);
    }

    #[test]
    fn from_wire_format_rejects_malformed_json() {
        assert!(CompatibilityEnvelope::from_wire_format("not json").is_none());
        assert!(CompatibilityEnvelope::from_wire_format("{\"version\":\"1\"").is_none());
        assert!(CompatibilityEnvelope::from_wire_format("{\"fields\":{}}").is_none());
    }

    #[test]
    fn audit_record_round_trips_through_envelope_and_wire_format() {
        use crate::governance::Role;

        let record = AuditRecord {
            timestamp_epoch_seconds: 12345,
            actor: "jane.doe".to_string(),
            role: Role::SecurityEngineer,
            action: "plan_tagged_scan".to_string(),
            target: "eng-1".to_string(),
            details: "tasks=2 high_impact=0".to_string(),
            test_run_id: Some("run-abc".to_string()),
        };

        let envelope = audit_record_to_envelope(&record);
        assert_eq!(envelope.payload_kind, "audit_record");
        let parsed = envelope_to_audit_record(&envelope).expect("should convert back");
        assert_eq!(parsed, record);

        // And through the wire format too.
        let line = envelope.to_wire_format();
        let reparsed_envelope =
            CompatibilityEnvelope::from_wire_format(&line).expect("should parse wire format");
        let reparsed_record =
            envelope_to_audit_record(&reparsed_envelope).expect("should convert back");
        assert_eq!(reparsed_record, record);
    }

    #[test]
    fn audit_record_without_test_run_id_round_trips() {
        use crate::governance::Role;

        let record = AuditRecord {
            timestamp_epoch_seconds: 1,
            actor: "secops".to_string(),
            role: Role::SecurityAdmin,
            action: "plan_authorized_scan".to_string(),
            target: "eng-2".to_string(),
            details: "tasks=1 high_impact=0".to_string(),
            test_run_id: None,
        };

        let envelope = audit_record_to_envelope(&record);
        assert!(!envelope.fields.contains_key("test_run_id"));
        let parsed = envelope_to_audit_record(&envelope).expect("should convert back");
        assert_eq!(parsed, record);
    }

    #[test]
    fn envelope_to_audit_record_rejects_wrong_payload_kind() {
        let envelope = sample_envelope();
        assert!(envelope_to_audit_record(&envelope).is_none());
    }
}
