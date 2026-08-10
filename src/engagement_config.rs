//! Zero-dependency parser for a human-authored engagement configuration
//! file, consumed by the `--plan-scan` CLI command.
//!
//! The format is a simple line-oriented `key=value` file (comments start
//! with `#`, blank lines are ignored) with repeated `[target]` sections:
//!
//! ```text
//! engagement_id=eng-2026-001
//! authorized_by=jane.doe
//! authorized_by_role=SecurityAdmin
//! time_window_start=1750000000
//! time_window_end=1760000000
//! in_scope_targets=api-staging,web-staging
//! allowed_techniques=PassiveRecon,ConfigurationAudit,ApiSecurity
//! deny_list_targets=prod-ledger
//! max_intensity=Standard
//! high_impact_approved=false
//! penetrative_testing_approved=true
//!
//! [target]
//! id=api-staging
//! target_type=Api
//! criticality=5
//! network_address=192.168.1.10
//!
//! [target]
//! id=web-staging
//! target_type=WebApp
//! criticality=3
//! ```
//!
//! Guardrails removed (see commit note "remove all guardrails"): none of
//! the authorization fields above are mandatory. Missing profile fields
//! fall back to permissive defaults (`authorized_by=unrestricted`,
//! unbounded time window, no deny-list, `max_intensity=Aggressive`,
//! `high_impact_approved=true`, `penetrative_testing_approved=true`), and
//! the authorization fields are informational only — the policy layer no
//! longer enforces them. Only structural validation is kept: malformed
//! `key=value` lines, empty `[target]` sections, and present-but-invalid
//! enum/number values still error so typos are caught.
//!
//! `network_address` is optional: a resolvable IP or hostname for the
//! target, used by real execution to bind network-tool invocations to the
//! authorized address (see `crate::execution::execute_plan`). Omitting it
//! (as `web-staging` does above) leaves the target label-only, exactly as
//! before this field existed.
//!
//! This is a minimal parser for this crate's fixed shape, not a
//! general-purpose config format.

use crate::governance::Role;
use crate::model::{EngagementProfile, Target, Technique, TestIntensity, TimeWindow};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug)]
pub enum EngagementConfigError {
    Io(std::io::Error),
    InvalidLine(String),
    MissingField(&'static str),
    InvalidField {
        field: &'static str,
        value: String,
        reason: String,
    },
    EmptyTargetSection,
}

impl fmt::Display for EngagementConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(source) => write!(formatter, "{source}"),
            Self::InvalidLine(line) => write!(formatter, "expected key=value, got: {line}"),
            Self::MissingField(field) => write!(formatter, "missing required field: {field}"),
            Self::InvalidField {
                field,
                value,
                reason,
            } => write!(formatter, "invalid value for {field} ({value:?}): {reason}"),
            Self::EmptyTargetSection => {
                formatter.write_str("a [target] section produced no fields")
            }
        }
    }
}

impl std::error::Error for EngagementConfigError {}

/// Loads and parses an engagement configuration file from disk.
///
/// # Errors
///
/// Returns [`EngagementConfigError::Io`] if the file cannot be read, or any
/// other variant if its contents don't match the expected shape (see
/// [`parse_engagement_config`]).
pub fn load_engagement_config(
    path: &Path,
) -> Result<(EngagementProfile, Vec<Target>), EngagementConfigError> {
    let text = fs::read_to_string(path).map_err(EngagementConfigError::Io)?;
    parse_engagement_config(&text)
}

/// Parses engagement configuration text into a profile and its targets.
///
/// # Errors
///
/// Returns [`EngagementConfigError::InvalidLine`] for a line that isn't a
/// comment, blank, `[target]`, or `key=value`; [`EngagementConfigError::MissingField`]
/// or [`EngagementConfigError::InvalidField`] for missing/malformed required
/// fields; and [`EngagementConfigError::EmptyTargetSection`] for a `[target]`
/// section with no fields.
pub fn parse_engagement_config(
    text: &str,
) -> Result<(EngagementProfile, Vec<Target>), EngagementConfigError> {
    let mut profile_fields = BTreeMap::new();
    let mut target_field_sets: Vec<BTreeMap<String, String>> = Vec::new();
    let mut current_target: Option<BTreeMap<String, String>> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[target]" {
            if let Some(fields) = current_target.take() {
                if fields.is_empty() {
                    return Err(EngagementConfigError::EmptyTargetSection);
                }
                target_field_sets.push(fields);
            }
            current_target = Some(BTreeMap::new());
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(EngagementConfigError::InvalidLine(line.to_string()));
        };
        let key = key.trim().to_string();
        let value = value.trim().to_string();

        match &mut current_target {
            Some(fields) => {
                fields.insert(key, value);
            }
            None => {
                profile_fields.insert(key, value);
            }
        }
    }
    if let Some(fields) = current_target.take() {
        if fields.is_empty() {
            return Err(EngagementConfigError::EmptyTargetSection);
        }
        target_field_sets.push(fields);
    }

    let profile = build_profile(&profile_fields)?;
    let targets = target_field_sets
        .iter()
        .map(build_target)
        .collect::<Result<Vec<_>, _>>()?;

    Ok((profile, targets))
}

fn build_profile(
    fields: &BTreeMap<String, String>,
) -> Result<EngagementProfile, EngagementConfigError> {
    Ok(EngagementProfile {
        engagement_id: fields
            .get("engagement_id")
            .cloned()
            .unwrap_or_else(|| "unrestricted".to_string()),
        authorized_by: fields
            .get("authorized_by")
            .cloned()
            .unwrap_or_else(|| "unrestricted".to_string()),
        authorized_by_role: parse_field_or_default(
            fields,
            "authorized_by_role",
            Role::SecurityAdmin,
        )?,
        time_window: TimeWindow {
            start_epoch_seconds: parse_field_or_default(fields, "time_window_start", 0)?,
            end_epoch_seconds: parse_field_or_default(fields, "time_window_end", u64::MAX)?,
        },
        in_scope_targets: csv_list(fields.get("in_scope_targets").map_or("", String::as_str)),
        allowed_techniques: csv_enum_list(fields, "allowed_techniques")?,
        deny_list_targets: csv_list(fields.get("deny_list_targets").map_or("", String::as_str)),
        max_intensity: parse_field_or_default(fields, "max_intensity", TestIntensity::Aggressive)?,
        high_impact_approved: parse_field_or_default(fields, "high_impact_approved", true)?,
        penetrative_testing_approved: parse_field_or_default(
            fields,
            "penetrative_testing_approved",
            true,
        )?,
    })
}

fn build_target(fields: &BTreeMap<String, String>) -> Result<Target, EngagementConfigError> {
    Ok(Target {
        id: required_string(fields, "id")?,
        target_type: parse_field(fields, "target_type")?,
        criticality: parse_field(fields, "criticality")?,
        network_address: fields.get("network_address").cloned(),
    })
}

fn required_string(
    fields: &BTreeMap<String, String>,
    field: &'static str,
) -> Result<String, EngagementConfigError> {
    fields
        .get(field)
        .cloned()
        .ok_or(EngagementConfigError::MissingField(field))
}

/// Parses `field` from `fields`, falling back to `default` when the key is
/// absent. A present-but-malformed value still yields an
/// [`EngagementConfigError::InvalidField`] (typo detection is kept — it is
/// data validation, not authorization).
fn parse_field_or_default<T>(
    fields: &BTreeMap<String, String>,
    field: &'static str,
    default: T,
) -> Result<T, EngagementConfigError>
where
    T: FromStr + Clone,
    T::Err: fmt::Display,
{
    fields.get(field).map_or_else(
        || Ok(default),
        |value| {
            value
                .parse::<T>()
                .map_err(|error| EngagementConfigError::InvalidField {
                    field,
                    value: value.clone(),
                    reason: error.to_string(),
                })
        },
    )
}

fn parse_field<T>(
    fields: &BTreeMap<String, String>,
    field: &'static str,
) -> Result<T, EngagementConfigError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    let value = fields
        .get(field)
        .ok_or(EngagementConfigError::MissingField(field))?;
    value
        .parse::<T>()
        .map_err(|error| EngagementConfigError::InvalidField {
            field,
            value: value.clone(),
            reason: error.to_string(),
        })
}

fn csv_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn csv_enum_list(
    fields: &BTreeMap<String, String>,
    field: &'static str,
) -> Result<Vec<Technique>, EngagementConfigError> {
    let raw = fields.get(field).map_or("", String::as_str);
    csv_list(raw)
        .into_iter()
        .map(|item| {
            item.parse::<Technique>()
                .map_err(|error| EngagementConfigError::InvalidField {
                    field,
                    value: item,
                    reason: error,
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::Role;
    use crate::model::{TargetType, TestIntensity};

    fn valid_config() -> &'static str {
        "\
# comment line
engagement_id=eng-2026-001
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=100
time_window_end=200
in_scope_targets=api-staging, web-staging
allowed_techniques=PassiveRecon,ConfigurationAudit,ApiSecurity
deny_list_targets=prod-ledger
max_intensity=Standard
high_impact_approved=false
penetrative_testing_approved=true

[target]
id=api-staging
target_type=Api
criticality=5

[target]
id=web-staging
target_type=WebApp
criticality=3
"
    }

    #[test]
    fn parses_a_valid_config_end_to_end() {
        let (profile, targets) = parse_engagement_config(valid_config()).expect("should parse");

        assert_eq!(profile.engagement_id, "eng-2026-001");
        assert_eq!(profile.authorized_by, "jane.doe");
        assert_eq!(profile.authorized_by_role, Role::SecurityAdmin);
        assert_eq!(profile.time_window.start_epoch_seconds, 100);
        assert_eq!(profile.time_window.end_epoch_seconds, 200);
        assert_eq!(profile.in_scope_targets, vec!["api-staging", "web-staging"]);
        assert_eq!(
            profile.allowed_techniques,
            vec![
                Technique::PassiveRecon,
                Technique::ConfigurationAudit,
                Technique::ApiSecurity
            ]
        );
        assert_eq!(profile.deny_list_targets, vec!["prod-ledger"]);
        assert_eq!(profile.max_intensity, TestIntensity::Standard);
        assert!(!profile.high_impact_approved);
        assert!(profile.penetrative_testing_approved);

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].id, "api-staging");
        assert_eq!(targets[0].target_type, TargetType::Api);
        assert_eq!(targets[0].criticality, 5);
        assert_eq!(targets[1].id, "web-staging");
        assert_eq!(targets[1].target_type, TargetType::WebApp);
        assert_eq!(targets[1].criticality, 3);
    }

    #[test]
    fn parses_optional_network_address() {
        let config = "\
engagement_id=eng-1
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=0
time_window_end=100
max_intensity=Passive
high_impact_approved=false
penetrative_testing_approved=false

[target]
id=t1
target_type=Api
criticality=5
network_address=192.168.1.10
";
        let (_, targets) = parse_engagement_config(config).expect("should parse");
        assert_eq!(targets[0].network_address.as_deref(), Some("192.168.1.10"));
    }

    #[test]
    fn network_address_absent_is_none() {
        // Regression guard: a config with no network_address key (the
        // shape every config used before this field existed) still parses,
        // leaving the target label-only.
        let (_, targets) = parse_engagement_config(valid_config()).expect("should parse");
        assert_eq!(targets[0].network_address, None);
        assert_eq!(targets[1].network_address, None);
    }

    #[test]
    fn empty_lists_parse_to_empty_vecs() {
        let config = "\
engagement_id=eng-1
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=0
time_window_end=100
in_scope_targets=
allowed_techniques=
deny_list_targets=
max_intensity=Passive
high_impact_approved=false
penetrative_testing_approved=false
";
        let (profile, targets) = parse_engagement_config(config).expect("should parse");
        assert!(profile.in_scope_targets.is_empty());
        assert!(profile.allowed_techniques.is_empty());
        assert!(profile.deny_list_targets.is_empty());
        assert!(targets.is_empty());
    }

    #[test]
    fn missing_authz_fields_parse_with_permissive_defaults() {
        // Guardrails removed: a config with no authorization fields at all
        // parses successfully and gets permissive defaults.
        let config = "\
# no authorization fields present
[target]
id=t1
target_type=Api
criticality=5
";
        let (profile, targets) = parse_engagement_config(config).expect("should parse");
        assert_eq!(profile.engagement_id, "unrestricted");
        assert_eq!(profile.authorized_by, "unrestricted");
        assert_eq!(profile.authorized_by_role, Role::SecurityAdmin);
        assert_eq!(profile.time_window.start_epoch_seconds, 0);
        assert_eq!(profile.time_window.end_epoch_seconds, u64::MAX);
        assert!(profile.in_scope_targets.is_empty());
        assert!(profile.allowed_techniques.is_empty());
        assert!(profile.deny_list_targets.is_empty());
        assert_eq!(profile.max_intensity, TestIntensity::Aggressive);
        assert!(profile.high_impact_approved);
        assert!(profile.penetrative_testing_approved);
        assert_eq!(targets.len(), 1);
    }

    #[test]
    fn empty_config_parses_with_permissive_defaults() {
        // Maximum freedom: even an empty config file is accepted.
        let (profile, targets) = parse_engagement_config("").expect("should parse");
        assert_eq!(profile.engagement_id, "unrestricted");
        assert_eq!(profile.authorized_by, "unrestricted");
        assert!(profile.high_impact_approved);
        assert!(profile.penetrative_testing_approved);
        assert!(targets.is_empty());
    }

    #[test]
    fn rejects_invalid_enum_value() {
        let config = "\
engagement_id=eng-1
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=0
time_window_end=100
max_intensity=Extreme
high_impact_approved=false
penetrative_testing_approved=false
";
        let result = parse_engagement_config(config);
        assert!(matches!(
            result,
            Err(EngagementConfigError::InvalidField {
                field: "max_intensity",
                ..
            })
        ));
    }

    #[test]
    fn rejects_invalid_technique_in_list() {
        let config = "\
engagement_id=eng-1
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=0
time_window_end=100
allowed_techniques=PassiveRecon,NotARealTechnique
max_intensity=Passive
high_impact_approved=false
penetrative_testing_approved=false
";
        let result = parse_engagement_config(config);
        assert!(matches!(
            result,
            Err(EngagementConfigError::InvalidField {
                field: "allowed_techniques",
                ..
            })
        ));
    }

    #[test]
    fn rejects_line_without_equals_sign() {
        let result = parse_engagement_config("not-a-key-value-line");
        assert!(matches!(result, Err(EngagementConfigError::InvalidLine(_))));
    }

    #[test]
    fn rejects_empty_target_section() {
        let config = "\
engagement_id=eng-1
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=0
time_window_end=100
max_intensity=Passive
high_impact_approved=false
penetrative_testing_approved=false

[target]
[target]
id=t1
target_type=Api
criticality=1
";
        let result = parse_engagement_config(config);
        assert!(matches!(
            result,
            Err(EngagementConfigError::EmptyTargetSection)
        ));
    }

    #[test]
    fn rejects_target_missing_required_field() {
        let config = "\
engagement_id=eng-1
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=0
time_window_end=100
max_intensity=Passive
high_impact_approved=false
penetrative_testing_approved=false

[target]
id=t1
target_type=Api
";
        let result = parse_engagement_config(config);
        assert!(matches!(
            result,
            Err(EngagementConfigError::MissingField("criticality"))
        ));
    }

    #[test]
    fn rejects_invalid_criticality_value() {
        let config = "\
engagement_id=eng-1
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=0
time_window_end=100
max_intensity=Passive
high_impact_approved=false
penetrative_testing_approved=false

[target]
id=t1
target_type=Api
criticality=not-a-number
";
        let result = parse_engagement_config(config);
        assert!(matches!(
            result,
            Err(EngagementConfigError::InvalidField {
                field: "criticality",
                ..
            })
        ));
    }

    #[test]
    fn load_engagement_config_reads_from_disk() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-engagement-config-{}.txt",
            std::process::id()
        ));
        fs::write(&path, valid_config()).expect("write temp config");

        let result = load_engagement_config(&path);
        fs::remove_file(&path).expect("remove temp config");

        let (profile, targets) = result.expect("should load and parse");
        assert_eq!(profile.engagement_id, "eng-2026-001");
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn load_engagement_config_reports_io_error_for_missing_file() {
        let path = std::env::temp_dir().join(format!(
            "security-agent-engagement-config-missing-{}.txt",
            std::process::id()
        ));
        let result = load_engagement_config(&path);
        assert!(matches!(result, Err(EngagementConfigError::Io(_))));
    }
}
