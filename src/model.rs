use crate::governance::Role;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SpecialistKind {
    Sast,
    Dast,
    ApiSecurity,
    DependencyRisk,
    CloudIaC,
    ContainerK8s,
    Secrets,
    Malware,
    Compliance,
    MobileAndroid,
    BlockchainSmartContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetType {
    WebApp,
    Api,
    MobileBackend,
    /// Android APK / mobile application binary analysis.
    MobileApp,
    Cloud,
    Blockchain,
    Container,
    Infrastructure,
    SourceCode,
    DependencyManifest,
}

impl fmt::Display for TargetType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::WebApp => "WebApp",
            Self::Api => "Api",
            Self::MobileBackend => "MobileBackend",
            Self::MobileApp => "MobileApp",
            Self::Cloud => "Cloud",
            Self::Blockchain => "Blockchain",
            Self::Container => "Container",
            Self::Infrastructure => "Infrastructure",
            Self::SourceCode => "SourceCode",
            Self::DependencyManifest => "DependencyManifest",
        };
        formatter.write_str(name)
    }
}

impl FromStr for TargetType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "WebApp" => Ok(Self::WebApp),
            "Api" => Ok(Self::Api),
            "MobileBackend" => Ok(Self::MobileBackend),
            "MobileApp" => Ok(Self::MobileApp),
            "Cloud" => Ok(Self::Cloud),
            "Blockchain" => Ok(Self::Blockchain),
            "Container" => Ok(Self::Container),
            "Infrastructure" => Ok(Self::Infrastructure),
            "SourceCode" => Ok(Self::SourceCode),
            "DependencyManifest" => Ok(Self::DependencyManifest),
            other => Err(format!("unknown target type: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Technique {
    PassiveRecon,
    ConfigurationAudit,
    Sast,
    Dast,
    ApiSecurity,
    DependencyAudit,
    CloudPosture,
    ContainerPosture,
    SecretScan,
    MalwareScan,
    ThreatModeling,
    AttackPathAnalysis,
    ExploitValidationSandboxed,
    /// Static analysis of Android APK/DEX bytecode.
    AndroidStaticAnalysis,
    /// Dynamic instrumentation of a running mobile application.
    MobileRuntime,
}

impl fmt::Display for Technique {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::PassiveRecon => "PassiveRecon",
            Self::ConfigurationAudit => "ConfigurationAudit",
            Self::Sast => "Sast",
            Self::Dast => "Dast",
            Self::ApiSecurity => "ApiSecurity",
            Self::DependencyAudit => "DependencyAudit",
            Self::CloudPosture => "CloudPosture",
            Self::ContainerPosture => "ContainerPosture",
            Self::SecretScan => "SecretScan",
            Self::MalwareScan => "MalwareScan",
            Self::ThreatModeling => "ThreatModeling",
            Self::AttackPathAnalysis => "AttackPathAnalysis",
            Self::ExploitValidationSandboxed => "ExploitValidationSandboxed",
            Self::AndroidStaticAnalysis => "AndroidStaticAnalysis",
            Self::MobileRuntime => "MobileRuntime",
        };
        formatter.write_str(name)
    }
}

impl FromStr for Technique {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "PassiveRecon" => Ok(Self::PassiveRecon),
            "ConfigurationAudit" => Ok(Self::ConfigurationAudit),
            "Sast" => Ok(Self::Sast),
            "Dast" => Ok(Self::Dast),
            "ApiSecurity" => Ok(Self::ApiSecurity),
            "DependencyAudit" => Ok(Self::DependencyAudit),
            "CloudPosture" => Ok(Self::CloudPosture),
            "ContainerPosture" => Ok(Self::ContainerPosture),
            "SecretScan" => Ok(Self::SecretScan),
            "MalwareScan" => Ok(Self::MalwareScan),
            "ThreatModeling" => Ok(Self::ThreatModeling),
            "AttackPathAnalysis" => Ok(Self::AttackPathAnalysis),
            "ExploitValidationSandboxed" => Ok(Self::ExploitValidationSandboxed),
            "AndroidStaticAnalysis" => Ok(Self::AndroidStaticAnalysis),
            "MobileRuntime" => Ok(Self::MobileRuntime),
            other => Err(format!("unknown technique: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TestIntensity {
    Passive,
    Standard,
    Aggressive,
}

impl fmt::Display for TestIntensity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Passive => "Passive",
            Self::Standard => "Standard",
            Self::Aggressive => "Aggressive",
        };
        formatter.write_str(name)
    }
}

impl FromStr for TestIntensity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Passive" => Ok(Self::Passive),
            "Standard" => Ok(Self::Standard),
            "Aggressive" => Ok(Self::Aggressive),
            other => Err(format!("unknown test intensity: {other}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TimeWindow {
    pub start_epoch_seconds: u64,
    pub end_epoch_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct EngagementProfile {
    pub engagement_id: String,
    pub authorized_by: String,
    /// The role `authorized_by` was acting in when they authorized this
    /// engagement. Carried through to every audit record the coordinator
    /// writes while planning under this profile.
    pub authorized_by_role: Role,
    pub time_window: TimeWindow,
    /// Explicit allow-list of target IDs that are authorized for this engagement.
    /// Empty means no target IDs are in scope.
    pub in_scope_targets: Vec<String>,
    pub allowed_techniques: Vec<Technique>,
    pub deny_list_targets: Vec<String>,
    pub max_intensity: TestIntensity,
    pub high_impact_approved: bool,
    /// Additional approval for active/penetrative testing techniques.
    pub penetrative_testing_approved: bool,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub id: String,
    pub target_type: TargetType,
    pub criticality: u8,
    /// Resolvable network address (IP or hostname) for this target, if
    /// any. `None` for label-only targets. When present, real execution
    /// of a network tool (see `crate::execution::execute_plan`) prepends
    /// this address as the tool's first argument, keeping the
    /// authorization boundary (the target `id`) connected to what the
    /// tool actually connects to — the operator's own arguments never
    /// need to (and should not) restate the target's address themselves.
    pub network_address: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_type_display_and_from_str_round_trip() {
        for target_type in [
            TargetType::WebApp,
            TargetType::Api,
            TargetType::MobileBackend,
            TargetType::MobileApp,
            TargetType::Cloud,
            TargetType::Blockchain,
            TargetType::Container,
            TargetType::Infrastructure,
            TargetType::SourceCode,
            TargetType::DependencyManifest,
        ] {
            assert_eq!(target_type.to_string().parse(), Ok(target_type));
        }
        assert!("nonexistent".parse::<TargetType>().is_err());
    }

    #[test]
    fn technique_display_and_from_str_round_trip() {
        for technique in [
            Technique::PassiveRecon,
            Technique::ConfigurationAudit,
            Technique::Sast,
            Technique::Dast,
            Technique::ApiSecurity,
            Technique::DependencyAudit,
            Technique::CloudPosture,
            Technique::ContainerPosture,
            Technique::SecretScan,
            Technique::MalwareScan,
            Technique::ThreatModeling,
            Technique::AttackPathAnalysis,
            Technique::ExploitValidationSandboxed,
            Technique::AndroidStaticAnalysis,
            Technique::MobileRuntime,
        ] {
            assert_eq!(technique.to_string().parse(), Ok(technique));
        }
        assert!("nonexistent".parse::<Technique>().is_err());
    }

    #[test]
    fn test_intensity_display_and_from_str_round_trip() {
        for intensity in [
            TestIntensity::Passive,
            TestIntensity::Standard,
            TestIntensity::Aggressive,
        ] {
            assert_eq!(intensity.to_string().parse(), Ok(intensity));
        }
        assert!("nonexistent".parse::<TestIntensity>().is_err());
    }
}
