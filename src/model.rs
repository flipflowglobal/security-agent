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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetType {
    WebApp,
    Api,
    MobileBackend,
    Cloud,
    Blockchain,
    Container,
    Infrastructure,
    SourceCode,
    DependencyManifest,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TestIntensity {
    Passive,
    Standard,
    Aggressive,
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
    pub time_window: TimeWindow,
    pub allowed_techniques: Vec<Technique>,
    pub deny_list_targets: Vec<String>,
    pub max_intensity: TestIntensity,
    pub high_impact_approved: bool,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub id: String,
    pub target_type: TargetType,
    pub criticality: u8,
}
