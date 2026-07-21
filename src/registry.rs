use crate::model::{SpecialistKind, TargetType, Technique, TestIntensity};
use std::collections::HashMap;

fn requested_full_toolset_names() -> Vec<String> {
    vec![
        "autopsy",
        "volatility",
        "binwalk",
        "bulk_extractor",
        "foremost",
        "hashdeep",
        "chkrootkit",
        "galleta",
        "mdb-sql",
        "sqlitebrowser",
        "wireshark",
        "tcpdump",
        "mitmproxy",
        "bettercap",
        "ettercap",
        "netsniff-ng",
        "driftnet",
        "macchanger",
        "cutycapt",
        "keepnote",
        "recordmydesktop",
        "msfconsole",
        "msfpc",
        "searchsploit",
        "sqlmap",
        "netexec",
        "crackmapexec",
        "evil-winrm",
        "setoolkit",
        "beef-xss",
        "yersinia",
        "thc-ipv6",
        "termineter",
        "aircrack-ng",
        "wifite",
        "reaver",
        "kismet",
        "giskismet",
        "mfoc",
        "mfterm",
        "chirpw",
        "hashcat",
        "john",
        "hydra",
        "medusa",
        "ncrack",
        "ophcrack",
        "pyrit",
        "rcrack",
        "cewl",
        "crunch",
        "burpsuite",
        "gobuster",
        "feroxbuster",
        "dirb",
        "ffuf",
        "wfuzz",
        "wpscan",
        "whatweb",
        "wafw00f",
        "skipfish",
        "httrack",
        "nikto",
        "nuclei",
        "lynis",
        "nmap",
        "zenmap",
        "masscan",
        "netdiscover",
        "amass",
        "subfinder",
        "dmitry",
        "ike-scan",
        "enum4linux",
        "smbmap",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Static source/bytecode analysis tools relevant to the SAST specialist.
fn sast_toolset_names() -> Vec<String> {
    vec![
        "semgrep",
        "qark",
        "mariana-trench",
        "trueseeing",
        "androguard",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Live web-application scanning tools relevant to the DAST specialist.
fn dast_toolset_names() -> Vec<String> {
    vec![
        "burpsuite",
        "nikto",
        "nuclei",
        "skipfish",
        "wafw00f",
        "whatweb",
        "wpscan",
        "gobuster",
        "ffuf",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// API-focused traffic inspection and fuzzing tools.
fn api_security_toolset_names() -> Vec<String> {
    vec!["mitmproxy", "burpsuite", "ffuf", "wfuzz", "nuclei"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Host/network posture-checking tools relevant to cloud and infrastructure.
fn cloud_iac_toolset_names() -> Vec<String> {
    vec!["lynis", "chkrootkit", "nmap", "masscan"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Host-integrity tools relevant to container/Kubernetes posture checks.
fn container_k8s_toolset_names() -> Vec<String> {
    vec!["lynis", "chkrootkit", "hashdeep"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Offline vulnerability-database lookup and integrity tools for dependency risk.
fn dependency_risk_toolset_names() -> Vec<String> {
    vec!["searchsploit", "hashdeep"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Secret-scanning tools for source, APK, and API surfaces.
fn secrets_toolset_names() -> Vec<String> {
    vec!["apkleaks", "semgrep"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Local forensic and malware-analysis tools.
fn malware_toolset_names() -> Vec<String> {
    vec![
        "chkrootkit",
        "binwalk",
        "bulk_extractor",
        "foremost",
        "volatility",
        "autopsy",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Compliance/hardening baseline tools.
fn compliance_toolset_names() -> Vec<String> {
    vec!["lynis", "chkrootkit"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Static-analysis tools applicable to smart-contract source review.
fn blockchain_toolset_names() -> Vec<String> {
    vec!["semgrep", "searchsploit"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Tools focused on Android / mobile application analysis.
fn android_toolset_names() -> Vec<String> {
    vec![
        "apktool",
        "jadx",
        "mobsf",
        "androguard",
        "frida",
        "objection",
        "apkleaks",
        "apksigner",
        "dex2jar",
        "drozer",
        "qark",
        "mariana-trench",
        "trueseeing",
        "nuclei",
        "semgrep",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

#[derive(Debug, Clone)]
pub struct SpecialistCapability {
    pub specialist: SpecialistKind,
    pub target_types: Vec<TargetType>,
    pub approved_tools: Vec<String>,
    pub supported_techniques: Vec<Technique>,
    pub max_intensity: TestIntensity,
}

#[derive(Debug, Clone)]
pub struct CapabilityRegistry {
    pub capabilities: Vec<SpecialistCapability>,
}

fn sast_capability() -> SpecialistCapability {
    SpecialistCapability {
        specialist: SpecialistKind::Sast,
        target_types: vec![TargetType::SourceCode],
        approved_tools: sast_toolset_names(),
        supported_techniques: vec![Technique::Sast, Technique::SecretScan],
        max_intensity: TestIntensity::Standard,
    }
}

fn dast_capability() -> SpecialistCapability {
    SpecialistCapability {
        specialist: SpecialistKind::Dast,
        target_types: vec![TargetType::WebApp],
        approved_tools: dast_toolset_names(),
        supported_techniques: vec![Technique::PassiveRecon, Technique::Dast],
        max_intensity: TestIntensity::Aggressive,
    }
}

fn api_security_capability() -> SpecialistCapability {
    SpecialistCapability {
        specialist: SpecialistKind::ApiSecurity,
        target_types: vec![TargetType::Api, TargetType::MobileBackend],
        approved_tools: api_security_toolset_names(),
        supported_techniques: vec![
            Technique::PassiveRecon,
            Technique::ApiSecurity,
            Technique::ConfigurationAudit,
        ],
        max_intensity: TestIntensity::Standard,
    }
}

fn cloud_iac_capability() -> SpecialistCapability {
    SpecialistCapability {
        specialist: SpecialistKind::CloudIaC,
        target_types: vec![TargetType::Cloud, TargetType::Infrastructure],
        approved_tools: cloud_iac_toolset_names(),
        supported_techniques: vec![Technique::ConfigurationAudit, Technique::CloudPosture],
        max_intensity: TestIntensity::Standard,
    }
}

fn container_k8s_capability() -> SpecialistCapability {
    SpecialistCapability {
        specialist: SpecialistKind::ContainerK8s,
        target_types: vec![TargetType::Container],
        approved_tools: container_k8s_toolset_names(),
        supported_techniques: vec![Technique::ContainerPosture],
        max_intensity: TestIntensity::Standard,
    }
}

fn dependency_risk_capability() -> SpecialistCapability {
    SpecialistCapability {
        specialist: SpecialistKind::DependencyRisk,
        target_types: vec![TargetType::DependencyManifest],
        approved_tools: dependency_risk_toolset_names(),
        supported_techniques: vec![Technique::DependencyAudit],
        max_intensity: TestIntensity::Standard,
    }
}

fn secrets_capability() -> SpecialistCapability {
    SpecialistCapability {
        specialist: SpecialistKind::Secrets,
        target_types: vec![TargetType::SourceCode, TargetType::Api, TargetType::WebApp],
        approved_tools: secrets_toolset_names(),
        supported_techniques: vec![Technique::SecretScan],
        max_intensity: TestIntensity::Standard,
    }
}

fn malware_capability() -> SpecialistCapability {
    SpecialistCapability {
        specialist: SpecialistKind::Malware,
        target_types: vec![TargetType::SourceCode, TargetType::Container],
        approved_tools: malware_toolset_names(),
        supported_techniques: vec![Technique::MalwareScan],
        max_intensity: TestIntensity::Standard,
    }
}

fn compliance_capability() -> SpecialistCapability {
    SpecialistCapability {
        specialist: SpecialistKind::Compliance,
        target_types: vec![
            TargetType::Api,
            TargetType::WebApp,
            TargetType::Infrastructure,
            TargetType::Cloud,
            TargetType::Container,
        ],
        approved_tools: compliance_toolset_names(),
        supported_techniques: vec![
            Technique::ConfigurationAudit,
            Technique::ThreatModeling,
            Technique::AttackPathAnalysis,
        ],
        max_intensity: TestIntensity::Passive,
    }
}

fn mobile_android_capability() -> SpecialistCapability {
    SpecialistCapability {
        specialist: SpecialistKind::MobileAndroid,
        target_types: vec![TargetType::MobileApp, TargetType::MobileBackend],
        approved_tools: android_toolset_names(),
        supported_techniques: vec![
            Technique::AndroidStaticAnalysis,
            Technique::MobileRuntime,
            Technique::SecretScan,
            Technique::DependencyAudit,
        ],
        max_intensity: TestIntensity::Aggressive,
    }
}

fn blockchain_capability() -> SpecialistCapability {
    SpecialistCapability {
        specialist: SpecialistKind::BlockchainSmartContract,
        target_types: vec![TargetType::Blockchain],
        approved_tools: blockchain_toolset_names(),
        supported_techniques: vec![
            Technique::Sast,
            Technique::ThreatModeling,
            Technique::AttackPathAnalysis,
        ],
        max_intensity: TestIntensity::Standard,
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self {
            capabilities: vec![
                sast_capability(),
                dast_capability(),
                api_security_capability(),
                cloud_iac_capability(),
                container_k8s_capability(),
                dependency_risk_capability(),
                secrets_capability(),
                malware_capability(),
                compliance_capability(),
                mobile_android_capability(),
                blockchain_capability(),
            ],
        }
    }
}

impl CapabilityRegistry {
    #[must_use]
    pub fn capabilities_for_target(&self, target_type: &TargetType) -> Vec<SpecialistCapability> {
        self.capabilities
            .iter()
            .filter(|cap| cap.target_types.iter().any(|tt| tt == target_type))
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UseCase {
    WebApp,
    Api,
    MobileBackend,
    MobileApp,
    Cloud,
    BlockchainSmartContract,
}

/// Coarse classification of what a cataloged tool actually *does* once run,
/// used to gate real execution (see `crate::execution`) independently of
/// whether the binary happens to be present on `PATH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionClass {
    /// Operates only on local files/evidence already on disk; no network
    /// I/O, no live target interaction. Safe to execute directly once a
    /// specialist has approved the tool.
    StaticLocalAnalysis,
    /// Sends traffic to, scans, or otherwise actively interacts with a
    /// live network target (host discovery, web/API fuzzing, brute force,
    /// wireless capture, etc.).
    ActiveNetwork,
    /// Delivers a payload, gains code execution, or otherwise attempts to
    /// compromise a live target or running process (exploitation
    /// frameworks, dynamic mobile instrumentation).
    ActiveExploitation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDefinition {
    pub name: String,
    pub version: String,
    pub signed: bool,
    pub vulnerability_reviewed: bool,
    pub egress_policy: Vec<String>,
    pub execution_class: ExecutionClass,
}

/// Best-effort classification of every cataloged tool's execution surface.
/// This drives which tools Phase-4-style real execution wiring may invoke
/// directly (`StaticLocalAnalysis`) versus which require additional,
/// not-yet-built live-target/rate-limit gating (`ActiveNetwork`,
/// `ActiveExploitation`). Unrecognized names fall back to the strictest
/// class rather than being silently treated as safe.
fn classify_execution(name: &str) -> ExecutionClass {
    use ExecutionClass::{ActiveExploitation, ActiveNetwork, StaticLocalAnalysis};
    match name {
        "autopsy" | "volatility" | "binwalk" | "bulk_extractor" | "foremost" | "hashdeep"
        | "chkrootkit" | "galleta" | "mdb-sql" | "sqlitebrowser" | "wireshark" | "keepnote"
        | "recordmydesktop" | "searchsploit" | "giskismet" | "chirpw" | "hashcat" | "john"
        | "ophcrack" | "pyrit" | "rcrack" | "crunch" | "lynis" | "apktool" | "jadx" | "mobsf"
        | "androguard" | "apkleaks" | "apksigner" | "dex2jar" | "qark" | "mariana-trench"
        | "trueseeing" | "semgrep" => StaticLocalAnalysis,

        "msfconsole" | "msfpc" | "sqlmap" | "netexec" | "crackmapexec" | "evil-winrm"
        | "setoolkit" | "beef-xss" | "frida" | "objection" | "drozer" => ActiveExploitation,

        _ => ActiveNetwork,
    }
}

fn requested_full_tool_definitions() -> Vec<ToolDefinition> {
    requested_full_toolset_names()
        .into_iter()
        .map(|name| ToolDefinition {
            execution_class: classify_execution(&name),
            name,
            version: "not-detected".to_string(),
            signed: false,
            vulnerability_reviewed: false,
            egress_policy: vec!["offline-local-only".to_string()],
        })
        .collect()
}

fn android_tool_definitions() -> Vec<ToolDefinition> {
    android_toolset_names()
        .into_iter()
        .map(|name| ToolDefinition {
            execution_class: classify_execution(&name),
            name,
            version: "not-detected".to_string(),
            signed: false,
            vulnerability_reviewed: false,
            egress_policy: vec!["offline-local-only".to_string()],
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct ToolchainPack {
    pub name: String,
    pub use_case: UseCase,
    pub tools: Vec<ToolDefinition>,
    pub deprecated: bool,
    pub replacement_pack: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ToolchainPackRegistry {
    pub packs: HashMap<UseCase, ToolchainPack>,
}

impl Default for ToolchainPackRegistry {
    fn default() -> Self {
        let mut packs = HashMap::new();
        let cataloged_tools = requested_full_tool_definitions();

        packs.insert(
            UseCase::WebApp,
            ToolchainPack {
                name: "webapp-core-pack".to_string(),
                use_case: UseCase::WebApp,
                tools: cataloged_tools.clone(),
                deprecated: false,
                replacement_pack: None,
            },
        );

        packs.insert(
            UseCase::Api,
            ToolchainPack {
                name: "api-core-pack".to_string(),
                use_case: UseCase::Api,
                tools: cataloged_tools.clone(),
                deprecated: false,
                replacement_pack: None,
            },
        );

        packs.insert(
            UseCase::MobileBackend,
            ToolchainPack {
                name: "mobile-backend-pack".to_string(),
                use_case: UseCase::MobileBackend,
                tools: cataloged_tools.clone(),
                // A mobile backend is an API surface, tested with the same
                // toolchain as any other API. The dedicated pack is retained
                // for use-case coverage but is on its way out in favor of the
                // api-core pack; this exercises the deprecation lifecycle
                // (`deprecated_packs`, and the plan's DEPRECATED marker).
                deprecated: true,
                replacement_pack: Some("api-core-pack".to_string()),
            },
        );

        packs.insert(
            UseCase::MobileApp,
            ToolchainPack {
                name: "android-mobile-pack".to_string(),
                use_case: UseCase::MobileApp,
                tools: android_tool_definitions(),
                deprecated: false,
                replacement_pack: None,
            },
        );

        packs.insert(
            UseCase::Cloud,
            ToolchainPack {
                name: "cloud-posture-pack".to_string(),
                use_case: UseCase::Cloud,
                tools: cataloged_tools.clone(),
                deprecated: false,
                replacement_pack: None,
            },
        );

        packs.insert(
            UseCase::BlockchainSmartContract,
            ToolchainPack {
                name: "smart-contract-pack".to_string(),
                use_case: UseCase::BlockchainSmartContract,
                tools: cataloged_tools,
                deprecated: false,
                replacement_pack: None,
            },
        );

        Self { packs }
    }
}

impl ToolchainPackRegistry {
    #[must_use]
    pub fn by_use_case(&self, use_case: &UseCase) -> Option<&ToolchainPack> {
        self.packs.get(use_case)
    }

    /// Every pack currently marked deprecated. Lets callers surface the
    /// pack-lifecycle signal — e.g. warn that a selected pack is on its way
    /// out and name the pack that supersedes it.
    #[must_use]
    pub fn deprecated_packs(&self) -> Vec<&ToolchainPack> {
        let mut deprecated: Vec<&ToolchainPack> =
            self.packs.values().filter(|pack| pack.deprecated).collect();
        // Deterministic order regardless of the backing map's iteration order.
        deprecated.sort_by(|a, b| a.name.cmp(&b.name));
        deprecated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deprecated_packs_returns_only_deprecated_packs_with_replacements() {
        let registry = ToolchainPackRegistry::default();
        let deprecated = registry.deprecated_packs();

        assert!(
            deprecated.iter().all(|pack| pack.deprecated),
            "accessor must return only deprecated packs"
        );
        assert!(
            deprecated
                .iter()
                .any(|pack| pack.name == "mobile-backend-pack"
                    && pack.replacement_pack.as_deref() == Some("api-core-pack")),
            "the deprecated mobile-backend-pack should name its replacement"
        );
    }

    #[test]
    fn execution_class_partitions_the_full_catalog_without_overlap() {
        let mut all_names: Vec<String> = requested_full_toolset_names();
        for name in android_toolset_names() {
            if !all_names.contains(&name) {
                all_names.push(name);
            }
        }
        assert_eq!(
            all_names.len(),
            89,
            "catalog should contain 89 unique tools"
        );

        let static_count = all_names
            .iter()
            .filter(|name| classify_execution(name) == ExecutionClass::StaticLocalAnalysis)
            .count();
        let exploitation_count = all_names
            .iter()
            .filter(|name| classify_execution(name) == ExecutionClass::ActiveExploitation)
            .count();
        let network_count = all_names
            .iter()
            .filter(|name| classify_execution(name) == ExecutionClass::ActiveNetwork)
            .count();

        assert_eq!(static_count, 34);
        assert_eq!(exploitation_count, 11);
        assert_eq!(network_count, 44);
        assert_eq!(
            static_count + exploitation_count + network_count,
            all_names.len()
        );
    }

    #[test]
    fn specialist_tool_scopes_are_not_all_identical() {
        // Regression guard for the "approved_tools doesn't discriminate"
        // finding: specialists must not all share the exact same tool list.
        let registry = CapabilityRegistry::default();
        let mut distinct_scopes = std::collections::HashSet::new();
        for capability in &registry.capabilities {
            let mut tools = capability.approved_tools.clone();
            tools.sort();
            distinct_scopes.insert(tools);
        }
        assert!(
            distinct_scopes.len() > 1,
            "specialists should have meaningfully different approved tool sets"
        );
    }
}
