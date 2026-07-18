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

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self {
            capabilities: vec![
                SpecialistCapability {
                    specialist: SpecialistKind::Sast,
                    target_types: vec![TargetType::SourceCode],
                    approved_tools: requested_full_toolset_names(),
                    supported_techniques: vec![Technique::Sast, Technique::SecretScan],
                    max_intensity: TestIntensity::Standard,
                },
                SpecialistCapability {
                    specialist: SpecialistKind::Dast,
                    target_types: vec![TargetType::WebApp],
                    approved_tools: requested_full_toolset_names(),
                    supported_techniques: vec![Technique::PassiveRecon, Technique::Dast],
                    max_intensity: TestIntensity::Aggressive,
                },
                SpecialistCapability {
                    specialist: SpecialistKind::ApiSecurity,
                    target_types: vec![TargetType::Api, TargetType::MobileBackend],
                    approved_tools: requested_full_toolset_names(),
                    supported_techniques: vec![
                        Technique::PassiveRecon,
                        Technique::ApiSecurity,
                        Technique::ConfigurationAudit,
                    ],
                    max_intensity: TestIntensity::Standard,
                },
                SpecialistCapability {
                    specialist: SpecialistKind::CloudIaC,
                    target_types: vec![TargetType::Cloud, TargetType::Infrastructure],
                    approved_tools: requested_full_toolset_names(),
                    supported_techniques: vec![
                        Technique::ConfigurationAudit,
                        Technique::CloudPosture,
                    ],
                    max_intensity: TestIntensity::Standard,
                },
                SpecialistCapability {
                    specialist: SpecialistKind::ContainerK8s,
                    target_types: vec![TargetType::Container],
                    approved_tools: requested_full_toolset_names(),
                    supported_techniques: vec![Technique::ContainerPosture],
                    max_intensity: TestIntensity::Standard,
                },
                SpecialistCapability {
                    specialist: SpecialistKind::DependencyRisk,
                    target_types: vec![TargetType::DependencyManifest],
                    approved_tools: requested_full_toolset_names(),
                    supported_techniques: vec![Technique::DependencyAudit],
                    max_intensity: TestIntensity::Standard,
                },
                SpecialistCapability {
                    specialist: SpecialistKind::Secrets,
                    target_types: vec![TargetType::SourceCode, TargetType::Api, TargetType::WebApp],
                    approved_tools: requested_full_toolset_names(),
                    supported_techniques: vec![Technique::SecretScan],
                    max_intensity: TestIntensity::Standard,
                },
                SpecialistCapability {
                    specialist: SpecialistKind::Malware,
                    target_types: vec![TargetType::SourceCode, TargetType::Container],
                    approved_tools: requested_full_toolset_names(),
                    supported_techniques: vec![Technique::MalwareScan],
                    max_intensity: TestIntensity::Standard,
                },
                SpecialistCapability {
                    specialist: SpecialistKind::Compliance,
                    target_types: vec![
                        TargetType::Api,
                        TargetType::WebApp,
                        TargetType::Infrastructure,
                        TargetType::Cloud,
                        TargetType::Container,
                    ],
                    approved_tools: requested_full_toolset_names(),
                    supported_techniques: vec![
                        Technique::ConfigurationAudit,
                        Technique::ThreatModeling,
                        Technique::AttackPathAnalysis,
                    ],
                    max_intensity: TestIntensity::Passive,
                },
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
                },
                SpecialistCapability {
                    specialist: SpecialistKind::BlockchainSmartContract,
                    target_types: vec![TargetType::Blockchain],
                    approved_tools: requested_full_toolset_names(),
                    supported_techniques: vec![
                        Technique::Sast,
                        Technique::ThreatModeling,
                        Technique::AttackPathAnalysis,
                    ],
                    max_intensity: TestIntensity::Standard,
                },
            ],
        }
    }
}

impl CapabilityRegistry {
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

#[derive(Debug, Clone)]
pub struct ToolDefinition {
    pub name: String,
    pub version: String,
    pub signed: bool,
    pub vulnerability_reviewed: bool,
    pub egress_policy: Vec<String>,
}

fn requested_full_tool_definitions() -> Vec<ToolDefinition> {
    requested_full_toolset_names()
        .into_iter()
        .map(|name| ToolDefinition {
            name,
            version: "imported".to_string(),
            signed: true,
            vulnerability_reviewed: true,
            egress_policy: vec!["restricted-by-engagement-policy".to_string()],
        })
        .collect()
}

fn android_tool_definitions() -> Vec<ToolDefinition> {
    android_toolset_names()
        .into_iter()
        .map(|name| ToolDefinition {
            name,
            version: "imported".to_string(),
            signed: true,
            vulnerability_reviewed: true,
            egress_policy: vec!["restricted-by-engagement-policy".to_string()],
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
        let imported_tools = requested_full_tool_definitions();

        packs.insert(
            UseCase::WebApp,
            ToolchainPack {
                name: "webapp-core-pack".to_string(),
                use_case: UseCase::WebApp,
                tools: imported_tools.clone(),
                deprecated: false,
                replacement_pack: None,
            },
        );

        packs.insert(
            UseCase::Api,
            ToolchainPack {
                name: "api-core-pack".to_string(),
                use_case: UseCase::Api,
                tools: imported_tools.clone(),
                deprecated: false,
                replacement_pack: None,
            },
        );

        packs.insert(
            UseCase::MobileBackend,
            ToolchainPack {
                name: "mobile-backend-pack".to_string(),
                use_case: UseCase::MobileBackend,
                tools: imported_tools.clone(),
                deprecated: false,
                replacement_pack: None,
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
                tools: imported_tools.clone(),
                deprecated: false,
                replacement_pack: None,
            },
        );

        packs.insert(
            UseCase::BlockchainSmartContract,
            ToolchainPack {
                name: "smart-contract-pack".to_string(),
                use_case: UseCase::BlockchainSmartContract,
                tools: imported_tools,
                deprecated: false,
                replacement_pack: None,
            },
        );

        Self { packs }
    }
}

impl ToolchainPackRegistry {
    pub fn by_use_case(&self, use_case: &UseCase) -> Option<&ToolchainPack> {
        self.packs.get(use_case)
    }
}
