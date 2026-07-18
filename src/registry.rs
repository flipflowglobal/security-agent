use crate::model::{SpecialistKind, TargetType, Technique, TestIntensity};
use std::collections::HashMap;

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
                    approved_tools: vec!["rust-sast-core".to_string()],
                    supported_techniques: vec![Technique::Sast, Technique::SecretScan],
                    max_intensity: TestIntensity::Standard,
                },
                SpecialistCapability {
                    specialist: SpecialistKind::Dast,
                    target_types: vec![TargetType::WebApp],
                    approved_tools: vec!["runtime-probe".to_string()],
                    supported_techniques: vec![Technique::PassiveRecon, Technique::Dast],
                    max_intensity: TestIntensity::Aggressive,
                },
                SpecialistCapability {
                    specialist: SpecialistKind::ApiSecurity,
                    target_types: vec![TargetType::Api],
                    approved_tools: vec!["api-policy-scanner".to_string()],
                    supported_techniques: vec![Technique::PassiveRecon, Technique::ApiSecurity],
                    max_intensity: TestIntensity::Standard,
                },
                SpecialistCapability {
                    specialist: SpecialistKind::CloudIaC,
                    target_types: vec![TargetType::Cloud, TargetType::Infrastructure],
                    approved_tools: vec!["cloud-posture-checker".to_string()],
                    supported_techniques: vec![
                        Technique::ConfigurationAudit,
                        Technique::CloudPosture,
                    ],
                    max_intensity: TestIntensity::Standard,
                },
                SpecialistCapability {
                    specialist: SpecialistKind::ContainerK8s,
                    target_types: vec![TargetType::Container],
                    approved_tools: vec!["k8s-posture-checker".to_string()],
                    supported_techniques: vec![Technique::ContainerPosture],
                    max_intensity: TestIntensity::Standard,
                },
                SpecialistCapability {
                    specialist: SpecialistKind::DependencyRisk,
                    target_types: vec![TargetType::DependencyManifest],
                    approved_tools: vec!["supply-chain-auditor".to_string()],
                    supported_techniques: vec![Technique::DependencyAudit],
                    max_intensity: TestIntensity::Standard,
                },
                SpecialistCapability {
                    specialist: SpecialistKind::Secrets,
                    target_types: vec![TargetType::SourceCode, TargetType::Api, TargetType::WebApp],
                    approved_tools: vec!["secret-scan-core".to_string()],
                    supported_techniques: vec![Technique::SecretScan],
                    max_intensity: TestIntensity::Standard,
                },
                SpecialistCapability {
                    specialist: SpecialistKind::Malware,
                    target_types: vec![TargetType::SourceCode, TargetType::Container],
                    approved_tools: vec!["artifact-malware-scan".to_string()],
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
                    approved_tools: vec!["compliance-mapper".to_string()],
                    supported_techniques: vec![
                        Technique::ConfigurationAudit,
                        Technique::ThreatModeling,
                    ],
                    max_intensity: TestIntensity::Passive,
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

        packs.insert(
            UseCase::WebApp,
            ToolchainPack {
                name: "webapp-core-pack".to_string(),
                use_case: UseCase::WebApp,
                tools: vec![
                    ToolDefinition {
                        name: "runtime-probe".to_string(),
                        version: "1.0.0".to_string(),
                        signed: true,
                        vulnerability_reviewed: true,
                        egress_policy: vec!["https://target-domain-only".to_string()],
                    },
                    ToolDefinition {
                        name: "secret-scan-core".to_string(),
                        version: "1.0.0".to_string(),
                        signed: true,
                        vulnerability_reviewed: true,
                        egress_policy: vec!["none".to_string()],
                    },
                ],
                deprecated: false,
                replacement_pack: None,
            },
        );

        packs.insert(
            UseCase::Api,
            ToolchainPack {
                name: "api-core-pack".to_string(),
                use_case: UseCase::Api,
                tools: vec![ToolDefinition {
                    name: "api-policy-scanner".to_string(),
                    version: "1.0.0".to_string(),
                    signed: true,
                    vulnerability_reviewed: true,
                    egress_policy: vec!["https://approved-api-hosts".to_string()],
                }],
                deprecated: false,
                replacement_pack: None,
            },
        );

        packs.insert(
            UseCase::MobileBackend,
            ToolchainPack {
                name: "mobile-backend-pack".to_string(),
                use_case: UseCase::MobileBackend,
                tools: vec![ToolDefinition {
                    name: "backend-config-audit".to_string(),
                    version: "1.0.0".to_string(),
                    signed: true,
                    vulnerability_reviewed: true,
                    egress_policy: vec!["https://approved-backend-hosts".to_string()],
                }],
                deprecated: false,
                replacement_pack: None,
            },
        );

        packs.insert(
            UseCase::Cloud,
            ToolchainPack {
                name: "cloud-posture-pack".to_string(),
                use_case: UseCase::Cloud,
                tools: vec![ToolDefinition {
                    name: "cloud-posture-checker".to_string(),
                    version: "1.0.0".to_string(),
                    signed: true,
                    vulnerability_reviewed: true,
                    egress_policy: vec!["cloud-control-plane-only".to_string()],
                }],
                deprecated: false,
                replacement_pack: None,
            },
        );

        packs.insert(
            UseCase::BlockchainSmartContract,
            ToolchainPack {
                name: "smart-contract-pack".to_string(),
                use_case: UseCase::BlockchainSmartContract,
                tools: vec![ToolDefinition {
                    name: "contract-static-analyzer".to_string(),
                    version: "1.0.0".to_string(),
                    signed: true,
                    vulnerability_reviewed: true,
                    egress_policy: vec!["chain-rpc-allowlist".to_string()],
                }],
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
