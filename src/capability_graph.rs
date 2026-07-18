use crate::model::TargetType;
use crate::registry::{CapabilityRegistry, ToolchainPackRegistry, UseCase};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionFamily {
    DiscoveryInventory,
    StaticSourceDependencyAnalysis,
    RuntimeAppApiMobileCloudContainerChecks,
    FindingNormalizationRiskScoring,
    AttackPathCorrelationRetestScheduling,
    RemediationVerificationLoop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityStage {
    Discovery,
    Analysis,
    Validation,
    Correlation,
    Remediation,
}

#[derive(Debug, Clone)]
pub struct CapabilityNode {
    pub stage: CapabilityStage,
    pub depends_on: Vec<CapabilityStage>,
}

#[derive(Debug, Clone)]
pub struct CapabilityGraph {
    pub nodes: Vec<CapabilityNode>,
}

impl Default for CapabilityGraph {
    fn default() -> Self {
        Self {
            nodes: vec![
                CapabilityNode {
                    stage: CapabilityStage::Discovery,
                    depends_on: vec![],
                },
                CapabilityNode {
                    stage: CapabilityStage::Analysis,
                    depends_on: vec![CapabilityStage::Discovery],
                },
                CapabilityNode {
                    stage: CapabilityStage::Validation,
                    depends_on: vec![CapabilityStage::Analysis],
                },
                CapabilityNode {
                    stage: CapabilityStage::Correlation,
                    depends_on: vec![CapabilityStage::Validation],
                },
                CapabilityNode {
                    stage: CapabilityStage::Remediation,
                    depends_on: vec![CapabilityStage::Correlation],
                },
            ],
        }
    }
}

impl CapabilityGraph {
    pub fn function_first_order() -> [FunctionFamily; 6] {
        [
            FunctionFamily::DiscoveryInventory,
            FunctionFamily::StaticSourceDependencyAnalysis,
            FunctionFamily::RuntimeAppApiMobileCloudContainerChecks,
            FunctionFamily::FindingNormalizationRiskScoring,
            FunctionFamily::AttackPathCorrelationRetestScheduling,
            FunctionFamily::RemediationVerificationLoop,
        ]
    }

    pub fn validate_coverage(
        capability_registry: &CapabilityRegistry,
        pack_registry: &ToolchainPackRegistry,
    ) -> Result<(), String> {
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
            if capability_registry
                .capabilities_for_target(&target_type)
                .is_empty()
            {
                return Err(format!(
                    "No specialist coverage for target type: {target_type:?}"
                ));
            }

            let use_case = match target_type {
                TargetType::WebApp => UseCase::WebApp,
                TargetType::Api => UseCase::Api,
                TargetType::MobileBackend => UseCase::MobileBackend,
                TargetType::MobileApp => UseCase::MobileApp,
                TargetType::Cloud | TargetType::Container | TargetType::Infrastructure => {
                    UseCase::Cloud
                }
                TargetType::Blockchain => UseCase::BlockchainSmartContract,
                TargetType::SourceCode | TargetType::DependencyManifest => UseCase::WebApp,
            };
            if pack_registry.by_use_case(&use_case).is_none() {
                return Err(format!(
                    "No toolchain pack coverage for use case: {use_case:?}"
                ));
            }
        }
        Ok(())
    }
}
