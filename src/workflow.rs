#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkflowStage {
    DiscoveryAndInventory,
    PassiveReconAndConfigChecks,
    SourceDependencyStaticAnalysis,
    RuntimeAppAndApiScanning,
    CloudContainerInfrastructurePosture,
    CorrelationAndRiskScoring,
}

impl WorkflowStage {
    pub fn ordered() -> [WorkflowStage; 6] {
        [
            WorkflowStage::DiscoveryAndInventory,
            WorkflowStage::PassiveReconAndConfigChecks,
            WorkflowStage::SourceDependencyStaticAnalysis,
            WorkflowStage::RuntimeAppAndApiScanning,
            WorkflowStage::CloudContainerInfrastructurePosture,
            WorkflowStage::CorrelationAndRiskScoring,
        ]
    }
}
