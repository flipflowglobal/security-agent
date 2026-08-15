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
    #[must_use]
    pub const fn ordered() -> [Self; 6] {
        [
            Self::DiscoveryAndInventory,
            Self::PassiveReconAndConfigChecks,
            Self::SourceDependencyStaticAnalysis,
            Self::RuntimeAppAndApiScanning,
            Self::CloudContainerInfrastructurePosture,
            Self::CorrelationAndRiskScoring,
        ]
    }
}
