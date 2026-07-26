#[derive(Debug, Clone)]
pub struct RoadmapPhase {
    pub phase: &'static str,
    pub focus: &'static str,
}

pub const ROADMAP_PHASES: [RoadmapPhase; 4] = [
    RoadmapPhase {
        phase: "Phase 1",
        focus: "Coordinator, core scanners, and reporting",
    },
    RoadmapPhase {
        phase: "Phase 2",
        focus: "Cloud, container, and supply-chain specialists",
    },
    RoadmapPhase {
        phase: "Phase 3",
        focus: "Attack-path analytics and autonomous retesting",
    },
    RoadmapPhase {
        phase: "Phase 4",
        focus: "Organization-wide policy automation and continuous validation",
    },
];
