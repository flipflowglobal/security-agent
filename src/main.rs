//! Aureon MEV System — runnable security orchestration agent binary.
//!
//! Build for the host:
//!   cargo build --release
//!   cargo run
//!
//! Cross-compile for Android (arm64-v8a) using the NDK linker configured in
//! `.cargo/config.toml`:
//!   cargo build --release --target aarch64-linux-android
//!
//! Cross-compile for 32-bit ARM Android (armeabi-v7a):
//!   cargo build --release --target armv7-linux-androideabi
//!
//! The resulting binary can be pushed to an Android device via ADB (e.g. via
//! Termux) and executed directly — no JVM or framework required:
//!   adb push target/aarch64-linux-android/release/aureon_mev_system /data/local/tmp/
//!   adb shell chmod +x /data/local/tmp/aureon_mev_system
//!   adb shell /data/local/tmp/aureon_mev_system

use aureon_mev_system::{
    AttackPathGraph, CapabilityRegistry, Coordinator, EngagementProfile, Finding,
    MISSION_STATEMENT, PolicyEngine, ROADMAP_PHASES, RiskScoreCalculator, Severity, Target,
    TargetType, Technique, TestIntensity, TimeWindow, ToolchainPackRegistry,
    propose_retest_schedule,
};

fn main() {
    println!("========================================");
    println!("  Aureon MEV Security Orchestration Agent");
    println!("========================================");
    println!("Mission: {MISSION_STATEMENT}");
    println!();

    // ── Roadmap overview ────────────────────────────────────────────────────
    println!("--- Roadmap ---");
    for phase in &ROADMAP_PHASES {
        println!("  {}: {}", phase.phase, phase.focus);
    }
    println!();

    // ── Build an engagement profile covering all target types ────────────────
    let profile = EngagementProfile {
        engagement_id: "eng-demo-001".to_string(),
        authorized_by: "secops-team".to_string(),
        time_window: TimeWindow {
            start_epoch_seconds: 0,
            end_epoch_seconds: u64::MAX,
        },
        in_scope_targets: vec![
            "com.example.app".to_string(),
            "mobile-api.example.com".to_string(),
            "web-app.example.com".to_string(),
            "api.example.com".to_string(),
            "defi-contract.eth".to_string(),
            "src-repo".to_string(),
            "deps-manifest".to_string(),
            "cloud-infra".to_string(),
            "k8s-cluster".to_string(),
        ],
        allowed_techniques: vec![
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
            Technique::AndroidStaticAnalysis,
            Technique::MobileRuntime,
        ],
        deny_list_targets: vec!["prod-ledger".to_string()],
        max_intensity: TestIntensity::Aggressive,
        high_impact_approved: true,
        penetrative_testing_approved: true,
    };

    // ── Define targets including Android / mobile ───────────────────────────
    let targets = vec![
        Target {
            id: "com.example.app".to_string(),
            target_type: TargetType::MobileApp,
            criticality: 7,
        },
        Target {
            id: "mobile-api.example.com".to_string(),
            target_type: TargetType::MobileBackend,
            criticality: 6,
        },
        Target {
            id: "web-app.example.com".to_string(),
            target_type: TargetType::WebApp,
            criticality: 5,
        },
        Target {
            id: "api.example.com".to_string(),
            target_type: TargetType::Api,
            criticality: 5,
        },
        Target {
            id: "defi-contract.eth".to_string(),
            target_type: TargetType::Blockchain,
            criticality: 9,
        },
        Target {
            id: "src-repo".to_string(),
            target_type: TargetType::SourceCode,
            criticality: 4,
        },
        Target {
            id: "deps-manifest".to_string(),
            target_type: TargetType::DependencyManifest,
            criticality: 3,
        },
        Target {
            id: "cloud-infra".to_string(),
            target_type: TargetType::Cloud,
            criticality: 8,
        },
        Target {
            id: "k8s-cluster".to_string(),
            target_type: TargetType::Container,
            criticality: 7,
        },
    ];

    // ── Run the coordinator ──────────────────────────────────────────────────
    let mut coordinator = Coordinator::new(
        CapabilityRegistry::default(),
        ToolchainPackRegistry::default(),
        PolicyEngine::default(),
    );

    let now = 500u64;
    let plan = match coordinator.plan_authorized_scan(profile, targets, now) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Authorization error: {e:?}");
            std::process::exit(1);
        }
    };

    // ── Print execution plan ─────────────────────────────────────────────────
    println!("--- Execution Plan: {} ---", plan.engagement_id);
    println!(
        "Workflow stages: {}",
        plan.workflow_stages
            .iter()
            .map(|s| format!("{s:?}"))
            .collect::<Vec<_>>()
            .join(" → ")
    );
    println!("Total tasks : {}", plan.tasks.len());
    println!("High-impact : {}", plan.high_impact_tasks);
    println!("Toolchain packs selected: {}", plan.selected_packs.len());
    println!();

    for task in &plan.tasks {
        println!(
            "  [{}] specialist={:?}  techniques=[{}]  tools={}",
            task.target_id,
            task.specialist.specialist,
            task.techniques
                .iter()
                .map(|t| format!("{t:?}"))
                .collect::<Vec<_>>()
                .join(", "),
            task.approved_tools.len(),
        );
    }
    println!();

    // ── Simulate findings and score them ─────────────────────────────────────
    println!("--- Simulated Findings & Risk Scores ---");
    let raw_findings = [
        (
            "f-001",
            "mobsf",
            "Insecure data storage",
            "com.example.app",
            Severity::High,
            90u8,
            true,
        ),
        (
            "f-002",
            "frida",
            "Cleartext traffic",
            "com.example.app",
            Severity::Medium,
            80,
            false,
        ),
        (
            "f-003",
            "apkleaks",
            "Hardcoded API key in APK",
            "com.example.app",
            Severity::Critical,
            95,
            true,
        ),
        (
            "f-004",
            "nuclei",
            "JWT none algorithm accepted",
            "api.example.com",
            Severity::Critical,
            85,
            true,
        ),
        (
            "f-005",
            "nikto",
            "Outdated TLS version",
            "web-app.example.com",
            Severity::Medium,
            70,
            false,
        ),
        (
            "f-006",
            "slither",
            "Reentrancy vulnerability",
            "defi-contract.eth",
            Severity::Critical,
            99,
            true,
        ),
        (
            "f-007",
            "semgrep",
            "SQL injection vector",
            "src-repo",
            Severity::High,
            88,
            false,
        ),
        (
            "f-008",
            "trivy",
            "CVE in base image",
            "k8s-cluster",
            Severity::High,
            92,
            false,
        ),
    ];

    let findings: Vec<Finding> = raw_findings
        .iter()
        .map(|(id, tool, title, target, sev, conf, exploitable)| {
            let score = RiskScoreCalculator::normalized_score(*sev, *conf, *exploitable);
            Finding {
                finding_id: id.to_string(),
                source_tool: tool.to_string(),
                title: title.to_string(),
                target_id: target.to_string(),
                severity: *sev,
                confidence_percent: *conf,
                remediation_playbook: format!("remediate-{id}"),
                normalized_risk_score: score,
            }
        })
        .collect();

    for f in &findings {
        println!(
            "  [{}] {:?} | score={:.2} | {} | {}",
            f.finding_id, f.severity, f.normalized_risk_score, f.source_tool, f.title
        );
    }
    println!();

    // ── Retest schedule ───────────────────────────────────────────────────────
    println!("--- Retest Schedule ---");
    for f in &findings {
        let sched = propose_retest_schedule(f, now);
        let days = (sched.next_retest_epoch_seconds - now) / (60 * 60 * 24);
        println!(
            "  {} → retest in {} day(s)  ({})",
            f.target_id, days, sched.reason
        );
    }
    println!();

    // ── Attack-path graph ─────────────────────────────────────────────────────
    println!("--- Attack-Path Graph ---");
    let graph = AttackPathGraph::build_from_findings(&findings);
    println!("Nodes: {}", graph.nodes.len());
    for node in &graph.nodes {
        println!(
            "  [{}] role={} zone={}",
            node.node_id, node.role, node.trust_zone
        );
    }
    println!("Edges: {}", graph.edges.len());
    for edge in &graph.edges {
        println!("  {} --[{}]--> {}", edge.from, edge.technique, edge.to);
    }
    println!();

    // ── Audit ledger ──────────────────────────────────────────────────────────
    println!("--- Audit Ledger ---");
    for record in coordinator.audit_ledger.records() {
        println!(
            "  t={} actor={} action={} target={} | {}",
            record.timestamp_epoch_seconds,
            record.actor,
            record.action,
            record.target,
            record.details,
        );
    }
    println!();

    println!("Done. Agent run complete.");
}
