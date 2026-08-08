//! The staged, result-driven engagement pipeline (Stage-2 territory).
//!
//! The orchestrator produces one flat, class-ordered schedule, but a real
//! engagement is a feedback loop: discovery enumerates live hosts, services,
//! and URLs, and later stages must scan exactly those — not the bare target
//! id the plan started with. This module runs the schedule one execution
//! class at a time and, between classes, folds each stage's tool output into
//! a shared [`EngagementContext`]. Because the adapters consult that context
//! when building commands (see [`crate::tool_adapter::InvocationContext`]),
//! an active-network stage automatically aims at what the discovery stage
//! found.
//!
//! Extraction here is deliberately conservative and total: it reads
//! nmap/masscan XML into hosts and services, URL JSON-lines into endpoints,
//! and subdomain JSON-lines into hosts, and it silently ignores anything it
//! cannot parse (untrusted tool output must never panic the pipeline). All
//! parsing is bounded by [`MAX_ARTIFACTS_PER_REPORT`].

use crate::coordinator::ExecutionPlan;
use crate::engagement_context::{Endpoint, EngagementContext, Host, Service};
use crate::execution::{TaskExecutionOutcome, ToolExecutionReport};
use crate::expansion::FollowUpPlanner;
use crate::json::{self, JsonValue};
use crate::local_assets::LocalAgentAssets;
use crate::model::TestIntensity;
use crate::network_policy::NetworkMode;
use crate::observability::EventSink;
use crate::orchestrator::{OrchestrationSchedule, OrchestrationStep, ToolOrchestrator};
use crate::registry::ExecutionClass;
use crate::run_control::RunController;
use crate::runtime::{ExecutionRuntime, RunInputs};
use crate::scope::ScopePolicy;
use crate::secrets::SecretStore;
use crate::tool_adapter::AdapterRegistry;
use crate::tool_gate::ToolGate;
use std::collections::BTreeSet;
use std::sync::atomic::AtomicBool;

/// Hard cap on result-driven expansion rounds. The proposal universe
/// (discovered targets × a fixed follow-up table) is finite and each pair is
/// scheduled at most once, so expansion converges well before this; the cap is
/// a belt-and-suspenders guarantee of termination.
const MAX_EXPANSION_ROUNDS: usize = 6;

/// The order stages run in — least invasive first, mirroring the runtime's
/// class barrier. Discovery (static + active-network) precedes exploitation,
/// so exploitation sees everything discovery found.
const STAGE_ORDER: [ExecutionClass; 3] = [
    ExecutionClass::StaticLocalAnalysis,
    ExecutionClass::ActiveNetwork,
    ExecutionClass::ActiveExploitation,
];

/// Upper bound on artifacts extracted from a single tool report, mirroring
/// the ingest cap so untrusted output can't force unbounded growth.
const MAX_ARTIFACTS_PER_REPORT: usize = 10_000;

/// One execution class's worth of results within an engagement.
#[derive(Debug)]
pub struct StageOutcome {
    /// The execution class this stage ran.
    pub class: ExecutionClass,
    /// The per-tool outcomes produced by the stage.
    pub outcomes: Vec<TaskExecutionOutcome>,
}

/// The full result of a staged engagement: everything discovered plus the
/// per-stage outcomes.
#[derive(Debug)]
pub struct EngagementReport {
    /// The accumulated discovery blackboard after all stages ran.
    pub context: EngagementContext,
    /// The stages, in execution order. A class can appear more than once when
    /// result-driven expansion adds follow-up steps in a later round.
    pub stages: Vec<StageOutcome>,
    /// How many follow-up steps result-driven expansion added across the run.
    pub expansion_added: usize,
}

impl EngagementReport {
    /// Every outcome across all stages, in stage order.
    #[must_use]
    pub fn all_outcomes(&self) -> Vec<&TaskExecutionOutcome> {
        self.stages
            .iter()
            .flat_map(|stage| stage.outcomes.iter())
            .collect()
    }
}

/// Optional safety guards threaded through every stage of an engagement.
///
/// Egress-scope enforcement, secret resolution/redaction, and a live event
/// sink. All default to `None`, giving an unguarded run; the `--run-engagement`
/// command populates them from its flags and the engagement's declared scope.
#[derive(Clone, Copy, Default)]
pub struct EngagementGuards<'a> {
    /// Refuses any step whose resolved arguments carry an out-of-scope
    /// network target before it spawns (see [`crate::scope`]).
    pub scope: Option<&'a ScopePolicy>,
    /// Resolves `${secret:NAME}` references before spawning and redacts secret
    /// values from recorded output (see [`crate::secrets`]).
    pub secrets: Option<&'a SecretStore>,
    /// Receives stage/step lifecycle events as the run progresses (see
    /// [`crate::observability`]).
    pub events: Option<&'a dyn EventSink>,
    /// Refuses any step whose tool is not authorized for the engagement,
    /// before it spawns, failing closed (see [`crate::tool_gate`]).
    pub gate: Option<&'a ToolGate>,
    /// Live run control: when set, the engagement can be paused, resumed,
    /// cancelled, or rate-adjusted while it runs (see [`crate::run_control`]).
    pub controller: Option<&'a RunController>,
    /// Enables result-driven expansion: after each round, discovered assets
    /// propose authorized, in-scope follow-up tools that run in a later round
    /// (see [`crate::expansion`]). Off by default.
    pub expand: bool,
}

/// The fixed inputs of one run, bundled so the per-stage runner and the
/// expansion loop stay readable.
struct StageRunner<'a> {
    adapters: &'a AdapterRegistry,
    runtime: &'a ExecutionRuntime,
    assets: &'a LocalAgentAssets,
    operator_args: &'a [String],
    mode: NetworkMode,
    guards: EngagementGuards<'a>,
    never_cancel: &'a AtomicBool,
}

impl StageRunner<'_> {
    /// Runs one class's schedule through the runtime, applying the guards and
    /// the discovered `context`.
    fn execute(
        &self,
        schedule: &OrchestrationSchedule,
        context: &EngagementContext,
    ) -> Vec<TaskExecutionOutcome> {
        let mut inputs = RunInputs::new(
            schedule,
            self.adapters,
            self.assets,
            context,
            self.operator_args,
            self.mode,
        );
        if let Some(scope) = self.guards.scope {
            inputs = inputs.with_scope(scope);
        }
        if let Some(secrets) = self.guards.secrets {
            inputs = inputs.with_secrets(secrets);
        }
        if let Some(events) = self.guards.events {
            inputs = inputs.with_events(events);
        }
        if let Some(gate) = self.guards.gate {
            inputs = inputs.with_gate(gate);
        }
        self.guards.controller.map_or_else(
            || self.runtime.run_with_cancel(&inputs, self.never_cancel),
            |controller| self.runtime.run_controlled(&inputs, controller),
        )
    }
}

/// The `(target, tool)` identity of a step, used to deduplicate the schedule.
fn step_key(step: &OrchestrationStep) -> (String, String) {
    (step.target_id.clone(), step.tool.clone())
}

/// The highest task intensity in the plan, stamped on expanded steps.
fn max_task_intensity(plan: &ExecutionPlan) -> TestIntensity {
    plan.tasks
        .iter()
        .map(|task| task.intensity)
        .max_by_key(|intensity| intensity_rank(*intensity))
        .unwrap_or(TestIntensity::Standard)
}

const fn intensity_rank(intensity: TestIntensity) -> u8 {
    match intensity {
        TestIntensity::Passive => 0,
        TestIntensity::Standard => 1,
        TestIntensity::Aggressive => 2,
    }
}

/// Runs `plan` as a staged, result-driven engagement.
///
/// Each round runs the not-yet-executed steps one execution class at a time
/// (least invasive first), folding each stage's tool output into the
/// [`EngagementContext`] so later adapters target the discovered assets. When
/// `guards.expand` is set, the accumulated context then proposes authorized,
/// in-scope follow-up tools (see [`crate::expansion`]); any new steps run in
/// the next round, and this repeats until the schedule stops growing (bounded
/// by [`MAX_EXPANSION_ROUNDS`]). `guards` are applied to every stage.
#[must_use]
pub fn run_engagement_pipeline(
    plan: &ExecutionPlan,
    adapters: &AdapterRegistry,
    runtime: &ExecutionRuntime,
    assets: &LocalAgentAssets,
    operator_args: &[String],
    mode: NetworkMode,
    guards: EngagementGuards,
) -> EngagementReport {
    let never_cancel = AtomicBool::new(false);
    let runner = StageRunner {
        adapters,
        runtime,
        assets,
        operator_args,
        mode,
        guards,
        never_cancel: &never_cancel,
    };

    // Expansion may only schedule tools the engagement approved (the gate
    // allows) that are actually installed — it can never widen authorization.
    let authorized = |tool: &str| {
        guards.gate.is_none_or(|gate| gate.allows(tool)) && assets.tool(tool).is_some()
    };
    let planner = FollowUpPlanner::new(&authorized, guards.scope, max_task_intensity(plan));

    let mut working = ToolOrchestrator::new().schedule(plan).steps;
    let mut scheduled: BTreeSet<(String, String)> = working.iter().map(step_key).collect();
    let mut executed: BTreeSet<(String, String)> = BTreeSet::new();
    let mut context = EngagementContext::new();
    let mut stages = Vec::new();
    let mut expansion_added = 0;

    for _round in 0..MAX_EXPANSION_ROUNDS {
        for class in STAGE_ORDER {
            let steps: Vec<OrchestrationStep> = working
                .iter()
                .filter(|step| step.execution_class == class && !executed.contains(&step_key(step)))
                .cloned()
                .collect();
            if steps.is_empty() {
                continue;
            }
            for step in &steps {
                executed.insert(step_key(step));
            }
            let outcomes = runner.execute(&OrchestrationSchedule { steps }, &context);
            for outcome in &outcomes {
                if let Ok(report) = &outcome.result {
                    record_report_artifacts(&mut context, &outcome.tool, report);
                }
            }
            stages.push(StageOutcome { class, outcomes });
        }

        if !guards.expand {
            break;
        }
        let proposed = planner.propose(&context, &scheduled);
        if proposed.is_empty() {
            break;
        }
        expansion_added += proposed.len();
        for step in proposed {
            scheduled.insert(step_key(&step));
            working.push(step);
        }
    }

    EngagementReport {
        context,
        stages,
        expansion_added,
    }
}

/// Folds one tool's output into `context`, dispatching on the tool that
/// produced it. Unknown tools contribute nothing.
pub fn record_report_artifacts(
    context: &mut EngagementContext,
    tool: &str,
    report: &ToolExecutionReport,
) {
    match tool {
        "nmap" | "masscan" => extract_nmap_xml(context, &report.stdout),
        "gobuster" | "feroxbuster" | "ffuf" => extract_url_jsonl(context, &report.stdout),
        "subfinder" => extract_host_jsonl(context, &report.stdout),
        _ => {}
    }
}

/// Reads an attribute value `key="value"` out of `s`, or `None`.
fn attr<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=\"");
    let start = s.find(&needle)? + needle.len();
    let rest = &s[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Parses nmap/masscan XML into hosts and their open services. Tolerant of
/// malformed input: unparseable fragments are skipped, never fatal.
fn extract_nmap_xml(context: &mut EngagementContext, xml: &str) {
    let mut recorded = 0usize;
    // "<host " avoids matching "<hosthint"/"<hostnames".
    for host_block in xml.split("<host ").skip(1) {
        if recorded >= MAX_ARTIFACTS_PER_REPORT {
            break;
        }
        let Some(address) = attr(host_block, "addr") else {
            continue;
        };
        let hostname = host_block
            .split_once("<hostname ")
            .and_then(|(_, rest)| attr(rest, "name"))
            .map(str::to_string);
        context.record_host(Host {
            address: address.to_string(),
            hostname,
        });
        recorded += 1;

        for port_block in host_block.split("<port ").skip(1) {
            if recorded >= MAX_ARTIFACTS_PER_REPORT {
                break;
            }
            if !port_block.contains("state=\"open\"") {
                continue;
            }
            let protocol = attr(port_block, "protocol").unwrap_or("tcp");
            let Some(port) = attr(port_block, "portid").and_then(|p| p.parse::<u16>().ok()) else {
                continue;
            };
            let service = port_block
                .split_once("<service ")
                .and_then(|(_, rest)| attr(rest, "name"))
                .map(str::to_string);
            context.record_service(Service {
                host: address.to_string(),
                port,
                protocol: protocol.to_string(),
                service,
            });
            recorded += 1;
        }
    }
}

/// Parses JSON-lines carrying a `url` field into endpoints.
fn extract_url_jsonl(context: &mut EngagementContext, output: &str) {
    for line in output.lines().take(MAX_ARTIFACTS_PER_REPORT) {
        if let Some(url) = json::parse(line)
            .as_ref()
            .and_then(|value| value.get("url"))
            .and_then(JsonValue::as_str)
        {
            context.record_endpoint(Endpoint {
                url: url.to_string(),
            });
        }
    }
}

/// Parses JSON-lines carrying a `host` field (e.g. subfinder) into hosts.
fn extract_host_jsonl(context: &mut EngagementContext, output: &str) {
    for line in output.lines().take(MAX_ARTIFACTS_PER_REPORT) {
        if let Some(host) = json::parse(line)
            .as_ref()
            .and_then(|value| value.get("host"))
            .and_then(JsonValue::as_str)
        {
            context.record_host(Host {
                address: host.to_string(),
                hostname: Some(host.to_string()),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn report(tool: &str, stdout: &str) -> ToolExecutionReport {
        ToolExecutionReport {
            tool: tool.to_string(),
            arguments: Vec::new(),
            exit_code: Some(0),
            stdout: stdout.to_string(),
            stderr: String::new(),
            duration: Duration::from_millis(1),
        }
    }

    #[test]
    fn nmap_xml_yields_hosts_and_open_services() {
        let xml = r#"<nmaprun>
          <host starttime="1"><address addr="10.0.0.5" addrtype="ipv4"/>
            <hostname name="web-01"/>
            <ports>
              <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
              <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
            </ports>
          </host>
        </nmaprun>"#;
        let mut ctx = EngagementContext::new();
        record_report_artifacts(&mut ctx, "nmap", &report("nmap", xml));

        assert_eq!(ctx.hosts().len(), 1);
        assert_eq!(ctx.hosts()[0].address, "10.0.0.5");
        assert_eq!(ctx.hosts()[0].hostname.as_deref(), Some("web-01"));
        // Only the open port is recorded.
        assert_eq!(ctx.services().len(), 1);
        assert_eq!(ctx.services()[0].port, 443);
        assert_eq!(ctx.services()[0].service.as_deref(), Some("https"));
    }

    #[test]
    fn malformed_nmap_xml_is_ignored_not_panicked() {
        let mut ctx = EngagementContext::new();
        record_report_artifacts(
            &mut ctx,
            "nmap",
            &report("nmap", "<host <not xml portid=??"),
        );
        // No well-formed host address -> nothing recorded, no panic.
        assert!(ctx.is_empty() || ctx.services().is_empty());
    }

    #[test]
    fn url_jsonl_yields_endpoints_and_skips_junk() {
        let out = "{\"url\":\"https://app/login\"}\nnot json\n{\"nope\":1}\n{\"url\":\"https://app/admin\"}\n";
        let mut ctx = EngagementContext::new();
        record_report_artifacts(&mut ctx, "gobuster", &report("gobuster", out));
        assert_eq!(ctx.endpoints().len(), 2);
        assert_eq!(ctx.endpoints()[0].url, "https://app/login");
    }

    #[test]
    fn subfinder_hosts_are_recorded() {
        let out = "{\"host\":\"api.example.com\"}\n{\"host\":\"cdn.example.com\"}\n";
        let mut ctx = EngagementContext::new();
        record_report_artifacts(&mut ctx, "subfinder", &report("subfinder", out));
        assert_eq!(ctx.hosts().len(), 2);
        assert_eq!(ctx.hosts()[0].hostname.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn unknown_tool_records_nothing() {
        let mut ctx = EngagementContext::new();
        record_report_artifacts(&mut ctx, "semgrep", &report("semgrep", "{\"results\":[]}"));
        assert!(ctx.is_empty());
    }

    #[test]
    fn pipeline_runs_stages_and_returns_a_report() {
        use crate::model::{SpecialistKind, TestIntensity};
        use crate::registry::SpecialistCapability;

        // A plan whose task approves no locally-installed tools: the pipeline
        // still runs cleanly and returns an (empty) report.
        let task = crate::coordinator::ScanTask {
            target_id: "t1".to_string(),
            specialist: SpecialistCapability {
                specialist: SpecialistKind::Sast,
                target_types: Vec::new(),
                approved_tools: Vec::new(),
                supported_techniques: Vec::new(),
                max_intensity: TestIntensity::Passive,
            },
            techniques: Vec::new(),
            approved_tools: Vec::new(),
            intensity: TestIntensity::Passive,
            network_address: None,
        };
        let plan = ExecutionPlan {
            engagement_id: "eng-test".to_string(),
            workflow_stages: Vec::new(),
            tasks: vec![task],
            selected_packs: Vec::new(),
            high_impact_tasks: 0,
        };
        let assets = LocalAgentAssets {
            skills: Vec::new(),
            tools: Vec::new(),
        };
        let report = run_engagement_pipeline(
            &plan,
            &AdapterRegistry::with_defaults(),
            &ExecutionRuntime::default(),
            &assets,
            &[],
            NetworkMode::Offline,
            EngagementGuards::default(),
        );
        assert!(report.context.is_empty());
        assert!(report.all_outcomes().is_empty());
        assert_eq!(report.expansion_added, 0);
    }

    fn task_with_tools(target: &str, tools: Vec<String>) -> crate::coordinator::ScanTask {
        use crate::model::{SpecialistKind, TestIntensity};
        use crate::registry::SpecialistCapability;
        crate::coordinator::ScanTask {
            target_id: target.to_string(),
            specialist: SpecialistCapability {
                specialist: SpecialistKind::Sast,
                target_types: Vec::new(),
                approved_tools: tools.clone(),
                supported_techniques: Vec::new(),
                max_intensity: TestIntensity::Standard,
            },
            techniques: Vec::new(),
            approved_tools: tools,
            intensity: TestIntensity::Standard,
            network_address: Some("10.0.0.5".to_string()),
        }
    }

    #[test]
    fn expansion_enabled_terminates_and_adds_nothing_without_discovery() {
        // With expansion on but no installed tools, discovery finds nothing, so
        // there is nothing to expand — and the bounded loop terminates.
        let plan = ExecutionPlan {
            engagement_id: "eng-expand".to_string(),
            workflow_stages: Vec::new(),
            tasks: vec![task_with_tools("t1", vec!["nmap".to_string()])],
            selected_packs: Vec::new(),
            high_impact_tasks: 0,
        };
        let assets = LocalAgentAssets {
            skills: Vec::new(),
            tools: Vec::new(),
        };
        let guards = EngagementGuards {
            expand: true,
            ..EngagementGuards::default()
        };
        let report = run_engagement_pipeline(
            &plan,
            &AdapterRegistry::with_defaults(),
            &ExecutionRuntime::default(),
            &assets,
            &[],
            NetworkMode::Offline,
            guards,
        );
        assert_eq!(report.expansion_added, 0);
        assert!(report.context.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn expansion_runs_a_discovered_web_scanner_end_to_end() {
        use crate::integrity::IntegrityStatus;
        use crate::local_assets::LocalTool;
        use crate::model::{SpecialistKind, TestIntensity};
        use crate::registry::{SpecialistCapability, ToolDefinition, classify_execution};
        use crate::tool_gate::ToolGate;
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;

        if !Path::new("/bin/sh").exists() {
            return;
        }

        // Two real executables: a fake `nmap` that prints nmap XML announcing
        // an open HTTP service, and a `nikto` that just runs. Their arguments
        // are irrelevant — the runtime captures whatever they print to stdout.
        let dir = std::env::temp_dir().join(format!("sa-expand-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let nmap_path = dir.join("nmap");
        std::fs::write(
            &nmap_path,
            "#!/bin/sh\ncat <<'XML'\n<nmaprun><host addr=\"10.0.0.5\" addrtype=\"ipv4\">\
             <ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/>\
             <service name=\"http\"/></port></ports></host></nmaprun>\nXML\n",
        )
        .expect("write nmap");
        let nikto_path = dir.join("nikto");
        std::fs::write(&nikto_path, "#!/bin/sh\necho 'nikto ran'\n").expect("write nikto");
        for path in [&nmap_path, &nikto_path] {
            let mut perms = std::fs::metadata(path).expect("stat").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(path, perms).expect("chmod");
        }

        let local = |name: &str, path: &Path| LocalTool {
            definition: ToolDefinition {
                name: name.to_string(),
                version: "not-detected".to_string(),
                signed: false,
                vulnerability_reviewed: false,
                egress_policy: vec!["offline-local-only".to_string()],
                execution_class: classify_execution(name),
            },
            built_in: false,
            executable: Some(path.to_path_buf()),
            integrity: IntegrityStatus::Unpinned,
        };
        let assets = LocalAgentAssets {
            skills: Vec::new(),
            tools: vec![local("nmap", &nmap_path), local("nikto", &nikto_path)],
        };

        // The base plan approves only nmap; the gate additionally sanctions
        // nikto, so expansion may schedule it against the discovered host.
        let task = crate::coordinator::ScanTask {
            target_id: "10.0.0.5".to_string(),
            specialist: SpecialistCapability {
                specialist: SpecialistKind::Sast,
                target_types: Vec::new(),
                approved_tools: vec!["nmap".to_string()],
                supported_techniques: Vec::new(),
                max_intensity: TestIntensity::Standard,
            },
            techniques: Vec::new(),
            approved_tools: vec!["nmap".to_string()],
            intensity: TestIntensity::Standard,
            network_address: Some("10.0.0.5".to_string()),
        };
        let plan = ExecutionPlan {
            engagement_id: "eng-e2e".to_string(),
            workflow_stages: Vec::new(),
            tasks: vec![task],
            selected_packs: Vec::new(),
            high_impact_tasks: 0,
        };
        let gate = ToolGate::allow_only(["nmap", "nikto"]);
        let guards = EngagementGuards {
            gate: Some(&gate),
            expand: true,
            ..EngagementGuards::default()
        };

        let report = run_engagement_pipeline(
            &plan,
            &AdapterRegistry::with_defaults(),
            &ExecutionRuntime::default(),
            &assets,
            &[],
            NetworkMode::Online,
            guards,
        );

        // Discovery found the open HTTP service...
        assert!(
            report
                .context
                .services()
                .iter()
                .any(|s| s.host == "10.0.0.5" && s.port == 80)
        );
        // ...expansion proposed exactly the one authorized+installed web tool...
        assert_eq!(report.expansion_added, 1);
        // ...and that follow-up (nikto against the discovered host) actually ran.
        assert!(report.all_outcomes().iter().any(|outcome| {
            outcome.tool == "nikto" && outcome.target_id == "10.0.0.5" && outcome.result.is_ok()
        }));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
