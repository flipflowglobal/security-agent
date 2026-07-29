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
use crate::json::{self, JsonValue};
use crate::local_assets::LocalAgentAssets;
use crate::network_policy::NetworkMode;
use crate::orchestrator::{OrchestrationSchedule, ToolOrchestrator};
use crate::registry::ExecutionClass;
use crate::runtime::ExecutionRuntime;
use crate::tool_adapter::AdapterRegistry;

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
    /// The stages, in execution order.
    pub stages: Vec<StageOutcome>,
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

/// Runs `plan` as a staged, result-driven engagement.
///
/// Each execution class runs in turn through `runtime`; between classes, the
/// completed stage's tool output is folded into the [`EngagementContext`] so
/// the next class's adapters target the discovered assets. Returns the
/// accumulated context and the per-stage outcomes.
#[must_use]
pub fn run_engagement_pipeline(
    plan: &ExecutionPlan,
    adapters: &AdapterRegistry,
    runtime: &ExecutionRuntime,
    assets: &LocalAgentAssets,
    operator_args: &[String],
    mode: NetworkMode,
) -> EngagementReport {
    let full = ToolOrchestrator::new().schedule(plan);
    let mut context = EngagementContext::new();
    let mut stages = Vec::with_capacity(STAGE_ORDER.len());

    for class in STAGE_ORDER {
        let class_schedule = schedule_for_class(&full, class);
        if class_schedule.is_empty() {
            continue;
        }
        let outcomes = runtime.run(
            &class_schedule,
            adapters,
            assets,
            &context,
            operator_args,
            mode,
        );
        // Fold this stage's discoveries in before the next stage plans.
        for outcome in &outcomes {
            if let Ok(report) = &outcome.result {
                record_report_artifacts(&mut context, &outcome.tool, report);
            }
        }
        stages.push(StageOutcome { class, outcomes });
    }

    EngagementReport { context, stages }
}

/// Builds the sub-schedule of `full` restricted to one execution class.
fn schedule_for_class(
    full: &OrchestrationSchedule,
    class: ExecutionClass,
) -> OrchestrationSchedule {
    OrchestrationSchedule {
        steps: full
            .steps
            .iter()
            .filter(|step| step.execution_class == class)
            .cloned()
            .collect(),
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
        );
        assert!(report.context.is_empty());
        assert!(report.all_outcomes().is_empty());
    }
}
