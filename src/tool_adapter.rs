//! The per-tool invocation model: how a scheduled step becomes a concrete
//! command line, and what its output will look like.
//!
//! `execute_plan`'s original contract applied one shared argument list to
//! every tool in a plan and only ever prepended a target address. That is
//! fine for a demo but cannot actually drive a real toolchain, where nmap,
//! sqlmap, and semgrep each need entirely different arguments and each emit
//! output in a different place and format. This module introduces a
//! [`ToolAdapter`] per cataloged tool that builds a [`ToolInvocation`] — the
//! exact `argv`, where results land, and in what format — from the
//! authorized [`OrchestrationStep`] plus whatever the engagement has already
//! discovered.
//!
//! This is **Stage-1 territory** (real per-tool invocation). Adapters are
//! pure: they translate authorized intent into a command, they never decide
//! authorization or egress — the [`crate::policy`] and
//! [`crate::network_policy`] gates still own that. **Every cataloged tool has
//! an adapter**: the tools with rich behavior (intensity mapping,
//! discovered-target selection) have hand-written adapters, and the rest are
//! covered by a declarative [`ToolSpec`] table driving a single
//! [`SpecAdapter`]. The `every_cataloged_tool_has_a_registered_adapter` test
//! enforces that coverage against [`crate::registry::cataloged_tool_names`].
//! A name outside the catalog still resolves to a conservative fallback (the
//! historical prepend-address behavior), so nothing ever runs uncommanded.

use crate::engagement_context::EngagementContext;
use crate::model::TestIntensity;
use crate::orchestrator::OrchestrationStep;
use crate::registry::{ExecutionClass, classify_execution};
use std::path::PathBuf;

/// Where a tool writes the results this crate will ingest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputChannel {
    /// Results are captured from the tool's standard output.
    Stdout,
    /// Results are written to a file at this path (e.g. `-oX out.xml`).
    File(PathBuf),
}

/// The shape of a tool's result output, so the findings pipeline knows how
/// to parse it. Extend this as adapters for new tools are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// `semgrep --json`.
    SemgrepJson,
    /// SARIF (`runs[].results[]`), e.g. `nuclei -sarif`.
    Sarif,
    /// One JSON object per line.
    JsonLines,
    /// nmap/masscan XML (`-oX`).
    NmapXml,
    /// Unstructured text with no registered parser.
    PlainText,
}

/// A fully-resolved command to run one tool for one authorized step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInvocation {
    /// The cataloged tool name (matches [`OrchestrationStep::tool`]).
    pub tool: String,
    /// The exact arguments to pass, in order. Does not include the binary.
    pub argv: Vec<String>,
    /// Where the tool's ingestible output will be.
    pub output: OutputChannel,
    /// The format of that output.
    pub format: OutputFormat,
}

/// Everything an adapter may consult when building an invocation.
///
/// Borrows the [`EngagementContext`] so an adapter can, for example, aim a
/// web scanner at the endpoints discovery already found instead of a bare
/// target id.
pub struct InvocationContext<'a> {
    /// The authorized target this step runs against.
    pub target_id: &'a str,
    /// The live address the step binds to, if any (already withheld for
    /// static-local steps by the orchestrator).
    pub network_address: Option<&'a str>,
    /// The intensity ceiling for this step.
    pub intensity: TestIntensity,
    /// Operator-supplied extra arguments (from `--execute <args>`), appended
    /// after the adapter's own arguments.
    pub operator_args: &'a [String],
    /// What the engagement has discovered so far.
    pub engagement: &'a EngagementContext,
}

impl InvocationContext<'_> {
    /// The single network host this step should act on: the bound address if
    /// present, otherwise the target id. Host/network tools (nmap, masscan)
    /// use this.
    #[must_use]
    pub fn network_target(&self) -> &str {
        self.network_address.unwrap_or(self.target_id)
    }

    /// The web URLs a web/API scanner should visit, in priority order:
    /// endpoints discovery already found; else HTTP(S) services promoted to
    /// URLs; else a single synthesized URL for the bound address/target. The
    /// result is never empty, so a web adapter always has something to scan.
    #[must_use]
    pub fn web_targets(&self) -> Vec<String> {
        let endpoints = self.engagement.endpoints();
        if !endpoints.is_empty() {
            return endpoints.iter().map(|e| e.url.clone()).collect();
        }
        let from_services: Vec<String> = self
            .engagement
            .services()
            .iter()
            .filter_map(service_to_url)
            .collect();
        if !from_services.is_empty() {
            return from_services;
        }
        vec![format!("http://{}", self.network_target())]
    }

    /// The first web target (for tools that take a single `-u URL`).
    #[must_use]
    pub fn primary_web_target(&self) -> String {
        self.web_targets()
            .into_iter()
            .next()
            .unwrap_or_else(|| format!("http://{}", self.network_target()))
    }
}

/// Promotes an HTTP(S)-looking service to a base URL, or `None` for
/// non-web services.
fn service_to_url(service: &crate::engagement_context::Service) -> Option<String> {
    let name = service.service.as_deref().unwrap_or("");
    let (scheme, is_web) = match (name, service.port) {
        (n, _) if n.contains("https") => ("https", true),
        (n, _) if n.contains("http") => ("http", true),
        (_, 443 | 8443) => ("https", true),
        (_, 80 | 8080 | 8000) => ("http", true),
        _ => ("http", false),
    };
    is_web.then(|| format!("{scheme}://{}:{}", service.host, service.port))
}

/// Translates an authorized step into a concrete [`ToolInvocation`] for one
/// specific tool.
pub trait ToolAdapter: Send + Sync {
    /// The cataloged tool name this adapter builds commands for.
    fn tool_name(&self) -> &'static str;
    /// The format this tool's ingestible output takes.
    fn output_format(&self) -> OutputFormat;
    /// Builds the command line for `ctx`.
    fn build(&self, ctx: &InvocationContext) -> ToolInvocation;
}

/// Registry of per-tool adapters with a conservative fallback.
pub struct AdapterRegistry {
    adapters: Vec<Box<dyn ToolAdapter>>,
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl AdapterRegistry {
    /// An empty registry (only the built-in fallback applies).
    #[must_use]
    pub fn new() -> Self {
        Self {
            adapters: Vec::new(),
        }
    }

    /// A registry seeded with an adapter for every cataloged tool — bespoke
    /// adapters for the tools with rich behavior, and the [`CATALOG_SPECS`]
    /// spec table for the rest. Only names outside the catalog use the
    /// fallback.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(SemgrepAdapter));
        registry.register(Box::new(JadxAdapter));
        registry.register(Box::new(NmapAdapter));
        registry.register(Box::new(MasscanAdapter));
        registry.register(Box::new(NucleiAdapter));
        registry.register(Box::new(GobusterAdapter));
        registry.register(Box::new(FeroxbusterAdapter));
        registry.register(Box::new(FfufAdapter));
        registry.register(Box::new(NiktoAdapter));
        registry.register(Box::new(WhatwebAdapter));
        registry.register(Box::new(WpscanAdapter));
        registry.register(Box::new(SubfinderAdapter));
        registry.register(Box::new(SqlmapAdapter));
        registry.register(Box::new(HydraAdapter));
        // Every remaining cataloged tool gets a spec-driven adapter, so the
        // registry covers the whole catalog rather than falling back.
        for spec in CATALOG_SPECS {
            registry.register(Box::new(SpecAdapter(spec)));
        }
        registry
    }

    /// Adds an adapter, replacing any existing adapter for the same tool.
    pub fn register(&mut self, adapter: Box<dyn ToolAdapter>) {
        let name = adapter.tool_name();
        self.adapters
            .retain(|existing| existing.tool_name() != name);
        self.adapters.push(adapter);
    }

    /// Looks up the adapter registered for `tool`, if any.
    #[must_use]
    pub fn adapter_for(&self, tool: &str) -> Option<&dyn ToolAdapter> {
        self.adapters
            .iter()
            .find(|adapter| adapter.tool_name() == tool)
            .map(AsRef::as_ref)
    }

    /// Builds the invocation for `step`, using the step's registered adapter
    /// or the conservative fallback when none is registered.
    #[must_use]
    pub fn invocation_for(
        &self,
        step: &OrchestrationStep,
        ctx: &InvocationContext,
    ) -> ToolInvocation {
        self.adapter_for(&step.tool).map_or_else(
            || fallback_invocation(&step.tool, ctx),
            |adapter| adapter.build(ctx),
        )
    }
}

/// The historical behavior, preserved for un-adapted tools: prepend the
/// network address (for non-static tools) then the operator's own arguments,
/// capture stdout, and treat the output as unstructured.
fn fallback_invocation(tool: &str, ctx: &InvocationContext) -> ToolInvocation {
    let is_network_tool = classify_execution(tool) != ExecutionClass::StaticLocalAnalysis;
    let mut argv = Vec::new();
    if is_network_tool {
        if let Some(address) = ctx.network_address {
            argv.push(address.to_string());
        }
    }
    argv.extend_from_slice(ctx.operator_args);
    ToolInvocation {
        tool: tool.to_string(),
        argv,
        output: OutputChannel::Stdout,
        format: OutputFormat::PlainText,
    }
}

/// Appends the operator's override arguments and returns the finished
/// invocation — the shared tail of every adapter so operator args always win.
fn finish(
    tool: &'static str,
    mut argv: Vec<String>,
    output: OutputChannel,
    format: OutputFormat,
    ctx: &InvocationContext,
) -> ToolInvocation {
    argv.extend_from_slice(ctx.operator_args);
    ToolInvocation {
        tool: tool.to_string(),
        argv,
        output,
        format,
    }
}

// ---------------------------------------------------------------------------
// Static local analysis
// ---------------------------------------------------------------------------

/// `semgrep` static analysis over the local target, emitting JSON on stdout.
struct SemgrepAdapter;
impl ToolAdapter for SemgrepAdapter {
    fn tool_name(&self) -> &'static str {
        "semgrep"
    }
    fn output_format(&self) -> OutputFormat {
        OutputFormat::SemgrepJson
    }
    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let argv = vec![
            "--json".to_string(),
            "--quiet".to_string(),
            "--config".to_string(),
            "auto".to_string(),
        ];
        finish(
            self.tool_name(),
            argv,
            OutputChannel::Stdout,
            self.output_format(),
            ctx,
        )
    }
}

/// `jadx` Android APK decompilation (static, local file). Output is a
/// decompiled tree, not a findings stream, so it is `PlainText`.
struct JadxAdapter;
impl ToolAdapter for JadxAdapter {
    fn tool_name(&self) -> &'static str {
        "jadx"
    }
    fn output_format(&self) -> OutputFormat {
        OutputFormat::PlainText
    }
    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let argv = vec![
            "--no-res".to_string(),
            "-d".to_string(),
            "jadx-out".to_string(),
        ];
        finish(
            self.tool_name(),
            argv,
            OutputChannel::Stdout,
            self.output_format(),
            ctx,
        )
    }
}

// ---------------------------------------------------------------------------
// Active network — host/service discovery and web scanning
// ---------------------------------------------------------------------------

/// Maps intensity onto nmap's `-T` timing template.
const fn nmap_timing(intensity: TestIntensity) -> &'static str {
    match intensity {
        TestIntensity::Passive => "-T2",
        TestIntensity::Standard => "-T3",
        TestIntensity::Aggressive => "-T4",
    }
}

/// `nmap` service/version discovery against the bound host, XML on stdout.
struct NmapAdapter;
impl ToolAdapter for NmapAdapter {
    fn tool_name(&self) -> &'static str {
        "nmap"
    }
    fn output_format(&self) -> OutputFormat {
        OutputFormat::NmapXml
    }
    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let argv = vec![
            "-sV".to_string(),
            nmap_timing(ctx.intensity).to_string(),
            "-oX".to_string(),
            "-".to_string(),
            ctx.network_target().to_string(),
        ];
        finish(
            self.tool_name(),
            argv,
            OutputChannel::Stdout,
            self.output_format(),
            ctx,
        )
    }
}

/// `masscan` fast port sweep; emits nmap-compatible XML on stdout. Rate
/// scales with intensity to stay within an authorized load.
struct MasscanAdapter;
impl ToolAdapter for MasscanAdapter {
    fn tool_name(&self) -> &'static str {
        "masscan"
    }
    fn output_format(&self) -> OutputFormat {
        OutputFormat::NmapXml
    }
    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let rate = match ctx.intensity {
            TestIntensity::Passive => "100",
            TestIntensity::Standard => "1000",
            TestIntensity::Aggressive => "10000",
        };
        let argv = vec![
            ctx.network_target().to_string(),
            "-p1-65535".to_string(),
            "--rate".to_string(),
            rate.to_string(),
            "-oX".to_string(),
            "-".to_string(),
        ];
        finish(
            self.tool_name(),
            argv,
            OutputChannel::Stdout,
            self.output_format(),
            ctx,
        )
    }
}

/// `nuclei` templated vulnerability scan over discovered web targets,
/// JSON-lines on stdout.
struct NucleiAdapter;
impl ToolAdapter for NucleiAdapter {
    fn tool_name(&self) -> &'static str {
        "nuclei"
    }
    fn output_format(&self) -> OutputFormat {
        OutputFormat::JsonLines
    }
    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let mut argv = vec!["-jsonl".to_string(), "-silent".to_string()];
        if matches!(ctx.intensity, TestIntensity::Passive) {
            argv.push("-severity".to_string());
            argv.push("low,medium,high,critical".to_string());
        }
        for target in ctx.web_targets() {
            argv.push("-u".to_string());
            argv.push(target);
        }
        finish(
            self.tool_name(),
            argv,
            OutputChannel::Stdout,
            self.output_format(),
            ctx,
        )
    }
}

/// `gobuster dir` content discovery against the primary web target,
/// JSON-lines on stdout.
struct GobusterAdapter;
impl ToolAdapter for GobusterAdapter {
    fn tool_name(&self) -> &'static str {
        "gobuster"
    }
    fn output_format(&self) -> OutputFormat {
        OutputFormat::JsonLines
    }
    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let threads = intensity_threads(ctx.intensity);
        let argv = vec![
            "dir".to_string(),
            "-q".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "-t".to_string(),
            threads.to_string(),
            "-u".to_string(),
            ctx.primary_web_target(),
        ];
        finish(
            self.tool_name(),
            argv,
            OutputChannel::Stdout,
            self.output_format(),
            ctx,
        )
    }
}

/// `feroxbuster` recursive content discovery, JSON-lines on stdout.
struct FeroxbusterAdapter;
impl ToolAdapter for FeroxbusterAdapter {
    fn tool_name(&self) -> &'static str {
        "feroxbuster"
    }
    fn output_format(&self) -> OutputFormat {
        OutputFormat::JsonLines
    }
    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let argv = vec![
            "--silent".to_string(),
            "--json".to_string(),
            "-t".to_string(),
            intensity_threads(ctx.intensity).to_string(),
            "-u".to_string(),
            ctx.primary_web_target(),
        ];
        finish(
            self.tool_name(),
            argv,
            OutputChannel::Stdout,
            self.output_format(),
            ctx,
        )
    }
}

/// `ffuf` path fuzzing against the primary web target, JSON to stdout.
struct FfufAdapter;
impl ToolAdapter for FfufAdapter {
    fn tool_name(&self) -> &'static str {
        "ffuf"
    }
    fn output_format(&self) -> OutputFormat {
        OutputFormat::JsonLines
    }
    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let base = ctx.primary_web_target();
        let argv = vec![
            "-s".to_string(),
            "-of".to_string(),
            "json".to_string(),
            "-o".to_string(),
            "-".to_string(),
            "-t".to_string(),
            intensity_threads(ctx.intensity).to_string(),
            "-u".to_string(),
            format!("{}/FUZZ", base.trim_end_matches('/')),
        ];
        finish(
            self.tool_name(),
            argv,
            OutputChannel::Stdout,
            self.output_format(),
            ctx,
        )
    }
}

/// `nikto` web server misconfiguration scan; JSON to stdout.
struct NiktoAdapter;
impl ToolAdapter for NiktoAdapter {
    fn tool_name(&self) -> &'static str {
        "nikto"
    }
    fn output_format(&self) -> OutputFormat {
        OutputFormat::JsonLines
    }
    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let argv = vec![
            "-Format".to_string(),
            "json".to_string(),
            "-output".to_string(),
            "-".to_string(),
            "-host".to_string(),
            ctx.primary_web_target(),
        ];
        finish(
            self.tool_name(),
            argv,
            OutputChannel::Stdout,
            self.output_format(),
            ctx,
        )
    }
}

/// `whatweb` technology fingerprinting; JSON to stdout.
struct WhatwebAdapter;
impl ToolAdapter for WhatwebAdapter {
    fn tool_name(&self) -> &'static str {
        "whatweb"
    }
    fn output_format(&self) -> OutputFormat {
        OutputFormat::JsonLines
    }
    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let aggression = match ctx.intensity {
            TestIntensity::Passive => "--aggression=1",
            TestIntensity::Standard => "--aggression=3",
            TestIntensity::Aggressive => "--aggression=4",
        };
        let argv = vec![
            aggression.to_string(),
            "--log-json=-".to_string(),
            ctx.primary_web_target(),
        ];
        finish(
            self.tool_name(),
            argv,
            OutputChannel::Stdout,
            self.output_format(),
            ctx,
        )
    }
}

/// `wpscan` `WordPress` audit; JSON to stdout.
struct WpscanAdapter;
impl ToolAdapter for WpscanAdapter {
    fn tool_name(&self) -> &'static str {
        "wpscan"
    }
    fn output_format(&self) -> OutputFormat {
        OutputFormat::JsonLines
    }
    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let argv = vec![
            "--format".to_string(),
            "json".to_string(),
            "--no-banner".to_string(),
            "--url".to_string(),
            ctx.primary_web_target(),
        ];
        finish(
            self.tool_name(),
            argv,
            OutputChannel::Stdout,
            self.output_format(),
            ctx,
        )
    }
}

/// `subfinder` passive subdomain enumeration for the target; JSON-lines.
struct SubfinderAdapter;
impl ToolAdapter for SubfinderAdapter {
    fn tool_name(&self) -> &'static str {
        "subfinder"
    }
    fn output_format(&self) -> OutputFormat {
        OutputFormat::JsonLines
    }
    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let argv = vec![
            "-silent".to_string(),
            "-oJ".to_string(),
            "-d".to_string(),
            ctx.network_target().to_string(),
        ];
        finish(
            self.tool_name(),
            argv,
            OutputChannel::Stdout,
            self.output_format(),
            ctx,
        )
    }
}

// ---------------------------------------------------------------------------
// Active exploitation
// ---------------------------------------------------------------------------

/// `sqlmap` SQL-injection testing against a discovered web target. `--batch`
/// keeps it non-interactive; the injection `--level`/`--risk` scale with
/// intensity. Output is a report tree/log, so `PlainText`.
struct SqlmapAdapter;
impl ToolAdapter for SqlmapAdapter {
    fn tool_name(&self) -> &'static str {
        "sqlmap"
    }
    fn output_format(&self) -> OutputFormat {
        OutputFormat::PlainText
    }
    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let (level, risk) = match ctx.intensity {
            TestIntensity::Passive => ("1", "1"),
            TestIntensity::Standard => ("2", "1"),
            TestIntensity::Aggressive => ("3", "2"),
        };
        let argv = vec![
            "--batch".to_string(),
            "--level".to_string(),
            level.to_string(),
            "--risk".to_string(),
            risk.to_string(),
            "-u".to_string(),
            ctx.primary_web_target(),
        ];
        finish(
            self.tool_name(),
            argv,
            OutputChannel::Stdout,
            self.output_format(),
            ctx,
        )
    }
}

/// `hydra` online credential attack against the bound host. The service must
/// be supplied by the operator (e.g. `ssh`), so this leaves the module to
/// `operator_args` and only wires the target + parallelism. `PlainText`.
struct HydraAdapter;
impl ToolAdapter for HydraAdapter {
    fn tool_name(&self) -> &'static str {
        "hydra"
    }
    fn output_format(&self) -> OutputFormat {
        OutputFormat::PlainText
    }
    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let tasks = match ctx.intensity {
            TestIntensity::Passive => "1",
            TestIntensity::Standard => "4",
            TestIntensity::Aggressive => "16",
        };
        let argv = vec![
            "-t".to_string(),
            tasks.to_string(),
            ctx.network_target().to_string(),
        ];
        finish(
            self.tool_name(),
            argv,
            OutputChannel::Stdout,
            self.output_format(),
            ctx,
        )
    }
}

/// Thread/parallelism count scaled by intensity, shared by the content and
/// fuzzing scanners.
const fn intensity_threads(intensity: TestIntensity) -> u8 {
    match intensity {
        TestIntensity::Passive => 5,
        TestIntensity::Standard => 20,
        TestIntensity::Aggressive => 50,
    }
}

// ---------------------------------------------------------------------------
// Spec-driven adapters for the rest of the catalog
// ---------------------------------------------------------------------------

/// How a [`ToolSpec`] positions its target in the argument list.
#[derive(Debug, Clone, Copy)]
enum ArgShape {
    /// Append the authorized network host/address as the positional target
    /// (recon/scan tools that take a host or range).
    NetworkHost,
    /// Append the primary discovered web URL (web scanners/crawlers).
    WebUrl,
    /// Append the target id, treated as a local file or image path
    /// (forensic/static-analysis/cracking tools that operate on a file).
    LocalPath,
    /// No positional target — the tool runs against an interface, a wordlist,
    /// or a fixed local scope, or is launched interactively. Operator
    /// arguments still apply.
    NoTarget,
}

/// A declarative adapter definition for a cataloged tool: its fixed leading
/// arguments, where the target goes, and the format of its output.
#[derive(Debug, Clone, Copy)]
struct ToolSpec {
    name: &'static str,
    format: OutputFormat,
    shape: ArgShape,
    fixed: &'static [&'static str],
}

/// A [`ToolAdapter`] built from a [`ToolSpec`]: fixed args, then the target
/// (per the spec's shape), then the operator's overrides.
struct SpecAdapter(&'static ToolSpec);

impl ToolAdapter for SpecAdapter {
    fn tool_name(&self) -> &'static str {
        self.0.name
    }

    fn output_format(&self) -> OutputFormat {
        self.0.format
    }

    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let spec = self.0;
        let mut argv: Vec<String> = spec.fixed.iter().map(|arg| (*arg).to_string()).collect();
        match spec.shape {
            ArgShape::NetworkHost => argv.push(ctx.network_target().to_string()),
            ArgShape::WebUrl => argv.push(ctx.primary_web_target()),
            ArgShape::LocalPath => argv.push(ctx.target_id.to_string()),
            ArgShape::NoTarget => {}
        }
        argv.extend_from_slice(ctx.operator_args);
        ToolInvocation {
            tool: spec.name.to_string(),
            argv,
            output: OutputChannel::Stdout,
            format: spec.format,
        }
    }
}

/// A spec-table entry — keeps [`CATALOG_SPECS`] compact and readable.
const fn spec(name: &'static str, shape: ArgShape, fixed: &'static [&'static str]) -> ToolSpec {
    ToolSpec {
        name,
        format: OutputFormat::PlainText,
        shape,
        fixed,
    }
}

/// A spec-driven adapter for every cataloged tool that does not already have
/// a bespoke adapter above. The fixed arguments reflect each tool's primary
/// non-interactive invocation; the shape places the authorized target; and
/// the operator's `--execute` arguments are appended last. Tools that are
/// interface-, wordlist-, or GUI-driven use [`ArgShape::NoTarget`].
static CATALOG_SPECS: &[ToolSpec] = &[
    // --- Digital forensics / local-file analysis (target = a file/image) ---
    spec("autopsy", ArgShape::NoTarget, &[]),
    spec("volatility", ArgShape::LocalPath, &["-f"]),
    spec("binwalk", ArgShape::LocalPath, &["-e"]),
    spec("bulk_extractor", ArgShape::LocalPath, &["-o", "bulk-out"]),
    spec(
        "foremost",
        ArgShape::LocalPath,
        &["-o", "foremost-out", "-i"],
    ),
    spec("hashdeep", ArgShape::LocalPath, &["-r"]),
    spec("galleta", ArgShape::LocalPath, &[]),
    spec("mdb-sql", ArgShape::LocalPath, &[]),
    spec("sqlitebrowser", ArgShape::LocalPath, &[]),
    spec("chkrootkit", ArgShape::NoTarget, &[]),
    spec("lynis", ArgShape::NoTarget, &["audit", "system"]),
    spec("keepnote", ArgShape::NoTarget, &[]),
    spec("recordmydesktop", ArgShape::NoTarget, &[]),
    spec("cutycapt", ArgShape::NoTarget, &[]),
    // --- Network capture / MITM (interface-driven) ---
    spec("wireshark", ArgShape::LocalPath, &["-r"]),
    spec(
        "tcpdump",
        ArgShape::NoTarget,
        &["-c", "100", "-w", "tcpdump.pcap"],
    ),
    spec("netsniff-ng", ArgShape::NoTarget, &[]),
    spec("driftnet", ArgShape::NoTarget, &["-i", "eth0"]),
    spec("bettercap", ArgShape::NoTarget, &[]),
    spec("ettercap", ArgShape::NoTarget, &["-T", "-q"]),
    spec("mitmproxy", ArgShape::NoTarget, &[]),
    spec("yersinia", ArgShape::NoTarget, &[]),
    spec("thc-ipv6", ArgShape::NoTarget, &[]),
    // --- Host / service / network recon (target = host or range) ---
    spec("amass", ArgShape::NetworkHost, &["enum", "-d"]),
    spec("dmitry", ArgShape::NetworkHost, &[]),
    spec("netdiscover", ArgShape::NetworkHost, &["-P", "-r"]),
    spec("ike-scan", ArgShape::NetworkHost, &[]),
    spec("enum4linux", ArgShape::NetworkHost, &["-a"]),
    spec("smbmap", ArgShape::NetworkHost, &["-H"]),
    spec("ncrack", ArgShape::NetworkHost, &[]),
    spec("medusa", ArgShape::NetworkHost, &["-h"]),
    spec("netexec", ArgShape::NetworkHost, &["smb"]),
    spec("crackmapexec", ArgShape::NetworkHost, &["smb"]),
    spec("evil-winrm", ArgShape::NetworkHost, &["-i"]),
    // --- Web content discovery / crawling (target = URL) ---
    spec("dirb", ArgShape::WebUrl, &[]),
    spec("wfuzz", ArgShape::WebUrl, &["-c"]),
    spec("skipfish", ArgShape::WebUrl, &["-o", "skipfish-out"]),
    spec("wafw00f", ArgShape::WebUrl, &[]),
    spec("httrack", ArgShape::WebUrl, &[]),
    spec("cewl", ArgShape::WebUrl, &[]),
    // --- Exploitation frameworks / payloads (interactive) ---
    spec(
        "msfconsole",
        ArgShape::NoTarget,
        &["-q", "-x", "version; exit"],
    ),
    spec("msfpc", ArgShape::NoTarget, &[]),
    spec("searchsploit", ArgShape::NoTarget, &[]),
    spec("setoolkit", ArgShape::NoTarget, &[]),
    spec("beef-xss", ArgShape::NoTarget, &[]),
    // --- Password / hash cracking (target = a local hash/capture file) ---
    spec("hashcat", ArgShape::LocalPath, &["-m", "0", "-a", "0"]),
    spec("john", ArgShape::LocalPath, &[]),
    spec("ophcrack", ArgShape::NoTarget, &[]),
    spec("rcrack", ArgShape::NoTarget, &[]),
    spec("crunch", ArgShape::NoTarget, &["1", "8"]),
    spec("pyrit", ArgShape::NoTarget, &["eval"]),
    // --- Wireless / RFID / hardware (interface-driven) ---
    spec("aircrack-ng", ArgShape::LocalPath, &[]),
    spec("kismet", ArgShape::NoTarget, &[]),
    spec("wifite", ArgShape::NoTarget, &[]),
    spec("reaver", ArgShape::NoTarget, &["-i", "wlan0"]),
    spec("giskismet", ArgShape::NoTarget, &[]),
    spec("macchanger", ArgShape::NoTarget, &["-r"]),
    spec("chirpw", ArgShape::NoTarget, &[]),
    spec("mfoc", ArgShape::NoTarget, &["-O", "mfoc-dump.mfd"]),
    spec("mfterm", ArgShape::NoTarget, &[]),
    spec("termineter", ArgShape::NoTarget, &[]),
    // --- Android / mobile static & dynamic analysis (target = an APK/path) ---
    spec(
        "apktool",
        ArgShape::LocalPath,
        &["d", "-f", "-o", "apktool-out"],
    ),
    spec("androguard", ArgShape::LocalPath, &["analyze"]),
    spec("apkleaks", ArgShape::LocalPath, &["-f"]),
    spec("apksigner", ArgShape::LocalPath, &["verify"]),
    spec("dex2jar", ArgShape::LocalPath, &[]),
    spec("qark", ArgShape::LocalPath, &["--apk"]),
    spec("mariana-trench", ArgShape::NoTarget, &[]),
    spec("trueseeing", ArgShape::LocalPath, &[]),
    spec("mobsf", ArgShape::LocalPath, &[]),
    spec("frida", ArgShape::NoTarget, &[]),
    spec("objection", ArgShape::NoTarget, &[]),
    spec("drozer", ArgShape::NoTarget, &[]),
    // --- Proxies / GUI suites (launched, not scripted) ---
    spec("burpsuite", ArgShape::NoTarget, &[]),
    spec("zenmap", ArgShape::NoTarget, &[]),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engagement_context::{Endpoint, Service};

    fn ctx<'a>(
        address: Option<&'a str>,
        intensity: TestIntensity,
        operator_args: &'a [String],
        engagement: &'a EngagementContext,
    ) -> InvocationContext<'a> {
        InvocationContext {
            target_id: "t1",
            network_address: address,
            intensity,
            operator_args,
            engagement,
        }
    }

    fn step(tool: &str, address: Option<&str>) -> OrchestrationStep {
        OrchestrationStep {
            sequence: 1,
            target_id: "t1".to_string(),
            tool: tool.to_string(),
            execution_class: classify_execution(tool),
            intensity: TestIntensity::Standard,
            network_address: address.map(str::to_string),
        }
    }

    fn build(tool: &str, c: &InvocationContext) -> ToolInvocation {
        AdapterRegistry::with_defaults().invocation_for(&step(tool, c.network_address), c)
    }

    #[test]
    fn every_cataloged_tool_has_a_registered_adapter() {
        let registry = AdapterRegistry::with_defaults();
        let engagement = EngagementContext::new();
        let args: Vec<String> = Vec::new();
        let catalog = crate::registry::cataloged_tool_names();
        assert!(!catalog.is_empty());

        for name in &catalog {
            // Coverage: a bespoke or spec adapter exists for the tool — never
            // the conservative fallback.
            assert!(
                registry.adapter_for(name).is_some(),
                "no adapter registered for cataloged tool '{name}'",
            );
            // The adapter builds a well-formed invocation for that exact tool.
            let invocation = registry.invocation_for(
                &step(name, Some("10.0.0.5")),
                &ctx(
                    Some("10.0.0.5"),
                    TestIntensity::Standard,
                    &args,
                    &engagement,
                ),
            );
            assert_eq!(
                &invocation.tool, name,
                "adapter built a mismatched tool name"
            );
        }
    }

    #[test]
    fn spec_adapters_place_targets_per_shape() {
        let engagement = EngagementContext::new();
        let args: Vec<String> = Vec::new();
        let context = ctx(
            Some("10.0.0.5"),
            TestIntensity::Standard,
            &args,
            &engagement,
        );

        // NetworkHost: the address is the positional target.
        let smbmap = build("smbmap", &context);
        assert_eq!(smbmap.argv, vec!["-H".to_string(), "10.0.0.5".to_string()]);

        // LocalPath: the target id is the positional target.
        let binwalk = build("binwalk", &context);
        assert_eq!(binwalk.argv, vec!["-e".to_string(), "t1".to_string()]);

        // WebUrl: a synthesized URL for the target.
        let dirb = build("dirb", &context);
        assert_eq!(dirb.argv, vec!["http://10.0.0.5".to_string()]);

        // NoTarget: only the fixed arguments, no positional target.
        let msf = build("msfconsole", &context);
        assert_eq!(
            msf.argv,
            vec![
                "-q".to_string(),
                "-x".to_string(),
                "version; exit".to_string()
            ],
        );
    }

    #[test]
    fn spec_adapter_appends_operator_args_after_target() {
        let engagement = EngagementContext::new();
        let args = vec!["--extra".to_string()];
        let inv = build(
            "smbmap",
            &ctx(
                Some("10.0.0.5"),
                TestIntensity::Standard,
                &args,
                &engagement,
            ),
        );
        assert_eq!(
            inv.argv,
            vec![
                "-H".to_string(),
                "10.0.0.5".to_string(),
                "--extra".to_string()
            ],
        );
    }

    #[test]
    fn nmap_maps_intensity_and_targets_bound_address() {
        let eng = EngagementContext::new();
        let args = Vec::new();
        let inv = build(
            "nmap",
            &ctx(Some("10.0.0.5"), TestIntensity::Aggressive, &args, &eng),
        );
        assert_eq!(inv.format, OutputFormat::NmapXml);
        assert!(inv.argv.contains(&"-T4".to_string()));
        assert!(inv.argv.contains(&"10.0.0.5".to_string()));
    }

    #[test]
    fn masscan_emits_nmap_xml_and_scales_rate() {
        let eng = EngagementContext::new();
        let args = Vec::new();
        let inv = build(
            "masscan",
            &ctx(Some("10.0.0.5"), TestIntensity::Passive, &args, &eng),
        );
        assert_eq!(inv.format, OutputFormat::NmapXml);
        let joined = inv.argv.join(" ");
        assert!(joined.contains("--rate 100"));
    }

    #[test]
    fn web_scanner_prefers_discovered_endpoints() {
        let mut eng = EngagementContext::new();
        eng.record_endpoint(Endpoint {
            url: "https://app.example/login".to_string(),
        });
        let args = Vec::new();
        let inv = build(
            "nuclei",
            &ctx(Some("10.0.0.5"), TestIntensity::Standard, &args, &eng),
        );
        // Targets the discovered endpoint, not the raw address.
        assert!(inv.argv.contains(&"https://app.example/login".to_string()));
        assert!(inv.argv.iter().all(|a| a != "10.0.0.5"));
    }

    #[test]
    fn web_scanner_promotes_https_service_to_url() {
        let mut eng = EngagementContext::new();
        eng.record_service(Service {
            host: "10.0.0.5".to_string(),
            port: 8443,
            protocol: "tcp".to_string(),
            service: Some("https-alt".to_string()),
        });
        let args = Vec::new();
        let inv = build(
            "gobuster",
            &ctx(Some("10.0.0.5"), TestIntensity::Standard, &args, &eng),
        );
        assert!(inv.argv.contains(&"https://10.0.0.5:8443".to_string()));
    }

    #[test]
    fn web_scanner_falls_back_to_synthesized_url() {
        let eng = EngagementContext::new();
        let args = Vec::new();
        let inv = build(
            "nikto",
            &ctx(Some("10.0.0.9"), TestIntensity::Standard, &args, &eng),
        );
        assert!(inv.argv.contains(&"http://10.0.0.9".to_string()));
    }

    #[test]
    fn sqlmap_scales_level_and_risk_with_intensity() {
        let eng = EngagementContext::new();
        let args = Vec::new();
        let inv = build(
            "sqlmap",
            &ctx(Some("10.0.0.5"), TestIntensity::Aggressive, &args, &eng),
        );
        let joined = inv.argv.join(" ");
        assert!(joined.contains("--level 3"));
        assert!(joined.contains("--risk 2"));
        assert!(inv.argv.contains(&"--batch".to_string()));
    }

    #[test]
    fn operator_args_are_appended_last() {
        let eng = EngagementContext::new();
        let args = vec!["--proxy".to_string(), "http://127.0.0.1:8080".to_string()];
        let inv = build(
            "nmap",
            &ctx(Some("10.0.0.5"), TestIntensity::Standard, &args, &eng),
        );
        let tail = &inv.argv[inv.argv.len() - 2..];
        assert_eq!(tail, args.as_slice());
    }

    #[test]
    fn unadapted_tool_uses_fallback_prepend_behavior() {
        let eng = EngagementContext::new();
        let args = vec!["-x".to_string()];
        // A name outside the catalog has no registered adapter, so the
        // conservative fallback applies (network tools get the address
        // prepended). Every cataloged tool, by contrast, is covered.
        assert!(
            !crate::registry::cataloged_tool_names()
                .iter()
                .any(|n| n == "uncataloged-probe")
        );
        let inv = build(
            "uncataloged-probe",
            &ctx(Some("10.0.0.9"), TestIntensity::Standard, &args, &eng),
        );
        assert_eq!(inv.argv, vec!["10.0.0.9".to_string(), "-x".to_string()]);
        assert_eq!(inv.format, OutputFormat::PlainText);
    }

    #[test]
    fn static_adapter_ignores_network_address() {
        let eng = EngagementContext::new();
        let args = Vec::new();
        let inv = build("semgrep", &ctx(None, TestIntensity::Passive, &args, &eng));
        assert_eq!(inv.format, OutputFormat::SemgrepJson);
        assert!(inv.argv.iter().all(|a| !a.contains("10.0.0")));
    }
}
