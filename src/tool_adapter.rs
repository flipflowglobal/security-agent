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
//! [`crate::network_policy`] gates still own that. The [`AdapterRegistry`]
//! resolves a step's tool to its adapter and falls back to a conservative
//! default (the historical prepend-address behavior) for tools that don't
//! have a bespoke adapter yet, so nothing regresses while adapters are added
//! incrementally.

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
    /// nmap XML (`-oX`).
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

    /// A registry seeded with the reference adapters shipped in this module.
    /// Stage-1 work extends this with an adapter per cataloged tool.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(SemgrepAdapter));
        registry.register(Box::new(NmapAdapter));
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
/// capture stdout, and treat the output as unstructured unless a parser is
/// keyed on the tool name elsewhere.
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

/// Reference adapter: `semgrep` static analysis over the local target,
/// emitting JSON on stdout.
struct SemgrepAdapter;

impl ToolAdapter for SemgrepAdapter {
    fn tool_name(&self) -> &'static str {
        "semgrep"
    }

    fn output_format(&self) -> OutputFormat {
        OutputFormat::SemgrepJson
    }

    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let mut argv = vec!["--json".to_string(), "--quiet".to_string()];
        argv.extend_from_slice(ctx.operator_args);
        ToolInvocation {
            tool: self.tool_name().to_string(),
            argv,
            output: OutputChannel::Stdout,
            format: self.output_format(),
        }
    }
}

/// Reference adapter: `nmap` service discovery against the bound address,
/// with intensity mapped onto timing/scan flags.
struct NmapAdapter;

impl ToolAdapter for NmapAdapter {
    fn tool_name(&self) -> &'static str {
        "nmap"
    }

    fn output_format(&self) -> OutputFormat {
        OutputFormat::NmapXml
    }

    fn build(&self, ctx: &InvocationContext) -> ToolInvocation {
        let timing = match ctx.intensity {
            TestIntensity::Passive => "-T2",
            TestIntensity::Standard => "-T3",
            TestIntensity::Aggressive => "-T4",
        };
        let mut argv = vec!["-sV".to_string(), timing.to_string(), "-oX".to_string()];
        argv.push("-".to_string()); // XML to stdout
        argv.extend_from_slice(ctx.operator_args);
        if let Some(address) = ctx.network_address {
            argv.push(address.to_string());
        }
        ToolInvocation {
            tool: self.tool_name().to_string(),
            argv,
            output: OutputChannel::Stdout,
            format: self.output_format(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(
        target: &'a str,
        address: Option<&'a str>,
        intensity: TestIntensity,
        operator_args: &'a [String],
        engagement: &'a EngagementContext,
    ) -> InvocationContext<'a> {
        InvocationContext {
            target_id: target,
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

    #[test]
    fn registered_adapter_builds_its_own_command() {
        let registry = AdapterRegistry::with_defaults();
        let engagement = EngagementContext::new();
        let args = Vec::new();
        let invocation = registry.invocation_for(
            &step("nmap", Some("10.0.0.5")),
            &ctx(
                "t1",
                Some("10.0.0.5"),
                TestIntensity::Aggressive,
                &args,
                &engagement,
            ),
        );
        assert_eq!(invocation.format, OutputFormat::NmapXml);
        assert!(invocation.argv.contains(&"-T4".to_string()));
        assert!(invocation.argv.contains(&"10.0.0.5".to_string()));
    }

    #[test]
    fn unadapted_tool_uses_fallback_prepend_behavior() {
        let registry = AdapterRegistry::new();
        let engagement = EngagementContext::new();
        let args = vec!["-p-".to_string()];
        // masscan has no adapter and is a network tool -> address prepended.
        let invocation = registry.invocation_for(
            &step("masscan", Some("10.0.0.9")),
            &ctx(
                "t1",
                Some("10.0.0.9"),
                TestIntensity::Standard,
                &args,
                &engagement,
            ),
        );
        assert_eq!(
            invocation.argv,
            vec!["10.0.0.9".to_string(), "-p-".to_string()]
        );
        assert_eq!(invocation.format, OutputFormat::PlainText);
    }

    #[test]
    fn static_fallback_tool_does_not_prepend_address() {
        let registry = AdapterRegistry::new();
        let engagement = EngagementContext::new();
        let args = vec!["scan".to_string()];
        let invocation = registry.invocation_for(
            &step("jadx", None),
            &ctx("t1", None, TestIntensity::Passive, &args, &engagement),
        );
        assert_eq!(invocation.argv, vec!["scan".to_string()]);
    }
}
