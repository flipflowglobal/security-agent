//! Result-driven expansion: grow the schedule from what discovery actually
//! found.
//!
//! The base schedule is planned up front from the authorized targets. But a
//! real engagement learns as it goes: a discovery scan turns one target into a
//! set of live hosts, open services, and reachable URLs, and the *right*
//! follow-up depends on those results — scan the web service that was found,
//! enumerate the SMB share that answered, and so on.
//!
//! This module maps discovered assets to concrete follow-up tools. It is
//! deliberately conservative and safe by construction:
//!
//! * **Authorized only.** A proposed tool is emitted only if the caller's
//!   `authorized` predicate accepts it — the pipeline wires that to "approved
//!   by the engagement, allowed by the active-tool gate, and installed", so
//!   expansion can never introduce a tool the engagement did not sanction.
//! * **In-scope only.** When a [`ScopePolicy`] is supplied, a follow-up whose
//!   target is out of scope is dropped before it is scheduled.
//! * **Deduplicated.** A `(target, tool)` pair already scheduled is never
//!   proposed again, so the fixpoint the pipeline runs terminates.
//!
//! The universe of proposals is finite (discovered targets × a fixed follow-up
//! table), and each is emitted at most once, so repeated expansion converges.

use std::collections::BTreeSet;

use crate::engagement_context::{EngagementContext, Service};
use crate::model::TestIntensity;
use crate::orchestrator::OrchestrationStep;
use crate::registry::{ExecutionClass, classify_execution};
use crate::scope::ScopePolicy;

/// Web application scanners, seeded onto any HTTP(S) service or discovered URL.
const WEB_TOOLS: &[&str] = &[
    "whatweb",
    "wafw00f",
    "nikto",
    "nuclei",
    "wpscan",
    "gobuster",
    "feroxbuster",
    "sqlmap",
];

/// SMB / Windows-share enumeration and access tools.
const SMB_TOOLS: &[&str] = &["enum4linux", "smbmap", "crackmapexec", "netexec"];

/// Proposes follow-up steps from a discovery blackboard, constrained to
/// authorized tools and in-scope targets.
pub struct FollowUpPlanner<'a> {
    authorized: &'a dyn Fn(&str) -> bool,
    scope: Option<&'a ScopePolicy>,
    intensity: TestIntensity,
}

impl<'a> FollowUpPlanner<'a> {
    /// Builds a planner.
    ///
    /// `authorized` decides whether a candidate tool may be scheduled at all
    /// (the pipeline passes "approved + gate-allowed + installed"); `scope`,
    /// when set, drops follow-ups whose target is out of scope; `intensity` is
    /// stamped on every proposed step.
    #[must_use]
    pub fn new(
        authorized: &'a dyn Fn(&str) -> bool,
        scope: Option<&'a ScopePolicy>,
        intensity: TestIntensity,
    ) -> Self {
        Self {
            authorized,
            scope,
            intensity,
        }
    }

    /// Proposes new steps for everything in `context` that is not already in
    /// `scheduled` (a set of `(target, tool)` keys). The returned steps are
    /// deduplicated and safe to append to the working schedule.
    #[must_use]
    pub fn propose(
        &self,
        context: &EngagementContext,
        scheduled: &BTreeSet<(String, String)>,
    ) -> Vec<OrchestrationStep> {
        let mut steps = Vec::new();
        let mut emitted: BTreeSet<(String, String)> = BTreeSet::new();

        // Open services → protocol-specific follow-ups, keyed by host address.
        for service in context.services() {
            for tool in follow_up_tools_for_service(service) {
                self.try_emit(&mut steps, &mut emitted, scheduled, &service.host, tool);
            }
        }

        // Reachable URLs → web scanners, keyed by the URL's host. The web
        // adapters additionally fold the discovered endpoints in from context.
        for endpoint in context.endpoints() {
            if let Some(host) = host_of_url(&endpoint.url) {
                for tool in WEB_TOOLS {
                    self.try_emit(&mut steps, &mut emitted, scheduled, host, tool);
                }
            }
        }

        // Hosts that resolved to a domain name → subdomain enumeration.
        for host in context.hosts() {
            if let Some(name) = host.hostname.as_deref() {
                if is_domain_like(name) {
                    for tool in ["subfinder", "amass"] {
                        self.try_emit(&mut steps, &mut emitted, scheduled, name, tool);
                    }
                }
            }
        }

        steps
    }

    /// Emits one step if the tool is authorized, the target is in scope, and
    /// the `(target, tool)` pair is neither already scheduled nor already
    /// emitted in this round.
    fn try_emit(
        &self,
        steps: &mut Vec<OrchestrationStep>,
        emitted: &mut BTreeSet<(String, String)>,
        scheduled: &BTreeSet<(String, String)>,
        target: &str,
        tool: &str,
    ) {
        if !(self.authorized)(tool) {
            return;
        }
        if self.scope.is_some_and(|scope| !scope.allows(target)) {
            return;
        }
        let key = (target.to_string(), tool.to_string());
        if scheduled.contains(&key) || !emitted.insert(key) {
            return;
        }
        let class = classify_execution(tool);
        let network_address = match class {
            ExecutionClass::StaticLocalAnalysis => None,
            _ => Some(target.to_string()),
        };
        steps.push(OrchestrationStep {
            sequence: 0,
            target_id: target.to_string(),
            tool: tool.to_string(),
            execution_class: class,
            intensity: self.intensity,
            network_address,
        });
    }
}

/// The follow-up tools warranted by one open service, chosen by port and by
/// the fingerprinted service name (so non-standard ports are still matched).
fn follow_up_tools_for_service(service: &Service) -> Vec<&'static str> {
    let name = service
        .service
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut tools: Vec<&'static str> = Vec::new();

    match service.port {
        80 | 443 | 3000 | 8000 | 8080 | 8081 | 8443 | 8888 => tools.extend_from_slice(WEB_TOOLS),
        139 | 445 => tools.extend_from_slice(SMB_TOOLS),
        21 | 3306 => tools.push("hydra"),
        22 | 23 => tools.extend_from_slice(&["hydra", "ncrack"]),
        389 | 636 => tools.push("enum4linux"),
        1433 => tools.push("crackmapexec"),
        3389 => tools.extend_from_slice(&["ncrack", "crackmapexec"]),
        5985 | 5986 => tools.extend_from_slice(&["evil-winrm", "netexec"]),
        _ => {}
    }

    let has = |needle: &str| name.contains(needle);
    if has("http") {
        tools.extend_from_slice(WEB_TOOLS);
    }
    if has("smb") || has("microsoft-ds") || has("netbios") {
        tools.extend_from_slice(SMB_TOOLS);
    }
    if has("ssh") {
        tools.extend_from_slice(&["hydra", "ncrack"]);
    }
    if has("ftp") {
        tools.push("hydra");
    }
    if has("rdp") || has("ms-wbt") {
        tools.extend_from_slice(&["ncrack", "crackmapexec"]);
    }
    if has("winrm") {
        tools.extend_from_slice(&["evil-winrm", "netexec"]);
    }
    if has("ldap") {
        tools.push("enum4linux");
    }

    tools.sort_unstable();
    tools.dedup();
    tools
}

/// Extracts the host of an absolute URL without pulling in a URL parser:
/// strips the scheme, any `user@` prefix, the path/query/fragment, and a
/// trailing `:port`. Returns `None` for an empty host.
fn host_of_url(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    // Strip a trailing `:port` only when the suffix is all digits (so an IPv6
    // literal like `[::1]` or a bare host is left intact).
    let host = match host_port.rsplit_once(':') {
        Some((head, tail)) if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) => head,
        _ => host_port,
    };
    let host = host.trim_matches(['[', ']']);
    (!host.is_empty()).then_some(host)
}

/// A hostname that looks like a DNS domain (has a dot and a letter), as
/// opposed to a bare IPv4/IPv6 literal — only those are worth subdomain
/// enumeration.
fn is_domain_like(name: &str) -> bool {
    name.contains('.') && name.bytes().any(|b| b.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engagement_context::{Endpoint, Host};

    fn allow_all(_: &str) -> bool {
        true
    }

    fn service(host: &str, port: u16, name: Option<&str>) -> Service {
        Service {
            host: host.to_string(),
            port,
            protocol: "tcp".to_string(),
            service: name.map(str::to_string),
        }
    }

    fn tools_of(steps: &[OrchestrationStep]) -> BTreeSet<String> {
        steps.iter().map(|s| s.tool.clone()).collect()
    }

    #[test]
    fn http_service_proposes_web_scanners() {
        let mut ctx = EngagementContext::new();
        ctx.record_service(service("10.0.0.5", 443, Some("https")));
        let planner = FollowUpPlanner::new(&allow_all, None, TestIntensity::Standard);
        let steps = planner.propose(&ctx, &BTreeSet::new());
        let tools = tools_of(&steps);
        assert!(tools.contains("nikto"));
        assert!(tools.contains("nuclei"));
        assert!(tools.contains("whatweb"));
        // Every proposed step targets the discovered host.
        assert!(steps.iter().all(|s| s.target_id == "10.0.0.5"));
        assert!(
            steps
                .iter()
                .all(|s| s.network_address.as_deref() == Some("10.0.0.5"))
        );
    }

    #[test]
    fn smb_service_by_nonstandard_port_matches_on_name() {
        let mut ctx = EngagementContext::new();
        ctx.record_service(service("10.0.0.9", 4450, Some("microsoft-ds")));
        let planner = FollowUpPlanner::new(&allow_all, None, TestIntensity::Standard);
        let tools = tools_of(&planner.propose(&ctx, &BTreeSet::new()));
        assert!(tools.contains("enum4linux"));
        assert!(tools.contains("smbmap"));
    }

    #[test]
    fn authorization_filters_proposals() {
        let mut ctx = EngagementContext::new();
        ctx.record_service(service("10.0.0.5", 80, Some("http")));
        // Only nikto is authorized; nothing else may be proposed.
        let only_nikto = |tool: &str| tool == "nikto";
        let planner = FollowUpPlanner::new(&only_nikto, None, TestIntensity::Standard);
        let tools = tools_of(&planner.propose(&ctx, &BTreeSet::new()));
        assert_eq!(tools, BTreeSet::from(["nikto".to_string()]));
    }

    #[test]
    fn out_of_scope_target_is_dropped() {
        let mut ctx = EngagementContext::new();
        ctx.record_service(service("10.9.9.9", 80, Some("http")));
        let policy = ScopePolicy::from_targets(&["10.0.0.0/24".to_string()]);
        let planner = FollowUpPlanner::new(&allow_all, Some(&policy), TestIntensity::Standard);
        assert!(planner.propose(&ctx, &BTreeSet::new()).is_empty());
    }

    #[test]
    fn already_scheduled_pair_is_not_reproposed() {
        let mut ctx = EngagementContext::new();
        ctx.record_service(service("10.0.0.5", 80, Some("http")));
        let scheduled: BTreeSet<(String, String)> = WEB_TOOLS
            .iter()
            .map(|t| ("10.0.0.5".to_string(), (*t).to_string()))
            .collect();
        let planner = FollowUpPlanner::new(&allow_all, None, TestIntensity::Standard);
        assert!(planner.propose(&ctx, &scheduled).is_empty());
    }

    #[test]
    fn endpoint_seeds_web_scanners_keyed_by_host() {
        let mut ctx = EngagementContext::new();
        ctx.record_endpoint(Endpoint {
            url: "https://app.example.com:8443/login?next=/x".to_string(),
        });
        let planner = FollowUpPlanner::new(&allow_all, None, TestIntensity::Standard);
        let steps = planner.propose(&ctx, &BTreeSet::new());
        assert!(!steps.is_empty());
        assert!(steps.iter().all(|s| s.target_id == "app.example.com"));
    }

    #[test]
    fn domain_host_seeds_subdomain_enumeration() {
        let mut ctx = EngagementContext::new();
        ctx.record_host(Host {
            address: "93.184.216.34".to_string(),
            hostname: Some("example.com".to_string()),
        });
        let planner = FollowUpPlanner::new(&allow_all, None, TestIntensity::Standard);
        let tools = tools_of(&planner.propose(&ctx, &BTreeSet::new()));
        assert!(tools.contains("subfinder"));
        assert!(tools.contains("amass"));
    }

    #[test]
    fn ip_only_host_does_not_seed_subdomain_enumeration() {
        let mut ctx = EngagementContext::new();
        ctx.record_host(Host {
            address: "10.0.0.5".to_string(),
            hostname: None,
        });
        assert!(
            FollowUpPlanner::new(&allow_all, None, TestIntensity::Standard)
                .propose(&ctx, &BTreeSet::new())
                .is_empty()
        );
    }

    #[test]
    fn url_host_extraction() {
        assert_eq!(host_of_url("https://a.b/c"), Some("a.b"));
        assert_eq!(host_of_url("http://user@a.b:8080/x"), Some("a.b"));
        assert_eq!(host_of_url("a.b/c"), Some("a.b"));
        assert_eq!(host_of_url("https://10.0.0.1"), Some("10.0.0.1"));
        assert_eq!(host_of_url("https://"), None);
    }

    #[test]
    fn domain_detection() {
        assert!(is_domain_like("example.com"));
        assert!(is_domain_like("a.b.c"));
        assert!(!is_domain_like("10.0.0.5"));
        assert!(!is_domain_like("localhost"));
    }
}
