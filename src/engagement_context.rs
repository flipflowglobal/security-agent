//! The engagement blackboard: a shared, deduplicated store of the artifacts
//! discovered during a running engagement (hosts, services, web endpoints).
//!
//! Orchestration alone answers *what is authorized and in what order*; it
//! cannot answer *what did discovery actually find*. A real engagement is
//! staged — a discovery tool enumerates live hosts and open services, and
//! later stages must scan exactly those, not a static guess. This module is
//! the seam that carries that information forward: discovery output is
//! recorded here (by the findings pipeline / runtime), and later planning
//! stages query it to expand their target set.
//!
//! Everything here is in-memory and dependency-free. Records are
//! deduplicated on their natural identity so the same host or service
//! reported by two tools is stored once. This is **Stage-2 territory**
//! (result-driven orchestration); Stages 1/3/4 read it to build invocations,
//! feed the runtime, and attach findings to concrete assets.

/// A live host discovered during the engagement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// The network address (IPv4/IPv6 literal or resolved address).
    pub address: String,
    /// A hostname for the address, when one was discovered.
    pub hostname: Option<String>,
}

/// An open service on a discovered [`Host`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// The address of the host this service runs on (matches [`Host::address`]).
    pub host: String,
    /// The port the service listens on.
    pub port: u16,
    /// Transport protocol, lowercased (`"tcp"` / `"udp"`).
    pub protocol: String,
    /// The identified service/product name, when fingerprinted.
    pub service: Option<String>,
}

/// A reachable web endpoint (used to seed web/API scanners).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Absolute URL of the endpoint.
    pub url: String,
}

/// The deduplicated store of everything discovery has found so far.
///
/// Cheap to clone; the whole point is to be threaded through the staged
/// pipeline and read by later planning. Insertion is idempotent on each
/// record's natural identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngagementContext {
    hosts: Vec<Host>,
    services: Vec<Service>,
    endpoints: Vec<Endpoint>,
}

impl EngagementContext {
    /// An empty context, before any discovery has run.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            hosts: Vec::new(),
            services: Vec::new(),
            endpoints: Vec::new(),
        }
    }

    /// Records a host, merging a newly-learned hostname into an existing
    /// entry rather than duplicating it. Returns `true` when this added or
    /// enriched a record.
    pub fn record_host(&mut self, host: Host) -> bool {
        if let Some(existing) = self.hosts.iter_mut().find(|h| h.address == host.address) {
            if existing.hostname.is_none() && host.hostname.is_some() {
                existing.hostname = host.hostname;
                return true;
            }
            return false;
        }
        self.hosts.push(host);
        true
    }

    /// Records an open service, deduplicated on `(host, port, protocol)`.
    /// Returns `true` when this was a new service.
    pub fn record_service(&mut self, mut service: Service) -> bool {
        service.protocol.make_ascii_lowercase();
        let is_duplicate = self.services.iter().any(|s| {
            s.host == service.host && s.port == service.port && s.protocol == service.protocol
        });
        if is_duplicate {
            return false;
        }
        self.services.push(service);
        true
    }

    /// Records a web endpoint, deduplicated on its URL. Returns `true` when
    /// this was a new endpoint.
    pub fn record_endpoint(&mut self, endpoint: Endpoint) -> bool {
        if self.endpoints.iter().any(|e| e.url == endpoint.url) {
            return false;
        }
        self.endpoints.push(endpoint);
        true
    }

    /// All discovered hosts.
    #[must_use]
    pub fn hosts(&self) -> &[Host] {
        &self.hosts
    }

    /// All discovered open services.
    #[must_use]
    pub fn services(&self) -> &[Service] {
        &self.services
    }

    /// All discovered web endpoints.
    #[must_use]
    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }

    /// Whether discovery has found nothing yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.services.is_empty() && self.endpoints.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_deduplicates_hosts() {
        let mut ctx = EngagementContext::new();
        assert!(ctx.record_host(Host {
            address: "10.0.0.1".to_string(),
            hostname: None,
        }));
        // Same address, no new info -> not added again.
        assert!(!ctx.record_host(Host {
            address: "10.0.0.1".to_string(),
            hostname: None,
        }));
        // Same address, new hostname -> enriches in place.
        assert!(ctx.record_host(Host {
            address: "10.0.0.1".to_string(),
            hostname: Some("web-01".to_string()),
        }));
        assert_eq!(ctx.hosts().len(), 1);
        assert_eq!(ctx.hosts()[0].hostname.as_deref(), Some("web-01"));
    }

    #[test]
    fn deduplicates_services_on_host_port_protocol() {
        let mut ctx = EngagementContext::new();
        let svc = Service {
            host: "10.0.0.1".to_string(),
            port: 443,
            protocol: "tcp".to_string(),
            service: Some("https".to_string()),
        };
        assert!(ctx.record_service(svc.clone()));
        assert!(!ctx.record_service(svc));
        assert_eq!(ctx.services().len(), 1);
    }

    #[test]
    fn canonicalizes_protocol_before_service_deduplication() {
        let mut ctx = EngagementContext::new();
        assert!(ctx.record_service(Service {
            host: "10.0.0.1".to_string(),
            port: 53,
            protocol: "UDP".to_string(),
            service: Some("domain".to_string()),
        }));
        assert!(!ctx.record_service(Service {
            host: "10.0.0.1".to_string(),
            port: 53,
            protocol: "udp".to_string(),
            service: Some("dns".to_string()),
        }));
        assert_eq!(ctx.services().len(), 1);
        assert_eq!(ctx.services()[0].protocol, "udp");
    }

    #[test]
    fn empty_context_reports_empty() {
        let mut ctx = EngagementContext::new();
        assert!(ctx.is_empty());
        ctx.record_endpoint(Endpoint {
            url: "https://10.0.0.1/".to_string(),
        });
        assert!(!ctx.is_empty());
        assert_eq!(ctx.endpoints().len(), 1);
    }
}
