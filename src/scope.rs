//! Pre-spawn egress scope enforcement.
//!
//! [`crate::network_policy`] decides *whether* active tools may run at all;
//! this module decides *where* they may point once they do. Given the
//! engagement's authorized targets — exact hosts and IPv4 CIDR ranges — a
//! [`ScopePolicy`] inspects the concrete argument list about to be handed to
//! a tool and refuses it if any network target in it falls outside scope.
//! It is defense in depth: even if an adapter, an operator override, or a
//! discovered artifact introduces an out-of-scope address, the tool never
//! spawns against it.
//!
//! Detection is deliberately conservative to avoid false positives on
//! non-network arguments (flags, file paths, wordlist names): only IPv4
//! literals, `host:port` pairs whose host is an IPv4 literal, and the hosts
//! of `scheme://` URLs are treated as network targets. Everything else is
//! ignored. CIDR matching is exact, in-house integer arithmetic — no
//! dependency and no DNS.

use std::collections::BTreeSet;
use std::fmt;

/// The authorized egress scope: exact hosts plus IPv4 CIDR ranges.
#[derive(Debug, Clone, Default)]
pub struct ScopePolicy {
    exact: BTreeSet<String>,
    cidrs: Vec<Ipv4Cidr>,
}

impl ScopePolicy {
    /// Builds a policy from authorized target strings. A target of the form
    /// `a.b.c.d/n` is parsed as an IPv4 CIDR; anything else is treated as an
    /// exact host (case-insensitive), including bare IPv4 literals and
    /// hostnames.
    #[must_use]
    pub fn from_targets(targets: &[String]) -> Self {
        let mut policy = Self::default();
        for target in targets {
            if let Some(cidr) = Ipv4Cidr::parse(target) {
                policy.cidrs.push(cidr);
            } else {
                policy.exact.insert(target.to_ascii_lowercase());
            }
        }
        policy
    }

    /// Whether `host` (a hostname or IPv4 literal) is in scope.
    #[must_use]
    pub fn allows(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        if self.exact.contains(&host) {
            return true;
        }
        parse_ipv4(&host).is_some_and(|ip| self.cidrs.iter().any(|cidr| cidr.contains(ip)))
    }

    /// Verifies that every network target present in `args` is in scope.
    ///
    /// # Errors
    ///
    /// Returns the first [`ScopeViolation`] found — the offending argument
    /// and the out-of-scope host — so the caller can refuse to spawn.
    pub fn enforce_args(&self, args: &[String]) -> Result<(), ScopeViolation> {
        for arg in args {
            if let Some(host) = candidate_host(arg) {
                if !self.allows(&host) {
                    return Err(ScopeViolation {
                        argument: arg.clone(),
                        host,
                    });
                }
            }
        }
        Ok(())
    }
}

/// An argument carrying a network target outside the authorized scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeViolation {
    /// The argument that carried the out-of-scope target.
    pub argument: String,
    /// The out-of-scope host or address.
    pub host: String,
}

impl fmt::Display for ScopeViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "out-of-scope target '{}' in argument '{}'",
            self.host, self.argument
        )
    }
}

impl std::error::Error for ScopeViolation {}

/// Extracts the network target an argument points at, if any: a URL host, an
/// IPv4 literal, or the IPv4 host of a `host:port` pair. Returns `None` for
/// arguments that are not network targets (flags, file paths, values).
fn candidate_host(arg: &str) -> Option<String> {
    if let Some((_, after)) = arg.split_once("://") {
        let authority = after.split(['/', '?', '#']).next().unwrap_or(after);
        let authority = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        let host = strip_port(authority);
        return (!host.is_empty()).then(|| host.to_ascii_lowercase());
    }
    if parse_ipv4(arg).is_some() {
        return Some(arg.to_string());
    }
    // host:port where the host is an IPv4 literal.
    if let Some((host, _port)) = arg.rsplit_once(':') {
        if parse_ipv4(host).is_some() {
            return Some(host.to_string());
        }
    }
    None
}

/// Strips a trailing `:port` from an authority, leaving the host.
fn strip_port(authority: &str) -> &str {
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, port)| {
            if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() {
                host
            } else {
                authority
            }
        })
}

/// Parses a dotted-quad IPv4 literal into a `u32`, or `None`.
fn parse_ipv4(text: &str) -> Option<u32> {
    let mut octets = text.split('.');
    let a: u8 = octets.next()?.parse().ok()?;
    let b: u8 = octets.next()?.parse().ok()?;
    let c: u8 = octets.next()?.parse().ok()?;
    let d: u8 = octets.next()?.parse().ok()?;
    if octets.next().is_some() {
        return None;
    }
    Some(u32::from_be_bytes([a, b, c, d]))
}

/// An IPv4 network in CIDR form.
#[derive(Debug, Clone, Copy)]
struct Ipv4Cidr {
    network: u32,
    prefix: u8,
}

impl Ipv4Cidr {
    /// Parses `a.b.c.d/n` (0 ≤ n ≤ 32).
    fn parse(text: &str) -> Option<Self> {
        let (addr, prefix) = text.split_once('/')?;
        let ip = parse_ipv4(addr)?;
        let prefix: u8 = prefix.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        Some(Self {
            network: ip & mask_for(prefix),
            prefix,
        })
    }

    /// Whether `ip` lies within this network.
    const fn contains(self, ip: u32) -> bool {
        ip & mask_for(self.prefix) == self.network
    }
}

/// The netmask for a prefix length, as a `u32`.
const fn mask_for(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(targets: &[&str]) -> ScopePolicy {
        ScopePolicy::from_targets(&targets.iter().map(ToString::to_string).collect::<Vec<_>>())
    }

    #[test]
    fn allows_exact_host_and_cidr_members() {
        let policy = policy(&["10.0.0.0/24", "app.example.com"]);
        assert!(policy.allows("10.0.0.5"));
        assert!(policy.allows("10.0.0.255"));
        assert!(policy.allows("APP.EXAMPLE.COM"));
        assert!(!policy.allows("10.0.1.5"));
        assert!(!policy.allows("evil.example.com"));
    }

    #[test]
    fn cidr_boundaries_are_exact() {
        let policy = policy(&["192.168.1.0/25"]);
        assert!(policy.allows("192.168.1.0"));
        assert!(policy.allows("192.168.1.127"));
        assert!(!policy.allows("192.168.1.128"));
    }

    #[test]
    fn enforce_passes_in_scope_ip_and_url() {
        let policy = policy(&["10.0.0.0/24", "app.example.com"]);
        let args = vec![
            "-sV".to_string(),
            "10.0.0.9".to_string(),
            "-u".to_string(),
            "https://app.example.com/login".to_string(),
        ];
        assert!(policy.enforce_args(&args).is_ok());
    }

    #[test]
    fn enforce_rejects_out_of_scope_ip() {
        let policy = policy(&["10.0.0.0/24"]);
        let args = vec!["10.9.9.9".to_string()];
        let violation = policy.enforce_args(&args).expect_err("out of scope");
        assert_eq!(violation.host, "10.9.9.9");
    }

    #[test]
    fn enforce_rejects_out_of_scope_url_host() {
        let policy = policy(&["app.example.com"]);
        let args = vec!["--url".to_string(), "http://evil.test:8080/x".to_string()];
        let violation = policy.enforce_args(&args).expect_err("out of scope");
        assert_eq!(violation.host, "evil.test");
    }

    #[test]
    fn url_userinfo_and_port_are_stripped() {
        let policy = policy(&["10.0.0.5"]);
        let args = vec!["https://user:pass@10.0.0.5:8443/app".to_string()];
        assert!(policy.enforce_args(&args).is_ok());
    }

    #[test]
    fn host_port_pair_with_ipv4_is_checked() {
        let policy = policy(&["10.0.0.0/24"]);
        assert!(policy.enforce_args(&["10.0.0.7:443".to_string()]).is_ok());
        assert!(policy.enforce_args(&["10.9.0.7:443".to_string()]).is_err());
    }

    #[test]
    fn non_network_arguments_are_ignored() {
        let policy = policy(&["10.0.0.0/24"]);
        // Flags, file paths, and plain values must not be treated as targets.
        let args = vec![
            "--config".to_string(),
            "auto".to_string(),
            "app.py".to_string(),
            "-T4".to_string(),
            "/usr/share/wordlists/list.txt".to_string(),
        ];
        assert!(policy.enforce_args(&args).is_ok());
    }
}
