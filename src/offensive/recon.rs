//! Network reconnaissance — TCP port scanning, service fingerprinting,
//! and OS detection. Pure-Rust implementations that produce structured
//! reports from local analysis or direct socket operations.

use std::fmt;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

// ─── TCP Connect Port Scanner ────────────────────────────────────────────────

/// Result of scanning a single port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub response_time_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Timeout,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Closed => write!(f, "closed"),
            Self::Filtered => write!(f, "filtered"),
            Self::Timeout => write!(f, "timeout"),
        }
    }
}

/// Full scan report for a target.
#[derive(Debug, Clone)]
pub struct PortScanReport {
    pub target: String,
    pub target_ip: Option<Ipv4Addr>,
    pub scan_type: String,
    pub total_ports_scanned: usize,
    pub open_ports: Vec<PortResult>,
    pub closed_ports: usize,
    pub filtered_ports: usize,
    pub timeout_ports: usize,
    pub scan_duration_ms: u64,
    pub os_fingerprint: Option<OsFingerprint>,
    pub services: Vec<ServiceInfo>,
}

impl fmt::Display for PortScanReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "TCP Port Scan Report")?;
        writeln!(f, "====================")?;
        writeln!(f, "Target          : {}", self.target)?;
        if let Some(ip) = self.target_ip {
            writeln!(f, "Resolved IP     : {ip}")?;
        }
        writeln!(f, "Scan type       : {}", self.scan_type)?;
        writeln!(f, "Ports scanned   : {}", self.total_ports_scanned)?;
        writeln!(f, "Duration        : {}ms", self.scan_duration_ms)?;
        writeln!(f)?;
        writeln!(f, "Results")?;
        writeln!(f, "-------")?;
        writeln!(f, "Open            : {}", self.open_ports.len())?;
        writeln!(f, "Closed          : {}", self.closed_ports)?;
        writeln!(f, "Filtered        : {}", self.filtered_ports)?;
        writeln!(f, "Timeout         : {}", self.timeout_ports)?;
        writeln!(f)?;
        if !self.open_ports.is_empty() {
            writeln!(f, "Open Ports")?;
            writeln!(f, "----------")?;
            writeln!(f, "{:<8} {:<12} {:<20} BANNER", "PORT", "STATE", "SERVICE")?;
            for port in &self.open_ports {
                let banner = port.banner.as_deref().unwrap_or("-");
                let service = port.service.as_deref().unwrap_or("unknown");
                writeln!(
                    f,
                    "{:<8} {:<12} {:<20} {}",
                    port.port,
                    port.state,
                    service,
                    truncate(banner, 40)
                )?;
            }
        }
        if let Some(ref os) = self.os_fingerprint {
            writeln!(f)?;
            writeln!(f, "OS Fingerprint")?;
            writeln!(f, "--------------")?;
            writeln!(f, "Detected OS     : {}", os.os_name)?;
            writeln!(f, "Confidence      : {}%", os.confidence)?;
            writeln!(f, "Details         : {}", os.details)?;
        }
        if !self.services.is_empty() {
            writeln!(f)?;
            writeln!(f, "Service Enumeration")?;
            writeln!(f, "-------------------")?;
            for svc in &self.services {
                writeln!(
                    f,
                    "{:<8} {:<15} {:<10} {}",
                    svc.port, svc.name, svc.version, svc.extra
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct OsFingerprint {
    pub os_name: String,
    pub confidence: u8,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub port: u16,
    pub name: String,
    pub version: String,
    pub extra: String,
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { s } else { &s[..max] }
}

/// Well-known port-to-service mapping for fingerprinting.
fn well_known_service(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 => Some("http"),
        110 => Some("pop3"),
        111 => Some("rpcbind"),
        135 => Some("msrpc"),
        139 => Some("netbios-ssn"),
        143 => Some("imap"),
        443 => Some("https"),
        445 => Some("microsoft-ds"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("ms-sql"),
        1521 => Some("oracle"),
        3306 => Some("mysql"),
        3389 => Some("ms-wbt-server"),
        5432 => Some("postgresql"),
        5900 => Some("vnc"),
        6379 => Some("redis"),
        8080 => Some("http-proxy"),
        8443 => Some("https-alt"),
        27017 => Some("mongodb"),
        _ => None,
    }
}

/// Run a TCP connect scan against the given host and port range.
///
/// This is a synchronous, blocking scan suitable for authorized testing.
/// Each connection attempt uses the given timeout. Returns a structured
/// report with open ports, service detection, and banner grabbing.
pub fn run_tcp_scan(
    target: &str,
    ports: &[u16],
    timeout_ms: u64,
    grab_banners: bool,
) -> PortScanReport {
    let timeout = Duration::from_millis(timeout_ms);
    let start = Instant::now();

    // Resolve the target
    let target_ip = resolve_target(target);

    let mut open_ports = Vec::new();
    let mut closed_ports = 0;
    let mut filtered_ports = 0;
    let mut timeout_ports = 0;

    for &port in ports {
        let result = scan_port(target, port, timeout, grab_banners);
        match result.state {
            PortState::Open => open_ports.push(result),
            PortState::Closed => closed_ports += 1,
            PortState::Filtered => filtered_ports += 1,
            PortState::Timeout => timeout_ports += 1,
        }
    }

    let scan_duration_ms = start.elapsed().as_millis() as u64;

    // OS fingerprinting based on open ports and banner patterns
    let os_fingerprint = fingerprint_os(&open_ports);

    // Service enumeration from banners and port mapping
    let services: Vec<ServiceInfo> = open_ports
        .iter()
        .map(|pr| ServiceInfo {
            port: pr.port,
            name: pr.service.clone().unwrap_or_else(|| "unknown".to_string()),
            version: extract_version(pr.banner.as_deref()),
            extra: pr
                .banner
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(60)
                .collect(),
        })
        .collect();

    PortScanReport {
        target: target.to_string(),
        target_ip,
        scan_type: "TCP Connect".to_string(),
        total_ports_scanned: ports.len(),
        open_ports,
        closed_ports,
        filtered_ports,
        timeout_ports,
        scan_duration_ms,
        os_fingerprint,
        services,
    }
}

fn resolve_target(target: &str) -> Option<Ipv4Addr> {
    // Try parsing as IP first
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    // Try DNS resolution
    let addr = format!("{target}:0").to_socket_addrs().ok()?.next()?;
    match addr.ip() {
        IpAddr::V4(ip) => Some(ip),
        _ => None,
    }
}

fn scan_port(target: &str, port: u16, timeout: Duration, grab_banners: bool) -> PortResult {
    let addr = format!("{target}:{port}");
    let start = Instant::now();

    let state = match TcpStream::connect_timeout(
        &addr.parse().unwrap_or_else(|_| {
            // Fallback: try address resolution
            "0.0.0.0:0".parse().unwrap()
        }),
        timeout,
    ) {
        Ok(stream) => {
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            PortState::Open
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionRefused => PortState::Closed,
        Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => PortState::Timeout,
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => PortState::Filtered,
        Err(_) => PortState::Filtered,
    };

    let response_time_ms = start.elapsed().as_millis() as u64;
    let service = well_known_service(port).map(str::to_string);

    let banner = if state == PortState::Open && grab_banners {
        grab_banner(target, port, timeout)
    } else {
        None
    };

    PortResult {
        port,
        state,
        service,
        banner,
        response_time_ms,
    }
}

fn grab_banner(target: &str, port: u16, timeout: Duration) -> Option<String> {
    let addr = format!("{target}:{port}");
    let mut stream = TcpStream::connect_timeout(&addr.parse().ok()?, timeout).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));

    let mut buffer = [0u8; 1024];
    // Some services send a banner on connect (HTTP, SMTP, FTP)
    // For HTTP, we need to send a request first
    if port == 80 || port == 8080 || port == 443 {
        let _ = stream.write_all(b"HEAD / HTTP/1.0\r\nHost: ");
        let _ = stream.write_all(target.as_bytes());
        let _ = stream.write_all(b"\r\n\r\n");
    }

    let n = stream.read(&mut buffer).ok()?;
    if n > 0 {
        let banner = String::from_utf8_lossy(&buffer[..n])
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if !banner.is_empty() {
            Some(banner)
        } else {
            None
        }
    } else {
        None
    }
}

use std::io::Read;

fn fingerprint_os(open_ports: &[PortResult]) -> Option<OsFingerprint> {
    let ports: Vec<u16> = open_ports.iter().map(|p| p.port).collect();

    // Heuristic OS detection based on characteristic port patterns
    let has_3389 = ports.contains(&3389);
    let has_445 = ports.contains(&445);
    let has_135 = ports.contains(&135);
    let has_22 = ports.contains(&22);
    let has_80 = ports.contains(&80);
    let has_443 = ports.contains(&443);

    if has_3389 && has_445 && has_135 {
        Some(OsFingerprint {
            os_name: "Windows (Server/Desktop)".to_string(),
            confidence: 85,
            details: "Characteristic Windows ports: RDP(3389), SMB(445), MSRPC(135)".to_string(),
        })
    } else if has_22 && has_80 && !has_445 && !has_135 && !has_3389 {
        Some(OsFingerprint {
            os_name: "Linux/Unix".to_string(),
            confidence: 70,
            details: "SSH(22) + HTTP(80) without Windows-specific services".to_string(),
        })
    } else if has_22 && has_443 {
        Some(OsFingerprint {
            os_name: "Linux/Unix (server)".to_string(),
            confidence: 60,
            details: "SSH(22) + HTTPS(443) — typical server configuration".to_string(),
        })
    } else if has_445 && !has_22 {
        Some(OsFingerprint {
            os_name: "Windows (legacy)".to_string(),
            confidence: 55,
            details: "SMB(445) present without SSH — legacy Windows".to_string(),
        })
    } else {
        None
    }
}

fn extract_version(banner: Option<&str>) -> String {
    let banner = match banner {
        Some(b) => b,
        None => return "unknown".to_string(),
    };

    // Try to extract version strings from common patterns
    if banner.contains("Apache/") {
        if let Some(start) = banner.find("Apache/") {
            let rest = &banner[start + 7..];
            let version: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.')
                .collect();
            return format!("Apache/{version}");
        }
    }
    if banner.contains("nginx/") {
        if let Some(start) = banner.find("nginx/") {
            let rest = &banner[start + 6..];
            let version: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.')
                .collect();
            return format!("nginx/{version}");
        }
    }
    if banner.contains("OpenSSH_") {
        if let Some(start) = banner.find("OpenSSH_") {
            let rest = &banner[start + 8..];
            let version: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.')
                .collect();
            return format!("OpenSSH_{version}");
        }
    }
    if banner.contains("ProFTPD") {
        return "ProFTPD".to_string();
    }
    if banner.contains("vsFTPd") {
        return "vsFTPd".to_string();
    }

    "detected".to_string()
}

/// Run a SYN scan simulation (reports what a SYN scan would find based on
/// connect scan results, with timing analysis for filtered detection).
pub fn run_syn_scan_analysis(target: &str, ports: &[u16], timeout_ms: u64) -> PortScanReport {
    // SYN scan is conceptually different but for a builtin we approximate
    // using connect scan with stricter timeout and no banner grabbing
    let mut report = run_tcp_scan(target, ports, timeout_ms, false);
    report.scan_type = "SYN (half-open) Analysis".to_string();

    // Reclassify very fast responses as potentially filtered (ICMP unreachable)
    for port in &mut report.open_ports {
        if port.response_time_ms < 1 {
            // Sub-millisecond response often means ICMP unreachable (filtered)
            port.state = PortState::Filtered;
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_service_maps_common_ports() {
        assert_eq!(well_known_service(22), Some("ssh"));
        assert_eq!(well_known_service(80), Some("http"));
        assert_eq!(well_known_service(443), Some("https"));
        assert_eq!(well_known_service(3306), Some("mysql"));
        assert_eq!(well_known_service(9999), None);
    }

    #[test]
    fn port_state_display() {
        assert_eq!(PortState::Open.to_string(), "open");
        assert_eq!(PortState::Closed.to_string(), "closed");
        assert_eq!(PortState::Filtered.to_string(), "filtered");
    }

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_string_cut() {
        assert_eq!(truncate("hello world", 5), "hello");
    }

    #[test]
    fn fingerprint_os_detects_windows() {
        let ports = vec![
            PortResult {
                port: 135,
                state: PortState::Open,
                service: None,
                banner: None,
                response_time_ms: 1,
            },
            PortResult {
                port: 445,
                state: PortState::Open,
                service: None,
                banner: None,
                response_time_ms: 1,
            },
            PortResult {
                port: 3389,
                state: PortState::Open,
                service: None,
                banner: None,
                response_time_ms: 1,
            },
        ];
        let os = fingerprint_os(&ports);
        assert!(os.is_some());
        assert!(os.unwrap().os_name.contains("Windows"));
    }

    #[test]
    fn fingerprint_os_detects_linux() {
        let ports = vec![
            PortResult {
                port: 22,
                state: PortState::Open,
                service: None,
                banner: None,
                response_time_ms: 1,
            },
            PortResult {
                port: 80,
                state: PortState::Open,
                service: None,
                banner: None,
                response_time_ms: 1,
            },
        ];
        let os = fingerprint_os(&ports);
        assert!(os.is_some());
        assert!(os.unwrap().os_name.contains("Linux"));
    }

    #[test]
    fn extract_version_from_apache_banner() {
        assert_eq!(
            extract_version(Some("Apache/2.4.41 (Ubuntu)")),
            "Apache/2.4.41"
        );
    }

    #[test]
    fn extract_version_from_nginx_banner() {
        assert_eq!(extract_version(Some("nginx/1.18.0")), "nginx/1.18.0");
    }

    #[test]
    fn extract_version_from_ssh_banner() {
        assert_eq!(
            extract_version(Some("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")),
            "OpenSSH_8.9p1"
        );
    }

    #[test]
    fn extract_version_unknown_banner() {
        assert_eq!(
            extract_version(Some("220 mail.example.com ESMTP")),
            "detected"
        );
    }
}
