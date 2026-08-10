//! Offline service-inventory engine.
//!
//! Serves the recon/scanning tools (`nmap`, `masscan`, `netdiscover`,
//! `amass`, `subfinder`, `dmitry`, `enum4linux`, `ike-scan`, …). Active
//! probing is a live-network action these substitutes never take; instead
//! each tool parses the kind of output it would normally consume — a prior
//! scan result, an ARP table, a subdomain list, or an SMB/IKE capture — and
//! produces a tool-specific exposure analysis.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use super::{payload_lines, text_banner};

/// Upper bound on how many input lines each engine consumes.
const MAX_LINES: usize = 500;

pub(super) fn report(tool: &str, text: &str) -> String {
    match tool {
        "nmap" | "zenmap" => nmap_report(tool, text),
        "masscan" => masscan_report(text),
        "netdiscover" => netdiscover_report(text),
        "amass" => amass_report(text),
        "subfinder" => subfinder_report(text),
        "dmitry" => dmitry_report(text),
        "enum4linux" => enum4linux_report(text),
        "ike-scan" => ike_scan_report(text),
        _ => generic_inventory_report(tool, text),
    }
}

// ── Shared helpers ──────────────────────────────────────────────────────────

fn note(out: &mut String, text: &str) {
    let _ = writeln!(out, "Note: {text}\n");
}

fn summary_block(out: &mut String, rows: &[(&str, usize)]) {
    let _ = writeln!(out, "\nSummary\n-------");
    for (label, value) in rows {
        let _ = writeln!(out, "{label:<24}: {value}");
    }
    if rows.iter().all(|(_, value)| *value == 0) {
        out.push_str("No inventory entries found.\n");
    }
}

/// `nmap`-style open-port token: `22/tcp open ssh`, `443/udp open|filtered`.
fn nmap_open_port(lower: &str) -> Option<u16> {
    let token = lower.split_whitespace().next()?;
    let (port_str, proto) = token.split_once('/')?;
    if proto != "tcp" && proto != "udp" {
        return None;
    }
    let port = port_str.parse::<u16>().ok()?;
    (port > 0 && lower.contains("open")).then_some(port)
}

/// `dmitry -p`-style port token: `21/tcp open` inside a `Ports:` line.
fn dmitry_port(lower: &str) -> Option<u16> {
    let token = lower.split_whitespace().find(|t| t.contains('/'))?;
    let (port_str, proto) = token.split_once('/')?;
    if proto != "tcp" && proto != "udp" {
        return None;
    }
    let port = port_str.parse::<u16>().ok()?;
    (port > 0).then_some(port)
}

fn key_value(line: &str, key: &str) -> Option<String> {
    let (k, v) = line.split_once(':')?;
    if k.trim().eq_ignore_ascii_case(key) {
        let v = v.trim();
        (!v.is_empty()).then(|| v.to_string())
    } else {
        None
    }
}

fn is_ipv4(s: &str) -> bool {
    let octets: Vec<&str> = s.split('.').collect();
    octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok())
}

fn is_mac(s: &str) -> bool {
    let pairs: Vec<&str> = s.split(':').collect();
    pairs.len() == 6
        && pairs
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

// ── nmap / zenmap: host + port scan analysis ────────────────────────────────

fn nmap_report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Offline Scan Analysis (hosts, ports, services)");
    note(
        &mut out,
        "Parses a prior scan run (host lines, open ports, MAC, OS detection)\n\
         and flags exposure risk by service.",
    );
    let mut hosts = 0_usize;
    let mut open_ports = 0_usize;
    let mut risky = 0_usize;
    for line in payload_lines(text).into_iter().take(MAX_LINES) {
        let lower = line.to_lowercase();
        if lower.contains("scan report for") {
            hosts += 1;
            let _ = writeln!(out, "[HOST] {line}");
        } else if lower.starts_with("mac address:") {
            let _ = writeln!(out, "[MAC ] {line}");
        } else if lower.starts_with("os details:") || lower.starts_with("os cpe:") {
            let _ = writeln!(out, "[OS  ] {line}");
        } else if let Some(port) = nmap_open_port(&lower) {
            open_ports += 1;
            if let Some((service, reason)) = risky_service(&lower, Some(port)) {
                risky += 1;
                let _ = writeln!(out, "[RISK] {line}\n       {service}: {reason}");
            }
        }
    }
    summary_block(
        &mut out,
        &[
            ("Hosts found", hosts),
            ("Open ports", open_ports),
            ("Flagged exposures", risky),
        ],
    );
    out
}

// ── masscan: fast port-scan inventory ───────────────────────────────────────

fn masscan_report(text: &str) -> String {
    let mut out = text_banner("masscan", "Offline Fast Port Scan Analysis");
    note(
        &mut out,
        "Parses `masscan -oL`/`-oG` output: open ports per target and\n\
         flagged exposure risk.",
    );
    let mut targets: BTreeSet<String> = BTreeSet::new();
    let mut ports = 0_usize;
    let mut risky = 0_usize;
    for line in payload_lines(text).into_iter().take(MAX_LINES) {
        let lower = line.to_lowercase();
        let mut port = None;
        if let Some(rest) = lower.strip_prefix("open ") {
            // -oL list format: "open tcp <port> <ip> <timestamp>".
            let fields: Vec<&str> = rest.split_whitespace().collect();
            if fields.len() >= 3 {
                port = fields[1].parse::<u16>().ok();
                if let Some(ip) = fields.get(2) {
                    targets.insert((*ip).to_string());
                }
            }
        } else if lower.contains("/open/") {
            // -oG grepable: "Host: 1.2.3.4 () Ports: 22/open/tcp//ssh///".
            let mut tokens = lower.split('/');
            if let Some(first) = tokens.next() {
                if let Some(port_token) = first.split_whitespace().last() {
                    port = port_token.parse::<u16>().ok();
                }
            }
            if let Some(host) = lower.split("host:").nth(1) {
                if let Some(ip) = host.split_whitespace().next() {
                    targets.insert(ip.to_string());
                }
            }
        }
        if let Some(p) = port.filter(|p| *p > 0) {
            ports += 1;
            if let Some((service, reason)) = risky_service(&lower, Some(p)) {
                risky += 1;
                let _ = writeln!(out, "[RISK] {line}\n       {service}: {reason}");
            }
        }
    }
    summary_block(
        &mut out,
        &[
            ("Targets", targets.len()),
            ("Open ports", ports),
            ("Flagged exposures", risky),
        ],
    );
    out
}

// ── netdiscover: ARP discovery table ────────────────────────────────────────

fn netdiscover_report(text: &str) -> String {
    let mut out = text_banner("netdiscover", "Offline ARP Discovery Analysis");
    note(
        &mut out,
        "Parses an ARP sweep table (IP, MAC, vendor) and groups the LAN\n\
         footprint by vendor.",
    );
    let mut hosts = 0_usize;
    let mut vendors: BTreeMap<String, usize> = BTreeMap::new();
    for line in payload_lines(text).into_iter().take(MAX_LINES) {
        let Some((ip, mac, vendor)) = parse_arp_line(line) else {
            continue;
        };
        hosts += 1;
        *vendors.entry(vendor.clone()).or_insert(0) += 1;
        let _ = writeln!(out, "[HOST] {ip}  {mac}  {vendor}");
    }
    if !vendors.is_empty() {
        let _ = writeln!(out, "\nVendor breakdown");
        for (vendor, count) in &vendors {
            let _ = writeln!(out, "  {vendor:<28} {count}");
        }
    }
    summary_block(&mut out, &[("Hosts on LAN", hosts)]);
    out
}

fn parse_arp_line(line: &str) -> Option<(String, String, String)> {
    let mut tokens = line.split_whitespace();
    let ip = tokens.next()?;
    let mac = tokens.next()?;
    if !is_ipv4(ip) || !is_mac(mac) {
        return None;
    }
    // Remaining tokens are packet/byte counters followed by the vendor name.
    let vendor: Vec<&str> = tokens
        .filter(|t| !t.bytes().all(|b| b.is_ascii_digit()))
        .collect();
    let vendor = if vendor.is_empty() {
        "Unknown".to_string()
    } else {
        vendor.join(" ")
    };
    Some((ip.to_string(), mac.to_uppercase(), vendor))
}

// ── amass / subfinder: subdomain enumeration ────────────────────────────────

struct SubdomainAnalysis {
    total: usize,
    apexes: BTreeMap<String, usize>,
    interesting: Vec<String>,
}

fn analyze_subdomains(text: &str) -> SubdomainAnalysis {
    let mut total = 0_usize;
    let mut apexes: BTreeMap<String, usize> = BTreeMap::new();
    let mut interesting = Vec::new();
    for line in payload_lines(text).into_iter().take(MAX_LINES) {
        let host = line.trim_end_matches('.');
        if host.is_empty() {
            continue;
        }
        total += 1;
        if let Some(apex) = apex_of(host) {
            *apexes.entry(apex).or_insert(0) += 1;
        }
        if is_interesting_subdomain(host) {
            interesting.push(host.to_string());
        }
    }
    SubdomainAnalysis {
        total,
        apexes,
        interesting,
    }
}

fn apex_of(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() >= 2 {
        Some(labels[labels.len() - 2..].join("."))
    } else {
        None
    }
}

fn is_interesting_subdomain(host: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "admin", "api", "backup", "console", "db", "dev", "git", "grafana", "internal", "jenkins",
        "jira", "mail", "portal", "prod", "stage", "staging", "test", "vpn", "wiki",
    ];
    let lower = host.to_lowercase();
    NEEDLES.iter().any(|needle| lower.contains(needle))
}

fn interesting_section(out: &mut String, interesting: &[String]) {
    if interesting.is_empty() {
        return;
    }
    let _ = writeln!(out, "\nInteresting targets (dev/staging/admin/api/vpn/…):");
    for host in interesting.iter().take(20) {
        let _ = writeln!(out, "  [!] {host}");
    }
    if interesting.len() > 20 {
        let _ = writeln!(out, "  … and {} more", interesting.len() - 20);
    }
}

fn amass_report(text: &str) -> String {
    let mut out = text_banner("amass", "Offline Subdomain Enumeration Analysis");
    note(
        &mut out,
        "Parses enumerated subdomains, groups them by apex domain, and flags\n\
         interesting targets.",
    );
    let analysis = analyze_subdomains(text);
    let _ = writeln!(out, "Total subdomains : {}", analysis.total);
    let _ = writeln!(out, "Apex domains     : {}", analysis.apexes.len());
    if !analysis.apexes.is_empty() {
        let _ = writeln!(out, "\nApex breakdown");
        for (apex, count) in &analysis.apexes {
            let _ = writeln!(out, "  {apex:<28} {count}");
        }
    }
    interesting_section(&mut out, &analysis.interesting);
    summary_block(
        &mut out,
        &[
            ("Subdomains", analysis.total),
            ("Apex domains", analysis.apexes.len()),
            ("Interesting", analysis.interesting.len()),
        ],
    );
    out
}

fn subfinder_report(text: &str) -> String {
    let mut out = text_banner("subfinder", "Offline Subdomain Discovery Analysis");
    note(
        &mut out,
        "Parses discovered subdomains, counts unique hosts, and flags\n\
         interesting targets.",
    );
    let analysis = analyze_subdomains(text);
    let _ = writeln!(out, "Discovered subdomains : {}", analysis.total);
    interesting_section(&mut out, &analysis.interesting);
    summary_block(
        &mut out,
        &[
            ("Subdomains", analysis.total),
            ("Interesting", analysis.interesting.len()),
        ],
    );
    out
}

// ── dmitry: deepmagic recon (whois, ports, banners) ─────────────────────────

fn dmitry_report(text: &str) -> String {
    let mut out = text_banner("dmitry", "Offline Deepmagic Recon Analysis");
    note(
        &mut out,
        "Parses `dmitry -o/-p/-b` output: host identity, open ports, banners,\n\
         and exposure risk.",
    );
    let mut hostname = None;
    let mut ip = None;
    let mut ports = 0_usize;
    let mut risky = 0_usize;
    for line in payload_lines(text).into_iter().take(MAX_LINES) {
        let lower = line.to_lowercase();
        if hostname.is_none() {
            hostname = key_value(line, "hostname");
        }
        if ip.is_none() {
            ip = key_value(line, "ip address").or_else(|| key_value(line, "ip"));
        }
        if let Some(port) = dmitry_port(&lower) {
            ports += 1;
            if let Some((service, reason)) = risky_service(&lower, Some(port)) {
                risky += 1;
                let _ = writeln!(out, "[RISK] {line}\n       {service}: {reason}");
            }
        }
    }
    if let Some(hostname) = hostname {
        let _ = writeln!(out, "[INFO] Hostname: {hostname}");
    }
    if let Some(ip) = ip {
        let _ = writeln!(out, "[INFO] IP      : {ip}");
    }
    summary_block(
        &mut out,
        &[("Open ports", ports), ("Flagged exposures", risky)],
    );
    out
}

// ── enum4linux: SMB enumeration ─────────────────────────────────────────────

fn enum4linux_report(text: &str) -> String {
    let mut out = text_banner("enum4linux", "Offline SMB Enumeration Analysis");
    note(
        &mut out,
        "Parses `enum4linux` output: share names, user accounts, password\n\
         policy, and null/guest access risk.",
    );
    let mut shares = 0_usize;
    let mut users = 0_usize;
    let mut risky = 0_usize;
    for line in payload_lines(text).into_iter().take(MAX_LINES) {
        let lower = line.to_lowercase();
        if lower.contains("sharename") || lower.starts_with("share") {
            shares += 1;
        }
        if lower.starts_with("user:")
            || lower.starts_with("user [")
            || lower.contains("[+] username:")
        {
            users += 1;
        }
        if lower.contains("null session")
            || lower.contains("guest")
            || lower.contains("ipc$")
            || lower.contains("admin$")
            || lower.contains("no password required")
        {
            risky += 1;
            let _ = writeln!(out, "[RISK] {line}");
        }
    }
    summary_block(
        &mut out,
        &[
            ("Shares/entries", shares),
            ("Users", users),
            ("SMB risk flags", risky),
        ],
    );
    out
}

// ── ike-scan: IKE/VPN discovery ─────────────────────────────────────────────

fn ike_scan_report(text: &str) -> String {
    let mut out = text_banner("ike-scan", "Offline IKE/VPN Discovery Analysis");
    note(
        &mut out,
        "Parses `ike-scan` output: responder handshakes, transforms, vendor\n\
         IDs, and Aggressive Mode risk.",
    );
    let mut responders = 0_usize;
    let mut vendors: Vec<String> = Vec::new();
    let mut aggressive = false;
    for line in payload_lines(text).into_iter().take(MAX_LINES) {
        let lower = line.to_lowercase();
        if lower.contains("returned handshake") || lower.contains("handshake returned") {
            responders += 1;
            let _ = writeln!(out, "[HOST] {line}");
        } else if lower.contains("vendor id") {
            let value = line
                .trim()
                .trim_start_matches(|c: char| !c.is_alphanumeric());
            if !value.is_empty() && !vendors.iter().any(|v| v == value) {
                vendors.push(value.to_string());
            }
        }
        if lower.contains("aggressive") {
            aggressive = true;
        }
    }
    let _ = writeln!(out, "\nResponder handshakes : {responders}");
    if !vendors.is_empty() {
        let _ = writeln!(out, "Vendor IDs           : {}", vendors.len());
        for vendor in vendors.iter().take(10) {
            let _ = writeln!(out, "  {vendor}");
        }
    }
    if aggressive {
        out.push_str(
            "\n[RISK] Aggressive Mode negotiated — PSK off-line cracking and MITM\n\
             exposure. Prefer Main Mode with strong DH groups.\n",
        );
    }
    summary_block(
        &mut out,
        &[("Responders", responders), ("Vendors", vendors.len())],
    );
    out
}

// ── Generic fallback: host port service inventory ───────────────────────────

fn generic_inventory_report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Offline Service Inventory Analysis");
    note(
        &mut out,
        "Parses a host/service inventory (host port service lines) and flags\n\
         exposure risk.",
    );
    let mut services = 0_usize;
    let mut risky = 0_usize;
    for line in payload_lines(text).into_iter().take(MAX_LINES) {
        let lower = line.to_lowercase();
        let port = lower
            .split(|c: char| !c.is_ascii_digit())
            .filter_map(|token| token.parse::<u16>().ok())
            .find(|&p| p > 0);
        if let Some((service, reason)) = risky_service(&lower, port) {
            risky += 1;
            let _ = writeln!(out, "[RISK] {line}\n       {service}: {reason}");
        }
        services += 1;
    }
    summary_block(
        &mut out,
        &[("Entries analyzed", services), ("Flagged exposures", risky)],
    );
    out
}

/// Classifies a service/port line as risky, returning `(service, reason)`.
fn risky_service(lower: &str, port: Option<u16>) -> Option<(&'static str, &'static str)> {
    const RISKS: &[(&str, u16, &str, &str)] = &[
        ("telnet", 23, "Telnet", "cleartext remote administration"),
        ("ftp", 21, "FTP", "cleartext credentials and data"),
        ("rlogin", 513, "rlogin", "legacy trust-based auth"),
        ("smb", 445, "SMB", "lateral movement / ransomware target"),
        (
            "microsoft-ds",
            445,
            "SMB",
            "lateral movement / ransomware target",
        ),
        ("rdp", 3389, "RDP", "brute-force and BlueKeep exposure"),
        ("vnc", 5900, "VNC", "often unauthenticated remote desktop"),
        ("mysql", 3306, "MySQL", "database exposed to the network"),
        ("mssql", 1433, "MSSQL", "database exposed to the network"),
        ("mongodb", 27017, "MongoDB", "frequently unauthenticated"),
        ("redis", 6379, "Redis", "frequently unauthenticated"),
        (
            "elasticsearch",
            9200,
            "Elasticsearch",
            "frequently unauthenticated",
        ),
        (
            "snmp",
            161,
            "SNMP",
            "default community strings leak topology",
        ),
        ("ldap", 389, "LDAP", "directory enumeration"),
        ("smtp", 25, "SMTP", "open relay / user enumeration"),
        ("nfs", 2049, "NFS", "world-readable exports"),
    ];
    for (needle, risk_port, service, reason) in RISKS {
        if lower.contains(needle) || port == Some(*risk_port) {
            return Some((service, reason));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmap_report_flags_telnet() {
        let report = report("nmap", "23/tcp open telnet\n80/tcp open http\n");
        assert!(report.contains("[RISK]"));
        assert!(report.contains("Telnet"));
        assert!(report.contains("Hosts found"));
    }

    #[test]
    fn masscan_list_format_reports_targets() {
        let report = report(
            "masscan",
            "open tcp 22 192.168.1.10 1457012345\nopen tcp 80 192.168.1.10 1457012345\n",
        );
        assert!(report.contains("Targets"));
        assert!(report.contains("Open ports"));
        assert!(!report.contains("[RISK]"));
    }

    #[test]
    fn netdiscover_groups_vendors() {
        let report = report(
            "netdiscover",
            "192.168.1.1 00:11:22:33:44:55 5 60 Cisco-Linksys\n\
             192.168.1.2 66:55:44:33:22:11 8 90 Raspberry Pi\n",
        );
        assert!(report.contains("Cisco-Linksys"));
        assert!(report.contains("Raspberry Pi"));
        assert!(report.contains("Vendor breakdown"));
    }

    #[test]
    fn amass_groups_apexes_and_flags_interesting() {
        let report = report(
            "amass",
            "www.example.com\ndev.example.com\nadmin.example.com\napi.other.org\n",
        );
        assert!(report.contains("Apex domains"));
        assert!(report.contains("example.com"));
        assert!(report.contains("other.org"));
        assert!(report.contains("dev.example.com"));
    }

    #[test]
    fn subfinder_counts_discovered_hosts() {
        let report = report("subfinder", "mail.example.com\nwww.example.com\n");
        assert!(report.contains("Discovered subdomains : 2"));
    }

    #[test]
    fn dmitry_flags_open_telnet() {
        let report = report(
            "dmitry",
            "HostName: lab.example\nIP Address: 10.0.0.5\n21/tcp open\n",
        );
        assert!(report.contains("[RISK]"));
        assert!(report.contains("Hostname: lab.example"));
    }

    #[test]
    fn enum4linux_flags_guest_access() {
        let report = report(
            "enum4linux",
            "[+] Sharename    Type    Comment\n[+] Guest account  enabled\n",
        );
        assert!(report.contains("[RISK]"));
        assert!(report.contains("SMB risk flags"));
    }

    #[test]
    fn ike_scan_flags_aggressive_mode() {
        let report = report(
            "ike-scan",
            "192.168.1.1 Main Mode Handshake returned\n\
             Vendor ID: Cisco VPN concentrator\nAggressive Mode Handshake returned\n",
        );
        assert!(report.contains("Responders"));
        assert!(report.contains("Vendor ID"));
        assert!(report.contains("[RISK] Aggressive Mode"));
    }

    #[test]
    fn unknown_tool_falls_back_to_generic() {
        let report = report("example-tool", "23/tcp open telnet\n");
        assert!(report.contains("[RISK]"));
        assert!(report.contains("Entries analyzed"));
    }
}
