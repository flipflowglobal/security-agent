//! Offline service-inventory engine.
//!
//! Serves the recon/scanning tools (`nmap`, `masscan`, `netdiscover`,
//! `amass`, `enum4linux`, `ike-scan`, …). Active probing is a live-network
//! action these substitutes never take; instead they parse a host/service
//! inventory (a prior scan, an asset list, or `host port service` lines) and
//! flag exposure risk by service and port.

use std::fmt::Write as _;

use super::{payload_lines, text_banner};

pub(super) fn report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Offline Service Inventory Analysis");
    out.push_str(
        "Note: active probing is disabled offline. This parses a host/service\n\
         inventory (e.g. a prior scan, an asset list, or `host port service` lines)\n\
         and flags exposure risk.\n\n",
    );
    let mut services = 0_usize;
    let mut risky = 0_usize;
    for line in payload_lines(text) {
        let lower = line.to_lowercase();
        // Extract a port number if present (e.g. "22/tcp" or "port 22").
        let port = lower
            .split(|c: char| !c.is_ascii_digit())
            .filter_map(|t| t.parse::<u16>().ok())
            .find(|&p| p > 0);
        if let Some((service, reason)) = risky_service(&lower, port) {
            risky += 1;
            let _ = writeln!(out, "[RISK] {line}\n       {service}: {reason}");
        }
        services += 1;
        if services >= 500 {
            break;
        }
    }
    let _ = writeln!(
        out,
        "\nSummary\n-------\nEntries analyzed : {services}\nFlagged exposures: {risky}"
    );
    if services == 0 {
        out.push_str("No inventory entries found.\n");
    }
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
    #[test]
    fn flags_telnet() {
        let report = super::report("nmap", "23/tcp open telnet\n80/tcp open http\n");
        assert!(report.contains("[RISK]"));
        assert!(report.contains("Telnet"));
    }
}
