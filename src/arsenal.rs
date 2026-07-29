//! Native offline "arsenal" substitutes for every cataloged tool.
//!
//! Each cataloged tool that has no bespoke forensic substitute in
//! [`crate::builtin_tools`] is handled here. Every entry performs **real,
//! offline analysis** of the operator-supplied local input file — no network
//! access, no external binary is ever spawned. Where a genuine analyzer
//! already exists in [`crate::offensive`] we reuse it; the catch-all path runs
//! a generic binary/string analysis so that no tool is ever a dead stub.

use std::fmt;
use std::fs;
use std::path::Path;

use crate::offensive::credential_attack::{
    analyze_password_strength, generate_targeted_wordlist, identify_hash,
};
use crate::offensive::evasion::{generate_decoys, obfuscate_powershell};
use crate::offensive::payload_gen::{analyze_payload, suggest_evasion};
use crate::offensive::post_exploit::{
    analyze_authorized_keys, analyze_hosts_file, analyze_passwd_file, analyze_shadow_file,
    analyze_sudoers,
};
use crate::offensive::web_exploit::{analyze_security_headers, detect_sqli_errors};
use crate::offensive::wireless::{analyze_eapol_frames, analyze_wps_pin, audit_wireless_security};

/// Largest input file the arsenal will read into memory (16 MiB).
const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

/// Error returned when an arsenal substitute cannot run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArsenalError(pub String);

impl fmt::Display for ArsenalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ArsenalError {}

/// Every tool name the arsenal can execute. Kept in sync with the catalog by
/// the coverage test at the bottom of this module.
#[must_use]
pub fn handles(name: &str) -> bool {
    dispatch_category(name).is_some()
}

/// The functional category a tool maps to. `None` means the generic
/// binary/string analyzer is used (still a real, offline analysis).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Category {
    HashCracker,
    Credential,
    Wordlist,
    Web,
    WirelessAudit,
    WirelessHandshake,
    WpsAttack,
    ScanInventory,
    Payload,
    Privesc,
    SourceScan,
    Evasion,
    Sniffer,
    Binary,
    Forensic,
}

fn dispatch_category(name: &str) -> Option<Category> {
    use Category::*;
    let category = match name {
        // ── Credential / hash cracking ──────────────────────────────────
        "hashcat" | "john" | "ophcrack" | "rcrack" => HashCracker,
        "hydra" | "medusa" | "ncrack" | "crackmapexec" | "netexec" | "evil-winrm" | "smbmap" => {
            Credential
        }
        "crunch" | "cewl" => Wordlist,

        // ── Web application testing ─────────────────────────────────────
        "sqlmap" | "nikto" | "wpscan" | "whatweb" | "wafw00f" | "nuclei" | "skipfish" | "wfuzz"
        | "ffuf" | "gobuster" | "dirb" | "feroxbuster" | "burpsuite" | "httrack" | "cutycapt"
        | "beef-xss" => Web,

        // ── Wireless ────────────────────────────────────────────────────
        "aircrack-ng" | "wifite" | "pyrit" => WirelessHandshake,
        "reaver" => WpsAttack,
        "kismet" | "giskismet" | "bettercap" | "mfoc" | "mfterm" | "chirpw" => WirelessAudit,

        // ── Reconnaissance / scanning (offline inventory analysis) ──────
        "nmap" | "zenmap" | "masscan" | "netdiscover" | "amass" | "subfinder" | "dmitry"
        | "enum4linux" | "ike-scan" => ScanInventory,

        // ── Payload / exploit generation ────────────────────────────────
        "msfconsole" | "msfpc" | "setoolkit" | "searchsploit" => Payload,

        // ── Post-exploitation / host hardening ──────────────────────────
        "chkrootkit" | "lynis" | "termineter" => Privesc,

        // ── Static source / dependency analysis ─────────────────────────
        "semgrep" => SourceScan,

        // ── Evasion / traffic manipulation ──────────────────────────────
        "macchanger" | "yersinia" | "thc-ipv6" => Evasion,

        // ── Passive capture / sniffing ──────────────────────────────────
        "tcpdump" | "netsniff-ng" | "ettercap" | "driftnet" | "mitmproxy" => Sniffer,

        // ── Mobile / binary reverse engineering ─────────────────────────
        "androguard" | "apkleaks" | "apksigner" | "apktool" | "dex2jar" | "jadx" | "drozer"
        | "frida" | "objection" | "qark" | "mobsf" | "trueseeing" | "mariana-trench" => Binary,

        // ── Local forensic artifact parsers ─────────────────────────────
        "galleta" | "mdb-sql" | "sqlitebrowser" | "keepnote" | "recordmydesktop" => Forensic,

        _ => return None,
    };
    Some(category)
}

/// Runs the arsenal substitute `name` against `input`, returning a rendered
/// text report.
///
/// # Errors
///
/// Returns [`ArsenalError`] if `name` has no arsenal handler, or if the input
/// file cannot be read (missing, too large, or an I/O error).
pub fn run(name: &str, input: &Path) -> Result<String, ArsenalError> {
    let Some(category) = dispatch_category(name) else {
        return Err(ArsenalError(format!("no arsenal substitute for '{name}'")));
    };
    match category {
        Category::HashCracker => hash_cracker_report(name, &read_text(input)?),
        Category::Credential => credential_report(name, &read_text(input)?),
        Category::Wordlist => wordlist_report(name, &read_text(input)?),
        Category::Web => web_report(name, &read_text(input)?),
        Category::WirelessAudit => wireless_audit_report(name, &read_text(input)?),
        Category::WirelessHandshake => handshake_report(name, input)?,
        Category::WpsAttack => wps_report(name, &read_text(input)?),
        Category::ScanInventory => scan_inventory_report(name, &read_text(input)?),
        Category::Payload => payload_report(name, &read_text(input)?),
        Category::Privesc => privesc_report(name, &read_text(input)?),
        Category::SourceScan => source_scan_report(name, &read_text(input)?),
        Category::Evasion => evasion_report(name, &read_text(input)?),
        Category::Sniffer => sniffer_report(name, input)?,
        Category::Binary => binary_report(name, input)?,
        Category::Forensic => forensic_report(name, input)?,
    }
    .pipe(Ok)
}

// ── Input helpers ───────────────────────────────────────────────────────────

fn read_text(input: &Path) -> Result<String, ArsenalError> {
    let bytes = read_bytes(input)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn read_bytes(input: &Path) -> Result<Vec<u8>, ArsenalError> {
    let metadata = fs::symlink_metadata(input)
        .map_err(|source| ArsenalError(format!("{}: {source}", input.display())))?;
    if metadata.file_type().is_symlink() {
        return Err(ArsenalError("input must not be a symbolic link".to_string()));
    }
    if !metadata.is_file() {
        return Err(ArsenalError(format!(
            "input must be a regular file: {}",
            input.display()
        )));
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(ArsenalError(format!(
            "input exceeds the {MAX_INPUT_BYTES}-byte arsenal limit"
        )));
    }
    fs::read(input).map_err(|source| ArsenalError(format!("{}: {source}", input.display())))
}

/// A consistent report banner matching the built-in forensic substitutes.
fn banner(tool: &str, title: &str, input: &Path) -> String {
    format!(
        "{title}\n{underline}\nTool           : {tool} (built-in substitute)\nNetwork used   : No\nInput          : {path}\n\n",
        underline = "=".repeat(title.len()),
        path = input.display(),
    )
}

/// Non-empty, comment-stripped lines of an input, trimmed.
fn payload_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

// ── Category reports ─────────────────────────────────────────────────────────

fn hash_cracker_report(tool: &str, text: &str) -> String {
    let mut out = format!(
        "{tool} — Offline Hash Identification\n{underline}\nTool           : {tool} (built-in substitute)\nNetwork used   : No\n\n",
        underline = "=".repeat(34),
    );
    let hashes = payload_lines(text);
    if hashes.is_empty() {
        out.push_str("No candidate hashes found in input (one hash per line).\n");
        return out;
    }
    out.push_str(&format!("Candidate hashes analyzed: {}\n\n", hashes.len()));
    for (index, hash) in hashes.iter().take(500).enumerate() {
        let analysis = identify_hash(hash);
        out.push_str(&format!("[{}] {analysis}\n", index + 1));
    }
    out
}

fn credential_report(tool: &str, text: &str) -> String {
    let mut out = format!(
        "{tool} — Offline Credential Strength Assessment\n{underline}\nTool           : {tool} (built-in substitute)\nNetwork used   : No\n\n",
        underline = "=".repeat(44),
    );
    let creds = payload_lines(text);
    if creds.is_empty() {
        out.push_str("No candidate passwords found (one credential per line).\n");
        return out;
    }
    out.push_str(&format!(
        "Passwords assessed: {} (live brute force is disabled offline; \
         this ranks candidates by resistance)\n\n",
        creds.len()
    ));
    for (index, cred) in creds.iter().take(200).enumerate() {
        // Accept `user:pass` pairs as well as bare passwords.
        let password = cred.rsplit(':').next().unwrap_or(cred);
        let strength = analyze_password_strength(password);
        out.push_str(&format!("[{}] {strength}\n", index + 1));
    }
    out
}

fn wordlist_report(tool: &str, text: &str) -> String {
    let lines = payload_lines(text);
    let mut out = format!(
        "{tool} — Targeted Wordlist Generation\n{underline}\nTool           : {tool} (built-in substitute)\nNetwork used   : No\n\n",
        underline = "=".repeat(33),
    );
    let Some((target, extra)) = lines.split_first() else {
        out.push_str("Provide a target/seed word on the first line, optional extra words after.\n");
        return out;
    };
    let wordlist = generate_targeted_wordlist(target, None, None, extra);
    out.push_str(&format!(
        "Seed target    : {target}\nExtra seeds    : {}\nGenerated words: {}\n\n",
        extra.len(),
        wordlist.len()
    ));
    for word in wordlist.iter().take(1000) {
        out.push_str(word);
        out.push('\n');
    }
    out
}

fn web_report(tool: &str, text: &str) -> String {
    let mut out = format!(
        "{tool} — Offline Web Response Analysis\n{underline}\nTool           : {tool} (built-in substitute)\nNetwork used   : No\n\n",
        underline = "=".repeat(34),
    );

    // Parse `Header: value` lines from the captured HTTP response.
    let headers: Vec<(String, String)> = text
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .filter(|(name, _)| !name.is_empty() && !name.contains(' '))
        .collect();

    out.push_str("Security Headers\n----------------\n");
    let findings = analyze_security_headers(&headers);
    if findings.is_empty() {
        out.push_str("No missing/weak security headers detected.\n");
    } else {
        for finding in &findings {
            out.push_str(&format!("{finding}\n"));
        }
    }

    out.push_str("\nSQL Error Signatures\n--------------------\n");
    let sqli = detect_sqli_errors(text);
    if sqli.is_empty() {
        out.push_str("No database error signatures observed in body.\n");
    } else {
        for signature in &sqli {
            out.push_str(&format!("- {signature}\n"));
        }
    }

    // Heuristic reflected-input scan for XSS-prone contexts.
    out.push_str("\nReflection / Injection Heuristics\n---------------------------------\n");
    let mut hits = 0_usize;
    for marker in ["<script", "onerror=", "onload=", "javascript:", "<img", "%3Cscript"] {
        let count = text.matches(marker).count();
        if count > 0 {
            hits += 1;
            out.push_str(&format!("Potential XSS sink '{marker}': {count} occurrence(s)\n"));
        }
    }
    if hits == 0 {
        out.push_str("No obvious reflected-script sinks in body.\n");
    }
    out
}

fn wireless_audit_report(tool: &str, text: &str) -> String {
    let mut out = format!(
        "{tool} — Wireless Security Audit\n{underline}\nTool           : {tool} (built-in substitute)\nNetwork used   : No\n\n",
        underline = "=".repeat(28),
    );
    // Expect `essid,security,encryption` per line (survey export).
    let mut networks = 0_usize;
    for line in payload_lines(text) {
        let fields: Vec<&str> = line.split([',', '\t']).map(str::trim).collect();
        let essid = fields.first().copied().unwrap_or("<unknown>");
        let security = fields.get(1).copied().unwrap_or("Open");
        let encryption = fields.get(2).copied().unwrap_or("None");
        let audit = audit_wireless_security(essid, security, encryption);
        out.push_str(&format!("{audit}\n"));
        networks += 1;
        if networks >= 100 {
            break;
        }
    }
    if networks == 0 {
        out.push_str(
            "Provide one network per line as: ESSID,security(WPA2/WPA3/WEP/Open),encryption(CCMP/TKIP/None)\n",
        );
    }
    out
}

fn handshake_report(tool: &str, input: &Path) -> Result<String, ArsenalError> {
    let text = read_text(input)?;
    let mut out = banner(tool, &format!("{tool} — WPA Handshake Analysis"), input);
    // Parse hex-encoded EAPOL frames, one per line; fall back to raw bytes.
    let mut frames: Vec<Vec<u8>> = Vec::new();
    for line in payload_lines(&text) {
        if let Some(frame) = decode_hex(line) {
            frames.push(frame);
        }
    }
    if frames.is_empty() {
        frames.push(read_bytes(input)?);
    }
    let info = analyze_eapol_frames(&frames);
    out.push_str(&format!("Frames parsed  : {}\n\n{info}\n", frames.len()));
    Ok(out)
}

fn wps_report(tool: &str, text: &str) -> String {
    let mut out = format!(
        "{tool} — WPS PIN Analysis\n{underline}\nTool           : {tool} (built-in substitute)\nNetwork used   : No\n\n",
        underline = "=".repeat(22),
    );
    match payload_lines(text).first() {
        Some(pin) => {
            let info = analyze_wps_pin(pin);
            out.push_str(&format!("{info}\n"));
        }
        None => out.push_str("Provide an 8-digit WPS PIN on the first line.\n"),
    }
    out
}

fn scan_inventory_report(tool: &str, text: &str) -> String {
    let mut out = format!(
        "{tool} — Offline Service Inventory Analysis\n{underline}\nTool           : {tool} (built-in substitute)\nNetwork used   : No\n\nNote: active probing is disabled offline. This parses a host/service\ninventory (e.g. a prior scan, an asset list, or `host port service` lines)\nand flags exposure risk.\n\n",
        underline = "=".repeat(39),
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
        let risk = risky_service(&lower, port);
        if let Some((service, reason)) = risk {
            risky += 1;
            out.push_str(&format!("[RISK] {line}\n       {service}: {reason}\n"));
        }
        services += 1;
        if services >= 500 {
            break;
        }
    }
    out.push_str(&format!(
        "\nSummary\n-------\nEntries analyzed : {services}\nFlagged exposures: {risky}\n"
    ));
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
        ("microsoft-ds", 445, "SMB", "lateral movement / ransomware target"),
        ("rdp", 3389, "RDP", "brute-force and BlueKeep exposure"),
        ("vnc", 5900, "VNC", "often unauthenticated remote desktop"),
        ("mysql", 3306, "MySQL", "database exposed to the network"),
        ("mssql", 1433, "MSSQL", "database exposed to the network"),
        ("mongodb", 27017, "MongoDB", "frequently unauthenticated"),
        ("redis", 6379, "Redis", "frequently unauthenticated"),
        ("elasticsearch", 9200, "Elasticsearch", "frequently unauthenticated"),
        ("snmp", 161, "SNMP", "default community strings leak topology"),
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

fn payload_report(tool: &str, text: &str) -> String {
    let mut out = format!(
        "{tool} — Payload Analysis & Evasion Advisory\n{underline}\nTool           : {tool} (built-in substitute)\nNetwork used   : No\n\n",
        underline = "=".repeat(41),
    );
    let sample = text.trim();
    if sample.is_empty() {
        out.push_str("Provide a payload/command string to analyze.\n");
        return out;
    }
    let analysis = analyze_payload(sample);
    out.push_str(&format!("{analysis}\n\nEvasion Suggestions\n-------------------\n"));
    let suggestions = suggest_evasion(&analysis);
    if suggestions.is_empty() {
        out.push_str("No additional evasion transforms recommended.\n");
    } else {
        for suggestion in &suggestions {
            out.push_str(&format!("{suggestion}\n"));
        }
    }
    out
}

fn privesc_report(tool: &str, text: &str) -> String {
    let mut out = format!(
        "{tool} — Host Hardening & Privilege-Escalation Review\n{underline}\nTool           : {tool} (built-in substitute)\nNetwork used   : No\n\n",
        underline = "=".repeat(50),
    );
    let mut total = 0_usize;
    total += push_section(
        &mut out,
        "Password Database (/etc/passwd)",
        analyze_passwd_file(text).iter().map(ToString::to_string).collect(),
    );
    total += push_section(
        &mut out,
        "Shadow Database (/etc/shadow)",
        analyze_shadow_file(text).iter().map(ToString::to_string).collect(),
    );
    total += push_section(
        &mut out,
        "Sudo Policy (/etc/sudoers)",
        analyze_sudoers(text).iter().map(ToString::to_string).collect(),
    );
    total += push_section(
        &mut out,
        "Authorized Keys",
        analyze_authorized_keys(text).iter().map(ToString::to_string).collect(),
    );
    total += push_section(
        &mut out,
        "Hosts / Trust File",
        analyze_hosts_file(text).iter().map(ToString::to_string).collect(),
    );
    out.push_str(&format!("Total indicators: {total}\n"));
    out
}

/// Appends a titled section and returns the number of indicator lines.
fn push_section(out: &mut String, title: &str, lines: Vec<String>) -> usize {
    out.push_str(&format!("{title}\n{}\n", "-".repeat(title.len())));
    if lines.is_empty() {
        out.push_str("No indicators.\n\n");
    } else {
        for line in &lines {
            out.push_str(&format!("{line}\n"));
        }
        out.push('\n');
    }
    lines.len()
}

fn source_scan_report(tool: &str, text: &str) -> String {
    let mut out = format!(
        "{tool} — Static Source Pattern Scan\n{underline}\nTool           : {tool} (built-in substitute)\nNetwork used   : No\n\n",
        underline = "=".repeat(32),
    );
    // (needle, severity, description)
    const RULES: &[(&str, &str, &str)] = &[
        ("eval(", "HIGH", "dynamic code evaluation"),
        ("exec(", "HIGH", "dynamic code execution"),
        ("os.system(", "HIGH", "shell command execution"),
        ("subprocess.", "MEDIUM", "subprocess invocation"),
        ("pickle.loads", "HIGH", "insecure deserialization"),
        ("yaml.load(", "HIGH", "unsafe YAML load"),
        ("innerHTML", "MEDIUM", "DOM XSS sink"),
        ("document.write", "MEDIUM", "DOM XSS sink"),
        ("md5(", "LOW", "weak hash algorithm"),
        ("sha1(", "LOW", "weak hash algorithm"),
        ("verify=False", "MEDIUM", "TLS verification disabled"),
        ("AKIA", "HIGH", "possible AWS access key id"),
        ("-----BEGIN", "HIGH", "embedded private key/cert"),
        ("password =", "MEDIUM", "possible hardcoded credential"),
        ("password:", "MEDIUM", "possible hardcoded credential"),
        ("secret", "LOW", "possible embedded secret"),
        ("api_key", "MEDIUM", "possible embedded API key"),
        ("TODO", "INFO", "unfinished code marker"),
    ];
    let mut total = 0_usize;
    for (number, line) in text.lines().enumerate().take(200_000) {
        let lower = line.to_lowercase();
        for (needle, severity, description) in RULES {
            if lower.contains(&needle.to_lowercase()) {
                total += 1;
                out.push_str(&format!(
                    "[{severity}] line {}: {description} ({needle})\n",
                    number + 1
                ));
                if total >= 1000 {
                    out.push_str("... (truncated at 1000 findings)\n");
                    return out;
                }
            }
        }
    }
    out.push_str(&format!("\nTotal findings: {total}\n"));
    if total == 0 {
        out.push_str("No matching insecure patterns found.\n");
    }
    out
}

fn evasion_report(tool: &str, text: &str) -> String {
    let mut out = format!(
        "{tool} — Evasion Transform Generator\n{underline}\nTool           : {tool} (built-in substitute)\nNetwork used   : No\n\n",
        underline = "=".repeat(33),
    );
    let sample = text.trim();
    if sample.is_empty() {
        out.push_str("Provide a command/payload to transform.\n");
        return out;
    }
    out.push_str("PowerShell Obfuscation\n----------------------\n");
    for result in obfuscate_powershell(sample).iter().take(10) {
        out.push_str(&format!("{result}\n"));
    }
    out.push_str("\nDecoy Traffic Plan\n------------------\n");
    // Use the first token that looks like an IP as the real source.
    let real_ip = sample
        .split_whitespace()
        .find(|t| t.split('.').filter(|o| o.parse::<u8>().is_ok()).count() == 4)
        .unwrap_or("10.0.0.1");
    out.push_str(&format!("{}\n", generate_decoys(real_ip, 5)));
    out
}

fn sniffer_report(tool: &str, input: &Path) -> Result<String, ArsenalError> {
    // A pcap file has a genuine builtin analyzer; reuse it. Otherwise fall
    // back to a generic binary analysis of the capture bytes.
    match crate::pcap::run_wireshark(input) {
        Ok(report) => Ok(format!(
            "{}{report}\n",
            banner(tool, &format!("{tool} — Passive Capture Analysis"), input)
        )),
        Err(_) => binary_report(tool, input),
    }
}

fn binary_report(tool: &str, input: &Path) -> Result<String, ArsenalError> {
    // Reuse the volatility-grade offline binary analyzer (entropy, embedded
    // signatures, printable strings) — a genuine reverse-engineering triage.
    let report = crate::builtin_tools::run_volatility(input)
        .map_err(|error| ArsenalError(error.to_string()))?;
    Ok(format!(
        "{}Binary triage (entropy / embedded signatures / strings):\n\n{report}\n",
        banner(tool, &format!("{tool} — Offline Binary Triage"), input)
    ))
}

fn forensic_report(tool: &str, input: &Path) -> Result<String, ArsenalError> {
    let bytes = read_bytes(input)?;
    let mut out = banner(tool, &format!("{tool} — Local Artifact Analysis"), input);
    out.push_str(&format!("Size           : {} bytes\n", bytes.len()));
    out.push_str(&format!("Detected type  : {}\n\n", detect_file_type(&bytes)));

    out.push_str("ASCII Strings (first 60)\n------------------------\n");
    let mut count = 0_usize;
    for text in extract_strings(&bytes, 4).into_iter().take(60) {
        out.push_str(&format!("- {text}\n"));
        count += 1;
    }
    if count == 0 {
        out.push_str("No printable strings of length >= 4 found.\n");
    }
    Ok(out)
}

// ── Small offline utilities ──────────────────────────────────────────────────

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    if cleaned.is_empty() || cleaned.len() % 2 != 0 || !cleaned.chars().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    let raw = cleaned.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        let hi = (raw[index] as char).to_digit(16)?;
        let lo = (raw[index + 1] as char).to_digit(16)?;
        bytes.push(((hi << 4) | lo) as u8);
        index += 2;
    }
    Some(bytes)
}

fn detect_file_type(bytes: &[u8]) -> &'static str {
    match bytes {
        [0x50, 0x4B, 0x03, 0x04, ..] => "ZIP/APK/JAR archive",
        [0x7F, b'E', b'L', b'F', ..] => "ELF executable",
        [0xCA, 0xFE, 0xBA, 0xBE, ..] => "Java class / Mach-O fat binary",
        [0xDE, 0xAD, 0xBE, 0xEF, ..] => "Android odex/vdex marker",
        [0x64, 0x65, 0x78, 0x0A, ..] => "Android DEX",
        [0x53, 0x51, 0x4C, 0x69, ..] => "SQLite database",
        [0x25, 0x50, 0x44, 0x46, ..] => "PDF document",
        [0xD4, 0xC3, 0xB2, 0xA1, ..] | [0xA1, 0xB2, 0xC3, 0xD4, ..] => "PCAP capture",
        [0x0A, 0x0D, 0x0D, 0x0A, ..] => "PCAPNG capture",
        [0x4D, 0x5A, ..] => "Windows PE executable",
        _ => "unknown/raw",
    }
}

fn extract_strings(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();
    for &byte in bytes {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte as char);
        } else {
            if current.len() >= min_len {
                strings.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
        }
        if strings.len() >= 4096 {
            break;
        }
    }
    if current.len() >= min_len {
        strings.push(current);
    }
    strings
}

/// Tiny helper so `run` reads as a pipeline.
trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}
impl<T> Pipe for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_non_forensic_cataloged_tool_is_handled() {
        // The seven bespoke forensic substitutes live in `builtin_tools`.
        let bespoke = [
            "autopsy",
            "volatility",
            "wireshark",
            "binwalk",
            "foremost",
            "bulk_extractor",
            "hashdeep",
        ];
        for name in crate::registry::cataloged_tool_names() {
            if bespoke.contains(&name.as_str()) {
                continue;
            }
            assert!(handles(&name), "no arsenal handler for cataloged tool '{name}'");
        }
    }

    #[test]
    fn hash_report_identifies_lines() {
        let report = hash_cracker_report("hashcat", "5f4dcc3b5aa765d61d8327deb882cf99\n");
        assert!(report.contains("Candidate hashes analyzed: 1"));
    }

    #[test]
    fn scan_inventory_flags_telnet() {
        let report = scan_inventory_report("nmap", "23/tcp open telnet\n80/tcp open http\n");
        assert!(report.contains("[RISK]"));
        assert!(report.contains("Telnet"));
    }

    #[test]
    fn hex_decoder_roundtrips() {
        assert_eq!(decode_hex("de:ad:be:ef"), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(decode_hex("xyz"), None);
    }
}
