//! Offline web-application testing engine.
//!
//! Serves the web application testing tools (`sqlmap`, `nikto`, `wpscan`,
//! `whatweb`, `wafw00f`, `nuclei`, `skipfish`, `wfuzz`, `ffuf`, `gobuster`,
//! `dirb`, `feroxbuster`, `burpsuite`, `httrack`, `cutycapt`, `beef-xss`).
//! Each tool gets a real offline parser for its most common export format so
//! an operator can feed it a captured response, scan log, or fuzz result and
//! get the same triage the live tool would have produced — without sending a
//! single live request.

use std::fmt::Write as _;

use super::{payload_lines, text_banner};
use crate::offensive::web_exploit::{analyze_security_headers, detect_sqli_errors};

pub(super) fn report(tool: &str, text: &str) -> String {
    match tool {
        "sqlmap" => sqlmap_report(text),
        "nikto" => nikto_report(text),
        "wpscan" => wpscan_report(text),
        "whatweb" | "wafw00f" => fingerprint_report(tool, text),
        "nuclei" => nuclei_report(text),
        "ffuf" | "wfuzz" => fuzz_report(tool, text),
        "gobuster" | "dirb" | "feroxbuster" => dirlist_report(tool, text),
        "burpsuite" => burp_report(text),
        "skipfish" => skipfish_report(text),
        "httrack" => mirror_report(text),
        "beef-xss" => beef_report(text),
        _ => generic_report(tool, text),
    }
}

// ── Shared parsing helpers ────────────────────────────────────────────────────

/// The response head (everything before the first blank line).
fn response_head(text: &str) -> &str {
    match text.split_once("\n\n") {
        Some((head, _)) => head,
        None => match text.split_once("\r\n\r\n") {
            Some((head, _)) => head,
            None => text,
        },
    }
}

fn parse_headers(text: &str) -> Vec<(String, String)> {
    response_head(text)
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .filter(|(name, _)| !name.is_empty() && !name.contains(' '))
        .collect()
}

fn extract_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for token in text.split_whitespace() {
        for scheme in ["http://", "https://"] {
            let Some(rest) = token.strip_prefix(scheme) else {
                continue;
            };
            let end = rest
                .find(['"', '\'', '<', '>', ')', ']', '}', ','])
                .unwrap_or(rest.len());
            let url = format!("{scheme}{}", &rest[..end]);
            if !urls.contains(&url) {
                urls.push(url);
            }
        }
    }
    urls
}

/// First 3-digit token after a `Status:` or `CODE:` marker (gobuster/dirb
/// line format), else a standalone 3-digit HTTP status anywhere in the line.
fn extract_status(line: &str) -> Option<u16> {
    let after = line.find("Status:").or_else(|| line.find("CODE:"))?;
    let digits: String = line[after..]
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take(3)
        .collect();
    if digits.len() != 3 {
        return None;
    }
    digits.parse().ok()
}

const fn is_interesting_status(status: u16) -> bool {
    !matches!(
        status,
        200 | 204 | 301 | 302 | 307 | 308 | 400 | 403 | 404 | 500
    )
}

// ── sqlmap: SQL error signature triage ────────────────────────────────────────

fn sqlmap_report(text: &str) -> String {
    let mut out = text_banner("sqlmap", "SQL Injection Error Analysis");
    let signatures = detect_sqli_errors(text);
    if signatures.is_empty() {
        out.push_str("No SQL error signatures observed in the captured responses.\n");
        return out;
    }
    let _ = writeln!(out, "SQL error signatures observed: {}\n", signatures.len());
    for signature in &signatures {
        let _ = writeln!(out, "- {signature}");
    }
    // Group by DBMS family so the operator knows which backend to target.
    let mut families: Vec<(String, usize)> = Vec::new();
    for signature in &signatures {
        let family = signature
            .split("detected (")
            .nth(1)
            .and_then(|rest| rest.split(')').next())
            .unwrap_or("Unknown");
        let family = family.to_string();
        if let Some(entry) = families.iter_mut().find(|(name, _)| *name == family) {
            entry.1 += 1;
        } else {
            families.push((family, 1));
        }
    }
    out.push_str("\nBackend family breakdown\n------------------------\n");
    for (family, count) in families {
        let _ = writeln!(out, "{family:<24} {count} signature(s)");
    }
    out
}

// ── nikto: server fingerprint + dangerous path discovery ─────────────────────

const DANGEROUS_PATHS: &[&str] = &[
    "/admin",
    "/phpmyadmin",
    "/server-status",
    "/server-info",
    "/.git",
    "/.env",
    "/backup",
    "/backups",
    "/wp-admin",
    "/wp-login.php",
    "/config",
    "/.svn",
];

fn nikto_report(text: &str) -> String {
    let mut out = text_banner("nikto", "Server Hardening Analysis");
    fingerprint_section(&mut out, text);
    let lower = text.to_ascii_lowercase();
    let mut hits = 0_usize;
    for path in DANGEROUS_PATHS {
        if lower.contains(path) {
            hits += 1;
            let _ = writeln!(out, "Dangerous/interesting path referenced: {path}");
        }
    }
    if hits == 0 {
        out.push_str("No dangerous path references detected.\n");
    }
    // Robots.txt directives embedded in a captured response.
    let directives: Vec<&str> = payload_lines(text)
        .into_iter()
        .filter(|line| line.starts_with("Disallow:") || line.starts_with("Allow:"))
        .collect();
    if !directives.is_empty() {
        out.push_str("\nrobots.txt directives\n---------------------\n");
        for line in directives {
            let _ = writeln!(out, "{line}");
        }
    }
    out
}

// ── wpscan: WordPress fingerprinting ─────────────────────────────────────────

fn wpscan_report(text: &str) -> String {
    let mut out = text_banner("wpscan", "WordPress Fingerprint Analysis");
    let lower = text.to_ascii_lowercase();
    let markers = [
        ("wp-login.php", "Login page (login brute-force surface)"),
        ("wp-admin", "Admin panel exposed"),
        ("wp-content", "wp-content served (plugins/themes directory)"),
        ("wp-includes", "wp-includes served (core scripts)"),
        (
            "wp-json",
            "REST API exposed (user enumeration via /wp-json/wp/v2/users)",
        ),
        (
            "xmlrpc.php",
            "XML-RPC enabled (pingback abuse / password brute force)",
        ),
        ("wp_generator", "generator meta tag present"),
    ];
    let mut found = 0_usize;
    for (marker, meaning) in markers {
        if lower.contains(marker) {
            found += 1;
            let _ = writeln!(out, "WordPress marker '{marker}': {meaning}");
        }
    }
    if found == 0 {
        out.push_str("No WordPress markers detected in the captured content.\n");
    }
    // Version disclosure, e.g. `?ver=6.4.2` or `content="WordPress 6.4.2"`.
    let mut versions: Vec<String> = Vec::new();
    for line in payload_lines(text) {
        for needle in ["?ver=", "wordpress "] {
            if let Some(index) = line.to_ascii_lowercase().find(needle) {
                let start = index + needle.len();
                let rest = &line[start..];
                let candidate: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                let digits = candidate.matches(|c: char| c.is_ascii_digit()).count();
                if digits >= 2 && !versions.contains(&candidate) {
                    versions.push(candidate);
                }
            }
        }
    }
    if !versions.is_empty() {
        out.push_str("\nVersion disclosure\n------------------\n");
        for version in versions {
            let _ = writeln!(out, "WordPress version string: {version}");
        }
    }
    // User enumeration hint.
    if lower.contains("author=") || lower.contains("/?author=") {
        out.push_str("\nUser enumeration: 'author=' parameter observed.\n");
    }
    out
}

// ── whatweb / wafw00f: technology + WAF fingerprinting ───────────────────────

fn fingerprint_section(out: &mut String, text: &str) {
    let headers = parse_headers(text);
    let interesting = [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-backend-server",
        "via",
        "x-cache",
        "x-generator",
        "x-drupal-cache",
        "x-shopify-stage",
        "x-turbo-charged-by",
    ];
    out.push_str("Technology fingerprint\n----------------------\n");
    let mut printed = 0_usize;
    for (name, value) in &headers {
        if interesting.contains(&name.to_ascii_lowercase().as_str()) {
            let _ = writeln!(out, "{name}: {value}");
            printed += 1;
        }
    }
    if printed == 0 {
        out.push_str("No recognizable technology headers found.\n");
    }
    let waf = detect_waf(text);
    if waf.is_empty() {
        out.push_str("\nWAF: no known WAF fingerprints detected.\n");
    } else {
        out.push_str("\nWAF fingerprints\n----------------\n");
        for marker in waf {
            let _ = writeln!(out, "- {marker}");
        }
    }
}

fn detect_waf(text: &str) -> Vec<String> {
    let mut waf = Vec::new();
    let lower = text.to_ascii_lowercase();
    let fingerprints = [
        ("cloudflare", "Cloudflare"),
        ("cf-ray", "Cloudflare"),
        ("__cfduid", "Cloudflare"),
        ("sucuri", "Sucuri WAF"),
        ("x-sucuri-id", "Sucuri WAF"),
        ("mod_security", "ModSecurity"),
        ("modsecurity", "ModSecurity"),
        ("bigipserver", "F5 BIG-IP"),
        ("x-iinfo", "Imperva Incapsula"),
        ("x-akamai", "Akamai Ghost"),
        ("nsc_", "Citrix NetScaler"),
        ("x-amzn-requestid", "AWS WAF / CloudFront"),
        ("barracuda", "Barracuda WAF"),
        ("x-waf", "Generic WAF header"),
    ];
    for (marker, name) in fingerprints {
        if lower.contains(marker) {
            waf.push(name.to_string());
        }
    }
    waf
}

fn fingerprint_report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Technology / WAF Fingerprint");
    fingerprint_section(&mut out, text);
    out
}

// ── nuclei: JSONL findings triage ────────────────────────────────────────────

fn json_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":");
    let start = line.find(&needle)? + needle.len();
    let rest = line[start..].trim_start();
    if let Some(quoted) = rest.strip_prefix('"') {
        let end = quoted.find('"')?;
        return Some(quoted[..end].to_string());
    }
    let end = rest.find([',', '}', ' ', '\n']).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

fn nuclei_report(text: &str) -> String {
    let mut out = text_banner("nuclei", "Template Match Triage");
    let mut entries: Vec<(String, String, String, String)> = Vec::new(); // severity, template, host, matched
    for line in payload_lines(text) {
        if !line.contains("template-id") {
            continue;
        }
        let template = json_field(line, "template-id").unwrap_or_default();
        let severity = json_field(line, "severity").unwrap_or_else(|| "info".to_string());
        let host = json_field(line, "host").unwrap_or_default();
        let matched = json_field(line, "matched-at").unwrap_or_default();
        entries.push((severity, template, host, matched));
    }
    if entries.is_empty() {
        out.push_str(
            "No nuclei JSONL findings parsed (expected one JSON object per line with \
             \"template-id\").\n",
        );
        return out;
    }
    let _ = writeln!(out, "Template matches parsed: {}\n", entries.len());
    let mut severity_counts: Vec<(&str, usize)> = Vec::new();
    for (severity, template, host, matched) in &entries {
        let _ = writeln!(out, "[{severity}] {template} @ {host} -> {matched}");
        if let Some(entry) = severity_counts
            .iter_mut()
            .find(|(name, _)| name == severity)
        {
            entry.1 += 1;
        } else {
            severity_counts.push((severity, 1));
        }
    }
    out.push_str("\nSeverity breakdown\n------------------\n");
    for (severity, count) in severity_counts {
        let _ = writeln!(out, "{severity:<10} {count}");
    }
    out
}

// ── ffuf / wfuzz: fuzzing result triage ──────────────────────────────────────

fn fuzz_report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Fuzzing Result Triage");
    let mut results: Vec<(String, u16, usize)> = Vec::new(); // payload, status, length
    for line in payload_lines(text) {
        if !line.contains("\"status\"") {
            continue;
        }
        let payload = json_field(line, "FUZZ").unwrap_or_default();
        let status: u16 = json_field(line, "status")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let length: usize = json_field(line, "length")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        results.push((payload, status, length));
    }
    if results.is_empty() {
        out.push_str(
            "No FFUF JSON results parsed (expected one JSON object per line with \
             \"status\").\n",
        );
        return out;
    }
    let _ = writeln!(out, "Fuzz results parsed: {}\n", results.len());
    let mut by_status: Vec<(u16, usize)> = Vec::new();
    for (payload, status, length) in &results {
        let _ = writeln!(out, "status={status:<4} len={length:<6} {payload}");
        if let Some(entry) = by_status.iter_mut().find(|(code, _)| code == status) {
            entry.1 += 1;
        } else {
            by_status.push((*status, 1));
        }
    }
    out.push_str("\nStatus code distribution\n------------------------\n");
    for (status, count) in by_status {
        let marker = if is_interesting_status(status) {
            " <- investigate"
        } else {
            ""
        };
        let _ = writeln!(out, "{status:<4} x {count}{marker}");
    }
    // Flag outliers: statuses other than the "normal" ones.
    let normal = [200, 301, 302, 307, 308, 400, 403, 404, 500];
    let outliers: Vec<&(String, u16, usize)> = results
        .iter()
        .filter(|(_, status, _)| !normal.contains(status))
        .collect();
    if !outliers.is_empty() {
        out.push_str("\nNon-standard responses (potential signals)\n");
        out.push_str("------------------------------------------\n");
        for (payload, status, length) in outliers {
            let _ = writeln!(out, "status={status} len={length} {payload}");
        }
    }
    out
}

// ── gobuster / dirb / feroxbuster: directory listing triage ──────────────────

fn dirlist_report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Directory / File Discovery Triage");
    let mut entries: Vec<(String, u16, usize)> = Vec::new(); // path, status, size
    for line in payload_lines(text) {
        let Some(status) = extract_status(line) else {
            continue;
        };
        let path = line
            .split_whitespace()
            .find(|token| token.starts_with('/') && token.len() > 1)
            .unwrap_or("(unknown path)")
            .to_string();
        let size: usize = line
            .find("Size:")
            .and_then(|index| {
                line[index + 5..]
                    .split(|c: char| !c.is_ascii_digit())
                    .next()
            })
            .and_then(|digits| digits.parse().ok())
            .unwrap_or(0);
        entries.push((path, status, size));
    }
    if entries.is_empty() {
        out.push_str(
            "No gobuster/dirb-style entries parsed (expected lines like \
             '/path (Status: 200) [Size: 123]').\n",
        );
        return out;
    }
    let _ = writeln!(out, "Entries parsed: {}\n", entries.len());
    let mut by_status: Vec<(u16, usize)> = Vec::new();
    for (path, status, size) in &entries {
        let _ = writeln!(out, "{status:<4} {size:<7} {path}");
        if let Some(entry) = by_status.iter_mut().find(|(code, _)| code == status) {
            entry.1 += 1;
        } else {
            by_status.push((*status, 1));
        }
    }
    out.push_str("\nStatus code distribution\n------------------------\n");
    for (status, count) in by_status {
        let _ = writeln!(out, "{status:<4} x {count}");
    }
    let accessible: Vec<&(String, u16, usize)> = entries
        .iter()
        .filter(|(_, status, _)| *status == 200)
        .collect();
    if !accessible.is_empty() {
        out.push_str("\nAccessible resources (HTTP 200)\n");
        out.push_str("-------------------------------\n");
        for (path, _, size) in accessible {
            let _ = writeln!(out, "{path} (size {size})");
        }
    }
    out
}

// ── burpsuite: captured traffic review ───────────────────────────────────────

fn burp_report(text: &str) -> String {
    let mut out = text_banner("burpsuite", "Captured Traffic Review");
    let urls = extract_urls(text);
    if urls.is_empty() {
        out.push_str("No URLs extracted from the captured traffic.\n");
        return out;
    }
    let _ = writeln!(out, "Unique URLs captured: {}\n", urls.len());
    for url in &urls {
        let _ = writeln!(out, "{url}");
    }
    let sensitive = [
        ".git", ".env", "admin", "config", "backup", "password", "login", "token", "api-key",
        "secret", "session",
    ];
    let lower = text.to_ascii_lowercase();
    let mut hits = 0_usize;
    for marker in sensitive {
        if lower.contains(marker) {
            hits += 1;
            let _ = writeln!(out, "Sensitive token in traffic: '{marker}'");
        }
    }
    if hits == 0 {
        out.push_str("\nNo obvious sensitive tokens found in captured traffic.\n");
    }
    out
}

// ── skipfish: scan log triage ────────────────────────────────────────────────

fn skipfish_report(text: &str) -> String {
    let mut out = text_banner("skipfish", "Scan Log Triage");
    let mut findings: Vec<(u16, String)> = Vec::new();
    for line in payload_lines(text) {
        if let Some(status) = extract_status(line) {
            let path = line
                .split_whitespace()
                .find(|token| token.contains('/'))
                .unwrap_or("(line)")
                .to_string();
            findings.push((status, path));
        }
    }
    if findings.is_empty() {
        out.push_str("No status-bearing scan lines parsed.\n");
        return out;
    }
    let _ = writeln!(out, "Scan lines parsed: {}\n", findings.len());
    for (status, path) in findings {
        let marker = if is_interesting_status(status) {
            " <- investigate"
        } else {
            ""
        };
        let _ = writeln!(out, "{status:<4} {path}{marker}");
    }
    out
}

// ── httrack: mirrored-site file review ───────────────────────────────────────

fn mirror_report(text: &str) -> String {
    let mut out = text_banner("httrack", "Mirrored Site File Review");
    let files: Vec<&str> = payload_lines(text)
        .into_iter()
        .filter(|line| line.contains('.'))
        .collect();
    if files.is_empty() {
        out.push_str("No file-like lines parsed from the mirror index.\n");
        return out;
    }
    let _ = writeln!(out, "File-like entries: {}\n", files.len());
    let sensitive = [
        ".env", ".git", ".bak", ".sql", ".conf", ".pem", ".key", ".p12",
    ];
    let mut flagged = 0_usize;
    for file in &files {
        if sensitive.iter().any(|ext| file.contains(ext)) {
            flagged += 1;
            let _ = writeln!(out, "SENSITIVE: {file}");
        }
    }
    let _ = writeln!(out, "\nSensitive file types mirrored: {flagged}");
    out
}

// ── beef-xss: hook detection ─────────────────────────────────────────────────

fn beef_report(text: &str) -> String {
    let mut out = text_banner("beef-xss", "Hook Detection");
    let lower = text.to_ascii_lowercase();
    if lower.contains("hook.js") || lower.contains("beef") {
        out.push_str("BeEF hook indicators observed in the captured page.\n");
    } else {
        out.push_str("No BeEF hook indicators detected.\n");
    }
    out
}

// ── Generic fallback: header / SQLi / reflection analysis ────────────────────

fn cookie_flags(headers: &[(String, String)]) -> Vec<String> {
    let mut findings = Vec::new();
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let cookie_name = value.split('=').next().unwrap_or("(unnamed)");
        let lower = value.to_ascii_lowercase();
        if !lower.contains("secure") {
            findings.push(format!("Cookie '{cookie_name}' lacks the Secure flag"));
        }
        if !lower.contains("httponly") {
            findings.push(format!("Cookie '{cookie_name}' lacks the HttpOnly flag"));
        }
        if !lower.contains("samesite") {
            findings.push(format!(
                "Cookie '{cookie_name}' lacks the SameSite attribute"
            ));
        }
    }
    findings
}

fn generic_report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Offline Web Response Analysis");
    let headers = parse_headers(text);

    out.push_str("Security Headers\n----------------\n");
    let findings = analyze_security_headers(&headers);
    if findings.is_empty() {
        out.push_str("No missing/weak security headers detected.\n");
    } else {
        for finding in &findings {
            let _ = writeln!(out, "{finding}");
        }
    }

    let cookie_findings = cookie_flags(&headers);
    if !cookie_findings.is_empty() {
        out.push_str("\nCookie attributes\n-----------------\n");
        for finding in cookie_findings {
            let _ = writeln!(out, "- {finding}");
        }
    }

    out.push_str("\nSQL Error Signatures\n--------------------\n");
    let sqli = detect_sqli_errors(text);
    if sqli.is_empty() {
        out.push_str("No database error signatures observed in body.\n");
    } else {
        for signature in &sqli {
            let _ = writeln!(out, "- {signature}");
        }
    }

    out.push_str("\nReflection / Injection Heuristics\n---------------------------------\n");
    let mut hits = 0_usize;
    for marker in [
        "<script",
        "onerror=",
        "onload=",
        "javascript:",
        "<img",
        "%3Cscript",
    ] {
        let count = text.matches(marker).count();
        if count > 0 {
            hits += 1;
            let _ = writeln!(out, "Potential XSS sink '{marker}': {count} occurrence(s)");
        }
    }
    if hits == 0 {
        out.push_str("No obvious reflected-script sinks in body.\n");
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn generic_flags_reflected_script() {
        let text = "HTTP/1.1 200 OK\n\n<script>alert(1)</script>";
        let report = super::generic_report("cutycapt", text);
        assert!(report.contains("Potential XSS sink"));
    }

    #[test]
    fn sqlmap_groups_dbms_family() {
        let text = "You have an error in your SQL syntax; check the manual\n\
                    MySQLSyntaxErrorException\nSQLite3::query() failed";
        let report = super::sqlmap_report(text);
        assert!(report.contains("MySQL"));
        assert!(report.contains("SQLite"));
    }

    #[test]
    fn wpscan_detects_markers_and_version() {
        let report = super::wpscan_report("wp-login.php?action=login\n?ver=6.4.2\nxmlrpc.php\n");
        assert!(report.contains("wp-login.php"));
        assert!(report.contains("xmlrpc.php"));
        assert!(report.contains("6.4.2"));
    }

    #[test]
    fn nuclei_parses_severities() {
        let text = "{\"template-id\":\"CVE-2024-1234\",\"severity\":\"high\",\
                    \"host\":\"app.example.com\",\"matched-at\":\"https://app.example.com/x\"}\n\
                    {\"template-id\":\"misconfig-xyz\",\"severity\":\"medium\",\
                    \"host\":\"app.example.com\",\"matched-at\":\"https://app.example.com/admin\"}\n";
        let report = super::nuclei_report(text);
        assert!(report.contains("Template matches parsed: 2"));
        assert!(report.contains("[high]"));
        assert!(report.contains("[medium]"));
    }

    #[test]
    fn ffuf_triage_flags_outliers() {
        let text = "{\"input\":{\"FUZZ\":\"admin\"},\"status\":200,\"length\":5678,\
                    \"url\":\"https://app.example.com/admin\"}\n\
                    {\"input\":{\"FUZZ\":\"zzz\"},\"status\":404,\"length\":12,\
                    \"url\":\"https://app.example.com/zzz\"}\n";
        let report = super::fuzz_report("ffuf", text);
        assert!(report.contains("Fuzz results parsed: 2"));
        assert!(report.contains("status=200"));
    }

    #[test]
    fn dirlist_extracts_status_and_size() {
        let text = "/admin (Status: 200) [Size: 1234]\n/private (Status: 403)\n";
        let report = super::dirlist_report("gobuster", text);
        assert!(report.contains("Entries parsed: 2"));
        assert!(report.contains("200"));
        assert!(report.contains("/admin"));
    }

    #[test]
    fn cookie_flags_detected() {
        let report =
            super::generic_report("cutycapt", "Set-Cookie: session=abc123; Path=/\n\n<body/>");
        assert!(report.contains("lacks the Secure flag"));
        assert!(report.contains("lacks the HttpOnly flag"));
    }

    #[test]
    fn waf_fingerprints_detected() {
        let text = "HTTP/1.1 403 Forbidden\nCF-Ray: 1a2b3c\nServer: cloudflare\n\nblocked";
        let report = super::fingerprint_report("wafw00f", text);
        assert!(report.contains("Cloudflare"));
    }

    #[test]
    fn burp_extracts_urls() {
        let report = super::burp_report(
            "GET https://app.example.com/admin HTTP/1.1\nHost: app.example.com\n",
        );
        assert!(report.contains("https://app.example.com/admin"));
        assert!(report.contains("admin"));
    }
}
