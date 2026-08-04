//! Offline web-response analysis engine.
//!
//! Serves the web application testing tools (`sqlmap`, `nikto`, `wpscan`,
//! `nuclei`, `ffuf`, `gobuster`, `burpsuite`, …). Given a captured HTTP
//! response (headers + body) it reuses the crate's real analyzers to grade
//! the security headers, spot database error signatures, and flag reflected
//! script sinks — the same triage those scanners perform once a response is
//! in hand, without sending a single live request.

use std::fmt::Write as _;

use super::text_banner;
use crate::offensive::web_exploit::{analyze_security_headers, detect_sqli_errors};

pub(super) fn report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Offline Web Response Analysis");

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
            let _ = writeln!(out, "{finding}");
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

    // Heuristic reflected-input scan for XSS-prone contexts.
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
    fn flags_reflected_script() {
        let report = super::report("nikto", "HTTP/1.1 200 OK\n\n<script>alert(1)</script>");
        assert!(report.contains("Potential XSS sink"));
    }
}
