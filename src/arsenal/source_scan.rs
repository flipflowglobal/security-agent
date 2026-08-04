//! Static source pattern-scan engine.
//!
//! Serves `semgrep`. Scans supplied source text line-by-line for a curated
//! set of insecure-code and hardcoded-secret patterns, reporting each with a
//! severity — a real, deterministic offline SAST pass (no rules download, no
//! telemetry).

use std::fmt::Write as _;

use super::text_banner;

pub(super) fn report(tool: &str, text: &str) -> String {
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
    let mut out = text_banner(tool, "Static Source Pattern Scan");
    let mut total = 0_usize;
    for (number, line) in text.lines().enumerate().take(200_000) {
        let lower = line.to_lowercase();
        for (needle, severity, description) in RULES {
            if lower.contains(&needle.to_lowercase()) {
                total += 1;
                let _ = writeln!(
                    out,
                    "[{severity}] line {}: {description} ({needle})",
                    number + 1
                );
                if total >= 1000 {
                    out.push_str("... (truncated at 1000 findings)\n");
                    return out;
                }
            }
        }
    }
    let _ = writeln!(out, "\nTotal findings: {total}");
    if total == 0 {
        out.push_str("No matching insecure patterns found.\n");
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn flags_eval() {
        let report = super::report("semgrep", "x = eval(user_input)\n");
        assert!(report.contains("[HIGH]"));
        assert!(report.contains("dynamic code evaluation"));
    }
}
