//! Evasion transform-generation engine.
//!
//! Serves the traffic-manipulation tools (`macchanger`, `yersinia`,
//! `thc-ipv6`). Given a command/payload it reuses the crate's real evasion
//! primitives to emit PowerShell obfuscations and a decoy-traffic plan — the
//! transform planning those tools support, computed entirely offline.

use std::fmt::Write as _;

use super::text_banner;
use crate::offensive::evasion::{generate_decoys, obfuscate_powershell};

pub(super) fn report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Evasion Transform Generator");
    let sample = text.trim();
    if sample.is_empty() {
        out.push_str("Provide a command/payload to transform.\n");
        return out;
    }
    out.push_str("PowerShell Obfuscation\n----------------------\n");
    for result in obfuscate_powershell(sample).iter().take(10) {
        let _ = writeln!(out, "{result}");
    }
    out.push_str("\nDecoy Traffic Plan\n------------------\n");
    // Use the first token that looks like an IP as the real source.
    let real_ip = sample
        .split_whitespace()
        .find(|t| t.split('.').filter(|o| o.parse::<u8>().is_ok()).count() == 4)
        .unwrap_or("10.0.0.1");
    let _ = writeln!(out, "{}", generate_decoys(real_ip, 5));
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn emits_a_decoy_plan() {
        let report = super::report("macchanger", "curl http://192.168.1.5/x");
        assert!(report.contains("Decoy Traffic Plan"));
    }
}
