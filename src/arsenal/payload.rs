//! Payload analysis & evasion-advisory engine.
//!
//! Serves the payload/exploit tools (`msfconsole`, `msfpc`, `setoolkit`,
//! `searchsploit`). Rather than generating a live payload, the substitute
//! statically analyzes a supplied command/payload string and recommends the
//! evasion transforms the crate's real analyzer would apply.

use std::fmt::Write as _;

use super::text_banner;
use crate::offensive::payload_gen::{analyze_payload, suggest_evasion};

pub(super) fn report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Payload Analysis & Evasion Advisory");
    let sample = text.trim();
    if sample.is_empty() {
        out.push_str("Provide a payload/command string to analyze.\n");
        return out;
    }
    let analysis = analyze_payload(sample);
    let _ = write!(
        out,
        "{analysis}\n\nEvasion Suggestions\n-------------------\n"
    );
    let suggestions = suggest_evasion(&analysis);
    if suggestions.is_empty() {
        out.push_str("No additional evasion transforms recommended.\n");
    } else {
        for suggestion in &suggestions {
            let _ = writeln!(out, "{suggestion}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn analyzes_a_sample() {
        let report = super::report("msfconsole", "powershell -enc AAAA");
        assert!(report.contains("Evasion Suggestions"));
    }
}
