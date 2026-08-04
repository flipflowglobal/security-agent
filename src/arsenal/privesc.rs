//! Host-hardening / privilege-escalation review engine.
//!
//! Serves `chkrootkit`, `lynis`, and `termineter`. Given the sensitive local
//! system files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`,
//! `authorized_keys`, hosts/trust files) concatenated into the input, it
//! reuses the crate's post-exploitation analyzers to surface hardening
//! indicators — exactly the local review those auditors perform.

use std::fmt::Write as _;

use super::text_banner;
use crate::offensive::post_exploit::{
    analyze_authorized_keys, analyze_hosts_file, analyze_passwd_file, analyze_shadow_file,
    analyze_sudoers,
};

pub(super) fn report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Host Hardening & Privilege-Escalation Review");
    let mut total = 0_usize;
    total += push_section(
        &mut out,
        "Password Database (/etc/passwd)",
        analyze_passwd_file(text)
            .iter()
            .map(ToString::to_string)
            .collect(),
    );
    total += push_section(
        &mut out,
        "Shadow Database (/etc/shadow)",
        analyze_shadow_file(text)
            .iter()
            .map(ToString::to_string)
            .collect(),
    );
    total += push_section(
        &mut out,
        "Sudo Policy (/etc/sudoers)",
        analyze_sudoers(text)
            .iter()
            .map(ToString::to_string)
            .collect(),
    );
    total += push_section(
        &mut out,
        "Authorized Keys",
        analyze_authorized_keys(text)
            .iter()
            .map(ToString::to_string)
            .collect(),
    );
    total += push_section(
        &mut out,
        "Hosts / Trust File",
        analyze_hosts_file(text)
            .iter()
            .map(ToString::to_string)
            .collect(),
    );
    let _ = writeln!(out, "Total indicators: {total}");
    out
}

/// Appends a titled section and returns the number of indicator lines.
fn push_section(out: &mut String, title: &str, lines: Vec<String>) -> usize {
    let count = lines.len();
    let _ = writeln!(out, "{title}\n{}", "-".repeat(title.len()));
    if lines.is_empty() {
        out.push_str("No indicators.\n\n");
    } else {
        for line in lines {
            let _ = writeln!(out, "{line}");
        }
        out.push('\n');
    }
    count
}

#[cfg(test)]
mod tests {
    #[test]
    fn renders_all_sections() {
        let report = super::report("lynis", "root:x:0:0:root:/root:/bin/bash\n");
        assert!(report.contains("Total indicators:"));
    }
}
