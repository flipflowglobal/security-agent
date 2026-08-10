//! Offline hash-identification engine.
//!
//! Serves the password-recovery tools (`hashcat`, `john`, `ophcrack`,
//! `rcrack`). Live brute force needs a wordlist and compute the offline
//! substitute deliberately withholds; instead every candidate hash is
//! classified by algorithm/family — with hashcat mode and John format where
//! known — so an operator knows *what* they are up against before taking the
//! workload to an authorized cracking rig. `ophcrack`/`rcrack` focus on the
//! LM/NTLM hashes their rainbow tables can attack.

use std::fmt::Write as _;

use super::{payload_lines, text_banner};
use crate::offensive::credential_attack::identify_hash;

pub(super) fn report(tool: &str, text: &str) -> String {
    if matches!(tool, "ophcrack" | "rcrack") {
        return rainbow_report(tool, text);
    }
    hashcat_report(tool, text)
}

/// Attack guidance that follows from the algorithm's cost profile.
fn attack_guidance(hash_type: &str) -> &'static str {
    let lower = hash_type.to_ascii_lowercase();
    if lower.contains("bcrypt") || lower.contains("scrypt") || lower.contains("argon") {
        return "slow hash: targeted wordlist only, expect low throughput";
    }
    if lower.contains("kerberos") || lower.contains("wpa") || lower.contains("netntlm") {
        return "specialized mode: extractor/ritual feeds this type directly";
    }
    if lower.contains("md5")
        || lower.contains("ntlm")
        || lower.contains("sha-1")
        || lower.contains("sha1")
        || lower.contains("lm")
        || lower.contains("mysql")
    {
        return "fast hash: wordlist + rule mutation, then mask attack";
    }
    "generic: wordlist + rules first, mask attack second"
}

fn hashcat_report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Offline Hash Identification");
    let hashes = payload_lines(text);
    if hashes.is_empty() {
        out.push_str("No candidate hashes found in input (one hash per line).\n");
        return out;
    }
    let _ = writeln!(out, "Candidate hashes analyzed: {}\n", hashes.len());
    let mut families: Vec<(String, usize)> = Vec::new();
    for (index, hash) in hashes.iter().take(500).enumerate() {
        let analysis = identify_hash(hash);
        let _ = write!(out, "[{}] {}", index + 1, analysis.hash_type);
        if let Some(mode) = analysis.hashcat_mode {
            let _ = write!(out, "  [hashcat -m {mode}]");
        }
        let _ = write!(out, "  (john: {})", analysis.john_format);
        out.push('\n');
        if let Some(entry) = families
            .iter_mut()
            .find(|(name, _)| *name == analysis.hash_type)
        {
            entry.1 += 1;
        } else {
            families.push((analysis.hash_type, 1));
        }
    }
    out.push_str("\nFamily breakdown\n----------------\n");
    for (family, count) in families {
        let _ = writeln!(out, "{family:<28} {count}  -> {}", attack_guidance(&family));
    }
    out
}

/// ophcrack / rcrack: how many candidates are actually rainbow-table
/// friendly (LM/NTLM, 32-hex, uppercase LM hashes)?
fn rainbow_friendly(hash: &str) -> bool {
    hash.len() == 32
        && hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
}

fn rainbow_report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Rainbow Table Applicability");
    let hashes = payload_lines(text);
    if hashes.is_empty() {
        out.push_str("No candidate hashes found in input (one hash per line).\n");
        return out;
    }
    let mut lm_ntlm = 0_usize;
    for (index, hash) in hashes.iter().take(500).enumerate() {
        let analysis = identify_hash(hash);
        let rainbow_ready = rainbow_friendly(hash);
        let _ = writeln!(
            out,
            "[{}] {}{}",
            index + 1,
            analysis.hash_type,
            if rainbow_ready {
                "  -> rainbow-table friendly"
            } else {
                ""
            }
        );
        if rainbow_ready {
            lm_ntlm += 1;
        }
    }
    let _ = writeln!(
        out,
        "\nRainbow-table friendly candidates: {lm_ntlm} (LM/NTLM only — use tables for \
         LANMAN challenges; NTLMv2 requires different tables)"
    );
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn identifies_lines() {
        let report = super::hashcat_report("hashcat", "5f4dcc3b5aa765d61d8327deb882cf99\n");
        assert!(report.contains("Candidate hashes analyzed: 1"));
        assert!(report.contains("MD5"));
    }

    #[test]
    fn groups_families_and_guidance() {
        let report = super::hashcat_report(
            "john",
            "5f4dcc3b5aa765d61d8327deb882cf99\n$2b$12$abcdefghijklmnopqrstuu\n",
        );
        assert!(report.contains("MD5"));
        assert!(report.contains("bcrypt"));
        assert!(report.contains("fast hash"));
        assert!(report.contains("slow hash"));
    }

    #[test]
    fn rainbow_marks_lm_ntlm_only() {
        let report = super::rainbow_report(
            "ophcrack",
            "AAD3B435B51404EEAAD3B435B51404EE\n5f4dcc3b5aa765d61d8327deb882cf99\n",
        );
        assert!(report.contains("Rainbow-table friendly candidates: 1"));
    }
}
