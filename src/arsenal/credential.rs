//! Offline credential-strength engine.
//!
//! Serves the online login-attack tools (`hydra`, `medusa`, `ncrack`,
//! `crackmapexec`, `netexec`, `evil-winrm`, `smbmap`). Firing real
//! authentication attempts is a live-network action these substitutes never
//! take; instead each supplied candidate is ranked by its resistance to
//! guessing, which is the decision an operator actually needs before booking
//! an authorized spray window.

use std::fmt::Write as _;

use super::{payload_lines, text_banner};
use crate::offensive::credential_attack::analyze_password_strength;

pub(super) fn report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Offline Credential Strength Assessment");
    let creds = payload_lines(text);
    if creds.is_empty() {
        out.push_str("No candidate passwords found (one credential per line).\n");
        return out;
    }
    let _ = writeln!(
        out,
        "Passwords assessed: {} (live brute force is disabled offline; \
         this ranks candidates by resistance)\n",
        creds.len()
    );
    for (index, cred) in creds.iter().take(200).enumerate() {
        // Accept `user:pass` pairs as well as bare passwords.
        let password = cred.rsplit(':').next().unwrap_or(cred);
        let strength = analyze_password_strength(password);
        let _ = writeln!(out, "[{}] {strength}", index + 1);
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn assesses_pairs_and_bare_passwords() {
        let report = super::report("hydra", "admin:password\nhunter2\n");
        assert!(report.contains("Passwords assessed: 2"));
    }
}
