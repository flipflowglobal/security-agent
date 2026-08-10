//! Offline credential-strength engine.
//!
//! Serves the online login-attack tools (`hydra`, `medusa`, `ncrack`,
//! `crackmapexec`, `netexec`, `evil-winrm`, `smbmap`). Firing real
//! authentication attempts is a live-network action these substitutes never
//! take; instead each supplied candidate is ranked by its resistance to
//! guessing — the decision an operator actually needs before booking an
//! authorized spray window. Captured tool logs (`crackmapexec`/`netexec`
//! successes, `smbmap` share listings) are parsed for the results they
//! already contain.

use std::fmt::Write as _;

use super::{payload_lines, text_banner};
use crate::offensive::credential_attack::analyze_password_strength;

/// Passwords that appear near the top of every breach corpus; flagging them
/// immediately is the whole point of an offline pre-spray review.
const WEAK_PASSWORDS: &[&str] = &[
    "password",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "1234567",
    "123456789",
    "111111",
    "1234567890",
    "123123",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "1234",
    "dragon",
    "1q2w3e4r",
    "master",
    "sunshine",
    "princess",
    "password1",
    "iloveyou",
    "football",
    "654321",
    "shadow",
    "000000",
    "azerty",
    "trustno1",
    "admin123",
    "root",
    "toor",
    "guest",
    "test",
    "default",
    "qwerty123",
    "123321",
    "passw0rd",
    "admin@123",
];

const ADMIN_USERS: &[&str] = &["admin", "root", "administrator", "guest"];

fn is_weak_password(password: &str) -> bool {
    let lower = password.to_ascii_lowercase();
    WEAK_PASSWORDS.contains(&lower.as_str())
}

pub(super) fn report(tool: &str, text: &str) -> String {
    let lines = payload_lines(text);
    if matches!(tool, "crackmapexec" | "netexec") && lines.iter().any(|l| l.starts_with("[+]")) {
        return cme_report(tool, text);
    }
    if tool == "smbmap" && (lines.iter().any(|l| l.starts_with("//")) || text.contains("Disk")) {
        return smbmap_report(text);
    }
    strength_report(tool, text)
}

// ── Hydra / medusa / ncrack / evil-winrm: candidate strength ranking ─────────

fn strength_report(tool: &str, text: &str) -> String {
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
    let mut weak = 0_usize;
    let mut default_pairs = 0_usize;
    for (index, cred) in creds.iter().take(200).enumerate() {
        // Accept `user:pass` pairs as well as bare passwords.
        let password = cred.rsplit(':').next().unwrap_or(cred);
        let user = cred
            .rsplit(':')
            .nth(1)
            .map(str::trim)
            .filter(|u| !u.is_empty());
        let strength = analyze_password_strength(password);
        let flags: Vec<&str> = {
            let mut f = Vec::new();
            if is_weak_password(password) {
                f.push("common password");
            }
            if let Some(user) = user {
                if password.eq_ignore_ascii_case(user) {
                    f.push("password == username");
                }
                if ADMIN_USERS.contains(&user.to_ascii_lowercase().as_str())
                    && is_weak_password(password)
                {
                    f.push("default admin pair");
                }
            }
            f
        };
        if flags
            .iter()
            .any(|f| matches!(*f, "common password" | "password == username"))
        {
            weak += 1;
        }
        if flags.contains(&"default admin pair") {
            default_pairs += 1;
        }
        let _ = write!(out, "[{}] {strength}", index + 1);
        if !flags.is_empty() {
            let _ = write!(out, "  ! {}", flags.join(", "));
        }
        out.push('\n');
    }
    let _ = writeln!(
        out,
        "\nSummary: {weak} weak candidate(s), {default_pairs} default admin pair(s)."
    );
    out
}

// ── crackmapexec / netexec: success-log triage ───────────────────────────────

fn cme_report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Captured Auth Log Review");
    let mut validated = 0_usize;
    let mut pwned = 0_usize;
    for line in payload_lines(text) {
        if !line.starts_with("[+]") {
            continue;
        }
        let token = line
            .split_whitespace()
            .find(|token| {
                let Some((left, _)) = token.split_once(':') else {
                    return false;
                };
                !left.contains('.') && !left.is_empty()
            })
            .unwrap_or("user:pass");
        let host = line
            .split_whitespace()
            .find(|token| token.contains('.') && !token.contains(':'))
            .unwrap_or("(host)");
        validated += 1;
        let _ = writeln!(out, "VALIDATED {host} {token}");
        if line.contains("pwn3d") || line.to_ascii_lowercase().contains("(pwn3d") {
            pwned += 1;
            let _ = writeln!(out, "  -> host is ADMINISTRATIVELY owned (Pwn3d!)");
        }
    }
    if validated == 0 {
        out.push_str("No `[+]` success lines parsed.\n");
        return out;
    }
    let _ = writeln!(
        out,
        "\nValidated logons in log: {validated} | owned hosts: {pwned}"
    );
    out
}

// ── smbmap: share-permission triage ──────────────────────────────────────────

fn smbmap_report(text: &str) -> String {
    let mut out = text_banner("smbmap", "Share Permissions Review");
    let mut accessible = 0_usize;
    let mut null_session = 0_usize;
    for line in payload_lines(text) {
        let lower = line.to_ascii_lowercase();
        if lower.contains("anonymous") || lower.contains("guest") || lower.contains("null session")
        {
            null_session += 1;
            let _ = writeln!(out, "NULL/GUEST session indicator: {line}");
        }
        if line.starts_with("//") {
            let has_read = lower.contains("read");
            let has_write = lower.contains("write");
            if has_read || has_write {
                accessible += 1;
                let _ = writeln!(
                    out,
                    "ACCESSIBLE {} ({})",
                    line,
                    if has_write { "READ, WRITE" } else { "READ" }
                );
            }
            continue;
        }
        // smbmap columnar output: `share  PERMISSIONS`.
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 2 && (lower.contains("read") || lower.contains("write")) {
            accessible += 1;
            let _ = writeln!(out, "ACCESSIBLE {} -> {}", cols[0], cols[1]);
        }
    }
    if accessible == 0 && null_session == 0 {
        out.push_str("No accessible shares or null-session indicators parsed.\n");
    }
    let _ = writeln!(
        out,
        "\nAccessible shares: {accessible} | null-session indicators: {null_session}"
    );
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn assesses_pairs_and_bare_passwords() {
        let report = super::report("hydra", "admin:password\nhunter2\n");
        assert!(report.contains("Passwords assessed: 2"));
        assert!(report.contains("common password"));
    }

    #[test]
    fn flags_default_admin_pair() {
        let report = super::report("medusa", "admin:admin\n");
        assert!(report.contains("default admin pair"));
    }

    #[test]
    fn cme_log_extracts_validations() {
        let report = super::report(
            "crackmapexec",
            "[+] 192.168.1.10 admin:Winter2026 (Pwn3d!)\n[+] 192.168.1.11 svc:x9k2m4\n",
        );
        assert!(report.contains("VALIDATED"));
        assert!(report.contains("owned hosts: 1"));
    }

    #[test]
    fn smbmap_lists_accessible_shares() {
        let report = super::report(
            "smbmap",
            "//192.168.1.10/public  READ\n//192.168.1.10/admin   NO ACCESS\n",
        );
        assert!(report.contains("ACCESSIBLE //192.168.1.10/public"));
    }
}
