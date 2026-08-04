//! Native offline "arsenal" substitutes for every cataloged tool.
//!
//! Each cataloged tool that has no bespoke forensic substitute in
//! [`crate::builtin_tools`] is handled here. Every entry performs **real,
//! offline analysis** of the operator-supplied local input file — no network
//! access, no external binary is ever spawned. Where a genuine analyzer
//! already exists in [`crate::offensive`] we reuse it.
//!
//! # Layout
//!
//! The executable substitutes are grouped by the *kind of analysis* they
//! perform — one module per engine, mirroring the [`crate::offensive`]
//! package. A tool is routed to an engine by [`dispatch_category`]; the
//! per-tool operator documentation lives alongside each tool's skill in
//! `.github/skills/<tool>/` (`SKILL.md` + `ARSENAL.md`).

mod capture;
mod credential;
mod evasion;
mod forensic;
mod hash_cracker;
mod mobile;
mod payload;
mod privesc;
mod scan_inventory;
mod source_scan;
mod web;
mod wireless;
mod wordlist;

use std::fmt;
use std::fs;
use std::path::Path;

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

/// The functional category a tool maps to. Each variant is served by the
/// engine submodule of the same theme.
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
    Mobile,
    Forensic,
}

fn dispatch_category(name: &str) -> Option<Category> {
    use Category::{
        Credential, Evasion, Forensic, HashCracker, Mobile, Payload, Privesc, ScanInventory,
        Sniffer, SourceScan, Web, WirelessAudit, WirelessHandshake, Wordlist, WpsAttack,
    };
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
        | "frida" | "objection" | "qark" | "mobsf" | "trueseeing" | "mariana-trench" => Mobile,

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
        Category::HashCracker => Ok(hash_cracker::report(name, &read_text(input)?)),
        Category::Credential => Ok(credential::report(name, &read_text(input)?)),
        Category::Wordlist => Ok(wordlist::report(name, &read_text(input)?)),
        Category::Web => Ok(web::report(name, &read_text(input)?)),
        Category::WirelessAudit => Ok(wireless::audit_report(name, &read_text(input)?)),
        Category::WirelessHandshake => wireless::handshake_report(name, input),
        Category::WpsAttack => Ok(wireless::wps_report(name, &read_text(input)?)),
        Category::ScanInventory => Ok(scan_inventory::report(name, &read_text(input)?)),
        Category::Payload => Ok(payload::report(name, &read_text(input)?)),
        Category::Privesc => Ok(privesc::report(name, &read_text(input)?)),
        Category::SourceScan => Ok(source_scan::report(name, &read_text(input)?)),
        Category::Evasion => Ok(evasion::report(name, &read_text(input)?)),
        Category::Sniffer => capture::report(name, input),
        Category::Mobile => mobile::report(name, input),
        Category::Forensic => forensic::report(name, input),
    }
}

// ── Shared input helpers (used by every engine submodule) ────────────────────

pub(super) fn read_text(input: &Path) -> Result<String, ArsenalError> {
    let bytes = read_bytes(input)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub(super) fn read_bytes(input: &Path) -> Result<Vec<u8>, ArsenalError> {
    let metadata = fs::symlink_metadata(input)
        .map_err(|source| ArsenalError(format!("{}: {source}", input.display())))?;
    if metadata.file_type().is_symlink() {
        return Err(ArsenalError(
            "input must not be a symbolic link".to_string(),
        ));
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
pub(super) fn banner(tool: &str, title: &str, input: &Path) -> String {
    format!(
        "{title}\n{underline}\nTool           : {tool} (built-in substitute)\nNetwork used   : No\nInput          : {path}\n\n",
        underline = "=".repeat(title.len()),
        path = input.display(),
    )
}

/// A report banner for the text-input engines (no file-path line). The title
/// is rendered as `"<tool> — <title>"` with a matching underline.
pub(super) fn text_banner(tool: &str, title: &str) -> String {
    let heading = format!("{tool} — {title}");
    let underline = "=".repeat(heading.chars().count());
    format!(
        "{heading}\n{underline}\nTool           : {tool} (built-in substitute)\nNetwork used   : No\n\n",
    )
}

/// Non-empty, comment-stripped lines of an input, trimmed.
pub(super) fn payload_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

pub(super) fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if cleaned.is_empty()
        || cleaned.len() % 2 != 0
        || !cleaned.chars().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    let raw = cleaned.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        let hi = (raw[index] as char).to_digit(16)?;
        let lo = (raw[index + 1] as char).to_digit(16)?;
        bytes.push(u8::try_from((hi << 4) | lo).unwrap_or(0));
        index += 2;
    }
    Some(bytes)
}

pub(super) fn detect_file_type(bytes: &[u8]) -> &'static str {
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

pub(super) fn extract_strings(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();
    for &byte in bytes {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte as char);
        } else if current.len() >= min_len {
            strings.push(std::mem::take(&mut current));
        } else {
            current.clear();
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
            assert!(
                handles(&name),
                "no arsenal handler for cataloged tool '{name}'"
            );
        }
    }

    #[test]
    fn hex_decoder_roundtrips() {
        assert_eq!(
            decode_hex("de:ad:be:ef"),
            Some(vec![0xDE, 0xAD, 0xBE, 0xEF])
        );
        assert_eq!(decode_hex("xyz"), None);
    }

    #[test]
    fn unknown_tool_has_no_handler() {
        assert!(!handles("definitely-not-a-tool"));
        assert!(dispatch_category("definitely-not-a-tool").is_none());
    }
}
