//! Wireless-audit engine: survey audit, WPA handshake, and WPS PIN analysis.
//!
//! Serves the 802.11 tools. `aircrack-ng`/`wifite`/`pyrit` map to
//! [`handshake_report`] (EAPOL frame analysis), `reaver` to [`wps_report`]
//! (WPS PIN structure), and the survey/RF tools (`kismet`, `bettercap`,
//! `mfoc`, …) to [`audit_report`]. Every path reuses the crate's real
//! wireless analyzers and never touches a radio.

use std::fmt::Write as _;
use std::path::Path;

use super::{ArsenalError, banner, decode_hex, payload_lines, read_bytes, read_text, text_banner};
use crate::offensive::wireless::{analyze_eapol_frames, analyze_wps_pin, audit_wireless_security};

pub(super) fn audit_report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Wireless Security Audit");
    // Expect `essid,security,encryption` per line (survey export).
    let mut networks = 0_usize;
    for line in payload_lines(text) {
        let fields: Vec<&str> = line.split([',', '\t']).map(str::trim).collect();
        let essid = fields.first().copied().unwrap_or("<unknown>");
        let security = fields.get(1).copied().unwrap_or("Open");
        let encryption = fields.get(2).copied().unwrap_or("None");
        let audit = audit_wireless_security(essid, security, encryption);
        let _ = writeln!(out, "{audit}");
        networks += 1;
        if networks >= 100 {
            break;
        }
    }
    if networks == 0 {
        out.push_str(
            "Provide one network per line as: ESSID,security(WPA2/WPA3/WEP/Open),encryption(CCMP/TKIP/None)\n",
        );
    }
    out
}

pub(super) fn handshake_report(tool: &str, input: &Path) -> Result<String, ArsenalError> {
    let text = read_text(input)?;
    let mut out = banner(tool, &format!("{tool} — WPA Handshake Analysis"), input);
    // Parse hex-encoded EAPOL frames, one per line; fall back to raw bytes.
    let mut frames: Vec<Vec<u8>> = Vec::new();
    for line in payload_lines(&text) {
        if let Some(frame) = decode_hex(line) {
            frames.push(frame);
        }
    }
    if frames.is_empty() {
        frames.push(read_bytes(input)?);
    }
    let info = analyze_eapol_frames(&frames);
    let _ = writeln!(out, "Frames parsed  : {}\n\n{info}", frames.len());
    Ok(out)
}

pub(super) fn wps_report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "WPS PIN Analysis");
    if let Some(pin) = payload_lines(text).first() {
        let info = analyze_wps_pin(pin);
        let _ = writeln!(out, "{info}");
    } else {
        out.push_str("Provide an 8-digit WPS PIN on the first line.\n");
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn audits_open_network() {
        let report = super::audit_report("kismet", "HomeWiFi,Open,None\n");
        assert!(report.contains("HomeWiFi"));
    }
}
