//! Wireless-audit engine: survey audit, WPA handshake, and WPS PIN analysis.
//!
//! Serves the 802.11 tools. `aircrack-ng`/`wifite`/`pyrit` map to
//! [`handshake_report`] (EAPOL frame analysis plus cracked-handshake log
//! triage), `reaver` to [`wps_report`] (WPS PIN structure), and the
//! survey/RF tools (`kismet`, `giskismet`, `bettercap`, `mfoc`, …) to
//! [`audit_report`] with per-tool export parsers. Every path reuses the
//! crate's real wireless analyzers and never touches a radio.

use std::fmt::Write as _;
use std::path::Path;

use super::{ArsenalError, banner, decode_hex, payload_lines, read_bytes, read_text, text_banner};
use crate::offensive::wireless::{analyze_eapol_frames, analyze_wps_pin, audit_wireless_security};

pub(super) fn audit_report(tool: &str, text: &str) -> String {
    match tool {
        "kismet" | "giskismet" => kismet_report(tool, text),
        _ => generic_audit_report(tool, text),
    }
}

pub(super) fn handshake_report(tool: &str, input: &Path) -> Result<String, ArsenalError> {
    let text = read_text(input)?;
    let lower = text.to_ascii_lowercase();
    if tool == "aircrack-ng" && lower.contains("key found") {
        return Ok(aircrack_crack_report(tool, input, &text));
    }
    if tool == "wifite" && (lower.contains("handshake captured") || lower.contains("pmkid")) {
        return Ok(wifite_capture_report(&text));
    }
    eapol_report(tool, input, &text)
}

pub(super) fn wps_report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "WPS PIN Analysis");
    let mut pins = 0_usize;
    for line in payload_lines(text) {
        // Accept a bare PIN, or a reaver progress line such as
        // `[+] WPS PIN: '12345678'`.
        let candidate = line
            .split(|c: char| !c.is_ascii_digit())
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .find(|part| part.len() == 8);
        let Some(pin) = candidate else {
            continue;
        };
        pins += 1;
        let info = analyze_wps_pin(&pin);
        let _ = writeln!(out, "PIN {pin}\n{info}\n");
    }
    if pins == 0 {
        out.push_str(
            "No 8-digit WPS PIN found (provide one PIN per line, optionally as a \
             reaver `[+] WPS PIN:` log).\n",
        );
    }
    out
}

// ── Survey export parsers ────────────────────────────────────────────────────

/// `essid,security,encryption` lines or freeform `bssid essid chan security`.
fn generic_audit_report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Wireless Security Audit");
    if text.contains("BSSID") && text.to_ascii_lowercase().contains("first time seen") {
        return airodump_report(tool, text);
    }
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

struct AirodumpNetwork {
    bssid: String,
    channel: String,
    privacy: String,
    cipher: String,
    auth: String,
    power: String,
    beacons: String,
    essid: String,
}

struct AirodumpStation {
    mac: String,
    power: String,
    packets: String,
    bssid: String,
    probed: String,
}

fn parse_airodump(text: &str) -> (Vec<AirodumpNetwork>, Vec<AirodumpStation>) {
    let mut networks = Vec::new();
    let mut stations = Vec::new();
    let mut in_stations = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.to_ascii_lowercase().contains("station mac") {
            in_stations = true;
            continue;
        }
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        if fields.is_empty() || !fields[0].contains(':') {
            continue;
        }
        if in_stations {
            stations.push(AirodumpStation {
                mac: fields[0].to_string(),
                power: fields.get(3).copied().unwrap_or("").to_string(),
                packets: fields.get(4).copied().unwrap_or("").to_string(),
                bssid: fields.get(5).copied().unwrap_or("").to_string(),
                probed: fields.get(6).copied().unwrap_or("").to_string(),
            });
        } else {
            networks.push(AirodumpNetwork {
                bssid: fields[0].to_string(),
                channel: fields.get(3).copied().unwrap_or("").to_string(),
                privacy: fields.get(5).copied().unwrap_or("").to_string(),
                cipher: fields.get(6).copied().unwrap_or("").to_string(),
                auth: fields.get(7).copied().unwrap_or("").to_string(),
                power: fields.get(8).copied().unwrap_or("").to_string(),
                beacons: fields.get(9).copied().unwrap_or("").to_string(),
                essid: fields.get(13).copied().unwrap_or("").to_string(),
            });
        }
    }
    (networks, stations)
}

fn airodump_report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Airodump Survey Analysis");
    let (networks, stations) = parse_airodump(text);
    if networks.is_empty() {
        out.push_str("No airodump network rows parsed (expected airodump-ng CSV export).\n");
        return out;
    }
    let _ = writeln!(
        out,
        "Networks observed: {} | clients: {}\n",
        networks.len(),
        stations.len()
    );
    for network in &networks {
        let audit = audit_wireless_security(&network.essid, &network.privacy, &network.cipher);
        let _ = writeln!(out, "{audit}");
        let _ = writeln!(
            out,
            "  channel={} power={}dBm beacons={} auth={} cipher={} bssid={}\n",
            network.channel,
            network.power,
            network.beacons,
            network.auth,
            network.cipher,
            network.bssid
        );
    }
    if !stations.is_empty() {
        out.push_str("Associated clients\n------------------\n");
        for station in &stations {
            let _ = writeln!(
                out,
                "  {} power={}dBm packets={} -> bssid={} probed=[{}]",
                station.mac, station.power, station.packets, station.bssid, station.probed
            );
        }
    }
    out
}

struct KismetNetwork {
    name: String,
    crypt: String,
    bssid: String,
    channel: String,
    cloaked: String,
    wps: String,
}

fn parse_kismet(text: &str) -> Vec<KismetNetwork> {
    text.lines()
        .filter_map(|raw| {
            let line = raw.trim();
            if !line.starts_with("Network;") {
                return None;
            }
            let fields: Vec<&str> = line.split(';').map(str::trim).collect();
            if fields.len() < 7 {
                return None;
            }
            Some(KismetNetwork {
                name: fields.get(2).copied().unwrap_or("").to_string(),
                crypt: fields.get(3).copied().unwrap_or("").to_string(),
                bssid: fields.get(4).copied().unwrap_or("").to_string(),
                channel: fields.get(6).copied().unwrap_or("").to_string(),
                cloaked: fields.get(7).copied().unwrap_or("").to_string(),
                wps: fields.get(9).copied().unwrap_or("").to_string(),
            })
        })
        .collect()
}

fn kismet_report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Kismet Survey Analysis");
    let networks = parse_kismet(text);
    if networks.is_empty() {
        out.push_str(
            "No kismet network rows parsed (expected kismet CSV export with \
             `Network;Type;Name;Crypt;…` header).\n",
        );
        return out;
    }
    let _ = writeln!(out, "Networks observed: {}\n", networks.len());
    for network in &networks {
        let audit = audit_wireless_security(&network.name, &network.crypt, "N/A");
        let _ = writeln!(out, "{audit}");
        let _ = writeln!(
            out,
            "  channel={} cloaked={} wps={} bssid={}\n",
            network.channel, network.cloaked, network.wps, network.bssid
        );
    }
    out
}

// ── Handshake / capture log triage ───────────────────────────────────────────

fn eapol_report(tool: &str, input: &Path, text: &str) -> Result<String, ArsenalError> {
    let mut out = banner(tool, &format!("{tool} — WPA Handshake Analysis"), input);
    let mut frames: Vec<Vec<u8>> = Vec::new();
    for line in payload_lines(text) {
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

/// aircrack-ng log that already contains `KEY FOUND! [ passphrase ]`.
fn aircrack_crack_report(tool: &str, input: &Path, text: &str) -> String {
    let mut out = banner(tool, "aircrack-ng — Cracked WPA Key", input);
    let mut found = 0_usize;
    for line in payload_lines(text) {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("key found") && !lower.contains("master key") {
            continue;
        }
        let passphrase = line
            .split('[')
            .nth(1)
            .and_then(|rest| rest.split(']').next())
            .map_or("(unparsed)", str::trim);
        let _ = writeln!(out, "KEY FOUND: {passphrase}");
        found += 1;
    }
    if found == 0 {
        let _ = writeln!(out, "Key material detected but no passphrase field parsed.");
    }
    out
}

/// wifite capture log noting a captured handshake or PMKID.
fn wifite_capture_report(text: &str) -> String {
    let mut out = text_banner("wifite", "Capture Progress Review");
    let mut hits = 0_usize;
    for line in payload_lines(text) {
        let lower = line.to_ascii_lowercase();
        if lower.contains("handshake captured")
            || lower.contains("pmkid")
            || lower.contains("captured handshake")
        {
            hits += 1;
            let _ = writeln!(out, "{line}");
        }
    }
    if hits == 0 {
        out.push_str("No handshake/PMKID capture markers found.\n");
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn audits_csv_lines_via_generic_tool() {
        let report = super::generic_audit_report("bettercap", "HomeWiFi,Open,None\n");
        assert!(report.contains("HomeWiFi"));
    }

    #[test]
    fn airodump_csv_parses_networks_and_clients() {
        let text = "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, \
                    Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n\
                    00:11:22:33:44:55, 2026-08-10 10:00:00, 2026-08-10 10:05:00, 6, 54, WPA2, \
                    CCMP, PSK, -40, 120, 0, 0.0.0.0, 8, HomeWiFi, \n\
                    Station MAC, First time seen, Last time seen, Power, # packets, BSSID, \
                    Probed ESSIDs\n\
                    aa:bb:cc:dd:ee:ff, 2026-08-10 10:01:00, 2026-08-10 10:04:00, -55, 40, \
                    00:11:22:33:44:55, HomeWiFi\n";
        let report = super::airodump_report("bettercap", text);
        assert!(report.contains("HomeWiFi"));
        assert!(report.contains("clients: 1"));
    }

    #[test]
    fn kismet_csv_parses_networks() {
        let text = "Network;Type;Name;Crypt;BSSID;Info;Channel;Cloaked;Weak;WPS\n\
                    Network;probe;OfficeWifi;WPA2;00:11:22:33:44:55;Info;6;N;N;Y\n";
        let report = super::kismet_report("kismet", text);
        assert!(report.contains("OfficeWifi"));
        assert!(report.contains("wps=Y"));
    }

    #[test]
    fn wps_analyzes_pins_from_reaver_log() {
        let report = super::wps_report("reaver", "[+] WPS PIN: '12345670'\n");
        assert!(report.contains("PIN 12345670"));
    }

    #[test]
    fn aircrack_crack_parses_passphrase() {
        let report = super::aircrack_crack_report(
            "aircrack-ng",
            std::path::Path::new("test.cap"),
            "KEY FOUND! [ password1 ]",
        );
        assert!(report.contains("KEY FOUND: password1"));
    }
}
