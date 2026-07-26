//! Wireless security analysis — WPA handshake analysis, WPS pin detection,
//! deauth frame detection, and wireless security auditing.
//!
//! Pure-Rust implementations for wireless security assessments.

use std::fmt;

// ─── WPA Handshake Analysis ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WpaHandshakeInfo {
    pub bssid: String,
    pub essid: String,
    pub handshake_version: String,
    pub has_pmkid: bool,
    pub pmkid: Option<String>,
    pub anonce: Option<String>,
    pub snonce: Option<String>,
    pub mic: Option<String>,
    pub eapol_frames: usize,
    pub crackable: bool,
    pub recommended_attack: String,
}

impl fmt::Display for WpaHandshakeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "WPA Handshake Analysis")?;
        writeln!(f, "=====================")?;
        writeln!(f, "BSSID        : {}", self.bssid)?;
        writeln!(f, "ESSID        : {}", self.essid)?;
        writeln!(f, "Version      : {}", self.handshake_version)?;
        writeln!(f, "EAPOL frames : {}", self.eapol_frames)?;
        writeln!(f, "Has PMKID    : {}", self.has_pmkid)?;
        if let Some(pmkid) = &self.pmkid {
            writeln!(f, "PMKID        : {pmkid}")?;
        }
        writeln!(f, "Crackable    : {}", self.crackable)?;
        writeln!(f, "Attack       : {}", self.recommended_attack)?;
        Ok(())
    }
}

/// Analyze raw EAPOL frame data to determine handshake completeness.
pub fn analyze_eapol_frames(frames: &[Vec<u8>]) -> WpaHandshakeInfo {
    let mut has_anonce = false;
    let mut has_snonce = false;
    let mut has_mic = false;
    let mut has_pmkid = false;
    let mut pmkid_value = None;
    let mut anonce_value = None;
    let mut snonce_value = None;
    let mut mic_value = None;
    let mut bssid = String::from("unknown");
    let essid = String::from("unknown");

    for frame in frames {
        // Parse 802.1X / EAPOL header
        if frame.len() < 99 {
            continue; // Too short for valid EAPOL
        }

        // Key descriptor type (byte 99+)
        let key_info = u16::from_be_bytes([frame[97], frame[98]]);

        // Check for key info bits
        let is_pairwise = (key_info & 0x0008) != 0;
        let is_install = (key_info & 0x0040) != 0;
        let is_ack = (key_info & 0x0080) != 0;
        let is_mic = (key_info & 0x0100) != 0;
        let _key_descriptor_version = key_info & 0x0007;

        // Message 1: ANonce (ACK=1, MIC=0, Install=0)
        if is_ack && !is_mic && !is_install && is_pairwise {
            has_anonce = true;
            if frame.len() >= 115 {
                anonce_value = Some(hex_encode(&frame[99..131]));
            }
        }
        // Message 2: SNonce (ACK=0, MIC=1, Install=0)
        if !is_ack && is_mic && !is_install && is_pairwise {
            has_snonce = true;
            has_mic = true;
            if frame.len() >= 115 {
                snonce_value = Some(hex_encode(&frame[99..131]));
            }
            mic_value = Some(hex_encode(&frame[131..147]));
        }
        // Message 3: (ACK=1, MIC=1, Install=1)
        if is_ack && is_mic && is_install {
            has_anonce = true; // ANonce resent in msg 3
        }

        // Check for PMKID in Key Data (AKM type 0x004F for PMKID)
        if frame.len() > 177 {
            // Look for PMKID sub-element (type 0x04)
            for chunk in frame[177..].chunks(2) {
                if chunk.len() == 2 && chunk[0] == 0x04 && chunk[1] == 0x10 {
                    if frame.len() > 179 {
                        has_pmkid = true;
                        pmkid_value = Some(hex_encode(&frame[179..195]));
                    }
                    break;
                }
            }
        }

        // Extract BSSID from Ethernet header (bytes 10-15)
        if frame.len() > 15 {
            bssid = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                frame[10], frame[11], frame[12], frame[13], frame[14], frame[15]
            );
        }
    }

    let eapol_count = frames.len();
    let crackable = (has_anonce && has_snonce && has_mic) || has_pmkid;

    let handshake_version = match frames.first().and_then(|f| f.get(99)).copied() {
        Some(2) => "WPA2 (RSN)".to_string(),
        Some(1) => "WPA (TKIP)".to_string(),
        _ => "Unknown".to_string(),
    };

    let recommended_attack = if has_pmkid {
        "PMKID attack — offline crack without client".to_string()
    } else if has_anonce && has_snonce && has_mic {
        "4-way handshake capture — offline dictionary/brute-force crack".to_string()
    } else {
        format!("Incomplete handshake — need {} more EAPOL frames", 4usize.saturating_sub(eapol_count))
    };

    WpaHandshakeInfo {
        bssid,
        essid,
        handshake_version,
        has_pmkid,
        pmkid: pmkid_value,
        anonce: anonce_value,
        snonce: snonce_value,
        mic: mic_value,
        eapol_frames: eapol_count,
        crackable,
        recommended_attack,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ─── WPS PIN Analysis ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WpsPinInfo {
    pub pin: String,
    pub is_default: bool,
    pub is_vulnerable_to_pixie_dust: bool,
    pub vulnerability_details: String,
}

impl fmt::Display for WpsPinInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "WPS PIN Analysis")?;
        writeln!(f, "================")?;
        writeln!(f, "PIN             : {}", self.pin)?;
        writeln!(f, "Default PIN     : {}", self.is_default)?;
        writeln!(f, "Pixie Dust vuln : {}", self.is_vulnerable_to_pixie_dust)?;
        if self.is_vulnerable_to_pixie_dust {
            writeln!(f, "Details         : {}", self.vulnerability_details)?;
        }
        Ok(())
    }
}

/// List of known default WPS PINs from common routers.
const KNOWN_DEFAULT_PINS: &[&str] = &[
    "12345670", "00000000", "11111111", "12345678",
    "22222222", "87654321", "12121212", "01234567",
    "99999999", "10000000", "20011974", "31266831",
    "88888888", "77777777", "66666666", "55555555",
    "33333333", "24682468", "13572468", "11223344",
    "password", "admin123", "12341234",
    // Common ISP defaults
    "1234567890", "123456789", "0987654321", "1122334455",
    // Vendor-specific defaults
    "10010010", "00100100", "11001100", "20020020", // D-Link
    "525441", "52544D", "20062006", "19891989",     // Netgear
    "12345678", "admin", "passw0rd",                 // TP-Link
];

/// Analyze a WPS PIN for known vulnerabilities.
pub fn analyze_wps_pin(pin: &str) -> WpsPinInfo {
    let is_default = KNOWN_DEFAULT_PINS.contains(&pin);

    // Check for vulnerable WPS implementations (pixie dust)
    // Most routers with Ralink, Broadcom, or Realtek chipsets manufactured
    // before 2015 are vulnerable to pixie dust attacks
    let is_vulnerable = is_default || pin.len() == 8;

    let vulnerability_details = if is_default {
        format!(
            "PIN '{pin}' is a known default — try before brute-forcing. \
             Default PINs indicate the router was never reconfigured."
        )
    } else if is_vulnerable {
        "WPS PIN is 8 digits — vulnerable to pixie dust offline attack \
         if router uses Ralink/Broadcom/Realtek chipset (pre-2015). \
         Attack takes seconds vs. 4-11 hours for online brute-force."
            .to_string()
    } else {
        "PIN format is unusual — may be a custom non-vulnerable implementation".to_string()
    };

    WpsPinInfo {
        pin: pin.to_string(),
        is_default,
        is_vulnerable_to_pixie_dust: is_vulnerable,
        vulnerability_details,
    }
}

// ─── Deauth Frame Analysis ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DeauthAnalysis {
    pub frame_type: String,
    pub subtype: u8,
    pub source_mac: String,
    pub dest_mac: String,
    pub bssid: String,
    pub reason_code: u16,
    pub reason_description: String,
    pub is_deauth: bool,
    pub is_disassoc: bool,
    pub threat_level: String,
}

impl fmt::Display for DeauthAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Deauth/Disassoc Analysis")?;
        writeln!(f, "========================")?;
        writeln!(f, "Type   : {} (subtype {})", self.frame_type, self.subtype)?;
        writeln!(f, "Source : {}", self.source_mac)?;
        writeln!(f, "Dest   : {}", self.dest_mac)?;
        writeln!(f, "BSSID  : {}", self.bssid)?;
        writeln!(f, "Reason : {} ({})", self.reason_description, self.reason_code)?;
        writeln!(f, "Threat : {}", self.threat_level)?;
        Ok(())
    }
}

/// Analyze a raw 802.11 deauthentication/disassociation frame.
pub fn analyze_deauth_frame(frame: &[u8]) -> Option<DeauthAnalysis> {
    if frame.len() < 26 {
        return None;
    }

    // Frame control field
    let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
    let subtype = (frame_control >> 4) & 0x0F;

    // Subtypes 10 (0x0C) = Disassociation, 12 (0x0C) = Deauthentication
    let is_deauth = subtype == 12;
    let is_disassoc = subtype == 10;

    if !is_deauth && !is_disassoc {
        return None;
    }

    let frame_type = if is_deauth {
        "Deauthentication".to_string()
    } else {
        "Disassociation".to_string()
    };

    // Destination address (bytes 4-9)
    let dest_mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        frame[4], frame[5], frame[6], frame[7], frame[8], frame[9]
    );

    // Source address (bytes 10-15)
    let source_mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        frame[10], frame[11], frame[12], frame[13], frame[14], frame[15]
    );

    // BSSID (bytes 16-21)
    let bssid = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        frame[16], frame[17], frame[18], frame[19], frame[20], frame[21]
    );

    // Reason code (bytes 22-23)
    let reason_code = u16::from_le_bytes([frame[22], frame[23]]);

    let reason_description = match reason_code {
        1 => "Unspecified reason",
        2 => "Previous authentication no longer valid",
        3 => "Deauthenticated because sending STA is leaving (or has left) IBSS or ESS",
        4 => "Disassociated due to inactivity",
        5 => "Disassociated because sending STA is not authenticated",
        6 => "Disassociated due to receiving frames from nonauthenticated STA",
        7 => "Disassociated due to receiving frames from nonassociated STA",
        8 => "Disassociated because the sending STA is not authenticated",
        9 => "Invalid information element",
        10 => "Michael MIC failure",
        14 => "MIC failure (legacy)",
        15 => "4-way handshake timeout",
        16 => "Group key handshake timeout",
        17 => "IE different in 4-way handshake",
        34 => "TDLS teardown unreachable",
        36 => "Requested from peer STA as STA does not want to use the mechanism",
        _ => "Reserved/unknown",
    };

    let threat_level = if reason_code == 7 || reason_code == 6 {
        "HIGH — Possible deauth attack targeting clients".to_string()
    } else if reason_code == 1 || reason_code == 2 {
        "MEDIUM — Generic reason codes often used in attacks".to_string()
    } else {
        "LOW — Standard reason code".to_string()
    };

    let subtype_u8 = subtype as u8;

    Some(DeauthAnalysis {
        frame_type,
        subtype: subtype_u8,
        source_mac,
        dest_mac,
        bssid,
        reason_code,
        reason_description: reason_description.to_string(),
        is_deauth,
        is_disassoc,
        threat_level,
    })
}

// ─── Wireless Security Audit ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WirelessSecurityAudit {
    pub essid: String,
    pub security_protocol: String,
    pub encryption: String,
    pub issues: Vec<String>,
    pub risk_score: u8,
    pub recommendations: Vec<String>,
}

impl fmt::Display for WirelessSecurityAudit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Wireless Security Audit")?;
        writeln!(f, "=======================")?;
        writeln!(f, "ESSID      : {}", self.essid)?;
        writeln!(f, "Protocol   : {}", self.security_protocol)?;
        writeln!(f, "Encryption : {}", self.encryption)?;
        writeln!(f, "Risk score : {}/100", self.risk_score)?;
        if !self.issues.is_empty() {
            writeln!(f)?;
            writeln!(f, "Issues")?;
            for issue in &self.issues {
                writeln!(f, "  ✗ {issue}")?;
            }
        }
        if !self.recommendations.is_empty() {
            writeln!(f)?;
            writeln!(f, "Recommendations")?;
            for rec in &self.recommendations {
                writeln!(f, "  ✓ {rec}")?;
            }
        }
        Ok(())
    }
}

/// Generate a wireless security audit report from beacon frame data.
pub fn audit_wireless_security(
    essid: &str,
    security_protocol: &str,
    encryption: &str,
) -> WirelessSecurityAudit {
    let mut issues = Vec::new();
    let mut recommendations = Vec::new();
    let mut risk_score: u8 = 0;

    // Check security protocol
    match security_protocol.to_lowercase().as_str() {
        "open" | "none" => {
            issues.push("Network is OPEN — no authentication required".to_string());
            risk_score += 80;
            recommendations.push("Implement WPA3-Personal minimum; use WPA3-Enterprise where possible".to_string());
        }
        "wep" => {
            issues.push("WEP encryption — can be cracked in minutes with aircrack-ng".to_string());
            risk_score += 90;
            recommendations.push("Migrate to WPA3 immediately — WEP is cryptographically broken".to_string());
        }
        "wpa" => {
            issues.push("WPA (TKIP) — deprecated, vulnerable to Beck-Tews and Ohigashi-Morii attacks".to_string());
            risk_score += 50;
            recommendations.push("Upgrade to WPA3-Personal (SAE) or at minimum WPA2-AES (CCMP)".to_string());
        }
        "wpa2" => {
            if encryption.to_uppercase() == "TKIP" {
                issues.push("WPA2 with TKIP — deprecated, vulnerable to fragmentation attacks".to_string());
                risk_score += 40;
                recommendations.push("Switch to WPA2-AES (CCMP) or upgrade to WPA3".to_string());
            }
            issues.push("WPA2-PSK — vulnerable to PMKID and offline dictionary attacks".to_string());
            risk_score += 30;
            recommendations.push("Consider WPA3-Enterprise for stronger authentication".to_string());
        }
        "wpa2-enterprise" => {
            issues.push("WPA2-Enterprise without certificate validation — vulnerable to Evil Twin/RADIUS impersonation".to_string());
            risk_score += 20;
            recommendations.push("Enforce certificate validation on all supplicants (disable EAP-PEAP without cert check)".to_string());
        }
        "wpa3" => {
            issues.push("WPA3 — strongest consumer standard, but check for Dragonblood side-channel vulnerabilities (CVE-2019-15126)".to_string());
            risk_score += 5;
            recommendations.push("Ensure firmware is up-to-date to patch Dragonblood variants".to_string());
        }
        _ => {
            issues.push(format!("Unknown security protocol: {security_protocol}"));
            risk_score += 10;
        }
    }

    // Check for common ESSID issues
    if essid.len() < 3 {
        issues.push("Short ESSID — easy to identify in crowds, low obscurity".to_string());
    }

    // Generic ESSID names
    let generic = ["linksys", "netgear", "dlink", "tp-link", "cisco", "default"];
    if generic.iter().any(|g| essid.to_lowercase().contains(g)) {
        issues.push("Generic/default ESSID — indicates router may be unconfigured".to_string());
        risk_score += 10;
        recommendations.push("Set a unique, non-identifying ESSID that doesn't reveal router vendor".to_string());
    }

    WirelessSecurityAudit {
        essid: essid.to_string(),
        security_protocol: security_protocol.to_string(),
        encryption: encryption.to_string(),
        issues,
        risk_score: risk_score.min(100),
        recommendations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wps_pin_default() {
        let info = analyze_wps_pin("12345670");
        assert!(info.is_default);
    }

    #[test]
    fn test_wps_pin_custom() {
        let info = analyze_wps_pin("84729301");
        assert!(!info.is_default);
    }

    #[test]
    fn test_wireless_audit_open() {
        let audit = audit_wireless_security("TestNet", "open", "none");
        assert!(audit.risk_score > 50);
        assert!(!audit.issues.is_empty());
    }

    #[test]
    fn test_wireless_audit_wep() {
        let audit = audit_wireless_security("OldNet", "wep", "wep");
        assert!(audit.risk_score > 80);
    }

    #[test]
    fn test_wireless_audit_wpa3() {
        let audit = audit_wireless_security("SecureNet", "wpa3", "aes");
        assert!(audit.risk_score < 20);
    }

    #[test]
    fn test_deauth_frame_too_short() {
        let result = analyze_deauth_frame(&[0u8; 10]);
        assert!(result.is_none());
    }
}
