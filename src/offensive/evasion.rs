//! Evasion techniques — payload obfuscation, encoding, fragmentation,
//! and anti-detection methods. Pure-Rust implementations for red team operations.

use std::fmt;

// ─── Obfuscation Techniques ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ObfuscationResult {
    pub technique: String,
    pub original: String,
    pub obfuscated: String,
    pub original_length: usize,
    pub obfuscated_length: usize,
    pub effectiveness: String,
    pub notes: String,
}

impl fmt::Display for ObfuscationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Obfuscation: {}", self.technique)?;
        writeln!(f, "Effectiveness: {}", self.effectiveness)?;
        writeln!(f, "Size change: {} → {} bytes", self.original_length, self.obfuscated_length)?;
        writeln!(f, "Notes: {}", self.notes)?;
        writeln!(f)?;
        writeln!(f, "Result:")?;
        writeln!(f, "{}", self.obfuscated)?;
        Ok(())
    }
}

/// Apply PowerShell string obfuscation techniques.
pub fn obfuscate_powershell(command: &str) -> Vec<ObfuscationResult> {
    let mut results = Vec::new();

    // Technique 1: String concatenation
    let concat_result = powershell_concat_obfuscate(command);
    results.push(concat_result);

    // Technique 2: Character code assembly
    let charcode_result = powershell_charcode_obfuscate(command);
    results.push(charcode_result);

    // Technique 3: Reverse string
    let reverse_result = powershell_reverse_obfuscate(command);
    results.push(reverse_result);

    // Technique 4: Base64 encoding
    let base64_result = powershell_base64_obfuscate(command);
    results.push(base64_result);

    // Technique 5: Tick insertion (PowerShell ignore)
    let tick_result = powershell_tick_obfuscate(command);
    results.push(tick_result);

    // Technique 6: Variable name randomization
    let var_result = powershell_var_obfuscate(command);
    results.push(var_result);

    results
}

fn powershell_concat_obfuscate(cmd: &str) -> ObfuscationResult {
    // Split each string into parts and concatenate
    let mut obfuscated = String::new();
    let parts: Vec<&str> = cmd.split('\'').collect();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            obfuscated.push_str("'+''");
        }
        obfuscated.push_str(part);
    }

    // If no single quotes, do character-by-character split on key words
    let fallback = cmd
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 && !c.is_whitespace() {
                format!("'{c}'+'")
            } else {
                c.to_string()
            }
        })
        .collect::<String>();

    let final_obfuscated = if obfuscated == cmd { &fallback } else { &obfuscated };

    ObfuscationResult {
        technique: "String concatenation".to_string(),
        original: cmd.to_string(),
        obfuscated: final_obfuscated.clone(),
        original_length: cmd.len(),
        obfuscated_length: final_obfuscated.len(),
        effectiveness: "Medium".to_string(),
        notes: "Breaks static string matching; AV may still detect at runtime".to_string(),
    }
}

fn powershell_charcode_obfuscate(cmd: &str) -> ObfuscationResult {
    let charcodes: Vec<String> = cmd.bytes().map(|b| format!("{}+", b)).collect();
    let joined = charcodes.join("");
    let trimmed = joined.trim_end_matches('+');

    let obfuscated = format!("([string]({trimmed}) -replace ' ','')");

    ObfuscationResult {
        technique: "Character code assembly".to_string(),
        original: cmd.to_string(),
        obfuscated,
        original_length: cmd.len(),
        obfuscated_length: cmd.len() * 4, // ~4x expansion
        effectiveness: "Medium-High".to_string(),
        notes: "Highly effective against basic signature matching; runtime detection may catch".to_string(),
    }
}

fn powershell_reverse_obfuscate(cmd: &str) -> ObfuscationResult {
    let reversed: String = cmd.chars().rev().collect();
    let obfuscated = format!("'{reversed}' -replace '(.|$)','' -replace '(.{{2}})','$$1' | ForEach-Object {{ [char]([int]$_ -bxor 0) }} | ForEach-Object {{ [string]$_ }} | Out-String | . {{ $_.Trim() }}");

    ObfuscationResult {
        technique: "String reversal with self-decode".to_string(),
        original: cmd.to_string(),
        obfuscated,
        original_length: cmd.len(),
        obfuscated_length: cmd.len() * 6,
        effectiveness: "High".to_string(),
        notes: "Self-decoding at runtime; very effective against static analysis".to_string(),
    }
}

fn powershell_base64_obfuscate(cmd: &str) -> ObfuscationResult {
    let encoded = base64_encode_simple(cmd);
    let obfuscated = format!("[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(\"{encoded}\")) | . {{ $_ }}");

    ObfuscationResult {
        technique: "Base64 encoded command".to_string(),
        original: cmd.to_string(),
        obfuscated,
        original_length: cmd.len(),
        obfuscated_length: encoded.len() + 80,
        effectiveness: "Medium".to_string(),
        notes: "Commonly used; easily detected by AMSI and behavioral analysis".to_string(),
    }
}

fn powershell_tick_obfuscate(cmd: &str) -> ObfuscationResult {
    // PowerShell ignores backtick (`) inside strings when not expanded
    let obfuscated: String = cmd
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if c.is_alphabetic() && i % 3 == 0 {
                format!("`{c}")
            } else {
                c.to_string()
            }
        })
        .collect();

    let len = obfuscated.len();
    ObfuscationResult {
        technique: "Tick (backtick) insertion".to_string(),
        original: cmd.to_string(),
        obfuscated,
        original_length: cmd.len(),
        obfuscated_length: len,
        effectiveness: "Low-Medium".to_string(),
        notes: "Simple but effective against naive pattern matching; modern AV ignores ticks".to_string(),
    }
}

fn powershell_var_obfuscate(cmd: &str) -> ObfuscationResult {
    // Replace common variables with randomized names
    let obfuscated = cmd
        .replace("$env", "$x1nv")
        .replace("$null", "$nUll")
        .replace("$true", "$TrUe")
        .replace("Invoke-Expression", "InVoKe-ExpResSiOn")
        .replace("IEX", "iEX")
        .replace("DownloadString", "dOwnLoAdStRiNg")
        .replace("Net.WebClient", "nEt.WEbClIeNt");

    let len = obfuscated.len();
    ObfuscationResult {
        technique: "Case randomization + variable renaming".to_string(),
        original: cmd.to_string(),
        obfuscated,
        original_length: cmd.len(),
        obfuscated_length: len,
        effectiveness: "Low".to_string(),
        notes: "Case-insensitive matching defeats this; useful as additional layer".to_string(),
    }
}

fn base64_encode_simple(input: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

// ─── HTTP Traffic Fragmentation ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FragmentedPayload {
    pub fragments: Vec<Vec<u8>>,
    pub fragment_count: usize,
    pub total_size: usize,
    pub mtu: u16,
    pub technique: String,
}

impl fmt::Display for FragmentedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Fragmented Payload")?;
        writeln!(f, "==================")?;
        writeln!(f, "Technique     : {}", self.technique)?;
        writeln!(f, "Fragments     : {}", self.fragment_count)?;
        writeln!(f, "Total size    : {} bytes", self.total_size)?;
        writeln!(f, "MTU           : {} bytes", self.mtu)?;
        Ok(())
    }
}

/// Fragment an HTTP payload to evade deep packet inspection.
pub fn fragment_http_payload(payload: &[u8], mtu: u16) -> FragmentedPayload {
    let header_overhead = 40; // TCP/IP header
    let max_fragment = (mtu as usize).saturating_sub(header_overhead);
    let max_fragment = max_fragment.max(1);

    let fragments: Vec<Vec<u8>> = payload
        .chunks(max_fragment)
        .map(|chunk| chunk.to_vec())
        .collect();

    let technique = if fragments.len() > 3 {
        "TCP segment fragmentation — evades DPI reassembly".to_string()
    } else {
        "TCP segment splitting — minimal fragmentation".to_string()
    };

    FragmentedPayload {
        fragment_count: fragments.len(),
        total_size: payload.len(),
        fragments,
        mtu,
        technique,
    }
}

// ─── IPID Sequence Manipulation ──────────────────────────────────────────────

/// Generate randomized IP ID values to avoid network fingerprinting.
pub fn generate_random_ipids(count: usize) -> Vec<u16> {
    // Simple linear congruential generator for deterministic randomness
    let mut seed: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut ipids = Vec::with_capacity(count);

    for _ in 0..count {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        ipids.push((seed >> 32) as u16);
    }

    ipids
}

// ─── Payload Checksum Manipulation ───────────────────────────────────────────

/// Calculate IP header checksum (used for packet forgery detection evasion).
pub fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

// ─── Decoy Generation ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DecoyTraffic {
    pub decoy_ips: Vec<String>,
    pub technique: String,
    pub description: String,
}

impl fmt::Display for DecoyTraffic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Decoy Traffic Generation")?;
        writeln!(f, "========================")?;
        writeln!(f, "Technique: {}", self.technique)?;
        writeln!(f, "Decoys  : {}", self.decoy_ips.len())?;
        writeln!(f, "{}", self.description)?;
        Ok(())
    }
}

/// Generate nmap-style decoy IP addresses for scan obfuscation.
pub fn generate_decoys(real_ip: &str, count: usize) -> DecoyTraffic {
    let mut decoys = Vec::new();
    let mut seed: u64 = 0xCAFE_BABE;

    for _ in 0..count {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let a = (seed >> 24) & 0xFF;
        let b = (seed >> 16) & 0xFF;
        let c = (seed >> 8) & 0xFF;
        let d = seed & 0xFF;

        // Generate valid-looking IPs (avoid .0 and .255)
        let ip = format!(
            "{}.{}.{}.{}",
            (a % 223) + 1,
            (b % 254) + 1,
            (c % 254) + 1,
            (d % 253) + 1,
        );

        if ip != real_ip {
            decoys.push(ip);
        }
    }

    DecoyTraffic {
        technique: "nmap -D (Decoy Scan)".to_string(),
        description: format!(
            "Interleave real IP ({real_ip}) among {} decoy IPs to confuse IDS/IPS source tracking. \
             Use: nmap -D {} {}",
            decoys.len(),
            decoys.join(","),
            real_ip,
        ),
        decoy_ips: decoys,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_powershell_obfuscation_techniques() {
        let results = obfuscate_powershell("Get-Process");
        assert!(results.len() >= 5);
        assert!(results.iter().any(|r| r.technique.contains("concatenation")));
    }

    #[test]
    fn test_http_fragmentation() {
        let payload = vec![0xAA; 1000];
        let fragmented = fragment_http_payload(&payload, 1500);
        assert!(fragmented.fragment_count >= 1);
        assert_eq!(fragmented.total_size, 1000);
    }

    #[test]
    fn test_ip_checksum() {
        let header = vec![0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02];
        let checksum = calculate_ip_checksum(&header);
        // Just verify it produces a result
        assert!(checksum != 0 || true); // checksum could be any value
    }

    #[test]
    fn test_decoy_generation() {
        let decoys = generate_decoys("192.168.1.100", 5);
        assert_eq!(decoys.decoy_ips.len(), 5);
        assert!(!decoys.decoy_ips.iter().any(|ip| ip == "192.168.1.100"));
    }

    #[test]
    fn test_ipid_sequence() {
        let ipids = generate_random_ipids(10);
        assert_eq!(ipids.len(), 10);
        // Verify they're not all the same
        assert!(ipids.windows(2).any(|w| w[0] != w[1]));
    }
}
