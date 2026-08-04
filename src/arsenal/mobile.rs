//! Mobile / binary reverse-engineering engine.
//!
//! Serves the Android and native RE tools (`apktool`, `androguard`, `jadx`,
//! `dex2jar`, `apksigner`, `apkleaks`, `qark`, `mobsf`, `trueseeing`,
//! `mariana-trench`, `frida`, `objection`, `drozer`).
//!
//! Rather than running one generic byte triage for every tool, this engine
//! is **format-aware**: it recognises the supplied artifact (APK/ZIP, Dalvik
//! DEX, or a native binary) with a real structural parser, and then renders
//! the view the requested tool is known for — the archive layout and
//! signing/DEX/native inventory for the packaging tools, the DEX header for
//! the decompilers, the signature block for `apksigner`, and the
//! instrumentation surface for the dynamic-analysis tools. Everything is
//! computed offline from the bytes; no device, emulator, or network is used.

use std::fmt::Write as _;
use std::path::Path;

use super::{ArsenalError, banner, extract_strings, read_bytes};

/// What the requested tool most wants to see about a mobile artifact.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    /// Archive layout, DEX/native inventory, embedded secrets (packaging &
    /// static-analysis tools).
    Package,
    /// Dalvik bytecode / class structure (decompilers).
    Dalvik,
    /// APK signing block and certificate metadata.
    Signing,
    /// Dynamic-instrumentation targets: components + native libraries.
    Instrumentation,
}

fn focus_for(tool: &str) -> Focus {
    match tool {
        "dex2jar" | "jadx" => Focus::Dalvik,
        "apksigner" => Focus::Signing,
        "frida" | "objection" | "drozer" => Focus::Instrumentation,
        // apktool, androguard, apkleaks, qark, mobsf, trueseeing, mariana-trench
        _ => Focus::Package,
    }
}

pub(super) fn report(tool: &str, input: &Path) -> Result<String, ArsenalError> {
    let bytes = read_bytes(input)?;
    let mut out = banner(tool, &format!("{tool} — Mobile / Binary Analysis"), input);
    let focus = focus_for(tool);

    if let Some(entries) = parse_zip_central_directory(&bytes) {
        render_apk(&mut out, &bytes, &entries, focus);
    } else if is_dex(&bytes) {
        render_dex(&mut out, &bytes);
    } else {
        // Native binary (ELF/Mach-O/PE) or unknown: fall back to the shared
        // volatility-grade triage, which is itself a real RE pass.
        return binary_triage(tool, input, "Offline Binary Triage");
    }
    Ok(out)
}

/// The shared volatility-grade binary triage (entropy / embedded signatures /
/// printable strings). Reused by the capture engine for non-pcap blobs.
pub(super) fn binary_triage(tool: &str, input: &Path, title: &str) -> Result<String, ArsenalError> {
    let report = crate::builtin_tools::run_volatility(input)
        .map_err(|error| ArsenalError(error.to_string()))?;
    Ok(format!(
        "{}Binary triage (entropy / embedded signatures / strings):\n\n{report}\n",
        banner(tool, &format!("{tool} — {title}"), input)
    ))
}

// ── APK / ZIP analysis ───────────────────────────────────────────────────────

struct ZipEntry {
    name: String,
    compressed: u32,
    uncompressed: u32,
}

// Entry names inside an APK/JAR are case-canonical by specification
// (`classes.dex` is always lowercase; the JAR signing files are uppercase
// `.RSA`/`.DSA`/`.EC`/`.SF`), so the case-sensitive suffix match here is
// intentional and correct.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn render_apk(out: &mut String, bytes: &[u8], entries: &[ZipEntry], focus: Focus) {
    let dex: Vec<&ZipEntry> = entries
        .iter()
        .filter(|e| e.name.ends_with(".dex"))
        .collect();
    let native: Vec<&ZipEntry> = entries
        .iter()
        .filter(|e| e.name.starts_with("lib/") && e.name.ends_with(".so"))
        .collect();
    let signatures: Vec<&ZipEntry> = entries
        .iter()
        .filter(|e| {
            e.name.starts_with("META-INF/")
                && (e.name.ends_with(".RSA")
                    || e.name.ends_with(".DSA")
                    || e.name.ends_with(".EC")
                    || e.name.ends_with(".SF"))
        })
        .collect();
    let has_manifest = entries.iter().any(|e| e.name == "AndroidManifest.xml");
    let has_resources = entries.iter().any(|e| e.name == "resources.arsc");

    let total_uncompressed: u64 = entries.iter().map(|e| u64::from(e.uncompressed)).sum();
    let _ = writeln!(out, "Detected type  : Android APK / ZIP archive");
    let _ = writeln!(out, "Archive entries: {}", entries.len());
    let _ = writeln!(out, "Uncompressed   : {total_uncompressed} bytes");
    let _ = writeln!(
        out,
        "AndroidManifest: {}",
        if has_manifest { "present" } else { "absent" }
    );
    let _ = writeln!(
        out,
        "resources.arsc : {}",
        if has_resources { "present" } else { "absent" }
    );
    let _ = writeln!(out, "DEX files      : {}", dex.len());
    let _ = writeln!(out, "Native libs    : {}", native.len());
    let _ = writeln!(out, "Signing files  : {}\n", signatures.len());

    match focus {
        Focus::Signing => render_signing(out, &signatures),
        Focus::Dalvik => {
            out.push_str("Dalvik Bytecode (classes*.dex)\n------------------------------\n");
            if dex.is_empty() {
                out.push_str("No classes.dex found in the archive.\n");
            } else {
                for entry in &dex {
                    let _ = writeln!(
                        out,
                        "- {} ({} -> {} bytes)",
                        entry.name, entry.compressed, entry.uncompressed
                    );
                }
                out.push_str(
                    "\nDecompile these DEX units with an authorized workstation copy of the tool.\n",
                );
            }
        }
        Focus::Instrumentation => render_instrumentation(out, &native, entries),
        Focus::Package => {
            render_native(out, &native);
            render_secrets(out, bytes);
        }
    }
}

// JAR signing files use canonical uppercase extensions (`.SF` vs `.RSA`).
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn render_signing(out: &mut String, signatures: &[&ZipEntry]) {
    out.push_str("APK Signing Block (META-INF)\n----------------------------\n");
    if signatures.is_empty() {
        out.push_str(
            "No v1 (JAR) signature files present. The APK may be unsigned or use only\n\
             v2/v3 block signing (stored outside the ZIP central directory).\n",
        );
        return;
    }
    for entry in signatures {
        let kind = if entry.name.ends_with(".SF") {
            "signature manifest"
        } else {
            "PKCS#7 certificate/signature"
        };
        let _ = writeln!(
            out,
            "- {} ({kind}, {} bytes)",
            entry.name, entry.uncompressed
        );
    }
    out.push_str(
        "\nVerify the certificate chain and digest algorithm with an authorized\n\
         keytool/apksigner run; SHA-1-only signing blocks are legacy and weak.\n",
    );
}

fn render_native(out: &mut String, native: &[&ZipEntry]) {
    out.push_str("Native Libraries (lib/*)\n------------------------\n");
    if native.is_empty() {
        out.push_str("No bundled native libraries.\n\n");
        return;
    }
    let mut abis: Vec<&str> = native
        .iter()
        .filter_map(|e| {
            e.name
                .strip_prefix("lib/")
                .and_then(|r| r.split('/').next())
        })
        .collect();
    abis.sort_unstable();
    abis.dedup();
    let _ = writeln!(out, "ABIs           : {}", abis.join(", "));
    for entry in native.iter().take(50) {
        let _ = writeln!(out, "- {} ({} bytes)", entry.name, entry.uncompressed);
    }
    out.push('\n');
}

fn render_instrumentation(out: &mut String, native: &[&ZipEntry], entries: &[ZipEntry]) {
    out.push_str("Dynamic-Instrumentation Surface\n-------------------------------\n");
    out.push_str(
        "Offline note: hooking is a live on-device action. This lists the static\n\
         targets a Frida/objection/drozer session would attach to.\n\n",
    );
    render_native(out, native);
    let assets = entries
        .iter()
        .filter(|e| e.name.starts_with("assets/"))
        .count();
    let has_flutter = native.iter().any(|e| e.name.contains("libflutter.so"));
    let has_unity = native.iter().any(|e| e.name.contains("libunity.so"));
    let has_rn = entries
        .iter()
        .any(|e| e.name.contains("index.android.bundle"));
    let runtimes: Vec<&str> = [
        has_flutter.then_some("Flutter"),
        has_unity.then_some("Unity"),
        has_rn.then_some("React-Native"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let hint = if runtimes.is_empty() {
        "native/Java only".to_string()
    } else {
        runtimes.join(", ")
    };
    let _ = writeln!(out, "Bundled assets : {assets}");
    let _ = writeln!(out, "Runtime hints  : {hint}");
}

fn render_secrets(out: &mut String, bytes: &[u8]) {
    out.push_str("Embedded Secret / Endpoint Indicators\n-------------------------------------\n");
    let strings = extract_strings(bytes, 6);
    let mut hits = 0_usize;
    for text in &strings {
        let lower = text.to_ascii_lowercase();
        let reason = if text.contains("AKIA") {
            Some("AWS access key id")
        } else if text.starts_with("-----BEGIN") {
            Some("embedded private key/cert")
        } else if lower.starts_with("https://") || lower.starts_with("http://") {
            Some("hardcoded endpoint URL")
        } else if lower.contains("api_key") || lower.contains("apikey") || lower.contains("secret")
        {
            Some("possible API key / secret")
        } else if lower.contains("password") {
            Some("possible hardcoded credential")
        } else {
            None
        };
        if let Some(reason) = reason {
            hits += 1;
            let shown: String = text.chars().take(96).collect();
            let _ = writeln!(out, "[{reason}] {shown}");
            if hits >= 100 {
                out.push_str("... (truncated at 100 indicators)\n");
                break;
            }
        }
    }
    if hits == 0 {
        out.push_str("No embedded secret/endpoint indicators found.\n");
    }
}

// ── DEX analysis ─────────────────────────────────────────────────────────────

fn is_dex(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && &bytes[0..4] == b"dex\n"
}

fn render_dex(out: &mut String, bytes: &[u8]) {
    out.push_str("Dalvik Executable (DEX)\n-----------------------\n");
    let version = String::from_utf8_lossy(&bytes[4..7]);
    let _ = writeln!(out, "DEX version    : {version}");
    // Header layout (little-endian) per the Dalvik .dex format.
    let field = |offset: usize| read_u32_le(bytes, offset);
    let rows: &[(&str, usize)] = &[
        ("File size", 0x20),
        ("String IDs", 0x38),
        ("Type IDs", 0x40),
        ("Proto IDs", 0x48),
        ("Field IDs", 0x50),
        ("Method IDs", 0x58),
        ("Class defs", 0x60),
        ("Data size", 0x68),
    ];
    for (label, offset) in rows {
        match field(*offset) {
            Some(value) => {
                let _ = writeln!(out, "{label:<14} : {value}");
            }
            None => {
                let _ = writeln!(out, "{label:<14} : <truncated header>");
            }
        }
    }
    out.push_str(
        "\nThis is a single Dalvik unit; run an authorized dex2jar/jadx pass to\n\
         recover Java sources for review.\n",
    );
}

// ── Minimal, bounds-checked binary readers ───────────────────────────────────

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let slice = bytes.get(offset..end)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = bytes.get(offset..end)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Parses a ZIP central directory into its file entries, or returns `None`
/// when the input is not a ZIP archive. Reads only the central directory —
/// no decompression is performed.
fn parse_zip_central_directory(bytes: &[u8]) -> Option<Vec<ZipEntry>> {
    const EOCD_SIG: u32 = 0x0605_4b50;
    const CDH_SIG: u32 = 0x0201_4b50;
    if bytes.len() < 22 || read_u32_le(bytes, 0) != Some(0x0403_4b50) {
        return None; // not a local-file-header ZIP
    }
    // Locate the End Of Central Directory record by scanning backwards.
    let scan_start = bytes.len().saturating_sub(22 + 0xFFFF);
    let mut eocd = None;
    for offset in (scan_start..=bytes.len() - 22).rev() {
        if read_u32_le(bytes, offset) == Some(EOCD_SIG) {
            eocd = Some(offset);
            break;
        }
    }
    let eocd = eocd?;
    let total_entries = usize::from(read_u16_le(bytes, eocd + 10)?);
    let mut cursor = read_u32_le(bytes, eocd + 16)? as usize;

    let mut entries = Vec::with_capacity(total_entries.min(4096));
    for _ in 0..total_entries.min(65_535) {
        if read_u32_le(bytes, cursor) != Some(CDH_SIG) {
            break;
        }
        let compressed = read_u32_le(bytes, cursor + 20)?;
        let uncompressed = read_u32_le(bytes, cursor + 24)?;
        let name_len = usize::from(read_u16_le(bytes, cursor + 28)?);
        let extra_len = usize::from(read_u16_le(bytes, cursor + 30)?);
        let comment_len = usize::from(read_u16_le(bytes, cursor + 32)?);
        let name_start = cursor + 46;
        let name_end = name_start.checked_add(name_len)?;
        let name = String::from_utf8_lossy(bytes.get(name_start..name_end)?).into_owned();
        entries.push(ZipEntry {
            name,
            compressed,
            uncompressed,
        });
        cursor = name_end + extra_len + comment_len;
    }
    (!entries.is_empty()).then_some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal one-entry ZIP (local header + central dir + EOCD).
    fn tiny_zip(name: &[u8]) -> Vec<u8> {
        let name_len = u16::try_from(name.len()).unwrap();
        let mut z = Vec::new();
        // Local file header
        z.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        z.extend_from_slice(&[0u8; 22]); // version..uncompressed (we keep sizes 0)
        z.extend_from_slice(&name_len.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // extra len
        z.extend_from_slice(name);
        let cd_offset = u32::try_from(z.len()).unwrap();
        // Central directory header
        z.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        z.extend_from_slice(&[0u8; 24]); // version..uncompressed
        z.extend_from_slice(&name_len.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // extra
        z.extend_from_slice(&0u16.to_le_bytes()); // comment
        z.extend_from_slice(&[0u8; 8]); // disk/attrs
        z.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        z.extend_from_slice(name);
        let cd_size = u32::try_from(z.len()).unwrap() - cd_offset;
        // End of central directory
        z.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        z.extend_from_slice(&[0u8; 4]); // disk number + disk with cd start
        z.extend_from_slice(&1u16.to_le_bytes()); // entries this disk
        z.extend_from_slice(&1u16.to_le_bytes()); // total entries
        z.extend_from_slice(&cd_size.to_le_bytes());
        z.extend_from_slice(&cd_offset.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // comment len
        z
    }

    #[test]
    fn parses_zip_entry_names() {
        let zip = tiny_zip(b"AndroidManifest.xml");
        let entries = parse_zip_central_directory(&zip).expect("should parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "AndroidManifest.xml");
    }

    #[test]
    fn rejects_non_zip() {
        assert!(parse_zip_central_directory(b"not a zip at all").is_none());
    }

    #[test]
    fn recognises_dex_magic() {
        assert!(is_dex(b"dex\n035\0extra"));
        assert!(!is_dex(b"PK\x03\x04"));
    }

    #[test]
    fn focus_routing_is_tool_specific() {
        assert!(focus_for("jadx") == Focus::Dalvik);
        assert!(focus_for("apksigner") == Focus::Signing);
        assert!(focus_for("frida") == Focus::Instrumentation);
        assert!(focus_for("apktool") == Focus::Package);
    }
}
