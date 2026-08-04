//! Local forensic artifact-parsing engine.
//!
//! Serves the artifact tools (`sqlitebrowser`, `galleta`, `mdb-sql`,
//! `keepnote`, `recordmydesktop`). The engine detects the artifact format
//! from its magic bytes and renders a structural view: `SQLite` database
//! headers + embedded schema, Internet Explorer `index.dat` cache records,
//! Microsoft Access (JET/ACE) database version, Ogg media containers, and a
//! printable-strings fallback for anything else. All parsing is offline and
//! read-only.

use std::fmt::Write as _;
use std::path::Path;

use super::{ArsenalError, banner, extract_strings, read_bytes};

pub(super) fn report(tool: &str, input: &Path) -> Result<String, ArsenalError> {
    let bytes = read_bytes(input)?;
    let mut out = banner(tool, &format!("{tool} — Local Artifact Analysis"), input);
    let _ = writeln!(out, "Size           : {} bytes", bytes.len());

    if bytes.starts_with(b"SQLite format 3\0") {
        render_sqlite(&mut out, &bytes);
    } else if bytes.len() > 0x14
        && (&bytes[4..19] == b"Standard Jet DB" || &bytes[4..19] == b"Standard ACE DB")
    {
        render_mdb(&mut out, &bytes);
    } else if bytes.starts_with(b"Client UrlCache MMF Ver ") {
        render_ie_cache(&mut out, &bytes);
    } else if bytes.starts_with(b"OggS") {
        render_ogg(&mut out, &bytes);
    } else {
        render_strings(&mut out, &bytes);
    }
    Ok(out)
}

// ── SQLite ───────────────────────────────────────────────────────────────────

fn render_sqlite(out: &mut String, bytes: &[u8]) {
    out.push_str("Detected type  : SQLite 3 database\n\n");
    out.push_str("Header\n------\n");
    // Page size is a big-endian u16 at offset 16; the value 1 means 65536.
    let page_size = match read_u16_be(bytes, 16) {
        Some(1) => 65_536,
        Some(value) => u32::from(value),
        None => 0,
    };
    let encoding = match read_u32_be(bytes, 56) {
        Some(1) => "UTF-8",
        Some(2) => "UTF-16le",
        Some(3) => "UTF-16be",
        _ => "unspecified",
    };
    let page_count = read_u32_be(bytes, 28).unwrap_or(0);
    let change_counter = read_u32_be(bytes, 24).unwrap_or(0);
    let _ = writeln!(out, "Page size      : {page_size} bytes");
    let _ = writeln!(out, "Page count     : {page_count}");
    let _ = writeln!(out, "Text encoding  : {encoding}");
    let _ = writeln!(out, "Change counter : {change_counter}\n");

    out.push_str("Schema (CREATE statements)\n--------------------------\n");
    let mut found = 0_usize;
    for text in extract_strings(bytes, 8) {
        let upper = text.to_ascii_uppercase();
        if upper.contains("CREATE TABLE") || upper.contains("CREATE INDEX") {
            found += 1;
            let shown: String = text.chars().take(160).collect();
            let _ = writeln!(out, "- {shown}");
            if found >= 200 {
                out.push_str("... (truncated at 200 schema objects)\n");
                break;
            }
        }
    }
    if found == 0 {
        out.push_str("No CREATE statements recovered from the page bytes.\n");
    }
}

// ── Microsoft Access (JET / ACE) ─────────────────────────────────────────────

fn render_mdb(out: &mut String, bytes: &[u8]) {
    out.push_str("Detected type  : Microsoft Access database\n");
    let family = if &bytes[4..19] == b"Standard ACE DB" {
        "ACE (Access 2007+ / .accdb)"
    } else {
        "JET (Access 97-2003 / .mdb)"
    };
    // The JET version byte lives at offset 0x14.
    let version = bytes.get(0x14).copied().unwrap_or(0);
    let jet = match version {
        0 => "Jet 3 (Access 97)",
        1 => "Jet 4 (Access 2000-2003)",
        2 => "ACE 12 (Access 2007)",
        3 => "ACE 14 (Access 2010)",
        4 | 5 => "ACE 15/16 (Access 2013+)",
        _ => "unknown",
    };
    let _ = writeln!(out, "Engine family  : {family}");
    let _ = writeln!(out, "Version marker : {version} ({jet})\n");
    out.push_str("Table Names (heuristic)\n-----------------------\n");
    let mut found = 0_usize;
    for text in extract_strings(bytes, 4) {
        // Access system tables are prefixed `MSys`; user tables appear as
        // plain identifiers in the catalog pages.
        if text.starts_with("MSys") || text.starts_with("Table") {
            found += 1;
            let _ = writeln!(out, "- {text}");
            if found >= 100 {
                break;
            }
        }
    }
    if found == 0 {
        out.push_str("No catalog table markers recovered.\n");
    }
}

// ── Internet Explorer cache (index.dat) ──────────────────────────────────────

fn render_ie_cache(out: &mut String, bytes: &[u8]) {
    out.push_str("Detected type  : Internet Explorer cache (index.dat)\n");
    let version: String = bytes
        .get(24..32)
        .map(|slice| String::from_utf8_lossy(slice).trim().to_string())
        .unwrap_or_default();
    let _ = writeln!(out, "Cache version  : {version}\n");
    out.push_str("Cached URLs\n-----------\n");
    let mut found = 0_usize;
    for text in extract_strings(bytes, 6) {
        let lower = text.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") || lower.contains("://") {
            found += 1;
            let shown: String = text.chars().take(160).collect();
            let _ = writeln!(out, "- {shown}");
            if found >= 200 {
                out.push_str("... (truncated at 200 URLs)\n");
                break;
            }
        }
    }
    if found == 0 {
        out.push_str("No cached URL records recovered.\n");
    }
}

// ── Ogg media (recordmydesktop) ──────────────────────────────────────────────

fn render_ogg(out: &mut String, bytes: &[u8]) {
    out.push_str("Detected type  : Ogg media container\n");
    // Count "OggS" page markers and identify the codecs from the first pages.
    let pages = count_marker(bytes, b"OggS");
    let has_theora = find_marker(bytes, b"theora");
    let has_vorbis = find_marker(bytes, b"vorbis");
    let mut codecs = Vec::new();
    if has_theora {
        codecs.push("Theora (video)");
    }
    if has_vorbis {
        codecs.push("Vorbis (audio)");
    }
    let codec_line = if codecs.is_empty() {
        "unrecognized".to_string()
    } else {
        codecs.join(", ")
    };
    let _ = writeln!(out, "Ogg pages      : {pages}");
    let _ = writeln!(out, "Codecs         : {codec_line}");
    out.push_str(
        "\nA screen recording captured by recordmydesktop; play/transcode it with an\n\
         authorized media tool for review.\n",
    );
}

// ── Generic fallback ─────────────────────────────────────────────────────────

fn render_strings(out: &mut String, bytes: &[u8]) {
    let _ = writeln!(out, "Detected type  : {}\n", super::detect_file_type(bytes));
    out.push_str("ASCII Strings (first 60)\n------------------------\n");
    let mut count = 0_usize;
    for text in extract_strings(bytes, 4).into_iter().take(60) {
        let _ = writeln!(out, "- {text}");
        count += 1;
    }
    if count == 0 {
        out.push_str("No printable strings of length >= 4 found.\n");
    }
}

// ── Bounds-checked big-endian readers + marker helpers ───────────────────────

fn read_u16_be(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([slice[0], slice[1]]))
}

fn read_u32_be(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn count_marker(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn find_marker(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sqlite_header() {
        let mut db = b"SQLite format 3\0".to_vec();
        db.extend_from_slice(&[0x10, 0x00]); // page size 4096 (BE u16 at 16)
        db.resize(64, 0);
        db.push(b'C'); // pad so extract_strings has room
        let mut out = String::new();
        render_sqlite(&mut out, &db);
        assert!(out.contains("SQLite 3 database"));
        assert!(out.contains("Page size      : 4096"));
    }

    #[test]
    fn counts_ogg_pages() {
        let mut data = b"OggS".to_vec();
        data.extend_from_slice(b"........OggS........vorbis");
        assert_eq!(count_marker(&data, b"OggS"), 2);
        assert!(find_marker(&data, b"vorbis"));
    }

    #[test]
    fn routes_unknown_to_strings() {
        let mut out = String::new();
        render_strings(&mut out, b"just some readable text here");
        assert!(out.contains("ASCII Strings"));
    }
}
